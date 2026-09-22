//! Subtrie creation module for SALT proof generation.
//!
//! This module provides the core functionality for creating minimal subtries and generating
//! IPA (Inner Product Argument) proofs for SALT's authenticated key-value store. The main
//! function [`create_sub_trie`] constructs the authentication paths needed to prove the
//! existence or non-existence of specified keys.
//!
//! # Architecture
//!
//! The proof generation process follows these steps:
//! 1. Extract and deduplicate bucket IDs from input keys
//! 2. Determine trie levels for each bucket (metadata vs dynamic data buckets)
//! 3. Build minimal node hierarchy using [`parents_and_points`]
//! 4. Read the commitment of every parent node
//! 5. Resolve every parent's polynomial, from the process-wide node-polynomial cache or storage
//! 6. Generate IPA prover queries for leaf nodes (bucket contents) and internal nodes (child commitments)
use crate::{
    constant::{
        default_commitment, BUCKET_SLOT_BITS, BUCKET_SLOT_ID_MASK, DOMAIN_SIZE, MAX_SUBTREE_LEVELS,
        META_BUCKET_SIZE, NUM_META_BUCKETS, STARTING_NODE_ID,
    },
    proof::{
        prover::slot_to_field,
        shape::{connect_parent_id, logic_parent_id, parents_and_points, slot_position},
        ProofError, ProofResult, SerdeCommitment,
    },
    traits::{StateReader, TrieReader},
    trie::node_utils::{get_child_node, subtree_leaf_start_key, subtree_root_level},
    types::{BucketId, BucketMeta, CommitmentBytes, NodeId, SaltKey},
    SlotId,
};
use banderwagon::{Element, Fr};
use ipa_multipoint::{lagrange_basis::LagrangeBasis, multiproof::ProverQuery};

use salt_macros::prelude::*;
use salt_macros::{chunks, iter, thread_chunk_size};
use std::collections::{BTreeMap, BTreeSet};
use std::{format, string::ToString, sync::Arc, vec, vec::Vec};

use hashbrown::HashMap;
use rustc_hash::FxBuildHasher;
type FxHashMap<K, V> = HashMap<K, V, FxBuildHasher>;

/// Process-wide cache of node polynomials, keyed by node id and validated by the node's
/// commitment.
///
/// A commitment binds the node's children, so a node whose commitment is unchanged since its
/// polynomial was last built has the same 256 child scalars (internal node) or slot scalars
/// (leaf node), and the store reads plus scalar conversions that produce them can be skipped.
/// Consecutive blocks share most of their authentication paths, which is what makes the hit
/// rate worth the memory: at most `SHARDS * MAX_PER_SHARD` polynomials of 8 KiB each, 256 MiB.
/// A shard that fills up is cleared whole; the working set refills within a few proofs.
mod node_poly_cache {
    use super::*;
    use crate::Lazy;
    use spin::RwLock;

    pub(super) const SHARDS: usize = 64;
    pub(super) const MAX_PER_SHARD: usize = 512;

    type Shard = RwLock<FxHashMap<NodeId, (CommitmentBytes, Arc<LagrangeBasis>)>>;

    /// The shards of one cache: [`CACHE`] is the process-wide instance, and a test holds its own.
    pub(super) struct NodePolyCache(Vec<Shard>);

    pub(super) static CACHE: Lazy<NodePolyCache> = Lazy::new(NodePolyCache::new);

    impl NodePolyCache {
        pub(super) fn new() -> Self {
            Self(
                (0..SHARDS)
                    .map(|_| RwLock::new(FxHashMap::default()))
                    .collect(),
            )
        }

        fn shard(&self, node: NodeId) -> &Shard {
            &self.0[(node % SHARDS as NodeId) as usize]
        }

        /// The cached polynomial of `node`, if it was built for exactly this commitment.
        pub(super) fn get(
            &self,
            node: NodeId,
            commitment: &CommitmentBytes,
        ) -> Option<Arc<LagrangeBasis>> {
            let guard = self.shard(node).read();
            guard
                .get(&node)
                .filter(|(seen, _)| seen == commitment)
                .map(|(_, poly)| Arc::clone(poly))
        }

        pub(super) fn insert(
            &self,
            node: NodeId,
            commitment: CommitmentBytes,
            poly: Arc<LagrangeBasis>,
        ) {
            let mut guard = self.shard(node).write();
            // Only a new node grows the shard. Whatever the insert evicts or replaces is dropped
            // after the lock is released, so readers do not wait on the frees.
            let evicted = (guard.len() >= MAX_PER_SHARD && !guard.contains_key(&node)).then(|| {
                core::mem::replace(
                    &mut *guard,
                    FxHashMap::with_capacity_and_hasher(MAX_PER_SHARD, FxBuildHasher),
                )
            });
            let replaced = guard.insert(node, (commitment, poly));
            drop(guard);
            drop((evicted, replaced));
        }
    }
}

// Constants for improved code readability
const METADATA_BUCKET_LEVEL: u8 = 1;
const ROOT_LEVEL_CHILD_START: NodeId = 1;

/// Information returned by the subtrie creation process
type SubTrieInfo = (
    Vec<ProverQuery>,
    BTreeMap<NodeId, SerdeCommitment>,
    FxHashMap<BucketId, u8>,
);

/// The polynomial of every internal node in `nodes` (logical ids), in order: its 256 child
/// commitments mapped to the scalar field, with the level's default commitment where a child
/// does not exist in storage (the root level's first child has its own default).
///
/// # Errors
///
/// Returns `ProofError::StateReadError` if unable to read child node commitments from storage.
fn internal_polynomials<Store>(store: &Store, nodes: &[NodeId]) -> ProofResult<Vec<LagrangeBasis>>
where
    Store: TrieReader,
{
    // Helper closure for concise element conversion
    let to_element = |bytes| Element::from_bytes_unchecked_uncompressed(bytes);

    // The trie is sparse, so most of a node's 256 children carry a default
    // commitment, of which only a handful of distinct values exist (one or two
    // per level). Mapping a commitment to the scalar field costs a field
    // inversion, so defaults are converted once and cached by value while only
    // the children that actually exist in storage are batch-converted.
    let mut default_scalars: FxHashMap<CommitmentBytes, Fr> = FxHashMap::default();
    let mut cached_default_scalar = |bytes: CommitmentBytes| {
        *default_scalars
            .entry(bytes)
            .or_insert_with(|| to_element(bytes).map_to_scalar_field())
    };

    let mut polys: Vec<Vec<Fr>> = Vec::with_capacity(nodes.len());
    // Children present in storage: `(node index, child index)`, and their commitments
    let mut real_positions: Vec<(usize, usize)> = Vec::new();
    let mut real_children: Vec<Element> = Vec::new();

    for (i, node_id) in nodes.iter().enumerate() {
        // Calculate starting index for this node's 256 children
        let child_idx = get_child_node(&logic_parent_id(*node_id), 0);

        // Load existing child commitments from storage
        let children = store
            .node_entries(child_idx..child_idx + DOMAIN_SIZE as NodeId)
            .map_err(|e| ProofError::StateReadError {
                reason: format!("Failed to load child nodes for parent {node_id}: {e:?}"),
            })?;

        // Initialize with appropriate default commitments
        let default_idx = if child_idx == ROOT_LEVEL_CHILD_START {
            child_idx + 1 // Root level: most children use child_idx + 1 as default
        } else {
            child_idx // Non-root levels: all use child_idx as default
        };
        let mut node_scalars =
            vec![cached_default_scalar(default_commitment(default_idx)); DOMAIN_SIZE];

        // Special case: root level first child uses different default
        if child_idx == ROOT_LEVEL_CHILD_START {
            node_scalars[0] = cached_default_scalar(default_commitment(child_idx));
        }

        // Record actual commitments to overwrite the defaults where they exist
        for (absolute_node_id, commitment_bytes) in children {
            real_positions.push((i, absolute_node_id as usize - child_idx as usize));
            real_children.push(to_element(commitment_bytes));
        }
        polys.push(node_scalars);
    }

    // Batch-convert the existing children and scatter them into place.
    let real_scalars = Element::batch_map_to_scalar_field(&real_children);
    for ((node, position), scalar) in real_positions.into_iter().zip(real_scalars) {
        polys[node][position] = scalar;
    }

    Ok(polys.into_iter().map(LagrangeBasis::new).collect())
}

/// One parent node of the subtrie: the logical id [`parents_and_points`] reports (which
/// encodes a bucket root's level), the physical id the store and the polynomial cache key by,
/// and its commitment as read for this proof.
struct ParentNode {
    logical: NodeId,
    physical: NodeId,
    bytes: CommitmentBytes,
    commitment: Element,
}

/// Creates IPA prover queries for a given commitment and evaluation points.
///
/// This helper function generates the cryptographic queries needed for IPA (Inner Product Argument)
/// multipoint proofs. Each query contains:
/// - The polynomial commitment (cryptographic hash)
/// - The polynomial coefficients in Lagrange basis form
/// - An evaluation point (child index within the polynomial)
/// - The result at that point
///
/// # Parameters
/// * `commitment` - The cryptographic commitment to the polynomial
/// * `poly` - The polynomial in Lagrange basis form (256 coefficients), shared by every query
/// * `points` - Set of evaluation points (child indices) to create queries for
///
/// # Returns
/// A vector of `ProverQuery` objects, one for each evaluation point
fn create_prover_queries(
    commitment: Element,
    poly: Arc<LagrangeBasis>,
    points: &BTreeSet<usize>,
) -> Vec<ProverQuery> {
    points
        .iter()
        .map(|&i| ProverQuery {
            commitment,
            poly: Arc::clone(&poly),
            point: i,
            result: poly.evaluate_in_domain(i),
        })
        .collect()
}

/// Creates a subtrie infomation for IPA proofs for the given salt keys.
///
/// This function is the core of SALT's proof generation system. It constructs a minimal
/// subtrie containing all the authentication paths needed to prove the existence or
/// non-existence of the specified keys. The function generates prover queries that can
/// be used with the IPA (Inner Product Argument) multipoint proof system.
///
/// # Parameters
///
/// * `store` - Storage backend providing access to both trie commitments and bucket data
/// * `salt_keys` - Pre-sorted and deduplicated keys to generate proofs for
///
/// # Returns
///
/// Returns a tuple containing:
/// * `Vec<ProverQuery>` - IPA prover queries for all nodes in the authentication paths
/// * `BTreeMap<NodeId, CommitmentBytesW>` - Commitments for all parent nodes in the subtrie
/// * `FxHashMap<BucketId, u8>` - Mapping of bucket IDs to their trie levels
///
/// # Errors
///
/// Returns `ProofError::StateReadError` if unable to read bucket metadata or trie commitments.
/// Returns `ProofError::InvalidSaltKey` if any salt key has a slot_id that exceeds its bucket's capacity.
pub(crate) fn create_sub_trie<Store>(
    store: &Store,
    salt_keys: &[SaltKey],
) -> ProofResult<SubTrieInfo>
where
    Store: StateReader + TrieReader,
{
    if salt_keys.is_empty() {
        return Err(ProofError::StateReadError {
            reason: "empty key set".to_string(),
        });
    }

    // Steps 1 & 2: Validate every key against its bucket capacity and record the trie level
    // of each bucket. Keys arrive sorted, so each bucket's keys form one run and its metadata
    // is read once.
    let mut buckets_level: FxHashMap<BucketId, u8> = FxHashMap::default();
    for bucket_keys in salt_keys.chunk_by(|a, b| a.bucket_id() == b.bucket_id()) {
        let bucket_id = bucket_keys[0].bucket_id();
        let (capacity, level) = if bucket_id < NUM_META_BUCKETS as BucketId {
            // Metadata buckets are always at level 1 (never expand into subtrees)
            (META_BUCKET_SIZE as u64, METADATA_BUCKET_LEVEL)
        } else {
            // Data buckets: read metadata to determine capacity and
            // subtree structure (higher capacity = higher level root)
            let meta = store
                .metadata(bucket_id)
                .map_err(|e| ProofError::StateReadError {
                    reason: format!("Failed to read metadata for bucket {bucket_id}: {e:?}"),
                })?;
            let level = MAX_SUBTREE_LEVELS - subtree_root_level(meta.capacity);
            (meta.capacity, level as u8)
        };
        buckets_level.insert(bucket_id, level);
        if let Some(key) = bucket_keys.iter().find(|key| key.slot_id() >= capacity) {
            return Err(ProofError::InvalidSaltKey {
                key: *key,
                capacity,
            });
        }
    }

    // Step 3: Build the minimal node hierarchy needed for authentication
    let (internal_nodes, leaf_nodes) = parents_and_points(salt_keys, &buckets_level);

    // Step 4: Read every parent's commitment in parallel, internal nodes first, then leaves;
    // steps 5 and 6 index this list instead of re-reading the store.
    let parents: Vec<ParentNode> = {
        let logical_ids: Vec<NodeId> = internal_nodes
            .keys()
            .chain(leaf_nodes.keys())
            .copied()
            .collect();
        // A store read is too short a task to split below one chunk per thread.
        iter!(logical_ids, thread_chunk_size!(logical_ids.len()))
            .map(|&logical| {
                let physical = connect_parent_id(logical);
                let bytes = store
                    .commitment(physical)
                    .map_err(|e| ProofError::StateReadError {
                        reason: format!("Failed to load commitment for node {physical}: {e:?}"),
                    })?;
                Ok(ParentNode {
                    logical,
                    physical,
                    bytes,
                    commitment: Element::from_bytes_unchecked_uncompressed(bytes),
                })
            })
            .collect::<ProofResult<_>>()?
    };
    let parents_commitments: BTreeMap<NodeId, SerdeCommitment> = parents
        .iter()
        .map(|parent| (parent.physical, SerdeCommitment(parent.commitment)))
        .collect();

    // Step 5: Resolve the polynomial of every parent, internal nodes in parallel chunks and
    // leaves one per task.
    let (internal_parents, leaf_parents) = parents.split_at(internal_nodes.len());
    let internal_polys = resolve_polys(internal_parents, |missing| {
        let chunk_size = thread_chunk_size!(missing.len());
        let chunks = chunks!(missing, chunk_size)
            .map(|nodes| internal_polynomials(store, nodes))
            .collect::<ProofResult<Vec<_>>>()?;
        Ok(chunks.into_iter().flatten().collect())
    })?;
    let leaf_polys = resolve_polys(leaf_parents, |missing| {
        iter!(missing)
            .map(|&node| leaf_polynomial(store, node))
            .collect()
    })?;

    // Step 6: One IPA prover query per proven point, in node order.
    let points = internal_nodes.into_values().chain(leaf_nodes.into_values());
    let polys = internal_polys.into_iter().chain(leaf_polys);
    let mut queries: Vec<ProverQuery> = Vec::new();
    for ((parent, points), poly) in parents.iter().zip(points).zip(polys) {
        queries.extend(create_prover_queries(parent.commitment, poly, &points));
    }

    Ok((queries, parents_commitments, buckets_level))
}

/// The polynomial of every parent in `parents`, in order: query order is node order, which
/// the transcript hashes, so a cache hit must not reorder the proof. A parent whose polynomial
/// the cache holds for the commitment it was read at skips `rebuild`; the misses are rebuilt
/// in one call (by logical id, one polynomial per miss) and cached under that commitment.
fn resolve_polys(
    parents: &[ParentNode],
    rebuild: impl FnOnce(&[NodeId]) -> ProofResult<Vec<LagrangeBasis>>,
) -> ProofResult<Vec<Arc<LagrangeBasis>>> {
    let hits: Vec<Option<Arc<LagrangeBasis>>> = parents
        .iter()
        .map(|parent| node_poly_cache::CACHE.get(parent.physical, &parent.bytes))
        .collect();
    let missing: Vec<NodeId> = parents
        .iter()
        .zip(&hits)
        .filter(|(_, hit)| hit.is_none())
        .map(|(parent, _)| parent.logical)
        .collect();
    let mut rebuilt = rebuild(&missing)?.into_iter();
    Ok(parents
        .iter()
        .zip(hits)
        .map(|(parent, hit)| {
            hit.unwrap_or_else(|| {
                let poly = Arc::new(rebuilt.next().expect("one rebuilt polynomial per miss"));
                node_poly_cache::CACHE.insert(parent.physical, parent.bytes, Arc::clone(&poly));
                poly
            })
        })
        .collect())
}

/// The 256-slot polynomial of a leaf node: every slot's value hashed to the field, with the
/// bucket kind's default for empty slots.
fn leaf_polynomial<Store>(store: &Store, parent: NodeId) -> ProofResult<LagrangeBasis>
where
    Store: StateReader,
{
    // Determine the starting slot and bucket ID for this leaf
    let (slot_start, bucket_id) = if parent < BUCKET_SLOT_ID_MASK as NodeId {
        // Main trie leaf: bucket ID derived from position in level 3
        let bucket_id = (parent - STARTING_NODE_ID[3] as NodeId) as BucketId;
        (0, bucket_id)
    } else {
        // Subtree leaf: extract bucket ID and slot start from node ID encoding
        (
            subtree_leaf_start_key(&parent).slot_id(),
            (parent >> BUCKET_SLOT_BITS) as BucketId,
        )
    };

    let start_key = SaltKey::from((bucket_id, slot_start));
    let end_key = SaltKey::from((bucket_id, slot_start + DOMAIN_SIZE as SlotId - 1));

    let entries = store.entries(start_key..=end_key).map_err(|e| {
        ProofError::StateReadError {
            reason: format!(
                "Failed to load bucket entries for bucket {bucket_id}, slots {slot_start}-{}: {e:?}",
                slot_start + DOMAIN_SIZE as SlotId - 1
            ),
        }
    })?;

    // Initialize polynomial coefficients with appropriate default values
    let mut default_coefficients = vec![empty_slot_scalar(bucket_id); DOMAIN_SIZE];

    // Replace default values with actual key-value hashes where data exists
    for (key, value) in entries {
        default_coefficients[slot_position(&key)] = slot_to_field(&Some(value));
    }

    Ok(LagrangeBasis::new(default_coefficients))
}

/// The scalar of an empty slot in `bucket_id`: the default metadata's hash for a metadata
/// bucket, the empty slot's hash for a data bucket.
fn empty_slot_scalar(bucket_id: BucketId) -> Fr {
    if bucket_id < NUM_META_BUCKETS as BucketId {
        slot_to_field(&Some(BucketMeta::default().into()))
    } else {
        slot_to_field(&None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::constant::{META_BUCKET_SIZE, ROOT_NODE_ID};
    use crate::proof::test_utils::*;
    use crate::{
        mem_store::MemStore, proof::prover::PRECOMPUTED_WEIGHTS, state::state::EphemeralSaltState,
        trie::trie::StateRoot,
    };
    use ark_ff::BigInt;
    use banderwagon::{Fr, Zero};
    use hashbrown::HashMap;
    use ipa_multipoint::{crs::CRS, multiproof::MultiPoint, transcript::Transcript};
    use rand::{rngs::StdRng, SeedableRng};

    fn setup_test_store() -> (MemStore, SaltKey) {
        let mut rng = StdRng::seed_from_u64(42);
        let key = mock_data(&mut rng, 52);
        let value = mock_data(&mut rng, 32);
        let kvs: HashMap<_, _> = [(key, Some(value))].iter().cloned().collect();

        let store = MemStore::new();
        let mut state = EphemeralSaltState::new(&store);
        let updates = state.update_fin(&kvs).unwrap();
        store.update_state(updates.clone());

        let mut trie = StateRoot::new(&store);
        let (_, trie_updates) = trie.update_fin(&updates).unwrap();
        store.update_trie(trie_updates);

        (store, *updates.data.keys().next().unwrap())
    }

    fn verify_ipa_proof(queries: Vec<ProverQuery>) -> bool {
        let crs = CRS::default();
        let proof = MultiPoint::open(
            crs.clone(),
            &PRECOMPUTED_WEIGHTS,
            &mut Transcript::new(b"st"),
            queries.clone(),
        );
        proof.check(
            &crs,
            &PRECOMPUTED_WEIGHTS,
            &queries.into_iter().map(Into::into).collect::<Vec<_>>(),
            &mut Transcript::new(b"st"),
        )
    }

    #[test]
    fn create_sub_trie_generates_valid_proofs() {
        let (store, salt_key) = setup_test_store();
        let (prover_queries, _, _) = create_sub_trie(&store, &[salt_key]).unwrap();
        assert!(verify_ipa_proof(prover_queries));
    }

    #[test]
    fn lagrange_polynomial_proof_verification() {
        let crs = CRS::default();
        let mut coeffs = vec![Fr::zero(); 256];
        coeffs[0] = Fr::from(BigInt([
            14950088112150747174,
            13253162737298189682,
            10931921008236264693,
            1309984686389044416,
        ]));
        coeffs[208] = Fr::from(BigInt([
            9954869294274886320,
            8441215309276124103,
            16970925962995195932,
            2055721457450359655,
        ]));

        let poly = LagrangeBasis::new(coeffs);
        let query = ProverQuery {
            commitment: crs.commit_lagrange_poly(&poly),
            poly: poly.clone().into(),
            point: 208,
            result: poly.evaluate_in_domain(208),
        };

        let proof = MultiPoint::open(
            crs.clone(),
            &PRECOMPUTED_WEIGHTS,
            &mut Transcript::new(b"st"),
            vec![query.clone()],
        );
        assert!(proof.check(
            &crs,
            &PRECOMPUTED_WEIGHTS,
            &[query.into()],
            &mut Transcript::new(b"st")
        ));
    }

    #[test]
    fn create_sub_trie_scenarios() {
        let (store, salt_key) = setup_test_store();

        // Single key
        let (q1, _, _) = create_sub_trie(&store, &[salt_key]).unwrap();
        assert!(verify_ipa_proof(q1.clone()));

        // Multiple keys
        let (q2, _, _) = create_sub_trie(
            &store,
            &[
                salt_key,
                SaltKey::from((salt_key.bucket_id(), salt_key.slot_id() + 1)),
            ],
        )
        .unwrap();
        assert!(verify_ipa_proof(q2));

        // Duplicate keys
        let (q3, _, _) = create_sub_trie(&store, &[salt_key, salt_key]).unwrap();
        assert_eq!(q1.len(), q3.len());

        // Metadata bucket
        let (q4, _, b4) = create_sub_trie(&store, &[SaltKey::from((0u32, 0u64))]).unwrap();
        assert!(verify_ipa_proof(q4));
        assert_eq!(b4[&0], 1);

        // Empty input
        let res = create_sub_trie(&store, &[]);
        assert!(res.is_err());
    }

    #[test]
    fn leaf_polynomial_with_real_commitment() {
        let (store, salt_key) = setup_test_store();
        let parent_node = STARTING_NODE_ID[3] as NodeId + salt_key.bucket_id() as u64;
        let commitment =
            Element::from_bytes_unchecked_uncompressed(store.commitment(parent_node).unwrap());
        let points = [0, slot_position(&salt_key)].into();

        let poly = Arc::new(leaf_polynomial(&store, parent_node).unwrap());
        let queries = create_prover_queries(commitment, poly, &points);
        assert_eq!(queries.len(), 2);
        assert!(verify_ipa_proof(queries));
    }

    #[test]
    fn leaf_polynomial_uses_metadata_default_for_meta_bucket() {
        let store = MemStore::new();
        let parent_node = STARTING_NODE_ID[3] as NodeId;
        let commitment =
            Element::from_bytes_unchecked_uncompressed(default_commitment(parent_node));
        let poly = Arc::new(leaf_polynomial(&store, parent_node).unwrap());
        let queries = create_prover_queries(commitment, poly, &[0, 255].into());
        let metadata_default = slot_to_field(&Some(BucketMeta::default().into()));

        assert_eq!(
            queries.iter().map(|q| q.point).collect::<Vec<_>>(),
            vec![0, 255]
        );
        assert!(queries.iter().all(|q| q.result == metadata_default));
    }

    #[test]
    fn leaf_polynomial_uses_empty_default_for_data_bucket() {
        let store = MemStore::new();
        let parent_node = STARTING_NODE_ID[3] as NodeId + NUM_META_BUCKETS as NodeId;
        let commitment =
            Element::from_bytes_unchecked_uncompressed(default_commitment(parent_node));
        let poly = Arc::new(leaf_polynomial(&store, parent_node).unwrap());
        let queries = create_prover_queries(commitment, poly, &[0, 255].into());
        let empty_default = slot_to_field(&None);

        assert_eq!(
            queries.iter().map(|q| q.point).collect::<Vec<_>>(),
            vec![0, 255]
        );
        assert!(queries.iter().all(|q| q.result == empty_default));
    }

    /// A full shard is cleared only by a node it does not hold: re-inserting a node it holds
    /// replaces that entry and keeps the rest, and a lookup at another commitment misses.
    #[test]
    fn node_poly_cache_clears_a_full_shard_only_for_a_new_node() {
        use node_poly_cache::{NodePolyCache, MAX_PER_SHARD, SHARDS};

        let cache = NodePolyCache::new();
        let poly = Arc::new(LagrangeBasis::new(vec![Fr::zero(); DOMAIN_SIZE]));
        let commitment = |byte: u8| -> CommitmentBytes { [byte; 64] };
        // Nodes `7 + i * SHARDS` share one shard.
        let node = |i: usize| (7 + i * SHARDS) as NodeId;

        for i in 0..MAX_PER_SHARD {
            cache.insert(node(i), commitment(1), Arc::clone(&poly));
        }
        assert!((0..MAX_PER_SHARD).all(|i| cache.get(node(i), &commitment(1)).is_some()));
        assert!(cache.get(node(0), &commitment(2)).is_none());

        cache.insert(node(0), commitment(2), Arc::clone(&poly));
        assert!(cache.get(node(0), &commitment(2)).is_some());
        assert!(cache.get(node(0), &commitment(1)).is_none());
        assert!((1..MAX_PER_SHARD).all(|i| cache.get(node(i), &commitment(1)).is_some()));

        cache.insert(node(MAX_PER_SHARD), commitment(1), Arc::clone(&poly));
        assert!(cache.get(node(MAX_PER_SHARD), &commitment(1)).is_some());
        assert!((0..MAX_PER_SHARD).all(|i| cache.get(node(i), &commitment(1)).is_none()));
    }

    #[test]
    fn internal_polynomials_empty_and_single_node() {
        let store = MemStore::new();

        // Empty input
        assert!(internal_polynomials(&store, &[]).unwrap().is_empty());

        // Single internal node
        let polys = internal_polynomials(&store, &[STARTING_NODE_ID[2] as NodeId]).unwrap();
        assert_eq!(polys.len(), 1);
    }

    #[test]
    fn internal_polynomials_root_defaults_are_pinned() {
        let store = MemStore::new();
        let polys = internal_polynomials(&store, &[ROOT_NODE_ID]).unwrap();
        let scalars: Vec<Fr> = (0..DOMAIN_SIZE)
            .map(|i| polys[0].evaluate_in_domain(i))
            .collect();
        let expected = Element::batch_map_to_scalar_field(&[
            Element::from_bytes_unchecked_uncompressed(default_commitment(
                STARTING_NODE_ID[1] as NodeId,
            )),
            Element::from_bytes_unchecked_uncompressed(default_commitment(
                STARTING_NODE_ID[1] as NodeId + 1,
            )),
        ]);

        assert_eq!(scalars.len(), DOMAIN_SIZE);
        assert_eq!(scalars[0], expected[0]);
        assert!(scalars[1..].iter().all(|scalar| *scalar == expected[1]));
        assert_ne!(scalars[0], scalars[1]);
    }

    #[test]
    fn validate_salt_keys() {
        let (store, _) = setup_test_store();

        // Invalid meta bucket key (slot_id >= META_BUCKET_SIZE)
        let invalid_meta_key = SaltKey::from((0u32, META_BUCKET_SIZE as u64));
        let result = create_sub_trie(&store, &[invalid_meta_key]);
        assert!(matches!(result, Err(ProofError::InvalidSaltKey { .. })));

        // Invalid data bucket key (slot_id >= capacity)
        let data_bucket_id = NUM_META_BUCKETS as u32;
        let invalid_data_key = SaltKey::from((data_bucket_id, 1000u64));
        let result = create_sub_trie(&store, &[invalid_data_key]);
        assert!(matches!(result, Err(ProofError::InvalidSaltKey { .. })));

        // Valid keys should work
        let valid_meta_key = SaltKey::from((0u32, 0u64));
        let result = create_sub_trie(&store, &[valid_meta_key]);
        assert!(result.is_ok());
    }
}
