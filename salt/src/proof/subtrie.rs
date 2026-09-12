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
//! 4. Collect cryptographic commitments for all parent nodes
//! 5. Generate IPA prover queries for leaf nodes (bucket contents) and internal nodes (child commitments)
//! 6. Optionally advance the process-wide node-polynomial cache to the witnessed block's
//!    post-state from the block's own transition ([`NodePolyRefresh`])
use crate::{
    constant::{
        default_commitment, BUCKET_SLOT_BITS, BUCKET_SLOT_ID_MASK, DOMAIN_SIZE, MAX_SUBTREE_LEVELS,
        META_BUCKET_SIZE, NUM_META_BUCKETS, ROOT_NODE_ID, STARTING_NODE_ID,
    },
    proof::{
        prover::slot_to_field,
        shape::{connect_parent_id, logic_parent_id, parents_and_points},
        ProofError, ProofResult, SerdeCommitment,
    },
    state::updates::StateUpdates,
    traits::{StateReader, TrieReader},
    trie::node_utils::{
        bucket_root_node_id, get_child_node, get_parent_node, subtree_leaf_for_key,
        subtree_leaf_start_key, subtree_root_level, vc_position_in_parent,
    },
    types::{
        bucket_id_from_metadata_key, get_bfs_level, get_local_number, BucketId, BucketMeta,
        CommitmentBytes, NodeId, SaltKey, SaltValue, METADATA_KEYS_RANGE,
    },
    SlotId,
};
use banderwagon::{Element, Fr, Zero};
use ipa_multipoint::{lagrange_basis::LagrangeBasis, multiproof::ProverQuery};

use salt_macros::prelude::*;
use salt_macros::{chunks, into_iter, num_threads};
use std::collections::{BTreeMap, BTreeSet};
use std::{format, string::ToString, sync::Arc, vec, vec::Vec};

use hashbrown::{HashMap, HashSet};
use rustc_hash::FxBuildHasher;
type FxHashMap<K, V> = HashMap<K, V, FxBuildHasher>;
type FxHashSet<K> = HashSet<K, FxBuildHasher>;

/// Smallest number of parent commitments one parallel task reads.
const MIN_PARENT_CHUNK: usize = 8;
/// Smallest number of internal nodes one parallel task materializes (256 child reads each).
const MIN_NODE_CHUNK: usize = 4;

/// Process-wide cache of node polynomials, keyed by node id and validated by the node's
/// commitment.
///
/// A commitment binds the node's children, so a node whose commitment is unchanged since its
/// polynomial was last built has the same 256 child scalars (internal node) or slot scalars
/// (leaf node), and the store reads plus scalar conversions that produce them can be skipped.
/// Consecutive blocks share most of their authentication paths, which is what makes the hit
/// rate worth the memory: at most `SHARDS * MAX_PER_SHARD` polynomials of 8 KiB each. A shard
/// that fills up is cleared whole; the working set refills within a few proofs.
mod node_poly_cache {
    use super::*;
    use crate::types::CommitmentBytes;
    use crate::Lazy;
    use spin::RwLock;

    const SHARDS: usize = 64;
    const MAX_PER_SHARD: usize = 512;

    type Shard = RwLock<FxHashMap<NodeId, (CommitmentBytes, Arc<LagrangeBasis>)>>;

    static CACHE: Lazy<Vec<Shard>> = Lazy::new(|| {
        (0..SHARDS)
            .map(|_| RwLock::new(FxHashMap::default()))
            .collect()
    });

    fn shard(node: NodeId) -> &'static Shard {
        &CACHE[(node % SHARDS as NodeId) as usize]
    }

    /// The cached polynomial of `node`, if it was built for exactly this commitment.
    pub(super) fn get(node: NodeId, commitment: &CommitmentBytes) -> Option<Arc<LagrangeBasis>> {
        let guard = shard(node).read();
        guard
            .get(&node)
            .filter(|(seen, _)| seen == commitment)
            .map(|(_, poly)| Arc::clone(poly))
    }

    pub(super) fn insert(node: NodeId, commitment: CommitmentBytes, poly: Arc<LagrangeBasis>) {
        let mut guard = shard(node).write();
        if guard.len() >= MAX_PER_SHARD {
            guard.clear();
        }
        guard.insert(node, (commitment, poly));
    }
}

/// One block's header-verified trie transition, used to advance the node-polynomial cache to
/// that block's post-state while the block's own witness is built.
///
/// The two fields are the pair [`StateRoot::update_fin`](crate::trie::trie::StateRoot::update_fin)
/// produced for the block: every node whose commitment changed with its pre- and post-state
/// commitment, and every slot that changed with its old and new value. The witness proves the
/// pre-state, so the polynomials it resolves are exactly the bases this transition transforms;
/// the refresh runs after the witness's own lookups, patches each changed node's polynomial at
/// its changed positions and inserts the result under the node's new commitment, so the next
/// block's witness hits instead of rebuilding from storage. Entries stay validated by
/// commitment, so a stale or foreign entry is only ever a miss, never a wrong witness.
///
/// The store the witness reads must be the transition's pre-state, the view `update_fin` ran
/// on; a parent the witness read at any other commitment is skipped. Applying one transition
/// again (a retried witness) derives the same polynomial from a base validated at the same
/// old commitment and inserts the same entry, so a refresh is idempotent.
pub struct NodePolyRefresh<'a> {
    /// The block's changed nodes as `(node, (old commitment, new commitment))`.
    pub trie_updates: &'a [(NodeId, (CommitmentBytes, CommitmentBytes))],
    /// The block's changed slots as `(key, (old value, new value))`.
    pub state_updates: &'a StateUpdates,
}

/// The changed positions of one parent's polynomial, with the parent's pre- and post-state
/// commitment.
struct ParentPatch {
    old: CommitmentBytes,
    new: CommitmentBytes,
    positions: Vec<(usize, Fr)>,
}

/// Derives, from the block's outputs alone, which position of which cached polynomial takes
/// which new scalar. Keys are physical node ids as the cache uses them
/// ([`connect_parent_id`]): a bucket whose subtree top changed is keyed by its main-trie
/// bucket root, like the witness keys it.
///
/// The plan is complete for every parent it emits: every node whose commitment
/// changed is in `trie_updates`, so a parent's unchanged positions keep the base's values and
/// its changed positions are exactly its changed children (internal node) or changed slots
/// (leaf). Shapes where a per-position patch is wrong under a valid commitment are excluded
/// whole: a bucket whose capacity changes is frozen and every patch inside it is dropped,
/// while the bucket root's position in its main-trie parent is still patched, because that
/// `(old, new)` pair is a true transition of the main-trie node.
fn refresh_plan(refresh: &NodePolyRefresh<'_>) -> FxHashMap<NodeId, ParentPatch> {
    // Fold duplicates to the first old and the last new commitment.
    let mut changed: FxHashMap<NodeId, (CommitmentBytes, CommitmentBytes)> =
        FxHashMap::with_capacity_and_hasher(refresh.trie_updates.len(), FxBuildHasher);
    for &(node, (old, new)) in refresh.trie_updates {
        changed
            .entry(node)
            .and_modify(|pair| pair.1 = new)
            .or_insert((old, new));
    }

    // Buckets whose capacity changes: the trie emits their old top with a default old
    // commitment and resets contracted nodes without their children, so nothing inside them
    // is patched.
    let capacity = |value: &Option<SaltValue>| {
        value
            .as_ref()
            .and_then(|value| BucketMeta::try_from(value).ok())
            .map(|meta| meta.capacity)
    };
    let frozen: FxHashSet<BucketId> = refresh
        .state_updates
        .data
        .range(METADATA_KEYS_RANGE)
        .filter(|(_, (old, new))| match (capacity(old), capacity(new)) {
            (Some(old), Some(new)) => old != new,
            _ => true,
        })
        .map(|(key, _)| bucket_id_from_metadata_key(*key))
        .collect();

    // A bucket is expanded when any of its subtree nodes changed; its slots then live in
    // subtree leaves rather than in the bucket root.
    let expanded: FxHashSet<BucketId> = changed
        .keys()
        .filter(|node| *node >> BUCKET_SLOT_BITS != 0)
        .map(|node| (node >> BUCKET_SLOT_BITS) as BucketId)
        .collect();

    // Changed children, keyed by the physical id of the parent whose polynomial holds them
    //. A changed subtree node is recorded under its own id unless it is the top, which
    // the trie records under the bucket root; so a subtree child's parent is the top exactly
    // when the parent is absent from the transition.
    let mut child_patches: Vec<(NodeId, usize, CommitmentBytes)> =
        Vec::with_capacity(changed.len());
    for (&child, &(_, new)) in &changed {
        if child == ROOT_NODE_ID {
            continue;
        }
        let physical = if child >> BUCKET_SLOT_BITS != 0 {
            let bucket = (child >> BUCKET_SLOT_BITS) as BucketId;
            if frozen.contains(&bucket) {
                continue;
            }
            // A subtree node at local level 0 is always a top, never a child.
            if get_bfs_level(get_local_number(child)) == 0 {
                continue;
            }
            let logical = get_parent_node(&child);
            if changed.contains_key(&logical) {
                logical
            } else {
                debug_assert!(
                    changed.contains_key(&bucket_root_node_id(bucket)),
                    "subtree node {child} changed but neither its parent nor its bucket root did"
                );
                bucket_root_node_id(bucket)
            }
        } else {
            get_parent_node(&child)
        };
        child_patches.push((physical, vc_position_in_parent(&child), new));
    }

    // Changed slots, keyed by their leaf. A key whose leaf is absent from the transition
    // (a slot beyond the bucket's capacity, which the trie drops) is skipped, never
    // re-attributed to the bucket root.
    let mut leaf_patches: Vec<(NodeId, usize, Fr)> =
        Vec::with_capacity(refresh.state_updates.data.len());
    for (key, (_, new)) in &refresh.state_updates.data {
        let leaf = if key.is_in_meta_bucket() {
            bucket_root_node_id(key.bucket_id())
        } else {
            let bucket = key.bucket_id();
            if frozen.contains(&bucket) {
                continue;
            }
            if expanded.contains(&bucket) {
                let leaf = subtree_leaf_for_key(key);
                if !changed.contains_key(&leaf) {
                    continue;
                }
                leaf
            } else {
                bucket_root_node_id(bucket)
            }
        };
        // An emptied slot takes the bucket kind's default, as `leaf_polynomial` fills it.
        let scalar = match new {
            Some(_) => slot_to_field(new),
            None if key.is_in_meta_bucket() => slot_to_field(&Some(BucketMeta::default().into())),
            None => slot_to_field(&None),
        };
        leaf_patches.push((leaf, (key.slot_id() & SLOT_INDEX_MASK) as usize, scalar));
    }

    // One batch maps every changed child commitment to its scalar; it is the same map the
    // rebuild applies to a child read from storage.
    let child_commitments: Vec<CommitmentBytes> = child_patches
        .iter()
        .map(|(_, _, commitment)| *commitment)
        .collect();
    let child_scalars = Element::hash_commitments(&child_commitments);

    // Group by parent; a parent without an (old, new) pair of its own is not patched.
    let mut plan: FxHashMap<NodeId, ParentPatch> = FxHashMap::default();
    let patches = child_patches
        .iter()
        .zip(child_scalars)
        .map(|(&(parent, position, _), scalar)| (parent, position, scalar))
        .chain(leaf_patches);
    for (parent, position, scalar) in patches {
        let Some(&(old, new)) = changed.get(&parent) else {
            continue;
        };
        plan.entry(parent)
            .or_insert_with(|| ParentPatch {
                old,
                new,
                positions: Vec::new(),
            })
            .positions
            .push((position, scalar));
    }
    plan
}

/// Applies a [`refresh_plan`]: for every planned parent, copies a base polynomial that is
/// validated at the parent's old commitment, overwrites the changed positions and inserts the
/// result under the new commitment. Returns the number of entries inserted.
///
/// The base is the witness's in-hand polynomial when the witness read the parent at exactly
/// the old commitment, else the cached entry for the old commitment, else the parent is
/// skipped (an entry is only ever derived from a base validated at `old`). Every
/// insert goes through the shard write lock as a whole `(commitment, polynomial)` pair, so
/// concurrent witnesses can only ever replace an entry with another valid one.
fn apply_refresh(
    plan: FxHashMap<NodeId, ParentPatch>,
    in_hand: &FxHashMap<NodeId, Arc<LagrangeBasis>>,
    parent_bytes: &FxHashMap<NodeId, CommitmentBytes>,
) -> usize {
    let mut refreshed = 0;
    for (physical, patch) in plan {
        let base = match in_hand.get(&physical) {
            Some(poly) => {
                // The witness resolved this polynomial against the commitment it read, so
                // it is the pre-state base only if that commitment is the transition's old.
                let read_at_old = parent_bytes.get(&physical) == Some(&patch.old);
                debug_assert!(
                    read_at_old,
                    "node {physical}: the witness read a commitment other than the refresh's pre-state"
                );
                if !read_at_old {
                    continue;
                }
                Arc::clone(poly)
            }
            None => match node_poly_cache::get(physical, &patch.old) {
                Some(poly) => poly,
                None => continue,
            },
        };
        let mut values: Vec<Fr> = (0..DOMAIN_SIZE)
            .map(|i| base.evaluate_in_domain(i))
            .collect();
        #[cfg(debug_assertions)]
        assert_patch_commits(physical, &patch, &values);
        for &(position, scalar) in &patch.positions {
            values[position] = scalar;
        }
        node_poly_cache::insert(physical, patch.new, Arc::new(LagrangeBasis::new(values)));
        refreshed += 1;
    }
    refreshed
}

/// Debug-build self-check of one refreshed entry: the patched positions must carry the
/// parent's commitment from `old` to exactly `new`, `old + Σ G_i·(s_i − base_i) == new`,
/// which is how the trie produced `new`. The check reads no store and fails on a wrong
/// position, a wrong scalar, and a missing or extra position, which commitment validation
/// alone cannot see.
#[cfg(debug_assertions)]
fn assert_patch_commits(physical: NodeId, patch: &ParentPatch, base: &[Fr]) {
    let committer = crate::trie::trie::shared_committer();
    let mut acc = Element::from_bytes_unchecked_uncompressed(patch.old);
    for &(position, scalar) in &patch.positions {
        acc += committer.mul_index(&(scalar - base[position]), position);
    }
    let got = Element::batch_to_commitments(&[acc])[0];
    assert_eq!(
        got, patch.new,
        "refreshed polynomial of node {physical} does not commit to its new commitment"
    );
}

// Constants for improved code readability
const METADATA_BUCKET_LEVEL: u8 = 1;
const SLOT_INDEX_MASK: u64 = 0xff;
const ROOT_LEVEL_CHILD_START: NodeId = 1;

/// Information returned by the subtrie creation process
type SubTrieInfo = (
    Vec<ProverQuery>,
    BTreeMap<NodeId, SerdeCommitment>,
    FxHashMap<BucketId, u8>,
);

/// Converts cryptographic commitments from multiple internal trie nodes into scalar field elements.
///
/// This function processes internal nodes in the trie hierarchy and converts their child node
/// commitments into scalar field elements suitable for IPA (Inner Product Argument) proof generation.
/// For each internal node, it loads commitments for all 256 possible child positions, using default
/// commitments where actual child nodes don't exist (sparse trie optimization).
///
/// # Parameters
///
/// * `store` - Storage backend providing access to trie node commitments
/// * `nodes` - Internal nodes with their evaluation points (child indices to prove)
///
/// # Returns
///
/// A vector of scalar field elements (`Fr`) representing all child commitments for the given nodes.
/// The elements are ordered by node, then by child index (0-255 per node).
///
/// # Implementation Details
///
/// - Handles sparse child nodes by filling missing positions with appropriate default commitments
/// - Special handling for root level nodes (different default commitment for first child)
/// - Uses parallel processing for performance when dealing with multiple nodes
/// - Converts Element commitments to scalar field using `serial_batch_map_to_scalar_field`
///
/// # Errors
///
/// Returns `ProofError::StateReadError` if unable to read child node commitments from storage.
fn multi_commitments_to_scalars<Store>(
    store: &Store,
    nodes: &[(NodeId, BTreeSet<usize>)],
) -> ProofResult<Vec<Fr>>
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

    let mut scalars = vec![Fr::zero(); nodes.len() * DOMAIN_SIZE];
    // Children present in storage: (position in `scalars`, commitment)
    let mut real_children: Vec<(usize, Element)> = Vec::new();

    for (i, (node_id, _)) in nodes.iter().enumerate() {
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
        let node_scalars = &mut scalars[i * DOMAIN_SIZE..(i + 1) * DOMAIN_SIZE];
        node_scalars.fill(cached_default_scalar(default_commitment(default_idx)));

        // Special case: root level first child uses different default
        if child_idx == ROOT_LEVEL_CHILD_START {
            node_scalars[0] = cached_default_scalar(default_commitment(child_idx));
        }

        // Record actual commitments to overwrite the defaults where they exist
        for (absolute_node_id, commitment_bytes) in children {
            let relative_index = absolute_node_id as usize - child_idx as usize;
            real_children.push((
                i * DOMAIN_SIZE + relative_index,
                to_element(commitment_bytes),
            ));
        }
    }

    // Batch-convert the existing children and scatter them into place.
    let elements: Vec<Element> = real_children.iter().map(|(_, element)| *element).collect();
    let real_scalars = Element::batch_map_to_scalar_field(&elements);
    for ((position, _), scalar) in real_children.iter().zip(real_scalars) {
        scalars[*position] = scalar;
    }

    Ok(scalars)
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
/// * `poly` - The polynomial in Lagrange basis form (256 coefficients)
/// * `points` - Set of evaluation points (child indices) to create queries for
///
/// # Returns
/// A vector of `ProverQuery` objects, one for each evaluation point
#[cfg(test)]
fn create_prover_queries(
    commitment: Element,
    poly: LagrangeBasis,
    points: BTreeSet<usize>,
) -> Vec<ProverQuery> {
    // One shared allocation per polynomial, however many points are opened.
    shared_prover_queries(commitment, Arc::new(poly), &points)
}

/// [`create_prover_queries`] over an already shared polynomial (a cache hit, or one built for
/// the cache).
fn shared_prover_queries(
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
/// * `refresh` - The witnessed block's own transition, applied to the node-polynomial cache
///   once this proof's polynomials are resolved (see [`NodePolyRefresh`]); `None` leaves the
///   cache to the lookups and rebuild inserts alone
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
    refresh: Option<&NodePolyRefresh<'_>>,
) -> ProofResult<SubTrieInfo>
where
    Store: StateReader + TrieReader,
{
    if salt_keys.is_empty() {
        return Err(ProofError::StateReadError {
            reason: "empty key set".to_string(),
        });
    }

    // Steps 1 & 2: Validate every key against its bucket capacity and record
    // the trie level of each bucket. Keys arrive sorted, so each bucket's
    // metadata is read exactly once.
    let mut buckets_level: FxHashMap<BucketId, u8> = FxHashMap::default();
    let mut current_bucket: Option<(BucketId, u64)> = None;
    for key in salt_keys {
        let bucket_id = key.bucket_id();
        let capacity = match current_bucket {
            Some((bucket, capacity)) if bucket == bucket_id => capacity,
            _ => {
                let (capacity, level) = if bucket_id < NUM_META_BUCKETS as BucketId {
                    // Metadata buckets are always at level 1 (never expand into subtrees)
                    (META_BUCKET_SIZE as u64, METADATA_BUCKET_LEVEL)
                } else {
                    // Data buckets: read metadata to determine capacity and
                    // subtree structure (higher capacity = higher level root)
                    let meta =
                        store
                            .metadata(bucket_id)
                            .map_err(|e| ProofError::StateReadError {
                                reason: format!(
                                    "Failed to read metadata for bucket {bucket_id}: {e:?}"
                                ),
                            })?;
                    let level = MAX_SUBTREE_LEVELS - subtree_root_level(meta.capacity);
                    (meta.capacity, level as u8)
                };
                buckets_level.insert(bucket_id, level);
                current_bucket = Some((bucket_id, capacity));
                capacity
            }
        };

        if key.slot_id() >= capacity {
            return Err(ProofError::InvalidSaltKey {
                key: *key,
                capacity,
            });
        }
    }

    // Step 3: Build the minimal node hierarchy needed for authentication
    let (internal_nodes, leaf_nodes) = parents_and_points(salt_keys, &buckets_level);

    // Step 4: Collect cryptographic commitments for all parent nodes in
    // parallel; steps 5 and 6 reuse them instead of re-reading the store.
    let parent_ids: Vec<NodeId> = internal_nodes
        .keys()
        .chain(leaf_nodes.keys())
        .map(|&parent| connect_parent_id(parent))
        .collect();
    let commitment_chunk = parent_ids
        .len()
        .div_ceil(num_threads!())
        .max(MIN_PARENT_CHUNK);
    let parents_read: Vec<(NodeId, crate::types::CommitmentBytes)> =
        chunks!(parent_ids, commitment_chunk)
            .map(|chunk| {
                chunk
                    .iter()
                    .map(|&physical_parent| {
                        let bytes = store.commitment(physical_parent).map_err(|e| {
                            ProofError::StateReadError {
                                reason: format!(
                                    "Failed to load commitment for node {physical_parent}: {e:?}"
                                ),
                            }
                        })?;
                        Ok((physical_parent, bytes))
                    })
                    .collect::<ProofResult<Vec<_>>>()
            })
            .collect::<ProofResult<Vec<_>>>()?
            .into_iter()
            .flatten()
            .collect();
    // The raw bytes key the polynomial cache; the decoded elements go into the proof.
    let parent_bytes: FxHashMap<NodeId, crate::types::CommitmentBytes> =
        parents_read.iter().copied().collect();
    let parents_commitments: BTreeMap<NodeId, SerdeCommitment> = parents_read
        .into_iter()
        .map(|(id, bytes)| {
            (
                id,
                SerdeCommitment(Element::from_bytes_unchecked_uncompressed(bytes)),
            )
        })
        .collect();

    let parent_commitment = |parent: NodeId| -> ProofResult<Element> {
        parents_commitments
            .get(&connect_parent_id(parent))
            .map(|commitment| commitment.0)
            .ok_or_else(|| ProofError::StateReadError {
                reason: format!("Failed to load commitment for node {parent}"),
            })
    };

    // Every resolved polynomial by physical parent id: the bases a refresh patches (the
    // witness reads the pre-state, so these are the polynomials the block's transition
    // transforms).
    let mut in_hand: FxHashMap<NodeId, Arc<LagrangeBasis>> = FxHashMap::default();

    // Step 5: Generate IPA prover queries for each node in internal nodes. A node whose
    // polynomial the cache holds for its current commitment skips the child reads; the rest
    // are materialized in parallel chunks. Query order (node order, then point order) is the
    // same either way: the transcript hashes it, so a cache hit must not reorder the proof.
    let in_nodes: Vec<_> = internal_nodes.into_iter().collect();
    let mut polys: Vec<Option<Arc<LagrangeBasis>>> = Vec::with_capacity(in_nodes.len());
    let mut missing: Vec<usize> = Vec::new();
    for (i, (parent, _)) in in_nodes.iter().enumerate() {
        let physical = connect_parent_id(*parent);
        let hit = parent_bytes
            .get(&physical)
            .and_then(|bytes| node_poly_cache::get(physical, bytes));
        if hit.is_none() {
            missing.push(i);
        }
        polys.push(hit);
    }
    let missing_nodes: Vec<(NodeId, BTreeSet<usize>)> = missing
        .iter()
        .map(|&i| (in_nodes[i].0, BTreeSet::new()))
        .collect();
    let chunk_size = missing_nodes
        .len()
        .div_ceil(num_threads!())
        .max(MIN_NODE_CHUNK);
    let computed: Vec<Vec<Arc<LagrangeBasis>>> = chunks!(missing_nodes, chunk_size)
        .map(|nodes| {
            let scalars = multi_commitments_to_scalars(store, nodes)?;
            Ok(scalars
                .chunks(DOMAIN_SIZE)
                .map(|node_scalars| Arc::new(LagrangeBasis::new(node_scalars.to_vec())))
                .collect::<Vec<_>>())
        })
        .collect::<ProofResult<Vec<_>>>()?;
    for (&i, poly) in missing.iter().zip(computed.into_iter().flatten()) {
        let physical = connect_parent_id(in_nodes[i].0);
        if let Some(bytes) = parent_bytes.get(&physical) {
            node_poly_cache::insert(physical, *bytes, Arc::clone(&poly));
        }
        polys[i] = Some(poly);
    }
    let mut queries: Vec<ProverQuery> = Vec::new();
    for ((parent, points), poly) in in_nodes.into_iter().zip(polys) {
        let poly = poly.expect("every internal node polynomial is resolved above");
        in_hand.insert(connect_parent_id(parent), Arc::clone(&poly));
        queries.extend(shared_prover_queries(
            parent_commitment(parent)?,
            poly,
            &points,
        ));
    }

    // Step 6: Generate IPA prover queries for each node in leaf nodes, with the same cache
    // and the same order discipline.
    let leaf_nodes: Vec<_> = leaf_nodes.into_iter().collect();
    let mut leaf_polys: Vec<Option<Arc<LagrangeBasis>>> = Vec::with_capacity(leaf_nodes.len());
    let mut leaf_missing: Vec<usize> = Vec::new();
    for (i, (parent, _)) in leaf_nodes.iter().enumerate() {
        let physical = connect_parent_id(*parent);
        let hit = parent_bytes
            .get(&physical)
            .and_then(|bytes| node_poly_cache::get(physical, bytes));
        if hit.is_none() {
            leaf_missing.push(i);
        }
        leaf_polys.push(hit);
    }
    let computed: Vec<Arc<LagrangeBasis>> = into_iter!(leaf_missing.clone())
        .map(|i| leaf_polynomial(store, leaf_nodes[i].0).map(Arc::new))
        .collect::<ProofResult<Vec<_>>>()?;
    for (&i, poly) in leaf_missing.iter().zip(computed) {
        let physical = connect_parent_id(leaf_nodes[i].0);
        if let Some(bytes) = parent_bytes.get(&physical) {
            node_poly_cache::insert(physical, *bytes, Arc::clone(&poly));
        }
        leaf_polys[i] = Some(poly);
    }
    for ((parent, points), poly) in leaf_nodes.into_iter().zip(leaf_polys) {
        let poly = poly.expect("every leaf node polynomial is resolved above");
        in_hand.insert(connect_parent_id(parent), Arc::clone(&poly));
        queries.extend(shared_prover_queries(
            parent_commitment(parent)?,
            poly,
            &points,
        ));
    }

    // Step 7: Advance the cache to the witnessed block's post-state. The queries above are
    // already built from the pre-state polynomials, so this proof is unaffected; it runs
    // here rather than after the proof so the entries land before the next block's witness
    // looks them up.
    if let Some(refresh) = refresh {
        apply_refresh(refresh_plan(refresh), &in_hand, &parent_bytes);
    }

    Ok((queries, parents_commitments, buckets_level))
}

/// Processes a leaf node to create prover queries.
#[cfg(test)]
fn process_leaf_node<Store>(
    store: &Store,
    parent: NodeId,
    parent_commitment: Element,
    points: BTreeSet<usize>,
) -> ProofResult<Vec<ProverQuery>>
where
    Store: StateReader,
{
    Ok(create_prover_queries(
        parent_commitment,
        leaf_polynomial(store, parent)?,
        points,
    ))
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
    let mut default_coefficients = if bucket_id < NUM_META_BUCKETS as BucketId {
        // Metadata buckets: initialize with default metadata hash
        vec![slot_to_field(&Some(BucketMeta::default().into())); DOMAIN_SIZE]
    } else {
        // Data buckets: initialize with empty slot hash
        vec![slot_to_field(&None); DOMAIN_SIZE]
    };

    // Replace default values with actual key-value hashes where data exists
    for (key, value) in entries {
        // Map slot ID to polynomial coefficient index (last 8 bits)
        let index = (key.slot_id() & SLOT_INDEX_MASK) as usize;
        default_coefficients[index] = slot_to_field(&Some(value));
    }

    Ok(LagrangeBasis::new(default_coefficients))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::constant::{MAIN_TRIE_LEVELS, META_BUCKET_SIZE, MIN_BUCKET_SIZE, ROOT_NODE_ID};
    use crate::proof::test_utils::*;
    use crate::{
        mem_store::MemStore,
        proof::{
            prover::{SaltProof, PRECOMPUTED_WEIGHTS},
            shape::{encode_parent, is_encoded_node},
        },
        state::state::EphemeralSaltState,
        trie::trie::{StateRoot, TrieUpdates},
        types::bucket_metadata_key,
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
        let (prover_queries, _, _) = create_sub_trie(&store, &[salt_key], None).unwrap();
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
        let (q1, _, _) = create_sub_trie(&store, &[salt_key], None).unwrap();
        assert!(verify_ipa_proof(q1.clone()));

        // Multiple keys
        let (q2, _, _) = create_sub_trie(
            &store,
            &[
                salt_key,
                SaltKey::from((salt_key.bucket_id(), salt_key.slot_id() + 1)),
            ],
            None,
        )
        .unwrap();
        assert!(verify_ipa_proof(q2));

        // Duplicate keys
        let (q3, _, _) = create_sub_trie(&store, &[salt_key, salt_key], None).unwrap();
        assert_eq!(q1.len(), q3.len());

        // Metadata bucket
        let (q4, _, b4) = create_sub_trie(&store, &[SaltKey::from((0u32, 0u64))], None).unwrap();
        assert!(verify_ipa_proof(q4));
        assert_eq!(b4[&0], 1);

        // Empty input
        let res = create_sub_trie(&store, &[], None);
        assert!(res.is_err());
    }

    #[test]
    fn process_leaf_node_with_real_commitment() {
        let (store, salt_key) = setup_test_store();
        let parent_node = STARTING_NODE_ID[3] as NodeId + salt_key.bucket_id() as u64;
        let commitment =
            Element::from_bytes_unchecked_uncompressed(store.commitment(parent_node).unwrap());
        let points = [0, salt_key.slot_id() as usize & 0xff].into();

        let queries = process_leaf_node(&store, parent_node, commitment, points).unwrap();
        assert_eq!(queries.len(), 2);
        assert!(verify_ipa_proof(queries));
    }

    #[test]
    fn process_leaf_node_uses_metadata_default_for_meta_bucket() {
        let store = MemStore::new();
        let parent_node = STARTING_NODE_ID[3] as NodeId;
        let commitment =
            Element::from_bytes_unchecked_uncompressed(default_commitment(parent_node));
        let queries = process_leaf_node(&store, parent_node, commitment, [0, 255].into()).unwrap();
        let metadata_default = slot_to_field(&Some(BucketMeta::default().into()));

        assert_eq!(
            queries.iter().map(|q| q.point).collect::<Vec<_>>(),
            vec![0, 255]
        );
        assert!(queries.iter().all(|q| q.result == metadata_default));
    }

    #[test]
    fn process_leaf_node_uses_empty_default_for_data_bucket() {
        let store = MemStore::new();
        let parent_node = STARTING_NODE_ID[3] as NodeId + NUM_META_BUCKETS as NodeId;
        let commitment =
            Element::from_bytes_unchecked_uncompressed(default_commitment(parent_node));
        let queries = process_leaf_node(&store, parent_node, commitment, [0, 255].into()).unwrap();
        let empty_default = slot_to_field(&None);

        assert_eq!(
            queries.iter().map(|q| q.point).collect::<Vec<_>>(),
            vec![0, 255]
        );
        assert!(queries.iter().all(|q| q.result == empty_default));
    }

    #[test]
    fn multi_commitments_to_scalars_empty_and_single_node() {
        let store = MemStore::new();

        // Empty input
        assert_eq!(multi_commitments_to_scalars(&store, &[]).unwrap().len(), 0);

        // Single internal node
        let node_points = vec![(STARTING_NODE_ID[2] as NodeId, [0, 1].into())];
        let scalars = multi_commitments_to_scalars(&store, &node_points).unwrap();
        assert_eq!(scalars.len(), DOMAIN_SIZE);
    }

    #[test]
    fn multi_commitments_to_scalars_root_defaults_are_pinned() {
        let store = MemStore::new();
        let scalars =
            multi_commitments_to_scalars(&store, &[(ROOT_NODE_ID, [0, 1, 255].into())]).unwrap();
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
        let result = create_sub_trie(&store, &[invalid_meta_key], None);
        assert!(matches!(result, Err(ProofError::InvalidSaltKey { .. })));

        // Invalid data bucket key (slot_id >= capacity)
        let data_bucket_id = NUM_META_BUCKETS as u32;
        let invalid_data_key = SaltKey::from((data_bucket_id, 1000u64));
        let result = create_sub_trie(&store, &[invalid_data_key], None);
        assert!(matches!(result, Err(ProofError::InvalidSaltKey { .. })));

        // Valid keys should work
        let valid_meta_key = SaltKey::from((0u32, 0u64));
        let result = create_sub_trie(&store, &[valid_meta_key], None);
        assert!(result.is_ok());
    }

    /// Applies one block's transition to `store` and returns its trie updates.
    fn apply_block(store: &MemStore, updates: StateUpdates) -> TrieUpdates {
        let (_, trie_updates) = StateRoot::new(store).update_fin(&updates).unwrap();
        store.update_state(updates);
        store.update_trie(trie_updates.clone());
        trie_updates
    }

    /// A store holding block A (64 random plain kvs), and block B's transition over it (16
    /// value updates, 8 deletes and 16 inserts) computed but not applied.
    fn two_block_fixture(seed: u64) -> (MemStore, StateUpdates, TrieUpdates) {
        let mut rng = StdRng::seed_from_u64(seed);
        let kvs_a: HashMap<Vec<u8>, Option<Vec<u8>>> = (0..64)
            .map(|_| (mock_data(&mut rng, 20), Some(mock_data(&mut rng, 40))))
            .collect();
        let store = MemStore::new();
        let updates_a = EphemeralSaltState::new(&store).update_fin(&kvs_a).unwrap();
        apply_block(&store, updates_a);

        let mut keys_a: Vec<Vec<u8>> = kvs_a.into_keys().collect();
        keys_a.sort();
        let mut kvs_b: HashMap<Vec<u8>, Option<Vec<u8>>> = HashMap::new();
        for key in &keys_a[..16] {
            kvs_b.insert(key.clone(), Some(mock_data(&mut rng, 40)));
        }
        for key in &keys_a[16..24] {
            kvs_b.insert(key.clone(), None);
        }
        for _ in 0..16 {
            kvs_b.insert(mock_data(&mut rng, 20), Some(mock_data(&mut rng, 40)));
        }
        let updates_b = EphemeralSaltState::new(&store).update_fin(&kvs_b).unwrap();
        let (_, trie_b) = StateRoot::new(&store).update_fin(&updates_b).unwrap();
        (store, updates_b, trie_b)
    }

    /// Whether `node` is a leaf of its trie: a main-trie bucket root or a subtree leaf.
    fn is_leaf_node(node: NodeId) -> bool {
        let leaf_level = if node >> BUCKET_SLOT_BITS == 0 {
            MAIN_TRIE_LEVELS - 1
        } else {
            MAX_SUBTREE_LEVELS - 1
        };
        !is_encoded_node(node) && get_bfs_level(get_local_number(node)) == leaf_level
    }

    /// The polynomial a witness rebuilds from storage for `node`; the root of an expanded
    /// bucket is passed encoded, as `parents_and_points` keys it.
    fn rebuilt_polynomial(store: &MemStore, node: NodeId) -> LagrangeBasis {
        if is_leaf_node(node) {
            leaf_polynomial(store, node).unwrap()
        } else {
            LagrangeBasis::new(
                multi_commitments_to_scalars(store, &[(node, BTreeSet::new())]).unwrap(),
            )
        }
    }

    /// The `(old, new)` pair `trie_updates` records for `node`.
    fn transition(trie_updates: &TrieUpdates, node: NodeId) -> (CommitmentBytes, CommitmentBytes) {
        trie_updates
            .iter()
            .find(|(id, _)| *id == node)
            .unwrap_or_else(|| panic!("node {node} is not in the transition"))
            .1
    }

    /// The nodes of a transition, and the parents of a plan.
    fn node_set<'a>(nodes: impl IntoIterator<Item = &'a NodeId>) -> BTreeSet<NodeId> {
        nodes.into_iter().copied().collect()
    }

    /// The patched positions the plan holds for `node`.
    fn planned_positions(plan: &FxHashMap<NodeId, ParentPatch>, node: NodeId) -> BTreeSet<usize> {
        plan[&node].positions.iter().map(|(i, _)| *i).collect()
    }

    /// The cache entry of `node` under its post-block commitment.
    ///
    /// A main-trie bucket root or a subtree node belongs to this fixture's bucket alone, so
    /// its entry must be there. The upper main-trie levels are shared by every test in the
    /// process, and another fixture's witness may have replaced such an entry with its own
    /// commitment in the meantime (a miss, never a wrong entry): those are checked when
    /// present.
    fn refreshed(node: NodeId, new: &CommitmentBytes) -> Option<Arc<LagrangeBasis>> {
        let entry = node_poly_cache::get(node, new);
        let bucket_local = node >> BUCKET_SLOT_BITS != 0
            || get_bfs_level(get_local_number(node)) == MAIN_TRIE_LEVELS - 1;
        assert!(
            entry.is_some() || !bucket_local,
            "node {node} was not refreshed"
        );
        entry
    }

    /// Whether `node` is the main-trie root of a data bucket. Fixtures do not share one: random
    /// keys spread over sixteen million buckets, and hand-picked buckets differ between tests.
    /// Its cache entry is therefore the current test's own, while every other class of node
    /// (upper main-trie levels, metadata leaves) is shared with the rest of the process and
    /// checked only when present.
    fn is_data_bucket_root(node: NodeId) -> bool {
        node >> BUCKET_SLOT_BITS == 0 && node >= bucket_root_node_id(NUM_META_BUCKETS as BucketId)
    }

    /// Every changed node is planned with its own transition, and every entry the refresh
    /// inserts equals the polynomial a rebuild from the post-block store produces, for
    /// main-trie leaves and internal nodes alike.
    #[test]
    fn refreshed_polynomials_equal_a_storage_rebuild() {
        let (store, updates_b, trie_b) = two_block_fixture(1);
        let keys: Vec<SaltKey> = updates_b.data.keys().copied().collect();
        let refresh = NodePolyRefresh {
            trie_updates: &trie_b,
            state_updates: &updates_b,
        };
        let plan = refresh_plan(&refresh);
        assert_eq!(
            node_set(plan.keys()),
            node_set(trie_b.iter().map(|(node, _)| node))
        );
        for &(node, (old, new)) in &trie_b {
            assert_eq!(
                (plan[&node].old, plan[&node].new),
                (old, new),
                "node {node}"
            );
        }
        let (queries, _, _) = create_sub_trie(&store, &keys, Some(&refresh)).unwrap();
        assert!(verify_ipa_proof(queries));

        store.update_state(updates_b);
        store.update_trie(trie_b.clone());
        let (mut leaves, mut internal) = (0, 0);
        for &(node, (_, new)) in &trie_b {
            let Some(entry) = refreshed(node, &new) else {
                continue;
            };
            assert_eq!(*entry, rebuilt_polynomial(&store, node), "node {node}");
            if is_leaf_node(node) {
                leaves += 1;
            } else {
                internal += 1;
            }
        }
        assert!(
            leaves >= 1 && internal >= 1,
            "{leaves} leaves, {internal} internal nodes"
        );
    }

    /// In an expanded bucket the refresh keys the subtree top under the bucket root, every
    /// other subtree node under its own id and every slot under its subtree leaf.
    #[test]
    fn refresh_covers_expanded_bucket_subtrees() {
        let store = MemStore::new();
        let bucket = NUM_META_BUCKETS as BucketId + 3 * MIN_BUCKET_SIZE as BucketId + 7;
        let capacity = 131072u64;
        let value = |byte: u8| Some(SaltValue::new(&[byte; 32], &[byte; 32]));
        let meta = |capacity| {
            Some(SaltValue::from(BucketMeta {
                capacity,
                ..BucketMeta::default()
            }))
        };
        let key = |slot| SaltKey::from((bucket, slot));

        // Block A: two slots, then an expansion to a three-level subtree (top at level 2).
        apply_block(
            &store,
            StateUpdates {
                data: [(key(3), (None, value(1))), (key(5), (None, value(2)))]
                    .into_iter()
                    .collect(),
            },
        );
        apply_block(
            &store,
            StateUpdates {
                data: [
                    (
                        bucket_metadata_key(bucket),
                        (meta(MIN_BUCKET_SIZE as u64), meta(capacity)),
                    ),
                    (key(3), (value(1), None)),
                    (key(2049), (None, value(3))),
                    (key(capacity - 259), (None, value(4))),
                    (key(capacity - 1), (None, value(5))),
                ]
                .into_iter()
                .collect(),
            },
        );

        // Block B: two segments under two different subtree children, capacity unchanged.
        let updates_b = StateUpdates {
            data: [
                (key(2049), (value(3), value(13))),
                (key(2050), (None, value(14))),
                (key(capacity - 259), (value(4), value(15))),
            ]
            .into_iter()
            .collect(),
        };
        let (_, trie_b) = StateRoot::new(&store).update_fin(&updates_b).unwrap();
        let keys: Vec<SaltKey> = updates_b.data.keys().copied().collect();
        let refresh = NodePolyRefresh {
            trie_updates: &trie_b,
            state_updates: &updates_b,
        };

        // The plan keys the top under the bucket root and patches exactly the changed
        // children and slots at their positions.
        let root = bucket_root_node_id(bucket);
        let parent = get_parent_node(&root);
        let leaf = |slot| subtree_leaf_for_key(&key(slot));
        let plan = refresh_plan(&refresh);
        assert_eq!(
            node_set(plan.keys()),
            node_set(trie_b.iter().map(|(node, _)| node))
        );
        assert_eq!(planned_positions(&plan, root), [0, 1].into());
        assert_eq!(
            planned_positions(&plan, get_parent_node(&leaf(2049))),
            [8].into()
        );
        assert_eq!(
            planned_positions(&plan, get_parent_node(&leaf(capacity - 259))),
            [254].into()
        );
        assert_eq!(planned_positions(&plan, leaf(2049)), [1, 2].into());
        assert_eq!(planned_positions(&plan, leaf(capacity - 259)), [253].into());
        assert_eq!(
            planned_positions(&plan, parent),
            [vc_position_in_parent(&root)].into()
        );

        let (queries, _, _) = create_sub_trie(&store, &keys, Some(&refresh)).unwrap();
        assert!(verify_ipa_proof(queries));

        store.update_state(updates_b);
        store.update_trie(trie_b.clone());
        let (_, new_root) = transition(&trie_b, root);
        assert_eq!(
            *refreshed(root, &new_root).unwrap(),
            rebuilt_polynomial(&store, encode_parent(root, 3)),
            "subtree top under the bucket root"
        );
        let (mut internal, mut leaves) = (0, 0);
        for &(node, (_, new)) in &trie_b {
            if node >> BUCKET_SLOT_BITS == 0 {
                continue;
            }
            if is_leaf_node(node) {
                leaves += 1;
            } else {
                internal += 1;
            }
            assert_eq!(
                *refreshed(node, &new).unwrap(),
                rebuilt_polynomial(&store, node),
                "subtree node {node}"
            );
        }
        assert_eq!((internal, leaves), (2, 2));
        let (_, new_parent) = transition(&trie_b, parent);
        if let Some(entry) = refreshed(parent, &new_parent) {
            assert_eq!(
                *entry,
                rebuilt_polynomial(&store, parent),
                "main-trie parent of the bucket root"
            );
        }
    }

    /// A bucket whose capacity changes is frozen for the block: nothing inside it is
    /// refreshed, while its root's position in the main trie and the metadata leaf are; the
    /// next witness over the bucket rebuilds from storage.
    #[test]
    fn refresh_skips_buckets_whose_capacity_changed() {
        let store = MemStore::new();
        let bucket = NUM_META_BUCKETS as BucketId + 5 * MIN_BUCKET_SIZE as BucketId + 9;
        let value = |byte: u8| Some(SaltValue::new(&[byte; 32], &[byte; 32]));
        let meta = |capacity| {
            Some(SaltValue::from(BucketMeta {
                capacity,
                ..BucketMeta::default()
            }))
        };
        let key = |slot| SaltKey::from((bucket, slot));
        let meta_key = bucket_metadata_key(bucket);
        let root = bucket_root_node_id(bucket);
        let parent = get_parent_node(&root);
        let meta_root = bucket_root_node_id(meta_key.bucket_id());

        apply_block(
            &store,
            StateUpdates {
                data: [(key(3), (None, value(1))), (key(5), (None, value(2)))]
                    .into_iter()
                    .collect(),
            },
        );

        // Witnesses `witnessed` against the current store with the block's refresh, applies
        // the block and checks what was and was not refreshed.
        let run = |updates: StateUpdates, witnessed: &[SaltKey]| {
            let (_, trie_updates) = StateRoot::new(&store).update_fin(&updates).unwrap();
            let refresh = NodePolyRefresh {
                trie_updates: &trie_updates,
                state_updates: &updates,
            };
            let plan = refresh_plan(&refresh);
            assert!(
                plan.keys()
                    .all(|&node| node != root && node >> BUCKET_SLOT_BITS == 0),
                "the frozen bucket was planned"
            );
            assert_eq!(
                planned_positions(&plan, parent),
                [vc_position_in_parent(&root)].into()
            );
            assert_eq!(
                planned_positions(&plan, meta_root),
                [(meta_key.slot_id() & SLOT_INDEX_MASK) as usize].into()
            );

            let (queries, _, _) = create_sub_trie(&store, witnessed, Some(&refresh)).unwrap();
            assert!(verify_ipa_proof(queries));
            store.update_state(updates);
            store.update_trie(trie_updates.clone());

            let (_, new_root) = transition(&trie_updates, root);
            assert!(
                node_poly_cache::get(root, &new_root).is_none(),
                "the frozen bucket's root was refreshed"
            );
            for &(node, (_, new)) in &trie_updates {
                if node >> BUCKET_SLOT_BITS != 0 {
                    assert!(
                        node_poly_cache::get(node, &new).is_none(),
                        "subtree node {node} of the frozen bucket was refreshed"
                    );
                }
            }
            let (_, new_meta_root) = transition(&trie_updates, meta_root);
            assert_eq!(
                *refreshed(meta_root, &new_meta_root).unwrap(),
                rebuilt_polynomial(&store, meta_root),
                "metadata leaf"
            );
            let (_, new_parent) = transition(&trie_updates, parent);
            if let Some(entry) = refreshed(parent, &new_parent) {
                assert_eq!(
                    *entry,
                    rebuilt_polynomial(&store, parent),
                    "main-trie parent of the bucket root"
                );
            }
        };

        // Block B doubles the capacity, deleting one slot and inserting one beyond the old
        // capacity; the witness covers only slots below the old capacity.
        run(
            StateUpdates {
                data: [
                    (
                        meta_key,
                        (
                            meta(MIN_BUCKET_SIZE as u64),
                            meta(2 * MIN_BUCKET_SIZE as u64),
                        ),
                    ),
                    (key(3), (value(1), None)),
                    (key(300), (None, value(3))),
                ]
                .into_iter()
                .collect(),
            },
            &[meta_key, key(3), key(5)],
        );
        let (queries, _, _) = create_sub_trie(&store, &[key(5), key(300)], None).unwrap();
        assert!(verify_ipa_proof(queries));

        // Block C contracts it back, removing the slot beyond the new capacity.
        run(
            StateUpdates {
                data: [
                    (
                        meta_key,
                        (
                            meta(2 * MIN_BUCKET_SIZE as u64),
                            meta(MIN_BUCKET_SIZE as u64),
                        ),
                    ),
                    (key(300), (value(3), None)),
                ]
                .into_iter()
                .collect(),
            },
            &[meta_key, key(5)],
        );
        let (queries, _, _) = create_sub_trie(&store, &[key(5)], None).unwrap();
        assert!(verify_ipa_proof(queries));
    }

    /// A retried witness re-applies the block's refresh: its lookups miss on the re-keyed
    /// entries, rebuild from the pre-block store and refresh again to the same entries, and
    /// the proof bytes do not change.
    #[test]
    fn refresh_is_idempotent_across_a_retried_witness() {
        let (store, updates_b, trie_b) = two_block_fixture(2);
        let keys: Vec<SaltKey> = updates_b.data.keys().copied().collect();
        let refresh = NodePolyRefresh {
            trie_updates: &trie_b,
            state_updates: &updates_b,
        };
        let build = || {
            SaltProof::create_with_refresh(keys.iter().copied(), &store, Some(&refresh)).unwrap()
        };
        let encode = |proof: &SaltProof| {
            bincode::serde::encode_to_vec(proof, bincode::config::legacy()).unwrap()
        };

        let first = encode(&build());
        let entries: Vec<Option<Arc<LagrangeBasis>>> = trie_b
            .iter()
            .map(|&(node, (_, new))| refreshed(node, &new))
            .collect();
        let second = encode(&build());
        assert_eq!(
            first, second,
            "a re-applied refresh must not change the proof"
        );
        let mut compared = 0;
        for (&(node, (_, new)), before) in trie_b.iter().zip(entries) {
            if let (Some(after), Some(before)) = (refreshed(node, &new), before) {
                assert_eq!(*after, *before, "node {node}");
                compared += 1;
            }
        }
        assert!(compared >= 1);
    }

    /// The debug self-check rejects a transition whose new commitment is not what the patched
    /// positions commit to.
    #[cfg(debug_assertions)]
    #[test]
    #[should_panic(expected = "does not commit")]
    fn refresh_debug_check_rejects_an_inconsistent_transition() {
        let (store, updates_b, mut trie_b) = two_block_fixture(3);
        let foreign = trie_b
            .iter()
            .find(|(node, _)| *node != ROOT_NODE_ID)
            .unwrap()
            .1
             .1;
        trie_b
            .iter_mut()
            .find(|(node, _)| *node == ROOT_NODE_ID)
            .unwrap()
            .1
             .1 = foreign;
        let keys: Vec<SaltKey> = updates_b.data.keys().copied().collect();
        let refresh = NodePolyRefresh {
            trie_updates: &trie_b,
            state_updates: &updates_b,
        };
        let _ = create_sub_trie(&store, &keys, Some(&refresh));
    }

    /// The debug self-check rejects a slot whose new value is not what its leaf's new
    /// commitment was computed from.
    #[cfg(debug_assertions)]
    #[test]
    #[should_panic(expected = "does not commit")]
    fn refresh_debug_check_rejects_a_wrong_slot_value() {
        let (store, mut updates_b, trie_b) = two_block_fixture(4);
        let key = *updates_b
            .data
            .iter()
            .find(|(key, (_, new))| !key.is_in_meta_bucket() && new.is_some())
            .unwrap()
            .0;
        updates_b.data.get_mut(&key).unwrap().1 = Some(SaltValue::new(&[9; 20], &[9; 40]));
        let keys: Vec<SaltKey> = updates_b.data.keys().copied().collect();
        let refresh = NodePolyRefresh {
            trie_updates: &trie_b,
            state_updates: &updates_b,
        };
        let _ = create_sub_trie(&store, &keys, Some(&refresh));
    }

    /// A planned parent the witness did not read takes its base from the cache's entry for its
    /// old commitment, and is skipped while the cache holds none: after a refresh whose witness
    /// covered one bucket, the other changed buckets' roots are absent under their new
    /// commitment, and present, equal to the post-block rebuild, once a witness over the
    /// pre-state has cached their bases.
    #[test]
    fn refresh_uses_cached_bases_for_parents_the_witness_did_not_read() {
        let (store, updates_b, trie_b) = two_block_fixture(5);
        let keys: Vec<SaltKey> = updates_b.data.keys().copied().collect();
        let refresh = NodePolyRefresh {
            trie_updates: &trie_b,
            state_updates: &updates_b,
        };
        let bucket = keys
            .iter()
            .find(|key| !key.is_in_meta_bucket())
            .unwrap()
            .bucket_id();
        let witnessed: Vec<SaltKey> = keys
            .iter()
            .copied()
            .filter(|key| key.bucket_id() == bucket)
            .collect();
        let unread_roots: Vec<(NodeId, CommitmentBytes)> = trie_b
            .iter()
            .filter(|&&(node, _)| is_data_bucket_root(node) && node != bucket_root_node_id(bucket))
            .map(|&(node, (_, new))| (node, new))
            .collect();
        assert!(
            unread_roots.len() >= 8,
            "{} unread roots",
            unread_roots.len()
        );

        // Nothing holds those roots' pre-state polynomials yet, so they are skipped.
        let (queries, _, _) = create_sub_trie(&store, &witnessed, Some(&refresh)).unwrap();
        assert!(verify_ipa_proof(queries));
        for &(node, new) in &unread_roots {
            assert!(
                node_poly_cache::get(node, &new).is_none(),
                "node {node} was refreshed without a base"
            );
        }

        // A witness over the pre-state caches every parent under its old commitment.
        create_sub_trie(&store, &keys, None).unwrap();
        let (queries, _, _) = create_sub_trie(&store, &witnessed, Some(&refresh)).unwrap();
        assert!(verify_ipa_proof(queries));

        store.update_state(updates_b);
        store.update_trie(trie_b.clone());
        for &(node, new) in &unread_roots {
            let entry = node_poly_cache::get(node, &new)
                .unwrap_or_else(|| panic!("node {node} was not refreshed from its cached base"));
            assert_eq!(*entry, rebuilt_polynomial(&store, node), "node {node}");
        }
        for &(node, (_, new)) in &trie_b {
            if let Some(entry) = node_poly_cache::get(node, &new) {
                assert_eq!(*entry, rebuilt_polynomial(&store, node), "node {node}");
            }
        }
    }

    /// Every planned parent whose base is in hand at its old commitment is applied: the
    /// refresh inserts one entry per planned parent, skipping none, and each entry equals the
    /// polynomial a rebuild from the post-block store produces.
    #[test]
    fn refresh_applies_every_planned_parent() {
        let (store, updates_b, trie_b) = two_block_fixture(9);
        let refresh = NodePolyRefresh {
            trie_updates: &trie_b,
            state_updates: &updates_b,
        };
        let plan = refresh_plan(&refresh);
        let planned = plan.len();
        let mut in_hand = FxHashMap::default();
        let mut parent_bytes = FxHashMap::default();
        for &node in plan.keys() {
            in_hand.insert(node, Arc::new(rebuilt_polynomial(&store, node)));
            parent_bytes.insert(node, store.commitment(node).unwrap());
        }
        assert_eq!(apply_refresh(plan, &in_hand, &parent_bytes), planned);

        store.update_state(updates_b);
        store.update_trie(trie_b.clone());
        for &(node, (_, new)) in &trie_b {
            let entry = node_poly_cache::get(node, &new);
            assert!(
                entry.is_some() || !is_data_bucket_root(node),
                "node {node} was not refreshed"
            );
            if let Some(entry) = entry {
                assert_eq!(*entry, rebuilt_polynomial(&store, node), "node {node}");
            }
        }
    }

    /// The witness must read the transition's pre-state: over the post-state store every
    /// parent is read at its new commitment, which the debug guard rejects before any entry
    /// is derived from it.
    #[cfg(debug_assertions)]
    #[test]
    #[should_panic(expected = "other than the refresh's pre-state")]
    fn refresh_rejects_a_witness_over_the_post_state() {
        let (store, updates_b, trie_b) = two_block_fixture(6);
        let keys: Vec<SaltKey> = updates_b.data.keys().copied().collect();
        store.update_state(updates_b.clone());
        store.update_trie(trie_b.clone());
        let refresh = NodePolyRefresh {
            trie_updates: &trie_b,
            state_updates: &updates_b,
        };
        let _ = create_sub_trie(&store, &keys, Some(&refresh));
    }

    /// A parent the witness read at a commitment other than the refresh's old one is skipped,
    /// never patched: a witness over the pre-B view carrying block C's transition (whose old
    /// commitments are B's) leaves the bucket root absent under C's commitment, and inserts
    /// nothing that differs from the post-C rebuild. Debug builds reject such a witness
    /// outright instead (`refresh_rejects_a_witness_over_the_post_state`).
    #[cfg(not(debug_assertions))]
    #[test]
    fn refresh_skips_a_parent_read_at_a_foreign_commitment() {
        let store = MemStore::new();
        let bucket = NUM_META_BUCKETS as BucketId + 7 * MIN_BUCKET_SIZE as BucketId + 11;
        let value = |byte: u8| Some(SaltValue::new(&[byte; 32], &[byte; 32]));
        let key = |slot| SaltKey::from((bucket, slot));

        // Blocks A and B change slot 3; block C, computed over B, changes slot 5.
        apply_block(
            &store,
            StateUpdates {
                data: [(key(3), (None, value(1))), (key(5), (None, value(2)))]
                    .into_iter()
                    .collect(),
            },
        );
        let pre_b = store.clone();
        apply_block(
            &store,
            StateUpdates {
                data: [(key(3), (value(1), value(3)))].into_iter().collect(),
            },
        );
        let updates_c = StateUpdates {
            data: [(key(5), (value(2), value(4)))].into_iter().collect(),
        };
        let (_, trie_c) = StateRoot::new(&store).update_fin(&updates_c).unwrap();
        let refresh = NodePolyRefresh {
            trie_updates: &trie_c,
            state_updates: &updates_c,
        };

        let (queries, _, _) = create_sub_trie(&pre_b, &[key(3), key(5)], Some(&refresh)).unwrap();
        assert!(verify_ipa_proof(queries));

        store.update_state(updates_c);
        store.update_trie(trie_c.clone());
        let root = bucket_root_node_id(bucket);
        let (_, new_root) = transition(&trie_c, root);
        assert!(
            node_poly_cache::get(root, &new_root).is_none(),
            "a parent read at a foreign commitment was patched"
        );
        for &(node, (_, new)) in &trie_c {
            if let Some(entry) = node_poly_cache::get(node, &new) {
                assert_eq!(*entry, rebuilt_polynomial(&store, node), "node {node}");
            }
        }
    }

    /// A metadata change that keeps the capacity (a rehash under a new nonce) does not freeze
    /// the bucket: over a two-level, 512-slot subtree the moved slots are patched in their
    /// leaves, the changed leaves in the top under the bucket root, and the metadata leaf at
    /// the bucket's slot.
    #[test]
    fn refresh_patches_a_rehashed_bucket_with_unchanged_capacity() {
        let store = MemStore::new();
        let bucket = NUM_META_BUCKETS as BucketId + 9 * MIN_BUCKET_SIZE as BucketId + 13;
        let capacity = 2 * MIN_BUCKET_SIZE as u64;
        let value = |byte: u8| Some(SaltValue::new(&[byte; 32], &[byte; 32]));
        let meta = |nonce| {
            Some(SaltValue::from(BucketMeta {
                nonce,
                capacity,
                ..BucketMeta::default()
            }))
        };
        let key = |slot| SaltKey::from((bucket, slot));
        let meta_key = bucket_metadata_key(bucket);
        let root = bucket_root_node_id(bucket);
        let meta_root = bucket_root_node_id(meta_key.bucket_id());

        // Block A: a 512-slot bucket holding two values in its first leaf and one in its
        // second.
        apply_block(
            &store,
            StateUpdates {
                data: [
                    (meta_key, (Some(BucketMeta::default().into()), meta(0))),
                    (key(3), (None, value(1))),
                    (key(5), (None, value(2))),
                    (key(300), (None, value(3))),
                ]
                .into_iter()
                .collect(),
            },
        );

        // Block B: a rehash under a new nonce moves the values, capacity unchanged.
        let updates_b = EphemeralSaltState::new(&store)
            .set_nonce(bucket, 1)
            .unwrap();
        assert_eq!(updates_b.data[&meta_key], (meta(0), meta(1)));
        let (_, trie_b) = StateRoot::new(&store).update_fin(&updates_b).unwrap();
        let refresh = NodePolyRefresh {
            trie_updates: &trie_b,
            state_updates: &updates_b,
        };

        // Every changed node is planned; the leaves at their moved slots, the top at the
        // changed leaves, the metadata leaf at the bucket's slot.
        let mut moved: BTreeMap<NodeId, BTreeSet<usize>> = BTreeMap::new();
        for key in updates_b.data.keys().filter(|key| !key.is_in_meta_bucket()) {
            moved
                .entry(subtree_leaf_for_key(key))
                .or_default()
                .insert((key.slot_id() & SLOT_INDEX_MASK) as usize);
        }
        assert_eq!(moved.len(), 2, "both leaves change");
        let plan = refresh_plan(&refresh);
        assert_eq!(
            node_set(plan.keys()),
            node_set(trie_b.iter().map(|(node, _)| node))
        );
        for (leaf, slots) in &moved {
            assert_eq!(planned_positions(&plan, *leaf), *slots, "leaf {leaf}");
        }
        assert_eq!(
            planned_positions(&plan, root),
            moved.keys().map(vc_position_in_parent).collect()
        );
        assert_eq!(
            planned_positions(&plan, meta_root),
            [(meta_key.slot_id() & SLOT_INDEX_MASK) as usize].into()
        );

        let keys: Vec<SaltKey> = updates_b.data.keys().copied().collect();
        let (queries, _, _) = create_sub_trie(&store, &keys, Some(&refresh)).unwrap();
        assert!(verify_ipa_proof(queries));

        store.update_state(updates_b);
        store.update_trie(trie_b.clone());
        let (_, new_root) = transition(&trie_b, root);
        assert_eq!(
            *refreshed(root, &new_root).unwrap(),
            rebuilt_polynomial(&store, encode_parent(root, 2)),
            "subtree top under the bucket root"
        );
        for leaf in moved.keys() {
            let (_, new) = transition(&trie_b, *leaf);
            assert_eq!(
                *refreshed(*leaf, &new).unwrap(),
                rebuilt_polynomial(&store, *leaf),
                "leaf {leaf}"
            );
        }
        let (_, new_meta_root) = transition(&trie_b, meta_root);
        if let Some(entry) = node_poly_cache::get(meta_root, &new_meta_root) {
            assert_eq!(
                *entry,
                rebuilt_polynomial(&store, meta_root),
                "metadata leaf"
            );
        }
    }
}
