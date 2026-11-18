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
    trie::{
        node_utils::{get_child_node, subtree_leaf_start_key, subtree_root_level},
        trie::shared_committer,
    },
    types::{BucketId, BucketMeta, CommitmentBytes, NodeId, SaltKey},
    SlotId,
};
use banderwagon::{multi_scalar_mul, Element, Fr, PrimeField, Zero};
use ipa_multipoint::{lagrange_basis::LagrangeBasis, multiproof::ProverQuery};

use salt_macros::prelude::*;
use salt_macros::{chunks, iter, reduce, thread_chunk_size};
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
/// rate worth the memory: by default at most 32768 polynomials of 8 KiB each, 256 MiB
/// ([`NodePolyCache::set_capacity`]). A full shard evicts one polynomial per new node and
/// passes over those used since it last considered them, so the paths that proof after
/// proof walks outlive the leaves a single proof touched.
///
/// The commitment key only holds if the polynomial really opens to that commitment, which a
/// store that is not a consistent snapshot (commitments and children or slots from different
/// states) does not guarantee. Callers should still keep the store unchanged while a proof is
/// created, since such a proof will not verify; but an inconsistent store must not poison the
/// cache for consistent ones, so a rebuilt polynomial is cached only once it is shown to open
/// to the commitment it was read at: one check for all the polynomials a call rebuilds
/// ([`batch_opens`]), and one per polynomial only when that fails. One that does not open is
/// used for this proof and dropped.
mod node_poly_cache {
    use super::*;
    use crate::{Lazy, RwLock};
    use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    pub(super) const SHARDS: usize = 64;

    /// One cached polynomial, with the node it belongs to and the commitment it was built
    /// for.
    struct Slot {
        node: NodeId,
        commitment: CommitmentBytes,
        poly: Arc<LagrangeBasis>,
        /// Set when the polynomial is served or the node is cached again, cleared when the
        /// eviction hand passes: a polynomial is evicted only when the hand comes round and
        /// finds it unused since.
        used: AtomicBool,
    }

    /// One shard: its polynomials, which slot holds which node, and the slot the next
    /// eviction considers first (taken modulo the number of slots).
    #[derive(Default)]
    struct Shard {
        slots: Vec<Slot>,
        index: FxHashMap<NodeId, usize>,
        hand: usize,
    }

    /// The cache of node polynomials that proof and witness creation share across calls: see
    /// [`NodePolyCache::global`] for the one instance a process has.
    ///
    /// A cached polynomial saves the store reads and scalar conversions that rebuild it, and
    /// costs 8 KiB while it is kept. The default bound suits a process that proves block
    /// after block; one that creates a single proof, or cannot spare the memory, can lower it
    /// or turn the cache off with [`set_capacity`](Self::set_capacity).
    pub struct NodePolyCache {
        shards: Vec<RwLock<Shard>>,
        max_per_shard: AtomicUsize,
    }

    static CACHE: Lazy<NodePolyCache> =
        Lazy::new(|| NodePolyCache::with_capacity(NodePolyCache::DEFAULT_CAPACITY));

    impl NodePolyCache {
        /// The bound a cache starts with: 32768 polynomials, 256 MiB.
        pub const DEFAULT_CAPACITY: usize = SHARDS * 512;

        /// The cache every proof and witness creation in this process reads and fills.
        pub fn global() -> &'static Self {
            &CACHE
        }

        /// The most polynomials the cache holds, at 8 KiB each.
        pub fn capacity(&self) -> usize {
            self.max_per_shard.load(Ordering::Relaxed) * SHARDS
        }

        /// Bounds the cache to `polynomials` entries, rounded up to a multiple of its 64
        /// shards. Zero turns it off: nothing is cached, and proof creation skips the check
        /// that caching a polynomial needs. A shard that holds more than its new share is
        /// emptied.
        pub fn set_capacity(&self, polynomials: usize) {
            let max = polynomials.div_ceil(SHARDS);
            // Stored before the shards are trimmed: `insert` reads it under the shard lock,
            // so an insert that follows a shard's trim sees the new bound.
            self.max_per_shard.store(max, Ordering::Relaxed);
            for shard in &self.shards {
                let mut guard = shard.write();
                let trimmed = (guard.slots.len() > max).then(|| core::mem::take(&mut *guard));
                drop(guard);
                drop(trimmed);
            }
        }

        /// Drops every cached polynomial, each shard's after its lock is released.
        pub fn clear(&self) {
            for shard in &self.shards {
                let mut guard = shard.write();
                let dropped = core::mem::take(&mut *guard);
                drop(guard);
                drop(dropped);
            }
        }

        pub(super) fn with_capacity(polynomials: usize) -> Self {
            Self {
                shards: (0..SHARDS).map(|_| RwLock::new(Shard::default())).collect(),
                max_per_shard: AtomicUsize::new(polynomials.div_ceil(SHARDS)),
            }
        }

        fn shard(&self, node: NodeId) -> &RwLock<Shard> {
            &self.shards[(node % SHARDS as NodeId) as usize]
        }

        /// The nodes the cache holds, in ascending order. Unlike `get`, looking does not
        /// count as a use.
        #[cfg(test)]
        pub(super) fn nodes(&self) -> Vec<NodeId> {
            let mut nodes: Vec<NodeId> = self
                .shards
                .iter()
                .flat_map(|shard| shard.read().index.keys().copied().collect::<Vec<_>>())
                .collect();
            nodes.sort_unstable();
            nodes
        }

        /// The cached polynomial of `node`, if it was built for exactly this commitment.
        pub(super) fn get(
            &self,
            node: NodeId,
            commitment: &CommitmentBytes,
        ) -> Option<Arc<LagrangeBasis>> {
            let shard = self.shard(node).read();
            let slot = &shard.slots[*shard.index.get(&node)?];
            if slot.commitment != *commitment {
                return None;
            }
            // Written only when it changes, so the readers of a polynomial every proof uses
            // do not pass its cache line back and forth.
            if !slot.used.load(Ordering::Relaxed) {
                slot.used.store(true, Ordering::Relaxed);
            }
            Some(Arc::clone(&slot.poly))
        }

        pub(super) fn insert(
            &self,
            node: NodeId,
            commitment: CommitmentBytes,
            poly: Arc<LagrangeBasis>,
        ) {
            let mut guard = self.shard(node).write();
            let max = self.max_per_shard.load(Ordering::Relaxed);
            if max == 0 {
                return;
            }
            let shard = &mut *guard;
            let slot = |used| Slot {
                node,
                commitment,
                poly,
                used: AtomicBool::new(used),
            };
            // Whatever the insert replaces or evicts is dropped after the lock is released,
            // so readers do not wait on the free.
            let dropped = if let Some(&at) = shard.index.get(&node) {
                // A node cached again was resolved again, which is a use.
                Some(core::mem::replace(&mut shard.slots[at], slot(true)))
            } else if shard.slots.len() < max {
                shard.index.insert(node, shard.slots.len());
                shard.slots.push(slot(false));
                None
            } else {
                // The hand passes over the polynomials used since its last visit, clearing
                // their mark, and takes the first one it finds unused: the one it started
                // at, after a full turn, if every mark was set.
                let len = shard.slots.len();
                let at = (0..=len)
                    .map(|step| (shard.hand + step) % len)
                    .find(|&at| !core::mem::take(shard.slots[at].used.get_mut()))
                    .expect("a full turn clears every mark");
                shard.hand = at + 1;
                let evicted = core::mem::replace(&mut shard.slots[at], slot(false));
                shard.index.remove(&evicted.node);
                shard.index.insert(node, at);
                Some(evicted)
            };
            drop(guard);
            drop(dropped);
        }
    }
}
pub use node_poly_cache::NodePolyCache;

// Constants for improved code readability
pub(crate) const METADATA_BUCKET_LEVEL: u8 = 1;
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
            // Subtract in u64 before narrowing: a 256-child range near the top of
            // a level-4 subtree straddles 2^32, so casting each id to a 32-bit
            // `usize` first would underflow.
            real_positions.push((i, (absolute_node_id - child_idx) as usize));
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
    let cache = NodePolyCache::global();
    let internal_polys = resolve_polys(cache, internal_parents, |missing| {
        let chunk_size = thread_chunk_size!(missing.len());
        let chunks = chunks!(missing, chunk_size)
            .map(|nodes| internal_polynomials(store, nodes))
            .collect::<ProofResult<Vec<_>>>()?;
        Ok(chunks.into_iter().flatten().collect())
    })?;
    let leaf_polys = resolve_polys(cache, leaf_parents, |missing| {
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
/// `cache` holds for the commitment it was read at skips `rebuild`; the misses are rebuilt
/// in one call (by logical id, one polynomial per miss) and cached under that commitment, but
/// only if the polynomial opens to it.
fn resolve_polys(
    cache: &NodePolyCache,
    parents: &[ParentNode],
    rebuild: impl FnOnce(&[NodeId]) -> ProofResult<Vec<LagrangeBasis>>,
) -> ProofResult<Vec<Arc<LagrangeBasis>>> {
    let hits: Vec<Option<Arc<LagrangeBasis>>> = parents
        .iter()
        .map(|parent| cache.get(parent.physical, &parent.bytes))
        .collect();
    let misses: Vec<&ParentNode> = parents
        .iter()
        .zip(&hits)
        .filter(|(_, hit)| hit.is_none())
        .map(|(parent, _)| parent)
        .collect();
    let missing: Vec<NodeId> = misses.iter().map(|parent| parent.logical).collect();
    let rebuilt: Vec<Arc<LagrangeBasis>> = rebuild(&missing)?.into_iter().map(Arc::new).collect();

    // A polynomial rebuilt from a store that does not match the commitment must not be cached
    // under it: the cache is process-wide, so every later proof reading that commitment would
    // reuse it. A consistent store passes the one check for the whole call; only a call that
    // fails it is gone through node by node, to cache the polynomials that do open. A cache
    // that is turned off takes nothing, so there is nothing to check.
    if cache.capacity() != 0 {
        let consistent: Vec<bool> = if batch_opens(&misses, &rebuilt) {
            vec![true; misses.len()]
        } else {
            iter!(misses)
                .zip(iter!(rebuilt))
                .map(|(parent, poly)| opens_to(poly, &parent.commitment))
                .collect()
        };
        for ((parent, poly), consistent) in misses.iter().zip(&rebuilt).zip(consistent) {
            if consistent {
                cache.insert(parent.physical, parent.bytes, Arc::clone(poly));
            }
        }
    }

    let mut rebuilt = rebuilt.into_iter();
    Ok(hits
        .into_iter()
        .map(|hit| hit.unwrap_or_else(|| rebuilt.next().expect("one rebuilt polynomial per miss")))
        .collect())
}

/// Whether every polynomial in `rebuilt` opens to the commitment its node was read at,
/// decided for all of them at once.
///
/// Checking a node on its own costs a 256-term fixed-base MSM ([`opens_to`]), and one per
/// miss is most of the work of a cold proof. Here every node gets a challenge `r_i`, and
/// `Σ r_i·poly_i` is committed once and compared with `Σ r_i·C_i`. The two are equal when
/// every polynomial opens to its commitment. When one does not, they are equal only if the
/// challenges cancel the differences, and the challenges are 128 bits drawn from a hash of
/// the very commitments and polynomials being checked ([`batch_challenges`]), so that happens
/// with probability about 2^-128.
fn batch_opens(misses: &[&ParentNode], rebuilt: &[Arc<LagrangeBasis>]) -> bool {
    let challenges = batch_challenges(misses, rebuilt);

    // Σ r_i·poly_i, one partial sum per thread.
    let chunk_size = thread_chunk_size!(rebuilt.len());
    let combined = reduce!(
        chunks!(rebuilt, chunk_size)
            .zip(chunks!(challenges, chunk_size))
            .map(|(polys, challenges)| {
                let mut sum = [Fr::zero(); DOMAIN_SIZE];
                for (poly, challenge) in polys.iter().zip(challenges) {
                    for (term, value) in sum.iter_mut().zip(poly.values()) {
                        *term += *value * challenge;
                    }
                }
                sum
            }),
        || [Fr::zero(); DOMAIN_SIZE],
        |mut sum, part| {
            for (term, part) in sum.iter_mut().zip(part) {
                *term += part;
            }
            sum
        }
    );

    let commitments: Vec<Element> = misses.iter().map(|parent| parent.commitment).collect();
    shared_committer().msm_dense(&combined) == multi_scalar_mul(&commitments, &challenges)
}

/// One 128-bit challenge per miss, drawn from a hash of the whole batch: each node's
/// commitment bytes and the 256 evaluations of its polynomial, in node order.
fn batch_challenges(misses: &[&ParentNode], rebuilt: &[Arc<LagrangeBasis>]) -> Vec<Fr> {
    const SCALAR_BYTES: usize = 32;

    // Each node is hashed on its own, so the polynomials (8 KiB apiece) are absorbed in
    // parallel and the batch hash below only reads a digest per node.
    let digests: Vec<[u8; blake3::OUT_LEN]> = iter!(misses)
        .zip(iter!(rebuilt))
        .map(|(parent, poly)| {
            let mut evaluations = [0u8; DOMAIN_SIZE * SCALAR_BYTES];
            let limbs = poly.values().iter().flat_map(|value| value.into_bigint().0);
            for (bytes, limb) in evaluations.chunks_exact_mut(8).zip(limbs) {
                bytes.copy_from_slice(&limb.to_le_bytes());
            }
            let mut hasher = blake3::Hasher::new();
            hasher.update(&parent.bytes).update(&evaluations);
            *hasher.finalize().as_bytes()
        })
        .collect();

    let mut hasher = blake3::Hasher::new();
    for digest in &digests {
        hasher.update(digest);
    }
    let mut output = hasher.finalize_xof();
    digests
        .iter()
        .map(|_| {
            let mut challenge = [0u8; 16];
            output.fill(&mut challenge);
            Fr::from(u128::from_le_bytes(challenge))
        })
        .collect()
}

/// Whether `poly` commits to `commitment` under the shared CRS.
fn opens_to(poly: &LagrangeBasis, commitment: &Element) -> bool {
    shared_committer().msm_dense(poly.values()) == *commitment
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
        let bucket_id = (parent - STARTING_NODE_ID[3]) as BucketId;
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
        mem_store::MemStore,
        proof::prover::PRECOMPUTED_WEIGHTS,
        state::state::EphemeralSaltState,
        trie::trie::{StateRoot, DEFAULT_CRS},
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
        let parent_node = STARTING_NODE_ID[3] + salt_key.bucket_id() as u64;
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
        let parent_node = STARTING_NODE_ID[3];
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
        let parent_node = STARTING_NODE_ID[3] + NUM_META_BUCKETS as NodeId;
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

    /// A cache bounded to four polynomials per shard, with the pieces the cache tests share:
    /// node `i` of one shard, a commitment made of one byte, and a polynomial to store.
    fn small_cache() -> (
        NodePolyCache,
        impl Fn(usize) -> NodeId,
        impl Fn(u8) -> CommitmentBytes,
        Arc<LagrangeBasis>,
    ) {
        use node_poly_cache::SHARDS;
        (
            NodePolyCache::with_capacity(4 * SHARDS),
            // Nodes `7 + i * SHARDS` share one shard.
            |i| (7 + i * SHARDS) as NodeId,
            |byte| [byte; 64],
            Arc::new(LagrangeBasis::new(vec![Fr::zero(); DOMAIN_SIZE])),
        )
    }

    /// A full shard evicts one polynomial per new node: the first the hand finds unused since
    /// its last visit. A polynomial served, or a node cached again, counts as used; a lookup
    /// at another commitment does not, and neither is a use that the hand has already passed.
    #[test]
    fn node_poly_cache_evicts_what_was_not_used_since_the_hand_passed() {
        let (cache, node, commitment, poly) = small_cache();
        let nodes = |held: &[usize]| held.iter().map(|&i| node(i)).collect::<Vec<_>>();
        let insert = |i: usize, byte: u8| cache.insert(node(i), commitment(byte), poly.clone());
        let hit = |i: usize, byte: u8| cache.get(node(i), &commitment(byte)).is_some();

        // A node of another shard, which nothing below disturbs.
        cache.insert(8, commitment(1), poly.clone());
        let with_other_shard = |held: &[usize]| {
            let mut all = nodes(held);
            all.push(8);
            all.sort_unstable();
            all
        };

        (0..4).for_each(|i| insert(i, 1));
        assert_eq!(cache.nodes(), with_other_shard(&[0, 1, 2, 3]));
        assert!(hit(0, 1) && hit(2, 1));
        assert!(!hit(1, 2), "another commitment is a miss");
        assert!(!hit(9, 1), "a node the cache does not hold is a miss");

        // The hand passes node 0 (used) and evicts node 1, then passes node 2 and evicts 3.
        insert(4, 1);
        assert_eq!(cache.nodes(), with_other_shard(&[0, 2, 3, 4]));
        insert(5, 1);
        assert_eq!(cache.nodes(), with_other_shard(&[0, 2, 4, 5]));
        // Back at node 0, whose use it has already passed over once.
        insert(6, 1);
        assert_eq!(cache.nodes(), with_other_shard(&[2, 4, 5, 6]));

        // Caching node 4 again replaces its polynomial in place and counts as a use, so the
        // hand passes it and evicts node 2.
        insert(4, 2);
        assert_eq!(cache.nodes(), with_other_shard(&[2, 4, 5, 6]));
        insert(7, 1);
        assert_eq!(cache.nodes(), with_other_shard(&[4, 5, 6, 7]));
        assert!(hit(4, 2) && !hit(4, 1));

        // With every polynomial used, the hand makes a full turn and evicts where it began.
        assert!(hit(5, 1) && hit(6, 1) && hit(7, 1));
        insert(9, 1);
        assert_eq!(cache.nodes(), with_other_shard(&[4, 6, 7, 9]));
    }

    /// The capacity is a bound per shard, rounded up. Lowering it empties the shards that hold
    /// more than their new share and leaves the rest; zero turns the cache off, and raising
    /// it again turns it back on. Clearing drops everything and changes no bound.
    #[test]
    fn node_poly_cache_capacity_bounds_trims_and_turns_the_cache_off() {
        use node_poly_cache::SHARDS;

        let (cache, node, commitment, poly) = small_cache();
        assert_eq!(cache.capacity(), 4 * SHARDS);
        assert_eq!(NodePolyCache::DEFAULT_CAPACITY, 32768);
        assert_eq!(
            NodePolyCache::global().capacity(),
            NodePolyCache::DEFAULT_CAPACITY
        );

        // Three nodes in one shard, one in another.
        (0..3).for_each(|i| cache.insert(node(i), commitment(1), poly.clone()));
        cache.insert(8, commitment(1), poly.clone());
        let everything = vec![node(0), 8, node(1), node(2)];
        assert_eq!(cache.nodes(), everything);

        cache.set_capacity(2 * SHARDS + 1);
        assert_eq!(cache.capacity(), 3 * SHARDS);
        assert_eq!(cache.nodes(), everything, "no shard is over three");
        cache.set_capacity(2 * SHARDS);
        assert_eq!(cache.nodes(), [8], "the shard holding three is emptied");

        cache.set_capacity(0);
        assert_eq!(cache.capacity(), 0);
        assert!(cache.nodes().is_empty());
        cache.insert(node(0), commitment(1), poly.clone());
        assert!(
            cache.nodes().is_empty(),
            "a cache that is off takes nothing"
        );

        cache.set_capacity(1);
        assert_eq!(cache.capacity(), SHARDS);
        cache.insert(node(0), commitment(1), poly.clone());
        cache.insert(8, commitment(1), poly.clone());
        assert_eq!(cache.nodes(), [node(0), 8]);
        // One polynomial per shard: a second node of a shard takes the first one's place.
        cache.insert(node(1), commitment(1), poly.clone());
        assert_eq!(cache.nodes(), [8, node(1)]);

        cache.clear();
        assert!(cache.nodes().is_empty());
        assert_eq!(cache.capacity(), SHARDS);
        cache.insert(node(0), commitment(1), poly);
        assert_eq!(cache.nodes(), [node(0)]);
    }

    /// Regression test for PR #152 review comment r4080228453: a store whose trie and state
    /// disagree must not poison the process-wide node-polynomial cache for consistent stores.
    ///
    /// The cache is keyed by (node id, commitment). On a miss, `resolve_polys` reads the
    /// node's commitment and rebuilds its polynomial from the store's slots or children; it
    /// files the result only if the polynomial opens to that commitment.
    ///
    /// Here `inconsistent` has block 2's state but block 1's trie (`update_state` without
    /// `update_trie`), so the leaf holding `key` reports block 1's commitment while its slots
    /// hold block 2's value. Without the check, creating a witness on it files block 2's leaf
    /// polynomial under block 1's commitment, `consistent` (a correct store of block 1) is
    /// then served that polynomial, and its witness no longer verifies.
    ///
    /// The `inconsistent` witness is created first on purpose: a cache entry for block 1's
    /// commitment that `consistent` had already filed would hide the problem. The key and
    /// values come from a seed no other test uses, so the only entries this test could poison
    /// are ones no other test in the process reads.
    #[test]
    fn inconsistent_store_does_not_poison_witnesses_of_a_consistent_store() {
        use crate::proof::salt_witness::SaltWitness;

        let mut rng = StdRng::seed_from_u64(0x5A17_0152);
        let key = mock_data(&mut rng, 52);
        let (block_1_value, block_2_value) = (mock_data(&mut rng, 32), mock_data(&mut rng, 32));
        let write = |value: &Vec<u8>| -> HashMap<Vec<u8>, Option<Vec<u8>>> {
            [(key.clone(), Some(value.clone()))].into_iter().collect()
        };

        // Block 1, fully applied: state and trie agree.
        let consistent = MemStore::new();
        let block_1 = EphemeralSaltState::new(&consistent)
            .update_fin(&write(&block_1_value))
            .unwrap();
        consistent.update_state(block_1.clone());
        let (_, block_1_trie) = StateRoot::new(&consistent).update_fin(&block_1).unwrap();
        consistent.update_trie(block_1_trie);
        let salt_key = *block_1.data.keys().next().unwrap();

        // Block 2 on top of it, with only its state applied: the commitments are block 1's.
        let inconsistent = consistent.clone();
        let block_2 = EphemeralSaltState::new(&inconsistent)
            .update_fin(&write(&block_2_value))
            .unwrap();
        assert_eq!(*block_2.data.keys().next().unwrap(), salt_key);
        inconsistent.update_state(block_2);

        // A witness from the inconsistent store cannot verify: its value is block 2's, its
        // commitments are block 1's. That is the expected cost of the bad store itself.
        let bad = SaltWitness::create(&[salt_key], &inconsistent).unwrap();
        assert!(bad.verify_proof().is_err());

        // The consistent store must be unaffected by what the other store did.
        let good = SaltWitness::create(&[salt_key], &consistent).unwrap();
        good.verify_proof().expect(
            "a witness from a consistent store must verify, \
             whatever other stores the process has proven before",
        );
    }

    /// `count` nodes with random polynomials, each read at the commitment its polynomial
    /// opens to. The commitments come from the CRS directly, not from the committer the
    /// checks under test use, and a node's physical id differs from its logical one.
    fn committed_nodes(seed: u64, count: usize) -> (Vec<ParentNode>, Vec<Arc<LagrangeBasis>>) {
        let mut rng = StdRng::seed_from_u64(seed);
        (0..count as NodeId)
            .map(|logical| {
                let poly = LagrangeBasis::new(
                    (0..DOMAIN_SIZE)
                        .map(|_| Fr::from_le_bytes_mod_order(&mock_data(&mut rng, 32)))
                        .collect(),
                );
                let bytes = DEFAULT_CRS
                    .commit_lagrange_poly(&poly)
                    .to_bytes_uncompressed();
                let node = ParentNode {
                    logical,
                    physical: logical + 1000,
                    bytes,
                    commitment: Element::from_bytes_unchecked_uncompressed(bytes),
                };
                (node, Arc::new(poly))
            })
            .unzip()
    }

    /// `poly` with the evaluation at `index` zeroed, which no longer opens to `poly`'s
    /// commitment: a random evaluation is not zero.
    fn zeroed_at(poly: &LagrangeBasis, index: usize) -> LagrangeBasis {
        let mut evaluations: Vec<Fr> = (0..DOMAIN_SIZE)
            .map(|i| poly.evaluate_in_domain(i))
            .collect();
        assert!(!evaluations[index].is_zero());
        evaluations[index] = Fr::zero();
        LagrangeBasis::new(evaluations)
    }

    /// The batch check passes when every polynomial opens to its node's commitment, and fails
    /// when any does not, however small the difference and wherever it sits in the batch.
    #[test]
    fn batch_check_passes_only_when_every_polynomial_opens_to_its_commitment() {
        let (nodes, polys) = committed_nodes(0xBA7C, 5);
        let misses: Vec<&ParentNode> = nodes.iter().collect();

        assert!(batch_opens(&misses, &polys));
        assert!(batch_opens(&misses[..1], &polys[..1]));
        assert!(batch_opens(&[], &[]));

        // One evaluation of one polynomial differs.
        for (node, index) in [(0, 0), (3, DOMAIN_SIZE - 1), (4, 17)] {
            let mut off = polys.clone();
            off[node] = Arc::new(zeroed_at(&polys[node], index));
            assert!(!batch_opens(&misses, &off), "node {node}, index {index}");
            assert!(!batch_opens(&misses[node..=node], &off[node..=node]));
        }

        // Two polynomials trade places. Each still opens to a commitment of the batch, so
        // the plain sums of the two sides agree; it is the per-node challenges that tell.
        let mut swapped = polys.clone();
        swapped.swap(1, 2);
        assert!(!batch_opens(&misses, &swapped));
    }

    /// The challenges are drawn from the batch itself: one per node, 128 bits each, and any
    /// change to a commitment, a polynomial or the node order moves every one of them.
    #[test]
    fn batch_challenges_depend_on_every_commitment_and_polynomial() {
        let (nodes, polys) = committed_nodes(0xC4A1, 3);
        let misses: Vec<&ParentNode> = nodes.iter().collect();
        let challenges = batch_challenges(&misses, &polys);

        assert_eq!(challenges.len(), 3);
        assert_eq!(challenges, batch_challenges(&misses, &polys));
        for (i, challenge) in challenges.iter().enumerate() {
            assert!(!challenge.is_zero());
            assert_eq!(challenge.into_bigint().0[2..], [0, 0], "128 bits");
            assert!(!challenges[..i].contains(challenge));
        }
        let all_moved =
            |other: Vec<Fr>| other.len() == 3 && other.iter().zip(&challenges).all(|(a, b)| a != b);

        // The first and the last evaluation of a polynomial.
        for (node, index) in [(0, 0), (2, DOMAIN_SIZE - 1)] {
            let mut changed = polys.clone();
            changed[node] = Arc::new(zeroed_at(&polys[node], index));
            assert!(all_moved(batch_challenges(&misses, &changed)));
        }

        // One bit of a commitment's bytes.
        let mut bytes = nodes[1].bytes;
        bytes[63] ^= 1;
        let rewritten = ParentNode {
            logical: nodes[1].logical,
            physical: nodes[1].physical,
            bytes,
            commitment: nodes[1].commitment,
        };
        assert!(all_moved(batch_challenges(
            &[&nodes[0], &rewritten, &nodes[2]],
            &polys
        )));

        // The order of the nodes.
        let reversed: Vec<Arc<LagrangeBasis>> = polys.iter().rev().cloned().collect();
        assert!(all_moved(batch_challenges(
            &[&nodes[2], &nodes[1], &nodes[0]],
            &reversed
        )));
    }

    /// `resolve_polys` hands the proof every polynomial it rebuilt, but caches only those that
    /// open to the commitment their node was read at: one that does not is rebuilt again by
    /// the next call, and the ones that do are served from the cache from then on.
    #[test]
    fn resolve_polys_caches_only_the_rebuilds_that_open_to_their_commitment() {
        let cache = NodePolyCache::with_capacity(NodePolyCache::DEFAULT_CAPACITY);
        let (nodes, polys) = committed_nodes(0x0152, 4);
        let rebuild = |poly: &Arc<LagrangeBasis>| LagrangeBasis::clone(poly);
        // What an inconsistent store rebuilds for node 2.
        let stale = zeroed_at(&polys[2], 0);

        let logical_ids: Vec<NodeId> = nodes.iter().map(|node| node.logical).collect();
        let first = resolve_polys(&cache, &nodes, |missing| {
            assert_eq!(missing, logical_ids);
            Ok(vec![
                rebuild(&polys[0]),
                rebuild(&polys[1]),
                stale.clone(),
                rebuild(&polys[3]),
            ])
        })
        .unwrap();
        assert_eq!(*first[2], stale);
        for (i, node) in nodes.iter().enumerate() {
            let cached = cache.get(node.physical, &node.bytes);
            if i == 2 {
                assert!(cached.is_none());
            } else {
                assert_eq!(first[i], polys[i]);
                assert_eq!(cached.as_ref(), Some(&polys[i]));
            }
            assert!(cache.get(node.logical, &node.bytes).is_none());
        }

        // Node 2 alone is rebuilt again, this time from a consistent store.
        let second = resolve_polys(&cache, &nodes, |missing| {
            assert_eq!(missing, [nodes[2].logical]);
            Ok(vec![rebuild(&polys[2])])
        })
        .unwrap();
        assert_eq!(second, polys);

        let third = resolve_polys(&cache, &nodes, |missing| {
            assert!(missing.is_empty());
            Ok(Vec::new())
        })
        .unwrap();
        assert_eq!(third, polys);
    }

    /// A cache that is turned off serves and takes nothing: every call rebuilds every node.
    #[test]
    fn resolve_polys_rebuilds_everything_when_the_cache_is_off() {
        let cache = NodePolyCache::with_capacity(0);
        let (nodes, polys) = committed_nodes(0x0FF, 3);
        let logical_ids: Vec<NodeId> = nodes.iter().map(|node| node.logical).collect();

        for _ in 0..2 {
            let resolved = resolve_polys(&cache, &nodes, |missing| {
                assert_eq!(missing, logical_ids);
                Ok(polys
                    .iter()
                    .map(|poly| LagrangeBasis::clone(poly))
                    .collect())
            })
            .unwrap();
            assert_eq!(resolved, polys);
            assert!(cache.nodes().is_empty());
        }
    }

    #[test]
    fn internal_polynomials_empty_and_single_node() {
        let store = MemStore::new();

        // Empty input
        assert!(internal_polynomials(&store, &[]).unwrap().is_empty());

        // Single internal node
        let polys = internal_polynomials(&store, &[STARTING_NODE_ID[2]]).unwrap();
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
            Element::from_bytes_unchecked_uncompressed(default_commitment(STARTING_NODE_ID[1])),
            Element::from_bytes_unchecked_uncompressed(default_commitment(STARTING_NODE_ID[1] + 1)),
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
