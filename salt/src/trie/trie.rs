//! State root computation and incremental trie updates.
//!
//! This module provides [`StateRoot`], the core engine for computing and maintaining
//! cryptographic commitments in SALT's authenticated trie. It implements an efficient
//! incremental update mechanism that minimizes redundant computation when processing
//! multiple state updates.
//!
//! # Incremental Updates
//!
//! - **Update phase**: Accumulates changes at the bucket level without propagating upward
//! - **Finalize phase**: Propagates all changes through the trie hierarchy to compute root
//!
//! This design allows batching multiple updates before expensive trie recomputation.
//!
//! # Key Operations
//!
//! - [`StateRoot::update`]: Accumulate state changes (can call multiple times)
//! - [`StateRoot::finalize`]: Complete computation and return root hash
//! - [`StateRoot::update_fin`]: Single-shot update and finalize
//! - [`StateRoot::rebuild`]: Reconstruct entire trie from storage

use crate::{
    constant::{
        default_commitment, BUCKET_SLOT_BITS, EMPTY_SLOT_HASH, MAIN_TRIE_LEVELS,
        MAX_SUBTREE_LEVELS, META_BUCKET_SIZE, MIN_BUCKET_SIZE, MIN_BUCKET_SIZE_BITS, NUM_BUCKETS,
        NUM_META_BUCKETS, STARTING_NODE_ID, TRIE_WIDTH,
    },
    empty_salt::EmptySalt,
    state::updates::StateUpdates,
    traits::*,
    trie::node_utils::*,
    types::*,
};
use banderwagon::{salt_committer::Committer, Element};
use ipa_multipoint::crs::CRS;
use once_cell::sync::Lazy;
use rayon::prelude::*;
use std::sync::Arc;
use std::{
    collections::{BTreeMap, HashMap, HashSet},
    ops::Range,
};

/// The size of the precomputed window.
const PRECOMP_WINDOW_SIZE: usize = 11;

/// Global shared instance of the Committer to avoid repeated expensive initialization
static SHARED_COMMITTER: Lazy<Arc<Committer>> =
    Lazy::new(|| Arc::new(Committer::new(&CRS::default().G, PRECOMP_WINDOW_SIZE)));

/// Records updates to the internal commitment values of a SALT trie.
/// Stores the old and new commitment values of the trie nodes,
/// formatted as (`node_id`, (`old_commitment`, `new_commitment`)).
pub type TrieUpdates = Vec<(NodeId, (CommitmentBytes, CommitmentBytes))>;

/// List of commitment deltas to be applied to specific nodes.
type DeltaList = Vec<(NodeId, Element)>;

/// Manages computation and incremental updates of SALT trie commitments.
///
/// `StateRoot` provides an efficient two-phase commit mechanism for updating the
/// cryptographic commitments in a SALT trie. It implements an incremental update
/// algorithm that:
///
/// 1. **Update Phase**: Accumulates state changes without immediately propagating
///    them to upper trie levels. Multiple `update()` calls can be batched together.
/// 2. **Finalize Phase**: Propagates all accumulated changes through the trie
///    hierarchy and computes the final state root.
///
/// This design avoids redundant recomputation of upper-level node commitments when
/// processing multiple state updates in sequence. The struct maintains internal
/// caches to track both incremental changes and current commitment values during
/// the update process.
///
/// # Example Flow
/// - Call `update()` multiple times to accumulate state changes
/// - Call `finalize()` once to compute the final state root
/// - Alternatively, use `update_fin()` for single-shot update and finalization
#[derive(Debug)]
pub struct StateRoot<'a, S, T> {
    /// Storage backend that implements `StateReader` to provide access to bucket
    /// entries and metadata.
    state_store: &'a S,

    /// Storage backend that implements `TrieReader` to provide access to trie node
    /// commitments.
    trie_store: &'a T,

    /// Accumulates commitment changes during the update phase.
    ///
    /// This field tracks (old_commitment, new_commitment) pairs for each modified
    /// node. It's essential for the incremental update algorithm because:
    /// - `update()` only computes changes at the bucket level
    /// - Upper trie levels remain unchanged until `finalize()` is called
    /// - This avoids redundant recomputation when processing multiple updates
    ///
    /// The map is cleared after `finalize()` or `update_fin()` completes.
    updates: HashMap<NodeId, (CommitmentBytes, CommitmentBytes)>,

    /// Maintains the latest commitment values for modified nodes.
    ///
    /// Unlike `updates` which tracks old->new transitions, this cache holds only
    /// the current commitment values. It persists across multiple `update()` calls
    /// within the same update session to ensure consistency when nodes are modified
    /// multiple times.
    cache: HashMap<NodeId, CommitmentBytes>,

    /// Shared IPA committer for computing vector commitments.
    ///
    /// Uses a globally shared instance with precomputed tables (window size 11)
    /// to accelerate cryptographic operations across all `StateRoot` instances.
    committer: Arc<Committer>,

    /// Minimum number of tasks per batch for parallel processing.
    ///
    /// Controls when to use parallel computation via rayon. Operations with fewer
    /// tasks than this threshold execute sequentially. Default: 64.
    min_par_batch_size: usize,
}

impl<'a, Store> StateRoot<'a, Store, Store>
where
    Store: StateReader + TrieReader<Error = <Store as StateReader>::Error>,
{
    /// Create a [`StateRoot`] object with a combined storage backend.
    pub fn new(store: &'a Store) -> Self {
        Self::new_with_stores(store, store)
    }
}

impl<'a, S, T> StateRoot<'a, S, T>
where
    S: StateReader,
    T: TrieReader<Error = S::Error>,
{
    /// Create a [`StateRoot`] object with separate state and trie storage backends.
    pub fn new_with_stores(state_store: &'a S, trie_store: &'a T) -> Self {
        Self {
            state_store,
            trie_store,
            updates: HashMap::new(),
            cache: HashMap::new(),
            committer: Arc::clone(&SHARED_COMMITTER),
            min_par_batch_size: 64,
        }
    }

    /// Configure the minimum task batch size for parallel processing.
    pub fn with_min_par_batch_size(mut self, min_task_size: usize) -> Self {
        self.min_par_batch_size = min_task_size;
        self
    }

    /// Updates the trie incrementally without computing the final state root.
    ///
    /// This method implements the "update phase" of the two-phase commit algorithm.
    /// It processes state changes and updates bucket commitments (main trie leaves)
    /// but deliberately avoids propagating changes to upper trie levels. This lazy
    /// approach allows multiple `update()` calls to be batched together efficiently.
    ///
    /// Changes are accumulated internally until `finalize()` is called to complete
    /// the computation. This avoids redundant updates of upper-level node commitments
    /// when processing sequential state updates.
    pub fn update(&mut self, state_updates: StateUpdates) -> Result<(), <T as TrieReader>::Error> {
        for (node_id, (old, new)) in self.update_bucket_subtrees(state_updates)? {
            self.cache.insert(node_id, new);
            self.updates
                .entry(node_id)
                .and_modify(|change| change.1 = new)
                .or_insert((old, new));
        }
        Ok(())
    }

    /// Completes the two-phase commit and returns the final state root.
    ///
    /// This method implements the "finalize phase" by propagating all accumulated
    /// changes from the `updates` cache through the upper main trie levels (L2-L0)
    /// to compute the final state root commitment.
    pub fn finalize(&mut self) -> Result<(ScalarBytes, TrieUpdates), <T as TrieReader>::Error> {
        let mut trie_updates = std::mem::take(&mut self.updates).into_iter().collect();
        let root_hash = self.update_main_trie(&mut trie_updates)?;
        for (node_id, (_, new)) in &trie_updates {
            self.cache.insert(*node_id, *new);
        }
        Ok((root_hash, trie_updates))
    }

    /// Convenience method that combines `update()` and `finalize()` in one call.
    ///
    /// This method is equivalent to calling `update(state_updates)` followed by
    /// `finalize()`. Use this for single-shot updates when you don't need to
    /// batch multiple state changes together.
    pub fn update_fin(
        &mut self,
        state_updates: StateUpdates,
    ) -> Result<(ScalarBytes, TrieUpdates), <T as TrieReader>::Error> {
        self.update(state_updates)?;
        self.finalize()
    }

    /// Propagates commitment updates from leaf nodes up through all internal nodes to the root.
    ///
    /// This is the main orchestrator for updating the main trie's cryptographic commitments
    /// in a bottom-up manner. It processes the trie level by level, starting from the deepest
    /// internal nodes and working toward the root, ensuring that all affected nodes in the
    /// path from changed leaves to root are updated consistently.
    ///
    /// # Arguments
    /// * `trie_updates` - Contains commitment updates from the update phase:
    ///   - **Main trie bucket roots**:
    ///     These are the roots of individual buckets in the main trie
    ///   - **Bucket subtree nodes**: Internal nodes within bucket subtrees,
    ///     present when buckets have expanded beyond MIN_BUCKET_SIZE
    ///
    ///   During execution, this collection is progressively expanded with:
    ///   - **Level 2 updates**: Parent nodes of modified bucket roots
    ///   - **Level 1 updates**: Grandparent nodes
    ///   - **Level 0 update**: The root node
    ///
    /// # Returns
    /// * `ScalarBytes` - The new root commitment hash
    fn update_main_trie(
        &self,
        trie_updates: &mut TrieUpdates,
    ) -> Result<ScalarBytes, <T as TrieReader>::Error> {
        // Filter out subtree nodes to get commitment updates at L3
        let mut level_updates = trie_updates
            .iter()
            .filter_map(|(node_id, change)| {
                if is_subtree_node(*node_id) {
                    None
                } else {
                    Some((*node_id, *change))
                }
            })
            .collect::<Vec<_>>();

        // Propagate updates level by level from deepest (level 3) to root (level 0).
        // Each iteration processes one level, computing parent updates from child changes.
        for _ in (0..MAIN_TRIE_LEVELS - 1).rev() {
            level_updates = self.update_internal_nodes(level_updates)?;
            trie_updates.extend(level_updates.iter());
        }

        // Extract the root commitment from the last update, or fetch from storage
        // if root wasn't modified
        let root_commitment = if let Some((0, (_, c))) = trie_updates.last() {
            *c
        } else {
            self.trie_store.commitment(0)?
        };

        Ok(hash_commitment(root_commitment))
    }

    /// Updates bucket subtree commitments in response to state changes.
    ///
    /// # Use Cases
    ///
    /// * **Data updates**: Key-value changes within expanded buckets
    /// * **Expansion**: Bucket capacity increases, creating new subtree levels
    /// * **Contraction**: Bucket capacity decreases, removing subtree levels
    /// * **Mixed updates**: Simultaneous data and capacity changes
    ///
    /// # Arguments
    /// * `state_updates` - State changes including:
    ///   - Key-value pair updates (insertions, modifications, deletions)
    ///   - Bucket metadata updates (capacity changes)
    ///   - Or both types together
    ///
    /// # Returns
    /// * `Ok(TrieUpdates)` - Commitment updates for all affected trie nodes
    /// * `Err` - On store failures or invalid metadata
    fn update_bucket_subtrees(
        &self,
        state_updates: StateUpdates,
    ) -> Result<TrieUpdates, <T as TrieReader>::Error> {
        let mut uncomputed_updates = vec![];
        let mut extra_updates = vec![vec![]; MAX_SUBTREE_LEVELS];

        // Step 1.1: Extract metadata changes from state updates
        let mut subtree_change_info: BTreeMap<BucketId, SubtrieChangeInfo> = state_updates
            .data
            .range(
                SaltKey::from((0, 0))
                    ..SaltKey::from((
                        (NUM_META_BUCKETS - 1) as BucketId,
                        MIN_BUCKET_SIZE as SlotId,
                    )),
            )
            .map(|(key, meta_change)| {
                let bucket_id = bucket_id_from_metadata_key(*key);
                let old_meta: BucketMeta = meta_change
                    .0
                    .clone()
                    .expect("old meta exist in updates")
                    .try_into()
                    .expect("old meta should be valid");
                let new_meta: BucketMeta = meta_change
                    .1
                    .clone()
                    .expect("new meta exist in updates")
                    .try_into()
                    .expect("new meta should be valid");
                (
                    bucket_id,
                    SubtrieChangeInfo::new(bucket_id, old_meta.capacity, new_meta.capacity),
                )
            })
            .collect();
        // Step 1.2: Identify buckets that need subtree processing
        let mut need_handle_buckets = HashSet::new();
        let mut last_bucket_id = u32::MAX;

        // Helper closure for expansion without KV changes
        let add_expansion_update =
            |extra_updates: &mut Vec<Vec<_>>, subtree_change: &SubtrieChangeInfo| {
                extra_updates[subtree_change.old_top_level].push((
                    subtree_change.old_top_id,
                    (
                        default_commitment(subtree_change.old_top_id),
                        self.commitment(subtree_change.root_id)?,
                    ),
                ));
                Ok(())
            };

        // Helper closure for contraction without KV changes
        let add_contraction_update =
            |uncomputed_updates: &mut Vec<_>, subtree_change: &SubtrieChangeInfo| {
                uncomputed_updates.push((
                    subtree_change.root_id,
                    (
                        self.commitment(subtree_change.root_id)?,
                        self.commitment(subtree_change.new_top_id)?,
                    ),
                ));
                Ok(())
            };

        for key in state_updates.data.keys() {
            let bucket_id = key.bucket_id();
            if last_bucket_id != bucket_id && bucket_id >= NUM_META_BUCKETS as BucketId {
                last_bucket_id = bucket_id;
                // Check if bucket has capacity changes or needs subtree handling
                if let Some(subtree_change) = subtree_change_info.get(&bucket_id) {
                    // Handle capacity changes
                    match subtree_change
                        .new_capacity
                        .cmp(&subtree_change.old_capacity)
                    {
                        std::cmp::Ordering::Greater => {
                            // Will be handled in subtree processing
                            let level = MAX_SUBTREE_LEVELS - subtree_change.old_top_level;
                            let level_capacity = (MIN_BUCKET_SIZE as u64).pow(level as u32);
                            if key.slot_id() < level_capacity {
                                need_handle_buckets.insert(bucket_id);
                                continue;
                            }
                        }
                        std::cmp::Ordering::Less => {
                            // Will be handled in subtree processing
                            let level = MAX_SUBTREE_LEVELS - subtree_change.new_top_level;
                            let level_capacity = (MIN_BUCKET_SIZE as u64).pow(level as u32);
                            if key.slot_id() < level_capacity {
                                need_handle_buckets.insert(bucket_id);
                                continue;
                            }
                        }
                        std::cmp::Ordering::Equal => {}
                    }
                } else if self.state_store.get_subtree_levels(bucket_id)? > 1 {
                    // KV changes in expanded bucket (capacity unchanged)
                    need_handle_buckets.insert(bucket_id);
                    let bucket_capacity = (TRIE_WIDTH as NodeId)
                        .pow(self.state_store.get_subtree_levels(bucket_id)? as u32);
                    subtree_change_info.insert(
                        bucket_id,
                        SubtrieChangeInfo::new(bucket_id, bucket_capacity, bucket_capacity),
                    );
                }
            }
        }

        // Initialize trigger levels for later processing
        let mut trigger_levels = vec![HashMap::new(); MAX_SUBTREE_LEVELS];

        // Step 2: Update leaf node commitments
        let mut trie_updates = self.update_leaf_nodes(&state_updates, &subtree_change_info)?;

        // Step 3: Optimize contracted buckets by resetting unused nodes to defaults
        for (bucket_id, subtree_change) in &subtree_change_info {
            if subtree_change.new_capacity >= subtree_change.old_capacity {
                continue;
            }
            let mut capacity_start_index =
                subtree_change.new_capacity >> MIN_BUCKET_SIZE_BITS as NodeId;
            let mut capacity_end_index =
                subtree_change.old_capacity >> MIN_BUCKET_SIZE_BITS as NodeId;
            let bucket_id = (*bucket_id as NodeId) << BUCKET_SLOT_BITS as NodeId;

            for level in (subtree_change.old_top_level + 1..MAX_SUBTREE_LEVELS).rev() {
                let extrat_end = ((capacity_start_index + MIN_BUCKET_SIZE as NodeId)
                    & (NodeId::MAX - (MIN_BUCKET_SIZE as NodeId - 1)))
                    .min(capacity_end_index)
                    + bucket_id
                    + STARTING_NODE_ID[level] as NodeId;

                let updates = (capacity_start_index..capacity_end_index)
                    .into_par_iter()
                    .filter_map(|i| {
                        let node_id = bucket_id + i + STARTING_NODE_ID[level] as NodeId;
                        let old_c = self.commitment(node_id).expect("node should exist in trie");
                        let new_c = default_commitment(node_id);
                        (new_c != old_c).then_some((node_id, (old_c, new_c)))
                    })
                    .collect::<Vec<_>>();

                let split_point = updates.partition_point(|node| node.0 < extrat_end);
                uncomputed_updates.extend(updates[split_point..].iter());
                extra_updates[level].extend(updates[0..split_point].iter());

                capacity_start_index >>= MIN_BUCKET_SIZE_BITS as NodeId;
                capacity_end_index >>= MIN_BUCKET_SIZE_BITS as NodeId;
            }
        }
        // Step 4: Set up triggers and handle capacity-only changes
        for (bucket_id, subtree_change) in &subtree_change_info {
            if need_handle_buckets.contains(bucket_id) {
                trigger_levels[subtree_change.new_top_level]
                    .insert(*bucket_id, subtree_change.clone());
                if subtree_change.old_top_level > subtree_change.new_top_level {
                    // Expansion: handle both old and new levels
                    trigger_levels[subtree_change.old_top_level]
                        .insert(*bucket_id, subtree_change.clone());
                }
            } else {
                // Handle capacity-only changes (no KV updates)
                match subtree_change
                    .old_top_level
                    .cmp(&subtree_change.new_top_level)
                {
                    std::cmp::Ordering::Greater => {
                        // Expansion: update old subtree root
                        add_expansion_update(&mut extra_updates, subtree_change)?;
                        need_handle_buckets.insert(*bucket_id);
                        // Also handle both top level
                        trigger_levels[subtree_change.old_top_level]
                            .insert(*bucket_id, subtree_change.clone());
                        trigger_levels[subtree_change.new_top_level]
                            .insert(*bucket_id, subtree_change.clone());
                    }
                    std::cmp::Ordering::Less => {
                        // Contraction: new root equals bucket commitment
                        add_contraction_update(&mut uncomputed_updates, subtree_change)?;
                    }
                    std::cmp::Ordering::Equal => {}
                }
            }
        }
        // Step 5: Extract subtree nodes for hierarchical processing
        let start = trie_updates
            .iter()
            .position(|update| is_subtree_node(update.0))
            .unwrap_or(trie_updates.len());
        let mut subtree_commitmens = if need_handle_buckets.is_empty() {
            vec![]
        } else {
            trie_updates.drain(start..).collect()
        };
        // Step 6: Process subtree levels bottom-up
        for level in (0..MAX_SUBTREE_LEVELS).rev() {
            // Handle subtree triggers at this level (if any)
            if !trigger_levels[level].is_empty() {
                // Helper closure for commitment arithmetic
                let adjust_commitment = |root_commitment, new_commitment, node_id| {
                    let new_element = Element::from_bytes_unchecked_uncompressed(root_commitment)
                        + Element::from_bytes_unchecked_uncompressed(new_commitment)
                        - Element::from_bytes_unchecked_uncompressed(default_commitment(node_id));
                    new_element.to_bytes_uncompressed()
                };

                let (subtrie_updates, subtrie_roots): (Vec<_>, Vec<_>) = subtree_commitmens
                    .into_par_iter()
                    .map(|(node_id, (old_commitment, new_commitment))| {
                        let current_bucket_id = (node_id >> BUCKET_SLOT_BITS as NodeId) as BucketId;

                        if let Some(subtree_change) = trigger_levels[level].get(&current_bucket_id)
                        {
                            let new_commitment = if subtree_change.old_top_level == level
                                && node_id == subtree_change.old_top_id
                            {
                                let root_commitment = self
                                    .commitment(subtree_change.root_id)
                                    .expect("root node should exist in trie");
                                adjust_commitment(root_commitment, new_commitment, node_id)
                            } else {
                                new_commitment
                            };

                            if subtree_change.new_top_level == level {
                                // Handle the new top level, subtree update is done
                                assert_eq!(subtree_change.new_top_id, node_id);
                                let root_commitment = self
                                    .commitment(subtree_change.root_id)
                                    .expect("root node should exist in trie");
                                return (
                                    vec![],
                                    vec![(
                                        subtree_change.root_id,
                                        (root_commitment, new_commitment),
                                    )],
                                );
                            }

                            // Expansion - new level going up, need to compute
                            (
                                vec![(
                                    node_id,
                                    (
                                        default_commitment(subtree_change.old_top_id),
                                        new_commitment,
                                    ),
                                )],
                                vec![],
                            )
                        } else {
                            (vec![(node_id, (old_commitment, new_commitment))], vec![])
                        }
                    })
                    .unzip();

                // Add the new subtree root updates to the main trie updates
                trie_updates.extend(subtrie_roots.into_iter().flatten());
                subtree_commitmens = subtrie_updates.into_iter().flatten().collect();
            }

            // Add level-specific updates
            subtree_commitmens.extend(extra_updates[level].iter());
            trie_updates.extend(subtree_commitmens.iter());

            // Early exit optimization
            let total_remaining_triggers: usize = trigger_levels
                .iter()
                .take(level)
                .map(|triggers| triggers.len())
                .sum();
            if total_remaining_triggers == 0 || level == 0 {
                break;
            }

            // Propagate updates to next level up
            subtree_commitmens = self
                .update_internal_nodes(subtree_commitmens)
                .expect("update internal nodes for subtrie failed");
        }

        trie_updates.extend(uncomputed_updates.iter());
        Ok(trie_updates)
    }

    /// Updates leaf node commitments in the trie based on state key-value changes.
    ///
    /// When key-value pairs in the underlying state change, this method efficiently
    /// updates the commitments stored in the trie's leaf nodes using a delta approach.
    ///
    /// # Vector Commitment Model
    /// Each leaf node stores: C = Σ(G[i] * hash(kv[i])) for i in 0..256
    /// When kv[j] changes: new_C = old_C + G[j] * (hash(new_kv[j]) - hash(old_kv[j]))
    /// This delta approach avoids recomputing the entire 256-element sum.
    ///
    /// # Arguments
    /// * `state_updates` - Key-value changes in the underlying state. These K-V pairs
    ///   are not part of the trie itself but are committed to by the trie's leaf nodes.
    ///   The method consumes this input.
    /// * `is_subtree` - Determines which leaf nodes to update:
    ///   - `false`: Updates main trie leaf nodes
    ///   - `true`: Updates subtree leaf nodes
    ///
    /// # Returns
    /// * `TrieUpdates` - Commitment updates for the affected leaf nodes
    fn update_leaf_nodes(
        &self,
        state_updates: &StateUpdates,
        subtree_change_info: &BTreeMap<BucketId, SubtrieChangeInfo>,
    ) -> Result<TrieUpdates, <T as TrieReader>::Error> {
        // Sort the state updates by slot IDs
        let mut state_updates = state_updates.data.iter().collect::<Vec<_>>();
        state_updates.par_sort_unstable_by(|(a, _), (b, _)| {
            (a.slot_id() as usize % TRIE_WIDTH).cmp(&(b.slot_id() as usize % TRIE_WIDTH))
        });

        // Compute the commitment deltas to be applied to the parent nodes.
        let batch_size = self.par_batch_size(state_updates.len());
        let c_deltas: DeltaList = state_updates
            .par_iter()
            .with_min_len(batch_size)
            .filter_map(|(salt_key, (old_value, new_value))| {
                let bucket_id = salt_key.bucket_id();
                let (capacity, is_subtree) =
                    if let Some(meta_change) = subtree_change_info.get(&bucket_id) {
                        (
                            meta_change.new_capacity,
                            meta_change.new_capacity > MIN_BUCKET_SIZE as u64
                                || meta_change.old_capacity > MIN_BUCKET_SIZE as u64,
                        )
                    } else {
                        (MIN_BUCKET_SIZE as u64, false)
                    };
                if salt_key.slot_id() >= capacity {
                    // This slot is beyond the current capacity, so it does not affect the commitment.
                    None
                } else {
                    Some((
                        if is_subtree {
                            subtree_leaf_for_key(salt_key)
                        } else {
                            bucket_root_node_id(bucket_id)
                        },
                        self.committer.gi_mul_delta(
                            &kv_hash(old_value),
                            &kv_hash(new_value),
                            salt_key.slot_id() as usize % TRIE_WIDTH,
                        ),
                    ))
                }
            })
            .collect::<Vec<_>>();

        self.add_commitment_deltas(c_deltas, batch_size)
    }

    /// Propagates commitment updates from child nodes to their parent nodes.
    ///
    /// Similar to `update_leaf_nodes`, this method uses the delta-based approach to
    /// efficiently update parent commitments when their children change. It processes
    /// a single trie level, computing new parent commitments based on child updates.
    ///
    /// # Arguments
    /// * `child_updates` - Commitment changes from child nodes that need to be
    ///   propagated to their parents.
    ///
    /// # Returns
    /// * `TrieUpdates` - Commitment updates for the parent nodes
    ///
    /// # Delta Computation
    /// For each child update, computes: delta = G[child_index] * (new_child - old_child)
    /// where child_index is the child's position (0-255) within its parent's vector commitment.
    /// All deltas for the same parent are accumulated to produce the parent's new commitment.
    ///
    /// See `update_leaf_nodes` for the vector commitment model details.
    fn update_internal_nodes(
        &self,
        mut child_updates: TrieUpdates,
    ) -> Result<TrieUpdates, <T as TrieReader>::Error> {
        // Sort by position within parent vector commitments for cache locality
        child_updates.par_sort_unstable_by(|(a, _), (b, _)| {
            vc_position_in_parent(a).cmp(&vc_position_in_parent(b))
        });

        let batch_size = self.par_batch_size(child_updates.len());
        let delta_list = child_updates
            .par_chunks(batch_size)
            .flat_map(|c_updates| {
                // Interleave old and new commitments for efficient batch hashing
                let hashes = Element::hash_commitments(
                    &c_updates
                        .iter()
                        .flat_map(|(_, (old_c, new_c))| [*old_c, *new_c])
                        .collect::<Vec<_>>(),
                );

                c_updates
                    .iter()
                    .zip(hashes.chunks_exact(2))
                    .map(|((id, _), h)| {
                        (
                            get_parent_node(id),
                            self.committer
                                .gi_mul_delta(&h[0], &h[1], vc_position_in_parent(id)),
                        )
                    })
                    .collect::<Vec<_>>()
            })
            .collect();

        self.add_commitment_deltas(delta_list, batch_size)
    }

    /// Computes a resonable batch size for parallel processing to balance workload
    /// and overhead.
    ///
    /// This method determines how to divide tasks among parallel threads to maximize
    /// performance. It aims to create enough batches for good work distribution while
    /// avoiding the overhead of too many small batches.
    ///
    /// # Arguments
    /// * `num_tasks` - Total number of tasks to be processed in parallel
    ///
    /// # Returns
    /// The batch size to use for parallel chunks, guaranteed to be at least `min_par_batch_size`
    fn par_batch_size(&self, num_tasks: usize) -> usize {
        // Factor of 10 provides a sweet spot for most workloads
        let num_batches = 10 * rayon::current_num_threads();
        self.min_par_batch_size.max(num_tasks.div_ceil(num_batches))
    }

    /// Applies cryptographic commitment deltas to trie nodes efficiently in parallel.
    ///
    /// This method takes a list of commitment changes (deltas) for various nodes and
    /// applies them atomically, returning the old and new commitment values for each
    /// affected node.
    ///
    /// # Arguments
    /// * `commitment_deltas` - Vector of (NodeId, Element) pairs representing commitment
    ///   changes. Multiple deltas for the same NodeId will be summed together.
    /// * `task_size` - Target chunk size for parallel processing.
    ///
    /// # Returns
    /// `TrieUpdates` - Vector of (NodeId, (old_commitment, new_commitment)) tuples.
    ///
    /// # Algorithm
    /// 1. Sorts deltas by NodeId to group changes for the same node
    /// 2. Creates chunks for parallel processing, never splitting deltas for the same node
    /// 3. Processes each chunk in parallel: accumulates deltas, applies to old commitments
    /// 4. Uses batch cryptographic operations for efficiency
    ///
    /// # Example
    /// ```ignore
    /// // Input: deltas for nodes 1 and 2
    /// let deltas = vec![(1, δ1), (1, δ2), (2, δ3)];
    /// let updates = trie.add_commitment_deltas(deltas, 64)?;
    /// // Output: [(1, (old_c1, old_c1 + δ1 + δ2)), (2, (old_c2, old_c2 + δ3))]
    /// ```
    fn add_commitment_deltas(
        &self,
        mut commitment_deltas: DeltaList,
        task_size: usize,
    ) -> Result<TrieUpdates, <T as TrieReader>::Error> {
        // Sort deltas by NodeId to group changes for the same node together
        // This enables efficient accumulation and ensures deterministic ordering
        commitment_deltas.par_sort_unstable_by_key(|&(node_id, _)| node_id);

        // Create node-aligned chunks for parallel processing
        let chunks = self.create_node_aligned_chunks(&commitment_deltas, task_size);

        // Process each chunk in parallel and collect results
        let results: Result<Vec<_>, _> = chunks
            .par_iter()
            .map(|chunk_range| self.accumulate_chunk_deltas(&commitment_deltas, chunk_range))
            .collect();

        // Flatten results from all chunks
        Ok(results?.into_iter().flatten().collect())
    }

    /// Helper for `par_update_node_commitments`: Creates chunks for parallel
    /// processing that never split commitment deltas for the same node.
    fn create_node_aligned_chunks(
        &self,
        deltas: &DeltaList,
        task_size: usize,
    ) -> Vec<std::ops::Range<usize>> {
        let mut chunk_boundaries = Vec::with_capacity(deltas.len() / task_size + 2);
        chunk_boundaries.push(0);

        let mut next_boundary = task_size;
        while next_boundary < deltas.len() {
            // Find next valid boundary: must be at a node boundary
            // Extend chunk if current position would split a node's deltas
            while next_boundary < deltas.len()
                && deltas[next_boundary].0 == deltas[next_boundary - 1].0
            {
                next_boundary += 1;
            }

            if next_boundary < deltas.len() {
                chunk_boundaries.push(next_boundary);
                next_boundary += task_size;
            }
        }
        chunk_boundaries.push(deltas.len());

        // Convert boundaries to ranges
        chunk_boundaries
            .windows(2)
            .map(|window| window[0]..window[1])
            .collect()
    }

    /// Helper for `par_update_node_commitments`: Accumulates deltas for nodes
    /// in a single chunk, computing updated commitments.
    fn accumulate_chunk_deltas(
        &self,
        deltas: &DeltaList,
        chunk_range: &Range<usize>,
    ) -> Result<TrieUpdates, <T as TrieReader>::Error> {
        let chunk_deltas = &deltas[chunk_range.clone()];
        let estimated_nodes = chunk_deltas.len().min(chunk_range.len());
        let mut accumulated_elements = Vec::with_capacity(estimated_nodes);
        let mut nodes_with_old_commitments = Vec::with_capacity(estimated_nodes);
        let mut current_node_id = NodeId::MAX;

        // Accumulate deltas for each node in this chunk
        for &(node_id, delta) in chunk_deltas {
            if node_id == current_node_id {
                // Same node: accumulate delta with previous deltas
                if let Some(last_element) = accumulated_elements.last_mut() {
                    *last_element += delta;
                }
            } else {
                // New node: start fresh accumulation
                let old_commitment = self.commitment(node_id)?;
                let new_element =
                    Element::from_bytes_unchecked_uncompressed(old_commitment) + delta;

                accumulated_elements.push(new_element);
                nodes_with_old_commitments.push((node_id, old_commitment));
                current_node_id = node_id;
            }
        }

        // Batch convert all accumulated elements to commitment bytes
        let new_commitments = Element::batch_to_commitments(&accumulated_elements);

        // Combine into final (NodeId, (old_commitment, new_commitment)) format
        Ok(nodes_with_old_commitments
            .into_iter()
            .zip(new_commitments)
            .map(|((node_id, old_commitment), new_commitment)| {
                (node_id, (old_commitment, new_commitment))
            })
            .collect())
    }

    /// Retrieves the commitment of a node from the trie or the cache.
    #[inline(always)]
    fn commitment(&self, node_id: NodeId) -> Result<CommitmentBytes, <T as TrieReader>::Error> {
        if let Some(c) = self.cache.get(&node_id) {
            Ok(*c)
        } else {
            self.trie_store.commitment(node_id)
        }
    }
}

impl StateRoot<'_, EmptySalt, EmptySalt> {
    /// Reconstructs the entire trie from scratch using data stored in the database.
    ///
    /// This method reads all bucket metadata and key-value pairs from storage and
    /// rebuilds the complete trie structure, including proper handling of expanded
    /// buckets (capacity > 256).
    ///
    /// # Algorithm
    ///
    /// 1. Processes data buckets in chunks for compute efficiency
    /// 2. For each chunk:
    ///    - Reads metadata from meta buckets, simulating changes from default values
    ///    - Reads key-value pairs from data buckets as insertions
    ///    - Updates bucket subtree structure, automatically triggering expansion logic
    ///    - Computes the bucket commitment
    /// 3. Computes commitments for all main trie nodes above the leaves
    ///
    /// # Expanded Buckets Handling
    ///
    /// The key insight for handling buckets with capacity > 256 is setting metadata
    /// old values to `BucketMeta::default()` (capacity=256). When `update_leaf_nodes`
    /// sees this "change" from default to actual capacity, it automatically triggers
    /// the expansion logic, creating the proper multi-level bucket subtree structure.
    ///
    /// # Returns
    ///
    /// * `Ok((root_commitment, trie_updates))` - Root hash and all node updates
    /// * `Err(S::Error)` - If reading from storage fails
    pub fn rebuild<S: StateReader>(reader: &S) -> Result<(ScalarBytes, TrieUpdates), S::Error> {
        // Process data buckets in chunks (chunk size must be multiples of 256)
        const CHUNK_SIZE: usize = META_BUCKET_SIZE;

        let all_trie_updates = (NUM_META_BUCKETS..NUM_BUCKETS)
            .into_par_iter()
            .step_by(CHUNK_SIZE)
            .map(|chunk_start| -> Result<TrieUpdates, S::Error> {
                let chunk_end = NUM_BUCKETS.min(chunk_start + CHUNK_SIZE) - 1;

                // Step 1: Read metadata for all buckets in this chunk
                let meta_bucket_start = (chunk_start / META_BUCKET_SIZE) as BucketId;
                let meta_bucket_end = (chunk_end / META_BUCKET_SIZE) as BucketId;
                let mut chunk_updates = reader
                    .entries(SaltKey::bucket_range(meta_bucket_start, meta_bucket_end))?
                    .into_iter()
                    .map(|(key, actual_metadata)| {
                        // Simulate metadata change: default -> actual
                        (
                            key,
                            (Some(BucketMeta::default().into()), Some(actual_metadata)),
                        )
                    })
                    .collect::<BTreeMap<_, _>>();

                // Step 2: Read all key-value pairs for buckets in this chunk
                // Treat as insertions since we're rebuilding from scratch
                chunk_updates.extend(
                    reader
                        .entries(SaltKey::bucket_range(
                            chunk_start as BucketId,
                            chunk_end as BucketId,
                        ))?
                        .into_iter()
                        .map(|(key, value)| (key, (None, Some(value)))),
                );

                // Step 3: Apply updates to trie, handling expansion automatically
                // `update_bucket_subtrees` detects metadata capacity changes and creates
                // appropriate subtrie structures without special handling
                StateRoot::new(&EmptySalt)
                    .update_bucket_subtrees(StateUpdates {
                        data: chunk_updates,
                    })
                    .map_err(|_| unreachable!("EmptySalt never returns errors"))
            })
            .collect::<Result<Vec<_>, _>>()?;

        let mut all_trie_updates = all_trie_updates.into_iter().flatten().collect::<Vec<_>>();

        // Step 4: Compute commitments for all internal nodes in the main trie
        let root_hash = StateRoot::new(&EmptySalt)
            .update_main_trie(&mut all_trie_updates)
            .map_err(|_| unreachable!("EmptySalt never returns errors"))?;
        Ok((root_hash, all_trie_updates))
    }
}

/// Generates a 256-bit secure hash from the bucket entry.
/// Note: as a special case, empty entries are hashed to 0.
#[inline(always)]
pub(crate) fn kv_hash(entry: &Option<SaltValue>) -> ScalarBytes {
    entry.as_ref().map_or_else(
        || EMPTY_SLOT_HASH,
        |salt_value| {
            let mut data = blake3::Hasher::new();
            data.update(salt_value.key());
            data.update(salt_value.value());
            *data.finalize().as_bytes()
        },
    )
}

/// The information of subtrie change.
#[derive(Debug, Clone)]
struct SubtrieChangeInfo {
    /// The capacity of the old subtrie.
    old_capacity: u64,
    /// The top level of the old subtrie.
    old_top_level: usize,
    /// The root id in the old subtrie.
    old_top_id: NodeId,
    /// The capacity of the new subtrie.
    new_capacity: u64,
    /// The top level of the new subtrie.
    new_top_level: usize,
    /// The root id in the new subtrie.
    new_top_id: NodeId,
    /// The root id in the main trie.
    root_id: NodeId,
}

impl SubtrieChangeInfo {
    fn new(bucket_id: BucketId, old_capacity: u64, new_capacity: u64) -> Self {
        let old_top_level = subtree_root_level(old_capacity);
        let new_top_level = subtree_root_level(new_capacity);
        let old_top_id = ((bucket_id as NodeId) << BUCKET_SLOT_BITS as NodeId)
            + STARTING_NODE_ID[old_top_level] as NodeId;
        let new_top_id = ((bucket_id as NodeId) << BUCKET_SLOT_BITS as NodeId)
            + STARTING_NODE_ID[new_top_level] as NodeId;
        let root_id = bucket_root_node_id(bucket_id);
        Self {
            old_capacity,
            old_top_level,
            old_top_id,
            new_capacity,
            new_top_level,
            new_top_id,
            root_id,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        mem_store::MemStore,
        state::{state::EphemeralSaltState, updates::StateUpdates},
        trie::trie::{kv_hash, StateRoot},
    };
    use iter_tools::Itertools;
    use rand::Rng;

    use crate::{
        constant::{default_commitment, MAIN_TRIE_LEVELS, STARTING_NODE_ID},
        empty_salt::EmptySalt,
    };
    use std::collections::HashMap;
    const KV_BUCKET_OFFSET: NodeId = NUM_META_BUCKETS as NodeId;

    /// Rebuilds a main trie node commitment from storage for testing purposes.
    ///
    /// **WARNING: This method does NOT handle expanded buckets (capacity > 256).**
    /// It assumes all buckets have the default capacity of 256 slots and will
    /// produce incorrect results for buckets that have been resized.
    ///
    /// # Purpose
    ///
    /// This is a test-only helper method used to verify that incremental trie updates
    /// produce the same commitments as computing from scratch. It should NOT be used
    /// in production code.
    ///
    /// # Algorithm
    ///
    /// 1. **Range Calculation**: Determines all bucket IDs that are descendants
    ///    of the given node by expanding the range level by level
    /// 2. **Default State Setup**: Creates default commitments for meta and data buckets
    /// 3. **Bucket Processing**: For each bucket in the range:
    ///    - Reads all KV pairs from storage
    ///    - Computes deltas from default state to actual state
    ///    - Generates bucket-level commitment
    /// 4. **Bottom-Up Aggregation**: Iteratively computes parent commitments
    ///    from child commitments until reaching the target node level
    ///
    /// # Arguments
    ///
    /// * `node_id` - The node whose subtree commitment should be computed
    /// * `store` - Storage reader to fetch KV pairs from
    ///
    /// # Returns
    ///
    /// The commitment bytes for the specified node
    fn rebuild_subtrie_without_expanded_buckets<S: StateReader>(
        node_id: NodeId,
        store: &S,
    ) -> CommitmentBytes {
        let node_level = get_bfs_level(node_id);
        let committer = SHARED_COMMITTER.as_ref();
        let zero_commitment = Committer::zero();

        // ========== Step 1: Calculate descendant bucket range ==========
        // For a node at a given level, calculate all bucket IDs in its subtree.
        // Example: Node at level 2, position 5 within that level:
        //   -> Level 3: covers buckets [5*256, 6*256) = [1280, 1536)
        //   -> Level 4: covers buckets [1280*256, 1536*256) = [327680, 393216)
        let node_position_in_level = node_id - STARTING_NODE_ID[node_level] as NodeId;
        let mut bucket_range_start = node_position_in_level;
        let mut bucket_range_end = node_position_in_level + 1;

        // Expand range through each level below until reaching leaf buckets
        for _ in node_level + 1..MAIN_TRIE_LEVELS {
            bucket_range_start *= MIN_BUCKET_SIZE as NodeId;
            bucket_range_end *= MIN_BUCKET_SIZE as NodeId;
        }

        // ========== Step 2: Create default bucket commitments ==========
        // These represent empty buckets and serve as the base for delta computation.
        // Meta buckets default to containing BucketMeta::default() in all slots.
        // Data buckets default to being completely empty (None in all slots).

        let meta_delta_indices = (0..MIN_BUCKET_SIZE)
            .map(|slot_index| {
                let old_value = [0u8; 32];
                let new_value = kv_hash(&Some(BucketMeta::default().into()));
                (slot_index, old_value, new_value)
            })
            .collect::<Vec<_>>();
        let data_delta_indices = (0..MIN_BUCKET_SIZE)
            .map(|slot_index| {
                let old_value = [0u8; 32];
                let new_value = kv_hash(&None);
                (slot_index, old_value, new_value)
            })
            .collect::<Vec<_>>();

        let default_bucket_meta = committer
            .add_deltas(zero_commitment, &meta_delta_indices)
            .to_bytes_uncompressed();
        let default_bucket_data = committer
            .add_deltas(zero_commitment, &data_delta_indices)
            .to_bytes_uncompressed();

        // ========== Step 3: Compute bucket commitments in parallel ==========
        // For each bucket in the range: read KV pairs, compute deltas from default
        // state, and generate the final bucket commitment.

        let mut level_commitments = (bucket_range_start..bucket_range_end)
            .into_par_iter()
            .map(|bucket_index| {
                let bucket_id = bucket_index as BucketId;

                // Read all KV pairs for this bucket
                let kv_pairs = store
                    .entries(SaltKey::bucket_range(bucket_id, bucket_id))
                    .unwrap();

                // Choose the appropriate default commitment based on bucket type
                let default_commitment = if bucket_id < NUM_META_BUCKETS as BucketId {
                    default_bucket_meta // Meta bucket
                } else {
                    default_bucket_data // Data bucket
                };

                // If bucket is empty, use default commitment
                if kv_pairs.is_empty() {
                    return (bucket_index as usize, default_commitment);
                }

                // Build delta indices: (slot_index, old_hash, new_hash)
                let delta_indices = kv_pairs
                    .into_iter()
                    .map(|(key, value)| {
                        // Determine old value hash based on bucket type
                        let old_value_hash = if key.is_in_meta_bucket() {
                            kv_hash(&Some(BucketMeta::default().into())) // Meta bucket default
                        } else {
                            kv_hash(&None) // Data bucket default (empty)
                        };

                        let slot_index = key.slot_id() as usize % MIN_BUCKET_SIZE;
                        let new_value_hash = kv_hash(&Some(value));

                        (slot_index, old_value_hash, new_value_hash)
                    })
                    .collect::<Vec<_>>();

                // Apply deltas to get final bucket commitment
                let bucket_commitment = committer
                    .add_deltas(default_commitment, &delta_indices)
                    .to_bytes_uncompressed();

                (bucket_index as usize, bucket_commitment)
            })
            .collect::<Vec<_>>();

        // ========== Step 4: Bottom-up aggregation to target node ==========
        // Iteratively combine child commitments into parent commitments,
        // working our way up the tree until we reach the target node level.

        for _ in (node_level + 1..MAIN_TRIE_LEVELS).rev() {
            // Group child nodes by their parent node
            // Map structure: parent_index -> (child_slot_indices, child_commitments)
            let mut parent_to_children = BTreeMap::new();

            for (child_node_index, child_commitment) in level_commitments {
                let parent_node_index = child_node_index / MIN_BUCKET_SIZE;
                let child_slot_in_parent = child_node_index % MIN_BUCKET_SIZE;

                let parent_entry = parent_to_children
                    .entry(parent_node_index)
                    .or_insert((vec![], vec![]));
                parent_entry.0.push(child_slot_in_parent);
                parent_entry.1.push(child_commitment);
            }

            // Compute parent commitments from their children
            level_commitments = parent_to_children
                .into_par_iter()
                .map(|(parent_index, (child_slot_indices, child_commitments))| {
                    // Hash the child commitments to get elements for delta computation
                    let hashed_children = Element::hash_commitments(&child_commitments);

                    // Create delta indices: (slot_index, old_hash, new_hash)
                    let parent_delta_indices = hashed_children
                        .into_iter()
                        .zip(child_slot_indices)
                        .map(|(child_hash, slot_index)| {
                            let old_value = [0u8; 32];
                            (slot_index, old_value, child_hash)
                        })
                        .collect::<Vec<_>>();

                    // Compute parent commitment by applying deltas to zero commitment
                    let parent_commitment = committer
                        .add_deltas(zero_commitment, &parent_delta_indices)
                        .to_bytes_uncompressed();

                    (parent_index, parent_commitment)
                })
                .collect();
        }

        // At this point, we should have exactly one commitment: our target node
        assert!(
            !level_commitments.is_empty(),
            "Should have at least one commitment after aggregation"
        );
        level_commitments[0].1
    }

    /// Tests incremental trie updates (applying changes sequentially to the same
    /// trie instance) produce identical results to batch updates (applying all
    /// changes at once to a fresh trie).
    #[test]
    fn test_incremental_vs_batch_update() {
        let mut trie = StateRoot::new(&EmptySalt); // Trie for incremental updates
        let mut cumulative = StateUpdates::default(); // Tracks all changes for batch comparison

        // Test data: 3 keys in bucket 65538
        let (k1, k2, k3) = (
            SaltKey::from((65538, 0)),
            SaltKey::from((65538, 1)),
            SaltKey::from((65538, 2)),
        );
        let (v1, v2, v3) = (
            SaltValue::new(&[1; 32], &[1; 32]),
            SaltValue::new(&[2; 32], &[2; 32]),
            SaltValue::new(&[3; 32], &[3; 32]),
        );

        // Update 1: Insert 3 keys
        let mut updates1 = StateUpdates::default();
        updates1.add(k1, None, Some(v1.clone()));
        updates1.add(k2, None, Some(v2.clone()));
        updates1.add(k3, None, Some(v3));
        cumulative.merge(updates1.clone());
        trie.update_fin(updates1).unwrap();

        // Update 2: k1: v1 → v2
        let mut updates2 = StateUpdates::default();
        updates2.add(k1, Some(v1.clone()), Some(v2.clone()));
        cumulative.merge(updates2.clone());

        let (incremental_root2, _) = trie.update_fin(updates2).unwrap();
        let (batch_root2, _) = StateRoot::new(&EmptySalt)
            .update_fin(cumulative.clone())
            .unwrap();
        assert_eq!(incremental_root2, batch_root2);

        // Update 3: k2: v2 → v1
        let mut updates3 = StateUpdates::default();
        updates3.add(k2, Some(v2), Some(v1));
        cumulative.merge(updates3.clone());

        let (incremental_root3, _) = trie.update_fin(updates3).unwrap();
        let (batch_root3, _) = StateRoot::new(&EmptySalt).update_fin(cumulative).unwrap();
        assert_eq!(incremental_root3, batch_root3);
    }

    #[test]
    fn expansion_and_contraction_no_kvchanges() {
        let store = MemStore::new();
        let mut trie = StateRoot::new(&store);
        let bid = KV_BUCKET_OFFSET as BucketId + 4;
        let salt_key = bucket_metadata_key(bid);
        // initialize the trie
        let state_updates = StateUpdates {
            data: vec![(
                (bid, 3).into(),
                (None, Some(SaltValue::new(&[1; 32], &[1; 32]))),
            )]
            .into_iter()
            .collect(),
        };
        let (root, trie_updates) = trie.update_fin(state_updates.clone()).unwrap();
        store.update_state(state_updates);
        store.update_trie(trie_updates);

        // only expand capacity
        let state_updates = StateUpdates {
            data: vec![(
                salt_key,
                (
                    Some(BucketMeta::default().into()),
                    Some(bucket_meta(0, 131072).into()),
                ),
            )]
            .into_iter()
            .collect(),
        };
        let (root1, trie_updates) = trie.update_fin(state_updates.clone()).unwrap();
        store.update_state(state_updates);
        store.update_trie(trie_updates);
        let (cmp_root, _) = StateRoot::rebuild(&store).unwrap();
        assert_eq!(root1, cmp_root);

        // only ‌contract capacity
        let state_updates = StateUpdates {
            data: vec![(
                salt_key,
                (
                    Some(bucket_meta(0, 131072).into()),
                    Some(BucketMeta::default().into()),
                ),
            )]
            .into_iter()
            .collect(),
        };
        let (root1, _) = trie.update_fin(state_updates).unwrap();
        assert_eq!(root1, root);
    }

    /// Tests bucket capacity expansion and contraction within the same subtree level.
    ///
    /// This test verifies that the trie correctly handles bucket capacity changes
    /// when those changes don't change the bucket subtree's root.
    ///
    /// The test uses capacities 512, 4096, and 1024, all of which require a Level 3
    /// subtree root, ensuring the trie structure remains stable during resizing.
    ///
    /// # Test Flow
    /// 1. **Initial Setup**: Create bucket with capacity 512 and one key-value pair
    /// 2. **Expansion**: Increase capacity to 4096, add a key at a high slot
    /// 3. **Contraction**: Reduce capacity to 1024, remove the out-of-bounds key
    ///
    /// # Verification Strategy
    /// After each operation, the test:
    /// - Updates the trie incrementally using `update_fin()`
    /// - Rebuilds the entire trie from scratch using `rebuild()`
    /// - Verifies both methods produce identical root hashes
    ///
    /// This ensures incremental updates correctly maintain trie integrity
    /// during capacity changes that don't alter the subtree structure.
    #[test]
    fn expansion_and_contraction_at_same_level() {
        let store = MemStore::new();
        let mut trie = StateRoot::new(&store);

        // Use data bucket 65540 (NUM_META_BUCKETS + 4)
        // Data buckets start at 65536, so this is the 5th data bucket
        let bid = KV_BUCKET_OFFSET as BucketId + 4;
        let meta_key = bucket_metadata_key(bid);

        // Define test phases: (old_capacity, new_capacity, slot_changes)
        // All capacities (512, 4096, 1024) require Level 3 as subtree root:
        // - 512 > 256 but < 65,536: needs 2 Level 4 nodes (512/256 = 2)
        // - 4096 < 65,536: needs 16 Level 4 nodes (4096/256 = 16)
        // - 1024 < 65,536: needs 4 Level 4 nodes (1024/256 = 4)
        // The subtree root stays at Level 3 throughout, hence "same level"
        let phases = [
            // Phase 1: Initialize with capacity 512, add key at slot 1
            // Creates subtree with 2 Level 4 nodes under Level 3 root
            (None, 512, vec![(1, None, Some([1; 32]))]),
            // Phase 2: Expand to 4096, add key at slot 4090 near end of range
            // Expands subtree to 16 Level 4 nodes, root still at Level 3
            (Some(512), 4096, vec![(4090, None, Some([2; 32]))]),
            // Phase 3: Contract to 1024, remove key now out of bounds
            // Contracts subtree to 4 Level 4 nodes, root remains at Level 3
            (Some(4096), 1024, vec![(4090, Some([2; 32]), None)]),
        ];

        for (phase, (old_cap, new_cap, slot_changes)) in phases.iter().enumerate() {
            // Build metadata update for capacity change
            let mut updates = vec![(
                meta_key,
                (
                    // Old metadata: either previous capacity or default (256)
                    old_cap
                        .map(|c| bucket_meta(0, c).into())
                        .or(Some(BucketMeta::default().into())),
                    // New metadata: target capacity
                    Some(bucket_meta(0, *new_cap).into()),
                ),
            )];

            // Add slot-level changes (insertions/deletions)
            for (slot, old_val, new_val) in slot_changes {
                updates.push((
                    (bid, *slot).into(),
                    (
                        old_val.map(|v| SaltValue::new(&v, &v)),
                        new_val.map(|v| SaltValue::new(&v, &v)),
                    ),
                ));
            }

            let state_updates = StateUpdates {
                data: updates.into_iter().collect(),
            };

            // Apply incremental updates and verify against full rebuild
            let (root, trie_updates) = trie.update_fin(state_updates.clone()).unwrap();
            store.update_state(state_updates);
            store.update_trie(trie_updates);

            // Ensure incremental update matches full trie reconstruction
            let (rebuilt_root, _) = StateRoot::rebuild(&store).unwrap();
            assert_eq!(root, rebuilt_root, "Phase {} root mismatch", phase + 1);
        }
    }

    #[test]
    fn expansion_and_contraction_small() {
        let store = MemStore::new();
        let mut trie = StateRoot::new(&store);
        let bid = KV_BUCKET_OFFSET as BucketId + 4;
        let salt_key = bucket_metadata_key(bid);
        // initialize the trie
        let initialize_state_updates = StateUpdates {
            data: vec![
                (
                    (bid, 3).into(),
                    (None, Some(SaltValue::new(&[1; 32], &[1; 32]))),
                ),
                (
                    (bid, 5).into(),
                    (None, Some(SaltValue::new(&[2; 32], &[2; 32]))),
                ),
            ]
            .into_iter()
            .collect(),
        };

        let (initialize_root, initialize_trie_updates) =
            trie.update_fin(initialize_state_updates.clone()).unwrap();
        store.update_state(initialize_state_updates);
        store.update_trie(initialize_trie_updates);
        let (root, mut init_trie_updates) = StateRoot::rebuild(&store).unwrap();
        init_trie_updates.par_sort_unstable_by(|(a, _), (b, _)| b.cmp(a));
        assert_eq!(root, initialize_root);

        // expand capacity and add kvs
        let new_capacity = 131072;
        let expand_state_updates = StateUpdates {
            data: vec![
                (
                    salt_key,
                    (
                        Some(BucketMeta::default().into()),
                        Some(bucket_meta(0, new_capacity).into()),
                    ),
                ),
                (
                    (bid, 3).into(),
                    (Some(SaltValue::new(&[1; 32], &[1; 32])), None),
                ),
                (
                    (bid, 2049).into(),
                    (None, Some(SaltValue::new(&[3; 32], &[3; 32]))),
                ),
                (
                    (bid, new_capacity - 259).into(),
                    (None, Some(SaltValue::new(&[4; 32], &[4; 32]))),
                ),
                (
                    (bid, new_capacity - 1).into(),
                    (None, Some(SaltValue::new(&[5; 32], &[5; 32]))),
                ),
            ]
            .into_iter()
            .collect(),
        };
        let (expansion_root, trie_updates) = trie.update_fin(expand_state_updates.clone()).unwrap();
        store.update_state(expand_state_updates);
        store.update_trie(trie_updates);
        let (root, _) = StateRoot::rebuild(&store).unwrap();
        assert_eq!(root, expansion_root);
        // update expansion bucket
        let expand_state_updates = StateUpdates {
            data: vec![(
                (bid, new_capacity - 1).into(),
                (
                    Some(SaltValue::new(&[5; 32], &[5; 32])),
                    Some(SaltValue::new(&[5; 32], &[6; 32])),
                ),
            )]
            .into_iter()
            .collect(),
        };
        let (expansion_root, trie_updates) = trie.update_fin(expand_state_updates.clone()).unwrap();
        store.update_state(expand_state_updates);
        store.update_trie(trie_updates);
        let (root, _) = StateRoot::rebuild(&store).unwrap();
        assert_eq!(root, expansion_root);

        // contract capacity and remove kvs
        let contract_state_updates = StateUpdates {
            data: vec![
                (
                    salt_key,
                    (
                        Some(bucket_meta(0, new_capacity).into()),
                        Some(bucket_meta(0, 1024).into()),
                    ),
                ),
                (
                    (bid, 3).into(),
                    (None, Some(SaltValue::new(&[1; 32], &[1; 32]))),
                ),
                (
                    (bid, 2049).into(),
                    (Some(SaltValue::new(&[3; 32], &[3; 32])), None),
                ),
                (
                    (bid, new_capacity - 259).into(),
                    (Some(SaltValue::new(&[4; 32], &[4; 32])), None),
                ),
                (
                    (bid, new_capacity - 1).into(),
                    (Some(SaltValue::new(&[5; 32], &[6; 32])), None),
                ),
            ]
            .into_iter()
            .collect(),
        };
        let (contraction_root, trie_updates) =
            trie.update_fin(contract_state_updates.clone()).unwrap();
        store.update_state(contract_state_updates);
        store.update_trie(trie_updates);
        let (root, _) = StateRoot::rebuild(&store).unwrap();
        assert_eq!(root, contraction_root);

        let contract_state_updates = StateUpdates {
            data: vec![(
                salt_key,
                (
                    Some(bucket_meta(0, 1024).into()),
                    Some(bucket_meta(0, 256).into()),
                ),
            )]
            .into_iter()
            .collect(),
        };
        let (contraction_root, _) = trie.update_fin(contract_state_updates).unwrap();
        assert_eq!(initialize_root, contraction_root);
    }

    #[test]
    fn expansion_and_contraction_large() {
        let store = MemStore::new();
        let mut trie = StateRoot::new(&store);
        let mut state_updates = StateUpdates::default();

        for bid in KV_BUCKET_OFFSET..KV_BUCKET_OFFSET + 10000 {
            for slot_id in 0..128 {
                state_updates.data.insert(
                    (bid as BucketId, slot_id).into(),
                    (
                        None,
                        Some(SaltValue::new(&[slot_id as u8; 32], &[slot_id as u8; 32])),
                    ),
                );
            }
        }

        let (root, trie_updates) = trie.update_fin(state_updates.clone()).unwrap();
        store.update_state(state_updates);
        store.update_trie(trie_updates);
        let (root1, _) = StateRoot::rebuild(&store).unwrap();
        assert_eq!(root, root1);

        // extend the trie
        let expand_capacity = 131072;
        let mut state_updates = StateUpdates::default();
        for bid in KV_BUCKET_OFFSET..KV_BUCKET_OFFSET + 100 {
            let salt_key: SaltKey = (
                bid as BucketId >> MIN_BUCKET_SIZE_BITS,
                bid as SlotId % MIN_BUCKET_SIZE as SlotId,
            )
                .into();
            state_updates.data.insert(
                salt_key,
                (
                    Some(BucketMeta::default().into()),
                    Some(bucket_meta(0, expand_capacity).into()),
                ),
            );
            for slot_id in 200..300 {
                state_updates.data.insert(
                    (bid as BucketId, slot_id).into(),
                    (None, Some(SaltValue::new(&[1; 32], &[1; 32]))),
                );
            }
            let start = expand_capacity - 200;
            for slot_id in start..start + 100 {
                state_updates.data.insert(
                    (bid as BucketId, slot_id).into(),
                    (None, Some(SaltValue::new(&[1; 32], &[1; 32]))),
                );
            }
        }

        let (extended_root, trie_updates) = trie.update_fin(state_updates.clone()).unwrap();
        store.update_state(state_updates);
        store.update_trie(trie_updates);
        let (root2, _) = StateRoot::rebuild(&store).unwrap();
        assert_eq!(root2, extended_root);

        // contract the trie
        let mut state_updates = StateUpdates::default();
        for bid in KV_BUCKET_OFFSET..KV_BUCKET_OFFSET + 10 {
            let salt_key: SaltKey = (
                bid as BucketId >> MIN_BUCKET_SIZE_BITS,
                bid as SlotId % MIN_BUCKET_SIZE as SlotId,
            )
                .into();
            state_updates.data.insert(
                salt_key,
                (
                    Some(bucket_meta(0, expand_capacity).into()),
                    Some(BucketMeta::default().into()),
                ),
            );
            for slot_id in 200..300 {
                state_updates.data.insert(
                    (bid as BucketId, slot_id).into(),
                    (Some(SaltValue::new(&[1; 32], &[1; 32])), None),
                );
            }

            let start = expand_capacity - 200;
            for slot_id in start..start + 100 {
                state_updates.data.insert(
                    (bid as BucketId, slot_id).into(),
                    (Some(SaltValue::new(&[1; 32], &[1; 32])), None),
                );
            }
        }
        let (contraction_root, trie_updates) = trie.update_fin(state_updates.clone()).unwrap();
        store.update_state(state_updates);
        store.update_trie(trie_updates);
        let (root3, _) = StateRoot::rebuild(&store).unwrap();
        assert_eq!(root3, contraction_root);
    }

    #[test]
    fn incremental_update_small() {
        // set expansion bucket metadata and check update with expanded bucket
        let update_bid = KV_BUCKET_OFFSET as BucketId + 2;
        let extend_bid = KV_BUCKET_OFFSET as BucketId + 3;
        let meta = bucket_meta(0, 65536 * 2);

        let state_updates1 = StateUpdates {
            data: vec![
                (
                    (KV_BUCKET_OFFSET as BucketId + 1, 1).into(),
                    (None, Some(SaltValue::new(&[1; 32], &[1; 32]))),
                ),
                (
                    (KV_BUCKET_OFFSET as BucketId + 65538, 2).into(),
                    (None, Some(SaltValue::new(&[2; 32], &[2; 32]))),
                ),
            ]
            .into_iter()
            .collect(),
        };

        let state_updates2 = StateUpdates {
            data: vec![
                (
                    (KV_BUCKET_OFFSET as BucketId + 65538, 2).into(),
                    (
                        Some(SaltValue::new(&[2; 32], &[2; 32])),
                        Some(SaltValue::new(&[3; 32], &[3; 32])),
                    ),
                ),
                (
                    (KV_BUCKET_OFFSET as BucketId + 65538, 3).into(),
                    (None, Some(SaltValue::new(&[3; 32], &[3; 32]))),
                ),
                // keys for expand bucket
                (
                    bucket_metadata_key(extend_bid),
                    (
                        Some(BucketMeta::default().into()),
                        Some(bucket_meta(0, 512).into()),
                    ),
                ),
                (
                    (extend_bid, 333).into(),
                    (None, Some(SaltValue::new(&[44; 32], &[44; 32]))),
                ),
                // keys for update expanded bucket
                (
                    bucket_metadata_key(update_bid),
                    (
                        Some(BucketMeta::default().into()),
                        Some(SaltValue::from(meta)),
                    ),
                ),
                (
                    (update_bid, 258).into(),
                    (None, Some(SaltValue::new(&[66; 32], &[66; 32]))),
                ),
                (
                    (update_bid, 1023).into(),
                    (None, Some(SaltValue::new(&[77; 32], &[77; 32]))),
                ),
            ]
            .into_iter()
            .collect(),
        };

        let trie_reader = &EmptySalt;
        let mut state_updates = StateUpdates::default();
        let mut trie = StateRoot::new(trie_reader);
        trie.update(state_updates1.clone()).unwrap();
        state_updates.merge(state_updates1);
        trie.update(state_updates2.clone()).unwrap();
        state_updates.merge(state_updates2);
        let (root, mut trie_updates) = trie.finalize().unwrap();

        let cmp_state_updates = StateUpdates {
            data: vec![
                (
                    (KV_BUCKET_OFFSET as BucketId + 1, 1).into(),
                    (None, Some(SaltValue::new(&[1; 32], &[1; 32]))),
                ),
                (
                    (KV_BUCKET_OFFSET as BucketId + 65538, 2).into(),
                    (None, Some(SaltValue::new(&[3; 32], &[3; 32]))),
                ),
                (
                    (KV_BUCKET_OFFSET as BucketId + 65538, 3).into(),
                    (None, Some(SaltValue::new(&[3; 32], &[3; 32]))),
                ),
                // keys for expand bucket
                (
                    bucket_metadata_key(extend_bid),
                    (
                        Some(BucketMeta::default().into()),
                        Some(bucket_meta(0, 512).into()),
                    ),
                ),
                (
                    bucket_metadata_key(update_bid),
                    (
                        Some(BucketMeta::default().into()),
                        Some(SaltValue::from(meta)),
                    ),
                ),
                (
                    (extend_bid, 333).into(),
                    (None, Some(SaltValue::new(&[44; 32], &[44; 32]))),
                ),
                // keys for update expanded bucket
                (
                    (update_bid, 258).into(),
                    (None, Some(SaltValue::new(&[66; 32], &[66; 32]))),
                ),
                (
                    (update_bid, 1023).into(),
                    (None, Some(SaltValue::new(&[77; 32], &[77; 32]))),
                ),
            ]
            .into_iter()
            .collect(),
        };
        assert_eq!(cmp_state_updates, state_updates);

        let mut trie = StateRoot::new(trie_reader);
        let (cmp_root, mut cmp_trie_updates) = trie.update_fin(cmp_state_updates).unwrap();
        assert_eq!(root, cmp_root);
        trie_updates.par_sort_unstable_by(|(a, _), (b, _)| a.cmp(b));
        cmp_trie_updates.par_sort_unstable_by(|(a, _), (b, _)| a.cmp(b));
        trie_updates.iter().zip(cmp_trie_updates.iter()).for_each(
            |(trie_update, cmp_trie_update)| {
                assert_eq!(trie_update.0, cmp_trie_update.0);
                assert!(is_commitment_equal(trie_update.1 .0, cmp_trie_update.1 .0));
                assert!(is_commitment_equal(trie_update.1 .1, cmp_trie_update.1 .1));
            },
        );
    }

    #[test]
    fn increment_updates_large() {
        let kvs = create_random_account(10000);
        let mock_db = MemStore::new();
        let mut state = EphemeralSaltState::new(&mock_db);
        let mut trie = StateRoot::new(&mock_db);
        let total_state_updates = state.update(&kvs).unwrap();
        let (root, mut total_trie_updates) = trie.update_fin(total_state_updates.clone()).unwrap();

        let sub_kvs: Vec<HashMap<Vec<u8>, Option<Vec<u8>>>> = kvs
            .into_iter()
            .chunks(1000)
            .into_iter()
            .map(|chunk| chunk.collect::<HashMap<Vec<u8>, Option<Vec<u8>>>>())
            .collect();

        let mut state = EphemeralSaltState::new(&mock_db);
        let mut trie = StateRoot::new(&mock_db);
        let mut final_state_updates = StateUpdates::default();
        for kvs in &sub_kvs {
            let state_updates = state.update(kvs).unwrap();
            trie.update(state_updates.clone()).unwrap();
            final_state_updates.merge(state_updates);
        }
        let (final_root, mut final_trie_updates) = trie.finalize().unwrap();

        assert_eq!(root, final_root);
        assert_eq!(total_state_updates, final_state_updates);
        total_trie_updates.par_sort_unstable_by(|(a, _), (b, _)| a.cmp(b));
        final_trie_updates.par_sort_unstable_by(|(a, _), (b, _)| a.cmp(b));
        total_trie_updates
            .iter()
            .zip(final_trie_updates.iter())
            .for_each(|(r1, r2)| {
                assert_eq!(r1.0, r2.0);
                assert!(is_commitment_equal(r1.1 .0, r2.1 .0));
                assert!(is_commitment_equal(r1.1 .1, r2.1 .1));
            });
    }

    #[test]
    fn test_rebuild_small() {
        let mock_db = MemStore::new();
        let mut trie = StateRoot::new(&mock_db);
        let mut state_updates = StateUpdates::default();

        let bid = KV_BUCKET_OFFSET as BucketId;
        let salt_key: SaltKey = bucket_metadata_key(bid);
        // bucket meta changes at bucket[bid]
        state_updates.data.insert(
            salt_key,
            (
                Some(SaltValue::from(BucketMeta::default())),
                Some(SaltValue::from(bucket_meta(15, 512))),
            ),
        );

        state_updates.data.insert(
            (bid, 1).into(),
            (None, Some(SaltValue::new(&[1; 32], &[1; 32]))),
        );
        state_updates.data.insert(
            (bid, 2).into(),
            (None, Some(SaltValue::new(&[2; 32], &[2; 32]))),
        );
        state_updates.data.insert(
            (bid + 1, 111).into(),
            (None, Some(SaltValue::new(&[2; 32], &[2; 32]))),
        );
        state_updates.data.insert(
            (bid + 65536, 55).into(),
            (None, Some(SaltValue::new(&[3; 32], &[3; 32]))),
        );

        let (root0, _) = trie.update_fin(state_updates.clone()).unwrap();
        mock_db.update_state(state_updates);
        let (root1, trie_updates) = StateRoot::rebuild(&mock_db).unwrap();

        let node_id = bid as NodeId / (MIN_BUCKET_SIZE * MIN_BUCKET_SIZE) as NodeId;
        let c = rebuild_subtrie_without_expanded_buckets(node_id, &mock_db);
        mock_db.update_trie(trie_updates);
        assert_eq!(
            hash_commitment(c),
            hash_commitment(mock_db.commitment(node_id).unwrap())
        );

        assert_eq!(root0, root1);
    }

    #[test]
    fn test_rebuild_large() {
        let mock_db = MemStore::new();
        let mut trie = StateRoot::new(&mock_db);
        let mut state_updates = StateUpdates::default();

        // bucket nonce changes
        state_updates.data.insert(
            (256, 0).into(),
            (
                Some(SaltValue::from(BucketMeta::default())),
                Some(SaltValue::from(bucket_meta(10, MIN_BUCKET_SIZE as SlotId))),
            ),
        );

        state_updates.data.insert(
            (65535, 255).into(),
            (
                Some(SaltValue::from(BucketMeta::default())),
                Some(SaltValue::from(bucket_meta(11, MIN_BUCKET_SIZE as SlotId))),
            ),
        );

        // key-value pairs changes
        for i in KV_BUCKET_OFFSET..KV_BUCKET_OFFSET + 1000 {
            for j in 0..256 {
                state_updates.data.insert(
                    (i as BucketId, j).into(),
                    (None, Some(SaltValue::new(&[j as u8; 32], &[j as u8; 32]))),
                );
            }
        }

        let (root0, _) = trie.update_fin(state_updates.clone()).unwrap();
        mock_db.update_state(state_updates);
        let (root1, _) = StateRoot::rebuild(&mock_db).unwrap();

        assert_eq!(root0, root1);
    }

    #[test]
    fn test_add_commitment_deltas() {
        let store = EmptySalt;
        let elements: Vec<Element> = create_commitments(11)
            .iter()
            .map(|c| Element::from_bytes_unchecked_uncompressed(*c))
            .collect();
        let binding = EmptySalt;
        let trie = StateRoot::new(&binding);
        let task_size = 3;
        let c_deltas = vec![
            (0, elements[0]),
            (1, elements[1]),
            (1, elements[2]),
            (2, elements[3]),
            (2, elements[4]),
            (2, elements[5]),
            (2, elements[6]),
            (3, elements[7]),
            (3, elements[8]),
            (4, elements[9]),
            (4, elements[10]),
        ];

        // expected ranges[(0,3), (3,7), (7,11)]
        let ranges = get_delta_ranges(&c_deltas, task_size);
        assert_eq!(vec![(0, 3), (3, 7), (7, 11)], ranges);

        let updates = trie
            .add_commitment_deltas(c_deltas.clone(), task_size)
            .unwrap();

        let exp_id_vec = [0 as NodeId, 1, 2, 3, 4];
        assert_eq!(exp_id_vec.len(), updates.len());
        updates
            .iter()
            .zip(exp_id_vec.iter())
            .for_each(|((id, (old_c, new_c)), exp_id)| {
                assert_eq!(*id, *exp_id);
                let cmp_old_c = store.commitment(*id).unwrap();
                assert_eq!(cmp_old_c, *old_c);

                let delta: Element = c_deltas
                    .iter()
                    .filter(|(i, _)| *i == *id)
                    .map(|(_, e)| *e)
                    .sum();

                let cmp_new_c = (Element::from_bytes_unchecked_uncompressed(cmp_old_c) + delta)
                    .to_bytes_uncompressed();
                assert_eq!(cmp_new_c, *new_c);
            });
    }

    #[test]
    fn trie_update_leaf_nodes() {
        let store = MemStore::new();
        let trie = StateRoot::new(&store);
        let committer = &trie.committer;
        let mut state_updates = StateUpdates::default();
        let key = [[1u8; 32], [2u8; 32], [3u8; 32]];
        let value = [100u8; 32];
        let bottom_level = MAIN_TRIE_LEVELS - 1;
        let bottom_level_start = STARTING_NODE_ID[bottom_level] as NodeId;
        let kv_none = kv_hash(&None);

        // Add the kv state updates
        state_updates.add(
            (KV_BUCKET_OFFSET as BucketId + 1, 1).into(),
            None,
            Some(SaltValue::new(&key[0], &value)),
        );
        state_updates.add(
            (KV_BUCKET_OFFSET as BucketId + 1, 2).into(),
            None,
            Some(SaltValue::new(&key[1], &value)),
        );
        // Add the bucket meta state updates
        state_updates.add(
            (4, 1).into(),
            Some(SaltValue::from(BucketMeta::default())),
            Some(SaltValue::from(bucket_meta(5, MIN_BUCKET_SIZE as SlotId))),
        );

        let salt_updates = trie.update_bucket_subtrees(state_updates).unwrap();

        let bottom_meta_c = default_commitment(STARTING_NODE_ID[bottom_level] as NodeId);
        let bottom_data_c =
            default_commitment((STARTING_NODE_ID[bottom_level] + NUM_META_BUCKETS) as NodeId);
        let c1 = committer
            .add_deltas(
                bottom_meta_c,
                &[(
                    1,
                    kv_hash(&Some(SaltValue::from(BucketMeta::default()))),
                    kv_hash(&Some(SaltValue::from(bucket_meta(
                        5,
                        MIN_BUCKET_SIZE as SlotId,
                    )))),
                )],
            )
            .to_bytes_uncompressed();
        let c2 = committer
            .add_deltas(
                bottom_data_c,
                &[
                    (1, kv_none, kv_hash(&Some(SaltValue::new(&key[0], &value)))),
                    (2, kv_none, kv_hash(&Some(SaltValue::new(&key[1], &value)))),
                ],
            )
            .to_bytes_uncompressed();

        assert_eq!(
            salt_updates,
            vec![
                (4 + bottom_level_start, (bottom_meta_c, c1)),
                (
                    bottom_level_start + KV_BUCKET_OFFSET + 1,
                    (bottom_data_c, c2)
                )
            ]
        );
    }

    #[test]
    fn trie_update_internal_nodes() {
        let bottom_level = MAIN_TRIE_LEVELS - 1;
        let trie = StateRoot::new(&EmptySalt);
        let committer = &trie.committer;
        let bottom_meta_c = default_commitment(STARTING_NODE_ID[bottom_level] as NodeId);
        let bottom_data_c =
            default_commitment((STARTING_NODE_ID[bottom_level] + NUM_META_BUCKETS) as NodeId);
        //let (zero, nonce_c) = (zero_commitment(), bottom_meta_c);
        let bottom_level_start = STARTING_NODE_ID[bottom_level] as NodeId;
        let cs = create_commitments(3);

        let updates = vec![
            (bottom_level_start + 1, (bottom_meta_c, cs[0])),
            (
                bottom_level_start + KV_BUCKET_OFFSET + 1,
                (bottom_data_c, cs[1]),
            ),
            (
                bottom_level_start + KV_BUCKET_OFFSET + 2,
                (bottom_data_c, cs[2]),
            ),
        ];

        // Check and handle the commitment updates of the bottom-level node
        let cur_level = bottom_level - 1;
        let unprocess_updates = trie.update_internal_nodes(updates).unwrap();

        let bytes_indices =
            Element::hash_commitments(&[bottom_data_c, bottom_meta_c, cs[0], cs[1], cs[2]]);
        let l3_meta_c = default_commitment(STARTING_NODE_ID[cur_level] as NodeId);
        let l3_data_c = default_commitment(STARTING_NODE_ID[cur_level] as NodeId + 256);
        let c1 = committer
            .add_deltas(l3_meta_c, &[(1, bytes_indices[1], bytes_indices[2])])
            .to_bytes_uncompressed();

        let c2 = committer
            .add_deltas(
                l3_data_c,
                &[
                    (1, bytes_indices[0], bytes_indices[3]),
                    (2, bytes_indices[0], bytes_indices[4]),
                ],
            )
            .to_bytes_uncompressed();

        assert_eq!(
            unprocess_updates,
            vec![(257, (l3_meta_c, c1)), (513, (l3_data_c, c2))]
        );

        // Check and handle the commitment updates of the second-level node
        let cur_level = cur_level - 1;
        let unprocess_updates = trie.update_internal_nodes(unprocess_updates).unwrap();

        let bytes_indices = Element::hash_commitments(&[l3_data_c, l3_meta_c, c1, c2]);
        let l2_meta_c = default_commitment(STARTING_NODE_ID[cur_level] as NodeId);
        let l2_data_c = default_commitment(STARTING_NODE_ID[cur_level] as NodeId + 1);
        let c3 = committer
            .add_deltas(l2_meta_c, &[(0, bytes_indices[1], bytes_indices[2])])
            .to_bytes_uncompressed();
        let c4 = committer
            .add_deltas(l2_data_c, &[(0, bytes_indices[0], bytes_indices[3])])
            .to_bytes_uncompressed();

        assert_eq!(
            unprocess_updates,
            vec![(1, (l2_meta_c, c3)), (2, (l2_data_c, c4))]
        );

        let cur_level = cur_level - 1;
        let unprocess_updates = trie.update_internal_nodes(unprocess_updates).unwrap();
        let bytes_indices = Element::hash_commitments(&[l2_data_c, l2_meta_c, c3, c4]);
        let l1_c = default_commitment(STARTING_NODE_ID[cur_level] as NodeId);
        let c5 = committer
            .add_deltas(
                l1_c,
                &[
                    (0, bytes_indices[1], bytes_indices[2]),
                    (1, bytes_indices[0], bytes_indices[3]),
                ],
            )
            .to_bytes_uncompressed();
        assert_eq!(unprocess_updates, vec![(0, (l1_c, c5))]);
    }

    #[test]
    fn trie_calculate_inner() {
        let mut trie = StateRoot::new(&EmptySalt);

        let mut state_updates = StateUpdates::default();
        let kv1 = Some(SaltValue::new(&[1; 32], &[1; 32]));
        let kv2 = Some(SaltValue::new(&[2; 32], &[2; 32]));
        let fr1 = kv_hash(&kv1);
        let fr2 = kv_hash(&kv2);
        let kv_none = kv_hash(&None);
        let default_bucket_data =
            default_commitment(bucket_root_node_id(NUM_META_BUCKETS as BucketId));

        // Prepare the state updates
        let bucket_ids = [
            KV_BUCKET_OFFSET as BucketId + 257,
            KV_BUCKET_OFFSET as BucketId + 65536,
        ];
        state_updates.add((bucket_ids[0], 1).into(), None, kv1.clone());
        state_updates.add((bucket_ids[0], 9).into(), None, kv2.clone());
        state_updates.add((bucket_ids[1], 9).into(), kv1, kv2);

        let (_, mut trie_updates) = trie.update_fin(state_updates).unwrap();
        trie_updates.par_sort_unstable_by(|(a, _), (b, _)| b.cmp(a));

        // Check the commitment updates of the bottom-level node
        let committer = &trie.committer;
        let c1 = committer
            .add_deltas(default_bucket_data, &[(9, fr1, fr2)])
            .to_bytes_uncompressed();
        let c2 = committer
            .add_deltas(default_bucket_data, &[(1, kv_none, fr1), (9, kv_none, fr2)])
            .to_bytes_uncompressed();
        assert_eq!(
            trie_updates[0..2],
            vec![
                (
                    bucket_root_node_id(bucket_ids[1]),
                    (default_bucket_data, c1)
                ),
                (
                    bucket_root_node_id(bucket_ids[0]),
                    (default_bucket_data, c2)
                ),
            ]
        );

        // Check the commitment updates of the TRIE_LEVELS - 2 level node
        let default_l3_c = default_commitment((STARTING_NODE_ID[2] + 256) as NodeId);
        let bytes_indices = Element::hash_commitments(&[default_bucket_data, c1, c2]);
        let c3 = committer
            .add_deltas(default_l3_c, &[(0, bytes_indices[0], bytes_indices[1])])
            .to_bytes_uncompressed();
        let c4 = committer
            .add_deltas(default_l3_c, &[(1, bytes_indices[0], bytes_indices[2])])
            .to_bytes_uncompressed();
        assert_eq!(
            trie_updates[2..4],
            vec![
                (
                    STARTING_NODE_ID[MAIN_TRIE_LEVELS - 2] as NodeId
                        + bucket_ids[1] as NodeId / 256,
                    (default_l3_c, c3)
                ),
                (
                    STARTING_NODE_ID[MAIN_TRIE_LEVELS - 2] as NodeId
                        + bucket_ids[0] as NodeId / 256,
                    (default_l3_c, c4)
                ),
            ]
        );

        // Check the commitment updates of the TRIE_LEVELS - 3 level node
        let default_l2_c = default_commitment((STARTING_NODE_ID[1] + 1) as NodeId);
        let bytes_indices = Element::hash_commitments(&[default_l3_c, c3, c4]);
        let c5 = committer
            .add_deltas(default_l2_c, &[(0, bytes_indices[0], bytes_indices[1])])
            .to_bytes_uncompressed();
        let c6 = committer
            .add_deltas(default_l2_c, &[(1, bytes_indices[0], bytes_indices[2])])
            .to_bytes_uncompressed();
        assert_eq!(
            trie_updates[4..6],
            vec![
                (
                    STARTING_NODE_ID[MAIN_TRIE_LEVELS - 3] as NodeId
                        + bucket_ids[1] as NodeId / 65536,
                    (default_l2_c, c5)
                ),
                (
                    STARTING_NODE_ID[MAIN_TRIE_LEVELS - 3] as NodeId
                        + bucket_ids[0] as NodeId / 65536,
                    (default_l2_c, c6)
                ),
            ]
        );

        // Check the commitment updates of the last level node
        let default_l1_c = default_commitment(STARTING_NODE_ID[0] as NodeId);
        assert_eq!(trie_updates[6].0, 0);
        let bytes_indices = Element::hash_commitments(&[default_l2_c, c5, c6]);
        let c7 = committer
            .add_deltas(
                default_l1_c,
                &[
                    (2, bytes_indices[0], bytes_indices[1]),
                    (1, bytes_indices[0], bytes_indices[2]),
                ],
            )
            .to_bytes_uncompressed();
        assert_eq!(trie_updates[6], (0, (default_l1_c, c7)));
    }

    /// Checks if the default commitment is correct
    #[test]
    fn trie_level_default_committment() {
        let zero = Committer::zero();
        let mut default_committment_vec = vec![(zero, zero); MAIN_TRIE_LEVELS];
        let len_vec = [1, MIN_BUCKET_SIZE, MIN_BUCKET_SIZE, MIN_BUCKET_SIZE];

        let store = MemStore::new();
        let c = rebuild_subtrie_without_expanded_buckets(260, &store);
        assert_eq!(c, default_commitment(STARTING_NODE_ID[2] as NodeId));
        let c =
            rebuild_subtrie_without_expanded_buckets(260 + STARTING_NODE_ID[2] as NodeId, &store);
        assert_eq!(c, default_commitment((STARTING_NODE_ID[3] - 1) as NodeId));

        // default commitments of main trie like this
        //  C0_0_META_KV
        //  C1_0_META C1_1_KV...
        //  C2_0_META ... C2_255_META C2_256_KV...
        //  C3_0_META ... C3_65535_META C3_65536_KV...

        for i in (0..MAIN_TRIE_LEVELS).rev() {
            let (meta_delta_indices, data_delta_indices) =
                if i == MAIN_TRIE_LEVELS - 1 {
                    let meta_delta_indices = (0..len_vec[i])
                        .map(|i| (i, [0u8; 32], kv_hash(&Some(BucketMeta::default().into()))))
                        .collect::<Vec<_>>();
                    let data_delta_indices = (0..len_vec[i])
                        .map(|i| (i, [0u8; 32], kv_hash(&None)))
                        .collect::<Vec<_>>();
                    (meta_delta_indices, data_delta_indices)
                } else {
                    if i == 0 {
                        let mut hash_bytes = Element::hash_commitments(&vec![
                            default_committment_vec[i + 1].0;
                            len_vec[i]
                        ]);
                        hash_bytes.extend(Element::hash_commitments(&vec![
                            default_committment_vec
                                [i + 1]
                                .1;
                            MIN_BUCKET_SIZE
                                - len_vec[i]
                        ]));
                        let delta_indices = hash_bytes
                            .into_iter()
                            .enumerate()
                            .map(|(i, e)| (i, [0u8; 32], e))
                            .collect::<Vec<_>>();
                        (delta_indices.clone(), delta_indices)
                    } else {
                        let meta_hash_bytes = Element::hash_commitments(&vec![
                            default_committment_vec[i + 1].0;
                            len_vec[i]
                        ]);
                        let meta_delta_indices = meta_hash_bytes
                            .into_iter()
                            .enumerate()
                            .map(|(i, e)| (i, [0u8; 32], e))
                            .collect::<Vec<_>>();
                        let data_hash_bytes = Element::hash_commitments(&vec![
                            default_committment_vec[i + 1].1;
                            len_vec[i]
                        ]);
                        let data_delta_indices = data_hash_bytes
                            .into_iter()
                            .enumerate()
                            .map(|(i, e)| (i, [0u8; 32], e))
                            .collect::<Vec<_>>();
                        (meta_delta_indices, data_delta_indices)
                    }
                };

            default_committment_vec[i].0 = SHARED_COMMITTER
                .add_deltas(zero, &meta_delta_indices)
                .to_bytes_uncompressed();
            default_committment_vec[i].1 = SHARED_COMMITTER
                .add_deltas(zero, &data_delta_indices)
                .to_bytes_uncompressed();

            assert_eq!(
                default_committment_vec[i].0,
                default_commitment(STARTING_NODE_ID[i] as NodeId),
                "The default commitment of the level {i} should be equal to the constant value"
            );

            assert_eq!(
                default_committment_vec[i].1,
                default_commitment((STARTING_NODE_ID[i + 1] - 1) as NodeId),
                "The default commitment of the level {i} should be equal to the constant value"
            )
        }

        // Check the default commitments of subtrie
        let mut default_subtrie_c_vec = vec![zero; MAX_SUBTREE_LEVELS];
        let bucket_id = (65536 as NodeId) << BUCKET_SLOT_BITS as NodeId;
        for i in (0..MAX_SUBTREE_LEVELS).rev() {
            let data_delta_indices = if i == MAX_SUBTREE_LEVELS - 1 {
                let data_delta_indices = (0..MIN_BUCKET_SIZE)
                    .map(|i| (i, [0u8; 32], kv_hash(&None)))
                    .collect::<Vec<_>>();
                data_delta_indices
            } else {
                let data_hash_bytes =
                    Element::hash_commitments(&vec![default_subtrie_c_vec[i + 1]; MIN_BUCKET_SIZE]);
                let data_delta_indices = data_hash_bytes
                    .into_iter()
                    .enumerate()
                    .map(|(i, e)| (i, [0u8; 32], e))
                    .collect::<Vec<_>>();
                data_delta_indices
            };

            default_subtrie_c_vec[i] = SHARED_COMMITTER
                .add_deltas(zero, &data_delta_indices)
                .to_bytes_uncompressed();

            assert_eq!(
                default_subtrie_c_vec[i],
                default_commitment(bucket_id + STARTING_NODE_ID[i] as NodeId),
                "The subtrie default commitment of the level {i} should be equal to the constant value"
            );
        }
    }

    fn get_delta_ranges(c_deltas: &[(NodeId, Element)], task_size: usize) -> Vec<(usize, usize)> {
        // Split the elements into chunks of roughly the same size.
        let mut splits = vec![0];
        let mut next_split = task_size;
        while next_split < c_deltas.len() {
            // Check if the current position is an eligible split point: i.e.,
            // the next element must belong to a different parent node.
            if c_deltas[next_split].0 == c_deltas[next_split - 1].0 {
                next_split += 1;
            } else {
                splits.push(next_split);
                next_split += task_size;
            }
        }
        splits.push(c_deltas.len());
        let ranges: Vec<_> = splits
            .iter()
            .zip(splits.iter().skip(1))
            .map(|(&a, &b)| (a, b))
            .collect();

        ranges
    }

    fn create_commitments(l: usize) -> Vec<CommitmentBytes> {
        let committer = SHARED_COMMITTER.as_ref();
        (0..l)
            .map(|i| {
                committer
                    .gi_mul_delta(&[0u8; 32], &[(i + 1) as u8; 32], 0)
                    .to_bytes_uncompressed()
            })
            .collect()
    }

    fn create_random_account(l: usize) -> HashMap<Vec<u8>, Option<Vec<u8>>> {
        let mut rng = rand::thread_rng();
        (0..l)
            .map(|_i| {
                let k: [u8; 32] = rng.gen();
                let v: [u8; 32] = rng.gen();
                (k.to_vec(), Some(v.to_vec()))
            })
            .collect()
    }

    fn is_commitment_equal(c1: CommitmentBytes, c2: CommitmentBytes) -> bool {
        hash_commitment(c1) == hash_commitment(c2)
    }

    fn bucket_meta(nonce: u32, capacity: SlotId) -> BucketMeta {
        BucketMeta {
            nonce,
            capacity,
            ..Default::default()
        }
    }
}
