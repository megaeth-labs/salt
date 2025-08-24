//! This module implements [`StateRoot`].

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
    collections::{BTreeMap, HashMap},
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
type SaltUpdates<'a> = Vec<(&'a SaltKey, &'a (Option<SaltValue>, Option<SaltValue>))>;
/// List of commitment deltas to be applied to specific nodes.
type DeltaList = Vec<(NodeId, Element)>;

/// Used to compute or update the root node of a SALT trie.
#[derive(Debug)]
pub struct StateRoot<'a, Store> {
    /// Storage backend providing both trie and state access.
    store: &'a Store,
    // FIXME: explain why this is needed (hint: because update() uses an incremental
    // algorithm that only computes the state root after finalize())
    // after finalize() or update_fin(), this field will be cleared out!
    /// Cache the incremental updates of the trie nodes.
    updates: HashMap<NodeId, (CommitmentBytes, CommitmentBytes)>,
    /// Cache the latest commitments of each updated trie node.
    cache: HashMap<NodeId, CommitmentBytes>,
    /// Shared committer instance for cryptographic operations.
    committer: Arc<Committer>,
    /// Minimum task batch size for parallel processing.
    min_par_batch_size: usize,
}

impl<'a, Store> StateRoot<'a, Store>
where
    Store: TrieReader + StateReader<Error = <Store as TrieReader>::Error>,
{
    /// Create a [`StateRoot`] object with the given storage backend.
    pub fn new(store: &'a Store) -> Self {
        Self {
            store,
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

    /// Updates the trie conservatively. This function defers the computation of
    /// the state root to `finalize` to avoid updating the same node commitments
    /// at the upper levels over and over again when more state updates arrive.
    pub fn update(
        &mut self,
        state_updates: &StateUpdates,
    ) -> Result<(), <Store as TrieReader>::Error> {
        // FIXME: we are calling update_bucket_subtrees here, so we are only updating L3 commitments (~16M)?
        let updates = self.update_bucket_subtrees(state_updates)?;
        // Cache the results of incremental calculations.
        for (k, v) in updates {
            self.cache
                .entry(k)
                .and_modify(|change| *change = v.1)
                .or_insert(v.1);
            self.updates
                .entry(k)
                .and_modify(|change| change.1 = v.1)
                .or_insert(v);
        }
        Ok(())
    }

    /// Finalizes and returns the state root after a series of calls to `incremental_update`.
    pub fn finalize(&mut self) -> Result<(ScalarBytes, TrieUpdates), <Store as TrieReader>::Error> {
        // FIXME: avoid converting between different collections?
        // Retrieve trie_updates from the cache
        let trie_updates = std::mem::take(&mut self.updates).into_iter().collect();

        let result = self.update_main_trie(trie_updates);

        // Update cache with the final computed TrieUpdates
        if let Ok((_, ref final_trie_updates)) = result {
            for (k, v) in final_trie_updates {
                self.cache
                    .entry(*k)
                    .and_modify(|change| *change = v.1)
                    .or_insert(v.1);
            }
        }

        result
    }

    /// Updates the state root (and all the internal commitments on the trie)
    /// based on the given state updates.
    pub fn update_fin(
        &mut self,
        state_updates: &StateUpdates,
    ) -> Result<(ScalarBytes, TrieUpdates), <Store as TrieReader>::Error> {
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
    /// * `trie_updates` - Initial updates from leaf/subtree nodes to propagate upward
    ///
    /// # Returns
    /// * `ScalarBytes` - The new root commitment hash
    /// * `TrieUpdates` - Complete list of all node updates from leaves to root
    ///
    /// # Algorithm
    /// 1. Filters out subtree nodes (handled separately from main trie)
    /// 2. Processes each trie level from bottom to top (TRIE_LEVELS-2 down to 0)
    /// 3. For each level, computes parent node updates based on child changes
    /// 4. Accumulates all updates for final return
    /// 5. Extracts the root commitment from the final update
    fn update_main_trie(
        &self,
        mut trie_updates: TrieUpdates,
    ) -> Result<(ScalarBytes, TrieUpdates), <Store as TrieReader>::Error> {
        // FIXME: use splice
        // Filter out subtree nodes - they use different update patterns and are
        // handled separately from the main trie structure
        let mut updates = trie_updates
            .iter()
            .filter_map(|(id, c)| {
                if is_subtree_node(*id) {
                    None // Skip subtree nodes - they don't participate in main trie updates
                } else {
                    Some((*id, *c)) // Include main trie nodes for propagation
                }
            })
            .collect::<Vec<_>>();

        // Update the state trie in descending order of depth (bottom-up).
        // Process from level TRIE_LEVELS-2 (deepest internal nodes) to level 0 (root)
        (0..MAIN_TRIE_LEVELS - 1).rev().try_for_each(|_| {
            // Compute updates for parent nodes at this level based on child changes
            updates = self.update_internal_nodes(&mut updates)?;

            // Record the new parent updates in the complete trie_updates collection
            trie_updates.extend(updates.iter());
            Ok(())
        })?;

        // Extract the root commitment from the last update, or fetch from storage if no updates
        let root_commitment = if let Some(c) = trie_updates.last() {
            c.1 .1 // Get the new commitment from the last update (should be root)
        } else {
            self.store.commitment(0)? // No updates occurred, fetch current root
        };

        Ok((hash_commitment(root_commitment), trie_updates))
    }

    /// Updates bucket subtrees based on state changes, handling both normal updates
    /// and bucket capacity changes (expansions/contractions).
    ///
    /// This method processes state updates to generate commitment updates for all affected
    /// trie nodes. It handles several complex scenarios:
    ///
    /// 1. **Normal buckets**: Simple key-value updates without capacity changes
    /// 2. **Expansion buckets**: Buckets that can change capacity (> MIN_BUCKET_SIZE)
    /// 3. **Contraction optimization**: Efficiently handles bucket size decreases
    /// 4. **Subtree restructuring**: Manages depth changes when bucket capacity changes
    ///
    /// The algorithm uses a complex filter to categorize updates while tracking capacity
    /// changes and subtree events. It then processes updates bottom-up through the trie
    /// levels, handling special cases where subtree roots change due to capacity changes.
    fn update_bucket_subtrees(
        &self,
        state_updates: &StateUpdates,
    ) -> Result<TrieUpdates, <Store as TrieReader>::Error> {
        // === DATA STRUCTURES SETUP ===
        // Separate containers for different types of updates and events

        // expansion kvs and non-expansion kvs are sorted separately
        let mut expansion_updates: SaltUpdates<'_> = vec![];
        // Track subtree events at each level (bucket capacity changes that affect structure)
        let mut event_levels: Vec<HashMap<BucketId, SubtrieChangeInfo>> =
            vec![HashMap::new(); MAX_SUBTREE_LEVELS];

        // State tracking variables used during the complex filter operation
        let (mut bucket_id, mut is_expansion, mut old_capacity, mut new_capacity) = (
            u32::MAX,               // Current bucket being processed
            false,                  // Whether current bucket is "expansion type"
            MIN_BUCKET_SIZE as u64, // Current bucket's old capacity
            MIN_BUCKET_SIZE as u64, // Current bucket's new capacity
        );

        // Maps bucket_id -> (old_capacity, new_capacity) from metadata updates
        let mut capacity_changes = HashMap::new();
        // Helper closure for contraction optimization: marks nodes as having zero commitment
        // This is used when buckets shrink - nodes beyond the new capacity become irrelevant
        let insert_uncomputed_node =
            |mut node_id: NodeId,
             start_level: usize,
             end_level: usize,
             uncomputed_nodes: &mut BTreeMap<u64, (CommitmentBytes, CommitmentBytes)>| {
                for level in (start_level..end_level).rev() {
                    if uncomputed_nodes.contains_key(&node_id) {
                        break;
                    }
                    uncomputed_nodes.insert(
                        node_id,
                        (
                            self.commitment(node_id).expect("node should exist in trie"),
                            default_commitment(node_id), // Zero commitment for removed nodes
                        ),
                    );
                    if level != start_level {
                        node_id = get_parent_node(&node_id);
                    }
                }
            };

        // === CONTRACTION OPTIMIZATION DATA STRUCTURES ===
        // When buckets shrink, many nodes become irrelevant and can be set to zero commitment
        // These structures track which nodes can be optimized away

        // Maps node_id -> (old_commitment, zero_commitment) for nodes being removed
        let mut uncomputed_updates = BTreeMap::new();

        // Nodes that need processing at each subtree level [0..MAX_SUBTREE_LEVELS]
        // The last group (MAX_SUBTREE_LEVELS) goes directly to final trie_updates
        let mut pending_updates = vec![vec![]; MAX_SUBTREE_LEVELS + 1];

        // List of buckets being contracted (capacity decreased)
        // Used to optimize computation by avoiding work on removed nodes
        let mut contractions = vec![];

        // === COMPLEX FILTER OPERATION ===
        // This filter serves multiple purposes:
        // 1. Separates normal updates from expansion updates
        // 2. Extracts capacity changes from metadata buckets
        // 3. Tracks subtree events when bucket capacity changes
        // 4. Applies contraction optimization for removed slots
        //
        // WARNING: This filter has side effects! It modifies several variables above.
        // The filter predicate (!is_expansion) determines which updates go to normal_updates

        let mut normal_updates = state_updates
            .data
            .iter()
            .filter(|(key, update_pair)| {
                let current_bucket_id = key.bucket_id();
                if current_bucket_id < NUM_META_BUCKETS as BucketId {
                    is_expansion = false;
                    // Record the bucket id and capacity when expansion or contraction occurs.
                    let old_meta: BucketMeta =
                        update_pair.0.clone()
                            .expect("old meta exist in updates")
                            .try_into()
                            .expect("old meta should be valid");
                    let new_meta: BucketMeta =
                        update_pair.1.clone()
                            .expect("new meta exist in updates")
                            .try_into()
                            .expect("new meta should be valid");
                    let node_id = (current_bucket_id << MIN_BUCKET_SIZE_BITS) + key.slot_id() as BucketId;
                    capacity_changes.insert(node_id, (old_meta.capacity, new_meta.capacity));
                } else if current_bucket_id != bucket_id {
                    // Read the new bucket meta from state_updates, otherwise get the old one.
                    (old_capacity, new_capacity) =
                        capacity_changes.remove(&current_bucket_id).unwrap_or_else(|| {
                            let bucket_capacity = self
                                .store
                                .metadata(current_bucket_id)
                                .expect("bucket capacity should exist")
                                .capacity;
                            (bucket_capacity, bucket_capacity)
                        });
                    (bucket_id, is_expansion) = (
                        current_bucket_id,
                        std::cmp::max(old_capacity, new_capacity) > MIN_BUCKET_SIZE as u64,
                    );
                    if is_expansion {
                        let subtree_change = SubtrieChangeInfo::new(current_bucket_id, old_capacity, new_capacity);
                        // Both downsizing and expanding need to handle new root node events
                        event_levels[subtree_change.new_top_level].insert(current_bucket_id, subtree_change.clone());

                        if subtree_change.old_capacity > subtree_change.new_capacity {
                            // Handle bucket contraction (capacity decreased)
                            contractions.push(subtree_change.clone());

                            // If this slot is being removed, record the root change
                            if key.slot_id() >= subtree_change.new_capacity {
                                pending_updates[MAX_SUBTREE_LEVELS].push((
                                    subtree_change.root_id,
                                    (
                                        self.commitment(subtree_change.root_id)
                                            .expect("node should exist in trie"),
                                        self.commitment(subtree_change.new_top_id)
                                            .expect("node should exist in trie"),
                                    ),
                                ));
                            }
                        } else {
                            // Handle bucket expansion (capacity increased)
                            event_levels[subtree_change.old_top_level].insert(current_bucket_id, subtree_change.clone());

                            // Check if this is a new slot in the expanded area
                            let is_new_slot_in_expanded_area = subtree_change.old_top_level
                                > subtree_change.new_top_level
                                && key.slot_id() >= subtree_change.old_capacity;

                            if is_new_slot_in_expanded_area {
                                pending_updates[subtree_change.old_top_level].push((
                                    subtree_change.old_top_id,
                                    (
                                        default_commitment(subtree_change.old_top_id),
                                        self.commitment(subtree_change.root_id)
                                            .expect("node should exist in trie"),
                                    ),
                                ));
                            }
                        }
                    }
                };
                if is_expansion {
                    // Handle expansion bucket updates and contraction optimization
                    if key.slot_id() < new_capacity {
                        // Slot is within new capacity - add to expansion updates
                        expansion_updates.push((key, update_pair));
                    } else {
                        // Slot beyond new capacity - mark as zero commitment (contraction optimization)
                        insert_uncomputed_node(
                            subtree_leaf_for_key(key),
                            subtree_root_level(old_capacity) + 1,
                            MAX_SUBTREE_LEVELS,
                            &mut uncomputed_updates,
                        );
                    }
                    false // Expansion buckets don't go to normal_updates
                } else {
                    true // Normal buckets go to normal_updates
                }
            })
            .collect::<Vec<_>>();

        // === PHASE 1: PROCESS NORMAL UPDATES ===
        // Handle buckets that don't change capacity (simple key-value updates)
        let mut trie_updates = self.update_leaf_nodes(&mut normal_updates, false)?;

        trie_updates.extend(pending_updates[MAX_SUBTREE_LEVELS].iter());

        // === PHASE 2: HANDLE CAPACITY-ONLY CHANGES ===
        // Process buckets that changed capacity but have no key-value updates
        // These require subtree restructuring when the depth changes
        for (bid, (old_capacity, new_capacity)) in capacity_changes {
            let subtree_change = SubtrieChangeInfo::new(bid, old_capacity, new_capacity);
            // filtor out load and nonce change or level not changed
            match subtree_change.old_top_level.cmp(&subtree_change.new_top_level) {
                std::cmp::Ordering::Greater => {
                    // If the top level changes, it is an expansion.
                    // The leaves (kv) of the subtrie do not change,
                    // and the upper old level nodes need to be calculated.
                    event_levels[subtree_change.new_top_level].insert(bid, subtree_change.clone());
                    pending_updates[subtree_change.old_top_level].push((
                        subtree_change.old_top_id,
                        (
                            default_commitment(subtree_change.old_top_id),
                            self.commitment(subtree_change.root_id)?,
                        ),
                    ));
                }
                std::cmp::Ordering::Less => {
                    // If the top level changes, it is a contraction.
                    // The leaves (kv) of the subtrie do not change,
                    // and calculate the upper new level nodes and update trie_updates.
                    let mut contraction_updates = BTreeMap::new();
                    insert_uncomputed_node(
                        subtree_change.new_top_id,
                        subtree_change.old_top_level,
                        subtree_change.new_top_level,
                        &mut contraction_updates,
                    );
                    trie_updates.push((
                        subtree_change.root_id,
                        (
                            self.commitment(subtree_change.root_id)?,
                            self.commitment(subtree_change.new_top_id)?,
                        ),
                    ));
                    trie_updates.extend(contraction_updates.into_iter());
                }
                _ => {}
            };
        }

        // === PHASE 3: APPLY CONTRACTION OPTIMIZATIONS ===
        // For buckets that shrank, optimize by distributing zero-commitment nodes
        // across appropriate levels to avoid unnecessary computation
        for subtree_change in contractions {
            assert!(subtree_change.old_capacity > subtree_change.new_capacity);
            // Add the contracted bucket to the uncomputed_updates
            let mut contraction_node_updates = BTreeMap::new();
            let bucket_root_offset = subtree_change.root_id - STARTING_NODE_ID[MAIN_TRIE_LEVELS - 1] as NodeId;
            let bucket_id = bucket_root_offset << BUCKET_SLOT_BITS as NodeId;
            insert_uncomputed_node(
                subtree_change.new_top_id,
                subtree_change.old_top_level,
                subtree_change.new_top_level,
                &mut contraction_node_updates,
            );
            let capacity_start_index = subtree_change.new_capacity >> MIN_BUCKET_SIZE_BITS as NodeId;
            let capacity_end_index = subtree_change.old_capacity >> MIN_BUCKET_SIZE_BITS as NodeId;
            let (mut start, mut end) = (capacity_start_index, capacity_end_index);
            for level in (subtree_change.new_top_level + 1..MAX_SUBTREE_LEVELS).rev() {
                // Add the uncomputed nodes to pending_updates for calculate the parent node
                // um = uncomputed map
                // |--caculate nodes---|---caculates in um--|---uncomputed in um--|
                //level start    pending start        pending end            level end
                let aligned_start = start - (start % MIN_BUCKET_SIZE as NodeId);
                let pending_end = bucket_id + aligned_start
                    + MIN_BUCKET_SIZE as NodeId
                    + STARTING_NODE_ID[level] as NodeId;
                let pending_range = bucket_id + start + STARTING_NODE_ID[level] as NodeId..pending_end;
                let uncomputed_nodes: Vec<_> = uncomputed_updates
                    .range(pending_range)
                    .map(|(node_key, update_value)| (*node_key, *update_value))
                    .collect();
                pending_updates[level].extend(uncomputed_nodes.iter());

                // Add the uncomputed nodes to the trie_updates
                let level_end_node_id = bucket_id + end + STARTING_NODE_ID[level] as u64;
                if pending_end < level_end_node_id {
                    let uncomputed_nodes: Vec<_> = uncomputed_updates
                        .range(pending_end..level_end_node_id)
                        .map(|(node_key, update_value)| (*node_key, *update_value))
                        .collect();
                    trie_updates.extend(uncomputed_nodes.iter());
                }
                (start, end) = (
                    start >> MIN_BUCKET_SIZE_BITS as u64,
                    end >> MIN_BUCKET_SIZE_BITS as u64,
                );
            }
            // Add the uncomputed nodes upper new level to the trie_updates
            let upper_level_range = if subtree_change.new_top_level == MAX_SUBTREE_LEVELS - 1 {
                let max_level_offset = 1 << (BUCKET_SLOT_BITS - MIN_BUCKET_SIZE_BITS) as NodeId;
                bucket_id..bucket_id + max_level_offset
            } else {
                let next_level_offset = STARTING_NODE_ID[subtree_change.new_top_level + 1] as NodeId;
                bucket_id..bucket_id + next_level_offset
            };
            let uncomputed_nodes: Vec<_> = uncomputed_updates
                .range(upper_level_range)
                .map(|(node_key, update_value)| (*node_key, *update_value))
                .collect();
            contraction_node_updates.extend(uncomputed_nodes.into_iter());
            trie_updates.extend(contraction_node_updates.into_iter());
        }

        // === PHASE 4: BOTTOM-UP SUBTREE PROCESSING ===
        // Process expansion buckets level by level from leaves to root
        // Handle subtree events where bucket capacity changes affect tree structure
        let mut current_level_updates = vec![];
        for level in (0..MAX_SUBTREE_LEVELS).rev() {
            // Early exit: if no more subtree events remain at this or lower levels, we're done
            let total_remaining_events: usize = event_levels
                .iter()
                .take(level + 1)
                .map(|events| events.len())
                .sum();
            if total_remaining_events == 0 {
                break;
            }

            // Update nodes at current level
            current_level_updates = if level == MAX_SUBTREE_LEVELS - 1 {
                // Leaf level: process expansion updates
                self.update_leaf_nodes(&mut expansion_updates, true)
                    .expect("update leaf nodes for subtrie failed")
            } else {
                // Internal level: propagate updates from children
                self.update_internal_nodes(&mut current_level_updates)
                    .expect("update internal nodes for subtrie failed")
            };

            // Handle subtree events at this level (if any)
            if !event_levels[level].is_empty() {
                let (subtrie_updates, subtrie_roots): (Vec<_>, Vec<_>) = current_level_updates
                    .into_par_iter()
                    .map(|(node_id, (old_commitment, mut new_commitment))| {
                        let current_bucket_id = (node_id >> BUCKET_SLOT_BITS as NodeId) as BucketId;
                        // Handle events for the bucket with  id = current_bucket_id
                        if let Some(subtree_change) = event_levels[level].get(&current_bucket_id) {
                            if subtree_change.old_top_level == level {
                                // Process the root node of the original subtrie
                                if node_id == subtree_change.old_top_id {
                                    // info.old_top_id not store in subtrie, so need to get from trie and add it,
                                    // then subtract the default commitment
                                    let root_commitment = self
                                        .commitment(subtree_change.root_id)
                                        .expect("root node should exist in trie");
                                    let new_element = Element::from_bytes_unchecked_uncompressed(root_commitment)
                                        + Element::from_bytes_unchecked_uncompressed(new_commitment);
                                    // subtract the default commitment
                                    let new_element = new_element
                                        - Element::from_bytes_unchecked_uncompressed(
                                            default_commitment(node_id),
                                        );
                                    new_commitment = new_element.to_bytes_uncompressed();
                                    // When expanding, if there is no level change,
                                    // the subtree calculation is over.
                                    if subtree_change.new_top_level == subtree_change.old_top_level {
                                        return (vec![], vec![(subtree_change.root_id, (root_commitment, new_commitment))]);
                                    }
                                }
                                (
                                    vec![(node_id, (default_commitment(subtree_change.old_top_id), new_commitment))],
                                    vec![],
                                )
                            } else if subtree_change.new_top_level == level {
                                // Process the root node of the new subtrie
                                assert_eq!(subtree_change.new_top_id, node_id);
                                let root_commitment = self
                                    .commitment(subtree_change.root_id)
                                    .expect("root node should exist in trie");
                                (vec![], vec![(subtree_change.root_id, (root_commitment, new_commitment))])
                            } else {
                                // Undefined event
                                (vec![(node_id, (old_commitment, new_commitment))], vec![])
                            }
                        } else {
                            (vec![(node_id, (old_commitment, new_commitment))], vec![])
                        }
                    })
                    .unzip();
                trie_updates.extend(
                    subtrie_roots
                        .into_iter()
                        .flatten()
                        .collect::<Vec<_>>()
                        .iter(),
                );
                current_level_updates = subtrie_updates.into_iter().flatten().collect();
            }

            // Add any pending updates for this level
            current_level_updates.extend(pending_updates[level].iter());
            trie_updates.extend(current_level_updates.iter());
        }

        Ok(trie_updates)
    }

    /// Updates the leaf nodes (i.e., the SALT buckets) based on the given state updates.
    fn update_leaf_nodes(
        &self,
        state_updates: &mut SaltUpdates<'_>,
        is_subtree: bool,
    ) -> Result<TrieUpdates, <Store as TrieReader>::Error> {
        // Sort the state updates by slot IDs
        state_updates.par_sort_unstable_by(|(a, _), (b, _)| {
            (a.slot_id() as usize % TRIE_WIDTH).cmp(&(b.slot_id() as usize % TRIE_WIDTH))
        });

        // Compute the commitment deltas to be applied to the parent nodes.
        let batch_size = self.par_batch_size(state_updates.len());
        let c_deltas: DeltaList = state_updates
            .par_iter()
            .with_min_len(batch_size)
            .map(|(salt_key, (old_value, new_value))| {
                (
                    if is_subtree {
                        subtree_leaf_for_key(salt_key)
                    } else {
                        bucket_root_node_id(salt_key.bucket_id())
                    },
                    self.committer.gi_mul_delta(
                        &kv_hash(old_value),
                        &kv_hash(new_value),
                        salt_key.slot_id() as usize % TRIE_WIDTH,
                    ),
                )
            })
            .collect();

        self.add_commitment_deltas(c_deltas, batch_size)
    }

    /// Computes commitment updates for parent nodes at a single trie level using delta-based updates.
    ///
    /// This method implements the core delta-based algorithm for updating vector commitments
    /// in the SALT trie. Instead of recomputing entire parent commitments, it efficiently
    /// computes and applies only the changes (deltas) caused by child node updates.
    ///
    /// # Arguments
    /// * `child_updates` - Updates from child nodes: (node_id, (old_commitment, new_commitment))
    /// * `level` - The target level for parent nodes (child nodes are at level + 1)
    /// * `get_parent_id` - Function to compute parent node ID from child node ID and level
    ///
    /// # Returns
    /// * `TrieUpdates` - Updates for parent nodes: (parent_id, (old_commitment, new_commitment))
    ///
    /// # Algorithm
    /// 1. **Parallel Setup**: Determines optimal task size for multi-core processing
    /// 2. **Sorting**: Orders child updates by their index within parent vector commitments
    /// 3. **Delta Computation**: For each chunk in parallel:
    ///    - Hashes old/new commitments to get scalar representations
    ///    - Computes delta = G[child_index] * (new_scalar - old_scalar)
    ///    - Groups deltas by parent node ID
    /// 4. **Accumulation**: Applies all deltas to compute new parent commitments
    ///
    /// # Vector Commitment Mathematics
    /// Each parent's commitment is: C = Σ(G[i] * child_commitment[i])
    /// When child[j] changes: new_C = old_C + G[j] * (new_child[j] - old_child[j])
    /// This delta approach avoids recomputing the entire sum.
    fn update_internal_nodes(
        &self,
        child_updates: &mut [(NodeId, (CommitmentBytes, CommitmentBytes))],
    ) -> Result<TrieUpdates, <Store as TrieReader>::Error> {
        // Sort child updates by their position within parent vector commitments.
        // This ensures cache-friendly access patterns and deterministic ordering
        // for consistent parallel processing results.
        child_updates.par_sort_unstable_by(|(a, _), (b, _)| {
            vc_position_in_parent(a).cmp(&vc_position_in_parent(b))
        });

        // Compute commitment deltas in parallel chunks to be applied to parent nodes.
        // Each chunk processes a subset of child updates independently.
        let batch_size = self.par_batch_size(child_updates.len());
        let c_deltas = child_updates
            .par_chunks(batch_size)
            .map(|c_updates| {
                // Collect all old and new commitments for this chunk, interleaved
                // Format: [old_c1, new_c1, old_c2, new_c2, ...]
                let c_vec: Vec<CommitmentBytes> = c_updates
                    .iter()
                    .flat_map(|(_, (old_c, new_c))| vec![old_c, new_c])
                    .copied()
                    .collect();

                // Hash all commitments to scalar bytes in batch for efficiency
                // Returns: [old_scalar1, new_scalar1, old_scalar2, new_scalar2, ...]
                let scalar_bytes = Element::hash_commitments(&c_vec);

                // For each child update, compute the delta contribution to its parent
                c_updates
                    .iter()
                    .zip(scalar_bytes.chunks_exact(2))
                    .map(|((id, _), scalars)| {
                        (
                            get_parent_node(id), // Which parent node to update
                            // Compute delta: G[child_index] * (new_scalar - old_scalar)
                            // This represents the change needed in parent's vector commitment
                            self.committer.gi_mul_delta(
                                &scalars[0],               // old commitment as scalar
                                &scalars[1],               // new commitment as scalar
                                vc_position_in_parent(id), // position within parent's VC
                            ),
                        )
                    })
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>()
            .into_iter()
            .flatten()
            .collect();

        // Accumulate all deltas per parent node and compute new commitments
        self.add_commitment_deltas(c_deltas, batch_size)
    }

    /// Computes a reasonable task batch size for parallel processing in rayon.
    fn par_batch_size(&self, num_tasks: usize) -> usize {
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
    /// * `c_deltas` - Vector of (NodeId, Element) pairs representing commitment changes.
    ///   Multiple deltas for the same NodeId will be summed together.
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
    ) -> Result<TrieUpdates, <Store as TrieReader>::Error> {
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
    ) -> Result<TrieUpdates, <Store as TrieReader>::Error> {
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
    fn commitment(&self, node_id: NodeId) -> Result<CommitmentBytes, <Store as TrieReader>::Error> {
        if let Some(c) = self.cache.get(&node_id) {
            Ok(*c)
        } else {
            self.store.commitment(node_id)
        }
    }
}

impl StateRoot<'_, EmptySalt> {
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
        let trie = StateRoot::new(&EmptySalt);
        let mut all_trie_updates = Vec::new();

        // Process data buckets in chunks (chunk size must be multiples of 256)
        const CHUNK_SIZE: usize = META_BUCKET_SIZE;
        (NUM_META_BUCKETS..NUM_BUCKETS)
            .step_by(CHUNK_SIZE)
            .try_for_each(|chunk_start| {
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
                // `update_leaf_nodes` detects metadata capacity changes and creates
                // appropriate subtrie structures without special handling
                let chunk_trie_updates = trie
                    .update_bucket_subtrees(&StateUpdates {
                        data: chunk_updates,
                    })
                    .unwrap();

                all_trie_updates.extend(chunk_trie_updates);
                Ok(())
            })?;

        // Step 4: Compute commitments for all internal nodes in the main trie
        Ok(trie.update_main_trie(all_trie_updates).unwrap())
    }
}

/// Generates a 256-bit secure hash from the bucket entry.
/// Note: as a special case, empty entries are hashed to 0.
#[inline(always)]
fn kv_hash(entry: &Option<SaltValue>) -> ScalarBytes {
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
        constant::{default_commitment, zero_commitment, MAIN_TRIE_LEVELS, STARTING_NODE_ID},
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
        trie.update_fin(&updates1).unwrap();

        // Update 2: k1: v1 → v2
        let mut updates2 = StateUpdates::default();
        updates2.add(k1, Some(v1.clone()), Some(v2.clone()));
        cumulative.merge(updates2.clone());

        let (incremental_root2, _) = trie.update_fin(&updates2).unwrap();
        let (batch_root2, _) = StateRoot::new(&EmptySalt).update_fin(&cumulative).unwrap();
        assert_eq!(incremental_root2, batch_root2);

        // Update 3: k2: v2 → v1
        let mut updates3 = StateUpdates::default();
        updates3.add(k2, Some(v2), Some(v1));
        cumulative.merge(updates3.clone());

        let (incremental_root3, _) = trie.update_fin(&updates3).unwrap();
        let (batch_root3, _) = StateRoot::new(&EmptySalt).update_fin(&cumulative).unwrap();
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
        let (root, trie_updates) = trie.update_fin(&state_updates).unwrap();
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
        let (root1, trie_updates) = trie.update_fin(&state_updates).unwrap();
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
        let (root1, _) = trie.update_fin(&state_updates).unwrap();
        assert_eq!(root1, root);
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
            trie.update_fin(&initialize_state_updates).unwrap();
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
        let (expansion_root, trie_updates) = trie.update_fin(&expand_state_updates).unwrap();
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
        let (expansion_root, trie_updates) = trie.update_fin(&expand_state_updates).unwrap();
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
        let (contraction_root, trie_updates) = trie.update_fin(&contract_state_updates).unwrap();
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
        let (contraction_root, _) = trie.update_fin(&contract_state_updates).unwrap();

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

        let (root, trie_updates) = trie.update_fin(&state_updates).unwrap();
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

        let (extended_root, trie_updates) = trie.update_fin(&state_updates).unwrap();
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
        let (contraction_root, trie_updates) = trie.update_fin(&state_updates).unwrap();
        store.update_state(state_updates);
        store.update_trie(trie_updates);
        let (root3, _) = StateRoot::rebuild(&store).unwrap();
        assert_eq!(root3, contraction_root);
    }

    #[test]
    fn incremental_update_small() {
        let mut state_updates = StateUpdates::default();
        let store = MemStore::new();
        // set expansion bucket metadata and check update with expanded bucket
        let update_bid = KV_BUCKET_OFFSET as BucketId + 2;
        let extend_bid = KV_BUCKET_OFFSET as BucketId + 3;
        let meta = bucket_meta(0, 65536 * 2);
        let salt_key = bucket_metadata_key(update_bid);
        let updates = StateUpdates {
            data: [(salt_key, (None, Some(SaltValue::from(meta))))].into(),
        };
        store.update_state(updates);

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
                    (
                        extend_bid >> MIN_BUCKET_SIZE_BITS,
                        extend_bid as SlotId % MIN_BUCKET_SIZE as SlotId,
                    )
                        .into(),
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
        let mut trie = StateRoot::new(trie_reader);
        trie.update(&state_updates1).unwrap();
        state_updates.merge(state_updates1);
        trie.update(&state_updates2).unwrap();
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
                    (
                        extend_bid >> MIN_BUCKET_SIZE_BITS,
                        extend_bid as SlotId % MIN_BUCKET_SIZE as SlotId,
                    )
                        .into(),
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
        let (cmp_root, mut cmp_trie_updates) = trie.update_fin(&cmp_state_updates).unwrap();
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
        let (root, mut total_trie_updates) = trie.update_fin(&total_state_updates).unwrap();

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
            trie.update(&state_updates).unwrap();
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

        let (root0, _) = trie.update_fin(&state_updates).unwrap();
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

        let (root0, _) = trie.update_fin(&state_updates).unwrap();
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

        let salt_updates = trie.update_bucket_subtrees(&state_updates).unwrap();

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

        let mut updates = vec![
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
        let mut unprocess_updates = trie.update_internal_nodes(&mut updates).unwrap();

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
        let mut unprocess_updates = trie.update_internal_nodes(&mut unprocess_updates).unwrap();

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
        let unprocess_updates = trie.update_internal_nodes(&mut unprocess_updates).unwrap();
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

        let (_, mut trie_updates) = trie.update_fin(&state_updates).unwrap();
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
        let zero = zero_commitment();
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
