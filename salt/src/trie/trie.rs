//! This module implements [`StateRoot`].

use crate::{
    constant::{
        default_commitment, BUCKET_SLOT_BITS, BUCKET_SLOT_ID_MASK, EMPTY_SLOT_HASH,
        MIN_BUCKET_SIZE, MIN_BUCKET_SIZE_BITS, NUM_BUCKETS, NUM_META_BUCKETS, STARTING_NODE_ID,
        SUB_TRIE_LEVELS, TRIE_LEVELS,
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
use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;

/// Don't use parallel processing in computing vector commitments if the total
/// number of updated elements is below this threshold.
const MIN_TASK_SIZE: usize = 64;
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

/// Used to compute or update the root node of a SALT trie.
#[derive(Debug)]
pub struct StateRoot<'a, Store> {
    /// Storage backend providing both trie and state access.
    store: &'a Store,
    /// Cache the incremental updates of the trie nodes.
    pub updates: HashMap<NodeId, (CommitmentBytes, CommitmentBytes)>,
    /// Cache the latest commitments of each updated trie node.
    pub cache: HashMap<NodeId, CommitmentBytes>,
    /// Shared committer instance for cryptographic operations.
    committer: Arc<Committer>,
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
        }
    }

    /// Merge the trie updates into the existing trie.
    pub fn add_deltas(&mut self, trie_updates: &TrieUpdates) {
        for (k, v) in trie_updates {
            self.cache
                .entry(*k)
                .and_modify(|change| *change = v.1)
                .or_insert(v.1);
        }
    }

    /// Updates the trie conservatively. This function defers the computation of
    /// the state root to `finalize` to avoid updating the same node commitments
    /// at the upper levels over and over again when more state updates arrive.
    pub fn update(
        &mut self,
        state_updates: &StateUpdates,
    ) -> Result<(), <Store as TrieReader>::Error> {
        let updates = self.update_leaf_nodes(state_updates)?;
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
    pub fn finalize(&mut self) -> Result<([u8; 32], TrieUpdates), <Store as TrieReader>::Error> {
        // Retrieve trie_updates from the cache
        let trie_updates = std::mem::take(&mut self.updates).into_iter().collect();

        self.update_internal_nodes(trie_updates)
    }

    /// Updates the state root (and all the internal commitments on the trie)
    /// based on the given state updates.
    pub fn update_fin(
        &mut self,
        state_updates: &StateUpdates,
    ) -> Result<([u8; 32], TrieUpdates), <Store as TrieReader>::Error> {
        self.update(state_updates)?;
        self.finalize()
    }

    fn update_internal_nodes(
        &self,
        mut trie_updates: TrieUpdates,
    ) -> Result<([u8; 32], TrieUpdates), <Store as TrieReader>::Error> {
        let mut updates = trie_updates
            .iter()
            .filter_map(|(id, c)| {
                if is_subtree_node(*id) {
                    None
                } else {
                    Some((*id, *c))
                }
            })
            .collect::<Vec<_>>();

        // Update the state trie in descending order of depth.
        (0..TRIE_LEVELS - 1).rev().try_for_each(|level| {
            updates = self.update_internal_nodes_inner(&mut updates, level, get_parent_id)?;
            // Record updates in `trie_updates`.
            trie_updates.extend(updates.iter());
            Ok(())
        })?;

        let root_commitment = if let Some(c) = trie_updates.last() {
            c.1 .1
        } else {
            self.store.commitment(0)?
        };

        Ok((hash_commitment(root_commitment), trie_updates))
    }

    /// Given the commitment updates at the lower level, generate the commitment
    /// updates of the internal trie nodes at the current level.
    fn update_internal_nodes_inner<P>(
        &self,
        child_updates: &mut [(NodeId, (CommitmentBytes, CommitmentBytes))],
        level: usize,
        get_parent_id: P,
    ) -> Result<TrieUpdates, <Store as TrieReader>::Error>
    where
        P: Fn(&NodeId, usize) -> NodeId + Sync + Send,
    {
        let committer = &self.committer;
        let num_tasks = 10 * rayon::current_num_threads();
        let task_size = std::cmp::max(MIN_TASK_SIZE, child_updates.len().div_ceil(num_tasks));

        // Sort the child updates by their positions within the VCs.
        child_updates.par_sort_unstable_by(|(a, _), (b, _)| {
            get_child_idx(a, level + 1).cmp(&get_child_idx(b, level + 1))
        });

        // Compute the commitment deltas to be applied to the parent nodes.
        let c_deltas = child_updates
            .par_chunks(task_size)
            .map(|c_updates| {
                let c_vec: Vec<CommitmentBytes> = c_updates
                    .iter()
                    .flat_map(|(_, (old_c, new_c))| vec![old_c, new_c])
                    .copied()
                    .collect();

                // Hash (interleaving) old and new commitments into scalar bytes
                let scalar_bytes = Element::hash_commitments(&c_vec);

                // Collect the commitment deltas, indexed by parent node IDs.
                c_updates
                    .iter()
                    .zip(scalar_bytes.chunks_exact(2))
                    .map(|((id, _), scalars)| {
                        (
                            get_parent_id(id, level + 1),
                            committer.gi_mul_delta(
                                &scalars[0],
                                &scalars[1],
                                get_child_idx(id, level + 1),
                            ),
                        )
                    })
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>()
            .into_iter()
            .flatten()
            .collect();

        self.apply_deltas(c_deltas, task_size)
    }

    /// Given the state updates, generates the commitment updates of the leaf nodes
    /// (i.e., the SALT buckets).
    fn update_leaf_nodes(
        &self,
        state_updates: &StateUpdates,
    ) -> Result<TrieUpdates, <Store as TrieReader>::Error> {
        // expansion kvs and non-expansion kvs are sorted separately
        let mut expansion_updates: SaltUpdates<'_> = vec![];
        let mut event_levels: Vec<HashMap<BucketId, SubtrieChangeInfo>> =
            vec![HashMap::new(); SUB_TRIE_LEVELS];
        let (mut bucket_id, mut is_expansion, mut old_capacity, mut new_capacity) = (
            u32::MAX,
            false,
            MIN_BUCKET_SIZE as u64,
            MIN_BUCKET_SIZE as u64,
        );
        let mut capacity_changes = HashMap::new();
        let insert_uncomputed_node =
            |mut id: NodeId,
             start: usize,
             end: usize,
             updates: &mut BTreeMap<u64, (CommitmentBytes, CommitmentBytes)>| {
                for level in (start..end).rev() {
                    if updates.contains_key(&id) {
                        break;
                    }
                    updates.insert(
                        id,
                        (
                            self.commitment(id).expect("node should exist in trie"),
                            default_commitment(id),
                        ),
                    );
                    if level != start {
                        id = subtrie_parent_id(&id, level);
                    }
                }
            };
        // When optimizing for contraction, the commitment of the contracted bucket is zero,
        // so it is directly updated to reduce computation.
        // uncomputed_updates is used to record uncomputed nodes
        let mut uncomputed_updates = BTreeMap::new();
        // Record the nodes that need extra processing during the subtrie calculation
        // from 0 to SUB_TRIE_LEVELS-1. The last group records the nodes that have been
        // calculated and directly updates to trie_updates.
        let mut pending_updates = vec![vec![]; SUB_TRIE_LEVELS + 1];
        // Record the information of buckets that have been downsized, used to distinguish
        // between nodes in uncomputed_updates that need to participate in the calculation
        // and those that do not.
        let mut contractions = vec![];

        let mut normal_updates = state_updates
            .data
            .iter()
            .filter(|(k, v)| {
                let bid = k.bucket_id();
                if bid < NUM_META_BUCKETS as BucketId {
                    is_expansion = false;
                    // Record the bucket id and capacity when expansion or contraction occurs.
                    let old_meta: BucketMeta =
                        v.0.clone()
                            .expect("old meta exist in updates")
                            .try_into()
                            .expect("old meta should be valid");
                    let new_meta: BucketMeta =
                        v.1.clone()
                            .expect("new meta exist in updates")
                            .try_into()
                            .expect("new meta should be valid");
                    let id = (bid << MIN_BUCKET_SIZE_BITS) + k.slot_id() as BucketId;
                    capacity_changes.insert(id, (old_meta.capacity, new_meta.capacity));
                } else if bid != bucket_id {
                    // Read the new bucket meta from state_updates, otherwise get the old one.
                    (old_capacity, new_capacity) =
                        capacity_changes.remove(&bid).unwrap_or_else(|| {
                            let bucket_capacity = self
                                .store
                                .metadata(bid)
                                .expect("bucket capacity should exist")
                                .capacity;
                            (bucket_capacity, bucket_capacity)
                        });
                    (bucket_id, is_expansion) = (
                        bid,
                        std::cmp::max(old_capacity, new_capacity) > MIN_BUCKET_SIZE as u64,
                    );
                    if is_expansion {
                        let info = SubtrieChangeInfo::new(bid, old_capacity, new_capacity);
                        // Both downsizing and expanding need to handle new root node events
                        event_levels[info.new_top_level].insert(bid, info.clone());
                        if info.old_capacity > info.new_capacity {
                            contractions.push(info.clone());
                            if k.slot_id() >= info.new_capacity {
                                // During contraction, subtrie not changed and need to record roots
                                // changed
                                pending_updates[SUB_TRIE_LEVELS].push((
                                    info.root_id,
                                    (
                                        self.commitment(info.root_id)
                                            .expect("node should exist in trie"),
                                        self.commitment(info.new_top_id)
                                            .expect("node should exist in trie"),
                                    ),
                                ));
                            }
                        } else {
                            // When expanding, old root node events need to be handled
                            event_levels[info.old_top_level].insert(bid, info.clone());
                            if info.old_top_level > info.new_top_level
                                && k.slot_id() >= info.old_capacity
                            {
                                // During expansion, original subtrie not changed and need to be
                                // updated above level
                                pending_updates[info.old_top_level].push((
                                    info.old_top_id,
                                    (
                                        default_commitment(info.old_top_id),
                                        self.commitment(info.root_id)
                                            .expect("node should exist in trie"),
                                    ),
                                ));
                            }
                        }
                    }
                };
                if is_expansion {
                    // optimize contraction kvs and commitments
                    if k.slot_id() < new_capacity {
                        expansion_updates.push((k, v));
                    } else {
                        // Set the zero commitment of the contracted bucket node
                        insert_uncomputed_node(
                            subtrie_node_id(k),
                            sub_trie_top_level(old_capacity) + 1,
                            SUB_TRIE_LEVELS,
                            &mut uncomputed_updates,
                        );
                    }
                }
                !is_expansion
            })
            .collect::<Vec<_>>();
        // Compute the commitment of the non-expansion kvs.
        let mut trie_updates = self.update_leaf_nodes_inner(&mut normal_updates, |salt_key| {
            salt_key.bucket_id() as NodeId + STARTING_NODE_ID[TRIE_LEVELS - 1] as NodeId
        })?;

        trie_updates.extend(pending_updates[SUB_TRIE_LEVELS].iter());

        // Record (bucket, capacity changes) of unchanged KV but changed capacity to
        // expansion_updates. it is used to compute the commitment of the subtrie.
        for (bid, (old_capacity, new_capacity)) in capacity_changes {
            let info = SubtrieChangeInfo::new(bid, old_capacity, new_capacity);
            // filtor out load and nonce change or level not changed
            match info.old_top_level.cmp(&info.new_top_level) {
                std::cmp::Ordering::Greater => {
                    // If the top level changes, it is an expansion.
                    // The leaves (kv) of the subtrie do not change,
                    // and the upper old level nodes need to be calculated.
                    event_levels[info.new_top_level].insert(bid, info.clone());
                    pending_updates[info.old_top_level].push((
                        info.old_top_id,
                        (
                            default_commitment(info.old_top_id),
                            self.commitment(info.root_id)?,
                        ),
                    ));
                }
                std::cmp::Ordering::Less => {
                    // If the top level changes, it is a contraction.
                    // The leaves (kv) of the subtrie do not change,
                    // and calculate the upper new level nodes and update trie_updates.
                    let mut updates_map = BTreeMap::new();
                    insert_uncomputed_node(
                        info.new_top_id,
                        info.old_top_level,
                        info.new_top_level,
                        &mut updates_map,
                    );
                    trie_updates.push((
                        info.root_id,
                        (
                            self.commitment(info.root_id)?,
                            self.commitment(info.new_top_id)?,
                        ),
                    ));
                    trie_updates.extend(updates_map.into_iter());
                }
                _ => {}
            };
        }

        // Distinguish between nodes in uncomputed_updates that need to participate
        // in the calculation and those that do not during downsizing.
        for info in contractions {
            assert!(info.old_capacity > info.new_capacity);
            // Add the contracted bucket to the uncomputed_updates
            let mut updates_map = BTreeMap::new();
            let bucket_id = (info.root_id - STARTING_NODE_ID[TRIE_LEVELS - 1] as NodeId)
                << BUCKET_SLOT_BITS as NodeId;
            insert_uncomputed_node(
                info.new_top_id,
                info.old_top_level,
                info.new_top_level,
                &mut updates_map,
            );
            let (mut start, mut end) = (
                info.new_capacity >> MIN_BUCKET_SIZE_BITS as NodeId,
                info.old_capacity >> MIN_BUCKET_SIZE_BITS as NodeId,
            );
            for level in (info.new_top_level + 1..SUB_TRIE_LEVELS).rev() {
                // Add the uncomputed nodes to pending_updates for calculate the parent node
                // um = uncomputed map
                // |--caculate nodes---|---caculates in um--|---uncomputed in um--|
                //level start    pending start        pending end            level end
                let pending_end = bucket_id + start - (start & (MIN_BUCKET_SIZE - 1) as NodeId)
                    + MIN_BUCKET_SIZE as NodeId
                    + STARTING_NODE_ID[level] as NodeId;
                let range = bucket_id + start + STARTING_NODE_ID[level] as NodeId..pending_end;
                let updates: Vec<_> = uncomputed_updates
                    .range(range)
                    .map(|(k, u)| (*k, *u))
                    .collect();
                pending_updates[level].extend(updates.iter());

                // Add the uncomputed nodes to the trie_updates
                let level_end = bucket_id + end + STARTING_NODE_ID[level] as u64;
                if pending_end < level_end {
                    let uncomputeds: Vec<_> = uncomputed_updates
                        .range(pending_end..level_end)
                        .map(|(k, u)| (*k, *u))
                        .collect();
                    trie_updates.extend(uncomputeds.iter());
                }
                (start, end) = (
                    start >> MIN_BUCKET_SIZE_BITS as u64,
                    end >> MIN_BUCKET_SIZE_BITS as u64,
                );
            }
            // Add the uncomputed nodes upper new level to the trie_updates
            let range = if info.new_top_level == SUB_TRIE_LEVELS - 1 {
                bucket_id..bucket_id + (1 << (BUCKET_SLOT_BITS - MIN_BUCKET_SIZE_BITS) as NodeId)
            } else {
                bucket_id..bucket_id + STARTING_NODE_ID[info.new_top_level + 1] as NodeId
            };
            let uncomputeds: Vec<_> = uncomputed_updates
                .range(range)
                .map(|(k, u)| (*k, *u))
                .collect();
            updates_map.extend(uncomputeds.into_iter());
            trie_updates.extend(updates_map.into_iter());
        }

        // calculate the commitments of the subtrie by leaves (KVS) changes
        let mut updates = vec![];
        for level in (0..SUB_TRIE_LEVELS).rev() {
            // // If there is no subtrie that needs to be calculated, exit the loop directly.
            if event_levels
                .iter()
                .take(level + 1)
                .map(|x| x.len())
                .sum::<usize>()
                == 0
            {
                break;
            }
            updates = if level == SUB_TRIE_LEVELS - 1 {
                self.update_leaf_nodes_inner(&mut expansion_updates, subtrie_node_id)
                    .expect("update leaf nodes for subtrie failed")
            } else {
                self.update_internal_nodes_inner(&mut updates, level, subtrie_parent_id)
                    .expect("update internal nodes for subtrie failed")
            };
            // If there are subtrie events that need to be processed,
            // handle the corresponding subtrie.
            updates = if event_levels[level].is_empty() {
                updates
            } else {
                let (subtrie_updates, subtrie_roots): (Vec<_>, Vec<_>) = updates
                    .into_par_iter()
                    .map(|(id, (old_c, mut new_c))| {
                        let bid = (id >> BUCKET_SLOT_BITS as NodeId) as BucketId;
                        // Handle events for the bucket with  id = bid
                        if let Some(info) = event_levels[level].get(&bid) {
                            if info.old_top_level == level {
                                // Process the root node of the original subtrie
                                if id == info.old_top_id {
                                    // info.old_top_id not store in subtrie, so need to get from trie and add it,
                                    // then subtract the default commitment
                                    let c = self
                                        .commitment(info.root_id)
                                        .expect("root node should exist in trie");
                                    let new_e = Element::from_bytes_unchecked_uncompressed(c)
                                        + Element::from_bytes_unchecked_uncompressed(new_c);
                                    // subtract the default commitment
                                    let new_e = new_e
                                        - Element::from_bytes_unchecked_uncompressed(
                                            default_commitment(id),
                                        );
                                    new_c = new_e.to_bytes_uncompressed();
                                    // When expanding, if there is no level change,
                                    // the subtree calculation is over.
                                    if info.new_top_level == info.old_top_level {
                                        return (vec![], vec![(info.root_id, (c, new_c))]);
                                    }
                                }
                                (
                                    vec![(id, (default_commitment(info.old_top_id), new_c))],
                                    vec![],
                                )
                            } else if info.new_top_level == level {
                                // Process the root node of the new subtrie
                                assert_eq!(info.new_top_id, id);
                                let c = self
                                    .commitment(info.root_id)
                                    .expect("root node should exist in trie");
                                (vec![], vec![(info.root_id, (c, new_c))])
                            } else {
                                // Undefined event
                                (vec![(id, (old_c, new_c))], vec![])
                            }
                        } else {
                            (vec![(id, (old_c, new_c))], vec![])
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
                subtrie_updates.into_iter().flatten().collect()
            };
            updates.extend(pending_updates[level].iter());
            trie_updates.extend(updates.iter());
        }

        Ok(trie_updates)
    }

    /// Updates the leaf nodes (i.e., the SALT buckets) based on the given state updates.
    fn update_leaf_nodes_inner<N>(
        &self,
        state_updates: &mut SaltUpdates<'_>,
        get_node_id: N,
    ) -> Result<TrieUpdates, <Store as TrieReader>::Error>
    where
        N: Fn(&SaltKey) -> NodeId + Sync + Send,
    {
        let committer = &self.committer;
        let num_tasks = 10 * rayon::current_num_threads();
        let task_size = std::cmp::max(MIN_TASK_SIZE, state_updates.len().div_ceil(num_tasks));

        // Sort the state updates by slot IDs
        state_updates.par_sort_unstable_by(|(a, _), (b, _)| {
            (a.slot_id() & (MIN_BUCKET_SIZE - 1) as SlotId)
                .cmp(&(b.slot_id() & (MIN_BUCKET_SIZE - 1) as SlotId))
        });

        // Compute the commitment deltas to be applied to the parent nodes.
        let c_deltas: Vec<(NodeId, Element)> = state_updates
            .par_iter()
            .with_min_len(task_size)
            .map(|(salt_key, (old_value, new_value))| {
                (
                    get_node_id(salt_key),
                    committer.gi_mul_delta(
                        &kv_hash(old_value),
                        &kv_hash(new_value),
                        (salt_key.slot_id() & (MIN_BUCKET_SIZE - 1) as SlotId) as usize,
                    ),
                )
            })
            .collect();

        self.apply_deltas(c_deltas, task_size)
    }

    /// Updates node commitments by adding up the precomputed deltas.
    fn apply_deltas(
        &self,
        mut c_deltas: Vec<(NodeId, Element)>,
        task_size: usize,
    ) -> Result<TrieUpdates, <Store as TrieReader>::Error> {
        // Sort the updated elements by their parent node IDs.
        c_deltas.par_sort_unstable_by(|a, b| a.0.cmp(&b.0));

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

        // Process chunks in parallel and collect the results.
        Ok(ranges
            .par_iter()
            .map(|(start, end)| {
                let mut last_node = NodeId::MAX;
                let mut new_e_vec = vec![];
                let mut node_vec = vec![];

                // Sum the deltas of nodes with the same id
                for (cur_node, e) in &c_deltas[*start..*end] {
                    if *cur_node == last_node {
                        *new_e_vec.last_mut().expect("last value in new_e_vec exist") += *e;
                    } else {
                        let old_c = self
                            .commitment(*cur_node)
                            .expect("node should exist in trie");
                        new_e_vec.push(Element::from_bytes_unchecked_uncompressed(old_c) + *e);
                        node_vec.push((*cur_node, old_c));
                        last_node = *cur_node;
                    }
                }

                let new_c_vec = Element::batch_to_commitments(&new_e_vec);

                node_vec
                    .iter()
                    .zip(new_c_vec.iter())
                    .map(|((id, old_c), new_c)| (*id, (*old_c, *new_c)))
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>()
            .into_iter()
            .flatten()
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
    /// Computes the state root from scratch given the SALT buckets.
    pub fn rebuild<S: StateReader>(reader: &S) -> Result<([u8; 32], TrieUpdates), S::Error> {
        let trie_reader = &EmptySalt;
        let trie = StateRoot::new(trie_reader);
        let mut trie_updates = Vec::new();

        // Compute bucket commitments.
        const STEP_SIZE: usize = 256;
        (NUM_META_BUCKETS..NUM_BUCKETS)
            .step_by(STEP_SIZE)
            .try_for_each(|start| {
                let end = std::cmp::min(start + STEP_SIZE, NUM_BUCKETS) - 1;
                // Read Bucket Metadata from store
                let meta_start = if start == NUM_META_BUCKETS {
                    0
                } else {
                    (start >> MIN_BUCKET_SIZE_BITS) as BucketId
                };
                let mut state_updates = reader
                    .entries(
                        SaltKey::from((meta_start, 0))
                            ..=SaltKey::from((
                                (end >> MIN_BUCKET_SIZE_BITS) as BucketId,
                                BUCKET_SLOT_ID_MASK,
                            )),
                    )?
                    .into_iter()
                    .map(|(k, v)| (k, (Some(SaltValue::from(BucketMeta::default())), Some(v))))
                    .collect::<BTreeMap<_, _>>();

                // Read buckets key-value pairs from store
                state_updates.extend(
                    reader
                        .entries(
                            SaltKey::from((start as BucketId, 0))
                                ..=SaltKey::from((end as BucketId, BUCKET_SLOT_ID_MASK)),
                        )?
                        .into_iter()
                        .map(|(k, v)| (k, (None, Some(v)))),
                );

                let updates = trie
                    .update_leaf_nodes(&StateUpdates {
                        data: state_updates,
                    })
                    .expect("no error in EmptySalt when update_leaf_nodes");
                trie_updates.extend(updates);
                Ok(())
            })?;

        Ok(trie
            .update_internal_nodes(trie_updates)
            .expect("no error in EmptySalt when update_internal_nodes"))
    }
}

/// Generates a 256-bit secure hash from the bucket entry.
/// Note: as a special case, empty entries are hashed to 0.
#[inline(always)]
fn kv_hash(entry: &Option<SaltValue>) -> [u8; 32] {
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
        let old_top_level = sub_trie_top_level(old_capacity);
        let new_top_level = sub_trie_top_level(new_capacity);
        let old_top_id = ((bucket_id as NodeId) << BUCKET_SLOT_BITS as NodeId)
            + STARTING_NODE_ID[old_top_level] as NodeId;
        let new_top_id = ((bucket_id as NodeId) << BUCKET_SLOT_BITS as NodeId)
            + STARTING_NODE_ID[new_top_level] as NodeId;
        let root_id = (bucket_id as NodeId) + STARTING_NODE_ID[TRIE_LEVELS - 1] as NodeId;
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
        constant::{default_commitment, zero_commitment, STARTING_NODE_ID, TRIE_LEVELS},
        empty_salt::EmptySalt,
    };
    use std::collections::HashMap;
    const KV_BUCKET_OFFSET: NodeId = NUM_META_BUCKETS as NodeId;

    /// Generates a node's commitment from its entire KV store.
    ///       - - - - -
    ///    - - [node] - -
    ///  - - -  /  \ - - - -
    /// - - -  /    \ - - - - -
    ///- - - [kv]...[kv] - - - - -
    fn calculate_subtrie_with_all_kvs<S: StateReader>(
        node_id: NodeId,
        store: &S,
    ) -> CommitmentBytes {
        let level = get_bfs_level(node_id);
        let committer = SHARED_COMMITTER.as_ref();
        let zero = Committer::zero();
        let mut start = node_id - STARTING_NODE_ID[level] as NodeId;
        let mut end = start + 1;
        for _i in level + 1..TRIE_LEVELS {
            start *= MIN_BUCKET_SIZE as NodeId;
            end *= MIN_BUCKET_SIZE as NodeId;
        }

        let meta_delta_indices = (0..MIN_BUCKET_SIZE)
            .map(|i| (i, [0u8; 32], kv_hash(&Some(BucketMeta::default().into()))))
            .collect::<Vec<_>>();
        let data_delta_indices = (0..MIN_BUCKET_SIZE)
            .map(|i| (i, [0u8; 32], kv_hash(&None)))
            .collect::<Vec<_>>();

        let default_bucket_meta = committer
            .add_deltas(zero, &meta_delta_indices)
            .to_bytes_uncompressed();
        let default_bucket_data = committer
            .add_deltas(zero, &data_delta_indices)
            .to_bytes_uncompressed();

        // compute bucket commitments
        let mut commitments = (start..end)
            .into_par_iter()
            .map(|id| {
                let bucket_id = id as BucketId;
                let kvs = store
                    .entries((bucket_id, 0).into()..=(bucket_id, BUCKET_SLOT_ID_MASK).into())
                    .unwrap();
                let delta_indices = kvs
                    .into_iter()
                    .map(|(k, v)| {
                        let old_bytes = if k.is_in_meta_bucket() {
                            kv_hash(&Some(BucketMeta::default().into()))
                        } else {
                            kv_hash(&None)
                        };
                        (
                            k.slot_id() as usize % MIN_BUCKET_SIZE,
                            old_bytes,
                            kv_hash(&Some(v)),
                        )
                    })
                    .collect::<Vec<_>>();
                let default_c = if bucket_id < NUM_META_BUCKETS as BucketId {
                    default_bucket_meta
                } else {
                    default_bucket_data
                };
                let new_c = if delta_indices.is_empty() {
                    default_c
                } else {
                    committer
                        .add_deltas(default_c, &delta_indices)
                        .to_bytes_uncompressed()
                };
                (bucket_id as usize, new_c)
            })
            .collect::<Vec<_>>();

        // compute commitment upon bucket commitment level
        for _i in (level + 1..TRIE_LEVELS).rev() {
            let mut datas: BTreeMap<usize, (Vec<usize>, Vec<CommitmentBytes>)> = BTreeMap::new();
            for (id, c) in commitments {
                let fid = id / MIN_BUCKET_SIZE;
                let ds = datas.entry(fid).or_insert((vec![], vec![]));
                ds.0.push(id % MIN_BUCKET_SIZE);
                ds.1.push(c);
            }
            commitments = datas
                .into_par_iter()
                .map(|(fid, (ids, cs))| {
                    let hash_bytes = Element::hash_commitments(&cs);
                    let delta_indices = hash_bytes
                        .into_iter()
                        .zip(ids)
                        .map(|(e, i)| (i, [0u8; 32], e))
                        .collect::<Vec<_>>();
                    (
                        fid,
                        committer
                            .add_deltas(zero, &delta_indices)
                            .to_bytes_uncompressed(),
                    )
                })
                .collect();
        }

        assert!(commitments.len() > 0);
        commitments[0].1
    }

    #[test]
    fn trie_add_deltas() {
        let trie_reader = &EmptySalt;
        let mut trie = StateRoot::new(trie_reader);
        let empty_reader = &EmptySalt;
        // Total updates of the state
        let mut state_updates = StateUpdates::default();

        let key1 = SaltKey::from((65538, 0));
        let key2 = SaltKey::from((65538, 1));
        let key3 = SaltKey::from((65538, 2));
        let value1 = SaltValue::new(&[1; 32], &[1; 32]);
        let value2 = SaltValue::new(&[2; 32], &[2; 32]);
        let value3 = SaltValue::new(&[3; 32], &[3; 32]);

        let mut state_updates1 = StateUpdates::default();
        state_updates1.add(key1, None, Some(value1.clone()));
        state_updates1.add(key2, None, Some(value2.clone()));
        state_updates1.add(key3, None, Some(value3));
        state_updates.merge(state_updates1.clone());

        // Update the trie with the first set of state updates, and check the root.
        let (_root1, trie_updates1) = trie.update_fin(&state_updates1).unwrap();
        let mut state_updates2 = StateUpdates::default();
        state_updates2.add(key1, Some(value1.clone()), Some(value2.clone()));
        state_updates.merge(state_updates2.clone());
        // after add deltas, trie's state with state_updates1
        trie.add_deltas(&trie_updates1);
        let (root2, trie_updates2) = trie.update_fin(&state_updates2).unwrap();

        let (new_root2, _) = StateRoot::new(empty_reader)
            .update_fin(&state_updates)
            .unwrap();
        assert_eq!(root2, new_root2);

        let mut state_updates3 = StateUpdates::default();
        state_updates3.add(key2, Some(value2), Some(value1));
        state_updates.merge(state_updates3.clone());
        trie.add_deltas(&trie_updates2);
        let (root3, _) = trie.update_fin(&state_updates3).unwrap();
        let (new_root3, _) = StateRoot::new(empty_reader)
            .update_fin(&state_updates)
            .unwrap();
        assert_eq!(root3, new_root3);
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
    fn scan_sub_trie_top_level() {
        assert_eq!(sub_trie_top_level(256), SUB_TRIE_LEVELS - 1);
        assert_eq!(sub_trie_top_level(512), SUB_TRIE_LEVELS - 2);
        assert_eq!(sub_trie_top_level(256 * 256), SUB_TRIE_LEVELS - 2);
        assert_eq!(sub_trie_top_level(256 * 256 * 2), SUB_TRIE_LEVELS - 3);
        assert_eq!(sub_trie_top_level(256 * 256 * 256), SUB_TRIE_LEVELS - 3);
        assert_eq!(sub_trie_top_level(256 * 256 * 256 * 2), SUB_TRIE_LEVELS - 4);
        assert_eq!(
            sub_trie_top_level(256 * 256 * 256 * 256),
            SUB_TRIE_LEVELS - 4
        );
        assert_eq!(
            sub_trie_top_level(256 * 256 * 256 * 256 * 2),
            SUB_TRIE_LEVELS - 5
        );
        // test with max capacity 40bits
        assert_eq!(
            sub_trie_top_level(256 * 256 * 256 * 256 * 256),
            SUB_TRIE_LEVELS - 5
        );
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
    fn compute_from_scratch_small() {
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
        let c = calculate_subtrie_with_all_kvs(node_id, &mock_db);
        mock_db.update_trie(trie_updates);
        assert_eq!(
            hash_commitment(c),
            hash_commitment(mock_db.commitment(node_id).unwrap())
        );

        assert_eq!(root0, root1);
    }

    #[test]
    fn compute_from_scratch_large() {
        let mock_db = MemStore::new();
        let mut trie = StateRoot::new(&mock_db);
        let mut state_updates = StateUpdates::default();

        // bucket nonce changes
        state_updates.data.insert(
            (0, 0).into(),
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
    fn apply_deltas() {
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

        let updates = trie.apply_deltas(c_deltas.clone(), task_size).unwrap();

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
        let bottom_level = TRIE_LEVELS - 1;
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

        let salt_updates = trie.update_leaf_nodes(&state_updates).unwrap();

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
        let bottom_level = TRIE_LEVELS - 1;
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
        let mut unprocess_updates = trie
            .update_internal_nodes_inner(&mut updates, cur_level, get_parent_id)
            .unwrap();

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
        let mut unprocess_updates = trie
            .update_internal_nodes_inner(&mut unprocess_updates, cur_level, get_parent_id)
            .unwrap();

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
        let unprocess_updates = trie
            .update_internal_nodes_inner(&mut unprocess_updates, cur_level, get_parent_id)
            .unwrap();
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
            default_commitment((STARTING_NODE_ID[TRIE_LEVELS - 1] + NUM_META_BUCKETS) as NodeId);

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
                    STARTING_NODE_ID[TRIE_LEVELS - 1] as NodeId + bucket_ids[1] as NodeId,
                    (default_bucket_data, c1)
                ),
                (
                    STARTING_NODE_ID[TRIE_LEVELS - 1] as NodeId + bucket_ids[0] as NodeId,
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
                    STARTING_NODE_ID[TRIE_LEVELS - 2] as NodeId + bucket_ids[1] as NodeId / 256,
                    (default_l3_c, c3)
                ),
                (
                    STARTING_NODE_ID[TRIE_LEVELS - 2] as NodeId + bucket_ids[0] as NodeId / 256,
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
                    STARTING_NODE_ID[TRIE_LEVELS - 3] as NodeId + bucket_ids[1] as NodeId / 65536,
                    (default_l2_c, c5)
                ),
                (
                    STARTING_NODE_ID[TRIE_LEVELS - 3] as NodeId + bucket_ids[0] as NodeId / 65536,
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
        let mut default_committment_vec = vec![(zero, zero); TRIE_LEVELS];
        let len_vec = [1, MIN_BUCKET_SIZE, MIN_BUCKET_SIZE, MIN_BUCKET_SIZE];

        let store = MemStore::new();
        let c = calculate_subtrie_with_all_kvs(260, &store);
        assert_eq!(c, default_commitment(STARTING_NODE_ID[2] as NodeId));
        let c = calculate_subtrie_with_all_kvs(260 + STARTING_NODE_ID[2] as NodeId, &store);
        assert_eq!(c, default_commitment((STARTING_NODE_ID[3] - 1) as NodeId));

        // default commitments of main trie like this
        //  C0_0_META_KV
        //  C1_0_META C1_1_KV...
        //  C2_0_META ... C2_255_META C2_256_KV...
        //  C3_0_META ... C3_65535_META C3_65536_KV...

        for i in (0..TRIE_LEVELS).rev() {
            let (meta_delta_indices, data_delta_indices) =
                if i == TRIE_LEVELS - 1 {
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
        let mut default_subtrie_c_vec = vec![zero; SUB_TRIE_LEVELS];
        let bucket_id = (65536 as NodeId) << BUCKET_SLOT_BITS as NodeId;
        for i in (0..SUB_TRIE_LEVELS).rev() {
            let data_delta_indices = if i == SUB_TRIE_LEVELS - 1 {
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
