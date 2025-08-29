//! This module implements [`StateRoot`].

use super::updates::TrieUpdates;
use crate::{
    constant::{
        get_node_level, is_extension_node, zero_commitment, BUCKET_SLOT_BITS, MIN_BUCKET_SIZE,
        MIN_BUCKET_SIZE_BITS, NUM_BUCKETS, NUM_META_BUCKETS, STARTING_NODE_ID, SUB_TRIE_LEVELS,
        TRIE_LEVELS, TRIE_WIDTH_BITS,
    },
    genesis::EmptySalt,
    state::updates::StateUpdates,
    traits::{BucketMetadataReader, StateReader, TrieReader},
    types::*,
};
use alloy_primitives::B256;
use banderwagon::{salt_committer::Committer, Element};
use ipa_multipoint::crs::CRS;
use once_cell::sync::OnceCell;
//use rayon::prelude::*;
use std::collections::{BTreeMap, HashMap};

/// Don't use parallel processing in computing vector commitments if the total
/// number of updated elements is below this threshold.
const MIN_TASK_SIZE: usize = 64;
/// The size of the precomputed window.
const PRECOMP_WINDOW_SIZE: usize = 11;

/// Used to compute or update the root node of a SALT trie.
#[derive(Debug, Default)]
pub struct StateRoot {
    /// Cache the initial and latest commitments of each updated trie node.
    pub cache: HashMap<NodeId, (CommitmentBytes, CommitmentBytes)>,
}

impl StateRoot {
    /// Create a [`StateRoot`] object.
    pub fn new() -> Self {
        Self { cache: HashMap::new() }
    }

    /// Updates the trie conservatively. This function defers the computation of
    /// the state root to `finalize` to avoid updating the same node commitments
    /// at the upper levels over and over again when more state updates arrive.
    pub fn incremental_update<T: TrieReader>(
        &mut self,
        trie: &T,
        state_updates: &StateUpdates,
    ) -> Result<(), <T as TrieReader>::Error> {
        let updates = self.update_leaf_nodes(trie, state_updates)?;
        // Cache the results of incremental calculations.
        for (k, v) in updates {
            self.cache.entry(k).and_modify(|change| change.1 = v.1).or_insert(v);
        }
        Ok(())
    }

    /// Finalizes and returns the state root after a series of calls to `incremental_update`.
    pub fn finalize<T: TrieReader>(
        &mut self,
        trie: &T,
    ) -> Result<(B256, TrieUpdates), <T as TrieReader>::Error> {
        // Retrieve trie_updates from the cache
        let trie_updates =
            TrieUpdates { data: std::mem::take(&mut self.cache).into_iter().collect() };

        self.update_internal_nodes(trie, trie_updates)
    }

    /// Updates the state root (and all the internal commitments on the trie)
    /// based on the given state updates.
    pub fn update<T: TrieReader>(
        &mut self,
        trie: &T,
        state_updates: &StateUpdates,
    ) -> Result<(B256, TrieUpdates), <T as TrieReader>::Error> {
        self.incremental_update(trie, state_updates)?;
        self.finalize(trie)
    }

    fn update_internal_nodes<T: TrieReader>(
        &self,
        trie: &T,
        mut trie_updates: TrieUpdates,
    ) -> Result<(B256, TrieUpdates), <T as TrieReader>::Error> {
        let mut updates = trie_updates
            .data
            .iter()
            .filter_map(
                |(id, c)| {
                    if is_extension_node(*id) {
                        None
                    } else {
                        Some((*id, c.clone()))
                    }
                },
            )
            .collect::<Vec<_>>();

        // Update the state trie in descending order of depth.
        (0..TRIE_LEVELS - 1).rev().try_for_each(|level| {
            updates = self.update_internal_nodes_inner(trie, &mut updates, level, get_parent_id)?;
            // Record updates in `trie_updates`.
            trie_updates.data.extend(updates.iter());
            Ok(())
        })?;

        let root_commitment =
            if let Some(c) = trie_updates.data.last() { c.1 .1 } else { trie.get(0)? };

        Ok((hash_commitment(root_commitment), trie_updates))
    }

    /// Given the commitment updates at the lower level, generate the commitment
    /// updates of the internal trie nodes at the current level.
    fn update_internal_nodes_inner<P, T>(
        &self,
        trie: &T,
        child_updates: &mut [(NodeId, (CommitmentBytes, CommitmentBytes))],
        level: usize,
        get_parent_id: P,
    ) -> Result<Vec<(NodeId, (CommitmentBytes, CommitmentBytes))>, <T as TrieReader>::Error>
    where
        P: Fn(&NodeId, usize) -> NodeId + Sync + Send,
        T: TrieReader,
    {
        let committer = get_global_committer();
        let num_tasks = 32;
        let task_size =
            std::cmp::max(MIN_TASK_SIZE, (child_updates.len() + num_tasks - 1) / num_tasks);

        // Sort the child updates by their positions within the VCs.
        child_updates.sort_by(|(a, _), (b, _)| {
            get_child_idx(a, level + 1).cmp(&get_child_idx(b, level + 1))
        });

        // Compute the commitment deltas to be applied to the parent nodes.
        let c_deltas = child_updates
            .chunks(task_size)
            .map(|c_updates| {
                let c_vec: Vec<CommitmentBytes> = c_updates
                    .iter()
                    .flat_map(|(_, (old_c, new_c))| vec![old_c, new_c])
                    .cloned()
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

        self.apply_deltas(trie, c_deltas, task_size)
    }

    /// Given the state updates, generates the commitment updates of the leaf nodes
    /// (i.e., the SALT buckets).
    fn update_leaf_nodes<T: TrieReader>(
        &self,
        trie: &T,
        state_updates: &StateUpdates,
    ) -> Result<Vec<(NodeId, (CommitmentBytes, CommitmentBytes))>, <T as TrieReader>::Error> {
        // expansion kvs and non-expansion kvs are sorted separately
        let mut expansion_updates: Vec<(&SaltKey, &(Option<SaltValue>, Option<SaltValue>))> =
            vec![];
        let mut event_levels: Vec<HashMap<BucketId, SubtrieChangeInfo>> =
            vec![HashMap::new(); SUB_TRIE_LEVELS];
        let (mut bucket_id, mut is_expansion, mut old_capacity, mut new_capacity) =
            (u32::MAX, false, MIN_BUCKET_SIZE as u64, MIN_BUCKET_SIZE as u64);
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
                    updates.insert(id, (self.get_node(trie, id), zero_commitment()));
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
                        v.0.as_ref().unwrap_or(&BucketMeta::default().into()).into();
                    let new_meta: BucketMeta =
                        v.1.as_ref().unwrap_or(&BucketMeta::default().into()).into();
                    let id = (bid << MIN_BUCKET_SIZE_BITS) + k.slot_id() as BucketId;
                    capacity_changes.insert(id, (old_meta.capacity, new_meta.capacity));
                } else if bid != bucket_id {
                    // Read the new bucket meta from state_updates, otherwise get the old one.
                    (old_capacity, new_capacity) =
                        capacity_changes.remove(&bid).unwrap_or_else(|| {
                            let bucket_capacity =
                                trie.bucket_capacity(bid).expect("bucket capacity should exist");
                            (bucket_capacity, bucket_capacity)
                        });
                    (bucket_id, is_expansion) =
                        (bid, std::cmp::max(old_capacity, new_capacity) > MIN_BUCKET_SIZE as u64);
                    if is_expansion {
                        let info = SubtrieChangeInfo::new(bid, old_capacity, new_capacity);
                        // Both downsizing and expanding need to handle new root node events
                        event_levels[info.new_level].insert(bid, info.clone());
                        if info.old_capacity > info.new_capacity {
                            contractions.push(info.clone());
                            if k.slot_id() >= info.new_capacity {
                                // During contraction, subtrie not changed and need to record roots
                                // changed
                                pending_updates[SUB_TRIE_LEVELS].push((
                                    info.root_id,
                                    (
                                        self.get_node(trie, info.root_id),
                                        self.get_node(trie, info.new_top_id),
                                    ),
                                ));
                            }
                        } else {
                            // When expanding, old root node events need to be handled
                            event_levels[info.old_level].insert(bid, info.clone());
                            if info.old_level > info.new_level && k.slot_id() >= info.old_capacity {
                                // During expansion, original subtrie not changed and need to be
                                // updated above level
                                pending_updates[info.old_level].push((
                                    info.old_top_id,
                                    (zero_commitment(), self.get_node(trie, info.root_id)),
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
        let mut trie_updates =
            self.update_leaf_nodes_inner(trie, &mut normal_updates, |salt_key| {
                salt_key.bucket_id() as NodeId + STARTING_NODE_ID[TRIE_LEVELS - 1] as NodeId
            })?;

        trie_updates.extend(pending_updates[SUB_TRIE_LEVELS].iter());

        // Record (bucket, capacity changes) of unchanged KV but changed capacity to
        // expansion_updates. it is used to compute the commitment of the subtrie.
        for (bid, (old_capacity, new_capacity)) in capacity_changes.into_iter() {
            let info = SubtrieChangeInfo::new(bid, old_capacity, new_capacity);
            // filtor out load and nonce change or level not changed
            if info.old_level > info.new_level {
                // When expanding, the leaves (kv) of the subtrie do not change,
                // and the upper old level nodes need to be calculated.
                event_levels[info.new_level].insert(bid, info.clone());
                pending_updates[info.old_level].push((
                    info.old_top_id,
                    (zero_commitment(), self.get_node(trie, info.root_id)),
                ));
            } else if info.old_level < info.new_level {
                // When contracting, the leaves (kv) of the subtrie do not change,
                // and calculate the upper new level nodes and update trie_updates.
                let mut updates_map = BTreeMap::new();
                insert_uncomputed_node(
                    info.new_top_id,
                    info.old_level,
                    info.new_level,
                    &mut updates_map,
                );
                trie_updates.push((
                    info.root_id,
                    (self.get_node(trie, info.root_id), self.get_node(trie, info.new_top_id)),
                ));
                trie_updates.extend(updates_map.into_iter());
            }
        }

        // Distinguish between nodes in uncomputed_updates that need to participate
        // in the calculation and those that do not during downsizing.
        for info in contractions.into_iter() {
            assert!(info.old_capacity > info.new_capacity);
            // Add the contracted bucket to the uncomputed_updates
            let mut updates_map = BTreeMap::new();
            let bucket_id = (info.root_id - STARTING_NODE_ID[TRIE_LEVELS - 1] as NodeId) <<
                BUCKET_SLOT_BITS as NodeId;
            insert_uncomputed_node(
                info.new_top_id,
                info.old_level,
                info.new_level,
                &mut updates_map,
            );
            let (mut start, mut end) = (
                info.new_capacity >> MIN_BUCKET_SIZE_BITS as NodeId,
                info.old_capacity >> MIN_BUCKET_SIZE_BITS as NodeId,
            );
            for level in (info.new_level + 1..SUB_TRIE_LEVELS).rev() {
                // Add the uncomputed nodes to pending_updates for calculate the parent node
                // um = uncomputed map
                // |--caculate nodes---|---caculates in um--|---uncomputed in um--|
                //level start    pending start        pending end            level end
                let pending_end = bucket_id + start - (start & (MIN_BUCKET_SIZE - 1) as NodeId) +
                    MIN_BUCKET_SIZE as NodeId +
                    STARTING_NODE_ID[level] as NodeId;
                let range = bucket_id + start + STARTING_NODE_ID[level] as NodeId..pending_end;
                let updates: Vec<_> =
                    uncomputed_updates.range(range).map(|(k, u)| (*k, *u)).collect();
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
                (start, end) =
                    (start >> MIN_BUCKET_SIZE_BITS as u64, end >> MIN_BUCKET_SIZE_BITS as u64);
            }
            // Add the uncomputed nodes upper new level to the trie_updates
            let range = if info.new_level == SUB_TRIE_LEVELS - 1 {
                bucket_id..bucket_id + (1 << (BUCKET_SLOT_BITS - MIN_BUCKET_SIZE_BITS) as NodeId)
            } else {
                bucket_id..bucket_id + STARTING_NODE_ID[info.new_level + 1] as NodeId
            };
            let uncomputeds: Vec<_> =
                uncomputed_updates.range(range).map(|(k, u)| (*k, *u)).collect();
            updates_map.extend(uncomputeds.into_iter());
            trie_updates.extend(updates_map.into_iter());
        }

        // calculate the commitments of the subtrie by leaves (KVS) changes
        let mut updates = vec![];
        for level in (0..SUB_TRIE_LEVELS).rev() {
            // // If there is no subtrie that needs to be calculated, exit the loop directly.
            if event_levels.iter().take(level + 1).map(|x| x.len()).sum::<usize>() == 0 {
                break;
            }
            updates = if level == SUB_TRIE_LEVELS - 1 {
                self.update_leaf_nodes_inner(trie, &mut expansion_updates, subtrie_node_id)
                    .expect("update leaf nodes for subtrie failed")
            } else {
                self.update_internal_nodes_inner(trie, &mut updates, level, subtrie_parent_id)
                    .expect("update internal nodes for subtrie failed")
            };
            // If there are subtrie events that need to be processed,
            // handle the corresponding subtrie.
            updates = if !event_levels[level].is_empty() {
                let (subtrie_updates, subtrie_roots): (Vec<_>, Vec<_>) = updates
                    .into_iter()
                    .map(|(id, (old_c, mut new_c))| {
                        let bid = (id >> BUCKET_SLOT_BITS as NodeId) as BucketId;
                        // Handle events for the bucket with  id = bid
                        if let Some(info) = event_levels[level].get(&bid) {
                            if info.old_level == level {
                                // Process the root node of the original subtrie
                                if id == info.old_top_id {
                                    let c = self.get_node(trie, info.root_id);
                                    let new_e = Element::from_bytes_unchecked_uncompressed(c) +
                                        Element::from_bytes_unchecked_uncompressed(new_c);
                                    new_c = new_e.to_bytes_uncompressed();
                                    // When expanding, if there is no level change,
                                    // the subtree calculation is over.
                                    if info.new_level == info.old_level {
                                        return (vec![], vec![(info.root_id, (c, new_c))]);
                                    }
                                }
                                (vec![(id, (zero_commitment(), new_c))], vec![])
                            } else if info.new_level == level {
                                // Process the root node of the new subtrie
                                assert_eq!(info.new_top_id, id);
                                let c = self.get_node(trie, info.root_id);
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
                trie_updates.extend(subtrie_roots.into_iter().flatten().collect::<Vec<_>>().iter());
                subtrie_updates.into_iter().flatten().collect()
            } else {
                updates
            };
            updates.extend(pending_updates[level].iter());
            trie_updates.extend(updates.iter());
        }

        Ok(trie_updates)
    }

    /// Updates the leaf nodes (i.e., the SALT buckets) based on the given state updates.
    fn update_leaf_nodes_inner<N, T>(
        &self,
        trie: &T,
        state_updates: &mut [(&SaltKey, &(Option<SaltValue>, Option<SaltValue>))],
        get_node_id: N,
    ) -> Result<Vec<(NodeId, (CommitmentBytes, CommitmentBytes))>, <T as TrieReader>::Error>
    where
        N: Fn(&SaltKey) -> NodeId + Sync + Send,
        T: TrieReader,
    {
        let committer = get_global_committer();
        let num_tasks = 32;
        let task_size =
            std::cmp::max(MIN_TASK_SIZE, (state_updates.len() + num_tasks - 1) / num_tasks);

        // Sort the state updates by slot IDs
        state_updates.sort_by(|(a, _), (b, _)| {
            (a.slot_id() & (MIN_BUCKET_SIZE - 1) as SlotId)
                .cmp(&(b.slot_id() & (MIN_BUCKET_SIZE - 1) as SlotId))
        });

        // Compute the commitment deltas to be applied to the parent nodes.
        let c_deltas: Vec<(NodeId, Element)> = state_updates
            .iter()
            .map(|(salt_key, (old_value, new_value))| {
                (
                    get_node_id(salt_key),
                    committer.gi_mul_delta(
                        &kv_hash(&old_value),
                        &kv_hash(&new_value),
                        (salt_key.slot_id() & (MIN_BUCKET_SIZE - 1) as SlotId) as usize,
                    ),
                )
            })
            .collect();

        self.apply_deltas(trie, c_deltas, task_size)
    }

    /// Updates node commitments by adding up the precomputed deltas.
    fn apply_deltas<T: TrieReader>(
        &self,
        trie: &T,
        mut c_deltas: Vec<(NodeId, Element)>,
        task_size: usize,
    ) -> Result<Vec<(NodeId, (CommitmentBytes, CommitmentBytes))>, <T as TrieReader>::Error> {
        // Sort the updated elements by their parent node IDs.
        c_deltas.sort_by(|a, b| a.0.cmp(&b.0));

        // Split the elements into chunks of roughly the same size.
        let mut splits = vec![0];
        let mut next_split = task_size;
        while next_split < c_deltas.len() {
            // Check if the current position is an eligible split point: i.e.,
            // the next element must belong to a different parent node.
            if c_deltas[next_split].0 != c_deltas[next_split - 1].0 {
                splits.push(next_split);
                next_split += task_size;
            } else {
                next_split += 1;
            }
        }
        splits.push(c_deltas.len());
        let ranges: Vec<_> =
            splits.iter().zip(splits.iter().skip(1)).map(|(&a, &b)| (a, b)).collect();

        // Process chunks in parallel and collect the results.
        Ok(ranges
            .iter()
            .map(|(start, end)| {
                let mut last_node = NodeId::MAX;
                let mut new_e_vec = vec![];
                let mut node_vec = vec![];

                // Sum the deltas of nodes with the same id
                c_deltas[*start..*end].iter().for_each(|(cur_node, e)| {
                    if *cur_node != last_node {
                        let old_c = self.get_node(trie, *cur_node);
                        new_e_vec.push(Element::from_bytes_unchecked_uncompressed(old_c) + *e);
                        node_vec.push((*cur_node, old_c));
                        last_node = *cur_node;
                    } else {
                        *new_e_vec.last_mut().expect("last value in new_e_vec exist") += *e;
                    }
                });

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
    fn get_node<T: TrieReader>(&self, trie: &T, node_id: NodeId) -> CommitmentBytes {
        if let Some(c) = self.cache.get(&node_id) {
            c.1
        } else {
            trie.get(node_id).expect("node_id should be in the trie")
        }
    }
}

/// Computes the state root from scratch given the SALT buckets.
pub fn compute_from_scratch<S: StateReader>(
    reader: &S,
) -> Result<(B256, TrieUpdates), <S as BucketMetadataReader>::Error> {
    let trie_reader = &EmptySalt;
    let trie = StateRoot::new();
    let mut trie_updates = TrieUpdates::default();

    // Compute bucket commitments.
    const STEP_SIZE: usize = 256;
    assert!(STEP_SIZE % MIN_BUCKET_SIZE == 0);
    (NUM_META_BUCKETS..NUM_BUCKETS).step_by(STEP_SIZE).try_for_each(|start| {
        let end = std::cmp::min(start + STEP_SIZE, NUM_BUCKETS) - 1;
        // Read Bucket Metadata from store
        let meta_start =
            if start == NUM_META_BUCKETS { 0 } else { (start >> MIN_BUCKET_SIZE_BITS) as BucketId };
        let mut state_updates = reader
            .range_bucket(meta_start..=(end >> MIN_BUCKET_SIZE_BITS) as BucketId)?
            .into_iter()
            .map(|(k, v)| (k, (Some(SaltValue::from(BucketMeta::default())), Some(v))))
            .collect::<BTreeMap<_, _>>();

        // Read buckets key-value pairs from store
        state_updates.extend(
            reader
                .range_bucket(start as BucketId..=end as BucketId)?
                .into_iter()
                .map(|(k, v)| (k, (None, Some(v)))),
        );

        let updates = trie
            .update_leaf_nodes(trie_reader, &StateUpdates { data: state_updates })
            .expect("no error in EmptySalt when update_leaf_nodes");
        trie_updates.data.extend(updates);
        Ok(())
    })?;

    Ok(trie
        .update_internal_nodes(trie_reader, trie_updates)
        .expect("no error in EmptySalt when update_internal_nodes"))
}

/// Given the ID and level of a node, return the index of this node among its siblings.
pub(crate) fn get_child_idx(node_id: &NodeId, level: usize) -> usize {
    (*node_id as usize - STARTING_NODE_ID[level]) & (MIN_BUCKET_SIZE - 1)
}

/// Given the ID of a parent node and the index of a child node,
/// return the ID of the child node.
pub fn get_child_node(parent_id: &NodeId, child_idx: usize) -> NodeId {
    let node_id = *parent_id & ((1 << BUCKET_SLOT_BITS) - 1);
    let bucket_id = *parent_id - node_id;
    let level = get_node_level(node_id);
    assert!(level < SUB_TRIE_LEVELS);

    bucket_id +
        ((node_id - STARTING_NODE_ID[level] as NodeId) << TRIE_WIDTH_BITS) +
        STARTING_NODE_ID[level + 1] as NodeId +
        child_idx as NodeId
}

/// Retrieves or creates a global `TrieCommitter` to reduce the overhead of repeatedly
/// creating precomputed instances.
pub fn get_global_committer() -> &'static Committer {
    static INSTANCE_COMMITTER: OnceCell<Committer> = OnceCell::new();
    INSTANCE_COMMITTER.get_or_init(|| Committer::new(&CRS::default().G, PRECOMP_WINDOW_SIZE))
}

/// Given the ID and level of a node, return the ID of its parent node
/// in the canonical trie.
pub(crate) fn get_parent_id(node_id: &NodeId, level: usize) -> NodeId {
    (((*node_id as usize - STARTING_NODE_ID[level]) >> MIN_BUCKET_SIZE_BITS) +
        STARTING_NODE_ID[level - 1]) as NodeId
}

/// Given the ID and level of a node, return the ID of its parent node
/// in the subtrie.
/// `level` is the level of the max subtrie, from 1..=4
pub(crate) fn subtrie_parent_id(id: &NodeId, level: usize) -> NodeId {
    let node_id = *id & ((1 << BUCKET_SLOT_BITS) - 1);
    let bucket_id = *id - node_id;
    bucket_id +
        STARTING_NODE_ID[level - 1] as NodeId +
        ((node_id - STARTING_NODE_ID[level] as NodeId) >> MIN_BUCKET_SIZE_BITS)
}

/// Given the SaltKey, return the ID of node in the subtrie.
pub(crate) fn subtrie_node_id(key: &SaltKey) -> NodeId {
    ((key.bucket_id() as NodeId) << BUCKET_SLOT_BITS) +
        (key.slot_id() >> MIN_BUCKET_SIZE_BITS) as NodeId +
        STARTING_NODE_ID[SUB_TRIE_LEVELS - 1] as NodeId
}

/// assume the node_id is subtrie_node_id()'s result;
pub(crate) fn subtrie_salt_key_start(id: &NodeId) -> SaltKey {
    let node_id = *id & ((1 << BUCKET_SLOT_BITS) - 1);
    let bucket_id = *id - node_id;
    let slot_id = (node_id - STARTING_NODE_ID[SUB_TRIE_LEVELS - 1] as u64) << MIN_BUCKET_SIZE_BITS;

    SaltKey(bucket_id + slot_id)
}

/// Return the hashed commitment in B256 format
pub fn hash_commitment(c: CommitmentBytes) -> B256 {
    B256::from_slice(&ffi_interface::hash_commitment(c))
}

/// Generates a 256-bit secure hash from the bucket entry.
/// Note: as a special case, empty entries are hashed to 0.
#[inline(always)]
pub(crate) fn kv_hash(entry: &Option<SaltValue>) -> B256 {
    entry.as_ref().map_or(B256::default(), |salt_value| {
        let mut data = blake3::Hasher::new();
        data.update(salt_value.key());
        data.update(salt_value.value());
        B256::from_slice(data.finalize().as_bytes())
    })
}

/// Return the top level(0..4) of the sub trie, by given the capacity.
pub(crate) fn sub_trie_top_level(mut capacity: u64) -> usize {
    let mut level = SUB_TRIE_LEVELS - 1;
    while capacity > MIN_BUCKET_SIZE as u64 {
        level -= 1;
        capacity >>= MIN_BUCKET_SIZE_BITS;
    }
    level
}

/// The information of subtrie change.
#[derive(Debug, Clone)]
struct SubtrieChangeInfo {
    old_capacity: u64,
    old_level: usize,
    old_top_id: NodeId,
    new_capacity: u64,
    new_level: usize,
    new_top_id: NodeId,
    root_id: NodeId,
}

impl SubtrieChangeInfo {
    fn new(bid: BucketId, old_capacity: u64, new_capacity: u64) -> Self {
        let old_level = sub_trie_top_level(old_capacity);
        let new_level = sub_trie_top_level(new_capacity);
        let old_top_id =
            ((bid as NodeId) << BUCKET_SLOT_BITS as NodeId) + STARTING_NODE_ID[old_level] as NodeId;
        let new_top_id =
            ((bid as NodeId) << BUCKET_SLOT_BITS as NodeId) + STARTING_NODE_ID[new_level] as NodeId;
        let root_id = (bid as NodeId) + STARTING_NODE_ID[TRIE_LEVELS - 1] as NodeId;
        Self { old_capacity, old_level, old_top_id, new_capacity, new_level, new_top_id, root_id }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        mem_salt::MemSalt,
        state::{state::EphemeralSaltState, updates::StateUpdates},
        trie::trie::{kv_hash, StateRoot},
        types::{PlainKey, PlainValue},
    };
    use alloy_primitives::*;
    use itertools::Itertools;

    use crate::{
        account::Account,
        constant::{zero_commitment, DEFAULT_COMMITMENT_AT_LEVEL, STARTING_NODE_ID, TRIE_LEVELS},
        genesis::EmptySalt,
        traits::*,
        types::Bytes,
    };
    use std::collections::HashMap;
    const KV_BUCKET_OFFSET: NodeId = NUM_META_BUCKETS as NodeId;

    #[test]
    fn expansion_and_contraction_no_kvchanges() {
        let store = MemSalt::new();
        let mut trie = StateRoot::new();
        let bid = KV_BUCKET_OFFSET as BucketId + 4;
        let salt_key: SaltKey =
            (bid >> MIN_BUCKET_SIZE_BITS, bid as SlotId % MIN_BUCKET_SIZE as SlotId).into();
        // initialize the trie
        let state_updates = StateUpdates {
            data: vec![((bid, 3).into(), (None, Some(SaltValue::new(&[1; 32], &[1; 32]))))]
                .into_iter()
                .collect(),
        };
        let (root, trie_updates) = trie.update(&store, &state_updates).unwrap();
        state_updates.write_to_store(&store).unwrap();
        trie_updates.write_to_store(&store).unwrap();

        // only expand capacity
        let state_updates = StateUpdates {
            data: vec![(
                salt_key,
                (Some(BucketMeta::default().into()), Some(bucket_meta(0, 131072).into())),
            )]
            .into_iter()
            .collect(),
        };
        let (root1, trie_updates) = trie.update(&store, &state_updates).unwrap();
        state_updates.write_to_store(&store).unwrap();
        trie_updates.write_to_store(&store).unwrap();
        let (cmp_root, _) = compute_from_scratch(&store).unwrap();
        assert_eq!(root1, cmp_root);

        // only ‌contract capacity
        let state_updates = StateUpdates {
            data: vec![(
                salt_key,
                (Some(bucket_meta(0, 131072).into()), Some(BucketMeta::default().into())),
            )]
            .into_iter()
            .collect(),
        };
        let (root1, _) = trie.update(&store, &state_updates).unwrap();
        assert_eq!(root1, root);
    }

    #[test]
    fn expansion_and_contraction_small() {
        let store = MemSalt::new();
        let mut trie = StateRoot::new();
        let bid = KV_BUCKET_OFFSET as BucketId + 4;
        let salt_key: SaltKey =
            (bid >> MIN_BUCKET_SIZE_BITS, bid as SlotId % MIN_BUCKET_SIZE as SlotId).into();
        // initialize the trie
        let initialize_state_updates = StateUpdates {
            data: vec![
                ((bid, 3).into(), (None, Some(SaltValue::new(&[1; 32], &[1; 32])))),
                ((bid, 5).into(), (None, Some(SaltValue::new(&[2; 32], &[2; 32])))),
            ]
            .into_iter()
            .collect(),
        };

        let (initialize_root, initialize_trie_updates) =
            trie.update(&store, &initialize_state_updates).unwrap();
        initialize_state_updates.clone().write_to_store(&store).unwrap();
        initialize_trie_updates.clone().write_to_store(&store).unwrap();
        let (root, mut init_trie_updates) = compute_from_scratch(&store).unwrap();
        init_trie_updates.data.sort_by(|(a, _), (b, _)| b.cmp(a));
        assert_eq!(root, initialize_root);

        // expand capacity and add kvs
        let new_capacity = 131072;
        let expand_state_updates = StateUpdates {
            data: vec![
                (
                    salt_key,
                    (Some(BucketMeta::default().into()), Some(bucket_meta(0, new_capacity).into())),
                ),
                ((bid, 3).into(), (Some(SaltValue::new(&[1; 32], &[1; 32])), None)),
                ((bid, 2049).into(), (None, Some(SaltValue::new(&[3; 32], &[3; 32])))),
                (
                    (bid, new_capacity - 259).into(),
                    (None, Some(SaltValue::new(&[4; 32], &[4; 32]))),
                ),
                ((bid, new_capacity - 1).into(), (None, Some(SaltValue::new(&[5; 32], &[5; 32])))),
            ]
            .into_iter()
            .collect(),
        };
        let (expansion_root, trie_updates) = trie.update(&store, &expand_state_updates).unwrap();
        expand_state_updates.write_to_store(&store).unwrap();
        trie_updates.write_to_store(&store).unwrap();
        let (root, _) = compute_from_scratch(&store).unwrap();
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
        let (expansion_root, trie_updates) = trie.update(&store, &expand_state_updates).unwrap();
        expand_state_updates.write_to_store(&store).unwrap();
        trie_updates.write_to_store(&store).unwrap();
        let (root, _) = compute_from_scratch(&store).unwrap();
        assert_eq!(root, expansion_root);

        // contract capacity and remove kvs
        let contract_state_updates = StateUpdates {
            data: vec![
                (
                    salt_key,
                    (Some(bucket_meta(0, new_capacity).into()), Some(bucket_meta(0, 1024).into())),
                ),
                ((bid, 3).into(), (None, Some(SaltValue::new(&[1; 32], &[1; 32])))),
                ((bid, 2049).into(), (Some(SaltValue::new(&[3; 32], &[3; 32])), None)),
                (
                    (bid, new_capacity - 259).into(),
                    (Some(SaltValue::new(&[4; 32], &[4; 32])), None),
                ),
                ((bid, new_capacity - 1).into(), (Some(SaltValue::new(&[5; 32], &[6; 32])), None)),
            ]
            .into_iter()
            .collect(),
        };
        let (contraction_root, trie_updates) =
            trie.update(&store, &contract_state_updates).unwrap();
        contract_state_updates.write_to_store(&store).unwrap();
        trie_updates.write_to_store(&store).unwrap();
        let (root, _) = compute_from_scratch(&store).unwrap();
        assert_eq!(root, contraction_root);

        let contract_state_updates = StateUpdates {
            data: vec![(
                salt_key,
                (Some(bucket_meta(0, 1024).into()), Some(bucket_meta(0, 256).into())),
            )]
            .into_iter()
            .collect(),
        };
        let (contraction_root, _) = trie.update(&store, &contract_state_updates).unwrap();

        assert_eq!(initialize_root, contraction_root);
    }

    #[test]
    fn expansion_and_contraction_large() {
        let store = MemSalt::new();
        let mut trie = StateRoot::new();
        let mut state_updates = StateUpdates::default();

        for bid in KV_BUCKET_OFFSET..KV_BUCKET_OFFSET + 10000 {
            for slot_id in 0..128 {
                state_updates.data.insert(
                    (bid as BucketId, slot_id).into(),
                    (None, Some(SaltValue::new(&[slot_id as u8; 32], &[slot_id as u8; 32]))),
                );
            }
        }

        let (root, trie_updates) = trie.update(&store, &state_updates).unwrap();
        state_updates.clone().write_to_store(&store).unwrap();
        trie_updates.clone().write_to_store(&store).unwrap();
        let (root1, _) = compute_from_scratch(&store).unwrap();
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
                (Some(BucketMeta::default().into()), Some(bucket_meta(0, expand_capacity).into())),
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

        let (extended_root, trie_updates) = trie.update(&store, &state_updates).unwrap();
        state_updates.clone().write_to_store(&store).unwrap();
        trie_updates.clone().write_to_store(&store).unwrap();
        let (root2, _) = compute_from_scratch(&store).unwrap();
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
                (Some(bucket_meta(0, expand_capacity).into()), Some(BucketMeta::default().into())),
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
        let (contraction_root, trie_updates) = trie.update(&store, &state_updates).unwrap();
        state_updates.clone().write_to_store(&store).unwrap();
        trie_updates.clone().write_to_store(&store).unwrap();
        let (root3, _) = compute_from_scratch(&store).unwrap();
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
        assert_eq!(sub_trie_top_level(256 * 256 * 256 * 256), SUB_TRIE_LEVELS - 4);
        assert_eq!(sub_trie_top_level(256 * 256 * 256 * 256 * 2), SUB_TRIE_LEVELS - 5);
        // test with max capacity 40bits
        assert_eq!(sub_trie_top_level(256 * 256 * 256 * 256 * 256), SUB_TRIE_LEVELS - 5);
    }

    #[test]
    fn incremental_update_small() {
        let mut state_updates = StateUpdates::default();
        let store = MemSalt::new();
        // set expansion bucket metadata and check update with expanded bucket
        let update_bid = KV_BUCKET_OFFSET as BucketId + 2;
        let extend_bid = KV_BUCKET_OFFSET as BucketId + 3;
        store.put_meta(update_bid, bucket_meta(0, 65536 * 2)).unwrap();

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
            ..Default::default()
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
                    (Some(BucketMeta::default().into()), Some(bucket_meta(0, 512).into())),
                ),
                ((extend_bid, 333).into(), (None, Some(SaltValue::new(&[44; 32], &[44; 32])))),
                // keys for update expanded bucket
                ((update_bid, 258).into(), (None, Some(SaltValue::new(&[66; 32], &[66; 32])))),
                ((update_bid, 1023).into(), (None, Some(SaltValue::new(&[77; 32], &[77; 32])))),
            ]
            .into_iter()
            .collect(),
            ..Default::default()
        };

        let mut trie = StateRoot::new();
        trie.incremental_update(&store, &state_updates1).unwrap();
        state_updates.merge(&state_updates1);
        trie.incremental_update(&store, &state_updates2).unwrap();
        state_updates.merge(&state_updates2);
        let (root, mut trie_updates) = trie.finalize(&store).unwrap();

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
                    (Some(BucketMeta::default().into()), Some(bucket_meta(0, 512).into())),
                ),
                ((extend_bid, 333).into(), (None, Some(SaltValue::new(&[44; 32], &[44; 32])))),
                // keys for update expanded bucket
                ((update_bid, 258).into(), (None, Some(SaltValue::new(&[66; 32], &[66; 32])))),
                ((update_bid, 1023).into(), (None, Some(SaltValue::new(&[77; 32], &[77; 32])))),
            ]
            .into_iter()
            .collect(),
            ..Default::default()
        };
        assert_eq!(cmp_state_updates, state_updates);

        let mut trie = StateRoot::new();
        let (cmp_root, mut cmp_trie_updates) = trie.update(&store, &cmp_state_updates).unwrap();
        assert_eq!(root, cmp_root);
        trie_updates.data.sort_by(|(a, _), (b, _)| a.cmp(b));
        cmp_trie_updates.data.sort_by(|(a, _), (b, _)| a.cmp(b));
        trie_updates.data.iter().zip(cmp_trie_updates.data.iter()).for_each(
            |(trie_update, cmp_trie_update)| {
                assert_eq!(trie_update.0, cmp_trie_update.0);
                check_commitments(trie_update.1 .0, cmp_trie_update.1 .0);
                check_commitments(trie_update.1 .1, cmp_trie_update.1 .1);
            },
        );
    }

    #[test]
    fn increment_updates_large() {
        let kvs = create_random_account(10000);
        let mock_db = MemSalt::new();
        let mut state = EphemeralSaltState::new(&mock_db);
        let mut trie = StateRoot::new();
        let total_state_updates = state.update(&kvs).unwrap();
        let (root, mut total_trie_updates) = trie.update(&mock_db, &total_state_updates).unwrap();

        let sub_kvs: Vec<HashMap<PlainKey, Option<PlainValue>>> = kvs
            .into_iter()
            .chunks(1000)
            .into_iter()
            .map(|chunk| chunk.collect::<HashMap<PlainKey, Option<PlainValue>>>())
            .collect();

        let mut state = EphemeralSaltState::new(&mock_db);
        let mut trie = StateRoot::new();
        let mut final_state_updates = StateUpdates::default();
        sub_kvs.iter().for_each(|kvs| {
            let state_updates = state.update(kvs).unwrap();
            trie.incremental_update(&mock_db, &state_updates).unwrap();
            final_state_updates.merge(&state_updates);
        });
        let (final_root, mut final_trie_updates) = trie.finalize(&mock_db).unwrap();

        assert_eq!(root, final_root);
        assert_eq!(total_state_updates, final_state_updates);
        total_trie_updates.data.sort_by(|(a, _), (b, _)| a.cmp(b));
        final_trie_updates.data.sort_by(|(a, _), (b, _)| a.cmp(b));
        total_trie_updates.data.iter().zip(final_trie_updates.data.iter()).for_each(|(r1, r2)| {
            assert_eq!(r1.0, r2.0);
            assert!(is_commitment_equal(r1.1 .0, r2.1 .0));
            assert!(is_commitment_equal(r1.1 .1, r2.1 .1));
        });
    }

    #[test]
    fn compute_from_scratch_small() {
        let mock_db = MemSalt::new();
        let mut trie = StateRoot::new();
        let mut state_updates = StateUpdates::default();

        let bid = KV_BUCKET_OFFSET as BucketId;
        let salt_key: SaltKey =
            (bid >> MIN_BUCKET_SIZE_BITS, (bid % MIN_BUCKET_SIZE as BucketId) as SlotId).into();
        // bucket meta changes at bucket[bid]
        state_updates.data.insert(
            salt_key,
            (
                Some(SaltValue::from(BucketMeta::default())),
                Some(SaltValue::from(bucket_meta(15, 512))),
            ),
        );

        state_updates
            .data
            .insert((bid, 1).into(), (None, Some(SaltValue::new(&[1; 32], &[1; 32]))));
        state_updates
            .data
            .insert((bid, 2).into(), (None, Some(SaltValue::new(&[2; 32], &[2; 32]))));
        state_updates
            .data
            .insert((bid + 1, 111).into(), (None, Some(SaltValue::new(&[2; 32], &[2; 32]))));
        state_updates
            .data
            .insert((bid + 65536, 55).into(), (None, Some(SaltValue::new(&[3; 32], &[3; 32]))));

        let (root0, _) = trie.update(&mock_db, &state_updates).unwrap();
        state_updates.write_to_store(&mock_db).unwrap();
        let (root1, _) = compute_from_scratch(&mock_db).unwrap();

        assert_eq!(root0, root1);
    }

    #[test]
    fn compute_from_scratch_large() {
        let mock_db = MemSalt::new();
        let mut trie = StateRoot::new();
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

        let (root0, _) = trie.update(&mock_db, &state_updates).unwrap();
        state_updates.write_to_store(&mock_db).unwrap();
        let (root1, _) = compute_from_scratch(&mock_db).unwrap();

        assert_eq!(root0, root1);
    }

    #[test]
    fn apply_deltas() {
        let elements: Vec<Element> = create_commitments(11)
            .iter()
            .map(|c| Element::from_bytes_unchecked_uncompressed(*c))
            .collect();
        let trie = StateRoot::new();
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
        let updates = trie.apply_deltas(&EmptySalt, c_deltas.clone(), task_size).unwrap();

        let exp_id_vec = vec![0 as NodeId, 1, 2, 3, 4];
        assert_eq!(exp_id_vec.len(), updates.len());
        updates.iter().zip(exp_id_vec.iter()).for_each(|((id, (old_c, new_c)), exp_id)| {
            assert_eq!(*id, *exp_id);
            let cmp_old_c = EmptySalt.get(*id).unwrap();
            assert_eq!(cmp_old_c, *old_c);

            let delta = c_deltas.iter().filter(|(i, _)| *i == *id).map(|(_, e)| *e).sum();

            let cmp_new_c = (Element::from_bytes_unchecked_uncompressed(cmp_old_c) + delta)
                .to_bytes_uncompressed();
            assert_eq!(cmp_new_c, *new_c);
        });
    }

    #[test]
    fn trie_update_leaf_nodes() {
        let committer = get_global_committer();
        let store = MemSalt::new();
        let trie = StateRoot::new();
        let mut state_updates = StateUpdates::default();
        let key: [Bytes; 3] = [[1; 32].into(), [2; 32].into(), [3; 32].into()];
        let value: Bytes = [100; 32].into();
        let bottom_level = TRIE_LEVELS - 1;
        let bottom_level_start = STARTING_NODE_ID[bottom_level] as NodeId;
        let zero = zero_commitment();

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

        let salt_updates = trie.update_leaf_nodes(&store, &state_updates).unwrap();

        let c1 = committer
            .add_deltas(
                DEFAULT_COMMITMENT_AT_LEVEL[bottom_level].1,
                &[(
                    1,
                    kv_hash(&Some(SaltValue::from(BucketMeta::default()))).0,
                    kv_hash(&Some(SaltValue::from(bucket_meta(5, MIN_BUCKET_SIZE as SlotId)))).0,
                )],
            )
            .to_bytes_uncompressed();
        let c2 = committer
            .add_deltas(
                zero,
                &[
                    (1, [0; 32], kv_hash(&Some(SaltValue::new(&key[0], &value))).0),
                    (2, [0; 32], kv_hash(&Some(SaltValue::new(&key[1], &value))).0),
                ],
            )
            .to_bytes_uncompressed();

        assert_eq!(
            salt_updates,
            vec![
                (4 + bottom_level_start, (DEFAULT_COMMITMENT_AT_LEVEL[bottom_level].1, c1)),
                (bottom_level_start + KV_BUCKET_OFFSET + 1, (zero, c2))
            ]
        );
    }

    #[test]
    fn trie_update_internal_nodes() {
        let committer = get_global_committer();
        let bottom_level = TRIE_LEVELS - 1;
        let trie = StateRoot::new();
        let (zero, nonce_c) = (zero_commitment(), DEFAULT_COMMITMENT_AT_LEVEL[bottom_level].1);
        let bottom_level_start = STARTING_NODE_ID[bottom_level] as NodeId;
        let cs = create_commitments(3);

        let updates = vec![
            (bottom_level_start + 1, (nonce_c, cs[0])),
            (bottom_level_start + KV_BUCKET_OFFSET + 1, (zero, cs[1])),
            (bottom_level_start + KV_BUCKET_OFFSET + 2, (zero, cs[2])),
        ];

        // Check and handle the commitment updates of the bottom-level node
        let cur_level = bottom_level - 1;
        let unprocess_updates = trie
            .update_internal_nodes_inner(&EmptySalt, &mut updates.clone(), cur_level, get_parent_id)
            .unwrap();

        let bytes_indices = Element::hash_commitments(&[zero, nonce_c, cs[0], cs[1], cs[2]]);
        let old_c = DEFAULT_COMMITMENT_AT_LEVEL[cur_level].1;
        let c1 = committer
            .add_deltas(old_c, &[(1, bytes_indices[1], bytes_indices[2])])
            .to_bytes_uncompressed();

        let c2 = committer
            .add_deltas(
                zero,
                &[(1, bytes_indices[0], bytes_indices[3]), (2, bytes_indices[0], bytes_indices[4])],
            )
            .to_bytes_uncompressed();

        assert_eq!(unprocess_updates, vec![(257, (old_c, c1)), (513, (zero, c2))]);

        // Check and handle the commitment updates of the second-level node
        let cur_level = cur_level - 1;
        let unprocess_updates = trie
            .update_internal_nodes_inner(
                &EmptySalt,
                &mut unprocess_updates.clone(),
                cur_level,
                get_parent_id,
            )
            .unwrap();

        let bytes_indices = Element::hash_commitments(&[zero, old_c, c1, c2]);
        let old_c = DEFAULT_COMMITMENT_AT_LEVEL[cur_level].1;
        let c3 = committer
            .add_deltas(old_c, &[(0, bytes_indices[1], bytes_indices[2])])
            .to_bytes_uncompressed();
        let c4 = committer
            .add_deltas(zero, &[(0, bytes_indices[0], bytes_indices[3])])
            .to_bytes_uncompressed();

        assert_eq!(unprocess_updates, vec![(1, (old_c, c3)), (2, (zero, c4))]);

        let cur_level = cur_level - 1;
        let unprocess_updates = trie
            .update_internal_nodes_inner(
                &EmptySalt,
                &mut unprocess_updates.clone(),
                cur_level,
                get_parent_id,
            )
            .unwrap();
        let bytes_indices = Element::hash_commitments(&[zero, old_c, c3, c4]);
        let old_c = DEFAULT_COMMITMENT_AT_LEVEL[cur_level].1;
        let c5 = committer
            .add_deltas(
                old_c,
                &[(0, bytes_indices[1], bytes_indices[2]), (1, bytes_indices[0], bytes_indices[3])],
            )
            .to_bytes_uncompressed();
        assert_eq!(unprocess_updates, vec![(0, (old_c, c5))]);
    }

    #[test]
    fn trie_calculate_inner() {
        let mut trie = StateRoot::new();
        let committer = get_global_committer();
        let zero = zero_commitment();

        let mut state_updates = StateUpdates::default();
        let kv1 = Some(SaltValue::new(&[1; 32], &[1; 32]));
        let kv2 = Some(SaltValue::new(&[2; 32], &[2; 32]));
        let fr1 = kv_hash(&kv1).0;
        let fr2 = kv_hash(&kv2).0;

        // Prepare the state updates
        let bucket_ids =
            vec![KV_BUCKET_OFFSET as BucketId + 257, KV_BUCKET_OFFSET as BucketId + 65536];
        state_updates.add((bucket_ids[0], 1).into(), None, kv1.clone());
        state_updates.add((bucket_ids[0], 9).into(), None, kv2.clone());
        state_updates.add((bucket_ids[1], 9).into(), kv1.clone(), kv2.clone());

        let (_, mut trie_updates) = trie.update(&EmptySalt, &state_updates).unwrap();
        trie_updates.data.sort_by(|(a, _), (b, _)| b.cmp(a));

        // Check the commitment updates of the bottom-level node
        let c1 = committer.add_deltas(zero, &[(9, fr1, fr2)]).to_bytes_uncompressed();
        let c2 = committer
            .add_deltas(zero, &[(1, [0; 32], fr1), (9, [0; 32], fr2)])
            .to_bytes_uncompressed();
        assert_eq!(
            trie_updates.data[0..2],
            vec![
                (STARTING_NODE_ID[TRIE_LEVELS - 1] as NodeId + bucket_ids[1] as NodeId, (zero, c1)),
                (STARTING_NODE_ID[TRIE_LEVELS - 1] as NodeId + bucket_ids[0] as NodeId, (zero, c2)),
            ]
        );

        // Check the commitment updates of the TRIE_LEVELS - 2 level node
        let bytes_indices = Element::hash_commitments(&[zero, c1, c2]);
        let c3 = committer
            .add_deltas(zero, &[(0, bytes_indices[0], bytes_indices[1])])
            .to_bytes_uncompressed();
        let c4 = committer
            .add_deltas(zero, &[(1, bytes_indices[0], bytes_indices[2])])
            .to_bytes_uncompressed();
        assert_eq!(
            trie_updates.data[2..4],
            vec![
                (
                    STARTING_NODE_ID[TRIE_LEVELS - 2] as NodeId + bucket_ids[1] as NodeId / 256,
                    (zero, c3)
                ),
                (
                    STARTING_NODE_ID[TRIE_LEVELS - 2] as NodeId + bucket_ids[0] as NodeId / 256,
                    (zero, c4)
                ),
            ]
        );

        // Check the commitment updates of the TRIE_LEVELS - 3 level node
        let bytes_indices = Element::hash_commitments(&[zero, c3, c4]);
        let c5 = committer
            .add_deltas(zero, &[(0, bytes_indices[0], bytes_indices[1])])
            .to_bytes_uncompressed();
        let c6 = committer
            .add_deltas(zero, &[(1, bytes_indices[0], bytes_indices[2])])
            .to_bytes_uncompressed();
        assert_eq!(
            trie_updates.data[4..6],
            vec![
                (
                    STARTING_NODE_ID[TRIE_LEVELS - 3] as NodeId + bucket_ids[1] as NodeId / 65536,
                    (zero, c5)
                ),
                (
                    STARTING_NODE_ID[TRIE_LEVELS - 3] as NodeId + bucket_ids[0] as NodeId / 65536,
                    (zero, c6)
                ),
            ]
        );

        // Check the commitment updates of the last level node
        assert_eq!(trie_updates.data[6].0, 0);
        let bytes_indices = Element::hash_commitments(&[zero, c5, c6]);
        let c7 = committer
            .add_deltas(
                DEFAULT_COMMITMENT_AT_LEVEL[0].1,
                &[(2, bytes_indices[0], bytes_indices[1]), (1, bytes_indices[0], bytes_indices[2])],
            )
            .to_bytes_uncompressed();
        assert_eq!(trie_updates.data[6], (0, (DEFAULT_COMMITMENT_AT_LEVEL[0].1, c7)));
    }

    #[test]
    fn calculate_trie_work() {
        let addresses: Vec<Address> = (0..5).map(|_| Address::random()).collect();
        let account1 = Account { balance: U256::from(10), ..Default::default() };
        let account2 = Account { balance: U256::from(100), ..Default::default() };
        let (slot1, storage_value1) = (B256::random(), B256::random());
        let (slot2, storage_value2) = (B256::random(), B256::random());
        let mock_db = MemSalt::new();

        let kvs1 = HashMap::from([
            (PlainKey::Account(addresses[0]), Some(PlainValue::Account(account1))),
            (PlainKey::Account(addresses[1]), Some(PlainValue::Account(account2))),
        ]);

        let kvs2 = HashMap::from([
            (PlainKey::Account(addresses[2]), Some(PlainValue::Account(account2))),
            (
                PlainKey::Storage(addresses[3], slot1),
                Some(PlainValue::Storage(storage_value1.into())),
            ),
            (
                PlainKey::Storage(addresses[4], slot2),
                Some(PlainValue::Storage(storage_value2.into())),
            ),
        ]);

        let mut kvs = kvs1.clone();
        kvs.extend(kvs2.clone());

        let total_state_updates = EphemeralSaltState::new(&mock_db).update(&kvs).unwrap();
        let (state_root, _) = StateRoot::new().update(&mock_db, &total_state_updates).unwrap();

        let state_updates1 = EphemeralSaltState::new(&mock_db).update(&kvs1).unwrap();
        let (_, trie_updates1) = StateRoot::new().update(&mock_db, &state_updates1).unwrap();
        state_updates1.write_to_store(&mock_db).unwrap();
        trie_updates1.write_to_store(&mock_db).unwrap();

        let state_updates2 = EphemeralSaltState::new(&mock_db).update(&kvs2).unwrap();
        let (state_root2, trie_updates2) =
            StateRoot::new().update(&mock_db, &state_updates2).unwrap();
        state_updates2.write_to_store(&mock_db).unwrap();
        trie_updates2.write_to_store(&mock_db).unwrap();
        assert_eq!(state_root, state_root2);

        let _ = TrieWriter::clear(&mock_db);
        let (state_root3, _) = compute_from_scratch(&mock_db).unwrap();
        assert_eq!(state_root, state_root3);
    }

    /// Checks if the default commitment is correct
    #[test]
    fn trie_level_default_committment() {
        let zero = zero_commitment();
        let mut default_committment_vec = vec![zero; TRIE_LEVELS];
        let len_vec = [1, 256, 256, 256];

        // default commitments like this
        //  C0_0
        //  C1_0 Zero...
        //  C2_0 ... C2_255 Zero...
        //  C3_0 ... C3_65535 Zero...
        for i in (0..TRIE_LEVELS).rev() {
            let delta_indices = if i == TRIE_LEVELS - 1 {
                (0..len_vec[i])
                    .map(|i| (i, [0u8; 32], kv_hash(&Some(BucketMeta::default().into())).0))
                    .collect::<Vec<_>>()
            } else {
                let bytes =
                    Element::hash_commitments(&vec![default_committment_vec[i + 1]; len_vec[i]]);
                bytes.into_iter().enumerate().map(|(i, e)| (i, [0u8; 32], e)).collect::<Vec<_>>()
            };

            default_committment_vec[i] =
                get_global_committer().add_deltas(zero, &delta_indices).to_bytes_uncompressed();

            assert_eq!(
                default_committment_vec[i], DEFAULT_COMMITMENT_AT_LEVEL[i].1,
                "The default commitment of the level {} should be equal to the constant value",
                i
            )
        }
    }

    fn get_delta_ranges(c_deltas: &[(NodeId, Element)], task_size: usize) -> Vec<(usize, usize)> {
        // Split the elements into chunks of roughly the same size.
        let mut splits = vec![0];
        let mut next_split = task_size;
        while next_split < c_deltas.len() {
            // Check if the current position is an eligible split point: i.e.,
            // the next element must belong to a different parent node.
            if c_deltas[next_split].0 != c_deltas[next_split - 1].0 {
                splits.push(next_split);
                next_split += task_size;
            } else {
                next_split += 1;
            }
        }
        splits.push(c_deltas.len());
        let ranges: Vec<_> =
            splits.iter().zip(splits.iter().skip(1)).map(|(&a, &b)| (a, b)).collect();

        ranges
    }

    fn create_commitments(l: usize) -> Vec<CommitmentBytes> {
        let committer = get_global_committer();
        (0..l)
            .map(|i| {
                committer.gi_mul_delta(&[0u8; 32], &[(i + 1) as u8; 32], 0).to_bytes_uncompressed()
            })
            .collect()
    }

    fn create_random_account(l: usize) -> HashMap<PlainKey, Option<PlainValue>> {
        (0..l)
            .map(|i| {
                (
                    PlainKey::Account(Address::random()),
                    Some(PlainValue::Account(Account {
                        balance: U256::from(i + 1),
                        ..Default::default()
                    })),
                )
            })
            .collect()
    }

    fn is_commitment_equal(c1: CommitmentBytes, c2: CommitmentBytes) -> bool {
        hash_commitment(c1) == hash_commitment(c2)
    }

    fn check_commitments(c1: CommitmentBytes, c2: CommitmentBytes) {
        assert_eq!(hash_commitment(c1), hash_commitment(c2))
    }

    fn bucket_meta(nonce: u32, capacity: SlotId) -> BucketMeta {
        BucketMeta { nonce, capacity, ..Default::default() }
    }
}
