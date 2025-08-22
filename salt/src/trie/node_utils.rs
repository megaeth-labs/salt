//! Utilities for working with NodeId in the SALT trie structure.
//!
//! This module provides functions for:
//! - Converting between different node representations
//! - Navigating the trie hierarchy (parent/child relationships)
//! - Mapping between SaltKeys and NodeIds
//! - Determining subtrie levels and structure

use crate::{
    constant::{
        BUCKET_SLOT_BITS, BUCKET_SLOT_ID_MASK, MIN_BUCKET_SIZE, MIN_BUCKET_SIZE_BITS,
        STARTING_NODE_ID, SUB_TRIE_LEVELS, TRIE_WIDTH_BITS,
    },
    types::{get_bfs_level, NodeId, SaltKey},
};

/// Given the ID and level of a node, return the index of this node among its siblings.
pub(crate) fn get_child_idx(node_id: &NodeId, level: usize) -> usize {
    (*node_id as usize - STARTING_NODE_ID[level]) & (MIN_BUCKET_SIZE - 1)
}

/// Given the ID of a parent node and the index of a child node,
/// return the ID of the child node.
pub fn get_child_node(parent_id: &NodeId, child_idx: usize) -> NodeId {
    let node_id = *parent_id & BUCKET_SLOT_ID_MASK;
    let bucket_id = *parent_id - node_id;
    let level = get_bfs_level(node_id);
    assert!(level < SUB_TRIE_LEVELS);

    bucket_id
        + ((node_id - STARTING_NODE_ID[level] as NodeId) << TRIE_WIDTH_BITS)
        + STARTING_NODE_ID[level + 1] as NodeId
        + child_idx as NodeId
}

/// Given the ID and level of a node, return the ID of its parent node
/// in the canonical trie.
pub(crate) fn get_parent_id(node_id: &NodeId, level: usize) -> NodeId {
    (((*node_id as usize - STARTING_NODE_ID[level]) >> MIN_BUCKET_SIZE_BITS)
        + STARTING_NODE_ID[level - 1]) as NodeId
}

/// Given the ID and level of a node, return the ID of its parent node
/// in the subtrie.
/// `level` is the level of the max subtrie, from 1..=4
pub(crate) fn subtrie_parent_id(id: &NodeId, level: usize) -> NodeId {
    let node_id = *id & BUCKET_SLOT_ID_MASK;
    let bucket_id = *id - node_id;
    bucket_id
        + STARTING_NODE_ID[level - 1] as NodeId
        + ((node_id - STARTING_NODE_ID[level] as NodeId) >> MIN_BUCKET_SIZE_BITS)
}

/// Given the `SaltKey`, return the ID of node in the subtrie.
pub(crate) fn subtrie_node_id(key: &SaltKey) -> NodeId {
    ((key.bucket_id() as NodeId) << BUCKET_SLOT_BITS)
        + (key.slot_id() >> MIN_BUCKET_SIZE_BITS) as NodeId
        + STARTING_NODE_ID[SUB_TRIE_LEVELS - 1] as NodeId
}

/// Return the top level(0..4) of the sub trie, by given the capacity.
///  level 0          |trie root:0|
///  level 1         |0| |1|....|256|
///  level 2       |0|...|256| |257|...|65536|
///  level 3     |0|...|256|...|65536| |65537|...|16777216|
///  level 4   |0|...|256|...|65536|...|16777216| |16777217|...|4294967296|
/// eg --- todo
pub(crate) fn sub_trie_top_level(mut capacity: u64) -> usize {
    let mut level = SUB_TRIE_LEVELS - 1;
    while capacity > MIN_BUCKET_SIZE as u64 {
        level -= 1;
        capacity >>= MIN_BUCKET_SIZE_BITS;
    }
    level
}

/// assume the node_id is subtrie_node_id()'s result;
pub(crate) fn subtrie_salt_key_start(id: &NodeId) -> SaltKey {
    let node_id = *id & BUCKET_SLOT_ID_MASK;
    let bucket_id = *id - node_id;
    let slot_id = (node_id - STARTING_NODE_ID[SUB_TRIE_LEVELS - 1] as u64) << MIN_BUCKET_SIZE_BITS;

    SaltKey(bucket_id + slot_id)
}
