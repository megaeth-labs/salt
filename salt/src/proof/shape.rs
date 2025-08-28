//! Shape computation and path extraction utilities for the SALT trie proof system.
//!
//! This module provides the core functionality for navigating and computing the structure
//! of the SALT trie, which is essential for generating and verifying cryptographic proofs.
//! It handles the hierarchical relationships between the main trie and bucket trees.
//!
//! # Key Concepts
//!
//! ## Path Representation
//! - **Bucket paths**: 3-element arrays `[u8; 3]` representing navigation from root to bucket
//! - **Slot paths**: 4-element arrays `[u8; 4]` representing navigation within a bucket, from
//!   bucket tree root to slot.
//! - **Path extraction**: Bit manipulation to convert IDs to navigable paths
//!
//! ## Node Addressing
//! Nodes can be addressed in two ways:
//! 1. **BFS number**: Absolute position in breadth-first traversal
//! 2. **Path**: Sequence of child indices from root
//!
//! Example: Node 590849 has path [8, 3, 0] and is located at:
//! - Level 1: Take child 8 (node 9)
//! - Level 2: Take child 3 (node 2308)
//! - Level 3: Take child 0 (node 590849)
//!
//! ## Bucket Tree Structure (up to 5 levels)
//! ```text
//! Each bucket at main trie level 3 can have its own internal tree,
//! and the main trie level 3 store the bucket tree root.
//!
//! Bucket Root(Level 0) ──┬── Level 1 (256 children)
//!                        ├── Level 2 (256² children)
//!                        ├── Level 3 (256³ children)
//!                        ├── Level 4 (256⁴ children)
//!                        └── 256⁵ slots(Leaf nodes are not included in the number of layers)
//!
//! - levels=1: 1-level bucket tree
//! - levels=2: 2-level bucket tree
//! - levels=3: 3-level bucket tree
//! - levels=4: 4-level bucket tree
//! - levels=5: 5-level bucket tree
//! ```

use std::collections::{BTreeMap, BTreeSet};

use crate::{
    constant::{
        BUCKET_SLOT_BITS, BUCKET_SLOT_ID_MASK, MAIN_TRIE_LEVELS, MAX_SUBTREE_LEVELS,
        STARTING_NODE_ID,
    },
    trie::node_utils::{
        bucket_root_node_id, get_parent_node, subtree_leaf_for_key, vc_position_in_parent,
    },
    BucketId, NodeId, SaltKey,
};
use rustc_hash::FxHashMap;

pub(crate) fn parents_and_points(
    salt_keys: &[SaltKey],
    levels: &FxHashMap<BucketId, u8>,
) -> BTreeMap<NodeId, BTreeSet<usize>> {
    let mut res = BTreeMap::new();

    for salt_key in salt_keys {
        let bucket_id = salt_key.bucket_id();
        let level = levels[&bucket_id];

        // handle main trie
        let mut node = bucket_root_node_id(salt_key.bucket_id());
        while node != 0 {
            let parent_node = get_parent_node(&node);
            res.entry(parent_node)
                .or_insert(BTreeSet::new())
                .insert(vc_position_in_parent(&node));

            node = parent_node;
        }

        // handle bucket tree
        let mut node = subtree_leaf_for_key(salt_key);

        let mut count = level;
        while count > 2 {
            let parent_node = get_parent_node(&node);
            res.entry(parent_node)
                .or_insert(BTreeSet::new())
                .insert(vc_position_in_parent(&node));

            node = parent_node;
            count -= 1;
        }

        if count == 2 {
            let main_trie_node = bucket_root_node_id(salt_key.bucket_id());
            res.entry(encode_parent(main_trie_node, level))
                .or_insert(BTreeSet::new())
                .insert(vc_position_in_parent(&node));
        }

        // hand kv's parent node
        let node = if level == 1 {
            bucket_root_node_id(salt_key.bucket_id())
        } else {
            subtree_leaf_for_key(salt_key)
        };

        res.entry(node)
            .or_insert(BTreeSet::new())
            .insert((salt_key.slot_id() & 0xFF) as usize);
    }

    res
}

/// Encode the parent node id and level into a single node id.
///
/// # Arguments
///
/// * `parent` - The parent node id
/// * `level` - The level of the parent node
///
/// *NOTE*: parent node id only is main trie L3 node, and it can works
///
pub const fn encode_parent(parent: NodeId, level: u8) -> NodeId {
    parent | ((level as u64) << 32)
}

pub const fn is_encoded_node(node: NodeId) -> bool {
    node < BUCKET_SLOT_ID_MASK && node > (1 << 32)
}

/// Extracts the connection parent ID from an encoded node ID.
///
/// Main trie L3 nodes with at least 2 levels bucket tree, will contain encoded level
/// information in their higher bits:
///
/// store the levels in node id 32-40 bits
///
/// [64..........40..32........0]
///
///    bucket id      node index
///
/// This function strips that information to retrieve the actual parent ID(Main trie L3 nodes)
/// used for establishing connections in the trie structure. If the node ID is not encoded, it
/// is returned as is.
pub const fn connect_parent_id(encode_parent: NodeId) -> NodeId {
    if is_encoded_node(encode_parent) {
        encode_parent & ((1 << 32) - 1)
    } else {
        encode_parent
    }
}

/// Calculates the logical parent ID from an encoded node ID.
///
/// Main trie L3 nodes with at least 2 levels bucket tree, will contain encoded level information in their higher
/// bits:
///
/// store the levels in node id 32-40 bits
///
/// [64..........40..32........0]
///
///    bucket id      node index
///
/// In the bucket tree, the root node are physically connected to the main trie, but
/// the bucket tree root node has a node id within the bucket's own tree structure. This function
/// computes this logical parent ID, which is necessary for operations like traversing
/// children within the bucket's conceptual hierarchy. If the node ID is not encoded,
/// it is returned as is.
pub const fn logic_parent_id(encode_parent: NodeId) -> NodeId {
    if is_encoded_node(encode_parent) {
        let connect_parent = encode_parent & ((1 << 32) - 1);
        let levels = (encode_parent >> 32) as u8;
        let bucket_id = connect_parent - STARTING_NODE_ID[3] as u64;
        STARTING_NODE_ID[MAX_SUBTREE_LEVELS - levels as usize] as u64
            + (bucket_id << BUCKET_SLOT_BITS)
    } else {
        encode_parent
    }
}

pub const fn is_leaf_node(encode_node: NodeId) -> bool {
    if (encode_node >> BUCKET_SLOT_BITS) > 0 {
        (encode_node & BUCKET_SLOT_ID_MASK) >= STARTING_NODE_ID[MAX_SUBTREE_LEVELS - 1] as u64
    } else if is_encoded_node(encode_node) {
        false
    } else {
        encode_node >= STARTING_NODE_ID[MAIN_TRIE_LEVELS - 1] as u64
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::{rngs::StdRng, Rng, SeedableRng};

    #[test]
    fn test_parents_and_points() {
        let bucket_ids = [
            0, 256, 65535, 65536, 65540, 1_000_000, 5_000_000, 16_777_215,
        ];
        let levels = [1, 1, 1, 1, 2, 3, 4, 5];

        let mut salt_keys = Vec::new();
        let mut rng = StdRng::seed_from_u64(42);

        for bucket_id in bucket_ids {
            if bucket_id <= 65536 {
                for _ in 0..100 {
                    salt_keys.push(SaltKey::from((bucket_id, rng.gen::<u64>() & 0xFF)));
                }
            } else if bucket_id == 65540 {
                for _ in 0..100 {
                    salt_keys.push(SaltKey::from((bucket_id, rng.gen::<u64>() & 0xFFFF)));
                }
            } else if bucket_id == 1_000_000 {
                for _ in 0..100 {
                    salt_keys.push(SaltKey::from((bucket_id, rng.gen::<u64>() & 0xFFFFFF)));
                }
            } else if bucket_id == 5_000_000 {
                for _ in 0..100 {
                    salt_keys.push(SaltKey::from((bucket_id, rng.gen::<u64>() & 0xFFFFFFFF)));
                }
            } else if bucket_id == 16_777_215 {
                for _ in 0..100 {
                    salt_keys.push(SaltKey::from((bucket_id, rng.gen::<u64>() & 0xFFFFFFFF)));
                }
            }
        }

        let levels = bucket_ids
            .into_iter()
            .zip(levels)
            .collect::<FxHashMap<BucketId, u8>>();

        let _res = parents_and_points(&salt_keys, &levels);
        // println!("res: {:?}", res);

        // // Test with a single bucket ID
        // let single_bucket_id = vec![525056];
        // let single_parent_nodes = main_trie_parents_and_points(&single_bucket_id);
        // let expected_single_parent_nodes = vec![(0, vec![8]), (9, vec![3]), (2308, vec![0])];

        // assert_eq!(
        //     single_parent_nodes, expected_single_parent_nodes,
        //     "Parent nodes for single bucket ID do not match expected values"
        // );

        // // Test with empty input
        // let empty_bucket_ids: Vec<BucketId> = vec![];
        // let empty_parent_nodes = parents_and_points(&empty_bucket_ids);
        // let expected_empty_parent_nodes = vec![];

        // assert_eq!(
        //     empty_parent_nodes, expected_empty_parent_nodes,
        //     "Parent nodes for empty input do not match expected values"
        // );
    }
}
