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

use crate::{
    constant::{
        BUCKET_SLOT_BITS, BUCKET_SLOT_ID_MASK, MAIN_TRIE_LEVELS, MAX_SUBTREE_LEVELS,
        STARTING_NODE_ID, TRIE_WIDTH_BITS,
    },
    trie::node_utils::subtree_leaf_for_key,
    BucketId, NodeId, SaltKey, SlotId,
};
use iter_tools::Itertools;
use rayon::prelude::*;
use rustc_hash::FxHashMap;

/// A parent node and some or all of its children form a mini-tree.
/// Given `bucket_ids`, compute the set of mini-trees that must be opened in the
/// canonical (main) trie.
///
/// The parent node of a mini-tree is the path node of the bucket. For robustness we
/// sort and deduplicate intermediate path collections to ensure correct grouping.
///
/// # Arguments
///
/// - `bucket_ids` - A slice of bucket IDs
///
/// # Returns
///
/// Parent nodes and its to be opened children nodes(mini-trees).
///
/// To be compatible with the return format of bucket trie,
/// two parent ids are returned in a mini-tree and they are the same.
/// see `bucket_trie_parents_and_points` for more details.
#[allow(clippy::type_complexity)]
pub(crate) fn main_trie_parents_and_points(bucket_ids: &[BucketId]) -> Vec<(NodeId, Vec<u8>)> {
    if bucket_ids.is_empty() {
        return vec![];
    }

    // Extract all nodes path for layer 1 and layer 2
    let (mut l1_paths, mut l2_paths, l3_paths): (Vec<u8>, Vec<(u8, u8)>, Vec<(u8, u8, u8)>) =
        bucket_ids
            .iter()
            .map(|&bucket_id| {
                let path = bucket_id_to_path(bucket_id);

                (path[0], (path[0], path[1]), (path[0], path[1], path[2]))
            })
            .multiunzip();

    // Remove duplicate paths
    l1_paths.dedup();

    l2_paths.dedup();

    let mut res = vec![];

    // root
    res.push((0u64, l1_paths));

    // l1
    res.extend(l2_paths.chunk_by(|&x, &y| x.0 == y.0).map(|paths| {
        let node_id = paths[0].0 as u64 + STARTING_NODE_ID[1] as u64;

        (node_id, paths.iter().map(|path| path.1).collect_vec())
    }));

    // l2
    res.extend(
        l3_paths
            .chunk_by(|&x, &y| (x.0 == y.0) && (x.1 == y.1))
            .map(|paths| {
                let node_id =
                    (((paths[0].0 as u64) << 8) | paths[0].1 as u64) + STARTING_NODE_ID[2] as u64;
                (node_id, paths.iter().map(|path| path.2).collect_vec())
            }),
    );

    res
}

/// Compute, for each bucket, the mini-trees(parent and children) in the bucket trie and the bucket state nodes
/// according to the provided salt keys and per-bucket top level information.
///
/// # Parameters
///
/// * `salt_keys` - list of salt keys to be processed
/// * `buckets_top_level` - trie height information of each bucket, used to determine the trie
///   structure of the bucket
///
/// # Returns
///
/// Return a tuple containing two parts of information:
///
/// 1. `bucket_trie_nodes`: mini-tree information of the bucket-trie
/// - Each element is a triple `(parent_id, logic_id, children_indices)`
/// - `parent_id`: ID of the real connected parent node in Salt trie
/// - `logic_parent_id`: logical node ID passed to `TrieReader.children`. For example, when
///   `buckets_top_level` is 3, the last level of bucket-trie nodes directly connects to the last
///   level of canonical (main) trie nodes, but the logical parent is still the level-3 bucket-trie
///   node (bucket root is level 0 in the bucket-trie)
/// - `children_indices`: list of child node indexes to be accessed
///
/// 2. `bucket_state_nodes`: bucket state node information
/// - Each element is a tuple `(bucket_id, state_nodes)`
/// - `bucket_id`: bucket ID
/// - `state_nodes`: list of state nodes for the bucket, each element is `(node_id, kv_indices)`
/// - `node_id`: state node ID
/// - `kv_indices`: list of kv indexes to be accessed
///
/// # Description
///
/// - For each bucket, construct trie nodes at different levels according to its `top_level`.
/// - `top_level` is in the range 0..=4, indicating from which level the bucket-trie starts.
/// - When `top_level == 4`, the bucket has no bucket-trie structure.
/// - When `top_level < 4`, build bucket-trie nodes from the bucket-trie root down to level 4.
/// - All node IDs are calculated based on `STARTING_NODE_ID` and path information.
#[allow(clippy::type_complexity)]
pub(crate) fn bucket_trie_parents_and_points(
    salt_keys: &[SaltKey],
    buckets_top_level: &FxHashMap<BucketId, u8>,
) -> (
    Vec<(NodeId, Vec<u8>)>,
    Vec<(BucketId, Vec<(NodeId, Vec<u8>)>)>,
) {
    if salt_keys.is_empty() {
        return (vec![], vec![]);
    }

    let bucket_trie_nodes = salt_keys
        .par_chunk_by(|&x, &y| x.bucket_id() == y.bucket_id())
        .into_par_iter()
        .flat_map(|keys| {
            let bucket_id = keys[0].bucket_id();
            let levels = MAX_SUBTREE_LEVELS as u8 - buckets_top_level[&bucket_id];

            let slot_ids = keys.iter().map(|key| key.slot_id()).collect_vec();

            // Extract all node paths for level1..=level4 within the bucket-trie
            let (mut l1_paths, mut l2_paths, mut l3_paths, mut l4_paths): (
                Vec<u8>,
                Vec<(u8, u8)>,
                Vec<(u8, u8, u8)>,
                Vec<(u8, u8, u8, u8)>,
            ) = slot_ids
                .iter()
                .map(|&slot_id| {
                    let path = slot_id_to_node_path(slot_id);
                    (
                        path[0],
                        (path[0], path[1]),
                        (path[0], path[1], path[2]),
                        (path[0], path[1], path[2], path[3]),
                    )
                })
                .multiunzip();

            l1_paths.dedup();
            l2_paths.dedup();
            l3_paths.dedup();
            l4_paths.dedup();

            process_bucket_trie_nodes(
                bucket_id, levels, &l1_paths, &l2_paths, &l3_paths, &l4_paths,
            )
        })
        .collect::<Vec<_>>();

    let bucket_state_nodes = salt_keys
        .par_chunk_by(|&x, &y| x.bucket_id() == y.bucket_id())
        .into_par_iter()
        .map(|keys| {
            let bucket_id = keys[0].bucket_id();
            let levels = MAX_SUBTREE_LEVELS as u8 - buckets_top_level[&bucket_id];
            process_bucket_state_nodes(bucket_id, levels, keys)
        })
        .collect::<Vec<_>>();

    (bucket_trie_nodes, bucket_state_nodes)
}

/// Process trie nodes for a single bucket
fn process_bucket_trie_nodes(
    bucket_id: BucketId,
    levels: u8,
    l1_paths: &[u8],
    l2_paths: &[(u8, u8)],
    l3_paths: &[(u8, u8, u8)],
    l4_paths: &[(u8, u8, u8, u8)],
) -> Vec<(NodeId, Vec<u8>)> {
    if levels == 1 {
        return vec![];
    }

    let mut nodes = Vec::new();
    let bucket_base = (bucket_id as u64) << BUCKET_SLOT_BITS;
    let main_trie_node = bucket_id as u64 + STARTING_NODE_ID[3] as u64;

    // Process different levels of nodes
    match levels {
        2 => {
            // l3 and its children
            // The capacity of the bucket is guaranteed to be (x.0 == y.0) && (x.1 == y.1) && (x.2 == y.2)
            nodes.push((
                // store the levels in node id 32-40 bits
                // [64..........40..32........0]
                //    bucket id      node index
                main_trie_node | ((levels as u64) << 32),
                l4_paths.iter().map(|path| path.3).collect_vec(),
            ));
        }
        3 => {
            // l2 and its children
            nodes.push((
                main_trie_node | ((levels as u64) << 32),
                l3_paths.iter().map(|path| path.2).collect_vec(),
            ));

            // l3 and its children
            nodes.extend(l4_paths.chunk_by(|&x, &y| x.2 == y.2).map(|chunk| {
                let parent_id = bucket_base + (chunk[0].2 as u64) + STARTING_NODE_ID[3] as u64;
                (parent_id, chunk.iter().map(|path| path.3).collect_vec())
            }));
        }
        4 => {
            // l1 and its children
            nodes.push((
                main_trie_node | ((levels as u64) << 32),
                l2_paths.iter().map(|path| path.1).collect_vec(),
            ));

            // l2 and its children
            nodes.extend(l3_paths.chunk_by(|&x, &y| x.1 == y.1).map(|chunk| {
                let parent_id = bucket_base + (chunk[0].1 as u64) + STARTING_NODE_ID[2] as u64;
                (parent_id, chunk.iter().map(|path| path.2).collect_vec())
            }));

            // l3 and its children
            nodes.extend(
                l4_paths
                    .chunk_by(|&x, &y| (x.1 == y.1) && (x.2 == y.2))
                    .map(|chunk| {
                        let parent_id = bucket_base
                            + (chunk[0].2 as u64)
                            + ((chunk[0].1 as u64) << TRIE_WIDTH_BITS)
                            + STARTING_NODE_ID[3] as u64;
                        (parent_id, chunk.iter().map(|path| path.3).collect_vec())
                    }),
            );
        }
        5 => {
            // l0 and its children
            nodes.push((main_trie_node | ((levels as u64) << 32), l1_paths.to_vec()));

            // l1 and its children
            nodes.extend(l2_paths.chunk_by(|&x, &y| x.0 == y.0).map(|chunk| {
                let parent_id = bucket_base + (chunk[0].0 as u64) + STARTING_NODE_ID[1] as u64;
                (parent_id, chunk.iter().map(|path| path.1).collect_vec())
            }));

            // l2 and its children
            nodes.extend(
                l3_paths
                    .chunk_by(|&x, &y| (x.0 == y.0) && (x.1 == y.1))
                    .map(|chunk| {
                        let parent_id = bucket_base
                            + (chunk[0].1 as u64)
                            + ((chunk[0].0 as u64) << TRIE_WIDTH_BITS)
                            + STARTING_NODE_ID[2] as u64;
                        (parent_id, chunk.iter().map(|path| path.2).collect_vec())
                    }),
            );

            // l3 and its children
            nodes.extend(
                l4_paths
                    .chunk_by(|&x, &y| (x.0 == y.0) && (x.1 == y.1) && (x.2 == y.2))
                    .map(|chunk| {
                        let parent_id = bucket_base
                            + (chunk[0].2 as u64)
                            + ((chunk[0].1 as u64) << TRIE_WIDTH_BITS)
                            + ((chunk[0].0 as u64) << (TRIE_WIDTH_BITS * 2))
                            + STARTING_NODE_ID[3] as u64;
                        (parent_id, chunk.iter().map(|path| path.3).collect_vec())
                    }),
            );
        }
        _ => unreachable!(),
    }

    nodes
}

/// Process bucket state nodes for a single bucket
fn process_bucket_state_nodes(
    bucket_id: BucketId,
    levels: u8,
    keys: &[SaltKey],
) -> (BucketId, Vec<(NodeId, Vec<u8>)>) {
    if levels == 1 {
        return (
            bucket_id,
            vec![(
                bucket_id as u64 + STARTING_NODE_ID[3] as u64,
                keys.iter().map(|key| key.slot_id() as u8).collect_vec(),
            )],
        );
    }

    let state_nodes = keys
        .chunk_by(|&x, &y| x.slot_id() >> 8 == y.slot_id() >> 8)
        .map(|chunk| {
            let subtrie_node_id = subtree_leaf_for_key(&chunk[0]);
            let slot_ids = chunk
                .iter()
                .map(|key| (key.slot_id() & 0xFF) as u8)
                .collect_vec();
            (subtrie_node_id, slot_ids)
        })
        .collect_vec();

    (bucket_id, state_nodes)
}

/// Convert a bucket id to a canonical-trie path.
/// The bucket id range is [0, 256^3); outside the range the function will panic.
///
/// # Arguments
///
/// * `bucket_id` - The bucket id to convert
///
/// # Returns
///
/// The calculated path
pub const fn bucket_id_to_path(bucket_id: BucketId) -> [u8; MAIN_TRIE_LEVELS - 1] {
    [
        ((bucket_id >> (TRIE_WIDTH_BITS * 2)) & 0xFF) as u8,
        ((bucket_id >> TRIE_WIDTH_BITS) & 0xFF) as u8,
        (bucket_id & 0xFF) as u8,
    ]
}

/// Convert a slot id to a sub-trie node full path (4 levels).
/// The slot id range is [0, 256^5); outside the range the function will panic.
///
/// # Arguments
///
/// * `slot` - The slot id to convert
///
/// # Returns
///
/// The calculated path
pub const fn slot_id_to_node_path(slot: SlotId) -> [u8; MAX_SUBTREE_LEVELS - 1] {
    [
        ((slot >> (TRIE_WIDTH_BITS * 4)) & 0xFF) as u8,
        ((slot >> (TRIE_WIDTH_BITS * 3)) & 0xFF) as u8,
        ((slot >> (TRIE_WIDTH_BITS * 2)) & 0xFF) as u8,
        ((slot >> TRIE_WIDTH_BITS) & 0xFF) as u8,
    ]
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
pub const fn connect_parent_id(parent: NodeId) -> NodeId {
    if parent < BUCKET_SLOT_ID_MASK && parent >= (1 << 32) {
        parent & ((1 << 32) - 1)
    } else {
        parent
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
pub const fn logic_parent_id(parent: NodeId) -> NodeId {
    if parent < BUCKET_SLOT_ID_MASK && parent >= (1 << 32) {
        let connect_parent = parent & ((1 << 32) - 1);
        let levels = (parent >> 32) as u8;
        let bucket_id = connect_parent - STARTING_NODE_ID[3] as u64;
        STARTING_NODE_ID[MAX_SUBTREE_LEVELS - levels as usize] as u64
            + (bucket_id << BUCKET_SLOT_BITS)
    } else {
        parent
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::Rng;

    const fn path_to_bucket_id(node_path: &[u8]) -> BucketId {
        ((node_path[0] as BucketId) << 16)
            | ((node_path[1] as BucketId) << 8)
            | (node_path[2] as BucketId)
    }

    fn path_to_node_id(node_path: &[u8]) -> NodeId {
        if node_path.is_empty() {
            return 0;
        }

        node_path
            .iter()
            .rev()
            .enumerate()
            .fold(0, |result, (i, &x)| result + ((x as u64 + 1) << (i * 8)))
    }

    #[test]
    fn test_bucket_id_and_path() {
        for bucket_id in 0..16777216 {
            let node_path = bucket_id_to_path(bucket_id);

            let bucket_id_back = path_to_bucket_id(&node_path);

            // Check if the conversion is reversible
            assert_eq!(
                bucket_id_back, bucket_id,
                "Failed for bucket_id: {bucket_id}"
            );
        }
    }

    #[test]
    fn test_path_to_bucket_id() {
        let mut rng = rand::thread_rng();

        // Generate 1000 random paths
        let bucket_paths: Vec<Vec<u8>> = (0..1000)
            .map(|_| vec![rng.gen::<u8>(), rng.gen::<u8>(), rng.gen::<u8>()])
            .collect();

        for path in bucket_paths {
            let bucket_id = path_to_bucket_id(&path);
            // Test reversibility
            let reversed_path = bucket_id_to_path(bucket_id);
            assert_eq!(
                path, reversed_path,
                "Reversibility failed for path: {path:?}. Got: {reversed_path:?}"
            );
        }
    }

    #[test]
    fn test_const_node_info() {
        let nodes_path = vec![
            vec![],
            vec![0],
            vec![2],
            vec![8],
            vec![177],
            vec![255],
            vec![2, 3],
            vec![8, 0],
            vec![8, 3],
            vec![8, 255],
            vec![177, 0],
            vec![177, 255],
            vec![2, 3, 4],
            vec![8, 3, 0],
            vec![8, 3, 152],
            vec![8, 3, 255],
            vec![177, 255, 0],
            vec![177, 255, 173],
            vec![177, 255, 255],
        ];
        let node_ids = [
            0, 1, 3, 9, 178, 256, 772, 2305, 2308, 2560, 45569, 45824, 197637, 590849, 591001,
            591104, 11730945, 11731118, 11731200,
        ];
        for (i, path) in nodes_path.iter().enumerate() {
            let node_id = path_to_node_id(path);
            assert_eq!(node_id, node_ids[i]);
        }
        for i in 12..node_ids.len() {
            assert_eq!(
                node_ids[i],
                (path_to_bucket_id(nodes_path[i].as_slice()) + 1 + 256 + 256 * 256) as NodeId
            );
        }
    }

    #[test]
    fn test_path_to_node_id() {
        let bucket_id = 131844;
        let node_path = bucket_id_to_path(bucket_id);

        let mut node_ids = vec![];
        for i in 0..3 {
            node_ids.push(path_to_node_id(&node_path[0..i]));
        }

        let node_path_1 = [2, 3, 4];
        let node_indecies_1 = [0, 3, 772, 197637];

        for (i, node_index) in node_ids.iter().enumerate() {
            let path = node_path[0..i].to_vec();

            let child_index = if i < node_ids.len() - 1 {
                node_path[i]
            } else {
                0
            };

            assert_eq!(path, node_path_1[0..i].to_vec());
            if i < node_ids.len() - 1 {
                assert_eq!(child_index, node_path_1[i])
            } else {
                assert_eq!(child_index, 0);
            }
            assert_eq!(*node_index, node_indecies_1[i]);
        }
    }

    #[test]
    fn test_get_sub_trie_parents_and_points() {
        let bucket_path = [
            [8, 3, 0],
            [8, 3, 152],
            [8, 3, 255],
            [8, 255, 152],
            [8, 255, 170],
            [177, 0, 0],
            [177, 0, 255],
            [177, 255, 0],
            [177, 255, 173],
            [177, 255, 255],
            [255, 7, 7],
        ];
        let bucket_ids: Vec<BucketId> = bucket_path
            .iter()
            .map(|path| path_to_bucket_id(path))
            .collect();

        let parent_nodes = main_trie_parents_and_points(&bucket_ids);

        // Expected parent nodes:
        // 0 (root)
        // 9 (1st level for [8,x,x])
        // 178 (1st level for [177,x,x])
        // 256 (1st level for [255,7,7])
        // 2308 (2nd level for [8,3,x])
        // 2560 (2nd level for [8,255,x])
        // 45569 (2nd level for [177,0,x])
        // 45824 (2nd level for [177,255,x])
        // 65544 (2nd level for [255,7,7])
        let expected_parent_nodes = vec![
            (0, vec![8, 177, 255]),
            (9, vec![3, 255]),
            (178, vec![0, 255]),
            (256, vec![7]),
            (2308, vec![0, 152, 255]),
            (2560, vec![152, 170]),
            (45569, vec![0, 255]),
            (45824, vec![0, 173, 255]),
            (65544, vec![7]),
        ];

        assert_eq!(
            parent_nodes, expected_parent_nodes,
            "Parent nodes do not match expected values"
        );

        // Test with a single bucket ID
        let single_bucket_id = vec![525056];
        let single_parent_nodes = main_trie_parents_and_points(&single_bucket_id);
        let expected_single_parent_nodes = vec![(0, vec![8]), (9, vec![3]), (2308, vec![0])];

        assert_eq!(
            single_parent_nodes, expected_single_parent_nodes,
            "Parent nodes for single bucket ID do not match expected values"
        );

        // Test with empty input
        let empty_bucket_ids: Vec<BucketId> = vec![];
        let empty_parent_nodes = main_trie_parents_and_points(&empty_bucket_ids);
        let expected_empty_parent_nodes = vec![];

        assert_eq!(
            empty_parent_nodes, expected_empty_parent_nodes,
            "Parent nodes for empty input do not match expected values"
        );
    }
}
