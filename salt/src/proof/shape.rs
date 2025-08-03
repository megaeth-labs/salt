//! This mod is used for calculation of shape in SALT Trie.
//！Here is an example data of a trie, and some nodes are not drawn in the figure.
//! The Trie have 4 layer, the branch size is 256, and all nodes are numbered using `node id`
//! starting from root.
//!
//! All nodes can be addressed using a path, for example, the path of node 590849 is [8,3,0]
//!
//! Only the last layer has leaf nodes, and each leaf node corresponds to a bucket one by one. The
//! relationship between them is that the bucket is where the data is stored, and the commitment
//! part of the bucket construct the leaf node. So the leaf node also has a `bucket id`, and
//! node id = bucket id + 1 + 256 + 256 * 256
//
// ┌───┐
// │ 0 │: node id
// └───┘
//
//   |
//   0  : path index
//   |
//
//                                           ┌───┐
//                                           │ 0 │
//                                           └─┬─┘
//      ┌───────────────────┬──────────────────┴──────────────┬───────────────────┐
//      0                   8                                177                 255
//      |                   |                                 |                   |
//    ┌─┴─┐               ┌─┴─┐                            ┌──┴──┐             ┌──┴──┐
//    │ 1 │               │ 9 │               ...          │ 178 │             │ 256 │
//    └───┘               └─┬─┘                            └──┬──┘             └─────┘
//             ┌────────────┼────────────┐          ┌─────────┴───────────┐
//             0            3           255         0                    255
//             |            |            |          |                     |
//          ┌──┴───┐     ┌──┴───┐     ┌──┴───┐  ┌───┴───┐             ┌───┴───┐
//     ...  │ 2305 │     │ 2308 │     │ 2560 │  │ 45569 │             │ 45824 │   ...
//          └──────┘     └──┬───┘     └──────┘  └───────┘             └───┬───┘
//              ┌───────────┼───────────┐                   ┌─────────────┼─────────────┐
//              0          152         255                  0            173           255
//              |           |           |                   |             |             |
//          ┌───┴────┐  ┌───┴────┐  ┌───┴────┐         ┌────┴─────┐  ┌────┴─────┐  ┌────┴─────┐
//  ...     │ 590849 │  │ 591001 │  │ 591104 │         │ 11730945 │  │ 11731118 │  │ 11731200 │ ...
//          └────────┘  └────────┘  └────────┘         └──────────┘  └──────────┘  └──────────┘
// bucket id:
//  0,1,2,...,525056      525208      525311     ...     11665152      11665325      11665407   ...
// bucket trie
// ...

use crate::{
    constant::{BUCKET_SLOT_BITS, STARTING_NODE_ID, SUB_TRIE_LEVELS, TRIE_LEVELS, TRIE_WIDTH_BITS},
    trie::trie::subtrie_node_id,
    types::get_node_level,
    BucketId, NodeId, SaltKey, SlotId,
};
use iter_tools::Itertools;
use rayon::prelude::*;
use rustc_hash::FxHashMap;

/// A parent node and some or all of its children form a mini-tree
/// Retrieve all mini-trees based on a given `bucket_ids` in main trie.
/// The mini-tree's parents node is the the path node of bucket
/// the `bucket_ids` have already been sorted and deduped
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
pub(crate) fn main_trie_parents_and_points(
    bucket_ids: &[BucketId],
) -> Vec<(NodeId, NodeId, Vec<u8>)> {
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
    res.push((0u64, 0u64, l1_paths));

    // l1
    res.extend(l2_paths.chunk_by(|&x, &y| x.0 == y.0).map(|paths| {
        let node_id = paths[0].0 as u64 + STARTING_NODE_ID[1] as u64;

        (
            node_id,
            node_id,
            paths.iter().map(|path| path.1).collect_vec(),
        )
    }));

    // l2
    res.extend(
        l3_paths
            .chunk_by(|&x, &y| (x.0 == y.0) && (x.1 == y.1))
            .map(|paths| {
                let node_id =
                    (((paths[0].0 as u64) << 8) | paths[0].1 as u64) + STARTING_NODE_ID[2] as u64;

                (
                    node_id,
                    node_id,
                    paths.iter().map(|path| path.2).collect_vec(),
                )
            }),
    );

    res
}

/// Calculate all mini-trees in bucket trie and bucket state according to the given salt keys and
/// bucket trie height information
///
/// # Parameters
///
/// * `salt_keys` - list of salt keys to be processed
/// * `buckets_top_level` - trie height information of each bucket, used to determine the trie
///   structure of the bucket
///
/// # Return value
///
/// Return a tuple containing two parts of information:
///
/// 1. `bucket_trie_nodes`: mini-tree information of bucket
/// - Each element is a triple `(parent_id, logic_id, children_indices)`
/// - `parent_id`: ID of the real connected parent node in Salt trie
/// - `logic_parent_id`: logical node ID used to call in TrieReader.children(), for example when
///   buckets_top_level is 3, the last level of bucket trie nodes are directly connected to the last
///   level of canonical(main) trie nodes. But its logic_parent_id is the node at level 3 in bucket
///   trie (bucket root is the node at level 0 in bucket trie)
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
/// - For each bucket, construct trie nodes of different levels according to its top_level
/// - top_level The range is 0--=4, indicating the level from which the bucket trie structure starts
/// - When top_level = 4, it means that the bucket does not have a bucket trie structure
/// - When top_level < 4, it is necessary to build bucket trie nodes from the bucket trie root node
///   to the 4th level
/// - All node IDs are calculated based on STARTING_NODE_ID and path information
#[allow(clippy::type_complexity)]
pub(crate) fn bucket_trie_parents_and_points(
    salt_keys: &[SaltKey],
    buckets_top_level: &FxHashMap<BucketId, u8>,
) -> (
    Vec<(NodeId, NodeId, Vec<u8>)>,
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
            let bucket_trie_top_level = buckets_top_level[&bucket_id];

            let slot_ids = keys.iter().map(|key| key.slot_id() as SlotId).collect_vec();

            // Extract all nodes path for layer 1 and layer 2 and layer3
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
                bucket_id,
                bucket_trie_top_level,
                &l1_paths,
                &l2_paths,
                &l3_paths,
                &l4_paths,
            )
        })
        .collect::<Vec<_>>();

    let bucket_state_nodes = salt_keys
        .par_chunk_by(|&x, &y| x.bucket_id() == y.bucket_id())
        .into_par_iter()
        .map(|keys| {
            let bucket_id = keys[0].bucket_id();
            let bucket_trie_top_level = buckets_top_level[&bucket_id];
            process_bucket_state_nodes(bucket_id, bucket_trie_top_level, keys)
        })
        .collect::<Vec<_>>();

    (bucket_trie_nodes, bucket_state_nodes)
}

/// Process trie nodes for a single bucket
fn process_bucket_trie_nodes(
    bucket_id: BucketId,
    bucket_trie_top_level: u8,
    l1_paths: &[u8],
    l2_paths: &[(u8, u8)],
    l3_paths: &[(u8, u8, u8)],
    l4_paths: &[(u8, u8, u8, u8)],
) -> Vec<(NodeId, NodeId, Vec<u8>)> {
    if bucket_trie_top_level == (SUB_TRIE_LEVELS - 1) as u8 {
        return vec![];
    }

    let mut nodes = Vec::new();
    let bucket_base = (bucket_id as u64) << BUCKET_SLOT_BITS;
    let bucket_node_base = bucket_id as u64 + STARTING_NODE_ID[3] as u64;

    // Process different levels of nodes
    match bucket_trie_top_level {
        3 => {
            // l0 and its children
            nodes.push((
                bucket_node_base,
                bucket_base + STARTING_NODE_ID[3] as u64,
                l4_paths.iter().map(|path| path.3).collect_vec(),
            ));
        }
        2 => {
            // l0 and its children
            nodes.push((
                bucket_node_base,
                bucket_base + STARTING_NODE_ID[2] as u64,
                l3_paths.iter().map(|path| path.2).collect_vec(),
            ));

            // l3 and its children
            nodes.extend(
                l4_paths
                    .chunk_by(|&x, &y| (x.0 == y.0) && (x.1 == y.1) && (x.2 == y.2))
                    .map(|chunk| {
                        let parent_id =
                            bucket_base + (chunk[0].2 as u64) + STARTING_NODE_ID[3] as u64;
                        (
                            parent_id,
                            parent_id,
                            chunk.iter().map(|path| path.3).collect_vec(),
                        )
                    }),
            );
        }
        1 => {
            // l0 and its children
            nodes.push((
                bucket_node_base,
                bucket_base + STARTING_NODE_ID[1] as u64,
                l2_paths.iter().map(|path| path.1).collect_vec(),
            ));

            // l2 and its children
            nodes.extend(
                l3_paths
                    .chunk_by(|&x, &y| (x.0 == y.0) && (x.1 == y.1))
                    .map(|chunk| {
                        let parent_id =
                            bucket_base + (chunk[0].1 as u64) + STARTING_NODE_ID[2] as u64;
                        (
                            parent_id,
                            parent_id,
                            chunk.iter().map(|path| path.2).collect_vec(),
                        )
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
                            + STARTING_NODE_ID[3] as u64;
                        (
                            parent_id,
                            parent_id,
                            chunk.iter().map(|path| path.3).collect_vec(),
                        )
                    }),
            );
        }
        0 => {
            // l0 and its children
            nodes.push((
                bucket_node_base,
                bucket_base + STARTING_NODE_ID[0] as u64,
                l1_paths.to_vec(),
            ));

            // l1 and its children
            nodes.extend(l2_paths.chunk_by(|&x, &y| x.0 == y.0).map(|chunk| {
                let parent_id = bucket_base + (chunk[0].0 as u64) + STARTING_NODE_ID[1] as u64;
                (
                    parent_id,
                    parent_id,
                    chunk.iter().map(|path| path.1).collect_vec(),
                )
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
                        (
                            parent_id,
                            parent_id,
                            chunk.iter().map(|path| path.2).collect_vec(),
                        )
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
                        (
                            parent_id,
                            parent_id,
                            chunk.iter().map(|path| path.3).collect_vec(),
                        )
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
    bucket_trie_top_level: u8,
    keys: &[SaltKey],
) -> (BucketId, Vec<(NodeId, Vec<u8>)>) {
    if bucket_trie_top_level == (SUB_TRIE_LEVELS - 1) as u8 {
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
            let subtrie_node_id = subtrie_node_id(&chunk[0]);
            let slot_ids = chunk
                .iter()
                .map(|key| (key.slot_id() & 0xFF) as u8)
                .collect_vec();
            (subtrie_node_id, slot_ids)
        })
        .collect_vec();

    (bucket_id, state_nodes)
}

/// Convert a bucket id to a path
/// bucket id's range is [0, 256^3), otherwise the function will panic
///
/// # Arguments
///
/// * `bucket_id` - The bucket id to convert
///
/// # Returns
///
/// The calculated path
pub const fn bucket_id_to_path(bucket_id: BucketId) -> [u8; TRIE_LEVELS - 1] {
    [
        ((bucket_id >> (TRIE_WIDTH_BITS * 2)) & 0xFF) as u8,
        ((bucket_id >> TRIE_WIDTH_BITS) & 0xFF) as u8,
        (bucket_id & 0xFF) as u8,
    ]
}

/// Convert a slot id to a sub trie node **full** path
/// slot id's range is [0, 256^5), otherwise the function will panic
///
/// # Arguments
///
/// * `slot` - The slot id to convert
///
/// # Returns
///
/// The calculated path
pub const fn slot_id_to_node_path(slot: SlotId) -> [u8; SUB_TRIE_LEVELS - 1] {
    [
        ((slot >> (TRIE_WIDTH_BITS * 4)) & 0xFF) as u8,
        ((slot >> (TRIE_WIDTH_BITS * 3)) & 0xFF) as u8,
        ((slot >> (TRIE_WIDTH_BITS * 2)) & 0xFF) as u8,
        ((slot >> TRIE_WIDTH_BITS) & 0xFF) as u8,
    ]
}

/// Get the child node of parent_id with child_index in the main trie
pub(crate) fn get_main_trie_child_node(parent_id: NodeId, point: u8) -> NodeId {
    let level = get_node_level(parent_id);

    point as NodeId
        + STARTING_NODE_ID[level + 1] as NodeId
        + ((parent_id - STARTING_NODE_ID[level] as NodeId) << TRIE_WIDTH_BITS)
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
            (0, 0, vec![8, 177, 255]),
            (9, 9, vec![3, 255]),
            (178, 178, vec![0, 255]),
            (256, 256, vec![7]),
            (2308, 2308, vec![0, 152, 255]),
            (2560, 2560, vec![152, 170]),
            (45569, 45569, vec![0, 255]),
            (45824, 45824, vec![0, 173, 255]),
            (65544, 65544, vec![7]),
        ];

        assert_eq!(
            parent_nodes, expected_parent_nodes,
            "Parent nodes do not match expected values"
        );

        // Test with a single bucket ID
        let single_bucket_id = vec![525056];
        let single_parent_nodes = main_trie_parents_and_points(&single_bucket_id);
        let expected_single_parent_nodes =
            vec![(0, 0, vec![8]), (9, 9, vec![3]), (2308, 2308, vec![0])];

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
