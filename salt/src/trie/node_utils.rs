//! Utilities for navigating and manipulating nodes in the SALT trie structure.
//!
//! This module provides core functionality for working with the hierarchical node
//! organization in SALT's authenticated data structure, which combines a main 256-ary
//! trie with dynamically-allocated bucket subtrees.
//!
//! # Architecture Overview
//!
//! SALT uses a two-tier trie structure:
//!
//! ```text
//! Main Trie (Levels 0-3):
//!     Level 0: Root node (single node)
//!     Level 1: 256 nodes (children of root)
//!     Level 2: 65,536 nodes (256² nodes)
//!     Level 3: 16,777,216 bucket roots (256³ nodes)
//!
//! Bucket Subtrees (Levels 0-4):
//!     Each bucket can expand into a 256-ary subtree
//!     Subtree depth depends on bucket capacity
//!     Leaf nodes represent 256-slot segments
//! ```
//!
//! # Node Identification Scheme
//!
//! Nodes are identified by 64-bit `NodeId` values encoding two components:
//!
//! - **Bits 0-23**: Bucket ID (0 for main trie nodes, 1-16777215 for subtree nodes)
//! - **Bits 24-63**: Local node number using BFS ordering within the trie
//!
//! ## BFS Numbering
//!
//! Nodes are numbered using breadth-first search (BFS) traversal:
//!
//! ```text
//! Level 0: [0]
//! Level 1: [1, 2, 3, ..., 256]
//! Level 2: [257, 258, ..., 65792]
//! Level 3: [65793, 65794, ..., 16843008]
//! Level 4: [16843009, 16843010, ..., 4311810304]
//! ```
//!
//! The starting node ID for each level is precomputed in `STARTING_NODE_ID`.
//!
//! # Vector Commitment Positions
//!
//! Each parent node maintains a 256-element vector commitment (VC) for its children.
//! Children are mapped to VC positions 0-255 based on their relative position within
//! their parent's child set.
//!
//! ## Example
//!
//! ```text
//! Parent at Level 1, Node 5:
//!   - First child: Node 257 + (4 * 256) = 1281 → VC position 0
//!   - Last child:  Node 257 + (4 * 256) + 255 = 1536 → VC position 255
//! ```
//!
//! # Bucket Organization
//!
//! The 16,777,216 buckets at level 3 of the main trie are divided into:
//!
//! - **Meta buckets** (0-65535): Store bucket metadata, fixed 256-slot capacity
//! - **Data buckets** (65536-16777215): Store key-value pairs, dynamic capacity
//!
//! ## Bucket Expansion
//!
//! When a bucket's capacity exceeds 256 slots, it expands into a subtree. The subtree
//! root node is **dynamically positioned** based on the bucket's capacity - it starts
//! at the deepest level and moves upward as capacity increases.
//!
//! ### Dynamic Root Positioning
//!
//! The subtree root's NodeId for a bucket is calculated as:
//! ```ignore
//! root_node_id = (bucket_id << 40) | STARTING_NODE_ID[subtree_root_level(capacity)]
//! ```
//!
//! As capacity grows, the root "climbs" the subtree hierarchy:
//!
//! ```text
//! Capacity ≤ 256 (2^8):
//!     Root at Level 4 (leaf level)
//!     NodeId = (bucket_id << 40) | 16843009
//!     No internal nodes needed - direct slot storage
//!
//! Capacity ≤ 65,536 (2^16):
//!     Root at Level 3
//!     NodeId = (bucket_id << 40) | 65793
//!     └─ Up to 256 Level 4 leaf nodes
//!
//! Capacity ≤ 16,777,216 (2^24):
//!     Root at Level 2
//!     NodeId = (bucket_id << 40) | 257
//!     ├─ Up to 256 Level 3 nodes
//!     └─ Up to 65,536 Level 4 leaf nodes
//!
//! Capacity ≤ 4,294,967,296 (2^32):
//!     Root at Level 1
//!     NodeId = (bucket_id << 40) | 1
//!     ├─ Up to 256 Level 2 nodes
//!     ├─ Up to 65,536 Level 3 nodes
//!     └─ Up to 16,777,216 Level 4 leaf nodes
//!
//! Capacity > 4,294,967,296:
//!     Root at Level 0
//!     NodeId = (bucket_id << 40) | 0
//!     Full 5-level subtree structure
//! ```
//!
//! ### Key Insights
//!
//! - The root node is always the **first node** at its level within the bucket's subtree namespace
//! - The `subtree_root_level()` function determines which level can accommodate the capacity
//! - The root NodeId changes as the bucket expands - it's not a fixed value
//! - All subtree nodes share the same bucket ID in their upper 24 bits
//!
//! # Key-to-Node Mapping
//!
//! SaltKeys encode both bucket ID and slot ID:
//!
//! ```text
//! SaltKey (64 bits):
//!   Bits 0-23: Bucket ID (24 bits)
//!   Bits 24-63:  Slot ID within bucket (40 bits)
//! ```
//!
//! For expanded buckets, slots map to subtree leaves:
//! - Slots 0-255 → Leaf 0
//! - Slots 256-511 → Leaf 1
//! - Slots 512-767 → Leaf 2
//! - And so on...
//!
//! # Module Functions
//!
//! ## Navigation Functions
//!
//! - [`vc_position_in_parent`]: Calculate a node's position (0-255) in parent's VC
//! - [`get_child_node`]: Navigate from parent to specific child by index
//! - [`get_parent_node`]: Navigate from child back to parent node
//!
//! ## Bucket Functions
//!
//! - [`bucket_root_node_id`]: Get the main trie node ID for a bucket
//! - [`subtree_root_level`]: Determine subtree depth needed for capacity
//!
//! ## Subtree Functions
//!
//! - [`subtree_leaf_for_key`]: Map a SaltKey to its containing subtree leaf
//! - [`subtree_leaf_start_key`]: Get the first SaltKey in a leaf's range
//!
//! # Usage Examples
//!
//! ## Navigating the Main Trie
//!
//! ```ignore
//! use salt::trie::node_utils::{get_child_node, get_parent_node, vc_position_in_parent};
//!
//! // Navigate from root to a specific path
//! let root = 0;
//! let child_at_idx_42 = get_child_node(&root, 42);  // Node at level 1, position 42
//! let grandchild = get_child_node(&child_at_idx_42, 100);  // Continue down
//!
//! // Find position in parent's vector commitment
//! let pos = vc_position_in_parent(&grandchild);  // Returns 100
//!
//! // Navigate back up
//! let parent = get_parent_node(&grandchild);  // Navigate back to level 1
//! ```
//!
//! ## Working with Buckets
//!
//! ```ignore
//! use salt::trie::node_utils::{bucket_root_node_id, subtree_leaf_for_key};
//! use salt::types::SaltKey;
//!
//! // Get the main trie node for bucket 100000
//! let bucket_100000_root = bucket_root_node_id(100000);
//!
//! // Map a key to its subtree leaf (for expanded buckets)
//! let key = SaltKey::from((100000, 1500));  // Bucket 100000, slot 1500
//! let leaf_node = subtree_leaf_for_key(&key);  // Leaf covering slots 1280-1535
//! ```
//!
//! # Related Modules
//!
//! - [`crate::constant`]: Defines trie dimensions and precomputed values
//! - [`crate::types`]: Core type definitions (NodeId, BucketId, SaltKey)
//! - [`crate::trie`]: Higher-level trie operations using these utilities

use crate::{
    constant::{
        BUCKET_SLOT_BITS, MAIN_TRIE_LEVELS, MAX_SUBTREE_LEVELS, MIN_BUCKET_SIZE_BITS,
        STARTING_NODE_ID, TRIE_WIDTH, TRIE_WIDTH_BITS,
    },
    get_local_number,
    types::{get_bfs_level, BucketId, NodeId, SaltKey},
};

/// Determines the position of a node within its parent's vector commitment.
///
/// Both the main trie and bucket subtrees use complete 256-ary tries as their
/// cryptographic structure. Each parent node maintains a vector commitment (VC)
/// with exactly 256 positions (TRIE_WIDTH = 256), one for each possible child.
/// This function calculates which position (0-255) a given node occupies in its
/// parent's vector commitment.
///
/// # Arguments
/// * `node_id` - The unique identifier of the node
///
/// # Returns
/// The position (0-255) within the parent's 256-element vector commitment
pub(crate) fn vc_position_in_parent(node_id: &NodeId) -> usize {
    let local_number = get_local_number(*node_id);
    let trie_level = get_bfs_level(local_number);

    // Calculate relative position from the start of this level
    let relative_pos = local_number as usize - STARTING_NODE_ID[trie_level];
    relative_pos % TRIE_WIDTH
}

/// Computes the NodeId of a specific child given its parent and child index.
///
/// This function navigates from a parent node to one of its 256 children in the
/// SALT trie. It handles both main trie and bucket subtree nodes by preserving
/// the bucket ID and calculating the child's position using BFS numbering.
///
/// # Arguments
/// * `parent` - The NodeId of the parent node
/// * `child_idx` - The child index (0-255) to navigate to
///
/// # Returns
/// The NodeId of the specified child node
pub fn get_child_node(parent: &NodeId, child_idx: usize) -> NodeId {
    // Extract the node position (lower 40 bits) and bucket ID (upper 24 bits)
    let local_node_id = get_local_number(*parent);
    let bucket_id = *parent - local_node_id;

    // Determine which level the parent is on
    let level = get_bfs_level(local_node_id);

    // Calculate parent's relative position from the start of its level
    let parent_relative_position = local_node_id - STARTING_NODE_ID[level] as NodeId;

    // Get the starting position for the child level
    let child_level_start = STARTING_NODE_ID[level + 1] as NodeId;

    // Multiply parent's position by 256 then add the child level start and the
    // specific child index
    bucket_id
        + child_level_start
        + (parent_relative_position << TRIE_WIDTH_BITS)
        + child_idx as NodeId
}

/// Computes the parent NodeId for a given node in the canonical SALT trie.
///
/// This function performs the inverse operation of `get_child_node`, navigating
/// upward from a child to its parent using BFS numbering. It works by reversing
/// the child calculation: dividing the relative position by 256 to find which
/// parent slot this child belongs to.
///
/// # Arguments
/// * `node_id` - The NodeId of the child node
///
/// # Returns
/// The NodeId of the parent node at level-1
///
/// # Panics
/// Implicitly panics if the node is the root (level 0) since root has no parent
pub(crate) fn get_parent_node(node_id: &NodeId) -> NodeId {
    // Extract the node position (lower 40 bits) and bucket ID (upper 24 bits)
    let local_node_id = get_local_number(*node_id);
    let bucket_id = *node_id - local_node_id;

    // Determine which level this node is on
    let level = get_bfs_level(local_node_id);

    // Calculate relative position from the start of current level
    let relative_position = local_node_id as usize - STARTING_NODE_ID[level];

    // Divide by 256 (right-shift by 8) to get parent's relative position
    // Each parent has 256 children, so child positions 0-255 → parent 0,
    // positions 256-511 → parent 1, etc.
    let parent_relative_position = relative_position >> TRIE_WIDTH_BITS;

    // Add parent level's starting position to get absolute parent ID
    // and preserve the bucket ID for subtree nodes
    bucket_id + (parent_relative_position + STARTING_NODE_ID[level - 1]) as NodeId
}

/// Maps a bucket ID to its subtree root node in the main trie.
///
/// This function calculates the NodeId of a bucket's root node at the main trie level.
/// It works for both expanded and unexpanded buckets - the bucket root is always at
/// the same position regardless of whether the bucket has been expanded into a subtree.
///
/// # Arguments
/// * `bucket_id` - The bucket identifier to locate in the main trie
///
/// # Returns
/// The NodeId of the bucket's root node at the main trie level (level 3)
pub(crate) fn bucket_root_node_id(bucket_id: BucketId) -> NodeId {
    bucket_id as NodeId + STARTING_NODE_ID[MAIN_TRIE_LEVELS - 1] as NodeId
}

/// Converts a SaltKey to the NodeId of its corresponding subtree leaf node.
///
/// This function maps data keys to their containing leaf nodes within bucket subtrees.
/// It ONLY works for keys belonging to expanded buckets that have subtree structures.
/// The returned leaf node is always at the deepest subtree level and represents
/// a segment of 256 consecutive slots within the bucket.
///
/// # Prerequisites
/// The bucket containing this key must be expanded (have a subtree structure).
/// This function should not be used for keys in unexpanded buckets.
///
/// # Arguments
/// * `key` - The SaltKey to locate within the subtree structure
///
/// # Returns
/// The NodeId of the subtree leaf node containing this key's 256-slot segment
pub(crate) fn subtree_leaf_for_key(key: &SaltKey) -> NodeId {
    // bucket_id (24 bits) | starting_node_at_L4 + slot_id/256 (40 bits)
    ((key.bucket_id() as u64) << BUCKET_SLOT_BITS)
        + (key.slot_id() >> MIN_BUCKET_SIZE_BITS)
        + STARTING_NODE_ID[MAX_SUBTREE_LEVELS - 1] as u64
}

/// Returns the starting SaltKey for a subtree leaf node's bucket segment.
///
/// This function is the inverse of `subtree_leaf_for_key()`. Given a subtree leaf
/// NodeId, it calculates which SaltKey represents the first slot in the 256-slot
/// range that this leaf node covers.
///
/// **IMPORTANT**: This function ONLY works with subtree leaf nodes at level 4
/// (the deepest subtree level). It will not produce correct results for other
/// types of nodes.
///
/// # Arguments
/// * `node_id` - A subtree leaf NodeId (must be from level 4)
///
/// # Returns
/// The SaltKey representing the first slot in the 256-slot segment covered by
/// this leaf
pub(crate) fn subtree_leaf_start_key(node_id: &NodeId) -> SaltKey {
    // Extract node position (lower 40 bits) and bucket ID (upper 24 bits)
    let local_node_number = get_local_number(*node_id);
    let bucket_id = *node_id - local_node_number;

    // Calculate relative position within the deepest subtree level
    let relative_position = local_node_number - STARTING_NODE_ID[MAX_SUBTREE_LEVELS - 1] as u64;

    // Convert back to slot ID by multiplying by 256
    // Each subtree node represents a range of 256 consecutive slots
    let slot_id = relative_position << MIN_BUCKET_SIZE_BITS;

    // Combine bucket and slot components into final SaltKey
    SaltKey(bucket_id + slot_id)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Tests the vc_position_in_parent function for various node types and positions.
    ///
    /// Verifies that the function correctly calculates vector commitment positions (0-255)
    /// for both main trie nodes and bucket subtree nodes, ensuring proper modulo arithmetic.
    #[test]
    fn test_vc_position_in_parent() {
        // Test cases: (node_id, expected_position, description)
        let test_cases = [
            // Main trie level 1 nodes (children of root at level 0)
            (1, 0, "First child of root"),
            (128, 127, "Middle child of root"),
            (256, 255, "Last child of root"),
            // Main trie level 2 nodes
            (257, 0, "First node at level 2"),
            (257 + 255, 255, "256th node at level 2"),
            (257 + 256, 0, "257th node wraps to position 0"),
            (257 + 511, 255, "512nd node at level 2"),
            (257 + 512, 0, "513rd node wraps to position 0"),
            // Main trie level 3 nodes (bucket roots)
            (65793, 0, "First bucket root (bucket 0)"),
            (65793 + 255, 255, "256th bucket root"),
            (65793 + 256, 0, "257th bucket root wraps to 0"),
            // Subtree nodes in bucket 100000
            (
                (100000u64 << BUCKET_SLOT_BITS) | 1,
                0,
                "First subtree node in bucket 100000",
            ),
            (
                (100000u64 << BUCKET_SLOT_BITS) | 256,
                255,
                "Last child of first subtree parent",
            ),
            (
                (100000u64 << BUCKET_SLOT_BITS) | 257,
                0,
                "First child of second subtree parent",
            ),
            (
                (100000u64 << BUCKET_SLOT_BITS) | 512,
                255,
                "Complex subtree position",
            ),
            // Edge case: maximum bucket ID
            (
                (16777215u64 << BUCKET_SLOT_BITS) | 1000,
                231,
                "Max bucket ID with position 1000 (1000-769=231)",
            ),
        ];

        for (node_id, expected, description) in test_cases {
            let result = vc_position_in_parent(&node_id);
            assert_eq!(
                result, expected,
                "Failed for {}: node_id={}, expected={}, got={}",
                description, node_id, expected, result
            );

            // Verify position is always in valid range
            assert!(
                result < TRIE_WIDTH,
                "Position {} should be < {} for {}",
                result,
                TRIE_WIDTH,
                description
            );
        }
    }

    /// Tests the get_child_node function for various parent-child navigation
    /// scenarios.
    ///
    /// Verifies correct child NodeId calculation across different trie levels
    /// and child indices.
    #[test]
    fn test_get_child_node() {
        // Test cases: (parent_id, child_idx, expected_child_id, description)
        let test_cases = [
            // Level 0 (root) to level 1
            (0, 0, 1, "Root to first child"),
            (0, 127, 128, "Root to middle child"),
            (0, 255, 256, "Root to last child"),
            // Level 1 to level 2
            (1, 0, 257, "First L1 node to first child"),
            (128, 0, 257 + 127 * 256, "Middle L1 node to first child"),
            // Bucket subtree navigation
            (
                (100u64 << BUCKET_SLOT_BITS) | 1,
                0,
                (100u64 << BUCKET_SLOT_BITS) | 257,
                "Bucket subtree navigation",
            ),
        ];

        for (parent, child_idx, expected, description) in test_cases {
            let result = get_child_node(&parent, child_idx);
            assert_eq!(result, expected, "Failed: {}", description);
        }
    }

    /// Tests the get_parent_node function for various child-parent navigation
    /// scenarios.
    ///
    /// Verifies correct parent NodeId calculation and tests the inverse relationship
    /// with get_child_node for both main trie and subtree nodes.
    #[test]
    fn test_get_parent_node() {
        // Test direct parent calculation for both main trie and subtree nodes
        let bucket_id = 100000u64;
        let test_cases = [
            // Main trie: Level 1 to level 0 (root)
            (1, 0, "First child back to root"),
            (128, 0, "Middle child back to root"),
            (256, 0, "Last child back to root"),
            // Main trie: Level 2 to level 1
            (257, 1, "First L2 node to parent"),
            (257 + 256, 2, "Second group L2 node to parent"),
            (257 + 127 * 256, 128, "Complex L2 node to parent"),
            // Subtree: Level 2 to level 1
            (
                (bucket_id << BUCKET_SLOT_BITS) | 257,
                (bucket_id << BUCKET_SLOT_BITS) | 1,
                "Subtree L2 first node to parent",
            ),
            (
                (bucket_id << BUCKET_SLOT_BITS) | (257 + 256),
                (bucket_id << BUCKET_SLOT_BITS) | 2,
                "Subtree L2 second group to parent",
            ),
            // Subtree: Level 3 to level 2
            (
                (bucket_id << BUCKET_SLOT_BITS) | 65793,
                (bucket_id << BUCKET_SLOT_BITS) | 257,
                "Subtree L3 first node to parent",
            ),
            (
                (bucket_id << BUCKET_SLOT_BITS) | (65793 + 1024),
                (bucket_id << BUCKET_SLOT_BITS) | (257 + 4),
                "Subtree L3 node to parent (1024/256=4)",
            ),
            // Subtree: Level 4 to level 3
            (
                (bucket_id << BUCKET_SLOT_BITS) | 16843009,
                (bucket_id << BUCKET_SLOT_BITS) | 65793,
                "Subtree L4 first node to parent",
            ),
        ];

        for (child, expected_parent, description) in test_cases {
            let result = get_parent_node(&child);
            assert_eq!(result, expected_parent, "Failed: {}", description);
        }

        // Test inverse relationship: parent -> child -> parent for both main trie and subtree
        let test_parents = [
            // Main trie parents
            0,
            1,
            128,
            // Subtree parents (bucket 100000)
            (bucket_id << BUCKET_SLOT_BITS) | 1,     // Level 1
            (bucket_id << BUCKET_SLOT_BITS) | 257,   // Level 2
            (bucket_id << BUCKET_SLOT_BITS) | 65793, // Level 3
        ];

        for parent in test_parents {
            for child_idx in [0, 127, 255] {
                let child = get_child_node(&parent, child_idx);
                let recovered_parent = get_parent_node(&child);
                assert_eq!(
                    recovered_parent, parent,
                    "Inverse relationship failed: parent={:#x}, child_idx={}",
                    parent, child_idx
                );
            }
        }
    }

    /// Tests the bucket_root_node_id function for various bucket types and IDs.
    ///
    /// Verifies that bucket IDs are correctly mapped to their root nodes at the
    /// main trie level (level 3).
    #[test]
    fn test_bucket_root_node_id() {
        let starting_l3_node = STARTING_NODE_ID[MAIN_TRIE_LEVELS - 1];
        let test_cases = [
            (0, starting_l3_node, "First bucket"),
            (100, starting_l3_node + 100, "Bucket 100"),
            (65535, starting_l3_node + 65535, "Last meta bucket"),
            (65536, starting_l3_node + 65536, "First data bucket"),
            (16777215, starting_l3_node + 16777215, "Max bucket ID"),
        ];

        for (bucket_id, expected, description) in test_cases {
            let result = bucket_root_node_id(bucket_id);
            assert_eq!(
                result, expected as NodeId,
                "Failed for {}: bucket_id={}, expected={}, got={}",
                description, bucket_id, expected, result
            );
        }
    }

    /// Tests the subtree_leaf_for_key function for various key patterns.
    ///
    /// Verifies that SaltKeys are correctly mapped to their subtree leaf nodes
    /// at the deepest subtree level (level 4).
    #[test]
    fn test_subtree_leaf_for_key() {
        let starting_l4_node = STARTING_NODE_ID[MAX_SUBTREE_LEVELS - 1] as u64;

        let test_cases = [
            (
                (0, 0),
                (0u64 << BUCKET_SLOT_BITS) + 0 + starting_l4_node,
                "Bucket 0, slot 0",
            ),
            (
                (0, 255),
                (0u64 << BUCKET_SLOT_BITS) + 0 + starting_l4_node,
                "Bucket 0, slots 0-255 same leaf",
            ),
            (
                (0, 256),
                (0u64 << BUCKET_SLOT_BITS) + 1 + starting_l4_node,
                "Bucket 0, slots 256-511",
            ),
            (
                (100, 1024),
                (100u64 << BUCKET_SLOT_BITS) + 4 + starting_l4_node,
                "Bucket 100, segment 4",
            ),
            (
                (16777215, 512),
                (16777215u64 << BUCKET_SLOT_BITS) + 2 + starting_l4_node,
                "Max bucket, segment 2",
            ),
        ];

        for ((bucket_id, slot_id), expected, description) in test_cases {
            let key = SaltKey::from((bucket_id, slot_id));
            let result = subtree_leaf_for_key(&key);
            assert_eq!(
                result, expected,
                "Failed for {}: key=({}, {}), expected={}, got={}",
                description, bucket_id, slot_id, expected, result
            );
        }
    }

    /// Tests the subtree_leaf_start_key function's inverse relationship with subtree_leaf_for_key.
    #[test]
    fn test_subtree_leaf_start_key() {
        // Test cases: (bucket_id, slot_id)
        let cases = [
            (0, 0),
            (0, 255),
            (0, 256),
            (0, 511),
            (0, 512),
            (100, 1024),
            (100, 1279),
            (100, 1280),
            (16777215, 0),
            (16777215, 65535),
        ];

        for (bucket_id, slot_id) in cases {
            let key = SaltKey::from((bucket_id, slot_id));
            let leaf_node = subtree_leaf_for_key(&key);
            let start_key = subtree_leaf_start_key(&leaf_node);

            // Start key should be the first slot in the 256-slot range
            let expected_start_slot = (slot_id / 256) * 256;
            assert_eq!(start_key, SaltKey::from((bucket_id, expected_start_slot)));
        }
    }
}
