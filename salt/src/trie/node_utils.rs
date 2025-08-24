//! Utilities for working with NodeId in the SALT trie structure.
//!
//! This module provides functions for:
//! - Converting between different node representations
//! - Navigating the trie hierarchy (parent/child relationships)
//! - Mapping between SaltKeys and NodeIds
//! - Determining subtrie levels and structure

use crate::{
    constant::{
        BUCKET_SLOT_BITS, BUCKET_SLOT_ID_MASK, MAIN_TRIE_LEVELS, MAX_SUBTREE_LEVELS,
        MIN_BUCKET_SIZE, MIN_BUCKET_SIZE_BITS, STARTING_NODE_ID, TRIE_WIDTH, TRIE_WIDTH_BITS,
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
/// * `level` - The level where the child node resides
///
/// # Returns
/// The NodeId of the parent node at level-1
///
/// # Panics
/// Implicitly panics if level is 0 (root has no parent) due to underflow
pub(crate) fn get_parent_node(node_id: &NodeId, level: usize) -> NodeId {
    // Calculate relative position from the start of current level
    let relative_position = *node_id as usize - STARTING_NODE_ID[level];

    // Divide by 256 (right-shift by 8) to get parent's relative position
    // Each parent has 256 children, so child positions 0-255 → parent 0,
    // positions 256-511 → parent 1, etc.
    let parent_relative_position = relative_position >> TRIE_WIDTH_BITS;

    // Add parent level's starting position to get absolute parent ID
    (parent_relative_position + STARTING_NODE_ID[level - 1]) as NodeId
}

/// Computes the parent NodeId for a node within a bucket's subtrie structure.
///
/// Unlike `get_parent_id` which works on the canonical trie, this function handles
/// navigation within bucket subtries. Bucket subtries use a different numbering
/// scheme where nodes are organized to optimize storage and access patterns for
/// key-value pairs within individual buckets.
///
/// # Subtrie Structure
/// Each bucket can have its own subtrie with up to 5 levels (SUB_TRIE_LEVELS).
/// The subtrie's depth depends on the bucket's capacity:
/// - Level 4: 256 slots (MIN_BUCKET_SIZE)
/// - Level 3: 65,536 slots
/// - Level 2: 16,777,216 slots
/// - Level 1: 4,294,967,296 slots
///
/// # Arguments
/// * `id` - The NodeId of the child node in the subtrie
/// * `level` - The subtrie level of the child node (1..=4)
///
/// # Returns
/// The NodeId of the parent node within the same bucket's subtrie
///
/// # Example
/// // For a node in bucket 100 at subtrie level 4
/// // Parent will be at level 3 within the same bucket
/// let child_id = subtree_leaf_for_key(&SaltKey::from((100, 42)));
/// let parent_id = subtrie_parent_id(&child_id, 4);
pub(crate) fn subtrie_parent_id(id: &NodeId, level: usize) -> NodeId {
    // FIXME: merge with get_parent_node?
    // Extract the node position (lower 40 bits) and bucket ID (upper 24 bits)
    let node_id = *id & BUCKET_SLOT_ID_MASK;
    let bucket_id = *id - node_id;

    // Calculate parent within the subtrie structure:
    bucket_id // Preserve bucket context
        + STARTING_NODE_ID[level - 1] as NodeId // Parent level's base position
        + ((node_id - STARTING_NODE_ID[level] as NodeId) >> MIN_BUCKET_SIZE_BITS)
    // Parent's relative position
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

/// Determines the top (shallowest) level of a bucket's subtrie based on its capacity.
///
/// Different bucket capacities require different subtrie depths to efficiently
/// organize their slots. This function calculates the minimal subtrie depth needed
/// to accommodate the given capacity.
///
/// # Subtrie Level Mapping
/// ```text
/// Level 0: Root (capacity = 1)              [root:0]
/// Level 1: Small (capacity ≤ 256)          [0] [1] ... [256]
/// Level 2: Medium (capacity ≤ 65,536)      [0]...[256] [257]...[65536]
/// Level 3: Large (capacity ≤ 16,777,216)   [0]...[65536] [65537]...[16777216]
/// Level 4: Extra Large (capacity ≤ 2^32)   [0]...[16777216] [16777217]...[2^32]
/// ```
///
/// # Algorithm
/// Start from the deepest level (4) and work upward, dividing capacity by 256
/// at each step. When capacity ≤ 256, we've found the appropriate top level.
///
/// # Arguments
/// * `capacity` - The total number of slots the bucket needs to accommodate
///
/// # Returns
/// The subtrie level (0-4) that should serve as the root for this capacity
///
/// # Example
/// assert_eq!(sub_trie_top_level(256), 4);     // Minimal subtrie
/// assert_eq!(sub_trie_top_level(1024), 3);    // Needs one more level
/// assert_eq!(sub_trie_top_level(65536), 2);   // Needs two more levels
pub(crate) fn sub_trie_top_level(mut capacity: u64) -> usize {
    // Start from the deepest possible level
    let mut level = MAX_SUBTREE_LEVELS - 1;

    // Work upward until capacity fits in a single level
    // Each level up can handle 256x more slots
    while capacity > MIN_BUCKET_SIZE as u64 {
        level -= 1; // Move up one level
        capacity >>= MIN_BUCKET_SIZE_BITS; // Divide capacity by 256
    }

    level
}

/// Converts a subtrie NodeId back to the starting SaltKey of its slot range.
///
/// This function performs the inverse operation of `subtree_leaf_for_key`, taking a NodeId
/// from a bucket's subtrie and calculating which SaltKey range it represents.
/// Each subtrie leaf node covers a range of 256 consecutive slots.
///
/// # Prerequisites
/// The input `node_id` must be a result from `subtree_leaf_for_key()` or equivalent,
/// representing a valid node in a bucket's subtrie structure.
///
/// # Algorithm
/// 1. Extract bucket ID (upper 24 bits) and node position (lower 40 bits)
/// 2. Calculate relative position within the deepest subtrie level
/// 3. Multiply by 256 to get the starting slot ID for this node's range
/// 4. Combine bucket ID and slot ID to form the SaltKey
///
/// # Arguments
/// * `id` - A NodeId from a bucket subtrie (typically from `subtree_leaf_for_key()`)
///
/// # Returns
/// The SaltKey representing the first slot in the range covered by this node
///
/// # Example
/// // Node covering slots 1024-1279 in bucket 100
/// let node_id = subtree_leaf_for_key(&SaltKey::from((100, 1024)));
/// let start_key = subtrie_salt_key_start(&node_id);
/// assert_eq!(start_key, SaltKey::from((100, 1024))); // First slot of the range
pub(crate) fn subtrie_salt_key_start(id: &NodeId) -> SaltKey {
    // Extract node position (lower 40 bits) and bucket ID (upper 24 bits)
    let node_id = *id & BUCKET_SLOT_ID_MASK;
    let bucket_id = *id - node_id;

    // Calculate relative position within the deepest subtrie level
    let relative_position = node_id - STARTING_NODE_ID[MAX_SUBTREE_LEVELS - 1] as u64;

    // Convert back to slot ID by multiplying by 256
    // Each subtrie node represents a range of 256 consecutive slots
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
    /// with get_child_node.
    #[test]
    fn test_get_parent_node() {
        // Test cases: (child_id, level, expected_parent_id, description)
        let test_cases = [
            // Level 1 to level 0 (root)
            (1, 1, 0, "First child back to root"),
            (128, 1, 0, "Middle child back to root"),
            (256, 1, 0, "Last child back to root"),
            // Level 2 to level 1
            (257, 2, 1, "First L2 node to parent"),
            (257 + 256, 2, 2, "Second group L2 node to parent"),
            (257 + 127 * 256, 2, 128, "Complex L2 node to parent"),
        ];

        for (child, level, expected_parent, description) in test_cases {
            let result = get_parent_node(&child, level);
            assert_eq!(result, expected_parent, "Failed: {}", description);
        }

        // Test inverse relationship: parent -> child -> parent
        let test_parents = [0, 1, 128];
        for parent in test_parents {
            for child_idx in [0, 127, 255] {
                let child = get_child_node(&parent, child_idx);
                let child_level = get_bfs_level(get_local_number(child));
                let recovered_parent = get_parent_node(&child, child_level);
                assert_eq!(
                    recovered_parent, parent,
                    "Inverse relationship failed: parent={}, child_idx={}",
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
}
