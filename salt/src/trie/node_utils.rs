//! Utilities for working with NodeId in the SALT trie structure.
//!
//! This module provides functions for:
//! - Converting between different node representations
//! - Navigating the trie hierarchy (parent/child relationships)
//! - Mapping between SaltKeys and NodeIds
//! - Determining subtrie levels and structure

use crate::{
    constant::{
        BUCKET_SLOT_BITS, BUCKET_SLOT_ID_MASK, MAX_SUBTREE_LEVELS, MIN_BUCKET_SIZE,
        MIN_BUCKET_SIZE_BITS, STARTING_NODE_ID, TRIE_WIDTH, TRIE_WIDTH_BITS,
    },
    get_local_number,
    types::{get_bfs_level, NodeId, SaltKey},
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
/// This function navigates from a parent node to one of its 256 children in the SALT trie.
/// It handles both main trie nodes and bucket subtrie nodes by preserving the bucket ID
/// and calculating the child's position using BFS numbering.
///
/// # NodeId Structure
/// ```text
/// NodeId = [24-bit bucket_id][40-bit node_position]
/// ```
///
/// # Algorithm
/// 1. Extract bucket ID (upper 24 bits) and node position (lower 40 bits)
/// 2. Calculate parent's relative position within its level
/// 3. Left-shift by 8 bits (TRIE_WIDTH_BITS) to account for 256 children per node
/// 4. Add the starting position of the child level
/// 5. Add the specific child index (0-255)
/// 6. Combine with bucket ID
///
/// # Arguments
/// * `parent_id` - The NodeId of the parent node
/// * `child_idx` - The child index (0-255) to navigate to
///
/// # Returns
/// The NodeId of the specified child node
///
/// # Panics
/// Panics if the parent's level is >= SUB_TRIE_LEVELS (invalid for child calculation)
///
/// # Example
/// // Navigate from root (0) to its 42nd child
/// let child = get_child_node(&0, 42);
/// assert_eq!(child, 43); // Root children start at ID 1
pub fn get_child_node(parent_id: &NodeId, child_idx: usize) -> NodeId {
    // Split NodeId into bucket ID (upper 24 bits) and node position (lower 40 bits)
    let node_id = *parent_id & BUCKET_SLOT_ID_MASK;
    let bucket_id = *parent_id - node_id;

    // Determine which level the parent is on
    let level = get_bfs_level(node_id);
    assert!(level < MAX_SUBTREE_LEVELS);

    // Calculate child NodeId using BFS numbering:
    bucket_id // Preserve the bucket context
        + ((node_id - STARTING_NODE_ID[level] as NodeId) << TRIE_WIDTH_BITS) // Parent's relative position * 256
        + STARTING_NODE_ID[level + 1] as NodeId // Child level starting position
        + child_idx as NodeId // Specific child index (0-255)
}

/// Computes the parent NodeId for a given node in the canonical SALT trie.
///
/// This function performs the inverse operation of `get_child_node`, navigating
/// upward from a child to its parent using BFS numbering. It works by reversing
/// the child calculation: dividing the relative position by 256 to find which
/// parent slot this child belongs to.
///
/// # Algorithm
/// 1. Calculate the node's relative position within its level
/// 2. Right-shift by 8 bits (divide by 256) to determine parent's relative position
/// 3. Add the parent level's starting position
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
///
/// # Example
/// // Node 300 at level 2 (relative position 43 = 300-257)
/// // Parent position = 43 >> 8 = 0 (first parent at level 1)
/// // Parent ID = 0 + STARTING_NODE_ID[1] = 0 + 1 = 1
/// let parent = get_parent_id(&300, 2);
/// assert_eq!(parent, 1);
pub(crate) fn get_parent_id(node_id: &NodeId, level: usize) -> NodeId {
    // Calculate relative position from the start of current level
    let relative_position = *node_id as usize - STARTING_NODE_ID[level];

    // Divide by 256 (right-shift by 8) to get parent's relative position
    // Each parent has 256 children, so child positions 0-255 → parent 0,
    // positions 256-511 → parent 1, etc.
    let parent_relative_position = relative_position >> MIN_BUCKET_SIZE_BITS;

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
/// let child_id = subtrie_node_id(&SaltKey::from((100, 42)));
/// let parent_id = subtrie_parent_id(&child_id, 4);
pub(crate) fn subtrie_parent_id(id: &NodeId, level: usize) -> NodeId {
    // Extract the node position (lower 40 bits) and bucket ID (upper 24 bits)
    let node_id = *id & BUCKET_SLOT_ID_MASK;
    let bucket_id = *id - node_id;

    // Calculate parent within the subtrie structure:
    bucket_id // Preserve bucket context
        + STARTING_NODE_ID[level - 1] as NodeId // Parent level's base position
        + ((node_id - STARTING_NODE_ID[level] as NodeId) >> MIN_BUCKET_SIZE_BITS)
    // Parent's relative position
}

/// Converts a SaltKey to its corresponding NodeId in the bucket's subtrie.
///
/// This function maps data keys to their storage locations in the trie structure.
/// SaltKeys encode both bucket identification and slot position, which this function
/// translates into a NodeId that can be used to navigate the subtrie.
///
/// # SaltKey Structure
/// ```text
/// SaltKey (64-bit) = [24-bit bucket_id][40-bit slot_id]
/// ```
///
/// # Algorithm
/// 1. Extract bucket ID (upper 24 bits) and shift left by 40 bits
/// 2. Extract slot ID (lower 40 bits) and divide by 256 to get node position
/// 3. Add the starting position of the deepest subtrie level
/// 4. Combine to form the final NodeId
///
/// # Arguments
/// * `key` - The SaltKey to convert to a NodeId
///
/// # Returns
/// The NodeId representing this key's location in the bucket subtrie
///
/// # Example
/// let key = SaltKey::from((100, 1024)); // Bucket 100, slot 1024
/// let node_id = subtrie_node_id(&key);
/// // node_id encodes: bucket 100, position 4 (1024 >> 8), at deepest level
pub(crate) fn subtrie_node_id(key: &SaltKey) -> NodeId {
    // Extract bucket ID (24 bits) and place in upper portion of NodeId
    let bucket_component = (key.bucket_id() as NodeId) << BUCKET_SLOT_BITS;

    // Extract slot ID and convert to node position by dividing by 256
    // This maps slot ranges to subtrie leaf nodes: slots 0-255 → node 0, etc.
    let node_position = (key.slot_id() >> MIN_BUCKET_SIZE_BITS) as NodeId;

    // Start from the deepest subtrie level and add relative position
    let base_position = STARTING_NODE_ID[MAX_SUBTREE_LEVELS - 1] as NodeId;

    bucket_component + node_position + base_position
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
/// This function performs the inverse operation of `subtrie_node_id`, taking a NodeId
/// from a bucket's subtrie and calculating which SaltKey range it represents.
/// Each subtrie leaf node covers a range of 256 consecutive slots.
///
/// # Prerequisites
/// The input `node_id` must be a result from `subtrie_node_id()` or equivalent,
/// representing a valid node in a bucket's subtrie structure.
///
/// # Algorithm
/// 1. Extract bucket ID (upper 24 bits) and node position (lower 40 bits)
/// 2. Calculate relative position within the deepest subtrie level
/// 3. Multiply by 256 to get the starting slot ID for this node's range
/// 4. Combine bucket ID and slot ID to form the SaltKey
///
/// # Arguments
/// * `id` - A NodeId from a bucket subtrie (typically from `subtrie_node_id()`)
///
/// # Returns
/// The SaltKey representing the first slot in the range covered by this node
///
/// # Example
/// // Node covering slots 1024-1279 in bucket 100
/// let node_id = subtrie_node_id(&SaltKey::from((100, 1024)));
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
}
