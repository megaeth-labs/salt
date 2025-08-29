//! # SALT Proof Shape Analysis
//!
//! This module provides utilities for analyzing the hierarchical structure of SALT's dual-tier
//! addressing system to determine the minimal set of parent-child relationships required for
//! cryptographic proof generation.
//!
//! ## Architecture Overview
//!
//! SALT uses a two-tier trie structure:
//! - **Main Trie**: 4-level, 256-ary tree with 16,777,216 leaf nodes (buckets)  
//! - **Bucket Subtrees**: Dynamic trees within buckets that can expand from 1-5 levels

use rayon::prelude::*;
use rustc_hash::FxHashMap;
use std::collections::{BTreeMap, BTreeSet};

use crate::{
    constant::{BUCKET_SLOT_BITS, MAX_SUBTREE_LEVELS, STARTING_NODE_ID},
    trie::node_utils::{
        bucket_root_node_id, get_parent_node, subtree_leaf_for_key, vc_position_in_parent,
    },
    BucketId, NodeId, SaltKey,
};

/// Builds the complete parent-child relationship map needed for SALT proof generation.
///
/// This function analyzes the hierarchical structure of SALT's two-tier trie system to collect
/// all parent nodes and their corresponding child positions that must be included in
/// cryptographic proofs. It handles both the static main trie and dynamic bucket subtrees.
///
/// # Algorithm Overview
///
/// For each `SaltKey`, the function performs four phases:
/// 1. **Main Trie Traversal**: Walks from bucket root to state root, recording path
/// 2. **Bucket Tree Traversal**: Handles internal nodes in expanded buckets (>256 slots)
/// 3. **Bridge Connection**: Links bucket trees to main trie for expanded buckets (>256 slots)
/// 4. **Slot Position**: Records direct parent-child relationship for key-value pairs
///
/// # Arguments
///
/// * `salt_keys` - Array of keys to analyze for proof generation
/// * `levels` - Mapping from bucket IDs to their tree depth levels (1-5)
///   - Level 1: Single-segment bucket (≤256 slots)
///   - Level 2+: Multi-segment bucket with internal tree structure
///
/// # Returns
///
/// A tuple of two mappings:
/// 1. Internal nodes mapping from parent node IDs to sets of child positions for structural nodes
/// 2. Key-Value Slot Position nodes mapping for actual data slot positions
///    This structure enables minimal proof generation by identifying exactly which
///    child commitments are needed at each level for verification.
pub(crate) fn parents_and_points(
    salt_keys: &[SaltKey],
    levels: &FxHashMap<BucketId, u8>,
) -> (
    BTreeMap<NodeId, BTreeSet<usize>>,
    BTreeMap<NodeId, BTreeSet<usize>>,
) {
    salt_keys
        .par_iter()
        .map(|salt_key| {
            let mut internal_nodes: BTreeMap<NodeId, BTreeSet<usize>> = BTreeMap::new();
            let mut slot_position_nodes: BTreeMap<NodeId, BTreeSet<usize>> = BTreeMap::new();
            let bucket_id = salt_key.bucket_id();
            let level = levels[&bucket_id];

            // ============================================================================
            // Phase 1: Main Trie Traversal
            // ============================================================================
            // Walk from the bucket root up to the main trie root (node 0), recording
            // each parent-child relationship. This captures the path through the fixed
            // 4-level main trie structure that leads to this bucket.
            let mut node = bucket_root_node_id(salt_key.bucket_id());
            while node != 0 {
                let parent_node = get_parent_node(&node);
                // Record that this parent needs to prove the child at this position
                internal_nodes
                    .entry(parent_node)
                    .or_default()
                    .insert(vc_position_in_parent(&node));

                node = parent_node;
            }

            // ============================================================================
            // Phase 2: Bucket Tree Traversal
            // ============================================================================
            // For expanded buckets (>256 slots), traverse the internal bucket tree
            // structure from the key's leaf segment up toward the bucket root.
            // This only applies to buckets with level > 2 (multi-level bucket trees).
            let mut node = subtree_leaf_for_key(salt_key);

            let mut count = level;
            while count > 2 {
                let parent_node = get_parent_node(&node);
                // Record parent-child relationships within the bucket subtree
                internal_nodes
                    .entry(parent_node)
                    .or_default()
                    .insert(vc_position_in_parent(&node));

                node = parent_node;
                count -= 1;
            }

            // ============================================================================
            // Phase 3: Bridge Connection (Expanded buckets)
            // ============================================================================
            // For bucket trees with exactly 2 levels, create the bridge connection
            // between the bucket subtree and the main trie. The encode_parent function
            // embeds level information in the node ID to distinguish different tree levels.
            if count == 2 {
                let main_trie_node = bucket_root_node_id(salt_key.bucket_id());
                // Use encoded parent to bridge bucket tree to main trie
                internal_nodes
                    .entry(encode_parent(main_trie_node, level))
                    .or_default()
                    .insert(vc_position_in_parent(&node));
            }

            // ============================================================================
            // Phase 4: Key-Value Slot Position
            // ============================================================================
            // Record the direct parent of the key-value pair itself. This determines
            // which node contains the actual data slot and what position within that
            // node's 256-slot array the key occupies.
            let node = if level == 1 {
                // Level 1: Key stored directly in bucket root (single 256-slot segment)
                bucket_root_node_id(salt_key.bucket_id())
            } else {
                // Level 2+: Key stored in a leaf segment of the bucket tree
                subtree_leaf_for_key(salt_key)
            };

            // Record which slot position within the segment contains this key
            // Use lowest 8 bits of slot_id as position within 256-slot segment
            slot_position_nodes
                .entry(node)
                .or_default()
                .insert((salt_key.slot_id() & 0xFF) as usize);

            (internal_nodes, slot_position_nodes)
        })
        .reduce(
            || (BTreeMap::new(), BTreeMap::new()),
            |mut acc, (internal_map, slot_map)| {
                for (node_id, positions) in internal_map {
                    acc.0.entry(node_id).or_default().extend(positions);
                }
                for (node_id, positions) in slot_map {
                    acc.1.entry(node_id).or_default().extend(positions);
                }
                acc
            },
        )
}

/// Encodes bucket tree level information into a main trie node ID.
///
/// SALT's dual addressing system requires bridging between the main trie and bucket
/// subtrees. This function embeds level information into main trie L3 node IDs to
/// create "encoded parent" references that preserve both the physical connection
/// point and the logical subtree depth.
///
/// # Bit Layout
///
/// ```text
/// [64..........35......33............0]
///  unused here  level    trie_node_id
///               (3 bits)  (33 bits)
/// ```
///
/// The level information is stored in bits 33-35, supporting levels 1-5:
///
/// # Arguments
///
/// * `parent` - Main trie L3 node ID (bucket root in physical structure)
/// * `level` - Bucket tree depth level (1-5), stored in 3 bits
///
/// # Returns
///
/// Encoded NodeID with level embedded in bits 33-35
///
/// # Usage Context
///
/// Used in `parents_and_points()` to create bridge connections between bucket
/// subtrees and the main trie, enabling proof generation across both
/// addressing domains.
pub const fn encode_parent(parent: NodeId, level: u8) -> NodeId {
    // Embed level information in bits 33-35 while preserving original node ID
    parent | ((level as u64) << 33)
}

/// Detects whether a NodeID contains encoded bucket tree level information.
///
/// # Detection Algorithm
///
/// Uses bitwise AND with mask `0x07 << 33` (bits 33, 34, 35) to check level storage:
/// - `0x07` = `0b111` covers all valid levels (1-5)
/// - Level 0 never occurs in practice (would indicate no bucket tree)
/// - Any non-zero result indicates an encoded node
///
/// # Returns
///
/// - `true` if NodeID contains encoded level information (bits 33-35 ≠ 0)
/// - `false` for regular main trie nodes or bucket subtree nodes
///
/// # Usage Context
///
/// Used throughout the addressing system to distinguish:
/// - Regular NodeIDs (main trie or bucket subtree addresses)
/// - Encoded NodeIDs (bridge connections with embedded level info)
pub const fn is_encoded_node(maybe_encoded_node: NodeId) -> bool {
    maybe_encoded_node & (0x07 << 33) != 0
}

/// Extracts the physical main trie node ID from an encoded parent reference.
///
/// When SALT creates encoded parent references (via `encode_parent`), the original
/// main trie L3 node ID is preserved in the lower 33 bits while level information
/// occupies bits 33-35. This function strips the level encoding to recover the
/// actual main trie node ID needed for physical tree traversal.
///
/// # Dual Addressing Context
///
/// SALT's bucket subtrees need two types of parent references:
/// - **Connection Parent** (this function): Physical main trie node for structural connections
/// - **Logical Parent** (`logic_parent_id`): Conceptual subtree root for bucket operations
///
/// # Arguments
///
/// * `maybe_encoded_node` - NodeID that may contain encoded level information
///
/// # Returns
///
/// - If encoded: Main trie L3 node ID (bits 0-32)
/// - If not encoded: Original NodeID unchanged
///
/// # Usage Context
///
/// Essential for:
/// - Traversing physical trie connections during proof generation
/// - Identifying actual bucket root locations in main trie
/// - Converting encoded references back to concrete node addresses
pub const fn connect_parent_id(maybe_encoded_node: NodeId) -> NodeId {
    if is_encoded_node(maybe_encoded_node) {
        maybe_encoded_node & ((1 << 33) - 1) // Mask: 0x1FFFFFFFF
    } else {
        maybe_encoded_node
    }
}

/// Computes the logical subtree root address for bucket tree operations.
///
/// While `connect_parent_id` extracts the physical main trie node, this function
/// calculates the corresponding logical address within the bucket's own subtree
/// coordinate system. This enables navigation within the bucket tree's internal
/// hierarchy for operations like child traversal and proof generation.
///
/// # Address Translation Algorithm
///
/// For encoded nodes, performs a 4-step coordinate transformation:
///
/// 1. **Extract Components**:
///    - `connect_parent`: Physical main trie L3 node ID (bits 0-32)
///    - `levels`: Bucket tree depth (bits 33-35)
///
/// 2. **Calculate Bucket ID**:
///    - `bucket_id = connect_parent - STARTING_NODE_ID[3]`
///    - Converts main trie position to bucket index
///
/// 3. **Determine Subtree Root Level**:
///    - `root_level = MAX_SUBTREE_LEVELS - levels`
///    - Higher capacity buckets have roots at higher levels
///    - Level 5: root at level 0 (maximum capacity)
///    - Level 1: root at level 4 (minimum capacity)
///
/// 4. **Compute Logical Address**:
///    - `STARTING_NODE_ID[root_level] + (bucket_id << BUCKET_SLOT_BITS)`
///    - Creates subtree-relative address with bucket ID in high bits
///
/// # Arguments
///
/// * `maybe_encoded_node` - NodeID that may contain encoded level information
///
/// # Returns
///
/// - If encoded: Logical subtree root address for bucket operations
/// - If not encoded: Original NodeID unchanged
pub const fn logic_parent_id(maybe_encoded_node: NodeId) -> NodeId {
    if is_encoded_node(maybe_encoded_node) {
        let connect_parent = maybe_encoded_node & ((1 << 33) - 1);
        let levels = (maybe_encoded_node >> 33) as u8;
        let bucket_id = connect_parent - STARTING_NODE_ID[3] as u64;
        STARTING_NODE_ID[MAX_SUBTREE_LEVELS - levels as usize] as u64
            | (bucket_id << BUCKET_SLOT_BITS)
    } else {
        maybe_encoded_node
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::{rngs::StdRng, Rng, SeedableRng};

    #[test]
    fn test_parents_and_points() {
        // Test data: (bucket_id, level, slot_mask) for different bucket types
        let test_cases = [
            (0, 1, 0xFF),
            (256, 1, 0xFF),
            (65535, 1, 0xFF),
            (65536, 1, 0xFF),
            (65540, 2, 0xFFFF),
            (1_000_000, 3, 0xFFFFFF),
            (5_000_000, 4, 0xFFFFFFFF),
            (16_777_215, 5, 0xFFFFFFFF),
        ];

        let rng = StdRng::seed_from_u64(42);
        let (salt_keys, levels): (Vec<_>, FxHashMap<_, _>) = test_cases
            .into_iter()
            .flat_map(|(bucket_id, level, slot_mask)| {
                (0..2).map({
                    let mut value = rng.clone();
                    move |_| {
                        let slot_id = value.gen::<u64>() & slot_mask;
                        (SaltKey::from((bucket_id, slot_id)), (bucket_id, level))
                    }
                })
            })
            .unzip();

        let (internal_nodes, slot_position_nodes) = parents_and_points(&salt_keys, &levels);

        // Validate basic structure and constraints
        assert!(!internal_nodes.is_empty());
        assert!(!slot_position_nodes.is_empty());
        internal_nodes.values().for_each(|positions| {
            assert!(!positions.is_empty() && positions.iter().all(|&p| p < 256));
        });
        slot_position_nodes.values().for_each(|positions| {
            assert!(!positions.is_empty() && positions.iter().all(|&p| p < 256));
        });

        // Verify expected internal nodes exist with correct values
        let expected_internal = [
            (0, &[0, 1, 15, 76, 255][..]),
            (1, &[0, 1, 255]),
            (256, &[255]),
        ];
        expected_internal.iter().for_each(|&(node, exp)| {
            let actual: Vec<_> = internal_nodes[&node].iter().copied().collect();
            assert_eq!(actual, exp);
        });

        // Verify expected slot position nodes exist with correct values
        let expected_slots = [(131329, &[125, 162][..]), (72061992101282085, &[162])];
        expected_slots.iter().for_each(|&(node, exp)| {
            let actual: Vec<_> = slot_position_nodes[&node].iter().copied().collect();
            assert_eq!(actual, exp);
        });

        // Verify encoded parent nodes exist
        [(131333, 2), (1065793, 3), (5065793, 4), (16843008, 5)]
            .iter()
            .for_each(|&(node, level)| {
                assert!(!internal_nodes[&encode_parent(node, level)].is_empty());
            });
    }

    #[test]
    fn test_encode_parent() {
        // Test with actual parent node IDs
        let parent_id = 131329; // data bucket start
        assert_eq!(encode_parent(parent_id, 3), parent_id | (3u64 << 33));

        // Test level boundaries (1-5)
        for level in 1..=5 {
            let encoded = encode_parent(parent_id, level);
            assert_eq!(encoded & ((1 << 33) - 1), parent_id); // Lower 33 bits unchanged
            assert_eq!((encoded >> 33) & 0x07, level as u64); // Level in bits 33-35
        }

        // Test that encoding preserves original node ID in lower bits
        let test_nodes = [65793, 1065793, 5065793, 16843008];
        for node in test_nodes {
            for level in 1..=5 {
                let encoded = encode_parent(node, level);
                assert_eq!(encoded & ((1 << 33) - 1), node);
            }
        }
    }

    #[test]
    fn test_is_encoded_node() {
        // Test unencoded nodes (should return false)
        assert!(!is_encoded_node(0));
        assert!(!is_encoded_node(1));
        assert!(!is_encoded_node(257));
        assert!(!is_encoded_node(65793));
        assert!(!is_encoded_node(16843009));
        assert!(!is_encoded_node((1 << 33) - 1)); // Maximum 33-bit value

        // Test encoded nodes (should return true)
        assert!(is_encoded_node(1 << 33)); // Level 1
        assert!(is_encoded_node(2 << 33)); // Level 2
        assert!(is_encoded_node(5 << 33)); // Level 5, Maximum level value

        // Test encoded nodes with parent IDs
        let parent_id = 131329;
        for level in 1..=5 {
            let encoded = encode_parent(parent_id, level);
            assert!(is_encoded_node(encoded));
        }

        // Test boundary cases
        assert!(is_encoded_node(0x07 << 32)); // Level bits in wrong position
        assert!(!is_encoded_node(0x08 << 33)); // Invalid level (> 7)
    }

    #[test]
    fn test_connect_parent_id() {
        // Test unencoded nodes (should return unchanged)
        let unencoded_nodes = [0, 1, 257, 65793, 16843009];
        for node in unencoded_nodes {
            assert_eq!(connect_parent_id(node), node);
        }

        // Test encoded nodes (should extract lower 33 bits)
        let parent_id = 131329;
        for level in 1..=5 {
            let encoded = encode_parent(parent_id, level);
            assert_eq!(connect_parent_id(encoded), parent_id);
        }

        // Test edge cases
        assert_eq!(connect_parent_id(0), 0);
        assert_eq!(connect_parent_id((1 << 33) - 1), (1 << 33) - 1); // Max 33-bit value

        // Test with different parent IDs
        let test_parents = [0, 1, 256, 65793];
        for parent in test_parents {
            for level in 1..=5 {
                let encoded = encode_parent(parent, level);
                assert_eq!(connect_parent_id(encoded), parent);
            }
        }
    }

    #[test]
    fn test_logic_parent_id() {
        // Test unencoded nodes (should return unchanged)
        let unencoded_nodes = [0, 1, 257, 65793, 16843009];
        for node in unencoded_nodes {
            assert_eq!(logic_parent_id(node), node);
        }

        // Test encoded nodes with known bucket IDs
        let bucket_root = 131329;

        // Test level 1: bucket_id = 65536, root_level = 4
        let encoded_level1 = encode_parent(bucket_root, 1);
        let expected_logic1 = (65536u64 << BUCKET_SLOT_BITS) | STARTING_NODE_ID[4] as u64;
        assert_eq!(logic_parent_id(encoded_level1), expected_logic1);

        // Test level 2: bucket_id = 65536, root_level = 3
        let encoded_level2 = encode_parent(bucket_root, 2);
        let expected_logic2 = (65536u64 << BUCKET_SLOT_BITS) | STARTING_NODE_ID[3] as u64;
        assert_eq!(logic_parent_id(encoded_level2), expected_logic2);

        // Test with bucket_id = 65540
        let bucket_root_1 = STARTING_NODE_ID[3] as u64 + 65540; // 131333
        let encoded = encode_parent(bucket_root_1, 2);
        let expected = STARTING_NODE_ID[3] as u64 | (65540u64 << BUCKET_SLOT_BITS);
        assert_eq!(logic_parent_id(encoded), expected);

        // Test level boundaries
        for level in 1..=5 {
            let encoded = encode_parent(bucket_root, level);
            let logic_id = logic_parent_id(encoded);
            // Verify the bucket_id is correctly extracted and shifted
            if level <= MAX_SUBTREE_LEVELS as u8 {
                let expected_base = STARTING_NODE_ID[MAX_SUBTREE_LEVELS - level as usize] as u64;
                assert!((logic_id & !((0xFFFFFFu64) << BUCKET_SLOT_BITS)) == expected_base);
            }
        }
    }
}
