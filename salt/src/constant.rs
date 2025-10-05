//! Constants defining the SALT data structure.
//!
//! SALT is a cryptographically authenticated key-value store organized as a 256-ary trie.
//! The structure consists of:
//! - A 4-level main trie with 256^3 = 16,777,216 leaf nodes (buckets)
//! - Each bucket can dynamically resize to hold key-value pairs
//! - The first 65,536 buckets store metadata, the rest store actual data
//!
//! ## Trie Structure
//! ```text
//!                    Root (Level 0)
//!                      /    |    \
//!                   /       |       \  [256 children]
//!            Level 1    Level 1   ...
//!               /|\        /|\
//!              / | \      / | \     [256 children each]
//!           Level 2    Level 2  ...
//!             /|\        /|\
//!            / | \      / | \       [256 children each]
//!         Buckets    Buckets ...    [16,777,216 total]
//! ```
use crate::types::{get_bfs_level, is_subtree_node, leftmost_node, CommitmentBytes, NodeId};

// ============================================================================
// Bucket Size Constants
// ============================================================================

/// Number of bits to represent the minimum bucket size.
pub const MIN_BUCKET_SIZE_BITS: usize = 8;
/// Minimum capacity of a SALT bucket (256 slots).
/// Buckets are dynamically resized but their capacities cannot drop below this value.
/// This represents the number of key-value pairs a bucket can hold at minimum.
pub const MIN_BUCKET_SIZE: usize = 1 << MIN_BUCKET_SIZE_BITS;
/// Fixed capacity of metadata buckets.
/// Set equal to MIN_BUCKET_SIZE since metadata buckets don't need to resize
/// and maintaining uniform size simplifies the implementation.
pub const META_BUCKET_SIZE: usize = MIN_BUCKET_SIZE;

// ============================================================================
// Trie Structure Constants
// ============================================================================

/// Number of levels in the SALT main trie.
/// - Level 0: Root node (1 node)
/// - Level 1: 256 nodes
/// - Level 2: 65,536 nodes
/// - Level 3: 16,777,216 nodes (buckets)
///
/// This gives us 256^3 = 16,777,216 total buckets.
pub const MAIN_TRIE_LEVELS: usize = 4;
/// Maximum levels in bucket subtrees.
///
/// Bucket subtrees organize data into 256-slot segments. These segments are ALWAYS
/// leaf nodes at the deepest level (level 4) of the MAXIMAL subtree structure. As
/// bucket capacity increases, the subtree root moves UP to accommodate more leaves.
///
/// Structure evolution by capacity:
/// - 256 slots (1 segment): Single-node subtree, root at level 4
/// - 512 slots (2 segments): Root at level 3, 2 leaf nodes at level 4
/// - 768-65536 slots: Root at level 2, internal nodes at level 3, leaves at level 4
/// - 65537+ slots: Root at higher levels as needed
///
/// Example for 512-slot bucket (2 segments):
/// ```text
///        Root (level 3, in subtree)
///         /                \
///   Segment_0           Segment_1  (level 4, in subtree)
///   [slots 0-255]    [slots 256-511]
///   NodeId: 16843009  NodeId: 16843010
/// ```
///
/// Key invariants:
/// - Bucket segments are always at level 4 (NodeId starts at 16843009)
/// - Each segment holds exactly 256 consecutive slots
/// - The root position depends on capacity (see subtree_root_level function)
pub const MAX_SUBTREE_LEVELS: usize = 5;
/// Number of bits to represent the trie width (branching factor).
pub const TRIE_WIDTH_BITS: usize = 8;

/// Branch factor of SALT trie nodes (256 children per node).
/// 256 was chosen because:
/// - Matches byte boundaries (one byte selects a child)
/// - Provides good fanout for reducing tree depth
/// - Aligns with common cryptographic block sizes
pub const TRIE_WIDTH: usize = 1 << TRIE_WIDTH_BITS;
/// Total number of buckets (leaf nodes) in the SALT trie.
/// Calculated as: 256^3 = 16,777,216 buckets
/// (3 levels of 256-way branching below the root)
pub const NUM_BUCKETS: usize = 1 << ((MAIN_TRIE_LEVELS - 1) * TRIE_WIDTH_BITS);
/// Number of metadata buckets in the SALT trie.
/// Calculated as: 16,777,216 / 256 = 65,536 buckets
/// These store bucket metadata (nonce, capacity) for all data buckets.
pub const NUM_META_BUCKETS: usize = NUM_BUCKETS / MIN_BUCKET_SIZE;
/// Number of data buckets for storing actual key-value pairs.
/// Calculated as: 16,777,216 - 65,536 = 16,711,680 buckets
pub const NUM_KV_BUCKETS: usize = NUM_BUCKETS - NUM_META_BUCKETS;

// ============================================================================
// Node Addressing Constants
// ============================================================================

/// Node ID of the root node in the main trie.
pub const ROOT_NODE_ID: NodeId = 0;

/// Default hash value for empty slots in buckets.
/// Set to [1u8; 32] to distinguish from zero-initialized memory.
pub const EMPTY_SLOT_HASH: [u8; 32] = [1u8; 32];

/// Array of starting node IDs for each trie level.
///
/// Since the SALT trie is always full, nodes can be flattened to an array.
/// The ID of the leftmost node at level i is calculated as: sum(256^j) for j in 0..i
///
/// - Level 0: 0 (just the root)
/// - Level 1: 1 (after 1 node at level 0)
/// - Level 2: 257 (after 1 + 256 nodes)
/// - Level 3: 65,793 (after 1 + 256 + 65,536 nodes)
/// - Level 4: 16,843,009 (after 1 + 256 + 65,536 + 16,777,216 nodes)
pub const STARTING_NODE_ID: [usize; MAX_SUBTREE_LEVELS] = [
    leftmost_node(0).unwrap() as usize, // 0
    leftmost_node(1).unwrap() as usize, // 1
    leftmost_node(2).unwrap() as usize, // 257
    leftmost_node(3).unwrap() as usize, // 65793
    leftmost_node(4).unwrap() as usize, // 16843009
];

/// Maximum number of bits to represent a bucket ID.
/// 24 bits supports up to ~16.7 million buckets, which matches NUM_BUCKETS.
pub const BUCKET_ID_BITS: usize = 24;

/// Maximum number of bits to represent a slot index in a bucket.
/// 40 bits supports up to ~1 trillion slots per bucket, providing ample room for growth.
pub const BUCKET_SLOT_BITS: usize = 40;

/// Mask to extract the slot ID from a NodeId or SaltKey.
/// The slot ID occupies the lower 40 bits.
/// Example: node_id & BUCKET_SLOT_ID_MASK extracts the position within a bucket.
pub const BUCKET_SLOT_ID_MASK: u64 = (1 << BUCKET_SLOT_BITS) - 1;

// ============================================================================
// Resizing Parameters
// ============================================================================

/// Load factor threshold (as percentage) that triggers bucket resizing.
/// When a bucket's usage exceeds this percentage of its capacity, it will be resized.
/// 80% provides a good balance between space efficiency and collision avoidance.
pub const BUCKET_RESIZE_LOAD_FACTOR_PCT: u64 = 80;

/// Multiplier used when expanding bucket capacity during resize operations.
/// The new capacity will be the old capacity multiplied by this factor.
pub const BUCKET_RESIZE_MULTIPLIER: u64 = 2;

// ============================================================================
// Cryptographic Constants
// ============================================================================

/// The degree of the polynomial used in the IPA (Inner Product Argument) proof.
/// 256 matches our trie branching factor for efficient proof generation.
pub const POLY_DEGREE: usize = 256;

/// Macro to convert a 128-character hex string into a [u8; 64] array at compile time.
/// Used for embedding precomputed cryptographic commitments.
macro_rules! b512 {
    ($s:literal) => {{
        const _: () = assert!(
            $s.len() == 128,
            "Hex string must be exactly 128 characters long"
        );

        const RESULT: [u8; 64] = {
            let s = $s.as_bytes();
            let mut commitment = [0u8; 64];
            let mut i = 0;

            // Process each byte pair at compile time
            while i < 64 {
                // Get high and low nibble characters
                let hi = s[i * 2];
                let lo = s[i * 2 + 1];
                let hi_val = hex_char_to_u8(hi);
                let lo_val = hex_char_to_u8(lo);
                // Combine into one byte
                commitment[i] = (hi_val << 4) | lo_val;
                i += 1;
            }
            commitment
        };

        /// Converts a single hex character to its 4-bit value (const fn)
        const fn hex_char_to_u8(c: u8) -> u8 {
            match c {
                b'0'..=b'9' => c - b'0',
                b'a'..=b'f' => c - b'a' + 10,
                b'A'..=b'F' => c - b'A' + 10,
                _ => panic!("Invalid hex character"),
            }
        }

        RESULT
    }};
}

/// Get the default commitment for an empty node at the specified position.
///
/// These commitments are precomputed for performance and represent
/// the cryptographic hash of an empty trie at each level. This allows
/// efficient validation without recomputing empty subtree hashes.
///
/// The commitments differ based on:
/// - Node level in the trie
/// - Position relative to metadata/data bucket boundary (at NUM_META_BUCKETS)
///
/// For implementation details, see the test case `trie_level_default_commitment`
/// in ../salt/src/trie/trie.rs.
pub fn default_commitment(node_id: NodeId) -> CommitmentBytes {
    // Precomputed commitments for each level of an empty SALT main trie.
    // Each entry contains: (boundary_position, left_commitment, right_commitment)
    // where left is for positions < boundary, right is for positions >= boundary.
    static DEFAULT_COMMITMENT_AT_LEVEL: [(usize, CommitmentBytes, CommitmentBytes); MAIN_TRIE_LEVELS] = [
        (
            STARTING_NODE_ID[0] + 1,
            b512!("a2f11cbb573b3beba869c4417fd616e550f66feea3edcf6b8979bee66dd18767d744099c52a92477cb2e005ca3665892ce7860ccaf476aa224528837e5732270"),
            b512!("a2f11cbb573b3beba869c4417fd616e550f66feea3edcf6b8979bee66dd18767d744099c52a92477cb2e005ca3665892ce7860ccaf476aa224528837e5732270"),
        ),
        (
            STARTING_NODE_ID[1] + 1,
            b512!("b744bfb480faaaaecfb534e10ce111489c89cc43ab90a380ef5eb0f8668b731049cd9f4222b06ca3e41d624b573b83e67a9f251ae7f4e26cd496fd4005fc8c72"),
            b512!("866b0fd149ea8e233d295dff7b91af9ac54e82e3083a979e068fe9f5a8747832f59ed53dfd1e939bdcbf9e1bbc87752c8fe8537c662f537ebfde227ce7845659"),
        ),
        (
            STARTING_NODE_ID[2] + MIN_BUCKET_SIZE,
            b512!("9ed527e0e507e93c05d5a77184211e6bbf6e1820fdc7cd36387c4d52f8b931182f47ece1ebb6dad09b8b96062bc5241b143e03f36e69ffb83b0ef8d99f818772"),
            b512!("1d8d81bcb60ff180ff99c497a8298af38d71d2fbf3c0ffda09b659839e3732612771a485191ab8fe740dc20d1a33c53f8cfbb1c07676d74050de914c0efc7f54"),
        ),
        (
            STARTING_NODE_ID[3] + NUM_META_BUCKETS,
            b512!("e07db25c34ee2ddb23992be6e8c3a9fc0c3b3c23effd4089cb262524ce64671abc3da78e1f67a926db11faa1385ca8d35aee7905cff1251536c75b73f60ed16b"),
            b512!("da260863cc36b265d34f9912c3b98ae7e046ced37bf5eebe1be164695093714efc9e5b23b9ab87c9f7b51e4fec4ea377e4fe44672d70752f7c3522e0f0269555"),
        ),
    ];

    // Precomputed commitments for each level of an empty SALT bucket subtree.
    // These are used when a bucket has expanded beyond MIN_BUCKET_SIZE.
    static SUBTREE_DEFAULT_COMMITMENT:[CommitmentBytes; MAX_SUBTREE_LEVELS] = [
        b512!("a7bba7dcf3ad2fbb9fd792f875adad094bb67119f2e83fd751299d9195d7301cfece2bfd0cbc9ce1150cd3a653377c9a038af061a0d8ebe4de54143ffe3cb172"),
        b512!("db1c8437754289cd759fa15c051b03950c135a8b67176946020087cdd86f0c2f660ba555b18020f3941854a87060bcf92b39312a63dcd21fc9b629ee6b0ca570"),
        b512!("866b0fd149ea8e233d295dff7b91af9ac54e82e3083a979e068fe9f5a8747832f59ed53dfd1e939bdcbf9e1bbc87752c8fe8537c662f537ebfde227ce7845659"),
        b512!("1d8d81bcb60ff180ff99c497a8298af38d71d2fbf3c0ffda09b659839e3732612771a485191ab8fe740dc20d1a33c53f8cfbb1c07676d74050de914c0efc7f54"),
        b512!("da260863cc36b265d34f9912c3b98ae7e046ced37bf5eebe1be164695093714efc9e5b23b9ab87c9f7b51e4fec4ea377e4fe44672d70752f7c3522e0f0269555"),
    ];

    let level = get_bfs_level(node_id & BUCKET_SLOT_ID_MASK as NodeId);

    if is_subtree_node(node_id) {
        SUBTREE_DEFAULT_COMMITMENT[level]
    } else if node_id < DEFAULT_COMMITMENT_AT_LEVEL[level].0 as NodeId {
        DEFAULT_COMMITMENT_AT_LEVEL[level].1
    } else {
        DEFAULT_COMMITMENT_AT_LEVEL[level].2
    }
}
