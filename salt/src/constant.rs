//! This module defines constants that determine the shape of the SALT data structure.
use crate::types::{CommitmentBytes, NodeId};
use banderwagon::salt_committer::Committer;

/// Number of bits to represent `MIN_BUCKET_SIZE`.
pub const MIN_BUCKET_SIZE_BITS: usize = 8;
/// Capacity of a default SALT bucket. Buckets are dynamically resized but their capacities cannot
/// drop below this value.
pub const MIN_BUCKET_SIZE: usize = 1 << MIN_BUCKET_SIZE_BITS;
/// Number of levels in the SALT trie. Level 0 is the root. Buckets are located at the last level.
pub const TRIE_LEVELS: usize = 4;
/// Number of levels in the sub-trie of the bucket. The root node is stored in the SALT trie,
/// while the remaining nodes are stored in the sub-trie. The node numbers of the sub-trie are
/// generated according to the 40-bit full encoding rule.
/// For example, if the bucket capacity is `MIN_BUCKET_SIZE`, the number of sub-trie nodes is 0.
/// If the bucket capacity is 2 * `MIN_BUCKET_SIZE`, the number of sub-trie nodes is 2, as shown in
/// the below:               |`STARTING_NODE_ID`[SUB_TRIE_LEVELS-2]| - root node stored in the SALT
/// trie                  /                         \
/// |`STARTING_NODE_ID`[SUB_TRIE_LEVELS-1]| |`STARTING_NODE_ID`[SUB_TRIE_LEVELS-1]+1|  - internal node stored in the sub trie
pub const SUB_TRIE_LEVELS: usize = 5;
/// Number of bits to represent `TRIE_WIDTH`.
pub const TRIE_WIDTH_BITS: usize = 8;
/// Branch factor of the SALT trie nodes. Always a power of two.
pub const TRIE_WIDTH: usize = 1 << TRIE_WIDTH_BITS;
/// Number of buckets (i.e., leaf nodes) in the SALT trie.
pub const NUM_BUCKETS: usize = 1 << ((TRIE_LEVELS - 1) * TRIE_WIDTH_BITS);
/// Number of meta buckets in the SALT trie. Meta buckets are used to store metadata for each
/// bucket. The remaining buckets are used to store key-value pairs.
pub const NUM_META_BUCKETS: usize = NUM_BUCKETS / MIN_BUCKET_SIZE;
/// Number of key-value buckets in the SALT trie.
pub const NUM_KV_BUCKETS: usize = NUM_BUCKETS - NUM_META_BUCKETS;
/// Index of root commitment in salt buckets.
pub const ROOT_NODE_ID: NodeId = 0;

/// The SALT trie is always full, so its nodes can be flattened to an array for efficient storage
/// and access. `STARTING_NODE_ID`[i] indicates the ID of the leftmost node (i.e., its index in the
/// array) at level i.
pub const STARTING_NODE_ID: [usize; SUB_TRIE_LEVELS] = [
    0,
    1,
    TRIE_WIDTH + 1,
    TRIE_WIDTH * TRIE_WIDTH + TRIE_WIDTH + 1,
    TRIE_WIDTH * TRIE_WIDTH * TRIE_WIDTH + TRIE_WIDTH * TRIE_WIDTH + TRIE_WIDTH + 1,
];

/// Maximum number of bits to represent a bucket ID. Although the ID consists of only 24 bits, it
/// will occupy the upper 32 bits of the `SaltKey`.
pub const BUCKET_ID_BITS: usize = 24;
/// Maximum number of bits to represent a slot index in a bucket. 2^40 slots per bucket should be
/// more than enough.
pub const BUCKET_SLOT_BITS: usize = 40;
/// Mask of the slot ID in a bucket. The slot ID is the lower 40 bits of the `SaltKey`.
pub const BUCKET_SLOT_ID_MASK: u64 = (1 << BUCKET_SLOT_BITS) - 1;

/// The degree of the polynomial used in the IPA proof.
pub const POLY_DEGREE: usize = 256;
/// Macro to convert a 128-character hex string into a [u8; 64] array at compile time
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

/// Calculate the level where the specified node is located.
pub fn get_node_level(node_id: NodeId) -> usize {
    STARTING_NODE_ID
        .iter()
        .enumerate()
        .rev()
        .find(|&(_, &threshold)| node_id >= threshold as NodeId)
        .unwrap()
        .0
}

/// Get the default commitment for the specified node.
pub fn default_commitment(node_id: NodeId) -> CommitmentBytes {
    // Precomputed node commitment at each level of an empty SALT trie.
    // Refer to the test case '`trie_level_default_committment`' in ../salt/src/trie/trie.rs for more
    // info.
    static DEFAULT_COMMITMENT_AT_LEVEL: [(usize, CommitmentBytes, CommitmentBytes); TRIE_LEVELS] = [
        (
            STARTING_NODE_ID[0] + 1,
            b512!("df6aca6a367180e5d1a1f33a16a0fd25a7e74b6eae96f356664fe0475367770af8493889191796b790360f4d4dd01d6ea69717c5295773603743fd075aacda3f"),
            b512!("df6aca6a367180e5d1a1f33a16a0fd25a7e74b6eae96f356664fe0475367770af8493889191796b790360f4d4dd01d6ea69717c5295773603743fd075aacda3f"),
        ),
        (
            STARTING_NODE_ID[1] + 1,
            b512!("872be2bdd38751a7331a8e84bbdac5c1894abd8e2bc157b4562612bbf780360384639d74c6248010cc29a98d3e451abec1c914c9f9aab378dde89a6929a92f53"),
            b512!("00000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000"),
        ),
        (
            STARTING_NODE_ID[2] + MIN_BUCKET_SIZE,
            b512!("4eae46a19a678b5ee3e410fa2b08dd6d3a6b40ad3c4d522371d0242b82bfbe37952bd51dcdb4853e86489e3d41f3655ccb7983f8e7336605347dd3f4d71ab90f"),
            b512!("00000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000"),
        ),
        (
            STARTING_NODE_ID[3] + NUM_META_BUCKETS,
            b512!("0a123e0d06b57a10df084aa5982e2b8d2d146562c8d80e06d88a9698e5497373788b0d4936bfb3987dded12a77a428c73ac661fffaea920adbb58267243c8366"),
            b512!("00000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000"),
        ),
    ];

    let level = get_node_level(node_id);

    if is_extension_node(node_id) {
        zero_commitment()
    } else if node_id < DEFAULT_COMMITMENT_AT_LEVEL[level].0 as NodeId {
        DEFAULT_COMMITMENT_AT_LEVEL[level].1
    } else {
        DEFAULT_COMMITMENT_AT_LEVEL[level].2
    }
}

/// Determine whether to expand the node
#[inline]
pub fn is_extension_node(node_id: NodeId) -> bool {
    node_id >= STARTING_NODE_ID[SUB_TRIE_LEVELS - 1] as NodeId
}

/// Return the zero commitment.
pub fn zero_commitment() -> CommitmentBytes {
    Committer::zero()
}
