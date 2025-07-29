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

/// Precomputed node commitment at each level of an empty SALT trie.
/// Refer to the test case '`trie_level_default_committment`' in ../salt/src/trie/trie.rs for more
/// info.
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
pub fn default_commitment(level: usize, id: NodeId) -> CommitmentBytes {
    static DEFAULT_COMMITMENT_AT_LEVEL: [(usize, CommitmentBytes, CommitmentBytes); TRIE_LEVELS] = [
        (
            STARTING_NODE_ID[0] + 1,
            b512!("5b61d927cf2984395c7a10a9300e6510371ff70a08b8be12d4598f2bd8212d39a480d92b37d8dea1d0f89260f9d9f0fee8164988d53c8b11c07a516afbf3dd1c"),
            b512!("5b61d927cf2984395c7a10a9300e6510371ff70a08b8be12d4598f2bd8212d39a480d92b37d8dea1d0f89260f9d9f0fee8164988d53c8b11c07a516afbf3dd1c"),
        ),
        (
            STARTING_NODE_ID[1] + 1,
            b512!("ac5cefa767c0826d57a742750205fcb5d21e73b9bd9d5e1ba4ae69cfb70cd45d8bb824a8728b172cdb9759e230ce91089d139e2a1a9b277fd9aa2148492ba31b"),
            b512!("00000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000"),
        ),
        (
            STARTING_NODE_ID[2] + MIN_BUCKET_SIZE,
            b512!("2d6d15700368640cf2ec8f8821028a9222c45a382456adf52f142273b38415061f5b84d1426ec7cdbdf6cb58446bc4115c183514a39560205dd95f60abb6d02f"),
            b512!("00000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000"),
        ),
        (
            STARTING_NODE_ID[3] + NUM_META_BUCKETS,
            b512!("b19f806b182b14a58e02fac5ea1325d017b058ce6dfe8926a841eb5d80776b2041b87b43527d3264923ad9806fe93e17e1366c7d161d5eac6809d06f4b0a3208"),
            b512!("00000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000"),
        ),
    ];

    if id < DEFAULT_COMMITMENT_AT_LEVEL[level].0 as NodeId {
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
