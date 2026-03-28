//! Core data types for the SALT data structure.
//!
//! This module defines the fundamental types used throughout the SALT implementation:
//! - [`SaltKey`]: 64-bit addressing for bucket slots
//! - [`SaltValue`]: Variable-length encoding for key-value pairs
//! - [`BucketMeta`]: Bucket metadata (nonce, capacity, usage)
//! - [`NodeId`]: 64-bit identifiers for trie nodes
//! - Cryptographic types: [`CommitmentBytes`] and [`ScalarBytes`]

use std::ops::RangeInclusive;

use crate::constant::{
    BUCKET_SLOT_BITS, BUCKET_SLOT_ID_MASK, MIN_BUCKET_SIZE, MIN_BUCKET_SIZE_BITS, NUM_BUCKETS,
    NUM_META_BUCKETS, TRIE_WIDTH,
};

use derive_more::{Deref, DerefMut};

/// 64-byte uncompressed group element for cryptographic commitments.
pub type CommitmentBytes = [u8; 64];

/// 32-byte scalar field element for cryptographic commitments.
pub type ScalarBytes = [u8; 32];

/// Version number for tracking state value changes.
pub type SaltVersion = u64;

/// Hash a 64-byte commitment into its 32-byte compressed format.
pub fn hash_commitment(commitment: CommitmentBytes) -> ScalarBytes {
    use banderwagon::{CanonicalSerialize, Element};
    let mut bytes = [0u8; 32];
    Element::from_bytes_unchecked_uncompressed(commitment)
        .map_to_scalar_field()
        .serialize_compressed(&mut bytes[..])
        .expect("Failed to serialize scalar to bytes");
    bytes
}

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Unified error type for SALT operations.
///
/// This enum consolidates all string-based errors throughout the SALT codebase
/// into a structured, type-safe error system using the `thiserror` crate.
#[derive(Error, Debug, Clone, PartialEq)]
pub enum SaltError {
    #[error("Invalid data format: {message}")]
    InvalidFormat { message: &'static str },

    #[error("{what} not available in witness")]
    NotInWitness { what: &'static str },

    #[error("Operation '{operation}' not supported")]
    UnsupportedOperation { operation: &'static str },
}

/// 24-bit bucket identifier (up to ~16M buckets).
pub type BucketId = u32;

/// 40-bit slot identifier within a bucket (up to ~1T slots).
pub type SlotId = u64;

/// Metadata for a bucket containing nonce, capacity, and usage statistics.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct BucketMeta {
    /// Nonce for SHI hash table operations.
    pub nonce: u32,
    /// Total # slots of the bucket.
    pub capacity: u64,
    /// Number of occupied slots in the bucket. This field can be computed by
    /// counting the actual number of SaltKeys in the bucket, so it does not
    /// participate in serialization or the computation of bucket commitment.
    pub used: Option<u64>,
}

impl Default for BucketMeta {
    /// Returns default bucket metadata with unknown usage statistics.
    ///
    /// This default represents a bucket with:
    /// - `nonce`: 0 (no rehashing operations performed)
    /// - `capacity`: MIN_BUCKET_SIZE (256 slots)
    /// - `used`: None (unknown, must be computed by counting actual entries)
    ///
    /// **Important**: A bucket with default metadata can still contain data entries.
    /// Default metadata simply means the bucket hasn't been explicitly resized or
    /// rehashed, but it may have been populated with entries that fit within the
    /// default capacity.
    fn default() -> Self {
        Self {
            nonce: 0,
            capacity: MIN_BUCKET_SIZE as u64,
            used: None,
        }
    }
}

impl TryFrom<&[u8]> for BucketMeta {
    type Error = SaltError;
    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        if bytes.len() != 12 {
            return Err(SaltError::InvalidFormat {
                message: "BucketMeta requires exactly 12 bytes",
            });
        }
        Ok(Self {
            nonce: u32::from_le_bytes(bytes[0..4].try_into().map_err(|_| {
                SaltError::InvalidFormat {
                    message: "Failed to parse nonce from bytes",
                }
            })?),
            capacity: u64::from_le_bytes(bytes[4..12].try_into().map_err(|_| {
                SaltError::InvalidFormat {
                    message: "Failed to parse capacity from bytes",
                }
            })?),
            used: None,
        })
    }
}

impl TryFrom<&SaltValue> for BucketMeta {
    type Error = SaltError;
    fn try_from(value: &SaltValue) -> Result<Self, Self::Error> {
        Self::try_from(value.key())
    }
}

impl BucketMeta {
    /// Serialize bucket metadata to a 12-byte little-endian byte array.
    ///
    /// Layout: `nonce`(4) | `capacity`(8)
    ///
    /// Note: The `used` field is not serialized as it can be computed dynamically.
    pub fn to_bytes(&self) -> [u8; 12] {
        let mut bytes = [0u8; 12];
        bytes[0..4].copy_from_slice(&self.nonce.to_le_bytes());
        bytes[4..12].copy_from_slice(&self.capacity.to_le_bytes());
        bytes
    }

    /// Checks if this bucket metadata represents default values.
    ///
    /// A bucket has default metadata when:
    /// - `nonce` is 0 (no rehashing operations performed)
    /// - `capacity` is `MIN_BUCKET_SIZE` (256 slots)
    ///
    /// The `used` field is ignored since it's computed dynamically and may vary
    /// even for buckets with otherwise default metadata.
    ///
    /// # Returns
    ///
    /// `true` if this metadata has default `nonce` and `capacity` values, `false` otherwise.
    pub fn is_default(&self) -> bool {
        self.nonce == 0 && self.capacity == MIN_BUCKET_SIZE as u64
    }
}

impl Serialize for BucketMeta {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let bytes = self.to_bytes();
        bytes.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for BucketMeta {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let bytes: [u8; 12] = <[u8; 12]>::deserialize(deserializer)?;
        BucketMeta::try_from(&bytes[..]).map_err(serde::de::Error::custom)
    }
}

/// 64-bit storage key encoding bucket and slot identifiers.
///
/// This is the key used by the underlying database to store SALT state.
///
/// Layout: `bucket_id` (high 24 bits) | `slot_id` (low 40 bits)
/// - Supports ~16M buckets (2^24)
/// - Supports ~1T slots per bucket (2^40)
#[derive(
    Clone,
    Copy,
    Deref,
    DerefMut,
    Debug,
    Default,
    PartialEq,
    Eq,
    Deserialize,
    Serialize,
    PartialOrd,
    Ord,
    Hash,
)]
pub struct SaltKey(pub u64);

impl SaltKey {
    /// Extract the 24-bit bucket ID from the high bits.
    #[inline]
    pub const fn bucket_id(&self) -> BucketId {
        (self.0 >> BUCKET_SLOT_BITS) as BucketId
    }

    /// Extract the 40-bit slot ID from the low bits.
    #[inline]
    pub const fn slot_id(&self) -> SlotId {
        self.0 as SlotId & BUCKET_SLOT_ID_MASK
    }

    /// Check if this key belongs to a metadata bucket (first 65,536 buckets).
    pub const fn is_in_meta_bucket(&self) -> bool {
        self.bucket_id() < NUM_META_BUCKETS as BucketId
    }

    /// Creates an inclusive range covering all possible SaltKeys within the given
    /// bucket range.
    ///
    /// This method generates a range from the first slot (0) of the start bucket
    /// to the last slot (BUCKET_SLOT_ID_MASK) of the end bucket.
    ///
    /// # Arguments
    /// * `start_bucket` - The first bucket ID in the range (inclusive)
    /// * `end_bucket` - The last bucket ID in the range (inclusive)
    ///
    /// # Returns
    /// An inclusive range covering all keys in the specified buckets.
    /// ```
    pub fn bucket_range(start_bucket: BucketId, end_bucket: BucketId) -> RangeInclusive<SaltKey> {
        SaltKey::from((start_bucket, 0))..=SaltKey::from((end_bucket, BUCKET_SLOT_ID_MASK))
    }
}

impl From<(BucketId, SlotId)> for SaltKey {
    #[inline]
    fn from(value: (BucketId, SlotId)) -> Self {
        Self(((value.0 as u64) << BUCKET_SLOT_BITS) + value.1)
    }
}

impl From<u64> for SaltKey {
    #[inline]
    fn from(value: u64) -> Self {
        Self(value)
    }
}

/// The maximum number of bytes that can be stored in a [`SaltValue`].
/// There are 3 types of [`SaltValue`]: `Account`, `Storage`, and `BucketMeta`.
///
/// For `Account`, the key length is 20 bytes, and the value length is either 40
/// (for EOA's) or 72 bytes (for smart contracts). So, encoding an `Account` requires:
///     `key_len`(1) + `value_len`(1) + `key`(20) + `value`(40 or 72) = 62 or 94 bytes.
///
/// For `Storage`, the key length is 52 bytes, and the value length is 32 bytes.
/// So, encoding a `Storage` requires:
///     `key_len`(1) + `value_len`(1) + `key`(52) + `value`(32) = 86 bytes.
///
/// For `BucketMeta`, the serialized form is 12 bytes (nonce:4 + capacity:8).
/// So, encoding a `BucketMetadata` requires:
///     `key_len`(1) + `value_len`(1) + `key`(12) + `value`(0) = 14 bytes.
///
/// Hence, the maximum number of bytes that can be stored in a [`SaltValue`] is 94,
/// which is the maximum of 94, 86, and 14.
pub const MAX_SALT_VALUE_BYTES: usize = 94;

/// Variable-length encoding of key-value pairs with length prefixes.
///
/// Format: `key_len` (1 byte) | `value_len` (1 byte) | `key` | `value`
/// Supports Account, Storage, and BucketMeta types.
#[derive(Clone, Debug, Deref, DerefMut, PartialEq, Eq, Serialize, Deserialize)]
#[repr(align(8))]
pub struct SaltValue {
    /// Fixed-size array accommodating the largest possible encoded data (94 bytes).
    #[deref]
    #[deref_mut]
    #[serde(with = "serde_arrays")]
    pub data: [u8; MAX_SALT_VALUE_BYTES],
}

impl SaltValue {
    /// Create a new encoded value from separate key and value byte slices.
    ///
    /// Encodes the data in the format: `key_len`(1) | `value_len`(1) | `key` | `value`
    pub fn new(key: &[u8], value: &[u8]) -> Self {
        let key_len = key.len();
        let value_len = value.len();

        let mut result = Self {
            data: [0u8; MAX_SALT_VALUE_BYTES],
        };
        result.data[0] = key_len as u8;
        result.data[1] = value_len as u8;
        result.data[2..2 + key_len].copy_from_slice(key);
        result.data[2 + key_len..2 + key_len + value_len].copy_from_slice(value);

        result
    }

    /// Extract the key portion from the encoded data.
    pub fn key(&self) -> &[u8] {
        let key_len = self.data[0] as usize;
        &self.data[2..2 + key_len]
    }

    /// Extract the value portion from the encoded data.
    pub fn value(&self) -> &[u8] {
        let key_len = self.data[0] as usize;
        let value_len = self.data[1] as usize;
        &self.data[2 + key_len..2 + key_len + value_len]
    }

    /// Returns the total length of the encoded data (header + key + value).
    ///
    /// This is the sum of:
    /// - 2 bytes for the length headers (key_len and value_len)
    /// - key length
    /// - value length
    pub fn data_len(&self) -> usize {
        let key_len = self.data[0] as usize;
        let value_len = self.data[1] as usize;
        2 + key_len + value_len
    }
}

impl From<BucketMeta> for SaltValue {
    fn from(value: BucketMeta) -> Self {
        Self::new(&value.to_bytes(), &[])
    }
}

impl TryFrom<SaltValue> for BucketMeta {
    type Error = SaltError;
    fn try_from(value: SaltValue) -> Result<Self, Self::Error> {
        Self::try_from(value.key())
    }
}

/// 64-bit unique identifier used to address nodes in both the main trie and
/// bucket subtrees (note: only regular data buckets can grow dynamically).
///
/// **Main trie structure (4 levels, 0-3):**
/// - Level 0 (root): 1 node
/// - Level 1: 256 nodes
/// - Level 2: 65,536 nodes
/// - Level 3: 16,777,216 nodes (bucket roots)
/// - Total: 16,843,009 nodes
///
/// **Bucket subtree structure (up to 5 levels, 0-4):**
/// - Level 0: 1 node (the root, addressed via main trie)
/// - Level 1: 256 nodes
/// - Level 2: 65,536 nodes
/// - Level 3: 16,777,216 nodes
/// - Level 4: 4,294,967,296 nodes
/// - Total: 4,311,810,305 nodes
///
/// **Node addressing scheme:**
///
/// *Main trie nodes (25 bits):*
/// - Uses lowest 25 bits for node position (25 bits needed since 2^25 > 16,843,009)
/// - BFS numbering: root=0, top-to-bottom, left-to-right
/// - Upper 39 bits unused (always 0)
/// - **Important**: Bucket roots are addressed as main trie nodes at level 3
///
/// *Bucket subtree nodes (24 + 33 bits):*
/// - Highest 24 bits: bucket ID (must be > 65,535 since meta buckets never grow)
/// - Lowest 40 bits: local position (33 bits needed since 2^33 > 4,311,810,305, 7 bits unused)
/// - Each subtree uses same BFS numbering starting from 0
/// - **Important**: Only used for internal subtree nodes (position > 0), never for roots
///
/// **Addressing bucket roots:**
/// Bucket roots can theoretically be addressed in two ways:
/// 1. As leaf nodes in the main trie (level 3) - e.g., bucket 0's root is at main trie position 16,843,008
/// 2. As position 0 in their own subtree - e.g., (bucket_id << 40 | 0)
///
/// To avoid ambiguity, **we always use the main trie addressing scheme (option 1)** for bucket roots.
/// This means a bucket root's NodeId has upper 39 bits = 0 and lower 25 bits = its main trie position.
///
/// **Examples:**
/// - Main trie root: NodeId = 0
/// - Bucket 0's root: NodeId = 65,793 (main trie level 3, position 0)
/// - Bucket 100000's root: NodeId = 165,793 (main trie level 3, position 100000)
/// - Bucket 100000's internal node at position 256: NodeId = (100000 << 40) | 256
pub type NodeId = u64;

/// Returns the local number of a node within its trie (either the main trie or
/// a bucket subtree) by clearing out the highest 24 bits in `NodeId`.
pub fn get_local_number(node_id: NodeId) -> u64 {
    node_id & BUCKET_SLOT_ID_MASK
}

/// Returns true if the given NodeId addresses a node in a bucket subtree.
///
/// According to the NodeId addressing scheme:
/// - If bucket_id (highest 24 bits) = 0: main trie node → returns false
/// - If bucket_id >= NUM_META_BUCKETS (65536): subtree node → returns true
/// - If bucket_id is 1-65535: INVALID (metadata buckets cannot have subtrees) → panics
#[inline]
pub fn is_subtree_node(node_id: NodeId) -> bool {
    let bucket_id = node_id >> BUCKET_SLOT_BITS;
    if bucket_id == 0 {
        false // Main trie node
    } else if bucket_id < NUM_META_BUCKETS as u64 {
        panic!("metadata buckets cannot have subtrees (bucket_id: {bucket_id})");
    } else {
        true // Subtree node
    }
}

/// Returns the BFS number of the leftmost node at the specified level in a complete N-ary tree.
///
/// In a breadth-first search (BFS) numbering scheme:
/// - The root node is numbered 0
/// - Node numbers increase with each level from top to bottom
/// - Within each level, nodes are numbered consecutively from left to right
///
/// This function calculates the number of the leftmost node at the given level using the
/// mathematical formula for the sum of a geometric series:
///
/// ```text
/// f(level) = (N^level - 1) / (N - 1)
/// ```
///
/// where N is `TRIE_WIDTH` (256 in this implementation).
///
/// # Arguments
///
/// * `level` - The 0-based level index. Level 0 is the root node.
///
/// # Returns
///
/// * `Some(node_id)` - The BFS number of the leftmost node at the specified level if it fits in a u64.
/// * `None` - If the result is too large for a u64.
///
/// # Examples
///
/// ```ignore
/// // Level 0 (root): BFS number = 0
/// assert_eq!(leftmost_node(0), Some(0));
///
/// // Level 1: BFS number = 1 (since there's 1 node at level 0)
/// assert_eq!(leftmost_node(1), Some(1));
///
/// // Level 2: BFS number = 257 (since there are 1 + 256 nodes at levels 0 and 1)
/// assert_eq!(leftmost_node(2), Some(257));
/// ```
pub const fn leftmost_node(level: u32) -> Option<u64> {
    if level == 0 {
        return Some(0);
    }

    // Compute the sum of the geometric series in an overflow-safe manner
    let width = TRIE_WIDTH as u128;
    let pow_result = match width.checked_pow(level) {
        Some(p) => p,
        None => return None,
    };
    let result = (pow_result - 1) / (width - 1);
    if result > u64::MAX as u128 {
        None // The result is valid but too large for a u64.
    } else {
        Some(result as u64) // It fits, so we can safely cast and return.
    }
}

/// Calculate the BFS level where the specified node is located in a complete 256-ary tree.
///
/// This function determines which level a given node belongs to by finding the highest level
/// whose starting BFS number is ≤ that of the given node.
///
/// # Arguments
/// * `bfs_number` - The node whose level to determine
///
/// # Returns
/// The level (0-based) where the node is located
pub fn get_bfs_level(bfs_number: u64) -> usize {
    for level in (0..=8).rev() {
        if let Some(leftmost) = leftmost_node(level) {
            if bfs_number >= leftmost {
                return level as usize;
            }
        }
    }
    unreachable!("n = {bfs_number} should always match at least level 0")
}

/// The valid range of metadata keys. Metadata keys span from bucket 0 slot 0
/// to bucket (NUM_META_BUCKETS-1) slot BUCKET_SLOT_ID_MASK.
pub const METADATA_KEYS_RANGE: RangeInclusive<SaltKey> =
    SaltKey(0)..=SaltKey(((NUM_META_BUCKETS - 1) as u64) << BUCKET_SLOT_BITS | BUCKET_SLOT_ID_MASK);

/// Checks if a bucket ID refers to a valid data bucket.
#[inline]
pub fn is_valid_data_bucket(bucket_id: BucketId) -> bool {
    bucket_id >= NUM_META_BUCKETS as BucketId && bucket_id < NUM_BUCKETS as BucketId
}

/// Calculate the SaltKey where bucket metadata is stored.
///
/// SALT uses a metadata storage scheme where each metadata bucket (first 65,536 buckets)
/// stores metadata for 256 regular buckets. Given a `bucket_id`, this function:
/// 1. Divides by 256 (>> 8 bits) to find the metadata bucket ID
/// 2. Takes modulo 256 to find the slot within that metadata bucket
///
/// This allows ~16M buckets to store their metadata in just 65,536 dedicated metadata buckets.
///
/// # Arguments
/// * `bucket_id` - The bucket ID whose metadata location to find. Must be a valid data
///   bucket ID (NUM_META_BUCKETS <= bucket_id < NUM_BUCKETS).
///
/// # Returns
/// SaltKey pointing to the metadata storage location
///
/// # Panics
/// Panics if `bucket_id` is not a valid data bucket:
/// - Meta buckets (0 to NUM_META_BUCKETS-1) don't have their own metadata
/// - Invalid bucket IDs (>= NUM_BUCKETS)
#[inline]
pub fn bucket_metadata_key(bucket_id: BucketId) -> SaltKey {
    assert!(
        is_valid_data_bucket(bucket_id),
        "bucket_id {bucket_id} must be a valid data bucket ID (range: {NUM_META_BUCKETS}..{NUM_BUCKETS})"
    );

    SaltKey::from((
        bucket_id >> MIN_BUCKET_SIZE_BITS,
        bucket_id as SlotId % MIN_BUCKET_SIZE as SlotId,
    ))
}

/// Extract the original bucket ID from a metadata storage key.
///
/// This is the inverse operation of [`bucket_metadata_key`]. Given a SaltKey that points
/// to a metadata storage location, reconstructs the original bucket ID whose metadata
/// is stored there.
///
/// The reconstruction works by:
/// 1. Taking the metadata bucket ID and shifting left by 8 bits (multiply by 256)
/// 2. Adding the slot ID (which represents the offset within the 256-bucket group)
///
/// # Arguments
/// * `key` - SaltKey pointing to a metadata storage location. Must be within
///   [`METADATA_KEYS_RANGE`] (i.e., a valid metadata key for a data bucket).
///
/// # Returns
/// The original bucket ID whose metadata is stored at this key
///
/// # Panics
/// Panics if the provided key is not within the valid metadata key range.
#[inline]
pub fn bucket_id_from_metadata_key(key: SaltKey) -> BucketId {
    assert!(
        METADATA_KEYS_RANGE.contains(&key),
        "SaltKey {key:?} is not in valid metadata key range"
    );
    (key.bucket_id() << MIN_BUCKET_SIZE_BITS) + key.slot_id() as BucketId
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Tests the basic operations of SaltKey: construction from bucket/slot pair and
    /// extraction of bucket ID and slot ID components. Verifies that the 64-bit layout
    /// correctly encodes bucket ID in high 24 bits and slot ID in low 40 bits.
    #[test]
    fn salt_key_operations() {
        let bucket_id = 0x123456;
        let slot_id = 0x789ABCDEF0;
        let key = SaltKey::from((bucket_id, slot_id));

        assert_eq!(key.bucket_id(), bucket_id);
        assert_eq!(key.slot_id(), slot_id);
        assert_eq!(key.0, ((bucket_id as u64) << 40) + slot_id);
    }

    /// Tests SaltKey behavior at the boundaries of its bit allocation. Verifies that
    /// maximum values (24-bit bucket ID, 40-bit slot ID) and minimum values (0, 0)
    /// are handled correctly without overflow or underflow issues.
    #[test]
    fn salt_key_boundaries() {
        // Test maximum values - ensures no overflow in bit shifting
        let max_bucket = (1u32 << 24) - 1; // 16,777,215 (24-bit max)
        let max_slot = (1u64 << 40) - 1; // 1,099,511,627,775 (40-bit max)
        let key = SaltKey::from((max_bucket, max_slot));

        assert_eq!(key.bucket_id(), max_bucket);
        assert_eq!(key.slot_id(), max_slot);

        // Test minimum values - ensures correct handling of zero values
        let key = SaltKey::from((0, 0));
        assert_eq!(key.bucket_id(), 0);
        assert_eq!(key.slot_id(), 0);
    }

    /// Tests the metadata bucket detection logic. SALT uses the first 65,536 buckets
    /// as metadata storage. This test verifies that is_bucket_meta_slot() correctly
    /// identifies whether a SaltKey points to a metadata storage location.
    #[test]
    fn salt_key_meta_bucket_detection() {
        let meta_key = SaltKey::from((100, 50)); // bucket 100 < 65536 (metadata)
        let regular_key = SaltKey::from((70000, 50)); // bucket 70000 >= 65536 (regular)

        assert!(meta_key.is_in_meta_bucket());
        assert!(!regular_key.is_in_meta_bucket());
    }

    /// Tests BucketMeta serialization and deserialization roundtrip. Verifies that
    /// the 12-byte little-endian encoding (nonce:4 + capacity:8) correctly
    /// preserves nonce and capacity values through serialize-then-deserialize operations.
    #[test]
    fn bucket_meta_serialization() {
        let meta = BucketMeta {
            nonce: 0x12345678,
            capacity: 0x123456789ABCDEF0,
            used: Some(100), // This value is not serialized
        };
        let bytes = meta.to_bytes();
        let recovered = BucketMeta::try_from(&bytes[..]).unwrap();

        assert_eq!(recovered.nonce, meta.nonce);
        assert_eq!(recovered.capacity, meta.capacity);
        assert_eq!(recovered.used, None); // Used field is not serialized
        assert_eq!(bytes.len(), 12);

        // Serialize using bincode (which will use our custom serde implementation)
        let bincode_bytes = bincode::serde::encode_to_vec(meta, bincode::config::legacy()).unwrap();

        assert_eq!(bincode_bytes, bytes);

        let bincode_recovered: BucketMeta =
            bincode::serde::decode_from_slice(&bincode_bytes, bincode::config::legacy())
                .unwrap()
                .0;

        assert_eq!(bincode_recovered, recovered);
    }

    /// Tests BucketMeta default constructor. Verifies that default values match
    /// expected initialization: nonce=0, capacity=MIN_BUCKET_SIZE (256), used=None.
    #[test]
    fn bucket_meta_default() {
        let meta = BucketMeta::default();
        assert_eq!(meta.nonce, 0);
        assert_eq!(meta.capacity, MIN_BUCKET_SIZE as u64);
        assert_eq!(meta.used, None);
    }

    /// Tests SaltValue encoding format: key_len(1) | value_len(1) | key | value.
    /// Verifies that arbitrary key-value pairs are correctly encoded with length
    /// prefixes and that extraction methods return the original data.
    #[test]
    fn salt_value_encoding() {
        let key = b"test_key";
        let value = b"test_value_data";
        let salt_value = SaltValue::new(key, value);

        assert_eq!(salt_value.key(), key);
        assert_eq!(salt_value.value(), value);
        assert_eq!(salt_value.data[0], key.len() as u8);
        assert_eq!(salt_value.data[1], value.len() as u8);
    }

    /// Tests conversion between BucketMeta and SaltValue. For metadata, the key
    /// contains the 12-byte serialized BucketMeta and the value is empty. Verifies
    /// bidirectional conversion preserves nonce and capacity correctly.
    #[test]
    fn salt_value_bucket_meta_conversion() {
        let meta = BucketMeta {
            nonce: 0xDEADBEEF,
            capacity: 1024,
            used: Some(100), // This value is not serialized
        };
        let salt_value = SaltValue::from(meta);

        assert_eq!(salt_value.data[0], 12); // key length (BucketMeta serialized size)
        assert_eq!(salt_value.data[1], 0); // value length (empty for metadata)

        let recovered_meta = BucketMeta::try_from(salt_value).unwrap();
        assert_eq!(recovered_meta.nonce, meta.nonce);
        assert_eq!(recovered_meta.capacity, meta.capacity);
        assert_eq!(recovered_meta.used, None); // Used field is not serialized
    }

    /// Tests the metadata storage mapping scheme. Each metadata bucket (0-65535) stores
    /// metadata for 256 regular buckets. bucket_metadata_key() divides bucket_id by 256
    /// to find the metadata bucket and uses modulo 256 for the slot within that bucket.
    #[test]
    fn bucket_metadata_key_mapping() {
        let test_cases = [
            // Only test valid data bucket IDs (>= NUM_META_BUCKETS)
            (NUM_META_BUCKETS as BucketId, 256, 0), // first data bucket -> meta bucket 256, slot 0
            (NUM_META_BUCKETS as BucketId + 1, 256, 1), // second data bucket -> meta bucket 256, slot 1
            (NUM_META_BUCKETS as BucketId + 255, 256, 255), // last slot in meta bucket 256
            (NUM_META_BUCKETS as BucketId + 256, 257, 0), // first slot in meta bucket 257
            (100000, 390, 160), // bucket 100000 -> meta bucket 390, slot 160 (100000 % 256)
            (NUM_BUCKETS as BucketId - 1, 65535, 255), // max bucket -> meta bucket 65535, slot 255
        ];

        for (bucket_id, expected_meta_bucket, expected_slot) in test_cases {
            let key = bucket_metadata_key(bucket_id);
            assert_eq!(
                key.bucket_id(),
                expected_meta_bucket,
                "bucket_id={}",
                bucket_id
            );
            assert_eq!(key.slot_id(), expected_slot, "bucket_id={}", bucket_id);
        }
    }

    /// Tests that bucket_metadata_key correctly panics for meta bucket IDs.
    #[test]
    #[should_panic]
    fn bucket_metadata_key_meta_bucket_panic() {
        let last_meta_bucket = NUM_META_BUCKETS as BucketId - 1;
        bucket_metadata_key(last_meta_bucket); // Last meta bucket
    }

    /// Tests that bucket_metadata_key correctly panics for invalid bucket IDs.
    #[test]
    #[should_panic]
    fn bucket_metadata_key_invalid_bucket_panic() {
        bucket_metadata_key(NUM_BUCKETS as BucketId); // >= NUM_BUCKETS
    }

    /// Tests the bidirectional conversion between bucket IDs and metadata storage keys.
    /// bucket_metadata_key() and bucket_id_from_metadata_key() should be perfect inverses,
    /// allowing any bucket ID to be mapped to a metadata key and back without loss.
    #[test]
    fn metadata_key_roundtrip() {
        let test_buckets = [
            NUM_META_BUCKETS as BucketId,     // First data bucket
            NUM_META_BUCKETS as BucketId + 1, // Second data bucket
            100000,                           // Arbitrary data bucket
            NUM_BUCKETS as BucketId - 1,      // Last valid bucket
        ];

        for bucket_id in test_buckets {
            let key = bucket_metadata_key(bucket_id);
            let recovered = bucket_id_from_metadata_key(key);
            assert_eq!(
                bucket_id, recovered,
                "Failed roundtrip for bucket {}",
                bucket_id
            );
        }
    }

    /// Tests that bucket_id_from_metadata_key correctly panics for keys outside the valid
    /// metadata key range. Only keys that correspond to actual data bucket metadata should
    /// be accepted.
    #[test]
    #[should_panic(expected = "SaltKey")]
    fn bucket_id_from_metadata_key_invalid_range_panic() {
        // Test with a key that's outside the valid metadata range
        // Use a key from a bucket beyond NUM_META_BUCKETS-1, which is outside metadata buckets
        let invalid_key = SaltKey::from((NUM_META_BUCKETS as u32, 0u64));
        bucket_id_from_metadata_key(invalid_key);
    }

    /// Tests BucketMeta deserialization error handling. The try_from implementation
    /// requires exactly 12 bytes for proper deserialization. Tests both
    /// insufficient data (should fail) and correct size data (should succeed).
    #[test]
    fn bucket_meta_error_handling() {
        // Test insufficient bytes - should return error
        let short_bytes = [1u8; 10];
        assert!(BucketMeta::try_from(&short_bytes[..]).is_err());

        // Test too many bytes - should return error
        let long_bytes = [1u8; 20];
        assert!(BucketMeta::try_from(&long_bytes[..]).is_err());

        // Test exactly 12 bytes (required) - should succeed
        let valid_bytes = [0u8; 12];
        assert!(BucketMeta::try_from(&valid_bytes[..]).is_ok());
    }

    /// Tests NodeId subtree node detection. Tests the three cases:
    /// - bucket_id = 0 (main trie): returns false
    /// - bucket_id >= NUM_META_BUCKETS (subtree): returns true
    /// - bucket_id 1-65535 (invalid): panics
    #[test]
    fn node_id_subtree_detection() {
        // Main trie nodes (bucket_id = 0) - should all return false
        let main_trie_nodes = [0, 1, 256, 65536, 16777216, 16843008];
        for node_id in main_trie_nodes {
            assert!(
                !is_subtree_node(node_id),
                "Main trie node {} incorrectly detected as subtree",
                node_id
            );
        }

        // Data bucket subtree nodes (bucket_id >= 65536) - should all return true
        let bucket_65536 = (65536u64 << BUCKET_SLOT_BITS) | 1;
        let bucket_100000 = (100000u64 << BUCKET_SLOT_BITS) | 1000;
        let bucket_max = (16777215u64 << BUCKET_SLOT_BITS) | 500;

        assert!(is_subtree_node(bucket_65536));
        assert!(is_subtree_node(bucket_100000));
        assert!(is_subtree_node(bucket_max));

        // Even bucket root addressing for data buckets should return true
        let bucket_root_65536 = 65536u64 << BUCKET_SLOT_BITS;
        assert!(is_subtree_node(bucket_root_65536));
    }

    /// Tests the leftmost_node function which calculates the NodeId of the leftmost node at a given level.
    ///
    /// For a complete 256-ary tree:
    /// - Level 0: 1 node        -> leftmost node ID = 0
    /// - Level 1: 256 nodes     -> leftmost node ID = 1
    /// - Level 2: 65,536 nodes  -> leftmost node ID = 1 + 256 = 257
    /// - Level 3: 16,777,216 nodes -> leftmost node ID = 1 + 256 + 65,536 = 65,793
    /// - Level 4: 4,294,967,296 nodes -> leftmost node ID = 1 + 256 + 65,536 + 16,777,216 = 16,843,009
    /// - ...
    /// - Level 9 and above: Overflow u64
    #[test]
    fn leftmost_node_calculation() {
        // Test level 0 (root node)
        assert_eq!(
            leftmost_node(0),
            Some(0),
            "Level 0 should have leftmost node at position 0"
        );

        // Test level 1
        assert_eq!(
            leftmost_node(1),
            Some(1),
            "Level 1 should have leftmost node at position 1"
        );

        // Test level 2: 1 + 256 = 257
        assert_eq!(
            leftmost_node(2),
            Some(257),
            "Level 2 should have leftmost node at position 257"
        );

        // Test level 3: 1 + 256 + 65536 = 65793
        assert_eq!(
            leftmost_node(3),
            Some(65793),
            "Level 3 should have leftmost node at position 65793"
        );

        // Test level 4: 1 + 256 + 65536 + 16777216 = 16843009
        assert_eq!(
            leftmost_node(4),
            Some(16843009),
            "Level 4 should have leftmost node at position 16843009"
        );

        // Test level 5: 1 + 256 + 65536 + 16777216 + 4294967296 = 4311810305
        assert_eq!(
            leftmost_node(5),
            Some(4311810305),
            "Level 5 should have leftmost node at position 4311810305"
        );

        // Test level 8: This should still fit in u64
        // For a 256-ary tree, level 8 would be at position:
        // (256^8 - 1) / 255 = 72340172838076673
        assert_eq!(
            leftmost_node(8),
            Some(72340172838076673),
            "Level 8 should have leftmost node at position 72340172838076673"
        );

        // Test level 9: This should overflow u64
        // For a 256-ary tree, level 9 would be at position:
        // (256^9 - 1) / 255 = 18519084246547628289
        // This is larger than u64::MAX (18446744073709551615)
        assert_eq!(
            leftmost_node(9),
            None,
            "Level 9 should overflow and return None"
        );

        // Test level 10: This should also overflow u64
        assert_eq!(
            leftmost_node(10),
            None,
            "Level 10 should overflow and return None"
        );
    }

    /// Tests BFS level detection for complete 256-ary trees. Both the main trie and bucket subtrees
    /// use BFS numbering to label its nodes. This test verifies that get_bfs_level correctly identifies
    /// the level for nodes at level boundaries and within each level.
    #[test]
    fn bfs_level_detection() {
        // Level 0: Root node only (ID 0)
        assert_eq!(get_bfs_level(0), 0, "Root node should be at level 0");

        // Level 1: Nodes 1-256 (256 nodes total)
        assert_eq!(get_bfs_level(1), 1, "First level 1 node");
        assert_eq!(get_bfs_level(128), 1, "Middle level 1 node");
        assert_eq!(get_bfs_level(256), 1, "Last level 1 node");

        // Level 2: Nodes 257-65,792 (65,536 nodes total)
        assert_eq!(get_bfs_level(257), 2, "First level 2 node");
        assert_eq!(get_bfs_level(32000), 2, "Middle level 2 node");
        assert_eq!(get_bfs_level(65792), 2, "Last level 2 node");

        // Level 3: Nodes 65,793-16,843,008 (16,777,216 nodes total)
        assert_eq!(get_bfs_level(65793), 3, "First level 3 node");
        assert_eq!(get_bfs_level(1000000), 3, "Middle level 3 node");
        assert_eq!(get_bfs_level(16843008), 3, "Last level 3 node");

        // Level 8: Nodes 72,340,172,838,076,673-18,519,084,246,547,628,288 (2^64 nodes total)
        assert_eq!(get_bfs_level(72340172838076673), 8, "First level 8 node");
        assert_eq!(get_bfs_level(9446744073709551615), 8, "Middle level 8 node");
        assert_eq!(get_bfs_level(u64::MAX), 8, "Largest node number in u64");
    }
}
