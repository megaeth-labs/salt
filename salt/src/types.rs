//! Core data types for the SALT data structure.
//!
//! This module defines the fundamental types used throughout the SALT implementation:
//! - [`SaltKey`]: 64-bit addressing for bucket slots
//! - [`SaltValue`]: Variable-length encoding for key-value pairs
//! - [`BucketMeta`]: Bucket metadata (nonce, capacity, usage)
//! - [`NodeId`]: 64-bit identifiers for trie nodes
//! - Cryptographic types: [`CommitmentBytes`] and [`ScalarBytes`]

use crate::constant::{
    BUCKET_SLOT_BITS, BUCKET_SLOT_ID_MASK, MIN_BUCKET_SIZE, MIN_BUCKET_SIZE_BITS, NUM_META_BUCKETS,
};

use derive_more::{Deref, DerefMut};

/// 64-byte uncompressed group element for cryptographic commitments.
pub type CommitmentBytes = [u8; 64];

/// 32-byte scalar field element for cryptographic commitments.
pub type ScalarBytes = [u8; 32];

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

/// 24-bit bucket identifier (up to ~16M buckets).
pub type BucketId = u32;

/// 40-bit slot identifier within a bucket (up to ~1T slots).
pub type SlotId = u64;

/// Metadata for a bucket containing nonce, capacity, and usage statistics.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize, Serialize, PartialOrd, Ord, Hash)]
pub struct BucketMeta {
    /// Nonce for SHI hash table operations.
    pub nonce: u32,
    /// Total # slots of the bucket.
    pub capacity: u64,
    /// Number of occupied slots in the bucket. This field can be inferred from
    /// the bucket data, so it does not participate in the computation of bucket
    /// commitment.
    pub used: u64,
}

impl Default for BucketMeta {
    fn default() -> Self {
        Self {
            nonce: 0,
            capacity: MIN_BUCKET_SIZE as u64,
            used: 0,
        }
    }
}

impl TryFrom<&[u8]> for BucketMeta {
    type Error = &'static str;
    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        if bytes.len() < 20 {
            return Err("bytes length too short for BucketMeta");
        }
        Ok(Self {
            nonce: u32::from_le_bytes(bytes[0..4].try_into().map_err(|_| "nonce error")?),
            capacity: u64::from_le_bytes(bytes[4..12].try_into().map_err(|_| "capacity error")?),
            used: u64::from_le_bytes(bytes[12..20].try_into().map_err(|_| "used error")?),
        })
    }
}

impl TryFrom<&SaltValue> for BucketMeta {
    type Error = &'static str;
    fn try_from(value: &SaltValue) -> Result<Self, Self::Error> {
        Self::try_from(value.key())
    }
}

impl BucketMeta {
    /// Serialize bucket metadata to a 20-byte little-endian byte array.
    ///
    /// Layout: `nonce`(4) | `capacity`(8) | `used`(8)
    pub fn to_bytes(&self) -> [u8; 20] {
        let mut bytes = [0u8; 20];
        bytes[0..4].copy_from_slice(&self.nonce.to_le_bytes());
        bytes[4..12].copy_from_slice(&self.capacity.to_le_bytes());
        bytes[12..20].copy_from_slice(&self.used.to_le_bytes());
        bytes
    }
}

/// 64-bit key encoding bucket and slot identifiers.
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

    /// Check if this key addresses a metadata slot (first 65,536 buckets).
    pub const fn is_bucket_meta_slot(&self) -> bool {
        self.bucket_id() < NUM_META_BUCKETS as BucketId
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
/// For `BucketMeta`, the serialized form is 20 bytes (nonce:4 + capacity:8 + used:8).
/// So, encoding a `BucketMetadata` requires:
///     `key_len`(1) + `value_len`(1) + `key`(20) + `value`(0) = 22 bytes.
///
/// Hence, the maximum number of bytes that can be stored in a [`SaltValue`] is 94,
/// which is the maximum of 94, 86, and 22.
pub const MAX_SALT_VALUE_BYTES: usize = 94;

/// Variable-length encoding of key-value pairs with length prefixes.
///
/// Format: `key_len` (1 byte) | `value_len` (1 byte) | `key` | `value`
/// Supports Account, Storage, and BucketMeta types.
#[derive(Clone, Debug, Deref, DerefMut, PartialEq, Eq, Serialize, Deserialize)]
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

        let mut data = [0u8; MAX_SALT_VALUE_BYTES];
        data[0] = key_len as u8;
        data[1] = value_len as u8;
        data[2..2 + key_len].copy_from_slice(key);
        data[2 + key_len..2 + key_len + value_len].copy_from_slice(value);

        Self { data }
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
}

impl From<BucketMeta> for SaltValue {
    fn from(value: BucketMeta) -> Self {
        Self::new(&value.to_bytes(), &[])
    }
}

impl TryFrom<SaltValue> for BucketMeta {
    type Error = &'static str;
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
/// - Level 3: 16,777,216 nodes
/// - Total: 16,843,009 nodes
///
/// **Bucket subtree structure (up to 5 levels, 0-4):**
/// - Level 0: 1 node
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
/// - Upper 39 bits unused
///
/// *Bucket subtree nodes (24 + 33 bits):*
/// - Highest 24 bits: bucket ID (must be > 65,535 since meta buckets never grow)
/// - Lowest 40 bits: local position (33 bits needed since 2^33 > 4,311,810,305, 7 bits unused)
/// - Each subtree uses same BFS numbering as main trie
pub type NodeId = u64;

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
/// * `bucket_id` - The regular bucket ID whose metadata location to find
///
/// # Returns
/// SaltKey pointing to the metadata storage location
#[inline]
pub fn bucket_metadata_key(bucket_id: BucketId) -> SaltKey {
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
/// * `key` - SaltKey pointing to a metadata storage location
///
/// # Returns
/// The original bucket ID whose metadata is stored at this key
#[inline]
pub fn bucket_id_from_metadata_key(key: SaltKey) -> BucketId {
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

        assert!(meta_key.is_bucket_meta_slot());
        assert!(!regular_key.is_bucket_meta_slot());
    }

    /// Tests BucketMeta serialization and deserialization roundtrip. Verifies that
    /// the 20-byte little-endian encoding (nonce:4 + capacity:8 + used:8) correctly
    /// preserves all field values through serialize-then-deserialize operations.
    #[test]
    fn bucket_meta_serialization() {
        let meta = BucketMeta {
            nonce: 0x12345678,
            capacity: 0x123456789ABCDEF0,
            used: 0x987654321,
        };
        let bytes = meta.to_bytes();
        let recovered = BucketMeta::try_from(&bytes[..]).unwrap();

        assert_eq!(meta, recovered);
        assert_eq!(bytes.len(), 20);
    }

    /// Tests BucketMeta default constructor. Verifies that default values match
    /// expected initialization: nonce=0, capacity=MIN_BUCKET_SIZE (256), used=0.
    #[test]
    fn bucket_meta_default() {
        let meta = BucketMeta::default();
        assert_eq!(meta.nonce, 0);
        assert_eq!(meta.capacity, MIN_BUCKET_SIZE as u64);
        assert_eq!(meta.used, 0);
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
    /// contains the 20-byte serialized BucketMeta and the value is empty. Verifies
    /// bidirectional conversion preserves all metadata fields correctly.
    #[test]
    fn salt_value_bucket_meta_conversion() {
        let meta = BucketMeta {
            nonce: 0xDEADBEEF,
            capacity: 1024,
            used: 100,
        };
        let salt_value = SaltValue::from(meta);

        assert_eq!(salt_value.data[0], 20); // key length (BucketMeta serialized size)
        assert_eq!(salt_value.data[1], 0); // value length (empty for metadata)

        let recovered_meta = BucketMeta::try_from(salt_value).unwrap();
        assert_eq!(recovered_meta, meta);
    }

    /// Tests the metadata storage mapping scheme. Each metadata bucket (0-65535) stores
    /// metadata for 256 regular buckets. bucket_metadata_key() divides bucket_id by 256
    /// to find the metadata bucket and uses modulo 256 for the slot within that bucket.
    #[test]
    fn bucket_metadata_key_mapping() {
        let test_cases = [
            (0, 0, 0),         // bucket 0 -> meta bucket 0, slot 0
            (255, 0, 255),     // bucket 255 -> meta bucket 0, slot 255
            (256, 1, 0),       // bucket 256 -> meta bucket 1, slot 0
            (512, 2, 0),       // bucket 512 -> meta bucket 2, slot 0
            (1000, 3, 232),    // bucket 1000 -> meta bucket 3, slot 232 (1000 % 256)
            (65535, 255, 255), // bucket 65535 -> meta bucket 255, slot 255
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

    /// Tests the bidirectional conversion between bucket IDs and metadata storage keys.
    /// bucket_metadata_key() and bucket_id_from_metadata_key() should be perfect inverses,
    /// allowing any bucket ID to be mapped to a metadata key and back without loss.
    #[test]
    fn metadata_key_roundtrip() {
        let test_buckets = [0, 1, 255, 256, 1000, 65535, 100000, 16777215];

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

    /// Tests BucketMeta deserialization error handling. The try_from implementation
    /// requires exactly 20 bytes minimum for proper deserialization. Tests both
    /// insufficient data (should fail) and minimum valid data (should succeed).
    #[test]
    fn bucket_meta_error_handling() {
        // Test insufficient bytes - should return error
        let short_bytes = [1u8; 10];
        assert!(BucketMeta::try_from(&short_bytes[..]).is_err());

        // Test exactly 20 bytes (minimum required) - should succeed
        let valid_bytes = [0u8; 20];
        assert!(BucketMeta::try_from(&valid_bytes[..]).is_ok());
    }
}
