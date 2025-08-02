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

/// 64-bit unique identifier used to address nodes in both the main trie and bucket subtrees.
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
/// - Highest 24 bits: bucket ID (up to ~16M buckets)
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

    #[test]
    fn test_salt_value_and_meta() {
        let meta = BucketMeta {
            nonce: 1234,
            capacity: 512,
            used: 0,
        };
        let salt_value = SaltValue::from(meta);
        assert_eq!(salt_value.data[0], 20);
        assert_eq!(salt_value.data[1], 0);
        assert_eq!(
            u32::from_le_bytes(salt_value.data[2..6].try_into().unwrap()),
            1234
        );
        assert_eq!(
            u64::from_le_bytes(salt_value.data[6..14].try_into().unwrap()),
            512
        );
        assert_eq!(
            u64::from_le_bytes(salt_value.data[14..22].try_into().unwrap()),
            0
        );

        assert_eq!(meta, BucketMeta::try_from(&salt_value).unwrap());
    }
}
