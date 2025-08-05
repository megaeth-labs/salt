#![allow(unexpected_cfgs)]

//! Define the types used for salt calculation and storage.
use crate::constant::{
    BUCKET_SLOT_BITS, BUCKET_SLOT_ID_MASK, MIN_BUCKET_SIZE, MIN_BUCKET_SIZE_BITS, NUM_META_BUCKETS,
};

use derive_more::{Deref, DerefMut};
pub use ffi_interface::CommitmentBytes;

use serde::{Deserialize, Serialize};

/// Represents the ID of a bucket.
pub type BucketId = u32;

/// Represents the ID of a slot.
pub type SlotId = u64;

/// This variable type is used to represent the meta value of a bucket.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct BucketMeta {
    /// nonce value of a bucket.
    pub nonce: u32,
    /// The capacity size of the bucket.
    pub capacity: u64,
    /// The number of slots that are currently used.
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
        if bytes.len() < 12 {
            return Err("bytes length too short for BucketMeta");
        }
        Ok(Self {
            nonce: u32::from_le_bytes(bytes[0..4].try_into().map_err(|_| "nonce error")?),
            capacity: u64::from_le_bytes(bytes[4..12].try_into().map_err(|_| "capacity error")?),
            used: 0,
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
    /// Creates a little-endian byte array from a `BucketMeta`.
    pub fn to_bytes(&self) -> [u8; 12] {
        let mut bytes = [0u8; 12];
        bytes[0..4].copy_from_slice(&self.nonce.to_le_bytes());
        bytes[4..12].copy_from_slice(&self.capacity.to_le_bytes());
        bytes
    }

    /// Updates the current `BucketMeta` using the values from [`SaltValue`].
    pub fn update(&mut self, value: &SaltValue) -> Result<(), &'static str> {
        let meta: Self = value.try_into()?;
        self.capacity = meta.capacity;
        self.nonce = meta.nonce;
        Ok(())
    }
}

/// The [`SaltKey`] type, its high 20 bits are the `bucket_id`, and low 40 bits
/// are the `slot_id`.
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
    /// Convert [`SaltKey`] to `bucket_id`.
    #[inline]
    pub const fn bucket_id(&self) -> BucketId {
        (self.0 >> BUCKET_SLOT_BITS) as BucketId
    }

    /// Convert [`SaltKey`] to `slot_id`.
    #[inline]
    pub const fn slot_id(&self) -> SlotId {
        self.0 as SlotId & BUCKET_SLOT_ID_MASK
    }

    /// Check if [`SaltKey`] is bucket meta slot.
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
/// There are 3 types of [`SaltValue`]: `Account`, `Storage`, and `BucketMetadata` (i.e.,
/// bucket nonce & capacity).
///
/// For `Account`, the key length is 20 bytes, and the value length is either 40
/// (for EOA's) or 72 bytes (for smart contracts). So, encoding an `Account` requires:
///     `key_len`(1) + `value_len`(1) + `key`(20) + `value`(40 or 72) = 62 or 94 bytes.
///
/// For `Storage`, the key length is 52 bytes, and the value length is 32 bytes.
/// So, encoding a `Storage` requires:
///     `key_len`(1) + `value_len`(1) + `key`(52) + `value`(32) = 86 bytes.
///
/// For `BucketMetadata`, the nonce and capacity are 4 and 8 bytes, respectively.
/// So, encoding a `BucketMetadata` requires:
///     `key_len`(1) + `value_len`(1) + `key`(4) + `value`(8) = 14 bytes.
///
/// Hence, the maximum number of bytes that can be stored in a [`SaltValue`] is 94,
/// which is the maximum of 94, 86, and 14.
pub const MAX_SALT_VALUE_BYTES: usize = 94;

/// Encodes `PlainKey` and `PlainValue` into a single byte array.
#[derive(Clone, Debug, Deref, DerefMut, PartialEq, Eq, Serialize, Deserialize)]
pub struct SaltValue {
    /// A byte array large enough to store any type of [`SaltValue`].
    #[deref]
    #[deref_mut]
    #[serde(with = "serde_arrays")]
    pub data: [u8; MAX_SALT_VALUE_BYTES],
}

impl SaltValue {
    /// Creates a new [`SaltValue`] instance.
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

    /// Returns the key of the [`SaltValue`].
    pub fn key(&self) -> &[u8] {
        let key_len = self.data[0] as usize;
        &self.data[2..2 + key_len]
    }

    /// Returns the value of the [`SaltValue`].
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

/// The data of salt trie will be persisted in the form of [`NodeId`]
/// and [`Commitment`].
pub type NodeId = u64;

/// Return the position of the bucket meta for given bucket id.
#[inline]
pub fn meta_position(bucket_id: BucketId) -> SaltKey {
    SaltKey::from((
        bucket_id >> MIN_BUCKET_SIZE_BITS,
        bucket_id as SlotId % MIN_BUCKET_SIZE as SlotId,
    ))
}

/// Return the bucket id of the bucket meta for given salt key.
#[inline]
pub fn meta_bucket_id(key: SaltKey) -> BucketId {
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
        assert_eq!(salt_value.data[0], 12);
        assert_eq!(salt_value.data[1], 0);
        assert_eq!(
            u32::from_le_bytes(salt_value.data[2..6].try_into().unwrap()),
            1234
        );
        assert_eq!(
            u64::from_le_bytes(salt_value.data[6..14].try_into().unwrap()),
            512
        );

        assert_eq!(meta, BucketMeta::try_from(&salt_value).unwrap());
    }
}
