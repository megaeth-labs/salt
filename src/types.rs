#![allow(unexpected_cfgs)]

//! Define the types used for salt calculation and storage.

use crate::constant::{BUCKET_SLOT_BITS, MIN_BUCKET_SIZE, MIN_BUCKET_SIZE_BITS};
pub use alloy_primitives::Bytes;
use alloy_primitives::{bytes::Buf, Address, B256, B512, U256};
use alloy_rlp::{BufMut, Decodable, Encodable};
pub use ffi_interface::CommitmentBytes;
use reth_codecs::{decode_varuint, derive_arbitrary, encode_varuint, Compact};
use reth_primitives_traits::Account;
use serde::{Deserialize, Serialize};
use std::ops::Deref;

/// Key of PlainAccount/StorageState.
#[derive(Hash, Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum PlainKey {
    /// Key of plainAccountState.
    Account(Address),
    /// Key of plainStorageState: (address,  storage slot).
    Storage(Address, B256),
}

/// data length of Key of Storage Slot
const SLOT_KEY_LEN: usize = B256::len_bytes();
/// data length of Key of Account
const PLAIN_ACCOUNT_KEY_LEN: usize = Address::len_bytes();
/// data length of Key of Storage
const PLAIN_STORAGE_KEY_LEN: usize = PLAIN_ACCOUNT_KEY_LEN + SLOT_KEY_LEN;

impl PlainKey {
    /// Convert PlainKey to Vec.
    pub fn encode(&self) -> Vec<u8> {
        match self {
            PlainKey::Account(addr) => addr.as_slice().to_vec(),
            PlainKey::Storage(addr, slot) => {
                addr.concat_const::<SLOT_KEY_LEN, PLAIN_STORAGE_KEY_LEN>(*slot).as_slice().to_vec()
            }
        }
    }

    fn decode(buf: &[u8]) -> Self {
        match buf.len() {
            PLAIN_ACCOUNT_KEY_LEN => PlainKey::Account(Address::from_slice(buf)),
            PLAIN_STORAGE_KEY_LEN => {
                let addr = Address::from_slice(&buf[..PLAIN_ACCOUNT_KEY_LEN]);
                let slot_id = B256::from_slice(&buf[PLAIN_ACCOUNT_KEY_LEN..]);
                PlainKey::Storage(addr, slot_id)
            }
            _ => unreachable!("unexpected length of plain key."),
        }
    }
}

impl From<&SaltValue> for (PlainKey, PlainValue) {
    #[inline]
    fn from(salt_value: &SaltValue) -> Self {
        let key_len = salt_value.data[0] as usize;
        let value_len = salt_value.data[1] as usize;
        let key = PlainKey::decode(salt_value.data[2..2 + key_len].as_ref());
        let value =
            PlainValue::decode(salt_value.data[2 + key_len..2 + key_len + value_len].as_ref());
        (key, value)
    }
}

impl From<Address> for PlainKey {
    #[inline]
    fn from(addr: Address) -> Self {
        PlainKey::Account(addr)
    }
}

impl From<(Address, B256)> for PlainKey {
    #[inline]
    fn from((addr, storage): (Address, B256)) -> Self {
        PlainKey::Storage(addr, storage)
    }
}

/// Value of PlainAccount/StorageState.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PlainValue {
    /// If Account is empty, means the account should be deleted.
    Account(Account),
    /// Value of plainStorageState.
    Storage(U256),
}

const U64_BYTES_LEN: usize = 8;
const BALANCE_BYTES_LEN: usize = U256::BYTES;
/// data length of Value of Account(Contract)
const PLAIN_EOA_ACCOUNT_LEN: usize = U64_BYTES_LEN + BALANCE_BYTES_LEN;
/// data length of Value of Account(EOA)
const PLAIN_CONTRACT_ACCOUNT_LEN: usize = PLAIN_EOA_ACCOUNT_LEN + B256::len_bytes();
/// data length of Value of Storage
const PLAIN_STORAGE_LEN: usize = U256::BYTES;

impl PlainValue {
    /// Return true if plain value is empty.
    pub fn is_empty(&self) -> bool {
        match self {
            PlainValue::Account(op_account) => op_account.is_empty(),
            PlainValue::Storage(value) => value.is_zero(),
        }
    }

    /// Convert PlainValue to Vec.
    pub fn encode(&self) -> Vec<u8> {
        match self {
            PlainValue::Account(account) => {
                let mut buffer = [0; PLAIN_CONTRACT_ACCOUNT_LEN];
                buffer[..U64_BYTES_LEN].copy_from_slice(account.nonce.to_be_bytes().as_ref());
                buffer[U64_BYTES_LEN..PLAIN_EOA_ACCOUNT_LEN]
                    .copy_from_slice(account.balance.to_be_bytes::<BALANCE_BYTES_LEN>().as_ref());
                if let Some(bytecode_hash) = account.bytecode_hash {
                    buffer[PLAIN_EOA_ACCOUNT_LEN..PLAIN_CONTRACT_ACCOUNT_LEN]
                        .copy_from_slice(bytecode_hash.as_slice());
                    buffer.to_vec()
                } else {
                    buffer[..PLAIN_EOA_ACCOUNT_LEN].to_vec()
                }
            }
            PlainValue::Storage(value) => value.to_be_bytes::<PLAIN_STORAGE_LEN>().to_vec(),
        }
    }

    /// Decode Vec to PlainValue.
    pub fn decode(buf: &[u8]) -> Self {
        match buf.len() {
            PLAIN_EOA_ACCOUNT_LEN => {
                let nonce = u64::from_be_bytes(buf[..U64_BYTES_LEN].try_into().unwrap());
                let balance = U256::from_be_slice(&buf[U64_BYTES_LEN..PLAIN_EOA_ACCOUNT_LEN]);
                PlainValue::Account(Account { nonce, balance, bytecode_hash: None })
            }
            PLAIN_CONTRACT_ACCOUNT_LEN => {
                let nonce = u64::from_be_bytes(buf[..U64_BYTES_LEN].try_into().unwrap());
                let balance = U256::from_be_slice(&buf[U64_BYTES_LEN..PLAIN_EOA_ACCOUNT_LEN]);
                let bytecode_hash =
                    B256::from_slice(&buf[PLAIN_EOA_ACCOUNT_LEN..PLAIN_CONTRACT_ACCOUNT_LEN]);
                PlainValue::Account(Account { nonce, balance, bytecode_hash: Some(bytecode_hash) })
            }
            PLAIN_STORAGE_LEN => PlainValue::Storage(U256::from_be_slice(&buf)),
            _ => unreachable!("unexpected length of plain value."),
        }
    }
}

impl From<Account> for PlainValue {
    #[inline]
    fn from(account: Account) -> Self {
        PlainValue::Account(account)
    }
}

impl From<U256> for PlainValue {
    #[inline]
    fn from(value: U256) -> Self {
        PlainValue::Storage(value)
    }
}

impl From<PlainValue> for Account {
    #[inline]
    fn from(value: PlainValue) -> Self {
        match value {
            PlainValue::Account(account) => account,
            _ => unreachable!("PlainValue is not Account"),
        }
    }
}

impl From<PlainValue> for U256 {
    #[inline]
    fn from(value: PlainValue) -> Self {
        match value {
            PlainValue::Storage(value) => value,
            _ => unreachable!("PlainValue is not U256"),
        }
    }
}

/// Represents the ID of a bucket.
pub type BucketId = u32;

/// Represents the ID of a slot.
pub type SlotId = u64;

/// This variable type is used to represent the meta value of a bucket.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize, Serialize, PartialOrd, Ord, Hash)]
pub struct BucketMeta {
    /// nonce value of a bucket.
    pub nonce: u32,
    /// The capacity size of the bucket.
    pub capacity: u64,
    /// The number of slots that are currently load.
    pub load: u64,
}

impl Default for BucketMeta {
    fn default() -> Self {
        BucketMeta { nonce: 0, capacity: MIN_BUCKET_SIZE as u64, load: 0 }
    }
}

impl From<&[u8]> for BucketMeta {
    fn from(bytes: &[u8]) -> Self {
        Self {
            nonce: u32::from_le_bytes(bytes[0..4].try_into().expect("bytes to nonce error")),
            capacity: u64::from_le_bytes(bytes[4..12].try_into().expect("bytes to capacity error")),
            load: u64::from_le_bytes(bytes[12..20].try_into().expect("bytes to load error")),
        }
    }
}

impl From<&SaltValue> for BucketMeta {
    fn from(value: &SaltValue) -> Self {
        value.key().into()
    }
}

impl BucketMeta {
    /// Creates a little-endian byte array from a BucketMeta.
    pub fn to_bytes(&self) -> [u8; 20] {
        let mut bytes = [0u8; 20];
        bytes[0..4].copy_from_slice(&self.nonce.to_le_bytes());
        bytes[4..12].copy_from_slice(&self.capacity.to_le_bytes());
        bytes[12..20].copy_from_slice(&self.load.to_le_bytes());
        bytes
    }
}

/// The [`SaltKey`] type, its high 32 bits are the bucket_id, and low 32 bits
/// are the slot_id.
#[derive_arbitrary(compact)]
#[derive(
    Clone, Copy, Debug, Default, PartialEq, Eq, Deserialize, Serialize, PartialOrd, Ord, Hash,
)]
pub struct SaltKey(pub u64);

impl From<(BucketId, SlotId)> for SaltKey {
    #[inline]
    fn from(value: (BucketId, SlotId)) -> Self {
        Self(((value.0 as u64) << BUCKET_SLOT_BITS) + value.1 as u64)
    }
}

impl From<u64> for SaltKey {
    fn from(value: u64) -> Self {
        Self(value)
    }
}

impl SaltKey {
    /// Convert [`SaltKey`] to `bucket_id`.
    #[inline]
    pub fn bucket_id(&self) -> BucketId {
        (self.0 >> BUCKET_SLOT_BITS) as BucketId
    }
    /// Convert [`SaltKey`] to `slot_id`.
    #[inline]
    pub fn slot_id(&self) -> SlotId {
        self.0 as SlotId & ((1 << BUCKET_SLOT_BITS as SlotId) - 1)
    }
}

impl Compact for SaltKey {
    #[inline]
    fn to_compact<B>(&self, buf: &mut B) -> usize
    where
        B: bytes::BufMut + AsMut<[u8]>,
    {
        buf.put_u64(self.0);
        8
    }

    #[inline]
    fn from_compact(mut buf: &[u8], _len: usize) -> (Self, &[u8]) {
        let value = buf.get_u64();
        (SaltKey(value), buf)
    }
}

/// The maximum number of bytes that can be stored in a [`SaltValue`].
/// There are 3 types of [`SaltValue`]: Account, Storage, and BucketMetadata (i.e.,
/// bucket nonce & capacity).
///
/// For Account, the key length is 20 bytes, and the value length is either 40
/// (for EOA's) or 72 bytes (for smart contracts). So, encoding an Account requires:
///     key_len(1) + value_len(1) + key(20) + value(40 or 72) = 62 or 94 bytes.
///
/// For Storage, the key length is 52 bytes, and the value length is 32 bytes.
/// So, encoding a Storage requires:
///     key_len(1) + value_len(1) + key(52) + value(32) = 86 bytes.
///
/// For BucketMetadata, the nonce and capacity are 4 and 8 bytes, respectively.
/// So, encoding a BucketMetadata requires:
///     key_len(1) + value_len(1) + key(4) + value(8) = 14 bytes.
///
/// Hence, the maximum number of bytes that can be stored in a [`SaltValue`] is 94,
/// which is the maximum of 94, 86, and 14.
pub const MAX_SALT_VALUE_BYTES: usize = 94;

/// Encodes PlainKey and PlainValue into a single byte array.
#[derive_arbitrary(compact)]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SaltValue {
    /// A byte array large enough to store any type of SaltValue.
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
        data[2..2 + key_len].copy_from_slice(&key);
        data[2 + key_len..2 + key_len + value_len].copy_from_slice(&value);

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

    /// Compute new [`SaltValue`] from old [`SaltValue`] and [`SaltValueDelta`].
    #[inline]
    pub fn compute(old_value: &Self, delta: &SaltValueDelta) -> Self {
        let buf = compute_xor(&old_value.data, delta);
        Self::from_compact(&buf, buf.len()).0
    }
}

impl From<BucketMeta> for SaltValue {
    fn from(value: BucketMeta) -> Self {
        Self::new(&value.to_bytes(), &[])
    }
}

impl Compact for SaltValue {
    /// Encode [`SaltValue`] into [u8].
    #[inline]
    fn to_compact<B>(&self, buf: &mut B) -> usize
    where
        B: bytes::BufMut + AsMut<[u8]>,
    {
        buf.put_slice(&self.data[..]);
        MAX_SALT_VALUE_BYTES
    }

    /// Decode [u8] to [`SaltValue`].
    #[inline]
    fn from_compact(buf: &[u8], _len: usize) -> (Self, &[u8]) {
        let mut data = [0u8; MAX_SALT_VALUE_BYTES];
        data.copy_from_slice(&buf[0..MAX_SALT_VALUE_BYTES]);
        (Self { data }, &buf[MAX_SALT_VALUE_BYTES..])
    }
}

impl From<(PlainKey, PlainValue)> for SaltValue {
    #[inline]
    fn from((key, value): (PlainKey, PlainValue)) -> Self {
        let key_bytes = key.encode();
        let value_bytes = value.encode();
        Self::new(&key_bytes, &value_bytes)
    }
}

impl From<SaltValue> for (PlainKey, PlainValue) {
    #[inline]
    fn from(salt_value: SaltValue) -> Self {
        let key_len = salt_value.data[0] as usize;
        let value_len = salt_value.data[1] as usize;
        let key = PlainKey::decode(salt_value.data[2..2 + key_len].as_ref());
        let value =
            PlainValue::decode(salt_value.data[2 + key_len..2 + key_len + value_len].as_ref());
        (key, value)
    }
}

/// Represents all kvs in a range of continuous bucket(s).
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct Buckets(pub Vec<(SaltKey, SaltValue)>);

impl Encodable for Buckets {
    fn encode(&self, out: &mut dyn BufMut) {
        self.0.len().encode(out);
        for (k, v) in &self.0 {
            k.0.encode(out);
            v.data.encode(out);
        }
    }

    fn length(&self) -> usize {
        let mut length = self.0.len().length();
        for (k, v) in &self.0 {
            length += k.0.length();
            length += v.data.length();
        }
        length
    }
}

impl Decodable for Buckets {
    fn decode(buf: &mut &[u8]) -> alloy_rlp::Result<Self> {
        let len = usize::decode(buf)?;
        let mut kvs = Vec::with_capacity(len);
        for _ in 0..len {
            let key = u64::decode(buf)?;
            let data = <[u8; MAX_SALT_VALUE_BYTES]>::decode(buf)?;
            kvs.push((SaltKey(key), SaltValue { data }))
        }
        Ok(Self(kvs))
    }
}

/// The data of salt trie will be persisted in the form of [`NodeId`]
/// and [`Commitment`].
pub type NodeId = u64;

/// [`Commitment`] is an encapsulation of a [`Commitment`] for easy
/// encoding.
pub type Commitment = B512;

/// The XOR delta between the old and new SaltValue's. To handle SaltValue's
/// with different lengths, we first pad the shorter one with leading 0's,
/// and then perform a byte-wise XOR operation between the two SaltValue's.
#[derive_arbitrary(compact)]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SaltValueDelta(pub Vec<u8>);

impl Deref for SaltValueDelta {
    type Target = Vec<u8>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl AsRef<[u8]> for SaltValueDelta {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl SaltValueDelta {
    /// Construct a new delta by XOR'ing two [`SaltValue`]'s.
    pub fn new(old: &SaltValue, new: &SaltValue) -> Self {
        Self(compute_xor(&old.data, &new.data))
    }
}

impl Compact for SaltValueDelta {
    /// Encode [`SaltValueDelta`] into [u8].
    #[inline]
    fn to_compact<B>(&self, buf: &mut B) -> usize
    where
        B: bytes::BufMut + AsMut<[u8]>,
    {
        let mut len = self.0.len();
        len += encode_varuint(len, buf);
        buf.put_slice(&self.0);
        len
    }

    /// Decode [u8] to [`SaltValueDelta`].
    #[inline]
    fn from_compact(buf: &[u8], _len: usize) -> (Self, &[u8]) {
        let (len, mut buf) = decode_varuint(buf);
        let value = Vec::<u8>::from(&buf[..len]);
        buf.advance(len);
        (Self(value), buf)
    }
}

/// Performs a byte-by-byte XOR operation between two byte slices of arbitrary length.
/// If the slices have different lengths, the shorter slice is padded with zeros at the
/// beginning.
///
/// To ensure that, given the XOR result and one of the input slices, the other slice
/// can be recovered using this method, both input slices must have non-zero most
/// significant bytes. Additionally, any leading zeros in the result will be trimmed.
///
/// # Examples
///
/// ```
/// use megaeth_salt::compute_xor;
///
/// let a = vec![1, 2, 3];
/// let b = vec![4, 5, 6, 7];
/// let delta = compute_xor(&a, &b);
/// assert_eq!(delta, vec![4, 4, 4, 4]);
/// ```
#[inline]
pub fn compute_xor(a: &[u8], b: &[u8]) -> Vec<u8> {
    // Determine which slice is longer and which is shorter
    let (a, b) = if a.len() > b.len() { (a, b) } else { (b, a) };
    let max_len = a.len();
    let pad_size = max_len - b.len();

    // Initialize the result vector with capacity of the longer slice
    let mut result = Vec::with_capacity(max_len);

    // Flag to track leading zeros
    let mut iterating_leading_zero = true;

    // Iterate over the range of the maximum length
    for i in 0..max_len {
        // Compute the XOR of the corresponding bytes
        let xor_byte = a[i] ^ if i >= pad_size { b[i - pad_size] } else { 0 };

        // Push the XOR result to the result vector if it's not a leading zero
        if xor_byte != 0 || !iterating_leading_zero {
            iterating_leading_zero = false;
            result.push(xor_byte);
        }
    }

    result
}

/// Return the position of the bucket meta for given bucket id.
#[inline]
pub fn meta_slot_id(bucket_id: BucketId) -> SaltKey {
    SaltKey::from((
        bucket_id >> MIN_BUCKET_SIZE_BITS,
        bucket_id as SlotId % MIN_BUCKET_SIZE as SlotId,
    ))
}

#[cfg(test)]
mod tests {
    use alloy_primitives::address;

    use super::*;

    #[test]
    fn test_salt_value_and_meta() {
        let meta = BucketMeta { nonce: 1234, capacity: 512, load: 0 };
        let salt_value = SaltValue::from(meta);
        assert_eq!(salt_value.data[0], 20);
        assert_eq!(salt_value.data[1], 0);
        assert_eq!(u32::from_le_bytes(salt_value.data[2..6].try_into().unwrap()), 1234);
        assert_eq!(u64::from_le_bytes(salt_value.data[6..14].try_into().unwrap()), 512);
        assert_eq!(u64::from_le_bytes(salt_value.data[14..22].try_into().unwrap()), 0);

        assert_eq!(meta, BucketMeta::from(&salt_value));
    }

    #[test]
    fn test_get_delta_no_padding() {
        let vec1 = vec![1, 2, 3, 4];
        let vec2 = vec![4, 3, 2, 1];
        let expected_diff = vec![5, 1, 1, 5]; // 1^4=5, 2^3=1, 3^2=1, 4^1=5

        let diff = compute_xor(&vec1, &vec2);
        assert_eq!(diff, expected_diff);

        let vec3 = vec![1, 2, 3, 4];
        let vec4 = vec![1, 2, 2, 1];
        let expected_diff = vec![1, 5]; // 1^1=0, 2^2=0, 3^2=1, 4^1=5

        let diff = compute_xor(&vec3, &vec4);
        assert_eq!(diff, expected_diff);
    }

    #[test]
    fn test_get_delta_with_padding() {
        let vec1 = vec![1, 2];
        let vec2 = vec![1, 2, 3, 4];
        let expected_diff = vec![1, 2, 2, 6]; // 1^0=1, 2^0=2, 1^3=2, 2^4=6

        let diff = compute_xor(&vec1, &vec2);
        assert_eq!(diff, expected_diff);
        let diff = compute_xor(&vec2, &vec1);
        assert_eq!(diff, expected_diff);
    }

    #[test]
    fn test_merge_delta_no_padding() {
        let vec1 = vec![1, 2, 3, 4];
        let diff = vec![5, 1, 1, 5]; // 1^4=5, 2^3=1, 3^2=1, 4^1=5
        let vec2 = vec![4, 3, 2, 1]; // 1^5=4, 2^1=3, 3^1=2, 4^5=1

        let merged = compute_xor(&vec1, &diff);
        assert_eq!(merged, vec2);

        let vec1 = vec![1, 2, 3, 4];
        let diff = vec![1, 5]; // 1^0=1, 2^0=2, 3^1=1, 4^5=1
        let vec2 = vec![1, 2, 2, 1];

        let merged = compute_xor(&vec1, &diff);
        assert_eq!(merged, vec2);
    }

    #[test]
    fn test_merge_delta_with_padding() {
        let vec1 = vec![1, 2];
        let diff = vec![1, 2, 2, 6];
        let vec2 = vec![1, 2, 3, 4]; // 1^0=1, 2^0=2, 2^1=3, 6^2=4

        let merged = compute_xor(&vec1, &diff);
        assert_eq!(merged, vec2);
        let merged = compute_xor(&vec2, &diff);
        assert_eq!(merged, vec1);
    }

    #[test]
    fn test_get_and_merge_delta() {
        let vec1 = vec![1, 2, 3, 4];
        let vec2 = vec![2, 3, 4];
        let diff = compute_xor(&vec1, &vec2);
        let merged = compute_xor(&vec2, &diff);
        assert_eq!(merged, vec1);

        let vec1 = vec![1, 2, 3, 4];
        let vec2 = vec![2, 3, 4, 5, 6];
        let vec3 = vec![3, 4, 5, 6, 7, 8];
        let vec4 = vec![4, 5, 6, 7, 8, 9, 10];
        let vec5 = vec![5, 6, 7, 8, 9, 10];
        let diff1 = compute_xor(&vec1, &vec2);
        let diff2 = compute_xor(&vec2, &vec3);
        let diff3 = compute_xor(&vec3, &vec4);
        let diff4 = compute_xor(&vec4, &vec5);
        let total_diff = compute_xor(&diff1, &diff2);
        let total_diff = compute_xor(&total_diff, &diff3);
        let total_diff = compute_xor(&total_diff, &diff4);
        let merged = compute_xor(&vec5, &total_diff);
        assert_eq!(merged, vec1);
    }

    #[test]
    fn test_salt_value_delta_new() {
        // Test case 1: Both old and new values are the same
        let old = SaltValue::new(b"key", &vec![1, 2, 3]);
        let new = SaltValue::new(b"key", &vec![1, 2, 3]);
        let delta = SaltValueDelta::new(&old, &new);
        assert_eq!(delta.0, Vec::<u8>::new()); // XOR of same values should be all zeros

        // Test case 2: Old and new values are different
        let old = SaltValue::new(b"key", &vec![1, 2, 3]);
        let new = SaltValue::new(b"key", &vec![4, 5, 6]);
        let delta = SaltValueDelta::new(&old, &new);
        assert_eq!(delta.0[0..3], vec![5, 7, 5]); // XOR of 1^4=5, 2^5=7, 3^6=5
        let new_salt_value_slice = compute_xor(old.data.as_slice(), &delta);
        assert_eq!(new_salt_value_slice, new.data.to_vec());

        // Test case 3: Old value is shorter than new value
        let old = SaltValue::new(b"loooooong", &vec![1, 2, 3]);
        let new = SaltValue::new(b"short", &vec![1, 2, 7]);
        let delta = SaltValueDelta::new(&old, &new);
        // XOR of 9^5=12, 3^3=0, 108^115=31, 111^104=7, 111^111=0, 111^114=29, 111^116=27,
        // 111^1=110, 111^2=109, 110^7=105, 103^0=103, 1^0=1, 2^0=2, 3^0=3
        assert_eq!(delta.0[0..14], [12, 0, 31, 7, 0, 29, 27, 110, 109, 105, 103, 1, 2, 3]);
        let new_salt_value_slice = compute_xor(old.data.as_slice(), &delta);
        assert_eq!(new_salt_value_slice, new.data.to_vec());

        // Test case 4: Old value is longer than new value
        let old = SaltValue::new(b"short", &vec![1, 2, 7]);
        let new = SaltValue::new(b"loooooong", &vec![1, 2, 3]);
        let delta = SaltValueDelta::new(&old, &new);
        // XOR of 9^5=12, 3^3=0, 108^115=31, 111^104=7, 111^111=0, 111^114=29, 111^116=27,
        // 111^1=110, 111^2=109, 110^7=105, 103^0=103, 1^0=1, 2^0=2, 3^0=3
        assert_eq!(delta.0[0..14], [12, 0, 31, 7, 0, 29, 27, 110, 109, 105, 103, 1, 2, 3]);
        let new_salt_value_slice = compute_xor(&old.data, &delta);
        assert_eq!(new_salt_value_slice, new.data.to_vec());
    }

    #[test]
    fn test_salt_value_to_plainkey_plainvalue() {
        let address = address!("8ba1f109551bD432803012645Ac136ddd64DBA72");
        let acc = Account {
            nonce: 100,
            balance: U256::from_limbs([256; U256::LIMBS]),
            bytecode_hash: None,
        };

        let plain_key = PlainKey::Account(address);
        let plain_value = PlainValue::Account(acc);

        let salt_value: SaltValue = (plain_key, plain_value).into();

        let (plain_key_recover, plain_value_recover) = salt_value.into();
        assert_eq!(plain_key, plain_key_recover);
        assert_eq!(plain_value, plain_value_recover);

        let plain_key = PlainKey::Storage(address, B256::random());
        let plain_value = PlainValue::Storage(U256::from(1000000000000000000u64));

        let salt_value: SaltValue = (plain_key, plain_value).into();
        let (plain_key_recover, plain_value_recover) = salt_value.into();
        assert_eq!(plain_key, plain_key_recover);
        assert_eq!(plain_value, plain_value_recover);
    }
}
