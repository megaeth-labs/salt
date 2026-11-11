//! [`reth_codecs`] encodings for [`SaltKey`] and [`SaltValue`], enabled by the `reth-codecs`
//! feature.
//!
//! These encodings are persisted by downstream databases, so the byte layouts below are a
//! storage format: changing them, or [`MAX_SALT_VALUE_BYTES`], silently reinterprets existing
//! rows.

use crate::{SaltKey, SaltValue, MAX_SALT_VALUE_BYTES};
use bytes::{Buf, BufMut};
use reth_codecs::{Compact, Compress, Decompress, DecompressError};
use std::vec::Vec;

/// Encodes as a fixed 8-byte big-endian `u64` and ignores `len` on decode.
impl Compact for SaltKey {
    #[inline]
    fn to_compact<B>(&self, buf: &mut B) -> usize
    where
        B: BufMut + AsMut<[u8]>,
    {
        buf.put_u64(self.0);
        8
    }

    #[inline]
    fn from_compact(mut buf: &[u8], _len: usize) -> (Self, &[u8]) {
        let value = buf.get_u64();
        (Self(value), buf)
    }
}

/// Encodes as exactly [`MAX_SALT_VALUE_BYTES`] raw bytes of `data` and ignores `len` on decode.
impl Compact for SaltValue {
    #[inline]
    fn to_compact<B>(&self, buf: &mut B) -> usize
    where
        B: BufMut + AsMut<[u8]>,
    {
        buf.put_slice(&self.data[..]);
        MAX_SALT_VALUE_BYTES
    }

    #[inline]
    fn from_compact(buf: &[u8], _len: usize) -> (Self, &[u8]) {
        let mut data = [0u8; MAX_SALT_VALUE_BYTES];
        data.copy_from_slice(&buf[..MAX_SALT_VALUE_BYTES]);
        (Self { data }, &buf[MAX_SALT_VALUE_BYTES..])
    }
}

macro_rules! impl_compression_for_compact {
    ($($name:ty),+) => {
        $(
            impl Compress for $name {
                type Compressed = Vec<u8>;

                fn compress_to_buf<B: BufMut + AsMut<[u8]>>(&self, buf: &mut B) {
                    let _ = Compact::to_compact(self, buf);
                }
            }

            impl Decompress for $name {
                fn decompress(value: &[u8]) -> Result<Self, DecompressError> {
                    let (obj, _) = Compact::from_compact(value, value.len());
                    Ok(obj)
                }
            }
        )+
    };
}

impl_compression_for_compact!(SaltKey, SaltValue);

#[cfg(test)]
mod tests {
    use super::*;
    use std::vec;

    #[test]
    fn compact_salt_key_roundtrip_and_layout() {
        let key = SaltKey(0x0102_0304_0506_0708);
        let mut buf = vec![];
        assert_eq!(key.to_compact(&mut buf), 8);
        assert_eq!(buf, vec![0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]);

        // A trailing byte must be left untouched and returned in the remainder.
        buf.push(0xaa);
        let (decoded, remaining) = SaltKey::from_compact(&buf, 8);
        assert_eq!(decoded, key);
        assert_eq!(remaining, [0xaa].as_slice());
    }

    #[test]
    fn compact_salt_value_roundtrip_and_layout() {
        // The persisted width is frozen at the raw `data` array.
        assert_eq!(
            MAX_SALT_VALUE_BYTES, 94,
            "SaltValue persisted width is frozen at 94 bytes"
        );

        // `data` layout: key_len(1) | value_len(1) | key | value, zero-padded to the fixed width.
        let value = SaltValue::new(&[0x11, 0x22], &[0x33, 0x44, 0x55]);
        let mut buf = vec![];
        assert_eq!(value.to_compact(&mut buf), MAX_SALT_VALUE_BYTES);
        assert_eq!(buf.len(), MAX_SALT_VALUE_BYTES);
        assert_eq!(&buf[..7], &[2, 3, 0x11, 0x22, 0x33, 0x44, 0x55]);
        assert!(
            buf[7..].iter().all(|&b| b == 0),
            "unused bytes must be zero-padded"
        );

        // A trailing byte must be left untouched and returned in the remainder.
        buf.push(0xaa);
        let (decoded, remaining) = SaltValue::from_compact(&buf, MAX_SALT_VALUE_BYTES);
        assert_eq!(decoded, value);
        assert_eq!(remaining, [0xaa].as_slice());
    }

    #[test]
    fn compress_matches_compact() {
        let key = SaltKey(42);
        let value = SaltValue::new(&[1, 2, 3], &[4, 5]);

        let mut key_compact = vec![];
        key.to_compact(&mut key_compact);
        assert_eq!(key.compress(), key_compact);
        assert_eq!(SaltKey::decompress(&key_compact).unwrap(), key);

        let mut value_compact = vec![];
        value.to_compact(&mut value_compact);
        assert_eq!(value.clone().compress(), value_compact);
        assert_eq!(SaltValue::decompress(&value_compact).unwrap(), value);
    }
}
