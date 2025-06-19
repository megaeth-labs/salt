//! Reth-specific implementations for types used in salt calculation and storage.
//!
//! This module is only available when the "reth" feature is enabled.

#![cfg(feature = "reth")]

use crate::types::{SaltKey, SaltValue, SaltValueDelta, MAX_SALT_VALUE_BYTES};
use alloy_primitives::bytes::Buf;
use alloy_rlp::BufMut;
use reth_codecs::{decode_varuint, derive_arbitrary, encode_varuint, Compact};

// Re-export the derive_arbitrary macro for use in the main types
pub use reth_codecs::derive_arbitrary;

/// Reth-specific Compact implementation for SaltKey
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

/// Reth-specific Compact implementation for SaltValue
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

/// Reth-specific Compact implementation for SaltValueDelta
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
