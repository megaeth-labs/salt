// Derived from AHash v0.8.12 - see NOTICE.md for full attribution

//! Byte-slice readers for the deterministic hasher.
//!
//! All reads use explicit little-endian conversion so the hash is
//! platform-independent. `bucket_id` is consensus-critical: the upstream
//! AHash code reinterpreted bytes in native endianness (via `transmute`),
//! which would assign the same key to different buckets on big-endian
//! targets. Little-endian is the canonical interpretation because every
//! current deployment target (x86_64, riscv64, wasm32) is little-endian,
//! so the pinned hash values in `state::hasher` tests define the network
//! format.

pub(crate) trait ReadFromSlice {
    fn read_u16(&self) -> (u16, &[u8]);
    fn read_u32(&self) -> (u32, &[u8]);
    fn read_u64(&self) -> (u64, &[u8]);
    fn read_u128(&self) -> (u128, &[u8]);
    fn read_last_u32(&self) -> u32;
    fn read_last_u64(&self) -> u64;
    fn read_last_u128(&self) -> u128;
}

impl ReadFromSlice for [u8] {
    #[inline(always)]
    fn read_u16(&self) -> (u16, &[u8]) {
        let (value, rest) = self.split_at(2);
        (u16::from_le_bytes(value.try_into().unwrap()), rest)
    }

    #[inline(always)]
    fn read_u32(&self) -> (u32, &[u8]) {
        let (value, rest) = self.split_at(4);
        (u32::from_le_bytes(value.try_into().unwrap()), rest)
    }

    #[inline(always)]
    fn read_u64(&self) -> (u64, &[u8]) {
        let (value, rest) = self.split_at(8);
        (u64::from_le_bytes(value.try_into().unwrap()), rest)
    }

    #[inline(always)]
    fn read_u128(&self) -> (u128, &[u8]) {
        let (value, rest) = self.split_at(16);
        (u128::from_le_bytes(value.try_into().unwrap()), rest)
    }

    #[inline(always)]
    fn read_last_u32(&self) -> u32 {
        let (_, value) = self.split_at(self.len() - 4);
        u32::from_le_bytes(value.try_into().unwrap())
    }

    #[inline(always)]
    fn read_last_u64(&self) -> u64 {
        let (_, value) = self.split_at(self.len() - 8);
        u64::from_le_bytes(value.try_into().unwrap())
    }

    #[inline(always)]
    fn read_last_u128(&self) -> u128 {
        let (_, value) = self.split_at(self.len() - 16);
        u128::from_le_bytes(value.try_into().unwrap())
    }
}
