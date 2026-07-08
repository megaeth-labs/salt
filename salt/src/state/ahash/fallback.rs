// Derived from AHash v0.8.12 - see NOTICE.md for full attribution

//! Deterministic AHash fallback implementation for consensus applications.

use super::convert::ReadFromSlice;

#[inline(always)]
fn read_small(data: &[u8]) -> [u64; 2] {
    debug_assert!(data.len() <= 8);
    if data.len() >= 2 {
        if data.len() >= 4 {
            [data.read_u32().0 as u64, data.read_last_u32() as u64]
        } else {
            [data.read_u16().0 as u64, data[data.len() - 1] as u64]
        }
    } else if !data.is_empty() {
        [data[0] as u64, data[0] as u64]
    } else {
        [0, 0]
    }
}

const PI2: [u64; 4] = [
    0x4528_21e6_38d0_1377,
    0xbe54_66cf_34e9_0c6c,
    0xc0ac_29b7_c97c_50dd,
    0x3f84_d5b5_b547_0917,
];

const MULTIPLE: u64 = 6364136223846793005;
const ROT: u32 = 23;

#[inline(always)]
const fn folded_multiply(s: u64, by: u64) -> u64 {
    let result = (s as u128).wrapping_mul(by as u128);
    ((result & 0xffff_ffff_ffff_ffff) as u64) ^ ((result >> 64) as u64)
}

#[derive(Debug, Clone)]
pub struct RandomState {
    pub k0: u64,
    pub k1: u64,
    pub k2: u64,
    pub k3: u64,
}

impl RandomState {
    #[inline]
    pub const fn with_seeds(k0: u64, k1: u64, k2: u64, k3: u64) -> RandomState {
        RandomState {
            k0: k0 ^ PI2[0],
            k1: k1 ^ PI2[1],
            k2: k2 ^ PI2[2],
            k3: k3 ^ PI2[3],
        }
    }
}

#[derive(Debug, Clone)]
pub struct DeterministicHasher {
    buffer: u64,
    pad: u64,
    extra_keys: [u64; 2],
}

impl DeterministicHasher {
    #[inline(always)]
    fn update(&mut self, new_data: u64) {
        self.buffer = folded_multiply(new_data ^ self.buffer, MULTIPLE);
    }

    #[inline(always)]
    fn large_update(&mut self, new_data: u128) {
        let block: [u64; 2] = [new_data as u64, (new_data >> 64) as u64];
        let combined =
            folded_multiply(block[0] ^ self.extra_keys[0], block[1] ^ self.extra_keys[1]);
        self.buffer = (self.buffer.wrapping_add(self.pad) ^ combined).rotate_left(ROT);
    }
}

impl core::hash::Hasher for DeterministicHasher {
    #[inline]
    fn write_u8(&mut self, i: u8) {
        self.update(i as u64);
    }

    #[inline]
    fn write_u16(&mut self, i: u16) {
        self.update(i as u64);
    }

    #[inline]
    fn write_u32(&mut self, i: u32) {
        self.update(i as u64);
    }

    #[inline]
    fn write_u64(&mut self, i: u64) {
        self.update(i);
    }

    #[inline]
    fn write_u128(&mut self, i: u128) {
        self.large_update(i);
    }

    #[inline]
    fn write_usize(&mut self, i: usize) {
        self.write_u64(i as u64);
    }

    #[inline]
    fn write(&mut self, input: &[u8]) {
        let mut data = input;
        let length = data.len() as u64;

        self.buffer = self.buffer.wrapping_add(length).wrapping_mul(MULTIPLE);

        if data.len() > 8 {
            if data.len() > 16 {
                let tail = data.read_last_u128();
                self.large_update(tail);
                while data.len() > 16 {
                    let (block, rest) = data.read_u128();
                    self.large_update(block);
                    data = rest;
                }
            } else {
                let front = data.read_u64().0;
                let back = data.read_last_u64();
                let combined = (front as u128) | ((back as u128) << 64);
                self.large_update(combined);
            }
        } else {
            let value = read_small(data);
            let combined = (value[0] as u128) | ((value[1] as u128) << 64);
            self.large_update(combined);
        }
    }

    #[inline]
    fn finish(&self) -> u64 {
        let rot = (self.buffer & 63) as u32;
        folded_multiply(self.buffer, self.pad).rotate_left(rot)
    }
}

impl core::hash::BuildHasher for RandomState {
    type Hasher = DeterministicHasher;

    #[inline]
    fn build_hasher(&self) -> Self::Hasher {
        DeterministicHasher {
            buffer: self.k1,
            pad: self.k0,
            extra_keys: [self.k2, self.k3],
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::hash::{BuildHasher, Hasher};

    /// The integer `write_*` overrides are what keep integer hashing
    /// endian-independent (the core::hash defaults go through native-endian
    /// bytes); pin their exact outputs so mutations to `update` and
    /// `large_update` cannot survive.
    #[test]
    fn write_integer_outputs_are_pinned() {
        let build = RandomState::with_seeds(1, 2, 3, 4);
        let finish = |f: &dyn Fn(&mut DeterministicHasher)| {
            let mut hasher = build.build_hasher();
            f(&mut hasher);
            hasher.finish()
        };

        assert_eq!(finish(&|h| h.write_u8(0xa5)), 18_003_160_624_292_972_093);
        assert_eq!(finish(&|h| h.write_u16(0xa5a5)), 13_293_305_771_500_139_834);
        assert_eq!(
            finish(&|h| h.write_u32(0xa5a5_a5a5)),
            1_920_462_131_907_294_801
        );
        assert_eq!(
            finish(&|h| h.write_u64(0xa5a5_a5a5_a5a5_a5a5)),
            3_694_995_219_585_681_531
        );
        assert_eq!(
            finish(&|h| h.write_u128(0xa5a5_a5a5_a5a5_a5a5_a5a5_a5a5_a5a5_a5a5)),
            5_605_269_915_146_111_207
        );
        assert_eq!(
            finish(&|h| h.write_usize(0x1234)),
            3_213_796_315_339_447_371
        );
    }

    #[test]
    fn read_small_length_classes() {
        let cases: &[(&[u8], [u64; 2])] = &[
            (&[], [0, 0]),
            (&[0xab], [0xab, 0xab]),
            (&[1, 2], [0x0201, 2]),
            (&[1, 2, 3], [0x0201, 3]),
            (&[1, 2, 3, 4], [0x0403_0201, 0x0403_0201]),
            (&[1, 2, 3, 4, 5, 6, 7], [0x0403_0201, 0x0706_0504]),
            (&[1, 2, 3, 4, 5, 6, 7, 8], [0x0403_0201, 0x0807_0605]),
        ];

        for (input, expected) in cases {
            assert_eq!(read_small(input), *expected, "input={input:?}");
        }
    }
}
