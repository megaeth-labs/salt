//! The scalar arithmetic [`crate::Element::from_bytes`] decodes a compressed point with, exact on
//! every input and specialized to the Banderwagon base field (`p − 1 = 2^32 · t`): the square
//! root of `y² = n/d` and the residue test of the subgroup check. Canonical parsing, the choice
//! of the positive `y` and the construction of the point stay in `element.rs`.
//! Both helpers are variable-time and are intended for public compressed points.
use ark_ed_on_bls12_381_bandersnatch::Fq;
#[cfg(test)]
use ark_ff::One;
use ark_ff::{BigInteger256, Field, PrimeField, Zero};

/// The Jacobi symbol by the binary algorithm on 256-bit integers.
mod jacobi {
    use core::cmp::Ordering;

    type Limbs = [u64; 4]; // little-endian limbs, canonical unsigned integer (not Montgomery form).

    #[inline(always)]
    fn cmp_limbs(a: &Limbs, b: &Limbs) -> Ordering {
        for i in (0..4).rev() {
            match a[i].cmp(&b[i]) {
                Ordering::Equal => {}
                other => return other,
            }
        }
        Ordering::Equal
    }

    #[inline(always)]
    fn sub_once(a: &mut Limbs, b: &Limbs) {
        // Caller has established a >= b; propagate both subtrahend and incoming borrow.
        let mut borrow = false;
        for i in 0..4 {
            let (first, b1) = a[i].overflowing_sub(b[i]);
            let (value, b2) = first.overflowing_sub(u64::from(borrow));
            a[i] = value;
            borrow = b1 || b2;
        }
        debug_assert!(!borrow);
    }

    #[inline(always)]
    fn trailing_zeros(a: &Limbs) -> u32 {
        for (i, limb) in a.iter().enumerate() {
            if *limb != 0 {
                return (i as u32) * 64 + limb.trailing_zeros();
            }
        }
        256
    }

    #[inline(always)]
    fn shift_right(a: &mut Limbs, bits: u32) {
        debug_assert!(bits < 256);
        let words = (bits / 64) as usize;
        let shift = bits % 64;
        let old = *a;
        for (i, limb) in a.iter_mut().enumerate() {
            let source = i + words;
            *limb = if source < 4 { old[source] >> shift } else { 0 };
            if shift != 0 && source + 1 < 4 {
                *limb |= old[source + 1] << (64 - shift);
            }
        }
    }

    /// The Jacobi symbol `(a | n)` of a canonical field value `a` and the odd modulus `n`: 1, −1,
    /// or 0 where they share a factor (`a = 0`, `n` being prime).
    #[inline]
    pub(super) fn binary_jacobi(mut a: Limbs, mut n: Limbs) -> i8 {
        // The decoder supplies the positive odd Fq modulus and canonical field value.
        debug_assert!(n[0] & 1 == 1);
        let mut sign = 1_i8;
        while a != [0; 4] {
            let twos = trailing_zeros(&a);
            if twos & 1 == 1 && matches!(n[0] & 7, 3 | 5) {
                sign = -sign;
            }
            shift_right(&mut a, twos);
            // Both operands are now odd. The denominator remains positive and odd.
            if cmp_limbs(&a, &n) == Ordering::Less {
                if a[0] & 3 == 3 && n[0] & 3 == 3 {
                    sign = -sign;
                }
                core::mem::swap(&mut a, &mut n);
            }
            // a >= n and both are odd, so a-n is even or zero. There is no repeated-
            // subtraction modulo loop: the NEXT iteration removes every factor of two.
            sub_once(&mut a, &n);
        }
        if n == [1, 0, 0, 0] {
            sign
        } else {
            0
        }
    }
}

struct SqrtTable {
    lookup: [Fq; 16],
    /// `c^(−j·2^(4·row − 1))` (row 0: `c^(−⌊j/2⌋)`), whose square divides the window out of `b`.
    correction: [[Fq; 16]; 8],
}
impl SqrtTable {
    #[cfg(test)]
    fn new() -> Self {
        assert_eq!(
            Fq::MODULUS.0,
            [
                0xffffffff00000001,
                0x53bda402fffe5bfe,
                0x3339d80809a1d805,
                0x73eda753299d7d48
            ]
        );
        let c = Fq::from(7u64).pow(Fq::TRACE);
        let mut check = c;
        for _ in 0..31 {
            check.square_in_place();
        }
        assert_eq!(check, -Fq::one());
        let ci = c.inverse().unwrap();
        let mut g = c;
        for _ in 0..28 {
            g.square_in_place();
        }
        let mut lookup = [Fq::one(); 16];
        for i in 1..16 {
            lookup[i] = lookup[i - 1] * g;
        }
        let mut correction = [[Fq::one(); 16]; 8];
        for (row, entries) in correction.iter_mut().enumerate() {
            for (j, entry) in entries.iter_mut().enumerate() {
                let e = if row == 0 {
                    j as u64 / 2
                } else {
                    (j as u64) << ((row * 4) - 1)
                };
                *entry = ci.pow([e]);
            }
        }
        Self { lookup, correction }
    }
    #[inline]
    fn sqrt(&self, u: Fq) -> Option<Fq> {
        if u.is_zero() {
            return Some(u);
        }
        let w = pow_trace_minus_one_div_two(u);
        let mut x = w * u;
        let mut b = x * w;
        for row in 0..8 {
            let mut z = b;
            for _ in 0..(28 - row * 4) {
                z.square_in_place();
            }
            let j = self.lookup.iter().position(|v| *v == z)?;
            if row == 0 && j & 1 == 1 {
                return None;
            }
            let correction = self.correction[row][j];
            x *= correction;
            // the next row reads `b` with this window divided out; after the last row nothing does
            if row < 7 {
                b *= correction.square();
            }
        }
        (x.square() == u).then_some(x)
    }
}

/// `u^((t − 1)/2)`, the exponentiation that dominates the square root (`p − 1 = 2^32 · t`), by a
/// four-bit fixed window as the vector lanes run it: 220 squarings and 64 products, where the
/// bit-at-a-time `Field::pow` takes 222 and 132. On an EPYC 9B45 the root takes 6.3 µs with it
/// and 7.6 µs without; arkworks' square root takes 11.1 µs.
#[inline]
fn pow_trace_minus_one_div_two(u: Fq) -> Fq {
    const E: [u64; 4] = Fq::TRACE_MINUS_ONE_DIV_TWO.0;
    let mut table = [Fq::ONE; 16];
    table[1] = u;
    for i in 2..16 {
        table[i] = table[i - 1] * u;
    }
    // the exponent's windows from the top, past the leading zero ones
    let mut windows = (0..64)
        .rev()
        .map(|w| (E[w / 16] >> (w % 16 * 4)) as usize & 0xf)
        .skip_while(|d| *d == 0);
    let Some(top) = windows.next() else {
        return Fq::ONE;
    };
    let mut acc = table[top];
    for d in windows {
        for _ in 0..4 {
            acc.square_in_place();
        }
        if d != 0 {
            acc *= table[d];
        }
    }
    acc
}

static SQRT_TABLE: SqrtTable = SqrtTable {
    lookup: [
        Fq::new(BigInteger256::new([
            0x0000000000000001,
            0x0000000000000000,
            0x0000000000000000,
            0x0000000000000000,
        ])),
        Fq::new(BigInteger256::new([
            0x53ea61d87742bcce,
            0x17beb312f20b6f76,
            0xdd1c0af834cec32c,
            0x20b1ce9140267af9,
        ])),
        Fq::new(BigInteger256::new([
            0x7228fd3397743f7a,
            0xb38b21c28713b700,
            0x8c0625cd70d77ce2,
            0x345766f603fa66e7,
        ])),
        Fq::new(BigInteger256::new([
            0x807b811a823f728d,
            0x967a6b6cfb0faca4,
            0x5ccd4631f16edba4,
            0x1edc919ec91f38ac,
        ])),
        Fq::new(BigInteger256::new([
            0x0001000000000000,
            0xec03000276030000,
            0x8d51ccce760304d0,
            0x0000000000000000,
        ])),
        Fq::new(BigInteger256::new([
            0x95df4b360411fe73,
            0x1ef4e672ebc1e1bb,
            0x6e92a9c460afca4a,
            0x4f2c596e753e4fcc,
        ])),
        Fq::new(BigInteger256::new([
            0x6037fe81ae99502e,
            0x8e74903694b04fd8,
            0xbabc5affca86bf65,
            0x1333b22e5ce11044,
        ])),
        Fq::new(BigInteger256::new([
            0xa1abb31fb37786b9,
            0x57bc96af334c36bc,
            0xcabf643eda8951f2,
            0x38c7f2dd7e0c63fc,
        ])),
        Fq::new(BigInteger256::new([
            0xffffffff00000000,
            0x53bda402fffe5bfe,
            0x3339d80809a1d805,
            0x73eda753299d7d48,
        ])),
        Fq::new(BigInteger256::new([
            0xac159e2688bd4333,
            0x3bfef0f00df2ec88,
            0x561dcd0fd4d314d9,
            0x533bd8c1e977024e,
        ])),
        Fq::new(BigInteger256::new([
            0x8dd702cb688bc087,
            0xa032824078eaa4fe,
            0xa733b23a98ca5b22,
            0x3f96405d25a31660,
        ])),
        Fq::new(BigInteger256::new([
            0x7f847ee47dc08d74,
            0xbd43389604eeaf5a,
            0xd66c91d61832fc60,
            0x551115b4607e449b,
        ])),
        Fq::new(BigInteger256::new([
            0xfffeffff00000001,
            0x67baa40089fb5bfe,
            0xa5e80b39939ed334,
            0x73eda753299d7d47,
        ])),
        Fq::new(BigInteger256::new([
            0x6a20b4c8fbee018e,
            0x34c8bd90143c7a43,
            0xc4a72e43a8f20dbb,
            0x24c14de4b45f2d7b,
        ])),
        Fq::new(BigInteger256::new([
            0x9fc8017d5166afd3,
            0xc54913cc6b4e0c26,
            0x787d7d083f1b189f,
            0x60b9f524ccbc6d03,
        ])),
        Fq::new(BigInteger256::new([
            0x5e544cdf4c887948,
            0xfc010d53ccb22542,
            0x687a73c92f188612,
            0x3b25b475ab91194b,
        ])),
    ],
    correction: [
        [
            Fq::new(BigInteger256::new([
                0x0000000000000001,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
            ])),
            Fq::new(BigInteger256::new([
                0x0000000000000001,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
            ])),
            Fq::new(BigInteger256::new([
                0x0fb4d6e13cf19a78,
                0x6f67d4a2b566f833,
                0xed4f2f74a35d0168,
                0x0538a6f66e19c653,
            ])),
            Fq::new(BigInteger256::new([
                0x0fb4d6e13cf19a78,
                0x6f67d4a2b566f833,
                0xed4f2f74a35d0168,
                0x0538a6f66e19c653,
            ])),
            Fq::new(BigInteger256::new([
                0xd81f9f026f5c391c,
                0x8e602ff1ba3a77b3,
                0x3991152f92ab73bd,
                0x65483c0b65acd330,
            ])),
            Fq::new(BigInteger256::new([
                0xd81f9f026f5c391c,
                0x8e602ff1ba3a77b3,
                0x3991152f92ab73bd,
                0x65483c0b65acd330,
            ])),
            Fq::new(BigInteger256::new([
                0x8230619dcb155808,
                0xe8075ae8bc260a7a,
                0x75ed047858f05cb9,
                0x69d778da9f679205,
            ])),
            Fq::new(BigInteger256::new([
                0x8230619dcb155808,
                0xe8075ae8bc260a7a,
                0x75ed047858f05cb9,
                0x69d778da9f679205,
            ])),
            Fq::new(BigInteger256::new([
                0x172ded2c7cc733db,
                0x04d52fdccbd4abe1,
                0x18923f8dd6fe2eb2,
                0x500b7ba5e0417702,
            ])),
            Fq::new(BigInteger256::new([
                0x172ded2c7cc733db,
                0x04d52fdccbd4abe1,
                0x18923f8dd6fe2eb2,
                0x500b7ba5e0417702,
            ])),
            Fq::new(BigInteger256::new([
                0xc627896a92b98782,
                0xf01422bd74a9192e,
                0xa4ed61c9006f0cf0,
                0x07c16f200a1a026e,
            ])),
            Fq::new(BigInteger256::new([
                0xc627896a92b98782,
                0xf01422bd74a9192e,
                0xa4ed61c9006f0cf0,
                0x07c16f200a1a026e,
            ])),
            Fq::new(BigInteger256::new([
                0x5703d918f08da63e,
                0x90a85f81008d6cf5,
                0x1392ac2522139c36,
                0x3c40553aa14cfa77,
            ])),
            Fq::new(BigInteger256::new([
                0x5703d918f08da63e,
                0x90a85f81008d6cf5,
                0x1392ac2522139c36,
                0x3c40553aa14cfa77,
            ])),
            Fq::new(BigInteger256::new([
                0x58c2351a8297f90b,
                0x5e8d3c1c2e2e94fd,
                0x9deeca7f131db7aa,
                0x6f6d51aa1927ecb9,
            ])),
            Fq::new(BigInteger256::new([
                0x58c2351a8297f90b,
                0x5e8d3c1c2e2e94fd,
                0x9deeca7f131db7aa,
                0x6f6d51aa1927ecb9,
            ])),
        ],
        [
            Fq::new(BigInteger256::new([
                0x0000000000000001,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
            ])),
            Fq::new(BigInteger256::new([
                0xcadd5a57119b30ed,
                0xe6f51dff8232e711,
                0x91b47f629b3acdfb,
                0x09e6369435a311d6,
            ])),
            Fq::new(BigInteger256::new([
                0x8c0fb4ee5c92abb4,
                0x29cf8bd1ea8d01b6,
                0x982109a3999fad16,
                0x18dec92f2a2d8918,
            ])),
            Fq::new(BigInteger256::new([
                0xcb6614c337db6d7d,
                0xc47a0e906eacbe47,
                0xa40230b088d7d226,
                0x1351584c0d04dbf8,
            ])),
            Fq::new(BigInteger256::new([
                0xbbb5c9fa2d30ae8d,
                0x163305d2e07a8c5f,
                0x2ada9adf927c68f8,
                0x20036a168c50c2fa,
            ])),
            Fq::new(BigInteger256::new([
                0xef99b54e5b85c445,
                0xbf54767ffd7dc660,
                0x8c44743c84ca75f4,
                0x2da71403f21668b5,
            ])),
            Fq::new(BigInteger256::new([
                0xf4f6f461fd28dd9a,
                0x9eacf2fa6f953f96,
                0x32aa167dfc46326f,
                0x025053bd92f332be,
            ])),
            Fq::new(BigInteger256::new([
                0x2793812c519b01c3,
                0xd4eb52765a73d6d1,
                0x8d0a0e75526418b2,
                0x092834ce6e7858e6,
            ])),
            Fq::new(BigInteger256::new([
                0xe91c56f8c471ab8f,
                0x3041399574a7dff6,
                0xec40785f01a608ea,
                0x469a312a702e4183,
            ])),
            Fq::new(BigInteger256::new([
                0xd3c78dbb66abc7b6,
                0x860edeb24deb3030,
                0x3ec87a16675ec764,
                0x26e65e8958d7a8d7,
            ])),
            Fq::new(BigInteger256::new([
                0x9f8bf20c962b76d6,
                0x500e9f32b1155f95,
                0x7cea0a2cdf9cf454,
                0x51d9ef11bee7b4b3,
            ])),
            Fq::new(BigInteger256::new([
                0xbf1a99108749d4a9,
                0xfee185786d7c4c96,
                0x3d49736853b228e2,
                0x6131579fcf893f87,
            ])),
            Fq::new(BigInteger256::new([
                0x0f6fc39890ffc8db,
                0x94c207868d77a94f,
                0xeb39ae9a12c03fd4,
                0x43a65743f02b1254,
            ])),
            Fq::new(BigInteger256::new([
                0xcf7ab36406b43098,
                0x2c75ba1b3e5b5426,
                0xd501ae1c28b9d338,
                0x2e1439d9fbd78537,
            ])),
            Fq::new(BigInteger256::new([
                0x16587da99fbc825b,
                0x742520b2099c8c6e,
                0x8d89186f4c01311c,
                0x1aa188984044d978,
            ])),
            Fq::new(BigInteger256::new([
                0x444fcac55922c91f,
                0xcd7d4cad82e72e7b,
                0x7fecbf470d053127,
                0x6f314b42a25cf9ea,
            ])),
        ],
        [
            Fq::new(BigInteger256::new([
                0x0000000000000001,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
            ])),
            Fq::new(BigInteger256::new([
                0x7491633ff3818d30,
                0x7ebe376e949286e7,
                0xd63b3e2d3cc09a42,
                0x6bdfb6afdc51e159,
            ])),
            Fq::new(BigInteger256::new([
                0xea4b5e832c8dc1d5,
                0xa96adcb5f3e15cbc,
                0xa537f74f3f6e8cff,
                0x172ed7073b37e3bb,
            ])),
            Fq::new(BigInteger256::new([
                0xf30566745e4f0bd6,
                0x56240bf9d760f4c7,
                0xd9e493b260499aec,
                0x282961fb68d62685,
            ])),
            Fq::new(BigInteger256::new([
                0x172791679351b310,
                0x717271f769857d69,
                0x1c2a4679e3a99823,
                0x3317ccccf619ad8c,
            ])),
            Fq::new(BigInteger256::new([
                0xbad48575b6526c7f,
                0x118bd8e1fae4a7a1,
                0x3d6c94f2f21f5445,
                0x3eb2040b0bcd7921,
            ])),
            Fq::new(BigInteger256::new([
                0x39b5c97111e92c55,
                0x2444c288b40c10ab,
                0x536146b726ecd423,
                0x35219b038803fa62,
            ])),
            Fq::new(BigInteger256::new([
                0xf2118ef0a69f4386,
                0xd8a6d11d754b1923,
                0xc7d109c0e17ba238,
                0x01ac14c114e0d41b,
            ])),
            Fq::new(BigInteger256::new([
                0x7540839d0a3df640,
                0xcc39b5c2fbc4a05e,
                0x4bfc37d5a352f5ab,
                0x2a89f520cb79e351,
            ])),
            Fq::new(BigInteger256::new([
                0x3c91c5c05b2a65a7,
                0xd12223a86db4d0e2,
                0xa425dd5e5798ea3e,
                0x0581a654d3d1a141,
            ])),
            Fq::new(BigInteger256::new([
                0x285760444575d18c,
                0x61c9fc0b7674ed22,
                0xe584393650116bbd,
                0x061e5a8c18513c8f,
            ])),
            Fq::new(BigInteger256::new([
                0x54e3991dcc4c1afb,
                0x8973fc56208a29b1,
                0x0adfb8432003e7e3,
                0x23b308333cc452d9,
            ])),
            Fq::new(BigInteger256::new([
                0xf529c5483d9780dd,
                0xb95e98e830a7e897,
                0x761c1cad84f3ec74,
                0x1028e86ce219a520,
            ])),
            Fq::new(BigInteger256::new([
                0x2303ec08f1676fc1,
                0x092ee5f34b9d64c7,
                0xf755f8cc2390c0bc,
                0x46e6ac59f375ee04,
            ])),
            Fq::new(BigInteger256::new([
                0xa42a44f4be334aed,
                0x01a367c6ba5fe4b5,
                0x556c94e013850990,
                0x67dc502e5e89898e,
            ])),
            Fq::new(BigInteger256::new([
                0x21391b466af9b610,
                0x61588f42cb6e95de,
                0x4651789a041a2a8c,
                0x0eb2a0fadac690cd,
            ])),
        ],
        [
            Fq::new(BigInteger256::new([
                0x0000000000000001,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
            ])),
            Fq::new(BigInteger256::new([
                0xdf9739f78f26d89e,
                0xbebeb8129b0029a5,
                0x91c8e2247cfa536d,
                0x5f3ed180c5146cab,
            ])),
            Fq::new(BigInteger256::new([
                0xef97c3573a28fc8c,
                0x0624a1bb17dbc026,
                0x68ac033fa6f60875,
                0x6c39442eade00927,
            ])),
            Fq::new(BigInteger256::new([
                0x592bd4b878a5bfd3,
                0x5f4a1618e5663db6,
                0xe43b574ba1c16405,
                0x47e49e08708cf0d7,
            ])),
            Fq::new(BigInteger256::new([
                0x99196be30704893a,
                0x0d93401ca14e79b4,
                0xa0e839716ec64c88,
                0x059d12338029659f,
            ])),
            Fq::new(BigInteger256::new([
                0xd9397abbcb467af2,
                0xf1b0309f8a650cba,
                0xe99fd4c113f9bed7,
                0x4380034cc052f966,
            ])),
            Fq::new(BigInteger256::new([
                0xbf0069faaa1fc385,
                0x3e935481a2e7e84d,
                0x35c35a014ecce200,
                0x38a63601e1393e6d,
            ])),
            Fq::new(BigInteger256::new([
                0xb2f325d3db70b01c,
                0x03b8ff0bd6be9b47,
                0xded4d31f0f8d2069,
                0x72e7e9bad2fc9da7,
            ])),
            Fq::new(BigInteger256::new([
                0x52b9248126d911d3,
                0xe358c8a0bbd6a833,
                0x706fe0e351de8579,
                0x11b71ed3f4008128,
            ])),
            Fq::new(BigInteger256::new([
                0xc0619badb9ba8dac,
                0x1977db5cbed9ba96,
                0xf33ef6cc2a0ce319,
                0x3e407fbefb98cd1c,
            ])),
            Fq::new(BigInteger256::new([
                0xbb1fe323999fa4bf,
                0xfbd2591d36448033,
                0x40737ff00aff3987,
                0x6a29fe31ac791e88,
            ])),
            Fq::new(BigInteger256::new([
                0xf39deb3d1c54e0b2,
                0x765facfc70cc60be,
                0xa3e1f9372da1889b,
                0x2d99d25fdd760911,
            ])),
            Fq::new(BigInteger256::new([
                0xf735c2c1d4952556,
                0xac047d66a117d30d,
                0x2088e3beaa4ca1b2,
                0x12995ccd5d9366d8,
            ])),
            Fq::new(BigInteger256::new([
                0x605eb5f09f6d3234,
                0xf2d535ebdaa44d32,
                0x5c61aa672585c2ce,
                0x11221be94984d04e,
            ])),
            Fq::new(BigInteger256::new([
                0x14ba7b7353059644,
                0xfa1f1537870e9796,
                0x440962213d3af0f1,
                0x166852eea25fc9a2,
            ])),
            Fq::new(BigInteger256::new([
                0x20f1b586a5b975c5,
                0xe4773fccdb7e35fd,
                0x811f660d75d6e849,
                0x7314b5966db8937c,
            ])),
        ],
        [
            Fq::new(BigInteger256::new([
                0x0000000000000001,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
            ])),
            Fq::new(BigInteger256::new([
                0xa8addb0398475e5f,
                0xb5420c483c2f23aa,
                0x8406d479623b2c68,
                0x19297f11ed262ea0,
            ])),
            Fq::new(BigInteger256::new([
                0x899e9d3360bf37a0,
                0x6f526a724590e6db,
                0xd309639c307e90eb,
                0x509e12811a867293,
            ])),
            Fq::new(BigInteger256::new([
                0x67a82cd82f10e91d,
                0x8e66cb8326442bed,
                0x7206c7551133d71e,
                0x11df3e6ab6baa6b9,
            ])),
            Fq::new(BigInteger256::new([
                0x92f8f71fe150df15,
                0xe05594bb9c30ac06,
                0xd40407303f881fa4,
                0x28e112deab701fe9,
            ])),
            Fq::new(BigInteger256::new([
                0x07f2904010601398,
                0x38613b5b0f09a152,
                0xe7426398bd337132,
                0x4cc2af291b1b2bda,
            ])),
            Fq::new(BigInteger256::new([
                0xf00849266460a7d0,
                0xcc36b1099267ee39,
                0x0928d8f1c60106fc,
                0x205ecd64a31e13a6,
            ])),
            Fq::new(BigInteger256::new([
                0x9db721656b6b26ff,
                0x822d3758cbd19bea,
                0x66a33f7757e2e92b,
                0x34c20f2434595f2e,
            ])),
            Fq::new(BigInteger256::new([
                0xd7a1f5bc8f529599,
                0xa14c38253fdb838c,
                0xfd013df1f683bf99,
                0x281f74790b85a216,
            ])),
            Fq::new(BigInteger256::new([
                0x33305285a3c660e4,
                0x64edd626e50b55c9,
                0x07f7220b4380d37a,
                0x08e1b659723d3c4d,
            ])),
            Fq::new(BigInteger256::new([
                0x79bc334e5f25cb16,
                0x6fb0d30f8130ce1f,
                0xb9a8a2f0b2571aa7,
                0x303d1f106abc9e9e,
            ])),
            Fq::new(BigInteger256::new([
                0x03db3d79888e500b,
                0xa2528ac163c2ac2f,
                0x86e313c1c2a931d5,
                0x04094b52cbfb7e9a,
            ])),
            Fq::new(BigInteger256::new([
                0xa78871f7706f3dcd,
                0xa8a9021ae3d771c5,
                0x29279d664dc8303d,
                0x123773ca3773ca20,
            ])),
            Fq::new(BigInteger256::new([
                0x072ecfc4bbfc2977,
                0xd88dd2299badf603,
                0x5ca554938fc271ab,
                0x3c1f8654f888b376,
            ])),
            Fq::new(BigInteger256::new([
                0x42bb886620a922fa,
                0xf90342d035eaf83d,
                0x8c1eee00b7b9ca19,
                0x23b2a2ba8d16dbbf,
            ])),
            Fq::new(BigInteger256::new([
                0x3e78f3a4b0eff1b8,
                0xe612a1f6f732b265,
                0x8cc8a8016ffb0b0b,
                0x6e0b92fdd9e1bd1a,
            ])),
        ],
        [
            Fq::new(BigInteger256::new([
                0x0000000000000001,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
            ])),
            Fq::new(BigInteger256::new([
                0x68946aad325251ed,
                0x204f9476cecef2df,
                0xd548fda262008419,
                0x57e6990d4981b177,
            ])),
            Fq::new(BigInteger256::new([
                0x961a252dd8543362,
                0x5046d17864183203,
                0x4ae25ffab9dc5986,
                0x391b2856c609b478,
            ])),
            Fq::new(BigInteger256::new([
                0x63161b0e604f2b5c,
                0xebb2c035b286d629,
                0xc405642e1a61b6c2,
                0x0b86cb0cc9981913,
            ])),
            Fq::new(BigInteger256::new([
                0xdc982deab639eb06,
                0xa954d02ff707ac89,
                0xae65b5bdd485b39a,
                0x55612c879036d62f,
            ])),
            Fq::new(BigInteger256::new([
                0xfd7775d58b6a4da1,
                0xf4174253da643e73,
                0x225eec1a443ac8ca,
                0x50ff4dca58acf2a5,
            ])),
            Fq::new(BigInteger256::new([
                0x84658d7d1fba4133,
                0x8a775193a915287b,
                0x26a96b6d8623b90e,
                0x2229dd16b97880c2,
            ])),
            Fq::new(BigInteger256::new([
                0xf8c967964fcdf998,
                0x23361307e4795dc8,
                0xe921369be50033e2,
                0x0c073e502e654af4,
            ])),
            Fq::new(BigInteger256::new([
                0x1b561347c6a47727,
                0x9ce862487904d0ab,
                0x942c20e45c3ad14d,
                0x5164ca4cf7456c9b,
            ])),
            Fq::new(BigInteger256::new([
                0x4308f6f61fd57922,
                0xb7fc93ca9fe43336,
                0xcae9f31d0271872d,
                0x587ef47ebaabb080,
            ])),
            Fq::new(BigInteger256::new([
                0x361e8ea8ae06b126,
                0xaca02a3a8f443648,
                0x3d4067ca08e2b3a4,
                0x482ec10c0dfb6cca,
            ])),
            Fq::new(BigInteger256::new([
                0x6b042e7d733f5935,
                0x25fe1c04dbeea15c,
                0x0e2768f592efb3ac,
                0x50f3a2474ec512ec,
            ])),
            Fq::new(BigInteger256::new([
                0x6704b9c8bb9bf61e,
                0xf32dcc1406da0f4c,
                0x2c8e657fe47ea551,
                0x2c6aa58b3a749bc6,
            ])),
            Fq::new(BigInteger256::new([
                0x681a482be5ae6e42,
                0x516b9a054e912c88,
                0xa82b95732cfc005e,
                0x6b4c4d5b58d3db0f,
            ])),
            Fq::new(BigInteger256::new([
                0x93fca26054dfc243,
                0x54eff6572f4ad109,
                0x9d9e66dd3f254fe9,
                0x523c2aaed4076db6,
            ])),
            Fq::new(BigInteger256::new([
                0xe59cbf4284f06873,
                0x6380dbfd20972cb6,
                0xc49e763946542f55,
                0x3afadf5f94f284e5,
            ])),
        ],
        [
            Fq::new(BigInteger256::new([
                0x0000000000000001,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
            ])),
            Fq::new(BigInteger256::new([
                0x16654b4e3193f385,
                0x7dd34dc48b542a79,
                0x881dab49e15d3727,
                0x6a61dbd781fc6d1c,
            ])),
            Fq::new(BigInteger256::new([
                0x7d01866add958780,
                0xdf7b4ee66e4caccb,
                0x67e701a945e9b713,
                0x18ba7658084c71a4,
            ])),
            Fq::new(BigInteger256::new([
                0xaddcfc96a506dae2,
                0x87736de903ce2b7a,
                0xaf1b0f713a146c93,
                0x346cbb19b5815e67,
            ])),
            Fq::new(BigInteger256::new([
                0x6207cd2f20df9d12,
                0x0081066e578d78bf,
                0x725ce48f79bf9cd6,
                0x60c7efec34093e9a,
            ])),
            Fq::new(BigInteger256::new([
                0xf9ed4f03933eef85,
                0x30eb83e42ef3f6bf,
                0xa9ca21650de7491c,
                0x07d1dbabda2a09d6,
            ])),
            Fq::new(BigInteger256::new([
                0xf3f90bd2b05e602e,
                0x42f464cb4256a3b3,
                0xcfdc1da7bf59004b,
                0x36e1ebe124834a8f,
            ])),
            Fq::new(BigInteger256::new([
                0x40e4c962f57bba4b,
                0xa3ce9513fd14fa73,
                0x5bef62d338fc0848,
                0x08097452c5c97866,
            ])),
            Fq::new(BigInteger256::new([
                0x8d28c143168bba2c,
                0xdb872ef3dce28e78,
                0x4e84b3cd7dc75b61,
                0x640d097461a2eeaf,
            ])),
            Fq::new(BigInteger256::new([
                0x1602cb7786c1f5e3,
                0x682032b420d1fe8b,
                0x3bc2e754e78bbdb0,
                0x67eb2fd57acdc0bc,
            ])),
            Fq::new(BigInteger256::new([
                0xf007bdc150d024b1,
                0xbf5354ab6e8c2ab4,
                0xe0eb9d91cdecccfb,
                0x1f2caa7aeef7d8de,
            ])),
            Fq::new(BigInteger256::new([
                0x122fe2e0669a2cc8,
                0x3050700bdc4b9b68,
                0x7a36b26c3985d063,
                0x035bc18d05559682,
            ])),
            Fq::new(BigInteger256::new([
                0x3ff630d3f89c4c2c,
                0x08ccffd43f1931b6,
                0xfaa1f3804fdb73d0,
                0x1f3834a0f387add7,
            ])),
            Fq::new(BigInteger256::new([
                0x1be69f3270830aad,
                0x6862075a6764c01e,
                0x447bddbac2fd51ed,
                0x5807969225ba3389,
            ])),
            Fq::new(BigInteger256::new([
                0x2e9a4db5f138dab3,
                0x7a1cb8c070f0ce32,
                0xbcca660ee327eb37,
                0x6a945980dade66ef,
            ])),
            Fq::new(BigInteger256::new([
                0xbd7831edbb030fe8,
                0x3305eef4a96aad48,
                0x6d7b9d657ca55704,
                0x3ec15814750a6cbe,
            ])),
        ],
        [
            Fq::new(BigInteger256::new([
                0x0000000000000001,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
            ])),
            Fq::new(BigInteger256::new([
                0xae34a81e1cfca2ec,
                0x6c7876bf0928e68f,
                0xae25b21df6c52b2a,
                0x5e73ed8c432405d0,
            ])),
            Fq::new(BigInteger256::new([
                0x5e544cdf4c887948,
                0xfc010d53ccb22542,
                0x687a73c92f188612,
                0x3b25b475ab91194b,
            ])),
            Fq::new(BigInteger256::new([
                0xdf2b12e5b0330148,
                0x51d460a1dbfcd267,
                0x8a490835c612d679,
                0x20e9cd3a7fca77e3,
            ])),
            Fq::new(BigInteger256::new([
                0x9fc8017d5166afd3,
                0xc54913cc6b4e0c26,
                0x787d7d083f1b189f,
                0x60b9f524ccbc6d03,
            ])),
            Fq::new(BigInteger256::new([
                0x11a43132b1888c36,
                0x0e6466930923ab78,
                0x8f907adac98af548,
                0x6f70f5e67a06fbd8,
            ])),
            Fq::new(BigInteger256::new([
                0x6a20b4c8fbee018e,
                0x34c8bd90143c7a43,
                0xc4a72e43a8f20dbb,
                0x24c14de4b45f2d7b,
            ])),
            Fq::new(BigInteger256::new([
                0xc13af36ece5c935e,
                0x2d0124a02ec3ede2,
                0x2d34ccafd6d0ce6e,
                0x0df6e1cface780a6,
            ])),
            Fq::new(BigInteger256::new([
                0xfffeffff00000001,
                0x67baa40089fb5bfe,
                0xa5e80b39939ed334,
                0x73eda753299d7d47,
            ])),
            Fq::new(BigInteger256::new([
                0x7d19743e43af5772,
                0xf116d26dfeb2f7ee,
                0xecaed406f9fc1065,
                0x1cfa4b9a3c48cf47,
            ])),
            Fq::new(BigInteger256::new([
                0x7f847ee47dc08d74,
                0xbd43389604eeaf5a,
                0xd66c91d61832fc60,
                0x551115b4607e449b,
            ])),
            Fq::new(BigInteger256::new([
                0x9733f3a6ba60eaa6,
                0xbd7fdf9c77487ae7,
                0xd84f8612c8b6cc00,
                0x476fa2fb6162ffab,
            ])),
            Fq::new(BigInteger256::new([
                0x8dd702cb688bc087,
                0xa032824078eaa4fe,
                0xa733b23a98ca5b22,
                0x3f96405d25a31660,
            ])),
            Fq::new(BigInteger256::new([
                0x196986abd51edcb5,
                0x708c291cbae2a361,
                0xac3f6e2f24bd52fe,
                0x6f8c83d4d0a0ae73,
            ])),
            Fq::new(BigInteger256::new([
                0xac159e2688bd4333,
                0x3bfef0f00df2ec88,
                0x561dcd0fd4d314d9,
                0x533bd8c1e977024e,
            ])),
            Fq::new(BigInteger256::new([
                0xc9f39f658c9620b3,
                0x944f1b07b3c56074,
                0x7e7d03f9e6ac83bc,
                0x230d17191423f48d,
            ])),
        ],
    ],
};

#[inline]
pub(super) fn sqrt(value: Fq) -> Option<Fq> {
    SQRT_TABLE.sqrt(value)
}

/// Whether `value` is a nonzero square: the residue test of the subgroup check.
///
/// On `x86_64` and `aarch64`, the native targets the decode was measured on, this is the binary
/// Jacobi symbol: 2.4 µs on an EPYC 9B45, where the exponentiation takes 6.2 µs. Every other
/// target keeps arkworks' Legendre exponentiation, the test this module replaced. That covers the
/// zkVM guests: a proof pays for every instruction of the Jacobi loop's several hundred
/// data-dependent iterations, a guest may run field multiplication as a precompile, and the two
/// have not been measured there. Add a target to the list once they have been.
#[inline]
pub(super) fn is_nonzero_square(value: Fq) -> bool {
    if cfg!(any(target_arch = "x86_64", target_arch = "aarch64")) {
        jacobi::binary_jacobi(value.into_bigint().0, Fq::MODULUS.0) == 1
    } else {
        value.legendre().is_qr()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_ff::{LegendreSymbol, UniformRand};
    use rand_chacha::rand_core::SeedableRng;
    #[test]
    fn generated_constants_match_original_runtime_constructor() {
        let expected = SqrtTable::new();
        assert_eq!(SQRT_TABLE.lookup, expected.lookup);
        assert_eq!(SQRT_TABLE.correction, expected.correction);
    }
    #[test]
    fn arithmetic_matches_arkworks_for_boundaries_and_random_fields() {
        let check = |value: Fq| {
            let actual = sqrt(value);
            let expected = value.sqrt();
            assert_eq!(actual.is_some(), expected.is_some());
            if let (Some(a), Some(b)) = (actual, expected) {
                assert_eq!(a.square(), value);
                assert!(a == b || a == -b);
            }
            assert_eq!(is_nonzero_square(value), value.legendre().is_qr());
            // the Jacobi symbol itself, on the targets whose `is_nonzero_square` is the
            // exponentiation too
            let symbol = match value.legendre() {
                LegendreSymbol::Zero => 0,
                LegendreSymbol::QuadraticResidue => 1,
                LegendreSymbol::QuadraticNonResidue => -1,
            };
            assert_eq!(
                jacobi::binary_jacobi(value.into_bigint().0, Fq::MODULUS.0),
                symbol
            );
        };
        check(Fq::zero());
        check(Fq::one());
        check(-Fq::one());
        let mut power = Fq::one();
        for _ in 0..256 {
            check(power);
            check(power - Fq::one());
            check(power + Fq::one());
            power += power;
        }
        let mut rng = rand_chacha::ChaCha20Rng::seed_from_u64(47);
        for _ in 0..8192 {
            check(Fq::rand(&mut rng));
        }
    }
}
