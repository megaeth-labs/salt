//! ZKVM-specific operations and utilities.
//! Only compiled when targeting zkVM on RISC-V32.

use crate::element::Element;
use ark_ed_on_bls12_381_bandersnatch::{EdwardsProjective, Fq, Fr};
use ark_ff::BigInteger;
use ark_ff::Zero;
use ark_ff::{BigInt, PrimeField};
use core::{cmp, ops::Neg};
use risc0_zkvm::guest::env;
use risc0_zkvm::guest::env::log;
use risc0_zkvm_platform::syscall::bigint::OP_MULTIPLY;
use risc0_zkvm_platform::syscall::sys_bigint;
use std::{vec, vec::Vec};

/// TODO
pub(crate) fn add_projective(result: &mut EdwardsProjective, other: &EdwardsProjective) {
    // See "Twisted Edwards Curves Revisited" (https://eprint.iacr.org/2008/522.pdf)
    // by Huseyin Hisil, Kenneth Koon-Ho Wong, Gary Carter, and Ed Dawson
    // 3.1 Unified Addition in E^e

    // A = x1 * x2
    let mut a = Fq::zero();
    mod_mul_zkvm(&mut a.0 .0, &result.x.0 .0, &other.x.0 .0);
    // println!("a {:?}",a.0.0);

    // B = y1 * y2
    let mut b = Fq::zero();
    mod_mul_zkvm(&mut b.0 .0, &result.y.0 .0, &other.y.0 .0);
    // println!("b {:?}",b.0.0);

    // C = d * t1 * t2
    let mut c = Fq::zero();
    let mut c1 = Fq::zero();

    mod_mul_zkvm(&mut c1.0 .0, &result.t.0 .0, &other.t.0 .0);
    mod_mul_zkvm(
        &mut c.0 .0,
        &c1.0 .0,
        &[
            12928131339836545255,
            14656515774364340114,
            14298431805095917272,
            7172476251385522123,
        ],
    );

    // D = z1 * z2
    let mut d = Fq::zero();
    mod_mul_zkvm(&mut d.0 .0, &result.z.0 .0, &other.z.0 .0);

    let mut h1 = a.clone();
    mod_mul_zkvm(
        &mut h1.0 .0,
        &a.0 .0,
        &[
            18446744069414584316,
            6034159408538082302,
            3691218898639771653,
            8353516859464449352,
        ],
    );

    let h = b - &h1;

    // E = (x1 + y1) * (x2 + y2) - A - B
    let e1 = result.x + &result.y;
    let e2 = other.x + &other.y;
    let mut e = Fq::zero();
    mod_mul_zkvm(&mut e.0 .0, &e1.0 .0, &e2.0 .0);
    e = e - &a - &b;

    // F = D - C
    let f = d - &c;

    // G = D + C
    let g = d + &c;

    // x3 = E * F
    mod_mul_zkvm(&mut result.x.0 .0, &e.0 .0, &f.0 .0);
    // println!("result.x {:?}",result.x.0.0);

    // y3 = G * H
    mod_mul_zkvm(&mut result.y.0 .0, &g.0 .0, &h.0 .0);
    // println!("result.y {:?}",result.y.0.0);

    // t3 = E * H
    mod_mul_zkvm(&mut result.t.0 .0, &e.0 .0, &h.0 .0);
    // println!("result.t {:?}",result.t.0.0);

    // z3 = F * G
    mod_mul_zkvm(&mut result.z.0 .0, &f.0 .0, &g.0 .0);
    // println!("result.z {:?}",result.z.0.0);
}

/*fn add_projective_zkvm(result: &mut ProjectiveZkvm, other: &ProjectiveZkvm) {
    // A = x1 * x2
    let mut a = [0u32; 8];
    let mut b = [0u32; 8];
    let mut c = [0u32; 8];
    let mut d = [0u32; 8];
    let mut h = [0u32; 8];
    let mut e = [0u32; 8];
    let mut f = [0u32; 8];
    let mut g = [0u32; 8];

    mod_mul_u32_zkvm(&mut a, &result.x, &other.x);

    // B = y1 * y2
    mod_mul_u32_zkvm(&mut b, &result.y, &other.y);
    // println!("b {:?}",b.0.0);

    // C = d * t1 * t2
    let mut c1 = [0u32; 8];

    mod_mul_u32_zkvm(&mut c1, &result.t, &other.t);
    mod_mul_u32_zkvm(
        &mut c,
        &c1,
        &[
            0x188D58E7, 0xB369F2F5, 0x77E54F92, 0xCB666771, 0x6BE3B6D8, 0xC66E3BF8, 0x33C267CB,
            0x6389C126,
        ],
    );

    // D = z1 * z2
    mod_mul_u32_zkvm(&mut d, &result.z, &other.z);

    let mut h1 = a.clone();
    mod_mul_u32_zkvm(
        &mut h1,
        &a,
        &[
            0xFFFFFFFC, 0xFFFFFFFE, 0xFFFE5BFE, 0x53BDA402, 0x09A1D805, 0x3339D808, 0x299D7D48,
            0x73EDA753,
        ],
    );

    mod_sub(&mut b, &h1, &mut h);

    // E = (x1 + y1) * (x2 + y2) - A - B
    let mut e1 = [0u32; 8];
    let mut e2 = [0u32; 8];
    mod_add(&result.x, &result.y, &mut e1);
    mod_add(&other.x, &other.y, &mut e2);
    mod_mul_u32_zkvm(&mut e, &e1, &e2);

    let mut e3 = [0u32; 8];
    mod_sub(&e, &a, &mut e3);
    mod_sub(&e3, &b, &mut e);

    // F = D - C
    mod_sub(&d, &c, &mut f);
    // G = D + C
    mod_add(&d, &c, &mut g);

    // x3 = E * F
    mod_mul_u32_zkvm(&mut result.x, &e, &f);

    // y3 = G * H
    mod_mul_u32_zkvm(&mut result.y, &g, &h);

    // t3 = E * H
    mod_mul_u32_zkvm(&mut result.t, &e, &h);

    // z3 = F * G
    mod_mul_u32_zkvm(&mut result.z, &f, &g);
}

fn add_affine_point_zkvm(result: &mut ProjectiveZkvm, p2x: &Fq, p2y: &Fq) {
    let mut p2_x = u64_array_to_u32_array_le(&p2x.0 .0);
    let mut p2_y = u64_array_to_u32_array_le(&p2y.0 .0);

    let mut a = [0u32; 8];
    let mut b = [0u32; 8];
    let mut c = [0u32; 8];
    let mut d = [0u32; 8];
    mod_mul_u32_zkvm(&mut a, &result.x, &p2_x);
    mod_mul_u32_zkvm(&mut b, &result.y, &p2_y);
    mod_mul_u32_zkvm(&mut c, &p2_x, &p2_y);
    mod_mul_u32_zkvm(&mut d, &result.t, &c);

    mod_mul_u32_zkvm(
        &mut c,
        &d,
        &[
            0x188D58E7, 0xB369F2F5, 0x77E54F92, 0xCB666771, 0x6BE3B6D8, 0xC66E3BF8, 0x33C267CB,
            0x6389C126,
        ],
    );
    let mut x_add_y = [0u32; 8];
    let mut p2x_add_p2y = [0u32; 8];
    mod_add(&result.x, &result.y, &mut x_add_y);
    mod_add(&p2_x, &p2_y, &mut p2x_add_p2y);

    mod_mul_u32_zkvm(&mut d, &x_add_y, &p2x_add_p2y);

    let mut e1 = [0u32; 8];
    mod_sub(&d, &a, &mut e1);
    let mut e = [0u32; 8];
    mod_sub(&e1, &b, &mut e);
    let mut f = [0u32; 8];
    mod_sub(&result.z, &c, &mut f);
    let mut g = [0u32; 8];
    mod_add(&result.z, &c, &mut g);

    mod_mul_by5_u32_zkvm(&mut a);
    let mut h = [0u32; 8];
    mod_add(&b, &a, &mut h);

    mod_mul_u32_zkvm(&mut result.x, &e, &f);
    mod_mul_u32_zkvm(&mut result.y, &g, &h);
    mod_mul_u32_zkvm(&mut result.t, &e, &h);
    mod_mul_u32_zkvm(&mut result.z, &f, &g);
}*/

/// TODO
pub fn scalar_mul_zkvm(base: &Element, scalar: &Fr) -> Element {
    // let start = env::cycle_count();
    let mut result = Element::zero();
    let mut temp = base.clone();
    let scalar_bigint = scalar.into_bigint();
    let scalar_bytes = scalar_bigint.to_bytes_le();

    for bit_position in 0..253 {
        let byte = scalar_bytes[bit_position / 8];
        let bit = (byte >> (bit_position % 8)) & 1;
        if bit == 1 {
            add_projective(&mut result.0, &temp.0);
        }
        if bit_position < 252 {
            let temp_clone = temp.0.clone();
            add_projective(&mut temp.0, &temp_clone);
        }
    }
    // let end = env::cycle_count();
    // println!("Scalar multiplication time is: {:?}", end - start);
    result
}

/// TODO
pub(crate) fn msm_bigint_wnaf_zkvm(bases: &[Element], scalars: &[Fr]) -> Element {
    let size = cmp::min(bases.len(), scalars.len());
    let scalars = &scalars[..size];
    let bases = &bases[..size];

    // 将 Fr 转为 BigInt，供 make_digits 使用
    let bigints: Vec<_> = scalars.iter().map(|s| s.into_bigint()).collect();

    // 选择窗口大小 c
    let c = if size < 32 {
        3
    } else {
        ln_without_floats(size) + 2
    };

    // 按标量比特宽度切分 wNAF 窗口
    let num_bits = Fr::MODULUS_BIT_SIZE as usize;
    let digits_count = num_bits.div_ceil(c);

    // 用 BigInt 展开 wNAF 数位
    let scalar_digits = bigints
        .iter()
        .flat_map(|b| make_digits(b, c, num_bits))
        .collect::<Vec<_>>();

    let zero = Element::zero();

    // 对每个窗口独立累加对应桶
    let window_sums: Vec<_> = (0..digits_count)
        .into_iter()
        .map(|i| {
            let mut buckets = vec![zero; 1 << c];

            for (digits, base) in scalar_digits.chunks(digits_count).zip(bases) {
                let d = digits[i];
                if d > 0 {
                    // buckets[(d - 1) as usize] += *base;
                    add_projective(&mut buckets[(d - 1) as usize].0, &base.0);
                } else if d < 0 {
                    let neg_base = base.neg();
                    // buckets[(-d - 1) as usize] += neg_base;
                    add_projective(&mut buckets[(-d - 1) as usize].0, &neg_base.0);
                }
            }

            // 反向前缀和
            let mut running_sum = Element::zero();
            let mut res = Element::zero();
            for b in buckets.into_iter().rev() {
                // running_sum += b;
                // res += running_sum;
                add_projective(&mut running_sum.0, &b.0);
                add_projective(&mut res.0, &running_sum.0);
            }
            res
        })
        .collect();

    // 最低窗的和
    let lowest = *window_sums.first().unwrap();

    // 从高到低窗回代，每窗做 c 次倍点
    // lowest
    //     + window_sums[1..]
    //     .iter()
    //     .rev()
    //     .fold(Element::zero(), |mut total, sum_i| {
    //         total += *sum_i;
    //         for _ in 0..c {
    //             total = Element(total.0 + total.0);
    //         }
    //         total
    //     })
    lowest
        + window_sums[1..]
            .iter()
            .rev()
            .fold(Element::zero(), |mut total, sum_i| {
                // total += *sum_i;
                add_projective(&mut total.0, &sum_i.0);
                for _ in 0..c {
                    // total = Element(total.0 + total.0);
                    let total_clone = total.0.clone();
                    add_projective(&mut total.0, &total_clone);
                }
                total
            })
}

/// TODO
fn ln_without_floats(n: usize) -> usize {
    // SAFETY: n>0 时合法；上层已保证 size>0
    usize::BITS as usize - 1 - n.leading_zeros() as usize
}

/// 从标量大整数构造 wNAF 数位（来自 gemini 实现，做了内联）
fn make_digits(a: &impl BigInteger, w: usize, num_bits: usize) -> impl Iterator<Item = i64> + '_ {
    let scalar = a.as_ref();
    let radix: u64 = 1 << w;
    let window_mask: u64 = radix - 1;

    let mut carry = 0u64;
    let num_bits = if num_bits == 0 {
        a.num_bits() as usize
    } else {
        num_bits
    };
    let digits_count = num_bits.div_ceil(w);

    (0..digits_count).map(move |i| {
        let bit_offset = i * w;
        let u64_idx = bit_offset / 64;
        let bit_idx = bit_offset % 64;

        let bit_buf = if bit_idx < 64 - w || u64_idx == scalar.len() - 1 {
            scalar[u64_idx] >> bit_idx
        } else {
            (scalar[u64_idx] >> bit_idx) | (scalar[1 + u64_idx] << (64 - bit_idx))
        };

        let coef = carry + (bit_buf & window_mask); // [0, 2^w)
        carry = (coef + radix / 2) >> w;

        let mut digit = (coef as i64) - (carry << w) as i64;
        if i == digits_count - 1 {
            digit += (carry << w) as i64;
        }
        digit
    })
}

pub const MODULUS: [u32; 8] = [
    0x00000001, 0xffffffff, 0xfffe5bfe, 0x53bda402, 0x09a1d805, 0x3339d808, 0x299d7d48, 0x73eda753,
];

/// Compares two arrays of `u32` values.
/// Returns `true` if `a` is greater than or equal to `b`, otherwise `false`.
pub(crate) fn compare(a: &[u32; 8], b: &[u32; 8]) -> bool {
    for i in (0..8).rev() {
        if a[i] > b[i] {
            return true;
        } else if a[i] < b[i] {
            return false;
        }
    }
    true
}
pub(crate) fn add(a: &[u32; 8], b: &[u32; 8], out: &mut [u32; 8]) {
    let mut carry = 0u32;

    for i in 0..8 {
        let (sum, carry1) = a[i].overflowing_add(b[i]);
        let (sum, carry2) = sum.overflowing_add(carry);
        out[i] = sum;
        carry = (carry1 as u32) + (carry2 as u32);
    }
}

pub(crate) fn sub(a: &[u32; 8], b: &[u32; 8], out: &mut [u32; 8]) {
    let mut borrow = 0u32;

    for i in 0..8 {
        let (diff, new_borrow) = a[i].overflowing_sub(b[i] + borrow);
        out[i] = diff;
        borrow = if new_borrow { 1 } else { 0 };
    }
}

pub(crate) fn mod_add(a: &[u32; 8], b: &[u32; 8], out: &mut [u32; 8]) {
    let mut sum = [0u32; 8];
    add(a, b, &mut sum);
    if compare(&sum, &MODULUS) {
        sub(&sum, &MODULUS, out);
    } else {
        *out = sum;
    }
}

pub(crate) fn mod_sub(a: &[u32; 8], b: &[u32; 8], out: &mut [u32; 8]) {
    if compare(a, b) {
        sub(a, b, out);
    } else {
        let mut diff = [0u32; 8];
        sub(&MODULUS, b, &mut diff);
        add(a, &diff, out);
    }
}
#[derive(Clone)]
pub struct ProjectiveZkvm {
    pub x: [u32; 8],
    pub y: [u32; 8],
    pub t: [u32; 8],
    pub z: [u32; 8],
}
impl ProjectiveZkvm {
    /// Initializes the structure to zero
    pub fn init_zero() -> Self {
        ProjectiveZkvm {
            x: [0; 8],
            y: [1, 0, 0, 0, 0, 0, 0, 0],
            t: [0; 8],
            z: [1, 0, 0, 0, 0, 0, 0, 0],
        }
    }

    pub fn to_edwards_projective(&self) -> EdwardsProjective {
        let mut data_x: [u64; 4] = [0; 4];
        let mut data_y: [u64; 4] = [0; 4];
        let mut data_t: [u64; 4] = [0; 4];
        let mut data_z: [u64; 4] = [0; 4];
        u32_array_to_u64_array_le(&self.x, &mut data_x);
        u32_array_to_u64_array_le(&self.y, &mut data_y);
        u32_array_to_u64_array_le(&self.t, &mut data_t);
        u32_array_to_u64_array_le(&self.z, &mut data_z);
        EdwardsProjective {
            x: Fq::new(BigInt::new(data_x)),
            y: Fq::new(BigInt::new(data_y)),
            t: Fq::new(BigInt::new(data_t)),
            z: Fq::new(BigInt::new(data_z)),
        }
    }

    /// TODO
    pub fn from_edwards_projective(edwards: &EdwardsProjective) -> Self {
        let x = edwards.x.into_bigint();
        let y = edwards.y.into_bigint();
        let t = edwards.t.into_bigint();
        let z = edwards.z.into_bigint();
        let x_data = u64_array_to_u32_array_le(&x.0);
        let y_data = u64_array_to_u32_array_le(&y.0);
        let t_data = u64_array_to_u32_array_le(&t.0);
        let z_data = u64_array_to_u32_array_le(&z.0);
        ProjectiveZkvm {
            x: x_data,
            y: y_data,
            t: t_data,
            z: z_data,
        }
    }
}

#[derive(Clone)]
pub struct AffineZkvm {
    pub x: [u32; 8],
    pub y: [u32; 8],
}

impl AffineZkvm {
    /// Initializes the structure to zero
    pub fn init_zero() -> Self {
        AffineZkvm {
            x: [0; 8],
            y: [1, 0, 0, 0, 0, 0, 0, 0],
        }
    }
}

pub(crate) const BIGINT_WIDTH_WORDS: usize = 8;
pub(crate) const FQ: [u32; BIGINT_WIDTH_WORDS] = [
    0x00000001, 0xffffffff, 0xfffe5bfe, 0x53bda402, 0x09a1d805, 0x3339d808, 0x299d7d48, 0x73eda753,
];

///convert bigint from u64 array to u32 array, little-endian
pub(crate) fn u64_array_to_u32_array_le(input: &[u64; 4]) -> [u32; 8] {
    let mut output = [0u32; 8];
    output[0] = (input[0] & 0xFFFFFFFF) as u32;
    output[1] = (input[0] >> 32) as u32;
    output[2] = (input[1] & 0xFFFFFFFF) as u32;
    output[3] = (input[1] >> 32) as u32;
    output[4] = (input[2] & 0xFFFFFFFF) as u32;
    output[5] = (input[2] >> 32) as u32;
    output[6] = (input[3] & 0xFFFFFFFF) as u32;
    output[7] = (input[3] >> 32) as u32;
    output
}

///convert bigint from u32 array to u64 array, little-endian
pub(crate) fn u32_array_to_u64_array_le(input: &[u32; 8], output: &mut [u64; 4]) {
    output[0] = (input[0] as u64) | ((input[1] as u64) << 32);
    output[1] = (input[2] as u64) | ((input[3] as u64) << 32);
    output[2] = (input[4] as u64) | ((input[5] as u64) << 32);
    output[3] = (input[6] as u64) | ((input[7] as u64) << 32);
}

///Implement Montgomery modular multiplication, result = x * y * R^-1 mod N
//先计算 z = x * y，然后计算z * R^-1 mod N
pub(crate) fn mont_mul_zkvm(result: &mut [u64; 4], x: &[u64; 4], y: &[u64; 4]) {
    let inv_r: [u32; BIGINT_WIDTH_WORDS] = [
        0xfe75c040, 0x13f75b69, 0x09dc705f, 0xab6fca8f, 0x4f77266a, 0x7204078a, 0x30009d57,
        0x1bbe8693,
    ];
    // let r: [u32; BIGINT_WIDTH_WORDS] = [0xfffffffe, 0x00000001, 0x00034802, 0x5884b7fa, 0xecbc4ff5, 0x998c4fef, 0xacc5056f, 0x1824b159];
    let fq: [u32; BIGINT_WIDTH_WORDS] = [
        0x00000001, 0xffffffff, 0xfffe5bfe, 0x53bda402, 0x09a1d805, 0x3339d808, 0x299d7d48,
        0x73eda753,
    ];
    let mut z: [u32; BIGINT_WIDTH_WORDS] = [0; BIGINT_WIDTH_WORDS];
    let mut out: [u32; BIGINT_WIDTH_WORDS] = [0; BIGINT_WIDTH_WORDS];
    let x_32 = u64_array_to_u32_array_le(x);
    let y_32 = u64_array_to_u32_array_le(y);

    // 调用 sys_bigint 函数
    unsafe {
        sys_bigint(&mut z, OP_MULTIPLY, &x_32, &y_32, &fq);
        sys_bigint(&mut out, OP_MULTIPLY, &z, &inv_r, &fq);
    }
    u32_array_to_u64_array_le(&out, result);
}

///compute result = 5 * x  mod N
pub(crate) fn mod_mul_by5_zkvm(result: &mut [u64; 4]) {
    let x_32 = u64_array_to_u32_array_le(result);
    let e5: [u32; BIGINT_WIDTH_WORDS] = [5, 0, 0, 0, 0, 0, 0, 0];
    let fq: [u32; BIGINT_WIDTH_WORDS] = [
        0x00000001, 0xffffffff, 0xfffe5bfe, 0x53bda402, 0x09a1d805, 0x3339d808, 0x299d7d48,
        0x73eda753,
    ];
    let mut out: [u32; BIGINT_WIDTH_WORDS] = [0; BIGINT_WIDTH_WORDS];
    unsafe {
        sys_bigint(&mut out, OP_MULTIPLY, &x_32, &e5, &fq);
    }
    u32_array_to_u64_array_le(&out, result);
}

pub(crate) fn mod_mul_by5_u32_zkvm(result: &mut [u32; 8]) {
    let e5: [u32; BIGINT_WIDTH_WORDS] = [5, 0, 0, 0, 0, 0, 0, 0];
    let mut temp_result: [u32; BIGINT_WIDTH_WORDS] = [0; BIGINT_WIDTH_WORDS];
    unsafe {
        sys_bigint(&mut temp_result, OP_MULTIPLY, result, &e5, &FQ);
    }
    *result = temp_result;
}

///Implement  modular multiplication, result = x * y  mod N
pub(crate) fn mod_mul_zkvm(result: &mut [u64; 4], x: &[u64; 4], y: &[u64; 4]) {
    let fq: [u32; BIGINT_WIDTH_WORDS] = [
        0x00000001, 0xffffffff, 0xfffe5bfe, 0x53bda402, 0x09a1d805, 0x3339d808, 0x299d7d48,
        0x73eda753,
    ];
    let mut out: [u32; BIGINT_WIDTH_WORDS] = [0; BIGINT_WIDTH_WORDS];
    let x_32 = u64_array_to_u32_array_le(x);
    let y_32 = u64_array_to_u32_array_le(y);

    // 调用 sys_bigint 函数
    unsafe {
        sys_bigint(&mut out, OP_MULTIPLY, &x_32, &y_32, &fq);
    }
    u32_array_to_u64_array_le(&out, result);
}

pub(crate) fn mod_mul_u32_zkvm(result: &mut [u32; 8], x: &[u32; 8], y: &[u32; 8]) {
    unsafe {
        sys_bigint(result, OP_MULTIPLY, x, y, &FQ);
    }
}
/*
pub(crate) fn mod_mul_zkvm1(result: &mut [u64; 4], x: &[u64; 4], y: &[u64; 4]) {
    let fq: [u32; BIGINT_WIDTH_WORDS] = [
        0x00000001, 0xffffffff, 0xfffe5bfe, 0x53bda402, 0x09a1d805, 0x3339d808, 0x299d7d48,
        0x73eda753,
    ];
    let mut out: [u32; BIGINT_WIDTH_WORDS] = [345; BIGINT_WIDTH_WORDS];
    let x_32 = [
        0x00230001, 0xffffffff, 0xfffe5bfe, 0x53bda402, 0x09a1d805, 0x3339d808, 0x299d7d48, 0x23,
    ];
    let y_32 = [
        0x000001, 0xffffffff, 0xfffe5bfe, 0x53bda402, 0x09a1d805, 0x3339d808, 0x299d7d48, 0x19,
    ];

    // 调用 sys_bigint 函数
    unsafe {
        sys_bigint(&mut out, OP_MULTIPLY, &x_32, &y_32, &fq);
    }
    result[0] = 0x11u64;
    result[1] = 0x22u64;
    result[2] = 0x33u64;
    result[3] = 0x44u64;

    //u32_array_to_u64_array_le(&out, result);
}
    */

///convert  Montgomery filed to bigint,little-endian, result = x * R^(-1) mod N
pub(crate) fn from_mont_to_bigint(result: &mut [u64; 4], x: &[u64; 4]) {
    let inv_r: [u32; BIGINT_WIDTH_WORDS] = [
        0xfe75c040, 0x13f75b69, 0x09dc705f, 0xab6fca8f, 0x4f77266a, 0x7204078a, 0x30009d57,
        0x1bbe8693,
    ];
    let fq: [u32; BIGINT_WIDTH_WORDS] = [
        0x00000001, 0xffffffff, 0xfffe5bfe, 0x53bda402, 0x09a1d805, 0x3339d808, 0x299d7d48,
        0x73eda753,
    ];
    let mut out: [u32; BIGINT_WIDTH_WORDS] = [0; BIGINT_WIDTH_WORDS];
    let x_32 = u64_array_to_u32_array_le(x);

    // 调用 sys_bigint 函数
    unsafe {
        sys_bigint(&mut out, OP_MULTIPLY, &x_32, &inv_r, &fq);
    }
    u32_array_to_u64_array_le(&out, result);
}

///convert bigint(little-endian) to Montgomery filed, result = x * R mod N
pub(crate) fn from_bigint_to_mont(result: &mut [u64; 4], x: &[u64; 4]) {
    let r: [u32; BIGINT_WIDTH_WORDS] = [
        0xfffffffe, 0x00000001, 0x00034802, 0x5884b7fa, 0xecbc4ff5, 0x998c4fef, 0xacc5056f,
        0x1824b159,
    ];
    let fq: [u32; BIGINT_WIDTH_WORDS] = [
        0x00000001, 0xffffffff, 0xfffe5bfe, 0x53bda402, 0x09a1d805, 0x3339d808, 0x299d7d48,
        0x73eda753,
    ];
    let mut out: [u32; BIGINT_WIDTH_WORDS] = [0; BIGINT_WIDTH_WORDS];
    let x_32 = u64_array_to_u32_array_le(x);

    // 调用 sys_bigint 函数
    unsafe {
        sys_bigint(&mut out, OP_MULTIPLY, &x_32, &r, &fq);
    }
    u32_array_to_u64_array_le(&out, result);
}
///convert result_x,result_y,result_t,result_z from bigint to Montgomery filed
pub(crate) fn project_from_bigint_to_mont(
    result_x: &mut [u64; 4],
    result_y: &mut [u64; 4],
    result_t: &mut [u64; 4],
    result_z: &mut [u64; 4],
) {
    let r: [u32; BIGINT_WIDTH_WORDS] = [
        0xfffffffe, 0x00000001, 0x00034802, 0x5884b7fa, 0xecbc4ff5, 0x998c4fef, 0xacc5056f,
        0x1824b159,
    ];
    let fq: [u32; BIGINT_WIDTH_WORDS] = [
        0x00000001, 0xffffffff, 0xfffe5bfe, 0x53bda402, 0x09a1d805, 0x3339d808, 0x299d7d48,
        0x73eda753,
    ];
    let mut out: [u32; BIGINT_WIDTH_WORDS] = [0; BIGINT_WIDTH_WORDS];
    let x_32 = u64_array_to_u32_array_le(result_x);
    let y_32 = u64_array_to_u32_array_le(result_y);
    let t_32 = u64_array_to_u32_array_le(result_t);
    let z_32 = u64_array_to_u32_array_le(result_z);
    let mut t_x: [u32; BIGINT_WIDTH_WORDS] = [0; BIGINT_WIDTH_WORDS];
    let mut t_y: [u32; BIGINT_WIDTH_WORDS] = [0; BIGINT_WIDTH_WORDS];
    let mut t_t: [u32; BIGINT_WIDTH_WORDS] = [0; BIGINT_WIDTH_WORDS];
    let mut t_z: [u32; BIGINT_WIDTH_WORDS] = [0; BIGINT_WIDTH_WORDS];

    // 调用 sys_bigint 函数
    unsafe {
        sys_bigint(&mut t_x, OP_MULTIPLY, &x_32, &r, &fq);
        sys_bigint(&mut t_y, OP_MULTIPLY, &y_32, &r, &fq);
        sys_bigint(&mut t_t, OP_MULTIPLY, &t_32, &r, &fq);
        sys_bigint(&mut t_z, OP_MULTIPLY, &z_32, &r, &fq);
    }

    u32_array_to_u64_array_le(&t_x, result_x);
    u32_array_to_u64_array_le(&t_y, result_y);
    u32_array_to_u64_array_le(&t_t, result_t);
    u32_array_to_u64_array_le(&t_z, result_z);
}

pub(crate) fn init_zero(
    result_x: &mut [u64; 4],
    result_y: &mut [u64; 4],
    result_t: &mut [u64; 4],
    result_z: &mut [u64; 4],
) {
    result_x[0] = 0;
    result_x[1] = 0;
    result_x[2] = 0;
    result_x[3] = 0;

    result_y[0] = 1;
    result_y[1] = 0;
    result_y[2] = 0;
    result_y[3] = 0;

    result_t[0] = 0;
    result_t[1] = 0;
    result_t[2] = 0;
    result_t[3] = 0;

    result_z[0] = 1;
    result_z[1] = 0;
    result_z[2] = 0;
    result_z[3] = 0;
}
