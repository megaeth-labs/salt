//! The variable-base multi-scalar multiplication of [`crate::multi_scalar_mul`] with the Pippenger bucket
//! accumulation and bucket reduction run eight-wide on AVX-512 IFMA, in the lane field arithmetic of
//! [`crate::ifma`].
//!
//! Accumulation, lane = bucket over digit-sorted runs (`msm_runs`): the points are prepared once, eight at
//! a time, into a point-major table (x, y, x + y, d·x·y in lane limbs); for each window the points are
//! counting-sorted by their signed digit, the non-empty buckets (runs) are ordered longest first, and eight
//! runs at a time are summed in registers — each step loads one point per lane by three row loads and an
//! in-register 8 × 8 transpose (no gather touches the table) and adds it, masked where a lane's run is
//! exhausted; a finished batch's eight bucket sums are scattered once into a lane-major bucket store
//! (lane = window there), kept per thread across calls. Nothing is gathered or scattered per point.
//! Reduction, lane = window: the running sums over the buckets, high to low, are eight independent chains
//! per group of windows; buckets no point reached are read as the identity through a mask. Signed digits
//! and the window combination are ark-ec's (`msm_bigint_wnaf`); the window size is the lanes' own
//! (`lane_window`). The result is the same group element the scalar path computes, which the tests check
//! against `EdwardsProjective::msm` on random inputs including zero scalars, the identity, equal scalars
//! (every point in one bucket) and every window size.
//!
//! Group additions are the unified twisted-Edwards formulas in extended coordinates (Hisil–Wong–Carter–
//! Dawson 2008, `a = -5`): mixed addition 9 lane products, full addition 11.
#![allow(clippy::needless_range_loop)]
use crate::ifma::*;
use ark_ec::twisted_edwards::TECurveConfig;
use ark_ec::AdditiveGroup;
use ark_ed_on_bls12_381_bandersnatch::{BandersnatchConfig, EdwardsAffine, EdwardsProjective, Fr};
use ark_ff::Field;
use ark_ff::{BigInt, BigInteger, PrimeField, Zero};
use core::arch::x86_64::*;
use std::cell::RefCell;
use std::sync::OnceLock;

thread_local! {
    /// The bucket store, kept per thread across calls: a fresh multi-megabyte allocation per call is
    /// re-faulted page by page on every call (glibc maps and unmaps it; jemalloc caches it for a while),
    /// and the store is written before it is read, so it needs no clearing between calls.
    static BUCKET_SCRATCH: RefCell<Vec<u64>> = const { RefCell::new(Vec::new()) };
}

/// Projective extended point, eight lanes.
#[derive(Clone, Copy)]
pub(crate) struct PtL {
    pub(crate) x: L5,
    pub(crate) y: L5,
    pub(crate) t: L5,
    pub(crate) z: L5,
}

/// Affine point prepared for mixed addition, eight lanes: x, y, x + y, d·x·y.
#[derive(Clone, Copy)]
struct AffL {
    x: L5,
    y: L5,
    xy: L5,
    dt: L5,
}

pub(crate) struct Consts {
    pub(crate) five: L5,
    pub(crate) d: L5,
    pub(crate) zero: L5,
    pub(crate) id: PtL,
    /// 2^264 mod p on every lane: `mont_mul(x·2^256, k264) = x·2^260`, ark's Montgomery representation
    /// taken straight into the lane form without a scalar reduction.
    k264: L5,
}

// SAFETY: __m512i is plain data; the constants are built once and only read afterwards.
unsafe impl Sync for Consts {}
unsafe impl Send for Consts {}

pub(crate) fn consts() -> &'static Consts {
    static K: OnceLock<Consts> = OnceLock::new();
    // SAFETY: callers check `available()` first; this only broadcasts constants.
    K.get_or_init(|| unsafe { build_consts(context()) })
}

#[target_feature(enable = "avx512f,avx512ifma")]
unsafe fn build_consts(c: &Ctx) -> Consts {
    let five = bcast(&bcast_limbs(&Fq::from(5u64)));
    let d = bcast(&bcast_limbs(&BandersnatchConfig::COEFF_D));
    let zero = [_mm512_setzero_si512(); 5];
    let k264 = {
        let mut v = Fq::from(2u64);
        v = v.pow([264u64]);
        bcast(&to_limbs52(&v.into_bigint()))
    };
    Consts {
        five,
        d,
        zero,
        id: PtL {
            x: zero,
            y: c.one,
            t: zero,
            z: c.one,
        },
        k264,
    }
}

/// The affine points in lane form, point-major: 20 words each (x, y, x + y, d·x·y), eight points per
/// pass through the lane multiplier; the tail is padded with the last point.
#[target_feature(enable = "avx512f,avx512ifma")]
unsafe fn prep_points(c: &Ctx, k: &Consts, bases: &[EdwardsAffine], out: &mut [u64]) {
    let n = bases.len();
    let mut i = 0;
    while i < n {
        let mut xl = [[0u64; 8]; 5];
        let mut yl = [[0u64; 8]; 5];
        for l in 0..8 {
            let p = &bases[(i + l).min(n - 1)];
            let x = to_limbs52(&p.x.0);
            let y = to_limbs52(&p.y.0);
            for j in 0..5 {
                xl[j][l] = x[j];
                yl[j][l] = y[j];
            }
        }
        let mut xv = [_mm512_setzero_si512(); 5];
        let mut yv = [_mm512_setzero_si512(); 5];
        for j in 0..5 {
            xv[j] = _mm512_loadu_si512(xl[j].as_ptr() as *const _);
            yv[j] = _mm512_loadu_si512(yl[j].as_ptr() as *const _);
        }
        let xv = mont_mul(c, &xv, &k.k264);
        let yv = mont_mul(c, &yv, &k.k264);
        let xy = add(c, &xv, &yv);
        let dt = mont_mul(c, &mont_mul(c, &xv, &yv), &k.d);
        let ws = [to_words(&xv), to_words(&yv), to_words(&xy), to_words(&dt)];
        for l in 0..8 {
            if i + l >= n {
                break;
            }
            let o = (i + l) * PW;
            for coord in 0..4 {
                for j in 0..5 {
                    out[o + coord * 5 + j] = ws[coord][j][l];
                }
            }
        }
        i += 8;
    }
}

/// Per-point precomputation in lane form (x, y, x+y, d·x·y), 20 words (scalar; superseded by `prep_points`).
#[cfg(test)]
#[allow(dead_code)]
fn prep_affine(p: &EdwardsAffine) -> [u64; 20] {
    let mut out = [0u64; 20];
    out[0..5].copy_from_slice(&bcast_limbs(&p.x));
    out[5..10].copy_from_slice(&bcast_limbs(&p.y));
    out[10..15].copy_from_slice(&bcast_limbs(&(p.x + p.y)));
    out[15..20].copy_from_slice(&bcast_limbs(&(BandersnatchConfig::COEFF_D * p.x * p.y)));
    out
}

#[cfg(test)]
#[inline]
#[target_feature(enable = "avx512f,avx512ifma")]
unsafe fn bcast_aff(w: &[u64; 20]) -> AffL {
    AffL {
        x: bcast(w[0..5].try_into().unwrap()),
        y: bcast(w[5..10].try_into().unwrap()),
        xy: bcast(w[10..15].try_into().unwrap()),
        dt: bcast(w[15..20].try_into().unwrap()),
    }
}

/// Lanes of `q` negated where the mask bit is set: (-x, y), x+y -> y-x, d·x·y -> -d·x·y.
#[inline]
#[target_feature(enable = "avx512f,avx512ifma")]
unsafe fn neg_aff(c: &Ctx, k: &Consts, q: &AffL, m: __mmask8) -> AffL {
    let nx = sub(c, &k.zero, &q.x);
    let nxy = sub(c, &q.y, &q.x);
    let ndt = sub(c, &k.zero, &q.dt);
    AffL {
        x: sel(m, &q.x, &nx),
        y: q.y,
        xy: sel(m, &q.xy, &nxy),
        dt: sel(m, &q.dt, &ndt),
    }
}

/// Mixed addition p + q (Z2 = 1, a = -5), 9 lane products.
#[inline]
#[target_feature(enable = "avx512f,avx512ifma")]
unsafe fn madd(c: &Ctx, k: &Consts, p: &PtL, q: &AffL) -> PtL {
    let a = mont_mul(c, &p.x, &q.x);
    let b = mont_mul(c, &p.y, &q.y);
    let cc = mont_mul(c, &p.t, &q.dt);
    let dd = mont_mul(c, &add(c, &p.x, &p.y), &q.xy);
    let e = sub(c, &sub(c, &dd, &a), &b);
    let f = sub(c, &p.z, &cc);
    let g = add(c, &p.z, &cc);
    let h = add(c, &b, &mont_mul(c, &a, &k.five));
    PtL {
        x: mont_mul(c, &e, &f),
        y: mont_mul(c, &g, &h),
        t: mont_mul(c, &e, &h),
        z: mont_mul(c, &f, &g),
    }
}

/// Full addition p + q, 11 lane products.
#[inline]
#[target_feature(enable = "avx512f,avx512ifma")]
pub(crate) unsafe fn padd(c: &Ctx, k: &Consts, p: &PtL, q: &PtL) -> PtL {
    let a = mont_mul(c, &p.x, &q.x);
    let b = mont_mul(c, &p.y, &q.y);
    let cc = mont_mul(c, &mont_mul(c, &p.t, &q.t), &k.d);
    let dd = mont_mul(c, &p.z, &q.z);
    let ee = mont_mul(c, &add(c, &p.x, &p.y), &add(c, &q.x, &q.y));
    let e = sub(c, &sub(c, &ee, &a), &b);
    let f = sub(c, &dd, &cc);
    let g = add(c, &dd, &cc);
    let h = add(c, &b, &mont_mul(c, &a, &k.five));
    PtL {
        x: mont_mul(c, &e, &f),
        y: mont_mul(c, &g, &h),
        t: mont_mul(c, &e, &h),
        z: mont_mul(c, &f, &g),
    }
}

/// The eight lanes of a lane point as ark projective points.
#[target_feature(enable = "avx512f,avx512ifma")]
pub(crate) unsafe fn unlane(c: &Ctx, p: &PtL) -> [EdwardsProjective; 8] {
    let x = store(c, &p.x);
    let y = store(c, &p.y);
    let t = store(c, &p.t);
    let z = store(c, &p.z);
    let mut out = [EdwardsProjective::zero(); 8];
    for i in 0..8 {
        out[i] = EdwardsProjective::new_unchecked(x[i], y[i], t[i], z[i]);
    }
    out
}

/// ark-ec's `make_digits` (scalar_mul/variable_base/mod.rs), so the bucket semantics match.
fn make_digits(a: &impl BigInteger, w: usize, num_bits: usize, out: &mut [i64]) {
    let scalar = a.as_ref();
    let radix: u64 = 1 << w;
    let window_mask: u64 = radix - 1;
    let mut carry = 0u64;
    let digits_count = num_bits.div_ceil(w);
    for i in 0..digits_count {
        let bit_offset = i * w;
        let u64_idx = bit_offset / 64;
        let bit_idx = bit_offset % 64;
        let bit_buf = if bit_idx < 64 - w || u64_idx == scalar.len() - 1 {
            scalar[u64_idx] >> bit_idx
        } else {
            (scalar[u64_idx] >> bit_idx) | (scalar[1 + u64_idx] << (64 - bit_idx))
        };
        let coef = carry + (bit_buf & window_mask);
        carry = (coef + radix / 2) >> w;
        let mut digit = (coef as i64) - (carry << w) as i64;
        if i == digits_count - 1 {
            digit += (carry << w) as i64;
        }
        out[i] = digit;
    }
}

/// ark-ec's window-size rule: log2(a) * ln(2), integer (the C2 design's rule, kept for the bench).
#[cfg(test)]
fn ln_without_floats(a: usize) -> usize {
    // ark_std::log2: the number of bits needed to represent a - 1, i.e. ceil(log2(a)); 0 for a <= 1
    let log2 = if a <= 1 {
        0
    } else {
        usize::BITS - (a - 1).leading_zeros()
    };
    (log2 * 69 / 100) as usize
}

/// Words per bucket in lane-major layout: 20 words × 8 lanes.
const BW: usize = 160;
/// Words per prepared point in the point-major table: 20 used (x, y, x + y, d·x·y) padded to three
/// eight-word rows, so eight points load as 24 rows and transpose in registers.
const PW: usize = 24;

/// `sum_i scalars[i] * bases[i]`, the same element as `EdwardsProjective::msm(bases, scalars)`.
///
/// # Safety
/// `available()` must have returned true on this host.
#[target_feature(enable = "avx512f,avx512ifma")]
pub(crate) unsafe fn msm(bases: &[EdwardsAffine], scalars: &[Fr]) -> EdwardsProjective {
    let n = bases.len().min(scalars.len());
    msm_runs(bases, scalars, lane_window(n))
}

/// The window size for the lane accumulation. ark's rule (`ln_without_floats(n) + 2`: c = 10 at the
/// verifier's per-thread chunk of ≈ 2,560 points) balances scalar bucket additions against the
/// reduction; in lanes the reduction's two full additions per bucket are the dear part (≈ 1,400
/// cycles per bucket, 22 products) and the bucket store must stay in cache, so the window is two sizes
/// smaller than ark's at the chunk and grows with the point count — measured one thread on this host:
/// n = 2,560: c = 8 2.0 µs/point, c = 9 2.3, c = 10 2.7; n = 40,960: c = 10 1.7, c = 11 1.5.
fn lane_window(n: usize) -> usize {
    if n < 32 {
        3
    } else {
        let log2 = usize::BITS - (n - 1).leading_zeros();
        // Capped at 9 (a 2.6 MB bucket store): the store is thread-local and retained, and a
        // whole-witness MSM (n ≈ 50k) on every resident validation's own thread at c = 11 would hold
        // 10.5 MB per thread.
        (log2 as usize).saturating_sub(4).clamp(8, 9)
    }
}

/// 8 × 8 transpose of 64-bit words: `r[i]` holds point `i`'s eight words in; word `j` of every point out.
#[inline]
#[target_feature(enable = "avx512f")]
pub(crate) unsafe fn transpose8(r: &[__m512i; 8]) -> [__m512i; 8] {
    let t0 = _mm512_unpacklo_epi64(r[0], r[1]);
    let t1 = _mm512_unpackhi_epi64(r[0], r[1]);
    let t2 = _mm512_unpacklo_epi64(r[2], r[3]);
    let t3 = _mm512_unpackhi_epi64(r[2], r[3]);
    let t4 = _mm512_unpacklo_epi64(r[4], r[5]);
    let t5 = _mm512_unpackhi_epi64(r[4], r[5]);
    let t6 = _mm512_unpacklo_epi64(r[6], r[7]);
    let t7 = _mm512_unpackhi_epi64(r[6], r[7]);
    // 128-bit lanes: gather lanes (0,2) / (1,3) of each pair
    let u0 = _mm512_shuffle_i64x2::<0x88>(t0, t2);
    let u1 = _mm512_shuffle_i64x2::<0xdd>(t0, t2);
    let u2 = _mm512_shuffle_i64x2::<0x88>(t1, t3);
    let u3 = _mm512_shuffle_i64x2::<0xdd>(t1, t3);
    let u4 = _mm512_shuffle_i64x2::<0x88>(t4, t6);
    let u5 = _mm512_shuffle_i64x2::<0xdd>(t4, t6);
    let u6 = _mm512_shuffle_i64x2::<0x88>(t5, t7);
    let u7 = _mm512_shuffle_i64x2::<0xdd>(t5, t7);
    [
        _mm512_shuffle_i64x2::<0x88>(u0, u4),
        _mm512_shuffle_i64x2::<0x88>(u2, u6),
        _mm512_shuffle_i64x2::<0x88>(u1, u5),
        _mm512_shuffle_i64x2::<0x88>(u3, u7),
        _mm512_shuffle_i64x2::<0xdd>(u0, u4),
        _mm512_shuffle_i64x2::<0xdd>(u2, u6),
        _mm512_shuffle_i64x2::<0xdd>(u1, u5),
        _mm512_shuffle_i64x2::<0xdd>(u3, u7),
    ]
}

/// One batch of up to eight runs (bucket, start in `order`, length), accumulated in registers with lane =
/// run, then scattered once into the lane-major bucket store at group offset `gbase` and lane `lane`.
/// A separate `target_feature` function rather than a closure, so the intrinsics inline.
#[target_feature(enable = "avx512f,avx512ifma")]
#[allow(clippy::too_many_arguments)]
unsafe fn run_batch(
    c: &Ctx,
    k: &Consts,
    pts: &[u64],
    order: &[u64],
    batch: &[(u32, u32, u32); 8],
    fill: usize,
    bptr: *mut u64,
    gbase: usize,
    lane: usize,
    nonempty: &mut [u8],
) {
    let zero = _mm512_setzero_si512();
    let mut bl = [0i64; 8];
    let mut sl = [0i64; 8];
    let mut ll = [0i64; 8];
    let mut maxlen = 0u32;
    for l in 0..fill {
        bl[l] = batch[l].0 as i64;
        sl[l] = batch[l].1 as i64;
        ll[l] = batch[l].2 as i64;
        maxlen = maxlen.max(batch[l].2);
    }
    let m_valid: __mmask8 = ((1u16 << fill) - 1) as __mmask8;
    let len_v = _mm512_loadu_si512(ll.as_ptr() as *const _);
    let b_v = _mm512_loadu_si512(bl.as_ptr() as *const _);
    let mut p = k.id;
    for s in 0..maxlen as i64 {
        let s_v = _mm512_set1_epi64(s);
        let m: __mmask8 = _mm512_cmpgt_epi64_mask(len_v, s_v) & m_valid;
        // the eight lanes' next points: index and sign from `order` (an exhausted lane re-reads its last
        // point, masked out of the addition below), three eight-word rows per point loaded and
        // transposed in registers so no gather touches the table
        let mut neg: __mmask8 = 0;
        let mut rows = [[zero; 8]; 3];
        for l in 0..8 {
            let pos = if (m >> l) & 1 == 1 {
                sl[l] as usize + s as usize
            } else {
                sl[l] as usize
            };
            let e = *order.get_unchecked(pos.min(order.len() - 1));
            neg |= (((e >> 32) & 1) as u8) << l;
            let base = pts.as_ptr().add((e & 0xffff_ffff) as usize * PW);
            for r in 0..3 {
                rows[r][l] = _mm512_loadu_si512(base.add(r * 8) as *const _);
            }
        }
        let t0 = transpose8(&rows[0]);
        let t1 = transpose8(&rows[1]);
        let t2 = transpose8(&rows[2]);
        let wv = [
            t0[0], t0[1], t0[2], t0[3], t0[4], t0[5], t0[6], t0[7], t1[0], t1[1], t1[2], t1[3],
            t1[4], t1[5], t1[6], t1[7], t2[0], t2[1], t2[2], t2[3],
        ];
        let q = AffL {
            x: [wv[0], wv[1], wv[2], wv[3], wv[4]],
            y: [wv[5], wv[6], wv[7], wv[8], wv[9]],
            xy: [wv[10], wv[11], wv[12], wv[13], wv[14]],
            dt: [wv[15], wv[16], wv[17], wv[18], wv[19]],
        };
        let qq = neg_aff(c, k, &q, neg);
        let r = madd(c, k, &p, &qq);
        p = PtL {
            x: sel(m, &p.x, &r.x),
            y: sel(m, &p.y, &r.y),
            t: sel(m, &p.t, &r.t),
            z: sel(m, &p.z, &r.z),
        };
    }
    // word index = ((gbase + b) * 20 + kk) * 8 + lane
    // BW = 160. Shifts avoid VPMULLQ, which requires AVX-512DQ in addition
    // to the AVX-512F/IFMA features checked by runtime dispatch.
    const { assert!(BW == 160) };
    let bucket_v = _mm512_add_epi64(b_v, _mm512_set1_epi64(gbase as i64));
    let base_v = _mm512_add_epi64(
        _mm512_add_epi64(
            _mm512_slli_epi64(bucket_v, 7),
            _mm512_slli_epi64(bucket_v, 5),
        ),
        _mm512_set1_epi64(lane as i64),
    );
    let out = [
        p.x[0], p.x[1], p.x[2], p.x[3], p.x[4], p.y[0], p.y[1], p.y[2], p.y[3], p.y[4], p.t[0],
        p.t[1], p.t[2], p.t[3], p.t[4], p.z[0], p.z[1], p.z[2], p.z[3], p.z[4],
    ];
    for kk in 0..20 {
        _mm512_mask_i64scatter_epi64::<8>(
            bptr as *mut _,
            m_valid,
            _mm512_add_epi64(base_v, _mm512_set1_epi64((kk * 8) as i64)),
            out[kk],
        );
    }
    for l in 0..fill {
        nonempty[gbase + batch[l].0 as usize] |= 1 << lane;
    }
}

/// Bucket accumulation with lane = bucket over digit-sorted runs: for each window the points are
/// counting-sorted by their digit, the non-empty buckets (runs) are ordered by length, and eight runs at a
/// time are accumulated in registers — each step gathers one prepared point per lane from the point-major
/// table and adds it (masked where a lane's run is exhausted); a finished batch's eight bucket sums are
/// scattered once into the lane-major bucket store the reduction reads (lane = window there). No bucket
/// state is gathered or scattered per point; empty buckets are never written and the reduction reads them
/// as the identity through a mask.
///
/// # Safety
/// `available()` must have returned true on this host.
#[target_feature(enable = "avx512f,avx512ifma")]
pub(crate) unsafe fn msm_runs(
    bases: &[EdwardsAffine],
    scalars: &[Fr],
    cbits: usize,
) -> EdwardsProjective {
    let c = context();
    let k = consts();
    let n = bases.len().min(scalars.len());
    if n == 0 {
        return EdwardsProjective::zero();
    }
    let num_bits = Fr::MODULUS_BIT_SIZE as usize;
    let nwin = num_bits.div_ceil(cbits);
    let groups = nwin.div_ceil(8);
    let nb = 1usize << cbits;
    // signed digits, window-minor per point (i16: |digit| <= 2^cbits, cbits <= 12)
    let mut digits = vec![0i16; n * nwin];
    {
        let mut tmp = vec![0i64; nwin];
        for (i, s) in scalars[..n].iter().enumerate() {
            let b: BigInt<4> = s.into_bigint();
            make_digits(&b, cbits, num_bits, &mut tmp);
            for w in 0..nwin {
                digits[i * nwin + w] = tmp[w] as i16;
            }
        }
    }
    // prepared points, point-major
    let mut pts = vec![0u64; n * PW];
    prep_points(c, k, &bases[..n], &mut pts);
    // bucket store, lane-major per group: written only where a bucket is non-empty
    let words = groups * nb * BW;
    let bptr = BUCKET_SCRATCH.with(|b| {
        let mut b = b.borrow_mut();
        if b.len() < words {
            b.resize(words, 0);
        }
        b.as_mut_ptr()
    });
    let mut nonempty = vec![0u8; groups * nb];
    // per-window scratch
    let mut cnt = vec![0u32; nb];
    let mut cursor = vec![0u32; nb];
    let mut order = vec![0u64; n];
    // runs (bucket, start, len) bucketed by length for a longest-first schedule; lengths >= LMAX share a bin
    const LMAX: usize = 64;
    let mut by_len: Vec<Vec<(u32, u32, u32)>> = (0..LMAX).map(|_| Vec::new()).collect();
    let zero = _mm512_setzero_si512();
    for w in 0..nwin {
        let g = w / 8;
        let lane = w % 8;
        cnt.fill(0);
        for i in 0..n {
            let d = digits[i * nwin + w];
            if d != 0 {
                cnt[d.unsigned_abs() as usize] += 1;
            }
        }
        let mut acc = 0u32;
        for b in 1..nb {
            cursor[b] = acc;
            acc += cnt[b];
        }
        for i in 0..n {
            let d = digits[i * nwin + w];
            if d != 0 {
                let b = d.unsigned_abs() as usize;
                order[cursor[b] as usize] = (i as u64) | (((d < 0) as u64) << 32);
                cursor[b] += 1;
            }
        }
        for v in by_len.iter_mut() {
            v.clear();
        }
        let mut start = 0u32;
        for b in 1..nb {
            let len = cnt[b];
            if len > 0 {
                by_len[(len as usize).min(LMAX - 1)].push((b as u32, start, len));
                start += len;
            }
        }
        // batches of eight runs, longest bins first
        let mut batch: [(u32, u32, u32); 8] = [(0, 0, 0); 8];
        let mut fill = 0usize;
        for bin in (0..LMAX).rev() {
            for &r in &by_len[bin] {
                batch[fill] = r;
                fill += 1;
                if fill == 8 {
                    run_batch(
                        c,
                        k,
                        &pts,
                        &order,
                        &batch,
                        8,
                        bptr,
                        g * nb,
                        lane,
                        &mut nonempty,
                    );
                    fill = 0;
                }
            }
        }
        if fill > 0 {
            run_batch(
                c,
                k,
                &pts,
                &order,
                &batch,
                fill,
                bptr,
                g * nb,
                lane,
                &mut nonempty,
            );
        }
    }
    // reduction per group: running sums over the buckets high to low, lanes = windows; empty buckets read
    // as the identity through the non-empty mask
    let id_words = [
        zero, zero, zero, zero, zero, c.one[0], c.one[1], c.one[2], c.one[3], c.one[4], zero, zero,
        zero, zero, zero, c.one[0], c.one[1], c.one[2], c.one[3], c.one[4],
    ];
    let mut window_sums = vec![EdwardsProjective::zero(); groups * 8];
    for g in 0..groups {
        let mut running = k.id;
        let mut res = k.id;
        for b in (1..nb).rev() {
            let ne: __mmask8 = nonempty[g * nb + b];
            let base = bptr.add((g * nb + b) * BW);
            let mut wv = [zero; 20];
            for kk in 0..20 {
                wv[kk] = _mm512_mask_loadu_epi64(id_words[kk], ne, base.add(kk * 8) as *const _);
            }
            let p = PtL {
                x: [wv[0], wv[1], wv[2], wv[3], wv[4]],
                y: [wv[5], wv[6], wv[7], wv[8], wv[9]],
                t: [wv[10], wv[11], wv[12], wv[13], wv[14]],
                z: [wv[15], wv[16], wv[17], wv[18], wv[19]],
            };
            running = padd(c, k, &running, &p);
            res = padd(c, k, &res, &running);
        }
        window_sums[g * 8..g * 8 + 8].copy_from_slice(&unlane(c, &res));
    }
    window_sums.truncate(nwin);
    let lowest = window_sums[0];
    let total = window_sums[1..]
        .iter()
        .rev()
        .fold(EdwardsProjective::zero(), |mut total, s| {
            total += s;
            for _ in 0..cbits {
                total.double_in_place();
            }
            total
        });
    lowest + total
}

/// The C2 design, kept for the equality test and the bench: lane = window, the bucket state gathered
/// and scattered per point (superseded by `msm_runs`, which touches no bucket per point).
///
/// # Safety
/// `available()` must have returned true on this host.
#[cfg(test)]
#[target_feature(enable = "avx512f,avx512ifma")]
pub(crate) unsafe fn msm_with_window(
    bases: &[EdwardsAffine],
    scalars: &[Fr],
    cbits: usize,
) -> EdwardsProjective {
    let c = context();
    let k = consts();
    let n = bases.len().min(scalars.len());
    if n == 0 {
        return EdwardsProjective::zero();
    }
    let num_bits = Fr::MODULUS_BIT_SIZE as usize;
    let nwin = num_bits.div_ceil(cbits);
    let groups = nwin.div_ceil(8);
    let nb = 1usize << cbits;
    // signed digits, padded to groups*8 per point
    let stride = groups * 8;
    let mut digits = vec![0i64; n * stride];
    for (i, s) in scalars[..n].iter().enumerate() {
        let b: BigInt<4> = s.into_bigint();
        make_digits(
            &b,
            cbits,
            num_bits,
            &mut digits[i * stride..i * stride + nwin],
        );
    }
    // buckets: groups × nb × 160 words, every lane the identity
    let words = groups * nb * BW;
    let bptr = BUCKET_SCRATCH.with(|b| {
        let mut b = b.borrow_mut();
        if b.len() < words {
            b.resize(words, 0);
        }
        b.as_mut_ptr()
    });
    let buckets = core::slice::from_raw_parts_mut(bptr, words);
    {
        let one = to_words(&c.one);
        for b in 0..groups * nb {
            let base = b * BW;
            for i in 0..5 {
                for w in 0..8 {
                    buckets[base + i * 8 + w] = 0; // x
                    buckets[base + (5 + i) * 8 + w] = one[i][w]; // y
                    buckets[base + (10 + i) * 8 + w] = 0; // t
                    buckets[base + (15 + i) * 8 + w] = one[i][w]; // z
                }
            }
        }
    }
    let lane_ids = _mm512_set_epi64(7, 6, 5, 4, 3, 2, 1, 0);
    let zero = _mm512_setzero_si512();
    let one_v = _mm512_set1_epi64(1);
    // prepared points, eight at a time in lanes (point-major table), broadcast per point below
    let mut pts = vec![0u64; n * PW];
    prep_points(c, k, &bases[..n], &mut pts);
    for i in 0..n {
        let q = bcast_aff(pts[i * PW..i * PW + 20].try_into().unwrap());
        for g in 0..groups {
            let d = _mm512_loadu_si512(digits.as_ptr().add(i * stride + g * 8) as *const _);
            let m: __mmask8 = _mm512_cmpneq_epi64_mask(d, zero);
            if m == 0 {
                continue;
            }
            let neg: __mmask8 = _mm512_cmplt_epi64_mask(d, zero);
            let idx = _mm512_sub_epi64(_mm512_abs_epi64(d), one_v);
            // word index = (g*nb + idx) * 160 + lane
            let v0 = _mm512_add_epi64(
                _mm512_add_epi64(_mm512_slli_epi64(idx, 7), _mm512_slli_epi64(idx, 5)),
                _mm512_add_epi64(lane_ids, _mm512_set1_epi64((g * nb * BW) as i64)),
            );
            let base = buckets.as_ptr();
            let mut words = [zero; 20];
            for kk in 0..20 {
                let vi = _mm512_add_epi64(v0, _mm512_set1_epi64((kk * 8) as i64));
                words[kk] = _mm512_mask_i64gather_epi64::<8>(zero, m, vi, base as *const _);
            }
            let p = PtL {
                x: [words[0], words[1], words[2], words[3], words[4]],
                y: [words[5], words[6], words[7], words[8], words[9]],
                t: [words[10], words[11], words[12], words[13], words[14]],
                z: [words[15], words[16], words[17], words[18], words[19]],
            };
            let qq = neg_aff(c, k, &q, neg);
            let r = madd(c, k, &p, &qq);
            let out = [
                r.x[0], r.x[1], r.x[2], r.x[3], r.x[4], r.y[0], r.y[1], r.y[2], r.y[3], r.y[4],
                r.t[0], r.t[1], r.t[2], r.t[3], r.t[4], r.z[0], r.z[1], r.z[2], r.z[3], r.z[4],
            ];
            let basem = buckets.as_mut_ptr();
            for kk in 0..20 {
                let vi = _mm512_add_epi64(v0, _mm512_set1_epi64((kk * 8) as i64));
                _mm512_mask_i64scatter_epi64::<8>(basem as *mut _, m, vi, out[kk]);
            }
        }
    }
    // reduction per group: running sums over the buckets high to low, lanes = windows
    let mut window_sums = vec![EdwardsProjective::zero(); groups * 8];
    for g in 0..groups {
        let mut running = k.id;
        let mut res = k.id;
        for b in (0..nb).rev() {
            let base = buckets.as_ptr().add((g * nb + b) * BW);
            let mut words = [zero; 20];
            for kk in 0..20 {
                words[kk] = _mm512_loadu_si512(base.add(kk * 8) as *const _);
            }
            let p = PtL {
                x: [words[0], words[1], words[2], words[3], words[4]],
                y: [words[5], words[6], words[7], words[8], words[9]],
                t: [words[10], words[11], words[12], words[13], words[14]],
                z: [words[15], words[16], words[17], words[18], words[19]],
            };
            running = padd(c, k, &running, &p);
            res = padd(c, k, &res, &running);
        }
        window_sums[g * 8..g * 8 + 8].copy_from_slice(&unlane(c, &res));
    }
    window_sums.truncate(nwin);
    // combine as ark: lowest window + fold from the top with cbits doublings per window
    let lowest = window_sums[0];
    let total = window_sums[1..]
        .iter()
        .rev()
        .fold(EdwardsProjective::zero(), |mut total, s| {
            total += s;
            for _ in 0..cbits {
                total.double_in_place();
            }
            total
        });
    lowest + total
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_ec::VariableBaseMSM;
    use ark_ff::UniformRand;
    use rand_chacha::rand_core::SeedableRng;

    /// Lane MSM ns per point at the verifier's chunk sizes, one thread; equality with ark checked per
    /// (n, c). `cargo test --release -p banderwagon bench_lane_msm -- --ignored --nocapture`.
    #[test]
    #[ignore]
    fn bench_lane_msm() {
        if !available() {
            println!("no IFMA on this host");
            return;
        }
        let mut rng = rand_chacha::ChaCha20Rng::seed_from_u64(0xc6);
        for &n in &[2560usize, 40960] {
            let bases: Vec<EdwardsAffine> = (0..n).map(|_| EdwardsAffine::rand(&mut rng)).collect();
            let scalars: Vec<Fr> = (0..n).map(|_| Fr::rand(&mut rng)).collect();
            let want = EdwardsProjective::msm(&bases, &scalars).unwrap();
            let reps = if n > 10000 { 2 } else { 8 };
            for &cb in &[8usize, 9, 10, 11] {
                let got = unsafe { msm_runs(&bases, &scalars, cb) };
                assert_eq!(got, want, "runs n = {n} c = {cb}");
                let t = std::time::Instant::now();
                for _ in 0..reps {
                    let _ = unsafe { msm_runs(&bases, &scalars, cb) };
                }
                let ns = t.elapsed().as_nanos() as f64 / (n * reps) as f64;
                println!("lane msm n = {n}: c = {cb}: runs {ns:.0} ns/pt");
            }
            let t = std::time::Instant::now();
            for _ in 0..reps {
                let _ = unsafe { msm_with_window(&bases, &scalars, ln_without_floats(n) + 2) };
            }
            let ns = t.elapsed().as_nanos() as f64 / (n * reps) as f64;
            println!(
                "lane msm n = {n}: C2 design at ark's window: {ns:.0} ns/pt; the rule now gives c = {}",
                lane_window(n)
            );
        }
    }

    #[test]
    fn lane_msm_matches_ark_msm() {
        if !available() {
            return;
        }
        let mut rng = rand_chacha::ChaCha20Rng::seed_from_u64(0xc2);
        for &n in &[1usize, 2, 7, 31, 32, 33, 100, 1000, 2560] {
            let mut bases: Vec<EdwardsAffine> =
                (0..n).map(|_| EdwardsAffine::rand(&mut rng)).collect();
            let mut scalars: Vec<Fr> = (0..n).map(|_| Fr::rand(&mut rng)).collect();
            if n > 3 {
                bases[1] = EdwardsAffine::zero();
                scalars[2] = Fr::zero();
                scalars[3] = -Fr::from(1u64);
            }
            let want = EdwardsProjective::msm(&bases, &scalars).unwrap();
            let got = unsafe { msm(&bases, &scalars) };
            assert_eq!(got, want, "n = {n}");
            for cb in [3usize, 5, 8, 12] {
                let got = unsafe { msm_runs(&bases, &scalars, cb) };
                assert_eq!(got, want, "runs n = {n} c = {cb}");
                let got = unsafe { msm_with_window(&bases, &scalars, cb) };
                assert_eq!(got, want, "window n = {n} c = {cb}");
            }
        }
        // every point in one bucket (equal scalars) and long runs with the sign flipped
        let n = 300;
        let bases: Vec<EdwardsAffine> = (0..n).map(|_| EdwardsAffine::rand(&mut rng)).collect();
        let s = Fr::rand(&mut rng);
        let scalars: Vec<Fr> = (0..n).map(|i| if i % 3 == 0 { -s } else { s }).collect();
        let want = EdwardsProjective::msm(&bases, &scalars).unwrap();
        let got = unsafe { msm_runs(&bases, &scalars, 10) };
        assert_eq!(got, want, "equal scalars");
    }
}
