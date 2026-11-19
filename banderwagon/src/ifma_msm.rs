//! The variable-base multi-scalar multiplication of [`crate::multi_scalar_mul`] with the Pippenger bucket
//! accumulation and bucket reduction run eight-wide on AVX-512 IFMA, in the lane field arithmetic of
//! [`crate::ifma`].
//!
//! Accumulation, lane = bucket over digit-sorted runs (`group_sums`): the points are prepared once, eight at
//! a time, into a point-major table (x, y, x + y, d·x·y in lane limbs); for each window the points are
//! counting-sorted by their signed digit, the non-empty buckets (runs) are ordered longest first, and eight
//! runs at a time are summed in registers — each step loads one point per lane by three row loads and an
//! in-register 8 × 8 transpose (no gather touches the table) and adds it, masked where a lane's run is
//! exhausted; a finished batch's eight bucket sums are scattered once into a lane-major bucket store
//! (lane = window there), kept per thread across calls. Nothing is gathered or scattered per point.
//! Reduction, lane = window: the running sums over the buckets, high to low, are eight independent chains
//! per group of windows; buckets no point reached are read as the identity through a mask. A group of
//! eight windows is accumulated and reduced as one unit, and the groups of an MSM can run on different
//! threads (`spread`): they share the digits and the prepared points and nothing else. Signed digits
//! and the window combination are ark-ec's (`msm_bigint_wnaf`); the window size is the lanes' own
//! (`lane_window`). The result is the same group element the scalar path computes, which the tests check
//! against `EdwardsProjective::msm` on random inputs including zero scalars, the identity, equal scalars
//! (every point in one bucket) and every window size from 3 to 12.
//!
//! Group additions are the unified twisted-Edwards formulas in extended coordinates (Hisil–Wong–Carter–
//! Dawson 2008, `a = -5`): mixed addition 9 lane products, full addition 11.
#![allow(clippy::needless_range_loop)]
use crate::ifma::*;
use crate::msm::{bucket_len, combine_windows, make_digits};
use crate::Fq;
use ark_ec::twisted_edwards::TECurveConfig;
use ark_ed_on_bls12_381_bandersnatch::{BandersnatchConfig, EdwardsAffine, EdwardsProjective, Fr};
use ark_ff::Field;
use ark_ff::{BigInt, PrimeField, Zero};
use core::arch::x86_64::*;
use std::cell::Cell;
use std::sync::OnceLock;
#[cfg(feature = "parallel")]
use std::{
    any::Any,
    panic::{catch_unwind, resume_unwind, AssertUnwindSafe},
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc, Condvar, Mutex, PoisonError,
    },
};

thread_local! {
    /// The bucket store of one group of windows, kept per thread across calls. Its size follows the
    /// window, not the input (0.17 MB at window 8, 0.33 MB at window 9), and it is written before it
    /// is read, so a group neither allocates nor clears it. A group takes it out of this slot and
    /// puts it back when it is done. The tables whose size follows the input are allocated: the
    /// prepared points and the digits once per call, the sort order once per group. Keeping them
    /// per thread as well, timed when all of them were allocated once per call, changed the time
    /// of a task of 4,096 to 16,384 points by under 1%, on glibc's allocator and on jemalloc: both
    /// hand the freed blocks back to the next call.
    static BUCKET_SCRATCH: Cell<Vec<u64>> = const { Cell::new(Vec::new()) };
}

/// Projective extended point, eight lanes.
#[derive(Clone, Copy)]
struct PtL {
    x: L5,
    y: L5,
    t: L5,
    z: L5,
}

/// Affine point prepared for mixed addition, eight lanes: x, y, x + y, d·x·y.
#[derive(Clone, Copy)]
struct AffL {
    x: L5,
    y: L5,
    xy: L5,
    dt: L5,
}

struct Consts {
    five: L5,
    d: L5,
    zero: L5,
    id: PtL,
    /// 2^264 mod p on every lane: `mont_mul(x·2^256, k264) = x·2^260`, ark's Montgomery representation
    /// taken straight into the lane form without a scalar reduction.
    k264: L5,
}

/// The lane MSM's constants, built on first use.
///
/// # Panics
/// On a host without AVX-512 IFMA, as [`context`] does.
fn consts() -> &'static Consts {
    static K: OnceLock<Consts> = OnceLock::new();
    K.get_or_init(|| {
        let c = context();
        // SAFETY: `context()` returned, so the host has the extension.
        unsafe { build_consts(c) }
    })
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
unsafe fn padd(c: &Ctx, k: &Consts, p: &PtL, q: &PtL) -> PtL {
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
unsafe fn unlane(c: &Ctx, p: &PtL) -> [EdwardsProjective; 8] {
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

/// Words per bucket in lane-major layout: 20 words × 8 lanes.
const BW: usize = 160;
/// Words per prepared point in the point-major table: 20 used (x, y, x + y, d·x·y) padded to three
/// eight-word rows, so eight points load as 24 rows and transpose in registers.
const PW: usize = 24;

/// `sum_i scalars[i] * bases[i]`, the same element as `EdwardsProjective::msm(bases, scalars)`.
/// With `spread` the pool's idle threads are asked to help with the groups of windows; without
/// it, or without the `parallel` feature, the groups run one after another on this thread. The
/// result is the same.
///
/// # Panics
/// If there are not as many scalars as bases.
///
/// # Safety
/// `available()` must have returned true on this host.
#[target_feature(enable = "avx512f,avx512ifma")]
pub(crate) unsafe fn msm(
    bases: &[EdwardsAffine],
    scalars: &[Fr],
    spread: bool,
) -> EdwardsProjective {
    msm_runs(bases, scalars, lane_window(bases.len()), spread)
}

/// The window size for the lane accumulation: 9 from 4,097 points, 8 from 32 points, 3 below. The
/// dispatch hands over tasks of 256 points and more, and of 4,096 or fewer while the pool has a
/// thread for every 4,096 points of the MSM, so its tasks run at window 8. A larger task runs at
/// window 9: any MSM over 4,096 points in a pool of one thread, one over 131,072 in a pool of 32.
///
/// ark's rule (`ln(n) + 2`: 10 at 8,192 points) balances scalar bucket additions against the reduction.
/// In lanes the reduction's two full additions per bucket are the dear part (22 lane products per
/// bucket) and the bucket store must stay in cache, so the window is smaller than ark's.
///
/// One thread of an EPYC 9B45, µs per point at windows 8, 9, 10 and 11: 1.00, 1.05, 1.01 and 1.16 for
/// 4,096 points; 1.01, 0.98, 0.89 and 0.92 for 8,192; 1.00, 1.01, 0.88 and 0.74 for 50,000. At windows
/// 6, 7, 8 and 9: 1.86, 1.88, 1.96 and 2.73 for 274 points; 1.40, 1.27, 1.14 and 1.37 for 1,024; 1.35,
/// 1.16, 1.01 and 1.13 for 2,047.
fn lane_window(n: usize) -> usize {
    if n < 32 {
        3
    } else {
        let log2 = usize::BITS - (n - 1).leading_zeros();
        // Capped at 9 (a 0.33 MB bucket store, against 0.66 MB at window 10 and 2.6 MB at 11):
        // the store is thread-local, and every thread that has run a group keeps it.
        (log2 as usize).saturating_sub(4).clamp(8, 9)
    }
}

/// 8 × 8 transpose of 64-bit words: `r[i]` holds point `i`'s eight words in; word `j` of every point out.
#[inline]
#[target_feature(enable = "avx512f")]
unsafe fn transpose8(r: &[__m512i; 8]) -> [__m512i; 8] {
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
/// run, then scattered once into the group's lane-major bucket store at lane `lane`.
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
    // word index = (b * 20 + kk) * 8 + lane
    // BW = 160. Shifts avoid VPMULLQ, which requires AVX-512DQ in addition
    // to the AVX-512F/IFMA features checked by runtime dispatch.
    const { assert!(BW == 160) };
    let base_v = _mm512_add_epi64(
        _mm512_add_epi64(_mm512_slli_epi64(b_v, 7), _mm512_slli_epi64(b_v, 5)),
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
        nonempty[batch[l].0 as usize] |= 1 << lane;
    }
}

/// The MSM at window size `cbits`: the signed digits and the prepared points are made once, each
/// group of eight windows is summed by [`group_sums`], and the window sums are combined. With
/// `spread` (and the `parallel` feature) the pool's idle threads are asked to take groups while
/// this thread sums them, see `spread`. No group does work another has done: what spreading
/// costs is the queueing, the tables read from several cores, and a bucket store on each thread
/// that takes a group.
///
/// # Panics
/// If there are not as many scalars as bases, and on a window whose digits do not fit the `i16`
/// they are kept in (`cbits` of 16 or more).
///
/// # Safety
/// `available()` must have returned true on this host.
#[target_feature(enable = "avx512f,avx512ifma")]
unsafe fn msm_runs(
    bases: &[EdwardsAffine],
    scalars: &[Fr],
    cbits: usize,
    spread: bool,
) -> EdwardsProjective {
    let c = context();
    let k = consts();
    assert_eq!(
        bases.len(),
        scalars.len(),
        "number of bases should equal number of scalars"
    );
    let n = bases.len();
    if n == 0 {
        return EdwardsProjective::zero();
    }
    let num_bits = Fr::MODULUS_BIT_SIZE as usize;
    let nwin = num_bits.div_ceil(cbits);
    let groups = nwin.div_ceil(8);
    // The largest digit magnitude: half the radix in every window but the last, which keeps its
    // carry instead of being recentered and reaches `2^last_bits` (the whole radix where the
    // window divides the scalar's bits, c = 11). A bucket is indexed by the magnitude and bucket 0
    // is unused, so a window has one bucket more than that: 257 at c = 9, not 512.
    let max_digit =
        bucket_len(cbits, num_bits, nwin, 0).max(bucket_len(cbits, num_bits, nwin, nwin - 1));
    assert!(
        max_digit <= i16::MAX as usize,
        "window {cbits}: a digit of up to {max_digit} does not fit the i16 it is kept in"
    );
    let nb = max_digit + 1;
    // signed digits, window-minor per point
    let mut digits = vec![0i16; n * nwin];
    {
        let mut tmp = vec![0i64; nwin];
        for (i, s) in scalars[..n].iter().enumerate() {
            let b: BigInt<4> = s.into_bigint();
            make_digits(&b.0, cbits, &mut tmp);
            for w in 0..nwin {
                digits[i * nwin + w] = tmp[w] as i16;
            }
        }
    }
    // prepared points, point-major
    let mut pts = vec![0u64; n * PW];
    prep_points(c, k, &bases[..n], &mut pts);
    let tables = Tables {
        digits,
        pts,
        n,
        nwin,
        nb,
    };
    let combine = |sums: Vec<[EdwardsProjective; 8]>| {
        let window_sums: Vec<EdwardsProjective> = sums.into_iter().flatten().collect();
        combine_windows(&window_sums[..nwin], cbits)
    };
    // The groups of eight windows are independent from here on: each reads the tables, and
    // accumulates and reduces in the bucket store of the thread it runs on.
    #[cfg(feature = "parallel")]
    if spread && groups > 1 {
        // SAFETY: the caller has checked the host, which is the same for every thread.
        return combine(self::spread(groups, move |g| unsafe {
            group_sums(&tables, g)
        }));
    }
    #[cfg(not(feature = "parallel"))]
    let _ = spread;
    // SAFETY: the caller's contract is this function's.
    combine(
        (0..groups)
            .map(|g| unsafe { group_sums(&tables, g) })
            .collect(),
    )
}

/// What the groups of one MSM read, built once by [`msm_runs`].
struct Tables {
    /// The signed digits, `nwin` per point, each of magnitude under `nb`.
    digits: Vec<i16>,
    /// The prepared points, [`PW`] words per point.
    pts: Vec<u64>,
    /// The number of points.
    n: usize,
    /// The number of windows.
    nwin: usize,
    /// The buckets of a window, bucket 0 included.
    nb: usize,
}

/// The groups of one job, taken one at a time by whichever thread asks next.
#[cfg(feature = "parallel")]
struct Spread<T, F> {
    /// What a thread does with a group it has taken.
    sum: F,
    groups: usize,
    /// The next group nobody has taken.
    next: AtomicUsize,
    state: Mutex<SpreadState<T>>,
    /// Signalled when the last group is done, and when a helper has panicked.
    done: Condvar,
}

#[cfg(feature = "parallel")]
struct SpreadState<T> {
    /// The groups' results, each written when its group is done.
    sums: Vec<Option<T>>,
    /// The groups done.
    finished: usize,
    /// What a helper panicked with while it had a group, if one did.
    panic: Option<Box<dyn Any + Send>>,
}

#[cfg(feature = "parallel")]
impl<T, F: Fn(usize) -> T> Spread<T, F> {
    /// Takes groups until none is left to take.
    fn work(&self) {
        loop {
            let g = self.next.fetch_add(1, Ordering::Relaxed);
            if g >= self.groups {
                return;
            }
            let sum = (self.sum)(g);
            let mut state = self.state.lock().unwrap();
            state.sums[g] = Some(sum);
            state.finished += 1;
            if state.finished == self.groups {
                self.done.notify_all();
            }
        }
    }
}

/// `sum(g)` for every group `g`, in order, with the pool's idle threads helping.
///
/// This thread starts on the groups at once and takes one after another. A helper is queued on
/// the pool for each group but the first, up to the threads the pool has besides this one, and a
/// helper that gets to run takes groups the same way. So this thread waits only for groups a
/// helper has already begun, and in a pool with no thread to spare it does every group itself,
/// as it would without spreading. A helper that runs after the call has returned finds it gone.
///
/// `sum` must not wait for the pool itself: this thread may be one of the pool's, and it waits
/// for the helpers' groups without running other jobs.
///
/// # Panics
/// If `sum` panics, on this thread or on a helper's, and no further group is started then. The
/// pool aborts the process on a panic in a queued job, so a helper catches its own and this
/// thread panics with it.
#[cfg(feature = "parallel")]
fn spread<T, F>(groups: usize, sum: F) -> Vec<T>
where
    T: Send + 'static,
    F: Fn(usize) -> T + Send + Sync + 'static,
{
    let shared = Arc::new(Spread {
        sum,
        groups,
        next: AtomicUsize::new(0),
        state: Mutex::new(SpreadState {
            sums: (0..groups).map(|_| None).collect(),
            finished: 0,
            panic: None,
        }),
        done: Condvar::new(),
    });
    let others =
        rayon::current_num_threads() - usize::from(rayon::current_thread_index().is_some());
    for _ in 0..groups.saturating_sub(1).min(others) {
        // A helper holds the job only while it works on it: one still queued when this call
        // returns keeps nothing alive.
        let job = Arc::downgrade(&shared);
        rayon::spawn(move || {
            let Some(shared) = job.upgrade() else { return };
            // After a panic only `panic` is read: the results are discarded.
            if let Err(panic) = catch_unwind(AssertUnwindSafe(|| shared.work())) {
                shared.next.fetch_max(groups, Ordering::Relaxed);
                let mut state = shared.state.lock().unwrap_or_else(PoisonError::into_inner);
                state.panic.get_or_insert(panic);
                shared.done.notify_all();
            }
        });
    }
    // However this thread leaves, by a panic in its own group too, no group is taken after it.
    struct Stop<'a>(&'a AtomicUsize, usize);
    impl Drop for Stop<'_> {
        fn drop(&mut self) {
            self.0.fetch_max(self.1, Ordering::Relaxed);
        }
    }
    let _stop = Stop(&shared.next, groups);
    shared.work();
    let mut state = shared.state.lock().unwrap();
    while state.finished < groups && state.panic.is_none() {
        state = shared.done.wait(state).unwrap();
    }
    if let Some(panic) = state.panic.take() {
        drop(state);
        resume_unwind(panic);
    }
    state.sums.drain(..).map(Option::unwrap).collect()
}

/// The sums of one group of up to eight windows, window `8 * g` and the seven after it.
///
/// Accumulation, lane = bucket over digit-sorted runs: for each window the points are counting-sorted
/// by their digit, the non-empty buckets (runs) are ordered by length, and eight runs at a time are
/// accumulated in registers — each step loads one prepared point per lane from the point-major table
/// (row loads and a transpose in registers, not a gather) and adds it, masked where a lane's run is
/// exhausted; a finished batch's eight bucket sums are scattered once into the lane-major bucket
/// store the reduction reads (lane = window there). No bucket state is gathered or scattered per
/// point; empty buckets are never written and the reduction reads them as the identity through a mask.
///
/// The group runs from start to end on one thread, in the bucket store it takes from that thread,
/// and nothing reads the store after it returns.
///
/// # Safety
/// `available()` must have returned true on this host, and `tables` must be as [`msm_runs`]
/// builds them: the prepared points are read unchecked.
#[target_feature(enable = "avx512f,avx512ifma")]
unsafe fn group_sums(tables: &Tables, g: usize) -> [EdwardsProjective; 8] {
    let c = context();
    let k = consts();
    let Tables {
        digits,
        pts,
        n,
        nwin,
        nb,
    } = tables;
    let (n, nwin, nb) = (*n, *nwin, *nb);
    // The bucket store, lane-major, written only where a bucket is non-empty. It is taken from
    // the thread and handed back at the end, so the thread's slot is empty while this group uses it.
    let mut store = BUCKET_SCRATCH.take();
    let words = nb * BW;
    if store.len() < words {
        store.resize(words, 0);
    }
    let bptr = store.as_mut_ptr();
    let mut nonempty = vec![0u8; nb];
    // the highest non-empty bucket of the group's windows: the reduction starts there
    let mut top = 0usize;
    // per-window scratch
    let mut cnt = vec![0u32; nb];
    let mut cursor = vec![0u32; nb];
    let mut order = vec![0u64; n];
    // runs (bucket, start, len) bucketed by length for a longest-first schedule; lengths >= LMAX share a bin
    const LMAX: usize = 64;
    let mut by_len: Vec<Vec<(u32, u32, u32)>> = (0..LMAX).map(|_| Vec::new()).collect();
    let zero = _mm512_setzero_si512();
    for w in 8 * g..nwin.min(8 * g + 8) {
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
                top = top.max(b);
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
                    run_batch(c, k, pts, &order, &batch, 8, bptr, lane, &mut nonempty);
                    fill = 0;
                }
            }
        }
        if fill > 0 {
            run_batch(c, k, pts, &order, &batch, fill, bptr, lane, &mut nonempty);
        }
    }
    // reduction: running sums over the buckets high to low, lanes = windows; empty buckets read as
    // the identity through the non-empty mask. The walk starts at the highest non-empty bucket,
    // since above it both sums are still the identity.
    let id_words = [
        zero, zero, zero, zero, zero, c.one[0], c.one[1], c.one[2], c.one[3], c.one[4], zero, zero,
        zero, zero, zero, c.one[0], c.one[1], c.one[2], c.one[3], c.one[4],
    ];
    let mut running = k.id;
    let mut res = k.id;
    for b in (1..=top).rev() {
        let ne: __mmask8 = nonempty[b];
        let base = bptr.add(b * BW);
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
    let sums = unlane(c, &res);
    BUCKET_SCRATCH.set(store);
    sums
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::element::tests::lanes_under_test;
    use ark_ec::VariableBaseMSM;
    use ark_ff::UniformRand;
    use rand_chacha::rand_core::SeedableRng;

    /// Lane MSM ns per point on one thread, per window; equality with ark checked per (n, c).
    /// `cargo test --release -p banderwagon bench_lane_msm -- --ignored --nocapture`.
    #[test]
    #[ignore]
    #[cfg_attr(coverage_nightly, coverage(off))]
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
                let got = unsafe { msm_runs(&bases, &scalars, cb, false) };
                assert_eq!(got, want, "runs n = {n} c = {cb}");
                let t = std::time::Instant::now();
                for _ in 0..reps {
                    let _ = unsafe { msm_runs(&bases, &scalars, cb, false) };
                }
                let ns = t.elapsed().as_nanos() as f64 / (n * reps) as f64;
                println!("lane msm n = {n}: c = {cb}: runs {ns:.0} ns/pt");
            }
            println!("lane msm n = {n}: the rule gives c = {}", lane_window(n));
        }
    }

    /// The lane MSM returns the curve point `EdwardsProjective::msm` returns, with its groups on
    /// one thread and spread over the pool: at the window [`lane_window`] picks for each size, up
    /// to the sizes the dispatch hands over, and at every window from 3 to 12 on the smaller ones.
    /// Windows 8 and 9 are the ones the dispatch's tasks get, and window 11 the one whose last
    /// digit runs over the whole radix instead of half of it.
    #[test]
    fn lane_msm_matches_ark_msm() {
        if !lanes_under_test() {
            return;
        }
        let mut rng = rand_chacha::ChaCha20Rng::seed_from_u64(0xc2);
        for &n in &[1usize, 2, 7, 31, 32, 33, 100, 1000, 2560, 4096, 4097, 8192] {
            let mut bases: Vec<EdwardsAffine> =
                (0..n).map(|_| EdwardsAffine::rand(&mut rng)).collect();
            let mut scalars: Vec<Fr> = (0..n).map(|_| Fr::rand(&mut rng)).collect();
            if n > 3 {
                bases[1] = EdwardsAffine::zero();
                scalars[2] = Fr::zero();
                // r − 1: the largest last digit
                scalars[3] = -Fr::from(1u64);
            }
            let want = EdwardsProjective::msm(&bases, &scalars).unwrap();
            for spread in [false, true] {
                let got = unsafe { msm(&bases, &scalars, spread) };
                assert_eq!(got, want, "n = {n} spread = {spread}");
            }
            if n > 2560 {
                continue;
            }
            for cb in 3usize..=12 {
                for spread in [false, true] {
                    let got = unsafe { msm_runs(&bases, &scalars, cb, spread) };
                    assert_eq!(got, want, "runs n = {n} c = {cb} spread = {spread}");
                }
            }
        }
        // every point in one bucket (equal scalars) and long runs with the sign flipped
        let n = 300;
        let bases: Vec<EdwardsAffine> = (0..n).map(|_| EdwardsAffine::rand(&mut rng)).collect();
        let s = Fr::rand(&mut rng);
        let scalars: Vec<Fr> = (0..n).map(|i| if i % 3 == 0 { -s } else { s }).collect();
        let want = EdwardsProjective::msm(&bases, &scalars).unwrap();
        let got = unsafe { msm_runs(&bases, &scalars, 10, true) };
        assert_eq!(got, want, "equal scalars");
    }

    /// Many MSMs at once in a pool of two to four threads, every one spreading its groups, each
    /// checked against arkworks. The few threads take groups of different MSMs in turn, at window
    /// 8 and at window 9 (the sizes over 4,096 points), where a thread's bucket store grows and
    /// the last group has five windows.
    #[cfg(feature = "parallel")]
    #[test]
    fn concurrent_lane_msms_match_ark_msm() {
        use rayon::prelude::*;
        if !lanes_under_test() {
            return;
        }
        let mut rng = rand_chacha::ChaCha20Rng::seed_from_u64(0xc3);
        let bases: Vec<EdwardsAffine> = (0..8192).map(|_| EdwardsAffine::rand(&mut rng)).collect();
        let scalars: Vec<Fr> = (0..8192).map(|_| Fr::rand(&mut rng)).collect();
        // (offset, length): 48 inputs of 300 to 2,099 points, and 8 of 4,200 to 5,600
        let jobs: Vec<(usize, usize)> = (0..48)
            .map(|j| (j * 37 % 1900, 300 + j * 53 % 1800))
            .chain((0..8).map(|j| (j * 311, 4200 + j * 200)))
            .collect();
        let want: Vec<EdwardsProjective> = jobs
            .iter()
            .map(|&(o, l)| EdwardsProjective::msm(&bases[o..o + l], &scalars[o..o + l]).unwrap())
            .collect();
        for threads in [2, 3, 4] {
            let pool = rayon::ThreadPoolBuilder::new()
                .num_threads(threads)
                .build()
                .unwrap();
            for round in 0..4 {
                let got: Vec<EdwardsProjective> = pool.install(|| {
                    jobs.par_iter()
                        // SAFETY: `lanes_under_test()` returned true, so the host has the extension.
                        .map(|&(o, l)| unsafe { msm(&bases[o..o + l], &scalars[o..o + l], true) })
                        .collect()
                });
                assert_eq!(got, want, "threads = {threads}, round {round}");
            }
        }
    }

    /// `spread` returns every group's result in group order: called from outside any pool, where
    /// the helpers are queued on the global one, and from a thread of a pool of one to four
    /// threads, with more groups than threads and fewer.
    #[cfg(feature = "parallel")]
    #[test]
    fn spread_returns_every_group_in_order() {
        for groups in [1usize, 2, 3, 4, 11] {
            let want: Vec<usize> = (0..groups).map(|g| g * g).collect();
            assert_eq!(spread(groups, |g| g * g), want);
            for threads in 1..=4 {
                let pool = rayon::ThreadPoolBuilder::new()
                    .num_threads(threads)
                    .build()
                    .unwrap();
                assert_eq!(pool.install(|| spread(groups, |g| g * g)), want);
            }
        }
    }

    /// A thread of the pool that has handed groups out waits for the ones a helper has begun,
    /// and gets them: its own first group does not end until another thread has taken one.
    #[cfg(feature = "parallel")]
    #[test]
    fn spread_waits_for_a_group_a_helper_has_begun() {
        use std::sync::atomic::AtomicBool;
        use std::time::{Duration, Instant};
        for threads in 2..=4 {
            let pool = rayon::ThreadPoolBuilder::new()
                .num_threads(threads)
                .build()
                .unwrap();
            let helped = Arc::new(AtomicBool::new(false));
            let got = pool.install(|| {
                let caller = rayon::current_thread_index();
                let helped = Arc::clone(&helped);
                spread(4, move |g| {
                    if rayon::current_thread_index() != caller {
                        helped.store(true, Ordering::Relaxed);
                        // long enough for the caller to run out of groups and wait
                        std::thread::sleep(Duration::from_millis(20));
                    } else {
                        let start = Instant::now();
                        while !helped.load(Ordering::Relaxed)
                            && start.elapsed() < Duration::from_secs(60)
                        {
                            std::thread::yield_now();
                        }
                    }
                    g
                })
            });
            assert_eq!(got, [0, 1, 2, 3], "threads = {threads}");
            assert!(helped.load(Ordering::Relaxed), "threads = {threads}");
        }
    }

    /// A group that panics on a helper's thread panics the caller with the same payload: the
    /// helper does not take the process down, and the caller does not wait for a group that
    /// will never be done. The pool serves the next call. The pool is the test's own, so that no
    /// other test's work keeps the helper from its group.
    #[cfg(feature = "parallel")]
    #[test]
    fn a_panic_on_a_helper_reaches_the_caller() {
        use std::sync::atomic::AtomicBool;
        use std::time::{Duration, Instant};
        let pool = rayon::ThreadPoolBuilder::new()
            .num_threads(2)
            .build()
            .unwrap();
        // The caller's first group does not end until the helper has taken one, and the
        // helper's panics.
        let taken = Arc::new(AtomicBool::new(false));
        let outcome = catch_unwind(AssertUnwindSafe(|| {
            pool.install(|| {
                let caller = rayon::current_thread_index();
                let taken = Arc::clone(&taken);
                spread(4, move |g| {
                    if rayon::current_thread_index() != caller {
                        taken.store(true, Ordering::Relaxed);
                        panic!("group {g} on a helper");
                    }
                    let start = Instant::now();
                    while !taken.load(Ordering::Relaxed)
                        && start.elapsed() < Duration::from_secs(60)
                    {
                        std::thread::yield_now();
                    }
                    g
                })
            })
        }));
        let panic = outcome.expect_err("the helper's panic reaches the caller");
        let message = panic
            .downcast_ref::<String>()
            .expect("the helper's own payload");
        assert!(message.ends_with("on a helper"), "{message}");
        assert_eq!(pool.install(|| spread(4, |g| g + 1)), [1, 2, 3, 4]);
    }

    /// A group that panics on the calling thread stops the helpers: of 64 groups only the
    /// caller's and the one the helper already had are begun.
    #[cfg(feature = "parallel")]
    #[test]
    fn a_panic_on_the_caller_stops_the_helpers() {
        use std::sync::atomic::AtomicBool;
        use std::time::{Duration, Instant};
        let pool = rayon::ThreadPoolBuilder::new()
            .num_threads(2)
            .build()
            .unwrap();
        let taken = Arc::new(AtomicBool::new(false));
        let begun = Arc::new(AtomicUsize::new(0));
        let outcome = catch_unwind(AssertUnwindSafe(|| {
            pool.install(|| {
                let caller = rayon::current_thread_index();
                let (taken, begun) = (Arc::clone(&taken), Arc::clone(&begun));
                spread(64, move |g| {
                    begun.fetch_add(1, Ordering::Relaxed);
                    if rayon::current_thread_index() != caller {
                        taken.store(true, Ordering::Relaxed);
                        // long enough for the caller to have unwound out of `spread`
                        std::thread::sleep(Duration::from_millis(200));
                        return g;
                    }
                    let start = Instant::now();
                    while !taken.load(Ordering::Relaxed)
                        && start.elapsed() < Duration::from_secs(60)
                    {
                        std::thread::yield_now();
                    }
                    panic!("group {g} on the caller");
                })
            })
        }));
        assert!(outcome.is_err());
        // The helper's group ends after the caller has gone, and it takes no other.
        pool.install(|| std::thread::sleep(Duration::from_millis(400)));
        assert_eq!(begun.load(Ordering::Relaxed), 2);
    }

    /// A window whose digits do not fit the `i16` they are kept in is refused, not truncated into
    /// other buckets: 16 is the first one (a digit of `2^15`).
    #[test]
    fn a_window_too_wide_for_its_digits_is_refused() {
        if !lanes_under_test() {
            return;
        }
        let bases = [EdwardsAffine::zero(); 2];
        let scalars = [Fr::from(3u64); 2];
        // SAFETY: `lanes_under_test()` returned true, so the host has the extension.
        let at = |cbits: usize| {
            std::panic::catch_unwind(|| unsafe { msm_runs(&bases, &scalars, cbits, false) })
        };
        assert_eq!(at(15).ok(), Some(EdwardsProjective::zero()));
        assert!(at(16).is_err());
    }
}
