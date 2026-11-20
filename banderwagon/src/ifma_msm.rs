//! The variable-base multi-scalar multiplication of [`crate::multi_scalar_mul`] with the Pippenger bucket
//! accumulation and bucket reduction run eight-wide on AVX-512 IFMA, in the lane field arithmetic of
//! [`crate::ifma`].
//!
//! Accumulation, lane = bucket over digit-sorted runs (`group_sums`): the points are prepared once, eight at
//! a time, into a point-major table (x, y, x + y, d·x·y in lane limbs); for each window the points are
//! counting-sorted by their signed digit, the non-empty buckets (runs) are ordered longest first, and eight
//! runs at a time are summed in registers — each step loads one point per lane by three row loads and an
//! in-register 8 × 8 transpose (no gather touches the table) and adds it, masked where a lane's run is
//! exhausted (a run's first point is taken as it is, with nothing to add it to); a finished batch's
//! eight bucket sums are scattered once into a lane-major bucket store
//! (lane = window there), kept per thread across calls. Nothing is gathered or scattered per point.
//! Reduction, lane = window: the running sums over the buckets, high to low, are eight independent chains
//! per group of windows; buckets no point reached are read as the identity through a mask. A group of
//! eight windows is accumulated and reduced as one unit, and the groups of a task can run on different
//! threads ([`crate::spread`]): they share the digits and the prepared points and nothing else. Signed
//! digits and the window combination are the scalar path's ([`crate::msm`]); the window size is the lanes'
//! own (`lane_window`). The result is the same group element the scalar path computes, which the tests
//! check against `EdwardsProjective::msm` on random inputs including zero scalars, the identity, equal
//! scalars (every point in one bucket) and every window size from 3 to 12.
//!
//! [`lane_msm`] is the way in. It splits an MSM into tasks ([`LANE_MSM_TASK_POINTS`]) and decides whether
//! the tasks share their groups with idle threads ([`LANE_MSMS`]).
//!
//! Group additions are the unified twisted-Edwards formulas in extended coordinates (Hisil–Wong–Carter–
//! Dawson 2008, `a = -5`): mixed addition 9 lane products, full addition 11.
#![allow(clippy::needless_range_loop)]
use crate::element::LaneMsm;
use crate::ifma::*;
use crate::msm::{bucket_len, combine_windows, make_digits};
use crate::spread::spread_groups;
use crate::Fq;
use ark_ec::twisted_edwards::TECurveConfig;
use ark_ed_on_bls12_381_bandersnatch::{BandersnatchConfig, EdwardsAffine, EdwardsProjective, Fr};
use ark_ff::Field;
use ark_ff::{BigInt, PrimeField, Zero};
use core::arch::x86_64::*;
use core::sync::atomic::{AtomicUsize, Ordering};
use salt_macros::prelude::*;
use salt_macros::{chunks, num_threads};
use std::cell::Cell;
use std::sync::OnceLock;

thread_local! {
    /// The bucket store of one group of windows, kept per thread across calls. Its size follows the
    /// window, not the input (0.17 MB at window 8, 0.33 MB at window 9), and it is written before it
    /// is read, so a group neither allocates nor clears it. A group takes it out of this slot and
    /// puts it back when it is done, so the slot is empty while a group uses it. The tables whose
    /// size follows the input are allocated: the
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
    let five = bcast(&bcast_limbs(&-BandersnatchConfig::COEFF_A));
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

/// The points a vector task gets when an MSM is split: one task for every full
/// `LANE_MSM_TASK_POINTS` the MSM has, and no more than one per thread.
///
/// Smaller tasks finish a large MSM sooner in an idle pool and take more thread time doing it:
/// every task repeats the bucket reduction, and past one task per core the tasks share cores. On
/// an EPYC 9B45 (a 32-thread KVM guest, 16 cores), in a pool of 32 threads that was asleep, 65,536
/// points take 3.5 ms as 32 tasks of 2,048 points, with 109 ms of thread time, and 4.6 ms as 8
/// tasks of 8,192, with 105 ms. With 64 such MSMs at once in that pool the batch takes 3.3 ms per
/// MSM in the smaller tasks and 4.0 ms in the larger.
///
/// Verifying 22 witnesses of 59,000 to 65,000 points with tasks of this size instead of 8,192
/// points: one verification in an idle pool takes 74 ms instead of 75 ms, and 16 threads verifying
/// at once do 87 a second instead of 83.
const LANE_MSM_TASK_POINTS: usize = 1024;

/// The points per task when `points` are split over `threads` threads: one task for every full
/// [`LANE_MSM_TASK_POINTS`], at least one, and no more than one per thread, with the points
/// spread evenly over them, so that no task is left a short remainder beside full ones: 2,049
/// points on two threads are 1,025 and 1,024, not 2,048 and 1. An MSM takes as long as its
/// longest task. Below two full tasks' worth an MSM is one task, of up to 2,047 points.
fn lane_msm_task_len(points: usize, threads: usize) -> usize {
    let tasks = (points / LANE_MSM_TASK_POINTS).min(threads).max(1);
    points.div_ceil(tasks).max(1)
}

/// The vector MSMs in flight in this process, in whichever pool.
///
/// A vector task sums its windows in groups of eight, and the groups can run on different threads
/// without repeating any work. An MSM that starts while no other is in flight asks the pool's idle
/// threads to help with its groups; one that starts beside another keeps each task on one thread,
/// since the threads it would borrow are the ones the others are using. The choice is made once,
/// when the MSM starts, and only vector MSMs are counted: a pool busy with other work has no
/// thread to help, and the MSM then takes as long as it would on its own. An MSM split into tasks
/// spreads each of them: the tasks do not end together, and a thread whose task is done can take
/// groups of one that is not.
///
/// On an EPYC 9B45 (a 32-thread KVM guest, 16 cores), verifying the witnesses of 62 mainnet
/// blocks: one at a time in an idle pool, a verification takes 1.9 ms with its MSMs' groups spread
/// and 2.6 ms without. With 16 threads verifying at once, spreading every MSM's groups does 2,970
/// a second, and spreading only the ones that start alone 3,100, against 3,080 for none.
static LANE_MSMS: AtomicUsize = AtomicUsize::new(0);

/// One MSM's entry in a count of the MSMs in flight, taken out when the MSM ends, however it
/// ends.
struct InFlight {
    count: &'static AtomicUsize,
    /// Whether no other MSM was in flight when this one started.
    alone: bool,
}

impl InFlight {
    fn enter(count: &'static AtomicUsize) -> Self {
        Self {
            count,
            alone: count.fetch_add(1, Ordering::Relaxed) == 0,
        }
    }
}

impl Drop for InFlight {
    fn drop(&mut self) {
        self.count.fetch_sub(1, Ordering::Relaxed);
    }
}

/// The vector MSM where this host executes it, `None` where it does not: the MSM in even tasks
/// ([`lane_msm_task_len`]), each summed in lanes, its groups of windows shared with the pool's
/// idle threads if no other vector MSM is in flight ([`LANE_MSMS`]).
pub(crate) fn lane_msm() -> Option<LaneMsm> {
    fn checked(bases: &[EdwardsAffine], scalars: &[Fr]) -> EdwardsProjective {
        let in_flight = InFlight::enter(&LANE_MSMS);
        // SAFETY: `lane_msm` hands this function out only where `available()` returned true.
        unsafe { split_msm(bases, scalars, in_flight.alone) }
    }
    available().then_some(checked as LaneMsm)
}

/// The MSM in even tasks, each summed by [`msm`] with `spread` as given.
///
/// # Panics
/// If there are not as many scalars as bases.
///
/// # Safety
/// `available()` must have returned true on this host.
unsafe fn split_msm(bases: &[EdwardsAffine], scalars: &[Fr], spread: bool) -> EdwardsProjective {
    assert_eq!(
        bases.len(),
        scalars.len(),
        "number of bases should equal number of scalars"
    );
    let len = lane_msm_task_len(bases.len(), num_threads!());
    chunks!(bases, len)
        .zip(chunks!(scalars, len))
        // SAFETY: the caller's contract is this function's.
        .map(|(b, s)| unsafe { msm(b, s, spread) })
        .sum()
}

/// One task: `sum_i scalars[i] * bases[i]`, the same element as
/// `EdwardsProjective::msm(bases, scalars)`. With `spread` the pool's idle threads are asked to
/// help with the groups of windows; without it, or without the `parallel` feature, the groups run
/// one after another on this thread. The result is the same.
///
/// # Panics
/// If there are not as many scalars as bases.
///
/// # Safety
/// `available()` must have returned true on this host.
#[target_feature(enable = "avx512f,avx512ifma")]
unsafe fn msm(bases: &[EdwardsAffine], scalars: &[Fr], spread: bool) -> EdwardsProjective {
    msm_runs(bases, scalars, lane_window(bases.len()), spread)
}

/// The window size for the lane accumulation: 9 from 4,097 points, 8 from 32 points, 3 below. A
/// task has 4,096 points or fewer while the pool has a thread for every 4,096 points of the MSM
/// ([`lane_msm_task_len`]), so the tasks run at window 8, and a larger one at window 9.
///
/// ark's rule (`ln(n) + 2`: 10 at 8,192 points) balances scalar bucket additions against the reduction.
/// In lanes the reduction's two full additions per bucket are the dear part (22 lane products per
/// bucket) and the bucket store must stay in cache, so the window is smaller than ark's.
///
/// One thread of an EPYC 9B45, µs per point at windows 8, 9, 10 and 11: 0.96, 0.99, 0.94 and 1.04 for
/// 4,096 points; 0.98, 0.95, 0.85 and 0.85 for 8,192; 0.99, 0.99, 0.87 and 0.73 for 50,000. At windows
/// 6, 7, 8 and 9: 1.76, 1.71, 1.73 and 2.42 for 274 points; 1.35, 1.22, 1.07 and 1.23 for 1,024; 1.31,
/// 1.13, 0.96 and 1.04 for 2,047.
fn lane_window(n: usize) -> usize {
    match n {
        0..32 => 3,
        32..=4096 => 8,
        // Capped at 9 (a 0.33 MB bucket store, against 0.66 MB at window 10 and 2.6 MB at 11):
        // the store is thread-local, and every thread that has run a group keeps it.
        _ => 9,
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

/// The eight lanes' points at step `s` of their runs, negated where the digit is negative: index
/// and sign from `order` (a lane outside `m` re-reads its first point), three eight-word rows per
/// point loaded and transposed in registers, so no gather touches the table.
#[inline]
#[target_feature(enable = "avx512f,avx512ifma")]
unsafe fn next_points(
    c: &Ctx,
    k: &Consts,
    pts: &[u64],
    order: &[u64],
    starts: &[i64; 8],
    s: usize,
    m: __mmask8,
) -> AffL {
    let mut neg: __mmask8 = 0;
    let mut rows = [[_mm512_setzero_si512(); 8]; 3];
    for l in 0..8 {
        let pos = if (m >> l) & 1 == 1 {
            starts[l] as usize + s
        } else {
            starts[l] as usize
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
        t0[0], t0[1], t0[2], t0[3], t0[4], t0[5], t0[6], t0[7], t1[0], t1[1], t1[2], t1[3], t1[4],
        t1[5], t1[6], t1[7], t2[0], t2[1], t2[2], t2[3],
    ];
    let q = AffL {
        x: [wv[0], wv[1], wv[2], wv[3], wv[4]],
        y: [wv[5], wv[6], wv[7], wv[8], wv[9]],
        xy: [wv[10], wv[11], wv[12], wv[13], wv[14]],
        dt: [wv[15], wv[16], wv[17], wv[18], wv[19]],
    };
    neg_aff(c, k, &q, neg)
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
    // A run's first point starts its sum: (x, y, x·y, 1) is the point in extended coordinates, for
    // one lane product where adding it to the identity takes nine. Every run has a first point, and
    // the lanes past `fill` are not stored.
    let first = next_points(c, k, pts, order, &sl, 0, m_valid);
    let mut p = PtL {
        x: first.x,
        y: first.y,
        t: mont_mul(c, &first.x, &first.y),
        z: c.one,
    };
    for s in 1..maxlen as usize {
        let m: __mmask8 = _mm512_cmpgt_epi64_mask(len_v, _mm512_set1_epi64(s as i64)) & m_valid;
        let q = next_points(c, k, pts, order, &sl, s, m);
        let r = madd(c, k, &p, &q);
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
/// `spread` the pool's idle threads are asked to take groups while this thread sums them
/// ([`spread_groups`]). No group does work another has done: what spreading costs is the queueing,
/// the tables read from several cores, and a bucket store on each thread that takes a group.
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
        for (i, s) in scalars.iter().enumerate() {
            let b: BigInt<4> = s.into_bigint();
            make_digits(&b.0, cbits, &mut tmp);
            for w in 0..nwin {
                digits[i * nwin + w] = tmp[w] as i16;
            }
        }
    }
    // prepared points, point-major
    let mut pts = vec![0u64; n * PW];
    prep_points(c, k, bases, &mut pts);
    let tables = Tables {
        digits,
        pts,
        nwin,
        nb,
    };
    // The groups of eight windows are independent from here on: each reads the tables, and
    // accumulates and reduces in the bucket store of the thread it runs on.
    // SAFETY: the caller has checked the host, which is the same for every thread.
    let sum = move |g| unsafe { group_sums(&tables, g) };
    let sums: Vec<[EdwardsProjective; 8]> = if spread {
        spread_groups(groups, sum)
    } else {
        (0..groups).map(sum).collect()
    };
    combine_windows(&sums.as_flattened()[..nwin], cbits)
}

/// What the groups of one task read, built once by [`msm_runs`].
struct Tables {
    /// The signed digits, `nwin` per point, each of magnitude under `nb`.
    digits: Vec<i16>,
    /// The prepared points, [`PW`] words per point.
    pts: Vec<u64>,
    /// The number of windows.
    nwin: usize,
    /// The buckets of a window, bucket 0 included.
    nb: usize,
}

/// The sums of one group of up to eight windows, window `8 * g` and the seven after it: the
/// accumulation and the reduction of the module's description. The group runs from start to end
/// on one thread, in the bucket store it takes from that thread ([`BUCKET_SCRATCH`]).
///
/// # Safety
/// `available()` must have returned true on this host, and `tables` must be as [`msm_runs`]
/// builds them: the prepared points are read unchecked.
#[target_feature(enable = "avx512f,avx512ifma")]
unsafe fn group_sums(tables: &Tables, g: usize) -> [EdwardsProjective; 8] {
    let c = context();
    let k = consts();
    let &Tables {
        ref digits,
        ref pts,
        nwin,
        nb,
    } = tables;
    let n = pts.len() / PW;
    // lane-major, written only where a bucket is non-empty
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
        for v in by_len.iter_mut() {
            v.clear();
        }
        let mut start = 0u32;
        for b in 1..nb {
            let len = cnt[b];
            cursor[b] = start;
            if len > 0 {
                by_len[(len as usize).min(LMAX - 1)].push((b as u32, start, len));
                start += len;
                top = top.max(b);
            }
        }
        for i in 0..n {
            let d = digits[i * nwin + w];
            if d != 0 {
                let b = d.unsigned_abs() as usize;
                order[cursor[b] as usize] = (i as u64) | (((d < 0) as u64) << 32);
                cursor[b] += 1;
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
    let id = [k.id.x, k.id.y, k.id.t, k.id.z];
    let id_words = id.as_flattened();
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

    /// `n` random points and scalars with the edge cases among them: the identity as a point, and
    /// the scalars zero and r − 1 (the largest last digit).
    fn input(seed: u64, n: usize) -> (Vec<EdwardsAffine>, Vec<Fr>) {
        let mut rng = rand_chacha::ChaCha20Rng::seed_from_u64(seed);
        let mut bases: Vec<EdwardsAffine> = (0..n).map(|_| EdwardsAffine::rand(&mut rng)).collect();
        let mut scalars: Vec<Fr> = (0..n).map(|_| Fr::rand(&mut rng)).collect();
        if n > 3 {
            bases[1] = EdwardsAffine::zero();
            scalars[2] = Fr::zero();
            scalars[3] = -Fr::from(1u64);
        }
        (bases, scalars)
    }

    #[cfg(feature = "parallel")]
    fn pool(threads: usize) -> rayon::ThreadPool {
        rayon::ThreadPoolBuilder::new()
            .num_threads(threads)
            .build()
            .unwrap()
    }

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
        for n in [1usize, 2, 7, 31, 32, 33, 100, 1000, 2560, 4096, 4097, 8192] {
            let (bases, scalars) = input(0xc2 + n as u64, n);
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
        let (bases, scalars) = input(0xc2, 300);
        let s = scalars[0];
        let scalars: Vec<Fr> = (0..300).map(|i| if i % 3 == 0 { -s } else { s }).collect();
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
        let (bases, scalars) = input(0xc3, 8192);
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
            let pool = pool(threads);
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

    /// The vector path returns what arkworks' MSM returns however it is split: as one task or
    /// several, in pools of one, two and eight threads, with a task's groups on one thread and
    /// spread. The dispatch picks between the last two by what else is in flight in the process,
    /// other tests included, so both are run here.
    #[cfg(feature = "parallel")]
    #[test]
    fn split_msm_matches_ark_msm_in_any_pool() {
        if !lanes_under_test() {
            return;
        }
        let (bases, scalars) = input(0xc4, 16385);
        for threads in [1, 2, 8] {
            let pool = pool(threads);
            for n in [256, 2047, 2048, 2049, 4097, 8193, 16385] {
                let want = EdwardsProjective::msm(&bases[..n], &scalars[..n]).unwrap();
                for spread in [false, true] {
                    // SAFETY: `lanes_under_test()` returned true, so the host has the extension.
                    let got =
                        pool.install(|| unsafe { split_msm(&bases[..n], &scalars[..n], spread) });
                    assert_eq!(got, want, "n = {n}, {threads} threads, spread = {spread}");
                }
            }
        }
    }

    /// The split's tasks: one for every full [`LANE_MSM_TASK_POINTS`], at least one, and no more
    /// than one per thread. They are even: they differ by fewer points than there are tasks, so
    /// the shortest is under one point per task below `LANE_MSM_TASK_POINTS`, and while threads
    /// remain none has twice that.
    #[test]
    fn lane_msm_tasks_are_even() {
        const TASK: usize = LANE_MSM_TASK_POINTS;
        for threads in [1, 2, 8, 16, 32] {
            for points in [
                TASK / 4,
                TASK,
                2 * TASK - 1,
                2 * TASK,
                2 * TASK + 1,
                3 * TASK - 1,
                12_000,
                32 * TASK + 1,
                50_000,
                65_292,
                300_000,
            ] {
                let len = lane_msm_task_len(points, threads);
                let tasks = points.div_ceil(len);
                let last = points - (tasks - 1) * len;
                let what = format!("{points} points, {threads} threads");
                assert_eq!(tasks, (points / TASK).clamp(1, threads), "{what}");
                assert!(len - last < tasks, "{what}: {len} and {last}");
                assert!(tasks == 1 || last + tasks > TASK, "{what}: {last}");
                assert!(len < 2 * TASK || tasks == threads, "{what}: {len}");
            }
        }
        // one task up to the last point before two full ones, then an even split
        assert_eq!(lane_msm_task_len(2 * TASK - 1, 32), 2 * TASK - 1);
        assert_eq!(lane_msm_task_len(2 * TASK + 1, 32), TASK + 1);
        // a short last task: 31 of 1,025 points and one of 994
        assert_eq!(lane_msm_task_len(32 * TASK + 1, 32), TASK + 1);
    }

    /// An entry in a count of MSMs in flight says whether it started alone, and leaves the count
    /// when it is dropped, by a panic too.
    #[test]
    fn in_flight_counts_what_is_running() {
        static COUNT: AtomicUsize = AtomicUsize::new(0);
        {
            let first = InFlight::enter(&COUNT);
            assert!(first.alone);
            {
                let second = InFlight::enter(&COUNT);
                assert!(!second.alone);
                assert_eq!(COUNT.load(Ordering::Relaxed), 2);
            }
            assert!(!InFlight::enter(&COUNT).alone);
            assert_eq!(COUNT.load(Ordering::Relaxed), 1);
        }
        assert_eq!(COUNT.load(Ordering::Relaxed), 0);
        let unwound = std::panic::catch_unwind(|| {
            let _entry = InFlight::enter(&COUNT);
            assert_eq!(COUNT.load(Ordering::Relaxed), 1);
            panic!("while in flight");
        });
        let message = unwound.expect_err("the closure panics");
        assert_eq!(message.downcast_ref::<&str>(), Some(&"while in flight"));
        assert_eq!(COUNT.load(Ordering::Relaxed), 0);
        assert!(InFlight::enter(&COUNT).alone);
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
