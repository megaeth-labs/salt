//! The committer's fixed-base scalar multiplications ([`crate::salt_committer::Committer::mul_index`])
//! eight per vector register on AVX-512 IFMA, in the lane field arithmetic of [`crate::ifma`].
//!
//! Every `mul_index` is a chain of `win_num` additions of table points that depends on nothing but its own
//! scalar and base index, and the trie update issues thousands of them per block that are independent of
//! one another; so eight of them share one vector register, one chain step per lane per iteration. The
//! window digits, the signed-digit carry rule and the table layout are the scalar path's
//! (`calculate_prefetch_index` and the index arithmetic of `mul_index`), so the result is the same group
//! element, which the tests check against `mul_index` on random scalars, zero, one, −1 and the largest
//! scalar.
//!
//! The table stays in ark's Montgomery form (`R = 2^256`, four 64-bit words per coordinate), which the
//! lanes read as the lane form (`R = 2^260`) of `x / 16`: the table point is added as the projective
//! representative `(x/16 : y/16 : x·y/16 : 1/16)` of `(x, y)`, one unified full addition per step
//! (10 lane products with `d` folded into the third coordinate, plus two to form it); no scaling of the
//! table and no second table.
#![allow(clippy::needless_range_loop)]
use crate::ifma::*;
use crate::ifma_msm::{consts, unlane, Consts, PtL};
use crate::salt_committer::calculate_prefetch_index;
use ark_ec::twisted_edwards::TECurveConfig;
use ark_ed_on_bls12_381_bandersnatch::{BandersnatchConfig, EdwardsAffine, EdwardsProjective, Fr};
use ark_ff::Field;
use core::arch::x86_64::*;
use std::sync::OnceLock;

struct CommitterConsts {
    /// `16·d` in lane form: `mont_mul(x/16, y/16) · 16d = d·x·y/16`.
    sixteen_d: L5,
    /// `1/16` in lane form: the Z coordinate of every table point as the lanes read it.
    z_inv16: L5,
}

// SAFETY: __m512i is plain data; the constants are built once and only read afterwards.
unsafe impl Sync for CommitterConsts {}
unsafe impl Send for CommitterConsts {}

fn committer_consts() -> &'static CommitterConsts {
    static K: OnceLock<CommitterConsts> = OnceLock::new();
    // SAFETY: callers check `available()` first; this only broadcasts constants.
    K.get_or_init(|| unsafe { build_committer_consts() })
}

#[target_feature(enable = "avx512f,avx512ifma")]
unsafe fn build_committer_consts() -> CommitterConsts {
    let sixteen = Fq::from(16u64);
    CommitterConsts {
        sixteen_d: bcast(&bcast_limbs(&(BandersnatchConfig::COEFF_D * sixteen))),
        z_inv16: bcast(&bcast_limbs(&sixteen.inverse().expect("16 is invertible"))),
    }
}

/// Four 64-bit words (ark's Montgomery representation, gathered one word per register) as five 52-bit limbs.
#[inline]
#[target_feature(enable = "avx512f,avx512ifma")]
pub(crate) unsafe fn words_to_limbs(c: &Ctx, w: &[__m512i; 4]) -> L5 {
    let m = c.mask;
    [
        _mm512_and_si512(w[0], m),
        _mm512_and_si512(
            _mm512_or_si512(_mm512_srli_epi64(w[0], 52), _mm512_slli_epi64(w[1], 12)),
            m,
        ),
        _mm512_and_si512(
            _mm512_or_si512(_mm512_srli_epi64(w[1], 40), _mm512_slli_epi64(w[2], 24)),
            m,
        ),
        _mm512_and_si512(
            _mm512_or_si512(_mm512_srli_epi64(w[2], 28), _mm512_slli_epi64(w[3], 36)),
            m,
        ),
        _mm512_srli_epi64(w[3], 16),
    ]
}

/// Per-lane table addresses for one chain step: the byte address of the table point each lane adds, and
/// whether the lane adds its negation (the signed-digit carry rule of `mul_index`).
struct Steps {
    addr: Vec<[i64; 8]>,
    neg: Vec<u8>,
}

fn plan(tables: &[Vec<EdwardsAffine>], w: usize, scalars: &[Fr], indices: &[usize]) -> Steps {
    let half_wnd = (1usize << (w - 1)) + 1;
    let wnd_size = 1usize << w;
    let win_num = 253 / w + 1;
    let mut addr = vec![[0i64; 8]; win_num];
    let mut neg = vec![0u8; win_num];
    for (l, (s, &g)) in scalars.iter().zip(indices).enumerate() {
        let chunks = calculate_prefetch_index(s, w);
        debug_assert_eq!(chunks.len(), win_num);
        let table = tables[g].as_ptr();
        let mut carry = 0usize;
        for (i, &d) in chunks.iter().enumerate() {
            let mut idx = d as usize + carry;
            if idx >= half_wnd {
                carry = 1;
                idx = wnd_size - idx;
                neg[i] |= 1 << l;
            } else {
                carry = 0;
            }
            // SAFETY: idx + i * half_wnd < win_num * half_wnd = the table length; the pointer is only
            // used as an address for the gathers.
            addr[i][l] = unsafe { table.add(idx + i * half_wnd) } as i64;
        }
    }
    // idle lanes (fewer than eight items) point at lane 0's addresses: their results are dropped
    for l in scalars.len()..8 {
        for i in 0..win_num {
            addr[i][l] = addr[i][0];
        }
    }
    Steps { addr, neg }
}

/// Up to eight `scalars[l] * bases[indices[l]]`, the same elements `mul_index` computes.
///
/// # Safety
/// `available()` must have returned true on this host; `scalars.len() == indices.len() <= 8`, every index
/// below `tables.len()`.
#[target_feature(enable = "avx512f,avx512ifma")]
pub(crate) unsafe fn mul_index8(
    tables: &[Vec<EdwardsAffine>],
    w: usize,
    scalars: &[Fr],
    indices: &[usize],
) -> [EdwardsProjective; 8] {
    let c = context();
    let k: &Consts = consts();
    let kc = committer_consts();
    let steps = plan(tables, w, scalars, indices);
    let n = steps.addr.len();
    let prefetch = |i: usize| {
        if i < n {
            for l in 0..8 {
                _mm_prefetch(steps.addr[i][l] as *const i8, _MM_HINT_T0);
            }
        }
    };
    prefetch(0);
    prefetch(1);
    let lane_off = |v: __m512i, bytes: i64| _mm512_add_epi64(v, _mm512_set1_epi64(bytes));
    let mut acc = k.id;
    for i in 0..n {
        prefetch(i + 2);
        let a = _mm512_loadu_si512(steps.addr[i].as_ptr() as *const _);
        // x: words 0..4 at +0, y: words 0..4 at +32 (EdwardsAffine { x: Fq, y: Fq }, 64 bytes)
        let mut xw = [_mm512_setzero_si512(); 4];
        let mut yw = [_mm512_setzero_si512(); 4];
        for j in 0..4 {
            xw[j] = _mm512_i64gather_epi64::<1>(lane_off(a, (8 * j) as i64), core::ptr::null());
            yw[j] =
                _mm512_i64gather_epi64::<1>(lane_off(a, (32 + 8 * j) as i64), core::ptr::null());
        }
        let x = words_to_limbs(c, &xw); // lane form of x / 16
        let y = words_to_limbs(c, &yw);
        let t = mont_mul(c, &mont_mul(c, &x, &y), &kc.sixteen_d); // d · x · y / 16
        let neg = steps.neg[i];
        let q = PtL {
            x: sel(neg, &x, &sub(c, &k.zero, &x)),
            y,
            t: sel(neg, &t, &sub(c, &k.zero, &t)),
            z: kc.z_inv16,
        };
        acc = padd_folded(c, k, &acc, &q);
    }
    unlane(c, &acc)
}

/// Full addition p + q where `q.t` already carries the curve's `d`: 10 lane products.
#[inline]
#[target_feature(enable = "avx512f,avx512ifma")]
unsafe fn padd_folded(c: &Ctx, k: &Consts, p: &PtL, q: &PtL) -> PtL {
    let a = mont_mul(c, &p.x, &q.x);
    let b = mont_mul(c, &p.y, &q.y);
    let cc = mont_mul(c, &p.t, &q.t);
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::element::Element;
    use crate::salt_committer::Committer;
    use ark_ff::{One, UniformRand, Zero};
    use rand_chacha::rand_core::{RngCore, SeedableRng};

    #[test]
    fn lane_mul_index_matches_scalar() {
        if !available() {
            return;
        }
        let mut rng = rand_chacha::ChaCha20Rng::seed_from_u64(0xc3);
        let bases: Vec<Element> = (0..16)
            .map(|_| Element(EdwardsProjective::rand(&mut rng)))
            .collect();
        for &w in &[11usize, 8, 9] {
            let committer = Committer::new(&bases, w);
            let mut scalars: Vec<Fr> = (0..8).map(|_| Fr::rand(&mut rng)).collect();
            scalars[1] = Fr::zero();
            scalars[2] = Fr::one();
            scalars[3] = -Fr::one();
            scalars[4] = -Fr::from(2u64);
            scalars[5] = Fr::from(1u64 << (w - 1));
            let indices: Vec<usize> = (0..8).map(|i| (i * 5) % 16).collect();
            for n in [8usize, 1, 3, 7] {
                let got = committer.mul_index_batch(&scalars[..n], &indices[..n]);
                for l in 0..n {
                    let want = committer.mul_index(&scalars[l], indices[l]);
                    assert_eq!(got[l], want, "w = {w}, n = {n}, lane {l}");
                }
            }
        }
    }

    /// Scalar `mul_index` against the lanes on the product's table shape (256 bases), per window size.
    /// `cargo test --release -p banderwagon bench_mul_index_batch -- --ignored --nocapture`
    #[test]
    #[ignore]
    fn bench_mul_index_batch() {
        if !available() {
            return;
        }
        let mut rng = rand_chacha::ChaCha20Rng::seed_from_u64(0xbe);
        let bases: Vec<Element> = (0..256)
            .map(|_| Element(EdwardsProjective::rand(&mut rng)))
            .collect();
        let n = 8192usize;
        let scalars: Vec<Fr> = (0..n).map(|_| Fr::rand(&mut rng)).collect();
        let indices: Vec<usize> = (0..n).map(|_| (rng.next_u64() % 256) as usize).collect();
        for &w in &[11usize, 9, 8, 7] {
            let t0 = std::time::Instant::now();
            let committer = Committer::new(&bases, w);
            let build = t0.elapsed();
            let mut acc = Element::zero();
            let t0 = std::time::Instant::now();
            for (s, &g) in scalars.iter().zip(&indices) {
                acc += committer.mul_index(s, g);
            }
            let scalar_ns = t0.elapsed().as_nanos() as f64 / n as f64;
            let t0 = std::time::Instant::now();
            let batch = committer.mul_index_batch(&scalars, &indices);
            let lane_ns = t0.elapsed().as_nanos() as f64 / n as f64;
            let mut acc2 = Element::zero();
            for e in &batch {
                acc2 += *e;
            }
            assert_eq!(acc, acc2, "w = {w}");
            println!(
                "committer w={w}: table build {:.2} s, scalar {scalar_ns:.0} ns/mul, lanes {lane_ns:.0} ns/mul, x{:.2}",
                build.as_secs_f64(),
                scalar_ns / lane_ns
            );
        }
    }
}
