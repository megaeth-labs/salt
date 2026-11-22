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
//! The committer's tables stay as the scalar path reads them: affine points in ark's Montgomery form
//! (`R = 2^256`, four 64-bit words per coordinate). The lanes' form has `R = 2^260`, so they read a
//! table point `(x, y)` as `(x/16, y/16)`. Nothing multiplies that 16 out. The accumulator carries
//! it: after `i` steps it holds `(X/16^i : Y/16^i : T/16^(2i) : Z)` for the sum `(X : Y : T : Z)` so
//! far, and the mixed addition keeps that shape when the table point's third coordinate, `d·x·y`,
//! comes multiplied by `16^(2i)`. That product is what [`LaneTables`] stores for the points of window
//! `i`, 32 bytes beside each 64-byte table point, so a step is one mixed addition of 8 lane products
//! ([`madd`]). The powers of 16 leave in the multiplication that takes the result out of the lanes'
//! Montgomery form ([`unscale`]).
#![allow(clippy::needless_range_loop)]
use crate::ifma::*;
use crate::ifma_msm::transpose8;
use crate::salt_committer::LANES;
use crate::Fq;
use ark_ec::twisted_edwards::TECurveConfig;
use ark_ed_on_bls12_381_bandersnatch::{BandersnatchConfig, EdwardsAffine, EdwardsProjective, Fr};
use ark_ff::{BigInt, Field, PrimeField};
use core::arch::x86_64::*;
use salt_macros::iter;
use salt_macros::prelude::*;
use std::sync::OnceLock;
use std::vec::Vec;

/// What the lane path keeps beside a committer's affine tables. Built only on a host with the
/// extension, so holding one is the proof that the lanes run here.
#[derive(Clone, Debug)]
pub(crate) struct LaneTables {
    /// For entry `e` of base `g`'s table, a point `(x, y)` of window `i`: `16^(2i) · d · x · y` in
    /// the lanes' Montgomery form, canonical, as four words.
    t: Vec<Vec<[u64; 4]>>,
    /// The factors that take a finished chain's `X` and `Y`, `T`, and `Z` to ark's Montgomery
    /// form: `16^n`, `16^(2n)` and 1 for the tables' `n` windows, each times `2^256`, as limbs.
    unscale: [[u64; 5]; 3],
}

impl LaneTables {
    /// The lane tables of a committer's `tables` at window `w`, or `None` on a host without the
    /// extension.
    pub(crate) fn new(tables: &[Vec<EdwardsAffine>], w: usize) -> Option<Self> {
        if !available() {
            return None;
        }
        let half_wnd = (1usize << (w - 1)) + 1;
        let win_num = 253 / w + 1;
        // the lane form of v is ark's form of 16·v
        let d = BandersnatchConfig::COEFF_D * Fq::from(16u64);
        let step = Fq::from(256u64);
        let t = iter!(tables)
            .map(|table| {
                debug_assert_eq!(table.len(), win_num * half_wnd);
                let mut t = Vec::with_capacity(table.len());
                let mut k = d;
                for window in table.chunks(half_wnd) {
                    t.extend(window.iter().map(|p| (p.x * p.y * k).0 .0));
                    k *= step;
                }
                t
            })
            .collect();
        let s = Fq::from(16u64).pow([win_num as u64]);
        let unscale = [s, s * s, Fq::ONE].map(|k| to_limbs52(&k.0));
        Some(Self { t, unscale })
    }
}

/// `3p` on every lane: what [`madd`] adds to a difference of three products to keep it positive.
fn three_p() -> &'static L5 {
    static K: OnceLock<L5> = OnceLock::new();
    K.get_or_init(|| {
        let p = to_limbs52(&Fq::MODULUS);
        let mut l = [0u64; 5];
        let mut carry = 0;
        for j in 0..5 {
            let v = 3 * p[j] + carry;
            l[j] = v & ((1 << 52) - 1);
            carry = v >> 52;
        }
        assert_eq!(carry, 0, "3p fits five limbs");
        assert!(available(), "the lane constants need AVX-512 IFMA");
        // SAFETY: `available()` returned true just above; this only broadcasts constants.
        unsafe { bcast(&l) }
    })
}

/// The loads of [`mul_index8`] read a table point as the 64-byte record `x` then `y` (ark's
/// `Affine { x, y }`, four 64-bit words each); a different layout must not compile.
const _: () = assert!(
    core::mem::size_of::<EdwardsAffine>() == 64
        && core::mem::offset_of!(EdwardsAffine, x) == 0
        && core::mem::offset_of!(EdwardsAffine, y) == 32
);

/// One group's chain: per step, the table entry each lane adds and whether the lane adds its
/// negation (the signed-digit carry rule of `mul_index`). Reused from group to group.
struct Steps {
    entry: Vec<[u32; LANES]>,
    neg: Vec<u8>,
}

/// Window `i` of a scalar's plain integer: the `w` bits from bit `i·w`, as
/// `calculate_prefetch_index` cuts them.
#[inline]
fn digit(words: &[u64; 4], w: usize, i: usize) -> usize {
    let bit = i * w;
    let (word, off) = (bit >> 6, bit & 63);
    let mut d = words[word] >> off;
    if off + w > 64 && word < 3 {
        d |= words[word + 1] << (64 - off);
    }
    (d & ((1 << w) - 1)) as usize
}

impl Steps {
    fn new(w: usize) -> Self {
        let win_num = 253 / w + 1;
        Self {
            entry: vec![[0; LANES]; win_num],
            neg: vec![0; win_num],
        }
    }

    /// Fills the steps for up to eight scalars. Idle lanes copy lane 0's entries, unnegated, so
    /// that their loads stay inside the tables; [`mul_index8`] gives them the last scalar's base,
    /// so what they compute is no product of the batch, and [`mul_index_batch`] drops it.
    fn plan(&mut self, w: usize, scalars: &[Fr]) {
        let half_wnd = (1usize << (w - 1)) + 1;
        let wnd_size = 1usize << w;
        self.neg.fill(0);
        for (l, s) in scalars.iter().enumerate() {
            let words = s.into_bigint().0;
            let mut carry = 0usize;
            for i in 0..self.entry.len() {
                let mut idx = digit(&words, w, i) + carry;
                if idx >= half_wnd {
                    carry = 1;
                    idx = wnd_size - idx;
                    self.neg[i] |= 1 << l;
                } else {
                    carry = 0;
                }
                self.entry[i][l] = (idx + i * half_wnd) as u32;
            }
        }
        for l in scalars.len()..LANES {
            for step in self.entry.iter_mut() {
                step[l] = step[0];
            }
        }
    }
}

/// `scalars[j] * bases[indices[j]]` for every `j`, the elements `mul_index` computes one by one.
///
/// # Safety
/// `lane` was built from `tables` at window `w` (so the host has the extension), the two slices
/// are equally long, and every index is below `tables.len()`.
#[target_feature(enable = "avx512f,avx512ifma")]
pub(crate) unsafe fn mul_index_batch(
    tables: &[Vec<EdwardsAffine>],
    lane: &LaneTables,
    w: usize,
    scalars: &[Fr],
    indices: &[usize],
) -> Vec<EdwardsProjective> {
    let mut out = Vec::with_capacity(scalars.len());
    let mut steps = Steps::new(w);
    for (s, g) in scalars.chunks(LANES).zip(indices.chunks(LANES)) {
        steps.plan(w, s);
        let r = mul_index8(tables, lane, &steps, g);
        out.extend_from_slice(&r[..s.len()]);
    }
    out
}

/// One chain per lane over `steps`, for the bases `indices` names (one to eight of them).
#[target_feature(enable = "avx512f,avx512ifma")]
unsafe fn mul_index8(
    tables: &[Vec<EdwardsAffine>],
    lane: &LaneTables,
    steps: &Steps,
    indices: &[usize],
) -> [EdwardsProjective; LANES] {
    let c = context();
    let three_p = three_p();
    let zero = [_mm512_setzero_si512(); 5];
    let points: [*const EdwardsAffine; LANES] =
        core::array::from_fn(|l| tables[indices[l.min(indices.len() - 1)]].as_ptr());
    let products: [*const [u64; 4]; LANES] =
        core::array::from_fn(|l| lane.t[indices[l.min(indices.len() - 1)]].as_ptr());
    let n = steps.entry.len();
    // SAFETY (the prefetches and the loads below): an entry is below win_num · half_wnd, the
    // length of both tables of a base, so each address is that of a whole point or product.
    let prefetch = |i: usize| {
        if i < n {
            for l in 0..LANES {
                let e = steps.entry[i][l] as usize;
                _mm_prefetch(points[l].add(e) as *const i8, _MM_HINT_T0);
                _mm_prefetch(products[l].add(e) as *const i8, _MM_HINT_T0);
            }
        }
    };
    prefetch(0);
    prefetch(1);
    let mut acc = Acc {
        x: zero,
        y: c.one,
        t: zero,
        z: c.one,
    };
    for i in 0..n {
        prefetch(i + 2);
        // each lane's point is one 64-byte row and its product half a row: loaded whole and
        // transposed in registers, so no gather touches the tables
        let mut rows = [_mm512_setzero_si512(); LANES];
        let mut halves = [_mm256_setzero_si256(); LANES];
        for l in 0..LANES {
            let e = steps.entry[i][l] as usize;
            rows[l] = _mm512_loadu_si512(points[l].add(e) as *const _);
            halves[l] = _mm256_loadu_si256(products[l].add(e) as *const _);
        }
        let words = transpose8(&rows);
        let x = words_to_limbs(c, &[words[0], words[1], words[2], words[3]]);
        let y = words_to_limbs(c, &[words[4], words[5], words[6], words[7]]);
        let t = words_to_limbs(c, &transpose4(&halves));
        // the negated point is (-x, y), and its product changes sign with x
        let neg = steps.neg[i];
        let x = sel(neg, &x, &sub(c, &zero, &x));
        let t = sel(neg, &t, &sub(c, &zero, &t));
        acc = madd(c, three_p, &acc, &x, &y, &t);
    }
    unscale(c, &lane.unscale, &acc)
}

/// 8 × 4 transpose of 64-bit words: `r[l]` holds lane `l`'s four words in; word `j` of every lane
/// out.
#[inline]
#[target_feature(enable = "avx512f")]
unsafe fn transpose4(r: &[__m256i; LANES]) -> [__m512i; 4] {
    // two lanes per register, paired so that the 128-bit shuffles below leave the lanes in order
    let pair = |a: usize, b: usize| _mm512_inserti64x4::<1>(_mm512_castsi256_si512(r[a]), r[b]);
    let (z0, z1, z2, z3) = (pair(0, 2), pair(1, 3), pair(4, 6), pair(5, 7));
    let t0 = _mm512_unpacklo_epi64(z0, z1);
    let t1 = _mm512_unpackhi_epi64(z0, z1);
    let t2 = _mm512_unpacklo_epi64(z2, z3);
    let t3 = _mm512_unpackhi_epi64(z2, z3);
    [
        _mm512_shuffle_i64x2::<0x88>(t0, t2),
        _mm512_shuffle_i64x2::<0x88>(t1, t3),
        _mm512_shuffle_i64x2::<0xdd>(t0, t2),
        _mm512_shuffle_i64x2::<0xdd>(t1, t3),
    ]
}

/// The running sum of a chain, eight lanes: after `i` steps `(X/16^i, Y/16^i, T/16^(2i), Z)` for
/// the extended coordinates `(X : Y : T : Z)` of the sum so far. No coordinate exceeds `2p`.
#[derive(Clone, Copy)]
struct Acc {
    x: L5,
    y: L5,
    t: L5,
    z: L5,
}

/// `p + q` for a table point `q = (x, y)` of the next window, read as the lanes read it, and its
/// product `t` from [`LaneTables`]: the unified mixed addition (`Z2 = 1`, `a = -5`), 8 lane
/// products.
///
/// With `s = 16^i` the inputs are `X1/s, Y1/s, T1/s², Z1` and `x2/16, y2/16, s²·d·x2·y2`, so
/// `A`, `B`, `E` and `H` come out divided by `16s` while `C`, `F` and `G` come out exact, and the
/// four products are `X3/16s`, `Y3/16s`, `T3/(16s)²` and `Z3`: the same shape one window on.
///
/// Bounds, with `p/2^260 < 0.0284`: `mont_mul` of factors below `u·p` and `v·p` needs
/// `u·v < 35.3` and returns less than `(0.0284·u·v + 1)·p`. `x` and `t` are at most `2p` (below
/// `p`, or `2p` minus that), `y` is below `p`, and the accumulator below `2p`; so `a`, `b` and `c`
/// are below `1.12p` and `ee` (factors below `4p` and `3p`) below `1.35p`. Then `e < 4.35p`,
/// `f < 4p`, `g < 3.12p` and `h < 6.63p`, and the largest product, `e·h`, has `u·v < 29`.
#[inline]
#[target_feature(enable = "avx512f,avx512ifma")]
unsafe fn madd(c: &Ctx, three_p: &L5, p: &Acc, x: &L5, y: &L5, t: &L5) -> Acc {
    let a = mont_mul(c, &p.x, x);
    let b = mont_mul(c, &p.y, y);
    let cc = mont_mul(c, &p.t, t);
    let ee = mont_mul(c, &add(c, &p.x, &p.y), &add(c, x, y));
    // E = ee - A - B, kept positive by 3p (A + B < 2.18p); H = B - a·A = B + 5A. Each in one
    // pass over the limbs, carries normalized at the end.
    let mut e = [_mm512_setzero_si512(); 5];
    let mut h = e;
    let (mut borrow, mut carry) = (e[0], e[0]);
    for j in 0..5 {
        let v = _mm512_sub_epi64(
            _mm512_add_epi64(ee[j], three_p[j]),
            _mm512_add_epi64(a[j], b[j]),
        );
        let v = _mm512_add_epi64(v, borrow);
        e[j] = _mm512_and_si512(v, c.mask);
        borrow = _mm512_srai_epi64::<52>(v); // arithmetic: -1 where the limb went negative
        let v = _mm512_add_epi64(_mm512_slli_epi64::<2>(a[j]), _mm512_add_epi64(a[j], b[j]));
        let v = _mm512_add_epi64(v, carry);
        h[j] = _mm512_and_si512(v, c.mask);
        carry = _mm512_srli_epi64::<52>(v);
    }
    let f = sub(c, &p.z, &cc);
    let g = add(c, &p.z, &cc);
    Acc {
        x: mont_mul(c, &e, &f),
        y: mont_mul(c, &g, &h),
        t: mont_mul(c, &e, &h),
        z: mont_mul(c, &f, &g),
    }
}

/// The eight lanes of a finished chain as ark projective points: each coordinate times its
/// factor of [`LaneTables`], which removes the chain's powers of 16 and lands on ark's Montgomery
/// form in the one multiplication.
#[target_feature(enable = "avx512f,avx512ifma")]
unsafe fn unscale(c: &Ctx, factors: &[[u64; 5]; 3], p: &Acc) -> [EdwardsProjective; LANES] {
    let [xy, t, z] = factors.map(|k| bcast(&k));
    let coords = [(&p.x, &xy), (&p.y, &xy), (&p.t, &t), (&p.z, &z)].map(|(v, k)| {
        let words = limbs_to_words(&canon(c, &mont_mul(c, v, k)));
        let mut out = [[0u64; LANES]; 4];
        for j in 0..4 {
            _mm512_storeu_si512(out[j].as_mut_ptr() as *mut _, words[j]);
        }
        out
    });
    let fq = |coord: &[[u64; LANES]; 4], l: usize| {
        Fq::new_unchecked(BigInt([coord[0][l], coord[1][l], coord[2][l], coord[3][l]]))
    };
    core::array::from_fn(|l| {
        EdwardsProjective::new_unchecked(
            fq(&coords[0], l),
            fq(&coords[1], l),
            fq(&coords[2], l),
            fq(&coords[3], l),
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::element::tests::lanes_under_test;
    use crate::element::Element;
    use crate::salt_committer::Committer;
    use ark_ff::{One, UniformRand, Zero};
    use rand_chacha::rand_core::{RngCore, SeedableRng};

    #[test]
    fn lane_mul_index_matches_scalar() {
        if !lanes_under_test() {
            return;
        }
        let mut rng = rand_chacha::ChaCha20Rng::seed_from_u64(0xc3);
        let bases: Vec<Element> = (0..16)
            .map(|_| Element(EdwardsProjective::rand(&mut rng)))
            .collect();
        for &w in &[
            11usize,
            8,
            9,
            6,
            4,
            crate::platform::LANE_PRECOMP_WINDOW_SIZE,
        ] {
            let committer = Committer::new(&bases, w);
            let mut scalars: Vec<Fr> = (0..8).map(|_| Fr::rand(&mut rng)).collect();
            scalars[1] = Fr::zero();
            scalars[2] = Fr::one();
            scalars[3] = -Fr::one();
            scalars[4] = -Fr::from(2u64);
            // the largest digit added as it is, and the smallest that is added negated
            scalars[5] = Fr::from(1u64 << (w - 1));
            scalars[6] = Fr::from((1u64 << (w - 1)) + 1);
            let indices: Vec<usize> = (0..8).map(|i| (i * 5) % 16).collect();
            for n in [8usize, 1, 3, 7] {
                let got = committer.mul_index_batch(&scalars[..n], &indices[..n]);
                for l in 0..n {
                    let want = committer.mul_index(&scalars[l], indices[l]);
                    assert_eq!(got[l], want, "w = {w}, n = {n}, lane {l}");
                    // `==` reads only X and Y; adding the product to anything also needs
                    // T = XY/Z, which the unscale sets apart from X and Y
                    let p = got[l].0;
                    assert!(!p.z.is_zero(), "w = {w}, n = {n}, lane {l}: Z = 0");
                    assert_eq!(p.x * p.y, p.t * p.z, "w = {w}, n = {n}, lane {l}: XY ≠ TZ");
                }
            }
        }
    }

    /// Scalar `mul_index` against the lanes on the product's table shape (256 bases), per window size.
    /// `cargo test --release -p banderwagon bench_mul_index_batch -- --ignored --nocapture`
    #[test]
    #[ignore]
    #[cfg_attr(coverage_nightly, coverage(off))]
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
