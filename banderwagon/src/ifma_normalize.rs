//! The trie update's commitment conversions eight per vector register on AVX-512 IFMA, in the lane field
//! arithmetic of [`crate::ifma`]: projective points to canonical 64-byte commitments
//! ([`crate::Element::batch_to_commitments`]), and commitments to the scalar field by `x / y`
//! ([`crate::Element::batch_map_to_scalar_field`], [`crate::Element::hash_commitments`]).
//!
//! Each is one batch inversion (Montgomery's trick: three products per element and one exponentiation
//! per block of [`BLOCK`] elements, the chain split four ways so the products overlap) and a few products
//! per element, all on eight elements per register. Ark's Montgomery words (`R = 2^256`) are read as the
//! lane form (`R = 2^260`) of `v / 16` without conversion, as the lane committer does: `X/Z`, `X/Y` are
//! ratios, so the common factor cancels and the affine coordinates come out exact; the canonical bytes
//! are the plain integers (one product by 1) with the sign rule of the scalar path (`y` positive), and
//! the scalar-field image is the scalar path's `Fr::from_le_bytes_mod_order` of those bytes. A zero
//! denominator (which ark's batch inversion leaves at zero) is masked out of the chain and yields zero,
//! as the scalar path's does. The tests check every output byte and scalar against the scalar path on
//! random points, the identity, points with a negative `y`, and batches of every length modulo eight.
#![allow(clippy::needless_range_loop)]
use crate::ifma::*;
use crate::ifma_committer::words_to_limbs;
use crate::ifma_msm::transpose8;
use crate::{AffineElement, Element};
use ark_ed_on_bls12_381_bandersnatch::{EdwardsAffine, EdwardsProjective, Fq, Fr};
use ark_ff::{BigInt, Field, PrimeField};
use core::arch::x86_64::*;
use std::sync::OnceLock;

/// Elements per exponentiation: 256 lane groups, four interleaved product chains of 64 steps.
const BLOCK: usize = 2048;
const GROUPS: usize = BLOCK / 8;
const CHAINS: usize = 4;

/// Byte offsets of the projective coordinates inside an [`Element`] (ark's `Projective { x, y, t, z }`,
/// 32-byte `Fq` each; the layout is read, not assumed).
const OX: usize = core::mem::offset_of!(EdwardsProjective, x);
const OY: usize = core::mem::offset_of!(EdwardsProjective, y);
const OZ: usize = core::mem::offset_of!(EdwardsProjective, z);
const _: () = assert!(
    core::mem::size_of::<Element>() == 128
        && core::mem::size_of::<Fq>() == 32
        && OX.is_multiple_of(8)
        && OY.is_multiple_of(8)
        && OZ.is_multiple_of(8)
);
/// An [`AffineElement`] is the 64-byte record `x` then `y` (ark's `Affine { x, y }`; the layout is read,
/// not assumed): the lanes load it as they load a 64-byte commitment.
const _: () = assert!(
    core::mem::size_of::<AffineElement>() == 64
        && core::mem::offset_of!(EdwardsAffine, x) == 0
        && core::mem::offset_of!(EdwardsAffine, y) == 32
);

/// Word `w` (0..16) of every point after the two transposes of eight 128-byte points.
#[inline]
fn word(a: &[__m512i; 8], b: &[__m512i; 8], w: usize) -> __m512i {
    if w < 8 {
        a[w]
    } else {
        b[w - 8]
    }
}

/// Loads eight consecutive points' `x`, `y`, `z` words as lane limbs of `x/16`, `y/16`, `z/16`.
#[inline]
#[target_feature(enable = "avx512f,avx512ifma")]
unsafe fn load_xyz(c: &Ctx, pts: *const Element) -> (L5, L5, L5) {
    let base = pts as *const u8;
    let mut lo = [_mm512_setzero_si512(); 8];
    let mut hi = [_mm512_setzero_si512(); 8];
    for i in 0..8 {
        lo[i] = _mm512_loadu_si512(base.add(128 * i) as *const _);
        hi[i] = _mm512_loadu_si512(base.add(128 * i + 64) as *const _);
    }
    let a = transpose8(&lo); // words 0..8 of every point
    let b = transpose8(&hi); // words 8..16
    let coord = |o: usize| {
        let w = o / 8;
        [
            word(&a, &b, w),
            word(&a, &b, w + 1),
            word(&a, &b, w + 2),
            word(&a, &b, w + 3),
        ]
    };
    let x = words_to_limbs(c, &coord(OX));
    let y = words_to_limbs(c, &coord(OY));
    let z = words_to_limbs(c, &coord(OZ));
    (x, y, z)
}

/// Loads eight consecutive 64-byte commitments (`x` then `y`, little-endian canonical integers) as plain
/// lane limbs.
#[inline]
#[target_feature(enable = "avx512f,avx512ifma")]
unsafe fn load_xy_bytes(c: &Ctx, recs: *const [u8; 64]) -> (L5, L5) {
    let base = recs as *const u8;
    let mut r = [_mm512_setzero_si512(); 8];
    for i in 0..8 {
        r[i] = _mm512_loadu_si512(base.add(64 * i) as *const _);
    }
    let a = transpose8(&r);
    let x = words_to_limbs(c, &[a[0], a[1], a[2], a[3]]);
    let y = words_to_limbs(c, &[a[4], a[5], a[6], a[7]]);
    (x, y)
}

/// Stores eight points' canonical `(x, y)` plain limbs as 64-byte commitments.
#[inline]
#[target_feature(enable = "avx512f,avx512ifma")]
unsafe fn store_xy_bytes(x: &L5, y: &L5, out: *mut [u8; 64]) {
    let xw = limbs_to_words(x);
    let yw = limbs_to_words(y);
    let r = transpose8(&[xw[0], xw[1], xw[2], xw[3], yw[0], yw[1], yw[2], yw[3]]);
    let base = out as *mut u8;
    for i in 0..8 {
        _mm512_storeu_si512(base.add(64 * i) as *mut _, r[i]);
    }
}

/// The scalar field `Fr` (253 bits) as a lane modulus: `mont_mul_r(a, b) = a·b·2^−260 mod r`. Used once per
/// converted point to reinterpret the plain base-field integer `u` (< 2^255) into `Fr`'s Montgomery form
/// (`R = 2^256`): `mont_mul_r(u, k) = u·2^256 mod r` with `k = 2^516 mod r`, which is `Fr::from_le_bytes_mod_order`
/// of `u`'s bytes — the same element — without the byte round trip and its five scalar products.
struct FrMod {
    p: L5,
    n0: __m512i,
    /// `2^516 mod r`, plain (`u · k / 2^260 = u · 2^256`).
    k: L5,
}

// SAFETY: __m512i is plain data; built once, read afterwards.
unsafe impl Sync for FrMod {}
unsafe impl Send for FrMod {}

fn fr_mod() -> &'static FrMod {
    static M: OnceLock<FrMod> = OnceLock::new();
    // SAFETY: callers check `available()` first; this only broadcasts constants.
    M.get_or_init(|| unsafe { build_fr_mod() })
}

#[target_feature(enable = "avx512f,avx512ifma")]
unsafe fn build_fr_mod() -> FrMod {
    let r = to_limbs52(&Fr::MODULUS);
    let mut inv = r[0];
    for _ in 0..7 {
        inv = inv.wrapping_mul(2u64.wrapping_sub(r[0].wrapping_mul(inv)));
    }
    let n0 = (0u64.wrapping_sub(inv)) & ((1u64 << 52) - 1);
    let k = Fr::from(2u64).pow([516u64]).into_bigint();
    FrMod {
        p: bcast(&r),
        n0: _mm512_set1_epi64(n0 as i64),
        k: bcast(&to_limbs52(&k)),
    }
}

/// `mont_mul` with `Fr`'s modulus (the same schoolbook loop as [`crate::ifma::mont_mul`]); inputs with normalized
/// limbs and `a·b < r·2^260`, output `< 2r`.
#[inline]
#[target_feature(enable = "avx512f,avx512ifma")]
unsafe fn mont_mul_r(c: &Ctx, m: &FrMod, a: &L5, b: &L5) -> L5 {
    let zero = _mm512_setzero_si512();
    let mut t = [zero; 6];
    for i in 0..5 {
        let bi = b[i];
        for j in 0..5 {
            t[j] = _mm512_madd52lo_epu64(t[j], a[j], bi);
            t[j + 1] = _mm512_madd52hi_epu64(t[j + 1], a[j], bi);
        }
        let q = _mm512_madd52lo_epu64(zero, t[0], m.n0);
        for j in 0..5 {
            t[j] = _mm512_madd52lo_epu64(t[j], q, m.p[j]);
            t[j + 1] = _mm512_madd52hi_epu64(t[j + 1], q, m.p[j]);
        }
        let carry = _mm512_srli_epi64(t[0], 52);
        t[1] = _mm512_add_epi64(t[1], carry);
        t[0] = t[1];
        t[1] = t[2];
        t[2] = t[3];
        t[3] = t[4];
        t[4] = t[5];
        t[5] = zero;
    }
    let mut r = [zero; 5];
    let mut carry = zero;
    for j in 0..5 {
        let v = _mm512_add_epi64(t[j], carry);
        r[j] = _mm512_and_si512(v, c.mask);
        carry = _mm512_srli_epi64(v, 52);
    }
    r
}

/// Canonical representative (< r) of a value < 2r.
#[inline]
#[target_feature(enable = "avx512f,avx512ifma")]
unsafe fn canon_r(c: &Ctx, m: &FrMod, a: &L5) -> L5 {
    let mut ge: __mmask8 = 0;
    let mut decided: __mmask8 = 0;
    for j in (0..5).rev() {
        let gt = _mm512_cmpgt_epu64_mask(a[j], m.p[j]);
        let lt = _mm512_cmplt_epu64_mask(a[j], m.p[j]);
        ge |= gt & !decided;
        decided |= gt | lt;
    }
    ge |= !decided;
    let mut r = *a;
    let mut borrow = _mm512_setzero_si512();
    for j in 0..5 {
        let d = _mm512_sub_epi64(_mm512_sub_epi64(a[j], m.p[j]), borrow);
        borrow = _mm512_srli_epi64(d, 63);
        let fixed = _mm512_and_si512(d, c.mask);
        r[j] = _mm512_mask_blend_epi64(ge, a[j], fixed);
    }
    r
}

/// Per-call scratch: a block's denominators (zero lanes replaced by one), the prefix products, the
/// inverses, and the zero masks.
struct Scratch {
    dd: Vec<L5>,
    prefix: Vec<L5>,
    inv: Vec<L5>,
    zero: Vec<u8>,
}

impl Scratch {
    /// Sized to the call's largest block: `groups` lane groups (≤ [`GROUPS`]).
    fn new(c: &Ctx, groups: usize) -> Self {
        let g = groups.min(GROUPS);
        Scratch {
            dd: vec![c.one; g],
            prefix: vec![c.one; g],
            inv: vec![c.one; g],
            zero: vec![0; g],
        }
    }
}

/// The lane groups of a call: eight elements each, at most a block's worth live at once.
fn groups_of(n: usize) -> usize {
    (n / 8).min(GROUPS)
}

/// The plain (non-Montgomery) inverses of every group's lanes in `d` (zero lanes give zero) into
/// `s.inv`, one exponentiation for the block: `mont_mul(v, inv_plain)` of a lane value `v` is then the
/// plain quotient `v / d` directly.
#[target_feature(enable = "avx512f,avx512ifma")]
unsafe fn invert_block(c: &Ctx, d: &[L5], s: &mut Scratch) {
    let n = d.len();
    debug_assert!(n <= GROUPS);
    for g in 0..n {
        let cd = canon(c, &d[g]);
        s.zero[g] = is_zero(&cd);
        s.dd[g] = sel(s.zero[g], &cd, &c.one);
    }
    // four interleaved prefix-product chains: chain k holds the groups g ≡ k (mod 4)
    for g in 0..n {
        s.prefix[g] = if g < CHAINS {
            s.dd[g]
        } else {
            mont_mul(c, &s.prefix[g - CHAINS], &s.dd[g])
        };
    }
    let mut ends = [c.one; CHAINS];
    for k in 0..CHAINS.min(n) {
        let last = (n - 1 - k) / CHAINS * CHAINS + k; // the largest g ≡ k (mod 4) below n
        ends[k] = s.prefix[last];
    }
    let mut inv = batch_inverse::<CHAINS>(c, &ends);
    let zero = [_mm512_setzero_si512(); 5];
    for g in (0..n).rev() {
        let k = g % CHAINS;
        let o = if g < CHAINS {
            inv[k]
        } else {
            let o = mont_mul(c, &inv[k], &s.prefix[g - CHAINS]);
            inv[k] = mont_mul(c, &inv[k], &s.dd[g]);
            o
        };
        s.inv[g] = sel(s.zero[g], &to_plain(c, &o), &zero);
    }
}

/// `Element::batch_to_commitments` on the lanes; `elements.len()` is a multiple of eight.
///
/// # Safety
/// `available()` must have returned true on this host.
#[target_feature(enable = "avx512f,avx512ifma")]
pub(crate) unsafe fn batch_to_commitments(elements: &[Element], out: &mut [[u8; 64]]) {
    debug_assert!(elements.len().is_multiple_of(8) && out.len() == elements.len());
    let c = context();
    let g = groups_of(elements.len());
    let mut s = Scratch::new(c, g);
    let mut xs = vec![c.one; g];
    let mut ys = vec![c.one; g];
    let mut zs = vec![c.one; g];
    for (blk, out_blk) in elements.chunks(BLOCK).zip(out.chunks_mut(BLOCK)) {
        let n = blk.len() / 8;
        for g in 0..n {
            let (x, y, z) = load_xyz(c, blk.as_ptr().add(8 * g));
            xs[g] = x;
            ys[g] = y;
            zs[g] = z;
        }
        invert_block(c, &zs[..n], &mut s);
        for g in 0..n {
            // (X/16)·(16/Z) = X/Z: the affine coordinates exactly, as plain canonical integers
            let x = canon(c, &mont_mul(c, &xs[g], &s.inv[g]));
            let y = canon(c, &mont_mul(c, &ys[g], &s.inv[g]));
            // the representative with positive y: negate both where y is not
            let flip = !is_positive(c, &y);
            let x = sel(flip, &x, &neg_canon(c, &x));
            let y = sel(flip, &y, &neg_canon(c, &y));
            store_xy_bytes(&x, &y, out_blk.as_mut_ptr().add(8 * g));
        }
    }
}

/// The plain integers of `num / den` for every group (zero where `den` is zero), reinterpreted into the scalar
/// field as the scalar path does (`Fr::from_le_bytes_mod_order` of the little-endian bytes: `u mod r`, in
/// Montgomery form), on the lanes.
#[target_feature(enable = "avx512f,avx512ifma")]
unsafe fn ratios_to_scalars(c: &Ctx, nums: &[L5], dens: &[L5], s: &mut Scratch, out: &mut [Fr]) {
    let m = fr_mod();
    let n = nums.len();
    invert_block(c, dens, s);
    for g in 0..n {
        let u = canon(c, &mont_mul(c, &nums[g], &s.inv[g])); // plain, < p < 2^255
        let f = canon_r(c, m, &mont_mul_r(c, m, &u, &m.k)); // u · 2^256 mod r: Fr's representation
        let w = limbs_to_words(&f);
        let mut words = [[0u64; 8]; 4];
        for j in 0..4 {
            _mm512_storeu_si512(words[j].as_mut_ptr() as *mut _, w[j]);
        }
        for l in 0..8 {
            out[8 * g + l] =
                Fr::new_unchecked(BigInt([words[0][l], words[1][l], words[2][l], words[3][l]]));
        }
    }
}

/// `Element::batch_map_to_scalar_field` on the lanes; `elements.len()` is a multiple of eight.
///
/// # Safety
/// `available()` must have returned true on this host.
#[target_feature(enable = "avx512f,avx512ifma")]
pub(crate) unsafe fn batch_map_to_scalar_field(elements: &[Element], out: &mut [Fr]) {
    debug_assert!(elements.len().is_multiple_of(8) && out.len() == elements.len());
    let c = context();
    let g = groups_of(elements.len());
    let mut s = Scratch::new(c, g);
    let mut xs = vec![c.one; g];
    let mut ys = vec![c.one; g];
    for (blk, out_blk) in elements.chunks(BLOCK).zip(out.chunks_mut(BLOCK)) {
        let n = blk.len() / 8;
        for g in 0..n {
            // x/y = (X/Z)/(Y/Z) = X/Y: the projective coordinates directly, Z unused
            let (x, y, _) = load_xyz(c, blk.as_ptr().add(8 * g));
            xs[g] = x;
            ys[g] = y;
        }
        ratios_to_scalars(c, &xs[..n], &ys[..n], &mut s, out_blk);
    }
}

/// `AffineElement::batch_map_to_scalar_field` on the lanes; `elements.len()` is a multiple of eight. The
/// 64-byte affine records (`x` then `y`, Montgomery words) are read as `hash_commitments` reads plain
/// bytes: `x/y` is a ratio, the common factor cancels.
///
/// # Safety
/// `available()` must have returned true on this host.
#[target_feature(enable = "avx512f,avx512ifma")]
pub(crate) unsafe fn batch_map_to_scalar_field_affine(elements: &[AffineElement], out: &mut [Fr]) {
    debug_assert!(elements.len().is_multiple_of(8) && out.len() == elements.len());
    let c = context();
    let g = groups_of(elements.len());
    let mut s = Scratch::new(c, g);
    let mut xs = vec![c.one; g];
    let mut ys = vec![c.one; g];
    for (blk, out_blk) in elements.chunks(BLOCK).zip(out.chunks_mut(BLOCK)) {
        let n = blk.len() / 8;
        for g in 0..n {
            let (x, y) = load_xy_bytes(c, blk.as_ptr().add(8 * g) as *const [u8; 64]);
            xs[g] = x;
            ys[g] = y;
        }
        ratios_to_scalars(c, &xs[..n], &ys[..n], &mut s, out_blk);
    }
}

/// `Element::hash_commitments` on the lanes; `commitments.len()` is a multiple of eight.
///
/// # Safety
/// `available()` must have returned true on this host.
#[target_feature(enable = "avx512f,avx512ifma")]
pub(crate) unsafe fn hash_commitments(commitments: &[[u8; 64]], out: &mut [Fr]) {
    debug_assert!(commitments.len().is_multiple_of(8) && out.len() == commitments.len());
    let c = context();
    let g = groups_of(commitments.len());
    let mut s = Scratch::new(c, g);
    let mut xs = vec![c.one; g];
    let mut ys = vec![c.one; g];
    for (blk, out_blk) in commitments.chunks(BLOCK).zip(out.chunks_mut(BLOCK)) {
        for bytes in blk {
            // Unchecked point decoding still rejects noncanonical field coordinates.
            // Validate before raw lane loads, without a Montgomery conversion.
            for coordinate in bytes.chunks_exact(32) {
                let words = core::array::from_fn(|i| {
                    u64::from_le_bytes(coordinate[i * 8..i * 8 + 8].try_into().unwrap())
                });
                assert!(
                    BigInt::<4>(words) < Fq::MODULUS,
                    "noncanonical commitment coordinate"
                );
            }
            #[cfg(debug_assertions)]
            let _ = Element::from_bytes_unchecked_uncompressed(*bytes);
        }
        let n = blk.len() / 8;
        for g in 0..n {
            // plain x, y read as the lane form of x/R, y/R: the ratio is x/y all the same
            let (x, y) = load_xy_bytes(c, blk.as_ptr().add(8 * g));
            xs[g] = x;
            ys[g] = y;
        }
        ratios_to_scalars(c, &xs[..n], &ys[..n], &mut s, out_blk);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::element::{
        batch_map_to_scalar_field_affine_scalar, batch_map_to_scalar_field_scalar,
        batch_to_commitments_scalar, hash_commitments_scalar,
    };
    use ark_ec::CurveGroup;
    use ark_ed_on_bls12_381_bandersnatch::{EdwardsAffine, EdwardsProjective, Fq};
    use ark_ff::{One, UniformRand, Zero};
    use rand_chacha::rand_core::SeedableRng;

    fn points(n: usize, seed: u64) -> Vec<Element> {
        let mut rng = rand_chacha::ChaCha20Rng::seed_from_u64(seed);
        let mut v: Vec<Element> = (0..n)
            .map(|_| Element(EdwardsProjective::rand(&mut rng)))
            .collect();
        if n > 0 {
            v[0] = Element::zero();
        }
        if n > 1 {
            // a point with negative y, projective with z ≠ 1 (a sum keeps z generic)
            let g = Element::prime_subgroup_generator();
            let a = EdwardsAffine::from(v[1].0);
            let neg_y = if crate::element::is_positive(a.y) {
                EdwardsAffine::new_unchecked(-a.x, -a.y)
            } else {
                a
            };
            v[1] = Element(EdwardsProjective::from(neg_y) + g.0 - g.0);
        }
        if n > 2 {
            // an ark-projective with z = 0 (not a valid point; ark's batch inversion leaves its inverse 0)
            v[2] = Element(EdwardsProjective::new_unchecked(
                Fq::from(7u64),
                Fq::from(9u64),
                Fq::zero(),
                Fq::zero(),
            ));
        }
        v
    }

    #[test]
    fn lane_batch_to_commitments_matches_scalar() {
        if !available() {
            return;
        }
        for n in [8usize, 16, 64, 2048, 2056, 4096 + 24] {
            let pts = points(n, n as u64);
            let want = batch_to_commitments_scalar(&pts);
            let mut got = vec![[0u8; 64]; n];
            unsafe { batch_to_commitments(&pts, &mut got) };
            assert_eq!(got, want, "n = {n}");
        }
    }

    /// The affine kernel reads the 64-byte Montgomery records and gives the projective kernel's and
    /// the scalar path's values: the identity, a point with negative `y`, `y = 0` (masked, zero), random
    /// points, at every batch length modulo the block.
    #[test]
    fn lane_batch_map_to_scalar_field_affine_matches_scalar() {
        if !available() {
            return;
        }
        for n in [8usize, 16, 64, 2048, 2056, 4096 + 24] {
            let mut pts = points(n, n as u64 + 1);
            if n > 2 {
                pts[2] = Element(EdwardsProjective::new_unchecked(
                    Fq::from(7u64),
                    Fq::zero(),
                    Fq::zero(),
                    Fq::one(),
                ));
            }
            let affine: Vec<AffineElement> = pts
                .iter()
                .map(|p| AffineElement(EdwardsAffine::new_unchecked(p.0.x / p.0.z, p.0.y / p.0.z)))
                .collect();
            let want = batch_map_to_scalar_field_affine_scalar(&affine);
            let mut got = vec![Fr::zero(); n];
            unsafe { batch_map_to_scalar_field_affine(&affine, &mut got) };
            assert_eq!(got, want, "n = {n}");
            // and the projective kernel on the same points
            let mut proj = vec![Fr::zero(); n];
            let as_elements: Vec<Element> = affine.iter().map(|a| a.to_element()).collect();
            unsafe { batch_map_to_scalar_field(&as_elements, &mut proj) };
            assert_eq!(proj, want, "n = {n} (projective)");
        }
    }

    #[test]
    fn lane_batch_map_to_scalar_field_matches_scalar() {
        if !available() {
            return;
        }
        for n in [8usize, 24, 2048, 2056, 4096 + 8] {
            let pts = points(n, 100 + n as u64);
            let want = batch_map_to_scalar_field_scalar(&pts);
            let mut got = vec![Fr::zero(); n];
            unsafe { batch_map_to_scalar_field(&pts, &mut got) };
            assert_eq!(got, want, "n = {n}");
        }
    }

    #[test]
    fn lane_hash_commitments_matches_scalar() {
        if !available() {
            return;
        }
        for n in [8usize, 40, 2048, 2064] {
            let mut pts = points(n, 200 + n as u64);
            pts[2] = pts[3]; // the z = 0 record has no affine form; the zero denominator is tested below
            let bytes: Vec<[u8; 64]> = pts
                .iter()
                .map(|e| {
                    let a = e.0.into_affine();
                    let mut b = [0u8; 64];
                    b[..32].copy_from_slice(&crate::element::fq_to_le_bytes(a.x));
                    b[32..].copy_from_slice(&crate::element::fq_to_le_bytes(a.y));
                    b
                })
                .collect();
            let want = hash_commitments_scalar(&bytes);
            let mut got = vec![Fr::zero(); n];
            unsafe { hash_commitments(&bytes, &mut got) };
            assert_eq!(got, want, "n = {n}");
        }
        // Unchecked release-mode parsing accepts canonical off-curve records; debug
        // parsing rejects them, exactly as the scalar reference does.
        #[cfg(not(debug_assertions))]
        {
            let mut recs = vec![[0u8; 64]; 8];
            let g = Element::prime_subgroup_generator().0.into_affine();
            for r in recs.iter_mut() {
                r[..32].copy_from_slice(&crate::element::fq_to_le_bytes(g.x));
                r[32..].copy_from_slice(&crate::element::fq_to_le_bytes(g.y));
            }
            recs[5][..32].copy_from_slice(&crate::element::fq_to_le_bytes(Fq::from(7u64)));
            recs[5][32..].fill(0);
            let mut got = vec![Fr::zero(); 8];
            unsafe { hash_commitments(&recs, &mut got) };
            let g_scalar = Element::prime_subgroup_generator().map_to_scalar_field();
            for (i, v) in got.iter().enumerate() {
                assert_eq!(*v, if i == 5 { Fr::zero() } else { g_scalar }, "lane {i}");
            }
        }
    }
    /// The scalar path against the lanes on the trie update's shapes (a level's changed nodes).
    /// `cargo test --release -p banderwagon bench_normalize -- --ignored --nocapture`
    #[test]
    #[ignore]
    fn bench_normalize() {
        if !available() {
            return;
        }
        for n in [64usize, 512, 4096, 32768] {
            let pts = points(n, 7);
            let bytes = batch_to_commitments_scalar(&pts);
            let reps = (1 << 18) / n;
            let time = |f: &dyn Fn()| {
                f();
                let t0 = std::time::Instant::now();
                for _ in 0..reps {
                    f();
                }
                t0.elapsed().as_nanos() as f64 / (reps * n) as f64
            };
            let s1 = time(&|| {
                std::hint::black_box(batch_to_commitments_scalar(&pts));
            });
            let l1 = time(&|| {
                std::hint::black_box(Element::batch_to_commitments(&pts));
            });
            let s2 = time(&|| {
                std::hint::black_box(batch_map_to_scalar_field_scalar(&pts));
            });
            let l2 = time(&|| {
                std::hint::black_box(Element::batch_map_to_scalar_field(&pts));
            });
            let s3 = time(&|| {
                std::hint::black_box(hash_commitments_scalar(&bytes));
            });
            let l3 = time(&|| {
                std::hint::black_box(Element::hash_commitments(&bytes));
            });
            println!(
                "n={n}: to_commitments scalar {s1:.0} lanes {l1:.0} ns/pt x{:.1}; map_to_scalar scalar {s2:.0} lanes {l2:.0} x{:.1}; hash_commitments scalar {s3:.0} lanes {l3:.0} x{:.1}",
                s1 / l1,
                s2 / l2,
                s3 / l3
            );
        }
    }
}
