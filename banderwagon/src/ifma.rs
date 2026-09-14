//! Eight-lane AVX-512 IFMA arithmetic in the Bandersnatch base field `Fq` (= BLS12-381 `Fr`, 255 bits) for
//! the witness decode's per-point work in [`crate::Element::from_bytes`]: the Legendre symbol of the
//! subgroup check, the inversion in `y² = n / d`, and the square root. Eight points share one vector
//! register: radix 2^52, five limbs, Montgomery form with `R = 2^260` (> 4p, so every product of inputs
//! < 2p is again < 2p without a final subtraction; values are canonicalized on store).
//!
//! The subgroup check's Legendre symbol is the binary Jacobi algorithm in lanes ([`jacobi_multi`]): a
//! fixed number of positive divsteps (the form libsecp256k1's `jacobi64_maybe_var` runs, one bit per
//! step) on the low 64-bit words, the batch's 2×2 transition applied to the full values by IFMA, and
//! the symbol's sign tracked from `f mod 8` at each halving and from `f, g mod 4` at each swap — about
//! a thousand lane operations per point where Euler's criterion costs 315 lane products. The chunk's
//! 32 inversions share one exponentiation (Montgomery's batch trick across the four lane groups), and
//! the square root is the 2-adic discrete-logarithm formulation: with `p − 1 = 2^32 · t`,
//! `w = a^((t−1)/2)` puts `b = w²·a = a^t` in the order-2^32 subgroup; `k = log_g(b)` is read eight bits
//! at a time from a 256-entry table (`a` is a residue iff `k` is even), and `√a = w·a·g^(−k/2)` from a
//! fixed-base table. Every lane runs the same instruction stream (select instead of branch), so a
//! chunk's cost does not depend on the points beyond the batch at which its last lane's Jacobi symbol
//! settles. The result on every input is the scalar path's (`legendre()` for the subgroup check, one
//! `d^(p-2)` per chunk, a root that squares back to `n/d`), which the tests check on accepted points,
//! off-curve `x` and out-of-subgroup points; a lane whose table lookup misses (never on a residue of a
//! field element) is reported undecided and takes the scalar path, and a lane whose Jacobi symbol has
//! not settled after the fixed batches (none in 40,000 sampled inputs) takes its group's Euler
//! exponentiation.
//!
//! Compiled only for `x86_64` with `std` (runtime detection of `avx512ifma`); every other target and a host
//! without the extension take the scalar path through [`crate::Element::from_bytes`].
#![allow(clippy::needless_range_loop)]
use ark_ec::twisted_edwards::TECurveConfig;
use ark_ed_on_bls12_381_bandersnatch::BandersnatchConfig;
use ark_ff::{BigInt, FftField, Field, One, PrimeField, Zero};
use core::arch::x86_64::*;
use std::sync::OnceLock;

pub(crate) type Fq = ark_ed_on_bls12_381_bandersnatch::Fq;
const MASK52: u64 = (1u64 << 52) - 1;
pub(crate) type L5 = [__m512i; 5];

/// Points per lane-decoded chunk: four interleaved groups of eight lanes, enough independent
/// multiplication chains to cover the IFMA latency.
pub(crate) const CHUNK: usize = 32;
const GROUPS: usize = CHUNK / 8;

/// Whether this host executes the lane path (`avx512f` + `avx512ifma`), detected once.
pub(crate) fn available() -> bool {
    static AVAILABLE: OnceLock<bool> = OnceLock::new();
    *AVAILABLE.get_or_init(|| {
        std::is_x86_feature_detected!("avx512f") && std::is_x86_feature_detected!("avx512ifma")
    })
}

pub(crate) fn context() -> &'static Ctx {
    static CTX: OnceLock<Ctx> = OnceLock::new();
    // SAFETY: callers check `available()` first; the context only broadcasts constants.
    CTX.get_or_init(|| unsafe { ctx() })
}

/// Lane chunks decoded together by [`decode_chunks`]: the parallel decode's task (four chunks, 128
/// points) shares one inversion exponentiation across its chunks.
pub(crate) const TASK_CHUNKS: usize = 4;

/// The decode of one chunk: `(x, y)` with positive `y` per point where the scalar path accepts, and the
/// lanes the vector path did not decide.
pub(crate) type ChunkDecode = ([Option<(Fq, Fq)>; CHUNK], [bool; CHUNK]);

/// Decodes up to [`TASK_CHUNKS`] chunks of `CHUNK` canonical `x` coordinates into `(x, y)` with
/// positive `y`, exactly where the scalar path accepts: `None` where no square root exists or the
/// subgroup check fails. Lanes whose denominator `d·x² − 1` is zero are reported undecided too; the
/// caller sends those to the scalar path so that its behavior (a division by zero) is preserved, but no
/// canonical `x` reaches them on Bandersnatch (`d` is a non-residue, so `1/d` has no root). The chunks'
/// inversions share one exponentiation.
///
/// # Safety
/// `available()` must have returned true on this host.
#[target_feature(enable = "avx512f,avx512ifma")]
pub(crate) unsafe fn decode_chunks(xs: &[[Fq; CHUNK]]) -> Vec<ChunkDecode> {
    decode_chunks_with(xs, JACOBI_BATCHES)
}

/// [`decode_chunks`] with the Jacobi batch count a parameter, so a test can force lanes through the
/// exponentiation fallback.
#[target_feature(enable = "avx512f,avx512ifma")]
unsafe fn decode_chunks_with(xs: &[[Fq; CHUNK]], jacobi_batches: usize) -> Vec<ChunkDecode> {
    assert!(!xs.is_empty() && xs.len() <= TASK_CHUNKS);
    let c = context();
    let a = BandersnatchConfig::COEFF_A;
    let d = BandersnatchConfig::COEFF_D;
    let n = xs.len();
    let mut den_zero = [[false; CHUNK]; TASK_CHUNKS];
    let mut nv = [[c.one; GROUPS]; TASK_CHUNKS];
    let mut dsafe = [c.one; GROUPS * TASK_CHUNKS];
    let mut qr_mask = [[0u8; GROUPS]; TASK_CHUNKS];
    for (k, chunk) in xs.iter().enumerate() {
        let mut e = [Fq::one(); CHUNK];
        let mut nn = [Fq::one(); CHUNK];
        let mut den = [Fq::one(); CHUNK];
        for i in 0..CHUNK {
            let x2 = chunk[i].square();
            nn[i] = a * x2 - Fq::one();
            den[i] = d * x2 - Fq::one();
            e[i] = Fq::one() - a * x2;
            den_zero[k][i] = den[i].is_zero();
        }
        let mut ev: [L5; GROUPS] = [c.one; GROUPS];
        for g in 0..GROUPS {
            ev[g] = load(c, e[g * 8..g * 8 + 8].try_into().unwrap());
            nv[k][g] = load(c, nn[g * 8..g * 8 + 8].try_into().unwrap());
            let dv = load(c, den[g * 8..g * 8 + 8].try_into().unwrap());
            // a zero denominator is set to one here and reported undecided below
            let mut zero: __mmask8 = 0;
            for j in 0..8 {
                if den_zero[k][g * 8 + j] {
                    zero |= 1 << j;
                }
            }
            dsafe[k * GROUPS + g] = sel(zero, &dv, &c.one);
        }
        // subgroup check: (1 - a x²) is a quadratic residue, its Jacobi symbol in lanes (two groups at
        // a time keep the divstep state in registers); a lane the divsteps leave unsettled takes its
        // group's Euler exponentiation, the same test as the scalar path's `legendre()`
        for pair in 0..GROUPS / 2 {
            let (res, dec) =
                jacobi_multi::<2>(c, &[ev[2 * pair], ev[2 * pair + 1]], jacobi_batches);
            for j in 0..2 {
                let g = 2 * pair + j;
                qr_mask[k][g] = res[j];
                if dec[j] != 0xff {
                    let leg = pow_multi::<1>(c, &[ev[g]], &c.modulus_minus_one_div_two);
                    qr_mask[k][g] = (res[j] & dec[j]) | (eq_one(c, &leg[0]) & !dec[j]);
                }
            }
        }
    }
    // y² = n / d: the task's inversions share one d^(p-2)
    let mut dinv = [c.one; GROUPS * TASK_CHUNKS];
    match n {
        1 => dinv[..GROUPS].copy_from_slice(&batch_inverse::<GROUPS>(
            c,
            dsafe[..GROUPS].try_into().unwrap(),
        )),
        2 => dinv[..2 * GROUPS].copy_from_slice(&batch_inverse::<{ 2 * GROUPS }>(
            c,
            dsafe[..2 * GROUPS].try_into().unwrap(),
        )),
        3 => dinv[..3 * GROUPS].copy_from_slice(&batch_inverse::<{ 3 * GROUPS }>(
            c,
            dsafe[..3 * GROUPS].try_into().unwrap(),
        )),
        _ => dinv = batch_inverse::<{ 4 * GROUPS }>(c, &dsafe),
    }
    let mut out = Vec::with_capacity(n);
    for (k, chunk) in xs.iter().enumerate() {
        let mut y2: [L5; GROUPS] = [c.one; GROUPS];
        for g in 0..GROUPS {
            y2[g] = mont_mul(c, &nv[k][g], &dinv[k * GROUPS + g]);
        }
        let (y, ok) = sqrt_dlog::<GROUPS>(c, &y2);
        let mut points = [None; CHUNK];
        for g in 0..GROUPS {
            let qr = qr_mask[k][g];
            let ys = store(c, &y[g]);
            for j in 0..8 {
                let i = g * 8 + j;
                let bit = 1u8 << j;
                if den_zero[k][i] || qr & bit == 0 || ok[g] & bit == 0 {
                    continue;
                }
                let mut yy = ys[j];
                if !crate::element::is_positive(yy) {
                    yy = -yy;
                }
                points[i] = Some((chunk[i], yy));
            }
        }
        out.push((points, den_zero[k]));
    }
    out
}

pub(crate) fn to_limbs52(b: &BigInt<4>) -> [u64; 5] {
    let w = b.0;
    let mut out = [0u64; 5];
    for i in 0..5 {
        let bit = 52 * i;
        let wi = bit / 64;
        let off = bit % 64;
        let mut v = w[wi] >> off;
        if off > 12 && wi + 1 < 4 {
            v |= w[wi + 1] << (64 - off);
        }
        out[i] = v & MASK52;
    }
    out
}
fn from_limbs52(l: &[u64; 5]) -> BigInt<4> {
    let mut w = [0u64; 4];
    for i in 0..5 {
        let bit = 52 * i;
        let wi = bit / 64;
        let off = bit % 64;
        w[wi] |= l[i] << off;
        if off > 12 && wi + 1 < 4 {
            w[wi + 1] |= l[i] >> (64 - off);
        }
    }
    BigInt(w)
}

pub(crate) struct Ctx {
    p: L5,
    n0: __m512i,
    pub(crate) mask: __m512i,
    pub(crate) one: L5,
    one_p: L5, // one + p: the other representative of 1 below 2p
    r2: [u64; 5],
    trace_minus_one_div_two: [u64; 4],
    modulus_minus_one_div_two: [u64; 4],
    pub(crate) modulus_minus_two: [u64; 4],
    /// The order-256 subgroup `⟨g^(2^24)⟩` (g the 2^32-th root of unity): the canonical Montgomery low
    /// limb of each element, sorted, and the exponent it belongs to.
    dlog_keys: [u64; 256],
    dlog_vals: [u64; 256],
    /// `g^(−j·2^(8i))` for window `i` in 0..4 and `j` in 0..256, lane limbs, entry `(i·256 + j)·5`.
    neg_pow: Vec<u64>,
}

// SAFETY: __m512i is plain data; the context is built once and only read afterwards.
unsafe impl Sync for Ctx {}
unsafe impl Send for Ctx {}

#[target_feature(enable = "avx512f,avx512ifma")]
unsafe fn ctx() -> Ctx {
    let p_scalar = to_limbs52(&Fq::MODULUS);
    let mut inv = p_scalar[0];
    for _ in 0..7 {
        inv = inv.wrapping_mul(2u64.wrapping_sub(p_scalar[0].wrapping_mul(inv)));
    }
    let n0 = (0u64.wrapping_sub(inv)) & MASK52;
    let two = Fq::from(2u64);
    let r = two.pow([260u64]).into_bigint();
    let r2 = two.pow([520u64]).into_bigint();
    let one_l = to_limbs52(&r);
    // one + p as 52-bit limbs
    let mut one_p_l = [0u64; 5];
    let mut carry = 0u64;
    for i in 0..5 {
        let s = one_l[i] + p_scalar[i] + carry;
        one_p_l[i] = s & MASK52;
        carry = s >> 52;
    }
    let mut p = [_mm512_setzero_si512(); 5];
    let mut one = [_mm512_setzero_si512(); 5];
    let mut one_p = [_mm512_setzero_si512(); 5];
    for i in 0..5 {
        p[i] = _mm512_set1_epi64(p_scalar[i] as i64);
        one[i] = _mm512_set1_epi64(one_l[i] as i64);
        one_p[i] = _mm512_set1_epi64(one_p_l[i] as i64);
    }
    let mut c = Ctx {
        p,
        n0: _mm512_set1_epi64(n0 as i64),
        mask: _mm512_set1_epi64(MASK52 as i64),
        one,
        one_p,
        r2: to_limbs52(&r2),
        trace_minus_one_div_two: Fq::TRACE_MINUS_ONE_DIV_TWO.0,
        modulus_minus_one_div_two: Fq::MODULUS_MINUS_ONE_DIV_TWO.0,
        modulus_minus_two: [0; 4],
        dlog_keys: [0; 256],
        dlog_vals: [0; 256],
        neg_pow: Vec::new(),
    };
    let mut pm2 = Fq::MODULUS;
    pm2.0[0] -= 2; // MODULUS is odd and > 2: no borrow
    c.modulus_minus_two = pm2.0;
    assert_eq!(
        Fq::TWO_ADICITY,
        32,
        "the 8-bit dlog windows assume p - 1 = 2^32 * t"
    );
    // the dlog table: g^(2^24) generates the order-256 subgroup
    let g = Fq::TWO_ADIC_ROOT_OF_UNITY;
    let g24 = g.pow([1u64 << 24]);
    let mut keyed: Vec<(u64, u64)> = Vec::with_capacity(256);
    let mut e = Fq::one();
    for j in 0..256u64 {
        keyed.push((canon_limb0(&c, &e), j));
        e *= g24;
    }
    keyed.sort_unstable();
    for w in keyed.windows(2) {
        assert!(w[0].0 != w[1].0, "two subgroup elements share a low limb");
    }
    for (i, (k, v)) in keyed.into_iter().enumerate() {
        c.dlog_keys[i] = k;
        c.dlog_vals[i] = v;
    }
    // g^(-j * 2^(8i))
    let g_inv = g.inverse().expect("root of unity is nonzero");
    let mut neg_pow = vec![0u64; 4 * 256 * 5];
    for i in 0..4 {
        let base = g_inv.pow([1u64 << (8 * i)]);
        let mut e = Fq::one();
        for j in 0..256 {
            let l = bcast_limbs(&e);
            neg_pow[(i * 256 + j) * 5..(i * 256 + j) * 5 + 5].copy_from_slice(&l);
            e *= base;
        }
    }
    c.neg_pow = neg_pow;
    c
}

/// The canonical Montgomery-form low limb of one element (the dlog table's key), through the lanes.
#[target_feature(enable = "avx512f,avx512ifma")]
unsafe fn canon_limb0(c: &Ctx, x: &Fq) -> u64 {
    let v = canon(c, &load(c, &[*x; 8]));
    let mut w = [0u64; 8];
    _mm512_storeu_si512(w.as_mut_ptr() as *mut _, v[0]);
    w[0]
}

#[inline]
#[target_feature(enable = "avx512f,avx512ifma")]
pub(crate) unsafe fn mont_mul(c: &Ctx, a: &L5, b: &L5) -> L5 {
    let zero = _mm512_setzero_si512();
    let mut t = [zero; 6];
    for i in 0..5 {
        let bi = b[i];
        for j in 0..5 {
            t[j] = _mm512_madd52lo_epu64(t[j], a[j], bi);
            t[j + 1] = _mm512_madd52hi_epu64(t[j + 1], a[j], bi);
        }
        let m = _mm512_madd52lo_epu64(zero, t[0], c.n0);
        for j in 0..5 {
            t[j] = _mm512_madd52lo_epu64(t[j], m, c.p[j]);
            t[j + 1] = _mm512_madd52hi_epu64(t[j + 1], m, c.p[j]);
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

/// Lane mask: which lanes of `a` (< 2p, normalized limbs) equal the field element one.
#[inline]
#[target_feature(enable = "avx512f,avx512ifma")]
unsafe fn eq_one(c: &Ctx, a: &L5) -> __mmask8 {
    let mut m1: __mmask8 = 0xff;
    let mut m2: __mmask8 = 0xff;
    for j in 0..5 {
        m1 &= _mm512_cmpeq_epi64_mask(a[j], c.one[j]);
        m2 &= _mm512_cmpeq_epi64_mask(a[j], c.one_p[j]);
    }
    m1 | m2
}

/// Lane mask: which lanes of `a` and `b` (both < 2p) are equal as field elements.
#[inline]
#[target_feature(enable = "avx512f,avx512ifma")]
unsafe fn eq_lanes(c: &Ctx, a: &L5, b: &L5) -> __mmask8 {
    // a - b ∈ (-2p, 2p); equal iff a == b or a == b ± p as integers. Compare the three cases limbwise
    // after canonicalizing both (subtract p where >= p): cheaper to canonicalize.
    let ca = canon(c, a);
    let cb = canon(c, b);
    let mut m: __mmask8 = 0xff;
    for j in 0..5 {
        m &= _mm512_cmpeq_epi64_mask(ca[j], cb[j]);
    }
    m
}

/// Canonical representative (< p) of a value < 2p.
#[inline]
#[target_feature(enable = "avx512f,avx512ifma")]
pub(crate) unsafe fn canon(c: &Ctx, a: &L5) -> L5 {
    // ge = a >= p, lexicographic from the top limb
    let mut ge: __mmask8 = 0;
    let mut decided: __mmask8 = 0;
    for j in (0..5).rev() {
        let gt = _mm512_cmpgt_epu64_mask(a[j], c.p[j]);
        let lt = _mm512_cmplt_epu64_mask(a[j], c.p[j]);
        ge |= gt & !decided;
        decided |= gt | lt;
    }
    ge |= !decided; // equal to p in every limb: a == p >= p
                    // subtract p with 52-bit borrows on the ge lanes
    let mut r = *a;
    let mut borrow = _mm512_setzero_si512();
    for j in 0..5 {
        let d = _mm512_sub_epi64(_mm512_sub_epi64(a[j], c.p[j]), borrow); // may wrap below zero
        borrow = _mm512_srli_epi64(d, 63); // 1 where the subtraction wrapped
        let fixed = _mm512_and_si512(d, c.mask); // wrapped values: d + 2^64 ≡ d + 2^52 mod 2^52 in the low 52 bits
        r[j] = _mm512_mask_blend_epi64(ge, a[j], fixed);
    }
    r
}

#[inline]
#[target_feature(enable = "avx512f,avx512ifma")]
pub(crate) unsafe fn sel(m: __mmask8, a: &L5, b: &L5) -> L5 {
    // lanes with the mask bit set take b, others a
    let mut r = *a;
    for j in 0..5 {
        r[j] = _mm512_mask_blend_epi64(m, a[j], b[j]);
    }
    r
}

/// Divsteps per Jacobi batch: a batch's transition entries are at most 2^JACOBI_K, and the IFMA
/// multiplier takes 52-bit inputs.
const JACOBI_K: u32 = 51;
/// Batches the lane Jacobi runs before an unsettled lane is handed to the exponentiation: 22 × 51 =
/// 1,122 positive divsteps. On uniformly random inputs the symbol settles after 750 steps on average
/// and within 867 (17 batches) on every one of 40,000 sampled; small integers and powers of two, as
/// Montgomery representatives, take up to 21 batches. The batch loop leaves early once every lane
/// has settled, so the cap is paid only by a chunk carrying such an input.
const JACOBI_BATCHES: usize = 22;

/// The Legendre symbol of `G` groups of eight lanes (Montgomery form, < 2p): the lanes whose value is
/// a nonzero quadratic residue, and the lanes the algorithm settled (a zero input settles as a
/// non-residue, the scalar path's `legendre().is_qr()`).
///
/// Positive divsteps on `(f, g)` from `(p, x)`, as libsecp256k1's `jacobi64_maybe_var` runs them, one
/// bit per step so that every lane executes the same stream: with `g` odd and `η < 0`, `(f, g)` are
/// swapped and `η` negated (the symbol flips when both are 3 mod 4); with `g` odd, `g += f`; then
/// `g /= 2` and `η −= 1` (the symbol flips when `f` is 3 or 5 mod 8). `JACOBI_K` steps are taken on the
/// low 64-bit words alone, accumulating the 2×2 transition `(u, v; q, r)`, and the batch is applied to
/// the full values as `(u·f + v·g, q·f + r·g) / 2^K` (exact; the values never grow, so they stay
/// below `p` and non-negative). A lane whose `f` reached 1 at a batch boundary has its symbol
/// `(g | 1) = 1` times the tracked sign; the Montgomery factor `R = 2^260` is an even power of two and
/// does not move the symbol.
#[target_feature(enable = "avx512f,avx512ifma")]
pub(crate) unsafe fn jacobi_multi<const G: usize>(
    c: &Ctx,
    x: &[L5; G],
    batches: usize,
) -> ([__mmask8; G], [__mmask8; G]) {
    let zero = _mm512_setzero_si512();
    let one = _mm512_set1_epi64(1);
    let ones = _mm512_set1_epi64(-1);
    let mut f = [c.p; G];
    let mut g = [c.one; G];
    let mut zero_in = [0u8; G];
    for i in 0..G {
        g[i] = canon(c, &x[i]);
        zero_in[i] = is_zero(&g[i]);
    }
    let mut eta = [ones; G];
    let mut jac = [zero; G];
    let mut decided = zero_in;
    let mut residue = [0u8; G];
    // the field's one (x = 0: the identity commitment, common in a witness) is a residue outright;
    // as a Montgomery representative it is one of the slowest inputs to settle
    for i in 0..G {
        let one_in = eq_one(c, &x[i]);
        residue[i] |= one_in;
        decided[i] |= one_in;
    }
    for _ in 0..batches {
        let mut f0 = [zero; G];
        let mut g0 = [zero; G];
        let mut u = [one; G];
        let mut v = [zero; G];
        let mut q = [zero; G];
        let mut r = [one; G];
        for i in 0..G {
            f0[i] = _mm512_or_si512(f[i][0], _mm512_slli_epi64(f[i][1], 52));
            g0[i] = _mm512_or_si512(g[i][0], _mm512_slli_epi64(g[i][1], 52));
        }
        for _ in 0..JACOBI_K {
            for i in 0..G {
                let odd = _mm512_test_epi64_mask(g0[i], one);
                let neg = _mm512_cmplt_epi64_mask(eta[i], zero);
                let swap = odd & neg;
                // the swap's reciprocity sign: both f and g are 3 mod 4
                let t = _mm512_srli_epi64(_mm512_and_si512(f0[i], g0[i]), 1);
                jac[i] = _mm512_mask_xor_epi64(jac[i], swap, jac[i], t);
                // g += f where g is odd (with the transition's row)
                g0[i] = _mm512_mask_add_epi64(g0[i], odd, g0[i], f0[i]);
                q[i] = _mm512_mask_add_epi64(q[i], odd, q[i], u[i]);
                r[i] = _mm512_mask_add_epi64(r[i], odd, r[i], v[i]);
                // the swap: the new f is the old g, i.e. the summed g minus the old f (rows likewise)
                f0[i] = _mm512_mask_sub_epi64(f0[i], swap, g0[i], f0[i]);
                u[i] = _mm512_mask_sub_epi64(u[i], swap, q[i], u[i]);
                v[i] = _mm512_mask_sub_epi64(v[i], swap, r[i], v[i]);
                // η: −η − 1 = !η on a swap, η − 1 otherwise
                let e1 = _mm512_sub_epi64(eta[i], one);
                eta[i] = _mm512_mask_xor_epi64(e1, swap, eta[i], ones);
                // the halving's sign: f is 3 or 5 mod 8
                let h = _mm512_xor_si512(_mm512_srli_epi64(f0[i], 1), _mm512_srli_epi64(f0[i], 2));
                jac[i] = _mm512_xor_si512(jac[i], h);
                g0[i] = _mm512_srli_epi64(g0[i], 1);
                u[i] = _mm512_slli_epi64(u[i], 1);
                v[i] = _mm512_slli_epi64(v[i], 1);
            }
        }
        let mut all: __mmask8 = 0xff;
        for i in 0..G {
            let nf = combine_shift(c, &f[i], &g[i], u[i], v[i]);
            let ng = combine_shift(c, &f[i], &g[i], q[i], r[i]);
            f[i] = nf;
            g[i] = ng;
            let mut is_one = _mm512_cmpeq_epi64_mask(f[i][0], one);
            for j in 1..5 {
                is_one &= _mm512_cmpeq_epi64_mask(f[i][j], zero);
            }
            let newly = is_one & !decided[i];
            residue[i] |= newly & _mm512_testn_epi64_mask(jac[i], one);
            decided[i] |= newly;
            all &= decided[i];
        }
        if all == 0xff {
            break;
        }
    }
    (residue, decided)
}

/// `(a·f + b·g) >> JACOBI_K` for normalized five-limb `f, g` and `a, b < 2^52`, exact when the low
/// `JACOBI_K` bits of the sum are zero (a divstep batch's transition); the result's limbs normalized.
#[inline]
#[target_feature(enable = "avx512f,avx512ifma")]
unsafe fn combine_shift(c: &Ctx, f: &L5, g: &L5, a: __m512i, b: __m512i) -> L5 {
    let zero = _mm512_setzero_si512();
    let mut t = [zero; 6];
    let mut hi_prev = zero;
    for j in 0..5 {
        let lo = _mm512_madd52lo_epu64(_mm512_madd52lo_epu64(zero, a, f[j]), b, g[j]);
        let hi = _mm512_madd52hi_epu64(_mm512_madd52hi_epu64(zero, a, f[j]), b, g[j]);
        t[j] = _mm512_add_epi64(lo, hi_prev);
        hi_prev = hi;
    }
    t[5] = hi_prev;
    let mut carry = zero;
    for j in 0..6 {
        let s = _mm512_add_epi64(t[j], carry);
        t[j] = _mm512_and_si512(s, c.mask);
        carry = _mm512_srli_epi64(s, 52);
    }
    let mut out = [zero; 5];
    for j in 0..5 {
        out[j] = _mm512_and_si512(
            _mm512_or_si512(
                _mm512_srli_epi64(t[j], JACOBI_K),
                _mm512_slli_epi64(t[j + 1], 52 - JACOBI_K),
            ),
            c.mask,
        );
    }
    out
}

/// x^e on all lanes, one exponent, 4-bit fixed window, `G` independent groups interleaved for ILP.
#[target_feature(enable = "avx512f,avx512ifma")]
pub(crate) unsafe fn pow_multi<const G: usize>(c: &Ctx, x: &[L5; G], e: &[u64; 4]) -> [L5; G] {
    let mut table = [[c.one; 16]; G];
    for g in 0..G {
        table[g][1] = x[g];
    }
    for i in 2..16 {
        for g in 0..G {
            table[g][i] = mont_mul(c, &table[g][i - 1], &x[g]);
        }
    }
    let mut acc = [c.one; G];
    let mut started = false;
    for w in (0..64).rev() {
        let d = ((e[w / 16] >> ((w % 16) * 4)) & 0xf) as usize;
        if started {
            for _ in 0..4 {
                for g in 0..G {
                    acc[g] = mont_mul(c, &acc[g], &acc[g]);
                }
            }
        }
        if d != 0 {
            for g in 0..G {
                acc[g] = mont_mul(c, &acc[g], &table[g][d]);
            }
            started = true;
        }
    }
    acc
}

/// The inverses of `G` groups of eight nonzero lanes with one exponentiation: prefix products across the
/// groups, `d^(p-2)` of the last, back-substitution (Montgomery's trick; 3(G−1) products + one
/// exponentiation instead of G).
#[target_feature(enable = "avx512f,avx512ifma")]
pub(crate) unsafe fn batch_inverse<const G: usize>(c: &Ctx, d: &[L5; G]) -> [L5; G] {
    let mut prefix = *d;
    for g in 1..G {
        prefix[g] = mont_mul(c, &prefix[g - 1], &d[g]);
    }
    let mut inv = pow_multi::<1>(c, &[prefix[G - 1]], &c.modulus_minus_two)[0];
    let mut out = [c.one; G];
    for g in (1..G).rev() {
        out[g] = mont_mul(c, &inv, &prefix[g - 1]);
        inv = mont_mul(c, &inv, &d[g]);
    }
    out[0] = inv;
    out
}

/// `log_{g^(2^24)}` of eight elements of the order-256 subgroup (binary search over the sorted canonical
/// low limbs): the exponents, and the lanes whose element was found.
#[inline]
#[target_feature(enable = "avx512f,avx512ifma")]
unsafe fn dlog256(c: &Ctx, b: &L5) -> (__m512i, __mmask8) {
    let key = canon(c, b)[0];
    let keys = c.dlog_keys.as_ptr();
    let mut lo = _mm512_setzero_si512();
    let mut step = 128i64;
    while step > 0 {
        let probe = _mm512_add_epi64(lo, _mm512_set1_epi64(step));
        let k = _mm512_i64gather_epi64::<8>(probe, keys as *const _);
        let le = _mm512_cmple_epu64_mask(k, key);
        lo = _mm512_mask_blend_epi64(le, lo, probe);
        step >>= 1;
    }
    let k = _mm512_i64gather_epi64::<8>(lo, keys as *const _);
    let found = _mm512_cmpeq_epi64_mask(k, key);
    let j = _mm512_i64gather_epi64::<8>(lo, c.dlog_vals.as_ptr() as *const _);
    (j, found)
}

/// `g^(−j·2^(8i))` for eight `j` (window `i`), gathered from the table.
#[inline]
#[target_feature(enable = "avx512f,avx512ifma")]
unsafe fn neg_pow_gather(c: &Ctx, i: usize, j: __m512i) -> L5 {
    let e = _mm512_add_epi64(j, _mm512_set1_epi64((i * 256) as i64));
    let idx = _mm512_add_epi64(_mm512_slli_epi64(e, 2), e); // 5 qwords per entry
    let base = c.neg_pow.as_ptr();
    let mut r = [_mm512_setzero_si512(); 5];
    for l in 0..5 {
        r[l] = _mm512_i64gather_epi64::<8>(idx, base.add(l) as *const _);
    }
    r
}

/// Square roots of `G` groups of eight lanes by the 2-adic discrete logarithm: returns the candidate
/// roots and, per group, the mask of lanes whose candidate squares back to the input (the residues).
/// Per group: one `(t−1)/2` exponentiation, 48 squarings, seven table products, four table lookups.
#[target_feature(enable = "avx512f,avx512ifma")]
unsafe fn sqrt_dlog<const G: usize>(c: &Ctx, a: &[L5; G]) -> ([L5; G], [__mmask8; G]) {
    let w = pow_multi::<G>(c, a, &c.trace_minus_one_div_two);
    let mut x = [c.one; G]; // w·a: the root up to a 2-power root of unity
    let mut b = [c.one; G]; // a^t = w²·a, in the order-2^32 subgroup
    for g in 0..G {
        x[g] = mont_mul(c, &w[g], &a[g]);
        b[g] = mont_mul(c, &x[g], &w[g]);
    }
    // k = log_g(b) in four 8-bit windows from the low end: b^(2^(24−8i)) lies in the order-256 subgroup
    // once the lower windows are divided out
    let mut k = [_mm512_setzero_si512(); G];
    let mut found = [0xffu8; G];
    for i in 0..4 {
        let mut t = b;
        for _ in 0..(24 - 8 * i) {
            for g in 0..G {
                t[g] = mont_mul(c, &t[g], &t[g]);
            }
        }
        for g in 0..G {
            let (j, f) = dlog256(c, &t[g]);
            found[g] &= f;
            k[g] = _mm512_or_si512(
                k[g],
                _mm512_sllv_epi64(j, _mm512_set1_epi64((8 * i) as i64)),
            );
            if i < 3 {
                b[g] = mont_mul(c, &b[g], &neg_pow_gather(c, i, j));
            }
        }
    }
    // a residue iff k is even; then √a = w·a·g^(−k/2)
    let mut ok = [0u8; G];
    for g in 0..G {
        let even = _mm512_testn_epi64_mask(k[g], _mm512_set1_epi64(1));
        let half = _mm512_srli_epi64(k[g], 1);
        let byte = _mm512_set1_epi64(0xff);
        for i in 0..4 {
            let j = _mm512_and_si512(
                _mm512_srlv_epi64(half, _mm512_set1_epi64((8 * i) as i64)),
                byte,
            );
            x[g] = mont_mul(c, &x[g], &neg_pow_gather(c, i, j));
        }
        let sq = mont_mul(c, &x[g], &x[g]);
        ok[g] = even & found[g] & eq_lanes(c, &sq, &a[g]);
    }
    (x, ok)
}

#[target_feature(enable = "avx512f,avx512ifma")]
pub(crate) unsafe fn load(c: &Ctx, xs: &[Fq; 8]) -> L5 {
    let mut limbs = [[0u64; 8]; 5];
    for (k, x) in xs.iter().enumerate() {
        let l = to_limbs52(&x.into_bigint());
        for i in 0..5 {
            limbs[i][k] = l[i];
        }
    }
    let mut v = [_mm512_setzero_si512(); 5];
    let mut r2 = [_mm512_setzero_si512(); 5];
    for i in 0..5 {
        v[i] = _mm512_loadu_si512(limbs[i].as_ptr() as *const _);
        r2[i] = _mm512_set1_epi64(c.r2[i] as i64);
    }
    mont_mul(c, &v, &r2)
}

#[target_feature(enable = "avx512f,avx512ifma")]
pub(crate) unsafe fn store(c: &Ctx, v: &L5) -> [Fq; 8] {
    let mut one_int = [_mm512_setzero_si512(); 5];
    one_int[0] = _mm512_set1_epi64(1);
    let r = canon(c, &mont_mul(c, v, &one_int)); // out of Montgomery form, canonical
    let mut limbs = [[0u64; 8]; 5];
    for i in 0..5 {
        _mm512_storeu_si512(limbs[i].as_mut_ptr() as *mut _, r[i]);
    }
    let mut out = [Fq::zero(); 8];
    for k in 0..8 {
        let mut l = [0u64; 5];
        for i in 0..5 {
            l[i] = limbs[i][k];
        }
        out[k] = Fq::from_bigint(from_limbs52(&l)).expect("canonical");
    }
    out
}

/// Lane mask: which lanes of canonical `a` are zero.
#[inline]
#[target_feature(enable = "avx512f,avx512ifma")]
pub(crate) unsafe fn is_zero(a: &L5) -> __mmask8 {
    let zero = _mm512_setzero_si512();
    let mut m: __mmask8 = 0xff;
    for j in 0..5 {
        m &= _mm512_cmpeq_epi64_mask(a[j], zero);
    }
    m
}

/// A field element (ark Montgomery form, R = 2^256) as the lane form's limbs (R = 2^260): the lane
/// integer is x·2^260 mod p = the ark representation of 16·x.
pub(crate) fn bcast_limbs(x: &Fq) -> [u64; 5] {
    let x16 = *x * Fq::from(16u64);
    to_limbs52(&x16.0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_ff::{LegendreSymbol, UniformRand};
    use rand_chacha::rand_core::SeedableRng;

    /// The lane symbol of every input, through groups of sixteen: `Some(is a nonzero residue)` where
    /// the lane settled, `None` where it did not.
    unsafe fn lane_symbols(xs: &[Fq]) -> Vec<Option<bool>> {
        let c = context();
        let mut out = Vec::with_capacity(xs.len());
        for chunk in xs.chunks(16) {
            let mut padded = [Fq::one(); 16];
            padded[..chunk.len()].copy_from_slice(chunk);
            let a = load(c, padded[..8].try_into().unwrap());
            let b = load(c, padded[8..].try_into().unwrap());
            let (res, dec) = jacobi_multi::<2>(c, &[a, b], JACOBI_BATCHES);
            for k in 0..chunk.len() {
                let bit = 1u8 << (k % 8);
                out.push((dec[k / 8] & bit != 0).then_some(res[k / 8] & bit != 0));
            }
        }
        out
    }

    /// `jacobi_multi` agrees with ark's `legendre()` (`is_qr`: a nonzero residue) on zero, one, −1,
    /// small integers, powers of two, squares, non-residues and random elements; every random input
    /// settles, and the few structured ones that do not are the fallback's.
    #[test]
    fn jacobi_matches_legendre() {
        if !available() {
            return;
        }
        let mut rng = rand_chacha::ChaCha20Rng::seed_from_u64(23);
        let mut xs: Vec<Fq> = vec![Fq::zero(), Fq::one(), -Fq::one(), Fq::from(2u64)];
        for k in 0..64u64 {
            xs.push(Fq::from(k + 3));
            xs.push(Fq::from(2u64).pow([k * 4 + 1]));
            xs.push(-Fq::from(k + 3));
        }
        let nr = (1..100u64)
            .map(Fq::from)
            .find(|v| v.legendre() == LegendreSymbol::QuadraticNonResidue)
            .unwrap();
        for _ in 0..2000 {
            let r = Fq::rand(&mut rng);
            xs.push(r);
            xs.push(r.square());
            xs.push(r.square() * nr);
        }
        let structured = xs.len() - 6000;
        let want: Vec<bool> = xs.iter().map(|x| x.legendre().is_qr()).collect();
        let got = unsafe { lane_symbols(&xs) };
        let mut unsettled = 0;
        for (i, (g, w)) in got.iter().zip(&want).enumerate() {
            match g {
                Some(q) => assert_eq!(q, w, "input {i}"),
                None => {
                    assert!(i < structured, "random input {i} did not settle");
                    unsettled += 1;
                }
            }
        }
        assert!(
            unsettled <= structured / 8,
            "{unsettled} unsettled of {structured}"
        );
        assert!(want.iter().filter(|q| **q).count() > 2000);
        assert!(want.iter().filter(|q| !**q).count() > 2000);
    }

    /// The decode with the Jacobi lanes forced unsettled (no batches, then too few for most lanes)
    /// equals the decode at the full count: the exponentiation fallback decides the same lanes.
    #[test]
    fn decode_fallback_matches_settled_decode() {
        if !available() {
            return;
        }
        use ark_ec::CurveGroup;
        let mut rng = rand_chacha::ChaCha20Rng::seed_from_u64(29);
        for round in 0..4 {
            let mut xs = [[Fq::zero(); CHUNK]; TASK_CHUNKS];
            for (i, x) in xs.iter_mut().flatten().enumerate() {
                *x = if (i + round) % 3 == 0 {
                    (crate::Element::prime_subgroup_generator() * crate::Fr::rand(&mut rng))
                        .0
                        .into_affine()
                        .x
                } else {
                    Fq::rand(&mut rng)
                };
            }
            // every task length shares one inversion; each equals the settled decode
            for n in 1..=TASK_CHUNKS {
                let full = unsafe { decode_chunks_with(&xs[..n], JACOBI_BATCHES) };
                assert_eq!(full.len(), n);
                for batches in [0usize, 14] {
                    let forced = unsafe { decode_chunks_with(&xs[..n], batches) };
                    for k in 0..n {
                        assert_eq!(forced[k].1, full[k].1);
                        for i in 0..CHUNK {
                            assert_eq!(
                                forced[k].0[i], full[k].0[i],
                                "point {i} at {batches} batches"
                            );
                        }
                    }
                }
                let single: Vec<ChunkDecode> = (0..n)
                    .map(|k| unsafe { decode_chunks_with(&xs[k..k + 1], JACOBI_BATCHES) }[0])
                    .collect();
                assert_eq!(
                    single, full,
                    "the shared inversion equals the per-chunk one"
                );
                assert!(full[0].0.iter().filter(|p| p.is_some()).count() >= CHUNK / 3);
            }
        }
    }

    /// Cost of the subgroup check per point: the lane Jacobi against the lane exponentiation it
    /// replaces (run with `--ignored --nocapture`).
    #[test]
    #[ignore]
    fn bench_jacobi() {
        if !available() {
            return;
        }
        let mut rng = rand_chacha::ChaCha20Rng::seed_from_u64(31);
        let c = context();
        let n = 4096;
        let xs: Vec<Fq> = (0..n).map(|_| Fq::rand(&mut rng)).collect();
        let lanes: Vec<L5> = xs
            .chunks(8)
            .map(|ch| unsafe { load(c, ch.try_into().unwrap()) })
            .collect();
        for rep in 0..3 {
            let t = std::time::Instant::now();
            let mut acc = 0u32;
            for pair in lanes.chunks(2) {
                let (res, dec) =
                    unsafe { jacobi_multi::<2>(c, &[pair[0], pair[1]], JACOBI_BATCHES) };
                acc += (res[0] & dec[0]).count_ones() + (res[1] & dec[1]).count_ones();
                assert_eq!(dec, [0xff, 0xff], "a random input did not settle");
            }
            let jac2_ns = t.elapsed().as_nanos() as f64 / n as f64;
            let t = std::time::Instant::now();
            let mut acc4 = 0u32;
            for quad in lanes.chunks(4) {
                let (res, dec) = unsafe {
                    jacobi_multi::<4>(c, &[quad[0], quad[1], quad[2], quad[3]], JACOBI_BATCHES)
                };
                for k in 0..4 {
                    acc4 += (res[k] & dec[k]).count_ones();
                }
            }
            let jac4_ns = t.elapsed().as_nanos() as f64 / n as f64;
            let t = std::time::Instant::now();
            let mut acc_e = 0u32;
            for quad in lanes.chunks(4) {
                let leg = unsafe {
                    pow_multi::<4>(
                        c,
                        &[quad[0], quad[1], quad[2], quad[3]],
                        &c.modulus_minus_one_div_two,
                    )
                };
                for l in &leg {
                    acc_e += unsafe { eq_one(c, l) }.count_ones();
                }
            }
            let euler_ns = t.elapsed().as_nanos() as f64 / n as f64;
            assert_eq!(acc, acc_e);
            assert_eq!(acc4, acc_e);
            println!(
                "jacobi rep {rep}: {n} points, one thread: euler exponentiation {euler_ns:.0} ns/point, lane jacobi G=2 {jac2_ns:.0} ns/point (x{:.2}), G=4 {jac4_ns:.0} ns/point (x{:.2}); residues {acc}",
                euler_ns / jac2_ns,
                euler_ns / jac4_ns
            );
        }
    }
}
