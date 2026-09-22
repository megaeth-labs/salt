use crate::Element;
use ark_ec::scalar_mul::wnaf::WnafContext;
use ark_ed_on_bls12_381_bandersnatch::{EdwardsAffine, EdwardsProjective, Fr};
use ark_ff::{AdditiveGroup, PrimeField, Zero};
use core::cmp::Ordering;

use salt_macros::prelude::*;
use salt_macros::{into_iter, iter};
use std::{vec, vec::Vec};

/// Window-parallel Pippenger multi-scalar multiplication over affine bases.
///
/// Mirrors the signed-digit bucket algorithm of arkworks' `msm_bigint_wnaf`,
/// but converts scalars and builds the digit matrix serially: at the MSM
/// sizes SALT handles (tens to a few thousand points), the parallel
/// conversion collects inside arkworks cost more in thread-pool traffic than
/// the entire digit pass. Windows are processed in parallel only when each
/// carries enough work to pay for the dispatch.
pub(crate) fn msm_windowed(bases: &[EdwardsAffine], scalars: &[Fr]) -> EdwardsProjective {
    let size = bases.len();
    let c = if size < 32 {
        3
    } else {
        // ln_without_floats: log2(size) * ln(2), plus 2
        (usize::BITS - (size - 1).leading_zeros()) as usize * 69 / 100 + 2
    };
    msm_windowed_with_c(bases, scalars, c)
}

/// [`msm_windowed`] with the window width given, so the tests can exercise every
/// width — and with it every bucket-count branch of [`bucket_len`] — at a size
/// that keeps a debug-mode run cheap.
fn msm_windowed_with_c(bases: &[EdwardsAffine], scalars: &[Fr], c: usize) -> EdwardsProjective {
    debug_assert_eq!(bases.len(), scalars.len());
    let size = bases.len();
    if size == 0 {
        return EdwardsProjective::zero();
    }

    let num_bits = <Fr as PrimeField>::MODULUS_BIT_SIZE as usize;
    let digits_count = num_bits.div_ceil(c);

    // Digit matrix: scalar `i` owns scalar_digits[i * digits_count..][..digits_count].
    let mut scalar_digits = vec![0i64; size * digits_count];
    for (scalar, digits) in scalars
        .iter()
        .zip(scalar_digits.chunks_exact_mut(digits_count))
    {
        make_digits(&scalar.into_bigint().0, c, digits);
    }

    let window_sum = |window: usize| -> EdwardsProjective {
        let mut buckets =
            vec![EdwardsProjective::zero(); bucket_len(c, num_bits, digits_count, window)];
        for (digits, base) in scalar_digits.chunks_exact(digits_count).zip(bases) {
            let digit = digits[window];
            match 0.cmp(&digit) {
                Ordering::Less => buckets[(digit - 1) as usize] += base,
                Ordering::Greater => buckets[(-digit - 1) as usize] -= base,
                Ordering::Equal => (),
            }
        }

        let mut running_sum = EdwardsProjective::zero();
        let mut res = EdwardsProjective::zero();
        buckets.into_iter().rev().for_each(|b| {
            running_sum += &b;
            res += &running_sum;
        });
        res
    };

    // Below this size the per-window work is too small to farm out.
    const MIN_PARALLEL_SIZE: usize = 64;
    let window_sums: Vec<EdwardsProjective> = if size >= MIN_PARALLEL_SIZE {
        into_iter!(0..digits_count).map(window_sum).collect()
    } else {
        (0..digits_count).map(window_sum).collect()
    };

    // Traverse windows from high to low, doubling `c` times between windows.
    let lowest = *window_sums.first().expect("digits_count >= 1");
    lowest
        + window_sums[1..]
            .iter()
            .rev()
            .fold(EdwardsProjective::zero(), |mut total, sum_i| {
                total += sum_i;
                for _ in 0..c {
                    total.double_in_place();
                }
                total
            })
}

/// Buckets one window of [`msm_windowed_with_c`] needs, which is half of the
/// window's `2^c` digit values for every window but the last.
///
/// [`make_digits`] recenters each digit to `[-2^(c-1), 2^(c-1) - 1]`, so a
/// bucket index `|digit| - 1` stays below `2^(c-1)` — the upper half of a
/// `2^c` array is never written, and reducing over it costs one full point
/// addition per empty bucket. The last window is the exception: it absorbs the
/// outstanding carry instead of being recentered, so its digits run
/// `0..=2^last_bits`, where `last_bits` is what the modulus leaves for it.
/// `last_bits == c` when `c` divides the modulus width (c = 11 and c = 23 at
/// 253 bits), and then the last window does need all `2^c` buckets.
fn bucket_len(c: usize, num_bits: usize, digits_count: usize, window: usize) -> usize {
    if window == digits_count - 1 {
        1 << (num_bits - (digits_count - 1) * c)
    } else {
        1 << (c - 1)
    }
}

/// Decomposes a scalar into signed `w`-bit digits in `[-2^(w-1), 2^(w-1)]`,
/// written into `digits`. Identical digit semantics to arkworks'
/// `make_digits` (the final digit absorbs the outstanding carry).
fn make_digits(scalar: &[u64], w: usize, digits: &mut [i64]) {
    let radix: u64 = 1 << w;
    let window_mask: u64 = radix - 1;

    let mut carry = 0u64;
    let digits_count = digits.len();
    for (i, digit_out) in digits.iter_mut().enumerate() {
        // Construct a buffer of bits of the scalar, starting at `bit_offset`.
        let bit_offset = i * w;
        let u64_idx = bit_offset / 64;
        let bit_idx = bit_offset % 64;
        // Read the bits from the scalar
        let bit_buf = if bit_idx < 64 - w || u64_idx == scalar.len() - 1 {
            // This window's bits are contained in a single u64,
            // or it's the last u64 anyway.
            scalar[u64_idx] >> bit_idx
        } else {
            // Combine the current u64's bits with the bits from the next u64
            (scalar[u64_idx] >> bit_idx) | (scalar[1 + u64_idx] << (64 - bit_idx))
        };

        // Read the actual coefficient value from the window
        let coef = carry + (bit_buf & window_mask); // coef = [0, 2^w)

        // Recenter coefficients from [0,2^w) to [-2^w/2, 2^w/2)
        carry = (coef + radix / 2) >> w;
        let mut digit = (coef as i64) - (carry << w) as i64;

        if i == digits_count - 1 {
            digit += (carry << w) as i64;
        }
        *digit_out = digit;
    }
}

#[derive(Clone, Debug)]
pub struct MSMPrecompWnaf {
    window_size: usize,
    tables: Vec<Vec<EdwardsProjective>>,
}

impl MSMPrecompWnaf {
    pub fn new(bases: &[Element], window_size: usize) -> MSMPrecompWnaf {
        let wnaf_context = WnafContext::new(window_size);
        let mut tables = Vec::with_capacity(bases.len());

        for base in bases {
            tables.push(wnaf_context.table(base.0));
        }

        MSMPrecompWnaf {
            tables,
            window_size,
        }
    }

    pub fn mul_index(&self, scalar: Fr, index: usize) -> Element {
        let wnaf_context = WnafContext::new(self.window_size);
        Element(
            wnaf_context
                .mul_with_table(&self.tables[index], &scalar)
                .unwrap(),
        )
    }

    pub fn mul(&self, scalars: &[Fr]) -> Element {
        let wnaf_context = WnafContext::new(self.window_size);
        let result: EdwardsProjective = scalars
            .iter()
            .zip(self.tables.iter())
            .filter(|(scalar, _)| !scalar.is_zero())
            .map(|(scalar, table)| wnaf_context.mul_with_table(table, scalar).unwrap())
            .sum();

        Element(result)
    }
    // TODO: This requires more benchmarking and feedback to see if we should
    // TODO put this behind a config flag
    pub fn mul_par(&self, scalars: &[Fr]) -> Element {
        let wnaf_context = WnafContext::new(self.window_size);
        let result: EdwardsProjective = iter!(scalars)
            .zip(iter!(&self.tables))
            .filter(|(scalar, _)| !scalar.is_zero())
            .map(|(scalar, table)| wnaf_context.mul_with_table(table, scalar).unwrap())
            .sum();

        Element(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{multi_scalar_mul, Element};
    use std::vec;

    /// `size` random affine points and scalars, with the edge cases `0`, `r - 1` (which
    /// maximizes the last window's digit, the one the last bucket count has to cover) and `1`
    /// patched into the first scalars.
    fn msm_input(seed: u8, size: usize) -> (Vec<EdwardsAffine>, Vec<Fr>) {
        use ark_ec::CurveGroup;
        use ark_ff::UniformRand;
        use rand_chacha::rand_core::SeedableRng;
        use rand_chacha::ChaCha20Rng;

        let mut rng = ChaCha20Rng::from_seed([seed; 32]);
        let bases_proj: Vec<EdwardsProjective> = (0..size)
            .map(|_| EdwardsProjective::rand(&mut rng))
            .collect();
        let bases = EdwardsProjective::normalize_batch(&bases_proj);
        let mut scalars: Vec<Fr> = (0..size).map(|_| Fr::rand(&mut rng)).collect();
        for (scalar, edge) in scalars
            .iter_mut()
            .zip([Fr::zero(), -Fr::from(1u64), Fr::from(1u64)])
        {
            *scalar = edge;
        }
        (bases, scalars)
    }

    /// The hand-rolled windowed MSM must agree with arkworks' generic MSM for
    /// every size class (serial windows, parallel windows, small-c) and for
    /// edge-case scalars.
    #[test]
    fn msm_windowed_matches_arkworks() {
        use ark_ec::VariableBaseMSM;

        for size in [1usize, 2, 16, 31, 32, 33, 129, 256, 1000] {
            let (bases, scalars) = msm_input(9, size);
            let expected = EdwardsProjective::msm(&bases, &scalars).unwrap();
            let got = msm_windowed(&bases, &scalars);
            assert_eq!(got, expected, "size {size}");
        }

        // Empty input yields the identity.
        assert!(msm_windowed(&[], &[]).is_zero());
    }

    /// Every window width must agree with arkworks, not only the ones the size
    /// heuristic happens to pick: [`bucket_len`] sizes the last window from the
    /// bits the modulus leaves it, and `c = 11` — the width chosen for 8,193 to
    /// 16,384 points — is the one where that is the full `2^c`.
    #[test]
    fn msm_windowed_matches_arkworks_for_every_window_width() {
        use ark_ec::VariableBaseMSM;

        let (bases, scalars) = msm_input(21, 200);
        let expected = EdwardsProjective::msm(&bases, &scalars).unwrap();
        for c in 3..=13 {
            assert_eq!(
                msm_windowed_with_c(&bases, &scalars, c),
                expected,
                "c = {c}"
            );
        }
    }

    /// The bucket counts [`bucket_len`] hands out must cover every digit
    /// [`make_digits`] can produce: a bucket index is `|digit| - 1`, so every
    /// window needs `|digit| <= bucket_len`.
    #[test]
    fn make_digits_stays_within_the_bucket_counts() {
        use ark_ff::UniformRand;
        use rand_chacha::rand_core::SeedableRng;
        use rand_chacha::ChaCha20Rng;

        let mut rng = ChaCha20Rng::from_seed([7u8; 32]);
        let num_bits = <Fr as PrimeField>::MODULUS_BIT_SIZE as usize;
        let mut scalars: Vec<Fr> = (0..64).map(|_| Fr::rand(&mut rng)).collect();
        scalars.extend([Fr::zero(), Fr::from(1u64), -Fr::from(1u64)]);

        for c in 3..=16 {
            let digits_count = num_bits.div_ceil(c);
            let mut digits = vec![0i64; digits_count];
            for scalar in &scalars {
                make_digits(&scalar.into_bigint().0, c, &mut digits);
                for (window, &digit) in digits.iter().enumerate() {
                    let len = bucket_len(c, num_bits, digits_count, window) as i64;
                    assert!(
                        digit.abs() <= len,
                        "c = {c}, window {window}: digit {digit} needs more than {len} buckets"
                    );
                    if window == digits_count - 1 {
                        assert!(digit >= 0, "c = {c}: the last digit absorbs the carry");
                    }
                }
            }
        }
    }

    #[test]
    fn correctness_smoke_test() {
        let mut crs = Vec::with_capacity(256);
        for i in 0..256 {
            crs.push(Element::prime_subgroup_generator() * Fr::from((i + 1) as u64));
        }

        let mut scalars = vec![];
        for i in 0..256 {
            scalars.push(-Fr::from(i + 1));
        }

        let result = multi_scalar_mul(&crs, &scalars);

        let precomp = MSMPrecompWnaf::new(&crs, 12);
        let got_result = precomp.mul(&scalars);
        let got_par_result = precomp.mul_par(&scalars);

        assert_eq!(result, got_result);
        assert_eq!(result, got_par_result);
    }
}
