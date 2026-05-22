use crate::curve_ops::PrecompTableConfig;
use crate::Element;
use crate::Fr;
use ark_ed_on_bls12_381_bandersnatch::{EdwardsAffine, EdwardsProjective, Fq};
use ark_ec::{CurveGroup, ScalarMul, VariableBaseMSM};
use ark_ff::{BigInteger, PrimeField};
use ark_ff::Zero;
use std::ops::Neg;

#[inline(always)]
pub(crate) fn projective_zero() -> EdwardsProjective {
    EdwardsProjective::default()
}

#[inline]
pub fn add(lhs: &Element, rhs: &Element) -> Element {
    Element(lhs.0 + rhs.0)
}

pub(crate) fn add_affine_point(result: &mut EdwardsProjective, p2_x: &Fq, p2_y: &Fq) {
    use ark_ff::biginteger::BigInt;

    let mut a = result.x * p2_x;
    let b = result.y * p2_y;
    let mut c = p2_x * p2_y;
    let mut d = result.t * c;

    c = d * Fq::new_unchecked(BigInt::new([
        12167860994669987632u64,
        4043113551995129031u64,
        6052647550941614584u64,
        3904213385886034240u64,
    ]));

    d = (result.x + result.y) * (p2_x + p2_y);
    let e = d - a - b;
    let f = result.z - c;
    let g = result.z + c;
    a *= Fq::from(5u64);
    let h = b + a;

    result.x = e * f;
    result.y = g * h;
    result.t = e * h;
    result.z = f * g;
}

pub(crate) fn batch_proj_to_affine(elements: &[EdwardsProjective]) -> Vec<EdwardsAffine> {
    let commitments = Element::batch_to_commitments(
        &elements
            .iter()
            .map(|element| Element(*element))
            .collect::<Vec<Element>>(),
    );
    commitments
        .iter()
        .map(|bytes| EdwardsAffine {
            x: Fq::from_le_bytes_mod_order(&bytes[0..32]),
            y: Fq::from_le_bytes_mod_order(&bytes[32..64]),
        })
        .collect()
}

pub(crate) fn build_precomp_table(
    base: &Element,
    config: &PrecompTableConfig,
) -> Vec<EdwardsAffine> {
    let mut table = Vec::with_capacity(config.inner_length);
    let mut element = base.0;

    for _ in 0..config.win_num {
        let base = element;
        table.push(EdwardsProjective::zero());
        table.push(element);
        for _ in 1..(1 << (config.window_size - 1)) {
            element += &base;
            table.push(element);
        }
        element += element;
    }

    EdwardsProjective::normalize_batch(&table)
}

pub fn scalar_mul(base: &Element, scalar: &Fr) -> Element {
    let mut result = Element::zero();
    let mut temp = *base;
    let scalar_bigint = scalar.into_bigint();
    let scalar_bits = scalar_bigint.to_bytes_le();

    for (byte_index, &byte) in scalar_bits.iter().enumerate() {
        for bit_index in 0..8 {
            let bit_position = byte_index * 8 + bit_index;
            if bit_position >= 256 {
                break;
            }

            if (byte >> bit_index) & 1 != 0 {
                result = result + temp;
            }

            if bit_position < 255 {
                temp = temp + temp;
            }
        }
    }

    result
}

#[inline]
pub fn sub(lhs: &Element, rhs: &Element) -> Element {
    Element(lhs.0 - rhs.0)
}

#[inline]
pub fn neg(element: &Element) -> Element {
    Element(-element.0)
}

pub fn multi_scalar_mul(bases: &[Element], scalars: &[Fr]) -> Element {
    let bases_inner: Vec<_> = bases.iter().map(|element| element.0).collect();

    let bases = EdwardsProjective::batch_convert_to_mul_base(&bases_inner);

    let result =
        EdwardsProjective::msm(&bases, scalars).expect("number of bases should equal number of scalars");

    Element(result)
}

pub(crate) fn msm_bigint_wnaf(bases: &[Element], scalars: &[Fr]) -> Element {
    let size = core::cmp::min(bases.len(), scalars.len());
    let scalars = &scalars[..size];
    let bases = &bases[..size];

    let bigints: Vec<_> = scalars.iter().map(|s| s.into_bigint()).collect();

    let c = if size < 32 {
        3
    } else {
        ln_without_floats(size) + 2
    };

    let num_bits = Fr::MODULUS_BIT_SIZE as usize;
    let digits_count = num_bits.div_ceil(c);

    let scalar_digits = bigints
        .iter()
        .flat_map(|b| make_digits(b, c, num_bits))
        .collect::<Vec<_>>();

    let zero = Element::zero();

    let window_sums: Vec<_> = (0..digits_count)
        .into_iter()
        .map(|i| {
            let mut buckets = vec![zero; 1 << c];

            for (digits, base) in scalar_digits.chunks(digits_count).zip(bases) {
                let d = digits[i];
                if d > 0 {
                    buckets[(d - 1) as usize] += *base;
                } else if d < 0 {
                    buckets[(-d - 1) as usize] += base.neg();
                }
            }

            let mut running_sum = Element::zero();
            let mut res = Element::zero();
            for b in buckets.into_iter().rev() {
                running_sum += b;
                res += running_sum;
            }
            res
        })
        .collect();

    let lowest = *window_sums.first().unwrap();

    lowest
        + window_sums[1..]
            .iter()
            .rev()
            .fold(Element::zero(), |mut total, sum_i| {
                total += *sum_i;
                for _ in 0..c {
                    total = Element(total.0 + total.0);
                }
                total
            })
}

#[inline]
fn ln_without_floats(n: usize) -> usize {
    usize::BITS as usize - 1 - n.leading_zeros() as usize
}

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

        let coef = carry + (bit_buf & window_mask);
        carry = (coef + radix / 2) >> w;

        let mut digit = (coef as i64) - (carry << w) as i64;
        if i == digits_count - 1 {
            digit += (carry << w) as i64;
        }
        digit
    })
}
