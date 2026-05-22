use crate::curve_ops::PrecompTableConfig;
use ark_ed_on_bls12_381_bandersnatch::{EdwardsAffine, EdwardsProjective, Fq};
use crate::zkvm_riscv32_primitives::{
    add_projective, from_bigint_to_mont, from_mont_to_bigint, mod_add, mod_mul_by5_u32_zkvm,
    mod_mul_u32_zkvm, mod_mul_zkvm, mod_sub, msm_bigint_wnaf_zkvm, scalar_mul_zkvm,
    u32_array_to_u64_array_le, u64_array_to_u32_array_le,
};
use crate::{Element, Fr};
use ark_ff::{Field, Zero};

#[inline(always)]
pub(crate) fn projective_zero() -> EdwardsProjective {
    let mut zero = EdwardsProjective::zero();
    zero.y = Fq::zero();
    zero.z = Fq::zero();
    zero.y.0 .0[0] = 1;
    zero.z.0 .0[0] = 1;
    zero
}

#[inline]
pub fn add(lhs: &Element, rhs: &Element) -> Element {
    let mut result = lhs.0;
    add_projective(&mut result, &rhs.0);
    Element(result)
}

pub(crate) fn add_affine_point(result: &mut EdwardsProjective, p2x: &Fq, p2y: &Fq) {
    let mut result_x = u64_array_to_u32_array_le(&result.x.0 .0);
    let mut result_y = u64_array_to_u32_array_le(&result.y.0 .0);
    let mut result_t = u64_array_to_u32_array_le(&result.t.0 .0);
    let mut result_z = u64_array_to_u32_array_le(&result.z.0 .0);
    let p2_x = u64_array_to_u32_array_le(&p2x.0 .0);
    let p2_y = u64_array_to_u32_array_le(&p2y.0 .0);

    let mut a = [0u32; 8];
    let mut b = [0u32; 8];
    let mut c = [0u32; 8];
    let mut d = [0u32; 8];
    mod_mul_u32_zkvm(&mut a, &result_x, &p2_x);
    mod_mul_u32_zkvm(&mut b, &result_y, &p2_y);
    mod_mul_u32_zkvm(&mut c, &p2_x, &p2_y);
    mod_mul_u32_zkvm(&mut d, &result_t, &c);

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
    mod_add(&result_x, &result_y, &mut x_add_y);
    mod_add(&p2_x, &p2_y, &mut p2x_add_p2y);

    mod_mul_u32_zkvm(&mut d, &x_add_y, &p2x_add_p2y);

    let mut e1 = [0u32; 8];
    mod_sub(&d, &a, &mut e1);
    let mut e = [0u32; 8];
    mod_sub(&e1, &b, &mut e);
    let mut f = [0u32; 8];
    mod_sub(&result_z, &c, &mut f);
    let mut g = [0u32; 8];
    mod_add(&result_z, &c, &mut g);

    mod_mul_by5_u32_zkvm(&mut a);
    let mut h = [0u32; 8];
    mod_add(&b, &a, &mut h);

    mod_mul_u32_zkvm(&mut result_x, &e, &f);
    mod_mul_u32_zkvm(&mut result_y, &g, &h);
    mod_mul_u32_zkvm(&mut result_t, &e, &h);
    mod_mul_u32_zkvm(&mut result_z, &f, &g);

    u32_array_to_u64_array_le(&result_x, &mut result.x.0 .0);
    u32_array_to_u64_array_le(&result_y, &mut result.y.0 .0);
    u32_array_to_u64_array_le(&result_t, &mut result.t.0 .0);
    u32_array_to_u64_array_le(&result_z, &mut result.z.0 .0);
}

pub(crate) fn batch_proj_to_affine(elements: &[EdwardsProjective]) -> Vec<EdwardsAffine> {
    let mut zeroes = vec![false; elements.len()];

    let mut zs_mul = Fq::zero();
    zs_mul.0 .0[0] = 1;

    let mut result: Vec<EdwardsAffine> = (0..elements.len())
        .into_iter()
        .map(|i| {
            if elements[i].z.is_zero() {
                zeroes[i] = true;
                return EdwardsAffine::default();
            }

            let r = EdwardsAffine {
                x: zs_mul,
                y: Fq::default(),
            };

            let zs_mul_clone = zs_mul.clone();
            mod_mul_zkvm(&mut zs_mul.0 .0, &zs_mul_clone.0 .0, &elements[i].z.0 .0);
            r
        })
        .collect();

    let zs_mul_clone = zs_mul.clone();
    from_bigint_to_mont(&mut zs_mul.0 .0, &zs_mul_clone.0 .0);
    let mut zs_inv = zs_mul.inverse().expect("zs_mul is not zero");
    let zs_inv_clone = zs_inv.clone();
    from_mont_to_bigint(&mut zs_inv.0 .0, &zs_inv_clone.0 .0);

    for i in (0..elements.len()).rev() {
        if zeroes[i] {
            continue;
        }
        let temp = result[i].x.0 .0;
        mod_mul_zkvm(&mut result[i].x.0 .0, &temp, &zs_inv.0 .0);
        let temp = zs_inv.0 .0;
        mod_mul_zkvm(&mut zs_inv.0 .0, &temp, &elements[i].z.0 .0);
    }

    elements
        .iter()
        .zip(result.iter_mut())
        .zip(zeroes.iter())
        .for_each(|((element, res), &is_zero)| {
            if is_zero {
                return;
            }

            let z_inv = res.x;
            mod_mul_zkvm(&mut res.x.0 .0, &element.x.0 .0, &z_inv.0 .0);
            mod_mul_zkvm(&mut res.y.0 .0, &element.y.0 .0, &z_inv.0 .0);
        });

    result
}

pub(crate) fn build_precomp_table(
    base: &Element,
    config: &PrecompTableConfig,
) -> Vec<EdwardsAffine> {
    let mut table = Vec::with_capacity(config.inner_length);
    let mut element = base.0;
    from_mont_to_bigint(&mut element.x.0 .0, &base.0.x.0 .0);
    from_mont_to_bigint(&mut element.y.0 .0, &base.0.y.0 .0);
    from_mont_to_bigint(&mut element.t.0 .0, &base.0.t.0 .0);
    from_mont_to_bigint(&mut element.z.0 .0, &base.0.z.0 .0);

    for _ in 0..config.win_num {
        let base = element;
        table.push(projective_zero());
        table.push(element);
        for _ in 1..(1 << (config.window_size - 1)) {
            add_projective(&mut element, &base);
            table.push(element);
        }
        let element_copy = element;
        add_projective(&mut element, &element_copy);
    }

    batch_proj_to_affine(&table)
}

pub fn scalar_mul(base: &Element, scalar: &Fr) -> Element {
    scalar_mul_zkvm(base, scalar)
}

#[inline]
pub fn sub(lhs: &Element, rhs: &Element) -> Element {
    let mut result = lhs.0;
    let neg_rhs = neg(rhs).0;
    add_projective(&mut result, &neg_rhs);
    Element(result)
}

#[inline]
pub fn neg(element: &Element) -> Element {
    Element(-element.0)
}

pub fn multi_scalar_mul(bases: &[Element], scalars: &[Fr]) -> Element {
    msm_bigint_wnaf_zkvm(bases, scalars)
}

pub(crate) fn msm_bigint_wnaf(bases: &[Element], scalars: &[Fr]) -> Element {
    msm_bigint_wnaf_zkvm(bases, scalars)
}

#[cfg(all(test, feature = "zkvm-riscv32-sim"))]
mod tests {
    use super::*;
    use crate::zkvm_riscv32_primitives::{from_bigint_to_mont, from_mont_to_bigint};
    use ark_ec::CurveGroup;

    fn projective_mont_to_bigint(point: &EdwardsProjective) -> EdwardsProjective {
        let mut result = *point;

        let x = point.x.0 .0;
        let y = point.y.0 .0;
        let t = point.t.0 .0;
        let z = point.z.0 .0;

        from_mont_to_bigint(&mut result.x.0 .0, &x);
        from_mont_to_bigint(&mut result.y.0 .0, &y);
        from_mont_to_bigint(&mut result.t.0 .0, &t);
        from_mont_to_bigint(&mut result.z.0 .0, &z);

        result
    }

    fn affine_bigint_to_mont(point: &EdwardsAffine) -> EdwardsAffine {
        let mut result = *point;

        let x = point.x.0 .0;
        let y = point.y.0 .0;

        from_bigint_to_mont(&mut result.x.0 .0, &x);
        from_bigint_to_mont(&mut result.y.0 .0, &y);

        result
    }

    fn affine_mont_to_bigint(point: &EdwardsAffine) -> EdwardsAffine {
        let mut result = *point;

        let x = point.x.0 .0;
        let y = point.y.0 .0;

        from_mont_to_bigint(&mut result.x.0 .0, &x);
        from_mont_to_bigint(&mut result.y.0 .0, &y);

        result
    }

    fn projective_bigint_to_mont(point: &EdwardsProjective) -> EdwardsProjective {
        let mut result = *point;

        let x = point.x.0 .0;
        let y = point.y.0 .0;
        let t = point.t.0 .0;
        let z = point.z.0 .0;

        from_bigint_to_mont(&mut result.x.0 .0, &x);
        from_bigint_to_mont(&mut result.y.0 .0, &y);
        from_bigint_to_mont(&mut result.t.0 .0, &t);
        from_bigint_to_mont(&mut result.z.0 .0, &z);

        result
    }

    #[test]
    fn add_affine_point_matches_reference_after_roundtrip() {
        let generator = Element::prime_subgroup_generator();
        let lhs_mont = (generator * Fr::from(3u64)).0;
        let rhs_mont = EdwardsProjective::normalize_batch(&[(generator * Fr::from(5u64)).0])[0];

        let mut lhs_bigint = projective_mont_to_bigint(&lhs_mont);
        let rhs_bigint = affine_mont_to_bigint(&rhs_mont);

        add_affine_point(&mut lhs_bigint, &rhs_bigint.x, &rhs_bigint.y);

        let got = projective_bigint_to_mont(&lhs_bigint);
        let expected = lhs_mont + rhs_mont;

        assert_eq!(got, expected);
    }

    #[test]
    fn bigint_and_mont_serialization_match() {
        let mont = Element::prime_subgroup_generator() * Fr::from(11u64);
        let bigint = Element(projective_mont_to_bigint(&mont.0));

        assert_eq!(bigint.to_bytes(), mont.to_bytes());
        assert_eq!(bigint.to_bytes_uncompressed(), mont.to_bytes_uncompressed());
    }

    #[test]
    fn bigint_and_mont_addition_serialization_match() {
        let lhs_mont = Element::prime_subgroup_generator() * Fr::from(11u64);
        let rhs_mont = Element::prime_subgroup_generator() * Fr::from(19u64);

        let mut lhs_bigint = projective_mont_to_bigint(&lhs_mont.0);
        let rhs_bigint = projective_mont_to_bigint(&rhs_mont.0);
        add_projective(&mut lhs_bigint, &rhs_bigint);
        let sum_bigint = Element(lhs_bigint);

        let sum_mont = lhs_mont + rhs_mont;

        assert_eq!(sum_bigint.to_bytes(), sum_mont.to_bytes());
        assert_eq!(
            sum_bigint.to_bytes_uncompressed(),
            sum_mont.to_bytes_uncompressed()
        );
    }

    #[test]
    fn bigint_element_add_matches_mont_reference_serialization() {
        let lhs_mont = Element::prime_subgroup_generator() * Fr::from(11u64);
        let rhs_mont = Element::prime_subgroup_generator() * Fr::from(19u64);

        let lhs_bigint = Element(projective_mont_to_bigint(&lhs_mont.0));
        let rhs_bigint = Element(projective_mont_to_bigint(&rhs_mont.0));

        let got = lhs_bigint + rhs_bigint;
        let expected = lhs_mont + rhs_mont;
        let got_mont = projective_bigint_to_mont(&got.0);
        let got_affine = got_mont.into_affine();
        let expected_affine = expected.0.into_affine();

        assert_ne!(got.0.x, expected.0.x);
        assert_ne!(got.0.y, expected.0.y);
        assert_ne!(got.0.z, expected.0.z);
        assert_ne!(got.0.t, expected.0.t);
        assert_eq!(got.to_bytes(), expected.to_bytes());
        assert_eq!(got.to_bytes_uncompressed(), expected.to_bytes_uncompressed());
        assert_eq!(got_affine.x, expected_affine.x);
        assert_eq!(got_affine.y, expected_affine.y);
    }

    #[test]
    fn batch_proj_to_affine_matches_normalize_batch_after_roundtrip() {
        let generator = Element::prime_subgroup_generator();
        let mont_points = vec![
            (generator * Fr::from(1u64)).0,
            (generator * Fr::from(2u64)).0,
            (generator * Fr::from(7u64)).0,
        ];
        let bigint_points = mont_points
            .iter()
            .map(projective_mont_to_bigint)
            .collect::<Vec<_>>();

        let got = batch_proj_to_affine(&bigint_points)
            .iter()
            .map(affine_bigint_to_mont)
            .collect::<Vec<_>>();
        let expected = EdwardsProjective::normalize_batch(&mont_points);

        assert_eq!(got, expected);
    }

    #[test]
    fn build_precomp_table_matches_reference_after_roundtrip() {
        let generator = Element::prime_subgroup_generator();
        let config = PrecompTableConfig {
            window_size: 4,
            win_num: 253 / 4 + 1,
            inner_length: (253 / 4 + 1) * (1 << (4 - 1)) + (253 / 4 + 1),
        };

        let got = build_precomp_table(&generator, &config)
            .iter()
            .map(affine_bigint_to_mont)
            .collect::<Vec<_>>();

        let mut table = Vec::with_capacity(config.inner_length);
        let mut element = generator.0;
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
        let expected = EdwardsProjective::normalize_batch(&table);

        assert_eq!(got, expected);
    }
}
