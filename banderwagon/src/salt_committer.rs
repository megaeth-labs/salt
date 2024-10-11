//! Provides MSM calculation module
//!

use crate::element::Element;
use ark_ec::CurveConfig;
use ark_ed_on_bls12_381_bandersnatch::{
    BandersnatchConfig, EdwardsAffine, EdwardsProjective, Fq, Fr,
};
use ark_ff::PrimeField;
use ark_ff::{Field, Zero};
use ark_serialize::CanonicalSerialize;
use rayon::prelude::*;
use hugepage_rs::{alloc, dealloc};
use std::alloc::Layout;


///MSM calculation for a fixed G points
#[derive(Clone, Debug)]
pub struct Committer {
    ///Window size for WNAF
    window_size: usize,
    ///Accelerate MSM by precomputing the table
    tables: Vec<Vec<EdwardsAffine>>,
}

impl Drop for Committer {
    fn drop(&mut self) {
        // drop inner vectors
        for table in self.tables.iter_mut() {
            let ptr = table.as_mut_ptr() as *mut u8;
            let cap = table.capacity();
            let layout = Layout::array::<EdwardsAffine>(cap).unwrap();
            std::mem::forget(std::mem::replace(table, Vec::new()));
            hugepage_rs::dealloc(ptr, layout);
        }

        // drop the outer vector
        let ptr = self.tables.as_mut_ptr() as *mut u8;
        let cap = self.tables.capacity();
        let layout = Layout::array::<Vec<EdwardsAffine>>(cap).unwrap();
        std::mem::forget(std::mem::replace(&mut self.tables, Vec::new()));
        hugepage_rs::dealloc(ptr, layout);
    }
}

impl Committer {
    pub fn new(bases: &[Element], window_size: usize) -> Committer {
        let table_num = bases.len();
        let win_num = 253 / window_size + 1;  // 253 is the bit length of Fr
        let inner_length = win_num * (1 << (window_size - 1));

        let src_tables: Vec<Vec<EdwardsAffine>> = bases.par_iter().map(|base| {
            let mut table = Vec::with_capacity(inner_length);
            let mut element = base.0;
            // Calculate the element values for each window
            for _ in 0..win_num {
                let base = element;
                table.push(EdwardsProjective::zero());
                table.push(element);
                for _i in 1..(1 << (window_size - 1)) {
                    element += &base;
                    table.push(element);
                }
                element += element;
            }
            Element::batch_proj_to_affine(&table)
        }).collect();

        let layout = Layout::array::<Vec<EdwardsAffine>>(table_num).unwrap();
        let tables_ptr = hugepage_rs::alloc(layout) as *mut Vec<EdwardsAffine>;
        if tables_ptr.is_null() {
            panic!("failed to allocate tables");
        }

        for i in 0..src_tables.len() {
            let src_ptr = src_tables[i].as_ptr();
            let layout = Layout::array::<EdwardsAffine>(inner_length).unwrap();
            let dst_ptr = hugepage_rs::alloc(layout) as *mut EdwardsAffine;
            if dst_ptr.is_null() {
                panic!("Failed: allocating huge page for precomputed table");
            }
            assert!(
                src_ptr.align_offset(std::mem::align_of::<EdwardsAffine>()) == 0,
                "Source pointer is not aligned"
            );
            assert!(
                dst_ptr.align_offset(std::mem::align_of::<EdwardsAffine>()) == 0,
                "Destination pointer is not aligned"
            );
            unsafe {
                std::ptr::copy_nonoverlapping(src_ptr, dst_ptr, inner_length);
                *tables_ptr.add(i) = Vec::from_raw_parts(dst_ptr, inner_length, inner_length);
            }
        }

        let tables = unsafe { Vec::from_raw_parts(tables_ptr, table_num, table_num) };

        Committer {
            tables,
            window_size,
        }
    }

    /// This is the identity element of the group
    pub fn zero() -> [u8; 64] {
        [
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0,
        ]
    }

    /// Calculate the new commitment after applying the deltas
    /// return old_c + (new_bytes[0] - old_bytes[0]) * G[tbi[0]] + ... + (new_bytes[n] - old_bytes[n]) * G[tbi[n]]
    pub fn add_deltas(
        &self,
        old_commitment: [u8; 64],
        delta_indices: &[(usize, [u8; 32], [u8; 32])],
    ) -> Element {
        let mut old = Element::from_bytes_unchecked_uncompressed(old_commitment);
        delta_indices
            .iter()
            .for_each(|(tb_i, old_bytes, new_bytes)| {
                let old_fr = Fr::from_le_bytes_mod_order(old_bytes);
                let new_fr = Fr::from_le_bytes_mod_order(new_bytes);
                old += self.mul_index(&(new_fr - old_fr), *tb_i)
            });
        old
    }

    /// scalar a fixed G[i] point
    fn mul_index(&self, scalar: &Fr, g_i: usize) -> Element {
        let chunks = calculate_prefetch_index(scalar, self.window_size);
        let mut carry = 0;
        let half_win = 1 << (self.window_size - 1);
        let mut result = EdwardsProjective::default();
        let precom_table = &self.tables[g_i];
        let mut ponits = Vec::with_capacity(chunks.len());

        for i in 0..chunks.len() {
            let mut index = (chunks[i] + carry) as usize;
            if index == 0 {
                continue;
            }

            carry = 0;
            // precom_table Stores half of the window values, from 1 to half_size
            // If index = 0, no calculation is needed, skip directly
            // If index <= half_win, take the value directly
            // If index > half_win, calculate the negative value of -G[win-index], then carry = 1
            if index > half_win {
                index = (1 << self.window_size) - index;
                if index != 0 {
                    let neg_point = EdwardsAffine {
                        x: -precom_table[index + i * (half_win + 1)].x,
                        y: precom_table[index + i * (half_win + 1)].y,
                    };
                    ponits.push(neg_point);
                }
                carry = 1;
            } else {
                ponits.push(precom_table[index + i * (half_win + 1)].clone());
            }
        }

        ponits.iter().for_each(|p| add_affine_point(&mut result, p));
        Element(result)
    }

    /// returns G[i] * (new_bytes - old_bytes)
    pub fn gi_mul_delta(&self, old_bytes: &[u8; 32], new_bytes: &[u8; 32], g_i: usize) -> Element {
        let old_fr = Fr::from_le_bytes_mod_order(old_bytes);
        let new_fr = Fr::from_le_bytes_mod_order(new_bytes);
        self.mul_index(&(new_fr - old_fr), g_i)
    }

}

#[cfg(not(target_arch = "x86_64"))]
fn add_affine_point(result: &mut EdwardsProjective, p2: &EdwardsAffine) {
    use ark_ff::biginteger::BigInt;

    let mut a = result.x * p2.x;
    let b = result.y * p2.y;
    let mut c = p2.x * p2.y;
    let mut d = result.t * c;

    c = d * Fq::new_unchecked(BigInt::new([
        12167860994669987632u64,
        4043113551995129031u64,
        6052647550941614584u64,
        3904213385886034240u64,
    ]));

    d = (result.x + result.y) * (p2.x + p2.y);
    let e = d - a - b;
    let f = result.z - c;
    let g = result.z + c;
    a = a * Fq::from(5u64);
    let h = b + a;

    result.x = e * f;
    result.y = g * h;
    result.t = e * h;
    result.z = f * g;
}

/// Optimized affine point addition for x86_64
#[cfg(target_arch = "x86_64")]
fn add_affine_point(result: &mut EdwardsProjective, p2: &EdwardsAffine) {
    use crate::scalar_multi_asm::*;

    let mut a = Fq::default();
    let mut b = Fq::default();
    let mut c = Fq::default();
    let mut d = Fq::default();

    mont_mul_asm(&mut a.0 .0, &result.x.0 .0, &p2.x.0 .0);
    mont_mul_asm(&mut b.0 .0, &result.y.0 .0, &p2.y.0 .0);
    mont_mul_asm(&mut c.0 .0, &p2.x.0 .0, &p2.y.0 .0);
    mont_mul_asm(&mut d.0 .0, &result.t.0 .0, &c.0 .0);

    mont_mul_asm(
        &mut c.0 .0,
        &d.0 .0,
        &[
            12167860994669987632u64,
            4043113551995129031u64,
            6052647550941614584u64,
            3904213385886034240u64,
        ],
    );
    mont_mul_asm(
        &mut d.0 .0,
        &(result.x + result.y).0 .0,
        &(p2.x + p2.y).0 .0,
    );
    let e = d - a - b;
    let f = result.z - c;
    let g = result.z + c;
    mont_mul_by5_asm(&mut a.0 .0);
    let h = b + a;
    mont_mul_asm(&mut result.x.0 .0, &e.0 .0, &f.0 .0);
    mont_mul_asm(&mut result.y.0 .0, &g.0 .0, &h.0 .0);
    mont_mul_asm(&mut result.t.0 .0, &e.0 .0, &h.0 .0);
    mont_mul_asm(&mut result.z.0 .0, &f.0 .0, &g.0 .0);
}

/// Calculate the corresponding data index in the
/// precomputed table through the scalar
#[inline]
fn calculate_prefetch_index(scalar: &Fr, w: usize) -> Vec<u64> {
    // Convert scalar from Montgomery form to big integer
    let source_vec = scalar.into_bigint().0;
    let mut index_vec = vec![];

    // Extract w bits of data from a scalar of n bits length
    for start_bit in (0..64 * source_vec.len()).step_by(w) {
        let source_i = start_bit >> 6;
        let offset_in_i = start_bit & 63;

        let mut d = (source_vec[source_i] >> offset_in_i) & ((1 << w) - 1);
        // If the data is not enough, take the remaining data from the next
        if offset_in_i + w > 64 && source_i < source_vec.len() - 1 {
            let left = w - (64 - offset_in_i);
            d |= (source_vec[source_i + 1] & ((1 << left) - 1)) << (64 - offset_in_i);
        };

        index_vec.push(d)
    }

    index_vec
}

impl Element {
    /// Batch conversion from EdwardsProjective to EdwardsAffine
    #[inline]
    pub(crate) fn batch_proj_to_affine(elements: &[EdwardsProjective]) -> Vec<EdwardsAffine> {
        let mut zeroes = vec![false; elements.len()];
        let mut zs_mul = <BandersnatchConfig as CurveConfig>::BaseField::ONE;

        // zs_mul = z0 * z1 * ... * zn
        // result[i] = z0 * z1 * ... * zi-1
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

                zs_mul *= &elements[i].z;

                r
            })
            .collect();

        // zs_inv = 1 / zs_mul
        let mut zs_inv = zs_mul.inverse().expect("zs_mul is not zero");

        // result[i] = (z0 * z1 * ... * zi-1)/(z0 * z1 * ... * zi) = 1/zi
        for i in (0..elements.len()).rev() {
            if zeroes[i] {
                continue;
            }
            result[i].x = result[i].x * &zs_inv;
            zs_inv = zs_inv * &elements[i].z;
        }

        // result[i].x = xi / zi, result[i].y = xi / zi
        elements
            .into_iter()
            .zip(result.iter_mut())
            .zip(zeroes.iter())
            .for_each(|((element, res), &is_zero)| {
                if is_zero {
                    return;
                }

                let z_inv = res.x;
                res.x = &element.x * &z_inv;
                res.y = &element.y * &z_inv;
            });

        result
    }

    /// Batch conversion from Element to CommitmentBytes
    #[inline]
    pub fn batch_elements_to_commitments(elements: &[Element]) -> Vec<[u8; 64]> {
        let mut bytes = vec![[0 as u8; 64]; elements.len()];
        let mut zi_mul = vec![Fq::ZERO; elements.len()];
        let mut zeroes = vec![false; elements.len()];
        let mut zs_mul = Fq::ONE;

        //zs_mul = 1*z1*z2*z3....zn
        //zi_mul[i] = 1*z1...zi-1
        elements.iter().enumerate().for_each(|(i, element)| {
            if element.0.z.is_zero() {
                zeroes[i] = true;
                return;
            }
            zi_mul[i] = zs_mul;
            zs_mul = zs_mul * &element.0.z;
        });

        // zs_inv = 1/zs_mul
        let mut zs_inv = zs_mul.inverse().expect("zs_mul is not zero");

        for i in (0..elements.len()).rev().step_by(1) {
            if zeroes[i] {
                let _ = Fq::ONE.serialize_uncompressed(&mut bytes[i][32..64]);
                continue;
            }
            // z_inv = 1/zi
            let z_inv = zi_mul[i] * &zs_inv;
            zs_inv = zs_inv * &elements[i].0.z;

            let _ = (elements[i].0.x * &z_inv).serialize_uncompressed(&mut bytes[i][0..32]);
            let _ = (elements[i].0.y * &z_inv).serialize_uncompressed(&mut bytes[i][32..64]);
        }
        bytes
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{element::Element, multi_scalar_mul};
    use ark_ec::CurveGroup;
    use ark_ed_on_bls12_381_bandersnatch::Fr;
    use ark_ff::UniformRand;
    use rand_chacha::rand_core::SeedableRng;
    use rand_chacha::ChaCha20Rng;
    use std::str::FromStr;

    #[test]
    fn batch_elements_to_hash_commitments() {
        let a_vec = vec![
            (Element::prime_subgroup_generator() * Fr::from(3333)),
            (Element::prime_subgroup_generator() * Fr::from(4444)),
        ];

        let hash_bytes = Element::batch_elements_to_commitments(&a_vec);

        for i in 0..a_vec.len() {
            let mut bytes = [0 as u8; 64];
            let x = a_vec[i].0.x * &a_vec[i].0.z.inverse().unwrap();
            let y = a_vec[i].0.y * &a_vec[i].0.z.inverse().unwrap();
            let _ = x.serialize_uncompressed(&mut bytes[0..32]);
            let _ = y.serialize_uncompressed(&mut bytes[32..64]);
            assert_eq!(bytes, hash_bytes[i]);
        }
    }

    #[test]
    fn batch_proj_to_affine() {
        let a_vec = vec![
            (Element::prime_subgroup_generator() * Fr::from(1)).0,
            (Element::prime_subgroup_generator() * Fr::from(2)).0,
        ];

        let es = Element::batch_proj_to_affine(&a_vec);

        for i in 0..a_vec.len() {
            assert_eq!(es[i].y, a_vec[i].y / a_vec[i].z);
            assert_eq!(es[i].x, a_vec[i].x / a_vec[i].z);
        }
    }

    #[test]
    fn mul_index() {
        let mut crs = Vec::with_capacity(256);
        for i in 0..256 {
            crs.push(Element::prime_subgroup_generator() * Fr::from((i + 1) as u64));
        }

        let mut scalars = vec![];
        for i in 0..256 {
            scalars.push(-Fr::from(i + 1));
        }

        let result = multi_scalar_mul(&crs, &scalars);

        let extend_precomp = Committer::new(&crs, 11);
        let mut got_result = Element::zero();
        scalars.iter().enumerate().for_each(|(i, scalar)| {
            got_result += extend_precomp.mul_index(scalar, i);
        });

        assert_eq!(got_result, result);
    }
    #[test]
    fn correctness_for_debug() {
        // Create a vector of 256 elements, each being a multiple of the prime subgroup generator

        let basis_num = 1;
        let mut basic_crs = Vec::with_capacity(basis_num);
        for i in 0..basis_num {
            basic_crs.push(Element::prime_subgroup_generator() * Fr::from((i + 1) as u64));
        }
        //q-1
        let scalar = Fr::from_str(
            "13108968793781547619861935127046491459309155893440570251786403306729687672800",
        )
        .unwrap();

        let precompute = Committer::new(&basic_crs, 11);
        let mem_byte_size = precompute.tables.len() * precompute.tables[0].len() * 2 * 32;
        println!("precompute_size: {:?}", mem_byte_size);
        use std::time::Instant;
        let start = Instant::now();
        let got_result = precompute.mul_index(&scalar, 0);

        let duration = start.elapsed();
        println!("Time elapsed in mul is: {:?}", duration / 1000);

        let affine_result = got_result.0.into_affine();
        let string_x =
            "33549696307925229982445904590536874618633472405590028303463218160177641247209";
        let string_y =
            "19188667384257783945677642223292697773471335439753913231509108946878080696678";
        let x = affine_result.x.to_string();
        let y = affine_result.y.to_string();
        assert_eq!(string_x, x);
        assert_eq!(string_y, y);
        println!("got_result: {:?}", affine_result);
    }
    #[test]
    fn correctness_benchmark_manual() {
        // Create a vector of 256 elements, each being a multiple of the prime subgroup generator

        let basis_num = 1;
        let mut basic_crs = Vec::with_capacity(basis_num);
        for i in 0..basis_num {
            basic_crs.push(Element::prime_subgroup_generator() * Fr::from((i + 1) as u64));
        }

        let test_round = 100;
        let windows_size = 17;
        for j in 4..windows_size {
            let precompute = Committer::new(&basic_crs, j);
            for _k in 0..test_round {
                let mut rng = ChaCha20Rng::from_seed([2u8; 32]);
                let scalar = Fr::rand(&mut rng);
                let got_result = precompute.mul_index(&scalar, 0);
                let mut scalars: Vec<Fr> = Vec::with_capacity(1);
                scalars.push(scalar);

                let correct_result = multi_scalar_mul(&basic_crs, &scalars);

                let affine_correct_result = correct_result.0.into_affine();
                let affine_got_result = got_result.0.into_affine();
                assert_eq!(affine_correct_result, affine_got_result);
            }
        }
    }
}
