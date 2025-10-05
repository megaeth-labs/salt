//! Efficient Multi-Scalar Multiplication (MSM) for the SALT commitment scheme.
//!
//! This module implements optimized MSM calculations over the Bandersnatch curve,
//! specifically tailored for SALT's vector commitment operations. The implementation
//! uses windowed Non-Adjacent Form (wNAF) with precomputed tables to accelerate
//! scalar multiplications.
//!
//! # Key Features
//!
//! - **Precomputed Tables**: Stores multiples of base points for fast scalar multiplication
//! - **Memory Optimization**: Optional hugepage support for better cache performance
//! - **Batch Operations**: Efficient batch conversion between projective and affine coordinates
//! - **Platform Optimization**: x86_64 specific optimizations with prefetching and assembly
//!
//! # Architecture
//!
//! The module provides two main components:
//!
//! 1. **`Committer`**: A precomputed MSM engine that stores windowed multiples of base points
//! 2. **Batch conversion utilities**: For efficient coordinate system conversions
//!
//! # Performance Characteristics
//!
//! - Window size affects the trade-off between memory usage and computation speed
//! - Typical window size of 11 provides good balance for 256 base points
//! - Hugepage support can reduce TLB misses for large precomputed tables

use crate::element::Element;
use ark_ec::CurveGroup;
use ark_ed_on_bls12_381_bandersnatch::{EdwardsAffine, EdwardsProjective, Fq, Fr};
use ark_ff::PrimeField;
use ark_ff::Zero;
use ark_serialize::CanonicalSerialize;
use rayon::prelude::*;
/// Precomputed Multi-Scalar Multiplication engine for fixed base points.
///
/// The `Committer` precomputes and stores windowed multiples of a set of base points
/// to accelerate scalar multiplication operations. This is particularly useful for
/// SALT's vector commitment scheme where the same base points are used repeatedly.
///
/// # Memory Layout
///
/// For each base point G[i] and window size w, the table stores:
/// - Window 0: [0, G[i], 2*G[i], ..., (2^(w-1)-1)*G[i]]
/// - Window 1: [0, 2^w*G[i], 2*2^w*G[i], ..., (2^(w-1)-1)*2^w*G[i]]
/// - And so on...
///
/// # Example
///
/// ```ignore
/// let bases = vec![Element::generator(); 256];
/// let committer = Committer::new(&bases, 11);
/// let scalar = Fr::from(12345u64);
/// let result = committer.mul_index(&scalar, 0); // Compute scalar * bases[0]
/// ```
#[derive(Clone, Debug)]
pub struct Committer {
    /// Window size for windowed NAF representation (typically 11 for 256 bases)
    window_size: usize,
    /// Precomputed tables of multiples for each base point.
    /// Structure: tables[base_index][window_index * half_window_size + multiple]
    tables: Vec<Vec<EdwardsAffine>>,
}

impl Drop for Committer {
    #[cfg(all(not(target_os = "macos"), feature = "enable-hugepages"))]
    fn drop(&mut self) {
        use hugepage_rs;
        use std::alloc::Layout;
        // drop inner vectors
        for table in self.tables.iter_mut() {
            let ptr = table.as_mut_ptr() as *mut u8;
            let cap = table.capacity();
            let layout = Layout::array::<EdwardsAffine>(cap).unwrap();
            std::mem::forget(std::mem::take(table));
            hugepage_rs::dealloc(ptr, layout);
        }

        // drop the outer vector
        let ptr = self.tables.as_mut_ptr() as *mut u8;
        let cap = self.tables.capacity();
        let layout = Layout::array::<Vec<EdwardsAffine>>(cap).unwrap();
        std::mem::forget(std::mem::take(&mut self.tables));
        hugepage_rs::dealloc(ptr, layout);
    }

    #[cfg(any(target_os = "macos", not(feature = "enable-hugepages")))]
    fn drop(&mut self) {
        // Standard drop implementation, no need for explicit deallocation
    }
}

impl Committer {
    #[cfg(all(not(target_os = "macos"), feature = "enable-hugepages"))]
    pub fn new(bases: &[Element], window_size: usize) -> Committer {
        use hugepage_rs;
        use std::alloc::Layout;

        let table_num = bases.len();
        let win_num = 253 / window_size + 1; // 253 is the bit length of Fr
        let inner_length = win_num * (1 << (window_size - 1)) + win_num;

        let src_tables: Vec<Vec<EdwardsAffine>> = bases
            .par_iter()
            .map(|base| {
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
                EdwardsProjective::normalize_batch(&table)
            })
            .collect();

        let tables = {
            let layout = Layout::array::<Vec<EdwardsAffine>>(table_num).unwrap();
            let tables_ptr = hugepage_rs::alloc(layout) as *mut Vec<EdwardsAffine>;

            for (i, _) in src_tables.iter().enumerate() {
                let layout = Layout::array::<EdwardsAffine>(inner_length).unwrap();
                let dst_ptr = hugepage_rs::alloc(layout) as *mut EdwardsAffine;
                if tables_ptr.is_null() || dst_ptr.is_null() {
                    panic!("Failed to allocate hugepages for the ECMUL precompute table.");
                }
                let src_ptr = src_tables[i].as_ptr();
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

            unsafe { Vec::from_raw_parts(tables_ptr, table_num, table_num) }
        };

        Committer {
            tables,
            window_size,
        }
    }

    #[cfg(any(target_os = "macos", not(feature = "enable-hugepages")))]
    pub fn new(bases: &[Element], window_size: usize) -> Committer {
        let win_num = 253 / window_size + 1; // 253 is the bit length of Fr
        let inner_length = win_num * (1 << (window_size - 1)) + win_num;

        let tables: Vec<Vec<EdwardsAffine>> = bases
            .par_iter()
            .map(|base| {
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
                EdwardsProjective::normalize_batch(&table)
            })
            .collect();

        Committer {
            tables,
            window_size,
        }
    }

    /// Returns the 64-byte representation of the identity element (point at infinity).
    ///
    /// The identity element is encoded as (0, 1) in affine coordinates,
    /// which serializes to 32 zero bytes followed by 32 bytes representing 1.
    pub const fn zero() -> [u8; 64] {
        [
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0,
        ]
    }

    /// Efficiently updates a commitment by applying a series of delta changes.
    ///
    /// This method is crucial for SALT's incremental update mechanism. Instead of
    /// recomputing the entire commitment from scratch, it only computes the changes.
    ///
    /// # Arguments
    ///
    /// * `old_commitment` - The current commitment value (64 bytes)
    /// * `delta_indices` - Vector of (index, old_value, new_value) tuples where:
    ///   - `index`: Position in the commitment vector
    ///   - `old_value`: Previous Fr value at this position
    ///   - `new_value`: New Fr value at this position
    ///
    /// # Returns
    ///
    /// The updated commitment as an `Element`.
    ///
    /// # Algorithm
    ///
    /// For each delta (i, old, new), computes:
    /// ```text
    /// result = old_commitment + Σ (new[i] - old[i]) * G[i]
    /// ```
    pub fn add_deltas(
        &self,
        old_commitment: [u8; 64],
        delta_indices: &[(usize, Fr, Fr)],
    ) -> Element {
        let mut old = Element::from_bytes_unchecked_uncompressed(old_commitment);
        delta_indices
            .iter()
            .for_each(|&(tb_i, old_fr, new_fr)| old += self.mul_index(&(new_fr - old_fr), tb_i));
        old
    }

    /// Multiplies a precomputed base point by a scalar using windowed NAF.
    ///
    /// This x86_64-optimized version uses CPU prefetching instructions to
    /// improve cache performance during table lookups.
    ///
    /// # Arguments
    ///
    /// * `scalar` - The scalar multiplier (field element)
    /// * `g_i` - Index of the base point to multiply
    ///
    /// # Returns
    ///
    /// The result of `scalar * G[g_i]` as an `Element`.
    #[cfg(target_arch = "x86_64")]
    pub fn mul_index(&self, scalar: &Fr, g_i: usize) -> Element {
        use std::arch::x86_64::{_mm_prefetch, _MM_HINT_T0};

        let chunks = calculate_prefetch_index(scalar, self.window_size);
        let mut result = EdwardsProjective::default();
        let precomp_table = &self.tables[g_i];

        let half_wnd = (1 << (self.window_size - 1)) + 1;
        let wnd_size = 1 << self.window_size;
        let mut idx_next;
        let mut idx;
        let mut c_next = 0;

        // prefetch first point
        let data_0 = unsafe { *chunks.get_unchecked(0) } as usize;
        if data_0 >= half_wnd {
            c_next = 1;
            idx_next = wnd_size - data_0;
        } else {
            idx_next = data_0;
        }
        unsafe {
            _mm_prefetch(
                precomp_table.as_ptr().add(idx_next) as *const i8,
                _MM_HINT_T0,
            );
        }
        idx = idx_next;

        // calculate point
        for i in 1..chunks.len() {
            // fetch next point
            idx_next = unsafe { *chunks.get_unchecked(i) as usize } + c_next;
            let carry = c_next;
            if idx_next >= half_wnd {
                c_next = 1;
                idx_next = wnd_size - idx_next + i * half_wnd;
            } else {
                c_next = 0;
                idx_next += i * half_wnd;
            }
            unsafe {
                _mm_prefetch(
                    precomp_table.as_ptr().add(idx_next) as *const i8,
                    _MM_HINT_T0,
                );
            }

            // add current point
            if carry > 0 {
                add_affine_point(
                    &mut result,
                    unsafe { &(-precomp_table.get_unchecked(idx).x) },
                    unsafe { &precomp_table.get_unchecked(idx).y },
                );
            } else {
                add_affine_point(
                    &mut result,
                    unsafe { &precomp_table.get_unchecked(idx).x },
                    unsafe { &precomp_table.get_unchecked(idx).y },
                );
            }
            idx = idx_next;
        }

        // last point
        if c_next > 0 {
            add_affine_point(
                &mut result,
                unsafe { &(-precomp_table.get_unchecked(idx).x) },
                unsafe { &precomp_table.get_unchecked(idx).y },
            );
        } else {
            add_affine_point(
                &mut result,
                unsafe { &precomp_table.get_unchecked(idx).x },
                unsafe { &precomp_table.get_unchecked(idx).y },
            );
        }

        Element(result)
    }

    /// Multiplies a precomputed base point by a scalar using windowed NAF.
    ///
    /// This is the generic implementation for non-x86_64 architectures.
    ///
    /// # Arguments
    ///
    /// * `scalar` - The scalar multiplier (field element)
    /// * `g_i` - Index of the base point to multiply
    ///
    /// # Returns
    ///
    /// The result of `scalar * G[g_i]` as an `Element`.
    #[cfg(not(target_arch = "x86_64"))]
    pub fn mul_index(&self, scalar: &Fr, g_i: usize) -> Element {
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
        ponits
            .iter()
            .for_each(|p| add_affine_point(&mut result, &p.x, &p.y));
        Element(result)
    }
}

/// Adds an affine point to a projective point using extended Edwards coordinates.
///
/// This is the generic implementation using the extended twisted Edwards addition formula.
/// The formula is optimized for adding an affine point (Z=1) to a projective point.
///
/// # Arguments
///
/// * `result` - The projective point to update (in-place)
/// * `p2_x` - X-coordinate of the affine point to add
/// * `p2_y` - Y-coordinate of the affine point to add
#[cfg(not(target_arch = "x86_64"))]
fn add_affine_point(result: &mut EdwardsProjective, p2_x: &Fq, p2_y: &Fq) {
    use ark_ff::biginteger::BigInt;

    let mut a = result.x * p2_x;
    let b = result.y * p2_y;
    let mut c = p2_x * p2_y;
    let mut d = result.t * c;

    // Multiply by the Edwards curve parameter d = -5
    // The constant below is -5 in Montgomery form for the Bandersnatch field
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
    a = a * Fq::from(5u64);
    let h = b + a;

    result.x = e * f;
    result.y = g * h;
    result.t = e * h;
    result.z = f * g;
}

/// Adds an affine point to a projective point using extended Edwards coordinates.
///
/// This x86_64-optimized version uses hand-written assembly for Montgomery multiplication
/// to achieve better performance than the generic implementation.
///
/// # Arguments
///
/// * `result` - The projective point to update (in-place)
/// * `p2_x` - X-coordinate of the affine point to add
/// * `p2_y` - Y-coordinate of the affine point to add
///
/// # Safety
///
/// Uses unsafe assembly operations that are guaranteed correct for the Bandersnatch field.
#[cfg(target_arch = "x86_64")]
fn add_affine_point(result: &mut EdwardsProjective, p2_x: &Fq, p2_y: &Fq) {
    use crate::scalar_multi_asm::*;

    let mut a = Fq::default();
    let mut b = Fq::default();
    let mut c = Fq::default();
    let mut d = Fq::default();

    mont_mul_asm(&mut a.0 .0, &result.x.0 .0, &p2_x.0 .0);
    mont_mul_asm(&mut b.0 .0, &result.y.0 .0, &p2_y.0 .0);
    mont_mul_asm(&mut c.0 .0, &p2_x.0 .0, &p2_y.0 .0);
    mont_mul_asm(&mut d.0 .0, &result.t.0 .0, &c.0 .0);

    // Multiply by the Edwards curve parameter d = -5
    // The constant is -5 in Montgomery form for the Bandersnatch field
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
        &(p2_x + p2_y).0 .0,
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

/// Decomposes a scalar into windows for efficient table lookups.
///
/// This function splits a scalar into w-bit windows for use with the
/// precomputed multiplication tables. Each window represents a digit
/// in the windowed representation of the scalar.
///
/// # Arguments
///
/// * `scalar` - The scalar to decompose
/// * `w` - Window size in bits
///
/// # Returns
///
/// A vector of w-bit values representing the windowed decomposition.
#[inline]
fn calculate_prefetch_index(scalar: &Fr, w: usize) -> Vec<u64> {
    // Convert scalar from Montgomery form to big integer
    let source_vec = scalar.into_bigint().0;
    let mut index_vec = vec![];

    // Extract w bits of data from a scalar of n bits length
    // Fr's bit length is 253 + Carry, so the maximum length is 254
    for start_bit in (0..254).step_by(w) {
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
    /// Converts banderwagon elements to their 64-byte commitment representations.
    ///
    /// # Arguments
    ///
    /// * `elements` - Slice of elements to convert
    ///
    /// # Returns
    ///
    /// Vector of 64-byte arrays, each containing:
    /// - Bytes 0-31: X-coordinate (little-endian)
    /// - Bytes 32-63: Y-coordinate (little-endian)
    pub fn batch_to_commitments(elements: &[Element]) -> Vec<[u8; 64]> {
        let points: Vec<_> = elements.iter().map(|e| e.0).collect();
        EdwardsProjective::normalize_batch(&points)
            .iter()
            .map(|affine_point| {
                let mut bytes = [0u8; 64];
                affine_point
                    .serialize_uncompressed(&mut bytes[..])
                    .expect("serialization should not fail for valid affine points");
                bytes
            })
            .collect()
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

    /// Tests that `batch_to_commitments` correctly converts elements to 64-byte uncompressed format.
    #[test]
    fn test_batch_to_commitments() {
        let elements: Vec<_> = (1..16)
            .map(|i| Element::prime_subgroup_generator() * Fr::from(i * 1111))
            .collect();

        let batch_result = Element::batch_to_commitments(&elements);

        for (element, commitment) in elements.iter().zip(batch_result.iter()) {
            assert_eq!(element.to_bytes_uncompressed(), *commitment);
        }
    }

    /// Tests the correctness of precomputed MSM against the reference implementation.
    ///
    /// This comprehensive test verifies that the `Committer`'s optimized scalar multiplication
    /// produces identical results to the standard multi-scalar multiplication algorithm.
    ///
    /// # Test Setup
    /// - Creates 256 base points: G, 2G, 3G, ..., 256G
    /// - Uses negative scalars: -1, -2, -3, ..., -256
    /// - Window size 11 (typical for 256 base points)
    ///
    /// # Test Process
    /// 1. Computes reference result using `multi_scalar_mul`
    /// 2. Creates a `Committer` with precomputed tables
    /// 3. Accumulates results using `mul_index` for each scalar
    /// 4. Verifies the optimized result matches the reference
    ///
    /// # Coverage
    /// This tests both positive and negative scalars, exercising the
    /// full windowed NAF algorithm including carry propagation.
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

    /// Tests a specific edge case with known output for debugging and validation.
    ///
    /// This test uses a carefully chosen scalar (q-1, where q is the subgroup order)
    /// to verify correct handling of large scalars near the field modulus.
    ///
    /// # Test Details
    /// - Uses scalar = q-1 = 13108968793781547619861935127046491459309155893440570251786403306729687672800
    /// - This represents -1 in the field, so (q-1)G = -G
    /// - Expected output coordinates are hardcoded for validation
    ///
    /// # Purpose
    /// 1. Validates correct modular reduction of large scalars
    /// 2. Tests edge case near field boundary
    /// 3. Provides performance metrics (memory usage and timing)
    /// 4. Serves as a regression test with known correct output
    ///
    /// # Debug Output
    /// - Prints precomputed table memory size
    /// - Measures and prints multiplication time
    /// - Shows resulting affine coordinates
    #[test]
    fn neg_one_scalar_mult() {
        let basis_num = 1;
        let mut basic_crs = Vec::with_capacity(basis_num);
        for i in 0..basis_num {
            basic_crs.push(Element::prime_subgroup_generator() * Fr::from((i + 1) as u64));
        }
        // q-1 where q is the subgroup order (represents -1 in the field)
        let scalar = Fr::from_str(
            "13108968793781547619861935127046491459309155893440570251786403306729687672800",
        )
        .unwrap();

        let precompute = Committer::new(&basic_crs, 11);
        let mem_byte_size = precompute.tables.len() * precompute.tables[0].len() * 2 * 32;
        println!("precompute_size: {mem_byte_size:?}");
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
        println!("got_result: {affine_result:?}");
    }

    /// Comprehensive correctness test across multiple window sizes with random scalars.
    ///
    /// This test validates the `Committer` implementation by testing various window sizes
    /// with random scalar inputs, ensuring correctness across different optimization levels.
    ///
    /// # Test Parameters
    /// - Window sizes: 4 through 16 (testing different memory/speed trade-offs)
    /// - 100 random scalars per window size
    /// - Uses deterministic RNG (seed [2u8; 32]) for reproducibility
    ///
    /// # Test Process
    /// For each window size:
    /// 1. Creates a new `Committer` with that window size
    /// 2. Generates random scalars
    /// 3. Computes result using optimized `mul_index`
    /// 4. Computes reference result using `multi_scalar_mul`
    /// 5. Verifies results match exactly
    ///
    /// # Coverage
    /// - Tests small to large window sizes (4-16)
    /// - Uses random scalars to test various bit patterns
    /// - Validates the windowing algorithm works correctly for all window sizes
    /// - Ensures precomputed tables are correct regardless of window choice
    #[test]
    fn test_window_size_variations_with_random_scalars() {
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
                let scalars: Vec<Fr> = vec![scalar];

                let correct_result = multi_scalar_mul(&basic_crs, &scalars);

                let affine_correct_result = correct_result.0.into_affine();
                let affine_got_result = got_result.0.into_affine();
                assert_eq!(affine_correct_result, affine_got_result);
            }
        }
    }
}
