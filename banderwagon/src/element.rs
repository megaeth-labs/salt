use ark_ec::{twisted_edwards::TECurveConfig, CurveGroup, PrimeGroup, ScalarMul};
use ark_ed_on_bls12_381_bandersnatch::{BandersnatchConfig, EdwardsAffine, EdwardsProjective, Fq};
use ark_ff::{serial_batch_inversion_and_mul, Field, One, Zero};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, SerializationError};

use core::{
    hash::{Hash, Hasher},
    iter::Sum,
    ops::{Add, AddAssign, Mul, Neg, Sub},
};
use salt_macros::prelude::*;
use salt_macros::{chunks, num_threads};
use std::vec::Vec;

pub use ark_ed_on_bls12_381_bandersnatch::Fr;

#[derive(Debug, Clone, Copy)]
pub struct Element(pub(crate) EdwardsProjective);

impl PartialEq for Element {
    /// Checks equality in the banderwagon quotient group.
    ///
    /// This implements the banderwagon equality check where points `(x, y)` and `(-x, -y)`
    /// are considered equivalent. Instead of checking exact point equality, this verifies
    /// whether `x₁/y₁ == x₂/y₂` by computing `x₁ * y₂ == x₂ * y₁` (avoiding division).
    ///
    /// This quotient group construction reduces the Bandersnatch curve to prime order by
    /// identifying point pairs that differ only in sign, effectively merging `(x, y)` with
    /// `(-x, -y)` as the same group element.
    ///
    /// # Preconditions
    ///
    /// Both `self` and `other` must be valid banderwagon elements that have passed the
    /// subgroup check (verifying that `1 - ax²` is a quadratic residue). This ensures:
    /// - The points lie in the correct prime-order subgroup
    /// - Points at infinity (with `y = 0`) are excluded
    fn eq(&self, other: &Self) -> bool {
        let (x1, y1) = (self.0.x, self.0.y);
        let (x2, y2) = (other.0.x, other.0.y);

        // Fail-safe check to reject the invalid but dangerous (0, 0) point.
        if x1.is_zero() & y1.is_zero() {
            return false;
        }
        if x2.is_zero() & y2.is_zero() {
            return false;
        }

        (x1 * y2) == (x2 * y1)
    }
}

impl Element {
    /// Serializes this element to a 32-byte compressed representation.
    ///
    /// This implements the banderwagon serialization strategy: `sign(y) × x`.
    /// The serialized form ensures that equivalent points `(x, y)` and `(-x, -y)`
    /// produce identical byte arrays, maintaining the quotient group structure.
    ///
    /// # Serialization Strategy
    ///
    /// - If `y` is positive (lexicographically larger): serialize `x`
    /// - If `y` is negative (lexicographically smaller): serialize `-x`
    ///
    /// This works because `sign(-y) × (-x) = sign(y) × x`, ensuring equivalent
    /// points map to the same representation.
    ///
    /// # Returns
    ///
    /// A 32-byte array in big-endian format for interoperability.
    ///
    /// # Panics
    ///
    /// Panics if serialization fails (should never occur for valid elements).
    pub fn to_bytes(&self) -> [u8; 32] {
        let affine = EdwardsAffine::from(self.0);
        let x = if is_positive(affine.y) {
            affine.x
        } else {
            -affine.x
        };
        let mut bytes = [0u8; 32];
        x.serialize_compressed(&mut bytes[..])
            .expect("serialization failed");

        // arkworks uses little endian, reverse bytes to big endian
        bytes.reverse();
        bytes
    }

    /// Deserializes a banderwagon element from a 32-byte compressed representation.
    ///
    /// # Deserialization Process
    ///
    /// 1. Interpret the input bytes as the field element `x`
    /// 2. Reconstruct the curve point from `x` (choosing positive y-coordinate)
    /// 3. Perform subgroup check
    ///
    /// # Returns
    ///
    /// - `Ok(Element)` if deserialization succeeds and passes validation
    /// - `Err(SerializationError)` if the bytes are invalid, the point doesn't exist,
    ///   or the subgroup check fails
    ///
    /// # Security
    ///
    /// This is the **safe** deserialization path. Always use this for untrusted input.
    pub fn from_bytes(bytes: [u8; 32]) -> Result<Element, SerializationError> {
        let x = x_from_bytes(bytes)?;
        let x_sq = x.square();
        // `d` is not a square, so `d·x² − 1` is never zero; were it zero, this panics as the
        // division `n / d` it replaces did
        let den_inv = denominator(x_sq)
            .inverse()
            .expect("d·x² − 1 is nonzero: d is not a square");
        Self::from_x(x, x_sq, den_inv)
    }

    /// The decode [`Element::from_bytes`] runs on a parsed `x`, given `x_sq = x²` and
    /// `den_inv = 1 / (d·x² − 1)` so that a batch can share the inversion: the point with positive
    /// `y` if one exists and lies in the prime subgroup.
    fn from_x(x: Fq, x_sq: Fq, den_inv: Fq) -> Result<Element, SerializationError> {
        // Construct a point that is on the curve
        let point =
            Self::get_point_from_x(x, x_sq, den_inv).ok_or(SerializationError::InvalidData)?;

        // Verify point is in the correct subgroup
        subgroup_check(x_sq)
            .then_some(Element(point))
            .ok_or(SerializationError::InvalidData)
    }

    /// Deserializes many 32-byte compressed elements, one result per input in order, each equal to
    /// what [`Element::from_bytes`] returns for it.
    ///
    /// The inputs are split into tasks decoded in parallel with the `parallel` feature: about four
    /// per thread, at most 128 points each, and on the vector path whole chunks of 32 points. Within
    /// a task the denominators of `y² = n/d` share one inversion.
    ///
    /// On an `x86_64` host with AVX-512 IFMA (and the `std` feature) the subgroup check, the inversion
    /// and the square root run eight points per vector register, 32 points per chunk, a short last
    /// chunk padded. An input whose bytes are not a canonical `x`, and any point the vector path does
    /// not accept, is decoded by [`Element::from_bytes`] itself, so every rejection is the scalar
    /// decoder's and the vector path cannot reject an input the scalar path accepts.
    ///
    /// Every input is decoded before this returns. The results come back as an iterator over the
    /// tasks' outputs rather than one `Vec`, so that a caller collecting them (into a map, say) copies
    /// each result once: gathering them into a single vector first is a serial copy that measured
    /// 15% of the whole decode on 20,000 points with the vector lanes.
    pub fn from_bytes_batch(
        bytes: &[[u8; 32]],
    ) -> impl Iterator<Item = Result<Element, SerializationError>> {
        let tasks: Vec<Vec<Result<Element, SerializationError>>> =
            chunks!(bytes, decode_task_len(bytes.len()))
                .map(Self::decode_task)
                .collect();
        tasks.into_iter().flatten()
    }

    /// One task of [`Element::from_bytes_batch`], on the vector lanes where this host has them.
    fn decode_task(bytes: &[[u8; 32]]) -> Vec<Result<Element, SerializationError>> {
        #[cfg(all(feature = "std", target_arch = "x86_64"))]
        if lanes_available() {
            // SAFETY: on this target `lanes_available()` is `ifma::available()`, which returned true.
            return Self::decode_task_lanes(bytes, |xs| unsafe { crate::ifma::decode_chunks(xs) });
        }
        Self::decode_task_scalar(bytes)
    }

    /// [`Element::from_bytes`] on every input, with the inversions of `y² = n/d` shared by the
    /// task: one inversion and three products per point instead of an inversion each. Bytes that are
    /// not a canonical `x`, and a zero denominator (which no `x` has, `d` not being a square), go
    /// through `from_bytes` itself, so its error and its behavior are kept exactly.
    fn decode_task_scalar(bytes: &[[u8; 32]]) -> Vec<Result<Element, SerializationError>> {
        // (x, x², d·x² − 1) where the input parses and the denominator is nonzero
        let parsed: Vec<Option<(Fq, Fq, Fq)>> = bytes
            .iter()
            .map(|b| {
                let x = x_from_bytes(*b).ok()?;
                let x_sq = x.square();
                let den = denominator(x_sq);
                (!den.is_zero()).then_some((x, x_sq, den))
            })
            .collect();
        let mut den_inv: Vec<Fq> = parsed.iter().flatten().map(|(_, _, den)| *den).collect();
        serial_batch_inversion_and_mul(&mut den_inv, &Fq::one());
        let mut den_inv = den_inv.into_iter();
        bytes
            .iter()
            .zip(parsed)
            .map(|(b, parsed)| match parsed {
                Some((x, x_sq, _)) => Self::from_x(
                    x,
                    x_sq,
                    den_inv.next().expect("an inverse per parsed input"),
                ),
                None => Self::from_bytes(*b),
            })
            .collect()
    }

    /// [`Element::from_bytes`] on every input, the canonical ones decoded by `decode_chunks` (the
    /// vector lanes, a stand-in in tests) in chunks of [`CHUNK`], at most [`TASK_CHUNKS`] chunks per
    /// call. A position whose bytes are not a canonical `x`, and the padding of a short last chunk,
    /// carry `x = 0` (the identity, whose lane settles first) and their lanes' answers are discarded.
    ///
    /// The lanes only accept, and only inputs that parse: every other input is decoded by
    /// `from_bytes` itself, so every rejection is the scalar decoder's and no fault in the lanes can
    /// turn an input the scalar path accepts into an error.
    #[cfg(any(test, all(feature = "std", target_arch = "x86_64")))]
    fn decode_task_lanes(
        bytes: &[[u8; 32]],
        mut decode_chunks: impl FnMut(&[[Fq; CHUNK]]) -> Vec<ChunkDecode>,
    ) -> Vec<Result<Element, SerializationError>> {
        let mut out = Vec::with_capacity(bytes.len());
        for group in bytes.chunks(CHUNK * TASK_CHUNKS) {
            let xs: Vec<Option<Fq>> = group.iter().map(|b| x_from_bytes(*b).ok()).collect();
            let mut lanes = std::vec![[Fq::zero(); CHUNK]; group.len().div_ceil(CHUNK)];
            for (i, x) in xs.iter().enumerate() {
                if let Some(x) = x {
                    lanes[i / CHUNK][i % CHUNK] = *x;
                }
            }
            let decoded = decode_chunks(&lanes);
            assert_eq!(decoded.len(), lanes.len(), "one decode per lane chunk");
            for (i, (b, x)) in group.iter().zip(&xs).enumerate() {
                out.push(match (x, decoded[i / CHUNK].0[i % CHUNK]) {
                    (Some(x), Some((_, y))) => {
                        Ok(Element(EdwardsAffine::new_unchecked(*x, y).into()))
                    }
                    _ => Self::from_bytes(*b),
                });
            }
        }
        out
    }

    /// Serializes this element to a 64-byte uncompressed representation.
    ///
    /// This format stores both x and y coordinates, enabling faster deserialization.
    /// This method canonicalizes with respect to the banderwagon quotient group by
    /// always choosing the point with a positive y-coordinate. Equivalent elements
    /// `(x, y)` and `(-x, -y)` will serialize to the same byte array.
    ///
    /// # Returns
    ///
    /// A 64-byte array in little-endian format containing uncompressed point coordinates,
    /// normalized to have a positive y-coordinate.
    ///
    /// # Panics
    ///
    /// Panics if serialization fails. This should never occur for valid `Element` instances.
    pub fn to_bytes_uncompressed(&self) -> [u8; 64] {
        affine_to_canonical_bytes(self.0.into())
    }

    /// Deserializes from 64-byte uncompressed format WITHOUT subgroup validation.
    ///
    /// This method provides significant performance benefits by skipping both point
    /// reconstruction from x-coordinate (solving the curve equation) and the subgroup
    /// check (quadratic residue test). However, it bypasses the validation required
    /// for valid banderwagon elements.
    ///
    /// # Security Warning
    ///
    /// Using this on untrusted input can create invalid elements and break cryptographic
    /// security. The performance optimization is only safe when operating on already-validated
    /// data.
    ///
    /// # Safety Contract
    ///
    /// Only use on data that was:
    /// 1. Previously validated via [`from_bytes()`], or
    /// 2. Produced by [`to_bytes_uncompressed()`] on a valid `Element`, or
    /// 3. Retrieved from trusted storage with validation at the entry point
    ///
    /// # Usage
    ///
    /// **Safe:** Deserializing from your database after validating on insertion, or internal
    /// operations where validation occurred at the API boundary.
    ///
    /// **Unsafe:** User input, network data, or any untrusted source.
    ///
    /// # Panics
    ///
    /// Panics on invalid bytes, indicating the upper protocol layers (IPA commitment scheme
    /// and ultimately authenticated key-value store) violated the safety contract.
    pub fn from_bytes_unchecked_uncompressed(bytes: [u8; 64]) -> Self {
        let point = EdwardsProjective::deserialize_uncompressed_unchecked(&bytes[..])
            .expect("could not deserialize byte array into a point");

        // Check element validity in debug builds
        debug_assert!(
            {
                let affine = EdwardsAffine::from(point);
                affine.is_on_curve() && subgroup_check(affine.x.square())
            },
            "Receive invalid Banderwagon element"
        );

        Self(point)
    }

    pub fn prime_subgroup_generator() -> Element {
        Element(EdwardsProjective::generator())
    }

    /// Reconstructs a twisted Edwards curve point from an x-coordinate.
    ///
    /// Given an x-coordinate on the Bandersnatch curve, this computes the corresponding
    /// y-coordinate using the twisted Edwards curve equation and returns the point with
    /// the positive (lexicographically larger) y-coordinate.
    ///
    /// # Curve Equation
    ///
    /// The Bandersnatch curve equation is: `ax² + y² = 1 + dx²y²`
    ///
    /// Solving for y² gives: `y² = (1 - ax²) / (1 - dx²)`
    ///
    /// where `a` and `d` are the curve parameters from [`BandersnatchConfig`].
    ///
    /// # Parameters
    ///
    /// - `x`: The x-coordinate of the point
    /// - `x_sq`: `x²`
    /// - `den_inv`: `1 / (d·x² − 1)`, the inverse of the denominator
    ///
    /// # Returns
    ///
    /// - `Some(EdwardsProjective)` if a valid curve point exists for the given x,
    ///   with the positive y-coordinate
    /// - `None` if `y²` has no square root (x-coordinate not on the curve)
    ///
    /// # Note
    ///
    /// This function does **not** perform subgroup validation. The caller is responsible
    /// for ensuring the resulting point is in the correct subgroup if needed.
    fn get_point_from_x(x: Fq, x_sq: Fq, den_inv: Fq) -> Option<EdwardsProjective> {
        let y_squared = (BandersnatchConfig::COEFF_A * x_sq - Fq::one()) * den_inv;

        let mut y = crate::decoder_arithmetic::sqrt(y_squared)?;
        if !is_positive(y) {
            y = -y;
        }

        Some(EdwardsAffine::new_unchecked(x, y).into())
    }

    /// Maps an elliptic curve point to a scalar field element.
    ///
    /// This is a critical operation in verkle trees, enabling commitments (curve points)
    /// to be used as values in parent node vectors.
    ///
    /// # Algorithm
    ///
    /// 1. Compute `x/y` where `(x, y)` are the point coordinates → yields a base field element (Fq)
    /// 2. Serialize the Fq element to bytes
    /// 3. Reinterpret those bytes as a scalar field element (Fr)
    ///
    /// # Non-Injectivity Properties
    ///
    /// This mapping is **not injective** in two ways:
    ///
    /// 1. **Banderwagon quotient group (2-to-1)**: Points `(x, y)` and `(-x, -y)` both map
    ///    to the same Fr value. This is by design - banderwagon identifies these as the same
    ///    element, so this property is harmless.
    ///
    /// 2. **Field size wrapping (Fq → Fr)**: Since the scalar field Fr is ~4x smaller than
    ///    the base field Fq, the byte reinterpretation can wrap. This means multiple distinct
    ///    points could theoretically map to the same Fr value.
    ///
    /// # Security Note
    ///
    /// While the Fq→Fr non-injectivity means a malicious prover could craft points that
    /// map to the same scalar, this doesn't compromise security in verkle tree proofs.
    /// The IPA vector opening forces the prover to know the actual committed vector,
    /// preventing exploitation of colliding commitments.
    ///
    /// **Warning**: If using this mapping in other protocols, ensure you require vector
    /// openings to prevent commitment substitution attacks.
    ///
    /// # References
    ///
    /// - [Non-injective mapping between Point→Fr](https://ihagopian.com/posts/anatomy-of-a-verkle-proof)
    pub fn map_to_scalar_field(&self) -> Fr {
        base_to_scalar(self.0.x / self.0.y)
    }

    /// Batch-optimized version of [`map_to_scalar_field()`](Element::map_to_scalar_field).
    ///
    /// Uses batch inversion to amortize the cost of computing `x/y` across all elements.
    ///
    /// This is intentionally a single-threaded implementation to avoid parallelization
    /// overhead on small batches.
    ///
    /// # Arguments
    ///
    /// * `elements` - Slice of Elements to convert
    ///
    /// # Returns
    ///
    /// Vector of scalar field elements, one for each input Element
    pub fn batch_map_to_scalar_field(elements: &[Element]) -> Vec<Fr> {
        let (xs, mut ys): (Vec<Fq>, Vec<Fq>) = elements.iter().map(|e| (e.0.x, e.0.y)).unzip();

        serial_batch_inversion_and_mul(&mut ys, &Fq::ONE);

        xs.into_iter()
            .zip(ys)
            .map(|(x, y_inv)| base_to_scalar(x * y_inv))
            .collect()
    }

    /// Takes uncompressed element bytes (64 bytes each) and returns scalar field elements.
    /// See [`map_to_scalar_field()`](Element::map_to_scalar_field) for mapping semantics.
    pub fn hash_commitments(elements: &[[u8; 64]]) -> Vec<Fr> {
        let elements: Vec<Element> = elements
            .iter()
            .map(|&bytes| Element::from_bytes_unchecked_uncompressed(bytes))
            .collect();

        Self::batch_map_to_scalar_field(&elements)
    }

    /// Converts banderwagon elements to their 64-byte commitment representations.
    ///
    /// This method canonicalizes with respect to the banderwagon quotient group by
    /// always choosing the point with a positive y-coordinate. Equivalent elements
    /// `(x, y)` and `(-x, -y)` will serialize to the same byte array.
    ///
    /// # Arguments
    ///
    /// * `elements` - Slice of elements to convert
    ///
    /// # Returns
    ///
    /// Vector of 64-byte arrays, each containing canonicalized uncompressed coordinates:
    /// - Bytes 0-31: X-coordinate (little-endian)
    /// - Bytes 32-63: Y-coordinate (little-endian, always positive)
    pub fn batch_to_commitments(elements: &[Element]) -> Vec<[u8; 64]> {
        let points: Vec<_> = elements.iter().map(|e| e.0).collect();
        EdwardsProjective::normalize_batch(&points)
            .into_iter()
            .map(affine_to_canonical_bytes)
            .collect()
    }

    pub fn zero() -> Element {
        Element(EdwardsProjective::zero())
    }

    /// Returns the canonical 64-byte representation of the banderwagon identity element.
    ///
    /// The identity element in the banderwagon quotient group is represented by the
    /// equivalence class `{(0, 1), (0, -1)}`. This function returns the canonical form
    /// with coordinates `(0, -1)`, chosen because `-1` is the lexicographically larger
    /// value in the field ordering.
    ///
    /// This is a compile-time constant that produces the same output as
    /// `Element::zero().to_bytes_uncompressed()`, but without any runtime computation.
    ///
    /// # Returns
    ///
    /// A 64-byte array in little-endian format containing the uncompressed coordinates:
    /// - Bytes 0-31: X-coordinate (0)
    /// - Bytes 32-63: Y-coordinate (-1 in the field)
    pub const fn zero_commitment() -> [u8; 64] {
        [
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 255, 255, 255, 255, 254, 91, 254, 255, 2, 164, 189, 83, 5, 216,
            161, 9, 8, 216, 57, 51, 72, 125, 157, 41, 83, 167, 237, 115,
        ]
    }

    pub fn is_zero(&self) -> bool {
        *self == Element::zero()
    }
}

// The lexographically largest value is defined to be the positive value
pub(crate) fn is_positive(coordinate: Fq) -> bool {
    coordinate > -coordinate
}

/// Canonicalizes an affine point and serializes it to 64 bytes.
///
/// Chooses the banderwagon representative with positive y-coordinate,
/// ensuring that equivalent points `(x, y)` and `(-x, -y)` produce
/// identical byte arrays.
fn affine_to_canonical_bytes(affine: EdwardsAffine) -> [u8; 64] {
    let canonical = if is_positive(affine.y) {
        affine
    } else {
        EdwardsAffine::new_unchecked(-affine.x, -affine.y)
    };

    let mut bytes = [0u8; 64];
    canonical
        .serialize_uncompressed(&mut bytes[..])
        .expect("serialization should not fail for valid affine points");
    bytes
}

/// Converts a base field element (Fq) to a scalar field element (Fr).
///
/// This is used to map banderwagon elements to scalars by serializing the
/// base field element and reinterpreting the bytes as a scalar field element.
fn base_to_scalar(base_field: Fq) -> Fr {
    use ark_ff::PrimeField;
    let mut bytes = [0u8; 32];
    base_field
        .serialize_compressed(&mut bytes[..])
        .expect("could not serialize point into a 32 byte array");
    Fr::from_le_bytes_mod_order(&bytes)
}

/// Checks whether a point is in the banderwagon prime-order subgroup, given the square
/// `x_sq = x²` of its affine x-coordinate.
///
/// # Precondition
///
/// Assumes the input point is on the Bandersnatch curve. This only checks subgroup
/// membership by verifying that `1 - ax²` is a nonzero quadratic residue.
///
/// # Warning
///
/// Invalid points not on the curve may pass this check. For example, (0, 0) passes
/// because `1 - a·0² = 1` is a QR, despite not being on the curve.
///
/// Used during deserialization to ensure valid banderwagon elements, and by the debug check of
/// [`Element::from_bytes_unchecked_uncompressed`].
fn subgroup_check(x_sq: Fq) -> bool {
    crate::decoder_arithmetic::is_nonzero_square(Fq::one() - BandersnatchConfig::COEFF_A * x_sq)
}

/// The `x` a 32-byte big-endian compressed element encodes, or the error for bytes that are not a
/// canonical field element.
fn x_from_bytes(mut bytes: [u8; 32]) -> Result<Fq, SerializationError> {
    // Switch from big endian to little endian for arkworks
    bytes.reverse();
    Fq::deserialize_compressed(&bytes[..])
}

/// The denominator `d·x² − 1` of `y² = (a·x² − 1) / (d·x² − 1)`, given `x_sq = x²`.
fn denominator(x_sq: Fq) -> Fq {
    BandersnatchConfig::COEFF_D * x_sq - Fq::one()
}

/// Points per vector-lane chunk of the batch decode: four interleaved groups of eight lanes, enough
/// independent multiplication chains to cover the IFMA latency.
pub(crate) const CHUNK: usize = 32;

/// Lane chunks one vector decode call takes (up to 128 points); its chunks share one inversion
/// exponentiation.
pub(crate) const TASK_CHUNKS: usize = 4;

/// The vector decode of one chunk: `(x, y)` with positive `y` per point where the scalar path
/// accepts, and the lanes the vector path did not decide.
#[cfg(any(test, all(feature = "std", target_arch = "x86_64")))]
pub(crate) type ChunkDecode = ([Option<(Fq, Fq)>; CHUNK], [bool; CHUNK]);

/// Whether [`Element::from_bytes_batch`] decodes on the AVX-512 IFMA lanes on this host: the lane
/// module is compiled (`x86_64` with `std`) and the CPU reports the extension. The batch decode
/// dispatches on this, and so does the test that requires the lanes in CI.
pub(crate) fn lanes_available() -> bool {
    #[cfg(all(feature = "std", target_arch = "x86_64"))]
    {
        crate::ifma::available()
    }
    #[cfg(not(all(feature = "std", target_arch = "x86_64")))]
    {
        false
    }
}

/// Tasks per thread [`Element::from_bytes_batch`] aims for, so that work stealing evens out threads
/// that run at different speeds (performance and efficiency cores, a thread busy elsewhere): with one
/// task per thread the slowest thread sets the decode's time.
const TASKS_PER_THREAD: usize = 4;

/// The length of the tasks [`Element::from_bytes_batch`] splits `total` points into: about
/// [`TASKS_PER_THREAD`] per thread, so that a small batch still spreads over every thread, and at
/// most `CHUNK * TASK_CHUNKS` (128) points, past which sharing the inversion saves nothing measurable
/// and a large batch is left with few tasks to balance. On the vector lanes it is rounded up to whole
/// [`CHUNK`]s.
fn decode_task_len(total: usize) -> usize {
    let len = total
        .div_ceil(TASKS_PER_THREAD * num_threads!())
        .clamp(1, CHUNK * TASK_CHUNKS);
    if lanes_available() {
        len.next_multiple_of(CHUNK)
    } else {
        len
    }
}

pub fn multi_scalar_mul(bases: &[Element], scalars: &[Fr]) -> Element {
    assert_eq!(
        bases.len(),
        scalars.len(),
        "number of bases should equal number of scalars"
    );

    // The MSM needs affine bases. Points loaded from storage or deserialized
    // proofs already have `z = 1`, so skip the batch inversion entirely in
    // that common case.
    let bases: Vec<EdwardsAffine> = if bases.iter().all(|element| element.0.z.is_one()) {
        bases
            .iter()
            .map(|element| EdwardsAffine::new_unchecked(element.0.x, element.0.y))
            .collect()
    } else {
        let bases_inner: Vec<_> = bases.iter().map(|element| element.0).collect();
        EdwardsProjective::batch_convert_to_mul_base(&bases_inner)
    };

    Element(crate::msm::msm_windowed(&bases, scalars))
}

/// Multiplies an `Element` by a scalar field element.
///
/// This performs scalar multiplication in the banderwagon group: `k * P` where
/// `k` is a scalar (Fr) and `P` is a group element. This operation is fundamental
/// to elliptic curve cryptography and is used in commitment schemes and signatures.
impl Mul<Fr> for Element {
    type Output = Element;

    fn mul(self, rhs: Fr) -> Self::Output {
        Element(self.0.mul(rhs))
    }
}

/// Multiplies an `Element` reference by a scalar field element reference.
///
/// This is the borrowed version of scalar multiplication, avoiding clones when
/// both operands are references.
impl Mul<&Fr> for &Element {
    type Output = Element;

    fn mul(self, rhs: &Fr) -> Self::Output {
        Element(self.0.mul(rhs))
    }
}

/// Adds two `Element`s together using banderwagon group addition.
///
/// This implements the group operation for the banderwagon elliptic curve group.
/// Addition is commutative and associative: `P + Q == Q + P` and `(P + Q) + R == P + (Q + R)`.
impl Add<Element> for Element {
    type Output = Element;

    fn add(self, rhs: Element) -> Self::Output {
        Element(self.0 + rhs.0)
    }
}

/// Adds another `Element` to this element in-place.
///
/// Mutates `self` to hold the sum, avoiding allocation of a new `Element`.
impl AddAssign<Element> for Element {
    fn add_assign(&mut self, rhs: Element) {
        self.0 += rhs.0
    }
}

/// Subtracts one `Element` from another using banderwagon group subtraction.
///
/// Equivalent to `self + (-rhs)`, where `-rhs` is the group inverse of `rhs`.
impl Sub<Element> for Element {
    type Output = Element;

    fn sub(self, rhs: Element) -> Self::Output {
        Element(self.0 - rhs.0)
    }
}

/// Returns the additive inverse (negation) of an `Element`.
///
/// For any element `P`, `-P` satisfies `P + (-P) = identity`.
impl Neg for Element {
    type Output = Element;

    fn neg(self) -> Self::Output {
        Element(-self.0)
    }
}

/// Sums an iterator of `Element`s into a single element.
///
/// Enables using `.sum()` on iterators: `elements.iter().copied().sum()`.
/// Returns the group identity element for an empty iterator.
impl Sum for Element {
    fn sum<I: Iterator<Item = Self>>(iter: I) -> Self {
        Element(iter.map(|element| element.0).sum())
    }
}

/// Hashes an `Element` by serializing it to bytes first.
///
/// Uses the canonical byte representation via `to_bytes()` to ensure consistent
/// hashing. This allows `Element` to be used as a key in `HashMap` and `HashSet`.
impl Hash for Element {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.to_bytes().hash(state)
    }
}

#[cfg(test)]
pub(crate) mod tests {
    extern crate std;
    use self::std::println;
    /// `from_bytes_batch` returns `from_bytes`'s result on every input: accepted points, canonical `x`
    /// with no square root, points off the prime subgroup, and non-canonical bytes.
    #[test]
    fn from_bytes_batch_matches_from_bytes() {
        use ark_ff::UniformRand;
        use rand_chacha::rand_core::{RngCore, SeedableRng};
        let mut rng = rand_chacha::ChaCha20Rng::seed_from_u64(7);
        let mut inputs: Vec<[u8; 32]> = Vec::new();
        for _ in 0..200 {
            inputs.push((Element::prime_subgroup_generator() * Fr::rand(&mut rng)).to_bytes());
        }
        for _ in 0..200 {
            let x = Fq::rand(&mut rng);
            let mut b = [0u8; 32];
            x.serialize_compressed(&mut b[..]).unwrap();
            b.reverse();
            inputs.push(b);
        }
        for _ in 0..20 {
            inputs.push([0xff; 32]);
            let mut b = [0u8; 32];
            rng.fill_bytes(&mut b);
            inputs.push(b);
        }
        let expected: Vec<_> = inputs
            .iter()
            .map(|b| outcome(Element::from_bytes(*b)))
            .collect();
        let got: Vec<_> = Element::from_bytes_batch(&inputs).map(outcome).collect();
        assert_eq!(got, expected);
        assert!(expected.iter().filter(|p| p.is_ok()).count() >= 200);
        assert!(expected.iter().filter(|p| p.is_err()).count() >= 100);
    }

    /// What a decode returns, comparable: the affine point, or the error's debug form.
    fn outcome(
        decoded: Result<Element, SerializationError>,
    ) -> Result<(Fq, Fq), std::string::String> {
        decoded
            .map(|element| {
                let point = element.0.into_affine();
                (point.x, point.y)
            })
            .map_err(|error| std::format!("{error:?}"))
    }

    /// The big-endian bytes of the modulus: the smallest input that is not a canonical `x`.
    fn modulus_bytes() -> [u8; 32] {
        use ark_ff::{BigInteger, PrimeField};
        Fq::MODULUS.to_bytes_be().try_into().unwrap()
    }

    /// `len` inputs of every kind `from_bytes` meets, interleaved so that every chunk holds each:
    /// points that decode, the edge `x` of [`decode_test_xs`] (no root, off the subgroup, zero, ±1,
    /// powers of two), uniform `x`, and bytes that are not a canonical `x`.
    fn decode_test_inputs(len: usize) -> Vec<[u8; 32]> {
        use ark_ff::UniformRand;
        use rand_chacha::rand_core::SeedableRng;
        let mut rng = rand_chacha::ChaCha20Rng::seed_from_u64(43);
        let edges = decode_test_xs(0);
        (0..len)
            .map(|i| match i % 12 {
                3 => [0xff; 32],
                7 => modulus_bytes(),
                k if k % 3 == 1 => x_to_bytes(edges[i % edges.len()]),
                k if k % 3 == 2 => x_to_bytes(Fq::rand(&mut rng)),
                _ => (Element::prime_subgroup_generator() * Fr::rand(&mut rng)).to_bytes(),
            })
            .collect()
    }

    /// A stand-in for the vector lanes that answers what `from_bytes` answers for every lane's `x`,
    /// so its padding lanes (`x = 0`, the identity) and the lanes of non-canonical inputs return a
    /// point the task decoder must discard.
    fn stand_in_lanes(xs: &[[Fq; CHUNK]]) -> Vec<ChunkDecode> {
        assert!(
            !xs.is_empty() && xs.len() <= TASK_CHUNKS,
            "{} chunks",
            xs.len()
        );
        xs.iter()
            .map(|chunk| (chunk.map(decode), [false; CHUNK]))
            .collect()
    }

    /// A stand-in for the vector lanes that accepts nothing: every input falls back to `from_bytes`.
    fn rejecting_lanes(xs: &[[Fq; CHUNK]]) -> Vec<ChunkDecode> {
        assert!(
            !xs.is_empty() && xs.len() <= TASK_CHUNKS,
            "{} chunks",
            xs.len()
        );
        std::vec![([None; CHUNK], [false; CHUNK]); xs.len()]
    }

    /// Each task decoder returns `from_bytes`'s outcome on every input, in order, at every length
    /// around the chunk and call boundaries, with non-canonical inputs mixed in and on those
    /// boundaries: the scalar task, the lane task on stand-in lanes (and on the real lanes where this
    /// host has them), and the whole batch.
    #[test]
    fn decode_tasks_match_from_bytes() {
        let pool = decode_test_inputs(600);
        let lengths = (0..=33).chain([63, 64, 65, 96, 127, 128, 129, 160, 255, 256, 257]);
        for len in lengths {
            for on_boundaries in [false, true] {
                let mut input: Vec<[u8; 32]> = pool[len % 97..][..len].to_vec();
                if on_boundaries {
                    let positions = [0, len.saturating_sub(1), 31, 32, 127, 128, 129];
                    for (k, i) in positions.into_iter().enumerate() {
                        if i < len {
                            input[i] = if k % 2 == 0 {
                                [0xff; 32]
                            } else {
                                modulus_bytes()
                            };
                        }
                    }
                }
                let want: Vec<_> = input
                    .iter()
                    .map(|b| outcome(Element::from_bytes(*b)))
                    .collect();
                let check = |decoder: &str, got: Vec<Result<Element, SerializationError>>| {
                    let got: Vec<_> = got.into_iter().map(outcome).collect();
                    assert_eq!(
                        got, want,
                        "{decoder}, length {len}, on boundaries {on_boundaries}"
                    );
                };
                check("scalar task", Element::decode_task_scalar(&input));
                check(
                    "stand-in lanes",
                    Element::decode_task_lanes(&input, stand_in_lanes),
                );
                check(
                    "rejecting lanes",
                    Element::decode_task_lanes(&input, rejecting_lanes),
                );
                #[cfg(all(feature = "std", target_arch = "x86_64"))]
                if lanes_under_test() {
                    // SAFETY: `lanes_under_test()` returned true, so the host has the extension.
                    let lanes = |xs: &[[Fq; CHUNK]]| unsafe { crate::ifma::decode_chunks(xs) };
                    check("lanes", Element::decode_task_lanes(&input, lanes));
                }
                check("batch", Element::from_bytes_batch(&input).collect());
            }
        }
    }

    /// The environment variable CI's AVX-512 IFMA job sets, where a lane test that cannot run fails.
    const REQUIRE_LANES: &str = "BANDERWAGON_REQUIRE_IFMA";

    /// Whether the lane tests run: the batch decode takes the lanes on this host. Where
    /// [`REQUIRE_LANES`] is set it fails instead of returning false, so that the lane tests of that
    /// job cannot turn into silent skips.
    pub(crate) fn lanes_under_test() -> bool {
        let available = lanes_available();
        assert!(
            available || std::env::var_os(REQUIRE_LANES).is_none(),
            "{REQUIRE_LANES} is set, but the batch decode does not take the AVX-512 IFMA lanes here"
        );
        available
    }

    /// Where CI requires the lanes, the batch decode takes them. Unlike the lane tests this one is
    /// compiled on every target and feature set, so a `cfg` gate or a feature detection that stops
    /// selecting the lanes on that runner fails it instead of removing or skipping the lane tests.
    #[test]
    fn batch_decode_takes_the_lanes_where_required() {
        lanes_under_test();
    }

    /// `d` is not a square, so no `x` makes the denominator `d·x² − 1` zero (the decoders send such
    /// an input to `from_bytes` all the same).
    #[test]
    fn d_is_not_a_square() {
        assert!(BandersnatchConfig::COEFF_D.legendre().is_qnr());
    }

    /// Decode cost per point on one thread: `from_bytes`, the scalar task with its shared inversion,
    /// and the task this host's batch decode runs (the lanes where it has them) at full length and
    /// at a short length padded to a chunk (run with `--ignored --nocapture`).
    #[test]
    #[ignore]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn bench_decode_task() {
        use ark_ff::UniformRand;
        use rand_chacha::rand_core::SeedableRng;
        let mut rng = rand_chacha::ChaCha20Rng::seed_from_u64(11);
        let inputs: Vec<[u8; 32]> = (0..4096)
            .map(|_| (Element::prime_subgroup_generator() * Fr::rand(&mut rng)).to_bytes())
            .collect();
        let want: Vec<_> = inputs
            .iter()
            .map(|b| outcome(Element::from_bytes(*b)))
            .collect();
        let ns_per_point = |decode: &dyn Fn() -> Vec<Result<Element, SerializationError>>| {
            let t = std::time::Instant::now();
            let got = decode();
            let ns = t.elapsed().as_nanos() as f64 / inputs.len() as f64;
            assert_eq!(got.into_iter().map(outcome).collect::<Vec<_>>(), want);
            ns
        };
        let full = CHUNK * TASK_CHUNKS;
        let short = CHUNK / 4;
        for rep in 0..5 {
            let point = ns_per_point(&|| inputs.iter().map(|b| Element::from_bytes(*b)).collect());
            let scalar = ns_per_point(&|| {
                inputs
                    .chunks(full)
                    .flat_map(Element::decode_task_scalar)
                    .collect()
            });
            let task =
                ns_per_point(&|| inputs.chunks(full).flat_map(Element::decode_task).collect());
            let padded = ns_per_point(&|| {
                inputs
                    .chunks(short)
                    .flat_map(Element::decode_task)
                    .collect()
            });
            println!(
                "decode rep {rep}, one thread, lanes {}: from_bytes {point:.0} ns/point, scalar task of {full} {scalar:.0} (x{:.2}), task of {full} {task:.0} (x{:.2}), task of {short} {padded:.0} (x{:.2})",
                lanes_available(),
                point / scalar,
                point / task,
                point / padded,
            );
        }
    }

    use super::*;
    use ark_ff::AdditiveGroup;
    use ark_serialize::CanonicalSerialize;
    use std::vec;

    /// The `x` coordinates a decoder is most likely to get wrong (zero, ±1, small values and
    /// their negations, the powers of two with their neighbours, the middle of the field, the
    /// `x` of points that decode and its negation), followed by `random` uniform ones.
    fn decode_test_xs(random: usize) -> Vec<Fq> {
        use ark_ff::UniformRand;
        use rand_chacha::rand_core::SeedableRng;
        let mut rng = rand_chacha::ChaCha20Rng::seed_from_u64(41);
        let mut xs = vec![Fq::zero(), Fq::one(), -Fq::one()];
        for k in 2..=32u64 {
            xs.extend([Fq::from(k), -Fq::from(k)]);
        }
        let mut power = Fq::one();
        for _ in 0..255 {
            power.double_in_place();
            xs.extend([power - Fq::one(), power, power + Fq::one()]);
        }
        let half = Fq::from(2u64).inverse().unwrap();
        xs.extend([half, -half, half - Fq::one()]);
        for _ in 0..64 {
            let x = (Element::prime_subgroup_generator() * Fr::rand(&mut rng))
                .0
                .into_affine()
                .x;
            xs.extend([x, -x]);
        }
        xs.extend((0..random).map(|_| Fq::rand(&mut rng)));
        xs
    }

    /// The 32 bytes `from_bytes` reads `x` from.
    fn x_to_bytes(x: Fq) -> [u8; 32] {
        let mut bytes = [0u8; 32];
        x.serialize_compressed(&mut bytes[..]).unwrap();
        bytes.reverse();
        bytes
    }

    /// What `from_bytes` returns for `x`, as affine coordinates.
    fn decode(x: Fq) -> Option<(Fq, Fq)> {
        Element::from_bytes(x_to_bytes(x)).ok().map(|element| {
            let point = element.0.into_affine();
            (point.x, point.y)
        })
    }

    /// The decode on arkworks' own square root and Legendre symbol, which `from_bytes` used
    /// before `decoder_arithmetic` replaced them.
    fn arkworks_decode(x: Fq) -> Option<(Fq, Fq)> {
        let x_sq = x.square();
        let y_squared = (BandersnatchConfig::COEFF_A * x_sq - Fq::one())
            / (BandersnatchConfig::COEFF_D * x_sq - Fq::one());
        let mut y = y_squared.sqrt()?;
        if !is_positive(y) {
            y = -y;
        }
        (Fq::one() - BandersnatchConfig::COEFF_A * x_sq)
            .legendre()
            .is_qr()
            .then_some((x, y))
    }

    /// `from_bytes` accepts exactly the `x` the arkworks decode accepts and returns the same point.
    #[test]
    fn from_bytes_matches_the_arkworks_decode() {
        let xs = decode_test_xs(4096);
        let mut accepted = 0;
        for (i, x) in xs.iter().enumerate() {
            let got = decode(*x);
            assert_eq!(got, arkworks_decode(*x), "input {i}");
            accepted += usize::from(got.is_some());
        }
        assert!(accepted > 500, "{accepted} accepted");
        assert!(xs.len() - accepted > 500, "{accepted} accepted");
    }

    /// The lanes return a point exactly where `from_bytes` accepts, and the same point, with every
    /// edge `x` in every lane position. `from_bytes_batch` decodes on the scalar path whatever the
    /// lanes do not return, which would hide a lane that wrongly returns nothing; this reads the
    /// lanes' own answer.
    #[cfg(all(feature = "std", target_arch = "x86_64"))]
    #[test]
    fn lane_decode_accepts_exactly_what_from_bytes_accepts() {
        use crate::ifma::decode_chunks;
        if !lanes_under_test() {
            return;
        }
        let xs = decode_test_xs(2048);
        let expected: Vec<Option<(Fq, Fq)>> = xs.iter().map(|x| decode(*x)).collect();
        // Shift the inputs through the lane positions, padding both ends with ones.
        for shift in 0..CHUNK {
            let mut padded = vec![Fq::one(); shift];
            padded.extend_from_slice(&xs);
            padded.resize(padded.len().next_multiple_of(CHUNK), Fq::one());
            for (k, chunk) in padded.chunks_exact(CHUNK).enumerate() {
                let chunk: [Fq; CHUNK] = chunk.try_into().unwrap();
                // SAFETY: `lanes_under_test()` returned true, so the host has the extension.
                let (points, undecided) = unsafe { decode_chunks(&[chunk]) }[0];
                assert_eq!(undecided, [false; CHUNK], "chunk {k} at shift {shift}");
                for (lane, point) in points.iter().enumerate() {
                    let Some(i) = (k * CHUNK + lane).checked_sub(shift) else {
                        continue;
                    };
                    if let Some(want) = expected.get(i) {
                        assert_eq!(point, want, "input {i} in lane {lane}");
                    }
                }
            }
        }
    }

    #[test]
    fn consistent_group_to_field() {
        // In python this is called commitment_to_field
        // print(commitment_to_field(Point(generator=True)).to_bytes(32, "little").hex())
        let expected = "d1e7de2aaea9603d5bc6c208d319596376556ecd8336671ba7670c2139772d14";

        let generator = Element::prime_subgroup_generator();
        let mut bytes = [0u8; 32];
        generator
            .map_to_scalar_field()
            .serialize_compressed(&mut bytes[..])
            .unwrap();
        assert_eq!(hex::encode(bytes), expected);
    }

    #[test]
    fn from_bytes_unchecked_uncompressed_roundtrip() {
        let generator = Element::prime_subgroup_generator();
        let bytes = generator.to_bytes_uncompressed();
        let element = Element::from_bytes_unchecked_uncompressed(bytes);

        assert_eq!(element, generator)
    }

    #[test]
    fn test_hash_commitments() {
        let points: Vec<_> = (0..10)
            .map(|i| Element::prime_subgroup_generator() * Fr::from(i))
            .collect();

        let got = Element::hash_commitments(
            &points
                .iter()
                .map(|p| p.to_bytes_uncompressed())
                .collect::<Vec<_>>(),
        );

        for (point, scalar) in points.iter().zip(got) {
            assert_eq!(point.map_to_scalar_field(), scalar);
        }
    }

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

    // Two torsion point, *not*  point at infinity {0,-1,0,1}
    fn two_torsion() -> EdwardsProjective {
        EdwardsProjective::new_unchecked(Fq::zero(), -Fq::one(), Fq::zero(), Fq::one())
    }

    fn points_at_infinity() -> [EdwardsProjective; 2] {
        let d = BandersnatchConfig::COEFF_D;
        let a = BandersnatchConfig::COEFF_A;
        let sqrt_da = (d / a).sqrt().unwrap();

        let p1 = EdwardsProjective::new_unchecked(sqrt_da, Fq::zero(), Fq::one(), Fq::zero());
        let p2 = EdwardsProjective::new_unchecked(-sqrt_da, Fq::zero(), Fq::one(), Fq::zero());

        [p1, p2]
    }

    #[test]
    fn fixed_test_vectors() {
        let expected_bit_string = [
            "4a2c7486fd924882bf02c6908de395122843e3e05264d7991e18e7985dad51e9",
            "43aa74ef706605705989e8fd38df46873b7eae5921fbed115ac9d937399ce4d5",
            "5e5f550494159f38aa54d2ed7f11a7e93e4968617990445cc93ac8e59808c126",
            "0e7e3748db7c5c999a7bcd93d71d671f1f40090423792266f94cb27ca43fce5c",
            "14ddaa48820cb6523b9ae5fe9fe257cbbd1f3d598a28e670a40da5d1159d864a",
            "6989d1c82b2d05c74b62fb0fbdf8843adae62ff720d370e209a7b84e14548a7d",
            "26b8df6fa414bf348a3dc780ea53b70303ce49f3369212dec6fbe4b349b832bf",
            "37e46072db18f038f2cc7d3d5b5d1374c0eb86ca46f869d6a95fc2fb092c0d35",
            "2c1ce64f26e1c772282a6633fac7ca73067ae820637ce348bb2c8477d228dc7d",
            "297ab0f5a8336a7a4e2657ad7a33a66e360fb6e50812d4be3326fab73d6cee07",
            "5b285811efa7a965bd6ef5632151ebf399115fcc8f5b9b8083415ce533cc39ce",
            "1f939fa2fd457b3effb82b25d3fe8ab965f54015f108f8c09d67e696294ab626",
            "3088dcb4d3f4bacd706487648b239e0be3072ed2059d981fe04ce6525af6f1b8",
            "35fbc386a16d0227ff8673bc3760ad6b11009f749bb82d4facaea67f58fc60ed",
            "00f29b4f3255e318438f0a31e058e4c081085426adb0479f14c64985d0b956e0",
            "3fa4384b2fa0ecc3c0582223602921daaa893a97b64bdf94dcaa504e8b7b9e5f",
        ];

        let mut points = vec![];
        let mut point = Element::prime_subgroup_generator();
        for (i, _) in expected_bit_string.into_iter().enumerate() {
            let byts = hex::encode(point.to_bytes());
            assert_eq!(byts, expected_bit_string[i], "index {i} does not match");

            points.push(point);
            point = Element(point.0.double())
        }
    }

    #[test]
    fn ser_der_roundtrip() {
        let point = EdwardsProjective::generator();

        let two_torsion_point = two_torsion();

        let element1 = Element(point);
        let bytes1 = element1.to_bytes();

        let element2 = Element(point + two_torsion_point);
        let bytes2 = element2.to_bytes();

        assert_eq!(bytes1, bytes2);

        let got = Element::from_bytes(bytes1).expect("points are in the valid subgroup");

        assert!(got == element1);
        assert!(got == element2);
    }
    #[test]
    fn check_infinity_does_not_pass_legendre() {
        // We cannot use the points at infinity themselves
        // as they have Z=0, which will panic when converting to
        // affine co-ordinates. So we create a point which is
        // the sum of the point at infinity and another point
        let point = points_at_infinity()[0];
        let gen = EdwardsProjective::generator();

        // Points at infinity should fail deserialization due to subgroup check
        let invalid_element = Element(point + gen + gen.double().double());

        assert!(
            Element::from_bytes(invalid_element.to_bytes()).is_err(),
            "point containing infinity should fail deserialization"
        );
    }

    #[test]
    fn two_torsion_correct() {
        let two_torsion_point = two_torsion();
        assert!(!two_torsion_point.is_zero());

        let result = two_torsion_point.double();
        assert!(result.is_zero());

        let [inf1, inf2] = points_at_infinity();
        assert!(!inf1.is_zero());
        assert!(!inf2.is_zero());

        assert!(inf1.double().is_zero());
        assert!(inf2.double().is_zero());
    }

    /// Verifies that the hardcoded constant in `Element::zero_bytes()` matches
    /// the canonical serialization of the identity element from `Element::zero()`.
    #[test]
    fn test_zero_commitment() {
        let zero_bytes = Element::zero_commitment();
        let element_zero = Element::zero().to_bytes_uncompressed();

        assert_eq!(
            zero_bytes, element_zero,
            "Element::zero_bytes() should equal Element::zero().to_bytes_uncompressed()"
        );
    }

    /// Verifies that Element::eq() rejects the invalid (0, 0) point as a failsafe.
    ///
    /// The point (0, 0) is not on the Bandersnatch curve, but is especially dangerous
    /// because it acts as an annihilator in group operations:
    /// - (0, 0) + P = (0, 0) for any point P
    /// - k × (0, 0) = (0, 0) for any scalar k
    ///
    /// This test ensures that our PartialEq implementation correctly rejects (0, 0),
    /// preventing it from trivially satisfying equality checks. This rejection violates
    /// reflexivity (x ≠ x), which is why Element only implements PartialEq, not Eq.
    #[test]
    fn test_eq_failsafe() {
        // Construct the invalid (0, 0) point (bypassing validation via new_unchecked)
        let double_zero = EdwardsAffine::new_unchecked(Fq::ZERO, Fq::ZERO);
        let invalid_element = Element(double_zero.into());

        // Verify (0, 0) is rejected by is_zero() check
        assert!(!invalid_element.is_zero());

        // Verify PartialEq rejects (0, 0), even when compared to itself.
        // This breaks reflexivity (violating Eq trait requirements), but prevents
        // the dangerous (0, 0) point from participating in any equality-based logic.
        assert_ne!(invalid_element, invalid_element);
    }
}
