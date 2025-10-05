use ark_ec::{twisted_edwards::TECurveConfig, PrimeGroup, ScalarMul, VariableBaseMSM};
use ark_ed_on_bls12_381_bandersnatch::{BandersnatchConfig, EdwardsAffine, EdwardsProjective, Fq};
use ark_ff::{batch_inversion, serial_batch_inversion_and_mul, Field, One, Zero};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};

use std::{
    hash::Hash,
    iter::Sum,
    ops::{Add, AddAssign, Mul, Neg, Sub},
};

pub use ark_ed_on_bls12_381_bandersnatch::Fr;

#[derive(Debug, Clone, Copy, Eq)]
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
        (self.0.x * other.0.y) == (other.0.x * self.0.y)
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
    /// - `Some(Element)` if deserialization succeeds and passes validation
    /// - `None` if the bytes are invalid, the point doesn't exist, or the subgroup check fails
    ///
    /// # Security
    ///
    /// This is the **safe** deserialization path. Always use this for untrusted input.
    pub fn from_bytes(mut bytes: [u8; 32]) -> Option<Element> {
        // Switch from big endian to little endian for arkworks
        bytes.reverse();

        // Construct a point that is on the curve
        let point = Self::get_point_from_x(Fq::deserialize_compressed(&bytes[..]).ok()?, true)?;

        // Check if the point is in the correct subgroup
        if !subgroup_check(&point) {
            return None;
        }

        Some(Element(point))
    }

    /// Serializes this element to a 64-byte uncompressed representation.
    ///
    /// This format stores both x and y coordinates, enabling faster deserialization.
    /// Unlike [`to_bytes()`](Element::to_bytes), this does **not** canonicalize with
    /// respect to the banderwagon quotient group. Equivalent elements `(x, y)` and
    /// `(-x, -y)` will serialize to different byte arrays.
    ///
    /// # Warning
    ///
    /// **Do not compare outputs directly.** Use [`to_bytes()`](Element::to_bytes) for
    /// canonical comparison that respects the equivalence class structure.
    ///
    /// # Returns
    ///
    /// A 64-byte array in little-endian format containing uncompressed point coordinates.
    ///
    /// # Panics
    ///
    /// Panics if serialization fails. This should never occur for valid `Element` instances.
    pub fn to_bytes_uncompressed(&self) -> [u8; 64] {
        let mut bytes = [0u8; 64];
        self.0
            .serialize_uncompressed(&mut bytes[..])
            .expect("cannot serialize point as an uncompressed byte array");
        bytes
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
            EdwardsAffine::from(point).is_on_curve() && subgroup_check(&point),
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
    /// y-coordinate using the twisted Edwards curve equation and returns the point.
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
    /// - `choose_largest`: If `true`, selects the lexicographically larger (positive) y-coordinate;
    ///   if `false`, selects the smaller (negative) y-coordinate
    ///
    /// # Returns
    ///
    /// - `Some(EdwardsProjective)` if a valid curve point exists for the given x
    /// - `None` if `y²` has no square root (x-coordinate not on the curve)
    ///
    /// # Note
    ///
    /// This function does **not** perform subgroup validation. The caller is responsible
    /// for ensuring the resulting point is in the correct subgroup if needed.
    fn get_point_from_x(x: Fq, choose_largest: bool) -> Option<EdwardsProjective> {
        let x_sq = x.square();
        let y_squared = (BandersnatchConfig::COEFF_A * x_sq - Fq::one())
            / (BandersnatchConfig::COEFF_D * x_sq - Fq::one());

        let y = y_squared.sqrt()?;
        let y = if is_positive(y) == choose_largest {
            y
        } else {
            -y
        };

        Some(EdwardsAffine::new_unchecked(x, y).into())
    }

    fn map_to_field(&self) -> Fq {
        self.0.x / self.0.y
    }

    // Note: This is a 2 to 1 map, but the two preimages are identified to be the same
    pub fn map_to_scalar_field(&self) -> Fr {
        use ark_ff::PrimeField;

        let base_field = self.map_to_field();

        let mut bytes = [0u8; 32];
        base_field
            .serialize_compressed(&mut bytes[..])
            .expect("could not serialize point into a 32 byte array");
        Fr::from_le_bytes_mod_order(&bytes)
    }

    pub fn batch_map_to_scalar_field(elements: &[Element]) -> Vec<Fr> {
        use ark_ff::PrimeField;

        let mut x_div_y = Vec::with_capacity(elements.len());
        for element in elements {
            let y = element.0.y;
            x_div_y.push(y);
        }
        batch_inversion(&mut x_div_y);

        for i in 0..elements.len() {
            x_div_y[i] *= elements[i].0.x;
        }

        let mut scalars = Vec::with_capacity(elements.len());
        for element in x_div_y {
            let mut bytes = [0u8; 32];
            element
                .serialize_compressed(&mut bytes[..])
                .expect("could not serialize point into a 32 byte array");
            scalars.push(Fr::from_le_bytes_mod_order(&bytes));
        }

        scalars
    }

    // serial optimized version
    pub fn serial_batch_map_to_scalar_field(elements: Vec<[u8; 64]>) -> Vec<Fr> {
        use ark_ff::PrimeField;

        let (xs, mut ys): (Vec<Fq>, Vec<Fq>) = elements
            .into_iter()
            .map(|e| {
                let e = Element::from_bytes_unchecked_uncompressed(e);
                (e.0.x, e.0.y)
            })
            .unzip();

        serial_batch_inversion_and_mul(&mut ys, &Fq::one());

        ys.iter_mut().zip(xs.iter()).for_each(|(y, x)| {
            *y *= x;
        });

        ys.iter()
            .map(|e| {
                let mut bytes = [0u8; 32];
                e.serialize_compressed(&mut bytes[..])
                    .expect("could not serialize point into a 32 byte array");
                Fr::from_le_bytes_mod_order(&bytes)
            })
            .collect()
    }

    pub fn zero() -> Element {
        Element(EdwardsProjective::zero())
    }

    pub fn is_zero(&self) -> bool {
        *self == Element::zero()
    }
}

// The lexographically largest value is defined to be the positive value
fn is_positive(coordinate: Fq) -> bool {
    coordinate > -coordinate
}

/// Checks whether a point is in the banderwagon prime-order subgroup.
///
/// # Precondition
///
/// Assumes the input point is on the Bandersnatch curve. This only checks subgroup
/// membership by verifying that `1 - ax²` is a quadratic residue.
///
/// # Warning
///
/// Invalid points not on the curve may pass this check. For example, (0, 0) passes
/// because `1 - a·0² = 1` is a QR, despite not being on the curve.
///
/// Used during deserialization to ensure valid banderwagon elements.
fn subgroup_check(point: &EdwardsProjective) -> bool {
    (Fq::one() - BandersnatchConfig::COEFF_A * point.x.square())
        .legendre()
        .is_qr()
}

pub fn multi_scalar_mul(bases: &[Element], scalars: &[Fr]) -> Element {
    let bases_inner: Vec<_> = bases.iter().map(|element| element.0).collect();

    // XXX: Converting all of these to affine hurts performance
    let bases = EdwardsProjective::batch_convert_to_mul_base(&bases_inner);

    let result = EdwardsProjective::msm(&bases, scalars)
        .expect("number of bases should equal number of scalars");

    Element(result)
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
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.to_bytes().hash(state)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_ff::AdditiveGroup;
    use ark_serialize::CanonicalSerialize;

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
    fn from_batch_map_to_scalar_field() {
        let mut points = Vec::new();
        for i in 0..10 {
            points.push(Element::prime_subgroup_generator() * Fr::from(i));
        }

        let got = Element::batch_map_to_scalar_field(&points);

        for i in 0..10 {
            let expected_i = points[i].map_to_scalar_field();
            assert_eq!(expected_i, got[i]);
        }
        for i in 0..10 {
            let expected_i = points[i].map_to_scalar_field();
            assert_eq!(expected_i, got[i]);
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
        let gen2 = gen + gen + gen + gen;

        let res = point + gen + gen2;

        let element1 = Element(res);
        let bytes1 = element1.to_bytes();

        if Element::from_bytes(bytes1).is_some() {
            panic!("point contains a point at infinity and should not have passed deserialization")
        }
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
}
