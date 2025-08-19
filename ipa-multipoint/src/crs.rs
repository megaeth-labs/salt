//! Common Reference String (CRS) implementation for polynomial commitments.
//!
//! This module provides the CRS structure used in Pedersen commitments.
//!
//! The CRS consists of:
//! - A vector of generator points `G` for committing to polynomial coefficients
//! - A separate generator point `Q` used to hide the committed values
//!
//! The points are generated deterministically from a seed using a hash-to-curve
//! approach, ensuring reproducibility and verifiability of the setup.

use crate::{default_crs, ipa::slow_vartime_multiscalar_mul, lagrange_basis::LagrangeBasis};
use banderwagon::{try_reduce_to_element, Element};

/// Common Reference String for the Pedersen commitment scheme.
#[allow(non_snake_case)]
#[derive(Debug, Clone)]
pub struct CRS {
    /// Capacity of the CRS (i.e., the maximum size of a vector that can be
    /// committed to using this CRS)
    pub n: usize,
    /// An array of `n` value-binding generators.
    pub G: Vec<Element>,
    /// Blinding generator.
    pub Q: Element,
}

impl Default for CRS {
    fn default() -> Self {
        CRS::from_hex(&default_crs::HEX_ENCODED_CRS)
    }
}

impl CRS {
    /// Creates a new CRS from the given seed.
    ///
    /// # Arguments
    /// * `n` - Capacity of the CRS
    /// * `seed` - Deterministic seed for point generation
    ///
    /// # Returns
    /// A cryptographically secure CRS
    #[allow(non_snake_case)]
    pub fn new(n: usize, seed: &'static [u8]) -> CRS {
        // Generate n+1 points: n for G and 1 for Q
        let all_points = generate_random_elements(n + 1, seed);
        let (G, q_slice) = all_points.split_at(n);
        let G = G.to_vec();
        let Q = q_slice[0];

        CRS::assert_dedup(&all_points);

        CRS { n, G, Q }
    }

    /// Returns the maximum number of elements that can be committed to.
    pub fn max_number_of_elements(&self) -> usize {
        self.n
    }

    /// Reconstructs a CRS from a byte array representation.
    ///
    /// The byte array should contain serialized elliptic curve points,
    /// where the last element represents `Q` and all preceding elements represent `G`.
    ///
    /// # Arguments
    /// * `bytes` - Array of 64-byte uncompressed point representations
    ///
    /// # Returns
    /// A CRS reconstructed from the byte data
    #[allow(non_snake_case)]
    pub fn from_bytes(bytes: &[[u8; 64]]) -> CRS {
        let (q_bytes, g_vec_bytes) = bytes
            .split_last()
            .expect("bytes vector should not be empty");

        let Q = Element::from_bytes_unchecked_uncompressed(*q_bytes);
        let G: Vec<_> = g_vec_bytes
            .iter()
            .map(|bytes| Element::from_bytes_unchecked_uncompressed(*bytes))
            .collect();
        let n = G.len();
        CRS { G, Q, n }
    }

    /// Reconstructs a CRS from hex-encoded string representations.
    ///
    /// # Arguments
    /// * `hex_encoded_crs` - Array of hex strings representing elliptic curve points
    ///
    /// # Returns
    /// A CRS reconstructed from the hex-encoded data
    pub fn from_hex(hex_encoded_crs: &[&str]) -> CRS {
        let bytes: Vec<[u8; 64]> = hex_encoded_crs
            .iter()
            .map(|hex| hex::decode(hex).unwrap())
            .map(|byte_vector| byte_vector.try_into().unwrap())
            .collect();
        CRS::from_bytes(&bytes)
    }

    /// Serializes the CRS to a vector of byte arrays.
    ///
    /// Each elliptic curve point is serialized to 64 bytes in uncompressed format.
    /// The `G` points come first, followed by the `Q` point.
    ///
    /// # Returns
    /// Vector of 64-byte arrays representing the CRS points
    pub fn to_bytes(&self) -> Vec<[u8; 64]> {
        let mut bytes = Vec::with_capacity(self.n + 1);
        for point in &self.G {
            bytes.push(point.to_bytes_uncompressed());
        }
        bytes.push(self.Q.to_bytes_uncompressed());
        bytes
    }

    /// Serializes the CRS to hex-encoded strings.
    ///
    /// # Returns
    /// Vector of hex strings representing the CRS points
    pub fn to_hex(&self) -> Vec<String> {
        self.to_bytes().iter().map(hex::encode).collect()
    }

    /// Asserts that none of the generated points are duplicates.
    ///
    /// This is a critical security check to ensure the CRS has full rank.
    /// Duplicate points would compromise the binding property of commitments.
    fn assert_dedup(points: &[Element]) {
        use std::collections::HashSet;
        let mut map = HashSet::new();
        for point in points {
            let value_is_new = map.insert(point.to_bytes());
            assert!(value_is_new, "crs has duplicated points")
        }
    }

    /// Commits to a polynomial in Lagrange basis form.
    ///
    /// Computes the commitment as a linear combination of the CRS generators
    /// with the polynomial coefficients as scalars.
    ///
    /// # Arguments
    /// * `polynomial` - Polynomial in Lagrange basis to commit to
    ///
    /// # Returns
    /// The elliptic curve point representing the polynomial commitment
    pub fn commit_lagrange_poly(&self, polynomial: &LagrangeBasis) -> Element {
        slow_vartime_multiscalar_mul(polynomial.values().iter(), self.G.iter())
    }
}

impl std::ops::Index<usize> for CRS {
    type Output = Element;

    fn index(&self, index: usize) -> &Self::Output {
        &self.G[index]
    }
}

/// Generates cryptographically secure random elliptic curve points.
///
/// Uses a deterministic hash-to-curve approach where each point is derived by:
/// 1. Hashing the seed concatenated with an index using SHA-256
/// 2. Attempting to map the hash output to a valid curve point
/// 3. Repeating with incremented index until enough valid points are found
///
/// This approach ensures:
/// - Deterministic generation from the same seed
/// - Cryptographic randomness properties
/// - No known discrete log relationships between points
///
/// # Arguments
/// * `num_required_points` - Number of points to generate
/// * `seed` - Deterministic seed for point generation
///
/// # Returns
/// Vector of cryptographically random elliptic curve points
fn generate_random_elements(num_required_points: usize, seed: &'static [u8]) -> Vec<Element> {
    use sha2::{Digest, Sha256};

    // The methodology for deriving the CRS is documented at:
    //   https://hackmd.io/1RcGSMQgT4uREaq1CCx_cg
    // However, the point finding strategy is a bit different now
    // as we are using banderwagon.

    let _choose_largest = false;

    // Hash the seed + index to get a candidate point value
    let hash_to_x = |index: u64| -> Vec<u8> {
        let mut hasher = Sha256::new();
        hasher.update(seed);
        hasher.update(index.to_be_bytes());
        let bytes: Vec<u8> = hasher.finalize().to_vec();
        bytes
    };

    (0u64..)
        .map(hash_to_x)
        .filter_map(|hash_bytes| try_reduce_to_element(&hash_bytes))
        .take(num_required_points)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Verifies deterministic CRS generation produces expected points.
    ///
    /// Checks specific point values and an aggregate hash to ensure the
    /// hash-to-curve algorithm remains consistent with the reference implementation.
    #[test]
    fn crs_consistency() {
        use sha2::{Digest, Sha256};

        let points = generate_random_elements(256, b"MAKE_ETHEREUM_GREAT_AGAIN");

        let bytes = points[0].to_bytes();
        assert_eq!(
            hex::encode(bytes),
            "2816c0c3ac2555ec31fd5790f97bec3ec9b87d25136507bae595567416e76b80",
            "the first point is incorrect"
        );
        let bytes = points[255].to_bytes();
        assert_eq!(
            hex::encode(bytes),
            "046e3ca0b403c4bb91b27583d57d305945cae298ce18386cd0c0a0d5d76871ab",
            "the 256th (last) point is incorrect"
        );

        let mut hasher = Sha256::new();
        for point in &points {
            let bytes = point.to_bytes();
            hasher.update(bytes);
        }
        let bytes = hasher.finalize().to_vec();
        assert_eq!(
            hex::encode(bytes),
            "e0d59418bbe04c1f4ec7493a9ed30497982d4ab5480d68b5e8ce426dd756d136",
            "unexpected point encountered"
        );
    }

    /// Tests round-trip serialization consistency for CRS byte encoding.
    ///
    /// Verifies that serializing a CRS to bytes and deserializing back
    /// produces identical byte representations.
    #[test]
    fn load_from_bytes_to_bytes() {
        let crs = CRS::new(256, b"eth_verkle_oct_2021");
        let bytes = crs.to_bytes();
        let crs2 = CRS::from_bytes(&bytes);
        let bytes2 = crs2.to_bytes();

        assert_eq!(
            bytes, bytes2,
            "Round-trip serialization must preserve all data"
        );
    }
}
