//! Test utilities for proof module.
//!
//! This module provides common mock data generation functions used across proof tests.

use crate::proof::SerdeCommitment;
use crate::types::SaltValue;
use banderwagon::{Element, Fr};
use rand::{rngs::StdRng, Rng};

/// Generates random test data of specified length.
///
/// This is the primary function for generating mock keys, values, or any
/// other byte arrays needed for testing. The data has no semantic meaning
/// and SALT treats it as opaque bytes.
///
/// # Examples
/// ```ignore
/// let mut rng = StdRng::seed_from_u64(42);
/// let key = mock_data(&mut rng, 20);
/// let value = mock_data(&mut rng, 32);
/// let data = mock_data(&mut rng, 52);
/// ```
pub(crate) fn mock_data(rng: &mut StdRng, len: usize) -> Vec<u8> {
    (0..len).map(|_| rng.gen()).collect()
}

/// Creates a dummy 64-byte cryptographic commitment for testing.
///
/// Used in proof verification tests where actual commitment content doesn't matter.
pub(crate) fn mock_commitment() -> SerdeCommitment {
    SerdeCommitment(Element::prime_subgroup_generator() * Fr::from(42))
}

/// Creates a mock SaltValue for testing.
///
/// Generates a SaltValue with fixed test key and value.
pub(crate) fn mock_salt_value() -> SaltValue {
    SaltValue::new(&[1u8; 32], &[2u8; 32])
}
