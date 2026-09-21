//! Test utilities for proof module.
//!
//! This module provides common mock data generation functions used across proof tests.

use crate::mem_store::MemStore;
use crate::proof::SerdeCommitment;
use crate::state::updates::StateUpdates;
use crate::trie::trie::{StateRoot, TrieUpdates};
use crate::types::SaltValue;
use banderwagon::{Element, Fr};
use rand::{rngs::StdRng, Rng};
use std::vec::Vec;

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
    (0..len).map(|_| rng.random()).collect()
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

/// Applies one block's transition to `store` and returns its trie updates.
pub(crate) fn apply_block(store: &MemStore, updates: StateUpdates) -> TrieUpdates {
    let (_, trie_updates) = StateRoot::new(store).update_fin(&updates).unwrap();
    store.update_state(updates);
    store.update_trie(trie_updates.clone());
    trie_updates
}
