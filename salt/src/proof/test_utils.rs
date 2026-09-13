//! Test utilities for proof module.
//!
//! This module provides common mock data generation functions used across proof tests.

use crate::mem_store::MemStore;
use crate::proof::SerdeCommitment;
use crate::state::{state::EphemeralSaltState, updates::StateUpdates};
use crate::trie::trie::{StateRoot, TrieUpdates};
use crate::types::SaltValue;
use banderwagon::{Element, Fr};
use hashbrown::HashMap;
use rand::{rngs::StdRng, Rng, SeedableRng};
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

/// A store holding block A (64 random plain kvs), and block B's transition over it (16 value
/// updates, 8 deletes and 16 inserts) computed but not applied.
pub(crate) struct TwoBlocks {
    pub store: MemStore,
    /// Block B's plain writes.
    pub kvs_b: HashMap<Vec<u8>, Option<Vec<u8>>>,
    pub updates_b: StateUpdates,
    pub trie_b: TrieUpdates,
}

/// Builds [`TwoBlocks`] from `seed`.
pub(crate) fn two_block_fixture(seed: u64) -> TwoBlocks {
    let mut rng = StdRng::seed_from_u64(seed);
    let kvs_a: HashMap<Vec<u8>, Option<Vec<u8>>> = (0..64)
        .map(|_| (mock_data(&mut rng, 20), Some(mock_data(&mut rng, 40))))
        .collect();
    let store = MemStore::new();
    let updates_a = EphemeralSaltState::new(&store).update_fin(&kvs_a).unwrap();
    apply_block(&store, updates_a);

    let mut keys_a: Vec<Vec<u8>> = kvs_a.into_keys().collect();
    keys_a.sort();
    let mut kvs_b: HashMap<Vec<u8>, Option<Vec<u8>>> = HashMap::new();
    for key in &keys_a[..16] {
        kvs_b.insert(key.clone(), Some(mock_data(&mut rng, 40)));
    }
    for key in &keys_a[16..24] {
        kvs_b.insert(key.clone(), None);
    }
    for _ in 0..16 {
        kvs_b.insert(mock_data(&mut rng, 20), Some(mock_data(&mut rng, 40)));
    }
    let updates_b = EphemeralSaltState::new(&store).update_fin(&kvs_b).unwrap();
    let (_, trie_b) = StateRoot::new(&store).update_fin(&updates_b).unwrap();
    TwoBlocks {
        store,
        kvs_b,
        updates_b,
        trie_b,
    }
}
