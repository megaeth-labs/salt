//! Plain key proof implementation for Salt trie.
//!
//! This module provides functionality to create and verify proofs for plain keys in the Salt
//! storage system. It handles both existing and non-existing keys by generating inclusion/exclusion
//! proofs that can be cryptographically verified.

use crate::{
    proof::witness::SaltWitness,
    proof::ProofError,
    state::{
        hasher,
        state::{EphemeralSaltState, PlainStateProvider},
    },
    traits::{StateReader, TrieReader},
    types::*,
};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    ops::{Range, RangeInclusive},
};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlainKeysProof {
    // TODO: the builtin serialization mechanism has too much redundant data.
    // e.g., every plain key is stored twice: one in `key_mapping` and one in
    // `salt_witness`.
    /// Mapping from plain keys to their corresponding salt keys (if they exist).
    pub(crate) key_mapping: BTreeMap<Vec<u8>, Option<SaltKey>>,

    /// Low-level SALT witness containing all bucket slots needed for proving the
    /// existence or non-existence of the plain keys and their cryptographic proof.
    pub(crate) salt_witness: SaltWitness,
}

impl PlainKeysProof {
    /// Creates a cryptographic proof for a set of plain keys.
    ///
    /// This method generates inclusion proofs for existing keys and exclusion
    /// proofs for non-existing keys, allowing stateless verification without
    /// full state access.
    ///
    /// # Arguments
    /// * `plain_keys` - The plain keys to create proofs for. Can be any byte
    ///   sequences representing user-provided keys in their original format.
    /// * `store` - The storage backend providing access to both state data
    ///   (key-value pairs) and trie data (cryptographic commitments).
    ///
    /// # Returns
    /// A `PlainKeysProof` containing:
    /// - A mapping from each plain key to its corresponding salt key (if it exists)
    /// - A `SaltWitness` with all state data and cryptographic proofs needed for verification
    ///
    /// # Errors
    /// Returns `ProofError::StateReadError` if:
    /// - Unable to read bucket metadata
    /// - Unable to perform SHI search operations
    /// - Unable to access required state data
    /// - Witness creation fails
    pub fn create<Store>(
        plain_keys: &[Vec<u8>],
        store: &Store,
    ) -> Result<PlainKeysProof, ProofError>
    where
        Store: StateReader + TrieReader,
    {
        let mut witnessed_keys = vec![];
        let mut key_mapping = BTreeMap::new();

        (|| -> Result<(), <Store as StateReader>::Error> {
            // Phase 1: Key Lookup - Find salt keys for each plain key
            let mut state = EphemeralSaltState::new(store);
            for plain_key in plain_keys {
                let bucket_id = hasher::bucket_id(plain_key);
                let metadata = store.metadata(bucket_id)?;

                let salt_key = state
                    .shi_find(bucket_id, metadata.nonce, metadata.capacity, plain_key)?
                    .map(|(slot_id, _)| SaltKey::from((bucket_id, slot_id)));

                key_mapping.insert(plain_key.clone(), salt_key);
            }

            // Phase 2: Witness Collection - Gather all data needed for verification
            let mut recorder = EphemeralSaltState::new(store).cache_read();
            for (plain_key, maybe_salt_key) in key_mapping.iter() {
                match maybe_salt_key {
                    // Non-existing keys: Trigger search to record all accessed slots
                    // This creates exclusion proofs by showing the key's absence
                    None => {
                        recorder.plain_value(plain_key)?;
                    }
                    // Existing keys: Includes their salt keys directly
                    Some(salt_key) => witnessed_keys.push(*salt_key),
                }
            }
            // Include all slots accessed during searches - these form the witness data
            witnessed_keys.extend(recorder.cache.into_keys());

            Ok(())
        })()
        .map_err(|e| ProofError::StateReadError {
            reason: format!("{e:?}"),
        })?;

        Ok(PlainKeysProof {
            key_mapping,
            salt_witness: SaltWitness::create(&witnessed_keys, store)?,
        })
    }

    /// Verifies the cryptographic proof against the given state root.
    ///
    /// This method validates that all plain keys in the proof have the correct
    /// existence status and that the underlying Salt proof is valid.
    ///
    /// # Arguments
    /// * `root` - The state root hash to verify against
    ///
    /// # Returns
    /// * `Ok(())` if the proof is valid
    /// * `Err(ProofError)` if verification fails
    pub fn verify(&self, root: ScalarBytes) -> Result<(), ProofError> {
        // Verify the underlying cryptographic proof using the witness
        self.salt_witness.verify_proof(root)?;

        // Create a fresh ephemeral state for each key to prevent cache interference
        // This ensures that the search process for one key doesn't affect another
        let mut state = EphemeralSaltState::new(&self.salt_witness);

        // Process each plain key individually to determine its status
        for (plain_key, maybe_salt_key) in &self.key_mapping {
            if let Some(salt_key) = maybe_salt_key {
                let maybe_salt_value =
                    self.salt_witness
                        .value(*salt_key)
                        .map_err(|e| ProofError::StateReadError {
                            reason: format!("Witness Failed to read salt value: {e:?}"),
                        })?;
                if let Some(salt_value) = maybe_salt_value {
                    if salt_value.key() != plain_key {
                        return Err(ProofError::StateReadError {
                            reason: format!(
                                "Witness plain key doesn't match, expected: {plain_key:?}, got: {:?}",
                                salt_value.key()
                            ),
                        });
                    }
                } else {
                    return Err(ProofError::StateReadError {
                        reason: format!("Witness salt value shouldn't be None, plain key: {plain_key:?}, salt key {salt_key:?}"),
                    });
                }
            } else {
                let maybe_plain_value =
                    state
                        .plain_value(plain_key)
                        .map_err(|e| ProofError::StateReadError {
                            reason: format!("Failed to read plain value from witness: {e:?}"),
                        })?;
                if maybe_plain_value.is_some() {
                    return Err(ProofError::StateReadError {
                        reason: format!(
                            "Witness plain value should be None, got: {maybe_plain_value:?}, plain key: {plain_key:?}"
                        ),
                    });
                }
            }
        }

        Ok(())
    }
}

// Implementation of StateReader trait for PlainKeysProof
// This allows the proof to be used as a state reader during verification,
// providing only the data that was included in the proof
impl StateReader for PlainKeysProof {
    type Error = &'static str;

    fn value(&self, key: SaltKey) -> Result<Option<SaltValue>, <Self as StateReader>::Error> {
        self.salt_witness.value(key)
    }

    fn entries(
        &self,
        range: RangeInclusive<SaltKey>,
    ) -> Result<Vec<(SaltKey, SaltValue)>, Self::Error> {
        self.salt_witness.entries(range)
    }

    fn metadata(&self, bucket_id: BucketId) -> Result<BucketMeta, Self::Error> {
        self.salt_witness.metadata(bucket_id)
    }

    fn plain_value_fast_path(&self, plain_key: &[u8]) -> Result<Option<SaltKey>, Self::Error> {
        match self.key_mapping.get(plain_key) {
            Some(slot) => Ok(*slot),
            None => Err("Plain key not in witness"),
        }
    }
}

impl PlainStateProvider for PlainKeysProof {
    type Error = &'static str;

    fn plain_value(&mut self, plain_key: &[u8]) -> Result<Option<Vec<u8>>, Self::Error> {
        match self.plain_value_fast_path(plain_key) {
            Ok(Some(salt_key)) => {
                let salt_value = self.value(salt_key)?.unwrap();
                Ok(Some(salt_value.value().to_vec()))
            }
            Ok(None) => Ok(None),
            Err(e) => Err(e),
        }
    }
}

impl TrieReader for PlainKeysProof {
    type Error = &'static str;

    fn commitment(&self, node_id: NodeId) -> Result<CommitmentBytes, Self::Error> {
        self.salt_witness.commitment(node_id)
    }

    fn node_entries(
        &self,
        range: Range<NodeId>,
    ) -> Result<Vec<(NodeId, CommitmentBytes)>, Self::Error> {
        self.salt_witness.node_entries(range)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        constant::NUM_META_BUCKETS,
        mem_store::MemStore,
        mock_evm_types::{Account, PlainKey, PlainValue},
        state::state::EphemeralSaltState,
        trie::trie::StateRoot,
    };
    use alloy_primitives::{Address, B256, U256};
    use iter_tools::Itertools;
    use rand::{rngs::StdRng, Rng, SeedableRng};
    use std::collections::HashMap;

    /// Test helper that extracts all proven values from a PlainKeysProof.
    /// Returns values in the same order as keys appear in the proof's key_mapping.
    pub fn get_proven_values(proof: &mut PlainKeysProof) -> Vec<Option<Vec<u8>>> {
        let keys: Vec<_> = proof.key_mapping.keys().cloned().collect();
        keys.iter()
            .map(|plain_key| proof.plain_value(plain_key).unwrap())
            .collect()
    }

    /// Test serialization and deserialization of PlainKeysProof.
    /// Ensures that proofs can be transmitted and stored reliably.
    #[test]
    fn test_plain_keys_proof_serialize() {
        // Create a test account to insert into Salt storage
        let account1 = Account {
            balance: U256::from(10),
            nonce: 10,
            bytecode_hash: None,
        };

        // Create a key-value pair for the account
        let kvs = HashMap::from([(
            PlainKey::Account(Address::random()).encode(),
            Some(PlainValue::Account(account1).encode()),
        )]);

        // Insert the account into Salt storage and update the trie
        let store = MemStore::new();
        let mut state = EphemeralSaltState::new(&store);
        let state_updates = state.update(&kvs).unwrap();
        store.update_state(state_updates.clone());

        let mut trie = StateRoot::new(&store);
        let (root, trie_updates) = trie.update_fin(state_updates.clone()).unwrap();
        store.update_trie(trie_updates);

        // Generate a proof for the inserted key
        let plain_keys_proof =
            PlainKeysProof::create(&[kvs.keys().next().unwrap().clone()], &store).unwrap();

        // Test serialization round-trip
        let serialized =
            bincode::serde::encode_to_vec(&plain_keys_proof, bincode::config::legacy()).unwrap();
        let deserialized: (PlainKeysProof, usize) =
            bincode::serde::decode_from_slice(&serialized, bincode::config::legacy()).unwrap();

        // Verify the deserialized proof is identical and still valid
        assert_eq!(plain_keys_proof, deserialized.0);
        plain_keys_proof.verify(root).unwrap()
    }

    #[test]
    fn test_plain_key_proof_exist_or_not_exist() {
        // Tests three main scenarios for plain key proof generation:
        //
        // Case 1: Key exists - final slot contains the exact key
        // Test: Insert keys [0..=6], prove key [6]
        //
        // Case 2: Key doesn't exist - final slot contains different key with lower priority
        // Test 2.1: Insert key [6], prove key [0] (higher priority, would displace [6])
        // Test 2.2: Insert keys [6,0], prove key [1] (higher priority than [6])
        // Test 2.3: Insert keys [6,0,2], prove key [1] (higher priority than [2])
        //
        // Case 3: Key doesn't exist - final slot is empty
        // Test 3.1: No insertions, prove key [0]
        // Test 3.2: Insert keys [0..=5], prove key [6] (lands in empty slot)

        // case 1
        let store = MemStore::new();
        let root = insert_kvs(get_plain_keys(vec![0, 1, 2, 3, 4, 5, 6]), &store);

        let plain_key = plain_keys()[6].clone();
        let mut proof = PlainKeysProof::create(&[plain_key.clone()], &store).unwrap();

        assert!(proof.verify(root).is_ok());

        let proof_value = proof.plain_value(&plain_key).unwrap();
        let proof_values = get_proven_values(&mut proof);

        assert!(proof_value.is_some());

        let plain_value = EphemeralSaltState::new(&store)
            .plain_value(&plain_key)
            .unwrap();

        assert_eq!(plain_value, proof_value);
        assert_eq!(proof_values, vec![proof_value]);

        // case 2.1
        let store = MemStore::new();
        let root = insert_kvs(get_plain_keys(vec![6]), &store);

        let plain_key = plain_keys()[0].clone();
        let mut proof = PlainKeysProof::create(&[plain_key.clone()], &store).unwrap();

        assert!(proof.verify(root).is_ok());

        let proof_value = proof.plain_value(&plain_key).unwrap();
        let proof_values = get_proven_values(&mut proof);

        assert!(proof_value.is_none());

        let plain_value = EphemeralSaltState::new(&store)
            .plain_value(&plain_key)
            .unwrap();

        assert_eq!(plain_value, proof_value);
        assert_eq!(proof_values, vec![proof_value]);

        let bucket_id: BucketId = 2448221;
        let slot_id: SlotId = 1;
        let salt_key = SaltKey::from((bucket_id, slot_id));

        // the salt_key stores the plain_keys()[6]'s salt_value
        let salt_value = proof.value(salt_key).unwrap().unwrap();
        // plain_keys()[0] has a high priority than the plain_keys()[6]
        assert!(plain_keys()[0] > plain_keys()[6]);
        assert_eq!(salt_value.key(), plain_keys()[6]);

        let meta = proof.metadata(bucket_id).unwrap();

        let mut proof_state = EphemeralSaltState::new(&proof);
        // can't find the plain_keys()[0]
        let find_res = proof_state
            .shi_find(bucket_id, meta.nonce, meta.capacity, &plain_keys()[0])
            .unwrap();
        assert!(find_res.is_none());

        let find_res = proof_state
            .shi_find(bucket_id, meta.nonce, meta.capacity, &plain_keys()[6])
            .unwrap();
        assert_eq!(find_res, Some((slot_id, salt_value)));

        // case 2.2
        let store = MemStore::new();
        let root = insert_kvs(get_plain_keys(vec![6, 0]), &store);

        let plain_key = plain_keys()[1].clone();
        let mut proof = PlainKeysProof::create(&[plain_key.clone()], &store).unwrap();

        assert!(proof.verify(root).is_ok());

        let proof_value = proof.plain_value(&plain_key).unwrap();
        let proof_values = get_proven_values(&mut proof);

        assert!(proof_value.is_none());

        let plain_value = EphemeralSaltState::new(&store)
            .plain_value(&plain_key)
            .unwrap();

        assert_eq!(plain_value, proof_value);
        assert_eq!(proof_values, vec![proof_value]);

        let bucket_id: BucketId = 2448221;
        let slot_id: SlotId = 2;
        let salt_key = SaltKey::from((bucket_id, slot_id));

        // the salt_key stores the plain_keys()[6]'s salt_value
        let salt_value = proof.value(salt_key).unwrap().unwrap();
        assert_eq!(salt_value.key(), plain_keys()[6]);
        // plain_keys()[1] has a high priority than the plain_keys()[6]
        assert!(plain_keys()[1] > salt_value.key().to_vec());

        let meta = proof.metadata(bucket_id).unwrap();

        let mut proof_state = EphemeralSaltState::new(&proof).cache_read();
        // can't find the plain_keys()[1]
        let find_res = proof_state
            .shi_find(bucket_id, meta.nonce, meta.capacity, &plain_keys()[1])
            .unwrap();
        assert!(find_res.is_none());

        let mut related_keys: Vec<SaltKey> = proof_state
            .cache
            .iter()
            .filter_map(|(k, _)| (k.bucket_id() > NUM_META_BUCKETS as u32).then_some(*k))
            .collect();

        related_keys.sort_unstable();
        assert_eq!(related_keys, vec![SaltKey::from((bucket_id, 2))]);

        // case 2.3
        let store = MemStore::new();
        let root = insert_kvs(get_plain_keys(vec![6, 0, 2]), &store);

        let plain_key = plain_keys()[1].clone();
        let mut proof = PlainKeysProof::create(&[plain_key.clone()], &store).unwrap();

        assert!(proof.verify(root).is_ok());

        let proof_value = proof.plain_value(&plain_key).unwrap();
        let proof_values = get_proven_values(&mut proof);

        assert!(proof_value.is_none());

        let plain_value = EphemeralSaltState::new(&store)
            .plain_value(&plain_key)
            .unwrap();

        assert_eq!(plain_value, proof_value);
        assert_eq!(proof_values, vec![proof_value]);

        let bucket_id: BucketId = 2448221;
        let slot_id: SlotId = 2;
        let salt_key = SaltKey::from((bucket_id, slot_id));

        // the salt_key stores the plain_keys()[2]'s salt_value
        let salt_value = proof.value(salt_key).unwrap().unwrap();
        assert_eq!(salt_value.key(), plain_keys()[2]);
        // plain_keys()[1] has a high priority than the plain_keys()[6]
        assert!(plain_keys()[1] > salt_value.key().to_vec());

        let meta = proof.metadata(bucket_id).unwrap();

        let mut proof_state = EphemeralSaltState::new(&store);
        // can't find the plain_keys()[1]
        let find_res = proof_state
            .shi_find(bucket_id, meta.nonce, meta.capacity, &plain_keys()[1])
            .unwrap();
        assert!(find_res.is_none());

        let find_res = proof_state
            .shi_find(bucket_id, meta.nonce, meta.capacity, &plain_keys()[2])
            .unwrap();
        assert_eq!(find_res, Some((slot_id, salt_value)));

        // case 3.1
        let store = MemStore::new();
        let root = insert_kvs(get_plain_keys(vec![]), &store);

        let plain_key = plain_keys()[0].clone();
        let mut proof = PlainKeysProof::create(&[plain_key.clone()], &store).unwrap();

        assert!(proof.verify(root).is_ok());

        let proof_value = proof.plain_value(&plain_key).unwrap();
        let proof_values = get_proven_values(&mut proof);

        assert!(proof_value.is_none());

        let plain_value = EphemeralSaltState::new(&store)
            .plain_value(&plain_key)
            .unwrap();

        assert_eq!(plain_value, proof_value);
        assert_eq!(proof_values, vec![proof_value]);

        let bucket_id: BucketId = 2448221;
        let slot_id: SlotId = 1;
        let salt_key = SaltKey::from((bucket_id, slot_id));

        // the salt_key stores none value
        let salt_value = proof.value(salt_key).unwrap();
        assert!(salt_value.is_none());

        let meta = proof.metadata(bucket_id).unwrap();

        let mut proof_state = EphemeralSaltState::new(&store);
        // can't find the plain_keys()[0]
        let find_res = proof_state
            .shi_find(bucket_id, meta.nonce, meta.capacity, &plain_keys()[0])
            .unwrap();
        assert!(find_res.is_none());

        // case 3.2
        let store = MemStore::new();
        let root = insert_kvs(get_plain_keys(vec![0, 1, 2, 3, 4, 5]), &store);

        let plain_key = plain_keys()[6].clone();
        let mut proof = PlainKeysProof::create(&[plain_key.clone()], &store).unwrap();

        assert!(proof.verify(root).is_ok());

        let proof_value = proof.plain_value(&plain_key).unwrap();
        let proof_values = get_proven_values(&mut proof);

        assert!(proof_value.is_none());

        let plain_value = EphemeralSaltState::new(&store)
            .plain_value(&plain_key)
            .unwrap();

        assert_eq!(plain_value, proof_value);
        assert_eq!(proof_values, vec![proof_value]);

        let bucket_id: BucketId = 2448221;
        let slot_id: SlotId = 7;
        let salt_key = SaltKey::from((bucket_id, slot_id));

        // the salt_key stores the plain_keys()[6]'s salt_value
        let salt_value = proof.value(salt_key).unwrap();
        assert!(salt_value.is_none());

        let meta = proof.metadata(bucket_id).unwrap();

        let mut proof_state = EphemeralSaltState::new(&proof).cache_read();
        // can't find the plain_keys()[1]
        let find_res = proof_state
            .shi_find(bucket_id, meta.nonce, meta.capacity, &plain_keys()[6])
            .unwrap();
        assert!(find_res.is_none());

        let mut related_keys: Vec<SaltKey> = proof_state
            .cache
            .iter()
            .filter_map(|(k, _)| (k.bucket_id() > NUM_META_BUCKETS as u32).then_some(*k))
            .collect();

        related_keys.sort_unstable();

        assert_eq!(
            related_keys,
            vec![
                SaltKey::from((bucket_id, 1)),
                SaltKey::from((bucket_id, 2)),
                SaltKey::from((bucket_id, 3)),
                SaltKey::from((bucket_id, 4)),
                SaltKey::from((bucket_id, 5)),
                SaltKey::from((bucket_id, 6)),
                SaltKey::from((bucket_id, 7)),
            ]
        );
    }

    #[test]
    fn test_plain_key_proof_in_loop_slot_id() {
        let store = MemStore::new();
        let root = insert_kvs(get_plain_keys(vec![9]), &store);

        let key = plain_keys()[7].clone();

        let proof = PlainKeysProof::create(&[key.clone()], &store).unwrap();

        assert!(proof.verify(root).is_ok());

        let bucket_id = 4030087;
        let salt_key = SaltKey::from((bucket_id, 0));

        let salt_value = proof.value(salt_key).unwrap();
        assert!(salt_value.is_none());

        let meta = proof.metadata(bucket_id).unwrap();

        let mut proof_state = EphemeralSaltState::new(&proof).cache_read();
        // can't find the plain_keys()[1]
        let find_res = proof_state
            .shi_find(bucket_id, meta.nonce, meta.capacity, &key)
            .unwrap();
        assert!(find_res.is_none());

        let mut related_keys: Vec<SaltKey> = proof_state
            .cache
            .iter()
            .filter_map(|(k, _)| (k.bucket_id() > NUM_META_BUCKETS as u32).then_some(*k))
            .collect();

        related_keys.sort_unstable();

        assert_eq!(
            related_keys,
            vec![
                SaltKey::from((bucket_id, 0)),
                SaltKey::from((bucket_id, 255))
            ]
        );

        // another case
        let store = MemStore::new();
        let root = insert_kvs(get_plain_keys(vec![7, 8, 9]), &store);

        let key = plain_keys()[8].clone();

        let proof = PlainKeysProof::create(&[key.clone()], &store).unwrap();

        assert!(proof.verify(root).is_ok());

        assert_eq!(proof.key_mapping.keys().next().unwrap(), &key);

        let salt_key = SaltKey::from((bucket_id, 1));
        let salt_value = proof.value(salt_key).unwrap().unwrap();

        let salt_val = store.value(salt_key).unwrap().unwrap();

        assert_eq!(salt_value, salt_val);
    }

    /// Test that PlainKeysProof correctly implements StateReader trait.
    /// Verifies that the proof contains the same data as the original state.
    #[test]
    fn test_state_reader_for_plain_keys_proof() {
        let l = 100;
        let mut rng = StdRng::seed_from_u64(42);
        let mut kvs = HashMap::new();

        // Generate random account data for half the test cases
        (0..l / 2).for_each(|_| {
            let pk = PlainKey::Account(Address::random_with(&mut rng)).encode();
            let pv = Some(
                PlainValue::Account(Account {
                    balance: U256::from(rng.gen_range(0..1000)),
                    nonce: rng.gen_range(0..100),
                    bytecode_hash: None,
                })
                .encode(),
            );
            kvs.insert(pk, pv);
        });

        // Generate random storage data for the other half
        (l / 2..l).for_each(|_| {
            let pk = PlainKey::Storage(Address::random_with(&mut rng), B256::random_with(&mut rng))
                .encode();
            let pv = Some(PlainValue::Storage(B256::random_with(&mut rng).into()).encode());
            kvs.insert(pk, pv);
        });

        let store = MemStore::new();
        let mut state = EphemeralSaltState::new(&store);
        let updates = state.update(&kvs).unwrap();
        store.update_state(updates.clone());

        let (_, trie_updates) = StateRoot::new(&store).update_fin(updates).unwrap();

        store.update_trie(trie_updates);

        let plain_keys_proof =
            PlainKeysProof::create(&kvs.keys().cloned().collect::<Vec<_>>(), &store).unwrap();

        for key in plain_keys_proof.salt_witness.kvs.keys() {
            let proof_value = plain_keys_proof.value(*key).unwrap();
            let mut state_value = state.value(*key).unwrap();
            if state_value.is_none() && key.is_in_meta_bucket() {
                state_value = Some(BucketMeta::default().into());
            }
            assert_eq!(proof_value, state_value);
        }
    }

    #[test]
    fn test_plain_key_exist_proof_should_without_bucket_meta() {
        let store = MemStore::new();
        let root = insert_kvs(get_plain_keys(vec![7, 8, 9]), &store);

        let keys = get_plain_keys(vec![7, 8, 9]);
        let proof = PlainKeysProof::create(&keys, &store).unwrap();

        assert!(proof.verify(root).is_ok());

        assert_eq!(proof.key_mapping.len(), 3);
        assert_eq!(proof.salt_witness.kvs.len(), 3);

        let salt_keys = proof.salt_witness.kvs.keys().copied().collect::<Vec<_>>();
        let salt_keys2 = proof
            .key_mapping
            .values()
            .map(|v| v.unwrap())
            .sorted_unstable()
            .collect::<Vec<_>>();

        assert_eq!(salt_keys, salt_keys2);
    }

    /// Helper function to get a subset of test keys by their indices.
    fn get_plain_keys(index: Vec<usize>) -> Vec<Vec<u8>> {
        index
            .into_iter()
            .map(|v| plain_keys()[v].clone())
            .collect::<Vec<_>>()
    }

    /// Helper function to insert key-value pairs and return the resulting state root.
    fn insert_kvs(plain_keys: Vec<Vec<u8>>, store: &MemStore) -> [u8; 32] {
        let kvs = plain_keys
            .iter()
            .map(|k| (k.clone(), Some(k[0..20].to_vec())))
            .collect::<HashMap<_, _>>();

        let state_updates = EphemeralSaltState::new(store).update(&kvs).unwrap();

        store.update_state(state_updates.clone());

        let mut trie = StateRoot::new(store);
        let (root, trie_updates) = trie.update_fin(state_updates.clone()).unwrap();

        store.update_trie(trie_updates);
        root
    }

    /// Returns 10 predefined test keys with known bucket/slot mappings.
    ///
    /// When all keys are inserted, their storage locations are:
    /// ```
    /// Index:    [0,       1,       2,       3,       4,       5,       6,       7,       8,       9]
    /// Bucket:   [2448221, 2448221, 2448221, 2448221, 2448221, 2448221, 2448221, 4030087, 4030087, 4030087]
    /// Slot:     [1,       2,       3,       4,       5,       6,       7,       0,       1,       255]
    /// ```
    ///
    /// Insertion conflicts (keys that need comparison during insertion):
    /// - key[2]: compares with slots 2,3
    /// - key[4]: compares with slots 4,5
    /// - key[6]: compares with slots 1,2,3,4,5,6,7
    /// - key[7]: compares with slots 255,0
    /// - key[8]: compares with slots 255,0,1
    fn plain_keys() -> Vec<Vec<u8>> {
        vec![
            vec![
                48, 1, 62, 32, 116, 157, 191, 48, 139, 176, 173, 251, 201, 192, 82, 146, 212, 212,
                72, 62, 42, 70, 230, 98, 153, 254, 5, 225, 54, 96, 119, 133, 13, 215, 150, 9, 239,
                78, 219, 57, 82, 47, 114, 62, 236, 212, 57, 81, 129, 32, 94, 28,
            ],
            vec![
                154, 221, 159, 18, 92, 229, 18, 12, 78, 44, 173, 46, 157, 25, 86, 74, 216, 124,
                123, 179, 73, 164, 70, 136, 156, 92, 251, 144, 116, 127, 24, 118, 238, 22, 158,
                125, 220, 88, 65, 208, 178, 202, 229, 44, 56, 87, 12, 136, 239, 134, 175, 120,
            ],
            vec![
                52, 220, 58, 90, 110, 77, 173, 74, 122, 102, 155, 171, 25, 2, 104, 65, 76, 187,
                122, 62,
            ],
            vec![
                164, 97, 20, 34, 94, 46, 59, 72, 254, 212, 177, 227, 38, 87, 20, 201, 80, 119, 63,
                148, 109, 7, 147, 15, 168, 242, 212, 100, 160, 114, 171, 80, 130, 82, 98, 215, 183,
                116, 78, 225, 48, 74, 210, 145, 191, 5, 202, 254, 206, 141, 251, 140,
            ],
            vec![
                37, 229, 167, 117, 247, 21, 40, 63, 212, 58, 225, 130, 62, 135, 163, 144, 210, 234,
                213, 243, 231, 221, 164, 152, 71, 179, 252, 229, 81, 170, 6, 206, 191, 153, 67,
                182, 67, 89, 82, 210, 22, 233, 56, 198, 208, 249, 164, 178, 27, 240, 162, 215,
            ],
            vec![
                179, 236, 188, 23, 90, 152, 46, 106, 112, 142, 244, 94, 214, 218, 253, 19, 104,
                147, 240, 226, 229, 175, 205, 249, 122, 208, 184, 248, 71, 252, 137, 173, 130, 37,
                47, 60, 197, 229, 225, 64, 209, 91, 80, 107, 188, 104, 249, 49, 219, 252, 212, 177,
            ],
            vec![
                2, 13, 181, 123, 127, 242, 138, 79, 226, 65, 186, 108, 10, 174, 161, 222, 31, 234,
                49, 177, 125, 148, 69, 98, 190, 26, 78, 124, 211, 119, 56, 133, 8, 197, 31, 181,
                53, 116, 123, 38, 95, 216, 90, 175, 5, 20, 221, 160, 98, 197, 192, 6,
            ],
            vec![
                149, 45, 146, 81, 212, 25, 86, 33, 50, 177, 251, 62, 110, 80, 177, 245, 126, 152,
                112, 52, 48, 128, 16, 227, 225, 129, 23, 220, 122, 36, 0, 26, 162, 51, 114, 163,
                100, 158, 146, 215, 211, 73, 30, 181, 160, 174, 176, 38, 52, 169, 255, 10,
            ],
            vec![
                66, 233, 111, 188, 160, 150, 80, 85, 10, 41, 149, 150, 89, 107, 41, 216, 5, 8, 255,
                4, 206, 232, 49, 88, 39, 218, 35, 43, 73, 131, 95, 92, 236, 144, 32, 159, 181, 216,
                21, 171, 177, 129, 249, 202, 223, 90, 237, 11, 55, 229, 229, 12,
            ],
            vec![
                159, 161, 59, 17, 118, 13, 243, 71, 32, 130, 21, 45, 24, 198, 214, 98, 137, 205,
                191, 172, 198, 20, 132, 194, 250, 133, 217, 69, 40, 45, 250, 235, 159, 64, 10, 79,
                142, 17, 252, 205, 83, 197, 51, 40, 108, 213, 83, 79, 193, 236, 57, 140,
            ],
        ]
    }
}
