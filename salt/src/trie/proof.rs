//! Plain key proof implementation for Salt trie.
//!
//! This module provides functionality to create and verify proofs for plain keys in the Salt
//! storage system. It handles both existing and non-existing keys by generating inclusion/exclusion
//! proofs that can be cryptographically verified.

use crate::{
    constant::TRIE_WIDTH_BITS,
    proof::{prover, ProofError},
    state::{
        hasher,
        state::{probe, EphemeralSaltState},
    },
    traits::{StateReader, TrieReader},
    trie::witness::BlockWitness,
    types::*,
};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    ops::{Range, RangeInclusive},
};

/// Creates cryptographic proofs for the given plain keys.
///
/// Salt uses a mapping: `salt_key => salt_value(plain_key, plain_value)` where the salt_key
/// is derived from `hash(plain_key, tree_state)`.
///
/// ## Key States
/// Plain keys can exist in two states:
/// - **Existed**: Key is stored in a Salt slot with its corresponding value
/// - **NotExisted**: Key is not present in any Salt slot
///
/// ## Proof Generation Process
///
/// ### For Existing Keys
/// 1. Locate the salt_key and salt_value pair
/// 2. Generate a SaltProof for the pair
/// 3. Verify that salt_value contains the expected plain_key
///
/// ### For Non-Existing Keys
/// 1. Calculate the optimal slot using the hash function
/// 2. Follow Salt's insertion algorithm to find the final slot position
/// 3. Record all accessed slots during traversal for proof reconstruction
/// 4. The final slot may be:
///    - The optimal slot (if empty or contains lower priority key)
///    - A subsequent slot (if optimal slot contains higher priority key)
///
/// All accessed salt keys, values, and bucket metadata are included in the proof
/// to enable verification of the insertion process.
pub fn create_proof<Store>(
    keys: &[Vec<u8>],
    store: &Store,
) -> Result<PlainKeysProof, ProofError<Store>>
where
    Store: StateReader + TrieReader,
{
    // Initialize collections to store proof data
    let mut status = Vec::with_capacity(keys.len()); // Status of each key (existed/not existed)
    let mut metas: BTreeMap<BucketId, Option<BucketMeta>> = BTreeMap::new(); // Bucket metadata needed for verification
    let mut sub_state: BTreeMap<SaltKey, Option<SaltValue>> = BTreeMap::new(); // Salt key-value pairs accessed during proof

    // Process each plain key individually to determine its status
    for key_buf in keys {
        // Create a fresh ephemeral state for each key to prevent cache interference
        // This ensures that the search process for one key doesn't affect another
        let mut state = EphemeralSaltState::new(store).cache_read();

        // Calculate which bucket this key belongs to using the hash function
        let bucket_id = hasher::bucket_id(key_buf);

        // Retrieve the bucket's metadata (capacity, nonce, etc.)
        let meta = store
            .metadata(bucket_id)
            .map_err(ProofError::ReadStateFailed)?;

        // Attempt to find the key in the Salt storage using the insertion algorithm
        // Returns Some((slot_id, salt_value)) if found, None if not found
        let slot_id = state
            .shi_find(bucket_id, meta.nonce, meta.capacity, key_buf)
            .map_err(ProofError::ReadStateFailed)?;

        match slot_id {
            // Case 1: Key exists - found at a specific slot with its value
            Some((slot_id, salt_value)) => {
                // Convert bucket_id and slot_id into a salt_key for the proof
                let salt_key = SaltKey::from((bucket_id, slot_id));

                // Record that this key exists and store the salt key-value pair
                status.push(PlainKeyStatus::Existed(salt_key));
                sub_state.insert(salt_key, Some(salt_value));
            }

            // Case 2: Key doesn't exist - need to prove non-existence
            None => {
                // The cache contains all slots that were accessed during the find operation
                // This is crucial for recreating the search path during verification
                let cache = &state.cache;
                if cache.is_empty() {
                    return Err(ProofError::ProveFailed(
                        "EphemeralSaltState cache is empty".to_string(),
                    ));
                }

                // Calculate the optimal slot where this key would be inserted
                // This is the starting point of Salt's linear probing algorithm
                let optimal_slot_id = probe(
                    hasher::hash_with_nonce(key_buf, meta.nonce),
                    0,
                    meta.capacity,
                );

                // Determine the final slot where the key would be inserted
                // This logic handles bucket capacity wraparound for linear probing
                let final_slot_id_salt_key = if optimal_slot_id + cache.len() as u64 > meta.capacity
                {
                    // Wraparound case: the search wrapped around the bucket boundary
                    // Calculate the final position using modular arithmetic
                    (
                        bucket_id,
                        (optimal_slot_id + cache.len() as u64 - 1) & (meta.capacity - 1),
                    )
                        .into()
                } else {
                    // Normal case: the search didn't wrap around
                    // The final slot is the maximum key in the cache (last accessed slot)
                    cache
                        .keys()
                        .max()
                        .cloned()
                        .ok_or(ProofError::ProveFailed("cache is empty".to_string()))?
                };

                // Record non-existence and include all necessary data for verification
                status.push(PlainKeyStatus::NotExisted(final_slot_id_salt_key));
                metas.insert(bucket_id, Some(meta)); // Bucket metadata needed for verification
                sub_state.extend(cache.iter().map(|(k, v)| (*k, v.clone()))); // All accessed slots
            }
        };
    }

    // Collect all salt keys that need to be included in the cryptographic proof
    // This includes both metadata keys and data keys accessed during the search
    let mut salt_keys = Vec::with_capacity(metas.len() + sub_state.len());

    // Add metadata keys: convert bucket_id to salt_key format for bucket metadata
    // The bit manipulation extracts the trie node ID and metadata slot within that node
    salt_keys.extend(
        metas
            .keys()
            .map(|&k| SaltKey::from((k >> TRIE_WIDTH_BITS, (k & 0xFF) as u64))),
    );

    // Add all data salt keys that were accessed during the proof generation
    salt_keys.extend(sub_state.keys().copied());

    // Generate the underlying cryptographic proof for all the salt keys and values
    // This creates a Merkle proof that these specific key-value pairs exist in the trie
    let proof = prover::create_salt_proof(&salt_keys, store)?;

    // Create a BlockWitness from the collected data
    let witness = BlockWitness {
        metadata: metas,
        kvs: sub_state,
        proof,
    };

    // Construct the final proof structure containing all necessary verification data
    Ok(PlainKeysProof {
        keys: keys.to_vec(), // The original plain keys being proved
        status,              // Existence status for each key
        witness,             // Block witness containing all state data and cryptographic proof
    })
}

/// Status of a plain key in the Salt storage system.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum PlainKeyStatus {
    /// Key exists in the storage at the specified salt key location.
    Existed(SaltKey),
    /// Key does not exist; the salt key indicates where it would be inserted.
    NotExisted(SaltKey),
}

/// Cryptographic proof for a set of plain keys.
///
/// This structure contains all necessary data to verify the existence or non-existence
/// of plain keys in the Salt storage system without access to the full state.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlainKeysProof {
    /// The plain keys being proved.
    pub(crate) keys: Vec<Vec<u8>>,
    /// The existence status for each corresponding plain key.
    pub(crate) status: Vec<PlainKeyStatus>,
    /// Block witness containing all state data and cryptographic proof.
    pub(crate) witness: BlockWitness,
}

impl PlainKeysProof {
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
    pub fn verify(&self, root: [u8; 32]) -> Result<(), ProofError<Self>> {
        // Sanity check: ensure each key has a corresponding status
        if self.keys.len() != self.status.len() {
            return Err(ProofError::VerifyFailed(
                "keys and status length mismatch".to_string(),
            ));
        }

        // Early validation: check if all required data is present
        if self.witness.kvs.is_empty() && self.witness.metadata.is_empty() {
            return Err(ProofError::VerifyFailed(
                "proof contains no data".to_string(),
            ));
        }

        // Verify the underlying cryptographic proof using the witness
        self.witness.verify_proof(root).map_err(|e| match e {
            ProofError::VerifyFailed(msg) => ProofError::VerifyFailed(msg),
            ProofError::ProveFailed(msg) => ProofError::ProveFailed(msg),
            ProofError::ReadStateFailed(_) => {
                ProofError::VerifyFailed("witness verification failed".to_string())
            }
            ProofError::ReadTrieFailed(_) => {
                ProofError::VerifyFailed("witness trie verification failed".to_string())
            }
        })?;

        // Verify each individual plain key according to its claimed status
        for (pkey, status) in self.keys.iter().zip(self.status.iter()) {
            match status {
                // Verification for keys claimed to exist
                PlainKeyStatus::Existed(salt_key) => {
                    // The salt_key should be always in sub_state instead of metadata
                    let salt_value = match self.witness.kvs.get(salt_key) {
                        Some(Some(value)) => value.clone(),
                        _ => {
                            return Err(ProofError::VerifyFailed(
                                "salt value not found for existed key".to_string(),
                            ))
                        }
                    };

                    // Extract the plain key from the salt value and verify it matches
                    let plain_key = salt_value.key();
                    if plain_key != pkey {
                        return Err(ProofError::VerifyFailed(format!(
                            "key mismatch: expected {pkey:?}, got {plain_key:?}"
                        )));
                    }
                }
                // Verification for keys claimed to NOT exist
                // This is more complex as we need to recreate the insertion process
                PlainKeyStatus::NotExisted(salt_key) => {
                    // Pre-calculate bucket_id to avoid repeated computation
                    let bucket_id = hasher::bucket_id(pkey);

                    // Get the bucket metadata from the proof
                    let meta = self
                        .witness
                        .metadata
                        .get(&bucket_id)
                        .and_then(|&opt| opt)
                        .unwrap_or_default();

                    // Create ephemeral state and simulate the find operation
                    let mut state = EphemeralSaltState::new(self).cache_read();
                    let find_result = state
                        .shi_find(bucket_id, meta.nonce, meta.capacity, pkey)
                        .map_err(|_| {
                            ProofError::VerifyFailed(
                                "find operation failed during verification".to_string(),
                            )
                        })?;

                    // If find returns a result, the key actually exists - proof is invalid
                    if find_result.is_some() {
                        return Err(ProofError::VerifyFailed(
                            "key found when proof claims non-existence".to_string(),
                        ));
                    }

                    // Validate the search path from cache
                    let cache = &state.cache;
                    if cache.is_empty() {
                        return Err(ProofError::VerifyFailed("cache is empty".to_string()));
                    }

                    // Optimize: Calculate target slot with pre-computed values
                    let optimal_slot_id =
                        probe(hasher::hash_with_nonce(pkey, meta.nonce), 0, meta.capacity);
                    let cache_len = cache.len() as u64;

                    let expected_target_key = if optimal_slot_id + cache_len > meta.capacity {
                        // Wraparound case: use modular arithmetic
                        SaltKey::from((
                            bucket_id,
                            (optimal_slot_id + cache_len - 1) & (meta.capacity - 1),
                        ))
                    } else {
                        // Normal case: find maximum key in cache (most efficient way)
                        *cache
                            .keys()
                            .max()
                            .ok_or(ProofError::VerifyFailed("cache is empty".to_string()))?
                    };

                    // Verify the target matches proof's claim
                    if expected_target_key != *salt_key {
                        return Err(ProofError::VerifyFailed(
                            "target salt key mismatch".to_string(),
                        ));
                    }

                    // Validate key ordering if the target slot contains a value
                    if let Some(Some(salt_value)) = cache.get(&expected_target_key) {
                        let stored_key = salt_value.key();

                        // Quick checks: key shouldn't exist and should have correct priority
                        if stored_key == pkey || stored_key > pkey.as_slice() {
                            return Err(ProofError::VerifyFailed(
                                "invalid key ordering".to_string(),
                            ));
                        }
                    }
                    // Empty slot is valid for non-existence
                }
            }
        }
        Ok(())
    }

    /// Retrieves the plain value associated with the given plain key.
    ///
    /// # Arguments
    /// * `plain_key` - The plain key to look up
    ///
    /// # Returns
    /// * `Ok(Some(value))` if the key exists and has a value
    /// * `Ok(None)` if the key does not exist
    /// * `Err(String)` if the key was not included in this proof
    pub fn get_plain_value(&self, plain_key: &Vec<u8>) -> Result<Option<Vec<u8>>, String> {
        let idx = match self.keys.iter().position(|n| n == plain_key) {
            Some(idx) => idx,
            None => return Err("plain_key is not proved".to_string()),
        };

        match self.status[idx] {
            PlainKeyStatus::Existed(salt_key) => {
                let opt_salt_value = self.value(salt_key).map_err(|e| e.to_string())?;
                Ok(opt_salt_value.map(|salt_val| salt_val.value().to_vec()))
            }
            PlainKeyStatus::NotExisted(_) => Ok(None),
        }
    }

    /// Retrieves all plain values for the keys in this proof.
    ///
    /// Returns a vector where each element corresponds to the plain key at the same index.
    /// Elements are `Some(value)` for existing keys and `None` for non-existing keys.
    ///
    /// # Returns
    /// A vector of optional values, one for each key in the proof
    pub fn get_values(&self) -> Vec<Option<Vec<u8>>> {
        self.status
            .iter()
            .map(|status| match status {
                PlainKeyStatus::Existed(salt_key) => {
                    let opt_salt_value = self.witness.kvs.get(salt_key).cloned().flatten();
                    opt_salt_value.map(|salt_val| salt_val.value().to_vec())
                }
                PlainKeyStatus::NotExisted(_) => None,
            })
            .collect()
    }
}

// Implementation of StateReader trait for PlainKeysProof
// This allows the proof to be used as a state reader during verification,
// providing only the data that was included in the proof
impl StateReader for PlainKeysProof {
    type Error = &'static str;

    /// Retrieves a salt value by its salt key from the proof data.
    /// Delegates to the underlying BlockWitness implementation.
    fn value(&self, key: SaltKey) -> Result<Option<SaltValue>, <Self as StateReader>::Error> {
        self.witness.value(key)
    }

    fn entries(
        &self,
        range: RangeInclusive<SaltKey>,
    ) -> Result<Vec<(SaltKey, SaltValue)>, Self::Error> {
        self.witness.entries(range)
    }

    /// Returns the metadata for a specific bucket.
    /// Delegates to the BlockWitness implementation which correctly handles all cases.
    fn metadata(&self, bucket_id: BucketId) -> Result<BucketMeta, Self::Error> {
        self.witness.metadata(bucket_id)
    }
}

impl TrieReader for PlainKeysProof {
    type Error = &'static str;

    fn commitment(&self, node_id: NodeId) -> Result<CommitmentBytes, Self::Error> {
        self.witness.commitment(node_id)
    }

    fn node_entries(
        &self,
        range: Range<NodeId>,
    ) -> Result<Vec<(NodeId, CommitmentBytes)>, Self::Error> {
        self.witness.node_entries(range)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        mem_store::MemStore,
        mock_evm_types::{Account, PlainKey, PlainValue},
        state::state::EphemeralSaltState,
        trie::trie::StateRoot,
    };
    use alloy_primitives::{Address, B256, U256};
    use rand::{rngs::StdRng, Rng, SeedableRng};
    use std::collections::HashMap;

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
        let (root, trie_updates) = trie.update(&state_updates).unwrap();
        store.update_trie(trie_updates);

        // Generate a proof for the inserted key
        let plain_keys_proof =
            create_proof(&vec![kvs.keys().next().unwrap().clone()], &store).unwrap();

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

        let proof = create_proof(&[get_plain_keys(vec![6])[0].clone()], &store).unwrap();

        assert!(proof.verify(root).is_ok());

        let salt_key = match proof.status.first().unwrap() {
            PlainKeyStatus::Existed(key) => key,
            PlainKeyStatus::NotExisted(_) => panic!("plain_keys()[6] should be existed"),
        };

        let proof_value = proof.value(*salt_key).unwrap().unwrap();
        let plain_value = store.value(*salt_key).unwrap().unwrap();

        assert_eq!(plain_value, proof_value);

        // case 2.1
        let store = MemStore::new();
        // Insert plain_keys()[6]
        let root = insert_kvs(get_plain_keys(vec![6]), &store);
        // generate proof for plain_keys()[0]
        let proof = create_proof(&[plain_keys()[0].clone()], &store).unwrap();

        assert!(proof.verify(root).is_ok());

        // plain_keys()[0] is not existed
        let salt_key = match proof.status.first().unwrap() {
            PlainKeyStatus::Existed(_) => panic!("plain_keys()[0] should be not existed"),
            PlainKeyStatus::NotExisted(key) => key,
        };

        // the salt_key stores the plain_keys()[6]'s salt_value
        let salt_value = proof.value(*salt_key).unwrap().unwrap();

        let bucket_id = 2448221;
        let meta = store.metadata(bucket_id).unwrap();

        let mut state = EphemeralSaltState::new(&store);
        // can't find the plain_keys()[0]
        let find_res = state
            .shi_find(bucket_id, meta.nonce, meta.capacity, &plain_keys()[0])
            .unwrap();

        assert!(find_res.is_none());

        // plain_keys()[0] has a high priority than the plain_keys()[6]
        assert!(plain_keys()[0] > salt_value.key().to_vec());

        // case 2.2
        let store = MemStore::new();
        let root = insert_kvs(get_plain_keys(vec![6, 0]), &store);

        let proof = create_proof(&[plain_keys()[1].clone()], &store).unwrap();

        assert!(proof.verify(root).is_ok());

        let salt_key = match proof.status.first().unwrap() {
            PlainKeyStatus::Existed(_) => panic!("plain_keys()[1] should be not existed"),
            PlainKeyStatus::NotExisted(key) => key,
        };

        // the salt_key stores the plain_keys()[6]'s salt_value
        let salt_value = proof.value(*salt_key).unwrap().unwrap();

        let bucket_id = 2448221;
        let meta = store.metadata(bucket_id).unwrap();

        let mut state = EphemeralSaltState::new(&store);
        // can't find the plain_keys()[1]
        let find_res = state
            .shi_find(bucket_id, meta.nonce, meta.capacity, &plain_keys()[1])
            .unwrap();

        assert!(find_res.is_none());

        // plain_keys()[1] has a high priority than the plain_keys()[6]
        assert!(plain_keys()[1] > salt_value.key().to_vec());
        assert_eq!(salt_value, store.value(*salt_key).unwrap().unwrap());

        // case 2.3
        let store = MemStore::new();
        let root = insert_kvs(get_plain_keys(vec![6, 0, 2]), &store);

        let proof = create_proof(&[plain_keys()[1].clone()], &store).unwrap();

        assert!(proof.verify(root).is_ok());

        let salt_key = match proof.status.first().unwrap() {
            PlainKeyStatus::Existed(_) => panic!("plain_keys()[1] should be not existed"),
            PlainKeyStatus::NotExisted(key) => key,
        };

        // the salt_key stores the plain_keys()[2]'s salt_value
        let salt_value = proof.value(*salt_key).unwrap().unwrap();

        let bucket_id = 2448221;
        let meta = store.metadata(bucket_id).unwrap();

        let mut state = EphemeralSaltState::new(&store);
        let find_res = state
            .shi_find(bucket_id, meta.nonce, meta.capacity, &plain_keys()[1])
            .unwrap();

        assert!(find_res.is_none());

        // plain_keys()[1] has a high priority than the plain_keys()[2]
        assert!(plain_keys()[1] > salt_value.key().to_vec());
        assert_eq!(salt_value, store.value(*salt_key).unwrap().unwrap());

        // case 3.1
        let store = MemStore::new();
        let root = insert_kvs(get_plain_keys(vec![]), &store);

        let proof = create_proof(&[plain_keys()[0].clone()], &store).unwrap();

        assert!(proof.verify(root).is_ok());

        let salt_key = match proof.status.first().unwrap() {
            PlainKeyStatus::Existed(_) => panic!("plain_keys()[0] should be not existed"),
            PlainKeyStatus::NotExisted(key) => key,
        };

        let salt_value = proof.value(*salt_key).unwrap();
        assert!(salt_value.is_none());

        let bucket_id = 2448221;
        let meta = store.metadata(bucket_id).unwrap();

        let mut state = EphemeralSaltState::new(&store);
        let find_res = state
            .shi_find(bucket_id, meta.nonce, meta.capacity, &plain_keys()[0])
            .unwrap();

        assert!(find_res.is_none());

        // case 3.2
        let store = MemStore::new();
        let root = insert_kvs(get_plain_keys(vec![0, 1, 2, 3, 4, 5]), &store);

        let proof = create_proof(&[plain_keys()[6].clone()], &store).unwrap();

        assert!(proof.verify(root).is_ok());

        let salt_key = match proof.status.first().unwrap() {
            PlainKeyStatus::Existed(_) => panic!("plain_keys()[6] should be not existed"),
            PlainKeyStatus::NotExisted(key) => key,
        };

        let salt_value = proof.value(*salt_key).unwrap();
        assert!(salt_value.is_none());

        let bucket_id = 2448221;
        let meta = store.metadata(bucket_id).unwrap();

        let mut state = EphemeralSaltState::new(&store);
        let find_res = state
            .shi_find(bucket_id, meta.nonce, meta.capacity, &plain_keys()[6])
            .unwrap();

        assert!(find_res.is_none());
    }

    #[test]
    fn test_plain_key_proof_in_loop_slot_id() {
        let store = MemStore::new();
        let root = insert_kvs(get_plain_keys(vec![9]), &store);

        let key = plain_keys()[7].clone();

        let proof = create_proof(&[key], &store).unwrap();

        assert!(proof.verify(root).is_ok());

        let salt_key = match proof.status.first().unwrap() {
            PlainKeyStatus::Existed(key) => key,
            PlainKeyStatus::NotExisted(key) => key,
        };

        assert_eq!(salt_key.slot_id(), 0);
        let salt_value = proof.value(*salt_key).unwrap();
        assert!(salt_value.is_none());

        // another case
        let store = MemStore::new();
        let root = insert_kvs(get_plain_keys(vec![7, 8, 9]), &store);

        let key = plain_keys()[8].clone();

        let proof = create_proof(&[key.clone()], &store).unwrap();

        assert!(proof.verify(root).is_ok());

        assert_eq!(proof.keys.first().unwrap(), &key);

        let salt_key = match proof.status.first().unwrap() {
            PlainKeyStatus::Existed(key) => key,
            PlainKeyStatus::NotExisted(key) => key,
        };

        assert_eq!(salt_key.slot_id(), 1);
        let salt_value = proof.value(*salt_key).unwrap().unwrap();

        let salt_val = store.value(*salt_key).unwrap().unwrap();

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

        let (_, trie_updates) = StateRoot::new(&store).update(&updates).unwrap();

        store.update_trie(trie_updates);

        let plain_keys_proof =
            create_proof(&kvs.keys().map(|k| k.clone()).collect::<Vec<_>>(), &store).unwrap();

        let data_keys: Vec<SaltKey> = plain_keys_proof
            .witness
            .kvs
            .keys()
            .map(|k| *k)
            .collect::<Vec<_>>();

        let mut meta_keys: Vec<SaltKey> = plain_keys_proof
            .witness
            .metadata
            .keys()
            .map(|bucket_id| bucket_metadata_key(*bucket_id))
            .collect();

        meta_keys.extend_from_slice(&data_keys);

        for key in meta_keys {
            let proof_value = plain_keys_proof.value(key).unwrap();
            let state_value = state.value(key).unwrap();

            assert_eq!(proof_value, state_value);
        }
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
        let (root, trie_updates) = trie.update(&state_updates).unwrap();

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
