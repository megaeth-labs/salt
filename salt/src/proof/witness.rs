//! Salt witness implementation for stateless validation.
//!
//! This module provides the `SaltWitness` data structure, which contains a subset
//! of state data along with cryptographic proofs for stateless validation. The witness
//! enforces critical security properties to prevent state manipulation attacks.
use crate::{
    proof::{ProofError, SaltProof},
    traits::{StateReader, TrieReader},
    types::*,
};
use rayon::prelude::*;
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    ops::{Range, RangeInclusive},
};

/// Salt witness for stateless validation with security guarantees.
///
/// A `SaltWitness` contains a curated subset of state data along with cryptographic
/// proofs that allow stateless validators to verify state transitions without having
/// access to the full state tree.
///
/// # Security Model
///
/// The witness enforces a critical distinction between three types of keys:
///
/// ## Key States
/// 1. **Witnessed Existing**: Key is in the witness with a value (`Some(Some(value))`)
/// 2. **Witnessed Non-existent**: Key is in the witness as absent (`Some(None)`)
/// 3. **Unknown**: Key is not included in the witness at all (`None`)
///
/// ## Security Properties
///
/// - **No State Hiding**: A malicious prover cannot make an existing key appear
///   as non-existent by omitting it from the witness. Unknown keys always return
///   errors, preventing confusion with proven non-existence.
///
/// - **Proof Integrity**: The cryptographic proof ensures that all witnessed data
///   (both existing and non-existent) is correctly authenticated against the state root.
///
/// - **No Range Manipulation**: Range queries are disabled to prevent selective
///   omission attacks where a prover hides some keys while including others in a range.
/// ```
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SaltWitness {
    /// All witnessed data in this proof, including both metadata and regular
    /// key-value pairs.
    /// - `Some(value)`: Key exists with the given value
    /// - `None`: Key does not exist
    /// - Missing key: Key not witnessed (unknown)
    ///
    /// Unlike regular data buckets, metadata bucket slots can never be empty.
    /// Default metadata is stored explicity as `Some(SaltValue)`, not `None`,
    /// to simplify the witness code.
    pub kvs: BTreeMap<SaltKey, Option<SaltValue>>,

    /// Cryptographic proof authenticating all witnessed data
    pub proof: SaltProof,
}

impl SaltWitness {
    /// Creates a salt witness for a given set of keys with their cryptographic proof.
    ///
    /// This method constructs a witness that includes the specified keys' data along
    /// with a cryptographic proof that authenticates the data against the state root.
    /// Every key is cryptographically proven to either exist (with its value) or not
    /// exist.
    ///
    /// # Arguments
    /// * `keys` - The set of salt keys to include in the witness
    /// * `store` - The storage backend providing access to state data
    ///
    /// # Returns
    /// * `Ok(SaltWitness)` - A witness containing the requested keys' data and their proof
    /// * `Err(ProofError)` - If reading any key fails or proof generation fails
    ///
    /// # Notes
    /// - For metadata keys, retrieves bucket metadata instead of regular values
    /// - For regular keys, retrieves their values (or None if non-existent)
    /// - The proof is generated for all requested keys to ensure completeness
    pub fn create<Store>(keys: &[SaltKey], store: &Store) -> Result<SaltWitness, ProofError>
    where
        Store: StateReader + TrieReader,
    {
        let kvs = keys
            .par_iter()
            .map(|&salt_key| {
                let value = (if salt_key.is_in_meta_bucket() {
                    // Handle metadata keys
                    let bucket_id = bucket_id_from_metadata_key(salt_key);
                    store.metadata(bucket_id).map(|meta| Some(meta.into()))
                } else {
                    // Handle regular data keys
                    store.value(salt_key)
                })
                .map_err(|e| ProofError::StateReadError {
                    reason: format!("Failed to read key: {e:?}"),
                })?;
                Ok((salt_key, value))
            })
            .collect::<Result<BTreeMap<_, _>, _>>()?;

        let proof = SaltProof::create(kvs.keys().copied(), store)?;
        Ok(SaltWitness { kvs, proof })
    }

    /// Verify the salt witness against the given state root.
    ///
    /// This method verifies that the witness correctly represents the state by
    /// checking the cryptographic proof. Importantly, it preserves the distinction
    /// between non-existent values (None) and existing values (Some) in the proof.
    ///
    /// # Security Note
    ///
    /// This verification ensures that:
    /// - All witnessed keys are correctly proven against the state root
    /// - Non-existent values (None) are properly verified as absent
    /// - The proof cannot be manipulated to hide or fabricate state
    pub fn verify_proof(&self, root: ScalarBytes) -> Result<(), ProofError> {
        self.proof.check(&self.kvs, root)
    }
}

impl StateReader for SaltWitness {
    type Error = &'static str;

    /// Retrieves a state value by key from the witness.
    ///
    /// # Security Model
    ///
    /// This method enforces a critical distinction for stateless validation:
    /// - `Ok(Some(value))` - Key exists with the given value (witnessed)
    /// - `Ok(None)` - Key is proven to not exist (witnessed as absent)
    /// - `Err(_)` - Key was not included in the witness (unknown state)
    ///
    /// **Security Property**: A malicious prover cannot make an unknown key appear
    /// as non-existent by omitting it from the witness. Unknown keys will always
    /// return an error, preventing state manipulation attacks.
    fn value(&self, key: SaltKey) -> Result<Option<SaltValue>, Self::Error> {
        match self.kvs.get(&key) {
            Some(Some(value)) => Ok(Some(value.clone())), // Key exists with value
            Some(None) => Ok(None),                       // Key witnessed as non-existent
            None => Err("Key not in witness"),            // Unknown - not witnessed
        }
    }

    /// Range queries are not supported for SaltWitness.
    ///
    /// # Security Rationale
    ///
    /// Range queries cannot be safely implemented for witnesses because we cannot
    /// guarantee that all keys in the requested range are included in the witness.
    /// A malicious prover could selectively omit keys from the witness, making
    /// them appear as non-existent when they are actually unknown.
    ///
    /// **For stateless validation**: Use individual `value()` calls instead of
    /// range queries. This ensures proper distinction between unknown and
    /// non-existent keys.
    fn entries(
        &self,
        _range: RangeInclusive<SaltKey>,
    ) -> Result<Vec<(SaltKey, SaltValue)>, Self::Error> {
        Err("Range queries not supported for SaltWitness")
    }

    /// Retrieves metadata for a specific bucket from the witness.
    ///
    /// This method only provides metadata for buckets that were included in the
    /// proof during witness generation. The behavior depends on what was stored:
    ///
    /// - If explicit metadata was stored: returns that metadata as-is
    /// - If bucket was not included in proof: returns an error
    ///
    /// # Arguments
    /// * `bucket_id` - The ID of the bucket whose metadata to retrieve
    ///
    /// # Returns
    /// - `Ok(BucketMeta)` - The bucket's metadata if it was included in the proof
    /// - `Err(str)` - If the bucket was not included in the proof
    ///
    /// # Note
    /// This method will never fabricate metadata for unknown buckets, ensuring proof integrity.
    fn metadata(&self, bucket_id: BucketId) -> Result<BucketMeta, Self::Error> {
        let metadata_key = bucket_metadata_key(bucket_id);
        match self.kvs.get(&metadata_key) {
            Some(Some(salt_value)) => BucketMeta::try_from(salt_value.clone())
                .map_err(|_| "Failed to decode metadata from SaltValue"),
            Some(None) => Err("Metadata stored as None in witness - unexpected state"),
            None => Err("Bucket metadata not available in witness"),
        }
    }

    /// Counts occupied slots in a bucket by checking every slot in the witness.
    ///
    /// This method provides an accurate count of occupied slots, but only if ALL slots
    /// in the bucket are included in the witness. If any slot is missing from the witness,
    /// this method returns an error to maintain security guarantees.
    ///
    /// # Security Model
    ///
    /// - **Complete coverage required**: Returns error if ANY slot in the bucket is not witnessed
    /// - **No partial counts**: Either counts ALL slots accurately or fails with error
    /// - **Malicious prover protection**: Cannot be tricked by selective slot omission
    ///
    /// # Arguments
    ///
    /// * `bucket_id` - The bucket ID to count slots for
    ///
    /// # Returns
    ///
    /// - `Ok(count)` - Number of occupied slots if all slots are witnessed
    /// - `Err(_)` - If bucket metadata is missing or any slot is not witnessed
    fn bucket_used_slots(&self, bucket_id: BucketId) -> Result<u64, Self::Error> {
        // Follow the convention of the default implementation
        if !is_valid_data_bucket(bucket_id) {
            return Ok(0);
        }

        // Get bucket metadata to determine capacity
        let metadata = self.metadata(bucket_id)?;
        let capacity = metadata.capacity;

        let mut used_count = 0u64;

        // Check every slot in the bucket
        for slot in 0..capacity {
            let salt_key = SaltKey::from((bucket_id, slot));
            // Returns error if any slot is not witnessed (`Err` from `value()`)
            if self.value(salt_key)?.is_some() {
                used_count += 1;
            }
        }

        Ok(used_count)
    }
}

impl TrieReader for SaltWitness {
    type Error = &'static str;

    /// Retrieves the commitment for a specific trie node from the witness.
    ///
    /// # Security Model
    ///
    /// This method enforces the same security properties as other SaltWitness methods:
    /// - Returns the commitment if the node is witnessed in the proof
    /// - Returns an error if the node is not included in the witness
    fn commitment(&self, node_id: NodeId) -> Result<CommitmentBytes, Self::Error> {
        match self.proof.parents_commitments.get(&node_id) {
            Some(commitment) => Ok(commitment.0),
            None => Err("Trie node not in witness"),
        }
    }

    /// Range queries are not supported for SaltWitness.
    ///
    /// **For stateless validation**: Use individual `commitment()` calls instead
    /// of range queries. This ensures proper distinction between unknown and
    /// default-valued nodes.
    fn node_entries(
        &self,
        _range: Range<NodeId>,
    ) -> Result<Vec<(NodeId, CommitmentBytes)>, Self::Error> {
        Err("Range queries not supported for SaltWitness")
    }
}

#[cfg(test)]
/// Helper function to create a mock SaltProof for testing
pub fn create_mock_proof() -> SaltProof {
    use crate::{empty_salt::EmptySalt, proof::SaltProof};

    // Create a minimal real proof using EmptySalt
    SaltProof::create([SaltKey(0)], &EmptySalt).unwrap()
}

#[cfg(test)]
/// Helper function to create a SaltWitness for testing
pub fn create_witness(
    bucket_id: BucketId,
    metadata: Option<BucketMeta>,
    slots: Vec<(u64, Option<SaltValue>)>,
) -> SaltWitness {
    let mut kvs = BTreeMap::new();

    if let Some(meta) = metadata {
        let metadata_key = bucket_metadata_key(bucket_id);
        kvs.insert(metadata_key, Some(meta.into()));
    }

    for (slot, val) in slots {
        let salt_key = SaltKey::from((bucket_id, slot));
        kvs.insert(salt_key, val);
    }

    SaltWitness {
        kvs,
        proof: create_mock_proof(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        constant::{MIN_BUCKET_SIZE, NUM_META_BUCKETS},
        mem_store::MemStore,
        mock_evm_types::*,
        proof::CommitmentBytesW,
        state::state::EphemeralSaltState,
        state::updates::StateUpdates,
        traits::TrieReader,
        trie::trie::StateRoot,
    };
    use alloy_primitives::{Address, B256, U256};
    use rand::{rngs::StdRng, Rng, SeedableRng};
    use std::collections::HashMap;

    #[test]
    fn get_mini_trie() {
        let kvs = create_random_kv_pairs(1000);

        let mem_store = MemStore::new();

        // 1. Initialize the state & trie to represent the origin state.
        let initial_updates = EphemeralSaltState::new(&mem_store).update(&kvs).unwrap();
        mem_store.update_state(initial_updates.clone());

        let mut trie = StateRoot::new(&mem_store);
        let (old_trie_root, initial_trie_updates) = trie.update_fin(initial_updates).unwrap();

        mem_store.update_trie(initial_trie_updates);

        // 2. Suppose that 100 new kv pairs need to be inserted
        // after the execution of the block.
        let new_kvs = create_random_kv_pairs(100);

        let mut state = EphemeralSaltState::new(&mem_store).cache_read();
        let state_updates = state.update(&new_kvs).unwrap();

        // Update the trie with the new inserts
        let (new_trie_root, mut trie_updates) = trie.update_fin(state_updates.clone()).unwrap();

        let min_sub_tree_keys = state.cache.keys().copied().collect::<Vec<_>>();
        let salt_witness = SaltWitness::create(&min_sub_tree_keys, &mem_store).unwrap();

        // 3.options in prover node
        // 3.1 verify the salt witness
        let res = salt_witness.verify_proof(old_trie_root);
        assert!(res.is_ok());

        // 3.2 create EphemeralSaltState from salt witness
        let mut prover_state = EphemeralSaltState::new(&salt_witness);

        // 3.3 prover client execute the same blocks, and get the same new_kvs
        let prover_updates = prover_state.update(&new_kvs).unwrap();

        assert_eq!(state_updates, prover_updates);

        let mut prover_trie = StateRoot::new(&salt_witness);
        let (prover_trie_root, mut prover_trie_updates) =
            prover_trie.update_fin(prover_updates).unwrap();

        trie_updates.sort_unstable_by(|(a, _), (b, _)| a.cmp(b));
        prover_trie_updates.sort_unstable_by(|(a, _), (b, _)| a.cmp(b));

        assert_eq!(trie_updates, prover_trie_updates);

        assert_eq!(new_trie_root, prover_trie_root);
    }

    #[test]
    fn test_error() {
        let kvs = create_random_kv_pairs(100);

        // 1. Initialize the state & trie to represent the origin state.
        let mem_store = MemStore::new();

        let initial_updates = EphemeralSaltState::new(&mem_store).update(&kvs).unwrap();
        mem_store.update_state(initial_updates.clone());

        let mut trie = StateRoot::new(&mem_store);
        let (root, initial_trie_updates) = trie.update_fin(initial_updates).unwrap();

        mem_store.update_trie(initial_trie_updates);

        // 2. Suppose that 100 new kv pairs need to be inserted
        // after the execution of the block.

        let pk = PlainKey::Storage(Address::ZERO, B256::ZERO).encode();

        let pv = Some(PlainValue::Storage(B256::ZERO.into()).encode());

        let mut state = EphemeralSaltState::new(&mem_store);
        state.update(vec![(&pk, &pv)]).unwrap();

        let min_sub_tree_keys = state.cache.keys().copied().collect::<Vec<_>>();
        let salt_witness_res = SaltWitness::create(&min_sub_tree_keys, &mem_store).unwrap();

        let res = salt_witness_res.verify_proof(root);
        assert!(res.is_ok());
    }

    #[test]
    fn test_state_reader_for_witness() {
        let kvs = create_random_kv_pairs(1000);

        // 1. Initialize the state & trie to represent the origin state.
        let mem_store = MemStore::new();

        let initial_updates = EphemeralSaltState::new(&mem_store).update(&kvs).unwrap();
        mem_store.update_state(initial_updates.clone());

        let mut trie = StateRoot::new(&mem_store);
        let (_, initial_trie_updates) = trie.update_fin(initial_updates).unwrap();

        mem_store.update_trie(initial_trie_updates);

        // 2. Suppose that 100 new kv pairs need to be inserted
        // after the execution of the block.
        let new_kvs = create_random_kv_pairs(100);
        let mut state = EphemeralSaltState::new(&mem_store);
        state.update(&new_kvs).unwrap();

        let min_sub_tree_keys = state.cache.keys().copied().collect::<Vec<_>>();

        let salt_witness = SaltWitness::create(&min_sub_tree_keys, &mem_store).unwrap();

        // use the old state
        for key in min_sub_tree_keys {
            let witness_value = salt_witness.value(key).unwrap();
            let state_value = mem_store.value(key).unwrap();
            assert_eq!(witness_value, state_value);
        }
    }

    fn create_random_kv_pairs(l: usize) -> HashMap<Vec<u8>, Option<Vec<u8>>> {
        let mut rng = StdRng::seed_from_u64(42);
        let mut res = HashMap::new();

        (0..l / 2).for_each(|_| {
            let pk = PlainKey::Account(Address::from(rng.gen::<[u8; 20]>())).encode();
            let pv = Some(
                PlainValue::Account(Account {
                    balance: U256::from(rng.gen_range(0..1000)),
                    nonce: rng.gen_range(0..100),
                    bytecode_hash: None,
                })
                .encode(),
            );
            res.insert(pk, pv);
        });
        (l / 2..l).for_each(|_| {
            let pk = PlainKey::Storage(
                Address::from(rng.gen::<[u8; 20]>()),
                B256::from(rng.gen::<[u8; 32]>()),
            );
            let pv = Some(PlainValue::Storage(B256::from(rng.gen::<[u8; 32]>()).into()).encode());
            res.insert(pk.encode(), pv);
        });
        res
    }

    /// Test all three cases of the SaltWitness::metadata() method
    #[test]
    fn test_salt_witness_metadata_cases() {
        let mock_salt_value = SaltValue::new(&[1u8; 32], &[2u8; 32]);

        // Use valid data bucket IDs (>= NUM_META_BUCKETS)
        let bucket1 = NUM_META_BUCKETS as u32;
        let bucket2 = NUM_META_BUCKETS as u32 + 1;
        let bucket3 = NUM_META_BUCKETS as u32 + 2;

        // Test Case 1: Explicit metadata present (Some(Some(meta)))
        let mut explicit_meta = BucketMeta::default();
        explicit_meta.nonce = 42;
        explicit_meta.capacity = 512;

        let mut kvs = BTreeMap::new();
        let metadata_key = bucket_metadata_key(bucket1);
        kvs.insert(metadata_key, Some(explicit_meta.into()));

        let witness = SaltWitness {
            kvs,
            proof: create_mock_proof(),
        };

        let result = witness.metadata(bucket1).unwrap();
        assert_eq!(result.nonce, 42);
        assert_eq!(result.capacity, 512);

        // Test Case 2: Default metadata case
        let default_meta = BucketMeta::default();
        let mut kvs = BTreeMap::new();
        let metadata_key = bucket_metadata_key(bucket2);
        kvs.insert(metadata_key, Some(default_meta.into()));

        // Add some kvs for used count calculation
        kvs.insert(
            SaltKey::from((bucket2, 0u64)),
            Some(mock_salt_value.clone()),
        );
        kvs.insert(
            SaltKey::from((bucket2, 1u64)),
            Some(mock_salt_value.clone()),
        );
        kvs.insert(
            SaltKey::from((bucket2, 5u64)),
            Some(mock_salt_value.clone()),
        );

        let witness = SaltWitness {
            kvs,
            proof: create_mock_proof(),
        };

        let result = witness.metadata(bucket2).unwrap();
        assert_eq!(result.nonce, 0); // Default value
        assert_eq!(result.capacity, MIN_BUCKET_SIZE as u64); // Default value
        assert_eq!(result.used, None); // Cannot compute reliably from partial witness

        // Test Case 3: Bucket not in proof (None)
        let witness = SaltWitness {
            kvs: BTreeMap::new(), // Empty - bucket not in proof
            proof: create_mock_proof(),
        };

        let result = witness.metadata(bucket3);
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err(),
            "Bucket metadata not available in witness"
        );
    }

    /// Test that verifies the security properties of SaltWitness StateReader
    /// implementation.
    ///
    /// This test ensures that the witness correctly distinguishes between:
    /// - Witnessed existing values (Ok(Some(value)))
    /// - Witnessed non-existent values (Ok(None))
    /// - Unknown values not in witness (Err)
    ///
    /// This prevents state manipulation attacks where a malicious prover
    /// could make unknown values appear as non-existent.
    #[test]
    fn test_witness_state_reader_security() {
        // Setup test keys
        let key_exists = SaltKey::from((100000, 1)); // Will be witnessed as existing
        let key_nonexistent = SaltKey::from((100000, 2)); // Will be witnessed as non-existent
        let key_unknown = SaltKey::from((100000, 3)); // Will NOT be in witness (unknown)

        // Create witness with partial data
        let mut kvs = BTreeMap::new();
        kvs.insert(key_exists, Some(SaltValue::new(&[1; 32], &[2; 32]))); // Exists
        kvs.insert(key_nonexistent, None); // Proven non-existent
                                           // key_unknown is intentionally omitted (unknown)

        let witness = SaltWitness {
            kvs,
            proof: create_mock_proof(),
        };

        // Test witnessed existing key
        match witness.value(key_exists) {
            Ok(Some(_)) => {} // Correct: witnessed as existing
            other => panic!("Expected Ok(Some(_)), got {:?}", other),
        }

        // Test witnessed non-existent key
        match witness.value(key_nonexistent) {
            Ok(None) => {} // Correct: witnessed as non-existent
            other => panic!("Expected Ok(None), got {:?}", other),
        }

        // Test unknown key (not in witness) - CRITICAL SECURITY TEST
        match witness.value(key_unknown) {
            Err(_) => {}, // Correct: unknown key returns error
            Ok(None) => panic!("SECURITY VIOLATION: Unknown key returned Ok(None) - could be exploited by malicious prover!"),
            Ok(Some(_)) => panic!("SECURITY VIOLATION: Unknown key returned Ok(Some(_)) - impossible case!"),
        }

        // Test that range queries are disabled for security
        assert!(witness.entries(key_exists..=key_unknown).is_err());

        // Test that bucket_used_slots requires complete bucket witness
        assert!(witness.bucket_used_slots(100000).is_err());

        // Test metadata security properties
        let bucket_exists = 100000;
        let bucket_default = 100001;
        let bucket_unknown = 100002;

        let mut kvs = BTreeMap::new();
        let meta_key_exists = bucket_metadata_key(bucket_exists);
        kvs.insert(
            meta_key_exists,
            Some(
                BucketMeta {
                    nonce: 42,
                    capacity: 512,
                    used: Some(10),
                }
                .into(),
            ),
        );
        let meta_key_default = bucket_metadata_key(bucket_default);
        kvs.insert(meta_key_default, Some(BucketMeta::default().into())); // Default metadata
                                                                          // bucket_unknown intentionally omitted

        let witness_meta = SaltWitness {
            kvs,
            proof: create_mock_proof(),
        };

        // Existing metadata
        assert!(witness_meta.metadata(bucket_exists).is_ok());

        // Default metadata
        let default_meta = witness_meta.metadata(bucket_default).unwrap();
        assert_eq!(default_meta.nonce, 0);
        assert_eq!(default_meta.capacity, MIN_BUCKET_SIZE as u64);
        assert_eq!(default_meta.used, None); // Cannot compute from partial witness

        // Unknown metadata - should error
        assert!(witness_meta.metadata(bucket_unknown).is_err());
    }

    /// Comprehensive tests for the bucket_used_slots method.
    ///
    /// Tests all scenarios:
    /// - Error when bucket metadata is missing
    /// - Successful counting with fully witnessed bucket
    /// - Error when some slots are not witnessed
    /// - Correct counting with mix of occupied and empty slots
    /// - Handling of default metadata buckets
    #[test]
    fn test_bucket_used_slots() {
        let bucket_id = 100000;
        let val = SaltValue::new(&[1u8; 32], &[2u8; 32]);

        // Test 1: Missing metadata
        let witness = create_witness(bucket_id, None, vec![]);
        assert_eq!(
            witness.bucket_used_slots(bucket_id).unwrap_err(),
            "Bucket metadata not available in witness"
        );

        // Test 2: Fully witnessed bucket
        let meta = BucketMeta {
            nonce: 0,
            capacity: 8,
            used: Some(3),
        };
        let slots = vec![
            (0, Some(val.clone())),
            (1, None),
            (2, Some(val.clone())),
            (3, None),
            (4, None),
            (5, Some(val.clone())),
            (6, None),
            (7, None),
        ];
        let witness = create_witness(bucket_id, Some(meta), slots);
        assert_eq!(witness.bucket_used_slots(bucket_id).unwrap(), 3);

        // Test 3: Partial witness (missing slots)
        let meta = BucketMeta {
            nonce: 0,
            capacity: 5,
            used: None,
        };
        let slots = vec![(0, Some(val.clone())), (1, None), (2, Some(val.clone()))];
        let witness = create_witness(bucket_id, Some(meta), slots);
        assert_eq!(
            witness.bucket_used_slots(bucket_id).unwrap_err(),
            "Key not in witness"
        );

        // Test 4: Empty bucket
        let meta = BucketMeta {
            nonce: 0,
            capacity: 3,
            used: None,
        };
        let slots = vec![(0, None), (1, None), (2, None)];
        let witness = create_witness(bucket_id, Some(meta), slots);
        assert_eq!(witness.bucket_used_slots(bucket_id).unwrap(), 0);

        // Test 5: Default metadata bucket
        let mut kvs = BTreeMap::new();
        let metadata_key = bucket_metadata_key(bucket_id);
        kvs.insert(metadata_key, Some(BucketMeta::default().into()));
        for slot in 0..MIN_BUCKET_SIZE as u64 {
            let val_opt = if slot % 3 == 0 {
                Some(val.clone())
            } else {
                None
            };
            kvs.insert(SaltKey::from((bucket_id, slot)), val_opt);
        }
        let witness = SaltWitness {
            kvs,
            proof: create_mock_proof(),
        };
        let expected = (MIN_BUCKET_SIZE as u64 + 2) / 3;
        assert_eq!(witness.bucket_used_slots(bucket_id).unwrap(), expected);
    }

    /// Test that verifies the security properties of SaltWitness TrieReader
    /// implementation.
    ///
    /// This test ensures that the TrieReader correctly distinguishes between:
    /// - Witnessed nodes (returns commitment)
    /// - Unknown nodes not in witness (returns error)
    ///
    /// This prevents state manipulation attacks where a malicious prover
    /// could omit critical trie nodes to hide state modifications.
    #[test]
    fn test_witness_trie_reader_security() {
        // Build witness with two witnessed nodes
        let mut proof = create_mock_proof();
        proof.parents_commitments = [
            (12345, CommitmentBytesW([1u8; 64])),
            (67890, CommitmentBytesW([2u8; 64])),
        ]
        .into();

        let witness = SaltWitness {
            kvs: BTreeMap::new(),
            proof,
        };

        // Witnessed nodes return correct commitments
        assert_eq!(witness.commitment(12345).unwrap(), [1u8; 64]);
        assert_eq!(witness.commitment(67890).unwrap(), [2u8; 64]);

        // Unknown nodes must return errors (critical security test)
        assert!(
            witness.commitment(99999).is_err(),
            "SECURITY: Unknown node must return error, not default!"
        );

        // Range queries must be disabled
        assert!(
            witness.node_entries(0..1000).is_err(),
            "SECURITY: Range queries must be disabled!"
        );
    }

    #[test]
    fn test_default_bucket_meta_proof() {
        let mem_store = MemStore::new();

        let mut trie = StateRoot::new(&mem_store);
        let (root, _) = trie.update_fin(StateUpdates::default()).unwrap();

        let bucket_id: BucketId = 100000;
        let salt_key = bucket_metadata_key(bucket_id);
        let witness = SaltWitness::create(&[salt_key], &mem_store).unwrap();
        let res = witness.verify_proof(root);
        assert!(res.is_ok());
    }
}
