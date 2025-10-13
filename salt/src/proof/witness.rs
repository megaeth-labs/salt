//! Witness generation and verification for plain (user-provided) keys.
//!
//! This module implements a high-level proof system that allows clients to prove
//! the existence or non-existence of plain keys without requiring access to the
//! full state. It acts as an abstraction layer over the lower-level `SaltWitness`
//! proof system.

use crate::{
    proof::salt_witness::SaltWitness,
    proof::ProofError,
    state::{hasher, state::EphemeralSaltState},
    traits::{StateReader, TrieReader},
    types::*,
};
use std::{
    collections::HashMap,
    ops::{Range, RangeInclusive},
};

use crate::types::{bucket_id_from_metadata_key, METADATA_KEYS_RANGE};

/// A cryptographic witness enabling stateless validation and execution.
///
/// The `Witness` allows stateless validators to:
/// - Re-execute transactions by providing necessary state data through
///   the `StateReader` trait
/// - Compute the new state root after transaction execution
///
/// Critically, the witness contains the minimal partial trie with all internal nodes
/// necessary to recompute the state root after applying state updates. This enables
/// stateless nodes to not only re-execute transactions but also produce new state roots.
#[derive(Clone, Debug, PartialEq)]
pub struct Witness {
    /// Direct mapping from plain keys to their salt key locations.
    /// Only contains keys that exist.
    pub(crate) direct_lookup_tbl: HashMap<Vec<u8>, SaltKey>,

    /// The underlying cryptographic witness containing:
    /// - All salt keys needed for inclusion/exclusion proofs
    /// - Their values (or None for empty slots)
    /// - Cryptographic commitments proving authenticity
    pub salt_witness: SaltWitness,
}

impl From<SaltWitness> for Witness {
    /// Reconstructs a Witness from a SaltWitness by extracting plain keys.
    ///
    /// This enables transmitting only the SaltWitness over the network, avoiding
    /// redundant storage of plain keys. The direct_lookup_tbl is rebuilt by:
    /// - Extracting plain keys from SaltValue data (where they're already stored)
    /// - Skipping metadata entries (which don't contain plain key-value pairs)
    fn from(salt_witness: SaltWitness) -> Self {
        let mut direct_lookup_tbl = HashMap::new();
        for (salt_key, value) in &salt_witness.kvs {
            if salt_key.is_in_meta_bucket() {
                continue;
            }

            if let Some(salt_value) = value {
                let plain_key = salt_value.key().to_vec();
                direct_lookup_tbl.insert(plain_key, *salt_key);
            }
        }

        Witness {
            direct_lookup_tbl,
            salt_witness,
        }
    }
}

impl Witness {
    /// Creates a comprehensive cryptographic witness for stateless validators.
    ///
    /// This method generates a witness that enables stateless validators to both
    /// re-execute transactions (using the lookup keys) and update the state root
    /// afterwards (using the state updates). It generates inclusion proofs for
    /// existing keys and exclusion proofs for non-existing keys.
    ///
    /// # Arguments
    /// * `lookups` - The read-set of plain keys needed to execute transactions.
    ///   These are keys that need to be read during transaction execution.
    /// * `updates` - The write-set of state updates resulting from transaction execution.
    ///   Each item is a tuple of (plain_key, optional_value) where None indicates deletion.
    ///   Updates that duplicate lookup keys are filtered out (except deletions which are
    ///   always processed to maintain correct state transitions).
    /// * `store` - The storage backend providing access to both state data
    ///   (key-value pairs) and trie data (cryptographic commitments).
    ///
    /// # Returns
    /// A `Witness` containing:
    /// - A mapping from each lookup key to its corresponding salt key (if it exists)
    /// - All state data needed for transaction execution (from lookups)
    /// - All state changes needed to update the root (from filtered updates)
    /// - Cryptographic proofs (SaltWitness) for verification
    ///
    /// # Errors
    /// Returns `ProofError::StateReadError` if:
    /// - Unable to read bucket metadata
    /// - Unable to perform SHI search operations
    /// - Unable to access required state data
    /// - Witness creation fails
    pub fn create<'b, Store>(
        lookups: &[Vec<u8>],
        updates: impl IntoIterator<Item = (&'b Vec<u8>, &'b Option<Vec<u8>>)>,
        store: &Store,
    ) -> Result<Witness, ProofError>
    where
        Store: StateReader + TrieReader,
    {
        let mut witnessed_keys = vec![];
        let mut direct_lookup_tbl = HashMap::new();

        (|| -> Result<(), <Store as StateReader>::Error> {
            // We use two separate state instances to collect witness data:
            // - 'state': For performing lookups to determine if keys exist
            // - 'recorder': For recording slot accesses during non-existence
            //   proofs and state updates
            let mut state = EphemeralSaltState::new(store);
            let mut recorder = EphemeralSaltState::new(store).cache_read();

            for plain_key in lookups {
                let bucket_id = hasher::bucket_id(plain_key);
                let metadata = store.metadata(bucket_id)?;

                if let Some((slot_id, _)) =
                    state.shi_find(bucket_id, metadata.nonce, metadata.capacity, plain_key)?
                {
                    // Key exists: Record the mapping in the lookup table and
                    // directly witness the salt key for inclusion proof
                    let salt_key = SaltKey::from((bucket_id, slot_id));
                    direct_lookup_tbl.insert(plain_key.clone(), salt_key);
                    witnessed_keys.push(salt_key);
                } else {
                    // Key doesn't exist: Perform a full search to capture all
                    // slots checked during the SHI lookup. These slots form the
                    // exclusion proof.
                    recorder.plain_value(plain_key)?;
                }
            }

            // Filter out plain keys from updates that are already in direct_lookup_tbl,
            // but only if the update is not a deletion (None value indicates deletion).
            // Since most updates are in-place, this optimization reduces the number of
            // slots that need to be tracked in the witness significantly.
            let filtered_updates: Vec<_> = updates
                .into_iter()
                .filter(|(key, value)| !direct_lookup_tbl.contains_key(*key) || value.is_none())
                .collect();
            let state_updates = recorder.update(filtered_updates)?;

            // Extract old capacities from buckets that had capacity changes
            let old_capacities: HashMap<_, _> = state_updates
                .data
                .range(METADATA_KEYS_RANGE)
                .filter_map(|(key, (old_val, _))| {
                    old_val
                        .as_ref()
                        .and_then(|v| BucketMeta::try_from(v).ok())
                        .map(|meta| (bucket_id_from_metadata_key(*key), meta.capacity))
                })
                .collect();

            // Filter out keys that exceed old capacities (this can happen after bucket expansion)
            witnessed_keys.extend(recorder.cache.into_keys().filter(|key| {
                old_capacities
                    .get(&key.bucket_id())
                    .is_none_or(|&old_cap| key.slot_id() < old_cap)
            }));

            Ok(())
        })()
        .map_err(|e| ProofError::StateReadError {
            reason: format!("{e:?}"),
        })?;

        Ok(Witness {
            direct_lookup_tbl,
            salt_witness: SaltWitness::create(&witnessed_keys, store)?,
        })
    }

    /// Returns the state root computed from the witness's root commitment.
    ///
    /// # Returns
    /// - `Ok(ScalarBytes)` - The 32-byte state root
    /// - `Err(ProofError)` - If the root commitment is not in the witness
    pub fn state_root(&self) -> Result<ScalarBytes, ProofError> {
        self.salt_witness.state_root()
    }

    /// Verifies the proof's integrity and validates key locations.
    ///
    /// This method performs a two-phase verification process:
    ///
    /// 1. **Cryptographic Proof Verification**: Validates the underlying SALT
    ///    witness proof against the [`state_root()`] to ensure the proof is
    ///    cryptographically sound and the claimed key-value pairs are authentic.
    ///
    /// 2. **Key Location Verification**: For each plain key in the proof, verifies
    ///    that it can be found exactly at the claimed salt key location.
    ///
    /// # Returns
    ///
    /// * `Ok(())` - If both cryptographic proof and key locations are valid
    /// * `Err(ProofError)` - If verification fails due to:
    ///   - Invalid cryptographic proof
    ///   - Incorrect lookup table
    ///   - Missing root commitment in witness
    pub fn verify(&self) -> Result<(), ProofError> {
        self.salt_witness.verify_proof()?;

        let mut state = EphemeralSaltState::new(self);

        for (plain_key, expected_salt_key) in &self.direct_lookup_tbl {
            // Verify lookup table consistency with underlying SaltWitness:
            // direct_find -> Self::plain_value_fast -> Self::value -> SaltWitness::value
            let found_key = state.direct_find(plain_key).ok().flatten().map(|(k, _)| k);

            match found_key {
                Some(k) if k == *expected_salt_key => {}
                Some(_) => {
                    return Err(ProofError::InvalidLookupTable {
                        reason: format!(
                            "Key found in wrong location: {:?}",
                            String::from_utf8_lossy(plain_key)
                        ),
                    })
                }
                None => {
                    return Err(ProofError::InvalidLookupTable {
                        reason: format!(
                            "Key claimed to exist but not found: {:?}",
                            String::from_utf8_lossy(plain_key)
                        ),
                    })
                }
            }
        }

        Ok(())
    }
}

// Implementation of StateReader trait for Witness
// This allows the proof to be used as a state reader during verification,
// providing only the data that was included in the proof
impl StateReader for Witness {
    type Error = SaltError;

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

    fn get_subtree_levels(&self, bucket_id: BucketId) -> Result<usize, Self::Error> {
        self.salt_witness.get_subtree_levels(bucket_id)
    }

    fn bucket_used_slots(&self, bucket_id: BucketId) -> Result<u64, Self::Error> {
        self.salt_witness.bucket_used_slots(bucket_id)
    }

    fn plain_value_fast(&self, plain_key: &[u8]) -> Result<SaltKey, Self::Error> {
        match self.direct_lookup_tbl.get(plain_key) {
            Some(salt_key) => Ok(*salt_key),
            None => Err(SaltError::NotInWitness { what: "Plain key" }),
        }
    }
}

impl TrieReader for Witness {
    type Error = SaltError;

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
        constant::*,
        mem_store::MemStore,
        proof::salt_witness::{create_mock_proof, SaltWitness},
        proof::test_utils::*,
        trie::trie::StateRoot,
        types::{bucket_metadata_key, BucketMeta, SaltKey, SaltValue},
    };
    use rand::{rngs::StdRng, SeedableRng};
    use std::collections::{BTreeMap, HashMap, HashSet};

    /// Extracts all values from a witness in the order of its lookup table keys.
    #[cfg(not(feature = "test-bucket-resize"))]
    pub fn extract_witness_values(witness: &Witness) -> Vec<Option<Vec<u8>>> {
        let mut state = EphemeralSaltState::new(witness);
        witness
            .direct_lookup_tbl
            .keys()
            .map(|key| state.plain_value(key).unwrap())
            .collect()
    }

    /// Selects specific test keys by their indices from the predefined set.
    fn select_test_keys(indices: Vec<usize>) -> Vec<Vec<u8>> {
        indices
            .into_iter()
            .map(|i| test_keys_with_known_mappings()[i].clone())
            .collect()
    }

    /// Sets up state with given keys and returns the computed state root.
    fn setup_state_with_keys(keys: Vec<Vec<u8>>, store: &MemStore) -> [u8; 32] {
        let kvs: HashMap<_, _> = keys
            .iter()
            .map(|k| (k.clone(), Some(k[0..20].to_vec())))
            .collect();
        let updates = EphemeralSaltState::new(store).update(&kvs).unwrap();
        store.update_state(updates.clone());
        let (root, trie_updates) = StateRoot::new(store).update_fin(&updates).unwrap();
        store.update_trie(trie_updates);
        root
    }

    /// Provides 10 test keys with predetermined bucket/slot mappings.
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
    fn test_keys_with_known_mappings() -> Vec<Vec<u8>> {
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

    /// Test serialization and deserialization of SaltWitness and that Witness
    /// can be reconstructed from the deserialized SaltWitness.
    #[test]
    fn test_witness_serde() {
        // Create test account data
        let mut rng = StdRng::seed_from_u64(42);
        let kvs = HashMap::from([(mock_data(&mut rng, 20), Some(mock_data(&mut rng, 40)))]);

        // Insert into Salt storage and update the trie
        let store = MemStore::new();
        let updates = EphemeralSaltState::new(&store).update(&kvs).unwrap();
        store.update_state(updates.clone());

        let (root, trie_updates) = StateRoot::new(&store).update_fin(&updates).unwrap();
        store.update_trie(trie_updates);

        // Generate a witness for the inserted key
        let witness = Witness::create(
            &kvs.keys().cloned().collect::<Vec<_>>(),
            std::iter::empty(),
            &store,
        )
        .unwrap();

        // Test serialization round-trip of the underlying SaltWitness
        let serialized =
            bincode::serde::encode_to_vec(&witness.salt_witness, bincode::config::legacy())
                .unwrap();
        let (deserialized, _): (SaltWitness, _) =
            bincode::serde::decode_from_slice(&serialized, bincode::config::legacy()).unwrap();

        // Reconstruct the Witness from the deserialized SaltWitness
        let reconstructed = Witness::from(deserialized);

        // Verify the reconstructed witness is identical and still valid
        assert_eq!(witness, reconstructed);
        assert_eq!(root, reconstructed.state_root().unwrap());
        assert!(reconstructed.verify().is_ok());
    }

    #[test]
    #[cfg(not(feature = "test-bucket-resize"))]
    fn test_witness_exist_or_not_exist() {
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
        let root = setup_state_with_keys(select_test_keys(vec![0, 1, 2, 3, 4, 5, 6]), &store);

        let plain_key = test_keys_with_known_mappings()[6].clone();
        let proof = Witness::create(&[plain_key.clone()], std::iter::empty(), &store).unwrap();

        assert_eq!(root, proof.state_root().unwrap());
        assert!(proof.verify().is_ok());

        let mut proof_state = EphemeralSaltState::new(&proof);
        let proof_value = proof_state.plain_value(&plain_key).unwrap();
        let proof_values = extract_witness_values(&proof);

        assert!(proof_value.is_some());

        let plain_value = EphemeralSaltState::new(&store)
            .plain_value(&plain_key)
            .unwrap();

        assert_eq!(plain_value, proof_value);
        assert_eq!(proof_values, vec![proof_value]);

        // case 2.1
        let store = MemStore::new();
        let root = setup_state_with_keys(select_test_keys(vec![6]), &store);

        let plain_key = test_keys_with_known_mappings()[0].clone();
        let proof = Witness::create(&[plain_key.clone()], std::iter::empty(), &store).unwrap();

        assert_eq!(root, proof.state_root().unwrap());
        assert!(proof.verify().is_ok());

        let mut proof_state = EphemeralSaltState::new(&proof);
        let proof_value = proof_state.plain_value(&plain_key).unwrap();
        assert!(proof_value.is_none());

        let plain_value = EphemeralSaltState::new(&store)
            .plain_value(&plain_key)
            .unwrap();
        assert_eq!(plain_value, proof_value);

        let bucket_id: BucketId = 2448221;
        let slot_id: SlotId = 1;
        let salt_key = SaltKey::from((bucket_id, slot_id));

        // the salt_key stores the test_keys_with_known_mappings()[6]'s salt_value
        let salt_value = proof.value(salt_key).unwrap().unwrap();
        // test_keys_with_known_mappings()[0] has a high priority than the test_keys_with_known_mappings()[6]
        assert!(test_keys_with_known_mappings()[0] > test_keys_with_known_mappings()[6]);
        assert_eq!(salt_value.key(), test_keys_with_known_mappings()[6]);

        let meta = proof.metadata(bucket_id).unwrap();

        let mut proof_state = EphemeralSaltState::new(&proof);
        // can't find the test_keys_with_known_mappings()[0]
        let find_res = proof_state
            .shi_find(
                bucket_id,
                meta.nonce,
                meta.capacity,
                &test_keys_with_known_mappings()[0],
            )
            .unwrap();
        assert!(find_res.is_none());

        let find_res = proof_state
            .shi_find(
                bucket_id,
                meta.nonce,
                meta.capacity,
                &test_keys_with_known_mappings()[6],
            )
            .unwrap();
        assert_eq!(find_res, Some((slot_id, salt_value)));

        // case 2.2
        let store = MemStore::new();
        let root = setup_state_with_keys(select_test_keys(vec![6, 0]), &store);

        let plain_key = test_keys_with_known_mappings()[1].clone();
        let proof = Witness::create(&[plain_key.clone()], std::iter::empty(), &store).unwrap();

        assert_eq!(root, proof.state_root().unwrap());
        assert!(proof.verify().is_ok());

        let mut proof_state = EphemeralSaltState::new(&proof);
        let proof_value = proof_state.plain_value(&plain_key).unwrap();
        assert!(proof_value.is_none());

        let plain_value = EphemeralSaltState::new(&store)
            .plain_value(&plain_key)
            .unwrap();
        assert_eq!(plain_value, proof_value);

        let bucket_id: BucketId = 2448221;
        let slot_id: SlotId = 2;
        let salt_key = SaltKey::from((bucket_id, slot_id));

        // the salt_key stores the test_keys_with_known_mappings()[6]'s salt_value
        let salt_value = proof.value(salt_key).unwrap().unwrap();
        assert_eq!(salt_value.key(), test_keys_with_known_mappings()[6]);
        // test_keys_with_known_mappings()[1] has a high priority than the test_keys_with_known_mappings()[6]
        assert!(test_keys_with_known_mappings()[1] > salt_value.key().to_vec());

        let meta = proof.metadata(bucket_id).unwrap();

        let mut proof_state = EphemeralSaltState::new(&proof).cache_read();
        // can't find the test_keys_with_known_mappings()[1]
        let find_res = proof_state
            .shi_find(
                bucket_id,
                meta.nonce,
                meta.capacity,
                &test_keys_with_known_mappings()[1],
            )
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
        let root = setup_state_with_keys(select_test_keys(vec![6, 0, 2]), &store);

        let plain_key = test_keys_with_known_mappings()[1].clone();
        let proof = Witness::create(&[plain_key.clone()], std::iter::empty(), &store).unwrap();

        assert_eq!(root, proof.state_root().unwrap());
        assert!(proof.verify().is_ok());

        let mut proof_state = EphemeralSaltState::new(&proof);
        let proof_value = proof_state.plain_value(&plain_key).unwrap();
        assert!(proof_value.is_none());

        let plain_value = EphemeralSaltState::new(&store)
            .plain_value(&plain_key)
            .unwrap();
        assert_eq!(plain_value, proof_value);

        let bucket_id: BucketId = 2448221;
        let slot_id: SlotId = 2;
        let salt_key = SaltKey::from((bucket_id, slot_id));

        // the salt_key stores the test_keys_with_known_mappings()[2]'s salt_value
        let salt_value = proof.value(salt_key).unwrap().unwrap();
        assert_eq!(salt_value.key(), test_keys_with_known_mappings()[2]);
        // test_keys_with_known_mappings()[1] has a high priority than the test_keys_with_known_mappings()[6]
        assert!(test_keys_with_known_mappings()[1] > salt_value.key().to_vec());

        let meta = proof.metadata(bucket_id).unwrap();

        let mut proof_state = EphemeralSaltState::new(&store);
        // can't find the test_keys_with_known_mappings()[1]
        let find_res = proof_state
            .shi_find(
                bucket_id,
                meta.nonce,
                meta.capacity,
                &test_keys_with_known_mappings()[1],
            )
            .unwrap();
        assert!(find_res.is_none());

        let find_res = proof_state
            .shi_find(
                bucket_id,
                meta.nonce,
                meta.capacity,
                &test_keys_with_known_mappings()[2],
            )
            .unwrap();
        assert_eq!(find_res, Some((slot_id, salt_value)));

        // case 3.1
        let store = MemStore::new();
        let root = setup_state_with_keys(select_test_keys(vec![]), &store);

        let plain_key = test_keys_with_known_mappings()[0].clone();
        let proof = Witness::create(&[plain_key.clone()], std::iter::empty(), &store).unwrap();

        assert_eq!(root, proof.state_root().unwrap());
        assert!(proof.verify().is_ok());

        let mut proof_state = EphemeralSaltState::new(&proof);
        let proof_value = proof_state.plain_value(&plain_key).unwrap();
        assert!(proof_value.is_none());

        let plain_value = EphemeralSaltState::new(&store)
            .plain_value(&plain_key)
            .unwrap();
        assert_eq!(plain_value, proof_value);

        let bucket_id: BucketId = 2448221;
        let slot_id: SlotId = 1;
        let salt_key = SaltKey::from((bucket_id, slot_id));

        // the salt_key stores none value
        let salt_value = proof.value(salt_key).unwrap();
        assert!(salt_value.is_none());

        let meta = proof.metadata(bucket_id).unwrap();

        let mut proof_state = EphemeralSaltState::new(&store);
        // can't find the test_keys_with_known_mappings()[0]
        let find_res = proof_state
            .shi_find(
                bucket_id,
                meta.nonce,
                meta.capacity,
                &test_keys_with_known_mappings()[0],
            )
            .unwrap();
        assert!(find_res.is_none());

        // case 3.2
        let store = MemStore::new();
        let root = setup_state_with_keys(select_test_keys(vec![0, 1, 2, 3, 4, 5]), &store);

        let plain_key = test_keys_with_known_mappings()[6].clone();
        let proof = Witness::create(&[plain_key.clone()], std::iter::empty(), &store).unwrap();

        assert_eq!(root, proof.state_root().unwrap());
        assert!(proof.verify().is_ok());

        let mut proof_state = EphemeralSaltState::new(&proof);
        let proof_value = proof_state.plain_value(&plain_key).unwrap();
        assert!(proof_value.is_none());

        let plain_value = EphemeralSaltState::new(&store)
            .plain_value(&plain_key)
            .unwrap();
        assert_eq!(plain_value, proof_value);

        let bucket_id: BucketId = 2448221;
        let slot_id: SlotId = 7;
        let salt_key = SaltKey::from((bucket_id, slot_id));

        // the salt_key stores the test_keys_with_known_mappings()[6]'s salt_value
        let salt_value = proof.value(salt_key).unwrap();
        assert!(salt_value.is_none());

        let meta = proof.metadata(bucket_id).unwrap();

        let mut proof_state = EphemeralSaltState::new(&proof).cache_read();
        // can't find the test_keys_with_known_mappings()[1]
        let find_res = proof_state
            .shi_find(
                bucket_id,
                meta.nonce,
                meta.capacity,
                &test_keys_with_known_mappings()[6],
            )
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
    #[cfg(not(feature = "test-bucket-resize"))]
    fn test_witness_in_loop_slot_id() {
        let store = MemStore::new();
        let root = setup_state_with_keys(select_test_keys(vec![9]), &store);

        let key = test_keys_with_known_mappings()[7].clone();

        let proof = Witness::create(&[key.clone()], std::iter::empty(), &store).unwrap();

        assert_eq!(root, proof.state_root().unwrap());
        assert!(proof.verify().is_ok());

        let bucket_id = 4030087;
        let salt_key = SaltKey::from((bucket_id, 0));

        let salt_value = proof.value(salt_key).unwrap();
        assert!(salt_value.is_none());

        let meta = proof.metadata(bucket_id).unwrap();

        let mut proof_state = EphemeralSaltState::new(&proof).cache_read();
        // can't find the test_keys_with_known_mappings()[1]
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
        let root = setup_state_with_keys(select_test_keys(vec![7, 8, 9]), &store);

        let key = test_keys_with_known_mappings()[8].clone();

        let proof = Witness::create(&[key.clone()], std::iter::empty(), &store).unwrap();

        assert_eq!(root, proof.state_root().unwrap());
        assert!(proof.verify().is_ok());

        assert_eq!(proof.direct_lookup_tbl.keys().next().unwrap(), &key);

        let salt_key = SaltKey::from((bucket_id, 1));
        let salt_value = proof.value(salt_key).unwrap().unwrap();

        let salt_val = store.value(salt_key).unwrap().unwrap();

        assert_eq!(salt_value, salt_val);
    }

    /// Test that Witness correctly implements StateReader trait.
    /// Verifies that the proof contains the same data as the original state.
    #[test]
    fn test_witness_state_reader_trait() {
        let l = 100;
        let mut rng = StdRng::seed_from_u64(42);
        let mut kvs = HashMap::new();

        // Generate shorter keys/values for half the test cases
        (0..l / 2).for_each(|_| {
            let pk = mock_data(&mut rng, 20);
            let pv = Some(mock_data(&mut rng, 40));
            kvs.insert(pk, pv);
        });

        // Generate longer keys/values for the other half
        (l / 2..l).for_each(|_| {
            let pk = mock_data(&mut rng, 52);
            let pv = Some(mock_data(&mut rng, 32));
            kvs.insert(pk, pv);
        });

        let store = MemStore::new();
        let mut state = EphemeralSaltState::new(&store);
        let updates = state.update(&kvs).unwrap();
        store.update_state(updates.clone());

        let (_, trie_updates) = StateRoot::new(&store).update_fin(&updates).unwrap();

        store.update_trie(trie_updates);

        let witness = Witness::create(
            &kvs.keys().cloned().collect::<Vec<_>>(),
            std::iter::empty(),
            &store,
        )
        .unwrap();

        for key in witness.salt_witness.kvs.keys() {
            let proof_value = witness.value(*key).unwrap();
            let mut state_value = state.value(*key).unwrap();
            if state_value.is_none() && key.is_in_meta_bucket() {
                state_value = Some(BucketMeta::default().into());
            }
            assert_eq!(proof_value, state_value);
        }
    }

    /// Verifies that witnesses for existing keys do not include bucket metadata.
    ///
    /// When creating a witness for keys that exist in storage, the witness should
    /// contain only the key-value pairs themselves, not the bucket metadata. This
    /// optimization reduces witness size since existing keys can be verified directly
    /// without needing bucket configuration (nonce, capacity) that's only required
    /// for non-existence proofs.
    #[test]
    fn test_existing_keys_witness_excludes_bucket_metadata() {
        // Setup: Insert 3 specific test keys into storage
        // These keys (indices 7,8,9) are chosen to test various bucket scenarios
        let store = MemStore::new();
        let root = setup_state_with_keys(select_test_keys(vec![7, 8, 9]), &store);

        // Create a witness for the same 3 keys that were inserted
        let keys = select_test_keys(vec![7, 8, 9]);
        let proof = Witness::create(&keys, std::iter::empty(), &store).unwrap();

        // Verify the witness is valid against the state root
        assert_eq!(root, proof.state_root().unwrap());
        assert!(proof.verify().is_ok());

        // Verify witness contains exactly 3 entries (no metadata included)
        assert_eq!(proof.direct_lookup_tbl.len(), 3);
        assert_eq!(proof.salt_witness.kvs.len(), 3);

        // Verify both structures contain the same salt keys (no extra metadata)
        let witness_keys: HashSet<_> = proof.salt_witness.kvs.keys().collect();
        let lookup_values: HashSet<_> = proof.direct_lookup_tbl.values().collect();
        assert_eq!(witness_keys, lookup_values);
    }

    /// Verifies that `Witness::get_subtree_levels` does not use the default
    /// implementation. It delegates to `SaltWitness::get_subtree_levels`.
    #[test]
    fn test_witness_get_subtree_levels() {
        let bucket_id = 100_000;
        let mut proof = create_mock_proof();
        proof.levels.insert(bucket_id, 3);

        let salt_witness = SaltWitness {
            kvs: BTreeMap::new(),
            proof,
        };
        let witness = Witness::from(salt_witness);

        assert_eq!(witness.get_subtree_levels(bucket_id).unwrap(), 3);
    }

    /// Verifies that `Witness::bucket_used_slots` does not use the default
    /// implementation. It delegates to `SaltWitness::slots`.
    #[test]
    fn test_witness_bucket_used_slots() {
        let bucket_id = 100_000;
        let meta_key = bucket_metadata_key(bucket_id);

        // SaltWitness::bucket_used_slots must know the bucket capacity
        let mut kvs = BTreeMap::new();
        kvs.insert(meta_key, Some(BucketMeta::default().into()));

        // Initialize every bucket slot so SaltWitness::bucket_used_slots can
        // scan and count the number of used slots.
        for i in 0..MIN_BUCKET_SIZE {
            kvs.insert(SaltKey::from((bucket_id, i as u64)), None);
        }
        let used_slots = 3;
        for i in 0..used_slots {
            let val = SaltValue::new(&[1u8; 32], &[2u8; 32]);
            kvs.insert(SaltKey::from((bucket_id, i)), Some(val));
        }

        let salt_witness = SaltWitness {
            kvs,
            proof: create_mock_proof(),
        };
        let witness = Witness::from(salt_witness);

        assert_eq!(witness.bucket_used_slots(bucket_id).unwrap(), used_slots);
    }
}
