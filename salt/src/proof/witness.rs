//! Witness generation and verification for plain (user-provided) keys.
//!
//! This module implements a high-level proof system that allows clients to prove
//! the existence or non-existence of plain keys without requiring access to the
//! full state. It acts as an abstraction layer over the lower-level `SaltWitness`
//! proof system.

use crate::types::{bucket_id_from_metadata_key, METADATA_KEYS_RANGE};
use crate::{
    proof::salt_witness::SaltWitness,
    proof::ProofError,
    state::{hasher, state::EphemeralSaltState},
    traits::{StateReader, TrieReader},
    types::*,
};
use core::ops::{Range, RangeInclusive};
use hashbrown::HashMap;
use std::{collections::BTreeMap, format, string::String, vec, vec::Vec};

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

    /// Occupied-slot count of every data bucket whose slots are all witnessed.
    ///
    /// Derived from `salt_witness.kvs` when the witness is built, so that
    /// [`StateReader::bucket_used_slots`] does not rescan the bucket on every insertion.
    pub(crate) fully_witnessed: HashMap<BucketId, u64>,

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
            fully_witnessed: fully_witnessed_usage(&salt_witness.kvs),
            salt_witness,
        }
    }
}

/// Occupied-slot counts of the data buckets whose slots are all witnessed.
///
/// One pass over the witnessed keys. Must not panic: this runs on witness bytes that have not been
/// verified yet.
fn fully_witnessed_usage(kvs: &BTreeMap<SaltKey, Option<SaltValue>>) -> HashMap<BucketId, u64> {
    let mut usage = HashMap::new();
    let first_data_key = SaltKey::from((crate::constant::NUM_META_BUCKETS as BucketId, 0));
    let mut data = kvs.range(first_data_key..).peekable();
    // Keys are ordered by bucket, so a bucket's witnessed slots form one run. Each step takes
    // the run's first key itself, then the keys that follow it in the same bucket.
    while let Some(first) = data.next() {
        let bucket_id = first.0.bucket_id();
        let capacity = match kvs.get(&bucket_metadata_key(bucket_id)) {
            Some(Some(value)) => BucketMeta::try_from(value).ok().map(|meta| meta.capacity),
            _ => None,
        };
        let rest = core::iter::from_fn(|| data.next_if(|(key, _)| key.bucket_id() == bucket_id));
        let (mut witnessed, mut used) = (0u64, 0u64);
        for (key, value) in core::iter::once(first).chain(rest) {
            if capacity.is_some_and(|capacity| key.slot_id() < capacity) {
                witnessed += 1;
                used += u64::from(value.is_some());
            }
        }
        if capacity == Some(witnessed) {
            usage.insert(bucket_id, used);
        }
    }
    usage
}

impl Witness {
    /// Creates a comprehensive cryptographic witness for stateless validators.
    ///
    /// This method generates a witness that enables stateless validators to both
    /// re-execute transactions (using the lookup keys) and update the state root
    /// afterwards (using the state updates). It generates inclusion proofs for
    /// existing keys and exclusion proofs for non-existing keys.
    ///
    /// # Deterministic Ordering
    ///
    /// The `updates` parameter uses `BTreeMap` to enforece deterministic key ordering.
    /// When producer and validator process keys in the same order, correctness becomes
    /// straightforward to verify.
    ///
    /// # Arguments
    /// * `bucket_ids` - Buckets whose metadata are read during execution
    /// * `lookups` - Plain keys to be read during execution
    /// * `updates` - Plain keys to be inserted, deleted, or updated during execution.
    ///   Each entry is (plain_key, optional_value) where:
    ///   - Some(value) indicates an insert or update
    ///   - None indicates deletion
    /// * `store` - The storage backend providing access to both state data
    ///   (key-value pairs) and trie data (cryptographic commitments).
    ///
    /// # Returns
    /// A `Witness` containing:
    /// - The minimal set of SALT key-value pairs needed for transaction execution
    /// - A minimal SALT subtrie needed for updating the state root post-execution
    /// - A cryptographic proof that proves the authenticity of these data
    ///
    /// # Errors
    /// Returns `ProofError::StateReadError` if:
    /// - Unable to read bucket metadata
    /// - Unable to perform SHI search operations
    /// - Unable to access required state data
    /// - Witness creation fails
    pub fn create<'b, Store>(
        bucket_ids: impl IntoIterator<Item = BucketId>,
        lookups: impl IntoIterator<Item = &'b Vec<u8>>,
        updates: &BTreeMap<Vec<u8>, Option<Vec<u8>>>,
        store: &Store,
    ) -> Result<Witness, ProofError>
    where
        Store: StateReader + TrieReader,
    {
        let mut witnessed_keys = vec![];
        let mut direct_lookup_tbl = HashMap::new();

        witnessed_keys.extend(bucket_ids.into_iter().map(bucket_metadata_key));

        (|| -> Result<(), <Store as StateReader>::Error> {
            // We use two separate state instances to collect witness data:
            // - 'state': For performing lookups to determine if keys exist
            // - 'recorder': For recording slot accesses during non-existence
            //   proofs and key insertion/deletion
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

            // Separate update operations from insert/delete operations
            let inserts_or_deletes: Vec<_> = updates
                .iter()
                .filter_map(|(plain_key, new_value)| {
                    let bucket_id = hasher::bucket_id(plain_key);
                    let metadata = store.metadata(bucket_id).ok()?;

                    match state
                        .shi_find(bucket_id, metadata.nonce, metadata.capacity, plain_key)
                        .ok()?
                    {
                        Some((slot_id, _)) if new_value.is_some() => {
                            // Update operation: witness the old state (same as lookups)
                            let salt_key = SaltKey::from((bucket_id, slot_id));
                            direct_lookup_tbl.insert(plain_key.clone(), salt_key);
                            witnessed_keys.push(salt_key);
                            None
                        }
                        _ => Some((plain_key, new_value)), // Insert or delete operation
                    }
                })
                .collect();

            let state_updates = recorder.update(inserts_or_deletes)?;

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

        let salt_witness = SaltWitness::create(&witnessed_keys, store)?;
        Ok(Witness {
            direct_lookup_tbl,
            fully_witnessed: fully_witnessed_usage(&salt_witness.kvs),
            salt_witness,
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

    /// Returns the occupied-slot count of a bucket whose slots are all witnessed.
    ///
    /// Same answers as [`SaltWitness::bucket_used_slots`] in constant time: resizing a bucket
    /// reinserts every key, and each insertion asks for this count.
    fn bucket_used_slots(&self, bucket_id: BucketId) -> Result<u64, Self::Error> {
        if !is_valid_data_bucket(bucket_id) {
            return Ok(0);
        }
        self.fully_witnessed
            .get(&bucket_id)
            .copied()
            .ok_or(SaltError::NotInWitness {
                what: "Bucket slots",
            })
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
#[allow(clippy::cloned_ref_to_slice_refs)]
mod tests {
    use super::*;
    use crate::{
        constant::*,
        empty_salt::EmptySalt,
        mem_store::MemStore,
        proof::{
            salt_witness::{create_mock_proof, SaltWitness},
            test_utils::*,
        },
        state::updates::StateUpdates,
        trie::trie::StateRoot,
        types::{bucket_metadata_key, BucketMeta, SaltKey, SaltValue},
    };
    use hashbrown::{HashMap, HashSet};
    use rand::{rngs::StdRng, SeedableRng};
    use std::collections::BTreeMap;
    use std::vec::Vec;

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
        let updates = EphemeralSaltState::new(store).update_fin(&kvs).unwrap();
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
        let kvs: HashMap<_, _> = [(mock_data(&mut rng, 20), Some(mock_data(&mut rng, 40)))]
            .iter()
            .cloned()
            .collect();

        // Insert into Salt storage and update the trie
        let store = MemStore::new();
        let updates = EphemeralSaltState::new(&store).update_fin(&kvs).unwrap();
        store.update_state(updates.clone());

        let (root, trie_updates) = StateRoot::new(&store).update_fin(&updates).unwrap();
        store.update_trie(trie_updates);

        // Generate a witness for the inserted key
        let witness = Witness::create([], kvs.keys(), &BTreeMap::new(), &store).unwrap();

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
    fn test_plain_value_fast_unknown_key_is_not_in_witness() {
        let witness = Witness {
            direct_lookup_tbl: HashMap::new(),
            fully_witnessed: HashMap::new(),
            salt_witness: SaltWitness {
                kvs: BTreeMap::new(),
                proof: crate::proof::salt_witness::create_mock_proof(),
            },
        };

        assert_eq!(
            witness.plain_value_fast(b"unknown"),
            Err(SaltError::NotInWitness { what: "Plain key" })
        );
    }

    /// A witness built for a block whose replay itself expands a bucket must
    /// carry everything the stateless re-execution needs: the old-capacity
    /// filter on recorded reads has to keep exactly the pre-state slots.
    #[test]
    #[cfg(not(feature = "test-bucket-resize"))]
    fn test_witness_replay_across_replay_triggered_expansion() {
        use crate::state::hasher::tests::get_same_bucket_test_keys;

        let keys = get_same_bucket_test_keys();
        let store = MemStore::new();
        let initial: BTreeMap<_, _> = keys[..200]
            .iter()
            .map(|k| (k.clone(), Some(k.clone())))
            .collect();
        let mut state = EphemeralSaltState::new(&store);
        let updates = state.update_fin(&initial).unwrap();
        store.update_state(updates.clone());
        let mut trie = StateRoot::new(&store);
        let (_, trie_updates) = trie.update_fin(&updates).unwrap();
        store.update_trie(trie_updates);

        // 60 more inserts push the bucket past the 80% load factor, so the
        // replay performed during witness creation expands it to 512 slots.
        let block_updates: BTreeMap<_, _> = keys[200..]
            .iter()
            .map(|k| (k.clone(), Some(k.clone())))
            .collect();
        let lookups = vec![keys[0].clone(), b"witness-missing-key".to_vec()];
        let witness = Witness::create([], &lookups, &block_updates, &store).unwrap();
        witness.verify().unwrap();

        let mut full_state = EphemeralSaltState::new(&store).cache_read();
        let full_updates = full_state.update_fin(block_updates.iter()).unwrap();
        let mut witness_state = EphemeralSaltState::new(&witness).cache_read();
        let witness_updates = witness_state.update_fin(block_updates.iter()).unwrap();
        assert_eq!(witness_updates, full_updates);

        let (full_root, _) = StateRoot::new(&store).update_fin(&full_updates).unwrap();
        let (witness_root, _) = StateRoot::new(&witness)
            .update_fin(&witness_updates)
            .unwrap();
        assert_eq!(witness_root, full_root);
    }

    #[test]
    fn test_witness_from_salt_witness_excludes_metadata_direct_lookup() {
        let bucket_id = NUM_META_BUCKETS as BucketId;
        let metadata_key = bucket_metadata_key(bucket_id);
        let data_key = SaltKey::from((bucket_id, 7));
        let plain_key = b"plain-key".to_vec();
        let mut kvs = BTreeMap::new();
        kvs.insert(metadata_key, Some(BucketMeta::default().into()));
        kvs.insert(data_key, Some(SaltValue::new(&plain_key, b"value")));

        let witness = Witness::from(SaltWitness {
            kvs,
            proof: crate::proof::salt_witness::create_mock_proof(),
        });

        assert_eq!(witness.direct_lookup_tbl.len(), 1);
        assert_eq!(witness.direct_lookup_tbl[&plain_key], data_key);
        let metadata_bytes = BucketMeta::default().to_bytes().to_vec();
        assert!(!witness.direct_lookup_tbl.contains_key(&metadata_bytes));
    }

    #[test]
    fn test_verify_rejects_tampered_direct_lookup_slot() {
        let store = MemStore::new();
        let plain_key = test_keys_with_known_mappings()[0].clone();
        setup_state_with_keys(vec![plain_key.clone()], &store);
        let mut witness =
            Witness::create([], &[plain_key.clone()], &BTreeMap::new(), &store).unwrap();
        let salt_key = witness.direct_lookup_tbl[&plain_key];

        witness.direct_lookup_tbl.insert(
            plain_key,
            SaltKey::from((salt_key.bucket_id(), salt_key.slot_id() + 1)),
        );

        assert!(matches!(
            witness.verify(),
            Err(ProofError::InvalidLookupTable { .. })
        ));
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
        let proof = Witness::create([], &[plain_key.clone()], &BTreeMap::new(), &store).unwrap();

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
        let proof = Witness::create([], &[plain_key.clone()], &BTreeMap::new(), &store).unwrap();

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
        let proof = Witness::create([], &[plain_key.clone()], &BTreeMap::new(), &store).unwrap();

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
            .keys()
            .filter_map(|k| (k.bucket_id() > NUM_META_BUCKETS as u32).then_some(*k))
            .collect();

        related_keys.sort_unstable();
        assert_eq!(related_keys, vec![SaltKey::from((bucket_id, 2))]);

        // case 2.3
        let store = MemStore::new();
        let root = setup_state_with_keys(select_test_keys(vec![6, 0, 2]), &store);

        let plain_key = test_keys_with_known_mappings()[1].clone();
        let proof = Witness::create([], &[plain_key.clone()], &BTreeMap::new(), &store).unwrap();

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
        let proof = Witness::create([], &[plain_key.clone()], &BTreeMap::new(), &store).unwrap();

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
        let proof = Witness::create([], &[plain_key.clone()], &BTreeMap::new(), &store).unwrap();

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
            .keys()
            .filter_map(|k| (k.bucket_id() > NUM_META_BUCKETS as u32).then_some(*k))
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

        let proof = Witness::create([], &[key.clone()], &BTreeMap::new(), &store).unwrap();

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
            .keys()
            .filter_map(|k| (k.bucket_id() > NUM_META_BUCKETS as u32).then_some(*k))
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

        let proof = Witness::create([], &[key.clone()], &BTreeMap::new(), &store).unwrap();

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
        let updates = state.update_fin(&kvs).unwrap();
        store.update_state(updates.clone());

        let (_, trie_updates) = StateRoot::new(&store).update_fin(&updates).unwrap();

        store.update_trie(trie_updates);

        let witness = Witness::create([], kvs.keys(), &BTreeMap::new(), &store).unwrap();

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
        let proof = Witness::create([], &keys, &BTreeMap::new(), &store).unwrap();

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

    /// Verifies that witnesses contain sufficient data to correctly compute new
    /// state roots, which is essential for stateless validation.
    #[test]
    fn test_witness_state_root_update() {
        let mut rng = StdRng::seed_from_u64(42);

        // Generate `n` random key-value pairs
        let n = 230;
        let kvs: HashMap<_, _> = (0..n)
            .map(|_| (mock_data(&mut rng, 32), Some(mock_data(&mut rng, 32))))
            .collect();

        // Both paths share the same starting point (empty MemStore in this case)
        let store = MemStore::new();

        // Create witness from initial state BEFORE any mutations
        let updates: BTreeMap<_, _> = kvs.iter().map(|(k, v)| (k.clone(), v.clone())).collect();
        let witness = Witness::create([], core::iter::empty(), &updates, &store).unwrap();

        // Pass 1: MemStore-based insertion (mutates store)
        let updates = EphemeralSaltState::new(&store).update_fin(&kvs).unwrap();
        store.update_state(updates.clone());
        let (store_root, _) = StateRoot::new(&store).update_fin(&updates).unwrap();

        // Pass 2: Witness-based insertion (using witness created from initial state)
        let witness_updates = EphemeralSaltState::new(&witness).update_fin(&kvs).unwrap();
        let (witness_root, _) = StateRoot::new(&witness)
            .update_fin(&witness_updates)
            .unwrap();

        // Both passes should produce identical roots
        assert_eq!(store_root, witness_root);
    }

    /// Verifie that Witness::create() should not canonicalize the bucket layouts before
    /// filtering out invalid keys.
    #[test]
    fn test_witness_create_should_not_canonicalize() {
        let mut rng = StdRng::seed_from_u64(42);

        // Inserts then deletes `n` random key-value pairs
        let n = 230;
        let inserts: HashMap<_, _> = (0..n)
            .map(|_| (mock_data(&mut rng, 32), Some(mock_data(&mut rng, 32))))
            .collect();

        let deletes: HashMap<_, _> = inserts.keys().map(|k| (k.clone(), None)).collect();

        // Salt proof creation should fail with an InvalidSaltKey error if Witness::create()
        // incorrectly uses update_fin() to eliminate the bucket capacity changes too early
        let combined: BTreeMap<_, _> = inserts
            .iter()
            .chain(deletes.iter())
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();
        let witness = Witness::create([], core::iter::empty(), &combined, &EmptySalt).unwrap();

        // Verify no keys should exist in witness
        let mut witness_state = EphemeralSaltState::new(&witness);
        for key in inserts.keys() {
            assert_eq!(
                witness_state.plain_value(key).unwrap(),
                None,
                "Key should be deleted in witness after insert+delete"
            );
        }
    }

    /// Verifies that Witness::create include bucket metadata for explicitly requested buckets.
    #[test]
    fn test_witness_create_bucket_ids() {
        // Test bucket IDs across the full 24-bit bucket ID space.
        let bucket_ids = [65536, 100_000, 1_000_000, 5_000_000, 16_777_215];
        let new_metadata = BucketMeta {
            capacity: (8 * MIN_BUCKET_SIZE) as u64,
            ..BucketMeta::default()
        };

        let meta_updates = StateUpdates {
            data: bucket_ids
                .iter()
                .map(|&id| {
                    (
                        bucket_metadata_key(id),
                        (
                            Some(BucketMeta::default().into()),
                            Some(new_metadata.into()),
                        ),
                    )
                })
                .collect(),
        };

        let store = MemStore::new();
        let (root, trie_updates) = StateRoot::new(&store).update_fin(&meta_updates).unwrap();
        store.update_state(meta_updates);
        store.update_trie(trie_updates);

        // Create witness with explicit bucket IDs (no plain keys)
        let witness = Witness::create(bucket_ids, [], &BTreeMap::new(), &store).unwrap();

        assert_eq!(witness.state_root().unwrap(), root);
        assert!(witness.verify().is_ok());
        assert!(bucket_ids
            .iter()
            .all(|&id| witness.metadata(id).unwrap() == new_metadata));
    }

    /// The precomputed count must agree with a scan of the witnessed slots.
    #[test]
    fn bucket_used_slots_matches_a_scan_of_the_witness() {
        use crate::constant::{NUM_BUCKETS, NUM_META_BUCKETS};
        use crate::proof::salt_witness::create_mock_proof;
        let bucket = NUM_META_BUCKETS as BucketId + 7;
        let meta_key = bucket_metadata_key(bucket);
        let slot = |s: u64| SaltKey::from((bucket, s));
        let occupied = SaltValue::new(&[1u8; 20], &[2u8; 32]);
        let meta = |capacity: u64| {
            SaltValue::from(BucketMeta {
                nonce: 0,
                capacity,
                used: None,
            })
        };
        let full = |capacity: u64| {
            let mut kvs: BTreeMap<SaltKey, Option<SaltValue>> = (0..capacity)
                .map(|s| (slot(s), (s % 3 == 0).then(|| occupied.clone())))
                .collect();
            kvs.insert(meta_key, Some(meta(capacity)));
            kvs
        };
        let wrap = |kvs| {
            Witness::from(SaltWitness {
                kvs,
                proof: create_mock_proof(),
            })
        };
        let check = |kvs| {
            let witness = wrap(kvs);
            let count = witness.bucket_used_slots(bucket).ok();
            assert_eq!(count, witness.salt_witness.bucket_used_slots(bucket).ok());
            count
        };

        for capacity in [256u64, 512, 4096, 65536] {
            assert_eq!(check(full(capacity)), Some(capacity.div_ceil(3)));
        }
        // Any missing slot leaves the count unknown, wherever it is.
        for missing in [0u64, 300, 511] {
            let mut kvs = full(512);
            kvs.remove(&slot(missing));
            assert_eq!(check(kvs), None);
        }
        // Without metadata the capacity is unknown.
        let mut kvs = full(512);
        kvs.remove(&meta_key);
        assert_eq!(check(kvs), None);
        // A slot at or beyond the capacity is not part of the bucket.
        for beyond in [256u64, 300] {
            let mut kvs = full(256);
            kvs.insert(slot(beyond), Some(occupied.clone()));
            assert_eq!(check(kvs), Some(256u64.div_ceil(3)));
        }

        // Neighbouring buckets are counted apart: a full one, a partly witnessed one and a
        // larger full one, each with its own number of occupied slots.
        let mut kvs = full(256);
        for (other, capacity, witnessed, every) in
            [(bucket + 1, 256, 3, 1), (bucket + 2, 512, 512, 5)]
        {
            kvs.insert(bucket_metadata_key(other), Some(meta(capacity)));
            kvs.extend((0..witnessed).map(|s| {
                let value = (s % every == 0).then(|| occupied.clone());
                (SaltKey::from((other, s)), value)
            }));
        }
        let witness = wrap(kvs);
        for (id, expected) in [
            (bucket, Some(256u64.div_ceil(3))),
            (bucket + 1, None),
            (bucket + 2, Some(512u64.div_ceil(5))),
        ] {
            assert_eq!(witness.bucket_used_slots(id).ok(), expected);
            assert_eq!(witness.salt_witness.bucket_used_slots(id).ok(), expected);
        }

        // Metadata buckets and out-of-range ids keep the `Ok(0)` convention.
        let witness = wrap(full(256));
        assert_eq!(witness.bucket_used_slots(0).unwrap(), 0);
        assert_eq!(
            witness.bucket_used_slots(NUM_BUCKETS as BucketId).unwrap(),
            0
        );
    }

    /// Witnesses are built from unverified bytes, so malformed metadata must not panic.
    #[test]
    fn building_a_witness_from_malformed_metadata_does_not_panic() {
        use crate::constant::NUM_META_BUCKETS;
        use crate::proof::salt_witness::create_mock_proof;
        let bucket = NUM_META_BUCKETS as BucketId + 7;
        let meta_key = bucket_metadata_key(bucket);
        let slot = SaltKey::from((bucket, 0));
        let occupied = SaltValue::new(&[1u8; 20], &[2u8; 32]);
        let bad_metas = [
            None,
            Some(SaltValue::new(&[9u8; 3], &[])),
            Some(SaltValue::from(BucketMeta {
                nonce: 0,
                capacity: u64::MAX,
                used: None,
            })),
        ];
        for bad in bad_metas {
            let kvs = BTreeMap::from([(meta_key, bad), (slot, Some(occupied.clone()))]);
            let witness = Witness::from(SaltWitness {
                kvs,
                proof: create_mock_proof(),
            });
            assert!(witness.fully_witnessed.is_empty());
        }
    }

    /// A block that resizes a bucket must give the same root through the witness as through the
    /// full store. `test-bucket-resize` maps keys into a few buckets and defaults to a 1% load
    /// factor, so resizes happen with a small state.
    #[cfg(feature = "test-bucket-resize")]
    #[test]
    fn resize_block_replayed_on_the_witness_matches_the_store() {
        use crate::{mem_store::MemStore, trie::trie::StateRoot};
        let store = MemStore::new();
        let key = |i: u32| format!("key-{i:08}").into_bytes();
        let existing: BTreeMap<Vec<u8>, Option<Vec<u8>>> =
            (0..300).map(|i| (key(i), Some(vec![1u8; 8]))).collect();
        let updates = EphemeralSaltState::new(&store)
            .update_fin(&existing)
            .unwrap();
        store.update_state(updates.clone());
        let (_, trie) = StateRoot::new(&store).update_fin(&updates).unwrap();
        store.update_trie(trie);

        let block: BTreeMap<Vec<u8>, Option<Vec<u8>>> =
            (300..1000).map(|i| (key(i), Some(vec![2u8; 8]))).collect();
        let lookups: Vec<Vec<u8>> = block.keys().cloned().collect();
        let expected = EphemeralSaltState::new(&store).update_fin(&block).unwrap();
        assert!(
            expected.data.keys().any(|k| k.is_in_meta_bucket()),
            "the block must resize"
        );
        let (expected_root, _) = StateRoot::new(&store).update_fin(&expected).unwrap();

        let witness = Witness::create([], lookups.iter(), &block, &store).unwrap();
        let witness = Witness::from(witness.salt_witness);
        let replayed = EphemeralSaltState::new(&witness)
            .update_fin(&block)
            .unwrap();
        assert_eq!(replayed, expected);
        let (root, _) = StateRoot::new(&witness).update_fin(&replayed).unwrap();
        assert_eq!(root, expected_root);
    }
}
