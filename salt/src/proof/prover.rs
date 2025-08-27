//! Prover for the Salt proof
use crate::{
    constant::TRIE_WIDTH,
    proof::{subtrie::create_sub_trie, verifier, ProofError},
    traits::{StateReader, TrieReader},
    types::{hash_commitment, CommitmentBytes, NodeId, SaltKey, SaltValue},
    BucketId, ScalarBytes,
};
use banderwagon::{Element, Fr, PrimeField};
use ipa_multipoint::{
    crs::CRS,
    lagrange_basis::PrecomputedWeights,
    multiproof::{MultiPoint, MultiPointProof},
    transcript::Transcript,
};
use once_cell::sync::Lazy;
use rayon::prelude::*;
use rustc_hash::FxHashMap;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::collections::BTreeMap;

/// Create a new CRS.
pub static PRECOMPUTED_WEIGHTS: Lazy<PrecomputedWeights> =
    Lazy::new(|| PrecomputedWeights::new(TRIE_WIDTH));

/// Wrapper of `CommitmentBytes` for serialization.
#[derive(Clone, Debug, Eq, Serialize, Deserialize)]
pub struct CommitmentBytesW(
    #[serde(serialize_with = "serialize_commitment")]
    #[serde(deserialize_with = "deserialize_commitment")]
    pub CommitmentBytes,
);

impl PartialEq for CommitmentBytesW {
    fn eq(&self, other: &Self) -> bool {
        Element::from_bytes_unchecked_uncompressed(self.0)
            == Element::from_bytes_unchecked_uncompressed(other.0)
    }
}

/// Salt proof.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SaltProof {
    /// the node id of nodes in the path => node commitment
    pub parents_commitments: BTreeMap<NodeId, CommitmentBytesW>,

    /// the IPA proof
    #[serde(serialize_with = "serialize_multipoint_proof")]
    #[serde(deserialize_with = "deserialize_multipoint_proof")]
    pub proof: MultiPointProof,

    /// the top level of the buckets trie
    /// used to let verifier determine the bucket trie level
    pub buckets_top_level: FxHashMap<BucketId, u8>,
}

fn serialize_multipoint_proof<S>(proof: &MultiPointProof, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    let bytes = proof
        .to_bytes()
        .map_err(|e| serde::ser::Error::custom(e.to_string()))?;
    bytes.serialize(serializer)
}

fn deserialize_multipoint_proof<'de, D>(deserializer: D) -> Result<MultiPointProof, D::Error>
where
    D: Deserializer<'de>,
{
    let bytes = Vec::<u8>::deserialize(deserializer)?;
    MultiPointProof::from_bytes(&bytes, crate::constant::POLY_DEGREE)
        .map_err(|e| serde::de::Error::custom(e.to_string()))
}

fn serialize_commitment<S>(commitment: &CommitmentBytes, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    let element = Element::from_bytes_unchecked_uncompressed(*commitment);
    let bytes = element.to_bytes();

    bytes.serialize(serializer)
}

fn deserialize_commitment<'de, D>(deserializer: D) -> Result<CommitmentBytes, D::Error>
where
    D: Deserializer<'de>,
{
    let bytes: [u8; 32] = <[u8; 32]>::deserialize(deserializer)?;
    let element = Element::from_bytes(&bytes)
        .ok_or_else(|| serde::de::Error::custom("from_bytes to an element is none"))?;

    Ok(element.to_bytes_uncompressed())
}

/// Calculate the hash value of the key-value pair.
#[inline(always)]
pub(crate) fn calculate_fr_by_kv(entry: &SaltValue) -> Fr {
    let mut data = blake3::Hasher::new();
    data.update(entry.key());
    data.update(entry.value());
    Fr::from_le_bytes_mod_order(data.finalize().as_bytes())
}

impl SaltProof {
    /// Create a new proof.
    pub fn create<Store, I>(keys: I, store: &Store) -> Result<SaltProof, ProofError>
    where
        I: IntoIterator<Item = SaltKey>,
        Store: StateReader + TrieReader,
    {
        let mut keys: Vec<_> = keys.into_iter().collect();
        if keys.is_empty() {
            return Err(ProofError::ProveFailed("empty key set".to_string()));
        }
        // Check if the array is already sorted - returns true if sorted, false otherwise
        // Using any() to find the first out-of-order pair for efficiency
        let needs_sorting = keys.windows(2).any(|w| w[0] > w[1]);

        if needs_sorting {
            keys.par_sort_unstable();
        }
        keys.dedup();

        let (prover_queries, parents_commitments, buckets_top_level) =
            create_sub_trie(store, &keys)?;

        let crs = CRS::default();

        let mut transcript = Transcript::new(b"st");

        let proof = MultiPoint::open(crs, &PRECOMPUTED_WEIGHTS, &mut transcript, prover_queries);

        Ok(SaltProof {
            parents_commitments,
            proof,
            buckets_top_level,
        })
    }

    /// Check if the proof is valid.
    pub fn check(
        &self,
        data: &BTreeMap<SaltKey, Option<SaltValue>>,
        state_root: ScalarBytes,
    ) -> Result<(), ProofError> {
        if data.is_empty() {
            return Err(ProofError::VerifyFailed("empty key set".to_string()));
        }

        let kvs: Vec<_> = data.iter().map(|(&k, v)| (k, v.clone())).collect();

        let queries = verifier::create_verifier_queries(
            &self.parents_commitments,
            kvs,
            &self.buckets_top_level,
        )?;

        let root = self
            .parents_commitments
            .get(&0)
            .ok_or(ProofError::VerifyFailed(
                "lack of root commitment".to_string(),
            ))?;

        let trie_root = hash_commitment(root.0);

        if state_root != trie_root {
            return Err(ProofError::VerifyFailed(format!(
                "state root not match, expect: {trie_root:?}, got: {state_root:?}"
            )));
        }

        let mut transcript = Transcript::new(b"st");

        let crs = CRS::default();

        // call MultiPointProof::check to verify the proof
        if self
            .proof
            .check(&crs, &PRECOMPUTED_WEIGHTS, &queries, &mut transcript)
        {
            Ok(())
        } else {
            Err(ProofError::VerifyFailed(
                "multi pointproof check failed".to_string(),
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        bucket_id_from_metadata_key, bucket_metadata_key,
        constant::{
            default_commitment, EMPTY_SLOT_HASH, MIN_BUCKET_SIZE, MIN_BUCKET_SIZE_BITS,
            NUM_META_BUCKETS, STARTING_NODE_ID,
        },
        empty_salt::EmptySalt,
        mem_store::MemStore,
        mock_evm_types::{PlainKey, PlainValue},
        proof::prover::calculate_fr_by_kv,
        state::{state::EphemeralSaltState, updates::StateUpdates},
        traits::{StateReader, TrieReader},
        trie::trie::StateRoot,
        types::{BucketId, SlotId},
        BucketMeta, NodeId, SaltKey, SaltValue,
    };
    use alloy_primitives::{Address, B256};
    use banderwagon::{CanonicalSerialize, Element, Fr, PrimeField};
    use ipa_multipoint::{crs::CRS, lagrange_basis::LagrangeBasis};
    use rand::{rngs::StdRng, Rng, SeedableRng};
    use std::collections::{BTreeMap, HashMap};

    fn fr_to_le_bytes(fr: Fr) -> [u8; 32] {
        let mut bytes = [0u8; 32];
        fr.serialize_compressed(&mut bytes[..])
            .expect("Failed to serialize scalar to bytes");
        bytes
    }

    const KV_BUCKET_OFFSET: NodeId = NUM_META_BUCKETS as NodeId;

    /// Tests proof generation and verification for an empty trie.
    /// Manually computes commitments at each trie level (L0-L4) and verifies
    /// they match the expected default values. Then creates a proof for a
    /// metadata key and verifies it against the computed empty root.
    #[test]
    fn test_empty_trie_proof() {
        let salt = EmptySalt;

        let salt_key: SaltKey = (0, 0).into();
        let first_data_bucket_id = 131329;
        let default_fr = Fr::from_le_bytes_mod_order(&EMPTY_SLOT_HASH);

        let crs = CRS::default();

        let meta_bucket_fr = calculate_fr_by_kv(&BucketMeta::default().into());
        let meta_bucket_frs = vec![meta_bucket_fr; 256];
        let meta_bucket_commitment = crs.commit_lagrange_poly(&LagrangeBasis::new(meta_bucket_frs));

        assert_eq!(
            meta_bucket_commitment,
            Element::from_bytes_unchecked_uncompressed(default_commitment(
                STARTING_NODE_ID[3] as NodeId
            ))
        );

        let data_bucket_frs = vec![default_fr; 256];
        let data_bucket_commitment = crs.commit_lagrange_poly(&LagrangeBasis::new(data_bucket_frs));

        assert_eq!(
            data_bucket_commitment,
            Element::from_bytes_unchecked_uncompressed(default_commitment(first_data_bucket_id))
        );

        let l3_left_frs = vec![meta_bucket_commitment.map_to_scalar_field(); 256];
        let l3_left_commitment = crs.commit_lagrange_poly(&LagrangeBasis::new(l3_left_frs));
        assert_eq!(
            l3_left_commitment,
            Element::from_bytes_unchecked_uncompressed(default_commitment(
                STARTING_NODE_ID[2] as NodeId
            ))
        );

        let l3_right_frs = vec![data_bucket_commitment.map_to_scalar_field(); 256];
        let l3_right_commitment = crs.commit_lagrange_poly(&LagrangeBasis::new(l3_right_frs));
        assert_eq!(
            l3_right_commitment,
            Element::from_bytes_unchecked_uncompressed(default_commitment(
                STARTING_NODE_ID[3] as NodeId - 1
            ))
        );

        let l2_left_frs = vec![l3_left_commitment.map_to_scalar_field(); 256];
        let l2_left_commitment = crs.commit_lagrange_poly(&LagrangeBasis::new(l2_left_frs));
        assert_eq!(
            l2_left_commitment,
            Element::from_bytes_unchecked_uncompressed(default_commitment(
                STARTING_NODE_ID[1] as NodeId
            ))
        );

        let l2_right_frs = vec![l3_right_commitment.map_to_scalar_field(); 256];
        let l2_right_commitment = crs.commit_lagrange_poly(&LagrangeBasis::new(l2_right_frs));
        assert_eq!(
            l2_right_commitment,
            Element::from_bytes_unchecked_uncompressed(default_commitment(
                STARTING_NODE_ID[2] as NodeId - 1
            ))
        );

        let mut l1_frs = vec![l2_right_commitment.map_to_scalar_field(); 256];
        l1_frs[0] = l2_left_commitment.map_to_scalar_field();

        let l1_commitment = crs.commit_lagrange_poly(&LagrangeBasis::new(l1_frs));
        assert_eq!(
            l1_commitment,
            Element::from_bytes_unchecked_uncompressed(default_commitment(
                STARTING_NODE_ID[0] as NodeId
            ))
        );

        let sub_trie_l1_frs = vec![l2_right_commitment.map_to_scalar_field(); 256];
        let sub_trie_l1_commitment = crs.commit_lagrange_poly(&LagrangeBasis::new(sub_trie_l1_frs));
        assert_eq!(
            sub_trie_l1_commitment,
            Element::from_bytes_unchecked_uncompressed(default_commitment((65536 << 40) + 1))
        );

        let sub_trie_l0_frs = vec![sub_trie_l1_commitment.map_to_scalar_field(); 256];
        let sub_trie_l0_commitment = crs.commit_lagrange_poly(&LagrangeBasis::new(sub_trie_l0_frs));
        assert_eq!(
            sub_trie_l0_commitment,
            Element::from_bytes_unchecked_uncompressed(default_commitment(65536 << 40))
        );

        let l0_fr = l1_commitment.map_to_scalar_field();
        let empty_root = fr_to_le_bytes(l0_fr);

        let proof = SaltProof::create([salt_key], &salt).unwrap();

        let value = salt
            .metadata(bucket_id_from_metadata_key(salt_key))
            .unwrap();

        let res = proof.check(&[(salt_key, Some(value.into()))].into(), empty_root);

        assert!(res.is_ok());
    }

    /// Tests basic proof creation and verification for a single key-value pair.
    /// Inserts one storage value into the trie, generates a proof for it,
    /// and verifies the proof matches the trie root.
    #[test]
    fn test_basic_proof_exist() {
        let mut rng = StdRng::seed_from_u64(42);

        let bytes: [u8; 32] = [
            204, 96, 246, 139, 174, 111, 240, 167, 42, 141, 172, 145, 227, 227, 67, 2, 127, 77,
            165, 138, 175, 150, 139, 98, 201, 151, 0, 212, 66, 107, 252, 84,
        ];

        let (slot, storage_value) = (B256::from(bytes), B256::from(bytes));

        let initial_key_values = HashMap::from([(
            PlainKey::Storage(Address::from(rng.gen::<[u8; 20]>()), slot).encode(),
            Some(PlainValue::Storage(storage_value.into()).encode()),
        )]);

        let mem_store = MemStore::new();
        let mut state = EphemeralSaltState::new(&mem_store);
        let updates = state.update(&initial_key_values).unwrap();
        mem_store.update_state(updates.clone());

        let mut trie = StateRoot::new(&mem_store);
        let (trie_root, trie_updates) = trie.update_fin(updates.clone()).unwrap();
        mem_store.update_trie(trie_updates);

        let salt_key = *updates.data.keys().next().unwrap();
        let value = mem_store.value(salt_key).unwrap();

        let proof = SaltProof::create([salt_key], &mem_store).unwrap();

        let res = proof.check(&[(salt_key, value)].into(), trie_root);
        assert!(res.is_ok());
    }

    /// Verifies that the trie root commitment correctly corresponds to the scalar field.
    /// After inserting a single key-value pair, checks that converting the root
    /// commitment to scalar field and back yields the same trie root.
    #[test]
    fn test_single_insert_commmitment() {
        let mut rng = StdRng::seed_from_u64(42);

        let byte_ff: [u8; 32] = [
            204, 96, 246, 139, 174, 111, 240, 167, 42, 141, 172, 145, 227, 227, 67, 2, 127, 77,
            165, 138, 175, 150, 139, 98, 201, 151, 0, 212, 66, 107, 252, 84,
        ];

        let (slot, storage_value) = (B256::from(byte_ff), B256::from(byte_ff));

        let initial_key_values = HashMap::from([(
            PlainKey::Storage(Address::from(rng.gen::<[u8; 20]>()), slot).encode(),
            Some(PlainValue::Storage(storage_value.into()).encode()),
        )]);

        let mem_store = MemStore::new();
        let mut state = EphemeralSaltState::new(&mem_store);
        let updates = state.update(&initial_key_values).unwrap();

        mem_store.update_state(updates.clone());

        let mut trie = StateRoot::new(&mem_store);
        let (trie_root, trie_updates) = trie.update_fin(updates.clone()).unwrap();

        mem_store.update_trie(trie_updates);

        let trie_root_commitment = mem_store.commitment(0).unwrap();

        let root_from_commitment = B256::from_slice(&fr_to_le_bytes(
            Element::from_bytes_unchecked_uncompressed(trie_root_commitment).map_to_scalar_field(),
        ));

        assert_eq!(trie_root, root_from_commitment);
    }

    /// Tests proof generation with a large number of key-value pairs.
    /// Inserts 1000 random key-value pairs, then generates a proof that includes
    /// both existing keys and non-existent keys. Verifies that existing keys
    /// return their values and non-existent keys return None.
    #[test]
    fn test_multi_insert_proof() {
        let mut rng = StdRng::seed_from_u64(42);

        let initial_kvs = (0..1000)
            .map(|_| {
                let k = PlainKey::Storage(
                    Address::from(rng.gen::<[u8; 20]>()),
                    B256::from(rng.gen::<[u8; 32]>()),
                )
                .encode();
                let v = PlainValue::Storage(B256::from(rng.gen::<[u8; 32]>()).into()).encode();
                (k, Some(v))
            })
            .collect::<HashMap<_, _>>();

        let mem_store = MemStore::new();
        let mut state = EphemeralSaltState::new(&mem_store);
        let updates = state.update(&initial_kvs).unwrap();

        mem_store.update_state(updates.clone());

        let mut trie = StateRoot::new(&mem_store);
        let (trie_root, trie_updates) = trie.update_fin(updates.clone()).unwrap();

        mem_store.update_trie(trie_updates.clone());

        let mut salt_keys = updates.data.keys().cloned().collect::<Vec<_>>();
        salt_keys.push((16777215, 1).into());
        salt_keys.push((16777215, 2).into());
        salt_keys.push((16777215, 255).into());

        let mut values = updates
            .data
            .values()
            .map(|(_, new)| new)
            .cloned()
            .collect::<Vec<_>>();
        values.push(None);
        values.push(None);
        values.push(None);

        let proof = SaltProof::create(salt_keys.iter().copied(), &mem_store).unwrap();

        let data: BTreeMap<_, _> = salt_keys.into_iter().zip(values).collect();
        let res = proof.check(&data, trie_root);

        assert!(res.is_ok());
    }

    /// Tests proof generation during bucket capacity expansion.
    /// Initializes a trie with a single value, expands the bucket from default
    /// capacity (256) to 65536, and verifies that:
    /// - Commitments at various subtrie levels remain correct
    /// - Proofs for non-existent keys in the expanded bucket verify correctly
    #[test]
    fn salt_proof_in_bucket_expansion() {
        let store = MemStore::new();
        let mut trie = StateRoot::new(&store);
        let bid = KV_BUCKET_OFFSET as BucketId + 4; // 65540
        let slot_id = 3;
        let salt_key: SaltKey = (bid, slot_id).into();
        let salt_value = SaltValue::new(&[1; 32], &[1; 32]);
        let bucket_meta_salt_key = bucket_metadata_key(bid);

        // initialize the trie
        let initialize_state_updates = StateUpdates {
            data: vec![(salt_key, (None, Some(salt_value.clone())))]
                .into_iter()
                .collect(),
        };

        let (initialize_root, initialize_trie_updates) =
            trie.update_fin(initialize_state_updates.clone()).unwrap();
        store.update_state(initialize_state_updates);
        store.update_trie(initialize_trie_updates.clone());

        let (root, mut init_trie_updates) = StateRoot::rebuild(&store).unwrap();
        init_trie_updates.sort_unstable_by(|(a, _), (b, _)| b.cmp(a));
        assert_eq!(root, initialize_root);
        assert_eq!(init_trie_updates, initialize_trie_updates);

        // only expand bucket 65540 capacity.
        let new_capacity = 256 * 256;
        fn bucket_meta(nonce: u32, capacity: SlotId) -> BucketMeta {
            BucketMeta {
                nonce,
                capacity,
                ..Default::default()
            }
        }

        let expand_state_updates = StateUpdates {
            data: vec![(
                bucket_meta_salt_key,
                (
                    Some(BucketMeta::default().into()),
                    Some(bucket_meta(0, new_capacity).into()),
                ),
            )]
            .into_iter()
            .collect(),
        };
        let (expansion_root, trie_updates) = trie.update_fin(expand_state_updates.clone()).unwrap();
        store.update_state(expand_state_updates);

        store.update_trie(trie_updates);

        let (root, _) = StateRoot::rebuild(&store).unwrap();
        assert_eq!(root, expansion_root);

        let crs = CRS::default();
        let default_fr = Fr::from_le_bytes_mod_order(&EMPTY_SLOT_HASH);
        let mut sub_bucket_frs = vec![default_fr; 256];
        sub_bucket_frs[3] = calculate_fr_by_kv(&salt_value);
        let sub_bucket_commitment = crs.commit_lagrange_poly(&LagrangeBasis::new(sub_bucket_frs));

        // sub trie L4
        assert_eq!(
            Element::from_bytes_unchecked_uncompressed(
                store.commitment(72_061_992_101_282_049).unwrap()
            ),
            sub_bucket_commitment
        );

        assert_eq!(
            Element::from_bytes_unchecked_uncompressed(
                store.commitment(72_061_992_101_282_057).unwrap()
            ),
            Element::from_bytes_unchecked_uncompressed(default_commitment(72_061_992_101_282_057))
        );

        let mut sub_trie_l3_frs = vec![
            Element::from_bytes_unchecked_uncompressed(
                store.commitment(72_061_992_101_282_050).unwrap()
            )
            .map_to_scalar_field();
            256
        ];
        sub_trie_l3_frs[0] = sub_bucket_commitment.map_to_scalar_field();
        let sub_trie_l3_commitment = crs.commit_lagrange_poly(&LagrangeBasis::new(sub_trie_l3_frs));

        // main trie L3
        assert_eq!(
            Element::from_bytes_unchecked_uncompressed(store.commitment(131333).unwrap()),
            sub_trie_l3_commitment
        );

        // sub trie L3
        assert_eq!(
            Element::from_bytes_unchecked_uncompressed(
                store.commitment(72_061_992_084_504_833).unwrap()
            ),
            Element::from_bytes_unchecked_uncompressed(default_commitment(72_061_992_084_504_833))
        );

        // sub trie L2
        let proof = SaltProof::create([SaltKey::from((bid, 2049))], &store).unwrap();

        let res = proof.check(&[(SaltKey::from((bid, 2049)), None)].into(), expansion_root);

        assert!(res.is_ok());
    }

    /// Tests proof correctness through multiple bucket capacity expansions.
    /// Performs two expansions (256 → 524288 → 1099511627776) while adding
    /// new key-value pairs at each stage. Verifies that proofs remain valid
    /// for both existing and non-existing keys throughout all expansion stages.
    #[test]
    fn salt_proof_in_bucket_expansion_2() {
        fn bucket_meta(nonce: u32, capacity: SlotId) -> BucketMeta {
            BucketMeta {
                nonce,
                capacity,
                ..Default::default()
            }
        }

        let store = MemStore::new();
        let mut trie = StateRoot::new(&store);
        let bid = KV_BUCKET_OFFSET as BucketId + 4; // 65540
        let salt_key: SaltKey = (
            bid >> MIN_BUCKET_SIZE_BITS,
            bid as SlotId % MIN_BUCKET_SIZE as SlotId,
        )
            .into();

        // initialize the trie, default bucket meta
        let initialize_state_updates = StateUpdates {
            data: vec![
                (
                    (bid, 3).into(),
                    (None, Some(SaltValue::new(&[1; 32], &[1; 32]))),
                ),
                (
                    (bid, 5).into(),
                    (None, Some(SaltValue::new(&[2; 32], &[2; 32]))),
                ),
            ]
            .into_iter()
            .collect(),
        };

        let (initialize_root, initialize_trie_updates) =
            trie.update_fin(initialize_state_updates.clone()).unwrap();
        store.update_state(initialize_state_updates);
        store.update_trie(initialize_trie_updates.clone());
        let (root, mut init_trie_updates) = StateRoot::rebuild(&store).unwrap();
        init_trie_updates.sort_unstable_by(|(a, _), (b, _)| b.cmp(a));
        assert_eq!(root, initialize_root);

        // expand capacity and add kvs
        let new_capacity = 8 * 256 * 256;

        let expand_state_updates = StateUpdates {
            data: vec![
                (
                    salt_key,
                    (
                        Some(BucketMeta::default().into()),
                        Some(bucket_meta(0, new_capacity).into()),
                    ),
                ),
                (
                    (bid, 2049).into(),
                    (None, Some(SaltValue::new(&[3; 32], &[3; 32]))),
                ),
            ]
            .into_iter()
            .collect(),
        };
        let (expansion_root, trie_updates) = trie.update_fin(expand_state_updates.clone()).unwrap();
        store.update_state(expand_state_updates);
        store.update_trie(trie_updates);
        let (root, _) = StateRoot::rebuild(&store).unwrap();
        assert_eq!(root, expansion_root);

        let proof = SaltProof::create(
            [
                (bid, 3).into(),
                (bid, 5).into(),
                (bid, 2049).into(),
                (bid, new_capacity - 1).into(),
            ],
            &store,
        )
        .unwrap();

        let res = proof.check(
            &[
                ((bid, 3).into(), Some(SaltValue::new(&[1; 32], &[1; 32]))),
                ((bid, 5).into(), Some(SaltValue::new(&[2; 32], &[2; 32]))),
                ((bid, 2049).into(), Some(SaltValue::new(&[3; 32], &[3; 32]))),
                ((bid, new_capacity - 1).into(), None),
            ]
            .into(),
            expansion_root,
        );

        assert!(res.is_ok());

        // expand capacity and add kvs
        let new_capacity2 = 256 * 256 * 256 * 256 * 256;

        let expand_state_updates = StateUpdates {
            data: vec![
                (
                    salt_key,
                    (
                        Some(bucket_meta(0, new_capacity).into()),
                        Some(bucket_meta(0, new_capacity2).into()),
                    ),
                ),
                (
                    (bid, new_capacity2 - 255).into(),
                    (None, Some(SaltValue::new(&[255; 32], &[255; 32]))),
                ),
            ]
            .into_iter()
            .collect(),
        };
        let (expansion_root, trie_updates) = trie.update_fin(expand_state_updates.clone()).unwrap();
        store.update_state(expand_state_updates);
        store.update_trie(trie_updates);
        let (root, _) = StateRoot::rebuild(&store).unwrap();
        assert_eq!(root, expansion_root);

        let proof = SaltProof::create(
            [
                (bid, 3).into(),
                (bid, 5).into(),
                (bid, 2049).into(),
                (bid, 256 * 256 * 256).into(),
                (bid, new_capacity - 1).into(),
                (bid, new_capacity2 - 255).into(),
                (bid, new_capacity2 - 1).into(),
            ],
            &store,
        )
        .unwrap();

        let res = proof.check(
            &[
                ((bid, 3).into(), Some(SaltValue::new(&[1; 32], &[1; 32]))),
                ((bid, 5).into(), Some(SaltValue::new(&[2; 32], &[2; 32]))),
                ((bid, 2049).into(), Some(SaltValue::new(&[3; 32], &[3; 32]))),
                ((bid, 256 * 256 * 256).into(), None),
                ((bid, new_capacity - 1).into(), None),
                (
                    (bid, new_capacity2 - 255).into(),
                    Some(SaltValue::new(&[255; 32], &[255; 32])),
                ),
                ((bid, new_capacity2 - 1).into(), None),
            ]
            .into(),
            expansion_root,
        );

        assert!(res.is_ok());
    }
}
