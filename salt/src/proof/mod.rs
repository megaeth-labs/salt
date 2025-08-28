//! This module is the implementation of generating and verifying proofs of SALT.
use thiserror::Error;

pub mod prover;
pub mod shape;
pub mod subtrie;
pub mod verifier;

pub use prover::{CommitmentBytesW, SaltProof};

/// Error type for proof.
#[derive(Debug, Error)]
pub enum ProofError {
    /// Prove error
    #[error("prove failed: {0}")]
    ProveFailed(String),
    /// Verify error
    #[error("verify failed: {0}")]
    VerifyFailed(String),
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        bucket_metadata_key,
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
        trie::trie::{compute_from_scratch, StateRoot},
        types::{BucketId, SlotId},
        BucketMeta, NodeId, SaltKey, SaltValue,
    };
    use alloy_primitives::{Address, B256};
    use banderwagon::{CanonicalSerialize, Element, Fr, PrimeField};
    use ipa_multipoint::{crs::CRS, lagrange_basis::LagrangeBasis};
    use rand::{rngs::StdRng, Rng, SeedableRng};
    use std::collections::HashMap;

    fn fr_to_le_bytes(fr: Fr) -> [u8; 32] {
        let mut bytes = [0u8; 32];
        fr.serialize_compressed(&mut bytes[..])
            .expect("Failed to serialize scalar to bytes");
        bytes
    }

    const KV_BUCKET_OFFSET: NodeId = NUM_META_BUCKETS as NodeId;

    #[test]
    fn test_empty_trie_proof() {
        let salt = EmptySalt;

        let salt_keys: Vec<SaltKey> = vec![(0, 0).into()];
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

        let proof = SaltProof::create(&salt_keys, &salt).unwrap();

        let value = salt.value(salt_keys[0]).unwrap();

        let res = proof.check(salt_keys, vec![value], empty_root);

        assert!(res.is_ok());
    }

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

        let mut trie = StateRoot::new();
        let (trie_root, trie_updates) = trie.update_one(&mem_store, &updates).unwrap();
        mem_store.update_trie(trie_updates);

        let salt_key = *updates.data.keys().next().unwrap();
        let value = mem_store.value(salt_key).unwrap();

        let proof = SaltProof::create(&[salt_key], &mem_store).unwrap();

        let res = proof.check(vec![salt_key], vec![value], trie_root);
        assert!(res.is_ok());
    }

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

        let mut trie = StateRoot::new();
        let (trie_root, trie_updates) = trie.update_one(&mem_store, &updates).unwrap();

        mem_store.update_trie(trie_updates);

        let trie_root_commitment = mem_store.commitment(0).unwrap();

        let root_from_commitment = B256::from_slice(&fr_to_le_bytes(
            Element::from_bytes_unchecked_uncompressed(trie_root_commitment).map_to_scalar_field(),
        ));

        assert_eq!(trie_root, root_from_commitment);
    }

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

        let mut trie = StateRoot::new();
        let (trie_root, trie_updates) = trie.update_one(&mem_store, &updates).unwrap();

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

        let proof = SaltProof::create(&salt_keys, &mem_store).unwrap();

        let res = proof.check(salt_keys, values, trie_root);

        assert!(res.is_ok());
    }

    #[test]
    fn test_sub_trie_top_level() {
        use crate::trie::trie::{
            get_child_node, sub_trie_top_level, subtrie_node_id, subtrie_parent_id,
            subtrie_salt_key_start,
        };

        assert_eq!(sub_trie_top_level(256), 4); // 4

        assert_eq!(sub_trie_top_level(256 * 256), 3); // 3

        assert_eq!(sub_trie_top_level(256 * 256 * 256), 2); // 2

        assert_eq!(sub_trie_top_level(131072), 2); // 2

        assert_eq!(sub_trie_top_level(256 * 256 * 256 * 256), 1); // 1

        assert_eq!(sub_trie_top_level(256 * 256 * 256 * 256 * 256), 0); // 0

        //assert_eq!(get_child_idx(&72061992101282049, 4), 0);

        assert_eq!(
            subtrie_node_id(&SaltKey(72061992084439043)),
            72061992101282049
        );

        assert_eq!(subtrie_parent_id(&72061992101282049, 3), 72061992084504833);

        assert_eq!(
            subtrie_salt_key_start(&72061992101282049),
            SaltKey(72061992084439040)
        );

        assert_eq!(get_child_node(&72061992084439041, 0), 72061992084439297);
        assert_eq!(get_child_node(&72061992084439297, 0), 72061992084504833);
        assert_eq!(get_child_node(&72061992084504833, 0), 72061992101282049);
    }

    #[test]
    fn salt_proof_in_bucket_expansion() {
        let store = MemStore::new();
        let mut trie = StateRoot::new();
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
            trie.update_one(&store, &initialize_state_updates).unwrap();
        store.update_state(initialize_state_updates.clone());
        store.update_trie(initialize_trie_updates.clone());

        let (root, mut init_trie_updates) = compute_from_scratch(&store).unwrap();
        init_trie_updates
            .data
            .sort_unstable_by(|(a, _), (b, _)| b.cmp(a));
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
        let (expansion_root, trie_updates) =
            trie.update_one(&store, &expand_state_updates).unwrap();
        store.update_state(expand_state_updates);

        store.update_trie(trie_updates);

        let (root, _) = compute_from_scratch(&store).unwrap();
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
        let proof = SaltProof::create(&[SaltKey::from((bid, 2049))], &store).unwrap();

        let res = proof.check(vec![SaltKey::from((bid, 2049))], vec![None], expansion_root);

        assert!(res.is_ok());
    }

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
        let mut trie = StateRoot::new();
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
            trie.update_one(&store, &initialize_state_updates).unwrap();
        store.update_state(initialize_state_updates.clone());
        store.update_trie(initialize_trie_updates.clone());
        let (root, mut init_trie_updates) = compute_from_scratch(&store).unwrap();
        init_trie_updates
            .data
            .sort_unstable_by(|(a, _), (b, _)| b.cmp(a));
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
        let (expansion_root, trie_updates) =
            trie.update_one(&store, &expand_state_updates).unwrap();
        store.update_state(expand_state_updates);
        store.update_trie(trie_updates);
        let (root, _) = compute_from_scratch(&store).unwrap();
        assert_eq!(root, expansion_root);

        let proof = SaltProof::create(
            &[
                (bid, 3).into(),
                (bid, 5).into(),
                (bid, 2049).into(),
                (bid, new_capacity - 1).into(),
            ],
            &store,
        )
        .unwrap();

        let res = proof.check(
            vec![
                (bid, 3).into(),
                (bid, 5).into(),
                (bid, 2049).into(),
                (bid, new_capacity - 1).into(),
            ],
            vec![
                Some(SaltValue::new(&[1; 32], &[1; 32])),
                Some(SaltValue::new(&[2; 32], &[2; 32])),
                Some(SaltValue::new(&[3; 32], &[3; 32])),
                None,
            ],
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
        let (expansion_root, trie_updates) =
            trie.update_one(&store, &expand_state_updates).unwrap();
        store.update_state(expand_state_updates);
        store.update_trie(trie_updates);
        let (root, _) = compute_from_scratch(&store).unwrap();
        assert_eq!(root, expansion_root);

        let proof = SaltProof::create(
            &[
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
            vec![
                (bid, 3).into(),
                (bid, 5).into(),
                (bid, 2049).into(),
                (bid, 256 * 256 * 256).into(),
                (bid, new_capacity - 1).into(),
                (bid, new_capacity2 - 255).into(),
                (bid, new_capacity2 - 1).into(),
            ],
            vec![
                Some(SaltValue::new(&[1; 32], &[1; 32])),
                Some(SaltValue::new(&[2; 32], &[2; 32])),
                Some(SaltValue::new(&[3; 32], &[3; 32])),
                None,
                None,
                Some(SaltValue::new(&[255; 32], &[255; 32])),
                None,
            ],
            expansion_root,
        );

        assert!(res.is_ok());
    }
}
