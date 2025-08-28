//! This module return all-needed queries for a given kv list by create_sub_trie()
use crate::{
    constant::{
        default_commitment, BUCKET_SLOT_BITS, BUCKET_SLOT_ID_MASK, EMPTY_SLOT_HASH,
        MAX_SUBTREE_LEVELS, NUM_META_BUCKETS, STARTING_NODE_ID, TRIE_WIDTH,
    },
    proof::{
        prover::calculate_fr_by_kv,
        shape::{connect_parent_id, is_leaf_node, logic_parent_id, parents_and_points},
        CommitmentBytesW, ProofError,
    },
    traits::{StateReader, TrieReader},
    trie::node_utils::{get_child_node, subtree_leaf_start_key, subtree_root_level},
    types::{BucketId, BucketMeta, NodeId, SaltKey},
    SlotId,
};
use banderwagon::{Element, Fr, PrimeField};
use ipa_multipoint::{lagrange_basis::LagrangeBasis, multiproof::ProverQuery};
use rustc_hash::FxHashMap;
use std::collections::{BTreeMap, BTreeSet};

type SubTrieInfo = (
    Vec<ProverQuery>,
    BTreeMap<NodeId, CommitmentBytesW>,
    FxHashMap<BucketId, u8>,
);

/// Helper function to create prover queries for a given commitment and points
fn create_prover_queries(
    commitment: Element,
    poly: LagrangeBasis,
    points: BTreeSet<usize>,
) -> Vec<ProverQuery> {
    points
        .iter()
        .map(|&i| ProverQuery {
            commitment,
            poly: poly.clone(),
            point: i,
            result: poly.evaluate_in_domain(i),
        })
        .collect()
}

/// Create a new sub trie.
/// the `salt_keys` have already been sorted and deduped
pub(crate) fn create_sub_trie<Store>(
    store: &Store,
    salt_keys: &[SaltKey],
) -> Result<SubTrieInfo, ProofError>
where
    Store: StateReader + TrieReader,
{
    let mut bucket_ids = salt_keys.iter().map(|k| k.bucket_id()).collect::<Vec<_>>();
    bucket_ids.dedup();

    let buckets_level = bucket_ids
        .into_iter()
        .map(|bucket_id| {
            if bucket_id < NUM_META_BUCKETS as BucketId {
                Ok((bucket_id, 1))
            } else {
                let meta = store.metadata(bucket_id)?;
                let level = MAX_SUBTREE_LEVELS - subtree_root_level(meta.capacity);
                Ok((bucket_id, level as u8))
            }
        })
        .collect::<Result<FxHashMap<_, _>, <Store as StateReader>::Error>>()
        .map_err(|e| ProofError::StateReadError {
            reason: format!("Failed to read state: {e:?}"),
        })?;

    let nodes = parents_and_points(salt_keys, &buckets_level);

    // Process trie nodes commitments
    let parents_commitments = nodes
        .iter()
        .map(|(&parent, _)| {
            let parent = connect_parent_id(parent);
            (
                parent,
                CommitmentBytesW(store.commitment(parent).expect("Failed to get trie node")),
            )
        })
        .collect::<BTreeMap<_, _>>();

    let queries = nodes
        .into_iter()
        .flat_map(|(parent, points)| {
            let parent_commitment = Element::from_bytes_unchecked_uncompressed(
                store
                    .commitment(connect_parent_id(parent))
                    .expect("Failed to get trie node"),
            );

            if is_leaf_node(parent) {
                let (slot_start, bucket_id) = if parent < BUCKET_SLOT_ID_MASK as NodeId {
                    let bucket_id = (parent - STARTING_NODE_ID[3] as NodeId) as BucketId;
                    (0, bucket_id)
                } else {
                    (subtree_leaf_start_key(&parent).slot_id(), (parent >> BUCKET_SLOT_BITS) as BucketId)
                };

                let mut default_frs = if bucket_id < 65536 {
                    vec![calculate_fr_by_kv(&BucketMeta::default().into()); 256]
                } else {
                    vec![Fr::from_le_bytes_mod_order(&EMPTY_SLOT_HASH); 256]
                };

                let children_kvs = store
                .entries(SaltKey::from((bucket_id, slot_start))..=SaltKey::from((bucket_id, slot_start + TRIE_WIDTH as SlotId -1)))
                .unwrap_or_else(|_| {
                    panic!(
                        "Failed to get bucket state by range_slot: bucket_id: {:?}, slot_start: {:?}, slot_end: {:?}",
                        bucket_id, slot_start, slot_start + TRIE_WIDTH as SlotId -1
                    )
                });

                for (k, v) in children_kvs {
                    default_frs[(k.slot_id() & 0xff) as usize] =
                        calculate_fr_by_kv(&v);
                }

                create_prover_queries(
                    parent_commitment,
                    LagrangeBasis::new(default_frs),
                    points
                )
            } else {
                let child_idx = get_child_node(&logic_parent_id(parent), 0);
                let children = store
                    .node_entries(child_idx..child_idx + TRIE_WIDTH as NodeId)
                    .expect("Failed to get trie children");
                let mut default_commitment = if child_idx == 1 {
                    let mut v = vec![default_commitment(child_idx + 1); TRIE_WIDTH];
                    v[0] = default_commitment(child_idx);
                    v
                } else {
                    vec![default_commitment(child_idx); TRIE_WIDTH]
                };
                for (k, v) in children {
                    default_commitment[k as usize - child_idx as usize] = v;
                }
                let children_frs = Element::serial_batch_map_to_scalar_field(default_commitment);
                create_prover_queries(
                    parent_commitment,
                    LagrangeBasis::new(children_frs),
                    points,
                )
                }
            }).collect::<Vec<_>>();

    Ok((queries, parents_commitments, buckets_level))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        mem_store::MemStore,
        mock_evm_types::{PlainKey, PlainValue},
        proof::prover::PRECOMPUTED_WEIGHTS,
        state::state::EphemeralSaltState,
        trie::trie::StateRoot,
    };
    use alloy_primitives::{Address, B256};
    use ark_ff::BigInt;
    use banderwagon::{Fr, Zero};
    use ipa_multipoint::{
        crs::CRS,
        multiproof::{MultiPoint, VerifierQuery},
        transcript::Transcript,
    };
    use rand::{rngs::StdRng, Rng, SeedableRng};
    use std::collections::HashMap;

    #[test]
    fn test_create_sub_trie() {
        let mut rng = StdRng::seed_from_u64(42);

        let byte_ff: [u8; 32] = [
            204, 96, 246, 139, 174, 111, 240, 167, 42, 141, 172, 145, 227, 227, 67, 2, 127, 77,
            165, 138, 175, 150, 139, 98, 201, 151, 0, 212, 66, 107, 252, 84,
        ];

        let (slot, storage_value) = (B256::from(byte_ff), B256::from(byte_ff));

        let initial_key_values = HashMap::from([(
            PlainKey::Storage(Address::from_slice(&rng.gen::<[u8; 20]>()), slot).encode(),
            Some(PlainValue::Storage(storage_value.into()).encode()),
        )]);

        let mem_store = MemStore::new();

        let mut state = EphemeralSaltState::new(&mem_store);
        let updates = state.update(&initial_key_values).unwrap();

        mem_store.update_state(updates.clone());

        let mut trie = StateRoot::new(&mem_store);
        let (_, trie_updates) = trie.update_fin(updates.clone()).unwrap();

        mem_store.update_trie(trie_updates);

        let salt_key = *updates.data.keys().next().unwrap();

        let keys = vec![salt_key];

        let (prover_queries, _, _) = create_sub_trie(&mem_store, &keys).unwrap();

        let crs = CRS::default();

        let mut transcript = Transcript::new(b"st");

        let proof = MultiPoint::open(
            crs.clone(),
            &PRECOMPUTED_WEIGHTS,
            &mut transcript,
            prover_queries.clone(),
        );

        let mut transcript = Transcript::new(b"st");

        let verifier_query: Vec<VerifierQuery> =
            prover_queries.into_iter().map(|q| q.into()).collect();

        let res = proof.check(&crs, &PRECOMPUTED_WEIGHTS, &verifier_query, &mut transcript);
        assert!(res);

        let mut poly_items = vec![Fr::zero(); 256];
        poly_items[0] = Fr::from(BigInt([
            14950088112150747174,
            13253162737298189682,
            10931921008236264693,
            1309984686389044416,
        ]));

        poly_items[208] = Fr::from(BigInt([
            9954869294274886320,
            8441215309276124103,
            16970925962995195932,
            2055721457450359655,
        ]));

        let poly = LagrangeBasis::new(poly_items);

        let point = 208;
        let result = poly.evaluate_in_domain(point);

        let poly_comm = crs.commit_lagrange_poly(&poly);

        let prover_query2 = ProverQuery {
            commitment: poly_comm,
            poly,
            point,
            result,
        };

        let mut transcript = Transcript::new(b"st");

        let multiproof = MultiPoint::open(
            crs.clone(),
            &PRECOMPUTED_WEIGHTS,
            &mut transcript,
            vec![prover_query2.clone()],
        );

        let verifier_queries: Vec<VerifierQuery> = vec![prover_query2.into()];

        let mut transcript = Transcript::new(b"st");

        assert!(multiproof.check(
            &crs,
            &PRECOMPUTED_WEIGHTS,
            &verifier_queries,
            &mut transcript
        ));
    }
}
