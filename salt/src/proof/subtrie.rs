//! This module return all-needed queries for a given kv list by create_sub_trie()
use crate::{
    constant::{default_commitment, EMPTY_SLOT_HASH, NUM_META_BUCKETS, TRIE_WIDTH},
    proof::{
        prover::calculate_fr_by_kv,
        shape::{bucket_trie_parents_and_points, main_trie_parents_and_points},
        CommitmentBytesW, ProofError,
    },
    traits::{StateReader, TrieReader},
    trie::node_utils::get_child_node,
    trie::node_utils::{subtree_leaf_start_key, subtree_root_level},
    types::{BucketId, BucketMeta, NodeId, SaltKey},
    SlotId,
};
use banderwagon::{Element, Fr, PrimeField};
use ipa_multipoint::{lagrange_basis::LagrangeBasis, multiproof::ProverQuery};
use rayon::prelude::*;
use rustc_hash::FxHashMap;
use std::collections::BTreeMap;

type SubTrieInfo = (
    Vec<ProverQuery>,
    BTreeMap<NodeId, CommitmentBytesW>,
    FxHashMap<BucketId, u8>,
);

type BucketStateNode = (BucketId, Vec<(NodeId, Vec<u8>)>);
/// Helper function to create prover queries for a given commitment and points
fn create_prover_queries(
    commitment: Element,
    poly: LagrangeBasis,
    points: &[u8],
) -> Vec<ProverQuery> {
    points
        .iter()
        .map(|&i| ProverQuery {
            commitment,
            poly: poly.clone(),
            point: i as usize,
            result: poly.evaluate_in_domain(i as usize),
        })
        .collect()
}

fn process_trie_queries<Store: TrieReader>(
    trie_nodes: Vec<(NodeId, NodeId, Vec<u8>)>,
    store: &Store,
    num_threads: usize,
    queries: &mut Vec<ProverQuery>,
) {
    if trie_nodes.is_empty() {
        return;
    }

    queries.extend(
        trie_nodes
            .par_chunks(trie_nodes.len().div_ceil(num_threads))
            .flat_map(|chunk| {
                let multi_children = chunk
                    .iter()
                    .flat_map(|(_, logic_parent, _)| {
                        let child_idx = get_child_node(logic_parent, 0);
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
                        default_commitment
                    })
                    .collect::<Vec<_>>();
                let multi_children_frs = Element::serial_batch_map_to_scalar_field(multi_children);

                chunk
                    .iter()
                    .zip(multi_children_frs.chunks(256))
                    .flat_map(|((parent, _, children), frs)| {
                        let parent_commitment = Element::from_bytes_unchecked_uncompressed(
                            store.commitment(*parent).expect("Failed to get trie node"),
                        );

                        create_prover_queries(
                            parent_commitment,
                            LagrangeBasis::new(frs.to_vec()),
                            children,
                        )
                    })
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>(),
    );
}

/// Process bucket state queries
fn process_bucket_state_queries<Store: StateReader + TrieReader>(
    bucket_state_nodes: Vec<BucketStateNode>,
    store: &Store,
    num_threads: usize,
    queries: &mut Vec<ProverQuery>,
) {
    queries.extend(
        bucket_state_nodes
            .par_chunks(bucket_state_nodes.len().div_ceil(num_threads))
            .flat_map(|chunk| {
                chunk
                    .iter()
                    .flat_map(|(bucket_id, state_nodes)| {
                        state_nodes
                            .iter()
                            .flat_map(|(node_id, slot_ids)| {
                                let parent_commitment = Element::from_bytes_unchecked_uncompressed(
                                    store
                                        .commitment(*node_id)
                                        .expect("Failed to get trie node"),
                                );

                                let salt_key_start = if node_id < &256u64.pow(5) {
                                    (*bucket_id, 0u64).into()
                                } else {
                                    subtree_leaf_start_key(node_id)
                                };

                                let mut default_frs = if *bucket_id < 65536 {
                                    vec![calculate_fr_by_kv(&BucketMeta::default().into()); 256]
                                } else {
                                    vec![Fr::from_le_bytes_mod_order(&EMPTY_SLOT_HASH); 256]
                                };
                                let slot_start = salt_key_start.slot_id();
                                let children_kvs = store
                                    .entries(SaltKey::from((*bucket_id, slot_start))..=SaltKey::from((*bucket_id, slot_start + TRIE_WIDTH as SlotId -1)))
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
                                    slot_ids.as_slice(),
                                )
                            })
                            .collect::<Vec<_>>()
                    })
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>(),
    );
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

    let main_trie_nodes = main_trie_parents_and_points(&bucket_ids);

    let buckets_top_level = bucket_ids
        .into_iter()
        .map(|bucket_id| {
            if bucket_id < NUM_META_BUCKETS as BucketId {
                return Ok((bucket_id, 4u8));
            }

            let meta = store.metadata(bucket_id)?;
            let bucket_trie_top_level = subtree_root_level(meta.capacity);
            Ok((bucket_id, bucket_trie_top_level as u8))
        })
        .collect::<Result<FxHashMap<_, _>, <Store as StateReader>::Error>>()
        .map_err(|e| ProofError::ProveFailed(format!("Failed to read state: {e:?}")))?;

    let (bucket_trie_nodes, bucket_state_nodes) =
        bucket_trie_parents_and_points(salt_keys, &buckets_top_level);

    let trie_nodes = main_trie_nodes
        .into_iter()
        .chain(bucket_trie_nodes)
        .collect::<Vec<_>>();

    let mut queries = Vec::with_capacity(
        trie_nodes
            .iter()
            .map(|(_, _, points)| points.len())
            .sum::<usize>()
            + salt_keys.len(),
    );

    let num_threads = rayon::current_num_threads();

    // Process trie queries
    process_trie_queries(trie_nodes.clone(), store, num_threads, &mut queries);

    // Process state queries
    process_bucket_state_queries(bucket_state_nodes.clone(), store, num_threads, &mut queries);

    // Process trie nodes commitments
    let mut parents_commitments = trie_nodes
        .into_iter()
        .map(|(parent, _, _)| {
            (
                parent,
                CommitmentBytesW(store.commitment(parent).expect("Failed to get trie node")),
            )
        })
        .collect::<BTreeMap<_, _>>();

    // Process bucket state nodes commitments
    parents_commitments.extend(
        bucket_state_nodes
            .into_iter()
            .flat_map(|(_, state_nodes)| state_nodes)
            .map(|(node_id, _)| {
                (
                    node_id,
                    CommitmentBytesW(store.commitment(node_id).expect("Failed to get trie node")),
                )
            }),
    );

    Ok((queries, parents_commitments, buckets_top_level))
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
        let (_, trie_updates) = trie.update_fin(&updates).unwrap();

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
