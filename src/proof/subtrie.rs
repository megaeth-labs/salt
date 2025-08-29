//! This module return all-needed queries for a given kv list by create_sub_trie()
use crate::{
    proof::{
        calculate_fr_by_kv,
        shape::{bucket_trie_parents_and_points, main_trie_parents_and_points},
        CommitmentBytesW, ProofError,
    },
    traits::{StateReader, TrieReader},
    trie::trie::{sub_trie_top_level, subtrie_salt_key_start},
    types::{BucketId, BucketMeta, NodeId, SaltKey},
};
use ark_ff::AdditiveGroup;
use banderwagon::{Element, Fr};
use ipa_multipoint::{lagrange_basis::LagrangeBasis, multiproof::ProverQuery};
//use rayon::prelude::*;
use rustc_hash::FxHashMap;
use std::collections::BTreeMap;

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

fn process_trie_queries<T: TrieReader>(
    trie_nodes: Vec<(NodeId, NodeId, Vec<u8>)>,
    trie_reader: &T,
    num_threads: usize,
    queries: &mut Vec<ProverQuery>,
) {
    if trie_nodes.is_empty() {
        return;
    }

    queries.extend(
        trie_nodes
            .chunks((trie_nodes.len() + num_threads - 1) / num_threads)
            .flat_map(|chunk| {
                let multi_children = chunk
                    .iter()
                    .flat_map(|(_, logic_parent, _)| {
                        trie_reader.children(*logic_parent).expect("Failed to get trie children")
                    })
                    .collect::<Vec<_>>();
                let multi_children_frs = Element::serial_batch_map_to_scalar_field(multi_children);

                chunk
                    .iter()
                    .zip(multi_children_frs.chunks(256))
                    .flat_map(|((parent, _, children), frs)| {
                        let parent_commitment = Element::from_bytes_unchecked_uncompressed(
                            trie_reader.get(*parent).expect("Failed to get trie node"),
                        );

                        create_prover_queries(
                            parent_commitment,
                            LagrangeBasis::new(frs.to_vec()),
                            &children,
                        )
                    })
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>(),
    );
}

/// Process bucket state queries
fn process_bucket_state_queries<S: StateReader, T: TrieReader>(
    bucket_state_nodes: Vec<(BucketId, Vec<(NodeId, Vec<u8>)>)>,
    state_reader: &S,
    trie_reader: &T,
    num_threads: usize,
    queries: &mut Vec<ProverQuery>,
) {
    queries.extend(
        bucket_state_nodes
            .chunks((bucket_state_nodes.len() + num_threads - 1) / num_threads)
            .flat_map(|chunk| {
                chunk
                    .iter()
                    .flat_map(|(bucket_id, state_nodes)| {
                        let children_kvs = state_reader
                            .range_bucket(*bucket_id..=*bucket_id)
                            .expect(&format!(
                                "Failed to get bucket state by range_bucket: bucket_id: {:?}",
                                bucket_id
                            ))
                            .into_iter()
                            .collect::<BTreeMap<_, _>>();

                        state_nodes
                            .into_iter()
                            .flat_map(|(node_id, slot_ids)| {
                                let parent_commitment = Element::from_bytes_unchecked_uncompressed(
                                    trie_reader.get(*node_id).expect("Failed to get trie node"),
                                );

                                let salt_key_start = if node_id < &256u64.pow(5) {
                                    (*bucket_id, 0u64).into()
                                } else {
                                    subtrie_salt_key_start(node_id)
                                };

                                let mut default_frs = if *bucket_id < 65536 {
                                    vec![calculate_fr_by_kv(&BucketMeta::default().into()); 256]
                                } else {
                                    vec![Fr::ZERO; 256]
                                };

                                for (k, v) in children_kvs
                                    .range(salt_key_start..SaltKey(salt_key_start.0 + 256))
                                {
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
pub(crate) fn create_sub_trie<S, T>(
    state_reader: &S,
    trie_reader: &T,
    salt_keys: &[SaltKey],
) -> Result<
    (Vec<ProverQuery>, BTreeMap<NodeId, CommitmentBytesW>, FxHashMap<BucketId, u8>),
    ProofError<S, T>,
>
where
    S: StateReader,
    T: TrieReader,
{
    let mut bucket_ids = salt_keys.iter().map(|k| k.bucket_id()).collect::<Vec<_>>();
    bucket_ids.dedup();

    let main_trie_nodes = main_trie_parents_and_points(&bucket_ids);

    let buckets_top_level = bucket_ids
        .into_iter()
        .map(|bucket_id| {
            let meta = state_reader.get_meta(bucket_id)?;
            let bucket_trie_top_level = sub_trie_top_level(meta.capacity);
            Ok((bucket_id, bucket_trie_top_level as u8))
        })
        .collect::<Result<FxHashMap<_, _>, S::Error>>()
        .map_err(|e| ProofError::ReadStateFailed(e))?;

    let (bucket_trie_nodes, bucket_state_nodes) =
        bucket_trie_parents_and_points(salt_keys, &buckets_top_level);

    let mut queries = Vec::with_capacity(
        main_trie_nodes.iter().map(|(_, _, points)| points.len()).sum::<usize>() +
            bucket_trie_nodes.iter().map(|(_, _, points)| points.len()).sum::<usize>() +
            salt_keys.len(),
    );

    let num_threads = 32;

    // Process main queries
    process_trie_queries(main_trie_nodes.clone(), trie_reader, num_threads, &mut queries);

    // Process bucket queries
    process_trie_queries(bucket_trie_nodes.clone(), trie_reader, num_threads, &mut queries);

    // Process state queries
    process_bucket_state_queries(
        bucket_state_nodes.clone(),
        state_reader,
        trie_reader,
        num_threads,
        &mut queries,
    );

    // Process main trie nodes commitments
    let mut parents_commitments = main_trie_nodes
        .into_iter()
        .map(|(parent, _, _)| {
            (parent, CommitmentBytesW(trie_reader.get(parent).expect("Failed to get trie node")))
        })
        .collect::<BTreeMap<_, _>>();

    // Process bucket trie nodes commitments
    parents_commitments.extend(bucket_trie_nodes.into_iter().map(|(parent, _, _)| {
        (parent, CommitmentBytesW(trie_reader.get(parent).expect("Failed to get trie node")))
    }));

    // Process bucket state nodes commitments
    parents_commitments.extend(
        bucket_state_nodes.into_iter().flat_map(|(_, state_nodes)| state_nodes).map(
            |(node_id, _)| {
                (
                    node_id,
                    CommitmentBytesW(trie_reader.get(node_id).expect("Failed to get trie node")),
                )
            },
        ),
    );

    Ok((queries, parents_commitments, buckets_top_level))
}
