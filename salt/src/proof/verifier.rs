//! Verifier for the Salt proof
use crate::{
    constant::{NUM_META_BUCKETS, STARTING_NODE_ID, SUB_TRIE_LEVELS, TRIE_LEVELS},
    proof::{
        calculate_fr_by_kv,
        shape::{
            bucket_trie_parents_and_points, get_main_trie_child_node, main_trie_parents_and_points,
        },
        CommitmentBytesW, ProofError,
    },
    traits::{StateReader, TrieReader},
    trie::trie::{get_child_node, subtrie_node_id},
    types::{BucketId, BucketMeta, NodeId, SaltKey, SaltValue},
};
use ark_ff::AdditiveGroup;
use banderwagon::{Element, Fr};
use ipa_multipoint::multiproof::VerifierQuery;
use rayon::prelude::*;
use rustc_hash::FxHashMap;
use std::collections::BTreeMap;

/// Helper function to create verify queries for a given commitment and points
fn create_verify_queries(
    parent_id: NodeId,
    logic_parent_id: NodeId,
    points: &[u8],
    commitment: Element,
    child_fr: &FxHashMap<NodeId, Fr>,
) -> Vec<VerifierQuery> {
    points
        .iter()
        .map(|point| {
            let child_id = if parent_id < STARTING_NODE_ID[3] as NodeId {
                get_main_trie_child_node(logic_parent_id, *point)
            } else {
                get_child_node(&logic_parent_id, *point as usize)
            };

            VerifierQuery {
                commitment,
                point: Fr::from(*point as u64),
                result: child_fr[&child_id],
            }
        })
        .collect()
}

/// Process trie query, convert main trie node to VerifierQuery
///
/// # Parameters
///
/// * `trie_nodes` - trie node list, each element is a triple `(parent_id, logic_id,
///   children_indices)`
/// * `path_commitments` - path commitment map, key is node ID, value is corresponding commitment
/// * `num_threads` - number of threads used for parallel processing
/// * `queries` - list of VerifierQuery to be verified, used to save processing results and reduce
///   clone
///
/// # Description
///
/// - Function uses parallel processing to improve performance
/// - For each trie node:
/// 1. Get its parent node ID and logical node ID
/// 2. Get the corresponding commitment from path_commitments
/// 3. According to children_indices Calculate the points that need to be verified
/// 4. Create a VerifierQuery object
fn process_trie_queries(
    trie_nodes: Vec<(NodeId, NodeId, Vec<u8>)>,
    path_commitments: &BTreeMap<NodeId, CommitmentBytesW>,
    num_threads: usize,
    queries: &mut Vec<VerifierQuery>,
) {
    if trie_nodes.is_empty() {
        return;
    }

    queries.extend(
        trie_nodes
            .par_chunks(trie_nodes.len().div_ceil(num_threads))
            .flat_map(|chunk| {
                let (multi_children_id, multi_children_commitment) = chunk
                    .iter()
                    .flat_map(|(parent, logic_parent, points)| {
                        points
                            .iter()
                            .map(|point| {
                                let child_id = if *parent < STARTING_NODE_ID[3] as NodeId {
                                    get_main_trie_child_node(*parent, *point)
                                } else {
                                    get_child_node(logic_parent, *point as usize)
                                };

                                (
                                    child_id,
                                    path_commitments
                                        .get(&child_id)
                                        .cloned()
                                        .unwrap_or_else(|| {
                                            panic!("path_commitments lack id {child_id:?}")
                                        })
                                        .0,
                                )
                            })
                            .collect::<Vec<_>>()
                    })
                    .unzip::<_, _, Vec<_>, Vec<_>>();

                // Convert children commitments to frs at the same time for faster processing
                let multi_children_frs =
                    Element::serial_batch_map_to_scalar_field(multi_children_commitment);

                let child_map: FxHashMap<NodeId, Fr> = multi_children_id
                    .iter()
                    .zip(multi_children_frs)
                    .map(|(id, fr)| (*id, fr))
                    .collect();

                chunk
                    .iter()
                    .flat_map(|(parent, logic_parent, points)| {
                        let commitment = Element::from_bytes_unchecked_uncompressed(
                            path_commitments
                                .get(parent)
                                .cloned()
                                .unwrap_or_else(|| panic!("path_commitments lack id {parent:?}"))
                                .0,
                        );

                        create_verify_queries(
                            *parent,
                            *logic_parent,
                            points,
                            commitment,
                            &child_map,
                        )
                    })
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>(),
    );
}

/// Create verifier queries.
/// kvs have already been sorted and deduped.
pub(crate) fn create_verifier_queries<B, T>(
    path_commitments: &BTreeMap<NodeId, CommitmentBytesW>,
    kvs: Vec<(SaltKey, Option<SaltValue>)>,
    buckets_top_level: &FxHashMap<BucketId, u8>,
) -> Result<Vec<VerifierQuery>, ProofError<B, T>>
where
    B: StateReader,
    T: TrieReader,
{
    let mut bucket_ids = kvs.iter().map(|(k, _)| k.bucket_id()).collect::<Vec<_>>();
    bucket_ids.dedup();

    let trie_nodes = main_trie_parents_and_points(&bucket_ids);

    // trie_nodes for main trie
    // kvs *1 for bucket state queries and kvs *2 > bucket trie querie' len in most cases
    let total_len = trie_nodes
        .iter()
        .map(|(_, _, points)| points.len())
        .sum::<usize>()
        + kvs.len() * 3;

    let mut queries = Vec::with_capacity(total_len);

    let num_threads = rayon::current_num_threads();

    process_trie_queries(trie_nodes, path_commitments, num_threads, &mut queries);

    // process bucket trie queries
    let salt_keys = kvs.iter().map(|(k, _)| *k).collect::<Vec<_>>();
    let (bucket_trie_nodes, _) = bucket_trie_parents_and_points(&salt_keys, buckets_top_level);

    process_trie_queries(
        bucket_trie_nodes,
        path_commitments,
        num_threads,
        &mut queries,
    );

    // process bucket state queries
    let chunk_size = kvs.len().div_ceil(num_threads);
    let bucket_state_queries = kvs
        .par_chunks(chunk_size)
        .flat_map(|chunk| {
            chunk
                .iter()
                .map(|(key, val)| {
                    let bucket_id = key.bucket_id();

                    let slot_id = key.slot_id() & 0xff;

                    let result = if bucket_id < NUM_META_BUCKETS as BucketId && val.is_none() {
                        calculate_fr_by_kv(&(BucketMeta::default().into()))
                    } else {
                        val.as_ref().map_or(Fr::ZERO, calculate_fr_by_kv)
                    };

                    let bucket_trie_top_level = buckets_top_level[&bucket_id];

                    let parent_id = if bucket_trie_top_level == SUB_TRIE_LEVELS as u8 - 1 {
                        bucket_id as NodeId + STARTING_NODE_ID[TRIE_LEVELS - 1] as NodeId
                    } else {
                        subtrie_node_id(key)
                    };

                    let l3_commitment = path_commitments
                        .get(&parent_id)
                        .cloned()
                        .unwrap_or_else(|| panic!("path_commitments lack id {parent_id:?}"))
                        .0;

                    VerifierQuery {
                        commitment: Element::from_bytes_unchecked_uncompressed(l3_commitment),
                        point: Fr::from(slot_id),
                        result,
                    }
                })
                .collect::<Vec<_>>()
        })
        .collect::<Vec<_>>();

    queries.extend(bucket_state_queries);

    Ok(queries)
}
