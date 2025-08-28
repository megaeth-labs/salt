//! Verifier for the Salt proof
use crate::{
    constant::{BUCKET_SLOT_ID_MASK, EMPTY_SLOT_HASH, STARTING_NODE_ID},
    proof::{
        prover::calculate_fr_by_kv,
        shape::{connect_parent_id, is_leaf_node, logic_parent_id, parents_and_points},
        CommitmentBytesW, ProofError,
    },
    trie::node_utils::{get_child_node, subtree_leaf_start_key},
    types::{BucketId, NodeId, SaltKey, SaltValue},
};
use banderwagon::{Element, Fr, PrimeField};
use ipa_multipoint::multiproof::VerifierQuery;
use iter_tools::Itertools;
use rustc_hash::FxHashMap;
use std::collections::BTreeMap;

/// Create verifier queries.
/// kvs have already been sorted and deduped.
pub(crate) fn create_verifier_queries(
    path_commitments: &BTreeMap<NodeId, CommitmentBytesW>,
    kvs: &BTreeMap<SaltKey, Option<SaltValue>>,
    buckets_level: &FxHashMap<BucketId, u8>,
) -> Result<Vec<VerifierQuery>, ProofError> {
    println!("kvs: {:?}", kvs);
    let mut bucket_ids = kvs.keys().map(|k| k.bucket_id()).collect::<Vec<_>>();
    bucket_ids.dedup();

    let top_level_bucket_ids: Vec<_> = buckets_level.keys().copied().sorted_unstable().collect();

    if top_level_bucket_ids != bucket_ids {
        return Err(ProofError::StateReadError {
            reason: "buckets_top_level in proof contains unknown bucket level info".to_string(),
        });
    }

    let salt_keys = kvs.keys().copied().collect::<Vec<_>>();
    let node = parents_and_points(&salt_keys, buckets_level);

    let node_ids = node
        .keys()
        .map(|node_id| connect_parent_id(*node_id))
        .sorted_unstable()
        .collect::<Vec<_>>();

    if path_commitments.keys().copied().collect::<Vec<_>>() != node_ids {
        return Err(ProofError::StateReadError {
            reason: "path_commitments in proof contains unknown node commitment".to_string(),
        });
    }

    let queries = node
        .into_iter()
        .flat_map(|(parent, points)| {
            let commitment = Element::from_bytes_unchecked_uncompressed(
                path_commitments
                    .get(&connect_parent_id(parent))
                    .cloned()
                    .unwrap_or_else(|| panic!("path_commitments lack id {parent:?}"))
                    .0,
            );

            if is_leaf_node(parent) {
                let salt_key_start = if parent < BUCKET_SLOT_ID_MASK as NodeId {
                    let bucket_id = (parent - STARTING_NODE_ID[3] as NodeId) as BucketId;
                    SaltKey::from((bucket_id, 0))
                } else {
                    subtree_leaf_start_key(&parent)
                };

                points
                    .iter()
                    .map(|&point| {
                        let salt_key = SaltKey(salt_key_start.0 + point as u64);

                        let salt_val = kvs.get(&salt_key).expect("salt_key must can found, as parent and points is calculated by salt_keys");
                        let result = salt_val.as_ref().map_or(
                            Fr::from_le_bytes_mod_order(&EMPTY_SLOT_HASH),
                            calculate_fr_by_kv,
                        );

                        VerifierQuery {
                            commitment,
                            point: Fr::from(point as u64),
                            result,
                        }
                    })
                    .collect::<Vec<_>>()
            } else {
                let logic_parent = logic_parent_id(parent);

                points
                    .iter()
                    .map(|&point| {
                        let child_id = get_child_node(&logic_parent, point);
                        let child_commitment = path_commitments
                            .get(&child_id)
                            .cloned()
                            .unwrap_or_else(|| panic!("path_commitments lack id {child_id:?}"))
                            .0;
                        VerifierQuery {
                            commitment,
                            point: Fr::from(point as u64),
                            result: Element::from_bytes_unchecked_uncompressed(child_commitment)
                                .map_to_scalar_field(),
                        }
                    })
                    .collect::<Vec<_>>()
            }
        })
        .collect::<Vec<_>>();

    Ok(queries)
}
