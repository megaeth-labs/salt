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
use std::collections::{BTreeMap, BTreeSet};

/// Validates that bucket level information in the proof matches the queried keys.
fn validate_bucket_consistency(
    kvs: &BTreeMap<SaltKey, Option<SaltValue>>,
    buckets_level: &FxHashMap<BucketId, u8>,
) -> Result<(), ProofError> {
    let mut bucket_ids_from_keys: Vec<_> = kvs.keys().map(|k| k.bucket_id()).collect();
    bucket_ids_from_keys.sort_unstable();
    bucket_ids_from_keys.dedup();

    let mut bucket_ids_from_proof: Vec<_> = buckets_level.keys().copied().collect();
    bucket_ids_from_proof.sort_unstable();

    if bucket_ids_from_proof != bucket_ids_from_keys {
        return Err(ProofError::StateReadError {
            reason: "buckets_top_level in proof contains unknown bucket level info".to_string(),
        });
    }

    Ok(())
}

/// Validates that the proof contains commitments for all required nodes.
fn validate_commitment_consistency(
    path_commitments: &BTreeMap<NodeId, CommitmentBytesW>,
    required_node_ids: &[NodeId],
) -> Result<(), ProofError> {
    let mut proof_node_ids: Vec<_> = path_commitments.keys().copied().collect();
    proof_node_ids.sort_unstable();

    if proof_node_ids != required_node_ids {
        return Err(ProofError::StateReadError {
            reason: "path_commitments in proof contains unknown node commitment".to_string(),
        });
    }

    Ok(())
}

/// Safely retrieves a commitment from the proof, returning an error instead of panicking.
fn get_commitment_safe(
    path_commitments: &BTreeMap<NodeId, CommitmentBytesW>,
    node_id: NodeId,
) -> Result<Element, ProofError> {
    let commitment_bytes =
        path_commitments
            .get(&node_id)
            .ok_or_else(|| ProofError::StateReadError {
                reason: format!("Missing commitment for node ID {node_id}"),
            })?;

    Ok(Element::from_bytes_unchecked_uncompressed(
        commitment_bytes.0,
    ))
}

/// Creates verifier queries for leaf nodes (bucket contents).
fn create_leaf_node_queries(
    parent: NodeId,
    points: &BTreeSet<usize>,
    kvs: &BTreeMap<SaltKey, Option<SaltValue>>,
    commitment: Element,
) -> Result<Vec<VerifierQuery>, ProofError> {
    // Calculate the starting SaltKey for this bucket/segment
    let salt_key_start = if parent < BUCKET_SLOT_ID_MASK as NodeId {
        // Main trie leaf (regular bucket)
        let bucket_id = (parent - STARTING_NODE_ID[3] as NodeId) as BucketId;
        SaltKey::from((bucket_id, 0))
    } else {
        // Subtree leaf (bucket segment)
        subtree_leaf_start_key(&parent)
    };

    let queries = points
        .iter()
        .map(|&point| {
            // Calculate the exact SaltKey for this slot position
            let salt_key = SaltKey(salt_key_start.0 + point as u64);

            // Look up the value and convert to field element
            let salt_val = kvs
                .get(&salt_key)
                .ok_or_else(|| ProofError::StateReadError {
                    reason: format!("Missing key-value entry for salt_key: {salt_key:?}"),
                })?;

            let result = salt_val.as_ref().map_or(
                // Non-existent key: use empty slot hash
                Fr::from_le_bytes_mod_order(&EMPTY_SLOT_HASH),
                // Existing key: hash the key-value pair
                calculate_fr_by_kv,
            );

            Ok(VerifierQuery {
                commitment,
                point: Fr::from(point as u64), // Slot position within bucket
                result,
            })
        })
        .collect::<Result<Vec<_>, _>>()?;

    Ok(queries)
}

/// Creates verifier queries for internal nodes (tree structure).
fn create_internal_node_queries(
    parent: NodeId,
    points: &BTreeSet<usize>,
    path_commitments: &BTreeMap<NodeId, CommitmentBytesW>,
    commitment: Element,
) -> Result<Vec<VerifierQuery>, ProofError> {
    let logic_parent = logic_parent_id(parent);

    let queries = points
        .iter()
        .map(|&point| {
            // Calculate the child node ID for this branch
            let child_id = get_child_node(&logic_parent, point);

            // Get the child's commitment from the proof
            let child_commitment = get_commitment_safe(path_commitments, child_id)?;

            Ok(VerifierQuery {
                commitment,
                point: Fr::from(point as u64), // Child index (0-255)
                // Convert child's commitment to scalar for polynomial evaluation
                result: child_commitment.map_to_scalar_field(),
            })
        })
        .collect::<Result<Vec<_>, _>>()?;

    Ok(queries)
}

/// Creates cryptographic verifier queries for SALT proof verification.
///
/// This function transforms a proof's structural data into the specific polynomial evaluation
/// queries needed by the IPA (Inner Product Argument) verifier. Each query specifies a
/// commitment to verify, an evaluation point, and the expected result.
///
/// # Process Overview
///
/// 1. **Validate Inputs**: Ensures bucket level information matches the queried keys
/// 2. **Analyze Tree Structure**: Determines parent nodes and evaluation points needed
/// 3. **Generate Queries**: Creates verification queries for both leaf and internal nodes
///
/// # Arguments
///
/// * `path_commitments` - Map of node IDs to their cryptographic commitments from the proof
/// * `kvs` - Key-value pairs to verify (already sorted and deduplicated). None values represent non-existent keys
/// * `buckets_level` - Bucket expansion levels for determining subtree structure
///
/// # Returns
///
/// Vector of `VerifierQuery` objects ready for IPA polynomial verification
///
/// # Errors
///
/// * `ProofError::StateReadError` - If bucket level info or path commitments are inconsistent with the queried keys
pub(crate) fn create_verifier_queries(
    path_commitments: &BTreeMap<NodeId, CommitmentBytesW>,
    kvs: &BTreeMap<SaltKey, Option<SaltValue>>,
    buckets_level: &FxHashMap<BucketId, u8>,
) -> Result<Vec<VerifierQuery>, ProofError> {
    // Early return for empty inputs
    if kvs.is_empty() {
        return Ok(Vec::new());
    }

    // Validate input consistency
    validate_bucket_consistency(kvs, buckets_level)?;

    // Analyze the SALT tree structure to determine which parent nodes need verification
    // and what evaluation points (child indices or slot positions) are required
    let keys_to_verify: Vec<_> = kvs.keys().copied().collect();
    let parent_points_map = parents_and_points(&keys_to_verify, buckets_level);

    // Convert logical parent IDs to their commitment storage IDs and validate
    let required_node_ids: Vec<_> = parent_points_map
        .keys()
        .map(|node_id| connect_parent_id(*node_id))
        .sorted_unstable()
        .collect();

    validate_commitment_consistency(path_commitments, &required_node_ids)?;

    // Transform each parent-points pair into polynomial evaluation queries
    let all_queries = parent_points_map
        .into_iter()
        .map(|(parent_node, evaluation_points)| {
            // Get the cryptographic commitment for this parent node
            let parent_commitment =
                get_commitment_safe(path_commitments, connect_parent_id(parent_node))?;

            // Generate different query types based on node type
            if is_leaf_node(parent_node) {
                // LEAF NODE QUERIES: Verify actual key-value data in buckets
                create_leaf_node_queries(parent_node, &evaluation_points, kvs, parent_commitment)
            } else {
                // INTERNAL NODE QUERIES: Verify trie structure by checking child commitments
                create_internal_node_queries(
                    parent_node,
                    &evaluation_points,
                    path_commitments,
                    parent_commitment,
                )
            }
        })
        .collect::<Result<Vec<_>, _>>()?
        .into_iter()
        .flatten()
        .collect();

    Ok(all_queries)
}
