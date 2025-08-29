//! Verifier for the Salt proof
use crate::{
    constant::{BUCKET_SLOT_ID_MASK, STARTING_NODE_ID},
    proof::{
        prover::slot_to_field,
        shape::{connect_parent_id, is_leaf_node, logic_parent_id, parents_and_points},
        ProofError, SerdeCommitment,
    },
    trie::node_utils::{get_child_node, subtree_leaf_start_key},
    types::{BucketId, NodeId, SaltKey, SaltValue},
};
use banderwagon::{Element, Fr};
use ipa_multipoint::multiproof::VerifierQuery;
use rayon::prelude::*;
use rustc_hash::FxHashMap;
use std::collections::BTreeMap;

/// Safely retrieves a commitment from the proof, returning an error instead of panicking.
fn get_commitment_safe(
    path_commitments: &BTreeMap<NodeId, SerdeCommitment>,
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
    path_commitments: &BTreeMap<NodeId, SerdeCommitment>,
    kvs: &BTreeMap<SaltKey, Option<SaltValue>>,
    buckets_level: &FxHashMap<BucketId, u8>,
) -> Result<Vec<VerifierQuery>, ProofError> {
    // Early return for empty inputs
    if kvs.is_empty() {
        return Ok(Vec::new());
    }

    // Validates that bucket level information in the proof matches the queried keys.
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

    // Analyze the SALT tree structure to determine which parent nodes need verification
    // and what evaluation points (child indices or slot positions) are required
    let keys_to_verify: Vec<_> = kvs.keys().copied().collect();
    let parent_points_map = parents_and_points(&keys_to_verify, buckets_level);

    // Convert logical parent IDs to their commitment storage IDs and validate
    let required_node_ids: Vec<_> = parent_points_map
        .keys()
        .map(|node_id| connect_parent_id(*node_id))
        .collect();

    // Validates that the proof contains and ONLY contains commitments for all required nodes, .
    let proof_node_ids: Vec<_> = path_commitments.keys().copied().collect();
    if proof_node_ids != required_node_ids {
        return Err(ProofError::StateReadError {
            reason: "path_commitments in proof contains unknown node commitment".to_string(),
        });
    }

    // Transform each parent-points pair into polynomial evaluation queries
    let all_queries = parent_points_map
        .into_par_iter()
        .map(|(parent_node, evaluation_points)| {
            // Get the cryptographic commitment for this parent node
            let commitment = get_commitment_safe(path_commitments, connect_parent_id(parent_node))?;

            // Generate different query types based on node type
            if is_leaf_node(parent_node) {
                // LEAF NODE QUERIES: Verify actual key-value data in buckets
                // Calculate the starting SaltKey for this bucket/segment
                let salt_key_start = if parent_node < BUCKET_SLOT_ID_MASK as NodeId {
                    // Main trie leaf (regular bucket)
                    let bucket_id = (parent_node - STARTING_NODE_ID[3] as NodeId) as BucketId;
                    SaltKey::from((bucket_id, 0))
                } else {
                    // Subtree leaf (bucket segment)
                    subtree_leaf_start_key(&parent_node)
                };

                evaluation_points
                    .iter()
                    .map(|&point| {
                        // Calculate the exact SaltKey for this slot position
                        let salt_key = SaltKey(salt_key_start.0 + point as u64);

                        // Look up the value and convert to field element
                        let salt_val =
                            kvs.get(&salt_key)
                                .ok_or_else(|| ProofError::StateReadError {
                                    reason: format!(
                                        "Missing key-value entry for salt_key: {salt_key:?}"
                                    ),
                                })?;

                        let result = slot_to_field(salt_val);

                        Ok(VerifierQuery {
                            commitment,
                            point: Fr::from(point as u64), // Slot position within bucket
                            result,
                        })
                    })
                    .collect::<Result<Vec<_>, _>>()
            } else {
                // INTERNAL NODE QUERIES: Verify trie structure by checking child commitments
                let child_commitments = evaluation_points
                    .iter()
                    .map(|&point| {
                        // Calculate the child node ID for this branch
                        let child_id = get_child_node(&logic_parent_id(parent_node), point);

                        // Get the child's commitment from the proof
                        Ok(path_commitments
                            .get(&child_id)
                            .ok_or_else(|| ProofError::StateReadError {
                                reason: format!("Missing commitment for node ID {child_id}"),
                            })?
                            .0)
                    })
                    .collect::<Result<Vec<_>, _>>()?;

                let children_frs = Element::serial_batch_map_to_scalar_field(child_commitments);

                Ok(evaluation_points
                    .into_iter()
                    .zip(children_frs)
                    .map(|(point, result)| {
                        VerifierQuery {
                            commitment,
                            point: Fr::from(point as u64), // Child index (0-255)
                            // Convert child's commitment to scalar for polynomial evaluation
                            result,
                        }
                    })
                    .collect::<Vec<_>>())
            }
        })
        .collect::<Result<Vec<_>, _>>()?
        .into_iter()
        .flatten()
        .collect();

    Ok(all_queries)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::constant::NUM_META_BUCKETS;

    /// Creates a dummy 64-byte cryptographic commitment for testing.
    fn mock_commitment() -> SerdeCommitment {
        SerdeCommitment([1u8; 64])
    }

    /// Creates a mock encoded key-value pair with fixed test data.
    fn mock_salt_value() -> SaltValue {
        SaltValue::new(&[1u8; 32], &[2u8; 32])
    }

    /// Tests successful commitment retrieval for existing node IDs.
    #[test]
    fn test_get_commitment_safe_success() {
        // Setup: Proof contains commitment for node 1
        let commitments = [(1u64, mock_commitment())].into();

        // Should successfully retrieve and convert commitment to Element
        assert!(get_commitment_safe(&commitments, 1).is_ok());

        // Should return error instead of panicking for missing node
        assert!(get_commitment_safe(&commitments, 2).is_err());
    }

    /// Tests main function behavior with empty inputs (edge case).
    #[test]
    fn test_create_verifier_queries_empty() {
        // Setup: All inputs empty
        let result =
            create_verifier_queries(&BTreeMap::new(), &BTreeMap::new(), &FxHashMap::default());

        // Should return empty query list without error (early return optimization)
        assert_eq!(result.unwrap(), Vec::new());
    }

    /// Tests main function error handling for inconsistent bucket level information.
    #[test]
    fn test_create_verifier_queries_bucket_mismatch() {
        // Setup: Key from bucket 100, but proof has level info for bucket 200
        let kvs = [(SaltKey::from((100, 0)), Some(mock_salt_value()))].into();
        let mut buckets_level = FxHashMap::default();
        buckets_level.insert(200, 1u8); // Proof references wrong bucket
        let path_commitments = BTreeMap::new();

        let result = create_verifier_queries(&path_commitments, &kvs, &buckets_level);

        // Should fail during bucket consistency validation
        assert!(matches!(result, Err(ProofError::StateReadError { .. })));
    }

    /// Tests main function error handling for missing node commitments in proof.
    #[test]
    fn test_create_verifier_queries_commitment_mismatch() {
        // Setup: Valid bucket consistency but empty proof commitments
        let kvs = [(
            SaltKey::from((NUM_META_BUCKETS as u32, 0)),
            Some(mock_salt_value()),
        )]
        .into();
        let mut buckets_level = FxHashMap::default();
        buckets_level.insert(NUM_META_BUCKETS as u32, 0u8); // Bucket levels match
        let path_commitments = BTreeMap::new(); // Proof missing required node commitments

        let result = create_verifier_queries(&path_commitments, &kvs, &buckets_level);

        // Should fail during commitment consistency validation
        assert!(matches!(result, Err(ProofError::StateReadError { .. })));
    }
}
