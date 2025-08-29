//! Verifier for the Salt proof
use crate::{
    constant::{BUCKET_SLOT_ID_MASK, STARTING_NODE_ID},
    proof::{
        prover::slot_to_field,
        shape::{connect_parent_id, logic_parent_id, parents_and_points},
        ProofError, ProofResult, SerdeCommitment,
    },
    trie::node_utils::{get_child_node, subtree_leaf_start_key},
    types::{BucketId, NodeId, SaltKey, SaltValue},
};
use banderwagon::{Element, Fr};
use ipa_multipoint::multiproof::VerifierQuery;
use rayon::prelude::*;
use rustc_hash::FxHashMap;
use std::collections::{BTreeMap, BTreeSet};

/// Safely retrieves a commitment from the proof, returning an error when the commitment is missing.
fn get_commitment_safe(
    path_commitments: &BTreeMap<NodeId, SerdeCommitment>,
    node_id: NodeId,
) -> ProofResult<Element> {
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
) -> ProofResult<Vec<VerifierQuery>> {
    if kvs.is_empty() {
        return Err(ProofError::StateReadError {
            reason: "kvs is empty".to_string(),
        });
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
    let (internal_nodes, leaf_nodes) = parents_and_points(&keys_to_verify, buckets_level);

    // Convert logical parent IDs to their commitment storage IDs and validate
    let required_node_ids: Vec<_> = internal_nodes
        .keys()
        .chain(leaf_nodes.keys())
        .map(|node_id| connect_parent_id(*node_id))
        .collect();

    // Validates that the proof contains and ONLY contains commitments for all required nodes, .
    let proof_node_ids: Vec<_> = path_commitments.keys().copied().collect();
    if proof_node_ids != required_node_ids {
        return Err(ProofError::StateReadError {
            reason: "path_commitments in proof contains unknown node commitment".to_string(),
        });
    }

    let internal_queries = create_internal_node_queries(&internal_nodes, path_commitments)?;
    let leaf_queries = create_leaf_node_queries(&leaf_nodes, path_commitments, kvs)?;

    let mut queries = internal_queries;
    queries.extend(leaf_queries);

    Ok(queries)
}

/// Creates verification queries for internal trie nodes using parallel processing.
///
/// This function generates polynomial evaluation queries that verify parent-child relationships
/// in the SALT trie structure. Each query checks that a parent node's polynomial correctly
/// evaluates to its child's commitment at the specified index.
///
/// # Arguments
///
/// * `internal_nodes` - Map of parent node IDs to sets of child indices that need verification
/// * `path_commitments` - Cryptographic commitments for all nodes in the proof
///
/// # Returns
///
/// Vector of `VerifierQuery` objects for polynomial verification of internal node relationships
fn create_internal_node_queries(
    internal_nodes: &BTreeMap<NodeId, BTreeSet<usize>>,
    path_commitments: &BTreeMap<NodeId, SerdeCommitment>,
) -> ProofResult<Vec<VerifierQuery>> {
    // Distribute internal nodes across CPU threads for parallel processing
    let in_nodes: Vec<_> = internal_nodes.iter().collect();

    let queries = in_nodes
        .par_chunks(in_nodes.len().div_ceil(rayon::current_num_threads()))
        .map(|nodes| {
            // Step 1: Collect all child commitments needed by this thread's nodes
            // This enables efficient batch conversion to field elements
            let (children_ids, children_commitments) =
                children_commitments_to_scalars(nodes, path_commitments)?;

            // Step 2: PERFORMANCE CRITICAL - Batch convert commitments to field elements
            // serial_batch_map_to_scalar_field() requires only ONE field inversion for all commitments
            // vs individual conversions which would require one inversion per commitment
            let children_frs = Element::serial_batch_map_to_scalar_field(children_commitments);
            let child_map: FxHashMap<NodeId, Fr> =
                children_ids.into_iter().zip(children_frs).collect();

            // Step 3: Generate verification queries for each parent-child relationship
            Ok(nodes
                .iter()
                .map(|(&encode_node, points)| {
                    let mut queries = Vec::new();
                    // Get parent node's polynomial commitment
                    let commitment =
                        get_commitment_safe(path_commitments, connect_parent_id(encode_node))?;

                    // Create one query per child
                    for &point in points.iter() {
                        let child_id = get_child_node(&logic_parent_id(encode_node), point);
                        let fr =
                            child_map
                                .get(&child_id)
                                .ok_or_else(|| ProofError::StateReadError {
                                    reason: format!("Missing commitment for node ID {child_id}"),
                                })?;

                        queries.push(VerifierQuery {
                            commitment,                    // Parent polynomial commitment
                            point: Fr::from(point as u64), // Child index (0-255)
                            result: *fr, // Expected result: child's commitment as field element
                        });
                    }

                    Ok(queries)
                })
                .collect::<ProofResult<Vec<_>>>()?
                .into_iter()
                .flatten()
                .collect::<Vec<_>>())
        })
        .collect::<ProofResult<Vec<_>>>()?;

    Ok(queries.into_iter().flatten().collect())
}

/// Extracts child node IDs and commitment bytes for batch processing.
///
/// This helper function collects all child commitments needed by a set of parent nodes,
/// enabling efficient batch conversion to field elements. It flattens the nested structure
/// of parent nodes → child indices → child commitments into parallel vectors.
///
/// # Arguments
///
/// * `nodes` - Slice of parent nodes and their child indices from one thread's work chunk  
/// * `path_commitments` - Map of all node commitments in the proof
///
/// # Returns
///
/// Tuple of (child_node_ids, child_commitment_bytes) ready for batch field conversion
fn children_commitments_to_scalars(
    nodes: &[(&NodeId, &BTreeSet<usize>)],
    path_commitments: &BTreeMap<NodeId, SerdeCommitment>,
) -> ProofResult<(Vec<NodeId>, Vec<[u8; 64]>)> {
    // Flatten nested structure: parent_nodes → child_indices → (child_id, commitment_bytes)
    let (children_ids, children_commitments): (Vec<_>, Vec<_>) = nodes
        .iter()
        .map(|(&encode_node, points)| {
            // For each child index of this parent, get the child's node ID and commitment
            points
                .iter()
                .map(|&point| {
                    let child_id = get_child_node(&logic_parent_id(encode_node), point);
                    Ok((
                        child_id,
                        // Extract raw commitment bytes for batch field conversion
                        path_commitments
                            .get(&child_id)
                            .ok_or_else(|| ProofError::StateReadError {
                                reason: format!("Missing commitment for node ID {child_id}"),
                            })?
                            .0,
                    ))
                })
                .collect::<ProofResult<Vec<_>>>()
        })
        .collect::<ProofResult<Vec<_>>>()?
        .into_iter()
        .flatten()
        .unzip(); // Separate into parallel vectors for batch processing

    Ok((children_ids, children_commitments))
}

/// Creates verification queries for leaf trie nodes (data buckets) using parallel processing.
///
/// This function generates polynomial evaluation queries that verify the actual key-value data
/// stored in SALT trie buckets. Each query checks that a bucket's polynomial correctly evaluates
/// to the stored value at the specified slot position.
///
/// # Key Differences from Internal Nodes
///
/// * **Data Verification**: Verifies actual stored values, not just structural commitments
/// * **No Batch Conversion**: Values are converted individually via `slot_to_field()`
/// * **Bucket Addressing**: Maps slot positions to actual `SaltKey` addresses
/// * **Memory Efficient**: Returns lazy iterator to avoid materializing all queries
///
/// # Bucket Types Handled
///
/// * **Main Trie Buckets**: Regular buckets with predictable addressing
/// * **Subtree Segments**: Expanded bucket segments with calculated start positions
///
/// # Arguments
///
/// * `leaf_nodes` - Map of bucket node IDs to sets of slot positions needing verification
/// * `path_commitments` - Cryptographic commitments for bucket polynomials
/// * `kvs` - Key-value data to verify against
///
/// # Returns
///
/// Lazy iterator of `VerifierQuery` objects for bucket data verification
fn create_leaf_node_queries(
    leaf_nodes: &BTreeMap<NodeId, BTreeSet<usize>>,
    path_commitments: &BTreeMap<NodeId, SerdeCommitment>,
    kvs: &BTreeMap<SaltKey, Option<SaltValue>>,
) -> ProofResult<impl Iterator<Item = VerifierQuery>> {
    // Process leaf nodes in parallel - each represents a data bucket
    let queries = leaf_nodes
        .par_iter()
        .map(|(parent_node, evaluation_points)| {
            // Get the polynomial commitment for this bucket
            let commitment =
                get_commitment_safe(path_commitments, connect_parent_id(*parent_node))?;

            // Calculate the starting SaltKey address for this bucket/segment
            let salt_key_start = if *parent_node < BUCKET_SLOT_ID_MASK as NodeId {
                // Main trie bucket: predictable addressing based on bucket ID
                let bucket_id = (*parent_node - STARTING_NODE_ID[3] as NodeId) as BucketId;
                SaltKey::from((bucket_id, 0))
            } else {
                // Subtree segment: use helper to calculate complex addressing
                subtree_leaf_start_key(parent_node)
            };

            // Generate verification queries for each slot position in this bucket
            evaluation_points
                .iter()
                .map(|&point| {
                    // Convert slot position to actual SaltKey address
                    let salt_key = SaltKey(salt_key_start.0 + point as u64);

                    // Look up the actual stored value for this key
                    let salt_val =
                        kvs.get(&salt_key)
                            .ok_or_else(|| ProofError::StateReadError {
                                reason: format!(
                                    "Missing key-value entry for salt_key: {salt_key:?}"
                                ),
                            })?;

                    // Create query: verify bucket_polynomial(slot_position) == stored_value
                    Ok(VerifierQuery {
                        commitment,                      // Bucket polynomial commitment
                        point: Fr::from(point as u64),   // Slot position within bucket (0-255)
                        result: slot_to_field(salt_val), // Stored value converted to field element
                    })
                })
                .collect::<Result<Vec<_>, _>>()
        })
        .collect::<Result<Vec<_>, _>>()?;

    // Return lazy iterator for memory efficiency - avoids materializing all queries at once
    Ok(queries.into_iter().flatten())
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

        // Should return error
        assert!(matches!(result, Err(ProofError::StateReadError { .. })));
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

    /// Tests the children_commitments_to_scalars helper function.
    #[test]
    fn test_children_commitments_to_scalars() {
        // Setup: Create mock nodes and commitments
        let node1 = 100u64;
        let node2 = 200u64;
        let points1 = [0usize, 1usize].into();
        let points2 = [2usize].into();
        let nodes = [(&node1, &points1), (&node2, &points2)];

        let mut path_commitments = BTreeMap::new();
        // Add commitments for child nodes that will be calculated
        let child1 = get_child_node(&logic_parent_id(node1), 0);
        let child2 = get_child_node(&logic_parent_id(node1), 1);
        let child3 = get_child_node(&logic_parent_id(node2), 2);

        path_commitments.insert(child1, mock_commitment());
        path_commitments.insert(child2, mock_commitment());
        path_commitments.insert(child3, mock_commitment());

        let result = children_commitments_to_scalars(&nodes, &path_commitments);

        // Should successfully extract child IDs and commitments
        assert!(result.is_ok());
        let (child_ids, commitments) = result.unwrap();
        assert_eq!(child_ids.len(), 3); // Two children from node1, one from node2
        assert_eq!(commitments.len(), 3);
        assert!(child_ids.contains(&child1));
        assert!(child_ids.contains(&child2));
        assert!(child_ids.contains(&child3));
    }

    /// Tests the children_commitments_to_scalars helper function with missing commitment.
    #[test]
    fn test_children_commitments_to_scalars_missing() {
        // Setup: Node with child but no commitment in proof
        let node1 = 100u64;
        let points1 = [0usize].into();
        let nodes = [(&node1, &points1)];
        let path_commitments = BTreeMap::new(); // Empty - missing child commitment

        let result = children_commitments_to_scalars(&nodes, &path_commitments);

        // Should fail due to missing child commitment
        assert!(matches!(result, Err(ProofError::StateReadError { .. })));
    }

    /// Tests create_internal_node_queries with valid data.
    #[test]
    fn test_create_internal_node_queries() {
        // Setup: Create internal node with children and their commitments
        let parent_node = 100u64;
        let child_points = [0usize, 1usize].into();
        let mut internal_nodes = BTreeMap::new();
        internal_nodes.insert(parent_node, child_points);

        let mut path_commitments = BTreeMap::new();
        // Add commitment for parent node
        path_commitments.insert(connect_parent_id(parent_node), mock_commitment());

        // Add commitments for child nodes
        let child1 = get_child_node(&logic_parent_id(parent_node), 0);
        let child2 = get_child_node(&logic_parent_id(parent_node), 1);
        path_commitments.insert(child1, mock_commitment());
        path_commitments.insert(child2, mock_commitment());

        let result = create_internal_node_queries(&internal_nodes, &path_commitments);

        // Should successfully create queries for both children
        assert!(result.is_ok());
        let queries = result.unwrap();
        assert_eq!(queries.len(), 2); // One query per child

        // Verify query structure
        assert_eq!(queries[0].point, Fr::from(0u64));
        assert_eq!(queries[1].point, Fr::from(1u64));
    }

    /// Tests create_leaf_node_queries with valid bucket data.
    #[test]
    fn test_create_leaf_node_queries() {
        // Setup: Create leaf node representing a bucket with key-value data
        let bucket_node = STARTING_NODE_ID[3] as NodeId + 100; // Main trie bucket
        let slot_points = [0usize, 5usize].into();
        let mut leaf_nodes = BTreeMap::new();
        leaf_nodes.insert(bucket_node, slot_points);

        let mut path_commitments = BTreeMap::new();
        path_commitments.insert(connect_parent_id(bucket_node), mock_commitment());

        // Add key-value data for the slots
        let bucket_id = (bucket_node - STARTING_NODE_ID[3] as NodeId) as BucketId;
        let key1 = SaltKey::from((bucket_id, 0));
        let key2 = SaltKey::from((bucket_id, 5));
        let mut kvs = BTreeMap::new();
        kvs.insert(key1, Some(mock_salt_value()));
        kvs.insert(key2, Some(mock_salt_value()));

        let result = create_leaf_node_queries(&leaf_nodes, &path_commitments, &kvs);

        // Should successfully create queries for both slots
        assert!(result.is_ok());
        let queries: Vec<_> = result.unwrap().collect();
        assert_eq!(queries.len(), 2); // One query per slot

        // Verify query structure
        assert_eq!(queries[0].point, Fr::from(0u64));
        assert_eq!(queries[1].point, Fr::from(5u64));
    }

    /// Tests create_leaf_node_queries with missing key-value data.
    #[test]
    fn test_create_leaf_node_queries_missing_data() {
        // Setup: Leaf node with slot but no corresponding key-value data
        let bucket_node = STARTING_NODE_ID[3] as NodeId + 100;
        let slot_points = [0usize].into();
        let mut leaf_nodes = BTreeMap::new();
        leaf_nodes.insert(bucket_node, slot_points);

        let mut path_commitments = BTreeMap::new();
        path_commitments.insert(connect_parent_id(bucket_node), mock_commitment());

        let kvs = BTreeMap::new(); // Empty - missing key-value data

        let result = create_leaf_node_queries(&leaf_nodes, &path_commitments, &kvs);

        // Should fail when trying to access missing key-value data
        assert!(result.is_err());
    }
}
