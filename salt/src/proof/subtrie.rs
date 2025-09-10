//! Subtrie creation module for SALT proof generation.
//!
//! This module provides the core functionality for creating minimal subtries and generating
//! IPA (Inner Product Argument) proofs for SALT's authenticated key-value store. The main
//! function [`create_sub_trie`] constructs the authentication paths needed to prove the
//! existence or non-existence of specified keys.
//!
//! # Architecture
//!
//! The proof generation process follows these steps:
//! 1. Extract and deduplicate bucket IDs from input keys
//! 2. Determine trie levels for each bucket (metadata vs dynamic data buckets)
//! 3. Build minimal node hierarchy using [`parents_and_points`]
//! 4. Collect cryptographic commitments for all parent nodes
//! 5. Generate IPA prover queries for leaf nodes (bucket contents) and internal nodes (child commitments)
use crate::{
    constant::{
        default_commitment, BUCKET_SLOT_BITS, BUCKET_SLOT_ID_MASK, MAX_SUBTREE_LEVELS,
        NUM_META_BUCKETS, POLY_DEGREE, STARTING_NODE_ID,
    },
    proof::{
        prover::slot_to_field,
        shape::{connect_parent_id, logic_parent_id, parents_and_points},
        ProofError, ProofResult, SerdeCommitment,
    },
    traits::{StateReader, TrieReader},
    trie::node_utils::{get_child_node, subtree_leaf_start_key, subtree_root_level},
    types::{BucketId, BucketMeta, NodeId, SaltKey},
    SlotId,
};
use banderwagon::{Element, Fr};
use ipa_multipoint::{lagrange_basis::LagrangeBasis, multiproof::ProverQuery};
use rayon::prelude::*;
use rustc_hash::FxHashMap;
use std::collections::{BTreeMap, BTreeSet};

// Constants for improved code readability
const METADATA_BUCKET_LEVEL: u8 = 1;
const SLOT_INDEX_MASK: u64 = 0xff;
const ROOT_LEVEL_CHILD_START: NodeId = 1;

/// Information returned by the subtrie creation process
type SubTrieInfo = (
    Vec<ProverQuery>,
    BTreeMap<NodeId, SerdeCommitment>,
    FxHashMap<BucketId, u8>,
);

/// Converts cryptographic commitments from multiple internal trie nodes into scalar field elements.
///
/// This function processes internal nodes in the trie hierarchy and converts their child node
/// commitments into scalar field elements suitable for IPA (Inner Product Argument) proof generation.
/// For each internal node, it loads commitments for all 256 possible child positions, using default
/// commitments where actual child nodes don't exist (sparse trie optimization).
///
/// # Parameters
///
/// * `store` - Storage backend providing access to trie node commitments
/// * `nodes` - Internal nodes with their evaluation points (child indices to prove)
///
/// # Returns
///
/// A vector of scalar field elements (`Fr`) representing all child commitments for the given nodes.
/// The elements are ordered by node, then by child index (0-255 per node).
///
/// # Implementation Details
///
/// - Handles sparse child nodes by filling missing positions with appropriate default commitments
/// - Special handling for root level nodes (different default commitment for first child)
/// - Uses parallel processing for performance when dealing with multiple nodes
/// - Converts Element commitments to scalar field using `serial_batch_map_to_scalar_field`
///
/// # Errors
///
/// Returns `ProofError::StateReadError` if unable to read child node commitments from storage.
fn multi_commitments_to_scalars<Store>(
    store: &Store,
    nodes: &[(NodeId, BTreeSet<usize>)],
) -> ProofResult<Vec<Fr>>
where
    Store: TrieReader,
{
    // Pre-allocate capacity for better memory efficiency
    // Each node contributes exactly 256 commitments
    let total_capacity = nodes.len() * POLY_DEGREE;
    let mut all_child_commitments: Vec<[u8; 64]> = Vec::with_capacity(total_capacity);

    // Load child commitments for each internal node
    for (node_id, _) in nodes {
        // Calculate starting index for this node's 256 children
        let child_idx = get_child_node(&logic_parent_id(*node_id), 0);

        // Load existing child commitments from storage
        let children = store
            .node_entries(child_idx..child_idx + POLY_DEGREE as NodeId)
            .map_err(|e| ProofError::StateReadError {
                reason: format!("Failed to load child nodes for parent {node_id}: {e:?}"),
            })?;

        // Initialize with appropriate default commitments based on tree level
        let mut child_commitments = if child_idx == ROOT_LEVEL_CHILD_START {
            // Root level: first child uses different default than others
            let mut commitments = vec![default_commitment(child_idx + 1); POLY_DEGREE];
            commitments[0] = default_commitment(child_idx);
            commitments
        } else {
            // Non-root levels: all positions use same default
            vec![default_commitment(child_idx); POLY_DEGREE]
        };

        // Replace defaults with actual commitments where child nodes exist
        for (absolute_node_id, commitment) in children {
            let relative_index = absolute_node_id as usize - child_idx as usize;
            child_commitments[relative_index] = commitment;
        }

        all_child_commitments.extend(child_commitments);
    }

    // Convert all Element commitments to scalar field elements in one batch operation
    // This is more efficient than converting individually
    Ok(Element::serial_batch_map_to_scalar_field(
        all_child_commitments,
    ))
}

/// Creates IPA prover queries for a given commitment and evaluation points.
///
/// This helper function generates the cryptographic queries needed for IPA (Inner Product Argument)
/// multipoint proofs. Each query contains:
/// - The polynomial commitment (cryptographic hash)
/// - The polynomial coefficients in Lagrange basis form
/// - An evaluation point (child index within the polynomial)
/// - The result at that point
///
/// # Parameters
/// * `commitment` - The cryptographic commitment to the polynomial
/// * `poly` - The polynomial in Lagrange basis form (256 coefficients)
/// * `points` - Set of evaluation points (child indices) to create queries for
///
/// # Returns
/// A vector of `ProverQuery` objects, one for each evaluation point
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

/// Creates a subtrie infomation for IPA proofs for the given salt keys.
///
/// This function is the core of SALT's proof generation system. It constructs a minimal
/// subtrie containing all the authentication paths needed to prove the existence or
/// non-existence of the specified keys. The function generates prover queries that can
/// be used with the IPA (Inner Product Argument) multipoint proof system.
///
/// # Parameters
///
/// * `store` - Storage backend providing access to both trie commitments and bucket data
/// * `salt_keys` - Pre-sorted and deduplicated keys to generate proofs for
///
/// # Returns
///
/// Returns a tuple containing:
/// * `Vec<ProverQuery>` - IPA prover queries for all nodes in the authentication paths
/// * `BTreeMap<NodeId, CommitmentBytesW>` - Commitments for all parent nodes in the subtrie
/// * `FxHashMap<BucketId, u8>` - Mapping of bucket IDs to their trie levels
///
/// # Errors
///
/// Returns `ProofError::StateReadError` if unable to read bucket metadata or trie commitments.
pub(crate) fn create_sub_trie<Store>(
    store: &Store,
    salt_keys: &[SaltKey],
) -> ProofResult<SubTrieInfo>
where
    Store: StateReader + TrieReader,
{
    if salt_keys.is_empty() {
        return Err(ProofError::StateReadError {
            reason: "empty key set".to_string(),
        });
    }

    // Step 1: Extract and deduplicate bucket IDs from the input keys
    let mut bucket_ids = salt_keys.iter().map(|k| k.bucket_id()).collect::<Vec<_>>();
    bucket_ids.dedup();

    // Step 2: Determine the trie level for each bucket
    let buckets_level: FxHashMap<BucketId, u8> = bucket_ids
        .into_iter()
        .map(|bucket_id| {
            if bucket_id < NUM_META_BUCKETS as BucketId {
                // Metadata buckets are always at level 1 (never expand into subtrees)
                Ok((bucket_id, METADATA_BUCKET_LEVEL))
            } else {
                // Data buckets: read metadata to determine subtree structure
                let meta = store
                    .metadata(bucket_id)
                    .map_err(|e| ProofError::StateReadError {
                        reason: format!("Failed to read metadata for bucket {bucket_id}: {e:?}"),
                    })?;
                // Convert capacity to subtree root level (higher capacity = higher level root)
                let level = MAX_SUBTREE_LEVELS - subtree_root_level(meta.capacity);
                Ok((bucket_id, level as u8))
            }
        })
        .collect::<ProofResult<_>>()?;

    // Step 3: Build the minimal node hierarchy needed for authentication
    let (internal_nodes, leaf_nodes) = parents_and_points(salt_keys, &buckets_level);

    // Step 4: Collect cryptographic commitments for all parent nodes
    let parents_commitments: BTreeMap<NodeId, SerdeCommitment> = internal_nodes
        .iter()
        .chain(leaf_nodes.iter())
        .map(|(&parent, _)| {
            let physical_parent = connect_parent_id(parent);
            let commitment =
                store
                    .commitment(physical_parent)
                    .map_err(|e| ProofError::StateReadError {
                        reason: format!(
                            "Failed to load commitment for node {physical_parent}: {e:?}"
                        ),
                    })?;

            Ok((physical_parent, SerdeCommitment(commitment)))
        })
        .collect::<ProofResult<_>>()?;

    // Step 5: Generate IPA prover queries for each node in internal nodes
    let in_nodes: Vec<_> = internal_nodes.into_iter().collect();
    let mut queries = in_nodes
        .par_chunks(in_nodes.len().div_ceil(rayon::current_num_threads()))
        .map(|nodes| {
            let children_scalars = multi_commitments_to_scalars(store, nodes)?;

            let res = nodes
                .iter()
                .zip(children_scalars.chunks(POLY_DEGREE))
                .map(|((parent, points), children_scalars)| {
                    let commitment = store
                        .commitment(connect_parent_id(*parent))
                        .map(Element::from_bytes_unchecked_uncompressed)
                        .map_err(|e| ProofError::StateReadError {
                            reason: format!("Failed to load commitment for node {parent}: {e:?}"),
                        })?;

                    Ok(create_prover_queries(
                        commitment,
                        LagrangeBasis::new(children_scalars.to_vec()),
                        points.clone(),
                    ))
                })
                .collect::<ProofResult<Vec<_>>>()?
                .into_iter()
                .flatten()
                .collect::<Vec<_>>();

            Ok(res)
        })
        .collect::<ProofResult<Vec<_>>>()?
        .into_iter()
        .flatten()
        .collect::<Vec<_>>();

    // Step 6: Generate IPA prover queries for each node in leaf nodes
    let leaf_queries = leaf_nodes
        .into_par_iter()
        .map(|(parent, points)| {
            let physical_parent = connect_parent_id(parent);
            let parent_commitment = store
                .commitment(physical_parent)
                .map(Element::from_bytes_unchecked_uncompressed)
                .map_err(|e| ProofError::StateReadError {
                    reason: format!(
                        "Failed to load element commitment for node {physical_parent}: {e:?}"
                    ),
                })?;
            process_leaf_node(store, parent, parent_commitment, points)
        })
        .collect::<ProofResult<Vec<_>>>()?
        .into_iter()
        .flatten();

    queries.extend(leaf_queries);

    Ok((queries, parents_commitments, buckets_level))
}

/// Processes a leaf node to create prover queries.
fn process_leaf_node<Store>(
    store: &Store,
    parent: NodeId,
    parent_commitment: Element,
    points: BTreeSet<usize>,
) -> ProofResult<Vec<ProverQuery>>
where
    Store: StateReader,
{
    // Determine the starting slot and bucket ID for this leaf
    let (slot_start, bucket_id) = if parent < BUCKET_SLOT_ID_MASK as NodeId {
        // Main trie leaf: bucket ID derived from position in level 3
        let bucket_id = (parent - STARTING_NODE_ID[3] as NodeId) as BucketId;
        (0, bucket_id)
    } else {
        // Subtree leaf: extract bucket ID and slot start from node ID encoding
        (
            subtree_leaf_start_key(&parent).slot_id(),
            (parent >> BUCKET_SLOT_BITS) as BucketId,
        )
    };

    let start_key = SaltKey::from((bucket_id, slot_start));
    let end_key = SaltKey::from((bucket_id, slot_start + POLY_DEGREE as SlotId - 1));

    let entries = store.entries(start_key..=end_key).map_err(|e| {
        ProofError::StateReadError {
            reason: format!(
                "Failed to load bucket entries for bucket {bucket_id}, slots {slot_start}-{}: {e:?}",
                slot_start + POLY_DEGREE as SlotId - 1
            ),
        }
    })?;

    // Initialize polynomial coefficients with appropriate default values
    let mut default_coefficients = if bucket_id < NUM_META_BUCKETS as BucketId {
        // Metadata buckets: initialize with default metadata hash
        vec![slot_to_field(&Some(BucketMeta::default().into())); POLY_DEGREE]
    } else {
        // Data buckets: initialize with empty slot hash
        vec![slot_to_field(&None); POLY_DEGREE]
    };

    // Replace default values with actual key-value hashes where data exists
    for (key, value) in entries {
        // Map slot ID to polynomial coefficient index (last 8 bits)
        let index = (key.slot_id() & SLOT_INDEX_MASK) as usize;
        default_coefficients[index] = slot_to_field(&Some(value));
    }

    // Create IPA prover queries for the specified evaluation points
    Ok(create_prover_queries(
        parent_commitment,
        LagrangeBasis::new(default_coefficients),
        points,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proof::test_utils::*;
    use crate::{
        mem_store::MemStore, proof::prover::PRECOMPUTED_WEIGHTS, state::state::EphemeralSaltState,
        trie::trie::StateRoot,
    };
    use ark_ff::BigInt;
    use banderwagon::{Fr, Zero};
    use ipa_multipoint::{crs::CRS, multiproof::MultiPoint, transcript::Transcript};
    use rand::{rngs::StdRng, SeedableRng};
    use std::collections::HashMap;

    fn setup_test_store() -> (MemStore, SaltKey) {
        let mut rng = StdRng::seed_from_u64(42);
        let key = mock_data(&mut rng, 52);
        let value = mock_data(&mut rng, 32);
        let kvs = HashMap::from([(key, Some(value))]);

        let store = MemStore::new();
        let mut state = EphemeralSaltState::new(&store);
        let updates = state.update(&kvs).unwrap();
        store.update_state(updates.clone());

        let mut trie = StateRoot::new(&store);
        let (_, trie_updates) = trie.update_fin(updates.clone()).unwrap();
        store.update_trie(trie_updates);

        (store, *updates.data.keys().next().unwrap())
    }

    fn verify_ipa_proof(queries: Vec<ProverQuery>) -> bool {
        let crs = CRS::default();
        let proof = MultiPoint::open(
            crs.clone(),
            &PRECOMPUTED_WEIGHTS,
            &mut Transcript::new(b"st"),
            queries.clone(),
        );
        proof.check(
            &crs,
            &PRECOMPUTED_WEIGHTS,
            &queries.into_iter().map(Into::into).collect::<Vec<_>>(),
            &mut Transcript::new(b"st"),
        )
    }

    #[test]
    fn create_sub_trie_generates_valid_proofs() {
        let (store, salt_key) = setup_test_store();
        let (prover_queries, _, _) = create_sub_trie(&store, &[salt_key]).unwrap();
        assert!(verify_ipa_proof(prover_queries));
    }

    #[test]
    fn lagrange_polynomial_proof_verification() {
        let crs = CRS::default();
        let mut coeffs = vec![Fr::zero(); 256];
        coeffs[0] = Fr::from(BigInt([
            14950088112150747174,
            13253162737298189682,
            10931921008236264693,
            1309984686389044416,
        ]));
        coeffs[208] = Fr::from(BigInt([
            9954869294274886320,
            8441215309276124103,
            16970925962995195932,
            2055721457450359655,
        ]));

        let poly = LagrangeBasis::new(coeffs);
        let query = ProverQuery {
            commitment: crs.commit_lagrange_poly(&poly),
            poly: poly.clone(),
            point: 208,
            result: poly.evaluate_in_domain(208),
        };

        let proof = MultiPoint::open(
            crs.clone(),
            &PRECOMPUTED_WEIGHTS,
            &mut Transcript::new(b"st"),
            vec![query.clone()],
        );
        assert!(proof.check(
            &crs,
            &PRECOMPUTED_WEIGHTS,
            &[query.into()],
            &mut Transcript::new(b"st")
        ));
    }

    #[test]
    fn create_sub_trie_scenarios() {
        let (store, salt_key) = setup_test_store();

        // Single key
        let (q1, _, _) = create_sub_trie(&store, &[salt_key]).unwrap();
        assert!(verify_ipa_proof(q1.clone()));

        // Multiple keys
        let (q2, _, _) = create_sub_trie(
            &store,
            &[
                salt_key,
                SaltKey::from((salt_key.bucket_id(), salt_key.slot_id() + 1)),
            ],
        )
        .unwrap();
        assert!(verify_ipa_proof(q2));

        // Duplicate keys
        let (q3, _, _) = create_sub_trie(&store, &[salt_key, salt_key]).unwrap();
        assert_eq!(q1.len(), q3.len());

        // Metadata bucket
        let (q4, _, b4) = create_sub_trie(&store, &[SaltKey::from((0u32, 0u64))]).unwrap();
        assert!(verify_ipa_proof(q4));
        assert_eq!(b4[&0], 1);

        // Empty input
        let res = create_sub_trie(&store, &[]);
        assert!(res.is_err());
    }

    #[test]
    fn process_leaf_node_with_real_commitment() {
        let (store, salt_key) = setup_test_store();
        let parent_node = STARTING_NODE_ID[3] as NodeId + salt_key.bucket_id() as u64;
        let commitment =
            Element::from_bytes_unchecked_uncompressed(store.commitment(parent_node).unwrap());
        let points = [0, salt_key.slot_id() as usize & 0xff].into();

        let queries = process_leaf_node(&store, parent_node, commitment, points).unwrap();
        assert_eq!(queries.len(), 2);
        assert!(verify_ipa_proof(queries));
    }

    #[test]
    fn multi_commitments_to_scalars_empty_and_single_node() {
        let store = MemStore::new();

        // Empty input
        assert_eq!(multi_commitments_to_scalars(&store, &[]).unwrap().len(), 0);

        // Single internal node
        let node_points = vec![(STARTING_NODE_ID[2] as NodeId, [0, 1].into())];
        let scalars = multi_commitments_to_scalars(&store, &node_points).unwrap();
        assert_eq!(scalars.len(), POLY_DEGREE);
    }
}
