//! Prover for the Salt proof
use crate::{
    constant::{BUCKET_SLOT_ID_MASK, DOMAIN_SIZE, STARTING_NODE_ID},
    proof::{
        shape::{connect_parent_id, logic_parent_id, parents_and_points},
        subtrie::create_sub_trie,
        ProofError, ProofResult,
    },
    traits::{StateReader, TrieReader},
    trie::{
        node_utils::{get_child_node, subtree_leaf_start_key},
        trie::kv_hash,
    },
    types::{hash_commitment, CommitmentBytes, NodeId, SaltKey, SaltValue},
    BucketId, ScalarBytes,
};
use banderwagon::{Element, Fr};
use ipa_multipoint::{
    crs::CRS,
    lagrange_basis::PrecomputedWeights,
    multiproof::{MultiPoint, MultiPointProof, VerifierQuery},
    transcript::Transcript,
};
use once_cell::sync::Lazy;
use rayon::prelude::*;
use rustc_hash::FxHashMap;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::collections::{BTreeMap, BTreeSet};

/// Create a new CRS.
pub static PRECOMPUTED_WEIGHTS: Lazy<PrecomputedWeights> =
    Lazy::new(|| PrecomputedWeights::new(DOMAIN_SIZE));

/// Serde wrapper for banderwagon `Element` with validation and compression.
///
/// This type ensures security by validating elements during deserialization
/// via `Element::from_bytes()`. Once validated, the `Element` is stored directly,
/// enabling efficient operations without repeated validation.
///
/// Serialization compresses the 64-byte uncompressed format to 32 bytes for
/// storage/transmission.
#[derive(Clone, Debug, PartialEq)]
pub struct SerdeCommitment(pub(crate) Element);

impl SerdeCommitment {
    /// Returns the commitment as a 64-byte uncompressed representation.
    ///
    /// This is used when interfacing with code that expects `CommitmentBytes`.
    pub fn as_bytes(&self) -> CommitmentBytes {
        self.0.to_bytes_uncompressed()
    }
}

impl Serialize for SerdeCommitment {
    /// Serializes the commitment from uncompressed (64-byte) to compressed (32-byte) format.
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.0.to_bytes().serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for SerdeCommitment {
    /// Deserializes from compressed (32-byte) format and validates the element.
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let bytes = <[u8; 32]>::deserialize(deserializer)?;
        Element::from_bytes(bytes)
            .map(Self)
            .map_err(|_| serde::de::Error::custom("invalid element bytes"))
    }
}

/// Serde wrapper for `MultiPointProof`.
#[derive(Debug, Clone, PartialEq)]
pub struct SerdeMultiPointProof(pub MultiPointProof);

impl Serialize for SerdeMultiPointProof {
    /// Serializes the MultiPointProof to its byte representation.
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.0
            .to_bytes()
            .map_err(|e| serde::ser::Error::custom(e.to_string()))?
            .serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for SerdeMultiPointProof {
    /// Deserializes from bytes back to MultiPointProof with the configured polynomial degree.
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let bytes = Vec::<u8>::deserialize(deserializer)?;
        MultiPointProof::from_bytes(&bytes, DOMAIN_SIZE)
            .map(SerdeMultiPointProof)
            .map_err(|e| serde::de::Error::custom(e.to_string()))
    }
}

/// Salt proof.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SaltProof {
    /// the node id of nodes in the path => node commitment
    pub parents_commitments: BTreeMap<NodeId, SerdeCommitment>,

    /// the IPA proof
    pub proof: SerdeMultiPointProof,

    /// the level of the buckets trie
    /// used to let verifier determine the bucket trie level
    pub levels: FxHashMap<BucketId, u8>,
}

/// Converts a bucket slot entry into a field element for IPA polynomial commitments.
///
/// This function maps key-value pairs (or empty slots) to field elements that serve
/// as polynomial evaluations in SALT's proof system.
///
/// # Arguments
/// * `entry` - Optional key-value pair from a bucket slot
///
/// # Returns
/// A field element (`Fr`) in the Banderwagon scalar field suitable for IPA polynomial
/// commitment schemes.
#[inline(always)]
pub(crate) fn slot_to_field(entry: &Option<SaltValue>) -> Fr {
    kv_hash(entry)
}

impl SaltProof {
    /// Create a new proof.
    pub fn create<Store, I>(keys: I, store: &Store) -> Result<SaltProof, ProofError>
    where
        I: IntoIterator<Item = SaltKey>,
        Store: StateReader + TrieReader,
    {
        let mut keys: Vec<_> = keys.into_iter().collect();
        // Check if the array is already sorted - returns true if sorted, false otherwise
        // Using any() to find the first out-of-order pair for efficiency
        let needs_sorting = keys.windows(2).any(|w| w[0] > w[1]);

        if needs_sorting {
            keys.par_sort_unstable();
        }
        keys.dedup();

        let (prover_queries, parents_commitments, levels) = create_sub_trie(store, &keys)?;

        let crs = CRS::default();

        let mut transcript = Transcript::new(b"st");

        let proof = MultiPoint::open(crs, &PRECOMPUTED_WEIGHTS, &mut transcript, prover_queries);

        Ok(SaltProof {
            parents_commitments,
            proof: SerdeMultiPointProof(proof),
            levels,
        })
    }

    /// Check if the proof is valid.
    pub fn check(
        &self,
        data: &BTreeMap<SaltKey, Option<SaltValue>>,
        state_root: ScalarBytes,
    ) -> Result<(), ProofError> {
        let queries = self.create_verifier_queries(data)?;

        let root = self
            .parents_commitments
            .get(&0)
            .ok_or(ProofError::MissingRootCommitment)?;

        let trie_root = hash_commitment(root.as_bytes());

        if state_root != trie_root {
            return Err(ProofError::RootMismatch {
                expected: trie_root,
                actual: state_root,
            });
        }

        let mut transcript = Transcript::new(b"st");

        let crs = CRS::default();

        // call MultiPointProof::check to verify the proof
        if self
            .proof
            .0
            .check(&crs, &PRECOMPUTED_WEIGHTS, &queries, &mut transcript)
        {
            Ok(())
        } else {
            Err(ProofError::MultiPointProofFailed)
        }
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
        &self,
        kvs: &BTreeMap<SaltKey, Option<SaltValue>>,
    ) -> ProofResult<Vec<VerifierQuery>> {
        if kvs.is_empty() {
            return Err(ProofError::StateReadError {
                reason: "kvs is empty".to_string(),
            });
        }

        // Validates that bucket level information in the proof matches the queried keys.
        let bucket_ids_from_keys: BTreeSet<_> = kvs.keys().map(|k| k.bucket_id()).collect();

        let bucket_ids_from_proof: BTreeSet<_> = self.levels.keys().copied().collect();

        if bucket_ids_from_proof != bucket_ids_from_keys {
            return Err(ProofError::StateReadError {
                reason: "buckets_top_level in proof contains unknown bucket level info".to_string(),
            });
        }

        // Analyze the SALT tree structure to determine which parent nodes need verification
        // and what evaluation points (child indices or slot positions) are required
        let keys_to_verify: Vec<_> = kvs.keys().copied().collect();
        let (internal_nodes, leaf_nodes) = parents_and_points(&keys_to_verify, &self.levels);

        // Convert logical parent IDs to their commitment storage IDs and validate
        let required_node_ids: BTreeSet<_> = internal_nodes
            .keys()
            .chain(leaf_nodes.keys())
            .map(|node_id| connect_parent_id(*node_id))
            .collect();

        // Validates that the proof contains and ONLY contains commitments for all required nodes, .
        let proof_node_ids: BTreeSet<_> = self.parents_commitments.keys().copied().collect();
        if proof_node_ids != required_node_ids {
            return Err(ProofError::StateReadError {
                reason: "path_commitments in proof contains unknown node commitment".to_string(),
            });
        }

        let internal_queries =
            create_internal_node_queries(&internal_nodes, &self.parents_commitments)?;
        let leaf_queries = create_leaf_node_queries(&leaf_nodes, &self.parents_commitments, kvs)?;

        let mut queries = internal_queries;
        queries.extend(leaf_queries);

        Ok(queries)
    }
}

/// Safely retrieves a commitment from the proof, returning an error when the commitment is missing.
fn get_commitment_safe(
    path_commitments: &BTreeMap<NodeId, SerdeCommitment>,
    node_id: NodeId,
) -> ProofResult<Element> {
    path_commitments
        .get(&node_id)
        .map(|c| c.0)
        .ok_or_else(|| ProofError::StateReadError {
            reason: format!("Missing commitment for node ID {node_id}"),
        })
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
            let children_frs = Element::batch_map_to_scalar_field(&children_commitments);
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
/// Tuple of (child_node_ids, child_commitments) ready for batch field conversion
fn children_commitments_to_scalars(
    nodes: &[(&NodeId, &BTreeSet<usize>)],
    path_commitments: &BTreeMap<NodeId, SerdeCommitment>,
) -> ProofResult<(Vec<NodeId>, Vec<Element>)> {
    // Flatten nested structure: parent_nodes → child_indices → (child_id, commitment)
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
                        // Extract Element from SerdeCommitment
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
    use crate::proof::test_utils::*;
    use crate::{
        bucket_id_from_metadata_key, bucket_metadata_key,
        constant::{
            default_commitment, EMPTY_SLOT_HASH, MIN_BUCKET_SIZE, MIN_BUCKET_SIZE_BITS,
            NUM_META_BUCKETS, STARTING_NODE_ID,
        },
        empty_salt::EmptySalt,
        hasher::tests::get_same_bucket_test_keys,
        mem_store::MemStore,
        state::{state::EphemeralSaltState, updates::StateUpdates},
        trie::trie::StateRoot,
        types::SlotId,
        BucketMeta,
    };
    use banderwagon::{CanonicalSerialize, PrimeField};
    use ipa_multipoint::lagrange_basis::LagrangeBasis;
    use rand::{rngs::StdRng, SeedableRng};
    use std::collections::HashMap;

    fn fr_to_le_bytes(fr: Fr) -> [u8; 32] {
        let mut bytes = [0u8; 32];
        fr.serialize_compressed(&mut bytes[..])
            .expect("Failed to serialize scalar to bytes");
        bytes
    }

    const KV_BUCKET_OFFSET: NodeId = NUM_META_BUCKETS as NodeId;

    /// Tests proof generation and verification for an empty trie.
    /// Manually computes commitments at each trie level (L0-L4) and verifies
    /// they match the expected default values. Then creates a proof for a
    /// metadata key and verifies it against the computed empty root.
    #[test]
    fn test_empty_trie_proof() {
        let salt = EmptySalt;

        let salt_key: SaltKey = (0, 0).into();
        let first_data_bucket_id = 131329;
        let default_fr = Fr::from_le_bytes_mod_order(&EMPTY_SLOT_HASH);

        let crs = CRS::default();

        let meta_bucket_fr = slot_to_field(&Some(BucketMeta::default().into()));
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

        let proof = SaltProof::create([salt_key], &salt).unwrap();

        let value = salt
            .metadata(bucket_id_from_metadata_key(salt_key))
            .unwrap();

        let res = proof.check(&[(salt_key, Some(value.into()))].into(), empty_root);

        assert!(res.is_ok());
    }

    /// Tests basic proof creation and verification for a single key-value pair.
    /// Inserts one storage value into the trie, generates a proof for it,
    /// and verifies the proof matches the trie root.
    #[test]
    fn test_basic_proof_exist() {
        let mut rng = StdRng::seed_from_u64(42);

        let key = mock_data(&mut rng, 52);
        let value = mock_data(&mut rng, 32);

        let initial_key_values = HashMap::from([(key, Some(value))]);

        let mem_store = MemStore::new();
        let mut state = EphemeralSaltState::new(&mem_store);
        let updates = state.update_fin(&initial_key_values).unwrap();
        mem_store.update_state(updates.clone());

        let mut trie = StateRoot::new(&mem_store);
        let (trie_root, trie_updates) = trie.update_fin(&updates).unwrap();
        mem_store.update_trie(trie_updates);

        let salt_key = *updates.data.keys().next().unwrap();
        let value = mem_store.value(salt_key).unwrap();

        let proof = SaltProof::create([salt_key], &mem_store).unwrap();

        let res = proof.check(&[(salt_key, value)].into(), trie_root);
        assert!(res.is_ok());
    }

    /// Verifies that the trie root commitment correctly corresponds to the scalar field.
    /// After inserting a single key-value pair, checks that converting the root
    /// commitment to scalar field and back yields the same trie root.
    #[test]
    fn test_single_insert_commmitment() {
        let mut rng = StdRng::seed_from_u64(42);

        let key = mock_data(&mut rng, 52);
        let value = mock_data(&mut rng, 32);

        let initial_key_values = HashMap::from([(key, Some(value))]);

        let mem_store = MemStore::new();
        let mut state = EphemeralSaltState::new(&mem_store);
        let updates = state.update_fin(&initial_key_values).unwrap();

        mem_store.update_state(updates.clone());

        let mut trie = StateRoot::new(&mem_store);
        let (trie_root, trie_updates) = trie.update_fin(&updates).unwrap();

        mem_store.update_trie(trie_updates);

        let trie_root_commitment = mem_store.commitment(0).unwrap();

        let root_from_commitment = fr_to_le_bytes(
            Element::from_bytes_unchecked_uncompressed(trie_root_commitment).map_to_scalar_field(),
        );

        assert_eq!(trie_root.as_slice(), &root_from_commitment);
    }

    /// Tests proof generation with a large number of key-value pairs.
    /// Inserts 1000 random key-value pairs, then generates a proof that includes
    /// both existing keys and non-existent keys. Verifies that existing keys
    /// return their values and non-existent keys return None.
    #[test]
    fn test_multi_insert_proof() {
        let mut rng = StdRng::seed_from_u64(42);

        let initial_kvs = (0..1000)
            .map(|_| {
                let k = mock_data(&mut rng, 52);
                let v = mock_data(&mut rng, 32);
                (k, Some(v))
            })
            .collect::<HashMap<_, _>>();

        let mem_store = MemStore::new();
        let mut state = EphemeralSaltState::new(&mem_store);
        let updates = state.update_fin(&initial_kvs).unwrap();

        mem_store.update_state(updates.clone());

        let mut trie = StateRoot::new(&mem_store);
        let (trie_root, trie_updates) = trie.update_fin(&updates).unwrap();

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

        let proof = SaltProof::create(salt_keys.iter().copied(), &mem_store).unwrap();

        let data: BTreeMap<_, _> = salt_keys.into_iter().zip(values).collect();
        let res = proof.check(&data, trie_root);

        assert!(res.is_ok());
    }

    #[test]
    fn test_empty_input() {
        let store = MemStore::new();

        let proof_res = SaltProof::create([], &store);

        assert!(proof_res.is_err());

        let proof = SaltProof::create([SaltKey::from((100, 42))], &store).unwrap();
        let (root, _) = StateRoot::rebuild(&store).unwrap();

        let res = proof.check(&Default::default(), root);
        assert!(res.is_err())
    }

    /// Tests proof generation during bucket capacity expansion.
    /// Initializes a trie with a single value, expands the bucket from default
    /// capacity (256) to 65536, and verifies that:
    /// - Commitments at various subtrie levels remain correct
    /// - Proofs for non-existent keys in the expanded bucket verify correctly
    #[test]
    fn salt_proof_in_bucket_expansion() {
        let store = MemStore::new();
        let mut trie = StateRoot::new(&store);
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
            trie.update_fin(&initialize_state_updates).unwrap();
        store.update_state(initialize_state_updates);
        store.update_trie(initialize_trie_updates.clone());

        let (root, mut init_trie_updates) = StateRoot::rebuild(&store).unwrap();
        init_trie_updates.sort_unstable_by(|(a, _), (b, _)| b.cmp(a));
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
        let (expansion_root, trie_updates) = trie.update_fin(&expand_state_updates).unwrap();
        store.update_state(expand_state_updates);

        store.update_trie(trie_updates);

        let (root, _) = StateRoot::rebuild(&store).unwrap();
        assert_eq!(root, expansion_root);

        let crs = CRS::default();
        let default_fr = Fr::from_le_bytes_mod_order(&EMPTY_SLOT_HASH);
        let mut sub_bucket_frs = vec![default_fr; 256];
        sub_bucket_frs[3] = slot_to_field(&Some(salt_value));
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
        let proof = SaltProof::create([SaltKey::from((bid, 2049))], &store).unwrap();

        let res = proof.check(&[(SaltKey::from((bid, 2049)), None)].into(), expansion_root);

        assert!(res.is_ok());
    }

    /// Tests proof correctness through multiple bucket capacity expansions.
    /// Performs two expansions (256 → 524288 → 536870912) while adding
    /// new key-value pairs at each stage. Verifies that proofs remain valid
    /// for both existing and non-existing keys throughout all expansion stages.
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
        let mut trie = StateRoot::new(&store);
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
            trie.update_fin(&initialize_state_updates).unwrap();
        store.update_state(initialize_state_updates);
        store.update_trie(initialize_trie_updates.clone());
        let (root, mut init_trie_updates) = StateRoot::rebuild(&store).unwrap();
        init_trie_updates.sort_unstable_by(|(a, _), (b, _)| b.cmp(a));
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
        let (expansion_root, trie_updates) = trie.update_fin(&expand_state_updates).unwrap();
        store.update_state(expand_state_updates);
        store.update_trie(trie_updates);
        let (root, _) = StateRoot::rebuild(&store).unwrap();
        assert_eq!(root, expansion_root);

        let proof = SaltProof::create(
            [
                (bid, 3).into(),
                (bid, 5).into(),
                (bid, 2049).into(),
                (bid, new_capacity - 1).into(),
            ],
            &store,
        )
        .unwrap();

        let res = proof.check(
            &[
                ((bid, 3).into(), Some(SaltValue::new(&[1; 32], &[1; 32]))),
                ((bid, 5).into(), Some(SaltValue::new(&[2; 32], &[2; 32]))),
                ((bid, 2049).into(), Some(SaltValue::new(&[3; 32], &[3; 32]))),
                ((bid, new_capacity - 1).into(), None),
            ]
            .into(),
            expansion_root,
        );

        assert!(res.is_ok());

        // expand capacity and add kvs
        let new_capacity2 = 256 * 256 * 256 * 32;

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
        let (expansion_root, trie_updates) = trie.update_fin(&expand_state_updates).unwrap();
        store.update_state(expand_state_updates);
        store.update_trie(trie_updates);
        let (root, _) = StateRoot::rebuild(&store).unwrap();
        assert_eq!(root, expansion_root);

        let proof = SaltProof::create(
            [
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
            &[
                ((bid, 3).into(), Some(SaltValue::new(&[1; 32], &[1; 32]))),
                ((bid, 5).into(), Some(SaltValue::new(&[2; 32], &[2; 32]))),
                ((bid, 2049).into(), Some(SaltValue::new(&[3; 32], &[3; 32]))),
                ((bid, 256 * 256 * 256).into(), None),
                ((bid, new_capacity - 1).into(), None),
                (
                    (bid, new_capacity2 - 255).into(),
                    Some(SaltValue::new(&[255; 32], &[255; 32])),
                ),
                ((bid, new_capacity2 - 1).into(), None),
            ]
            .into(),
            expansion_root,
        );

        assert!(res.is_ok());
    }

    /// Tests proof generation and verification when automatic bucket expansion occurs.
    #[test]
    fn test_proof_in_auto_bucket_expansion() {
        let store = MemStore::new();
        let mut state = EphemeralSaltState::new(&store);

        // Use 260 keys that hash to same bucket - triggering expansion
        let kvs = get_same_bucket_test_keys()
            .iter()
            .enumerate()
            .take(260)
            .map(|(i, key)| (key.clone(), Some(i.to_be_bytes().to_vec())))
            .collect::<HashMap<Vec<u8>, Option<Vec<u8>>>>();

        // Update state and trie with expanded bucket
        let state_updates = state.update_fin(&kvs).unwrap();
        store.update_state(state_updates.clone());

        let (root_hash, trie_updates) = StateRoot::new(&store).update_fin(&state_updates).unwrap();
        store.update_trie(trie_updates);

        // Prepare data for proof verification
        let data = state_updates
            .data
            .iter()
            .map(|(key, (_, new))| (*key, new.clone()))
            .collect::<BTreeMap<_, _>>();

        // Create and verify proof works correctly after automatic expansion
        let proof = SaltProof::create(state_updates.data.keys().copied(), &store).unwrap();

        assert!(proof.check(&data, root_hash).is_ok());
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
        let proof = SaltProof::create([SaltKey::from((100, 0))], &MemStore::new()).unwrap();
        // Setup: All inputs empty
        let result = proof.create_verifier_queries(&BTreeMap::new());

        // Should return error
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

        let proof = SaltProof::create([SaltKey::from((100, 0))], &MemStore::new()).unwrap();

        let result = proof.create_verifier_queries(&kvs);
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
