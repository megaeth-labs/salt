//! Prover for the Salt proof
use crate::{
    constant::TRIE_WIDTH,
    proof::{subtrie::create_sub_trie, verifier, ProofError},
    traits::{StateReader, TrieReader},
    types::{hash_commitment, CommitmentBytes, NodeId, SaltKey, SaltValue},
    BucketId, ScalarBytes,
};
use banderwagon::{Element, Fr, PrimeField};
use ipa_multipoint::{
    crs::CRS,
    lagrange_basis::PrecomputedWeights,
    multiproof::{MultiPoint, MultiPointProof},
    transcript::Transcript,
};
use once_cell::sync::Lazy;
use rayon::prelude::*;
use rustc_hash::FxHashMap;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::collections::BTreeMap;

/// Create a new CRS.
pub static PRECOMPUTED_WEIGHTS: Lazy<PrecomputedWeights> =
    Lazy::new(|| PrecomputedWeights::new(TRIE_WIDTH));

/// Wrapper of `CommitmentBytes` for serialization.
#[derive(Clone, Debug, Eq, Serialize, Deserialize)]
pub struct CommitmentBytesW(
    #[serde(serialize_with = "serialize_commitment")]
    #[serde(deserialize_with = "deserialize_commitment")]
    pub CommitmentBytes,
);

impl PartialEq for CommitmentBytesW {
    fn eq(&self, other: &Self) -> bool {
        Element::from_bytes_unchecked_uncompressed(self.0)
            == Element::from_bytes_unchecked_uncompressed(other.0)
    }
}

/// Salt proof.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SaltProof {
    /// the node id of nodes in the path => node commitment
    pub parents_commitments: BTreeMap<NodeId, CommitmentBytesW>,

    /// the IPA proof
    #[serde(serialize_with = "serialize_multipoint_proof")]
    #[serde(deserialize_with = "deserialize_multipoint_proof")]
    pub proof: MultiPointProof,

    /// the top level of the buckets trie
    /// used to let verifier determine the bucket trie level
    pub buckets_top_level: FxHashMap<BucketId, u8>,
}

fn serialize_multipoint_proof<S>(proof: &MultiPointProof, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    let bytes = proof
        .to_bytes()
        .map_err(|e| serde::ser::Error::custom(e.to_string()))?;
    bytes.serialize(serializer)
}

fn deserialize_multipoint_proof<'de, D>(deserializer: D) -> Result<MultiPointProof, D::Error>
where
    D: Deserializer<'de>,
{
    let bytes = Vec::<u8>::deserialize(deserializer)?;
    MultiPointProof::from_bytes(&bytes, crate::constant::POLY_DEGREE)
        .map_err(|e| serde::de::Error::custom(e.to_string()))
}

fn serialize_commitment<S>(commitment: &CommitmentBytes, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    let element = Element::from_bytes_unchecked_uncompressed(*commitment);
    let bytes = element.to_bytes();

    bytes.serialize(serializer)
}

fn deserialize_commitment<'de, D>(deserializer: D) -> Result<CommitmentBytes, D::Error>
where
    D: Deserializer<'de>,
{
    let bytes: [u8; 32] = <[u8; 32]>::deserialize(deserializer)?;
    let element = Element::from_bytes(&bytes)
        .ok_or_else(|| serde::de::Error::custom("from_bytes to an element is none"))?;

    Ok(element.to_bytes_uncompressed())
}

/// Calculate the hash value of the key-value pair.
#[inline(always)]
pub(crate) fn calculate_fr_by_kv(entry: &SaltValue) -> Fr {
    let mut data = blake3::Hasher::new();
    data.update(entry.key());
    data.update(entry.value());
    Fr::from_le_bytes_mod_order(data.finalize().as_bytes())
}

impl SaltProof {
    /// Create a new proof.
    pub fn create<Store, I>(keys: I, store: &Store) -> Result<SaltProof, ProofError>
    where
        I: IntoIterator<Item = SaltKey>,
        Store: StateReader + TrieReader,
    {
        let mut keys: Vec<_> = keys.into_iter().collect();
        if keys.is_empty() {
            return Err(ProofError::ProveFailed("empty key set".to_string()));
        }
        // Check if the array is already sorted - returns true if sorted, false otherwise
        // Using any() to find the first out-of-order pair for efficiency
        let needs_sorting = keys.windows(2).any(|w| w[0] > w[1]);

        if needs_sorting {
            keys.par_sort_unstable();
        }
        keys.dedup();

        let (prover_queries, parents_commitments, buckets_top_level) =
            create_sub_trie(store, &keys)?;

        let crs = CRS::default();

        let mut transcript = Transcript::new(b"st");

        let proof = MultiPoint::open(crs, &PRECOMPUTED_WEIGHTS, &mut transcript, prover_queries);

        Ok(SaltProof {
            parents_commitments,
            proof,
            buckets_top_level,
        })
    }

    /// Check if the proof is valid.
    pub fn check(
        &self,
        data: &BTreeMap<SaltKey, Option<SaltValue>>,
        state_root: ScalarBytes,
    ) -> Result<(), ProofError> {
        if data.is_empty() {
            return Err(ProofError::VerifyFailed("empty key set".to_string()));
        }

        let kvs: Vec<_> = data.iter().map(|(&k, v)| (k, v.clone())).collect();

        let queries = verifier::create_verifier_queries(
            &self.parents_commitments,
            kvs,
            &self.buckets_top_level,
        )?;

        let root = self
            .parents_commitments
            .get(&0)
            .ok_or(ProofError::VerifyFailed(
                "lack of root commitment".to_string(),
            ))?;

        let trie_root = hash_commitment(root.0);

        if state_root != trie_root {
            return Err(ProofError::VerifyFailed(format!(
                "state root not match, expect: {trie_root:?}, got: {state_root:?}"
            )));
        }

        let mut transcript = Transcript::new(b"st");

        let crs = CRS::default();

        // call MultiPointProof::check to verify the proof
        if self
            .proof
            .check(&crs, &PRECOMPUTED_WEIGHTS, &queries, &mut transcript)
        {
            Ok(())
        } else {
            Err(ProofError::VerifyFailed(
                "multi pointproof check failed".to_string(),
            ))
        }
    }
}
