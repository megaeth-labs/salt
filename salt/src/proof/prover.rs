//! Prover for the Salt proof
use crate::{
    constant::TRIE_WIDTH,
    proof::{subtrie::create_sub_trie, ProofError, SaltProof},
    traits::{StateReader, TrieReader},
    types::SaltKey,
};
use ipa_multipoint::{
    crs::CRS, lagrange_basis::PrecomputedWeights, multiproof::MultiPoint, transcript::Transcript,
};
use once_cell::sync::Lazy;
use rayon::prelude::*;

/// Create a new CRS.
pub static PRECOMPUTED_WEIGHTS: Lazy<PrecomputedWeights> =
    Lazy::new(|| PrecomputedWeights::new(TRIE_WIDTH));

/// Create a new proof.
pub fn create_salt_proof<Store>(keys: &[SaltKey], store: &Store) -> Result<SaltProof, ProofError>
where
    Store: StateReader + TrieReader,
{
    if keys.is_empty() {
        return Err(ProofError::ProveFailed("empty key set".to_string()));
    }

    let mut keys = keys.to_vec();
    // Check if the array is already sorted - returns true if sorted, false otherwise
    // Using any() to find the first out-of-order pair for efficiency
    let needs_sorting = keys.windows(2).any(|w| w[0] > w[1]);

    if needs_sorting {
        keys.par_sort_unstable();
    }
    keys.dedup();

    let (prover_queries, parents_commitments, buckets_top_level) = create_sub_trie(store, &keys)?;

    let crs = CRS::default();

    let mut transcript = Transcript::new(b"st");

    let proof = MultiPoint::open(crs, &PRECOMPUTED_WEIGHTS, &mut transcript, prover_queries);

    Ok(SaltProof {
        parents_commitments,
        proof,
        buckets_top_level,
    })
}
