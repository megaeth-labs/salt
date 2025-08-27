//! This module is the implementation of generating and verifying proofs of SALT.
use thiserror::Error;

pub mod plain_keys_proof;
pub mod prover;
pub mod shape;
pub mod subtrie;
pub mod verifier;
pub mod witness;

pub use plain_keys_proof::PlainKeysProof;
pub use prover::{CommitmentBytesW, SaltProof};
pub use witness::BlockWitness;

/// Error type for proof.
#[derive(Debug, Error)]
pub enum ProofError {
    /// Prove error
    #[error("prove failed: {0}")]
    ProveFailed(String),
    /// Verify error
    #[error("verify failed: {0}")]
    VerifyFailed(String),
}
