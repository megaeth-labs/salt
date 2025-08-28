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
pub use witness::SaltWitness;

/// Error type for proof operations
#[derive(Debug, Error)]
pub enum ProofError {
    /// Failed to read state data during proof operations
    #[error("failed to read state: {reason}")]
    StateReadError { reason: String },

    /// Root commitment is missing from proof
    #[error("missing root commitment in proof")]
    MissingRootCommitment,

    /// State root mismatch during verification
    #[error("state root mismatch: expected {expected:?}, got {actual:?}")]
    RootMismatch {
        expected: [u8; 32],
        actual: [u8; 32],
    },

    /// Multi-point proof verification failed
    #[error("multi-point proof check failed")]
    MultiPointProofFailed,

    /// Key mapping verification failed during proof validation
    #[error("invalid key mapping: {reason}")]
    InvalidKeyMapping { reason: String },
}
