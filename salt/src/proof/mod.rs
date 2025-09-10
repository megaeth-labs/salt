//! Cryptographic proof system for SALT's authenticated key-value store.
//!
//! This module implements a sophisticated proof system that provides compact
//! cryptographic proofs for both the existence (membership) and non-existence
//! (non-membership) of keys - allowing light clients and stateless validators
//! to efficiently verify state without storing the full trie.
//!
//! at most 9 levels total even with bucket expansion,
//! enabling compact proofs and efficient verification.
//!
//! # Architecture Overview
//!
//! SALT uses a unified proof structure throughout its entire trie, from root to leaves.
//! Every node in the system - whether in the main trie or within bucket subtrees - uses
//! the same 256-ary vector commitment scheme based on IPA (Inner Product Argument) with
//! Pedersen commitments.
//!
//! ## Unified Proof Structure
//! All internal nodes commit to exactly 256 children using the same cryptographic mechanism:
//! - Each node's commitment is computed as a vector commitment over 256 field elements
//! - These elements represent either child node commitments (for internal nodes) or
//!   hashed key-value pairs (for leaf nodes containing actual data)
//!
//! ## Trie Organization
//! While the proof structure is uniform, the trie has two logical regions:
//! - **Main Trie**: A static, 4-level complete 256-ary tree with 16,777,216 leaf nodes.
//!   These leaves contain commitments to buckets rather than direct data.
//! - **Bucket Subtrees**: Dynamic trees that grow as needed. Buckets are Strongly
//!   History-Independent (SHI) hash tables where the actual key-value pairs reside.
//!   Large buckets expand into their own 256-ary subtrees.
//!
//! The authentication path from any key to the root follows the same pattern regardless
//! of whether it passes through main trie nodes or bucket subtree nodes.
//!
//! # Proof Types
//!
//! ## Membership Proofs
//! Prove a key exists by providing:
//! - The bucket slot containing the key-value pair
//! - The authentication path from bucket to root
//! - IPA proof for the bucket's vector commitment
//!
//! ## Non-Membership Proofs
//! Prove a key doesn't exist by demonstrating it's absent from its probe sequence:
//! - Include all slots in the linear probe sequence
//! - Terminate at an empty slot or lexicographically smaller key
//! - Leverage SHI's ordering invariant for completeness
//!
//! # Submodules
//!
//! - [`prover`]: Core proof generation logic, including IPA multi-point proofs and
//!   commitment serialization. Handles the cryptographic heavy lifting for creating proofs.
//!
//! - [`salt_witness`]: Low-level witness structure containing authenticated state subsets
//!   with cryptographic proofs. Enforces security properties against state manipulation.
//!
//! - [`witness`]: High-level witness abstraction for plain (user-provided) keys. Provides
//!   a user-friendly interface over `SaltWitness` for stateless validation and execution.
//!
//! - [`shape`]: Utilities for analyzing SALT's hierarchical structure to determine minimal
//!   parent-child relationships needed for proof generation.
//!
//! - [`subtrie`]: Constructs minimal subtries and generates IPA proofs by building
//!   authentication paths from specified keys to the state root.

use thiserror::Error;

pub mod prover;
pub mod salt_witness;
pub mod shape;
pub mod subtrie;
pub mod witness;

#[cfg(test)]
mod test_utils;

pub use prover::{SaltProof, SerdeCommitment, SerdeMultiPointProof};
pub use salt_witness::SaltWitness;
pub use witness::Witness;

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

    /// Direct lookup table verification failed during proof validation
    #[error("invalid lookup table: {reason}")]
    InvalidLookupTable { reason: String },
}

/// Result type for operations that can fail during subtrie creation
pub type ProofResult<T> = Result<T, ProofError>;
