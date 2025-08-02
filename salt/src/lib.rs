#![doc = include_str!("../README.md")]

pub mod constant;
pub mod empty_salt;
pub mod proof;
pub use proof::{ProofError, SaltProof};
pub mod state;
pub use state::{
    state::{pk_hasher, EphemeralSaltState, PlainStateProvider},
    updates::StateUpdates,
};
pub mod trie;
pub use trie::{
    trie::{get_child_node, StateRoot},
    updates::TrieUpdates,
    witness::{get_block_witness, BlockWitness},
};

pub mod traits;
pub mod types;
pub use types::*;
pub mod mem_salt;
pub use mem_salt::MemSalt;

#[cfg(test)]
pub mod formate;
