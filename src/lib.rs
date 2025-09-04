//! This crate implements a new state trie data structure called SALT, which is
//! used to replace MPT in megaeth. The most distinguishing feature of SALT is
//! its memory & IO-efficiency: the trie is small enough to fit in memory and,
//! thus, allows nodes to update their state roots w/o incuring disk IOs.
//!
//! Like MPT, SALT provides the interface of an authenticated KV store (AKVS).
//! That is, it provides two basic functionalities:
//! - Storage: store the blockchain state as a set of KV pairs.
//! - Authentication: compute a deterministic and cryptographically secure hash value that uniquely
//!   identifies the blockchain state.
//!
//! SALT has a very shallow and wide trie structure. For example, a common setup
//! is a 4-level trie with a branch factor of 256. In this case, SALT has 256^3,
//! or ~16 million, leaf nodes. Each leaf node is called a bucket and it stores
//! the key-value pairs that make up the blockchain state. Internally, the bucket
//! is implemented using a strongly history-independent (SHI) hash table; this
//! ensures that the internal representation of SALT depends only on the set of
//! key-value pairs (and not on the key insertion/deletion order).
//!
//! SALT authenticates its state recursively. At the bottom, each bucket computes
//! a commitment of its internal key-value pairs. Then, each internal trie node
//! computes a commitment of its child nodes. Like Ethereum Verkle tree, SALT uses
//! IPA, a homomorphic vector commitment scheme, to compute these commitments.
//!
//! This crate divides the implementation of SALT into two major modules: the
//! "state" module, which manages the storage & accesses of all the key-value
//! pairs inside the buckets, and the "trie" module, which maintains commitments
//! of the trie nodes.

pub mod account;
pub mod constant;
pub mod genesis;
pub mod proof;
pub use proof::{ProofError, SaltProof};
pub mod state;
pub use state::{
    state::{pk_hasher, EphemeralSaltState, PlainStateProvider},
    updates::{SaltDeltas, StateUpdates},
};
pub mod trie;
pub use trie::{
    trie::{get_child_node, hash_commitment, StateRoot},
    updates::TrieUpdates,
    witness::{get_block_witness, BlockWitness},
};

pub mod traits;
pub mod types;
pub use types::*;

pub mod mem_salt;
