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
    trie::{compute_from_scratch, get_child_node, StateRoot},
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::trie::trie::compute_from_scratch;
    use std::collections::HashMap;

    #[test]
    /// A simple end-to-end test demonstrating the complete SALT workflow.
    fn basic_integration_test() -> Result<(), Box<dyn std::error::Error>> {
        // Create a PoC in-memory SALT instance
        let mem_salt = MemSalt::new();
        let mut state = EphemeralSaltState::new(&mem_salt);

        // Prepare plain key-value updates (EVM account/storage data)
        let kvs = HashMap::from([
            (b"account1".to_vec(), Some(b"balance100".to_vec())),
            (b"storage_key".to_vec(), Some(b"storage_value".to_vec())),
        ]);

        // Apply kv updates and get SALT-encoded state changes
        let state_updates = state.update(&kvs)?;
        // "Persist" the state updates to storage (the "trie" remains unchanged)
        mem_salt.update_state(state_updates.clone());

        // Read plain value back using PlainStateProvider
        let provider = PlainStateProvider::new(&mem_salt);
        let balance = provider.get_raw(b"account1")?;
        assert_eq!(balance, Some(b"balance100".to_vec()));

        // Incremental state root computation from the SALT-encoded state changes
        let mut state_root = StateRoot::new();
        let (root_hash, trie_updates) = state_root.update(&mem_salt, &mem_salt, &state_updates)?;

        // Or compute from scratch based on the previously updated state
        let (root_hash_from_scratch, _) = compute_from_scratch(&mem_salt)?;
        assert_eq!(root_hash, root_hash_from_scratch);

        // "Persist" the trie updates to storage
        mem_salt.update_trie(trie_updates);

        Ok(())
    }
}
