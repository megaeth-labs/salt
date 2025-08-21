#![doc = include_str!("../README.md")]

pub mod constant;
pub mod empty_salt;
pub mod proof;
pub use proof::{ProofError, SaltProof};
pub mod state;
pub use state::{hasher, state::EphemeralSaltState, updates::StateUpdates};
pub mod trie;
pub use trie::{
    proof::PlainKeysProof,
    trie::{get_child_node, StateRoot},
    updates::TrieUpdates,
    witness::{get_block_witness, BlockWitness},
};

pub mod traits;
pub mod types;
pub use types::*;
pub mod mem_store;
pub use mem_store::MemStore;

#[cfg(test)]
pub mod mock_evm_types;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::trie::trie::compute_from_scratch;
    use std::collections::HashMap;

    #[test]
    /// A simple end-to-end test demonstrating the complete SALT workflow.
    fn basic_integration_test() -> Result<(), Box<dyn std::error::Error>> {
        // Create a PoC in-memory SALT instance
        let store = MemStore::new();
        let mut state = EphemeralSaltState::new(&store);

        // Prepare plain key-value updates (EVM account/storage data)
        let kvs = HashMap::from([
            (b"account1".to_vec(), Some(b"balance100".to_vec())),
            (b"storage_key".to_vec(), Some(b"storage_value".to_vec())),
        ]);

        // Apply kv updates and get SALT-encoded state changes
        let state_updates = state.update(&kvs)?;
        // "Persist" the state updates to storage (the "trie" remains unchanged)
        store.update_state(state_updates.clone());

        // Read plain value back
        let balance = state.plain_value(b"account1")?;
        assert_eq!(balance, Some(b"balance100".to_vec()));

        // Incremental state root computation from the SALT-encoded state changes
        let mut state_root = StateRoot::new(&store);
        let (root_hash, trie_updates) = state_root.update(&state_updates)?;

        // Or compute from scratch based on the previously updated state
        let (root_hash_from_scratch, _) = compute_from_scratch(&store)?;
        assert_eq!(root_hash, root_hash_from_scratch);

        // "Persist" the trie updates to storage
        store.update_trie(trie_updates);

        let plain_keys_to_prove = vec![b"account1".to_vec(), b"non_existent_key".to_vec()];
        let expected_values = vec![Some(b"balance100".to_vec()), None];

        // Alice creates a cryptographic proof for plain key-value pairs
        let proof = trie::proof::create_proof(&plain_keys_to_prove, &store, &store)?;

        // Bob verifies the proof against its local state root
        let is_valid = proof.verify::<MemStore, MemStore>(root_hash);
        assert!(is_valid.is_ok());

        let proof_plain_values = proof.get_values();

        assert_eq!(proof_plain_values, expected_values);

        Ok(())
    }
}
