#![doc = include_str!("../README.md")]

pub mod constant;
pub mod empty_salt;
pub mod proof;
pub use proof::{PlainKeysProof, ProofError, SaltProof, SaltWitness};
pub mod state;
pub use state::{hasher, state::EphemeralSaltState, updates::StateUpdates};
pub mod trie;
pub use trie::{
    node_utils::get_child_node,
    trie::{StateRoot, TrieUpdates},
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
    use crate::trie::trie::StateRoot;
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
        let (root_hash, trie_updates) = state_root.update_fin(state_updates)?;

        // Or compute from scratch based on the previously updated state
        let (root_hash_from_scratch, _) = StateRoot::rebuild(&store)?;
        assert_eq!(root_hash, root_hash_from_scratch);

        // "Persist" the trie updates to storage
        store.update_trie(trie_updates);

        // Alice creates a cryptographic proof for plain key-value pairs
        let plain_keys_to_prove = vec![b"account1".to_vec(), b"non_existent_key".to_vec()];
        let proof = PlainKeysProof::create(&plain_keys_to_prove, &store)?;

        // Bob verifies the proof against its local state root
        let is_valid = proof.verify(root_hash);
        assert!(is_valid.is_ok());

        // Bob looks up values from the proof using EphemeralSaltState
        let mut bob_state = EphemeralSaltState::new(&proof);
        assert_eq!(
            bob_state.plain_value(b"account1")?,
            Some(b"balance100".to_vec())
        );
        assert_eq!(bob_state.plain_value(b"non_existent_key")?, None);

        Ok(())
    }
}
