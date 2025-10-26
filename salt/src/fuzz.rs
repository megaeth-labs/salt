//! End-to-end fuzz testing for SALT blockchain state management.
//!
//! Simulates the complete block processing lifecycle from two perspectives:
//!
//! **Block Producer:**
//! - Process state reads and modifications in small batches
//! - Update state and trie incrementally, then canonicalize at block boundaries
//! - Generate witnesses containing all data needed for stateless validation
//!
//! **Stateless Validator:**
//! - Verify witness integrity and re-execute blocks using only witness data
//! - Validate that state transitions match the block producer's results
//!
//! The test validates correctness by checking two key properties:
//! - **State consistency**: All state reads/writes match a reference BTreeMap oracle
//! - **Trie consistency**: The state root computed incrementally at the block producer,
//!   the state root verified by the stateless validator, and the final state root
//!   rebuilt from scratch must all agree

use crate::constant::{NUM_BUCKETS, NUM_META_BUCKETS};
use crate::traits::StateReader;
use crate::types::{BucketId, SaltKey};
use crate::{EphemeralSaltState, MemStore, SaltWitness, StateRoot, StateUpdates, Witness};
use std::collections::BTreeMap;

/// A state modification resulting from transaction execution.
///
/// Operations reference keys via indices into a pre-generated KV pool,
/// allowing the fuzzer to focus on operation sequences rather than key generation.
#[derive(Debug, Clone)]
pub enum Operation {
    /// Inserts or updates the key at pool index with a new single-byte value.
    ///
    /// The `u16` index is used modulo the pool size to reference a key.
    /// This will update the value if the key already exists, or insert a new
    /// key-value pair otherwise.
    Insert(u16, u8),

    /// Removes the key at pool index from the state.
    ///
    /// The `u16` index is used modulo the pool size to reference a key.
    Delete(u16),
}

/// Simulates a blockchain block containing state reads and modifications.
///
/// After transaction execution produces state modifications, these changes are
/// applied to the state trie in small batches to enable pipelining of operations
/// like state trie updates and block propagation.
#[derive(Debug, Clone)]
pub struct Block {
    /// Small batches of state modifications to apply incrementally.
    ///
    /// Each `Vec<Operation>` represents a batch of state changes applied together.
    /// Multiple mini-blocks test incremental state/trie updates via `update()` before
    /// the final `canonicalize()` at block boundaries.
    pub mini_blocks: Vec<Vec<Operation>>,

    /// Keys (as KV pool indices) that are read during block execution.
    ///
    /// These simulate state reads that occur during transaction processing.
    /// All lookup keys must be included in the witness so a stateless validator
    /// has sufficient data to re-execute the block and verify state transitions.
    pub lookups: Vec<u16>,
}

/// Main end-to-end fuzz test function.
#[cfg(test)]
pub fn e2e_fuzz_test(blocks: &Vec<Block>) {
    // Generate the plain key-value pairs to be used in testing beforehand
    const KV_POOL_SIZE: usize = 4096;
    let kv_pool: Vec<_> = (0..KV_POOL_SIZE)
        .map(|i| {
            let key = format!("key_{:05x}", i).into_bytes();
            let value = vec![i as u8];
            (key, value)
        })
        .collect();

    // Create the mock database and BTreeMap-based reference state implementation.
    let db = MemStore::new();
    let mut ref_state = BTreeMap::new();
    let mut pre_state_root = StateRoot::rebuild(&db)
        .expect("Failed to get initial state root")
        .0;

    for block in blocks {
        let mut state = EphemeralSaltState::new(&db);
        let mut trie = StateRoot::new(&db);
        let mut state_updates = StateUpdates::default();

        // Block producer: Process read-only lookups that occur during transaction execution.
        // These keys must be included in the witness for stateless validation.
        let mut lookup_results = Vec::new();
        for &idx in &block.lookups {
            let (key, _) = &kv_pool[idx as usize % kv_pool.len()];
            let actual = state
                .plain_value(key)
                .expect("Failed to lookup value from state");
            let expected = ref_state.get(key).cloned();

            assert_eq!(
                actual, expected,
                "Lookup mismatch for key {:?}: expected {:?}, got {:?}",
                key, expected, actual
            );

            lookup_results.push((key.clone(), actual));
        }

        // Categorize keys for witness creation:
        // - lookups_or_updates: keys that exist pre-block (reads + updates)
        // - inserts_or_deletes: keys created or removed during block (inserts + deletes)
        let mut lookups_or_updates: Vec<_> =
            lookup_results.iter().map(|(k, _)| k.clone()).collect();
        let mut inserts_or_deletes = Vec::new();

        // Block producer: Apply state modifications incrementally (simulates pipelined execution)
        for mini_block in &block.mini_blocks {
            let plain_kvs = get_plain_kv_updates(mini_block, &kv_pool);

            // Update reference oracle and categorize operations for witness
            for (key, value) in &plain_kvs {
                match value {
                    Some(val) => {
                        // Update to existing key → lookup; Insert of new key → modification
                        if ref_state.insert(key.clone(), val.clone()).is_some() {
                            lookups_or_updates.push(key.clone());
                        } else {
                            inserts_or_deletes.push((key.clone(), Some(val.clone())));
                        }
                    }
                    None => {
                        // Delete always goes to modifications
                        ref_state.remove(key);
                        inserts_or_deletes.push((key.clone(), None));
                    }
                }
            }

            // Apply updates to state and trie (incremental, not yet canonical)
            let mini_updates = state
                .update(plain_kvs.iter().map(|(k, v)| (k, v)))
                .expect("Failed to update state");
            trie.update(&mini_updates).expect("Failed to update trie");
            state_updates.merge(mini_updates);
        }

        // Block producer: Canonicalize state at block boundary
        let canon_updates = state.canonicalize().expect("Failed to canonicalize state");
        trie.update(&canon_updates).expect("Failed to update trie");
        let (post_state_root, trie_updates) = trie.finalize().expect("Failed to finalize trie");
        state_updates.merge(canon_updates);

        // Block producer: Generate witness containing all data needed for stateless validation
        let witness = Witness::create(
            &lookups_or_updates,
            inserts_or_deletes.iter().map(|(k, v)| (k, v)),
            &db,
        )
        .expect("Failed to create witness");

        // Block producer: persist to database
        db.update_state(state_updates);
        db.update_trie(trie_updates);

        // Simulate witness transmission: serialize, send over network, and reconstruct
        let witness = {
            let serialized =
                bincode::serde::encode_to_vec(&witness.salt_witness, bincode::config::legacy())
                    .expect("Failed to serialize witness");
            let (deserialized, _): (SaltWitness, _) =
                bincode::serde::decode_from_slice(&serialized, bincode::config::legacy())
                    .expect("Failed to deserialize witness");
            Witness::from(deserialized)
        };

        // Stateless validator: Verify witness integrity and initial state root
        witness.verify().expect("Witness verification failed");
        assert_eq!(
            witness
                .state_root()
                .expect("Failed to get witness state root"),
            pre_state_root,
            "Witness state root mismatch"
        );

        // Stateless validator: Re-execute lookups using only witness data
        let mut witness_state = EphemeralSaltState::new(&witness);
        for (key, expected_value) in &lookup_results {
            assert_eq!(
                &witness_state.plain_value(key).expect("Lookup failed"),
                expected_value,
                "Witness lookup mismatch for key {:?}",
                key
            );
        }

        // Stateless validator: Re-execute modifications and verify final state root matches
        let state_updates = witness_state
            .update_fin(inserts_or_deletes.iter().map(|(k, v)| (k, v)))
            .expect("Failed to update witness state");
        let (computed_root, _) = StateRoot::new(&witness)
            .update_fin(&state_updates)
            .expect("Failed to compute state root");
        assert_eq!(computed_root, post_state_root, "Final state root mismatch");

        pre_state_root = post_state_root;
    }

    // Post-test verification: Rebuild state root from scratch and ensure consistency
    let (rebuilt_root, _) = StateRoot::rebuild(&db).expect("Failed to rebuild state root");
    assert_eq!(
        rebuilt_root, pre_state_root,
        "Rebuilt state root mismatch: expected {:?}, got {:?}",
        pre_state_root, rebuilt_root
    );

    // Verify all keys in reference oracle match final database state
    let mut final_state = EphemeralSaltState::new(&db);
    for (key, expected_value) in &ref_state {
        let actual = final_state
            .plain_value(key)
            .expect("Failed to lookup value");
        assert_eq!(
            actual.as_ref(),
            Some(expected_value),
            "Key {:?} mismatch",
            key
        );
    }

    // Verify entry count matches (ensures no phantom entries exist)
    let entries = db
        .entries(SaltKey::bucket_range(
            NUM_META_BUCKETS as BucketId,
            (NUM_BUCKETS - 1) as BucketId,
        ))
        .expect("Failed to enumerate entries");
    assert_eq!(entries.len(), ref_state.len(), "Entry count mismatch");
}

/// Converts test operations into plain key-value updates.
///
/// Maps operation indices to actual keys via the KV pool, producing
/// the key-value pairs that will be applied to the state.
fn get_plain_kv_updates(
    operations: &[Operation],
    kv_pool: &[(Vec<u8>, Vec<u8>)],
) -> Vec<(Vec<u8>, Option<Vec<u8>>)> {
    operations
        .iter()
        .map(|op| match op {
            Operation::Insert(idx, new_value) => {
                let (key, _) = &kv_pool[*idx as usize % kv_pool.len()];
                (key.clone(), Some(vec![*new_value]))
            }
            Operation::Delete(idx) => {
                let (key, _) = &kv_pool[*idx as usize % kv_pool.len()];
                (key.clone(), None)
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_empty_blocks() {
        let blocks = vec![];
        e2e_fuzz_test(&blocks);
    }

    #[test]
    fn test_single_insert() {
        let blocks = vec![Block {
            mini_blocks: vec![vec![Operation::Insert(0, 42)]],
            lookups: vec![0],
        }];
        e2e_fuzz_test(&blocks);
    }

    #[test]
    fn test_insert_delete() {
        let blocks = vec![Block {
            mini_blocks: vec![vec![Operation::Insert(0, 42)], vec![Operation::Delete(0)]],
            lookups: vec![0],
        }];
        e2e_fuzz_test(&blocks);
    }
}
