//! End-to-end fuzz testing for SALT blockchain state management.

use crate::constant::{NUM_BUCKETS, NUM_META_BUCKETS};
use crate::traits::StateReader;
use crate::types::{BucketId, SaltKey};
use crate::{
    EphemeralSaltState, MemStore, SaltValue, SaltWitness, StateRoot, StateUpdates, Witness,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// A state modification resulting from transaction execution.
///
/// Operations reference keys via indices into a pre-generated KV pool,
/// allowing the fuzzer to focus on operation sequences rather than key generation.
#[derive(Debug, Clone, Serialize, Deserialize)]
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
#[derive(Debug, Clone, Serialize, Deserialize)]
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

/// End-to-end test validating SALT blockchain state management correctness.
///
/// Simulates the complete block processing lifecycle from both block producer
/// and stateless validator perspectives:
///
/// **Block Producer Flow:**
/// - Processes state reads (lookups) during transaction execution
/// - Applies state modifications incrementally via mini-blocks (simulates pipelining)
/// - Canonicalizes state at block boundaries
/// - Generates witness containing all data needed for validation
///
/// **Stateless Validator Flow:**
/// - Verifies witness integrity and pre-state root
/// - Re-executes all lookups and modifications using only witness data
/// - Computes final state root and validates it matches producer's result
///
/// **Correctness Validation:**
/// - **State consistency**: All reads/writes match a BTreeMap reference oracle.
///   Final verification ensures the database contains exactly the same key-value
///   pairs as the reference (both values and count match).
/// - **Trie consistency**: State roots from producer, validator, and rebuild-from-scratch all match.
///
/// # Panics
/// Panics if any consistency check fails, indicating a bug in SALT's implementation.
#[cfg(test)]
fn e2e_test(blocks: &Vec<Block>) {
    // Generate the plain key-value pairs to be used in testing beforehand
    let kv_pool_size = env("RANDOM_KV_POOL_SIZE", 4096);
    let kv_pool: Vec<_> = (0..kv_pool_size)
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

        // Keys to lookup during block execution
        let lookups: Vec<_> = lookup_results.iter().map(|(k, _)| k.clone()).collect();
        let mut all_modifications = BTreeMap::new();

        // Block producer: Apply state modifications incrementally
        for mini_block in &block.mini_blocks {
            let plain_kvs = get_plain_kv_updates(mini_block, &kv_pool);

            // Update reference oracle and collect all modifications
            for (key, value) in &plain_kvs {
                all_modifications.insert(key.clone(), value.clone());
                match value {
                    Some(val) => {
                        ref_state.insert(key.clone(), val.clone());
                    }
                    None => {
                        ref_state.remove(key);
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
        let witness =
            Witness::create(&lookups, &all_modifications, &db).expect("Failed to create witness");

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
        for (key, expected) in &lookup_results {
            assert_eq!(
                &witness_state.plain_value(key).expect("Lookup failed"),
                expected,
                "Witness lookup mismatch for key {key:?}",
            );
        }

        // Stateless validator: Re-execute modifications and verify final state root matches
        //
        // Apply updates first, then inserts/deletes in deterministic key order (same as
        // Witness::create). This ordering is critical: inserts/deletes may trigger key
        // displacement or bucket expansion, invalidating the witness's direct lookup table.
        let mut state_updates = StateUpdates::default();
        let mut inserts_or_deletes = BTreeMap::new();

        for (plain_key, opt_plain_value) in all_modifications {
            if let (Ok(Some((salt_key, old_value))), Some(new_value)) =
                (witness_state.find(&plain_key), &opt_plain_value)
            {
                // Update operation: key exists and new value is not None
                witness_state.update_value(
                    &mut state_updates,
                    salt_key,
                    Some(old_value),
                    Some(SaltValue::new(&plain_key, new_value)),
                );
            } else {
                inserts_or_deletes.insert(plain_key, opt_plain_value);
            }
        }
        state_updates.merge(
            witness_state
                .update_fin(&inserts_or_deletes)
                .expect("Failed to apply inserts/deletes"),
        );
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

/// Reads an environment variable and parses it, falling back to default if missing or invalid.
#[cfg(test)]
fn env<T: std::str::FromStr>(key: &str, default: T) -> T {
    std::env::var(key)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Stress test validating SALT correctness with randomly generated operation sequences.
    ///
    /// Performs property-based stress testing by running multiple iterations with different
    /// random seeds, validating that state consistency and trie consistency properties hold
    /// across diverse operation sequences. Each iteration:
    /// - Generates random blocks with operations (70% Insert, 30% Delete)
    /// - Validates via [`e2e_test`] (state oracle matching + trie root consistency)
    /// - Uses iteration number as RNG seed for deterministic reproduction
    /// - On failure, saves input to `random_stress_failure_{timestamp}.json` for replay via
    ///   [`replay_test_failure`]
    ///
    /// Configuration via environment variables (with defaults):
    /// - `RANDOM_KV_POOL_SIZE=4096` - Size of the key-value pool
    /// - `RANDOM_ITERATIONS=100` - Number of test iterations
    /// - `RANDOM_BLOCKS=3` - Blocks per iteration
    /// - `RANDOM_MINI_BLOCKS=10` - Mini-blocks per block
    /// - `RANDOM_OPS=100` - Operations per mini-block
    /// - `RANDOM_LOOKUPS=50` - Lookups per block
    #[test]
    #[ignore]
    fn test_e2e_random_stress() {
        use rand::rngs::StdRng;
        use rand::{Rng, SeedableRng};
        use std::panic;

        let (
            iterations,
            blocks_per_iter,
            mini_blocks_per_block,
            ops_per_mini_block,
            lookups_per_block,
        ) = (
            env("RANDOM_ITERATIONS", 100),
            env("RANDOM_BLOCKS", 3),
            env("RANDOM_MINI_BLOCKS", 10),
            env("RANDOM_OPS", 100),
            env("RANDOM_LOOKUPS", 50),
        );

        println!("\nStarting deterministic random loop test:");
        println!(
            "  {} iterations x {} blocks x {} mini-blocks x {} ops",
            iterations, blocks_per_iter, mini_blocks_per_block, ops_per_mini_block
        );
        println!(
            "  Total operations: {}\n",
            iterations * blocks_per_iter * mini_blocks_per_block * ops_per_mini_block
        );

        for iteration in 0..iterations {
            println!("Iteration {}/{}...", iteration + 1, iterations);

            let mut rng = StdRng::seed_from_u64(iteration as u64);
            let blocks: Vec<Block> = (0..blocks_per_iter)
                .map(|_| Block {
                    mini_blocks: (0..mini_blocks_per_block)
                        .map(|_| {
                            (0..ops_per_mini_block)
                                .map(|_| {
                                    if rng.gen_bool(0.7) {
                                        Operation::Insert(rng.gen(), rng.gen())
                                    } else {
                                        Operation::Delete(rng.gen())
                                    }
                                })
                                .collect()
                        })
                        .collect(),
                    lookups: (0..lookups_per_block).map(|_| rng.gen()).collect(),
                })
                .collect();

            if let Err(err) = panic::catch_unwind(panic::AssertUnwindSafe(|| e2e_test(&blocks))) {
                let timestamp = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_secs();
                let filename = format!("random_stress_failure_{}.json", timestamp);
                if let Ok(json) = serde_json::to_string_pretty(&blocks) {
                    let _ = std::fs::write(&filename, json);
                    eprintln!(
                        "\nTest failed at iteration {} (seed: {})",
                        iteration, iteration
                    );
                    eprintln!("Failing input saved to: {}", filename);
                    eprintln!(
                        "Replay with: TEST_FAILURE={} cargo test replay_test_failure -- --ignored",
                        filename
                    );
                }
                panic::resume_unwind(err);
            }
        }

        println!("\nAll {} tests passed!", iterations);
    }

    /// Debugging utility to replay a saved test failure from a JSON file.
    ///
    /// This is not a standalone test - it reproduces failures by re-running
    /// the exact operation sequence that caused a previous test failure.
    ///
    /// Usage:
    /// ```bash
    /// TEST_FAILURE=random_stress_failure_1234567890.json cargo test replay_test_failure -- --nocapture --ignored
    /// ```
    #[test]
    #[ignore]
    fn replay_test_failure() {
        let filename =
            std::env::var("TEST_FAILURE").expect("TEST_FAILURE environment variable must be set");
        let json = std::fs::read_to_string(&filename)
            .unwrap_or_else(|e| panic!("Failed to read {}: {}", filename, e));
        let blocks: Vec<Block> = serde_json::from_str(&json)
            .unwrap_or_else(|e| panic!("Failed to parse {}: {}", filename, e));

        println!("Replaying from {} ({} blocks)", filename, blocks.len());
        e2e_test(&blocks);
        println!("Replay passed!");
    }
}
