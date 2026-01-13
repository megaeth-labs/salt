#![no_main]

use libfuzzer_sys::fuzz_target;
use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};
use salt::{
    constant::{NUM_BUCKETS, NUM_META_BUCKETS},
    traits::StateReader,
    BucketId, EphemeralSaltState, MemStore, SaltKey, SaltValue, SaltWitness, StateRoot,
    StateUpdates, Witness,
};
use std::collections::BTreeMap;
use std::sync::OnceLock;

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

static STORE: OnceLock<MemStore> = OnceLock::new();

fuzz_target!(|data: &[u8]| {
    // fuzzed code goes here
    if data.len() < 1024 {
        return;
    }

    let seed: u64 = u64::from_le_bytes(data[0..8].try_into().unwrap());
    let blocks = generate_blocks(seed, data);
    e2e_test(&blocks);
});

/// Reads an environment variable and parses it, falling back to default if missing or invalid.
fn env<T: std::str::FromStr>(key: &str, default: T) -> T {
    std::env::var(key)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

/// Generates a sequence of test blocks from fuzzer input data.
///
/// Converts raw fuzzer bytes into structured blocks containing mini-blocks and lookups.
/// Each byte is interpreted as an operation: values < 180 become Insert operations,
/// others become Delete operations. The function divides the input data into blocks,
/// then further subdivides each block into mini-blocks to simulate pipelined execution.
///
/// # Arguments
/// * `seed` - Random seed for deterministic key/value generation
/// * `data` - Raw fuzzer input bytes to convert into operations
///
/// # Returns
/// A vector of blocks, each containing mini-blocks of operations and lookup keys
fn generate_blocks(seed: u64, data: &[u8]) -> Vec<Block> {
    let total_size = data.len();
    let blocks_per_run = total_size.div_ceil(env("RANDOM_BLOCKS", 3));
    let mini_blocks_per_block = blocks_per_run.div_ceil(env("RANDOM_MINI_BLOCKS", 10));
    let lookups_per_block = env("RANDOM_LOOKUPS", 50);
    let mut rng = StdRng::seed_from_u64(seed);

    let blocks: Vec<Block> = data
        .chunks(blocks_per_run)
        .map(|chunk| Block {
            mini_blocks: chunk
                .chunks(mini_blocks_per_block)
                .map(|mini_chucks| {
                    mini_chucks
                        .iter()
                        .map(|op| {
                            if *op < 180 {
                                Operation::Insert(rng.random(), rng.random())
                            } else {
                                Operation::Delete(rng.random())
                            }
                        })
                        .collect()
                })
                .collect(),
            lookups: (0..lookups_per_block).map(|_| rng.random()).collect(),
        })
        .collect();
    blocks
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
    let db = STORE.get_or_init(MemStore::default);
    let mut ref_state: BTreeMap<Vec<u8>, Vec<u8>> = db
        .entries(SaltKey::bucket_range(
            NUM_META_BUCKETS as BucketId,
            (NUM_BUCKETS - 1) as BucketId,
        ))
        .expect("Failed to enumerate entries")
        .iter()
        .map(|(_, v)| (v.key().to_vec(), v.value().to_vec()))
        .collect();
    let mut pre_state_root = StateRoot::rebuild(db)
        .expect("Failed to get initial state root")
        .0;

    let mut revert_state_updates = StateUpdates::default();
    let expected_revert_state_root = pre_state_root;

    for block in blocks {
        let mut state = EphemeralSaltState::new(db);
        let mut trie = StateRoot::new(db);
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
        let witness = Witness::create([], &lookups, &all_modifications, db)
            .expect("Failed to create witness");

        // Save revert information for post-test verification: stores the
        // inverse updates to enable rolling back all blocks to initial state later.
        // This validates that state updates are correctly invertible.
        revert_state_updates.merge(state_updates.clone());

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

    // Post-test verification: Revert blocks back to initial state to validate state reconstruction.
    //
    // This section tests the system's ability to correctly undo state changes by applying
    // inverse state updates in reverse order. This validates that:
    // 1. State updates are correctly invertible (can be undone)
    // 2. The trie correctly computes intermediate state roots during reversion
    //
    // When bucket expansion occurs, this also validates the correctness of bucket contraction
    let (revert_state_root, _) = StateRoot::new(&db)
        .update_fin(&revert_state_updates.inverse())
        .expect("Failed to compute state root during reversion");
    assert_eq!(
        revert_state_root, expected_revert_state_root,
        "State root mismatch during reversion"
    );
}
