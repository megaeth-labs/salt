# SALT - Small Authentication Large Trie

A memory-efficient state trie data structure designed to replace Merkle Patricia Trie (MPT) in blockchain systems.
SALT provides authenticated key-value storage using IPA (Inner Product Argument) and Pedersen commitments.

## Overview

SALT (Small Authentication Large Trie) is the core state management component of the MegaETH blockchain.
Unlike traditional Merkle Patricia Tries that require frequent disk I/O operations during state root updates,
SALT is designed to fit all intermediate commitments in memory and eliminate all random disk I/O's.

### Key Features

- **Memory Efficient**: Designed to fit all cryptographic commitments in memory even for huge blockchain states
- **Shallow & Wide Structure**: 4-level trie with 256 branch factor (~16M leaf nodes)
- **Dynamic Bucket Sizing**: Adaptive capacity management with SHI hash tables
- **Incremental Updates**: Homomorphic vector commitments for efficient, incremental state root updates
- **History Independence**: Deterministic state representation regardless of update order
- **Storage Backend Agnostic**: Compatible with any persistent key-value store

## Architecture

### Trie Structure

```text
Level 0: Root (1 node)
Level 1: 256 nodes
Level 2: 65,536 nodes
Level 3: 16,777,216 buckets (leaf nodes)
```

Each bucket contains:
- Minimum 256 slots (expandable to 2^40)
- Key-value pairs stored using SHI hash tables
- Metadata (nonce, capacity, usage statistics)

### Key Components

#### State Management ([`state`])
- [`EphemeralSaltState`]: Non-persistent state snapshot with change tracking
- [`PlainStateProvider`]: Interface for reading EVM account/storage data
- [`StateUpdates`]: Incremental state change accumulator

#### Trie Authentication ([`trie`])
- [`StateRoot`]: Updates cryptographic commitments incrementally
- [`TrieUpdates`]: Tracks commitment changes across trie levels
- [`BlockWitness`]: Generates and verifies cryptographic proofs

#### Storage Abstraction ([`traits`])
- [`StateReader`]: Interface for reading bucket entries
- [`TrieReader`]: Interface for reading node commitments
- Enables pluggable storage backends

## Usage

### Basic State Operations

```rust,ignore
use salt::{EphemeralSaltState, PlainStateProvider, MemSalt};
use std::collections::HashMap;

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
mem_salt.update_state(state_updates);

// Read plain value back using PlainStateProvider
let provider = PlainStateProvider::new(&mem_salt);
let balance = provider.get_raw(b"account1")?;
assert_eq!(balance, Some(b"balance100".to_vec()));
```

### Computing State Root

```rust,ignore
use salt::{StateRoot, compute_from_scratch};

// Incremental state root computation from the SALT-encoded state changes
let mut state_root = StateRoot::new();
let (root_hash, trie_updates) = state_root.update(&mem_salt, &state_updates)?;

// Or compute from scratch based on the previously updated state
let (root_hash_from_scratch, _) = compute_from_scratch(&mem_salt)?;
assert_eq!(root_hash, root_hash_from_scratch);

// "Persist" the trie updates to storage
mem_salt.update_trie(trie_updates);
```

### Generating Proofs

```rust,ignore
use salt::{get_block_witness, SaltProof};

// FIXME: the following code is fictional now; make it work!

/*
// Define plain keys to prove (both existing and non-existing)
let plain_keys_to_prove = vec![b"account1", b"non_existent_key"];
let expected_values = vec![Some(b"balance100"), None];

// Alice creates a cryptographic proof for plain key-value pairs
let proof = prover::create_salt_proof(&plain_keys, &mem_salt)?;

// Bob verifies the proof against its local state root
let is_valid = proof.check::<MemSalt>(plain_keys, expected_values, root_hash);
// FIXME: why can't is_value simply be a bool?
assert!(is_valid.is_ok());
 */
```

## Data Types

### Core Types

- [`SaltKey`]: 64-bit key (24-bit bucket ID + 40-bit bucket slot ID)
- [`SaltValue`]: Variable-length encoded key-value pair
- [`NodeId`]: 64-bit unique ID for all trie nodes (including bucket tree nodes)
- [`BucketMeta`]: Bucket metadata (nonce, capacity)
- [`CommitmentBytes`]: 64-byte uncompressed group elements

### Configuration Constants

- **Main Trie**: 4 levels with 256 branch factor
- **Maximum Bucket Tree**: 5 levels with 256 branch factor
- **Minimum Bucket Size**: 256 slots
- **Maximum Bucket Size**: 2^40 slots (i.e., 2^32 bucket segments)

## Algorithms

### SHI Hash Tables

SALT uses Strongly History-Independent hash tables to ensure deterministic bucket representation:

1. **Linear Probing**: Search slots sequentially to find data items
2. **Collision Resolution**: Swap elements upon insertion/deletion to maintain a canonical order
3. **Manual Rehashing**: Shuffle elements upon nonce change to mitigate pathological cases
4. **Dynamic Resizing**: Auto expansion at high load factor, manual contraction when underutilized

### Commitment Computation

State authentication uses IPA + Pedersen commitments:

1. **Bottom-up Updates**: Compute bucket commitments first, propagate upward
2. **Incremental Updates**: Only compute commitment deltas from updated child nodes
3. **Parallel Processing**: Parallel computation at each trie level

### Bucket Management

Large buckets use tree structures for efficiency:

1. **Meta Buckets**: Set aside the first 65,536 buckets to store metadata for other buckets
2. **Dynamic Expansion**: Add subtree levels as bucket grows
3. **5-Level Subtrees**: Handle buckets up to 1 trillion (2^40) slots

## Dependencies

- **Cryptography**: `banderwagon` (elliptic curves), `ipa-multipoint` (IPA proofs)
- **Hashing**: `blake3` (content hashing), `megaeth-ahash` (bucket placement)
- **Parallelism**: `rayon` (multi-threading)
- **Serialization**: `serde` (data persistence)

## Testing

Run the test suite:

```bash
cargo test
```

Run benchmarks:

```bash
cargo bench
```

[`state`]: crate::state
[`trie`]: crate::trie
[`traits`]: crate::traits
[`EphemeralSaltState`]: crate::state::EphemeralSaltState
[`PlainStateProvider`]: crate::state::PlainStateProvider
[`StateUpdates`]: crate::state::StateUpdates
[`StateRoot`]: crate::trie::StateRoot
[`TrieUpdates`]: crate::trie::TrieUpdates
[`BlockWitness`]: crate::trie::BlockWitness
[`StateReader`]: crate::traits::StateReader
[`TrieReader`]: crate::traits::TrieReader
[`SaltKey`]: crate::types::SaltKey
[`SaltValue`]: crate::types::SaltValue
[`NodeId`]: crate::types::NodeId
[`BucketMeta`]: crate::types::BucketMeta
[`CommitmentBytes`]: crate::types::CommitmentBytes