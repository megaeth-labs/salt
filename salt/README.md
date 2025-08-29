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

#### Storage Abstraction ([`traits`])
Provides pluggable storage backend interfaces:
- [`StateReader`]: Interface for reading bucket entries
- [`TrieReader`]: Interface for reading node commitments
- [`MemStore`]: Reference in-memory storage implementation

#### State Management ([`state`])
Handles the application layer of SALT, managing key-value pairs with SHI hash tables:
- [`EphemeralSaltState`]: Non-persistent state view with in-memory caching
  - Implements SHI (Strongly History-Independent) hash table operations
  - Provides EVM account/storage data interface
  - Tracks changes and generates state updates
- [`StateUpdates`]: Accumulates state changes for batch processing

#### Trie Authentication ([`trie`])
Manages cryptographic commitments using IPA vector commitments:
- [`StateRoot`]: Computes and maintains the authenticated state root
  - Supports incremental updates
  - Optimizes computation by only updating changed paths
- [`TrieUpdates`]: Tracks commitment changes across all trie levels
  - Handles both main trie and dynamic bucket subtree updates
- [`node_utils`]: Utilities for node navigation and subtree management
  - Manages dynamic bucket expansion/contraction
  - Provides node ID calculation and tree traversal

#### Proof Generation ([`proof`])
Creates and verifies cryptographic witnesses:
- [`BlockWitness`]: Generates witnesses for state transitions
  - Supports both inclusion and exclusion proofs
- [`PlainKeysProof`]: Proves existence/non-existence of plain keys
  - Enables light client verification
- [`SaltProof`]: Low-level proof structure with IPA commitments

## Usage

### Basic State Operations

```rust,ignore
use salt::{EphemeralSaltState, MemStore};
use std::collections::HashMap;

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
store.update_state(state_updates);

// Read plain value back
let balance = state.plain_value(b"account1")?;
assert_eq!(balance, Some(b"balance100".to_vec()));
```

### Computing State Root

```rust,ignore
use salt::{StateRoot, compute_from_scratch};

// Incremental state root computation from the SALT-encoded state changes
let mut state_root = StateRoot::new();
let (root_hash, trie_updates) = state_root.update(&store, &state_updates)?;

// Or compute from scratch based on the previously updated state
let (root_hash_from_scratch, _) = compute_from_scratch(&store)?;
assert_eq!(root_hash, root_hash_from_scratch);

// "Persist" the trie updates to storage
store.update_trie(trie_updates);
```

### Generating Proofs

```rust,ignore
use salt::trie::witness::Witness;

// Define plain keys to prove (both existing and non-existing)
let plain_keys_to_prove = vec![b"account1".to_vec(), b"non_existent_key".to_vec()];
let expected_values = vec![Some(b"balance100".to_vec()), None];

// Alice creates a cryptographic proof for plain key-value pairs
let witness = Witness::create(&plain_keys_to_prove, &store)?;

// Bob verifies the witness against its local state root
let is_valid = witness.verify(root_hash);
assert!(is_valid.is_ok());
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