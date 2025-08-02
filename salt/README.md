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

```
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

FIXME: are these executable doctest?
FIXME: need to differentiate ops on salt state & plain state

```rust
use salt::{EphemeralSaltState, StateUpdates, MemSalt};

// Create an in-memory SALT instance
let store = MemSalt::new();
let mut state = EphemeralSaltState::new(&store);

// Prepare key-value updates
let kvs = vec![
    (b"account1".to_vec(), Some(b"balance100".to_vec())),
    (b"storage_key".to_vec(), Some(b"storage_value".to_vec())),
];

// FIXME: need more examples on reads (not just writes)

// Apply kv updates and get salt state changes
let state_updates = state.update(&kvs)?;
```

### Computing State Root

```rust
use salt::{StateRoot, compute_from_scratch};

// Incremental state root computation
let mut trie = StateRoot::new();
// FIXME: fix this ugly api (passing &store twice); store should implement StateReader + TrieReader
let (root_hash, trie_updates) = trie.update(&store, &state_updates)?;
// let (root_hash, trie_updates) = trie.update(&store, &store, &state_updates)?;

// Or compute from scratch
let (root_hash, trie_updates) = compute_from_scratch(&store)?;
```

### Generating Proofs

```rust
use salt::{get_block_witness, SaltProof};

// Generate witness for a block of updates
let witness = get_block_witness(&store, &state_updates)?;

// FIXME: it's not clear to how to prove existence & non-existence
// Create and verify proofs
let proof = SaltProof::new(&witness, &keys_to_prove)?;
let is_valid = proof.verify(&root_hash, &expected_values)?;
```

## Data Types

### Core Types

FIXME: more core types to be covered?
- [`SaltKey`]: 64-bit key (24-bit bucket ID + 40-bit slot ID)
- [`SaltValue`]: Variable-length encoded key-value pair
- [`BucketMeta`]: Bucket metadata (nonce, capacity, usage)
- [`CommitmentBytes`]: 64-byte uncompressed group elements

### Configuration Constants

- **Trie Levels**: 4 levels with 256 branch factor
- **Minimum Bucket Size**: 256 slots
- **Maximum Bucket Size**: 2^40 slots
- **Slot Addressing**: 40-bit slot IDs within buckets

## Algorithms

### SHI Hash Tables

SALT uses Strongly History-Independent hash tables to ensure deterministic bucket representation:

1. **Linear Probing**: Search slots sequentially to find data items
2. **Collision Resolution**: Swap elements upon insertion/deletion to maintain a canonical order
3. **Manual Rehashing**: Shuffle elements to mitigate pathological cases
4. **Dynamic Resizing**: Auto expansion at high load factor, manual contraction when underutilized

### Commitment Computation

// FIXME: revise this subsection
State authentication uses IPA vector commitments:

1. **Bottom-up Updates**: Compute leaf commitments first, propagate upward
2. **Delta Optimization**: Only recompute changed commitment differences
3. **Parallel Processing**: Multi-threaded computation with work-stealing
4. **Precomputed Generators**: Accelerate cryptographic operations

### Bucket Management

// FIXME: revise this sub section
Large buckets use subtrie structures for efficiency:

1. **5-Level Subtries**: Handle buckets larger than 256 slots
2. **Dynamic Expansion**: Add subtrie levels as bucket grows
3. **Efficient Rehashing**: Minimize data movement during resize operations

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

// FIXME: what are these for? is this necessary for rustdoc linking to work?
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
[`BucketMeta`]: crate::types::BucketMeta
[`CommitmentBytes`]: crate::types::CommitmentBytes