# AGENT.md — SALT Library

## What is SALT

SALT (Small Authentication Large Trie) is a Rust library implementing a memory-efficient authenticated key-value state trie for blockchain systems. It replaces Merkle Patricia Trie (MPT) using IPA (Inner Product Argument) + Pedersen commitments.

The workspace has three crates:
- `salt/` — main library (state management, trie, proof system)
- `banderwagon/` — elliptic curve group operations
- `ipa-multipoint/` — IPA proof system

---

## Architecture

### Two-Tier Trie

```
Level 0: Root (1 node)
Level 1: 256 nodes
Level 2: 65,536 nodes
Level 3: 16,777,216 buckets (leaf nodes)
         └── each bucket → dynamic subtree (1–5 levels, up to 2^40 slots)
```

- Buckets 0–65,535: **metadata buckets** (store config for data buckets)
- Buckets 65,536–16,777,215: **data buckets** (store actual key-value pairs)

### Key Abstractions

| Type | Role |
|------|------|
| `SaltKey` | 64-bit key: 24-bit bucket ID + 40-bit slot ID |
| `SaltValue` | Encoded `(plain_key, plain_value)` pair |
| `BucketMeta` | Bucket config: `nonce`, `capacity`, `used` |
| `StateUpdates` | Batch of `(key → (old, new))` changes |
| `TrieUpdates` | Batch of `(node_id → (old_commitment, new_commitment))` |

---

## Core Workflows

### 1. Insert / Update State

```rust
let store = MemStore::new();
let mut state = EphemeralSaltState::new(&store);

let kvs = HashMap::from([
    (b"account1".to_vec(), Some(b"balance100".to_vec())),
    (b"key_to_delete".to_vec(), None),  // None = delete
]);

let state_updates = state.update_fin(&kvs)?;
store.update_state(state_updates.clone());
```

Use `update()` + `canonicalize()` for incremental batches:

```rust
let updates1 = state.update(&batch1)?;
let updates2 = state.update(&batch2)?;
let final_updates = state.canonicalize()?;  // must call this!
```

### 2. Read State

```rust
// Via EphemeralSaltState (mutable, supports partial backends)
let value: Option<Vec<u8>> = state.plain_value(b"account1")?;

// Via PlainStateProvider (immutable, full state only, zero allocation)
let provider = PlainStateProvider::new(&store);
let value = provider.plain_value(b"account1", None)?;
// Optional bucket hint for performance:
let value = provider.plain_value(b"account1", Some(bucket_id))?;
```

### 3. Compute State Root

```rust
// Incremental update (preferred)
let mut state_root = StateRoot::new(&store);
let (root_hash, trie_updates) = state_root.update_fin(&state_updates)?;
store.update_trie(trie_updates);

// Full rebuild from scratch
let (root_hash, trie_updates) = StateRoot::rebuild(&store)?;
```

### 4. Create and Verify Witnesses

```rust
// Alice creates a witness
let lookups = vec![b"account1".to_vec(), b"missing_key".to_vec()];
let witness = Witness::create([], &lookups, &BTreeMap::new(), &store)?;

// Bob verifies
assert_eq!(root_hash, witness.state_root().unwrap());
assert!(witness.verify().is_ok());

// Bob reads values from the witness
let mut bob_state = EphemeralSaltState::new(&witness);
let value = bob_state.plain_value(b"account1")?;
```

---

## Key Types and Traits

### `StateReader` trait (`traits.rs`)

Implement this to plug in a custom storage backend:

```rust
fn value(&self, key: SaltKey) -> Result<Option<SaltValue>, Self::Error>;
fn entries(&self, range: RangeInclusive<SaltKey>) -> Result<Vec<(SaltKey, SaltValue)>, Self::Error>;
fn metadata(&self, bucket_id: BucketId) -> Result<BucketMeta, Self::Error>;
fn plain_value_fast(&self, plain_key: &[u8]) -> Result<SaltKey, Self::Error>;
```

`plain_value_fast` is required for partial state backends (witnesses). Full state backends may return `Err`.

### `EphemeralSaltState` (`state/state.rs`)

Non-persistent mutable view over any `StateReader`. Buffers all writes in a `HashMap` cache. Key methods:

- `new(store)` — create view
- `cache_read()` — also cache reads (useful for proof generation)
- `plain_value(key)` — lookup by plain key
- `update(kvs)` — accumulate changes
- `update_fin(kvs)` — update + canonicalize in one call
- `canonicalize()` — finalize bucket layouts, return `StateUpdates`
- `set_nonce(bucket_id, nonce)` — manual rehash with new nonce

### `MemStore` (`mem_store.rs`)

Reference in-memory backend. Thread-safe via `RwLock`. Use for tests and development only.

---

## Important Constants (`constant.rs`)

| Constant | Value | Meaning |
|----------|-------|---------|
| `MIN_BUCKET_SIZE` | 256 | Minimum slots per bucket |
| `NUM_BUCKETS` | 16,777,216 | Total buckets (256³) |
| `NUM_META_BUCKETS` | 65,536 | Metadata-only buckets |
| `BUCKET_RESIZE_LOAD_FACTOR_PCT` | 80 | Resize threshold (%) |
| `BUCKET_RESIZE_MULTIPLIER` | 2 | Capacity multiplier on resize |
| `MAX_SUBTREE_LEVELS` | 5 | Max levels in a bucket subtree |
| `TRIE_WIDTH` | 256 | Branch factor |

---

## Running Tests

```bash
# All tests
cargo test

# Library unit tests only
cargo test --lib

# With bucket resize testing (sets resize threshold to 1% by default)
cargo test --features test-bucket-resize

# Control resize threshold via env var
BUCKET_RESIZE_LOAD_FACTOR_PCT=50 cargo test --features test-bucket-resize

# Benchmarks
cargo bench
```

---

## File Map

```
salt/src/
├── lib.rs              — public re-exports, integration test
├── types.rs            — SaltKey, SaltValue, BucketMeta, NodeId, ...
├── traits.rs           — StateReader, TrieReader
├── constant.rs         — all numeric constants
├── mem_store.rs        — MemStore (in-memory backend)
├── state/
│   ├── state.rs        — EphemeralSaltState, PlainStateProvider, SHI algorithm
│   ├── updates.rs      — StateUpdates
│   └── hasher.rs       — bucket_id(), hash_with_nonce()
├── trie/
│   ├── trie.rs         — StateRoot, TrieUpdates
│   └── node_utils.rs   — NodeId helpers
└── proof/
    ├── mod.rs          — Witness, SaltProof public API
    ├── prover.rs       — proof construction
    └── witness.rs      — witness verification + StateReader impl
```

---

## SHI Hash Table Notes

SALT uses Strongly History-Independent (SHI) hash tables inside each bucket:

- **Linear probing with key swapping**: keys are stored in lexicographic order along the probe chain
- **Deterministic layout**: same set of key-value pairs always produces the same bucket layout regardless of insertion order
- **Canonicalization**: after incremental updates, call `canonicalize()` to prevent premature bucket expansions
- **Rehashing**: changing a bucket's nonce reassigns all keys to new slots while preserving all data
