# SALT: Small Authentication Large Trie

**SALT (Small Authentication Large Trie)** is a novel authenticated key-value store that powers <img src="https://github.com/megaeth-labs/.github/blob/main/profile/assets/logo.png" width="140" align=top>. SALT is highly memory- and I/O-efficient. For up to 3 billion key-value pairs, SALT's authentication layer requires only a 1 GB memory footprint, and it scales smoothly to tens of billions of items. Thus, SALT can fit entirely in the memory of most modern machines, relieving blockchain nodes of expensive random disk I/Os. To the best of our knowledge, SALT is the first authenticated KV store to scale to tens of billions of items and completely eliminate random disk I/Os during state root updates, all while maintaining its low memory footprint.

## Design

### Trie Structure

While inspired by Ethereum's Verkle trees, SALT's design differs substantially by avoiding the large, sparse nature of dynamic tries. It features a succinct two-tier architecture: a **static main trie** serves as the top tier, and **dynamic buckets** form the second tier. The main trie is a fixed, **4-level complete 256-ary trie**. The leaves of this trie don't hold values directly, but rather commitments to the buckets where the actual data resides.

A bucket itself is an open-addressing, **Strongly History-Independent (SHI) hash table** backed by a resizable array. This structure offers two key advantages. First, data within a bucket can be flattened for highly efficient authentication. By contrast, Verkle or MPT would represent the same data as a sparse sub-trie, requiring many internal nodes just to store intermediate commitments. Second, the SHI property guarantees a canonical commitment that is independent of the element insertion order.

SALT's wide and shallow trie structure is exceptionally efficient. Assuming each bucket holds 256 slots, SALT can authenticate over 4 billion data items using just 16.8 million commitments. As a result, the main trie can easily fit into memory, even on blockchain nodes running on low-cost hardware. The diagram below illustrates the structure of the main trie and the number of nodes at each level.
```
                      [ Level 1: Root (1 node) ]
                                 |
           +---------------------+---------------------+ ...
           |                     |                     |
[ Level 2 Node ]        [ Level 2 Node ]        [ Level 2 Node ]      (256 L2 nodes)
           |                     |
           v (L3)                v (L3)  ...                       (65,536 L3 nodes)
           |                     |
           v (L4)                v (L4)                        (16,777,216 leaf nodes)
   [ Leaf Node ]           [ Leaf Node ] ...
           |                     |
           v                     v
Commitment to Bucket      Commitment to Bucket
```

### Data Operations
SALT stores and authenticates key-value pairs of arbitrary sizes.

All operations—lookups, insertions, and deletions—begin by locating the correct bucket, after which the specific action is handled by that bucket's internal logic:
1. **Find the Bucket**: First, a hash of the key (`f(key) % 256^3`) is used to identify the correct bucket for the operation.
2. **Execute Bucket Operation**: Next, the bucket's internal SHI hash table algorithm is executed.
    * A lookup involves probing until the key's specific slot is found.
    * An insertion or deletion is more complex. The SHI algorithm may modify **multiple slots** to maintain the table's invariants, such as by shifting other items in a probe sequence.


### Efficient State Root Updates

Updating the state root in SALT is highly efficient. The process involves first updating the affected bucket's commitment, then propagating that change up the shallow main trie. For simplicity, we assume all buckets have a fixed capacity of 256 for now.

**Bucket Commitment Updates**

A bucket's commitment can be computed as follows:
1. Each key-value pair is hashed into a 32-byte value; empty slots are represented as a special value $\bot$.
2. A vector commitment scheme processes this entire array to produce the final commitment.

However, this process is very computationally expensive. To avoid this high cost on every change, SALT uses IPA with Pedersen commitments, a homomorphic vector commitment (VC) scheme, to perform incremental updates. When a slot's value changes, the commitment is efficiently modified with a single elliptic curve multiplication (ECMul) based on the delta between the old and new values.

**Update Propagation**

The main trie's internal nodes also use homomorphic commitments. After bucket commitments are changed, the updates propagate up the three parent levels to the state root. So, updating a single key-value pair results in a total of 4 EcMul operations.

While each step up the trie costs one ECMul, updates from multiple distinct child nodes are batched into a single update for their common parent. This optimization is extremely effective because the trie's width shrinks dramatically at higher levels, consolidating many changes at the leaf level into a small number of updates near the root. For example, updating 200,000 random keys in SALT requires a total of approximately 460,000 ECMul operations, or an amortized cost of about **2.3 ECMuls** per key.

### Bucket Growth
While the main SALT tree is static, the buckets are not. A bucket is initialized with 256 slots. When it fills up, it can be resized to a multiple of 256. If a bucket grows beyond 256 slots, it is partitioned into 256-slot segments. A new complete 256-ary **bucket tree** is built on top of these segments, and the root of this new tree becomes the bucket's new commitment (also the new leaf in the main trie). The diagram below shows a bucket tree of 768 slots.

```
(In Main SALT Trie)
      [ Leaf Node ]
            |
            +------------> [ Bucket Tree Root ]  <-- New commitment for the large bucket
                                    |
                  +-----------------+-----------------+ ...
                  |                 |                 |
      Commitment(Segment 0)  Commitment(Segment 1)  Commitment(Segment N)
                  ^                 ^                 ^
                  |                 |                 |
           [ Segment 0 ]     [ Segment 1 ]     [ Segment N ]
           (256 slots)       (256 slots)       (256 slots)
```

### DoS Attacks

TODO: meta buckets

### (Non-)Membership Proof

### Decoupling authentication and storage

authentication layer: contains all commitments; map from nodeId to commitments

storage layer: contains all data items; map from salt key to plainKV

## Project Architecture

This project consists of three main components organized as a Rust workspace:

### 1. Banderwagon (`banderwagon/`)
- **Purpose**: Elliptic curve group operations over the Bandersnatch curve
- **Key Features**:
  - Prime subgroup implementation over Bandersnatch curve
  - Multi-scalar multiplication (MSM) with precomputation
  - Efficient serialization and point operations
  - Memory-optimized operations with hugepage support
- **Core Types**: `Element`, `Fr` (field elements)

### 2. IPA Multipoint (`ipa-multipoint/`)
- **Purpose**: Inner Product Argument-based polynomial commitment scheme
- **Key Features**:
  - Polynomial commitments for opening multiple polynomials at different points
  - Vector commitment scheme using homomorphic properties
  - Transcript-based proofs following BCMS20 scheme
  - Lagrange basis operations and precomputed weights
- **Core Components**: `MultiPoint`, `IPAProof`, `Committer`, `CRS`

### 3. SALT (`salt/`)
- **Purpose**: Main SALT trie implementation
- **Architecture**:
  - **State Module**: Manages storage and access of key-value pairs in buckets
  - **Trie Module**: Maintains commitments of trie nodes
  - **Proof Module**: Generates and verifies cryptographic proofs
- **Core Types**: `MemSalt`, `EphemeralSaltState`, `StateRoot`, `SaltProof`

## Component Interactions

```
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│   Banderwagon   │    │  IPA Multipoint  │    │      SALT       │
│                 │    │                  │    │                 │
│ • Element       │◄───┤ • Committer      │◄───┤ • StateRoot     │
│ • Fr            │    │ • MultiPoint     │    │ • SaltProof     │
│ • MSM           │    │ • IPAProof       │    │ • MemSalt       │
└─────────────────┘    └──────────────────┘    └─────────────────┘
```

### Data Flow:
1. **State Updates**: Key-value pairs are stored in SALT buckets
2. **Commitment Generation**: Each bucket computes commitments using IPA vector commitments
3. **Trie Maintenance**: Internal nodes compute commitments of child nodes recursively
4. **Proof Generation**: Multi-point proofs are generated for state verification
5. **Cryptographic Operations**: All group operations use optimized Banderwagon curve arithmetic

## Key Features

### Memory Efficiency
- Shallow, wide trie structure minimizes depth
- In-memory storage eliminates disk I/O for state updates
- Hugepage support for optimized memory access patterns

### Cryptographic Security
- Uses Inner Product Arguments (IPA) for vector commitments
- History-independent hash tables ensure deterministic representation
- Banderwagon curve provides efficient group operations

### Performance Optimizations
- Parallel processing for large vector operations
- Precomputed tables for MSM operations
- Batch operations for field arithmetic

## Usage

### Basic Operations

```rust
use salt::{MemSalt, EphemeralSaltState};

// Create a new SALT instance
let salt = MemSalt::new();

// Create ephemeral state for tentative updates
let mut state = EphemeralSaltState::new(&salt);

// Update key-value pairs
state.set(key, value);

// Compute state root
let root = state.compute_state_root();
```

### Proof Generation

```rust
use salt::proof::create_salt_proof;

// Generate proof for specific keys
let proof = create_salt_proof(&keys, &state_reader, &trie_reader)?;

// Verify proof
let is_valid = proof.verify(&state_root, &keys, &values)?;
```

## Development Setup

### Prerequisites
- Rust 1.70+ with 2021 edition
- For optimal performance: Linux with hugepage support

### Building

```bash
# Clone the repository
git clone <repository-url>
cd salt

# Build all components
cargo build --release

# Run tests
cargo test

# Run benchmarks
cargo bench
```

### Hugepage Configuration (Linux)

By default, SALT uses standard memory allocation for compatibility. For optimal performance with large precomputed tables, you can enable hugepages:

```bash
# Check current hugepage allocation
grep HugePages /proc/meminfo

# Allocate hugepages (requires ~400MB for precomputed tables)
sudo sysctl -w vm.nr_hugepages=1024
```

To enable hugepages for better performance:

```toml
[dependencies]
banderwagon = { path = "banderwagon", features = ["enable-hugepages"] }
```

## Performance Characteristics

### Benchmarks (Apple M1 Pro, 16GB RAM)
- IPA prove (256 elements): ~28.7ms
- IPA verify (256 elements): ~20.8ms
- Multipoint verify (256/1000 proofs): ~8.6ms
- Multipoint verify (256/16000 proofs): ~69.4ms

### Scalability
- Supports millions of key-value pairs
- Parallel processing for operations >64 elements
- Optimized batch operations for field arithmetic

## Security Considerations

⚠️ **Warning**: This implementation is for research and development purposes. The code has not undergone security audits and should not be used in production environments.

### Known Limitations
- CRS generation is not cryptographically secure (relative DLOG is known)
- Requires proper hash-to-group implementation for production use
- Some optimizations (GLV endomorphism, full parallelization) not yet implemented

## Project Status

- **Current State**: Active development, proof-of-concept implementation
- **Testing**: Comprehensive unit and integration tests
- **Documentation**: Extensive inline documentation and examples
- **Benchmarking**: Performance benchmarks included

## Contributing

This project follows standard Rust development practices:
- Use `cargo fmt` for code formatting
- Run `cargo clippy` for linting
- Ensure all tests pass before submitting PRs
- Follow the existing code style and patterns

## License

Licensed under either of:
- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT License ([LICENSE-MIT](LICENSE-MIT))

at your option.

## References

- [Bandersnatch Curve Specification](https://eprint.iacr.org/2021/1152.pdf)
- [Verkle Trees and Vector Commitments](https://hackmd.io/@6iQDuIePQjyYBqDChYw_jg/BJ2-L6Nzc)
- [Inner Product Arguments (BCMS20)](https://eprint.iacr.org/2019/1177.pdf)
