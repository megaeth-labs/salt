# SALT: Small Authentication Large Trie

SALT is a next-generation state trie data structure designed to replace Merkle Patricia Tries (MPT) in high-performance blockchain systems like Megaeth. The project implements a memory and I/O efficient trie that can fit entirely in memory, eliminating disk I/O during state root updates.

## Overview

SALT provides the interface of an authenticated key-value store (AKVS) with two primary functionalities:
- **Storage**: Store blockchain state as key-value pairs
- **Authentication**: Compute deterministic, cryptographically secure hash values that uniquely identify blockchain state

The trie features a shallow and wide structure (e.g., 4-level trie with 256 branch factor) containing ~16 million leaf nodes called "buckets". Each bucket stores key-value pairs using a strongly history-independent (SHI) hash table, ensuring internal representation depends only on the set of key-value pairs, not insertion/deletion order.

## Architecture

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
