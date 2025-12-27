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

### Proof

SALT provides cryptographic proofs for both the existence (membership) and non-existence (non-membership) of keys in the authenticated key-value store. These proofs leverage the deterministic properties of the SHI (Strongly History-Independent) hash table to create compact, verifiable witnesses.

#### Membership Proof (Key Exists)

To prove that a key exists in SALT, the proof simply includes:
1. **The bucket slot** containing the key-value pair
2. **The SALT path** from the bucket to the root
3. **The IPA proof** for the bucket's vector commitment

Since the key is present at a specific slot determined by the SHI algorithm, verifiers can:
- Confirm the key-value pair exists at the claimed slot
- Verify the cryptographic path to the state root
- Validate that the value matches the expected data

#### Non-Membership Proof (Key Doesn't Exist)

Proving non-existence is more complex due to the SHI hash table's linear probing mechanism. The proof must demonstrate that the key cannot exist anywhere in its probe sequence:

1. **Probe Sequence**: Starting from the slot determined by `hash(key, nonce) % capacity`, the proof includes all slots in the linear probe sequence until reaching either:
   - An **empty slot** - indicating the key was never inserted
   - A slot containing a **lexicographically smaller key** - due to SHI's ordering property, the target key cannot exist beyond this point

2. **SHI Ordering Invariant**: The SHI algorithm maintains that during insertion, smaller keys displace larger keys. Therefore, if we encounter a key smaller than our target during probing, we know the target key cannot exist in the bucket.

3. **Proof Contents**: The non-membership proof includes:
   - All bucket slots in the probe sequence (potentially multiple consecutive slots)
   - The SALT path from the bucket to the root
   - The IPA proof covering all accessed slots

#### Example

Consider proving non-existence of key "foo" in a bucket:
```
Bucket slots:
[0]: "bar"    <- hash("foo") maps here, but "bar" < "foo", continue probing
[1]: "qux"    <- "qux" > "foo", continue probing
[2]: "xyz"    <- "xyz" > "foo", continue probing
[3]: empty    <- Empty slot found, "foo" doesn't exist

Proof includes: slots 0-3 with their values
```

Or with early termination:
```
Bucket slots:
[0]: "bar"    <- hash("foo") maps here, but "bar" < "foo", continue probing
[1]: "egg"    <- "egg" < "foo", stop here (SHI ordering violated)

Proof includes: slots 0-1 with their values
```

This approach ensures that proofs are minimal (only including necessary slots) while remaining cryptographically sound and efficiently verifiable.

## Project Architecture

SALT is implemented as a Rust workspace with three main crates that work together to provide an efficient authenticated key-value store:

### Core Components

#### 1. Banderwagon (`banderwagon/`)
**Purpose**: High-performance elliptic curve operations over the Bandersnatch curve

- **Key Features**:
  - Optimized group operations for the prime subgroup of Bandersnatch
  - Multi-scalar multiplication (MSM) with precomputation tables
  - Memory-efficient operations with optional hugepage support
  - SIMD-optimized scalar multiplication
- **Core Types**:
  - `Element`: Group elements on the curve
  - `Fr`: Scalar field elements
  - `Committer`: High-level commitment interface for SALT

#### 2. IPA Multipoint (`ipa-multipoint/`)
**Purpose**: Vector commitment scheme using Inner Product Arguments

- **Key Features**:
  - Homomorphic commitments enabling incremental updates
  - Multi-point polynomial opening proofs
  - Optimized Lagrange basis operations
  - Transcript-based Fiat-Shamir transformation
- **Core Components**:
  - `MultiPoint`: Multi-point proof generation and verification
  - `IPAProof`: Inner product argument proofs
  - `CRS`: Common reference string for trusted setup
  - `LagrangeBasis`: Efficient polynomial evaluations

#### 3. SALT (`salt/`)
**Purpose**: The main authenticated key-value store implementation

- **Architecture Layers**:
  - **Storage Layer** (`state` module):
    - Manages key-value pairs using SHI hash tables
    - Implements bucket operations (insert, delete, lookup)
    - Handles dynamic bucket resizing and metadata
  - **Authentication Layer** (`trie` module):
    - Maintains cryptographic commitments for all nodes
    - Computes state root using incremental updates
    - Manages bucket subtree expansion/contraction
  - **Proof Layer** (`proof` module):
    - Generates inclusion/exclusion proofs
    - Creates block witnesses for state transitions
    - Verifies proofs against state root

- **Core Types**:
  - `EphemeralSaltState`: Non-persistent state view with caching
  - `StateRoot`: Incremental state root computation
  - `MemStore`: Thread-safe in-memory storage backend
  - `SaltKey`/`SaltValue`: Encoded key-value pairs
  - `PlainKeysProof`: Inclusion/exclusion proofs for plain keys

### Architectural Design

```
┌──────────────────────────────────────────────────────────────────┐
│                    Application Layer                             │
│               (Plain key-value operations)                       │
└────────────────────────┬─────────────────────────────────────────┘
                         │
┌────────────────────────▼─────────────────────────────────────────┐
│                    State Management Layer                        │
│  ┌──────────────────────────────────────────────────────────┐    │
│  │ EphemeralSaltState: SHI hash table operations            │    │
│  │ • Bucket lookups, insertions, deletions                  │    │
│  │ • Dynamic resizing and rehashing                         │    │
│  │ • Change tracking and state updates                      │    │
│  └──────────────────────┬───────────────────────────────────┘    │
└─────────────────────────┼────────────────────────────────────────┘
                          │
┌─────────────────────────▼────────────────────────────────────────┐
│                    Authentication Layer                          │
│  ┌──────────────────────────────────────────────────────────┐    │
│  │ StateRoot: Cryptographic commitment management           │    │
│  │ • Incremental commitment updates using homomorphism      │    │
│  │ • 4-level main trie + dynamic bucket subtrees            │    │
│  │ • Batch updates with delta propagation                   │    │
│  └──────────────────────┬───────────────────────────────────┘    │
└─────────────────────────┼────────────────────────────────────────┘
                          │
┌─────────────────────────▼────────────────────────────────────────┐
│                    Cryptographic Layer                           │
│  ┌─────────────────┐        ┌──────────────────┐                 │
│  │ IPA Multipoint  │◄───────┤   Banderwagon    │                 │
│  │ • IPAProof      │        │ • Element ops    │                 │
│  │ • Committer     │        │ • MSM operations │                 │
│  └─────────────────┘        └──────────────────┘                 │
└──────────────────────────────────────────────────────────────────┘
```

### Data Flow

1. **Write Path**:
   - Application submits key-value updates
   - State layer applies SHI hash table operations to buckets
   - Authentication layer computes commitment deltas
   - Deltas propagate up the trie to update state root
   - Storage backend persists state and trie updates

2. **Read Path**:
   - Application queries by plain key
   - State layer locates bucket and performs SHI lookup
   - Returns value if found, None otherwise

3. **Proof Generation**:
   - Collect all affected bucket commitments
   - Build SALT paths from buckets to root
   - Generate IPA proofs for bucket contents
   - Package into verifiable witness

### Storage Abstraction

SALT cleanly separates storage from authentication through trait interfaces:

- **`StateReader`**: Read-only access to bucket data
- **`TrieReader`**: Read-only access to node commitments
- **`MemStore`**: Reference implementation using `RwLock<HashMap>`

This allows plugging in different storage backends (RocksDB, PostgreSQL, etc.) without changing the core logic.

### Hugepage Configuration (Linux)

By default, SALT uses standard memory allocation for compatibility. For optimal performance with large precomputation tables, you can enable hugepages:

```bash
# Check current hugepage allocation
grep HugePages /proc/meminfo

# Allocate hugepages (requires ~400MB for precomputation tables)
sudo sysctl -w vm.nr_hugepages=1024
```

To enable hugepages when building SALT:

```bash
cargo build --features enable-hugepages
cargo test --features enable-hugepages
```

Or enable it in your Cargo.toml:

```toml
[dependencies]
salt = { path = "path/to/salt", features = ["enable-hugepages"] }
```

## Development and Testing

### Bucket Resize Testing Feature

For testing and debugging purposes, SALT includes a `test-bucket-resize` feature that facilitates testing of bucket expansion behavior by:
1. Concentrating keys into a smaller number of buckets instead of the full range of ~16.7 million data buckets
2. Using a much lower load factor threshold to trigger bucket expansions more easily

#### Usage

Enable the feature with cargo:
```bash
# Use defaults (2 buckets, 1% load factor)
cargo test --features test-bucket-resize

# Configure custom settings
NUM_DATA_BUCKETS=5 BUCKET_RESIZE_LOAD_FACTOR_PCT=5 cargo test --features test-bucket-resize
NUM_DATA_BUCKETS=3 BUCKET_RESIZE_LOAD_FACTOR_PCT=1 cargo build --features test-bucket-resize
```

## References

### Papers & Blog Posts
- [Bandersnatch Curve Specification](https://eprint.iacr.org/2021/1152.pdf)
- [Understanding The Wagon - From Bandersnatch to Banderwagon](https://hackmd.io/@kevaundray/BJBNcv9fq)
- [Verkle Trees and Vector Commitments](https://hackmd.io/@6iQDuIePQjyYBqDChYw_jg/BJ2-L6Nzc)
- [Anatomy of a Verkle Proof](https://ihagopian.com/posts/anatomy-of-a-verkle-proof)
- [Inner Product Arguments (BCMS20)](https://eprint.iacr.org/2019/1177.pdf)

### Presentations & Talks
- [SALT: Breaking the I/O Bottleneck for Blockchains with a Scalable Authenticated Key-Value Store](https://x.com/yangl1996/status/1957487663818416406) - [Science and Engineering of Consensus 2025](https://tselab.stanford.edu/workshop-sbc25/), August 3rd, 2025
