//! SALT Trie Performance Benchmarks
//!
//! This module contains comprehensive benchmarks for measuring the performance of SALT's
//! state root computation under various real-world scenarios. The benchmarks help identify:
//!
//! - **Batch size impact**: How update size affects performance (1k vs 100k KVs)
//! - **Two-phase commit efficiency**: Benefits of incremental updates with delayed finalization
//! - **Bucket expansion overhead**: Performance impact when buckets grow beyond minimum size
//! - **Memory allocation patterns**: Cost of repeated trie creation vs reuse
//!
//! ## Benchmark Scenarios
//!
//! 1. **Large batch updates**: Simulates blockchain state sync or large imports
//! 2. **Moderate batch updates**: Represents typical block processing
//! 3. **Incremental updates**: Tests two-phase commit optimization for transaction batches
//! 4. **Repeated individual updates**: Measures overhead of non-batched processing
//! 5. **Expansion scenarios**: Tests performance with enlarged bucket capacities
//!
//! ## Running Benchmarks
//!
//! ```bash
//! cargo bench --package salt --bench salt_trie
//! ```
//!
//! Results show throughput in operations per second and help optimize SALT for different
//! usage patterns in blockchain and authenticated storage applications.

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use rand::{rngs::StdRng, Rng, SeedableRng};
use salt::{
    constant::{default_commitment, MIN_BUCKET_SIZE, NUM_BUCKETS, NUM_META_BUCKETS},
    empty_salt::EmptySalt,
    state::updates::*,
    traits::*,
    trie::trie::StateRoot,
    types::*,
};
use std::ops::Range;

/// Generates synthetic state updates for benchmarking SALT trie operations.
///
/// Creates realistic test data by generating random key-value pairs distributed across
/// data buckets (avoiding metadata buckets). Each update simulates insertions only,
/// with random 20-byte keys and 32-byte values.
///
/// # Data Generation Strategy
///
/// - **Bucket selection**: Random buckets from data range (`NUM_META_BUCKETS..NUM_BUCKETS`)
/// - **Bucket ordering**: Sorted by ID for better cache locality during benchmarking
/// - **Slot placement**: Random slots within minimum bucket size (0-255)
/// - **Operation type**: Insertions only (old_value = None, new_value = random)
///
/// # Arguments
///
/// * `num` - The number of `StateUpdates` objects to generate
/// * `l` - The number of key-value pairs in each `StateUpdates`
/// * `rng` - A seeded random number generator for reproducible benchmarks
///
/// # Returns
///
/// A vector of `StateUpdates`, each containing `l` random insertion operations.
fn gen_state_updates(num: usize, l: usize, rng: &mut StdRng) -> Vec<StateUpdates> {
    (0..num)
        .map(|_| {
            // Generate random bucket IDs from data bucket range (avoids metadata buckets)
            let mut bids: Vec<_> = (0..l)
                .map(|_| rng.gen_range(NUM_META_BUCKETS as BucketId..NUM_BUCKETS as BucketId))
                .collect();
            // Sort for better cache locality during benchmark execution
            bids.sort();
            let mut updates = StateUpdates::default();
            for bid in bids {
                // Create insertion operation: None -> Some(random_value)
                updates.add(
                    SaltKey::from((bid, rng.gen_range(0..MIN_BUCKET_SIZE as SlotId))),
                    None, // old_value: None indicates this is an insertion
                    Some(SaltValue::new(
                        &rng.gen::<[u8; 20]>(), // 20-byte random key
                        &rng.gen::<[u8; 32]>(), // 32-byte random value
                    )),
                );
            }
            updates
        })
        .collect()
}

/// Comprehensive benchmark suite for SALT trie state root computation performance.
///
/// Tests five different update patterns to identify optimal usage strategies and
/// performance characteristics under various real-world scenarios.
fn salt_trie_bench(_c: &mut Criterion) {
    let mut bench = Criterion::default();
    let mut rng = StdRng::seed_from_u64(42);

    // Pre-initialize cryptographic precomputation tables to ensure consistent timing
    let _ = StateRoot::new();

    // BENCHMARK 1: Large Batch Update (100,000 KVs)
    // Simulates: Blockchain state sync, large data imports, initial state population
    // Tests: Performance with massive single updates, memory allocation patterns
    // Expected: High absolute time but good amortized cost per KV
    bench.bench_function("salt trie update 100k KVs", |b| {
        b.iter_batched(
            || gen_state_updates(1, 100_000, &mut rng), // Setup: Generate test data
            |inputs| {
                // Measured operation: Single large update with immediate finalization
                black_box(
                    StateRoot::new()
                        .update_fin_one(&EmptySalt, &inputs.into_iter().next().unwrap())
                        .unwrap(),
                )
            },
            criterion::BatchSize::SmallInput, // Data generation cost is small vs computation
        );
    });

    // BENCHMARK 2: Moderate Batch Update (1,000 KVs)
    // Simulates: Typical blockchain block processing, application batch operations
    // Tests: Performance sweet spot for most real-world usage
    // Expected: Good balance of throughput and latency
    bench.bench_function("salt trie update 1k KVs", |b| {
        b.iter_batched(
            || gen_state_updates(1, 1_000, &mut rng),
            |inputs| {
                black_box(
                    StateRoot::new()
                        .update_fin_one(&EmptySalt, &inputs.into_iter().next().unwrap())
                        .unwrap(),
                )
            },
            criterion::BatchSize::SmallInput,
        );
    });

    // BENCHMARK 3: Two-Phase Commit Pattern (10 × 100 KVs)
    // Simulates: Transaction processing with delayed root computation
    // Tests: Efficiency of update() + finalize() vs repeated update_fin()
    // Expected: Better performance than Benchmark 4 due to batched commitment computation
    bench.bench_function("salt trie incremental update 10 * 100 KVs", |b| {
        b.iter_batched(
            || gen_state_updates(10, 100, &mut rng),
            |inputs| {
                black_box({
                    let mut trie = StateRoot::new();
                    // Accumulate multiple updates without computing intermediate roots
                    for state_updates in inputs.into_iter() {
                        trie.update(&EmptySalt, &EmptySalt, &state_updates).unwrap();
                    }
                    // Single expensive commitment computation at the end
                    trie.finalize(&EmptySalt).unwrap()
                })
            },
            criterion::BatchSize::SmallInput,
        );
    });

    // BENCHMARK 4: Repeated Individual Updates (10 × 100 KVs)
    // Simulates: Processing transactions individually (anti-pattern)
    // Tests: Overhead of repeated StateRoot creation and full commitment computation
    // Expected: Worse performance than Benchmark 3, shows cost of not batching
    bench.bench_function("salt trie update 10 * 100 KVs", |b| {
        b.iter_batched(
            || gen_state_updates(10, 100, &mut rng),
            |inputs| {
                {
                    // Anti-pattern: Create fresh trie and compute root for each update
                    for state_updates in inputs.into_iter() {
                        StateRoot::new()
                            .update_fin_one(&EmptySalt, &state_updates)
                            .unwrap();
                    }
                }
                black_box(()) // Measure total time of all operations combined
            },
            criterion::BatchSize::SmallInput,
        );
    });

    // BENCHMARK 5: Expanded Buckets Scenario (100,000 KVs)
    // Simulates: High-load buckets that have grown beyond minimum 256-slot capacity
    // Tests: Performance impact of bucket subtree creation and larger commitment vectors
    // Expected: Slower than Benchmark 1 due to subtree management overhead
    bench.bench_function("salt trie update 100k expansion KVs", |b| {
        b.iter_batched(
            || gen_state_updates(1, 100_000, &mut rng),
            |inputs| {
                black_box({
                    let reader = &MockExpandedBuckets::new(65536 * 16, 512);
                    StateRoot::new()
                        .update_fin_one(reader, &inputs.into_iter().next().unwrap())
                        .unwrap()
                })
            },
            criterion::BatchSize::SmallInput,
        );
    });
}

/// Mock storage backend that simulates buckets with expanded capacities.
///
/// This test creates a scenario where some buckets have grown beyond the
/// minimum 256-slot capacity, triggering bucket subtree creation and testing
/// the performance impact of expanded bucket management.
///
/// # Configuration
///
/// - **Expanded buckets**: First N buckets have larger capacity
/// - **Standard buckets**: All other buckets have the minimum 256 slots
///
/// # Usage in Benchmarks
///
/// Used in "expansion KVs" benchmark to measure performance when SALT must:
/// - Create bucket subtrees for large buckets
/// - Compute commitment vectors for expanded slots instead of 256
/// - Handle the additional tree navigation overhead
///
/// All storage operations return empty results since this is purely for measuring
/// commitment computation performance, not data retrieval.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MockExpandedBuckets {
    /// Number of buckets that have expanded capacity
    expanded_bucket_count: u64,
    /// Capacity of expanded buckets (should be multiple of 256)
    expanded_capacity: u64,
}

impl MockExpandedBuckets {
    /// Creates a new mock with specified expansion configuration.
    ///
    /// # Arguments
    /// * `expanded_bucket_count` - Number of buckets with expanded capacity
    /// * `expanded_capacity` - Capacity for expanded buckets (should be multiple of 256)
    pub fn new(expanded_bucket_count: u64, expanded_capacity: u64) -> Self {
        Self {
            expanded_bucket_count,
            expanded_capacity,
        }
    }
}

impl TrieReader for MockExpandedBuckets {
    type Error = SaltError;

    fn commitment(&self, node_id: NodeId) -> Result<CommitmentBytes, Self::Error> {
        Ok(default_commitment(node_id))
    }

    fn node_entries(
        &self,
        _range: Range<NodeId>,
    ) -> Result<Vec<(NodeId, CommitmentBytes)>, Self::Error> {
        Ok(vec![])
    }
}

impl StateReader for MockExpandedBuckets {
    type Error = SaltError;

    fn value(&self, _key: SaltKey) -> Result<Option<SaltValue>, Self::Error> {
        Ok(None)
    }

    fn metadata(&self, bucket_id: BucketId) -> Result<BucketMeta, Self::Error> {
        assert!(bucket_id >= NUM_META_BUCKETS as BucketId);

        let metadata = BucketMeta {
            capacity: if u64::from(bucket_id)
                < (NUM_META_BUCKETS as u64 + self.expanded_bucket_count)
            {
                self.expanded_capacity
            } else {
                MIN_BUCKET_SIZE as u64
            },
            used: Some(0),
            ..Default::default()
        };
        Ok(metadata)
    }

    fn entries(
        &self,
        _range: std::ops::RangeInclusive<SaltKey>,
    ) -> Result<Vec<(SaltKey, SaltValue)>, Self::Error> {
        Ok(vec![])
    }

    fn plain_value_fast(&self, _plain_key: &[u8]) -> Result<SaltKey, Self::Error> {
        Err("`MockExpandedBuckets` salt has no keys".into())
    }
}

criterion_group!(benches, salt_trie_bench);
criterion_main!(benches);
