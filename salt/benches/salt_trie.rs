//! SALT Trie Performance Benchmarks
//!
//! This module contains comprehensive benchmarks for measuring the performance of SALT's
//! state root computation through both incremental updates and full state reconstruction
//! under various real-world scenarios. The benchmarks help identify:
//!
//! - **Batch size impact**: How update size affects performance (1k vs 100k KVs)
//! - **Two-phase commit efficiency**: Benefits of incremental updates with delayed finalization
//! - **Bucket expansion overhead**: Performance impact when buckets grow beyond minimum size
//! - **Rebuild scaling characteristics**: How full state reconstruction scales with state size
//!
//! ## Running Benchmarks
//!
//! ```bash
//! cargo bench --package salt --bench salt_trie
//! ```
//!
//! Results show throughput in operations per second and scaling characteristics, helping
//! optimize SALT for different usage patterns including incremental updates during normal
//! operation and full state reconstruction for recovery or verification scenarios.

use criterion::{criterion_group, criterion_main, Criterion};
use rand::{rngs::StdRng, Rng, SeedableRng};
use salt::{
    constant::{default_commitment, MIN_BUCKET_SIZE, NUM_BUCKETS, NUM_META_BUCKETS},
    empty_salt::EmptySalt,
    state::updates::*,
    traits::*,
    trie::trie::StateRoot,
    types::*,
};
use std::collections::HashSet;
use std::hint::black_box;
use std::ops::Range;

/// Generates synthetic state updates for benchmarking SALT trie operations.
///
/// Creates realistic test data by generating random key-value pairs distributed across
/// data buckets (avoiding metadata buckets). Each update simulates insertions only,
/// with random 20-byte keys and 32-byte values.
///
/// # Arguments
///
/// * `num` - The number of `StateUpdates` objects to generate
/// * `l` - The number of unique key-value pairs in each `StateUpdates`
/// * `rng` - A seeded random number generator for reproducible benchmarks
///
/// # Returns
///
/// A vector of `StateUpdates`, each containing `l` random insertion operations.
fn gen_state_updates(num: usize, l: usize, rng: &mut StdRng) -> Vec<StateUpdates> {
    (0..num)
        .map(|_| {
            let mut updates = StateUpdates::default();
            let mut used_keys = HashSet::new();

            // Generate exactly `l` unique keys
            for _ in 0..l {
                let mut salt_key;
                // Retry until we find a unique key
                loop {
                    let bid = rng.gen_range(NUM_META_BUCKETS as BucketId..NUM_BUCKETS as BucketId);
                    let slot_id = rng.gen_range(0..MIN_BUCKET_SIZE as SlotId);
                    salt_key = SaltKey::from((bid, slot_id));
                    if used_keys.insert(salt_key) {
                        break; // Found a unique key
                    }
                }

                // Create insertion operation: None -> Some(random_value)
                updates.add(
                    salt_key,
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
fn benchmark_trie_updates(c: &mut Criterion) {
    let mut rng = StdRng::seed_from_u64(42);

    // Pre-initialize cryptographic precomputation tables to ensure consistent timing
    let _ = StateRoot::new(&EmptySalt);

    // BENCHMARK 1: Large Batch Update (100,000 KVs)
    // Simulates: Blockchain state sync, large data imports, initial state population
    // Tests: Performance with massive single updates, memory allocation patterns
    // Expected: High absolute time but good amortized cost per KV
    c.bench_function("salt trie update 100k KVs", |b| {
        b.iter_batched(
            || gen_state_updates(1, 100_000, &mut rng), // Setup: Generate test data
            |inputs| {
                // Measured operation: Single large update with immediate finalization
                black_box(
                    StateRoot::new(&EmptySalt)
                        .update_fin(inputs.into_iter().next().unwrap())
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
    c.bench_function("salt trie update 1k KVs", |b| {
        b.iter_batched(
            || gen_state_updates(1, 1_000, &mut rng),
            |inputs| {
                black_box(
                    StateRoot::new(&EmptySalt)
                        .update_fin(inputs.into_iter().next().unwrap())
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
    c.bench_function("salt trie incremental update 10 * 100 KVs", |b| {
        b.iter_batched(
            || gen_state_updates(10, 100, &mut rng),
            |inputs| {
                black_box({
                    let mut trie = StateRoot::new(&EmptySalt);
                    // Accumulate multiple updates without computing intermediate roots
                    for state_updates in inputs.into_iter() {
                        trie.update(state_updates).unwrap();
                    }
                    // Single expensive commitment computation at the end
                    trie.finalize().unwrap()
                })
            },
            criterion::BatchSize::SmallInput,
        );
    });

    // BENCHMARK 4: Repeated Individual Updates (10 × 100 KVs)
    // Simulates: Processing transactions individually (anti-pattern)
    // Tests: Overhead of repeated StateRoot creation and full commitment computation
    // Expected: Worse performance than Benchmark 3, shows cost of not batching
    c.bench_function("salt trie update 10 * 100 KVs", |b| {
        b.iter_batched(
            || gen_state_updates(10, 100, &mut rng),
            |inputs| {
                {
                    // Anti-pattern: Create fresh trie and compute root for each update
                    for state_updates in inputs.into_iter() {
                        StateRoot::new(&EmptySalt)
                            .update_fin(state_updates)
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
    c.bench_function("salt trie update 100k expansion KVs", |b| {
        b.iter_batched(
            || gen_state_updates(1, 100_000, &mut rng),
            |inputs| {
                black_box({
                    StateRoot::new(&MockExpandedBuckets::new(65536 * 16, 512))
                        .update_fin(inputs.into_iter().next().unwrap())
                        .unwrap()
                })
            },
            criterion::BatchSize::SmallInput,
        );
    });
}

/// Benchmarks StateRoot::rebuild performance with different numbers of key-value pairs.
///
/// Tests rebuild performance across multiple scales from 1K to 1M key-value pairs,
/// measuring how the algorithm scales with state size. Each test distributes the
/// specified number of KVs evenly across all data buckets.
fn benchmark_trie_rebuild(c: &mut Criterion) {
    // Pre-initialize cryptographic precomputation tables for consistent timing
    let _ = StateRoot::new(&EmptySalt);

    // Test multiple scales: 1M, 10M KVs
    for num_kvs in [1_000_000, 10_000_000] {
        c.bench_function(&format!("rebuild {} KVs", num_kvs), |b| {
            b.iter(|| {
                let reader = MockRebuildReader::new(num_kvs);
                black_box(StateRoot::rebuild(&reader).unwrap())
            });
        });
    }
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
        Err(SaltError::UnsupportedOperation {
            operation: "MockExpandedBuckets::plain_value_fast",
        })
    }
}

/// Mock StateReader implementation for benchmarking StateRoot::rebuild performance.
///
/// This implementation generates key-value pairs on-demand during benchmark execution,
/// distributing the specified number of KV pairs evenly across all data buckets.
/// It avoids memory overhead by generating dummy values on the fly.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MockRebuildReader {
    /// Total number of key-value pairs to distribute across data buckets
    num_kvs: u64,
}

impl MockRebuildReader {
    /// Creates a new mock reader with the specified number of key-value pairs.
    ///
    /// # Arguments
    /// * `num_kvs` - Total number of plain key-value pairs to simulate
    pub fn new(num_kvs: u64) -> Self {
        Self { num_kvs }
    }

    /// Generates key-value pairs for a specific bucket within the given slot range.
    ///
    /// Uses even distribution logic to spread `num_kvs` across all data buckets,
    /// with remainder pairs distributed to the first few buckets.
    fn generate_bucket_entries(
        &self,
        bucket_id: BucketId,
        slot_start: SlotId,
        slot_end: SlotId,
    ) -> Vec<(SaltKey, SaltValue)> {
        use salt::constant::NUM_KV_BUCKETS;

        let data_bucket_index = bucket_id - NUM_META_BUCKETS as BucketId;
        let kvs_per_bucket = self.num_kvs / NUM_KV_BUCKETS as u64;
        let remainder = self.num_kvs % NUM_KV_BUCKETS as u64;

        // This bucket gets extra KV if it's within remainder range
        let bucket_kv_count = if data_bucket_index < remainder as BucketId {
            kvs_per_bucket + 1
        } else {
            kvs_per_bucket
        };

        let mut results = Vec::new();

        // Generate exactly bucket_kv_count entries using deterministic slots
        for i in 0..bucket_kv_count {
            let slot_id = (i % MIN_BUCKET_SIZE as u64) as SlotId;

            // Only include if slot is within requested range
            if slot_id >= slot_start && slot_id <= slot_end {
                let salt_key = SaltKey::from((bucket_id, slot_id));
                let salt_value = SaltValue::new(&[1u8; 32], &[1u8; 32]);
                results.push((salt_key, salt_value));
            }
        }

        results
    }
}

impl StateReader for MockRebuildReader {
    type Error = SaltError;

    fn value(&self, _key: SaltKey) -> Result<Option<SaltValue>, Self::Error> {
        // Not used by rebuild - return None for all queries
        Ok(None)
    }

    fn entries(
        &self,
        range: std::ops::RangeInclusive<SaltKey>,
    ) -> Result<Vec<(SaltKey, SaltValue)>, Self::Error> {
        let start_key = *range.start();
        let end_key = *range.end();

        let start_bucket = start_key.bucket_id();
        let end_bucket = end_key.bucket_id();

        let mut results = Vec::new();

        for bucket_id in start_bucket..=end_bucket {
            // Skip meta buckets - only generate data for data buckets
            if bucket_id < NUM_META_BUCKETS as BucketId {
                continue;
            }

            // Determine slot range for this bucket (max 256 slots)
            let slot_start = if bucket_id == start_bucket {
                start_key.slot_id()
            } else {
                0
            };
            let slot_end = if bucket_id == end_bucket {
                end_key.slot_id()
            } else {
                (MIN_BUCKET_SIZE - 1) as SlotId
            };

            // Generate KVs for this bucket within the slot range
            results.extend(self.generate_bucket_entries(bucket_id, slot_start, slot_end));
        }

        Ok(results)
    }

    fn metadata(&self, bucket_id: BucketId) -> Result<BucketMeta, Self::Error> {
        assert!(bucket_id >= NUM_META_BUCKETS as BucketId);
        Ok(BucketMeta::default())
    }

    fn plain_value_fast(&self, _plain_key: &[u8]) -> Result<SaltKey, Self::Error> {
        // Not used by rebuild - return error
        Err(SaltError::UnsupportedOperation {
            operation: "MockRebuildReader::plain_value_fast",
        })
    }
}

criterion_group!(benches, benchmark_trie_updates, benchmark_trie_rebuild);
criterion_main!(benches);
