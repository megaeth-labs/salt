#![allow(missing_docs)]

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use rand::{rngs::StdRng, Rng, SeedableRng};
use salt::{
    constant::{zero_commitment, MIN_BUCKET_SIZE, NUM_BUCKETS, NUM_META_BUCKETS},
    empty_salt::EmptySalt,
    state::updates::*,
    traits::*,
    trie::trie::StateRoot,
    types::*,
};
use std::ops::Range;

/// Generates a series of fixed-size state updates.
///
/// # Arguments
///
/// * `len` - The number of state updates to generate.
/// * `s` - The number of key-value pairs in each state update.
/// * `rng` - A mutable reference to a random number generator.
///
/// # Returns
///
/// A vector of `StateUpdates` containing the generated state updates.
fn gen_state_updates(num: usize, l: usize, rng: &mut StdRng) -> Vec<StateUpdates> {
    (0..num)
        .map(|_| {
            let mut bids: Vec<_> = (0..l)
                .map(|_| rng.gen_range(NUM_META_BUCKETS as BucketId..NUM_BUCKETS as BucketId))
                .collect();
            bids.sort();
            let mut updates = StateUpdates::default();
            for bid in bids {
                updates.add(
                    SaltKey::from((bid, rng.gen_range(0..MIN_BUCKET_SIZE as SlotId))),
                    None,
                    Some(SaltValue::new(
                        &rng.gen::<[u8; 20]>(),
                        &rng.gen::<[u8; 32]>(),
                    )),
                );
            }
            updates
        })
        .collect()
}

/// This function sets up and runs a series of benchmarks to measure the performance
/// of updating the state trie with different numbers of key-value pairs (KVs).
/// The benchmarks include:
///
/// - Updating the state trie with 100,000 KVs in a single update.
/// - Updating the state trie with 1,000 KVs in a single update.
/// - Incrementally updating the state trie with 1,000 KVs in batches of 100 KVs each.
/// - Updating the state trie 10 times with a total of 1,000 KVs.
fn salt_trie_bench(_c: &mut Criterion) {
    let mut bench = Criterion::default();
    let mut rng = StdRng::seed_from_u64(42);
    // Initialize the committer by creating a StateRoot instance before benchmarking
    let _ = StateRoot::new(&EmptySalt);

    bench.bench_function("salt trie update 100k KVs", |b| {
        b.iter_batched(
            || gen_state_updates(1, 100_000, &mut rng),
            |state_updates_vec| {
                black_box(
                    StateRoot::new(&EmptySalt)
                        .update_fin(&state_updates_vec[0])
                        .unwrap(),
                )
            },
            criterion::BatchSize::SmallInput,
        );
    });

    bench.bench_function("salt trie update 1k KVs", |b| {
        b.iter_batched(
            || gen_state_updates(1, 1_000, &mut rng),
            |state_updates_vec| {
                black_box(
                    StateRoot::new(&EmptySalt)
                        .update_fin(&state_updates_vec[0])
                        .unwrap(),
                )
            },
            criterion::BatchSize::SmallInput,
        );
    });

    bench.bench_function("salt trie incremental update 10 * 100 KVs", |b| {
        b.iter_batched(
            || gen_state_updates(10, 100, &mut rng),
            |state_updates_vec| {
                black_box({
                    let mut trie = StateRoot::new(&EmptySalt);
                    for state_updates in state_updates_vec.iter() {
                        trie.update(state_updates).unwrap();
                    }
                    trie.finalize().unwrap()
                })
            },
            criterion::BatchSize::SmallInput,
        );
    });

    bench.bench_function("salt trie update 10 * 100 KVs", |b| {
        b.iter_batched(
            || gen_state_updates(10, 100, &mut rng),
            |state_updates_vec| {
                {
                    for state_updates in state_updates_vec.iter() {
                        StateRoot::new(&EmptySalt)
                            .update_fin(state_updates)
                            .unwrap();
                    }
                }
                black_box(())
            },
            criterion::BatchSize::SmallInput,
        );
    });

    bench.bench_function("salt trie update 100k expansion KVs", |b| {
        b.iter_batched(
            || gen_state_updates(1, 100_000, &mut rng),
            |state_updates_vec| {
                black_box({
                    StateRoot::new(&ExpansionSalt((65536 * 16, 512)))
                        .update_fin(&state_updates_vec[0])
                        .unwrap()
                })
            },
            criterion::BatchSize::SmallInput,
        );
    });
}

/// This is a testing module that returns expansion information.
/// When the bucket_id is less than the first parameter,
/// it returns the capacity value of the second parameter
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct ExpansionSalt((u64, u64));

impl TrieReader for ExpansionSalt {
    type Error = &'static str;

    fn commitment(&self, _node_id: NodeId) -> Result<CommitmentBytes, Self::Error> {
        Ok(zero_commitment())
    }

    fn node_entries(
        &self,
        _range: Range<NodeId>,
    ) -> Result<Vec<(NodeId, CommitmentBytes)>, Self::Error> {
        Ok(vec![])
    }
}

impl StateReader for ExpansionSalt {
    type Error = &'static str;

    fn value(&self, _key: SaltKey) -> Result<Option<SaltValue>, Self::Error> {
        Ok(None)
    }

    fn metadata(&self, bucket_id: BucketId) -> Result<BucketMeta, Self::Error> {
        let meta = BucketMeta {
            capacity: if bucket_id < self.0 .0 as BucketId {
                self.0 .1
            } else {
                MIN_BUCKET_SIZE as u64
            },
            used: Some(self.bucket_used_slots(bucket_id)?),
            ..Default::default()
        };
        Ok(meta)
    }

    fn entries(
        &self,
        _range: std::ops::RangeInclusive<SaltKey>,
    ) -> Result<Vec<(SaltKey, SaltValue)>, Self::Error> {
        Ok(vec![])
    }
}

criterion_group!(benches, salt_trie_bench);
criterion_main!(benches);
