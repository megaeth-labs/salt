//! SALT Proof & Witness Performance Benchmarks
//!
//! Measures the four hot paths of the proof layer:
//!
//! - `SaltProof::create`  — proof generation for a set of salt keys
//! - `SaltProof::check`   — proof verification against the state root
//! - `Witness::create`    — block witness generation (lookups + updates)
//! - `Witness::verify`    — block witness verification (stateless validator)
//!
//! ```bash
//! cargo bench --package salt --bench proof
//! ```

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use rand::{rngs::StdRng, Rng, SeedableRng};
use salt::{
    traits::StateReader, types::*, EphemeralSaltState, MemStore, SaltProof, StateRoot, Witness,
};
use std::collections::BTreeMap;
use std::hint::black_box;
use std::sync::OnceLock;
use std::time::Duration;

/// Number of key-value pairs pre-inserted into the store.
const INITIAL_KEYS: usize = 50_000;

struct Setup {
    store: MemStore,
    /// Plain keys that exist in the store.
    plain_keys: Vec<Vec<u8>>,
    /// Salt keys of all existing entries.
    salt_keys: Vec<SaltKey>,
    /// State root after setup.
    root: ScalarBytes,
}

fn mock_data(rng: &mut StdRng, len: usize) -> Vec<u8> {
    (0..len).map(|_| rng.random()).collect()
}

fn setup() -> &'static Setup {
    static SETUP: OnceLock<Setup> = OnceLock::new();
    SETUP.get_or_init(|| {
        let mut rng = StdRng::seed_from_u64(42);

        let kvs: hashbrown::HashMap<Vec<u8>, Option<Vec<u8>>> = (0..INITIAL_KEYS)
            .map(|_| (mock_data(&mut rng, 32), Some(mock_data(&mut rng, 32))))
            .collect();

        let store = MemStore::new();
        let updates = EphemeralSaltState::new(&store).update_fin(&kvs).unwrap();
        store.update_state(updates.clone());

        let (root, trie_updates) = StateRoot::new(&store).update_fin(&updates).unwrap();
        store.update_trie(trie_updates);

        let plain_keys: Vec<Vec<u8>> = kvs.keys().cloned().collect();
        let salt_keys: Vec<SaltKey> = updates
            .data
            .keys()
            .copied()
            .filter(|k| !k.is_in_meta_bucket())
            .collect();

        Setup {
            store,
            plain_keys,
            salt_keys,
            root,
        }
    })
}

/// Selects `n` existing salt keys plus a few non-existent ones (sorted, deduped).
fn proof_keys(s: &Setup, n: usize) -> Vec<SaltKey> {
    let mut keys: Vec<SaltKey> = s
        .salt_keys
        .iter()
        .step_by(s.salt_keys.len() / n)
        .copied()
        .collect();
    keys.truncate(n);
    // A few keys proven absent (bucket untouched by setup with default capacity).
    keys.push(SaltKey::from((16_777_215, 1)));
    keys.push(SaltKey::from((16_777_215, 254)));
    keys.sort_unstable();
    keys.dedup();
    keys
}

/// Builds the kv data map the verifier is given for `keys`.
fn proof_data(s: &Setup, keys: &[SaltKey]) -> BTreeMap<SaltKey, Option<SaltValue>> {
    keys.iter()
        .map(|&k| {
            let v = if k.is_in_meta_bucket() {
                Some(
                    s.store
                        .metadata(bucket_id_from_metadata_key(k))
                        .unwrap()
                        .into(),
                )
            } else {
                s.store.value(k).unwrap()
            };
            (k, v)
        })
        .collect()
}

fn bench_salt_proof(c: &mut Criterion) {
    let s = setup();

    let mut group = c.benchmark_group("salt_proof/create");
    group.sample_size(10);
    group.measurement_time(Duration::from_secs(10));
    for n in [16usize, 256, 2048] {
        let keys = proof_keys(s, n);
        group.bench_with_input(BenchmarkId::from_parameter(n), &keys, |b, keys| {
            b.iter(|| black_box(SaltProof::create(keys.iter().copied(), &s.store).unwrap()));
        });
    }
    group.finish();

    let mut group = c.benchmark_group("salt_proof/check");
    group.sample_size(10);
    group.measurement_time(Duration::from_secs(10));
    for n in [16usize, 256, 2048] {
        let keys = proof_keys(s, n);
        let proof = SaltProof::create(keys.iter().copied(), &s.store).unwrap();
        let data = proof_data(s, &keys);
        group.bench_with_input(
            BenchmarkId::from_parameter(n),
            &(proof, data),
            |b, (proof, data)| {
                b.iter(|| proof.check(black_box(data), s.root).unwrap());
            },
        );
    }
    group.finish();
}

/// Plain-key updates: key -> new value (None = delete).
type PlainUpdates = BTreeMap<Vec<u8>, Option<Vec<u8>>>;

/// A block-like workload: half the size is lookups (2/3 hits, 1/3 misses),
/// half is updates (1/2 overwrites of existing keys, 1/2 fresh inserts).
fn witness_workload(s: &Setup, n: usize, rng: &mut StdRng) -> (Vec<Vec<u8>>, PlainUpdates) {
    let half = n / 2;
    let hits = half * 2 / 3;
    let step = s.plain_keys.len() / half.max(1);

    let mut lookups: Vec<Vec<u8>> = s
        .plain_keys
        .iter()
        .step_by(step.max(1))
        .take(hits)
        .cloned()
        .collect();
    for _ in 0..(half - hits) {
        lookups.push(mock_data(rng, 32)); // misses
    }

    let mut updates = BTreeMap::new();
    for key in s
        .plain_keys
        .iter()
        .skip(1)
        .step_by(step.max(1))
        .take(half / 2)
    {
        updates.insert(key.clone(), Some(mock_data(rng, 32))); // overwrite
    }
    while updates.len() < half {
        updates.insert(mock_data(rng, 32), Some(mock_data(rng, 32))); // insert
    }

    (lookups, updates)
}

fn bench_witness(c: &mut Criterion) {
    let s = setup();
    let mut rng = StdRng::seed_from_u64(7);

    let mut group = c.benchmark_group("witness/create");
    group.sample_size(10);
    group.measurement_time(Duration::from_secs(15));
    for n in [256usize, 1024] {
        let (lookups, updates) = witness_workload(s, n, &mut rng);
        group.bench_with_input(
            BenchmarkId::from_parameter(n),
            &(lookups, updates),
            |b, (lookups, updates)| {
                b.iter(|| {
                    black_box(Witness::create([], lookups.iter(), updates, &s.store).unwrap())
                });
            },
        );
    }
    group.finish();

    let mut group = c.benchmark_group("witness/verify");
    group.sample_size(10);
    group.measurement_time(Duration::from_secs(15));
    for n in [256usize, 1024] {
        let (lookups, updates) = witness_workload(s, n, &mut rng);
        let witness = Witness::create([], lookups.iter(), &updates, &s.store).unwrap();
        assert_eq!(witness.state_root().unwrap(), s.root);
        group.bench_with_input(BenchmarkId::from_parameter(n), &witness, |b, witness| {
            b.iter(|| witness.verify().unwrap());
        });
    }
    group.finish();
}

criterion_group!(benches, bench_salt_proof, bench_witness);
criterion_main!(benches);
