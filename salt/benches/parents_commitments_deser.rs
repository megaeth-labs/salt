//! Microbenchmarks over real mainnet `SaltProof` fixtures, committed under
//! `benches/fixtures/*.proof` (legacy bincode, one proof per file).
//!
//! Two groups:
//! - `parents_commitments_deser` — sequential vs parallel deserialization of just the
//!   `parents_commitments` map, the witness-decode hot path this crate parallelizes. Each
//!   commitment costs a modular sqrt (point decompression) plus a subgroup check in
//!   `Element::from_bytes`, and a proof carries one per path node, so this map dominates decode.
//!   `sequential` is the derived per-element path; `parallel` is the overridden
//!   [`parents_commitments_serde::deserialize`].
//! - `salt_proof_codec` — full-`SaltProof` bincode `serialize` vs `deserialize` (deserialize uses
//!   the parallel override), showing the encode/decode asymmetry: encoding already-normalized
//!   commitments is cheap, decoding pays the per-point elliptic-curve work.
//!
//! ```bash
//! cargo bench --package salt --bench parents_commitments_deser
//! ```

use std::collections::BTreeMap;
use std::hint::black_box;

use bincode::config::legacy;
use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use salt::proof::SerdeCommitment;
use salt::{types::NodeId, SaltProof};

/// Directory of committed `SaltProof` fixtures, resolved relative to this crate at compile time.
const FIXTURES_DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/benches/fixtures");

/// One-field wrapper that routes deserialization through the optimized parallel path. A
/// single-field bincode struct adds no framing, so it decodes the same bytes as a bare map.
#[derive(serde::Deserialize)]
struct ParallelMap {
    #[serde(deserialize_with = "salt::proof::prover::parents_commitments_serde::deserialize")]
    inner: BTreeMap<NodeId, SerdeCommitment>,
}

/// A loaded fixture: the parsed proof, its on-wire bytes, and its `parents_commitments` map bytes.
struct Case {
    label: String,
    count: u64,
    proof: SaltProof,
    proof_bytes: Vec<u8>,
    map_wire: Vec<u8>,
}

/// Loads every `*.proof` fixture, sorted by name for deterministic benchmark ids.
fn corpus() -> Vec<Case> {
    let mut paths: Vec<_> = std::fs::read_dir(FIXTURES_DIR)
        .unwrap_or_else(|e| panic!("read fixtures dir {FIXTURES_DIR}: {e}"))
        .filter_map(|entry| entry.ok().map(|e| e.path()))
        .filter(|path| path.extension().and_then(|s| s.to_str()) == Some("proof"))
        .collect();
    assert!(!paths.is_empty(), "no .proof fixtures in {FIXTURES_DIR}");
    paths.sort();

    paths
        .into_iter()
        .map(|path| {
            let proof_bytes = std::fs::read(&path).expect("read fixture");
            let (proof, _): (SaltProof, usize) =
                bincode::serde::decode_from_slice(&proof_bytes, legacy()).expect("decode proof");
            let stem = path
                .file_stem()
                .unwrap_or_default()
                .to_string_lossy()
                .into_owned();
            let count = proof.parents_commitments.len() as u64;
            let map_wire = bincode::serde::encode_to_vec(&proof.parents_commitments, legacy())
                .expect("encode map");
            Case {
                label: format!("{stem}/{count}"),
                count,
                proof,
                proof_bytes,
                map_wire,
            }
        })
        .collect()
}

fn bench(c: &mut Criterion) {
    let corpus = corpus();

    // Sequential vs parallel deserialization of just the `parents_commitments` map.
    let mut group = c.benchmark_group("parents_commitments_deser");
    // Each `sequential` iteration is ~1s on a real fixture; cap samples so a full run stays short.
    group.sample_size(10);
    for case in &corpus {
        group.throughput(Throughput::Elements(case.count));
        group.bench_with_input(
            BenchmarkId::new("sequential", &case.label),
            &case.map_wire,
            |b, bytes| {
                b.iter(|| {
                    let (map, _): (BTreeMap<NodeId, SerdeCommitment>, usize) =
                        bincode::serde::decode_from_slice(black_box(bytes), legacy())
                            .expect("decode");
                    black_box(map)
                });
            },
        );
        group.bench_with_input(
            BenchmarkId::new("parallel", &case.label),
            &case.map_wire,
            |b, bytes| {
                b.iter(|| {
                    let (wrapped, _): (ParallelMap, usize) =
                        bincode::serde::decode_from_slice(black_box(bytes), legacy())
                            .expect("decode");
                    black_box(wrapped.inner)
                });
            },
        );
    }
    group.finish();

    // Full-`SaltProof` bincode serialize vs deserialize (deserialize uses the parallel override).
    let mut group = c.benchmark_group("salt_proof_codec");
    // `deserialize` is ~1s/iter on a real fixture; cap samples to keep the run short.
    group.sample_size(10);
    for case in &corpus {
        group.throughput(Throughput::Elements(case.count));
        group.bench_with_input(
            BenchmarkId::new("serialize", &case.label),
            &case.proof,
            |b, proof| {
                b.iter(|| {
                    let bytes =
                        bincode::serde::encode_to_vec(black_box(proof), legacy()).expect("encode");
                    black_box(bytes)
                });
            },
        );
        group.bench_with_input(
            BenchmarkId::new("deserialize", &case.label),
            &case.proof_bytes,
            |b, bytes| {
                b.iter(|| {
                    let (proof, _): (SaltProof, usize) =
                        bincode::serde::decode_from_slice(black_box(bytes), legacy())
                            .expect("decode");
                    black_box(proof)
                });
            },
        );
    }
    group.finish();
}

criterion_group!(benches, bench);
criterion_main!(benches);
