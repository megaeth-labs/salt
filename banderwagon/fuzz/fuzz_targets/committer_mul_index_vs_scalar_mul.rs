#![no_main]

//! Verifies that the precomputed `Committer::mul_index` path matches direct
//! scalar multiplication when using the same CRS bases as Salt Trie.

use arbitrary::Arbitrary;
use banderwagon::salt_committer::Committer;
use banderwagon::{Element, Fr};
use ipa_multipoint::crs::CRS;
use libfuzzer_sys::fuzz_target;
use std::sync::OnceLock;

/// Matches the zkvm-oriented precomputation setting used in current testing.
const WINDOW_SIZE: usize = 3;

/// Fuzz input selects one CRS base, a scalar multiplier, and an existing
/// commitment to which the computed delta will be added.
#[derive(Arbitrary, Debug)]
struct Input {
    index_seed: u16,
    scalar: u64,
    old: u64,
}

/// Lazily initializes the production CRS once so fuzzing spends time on the
/// arithmetic path rather than rebuilding 256 generators per input.
fn crs() -> &'static Vec<Element> {
    static CRS_POINTS: OnceLock<Vec<Element>> = OnceLock::new();
    CRS_POINTS.get_or_init(|| CRS::default().G)
}

/// Lazily initializes the precomputed committer once with the same bases and
/// window size used by the fuzz target.
fn committer() -> &'static Committer {
    static COMMITTER: OnceLock<Committer> = OnceLock::new();
    COMMITTER.get_or_init(|| Committer::new(crs(), WINDOW_SIZE))
}

fuzz_target!(|input: Input| {
    let index = input.index_seed as usize % crs().len();
    let scalar = Fr::from(input.scalar);
    let old_commitment = Element::prime_subgroup_generator() * Fr::from(input.old);

    let delta = committer().mul_index(&scalar, index);
    let got = old_commitment + delta;

    // Compare against the direct scalar multiplication reference on the same base.
    let expected = old_commitment + (crs()[index] * scalar);

    assert_eq!(got.to_bytes(), expected.to_bytes());
    assert_eq!(got.to_bytes_uncompressed(), expected.to_bytes_uncompressed());
});
