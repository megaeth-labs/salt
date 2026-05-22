#![no_main]

//! Verifies that bigint-domain point addition remains equivalent to the
//! standard Montgomery-domain path at the serialized output boundary.

use arbitrary::Arbitrary;
use banderwagon::fuzz_support::{element_add_projective_bigint, element_mont_to_bigint};
use banderwagon::{Element, Fr};
use libfuzzer_sys::fuzz_target;

/// Two scalar seeds used to derive valid banderwagon points from the generator.
#[derive(Arbitrary, Debug)]
struct Input {
    lhs: u64,
    rhs: u64,
}

fuzz_target!(|input: Input| {
    let generator = Element::prime_subgroup_generator();

    let lhs_mont = generator * Fr::from(input.lhs);
    let rhs_mont = generator * Fr::from(input.rhs);

    let lhs_bigint = element_mont_to_bigint(&lhs_mont);
    let rhs_bigint = element_mont_to_bigint(&rhs_mont);

    let bigint_projective_sum = element_add_projective_bigint(&lhs_bigint, &rhs_bigint);
    let bigint_sum = lhs_bigint + rhs_bigint;
    let mont_sum = lhs_mont + rhs_mont;

    // First check the zkvm primitive-style bigint addition path against the
    // regular Element bigint addition path.
    assert_eq!(bigint_projective_sum.to_bytes(), bigint_sum.to_bytes());
    assert_eq!(
        bigint_projective_sum.to_bytes_uncompressed(),
        bigint_sum.to_bytes_uncompressed()
    );

    // Then compare the bigint-domain Element addition against the standard
    // Montgomery-domain reference result.
    assert_eq!(bigint_sum.to_bytes(), mont_sum.to_bytes());
    assert_eq!(
        bigint_sum.to_bytes_uncompressed(),
        mont_sum.to_bytes_uncompressed()
    );
});
