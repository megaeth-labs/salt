#![cfg(feature = "zkvm-riscv32-sim")]

//! Minimal fuzz-only helpers for constructing bigint-domain `Element` values
//! and invoking zkvm-style projective addition from external fuzz targets.

use crate::zkvm_riscv32_primitives::{add_projective, from_mont_to_bigint};
use crate::Element;

/// Converts a normal Montgomery-domain `Element` into the bigint-domain
/// representation consumed by zkvm arithmetic helpers.
pub fn element_mont_to_bigint(element: &Element) -> Element {
    let mut result = element.0;

    let x = element.0.x.0 .0;
    let y = element.0.y.0 .0;
    let t = element.0.t.0 .0;
    let z = element.0.z.0 .0;

    from_mont_to_bigint(&mut result.x.0 .0, &x);
    from_mont_to_bigint(&mut result.y.0 .0, &y);
    from_mont_to_bigint(&mut result.t.0 .0, &t);
    from_mont_to_bigint(&mut result.z.0 .0, &z);

    Element(result)
}

/// Applies the zkvm bigint projective addition helper to two bigint-domain
/// elements and returns the bigint-domain result.
pub fn element_add_projective_bigint(lhs: &Element, rhs: &Element) -> Element {
    let mut result = lhs.0;
    add_projective(&mut result, &rhs.0);
    Element(result)
}
