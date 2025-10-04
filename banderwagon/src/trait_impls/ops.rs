//! Arithmetic operations and standard trait implementations for banderwagon `Element`.
//!
//! This module provides operator overloads and trait implementations that allow `Element`
//! to integrate seamlessly with Rust's standard library:
//!
//! # Group Operations
//! - **Addition** ([`Add`], [`AddAssign`]) - Group addition with `+` and `+=`
//! - **Subtraction** ([`Sub`]) - Group subtraction with `-`
//! - **Negation** ([`Neg`]) - Additive inverse with unary `-`
//! - **Scalar Multiplication** ([`Mul`]) - Multiply by field elements with `*`
//!
//! # Iterator Support
//! - **Summation** ([`Sum`]) - Use `.sum()` on iterators of elements
//!
//! # Collections Support
//! - **Hashing** ([`Hash`]) - Use elements as keys in `HashMap` and `HashSet`
//!
//! # Examples
//! ```
//! # use banderwagon::Element;
//! # use ark_ed_on_bls12_381_bandersnatch::Fr;
//! let p = Element::generator();
//! let q = Element::generator();
//!
//! // Group operations
//! let sum = p + q;
//! let diff = p - q;
//! let neg = -p;
//!
//! // Scalar multiplication
//! let scalar = Fr::from(5u64);
//! let scaled = p * scalar;
//!
//! // Iterator summation
//! let elements = vec![p, q];
//! let total: Element = elements.into_iter().sum();
//! ```
use crate::Element;
use ark_ed_on_bls12_381_bandersnatch::Fr;

use std::{
    hash::Hash,
    iter::Sum,
    ops::{Add, AddAssign, Mul, Neg, Sub},
};

/// Multiplies an `Element` by a scalar field element.
///
/// This performs scalar multiplication in the banderwagon group: `k * P` where
/// `k` is a scalar (Fr) and `P` is a group element. This operation is fundamental
/// to elliptic curve cryptography and is used in commitment schemes and signatures.
impl Mul<Fr> for Element {
    type Output = Element;

    fn mul(self, rhs: Fr) -> Self::Output {
        Element(self.0.mul(rhs))
    }
}

/// Multiplies an `Element` reference by a scalar field element reference.
///
/// This is the borrowed version of scalar multiplication, avoiding clones when
/// both operands are references.
impl Mul<&Fr> for &Element {
    type Output = Element;

    fn mul(self, rhs: &Fr) -> Self::Output {
        Element(self.0.mul(rhs))
    }
}

/// Adds two `Element`s together using banderwagon group addition.
///
/// This implements the group operation for the banderwagon elliptic curve group.
/// Addition is commutative and associative: `P + Q == Q + P` and `(P + Q) + R == P + (Q + R)`.
impl Add<Element> for Element {
    type Output = Element;

    fn add(self, rhs: Element) -> Self::Output {
        Element(self.0 + rhs.0)
    }
}

/// Adds another `Element` to this element in-place.
///
/// Mutates `self` to hold the sum, avoiding allocation of a new `Element`.
impl AddAssign<Element> for Element {
    fn add_assign(&mut self, rhs: Element) {
        self.0 += rhs.0
    }
}

/// Subtracts one `Element` from another using banderwagon group subtraction.
///
/// Equivalent to `self + (-rhs)`, where `-rhs` is the group inverse of `rhs`.
impl Sub<Element> for Element {
    type Output = Element;

    fn sub(self, rhs: Element) -> Self::Output {
        Element(self.0 - rhs.0)
    }
}

/// Returns the additive inverse (negation) of an `Element`.
///
/// For any element `P`, `-P` satisfies `P + (-P) = identity`.
impl Neg for Element {
    type Output = Element;

    fn neg(self) -> Self::Output {
        Element(-self.0)
    }
}

/// Sums an iterator of `Element`s into a single element.
///
/// Enables using `.sum()` on iterators: `elements.iter().copied().sum()`.
/// Returns the group identity element for an empty iterator.
impl Sum for Element {
    fn sum<I: Iterator<Item = Self>>(iter: I) -> Self {
        Element(iter.map(|element| element.0).sum())
    }
}

/// Hashes an `Element` by serializing it to bytes first.
///
/// Uses the canonical byte representation via `to_bytes()` to ensure consistent
/// hashing. This allows `Element` to be used as a key in `HashMap` and `HashSet`.
impl Hash for Element {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.to_bytes().hash(state)
    }
}
