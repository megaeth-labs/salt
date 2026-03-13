#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(not(feature = "std"))]
extern crate alloc as std;

pub mod crs;
mod default_crs;
pub mod ipa; // follows the BCMS20 scheme
pub mod math_utils;
pub mod multiproof;
pub mod transcript;

pub mod lagrange_basis;

/// A custom error type for serialization and deserialization errors.
#[derive(Debug, thiserror::Error)]
pub enum SerdeError {
    #[error("invalid data")]
    InvalidData,
}

pub type IOResult<T> = Result<T, SerdeError>;
