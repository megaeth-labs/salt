#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(not(feature = "std"))]
extern crate alloc;

#[cfg(not(feature = "std"))]
use alloc::vec::Vec;

pub mod crs;
mod default_crs;
pub mod ipa; // follows the BCMS20 scheme
pub mod math_utils;
pub mod multiproof;
pub mod transcript;

pub mod lagrange_basis;

// TODO: We use the IO Result while we do not have a dedicated Error enum
#[cfg(feature = "std")]
pub(crate) type IOResult<T> = std::io::Result<T>;
#[cfg(feature = "std")]
pub(crate) type IOError = std::io::Error;
#[cfg(feature = "std")]
pub(crate) type IOErrorKind = std::io::ErrorKind;
