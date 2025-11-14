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

// TODO: We use the IO Result while we do not have a dedicated Error enum
#[cfg(feature = "std")]
pub(crate) type IOResult<T> = std::io::Result<T>;
#[cfg(feature = "std")]
pub(crate) type IOError = std::io::Error;
#[cfg(feature = "std")]
pub(crate) type IOErrorKind = std::io::ErrorKind;

#[cfg(not(feature = "std"))]
mod io_compat {
    use core::fmt;

    #[derive(Debug)]
    pub struct Error(&'static str);

    impl fmt::Display for Error {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(f, "{}", self.0)
        }
    }

    impl From<ErrorKind> for Error {
        fn from(kind: ErrorKind) -> Self {
            Error(kind.0)
        }
    }

    #[derive(Debug, Clone, Copy)]
    pub struct ErrorKind(&'static str);

    impl ErrorKind {
        /// Mimics std::io::ErrorKind::InvalidData for compatibility
        #[allow(non_upper_case_globals)]
        pub const InvalidData: Self = ErrorKind("invalid data");
    }
}

#[cfg(not(feature = "std"))]
pub(crate) type IOResult<T> = Result<T, io_compat::Error>;
#[cfg(not(feature = "std"))]
pub(crate) type IOError = io_compat::Error;
#[cfg(not(feature = "std"))]
pub(crate) type IOErrorKind = io_compat::ErrorKind;
