//! This module implements the "state" component of the SALT
//! data structure that holds the key-value pairs of the
//! blockchain state to be authenticated.

#[allow(clippy::module_inception)]
pub mod state;
pub mod updates;

pub use state::pk_hasher;
