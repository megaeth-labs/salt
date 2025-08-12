//! This module implements the trie component of the SALT data structure
//! that is used to authenticate the key-value pairs stored in the leaf
//! nodes (i.e., the SALT buckets).

pub mod proof;
#[allow(clippy::module_inception)]
pub mod trie;
pub mod updates;
pub use banderwagon::Element;
pub mod witness;
