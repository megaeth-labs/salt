//! Cryptographic authentication layer for the SALT data structure.
//!
//! This module implements SALT's trie component using IPA vector commitments to
//! authenticate key-value pairs stored in SALT buckets. SALT uses a **two-tier
//! architecture** combining a static main trie with dynamic bucket subtrees.
//!
//! # Architecture
//!
//! - **Main trie**: 4-level, 256-ary tree with ~16.7M leaf nodes (buckets)
//! - **Bucket subtrees**: Dynamic expansion when buckets exceed 256 slots
//!   - Subtrees can have up to 5 levels of 256-ary expansion
//!   - Root position "climbs" upward as bucket capacity grows
//!   - Only allocate subtree nodes when needed
//!
//! # Key Components
//!
//! - **[`StateRoot`](trie::StateRoot)**: Main interface for computing trie commitments
//!   with incremental updates and two-phase commits
//! - **[`node_utils`]**: Utilities for node navigation and dynamic subtree management
//! - **Proof integration**: Works with [`crate::proof`] for cryptographic witnesses

pub mod node_utils;
#[allow(clippy::module_inception)]
pub mod trie;
pub use banderwagon::Element;
