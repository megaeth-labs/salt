//! Deterministic hashing utilities extracted from AHash v0.8.12.
//!
//! This module contains AHash's fallback "folded multiply" algorithm with true
//! 128-bit multiplication. Unlike the standard AHash implementation which may
//! use different algorithms on different platforms for performance, this always
//! uses the same deterministic algorithm.
//!
//! The code is derived from [AHash v0.8.12](https://github.com/tkaitchuck/aHash)
//! under Apache License 2.0. See [`NOTICE.md`](./NOTICE.md) for full attribution.

/// Convert utilities extracted from AHash for efficient byte operations.
pub mod convert;

/// Deterministic fallback hasher implementation extracted from AHash.
pub mod fallback;
