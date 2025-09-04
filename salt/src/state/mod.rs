//! State management for SALT with plain key abstraction.
//!
//! This module provides the core state management functionality for SALT,
//! translating between plain keys and SALT's internal bucket-slot addressing.
//! It supports an ephemeral state layer for batched updates and implements
//! strongly history-independent (SHI) hash tables for organizing data within
//! buckets.

/// AHash-based utilities for deterministic cross-platform hashing.
pub mod ahash;

/// Hashing utilities for deterministic bucket and slot assignment.
pub mod hasher;

/// Core state management with SHI hash table implementation and ephemeral state layer.
#[allow(clippy::module_inception)]
pub mod state;

/// State change tracking and merging for atomic batch operations.
pub mod updates;
