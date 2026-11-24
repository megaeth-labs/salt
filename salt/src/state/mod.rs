//! State management for SALT with plain key abstraction.
//!
//! This module provides the core state management functionality for SALT,
//! translating between plain keys and SALT's internal bucket-slot addressing.
//! It supports an ephemeral state layer for batched updates and implements
//! strongly history-independent (SHI) hash tables for organizing data within
//! buckets.

pub mod ahash;

pub mod hasher;

#[allow(clippy::module_inception)]
pub mod state;

pub mod updates;
