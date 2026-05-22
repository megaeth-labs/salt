//! Platform-specific configuration values shared across crates.

/// Default precomputation window size for commitment tables.
///
/// zkVM uses a smaller value to reduce precomputation table cost and memory pressure.
#[cfg(zkvm_riscv32)]
pub const DEFAULT_PRECOMP_WINDOW_SIZE: usize = 3;

/// Default precomputation window size for commitment tables.
#[cfg(not(zkvm_riscv32))]
pub const DEFAULT_PRECOMP_WINDOW_SIZE: usize = 11;
