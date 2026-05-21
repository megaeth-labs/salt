//! Platform-specific configuration values shared across crates.

#[cfg(all(target_os = "zkvm", target_arch = "riscv32"))]
pub const DEFAULT_PRECOMP_WINDOW_SIZE: usize = 3;

#[cfg(not(all(target_os = "zkvm", target_arch = "riscv32")))]
pub const DEFAULT_PRECOMP_WINDOW_SIZE: usize = 11;
