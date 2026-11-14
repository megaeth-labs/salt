//! Platform-specific configuration values shared across crates.

#[cfg(all(target_os = "zkvm", target_arch = "riscv32"))]
pub const DEFAULT_PRECOMP_WINDOW_SIZE: usize = 3;

#[cfg(not(all(target_os = "zkvm", target_arch = "riscv32")))]
pub const DEFAULT_PRECOMP_WINDOW_SIZE: usize = 11;

/// The committer's window when its multiplications run in lanes: the lanes make each window's addition
/// cheap enough that the table (`win_num · (2^(w-1) + 1) · 64 B` per base) is chosen for its memory
/// rather than for the addition count: window 7 stores 37 windows and 39.4 MB of point data for
/// 256 bases, versus 24 windows and 403 MB at window 11 (excluding allocation metadata).
pub const LANE_PRECOMP_WINDOW_SIZE: usize = 7;

/// The committer window for this host: [`LANE_PRECOMP_WINDOW_SIZE`] where the lane path runs,
/// [`DEFAULT_PRECOMP_WINDOW_SIZE`] everywhere else.
pub fn precomp_window_size() -> usize {
    #[cfg(all(target_arch = "x86_64", feature = "std"))]
    {
        if crate::ifma::available() {
            return LANE_PRECOMP_WINDOW_SIZE;
        }
    }
    DEFAULT_PRECOMP_WINDOW_SIZE
}
