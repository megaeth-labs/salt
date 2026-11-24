//! Platform-specific configuration values shared across crates.

#[cfg(all(target_os = "zkvm", target_arch = "riscv32"))]
pub const DEFAULT_PRECOMP_WINDOW_SIZE: usize = 3;

#[cfg(not(all(target_os = "zkvm", target_arch = "riscv32")))]
pub const DEFAULT_PRECOMP_WINDOW_SIZE: usize = 11;

/// The committer's window when its multiplications run in lanes: the lanes make each window's
/// addition cheap enough that the tables are chosen for their memory rather than for the addition
/// count. A lane host keeps `win_num · (2^(w-1) + 1)` entries per base, each a 64-byte point and
/// the 32-byte product the lanes add beside it: window 7 stores 37 windows and 59.1 MB for 256
/// bases (39.4 MB of points, 19.7 MB of products), versus 24 windows and 403 MB of points at
/// window 11 (excluding allocation metadata). The products are kept at any window a lane host
/// builds: at window 11 they add 201.5 MB to those points.
pub const LANE_PRECOMP_WINDOW_SIZE: usize = 7;

/// The committer window for this host: [`LANE_PRECOMP_WINDOW_SIZE`] where the lane path runs,
/// [`DEFAULT_PRECOMP_WINDOW_SIZE`] everywhere else.
pub fn precomp_window_size() -> usize {
    #[cfg(all(target_arch = "x86_64", feature = "std"))]
    if crate::ifma::available() {
        return LANE_PRECOMP_WINDOW_SIZE;
    }
    DEFAULT_PRECOMP_WINDOW_SIZE
}
