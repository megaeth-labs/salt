//! A no_std compatible logging utility with zkvm support.
//!
//! This crate provides cross-platform logging functionality that automatically
//! adapts to different execution environments:
//! - On zkvm targets: Uses risc0_zkvm's logging mechanism
//! - On standard targets: Uses the tracing crate
//!
//! # Features
//! - `std` (default): Enables tracing support for standard environments
//! - `zkvm`: Enables risc0_zkvm support (automatically enabled for zkvm targets)

#[cfg(feature = "std")]
extern crate std;

/// Logs a given message under different logging mechanisms based on the target operating system.
///
/// # Parameters
/// - `msg`: A string slice representing the message to be logged.
///
/// # Platform-specific Behavior
/// - On a `zkvm` target operating system:
///   - Logs the message using the RISC Zero zkVM environment's logging mechanism
///     (`risc0_zkvm::guest::env::log`).
/// - On other target operating systems:
///   - Logs the message using the `tracing` crate's `info!` macro.
pub fn log(msg: &str) {
    #[cfg(target_os = "zkvm")]
    {
        risc0_zkvm::guest::env::log(msg);
    }

    #[cfg(not(target_os = "zkvm"))]
    #[cfg(feature = "std")]
    {
        println!("{msg}");
        tracing::info!("{msg}");
    }

    #[cfg(not(target_os = "zkvm"))]
    #[cfg(not(feature = "std"))]
    {
        // In no_std environments without zkvm, we can't do much
        // This is a fallback that does nothing
        let _ = msg;
    }
}
