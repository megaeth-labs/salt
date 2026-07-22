//! Shared scaffolding for the issue #146 deadlock regression binaries.
//!
//! Each regression lives in its own single-test binary so the process
//! starts with the shared committer uninitialized.

use std::sync::mpsc::RecvTimeoutError;
use std::time::Duration;

/// Runs `body` on a worker thread and fails the test if it does not finish
/// within the deadline: a deadlock regression manifests as a hang, and this
/// converts it into a reported failure.
pub fn run_guarded(body: impl FnOnce() + Send + 'static) {
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        body();
        let _ = tx.send(());
    });
    match rx.recv_timeout(Duration::from_secs(120)) {
        Ok(()) => {}
        Err(RecvTimeoutError::Timeout) => {
            panic!("shared committer initialization deadlocked (issue #146)")
        }
        Err(RecvTimeoutError::Disconnected) => {
            panic!("regression body panicked; see the output above")
        }
    }
}
