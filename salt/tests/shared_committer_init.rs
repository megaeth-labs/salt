//! Regression test for issue #146: the shared committer's one-time
//! initialization must complete even when its first touch happens inside
//! global-rayon-pool jobs racing with OS threads.
//!
//! Kept as the only test in this binary so the process starts with the
//! committer uninitialized.
#![cfg(feature = "parallel")]

use salt::empty_salt::EmptySalt;
use salt::StateRoot;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

static DONE: AtomicBool = AtomicBool::new(false);

#[test]
fn concurrent_first_touch_from_pool_jobs_and_threads() {
    // A regression manifests as a hang, not a failure; convert it into one.
    std::thread::spawn(|| {
        std::thread::sleep(Duration::from_secs(120));
        if !DONE.load(Ordering::SeqCst) {
            // Write directly to the real stderr: libtest's output capture
            // swallows eprintln! from spawned threads, and process::exit
            // bypasses the flush that would surface it.
            use std::io::Write;
            let _ = writeln!(
                std::io::stderr(),
                "shared committer initialization deadlocked (issue #146)"
            );
            std::process::exit(1);
        }
    });

    let threads: Vec<_> = (0..8)
        .map(|_| {
            std::thread::spawn(|| {
                rayon::scope(|s| {
                    for _ in 0..16 {
                        s.spawn(|_| {
                            let _ = StateRoot::new(&EmptySalt);
                        });
                    }
                });
                let _ = StateRoot::new(&EmptySalt);
            })
        })
        .collect();
    for t in threads {
        t.join().unwrap();
    }
    DONE.store(true, Ordering::SeqCst);
}
