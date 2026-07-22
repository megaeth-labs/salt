//! Regression test for issue #146 — the original deadlock channel: an OS
//! thread wins the committer initialization, so (pre-fix) its parallel table
//! build was injected into the global rayon pool, whose workers stole flood
//! jobs dereferencing the initializing static at their join points and froze
//! unfinished build fragments beneath them — a circular wait. This shape
//! reproduced the pre-fix deadlock 5/5 on a 14-core host.
//!
//! Complements `shared_committer_init.rs`, which covers first touch from
//! inside pool jobs (the initiator-steals-while-waiting channel). Kept as
//! the only test in this binary so the process starts with the committer
//! uninitialized.
#![cfg(feature = "parallel")]

use salt::empty_salt::EmptySalt;
use salt::StateRoot;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

static DONE: AtomicBool = AtomicBool::new(false);

#[test]
fn os_thread_wins_init_while_pool_jobs_race() {
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

    // Give an OS thread a head start into the initializer so the table
    // build's parallelism reaches the global pool (pre-fix) rather than
    // running inline on a pool worker.
    let winner = std::thread::spawn(|| {
        let _ = StateRoot::new(&EmptySalt);
    });
    std::thread::sleep(Duration::from_millis(30));

    // Flood the global pool with jobs that dereference the initializing
    // static, so workers helping the build can steal them at join points.
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
            })
        })
        .collect();
    winner.join().unwrap();
    for t in threads {
        t.join().unwrap();
    }
    DONE.store(true, Ordering::SeqCst);
}
