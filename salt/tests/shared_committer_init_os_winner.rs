//! Regression test for issue #146, the original deadlock channel: an OS
//! thread wins the committer initialization, so (pre-fix) its parallel
//! table build was injected into the global rayon pool, whose workers stole
//! flood jobs dereferencing the initializing static at their join points
//! and froze unfinished build fragments beneath them — a circular wait.
//! This shape reproduced the pre-fix deadlock 5/5 on a 14-core host. The
//! initiator-steal channel is covered by `shared_committer_init.rs`.
#![cfg(feature = "parallel")]

mod common;

use salt::empty_salt::EmptySalt;
use salt::StateRoot;
use std::time::Duration;

#[test]
fn os_thread_wins_init_while_pool_jobs_race() {
    common::run_guarded(|| {
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
    });
}
