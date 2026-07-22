//! Regression test for issue #146, initiator-steal channel: the shared
//! committer's one-time initialization must complete even when its first
//! touch happens inside global-rayon-pool jobs racing with OS threads. A
//! pool worker that wins the initialization must not block on the pool via
//! a work-stealing wait, or it re-enters the lazy on its own stack (this
//! caught a broken intermediate version of the fix). The original deadlock
//! channel is covered by `shared_committer_init_os_winner.rs`.
#![cfg(feature = "parallel")]

mod common;

use salt::empty_salt::EmptySalt;
use salt::StateRoot;

#[test]
fn concurrent_first_touch_from_pool_jobs_and_threads() {
    common::run_guarded(|| {
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
    });
}
