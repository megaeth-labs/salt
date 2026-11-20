//! Sharing the independent parts of one job between the calling thread and the pool's idle ones.
//!
//! [`spread_groups`] is for a job that arrives on a thread outside the pool, as a proof check
//! does, and is short enough that the time to wake the pool matters. A parallel iterator queues
//! every part from such a thread and waits for the pool to run them. Here the calling thread
//! starts on the parts at once, and whichever threads of the pool are free take the rest.

#[cfg(feature = "parallel")]
use std::{
    any::Any,
    panic::{catch_unwind, resume_unwind, AssertUnwindSafe},
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc, Condvar, Mutex, PoisonError,
    },
};

/// The groups of one job, taken one at a time by whichever thread asks next.
#[cfg(feature = "parallel")]
struct Spread<T, F> {
    /// What a thread does with a group it has taken.
    sum: F,
    groups: usize,
    /// The next group nobody has taken.
    next: AtomicUsize,
    state: Mutex<SpreadState<T>>,
    /// Signalled when the last group is done, and when a group has panicked.
    done: Condvar,
}

#[cfg(feature = "parallel")]
struct SpreadState<T> {
    /// The groups' results, each written when its group is done.
    sums: Vec<Option<T>>,
    /// The groups done.
    finished: usize,
    /// What a group panicked with, if one did.
    panic: Option<Box<dyn Any + Send>>,
}

#[cfg(feature = "parallel")]
impl<T, F: Fn(usize) -> T> Spread<T, F> {
    /// Takes groups until none is left to take. If one panics, no thread takes another, and the
    /// panic is kept for the calling thread.
    fn run(&self) {
        // After a panic only `panic` is read: the results are discarded.
        let outcome = catch_unwind(AssertUnwindSafe(|| loop {
            let g = self.next.fetch_add(1, Ordering::Relaxed);
            if g >= self.groups {
                return;
            }
            let sum = (self.sum)(g);
            let mut state = self.state.lock().unwrap();
            state.sums[g] = Some(sum);
            state.finished += 1;
            if state.finished == self.groups {
                self.done.notify_all();
            }
        }));
        if let Err(panic) = outcome {
            self.next.fetch_max(self.groups, Ordering::Relaxed);
            let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
            state.panic.get_or_insert(panic);
            self.done.notify_all();
        }
    }
}

/// `sum(g)` for every group `g`, in order, with the pool's idle threads helping.
///
/// This thread starts on the groups at once and takes one after another. A helper is queued on
/// the pool for each group but the first, up to the threads the pool has besides this one, and a
/// helper that gets to run takes groups the same way. So this thread waits only for groups a
/// helper has already begun, and in a pool with no thread to spare it does every group itself,
/// as it would without spreading. A helper that runs after the call has returned finds it gone.
///
/// `sum` must not wait for the pool itself: this thread may be one of the pool's, and it waits
/// for the helpers' groups without running other jobs.
///
/// # Panics
/// If `sum` panics, on this thread or on a helper's, and no further group is started then. The
/// pool aborts the process on a panic in a queued job, so the panic is caught where it happens
/// and raised again on this thread.
#[cfg(feature = "parallel")]
pub(crate) fn spread_groups<T, F>(groups: usize, sum: F) -> Vec<T>
where
    T: Send + 'static,
    F: Fn(usize) -> T + Send + Sync + 'static,
{
    let others =
        rayon::current_num_threads() - usize::from(rayon::current_thread_index().is_some());
    let helpers = groups.saturating_sub(1).min(others);
    if helpers == 0 {
        return (0..groups).map(sum).collect();
    }
    let shared = Arc::new(Spread {
        sum,
        groups,
        next: AtomicUsize::new(0),
        state: Mutex::new(SpreadState {
            sums: (0..groups).map(|_| None).collect(),
            finished: 0,
            panic: None,
        }),
        done: Condvar::new(),
    });
    for _ in 0..helpers {
        // A helper holds the job only while it works on it: one still queued when this call
        // returns keeps nothing alive.
        let job = Arc::downgrade(&shared);
        rayon::spawn(move || {
            if let Some(shared) = job.upgrade() {
                shared.run();
            }
        });
    }
    shared.run();
    let mut state = shared.state.lock().unwrap_or_else(PoisonError::into_inner);
    while state.finished < groups && state.panic.is_none() {
        state = shared
            .done
            .wait(state)
            .unwrap_or_else(PoisonError::into_inner);
    }
    if let Some(panic) = state.panic.take() {
        drop(state);
        resume_unwind(panic);
    }
    state.sums.drain(..).map(Option::unwrap).collect()
}

/// `sum(g)` for every group `g`, in order: without a pool there is nobody to share them with.
#[cfg(not(feature = "parallel"))]
pub(crate) fn spread_groups<T>(groups: usize, sum: impl Fn(usize) -> T) -> Vec<T> {
    (0..groups).map(sum).collect()
}

#[cfg(all(test, feature = "parallel"))]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicBool;
    use std::time::{Duration, Instant};

    fn pool(threads: usize) -> rayon::ThreadPool {
        rayon::ThreadPoolBuilder::new()
            .num_threads(threads)
            .build()
            .unwrap()
    }

    /// Returns once `flag` is set. It gives up after a minute, so that a test whose other thread
    /// never arrives fails on its assertion instead of hanging.
    fn wait_for(flag: &AtomicBool) {
        let start = Instant::now();
        while !flag.load(Ordering::Relaxed) && start.elapsed() < Duration::from_secs(60) {
            std::thread::yield_now();
        }
    }

    /// Every group's result comes back in group order: called from outside any pool, where the
    /// helpers are queued on the global one, and from a thread of a pool of one to four threads,
    /// with more groups than threads and fewer.
    #[test]
    fn every_group_comes_back_in_order() {
        for groups in [0usize, 1, 2, 3, 4, 11] {
            let want: Vec<usize> = (0..groups).map(|g| g * g).collect();
            assert_eq!(spread_groups(groups, |g| g * g), want);
            for threads in 1..=4 {
                assert_eq!(
                    pool(threads).install(|| spread_groups(groups, |g| g * g)),
                    want
                );
            }
        }
    }

    /// A thread of the pool that has handed groups out waits for the ones a helper has begun,
    /// and gets them: its own first group does not end until another thread has taken one.
    #[test]
    fn the_caller_waits_for_a_group_a_helper_has_begun() {
        for threads in 2..=4 {
            let helped = Arc::new(AtomicBool::new(false));
            let got = pool(threads).install(|| {
                let caller = rayon::current_thread_index();
                let helped = Arc::clone(&helped);
                spread_groups(4, move |g| {
                    if rayon::current_thread_index() != caller {
                        helped.store(true, Ordering::Relaxed);
                        // long enough for the caller to run out of groups and wait
                        std::thread::sleep(Duration::from_millis(20));
                    } else {
                        wait_for(&helped);
                    }
                    g
                })
            });
            assert_eq!(got, [0, 1, 2, 3], "threads = {threads}");
            assert!(helped.load(Ordering::Relaxed), "threads = {threads}");
        }
    }

    /// A group that panics on a helper's thread panics the caller with the same payload: the
    /// helper does not take the process down, and the caller does not wait for a group that
    /// will never be done. The pool serves the next call. The pool is the test's own, so that no
    /// other test's work keeps the helper from its group.
    #[test]
    fn a_panic_on_a_helper_reaches_the_caller() {
        let pool = pool(2);
        // The caller's first group does not end until the helper has taken one, and the
        // helper's panics.
        let taken = Arc::new(AtomicBool::new(false));
        let outcome = catch_unwind(AssertUnwindSafe(|| {
            pool.install(|| {
                let caller = rayon::current_thread_index();
                let taken = Arc::clone(&taken);
                spread_groups(4, move |g| {
                    if rayon::current_thread_index() != caller {
                        taken.store(true, Ordering::Relaxed);
                        panic!("group {g} on a helper");
                    }
                    wait_for(&taken);
                    g
                })
            })
        }));
        let panic = outcome.expect_err("the helper's panic reaches the caller");
        let message = panic
            .downcast_ref::<String>()
            .expect("the helper's own payload");
        assert!(message.ends_with("on a helper"), "{message}");
        assert_eq!(pool.install(|| spread_groups(4, |g| g + 1)), [1, 2, 3, 4]);
    }

    /// A group that panics on the calling thread stops the helpers: of 64 groups only the
    /// caller's and the one the helper already had are begun.
    #[test]
    fn a_panic_on_the_caller_stops_the_helpers() {
        let pool = pool(2);
        let taken = Arc::new(AtomicBool::new(false));
        let begun = Arc::new(AtomicUsize::new(0));
        let outcome = catch_unwind(AssertUnwindSafe(|| {
            pool.install(|| {
                let caller = rayon::current_thread_index();
                let (taken, begun) = (Arc::clone(&taken), Arc::clone(&begun));
                spread_groups(64, move |g| {
                    begun.fetch_add(1, Ordering::Relaxed);
                    if rayon::current_thread_index() != caller {
                        taken.store(true, Ordering::Relaxed);
                        // long enough for the caller to have unwound out of the call
                        std::thread::sleep(Duration::from_millis(200));
                        return g;
                    }
                    wait_for(&taken);
                    panic!("group {g} on the caller");
                })
            })
        }));
        let panic = outcome.expect_err("the caller's own panic comes out");
        let message = panic
            .downcast_ref::<String>()
            .expect("the caller's payload");
        assert!(message.ends_with("on the caller"), "{message}");
        // The helper's group ends after the caller has gone, and it takes no other.
        std::thread::sleep(Duration::from_millis(400));
        assert_eq!(begun.load(Ordering::Relaxed), 2);
    }
}
