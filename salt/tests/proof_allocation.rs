use std::{
    alloc::{GlobalAlloc, Layout, System},
    cell::Cell,
    panic::catch_unwind,
};

use salt::proof::PathCommitments;

/// The most heap a decode may hold before it rejects a fabricated length: the parents map's
/// preallocation cap, 65,536 entries of 8 + 32 bytes (2.6 MB), with room to spare. A doubled cap
/// (5.2 MB) exceeds it.
const HOSTILE_PEAK_LIMIT: usize = 4 << 20;

/// Counts heap bytes per thread, so a test measures its own decode while others run beside it.
struct ThreadCounting;

thread_local! {
    /// Bytes allocated minus bytes freed on this thread since `peak_heap` began.
    static LIVE: Cell<isize> = const { Cell::new(0) };
    /// The highest `LIVE` since `peak_heap` began.
    static PEAK: Cell<isize> = const { Cell::new(0) };
}

unsafe impl GlobalAlloc for ThreadCounting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        // `try_with`: what a thread allocates after its locals are destroyed is not counted.
        let _ = LIVE.try_with(|live| {
            live.set(live.get() + layout.size() as isize);
            let _ = PEAK.try_with(|peak| peak.set(peak.get().max(live.get())));
        });
        unsafe { System.alloc(layout) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        let _ = LIVE.try_with(|live| live.set(live.get() - layout.size() as isize));
        unsafe { System.dealloc(ptr, layout) }
    }
}

#[global_allocator]
static ALLOCATOR: ThreadCounting = ThreadCounting;

/// `f`'s result and the most heap it held at once on this thread.
fn peak_heap<R>(f: impl FnOnce() -> R) -> (R, usize) {
    LIVE.set(0);
    PEAK.set(0);
    let result = f();
    (result, PEAK.get() as usize)
}

#[test]
fn hostile_96_byte_witness_returns_error() {
    for n in [1u64 << 56, u64::MAX] {
        // Empty key/value map, then a proof map with a false length and two entries.
        let mut wire = 0u64.to_le_bytes().to_vec();
        wire.extend_from_slice(&n.to_le_bytes());
        for id in 0u64..2 {
            wire.extend_from_slice(&id.to_le_bytes());
            wire.extend_from_slice(&[0u8; 32]);
        }
        assert_eq!(wire.len(), 96);
        let (result, peak) = peak_heap(|| {
            catch_unwind(|| {
                bincode::serde::decode_from_slice::<salt::SaltWitness, _>(
                    &wire,
                    bincode::config::legacy(),
                )
            })
        });
        assert!(result.is_ok(), "witness panic with length {n}");
        assert!(result.unwrap().is_err());
        assert!(
            peak <= HOSTILE_PEAK_LIMIT,
            "witness length {n} held {peak} bytes"
        );
        let (limited, peak) = peak_heap(|| {
            catch_unwind(|| {
                bincode::serde::decode_from_slice::<salt::SaltWitness, _>(
                    &wire,
                    bincode::config::legacy().with_limit::<1024>(),
                )
            })
        });
        assert!(limited.is_ok(), "limited witness panic with length {n}");
        assert!(limited.unwrap().is_err());
        assert!(
            peak <= HOSTILE_PEAK_LIMIT,
            "limited witness length {n} held {peak} bytes"
        );
    }
}

#[test]
fn fabricated_lengths_return_errors_without_panicking() {
    for n in [0, 1, 65_535, 65_536, 65_537, 1u64 << 56, u64::MAX] {
        let bytes = n.to_le_bytes();
        let (result, peak) = peak_heap(|| {
            catch_unwind(|| {
                bincode::serde::decode_from_slice::<salt::SaltProof, _>(
                    &bytes,
                    bincode::config::legacy(),
                )
            })
        });
        assert!(result.is_ok(), "panic with declared length {n}");
        assert!(result.unwrap().is_err());
        assert!(
            peak <= HOSTILE_PEAK_LIMIT,
            "declared length {n} held {peak} bytes"
        );
        // bincode charges its byte budget on reads, so the budget does not lower the peak.
        let (limited, peak) = peak_heap(|| {
            catch_unwind(|| {
                bincode::serde::decode_from_slice::<salt::SaltProof, _>(
                    &bytes,
                    bincode::config::legacy().with_limit::<1024>(),
                )
            })
        });
        assert!(limited.is_ok(), "panic with byte budget, length {n}");
        assert!(limited.unwrap().is_err());
        assert!(
            peak <= HOSTILE_PEAK_LIMIT,
            "declared length {n} held {peak} bytes with a budget"
        );
    }
}

#[test]
fn valid_map_larger_than_initial_cap_still_decodes() {
    let n = 65_537u64;
    let mut wire = n.to_le_bytes().to_vec();
    for id in 0..n {
        wire.extend_from_slice(&id.to_le_bytes());
        // The zero-byte encoding is a valid identity commitment.
        wire.extend_from_slice(&[0u8; 32]);
    }
    let (map, consumed) =
        bincode::serde::decode_from_slice::<PathCommitments, _>(&wire, bincode::config::legacy())
            .unwrap();
    assert_eq!(map.len(), n as usize);
    assert_eq!(consumed, wire.len());
    let encoded = bincode::serde::encode_to_vec(&map, bincode::config::legacy()).unwrap();
    assert_eq!(encoded, wire);
}
