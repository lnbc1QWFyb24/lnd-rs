//! Process-local allocation oracle in a separate test binary with one test.
use std::{
    alloc::{GlobalAlloc, Layout, System},
    sync::atomic::{AtomicBool, AtomicUsize, Ordering},
};

pub struct Meter;
static LIVE: AtomicUsize = AtomicUsize::new(0);
static PEAK: AtomicUsize = AtomicUsize::new(0);
static BASELINE: AtomicUsize = AtomicUsize::new(0);
static MEASURING: AtomicBool = AtomicBool::new(false);

fn allocated(bytes: usize) {
    let live = LIVE.fetch_add(bytes, Ordering::SeqCst) + bytes;
    if MEASURING.load(Ordering::SeqCst) {
        PEAK.fetch_max(live, Ordering::SeqCst);
    }
}

// SAFETY: All pointer/layout operations are forwarded unchanged to System.
// Counters retain no allocations and never alter allocator behavior.
unsafe impl GlobalAlloc for Meter {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        // SAFETY: The caller supplies the valid GlobalAlloc layout.
        let pointer = unsafe { System.alloc(layout) };
        if !pointer.is_null() {
            allocated(layout.size());
        }
        pointer
    }

    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        LIVE.fetch_sub(layout.size(), Ordering::SeqCst);
        // SAFETY: The original pointer/layout pair is forwarded unchanged.
        unsafe { System.dealloc(pointer, layout) };
    }

    unsafe fn realloc(&self, pointer: *mut u8, layout: Layout, size: usize) -> *mut u8 {
        // SAFETY: The caller's allocation and new size are forwarded unchanged.
        let result = unsafe { System.realloc(pointer, layout, size) };
        if !result.is_null() {
            if size >= layout.size() {
                allocated(size - layout.size());
            } else {
                LIVE.fetch_sub(layout.size() - size, Ordering::SeqCst);
            }
        }
        result
    }
}

pub fn begin() {
    let live = LIVE.load(Ordering::SeqCst);
    BASELINE.store(live, Ordering::SeqCst);
    PEAK.store(live, Ordering::SeqCst);
    MEASURING.store(true, Ordering::SeqCst);
}

pub fn finish() -> usize {
    MEASURING.store(false, Ordering::SeqCst);
    PEAK.load(Ordering::SeqCst)
        .saturating_sub(BASELINE.load(Ordering::SeqCst))
}
