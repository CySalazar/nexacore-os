//! Host-mode integration tests for the K3 bump allocator
//! ([`nexacore_kernel::bare_metal::heap::BumpHeap`]).
//!
//! Specified by `NCIP-Kernel-012` § S4. The tests run on the developer
//! host (NOT under `x86_64-unknown-none`) because the test harness
//! itself needs `std` for the runner; this is acceptable because the
//! `BumpHeap` type is `#[cfg(feature = "bare-metal")]` only — the
//! `#[global_allocator]` attribute is the `target_os = "none"` part —
//! so the *type* is host-buildable and exercisable against a
//! synthetic `[u8; N]` heap region.

#![cfg(feature = "bare-metal")]
// Test-only relaxations: integration tests exercise unsafe APIs by
// design (BumpHeap::init, GlobalAlloc::alloc), fail-loudly via
// `expect`/`unwrap`, and do casts/indexing against statically-sized
// fixtures. The corresponding workspace lints are intentionally not
// propagated into the test target.
#![allow(unsafe_code)]
#![allow(
    clippy::undocumented_unsafe_blocks,
    clippy::multiple_unsafe_ops_per_block,
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::integer_division,
    clippy::cast_possible_truncation,
    clippy::missing_docs_in_private_items,
    clippy::uninlined_format_args
)]

use core::alloc::{GlobalAlloc, Layout};

use nexacore_kernel::bare_metal::heap::{
    BumpHeap, MAX_SMALL_BYTES, NUM_SIZE_CLASSES, PAGE_BYTES, SIZE_CLASSES, SlabHeap,
    size_class_bytes, size_class_index,
};

/// Fresh, uninitialised `BumpHeap` instance for use as a test fixture.
fn fresh_heap() -> BumpHeap {
    BumpHeap::new()
}

/// A synthetic heap region. We use `'static` so the `unsafe { init }`
/// pointer remains valid for the entire test duration without
/// borrowing-checker contortions.
fn static_region(len: usize) -> (*mut u8, usize) {
    let buf = vec![0u8; len].leak();
    (buf.as_mut_ptr(), buf.len())
}

#[test]
fn uninitialised_heap_allocates_null() {
    // Per § S2 constraint: an uninitialised allocator returns null
    // (the alloc crate's OOM path takes over downstream).
    let heap = fresh_heap();
    let layout = Layout::from_size_align(64, 8).unwrap();
    let ptr = unsafe { heap.alloc(layout) };
    assert!(ptr.is_null(), "uninitialised heap must return null");
    assert!(!heap.is_initialised());
}

#[test]
fn init_marks_heap_initialised_and_reports_total() {
    let heap = fresh_heap();
    let (base, len) = static_region(8 * 1024);
    unsafe { heap.init(base, len) };
    assert!(heap.is_initialised());
    assert_eq!(heap.total_bytes(), 8 * 1024);
    assert_eq!(heap.used_bytes(), 0);
}

#[test]
fn allocations_are_monotonic_and_aligned() {
    let heap = fresh_heap();
    let (base, len) = static_region(64 * 1024);
    unsafe { heap.init(base, len) };

    let layout8 = Layout::from_size_align(13, 8).unwrap();
    let p1 = unsafe { heap.alloc(layout8) };
    assert!(!p1.is_null());
    assert_eq!((p1 as usize) % 8, 0, "p1 must be 8-byte aligned");

    let layout16 = Layout::from_size_align(40, 16).unwrap();
    let p2 = unsafe { heap.alloc(layout16) };
    assert!(!p2.is_null());
    assert_eq!((p2 as usize) % 16, 0, "p2 must be 16-byte aligned");

    assert!(
        (p2 as usize) >= (p1 as usize) + 13,
        "p2 must be past p1+size"
    );
    assert!(heap.used_bytes() >= 13 + 40);
}

#[test]
fn oom_returns_null_without_panic() {
    let heap = fresh_heap();
    let (base, len) = static_region(256);
    unsafe { heap.init(base, len) };

    // First allocation: 100 bytes, 1-byte aligned. Should succeed.
    let l1 = Layout::from_size_align(100, 1).unwrap();
    let p1 = unsafe { heap.alloc(l1) };
    assert!(!p1.is_null());

    // Second allocation: 200 bytes, 1-byte aligned. Total 100 + 200 =
    // 300 > 256 byte heap. Must return null, NOT panic.
    let l2 = Layout::from_size_align(200, 1).unwrap();
    let p2 = unsafe { heap.alloc(l2) };
    assert!(p2.is_null(), "OOM must return null, not panic");
}

#[test]
fn zero_size_alloc_still_advances_alignment() {
    // A zero-size allocation must still return an aligned pointer; the
    // `next` pointer is advanced only by alignment padding.
    let heap = fresh_heap();
    let (base, len) = static_region(1024);
    unsafe { heap.init(base, len) };

    let layout = Layout::from_size_align(0, 64).unwrap();
    let p = unsafe { heap.alloc(layout) };
    assert!(!p.is_null());
    assert_eq!((p as usize) % 64, 0);
}

#[test]
fn dealloc_is_noop() {
    // Per § S2 constraint 2: dealloc never frees. used_bytes is
    // monotonic; calling dealloc does not reset it.
    let heap = fresh_heap();
    let (base, len) = static_region(1024);
    unsafe { heap.init(base, len) };

    let layout = Layout::from_size_align(64, 8).unwrap();
    let p = unsafe { heap.alloc(layout) };
    let used_before = heap.used_bytes();
    unsafe { heap.dealloc(p, layout) };
    assert_eq!(
        heap.used_bytes(),
        used_before,
        "dealloc must not reset used_bytes"
    );
}

#[test]
#[should_panic(expected = "BumpHeap::init called twice")]
fn double_init_panics() {
    let heap = fresh_heap();
    let (base, len) = static_region(1024);
    unsafe { heap.init(base, len) };
    // Second call MUST panic per § S2 constraint 1.
    unsafe { heap.init(base, len) };
}

#[test]
fn large_alignment_is_honored() {
    // Pathological case: alignment larger than typical cache line
    // (4096 — page-sized). The bump pointer must skip enough to land
    // on the next 4 KiB boundary.
    let heap = fresh_heap();
    let (base, len) = static_region(32 * 1024);
    unsafe { heap.init(base, len) };

    // Burn some bytes so the bump pointer is *not* at a page boundary.
    let prelude = Layout::from_size_align(7, 1).unwrap();
    let _ = unsafe { heap.alloc(prelude) };

    let page = Layout::from_size_align(64, 4096).unwrap();
    let p = unsafe { heap.alloc(page) };
    assert!(!p.is_null());
    assert_eq!((p as usize) % 4096, 0, "must be 4 KiB aligned");
}

#[test]
fn allocations_fall_inside_heap_region() {
    // Every returned pointer must lie in [base, end).
    let heap = fresh_heap();
    let (base, len) = static_region(4096);
    unsafe { heap.init(base, len) };
    let base_addr = base as usize;

    for _ in 0..16 {
        let layout = Layout::from_size_align(64, 8).unwrap();
        let p = unsafe { heap.alloc(layout) };
        assert!(!p.is_null());
        let addr = p as usize;
        assert!(addr >= base_addr, "p must be at or above base");
        assert!(addr + 64 <= base_addr + len, "p+size must be within region");
    }
}

// ===========================================================================
// SlabHeap — WS1-08.2: struct + fixed size classes (NCIP-Kernel-Alloc-029).
// These cover the size-class machinery and the one-shot arena install; the
// reclaiming alloc/free paths arrive (with their own tests) in WS1-08.3–.5.
// ===========================================================================

#[test]
fn size_classes_are_strictly_increasing_powers_of_two() {
    // NCIP-029 § S3.1: classes are 16,32,…,4096, the last == MAX_SMALL_BYTES.
    assert_eq!(SIZE_CLASSES, [16, 32, 64, 128, 256, 512, 1024, 2048, 4096]);
    assert_eq!(NUM_SIZE_CLASSES, 9);
    assert_eq!(*SIZE_CLASSES.last().unwrap(), MAX_SMALL_BYTES);
    for w in SIZE_CLASSES.windows(2) {
        assert!(w[1] > w[0], "classes must strictly increase");
        assert!(w[0].is_power_of_two(), "each class must be a power of two");
    }
    assert!(SIZE_CLASSES.last().unwrap().is_power_of_two());
}

#[test]
fn size_class_index_rounds_up_to_smallest_fitting_class() {
    // Exact class boundaries map to themselves.
    assert_eq!(size_class_index(16, 1), Some(0));
    assert_eq!(size_class_index(4096, 1), Some(8));
    // Below the first class rounds up to class 0 (16 B).
    assert_eq!(size_class_index(1, 1), Some(0));
    assert_eq!(size_class_index(0, 1), Some(0)); // zero-size treated as 1 (§ S2.1.4)
    // In-between sizes round up.
    assert_eq!(size_class_index(33, 8), Some(2)); // 33 → class 64 (idx 2)
    assert_eq!(size_class_index(17, 8), Some(1)); // 17 → class 32 (idx 1)
    assert_eq!(size_class_index(513, 8), Some(6)); // 513 → class 1024 (idx 6)
}

#[test]
fn size_class_index_promotes_on_alignment() {
    // NCIP-029 § S2.3.2: a small request whose alignment exceeds its size is
    // promoted to the class >= align.
    assert_eq!(size_class_index(8, 64), Some(2)); // align 64 dominates → class 64
    assert_eq!(size_class_index(16, 256), Some(4)); // align 256 → class 256 (idx 4)
    assert_eq!(size_class_index(1, 4096), Some(8)); // page-aligned tiny → class 4096
}

#[test]
fn large_requests_take_the_large_path() {
    // NCIP-029 § S3.1/§ S2.1.3: > MAX_SMALL_BYTES (by size OR align) → None.
    assert_eq!(size_class_index(4097, 1), None);
    assert_eq!(size_class_index(8192, 8), None);
    assert_eq!(size_class_index(64, 8192), None); // align beyond small max
}

#[test]
fn size_class_bytes_maps_index_to_class_and_guards_range() {
    assert_eq!(size_class_bytes(0), Some(16));
    assert_eq!(size_class_bytes(8), Some(4096));
    assert_eq!(size_class_bytes(NUM_SIZE_CLASSES), None); // out of range → None, no panic
    assert_eq!(size_class_bytes(usize::MAX), None);
}

#[test]
fn fresh_slabheap_is_uninitialised_with_empty_freelists() {
    let heap = SlabHeap::new();
    assert!(!heap.is_initialised());
    assert_eq!(heap.used_bytes(), 0);
    assert_eq!(heap.total_bytes(), 0);
    for idx in 0..NUM_SIZE_CLASSES {
        assert_eq!(heap.free_list_head(idx), 0, "class {idx} must start empty");
    }
    // Out-of-range index is a benign empty head, never a panic.
    assert_eq!(heap.free_list_head(NUM_SIZE_CLASSES), 0);
}

#[test]
fn slabheap_init_reports_total_and_zero_used() {
    let heap = SlabHeap::new();
    let (base, len) = static_region(64 * 1024);
    unsafe { heap.init(base, len) };
    assert!(heap.is_initialised());
    assert_eq!(heap.total_bytes(), 64 * 1024);
    assert_eq!(heap.used_bytes(), 0, "cursor at base before any carve");
}

#[test]
#[should_panic(expected = "SlabHeap::init called twice")]
fn slabheap_double_init_panics() {
    let heap = SlabHeap::new();
    let (base, len) = static_region(1024);
    unsafe { heap.init(base, len) };
    unsafe { heap.init(base, len) }; // second call MUST panic (one-shot contract)
}

#[test]
fn slabheap_default_matches_new() {
    let heap = SlabHeap::default();
    assert!(!heap.is_initialised());
}

// ---- WS1-08.3: intrusive free-list push/pop (NCIP-029 § S3.2) --------------

/// A `usize`-aligned synthetic region. `push_free` writes the intrusive link
/// into a block's first word, so the backing store must be at least
/// `align_of::<usize>()`-aligned (a `Vec<u8>` makes no such guarantee).
fn aligned_region(len: usize) -> (*mut u8, usize) {
    let words = (len + 7) / 8;
    let buf = vec![0u64; words].leak();
    (buf.as_mut_ptr().cast::<u8>(), words * 8)
}

#[test]
fn freelist_push_pop_is_lifo_and_reuses() {
    let heap = SlabHeap::new();
    let (base, len) = aligned_region(4096);
    unsafe { heap.init(base, len) };

    // Three distinct class-2 (64-byte) blocks inside the region.
    let b0 = base;
    let b1 = unsafe { base.add(64) };
    let b2 = unsafe { base.add(128) };

    assert_eq!(heap.free_list_head(2), 0, "class starts empty");
    unsafe { heap.push_free(2, b0) };
    unsafe { heap.push_free(2, b1) };
    unsafe { heap.push_free(2, b2) };
    assert_eq!(heap.free_list_head(2), b2 as usize, "head is last pushed");

    // LIFO: most-recently-pushed comes back first.
    assert_eq!(unsafe { heap.pop_free(2) }, Some(b2));
    assert_eq!(unsafe { heap.pop_free(2) }, Some(b1));
    assert_eq!(unsafe { heap.pop_free(2) }, Some(b0));
    assert!(
        unsafe { heap.pop_free(2) }.is_none(),
        "drained list is empty"
    );
    assert_eq!(heap.free_list_head(2), 0);
}

#[test]
fn freelist_pop_empty_and_out_of_range_returns_none() {
    let heap = SlabHeap::new();
    let (base, len) = aligned_region(1024);
    unsafe { heap.init(base, len) };
    assert!(unsafe { heap.pop_free(0) }.is_none(), "empty class → None");
    assert!(
        unsafe { heap.pop_free(NUM_SIZE_CLASSES) }.is_none(),
        "out-of-range idx → None"
    );
    // push to an out-of-range class is a no-op, not a crash.
    unsafe { heap.push_free(NUM_SIZE_CLASSES, base) };
    assert_eq!(heap.free_list_head(NUM_SIZE_CLASSES), 0);
}

#[test]
fn freelist_classes_are_independent() {
    let heap = SlabHeap::new();
    let (base, len) = aligned_region(4096);
    unsafe { heap.init(base, len) };
    let a = base;
    let b = unsafe { base.add(512) };

    unsafe { heap.push_free(1, a) }; // class 1 (32 B)
    unsafe { heap.push_free(5, b) }; // class 5 (512 B)

    assert_eq!(heap.free_list_head(2), 0, "untouched class stays empty");
    assert_eq!(unsafe { heap.pop_free(5) }, Some(b), "class 5 isolated");
    assert_eq!(unsafe { heap.pop_free(1) }, Some(a), "class 1 isolated");
}

#[test]
fn freelist_concurrent_push_conserves_all_blocks() {
    // Concurrent push is ABA-free (each block is private to its pusher). After
    // all threads finish, every distinct block must be recoverable exactly
    // once — no loss, no duplication under CAS contention.
    const THREADS: usize = 4;
    const PER_THREAD: usize = 256;
    const BLOCK: usize = 64; // class 2
    let heap = SlabHeap::new();
    let total = THREADS * PER_THREAD;
    let (base, len) = aligned_region(total * BLOCK);
    unsafe { heap.init(base, len) };
    let base_addr = base as usize;

    std::thread::scope(|s| {
        for t in 0..THREADS {
            let heap = &heap;
            s.spawn(move || {
                for i in 0..PER_THREAD {
                    let off = (t * PER_THREAD + i) * BLOCK;
                    let p = (base_addr + off) as *mut u8;
                    unsafe { heap.push_free(2, p) };
                }
            });
        }
    });

    let mut seen = std::collections::HashSet::new();
    while let Some(p) = unsafe { heap.pop_free(2) } {
        assert!(seen.insert(p as usize), "duplicate block popped");
    }
    assert_eq!(seen.len(), total, "all pushed blocks must be recoverable");
}

// ---- WS1-08.4: allocate — class selection + free-list + slab carve --------

/// A page-aligned synthetic region, so `align_up(base, class)` adds no padding
/// for any class ≤ `PAGE_BYTES` and `used_bytes` is exact in the assertions
/// below. Leaked, like the other fixtures.
fn page_region(len: usize) -> (*mut u8, usize) {
    let layout = std::alloc::Layout::from_size_align(len, PAGE_BYTES).unwrap();
    let p = unsafe { std::alloc::alloc_zeroed(layout) };
    assert!(!p.is_null(), "test fixture allocation failed");
    (p, len)
}

#[test]
fn allocate_uninitialised_returns_null() {
    let heap = SlabHeap::new();
    let l = Layout::from_size_align(64, 8).unwrap();
    assert!(unsafe { heap.allocate(l) }.is_null());
}

#[test]
fn allocate_serves_each_class_aligned_and_in_bounds() {
    let heap = SlabHeap::new();
    let (base, len) = page_region(1 << 20); // 1 MiB
    unsafe { heap.init(base, len) };
    let base_addr = base as usize;

    for &c in &SIZE_CLASSES {
        let l = Layout::from_size_align(c, c).unwrap();
        let p = unsafe { heap.allocate(l) };
        assert!(!p.is_null(), "class {c} must allocate");
        assert_eq!((p as usize) % c, 0, "class {c} must be {c}-aligned");
        let addr = p as usize;
        assert!(addr >= base_addr, "class {c} in bounds (low)");
        assert!(addr + c <= base_addr + len, "class {c} in bounds (high)");
    }
}

#[test]
fn allocate_batches_a_slab_then_reuses_free_list() {
    // NCIP-029 § S3.3 + I3: the first small alloc carves one page-sized slab and
    // threads the remainder onto the free-list; subsequent same-class allocs
    // are served from the free-list with no new carve.
    let heap = SlabHeap::new();
    let (base, len) = page_region(16 * 1024);
    unsafe { heap.init(base, len) };
    let l = Layout::from_size_align(16, 8).unwrap(); // class 0 (16 B)
    let per_slab = PAGE_BYTES / 16; // 256 blocks per slab

    let p1 = unsafe { heap.allocate(l) };
    assert!(!p1.is_null());
    assert_eq!(heap.used_bytes(), PAGE_BYTES, "first alloc carves one slab");
    assert_ne!(
        heap.free_list_head(0),
        0,
        "slab remainder threaded to free-list"
    );

    // The rest of the slab (per_slab - 1 blocks) comes from the free-list.
    for _ in 0..(per_slab - 1) {
        assert!(!unsafe { heap.allocate(l) }.is_null());
    }
    assert_eq!(
        heap.used_bytes(),
        PAGE_BYTES,
        "{per_slab} allocs all served from one slab — no extra carve"
    );
    assert_eq!(heap.free_list_head(0), 0, "free-list drained");

    // The next alloc must carve a second slab.
    assert!(!unsafe { heap.allocate(l) }.is_null());
    assert_eq!(heap.used_bytes(), 2 * PAGE_BYTES, "second slab carved");
}

#[test]
fn allocate_large_path_page_rounds_and_aligns() {
    let heap = SlabHeap::new();
    let (base, len) = page_region(1 << 20);
    unsafe { heap.init(base, len) };
    let l = Layout::from_size_align(5000, 8).unwrap(); // > MAX_SMALL_BYTES
    let p = unsafe { heap.allocate(l) };
    assert!(!p.is_null());
    assert_eq!((p as usize) % PAGE_BYTES, 0, "large path is page-aligned");
    assert_eq!(
        heap.used_bytes(),
        2 * PAGE_BYTES,
        "5000 B rounds up to 2 pages"
    );
}

#[test]
fn allocate_rejects_alignment_above_a_page() {
    let heap = SlabHeap::new();
    let (base, len) = page_region(1 << 20);
    unsafe { heap.init(base, len) };
    // align 8192 (> PAGE_BYTES, and above the MAX_SMALL_BYTES small-class cap)
    // → large path → deferred → null (§ S2.3.3).
    let l = Layout::from_size_align(64, 8192).unwrap();
    assert!(unsafe { heap.allocate(l) }.is_null());
}

#[test]
fn allocate_oom_returns_null_without_panic() {
    let heap = SlabHeap::new();
    let (base, len) = page_region(PAGE_BYTES); // exactly one page
    unsafe { heap.init(base, len) };
    let l = Layout::from_size_align(4000, 8).unwrap(); // class 4096 → fills the page
    let p1 = unsafe { heap.allocate(l) };
    assert!(!p1.is_null());
    // Arena exhausted: the next request must return null, not panic.
    let p2 = unsafe { heap.allocate(l) };
    assert!(p2.is_null(), "OOM must return null");
}

// ---- WS1-08.5: free — reinsert into the correct free-list -----------------

#[test]
fn free_small_returns_block_to_its_class() {
    let heap = SlabHeap::new();
    let (base, len) = page_region(16 * 1024);
    unsafe { heap.init(base, len) };
    let l = Layout::from_size_align(100, 8).unwrap(); // class 128 (idx 3)

    let p = unsafe { heap.allocate(l) };
    assert!(!p.is_null());
    let used_after_alloc = heap.used_bytes();
    unsafe { heap.free(p, l) };
    // The freed block heads class 3's free-list and the very next same-class
    // allocation hands it straight back (LIFO reuse), with no extra carve.
    assert_eq!(
        heap.free_list_head(3),
        p as usize,
        "freed block heads class 3"
    );
    let p2 = unsafe { heap.allocate(l) };
    assert_eq!(p2, p, "alloc after free reuses the same block");
    assert_eq!(
        heap.used_bytes(),
        used_after_alloc,
        "reuse carves nothing new"
    );
}

#[test]
fn free_null_is_a_noop() {
    let heap = SlabHeap::new();
    let (base, len) = page_region(4096);
    unsafe { heap.init(base, len) };
    let l = Layout::from_size_align(64, 8).unwrap();
    unsafe { heap.free(core::ptr::null_mut(), l) }; // must not crash / mutate
    for idx in 0..NUM_SIZE_CLASSES {
        assert_eq!(heap.free_list_head(idx), 0);
    }
}

#[test]
fn alloc_free_churn_does_not_grow_used_bytes() {
    // The whole point of the allocator: churn must not leak. Allocate and free
    // the same class repeatedly; arena consumption stays at one slab.
    let heap = SlabHeap::new();
    let (base, len) = page_region(64 * 1024);
    unsafe { heap.init(base, len) };
    let l = Layout::from_size_align(64, 8).unwrap(); // class 2
    let first = unsafe { heap.allocate(l) };
    assert!(!first.is_null());
    let baseline = heap.used_bytes();
    for _ in 0..10_000 {
        let p = unsafe { heap.allocate(l) };
        assert!(!p.is_null());
        unsafe { heap.free(p, l) };
    }
    assert_eq!(
        heap.used_bytes(),
        baseline,
        "10k alloc/free cycles must not carve beyond the first slab"
    );
}

#[test]
fn free_large_run_is_reused_by_a_same_size_alloc() {
    let heap = SlabHeap::new();
    let (base, len) = page_region(1 << 20);
    unsafe { heap.init(base, len) };
    let l = Layout::from_size_align(5000, 8).unwrap(); // 2-page run
    let p1 = unsafe { heap.allocate(l) };
    assert!(!p1.is_null());
    let used = heap.used_bytes();
    unsafe { heap.free(p1, l) };
    let p2 = unsafe { heap.allocate(l) };
    assert_eq!(p2, p1, "freed large run is reused exactly");
    assert_eq!(heap.used_bytes(), used, "large reuse carves nothing new");
}

#[test]
fn free_large_run_splits_for_a_smaller_alloc() {
    // Free a 4-page run, then satisfy two 2-page allocations from it via
    // first-fit + split — no fresh carve for either.
    let heap = SlabHeap::new();
    let (base, len) = page_region(1 << 20);
    unsafe { heap.init(base, len) };
    let big = Layout::from_size_align(4 * PAGE_BYTES, 8).unwrap(); // 4-page run
    let small = Layout::from_size_align(2 * PAGE_BYTES, 8).unwrap(); // 2-page run

    let pbig = unsafe { heap.allocate(big) };
    assert!(!pbig.is_null());
    let used = heap.used_bytes();
    unsafe { heap.free(pbig, big) }; // 4-page run on the large free-list

    let a = unsafe { heap.allocate(small) };
    assert!(!a.is_null());
    assert_eq!(a as usize, pbig as usize, "first 2 pages come from the run");
    // Remainder (2 pages) was pushed back as a large run; the next 2-page alloc
    // reuses it — still no fresh carve.
    let b = unsafe { heap.allocate(small) };
    assert!(!b.is_null());
    assert_eq!(
        b as usize,
        pbig as usize + 2 * PAGE_BYTES,
        "second 2 pages come from the split remainder"
    );
    assert_eq!(heap.used_bytes(), used, "split reuse carves nothing new");
}

#[test]
fn free_large_run_recycles_one_page_remainder_into_class_8() {
    // A 3-page run split for a 2-page request leaves exactly one page, which
    // must reappear as a small class-8 (4096 B) block — not stranded.
    let heap = SlabHeap::new();
    let (base, len) = page_region(1 << 20);
    unsafe { heap.init(base, len) };
    let three = Layout::from_size_align(3 * PAGE_BYTES, 8).unwrap();
    let two = Layout::from_size_align(2 * PAGE_BYTES, 8).unwrap();

    let p3 = unsafe { heap.allocate(three) };
    assert!(!p3.is_null());
    unsafe { heap.free(p3, three) };
    assert_eq!(heap.free_list_head(8), 0, "class 8 starts empty");

    let a = unsafe { heap.allocate(two) }; // splits: 2 pages out, 1 page remainder
    assert_eq!(a as usize, p3 as usize);
    assert_eq!(
        heap.free_list_head(8),
        p3 as usize + 2 * PAGE_BYTES,
        "one-page remainder recycled into class 8"
    );
}

// ---- WS1-08.6: GlobalAlloc trait wiring (the path the kernel takes) -------

#[test]
fn slabheap_globalalloc_trait_alloc_and_dealloc() {
    // Exercise SlabHeap through the GlobalAlloc trait — the exact entry point
    // the kernel's `#[global_allocator]` uses. The inherent `allocate`/`free`
    // are tested above; this asserts the trait forwarding is correct.
    let heap = SlabHeap::new();
    let (base, len) = page_region(64 * 1024);
    unsafe { heap.init(base, len) };

    let l = Layout::from_size_align(48, 8).unwrap(); // class 64 (idx 2)
    let p = unsafe { GlobalAlloc::alloc(&heap, l) };
    assert!(!p.is_null(), "trait alloc returns a block");
    assert_eq!((p as usize) % 8, 0, "trait alloc honours alignment");

    // Write through the whole reported size to confirm it is writable.
    unsafe { core::ptr::write_bytes(p, 0xABu8, l.size()) };

    let used = heap.used_bytes();
    unsafe { GlobalAlloc::dealloc(&heap, p, l) };
    let p2 = unsafe { GlobalAlloc::alloc(&heap, l) };
    assert_eq!(
        p2, p,
        "trait dealloc returns the block to its free-list for reuse"
    );
    assert_eq!(
        heap.used_bytes(),
        used,
        "reuse via the trait carves nothing new"
    );
}

#[test]
fn slabheap_globalalloc_dealloc_null_is_noop() {
    let heap = SlabHeap::new();
    let (base, len) = page_region(4096);
    unsafe { heap.init(base, len) };
    let l = Layout::from_size_align(64, 8).unwrap();
    unsafe { GlobalAlloc::dealloc(&heap, core::ptr::null_mut(), l) }; // must not crash
}

// ---- WS1-08.8: 10^5 channel-sized create/destroy in a limited arena -------

#[test]
fn stress_channel_sized_churn_in_limited_arena_no_oom() {
    // The allocator-level half of WS1-08.8: 100_000 "create + destroy" cycles
    // of a channel-sized allocation set (a queue buffer + two waiter buffers,
    // mirroring `Channel`'s heap footprint) against a deliberately small arena.
    // A non-reclaiming allocator would exhaust 512 KiB within ~1.4k cycles; the
    // reclaiming SlabHeap must run all 100k with `used_bytes` bounded to the few
    // slabs the touched classes ever need.
    let heap = SlabHeap::new();
    let (base, len) = page_region(512 * 1024); // 512 KiB ≪ 100k × channel footprint
    unsafe { heap.init(base, len) };

    let q = Layout::from_size_align(256, 8).unwrap(); // queue buffer  → class 256
    let w1 = Layout::from_size_align(64, 8).unwrap(); // waiters_send  → class 64
    let w2 = Layout::from_size_align(64, 8).unwrap(); // waiters_recv  → class 64

    for _ in 0..100_000u32 {
        let a = unsafe { heap.allocate(q) };
        let b = unsafe { heap.allocate(w1) };
        let c = unsafe { heap.allocate(w2) };
        assert!(
            !a.is_null() && !b.is_null() && !c.is_null(),
            "no OOM under create/destroy churn in a limited arena"
        );
        unsafe {
            heap.free(a, q);
            heap.free(b, w1);
            heap.free(c, w2);
        }
    }

    // Only the two touched classes (256 and 64) ever carve a slab; memory is
    // bounded regardless of the 100k cycles — the anti-leak guarantee at scale.
    assert!(
        heap.used_bytes() <= 8 * PAGE_BYTES,
        "used_bytes must stay bounded under churn, got {}",
        heap.used_bytes()
    );
}
