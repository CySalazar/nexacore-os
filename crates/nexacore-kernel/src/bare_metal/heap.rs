//! In-crate allocators backing the kernel `#[global_allocator]`.
//!
//! Two allocators live here:
//!
//! - [`SlabHeap`] — the **installed** global allocator as of WS1-08.6
//!   (`NCIP-Kernel-Alloc-029`): a reclaiming slab + free-list allocator with
//!   fixed power-of-two size classes and a page-granular large path. It is what
//!   the kernel actually runs on.
//! - [`BumpHeap`] — the **legacy** K3 allocator (`NCIP-Kernel-012` § S2),
//!   described below. No longer registered; retained for reference.
//!
//! The original bump allocator is specified by [`NCIP-Kernel-012`] § S2. The
//! allocator is **bump**: every allocation advances a single atomic pointer;
//! nothing is ever freed. This is the smallest possible TCB surface for a
//! kernel-side allocator (≈ 80 lines of `unsafe`-free Rust over `core::sync::
//! atomic`) and matches the pattern used by `seL4`, `NOVA`, and `Redox`'s
//! early-boot path. `SlabHeap` keeps this bump cursor as its *slab source* but
//! adds real reclamation on top.
//!
//! ## Properties (binding by § S2)
//!
//! 1. **One-shot `init`.** Setting `base`/`end` more than once panics.
//! 2. **No `dealloc`.** `dealloc()` is a no-op. The kernel's heap is
//!    populated with long-lived structures (IPC ring buffers, task
//!    table, capability table); transient allocations either avoid
//!    the kernel heap or live for the kernel's lifetime.
//! 3. **Honour alignment.** The bump pointer is rounded up before
//!    each allocation.
//! 4. **OOM returns null.** When `next + size > end`, `alloc` returns
//!    `null_mut()`. The Rust `alloc` crate routes this through its
//!    default alloc-error hook, which on `no_std` ultimately panics
//!    into our [`super::panic`] handler.
//! 5. **Single-CPU at v1.0** — the atomic operations are present so
//!    a future SMP enablement does not require an allocator rewrite.
//! 6. **No external crate.** `linked_list_allocator`, `talc`, and
//!    `buddy_system_allocator` are all reasonable v1.x candidates but
//!    are deferred behind a separate NCIP (each adds an external trust
//!    base).
//!
//! ## API surface
//!
//! - [`BumpHeap`] — the allocator type. `pub const fn new()` so it
//!   can be used to initialise a `static` at compile time.
//! - [`BumpHeap::init`] — one-shot installation of the heap region,
//!   called from `kernel_entry` (the runner) once `BootInfo` is
//!   available. K3 leaves the region-selection policy to the runner;
//!   K4 / `NCIP-Kernel-005` adds `pick_region` to bridge `BootInfo`'s
//!   `MemoryRegions` to this `init` call.
//! - `#[global_allocator] static GLOBAL_HEAP` — the singleton
//!   instance, attribute-gated `target_os = "none"` so the test
//!   harness on host keeps its own allocator.

use core::{
    alloc::{GlobalAlloc, Layout},
    ptr,
    sync::atomic::{AtomicUsize, Ordering},
};

/// Magic value for `BumpHeap::base` / `end` in the uninitialised
/// state. Picked so a stray dereference traps deterministically
/// (canonical-non-canonical `x86_64` address).
const UNINIT: usize = 0;

/// Single-allocator-per-binary bump heap.
///
/// **Legacy (K3 / `NCIP-Kernel-012` § S2).** As of WS1-08.6 the installed
/// `#[global_allocator]` is the reclaiming [`SlabHeap`] (NCIP-029); `BumpHeap`
/// is no longer registered. It is retained as the reference implementation of
/// the never-free bump policy — and its `tests/heap.rs` suite still exercises
/// the bump-cursor algorithm that `SlabHeap::carve` mirrors as its slab source.
///
/// All three fields are `AtomicUsize` rather than `AtomicPtr<u8>`
/// because the alignment math is cleaner in integer space and the
/// final pointer conversion is a single cast at allocation time.
pub struct BumpHeap {
    base: AtomicUsize,
    next: AtomicUsize,
    end: AtomicUsize,
}

impl BumpHeap {
    /// Construct an uninitialised heap.
    ///
    /// The result is **not safe to allocate against** until
    /// [`Self::init`] runs.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            base: AtomicUsize::new(UNINIT),
            next: AtomicUsize::new(UNINIT),
            end: AtomicUsize::new(UNINIT),
        }
    }

    /// One-shot installation of the heap region.
    ///
    /// `base` is the lowest address of a contiguous region of `len`
    /// bytes the allocator may hand out. The pointer + length pair is
    /// sourced from the bootloader's memory map (`NCIP-Kernel-005`
    /// `pick_region` in K4); for K3 the caller is the test harness or
    /// the kernel-runner shim invoking this directly.
    ///
    /// # Safety
    ///
    /// The caller MUST guarantee that:
    /// - `base..base + len` is a single contiguous mapped region the
    ///   kernel exclusively owns for the remainder of the boot.
    /// - The region is at least `MIN_HEAP_BYTES` long (the K4
    ///   `pick_region` enforces this; the K3 path is documented as a
    ///   stop-gap).
    /// - `init` is called exactly once. A second invocation panics.
    ///
    /// # Panics
    ///
    /// Panics if the heap has already been initialised (the `base`
    /// CAS from `UNINIT` to `base as usize` fails).
    pub unsafe fn init(&self, base: *mut u8, len: usize) {
        let base_addr = base as usize;
        let Some(end_addr) = base_addr.checked_add(len) else {
            // The K4 `pick_region` enforces a 4 MiB minimum and reads
            // its inputs from the bootloader memory map, both of which
            // exclude this overflow path in practice. A kernel that
            // *did* reach it is in an invariant-violated state and
            // panicking is the correct loud signal — captured here
            // explicitly so the `Option::expect` lint stays clean.
            #[allow(
                clippy::panic,
                reason = "kernel invariant violation: heap region overflows usize"
            )]
            {
                panic!("BumpHeap::init: base + len overflows usize");
            }
        };
        // Atomically install `base` exactly once. A second init() call
        // observes a non-UNINIT `base` and is reported as a kernel
        // invariant violation.
        if self
            .base
            .compare_exchange(UNINIT, base_addr, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
        {
            self.end.store(end_addr, Ordering::Release);
            self.next.store(base_addr, Ordering::Release);
        } else {
            #[allow(
                clippy::panic,
                reason = "kernel invariant violation: BumpHeap::init called twice"
            )]
            {
                panic!("BumpHeap::init called twice — kernel invariant violation");
            }
        }
    }

    /// Report whether the heap has been initialised.
    ///
    /// Visible to host tests that want to assert pre/post-init
    /// behaviour separately. The bare-metal binary never calls this
    /// — `init` is invoked exactly once from `kernel_entry`.
    #[must_use]
    pub fn is_initialised(&self) -> bool {
        self.base.load(Ordering::Acquire) != UNINIT
    }

    /// Returns the number of bytes already handed out by the
    /// allocator (useful for forensics / telemetry; not part of the
    /// `GlobalAlloc` contract).
    #[must_use]
    pub fn used_bytes(&self) -> usize {
        let base = self.base.load(Ordering::Acquire);
        let next = self.next.load(Ordering::Acquire);
        next.saturating_sub(base)
    }

    /// Returns the total heap region size in bytes.
    #[must_use]
    pub fn total_bytes(&self) -> usize {
        let base = self.base.load(Ordering::Acquire);
        let end = self.end.load(Ordering::Acquire);
        end.saturating_sub(base)
    }
}

impl Default for BumpHeap {
    fn default() -> Self {
        Self::new()
    }
}

/// Round `addr` up to a multiple of `align`.
///
/// `align` MUST be a power of two — `core::alloc::Layout` invariants
/// guarantee this for any `Layout` we receive.
#[inline]
const fn align_up(addr: usize, align: usize) -> usize {
    // `(addr + align - 1) & !(align - 1)` rounds up to a multiple of
    // `align`. The pre-add is checked for overflow at the call site
    // via the subsequent `> end` comparison; we use `wrapping_add`
    // here because an overflow downstream is caught structurally.
    addr.wrapping_add(align - 1) & !(align - 1)
}

// SAFETY: `BumpHeap` upholds the `GlobalAlloc` contract:
//  - `alloc` returns either a properly-aligned, non-null pointer to
//    `layout.size()` writable bytes inside the heap region, or null.
//  - `dealloc` is a no-op, which is a valid `GlobalAlloc` impl for an
//    arena allocator (memory simply leaks until kernel shutdown).
//  - All pointer arithmetic is bounded by `base ≤ next ≤ end`, the
//    sole invariant. The `compare_exchange_weak` loop maintains it
//    under any interleaving across CPUs.
unsafe impl GlobalAlloc for BumpHeap {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let end = self.end.load(Ordering::Acquire);
        if end == UNINIT {
            // Allocator not initialised. Returning null here lets the
            // `alloc` crate trigger its OOM handler — which will
            // route into our panic handler.
            return ptr::null_mut();
        }
        let mut current = self.next.load(Ordering::Acquire);
        loop {
            let aligned = align_up(current, layout.align());
            let Some(new_next) = aligned.checked_add(layout.size()) else {
                return ptr::null_mut();
            };
            if new_next > end {
                return ptr::null_mut();
            }
            match self.next.compare_exchange_weak(
                current,
                new_next,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => return aligned as *mut u8,
                Err(actual) => current = actual,
            }
        }
    }

    unsafe fn dealloc(&self, _ptr: *mut u8, _layout: Layout) {
        // No-op. See § S2 constraint 2.
    }
}

/// The singleton `#[global_allocator]` instance for the bare-metal
/// kernel.
///
/// As of WS1-08.6 (NCIP-Kernel-Alloc-029) this is the reclaiming
/// [`SlabHeap`], installed in place of the legacy [`BumpHeap`]. The
/// `init` / `used_bytes` / `total_bytes` surface is identical, so the
/// `kernel-runner` boot hand-off (`GLOBAL_HEAP.init(base, len)`) is
/// unchanged.
///
/// Gated `target_os = "none"` (the bare-metal cross-target) so that a
/// host build with `--features bare-metal` does not try to install a
/// second `#[global_allocator]` alongside `std`'s default. Host
/// integration tests at `tests/heap.rs` construct fresh allocator
/// instances over a stack buffer and exercise them directly without
/// registering one globally.
#[cfg(all(target_os = "none", not(test)))]
#[global_allocator]
pub static GLOBAL_HEAP: SlabHeap = SlabHeap::new();

/// Minimum heap region size accepted by [`pick_region`].
///
/// Per `NCIP-Kernel-005` § S5 and `NCIP-Kernel-003` § 5 rationale: the
/// long-lived kernel allocations (IPC ring buffers, task table,
/// capability table) at the v1.0 "small-server" baseline (256
/// channels × 64 KiB + 1024 tasks × 1 KiB + 16k capabilities × 256 B
/// ≈ 21 MiB) need at least 4 MiB headroom. Hardware that cannot
/// surface a 4 MiB contiguous Usable region falls back to the panic
/// path with a clear message.
///
/// Changing this constant is breaking-change-equivalent at the boot
/// ABI (hardware that boots today may not boot tomorrow) and requires
/// an NCIP that supersedes `NCIP-Kernel-005`.
pub const MIN_HEAP_BYTES: usize = 4 * 1024 * 1024;

/// Upper bound on the heap arena installed by [`pick_region`].
///
/// The selected Usable region is frequently the single largest block of
/// RAM (often nearly all of it). The `BumpHeap` claims its entire reported
/// length as its arena, so without a cap the heap would lay claim to the
/// same physical frames the [`crate::memory::BitmapFrameAllocator`] hands
/// out for page tables and user stacks — they would silently alias and
/// corrupt one another once the bump pointer grew far enough (the M0
/// cross-process user-stack corruption, 2026-06-03).
///
/// Capping the returned length to a fixed ceiling keeps the heap arena and
/// the frame allocator **disjoint**: `pick_region` returns `(base, capped)`
/// to `BumpHeap::init` AND to the kmain reservation
/// (`mark_range_used(base, capped)`), so both agree on the exact bytes the
/// heap owns; every frame beyond `capped` in the same region stays free for
/// the frame allocator.
///
/// 128 MiB comfortably covers the kernel's heap working set (VFS-resident
/// initramfs, scheduler/IPC structures, the userspace network stack, the
/// desktop) with wide margin while leaving the bulk of RAM for frames.
pub const HEAP_MAX_BYTES: usize = 128 * 1024 * 1024;

// =============================================================================
// pick_region — bridge `bootloader::bootinfo::BootInfo::memory_map`
// to a contiguous heap region for `BumpHeap::init`.
//
// NCIP-Kernel-005 § S5.
// =============================================================================

/// Select the heap region from a bootloader-supplied memory map.
///
/// The selection algorithm (per `NCIP-Kernel-005` § S5):
///
/// 1. Iterate `regions` in order.
/// 2. Filter to entries with `kind == MemoryRegionKind::Usable`.
/// 3. Pick the **largest** filtered entry whose length is at least
///    [`MIN_HEAP_BYTES`].
/// 4. Tie-break on equal length by **lowest start address**
///    (determinism across boots on the same hardware — same map →
///    same returned region).
/// 5. If no entry satisfies (3), panic with a clear "no usable heap
///    region" message. The K3 panic handler emits the structured
///    record over COM1 and halts; this is the documented "unbootable
///    hardware" termination state.
///
/// Returns `(*mut u8, usize)` — the base pointer and length of the
/// chosen region, suitable for passing directly into
/// [`BumpHeap::init`].
///
/// # Panics
///
/// Panics if no Usable contiguous region of at least [`MIN_HEAP_BYTES`]
/// exists in `regions`.
#[cfg(feature = "bare-metal")]
#[must_use]
pub fn pick_region(regions: &[bootloader_api::info::MemoryRegion]) -> (*mut u8, usize) {
    use bootloader_api::info::MemoryRegionKind;

    let mut best: Option<(u64, u64)> = None; // (start, length)
    for region in regions {
        if region.kind != MemoryRegionKind::Usable {
            continue;
        }
        let length = region.end.saturating_sub(region.start);
        // x86_64 is 64-bit; `u64 → usize` is lossless on the kernel
        // target. The cast lint also fires on 32-bit hosts during
        // host tests, where the actual u64 values are bounded to
        // synthetic test fixtures (well under usize::MAX).
        #[allow(
            clippy::cast_possible_truncation,
            reason = "u64 → usize is lossless on x86_64; bounded on test hosts"
        )]
        let length_us = length as usize;
        if length_us < MIN_HEAP_BYTES {
            continue;
        }
        let region_start = region.start;
        match best {
            None => best = Some((region_start, length)),
            Some((cur_start, cur_len)) => {
                if length > cur_len || (length == cur_len && region_start < cur_start) {
                    best = Some((region_start, length));
                }
            }
        }
    }

    match best {
        Some((start, length)) => {
            // Same `u64 → usize` lossless cast as above; the start
            // address fits in a pointer because the bootloader's
            // memory map already ranges over the host's address
            // space.
            #[allow(
                clippy::cast_possible_truncation,
                reason = "u64 → usize is lossless on x86_64; bounded on test hosts"
            )]
            // Cap the arena to `HEAP_MAX_BYTES` so it stays disjoint from the
            // frame allocator's pool (see `HEAP_MAX_BYTES`). The selection above
            // still ranks by the FULL region length; only the arena handed to
            // `BumpHeap::init` (and reserved in `FRAME_ALLOC`) is bounded.
            let length_us = (length as usize).min(HEAP_MAX_BYTES);
            (start as *mut u8, length_us)
        }
        None => {
            #[allow(
                clippy::panic,
                reason = "documented \"unbootable hardware\" termination state per NCIP-Kernel-005 § S5"
            )]
            {
                panic!("no usable heap region of \u{2265} 4 MiB found in BootInfo memory map");
            }
        }
    }
}

// Host-mode tests can exercise `pick_region`'s logic by importing the
// `bootloader` types directly (it is `no_std`). The integration
// test at `tests/boot_info.rs` covers tie-breaking, smallest-rejection,
// and the panic-on-empty case.

// =============================================================================
// SlabHeap — slab + free-list allocator (NCIP-Kernel-Alloc-029)
//
// Replaces `BumpHeap`'s never-free policy with a reclaiming allocator.
// This is staged across plan task WS1-08:
//   .2 (here) — the type + fixed size classes (§ S3.1) + one-shot arena
//               install. Host-testable in isolation.
//   .3        — intrusive free-list push/pop (§ S3.2).
//   .4 / .5   — `alloc` / `free` over the slab + free-list (§ S2).
//   .6        — install behind `#[global_allocator]` in place of `BumpHeap`.
// The bump cursor is retained here as the *slab source* (§ S3.3): when a
// class's free-list is empty, `alloc` (WS1-08.4) will carve a fresh block
// by advancing `next`, exactly as `BumpHeap::alloc` does today.
// =============================================================================

/// Fixed, power-of-two small-allocation size classes (NCIP-029 § S3.1).
///
/// A small request is rounded up to the smallest class that fits both its
/// size and its alignment. Power-of-two spacing bounds internal
/// fragmentation to `< 2×` and makes the class a pure function of
/// `max(size, align)` (see [`size_class_index`]), so the small path needs
/// no per-block metadata.
pub const SIZE_CLASSES: [usize; 9] = [16, 32, 64, 128, 256, 512, 1024, 2048, 4096];

/// Number of small size classes — the per-class free-list array length.
pub const NUM_SIZE_CLASSES: usize = SIZE_CLASSES.len();

/// Largest small-path allocation, in bytes (NCIP-029 § S3.1).
///
/// Requests whose effective size (`max(size, align)`) exceeds this take the
/// page-granular large path (§ S3.3, implemented in WS1-08.4).
pub const MAX_SMALL_BYTES: usize = 4096;

/// Page granularity for the large path and the slab carve unit (NCIP-029 § S3.3).
///
/// Equal to [`MAX_SMALL_BYTES`] by design — the largest small class is exactly
/// one page, so the small-path slab source and the large-path run granularity
/// share a constant.
pub const PAGE_BYTES: usize = 4096;

/// Smallest large run, in bytes (NCIP-029 § S3.3).
///
/// A large request is `> MAX_SMALL_BYTES` (4096) by definition, so its
/// page-rounded run is at least two pages. A split remainder below this is not
/// a reusable large run: an exactly-one-page (4096 B) remainder is recycled
/// into small size class 8 instead (it is a valid `PAGE_BYTES`-aligned,
/// `PAGE_BYTES`-byte block), keeping reclamation complete (§ S2.4.3).
const LARGE_RUN_MIN: usize = 2 * PAGE_BYTES;

/// Round `size` up to a whole number of [`PAGE_BYTES`] pages, or [`None`] on
/// overflow. The large path operates in page units (§ S3.3); both `allocate`
/// and `free` derive a request's run length from `layout` via this function,
/// so no per-block size header is needed.
fn page_round_up(size: usize) -> Option<usize> {
    size.checked_add(PAGE_BYTES - 1)
        .map(|s| s & !(PAGE_BYTES - 1))
}

/// Sentinel for an empty free-list head (and, sharing the `UNINIT` value, an
/// uninitialised cursor). A real heap block is never at address 0, so 0 is an
/// unambiguous "no block" marker for the intrusive list (WS1-08.3).
const NULL_LINK: usize = 0;

/// Select the size-class index for a small request, or [`None`] for the large
/// path.
///
/// The chosen class is the smallest class whose size is `≥ max(size, align)`
/// — alignment promotion per NCIP-029 § S2.3.2 (a request that needs more
/// alignment than its size class naturally provides is promoted to a class
/// that is a multiple of `align`, which for power-of-two classes is simply the
/// class `≥ align`). A `size` of 0 is treated as 1 (§ S2.1.4): `align` is
/// always `≥ 1`, so the effective need is `≥ 1` and maps to the smallest
/// class.
///
/// Returns [`None`] when `max(size, align) > MAX_SMALL_BYTES`, signalling the
/// caller to use the large path.
#[must_use]
#[allow(
    clippy::indexing_slicing,
    reason = "`i` is bounded by the `i < NUM_SIZE_CLASSES` loop condition; \
              `.get()` is not a const fn so direct indexing is required here"
)]
pub const fn size_class_index(size: usize, align: usize) -> Option<usize> {
    let need = if size > align { size } else { align };
    if need > MAX_SMALL_BYTES {
        return None;
    }
    let mut i = 0;
    while i < NUM_SIZE_CLASSES {
        if SIZE_CLASSES[i] >= need {
            return Some(i);
        }
        i += 1;
    }
    // Unreachable in practice: `need ≤ MAX_SMALL_BYTES` and the last class is
    // exactly `MAX_SMALL_BYTES`, so the loop always returns above. Kept as a
    // total function (no panic) for the `const fn` contract.
    None
}

/// Bytes served by size class `idx`, or [`None`] if `idx` is out of range.
///
/// Uses [`slice::get`] rather than indexing so an out-of-range index is a
/// recoverable [`None`] instead of a panic (NCIP-029 forbids reachable panics
/// on the allocator hot path).
#[must_use]
pub fn size_class_bytes(idx: usize) -> Option<usize> {
    SIZE_CLASSES.get(idx).copied()
}

/// Slab + free-list global allocator (NCIP-Kernel-Alloc-029).
///
/// At this stage (WS1-08.2) the type owns the arena bounds, the bump cursor
/// that doubles as the slab source (§ S3.3), and the per-class intrusive
/// free-list heads (§ S3.2). The reclaiming `alloc`/`free` land in WS1-08.4/.5;
/// the one-shot `init` and the forensic accessors mirror [`BumpHeap`] so the
/// `kernel_entry` / `kernel-runner` call sites are source-compatible when the
/// `#[global_allocator]` is swapped in WS1-08.6.
pub struct SlabHeap {
    /// Lowest arena address; `UNINIT` until [`Self::init`].
    base: AtomicUsize,
    /// Bump cursor = slab source (§ S3.3). Advances only when a class's
    /// free-list is empty and a fresh block must be carved (WS1-08.4).
    next: AtomicUsize,
    /// One-past-the-last arena address; `UNINIT` until [`Self::init`].
    end: AtomicUsize,
    /// Per-size-class intrusive free-list heads (§ S3.2), `NULL_LINK` = empty.
    /// The `next` link of a free block is stored in the block's first word;
    /// push/pop land in WS1-08.3.
    free_lists: [AtomicUsize; NUM_SIZE_CLASSES],
    /// Head of the large-run free-list (§ S3.3), `NULL_LINK` = empty. A freed
    /// large run stores `[next_run_addr, run_size_bytes]` in its first two
    /// words; reuse is first-fit-with-split (WS1-08.5). Distinct from the small
    /// per-class lists because large runs are variable-size.
    large_free: AtomicUsize,
}

impl SlabHeap {
    /// Construct an uninitialised heap with every free-list empty.
    ///
    /// `const fn` so a `static` instance can be declared at compile time
    /// (required for the future `#[global_allocator]`). Not safe to allocate
    /// against until [`Self::init`] runs.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            base: AtomicUsize::new(UNINIT),
            next: AtomicUsize::new(UNINIT),
            end: AtomicUsize::new(UNINIT),
            free_lists: [const { AtomicUsize::new(NULL_LINK) }; NUM_SIZE_CLASSES],
            large_free: AtomicUsize::new(NULL_LINK),
        }
    }

    /// One-shot installation of the heap region.
    ///
    /// Identical contract to [`BumpHeap::init`]: `base..base + len` is the
    /// contiguous arena the allocator may carve slabs from. The cursor starts
    /// at `base`; subsequent slab carves (WS1-08.4) advance it toward `end`.
    ///
    /// # Safety
    ///
    /// The caller MUST guarantee that:
    /// - `base..base + len` is a single contiguous mapped region the kernel
    ///   exclusively owns for the remainder of the boot.
    /// - The region is at least [`MIN_HEAP_BYTES`] long.
    /// - `init` is called exactly once. A second invocation panics.
    ///
    /// # Panics
    ///
    /// Panics if the heap has already been initialised (the `base` CAS from
    /// `UNINIT` fails) or if `base + len` overflows `usize`.
    pub unsafe fn init(&self, base: *mut u8, len: usize) {
        let base_addr = base as usize;
        let Some(end_addr) = base_addr.checked_add(len) else {
            #[allow(
                clippy::panic,
                reason = "kernel invariant violation: heap region overflows usize"
            )]
            {
                panic!("SlabHeap::init: base + len overflows usize");
            }
        };
        if self
            .base
            .compare_exchange(UNINIT, base_addr, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
        {
            self.end.store(end_addr, Ordering::Release);
            self.next.store(base_addr, Ordering::Release);
        } else {
            #[allow(
                clippy::panic,
                reason = "kernel invariant violation: SlabHeap::init called twice"
            )]
            {
                panic!("SlabHeap::init called twice — kernel invariant violation");
            }
        }
    }

    /// Report whether the heap has been initialised.
    #[must_use]
    pub fn is_initialised(&self) -> bool {
        self.base.load(Ordering::Acquire) != UNINIT
    }

    /// Bytes carved from the arena by the slab source so far (forensics /
    /// telemetry). This is monotonic — it never decreases on `free` (reclaimed
    /// blocks return to the free-lists, the cursor does not retreat), so it is
    /// *not* the live working set; the soak counter for that lands with the
    /// the test VM soak test (WS1-08.9).
    #[must_use]
    pub fn used_bytes(&self) -> usize {
        let base = self.base.load(Ordering::Acquire);
        let next = self.next.load(Ordering::Acquire);
        next.saturating_sub(base)
    }

    /// Total arena size in bytes.
    #[must_use]
    pub fn total_bytes(&self) -> usize {
        let base = self.base.load(Ordering::Acquire);
        let end = self.end.load(Ordering::Acquire);
        end.saturating_sub(base)
    }

    /// Current free-list head address for size class `idx` (`NULL_LINK` when
    /// the class is empty, or for an out-of-range `idx`).
    ///
    /// After [`Self::new`] every class is empty. Exposed so host tests can
    /// assert free-list state once push/pop land in WS1-08.3.
    #[must_use]
    pub fn free_list_head(&self, idx: usize) -> usize {
        self.free_lists
            .get(idx)
            .map_or(NULL_LINK, |head| head.load(Ordering::Acquire))
    }

    /// Push a reclaimed block onto size class `idx`'s free-list (WS1-08.3,
    /// NCIP-029 § S3.2).
    ///
    /// The list is **intrusive**: the block's first word stores the link to
    /// the previous head, so no external metadata is needed. Insertion is at
    /// the head (LIFO — recently-freed blocks are handed back first, maximising
    /// cache reuse). The head update is a lock-free Treiber-stack push: write
    /// the observed head into the block, then `compare_exchange` the head to
    /// the block, retrying on contention. Push is inherently ABA-free (the
    /// block being inserted is private to this caller), so it is fully SMP-safe
    /// and safe from interrupt context (NCIP-029 § S2.5.2/§ S2.5.3 — lock-free).
    ///
    /// An out-of-range `idx` is a no-op (the large path does not use these
    /// per-class lists).
    ///
    /// # Safety
    ///
    /// The caller MUST guarantee that `block`:
    /// - points to a writable region of at least `size_of::<usize>()` bytes
    ///   that the caller exclusively owns (it is being freed),
    /// - is aligned to at least `align_of::<usize>()` (every size class is
    ///   ≥ 16 B and class-aligned, so this always holds for allocator-produced
    ///   blocks),
    /// - belongs to size class `idx` and is **not** already on any free-list
    ///   (a double-free would corrupt the list — caller UB per § S2.2.2).
    #[allow(
        clippy::cast_ptr_alignment,
        reason = "blocks are usize-aligned by the size-class contract (every \
                  class is ≥ 16 B and class-aligned) — see the # Safety section"
    )]
    pub unsafe fn push_free(&self, idx: usize, block: *mut u8) {
        let Some(head_cell) = self.free_lists.get(idx) else {
            return;
        };
        let block_addr = block as usize;
        let link_slot = block.cast::<usize>();
        let mut current = head_cell.load(Ordering::Acquire);
        loop {
            // SAFETY: `block` is a caller-owned, usize-aligned block of at least
            // `size_of::<usize>()` bytes (method contract); writing the link
            // into its first word is sound and races nothing — the block is not
            // yet published on the list until the CAS below succeeds.
            unsafe {
                link_slot.write(current);
            }
            match head_cell.compare_exchange_weak(
                current,
                block_addr,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => return,
                Err(actual) => current = actual,
            }
        }
    }

    /// Pop a block from size class `idx`'s free-list, or [`None`] if the class
    /// is empty / `idx` is out of range (WS1-08.3, NCIP-029 § S3.2).
    ///
    /// Returns the most-recently-pushed block (LIFO). The returned pointer's
    /// first word still holds the stale intrusive link; the caller (the
    /// WS1-08.4 `alloc` path) owns the whole block and may overwrite it.
    ///
    /// Correctness note: the pop is a Treiber-stack `compare_exchange` loop,
    /// correct for the v1.0 single-CPU allocation model (allocation runs on the
    /// BSP with interrupts masked — same execution model `BumpHeap` assumed,
    /// `NCIP-Kernel-012` § S2 constraint 5). Enabling concurrent allocation
    /// across APs requires ABA-hardening of this pop (a tagged/versioned head
    /// pointer or safe-linking), tracked for SMP enablement in NCIP-029
    /// § Security Considerations — the lock-free *shape* is in place so that
    /// step is local to this method.
    ///
    /// # Safety
    ///
    /// The free-list for `idx` MUST contain only valid, class-`idx` blocks
    /// inserted by [`Self::push_free`] (upheld by the allocator's own
    /// alloc/free discipline). A corrupted list (from a prior double-free /
    /// wrong-size free) yields an arbitrary pointer — caller UB per § S2.2.2.
    #[allow(
        clippy::cast_ptr_alignment,
        reason = "free-list blocks are usize-aligned by the size-class contract \
                  (every class is ≥ 16 B and class-aligned) — see # Safety"
    )]
    pub unsafe fn pop_free(&self, idx: usize) -> Option<*mut u8> {
        let head_cell = self.free_lists.get(idx)?;
        let mut current = head_cell.load(Ordering::Acquire);
        loop {
            if current == NULL_LINK {
                return None;
            }
            let link_slot = (current as *mut u8).cast::<usize>();
            // SAFETY: `current` is a non-null free-list head — i.e. a block
            // previously published by `push_free`, hence a usize-aligned,
            // owned-by-the-allocator block whose first word holds the next
            // link. Reading that word is sound.
            let next = unsafe { link_slot.read() };
            match head_cell.compare_exchange_weak(
                current,
                next,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => return Some(current as *mut u8),
                Err(actual) => current = actual,
            }
        }
    }

    /// Carve `size` bytes aligned to `align` from the bump cursor (the slab
    /// source, § S3.3), or [`None`] if the arena cannot satisfy it.
    ///
    /// This is the surviving core of `BumpHeap::alloc`: a lock-free
    /// `compare_exchange` advance of `next`, bounded by `end`. Unlike
    /// `BumpHeap` it is no longer the per-allocation path — it backs slab
    /// refills (small path) and whole runs (large path). Returns the aligned
    /// base address as a `usize`.
    fn carve(&self, size: usize, align: usize) -> Option<usize> {
        let end = self.end.load(Ordering::Acquire);
        if end == UNINIT {
            return None;
        }
        let mut current = self.next.load(Ordering::Acquire);
        loop {
            let aligned = align_up(current, align);
            let new_next = aligned.checked_add(size)?;
            if new_next > end {
                return None;
            }
            match self.next.compare_exchange_weak(
                current,
                new_next,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => return Some(aligned),
                Err(actual) => current = actual,
            }
        }
    }

    /// Refill size class `idx` from the slab source and return one block, or
    /// `null` on OOM (NCIP-029 § S3.3).
    ///
    /// Carves one slab worth of blocks (`PAGE_BYTES / class`, ≥ 1) in a single
    /// contiguous run, returns the first block, and threads the rest onto the
    /// class's free-list — so the *next* `class`-sized allocations are served
    /// from the free-list, not from fresh arena (invariant I3). If a full slab
    /// does not fit, it retries with a single block, so OOM is reported only
    /// when not even one block fits (§ S2.4.3 — no false OOM while the arena
    /// could still satisfy the request).
    #[allow(
        clippy::integer_division,
        reason = "`class` is a size class (≥ 16, never 0); blocks-per-slab is an \
                  intentional floor division"
    )]
    fn refill_class(&self, idx: usize) -> *mut u8 {
        let Some(class) = size_class_bytes(idx) else {
            return ptr::null_mut();
        };
        let want = {
            let n = PAGE_BYTES / class;
            if n == 0 { 1 } else { n }
        };
        // Try a full slab, then fall back to a single block (§ S2.4.3).
        for blocks in [want, 1] {
            if let Some(run) = self.carve(class * blocks, class) {
                // Thread blocks [1, blocks) onto the free-list; return block 0.
                let mut k = 1;
                while k < blocks {
                    let extra = run + k * class;
                    // SAFETY: `extra` lies in the just-carved run
                    // `[run, run + blocks*class)`, is `class`-aligned (hence
                    // usize-aligned), owned exclusively by this allocator, and
                    // not yet on any free-list — the `push_free` contract holds.
                    unsafe {
                        self.push_free(idx, extra as *mut u8);
                    }
                    k += 1;
                }
                return run as *mut u8;
            }
            if blocks == 1 {
                break;
            }
        }
        ptr::null_mut()
    }

    /// Allocate a block satisfying `layout`, or `null` on OOM (NCIP-029 § S2.1).
    ///
    /// Small path (`max(size, align) ≤ MAX_SMALL_BYTES`): serve the smallest
    /// fitting size class — pop the free-list first (reuse, I3), else refill
    /// from the slab source. Large path: a page-granular run aligned to one
    /// page; alignments above a page are deferred and rejected with `null`
    /// (§ S2.3.3). An uninitialised heap returns `null` (§ S2.1, routed to the
    /// panic handler downstream).
    ///
    /// This is the inherent allocation routine; WS1-08.6 wires it behind
    /// `GlobalAlloc::alloc`.
    ///
    /// # Safety
    ///
    /// Callers must treat the returned pointer per the `GlobalAlloc` contract:
    /// the block is valid for `layout.size()` bytes only, and must eventually
    /// be returned via [`Self::free`] (WS1-08.5) with the same `layout`.
    #[must_use]
    pub unsafe fn allocate(&self, layout: Layout) -> *mut u8 {
        if self.end.load(Ordering::Acquire) == UNINIT {
            return ptr::null_mut();
        }
        if let Some(idx) = size_class_index(layout.size(), layout.align()) {
            // Small path: free-list first (I3), else refill from the slab source.
            // SAFETY: `idx` is a valid class index and its free-list holds only
            // class-`idx` blocks from `push_free` (allocator invariant).
            if let Some(block) = unsafe { self.pop_free(idx) } {
                return block;
            }
            self.refill_class(idx)
        } else {
            // Large path (§ S3.3). Alignments above one page are deferred
            // (§ S2.3.3) — no current kernel heap site needs them.
            if layout.align() > PAGE_BYTES {
                return ptr::null_mut();
            }
            let Some(run_bytes) = page_round_up(layout.size()) else {
                return ptr::null_mut();
            };
            // Reuse a freed run first (first-fit + split, I3 / § S2.4.3), else
            // carve a fresh run from the slab source.
            let reused = self.take_large_run(run_bytes);
            if !reused.is_null() {
                return reused;
            }
            self.carve(run_bytes, PAGE_BYTES)
                .map_or(ptr::null_mut(), |addr| addr as *mut u8)
        }
    }

    /// Return a block to its free-list so it can be reused (NCIP-029 § S2.2).
    ///
    /// Small path: the size class is recovered from `layout` alone (same
    /// rounding as [`Self::allocate`], no per-block header), and the block is
    /// pushed back onto that class's free-list. Large path: the run length is
    /// recomputed from `layout` and the run is returned to the large-run
    /// free-list. `free(null, _)` is a no-op (§ S2.2.5).
    ///
    /// This is the inherent deallocation routine; WS1-08.6 wires it behind
    /// `GlobalAlloc::dealloc`.
    ///
    /// # Safety
    ///
    /// `ptr`/`layout` MUST be a pair previously returned by [`Self::allocate`]
    /// with the **same** `layout`, not yet freed (§ S2.2.1/§ S2.2.2). A
    /// double-free or wrong-`layout` free corrupts the target free-list — the
    /// allocator does not detect it (caller UB).
    pub unsafe fn free(&self, ptr: *mut u8, layout: Layout) {
        if ptr.is_null() {
            return;
        }
        if let Some(idx) = size_class_index(layout.size(), layout.align()) {
            // SAFETY: by the method contract `ptr` is a live class-`idx` block
            // from `allocate`; `push_free`'s own contract is thereby upheld.
            unsafe {
                self.push_free(idx, ptr);
            }
        } else if layout.align() <= PAGE_BYTES {
            // Large path: a run that `allocate` produced (align > page was
            // rejected there, so a well-formed free never hits the else branch).
            if let Some(run_bytes) = page_round_up(layout.size()) {
                self.push_large_run(ptr as usize, run_bytes);
            }
        }
    }

    /// Push a freed large run of `size` bytes onto the large-run free-list
    /// (NCIP-029 § S3.3). Lock-free Treiber push: the run's first two words are
    /// set to `[previous_head, size]`, then the head CAS-swings to `addr`.
    ///
    /// `addr` is a `PAGE_BYTES`-aligned run of at least [`LARGE_RUN_MIN`] bytes
    /// (so its 2-word header always fits), exclusively owned and not already on
    /// the list — upheld by the allocator's own discipline.
    fn push_large_run(&self, addr: usize, size: usize) {
        let slot = addr as *mut usize;
        let mut head = self.large_free.load(Ordering::Acquire);
        loop {
            // SAFETY: `addr` is a page-aligned (hence usize-aligned) run of
            // ≥ 16 bytes that the allocator owns; writing its first two words
            // (next link + size) is sound and races nothing until the CAS
            // publishes the run below.
            unsafe {
                slot.write(head);
                slot.add(1).write(size);
            }
            match self.large_free.compare_exchange_weak(
                head,
                addr,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => return,
                Err(actual) => head = actual,
            }
        }
    }

    /// First-fit removal of a free large run of at least `need` bytes, split to
    /// exactly `need` (NCIP-029 § S3.3); returns the run base, or [`None`] if no
    /// free run is large enough.
    ///
    /// The remainder `size - need` (a whole number of pages) is recycled so no
    /// reclaimable memory is stranded (§ S2.4.3): a remainder ≥ [`LARGE_RUN_MIN`]
    /// goes back on the large-run list; an exactly-one-page remainder becomes a
    /// small size-class-8 block; a zero remainder (exact fit) leaves nothing.
    ///
    /// Correctness model: the traversal and unlink are correct under the v1.0
    /// single-CPU / interrupt-masked allocation model (the same model
    /// documented for [`Self::pop_free`]); SMP enablement needs the same
    /// lock-free / locking hardening tracked in NCIP-029 § Security
    /// Considerations.
    fn take_large_run(&self, need: usize) -> *mut u8 {
        let mut cur = self.large_free.load(Ordering::Acquire);
        let mut prev_slot: *mut usize = ptr::null_mut(); // null ⇒ predecessor is the head
        while cur != NULL_LINK {
            let cur_slot = cur as *mut usize;
            // SAFETY: `cur` is a free run published by `push_large_run`: a
            // page-aligned, allocator-owned region whose first two words hold
            // `[next, size]`. Reading them is sound.
            let (cur_next, cur_size) = unsafe { (cur_slot.read(), cur_slot.add(1).read()) };
            if cur_size >= need {
                // Unlink `cur` (predecessor's next ← cur_next).
                if prev_slot.is_null() {
                    self.large_free.store(cur_next, Ordering::Release);
                } else {
                    // SAFETY: `prev_slot` points at the predecessor run's first
                    // word (its next link), a valid allocator-owned usize cell.
                    unsafe {
                        prev_slot.write(cur_next);
                    }
                }
                let remainder = cur_size - need;
                if remainder >= LARGE_RUN_MIN {
                    self.push_large_run(cur + need, remainder);
                } else if remainder == PAGE_BYTES {
                    // One leftover page: a valid class-8 (4096 B) small block.
                    // SAFETY: `cur + need` is page-aligned and owns exactly
                    // `PAGE_BYTES` bytes — the class-8 `push_free` contract.
                    unsafe {
                        self.push_free(8, (cur + need) as *mut u8);
                    }
                }
                return cur as *mut u8;
            }
            prev_slot = cur_slot;
            cur = cur_next;
        }
        ptr::null_mut()
    }
}

impl Default for SlabHeap {
    fn default() -> Self {
        Self::new()
    }
}

// SAFETY: `SlabHeap` upholds the `GlobalAlloc` contract per NCIP-029 § S2:
//  - `alloc` returns either a non-null, `layout.align()`-aligned pointer to
//    ≥ `layout.size()` writable in-arena bytes, or null on OOM (§ S2.1/§ S2.4).
//  - `dealloc` returns the block to the correct free-list so it is reused
//    (§ S2.2); it is a no-op on null.
//  - All pointer arithmetic is bounded by the arena (invariant I1) and the
//    free-list / slab cursors transition only between valid states (I2/I3/I6)
//    via the `compare_exchange` discipline in the inherent routines.
unsafe impl GlobalAlloc for SlabHeap {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        // SAFETY: forwarded to the inherent allocation routine; the
        // `GlobalAlloc` caller's obligation (a valid `Layout`) is exactly what
        // `allocate` requires.
        unsafe { self.allocate(layout) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        // SAFETY: by the `GlobalAlloc` contract `ptr`/`layout` come from a prior
        // `alloc` with the same `layout`, which is exactly `free`'s precondition.
        unsafe {
            self.free(ptr, layout);
        }
    }
}
