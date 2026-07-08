//! Host-mode integration tests for the K4 heap-region selector
//! ([`nexacore_kernel::bare_metal::heap::pick_region`]).
//!
//! Specified by `NCIP-Kernel-005` § S10. The tests fabricate synthetic
//! `[MemoryRegion]` slices and assert the selection algorithm's
//! invariants: largest-region wins, lowest-start tie-break, and the
//! "no Usable region of ≥ `MIN_HEAP_BYTES`" panic path.
//!
//! Ported from bootloader 0.9 types to `bootloader_api` 0.11 types
//! (`MemoryRegion { start, end, kind }` instead of
//! `MemoryRegion { range: FrameRange, region_type }`).

#![cfg(feature = "bare-metal")]
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::missing_docs_in_private_items,
    clippy::uninlined_format_args,
    clippy::doc_markdown
)]

use bootloader_api::info::{MemoryRegion, MemoryRegionKind};
use nexacore_kernel::bare_metal::heap::{MIN_HEAP_BYTES, pick_region};

/// Build a `MemoryRegion` from raw `(start, len, kind)`.
fn region(start: u64, len: u64, kind: MemoryRegionKind) -> MemoryRegion {
    MemoryRegion {
        start,
        end: start + len,
        kind,
    }
}

#[test]
fn picks_largest_usable_region() {
    let regions = [
        region(0x0000_0000, 0x0010_0000, MemoryRegionKind::Bootloader), // 1 MiB, reserved
        region(0x0010_0000, 0x0040_0000, MemoryRegionKind::Usable),     // 4 MiB
        region(0x0050_0000, 0x0100_0000, MemoryRegionKind::Usable),     // 16 MiB <- winner
        region(0x0150_0000, 0x0020_0000, MemoryRegionKind::Usable),     // 2 MiB (< MIN)
    ];
    let (ptr, len) = pick_region(&regions);
    assert_eq!(ptr as u64, 0x0050_0000);
    assert_eq!(len, 0x0100_0000);
}

#[test]
fn tie_breaks_on_lowest_start_address() {
    // Two Usable regions of identical (>= MIN) length: the lower start
    // wins for determinism across boots on identical hardware.
    let regions = [
        region(0x0200_0000, 0x0040_0000, MemoryRegionKind::Usable), // 4 MiB at 32 MiB
        region(0x0100_0000, 0x0040_0000, MemoryRegionKind::Usable), // 4 MiB at 16 MiB <- winner
    ];
    let (ptr, len) = pick_region(&regions);
    assert_eq!(ptr as u64, 0x0100_0000);
    assert_eq!(len, 0x0040_0000);
}

#[test]
fn skips_regions_below_min_heap_bytes() {
    let regions = [
        region(
            0x0010_0000,
            MIN_HEAP_BYTES as u64 - 1,
            MemoryRegionKind::Usable,
        ),
        region(0x0100_0000, MIN_HEAP_BYTES as u64, MemoryRegionKind::Usable), // = MIN <- winner
    ];
    let (_, len) = pick_region(&regions);
    assert_eq!(len, MIN_HEAP_BYTES);
}

#[test]
fn skips_non_usable_regions() {
    let regions = [
        region(0x0010_0000, 0x0100_0000, MemoryRegionKind::Bootloader),
        region(0x0200_0000, 0x0100_0000, MemoryRegionKind::UnknownUefi(0)),
        region(0x0300_0000, 0x0080_0000, MemoryRegionKind::Usable), // 8 MiB <- only Usable
    ];
    let (ptr, _) = pick_region(&regions);
    assert_eq!(ptr as u64, 0x0300_0000);
}

#[test]
#[should_panic(expected = "no usable heap region")]
fn panics_when_no_region_meets_minimum() {
    let regions = [
        region(
            0x0010_0000,
            MIN_HEAP_BYTES as u64 - 1,
            MemoryRegionKind::Usable,
        ),
        region(0x0200_0000, 0x0010_0000, MemoryRegionKind::Bootloader),
    ];
    let _ = pick_region(&regions);
}

#[test]
#[should_panic(expected = "no usable heap region")]
fn panics_on_empty_regions_slice() {
    let regions: [MemoryRegion; 0] = [];
    let _ = pick_region(&regions);
}

#[test]
fn deterministic_across_repeat_calls() {
    let regions = [
        region(0x0010_0000, MIN_HEAP_BYTES as u64, MemoryRegionKind::Usable),
        region(0x0100_0000, 0x0080_0000, MemoryRegionKind::Usable),
        region(0x0200_0000, 0x0080_0000, MemoryRegionKind::Usable),
    ];
    let a = pick_region(&regions);
    let b = pick_region(&regions);
    assert_eq!(a.0 as u64, b.0 as u64);
    assert_eq!(a.1, b.1);
}
