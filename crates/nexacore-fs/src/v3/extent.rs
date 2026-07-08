//! Extent format and the allocation map with reflink refcounts (WS3-01.4).
//!
//! A file's data is described by [`Extent`]s — `(logical_block, physical_block,
//! len_blocks)` runs. The first four live inline in the [`super::inode::InodeV3`];
//! larger files spill into an extent-tree block. [`AllocMap`] tracks a refcount
//! per physical block so a reflink/snapshot can share blocks (refcount > 1) and
//! the data path copies-on-write only when a shared block is modified.

#![allow(clippy::cast_possible_truncation)]

use alloc::{vec, vec::Vec};

use super::V3Error;

/// Encoded size of one [`Extent`].
pub const EXTENT_LEN: usize = 24;
/// Number of extents stored inline in an inode.
pub const INLINE_EXTENTS: usize = 4;

/// A contiguous run mapping `len_blocks` logical blocks of a file to physical
/// blocks starting at `physical_block`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Extent {
    /// First logical (file-relative) block this run covers.
    pub logical_block: u64,
    /// First physical (volume) block of the run.
    pub physical_block: u64,
    /// Run length in blocks (`0` = unused extent slot).
    pub len_blocks: u32,
}

impl Extent {
    /// `true` for an empty (unused) extent slot.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.len_blocks == 0
    }

    /// `true` if `logical` falls inside this run.
    #[must_use]
    pub const fn contains(&self, logical: u64) -> bool {
        !self.is_empty()
            && logical >= self.logical_block
            && logical < self.logical_block + self.len_blocks as u64
    }

    /// Map a logical block within this run to its physical block.
    #[must_use]
    pub const fn map(&self, logical: u64) -> Option<u64> {
        if self.contains(logical) {
            Some(self.physical_block + (logical - self.logical_block))
        } else {
            None
        }
    }

    /// Encode to [`EXTENT_LEN`] bytes.
    #[must_use]
    pub fn encode(&self) -> [u8; EXTENT_LEN] {
        let mut b = [0u8; EXTENT_LEN];
        b[0..8].copy_from_slice(&self.logical_block.to_le_bytes());
        b[8..16].copy_from_slice(&self.physical_block.to_le_bytes());
        b[16..20].copy_from_slice(&self.len_blocks.to_le_bytes());
        // bytes 20..24 reserved.
        b
    }

    /// Decode from a byte slice (`None` if shorter than [`EXTENT_LEN`]).
    #[must_use]
    pub fn decode(buf: &[u8]) -> Option<Self> {
        let logical_block = u64::from_le_bytes(buf.get(0..8)?.try_into().ok()?);
        let physical_block = u64::from_le_bytes(buf.get(8..16)?.try_into().ok()?);
        let len_blocks = u32::from_le_bytes(buf.get(16..20)?.try_into().ok()?);
        Some(Self {
            logical_block,
            physical_block,
            len_blocks,
        })
    }
}

/// Resolve `logical` to a physical block across a list of extents.
#[must_use]
pub fn map_logical(extents: &[Extent], logical: u64) -> Option<u64> {
    extents.iter().find_map(|e| e.map(logical))
}

/// Per-physical-block refcount map enabling reflink / CoW snapshots.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AllocMap {
    refcounts: Vec<u32>,
    reserved: u64,
}

impl AllocMap {
    /// New map over `total_blocks` with the first `reserved` blocks (superblocks,
    /// the map itself, …) pinned as allocated.
    #[must_use]
    pub fn new(total_blocks: u64, reserved: u64) -> Self {
        let mut refcounts = vec![0u32; total_blocks as usize];
        for r in refcounts.iter_mut().take(reserved as usize) {
            *r = 1;
        }
        Self {
            refcounts,
            reserved,
        }
    }

    /// Total blocks tracked.
    #[must_use]
    pub fn len(&self) -> usize {
        self.refcounts.len()
    }

    /// `true` if the map tracks no blocks.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.refcounts.is_empty()
    }

    /// Refcount of physical block `idx` (`0` if out of range).
    #[must_use]
    pub fn refcount(&self, idx: u64) -> u32 {
        self.refcounts.get(idx as usize).copied().unwrap_or(0)
    }

    /// `true` if the block is shared (refcount > 1) and so must be copied on
    /// write.
    #[must_use]
    pub fn is_shared(&self, idx: u64) -> bool {
        self.refcount(idx) > 1
    }

    /// Allocate a free block (refcount 0 → 1), skipping reserved blocks.
    pub fn alloc(&mut self) -> Option<u64> {
        let start = self.reserved as usize;
        let idx = self
            .refcounts
            .iter()
            .enumerate()
            .skip(start)
            .find_map(|(i, &rc)| (rc == 0).then_some(i))?;
        if let Some(slot) = self.refcounts.get_mut(idx) {
            *slot = 1;
        }
        Some(idx as u64)
    }

    /// Allocate a contiguous run of `count` free blocks (first-fit), returning
    /// the starting physical block. All blocks in the run go refcount 0 → 1.
    /// Reserved blocks are never part of a run. `count == 0` allocates nothing
    /// and returns `None`.
    ///
    /// Multi-block objects (extent-tree nodes, inode-tree nodes, the alloc map
    /// and snapshot table themselves) allocate a run so they occupy contiguous
    /// storage (WS3-01.3, NCIP-027 §S2).
    pub fn alloc_run(&mut self, count: u64) -> Option<u64> {
        if count == 0 {
            return None;
        }
        let total = self.refcounts.len();
        let need = count as usize;
        let mut start = self.reserved as usize;
        while start.checked_add(need)? <= total {
            // A run is placeable at `start` iff every block in it is free.
            let free_run = self
                .refcounts
                .get(start..start + need)
                .is_some_and(|window| window.iter().all(|&rc| rc == 0));
            if free_run {
                for slot in self.refcounts.iter_mut().skip(start).take(need) {
                    *slot = 1;
                }
                return Some(start as u64);
            }
            // Skip past the first occupied block in the window to the next
            // candidate start (linear scan, first-fit).
            let occupied_at = self
                .refcounts
                .iter()
                .enumerate()
                .skip(start)
                .take(need)
                .find_map(|(i, &rc)| (rc != 0).then_some(i));
            start = occupied_at.map_or(start + 1, |i| i + 1);
        }
        None
    }

    /// Release a contiguous run of `count` blocks starting at `start`,
    /// decrementing each block's refcount (freed when it reaches `0`).
    ///
    /// # Errors
    /// [`V3Error::BlockOutOfRange`] if any block in the run is not tracked.
    pub fn free_run(&mut self, start: u64, count: u64) -> Result<(), V3Error> {
        for offset in 0..count {
            let idx = start.checked_add(offset).ok_or(V3Error::BlockOutOfRange)?;
            self.decref(idx)?;
        }
        Ok(())
    }

    /// Increment a block's refcount (reflink / snapshot share).
    ///
    /// # Errors
    /// [`V3Error::BlockOutOfRange`] if `idx` is not tracked.
    pub fn incref(&mut self, idx: u64) -> Result<(), V3Error> {
        let slot = self
            .refcounts
            .get_mut(idx as usize)
            .ok_or(V3Error::BlockOutOfRange)?;
        *slot = slot.saturating_add(1);
        Ok(())
    }

    /// Decrement a block's refcount; returns the new count (a count of `0` means
    /// the block is now free).
    ///
    /// # Errors
    /// [`V3Error::BlockOutOfRange`] if `idx` is not tracked.
    pub fn decref(&mut self, idx: u64) -> Result<u32, V3Error> {
        let slot = self
            .refcounts
            .get_mut(idx as usize)
            .ok_or(V3Error::BlockOutOfRange)?;
        *slot = slot.saturating_sub(1);
        Ok(*slot)
    }

    /// Number of currently-free blocks.
    #[must_use]
    pub fn free_count(&self) -> u64 {
        self.refcounts.iter().filter(|&&rc| rc == 0).count() as u64
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extent_round_trips_and_maps() {
        let e = Extent {
            logical_block: 10,
            physical_block: 200,
            len_blocks: 4,
        };
        let back = Extent::decode(&e.encode()).unwrap();
        assert_eq!(back, e);
        // logical 10..14 → physical 200..204.
        assert_eq!(e.map(10), Some(200));
        assert_eq!(e.map(13), Some(203));
        assert_eq!(e.map(14), None);
        assert_eq!(e.map(9), None);
    }

    #[test]
    fn map_logical_across_extents() {
        let extents = [
            Extent {
                logical_block: 0,
                physical_block: 100,
                len_blocks: 2,
            },
            Extent {
                logical_block: 2,
                physical_block: 500,
                len_blocks: 3,
            },
        ];
        assert_eq!(map_logical(&extents, 1), Some(101));
        assert_eq!(map_logical(&extents, 2), Some(500));
        assert_eq!(map_logical(&extents, 4), Some(502));
        assert_eq!(map_logical(&extents, 5), None);
    }

    #[test]
    fn alloc_skips_reserved_and_tracks_free() {
        let mut m = AllocMap::new(8, 3); // blocks 0,1,2 reserved
        assert_eq!(m.len(), 8);
        assert_eq!(m.free_count(), 5);
        assert_eq!(m.alloc(), Some(3));
        assert_eq!(m.alloc(), Some(4));
        assert_eq!(m.free_count(), 3);
        assert_eq!(m.refcount(0), 1, "reserved stays allocated");
    }

    #[test]
    fn reflink_share_and_cow() {
        let mut m = AllocMap::new(8, 2);
        let b = m.alloc().unwrap();
        assert!(!m.is_shared(b));
        // Reflink: a second reference shares the block.
        m.incref(b).unwrap();
        assert!(m.is_shared(b), "shared block must CoW on write");
        // Dropping one reference: still allocated, no longer shared.
        assert_eq!(m.decref(b).unwrap(), 1);
        assert!(!m.is_shared(b));
        // Dropping the last reference frees it.
        assert_eq!(m.decref(b).unwrap(), 0);
        assert_eq!(m.refcount(b), 0);
    }

    #[test]
    fn incref_out_of_range_errors() {
        let mut m = AllocMap::new(4, 0);
        assert_eq!(m.incref(99), Err(V3Error::BlockOutOfRange));
    }

    #[test]
    fn alloc_run_finds_contiguous_free_span() {
        let mut m = AllocMap::new(16, 2); // 0,1 reserved
        // A 4-block run starts at the first free block past the reserved head.
        assert_eq!(m.alloc_run(4), Some(2));
        for b in 2..6 {
            assert_eq!(m.refcount(b), 1);
        }
        assert_eq!(m.free_count(), 10);
        // The next run is placed after the first.
        assert_eq!(m.alloc_run(3), Some(6));
        // Zero-length run allocates nothing.
        assert_eq!(m.alloc_run(0), None);
    }

    #[test]
    fn alloc_run_skips_occupied_windows() {
        let mut m = AllocMap::new(12, 0);
        // Occupy block 2 so the first 3-run cannot start at 0 (spans the hole);
        // first-fit lands at block 3.
        m.incref(2).unwrap();
        assert_eq!(m.alloc_run(3), Some(3));
        for b in 3..6 {
            assert_eq!(m.refcount(b), 1);
        }
    }

    #[test]
    fn alloc_run_none_when_no_span_fits() {
        let mut m = AllocMap::new(6, 4); // only blocks 4,5 free
        assert_eq!(m.alloc_run(3), None);
        assert_eq!(m.alloc_run(2), Some(4));
    }

    #[test]
    fn free_run_releases_the_whole_run() {
        let mut m = AllocMap::new(16, 2);
        let start = m.alloc_run(4).unwrap();
        assert_eq!(start, 2);
        m.free_run(start, 4).unwrap();
        for b in 2..6 {
            assert_eq!(m.refcount(b), 0);
        }
        // The freed span can be re-allocated.
        assert_eq!(m.alloc_run(4), Some(2));
    }

    #[test]
    fn free_run_out_of_range_errors() {
        let mut m = AllocMap::new(4, 0);
        assert_eq!(m.free_run(2, 99), Err(V3Error::BlockOutOfRange));
    }
}
