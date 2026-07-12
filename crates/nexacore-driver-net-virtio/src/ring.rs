//! Split virtqueue descriptor ring — operational logic for the M1 virtio-net
//! driver.
//!
//! `NCIP-Driver-Net-015` § S4.1 step 6 allocates two split virtqueues (RX = 0,
//! TX = 1) following the virtio 1.0 § 2.4 layout. This module provides the
//! pure-Rust, `no_std + alloc`, zero-`unsafe` bookkeeping layer: descriptor
//! allocation, free-list management, avail-ring production, and used-ring
//! consumption.
//!
//! ## What lives here vs what lives elsewhere
//!
//! - **Constants / size formulae** (`VIRTQ_DESC_BYTES`, `descriptor_table_bytes`, …)
//!   live in [`crate::virtqueue`] where they were introduced in the P6.7.8.2
//!   scaffold.
//! - **Operational logic** (allocate descriptors, push avail entries, pop used
//!   completions) lives here so that the data layer and the algorithm layer are
//!   separately auditable.
//! - **MMIO / DMA / IOMMU wiring** lives in `nexacore-driver-net-virtio-image`
//!   (the bootable ELF sibling). This crate stays host-testable.
//!
//! ## Free-list design
//!
//! Descriptors are managed via a singly-linked free list embedded inside the
//! descriptor table itself: `desc.next` of a free descriptor points to the
//! next free index, and `free_head` anchors the list. This matches the
//! standard virtio driver implementation pattern and avoids a separate
//! allocation for the free-list nodes.

extern crate alloc;

use alloc::{vec, vec::Vec};

// ---------------------------------------------------------------------------
// Descriptor flags
// ---------------------------------------------------------------------------

/// `VIRTQ_DESC_F_NEXT` (bit 0): the buffer continues via the `next` field.
///
/// Source: virtio 1.0 § 2.4.5.3.
pub const VIRTQ_DESC_F_NEXT: u16 = 0x0001;

/// `VIRTQ_DESC_F_WRITE` (bit 1): the buffer is device-writable (used for RX).
///
/// Source: virtio 1.0 § 2.4.5.3. TX buffers leave this clear; RX buffers set
/// it so the device knows it may write into them.
pub const VIRTQ_DESC_F_WRITE: u16 = 0x0002;

// ---------------------------------------------------------------------------
// Core layout types
// ---------------------------------------------------------------------------

/// One entry in the virtqueue descriptor table — `virtq_desc` from virtio 1.0
/// § 2.4.5.
///
/// The wire layout is `{u64 addr, u32 len, u16 flags, u16 next}` = 16 bytes,
/// matching [`crate::virtqueue::VIRTQ_DESC_BYTES`].
///
/// In this library crate `addr` stores a **logical** buffer address (e.g. a
/// DMA-mapped IOVA in the bootable image, or a test-injected synthetic
/// address in unit tests). The MMIO write of the actual physical/IOVA address
/// happens in `nexacore-driver-net-virtio-image`.
#[derive(Debug, Clone, Copy, Default)]
#[repr(C)]
pub struct VirtqDesc {
    /// Physical / IOVA address of the buffer.
    pub addr: u64,
    /// Length of the buffer in bytes.
    pub len: u32,
    /// Descriptor flags (see `VIRTQ_DESC_F_*` constants).
    pub flags: u16,
    /// Index of the next descriptor in the chain, if `VIRTQ_DESC_F_NEXT` is
    /// set. Otherwise this field is ignored by the device.
    pub next: u16,
}

/// Available ring — virtio 1.0 § 2.4.6.
///
/// The driver adds descriptor-chain head indices to `ring` and increments
/// `idx` to notify the device. `flags` is currently unused by this driver
/// (no `VIRTQ_AVAIL_F_NO_INTERRUPT` support in M1).
#[derive(Debug, Clone)]
pub struct VirtqAvail {
    /// Available-ring flags. Reserved as `0` for M1.
    pub flags: u16,
    /// Producer index. Wraps at `u16::MAX + 1`. The device reads entries at
    /// `ring[idx % queue_size]`.
    pub idx: u16,
    /// The descriptor-chain head-index slots.
    pub ring: Vec<u16>,
}

/// One element of the used ring — `virtq_used_elem` from virtio 1.0 § 2.4.8.
///
/// The device writes here after consuming a descriptor chain.
#[derive(Debug, Clone, Copy, Default)]
pub struct VirtqUsedElem {
    /// Index of the start of the used descriptor chain.
    pub id: u32,
    /// Total bytes written into the chain (meaningful for device-writable / RX
    /// descriptors; zero or unspecified for TX).
    pub len: u32,
}

// ---------------------------------------------------------------------------
// Split virtqueue manager
// ---------------------------------------------------------------------------

/// Software-side bookkeeping for a single split virtqueue.
///
/// This struct models one virtio split virtqueue per virtio 1.0 § 2.4. It
/// manages:
///
/// - A descriptor table (`desc_table`) of `queue_size` entries.
/// - An available ring (`avail`) that the driver populates.
/// - A simulated used ring (`used_elems` + `used_flags` / `used_idx`) that
///   the device populates in hardware; in unit tests the test harness writes
///   here to simulate device completions.
/// - A free-list (`free_head` / `num_free`) embedded in `desc_table.next`.
///
/// ## `no_std` + alloc, zero unsafe
///
/// Backed by `Vec` so descriptor tables and rings live in heap memory. The
/// actual MMIO/DMA wiring (IOVA, physical addresses, memory barriers) happens
/// in the bootable image sibling. This crate is purely logical and testable on
/// a standard host.
///
/// # Example
///
/// ```
/// use nexacore_driver_net_virtio::ring::SplitVirtqueue;
///
/// let mut vq = SplitVirtqueue::new(4);
/// assert_eq!(vq.num_free(), 4);
/// assert!(!vq.is_full());
///
/// let idx = vq.add_buffer(0x1000, 64, false);
/// assert!(idx.is_some());
/// assert_eq!(vq.num_free(), 3);
/// ```
#[derive(Debug, Clone)]
pub struct SplitVirtqueue {
    /// Descriptor table — `queue_size` entries.
    desc_table: Vec<VirtqDesc>,
    /// Available ring.
    avail: VirtqAvail,
    /// Simulated used ring elements (written by device / test harness).
    used_elems: Vec<VirtqUsedElem>,
    /// Used-ring flags (device-written; `0` means interrupts enabled).
    ///
    /// Not read by the M1 driver (interrupt suppression not implemented),
    /// but kept to mirror the virtio 1.0 § 2.4.8 used-ring layout.
    #[allow(dead_code)]
    used_flags: u16,
    /// Used-ring producer index (device-written; driver reads this to detect
    /// completions).
    used_idx: u16,
    /// Number of descriptors in the queue.
    queue_size: u16,
    /// Head of the free-list (index of the first free descriptor).
    free_head: u16,
    /// Number of descriptors currently on the free list.
    num_free: u16,
    /// Last value of `used_idx` seen by the driver (used to detect new
    /// completions on `pop_used`).
    last_used_idx: u16,
}

impl SplitVirtqueue {
    /// Construct a new split virtqueue with `queue_size` descriptors.
    ///
    /// `queue_size` SHOULD be a power of two in `1..=4096` (validated by
    /// [`crate::virtqueue::is_valid_queue_depth`]). If an odd value is passed
    /// the queue still initialises correctly — the caller is responsible for
    /// enforcing the virtio constraint before programming the hardware.
    ///
    /// All descriptors start on the free list; the avail and used rings are
    /// empty.
    ///
    /// # Panics
    ///
    /// Panics if `queue_size` is `0` (a zero-length descriptor table is
    /// nonsensical and cannot be represented as a `u16` free-list).
    ///
    /// # Example
    ///
    /// ```
    /// use nexacore_driver_net_virtio::ring::SplitVirtqueue;
    ///
    /// let vq = SplitVirtqueue::new(256);
    /// assert_eq!(vq.num_free(), 256);
    /// assert_eq!(vq.avail_idx(), 0);
    /// assert!(vq.is_full() == false);
    /// ```
    #[must_use]
    pub fn new(queue_size: u16) -> Self {
        assert!(queue_size > 0, "queue_size must be > 0");

        let size = queue_size as usize;

        // Initialise the descriptor table with a linear free list:
        //   desc[i].next = i + 1   for 0 ≤ i < queue_size - 1
        //   desc[queue_size - 1].next = 0  (sentinel — never dereferenced
        //                                   while free_head tracks num_free)
        let desc_table: Vec<VirtqDesc> = (0..size)
            .map(|i| VirtqDesc {
                addr: 0,
                len: 0,
                flags: 0,
                // Point to the next descriptor (wraps at the end; the last
                // entry's `next` is never read because `num_free` prevents
                // over-allocation).
                // `size ≤ MAX_QUEUE_DEPTH (4096) ≤ u16::MAX`, so the cast
                // from usize to u16 cannot truncate.
                #[allow(clippy::cast_possible_truncation)]
                next: ((i + 1) % size) as u16,
            })
            .collect();

        let avail = VirtqAvail {
            flags: 0,
            idx: 0,
            ring: vec![0u16; size],
        };

        let used_elems = vec![VirtqUsedElem::default(); size];

        Self {
            desc_table,
            avail,
            used_elems,
            used_flags: 0,
            used_idx: 0,
            queue_size,
            free_head: 0,
            num_free: queue_size,
            last_used_idx: 0,
        }
    }

    /// Add a single-descriptor buffer to the queue and push it onto the
    /// available ring.
    ///
    /// Returns the descriptor index on success, or `None` if the queue is
    /// full (all `queue_size` descriptors are already in flight).
    ///
    /// `buf_addr` is the physical / IOVA address of the buffer (set by the
    /// caller; in unit tests this can be any synthetic value). `len` is the
    /// buffer length in bytes. `writable` indicates whether the buffer is
    /// device-writable (set for RX, clear for TX) per virtio 1.0 § 2.4.5.3.
    ///
    /// # Example
    ///
    /// ```
    /// use nexacore_driver_net_virtio::ring::SplitVirtqueue;
    ///
    /// let mut vq = SplitVirtqueue::new(4);
    /// let idx = vq.add_buffer(0x4000, 128, true);
    /// assert_eq!(idx, Some(0)); // first free descriptor is index 0
    /// assert_eq!(vq.num_free(), 3);
    /// assert_eq!(vq.avail_idx(), 1); // avail ring advanced
    /// ```
    pub fn add_buffer(&mut self, buf_addr: u64, len: u32, writable: bool) -> Option<u16> {
        if self.num_free == 0 {
            return None;
        }

        let idx = self.free_head;

        // SAFETY OF INDEXING: `free_head` is always a valid descriptor index
        // (< queue_size) by the free-list construction invariant in `new` and
        // the push-front in `pop_used`.  The modulo in `avail_slot` likewise
        // bounds the ring access to [0, queue_size).
        #[allow(clippy::indexing_slicing)]
        // Advance the free-list head to the next free descriptor before we
        // overwrite `desc.next` with the buffer-chain terminator.
        let next_free = self.desc_table[idx as usize].next;

        // Program the descriptor. No NEXT chain for single-descriptor buffers.
        let flags: u16 = if writable { VIRTQ_DESC_F_WRITE } else { 0 };
        #[allow(clippy::indexing_slicing)]
        {
            self.desc_table[idx as usize] = VirtqDesc {
                addr: buf_addr,
                len,
                flags,
                next: 0, // no chain
            };
        }

        // Publish to the available ring.
        let avail_slot = (self.avail.idx as usize) % (self.queue_size as usize);
        #[allow(clippy::indexing_slicing)]
        {
            self.avail.ring[avail_slot] = idx;
        }
        self.avail.idx = self.avail.idx.wrapping_add(1);

        // Update free-list bookkeeping.
        self.free_head = next_free;
        self.num_free -= 1;

        Some(idx)
    }

    /// Consume one completion from the used ring, if available.
    ///
    /// Returns `(desc_index, bytes_written)` where `desc_index` is the
    /// descriptor chain head returned by the device and `bytes_written` is the
    /// number of bytes the device wrote into the buffer (meaningful for RX;
    /// usually `0` or unspecified for TX).
    ///
    /// The descriptor is returned to the free list automatically.
    ///
    /// Returns `None` when the used ring has no new completions
    /// (`used_idx == last_used_idx`).
    ///
    /// # Example
    ///
    /// ```
    /// use nexacore_driver_net_virtio::ring::{SplitVirtqueue, VirtqUsedElem};
    ///
    /// let mut vq = SplitVirtqueue::new(4);
    /// let idx = vq.add_buffer(0x8000, 256, true).unwrap();
    ///
    /// // Simulate the device completing the buffer.
    /// vq.simulate_device_completion(idx, 100);
    ///
    /// let (desc_idx, written) = vq.pop_used().unwrap();
    /// assert_eq!(desc_idx, idx);
    /// assert_eq!(written, 100);
    /// // Descriptor is back on the free list.
    /// assert_eq!(vq.num_free(), 4);
    /// ```
    pub fn pop_used(&mut self) -> Option<(u16, u32)> {
        if self.last_used_idx == self.used_idx {
            return None;
        }

        // SAFETY OF INDEXING: `slot` is bounded by `% queue_size` (< len of
        // `used_elems`).  `desc_idx` comes from a used-ring element written by
        // `simulate_device_completion` (tests) or the device (production), both
        // of which are constrained to [0, queue_size) by the same invariant.
        let slot = (self.last_used_idx as usize) % (self.queue_size as usize);
        #[allow(clippy::indexing_slicing)]
        let elem = self.used_elems[slot];
        self.last_used_idx = self.last_used_idx.wrapping_add(1);

        // Return the descriptor to the free list (push-front).
        // `elem.id` was written by `simulate_device_completion` (or the
        // device) as `u32::from(desc_idx: u16)`, so it always fits in u16.
        #[allow(clippy::cast_possible_truncation)]
        let desc_idx = elem.id as u16;
        #[allow(clippy::indexing_slicing)]
        {
            self.desc_table[desc_idx as usize].next = self.free_head;
        }
        self.free_head = desc_idx;
        self.num_free = self.num_free.saturating_add(1);

        Some((desc_idx, elem.len))
    }

    /// Returns `true` if no free descriptors remain.
    ///
    /// # Example
    ///
    /// ```
    /// use nexacore_driver_net_virtio::ring::SplitVirtqueue;
    ///
    /// let mut vq = SplitVirtqueue::new(2);
    /// assert!(!vq.is_full());
    /// vq.add_buffer(0x1000, 64, false);
    /// vq.add_buffer(0x2000, 64, false);
    /// assert!(vq.is_full());
    /// ```
    #[must_use]
    pub fn is_full(&self) -> bool {
        self.num_free == 0
    }

    /// Returns the number of currently free descriptors.
    ///
    /// # Example
    ///
    /// ```
    /// use nexacore_driver_net_virtio::ring::SplitVirtqueue;
    ///
    /// let vq = SplitVirtqueue::new(8);
    /// assert_eq!(vq.num_free(), 8);
    /// ```
    #[must_use]
    pub fn num_free(&self) -> u16 {
        self.num_free
    }

    /// Returns the current available-ring producer index.
    ///
    /// This value is written into the Common Configuration `queue_avail`
    /// register to notify the device of new entries. It wraps at `u16::MAX + 1`.
    ///
    /// # Example
    ///
    /// ```
    /// use nexacore_driver_net_virtio::ring::SplitVirtqueue;
    ///
    /// let mut vq = SplitVirtqueue::new(4);
    /// assert_eq!(vq.avail_idx(), 0);
    /// vq.add_buffer(0x1000, 64, false);
    /// assert_eq!(vq.avail_idx(), 1);
    /// ```
    #[must_use]
    pub fn avail_idx(&self) -> u16 {
        self.avail.idx
    }

    /// Return the queue size (capacity in descriptors).
    ///
    /// # Example
    ///
    /// ```
    /// use nexacore_driver_net_virtio::ring::SplitVirtqueue;
    ///
    /// let vq = SplitVirtqueue::new(64);
    /// assert_eq!(vq.queue_size(), 64);
    /// ```
    #[must_use]
    pub fn queue_size(&self) -> u16 {
        self.queue_size
    }

    /// Read the descriptor at `index`.
    ///
    /// Returns `None` if `index >= queue_size`.
    ///
    /// # Example
    ///
    /// ```
    /// use nexacore_driver_net_virtio::ring::SplitVirtqueue;
    ///
    /// let mut vq = SplitVirtqueue::new(4);
    /// vq.add_buffer(0xDEAD, 42, false);
    /// let desc = vq.desc(0).unwrap();
    /// assert_eq!(desc.addr, 0xDEAD);
    /// assert_eq!(desc.len, 42);
    /// ```
    #[must_use]
    pub fn desc(&self, index: u16) -> Option<&VirtqDesc> {
        self.desc_table.get(index as usize)
    }

    // -----------------------------------------------------------------------
    // Test-harness helpers (public so unit tests in child modules can reach
    // them; prefixed with `simulate_` to make the test-only intent legible).
    // -----------------------------------------------------------------------

    /// **Test harness only.** Simulate a device completion by writing a used
    /// ring element and advancing the used-ring index.
    ///
    /// In production the device firmware writes to the used ring in MMIO
    /// memory; there is no equivalent path in the pure-library layer. This
    /// method lets unit tests drive the `pop_used` path without a running
    /// device.
    ///
    /// # Example
    ///
    /// ```
    /// use nexacore_driver_net_virtio::ring::SplitVirtqueue;
    ///
    /// let mut vq = SplitVirtqueue::new(4);
    /// let idx = vq.add_buffer(0x1000, 64, true).unwrap();
    /// vq.simulate_device_completion(idx, 60);
    /// let result = vq.pop_used();
    /// assert_eq!(result, Some((idx, 60)));
    /// ```
    pub fn simulate_device_completion(&mut self, desc_idx: u16, bytes_written: u32) {
        // `slot` is bounded by `% queue_size` which equals `used_elems.len()`.
        let slot = (self.used_idx as usize) % (self.queue_size as usize);
        #[allow(clippy::indexing_slicing)]
        {
            self.used_elems[slot] = VirtqUsedElem {
                id: u32::from(desc_idx),
                len: bytes_written,
            };
        }
        self.used_idx = self.used_idx.wrapping_add(1);
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // ---- construction -------------------------------------------------------

    #[test]
    fn new_queue_is_empty_of_used_entries() {
        let vq = SplitVirtqueue::new(16);
        // No used entries yet.
        assert_eq!(vq.last_used_idx, 0);
        assert_eq!(vq.used_idx, 0);
    }

    #[test]
    fn new_queue_has_all_descriptors_free() {
        let vq = SplitVirtqueue::new(256);
        assert_eq!(vq.num_free(), 256);
        assert_eq!(vq.queue_size(), 256);
    }

    #[test]
    fn avail_idx_starts_at_zero() {
        let vq = SplitVirtqueue::new(8);
        assert_eq!(vq.avail_idx(), 0);
    }

    #[test]
    fn is_full_is_false_on_new_queue() {
        let vq = SplitVirtqueue::new(4);
        assert!(!vq.is_full());
    }

    // ---- add_buffer ---------------------------------------------------------

    #[test]
    fn add_buffer_returns_descriptor_index() {
        let mut vq = SplitVirtqueue::new(4);
        let idx = vq.add_buffer(0x1000, 64, false);
        assert!(idx.is_some());
    }

    #[test]
    fn add_buffer_decrements_num_free() {
        let mut vq = SplitVirtqueue::new(4);
        vq.add_buffer(0x1000, 64, false);
        assert_eq!(vq.num_free(), 3);
    }

    #[test]
    fn add_buffer_advances_avail_idx() {
        let mut vq = SplitVirtqueue::new(4);
        vq.add_buffer(0x1000, 64, false);
        assert_eq!(vq.avail_idx(), 1);
        vq.add_buffer(0x2000, 64, false);
        assert_eq!(vq.avail_idx(), 2);
    }

    #[test]
    fn add_buffer_sets_write_flag_for_rx() {
        let mut vq = SplitVirtqueue::new(4);
        let idx = vq.add_buffer(0x5000, 128, true).unwrap();
        let desc = vq.desc(idx).unwrap();
        assert_eq!(desc.flags & VIRTQ_DESC_F_WRITE, VIRTQ_DESC_F_WRITE);
    }

    #[test]
    fn add_buffer_clears_write_flag_for_tx() {
        let mut vq = SplitVirtqueue::new(4);
        let idx = vq.add_buffer(0x5000, 128, false).unwrap();
        let desc = vq.desc(idx).unwrap();
        assert_eq!(desc.flags & VIRTQ_DESC_F_WRITE, 0);
    }

    #[test]
    fn add_buffer_stores_address_and_length() {
        let mut vq = SplitVirtqueue::new(4);
        let idx = vq.add_buffer(0xDEAD_BEEF, 99, false).unwrap();
        let desc = vq.desc(idx).unwrap();
        assert_eq!(desc.addr, 0xDEAD_BEEF);
        assert_eq!(desc.len, 99);
    }

    // ---- queue full ---------------------------------------------------------

    #[test]
    fn add_buffer_returns_none_when_full() {
        let mut vq = SplitVirtqueue::new(2);
        assert!(vq.add_buffer(0x1000, 64, false).is_some());
        assert!(vq.add_buffer(0x2000, 64, false).is_some());
        // Third allocation must fail.
        assert!(vq.add_buffer(0x3000, 64, false).is_none());
        assert!(vq.is_full());
    }

    #[test]
    fn num_free_zero_when_full() {
        let mut vq = SplitVirtqueue::new(1);
        vq.add_buffer(0x1000, 1, false);
        assert_eq!(vq.num_free(), 0);
    }

    // ---- pop_used -----------------------------------------------------------

    #[test]
    fn pop_used_returns_none_before_completion() {
        let mut vq = SplitVirtqueue::new(4);
        vq.add_buffer(0x1000, 64, false);
        assert!(vq.pop_used().is_none());
    }

    #[test]
    fn pop_used_returns_completion_after_simulate() {
        let mut vq = SplitVirtqueue::new(4);
        let idx = vq.add_buffer(0x1000, 64, true).unwrap();
        vq.simulate_device_completion(idx, 60);
        let result = vq.pop_used();
        assert_eq!(result, Some((idx, 60)));
    }

    #[test]
    fn pop_used_returns_descriptor_to_free_list() {
        let mut vq = SplitVirtqueue::new(4);
        let idx = vq.add_buffer(0x1000, 64, false).unwrap();
        assert_eq!(vq.num_free(), 3);
        vq.simulate_device_completion(idx, 0);
        vq.pop_used();
        assert_eq!(vq.num_free(), 4);
    }

    #[test]
    fn pop_used_drains_multiple_completions_in_order() {
        let mut vq = SplitVirtqueue::new(4);
        let a = vq.add_buffer(0x1000, 64, true).unwrap();
        let b = vq.add_buffer(0x2000, 64, true).unwrap();
        vq.simulate_device_completion(a, 60);
        vq.simulate_device_completion(b, 62);
        let c1 = vq.pop_used();
        let c2 = vq.pop_used();
        let c3 = vq.pop_used();
        assert_eq!(c1, Some((a, 60)));
        assert_eq!(c2, Some((b, 62)));
        assert!(c3.is_none());
    }

    // ---- wrap-around --------------------------------------------------------

    #[test]
    fn avail_idx_wraps_at_u16_max() {
        let mut vq = SplitVirtqueue::new(2);
        // Manually set avail.idx close to the wrap point.
        vq.avail.idx = u16::MAX;
        // Drain the free list first so we do not over-allocate.
        vq.add_buffer(0x1000, 1, false);
        // Release back
        vq.simulate_device_completion(0, 0);
        vq.pop_used();
        // Now add one more — avail.idx should wrap to 0.
        vq.add_buffer(0x2000, 1, false);
        // MAX + 2 wraps to 1 (MAX→wraps to 0, then +1 for the fresh add).
        // After the first add at MAX: idx = MAX.wrapping_add(1) = 0
        // After the second add:      idx = 0.wrapping_add(1) = 1
        assert_eq!(vq.avail_idx(), 1);
    }

    #[test]
    fn free_list_consistent_after_alloc_release_cycle() {
        let mut vq = SplitVirtqueue::new(4);
        // Allocate all four.
        let indices: Vec<u16> = (0..4)
            .map(|i| vq.add_buffer(0x1000 * (i + 1), 64, false).unwrap())
            .collect();
        assert_eq!(vq.num_free(), 0);
        // Release all via simulated completions.
        for &idx in &indices {
            vq.simulate_device_completion(idx, 0);
        }
        for _ in 0..4 {
            vq.pop_used();
        }
        // All should be free again.
        assert_eq!(vq.num_free(), 4);
        // And we should be able to allocate all again.
        for i in 0..4 {
            assert!(vq.add_buffer(0xA000 * (i + 1), 32, false).is_some());
        }
    }

    // ---- queue_size = 1 edge case -------------------------------------------

    #[test]
    fn single_entry_queue_works() {
        let mut vq = SplitVirtqueue::new(1);
        assert_eq!(vq.num_free(), 1);
        let idx = vq.add_buffer(0x1000, 8, false).unwrap();
        assert_eq!(vq.num_free(), 0);
        assert!(vq.is_full());
        vq.simulate_device_completion(idx, 0);
        vq.pop_used();
        assert_eq!(vq.num_free(), 1);
    }

    // ---- descriptor field coverage ------------------------------------------

    #[test]
    fn desc_out_of_range_returns_none() {
        let vq = SplitVirtqueue::new(4);
        assert!(vq.desc(4).is_none());
        assert!(vq.desc(255).is_none());
    }

    // ---- flag constants -----------------------------------------------------

    #[test]
    fn flag_constants_match_virtio_spec() {
        // virtio 1.0 § 2.4.5.3: NEXT=1, WRITE=2.
        assert_eq!(VIRTQ_DESC_F_NEXT, 0x0001);
        assert_eq!(VIRTQ_DESC_F_WRITE, 0x0002);
    }

    #[test]
    fn flags_do_not_overlap() {
        assert_eq!(VIRTQ_DESC_F_NEXT & VIRTQ_DESC_F_WRITE, 0);
    }

    // ---- RX re-arm steady state (WS2-02.8) ----------------------------------

    #[test]
    fn rx_ring_stays_armed_across_many_receive_cycles() {
        // The RX path keeps the ring full by re-arming (re-posting) each buffer
        // immediately after the device completes it. Over many receive cycles
        // the ring must never lose descriptors nor desync its avail/used
        // indices — the failure mode behind the intermittent RX death
        // (DE-F-RXFLAKE). This drives far more cycles than the queue depth.
        const Q: u16 = 8;
        let mut vq = SplitVirtqueue::new(Q);

        // Initial fill: post all Q writable RX buffers.
        let mut posted: Vec<u16> = (0..Q)
            .map(|i| {
                vq.add_buffer(0x1_0000 + u64::from(i) * 0x1000, 2048, true)
                    .expect("initial RX fill must succeed")
            })
            .collect();
        assert!(vq.is_full(), "RX ring must be full after the initial fill");
        assert_eq!(vq.num_free(), 0);

        // Steady state: the device completes one buffer, the driver reclaims it
        // and immediately re-arms (re-posts) it. Repeat well beyond Q.
        for cycle in 0..(u32::from(Q) * 16) {
            let slot = (cycle as usize) % posted.len();
            let head = posted[slot];

            // Device writes 64 bytes into the head descriptor.
            vq.simulate_device_completion(head, 64);

            // Driver reclaims the completed buffer (one descriptor freed).
            let (reclaimed, bytes) = vq.pop_used().expect("a completion must be available");
            assert_eq!(reclaimed, head, "completions drain in FIFO order");
            assert_eq!(bytes, 64);
            assert_eq!(vq.num_free(), 1, "exactly one descriptor freed per cycle");

            // Driver re-arms: re-post a writable buffer into the freed slot.
            let rearmed = vq
                .add_buffer(0x1_0000 + u64::from(reclaimed) * 0x1000, 2048, true)
                .expect("re-arm must succeed when a slot is free");
            assert_eq!(
                vq.num_free(),
                0,
                "ring must be full again after re-arming (no descriptor leak)"
            );
            assert!(vq.is_full(), "RX ring must stay armed every cycle");

            posted[slot] = rearmed;
        }

        // After all the churn the ring is still fully armed with Q descriptors.
        assert!(vq.is_full());
        assert_eq!(vq.num_free(), 0);
    }

    // ---- arm-time pre-consumed buffer recycling (WS2-02.6) ------------------

    #[test]
    fn pre_arm_completions_are_drained_and_recycled_not_skipped() {
        // The DE-F-RXFLAKE fix defers the first RX doorbell to post-DRIVER_OK.
        // In that window the device may proactively consume some posted buffers
        // (bridge flood). The driver must DRAIN and RECYCLE those completions —
        // NOT skip them by fast-forwarding its used cursor — otherwise their
        // buffers never return to the ring and RX starves. This models that: a
        // full ring, device consumes every buffer, then pop_used drains all and
        // the descriptors return to the free list so the ring can be re-armed.
        const Q: u16 = 4;
        let mut vq = SplitVirtqueue::new(Q);
        let idxs: Vec<u16> = (0..Q)
            .map(|i| vq.add_buffer(0x1000 * u64::from(i + 1), 64, true).unwrap())
            .collect();
        assert_eq!(vq.num_free(), 0, "ring starts fully posted");
        // Device consumes all Q buffers before the driver armed.
        for &idx in &idxs {
            vq.simulate_device_completion(idx, 0);
        }
        // Draining recycles every buffer back to the free list (no skip).
        let mut drained = 0;
        while vq.pop_used().is_some() {
            drained += 1;
        }
        assert_eq!(drained, Q as usize, "every pre-arm completion is drained");
        assert_eq!(vq.num_free(), Q, "all buffers recycled — ring can re-arm");
    }
}
