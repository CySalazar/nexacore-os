//! Swap device format, swap-out/in, a compressed zram backend, and victim
//! page selection (WS3-06).
//!
//! Overcommit — large AI models and many apps — needs a place to evict cold
//! pages under memory pressure. This module is the **device-independent,
//! host-testable** core:
//!
//! - the on-disk swap format ([`SwapHeader`] + [`SwapSlotMap`], WS3-06.1) and
//!   the swap-out/swap-in mechanism over a [`SwapDevice`] seam (WS3-06.2/.3);
//! - a [`ZramStore`] compressed in-RAM backend (WS3-06.4) behind a
//!   [`PageCompressor`] seam (LZ4/ZSTD is library-gated; the default stores
//!   verbatim);
//! - a clock / second-chance [`ClockSelector`] that picks the victim frame under
//!   pressure (WS3-06.6).
//!
//! Wiring swap into the frame allocator's eviction path (WS1-08) is WS3-06.5;
//! the VM-103 memory-pressure test is WS3-06.7.

use alloc::{collections::BTreeMap, vec, vec::Vec};

/// A memory page — the swap and zram unit.
pub const PAGE_SIZE: usize = 4096;

/// A single page.
pub type Page = [u8; PAGE_SIZE];

/// A resident physical frame identifier.
pub type FrameId = u64;

/// Errors from the swap subsystem.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SwapError {
    /// The swap device has no free slot.
    Full,
    /// A slot index was outside the device.
    SlotOutOfRange,
    /// The slot is not currently allocated.
    SlotNotAllocated,
    /// A structure failed to parse (bad magic / version / page size).
    Corrupt,
    /// A backing-store read/write failed.
    Io,
    /// A stored page could not be decompressed.
    Decompress,
}

/// Swap header magic (`"NCSWAP01"`).
pub const SWAP_MAGIC: [u8; 8] = *b"NCSWAP01";

/// The swap device header: how many page slots and the page size (WS3-06.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SwapHeader {
    /// Number of page slots on the device.
    pub slot_count: u64,
    /// Page size in bytes (must equal [`PAGE_SIZE`]).
    pub page_size: u32,
}

impl SwapHeader {
    /// Serialise the header (20 bytes: magic ‖ `slot_count` ‖ `page_size`).
    #[must_use]
    pub fn encode(&self) -> [u8; 20] {
        let mut out = [0u8; 20];
        if let Some(s) = out.get_mut(0..8) {
            s.copy_from_slice(&SWAP_MAGIC);
        }
        if let Some(s) = out.get_mut(8..16) {
            s.copy_from_slice(&self.slot_count.to_le_bytes());
        }
        if let Some(s) = out.get_mut(16..20) {
            s.copy_from_slice(&self.page_size.to_le_bytes());
        }
        out
    }

    /// Parse a header, validating the magic and that the page size matches.
    ///
    /// # Errors
    /// [`SwapError::Corrupt`] on a bad magic or a page size other than
    /// [`PAGE_SIZE`].
    pub fn decode(bytes: &[u8]) -> Result<Self, SwapError> {
        let magic = bytes.get(0..8).ok_or(SwapError::Corrupt)?;
        if magic != SWAP_MAGIC {
            return Err(SwapError::Corrupt);
        }
        let slot_bytes: [u8; 8] = bytes
            .get(8..16)
            .and_then(|s| s.try_into().ok())
            .ok_or(SwapError::Corrupt)?;
        let page_bytes: [u8; 4] = bytes
            .get(16..20)
            .and_then(|s| s.try_into().ok())
            .ok_or(SwapError::Corrupt)?;
        let page_size = u32::from_le_bytes(page_bytes);
        if page_size as usize != PAGE_SIZE {
            return Err(SwapError::Corrupt);
        }
        Ok(Self {
            slot_count: u64::from_le_bytes(slot_bytes),
            page_size,
        })
    }
}

/// A free/used map over the swap device's page slots (WS3-06.1).
#[derive(Debug, Clone)]
pub struct SwapSlotMap {
    used: Vec<bool>,
}

impl SwapSlotMap {
    /// A map over `slot_count` slots, all free.
    #[must_use]
    pub fn new(slot_count: u64) -> Self {
        Self {
            used: vec![false; usize::try_from(slot_count).unwrap_or(usize::MAX)],
        }
    }

    /// The number of slots.
    #[must_use]
    pub fn slot_count(&self) -> u64 {
        self.used.len() as u64
    }

    /// The number of free slots.
    #[must_use]
    pub fn free_count(&self) -> u64 {
        self.used.iter().filter(|&&u| !u).count() as u64
    }

    /// Whether `slot` is allocated (`false` if out of range).
    #[must_use]
    pub fn is_used(&self, slot: u64) -> bool {
        usize::try_from(slot)
            .ok()
            .and_then(|i| self.used.get(i))
            .copied()
            .unwrap_or(false)
    }

    /// Allocate the lowest free slot, if any.
    pub fn alloc(&mut self) -> Option<u64> {
        let slot = self.used.iter().position(|&u| !u)?;
        if let Some(flag) = self.used.get_mut(slot) {
            *flag = true;
        }
        Some(slot as u64)
    }

    /// Free `slot`.
    ///
    /// # Errors
    /// [`SwapError::SlotOutOfRange`] if `slot` is outside the map;
    /// [`SwapError::SlotNotAllocated`] if it was already free.
    pub fn free(&mut self, slot: u64) -> Result<(), SwapError> {
        let idx = usize::try_from(slot).map_err(|_| SwapError::SlotOutOfRange)?;
        let flag = self.used.get_mut(idx).ok_or(SwapError::SlotOutOfRange)?;
        if !*flag {
            return Err(SwapError::SlotNotAllocated);
        }
        *flag = false;
        Ok(())
    }
}

/// A swap backing store addressed by page slot (WS3-06.2/.3).
pub trait SwapDevice {
    /// Number of page slots.
    fn slot_count(&self) -> u64;

    /// Write `page` to `slot`.
    ///
    /// # Errors
    /// [`SwapError::SlotOutOfRange`] / [`SwapError::Io`].
    fn write_page(&mut self, slot: u64, page: &Page) -> Result<(), SwapError>;

    /// Read `slot` into `out`.
    ///
    /// # Errors
    /// [`SwapError::SlotOutOfRange`] / [`SwapError::Io`].
    fn read_page(&self, slot: u64, out: &mut Page) -> Result<(), SwapError>;
}

/// In-memory [`SwapDevice`] for host tests.
#[derive(Debug, Clone)]
pub struct MemSwapDevice {
    slots: Vec<Page>,
}

impl MemSwapDevice {
    /// A device with `slot_count` zeroed slots.
    #[must_use]
    pub fn new(slot_count: u64) -> Self {
        Self {
            slots: vec![[0u8; PAGE_SIZE]; usize::try_from(slot_count).unwrap_or(usize::MAX)],
        }
    }
}

impl SwapDevice for MemSwapDevice {
    fn slot_count(&self) -> u64 {
        self.slots.len() as u64
    }

    fn write_page(&mut self, slot: u64, page: &Page) -> Result<(), SwapError> {
        let idx = usize::try_from(slot).map_err(|_| SwapError::SlotOutOfRange)?;
        let dst = self.slots.get_mut(idx).ok_or(SwapError::SlotOutOfRange)?;
        dst.copy_from_slice(page);
        Ok(())
    }

    fn read_page(&self, slot: u64, out: &mut Page) -> Result<(), SwapError> {
        let idx = usize::try_from(slot).map_err(|_| SwapError::SlotOutOfRange)?;
        let src = self.slots.get(idx).ok_or(SwapError::SlotOutOfRange)?;
        out.copy_from_slice(src);
        Ok(())
    }
}

/// Swap `page` out: allocate a slot and write it, returning the slot. On a write
/// failure the slot is released so it is not leaked.
///
/// # Errors
/// [`SwapError::Full`] if no slot is free, or a device error from the write.
pub fn swap_out<D: SwapDevice>(
    dev: &mut D,
    map: &mut SwapSlotMap,
    page: &Page,
) -> Result<u64, SwapError> {
    let slot = map.alloc().ok_or(SwapError::Full)?;
    match dev.write_page(slot, page) {
        Ok(()) => Ok(slot),
        Err(err) => {
            let _ = map.free(slot);
            Err(err)
        }
    }
}

/// Swap a page in: read `slot` into `out` and free it (the page is back in RAM).
///
/// # Errors
/// [`SwapError::SlotNotAllocated`] if `slot` is not allocated, or a device error
/// from the read.
pub fn swap_in<D: SwapDevice>(
    dev: &D,
    map: &mut SwapSlotMap,
    slot: u64,
    out: &mut Page,
) -> Result<(), SwapError> {
    if !map.is_used(slot) {
        return Err(SwapError::SlotNotAllocated);
    }
    dev.read_page(slot, out)?;
    map.free(slot)
}

/// A pluggable page compressor for [`ZramStore`] (LZ4/ZSTD is library-gated).
pub trait PageCompressor {
    /// Compress a page. A backend that cannot shrink it may return it unchanged.
    fn compress(&self, page: &Page) -> Vec<u8>;

    /// Decompress `data` (`orig_len` bytes) into `out`.
    ///
    /// # Errors
    /// [`SwapError::Decompress`] if the input is malformed.
    fn decompress(&self, data: &[u8], out: &mut Page) -> Result<(), SwapError>;
}

/// The identity compressor: stores pages verbatim (placeholder until LZ4/ZSTD).
#[derive(Debug, Clone, Copy, Default)]
pub struct IdentityCompressor;

impl PageCompressor for IdentityCompressor {
    fn compress(&self, page: &Page) -> Vec<u8> {
        page.to_vec()
    }

    fn decompress(&self, data: &[u8], out: &mut Page) -> Result<(), SwapError> {
        if data.len() != PAGE_SIZE {
            return Err(SwapError::Decompress);
        }
        out.copy_from_slice(data);
        Ok(())
    }
}

/// A stored zram page: whether it is compressed, plus the bytes.
#[derive(Debug, Clone)]
struct ZramEntry {
    compressed: bool,
    data: Vec<u8>,
}

/// A compressed in-RAM swap backend: pages are compressed and kept in memory
/// instead of going to a disk device (WS3-06.4).
#[derive(Debug, Clone)]
pub struct ZramStore<C: PageCompressor> {
    compressor: C,
    frames: BTreeMap<FrameId, ZramEntry>,
    stored_bytes: usize,
}

impl<C: PageCompressor> ZramStore<C> {
    /// A store using `compressor`.
    #[must_use]
    pub fn new(compressor: C) -> Self {
        Self {
            compressor,
            frames: BTreeMap::new(),
            stored_bytes: 0,
        }
    }

    /// The number of stored frames.
    #[must_use]
    pub fn len(&self) -> usize {
        self.frames.len()
    }

    /// Whether the store is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.frames.is_empty()
    }

    /// Total bytes held (compressed where it helped).
    #[must_use]
    pub fn stored_bytes(&self) -> usize {
        self.stored_bytes
    }

    /// Store `page` under `frame_id`, compressing only if it shrinks the page
    /// (opt-in), replacing any prior entry.
    pub fn store(&mut self, frame_id: FrameId, page: &Page) {
        let compressed = self.compressor.compress(page);
        let entry = if compressed.len() < PAGE_SIZE {
            ZramEntry {
                compressed: true,
                data: compressed,
            }
        } else {
            ZramEntry {
                compressed: false,
                data: page.to_vec(),
            }
        };
        if let Some(prev) = self.frames.insert(frame_id, entry) {
            self.stored_bytes = self.stored_bytes.saturating_sub(prev.data.len());
        }
        if let Some(entry) = self.frames.get(&frame_id) {
            self.stored_bytes = self.stored_bytes.saturating_add(entry.data.len());
        }
    }

    /// Load the page stored under `frame_id` into `out`.
    ///
    /// # Errors
    /// [`SwapError::SlotNotAllocated`] if no page is stored for `frame_id`;
    /// [`SwapError::Decompress`] if a compressed entry cannot be expanded.
    pub fn load(&self, frame_id: FrameId, out: &mut Page) -> Result<(), SwapError> {
        let entry = self
            .frames
            .get(&frame_id)
            .ok_or(SwapError::SlotNotAllocated)?;
        if entry.compressed {
            self.compressor.decompress(&entry.data, out)
        } else if entry.data.len() == PAGE_SIZE {
            out.copy_from_slice(&entry.data);
            Ok(())
        } else {
            Err(SwapError::Decompress)
        }
    }

    /// Drop the page stored under `frame_id`, returning whether it existed.
    pub fn evict(&mut self, frame_id: FrameId) -> bool {
        match self.frames.remove(&frame_id) {
            Some(entry) => {
                self.stored_bytes = self.stored_bytes.saturating_sub(entry.data.len());
                true
            }
            None => false,
        }
    }
}

/// A clock / second-chance page-replacement selector (WS3-06.6).
///
/// Resident frames sit on a circular list, each with a reference bit set on
/// access. [`ClockSelector::select_victim`] sweeps the hand: a referenced frame
/// gets a second chance (its bit is cleared and the hand advances); the first
/// unreferenced frame is evicted and returned.
#[derive(Debug, Clone, Default)]
pub struct ClockSelector {
    entries: Vec<(FrameId, bool)>,
    hand: usize,
}

impl ClockSelector {
    /// An empty selector.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// The number of resident frames tracked.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether no frames are tracked.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Track `frame` as resident and recently accessed (reference bit set). A
    /// duplicate add just marks it accessed.
    pub fn add(&mut self, frame: FrameId) {
        if self.note_access(frame) {
            return;
        }
        self.entries.push((frame, true));
    }

    /// Mark `frame` as accessed (set its reference bit); returns whether it was
    /// tracked.
    pub fn note_access(&mut self, frame: FrameId) -> bool {
        for entry in &mut self.entries {
            if entry.0 == frame {
                entry.1 = true;
                return true;
            }
        }
        false
    }

    /// Stop tracking `frame`, returning whether it was tracked.
    pub fn remove(&mut self, frame: FrameId) -> bool {
        if let Some(idx) = self.entries.iter().position(|&(f, _)| f == frame) {
            self.entries.remove(idx);
            if self.hand > idx {
                self.hand -= 1;
            }
            if self.entries.is_empty() {
                self.hand = 0;
            } else {
                self.hand %= self.entries.len();
            }
            true
        } else {
            false
        }
    }

    /// Select and evict the next victim frame, or `None` if empty.
    pub fn select_victim(&mut self) -> Option<FrameId> {
        if self.entries.is_empty() {
            return None;
        }
        // At most two full sweeps: the first clears all reference bits, the
        // second is guaranteed to find one at `false`.
        let bound = self.entries.len().saturating_mul(2).saturating_add(1);
        for _ in 0..bound {
            if self.hand >= self.entries.len() {
                self.hand = 0;
            }
            let (frame, referenced) = *self.entries.get(self.hand)?;
            if referenced {
                if let Some(entry) = self.entries.get_mut(self.hand) {
                    entry.1 = false;
                }
                self.hand = self.hand.saturating_add(1);
            } else {
                self.entries.remove(self.hand);
                if self.entries.is_empty() {
                    self.hand = 0;
                } else {
                    self.hand %= self.entries.len();
                }
                return Some(frame);
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn page(byte: u8) -> Page {
        [byte; PAGE_SIZE]
    }

    #[test]
    fn swap_header_round_trips_and_rejects_bad_magic() {
        let h = SwapHeader {
            slot_count: 4096,
            page_size: u32::try_from(PAGE_SIZE).unwrap(),
        };
        assert_eq!(SwapHeader::decode(&h.encode()).unwrap(), h);
        let mut bytes = h.encode();
        bytes[0] ^= 0xFF;
        assert_eq!(SwapHeader::decode(&bytes), Err(SwapError::Corrupt));
        // A mismatched page size is rejected (0x1000 → 0x0000 by clearing the
        // high byte of the low half).
        let mut bytes = h.encode();
        bytes[17] = 0;
        assert_eq!(SwapHeader::decode(&bytes), Err(SwapError::Corrupt));
    }

    #[test]
    fn slot_map_allocates_frees_and_reports_full() {
        let mut map = SwapSlotMap::new(2);
        assert_eq!(map.free_count(), 2);
        let a = map.alloc().unwrap();
        let b = map.alloc().unwrap();
        assert_eq!((a, b), (0, 1));
        assert!(map.is_used(0) && map.is_used(1));
        assert_eq!(map.alloc(), None, "full");
        map.free(0).unwrap();
        assert_eq!(map.free(0), Err(SwapError::SlotNotAllocated));
        assert_eq!(map.free(9), Err(SwapError::SlotOutOfRange));
        assert_eq!(map.alloc(), Some(0), "freed slot reused");
    }

    #[test]
    fn swap_out_then_in_round_trips() {
        let mut dev = MemSwapDevice::new(4);
        let mut map = SwapSlotMap::new(4);
        let slot = swap_out(&mut dev, &mut map, &page(0xAB)).unwrap();
        assert!(map.is_used(slot));
        let mut out = page(0);
        swap_in(&dev, &mut map, slot, &mut out).unwrap();
        assert_eq!(out, page(0xAB));
        // The slot is freed after swap-in; swapping it in again is an error.
        assert!(!map.is_used(slot));
        assert_eq!(
            swap_in(&dev, &mut map, slot, &mut out),
            Err(SwapError::SlotNotAllocated)
        );
    }

    #[test]
    fn swap_out_reports_full_when_no_slot() {
        let mut dev = MemSwapDevice::new(1);
        let mut map = SwapSlotMap::new(1);
        swap_out(&mut dev, &mut map, &page(1)).unwrap();
        assert_eq!(swap_out(&mut dev, &mut map, &page(2)), Err(SwapError::Full));
    }

    #[test]
    fn zram_stores_and_loads_pages() {
        let mut zram = ZramStore::new(IdentityCompressor);
        assert!(zram.is_empty());
        zram.store(7, &page(0x5A));
        assert_eq!(zram.len(), 1);
        let mut out = page(0);
        zram.load(7, &mut out).unwrap();
        assert_eq!(out, page(0x5A));
        // Overwrite keeps a single entry and re-accounts bytes.
        zram.store(7, &page(0x11));
        assert_eq!(zram.len(), 1);
        zram.load(7, &mut out).unwrap();
        assert_eq!(out, page(0x11));
        assert!(zram.evict(7));
        assert!(!zram.evict(7));
        assert_eq!(zram.load(7, &mut out), Err(SwapError::SlotNotAllocated));
    }

    /// A trivial run-length compressor to exercise the compressed zram path.
    struct Rle;
    impl PageCompressor for Rle {
        fn compress(&self, page: &Page) -> Vec<u8> {
            // A full page of one byte compresses to 2 bytes.
            let first = page[0];
            if page.iter().all(|&b| b == first) {
                alloc::vec![0u8, first]
            } else {
                page.to_vec()
            }
        }
        fn decompress(&self, data: &[u8], out: &mut Page) -> Result<(), SwapError> {
            match data {
                [0u8, byte] => {
                    *out = [*byte; PAGE_SIZE];
                    Ok(())
                }
                _ if data.len() == PAGE_SIZE => {
                    out.copy_from_slice(data);
                    Ok(())
                }
                _ => Err(SwapError::Decompress),
            }
        }
    }

    #[test]
    fn zram_compresses_when_it_helps() {
        let mut zram = ZramStore::new(Rle);
        zram.store(1, &page(0x77)); // uniform → compresses to 2 bytes
        assert_eq!(zram.stored_bytes(), 2);
        let mut out = page(0);
        zram.load(1, &mut out).unwrap();
        assert_eq!(out, page(0x77));
    }

    #[test]
    fn clock_gives_second_chance_then_evicts_unreferenced() {
        let mut clock = ClockSelector::new();
        for f in [1u64, 2, 3] {
            clock.add(f); // all start referenced
        }
        assert_eq!(clock.len(), 3);
        // First sweep clears the reference bits, so the first frame (1) is the
        // first one found unreferenced and is evicted.
        assert_eq!(clock.select_victim(), Some(1));
        assert_eq!(clock.len(), 2);
        // Re-reference frame 2; the next victim should be 3, not 2.
        clock.note_access(2);
        assert_eq!(clock.select_victim(), Some(3));
        assert_eq!(clock.select_victim(), Some(2));
        assert_eq!(clock.select_victim(), None, "empty");
    }

    #[test]
    fn clock_remove_is_stable() {
        let mut clock = ClockSelector::new();
        for f in [10u64, 20, 30] {
            clock.add(f);
        }
        assert!(clock.remove(20));
        assert!(!clock.remove(20));
        assert_eq!(clock.len(), 2);
        // Still selects the survivors.
        let a = clock.select_victim().unwrap();
        let b = clock.select_victim().unwrap();
        assert!(matches!((a, b), (10, 30) | (30, 10)));
    }
}
