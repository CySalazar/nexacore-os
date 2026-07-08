//! NVMe Identify response parsers.
//!
//! Pure-function decoders for the 4 KiB response payloads the
//! controller writes into the IOVA buffer the driver supplied with
//! `Identify Controller` (NVMe 1.4 § 5.15.2 Figure 247) and
//! `Identify Namespace` (§ 5.15.2 Figure 245). The driver consumes
//! a small subset of the fields for Phase-1 bring-up per
//! NCIP-Driver-NVMe-014 § S6 steps 8–10:
//!
//! - `Identify Controller` → `NN` (Number of Namespaces, the count
//!   of namespaces the controller exposes).
//! - `Identify Namespace` → `NSZE` (Namespace Size in 4 KiB
//!   sectors), `NCAP` (Namespace Capacity), `LBADS` (LBA Data
//!   Size — Phase-1 requires `LBADS = 12`, i.e. 4 KiB sectors).
//!
//! All multi-byte fields are little-endian per NVMe 1.4 § 3.0.
//!
//! ## What this module does NOT do
//!
//! - It does NOT validate the response page's checksum (NVMe has
//!   none — integrity is enforced by the IOMMU + completion
//!   status word).
//! - It does NOT pull every field — only the subset Phase-1 needs.
//!   Future fields land as additional pure-function accessors on
//!   the [`IdentifyController`] / [`IdentifyNamespace`] views.

use core::convert::TryInto;

/// Required size of an Identify response page per NVMe 1.4
/// § 5.15.2.
pub const IDENTIFY_RESPONSE_BYTES: usize = 4096;

/// `LBADS` value Phase-1 NVMe accepts (4 KiB sectors per NexaCore OS
/// kernel page size). NVMe 1.4 § 5.15.2 encodes LBADS as the
/// `log2(LBA size)` so `LBADS = 12` corresponds to 4096-byte
/// sectors.
pub const PHASE_1_REQUIRED_LBADS: u8 = 12;

/// Errors a parser can surface.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum IdentifyError {
    /// The supplied page is smaller than
    /// [`IDENTIFY_RESPONSE_BYTES`]. Indicates a buffer-shape
    /// regression upstream (the IOMMU buffer is expected to be
    /// exactly 4 KiB).
    PageTooSmall,
    /// `LBADS` field is not equal to [`PHASE_1_REQUIRED_LBADS`].
    /// Per NCIP-014 § S6 step 10 the driver rejects any namespace
    /// whose sector size is not 4 KiB.
    UnsupportedLbads {
        /// The actual `LBADS` value the controller reported.
        observed: u8,
    },
}

// =============================================================================
// IdentifyController
// =============================================================================

/// Zero-copy view of the 4 KiB Identify Controller response page.
///
/// The view stores the byte slice borrow; field accessors decode
/// fields on demand so the parser never allocates.
#[derive(Debug, Clone, Copy)]
pub struct IdentifyController<'a> {
    page: &'a [u8],
}

impl<'a> IdentifyController<'a> {
    /// `NN` — Number of Namespaces field offset (Figure 247).
    pub const NN_OFFSET: usize = 516;

    /// Construct the view over a 4 KiB response page.
    ///
    /// # Errors
    ///
    /// - [`IdentifyError::PageTooSmall`] if `page.len() <
    ///   IDENTIFY_RESPONSE_BYTES`.
    pub fn new(page: &'a [u8]) -> Result<Self, IdentifyError> {
        if page.len() < IDENTIFY_RESPONSE_BYTES {
            return Err(IdentifyError::PageTooSmall);
        }
        Ok(Self { page })
    }

    /// Number of Namespaces the controller exposes.
    ///
    /// NVMe 1.4 § 5.15.2 Figure 247 encodes NN as a 32-bit
    /// little-endian value at offset 516. Phase-1 driver uses
    /// `NN` only to log the controller's capacity (the single
    /// supported namespace is identified via
    /// `Identify(ActiveNsList)` at the next bring-up step).
    #[must_use]
    pub fn nn(&self) -> u32 {
        read_le_u32(self.page, Self::NN_OFFSET)
    }
}

// =============================================================================
// IdentifyNamespace
// =============================================================================

/// Zero-copy view of the 4 KiB Identify Namespace response page.
#[derive(Debug, Clone, Copy)]
pub struct IdentifyNamespace<'a> {
    page: &'a [u8],
}

impl<'a> IdentifyNamespace<'a> {
    /// `NSZE` — Namespace Size field offset (Figure 245).
    pub const NSZE_OFFSET: usize = 0;

    /// `NCAP` — Namespace Capacity field offset.
    pub const NCAP_OFFSET: usize = 8;

    /// `NLBAF` — Number of LBA Formats field offset (1-based
    /// count − 1; e.g. `NLBAF = 0` means one format).
    pub const NLBAF_OFFSET: usize = 25;

    /// `FLBAS` — Formatted LBA Size field offset. Bits 3..=0
    /// select which of the up-to-16 `LBAF` entries below
    /// describes the namespace's active format.
    pub const FLBAS_OFFSET: usize = 26;

    /// `LBAF0` — first LBA Format descriptor offset. Each
    /// descriptor is 4 bytes; the LBADS byte we want lives at
    /// offset `LBAF_BASE + 2 + 4 * format_index`.
    pub const LBAF_BASE_OFFSET: usize = 128;

    /// Bytes per `LBAF` descriptor (NVMe 1.4 § 5.15.2 Figure 245).
    pub const LBAF_BYTES: usize = 4;

    /// Construct the view over a 4 KiB response page.
    ///
    /// # Errors
    ///
    /// - [`IdentifyError::PageTooSmall`] if `page.len() <
    ///   IDENTIFY_RESPONSE_BYTES`.
    pub fn new(page: &'a [u8]) -> Result<Self, IdentifyError> {
        if page.len() < IDENTIFY_RESPONSE_BYTES {
            return Err(IdentifyError::PageTooSmall);
        }
        Ok(Self { page })
    }

    /// Namespace Size in 4 KiB sectors per NVMe 1.4 § 5.15.2
    /// Figure 245. The value is the total LBA count of the
    /// namespace; multiplied by the active LBA size it gives the
    /// total byte capacity.
    #[must_use]
    pub fn nsze(&self) -> u64 {
        read_le_u64(self.page, Self::NSZE_OFFSET)
    }

    /// Namespace Capacity in sectors (the largest value
    /// `NSZE` may grow to without re-formatting).
    #[must_use]
    pub fn ncap(&self) -> u64 {
        read_le_u64(self.page, Self::NCAP_OFFSET)
    }

    /// `FLBAS` byte (Formatted LBA Size). Bits 3..=0 select the
    /// active LBA format; bits 4..=6 are extended metadata
    /// flags Phase-1 ignores.
    #[must_use]
    pub fn flbas(&self) -> u8 {
        self.page.get(Self::FLBAS_OFFSET).copied().unwrap_or(0)
    }

    /// Active LBA format index — `FLBAS & 0xF`.
    #[must_use]
    pub fn active_format_index(&self) -> u8 {
        self.flbas() & 0x0F
    }

    /// LBA Data Size of the active LBA format, as the
    /// `log2(sector_size_in_bytes)` per NVMe 1.4 § 5.15.2.
    ///
    /// `LBADS = 12` ↔ 4 KiB sectors (Phase-1 supported value).
    #[must_use]
    pub fn lbads(&self) -> u8 {
        let format_index = self.active_format_index() as usize;
        let lbaf_offset = Self::LBAF_BASE_OFFSET + format_index * Self::LBAF_BYTES;
        // The LBA Data Size byte lives at offset `+2` inside the
        // LBAF descriptor (Figure 245); bits 4..=0 hold the value.
        self.page
            .get(lbaf_offset + 2)
            .copied()
            .map_or(0, |b| b & 0x1F)
    }

    /// Returns `Ok(byte_size)` when the active LBA format matches
    /// the Phase-1 4 KiB requirement, where `byte_size = NSZE *
    /// 4096`. Returns [`IdentifyError::UnsupportedLbads`] when
    /// `LBADS != PHASE_1_REQUIRED_LBADS`.
    ///
    /// # Errors
    ///
    /// - [`IdentifyError::UnsupportedLbads`] per NCIP-014 § S6
    ///   step 10.
    pub fn validated_byte_size(&self) -> Result<u64, IdentifyError> {
        let lbads = self.lbads();
        if lbads != PHASE_1_REQUIRED_LBADS {
            return Err(IdentifyError::UnsupportedLbads { observed: lbads });
        }
        // Sector size = 1 << LBADS = 4096; NSZE * 4096 = NSZE << 12.
        Ok(self.nsze().wrapping_shl(u32::from(lbads)))
    }
}

// =============================================================================
// ActiveNsListView
// =============================================================================

/// Maximum number of NSIDs the controller may report in a single
/// `Identify Active Namespace List` response page (NVMe 1.4
/// § 5.15.2 Figure 246: 4096 bytes / 4 bytes per NSID = 1024).
#[allow(
    clippy::integer_division,
    reason = "compile-time division 4096/4 = 1024 is exact and has no runtime cost"
)]
pub const MAX_ACTIVE_NSIDS: usize = IDENTIFY_RESPONSE_BYTES / 4;

/// Zero-copy view of the 4 KiB `Identify(ActiveNsList)` response.
///
/// The page is a packed array of up-to-1024 little-endian 32-bit
/// NSIDs in ascending order, terminated by a sentinel NSID = 0
/// entry per NVMe 1.4 § 5.15.2 Figure 246. The driver iterates
/// until it sees the terminator (or until the page is exhausted at
/// `MAX_ACTIVE_NSIDS` entries).
#[derive(Debug, Clone, Copy)]
pub struct ActiveNsListView<'a> {
    page: &'a [u8],
}

impl<'a> ActiveNsListView<'a> {
    /// Construct the view over a 4 KiB response page.
    ///
    /// # Errors
    ///
    /// - [`IdentifyError::PageTooSmall`] if `page.len() <
    ///   IDENTIFY_RESPONSE_BYTES`.
    pub fn new(page: &'a [u8]) -> Result<Self, IdentifyError> {
        if page.len() < IDENTIFY_RESPONSE_BYTES {
            return Err(IdentifyError::PageTooSmall);
        }
        Ok(Self { page })
    }

    /// Iterate over the active NSIDs the controller reported.
    ///
    /// The iterator yields NSIDs in the order they appear in the
    /// page and stops at the first NSID = 0 entry (the sentinel
    /// terminator per Figure 246). If the page is full (no
    /// terminator within [`MAX_ACTIVE_NSIDS`] entries), the
    /// iterator yields every non-zero NSID and then stops.
    #[must_use]
    pub fn iter_nsids(&self) -> ActiveNsListIter<'a> {
        ActiveNsListIter {
            page: self.page,
            next_index: 0,
        }
    }

    /// Returns the first active NSID, or `None` if the controller
    /// reported zero namespaces. The Phase-1 bring-up FSM uses
    /// this to seed the subsequent `Identify(Namespace)` call.
    #[must_use]
    pub fn first_active_nsid(&self) -> Option<u32> {
        self.iter_nsids().next()
    }
}

/// Forward-only iterator over the NSIDs in an
/// [`ActiveNsListView`]. Stops at the first zero (sentinel) entry
/// or after [`MAX_ACTIVE_NSIDS`] entries — whichever comes first.
#[derive(Debug, Clone)]
pub struct ActiveNsListIter<'a> {
    page: &'a [u8],
    next_index: usize,
}

impl Iterator for ActiveNsListIter<'_> {
    type Item = u32;

    fn next(&mut self) -> Option<u32> {
        if self.next_index >= MAX_ACTIVE_NSIDS {
            return None;
        }
        let off = self.next_index * 4;
        let nsid = read_le_u32(self.page, off);
        if nsid == 0 {
            // Sentinel: clamp the index so subsequent calls also
            // return None without re-reading bytes past the
            // terminator.
            self.next_index = MAX_ACTIVE_NSIDS;
            return None;
        }
        self.next_index += 1;
        Some(nsid)
    }
}

// =============================================================================
// Internal byte helpers
// =============================================================================

fn read_le_u32(page: &[u8], off: usize) -> u32 {
    let slice = page
        .get(off..off + 4)
        .and_then(|s| s.try_into().ok())
        .unwrap_or([0u8; 4]);
    u32::from_le_bytes(slice)
}

fn read_le_u64(page: &[u8], off: usize) -> u64 {
    let slice = page
        .get(off..off + 8)
        .and_then(|s| s.try_into().ok())
        .unwrap_or([0u8; 8]);
    u64::from_le_bytes(slice)
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
#[allow(
    clippy::indexing_slicing,
    reason = "host tests pre-allocate a fixed 4 KiB page and write canonical NVMe field offsets in-place; the indexing pattern mirrors NVMe 1.4 Figure 245/247 verbatim"
)]
mod tests {
    use alloc::vec;

    use super::*;

    fn zero_page() -> alloc::vec::Vec<u8> {
        vec![0u8; IDENTIFY_RESPONSE_BYTES]
    }

    // -------------------------------------------------------------------
    // Constants tripwires
    // -------------------------------------------------------------------

    #[test]
    fn identify_response_bytes_matches_spec() {
        assert_eq!(IDENTIFY_RESPONSE_BYTES, 4096);
    }

    #[test]
    fn phase_1_required_lbads_matches_ncip_014() {
        // NCIP-014 § S6 step 10 — `LBADS = 12` for 4 KiB sectors.
        assert_eq!(PHASE_1_REQUIRED_LBADS, 12);
    }

    // -------------------------------------------------------------------
    // IdentifyController
    // -------------------------------------------------------------------

    #[test]
    fn identify_controller_rejects_undersized_page() {
        let small = vec![0u8; IDENTIFY_RESPONSE_BYTES - 1];
        let res = IdentifyController::new(&small);
        assert!(matches!(res, Err(IdentifyError::PageTooSmall)));
    }

    #[test]
    fn identify_controller_nn_at_offset_516_little_endian() {
        let mut page = zero_page();
        // NN = 0x1234_5678 little-endian.
        page[IdentifyController::NN_OFFSET] = 0x78;
        page[IdentifyController::NN_OFFSET + 1] = 0x56;
        page[IdentifyController::NN_OFFSET + 2] = 0x34;
        page[IdentifyController::NN_OFFSET + 3] = 0x12;
        let view = IdentifyController::new(&page).unwrap();
        assert_eq!(view.nn(), 0x1234_5678);
    }

    #[test]
    fn identify_controller_nn_zero_for_empty_page() {
        let page = zero_page();
        let view = IdentifyController::new(&page).unwrap();
        assert_eq!(view.nn(), 0);
    }

    // -------------------------------------------------------------------
    // IdentifyNamespace
    // -------------------------------------------------------------------

    #[test]
    fn identify_namespace_rejects_undersized_page() {
        let small = vec![0u8; IDENTIFY_RESPONSE_BYTES - 1];
        let res = IdentifyNamespace::new(&small);
        assert!(matches!(res, Err(IdentifyError::PageTooSmall)));
    }

    #[test]
    fn identify_namespace_nsze_at_offset_zero_little_endian() {
        let mut page = zero_page();
        // NSZE = 0x0000_0000_1000_0000 (= 256 Mi sectors at 4 KiB =
        // 1 TiB namespace).
        let val: u64 = 0x0000_0000_1000_0000;
        page[..8].copy_from_slice(&val.to_le_bytes());
        let view = IdentifyNamespace::new(&page).unwrap();
        assert_eq!(view.nsze(), val);
    }

    #[test]
    fn identify_namespace_ncap_at_offset_eight() {
        let mut page = zero_page();
        let val: u64 = 0xCAFE_BABE_DEAD_BEEF;
        page[8..16].copy_from_slice(&val.to_le_bytes());
        let view = IdentifyNamespace::new(&page).unwrap();
        assert_eq!(view.ncap(), val);
    }

    #[test]
    fn identify_namespace_active_format_index_masks_low_4_bits() {
        let mut page = zero_page();
        // FLBAS = 0b1010_0011 → active format index = 0b0011 = 3.
        page[IdentifyNamespace::FLBAS_OFFSET] = 0b1010_0011;
        let view = IdentifyNamespace::new(&page).unwrap();
        assert_eq!(view.flbas(), 0b1010_0011);
        assert_eq!(view.active_format_index(), 3);
    }

    #[test]
    fn identify_namespace_lbads_reads_active_format_descriptor() {
        let mut page = zero_page();
        // Active format = 1 (FLBAS low nibble = 1).
        page[IdentifyNamespace::FLBAS_OFFSET] = 0x01;
        // LBAF1 lives at LBAF_BASE_OFFSET + 1 * 4 = 132. The
        // LBADS byte is at offset +2 inside the descriptor =
        // 132 + 2 = 134. LBADS = 12 (4 KiB sectors).
        let lbaf1_lbads_offset = IdentifyNamespace::LBAF_BASE_OFFSET + 4 + 2;
        page[lbaf1_lbads_offset] = 12;
        let view = IdentifyNamespace::new(&page).unwrap();
        assert_eq!(view.lbads(), 12);
    }

    #[test]
    fn identify_namespace_lbads_masks_high_3_bits() {
        let mut page = zero_page();
        page[IdentifyNamespace::FLBAS_OFFSET] = 0x00; // active = 0
        // LBAF0 LBADS byte at LBAF_BASE_OFFSET + 0 * 4 + 2 = 130.
        // Set high bits + LBADS = 12.
        page[130] = 0b1110_1100; // 0xEC = high bits 111 | LBADS 01100 = 12
        let view = IdentifyNamespace::new(&page).unwrap();
        assert_eq!(view.lbads(), 12, "high bits must be masked away");
    }

    #[test]
    fn identify_namespace_validated_byte_size_returns_size_when_lbads_12() {
        let mut page = zero_page();
        // NSZE = 1024 sectors.
        let nsze: u64 = 1024;
        page[..8].copy_from_slice(&nsze.to_le_bytes());
        // FLBAS = 0 → active format = 0.
        page[IdentifyNamespace::FLBAS_OFFSET] = 0;
        // LBAF0 LBADS = 12.
        page[IdentifyNamespace::LBAF_BASE_OFFSET + 2] = 12;
        let view = IdentifyNamespace::new(&page).unwrap();
        let size = view.validated_byte_size().expect("LBADS=12 accepted");
        // Expected: 1024 sectors * 4096 bytes/sector = 4 MiB =
        // 0x40_0000.
        assert_eq!(size, 1024 * 4096);
    }

    #[test]
    fn identify_namespace_validated_byte_size_rejects_lbads_9() {
        let mut page = zero_page();
        page[..8].copy_from_slice(&1024_u64.to_le_bytes());
        page[IdentifyNamespace::FLBAS_OFFSET] = 0;
        // LBAF0 LBADS = 9 (= 512-byte sectors, the legacy default).
        page[IdentifyNamespace::LBAF_BASE_OFFSET + 2] = 9;
        let view = IdentifyNamespace::new(&page).unwrap();
        assert_eq!(
            view.validated_byte_size(),
            Err(IdentifyError::UnsupportedLbads { observed: 9 })
        );
    }

    #[test]
    fn identify_namespace_validated_byte_size_rejects_lbads_zero_default_page() {
        // Empty page → LBADS = 0 → rejected.
        let page = zero_page();
        let view = IdentifyNamespace::new(&page).unwrap();
        assert_eq!(
            view.validated_byte_size(),
            Err(IdentifyError::UnsupportedLbads { observed: 0 })
        );
    }

    // -------------------------------------------------------------------
    // Error taxonomy
    // -------------------------------------------------------------------

    #[test]
    fn identify_error_variants_are_distinguishable() {
        let page_too_small = IdentifyError::PageTooSmall;
        let unsupported_9 = IdentifyError::UnsupportedLbads { observed: 9 };
        let unsupported_10 = IdentifyError::UnsupportedLbads { observed: 10 };
        assert_ne!(page_too_small, unsupported_9);
        assert_ne!(unsupported_9, unsupported_10);
        assert_eq!(
            unsupported_9,
            IdentifyError::UnsupportedLbads { observed: 9 }
        );
    }

    // -------------------------------------------------------------------
    // ActiveNsListView (P6.7.10-pre.26)
    // -------------------------------------------------------------------

    /// Write `nsids` followed by a zero terminator into the first
    /// `4 * (nsids.len() + 1)` bytes of a fresh 4 KiB page.
    fn page_with_nsids(nsids: &[u32]) -> alloc::vec::Vec<u8> {
        let mut page = zero_page();
        for (i, &nsid) in nsids.iter().enumerate() {
            let bytes = nsid.to_le_bytes();
            let off = i * 4;
            page[off..off + 4].copy_from_slice(&bytes);
        }
        // The zero terminator at index `nsids.len()` is implicit
        // (zero_page is all zeros).
        page
    }

    #[test]
    fn max_active_nsids_matches_spec() {
        // 4 KiB / 4 bytes per entry = 1024 NSIDs per response page
        // per NVMe 1.4 § 5.15.2 Figure 246.
        assert_eq!(MAX_ACTIVE_NSIDS, 1024);
    }

    #[test]
    fn active_ns_list_view_rejects_undersized_page() {
        let small = vec![0u8; IDENTIFY_RESPONSE_BYTES - 1];
        let res = ActiveNsListView::new(&small);
        assert!(matches!(res, Err(IdentifyError::PageTooSmall)));
    }

    #[test]
    fn active_ns_list_view_empty_list_yields_no_nsids() {
        let page = zero_page();
        let view = ActiveNsListView::new(&page).unwrap();
        assert_eq!(view.first_active_nsid(), None);
        assert_eq!(view.iter_nsids().count(), 0);
    }

    #[test]
    fn active_ns_list_view_single_entry_terminated_by_zero() {
        let page = page_with_nsids(&[1]);
        let view = ActiveNsListView::new(&page).unwrap();
        assert_eq!(view.first_active_nsid(), Some(1));
        let nsids: alloc::vec::Vec<u32> = view.iter_nsids().collect();
        assert_eq!(nsids, vec![1]);
    }

    #[test]
    fn active_ns_list_view_multiple_entries_in_order() {
        let page = page_with_nsids(&[1, 2, 3, 7, 42]);
        let view = ActiveNsListView::new(&page).unwrap();
        let nsids: alloc::vec::Vec<u32> = view.iter_nsids().collect();
        assert_eq!(nsids, vec![1, 2, 3, 7, 42]);
        assert_eq!(view.first_active_nsid(), Some(1));
    }

    #[test]
    fn active_ns_list_view_stops_at_first_zero_sentinel() {
        // [4, 5, 0, 99, 100] — the zero terminator stops iteration
        // BEFORE the 99 + 100 entries (which the controller MUST
        // NOT write per Figure 246, but defensive parsing is the
        // safer choice).
        let page = page_with_nsids(&[4, 5, 0, 99, 100]);
        let view = ActiveNsListView::new(&page).unwrap();
        let nsids: alloc::vec::Vec<u32> = view.iter_nsids().collect();
        assert_eq!(nsids, vec![4, 5]);
    }

    #[test]
    fn active_ns_list_view_full_page_no_terminator_yields_max_nsids() {
        // Fill all 1024 slots with non-zero values — the iterator
        // yields every entry and then stops at MAX_ACTIVE_NSIDS
        // without overflowing the page.
        let mut page = zero_page();
        for i in 0..MAX_ACTIVE_NSIDS {
            // `i` is bounded by `MAX_ACTIVE_NSIDS = 1024` which
            // fits trivially in `u32`; the `try_from` conversion
            // is infallible here.
            let nsid: u32 = u32::try_from(i).expect("MAX_ACTIVE_NSIDS fits u32") + 1;
            let off = i * 4;
            page[off..off + 4].copy_from_slice(&nsid.to_le_bytes());
        }
        let view = ActiveNsListView::new(&page).unwrap();
        let count = view.iter_nsids().count();
        assert_eq!(count, MAX_ACTIVE_NSIDS);
    }

    #[test]
    fn active_ns_list_view_first_active_nsid_skips_no_terminator_search() {
        // Sanity check: first_active_nsid returns the first NSID
        // without scanning past it.
        let page = page_with_nsids(&[7, 8, 9]);
        let view = ActiveNsListView::new(&page).unwrap();
        assert_eq!(view.first_active_nsid(), Some(7));
    }

    #[test]
    fn active_ns_list_view_first_nsid_is_one_per_ncip_014_default() {
        // NCIP-014 § S6 step 9: the Phase-1 driver picks the first
        // NSID returned (which the spec recommends be NSID=1 for
        // the canonical single-namespace controller).
        let page = page_with_nsids(&[1]);
        let view = ActiveNsListView::new(&page).unwrap();
        assert_eq!(view.first_active_nsid(), Some(1));
    }

    #[test]
    fn active_ns_list_iter_is_clonable_for_lookahead() {
        // ActiveNsListIter derives Clone so a future bring-up
        // implementation can peek at the first NSID then iterate
        // the full list without re-parsing the page.
        let page = page_with_nsids(&[10, 20, 30]);
        let view = ActiveNsListView::new(&page).unwrap();
        let mut iter1 = view.iter_nsids();
        let iter2 = iter1.clone();
        assert_eq!(iter1.next(), Some(10));
        // iter2 is independent — still yields 10 first.
        let collected: alloc::vec::Vec<u32> = iter2.collect();
        assert_eq!(collected, vec![10, 20, 30]);
    }
}
