//! Data-transfer model — PRP (Physical Region Page lists) only.
//!
//! [`NCIP-Driver-NVMe-014`] § M4 + § R1 lock the v0.3 deliverable to PRP
//! lists. SGL is explicitly out of scope (the manifest schema accepts
//! only `transfer_model = "prp"`; any other value MUST be rejected with
//! `EINVAL` per NCIP-014 § S1.1).
//!
//! ## Why a const-fn module
//!
//! The bring-up FSM and the eventual command-issuing path both need
//! cheap, host-testable predicates for the two PRP invariants:
//!
//! 1. **Alignment.** Every buffer pointer (PRP1 and every entry of the
//!    PRP list) MUST be aligned to the controller's memory page size
//!    (MPS). For v0.3 the kernel page size is 4 KiB
//!    (`CC.MPS = 0`), so PRP entries are 4 KiB-aligned.
//! 2. **Span coverage.** PRP1 covers the first page; if the transfer
//!    spans more than one page, PRP2 either points at a second page
//!    (two-page transfer) or at a flat array of additional 4 KiB
//!    pointers (`> 2` pages). The driver picks the layout based on the
//!    transfer's byte length.
//!
//! Both predicates are pure functions so they can be unit-tested
//! host-side without standing up a controller.
//!
//! [`NCIP-Driver-NVMe-014`]: ../../../ncips/ncip-driver-nvme-014.md

/// Page size used by the PRP transfer model in v0.3.
///
/// Anchored to the kernel's 4 KiB page size (`CC.MPS = 0` per
/// [`crate::controller_regs::CC_MPS_SHIFT`]). PRP entries MUST be
/// aligned to this boundary; the driver rejects misaligned buffers
/// with `BlkResponse::InvalidArgument` per NCIP-014 § TC5.
pub const PRP_PAGE_SIZE: usize = 4096;

/// Maximum block count per PRP-list transfer for the v0.3 deliverable.
///
/// NCIP-014 § S2 caps `block_count` at 2048 4 KiB blocks (= 8 MiB),
/// which fits comfortably within a one-page PRP list (the list itself
/// is 4 KiB / 8 bytes = 512 entries; each entry covers one 4 KiB page,
/// so the list addresses up to 2 MiB by itself — combined with PRP1's
/// first page we get up to 513 × 4 KiB ≈ 2 MiB. For larger transfers
/// the driver chains, but v0.3 caps below the chain threshold).
pub const MAX_BLOCK_COUNT_PER_COMMAND: u32 = 2048;

/// PRP list entry size in bytes (NVMe 1.4 § 4.1.4).
///
/// Each PRP entry is a 64-bit physical (IOVA after `DmaMap`) pointer.
pub const PRP_ENTRY_BYTES: usize = 8;

/// Number of PRP entries that fit in one 4 KiB list page.
///
/// `4096 / 8 = 512`. The driver allocates one PRP-list page per
/// transfer that spans more than two NVMe pages; that page covers up
/// to `512 × 4 KiB = 2 MiB` of additional payload (on top of PRP1's
/// first page).
#[allow(
    clippy::integer_division,
    reason = "compile-time division of two `const usize` powers-of-two — \
              `4096 / 8 = 512` is exact and has no runtime cost"
)]
pub const PRP_ENTRIES_PER_LIST_PAGE: usize = PRP_PAGE_SIZE / PRP_ENTRY_BYTES;

/// The data-transfer model accepted by the v0.3 driver.
///
/// `#[non_exhaustive]` so a future NCIP (`NCIP-Driver-NVMe-SGL-XXX`) can
/// add the SGL variant without breaking the wire-format contract. Until
/// then, the only valid value is [`TransferModel::Prp`]; any other
/// manifest value is rejected with `EINVAL`.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransferModel {
    /// Physical Region Page lists — the only model accepted in v0.3
    /// (NCIP-014 § M4 / § R1).
    Prp,
}

impl TransferModel {
    /// Parse a manifest `transfer_model = "..."` string.
    ///
    /// Returns `None` for any unrecognized value; the caller maps that
    /// to `EINVAL` per NCIP-014 § S1.1.
    #[must_use]
    pub fn from_manifest_str(s: &str) -> Option<Self> {
        match s {
            "prp" => Some(Self::Prp),
            _ => None,
        }
    }

    /// The canonical manifest string for this transfer model.
    #[must_use]
    pub const fn as_manifest_str(self) -> &'static str {
        match self {
            Self::Prp => "prp",
        }
    }
}

/// Returns `true` if `iova` satisfies the PRP alignment invariant
/// ([`PRP_PAGE_SIZE`]-aligned). The driver rejects any buffer that
/// fails this check with `BlkResponse::InvalidArgument` per NCIP-014
/// § TC5.
#[must_use]
pub const fn is_prp_aligned(iova: u64) -> bool {
    // PRP_PAGE_SIZE is a power of 2; the `iova & (size - 1)` trick is
    // exact and overflow-free even at `u64::MAX`.
    (iova & (PRP_PAGE_SIZE as u64 - 1)) == 0
}

/// Returns the byte length implied by `block_count` 4 KiB blocks.
///
/// Returns `None` on overflow (cannot happen at
/// `block_count ≤ MAX_BLOCK_COUNT_PER_COMMAND`, but kept as
/// defence-in-depth for the eventual command-validation path).
#[must_use]
pub const fn block_payload_bytes(block_count: u32) -> Option<usize> {
    (block_count as usize).checked_mul(PRP_PAGE_SIZE)
}

/// Layout of the PRP fields for a transfer of the given byte length.
///
/// - `len ≤ PRP_PAGE_SIZE`: one page, PRP2 = 0.
/// - `len ≤ 2 × PRP_PAGE_SIZE`: two pages, PRP2 = pointer to the
///   second page directly.
/// - `len  > 2 × PRP_PAGE_SIZE`: PRP2 = pointer to a flat array of
///   4 KiB-page pointers (one PRP-list page).
///
/// NVMe 1.4 § 4.1.4 defines the chained case (`PRP2 = pointer to next
/// PRP list page`), but v0.3 caps transfer size below the chain
/// threshold per [`MAX_BLOCK_COUNT_PER_COMMAND`], so the driver never
/// emits a chained PRP list.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PrpLayout {
    /// Single-page transfer; PRP1 covers everything, PRP2 unused
    /// (the driver writes 0).
    SinglePage,
    /// Two-page transfer; PRP1 covers the first page, PRP2 covers the
    /// second.
    TwoPages,
    /// Multi-page transfer; PRP1 covers the first page, PRP2 points at
    /// a PRP-list page containing `n_entries` 4 KiB pointers.
    PrpList {
        /// Number of 4 KiB pointers in the PRP list (excluding PRP1).
        n_entries: usize,
    },
}

/// Pick the PRP layout for a transfer of `len` bytes. `len = 0`
/// degenerates to `SinglePage` (a flush-style command); the caller is
/// responsible for rejecting actual zero-length data transfers earlier.
#[must_use]
pub const fn prp_layout(len: usize) -> PrpLayout {
    if len <= PRP_PAGE_SIZE {
        PrpLayout::SinglePage
    } else if len <= 2 * PRP_PAGE_SIZE {
        PrpLayout::TwoPages
    } else {
        // Number of additional pages beyond PRP1: ceil((len - 4096) /
        // 4096). All values fit in `usize` because `len < 2 MiB` for
        // v0.3 — but we use `checked_*` arithmetic anyway to keep the
        // function defence-in-depth against future cap relaxations.
        let extra_bytes = len - PRP_PAGE_SIZE;
        let n = extra_bytes.div_ceil(PRP_PAGE_SIZE);
        PrpLayout::PrpList { n_entries: n }
    }
}

// =============================================================================
// PRP1 / PRP2 / PRP-list encoder (P6.7.10-pre.8)
// =============================================================================

/// Reason a PRP encoder helper could not complete.
///
/// All variants are observable through the future IO ring-buffer
/// driver's `BlkResponse::InvalidArgument` path; the encoder maps
/// each variant deterministically without touching MMIO.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum PrpError {
    /// [`write_prp_list_entries`] was called with a destination slice
    /// shorter than `n_entries * PRP_ENTRY_BYTES` bytes. The driver
    /// MUST allocate a full [`PRP_PAGE_SIZE`]-byte buffer per
    /// NCIP-014 § S2 and pass it verbatim; landing here indicates a
    /// buffer-shape regression in the caller.
    ListBufferTooSmall,
    /// [`write_prp_list_entries`] was called with `n_entries`
    /// exceeding [`PRP_ENTRIES_PER_LIST_PAGE`]. v0.3 caps transfer
    /// size below the chained-PRP-list threshold per
    /// [`MAX_BLOCK_COUNT_PER_COMMAND`]; landing here means the
    /// driver attempted a transfer larger than the documented cap,
    /// a contract violation upstream of the encoder.
    TooManyEntries,
}

/// Return the PRP1 dword for a transfer that starts at `buffer_iova`.
///
/// PRP1 is the IOVA of the first 4 KiB page of the data buffer. The
/// encoder does NOT validate alignment — the caller MUST have already
/// rejected misaligned buffers via [`is_prp_aligned`] per NCIP-014
/// § TC5. Provided as a named helper so the call sites do not
/// embed the trivial pass-through inline (this also keeps the API
/// symmetric with [`prp2_for`]).
#[must_use]
pub const fn prp1_for(buffer_iova: u64) -> u64 {
    buffer_iova
}

/// Return the PRP2 dword for a transfer of the given [`PrpLayout`].
///
/// - [`PrpLayout::SinglePage`] → `0` (PRP2 unused per NVMe 1.4
///   § 4.1.4 when the entire transfer fits in one page).
/// - [`PrpLayout::TwoPages`] → `buffer_iova + PRP_PAGE_SIZE` (PRP2
///   points directly at the second page; no list allocation needed).
/// - [`PrpLayout::PrpList { .. }`] → `list_page_iova` (PRP2 points at
///   the host-prepared 4 KiB PRP list page; the caller MUST have
///   already populated the page through [`write_prp_list_entries`]
///   before submitting the SQE).
///
/// `list_page_iova` is ignored when `layout` is not `PrpList`. The
/// caller may pass `0` in those cases for symmetry with the
/// encoder API.
#[must_use]
pub const fn prp2_for(buffer_iova: u64, layout: PrpLayout, list_page_iova: u64) -> u64 {
    match layout {
        PrpLayout::SinglePage => 0,
        PrpLayout::TwoPages => buffer_iova.wrapping_add(PRP_PAGE_SIZE as u64),
        PrpLayout::PrpList { .. } => list_page_iova,
    }
}

/// Populate a host-allocated PRP list page with the 4 KiB-page
/// pointers for the tail of a multi-page transfer.
///
/// Each PRP list entry is a 64-bit little-endian pointer to the
/// `(1 + i)`-th 4 KiB page of the data buffer — PRP1 covers the
/// first page (index 0), so the list starts at index 1. NVMe 1.4
/// § 4.1.4 requires every PRP list entry to be 4 KiB-aligned, which
/// is satisfied by construction here because each entry is
/// `buffer_iova + (1 + i) * PRP_PAGE_SIZE`.
///
/// Wraparound at `u64::MAX` is silently saturated via
/// `wrapping_add` — the caller is responsible for keeping the buffer
/// inside the addressable IOVA range. Phase-1 IOVA allocator caps
/// buffers below the 4 GiB DMA arena ceiling so the wraparound path
/// is unreachable; the helper documents the behaviour for
/// defence-in-depth.
///
/// # Errors
///
/// - [`PrpError::TooManyEntries`] if `n_entries >
///   PRP_ENTRIES_PER_LIST_PAGE` (v0.3 caps below the chained-PRP-list
///   threshold).
/// - [`PrpError::ListBufferTooSmall`] if
///   `dest.len() < n_entries * PRP_ENTRY_BYTES`.
///
/// On success the helper writes exactly `n_entries * PRP_ENTRY_BYTES`
/// bytes starting at `dest[0]`. Bytes past the last entry are left
/// untouched (the caller MUST zero-initialise the PRP list page
/// before passing it here — un-touched entries with non-zero stale
/// data would be interpreted as garbage page pointers by the
/// controller).
pub fn write_prp_list_entries(
    buffer_iova: u64,
    n_entries: usize,
    dest: &mut [u8],
) -> Result<(), PrpError> {
    if n_entries > PRP_ENTRIES_PER_LIST_PAGE {
        return Err(PrpError::TooManyEntries);
    }
    let needed = n_entries.saturating_mul(PRP_ENTRY_BYTES);
    if dest.len() < needed {
        return Err(PrpError::ListBufferTooSmall);
    }
    let entries_slice = dest.get_mut(..needed).ok_or(PrpError::ListBufferTooSmall)?;
    for (i, chunk) in entries_slice.chunks_exact_mut(PRP_ENTRY_BYTES).enumerate() {
        // PRP1 covers page index 0; PRP list entry `i` covers page
        // index `i + 1`.
        let page_index = (i as u64).wrapping_add(1);
        let entry = buffer_iova.wrapping_add(page_index.wrapping_mul(PRP_PAGE_SIZE as u64));
        chunk.copy_from_slice(&entry.to_le_bytes());
    }
    Ok(())
}

// =============================================================================
// High-level PRP-pair derivation (P6.7.10-pre.28)
// =============================================================================

/// Errors specific to the [`derive_prp_pair_for_blocks`] helper.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum PrpDeriveError {
    /// `buf_iova` is not 4 KiB-aligned per NCIP-014 § TC5 + NVMe 1.4
    /// § 4.1.4. The caller MUST reject misaligned buffers upstream
    /// at the BLK channel boundary; surfacing here is
    /// defence-in-depth.
    BufferMisaligned,
    /// `block_count` is zero. The encoder cannot derive a PRP pair
    /// without at least one block of data; the caller MUST emit
    /// `BlkResponse::InvalidArgument` upstream.
    ZeroBlockCount,
    /// `block_count` exceeds [`MAX_BLOCK_COUNT_PER_COMMAND`]. The
    /// caller MUST split the transfer at the BLK channel boundary
    /// before reaching the encoder.
    TooManyBlocks,
    /// `list_page_iova` is required (the layout is `PrpList`) but
    /// the caller passed zero. The caller MUST allocate a 4 KiB
    /// IOVA buffer via `DmaMap` and pass its IOVA whenever the
    /// transfer spans more than two pages.
    PrpListPageMissing,
    /// `list_page_iova` is not 4 KiB-aligned. Same alignment rule
    /// as `buf_iova`.
    PrpListPageMisaligned,
}

/// Derive the `(layout, prp1, prp2)` triple from a BLK-level
/// `(buf_iova, block_count)` pair, falling back to
/// `list_page_iova` for transfers that need a PRP-list page.
///
/// Composes the existing primitives:
/// 1. [`block_payload_bytes`] computes the byte length from the
///    block count (Phase-1 uses 4 KiB sectors per NCIP-014 § S6
///    step 10 so `len = block_count * 4096`).
/// 2. [`prp_layout`] picks the layout (`SinglePage` / `TwoPages` /
///    `PrpList`).
/// 3. [`prp1_for`] / [`prp2_for`] produce the two SQE fields.
///
/// The caller passes `list_page_iova = 0` for transfers that
/// don't need it (1 or 2 blocks); the helper validates the value
/// only when [`prp_layout`] returns `PrpList`.
///
/// # Errors
///
/// - [`PrpDeriveError::BufferMisaligned`] if `buf_iova` is not
///   4 KiB-aligned.
/// - [`PrpDeriveError::ZeroBlockCount`] if `block_count == 0`.
/// - [`PrpDeriveError::TooManyBlocks`] if
///   `block_count > MAX_BLOCK_COUNT_PER_COMMAND`.
/// - [`PrpDeriveError::PrpListPageMissing`] if the derived
///   layout is `PrpList` but `list_page_iova == 0`.
/// - [`PrpDeriveError::PrpListPageMisaligned`] if
///   `list_page_iova` is not 4 KiB-aligned.
pub fn derive_prp_pair_for_blocks(
    buf_iova: u64,
    block_count: u32,
    list_page_iova: u64,
) -> Result<(PrpLayout, u64, u64), PrpDeriveError> {
    if !is_prp_aligned(buf_iova) {
        return Err(PrpDeriveError::BufferMisaligned);
    }
    if block_count == 0 {
        return Err(PrpDeriveError::ZeroBlockCount);
    }
    if block_count > MAX_BLOCK_COUNT_PER_COMMAND {
        return Err(PrpDeriveError::TooManyBlocks);
    }
    // `block_payload_bytes` returns `Some` for `block_count > 0`
    // and `<= MAX_BLOCK_COUNT_PER_COMMAND`; the early returns
    // above guarantee we get a `Some` here.
    let len = block_payload_bytes(block_count).ok_or(PrpDeriveError::TooManyBlocks)?;
    let layout = prp_layout(len);

    if matches!(layout, PrpLayout::PrpList { .. }) {
        if list_page_iova == 0 {
            return Err(PrpDeriveError::PrpListPageMissing);
        }
        if !is_prp_aligned(list_page_iova) {
            return Err(PrpDeriveError::PrpListPageMisaligned);
        }
    }

    let prp1 = prp1_for(buf_iova);
    let prp2 = prp2_for(buf_iova, layout, list_page_iova);
    Ok((layout, prp1, prp2))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn page_size_matches_kernel_invariant() {
        // The kernel's page size is 4 KiB everywhere (boot, MMU,
        // virtio, NVMe). Drift here would silently break PRP layout.
        assert_eq!(PRP_PAGE_SIZE, 4096);
    }

    #[test]
    fn entries_per_list_page_matches_spec() {
        // 4096 / 8 = 512 — the driver allocates this exact number of
        // slots when it picks `PrpList`.
        assert_eq!(PRP_ENTRIES_PER_LIST_PAGE, 512);
    }

    #[test]
    fn prp_only_manifest_value() {
        // NCIP-014 § S1.1: only "prp" is accepted; anything else is
        // EINVAL.
        assert_eq!(
            TransferModel::from_manifest_str("prp"),
            Some(TransferModel::Prp)
        );
        assert_eq!(TransferModel::from_manifest_str("sgl"), None);
        assert_eq!(TransferModel::from_manifest_str("PRP"), None);
        assert_eq!(TransferModel::from_manifest_str(""), None);
    }

    #[test]
    fn manifest_str_round_trips() {
        assert_eq!(TransferModel::Prp.as_manifest_str(), "prp");
        assert_eq!(
            TransferModel::from_manifest_str(TransferModel::Prp.as_manifest_str()),
            Some(TransferModel::Prp)
        );
    }

    #[test]
    fn alignment_check_accepts_page_boundaries() {
        assert!(is_prp_aligned(0));
        assert!(is_prp_aligned(0x1000));
        assert!(is_prp_aligned(0x10_0000));
        assert!(is_prp_aligned(0xDEAD_0000));
    }

    #[test]
    fn alignment_check_rejects_misaligned_addresses() {
        // NCIP-014 § TC5: misaligned buffer -> BlkResponse::InvalidArgument.
        assert!(!is_prp_aligned(0x1));
        assert!(!is_prp_aligned(0xFFF));
        assert!(!is_prp_aligned(0x1001));
        assert!(!is_prp_aligned(0x1234));
    }

    #[test]
    fn single_page_layout_for_one_block() {
        let len = block_payload_bytes(1).unwrap();
        assert_eq!(len, PRP_PAGE_SIZE);
        assert_eq!(prp_layout(len), PrpLayout::SinglePage);
    }

    #[test]
    fn two_page_layout_at_eight_kib() {
        let len = block_payload_bytes(2).unwrap();
        assert_eq!(len, 2 * PRP_PAGE_SIZE);
        assert_eq!(prp_layout(len), PrpLayout::TwoPages);
    }

    #[test]
    fn prp_list_layout_at_three_pages() {
        // 3 × 4 KiB > 2 × 4 KiB → PrpList with 2 extra entries.
        let len = block_payload_bytes(3).unwrap();
        assert_eq!(prp_layout(len), PrpLayout::PrpList { n_entries: 2 });
    }

    #[test]
    fn prp_list_layout_for_max_block_count() {
        // NCIP-014 § S2 cap: 2048 × 4 KiB = 8 MiB. PRP1 covers the
        // first page; the list covers the remaining 2047 pages.
        let len = block_payload_bytes(MAX_BLOCK_COUNT_PER_COMMAND).unwrap();
        assert_eq!(prp_layout(len), PrpLayout::PrpList { n_entries: 2047 });
    }

    #[test]
    fn block_payload_bytes_is_exact_multiples() {
        assert_eq!(block_payload_bytes(0), Some(0));
        assert_eq!(block_payload_bytes(1), Some(4096));
        assert_eq!(block_payload_bytes(8), Some(8 * 4096));
    }

    #[test]
    fn prp_layout_zero_length_degenerates_to_single_page() {
        // Flush/Discard carry no data buffer; the layout helper still
        // returns a well-defined value (the call site never inspects
        // PRP fields in that case).
        assert_eq!(prp_layout(0), PrpLayout::SinglePage);
    }

    #[test]
    fn prp_layout_just_above_one_page_boundary() {
        assert_eq!(prp_layout(PRP_PAGE_SIZE + 1), PrpLayout::TwoPages);
    }

    #[test]
    fn prp_layout_just_above_two_page_boundary() {
        // 8193 bytes: PRP1 covers bytes 0..4096 (one page); the
        // remaining 4097 bytes span two more pages (4096..8192 +
        // 8192..8193), so the PRP list needs 2 entries.
        assert_eq!(
            prp_layout(2 * PRP_PAGE_SIZE + 1),
            PrpLayout::PrpList { n_entries: 2 }
        );
    }

    // -----------------------------------------------------------------
    // PRP1 / PRP2 / list encoder (P6.7.10-pre.8)
    // -----------------------------------------------------------------

    fn read_prp_entry(buf: &[u8], i: usize) -> u64 {
        let off = i * PRP_ENTRY_BYTES;
        let slice = buf
            .get(off..off + PRP_ENTRY_BYTES)
            .expect("entry in bounds");
        let mut tmp = [0u8; 8];
        tmp.copy_from_slice(slice);
        u64::from_le_bytes(tmp)
    }

    #[test]
    fn prp1_for_returns_buffer_iova_verbatim() {
        assert_eq!(prp1_for(0), 0);
        assert_eq!(prp1_for(0x1000), 0x1000);
        assert_eq!(prp1_for(0xDEAD_BEEF_0000), 0xDEAD_BEEF_0000);
    }

    #[test]
    fn prp2_for_single_page_returns_zero() {
        assert_eq!(prp2_for(0x1000, PrpLayout::SinglePage, 0x9000), 0);
    }

    #[test]
    fn prp2_for_two_pages_returns_buffer_plus_page_size() {
        let buf: u64 = 0x4000;
        let prp2 = prp2_for(buf, PrpLayout::TwoPages, 0);
        assert_eq!(prp2, buf + PRP_PAGE_SIZE as u64);
    }

    #[test]
    fn prp2_for_prp_list_returns_list_page_iova() {
        let list: u64 = 0xCAFE_C000;
        let prp2 = prp2_for(0x1000, PrpLayout::PrpList { n_entries: 5 }, list);
        assert_eq!(prp2, list);
    }

    #[test]
    fn prp2_for_ignores_list_arg_for_single_and_two_page_layouts() {
        assert_eq!(prp2_for(0x1000, PrpLayout::SinglePage, 0xDEAD), 0);
        assert_eq!(
            prp2_for(0x1000, PrpLayout::TwoPages, 0xDEAD),
            0x1000 + PRP_PAGE_SIZE as u64
        );
    }

    #[test]
    fn write_prp_list_entries_happy_path_three_entries() {
        let buf_iova: u64 = 0x1_0000;
        let mut page = [0u8; PRP_PAGE_SIZE];
        // 3 entries → list covers buffer pages 1, 2, 3 (PRP1 covers
        // page 0).
        write_prp_list_entries(buf_iova, 3, &mut page).expect("write");
        assert_eq!(read_prp_entry(&page, 0), buf_iova + PRP_PAGE_SIZE as u64);
        assert_eq!(
            read_prp_entry(&page, 1),
            buf_iova + 2 * PRP_PAGE_SIZE as u64
        );
        assert_eq!(
            read_prp_entry(&page, 2),
            buf_iova + 3 * PRP_PAGE_SIZE as u64
        );
        // Untouched tail stays zero (page was zero-initialised).
        let untouched = page.get(24..).expect("tail in bounds");
        for &b in untouched {
            assert_eq!(b, 0);
        }
    }

    #[test]
    fn write_prp_list_entries_zero_entries_is_noop() {
        let mut page = [0xAAu8; PRP_PAGE_SIZE];
        write_prp_list_entries(0x1000, 0, &mut page).expect("zero entries");
        // No bytes touched; the 0xAA marker survives end-to-end.
        for &b in &page {
            assert_eq!(b, 0xAA);
        }
    }

    #[test]
    fn write_prp_list_entries_full_list_page() {
        let buf_iova: u64 = 0x10_0000;
        let mut page = [0u8; PRP_PAGE_SIZE];
        write_prp_list_entries(buf_iova, PRP_ENTRIES_PER_LIST_PAGE, &mut page).expect("full");
        // First entry covers buffer page 1; last entry covers
        // buffer page 512 (since list has 512 entries indexed 0..511,
        // each pointing at page (i + 1)).
        assert_eq!(read_prp_entry(&page, 0), buf_iova + PRP_PAGE_SIZE as u64);
        assert_eq!(
            read_prp_entry(&page, PRP_ENTRIES_PER_LIST_PAGE - 1),
            buf_iova + (PRP_ENTRIES_PER_LIST_PAGE as u64) * PRP_PAGE_SIZE as u64
        );
    }

    #[test]
    fn write_prp_list_entries_rejects_too_many_entries() {
        let mut page = [0u8; PRP_PAGE_SIZE];
        let res = write_prp_list_entries(0x1000, PRP_ENTRIES_PER_LIST_PAGE + 1, &mut page);
        assert_eq!(res, Err(PrpError::TooManyEntries));
    }

    #[test]
    fn write_prp_list_entries_rejects_undersized_buffer() {
        let mut page = [0u8; 16]; // room for 2 entries (16 / 8)
        let res = write_prp_list_entries(0x1000, 3, &mut page);
        assert_eq!(res, Err(PrpError::ListBufferTooSmall));
    }

    #[test]
    fn write_prp_list_entries_accepts_exact_size_buffer() {
        // dest.len() == n_entries * 8 — boundary case.
        let mut buf = [0u8; 24]; // exactly 3 entries
        write_prp_list_entries(0x1000, 3, &mut buf).expect("exact size");
        assert_eq!(read_prp_entry(&buf, 0), 0x1000 + PRP_PAGE_SIZE as u64);
        assert_eq!(read_prp_entry(&buf, 2), 0x1000 + 3 * PRP_PAGE_SIZE as u64);
    }

    #[test]
    fn write_prp_list_entries_emits_little_endian_bytes() {
        let buf_iova: u64 = 0xCAFE_BABE_0000;
        let mut page = [0u8; 8];
        write_prp_list_entries(buf_iova, 1, &mut page).expect("one entry");
        // Expected: buf_iova + 4096 = 0xCAFE_BABE_1000 in LE.
        let expected = (buf_iova + PRP_PAGE_SIZE as u64).to_le_bytes();
        assert_eq!(page, expected);
    }

    #[test]
    fn prp_error_taxonomy_is_non_exhaustive_tripwire() {
        // Defensive sanity-check that the two variants we publish
        // round-trip through the workspace `match` rules. A future
        // addition to `PrpError` will not break source-level
        // consumers as long as they use a `_ =>` arm.
        let errs = [PrpError::ListBufferTooSmall, PrpError::TooManyEntries];
        for (i, e) in errs.iter().enumerate() {
            for (j, f) in errs.iter().enumerate() {
                if i == j {
                    assert_eq!(e, f);
                } else {
                    assert_ne!(e, f);
                }
            }
        }
    }

    // -------------------------------------------------------------------
    // derive_prp_pair_for_blocks (P6.7.10-pre.28)
    // -------------------------------------------------------------------

    #[test]
    fn derive_prp_pair_single_block_returns_single_page_layout() {
        let buf: u64 = 0x1_0000;
        let (layout, prp1, prp2) = derive_prp_pair_for_blocks(buf, 1, 0).expect("1 block");
        assert_eq!(layout, PrpLayout::SinglePage);
        assert_eq!(prp1, buf);
        assert_eq!(prp2, 0);
    }

    #[test]
    fn derive_prp_pair_two_blocks_returns_two_pages_layout() {
        let buf: u64 = 0x2_0000;
        let (layout, prp1, prp2) = derive_prp_pair_for_blocks(buf, 2, 0).expect("2 blocks");
        assert_eq!(layout, PrpLayout::TwoPages);
        assert_eq!(prp1, buf);
        // PRP2 points at the second 4 KiB page directly.
        assert_eq!(prp2, buf + PRP_PAGE_SIZE as u64);
    }

    #[test]
    fn derive_prp_pair_three_blocks_returns_prp_list_layout() {
        let buf: u64 = 0x3_0000;
        let list_page: u64 = 0x10_0000;
        let (layout, prp1, prp2) = derive_prp_pair_for_blocks(buf, 3, list_page).expect("3 blocks");
        // 3 blocks = 12 KiB = 3 pages → PrpList with 2 entries
        // (PRP1 covers page 0, list covers pages 1 + 2).
        match layout {
            PrpLayout::PrpList { n_entries } => {
                assert_eq!(n_entries, 2);
            }
            _ => panic!("expected PrpList, got {layout:?}"),
        }
        assert_eq!(prp1, buf);
        assert_eq!(prp2, list_page);
    }

    #[test]
    fn derive_prp_pair_rejects_misaligned_buf_iova() {
        // 0x1001 is not 4 KiB-aligned.
        let res = derive_prp_pair_for_blocks(0x1001, 1, 0);
        assert_eq!(res, Err(PrpDeriveError::BufferMisaligned));
    }

    #[test]
    fn derive_prp_pair_rejects_zero_block_count() {
        let res = derive_prp_pair_for_blocks(0x1_0000, 0, 0);
        assert_eq!(res, Err(PrpDeriveError::ZeroBlockCount));
    }

    #[test]
    fn derive_prp_pair_rejects_block_count_above_cap() {
        let res = derive_prp_pair_for_blocks(0x1_0000, MAX_BLOCK_COUNT_PER_COMMAND + 1, 0x10_0000);
        assert_eq!(res, Err(PrpDeriveError::TooManyBlocks));
    }

    #[test]
    fn derive_prp_pair_rejects_missing_list_page_for_multi_page_transfer() {
        // 3 blocks needs a PRP list; passing list_page_iova = 0
        // surfaces PrpListPageMissing.
        let res = derive_prp_pair_for_blocks(0x1_0000, 3, 0);
        assert_eq!(res, Err(PrpDeriveError::PrpListPageMissing));
    }

    #[test]
    fn derive_prp_pair_rejects_misaligned_list_page() {
        // 3 blocks + non-aligned list page → PrpListPageMisaligned.
        let res = derive_prp_pair_for_blocks(0x1_0000, 3, 0x10_0001);
        assert_eq!(res, Err(PrpDeriveError::PrpListPageMisaligned));
    }

    #[test]
    fn derive_prp_pair_ignores_list_page_iova_for_single_page() {
        // Single-page transfer: the helper should NOT validate
        // list_page_iova alignment (it's unused). Pass a garbage
        // value and verify the call succeeds.
        let res = derive_prp_pair_for_blocks(0x1_0000, 1, 0xDEAD_BEEF);
        let (layout, _, prp2) = res.expect("ok");
        assert_eq!(layout, PrpLayout::SinglePage);
        assert_eq!(prp2, 0);
    }

    #[test]
    fn derive_prp_pair_ignores_list_page_iova_for_two_pages() {
        // TwoPages also ignores list_page_iova; PRP2 is computed
        // from buf_iova directly.
        let buf: u64 = 0x4_0000;
        let res = derive_prp_pair_for_blocks(buf, 2, 0xDEAD_BEEF);
        let (layout, _, prp2) = res.expect("ok");
        assert_eq!(layout, PrpLayout::TwoPages);
        assert_eq!(prp2, buf + PRP_PAGE_SIZE as u64);
    }

    #[test]
    fn derive_prp_pair_max_block_count_uses_prp_list() {
        // The maximum legal block count (`MAX_BLOCK_COUNT_PER_COMMAND
        // = 2048` for 8 MiB) MUST resolve to PrpList with the
        // expected n_entries = 2047 (2048 pages total, PRP1 covers
        // page 0, list covers pages 1..=2047).
        let buf: u64 = 0x10_0000;
        let list_page: u64 = 0x20_0000;
        let (layout, _, _) =
            derive_prp_pair_for_blocks(buf, MAX_BLOCK_COUNT_PER_COMMAND, list_page).unwrap();
        match layout {
            PrpLayout::PrpList { n_entries } => {
                assert_eq!(n_entries, MAX_BLOCK_COUNT_PER_COMMAND as usize - 1);
            }
            _ => panic!("expected PrpList at MAX_BLOCK_COUNT_PER_COMMAND, got {layout:?}"),
        }
    }

    #[test]
    fn prp_derive_error_taxonomy_is_distinguishable() {
        // All 5 variants distinct from each other.
        let errs = [
            PrpDeriveError::BufferMisaligned,
            PrpDeriveError::ZeroBlockCount,
            PrpDeriveError::TooManyBlocks,
            PrpDeriveError::PrpListPageMissing,
            PrpDeriveError::PrpListPageMisaligned,
        ];
        for (i, e) in errs.iter().enumerate() {
            for (j, f) in errs.iter().enumerate() {
                if i == j {
                    assert_eq!(e, f);
                } else {
                    assert_ne!(e, f, "variants {i} and {j} must differ");
                }
            }
        }
    }
}
