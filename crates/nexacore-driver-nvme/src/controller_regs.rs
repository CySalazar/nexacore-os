//! NVMe Controller Register offsets and field accessors.
//!
//! Pinned by [`NCIP-Driver-NVMe-014`] § S6 step 2 and step 5/6. The driver
//! maps the controller's MMIO BAR0 via [`NCIP-Driver-Framework-013`] § S2
//! `MmioMap` and reads/writes 32-bit registers at the offsets defined by
//! NVMe 1.4 base spec § 3.1 ("Controller Registers"). Each constant
//! anchors one field; layout drift between the spec, the manifest
//! template, and the bring-up FSM is caught by the unit tests below.
//!
//! ## Address-space contract
//!
//! All offsets are byte-relative to the base of BAR0 (mapped as
//! uncached / write-coalescing inhibited per NCIP-013 § S2.5). The
//! controller register region MUST be at least
//! [`CONTROLLER_REGISTER_REGION_BYTES`] bytes — i.e., one full page
//! whose top half hosts the doorbell array. Larger regions are allowed
//! (NVMe 1.4 § 3.1 reserves up to a 16 KiB capability mailbox); v0.3
//! only touches the documented 32-bit fields below.
//!
//! [`NCIP-Driver-Framework-013`]: ../../../ncips/ncip-driver-framework-013.md
//! [`NCIP-Driver-NVMe-014`]: ../../../ncips/ncip-driver-nvme-014.md

/// Size of the NVMe controller register region the driver requests via
/// `MmioMap`.
///
/// The NCIP-014 § S1 manifest template advertises a 16 KiB MMIO window
/// (`len = "0x4000"`); NVMe 1.4 § 3.1 defines the architected register
/// fields within the first 4 KiB and reserves the upper portion for the
/// doorbell array (one 4-byte SQ/CQ pair per queue).
pub const CONTROLLER_REGISTER_REGION_BYTES: usize = 0x4000;

/// `CAP` — Controller Capabilities (64-bit). NVMe 1.4 § 3.1.1, offset `0x00`.
///
/// The driver reads this register before any other operation to extract
/// `MQES` (max queue entries supported), `DSTRD` (doorbell stride),
/// supported command sets, and `MPSMIN`/`MPSMAX` (memory page size
/// bounds).
pub const CAP_OFFSET: usize = 0x00;

/// `VS` — Version (32-bit). NVMe 1.4 § 3.1.2, offset `0x08`.
///
/// Encodes `{u16 major, u8 minor, u8 tertiary}` reversed. The driver
/// MUST verify the controller advertises NVMe 1.0 or newer (the wire
/// format pinned by NCIP-014).
pub const VS_OFFSET: usize = 0x08;

/// `INTMS` — Interrupt Mask Set (32-bit, RW1S). NVMe 1.4 § 3.1.3, offset
/// `0x0C`. Used only when falling back to single shared IOAPIC line per
/// NCIP-014 § S5.1; with MSI-X the field is reserved.
pub const INTMS_OFFSET: usize = 0x0C;

/// `INTMC` — Interrupt Mask Clear (32-bit, RW1C). NVMe 1.4 § 3.1.4,
/// offset `0x10`.
pub const INTMC_OFFSET: usize = 0x10;

/// `CC` — Controller Configuration (32-bit). NVMe 1.4 § 3.1.5, offset
/// `0x14`. Bit 0 = `EN` (enable); writing it through the disable/enable
/// transitions of NCIP-014 § S6 steps 4 and 6.
pub const CC_OFFSET: usize = 0x14;

/// `CSTS` — Controller Status (32-bit). NVMe 1.4 § 3.1.6, offset `0x1C`.
///
/// Bit 0 = `RDY` (the controller acknowledges the enable/disable
/// transition); bit 1 = `CFS` (Controller Fatal Status). The driver
/// polls `RDY` to confirm steps 4 and 6 of the bring-up sequence.
pub const CSTS_OFFSET: usize = 0x1C;

/// `AQA` — Admin Queue Attributes (32-bit). NVMe 1.4 § 3.1.8, offset `0x24`.
///
/// Lower 12 bits = `ASQS` (Admin SQ Size) - 1, upper 12 bits (16-27) =
/// `ACQS` (Admin CQ Size) - 1. The driver programs the
/// manifest-declared depths here at step 5 of NCIP-014 § S6.
pub const AQA_OFFSET: usize = 0x24;

/// `ASQ` — Admin Submission Queue Base Address (64-bit). NVMe 1.4
/// § 3.1.9, offset `0x28`. Physical (IOVA after `DmaMap`) address of the
/// Admin Submission Queue.
pub const ASQ_OFFSET: usize = 0x28;

/// `ACQ` — Admin Completion Queue Base Address (64-bit). NVMe 1.4
/// § 3.1.10, offset `0x30`. Physical (IOVA after `DmaMap`) address of
/// the Admin Completion Queue.
pub const ACQ_OFFSET: usize = 0x30;

/// `CMBLOC` — Controller Memory Buffer Location (32-bit, optional). NVMe 1.4 § 3.1.11, offset `0x38`.
///
/// CMB is not used by the v0.3 driver; the constant is defined for
/// completeness so that future CMB-enabled NCIPs can reference it
/// without re-deriving the offset.
pub const CMBLOC_OFFSET: usize = 0x38;

/// `CMBSZ` — Controller Memory Buffer Size (32-bit, optional). NVMe 1.4
/// § 3.1.12, offset `0x3C`.
pub const CMBSZ_OFFSET: usize = 0x3C;

/// Start of the doorbell array (32-bit each). NVMe 1.4 § 3.1.21.
///
/// The array origin is `0x1000`; for queue `i`, the SQ tail doorbell
/// lives at `DOORBELL_ARRAY_OFFSET + (2*i) * (4 << CAP.DSTRD)` and the
/// CQ head doorbell at `+ (2*i+1) * (4 << CAP.DSTRD)`. For `DSTRD = 0`
/// (typical), entries are 4 bytes apart.
pub const DOORBELL_ARRAY_OFFSET: usize = 0x1000;

// =============================================================================
// CC (Controller Configuration) field encodings — NVMe 1.4 § 3.1.5
// =============================================================================

/// `CC.EN` — bit 0. Setting it to 1 enables the controller; clearing
/// to 0 transitions to the disabled state (poll `CSTS.RDY` to 0).
pub const CC_EN_BIT: u32 = 1 << 0;

/// `CC.CSS` field shift (bits 6:4). `0b000` = NVM command set (the only
/// command set v0.3 supports).
pub const CC_CSS_SHIFT: u32 = 4;

/// `CC.MPS` field shift (bits 10:7). Encodes
/// `host page size = 2^(12 + MPS)` bytes. Value `0` = 4 KiB pages
/// (matches the kernel's `PAGE_SIZE`).
pub const CC_MPS_SHIFT: u32 = 7;

/// `CC.AMS` field shift (bits 13:11). `0b000` = round-robin arbitration
/// (default; v0.3 does not implement weighted RR or vendor-specific).
pub const CC_AMS_SHIFT: u32 = 11;

/// `CC.SHN` field shift (bits 15:14). Shutdown notification; not used
/// during normal boot (only at clean shutdown — out of scope for v0.3).
pub const CC_SHN_SHIFT: u32 = 14;

/// `CC.IOSQES` field shift (bits 19:16). NVMe 1.4 fixes the IO
/// Submission Queue Entry Size at 64 bytes (`2^6`), so the driver
/// programs `IOSQES = 6` at step 6 of NCIP-014 § S6.
pub const CC_IOSQES_SHIFT: u32 = 16;

/// `CC.IOCQES` field shift (bits 23:20). IO Completion Queue Entry Size
/// is 16 bytes (`2^4`), so the driver programs `IOCQES = 4`.
pub const CC_IOCQES_SHIFT: u32 = 20;

/// NVMe 1.4 fixed value for `CC.IOSQES` — submission queue entries are
/// `2^6 = 64` bytes per NVMe 1.4 § 4.2 (Common Submission Queue Entry).
pub const CC_IOSQES_VALUE: u32 = 6;

/// NVMe 1.4 fixed value for `CC.IOCQES` — completion queue entries are
/// `2^4 = 16` bytes per NVMe 1.4 § 4.6 (Common Completion Queue Entry).
pub const CC_IOCQES_VALUE: u32 = 4;

/// Compose the `CC` value the driver writes at step 6 of NCIP-014 § S6
/// (enable, NVM command set, 4 KiB pages, round-robin, IOSQES=6,
/// IOCQES=4).
#[must_use]
pub const fn cc_enable_value() -> u32 {
    CC_EN_BIT | (CC_IOSQES_VALUE << CC_IOSQES_SHIFT) | (CC_IOCQES_VALUE << CC_IOCQES_SHIFT)
    // CSS = 0, MPS = 0, AMS = 0, SHN = 0 — explicit OR-with-zero omitted.
}

// =============================================================================
// CSTS (Controller Status) field encodings — NVMe 1.4 § 3.1.6
// =============================================================================

/// `CSTS.RDY` — bit 0. The controller is ready to accept commands when
/// the bit reads `1`, and has fully transitioned to disabled when the
/// bit reads `0`.
pub const CSTS_RDY_BIT: u32 = 1 << 0;

/// `CSTS.CFS` — bit 1. Controller Fatal Status; the driver MUST emit
/// `ControllerFatal` (NCIP-014 § S3) and exit when this bit is set.
pub const CSTS_CFS_BIT: u32 = 1 << 1;

/// Compute the byte offset of queue `qid`'s submission-queue tail
/// doorbell, given the doorbell stride encoded in `CAP.DSTRD` (the
/// `dstrd` argument here, already extracted by the caller).
///
/// Returns `None` if the offset arithmetic would overflow `usize`
/// (defence-in-depth — at `dstrd ≤ 15` and `qid ≤ 65535` the result is
/// always representable, but the saturating check costs nothing).
#[must_use]
pub const fn sq_tail_doorbell_offset(qid: u16, dstrd: u8) -> Option<usize> {
    let Some(stride) = 4usize.checked_shl(dstrd as u32) else {
        return None;
    };
    let Some(index) = (qid as usize).checked_mul(2) else {
        return None;
    };
    let Some(off) = index.checked_mul(stride) else {
        return None;
    };
    off.checked_add(DOORBELL_ARRAY_OFFSET)
}

/// Compute the byte offset of queue `qid`'s completion-queue head
/// doorbell. See [`sq_tail_doorbell_offset`] for overflow semantics.
#[must_use]
pub const fn cq_head_doorbell_offset(qid: u16, dstrd: u8) -> Option<usize> {
    let Some(stride) = 4usize.checked_shl(dstrd as u32) else {
        return None;
    };
    let Some(pair_index) = (qid as usize).checked_mul(2) else {
        return None;
    };
    let Some(cq_index) = pair_index.checked_add(1) else {
        return None;
    };
    let Some(off) = cq_index.checked_mul(stride) else {
        return None;
    };
    off.checked_add(DOORBELL_ARRAY_OFFSET)
}

// =============================================================================
// CAP (Controller Capabilities) field extractors — NVMe 1.4 § 3.1.1
// =============================================================================

/// Extract `CAP.MQES` (Maximum Queue Entries Supported, bits 15:0).
///
/// The value is **zero-based**: `MQES = 0` means the controller
/// supports a minimum of 2 entries (one producer + one consumer).
/// NexaCore OS Phase-1 interprets `MQES + 1` as the maximum queue depth
/// the controller can handle.
#[must_use]
pub const fn cap_mqes(cap: u64) -> u16 {
    (cap & 0xFFFF) as u16
}

/// Extract `CAP.CQR` (Contiguous Queues Required, bit 16).
///
/// When `true` the controller requires physically contiguous queue
/// pages. Phase-1 always passes `physically_contiguous = true` in
/// `Create IO CQ/SQ` per NCIP-014 § R2.
#[must_use]
pub const fn cap_cqr(cap: u64) -> bool {
    (cap >> 16) & 1 != 0
}

/// Extract `CAP.DSTRD` (Doorbell Stride, bits 35:32).
///
/// The doorbell stride is `4 << DSTRD` bytes. Phase-1 hard-codes
/// `DSTRD = 0` (4-byte stride); any controller reporting a non-zero
/// value must be rejected until the driver is extended.
#[must_use]
pub const fn cap_dstrd(cap: u64) -> u8 {
    ((cap >> 32) & 0x0F) as u8
}

/// Extract `CAP.MPSMIN` (Memory Page Size Minimum, bits 51:48).
///
/// The minimum host page size the controller supports is
/// `2^(12 + MPSMIN)` bytes. Phase-1 requires `MPSMIN <= 0` (i.e.
/// the controller must support 4 KiB pages).
#[must_use]
pub const fn cap_mpsmin(cap: u64) -> u8 {
    ((cap >> 48) & 0x0F) as u8
}

/// Extract `CAP.MPSMAX` (Memory Page Size Maximum, bits 55:52).
///
/// The maximum host page size the controller supports is
/// `2^(12 + MPSMAX)` bytes. Phase-1 does not constrain this.
#[must_use]
pub const fn cap_mpsmax(cap: u64) -> u8 {
    ((cap >> 52) & 0x0F) as u8
}

// =============================================================================
// VS (Version) field extractors — NVMe 1.4 § 3.1.2
// =============================================================================

/// Extract the major version from the 32-bit VS register value.
///
/// NVMe 1.4 § 3.1.2: bits 31:16 encode the major version. A
/// compliant NVMe 1.0+ controller MUST report `major >= 1`.
#[must_use]
pub const fn vs_major(vs: u32) -> u16 {
    (vs >> 16) as u16
}

/// Extract the minor version from the 32-bit VS register value.
///
/// NVMe 1.4 § 3.1.2: bits 15:8 encode the minor version.
#[must_use]
pub const fn vs_minor(vs: u32) -> u8 {
    ((vs >> 8) & 0xFF) as u8
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn architected_offsets_match_nvme_1_4() {
        // NVMe 1.4 base spec § 3.1 figure: pin every architected field
        // by byte offset so a future "tidy up the register module" PR
        // cannot silently drift the layout.
        assert_eq!(CAP_OFFSET, 0x00);
        assert_eq!(VS_OFFSET, 0x08);
        assert_eq!(INTMS_OFFSET, 0x0C);
        assert_eq!(INTMC_OFFSET, 0x10);
        assert_eq!(CC_OFFSET, 0x14);
        assert_eq!(CSTS_OFFSET, 0x1C);
        assert_eq!(AQA_OFFSET, 0x24);
        assert_eq!(ASQ_OFFSET, 0x28);
        assert_eq!(ACQ_OFFSET, 0x30);
        assert_eq!(CMBLOC_OFFSET, 0x38);
        assert_eq!(CMBSZ_OFFSET, 0x3C);
        assert_eq!(DOORBELL_ARRAY_OFFSET, 0x1000);
    }

    // The two layout invariants below compare crate-level `const usize`
    // values, so clippy correctly notes that an `assert!()` would fold to
    // `assert!(true)` at compile time. They're expressed as
    // `const _: () = assert!(...)` at module scope instead — same
    // compile-time guarantee, zero runtime cost.

    /// The architected register block tops out at `CMBSZ + 4 = 0x40`
    /// (rounded up to the documented 0x1000 doorbell boundary). The
    /// driver MUST NOT trip into the reserved gap, so the start of the
    /// doorbell array is strictly greater than the last architected
    /// field.
    const _DOORBELL_ABOVE_ARCHITECTED: () = assert!(DOORBELL_ARRAY_OFFSET > CMBSZ_OFFSET + 4);

    /// The 16 KiB region MUST host at least one queue pair's doorbells.
    /// The first queue pair lives at `0x1000` (SQ) and `0x1004` (CQ).
    const _REGION_COVERS_DOORBELLS: () =
        assert!(CONTROLLER_REGISTER_REGION_BYTES > DOORBELL_ARRAY_OFFSET + 8);

    #[test]
    fn cc_field_encodings_match_spec() {
        assert_eq!(CC_EN_BIT, 0x01);
        assert_eq!(CC_CSS_SHIFT, 4);
        assert_eq!(CC_MPS_SHIFT, 7);
        assert_eq!(CC_AMS_SHIFT, 11);
        assert_eq!(CC_SHN_SHIFT, 14);
        assert_eq!(CC_IOSQES_SHIFT, 16);
        assert_eq!(CC_IOCQES_SHIFT, 20);
    }

    #[test]
    fn cc_entry_sizes_match_nvme_1_4_fixed_values() {
        // NVMe 1.4 § 4.2 / § 4.6 fix SQE = 64 B (2^6) and CQE = 16 B (2^4).
        assert_eq!(CC_IOSQES_VALUE, 6);
        assert_eq!(CC_IOCQES_VALUE, 4);
    }

    #[test]
    fn cc_enable_value_encodes_required_fields() {
        // EN=1, IOSQES=6 << 16, IOCQES=4 << 20.
        let expected = 0x0001 | (6 << 16) | (4 << 20);
        assert_eq!(cc_enable_value(), expected);
    }

    #[test]
    fn csts_bit_encodings_match_spec() {
        assert_eq!(CSTS_RDY_BIT, 0x01);
        assert_eq!(CSTS_CFS_BIT, 0x02);
    }

    // -------------------------------------------------------------------
    // CAP field extractors (P6.7.10-pre.41)
    // -------------------------------------------------------------------

    #[test]
    fn cap_mqes_extracts_bits_15_0() {
        // MQES = 0x00FF → controller supports up to 256 entries.
        let cap: u64 = 0x00FF;
        assert_eq!(cap_mqes(cap), 0x00FF);
        // Full 16-bit range.
        let cap_max: u64 = 0xFFFF;
        assert_eq!(cap_mqes(cap_max), 0xFFFF);
    }

    #[test]
    fn cap_cqr_extracts_bit_16() {
        let cap_cqr_set: u64 = 1 << 16;
        assert!(cap_cqr(cap_cqr_set));
        let cap_cqr_clear: u64 = 0;
        assert!(!cap_cqr(cap_cqr_clear));
    }

    #[test]
    fn cap_dstrd_extracts_bits_35_32() {
        // DSTRD = 0 → 4-byte stride (most common).
        let cap_dstrd_0: u64 = 0;
        assert_eq!(cap_dstrd(cap_dstrd_0), 0);
        // DSTRD = 3 → 32-byte stride.
        let cap_dstrd_3: u64 = 3_u64 << 32;
        assert_eq!(cap_dstrd(cap_dstrd_3), 3);
        // DSTRD = 15 → max 4-bit field.
        let cap_dstrd_15: u64 = 0x0F_u64 << 32;
        assert_eq!(cap_dstrd(cap_dstrd_15), 15);
    }

    #[test]
    fn cap_mpsmin_extracts_bits_51_48() {
        // MPSMIN = 0 → minimum page size 2^12 = 4 KiB.
        assert_eq!(cap_mpsmin(0), 0);
        // MPSMIN = 1 → minimum page size 2^13 = 8 KiB.
        let cap_mpsmin_1: u64 = 1_u64 << 48;
        assert_eq!(cap_mpsmin(cap_mpsmin_1), 1);
    }

    #[test]
    fn cap_mpsmax_extracts_bits_55_52() {
        // MPSMAX = 0 → max page size 4 KiB (degenerate single-size).
        assert_eq!(cap_mpsmax(0), 0);
        // MPSMAX = 5 → max page size 2^17 = 128 KiB.
        let cap_mpsmax_5: u64 = 5_u64 << 52;
        assert_eq!(cap_mpsmax(cap_mpsmax_5), 5);
    }

    // -------------------------------------------------------------------
    // VS field extractors (P6.7.10-pre.41)
    // -------------------------------------------------------------------

    #[test]
    fn vs_major_extracts_bits_31_16() {
        // NVMe 1.4 reports VS = 0x0001_0400.
        let vs_1_4: u32 = 0x0001_0400;
        assert_eq!(vs_major(vs_1_4), 1);
        // NVMe 2.0 reports VS = 0x0002_0000.
        let vs_2_0: u32 = 0x0002_0000;
        assert_eq!(vs_major(vs_2_0), 2);
    }

    #[test]
    fn vs_minor_extracts_bits_15_8() {
        let vs_1_4: u32 = 0x0001_0400;
        assert_eq!(vs_minor(vs_1_4), 4);
        let vs_1_0: u32 = 0x0001_0000;
        assert_eq!(vs_minor(vs_1_0), 0);
    }

    #[test]
    fn cap_fields_independent_of_each_other() {
        // Composite CAP: MQES=0x003F, CQR=1, DSTRD=2, MPSMIN=0, MPSMAX=4.
        let cap: u64 = 0x003F | (1 << 16) | (2_u64 << 32) | (4_u64 << 52);
        assert_eq!(cap_mqes(cap), 0x003F);
        assert!(cap_cqr(cap));
        assert_eq!(cap_dstrd(cap), 2);
        assert_eq!(cap_mpsmin(cap), 0);
        assert_eq!(cap_mpsmax(cap), 4);
    }

    #[test]
    fn sq_tail_doorbell_offset_for_qid_0_dstrd_0() {
        // Admin queue (qid=0) SQ tail doorbell at the array origin.
        assert_eq!(sq_tail_doorbell_offset(0, 0), Some(0x1000));
    }

    #[test]
    fn cq_head_doorbell_offset_for_qid_0_dstrd_0() {
        // Admin queue (qid=0) CQ head doorbell 4 bytes past the SQ tail.
        assert_eq!(cq_head_doorbell_offset(0, 0), Some(0x1004));
    }

    #[test]
    fn doorbell_offsets_advance_per_queue_pair() {
        // Queue 1 (first IO queue) SQ tail at 0x1008, CQ head at 0x100C
        // (stride 4 bytes, two doorbells per queue pair).
        assert_eq!(sq_tail_doorbell_offset(1, 0), Some(0x1008));
        assert_eq!(cq_head_doorbell_offset(1, 0), Some(0x100C));
    }

    #[test]
    fn doorbell_offsets_respect_dstrd() {
        // DSTRD=1 doubles the stride: SQ tail at 0x1000, CQ head at
        // 0x1008, queue 1 SQ tail at 0x1010.
        assert_eq!(sq_tail_doorbell_offset(0, 1), Some(0x1000));
        assert_eq!(cq_head_doorbell_offset(0, 1), Some(0x1008));
        assert_eq!(sq_tail_doorbell_offset(1, 1), Some(0x1010));
    }
}
