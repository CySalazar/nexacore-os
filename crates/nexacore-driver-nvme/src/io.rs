//! NVMe IO Submission Queue Entry encoders.
//!
//! Pinned by NVMe 1.4 base spec § 6 ("NVM Command Set") and re-uses
//! the 64-byte SQE layout pinned in [`crate::admin`] (§ 4.2 applies to
//! both Admin and IO queues — only the opcode and `CDWx` semantics
//! differ). This module is the auditable byte-layout source-of-truth
//! for the four IO operations NexaCore OS Phase 1 surfaces on
//! `nexacore.svc.blk.<diskN>`:
//!
//! - `0x02 NVM Read`           → [`encode_read`]    (§ 6.9)
//! - `0x01 NVM Write`          → [`encode_write`]   (§ 6.15)
//! - `0x00 NVM Flush`          → [`encode_flush`]   (§ 6.8)
//! - `0x09 Dataset Management` → [`encode_discard`] (§ 6.7, Attribute = Deallocate)
//!
//! The encoders mirror the strict separation of concerns the admin
//! module already follows: pure functions over a plain `[u8; 64]`
//! buffer with little-endian dword writes, no MMIO, no allocation, no
//! validation of IOMMU mappings. The live IO-queue driver (a future
//! sub-slice) wraps these encoders with doorbell ring-buffer
//! bookkeeping and reuses [`crate::admin::parse_admin_cqe`] to drain
//! the matching IO CQ ring (the CQE byte layout is shared too).
//!
//! ## Why share `AdminSqe` instead of a parallel `IoSqe` newtype
//!
//! NVMe 1.4 § 4.2 fixes the SQE size at 64 bytes for every queue in
//! the controller (Admin queue, every IO queue) — Submission Queue
//! Entry sizes are programmed through `CC.IOSQES` / `CC.IOCQES` but
//! the spec mandates the same 64-byte / 16-byte sizes NexaCore OS uses.
//! A second newtype would double the surface area without buying
//! type-safety: the queue identifier the driver writes through the
//! doorbell pair is what distinguishes Admin from IO traffic, not the
//! SQE type. [`crate::admin::AdminSqe`] is therefore re-used here as
//! the canonical 64-byte submission entry across both queue families.

use crate::admin::AdminSqe;

// =============================================================================
// IO opcodes (NVMe 1.4 § 6)
// =============================================================================

/// `NVM Flush` opcode per NVMe 1.4 § 6.8.
///
/// Commits the volatile write cache for the specified namespace to
/// persistent media. Phase-1 driver issues exactly one outstanding
/// flush per BLK `Flush` request.
pub const OPC_NVM_FLUSH: u8 = 0x00;

/// `NVM Write` opcode per NVMe 1.4 § 6.15.
///
/// Writes `NLB + 1` consecutive 4 KiB blocks starting at the supplied
/// LBA from the PRP-pointed buffer (`NLB` is 0-based per spec —
/// 0 means "1 block"; NexaCore OS encodes `block_count - 1` so user-space
/// callers see a 1-based count).
pub const OPC_NVM_WRITE: u8 = 0x01;

/// `NVM Read` opcode per NVMe 1.4 § 6.9.
///
/// Reads `NLB + 1` consecutive 4 KiB blocks into the PRP-pointed
/// buffer; same `NLB` zero-based semantics as
/// [`OPC_NVM_WRITE`].
pub const OPC_NVM_READ: u8 = 0x02;

/// `NVM Dataset Management` opcode per NVMe 1.4 § 6.7.
///
/// Used by NexaCore OS to surface BLK `Discard` (TRIM equivalent) — the
/// driver sets the `Attribute = Deallocate` bit in CDW11 and points
/// CDW10 at a 16-byte "Dataset Management Range" descriptor in the
/// PRP1 buffer that names the LBA range to deallocate.
pub const OPC_NVM_DATASET_MGMT: u8 = 0x09;

// =============================================================================
// CDW11 bits for Dataset Management (NVMe 1.4 § 6.7)
// =============================================================================

/// CDW11 bit 2 — `AD` (Attribute Deallocate) per NVMe 1.4 § 6.7.
///
/// Set by [`encode_discard`] so the controller treats the supplied
/// LBA range as "freed" and may stop tracking it for read-back. The
/// Phase-1 driver does not set the `IDW` (Integral Dataset for Write)
/// or `IDR` (Read) hints — those are valid optimizations but require
/// the namespace to advertise support, which Phase-1 does not probe.
pub const DSM_AD_BIT: u32 = 1 << 2;

/// CDW10 dword value for a single-range dataset-management command.
///
/// Bits 7:0 of CDW10 hold the `NR` (Number of Ranges) field — 0-based
/// per NVMe 1.4 § 6.7 (`NR = 0` means "1 range"). Phase-1 always sends
/// one range, so this is `0`. Provided as a named constant so the
/// encoder sites do not embed the magic literal inline.
pub const DSM_CDW10_NR_SINGLE_RANGE: u32 = 0;

// =============================================================================
// IO command encoders
// =============================================================================

/// Encode an NVM Read into a fresh [`AdminSqe`].
///
/// Field layout per NVMe 1.4 § 6.9 (which inherits the § 4.2 SQE
/// frame):
///
/// | Bytes | Field | Source |
/// |---|---|---|
/// | 0     | OPC = 0x02           | [`OPC_NVM_READ`] |
/// | 1     | FUSE\|PSDT = 0       | not fused, PRP transfer |
/// | 2..=3 | CID                  | `cid` |
/// | 4..=7 | NSID                 | `nsid` |
/// | 8..=23 | Reserved + MPTR     | zero |
/// | 24..=31 | DPTR.PRP1          | `prp1` |
/// | 32..=39 | DPTR.PRP2          | `prp2` |
/// | 40..=43 | CDW10 = SLBA\[31:0\] | low half of `lba` |
/// | 44..=47 | CDW11 = SLBA\[63:32\] | high half of `lba` |
/// | 48..=51 | CDW12 = NLB (0-based) | `block_count - 1` |
/// | 52..=63 | CDW13..15 = 0       | zero |
///
/// `block_count` MUST be in `1..=`[`crate::transfer_model::MAX_BLOCK_COUNT_PER_COMMAND`];
/// the encoder does not enforce the upper bound because it is also
/// exercised in host tests with synthetic values. The bring-up FSM
/// validates the bound at the BLK layer per
/// `NCIP-Driver-NVMe-014` § S2.2 before calling the encoder.
#[must_use]
pub fn encode_read(
    nsid: u32,
    lba: u64,
    block_count: u32,
    prp1: u64,
    prp2: u64,
    cid: u16,
) -> AdminSqe {
    encode_nvm_data_transfer(OPC_NVM_READ, nsid, lba, block_count, prp1, prp2, cid)
}

/// Encode an NVM Write into a fresh [`AdminSqe`].
///
/// Identical field layout to [`encode_read`] modulo `OPC = 0x01`
/// (NVM Write per NVMe 1.4 § 6.15). Same `NLB` zero-based encoding,
/// same PRP semantics.
#[must_use]
pub fn encode_write(
    nsid: u32,
    lba: u64,
    block_count: u32,
    prp1: u64,
    prp2: u64,
    cid: u16,
) -> AdminSqe {
    encode_nvm_data_transfer(OPC_NVM_WRITE, nsid, lba, block_count, prp1, prp2, cid)
}

/// Encode an NVM Flush into a fresh [`AdminSqe`].
///
/// Field layout per NVMe 1.4 § 6.8:
///
/// | Bytes | Field | Source |
/// |---|---|---|
/// | 0     | OPC = 0x00 | [`OPC_NVM_FLUSH`] |
/// | 2..=3 | CID        | `cid` |
/// | 4..=7 | NSID       | `nsid` |
/// | other | zero       | zero |
///
/// Flush carries no PRPs and no `CDWx` data; the controller commits the
/// volatile write cache for the named namespace (or every namespace
/// when `NSID = 0xFFFF_FFFF`, but NexaCore OS Phase-1 always passes a
/// concrete `nsid`).
#[must_use]
pub fn encode_flush(nsid: u32, cid: u16) -> AdminSqe {
    let mut sqe = AdminSqe::zeroed();
    let buf = sqe.as_bytes_mut();
    let cdw0: u32 = u32::from(OPC_NVM_FLUSH) | (u32::from(cid) << 16);
    write_le_u32(buf, 0, cdw0);
    write_le_u32(buf, 4, nsid);
    sqe
}

/// Encode an NVM Dataset Management (Deallocate) into a fresh
/// [`AdminSqe`] — the wire-level form NexaCore OS uses for BLK
/// `Discard{lba, count}` per `NCIP-Driver-NVMe-014` § S4.
///
/// Field layout per NVMe 1.4 § 6.7:
///
/// | Bytes | Field | Source |
/// |---|---|---|
/// | 0     | OPC = 0x09             | [`OPC_NVM_DATASET_MGMT`] |
/// | 2..=3 | CID                    | `cid` |
/// | 4..=7 | NSID                   | `nsid` |
/// | 24..=31 | DPTR.PRP1            | host-supplied 16-byte Range Descriptor IOVA |
/// | 32..=39 | DPTR.PRP2            | zero (one range fits in PRP1) |
/// | 40..=43 | CDW10 = NR (0-based) | [`DSM_CDW10_NR_SINGLE_RANGE`] |
/// | 44..=47 | CDW11 = `AD`         | [`DSM_AD_BIT`] (bit 2) |
/// | other | zero                   | zero |
///
/// `lba` + `block_count` describe the range to deallocate; the
/// Phase-1 driver fills the corresponding 16-byte "Dataset Management
/// Range" descriptor at the PRP1 buffer and points the encoder at it.
/// The encoder records `lba` + `block_count` in CDW12 + CDW13 as a
/// debugging tripwire so a host-side test can verify the encoder
/// receives the right inputs without intercepting the PRP1 buffer
/// content; the controller itself ignores these dwords for the
/// Dataset Management opcode (per § 6.7 they are reserved).
///
/// `prp1` MUST point to a host-prepared 16-byte Range Descriptor
/// buffer in IOVA space; passing `0` is a contract violation. The
/// encoder packs the value verbatim; the IOMMU enforces access at
/// translation time.
#[must_use]
pub fn encode_discard(nsid: u32, lba: u64, block_count: u32, prp1: u64, cid: u16) -> AdminSqe {
    let mut sqe = AdminSqe::zeroed();
    let buf = sqe.as_bytes_mut();

    let cdw0: u32 = u32::from(OPC_NVM_DATASET_MGMT) | (u32::from(cid) << 16);
    write_le_u32(buf, 0, cdw0);
    write_le_u32(buf, 4, nsid);

    // DPTR.PRP1 at bytes 24..=31; PRP2 stays zero (single 16-byte
    // range descriptor fits in PRP1).
    write_le_u64(buf, 24, prp1);
    // PRP2 already zero by AdminSqe::zeroed().

    // CDW10 = NR (Number of Ranges, 0-based). Phase-1 always sends
    // one range so NR = 0.
    write_le_u32(buf, 40, DSM_CDW10_NR_SINGLE_RANGE);

    // CDW11 = AD (bit 2). IDW/IDR optional hints stay 0.
    write_le_u32(buf, 44, DSM_AD_BIT);

    // CDW12 + CDW13 = encoder-side tripwires (see fn-doc). The
    // controller treats these as reserved for the DSM opcode per
    // NVMe 1.4 § 6.7 so writing them is safe; readers MUST NOT
    // assume the controller observes the values.
    write_le_u32(buf, 48, (lba & 0xFFFF_FFFF) as u32);
    write_le_u32(buf, 52, ((lba >> 32) & 0xFFFF_FFFF) as u32);
    write_le_u32(buf, 56, block_count);

    sqe
}

/// Shared encoder for NVM Read and NVM Write — the two commands have
/// identical SQE layouts modulo their opcode. Factored here so a
/// future regression in either path surfaces with a single edit
/// site.
fn encode_nvm_data_transfer(
    opc: u8,
    nsid: u32,
    lba: u64,
    block_count: u32,
    prp1: u64,
    prp2: u64,
    cid: u16,
) -> AdminSqe {
    let mut sqe = AdminSqe::zeroed();
    let buf = sqe.as_bytes_mut();

    let cdw0: u32 = u32::from(opc) | (u32::from(cid) << 16);
    write_le_u32(buf, 0, cdw0);
    write_le_u32(buf, 4, nsid);

    // DPTR.PRP1 at bytes 24..=31, DPTR.PRP2 at bytes 32..=39.
    write_le_u64(buf, 24, prp1);
    write_le_u64(buf, 32, prp2);

    // CDW10 = SLBA bits 31:0, CDW11 = SLBA bits 63:32.
    write_le_u32(buf, 40, (lba & 0xFFFF_FFFF) as u32);
    write_le_u32(buf, 44, ((lba >> 32) & 0xFFFF_FFFF) as u32);

    // CDW12 = NLB (Number of Logical Blocks, 0-based) in bits 15:0.
    // The driver presents `block_count` as 1-based; subtract one
    // here. `block_count == 0` is illegal per NCIP-014 § S2.2 and the
    // FSM rejects it before reaching the encoder; we saturate at 0
    // here so the encoder is total over all `u32` inputs (the
    // saturation is invisible in production because the FSM filters
    // upstream).
    let nlb_zero_based: u32 = block_count.saturating_sub(1);
    write_le_u32(buf, 48, nlb_zero_based);

    sqe
}

// =============================================================================
// Internal byte helpers (duplicated from `crate::admin` to keep this
// module self-contained — re-exporting through `crate::admin` would
// blur the auditable boundary between Admin and IO encoders).
// =============================================================================

#[inline]
fn write_le_u32(buf: &mut [u8], off: usize, val: u32) {
    let bytes = val.to_le_bytes();
    for (i, byte) in bytes.iter().enumerate() {
        if let Some(slot) = buf.get_mut(off + i) {
            *slot = *byte;
        }
    }
}

#[inline]
fn write_le_u64(buf: &mut [u8], off: usize, val: u64) {
    let bytes = val.to_le_bytes();
    for (i, byte) in bytes.iter().enumerate() {
        if let Some(slot) = buf.get_mut(off + i) {
            *slot = *byte;
        }
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::admin::ADMIN_SQE_BYTES;

    fn read_le_u32(buf: &[u8], off: usize) -> u32 {
        let slice = buf.get(off..off + 4).expect("range in bounds");
        let mut tmp = [0u8; 4];
        tmp.copy_from_slice(slice);
        u32::from_le_bytes(tmp)
    }

    fn read_le_u64(buf: &[u8], off: usize) -> u64 {
        let slice = buf.get(off..off + 8).expect("range in bounds");
        let mut tmp = [0u8; 8];
        tmp.copy_from_slice(slice);
        u64::from_le_bytes(tmp)
    }

    // -------------------------------------------------------------------
    // Opcode constants
    // -------------------------------------------------------------------

    #[test]
    fn opcodes_match_nvme_spec() {
        assert_eq!(OPC_NVM_FLUSH, 0x00);
        assert_eq!(OPC_NVM_WRITE, 0x01);
        assert_eq!(OPC_NVM_READ, 0x02);
        assert_eq!(OPC_NVM_DATASET_MGMT, 0x09);
    }

    #[test]
    fn dsm_ad_bit_is_bit_2() {
        assert_eq!(DSM_AD_BIT, 0b100);
    }

    #[test]
    fn dsm_single_range_is_zero() {
        assert_eq!(DSM_CDW10_NR_SINGLE_RANGE, 0);
    }

    // -------------------------------------------------------------------
    // encode_read field-layout pinning
    // -------------------------------------------------------------------

    #[test]
    fn encode_read_writes_opcode() {
        let sqe = encode_read(1, 0, 1, 0x1000, 0, 0xABCD);
        assert_eq!(sqe.as_bytes().first().copied().expect("opc"), OPC_NVM_READ);
    }

    #[test]
    fn encode_read_writes_cid_le() {
        let sqe = encode_read(1, 0, 1, 0x1000, 0, 0xABCD);
        let cid = sqe.as_bytes().get(2..4).expect("cid");
        assert_eq!(cid, &[0xCD, 0xAB]);
    }

    #[test]
    fn encode_read_writes_nsid_le() {
        let sqe = encode_read(0xDEAD_BEEF, 0, 1, 0x1000, 0, 1);
        let nsid_bytes = sqe.as_bytes().get(4..8).expect("nsid");
        assert_eq!(nsid_bytes, &[0xEF, 0xBE, 0xAD, 0xDE]);
    }

    #[test]
    fn encode_read_writes_prp1_and_prp2() {
        let prp1: u64 = 0xCAFE_BABE_DEAD_BEEF;
        let prp2: u64 = 0x1111_2222_3333_4444;
        let sqe = encode_read(1, 0, 8, prp1, prp2, 1);
        assert_eq!(read_le_u64(sqe.as_bytes(), 24), prp1);
        assert_eq!(read_le_u64(sqe.as_bytes(), 32), prp2);
    }

    #[test]
    fn encode_read_writes_lba_split_across_cdw10_cdw11() {
        let lba: u64 = 0x1234_5678_9ABC_DEF0;
        let sqe = encode_read(1, lba, 1, 0x1000, 0, 1);
        assert_eq!(read_le_u32(sqe.as_bytes(), 40), 0x9ABC_DEF0);
        assert_eq!(read_le_u32(sqe.as_bytes(), 44), 0x1234_5678);
    }

    #[test]
    fn encode_read_writes_nlb_zero_based() {
        // block_count = 1 ⇒ NLB = 0 (one block).
        let sqe1 = encode_read(1, 0, 1, 0x1000, 0, 1);
        assert_eq!(read_le_u32(sqe1.as_bytes(), 48), 0);
        // block_count = 8 ⇒ NLB = 7.
        let sqe8 = encode_read(1, 0, 8, 0x1000, 0, 1);
        assert_eq!(read_le_u32(sqe8.as_bytes(), 48), 7);
        // block_count = 2048 (max) ⇒ NLB = 2047.
        let sqe_max = encode_read(1, 0, 2048, 0x1000, 0, 1);
        assert_eq!(read_le_u32(sqe_max.as_bytes(), 48), 2047);
    }

    #[test]
    fn encode_read_saturating_sub_keeps_zero_on_zero_input() {
        // Contract: the FSM rejects `block_count == 0` upstream;
        // the encoder is total over all inputs so we pin the
        // saturation behaviour explicitly. NLB = 0 ≠ "send 0
        // blocks" — it means "send 1 block" per spec. The
        // saturation therefore degenerates to a 1-block transfer
        // rather than a wraparound to `u32::MAX`.
        let sqe = encode_read(1, 0, 0, 0x1000, 0, 1);
        assert_eq!(read_le_u32(sqe.as_bytes(), 48), 0);
    }

    #[test]
    fn encode_read_cdw13_to_15_are_zero() {
        let sqe = encode_read(1, 0, 1, 0x1000, 0, 1);
        let trailing = sqe.as_bytes().get(52..64).expect("cdw13..15 range");
        assert_eq!(trailing, &[0u8; 12]);
    }

    // -------------------------------------------------------------------
    // encode_write — same layout, different opcode
    // -------------------------------------------------------------------

    #[test]
    fn encode_write_writes_opcode_01() {
        let sqe = encode_write(1, 0, 1, 0x1000, 0, 1);
        assert_eq!(sqe.as_bytes().first().copied().expect("opc"), OPC_NVM_WRITE);
    }

    #[test]
    fn encode_write_field_layout_matches_encode_read_modulo_opcode() {
        // Tripwire: Read and Write SHARE everything but the opcode
        // byte. Encoding the same args with both and XOR-comparing
        // proves a future regression in either path surfaces here.
        let r = encode_read(7, 0x1_0000, 4, 0x2000, 0, 0x42);
        let w = encode_write(7, 0x1_0000, 4, 0x2000, 0, 0x42);
        // Byte 0 differs (opcode).
        assert_ne!(
            r.as_bytes().first().copied().expect("opc r"),
            w.as_bytes().first().copied().expect("opc w")
        );
        // Every other byte matches.
        let r_bytes = r.as_bytes();
        let w_bytes = w.as_bytes();
        for i in 1..ADMIN_SQE_BYTES {
            assert_eq!(
                r_bytes.get(i).copied(),
                w_bytes.get(i).copied(),
                "byte {i} differs between Read and Write"
            );
        }
    }

    // -------------------------------------------------------------------
    // encode_flush — minimal, no PRPs, no CDWx
    // -------------------------------------------------------------------

    #[test]
    fn encode_flush_writes_opcode_and_nsid_only() {
        let sqe = encode_flush(0xDEAD_BEEF, 0xCAFE);
        assert_eq!(sqe.as_bytes().first().copied().expect("opc"), OPC_NVM_FLUSH);
        // CID at bytes 2..=3.
        let cid = sqe.as_bytes().get(2..4).expect("cid range");
        assert_eq!(cid, &[0xFE, 0xCA]);
        // NSID at bytes 4..=7.
        assert_eq!(read_le_u32(sqe.as_bytes(), 4), 0xDEAD_BEEF);
    }

    #[test]
    fn encode_flush_prps_and_cdw_remain_zero() {
        let sqe = encode_flush(1, 0xABCD);
        // PRP1 + PRP2 zero.
        for off in [24usize, 32] {
            let qw = read_le_u64(sqe.as_bytes(), off);
            assert_eq!(qw, 0, "qword at {off} must be zero");
        }
        // CDW10..15 all zero.
        let cdw = sqe.as_bytes().get(40..64).expect("cdw10..15 range");
        assert_eq!(cdw, &[0u8; 24]);
    }

    // -------------------------------------------------------------------
    // encode_discard — Dataset Management Deallocate
    // -------------------------------------------------------------------

    #[test]
    fn encode_discard_writes_opcode_09() {
        let sqe = encode_discard(1, 0, 1, 0x1000, 1);
        assert_eq!(
            sqe.as_bytes().first().copied().expect("opc"),
            OPC_NVM_DATASET_MGMT
        );
    }

    #[test]
    fn encode_discard_writes_prp1_and_keeps_prp2_zero() {
        let prp1: u64 = 0xCAFE_BABE_DEAD_BEEF;
        let sqe = encode_discard(1, 0, 1, prp1, 1);
        assert_eq!(read_le_u64(sqe.as_bytes(), 24), prp1);
        assert_eq!(read_le_u64(sqe.as_bytes(), 32), 0);
    }

    #[test]
    fn encode_discard_writes_cdw10_nr_zero_and_cdw11_ad_bit() {
        let sqe = encode_discard(1, 0, 1, 0x1000, 1);
        assert_eq!(read_le_u32(sqe.as_bytes(), 40), DSM_CDW10_NR_SINGLE_RANGE);
        assert_eq!(read_le_u32(sqe.as_bytes(), 44), DSM_AD_BIT);
    }

    #[test]
    fn encode_discard_writes_lba_and_block_count_tripwires() {
        // The encoder records LBA + block_count in CDW12..13 as a
        // tripwire; the controller treats these as reserved for the
        // DSM opcode (NVMe 1.4 § 6.7).
        let lba: u64 = 0x1234_5678_9ABC_DEF0;
        let block_count: u32 = 256;
        let sqe = encode_discard(1, lba, block_count, 0x1000, 1);
        // CDW12 = LBA[31:0].
        assert_eq!(read_le_u32(sqe.as_bytes(), 48), 0x9ABC_DEF0);
        // CDW13 = LBA[63:32].
        assert_eq!(read_le_u32(sqe.as_bytes(), 52), 0x1234_5678);
        // CDW14 = block_count (1-based).
        assert_eq!(read_le_u32(sqe.as_bytes(), 56), 256);
        // CDW15 = 0.
        assert_eq!(read_le_u32(sqe.as_bytes(), 60), 0);
    }

    // -------------------------------------------------------------------
    // Cross-encoder invariants
    // -------------------------------------------------------------------

    #[test]
    fn every_encoder_produces_64_byte_sqe() {
        // Tripwire: AdminSqe is statically `[u8; 64]`; any change
        // here is an ABI break the admin module's sibling tripwire
        // catches first, but pinning it on the IO side too keeps
        // the contract observable from this module.
        let r = encode_read(1, 0, 1, 0x1000, 0, 1);
        let w = encode_write(1, 0, 1, 0x1000, 0, 1);
        let f = encode_flush(1, 1);
        let d = encode_discard(1, 0, 1, 0x1000, 1);
        assert_eq!(r.as_bytes().len(), ADMIN_SQE_BYTES);
        assert_eq!(w.as_bytes().len(), ADMIN_SQE_BYTES);
        assert_eq!(f.as_bytes().len(), ADMIN_SQE_BYTES);
        assert_eq!(d.as_bytes().len(), ADMIN_SQE_BYTES);
    }

    #[test]
    fn distinct_opcodes_produce_distinct_byte_zero() {
        // Tripwire: regression that aliases two opcodes would
        // silently route Read traffic to Flush (or worse). Verify
        // pairwise byte-zero distinctness across the four IO
        // encoders.
        let read_op = encode_read(1, 0, 1, 0x1000, 0, 1)
            .as_bytes()
            .first()
            .copied()
            .expect("read opc");
        let write_op = encode_write(1, 0, 1, 0x1000, 0, 1)
            .as_bytes()
            .first()
            .copied()
            .expect("write opc");
        let flush_op = encode_flush(1, 1)
            .as_bytes()
            .first()
            .copied()
            .expect("flush opc");
        let discard_op = encode_discard(1, 0, 1, 0x1000, 1)
            .as_bytes()
            .first()
            .copied()
            .expect("discard opc");
        let sqes = [read_op, write_op, flush_op, discard_op];
        for (i, &a) in sqes.iter().enumerate() {
            for (j, &b) in sqes.iter().enumerate().skip(i + 1) {
                assert_ne!(a, b, "encoders {i} and {j} share opcode byte");
            }
        }
    }
}
