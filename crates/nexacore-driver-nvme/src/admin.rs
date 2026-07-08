//! NVMe Admin Submission Queue Entry (SQE) and Completion Queue Entry
//! (CQE) encoders / decoders.
//!
//! Pinned by NVMe 1.4 base spec § 4.2 (SQE layout) and § 4.6 (CQE
//! layout). The user-space NVMe driver consumes these primitives to
//! build the Admin SQ ring it writes through the MMIO doorbell pair
//! during the bring-up sequence (NCIP-Driver-NVMe-014 § S6 steps 6 / 8
//! / 9 / 10 / 11) and to parse the matching admin completions on the
//! Admin CQ ring.
//!
//! ## Why a pure-state encoder module
//!
//! The bring-up FSM, the live admin-queue driver, and the host test
//! harness all need a single source of truth for the byte layout of
//! the 64-byte SQE and the 16-byte CQE. Putting the encoders here
//! (pure functions over plain `[u8; 64]` / `[u8; 16]` buffers) keeps
//! the wire-format contract in one auditable place and lets the host
//! tests exercise every bit position without standing up a controller.
//!
//! ## What this module does NOT do
//!
//! - It does not touch MMIO. The live admin-queue driver (a future
//!   sub-slice) wraps these encoders with the doorbell ring-buffer
//!   bookkeeping.
//! - It does not validate IOMMU mappings. PRP1 / PRP2 values are
//!   trusted to come from a prior `DmaMap` syscall on the caller side;
//!   the encoder packs them verbatim. The IOMMU enforces the actual
//!   access permission at translation time.
//! - It does not encode IO commands (Read / Write / Flush / Discard).
//!   Those land on the IO SQ ring, which uses the same SQE byte layout
//!   but with different opcodes and `CDWx` semantics. The IO encoder
//!   is a future sibling module.

pub use nexacore_types::nvme::IdentifyTarget;

// =============================================================================
// Sizes
// =============================================================================

/// Submission Queue Entry size in bytes per NVMe 1.4 § 4.2.
///
/// Fixed at 64 bytes by the spec; mirrored in
/// [`crate::queue_config`] for the ring-buffer arithmetic.
pub const ADMIN_SQE_BYTES: usize = 64;

/// Completion Queue Entry size in bytes per NVMe 1.4 § 4.6.
///
/// Fixed at 16 bytes by the spec.
pub const ADMIN_CQE_BYTES: usize = 16;

// =============================================================================
// Admin opcodes (subset surfaced by the Phase-1 bring-up sequence)
// =============================================================================

/// `Identify` admin command opcode per NVMe 1.4 § 5.15.
pub const OPC_IDENTIFY: u8 = 0x06;

/// `Create I/O Completion Queue` admin command opcode per NVMe 1.4
/// § 5.5. Reserved here for the future IO-queue creation slice; not
/// currently encoded by this module.
pub const OPC_CREATE_IO_CQ: u8 = 0x05;

/// `Create I/O Submission Queue` admin command opcode per NVMe 1.4
/// § 5.4.
pub const OPC_CREATE_IO_SQ: u8 = 0x01;

/// `Get Log Page` admin command opcode per NVMe 1.4 § 5.14.
pub const OPC_GET_LOG_PAGE: u8 = 0x02;

// =============================================================================
// Identify CNS values
// =============================================================================

/// CNS = `0x00` per NVMe 1.4 § 5.15.1 — Identify Namespace data
/// structure.
pub const CNS_IDENTIFY_NAMESPACE: u8 = 0x00;

/// CNS = `0x01` per NVMe 1.4 § 5.15.1 — Identify Controller data
/// structure.
pub const CNS_IDENTIFY_CONTROLLER: u8 = 0x01;

/// CNS = `0x02` per NVMe 1.4 § 5.15.1 — Active Namespace ID list
/// (4 KiB list of 32-bit NSIDs > the supplied starting NSID).
pub const CNS_ACTIVE_NSID_LIST: u8 = 0x02;

// =============================================================================
// AdminSqe — 64-byte Submission Queue Entry
// =============================================================================

/// A 64-byte NVMe Admin Submission Queue Entry per NVMe 1.4 § 4.2.
///
/// Wrapped as a `repr(transparent)` newtype over `[u8; 64]` so the
/// driver can `memcpy` the value directly into the ring-buffer slot
/// the doorbell pair tracks. The encoder builds the entry by writing
/// little-endian 32-bit dwords; NVMe MMIO is defined as little-endian
/// in NVMe 1.4 § 3.0 ("Endianness").
#[repr(transparent)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AdminSqe(pub [u8; ADMIN_SQE_BYTES]);

impl AdminSqe {
    /// Construct an all-zero SQE.
    ///
    /// Zero is the "no-op" submission entry; submitting it to the
    /// controller surfaces an Invalid Opcode completion, so the
    /// constructor is only useful as a clean starting point for the
    /// per-command encoders below.
    #[must_use]
    pub const fn zeroed() -> Self {
        Self([0u8; ADMIN_SQE_BYTES])
    }

    /// Borrow the raw 64-byte buffer.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; ADMIN_SQE_BYTES] {
        &self.0
    }

    /// Mutable borrow of the raw 64-byte buffer. The driver MUST NOT
    /// hand the underlying slice to user code; the encoder helpers in
    /// this module are the only legal mutators.
    pub fn as_bytes_mut(&mut self) -> &mut [u8; ADMIN_SQE_BYTES] {
        &mut self.0
    }
}

impl Default for AdminSqe {
    fn default() -> Self {
        Self::zeroed()
    }
}

// =============================================================================
// AdminSqe encoders
// =============================================================================

/// Encode an Identify admin command into a fresh [`AdminSqe`].
///
/// Field layout per NVMe 1.4 § 4.2 + § 5.15:
///
/// | Bytes | Field | Source |
/// |---|---|---|
/// | 0     | OPC = 0x06        | [`OPC_IDENTIFY`] |
/// | 1     | FUSE\|PSDT = 0    | not fused, PRP transfer |
/// | 2..=3 | CID               | `cid` |
/// | 4..=7 | NSID              | per [`IdentifyTarget`] |
/// | 8..=23| Reserved + MPTR   | zero |
/// | 24..=31 | DPTR.PRP1       | `prp1` |
/// | 32..=39 | DPTR.PRP2       | `prp2` |
/// | 40..=43 | CDW10           | CNS (bits 7:0) per [`IdentifyTarget`] |
/// | 44..=63 | CDW11..15       | zero |
///
/// Notes:
///
/// - `prp1` MUST point to a 4 KiB buffer the controller will write
///   the 4 KiB Identify response into. The buffer alignment invariant
///   is checked by [`crate::transfer_model::is_prp_aligned`] at the
///   bring-up FSM boundary, not here, because the encoder is also
///   exercised in host tests with synthetic addresses.
/// - `prp2` is unused for Identify (the response fits in one page);
///   the spec mandates encoding it as zero.
/// - `cid` is the Command Identifier (NVMe 1.4 § 4.2 bits 31:16 of
///   CDW0). The driver MUST keep `cid` unique across all outstanding
///   admin commands so the matching completion can be correlated;
///   reuse after completion is permitted.
#[must_use]
pub fn encode_identify(target: IdentifyTarget, prp1: u64, prp2: u64, cid: u16) -> AdminSqe {
    let mut sqe = AdminSqe::zeroed();

    // CDW0 = OPC (bits 7:0) | FUSE (bits 9:8) | PSDT (bits 15:14) | CID (bits 31:16).
    // FUSE = 0 (not fused), PSDT = 0 (PRPs used for data transfer), CID = supplied.
    let cdw0: u32 = u32::from(OPC_IDENTIFY) | (u32::from(cid) << 16);
    write_dw_at(&mut sqe.0, 0, cdw0);

    // NSID dispatch per CNS — only Identify Namespace looks at NSID;
    // Identify Controller MUST pass NSID = 0; Active NSID List passes
    // the starting NSID (zero asks for the first 1024 NSIDs). Every
    // other (`#[non_exhaustive]` future) target also defaults to
    // NSID = 0, so the wildcard arm covers `Controller`,
    // `ActiveNsList`, and anything we add later.
    let nsid: u32 = match target {
        IdentifyTarget::Namespace { nsid } => nsid,
        _ => 0,
    };
    write_dw_at(&mut sqe.0, 4, nsid);

    // Bytes 8..=23 stay zero (Reserved + MPTR). Already zero by
    // `AdminSqe::zeroed()`.

    // DPTR.PRP1 at bytes 24..=31 (64-bit, little-endian).
    write_qw_at(&mut sqe.0, 24, prp1);
    // DPTR.PRP2 at bytes 32..=39 (64-bit, little-endian). Zero for
    // Identify per NVMe 1.4 § 5.15.
    write_qw_at(&mut sqe.0, 32, prp2);

    // CDW10 = CNS (bits 7:0) | CNTID (bits 31:16); CNTID = 0 for the
    // three Phase-1 CNS values. The wildcard arm defaults to
    // `Identify Controller` (the safest "broadest introspection"
    // request) for future `#[non_exhaustive]` variants — those land
    // with their own explicit arms before the encoder is asked to
    // emit them in production.
    let cns: u8 = match target {
        IdentifyTarget::Namespace { .. } => CNS_IDENTIFY_NAMESPACE,
        IdentifyTarget::ActiveNsList => CNS_ACTIVE_NSID_LIST,
        _ => CNS_IDENTIFY_CONTROLLER,
    };
    write_dw_at(&mut sqe.0, 40, u32::from(cns));

    // CDW11..15 stay zero. Already zero.

    sqe
}

// =============================================================================
// Create I/O Completion Queue / Submission Queue encoders
// =============================================================================

/// CDW11 bit 0 — `PC` (Physically Contiguous).
///
/// Per NVMe 1.4 § 5.4 + § 5.5: set when the queue's data buffer is
/// one contiguous range. Phase-1 driver always allocates a single
/// contiguous page-aligned region via `DmaMap`.
pub const CIOQ_CDW11_PC_BIT: u32 = 1 << 0;

/// CDW11 bit 1 — `IEN` (Interrupts Enabled).
///
/// Per NVMe 1.4 § 5.5 (Create I/O Completion Queue only). Phase-1
/// driver always sets this so MSI-X vectors deliver to the bound
/// IRQ channel.
pub const CIOCQ_CDW11_IEN_BIT: u32 = 1 << 1;

/// Queue Priority field shift in CDW11 for Create IO SQ.
///
/// Per NVMe 1.4 § 5.4: bits 2:1 hold the priority (0 = Urgent,
/// 1 = High, 2 = Medium, 3 = Low). Phase-1 driver requests Medium
/// (`0b10`) to match the QEMU `weighted_round_robin` default.
pub const CIOSQ_CDW11_QPRIO_SHIFT: u32 = 1;

/// Queue Priority value: Urgent per NVMe 1.4 § 5.4.
pub const CIOSQ_QPRIO_URGENT: u32 = 0b00;
/// Queue Priority value: High per NVMe 1.4 § 5.4.
pub const CIOSQ_QPRIO_HIGH: u32 = 0b01;
/// Queue Priority value: Medium per NVMe 1.4 § 5.4 (Phase-1 default).
pub const CIOSQ_QPRIO_MEDIUM: u32 = 0b10;
/// Queue Priority value: Low per NVMe 1.4 § 5.4.
pub const CIOSQ_QPRIO_LOW: u32 = 0b11;

/// Interrupt vector shift in CDW11 for Create IO CQ per
/// NVMe 1.4 § 5.5: bits 31:16 hold the MSI-X vector index.
pub const CIOCQ_CDW11_IV_SHIFT: u32 = 16;

/// Completion-queue identifier shift in CDW11 for Create IO SQ per
/// NVMe 1.4 § 5.4: bits 31:16 hold the CQID this SQ pairs with.
pub const CIOSQ_CDW11_CQID_SHIFT: u32 = 16;

/// Encode a `Create I/O Completion Queue` admin command into a fresh
/// [`AdminSqe`].
///
/// Field layout per NVMe 1.4 § 5.5 + § 4.2:
///
/// | Bytes | Field | Source |
/// |---|---|---|
/// | 0     | OPC = 0x05        | [`OPC_CREATE_IO_CQ`] |
/// | 2..=3 | CID               | `cid` |
/// | 4..=7 | NSID              | 0 (admin command, namespace-agnostic) |
/// | 24..=31 | DPTR.PRP1       | `prp1` (CQ data buffer, 4 KiB-aligned) |
/// | 40..=43 | CDW10 = QSIZE\[31:16\] \| QID\[15:0\] | `qsize - 1` (0-based per spec) \| `qid` |
/// | 44..=47 | CDW11 = IV\[31:16\] \| IEN\[1\] \| PC\[0\] | `irq_vector`, `irq_enabled`, `physically_contig` |
///
/// `qsize` is 1-based in NexaCore OS (callers see "this many entries");
/// the encoder subtracts one to match the NVMe 0-based field
/// convention. `qsize = 0` saturates to `0` (degenerate single-slot
/// queue) — the bring-up FSM rejects zero upstream.
#[must_use]
pub fn encode_create_io_cq(
    qid: u16,
    qsize: u16,
    prp1: u64,
    irq_vector: u16,
    irq_enabled: bool,
    physically_contig: bool,
    cid: u16,
) -> AdminSqe {
    let mut sqe = AdminSqe::zeroed();
    let buf = sqe.as_bytes_mut();

    let header_dw: u32 = u32::from(OPC_CREATE_IO_CQ) | (u32::from(cid) << 16);
    write_dw_at(buf, 0, header_dw);
    // NSID = 0 for admin commands; already zero by `zeroed()`.

    // DPTR.PRP1 at bytes 24..=31. PRP2 stays zero (CQ data buffer
    // fits in one PRP per the physically-contiguous flag).
    write_qw_at(buf, 24, prp1);

    // CDW10 = QSIZE 0-based (bits 31:16) | QID (bits 15:0).
    let qsize_zero_based: u32 = u32::from(qsize.saturating_sub(1));
    let queue_dw10: u32 = u32::from(qid) | (qsize_zero_based << 16);
    write_dw_at(buf, 40, queue_dw10);

    // CDW11 = IV (bits 31:16) | IEN (bit 1) | PC (bit 0).
    let mut flags_dw11: u32 = 0;
    if physically_contig {
        flags_dw11 |= CIOQ_CDW11_PC_BIT;
    }
    if irq_enabled {
        flags_dw11 |= CIOCQ_CDW11_IEN_BIT;
    }
    flags_dw11 |= u32::from(irq_vector) << CIOCQ_CDW11_IV_SHIFT;
    write_dw_at(buf, 44, flags_dw11);

    sqe
}

/// Encode a `Create I/O Submission Queue` admin command into a fresh
/// [`AdminSqe`].
///
/// Field layout per NVMe 1.4 § 5.4 + § 4.2:
///
/// | Bytes | Field | Source |
/// |---|---|---|
/// | 0     | OPC = 0x01        | [`OPC_CREATE_IO_SQ`] |
/// | 2..=3 | CID               | `cid` |
/// | 4..=7 | NSID              | 0 (admin command) |
/// | 24..=31 | DPTR.PRP1       | `prp1` (SQ data buffer) |
/// | 40..=43 | CDW10 = QSIZE\[31:16\] \| QID\[15:0\] | `qsize - 1` \| `qid` |
/// | 44..=47 | CDW11 = CQID\[31:16\] \| QPRIO\[2:1\] \| PC\[0\] | `cq_id`, `queue_priority`, `physically_contig` |
///
/// `queue_priority` MUST be one of
/// [`CIOSQ_QPRIO_URGENT`] / [`CIOSQ_QPRIO_HIGH`] /
/// [`CIOSQ_QPRIO_MEDIUM`] / [`CIOSQ_QPRIO_LOW`]; values outside
/// `0..=3` are masked to 2 bits.
#[must_use]
pub fn encode_create_io_sq(
    qid: u16,
    qsize: u16,
    prp1: u64,
    cq_id: u16,
    queue_priority: u32,
    physically_contig: bool,
    cid: u16,
) -> AdminSqe {
    let mut sqe = AdminSqe::zeroed();
    let buf = sqe.as_bytes_mut();

    let header_dw: u32 = u32::from(OPC_CREATE_IO_SQ) | (u32::from(cid) << 16);
    write_dw_at(buf, 0, header_dw);

    write_qw_at(buf, 24, prp1);

    let qsize_zero_based: u32 = u32::from(qsize.saturating_sub(1));
    let queue_dw10: u32 = u32::from(qid) | (qsize_zero_based << 16);
    write_dw_at(buf, 40, queue_dw10);

    // CDW11 = CQID (bits 31:16) | QPRIO (bits 2:1) | PC (bit 0).
    let mut flags_dw11: u32 = 0;
    if physically_contig {
        flags_dw11 |= CIOQ_CDW11_PC_BIT;
    }
    let qprio_masked: u32 = queue_priority & 0b11;
    flags_dw11 |= qprio_masked << CIOSQ_CDW11_QPRIO_SHIFT;
    flags_dw11 |= u32::from(cq_id) << CIOSQ_CDW11_CQID_SHIFT;
    write_dw_at(buf, 44, flags_dw11);

    sqe
}

// =============================================================================
// AdminCqe — 16-byte Completion Queue Entry
// =============================================================================

/// A 16-byte NVMe Admin Completion Queue Entry per NVMe 1.4 § 4.6.
///
/// Field layout (little-endian dwords):
///
/// | Bytes | Field |
/// |---|---|
/// | 0..=3   | Command Specific (CDW0) |
/// | 4..=7   | Reserved (CDW1) |
/// | 8..=11  | SQ Head Pointer (bits 15:0) \| SQ Identifier (bits 31:16) |
/// | 12..=15 | Command Identifier (bits 15:0) \| Status Field (bits 31:16) |
///
/// The Status Field bit layout (bits 31:16 of CDW3):
///
/// | Bit | Field |
/// |---|---|
/// | 16 (P)     | Phase Tag (toggled by the controller every wrap of the CQ ring) |
/// | 17..=24    | Status Code (SC) |
/// | 25..=27    | Status Code Type (SCT) |
/// | 28..=29    | CRD |
/// | 30 (M)     | More — additional information available in the AEN log |
/// | 31 (DNR)   | Do Not Retry |
#[repr(transparent)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AdminCqe(pub [u8; ADMIN_CQE_BYTES]);

impl AdminCqe {
    /// Wrap a raw 16-byte buffer.
    #[must_use]
    pub const fn from_bytes(raw: [u8; ADMIN_CQE_BYTES]) -> Self {
        Self(raw)
    }

    /// Borrow the raw 16-byte buffer.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; ADMIN_CQE_BYTES] {
        &self.0
    }
}

/// Parsed view of an [`AdminCqe`].
///
/// `parse_admin_cqe` returns this struct so callers do not have to
/// re-extract the same fields twice. The fields mirror the NVMe 1.4
/// § 4.6 wire layout one-for-one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AdminCqeFields {
    /// Command Specific Dword 0 — semantics depend on the originating
    /// command (e.g. Identify returns 0; Create IO CQ returns 0 too).
    pub cdw0: u32,
    /// SQ Head Pointer — the controller's view of the SQ head after
    /// this command was consumed. The driver compares it with its own
    /// tail to detect ring-buffer underruns.
    pub sq_head: u16,
    /// SQ Identifier — for the admin queue this is always 0 (`SQID =
    /// 0` per NVMe 1.4 § 1.6.20).
    pub sq_id: u16,
    /// Command Identifier — echoes the CID the driver assigned when
    /// submitting the matching SQE.
    pub cid: u16,
    /// Phase Tag — flips every time the CQ ring wraps. The driver
    /// MUST track the expected phase per slot and ignore CQEs whose
    /// phase does not match (they belong to a previous wrap).
    pub phase: bool,
    /// Status Code per NVMe 1.4 § 4.6 bits 17..=24.
    pub sc: u8,
    /// Status Code Type per NVMe 1.4 § 4.6 bits 25..=27.
    pub sct: u8,
    /// `More` bit — `true` if the controller has additional event
    /// information available in the asynchronous event log.
    pub more: bool,
    /// `Do Not Retry` bit — `true` if the controller has determined
    /// retrying the command would not change the outcome.
    pub do_not_retry: bool,
}

impl AdminCqeFields {
    /// Returns `true` iff the completion reports success.
    ///
    /// Success per NVMe 1.4 § 4.6 = `SCT == 0` (Generic Command
    /// Status) AND `SC == 0` (Successful Completion).
    #[must_use]
    pub const fn is_success(&self) -> bool {
        self.sct == 0 && self.sc == 0
    }

    /// Pack the `(SCT, SC, M, DNR, P)` bits into the 16-bit status
    /// word as it appears in
    /// [`nexacore_types::nvme::NvmeEvent::CommandComplete::status`].
    ///
    /// The bit positions match the CDW3-status half of the CQE
    /// shifted down by 16, i.e. the upper 16 bits of CDW3 become the
    /// 16-bit status word. This is the canonical form NexaCore OS
    /// surfaces on the event channel — clients decode it via the
    /// NVMe 1.4 § 4.5 table.
    ///
    /// Layout:
    ///
    /// | Bit | Field |
    /// |---|---|
    /// | 0  | Phase Tag |
    /// | 8:1 | Status Code |
    /// | 11:9 | Status Code Type |
    /// | 12-13 | CRD (zeroed here — Phase-1 driver does not surface) |
    /// | 14 | More |
    /// | 15 | DNR |
    #[must_use]
    pub const fn packed_status(&self) -> u16 {
        let mut s: u16 = 0;
        if self.phase {
            s |= 1 << 0;
        }
        s |= (self.sc as u16) << 1;
        s |= ((self.sct as u16) & 0b111) << 9;
        if self.more {
            s |= 1 << 14;
        }
        if self.do_not_retry {
            s |= 1 << 15;
        }
        s
    }
}

/// Decode a raw [`AdminCqe`] into its constituent fields.
///
/// The decode is little-endian per NVMe 1.4 § 3.0. The function is
/// total over the 16-byte input — there is no "decode failure" mode
/// because every bit pattern represents a syntactically-valid CQE
/// (some patterns may be semantically meaningless, but parsing them
/// is still defined).
#[must_use]
pub fn parse_admin_cqe(cqe: &AdminCqe) -> AdminCqeFields {
    let cdw0 = read_dw_at(&cqe.0, 0);
    let cdw2 = read_dw_at(&cqe.0, 8);
    let cdw3 = read_dw_at(&cqe.0, 12);

    let sq_head: u16 = (cdw2 & 0xFFFF) as u16;
    let sq_id: u16 = ((cdw2 >> 16) & 0xFFFF) as u16;
    let cid: u16 = (cdw3 & 0xFFFF) as u16;
    let status_word: u16 = ((cdw3 >> 16) & 0xFFFF) as u16;

    AdminCqeFields {
        cdw0,
        sq_head,
        sq_id,
        cid,
        phase: (status_word & 0b1) != 0,
        sc: ((status_word >> 1) & 0xFF) as u8,
        sct: ((status_word >> 9) & 0b111) as u8,
        more: (status_word & (1 << 14)) != 0,
        do_not_retry: (status_word & (1 << 15)) != 0,
    }
}

// =============================================================================
// Internal byte helpers
// =============================================================================

/// Write a little-endian `u32` at byte offset `off` of `buf`.
///
/// `buf` MUST be ≥ `off + 4` bytes; the encoder helpers above always
/// pass an in-bounds offset because the SQE / CQE sizes are
/// statically known. Out-of-bounds would be a bug in this module.
#[inline]
fn write_dw_at(buf: &mut [u8], off: usize, val: u32) {
    let bytes = val.to_le_bytes();
    // Manual unrolled write rather than `buf[off..off + 4].copy_from_slice(&bytes)`
    // to satisfy `clippy::indexing_slicing` on the workspace lint set.
    if let Some(slot) = buf.get_mut(off) {
        *slot = bytes[0];
    }
    if let Some(slot) = buf.get_mut(off + 1) {
        *slot = bytes[1];
    }
    if let Some(slot) = buf.get_mut(off + 2) {
        *slot = bytes[2];
    }
    if let Some(slot) = buf.get_mut(off + 3) {
        *slot = bytes[3];
    }
}

/// Write a little-endian `u64` at byte offset `off` of `buf`.
#[inline]
fn write_qw_at(buf: &mut [u8], off: usize, val: u64) {
    let bytes = val.to_le_bytes();
    for (i, byte) in bytes.iter().enumerate() {
        if let Some(slot) = buf.get_mut(off + i) {
            *slot = *byte;
        }
    }
}

/// Read a little-endian `u32` at byte offset `off` of `buf`.
///
/// Returns `0` if any of the four bytes is out of bounds — only
/// reachable on a programming error in this module since the CQE
/// size is statically known.
#[inline]
fn read_dw_at(buf: &[u8], off: usize) -> u32 {
    let b0 = buf.get(off).copied().unwrap_or(0);
    let b1 = buf.get(off + 1).copied().unwrap_or(0);
    let b2 = buf.get(off + 2).copied().unwrap_or(0);
    let b3 = buf.get(off + 3).copied().unwrap_or(0);
    u32::from_le_bytes([b0, b1, b2, b3])
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // -------------------------------------------------------------------
    // Constants & tripwires
    // -------------------------------------------------------------------

    #[test]
    fn admin_sqe_size_matches_nvme_spec() {
        assert_eq!(ADMIN_SQE_BYTES, 64);
    }

    #[test]
    fn admin_cqe_size_matches_nvme_spec() {
        assert_eq!(ADMIN_CQE_BYTES, 16);
    }

    #[test]
    fn admin_sqe_struct_is_64_bytes() {
        assert_eq!(core::mem::size_of::<AdminSqe>(), ADMIN_SQE_BYTES);
    }

    #[test]
    fn admin_cqe_struct_is_16_bytes() {
        assert_eq!(core::mem::size_of::<AdminCqe>(), ADMIN_CQE_BYTES);
    }

    #[test]
    fn opcodes_match_nvme_spec() {
        assert_eq!(OPC_IDENTIFY, 0x06);
        assert_eq!(OPC_CREATE_IO_CQ, 0x05);
        assert_eq!(OPC_CREATE_IO_SQ, 0x01);
        assert_eq!(OPC_GET_LOG_PAGE, 0x02);
    }

    #[test]
    fn cns_values_match_nvme_spec() {
        assert_eq!(CNS_IDENTIFY_NAMESPACE, 0x00);
        assert_eq!(CNS_IDENTIFY_CONTROLLER, 0x01);
        assert_eq!(CNS_ACTIVE_NSID_LIST, 0x02);
    }

    #[test]
    fn admin_sqe_zeroed_is_all_zero() {
        let sqe = AdminSqe::zeroed();
        assert_eq!(sqe.as_bytes(), &[0u8; 64]);
    }

    #[test]
    fn admin_sqe_default_matches_zeroed() {
        let z = AdminSqe::zeroed();
        let d = AdminSqe::default();
        assert_eq!(z, d);
    }

    // -------------------------------------------------------------------
    // encode_identify — Identify Controller
    // -------------------------------------------------------------------

    #[test]
    fn encode_identify_controller_writes_opcode() {
        let sqe = encode_identify(IdentifyTarget::Controller, 0x1000, 0, 0xABCD);
        // OPC at byte 0.
        let opc = sqe.as_bytes().first().copied().expect("opc byte 0");
        assert_eq!(opc, OPC_IDENTIFY);
    }

    #[test]
    fn encode_identify_controller_writes_cid() {
        let sqe = encode_identify(IdentifyTarget::Controller, 0x1000, 0, 0xABCD);
        // CID at bytes 2..=3 (little-endian).
        let cid_bytes = sqe.as_bytes().get(2..4).expect("cid range in bounds");
        assert_eq!(cid_bytes, &[0xCD, 0xAB]);
    }

    #[test]
    fn encode_identify_controller_nsid_is_zero() {
        let sqe = encode_identify(IdentifyTarget::Controller, 0x1000, 0, 0xABCD);
        // NSID at bytes 4..=7.
        let nsid = sqe.as_bytes().get(4..8).expect("nsid range in bounds");
        assert_eq!(nsid, &[0, 0, 0, 0]);
    }

    #[test]
    fn encode_identify_controller_writes_prp1() {
        let prp1: u64 = 0xCAFE_BABE_DEAD_BEEF;
        let sqe = encode_identify(IdentifyTarget::Controller, prp1, 0, 1);
        // PRP1 at bytes 24..=31 (little-endian).
        let expected = prp1.to_le_bytes();
        let observed = sqe.as_bytes().get(24..32).expect("prp1 range in bounds");
        assert_eq!(observed, &expected);
    }

    #[test]
    fn encode_identify_controller_writes_prp2_zero() {
        let sqe = encode_identify(IdentifyTarget::Controller, 0x1000, 0, 1);
        // PRP2 at bytes 32..=39.
        let prp2 = sqe.as_bytes().get(32..40).expect("prp2 range in bounds");
        assert_eq!(prp2, &[0u8; 8]);
    }

    #[test]
    fn encode_identify_controller_writes_cns_01_in_cdw10() {
        let sqe = encode_identify(IdentifyTarget::Controller, 0x1000, 0, 1);
        // CDW10 at bytes 40..=43; CNS in low 8 bits, upper bytes zero
        // (CNTID = 0).
        let cdw10 = sqe.as_bytes().get(40..44).expect("cdw10 range in bounds");
        assert_eq!(cdw10, &[CNS_IDENTIFY_CONTROLLER, 0, 0, 0]);
    }

    // -------------------------------------------------------------------
    // encode_identify — Identify Namespace
    // -------------------------------------------------------------------

    #[test]
    fn encode_identify_namespace_writes_nsid() {
        let sqe = encode_identify(
            IdentifyTarget::Namespace { nsid: 0xDEAD_BEEF },
            0x2000,
            0,
            2,
        );
        // NSID at bytes 4..=7 (little-endian).
        let nsid = sqe.as_bytes().get(4..8).expect("nsid range in bounds");
        assert_eq!(nsid, &[0xEF, 0xBE, 0xAD, 0xDE]);
    }

    #[test]
    fn encode_identify_namespace_cns_is_00() {
        let sqe = encode_identify(IdentifyTarget::Namespace { nsid: 1 }, 0x2000, 0, 2);
        let cns = sqe.as_bytes().get(40).copied().expect("cdw10 byte 40");
        assert_eq!(cns, CNS_IDENTIFY_NAMESPACE);
    }

    // -------------------------------------------------------------------
    // encode_identify — Active NSID List
    // -------------------------------------------------------------------

    #[test]
    fn encode_identify_active_ns_list_cns_is_02() {
        let sqe = encode_identify(IdentifyTarget::ActiveNsList, 0x3000, 0, 3);
        let cns = sqe.as_bytes().get(40).copied().expect("cdw10 byte 40");
        assert_eq!(cns, CNS_ACTIVE_NSID_LIST);
    }

    #[test]
    fn encode_identify_active_ns_list_nsid_is_zero() {
        let sqe = encode_identify(IdentifyTarget::ActiveNsList, 0x3000, 0, 3);
        let nsid = sqe.as_bytes().get(4..8).expect("nsid range in bounds");
        assert_eq!(nsid, &[0, 0, 0, 0]);
    }

    // -------------------------------------------------------------------
    // encode_identify — reserved bytes stay zero
    // -------------------------------------------------------------------

    #[test]
    fn encode_identify_reserved_bytes_8_through_23_are_zero() {
        let sqe = encode_identify(IdentifyTarget::Controller, 0x1000, 0, 1);
        let reserved = sqe.as_bytes().get(8..24).expect("reserved range in bounds");
        assert_eq!(reserved, &[0u8; 16]);
    }

    #[test]
    fn encode_identify_cdw11_to_15_are_zero() {
        let sqe = encode_identify(IdentifyTarget::Controller, 0x1000, 0, 1);
        // CDW11..15 occupies bytes 44..=63 (5 dwords × 4 bytes = 20).
        let trailing = sqe
            .as_bytes()
            .get(44..64)
            .expect("cdw11..15 range in bounds");
        assert_eq!(trailing, &[0u8; 20]);
    }

    // -------------------------------------------------------------------
    // parse_admin_cqe — happy path
    // -------------------------------------------------------------------

    fn cqe_with(cdw0: u32, sq_head: u16, sq_id: u16, cid: u16, status_word: u16) -> AdminCqe {
        let mut raw = [0u8; ADMIN_CQE_BYTES];
        let cdw2: u32 = u32::from(sq_head) | (u32::from(sq_id) << 16);
        let cdw3: u32 = u32::from(cid) | (u32::from(status_word) << 16);
        // `chunks_exact_mut(4)` walks the four 4-byte dwords without
        // index arithmetic. The `expect` calls are unreachable because
        // `ADMIN_CQE_BYTES = 16` ⇒ exactly four dwords.
        let mut chunks = raw.chunks_exact_mut(4);
        chunks
            .next()
            .expect("cdw0 chunk")
            .copy_from_slice(&cdw0.to_le_bytes());
        chunks.next().expect("cdw1 chunk"); // CDW1 stays zero
        chunks
            .next()
            .expect("cdw2 chunk")
            .copy_from_slice(&cdw2.to_le_bytes());
        chunks
            .next()
            .expect("cdw3 chunk")
            .copy_from_slice(&cdw3.to_le_bytes());
        AdminCqe::from_bytes(raw)
    }

    #[test]
    fn parse_cqe_success_round_trip() {
        // Status word = phase bit only set (a real successful CQE).
        let cqe = cqe_with(0, 5, 0, 0x1234, 0b0000_0000_0000_0001);
        let f = parse_admin_cqe(&cqe);
        assert_eq!(f.cdw0, 0);
        assert_eq!(f.sq_head, 5);
        assert_eq!(f.sq_id, 0);
        assert_eq!(f.cid, 0x1234);
        assert!(f.phase);
        assert_eq!(f.sc, 0);
        assert_eq!(f.sct, 0);
        assert!(!f.more);
        assert!(!f.do_not_retry);
        assert!(f.is_success());
    }

    #[test]
    fn parse_cqe_phase_bit_clear_on_unwrapped_slot() {
        // Phase bit = 0 (slot has not been used yet; the driver MUST
        // skip this CQE on the first lap of the ring).
        let cqe = cqe_with(0, 0, 0, 0x0001, 0b0000_0000_0000_0000);
        let f = parse_admin_cqe(&cqe);
        assert!(!f.phase);
    }

    #[test]
    fn parse_cqe_status_code_extracted() {
        // SC = 0x81 (Invalid LBA Range, NVMe 1.4 § 4.5 Generic Command
        // Status). status_word = (sc << 1) | phase.
        let status_word: u16 = (0x81u16 << 1) | 0b1;
        let cqe = cqe_with(0, 1, 0, 0x42, status_word);
        let f = parse_admin_cqe(&cqe);
        assert_eq!(f.sc, 0x81);
        assert_eq!(f.sct, 0);
        assert!(!f.is_success());
    }

    #[test]
    fn parse_cqe_status_code_type_extracted() {
        // SCT = 0b010 (Path-related, NVMe 1.4 § 4.5). SC = 0. phase = 1.
        let status_word: u16 = (0b010u16 << 9) | 0b1;
        let cqe = cqe_with(0, 0, 0, 1, status_word);
        let f = parse_admin_cqe(&cqe);
        assert_eq!(f.sct, 0b010);
        assert_eq!(f.sc, 0);
        assert!(!f.is_success());
    }

    #[test]
    fn parse_cqe_more_and_dnr_bits() {
        // More = 1, DNR = 1, SC = 0x10, SCT = 0b001, phase = 1.
        let status_word: u16 = (1u16 << 15) | (1 << 14) | (0b001u16 << 9) | (0x10u16 << 1) | 0b1;
        let cqe = cqe_with(0xCAFE_BABE, 7, 0, 0x99, status_word);
        let f = parse_admin_cqe(&cqe);
        assert!(f.more);
        assert!(f.do_not_retry);
        assert_eq!(f.sc, 0x10);
        assert_eq!(f.sct, 0b001);
        assert_eq!(f.cdw0, 0xCAFE_BABE);
        assert_eq!(f.cid, 0x99);
    }

    // -------------------------------------------------------------------
    // packed_status — bit packing inverse
    // -------------------------------------------------------------------

    #[test]
    fn packed_status_success_only_phase_bit() {
        let f = AdminCqeFields {
            cdw0: 0,
            sq_head: 0,
            sq_id: 0,
            cid: 0,
            phase: true,
            sc: 0,
            sct: 0,
            more: false,
            do_not_retry: false,
        };
        assert_eq!(f.packed_status(), 0b1);
    }

    #[test]
    fn packed_status_round_trips_through_parse_admin_cqe() {
        // Build a status word, encode into a synthetic CQE, parse it,
        // re-pack — MUST equal the original.
        let original_status: u16 =
            (1u16 << 15) | (1 << 14) | (0b011u16 << 9) | (0x42u16 << 1) | 0b1;
        let cqe = cqe_with(0, 0, 0, 0, original_status);
        let f = parse_admin_cqe(&cqe);
        assert_eq!(f.packed_status(), original_status);
    }

    #[test]
    fn packed_status_clears_unused_crd_bits() {
        // CRD field (bits 12..=13 of the status word) is not surfaced
        // by `AdminCqeFields`; packing MUST emit zero there even when
        // the source CQE happens to have them set.
        let f = AdminCqeFields {
            cdw0: 0,
            sq_head: 0,
            sq_id: 0,
            cid: 0,
            phase: false,
            sc: 0,
            sct: 0,
            more: false,
            do_not_retry: false,
        };
        let packed = f.packed_status();
        // Bits 12..=13 MUST be zero.
        assert_eq!(packed & (0b11 << 12), 0);
    }

    // -------------------------------------------------------------------
    // SQE / CQE byte layout pinning (detect endian regressions)
    // -------------------------------------------------------------------

    #[test]
    fn encode_identify_controller_cdw0_layout_matches_nvme_le() {
        // Spec encodes CDW0 as little-endian u32 with OPC in bits 7:0
        // and CID in bits 31:16. Build the expected dword and compare
        // through the canonical little-endian decode helper.
        let cid: u16 = 0xBEEF;
        let sqe = encode_identify(IdentifyTarget::Controller, 0, 0, cid);
        let expected_cdw0: u32 = u32::from(OPC_IDENTIFY) | (u32::from(cid) << 16);
        let bytes = sqe.as_bytes().get(0..4).expect("cdw0 range in bounds");
        let mut buf = [0u8; 4];
        buf.copy_from_slice(bytes);
        let observed = u32::from_le_bytes(buf);
        assert_eq!(observed, expected_cdw0);
    }

    #[test]
    fn parse_admin_cqe_handles_max_value_status_word() {
        let cqe = cqe_with(u32::MAX, u16::MAX, u16::MAX, u16::MAX, u16::MAX);
        let f = parse_admin_cqe(&cqe);
        assert_eq!(f.cdw0, u32::MAX);
        assert_eq!(f.sq_head, u16::MAX);
        assert_eq!(f.sq_id, u16::MAX);
        assert_eq!(f.cid, u16::MAX);
        assert!(f.phase);
        assert_eq!(f.sc, u8::MAX);
        // SCT is 3 bits; max parsed value is 0b111 = 7.
        assert_eq!(f.sct, 0b111);
        assert!(f.more);
        assert!(f.do_not_retry);
    }

    // -------------------------------------------------------------------
    // Create IO CQ / Create IO SQ encoders (P6.7.10-pre.10)
    // -------------------------------------------------------------------

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

    #[test]
    fn create_io_cq_opcode_at_byte_zero() {
        let sqe = encode_create_io_cq(1, 64, 0x1000, 0, true, true, 1);
        assert_eq!(
            sqe.as_bytes().first().copied().expect("opc"),
            OPC_CREATE_IO_CQ
        );
    }

    #[test]
    fn create_io_cq_cdw10_packs_qid_in_low_and_qsize_zero_based_in_high() {
        // qid=1, qsize=64 (1-based) → QSIZE field = 63 (0-based).
        let sqe = encode_create_io_cq(1, 64, 0x1000, 0, true, true, 1);
        let cdw10 = read_le_u32(sqe.as_bytes(), 40);
        let qid_field = cdw10 & 0xFFFF;
        let qsize_field = (cdw10 >> 16) & 0xFFFF;
        assert_eq!(qid_field, 1);
        assert_eq!(qsize_field, 63);
    }

    #[test]
    fn create_io_cq_cdw11_bits_packed_correctly() {
        // IV = 3, IEN = true, PC = true.
        let sqe = encode_create_io_cq(1, 64, 0x1000, 3, true, true, 1);
        let cdw11 = read_le_u32(sqe.as_bytes(), 44);
        assert_eq!(cdw11 & CIOQ_CDW11_PC_BIT, CIOQ_CDW11_PC_BIT);
        assert_eq!(cdw11 & CIOCQ_CDW11_IEN_BIT, CIOCQ_CDW11_IEN_BIT);
        assert_eq!(cdw11 >> CIOCQ_CDW11_IV_SHIFT, 3);
    }

    #[test]
    fn create_io_cq_cdw11_clears_unset_flags() {
        // IEN = false, PC = false ⇒ low byte = 0.
        let sqe = encode_create_io_cq(1, 64, 0x1000, 0, false, false, 1);
        let cdw11 = read_le_u32(sqe.as_bytes(), 44);
        assert_eq!(cdw11 & CIOQ_CDW11_PC_BIT, 0);
        assert_eq!(cdw11 & CIOCQ_CDW11_IEN_BIT, 0);
    }

    #[test]
    fn create_io_cq_writes_prp1_at_bytes_24_through_31() {
        let prp1: u64 = 0xCAFE_BABE_DEAD_BEEF;
        let sqe = encode_create_io_cq(1, 64, prp1, 0, true, true, 1);
        assert_eq!(read_le_u64(sqe.as_bytes(), 24), prp1);
    }

    #[test]
    fn create_io_cq_nsid_zero_for_admin_command() {
        let sqe = encode_create_io_cq(1, 64, 0x1000, 0, true, true, 1);
        assert_eq!(read_le_u32(sqe.as_bytes(), 4), 0);
    }

    #[test]
    fn create_io_cq_qsize_saturating_sub_keeps_zero_on_zero_input() {
        let sqe = encode_create_io_cq(1, 0, 0x1000, 0, true, true, 1);
        let cdw10 = read_le_u32(sqe.as_bytes(), 40);
        let qsize_field = (cdw10 >> 16) & 0xFFFF;
        assert_eq!(qsize_field, 0);
    }

    #[test]
    fn create_io_sq_opcode_at_byte_zero() {
        let sqe = encode_create_io_sq(1, 1024, 0x2000, 1, CIOSQ_QPRIO_MEDIUM, true, 1);
        assert_eq!(
            sqe.as_bytes().first().copied().expect("opc"),
            OPC_CREATE_IO_SQ
        );
    }

    #[test]
    fn create_io_sq_cdw10_packs_qid_and_qsize() {
        let sqe = encode_create_io_sq(2, 1024, 0x2000, 1, CIOSQ_QPRIO_MEDIUM, true, 1);
        let cdw10 = read_le_u32(sqe.as_bytes(), 40);
        let qid_field = cdw10 & 0xFFFF;
        let qsize_field = (cdw10 >> 16) & 0xFFFF;
        assert_eq!(qid_field, 2);
        assert_eq!(qsize_field, 1023); // 1024 - 1
    }

    #[test]
    fn create_io_sq_cdw11_packs_cqid_qprio_pc() {
        let sqe = encode_create_io_sq(2, 1024, 0x2000, 1, CIOSQ_QPRIO_MEDIUM, true, 1);
        let cdw11 = read_le_u32(sqe.as_bytes(), 44);
        assert_eq!(cdw11 & CIOQ_CDW11_PC_BIT, CIOQ_CDW11_PC_BIT);
        let qprio_field = (cdw11 >> CIOSQ_CDW11_QPRIO_SHIFT) & 0b11;
        assert_eq!(qprio_field, CIOSQ_QPRIO_MEDIUM);
        let cqid_field = cdw11 >> CIOSQ_CDW11_CQID_SHIFT;
        assert_eq!(cqid_field, 1);
    }

    #[test]
    fn create_io_sq_qprio_constants_pin_spec_values() {
        assert_eq!(CIOSQ_QPRIO_URGENT, 0b00);
        assert_eq!(CIOSQ_QPRIO_HIGH, 0b01);
        assert_eq!(CIOSQ_QPRIO_MEDIUM, 0b10);
        assert_eq!(CIOSQ_QPRIO_LOW, 0b11);
    }

    #[test]
    fn create_io_sq_qprio_masked_to_two_bits() {
        // Out-of-range priority (0xFF) MUST mask to 0b11 = Low, not
        // bleed into higher bits.
        let sqe = encode_create_io_sq(2, 8, 0x2000, 1, 0xFF, true, 1);
        let cdw11 = read_le_u32(sqe.as_bytes(), 44);
        let qprio_field = (cdw11 >> CIOSQ_CDW11_QPRIO_SHIFT) & 0b11;
        assert_eq!(qprio_field, 0b11);
        // No bits should leak beyond the 2-bit qprio field except
        // CQID (in bits 31:16) and PC (bit 0).
        let leak_mask = cdw11 & 0xFFF8; // bits 3..=15
        assert_eq!(leak_mask, 0);
    }

    #[test]
    fn create_io_sq_writes_prp1() {
        let prp1: u64 = 0xDEAD_BEEF_0000;
        let sqe = encode_create_io_sq(2, 8, prp1, 1, CIOSQ_QPRIO_MEDIUM, true, 1);
        assert_eq!(read_le_u64(sqe.as_bytes(), 24), prp1);
    }

    #[test]
    fn create_io_sq_nsid_zero_for_admin_command() {
        let sqe = encode_create_io_sq(2, 8, 0x2000, 1, CIOSQ_QPRIO_MEDIUM, true, 1);
        assert_eq!(read_le_u32(sqe.as_bytes(), 4), 0);
    }

    #[test]
    fn create_io_cq_and_sq_opcode_constants_distinct() {
        // Tripwire: regression that aliased the two admin opcodes
        // would silently route Create-CQ traffic to Create-SQ (or
        // vice versa) with disastrous bring-up results.
        assert_ne!(OPC_CREATE_IO_CQ, OPC_CREATE_IO_SQ);
    }

    #[test]
    fn create_io_cq_cdw11_iv_shift_clears_low_bits() {
        // High vector value (e.g. 0x4000) MUST land entirely in
        // bits 31:16 and leave bits 0..=15 alone (modulo IEN/PC).
        let sqe = encode_create_io_cq(1, 64, 0x1000, 0x4000, false, false, 1);
        let cdw11 = read_le_u32(sqe.as_bytes(), 44);
        let iv_field = cdw11 >> CIOCQ_CDW11_IV_SHIFT;
        assert_eq!(iv_field, 0x4000);
        // Bits 0..=15 should be all zero (no IEN, no PC).
        assert_eq!(cdw11 & 0xFFFF, 0);
    }
}
