//! TPM 2.0 MMIO register maps (WS2-15.1/.2) — TIS and CRB.
//!
//! Two hardware interfaces carry TPM 2.0 commands: the legacy **TIS** (TPM
//! Interface Specification, FIFO at `0xFED4_0000` with a per-locality 4 KiB
//! window) and the newer **CRB** (Command Response Buffer). This module defines
//! both register maps + their status bits per the *TCG PC Client Platform TPM
//! Profile*; the MMIO accesses live in the bare-metal bring-up.

#![allow(
    clippy::doc_markdown,
    reason = "register mnemonics (TPM_STS, locActive, …) read as identifiers"
)]

// =============================================================================
// TIS — FIFO interface (per-locality registers at 0xFED4_0000 + loc*0x1000)
// =============================================================================

/// TIS MMIO base address (locality 0).
pub const TIS_BASE: usize = 0xFED4_0000;

/// Stride between TIS localities (4 KiB).
pub const TIS_LOCALITY_STRIDE: usize = 0x1000;

/// Base of TIS locality `loc` (0..=4).
#[must_use]
pub const fn tis_locality_base(loc: u8) -> usize {
    TIS_BASE + (loc as usize) * TIS_LOCALITY_STRIDE
}

/// `TPM_ACCESS` (RW) — request/release locality, see [`ACCESS_REQUEST_USE`].
pub const TIS_ACCESS: usize = 0x00;
/// `TPM_INT_ENABLE` (RW).
pub const TIS_INT_ENABLE: usize = 0x08;
/// `TPM_INT_STATUS` (RWC).
pub const TIS_INT_STATUS: usize = 0x10;
/// `TPM_INTF_CAPABILITY` (RO).
pub const TIS_INTF_CAPABILITY: usize = 0x14;
/// `TPM_STS` (RW) — status / command-ready / data-available.
pub const TIS_STS: usize = 0x18;
/// `TPM_DATA_FIFO` (RW) — command/response byte FIFO.
pub const TIS_DATA_FIFO: usize = 0x24;
/// `TPM_DID_VID` (RO) — device + vendor id.
pub const TIS_DID_VID: usize = 0xF00;

// --- TPM_ACCESS bits ---
/// `tpmEstablishment` (RO).
pub const ACCESS_ESTABLISHMENT: u8 = 1 << 0;
/// `requestUse` — write to request the locality.
pub const ACCESS_REQUEST_USE: u8 = 1 << 1;
/// `pendingRequest` (RO).
pub const ACCESS_PENDING_REQUEST: u8 = 1 << 2;
/// `activeLocality` — set when this locality owns the TPM; write to release.
pub const ACCESS_ACTIVE_LOCALITY: u8 = 1 << 5;
/// `tpmRegValidSts` (RO).
pub const ACCESS_VALID: u8 = 1 << 7;

// --- TPM_STS bits ---
/// `responseRetry` — write to re-send the response.
pub const STS_RESPONSE_RETRY: u32 = 1 << 1;
/// `expect` — TPM expects more command bytes.
pub const STS_EXPECT: u32 = 1 << 3;
/// `dataAvail` — response bytes are available to read.
pub const STS_DATA_AVAIL: u32 = 1 << 4;
/// `tpmGo` — write to start command execution.
pub const STS_GO: u32 = 1 << 5;
/// `commandReady` — TPM is ready to accept a command (write to set).
pub const STS_COMMAND_READY: u32 = 1 << 6;
/// `stsValid` — the status field is valid.
pub const STS_VALID: u32 = 1 << 7;

/// Extract the `burstCount` field (`TPM_STS[23:8]`) — how many bytes may be
/// written/read in one burst.
#[must_use]
pub const fn sts_burst_count(sts: u32) -> u16 {
    ((sts >> 8) & 0xFFFF) as u16
}

// =============================================================================
// CRB — Command Response Buffer interface
// =============================================================================

/// `TPM_LOC_STATE` (RO) — locality state.
pub const CRB_LOC_STATE: usize = 0x00;
/// `TPM_LOC_CTRL` (WO) — request/relinquish locality.
pub const CRB_LOC_CTRL: usize = 0x08;
/// `TPM_LOC_STS` (RO) — locality granted / been seized.
pub const CRB_LOC_STS: usize = 0x0C;
/// `TPM_CRB_CTRL_REQ` (RW) — command-ready / go-idle request.
pub const CRB_CTRL_REQ: usize = 0x40;
/// `TPM_CRB_CTRL_STS` (RO) — TPM status (error / idle).
pub const CRB_CTRL_STS: usize = 0x44;
/// `TPM_CRB_CTRL_START` (RW) — write 1 to start command execution.
pub const CRB_CTRL_START: usize = 0x4C;

// --- CRB_LOC_CTRL bits ---
/// `requestAccess` — request the locality.
pub const LOC_CTRL_REQUEST_ACCESS: u32 = 1 << 0;
/// `relinquish` — release the locality.
pub const LOC_CTRL_RELINQUISH: u32 = 1 << 1;

// --- CRB_LOC_STS bits ---
/// `Granted` — the requested locality was granted.
pub const LOC_STS_GRANTED: u32 = 1 << 0;

// --- CRB_CTRL_REQ bits ---
/// `cmdReady` — request the command/ready state.
pub const CTRL_REQ_COMMAND_READY: u32 = 1 << 0;
/// `goIdle` — request the idle state.
pub const CTRL_REQ_GO_IDLE: u32 = 1 << 1;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tis_locality_strides_by_4kib() {
        assert_eq!(tis_locality_base(0), 0xFED4_0000);
        assert_eq!(tis_locality_base(1), 0xFED4_1000);
        assert_eq!(tis_locality_base(4), 0xFED4_4000);
    }

    #[test]
    fn sts_burst_count_extracts_bits_23_8() {
        // burstCount = 0x0040 in [23:8], plus dataAvail + stsValid low bits.
        let sts = (0x0040 << 8) | STS_DATA_AVAIL | STS_VALID;
        assert_eq!(sts_burst_count(sts), 0x0040);
        assert!(sts & STS_DATA_AVAIL != 0);
    }

    #[test]
    fn access_and_ctrl_bits_are_distinct() {
        // Sanity: the bits we OR together at different sites do not collide.
        assert_ne!(ACCESS_REQUEST_USE, ACCESS_ACTIVE_LOCALITY);
        assert_ne!(LOC_CTRL_REQUEST_ACCESS, LOC_CTRL_RELINQUISH);
        assert_ne!(CTRL_REQ_COMMAND_READY, CTRL_REQ_GO_IDLE);
    }
}
