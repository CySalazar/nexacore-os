//! iwlwifi CSR register map and host-command (`HCMD`) header (WS2-11.1).
//!
//! Control/Status Register (CSR) offsets from the device's MMIO BAR, the reset
//! and `GP_CNTRL` handshake bits the driver toggles to bring the MAC out of
//! reset, the interrupt-cause bits, and the 4-byte command header the driver
//! prepends to every host command queued to the device.
//!
//! Offsets/bit values match the Linux `iwlwifi` `iwl-csr.h` definitions (the
//! de-facto reference for this chipset family). Issuing the MMIO writes and
//! draining the queues is device-side (WS2-11.3); the layouts here are pure and
//! host-tested.

// The command header packs a u8/u8/le16; the byte assembly is exact.
#![allow(clippy::cast_possible_truncation)]

// ===========================================================================
// CSR register offsets (from the MMIO BAR base)
// ===========================================================================

/// `CSR_HW_IF_CONFIG_REG` — hardware interface configuration / revision.
pub const CSR_HW_IF_CONFIG_REG: usize = 0x000;
/// `CSR_INT_COALESCING` — interrupt coalescing timer.
pub const CSR_INT_COALESCING: usize = 0x004;
/// `CSR_INT` — interrupt cause (write-1-to-clear).
pub const CSR_INT: usize = 0x008;
/// `CSR_INT_MASK` — interrupt enable mask.
pub const CSR_INT_MASK: usize = 0x00C;
/// `CSR_FH_INT_STATUS` — flow-handler (DMA) interrupt status.
pub const CSR_FH_INT_STATUS: usize = 0x010;
/// `CSR_RESET` — software reset / stop-master control.
pub const CSR_RESET: usize = 0x020;
/// `CSR_GP_CNTRL` — general-purpose control: clock-ready / MAC-access handshake.
pub const CSR_GP_CNTRL: usize = 0x024;
/// `CSR_HW_REV` — hardware step/dash revision.
pub const CSR_HW_REV: usize = 0x028;
/// `CSR_EEPROM_REG` — EEPROM/OTP read interface.
pub const CSR_EEPROM_REG: usize = 0x02C;
/// `CSR_GIO_REG` — general I/O (L0s/L1 PCIe power-state bits).
pub const CSR_GIO_REG: usize = 0x03C;
/// `CSR_UCODE_DRV_GP1` — uCode/driver general-purpose handshake register 1.
pub const CSR_UCODE_DRV_GP1: usize = 0x054;
/// `CSR_LED_REG` — activity LED control.
pub const CSR_LED_REG: usize = 0x094;
/// `CSR_DRAM_INT_TBL_REG` — interrupt-coalescing DRAM table pointer.
pub const CSR_DRAM_INT_TBL_REG: usize = 0x0A0;
/// `CSR_GP_CNTRL` alias kept for the firmware-revision read path.
pub const CSR_HW_REV_WA_REG: usize = 0x22C;

// ===========================================================================
// CSR_RESET bits
// ===========================================================================

/// `CSR_RESET.SW_RESET` — write to trigger a software reset of the device.
pub const CSR_RESET_REG_FLAG_SW_RESET: u32 = 1 << 7;
/// `CSR_RESET.MASTER_DISABLED` — set by HW once the bus master has stopped.
pub const CSR_RESET_REG_FLAG_MASTER_DISABLED: u32 = 1 << 8;
/// `CSR_RESET.STOP_MASTER` — write to request the bus master to stop.
pub const CSR_RESET_REG_FLAG_STOP_MASTER: u32 = 1 << 9;
/// `CSR_RESET.FORCE_NMI` — force a firmware NMI (debug).
pub const CSR_RESET_REG_FLAG_FORCE_NMI: u32 = 1 << 1;

// ===========================================================================
// CSR_GP_CNTRL bits (MAC clock / access handshake)
// ===========================================================================

/// `CSR_GP_CNTRL.MAC_CLOCK_READY` — MAC clock is up; registers are accessible.
pub const CSR_GP_CNTRL_REG_FLAG_MAC_CLOCK_READY: u32 = 1 << 0;
/// `CSR_GP_CNTRL.INIT_DONE` — driver tells HW init is complete.
pub const CSR_GP_CNTRL_REG_FLAG_INIT_DONE: u32 = 1 << 2;
/// `CSR_GP_CNTRL.MAC_ACCESS_REQ` — driver requests access to the MAC clock.
pub const CSR_GP_CNTRL_REG_FLAG_MAC_ACCESS_REQ: u32 = 1 << 3;
/// `CSR_GP_CNTRL.GOING_TO_SLEEP` — HW indicates it is entering low power.
pub const CSR_GP_CNTRL_REG_FLAG_GOING_TO_SLEEP: u32 = 1 << 4;

// ===========================================================================
// CSR_INT cause bits
// ===========================================================================

/// `CSR_INT.FH_RX` — flow-handler RX DMA completed (bit 31).
pub const CSR_INT_BIT_FH_RX: u32 = 1 << 31;
/// `CSR_INT.HW_ERR` — hardware error (bit 29).
pub const CSR_INT_BIT_HW_ERR: u32 = 1 << 29;
/// `CSR_INT.FH_TX` — flow-handler TX DMA completed (bit 27).
pub const CSR_INT_BIT_FH_TX: u32 = 1 << 27;
/// `CSR_INT.SW_ERR` — firmware/software error (bit 25).
pub const CSR_INT_BIT_SW_ERR: u32 = 1 << 25;
/// `CSR_INT.RF_KILL` — RF-kill switch toggled (bit 7).
pub const CSR_INT_BIT_RF_KILL: u32 = 1 << 7;
/// `CSR_INT.ALIVE` — uCode signalled it is alive (bit 0).
pub const CSR_INT_BIT_ALIVE: u32 = 1 << 0;

/// `true` if the device `STATUS`/`GP_CNTRL` value shows the MAC clock is ready
/// (the precondition for touching most other registers).
#[must_use]
pub const fn mac_clock_ready(gp_cntrl: u32) -> bool {
    gp_cntrl & CSR_GP_CNTRL_REG_FLAG_MAC_CLOCK_READY != 0
}

/// `true` once the bus master has stopped after a `STOP_MASTER` request — the
/// driver polls `CSR_RESET` for this before continuing the reset sequence.
#[must_use]
pub const fn master_stopped(reset: u32) -> bool {
    reset & CSR_RESET_REG_FLAG_MASTER_DISABLED != 0
}

// ===========================================================================
// Host-command (HCMD) header
// ===========================================================================

/// Size in bytes of the host-command header ([`build_cmd_header`]).
pub const CMD_HEADER_LEN: usize = 4;

/// `iwl_cmd_header.flags` bit: response/abort markers live here; bit 7 marks an
/// internally-generated command.
pub const CMD_FLAG_INTERNAL: u8 = 1 << 7;

/// Selected host-command opcodes (`iwl-commands.h`). The driver issues these on
/// the command queue; only the ids needed by the scan/assoc path are pinned.
pub mod cmd {
    /// `REPLY_ALIVE` — uCode alive notification.
    pub const REPLY_ALIVE: u8 = 0x01;
    /// `REPLY_RXON` — program the RX-on configuration (BSSID, channel, filters).
    pub const REPLY_RXON: u8 = 0x10;
    /// `REPLY_TX` — transmit a frame.
    pub const REPLY_TX: u8 = 0x1C;
    /// `REPLY_SCAN_CMD` — start a scan.
    pub const REPLY_SCAN_CMD: u8 = 0x80;
    /// `REPLY_SCAN_COMPLETE` — scan finished notification.
    pub const REPLY_SCAN_COMPLETE: u8 = 0x84;
    /// `REPLY_ADD_STA` — add/modify a station (peer) entry.
    pub const REPLY_ADD_STA: u8 = 0x18;
}

/// Build the 4-byte host-command header: command id, flags, and a 16-bit
/// little-endian sequence number the driver assigns.
///
/// # Example
///
/// ```
/// use nexacore_driver_wifi::regs::{build_cmd_header, cmd, parse_cmd_header};
///
/// let h = build_cmd_header(cmd::REPLY_SCAN_CMD, 0, 0x1234);
/// let (id, flags, seq) = parse_cmd_header(&h).unwrap();
/// assert_eq!(id, cmd::REPLY_SCAN_CMD);
/// assert_eq!(flags, 0);
/// assert_eq!(seq, 0x1234);
/// ```
#[must_use]
pub fn build_cmd_header(cmd_id: u8, flags: u8, sequence: u16) -> [u8; CMD_HEADER_LEN] {
    let [lo, hi] = sequence.to_le_bytes();
    [cmd_id, flags, lo, hi]
}

/// Parse a host-command header, returning `(cmd_id, flags, sequence)` or `None`
/// if the buffer is shorter than [`CMD_HEADER_LEN`].
#[must_use]
pub fn parse_cmd_header(buf: &[u8]) -> Option<(u8, u8, u16)> {
    let hdr = buf.get(..CMD_HEADER_LEN)?;
    let cmd_id = *hdr.first()?;
    let flags = *hdr.get(1)?;
    let lo = *hdr.get(2)?;
    let hi = *hdr.get(3)?;
    Some((cmd_id, flags, u16::from_le_bytes([lo, hi])))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reset_offset_matches_reference() {
        // A pinned offset guards against an accidental edit moving the reset
        // register (which would brick the bring-up sequence).
        assert_eq!(CSR_RESET, 0x020);
        assert_eq!(CSR_GP_CNTRL, 0x024);
    }

    #[test]
    fn gp_cntrl_clock_ready_decode() {
        assert!(mac_clock_ready(CSR_GP_CNTRL_REG_FLAG_MAC_CLOCK_READY));
        assert!(!mac_clock_ready(0));
    }

    #[test]
    fn master_stopped_decode() {
        assert!(master_stopped(CSR_RESET_REG_FLAG_MASTER_DISABLED));
        assert!(!master_stopped(CSR_RESET_REG_FLAG_STOP_MASTER));
    }

    #[test]
    fn cmd_header_round_trips() {
        let h = build_cmd_header(cmd::REPLY_ADD_STA, CMD_FLAG_INTERNAL, 0xBEEF);
        assert_eq!(h.len(), CMD_HEADER_LEN);
        let (id, flags, seq) = parse_cmd_header(&h).unwrap();
        assert_eq!(id, cmd::REPLY_ADD_STA);
        assert_eq!(flags, CMD_FLAG_INTERNAL);
        assert_eq!(seq, 0xBEEF);
    }

    #[test]
    fn cmd_header_parse_rejects_short_buffer() {
        assert!(parse_cmd_header(&[0x01, 0x02, 0x03]).is_none());
        assert!(parse_cmd_header(&[]).is_none());
    }

    #[test]
    fn int_bits_are_distinct() {
        let bits = [
            CSR_INT_BIT_FH_RX,
            CSR_INT_BIT_HW_ERR,
            CSR_INT_BIT_FH_TX,
            CSR_INT_BIT_SW_ERR,
            CSR_INT_BIT_RF_KILL,
            CSR_INT_BIT_ALIVE,
        ];
        for (i, a) in bits.iter().enumerate() {
            for b in bits.iter().skip(i + 1) {
                assert_ne!(a, b, "interrupt cause bits must be distinct");
            }
        }
    }
}
