//! AHCI HBA register map (WS2-07.1) — generic + per-port, at the ABAR.
//!
//! Offsets and bit positions follow the *Serial ATA AHCI 1.3.1 Specification*
//! § 3 (Host Bus Adapter) and § 3.3 (Port registers). These are pure constants
//! and small helpers; the actual MMIO reads/writes against the ABAR live in the
//! bare-metal bring-up.

#![allow(
    clippy::doc_markdown,
    reason = "register mnemonics (PxCLB, GHC, …) read as identifiers without backticks"
)]

// =============================================================================
// Generic Host Control registers (ABAR + offset)
// =============================================================================

/// HBA Capabilities (RO). Encodes port count, command-slot count, 64-bit
/// addressing, and NCQ support.
pub const CAP: usize = 0x00;
/// Global HBA Control (RW): AHCI Enable, Interrupt Enable, HBA Reset.
pub const GHC: usize = 0x04;
/// Interrupt Status (RWC): one bit per port with a pending interrupt.
pub const IS: usize = 0x08;
/// Ports Implemented (RO): bitmask of populated port slots.
pub const PI: usize = 0x0C;
/// AHCI Version (RO).
pub const VS: usize = 0x10;
/// HBA Capabilities Extended (RO).
pub const CAP2: usize = 0x24;

// --- GHC bits ---
/// `GHC.HR` — HBA Reset (self-clearing once reset completes).
pub const GHC_HR: u32 = 1 << 0;
/// `GHC.IE` — global Interrupt Enable.
pub const GHC_IE: u32 = 1 << 1;
/// `GHC.AE` — AHCI Enable (must be set before touching port registers).
pub const GHC_AE: u32 = 1 << 31;

/// Extract the number of ports (`CAP.NP` + 1, field `CAP[4:0]`).
#[must_use]
pub const fn cap_num_ports(cap: u32) -> u8 {
    ((cap & 0x1F) as u8) + 1
}

/// Extract the number of command slots (`CAP.NCS` + 1, field `CAP[12:8]`).
#[must_use]
pub const fn cap_num_command_slots(cap: u32) -> u8 {
    (((cap >> 8) & 0x1F) as u8) + 1
}

/// `CAP.S64A` — 64-bit addressing supported (`CAP[31]`).
#[must_use]
pub const fn cap_supports_64bit(cap: u32) -> bool {
    cap & (1 << 31) != 0
}

/// `CAP.SNCQ` — native command queuing supported (`CAP[30]`).
#[must_use]
pub const fn cap_supports_ncq(cap: u32) -> bool {
    cap & (1 << 30) != 0
}

// =============================================================================
// Per-port registers (ABAR + 0x100 + port * 0x80)
// =============================================================================

/// First per-port register block offset.
pub const PORT_BASE: usize = 0x100;
/// Stride between consecutive port register blocks.
pub const PORT_STRIDE: usize = 0x80;

/// Byte offset of port `n`'s register block within the ABAR.
#[must_use]
pub const fn port_offset(port: u8) -> usize {
    PORT_BASE + (port as usize) * PORT_STRIDE
}

/// `PxCLB` — Command List Base Address (low 32 bits), 1 KiB-aligned.
pub const PX_CLB: usize = 0x00;
/// `PxCLBU` — Command List Base Address (high 32 bits).
pub const PX_CLBU: usize = 0x04;
/// `PxFB` — FIS Base Address (low 32 bits), 256-byte-aligned.
pub const PX_FB: usize = 0x08;
/// `PxFBU` — FIS Base Address (high 32 bits).
pub const PX_FBU: usize = 0x0C;
/// `PxIS` — Port Interrupt Status (RWC).
pub const PX_IS: usize = 0x10;
/// `PxIE` — Port Interrupt Enable.
pub const PX_IE: usize = 0x14;
/// `PxCMD` — Port Command and Status.
pub const PX_CMD: usize = 0x18;
/// `PxTFD` — Task File Data (busy/error status from the device).
pub const PX_TFD: usize = 0x20;
/// `PxSIG` — Device Signature.
pub const PX_SIG: usize = 0x24;
/// `PxSSTS` — SATA Status (SCR0: SStatus).
pub const PX_SSTS: usize = 0x28;
/// `PxSCTL` — SATA Control (SCR2: SControl).
pub const PX_SCTL: usize = 0x2C;
/// `PxSERR` — SATA Error (SCR1: SError, RWC).
pub const PX_SERR: usize = 0x30;
/// `PxSACT` — SATA Active (set per NCQ tag before issue).
pub const PX_SACT: usize = 0x34;
/// `PxCI` — Command Issue (set bit `slot` to issue, cleared on completion).
pub const PX_CI: usize = 0x38;

// --- PxCMD bits ---
/// `PxCMD.ST` — Start (enable command list processing).
pub const PX_CMD_ST: u32 = 1 << 0;
/// `PxCMD.FRE` — FIS Receive Enable.
pub const PX_CMD_FRE: u32 = 1 << 4;
/// `PxCMD.FR` — FIS Receive Running (RO).
pub const PX_CMD_FR: u32 = 1 << 14;
/// `PxCMD.CR` — Command List Running (RO).
pub const PX_CMD_CR: u32 = 1 << 15;

// --- PxSSTS.DET / signatures ---
/// `PxSSTS.DET` value for "device present and PHY communication established".
pub const SSTS_DET_PRESENT: u32 = 0x3;

/// Extract `PxSSTS.DET` (field `[3:0]`).
#[must_use]
pub const fn ssts_det(ssts: u32) -> u32 {
    ssts & 0xF
}

/// `true` when a port is occupied by a communicating device.
#[must_use]
pub const fn port_device_present(ssts: u32) -> bool {
    ssts_det(ssts) == SSTS_DET_PRESENT
}

/// `PxSIG` value for a non-packet SATA drive (the only signature WS2-07
/// targets).
pub const SIG_SATA: u32 = 0x0000_0101;
/// `PxSIG` value for an ATAPI device (handled as "unsupported" for now).
pub const SIG_ATAPI: u32 = 0xEB14_0101;

/// Iterate the implemented-port indices from a `PI` bitmask, in ascending
/// order (host helper for the bring-up's enumeration).
pub fn implemented_ports(pi: u32) -> impl Iterator<Item = u8> {
    (0u8..32).filter(move |p| pi & (1 << p) != 0)
}

#[cfg(test)]
mod tests {
    extern crate alloc;

    use alloc::vec::Vec;

    use super::*;

    #[test]
    fn cap_fields_decode() {
        // NP=3 (→4 ports), NCS=0x1F (→32 slots), S64A + SNCQ set.
        let cap = 0x03 | (0x1F << 8) | (1 << 30) | (1 << 31);
        assert_eq!(cap_num_ports(cap), 4);
        assert_eq!(cap_num_command_slots(cap), 32);
        assert!(cap_supports_64bit(cap));
        assert!(cap_supports_ncq(cap));
    }

    #[test]
    fn port_offsets_follow_spec_stride() {
        assert_eq!(port_offset(0), 0x100);
        assert_eq!(port_offset(1), 0x180);
        assert_eq!(port_offset(2), 0x200);
    }

    #[test]
    fn ssts_detects_present_device() {
        assert!(port_device_present(0x0123)); // DET=3
        assert!(!port_device_present(0x0120)); // DET=0
        assert_eq!(ssts_det(0x0123), 3);
    }

    #[test]
    fn implemented_ports_lists_set_bits() {
        // ports 0, 2, 5 implemented.
        let pi = (1 << 0) | (1 << 2) | (1 << 5);
        let ports: Vec<u8> = implemented_ports(pi).collect();
        assert_eq!(ports, [0, 2, 5]);
    }
}
