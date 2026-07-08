//! xHCI controller register set offsets and field accessors.
//!
//! Covers the four register spaces of an xHCI controller (xHCI spec § 5):
//!
//! | Space | Base address | Key registers |
//! |-------|-------------|---------------|
//! | Capability | BAR + 0 | `CAPLENGTH`, `HCIVERSION`, `HCSPARAMS1/2`, `HCCPARAMS1`, `DBOFF`, `RTSOFF` |
//! | Operational | BAR + `CAPLENGTH` | `USBCMD`, `USBSTS`, `PAGESIZE`, `CRCR`, `DCBAAP`, `CONFIG`, `PORTSC[n]` |
//! | Runtime | BAR + `RTSOFF` | Interrupter 0: `IMAN`, `IMOD`, `ERSTSZ`, `ERSTBA`, `ERDP` |
//! | Doorbell | BAR + `DBOFF` | One `u32` per slot; slot 0 = command ring, 1.. = device endpoints |
//!
//! ## Address-space contract
//!
//! All offsets are byte-relative to the base of BAR0 (mapped uncached /
//! write-combining inhibited). The [`operational_base`], [`port_reg_offset`],
//! [`doorbell_offset`], and [`interrupter_offset`] helpers compute derived
//! offsets from the capability-register values; all use checked arithmetic
//! so that a malformed register value cannot overflow `usize`.
//!
//! ## Security note
//!
//! No raw pointers are created in this module. All register access is
//! mediated by the [`crate::MmioBackend`] / [`crate::MmioReadBackend`]
//! trait seam, which the image crate implements with `volatile_write` /
//! `volatile_read` against the mapped BAR.

// =============================================================================
// Capability register offsets (xHCI § 5.3)
// =============================================================================

/// `CAPLENGTH` — Capability Registers Length (u8). xHCI § 5.3.1, byte offset 0.
///
/// The byte offset from the base of the BAR to the Operational Registers.
/// Used by [`operational_base`] to locate the operational register space.
pub const CAPLENGTH_OFFSET: usize = 0x00;

/// `HCIVERSION` — Host Controller Interface Version Number (u16). xHCI § 5.3.2,
/// byte offset 0x02.
///
/// Encodes the BCD version of the xHCI specification implemented by this
/// controller. Version 1.0.0 → `0x0100`; version 1.2.0 → `0x0120`.
pub const HCIVERSION_OFFSET: usize = 0x02;

/// `HCSPARAMS1` — Structural Parameters 1 (u32). xHCI § 5.3.3, byte offset 0x04.
///
/// Fields: `MaxSlots` (bits 7:0), `MaxIntrs` (bits 18:8), `MaxPorts` (bits 31:24).
/// The driver reads `MaxSlots` to set `CONFIG.MaxSlotsEn` and `MaxPorts` to
/// iterate root-hub ports during enumeration.
pub const HCSPARAMS1_OFFSET: usize = 0x04;

/// `HCSPARAMS2` — Structural Parameters 2 (u32). xHCI § 5.3.4, byte offset 0x08.
///
/// Fields: `IST` (bits 3:0), `ERST Max` (bits 7:4), `Max Scratchpad Bufs Hi`
/// (bits 25:21), `SPR` (bit 26), `Max Scratchpad Bufs Lo` (bits 31:27).
pub const HCSPARAMS2_OFFSET: usize = 0x08;

/// `HCCPARAMS1` — Capability Parameters 1 (u32). xHCI § 5.3.6, byte offset 0x10.
///
/// Key fields: `AC64` (bit 0) — 64-bit addressing; `CSZ` (bit 2) — context
/// size (`0` = 32-byte contexts, `1` = 64-byte contexts). The driver checks
/// `CSZ` at bring-up to parameterise the DCBAA and context allocations.
pub const HCCPARAMS1_OFFSET: usize = 0x10;

/// `DBOFF` — Doorbell Array Offset (u32). xHCI § 5.3.7, byte offset 0x14.
///
/// The byte offset from the BAR base to the doorbell array, **4-byte aligned**
/// (bits 1:0 are reserved and must be ignored). Use [`doorbell_base`] to
/// compute the actual offset after masking.
pub const DBOFF_OFFSET: usize = 0x14;

/// `RTSOFF` — Runtime Register Space Offset (u32). xHCI § 5.3.8, byte offset 0x18.
///
/// The byte offset from the BAR base to the Runtime Register Space, **32-byte
/// aligned** (bits 4:0 are reserved). Use [`runtime_base`] to compute the
/// actual offset after masking.
pub const RTSOFF_OFFSET: usize = 0x18;

// =============================================================================
// Capability register field extractors
// =============================================================================

/// Extract `CAPLENGTH` from the 32-bit word at offset 0x00.
///
/// The capability register block starts at BAR+0 as a single u32 that packs
/// `CAPLENGTH` (u8, bits 7:0) and `HCIVERSION` (u16, bits 31:16). This
/// extractor isolates the lower 8 bits. The returned value is the byte offset
/// to the operational registers: see [`operational_base`].
///
/// # Example
///
/// ```rust
/// use nexacore_driver_xhci::regs::caplength;
/// // CAPLENGTH = 0x20 (32 bytes), HCIVERSION = 0x0100 in the combined word.
/// assert_eq!(caplength(0x0100_0020), 0x20);
/// ```
#[must_use]
pub const fn caplength(cap_word: u32) -> u8 {
    (cap_word & 0xFF) as u8
}

/// Extract `HCIVERSION` from the 32-bit word at offset 0x00 (same register
/// as `CAPLENGTH`).
///
/// Bits 31:16. Version 1.0.0 reports `0x0100`; version 1.2.0 reports `0x0120`.
///
/// # Example
///
/// ```rust
/// use nexacore_driver_xhci::regs::hciversion;
/// assert_eq!(hciversion(0x0100_0020), 0x0100);
/// ```
#[must_use]
pub const fn hciversion(cap_word: u32) -> u16 {
    (cap_word >> 16) as u16
}

/// Extract `HCSPARAMS1.MaxSlots` (bits 7:0).
///
/// The maximum number of device slots supported by the controller. The driver
/// programs `CONFIG.MaxSlotsEn` to this value (or the manifest ceiling,
/// whichever is lower) during bring-up per xHCI § 4.2.
///
/// # Example
///
/// ```rust
/// use nexacore_driver_xhci::regs::hcsparams1_max_slots;
/// assert_eq!(hcsparams1_max_slots(0x0000_0020), 0x20); // MaxSlots=32
/// ```
#[must_use]
pub const fn hcsparams1_max_slots(hcsparams1: u32) -> u8 {
    (hcsparams1 & 0xFF) as u8
}

/// Extract `HCSPARAMS1.MaxIntrs` (bits 18:8).
///
/// The maximum number of interrupters supported. TASK-26 uses interrupter 0
/// only; this value is read to verify the controller supports at least one.
///
/// # Example
///
/// ```rust
/// use nexacore_driver_xhci::regs::hcsparams1_max_intrs;
/// // MaxIntrs field at bits 18:8. Bit 8 set → MaxIntrs=1.
/// assert_eq!(hcsparams1_max_intrs(0x0000_0100), 1);
/// ```
#[must_use]
pub const fn hcsparams1_max_intrs(hcsparams1: u32) -> u16 {
    ((hcsparams1 >> 8) & 0x7FF) as u16
}

/// Extract `HCSPARAMS1.MaxPorts` (bits 31:24).
///
/// The number of root-hub ports. The enumeration state machine iterates ports
/// `1..=MaxPorts` probing for connected devices per xHCI § 4.3.
///
/// # Example
///
/// ```rust
/// use nexacore_driver_xhci::regs::hcsparams1_max_ports;
/// assert_eq!(hcsparams1_max_ports(0x0400_0000), 4);
/// ```
#[must_use]
pub const fn hcsparams1_max_ports(hcsparams1: u32) -> u8 {
    ((hcsparams1 >> 24) & 0xFF) as u8
}

/// Extract `HCCPARAMS1.AC64` (bit 0) — 64-bit addressing capability.
///
/// When `true` the controller supports 64-bit physical addresses for all
/// xHCI data structures. NexaCore OS always uses 64-bit addresses in the
/// DCBAA and ring base pointers.
///
/// # Example
///
/// ```rust
/// use nexacore_driver_xhci::regs::hccparams1_ac64;
/// assert!(hccparams1_ac64(0x0000_0001));
/// assert!(!hccparams1_ac64(0x0000_0000));
/// ```
#[must_use]
pub const fn hccparams1_ac64(hccparams1: u32) -> bool {
    (hccparams1 & 0x1) != 0
}

/// Extract `HCCPARAMS1.CSZ` (bit 2) — context size.
///
/// `false` = 32-byte contexts (32B slot + 32B endpoint contexts).
/// `true` = 64-byte contexts.
///
/// The driver uses this at bring-up to parameterise the DCBAA and all context
/// allocations in the DMA arena. See [`context`](crate::context) module.
///
/// # Example
///
/// ```rust
/// use nexacore_driver_xhci::regs::hccparams1_csz;
/// assert!(!hccparams1_csz(0x0000_0001)); // AC64 only, CSZ=0
/// assert!(hccparams1_csz(0x0000_0004)); // CSZ=1
/// ```
#[must_use]
pub const fn hccparams1_csz(hccparams1: u32) -> bool {
    (hccparams1 & 0x4) != 0
}

// =============================================================================
// Derived-base helpers
// =============================================================================

/// Compute the byte offset from BAR base to the Operational Register Space.
///
/// `CAPLENGTH` is the byte offset (xHCI § 5.3.1); values `< 0x20` are
/// reserved by the spec (the capability registers themselves span at least
/// 32 bytes). Returns `None` if `caplength_val < 0x20` (malformed controller)
/// or if the addition overflows `usize` (defence-in-depth).
///
/// # Example
///
/// ```rust
/// use nexacore_driver_xhci::regs::operational_base;
/// assert_eq!(operational_base(0x20), Some(0x20));
/// assert!(operational_base(0x10).is_none()); // too small — reserved
/// ```
#[must_use]
pub const fn operational_base(caplength_val: u8) -> Option<usize> {
    // xHCI § 5.3.1: CAPLENGTH values below 0x20 are reserved.
    if (caplength_val as usize) < 0x20 {
        return None;
    }
    Some(caplength_val as usize)
}

/// Compute the byte offset from BAR base to the doorbell array.
///
/// `DBOFF` bits 1:0 are reserved (always `0`); the helper masks them.
/// Returns `None` on overflow (defence-in-depth).
///
/// # Example
///
/// ```rust
/// use nexacore_driver_xhci::regs::doorbell_base;
/// // DBOFF = 0x0000_2000 → doorbell array at offset 0x2000.
/// assert_eq!(doorbell_base(0x0000_2000), Some(0x2000));
/// // Bits 1:0 are reserved and must be masked.
/// assert_eq!(doorbell_base(0x0000_2003), Some(0x2000));
/// ```
#[must_use]
pub const fn doorbell_base(dboff: u32) -> Option<usize> {
    let base = (dboff & !0x3) as usize;
    // A zero doorbell base would overlap the capability registers —
    // guard against obviously-invalid controller firmware.
    if base == 0 {
        return None;
    }
    Some(base)
}

/// Compute the byte offset from BAR base to the Runtime Register Space.
///
/// `RTSOFF` bits 4:0 are reserved; the helper masks them. Returns `None`
/// on overflow or a zero/too-small base.
///
/// # Example
///
/// ```rust
/// use nexacore_driver_xhci::regs::runtime_base;
/// assert_eq!(runtime_base(0x0000_3000), Some(0x3000));
/// assert_eq!(runtime_base(0x0000_3001), Some(0x3000)); // masked
/// ```
#[must_use]
pub const fn runtime_base(rtsoff: u32) -> Option<usize> {
    let base = (rtsoff & !0x1F) as usize;
    if base == 0 {
        return None;
    }
    Some(base)
}

/// Compute the byte offset of the port status/control register for port `n`
/// (1-based, per xHCI § 5.4.8), relative to the Operational Register base.
///
/// `PORT_SC_BASE_OPERATIONAL_OFFSET + (port - 1) * 16`. Returns `None` if
/// `port == 0` (ports are 1-based) or if the arithmetic overflows `usize`.
///
/// # Example
///
/// ```rust
/// use nexacore_driver_xhci::regs::{PORT_SC_BASE_OPERATIONAL_OFFSET, port_reg_offset};
/// assert_eq!(port_reg_offset(1), Some(PORT_SC_BASE_OPERATIONAL_OFFSET));
/// assert_eq!(
///     port_reg_offset(2),
///     Some(PORT_SC_BASE_OPERATIONAL_OFFSET + 16)
/// );
/// assert!(port_reg_offset(0).is_none());
/// ```
#[must_use]
pub const fn port_reg_offset(port: u8) -> Option<usize> {
    if port == 0 {
        return None;
    }
    let index = (port as usize) - 1;
    let Some(scaled) = index.checked_mul(16) else {
        return None;
    };
    scaled.checked_add(PORT_SC_BASE_OPERATIONAL_OFFSET)
}

/// Compute the byte offset of doorbell register for slot `slot_id`,
/// relative to the BAR-base doorbell array start (`DBOFF`).
///
/// Slot 0 is the command ring doorbell. Slots 1..=`MaxSlots` are device
/// endpoints. Each doorbell is a 4-byte u32. Returns `None` on overflow.
///
/// # Example
///
/// ```rust
/// use nexacore_driver_xhci::regs::doorbell_offset;
/// assert_eq!(doorbell_offset(0), Some(0)); // command ring
/// assert_eq!(doorbell_offset(1), Some(4)); // slot 1
/// assert_eq!(doorbell_offset(2), Some(8));
/// ```
#[must_use]
pub const fn doorbell_offset(slot_id: u8) -> Option<usize> {
    (slot_id as usize).checked_mul(4)
}

/// Compute the byte offset of interrupter `n`'s register set, relative to
/// the Runtime Register Space base (`RTSOFF`).
///
/// Per xHCI § 5.5.2: the interrupter array starts at `RTSOFF + 0x20`; each
/// interrupter occupies 32 bytes. Returns `None` on overflow.
///
/// # Example
///
/// ```rust
/// use nexacore_driver_xhci::regs::interrupter_offset;
/// assert_eq!(interrupter_offset(0), Some(0x20));
/// assert_eq!(interrupter_offset(1), Some(0x40));
/// ```
#[must_use]
pub const fn interrupter_offset(n: u16) -> Option<usize> {
    let Some(scaled) = (n as usize).checked_mul(32) else {
        return None;
    };
    scaled.checked_add(RUNTIME_INTERRUPTER_ARRAY_OFFSET)
}

// =============================================================================
// Operational register offsets (relative to operational base)  xHCI § 5.4
// =============================================================================

/// `USBCMD` — USB Command register (u32). xHCI § 5.4.1, operational +0x00.
///
/// Key bits: `R/S` (bit 0) — run/stop; `HCRST` (bit 1) — host controller reset;
/// `INTE` (bit 2) — interrupter enable; `HSEE` (bit 3) — host system error enable.
pub const USBCMD_OFFSET: usize = 0x00;

/// `USBSTS` — USB Status register (u32). xHCI § 5.4.2, operational +0x04.
///
/// Key bits: `HCH` (bit 0) — halted; `HSE` (bit 2) — host system error;
/// `EINT` (bit 3) — event interrupt; `PCD` (bit 4) — port change detect;
/// `CNR` (bit 11) — controller not ready.
pub const USBSTS_OFFSET: usize = 0x04;

/// `PAGESIZE` — Page Size register (u32). xHCI § 5.4.3, operational +0x08.
///
/// Bit n set means the controller supports `2^(n+12)` byte pages. Bit 0 = 4 KiB.
pub const PAGESIZE_OFFSET: usize = 0x08;

/// `CRCR` — Command Ring Control Register (u64). xHCI § 5.4.5, operational +0x18.
///
/// Bits: `RCS` (bit 0) — ring cycle state (initial producer cycle bit);
/// `CS` (bit 1) — command stop; `CA` (bit 2) — command abort;
/// `CRR` (bit 3) — command ring running (RO);
/// bits 63:6 — command ring dequeue pointer (64-byte aligned).
pub const CRCR_OFFSET: usize = 0x18;

/// `DCBAAP` — Device Context Base Address Array Pointer (u64). xHCI § 5.4.6,
/// operational +0x30.
///
/// 64-bit physical (IOVA) address of the DCBAA. Must be 64-byte aligned.
pub const DCBAAP_OFFSET: usize = 0x30;

/// `CONFIG` — Configure register (u32). xHCI § 5.4.7, operational +0x38.
///
/// Bits 7:0 = `MaxSlotsEn` — the driver programs this to the value read from
/// `HCSPARAMS1.MaxSlots` (capped by the manifest ceiling).
pub const CONFIG_OFFSET: usize = 0x38;

/// Byte offset of port 1's `PORTSC` register relative to the Operational base.
/// xHCI § 5.4.8: port registers start at operational offset `0x400`.
///
/// Port `n` (1-based) has `PORTSC` at `PORT_SC_BASE_OPERATIONAL_OFFSET + (n-1)*16`.
/// Use [`port_reg_offset`] to compute the offset for a given port number.
pub const PORT_SC_BASE_OPERATIONAL_OFFSET: usize = 0x400;

// =============================================================================
// USBCMD field bits (xHCI § 5.4.1)
// =============================================================================

/// `USBCMD.R/S` — Run/Stop (bit 0). Setting `1` starts the controller;
/// clearing to `0` stops it. The driver must wait for `USBSTS.HCH` to clear
/// after setting this bit.
pub const USBCMD_RUN_STOP: u32 = 1 << 0;

/// `USBCMD.HCRST` — Host Controller Reset (bit 1). Writing `1` initiates a
/// software reset. The bit clears when the reset is complete. The driver must
/// also wait for `USBSTS.CNR = 0` after the bit clears.
pub const USBCMD_HCRST: u32 = 1 << 1;

/// `USBCMD.INTE` — Interrupter Enable (bit 2). Must be set alongside
/// `IMAN.IE` on interrupter 0 for MSI/MSI-X delivery.
pub const USBCMD_INTE: u32 = 1 << 2;

// =============================================================================
// USBSTS field bits (xHCI § 5.4.2)
// =============================================================================

/// `USBSTS.HCH` — Host Controller Halted (bit 0). Set when `USBCMD.R/S = 0`
/// and the controller has stopped execution. The bring-up sequence waits for
/// this bit to clear after setting `USBCMD.R/S = 1`.
pub const USBSTS_HCH: u32 = 1 << 0;

/// `USBSTS.HSE` — Host System Error (bit 2). Indicates a severe error;
/// the driver must treat this as a fatal condition and reset the controller.
pub const USBSTS_HSE: u32 = 1 << 2;

/// `USBSTS.CNR` — Controller Not Ready (bit 11).
///
/// Set during power-on or reset; the driver must wait for this bit to clear
/// before issuing any writes to the operational registers. This is the first
/// poll in the bring-up sequence.
pub const USBSTS_CNR: u32 = 1 << 11;

// =============================================================================
// CRCR field bits (xHCI § 5.4.5)
// =============================================================================

/// `CRCR.RCS` — Ring Cycle State (bit 0).
///
/// The initial producer cycle bit for the command ring. Set to `1` at
/// initialisation (the first TRB on the ring will have cycle bit = 1,
/// matching this initial value).
pub const CRCR_RCS: u64 = 1 << 0;

/// Mask to extract / set the 64-bit command ring dequeue pointer from `CRCR`.
/// The pointer must be 64-byte aligned; bits 5:0 carry the control bits.
pub const CRCR_PTR_MASK: u64 = !0x3F;

// =============================================================================
// PORTSC field bits (xHCI § 5.4.8)
// =============================================================================

/// `PORTSC.CCS` — Current Connect Status (bit 0, RO). `1` = a device is
/// connected to this port.
pub const PORTSC_CCS: u32 = 1 << 0;

/// `PORTSC.PED` — Port Enabled/Disabled (bit 1). `1` = port is enabled.
/// USB 3 ports are enabled by hardware after reset; USB 2 ports require
/// explicit software reset and enumeration.
pub const PORTSC_PED: u32 = 1 << 1;

/// `PORTSC.PR` — Port Reset (bit 4, RW1S). Writing `1` asserts reset on the
/// port. The bit clears when reset is complete.
pub const PORTSC_PR: u32 = 1 << 4;

/// `PORTSC.PLS` — Port Link State (bits 8:5). The 4-bit link state field.
///
/// `0x0` = U0 (active); `0x5` = `RxDetect` (disconnected); `0x7` = Polling.
pub const PORTSC_PLS_SHIFT: u32 = 5;

/// Mask for the `PORTSC.PLS` 4-bit field after right-shifting by
/// [`PORTSC_PLS_SHIFT`].
pub const PORTSC_PLS_MASK: u32 = 0xF;

/// `PORTSC.PP` — Port Power (bit 9). Must be `1` for the port to function.
pub const PORTSC_PP: u32 = 1 << 9;

/// `PORTSC.PORT_SPEED` — Port Speed (bits 13:10, RO). The USB speed of the
/// connected device after reset: 1=Full, 2=Low, 3=High, 4=Super.
pub const PORTSC_PORT_SPEED_SHIFT: u32 = 10;

/// Mask for the `PORTSC.PORT_SPEED` 4-bit field after right-shifting by
/// [`PORTSC_PORT_SPEED_SHIFT`].
pub const PORTSC_PORT_SPEED_MASK: u32 = 0xF;

/// `PORTSC.PRC` — Port Reset Change (bit 21, RW1CS).
///
/// Set by hardware when port reset completes. The driver clears this bit by
/// writing `1` to it (RW1CS semantics), then reads `PORTSC.CCS` to confirm a
/// device is present.
pub const PORTSC_PRC: u32 = 1 << 21;

/// Write mask for `PORTSC`.
///
/// Preserves read-only bits and RW1CS status bits; only the explicitly
/// supported write-1-to-set / write-clear bits pass through. Used by the
/// image crate when modifying `PORTSC` fields.
///
/// Per xHCI § 5.4.8 "Port Status and Control" table: PP (bit 9) and PR
/// (bit 4) are the primary driver-written bits; PRC/CSC/PEC/OCC/WRC/PLC/CEC
/// (bits 17-22) are RW1CS — writing `1` clears them; the driver should NOT
/// pass these through unless intentionally clearing them.
pub const PORTSC_RW_MASK: u32 = PORTSC_PR | PORTSC_PP | PORTSC_PRC;

// =============================================================================
// Runtime register offsets relative to the Runtime Register Space base
// =============================================================================

/// Byte offset of the interrupter register array from the Runtime base.
/// xHCI § 5.5.2: interrupter 0 starts at `Runtime base + 0x20`.
pub const RUNTIME_INTERRUPTER_ARRAY_OFFSET: usize = 0x20;

// =============================================================================
// Interrupter register offsets (relative to the interrupter's base)
// xHCI § 5.5.2
// =============================================================================

/// `IMAN` — Interrupter Management register (u32). xHCI § 5.5.2.1, offset +0x00.
///
/// Bits: `IP` (bit 0) — interrupt pending (RW1CS); `IE` (bit 1) — interrupt enable.
pub const IMAN_OFFSET: usize = 0x00;

/// `IMOD` — Interrupter Moderation register (u32). xHCI § 5.5.2.2, offset +0x04.
///
/// Controls interrupt moderation. `IMOD = 0` disables moderation (interrupts
/// are generated immediately). TASK-26 uses the default value (0 = no throttle).
pub const IMOD_OFFSET: usize = 0x04;

/// `ERSTSZ` — Event Ring Segment Table Size (u32). xHCI § 5.5.2.3, offset +0x08.
///
/// The number of segments in the Event Ring Segment Table. TASK-26 uses one
/// segment; this field is programmed to `1`.
pub const ERSTSZ_OFFSET: usize = 0x08;

/// `ERSTBA` — Event Ring Segment Table Base Address (u64). xHCI § 5.5.2.4,
/// offset +0x10.
///
/// 64-bit IOVA of the Event Ring Segment Table (ERST). Must be 64-byte aligned.
pub const ERSTBA_OFFSET: usize = 0x10;

/// `ERDP` — Event Ring Dequeue Pointer (u64). xHCI § 5.5.2.5, offset +0x18.
///
/// Bits 63:4 = dequeue pointer (16-byte aligned); bit 3 = `EHB` (Event Handler
/// Busy, RW1C — writing `1` clears it). The driver writes this register after
/// consuming each event to advance the hardware dequeue pointer.
pub const ERDP_OFFSET: usize = 0x18;

/// `IMAN.IE` — Interrupt Enable (bit 1).
pub const IMAN_IE: u32 = 1 << 1;

/// `IMAN.IP` — Interrupt Pending (bit 0, RW1CS). Writing `1` clears it.
pub const IMAN_IP: u32 = 1 << 0;

/// `ERDP.EHB` — Event Handler Busy flag (bit 3). Writing `1` clears this
/// bit, signalling to the hardware that the driver has consumed all pending
/// events and the dequeue pointer is valid.
pub const ERDP_EHB: u64 = 1 << 3;

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // -- CAPLENGTH / HCIVERSION extractors -----------------------------------

    #[test]
    fn caplength_extracts_low_byte() {
        assert_eq!(caplength(0x0100_0020), 0x20);
        assert_eq!(caplength(0x0000_0040), 0x40);
        assert_eq!(caplength(0xFF), 0xFF);
    }

    #[test]
    fn hciversion_extracts_high_word() {
        assert_eq!(hciversion(0x0100_0020), 0x0100);
        assert_eq!(hciversion(0x0120_0040), 0x0120);
        assert_eq!(hciversion(0x0000_0020), 0x0000);
    }

    // -- HCSPARAMS1 extractors -----------------------------------------------

    #[test]
    fn hcsparams1_max_slots_extracts_bits_7_0() {
        assert_eq!(hcsparams1_max_slots(0x0000_0020), 32);
        assert_eq!(hcsparams1_max_slots(0xFF), 0xFF);
        assert_eq!(hcsparams1_max_slots(0xFFFF_FF00), 0x00);
    }

    #[test]
    fn hcsparams1_max_intrs_extracts_bits_18_8() {
        // MaxIntrs = 1: bit 8 set.
        assert_eq!(hcsparams1_max_intrs(0x0000_0100), 1);
        // MaxIntrs = 0x7FF (max 11-bit field).
        assert_eq!(hcsparams1_max_intrs(0x0007_FF00), 0x7FF);
    }

    #[test]
    fn hcsparams1_max_ports_extracts_bits_31_24() {
        assert_eq!(hcsparams1_max_ports(0x0400_0000), 4);
        assert_eq!(hcsparams1_max_ports(0xFF00_0000), 0xFF);
        assert_eq!(hcsparams1_max_ports(0x00FF_FFFF), 0x00);
    }

    // -- HCCPARAMS1 extractors -----------------------------------------------

    #[test]
    fn hccparams1_ac64_extracts_bit_0() {
        assert!(hccparams1_ac64(0x0000_0001));
        assert!(!hccparams1_ac64(0x0000_0000));
        assert!(!hccparams1_ac64(0xFFFF_FFFE));
    }

    #[test]
    fn hccparams1_csz_extracts_bit_2() {
        assert!(!hccparams1_csz(0x0000_0001)); // AC64 only
        assert!(hccparams1_csz(0x0000_0004));
        assert!(!hccparams1_csz(0x0000_0003));
    }

    // -- Derived base helpers ------------------------------------------------

    #[test]
    fn operational_base_accepts_valid_caplength() {
        assert_eq!(operational_base(0x20), Some(0x20));
        assert_eq!(operational_base(0x40), Some(0x40));
        assert_eq!(operational_base(0xFF), Some(0xFF));
    }

    #[test]
    fn operational_base_rejects_small_caplength() {
        assert!(operational_base(0x00).is_none());
        assert!(operational_base(0x10).is_none());
        assert!(operational_base(0x1F).is_none());
    }

    #[test]
    fn doorbell_base_masks_reserved_bits() {
        assert_eq!(doorbell_base(0x0000_2000), Some(0x2000));
        assert_eq!(doorbell_base(0x0000_2001), Some(0x2000));
        assert_eq!(doorbell_base(0x0000_2003), Some(0x2000));
    }

    #[test]
    fn doorbell_base_rejects_zero() {
        assert!(doorbell_base(0x0000_0000).is_none());
        assert!(doorbell_base(0x0000_0003).is_none()); // masks to zero
    }

    #[test]
    fn runtime_base_masks_reserved_bits() {
        assert_eq!(runtime_base(0x0000_3000), Some(0x3000));
        assert_eq!(runtime_base(0x0000_3001), Some(0x3000));
        assert_eq!(runtime_base(0x0000_3010), Some(0x3000));
    }

    #[test]
    fn runtime_base_rejects_zero() {
        assert!(runtime_base(0x0000_0000).is_none());
        assert!(runtime_base(0x0000_001F).is_none()); // masks to zero
    }

    #[test]
    fn port_reg_offset_computes_correctly() {
        assert_eq!(port_reg_offset(1), Some(PORT_SC_BASE_OPERATIONAL_OFFSET));
        assert_eq!(
            port_reg_offset(2),
            Some(PORT_SC_BASE_OPERATIONAL_OFFSET + 16)
        );
        assert_eq!(
            port_reg_offset(4),
            Some(PORT_SC_BASE_OPERATIONAL_OFFSET + 48)
        );
    }

    #[test]
    fn port_reg_offset_rejects_zero() {
        assert!(port_reg_offset(0).is_none());
    }

    #[test]
    fn doorbell_offset_computes_correctly() {
        assert_eq!(doorbell_offset(0), Some(0)); // command ring
        assert_eq!(doorbell_offset(1), Some(4));
        assert_eq!(doorbell_offset(255), Some(255 * 4));
    }

    #[test]
    fn interrupter_offset_computes_correctly() {
        assert_eq!(
            interrupter_offset(0),
            Some(RUNTIME_INTERRUPTER_ARRAY_OFFSET)
        );
        assert_eq!(
            interrupter_offset(1),
            Some(RUNTIME_INTERRUPTER_ARRAY_OFFSET + 32)
        );
    }

    // -- Architected offsets pinning -----------------------------------------

    #[test]
    fn architected_capability_offsets_match_xhci_spec() {
        assert_eq!(CAPLENGTH_OFFSET, 0x00);
        assert_eq!(HCIVERSION_OFFSET, 0x02);
        assert_eq!(HCSPARAMS1_OFFSET, 0x04);
        assert_eq!(HCSPARAMS2_OFFSET, 0x08);
        assert_eq!(HCCPARAMS1_OFFSET, 0x10);
        assert_eq!(DBOFF_OFFSET, 0x14);
        assert_eq!(RTSOFF_OFFSET, 0x18);
    }

    #[test]
    fn architected_operational_offsets_match_xhci_spec() {
        assert_eq!(USBCMD_OFFSET, 0x00);
        assert_eq!(USBSTS_OFFSET, 0x04);
        assert_eq!(PAGESIZE_OFFSET, 0x08);
        assert_eq!(CRCR_OFFSET, 0x18);
        assert_eq!(DCBAAP_OFFSET, 0x30);
        assert_eq!(CONFIG_OFFSET, 0x38);
        assert_eq!(PORT_SC_BASE_OPERATIONAL_OFFSET, 0x400);
    }

    #[test]
    fn architected_interrupter_offsets_match_xhci_spec() {
        assert_eq!(IMAN_OFFSET, 0x00);
        assert_eq!(IMOD_OFFSET, 0x04);
        assert_eq!(ERSTSZ_OFFSET, 0x08);
        assert_eq!(ERSTBA_OFFSET, 0x10);
        assert_eq!(ERDP_OFFSET, 0x18);
    }

    #[test]
    fn usbcmd_bit_encodings_match_spec() {
        assert_eq!(USBCMD_RUN_STOP, 0x0000_0001);
        assert_eq!(USBCMD_HCRST, 0x0000_0002);
    }

    #[test]
    fn usbsts_bit_encodings_match_spec() {
        assert_eq!(USBSTS_HCH, 0x0000_0001);
        assert_eq!(USBSTS_HSE, 0x0000_0004);
        assert_eq!(USBSTS_CNR, 0x0000_0800);
    }

    #[test]
    fn portsc_bit_encodings_match_spec() {
        assert_eq!(PORTSC_CCS, 0x0000_0001);
        assert_eq!(PORTSC_PED, 0x0000_0002);
        assert_eq!(PORTSC_PR, 0x0000_0010);
        assert_eq!(PORTSC_PP, 0x0000_0200);
        assert_eq!(PORTSC_PRC, 0x0020_0000);
    }
}
