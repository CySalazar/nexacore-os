//! CSR (Control / Status Register) offsets for the Intel e1000e family.
//!
//! Pinned by [`NCIP-Driver-Net-015`] § S5.1 and the Intel 82574L
//! Gigabit Ethernet Controller datasheet § 10 ("Programming Interface").
//! The driver maps the controller's BAR0 via
//! [`NCIP-Driver-Framework-013`] § S2 `MmioMap` and reads/writes 32-bit
//! registers at the offsets defined below. Layout drift between the
//! datasheet, the manifest template, and the bring-up FSM is caught by
//! the unit tests at the bottom of this module.
//!
//! ## Address-space contract
//!
//! All offsets are byte-relative to the base of BAR0 (mapped as uncached
//! per NCIP-013 § S2.5). The CSR region is **128 KiB** by datasheet § 10.1
//! and by NCIP-015 § S5.1 step 1; v0.3 touches a small subset of that
//! window (`0x00000`..`0x05408`), but the manifest declares the full
//! 128 KiB so future feature additions stay backwards-compatible at the
//! capability layer.
//!
//! ## Register groups
//!
//! - **Device control** (`CTRL`, `STATUS`): § 10.2-10.3 of the datasheet.
//! - **Interrupt control** (`ICR`, `ITR`, `IMS`, `IMC`): § 10.6.
//! - **PHY / MDIO** (`MDIC`): § 10.5.
//! - **Receive control + descriptor ring** (`RCTL`, `RDBAL`, `RDBAH`,
//!   `RDLEN`, `RDH`, `RDT`): § 10.7.
//! - **Transmit control + descriptor ring** (`TCTL`, `TDBAL`, `TDBAH`,
//!   `TDLEN`, `TDH`, `TDT`): § 10.8.
//! - **Receive Address** (`RAL[0]`, `RAH[0]`): § 10.7.4 — used to read
//!   the EEPROM-loaded MAC address at bring-up step 4.
//!
//! [`NCIP-Driver-Framework-013`]: ../../../ncips/ncip-driver-framework-013.md
//! [`NCIP-Driver-Net-015`]: ../../../ncips/ncip-driver-net-015.md

// =============================================================================
// MMIO window size — NCIP-015 § S5.1 step 1
// =============================================================================

/// Size of the e1000e CSR register region the driver requests via
/// `MmioMap`. 128 KiB per Intel 82574L datasheet § 10.1 and
/// NCIP-015 § S5.1.
pub const CSR_REGION_BYTES: usize = 0x0002_0000;

// =============================================================================
// Device control / status — Intel 82574L datasheet § 10.2-10.3
// =============================================================================

/// `CTRL` — Device Control (32-bit, RW). Offset `0x00000`.
///
/// Hosts global reset (`CTRL.RST`, bit 26) plus auto-speed / link-up
/// detection bits. The driver triggers a global reset at bring-up step 3
/// and otherwise leaves this register at its post-reset default.
pub const CTRL_OFFSET: usize = 0x0000;

/// `STATUS` — Device Status (32-bit, RO). Offset `0x00008`.
///
/// Bit 0 = `FD` (Full-Duplex), bit 1 = `LU` (Link Up), bits 7:6 = speed
/// (`00` = 10 Mb/s, `01` = 100 Mb/s, `10` = 1 Gb/s). Polled by the driver
/// on every `LSC` interrupt to emit `NetEvent::LinkStateChange`.
pub const STATUS_OFFSET: usize = 0x0008;

/// `CTRL.RST` — bit 26. Software writes 1 to trigger a controller reset;
/// the hardware self-clears the bit on completion. Bring-up step 3.
pub const CTRL_RST_BIT: u32 = 1 << 26;

/// `STATUS.FD` — bit 0. Set when the negotiated duplex is full.
pub const STATUS_FD_BIT: u32 = 1 << 0;

/// `STATUS.LU` — bit 1. Set when the PHY reports a live link.
pub const STATUS_LU_BIT: u32 = 1 << 1;

/// `STATUS` speed field shift — bits 7:6 encode the negotiated link speed.
pub const STATUS_SPEED_SHIFT: u32 = 6;

/// `STATUS` speed field mask (2 bits, applied after [`STATUS_SPEED_SHIFT`]).
pub const STATUS_SPEED_MASK: u32 = 0b11;

// =============================================================================
// PHY / MDIO control — Intel 82574L datasheet § 10.5
// =============================================================================

/// `MDIC` — MDI Control (32-bit, RW). Offset `0x00020`.
///
/// Software triggers a PHY register read/write by composing this 32-bit
/// value (PHY address in bits 25:21, register address in bits 20:16,
/// opcode in bits 27:26, data in bits 15:0) and polling bit 28 (`R` —
/// Ready) to wait for completion. Used in bring-up step 5 to read
/// `MII_CTRL` and trigger auto-negotiation.
pub const MDIC_OFFSET: usize = 0x0020;

// =============================================================================
// Interrupt control — Intel 82574L datasheet § 10.6
// =============================================================================

/// `ICR` — Interrupt Cause Read (32-bit, R/W1C). Offset `0x000C0`.
///
/// The driver reads this register inside its IRQ handler trampoline (per
/// NCIP-013 § S4) to discover which event(s) fired. Reading clears the
/// register (write-1-to-clear semantics with read-clear shortcut). The
/// bit positions are mirrored in [`crate::interrupts`].
pub const ICR_OFFSET: usize = 0x00C0;

/// `ITR` — Interrupt Throttling Rate (32-bit, RW). Offset `0x000C4`.
///
/// Sets the minimum inter-interrupt interval in 256 ns units. v0.3
/// leaves this at the post-reset default (`0` — no throttling); a future
/// NCIP may tune it for latency / IPC-pressure trade-offs.
pub const ITR_OFFSET: usize = 0x00C4;

/// `IMS` — Interrupt Mask Set (32-bit, W). Offset `0x000D0`.
///
/// Writing a 1 to a bit *unmasks* that interrupt source; reading returns
/// the current mask. Bring-up step 10 writes `RXT0 | TXDW | LSC`
/// (see [`crate::interrupts`]).
pub const IMS_OFFSET: usize = 0x00D0;

/// `IMC` — Interrupt Mask Clear (32-bit, W). Offset `0x000D8`.
///
/// Writing a 1 to a bit *masks* that interrupt source. Bring-up step 2
/// writes `0xFFFFFFFF` here to disable every interrupt before the global
/// reset.
pub const IMC_OFFSET: usize = 0x00D8;

/// Sentinel value the driver writes to `IMC` at bring-up step 2 to mask
/// every interrupt source before issuing the global reset.
pub const IMC_DISABLE_ALL: u32 = 0xFFFF_FFFF;

// =============================================================================
// Receive control + descriptor ring — Intel 82574L datasheet § 10.7
// =============================================================================

/// `RCTL` — Receive Control (32-bit, RW). Offset `0x00100`.
///
/// Hosts the receive enable bit (`EN`, bit 1), broadcast accept (`BAM`,
/// bit 15), strip Ethernet CRC (`SECRC`, bit 26), and the receive buffer
/// size encoding (`BSIZE`, bits 17:16 — `00` = 2 KiB).
pub const RCTL_OFFSET: usize = 0x0100;

/// `RDBAL` — Receive Descriptor Base Address Low (32-bit, RW).
/// Offset `0x02800`.
pub const RDBAL_OFFSET: usize = 0x2800;

/// `RDBAH` — Receive Descriptor Base Address High (32-bit, RW).
/// Offset `0x02804`.
pub const RDBAH_OFFSET: usize = 0x2804;

/// `RDLEN` — Receive Descriptor Length (32-bit, RW). Offset `0x02808`.
///
/// The driver writes `rx_ring_depth * 16` (16 bytes per descriptor).
pub const RDLEN_OFFSET: usize = 0x2808;

/// `RDH` — Receive Descriptor Head (32-bit, RW). Offset `0x02810`.
///
/// Hardware advances this pointer as it consumes descriptors from the
/// ring. Initialised to `0` at bring-up.
pub const RDH_OFFSET: usize = 0x2810;

/// `RDT` — Receive Descriptor Tail (32-bit, RW). Offset `0x02818`.
///
/// Software advances this pointer as it posts fresh buffers. Initialised
/// to `rx_ring_depth - 1` after the pre-post step.
pub const RDT_OFFSET: usize = 0x2818;

/// `RCTL.EN` — bit 1. Setting it to 1 enables the receive path.
pub const RCTL_EN_BIT: u32 = 1 << 1;

/// `RCTL.BAM` — bit 15. Accept broadcast frames.
pub const RCTL_BAM_BIT: u32 = 1 << 15;

/// `RCTL.SECRC` — bit 26. Strip the Ethernet FCS from received frames
/// (NCIP-015 § S2.1 — the NET channel sees frames without FCS).
pub const RCTL_SECRC_BIT: u32 = 1 << 26;

/// `RCTL.BSIZE` field shift (bits 17:16). Value `0b00` = 2 KiB buffers,
/// matching `rx_buffer_count × 2 KiB` in the manifest template.
pub const RCTL_BSIZE_SHIFT: u32 = 16;

/// Compose the `RCTL` value the driver writes at bring-up step 9:
/// receive enable + broadcast accept + strip CRC, 2 KiB buffer size,
/// no multicast hash, no long packet mode.
#[must_use]
pub const fn rctl_enable_value() -> u32 {
    RCTL_EN_BIT | RCTL_BAM_BIT | RCTL_SECRC_BIT
    // BSIZE = 0b00 (2 KiB), no other flags — explicit OR-with-zero omitted.
}

// =============================================================================
// Transmit control + descriptor ring — Intel 82574L datasheet § 10.8
// =============================================================================

/// `TCTL` — Transmit Control (32-bit, RW). Offset `0x00400`.
///
/// Hosts the transmit enable bit (`EN`, bit 1), pad short packets
/// (`PSP`, bit 3), the collision threshold field (`CT`, bits 11:4 —
/// IEEE 802.3 default `0x0F`), and the collision distance field
/// (`COLD`, bits 21:12 — `0x40` for full-duplex).
pub const TCTL_OFFSET: usize = 0x0400;

/// `TDBAL` — Transmit Descriptor Base Address Low (32-bit, RW).
/// Offset `0x03800`.
pub const TDBAL_OFFSET: usize = 0x3800;

/// `TDBAH` — Transmit Descriptor Base Address High (32-bit, RW).
/// Offset `0x03804`.
pub const TDBAH_OFFSET: usize = 0x3804;

/// `TDLEN` — Transmit Descriptor Length (32-bit, RW). Offset `0x03808`.
pub const TDLEN_OFFSET: usize = 0x3808;

/// `TDH` — Transmit Descriptor Head (32-bit, RW). Offset `0x03810`.
pub const TDH_OFFSET: usize = 0x3810;

/// `TDT` — Transmit Descriptor Tail (32-bit, RW). Offset `0x03818`.
pub const TDT_OFFSET: usize = 0x3818;

/// `TCTL.EN` — bit 1.
pub const TCTL_EN_BIT: u32 = 1 << 1;

/// `TCTL.PSP` — bit 3. Pad short packets to 64 bytes (IEEE 802.3 min).
pub const TCTL_PSP_BIT: u32 = 1 << 3;

/// `TCTL.CT` field shift (bits 11:4). IEEE 802.3 default = `0x0F`
/// (Intel datasheet § 13 recommends this exact value).
pub const TCTL_CT_SHIFT: u32 = 4;

/// `TCTL.COLD` field shift (bits 21:12). Full-duplex default = `0x40`.
pub const TCTL_COLD_SHIFT: u32 = 12;

/// IEEE 802.3 default collision threshold for `TCTL.CT`.
pub const TCTL_CT_DEFAULT: u32 = 0x0F;

/// Full-duplex default collision distance for `TCTL.COLD`.
pub const TCTL_COLD_DEFAULT_FD: u32 = 0x40;

/// Compose the `TCTL` value the driver writes at bring-up step 9:
/// transmit enable + pad short packets + IEEE 802.3 collision threshold
/// + full-duplex collision distance.
#[must_use]
pub const fn tctl_enable_value() -> u32 {
    TCTL_EN_BIT
        | TCTL_PSP_BIT
        | (TCTL_CT_DEFAULT << TCTL_CT_SHIFT)
        | (TCTL_COLD_DEFAULT_FD << TCTL_COLD_SHIFT)
}

// =============================================================================
// Receive Address (MAC) — Intel 82574L datasheet § 10.7.4
// =============================================================================

/// `RAL[0]` — Receive Address Low 0 (32-bit, RW). Offset `0x05400`.
///
/// EEPROM-loaded MAC address bytes 0..=3. Read at bring-up step 4 to
/// surface the negotiated MAC for the eventual `NetEvent::MacChanged`
/// emission (NCIP-015 § S2.3 + § S3).
pub const RAL0_OFFSET: usize = 0x5400;

/// `RAH[0]` — Receive Address High 0 (32-bit, RW). Offset `0x05404`.
///
/// EEPROM-loaded MAC address bytes 4..=5 in bits 15:0; bit 31 = `AV`
/// (Address Valid).
pub const RAH0_OFFSET: usize = 0x5404;

/// `RAH[0].AV` — bit 31. Hardware sets this to 1 once the EEPROM has
/// finished loading the MAC; software MUST verify it before treating
/// the MAC as authoritative.
pub const RAH_AV_BIT: u32 = 1 << 31;

/// Decode the interface MAC address from the `RAL[0]` / `RAH[0]` register pair
/// (WS2-03.2).
///
/// `RAL[0]` holds MAC bytes 0..=3 (little-endian); `RAH[0]` bits 15:0 hold
/// bytes 4..=5 and bit 31 is [`RAH_AV_BIT`] (`AV`, Address Valid). Returns
/// `Some(mac)` only when `AV` is set: the EEPROM-loaded MAC is authoritative
/// only after the NVM load completes, so a clear `AV` is treated fail-closed
/// as "MAC not ready yet" (`None`) rather than as a zero/garbage address.
///
/// # Example
///
/// ```
/// use nexacore_driver_e1000e::controller_regs::{RAH_AV_BIT, decode_mac};
///
/// // RAL = 0x44332211, RAH = AV | 0x6655 → 11:22:33:44:55:66.
/// let mac = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66];
/// assert_eq!(decode_mac(0x4433_2211, RAH_AV_BIT | 0x6655), Some(mac));
/// // AV clear → MAC not yet loaded.
/// assert_eq!(decode_mac(0x4433_2211, 0x6655), None);
/// ```
#[must_use]
#[allow(clippy::similar_names)] // ral/rah + b0..b5 are datasheet field names
pub const fn decode_mac(ral: u32, rah: u32) -> Option<[u8; 6]> {
    if rah & RAH_AV_BIT == 0 {
        return None;
    }
    let [b0, b1, b2, b3] = ral.to_le_bytes();
    let [b4, b5, _, _] = rah.to_le_bytes();
    Some([b0, b1, b2, b3, b4, b5])
}

/// Encode a MAC address into the `(RAL[0], RAH[0])` register pair with `AV`
/// set — the inverse of [`decode_mac`]. Used to program an override MAC and by
/// tests to exercise [`decode_mac`] round-trips.
///
/// # Example
///
/// ```
/// use nexacore_driver_e1000e::controller_regs::{decode_mac, encode_mac_regs};
///
/// let mac = [0x52, 0x54, 0x00, 0xAB, 0xCD, 0xEF];
/// let (ral, rah) = encode_mac_regs(mac);
/// assert_eq!(decode_mac(ral, rah), Some(mac));
/// ```
#[must_use]
#[allow(clippy::similar_names)] // b0..b5 are sequential MAC byte names
pub const fn encode_mac_regs(mac: [u8; 6]) -> (u32, u32) {
    let [b0, b1, b2, b3, b4, b5] = mac;
    let ral = u32::from_le_bytes([b0, b1, b2, b3]);
    let rah = u32::from_le_bytes([b4, b5, 0, 0]) | RAH_AV_BIT;
    (ral, rah)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn architected_device_control_offsets_match_intel_datasheet() {
        // Intel 82574L datasheet § 10.2-10.6: device control + PHY +
        // interrupt block. Pin each architected field by byte offset so
        // a future "tidy up the register module" PR cannot silently
        // drift the layout.
        assert_eq!(CTRL_OFFSET, 0x0000);
        assert_eq!(STATUS_OFFSET, 0x0008);
        assert_eq!(MDIC_OFFSET, 0x0020);
        assert_eq!(ICR_OFFSET, 0x00C0);
        assert_eq!(ITR_OFFSET, 0x00C4);
        assert_eq!(IMS_OFFSET, 0x00D0);
        assert_eq!(IMC_OFFSET, 0x00D8);
    }

    #[test]
    fn architected_rx_ring_offsets_match_intel_datasheet() {
        // Intel 82574L datasheet § 10.7: receive control + RX ring.
        assert_eq!(RCTL_OFFSET, 0x0100);
        assert_eq!(RDBAL_OFFSET, 0x2800);
        assert_eq!(RDBAH_OFFSET, 0x2804);
        assert_eq!(RDLEN_OFFSET, 0x2808);
        assert_eq!(RDH_OFFSET, 0x2810);
        assert_eq!(RDT_OFFSET, 0x2818);
    }

    #[test]
    fn architected_tx_ring_offsets_match_intel_datasheet() {
        // Intel 82574L datasheet § 10.8: transmit control + TX ring.
        assert_eq!(TCTL_OFFSET, 0x0400);
        assert_eq!(TDBAL_OFFSET, 0x3800);
        assert_eq!(TDBAH_OFFSET, 0x3804);
        assert_eq!(TDLEN_OFFSET, 0x3808);
        assert_eq!(TDH_OFFSET, 0x3810);
        assert_eq!(TDT_OFFSET, 0x3818);
    }

    #[test]
    fn architected_mac_offsets_match_intel_datasheet() {
        // Intel 82574L datasheet § 10.7.4: receive address.
        assert_eq!(RAL0_OFFSET, 0x5400);
        assert_eq!(RAH0_OFFSET, 0x5404);
    }

    // Compile-time invariant: every touched register lies inside the
    // declared 128 KiB CSR region. Caught at build time.
    const _CSR_REGION_COVERS_RAH0: () = assert!(CSR_REGION_BYTES > RAH0_OFFSET);
    const _CSR_REGION_COVERS_TDT: () = assert!(CSR_REGION_BYTES > TDT_OFFSET);

    #[test]
    fn ctrl_rst_lives_at_bit_26() {
        // Intel 82574L datasheet § 10.2 places the global reset bit
        // exactly at bit 26 of CTRL. Drift here would silently reboot
        // the wrong bit when the driver triggers the reset path.
        assert_eq!(CTRL_RST_BIT, 1 << 26);
    }

    #[test]
    fn status_lu_lives_at_bit_1() {
        // NCIP-015 § S5.2: polling STATUS.LU (bit 1) drives the
        // LinkStateChange event emission. Pin the bit position.
        assert_eq!(STATUS_LU_BIT, 1 << 1);
        assert_eq!(STATUS_FD_BIT, 1 << 0);
    }

    #[test]
    fn imc_disable_all_value_masks_every_bit() {
        // NCIP-015 § S5.1 step 2 mandates writing 0xFFFFFFFF to IMC.
        assert_eq!(IMC_DISABLE_ALL, 0xFFFF_FFFF);
    }

    #[test]
    fn rctl_enable_value_sets_required_bits() {
        let value = rctl_enable_value();
        assert_ne!(value & RCTL_EN_BIT, 0, "RCTL.EN must be set");
        assert_ne!(value & RCTL_BAM_BIT, 0, "RCTL.BAM must be set");
        assert_ne!(value & RCTL_SECRC_BIT, 0, "RCTL.SECRC must be set");
        // BSIZE = 0b00 (2 KiB) — bits 17:16 MUST be clear.
        assert_eq!(value & (0b11 << RCTL_BSIZE_SHIFT), 0);
    }

    #[test]
    fn tctl_enable_value_encodes_ct_and_cold_defaults() {
        let value = tctl_enable_value();
        assert_ne!(value & TCTL_EN_BIT, 0, "TCTL.EN must be set");
        assert_ne!(value & TCTL_PSP_BIT, 0, "TCTL.PSP must be set");
        // CT field (bits 11:4) must encode IEEE 802.3 default 0x0F.
        let ct = (value >> TCTL_CT_SHIFT) & 0xFF;
        assert_eq!(ct, TCTL_CT_DEFAULT);
        // COLD field (bits 21:12) must encode full-duplex default 0x40.
        let cold = (value >> TCTL_COLD_SHIFT) & 0x3FF;
        assert_eq!(cold, TCTL_COLD_DEFAULT_FD);
    }

    #[test]
    fn rah_av_lives_at_bit_31() {
        // Intel 82574L datasheet § 10.7.4: RAH[i].AV is the high bit.
        assert_eq!(RAH_AV_BIT, 1 << 31);
    }

    #[test]
    fn decode_mac_extracts_bytes_in_datasheet_order() {
        // RAL = bytes 0..=3 little-endian, RAH[15:0] = bytes 4..=5, AV set.
        let ral = 0x4433_2211;
        let rah = RAH_AV_BIT | 0x0000_6655;
        assert_eq!(
            decode_mac(ral, rah),
            Some([0x11, 0x22, 0x33, 0x44, 0x55, 0x66])
        );
    }

    #[test]
    fn decode_mac_fails_closed_when_av_clear() {
        // EEPROM/NVM load not finished → AV clear → no authoritative MAC.
        assert_eq!(decode_mac(0x4433_2211, 0x0000_6655), None);
    }

    #[test]
    fn encode_decode_mac_round_trips_with_av_set() {
        let mac = [0x52, 0x54, 0x00, 0xAB, 0xCD, 0xEF];
        let (ral, rah) = encode_mac_regs(mac);
        assert_ne!(rah & RAH_AV_BIT, 0, "encode must set AV");
        assert_eq!(decode_mac(ral, rah), Some(mac));
    }

    #[test]
    fn status_speed_field_occupies_bits_7_6() {
        assert_eq!(STATUS_SPEED_SHIFT, 6);
        assert_eq!(STATUS_SPEED_MASK, 0b11);
        // The speed field must not overlap LU (bit 1) or FD (bit 0).
        assert_eq!((STATUS_SPEED_MASK << STATUS_SPEED_SHIFT) & STATUS_LU_BIT, 0);
        assert_eq!((STATUS_SPEED_MASK << STATUS_SPEED_SHIFT) & STATUS_FD_BIT, 0);
    }

    // Defensive: a copy-paste error swapping RX and TX descriptor
    // base addresses would silently corrupt the data path. The two
    // invariants below compare crate-level `const usize` values, so
    // clippy folds an `assert!()` to `assert!(true)` at compile time.
    // Use `const _: () = assert!(...)` at module scope instead.

    const _TDBAL_AFTER_RDT: () = assert!(TDBAL_OFFSET > RDT_OFFSET);
    const _RX_TX_BASE_SPACING: () = assert!(TDBAL_OFFSET - RDBAL_OFFSET == 0x1000);
}
