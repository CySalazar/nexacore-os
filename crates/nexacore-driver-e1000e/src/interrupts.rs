//! Interrupt mask + cause bit positions for the Intel e1000e family.
//!
//! Pinned by [`NCIP-Driver-Net-015`] § S5.1 step 10 and § S7. The driver
//! enables exactly three interrupt sources at bring-up:
//!
//! - `RXT0` — receiver timer (an inbound frame is sitting in the RX
//!   ring, ready to drain).
//! - `TXDW` — TX descriptor written-back (the device finished consuming
//!   a TX descriptor; the buffer can be reclaimed).
//! - `LSC` — link status change (PHY observed an up/down transition;
//!   driver re-reads `STATUS.LU` to emit `NetEvent::LinkStateChange`).
//!
//! e1000e exposes one combined MSI-X vector by default per NCIP-015 § S7.
//! Multi-vector partitioning (one vector per source) is deferred to a
//! follow-up NCIP that lands together with per-CPU IRQ affinity.
//!
//! ## Register sharing
//!
//! The `ICR` (cause), `IMS` (unmask), and `IMC` (mask) registers use
//! identical bit layouts. The constants below are the canonical bit
//! positions; the [`crate::controller_regs`] module defines the byte
//! offsets at which the three registers live.
//!
//! [`NCIP-Driver-Net-015`]: ../../../ncips/ncip-driver-net-015.md

/// `TXDW` — TX Descriptor Written-back. Bit 0 of `ICR`/`IMS`/`IMC`.
///
/// Asserted when the device finishes consuming a TX descriptor. The
/// driver uses this to reclaim the buffer and post the next pending
/// frame; without it the TX ring would back-pressure on completion.
pub const TXDW_BIT: u32 = 1 << 0;

/// `LSC` — Link Status Change. Bit 2 of `ICR`/`IMS`/`IMC`.
///
/// Asserted on every PHY-detected link transition (up or down). The
/// driver re-reads `STATUS.LU` and emits `NetEvent::LinkStateChange`
/// on the event channel.
pub const LSC_BIT: u32 = 1 << 2;

/// `RXT0` — Receiver Timer Interrupt. Bit 7 of `ICR`/`IMS`/`IMC`.
///
/// Asserted when at least one fresh RX descriptor has been written
/// by the device and the (programmable) receiver timer elapsed. The
/// driver drains the RX ring on receipt.
pub const RXT0_BIT: u32 = 1 << 7;

/// The interrupt mask the driver writes to `IMS` at bring-up step 10.
///
/// `NCIP-Driver-Net-015` § S5.1 step 10: the v0.3 driver enables exactly
/// `RXT0 | TXDW | LSC`. Drift here would either over-subscribe (waking
/// the driver on noise) or under-subscribe (missing data-path events).
pub const ENABLED_IMS: u32 = RXT0_BIT | TXDW_BIT | LSC_BIT;

/// Returns `true` if the `ICR` value indicates an RX-side event the
/// driver should service this IRQ.
#[must_use]
pub const fn icr_has_rx(icr: u32) -> bool {
    icr & RXT0_BIT != 0
}

/// Returns `true` if the `ICR` value indicates a TX completion the
/// driver should reap this IRQ.
#[must_use]
pub const fn icr_has_tx(icr: u32) -> bool {
    icr & TXDW_BIT != 0
}

/// Returns `true` if the `ICR` value indicates a link-state change the
/// driver should report on the event channel.
#[must_use]
pub const fn icr_has_link_change(icr: u32) -> bool {
    icr & LSC_BIT != 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bit_positions_match_intel_datasheet() {
        // Intel 82574L datasheet § 10.6.6 figure ICR layout: pin the
        // three bit positions v0.3 cares about.
        assert_eq!(TXDW_BIT, 1 << 0);
        assert_eq!(LSC_BIT, 1 << 2);
        assert_eq!(RXT0_BIT, 1 << 7);
    }

    #[test]
    fn enabled_ims_matches_ncip_015() {
        // NCIP-015 § S5.1 step 10 enables exactly RXT0 | TXDW | LSC.
        assert_eq!(ENABLED_IMS, RXT0_BIT | TXDW_BIT | LSC_BIT);
    }

    #[test]
    fn enabled_ims_lights_three_distinct_bits() {
        // Sanity: the three sources MUST occupy three distinct bit
        // positions. count_ones on the OR-ed value must equal 3.
        assert_eq!(ENABLED_IMS.count_ones(), 3);
    }

    #[test]
    fn icr_classifiers_detect_each_source() {
        // Each predicate must fire for its own bit and only its own bit.
        assert!(icr_has_rx(RXT0_BIT));
        assert!(!icr_has_tx(RXT0_BIT));
        assert!(!icr_has_link_change(RXT0_BIT));

        assert!(!icr_has_rx(TXDW_BIT));
        assert!(icr_has_tx(TXDW_BIT));
        assert!(!icr_has_link_change(TXDW_BIT));

        assert!(!icr_has_rx(LSC_BIT));
        assert!(!icr_has_tx(LSC_BIT));
        assert!(icr_has_link_change(LSC_BIT));
    }

    #[test]
    fn icr_classifiers_handle_or_combinations() {
        // A burst IRQ servicing all three sources simultaneously must
        // fire every predicate. Drift here would silently drop link
        // notifications under load.
        let burst = RXT0_BIT | TXDW_BIT | LSC_BIT;
        assert!(icr_has_rx(burst));
        assert!(icr_has_tx(burst));
        assert!(icr_has_link_change(burst));
    }

    #[test]
    fn icr_classifiers_ignore_unrelated_bits() {
        // Other ICR bits (e.g. RXDMT0 at bit 4, RXSEQ at bit 3) MUST NOT
        // confuse the v0.3 classifiers; they're not yet enabled in IMS.
        let unrelated = 1 << 4;
        assert!(!icr_has_rx(unrelated));
        assert!(!icr_has_tx(unrelated));
        assert!(!icr_has_link_change(unrelated));
    }

    #[test]
    fn enabled_ims_value_pins_to_intel_default() {
        // Pin the literal value so a copy-paste change to one of the
        // three constants would fail this test rather than silently
        // change the IRQ mask.
        assert_eq!(ENABLED_IMS, 0x0000_0085);
    }
}
