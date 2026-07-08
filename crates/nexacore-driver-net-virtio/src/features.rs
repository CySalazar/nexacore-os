//! Feature negotiation bit positions for virtio-net.
//!
//! The driver reads the device's `device_feature` 64-bit value from the
//! Common Configuration (virtio 1.0 § 4.1.4.3) across banks 0 and 1, AND
//! it with the union of the constants below, and writes the result back
//! to `driver_feature`. The kernel-resident `NCIP-Driver-Net-015` § S4.1
//! step 4 mandates the **v0.3 negotiated subset** as:
//!
//! ```text
//!   VIRTIO_F_VERSION_1
//!   VIRTIO_NET_F_MAC
//!   VIRTIO_NET_F_STATUS
//! ```
//!
//! Additional features (`VIRTIO_NET_F_MRG_RXBUF`, `VIRTIO_NET_F_CSUM`) MAY
//! be added by the bring-up state machine when the developer-authored
//! manifest opts in via the `[net]` table (`tx_checksum_offload`, etc.).

/// Bit 32: device complies with virtio 1.0 specification (i.e., is not a
/// legacy / transitional device that requires the IO-port BAR0 layout).
///
/// Negotiating this bit is **mandatory** per `NCIP-Driver-Net-015` § S4.1
/// step 4: without it, the driver would have to fall back to the legacy
/// MMIO/IO layout, which the M1 deliverable does not implement.
pub const VIRTIO_F_VERSION_1: u64 = 1u64 << 32;

/// Bit 5: device has given the driver a permanent MAC address in the
/// Device Cfg structure (offset 0).
///
/// Without this bit the driver cannot retrieve the MAC and would have to
/// synthesise a locally-administered address — disallowed for first-party
/// drivers by `NCIP-Driver-Net-015` § S2.3.
pub const VIRTIO_NET_F_MAC: u64 = 1u64 << 5;

/// Bit 16: link-state notifications are available.
///
/// The Device Cfg exposes a 16-bit `status` field whose
/// `VIRTIO_NET_S_LINK_UP` bit reflects the current link state. Required
/// for [`NCIP-Driver-Net-015`] § S2.3 `NetEvent::LinkStateChange`
/// emission.
///
/// [`NCIP-Driver-Net-015`]: ../../../ncips/ncip-driver-net-015.md
pub const VIRTIO_NET_F_STATUS: u64 = 1u64 << 16;

/// Bit 0: device handles packets with partial checksum (TX checksum
/// offload). Opt-in per manifest `[net].tx_checksum_offload`.
pub const VIRTIO_NET_F_CSUM: u64 = 1u64 << 0;

/// Bit 15: driver can merge receive buffers (used when an inbound frame
/// spans multiple RX buffers). Opt-in per manifest `[net].lro_enabled`.
pub const VIRTIO_NET_F_MRG_RXBUF: u64 = 1u64 << 15;

/// The mandatory negotiated feature set for the v0.3 virtio-net driver.
///
/// `NCIP-Driver-Net-015` § S4.1 step 4: this is the floor — the driver
/// MUST negotiate at minimum these three bits. Optional bits
/// ([`VIRTIO_NET_F_CSUM`], [`VIRTIO_NET_F_MRG_RXBUF`]) are OR-ed on top
/// by the bring-up state machine when the developer-authored manifest
/// opts in.
pub const REQUIRED_FEATURES: u64 = VIRTIO_F_VERSION_1 | VIRTIO_NET_F_MAC | VIRTIO_NET_F_STATUS;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_1_lives_in_upper_bank() {
        // virtio 1.0 § 6: feature bits ≥ 32 occupy bank 1 of the
        // device_feature register. The reserved range for transport-level
        // features starts at bit 32 (VIRTIO_F_VERSION_1 lives here);
        // anything below would break the negotiated-subset assumption
        // baked into the bring-up state machine.
        assert_eq!(VIRTIO_F_VERSION_1, 1u64 << 32);
    }

    #[test]
    fn required_features_covers_mandatory_three() {
        // NCIP-015 § S4.1 step 4 lists exactly these three. Drift here
        // would let a driver build pass while silently dropping a
        // mandatory bit.
        assert_eq!(
            REQUIRED_FEATURES,
            VIRTIO_F_VERSION_1 | VIRTIO_NET_F_MAC | VIRTIO_NET_F_STATUS
        );
    }

    #[test]
    fn optional_csum_does_not_overlap_required() {
        assert_eq!(REQUIRED_FEATURES & VIRTIO_NET_F_CSUM, 0);
    }

    #[test]
    fn optional_mrg_rxbuf_does_not_overlap_required() {
        assert_eq!(REQUIRED_FEATURES & VIRTIO_NET_F_MRG_RXBUF, 0);
    }
}
