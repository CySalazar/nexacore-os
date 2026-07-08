//! PCI vendor/device matchers for the virtio-net family.
//!
//! Locked by [`NCIP-Driver-Net-015`] § S4. The kernel-side matching happens
//! during `DriverLoad` (`NCIP-Driver-Framework-013` § S5.3 step 8) against
//! the `[matchers].pci_vendor_device` field of the developer-authored
//! manifest TOML; the constants below are the **authoritative source** for
//! that field so the in-crate manifest template and any test-only
//! generators stay in sync with the spec.
//!
//! [`NCIP-Driver-Net-015`]: ../../../ncips/ncip-driver-net-015.md

/// PCI vendor ID assigned to Red Hat for virtio (PCI-SIG OUI `1AF4`).
///
/// Source: virtio 1.0 § 4.1.2.1. Every virtio-net device — modern and
/// legacy — surfaces this vendor ID on the PCI configuration space.
pub const VIRTIO_PCI_VENDOR_ID: u16 = 0x1AF4;

/// PCI device ID for **modern** virtio-net devices (virtio 1.0+).
///
/// Source: virtio 1.0 § 4.1.2.1, table "Transitional and modern PCI Device
/// IDs". The kernel SHOULD prefer modern devices over legacy when both are
/// present (modern devices expose the Common / Notify / ISR / Device-specific
/// configurations via vendor-specific PCI capabilities, which is the only
/// layout `NCIP-Driver-Net-015` § S4.1 supports without the legacy IO-port
/// fallback).
pub const VIRTIO_NET_PCI_DEVICE_ID_MODERN: u16 = 0x1041;

/// PCI device ID for **legacy / transitional** virtio-net devices
/// (pre-virtio-1.0).
///
/// Source: virtio 1.0 § 4.1.2.1. Supported as a fallback per
/// `NCIP-Driver-Net-015` § S4 ("supported as a fallback but discouraged");
/// the M1 deliverable targets modern devices first and the legacy path is
/// optional.
pub const VIRTIO_NET_PCI_DEVICE_ID_LEGACY: u16 = 0x1000;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vendor_id_matches_pci_sig_allocation() {
        // virtio 1.0 § 4.1.2.1 hard-codes Red Hat's vendor ID. Anchoring it
        // here means a future copy-paste error in the manifest template
        // will fail this test rather than ship a silently broken driver.
        assert_eq!(VIRTIO_PCI_VENDOR_ID, 0x1AF4);
    }

    #[test]
    fn modern_device_id_matches_spec() {
        assert_eq!(VIRTIO_NET_PCI_DEVICE_ID_MODERN, 0x1041);
    }

    #[test]
    fn legacy_device_id_matches_spec() {
        assert_eq!(VIRTIO_NET_PCI_DEVICE_ID_LEGACY, 0x1000);
    }

    #[test]
    fn modern_and_legacy_device_ids_are_distinct() {
        // Sanity: the kernel matcher discriminates on device ID, so the
        // two MUST NOT collapse.
        assert_ne!(
            VIRTIO_NET_PCI_DEVICE_ID_MODERN,
            VIRTIO_NET_PCI_DEVICE_ID_LEGACY
        );
    }
}
