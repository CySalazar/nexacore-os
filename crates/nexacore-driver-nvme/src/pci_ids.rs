//! PCI class code matchers for the NVMe storage class.
//!
//! Locked by [`NCIP-Driver-NVMe-014`] § S1. The driver matches devices by
//! **PCI class code** rather than enumerating individual vendor/device
//! pairs (NCIP-014 § R4 rationale): one driver image covers every
//! NVMe-class controller the project has not individually tested. The
//! signed-image / `KNOWN_ISSUERS` invariant (NCIP-013 § S5) keeps the
//! attack surface bounded.
//!
//! The class triple is `(class=0x01, subclass=0x08, prog_if=0x02)`,
//! defined by the PCI-SIG class code list as **NVM Express I/O
//! Controller**. The kernel-side matching happens during `DriverLoad`
//! (`NCIP-Driver-Framework-013` § S5.3 step 8) against the
//! `[matchers].pci_class` field of the developer-authored manifest TOML;
//! the constants below are the **authoritative source** for that field
//! so the in-crate manifest template and any test-only generators stay
//! in sync with the spec.
//!
//! [`NCIP-Driver-NVMe-014`]: ../../../ncips/ncip-driver-nvme-014.md

/// PCI base class for **mass storage controllers** (PCI-SIG class list).
///
/// Anchored by NVMe 1.4 base spec § 2.1 ("PCI Express Controller
/// Implementation") and PCI Code and ID Assignment Specification rev 1.16
/// table 2-1.
pub const PCI_CLASS_MASS_STORAGE: u8 = 0x01;

/// PCI subclass for **non-volatile memory controllers**.
///
/// PCI-SIG class code table 2-1 row `class=0x01, subclass=0x08`. Covers
/// every NVM controller flavour (the prog-if discriminates NVMHCI vs NVM
/// Express vs vendor-specific).
pub const PCI_SUBCLASS_NON_VOLATILE_MEMORY: u8 = 0x08;

/// PCI programming interface for **NVM Express I/O Controller**.
///
/// PCI-SIG class code table 2-1 row `class=0x01, subclass=0x08,
/// prog_if=0x02`. The other defined prog-if values for subclass `0x08`
/// (e.g. `0x01 = NVMHCI`) are explicitly NOT matched by this driver —
/// the v0.3 deliverable targets NVM Express only.
pub const PCI_PROG_IF_NVM_EXPRESS: u8 = 0x02;

/// Returns `true` if the (class, subclass, prog-if) triple identifies a
/// PCIe NVM Express I/O controller per NCIP-014 § S1.
///
/// Used by the kernel-side `pci_class` matcher and by the driver's own
/// post-`DriverLoad` PCI enumeration walk to filter the ECAM space.
#[must_use]
pub const fn is_nvme_class(class: u8, subclass: u8, prog_if: u8) -> bool {
    class == PCI_CLASS_MASS_STORAGE
        && subclass == PCI_SUBCLASS_NON_VOLATILE_MEMORY
        && prog_if == PCI_PROG_IF_NVM_EXPRESS
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nvme_class_triple_matches_ncip_014() {
        // NCIP-014 § S1: `pci_class = { class = "0x01", subclass = "0x08",
        // prog_if = "0x02" }`. Anchoring it here means a future copy-paste
        // error in the manifest template will fail this test rather than
        // ship a silently broken driver.
        assert_eq!(PCI_CLASS_MASS_STORAGE, 0x01);
        assert_eq!(PCI_SUBCLASS_NON_VOLATILE_MEMORY, 0x08);
        assert_eq!(PCI_PROG_IF_NVM_EXPRESS, 0x02);
    }

    #[test]
    fn matcher_accepts_the_exact_triple() {
        assert!(is_nvme_class(0x01, 0x08, 0x02));
    }

    #[test]
    fn matcher_rejects_nvmhci_prog_if() {
        // prog_if 0x01 = NVMHCI (legacy). NCIP-014 § S1 explicitly excludes
        // it from v0.3 scope; the matcher must not accept it.
        assert!(!is_nvme_class(0x01, 0x08, 0x01));
    }

    #[test]
    fn matcher_rejects_vendor_specific_prog_if() {
        // prog_if 0xFF = vendor-specific NVM. Not covered by v0.3.
        assert!(!is_nvme_class(0x01, 0x08, 0xFF));
    }

    #[test]
    fn matcher_rejects_other_storage_subclass() {
        // class=0x01, subclass=0x06 = SATA controller. Definitely not NVMe.
        assert!(!is_nvme_class(0x01, 0x06, 0x01));
    }

    #[test]
    fn matcher_rejects_non_storage_class() {
        // class=0x02 = network controller. Anything outside mass storage
        // must be rejected at the matcher layer.
        assert!(!is_nvme_class(0x02, 0x08, 0x02));
    }

    #[test]
    fn matcher_rejects_all_wildcards() {
        // A zero triple must NOT auto-match; we never want to claim
        // every PCI device by accident.
        assert!(!is_nvme_class(0x00, 0x00, 0x00));
    }
}
