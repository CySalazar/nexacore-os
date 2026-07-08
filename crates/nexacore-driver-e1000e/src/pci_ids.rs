//! PCI vendor/device matchers for the Intel e1000e family.
//!
//! Locked by [`NCIP-Driver-Net-015`] § S5 (and the manifest template
//! comment block in § S1, which lists the canonical entries the
//! developer-authored TOML MUST replicate). The kernel-side matching
//! happens during `DriverLoad` (`NCIP-Driver-Framework-013` § S5.3 step 8)
//! against the `[matchers].pci_vendor_device` field of the manifest; the
//! constants below are the **authoritative source** for that field so the
//! in-crate manifest template and any test-only generators stay in sync
//! with the spec.
//!
//! ## Coverage
//!
//! The e1000e PCI Express family covers a wide range of integrated NICs
//! manufactured by Intel from the mid-2000s onwards. v0.3 targets a
//! representative subset that QEMU's `e1000e` device model and common
//! bare-metal hardware actually surface:
//!
//! | Device ID | Codename | Notes |
//! |-----------|----------|-------|
//! | `0x10D3`  | 82574L   | QEMU `-device e1000e` defaults to this |
//! | `0x153A`  | I217-LM  | Lynx Point — common on 4th-gen Core (Haswell) chipsets |
//! | `0x153B`  | I217-V   | Lynx Point consumer variant |
//! | `0x15A1`  | I218-LM  | Wildcat Point |
//! | `0x15A3`  | I219-LM  | Sunrise Point — common on 6th-gen Core (Skylake) and later |
//!
//! Additional revisions (I219-LM2/-LM3/-LM7/-LM9/-LM10, et al.) share the
//! same CSR layout and are out-of-scope only because they require
//! validation passes on physical hardware before claiming the manifest.
//! They will be added by follow-up PRs as test boxes become available.
//!
//! [`NCIP-Driver-Net-015`]: ../../../ncips/ncip-driver-net-015.md
//! [`NCIP-Driver-Framework-013`]: ../../../ncips/ncip-driver-framework-013.md

/// PCI vendor ID assigned to **Intel Corporation** (PCI-SIG OUI `8086`).
///
/// Source: PCI-SIG vendor ID registry. Every e1000e device — regardless of
/// codename — surfaces this vendor ID on the PCI configuration space.
pub const INTEL_PCI_VENDOR_ID: u16 = 0x8086;

/// PCI device ID for the **82574L** Gigabit Ethernet controller.
///
/// QEMU's `-device e1000e` defaults to this device ID; it is the
/// reference target for the M2 deliverable and the model used by the
/// `[driver-net] ready ...` smoke validation on the Proxmox test VM
/// (NCIP-015 § TC5).
pub const E1000E_DEVICE_ID_82574L: u16 = 0x10D3;

/// PCI device ID for the **I217-LM** Gigabit Ethernet controller
/// (Lynx Point platform, ca. 2013).
///
/// Common on 4th-generation Intel Core (Haswell) desktop chipsets. The
/// CSR layout is identical to the 82574L for the registers v0.3 touches;
/// PHY init differs slightly (already paged at boot in most BIOSes).
pub const E1000E_DEVICE_ID_I217_LM: u16 = 0x153A;

/// PCI device ID for the **I217-V** Gigabit Ethernet controller (Lynx
/// Point consumer variant).
///
/// CSR-compatible with `I217-LM`; the difference is in vPro / AMT firmware
/// presence (LM ships with management firmware enabled, V does not). The
/// driver does not care about the AMT layer.
pub const E1000E_DEVICE_ID_I217_V: u16 = 0x153B;

/// PCI device ID for the **I218-LM** Gigabit Ethernet controller
/// (Wildcat Point platform, ca. 2014).
pub const E1000E_DEVICE_ID_I218_LM: u16 = 0x15A1;

/// PCI device ID for the **I219-LM** Gigabit Ethernet controller
/// (Sunrise Point platform, ca. 2015).
///
/// Common on 6th-generation Intel Core (Skylake) and later desktop
/// chipsets. CSR-compatible with the 82574L for the v0.3 register set.
pub const E1000E_DEVICE_ID_I219_LM: u16 = 0x15A3;

/// Returns `true` if `(vendor, device)` identifies an e1000e family
/// device that v0.3 of the driver claims via the manifest matcher table.
///
/// Used by the kernel-side `pci_vendor_device` matcher (driven from the
/// manifest TOML) and by the driver's own post-`DriverLoad` PCI
/// enumeration walk to filter the ECAM space. The kernel evaluates the
/// manifest table; this helper exists for host-side tests and for
/// driver-internal sanity checks.
#[must_use]
pub const fn is_e1000e_device(vendor: u16, device: u16) -> bool {
    if vendor != INTEL_PCI_VENDOR_ID {
        return false;
    }
    matches!(
        device,
        E1000E_DEVICE_ID_82574L
            | E1000E_DEVICE_ID_I217_LM
            | E1000E_DEVICE_ID_I217_V
            | E1000E_DEVICE_ID_I218_LM
            | E1000E_DEVICE_ID_I219_LM
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vendor_id_matches_pci_sig_allocation() {
        // PCI-SIG vendor ID for Intel Corporation. Drift here would let
        // a copy-paste error in the manifest template silently ship a
        // broken driver.
        assert_eq!(INTEL_PCI_VENDOR_ID, 0x8086);
    }

    #[test]
    fn device_ids_match_ncip_015_table() {
        // NCIP-Driver-Net-015 § S5 table: pin every supported device ID
        // by exact byte value so the matcher cannot drift silently.
        assert_eq!(E1000E_DEVICE_ID_82574L, 0x10D3);
        assert_eq!(E1000E_DEVICE_ID_I217_LM, 0x153A);
        assert_eq!(E1000E_DEVICE_ID_I217_V, 0x153B);
        assert_eq!(E1000E_DEVICE_ID_I218_LM, 0x15A1);
        assert_eq!(E1000E_DEVICE_ID_I219_LM, 0x15A3);
    }

    #[test]
    fn device_ids_are_distinct() {
        // Sanity: the kernel matcher discriminates on device ID, so the
        // supported set MUST NOT collapse to fewer than five entries.
        let ids = [
            E1000E_DEVICE_ID_82574L,
            E1000E_DEVICE_ID_I217_LM,
            E1000E_DEVICE_ID_I217_V,
            E1000E_DEVICE_ID_I218_LM,
            E1000E_DEVICE_ID_I219_LM,
        ];
        for (i, a) in ids.iter().enumerate() {
            for b in ids.iter().skip(i + 1) {
                assert_ne!(a, b, "device IDs collide: 0x{a:04X} / 0x{b:04X}");
            }
        }
    }

    #[test]
    fn matcher_accepts_every_supported_id() {
        // Every entry of the manifest table MUST satisfy the matcher;
        // future PRs adding new IDs should extend the match arm and
        // this test in lockstep.
        for device in [
            E1000E_DEVICE_ID_82574L,
            E1000E_DEVICE_ID_I217_LM,
            E1000E_DEVICE_ID_I217_V,
            E1000E_DEVICE_ID_I218_LM,
            E1000E_DEVICE_ID_I219_LM,
        ] {
            assert!(
                is_e1000e_device(INTEL_PCI_VENDOR_ID, device),
                "matcher rejected supported device 0x{device:04X}"
            );
        }
    }

    #[test]
    fn matcher_rejects_other_intel_devices() {
        // The 82599 (10 GbE) and X550 (10 GbE) use a different register
        // layout (ixgbe driver family). They MUST NOT be claimed by the
        // e1000e driver.
        assert!(!is_e1000e_device(INTEL_PCI_VENDOR_ID, 0x10FB)); // 82599 SFP
        assert!(!is_e1000e_device(INTEL_PCI_VENDOR_ID, 0x1563)); // X550-T2
    }

    #[test]
    fn matcher_rejects_non_intel_vendors() {
        // virtio-net (Red Hat) MUST NOT be matched by the e1000e driver.
        assert!(!is_e1000e_device(0x1AF4, 0x1041));
        // Realtek RTL8169 MUST NOT be matched either.
        assert!(!is_e1000e_device(0x10EC, 0x8169));
    }

    #[test]
    fn matcher_rejects_zero_triple() {
        // A zero vendor MUST NOT auto-match (defence against PCI
        // enumeration walking unpopulated slots that return all-ones or
        // all-zeros).
        assert!(!is_e1000e_device(0x0000, 0x10D3));
        assert!(!is_e1000e_device(0x0000, 0x0000));
    }
}
