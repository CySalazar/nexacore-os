//! WS2-16 — PCI device → driver-pack matching + auto-loader core.
//!
//! The kernel's PCI ECAM walk discovers devices; this module decides **which
//! signed driver pack** ([`crate::driver_manifest`]) should claim each one, and
//! models the surprise add/remove (hotplug) lifecycle. It is the host-testable
//! decision layer — the bare-metal seams it feeds are:
//!
//! * the actual `DriverLoad (73)` syscall invocation (`bare_metal::driver_loader`),
//! * the ACPI GPE / `Notify` hotplug interrupt source (bus-check / device-check).
//!
//! ## Why a richer matcher than `PciMatcher`
//!
//! [`crate::driver_manifest::PciMatcher`] matches only an exact `(vendor,
//! device)` pair. Real hardware needs **class-based** fallbacks too: a generic
//! AHCI driver claims *any* `class=0x01 subclass=0x06 prog_if=0x01` device
//! regardless of vendor, while a vendor-specific NIC driver claims an exact
//! `(vendor, device)`. [`crate::driver_match::MatchRule`] expresses both, and
//! [`crate::driver_match::DriverMatchTable`] resolves a scanned device to the
//! **most specific** matching pack so an exact vendor:device rule always beats a
//! generic class rule.

use alloc::{string::String, vec::Vec};

/// The PCI identity of a scanned device.
///
/// Decoupled from the bare-metal `pci_scan::PciDevice` (which is feature-gated)
/// so the match logic stays host-testable; the bare-metal bus walk constructs
/// one of these per device.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PciIdent {
    /// 16-bit PCI vendor id (config space 0x00\[15:0\]).
    pub vendor: u16,
    /// 16-bit PCI device id (config space 0x00\[31:16\]).
    pub device: u16,
    /// Class code (config space 0x08\[31:24\]).
    pub class: u8,
    /// Sub-class (config space 0x08\[23:16\]).
    pub subclass: u8,
    /// Programming interface (config space 0x08\[15:8\]).
    pub prog_if: u8,
}

/// A rule that claims a device for a driver pack.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MatchRule {
    /// Exact `(vendor, device)` — the most specific rule, for
    /// vendor-specific drivers.
    VendorDevice {
        /// PCI vendor id.
        vendor: u16,
        /// PCI device id.
        device: u16,
    },
    /// Class-based, for generic drivers (AHCI, xHCI, …). `subclass` and
    /// `prog_if` are optional refinements; `None` means "any".
    Class {
        /// PCI class code (required).
        class: u8,
        /// Optional sub-class refinement.
        subclass: Option<u8>,
        /// Optional programming-interface refinement.
        prog_if: Option<u8>,
    },
}

impl MatchRule {
    /// Whether this rule claims `id`.
    #[must_use]
    pub fn matches(self, id: PciIdent) -> bool {
        match self {
            Self::VendorDevice { vendor, device } => id.vendor == vendor && id.device == device,
            Self::Class {
                class,
                subclass,
                prog_if,
            } => {
                id.class == class
                    && subclass.is_none_or(|s| id.subclass == s)
                    && prog_if.is_none_or(|p| id.prog_if == p)
            }
        }
    }

    /// Specificity score — higher binds first. An exact `(vendor, device)`
    /// always outranks any class rule; among class rules, more refinements
    /// score higher.
    #[must_use]
    pub fn specificity(self) -> u32 {
        match self {
            Self::VendorDevice { .. } => 100,
            Self::Class {
                subclass, prog_if, ..
            } => 10 + u32::from(subclass.is_some()) * 20 + u32::from(prog_if.is_some()) * 5,
        }
    }
}

/// A driver-pack identifier (the pack's `DriverMeta::name`).
pub type PackId = String;

/// One `(rule → pack)` registration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MatchEntry {
    /// The claiming rule.
    pub rule: MatchRule,
    /// The pack that claims devices matching `rule`.
    pub pack: PackId,
}

/// The device → driver-pack match table (WS2-16.1).
///
/// Packs register their matchers here at boot (or on pack install). Resolution
/// (WS2-16.2) returns the most-specific matching pack; ties at equal
/// specificity are broken deterministically by registration order (first wins).
#[derive(Debug, Clone, Default)]
pub struct DriverMatchTable {
    entries: Vec<MatchEntry>,
}

impl DriverMatchTable {
    /// An empty table.
    #[must_use]
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    /// Register a `(rule → pack)` entry.
    pub fn register(&mut self, rule: MatchRule, pack: impl Into<PackId>) {
        self.entries.push(MatchEntry {
            rule,
            pack: pack.into(),
        });
    }

    /// Number of registered entries.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the table has no entries.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Resolve `id` to the most-specific matching pack (WS2-16.2).
    ///
    /// Returns `None` when no rule claims the device. Among equally-specific
    /// matches the first registered wins (stable, deterministic).
    #[must_use]
    pub fn resolve(&self, id: PciIdent) -> Option<&PackId> {
        let mut best: Option<(&MatchEntry, u32)> = None;
        for e in &self.entries {
            if e.rule.matches(id) {
                let spec = e.rule.specificity();
                // Strict `>` keeps the earliest entry on a tie.
                if best.is_none_or(|(_, bs)| spec > bs) {
                    best = Some((e, spec));
                }
            }
        }
        best.map(|(e, _)| &e.pack)
    }

    /// All packs that claim `id`, highest-specificity first (stable within a
    /// specificity tier). Useful for diagnostics / conflict reporting.
    #[must_use]
    pub fn resolve_all(&self, id: PciIdent) -> Vec<&PackId> {
        let mut hits: Vec<(&MatchEntry, usize)> = self
            .entries
            .iter()
            .enumerate()
            .filter(|(_, e)| e.rule.matches(id))
            .map(|(i, e)| (e, i))
            .collect();
        // Sort by specificity desc, then registration order asc.
        hits.sort_by(|(a, ai), (b, bi)| {
            b.rule
                .specificity()
                .cmp(&a.rule.specificity())
                .then(ai.cmp(bi))
        });
        hits.into_iter().map(|(e, _)| &e.pack).collect()
    }
}

/// A hotplug event from the ACPI notification source (WS2-16.4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HotplugEvent {
    /// A device appeared (bus-check / device-check `Notify` 0x00 / 0x01).
    Add(PciIdent),
    /// A device was removed (eject `Notify` 0x03).
    Remove(PciIdent),
}

/// The action the auto-loader should take for a hotplug event (WS2-16.3/.5/.6).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HotplugAction {
    /// Bind `pack` to the device (issue `DriverLoad`).
    Bind {
        /// The pack to load.
        pack: PackId,
        /// The device being claimed.
        ident: PciIdent,
    },
    /// Tear down the driver currently bound to the device.
    Teardown {
        /// The pack being unbound.
        pack: PackId,
        /// The device being removed.
        ident: PciIdent,
    },
    /// No registered pack claims the device; leave it unbound.
    NoDriver(PciIdent),
    /// A remove for a device that was never bound — nothing to do.
    NotBound(PciIdent),
}

/// The auto-loader: a match table plus the set of currently-bound devices.
///
/// Surprise add/remove are handled idempotently (WS2-16.5/.6); the actual
/// `DriverLoad`/teardown syscalls are issued by the bare-metal seam in response
/// to the returned [`HotplugAction`].
#[derive(Debug, Clone, Default)]
pub struct DriverAutoLoader {
    table: DriverMatchTable,
    bound: Vec<(PciIdent, PackId)>,
}

impl DriverAutoLoader {
    /// Build from a populated match table.
    #[must_use]
    pub fn new(table: DriverMatchTable) -> Self {
        Self {
            table,
            bound: Vec::new(),
        }
    }

    /// The pack currently bound to `id`, if any.
    #[must_use]
    pub fn bound_pack(&self, id: PciIdent) -> Option<&PackId> {
        self.bound.iter().find(|(i, _)| *i == id).map(|(_, p)| p)
    }

    /// Number of currently-bound devices.
    #[must_use]
    pub fn bound_count(&self) -> usize {
        self.bound.len()
    }

    /// Plan + record the action for a hotplug event.
    ///
    /// On `Add`: resolve to a pack and bind (idempotent — re-adding an
    /// already-bound device that resolves to the same pack is still reported as
    /// `Bind`, but does not duplicate the binding). On `Remove`: tear down if
    /// bound, else `NotBound`.
    pub fn on_event(&mut self, event: HotplugEvent) -> HotplugAction {
        match event {
            HotplugEvent::Add(ident) => match self.table.resolve(ident) {
                Some(pack) => {
                    let pack = pack.clone();
                    if let Some(slot) = self.bound.iter_mut().find(|(i, _)| *i == ident) {
                        slot.1.clone_from(&pack);
                    } else {
                        self.bound.push((ident, pack.clone()));
                    }
                    HotplugAction::Bind { pack, ident }
                }
                None => HotplugAction::NoDriver(ident),
            },
            HotplugEvent::Remove(ident) => {
                if let Some(pos) = self.bound.iter().position(|(i, _)| *i == ident) {
                    let (_, pack) = self.bound.remove(pos);
                    HotplugAction::Teardown { pack, ident }
                } else {
                    HotplugAction::NotBound(ident)
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // QEMU-ish identities: virtio-net (vendor 0x1AF4 device 0x1041), and a
    // generic AHCI controller (class 0x01 subclass 0x06 prog_if 0x01).
    const VIRTIO_NET: PciIdent = PciIdent {
        vendor: 0x1AF4,
        device: 0x1041,
        class: 0x02,
        subclass: 0x00,
        prog_if: 0x00,
    };
    const AHCI: PciIdent = PciIdent {
        vendor: 0x8086,
        device: 0x2922,
        class: 0x01,
        subclass: 0x06,
        prog_if: 0x01,
    };

    fn table() -> DriverMatchTable {
        let mut t = DriverMatchTable::new();
        // Generic AHCI by class, vendor-specific virtio-net by id.
        t.register(
            MatchRule::Class {
                class: 0x01,
                subclass: Some(0x06),
                prog_if: Some(0x01),
            },
            "nexacore-driver-ahci",
        );
        t.register(
            MatchRule::VendorDevice {
                vendor: 0x1AF4,
                device: 0x1041,
            },
            "nexacore-driver-net-virtio",
        );
        t
    }

    #[test]
    fn exact_vendor_device_resolves() {
        assert_eq!(
            table().resolve(VIRTIO_NET).map(String::as_str),
            Some("nexacore-driver-net-virtio")
        );
    }

    #[test]
    fn class_rule_resolves_generic_device() {
        assert_eq!(
            table().resolve(AHCI).map(String::as_str),
            Some("nexacore-driver-ahci")
        );
    }

    #[test]
    fn unmatched_device_resolves_to_none() {
        let unknown = PciIdent {
            vendor: 0xDEAD,
            device: 0xBEEF,
            class: 0xFF,
            subclass: 0xFF,
            prog_if: 0xFF,
        };
        assert!(table().resolve(unknown).is_none());
    }

    #[test]
    fn exact_match_beats_class_match() {
        // Register a class rule that ALSO matches virtio-net (class 0x02) after
        // the exact rule; the exact one must still win on specificity.
        let mut t = DriverMatchTable::new();
        t.register(
            MatchRule::Class {
                class: 0x02,
                subclass: None,
                prog_if: None,
            },
            "generic-net",
        );
        t.register(
            MatchRule::VendorDevice {
                vendor: 0x1AF4,
                device: 0x1041,
            },
            "nexacore-driver-net-virtio",
        );
        assert_eq!(
            t.resolve(VIRTIO_NET).map(String::as_str),
            Some("nexacore-driver-net-virtio"),
            "exact (vendor,device) must outrank a generic class rule"
        );
        // Both match → resolve_all reports the exact one first.
        let all: Vec<&str> = t
            .resolve_all(VIRTIO_NET)
            .iter()
            .map(|p| p.as_str())
            .collect();
        assert_eq!(all, ["nexacore-driver-net-virtio", "generic-net"]);
    }

    #[test]
    fn more_refined_class_rule_wins() {
        let mut t = DriverMatchTable::new();
        t.register(
            MatchRule::Class {
                class: 0x01,
                subclass: None,
                prog_if: None,
            },
            "generic-storage",
        );
        t.register(
            MatchRule::Class {
                class: 0x01,
                subclass: Some(0x06),
                prog_if: Some(0x01),
            },
            "nexacore-driver-ahci",
        );
        assert_eq!(
            t.resolve(AHCI).map(String::as_str),
            Some("nexacore-driver-ahci"),
            "class+subclass+prog_if must beat class-only"
        );
    }

    #[test]
    fn tie_breaks_on_registration_order() {
        let mut t = DriverMatchTable::new();
        let rule = MatchRule::VendorDevice {
            vendor: 0x1AF4,
            device: 0x1041,
        };
        t.register(rule, "first");
        t.register(rule, "second");
        assert_eq!(
            t.resolve(VIRTIO_NET).map(String::as_str),
            Some("first"),
            "equal specificity → earliest registration wins"
        );
    }

    #[test]
    fn hotplug_add_binds_then_remove_tears_down() {
        let mut loader = DriverAutoLoader::new(table());
        assert_eq!(loader.bound_count(), 0);

        let add = loader.on_event(HotplugEvent::Add(AHCI));
        assert_eq!(
            add,
            HotplugAction::Bind {
                pack: "nexacore-driver-ahci".into(),
                ident: AHCI,
            }
        );
        assert_eq!(loader.bound_count(), 1);
        assert_eq!(
            loader.bound_pack(AHCI).map(String::as_str),
            Some("nexacore-driver-ahci")
        );

        let remove = loader.on_event(HotplugEvent::Remove(AHCI));
        assert_eq!(
            remove,
            HotplugAction::Teardown {
                pack: "nexacore-driver-ahci".into(),
                ident: AHCI,
            }
        );
        assert_eq!(loader.bound_count(), 0);
    }

    #[test]
    fn hotplug_add_unknown_device_reports_no_driver() {
        let mut loader = DriverAutoLoader::new(table());
        let unknown = PciIdent {
            vendor: 0xDEAD,
            device: 0xBEEF,
            class: 0xFF,
            subclass: 0xFF,
            prog_if: 0xFF,
        };
        assert_eq!(
            loader.on_event(HotplugEvent::Add(unknown)),
            HotplugAction::NoDriver(unknown)
        );
        assert_eq!(loader.bound_count(), 0);
    }

    #[test]
    fn removing_an_unbound_device_is_a_noop() {
        let mut loader = DriverAutoLoader::new(table());
        assert_eq!(
            loader.on_event(HotplugEvent::Remove(AHCI)),
            HotplugAction::NotBound(AHCI)
        );
    }

    #[test]
    fn re_adding_a_device_does_not_duplicate_the_binding() {
        let mut loader = DriverAutoLoader::new(table());
        loader.on_event(HotplugEvent::Add(AHCI));
        loader.on_event(HotplugEvent::Add(AHCI));
        assert_eq!(loader.bound_count(), 1, "idempotent re-add");
    }
}
