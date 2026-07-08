//! PCI configuration-space bus scanner with PCI-to-PCI bridge traversal
//! (P6.7.9-pre.9).
//!
//! Discovers PCI devices across all reachable buses via the legacy
//! CF8/CFC I/O port mechanism.  When a Type 1 header (PCI-to-PCI bridge)
//! is found, the scanner reads the bridge's secondary bus number and
//! recursively enumerates devices behind it.
//!
//! ## Scope
//!
//! Phase 1 scans up to 256 buses with a recursion depth limit of 8
//! levels (matching typical hardware topologies).  Each bus enumerates
//! 32 device slots × 8 functions.

#![allow(unsafe_code, reason = "PCI config-space reads via I/O ports")]
#![allow(
    clippy::cast_possible_truncation,
    clippy::doc_markdown,
    clippy::indexing_slicing,
    reason = "PCI register fields are well-defined widths; VirtIO/NVMe are spec names; \
              scanner array indexing is bounded by MAX_DISCOVERED"
)]

use super::arch;

/// Maximum number of devices the scanner will record.
const MAX_DISCOVERED: usize = 64;

/// Maximum bridge traversal depth to prevent infinite loops on
/// misconfigured topologies.
const MAX_BRIDGE_DEPTH: u8 = 8;

/// PCI header type register offset.
const PCI_REG_HEADER_TYPE: u8 = 0x0C;

/// PCI class/subclass register offset.
const PCI_REG_CLASS: u8 = 0x08;

/// Bridge secondary/primary bus register offset (Type 1 header).
const PCI_REG_BUS_INFO: u8 = 0x18;

/// PCI-to-PCI bridge class code.
const PCI_CLASS_BRIDGE: u8 = 0x06;

/// PCI-to-PCI bridge sub-class code.
const PCI_SUBCLASS_PCI_TO_PCI: u8 = 0x04;

/// Dword holding both the Command (low 16) and Status (high 16) registers.
/// The Status register lives at config offset 0x06.
const PCI_REG_STATUS_DWORD: u8 = 0x04;
/// Capabilities-list-present flag = bit 4 of the 16-bit Status register. The
/// caller shifts the 0x04 dword right by 16 before testing this mask, so a
/// capabilities list at offset 0x34 is present when `(dword >> 16) & this`.
const PCI_STATUS_CAP_LIST: u32 = 1 << 4;
/// Capabilities pointer register (offset 0x34); low byte = first cap offset.
const PCI_REG_CAP_PTR: u8 = 0x34;
/// Vendor-specific PCI capability id. virtio modern places its config
/// structures behind a chain of these (virtio 1.0 § 4.1.4).
const PCI_CAP_ID_VENDOR: u8 = 0x09;

/// virtio `cfg_type` values inside a `VIRTIO_PCI_CAP` (virtio 1.0 § 4.1.4.1).
const VIRTIO_PCI_CAP_COMMON_CFG: u8 = 1;
const VIRTIO_PCI_CAP_NOTIFY_CFG: u8 = 2;
const VIRTIO_PCI_CAP_ISR_CFG: u8 = 3;
const VIRTIO_PCI_CAP_DEVICE_CFG: u8 = 4;

/// One discovered virtio modern config structure: which BAR it lives in,
/// the byte offset within that BAR, and the structure length.
#[derive(Clone, Copy, Default)]
pub struct VirtioCapLocation {
    /// `true` once this location has been populated from the cap chain.
    pub present: bool,
    /// BAR index (0..=5) the structure is mapped through.
    pub bar: u8,
    /// Byte offset of the structure within its BAR.
    pub offset: u32,
    /// Structure length in bytes.
    pub length: u32,
}

/// Modern-virtio register geometry from a device's PCI capability chain.
///
/// Carries everything a Ring-3 driver needs to locate the common-config,
/// notify, ISR, and device-config windows inside the BARs (virtio 1.0 § 4.1.4).
#[derive(Clone, Copy, Default)]
pub struct VirtioModernCaps {
    /// `common_cfg` (cfg_type 1) — the device control/queue registers.
    pub common: VirtioCapLocation,
    /// `notify` (cfg_type 2) — the queue-notify doorbell window.
    pub notify: VirtioCapLocation,
    /// `isr` (cfg_type 3) — the legacy-INTx ISR status byte.
    pub isr: VirtioCapLocation,
    /// `device` (cfg_type 4) — the virtio-net device-specific config (MAC …).
    pub device: VirtioCapLocation,
    /// `notify_off_multiplier` from the notify capability (virtio 1.0
    /// § 4.1.4.4): notify address = notify.offset + queue_notify_off * mult.
    pub notify_off_multiplier: u32,
    /// `true` if at least the `common` and `notify` structures were found —
    /// the minimum a driver needs to program a queue and kick it.
    pub usable: bool,
}

/// Walk a device's PCI capability list for modern-virtio config structures.
///
/// Extracts the common/notify/isr/device structure locations (virtio 1.0
/// § 4.1.4). Returns `None` if the device has no capability list or no virtio
/// vendor capabilities. Pure config-space reads — no device side effects.
///
/// # Safety
///
/// Ring-0 only (issues CF8/CFC config reads).
pub unsafe fn parse_virtio_modern_caps(bus: u8, dev: u8, func: u8) -> Option<VirtioModernCaps> {
    // Capabilities list present? The Status register is the UPPER 16 bits of
    // the 0x04 dword (Command is the lower 16); the cap-list flag is bit 4 of
    // Status, i.e. bit 20 of the dword — shift the dword down by 16 first.
    let cmd_status = unsafe { arch::pci_cfg_read32(bus, dev, func, PCI_REG_STATUS_DWORD) };
    let status = cmd_status >> 16;
    if status & PCI_STATUS_CAP_LIST == 0 {
        return None;
    }

    let mut caps = VirtioModernCaps::default();
    let mut found_any = false;

    // First capability offset (low byte of the cap pointer dword).
    let mut cap_off =
        (unsafe { arch::pci_cfg_read32(bus, dev, func, PCI_REG_CAP_PTR) } & 0xFF) as u8;

    // Bounded walk: the cap list is at most 48 entries (256-byte config space
    // / 4-byte minimum cap), so cap a generous iteration count to defend
    // against a malformed self-referential chain.
    let mut guard = 0u32;
    while cap_off != 0 && guard < 64 {
        guard += 1;
        // A capability must live in the 0x40..0xFF window; anything below the
        // standard header is a malformed pointer — stop.
        if cap_off < 0x40 {
            break;
        }

        // cap[0] = cap_id, cap[1] = next_ptr (read the dword at cap_off).
        let cap_dw0 = unsafe { arch::pci_cfg_read32(bus, dev, func, cap_off) };
        let cap_id = (cap_dw0 & 0xFF) as u8;
        let next = ((cap_dw0 >> 8) & 0xFF) as u8;

        if cap_id == PCI_CAP_ID_VENDOR {
            // VIRTIO_PCI_CAP layout (virtio 1.0 § 4.1.4):
            //   +0x00 cap_vndr (u8) | cap_next (u8) | cap_len (u8) | cfg_type (u8)
            //   +0x04 bar (u8) | id (u8) | pad[2]
            //   +0x08 offset (u32 LE)
            //   +0x0C length (u32 LE)
            //   +0x10 notify_off_multiplier (u32 LE) — only for NOTIFY caps
            let cfg_type = ((cap_dw0 >> 24) & 0xFF) as u8;
            let dw1 = unsafe { arch::pci_cfg_read32(bus, dev, func, cap_off.wrapping_add(4)) };
            let bar = (dw1 & 0xFF) as u8;
            let offset = unsafe { arch::pci_cfg_read32(bus, dev, func, cap_off.wrapping_add(8)) };
            let length = unsafe { arch::pci_cfg_read32(bus, dev, func, cap_off.wrapping_add(12)) };

            let loc = VirtioCapLocation {
                present: true,
                bar,
                offset,
                length,
            };
            match cfg_type {
                VIRTIO_PCI_CAP_COMMON_CFG => {
                    caps.common = loc;
                    found_any = true;
                }
                VIRTIO_PCI_CAP_NOTIFY_CFG => {
                    caps.notify = loc;
                    caps.notify_off_multiplier =
                        unsafe { arch::pci_cfg_read32(bus, dev, func, cap_off.wrapping_add(16)) };
                    found_any = true;
                }
                VIRTIO_PCI_CAP_ISR_CFG => caps.isr = loc,
                VIRTIO_PCI_CAP_DEVICE_CFG => caps.device = loc,
                _ => {}
            }
        }

        cap_off = next;
    }

    if !found_any {
        return None;
    }
    caps.usable = caps.common.present && caps.notify.present;
    Some(caps)
}

/// A discovered PCI device descriptor.
#[derive(Debug, Clone, Copy)]
pub struct PciDevice {
    /// PCI bus number.
    pub bus: u8,
    /// PCI device number (0..31).
    pub device: u8,
    /// PCI function number (0..7).
    pub function: u8,
    /// Vendor ID from config register 0x00\[15:0\].
    pub vendor_id: u16,
    /// Device ID from config register 0x00\[31:16\].
    pub device_id: u16,
    /// Class code from config register 0x08\[31:24\].
    pub class_code: u8,
    /// Sub-class code from config register 0x08\[23:16\].
    pub subclass: u8,
    /// BAR0 raw value from config register 0x10.
    pub bar0: u32,
    /// BAR1 raw value from config register 0x14.
    pub bar1: u32,
    /// BAR4 raw value from config register 0x20.
    pub bar4: u32,
    /// BAR5 raw value from config register 0x24.
    pub bar5: u32,
    /// Interrupt line from config register 0x3C\[7:0\].
    pub irq_line: u8,
    /// Header type (0 = endpoint, 1 = PCI-to-PCI bridge).
    pub header_type: u8,
}

impl PciDevice {
    /// Decode a 32-bit BAR as a memory-mapped base address (mask low 4 bits).
    #[must_use]
    pub const fn bar_mmio_base(bar_raw: u32) -> u64 {
        (bar_raw & 0xFFFF_FFF0) as u64
    }

    /// Check if BAR is 64-bit (bit 2:1 of the BAR value == 0b10).
    #[must_use]
    pub const fn bar_is_64bit(bar_raw: u32) -> bool {
        (bar_raw & 0x06) == 0x04
    }

    /// Reconstruct a 64-bit BAR address from two consecutive 32-bit BARs.
    #[must_use]
    pub const fn bar64(low: u32, high: u32) -> u64 {
        ((high as u64) << 32) | ((low & 0xFFFF_FFF0) as u64)
    }

    /// Return the 64-bit physical base of BAR0, handling 32/64-bit BARs.
    #[must_use]
    pub const fn bar0_phys(&self) -> u64 {
        if Self::bar_is_64bit(self.bar0) {
            Self::bar64(self.bar0, self.bar1)
        } else {
            Self::bar_mmio_base(self.bar0)
        }
    }

    /// Return the 64-bit physical base of BAR4, handling 32/64-bit BARs.
    #[must_use]
    pub const fn bar4_phys(&self) -> u64 {
        if Self::bar_is_64bit(self.bar4) {
            Self::bar64(self.bar4, self.bar5)
        } else {
            Self::bar_mmio_base(self.bar4)
        }
    }

    /// Check if BAR is an I/O space BAR (bit 0 set).
    #[must_use]
    pub const fn bar_is_io(bar_raw: u32) -> bool {
        (bar_raw & 0x01) != 0
    }

    /// Decode an I/O space BAR as a port base address (mask low 2 bits).
    #[must_use]
    pub const fn bar_io_base(bar_raw: u32) -> u16 {
        (bar_raw & 0xFFFF_FFFC) as u16
    }

    /// Returns `true` if this device is a PCI-to-PCI bridge (Type 1).
    #[must_use]
    pub const fn is_pci_bridge(&self) -> bool {
        self.class_code == PCI_CLASS_BRIDGE
            && self.subclass == PCI_SUBCLASS_PCI_TO_PCI
            && (self.header_type & 0x7F) == 0x01
    }
}

/// Result of a PCI bus scan.
pub struct ScanResult {
    devices: [Option<PciDevice>; MAX_DISCOVERED],
    count: usize,
    buses_scanned: u16,
    bridges_found: u8,
}

impl ScanResult {
    /// Number of devices discovered.
    #[must_use]
    pub const fn count(&self) -> usize {
        self.count
    }

    /// Number of PCI buses scanned during traversal.
    #[must_use]
    pub const fn buses_scanned(&self) -> u16 {
        self.buses_scanned
    }

    /// Number of PCI-to-PCI bridges found.
    #[must_use]
    pub const fn bridges_found(&self) -> u8 {
        self.bridges_found
    }

    /// Find the first device matching the given vendor and device ID.
    #[must_use]
    pub fn find(&self, vendor_id: u16, device_id: u16) -> Option<&PciDevice> {
        self.iter()
            .find(|d| d.vendor_id == vendor_id && d.device_id == device_id)
    }

    /// Find the first device matching the given vendor ID (any device ID).
    #[must_use]
    pub fn find_by_vendor(&self, vendor_id: u16) -> Option<&PciDevice> {
        self.iter().find(|d| d.vendor_id == vendor_id)
    }

    /// Find the first device matching the given class + subclass.
    #[must_use]
    pub fn find_by_class(&self, class_code: u8, subclass: u8) -> Option<&PciDevice> {
        self.iter()
            .find(|d| d.class_code == class_code && d.subclass == subclass)
    }

    /// Iterator over discovered devices.
    pub fn iter(&self) -> impl Iterator<Item = &PciDevice> {
        self.devices
            .get(..self.count)
            .unwrap_or(&[])
            .iter()
            .flatten()
    }

    fn push(&mut self, dev: PciDevice) -> bool {
        if self.count < MAX_DISCOVERED {
            self.devices[self.count] = Some(dev);
            self.count += 1;
            true
        } else {
            false
        }
    }
}

/// Scan all reachable PCI buses, traversing PCI-to-PCI bridges.
///
/// Starts at bus 0 and recursively follows every bridge's secondary bus.
/// A depth limit of `MAX_BRIDGE_DEPTH` prevents runaway recursion on
/// misconfigured topologies.
///
/// # Safety
///
/// Must be called from Ring 0.  PCI config reads via I/O ports are
/// side-effect-free.
pub unsafe fn scan_all_buses() -> ScanResult {
    let mut result = ScanResult {
        devices: [None; MAX_DISCOVERED],
        count: 0,
        buses_scanned: 0,
        bridges_found: 0,
    };

    // Check if host bridge is a multi-function device (multiple root
    // complexes on separate bus segments).
    let header_type_0 = unsafe { arch::pci_cfg_read32(0, 0, 0, PCI_REG_HEADER_TYPE) };
    let multi_func = ((header_type_0 >> 23) & 1) != 0;

    if multi_func {
        for func in 0u8..8 {
            let id = unsafe { arch::pci_cfg_read32(0, 0, func, 0x00) };
            let vendor_id = (id & 0xFFFF) as u16;
            if vendor_id == 0xFFFF {
                continue;
            }
            unsafe { scan_bus(func, 0, &mut result) };
        }
    } else {
        unsafe { scan_bus(0, 0, &mut result) };
    }

    result
}

/// Scan PCI bus 0 for all present devices (backward-compatible entry point).
///
/// # Safety
///
/// Must be called from Ring 0.
pub unsafe fn scan_bus_0() -> ScanResult {
    unsafe { scan_all_buses() }
}

/// Recursively scan a single PCI bus.
///
/// # Safety
///
/// Ring-0 only.
unsafe fn scan_bus(bus: u8, depth: u8, result: &mut ScanResult) {
    if depth > MAX_BRIDGE_DEPTH {
        return;
    }

    result.buses_scanned += 1;

    for dev_slot in 0u8..32 {
        for func in 0u8..8 {
            let id = unsafe { arch::pci_cfg_read32(bus, dev_slot, func, 0x00) };
            let vendor_id = (id & 0xFFFF) as u16;
            if vendor_id == 0xFFFF {
                if func == 0 {
                    break;
                }
                continue;
            }
            let device_id = ((id >> 16) & 0xFFFF) as u16;

            let class_reg = unsafe { arch::pci_cfg_read32(bus, dev_slot, func, PCI_REG_CLASS) };
            let class_code = ((class_reg >> 24) & 0xFF) as u8;
            let subclass = ((class_reg >> 16) & 0xFF) as u8;

            let header_reg =
                unsafe { arch::pci_cfg_read32(bus, dev_slot, func, PCI_REG_HEADER_TYPE) };
            let header_type = ((header_reg >> 16) & 0xFF) as u8;

            let bar0 = unsafe { arch::pci_cfg_read32(bus, dev_slot, func, 0x10) };
            let bar1 = unsafe { arch::pci_cfg_read32(bus, dev_slot, func, 0x14) };
            let bar4 = unsafe { arch::pci_cfg_read32(bus, dev_slot, func, 0x20) };
            let bar5 = unsafe { arch::pci_cfg_read32(bus, dev_slot, func, 0x24) };

            let intr_reg = unsafe { arch::pci_cfg_read32(bus, dev_slot, func, 0x3C) };
            let irq_line = (intr_reg & 0xFF) as u8;

            let dev = PciDevice {
                bus,
                device: dev_slot,
                function: func,
                vendor_id,
                device_id,
                class_code,
                subclass,
                bar0,
                bar1,
                bar4,
                bar5,
                irq_line,
                header_type,
            };

            let is_bridge = dev.is_pci_bridge();
            result.push(dev);

            if is_bridge {
                result.bridges_found += 1;
                let bus_info =
                    unsafe { arch::pci_cfg_read32(bus, dev_slot, func, PCI_REG_BUS_INFO) };
                let secondary_bus = ((bus_info >> 8) & 0xFF) as u8;
                if secondary_bus != 0 && secondary_bus != bus {
                    unsafe { scan_bus(secondary_bus, depth + 1, result) };
                }
            }

            if func == 0 {
                let multi_func = (header_type >> 7) & 1;
                if multi_func == 0 {
                    break;
                }
            }
        }
    }
}

/// Enable Bus Master + Memory Space on the given PCI device.
///
/// # Safety
///
/// Ring 0 only.  Writes to PCI command register.
pub unsafe fn enable_bus_master(dev: &PciDevice) {
    let cmd = unsafe { arch::pci_cfg_read32(dev.bus, dev.device, dev.function, 0x04) };
    let new_cmd = cmd | 0x0006; // MSE (bit 1) | BME (bit 2)
    if new_cmd != cmd {
        unsafe { pci_cfg_write_cmd(dev, new_cmd) };
    }
}

/// Enable Bus Master + Memory Space + I/O Space on the given PCI device.
///
/// # Safety
///
/// Ring 0 only.  Writes to PCI command register.
pub unsafe fn enable_device_full(dev: &PciDevice) {
    let cmd = unsafe { arch::pci_cfg_read32(dev.bus, dev.device, dev.function, 0x04) };
    let new_cmd = cmd | 0x0007; // IOSE (bit 0) | MSE (bit 1) | BME (bit 2)
    if new_cmd != cmd {
        unsafe { pci_cfg_write_cmd(dev, new_cmd) };
    }
}

unsafe fn pci_cfg_write_cmd(dev: &PciDevice, cmd: u32) {
    let addr: u32 = 0x8000_0000
        | (u32::from(dev.bus) << 16)
        | (u32::from(dev.device) << 11)
        | (u32::from(dev.function) << 8)
        | 0x04u32;
    unsafe {
        arch::outl(0xCF8, addr);
        arch::outl(0xCFC, cmd);
    }
}

// =========================================================================
// Well-known PCI vendor/device IDs
// =========================================================================

/// Red Hat / VirtIO vendor ID.
pub const VIRTIO_VENDOR_ID: u16 = 0x1AF4;

/// VirtIO network device (transitional).
pub const VIRTIO_NET_DEVICE_ID_TRANSITIONAL: u16 = 0x1000;

/// VirtIO network device (modern, non-transitional).
pub const VIRTIO_NET_DEVICE_ID_MODERN: u16 = 0x1041;

/// Intel vendor ID.
pub const INTEL_VENDOR_ID: u16 = 0x8086;

/// NVMe class code (Mass Storage Controller, NVM Express).
pub const NVME_CLASS_CODE: u8 = 0x01;
/// NVMe sub-class code.
pub const NVME_SUBCLASS: u8 = 0x08;

/// Ethernet Network Controller class code (PCI SIG base class 0x02).
pub const ETHERNET_CLASS_CODE: u8 = 0x02;
/// Ethernet sub-class code (PCI SIG sub-class 0x00).
pub const ETHERNET_SUBCLASS: u8 = 0x00;

/// xHCI USB Host Controller class code (Serial Bus Controller, base class 0x0C).
pub const XHCI_CLASS_CODE: u8 = 0x0C;
/// xHCI USB Host Controller sub-class code (USB Controller, sub-class 0x03).
pub const XHCI_SUBCLASS: u8 = 0x03;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bar_mmio_base_masks_low_bits() {
        assert_eq!(PciDevice::bar_mmio_base(0xFEBC_0001), 0xFEBC_0000);
        assert_eq!(PciDevice::bar_mmio_base(0xFEBC_000F), 0xFEBC_0000);
    }

    #[test]
    fn bar_is_64bit_detects_type() {
        assert!(!PciDevice::bar_is_64bit(0xFEBC_0000));
        assert!(PciDevice::bar_is_64bit(0xFEBC_0004));
    }

    #[test]
    fn bar64_combines_halves() {
        assert_eq!(
            PciDevice::bar64(0x0000_0004, 0x0000_0001),
            0x0000_0001_0000_0000
        );
    }

    #[test]
    fn scan_result_find_returns_none_when_empty() {
        let result = ScanResult {
            devices: [None; MAX_DISCOVERED],
            count: 0,
            buses_scanned: 0,
            bridges_found: 0,
        };
        assert!(result.find(0x1AF4, 0x1000).is_none());
    }

    #[test]
    fn scan_result_iter_yields_nothing_when_empty() {
        let result = ScanResult {
            devices: [None; MAX_DISCOVERED],
            count: 0,
            buses_scanned: 0,
            bridges_found: 0,
        };
        assert_eq!(result.iter().count(), 0);
    }

    #[test]
    fn scan_result_push_respects_capacity() {
        let mut result = ScanResult {
            devices: [None; MAX_DISCOVERED],
            count: 0,
            buses_scanned: 0,
            bridges_found: 0,
        };
        let dev = PciDevice {
            bus: 0,
            device: 1,
            function: 0,
            vendor_id: 0x1AF4,
            device_id: 0x1000,
            class_code: 0x02,
            subclass: 0x00,
            bar0: 0xFEBC_0000,
            bar1: 0,
            bar4: 0,
            bar5: 0,
            irq_line: 11,
            header_type: 0x00,
        };
        for _ in 0..MAX_DISCOVERED {
            assert!(result.push(dev));
        }
        assert!(!result.push(dev));
        assert_eq!(result.count(), MAX_DISCOVERED);
    }

    #[test]
    fn is_pci_bridge_detects_type1_header() {
        let bridge = PciDevice {
            bus: 0,
            device: 0,
            function: 0,
            vendor_id: 0x8086,
            device_id: 0x1234,
            class_code: PCI_CLASS_BRIDGE,
            subclass: PCI_SUBCLASS_PCI_TO_PCI,
            bar0: 0,
            bar1: 0,
            bar4: 0,
            bar5: 0,
            irq_line: 0,
            header_type: 0x01,
        };
        assert!(bridge.is_pci_bridge());
    }

    #[test]
    fn is_pci_bridge_rejects_non_bridge() {
        let endpoint = PciDevice {
            bus: 0,
            device: 1,
            function: 0,
            vendor_id: 0x1AF4,
            device_id: 0x1000,
            class_code: 0x02,
            subclass: 0x00,
            bar0: 0xFEBC_0000,
            bar1: 0,
            bar4: 0,
            bar5: 0,
            irq_line: 11,
            header_type: 0x00,
        };
        assert!(!endpoint.is_pci_bridge());
    }

    #[test]
    fn is_pci_bridge_ignores_multifunction_bit() {
        let bridge_mf = PciDevice {
            bus: 0,
            device: 0,
            function: 0,
            vendor_id: 0x8086,
            device_id: 0x1234,
            class_code: PCI_CLASS_BRIDGE,
            subclass: PCI_SUBCLASS_PCI_TO_PCI,
            bar0: 0,
            bar1: 0,
            bar4: 0,
            bar5: 0,
            irq_line: 0,
            header_type: 0x81, // multi-function bit set
        };
        assert!(bridge_mf.is_pci_bridge());
    }

    #[test]
    fn find_by_class_returns_matching_device() {
        let mut result = ScanResult {
            devices: [None; MAX_DISCOVERED],
            count: 0,
            buses_scanned: 1,
            bridges_found: 0,
        };
        let dev = PciDevice {
            bus: 0,
            device: 3,
            function: 0,
            vendor_id: 0x8086,
            device_id: 0x5678,
            class_code: NVME_CLASS_CODE,
            subclass: NVME_SUBCLASS,
            bar0: 0xFC00_0000,
            bar1: 0,
            bar4: 0,
            bar5: 0,
            irq_line: 10,
            header_type: 0x00,
        };
        result.push(dev);
        assert!(
            result
                .find_by_class(NVME_CLASS_CODE, NVME_SUBCLASS)
                .is_some()
        );
        assert!(result.find_by_class(0x02, 0x00).is_none());
    }

    #[test]
    fn bar_is_io_detects_io_space() {
        assert!(PciDevice::bar_is_io(0x0000_6081));
        assert!(PciDevice::bar_is_io(0x0000_0001));
        assert!(!PciDevice::bar_is_io(0xFEBC_0000));
        assert!(!PciDevice::bar_is_io(0xFEBC_0004));
    }

    #[test]
    fn bar_io_base_masks_low_bits() {
        assert_eq!(PciDevice::bar_io_base(0x0000_6081), 0x6080);
        assert_eq!(PciDevice::bar_io_base(0x0000_0001), 0x0000);
        assert_eq!(PciDevice::bar_io_base(0x0000_CF01), 0xCF00);
    }

    #[test]
    fn scan_result_metadata_initializes_zero() {
        let result = ScanResult {
            devices: [None; MAX_DISCOVERED],
            count: 0,
            buses_scanned: 0,
            bridges_found: 0,
        };
        assert_eq!(result.buses_scanned(), 0);
        assert_eq!(result.bridges_found(), 0);
    }
}
