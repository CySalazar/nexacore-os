//! Kernel-side MSI-X table programming for Ring 3 drivers (TASK-14,
//! ADR-0036 D4).
//!
//! A Ring 3 driver owns its device's BAR0 (via an `MmioMap` token) but
//! NOT the device's MSI-X table BAR, and it must never choose the MSI
//! address/vector (that would let it point interrupts at arbitrary
//! vectors). So the kernel programs MSI-X on the driver's behalf:
//!
//! 1. **At boot** ([`register`]), once the PCI scan has located a device
//!    and the caller has mapped its MSI-X table BAR into a kernel VA, the
//!    device's `(irq_line → table_va, config BDF, cap offset)` is recorded.
//! 2. **At `IrqAttach`** ([`program_vector`]), after the kernel has
//!    allocated a LAPIC `vector` and bound it to the driver's channel, the
//!    table entry is written (MSI address = BSP local-APIC, data = the
//!    allocated vector, unmasked) and the capability's Message-Control
//!    Enable bit is set.
//!
//! Phase 1 programs table entry 0 only (single IO completion vector,
//! single-queue per NCIP-Driver-NVMe-014 §S5). The store table is a small
//! fixed array; a device with no registration is a best-effort no-op
//! (the driver's cooperative CQ-drain keeps liveness — never silent: the
//! caller logs the outcome).
//!
//! ## Single-CPU invariant
//!
//! Like [`crate::irq_table`], the registration table is a `static mut`
//! valid under the Phase-1 single-CPU model: [`register`] runs only
//! during single-threaded boot, [`program_vector`] only on the
//! interrupt-masked SYSCALL path. MP enablement upgrades this to a
//! spinlock (tracked with the irq_table TODO).

#![allow(
    unsafe_code,
    reason = "MMIO writes to the MSI-X table + PCI config writes; SAFETY per fn"
)]

use crate::bare_metal::arch;

/// Maximum number of MSI-X-capable devices the kernel tracks. Phase 1
/// has at most NVMe + e1000e; 4 leaves headroom (xHCI, a second NIC).
const MAX_MSIX_DEVICES: usize = 4;

/// MSI-X capability id in the PCI capability list.
pub const PCI_CAP_ID_MSIX: u8 = 0x11;

/// BSP local-APIC MSI address (no redirection hint, physical mode,
/// destination APIC id 0). `0xFEE0_0000 | (apic_id << 12)`; `apic_id` is
/// 0 for the BSP, which is where Phase-1 IRQs are delivered.
const MSI_ADDR_BSP: u32 = 0xFEE0_0000;

/// One registered MSI-X device.
#[derive(Clone, Copy)]
struct MsixDevice {
    /// Opaque IRQ-line identifier the driver passes to `IrqAttach`
    /// (e.g. `34` for the NVMe IO CQ). `0` marks an empty slot.
    irq_line: u16,
    /// PCI config-space bus/device/function of the device.
    bus: u8,
    dev: u8,
    func: u8,
    /// Byte offset of the MSI-X capability in PCI config space.
    cap_off: u8,
    /// Kernel VA where the device's MSI-X table BAR was mapped at boot.
    table_va: u64,
}

impl MsixDevice {
    const EMPTY: Self = Self {
        irq_line: 0,
        bus: 0,
        dev: 0,
        func: 0,
        cap_off: 0,
        table_va: 0,
    };
}

/// Registration table. `static mut` under the single-CPU invariant (see
/// module docs).
static mut MSIX_DEVICES: [MsixDevice; MAX_MSIX_DEVICES] = [MsixDevice::EMPTY; MAX_MSIX_DEVICES];

/// Record a device's MSI-X parameters so [`program_vector`] can program
/// its table at `IrqAttach` time.
///
/// `table_va` must be a kernel VA at which the caller has already mapped
/// the device's MSI-X table BAR (the caller owns the mapper + allocator
/// at boot; this module only stores + writes). Returns `false` if the
/// table is full or `irq_line` is `0` (the empty sentinel).
///
/// # Safety
///
/// Boot-time, single-CPU. The caller guarantees `table_va` stays mapped
/// for the lifetime of the kernel.
pub unsafe fn register(
    irq_line: u16,
    bus: u8,
    dev: u8,
    func: u8,
    cap_off: u8,
    table_va: u64,
) -> bool {
    if irq_line == 0 {
        return false;
    }
    // SAFETY: single-CPU boot context; MSIX_DEVICES not aliased.
    let table = unsafe { &mut *core::ptr::addr_of_mut!(MSIX_DEVICES) };
    for slot in table.iter_mut() {
        if slot.irq_line == 0 {
            *slot = MsixDevice {
                irq_line,
                bus,
                dev,
                func,
                cap_off,
                table_va,
            };
            return true;
        }
    }
    false
}

/// Program the MSI-X table entry for the device registered under
/// `irq_line` so the device fires `vector` on the BSP.
///
/// No-op (returns `false`) when no device is registered for `irq_line`
/// — the attach still succeeds and the driver's cooperative CQ-drain
/// provides completion (best-effort, ADR-0036 D5). On success writes
/// table entry 0 (addr = BSP APIC, data = `vector`, unmasked) and sets
/// the capability's global Enable + clears the Function Mask.
///
/// # Safety
///
/// SYSCALL path, single-CPU, interrupts masked. The table VA was mapped
/// at boot and the PCI BDF is fixed for the device's lifetime.
pub unsafe fn program_vector(irq_line: u16, vector: u8) -> bool {
    // SAFETY: single-CPU SYSCALL path; MSIX_DEVICES not aliased.
    let table = unsafe { &*core::ptr::addr_of!(MSIX_DEVICES) };
    let Some(d) = table.iter().copied().find(|d| d.irq_line == irq_line) else {
        return false;
    };

    // --- Write MSI-X table entry 0 (16 bytes: addr_lo, addr_hi, data,
    //     vector control). ---
    // SAFETY: `table_va` is a mapped, uncacheable MMIO VA (boot mapping).
    unsafe {
        let entry = d.table_va as *mut u32;
        core::ptr::write_volatile(entry.add(0), MSI_ADDR_BSP); // message addr low
        core::ptr::write_volatile(entry.add(1), 0); // message addr high
        core::ptr::write_volatile(entry.add(2), u32::from(vector)); // message data
        core::ptr::write_volatile(entry.add(3), 0); // vector control: unmasked
    }

    // --- Enable MSI-X at the capability: set Enable (bit 15), clear
    //     Function Mask (bit 14) in the 16-bit Message Control at
    //     cap_off + 2. We read the containing dword, edit the high 16
    //     bits, and write it back. ---
    // SAFETY: Ring-0 PCI config access; the BDF + cap offset were
    // validated at boot registration.
    unsafe {
        let ctrl_dword = arch::pci_cfg_read32(d.bus, d.dev, d.func, d.cap_off);
        // Message Control occupies the high 16 bits of the cap's first
        // dword (cap id + next-ptr are the low 16 bits).
        let mut mc = (ctrl_dword >> 16) as u16;
        mc |= 1 << 15; // MSI-X Enable
        mc &= !(1 << 14); // clear Function Mask
        let new_dword = (ctrl_dword & 0x0000_FFFF) | (u32::from(mc) << 16);
        arch::pci_cfg_write32(d.bus, d.dev, d.func, d.cap_off, new_dword);
    }

    // --- WS1-07 serial audit: read back what the device actually sees,
    //     so a write that silently failed to land (wrong page, config
    //     write ignored) is visible on the serial log instead of
    //     presenting as "the MSI never fired". ---
    // SAFETY: same table VA / config-space contracts as the writes above;
    // reads are side-effect-free.
    unsafe {
        use crate::bare_metal::early_console;
        let entry = d.table_va as *const u32;
        let rb_addr = core::ptr::read_volatile(entry.add(0));
        let rb_data = core::ptr::read_volatile(entry.add(2));
        let rb_ctrl = core::ptr::read_volatile(entry.add(3));
        let rb_mc = (arch::pci_cfg_read32(d.bus, d.dev, d.func, d.cap_off) >> 16) as u16;
        early_console::write_str("[irq] msix readback addr=");
        write_hex_u32(rb_addr);
        early_console::write_str(" data=");
        write_hex_u32(rb_data);
        early_console::write_str(" ctrl=");
        write_hex_u32(rb_ctrl);
        early_console::write_str(" mc=");
        write_hex_u32(u32::from(rb_mc));
        early_console::write_str("\n");
    }

    true
}

/// Hex print helper for the readback audit (this module has no access
/// to the `driver_loader` formatting helpers; 8 nibbles, big-endian
/// nibble order).
fn write_hex_u32(val: u32) {
    use crate::bare_metal::early_console;
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    let mut buf = [0u8; 8];
    for (i, b) in buf.iter_mut().enumerate() {
        let shift = 28 - i * 4;
        // Masked to 4 bits, so the index is always in 0..16.
        let nibble = ((val >> shift) & 0xF) as usize;
        *b = *HEX.get(nibble).unwrap_or(&b'?');
    }
    early_console::write_str(core::str::from_utf8(&buf).unwrap_or("????????"));
}

/// Walk a device's PCI capability list for the MSI-X capability.
///
/// Returns `Some((cap_off, table_bir, table_offset))` where `cap_off` is
/// the capability's config offset, `table_bir` is the BAR index holding
/// the table, and `table_offset` is the byte offset of the table within
/// that BAR. `None` if the device has no capability list or no MSI-X cap.
///
/// # Safety
///
/// Ring-0 PCI config reads (side-effect-free).
pub unsafe fn find_msix_cap(bus: u8, dev: u8, func: u8) -> Option<(u8, u8, u32)> {
    // Status register (offset 0x06) bit 4 = capability list present.
    // SAFETY: side-effect-free config read.
    let status = (unsafe { arch::pci_cfg_read32(bus, dev, func, 0x04) } >> 16) as u16;
    if status & (1 << 4) == 0 {
        return None;
    }
    // Capabilities pointer at 0x34 (low byte).
    // SAFETY: side-effect-free config read.
    let mut cap_off = (unsafe { arch::pci_cfg_read32(bus, dev, func, 0x34) } & 0xFF) as u8;
    // Walk the singly-linked cap list; bound the walk (config space is
    // 256 bytes → ≤ 64 caps) to defend against a cyclic list.
    let mut guard = 0u8;
    while cap_off != 0 && guard < 64 {
        // SAFETY: side-effect-free config read.
        let dword = unsafe { arch::pci_cfg_read32(bus, dev, func, cap_off & 0xFC) };
        let cap_id = (dword & 0xFF) as u8;
        let next = ((dword >> 8) & 0xFF) as u8;
        if cap_id == PCI_CAP_ID_MSIX {
            // Table Offset/BIR register at cap_off + 4.
            // SAFETY: side-effect-free config read.
            let tob = unsafe { arch::pci_cfg_read32(bus, dev, func, cap_off + 4) };
            let bir = (tob & 0x7) as u8;
            let offset = tob & !0x7;
            return Some((cap_off, bir, offset));
        }
        cap_off = next;
        guard += 1;
    }
    None
}
