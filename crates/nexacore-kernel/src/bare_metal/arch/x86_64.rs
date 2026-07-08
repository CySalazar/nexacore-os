//! `x86_64` implementation of the bare-metal arch intrinsics.
//!
//! All routines here are `unsafe` at the asm level but expose safe
//! wrappers. They are the **only** site in the kernel that may emit
//! raw inline assembly — every other module reaches port I/O and
//! control-flow termination through this module.

#![allow(
    unsafe_code,
    reason = "module is the inline-asm gateway; every fn wraps `unsafe { asm!(...) }`"
)]
#![allow(
    clippy::doc_markdown,
    reason = "module references ACPI/FADT/PCI/PIIX4/ICH9 acronyms in prose"
)]
#![allow(
    clippy::ptr_as_ptr,
    reason = "FADT byte-table walks reinterpret *const u8 to read u16/u32 fields"
)]
#![allow(
    clippy::similar_names,
    reason = "ACPI/FADT field names (PM1a_CNT, SLP_TYPa, etc.) are SDM-canonical"
)]
#![allow(
    clippy::integer_division,
    reason = "ACPI register offsets are byte-aligned; truncation in offset math is intended"
)]
#![allow(
    clippy::too_long_first_doc_paragraph,
    reason = "ACPI poweroff fallback chain is documented in a single descriptive paragraph"
)]

use core::arch::asm;

/// Interrupt control primitives.
pub mod interrupts {
    use super::asm;

    /// Disable hardware interrupts (`cli`).
    ///
    /// Used as the FIRST step of the panic handler so that a nested
    /// interrupt cannot reenter the panic path while it is writing
    /// the static `PanicRecord` buffer.
    #[inline]
    pub fn disable() {
        // SAFETY: `cli` is a privileged but otherwise side-effect-free
        // instruction that masks maskable interrupts in the RFLAGS
        // register. The kernel runs in ring 0 (the bootloader hands us
        // CPL=0 per UEFI hand-off), so this is always permitted.
        unsafe {
            asm!("cli", options(nomem, nostack, preserves_flags));
        }
    }

    /// Returns `true` if maskable interrupts are currently enabled
    /// (RFLAGS.IF, bit 9, is set).
    ///
    /// Used to snapshot the caller's interrupt state before a short
    /// critical section so it can be restored exactly (rather than blindly
    /// re-enabling). Reads RFLAGS via `pushfq; pop`.
    #[inline]
    #[must_use]
    pub fn are_enabled() -> bool {
        let flags: u64;
        // SAFETY: `pushfq; pop` reads RFLAGS into a GPR. It touches the stack
        // (so no `nostack`) but has no memory or interrupt-state side effects
        // and does not modify the flags register.
        unsafe {
            asm!("pushfq", "pop {}", out(reg) flags, options(nomem, preserves_flags));
        }
        flags & (1 << 9) != 0
    }

    /// Enable hardware interrupts (`sti`).
    ///
    /// # Safety
    ///
    /// The caller must ensure it is sound to accept interrupts at this point —
    /// e.g. not inside a critical section that relies on `IF = 0`, and only to
    /// restore a previously-observed enabled state (see [`are_enabled`]).
    #[inline]
    pub unsafe fn enable() {
        // SAFETY: `sti` sets RFLAGS.IF. Permitted in ring 0; the caller's
        // safety contract governs whether enabling interrupts here is sound.
        unsafe {
            asm!("sti", options(nomem, nostack, preserves_flags));
        }
    }
}

/// Halt the CPU forever (`hlt` in a loop).
///
/// The function returns `!`. Callers MUST never expect control flow
/// past this point: the CPU will execute `hlt` until the next
/// interrupt (which, given `interrupts::disable()` above, never
/// arrives for maskable IRQs; an NMI would re-enter `hlt` immediately
/// on resume).
///
/// This is the panic-path terminator and also the K4 `kmain` post-
/// banner terminator.
#[inline]
pub fn halt_forever() -> ! {
    loop {
        // SAFETY: `hlt` halts the CPU until the next external
        // interrupt. It has no memory effects and no register
        // clobbers.
        unsafe {
            asm!("hlt", options(nomem, nostack, preserves_flags));
        }
    }
}

/// Write a single byte to an x86 I/O port (`out dx, al`).
///
/// Used by the early console to talk to the 16550 UART at COM1
/// (`0x3f8`). Public because [`super::super::early_console`] needs
/// to invoke it; not stable API for the rest of the kernel.
///
/// # Safety
///
/// The caller MUST ensure that `port` is a port the kernel is
/// permitted to touch. At v0.2 only ports `0x3f8..=0x3ff` (COM1
/// register block) are used.
#[inline]
pub unsafe fn outb(port: u16, value: u8) {
    // SAFETY: forwarded to the caller's safety contract.
    unsafe {
        asm!("out dx, al",
             in("dx") port,
             in("al") value,
             options(nomem, nostack, preserves_flags));
    }
}

/// Read a single byte from an x86 I/O port (`in al, dx`).
///
/// # Safety
///
/// Same caveat as [`outb`].
#[inline]
pub unsafe fn inb(port: u16) -> u8 {
    let value: u8;
    // SAFETY: forwarded to the caller's safety contract.
    unsafe {
        asm!("in al, dx",
             out("al") value,
             in("dx") port,
             options(nomem, nostack, preserves_flags));
    }
    value
}

// ---------------------------------------------------------------------------
// RTC-based busy-wait
// ---------------------------------------------------------------------------

const CMOS_ADDR: u16 = 0x70;
const CMOS_DATA: u16 = 0x71;

unsafe fn cmos_read(reg: u8) -> u8 {
    // Bit 7 of the address port controls NMI; keep it clear.
    // SAFETY: forwarded to caller's safety contract.
    unsafe {
        outb(CMOS_ADDR, reg & 0x7F);
        inb(CMOS_DATA)
    }
}

fn rtc_update_in_progress() -> bool {
    // SAFETY: CMOS status register A (0x0A) is a well-defined read target.
    (unsafe { cmos_read(0x0A) } & 0x80) != 0
}

// ---------------------------------------------------------------------------
// ACPI S5 power-off via PCI config-space discovery
// ---------------------------------------------------------------------------
//
// Previous approach (RSDP scan in BIOS ROM) caused a guru-meditation fault:
// VirtualBox places the RSDT above 1 GiB of physical memory, outside the
// identity-mapped window that bootloader v0.9 provides. The PCI config-space
// approach uses only I/O ports 0xCF8/0xCFC and therefore never touches
// memory above 1 GiB, making it page-fault-safe.

/// Write a 16-bit word to an x86 I/O port (`out dx, ax`).
///
/// # Safety
///
/// Same caveat as [`outb`].
#[inline]
pub unsafe fn outw(port: u16, value: u16) {
    unsafe {
        asm!("out dx, ax",
             in("dx") port,
             in("ax") value,
             options(nomem, nostack, preserves_flags));
    }
}

/// Read a 16-bit word from an x86 I/O port (`in ax, dx`).
///
/// # Safety
///
/// Same caveat as [`outb`].
#[inline]
pub unsafe fn inw(port: u16) -> u16 {
    let value: u16;
    unsafe {
        asm!("in ax, dx",
             out("ax") value,
             in("dx") port,
             options(nomem, nostack, preserves_flags));
    }
    value
}

/// Write a 32-bit dword to an x86 I/O port (`out dx, eax`).
///
/// # Safety
///
/// Same caveat as [`outb`].
#[inline]
pub unsafe fn outl(port: u16, value: u32) {
    unsafe {
        asm!("out dx, eax",
             in("dx") port,
             in("eax") value,
             options(nomem, nostack, preserves_flags));
    }
}

/// Read a 32-bit dword from an x86 I/O port (`in eax, dx`).
///
/// # Safety
///
/// Same caveat as [`outb`].
#[inline]
pub unsafe fn inl(port: u16) -> u32 {
    let v: u32;
    unsafe {
        asm!("in eax, dx",
             out("eax") v,
             in("dx") port,
             options(nomem, nostack, preserves_flags));
    }
    v
}

/// Write a single byte into PCI configuration space (CF8/CFC mechanism).
#[inline]
unsafe fn pci_cfg_write8(bus: u8, dev: u8, func: u8, off: u8, val: u8) {
    let addr: u32 = 0x8000_0000
        | (u32::from(bus) << 16)
        | (u32::from(dev) << 11)
        | (u32::from(func) << 8)
        | u32::from(off & 0xFC);
    unsafe {
        outl(0xCF8, addr);
        // The CFC register is 4 bytes; byte offset within the dword.
        outb(0xCFC + u16::from(off & 3), val);
    }
}

/// Read 32 bits from PCI configuration space via the CF8/CFC access mechanism.
///
/// # Safety
///
/// Ring-0 only. Reads from PCI configuration space have no side effects on
/// devices and are safe to issue against any (bus, dev, func, off) triple;
/// nonexistent devices return `0xFFFF_FFFF`.
#[inline]
pub unsafe fn pci_cfg_read32(bus: u8, dev: u8, func: u8, off: u8) -> u32 {
    let addr: u32 = 0x8000_0000
        | (u32::from(bus) << 16)
        | (u32::from(dev) << 11)
        | (u32::from(func) << 8)
        | u32::from(off & 0xFC);
    unsafe {
        outl(0xCF8, addr);
        inl(0xCFC)
    }
}

/// Write a 32-bit dword to PCI configuration space (legacy 0xCF8/0xCFC
/// mechanism). `off` is dword-aligned (low two bits ignored).
///
/// # Safety
///
/// Ring-0 only. Writes to config space can change device behaviour (e.g.
/// command register, MSI-X enable); the caller is responsible for the
/// semantics of the register being written.
#[inline]
pub unsafe fn pci_cfg_write32(bus: u8, dev: u8, func: u8, off: u8, value: u32) {
    let addr: u32 = 0x8000_0000
        | (u32::from(bus) << 16)
        | (u32::from(dev) << 11)
        | (u32::from(func) << 8)
        | u32::from(off & 0xFC);
    unsafe {
        outl(0xCF8, addr);
        outl(0xCFC, value);
    }
}

/// Parse RSDP → RSDT/XSDT → FADT and return the `PM1a_CNT_BLK` I/O port.
///
/// `rsdp_phys` is the physical address of the RSDP structure (from
/// `BootInfo.rsdp_addr`). `phys_offset` is the virtual offset at which
/// the entire physical address space is identity-mapped (from
/// `BootInfo.physical_memory_offset`).
///
/// Returns `Some(port)` on success, `None` if any step fails (bad
/// signature, missing table, etc.). Accesses memory only via the
/// physical-memory window; never touches un-mapped addresses.
///
/// # Safety
///
/// Caller must ensure `phys_offset + rsdp_phys` points to a valid,
/// readable RSDP and that all ACPI table pointers within it also fall
/// inside the mapped physical-memory window.
unsafe fn find_pm1a_cnt_from_fadt(rsdp_phys: u64, phys_offset: u64) -> Option<u16> {
    // Helper: physical address → virtual pointer.
    let p2v = |phys: u64| -> *const u8 { (phys_offset.wrapping_add(phys)) as *const u8 };

    // Read 4-byte little-endian value from an unaligned virtual pointer.
    let read32 = |ptr: *const u8, off: usize| -> u32 {
        unsafe { (ptr.add(off) as *const u32).read_unaligned() }
    };
    let read64 = |ptr: *const u8, off: usize| -> u64 {
        unsafe { (ptr.add(off) as *const u64).read_unaligned() }
    };

    // Verify RSDP signature ("RSD PTR ").
    let rsdp = p2v(rsdp_phys);
    let sig = unsafe { core::slice::from_raw_parts(rsdp, 8) };
    if sig != b"RSD PTR " {
        return None;
    }
    let revision = unsafe { *rsdp.add(15) };

    // Helper: iterate RSDT (32-bit entries) or XSDT (64-bit entries),
    // searching for the FADT ("FACP").
    let try_rsdt = |rsdt_phys: u64, wide: bool| -> Option<u16> {
        let rsdt = p2v(rsdt_phys);
        let sig4 = unsafe { core::slice::from_raw_parts(rsdt, 4) };
        let expected: &[u8] = if wide { b"XSDT" } else { b"RSDT" };
        if sig4 != expected {
            return None;
        }
        let len = read32(rsdt, 4) as usize;
        let entry_size: usize = if wide { 8 } else { 4 };
        let count = len.saturating_sub(36) / entry_size;
        for i in 0..count {
            let entry_phys: u64 = if wide {
                read64(rsdt, 36 + i * 8)
            } else {
                u64::from(read32(rsdt, 36 + i * 4))
            };
            let tbl = p2v(entry_phys);
            let tsig = unsafe { core::slice::from_raw_parts(tbl, 4) };
            if tsig == b"FACP" {
                // FADT: PM1a_CNT_BLK at byte offset 64 (4-byte I/O address).
                // Per ACPI spec § 5.2.9 table, PM1a_CNT_BLK is at FADT+64.
                // The register width is PM1_CNT_LEN (1 byte) bytes but the
                // port address fits in 16 bits for x86.
                #[allow(clippy::cast_possible_truncation)]
                return Some(read32(tbl, 64) as u16);
            }
        }
        None
    };

    // Prefer XSDT (ACPI 2.0+); fall back to RSDT.
    if revision >= 2 {
        let xsdt_phys = read64(rsdp, 24);
        if let Some(port) = try_rsdt(xsdt_phys, true) {
            return Some(port);
        }
    }
    let rsdt_phys = u64::from(read32(rsdp, 16));
    try_rsdt(rsdt_phys, false)
}

/// Trigger ACPI S5 via FADT-provided `PM1a_CNT_BLK`.
///
/// The ACPI spec requires parsing the DSDT `_S5` object to obtain the
/// exact `SLP_TYP` bits. Since we do not have an AML interpreter yet,
/// we try the three most common values in order:
///
/// | SLP_TYP | Platform                          | PM1a_CNT value |
/// |---------|-----------------------------------|----------------|
/// | 0       | QEMU q35 + OVMF                   | `0x2000`       |
/// | 5       | VirtualBox / QEMU i440fx           | `0x3400`       |
/// | 1       | Bochs / alternative QEMU configs   | `0x2400`       |
///
/// Falls through to [`acpi_poweroff`] if table parsing fails or none
/// of the hardcoded values triggers S5.
///
/// # Safety
///
/// Same as [`find_pm1a_cnt_from_fadt`]: caller ensures both addresses
/// are valid and the physical-memory window covers all ACPI tables.
#[allow(
    rustdoc::private_intra_doc_links,
    reason = "links to the private FADT walker; preserved for --document-private-items"
)]
pub unsafe fn acpi_poweroff_from_fadt(rsdp_phys: u64, phys_offset: u64) {
    if let Some(pm1a_cnt) = unsafe { find_pm1a_cnt_from_fadt(rsdp_phys, phys_offset) } {
        if pm1a_cnt != 0 {
            // SLP_EN = bit 13 = 0x2000. Combined with SLP_TYP in bits [12:10].
            // Attempt A: QEMU q35 + OVMF (SLP_TYP = 0).
            unsafe { outw(pm1a_cnt, 0x2000) };
            for _ in 0..10_000 {
                core::hint::spin_loop();
            }

            // Attempt B: VirtualBox / QEMU i440fx (SLP_TYP = 5).
            unsafe { outw(pm1a_cnt, 0x2000 | (5 << 10)) };
            for _ in 0..10_000 {
                core::hint::spin_loop();
            }

            // Attempt C: Bochs / alternative (SLP_TYP = 1).
            unsafe { outw(pm1a_cnt, 0x2000 | (1 << 10)) };
            for _ in 0..10_000 {
                core::hint::spin_loop();
            }
        }
    }
    // FADT path failed; fall back to PCI/hardcoded scan.
    acpi_poweroff();
}

/// Trigger ACPI S5 (soft power-off) via PCI scan + hardcoded fallbacks.
///
/// Tries five power-off paths in order, stopping as soon as one succeeds:
///
/// 1. **PCI discovery (PIIX4)**: scans bus 0 for vendor `0x8086` / device
///    `0x7113` (Intel PIIX4 PM, used by VirtualBox BIOS and i440fx QEMU).
/// 2. **PCI discovery (ICH9 LPC)**: scans bus 0 for vendor `0x8086` / device
///    `0x2918` (Intel ICH9 LPC bridge, used by QEMU q35), sets ACPI_EN bit.
/// 3. **QEMU q35 / ICH9 default**: `PM1a_CNT = 0x0604`.
/// 4. **VirtualBox / i440fx fallback**: `PM1a_CNT = 0x4004`.
/// 5. **8042 keyboard reset**: with QEMU `-no-reboot` this exits QEMU cleanly.
///
/// All ACPI writes use `SLP_TYP_A = 5`, `SLP_EN = 1` → `0x3400`.
pub fn acpi_poweroff() {
    // Attempt 1: PCI scan for PIIX4 (VirtualBox / i440fx QEMU).
    if let Some(pmbase) = unsafe { find_piix4_pmbase() } {
        #[allow(clippy::cast_possible_truncation)]
        let pm1a_cnt = (pmbase & !1_u32) as u16 + 4;
        unsafe { outw(pm1a_cnt, 0x3400) };
        // Reaches here only if the write had no effect.
    }
    // Attempt 2: PCI scan for ICH9 LPC bridge (QEMU q35).
    if let Some(pmbase) = unsafe { find_ich9_pmbase() } {
        #[allow(clippy::cast_possible_truncation)]
        let pm1a_cnt = (pmbase & !1_u32) as u16 + 4;
        unsafe { outw(pm1a_cnt, 0x3400) };
    }
    // Attempt 3: QEMU q35 + OVMF hardcoded fallback — PM1a_CNT at 0x0604.
    unsafe { outw(0x0604, 0x3400) };
    // Attempt 4: VirtualBox / i440fx fallback — PM1a_CNT at 0x4004.
    unsafe { outw(0x4004, 0x3400) };
    // Attempt 5: 8042 keyboard controller CPU reset. QEMU converts this to
    // an exit when launched with `-no-reboot`. Used as a last resort when
    // the ACPI PM path is unavailable (e.g. ACPI_EN not set by firmware).
    unsafe { outb(0x64, 0xFE) };
    // All attempts exhausted; caller falls through to halt_forever.
}

/// Trigger a system reset via the ACPI FADT `RESET_REG`, with port
/// `0xCF9` and triple-fault fallbacks.
///
/// # Safety
///
/// Same as [`acpi_poweroff_from_fadt`]: caller ensures the RSDP and
/// ACPI tables fall inside the `phys_offset` direct-map window.
#[allow(
    rustdoc::private_intra_doc_links,
    reason = "links to the private FADT walker; preserved for --document-private-items"
)]
pub unsafe fn acpi_reboot_from_fadt(rsdp_phys: u64, phys_offset: u64) {
    // Attempt 1: ACPI FADT RESET_REG (the correct, spec-compliant method).
    if let Some((port, value)) = unsafe { find_fadt_reset_reg(rsdp_phys, phys_offset) } {
        if port != 0 {
            unsafe { outb(port, value) };
            for _ in 0..50_000 {
                core::hint::spin_loop();
            }
        }
    }

    // Attempt 2: port 0xCF9 (ICH/PCH reset control register).
    acpi_reboot();
}

/// Trigger a system reset without FADT. Uses port `0xCF9` and
/// triple-fault fallback.
///
/// The 8042 keyboard reset (`0xFE` → port `0x64`) is intentionally
/// NOT used: QEMU/KVM converts it to a VM exit (shutdown) rather
/// than a guest-visible CPU reset on some Proxmox configurations.
pub fn acpi_reboot() -> ! {
    // Attempt 1: port 0xCF9 (ICH/PCH reset control register).
    let cf9 = unsafe { inb(0xCF9) } & !0x06;
    unsafe { outb(0xCF9, cf9 | 0x02) };
    for _ in 0..50_000 {
        core::hint::spin_loop();
    }
    unsafe { outb(0xCF9, cf9 | 0x06) };
    for _ in 0..50_000 {
        core::hint::spin_loop();
    }

    // Attempt 2: triple fault — guaranteed reset on all x86_64 CPUs.
    #[allow(unsafe_code, reason = "intentional triple-fault to force CPU reset")]
    unsafe {
        let null_idt: [u8; 10] = [0; 10];
        asm!(
            "lidt [{ptr}]",
            "ud2",
            ptr = in(reg) (&raw const null_idt) as u64,
            options(noreturn),
        );
    }
}

/// Parse RSDP → RSDT/XSDT → FADT and return the `RESET_REG` I/O port
/// and `RESET_VALUE` (ACPI 2.0+, FADT revision ≥ 2).
///
/// Returns `None` if the FADT is too short, the RESET_REG is not in
/// System I/O space, or the `RESET_REG_SUP` flag (FADT flags bit 10)
/// is not set.
///
/// # Safety
///
/// Same as [`find_pm1a_cnt_from_fadt`].
unsafe fn find_fadt_reset_reg(rsdp_phys: u64, phys_offset: u64) -> Option<(u16, u8)> {
    let p2v = |phys: u64| -> *const u8 { (phys_offset.wrapping_add(phys)) as *const u8 };
    let read32 = |ptr: *const u8, off: usize| -> u32 {
        unsafe { (ptr.add(off) as *const u32).read_unaligned() }
    };
    let read64 = |ptr: *const u8, off: usize| -> u64 {
        unsafe { (ptr.add(off) as *const u64).read_unaligned() }
    };

    let rsdp = p2v(rsdp_phys);
    let sig = unsafe { core::slice::from_raw_parts(rsdp, 8) };
    if sig != b"RSD PTR " {
        return None;
    }
    let revision = unsafe { *rsdp.add(15) };

    let find_facp = |rsdt_phys: u64, wide: bool| -> Option<*const u8> {
        let rsdt = p2v(rsdt_phys);
        let sig4 = unsafe { core::slice::from_raw_parts(rsdt, 4) };
        let expected: &[u8] = if wide { b"XSDT" } else { b"RSDT" };
        if sig4 != expected {
            return None;
        }
        let len = read32(rsdt, 4) as usize;
        let entry_size: usize = if wide { 8 } else { 4 };
        let count = len.saturating_sub(36) / entry_size;
        for i in 0..count {
            let entry_phys: u64 = if wide {
                read64(rsdt, 36 + i * 8)
            } else {
                u64::from(read32(rsdt, 36 + i * 4))
            };
            let tbl = p2v(entry_phys);
            let tsig = unsafe { core::slice::from_raw_parts(tbl, 4) };
            if tsig == b"FACP" {
                return Some(tbl);
            }
        }
        None
    };

    // Find FADT (prefer XSDT).
    let fadt = if revision >= 2 {
        let xsdt_phys = read64(rsdp, 24);
        find_facp(xsdt_phys, true).or_else(|| {
            let rsdt_phys = u64::from(read32(rsdp, 16));
            find_facp(rsdt_phys, false)
        })
    } else {
        let rsdt_phys = u64::from(read32(rsdp, 16));
        find_facp(rsdt_phys, false)
    };

    let fadt = fadt?;
    let fadt_len = read32(fadt, 4) as usize;

    // RESET_REG is at FADT offset 128 (12-byte Generic Address Structure),
    // RESET_VALUE at offset 128+12 = 140. Requires FADT length ≥ 141.
    if fadt_len < 141 {
        return None;
    }

    // FADT flags at offset 112; bit 10 = RESET_REG_SUP.
    let flags = read32(fadt, 112);
    if flags & (1 << 10) == 0 {
        return None;
    }

    // Generic Address Structure at offset 128:
    //   byte 0: address_space_id (must be 1 = System I/O)
    //   byte 1: register_bit_width
    //   byte 2: register_bit_offset
    //   byte 3: access_size
    //   bytes 4..12: address (u64)
    let addr_space = unsafe { *fadt.add(128) };
    if addr_space != 1 {
        return None; // Not System I/O — we only support port I/O resets.
    }
    let reset_port = read64(fadt, 132);
    let reset_value = unsafe { *fadt.add(140) };

    #[allow(clippy::cast_possible_truncation)]
    Some((reset_port as u16, reset_value))
}

/// Scan PCI bus 0 for the PIIX4 PM controller and return its `PMBASE`.
///
/// `VirtualBox` places the PIIX4 at bus=0, device=1 (or device=7 in some
/// configurations), function=3. Scanning all 32 devices is safe because
/// reading a non-existent device returns `0xFFFF_FFFF` (no device present).
unsafe fn find_piix4_pmbase() -> Option<u32> {
    for dev in 0_u8..32 {
        // PIIX4 PM controller: Intel (0x8086), device ID 0x7113.
        if unsafe { pci_cfg_read32(0, dev, 3, 0) } == 0x7113_8086 {
            // PMBASE at PCI config offset 0x40.
            return Some(unsafe { pci_cfg_read32(0, dev, 3, 0x40) });
        }
    }
    None
}

/// Scan PCI bus 0 for the ICH9 LPC bridge and return its `PMBASE`.
///
/// QEMU q35 places the ICH9 LPC bridge (vendor `0x8086`, device `0x2918`)
/// at bus=0, device=31, function=0. PMBASE is at config offset `0x40`.
/// The PM I/O region is gated by the ACPI_EN bit (bit 7) in the ACPI
/// Control register at config offset `0x44`; this function sets it if clear.
/// QEMU's default PMBASE is `0x600`.
unsafe fn find_ich9_pmbase() -> Option<u32> {
    for dev in 0_u8..32 {
        // ICH9 LPC bridge: Intel (0x8086), device ID 0x2918.
        if unsafe { pci_cfg_read32(0, dev, 0, 0) } == 0x2918_8086 {
            // Ensure ACPI I/O Enable bit (bit 7 of ACPI_CTRL at config 0x44).
            let acpi_ctrl_dw = unsafe { pci_cfg_read32(0, dev, 0, 0x44) };
            #[allow(clippy::cast_possible_truncation)]
            let acpi_ctrl = acpi_ctrl_dw as u8;
            if acpi_ctrl & 0x80 == 0 {
                unsafe { pci_cfg_write8(0, dev, 0, 0x44, acpi_ctrl | 0x80) };
            }
            // PMBASE at PCI config offset 0x40.
            return Some(unsafe { pci_cfg_read32(0, dev, 0, 0x40) });
        }
    }
    None
}

// ---------------------------------------------------------------------------
// RTC-based busy-wait
// ---------------------------------------------------------------------------

/// Read the CMOS RTC seconds register (0–59) without blocking for a full
/// second. Waits only for the Update-In-Progress flag to clear (at most
/// ~244 µs), then returns the decoded value. Safe to call in a polling
/// loop without introducing multi-second stalls.
pub fn rtc_seconds() -> u32 {
    while rtc_update_in_progress() {
        core::hint::spin_loop();
    }
    let is_binary = unsafe { cmos_read(0x0B) } & 0x04 != 0;
    let raw = unsafe { cmos_read(0x00) };
    if is_binary {
        u32::from(raw)
    } else {
        u32::from(raw >> 4) * 10 + u32::from(raw & 0x0F)
    }
}

/// Read hours, minutes, and seconds from the CMOS RTC.
///
/// Returns `(hours, minutes, seconds)` in 24-hour format. Waits for the
/// Update-In-Progress flag to clear before reading all three registers.
/// Note: consecutive register reads may span an RTC tick in rare cases
/// (~1 in 10⁶ at polling rates used here); accuracy is ±1 second.
pub fn rtc_time() -> (u8, u8, u8) {
    while rtc_update_in_progress() {
        core::hint::spin_loop();
    }
    let rb = unsafe { cmos_read(0x0B) };
    let is_binary = rb & 0x04 != 0;
    let h_raw = unsafe { cmos_read(0x04) };
    let m_raw = unsafe { cmos_read(0x02) };
    let s_raw = unsafe { cmos_read(0x00) };
    let decode = |v: u8| -> u8 {
        if is_binary {
            v
        } else {
            (v >> 4) * 10 + (v & 0x0F)
        }
    };
    (decode(h_raw), decode(m_raw), decode(s_raw))
}

// ---------------------------------------------------------------------------
// Paging control registers
// ---------------------------------------------------------------------------

/// Reads the CR3 register (physical base address of the PML4 page table).
///
/// Returns the raw CR3 value; bits \[11:0\] are flags (PCID / ignored in
/// simple setups). Mask with `!0xFFF` to obtain the PML4 physical address.
#[inline]
pub fn read_cr3() -> u64 {
    let val: u64;
    // SAFETY: `mov rax, cr3` is a ring-0 read; no memory side effects.
    unsafe {
        asm!("mov {0}, cr3", out(reg) val, options(nomem, nostack, preserves_flags));
    }
    val
}

/// Reads the CR2 register (linear address that caused the most recent
/// page fault).
///
/// Valid immediately inside a `#PF` handler before the next memory access
/// can clobber it. Returns the raw 64-bit linear address.
#[inline]
pub fn read_cr2() -> u64 {
    let val: u64;
    // SAFETY: `mov rax, cr2` is a ring-0 read; no memory side effects.
    unsafe {
        asm!("mov {0}, cr2", out(reg) val, options(nomem, nostack, preserves_flags));
    }
    val
}

/// Invalidates the TLB entry for the virtual address `virt` (`invlpg`).
///
/// Must be called after clearing a page-table entry to ensure subsequent
/// accesses to `virt` are not served from a stale TLB cache line.
///
/// # Safety
///
/// Must only be called in ring 0. `virt` should be a virtual address that
/// was previously mapped; calling it on an unmapped address is harmless but
/// wasteful.
#[inline]
pub unsafe fn invlpg(virt: u64) {
    // SAFETY: forwarded to the caller's safety contract.
    unsafe {
        asm!("invlpg [{0}]", in(reg) virt, options(nostack, preserves_flags));
    }
}

/// Spin-wait for `secs` seconds using the CMOS Real-Time Clock.
///
/// The RTC seconds register advances once per second regardless of
/// interrupt state, making it safe to call after `interrupts::disable`.
/// Accuracy: ±1 second (single-second resolution of the RTC register).
/// Works on QEMU `pc` and `q35` machine types and on `VirtualBox`.
pub fn wait_secs(secs: u32) {
    if secs == 0 {
        return;
    }

    // Status register B bit 2: 1 = binary mode, 0 = BCD mode.
    // SAFETY: CMOS register 0x0B is safe to read in ring 0.
    let is_binary = unsafe { cmos_read(0x0B) } & 0x04 != 0;

    let decode = |raw: u8| -> u32 {
        if is_binary {
            u32::from(raw)
        } else {
            u32::from(raw >> 4) * 10 + u32::from(raw & 0x0F)
        }
    };

    // Wait for any in-progress update to finish before sampling start time.
    while rtc_update_in_progress() {
        core::hint::spin_loop();
    }
    // SAFETY: CMOS register 0x00 (seconds) is safe to read in ring 0.
    let start = decode(unsafe { cmos_read(0x00) });
    let mut prev = start;
    let mut elapsed: u32 = 0;

    while elapsed < secs {
        // Spin until the RTC is not in an update cycle.
        while rtc_update_in_progress() {
            core::hint::spin_loop();
        }
        let curr = decode(unsafe { cmos_read(0x00) });
        if curr != prev {
            elapsed += if curr > prev {
                curr - prev
            } else {
                // Wrapped past 59 → 0.
                (60 - prev) + curr
            };
            prev = curr;
        }
        core::hint::spin_loop();
    }
}
