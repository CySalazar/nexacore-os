//! DEV-ONLY driver auto-loader (P6.7.9-pre.11).
//!
//! Spawns a hand-crafted "driver probe" ELF at boot time that exercises
//! the full `MmioMap (70)` / `DmaMap (71)` / `IrqAttach (72)` syscall
//! path against capability tokens deposited by the kernel.
//!
//! ## Flow
//!
//! 1. [`pci_scan::scan_bus_0`] discovers PCI devices on bus 0.
//! 2. The auto-loader picks the first suitable device (or uses a
//!    synthetic descriptor for MMIO smoke testing).
//! 3. [`crate::process::ProcessControlBlock::spawn_from_elf`] spawns
//!    the probe ELF as a Ring 3 process.
//! 4. [`crate::cap_deposit::deposit_for_driver`] pre-installs `MmioMap`,
//!    `DmaMap`, and `IrqAttach` capability tokens at the well-known
//!    deposit VA.
//! 5. The probe reads the tokens and issues the three syscalls. Exit
//!    sentinel codes distinguish success from each possible failure
//!    point.
//!
//! ## Probe exit sentinel codes
//!
//! | Code | Meaning |
//! |------|---------|
//! |  0   | All three syscalls succeeded |
//! | 10   | No MmioMap token in deposit |
//! | 20   | No DmaMap token in deposit |
//! | 30   | No IrqAttach token in deposit |
//! | 40+e | MmioMap returned errno `e` |
//! | 60+e | DmaMap returned errno `e` |
//! | 80+e | IrqAttach returned errno `e` |
//!
//! ## DEV-ONLY marker
//!
//! This module is a Phase 1 scaffold.  Production driver loading will
//! use a user-space init process with `DriverLoad (73)` and signed
//! NexaCore-Pack blobs.

#![allow(
    unsafe_code,
    reason = "wraps ProcessControlBlock::spawn_from_elf and deposit_for_driver which are both unsafe"
)]

use core::sync::atomic::{AtomicBool, AtomicU8, Ordering};

use nexacore_capability::Resource;

use super::pci_scan;
use crate::{
    bare_metal::early_console, cap_deposit, driver_manifest::DriverCapabilities,
    process::ProcessControlBlock, scheduling::PriorityClass,
};

/// RAII interrupt-mask guard for the boot spawn+deposit critical section
/// (deposit-#PF flake fix). [`IrqRestore::mask`] snapshots `RFLAGS.IF`, masks
/// interrupts (`cli`), and the `Drop` impl restores the exact prior state on
/// every return path. See `spawn_driver_and_deposit` for why the section must
/// be atomic w.r.t. scheduler preemption.
struct IrqRestore(bool);

impl IrqRestore {
    /// Snapshot the current interrupt state and mask interrupts.
    fn mask() -> Self {
        let was_enabled = crate::bare_metal::arch::interrupts::are_enabled();
        crate::bare_metal::arch::interrupts::disable();
        Self(was_enabled)
    }
}

impl Drop for IrqRestore {
    fn drop(&mut self) {
        if self.0 {
            // SAFETY: restore the exact IF state observed on entry; nothing
            // after this boot critical section relies on IF = 0.
            unsafe { crate::bare_metal::arch::interrupts::enable() };
        }
    }
}

// =========================================================================
// e1000e bring-up state (read by the Build Info panel renderer)
// =========================================================================

/// Set to `true` once the e1000e live bring-up completes successfully.
pub static E1000E_LIVE: AtomicBool = AtomicBool::new(false);

/// 6-byte MAC address read from the e1000e controller (valid only when
/// `E1000E_LIVE` is `true`).
pub static E1000E_MAC: [AtomicU8; 6] = [
    AtomicU8::new(0),
    AtomicU8::new(0),
    AtomicU8::new(0),
    AtomicU8::new(0),
    AtomicU8::new(0),
    AtomicU8::new(0),
];

// =========================================================================
// Hand-crafted driver probe ELF
// =========================================================================
//
// Mapped at VA 0x0040_0000.  The probe:
//
//   1. Reads the OMNICAPS deposit header at 0x0010_0000.
//   2. Scans entries for ACTION_TAG_MMIO_MAP (1).
//   3. Issues MmioMap (70) with the discovered token.
//   4. Exits with sentinel code 0 (success) or 40+errno.
//
// Code layout (offsets relative to PT_LOAD segment at VA 0x0040_0000):
//
//   0x00: mov r12, 0x100000        ; deposit VA            (10 bytes)
//   0x0A: mov ecx, [r12+12]        ; entry_count           (5 bytes)
//   0x0F: test ecx, ecx            ; check zero            (2 bytes)
//   0x11: jz .exit_no_mmio         ; → exit(10)            (6 bytes)
//   0x17: lea r13, [r12+16]        ; first descriptor      (5 bytes)
//   0x1C: mov ebx, ecx             ; counter               (2 bytes)
// .scan:
//   0x1E: cmp dword [r13], 1       ; == MMIO_MAP?          (5 bytes)
//   0x23: je .found                ; yes                   (2 bytes)
//   0x25: add r13, 16              ; next descriptor       (4 bytes)
//   0x29: dec ebx                  ; decrement             (2 bytes)
//   0x2B: jnz .scan                ; loop                  (2 bytes)
//   0x2D: jmp .exit_no_mmio        ; not found             (2 bytes)
// .found:
//   0x2F: mov r14d, [r13+8]        ; token_offset          (4 bytes)
//   0x33: mov r15d, [r13+12]       ; token_len             (4 bytes)
//   0x37: lea r10, [r12+r14]       ; token_ptr             (4 bytes)
//   0x3B: mov r8, r15              ; token_len → r8        (3 bytes)
//   0x3E: mov eax, 70              ; SYS_MMIO_MAP          (5 bytes)
//   0x43: mov edi, 0xFEBC0000      ; phys_base             (5 bytes)
//   0x48: mov esi, 0x1000          ; len                   (5 bytes)
//   0x4D: xor edx, edx            ; flags=0               (2 bytes)
//   0x4F: syscall                  ;                       (2 bytes)
//   0x51: test rdx, rdx           ; errno?                (3 bytes)
//   0x54: jnz .mmio_err           ; → exit(40+e)          (2 bytes)
// .exit_ok:
//   0x56: mov eax, 11             ; TaskExit              (5 bytes)
//   0x5B: xor edi, edi            ; code=0                (2 bytes)
//   0x5D: syscall                 ;                       (2 bytes)
//   0x5F: jmp $                   ;                       (2 bytes)
// .mmio_err:
//   0x61: mov eax, 11             ; TaskExit              (5 bytes)
//   0x66: mov edi, 40             ; EXIT_MMIO_BASE        (5 bytes)
//   0x6B: add rdi, rdx            ; + errno               (3 bytes)
//   0x6E: syscall                 ;                       (2 bytes)
//   0x70: jmp $                   ;                       (2 bytes)
// .exit_no_mmio:
//   0x72: mov eax, 11             ; TaskExit              (5 bytes)
//   0x77: mov edi, 10             ; EXIT_NO_MMIO          (5 bytes)
//   0x7C: syscall                 ;                       (2 bytes)
//   0x7E: jmp $                   ;                       (2 bytes)
//
// Segment: file_size = mem_size = 128 (0x80).  PF_R | PF_X = 5.
// Total ELF: 64 (header) + 56 (phdr) + 128 (code) = 248 bytes.

const DRIVER_PROBE_ELF: &[u8] = &[
    // ── ELF64 header — 64 bytes ──────────────────────────────────
    0x7F, b'E', b'L', b'F', 2, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x02, 0x00, // e_type = ET_EXEC
    0x3E, 0x00, // e_machine = EM_X86_64
    0x01, 0x00, 0x00, 0x00, // e_version = 1
    0x00, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, // e_entry = 0x0040_0000
    0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // e_phoff = 0x40
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // e_shoff = 0
    0x00, 0x00, 0x00, 0x00, // e_flags
    0x40, 0x00, // e_ehsize = 64
    0x38, 0x00, // e_phentsize = 56
    0x01, 0x00, // e_phnum = 1
    0x00, 0x00, // e_shentsize
    0x00, 0x00, // e_shnum
    0x00, 0x00, // e_shstrndx
    // ── Program header — 56 bytes (PT_LOAD, R+X) ────────────────
    0x01, 0x00, 0x00, 0x00, // p_type = PT_LOAD
    0x05, 0x00, 0x00, 0x00, // p_flags = PF_R | PF_X
    0x78, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // p_offset = 0x78
    0x00, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, // p_vaddr = 0x0040_0000
    0x00, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, // p_paddr = 0x0040_0000
    0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // p_filesz = 128
    0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // p_memsz  = 128
    0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // p_align  = 0x1000
    // ── Code — 128 bytes at file offset 0x78 ─────────────────────
    // 0x00: mov r12, 0x100000
    0x49, 0xBC, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00,
    // 0x0A: mov ecx, [r12+12]
    0x41, 0x8B, 0x4C, 0x24, 0x0C, // 0x0F: test ecx, ecx
    0x85, 0xC9,
    // 0x11: jz .exit_no_mmio (rel32 → offset 0x72; disp = 0x72 - 0x17 = 0x5B)
    0x0F, 0x84, 0x5B, 0x00, 0x00, 0x00, // 0x17: lea r13, [r12+16]
    0x4D, 0x8D, 0x6C, 0x24, 0x10, // 0x1C: mov ebx, ecx
    0x89, 0xCB, // .scan (0x1E):
    // 0x1E: cmp dword [r13], 1
    0x41, 0x83, 0x7D, 0x00, 0x01,
    // 0x23: je .found (rel8 → offset 0x2F; disp = 0x2F - 0x25 = 0x0A)
    0x74, 0x0A, // 0x25: add r13, 16
    0x49, 0x83, 0xC5, 0x10, // 0x29: dec ebx
    0xFF, 0xCB,
    // 0x2B: jnz .scan (rel8 → offset 0x1E; disp = 0x1E - 0x2D = -0x0F = 0xF1)
    0x75, 0xF1,
    // 0x2D: jmp .exit_no_mmio (rel8 → offset 0x72; disp = 0x72 - 0x2F = 0x43)
    0xEB, 0x43, // .found (0x2F):
    // 0x2F: mov r14d, [r13+8]
    0x45, 0x8B, 0x75, 0x08, // 0x33: mov r15d, [r13+12]
    0x45, 0x8B, 0x7D, 0x0C, // 0x37: lea r10, [r12+r14]
    0x4F, 0x8D, 0x14, 0x34, // 0x3B: mov r8, r15
    0x4D, 0x89, 0xF8, // 0x3E: mov eax, 70 (SYS_MMIO_MAP)
    0xB8, 0x46, 0x00, 0x00, 0x00, // 0x43: mov edi, 0xFEBC0000
    0xBF, 0x00, 0x00, 0xBC, 0xFE, // 0x48: mov esi, 0x1000
    0xBE, 0x00, 0x10, 0x00, 0x00, // 0x4D: xor edx, edx
    0x31, 0xD2, // 0x4F: syscall
    0x0F, 0x05, // 0x51: test rdx, rdx
    0x48, 0x85, 0xD2,
    // 0x54: jnz .mmio_err (rel8 → offset 0x61; disp = 0x61 - 0x56 = 0x0B)
    0x75, 0x0B, // .exit_ok (0x56):
    // 0x56: mov eax, 11 (TaskExit)
    0xB8, 0x0B, 0x00, 0x00, 0x00, // 0x5B: xor edi, edi
    0x31, 0xFF, // 0x5D: syscall
    0x0F, 0x05, // 0x5F: jmp $
    0xEB, 0xFE, // .mmio_err (0x61):
    // 0x61: mov eax, 11 (TaskExit)
    0xB8, 0x0B, 0x00, 0x00, 0x00, // 0x66: mov edi, 40 (EXIT_MMIO_BASE)
    0xBF, 0x28, 0x00, 0x00, 0x00, // 0x6B: add rdi, rdx
    0x48, 0x01, 0xD7, // 0x6E: syscall
    0x0F, 0x05, // 0x70: jmp $
    0xEB, 0xFE, // .exit_no_mmio (0x72):
    // 0x72: mov eax, 11 (TaskExit)
    0xB8, 0x0B, 0x00, 0x00, 0x00, // 0x77: mov edi, 10 (EXIT_NO_MMIO_TOKEN)
    0xBF, 0x0A, 0x00, 0x00, 0x00, // 0x7C: syscall
    0x0F, 0x05, // 0x7E: jmp $
    0xEB, 0xFE,
];

/// Load and start the driver probe at boot time.
///
/// Called from `kmain` after IOMMU init, scheduler init, and `sti`.
/// The probe process is enqueued in the scheduler and will be
/// dispatched on the next LAPIC timer preemption.
///
/// # Safety
///
/// Caller must ensure single-CPU invariant holds and that
/// `scheduler`, `mapper`, `alloc` are the live kernel singletons.
// justification: u64→u32 casts print low/high halves of 64-bit BAR addresses
// in diagnostic console output; truncation is intentional for readability.
#[allow(clippy::cast_possible_truncation)]
// justification: boot probe orchestrates NVMe + e1000e + virtio-net in a single
// linear sequence; extracting sub-sequences into helpers would hide the boot
// ordering dependency and scatter the Phase-1 scaffold across many functions.
#[allow(clippy::too_many_lines)]
#[cfg(target_arch = "x86_64")]
pub unsafe fn boot_load_driver_probe<const N: usize>(
    mapper: &mut crate::bare_metal::paging::PageMapper,
    alloc: &mut crate::memory::BitmapFrameAllocator<N>,
    scheduler: &mut crate::scheduling::RoundRobinScheduler,
) {
    early_console::write_str("[driver-loader] PCI scan all buses (bridge traversal)...\n");

    // SAFETY: Ring 0, single-CPU boot path.
    let scan = unsafe { pci_scan::scan_all_buses() };
    early_console::write_str("[driver-loader] buses scanned: ");
    early_console::write_usize(scan.buses_scanned() as usize);
    early_console::write_str("  bridges: ");
    early_console::write_usize(scan.bridges_found() as usize);
    early_console::write_str("\n");
    early_console::write_str("[driver-loader] PCI devices found: ");
    #[allow(
        clippy::cast_possible_truncation,
        reason = "PCI device count always < 64; fits usize"
    )]
    early_console::write_usize(scan.count());
    early_console::write_str("\n");

    for dev in scan.iter() {
        early_console::write_str("[driver-loader]   bus=");
        write_hex_u8(dev.bus);
        early_console::write_str(" ");
        write_hex_u16(dev.vendor_id);
        early_console::write_str(":");
        write_hex_u16(dev.device_id);
        early_console::write_str(" class=");
        write_hex_u8(dev.class_code);
        early_console::write_str(":");
        write_hex_u8(dev.subclass);
        early_console::write_str(" bar0=");
        write_hex_u32(dev.bar0);
        early_console::write_str(" irq=");
        early_console::write_usize(dev.irq_line as usize);
        if dev.is_pci_bridge() {
            early_console::write_str(" [BRIDGE]");
        }
        early_console::write_str("\n");
    }

    // ── TASK-004: virtio-net live bring-up (P6.7.9-pre.10) ──────────
    //
    // Find the virtio-net device (transitional 1AF4:1000 or modern
    // 1AF4:1041) across all scanned buses. If found and BAR0 is an
    // I/O port, perform live device initialization via legacy I/O.
    if let Some(vnet) = scan
        .find(
            pci_scan::VIRTIO_VENDOR_ID,
            pci_scan::VIRTIO_NET_DEVICE_ID_TRANSITIONAL,
        )
        .or_else(|| {
            scan.find(
                pci_scan::VIRTIO_VENDOR_ID,
                pci_scan::VIRTIO_NET_DEVICE_ID_MODERN,
            )
        })
    {
        early_console::write_str("[virtio-net] found on bus=");
        write_hex_u8(vnet.bus);
        early_console::write_str(" dev=");
        write_hex_u8(vnet.device);
        early_console::write_str(" devid=");
        write_hex_u16(vnet.device_id);
        early_console::write_str("\n");

        // M0 Phase 3 device-model diagnosis: dump every BAR so we can tell
        // from serial alone whether this (transitional) virtio-net exposes a
        // modern MMIO BAR4 alongside the legacy I/O-port BAR0. The MMIO image
        // (`nexacore-driver-net-virtio-image`) drives the modern BAR4 window; if
        // only legacy BAR0 is present, Phase 3 must port the image to the
        // legacy I/O transport (or the test VM's NIC must be reconfigured).
        early_console::write_str("[virtio-net] BARs: bar0=");
        write_hex_u32(vnet.bar0);
        early_console::write_str(if pci_scan::PciDevice::bar_is_io(vnet.bar0) {
            "(io)"
        } else {
            "(mmio)"
        });
        early_console::write_str(" bar1=");
        write_hex_u32(vnet.bar1);
        early_console::write_str(" bar4=");
        write_hex_u32(vnet.bar4);
        early_console::write_str(
            if vnet.bar4 != 0 && !pci_scan::PciDevice::bar_is_io(vnet.bar4) {
                "(mmio)"
            } else {
                ""
            },
        );
        early_console::write_str(" bar5=");
        write_hex_u32(vnet.bar5);
        early_console::write_str(" bar4_phys=");
        write_hex_u32((vnet.bar4_phys() >> 32) as u32);
        write_hex_u32(vnet.bar4_phys() as u32);
        early_console::write_str("\n");

        // M0 Phase 3 device-model discovery: walk the virtio modern PCI
        // capability chain (virtio 1.0 § 4.1.4) and dump the real register
        // geometry (which BAR + offset for common_cfg / notify / isr / device,
        // plus notify_off_multiplier). A Ring-3 driver cannot do I/O-port and
        // cannot read PCI config space, so it needs these values handed to it;
        // this confirms what the device actually advertises before we wire the
        // deposit. Pure config-space reads — no device side effects.
        // SAFETY: Ring 0, single-CPU boot path.
        if let Some(vcaps) =
            unsafe { pci_scan::parse_virtio_modern_caps(vnet.bus, vnet.device, vnet.function) }
        {
            let dump = |tag: &str, loc: &pci_scan::VirtioCapLocation| {
                early_console::write_str(tag);
                if loc.present {
                    early_console::write_str(" bar=");
                    write_hex_u8(loc.bar);
                    early_console::write_str(" off=");
                    write_hex_u32(loc.offset);
                    early_console::write_str(" len=");
                    write_hex_u32(loc.length);
                } else {
                    early_console::write_str(" <absent>");
                }
                early_console::write_str("\n");
            };
            early_console::write_str("[virtio-net] modern caps: usable=");
            write_hex_u8(u8::from(vcaps.usable));
            early_console::write_str("\n");
            dump("[virtio-net]   common", &vcaps.common);
            dump("[virtio-net]   notify", &vcaps.notify);
            dump("[virtio-net]   isr   ", &vcaps.isr);
            dump("[virtio-net]   device", &vcaps.device);
            early_console::write_str("[virtio-net]   notify_off_multiplier=");
            write_hex_u32(vcaps.notify_off_multiplier);
            early_console::write_str("\n");
        } else {
            early_console::write_str(
                "[virtio-net] modern caps: NONE (no virtio vendor cap chain)\n",
            );
        }

        // SAFETY: Ring 0, single-CPU boot path.
        unsafe { pci_scan::enable_device_full(vnet) };
        early_console::write_str("[virtio-net] PCI cmd: IOSE+MSE+BME enabled\n");

        if pci_scan::PciDevice::bar_is_io(vnet.bar0) {
            let io_base = pci_scan::PciDevice::bar_io_base(vnet.bar0);
            early_console::write_str("[virtio-net] I/O port base=");
            write_hex_u16(io_base);
            early_console::write_str("\n");

            // SAFETY: Ring 0, I/O port reads to PCI device BAR.
            unsafe { virtio_net_live_bringup(io_base) };
        } else {
            early_console::write_str("[virtio-net] BAR0 is MMIO — I/O port bringup skipped\n");
        }

        // WS1-06: record the MSI-X geometry so the Ring 3 driver's
        // `IrqAttach(33)` programs a real table entry. Gated like the
        // `msix` module itself (bare-metal x86_64, non-test).
        // SAFETY: single-CPU boot path; kernel singletons not aliased.
        #[cfg(all(target_os = "none", not(test)))]
        unsafe {
            register_msix_for_device(
                vnet,
                MSIX_IRQ_LINE_VIRTIO_NET,
                "virtio-net",
                MSIX_TABLE_VA_VIRTIO_NET,
                mapper,
                alloc,
            );
        }
    } else {
        early_console::write_str("[virtio-net] not found on any bus\n");
    }

    // ── TASK-005: NVMe live bring-up (P6.7.9-pre.11) ────────────────
    //
    // Find the NVMe device (class 01:08) across all scanned buses.
    // If found, perform live controller initialization via MMIO.
    if let Some(nvme) = scan.find_by_class(pci_scan::NVME_CLASS_CODE, pci_scan::NVME_SUBCLASS) {
        early_console::write_str("[nvme] found on bus=");
        write_hex_u8(nvme.bus);
        early_console::write_str(" dev=");
        write_hex_u8(nvme.device);
        early_console::write_str(" bar0=");
        write_hex_u32(nvme.bar0);
        early_console::write_str(" bar1=");
        write_hex_u32(nvme.bar1);
        early_console::write_str("\n");

        unsafe { pci_scan::enable_device_full(nvme) };
        early_console::write_str("[nvme] PCI cmd: IOSE+MSE+BME enabled\n");

        if pci_scan::PciDevice::bar_is_io(nvme.bar0) {
            early_console::write_str("[nvme] BAR0 is I/O port — MMIO bringup skipped\n");
        } else {
            let bar0_phys = nvme.bar0_phys();
            early_console::write_str("[nvme] BAR0 phys=");
            write_hex_u32((bar0_phys >> 32) as u32);
            write_hex_u32(bar0_phys as u32);
            early_console::write_str("\n");

            if bar0_phys != 0 {
                unsafe { nvme_live_bringup(bar0_phys, mapper, alloc) };
            } else {
                early_console::write_str("[nvme] BAR0 is zero — skipping\n");
            }
        }

        // WS1-06: record the MSI-X geometry so a future `IrqAttach(34)`
        // (WS1-07.5 NVMe completion path) programs a real table entry.
        // SAFETY: single-CPU boot path; kernel singletons not aliased.
        #[cfg(all(target_os = "none", not(test)))]
        unsafe {
            register_msix_for_device(
                nvme,
                MSIX_IRQ_LINE_NVME,
                "nvme",
                MSIX_TABLE_VA_NVME,
                mapper,
                alloc,
            );
        }
    } else {
        early_console::write_str("[nvme] not found on any bus\n");
    }

    // ── TASK-006: e1000e live bring-up (P6.7.9.c) ──────────────────
    //
    // Find the Intel e1000e device (vendor 0x8086, class 02:00 Ethernet)
    // across all scanned buses. If found, perform live controller
    // initialization via MMIO BAR0 (128 KiB CSR window).
    if let Some(e1000e) = scan.iter().find(|d| {
        d.vendor_id == pci_scan::INTEL_VENDOR_ID
            && d.class_code == pci_scan::ETHERNET_CLASS_CODE
            && d.subclass == pci_scan::ETHERNET_SUBCLASS
    }) {
        early_console::write_str("[e1000e] found on bus=");
        write_hex_u8(e1000e.bus);
        early_console::write_str(" dev=");
        write_hex_u8(e1000e.device);
        early_console::write_str(" bar0=");
        write_hex_u32(e1000e.bar0);
        early_console::write_str(" devid=");
        write_hex_u16(e1000e.device_id);
        early_console::write_str("\n");

        unsafe { pci_scan::enable_device_full(e1000e) };
        early_console::write_str("[e1000e] PCI cmd: IOSE+MSE+BME enabled\n");

        if pci_scan::PciDevice::bar_is_io(e1000e.bar0) {
            early_console::write_str("[e1000e] BAR0 is I/O port — MMIO bringup skipped\n");
        } else {
            let bar0_phys = e1000e.bar0_phys();
            early_console::write_str("[e1000e] BAR0 phys=");
            write_hex_u32((bar0_phys >> 32) as u32);
            write_hex_u32(bar0_phys as u32);
            early_console::write_str("\n");

            if bar0_phys != 0 {
                unsafe { e1000e_live_bringup(bar0_phys, mapper, alloc) };
            } else {
                early_console::write_str("[e1000e] BAR0 is zero — skipping\n");
            }
        }

        // WS1-06: record the MSI-X geometry so the Ring 3 driver's
        // `IrqAttach(35)` programs a real table entry.
        // SAFETY: single-CPU boot path; kernel singletons not aliased.
        #[cfg(all(target_os = "none", not(test)))]
        unsafe {
            register_msix_for_device(
                e1000e,
                MSIX_IRQ_LINE_E1000E,
                "e1000e",
                MSIX_TABLE_VA_E1000E,
                mapper,
                alloc,
            );
        }
    } else {
        early_console::write_str("[e1000e] not found on any bus\n");
    }

    // ── Probe ELF (smoke test for MmioMap/DmaMap/IrqAttach) ──────
    //
    // Pick any device with a non-zero BAR for the capability deposit
    // probe (unchanged from pre.9).
    if let Some(vdev) = scan.find_by_vendor(pci_scan::VIRTIO_VENDOR_ID) {
        let probe_bar = vdev.bar4_phys();
        let probe_irq = u16::from(vdev.irq_line);
        if probe_bar == 0 {
            let bar0 = vdev.bar0_phys();
            if bar0 != 0 {
                return unsafe { boot_load_with_bar(bar0, probe_irq, mapper, alloc, scheduler) };
            }
        } else {
            return unsafe { boot_load_with_bar(probe_bar, probe_irq, mapper, alloc, scheduler) };
        }
    }

    let synthetic_bar: u64 = 0xFEBC_0000;
    let synthetic_irq: u16 = 33;
    early_console::write_str("[driver-loader] using synthetic BAR 0xFEBC0000\n");
    unsafe { boot_load_with_bar(synthetic_bar, synthetic_irq, mapper, alloc, scheduler) };
}

/// Spawn a Ring 3 driver ELF and deposit its capability tokens.
///
/// Shared by the DEV-ONLY probe loader ([`boot_load_with_bar`]) and the real
/// virtio-net image loader ([`boot_load_virtio_net_image`]). Spawns `elf_bytes`
/// at `priority`, then deposits the `MmioMap`/`DmaMap`/`IrqAttach` tokens
/// described by `caps` into the new task's address space at the well-known
/// deposit VA. `label` tags the COM1 diagnostics.
///
/// Returns the spawned [`TaskId`] on success, or `None` if either the spawn or
/// the deposit failed (both log the reason to COM1).
///
/// # Safety
///
/// Ring 0, single-CPU boot path. `boot_cr3`, `mapper`, `alloc`, `scheduler`
/// must be the live kernel singletons (same invariant as the MB11 userprobe
/// spawn in `kmain`).
#[cfg(target_arch = "x86_64")]
#[allow(
    clippy::too_many_arguments,
    reason = "boot-path spawn+deposit helper threads the ELF, caps, optional device-info, \
              priority, label and the three kernel singletons; splitting it would only \
              shuffle the same state through a struct"
)]
unsafe fn spawn_driver_and_deposit<const N: usize>(
    elf_bytes: &[u8],
    caps: &DriverCapabilities,
    device_info: Option<cap_deposit::VirtioDeviceInfo>,
    priority: PriorityClass,
    label: &str,
    mapper: &mut crate::bare_metal::paging::PageMapper,
    alloc: &mut crate::memory::BitmapFrameAllocator<N>,
    scheduler: &mut crate::scheduling::RoundRobinScheduler,
) -> Option<crate::scheduling::TaskId> {
    use crate::{capabilities::KernelPrincipal, memory::PhysAddr};

    let boot_cr3 = PhysAddr(super::boot_cr3());
    if boot_cr3.0 == 0 {
        early_console::write_str("[driver-loader] boot_cr3 not set — aborting\n");
        return None;
    }

    // Ordering guarantee — deposit-#PF flake fix (NCIP-Kernel-Sec-026, R8-adjacent).
    //
    // `spawn_from_elf` below enrolls the driver task as **Runnable**, but the
    // capability deposit — which maps the cap window at
    // `DRIVER_CAP_DEPOSIT_VA = 0x10_0000` into the task's address space and
    // signs the tokens (Ed25519, non-trivial latency) — runs only AFTER it.
    // The LAPIC timer is already live at this point in boot, so a tick landing
    // in that window preempts kmain and dispatches the freshly-spawned driver,
    // which then reads `0x10_0000` before the deposit has mapped it → an
    // intermittent user-mode not-present fault (`#PF code=4 cr2=0x100000`,
    // ~half of cold boots; the signing latency widens the race).
    //
    // Mask interrupts across the entire spawn+deposit so the driver cannot be
    // dispatched until its capability window is installed. This is a single-CPU
    // boot path doing only memory + compute work (no interrupt-dependent
    // waits), so the short masked section is safe. The RAII guard restores the
    // caller's exact prior interrupt state on every return path.
    let _irq_guard = IrqRestore::mask();

    // Spawn the driver ELF.
    // SAFETY: single-CPU boot path; `boot_cr3`, `mapper`, `alloc`,
    // `scheduler` are the live kernel singletons (same invariant as
    // the MB11 userprobe spawn in `kmain`).
    let task_id = match unsafe {
        ProcessControlBlock::spawn_from_elf(
            elf_bytes,
            boot_cr3,
            mapper,
            alloc,
            scheduler,
            priority,
            KernelPrincipal::ZERO,
        )
    } {
        Ok(id) => id,
        Err(e) => {
            early_console::write_str("[driver-loader] ");
            early_console::write_str(label);
            early_console::write_str(" spawn FAILED: ");
            early_console::write_str(match e {
                crate::KernelError::ResourceExhausted => "ResourceExhausted",
                crate::KernelError::InvalidArgument => "InvalidArgument",
                _ => "Unknown",
            });
            early_console::write_str("\n");
            return None;
        }
    };

    early_console::write_str("[driver-loader] ");
    early_console::write_str(label);
    early_console::write_str(" spawned  task_id=");
    #[allow(
        clippy::cast_possible_truncation,
        reason = "task id fits usize on x86_64"
    )]
    early_console::write_usize(task_id.0 as usize);
    early_console::write_str("\n");

    // Deposit capability tokens into the new task's address space.
    let Some(pcb) = scheduler.process(task_id) else {
        early_console::write_str("[driver-loader] process lookup FAILED\n");
        return None;
    };

    // SAFETY: single-CPU boot path; `pcb.address_space` was just created
    // by `spawn_from_elf`; `mapper` and `alloc` are the live kernel
    // singletons. Direct-map offset is valid (set earlier in `kmain`).
    let deposit_result = unsafe {
        cap_deposit::deposit_for_driver_with_device_info(
            caps,
            0,           // boot_seconds (Phase 1: no RTC in token window)
            [0u8; 32],   // subject_node_id (DEV-ONLY placeholder)
            device_info, // optional virtio modern geometry (M0 Phase 3)
            &pcb.address_space,
            mapper,
            alloc,
        )
    };
    match deposit_result {
        Ok(va) => {
            early_console::write_str("[driver-loader] ");
            early_console::write_str(label);
            early_console::write_str(" deposit OK  va=");
            #[allow(
                clippy::cast_possible_truncation,
                reason = "deposit VA fits usize on x86_64"
            )]
            early_console::write_usize(va as usize);
            early_console::write_str("\n");
            // SAFETY: still inside the IrqRestore-masked single-CPU boot
            // section — the freshly spawned driver cannot be dispatched
            // until the IOMMU bind below has completed.
            unsafe { bind_driver_iommu_domain(task_id, caps, label, alloc, scheduler) };
            Some(task_id)
        }
        Err(e) => {
            early_console::write_str("[driver-loader] ");
            early_console::write_str(label);
            early_console::write_str(" deposit FAILED: ");
            early_console::write_str(match e {
                cap_deposit::DepositError::TokenCountExceeded { .. } => "TokenCountExceeded",
                cap_deposit::DepositError::TokenEncodingFailed => "TokenEncodingFailed",
                cap_deposit::DepositError::TokenSigningFailed => "TokenSigningFailed",
                cap_deposit::DepositError::ScopeBytesOverflow { .. } => "ScopeBytesOverflow",
                #[cfg(feature = "bare-metal")]
                cap_deposit::DepositError::MapFailed => "MapFailed",
                #[cfg(not(feature = "bare-metal"))]
                cap_deposit::DepositError::HostStub => "HostStub",
            });
            early_console::write_str("\n");
            None
        }
    }
}

/// Bind a freshly spawned boot-path driver to its per-device IOMMU domain
/// (WI-7b step 2 — NCIP-026 R2, TASK-07).
///
/// Mirror of the `DriverLoad (73)` bind block in `syscall_entry.rs`: the M0
/// drivers load through this deposit path rather than the signed-manifest
/// syscall (ADR-0024), so without this block they would have no IOMMU domain
/// and the operator-gated `GCMD.TE` flip would fault all of their DMA.
///
/// Sequence (each step best-effort, logged to COM1; a failure leaves the
/// driver alive with whatever bindings did succeed — same observability
/// policy as the cap-deposit failure path):
///
/// 1. `install_domain(domain_for_task(task_id))`.
/// 2. Attach every `Resource::PciDevice` BDF declared in `caps`; record
///    successes in `pcb.bound_pci_devices` (drives the exit teardown).
/// 3. Provision the per-domain SLPT root through [`KernelFrameSource`]
///    (the root the driver's later `DmaMap` calls populate via the WI-7a
///    builder).
/// 4. Live vendor install of the VT-d context entry / AMD-Vi DTE, sized to
///    the unit's live `CAP.SAGAW` (fallback 48-bit/4-level before
///    activation — same width the SLPT builder uses, so context-entry AGAW
///    and tree depth cannot disagree).
/// 5. **NO translation enable** — `GCMD.TE` / `CTRL.IommuEn` stays off; the
///    flip is operator-gated behind the `iommu-te` cargo feature and a
///    dedicated WI-7b hardware session.
///
/// No-PCI drivers (empty `caps.pci_devices`, e.g. the DEV-ONLY probe) skip
/// everything after step 1's idempotent domain install.
///
/// # Safety
///
/// Ring 0, single-CPU boot path under the caller's `IrqRestore` mask.
/// `alloc` and `scheduler` must be the live kernel singletons and the
/// bootloader direct map must be established (`bare_metal::phys_offset`).
#[cfg(target_arch = "x86_64")]
#[allow(
    clippy::too_many_lines,
    reason = "single boot-path bind helper — keeps domain install + attach + provision + \
              vendor-table install and their per-step COM1 diagnostics locally auditable, \
              mirroring the DriverLoad(73) block (same rationale as dma_map)"
)]
unsafe fn bind_driver_iommu_domain<const N: usize>(
    task_id: crate::scheduling::TaskId,
    caps: &DriverCapabilities,
    label: &str,
    alloc: &mut crate::memory::BitmapFrameAllocator<N>,
    scheduler: &mut crate::scheduling::RoundRobinScheduler,
) {
    use crate::bare_metal::iommu::{
        IommuBackend, KernelFrameSource, domain_for_task, iommu_attach_device,
        iommu_provision_domain_pt, pci_bdfs_from_resources, with_iommu_backend,
    };

    let domain_id = domain_for_task(task_id.0);
    let bdfs = pci_bdfs_from_resources(&caps.pci_devices);
    if bdfs.is_empty() {
        return;
    }
    if with_iommu_backend(|kind| kind.install_domain(domain_id)).is_err() {
        early_console::write_str("[driver-loader] ");
        early_console::write_str(label);
        early_console::write_str(" iommu install_domain FAILED\n");
        return;
    }
    let mut any_bdf_attached = false;
    if let Some(pcb) = scheduler.process_mut(task_id) {
        for bdf in bdfs {
            if iommu_attach_device(bdf, domain_id).is_ok() {
                pcb.bound_pci_devices.push(bdf);
                any_bdf_attached = true;
            } else {
                // Partial-attach failures must be observable in the
                // hardware capture (review finding: a 1-of-N conflict
                // would otherwise masquerade as full success).
                early_console::write_str("[driver-loader] ");
                early_console::write_str(label);
                early_console::write_str(" iommu attach skipped (conflict)\n");
            }
        }
    }
    early_console::write_str("[driver-loader] ");
    early_console::write_str(label);
    if !any_bdf_attached {
        early_console::write_str(" iommu attach FAILED\n");
        return;
    }
    early_console::write_str(" iommu domain attached  did=");
    early_console::write_usize(usize::from(domain_id.raw()));
    early_console::write_str("\n");

    let phys_off = crate::bare_metal::phys_offset();
    // Provision the per-domain SLPT root. Passthrough short-circuits to
    // Ok(0) without consuming a frame; on Intel/AMD the recorded root is
    // what the live install below points the context entry / DTE at and
    // what the driver's `DmaMap` calls populate. The flag (instead of an
    // early return) keeps the function tail structurally valid on host
    // builds where the cfg-gated install block below compiles out.
    let provisioned = {
        let mut src = KernelFrameSource::new(&mut *alloc, phys_off);
        iommu_provision_domain_pt(domain_id, &mut src).is_ok()
    };
    if !provisioned {
        early_console::write_str("[driver-loader] ");
        early_console::write_str(label);
        early_console::write_str(" iommu slpt-root provision FAILED\n");
    }

    // Live vendor-table install — bare-metal only (the host build has no
    // MMIO window to program). TE is NOT raised here by design.
    #[cfg(target_os = "none")]
    if provisioned {
        use crate::bare_metal::iommu::{
            IommuFlags, IommuVendor,
            amdvi::PageMode,
            install_amd_vi_device_entry, install_vt_d_device_entry_managed,
            iommu_domain_pt_root_phys, iommu_supported_address_width, iommu_vendor,
            vtd::{AddressWidth, TranslationType},
        };
        if let Some(slpt_phys) = iommu_domain_pt_root_phys(domain_id) {
            let bound = scheduler
                .process(task_id)
                .map(|pcb| pcb.bound_pci_devices.clone())
                .unwrap_or_default();
            let vendor = iommu_vendor();
            // Live CAP.SAGAW width (cached at activation); the fallback
            // matches the SLPT builder's so the two can never disagree.
            let width = iommu_supported_address_width().unwrap_or(AddressWidth::Bits48Level4);
            let mut src = KernelFrameSource::new(&mut *alloc, phys_off);
            for bdf in bound {
                let install_result = match vendor {
                    // SAFETY: single-CPU boot path; `phys_off` is the live
                    // direct-map offset; `slpt_phys` was just provisioned
                    // from FRAME_ALLOC (kernel-owned, 4-KiB-aligned).
                    IommuVendor::Intel => unsafe {
                        install_vt_d_device_entry_managed(
                            phys_off,
                            bdf,
                            domain_id,
                            slpt_phys,
                            width,
                            // WI-7b step 3 C2 (ADR-0028): the confined
                            // driver's entry is `UntranslatedOnly` (TT=00b)
                            // — all of its DMA is routed through its own
                            // second-level page table (the identity
                            // `phys_base→phys_base` windows the driver's
                            // `DmaMap` calls build), so the device can only
                            // reach its own buffers and nothing else. 00b
                            // (not 01b) because the driver issues no ATS
                            // requests and QEMU advertises no `ECAP.DT`. The
                            // TE-finalize guard refuses the flip until this
                            // domain's SLPT is built, so an early flip cannot
                            // fault the driver. (C1 used `Passthrough` to
                            // prove the flip mechanism + device enumeration
                            // independent of SLPT correctness.)
                            TranslationType::UntranslatedOnly,
                            &mut src,
                        )
                    },
                    // SAFETY: same invariants; the AMD path programs the
                    // device-table page recorded at AMD-Vi activation.
                    IommuVendor::Amd => unsafe {
                        install_amd_vi_device_entry(
                            phys_off,
                            bdf,
                            domain_id,
                            slpt_phys,
                            IommuFlags::READ.union(IommuFlags::WRITE),
                            PageMode::Level4,
                        )
                    },
                    IommuVendor::Passthrough => Ok(false),
                };
                early_console::write_str("[driver-loader] ");
                early_console::write_str(label);
                match install_result {
                    Ok(true) => {
                        early_console::write_str(" iommu ctx-entry installed (TE off)\n");
                    }
                    Ok(false) => {
                        early_console::write_str(" iommu ctx-entry skipped (passthrough)\n");
                    }
                    Err(_) => early_console::write_str(" iommu ctx-entry FAILED\n"),
                }
            }
        }
    }
}

/// Finalize the IOMMU and raise VT-d `GCMD.TE` — WI-7b step 3 C1 (ADR-0028,
/// NCIP-026 R2, TASK-07).
///
/// Operator-gated behind the `iommu-te` cargo feature; never compiled into
/// the default / CI build. Runs ONCE at the end of `kmain`, AFTER every
/// device bring-up and the confined driver's `bind_driver_iommu_domain`,
/// and BEFORE `run_desktop`.
///
/// ## What it does (C1 — all-passthrough baseline)
///
/// 1. Installs a `Passthrough` (TT=10b, `slpt_phys = 0`, `AW = highest
///    CAP.SAGAW`) context entry under a bring-up domain for EVERY scanned
///    PCI device that does not already have one (the confined virtio-net
///    driver already installed its own via `bind_driver_iommu_domain`).
///    With TE about to be raised, an absent context entry would cause the
///    IOMMU to block + fault that device's DMA, so the passthrough baseline
///    is what keeps the in-kernel virtio-tablet, e1000e, NVMe, virtio-blk
///    and USB controllers alive across the flip.
/// 2. Raises `GCMD.TE` (via [`super::iommu::iommu_enable_translation`]) only
///    if EVERY install succeeded — a partial baseline would brick a device,
///    so any failure aborts the flip (M0 stays in TE-off passthrough).
/// 3. Drains the DMAR fault registers and logs any fault (expected: none on
///    a clean all-passthrough flip).
///
/// In C1 the confined driver's entry is itself `Passthrough` (see
/// `bind_driver_iommu_domain`), so the first flip leaves EVERY device
/// identity-addressing — behaviourally equal to TE-off — which isolates
/// "is device enumeration complete?" from "is the confined SLPT correct?".
/// C2 switches the confined driver to a translating entry.
///
/// # Safety
///
/// Ring 0, single-CPU boot path. `alloc` must be the live kernel frame
/// allocator and the bootloader direct map must be established. The live
/// VT-d unit must have been activated (`activate_intel_vt_d`).
#[cfg(all(target_arch = "x86_64", target_os = "none", feature = "iommu-te"))]
#[allow(
    clippy::too_many_lines,
    clippy::cognitive_complexity,
    clippy::cast_possible_truncation,
    reason = "single boot-finalisation step — passthrough baseline + flip + \
              fault drain + (negtest) the §S9.1 harness, kept in one locally \
              auditable place; splitting would scatter the unsafe MMIO sites. \
              The u64→u32 casts split addresses/registers into hex halves (exact)."
)]
pub unsafe fn iommu_finalize_enable_translation<const N: usize>(
    alloc: &mut crate::memory::BitmapFrameAllocator<N>,
) {
    use crate::bare_metal::iommu::{
        DomainId, IommuBackend, IommuVendor, KernelFrameSource, PciBdf,
        install_vt_d_device_entry_managed, iommu_attached_domain, iommu_domain_has_mappings,
        iommu_drain_faults, iommu_enable_translation, iommu_has_attachment,
        iommu_supported_address_width, iommu_vendor, vtd::TranslationType, with_iommu_backend,
    };

    // Bring-up domain 0 holds the passthrough baseline entries. No DMA
    // driver uses task 0, so domain 0 is free for this role.
    const BRINGUP: DomainId = DomainId::new(0);

    if iommu_vendor() != IommuVendor::Intel {
        early_console::write_str("[iommu] TE finalize: backend not Intel — skip\n");
        return;
    }
    let Some(width) = iommu_supported_address_width() else {
        early_console::write_str("[iommu] TE finalize: CAP.SAGAW empty — NOT flipping TE\n");
        return;
    };
    let phys_off = crate::bare_metal::phys_offset();

    if with_iommu_backend(|b| b.install_domain(BRINGUP)).is_err() {
        early_console::write_str("[iommu] TE finalize: install_domain(0) FAILED — NOT flipping\n");
        return;
    }

    // SAFETY: Ring 0 boot path; PCI config-space reads are side-effect free.
    let scan = unsafe { pci_scan::scan_all_buses() };
    let mut installed: usize = 0;
    let mut skipped: usize = 0;
    let mut failed: usize = 0;
    // Domains of the confined (already-attached) drivers we skip — their
    // SLPT must be built before the flip (C2 guard below).
    let mut confined_domains: alloc::vec::Vec<DomainId> = alloc::vec::Vec::new();
    // §S9.1 negative-test target (ADR-0029): the e1000e BDF given an empty
    // SLPT so its post-flip DMA faults. `None` outside the negtest build.
    #[cfg(feature = "iommu-negtest")]
    let mut negtest_e1000e: Option<PciBdf> = None;
    for dev in scan.iter() {
        let bdf = PciBdf::from_parts(dev.bus, dev.device, dev.function);
        // §S9.1 NEGATIVE test (ADR-0029): give the in-kernel e1000e (which
        // M0 does not use) a TRANSLATING entry to a fresh domain with an
        // EMPTY second-level page table, so the forced TX DMA after the
        // flip hits an unmapped IOVA and the IOMMU faults it. Done before
        // the passthrough branch so e1000e does NOT get a passthrough
        // entry. Its empty domain is deliberately NOT added to
        // `confined_domains` (the empty SLPT is the whole point).
        #[cfg(feature = "iommu-negtest")]
        if dev.vendor_id == pci_scan::INTEL_VENDOR_ID
            && dev.class_code == pci_scan::ETHERNET_CLASS_CODE
            && dev.subclass == pci_scan::ETHERNET_SUBCLASS
        {
            const NEGTEST_DOMAIN: DomainId = DomainId::new(0xFFFE);
            let _ = with_iommu_backend(|b| b.install_domain(NEGTEST_DOMAIN));
            let root = {
                let mut src = KernelFrameSource::new(&mut *alloc, phys_off);
                crate::bare_metal::iommu::iommu_provision_domain_pt(NEGTEST_DOMAIN, &mut src).ok()
            };
            if let Some(root_phys) = root {
                let mut src = KernelFrameSource::new(&mut *alloc, phys_off);
                // SAFETY: `phys_off` live; `root_phys` just provisioned
                // (kernel-owned, 4-KiB aligned); the SLPT is intentionally
                // empty so e1000e's DMA faults.
                let r = unsafe {
                    install_vt_d_device_entry_managed(
                        phys_off,
                        bdf,
                        NEGTEST_DOMAIN,
                        root_phys,
                        width,
                        TranslationType::UntranslatedOnly,
                        &mut src,
                    )
                };
                if r.is_ok() {
                    negtest_e1000e = Some(bdf);
                    early_console::write_str(
                        "[iommu] negtest: e1000e installed with EMPTY SLPT (will fault)\n",
                    );
                    installed += 1;
                } else {
                    failed += 1;
                }
            } else {
                failed += 1;
            }
            continue;
        }
        if iommu_has_attachment(bdf) {
            // The confined driver already installed its context entry
            // (`bind_driver_iommu_domain`). Record its domain so the
            // pre-flip guard can verify its SLPT is populated.
            if let Some(dom) = iommu_attached_domain(bdf) {
                if !confined_domains.contains(&dom) {
                    confined_domains.push(dom);
                }
            }
            skipped += 1;
            continue;
        }
        let mut src = KernelFrameSource::new(&mut *alloc, phys_off);
        // SAFETY: `phys_off` is the live direct-map offset; this is a
        // passthrough entry so `slpt_phys = 0` is ignored by hardware;
        // BRINGUP was installed above.
        let r = unsafe {
            install_vt_d_device_entry_managed(
                phys_off,
                bdf,
                BRINGUP,
                0,
                width,
                TranslationType::Passthrough,
                &mut src,
            )
        };
        if r.is_ok() {
            installed += 1;
        } else {
            failed += 1;
        }
    }
    early_console::write_str("[iommu] TE finalize: passthrough installed=");
    early_console::write_usize(installed);
    early_console::write_str(" skipped=");
    early_console::write_usize(skipped);
    early_console::write_str(" failed=");
    early_console::write_usize(failed);
    early_console::write_str("\n");
    if failed > 0 {
        early_console::write_str(
            "[iommu] TE finalize: some install FAILED — NOT flipping TE (M0-safe abort)\n",
        );
        return;
    }

    // C2 timing barrier: a confined driver is on a TRANSLATING context
    // entry, so its DMA goes through its second-level page table. That
    // SLPT is built by the driver's `DmaMap` calls, which run when the
    // live LAPIC timer preempts this boot path into the driver task — a
    // race relative to reaching this finalize step (it shifted with
    // `caching-mode=on`, which adds invalidation VM-exits to the driver's
    // `DmaMap` path). Rather than gamble on the timing, WAIT here: a
    // bounded busy-spin with interrupts live lets the timer dispatch the
    // driver, which completes its `DmaMap` and populates the SLPT, then
    // returns control here. Re-check each round. This makes the flip
    // deterministic instead of timing-dependent.
    //
    // Bounded so a genuinely stuck/absent driver cannot hang boot: if the
    // SLPT is still empty after the budget, abort the flip (M0 stays in
    // TE-off passthrough — safe degrade — and the condition is logged).
    {
        let mut ready = false;
        for _ in 0..200_u32 {
            if confined_domains
                .iter()
                .all(|d| iommu_domain_has_mappings(*d))
            {
                ready = true;
                break;
            }
            // Busy-spin a slice; the live timer preempts us into the
            // driver task (same coexistence the desktop loop relies on).
            for _ in 0..2_000_000_u32 {
                core::hint::spin_loop();
            }
        }
        if !ready {
            early_console::write_str(
                "[iommu] TE finalize: confined domain SLPT not built after wait — NOT flipping TE (M0-safe abort)\n",
            );
            return;
        }
    }
    early_console::write_str("[iommu] TE finalize: confined domain SLPT ready\n");

    // SAFETY: `phys_off` live; every DMA-capable device now has a context
    // entry (passthrough baseline + the confined driver's own), and every
    // confined domain's SLPT is populated.
    match unsafe { iommu_enable_translation(phys_off) } {
        Ok(true) => early_console::write_str("[iommu] GCMD.TE raised — translation ENABLED\n"),
        Ok(false) => early_console::write_str("[iommu] TE finalize: no-op backend\n"),
        Err(_) => early_console::write_str("[iommu] TE finalize: GCMD.TE flip FAILED\n"),
    }

    // §S9.1 NEGATIVE test (ADR-0029): force an e1000e TX so it DMA-reads a
    // descriptor from its TX ring (TDBAL = phys 0) — unmapped in its empty
    // SLPT — and the IOMMU must fault it. The controller's TX engine may
    // process the tail bump asynchronously, so we poll: each STATUS read is
    // a VM exit that lets QEMU advance, and we drain after each round,
    // stopping as soon as the out-of-window fetch faults. TDH before/after
    // and the raw FSTS are logged to diagnose a no-fault outcome.
    #[cfg(feature = "iommu-negtest")]
    let mut negtest_observed: alloc::vec::Vec<crate::bare_metal::iommu::vtd::FaultRecord> =
        alloc::vec::Vec::new();
    #[cfg(feature = "iommu-negtest")]
    if let Some(e_bdf) = negtest_e1000e {
        if E1000E_LIVE.load(Ordering::Relaxed) {
            let tx_tail_reg = (E1000E_MMIO_VA_BASE + E1000E_REG_TDT as u64) as *mut u32;
            let tx_head_reg = (E1000E_MMIO_VA_BASE + E1000E_REG_TDH as u64) as *const u32;
            let tx_base_lo = (E1000E_MMIO_VA_BASE + E1000E_REG_TDBAL as u64) as *mut u32;
            let tx_base_hi = (E1000E_MMIO_VA_BASE + E1000E_REG_TDBAH as u64) as *mut u32;
            // STATUS register (offset 0x0008) — read to force a VM exit.
            let status = (E1000E_MMIO_VA_BASE + 0x0008) as *const u32;
            // Point the TX ring base at a deliberately non-zero, unmapped
            // IOVA (1 GiB) so the descriptor fetch is an unambiguous
            // out-of-window access (avoids any IOVA-0 special-casing).
            // SAFETY: kernel-mapped live e1000e CSR window.
            unsafe {
                core::ptr::write_volatile(tx_base_lo, 0x4000_0000);
                core::ptr::write_volatile(tx_base_hi, 0);
            }
            // SAFETY: kernel-mapped live e1000e CSR window.
            let tdh_before = unsafe { core::ptr::read_volatile(tx_head_reg) };
            // Force TX: bump tail so the controller fetches descriptor[0]
            // from TDBAL (1 GiB IOVA), unmapped in the empty SLPT.
            // SAFETY: single 32-bit MMIO write to the TX tail.
            unsafe { core::ptr::write_volatile(tx_tail_reg, 1) };
            for _ in 0..4096_u32 {
                // SAFETY: MMIO read of the live e1000e STATUS register —
                // a VM exit that lets QEMU advance the TX engine.
                let _ = unsafe { core::ptr::read_volatile(status) };
                // SAFETY: `phys_off` live; drains + RW1C-clears FRCD.
                let f = unsafe { iommu_drain_faults(phys_off) };
                if !f.is_empty() {
                    negtest_observed = f;
                    break;
                }
            }
            // SAFETY: kernel-mapped live e1000e CSR window.
            let tdh_after = unsafe { core::ptr::read_volatile(tx_head_reg) };
            // SAFETY: `phys_off` live; raw fault-register diagnostic.
            let (cap, fsts, frcd_lo, frcd_hi) =
                unsafe { crate::bare_metal::iommu::iommu_fault_regs_debug(phys_off) };
            early_console::write_str("[iommu] negtest: forced e1000e TX TDH ");
            early_console::write_usize(tdh_before as usize);
            early_console::write_str("->");
            early_console::write_usize(tdh_after as usize);
            early_console::write_str(" FSTS=");
            write_hex_u32(fsts);
            early_console::write_str("\n[iommu] negtest diag: CAP.FRO=");
            write_hex_u32(crate::bare_metal::iommu::vtd::cap_fault_recording_offset(
                cap,
            ));
            early_console::write_str(" FRCD0_hi=");
            write_hex_u32((frcd_hi >> 32) as u32);
            write_hex_u32(frcd_hi as u32);
            early_console::write_str(" FRCD0_lo=");
            write_hex_u32((frcd_lo >> 32) as u32);
            write_hex_u32(frcd_lo as u32);
            early_console::write_str("\n");
        }
        let _ = e_bdf;
    }

    // SAFETY: `phys_off` live; drains + RW1C-clears the fault registers.
    let faults = unsafe { iommu_drain_faults(phys_off) };
    if faults.is_empty() {
        early_console::write_str("[iommu] TE finalize: 0 DMAR faults post-flip\n");
    } else {
        for f in &faults {
            early_console::write_str("[iommu] DMAR FAULT sid=");
            write_hex_u32(u32::from(f.source_id));
            early_console::write_str(" reason=");
            write_hex_u8(f.reason);
            early_console::write_str(" addr=");
            write_hex_u32((f.address >> 32) as u32);
            write_hex_u32(f.address as u32);
            early_console::write_str("\n");
        }
    }

    // §S9.1 NEGATIVE test result + REVOCATION (ADR-0029): a fault whose
    // source-id matches the e1000e proves the IOMMU blocked the
    // out-of-window DMA. Then quiesce e1000e (RX/TX off) and revoke its
    // context entry (detach + invalidation) — the same MMIO teardown a
    // token destruction drives via `tear_down_pci_bindings`.
    #[cfg(feature = "iommu-negtest")]
    if let Some(e_bdf) = negtest_e1000e {
        // The fault was collected by the poll loop above (already
        // RW1C-cleared there); `faults` from the generic drain may be empty.
        for f in &negtest_observed {
            early_console::write_str("[iommu] negtest DMAR FAULT sid=");
            write_hex_u32(u32::from(f.source_id));
            early_console::write_str(" reason=");
            write_hex_u8(f.reason);
            early_console::write_str("\n");
        }
        let blocked = negtest_observed.iter().any(|f| f.source_id == e_bdf.raw());
        if blocked {
            early_console::write_str(
                "[iommu] negtest PASS: e1000e out-of-window DMA BLOCKED + faulted by IOMMU\n",
            );
        } else {
            early_console::write_str(
                "[iommu] negtest: no e1000e fault observed (see TDH/FSTS diag above)\n",
            );
        }
        // Quiesce e1000e so it stops issuing (now-blocked) DMA after revoke.
        if E1000E_LIVE.load(Ordering::Relaxed) {
            let rctl = (E1000E_MMIO_VA_BASE + E1000E_REG_RCTL as u64) as *mut u32;
            let tctl = (E1000E_MMIO_VA_BASE + E1000E_REG_TCTL as u64) as *mut u32;
            // SAFETY: kernel-mapped live e1000e CSR window; disable RX/TX.
            unsafe {
                core::ptr::write_volatile(rctl, 0);
                core::ptr::write_volatile(tctl, 0);
            }
        }
        // Revocation: zero the context entry + invalidate (the teardown
        // path a destroyed DMA token triggers).
        let mut src = KernelFrameSource::new(&mut *alloc, phys_off);
        // SAFETY: `phys_off` live; `e_bdf` was installed above.
        let revoked = unsafe {
            crate::bare_metal::iommu::release_vt_d_device_entry_managed(phys_off, e_bdf, &mut src)
        };
        match revoked {
            Ok(_) => early_console::write_str(
                "[iommu] negtest: e1000e context entry REVOKED (detach + invalidation)\n",
            ),
            Err(_) => {
                early_console::write_str("[iommu] negtest: e1000e revoke FAILED\n");
            }
        }
        // Drain any fault raised between the first drain and the revoke.
        // SAFETY: `phys_off` live.
        let post = unsafe { iommu_drain_faults(phys_off) };
        early_console::write_str("[iommu] negtest: post-revoke faults drained=");
        early_console::write_usize(post.len());
        early_console::write_str("\n");
    }
}

/// Spawn the Ring 3 virtio-net driver image and deposit its capability tokens.
///
/// Called once at boot from `kmain` AFTER the DEV-ONLY probe loader (so the
/// in-kernel NVMe CAP read has already completed on the boot CR3) and BEFORE
/// the `nexacore-net` service, so the driver can `NetRegister("virtio0")` before
/// the network stack looks it up. Spawned at `System` priority alongside
/// `nexacore-net`.
///
/// The MMIO scope is the device's REAL modern BAR (discovered from the PCI
/// capability chain, NOT a hardcoded address) covering the common/isr/device/
/// notify structures; the geometry is handed to the image via the deposit
/// page's [`cap_deposit::VirtioDeviceInfo`] section so it can `MmioMap` the
/// right window and locate the registers without PCI-config / I/O-port access.
/// DMA IOVA `0x100_0000_0000`/`4 KiB` (inside `[DRIVER_DMA_VA_BASE,
/// DRIVER_DMA_VA_END)`, one page to dodge the Phase-1 contiguity limit), IRQ
/// line `33`.
///
/// `elf_bytes` is the driver image read from the VFS by the caller. Best-effort:
/// any spawn/deposit failure is logged to COM1 and the boot continues (the
/// network stack then retries the `virtio0` lookup and reports it unregistered).
///
/// # Safety
///
/// Ring 0, single-CPU boot path. `mapper`, `alloc`, `scheduler` must be the
/// live kernel singletons (same invariant as the probe loader and the
/// `nexacore-net` spawn block in `kmain`).
#[cfg(target_arch = "x86_64")]
pub unsafe fn boot_load_virtio_net_image<const N: usize>(
    elf_bytes: &[u8],
    mapper: &mut crate::bare_metal::paging::PageMapper,
    alloc: &mut crate::memory::BitmapFrameAllocator<N>,
    scheduler: &mut crate::scheduling::RoundRobinScheduler,
) {
    // Legacy fallback window (used only if no modern caps are advertised) and
    // the BAR window length to map. Declared first to satisfy
    // `items_after_statements`.
    const FALLBACK_PHYS: u64 = 0xFEBC_0000;
    const FALLBACK_LEN: u64 = 0x1000;
    // Map a generous 4 pages of the BAR: the 4 structures sit in the first 4
    // pages (common@0, isr@0x1000, device@0x2000, notify@0x3000 on QEMU q35).
    const MMIO_WINDOW_LEN: u32 = 0x4000;

    // Rediscover the virtio-net device + its modern register geometry. The
    // BAR is firmware-assigned, so we must read it live rather than hardcode.
    // SAFETY: Ring 0 boot path; config-space reads have no side effects.
    let scan = unsafe { pci_scan::scan_all_buses() };
    let vnet = scan
        .find(
            pci_scan::VIRTIO_VENDOR_ID,
            pci_scan::VIRTIO_NET_DEVICE_ID_TRANSITIONAL,
        )
        .or_else(|| {
            scan.find(
                pci_scan::VIRTIO_VENDOR_ID,
                pci_scan::VIRTIO_NET_DEVICE_ID_MODERN,
            )
        });

    let mut caps = DriverCapabilities::default();

    // Discover the modern register geometry. `device_info` is `Some` only when
    // the device advertises usable virtio modern caps; otherwise we fall back
    // to the legacy hardcoded window so the deposit still succeeds (the image
    // then finds no usable geometry and reports it).
    let device_info: Option<cap_deposit::VirtioDeviceInfo> = vnet.and_then(|dev| {
        // SAFETY: Ring 0; pure config-space reads.
        let vc = unsafe { pci_scan::parse_virtio_modern_caps(dev.bus, dev.device, dev.function) }?;
        Some(cap_deposit::VirtioDeviceInfo {
            bar_phys: bar_phys_for_index(dev, vc.common.bar),
            mmio_len: MMIO_WINDOW_LEN,
            common_offset: vc.common.offset,
            notify_offset: vc.notify.offset,
            isr_offset: vc.isr.offset,
            device_offset: vc.device.offset,
            notify_off_multiplier: vc.notify_off_multiplier,
        })
    });
    let (mmio_phys, mmio_len) = device_info.map_or((FALLBACK_PHYS, FALLBACK_LEN), |i| {
        (i.bar_phys, u64::from(i.mmio_len))
    });

    caps.mmio_regions.push(Resource::MmioRegion {
        phys_base: mmio_phys,
        len: mmio_len,
    });
    caps.dma_windows.push(Resource::DmaWindow {
        // Two-page DMA scope inside the kernel's driver-DMA window
        // (DRIVER_DMA_VA_BASE = 0x100_0000_0000): page 0 = TX virtqueue+frame,
        // page 1 = RX virtqueue+buffers. The image issues TWO separate one-page
        // DmaMap calls (TX iova 0x100_0000_0000, RX iova 0x100_0000_1000), each
        // a subset of this scope and each individually contiguous (dodging the
        // Phase-1 per-call contiguity limit). One token covers both so the
        // image needs no postcard decode to pick a token.
        iova_base: 0x0000_0100_0000_0000,
        len: 0x2000,
    });
    caps.irq_lines.push(Resource::IrqLine(33));
    // WI-7b step 2 (NCIP-026, TASK-07): declare the device's PCI BDF so
    // `spawn_driver_and_deposit` binds the driver process to a
    // per-device IOMMU domain (attach + per-domain SLPT root +
    // VT-d context entry) exactly like the `DriverLoad (73)` path does
    // from a signed manifest. `GCMD.TE` stays OFF — the binding is
    // inert until the operator-gated TE session — but every boot now
    // exercises the live context-entry + invalidation-queue path and
    // the driver's `DmaMap` windows land in a real SLPT.
    if let Some(dev) = vnet {
        caps.pci_devices.push(Resource::PciDevice {
            segment: 0,
            bus: dev.bus,
            device: dev.device,
            function: dev.function,
        });
    }

    early_console::write_str("[driver-loader] virtio-net MMIO scope phys=");
    #[allow(
        clippy::cast_possible_truncation,
        reason = "splitting a u64 into two u32 halves for hex display; each half is exact"
    )]
    {
        write_hex_u32((mmio_phys >> 32) as u32);
        write_hex_u32(mmio_phys as u32);
        early_console::write_str(" len=");
        write_hex_u32(mmio_len as u32);
    }
    early_console::write_str(if device_info.is_some() {
        " (modern caps)\n"
    } else {
        " (FALLBACK — no modern caps)\n"
    });

    // SAFETY: single-CPU boot path; the kernel singletons are not aliased.
    let _ = unsafe {
        spawn_driver_and_deposit(
            elf_bytes,
            &caps,
            device_info,
            PriorityClass::System,
            "virtio-net",
            mapper,
            alloc,
            scheduler,
        )
    };
}

/// Boot-spawn the Ring 3 NVMe driver (`/bin/nexacore-driver-nvme`) at `System`
/// priority and deposit its `MmioMap` / `DmaMap` capability tokens
/// (TASK-14, ADR-0036 D1).
///
/// Mirrors [`boot_load_virtio_net_image`] but for NVMe: rediscover the
/// controller live (its BAR is firmware-assigned), deposit a BAR0 MMIO
/// scope + a 4 GiB DMA arena (`iova_base = 0`, passthrough IOMMU →
/// `user_va == iova`, the image's hardcoded convention) + the PCI BDF
/// (so the driver gets its per-device IOMMU domain + the DMA windows land
/// in a real SLPT — TASK-07). NO IRQ token: Option A serves completions
/// by cooperative-yield CQ drain, not interrupts (real MSI-X delivery is
/// tracked separately — ADR-0036 status appendix).
///
/// Additive + best-effort: a missing image or absent controller logs and
/// boot continues.
///
/// # Safety
///
/// Single-CPU boot path; the kernel singletons are not aliased.
#[cfg(target_arch = "x86_64")]
pub unsafe fn boot_load_nvme_image<const N: usize>(
    elf_bytes: &[u8],
    mapper: &mut crate::bare_metal::paging::PageMapper,
    alloc: &mut crate::memory::BitmapFrameAllocator<N>,
    scheduler: &mut crate::scheduling::RoundRobinScheduler,
) {
    // BAR0 window length the image maps (16 KiB per NCIP-014 §S1).
    const NVME_MMIO_LEN: u64 = 0x4000;
    // DMA arena: 8 pages (32 KiB) at the kernel driver-DMA window base.
    // The image lays admin SQ/CQ + Identify buffers + IO SQ/CQ + the
    // sector bounce buffer at offsets 0x0..0x7FFF within it (TASK-14,
    // ADR-0036). `DmaMap` requires `iova >= DRIVER_DMA_VA_BASE` and
    // strictly-contiguous frames, so the window MUST sit in that range
    // and stay small (8 contiguous frames is an early-boot-feasible ask;
    // 4 GiB would need 1 M contiguous frames — impossible).
    const NVME_DMA_IOVA_BASE: u64 = 0x0000_0100_0000_0000;
    const NVME_DMA_LEN: u64 = 0x8000;

    // SAFETY: Ring 0 boot path; config-space reads have no side effects.
    let scan = unsafe { pci_scan::scan_all_buses() };
    let Some(nvme) = scan.find_by_class(pci_scan::NVME_CLASS_CODE, pci_scan::NVME_SUBCLASS) else {
        early_console::write_str("[driver-loader] nvme: controller not found — skipping spawn\n");
        return;
    };
    let bar0_phys = nvme.bar0_phys();
    if bar0_phys == 0 || pci_scan::PciDevice::bar_is_io(nvme.bar0) {
        early_console::write_str("[driver-loader] nvme: BAR0 not MMIO — skipping spawn\n");
        return;
    }

    let mut caps = DriverCapabilities::default();
    caps.mmio_regions.push(Resource::MmioRegion {
        phys_base: bar0_phys,
        len: NVME_MMIO_LEN,
    });
    caps.dma_windows.push(Resource::DmaWindow {
        iova_base: NVME_DMA_IOVA_BASE,
        len: NVME_DMA_LEN,
    });
    caps.pci_devices.push(Resource::PciDevice {
        segment: 0,
        bus: nvme.bus,
        device: nvme.device,
        function: nvme.function,
    });
    // WS1-07 (ADR-0036 D5, Option B): grant the IO-CQ interrupt line so
    // the driver can `IrqAttach(34)` its completion notification channel.
    // The boot probe registered the device's MSI-X geometry under the
    // same line (WS1-06), so the attach programs a real table entry.
    caps.irq_lines.push(Resource::IrqLine(MSIX_IRQ_LINE_NVME));

    early_console::write_str("[driver-loader] nvme MMIO scope phys=");
    #[allow(
        clippy::cast_possible_truncation,
        reason = "splitting a u64 into two u32 halves for hex display; each half is exact"
    )]
    {
        write_hex_u32((bar0_phys >> 32) as u32);
        write_hex_u32(bar0_phys as u32);
    }
    early_console::write_str(" len=4000 dma=hi+32KiB\n");

    // The NVMe BAR is firmware-assigned (a 64-bit PCIe BAR can land at a
    // HIGH physical address, e.g. 0x3840_0000_4000 on QEMU pcie.0), so the
    // image MUST learn the live phys rather than hardcode it. We carry it
    // in the deposit page's device-info section (reusing the BAR-phys +
    // len fields; the virtio-specific offsets are zero/unused for NVMe).
    // The image reads it via `nexacore_driver_shared::device_info::read()`
    // (no-alloc) and maps THAT base (TASK-14, ADR-0036).
    #[allow(
        clippy::cast_possible_truncation,
        reason = "NVME_MMIO_LEN = 0x4000 fits u32"
    )]
    let nvme_info = cap_deposit::VirtioDeviceInfo {
        bar_phys: bar0_phys,
        mmio_len: NVME_MMIO_LEN as u32,
        common_offset: 0,
        notify_offset: 0,
        isr_offset: 0,
        device_offset: 0,
        notify_off_multiplier: 0,
    };

    // SAFETY: single-CPU boot path; the kernel singletons are not aliased.
    let _ = unsafe {
        spawn_driver_and_deposit(
            elf_bytes,
            &caps,
            Some(nvme_info),
            PriorityClass::System,
            "nvme",
            mapper,
            alloc,
            scheduler,
        )
    };
}

/// Boot-spawn the Ring 3 xHCI USB host controller driver image
/// (`/bin/nexacore-driver-xhci`, TASK-26, ADR-0048).
///
/// Mirrors [`boot_load_nvme_image`] exactly: PCI scan, BAR0 MMIO region
/// (64 KiB), DMA window (8 pages = 32 KiB), PCI BDF, device-info deposit.
///
/// The DMA window is at the same `DRIVER_DMA_VA_BASE` base (`0x0000_0100_0000_0000`)
/// as the NVMe driver; the xHCI image maps all 8 pages individually.
///
/// Additive and best-effort: if no xHCI controller is present, or if
/// `/bin/nexacore-driver-xhci` is absent from the initramfs, the boot continues.
///
/// # Safety
///
/// Single-CPU boot path; the kernel singletons are not aliased.
#[cfg(target_arch = "x86_64")]
pub unsafe fn boot_load_xhci_image<const N: usize>(
    elf_bytes: &[u8],
    input_channel_id: u64,
    fb_width: u32,
    fb_height: u32,
    mapper: &mut crate::bare_metal::paging::PageMapper,
    alloc: &mut crate::memory::BitmapFrameAllocator<N>,
    scheduler: &mut crate::scheduling::RoundRobinScheduler,
) {
    // xHCI MMIO window — 64 KiB covers all four register spaces
    // (capability, operational, runtime, doorbell) for any real xHCI
    // controller (ADR-0048 D2).
    const XHCI_MMIO_LEN: u64 = 0x1_0000;
    // DMA arena: 10 pages (40 KiB) at the kernel driver-DMA window base.
    // One DmaMap per page (contiguous-frame guarantee, ADR-0036 appendix 2).
    // Pages 0-7: controller structures + storage (ADR-0048/0049); pages 8-9:
    // HID interrupt-IN transfer rings + report buffers (WS7-06).
    const XHCI_DMA_IOVA_BASE: u64 = 0x0000_0100_0000_0000;
    const XHCI_DMA_LEN: u64 = 0xA000;

    // SAFETY: Ring 0 boot path; config-space reads have no side effects.
    let scan = unsafe { pci_scan::scan_all_buses() };
    let Some(xhci) = scan.find_by_class(pci_scan::XHCI_CLASS_CODE, pci_scan::XHCI_SUBCLASS) else {
        early_console::write_str("[driver-loader] xhci: controller not found — skipping spawn\n");
        return;
    };
    let bar0_phys = xhci.bar0_phys();
    if bar0_phys == 0 || pci_scan::PciDevice::bar_is_io(xhci.bar0) {
        early_console::write_str("[driver-loader] xhci: BAR0 not MMIO — skipping spawn\n");
        return;
    }

    let mut caps = DriverCapabilities::default();
    caps.mmio_regions.push(Resource::MmioRegion {
        phys_base: bar0_phys,
        len: XHCI_MMIO_LEN,
    });
    caps.dma_windows.push(Resource::DmaWindow {
        iova_base: XHCI_DMA_IOVA_BASE,
        len: XHCI_DMA_LEN,
    });
    caps.pci_devices.push(Resource::PciDevice {
        segment: 0,
        bus: xhci.bus,
        device: xhci.device,
        function: xhci.function,
    });

    early_console::write_str("[driver-loader] xhci MMIO scope phys=");
    #[allow(
        clippy::cast_possible_truncation,
        reason = "splitting a u64 into two u32 halves for hex display; each half is exact"
    )]
    {
        write_hex_u32((bar0_phys >> 32) as u32);
        write_hex_u32(bar0_phys as u32);
    }
    early_console::write_str(" len=10000 dma=hi+32KiB\n");

    // Deposit the BAR phys in the device-info section so the image can call
    // `nexacore_driver_shared::device_info::read()` to discover it at run-time
    // (xHCI BAR0 can be a 64-bit PCIe BAR above 4 GiB; the image cannot
    // read PCI config space directly from Ring 3).
    //
    // The three spare fields ride the WS7-06 HID contract (OVERLOADED, like
    // the ADR-0040 display deposit):
    //
    // | Field           | Overloaded meaning                              |
    // |-----------------|--------------------------------------------------|
    // | `common_offset` | framebuffer width (px; 0 = no framebuffer)       |
    // | `notify_offset` | framebuffer height (px; 0 = no framebuffer)     |
    // | `isr_offset`    | display input channel id (0 = channel absent)   |
    //
    // With them the HID class driver scales absolute tablet coordinates to
    // the screen and `IpcSend`s `DisplayInputEvent`s without any extra
    // syscall surface.
    #[allow(
        clippy::cast_possible_truncation,
        reason = "XHCI_MMIO_LEN = 0x10000 fits u32; channel ids are small \
                  monotonic integers (guarded below)"
    )]
    let xhci_info = cap_deposit::VirtioDeviceInfo {
        bar_phys: bar0_phys,
        mmio_len: XHCI_MMIO_LEN as u32,
        common_offset: fb_width,
        notify_offset: fb_height,
        isr_offset: u32::try_from(input_channel_id).unwrap_or(0),
        device_offset: 0,
        notify_off_multiplier: 0,
    };

    // SAFETY: single-CPU boot path; the kernel singletons are not aliased.
    let _ = unsafe {
        spawn_driver_and_deposit(
            elf_bytes,
            &caps,
            Some(xhci_info),
            PriorityClass::System,
            "xhci",
            mapper,
            alloc,
            scheduler,
        )
    };
}

/// Boot-spawn a Ring 3 BLK-service CLIENT (e.g. `/bin/nexacore-blkcheck`,
/// TASK-14, or `/bin/nexacore-fsd`, TASK-15) and deposit a single `IpcSend`
/// capability token (ADR-0036 D6/D7, ADR-0037 D1).
///
/// Unlike a hardware driver such a task owns no device: it presents the
/// deposited `IpcSend` token to pass the capability-gated `BlkLookup`
/// for the block channel the NVMe driver registered. No MMIO/DMA/IRQ/PCI
/// scopes — so the IOMMU bind in [`spawn_driver_and_deposit`] is the
/// idempotent domain-install no-op for a PCI-less task. `label` names
/// the task in the boot log; `priority` is the scheduler class.
///
/// Additive + best-effort: a missing image logs and boot continues.
///
/// # Safety
///
/// Single-CPU boot path; the kernel singletons are not aliased.
#[cfg(target_arch = "x86_64")]
pub unsafe fn boot_load_blk_client_image<const N: usize>(
    elf_bytes: &[u8],
    label: &str,
    priority: PriorityClass,
    mapper: &mut crate::bare_metal::paging::PageMapper,
    alloc: &mut crate::memory::BitmapFrameAllocator<N>,
    scheduler: &mut crate::scheduling::RoundRobinScheduler,
) {
    let mut caps = DriverCapabilities::default();
    // Resource value is informational: the `BlkLookup` gate checks
    // action == IpcSend + per-boot issuer + validity, not the channel
    // id (ADR-0036 D6). A sentinel channel id is sufficient.
    caps.ipc_send_channels.push(Resource::IpcChannel(0));

    early_console::write_str("[driver-loader] ");
    early_console::write_str(label);
    early_console::write_str(": depositing IpcSend cap\n");

    // SAFETY: single-CPU boot path; the kernel singletons are not aliased.
    let _ = unsafe {
        spawn_driver_and_deposit(
            elf_bytes, &caps, None, priority, label, mapper, alloc, scheduler,
        )
    };
}

/// Spawn the Ring 3 display probe image and deposit its capability tokens
/// (TASK-18, ADR-0040 D5, `display-probe` feature).
///
/// Deposits two capabilities:
///
/// 1. `(Action::DisplayMap, Resource::Framebuffer { phys_base, len })` —
///    scoped to the entire GOP framebuffer. The probe can request any
///    page-aligned sub-window via `DisplayMap (79)`.
/// 2. `(Action::IpcSend, Resource::IpcChannel(input_channel_id))` —
///    the kernel-owned display input channel id, deposited so the probe
///    can call `IpcTryReceive (24)` to drain keyboard events.
///
/// The [`cap_deposit::VirtioDeviceInfo`] section carries display parameters
/// with the OVERLOADED interpretation (ADR-0040 shared contract):
///
/// | Field                   | Overloaded meaning          |
/// |-------------------------|-----------------------------|
/// | `bar_phys`              | input channel id (u64)      |
/// | `common_offset`         | framebuffer width (px)      |
/// | `notify_offset`         | framebuffer height (px)     |
/// | `isr_offset`            | framebuffer stride (px/row) |
/// | `device_offset`         | bytes per pixel             |
/// | `mmio_len`              | framebuffer total byte len  |
/// | `notify_off_multiplier` | unused / 0                  |
///
/// Best-effort: any spawn or deposit failure is logged to COM1 and the
/// boot continues (the probe simply never appears).
///
/// # Safety
///
/// Ring 0, single-CPU boot path. `fb_info`, `mapper`, `alloc`, and
/// `scheduler` must be the live kernel singletons. The invariant is
/// identical to [`boot_load_blk_client_image`].
#[cfg(target_arch = "x86_64")]
pub unsafe fn boot_load_display_probe_image<const N: usize>(
    elf_bytes: &[u8],
    fb_info: &crate::bare_metal::graphics::FramebufferInfo,
    input_channel_id: crate::ipc::ChannelId,
    mapper: &mut crate::bare_metal::paging::PageMapper,
    alloc: &mut crate::memory::BitmapFrameAllocator<N>,
    scheduler: &mut crate::scheduling::RoundRobinScheduler,
) {
    let mut caps = DriverCapabilities::default();

    // DisplayMap capability: the whole framebuffer.
    caps.framebuffer_regions.push(Resource::Framebuffer {
        phys_base: fb_info.phys_base,
        len: fb_info.len,
    });

    // IpcSend capability: the display input channel.
    caps.ipc_send_channels
        .push(Resource::IpcChannel(input_channel_id.0));

    // Overloaded VirtioDeviceInfo: pass display geometry + input channel id
    // (ADR-0040 shared contract). `notify_off_multiplier` is unused.
    #[allow(
        clippy::cast_possible_truncation,
        reason = "fb.len fits u32 for any real framebuffer (≤ 4 GiB); \
                  fb.stride/width/height/bpp are all u32 already"
    )]
    let device_info = cap_deposit::VirtioDeviceInfo {
        bar_phys: input_channel_id.0,
        common_offset: fb_info.width,
        notify_offset: fb_info.height,
        isr_offset: fb_info.stride,
        device_offset: fb_info.bpp,
        mmio_len: fb_info.len as u32,
        notify_off_multiplier: 0,
    };

    early_console::write_str("[driver-loader] display-probe: depositing DisplayMap+IpcSend caps\n");

    // SAFETY: single-CPU boot path; the kernel singletons are not aliased.
    let _ = unsafe {
        spawn_driver_and_deposit(
            elf_bytes,
            &caps,
            Some(device_info),
            PriorityClass::System,
            "display-probe",
            mapper,
            alloc,
            scheduler,
        )
    };
}

/// Return the 64-bit physical base of BAR index `idx` (0..=5) for `dev`,
/// handling the 32/64-bit BAR0 and BAR4 pairs the scanner records. Other
/// indices fall back to 0 (the scanner only captures bar0/1/4/5).
#[cfg(target_arch = "x86_64")]
fn bar_phys_for_index(dev: &pci_scan::PciDevice, idx: u8) -> u64 {
    match idx {
        0 => dev.bar0_phys(),
        4 => dev.bar4_phys(),
        _ => 0,
    }
}

// =========================================================================
// Boot-time MSI-X device registration (WS1-06, TASK-14/ADR-0036 follow-up)
// =========================================================================
//
// `msix::program_vector` (driven by the `IrqAttach (72)` handler) can only
// program a device whose MSI-X geometry was recorded at boot via
// `msix::register` — and until WS1-06 nothing called it, so every attach
// fell back to the cooperative-polling path. The boot probe now walks the
// capability list of each first-party device, maps its MSI-X table BAR
// pages into a fixed kernel VA, and registers the geometry under the
// project-wide IRQ-line convention below.

/// IRQ-line identifiers shared between the boot registration and the
/// Ring 3 drivers' `IrqAttach` calls. The two sides MUST agree — the
/// kernel matches `IrqAttach(irq_line)` against this registration key.
/// Convention (one line per first-party device):
/// 33 = virtio-net (`Resource::IrqLine(33)` granted in
/// [`boot_load_virtio_net_image`]), 34 = NVMe IO CQ (msix module docs,
/// NCIP-Driver-NVMe-014 § S5), 35 = e1000e RX/TX combined vector
/// (`IRQ_LINE_E1000E` in `nexacore-driver-e1000e-image`).
#[cfg_attr(
    not(target_os = "none"),
    allow(
        dead_code,
        reason = "live consumers are the cfg(none)-gated boot call sites; host builds keep the consts for the convention-pinning tests"
    )
)]
const MSIX_IRQ_LINE_VIRTIO_NET: u16 = 33;
/// See [`MSIX_IRQ_LINE_VIRTIO_NET`].
#[cfg_attr(
    not(target_os = "none"),
    allow(dead_code, reason = "see MSIX_IRQ_LINE_VIRTIO_NET")
)]
const MSIX_IRQ_LINE_NVME: u16 = 34;
/// See [`MSIX_IRQ_LINE_VIRTIO_NET`].
#[cfg_attr(
    not(target_os = "none"),
    allow(dead_code, reason = "see MSIX_IRQ_LINE_VIRTIO_NET")
)]
const MSIX_IRQ_LINE_E1000E: u16 = 35;

/// Fixed kernel VAs the boot probe maps each device's MSI-X table at
/// (2 pages per device). Chosen in the same `0xFFFF_F000_00xx_xxxx`
/// kernel-MMIO window as the BAR0 mappings (NVMe CSRs at `_0000_0000`,
/// e1000e CSRs at `_0010_0000`) without overlapping them.
#[cfg(target_arch = "x86_64")]
#[cfg_attr(
    not(target_os = "none"),
    allow(dead_code, reason = "see MSIX_IRQ_LINE_VIRTIO_NET")
)]
const MSIX_TABLE_VA_VIRTIO_NET: u64 = 0xFFFF_F000_0020_0000;
/// See [`MSIX_TABLE_VA_VIRTIO_NET`].
#[cfg(target_arch = "x86_64")]
#[cfg_attr(
    not(target_os = "none"),
    allow(dead_code, reason = "see MSIX_IRQ_LINE_VIRTIO_NET")
)]
const MSIX_TABLE_VA_NVME: u64 = 0xFFFF_F000_0021_0000;
/// See [`MSIX_TABLE_VA_VIRTIO_NET`].
#[cfg(target_arch = "x86_64")]
#[cfg_attr(
    not(target_os = "none"),
    allow(dead_code, reason = "see MSIX_IRQ_LINE_VIRTIO_NET")
)]
const MSIX_TABLE_VA_E1000E: u64 = 0xFFFF_F000_0022_0000;

/// Read the physical base of BAR `bir` straight from PCI config space,
/// handling 32/64-bit memory BARs. Returns `0` for I/O BARs, an
/// out-of-range index, or a 64-bit BAR claimed at index 5 (no high
/// dword exists).
///
/// Unlike [`bar_phys_for_index`] this is not limited to the BAR0/BAR4
/// values cached in [`pci_scan::PciDevice`] — the MSI-X Table BIR can
/// name any of the six BARs (QEMU: NVMe → BAR4, e1000e → BAR3,
/// virtio-net → BAR1).
///
/// # Safety
///
/// Ring-0 PCI config reads (side-effect-free).
#[cfg(all(target_arch = "x86_64", target_os = "none", not(test)))]
unsafe fn read_bar_phys(bus: u8, dev: u8, func: u8, bir: u8) -> u64 {
    use super::arch;
    if bir > 5 {
        return 0;
    }
    let off = 0x10 + bir * 4;
    // SAFETY: side-effect-free config read per the function contract.
    let low = unsafe { arch::pci_cfg_read32(bus, dev, func, off) };
    if pci_scan::PciDevice::bar_is_io(low) {
        return 0;
    }
    if pci_scan::PciDevice::bar_is_64bit(low) {
        if bir == 5 {
            return 0;
        }
        // SAFETY: same as above; `off + 4 ≤ 0x28` stays in the header.
        let high = unsafe { arch::pci_cfg_read32(bus, dev, func, off + 4) };
        pci_scan::PciDevice::bar64(low, high)
    } else {
        pci_scan::PciDevice::bar_mmio_base(low)
    }
}

/// Locate `dev`'s MSI-X capability, map its table BAR pages at
/// `table_va_base`, and record the geometry via [`msix::register`] so a
/// later `IrqAttach(irq_line)` can program the table (WS1-06).
///
/// Best-effort by design (mirrors `program_vector`'s contract): a device
/// without the capability, with an unreadable BAR, or a failed mapping
/// logs the outcome and returns — the driver's cooperative polling path
/// keeps liveness, never silently.
///
/// Maps **2 pages** from the table's page base: entry 0 (16 bytes) is all
/// Phase 1 programs, and the second page guards a table offset landing
/// near a page boundary.
///
/// # Safety
///
/// Single-CPU boot path; `mapper`/`alloc` are the live kernel singletons;
/// the mapped VA window `[table_va_base, +2 pages)` must be reserved for
/// this device's table for the lifetime of the kernel.
#[cfg(all(target_arch = "x86_64", target_os = "none", not(test)))]
unsafe fn register_msix_for_device<const N: usize>(
    dev: &pci_scan::PciDevice,
    irq_line: u16,
    label: &str,
    table_va_base: u64,
    mapper: &mut crate::bare_metal::paging::PageMapper,
    alloc: &mut crate::memory::BitmapFrameAllocator<N>,
) {
    use crate::{
        bare_metal::{
            msix,
            paging::{PTE_NO_EXEC, PTE_WRITABLE},
        },
        memory::{PhysAddr, VirtAddr},
    };

    // PCD (bit 4) + PWT (bit 3) → uncacheable MMIO (same flags as the
    // BAR0 bring-up mappings).
    const PTE_PCD: u64 = 1 << 4;
    const PTE_PWT: u64 = 1 << 3;

    // SAFETY: side-effect-free config reads (function contract).
    let Some((cap_off, bir, table_off)) =
        (unsafe { msix::find_msix_cap(dev.bus, dev.device, dev.function) })
    else {
        early_console::write_str("[msix] ");
        early_console::write_str(label);
        early_console::write_str(": no MSI-X capability — polling fallback stays\n");
        return;
    };

    // SAFETY: side-effect-free config reads.
    let bar_phys = unsafe { read_bar_phys(dev.bus, dev.device, dev.function, bir) };
    if bar_phys == 0 {
        early_console::write_str("[msix] ");
        early_console::write_str(label);
        early_console::write_str(": table BAR unreadable — skipped\n");
        return;
    }

    // Map 2 uncacheable pages covering the table start.
    let mmio_flags = PTE_WRITABLE | PTE_NO_EXEC | PTE_PCD | PTE_PWT;
    let table_phys = bar_phys + u64::from(table_off);
    let page_base = table_phys & !0xFFF;
    for i in 0..2u64 {
        let virt = VirtAddr(table_va_base + i * 0x1000);
        let phys = PhysAddr(page_base + i * 0x1000);
        if !mapper.map_4k(virt, phys, mmio_flags, alloc) {
            early_console::write_str("[msix] ");
            early_console::write_str(label);
            early_console::write_str(": table page map failed — skipped\n");
            return;
        }
        // SAFETY: newly mapped kernel VA; invlpg is always safe on a VA.
        unsafe { crate::bare_metal::arch::invlpg(virt.0) };
    }
    let table_va = table_va_base + (table_phys & 0xFFF);

    // SAFETY: single-CPU boot; the table VA mapped above stays mapped for
    // the kernel's lifetime (fixed VA, never unmapped).
    let ok = unsafe {
        msix::register(
            irq_line,
            dev.bus,
            dev.device,
            dev.function,
            cap_off,
            table_va,
        )
    };
    early_console::write_str("[msix] ");
    early_console::write_str(label);
    if ok {
        early_console::write_str(" registered line=");
        early_console::write_usize(usize::from(irq_line));
        early_console::write_str(" bir=");
        write_hex_u8(bir);
        early_console::write_str(" off=");
        write_hex_u32(table_off);
        early_console::write_str("\n");
    } else {
        early_console::write_str(": registration table full — skipped\n");
    }
}

#[cfg(target_arch = "x86_64")]
unsafe fn boot_load_with_bar<const N: usize>(
    bar_phys: u64,
    irq_line: u16,
    mapper: &mut crate::bare_metal::paging::PageMapper,
    alloc: &mut crate::memory::BitmapFrameAllocator<N>,
    scheduler: &mut crate::scheduling::RoundRobinScheduler,
) {
    // Construct DriverCapabilities matching the probe ELF's expectations.
    // The MmioMap scope covers the BAR address so the syscall scope
    // check passes. The DmaMap and IrqAttach scopes are wide enough
    // for the probe's hardcoded parameters.
    let mut caps = DriverCapabilities::default();
    caps.mmio_regions.push(Resource::MmioRegion {
        phys_base: bar_phys,
        len: 0x1000,
    });
    caps.dma_windows.push(Resource::DmaWindow {
        iova_base: 0,
        len: 0x1_0000_0000,
    });
    caps.irq_lines.push(Resource::IrqLine(irq_line));

    // SAFETY: single-CPU boot path; the kernel singletons are not aliased.
    let _ = unsafe {
        spawn_driver_and_deposit(
            DRIVER_PROBE_ELF,
            &caps,
            None, // probe ELF does no virtio MMIO — no device-info section
            PriorityClass::Interactive,
            "probe",
            mapper,
            alloc,
            scheduler,
        )
    };

    early_console::write_str("[driver-loader] probe enqueued — will dispatch on next tick\n");
}

// =========================================================================
// TASK-004: virtio-net legacy I/O port bring-up (P6.7.9-pre.10)
// =========================================================================
//
// The virtio 1.0 § 4.1 legacy interface uses I/O ports via BAR0.
// Register offsets (transitional device, 1AF4:1000):
//
//   0x00  Device Features    (4 bytes, R)
//   0x04  Driver Features    (4 bytes, R/W)
//   0x08  Queue Address      (4 bytes, R/W)
//   0x0C  Queue Size         (2 bytes, R)
//   0x0E  Queue Select       (2 bytes, R/W)
//   0x10  Queue Notify       (2 bytes, R/W)
//   0x12  Device Status      (1 byte,  R/W)
//   0x13  ISR Status         (1 byte,  R)
//   0x14  MAC Address        (6 bytes, R)

const VIRTIO_IO_OFF_DEVICE_FEATURES: u16 = 0x00;
const VIRTIO_IO_OFF_DEVICE_STATUS: u16 = 0x12;
const VIRTIO_IO_OFF_MAC: u16 = 0x14;

const VIRTIO_STATUS_ACKNOWLEDGE: u8 = 0x01;
const VIRTIO_STATUS_DRIVER: u8 = 0x02;
const VIRTIO_STATUS_FEATURES_OK: u8 = 0x08;
const VIRTIO_STATUS_DRIVER_OK: u8 = 0x04;

/// Perform the live virtio-net bring-up sequence via legacy I/O ports.
///
/// # NOT the datapath (ADR-0024)
///
/// This in-kernel bring-up is **diagnostics + PCI enable only**. The M0
/// NIC datapath is the Ring 3 driver image
/// (`/bin/nexacore-driver-net-virtio`), which resets and re-initialises the
/// device through its modern-MMIO capability mappings right after this
/// runs, owns the virtqueues, and is the sole registrant of `virtio0`
/// (`NetRegister (100)`). The load-bearing effects here are the PCI
/// command-register enable (IOSE+MSE+BME — the Ring 3 driver has no
/// PCI-config capability) and the boot-log dumps; the legacy status
/// dance below is superseded and is slated for removal when NCIP-026
/// WI-7 re-homes bus-master gating to IOMMU domain attach (TASK-07).
///
/// # Safety
///
/// Ring 0 only. `io_base` must be the decoded I/O port base from BAR0.
#[cfg(target_arch = "x86_64")]
unsafe fn virtio_net_live_bringup(io_base: u16) {
    use super::arch;

    // Step 1: Reset — write 0 to device_status.
    unsafe { arch::outb(io_base + VIRTIO_IO_OFF_DEVICE_STATUS, 0) };
    let status = unsafe { arch::inb(io_base + VIRTIO_IO_OFF_DEVICE_STATUS) };
    early_console::write_str("[virtio-net] RESET  status=");
    write_hex_u8(status);
    early_console::write_str(if status == 0 { " OK\n" } else { " FAIL\n" });

    // Step 2: Acknowledge — set ACKNOWLEDGE bit.
    unsafe {
        arch::outb(
            io_base + VIRTIO_IO_OFF_DEVICE_STATUS,
            VIRTIO_STATUS_ACKNOWLEDGE,
        );
    };
    let status = unsafe { arch::inb(io_base + VIRTIO_IO_OFF_DEVICE_STATUS) };
    early_console::write_str("[virtio-net] ACK    status=");
    write_hex_u8(status);
    early_console::write_str("\n");

    // Step 3: Driver — set DRIVER bit.
    unsafe {
        arch::outb(
            io_base + VIRTIO_IO_OFF_DEVICE_STATUS,
            VIRTIO_STATUS_ACKNOWLEDGE | VIRTIO_STATUS_DRIVER,
        );
    };
    let status = unsafe { arch::inb(io_base + VIRTIO_IO_OFF_DEVICE_STATUS) };
    early_console::write_str("[virtio-net] DRIVER status=");
    write_hex_u8(status);
    early_console::write_str("\n");

    // Step 4: Read device features (first 32 bits).
    let features = unsafe { arch::inl(io_base + VIRTIO_IO_OFF_DEVICE_FEATURES) };
    early_console::write_str("[virtio-net] features=");
    write_hex_u32(features);
    early_console::write_str("\n");

    // Step 5: Write driver features (accept all device-offered).
    unsafe {
        arch::outl(io_base + 0x04, features);
    };

    // Step 6: Set FEATURES_OK.
    unsafe {
        arch::outb(
            io_base + VIRTIO_IO_OFF_DEVICE_STATUS,
            VIRTIO_STATUS_ACKNOWLEDGE | VIRTIO_STATUS_DRIVER | VIRTIO_STATUS_FEATURES_OK,
        );
    };
    let status = unsafe { arch::inb(io_base + VIRTIO_IO_OFF_DEVICE_STATUS) };
    early_console::write_str("[virtio-net] FEAT   status=");
    write_hex_u8(status);
    let features_accepted = (status & VIRTIO_STATUS_FEATURES_OK) != 0;
    early_console::write_str(if features_accepted {
        " features_ok=yes\n"
    } else {
        " features_ok=NO\n"
    });

    if !features_accepted {
        early_console::write_str("[virtio-net] device rejected features — aborting\n");
        return;
    }

    // Step 7: Read MAC address (6 bytes at offset 0x14).
    early_console::write_str("[virtio-net] MAC=");
    for i in 0u16..6 {
        if i > 0 {
            early_console::write_str(":");
        }
        let byte = unsafe { arch::inb(io_base + VIRTIO_IO_OFF_MAC + i) };
        write_hex_u8(byte);
    }
    early_console::write_str("\n");

    // Step 8: Set DRIVER_OK — device is live.
    unsafe {
        arch::outb(
            io_base + VIRTIO_IO_OFF_DEVICE_STATUS,
            VIRTIO_STATUS_ACKNOWLEDGE
                | VIRTIO_STATUS_DRIVER
                | VIRTIO_STATUS_FEATURES_OK
                | VIRTIO_STATUS_DRIVER_OK,
        );
    };
    let status = unsafe { arch::inb(io_base + VIRTIO_IO_OFF_DEVICE_STATUS) };
    early_console::write_str("[virtio-net] READY  status=");
    write_hex_u8(status);
    let driver_ok = (status & VIRTIO_STATUS_DRIVER_OK) != 0;
    early_console::write_str(if driver_ok {
        " driver_ok=yes\n"
    } else {
        " driver_ok=NO\n"
    });

    early_console::write_str("[virtio-net] live bring-up complete\n");
}

// =========================================================================
// TASK-005: NVMe live MMIO bring-up (P6.7.9-pre.11)
// =========================================================================
//
// NVMe 1.4 controller registers at BAR0 offset:
//
//   0x00  CAP    (8 bytes, R)   — Controller Capabilities
//   0x08  VS     (4 bytes, R)   — Version
//   0x0C  INTMS  (4 bytes, R/W) — Interrupt Mask Set
//   0x10  INTMC  (4 bytes, R/W) — Interrupt Mask Clear
//   0x14  CC     (4 bytes, R/W) — Controller Configuration
//   0x1C  CSTS   (4 bytes, R)   — Controller Status
//   0x24  AQA    (4 bytes, R/W) — Admin Queue Attributes
//   0x28  ASQ    (8 bytes, R/W) — Admin Submission Queue Base
//   0x30  ACQ    (8 bytes, R/W) — Admin Completion Queue Base

const NVME_REG_CAP: usize = 0x00;
const NVME_REG_VS: usize = 0x08;
const NVME_REG_CC: usize = 0x14;
const NVME_REG_CSTS: usize = 0x1C;

/// Perform live NVMe controller identification via MMIO.
///
/// Maps BAR0 pages into the kernel page tables (PCD+PWT uncacheable)
/// then performs the NVMe 1.4 enable sequence.
///
/// # Safety
///
/// Ring 0 only. `bar0_phys` must be the decoded MMIO base from BAR0.
// justification: NVMe bring-up sequence (disable, configure CC, wait for
// CSTS.RDY) is a linear protocol; splitting hides the hardware state machine.
#[allow(clippy::too_many_lines)]
// justification: u64→u32/usize casts used for MMIO debug output only; on
// x86_64 (the only target) usize == u64 and the u32 casts intentionally
// print the low/high halves of 64-bit addresses for human readability.
#[allow(clippy::cast_possible_truncation)]
#[cfg(target_arch = "x86_64")]
unsafe fn nvme_live_bringup<const N: usize>(
    bar0_phys: u64,
    mapper: &mut crate::bare_metal::paging::PageMapper,
    alloc: &mut crate::memory::BitmapFrameAllocator<N>,
) {
    use crate::{
        bare_metal::paging::{PTE_NO_EXEC, PTE_WRITABLE},
        memory::{PhysAddr, VirtAddr},
    };

    // NVMe BAR0 is 16 KiB (4 pages). Map into a fixed kernel VA range.
    // Pick a VA in the upper-half kernel space that's unlikely to collide.
    const NVME_MMIO_VA_BASE: u64 = 0xFFFF_F000_0000_0000;
    const NVME_BAR_PAGES: u64 = 4;
    // PCD (bit 4) + PWT (bit 3) → uncacheable MMIO.
    const PTE_PCD: u64 = 1 << 4;
    const PTE_PWT: u64 = 1 << 3;
    let mmio_flags = PTE_WRITABLE | PTE_NO_EXEC | PTE_PCD | PTE_PWT;

    let bar_page_base = bar0_phys & !0xFFF;
    for i in 0..NVME_BAR_PAGES {
        let virt = VirtAddr(NVME_MMIO_VA_BASE + i * 0x1000);
        let phys = PhysAddr(bar_page_base + i * 0x1000);
        if !mapper.map_4k(virt, phys, mmio_flags, alloc) {
            early_console::write_str("[nvme] failed to map BAR page ");
            early_console::write_usize(i as usize);
            early_console::write_str(" — aborting\n");
            return;
        }
        unsafe { crate::bare_metal::arch::invlpg(virt.0) };
    }

    let mmio_offset = bar0_phys & 0xFFF;
    let mmio_va = NVME_MMIO_VA_BASE + mmio_offset;
    early_console::write_str("[nvme] mapped ");
    early_console::write_usize(NVME_BAR_PAGES as usize);
    early_console::write_str(" pages at VA=");
    write_hex_u32((mmio_va >> 32) as u32);
    write_hex_u32(mmio_va as u32);
    early_console::write_str("\n");

    let base = mmio_va as *const u32;

    // Read CAP register (64-bit, two 32-bit halves).
    let cap_lo = unsafe { core::ptr::read_volatile(base.byte_add(NVME_REG_CAP)) };
    let cap_hi = unsafe { core::ptr::read_volatile(base.byte_add(NVME_REG_CAP + 4)) };
    early_console::write_str("[nvme] CAP=");
    write_hex_u32(cap_hi);
    write_hex_u32(cap_lo);

    // CAP.MQES = bits 15:0 (Maximum Queue Entries Supported, 0-based).
    let mqes = (cap_lo & 0xFFFF) + 1;
    early_console::write_str(" MQES=");
    early_console::write_usize(mqes as usize);

    // CAP.TO = bits 31:24 (Timeout in 500ms units).
    let timeout_500ms = (cap_lo >> 24) & 0xFF;
    early_console::write_str(" TO=");
    early_console::write_usize(timeout_500ms as usize);
    early_console::write_str("\n");

    // Read VS register (NVMe version).
    let vs = unsafe { core::ptr::read_volatile(base.byte_add(NVME_REG_VS)) };
    let major = (vs >> 16) & 0xFFFF;
    let minor = (vs >> 8) & 0xFF;
    let tertiary = vs & 0xFF;
    early_console::write_str("[nvme] VS=");
    early_console::write_usize(major as usize);
    early_console::write_str(".");
    early_console::write_usize(minor as usize);
    early_console::write_str(".");
    early_console::write_usize(tertiary as usize);
    early_console::write_str("\n");

    // Read CSTS (Controller Status).
    let csts = unsafe { core::ptr::read_volatile(base.byte_add(NVME_REG_CSTS)) };
    let rdy = (csts & 1) != 0;
    let cfs = (csts & 2) != 0;
    early_console::write_str("[nvme] CSTS=");
    write_hex_u32(csts);
    early_console::write_str(if rdy { " RDY=yes" } else { " RDY=no" });
    early_console::write_str(if cfs { " CFS=FATAL\n" } else { " CFS=ok\n" });

    // Read CC (Controller Configuration).
    let cc = unsafe { core::ptr::read_volatile(base.byte_add(NVME_REG_CC)) };
    let en = (cc & 1) != 0;
    early_console::write_str("[nvme] CC=");
    write_hex_u32(cc);
    early_console::write_str(if en { " EN=yes" } else { " EN=no" });
    early_console::write_str("\n");

    // READ-ONLY probe (TASK-14, ADR-0036): controller bring-up ownership
    // moved entirely to the Ring 3 `nexacore-driver-nvme` driver, which does
    // its own disable → reprogram (AQA/ASQ/ACQ to ITS OWN DMA frames) →
    // enable. The probe MUST NOT enable the controller here: doing so
    // would point the admin queues at kernel frames that the bitmap
    // allocator later hands to other tasks, and would double-bring-up the
    // device. We only read + log CAP/VS/CC/CSTS for boot diagnostics; the
    // driver disables whatever state we observed before it reprograms.
    early_console::write_str("[nvme] probe is read-only — Ring 3 driver owns bring-up\n");
}

// =========================================================================
// TASK-006: e1000e live bring-up (P6.7.9.c)
// =========================================================================

/// e1000e CSR register offsets (Intel 82574L datasheet § 10).
const E1000E_REG_CTRL: usize = 0x0000;
const E1000E_REG_IMC: usize = 0x00D8;
const E1000E_REG_IMS: usize = 0x00D0;
const E1000E_REG_RAL0: usize = 0x5400;
const E1000E_REG_RAH0: usize = 0x5404;
const E1000E_REG_MDIC: usize = 0x0020;
const E1000E_REG_RCTL: usize = 0x0100;
const E1000E_REG_TCTL: usize = 0x0400;
const E1000E_REG_RDBAL: usize = 0x2800;
const E1000E_REG_RDBAH: usize = 0x2804;
const E1000E_REG_RDLEN: usize = 0x2808;
const E1000E_REG_RDH: usize = 0x2810;
const E1000E_REG_RDT: usize = 0x2818;
const E1000E_REG_TDBAL: usize = 0x3800;
const E1000E_REG_TDBAH: usize = 0x3804;
const E1000E_REG_TDLEN: usize = 0x3808;
const E1000E_REG_TDH: usize = 0x3810;
const E1000E_REG_TDT: usize = 0x3818;

/// Fixed kernel VA the e1000e BAR0 (128-KiB CSR window) is mapped at by
/// [`e1000e_live_bringup`]. Module-level so the §S9.1 negative-test
/// harness (ADR-0029) can poke the TX tail after the `GCMD.TE` flip.
/// QEMU assigns a page-aligned BAR0 (offset 0), so the CSR base equals
/// this VA.
#[cfg(target_arch = "x86_64")]
const E1000E_MMIO_VA_BASE: u64 = 0xFFFF_F000_0010_0000;

/// `CTRL.RST` — bit 26.
const E1000E_CTRL_RST: u32 = 1 << 26;
/// `RAH[0].AV` — bit 31.
const E1000E_RAH_AV: u32 = 1 << 31;
/// MDIC Ready bit — bit 28.
const E1000E_MDIC_READY: u32 = 1 << 28;
/// MDIC Read opcode — bits 27:26 = 0b10.
const E1000E_MDIC_OP_READ: u32 = 0b10 << 26;
/// IMS enabled mask: RXT0 (bit 7) | TXDW (bit 0) | LSC (bit 2).
const E1000E_IMS_ENABLED: u32 = (1 << 7) | (1 << 0) | (1 << 2);

/// Perform the live e1000e bring-up sequence via MMIO BAR0.
///
/// Maps 32 pages (128 KiB) of the e1000e CSR window into a fixed kernel VA,
/// then performs the 13-step bring-up per NCIP-Driver-Net-015 § S5.1.
///
/// # Safety
///
/// Caller must hold single-CPU invariant; `mapper` and `alloc` are
/// the live kernel singletons.
// justification: ral/rah are the Intel e1000e datasheet names for
// Receive Address Low/High registers; tdh/tdt and rdh/rdt are the
// Transmit/Receive Descriptor Head/Tail registers. All names are mandated
// by the 82574L specification and must not be renamed for auditability.
#[allow(clippy::similar_names)]
// justification: 13-step MMIO bring-up sequence cannot be meaningfully
// split without obscuring the hardware protocol ordering.
#[allow(clippy::too_many_lines)]
// justification: u64→u32/usize casts used for MMIO debug output only; on
// x86_64 (the only target) usize == u64 and the u32 casts intentionally
// print the low/high halves of 64-bit addresses for human readability.
#[allow(clippy::cast_possible_truncation)]
#[cfg(target_arch = "x86_64")]
unsafe fn e1000e_live_bringup<const N: usize>(
    bar0_phys: u64,
    mapper: &mut crate::bare_metal::paging::PageMapper,
    alloc: &mut crate::memory::BitmapFrameAllocator<N>,
) {
    use crate::{
        bare_metal::paging::{PTE_NO_EXEC, PTE_WRITABLE},
        memory::{PhysAddr, VirtAddr},
    };

    // e1000e BAR0 is 128 KiB (32 pages). Map into a fixed kernel VA range
    // (`E1000E_MMIO_VA_BASE`, module-level so the negtest harness can reuse it).
    const E1000E_BAR_PAGES: u64 = 32;
    const PTE_PCD: u64 = 1 << 4;
    const PTE_PWT: u64 = 1 << 3;
    let mmio_flags = PTE_WRITABLE | PTE_NO_EXEC | PTE_PCD | PTE_PWT;

    let bar_page_base = bar0_phys & !0xFFF;
    for i in 0..E1000E_BAR_PAGES {
        let virt = VirtAddr(E1000E_MMIO_VA_BASE + i * 0x1000);
        let phys = PhysAddr(bar_page_base + i * 0x1000);
        if !mapper.map_4k(virt, phys, mmio_flags, alloc) {
            early_console::write_str("[e1000e] failed to map BAR page ");
            early_console::write_usize(i as usize);
            early_console::write_str(" — aborting\n");
            return;
        }
        unsafe { crate::bare_metal::arch::invlpg(virt.0) };
    }

    let mmio_offset = bar0_phys & 0xFFF;
    let mmio_va = E1000E_MMIO_VA_BASE + mmio_offset;
    early_console::write_str("[e1000e] mapped ");
    early_console::write_usize(E1000E_BAR_PAGES as usize);
    early_console::write_str(" pages at VA=");
    write_hex_u32((mmio_va >> 32) as u32);
    write_hex_u32(mmio_va as u32);
    early_console::write_str("\n");

    let base = mmio_va as *const u32;

    // Step 1: Disable all interrupts (IMC = 0xFFFFFFFF).
    unsafe { core::ptr::write_volatile(base.byte_add(E1000E_REG_IMC).cast_mut(), 0xFFFF_FFFF) };
    early_console::write_str("[e1000e] IMC=FFFFFFFF — interrupts disabled\n");

    // Step 2: Global reset (set CTRL.RST, poll until cleared).
    let ctrl = unsafe { core::ptr::read_volatile(base.byte_add(E1000E_REG_CTRL)) };
    unsafe {
        core::ptr::write_volatile(
            base.byte_add(E1000E_REG_CTRL).cast_mut(),
            ctrl | E1000E_CTRL_RST,
        );
    };
    early_console::write_str("[e1000e] CTRL.RST set — polling...\n");

    let mut polls: u32 = 0;
    loop {
        let v = unsafe { core::ptr::read_volatile(base.byte_add(E1000E_REG_CTRL)) };
        if (v & E1000E_CTRL_RST) == 0 {
            break;
        }
        polls += 1;
        if polls > 100_000 {
            early_console::write_str("[e1000e] reset timeout — aborting\n");
            return;
        }
    }
    early_console::write_str("[e1000e] reset complete  polls=");
    early_console::write_usize(polls as usize);
    early_console::write_str("\n");

    // Post-reset: re-disable interrupts.
    unsafe { core::ptr::write_volatile(base.byte_add(E1000E_REG_IMC).cast_mut(), 0xFFFF_FFFF) };

    // Step 3: Read MAC address from RAL[0] / RAH[0].
    let ral = unsafe { core::ptr::read_volatile(base.byte_add(E1000E_REG_RAL0)) };
    let rah = unsafe { core::ptr::read_volatile(base.byte_add(E1000E_REG_RAH0)) };

    if (rah & E1000E_RAH_AV) == 0 {
        early_console::write_str("[e1000e] RAH.AV not set — MAC invalid, aborting\n");
        return;
    }

    early_console::write_str("[e1000e] MAC=");
    write_hex_u8((ral & 0xFF) as u8);
    early_console::write_str(":");
    write_hex_u8(((ral >> 8) & 0xFF) as u8);
    early_console::write_str(":");
    write_hex_u8(((ral >> 16) & 0xFF) as u8);
    early_console::write_str(":");
    write_hex_u8(((ral >> 24) & 0xFF) as u8);
    early_console::write_str(":");
    write_hex_u8((rah & 0xFF) as u8);
    early_console::write_str(":");
    write_hex_u8(((rah >> 8) & 0xFF) as u8);
    early_console::write_str("\n");

    // Store MAC for the Build Info panel renderer.
    E1000E_MAC[0].store((ral & 0xFF) as u8, Ordering::Relaxed);
    E1000E_MAC[1].store(((ral >> 8) & 0xFF) as u8, Ordering::Relaxed);
    E1000E_MAC[2].store(((ral >> 16) & 0xFF) as u8, Ordering::Relaxed);
    E1000E_MAC[3].store(((ral >> 24) & 0xFF) as u8, Ordering::Relaxed);
    E1000E_MAC[4].store((rah & 0xFF) as u8, Ordering::Relaxed);
    E1000E_MAC[5].store(((rah >> 8) & 0xFF) as u8, Ordering::Relaxed);

    // Step 4: PHY Init — issue MDIC read of MII_CTRL (register 0, PHY addr 1).
    // PHY addr=1 (bits 20:16), register=0 (MII_CTRL, bits 15:11 = 0).
    // The (0u32 << 16) term was removed — it contributes 0 to the OR.
    let mdic_read = E1000E_MDIC_OP_READ | (1u32 << 21);
    unsafe { core::ptr::write_volatile(base.byte_add(E1000E_REG_MDIC).cast_mut(), mdic_read) };

    polls = 0;
    let mut mdic_ok = false;
    loop {
        let v = unsafe { core::ptr::read_volatile(base.byte_add(E1000E_REG_MDIC)) };
        if (v & E1000E_MDIC_READY) != 0 {
            mdic_ok = true;
            break;
        }
        polls += 1;
        if polls > 10_000 {
            break;
        }
    }
    if mdic_ok {
        early_console::write_str("[e1000e] MDIC read OK  polls=");
        early_console::write_usize(polls as usize);
        early_console::write_str("\n");
    } else {
        early_console::write_str("[e1000e] MDIC timeout (non-fatal on QEMU)\n");
    }

    // Step 5: Setup RX ring (RDBAL/RDBAH/RDLEN/RDH/RDT = 0).
    unsafe {
        core::ptr::write_volatile(base.byte_add(E1000E_REG_RDBAL).cast_mut(), 0);
        core::ptr::write_volatile(base.byte_add(E1000E_REG_RDBAH).cast_mut(), 0);
        core::ptr::write_volatile(base.byte_add(E1000E_REG_RDLEN).cast_mut(), 256 * 16);
        core::ptr::write_volatile(base.byte_add(E1000E_REG_RDH).cast_mut(), 0);
        core::ptr::write_volatile(base.byte_add(E1000E_REG_RDT).cast_mut(), 0);
    };
    early_console::write_str("[e1000e] RX ring programmed  RDLEN=4096\n");

    // Step 6: Setup TX ring (TDBAL/TDBAH/TDLEN/TDH/TDT = 0).
    unsafe {
        core::ptr::write_volatile(base.byte_add(E1000E_REG_TDBAL).cast_mut(), 0);
        core::ptr::write_volatile(base.byte_add(E1000E_REG_TDBAH).cast_mut(), 0);
        core::ptr::write_volatile(base.byte_add(E1000E_REG_TDLEN).cast_mut(), 256 * 16);
        core::ptr::write_volatile(base.byte_add(E1000E_REG_TDH).cast_mut(), 0);
        core::ptr::write_volatile(base.byte_add(E1000E_REG_TDT).cast_mut(), 0);
    };
    early_console::write_str("[e1000e] TX ring programmed  TDLEN=4096\n");

    // Step 7: Configure RCTL (enable + broadcast accept + strip CRC).
    // RCTL: EN(bit1) | BAM(bit15) | SECRC(bit26), BSIZE=2KiB(00).
    let rctl: u32 = (1 << 1) | (1 << 15) | (1 << 26);
    unsafe { core::ptr::write_volatile(base.byte_add(E1000E_REG_RCTL).cast_mut(), rctl) };

    // Step 8: Configure TCTL (enable + pad short + CT=0x0F + COLD=0x40).
    let tctl: u32 = (1 << 1) | (1 << 3) | (0x0F << 4) | (0x40 << 12);
    unsafe { core::ptr::write_volatile(base.byte_add(E1000E_REG_TCTL).cast_mut(), tctl) };
    early_console::write_str("[e1000e] RCTL+TCTL configured\n");

    // Step 9: Enable interrupts (IMS = RXT0 | TXDW | LSC).
    unsafe {
        core::ptr::write_volatile(base.byte_add(E1000E_REG_IMS).cast_mut(), E1000E_IMS_ENABLED);
    };
    early_console::write_str("[e1000e] IMS=0085 — interrupts enabled\n");

    // TX/RX round-trip smoke: write a single TX descriptor and check
    // the TDH advances after the tail bump (proves the controller's
    // DMA engine is processing the descriptor ring).
    //
    // For this Phase-1 validation, we verify that the controller
    // accepted the ring programming by reading back TDH/TDT (the
    // hardware should leave them at 0 since we haven't posted any
    // actual descriptors with valid buffer addresses).
    let tdh = unsafe { core::ptr::read_volatile(base.byte_add(E1000E_REG_TDH)) };
    let tdt = unsafe { core::ptr::read_volatile(base.byte_add(E1000E_REG_TDT)) };
    early_console::write_str("[e1000e] TDH=");
    early_console::write_usize(tdh as usize);
    early_console::write_str(" TDT=");
    early_console::write_usize(tdt as usize);
    early_console::write_str("\n");

    let rdh = unsafe { core::ptr::read_volatile(base.byte_add(E1000E_REG_RDH)) };
    let rdt = unsafe { core::ptr::read_volatile(base.byte_add(E1000E_REG_RDT)) };
    early_console::write_str("[e1000e] RDH=");
    early_console::write_usize(rdh as usize);
    early_console::write_str(" RDT=");
    early_console::write_usize(rdt as usize);
    early_console::write_str("\n");

    E1000E_LIVE.store(true, Ordering::Relaxed);
    early_console::write_str("[e1000e] live bring-up complete\n");
}

// =========================================================================
// Hex formatting helpers (no alloc, no format!)
// =========================================================================

#[allow(clippy::indexing_slicing, reason = "nibble index is always 0..15")]
fn write_hex_u8(val: u8) {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    let hi = HEX[(val >> 4) as usize];
    let lo = HEX[(val & 0xF) as usize];
    let buf = [hi, lo];
    // SAFETY: both bytes are ASCII hex digits from the const table.
    #[allow(unsafe_code, reason = "ASCII-only from const table")]
    let s = unsafe { core::str::from_utf8_unchecked(&buf) };
    early_console::write_str(s);
}

#[allow(clippy::cast_possible_truncation, reason = "shifting u16 >> 8 fits u8")]
fn write_hex_u16(val: u16) {
    write_hex_u8((val >> 8) as u8);
    write_hex_u8(val as u8);
}

#[allow(
    clippy::cast_possible_truncation,
    reason = "shifting u32 >> 16 fits u16"
)]
fn write_hex_u32(val: u32) {
    write_hex_u16((val >> 16) as u16);
    write_hex_u16(val as u16);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn probe_elf_starts_with_elf_magic() {
        assert_eq!(&DRIVER_PROBE_ELF[0..4], &[0x7F, b'E', b'L', b'F']);
    }

    #[test]
    fn probe_elf_entry_is_0x400000() {
        let entry = u64::from_le_bytes(DRIVER_PROBE_ELF[24..32].try_into().unwrap());
        assert_eq!(entry, 0x0040_0000);
    }

    #[test]
    fn probe_elf_has_one_program_header() {
        let phnum = u16::from_le_bytes(DRIVER_PROBE_ELF[56..58].try_into().unwrap());
        assert_eq!(phnum, 1);
    }

    #[test]
    fn probe_elf_total_size_is_248() {
        assert_eq!(DRIVER_PROBE_ELF.len(), 248);
    }

    #[test]
    fn probe_elf_code_segment_size_matches() {
        let filesz = u64::from_le_bytes(DRIVER_PROBE_ELF[96..104].try_into().unwrap());
        assert_eq!(filesz, 128);
    }

    // ---- WS1-06: boot-time MSI-X registration convention -----------------

    #[test]
    fn msix_irq_lines_match_the_project_convention() {
        // The boot registration key MUST equal the line each Ring 3
        // driver passes to `IrqAttach`: 33 = virtio-net (the
        // `Resource::IrqLine(33)` grant in boot_load_virtio_net_image),
        // 34 = NVMe IO CQ (msix module docs / NCIP-Driver-NVMe-014 §S5),
        // 35 = e1000e (`IRQ_LINE_E1000E` in nexacore-driver-e1000e-image).
        assert_eq!(MSIX_IRQ_LINE_VIRTIO_NET, 33);
        assert_eq!(MSIX_IRQ_LINE_NVME, 34);
        assert_eq!(MSIX_IRQ_LINE_E1000E, 35);
    }

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn msix_table_vas_are_page_aligned_and_disjoint() {
        // 2 pages are mapped per device; the windows must not overlap
        // each other nor the fixed BAR0 windows (NVMe CSRs at
        // 0xFFFF_F000_0000_0000 + 4 pages, e1000e CSRs at
        // 0xFFFF_F000_0010_0000 + 32 pages).
        const WINDOW: u64 = 2 * 0x1000;
        let vas = [
            MSIX_TABLE_VA_VIRTIO_NET,
            MSIX_TABLE_VA_NVME,
            MSIX_TABLE_VA_E1000E,
        ];
        for (i, &va) in vas.iter().enumerate() {
            assert_eq!(va & 0xFFF, 0, "table VA must be page-aligned");
            assert!(
                va >= 0xFFFF_F000_0020_0000,
                "table VA must sit above the BAR0 CSR windows"
            );
            for &other in vas.iter().skip(i + 1) {
                assert!(
                    va + WINDOW <= other || other + WINDOW <= va,
                    "table VA windows must be disjoint"
                );
            }
        }
    }
}
