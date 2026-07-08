//! NexaCore OS xHCI USB host controller driver image — TASK-27 Phase 2a (ADR-0049).
//!
//! `no_std + no_main` ELF entry that the kernel boot-spawns at start-up.
//! The kernel writes per-driver capability tokens at the well-known deposit VA
//! before transferring control to `_start`; the image reads them via
//! [`nexacore_driver_shared::caps::find_token`] and invokes `MmioMap (70)` /
//! `DmaMap (71)` to materialise the controller register file and the DMA arena.
//!
//! ## DMA dual-address model (ADR-0036 appendix 2, reused verbatim)
//!
//! `DmaMap (71)` returns the allocated **physical** base in `rax` (the IOVA
//! carries the CPU virtual address). Under the IOMMU TE-off passthrough the
//! controller DMAs to the **physical** address; the CPU accesses the same frame
//! through the **IOVA** (the kernel maps `iova → phys` in the driver's page
//! table).
//!
//! ## DMA page layout (8 pages at `DMA_IOVA_BASE`) — Phase 2a sub-page layout
//!
//! | Page | IOVA offset | Content |
//! |------|-------------|---------|
//! | 0 | `+0x0000` | DCBAA (up to MaxSlots × 8 B) |
//! | 1 | `+0x1000` | Command Ring (64 TRBs × 16 B + Link TRB) |
//! | 2 | `+0x2000` | Event Ring segment (128 TRBs × 16 B) |
//! | 3 | `+0x3000` | Event Ring Segment Table (ERST, one entry × 16 B) |
//! | 4+lo | `+0x4000` | EP0 Transfer Ring (64 TRBs × 16 B) |
//! | 4+hi | `+0x4800` | Bulk-OUT Transfer Ring (64 TRBs × 16 B) |
//! | 5+lo | `+0x5000` | Input Context (controller + slot + EP0..EP2 contexts) |
//! | 5+hi | `+0x5800` | Bulk-IN Transfer Ring (64 TRBs × 16 B) |
//! | 6+lo | `+0x6000` | Output Device Context for first storage device |
//! | 6+hi | `+0x6800` | Output Device Context for second storage device |
//! | 7 | `+0x7000` | Multi-purpose data buffer (descriptor reads, CBW, CSW, etc.) |
//!
//! Eight pages (0x8000 bytes) suffice for up to two storage devices.
//! No kernel window change is required.
//!
//! ## Boot sequence
//!
//! 1. Read xHCI BAR phys from the deposit device-info section (`bar_phys`).
//! 2. `MmioMap (70)` — map the BAR (64 KiB) into user space.
//! 3. `DmaMap (71)` × 8 — map each page separately.
//! 4. Controller bring-up per ADR-0049 D3 + xHCI § 4.2.
//! 5. Multi-device port scan + speed-aware enumeration (ADR-0049 D3).
//! 6. Config descriptor fetch + class dispatch (ADR-0049 D2).
//! 7. For Mass Storage devices: Configure Endpoint → BOT init → BLK service.
//! 8. For non-storage devices: log and skip (Phase 2b).
//! 9. Serve BLK requests over IPC (`usb0` + `usb0-reply` channels).
//!
//! ## Exit sentinel codes
//!
//! | Code | Meaning |
//! |------|---------|
//! | 2 | panic handler |
//! | 10 | no `MmioMap` token in deposit |
//! | 20 | no `DmaMap` token in deposit |
//! | 40+e | `MmioMap` returned errno `e` |
//! | 60+e | `DmaMap` page returned errno `e` |
//! | 200 | `USBSTS.CNR` did not clear |
//! | 210 | `HCRST` did not clear |
//! | 220 | `CAPLENGTH` < 0x20 |
//! | 230 | `RTSOFF` or `DBOFF` is zero |
//! | 250 | `USBSTS.HCH` did not clear after R/S |
//! | 300 | no connected root-hub port found |
//! | 310 | port reset timeout |
//! | 320 | enumeration timed out or failed |

#![no_std]
#![no_main]
#![allow(unsafe_code)]
#![warn(missing_docs)]

use core::{
    alloc::{GlobalAlloc, Layout},
    panic::PanicInfo,
};

use nexacore_driver_shared::{ACTION_TAG_DMA_MAP, ACTION_TAG_MMIO_MAP, caps::find_token};
use nexacore_driver_xhci::{
    MmioBackend, MmioReadBackend,
    context::{
        CTX_SIZE_32, CTX_SIZE_64, EndpointType, hs_interrupt_context_interval, write_dcbaa_entry,
        write_endpoint_context, write_ep0_context, write_input_control_context, write_slot_context,
    },
    control::{
        get_descriptor_setup, get_report_descriptor_setup, set_configuration_setup, set_idle_setup,
        set_protocol_boot_setup,
    },
    descriptor::{ConfigDescItem, parse_configuration_header, walk_config_descriptors},
    enumerate::{EnumCommand, Enumerator, ep0_max_packet_for_speed},
    hid::{
        HidKeyboardState, KeyEvent, MAX_KEY_EVENTS_PER_REPORT, PointerLayout,
        decode_pointer_report, extract_pointer_layout, parse_keyboard_report,
        scale_absolute_to_screen,
    },
    regs::{
        CAPLENGTH_OFFSET, CONFIG_OFFSET, CRCR_OFFSET, CRCR_RCS, DBOFF_OFFSET, DCBAAP_OFFSET,
        ERDP_EHB, ERDP_OFFSET, ERSTBA_OFFSET, ERSTSZ_OFFSET, HCCPARAMS1_OFFSET, HCSPARAMS1_OFFSET,
        IMAN_IE, IMAN_OFFSET, PORTSC_CCS, PORTSC_PP, PORTSC_PR, PORTSC_PRC, RTSOFF_OFFSET,
        USBCMD_HCRST, USBCMD_OFFSET, USBCMD_RUN_STOP, USBSTS_CNR, USBSTS_HCH, USBSTS_OFFSET,
        caplength, doorbell_base, doorbell_offset, hccparams1_csz, hcsparams1_max_ports,
        hcsparams1_max_slots, interrupter_offset, operational_base, port_reg_offset, runtime_base,
    },
    ring::{CommandRing, EventRing, TransferRing},
    storage::{
        CBW_LEN, CSW_LEN, INQUIRY_RESPONSE_MIN_LEN, blk_request_to_scsi, cdb_inquiry,
        cdb_read_capacity10, cdb_read10, cdb_test_unit_ready, cdb_write10, encode_cbw, parse_csw,
        parse_inquiry, parse_read_capacity10,
    },
    trb::{
        COMPLETION_CODE_SHORT_PACKET, COMPLETION_CODE_SUCCESS, TRB_TYPE_PORT_STATUS_CHANGE_EVENT,
        TRB_TYPE_TRANSFER_EVENT, Trb, configure_endpoint_trb, data_stage_trb, normal_trb,
        parse_transfer_event, setup_stage_trb, status_stage_trb,
    },
};
use nexacore_types::{
    blk::{BlkRequest, BlkResponse},
    display_channel::DisplayInputEvent,
    wire::{decode_canonical, encode_into_slice},
};

// =============================================================================
// Global allocator stub (PanicOnAlloc — stack-only, no heap)
// =============================================================================

/// Global allocator that panics on any allocation attempt.
///
/// This image is stack-only and must never reach the heap path. Any allocation
/// is a driver bug caught at the earliest possible moment.
struct PanicOnAlloc;

// SAFETY: GlobalAlloc is an unsafe trait; the implementation is trivially
// correct because alloc() panics (never returns a valid pointer) and dealloc()
// is a no-op.
unsafe impl GlobalAlloc for PanicOnAlloc {
    unsafe fn alloc(&self, _layout: Layout) -> *mut u8 {
        panic!("nexacore-driver-xhci-image: heap alloc (PanicOnAlloc)");
    }
    unsafe fn dealloc(&self, _ptr: *mut u8, _layout: Layout) {}
}

#[global_allocator]
static GLOBAL_ALLOC: PanicOnAlloc = PanicOnAlloc;

// =============================================================================
// Syscall numbers
// =============================================================================

/// `TaskExit (11)` — terminate the process.
const SYS_TASK_EXIT: u64 = 11;

/// `TaskYield (12)` — cooperatively yield the CPU.
const SYS_TASK_YIELD: u64 = 12;

/// `IpcCreateChannel (20)` — allocate a kernel-side IPC channel.
const SYS_IPC_CREATE_CHANNEL: u64 = 20;

/// `IpcSend (22)` — send a message on an IPC channel.
const SYS_IPC_SEND: u64 = 22;

/// `IpcTryReceive (24)` — non-blocking receive from an IPC channel.
const SYS_IPC_TRY_RECEIVE: u64 = 24;

/// `MmioMap (70)` — map an MMIO region into the caller's address space.
const SYS_MMIO_MAP: u64 = 70;

/// `DmaMap (71)` — allocate a DMA-coherent page and return its physical base.
const SYS_DMA_MAP: u64 = 71;

/// `WriteConsole (60)` — write bytes to the kernel console (COM1).
const SYS_WRITE_CONSOLE: u64 = 60;

/// `BlkRegister (76)` — register a BLK channel in the kernel registry.
const SYS_BLK_REGISTER: u64 = 76;

// =============================================================================
// DMA arena layout
// =============================================================================

/// DMA arena IOVA base — the kernel driver-DMA window.
const DMA_IOVA_BASE: u64 = 0x0000_0100_0000_0000;

/// DMA direction = bidirectional.
const DMA_DIR_BIDIR: u64 = 2;

/// IOVA of the DCBAA page (page 0).
const XHCI_DCBAA_IOVA: u64 = DMA_IOVA_BASE;

/// IOVA of the Command Ring page (page 1).
const XHCI_CMD_RING_IOVA: u64 = DMA_IOVA_BASE + 0x1000;

/// IOVA of the Event Ring segment page (page 2).
const XHCI_EVENT_RING_IOVA: u64 = DMA_IOVA_BASE + 0x2000;

/// IOVA of the Event Ring Segment Table (ERST) page (page 3).
const XHCI_ERST_IOVA: u64 = DMA_IOVA_BASE + 0x3000;

/// IOVA of the EP0 Transfer Ring (lower half of page 4, offset +0x0000).
const XHCI_EP0_RING_IOVA: u64 = DMA_IOVA_BASE + 0x4000;

/// IOVA of the Bulk-OUT Transfer Ring (upper half of page 4, offset +0x0800).
const XHCI_BULK_OUT_RING_IOVA: u64 = DMA_IOVA_BASE + 0x4800;

/// IOVA of the Input Context (lower half of page 5, offset +0x0000).
const XHCI_INPUT_CTX_IOVA: u64 = DMA_IOVA_BASE + 0x5000;

/// IOVA of the Bulk-IN Transfer Ring (upper half of page 5, offset +0x0800).
const XHCI_BULK_IN_RING_IOVA: u64 = DMA_IOVA_BASE + 0x5800;

/// IOVA of the Output Device Context for the first storage device (lower half of page 6).
const XHCI_OUTPUT_CTX_IOVA: u64 = DMA_IOVA_BASE + 0x6000;

/// IOVA of the Output Device Context for the second storage device (upper half of page 6).
/// Reserved for a second device if present; not actively used by the single-device BLK service.
#[allow(dead_code)]
const XHCI_OUTPUT_CTX2_IOVA: u64 = DMA_IOVA_BASE + 0x6800;

/// IOVA of the multi-purpose data buffer (page 7, offset +0x0000).
/// Used for descriptor reads, CBW, CSW, INQUIRY, READ CAPACITY responses.
const XHCI_DATA_BUF_IOVA: u64 = DMA_IOVA_BASE + 0x7000;

/// IOVA of the HID keyboard interrupt-IN Transfer Ring (page 8 lower, WS7-06).
const XHCI_HID_KBD_RING_IOVA: u64 = DMA_IOVA_BASE + 0x8000;

/// IOVA of the HID pointer interrupt-IN Transfer Ring (page 8 upper, WS7-06).
const XHCI_HID_PTR_RING_IOVA: u64 = DMA_IOVA_BASE + 0x8800;

/// IOVA of the Output Device Context for the third device (page 9 lower,
/// WS7-06 — with keyboard + storage + tablet, three slots are live).
const XHCI_OUTPUT_CTX3_IOVA: u64 = DMA_IOVA_BASE + 0x9000;

/// IOVA of the HID keyboard report buffer (page 9 upper, WS7-06).
const XHCI_HID_KBD_REPORT_IOVA: u64 = DMA_IOVA_BASE + 0x9800;

/// IOVA of the HID pointer report buffer (page 9 upper + 0x40, WS7-06).
const XHCI_HID_PTR_REPORT_IOVA: u64 = DMA_IOVA_BASE + 0x9840;

/// Total number of DMA pages (10 — see the kernel `XHCI_DMA_LEN`).
const DMA_PAGE_COUNT: usize = 10;

/// Command Ring capacity (TRBs including the Link TRB slot).
const CMD_RING_CAPACITY: u32 = 64;

/// Event Ring capacity (TRBs per segment).
const EVENT_RING_CAPACITY: u32 = 128;

/// EP0 Transfer Ring capacity.
const EP0_RING_CAPACITY: u32 = 64;

/// Bulk-IN Transfer Ring capacity.
const BULK_IN_RING_CAPACITY: u32 = 64;

/// Bulk-OUT Transfer Ring capacity.
const BULK_OUT_RING_CAPACITY: u32 = 64;

/// HID interrupt-IN Transfer Ring capacity (WS7-06).
///
/// 32 TRBs × 16 B = 512 B, fitting comfortably in each ring's half-page
/// (0x800 B) region on page 8.
const HID_RING_CAPACITY: u32 = 32;

/// Maximum HID report bytes armed per interrupt-IN Normal TRB (WS7-06).
///
/// Each report buffer occupies a 64-byte sub-slot of page 9's upper half;
/// the armed length is the endpoint's `wMaxPacketSize` clamped to this cap.
/// Devices with a shorter report complete with a Short Packet, which is
/// normal for interrupt endpoints.
const HID_REPORT_BUF_MAX: u32 = 64;

// =============================================================================
// IPC / BLK service constants
// =============================================================================

/// BLK channel queue depth (matches NVMe driver convention).
const BLK_CHANNEL_QUEUE_DEPTH: u64 = 1024;

/// BLK channel backpressure mode: 0 = non-blocking.
const BLK_CHANNEL_BACKPRESSURE_BLOCK: u64 = 0;

/// BLK channel TEE binding: 0 = not bound.
const BLK_CHANNEL_TEE_NOT_BOUND: u64 = 0;

/// IPC message kind: reply.
const IPC_KIND_REPLY: u64 = 2;

/// IPC message kind: asynchronous notification (`MessageKind::Notification`)
/// — the kind the display input channel consumes (WS7-06).
const IPC_KIND_NOTIFICATION: u64 = 3;

/// Request channel name for the USB storage BLK service.
const USB_DISK_SLOT: &[u8] = b"usb0";

/// Reply channel name for the USB storage BLK service.
const USB_DISK_SLOT_REPLY: &[u8] = b"usb0-reply";

// =============================================================================
// MmioMap parameters
// =============================================================================

/// MmioMap flags = 0 (uncached/UC default).
const MMIO_FLAGS_DEFAULT: u64 = 0;

/// xHCI MMIO window size — 64 KiB covers all four register spaces.
const XHCI_MMIO_LEN: u64 = 0x1_0000;

// =============================================================================
// Exit sentinel codes
// =============================================================================

/// No `MmioMap` token found in the deposit window.
const EXIT_NO_MMIO_TOKEN: u64 = 10;
/// No `DmaMap` token found in the deposit window.
const EXIT_NO_DMA_TOKEN: u64 = 20;
/// Base code for `MmioMap` syscall errno.
const EXIT_MMIO_BASE: u64 = 40;
/// Base code for `DmaMap` syscall errno.
const EXIT_DMA_BASE: u64 = 60;
/// `USBSTS.CNR` did not clear within the poll budget.
const EXIT_CNR_TIMEOUT: u64 = 200;
/// `USBCMD.HCRST` did not clear within the poll budget.
const EXIT_HCRST_TIMEOUT: u64 = 210;
/// `CAPLENGTH` < 0x20 (malformed controller).
const EXIT_BAD_CAPLENGTH: u64 = 220;
/// `RTSOFF` or `DBOFF` is zero after masking.
const EXIT_BAD_OFFSETS: u64 = 230;
/// `USBSTS.HCH` did not clear after setting `USBCMD.R/S`.
const EXIT_HCH_TIMEOUT: u64 = 250;
/// No connected root-hub port found.
/// Retained for documentation; multi-port scan continues rather than exiting.
#[allow(dead_code)]
const EXIT_NO_CONNECTED_PORT: u64 = 300;
/// Port reset (`PORTSC.PRC`) timeout.
/// Retained for documentation; per-port skip is used instead of process exit.
#[allow(dead_code)]
const EXIT_PORT_RESET_TIMEOUT: u64 = 310;
/// Enumeration timed out or failed.
const EXIT_ENUM_FAILED: u64 = 320;

// =============================================================================
// Poll budgets
// =============================================================================

/// Max iterations waiting for `USBSTS.CNR = 0`.
const CNR_POLL_BUDGET: u32 = 100_000;
/// Max iterations waiting for `USBCMD.HCRST = 0`.
const HCRST_POLL_BUDGET: u32 = 100_000;
/// Max iterations waiting for `USBSTS.HCH = 0` after R/S.
const HCH_POLL_BUDGET: u32 = 100_000;
/// Max iterations waiting for `PORTSC.PRC` to set.
const PORT_RESET_POLL_BUDGET: u32 = 500_000;
/// Max event-ring poll iterations in the enumeration loop.
const ENUM_POLL_BUDGET: u32 = 1_000_000;
/// Max event-ring poll iterations for a single control transfer.
const CTRL_XFER_POLL_BUDGET: u32 = 500_000;
/// Max event-ring poll iterations for a single bulk transfer.
const BULK_XFER_POLL_BUDGET: u32 = 500_000;

// =============================================================================
// Static BSS buffers for IPC request/response (single-threaded, no heap)
// =============================================================================

/// Receive buffer for incoming `BlkRequest` IPC messages.
///
/// Sized to hold the largest possible canonical-encoded `BlkRequest`.
/// Accessed exclusively via `addr_of_mut!`.
static mut REQ_BUF: [u8; 4096] = [0u8; 4096];

/// Encode buffer for `BlkResponse` wire bytes.
///
/// `encode_into_slice` writes at most a few dozen bytes. Accessed exclusively
/// via `addr_of_mut!`.
static mut RESP_BUF: [u8; 64] = [0u8; 64];

// =============================================================================
// Full-clobber syscall wrapper (ADR-0035)
// =============================================================================

/// Issue a `syscall` instruction with up to 5 arguments.
///
/// Returns `(rax_out, rdx_out)` — the two-register driver-framework convention.
///
/// # Safety
///
/// All argument registers (`rdi`, `rsi`, `rdx`, `r10`, `r8`) are declared as
/// `inout ... => _` clobbers. The kernel does NOT restore argument registers
/// after the syscall entry (ADR-0035 full-clobber ABI).
#[inline(always)]
unsafe fn syscall5(number: u64, a0: u64, a1: u64, a2: u64, a3: u64, a4: u64) -> (u64, u64) {
    let mut rax_out: u64 = number;
    let rdx_out: u64;
    // SAFETY: `syscall` is the Ring 3 → Ring 0 transition on x86-64; the
    // kernel entry does not restore rdi/rsi/rdx/r10/r8, so each must be
    // clobbered here (ADR-0035 full-clobber ABI).
    unsafe {
        core::arch::asm!(
            "syscall",
            inout("rax") rax_out,
            inout("rdi") a0 => _,
            inout("rsi") a1 => _,
            inout("rdx") a2 => rdx_out,
            inout("r10") a3 => _,
            inout("r8")  a4 => _,
            out("r9")  _,
            out("rcx") _,
            out("r11") _,
            options(nostack, preserves_flags),
        );
    }
    (rax_out, rdx_out)
}

/// Issue `TaskExit(code)` — unconditionally terminates the process.
///
/// # Safety
///
/// Diverges via `TaskExit`; must only be called when the process must exit.
#[inline(always)]
unsafe fn sys_exit(code: u64) -> ! {
    // SAFETY: TaskExit terminates the process unconditionally; no return path.
    unsafe {
        core::arch::asm!(
            "syscall",
            in("rax") SYS_TASK_EXIT,
            in("rdi") code,
            lateout("rcx") _,
            lateout("r11") _,
            options(nostack),
        );
    }
    loop {
        core::hint::spin_loop();
    }
}

// =============================================================================
// Logging helpers (COM1 via WriteConsole (60))
// =============================================================================

/// Write `msg` to the kernel console (COM1) via `WriteConsole (60)`.
fn write(msg: &str) {
    let b = msg.as_bytes();
    // SAFETY: `b` is valid for the syscall duration; full-clobber stub.
    let _ = unsafe {
        syscall5(
            SYS_WRITE_CONSOLE,
            b.as_ptr() as u64,
            b.len() as u64,
            0,
            0,
            0,
        )
    };
}

/// Format `v` as 8 lowercase hex digits prefixed with `0x` and write to COM1.
fn write_hex32(v: u32) {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut buf = [0u8; 10];
    buf[0] = b'0';
    buf[1] = b'x';
    for i in 0..8usize {
        let nibble = ((v >> ((7 - i) * 4)) & 0xF) as usize;
        buf[2 + i] = HEX[nibble];
    }
    if let Ok(s) = core::str::from_utf8(&buf) {
        write(s);
    }
}

/// Format `v` as 4 lowercase hex digits prefixed with `0x` and write to COM1.
fn write_hex16(v: u16) {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut buf = [0u8; 6];
    buf[0] = b'0';
    buf[1] = b'x';
    for i in 0..4usize {
        let nibble = ((v >> ((3 - i) * 4)) & 0xF) as usize;
        buf[2 + i] = HEX[nibble];
    }
    if let Ok(s) = core::str::from_utf8(&buf) {
        write(s);
    }
}

/// Format `v` as 2 lowercase hex digits prefixed with `0x` and write to COM1.
fn write_hex8(v: u8) {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut buf = [0u8; 4];
    buf[0] = b'0';
    buf[1] = b'x';
    buf[2] = HEX[((v >> 4) & 0xF) as usize];
    buf[3] = HEX[(v & 0xF) as usize];
    if let Ok(s) = core::str::from_utf8(&buf) {
        write(s);
    }
}

/// Yield the CPU cooperatively via `TaskYield (12)`.
///
/// All tight polling loops call this to avoid busy-spinning under QEMU
/// emulation (mirrors the NVMe driver's Option-A cooperative style,
/// ADR-0036 D5).
fn task_yield() {
    let _ = unsafe { syscall5(SYS_TASK_YIELD, 0, 0, 0, 0, 0) };
}

// =============================================================================
// DmaMap helper
// =============================================================================

/// Map a single 4 KiB DMA page at `iova` and return its physical base.
///
/// Calls `DmaMap (71)` for exactly one page (always contiguous).
/// On failure (errno != 0) calls [`sys_exit`] with `EXIT_DMA_BASE + errno`.
///
/// # Safety
///
/// `dma_token` must be a valid slice from the deposit window and must remain
/// valid for the duration of the syscall.
unsafe fn dma_map_page(iova: u64, dma_token: &[u8]) -> u64 {
    // SAFETY: `syscall5` uses the full-clobber ABI (ADR-0035); `dma_token` is
    // valid for the call duration; `iova` is within the deposited DmaWindow.
    let (phys, errno) = unsafe {
        syscall5(
            SYS_DMA_MAP,
            iova,
            0x1000,
            DMA_DIR_BIDIR,
            dma_token.as_ptr() as u64,
            dma_token.len() as u64,
        )
    };
    if errno != 0 {
        // SAFETY: sys_exit diverges.
        unsafe { sys_exit(EXIT_DMA_BASE + errno) };
    }
    phys
}

// =============================================================================
// LiveMmioBackend — MmioBackend + MmioReadBackend over the mapped BAR
// =============================================================================

/// Volatile MMIO backend wrapping the BAR user-VA returned by `MmioMap`.
///
/// Implements [`MmioBackend`] (volatile u32 write) and [`MmioReadBackend`]
/// (volatile u32 read) so all bring-up code can drive the live controller
/// through the Phase-1 lib's trait seam.
///
/// `Copy` so callers can hold two independent instances at zero cost — no
/// mutable state is held beyond the VA.
#[derive(Clone, Copy)]
struct LiveMmioBackend {
    /// User virtual address of the first byte of the BAR0 MMIO mapping.
    mmio_va_base: u64,
}

impl MmioBackend for LiveMmioBackend {
    /// Write `value` to the register at `offset` bytes from BAR0 base.
    ///
    /// Uses a volatile 32-bit store as required by xHCI specification § 5.1.
    #[inline]
    fn write_u32(&mut self, offset: usize, value: u32) {
        // SAFETY: `mmio_va_base + offset` is inside the 64 KiB MMIO region
        // granted by `MmioMap`; the mapping is uncached (UC), so the volatile
        // write reaches the controller directly.
        unsafe {
            let ptr = (self.mmio_va_base as usize + offset) as *mut u32;
            ptr.write_volatile(value);
        }
    }
}

impl MmioReadBackend for LiveMmioBackend {
    /// Read a 32-bit value from the register at `offset` bytes from BAR0 base.
    ///
    /// Uses a volatile 32-bit load to prevent the compiler from caching the
    /// register value across polling loops.
    #[inline]
    fn read_u32(&mut self, offset: usize) -> u32 {
        // SAFETY: same region guarantee as `write_u32`; volatile reads prevent
        // the compiler from eliminating repeated reads in polling loops.
        unsafe {
            let ptr = (self.mmio_va_base as usize + offset) as *const u32;
            ptr.read_volatile()
        }
    }
}

// =============================================================================
// TRB ring I/O helpers — volatile access to DMA pages
// =============================================================================

/// Write a [`Trb`] into slot `idx` of a DMA ring page at IOVA `ring_iova`.
///
/// Each TRB slot is exactly 16 bytes. The write is performed as four volatile
/// 32-bit stores (little-endian), ensuring the controller sees the full TRB
/// before the doorbell is rung.
///
/// # Safety
///
/// - `ring_iova` must be a valid CPU-accessible IOVA returned by `DmaMap`.
/// - `idx * 16 + 16` must not exceed 4096 (the page boundary).
/// - No other code must concurrently write to the same slot.
#[inline]
unsafe fn write_trb_at(ring_iova: u64, idx: u16, trb: Trb) {
    let bytes = trb.to_bytes();
    // SAFETY: `ring_iova` is the CPU IOVA of a kernel-allocated DMA page;
    // `idx < capacity` ensures the 16-byte write stays within the page.
    // Volatile stores ensure the controller sees the TRB before the doorbell.
    unsafe {
        let base = ring_iova as *mut u8;
        let slot_ptr = base.add(usize::from(idx) * 16);
        for (i, chunk) in bytes.chunks_exact(4).enumerate() {
            let val = u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
            (slot_ptr.add(i * 4) as *mut u32).write_volatile(val);
        }
    }
}

/// Read the [`Trb`] at slot `idx` from the DMA ring page at IOVA `ring_iova`.
///
/// Reads are volatile so the compiler cannot cache the controller-written
/// event TRB value across Event Ring polling iterations.
///
/// # Safety
///
/// Same guarantees as [`write_trb_at`].
#[inline]
unsafe fn read_trb_at(ring_iova: u64, idx: u16) -> Trb {
    // SAFETY: `ring_iova` is a valid DMA page IOVA; the read stays within the
    // page; volatile reads prevent caching of event TRBs.
    unsafe {
        let base = ring_iova as *const u8;
        let slot_ptr = base.add(usize::from(idx) * 16);
        let mut raw = [0u8; 16];
        for i in 0..4usize {
            let val = (slot_ptr.add(i * 4) as *const u32).read_volatile();
            let b = val.to_le_bytes();
            raw[i * 4] = b[0];
            raw[i * 4 + 1] = b[1];
            raw[i * 4 + 2] = b[2];
            raw[i * 4 + 3] = b[3];
        }
        Trb::from_bytes(&raw).unwrap_or(Trb::from_dwords([0u32; 4]))
    }
}

// =============================================================================
// IPC helpers (mirrors NVMe image pattern, ADR-0036 D2)
// =============================================================================

/// Send a message on `channel_id` with kind `kind`.
///
/// Returns `true` on success (kernel returned 0), `false` on error.
fn ipc_send(channel_id: u64, kind: u64, data: &[u8]) -> bool {
    // SAFETY: `data` is a valid slice for the duration of the syscall.
    let (rax, _rdx) = unsafe {
        syscall5(
            SYS_IPC_SEND,
            channel_id,
            kind,
            data.as_ptr() as u64,
            data.len() as u64,
            0,
        )
    };
    rax != u64::MAX
}

/// Non-blocking IPC receive: copy at most `buf.len()` bytes of the next
/// pending message into `buf`. Returns `Some(n)` (bytes copied) when a
/// message was available, `None` when the queue is empty.
fn ipc_try_receive(channel_id: u64, buf: &mut [u8]) -> Option<usize> {
    // SAFETY: `buf` is a valid writable slice; the kernel copies at most
    // `buf.len()` bytes.
    let (rax, _rdx) = unsafe {
        syscall5(
            SYS_IPC_TRY_RECEIVE,
            channel_id,
            buf.as_mut_ptr() as u64,
            buf.len() as u64,
            0,
            0,
        )
    };
    if rax == u64::MAX {
        None
    } else {
        // SAFETY: kernel copies at most buf.len() bytes, so rax fits usize.
        #[allow(clippy::cast_possible_truncation)]
        Some(rax as usize)
    }
}

/// Encode `resp` into `RESP_BUF` and send it as an IPC reply on `reply_channel_id`.
///
/// # Safety
///
/// The caller must ensure exclusive access to `RESP_BUF`.
unsafe fn send_blk_response(reply_channel_id: u64, resp: BlkResponse) {
    // SAFETY: exclusive BSS access guaranteed by single-threaded design.
    let resp_buf = unsafe { &mut *core::ptr::addr_of_mut!(RESP_BUF) };
    let Ok(n) = encode_into_slice(&resp, resp_buf) else {
        return;
    };
    ipc_send(reply_channel_id, IPC_KIND_REPLY, &resp_buf[..n]);
}

// =============================================================================
// Controller bring-up helpers
// =============================================================================

/// Poll the Event Ring for the next valid event TRB, draining Port Status
/// Change Events. Calls `task_yield` when no event is available. Returns
/// `None` after `budget` iterations.
fn poll_event_ring(
    event_ring: &mut EventRing,
    event_ring_phys: u64,
    ir0_base: usize,
    mmio: &mut LiveMmioBackend,
    budget: u32,
) -> Option<Trb> {
    let mut polls: u32 = 0;
    loop {
        if polls >= budget {
            return None;
        }
        polls = polls.saturating_add(1);

        // SAFETY: XHCI_EVENT_RING_IOVA is a valid DMA page IOVA.
        let raw = unsafe { read_trb_at(XHCI_EVENT_RING_IOVA, event_ring.dequeue_ptr()) };
        let Some(trb) = event_ring.try_dequeue(raw) else {
            task_yield();
            continue;
        };

        // Advance ERDP.
        let new_erdp = event_ring
            .erdp_value(event_ring_phys)
            .unwrap_or(event_ring_phys | ERDP_EHB);
        mmio.write_u64(ir0_base + ERDP_OFFSET, new_erdp);

        // Port Status Change Events do not belong to enumeration/transfer flows;
        // drain them silently per the TASK-26 pattern.
        if trb.trb_type() == TRB_TYPE_PORT_STATUS_CHANGE_EVENT {
            task_yield();
            continue;
        }

        return Some(trb);
    }
}

/// Submit one TRB to the Command Ring and ring doorbell 0.
fn submit_command(
    cmd_ring: &mut CommandRing,
    cmd_ring_phys: u64,
    trb: Trb,
    mmio: &mut LiveMmioBackend,
    db_base: usize,
    db_slot0_offset: usize,
) {
    let slot_idx = cmd_ring.enqueue();
    let trb_with_cycle = trb.with_cycle_bit(cmd_ring.producer_cycle());
    // SAFETY: slot_idx < capacity; page is mapped.
    unsafe { write_trb_at(XHCI_CMD_RING_IOVA, slot_idx, trb_with_cycle) };
    // Refresh Link TRB after every enqueue.
    let new_link = cmd_ring.build_link_trb(cmd_ring_phys);
    let link_slot = cmd_ring.capacity() - 1;
    unsafe { write_trb_at(XHCI_CMD_RING_IOVA, link_slot, new_link) };
    mmio.write_u32(db_base + db_slot0_offset, 0);
}

/// Submit a control transfer (SETUP + DATA + STATUS) on the EP0 ring and ring
/// the EP0 doorbell for `slot_id`.
#[allow(clippy::too_many_arguments)]
fn submit_ep0_transfer(
    ep0_ring: &mut TransferRing,
    ep0_ring_phys: u64,
    slot_id: u8,
    setup: Trb,
    data: Trb,
    status: Trb,
    mmio: &mut LiveMmioBackend,
    db_base: usize,
) {
    let s_idx = ep0_ring.enqueue();
    unsafe {
        write_trb_at(
            XHCI_EP0_RING_IOVA,
            s_idx,
            setup.with_cycle_bit(ep0_ring.producer_cycle()),
        )
    };

    let d_idx = ep0_ring.enqueue();
    unsafe {
        write_trb_at(
            XHCI_EP0_RING_IOVA,
            d_idx,
            data.with_cycle_bit(ep0_ring.producer_cycle()),
        )
    };

    let st_idx = ep0_ring.enqueue();
    unsafe {
        write_trb_at(
            XHCI_EP0_RING_IOVA,
            st_idx,
            status.with_cycle_bit(ep0_ring.producer_cycle()),
        )
    };

    // Refresh Link TRB.
    let link_slot = ep0_ring.capacity() - 1;
    let link = ep0_ring.build_link_trb(ep0_ring_phys);
    unsafe { write_trb_at(XHCI_EP0_RING_IOVA, link_slot, link) };

    // Ring EP0 doorbell — DB Target = 1 (EP0 per xHCI § 4.7.2).
    if let Some(db_off) = doorbell_offset(slot_id) {
        mmio.write_u32(db_base + db_off, 1);
    }
}

/// Submit one Normal TRB on the Bulk-OUT ring and ring its doorbell.
///
/// `dci` is the Doorbell target (2 for OUT EP1, 4 for OUT EP2, etc.).
#[allow(clippy::too_many_arguments)]
fn submit_bulk_out(
    ring: &mut TransferRing,
    ring_iova: u64,
    ring_phys: u64,
    slot_id: u8,
    dci: u32,
    buf_iova: u64,
    length: u32,
    mmio: &mut LiveMmioBackend,
    db_base: usize,
) {
    let trb = normal_trb(buf_iova, length, false, true, ring.producer_cycle());
    let idx = ring.enqueue();
    unsafe { write_trb_at(ring_iova, idx, trb) };
    let link_slot = ring.capacity() - 1;
    let link = ring.build_link_trb(ring_phys);
    unsafe { write_trb_at(ring_iova, link_slot, link) };
    if let Some(db_off) = doorbell_offset(slot_id) {
        mmio.write_u32(db_base + db_off, dci);
    }
}

/// Submit one Normal TRB on the Bulk-IN ring and ring its doorbell.
///
/// `dci` is the Doorbell target (3 for IN EP1, 5 for IN EP2, etc.).
#[allow(clippy::too_many_arguments)]
fn submit_bulk_in(
    ring: &mut TransferRing,
    ring_iova: u64,
    ring_phys: u64,
    slot_id: u8,
    dci: u32,
    buf_iova: u64,
    length: u32,
    mmio: &mut LiveMmioBackend,
    db_base: usize,
) {
    let trb = normal_trb(buf_iova, length, true, true, ring.producer_cycle());
    let idx = ring.enqueue();
    unsafe { write_trb_at(ring_iova, idx, trb) };
    let link_slot = ring.capacity() - 1;
    let link = ring.build_link_trb(ring_phys);
    unsafe { write_trb_at(ring_iova, link_slot, link) };
    if let Some(db_off) = doorbell_offset(slot_id) {
        mmio.write_u32(db_base + db_off, dci);
    }
}

// =============================================================================
// BOT (Bulk-Only Transport) sequence helpers
// =============================================================================

/// Carries the bulk endpoint numbers discovered during Configure Endpoint.
///
/// Both fields are xHCI DCI values:
/// `dci = 2 * ep_number + direction_bit` where `direction_bit = 1` for IN.
struct BulkEndpoints {
    /// DCI of the Bulk-OUT endpoint.
    out_dci: u32,
    /// DCI of the Bulk-IN endpoint.
    in_dci: u32,
    /// `wMaxPacketSize` for the Bulk-OUT endpoint.
    /// Stored for future use (e.g. splitting large transfers per MPS).
    #[allow(dead_code)]
    out_mps: u16,
    /// `wMaxPacketSize` for the Bulk-IN endpoint.
    /// Stored for future use (e.g. splitting large transfers per MPS).
    #[allow(dead_code)]
    in_mps: u16,
}

// =============================================================================
// HID runtime (WS7-06) — live USB HID reports → display input channel
// =============================================================================

/// Per-device HID class state: boot keyboard tracker or pointer layout.
enum HidKind {
    /// Boot-protocol keyboard: consecutive-report diffing state.
    Keyboard(HidKeyboardState),
    /// Report-protocol pointer (absolute tablet or relative mouse): the
    /// fixed report layout extracted from the report descriptor at setup.
    Pointer(PointerLayout),
}

/// One configured HID device with its armed interrupt-IN transfer ring.
struct HidDevice {
    /// xHCI device slot.
    slot_id: u8,
    /// DCI of the interrupt-IN endpoint (doorbell target).
    dci: u32,
    /// Producer-side transfer ring state.
    ring: TransferRing,
    /// CPU IOVA of the ring memory.
    ring_iova: u64,
    /// Physical base of the ring memory (for Link TRBs).
    ring_phys: u64,
    /// CPU IOVA of the report buffer.
    report_iova: u64,
    /// Physical address of the report buffer (Normal TRB data pointer).
    report_phys: u64,
    /// Bytes armed per Normal TRB (`wMaxPacketSize` clamped to the 64-byte
    /// buffer slot).
    report_len: u32,
    /// Class-specific decode state.
    kind: HidKind,
}

/// Live HID input state shared across the port scan and the serve loop.
///
/// `try_consume` gives every event-ring drain point (including the BOT
/// sequences of the storage service) a single place to route HID transfer
/// events so no input report is lost or misattributed to a bulk transfer.
struct HidRuntime {
    /// Configured boot keyboard, if one enumerated.
    kbd: Option<HidDevice>,
    /// Configured pointer device, if one enumerated.
    ptr: Option<HidDevice>,
    /// Display input channel id from the deposit (0 = kernel without the
    /// WS7-06 overload — HID input disabled).
    input_channel_id: u64,
    /// Framebuffer width for absolute-pointer scaling (0 = unknown).
    fb_width: u32,
    /// Framebuffer height for absolute-pointer scaling (0 = unknown).
    fb_height: u32,
    /// Accumulated cursor position for RELATIVE pointer devices, clamped to
    /// the framebuffer (mirrors the kernel PS/2 pump's cursor model).
    cursor_x: i32,
    /// See `cursor_x`.
    cursor_y: i32,
    /// Set once the rings are armed (after the port scan); before that no
    /// transfer event can belong to a HID endpoint.
    armed: bool,
}

/// Synthetic modifier keycode range emitted by `HidKeyboardState`
/// (`0x90..=0x97`) — driver-internal, never forwarded to the display
/// channel (the PS/2 pump does not produce them either).
const MODIFIER_KEYCODE_MIN: u8 = 0x90;
/// Upper bound of the synthetic modifier keycode range (inclusive).
const MODIFIER_KEYCODE_MAX: u8 = 0x97;

impl HidRuntime {
    /// Construct with the deposit-provided channel id and screen geometry.
    fn new(input_channel_id: u64, fb_width: u32, fb_height: u32) -> Self {
        #[allow(
            clippy::cast_possible_wrap,
            reason = "framebuffer dimensions are small positive pixel counts"
        )]
        Self {
            kbd: None,
            ptr: None,
            input_channel_id,
            fb_width,
            fb_height,
            cursor_x: (fb_width / 2) as i32,
            cursor_y: (fb_height / 2) as i32,
            armed: false,
        }
    }

    /// Whether HID input production is possible at all.
    fn enabled(&self) -> bool {
        self.input_channel_id != 0
    }

    /// Arm one interrupt-IN Normal TRB on every configured device and mark
    /// the runtime live. Called ONCE, after the port scan, so stray HID
    /// events can never confuse the enumeration event loops.
    fn arm_all(&mut self, mmio: &mut LiveMmioBackend, db_base: usize) {
        if !self.enabled() {
            return;
        }
        if let Some(dev) = self.kbd.as_mut() {
            hid_arm(dev, mmio, db_base);
            write("[xhci] hid: keyboard armed\n");
        }
        if let Some(dev) = self.ptr.as_mut() {
            hid_arm(dev, mmio, db_base);
            write("[xhci] hid: pointer armed\n");
        }
        self.armed = self.kbd.is_some() || self.ptr.is_some();
    }

    /// Route `trb` if it is a Transfer Event for one of the HID endpoints:
    /// decode the report, produce `DisplayInputEvent`s on the input channel,
    /// re-arm the ring. Returns `true` when the event was consumed.
    fn try_consume(&mut self, trb: &Trb, mmio: &mut LiveMmioBackend, db_base: usize) -> bool {
        if !self.armed || trb.trb_type() != TRB_TYPE_TRANSFER_EVENT {
            return false;
        }
        // The cycle bit was already validated by the event-ring dequeue.
        let Some(ev) = parse_transfer_event(trb, trb.cycle_bit()) else {
            return false;
        };
        let matches =
            |dev: &HidDevice| dev.slot_id == ev.slot_id && dev.dci == u32::from(ev.endpoint_id);
        let is_kbd = self.kbd.as_ref().is_some_and(matches);
        let is_ptr = !is_kbd && self.ptr.as_ref().is_some_and(matches);
        if !is_kbd && !is_ptr {
            return false;
        }

        let ok = ev.completion_code == COMPLETION_CODE_SUCCESS
            || ev.completion_code == COMPLETION_CODE_SHORT_PACKET;

        let input_ch = self.input_channel_id;
        let (fb_w, fb_h) = (self.fb_width, self.fb_height);

        if is_kbd {
            if let Some(dev) = self.kbd.as_mut() {
                if ok {
                    handle_kbd_report(dev, input_ch);
                }
                hid_arm(dev, mmio, db_base);
            }
        } else if let Some(dev) = self.ptr.as_mut() {
            if ok {
                let (cx, cy) = (self.cursor_x, self.cursor_y);
                if let Some((nx, ny)) = handle_ptr_report(dev, input_ch, fb_w, fb_h, cx, cy) {
                    self.cursor_x = nx;
                    self.cursor_y = ny;
                }
            }
            hid_arm(dev, mmio, db_base);
        }
        true
    }
}

/// Arm one interrupt-IN Normal TRB on `dev`'s ring and ring its doorbell.
fn hid_arm(dev: &mut HidDevice, mmio: &mut LiveMmioBackend, db_base: usize) {
    let trb = normal_trb(
        dev.report_phys,
        dev.report_len,
        true,
        true,
        dev.ring.producer_cycle(),
    );
    let idx = dev.ring.enqueue();
    // SAFETY: idx < capacity; the ring page is DMA-mapped.
    unsafe { write_trb_at(dev.ring_iova, idx, trb) };
    let link_slot = dev.ring.capacity() - 1;
    let link = dev.ring.build_link_trb(dev.ring_phys);
    // SAFETY: link_slot < capacity; the ring page is DMA-mapped.
    unsafe { write_trb_at(dev.ring_iova, link_slot, link) };
    if let Some(db_off) = doorbell_offset(dev.slot_id) {
        mmio.write_u32(db_base + db_off, dev.dci);
    }
}

/// Copy the device-written report bytes out of `dev`'s DMA buffer.
fn read_report_bytes(dev: &HidDevice, out: &mut [u8; 64]) -> usize {
    let len = (dev.report_len as usize).min(out.len());
    // SAFETY: report_iova is a valid DMA sub-buffer of at least
    // HID_REPORT_BUF_MAX bytes; len ≤ 64.
    unsafe {
        let src = dev.report_iova as *const u8;
        for (i, slot) in out.iter_mut().take(len).enumerate() {
            *slot = src.add(i).read_volatile();
        }
    }
    len
}

/// Encode one `DisplayInputEvent` and send it on the input channel.
fn send_input_event(input_channel_id: u64, event: &DisplayInputEvent) {
    let mut buf = [0u8; 32];
    if let Ok(n) = encode_into_slice(event, &mut buf) {
        let payload = buf.get(..n).unwrap_or(&[]);
        let _ = ipc_send(input_channel_id, IPC_KIND_NOTIFICATION, payload);
    }
}

/// Decode a boot keyboard report and forward key transitions (WS7-06).
fn handle_kbd_report(dev: &mut HidDevice, input_channel_id: u64) {
    let mut bytes = [0u8; 64];
    let len = read_report_bytes(dev, &mut bytes);
    let Some(report_bytes) = bytes.get(..len.min(8)) else {
        return;
    };
    let Ok(report) = parse_keyboard_report(report_bytes) else {
        // Too-short or rollover-phantom report: ignore, keep polling.
        return;
    };
    let HidKind::Keyboard(state) = &mut dev.kind else {
        return;
    };
    let mut events = [KeyEvent {
        code: 0,
        pressed: false,
    }; MAX_KEY_EVENTS_PER_REPORT];
    let n = state.update_into(report, &mut events);
    for ev in events.iter().take(n) {
        // Synthetic modifier codes are driver-internal.
        if (MODIFIER_KEYCODE_MIN..=MODIFIER_KEYCODE_MAX).contains(&ev.code) {
            continue;
        }
        send_input_event(
            input_channel_id,
            &DisplayInputEvent::Key {
                code: ev.code,
                pressed: ev.pressed,
            },
        );
    }
}

/// Decode a pointer report and forward it as an absolute `Pointer` event.
///
/// Returns the updated relative-cursor position when the device is a
/// relative mouse (`None` for absolute tablets, whose position is stateless).
fn handle_ptr_report(
    dev: &mut HidDevice,
    input_channel_id: u64,
    fb_width: u32,
    fb_height: u32,
    cursor_x: i32,
    cursor_y: i32,
) -> Option<(i32, i32)> {
    let mut bytes = [0u8; 64];
    let len = read_report_bytes(dev, &mut bytes);
    let HidKind::Pointer(layout) = &dev.kind else {
        return None;
    };
    let Ok(sample) = decode_pointer_report(layout, bytes.get(..len).unwrap_or(&[])) else {
        return None;
    };
    if fb_width == 0 || fb_height == 0 {
        return None;
    }
    let (x, y, moved_cursor) = if sample.relative {
        #[allow(
            clippy::cast_possible_wrap,
            reason = "framebuffer dimensions are small positive pixel counts"
        )]
        let (max_x, max_y) = ((fb_width - 1) as i32, (fb_height - 1) as i32);
        let nx = cursor_x.saturating_add(sample.x).clamp(0, max_x);
        let ny = cursor_y.saturating_add(sample.y).clamp(0, max_y);
        #[allow(
            clippy::cast_sign_loss,
            reason = "clamped to [0, fb-1], so non-negative"
        )]
        (nx as u32, ny as u32, Some((nx, ny)))
    } else {
        (
            scale_absolute_to_screen(sample.x, sample.x_min, sample.x_max, fb_width),
            scale_absolute_to_screen(sample.y, sample.y_min, sample.y_max, fb_height),
            None,
        )
    };
    send_input_event(
        input_channel_id,
        &DisplayInputEvent::Pointer {
            x,
            y,
            buttons: sample.buttons,
        },
    );
    moved_cursor
}

/// Issue a no-data EP0 control request (SETUP + STATUS-IN) and drain its
/// Transfer Event. Returns `false` on event timeout (WS7-06).
#[allow(clippy::too_many_arguments)]
fn ep0_no_data_request(
    setup_data: [u8; 8],
    slot_id: u8,
    ep0_ring: &mut TransferRing,
    ep0_ring_phys: u64,
    event_ring: &mut EventRing,
    event_ring_phys: u64,
    ir0_base: usize,
    mmio: &mut LiveMmioBackend,
    db_base: usize,
) -> bool {
    // TRT = 0 (No Data); STATUS phase direction = IN.
    let setup = setup_stage_trb(setup_data, 0, ep0_ring.producer_cycle());
    let status = status_stage_trb(true, ep0_ring.producer_cycle());
    let s_idx = ep0_ring.enqueue();
    // SAFETY: index < capacity; the EP0 ring page is DMA-mapped.
    unsafe {
        write_trb_at(
            XHCI_EP0_RING_IOVA,
            s_idx,
            setup.with_cycle_bit(ep0_ring.producer_cycle()),
        )
    };
    let st_idx = ep0_ring.enqueue();
    // SAFETY: index < capacity; the EP0 ring page is DMA-mapped.
    unsafe {
        write_trb_at(
            XHCI_EP0_RING_IOVA,
            st_idx,
            status.with_cycle_bit(ep0_ring.producer_cycle()),
        )
    };
    let lslot = ep0_ring.capacity() - 1;
    let ltrb = ep0_ring.build_link_trb(ep0_ring_phys);
    // SAFETY: link slot < capacity; the EP0 ring page is DMA-mapped.
    unsafe { write_trb_at(XHCI_EP0_RING_IOVA, lslot, ltrb) };
    if let Some(db_off) = doorbell_offset(slot_id) {
        mmio.write_u32(db_base + db_off, 1);
    }
    drain_one_transfer_event(event_ring, event_ring_phys, ir0_base, mmio)
}

/// Poll until one Transfer Event arrives (dropping non-TE events), bounded
/// by `CTRL_XFER_POLL_BUDGET`. Returns `false` on timeout (WS7-06).
fn drain_one_transfer_event(
    event_ring: &mut EventRing,
    event_ring_phys: u64,
    ir0_base: usize,
    mmio: &mut LiveMmioBackend,
) -> bool {
    let mut p = 0u32;
    while p < CTRL_XFER_POLL_BUDGET {
        p = p.saturating_add(1);
        if let Some(ev) = poll_event_ring(event_ring, event_ring_phys, ir0_base, mmio, 1) {
            if ev.trb_type() == TRB_TYPE_TRANSFER_EVENT {
                return true;
            }
        } else {
            task_yield();
        }
    }
    false
}

/// Configure one enumerated HID device (WS7-06): SET_CONFIGURATION, class
/// setup (boot keyboard: `SET_PROTOCOL(boot)` + `SET_IDLE(0)`; pointer:
/// report-descriptor fetch + layout extraction), interrupt-IN endpoint
/// context + Configure Endpoint, then stash the armed-later device state in
/// the [`HidRuntime`]. Failures log and leave the runtime unchanged (the
/// device is simply not an input source).
#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
fn hid_setup_device(
    port: u8,
    slot_id: u8,
    port_speed: u8,
    config_value: u8,
    iface_num: u8,
    is_boot_kbd: bool,
    int_in_ep: Option<(u8, u16, u8)>,
    hid_rt: &mut HidRuntime,
    ep0_ring: &mut TransferRing,
    ep0_ring_phys: u64,
    ring_phys_pair: (u64, u64),
    report_phys_pair: (u64, u64),
    input_ctx_phys: u64,
    data_buf_phys: u64,
    ctx_size: usize,
    cmd_ring: &mut CommandRing,
    cmd_ring_phys: u64,
    db_slot0_offset: usize,
    event_ring: &mut EventRing,
    event_ring_phys: u64,
    ir0_base: usize,
    mmio: &mut LiveMmioBackend,
    db_base: usize,
) {
    if !hid_rt.enabled() {
        write("[xhci] port ");
        write_hex32(u32::from(port));
        write(": HID device but no input channel in deposit — skip\n");
        return;
    }
    let Some((ep_num, ep_mps, ep_interval)) = int_in_ep else {
        write("[xhci] port ");
        write_hex32(u32::from(port));
        write(": HID without interrupt-IN endpoint — skip\n");
        return;
    };
    // One keyboard + one pointer slot available.
    if (is_boot_kbd && hid_rt.kbd.is_some()) || (!is_boot_kbd && hid_rt.ptr.is_some()) {
        write("[xhci] port ");
        write_hex32(u32::from(port));
        write(": HID slot of this kind already taken — skip\n");
        return;
    }

    // ---- SET_CONFIGURATION ----
    if !ep0_no_data_request(
        set_configuration_setup(config_value),
        slot_id,
        ep0_ring,
        ep0_ring_phys,
        event_ring,
        event_ring_phys,
        ir0_base,
        mmio,
        db_base,
    ) {
        write("[xhci] hid: SET_CONFIGURATION timeout — skip\n");
        return;
    }

    // ---- Class-specific setup ----
    let kind = if is_boot_kbd {
        // Boot protocol + idle-on-change only.
        if !ep0_no_data_request(
            set_protocol_boot_setup(iface_num),
            slot_id,
            ep0_ring,
            ep0_ring_phys,
            event_ring,
            event_ring_phys,
            ir0_base,
            mmio,
            db_base,
        ) {
            write("[xhci] hid: SET_PROTOCOL timeout — skip\n");
            return;
        }
        if !ep0_no_data_request(
            set_idle_setup(iface_num),
            slot_id,
            ep0_ring,
            ep0_ring_phys,
            event_ring,
            event_ring_phys,
            ir0_base,
            mmio,
            db_base,
        ) {
            write("[xhci] hid: SET_IDLE timeout — skip\n");
            return;
        }
        HidKind::Keyboard(HidKeyboardState::new())
    } else {
        // ---- Report-descriptor fetch (255 bytes into data buf +0x200) ----
        //
        // The walker does not expose the HID class descriptor's
        // wDescriptorLength, so a generous fixed length is requested; the
        // device short-packets at its real size and the pre-zeroed tail
        // decodes as harmless zero-length items.
        const REPORT_DESC_FETCH_LEN: u16 = 255;
        const REPORT_DESC_OFF: u64 = 0x200;
        // SAFETY: the data-buffer page is DMA-mapped; +0x200..+0x300 is in-page.
        unsafe {
            let dst = (XHCI_DATA_BUF_IOVA + REPORT_DESC_OFF) as *mut u8;
            for i in 0..usize::from(REPORT_DESC_FETCH_LEN) {
                dst.add(i).write_volatile(0u8);
            }
        }
        let setup = setup_stage_trb(
            get_report_descriptor_setup(iface_num, REPORT_DESC_FETCH_LEN),
            3,
            ep0_ring.producer_cycle(),
        );
        let data = data_stage_trb(
            data_buf_phys + REPORT_DESC_OFF,
            u32::from(REPORT_DESC_FETCH_LEN),
            true,
            ep0_ring.producer_cycle(),
        );
        let status = status_stage_trb(false, ep0_ring.producer_cycle());
        submit_ep0_transfer(
            ep0_ring,
            ep0_ring_phys,
            slot_id,
            setup,
            data,
            status,
            mmio,
            db_base,
        );
        // DATA stage event, then STATUS stage event.
        if !drain_one_transfer_event(event_ring, event_ring_phys, ir0_base, mmio)
            || !drain_one_transfer_event(event_ring, event_ring_phys, ir0_base, mmio)
        {
            write("[xhci] hid: report descriptor fetch timeout — skip\n");
            return;
        }
        // SAFETY: the fetch target is a DMA sub-buffer of 255 bytes just
        // written by the controller.
        let desc: &[u8] = unsafe {
            core::slice::from_raw_parts(
                (XHCI_DATA_BUF_IOVA + REPORT_DESC_OFF) as *const u8,
                usize::from(REPORT_DESC_FETCH_LEN),
            )
        };
        match extract_pointer_layout(desc) {
            Ok(layout) => HidKind::Pointer(layout),
            Err(_) => {
                write("[xhci] hid: report descriptor has no pointer layout — skip\n");
                return;
            }
        }
    };

    // ---- Per-kind ring + report buffer resources ----
    let (ring_iova, ring_phys, report_iova, report_phys) = if is_boot_kbd {
        (
            XHCI_HID_KBD_RING_IOVA,
            ring_phys_pair.0,
            XHCI_HID_KBD_REPORT_IOVA,
            report_phys_pair.0,
        )
    } else {
        (
            XHCI_HID_PTR_RING_IOVA,
            ring_phys_pair.1,
            XHCI_HID_PTR_REPORT_IOVA,
            report_phys_pair.1,
        )
    };

    // Zero the ring half-page region and build the ring.
    // SAFETY: the ring region is a DMA-mapped half page (0x800 bytes).
    unsafe {
        let ptr = ring_iova as *mut u8;
        for i in 0..0x800usize {
            ptr.add(i).write_volatile(0u8);
        }
    }
    let ring = TransferRing::new(HID_RING_CAPACITY).unwrap_or_else(|_| panic!("HID_RING_CAPACITY"));
    {
        let lslot = ring.capacity() - 1;
        let ltrb = ring.build_link_trb(ring_phys);
        // SAFETY: link slot < capacity; the ring region is DMA-mapped.
        unsafe { write_trb_at(ring_iova, lslot, ltrb) };
    }

    // ---- Configure Endpoint: add the interrupt-IN context ----
    let dci: u32 = 2 * u32::from(ep_num) + 1;
    {
        // SAFETY: input-context region is the DMA-mapped lower half of page 5.
        let ic_buf: &mut [u8] =
            unsafe { core::slice::from_raw_parts_mut(XHCI_INPUT_CTX_IOVA as *mut u8, 0x800) };
        ic_buf.fill(0);
        let add_flags: u32 = 1u32 | (1u32 << dci);
        write_input_control_context(ic_buf, ctx_size, add_flags, 0);
        #[allow(clippy::cast_possible_truncation, reason = "DCI of EP <= 15 fits u8")]
        write_slot_context(
            &mut ic_buf[ctx_size..],
            ctx_size,
            0,
            port_speed,
            port,
            dci as u8,
        );
        let ep0_mps = ep0_max_packet_for_speed(port_speed);
        let dcs_ptr = ep0_ring.dequeue_ptr_with_dcs(ep0_ring_phys);
        write_ep0_context(
            &mut ic_buf[2 * ctx_size..],
            ctx_size,
            dcs_ptr,
            ep0_mps,
            true,
        );
        let ring_dcs = ring.dequeue_ptr_with_dcs(ring_phys);
        let ep_ctx_off = (usize::try_from(dci).unwrap_or(3) + 1) * ctx_size;
        write_endpoint_context(
            &mut ic_buf[ep_ctx_off..],
            ctx_size,
            EndpointType::InterruptIn,
            ep_mps,
            hs_interrupt_context_interval(ep_interval),
            ring_dcs,
        );
        let cfg_ep_trb = configure_endpoint_trb(input_ctx_phys, slot_id, cmd_ring.producer_cycle());
        submit_command(
            cmd_ring,
            cmd_ring_phys,
            cfg_ep_trb,
            mmio,
            db_base,
            db_slot0_offset,
        );
    }

    // Await the Configure Endpoint completion.
    let mut cfg_ok = false;
    let mut p = 0u32;
    while p < ENUM_POLL_BUDGET {
        p = p.saturating_add(1);
        let Some(ev) = poll_event_ring(event_ring, event_ring_phys, ir0_base, mmio, 1) else {
            task_yield();
            continue;
        };
        if ev.trb_type() == nexacore_driver_xhci::trb::TRB_TYPE_COMMAND_COMPLETION_EVENT {
            #[allow(
                clippy::cast_possible_truncation,
                reason = "bits 31:24 shifted right 24 → 8-bit value"
            )]
            let cc = (ev.dwords()[2] >> 24) as u8;
            cfg_ok = cc == COMPLETION_CODE_SUCCESS;
            break;
        }
    }
    if !cfg_ok {
        write("[xhci] hid: Configure Endpoint failed — skip\n");
        return;
    }

    let report_len = u32::from(ep_mps).clamp(1, HID_REPORT_BUF_MAX);
    let dev = HidDevice {
        slot_id,
        dci,
        ring,
        ring_iova,
        ring_phys,
        report_iova,
        report_phys,
        report_len,
        kind,
    };
    write("[xhci] port ");
    write_hex32(u32::from(port));
    if is_boot_kbd {
        hid_rt.kbd = Some(dev);
        write(": HID boot keyboard configured DCI=");
    } else {
        hid_rt.ptr = Some(dev);
        write(": HID pointer configured DCI=");
    }
    write_hex32(dci);
    write("\n");
}

/// [`poll_event_ring`] with HID routing (WS7-06): HID transfer events are
/// consumed in place (decode → IPC → re-arm) and polling continues; any
/// other event is returned to the caller exactly as before. This is what
/// keeps a mouse/keyboard report arriving MID-BOT from being misread as a
/// bulk-transfer completion — and conversely keeps the BOT wait from
/// silently eating input reports.
#[allow(clippy::too_many_arguments)]
fn poll_event_ring_routed(
    event_ring: &mut EventRing,
    event_ring_phys: u64,
    ir0_base: usize,
    mmio: &mut LiveMmioBackend,
    budget: u32,
    hid: &mut HidRuntime,
    db_base: usize,
) -> Option<Trb> {
    loop {
        let trb = poll_event_ring(event_ring, event_ring_phys, ir0_base, mmio, budget)?;
        if !hid.try_consume(&trb, mmio, db_base) {
            return Some(trb);
        }
        // A HID event was routed; keep waiting for the caller's event.
    }
}

/// Execute a complete BOT command sequence: CBW → data phase → CSW.
///
/// ## Dual-address model (ADR-0036 appendix 2)
///
/// The xHCI controller DMAs to/from **physical** addresses embedded in TRBs.
/// CPU-side reads/writes use the corresponding IOVAs.  This function accepts
/// three distinct DMA regions, each specified as a `(physical, iova)` pair:
///
/// - **CBW/CSW region** (`cbw_buf_phys` / `cbw_buf_iova`): a scratch area of
///   at least 77 bytes (31 B CBW at `+0x000`, 13 B CSW at `+0x040`).  For
///   normal BOT calls this is page 7's first 64 bytes.  The self-test uses
///   a separate page so that page 7 can hold a full 4 KiB sector buffer.
/// - **Data phase buffer** (`data_phys`): physical DMA target for the Bulk-IN
///   or Bulk-OUT data transfer.  The caller is responsible for CPU-side
///   reads/writes through the corresponding IOVA.
///
/// ## CBW / CSW offsets within the CBW buffer
///
/// | Offset | Content              | Length |
/// |--------|----------------------|--------|
/// | +0x000 | CBW (written by CPU) | 31 B   |
/// | +0x040 | CSW (written by HW)  | 13 B   |
///
/// Returns `true` if the CSW was received and `bCSWStatus == 0` (GOOD).
#[allow(clippy::too_many_arguments)]
fn bot_execute(
    tag: u32,
    data_len: u32,
    dir_in: bool,
    lun: u8,
    cdb: &[u8],
    // Physical address of the data-phase DMA buffer (device-side).
    data_phys: u64,
    // Physical base of the CBW/CSW scratch region (at least 77 bytes).
    // CBW at +0x000, CSW at +0x040.
    cbw_buf_phys: u64,
    // CPU IOVA of the same CBW/CSW scratch region.
    cbw_buf_iova: u64,
    bulk_out: &mut TransferRing,
    bulk_out_phys: u64,
    bulk_in: &mut TransferRing,
    bulk_in_phys: u64,
    eps: &BulkEndpoints,
    slot_id: u8,
    event_ring: &mut EventRing,
    event_ring_phys: u64,
    ir0_base: usize,
    mmio: &mut LiveMmioBackend,
    db_base: usize,
    hid: &mut HidRuntime,
) -> bool {
    // ---- Build and write CBW ----
    //
    // CPU writes the CBW bytes at `cbw_buf_iova` (the CPU-accessible IOVA).
    // The controller reads CBW bytes from `cbw_buf_phys` (the physical address).
    let cbw = match encode_cbw(tag, data_len, dir_in, lun, cdb) {
        Ok(c) => c,
        Err(_) => return false,
    };
    // SAFETY: `cbw_buf_iova` is a valid DMA page IOVA supplied by the caller;
    // CBW_LEN = 31 bytes, which is always within a 4 KiB page.
    unsafe {
        let dst = cbw_buf_iova as *mut u8;
        for (i, &b) in cbw.iter().enumerate() {
            dst.add(i).write_volatile(b);
        }
    }

    // ---- Submit CBW on Bulk-OUT ----
    //
    // TRB data-buffer pointer = `cbw_buf_phys` (physical, read by controller).
    submit_bulk_out(
        bulk_out,
        XHCI_BULK_OUT_RING_IOVA,
        bulk_out_phys,
        slot_id,
        eps.out_dci,
        cbw_buf_phys, // physical — controller reads CBW from here
        CBW_LEN as u32,
        mmio,
        db_base,
    );
    // Wait for CBW Transfer Event (HID events are routed inline).
    match poll_event_ring_routed(
        event_ring,
        event_ring_phys,
        ir0_base,
        mmio,
        BULK_XFER_POLL_BUDGET,
        hid,
        db_base,
    ) {
        Some(ev) => {
            write("[xhci] BOT diag: cbw cc=");
            write_hex32((ev.dwords()[2] >> 24) & 0xFF);
            write("\n");
        }
        None => {
            write("[xhci] BOT: CBW transfer event timeout\n");
            return false;
        }
    }

    // ---- Data phase (optional) ----
    //
    // `data_phys` is the physical DMA target supplied by the caller.
    if data_len > 0 {
        if dir_in {
            // Device → Host: controller writes to `data_phys` (physical).
            submit_bulk_in(
                bulk_in,
                XHCI_BULK_IN_RING_IOVA,
                bulk_in_phys,
                slot_id,
                eps.in_dci,
                data_phys,
                data_len,
                mmio,
                db_base,
            );
        } else {
            // Host → Device: controller reads from `data_phys` (physical).
            submit_bulk_out(
                bulk_out,
                XHCI_BULK_OUT_RING_IOVA,
                bulk_out_phys,
                slot_id,
                eps.out_dci,
                data_phys,
                data_len,
                mmio,
                db_base,
            );
        }
        // Wait for data phase Transfer Event (HID events are routed inline).
        if poll_event_ring_routed(
            event_ring,
            event_ring_phys,
            ir0_base,
            mmio,
            BULK_XFER_POLL_BUDGET,
            hid,
            db_base,
        )
        .is_none()
        {
            write("[xhci] BOT: data transfer event timeout\n");
            return false;
        }
    }

    // ---- CSW phase: receive on Bulk-IN ----
    //
    // CSW sub-region at physical `cbw_buf_phys + 0x40`; CPU reads via
    // IOVA `cbw_buf_iova + 0x40`.
    let csw_phys = cbw_buf_phys + 0x40;
    let csw_iova = cbw_buf_iova + 0x40;
    submit_bulk_in(
        bulk_in,
        XHCI_BULK_IN_RING_IOVA,
        bulk_in_phys,
        slot_id,
        eps.in_dci,
        csw_phys, // physical — controller writes CSW here
        CSW_LEN as u32,
        mmio,
        db_base,
    );
    // Wait for CSW Transfer Event (HID events are routed inline).
    match poll_event_ring_routed(
        event_ring,
        event_ring_phys,
        ir0_base,
        mmio,
        BULK_XFER_POLL_BUDGET,
        hid,
        db_base,
    ) {
        Some(ev) => {
            write("[xhci] BOT diag: csw cc=");
            write_hex32((ev.dwords()[2] >> 24) & 0xFF);
            write("\n");
        }
        None => {
            write("[xhci] BOT: CSW transfer event timeout\n");
            return false;
        }
    }

    // ---- Parse CSW ----
    //
    // SAFETY: `csw_iova` is a valid DMA page IOVA supplied by the caller;
    // CSW_LEN = 13 bytes, always within a 4 KiB page.
    let csw_bytes: [u8; CSW_LEN] = unsafe {
        let src = csw_iova as *const u8;
        let mut arr = [0u8; CSW_LEN];
        for (i, b) in arr.iter_mut().enumerate() {
            *b = src.add(i).read_volatile();
        }
        arr
    };
    write("[xhci] BOT diag: csw[0..4]=");
    write_hex32(u32::from_le_bytes([
        csw_bytes[0],
        csw_bytes[1],
        csw_bytes[2],
        csw_bytes[3],
    ]));
    write("\n");
    match parse_csw(&csw_bytes) {
        Ok(csw) => csw.status == 0,
        Err(_) => {
            write("[xhci] BOT: CSW parse error\n");
            false
        }
    }
}

// =============================================================================
// ELF entry point
// =============================================================================

/// ELF entry point. The kernel's `spawn_from_elf` jumps here after mapping the
/// capability deposit window at the well-known VA.
///
/// This function never returns (it either loops in the BLK service or calls
/// [`sys_exit`] on an unrecoverable error).
#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    // -------------------------------------------------------------------------
    // 1. Locate capability tokens in the deposit window.
    // -------------------------------------------------------------------------
    let Some(mmio_token) = find_token(ACTION_TAG_MMIO_MAP, |_| true) else {
        // SAFETY: diverges.
        unsafe { sys_exit(EXIT_NO_MMIO_TOKEN) };
    };
    let Some(dma_token) = find_token(ACTION_TAG_DMA_MAP, |_| true) else {
        unsafe { sys_exit(EXIT_NO_DMA_TOKEN) };
    };

    // -------------------------------------------------------------------------
    // 2. Read the xHCI BAR phys from the deposit device-info section.
    // -------------------------------------------------------------------------
    // SAFETY: the deposit window is mapped read-only at the well-known VA
    // by the kernel before transferring execution to `_start`.
    //
    // WS7-06 overload (see `boot_load_xhci_image`): `common_offset` /
    // `notify_offset` carry the framebuffer width/height for absolute-pointer
    // scaling and `isr_offset` carries the display input channel id (0 on an
    // older kernel deposit → the HID input path stays disabled).
    let (bar0_phys, fb_width, fb_height, input_channel_id) =
        match unsafe { nexacore_driver_shared::device_info::read() } {
            Some(info) if info.bar_phys != 0 => (
                info.bar_phys,
                info.common_offset,
                info.notify_offset,
                u64::from(info.isr_offset),
            ),
            _ => (0xFEB8_0000_u64, 0u32, 0u32, 0u64),
        };

    // -------------------------------------------------------------------------
    // 3. MmioMap (70): map the xHCI BAR (64 KiB).
    // -------------------------------------------------------------------------
    let (mmio_va, mmio_errno) = unsafe {
        syscall5(
            SYS_MMIO_MAP,
            bar0_phys,
            XHCI_MMIO_LEN,
            MMIO_FLAGS_DEFAULT,
            mmio_token.as_ptr() as u64,
            mmio_token.len() as u64,
        )
    };
    if mmio_errno != 0 {
        unsafe { sys_exit(EXIT_MMIO_BASE + mmio_errno) };
    }
    write("[xhci] MmioMap OK\n");

    // -------------------------------------------------------------------------
    // 4. DmaMap (71) × 8: map each DMA page separately.
    //
    // Physical addresses returned by DmaMap go into controller registers.
    // IOVAs are the CPU virtual addresses used for CPU-side reads/writes.
    // -------------------------------------------------------------------------
    // SAFETY: each `dma_token` is from the deposit window; each IOVA is
    // within the deposited DmaWindow.
    let dcbaa_phys: u64 = unsafe { dma_map_page(XHCI_DCBAA_IOVA, dma_token) };
    let cmd_ring_phys: u64 = unsafe { dma_map_page(XHCI_CMD_RING_IOVA, dma_token) };
    let event_ring_phys: u64 = unsafe { dma_map_page(XHCI_EVENT_RING_IOVA, dma_token) };
    let erst_phys: u64 = unsafe { dma_map_page(XHCI_ERST_IOVA, dma_token) };
    // Page 4: EP0 ring (lower) + Bulk-OUT ring (upper) share one physical page.
    let page4_phys: u64 = unsafe { dma_map_page(XHCI_EP0_RING_IOVA, dma_token) };
    let ep0_ring_phys = page4_phys;
    let bulk_out_ring_phys = page4_phys + 0x800;
    // Page 5: Input Context (lower) + Bulk-IN ring (upper) share one physical page.
    let page5_phys: u64 = unsafe { dma_map_page(XHCI_INPUT_CTX_IOVA, dma_token) };
    let input_ctx_phys = page5_phys;
    let bulk_in_ring_phys = page5_phys + 0x800;
    // Page 6: Output contexts for up to two devices.
    let page6_phys: u64 = unsafe { dma_map_page(XHCI_OUTPUT_CTX_IOVA, dma_token) };
    let output_ctx_phys = page6_phys;
    let output_ctx2_phys = page6_phys + 0x800;
    let data_buf_phys: u64 = unsafe { dma_map_page(XHCI_DATA_BUF_IOVA, dma_token) };
    // Page 8: HID keyboard ring (lower) + HID pointer ring (upper), WS7-06.
    let page8_phys: u64 = unsafe { dma_map_page(XHCI_HID_KBD_RING_IOVA, dma_token) };
    let hid_kbd_ring_phys = page8_phys;
    let hid_ptr_ring_phys = page8_phys + 0x800;
    // Page 9: third output context (lower) + HID report buffers (upper).
    let page9_phys: u64 = unsafe { dma_map_page(XHCI_OUTPUT_CTX3_IOVA, dma_token) };
    let output_ctx3_phys = page9_phys;
    let hid_kbd_report_phys = page9_phys + 0x800;
    let hid_ptr_report_phys = page9_phys + 0x840;

    write("[xhci] DmaMap OK (10 pages)\n");

    // Zero every DMA page via CPU IOVA — defence-in-depth against stale data.
    // Page 5 upper (Bulk-IN ring) and page 4 upper (Bulk-OUT ring) are separate
    // IOVA ranges within the same physical page; zeroing the full 4 KiB from
    // the lower IOVA covers both halves.
    let iovas: [u64; DMA_PAGE_COUNT] = [
        XHCI_DCBAA_IOVA,
        XHCI_CMD_RING_IOVA,
        XHCI_EVENT_RING_IOVA,
        XHCI_ERST_IOVA,
        XHCI_EP0_RING_IOVA,   // covers page 4 lower + upper
        XHCI_INPUT_CTX_IOVA,  // covers page 5 lower + upper
        XHCI_OUTPUT_CTX_IOVA, // covers page 6 lower + upper
        XHCI_DATA_BUF_IOVA,
        XHCI_HID_KBD_RING_IOVA, // covers page 8 lower + upper (WS7-06)
        XHCI_OUTPUT_CTX3_IOVA,  // covers page 9 lower + upper (WS7-06)
    ];
    for &iova in &iovas {
        // SAFETY: each IOVA was returned by `dma_map_page`; 4 KiB write stays
        // within the mapped page; no other code holds a reference at this point.
        unsafe {
            let ptr = iova as *mut u8;
            for i in 0..0x1000usize {
                ptr.add(i).write_volatile(0u8);
            }
        }
    }

    // -------------------------------------------------------------------------
    // 5. Construct the live MMIO backend.
    // -------------------------------------------------------------------------
    let mut mmio = LiveMmioBackend {
        mmio_va_base: mmio_va,
    };

    // -------------------------------------------------------------------------
    // 6. Read capability registers.
    // -------------------------------------------------------------------------
    let cap_word0 = mmio.read_u32(CAPLENGTH_OFFSET);
    let caplength_val = caplength(cap_word0);

    let Some(op_base) = operational_base(caplength_val) else {
        write("[xhci] CAPLENGTH < 0x20 — abort\n");
        unsafe { sys_exit(EXIT_BAD_CAPLENGTH) };
    };

    let hcsparams1 = mmio.read_u32(HCSPARAMS1_OFFSET);
    let hccparams1 = mmio.read_u32(HCCPARAMS1_OFFSET);
    let dboff_raw = mmio.read_u32(DBOFF_OFFSET);
    let rtsoff_raw = mmio.read_u32(RTSOFF_OFFSET);

    let max_slots = hcsparams1_max_slots(hcsparams1);
    let max_ports = hcsparams1_max_ports(hcsparams1);
    let ctx_size: usize = if hccparams1_csz(hccparams1) {
        CTX_SIZE_64
    } else {
        CTX_SIZE_32
    };

    let Some(db_base) = doorbell_base(dboff_raw) else {
        write("[xhci] DBOFF=0 — abort\n");
        unsafe { sys_exit(EXIT_BAD_OFFSETS) };
    };
    let Some(rt_base) = runtime_base(rtsoff_raw) else {
        write("[xhci] RTSOFF=0 — abort\n");
        unsafe { sys_exit(EXIT_BAD_OFFSETS) };
    };

    write("[xhci] CAPLENGTH=");
    write_hex32(u32::from(caplength_val));
    write(" MaxSlots=");
    write_hex32(u32::from(max_slots));
    write(" MaxPorts=");
    write_hex32(u32::from(max_ports));
    write(" CSZ=");
    write(if ctx_size == CTX_SIZE_64 {
        "64\n"
    } else {
        "32\n"
    });

    // -------------------------------------------------------------------------
    // 7. Wait for USBSTS.CNR = 0.
    // -------------------------------------------------------------------------
    {
        let mut polls: u32 = 0;
        loop {
            let sts = mmio.read_u32(op_base + USBSTS_OFFSET);
            if (sts & USBSTS_CNR) == 0 {
                break;
            }
            polls = polls.saturating_add(1);
            if polls >= CNR_POLL_BUDGET {
                write("[xhci] CNR timeout — abort\n");
                unsafe { sys_exit(EXIT_CNR_TIMEOUT) };
            }
            task_yield();
        }
    }
    write("[xhci] CNR cleared\n");

    // -------------------------------------------------------------------------
    // 8. Assert HCRST, poll until HCRST = 0 and CNR = 0.
    // -------------------------------------------------------------------------
    {
        let usbcmd = mmio.read_u32(op_base + USBCMD_OFFSET);
        mmio.write_u32(op_base + USBCMD_OFFSET, usbcmd | USBCMD_HCRST);

        let mut polls: u32 = 0;
        loop {
            let cmd = mmio.read_u32(op_base + USBCMD_OFFSET);
            if (cmd & USBCMD_HCRST) == 0 {
                let sts = mmio.read_u32(op_base + USBSTS_OFFSET);
                if (sts & USBSTS_CNR) == 0 {
                    break;
                }
            }
            polls = polls.saturating_add(1);
            if polls >= HCRST_POLL_BUDGET {
                write("[xhci] HCRST timeout — abort\n");
                unsafe { sys_exit(EXIT_HCRST_TIMEOUT) };
            }
            task_yield();
        }
    }
    write("[xhci] HCRST complete\n");

    // -------------------------------------------------------------------------
    // 9. CONFIG.MaxSlotsEn = max_slots.
    // -------------------------------------------------------------------------
    mmio.write_u32(op_base + CONFIG_OFFSET, u32::from(max_slots));

    // -------------------------------------------------------------------------
    // 10. Write DCBAAP.
    // -------------------------------------------------------------------------
    mmio.write_u64(op_base + DCBAAP_OFFSET, dcbaa_phys);

    // -------------------------------------------------------------------------
    // 11. Initialise Command Ring + write CRCR.
    // -------------------------------------------------------------------------
    let mut cmd_ring =
        CommandRing::new(CMD_RING_CAPACITY).unwrap_or_else(|_| panic!("CMD_RING_CAPACITY invalid"));

    {
        let link_slot = cmd_ring.capacity() - 1;
        let link_trb = cmd_ring.build_link_trb(cmd_ring_phys);
        unsafe { write_trb_at(XHCI_CMD_RING_IOVA, link_slot, link_trb) };
    }
    mmio.write_u64(op_base + CRCR_OFFSET, cmd_ring_phys | CRCR_RCS);

    // -------------------------------------------------------------------------
    // 12. Initialise Event Ring and ERST.
    // -------------------------------------------------------------------------
    let mut event_ring = EventRing::new(EVENT_RING_CAPACITY)
        .unwrap_or_else(|_| panic!("EVENT_RING_CAPACITY invalid"));

    // Write the single ERST entry.
    // SAFETY: XHCI_ERST_IOVA is a valid DMA page IOVA; 16-byte write stays within page.
    unsafe {
        let erst_ptr = XHCI_ERST_IOVA as *mut u64;
        erst_ptr.write_volatile(event_ring_phys);
        let size_ptr = (XHCI_ERST_IOVA + 8) as *mut u32;
        #[allow(clippy::cast_possible_truncation, reason = "capacity <= u16::MAX")]
        size_ptr.write_volatile(u32::from(event_ring.capacity()));
        let rsv_ptr = (XHCI_ERST_IOVA + 12) as *mut u32;
        rsv_ptr.write_volatile(0);
    }

    let Some(ir0_offset) = interrupter_offset(0) else {
        unsafe { sys_exit(EXIT_BAD_OFFSETS) };
    };
    let ir0_base = rt_base + ir0_offset;

    mmio.write_u32(ir0_base + ERSTSZ_OFFSET, 1);
    mmio.write_u64(ir0_base + ERSTBA_OFFSET, erst_phys);
    let initial_erdp = event_ring
        .erdp_value(event_ring_phys)
        .unwrap_or(event_ring_phys | ERDP_EHB);
    mmio.write_u64(ir0_base + ERDP_OFFSET, initial_erdp);
    mmio.write_u32(ir0_base + IMAN_OFFSET, IMAN_IE | 1);

    write("[xhci] Event Ring + ERST programmed\n");

    // -------------------------------------------------------------------------
    // 13. Set USBCMD.R/S = 1 (run), poll USBSTS.HCH = 0.
    // -------------------------------------------------------------------------
    {
        let usbcmd2 = mmio.read_u32(op_base + USBCMD_OFFSET);
        mmio.write_u32(op_base + USBCMD_OFFSET, usbcmd2 | USBCMD_RUN_STOP);

        let mut polls: u32 = 0;
        loop {
            let sts = mmio.read_u32(op_base + USBSTS_OFFSET);
            if (sts & USBSTS_HCH) == 0 {
                break;
            }
            polls = polls.saturating_add(1);
            if polls >= HCH_POLL_BUDGET {
                write("[xhci] HCH timeout — abort\n");
                unsafe { sys_exit(EXIT_HCH_TIMEOUT) };
            }
            task_yield();
        }
    }
    write("[xhci] controller running (HCH=0)\n");

    // -------------------------------------------------------------------------
    // 14. Initialise EP0 Transfer Ring.
    // -------------------------------------------------------------------------
    let mut ep0_ring = TransferRing::new(EP0_RING_CAPACITY)
        .unwrap_or_else(|_| panic!("EP0_RING_CAPACITY invalid"));

    {
        let ep0_link_slot = ep0_ring.capacity() - 1;
        let ep0_link_trb = ep0_ring.build_link_trb(ep0_ring_phys);
        unsafe { write_trb_at(XHCI_EP0_RING_IOVA, ep0_link_slot, ep0_link_trb) };
    }

    // -------------------------------------------------------------------------
    // 15. Initialise Bulk-IN and Bulk-OUT Transfer Rings.
    // -------------------------------------------------------------------------
    let mut bulk_out_ring = TransferRing::new(BULK_OUT_RING_CAPACITY)
        .unwrap_or_else(|_| panic!("BULK_OUT_RING_CAPACITY invalid"));

    {
        let link_slot = bulk_out_ring.capacity() - 1;
        let link = bulk_out_ring.build_link_trb(bulk_out_ring_phys);
        unsafe { write_trb_at(XHCI_BULK_OUT_RING_IOVA, link_slot, link) };
    }

    let mut bulk_in_ring = TransferRing::new(BULK_IN_RING_CAPACITY)
        .unwrap_or_else(|_| panic!("BULK_IN_RING_CAPACITY invalid"));

    {
        let link_slot = bulk_in_ring.capacity() - 1;
        let link = bulk_in_ring.build_link_trb(bulk_in_ring_phys);
        unsafe { write_trb_at(XHCI_BULK_IN_RING_IOVA, link_slot, link) };
    }

    write("[xhci] bring-up complete — scanning root-hub ports\n");

    // -------------------------------------------------------------------------
    // 16. Scan ALL root-hub ports for connected devices.
    //
    // Phase 2a: each connected port gets speed-aware enumeration, config
    // descriptor fetch, and class dispatch. We process one port per loop
    // iteration and stop as soon as we have a storage device ready to serve,
    // or after scanning all ports.
    // -------------------------------------------------------------------------

    // Command ring doorbell offset (slot 0).
    let Some(db_slot0_offset) = doorbell_offset(0) else {
        unsafe { sys_exit(EXIT_ENUM_FAILED) };
    };

    // Tracks whether we found and set up a storage device.
    let mut storage_slot_id: Option<u8> = None;
    let mut storage_eps: Option<BulkEndpoints> = None;

    // Live HID input state (WS7-06): populated by the port scan, armed after
    // it. With input_channel_id = 0 (older kernel deposit) HID setup is
    // skipped entirely and the driver behaves exactly as before.
    let mut hid_rt = HidRuntime::new(input_channel_id, fb_width, fb_height);

    // Output context physical addresses, one distinct frame half-page per
    // enumerated device (keyboard + storage + tablet on the rig): DCBAA
    // entries must never alias or the controller overwrites one device's
    // context with another's.
    let output_ctx_choices = [output_ctx_phys, output_ctx2_phys, output_ctx3_phys];
    let mut output_ctx_next: usize = 0;

    'port_scan: for port in 1u8..=max_ports {
        // All output-context frames in use — no room for another device.
        if output_ctx_next >= output_ctx_choices.len() {
            write("[xhci] port scan: out of device context frames — stop\n");
            break;
        }

        let Some(portsc_off) = port_reg_offset(port) else {
            continue;
        };
        let portsc = mmio.read_u32(op_base + portsc_off);
        if (portsc & PORTSC_CCS) == 0 {
            continue;
        }

        // Read port speed before reset (bits 13:10).
        #[allow(clippy::cast_possible_truncation)]
        let port_speed = ((portsc >> 10) & 0xF) as u8;

        write("[xhci] port ");
        write_hex32(u32::from(port));
        write(": device speed=");
        write_hex8(port_speed);
        write(" PORTSC=");
        write_hex32(portsc);
        write("\n");

        // ---- Port reset ----
        {
            const RW1CS_MASK: u32 =
                (1 << 17) | (1 << 18) | (1 << 19) | (1 << 20) | (1 << 21) | (1 << 22) | (1 << 23);
            let portsc_before = mmio.read_u32(op_base + portsc_off);
            let portsc_write = (portsc_before & !RW1CS_MASK) | PORTSC_PP | PORTSC_PR;
            mmio.write_u32(op_base + portsc_off, portsc_write);
        }

        // Poll for PRC.
        {
            let mut polls: u32 = 0;
            loop {
                let ps = mmio.read_u32(op_base + portsc_off);
                if (ps & PORTSC_PRC) != 0 {
                    const RW1CS_MASK: u32 = (1 << 17)
                        | (1 << 18)
                        | (1 << 19)
                        | (1 << 20)
                        | (1 << 21)
                        | (1 << 22)
                        | (1 << 23);
                    let clear_prc = (ps & !RW1CS_MASK & !PORTSC_PR) | PORTSC_PP | PORTSC_PRC;
                    mmio.write_u32(op_base + portsc_off, clear_prc);
                    break;
                }
                polls = polls.saturating_add(1);
                if polls >= PORT_RESET_POLL_BUDGET {
                    write("[xhci] port ");
                    write_hex32(u32::from(port));
                    write(": reset timeout — skip\n");
                    continue 'port_scan;
                }
                task_yield();
            }
        }

        write("[xhci] port ");
        write_hex32(u32::from(port));
        write(": reset complete\n");

        // ---- Speed-aware enumeration ----
        let mut enumerator = Enumerator::new_with_speed(port, XHCI_EP0_RING_IOVA, port_speed);

        // Reset the EP0 ring for this new device.
        //
        // CRITICAL: zero the DMA page BEFORE recreating the ring.
        // `TransferRing::new` resets the Rust state (producer_cycle=true,
        // dequeue_ptr=0) but does NOT touch DMA memory.  If device N-1 left
        // TRBs at positions 0-2 with cycle_bit=true, the controller will see
        // DCS=true in the new EP0 Context, start from position 0, find those
        // stale TRBs with a matching cycle bit, and re-execute them — generating
        // spurious Transfer Events that confuse the enumeration state machine.
        // SAFETY: XHCI_EP0_RING_IOVA is a valid DMA page IOVA (page 4 lower).
        // ONLY the lower half (the EP0 ring) is zeroed: the upper half is the
        // Bulk-OUT ring, which belongs to an already-configured storage
        // device once multiple ports are processed (WS7-06) and must not be
        // wiped mid-life.
        unsafe {
            let ptr = XHCI_EP0_RING_IOVA as *mut u8;
            for i in 0..0x800usize {
                ptr.add(i).write_volatile(0u8);
            }
        }

        ep0_ring = TransferRing::new(EP0_RING_CAPACITY)
            .unwrap_or_else(|_| panic!("EP0_RING_CAPACITY invalid"));
        {
            let lslot = ep0_ring.capacity() - 1;
            let ltrb = ep0_ring.build_link_trb(ep0_ring_phys);
            unsafe { write_trb_at(XHCI_EP0_RING_IOVA, lslot, ltrb) };
        }

        // Zero the Input Context region for this new device so no fields from
        // a previous device's context bleed through. ONLY the lower half: the
        // upper half is the Bulk-IN ring of an already-configured storage
        // device (WS7-06) and must not be wiped mid-life.
        // SAFETY: XHCI_INPUT_CTX_IOVA is a valid DMA page IOVA (page 5 lower).
        unsafe {
            let ptr = XHCI_INPUT_CTX_IOVA as *mut u8;
            for i in 0..0x800usize {
                ptr.add(i).write_volatile(0u8);
            }
        }

        // Transition PortReset → EnableSlot.
        let first_cmd = enumerator.on_port_reset_complete(0, u64::MAX, cmd_ring.producer_cycle());
        let enable_slot_trb_val = match first_cmd {
            Some(EnumCommand::CommandRingTrb(trb)) => trb,
            _ => {
                write("[xhci] port ");
                write_hex32(u32::from(port));
                write(": on_port_reset_complete returned no command — skip\n");
                continue 'port_scan;
            }
        };

        submit_command(
            &mut cmd_ring,
            cmd_ring_phys,
            enable_slot_trb_val,
            &mut mmio,
            db_base,
            db_slot0_offset,
        );
        write("[xhci] port ");
        write_hex32(u32::from(port));
        write(": Enable Slot submitted\n");

        // Enumeration event loop.
        let mut enum_polls: u32 = 0;
        'enum_loop: loop {
            if enum_polls >= ENUM_POLL_BUDGET {
                write("[xhci] port ");
                write_hex32(u32::from(port));
                write(": enumeration timeout — skip\n");
                continue 'port_scan;
            }
            enum_polls = enum_polls.saturating_add(1);

            let Some(event_trb) =
                poll_event_ring(&mut event_ring, event_ring_phys, ir0_base, &mut mmio, 1)
            else {
                task_yield();
                continue;
            };

            if enumerator.is_finished() {
                break 'enum_loop;
            }

            // Read descriptor buffer for the GetDeviceDescriptor state.
            // SAFETY: XHCI_DATA_BUF_IOVA is a valid DMA page; 18 bytes < 4096.
            let descriptor_buf: &[u8] =
                unsafe { core::slice::from_raw_parts(XHCI_DATA_BUF_IOVA as *const u8, 18) };

            // Extract slot_id from event TRB for DCBAA setup.
            #[allow(clippy::cast_possible_truncation)]
            let event_slot_id = (event_trb.dwords()[3] >> 24) as u8;

            let next_cmd = enumerator.on_event(
                &event_trb,
                input_ctx_phys,
                data_buf_phys,
                descriptor_buf,
                u64::from(enum_polls),
                u64::MAX,
                cmd_ring.producer_cycle(),
            );

            match next_cmd {
                Some(EnumCommand::CommandRingTrb(trb)) => {
                    // Address Device: build Input Context first.
                    let slot_id = event_slot_id;
                    let ep0_mps = ep0_max_packet_for_speed(port_speed);

                    // SAFETY: XHCI_INPUT_CTX_IOVA is a valid DMA page IOVA.
                    let ic_buf: &mut [u8] = unsafe {
                        core::slice::from_raw_parts_mut(XHCI_INPUT_CTX_IOVA as *mut u8, 0x1000)
                    };

                    write_input_control_context(ic_buf, ctx_size, 0b11, 0);

                    write_slot_context(
                        &mut ic_buf[ctx_size..],
                        ctx_size,
                        0,
                        port_speed,
                        port,
                        1, // context_entries = 1 (EP0 only for Address Device)
                    );

                    let dcs_ptr = ep0_ring.dequeue_ptr_with_dcs(ep0_ring_phys);
                    write_ep0_context(
                        &mut ic_buf[2 * ctx_size..],
                        ctx_size,
                        dcs_ptr,
                        ep0_mps,
                        true,
                    );

                    // Write output context pointer into DCBAA[slot_id].
                    // SAFETY: XHCI_DCBAA_IOVA is a valid DMA page IOVA.
                    let dcbaa_buf: &mut [u8] = unsafe {
                        core::slice::from_raw_parts_mut(XHCI_DCBAA_IOVA as *mut u8, 0x1000)
                    };
                    // Each device gets a distinct output-context frame —
                    // aliasing DCBAA entries would let the controller
                    // overwrite one device's context with another's.
                    let ctx_phys = *output_ctx_choices
                        .get(output_ctx_next)
                        .unwrap_or(&output_ctx_phys);
                    write_dcbaa_entry(dcbaa_buf, slot_id, ctx_phys);
                    output_ctx_next += 1;

                    submit_command(
                        &mut cmd_ring,
                        cmd_ring_phys,
                        trb,
                        &mut mmio,
                        db_base,
                        db_slot0_offset,
                    );

                    write("[xhci] port ");
                    write_hex32(u32::from(port));
                    write(": Address Device submitted slot=");
                    write_hex32(u32::from(slot_id));
                    write("\n");
                }

                Some(EnumCommand::Ep0Transfer {
                    slot_id,
                    setup,
                    data,
                    status,
                }) => {
                    submit_ep0_transfer(
                        &mut ep0_ring,
                        ep0_ring_phys,
                        slot_id,
                        setup,
                        data,
                        status,
                        &mut mmio,
                        db_base,
                    );
                    write("[xhci] port ");
                    write_hex32(u32::from(port));
                    write(": GET_DESCRIPTOR submitted slot=");
                    write_hex32(u32::from(slot_id));
                    write("\n");
                }

                None => {
                    if enumerator.is_finished() {
                        break 'enum_loop;
                    }
                }
            }
        } // 'enum_loop

        // ---- Drain the STATUS stage Transfer Event from GET_DESCRIPTOR(Device) ----
        //
        // `'enum_loop` breaks as soon as `on_event` transitions the Enumerator to
        // `Enumerated` — which happens when the DATA stage Transfer Event for
        // GET_DESCRIPTOR(Device) arrives.  Because the STATUS stage TRB has IOC=1,
        // the controller generates a second Transfer Event for the status stage.
        // That event is still on the ring at this point: it MUST be consumed here,
        // before the config descriptor fetch, or it will be mistakenly treated as
        // the DATA event for the first GET_DESCRIPTOR(Configuration) call.
        {
            let mut drain_polls: u32 = 0;
            while drain_polls < CTRL_XFER_POLL_BUDGET {
                drain_polls = drain_polls.saturating_add(1);
                if let Some(ev) =
                    poll_event_ring(&mut event_ring, event_ring_phys, ir0_base, &mut mmio, 1)
                {
                    // Consume whatever arrives; Transfer Event means status stage done.
                    if ev.trb_type() == nexacore_driver_xhci::trb::TRB_TYPE_TRANSFER_EVENT {
                        break;
                    }
                    // Non-TE events (unexpected at this point) are silently dropped.
                } else {
                    task_yield();
                }
            }
        }

        // ---- Check enumeration result ----
        let (vid, pid, slot_id, speed, _ep0_mps) = match enumerator.enumerated_device_full() {
            Some(d) => d,
            None => {
                write("[xhci] port ");
                write_hex32(u32::from(port));
                write(": enumeration failed\n");
                continue 'port_scan;
            }
        };

        write("[xhci] port ");
        write_hex32(u32::from(port));
        write(": enumerated VID=");
        write_hex16(vid);
        write(" PID=");
        write_hex16(pid);
        write(" slot=");
        write_hex32(u32::from(slot_id));
        write(" speed=");
        write_hex8(speed);
        write("\n");

        // ---- Config descriptor fetch (two GET_DESCRIPTOR(Configuration) calls) ----
        //
        // First call: 9 bytes to get wTotalLength.
        // Second call: wTotalLength bytes to get the full descriptor.
        //
        // Both use the data buffer page (XHCI_DATA_BUF_IOVA).
        // Max config descriptor we handle: 255 bytes (fits in the 4 KiB page).
        const MAX_CONFIG_LEN: u16 = 255;

        // First GET_DESCRIPTOR(Configuration, 9 bytes).
        {
            let setup_data = get_descriptor_setup(0x02, 0, 9);
            let setup = setup_stage_trb(setup_data, 3, ep0_ring.producer_cycle());
            let data = data_stage_trb(data_buf_phys, 9, true, ep0_ring.producer_cycle());
            let status = status_stage_trb(false, ep0_ring.producer_cycle());
            submit_ep0_transfer(
                &mut ep0_ring,
                ep0_ring_phys,
                slot_id,
                setup,
                data,
                status,
                &mut mmio,
                db_base,
            );
        }
        // Drain transfer events for the 3-TRB sequence (DATA event is what we need).
        let mut xfer_polls = 0u32;
        let mut got_data_event = false;
        while xfer_polls < CTRL_XFER_POLL_BUDGET {
            xfer_polls = xfer_polls.saturating_add(1);
            let Some(ev) =
                poll_event_ring(&mut event_ring, event_ring_phys, ir0_base, &mut mmio, 1)
            else {
                task_yield();
                continue;
            };
            // Transfer event for the DATA stage — we need exactly one.
            if ev.trb_type() == nexacore_driver_xhci::trb::TRB_TYPE_TRANSFER_EVENT {
                got_data_event = true;
                break;
            }
        }
        if !got_data_event {
            write("[xhci] port ");
            write_hex32(u32::from(port));
            write(": config header fetch timeout — skip\n");
            continue 'port_scan;
        }

        // Also drain the STATUS stage event.
        {
            let mut p = 0u32;
            while p < CTRL_XFER_POLL_BUDGET {
                p = p.saturating_add(1);
                if let Some(ev) =
                    poll_event_ring(&mut event_ring, event_ring_phys, ir0_base, &mut mmio, 1)
                {
                    if ev.trb_type() == nexacore_driver_xhci::trb::TRB_TYPE_TRANSFER_EVENT {
                        break;
                    }
                } else {
                    task_yield();
                }
            }
        }

        // Read wTotalLength from the 9-byte header in data buffer.
        // SAFETY: XHCI_DATA_BUF_IOVA is a valid DMA page; 9 bytes < 4096.
        let total_length: u16 = unsafe {
            let base = XHCI_DATA_BUF_IOVA as *const u8;
            let lo = base.add(2).read_volatile();
            let hi = base.add(3).read_volatile();
            u16::from_le_bytes([lo, hi])
        };

        let fetch_len = if !(9..=MAX_CONFIG_LEN).contains(&total_length) {
            write("[xhci] port ");
            write_hex32(u32::from(port));
            write(": wTotalLength=");
            write_hex16(total_length);
            write(" out of range — use 9\n");
            9u16
        } else {
            total_length
        };

        // Second GET_DESCRIPTOR(Configuration, fetch_len bytes).
        {
            let setup_data = get_descriptor_setup(0x02, 0, fetch_len);
            let setup = setup_stage_trb(setup_data, 3, ep0_ring.producer_cycle());
            let data = data_stage_trb(
                data_buf_phys,
                u32::from(fetch_len),
                true,
                ep0_ring.producer_cycle(),
            );
            let status = status_stage_trb(false, ep0_ring.producer_cycle());
            submit_ep0_transfer(
                &mut ep0_ring,
                ep0_ring_phys,
                slot_id,
                setup,
                data,
                status,
                &mut mmio,
                db_base,
            );
        }
        // Drain DATA event.
        xfer_polls = 0;
        got_data_event = false;
        while xfer_polls < CTRL_XFER_POLL_BUDGET {
            xfer_polls = xfer_polls.saturating_add(1);
            let Some(ev) =
                poll_event_ring(&mut event_ring, event_ring_phys, ir0_base, &mut mmio, 1)
            else {
                task_yield();
                continue;
            };
            if ev.trb_type() == nexacore_driver_xhci::trb::TRB_TYPE_TRANSFER_EVENT {
                got_data_event = true;
                break;
            }
        }
        if !got_data_event {
            write("[xhci] port ");
            write_hex32(u32::from(port));
            write(": full config fetch timeout — skip\n");
            continue 'port_scan;
        }
        // Drain STATUS event.
        {
            let mut p = 0u32;
            while p < CTRL_XFER_POLL_BUDGET {
                p = p.saturating_add(1);
                if let Some(ev) =
                    poll_event_ring(&mut event_ring, event_ring_phys, ir0_base, &mut mmio, 1)
                {
                    if ev.trb_type() == nexacore_driver_xhci::trb::TRB_TYPE_TRANSFER_EVENT {
                        break;
                    }
                } else {
                    task_yield();
                }
            }
        }

        // ---- Parse config descriptor and dispatch by interface class ----
        let config_data: &[u8] = unsafe {
            core::slice::from_raw_parts(XHCI_DATA_BUF_IOVA as *const u8, usize::from(fetch_len))
        };

        let (config_hdr, nested) = match parse_configuration_header(config_data) {
            Ok(r) => r,
            Err(_) => {
                write("[xhci] port ");
                write_hex32(u32::from(port));
                write(": config descriptor parse error — skip\n");
                continue 'port_scan;
            }
        };

        // Collect the bulk endpoints for this device.
        let mut found_bulk_out_ep: Option<(u8, u16)> = None; // (ep_number, mps)
        let mut found_bulk_in_ep: Option<(u8, u16)> = None;
        let mut is_mass_storage = false;
        let mut interface_class: u8 = 0;
        // HID interface facts (WS7-06): interface number, boot-keyboard
        // flag, and the first interrupt-IN endpoint (number, mps, bInterval).
        let mut is_hid = false;
        let mut in_hid_iface = false;
        let mut hid_iface_num: u8 = 0;
        let mut hid_is_boot_kbd = false;
        let mut hid_int_in_ep: Option<(u8, u16, u8)> = None;

        let _ = walk_config_descriptors(nested, |item| match item {
            ConfigDescItem::Interface(iface) => {
                interface_class = iface.interface_class;
                in_hid_iface = false;
                if iface.interface_class == 0x08
                    && iface.interface_sub_class == 0x06
                    && iface.interface_protocol == 0x50
                {
                    is_mass_storage = true;
                }
                // HID class 0x03: subclass 1 + protocol 1 = boot keyboard;
                // anything else (e.g. the QEMU tablet: subclass 0/protocol 0)
                // is handled via its report descriptor.
                if iface.interface_class == 0x03 && !is_hid {
                    is_hid = true;
                    in_hid_iface = true;
                    hid_iface_num = iface.interface_number;
                    hid_is_boot_kbd =
                        iface.interface_sub_class == 0x01 && iface.interface_protocol == 0x01;
                }
            }
            ConfigDescItem::Endpoint(ep) => {
                // Only collect endpoints if we are in the storage interface.
                if is_mass_storage {
                    // bmAttributes bits 1:0 = transfer type; 0x02 = Bulk.
                    if (ep.attributes & 0x03) == 0x02 {
                        let ep_number = ep.address & 0x7F;
                        let is_in = (ep.address & 0x80) != 0;
                        if is_in && found_bulk_in_ep.is_none() {
                            found_bulk_in_ep = Some((ep_number, ep.max_packet_size));
                        } else if !is_in && found_bulk_out_ep.is_none() {
                            found_bulk_out_ep = Some((ep_number, ep.max_packet_size));
                        }
                    }
                }
                // First interrupt-IN endpoint of the HID interface (WS7-06).
                if in_hid_iface
                    && hid_int_in_ep.is_none()
                    && (ep.attributes & 0x03) == 0x03
                    && (ep.address & 0x80) != 0
                {
                    hid_int_in_ep = Some((ep.address & 0x7F, ep.max_packet_size, ep.interval));
                }
            }
            ConfigDescItem::Unknown(_, _) => {}
        });

        // ---- HID device (WS7-06): configure and stash, then next port ----
        if is_hid && !is_mass_storage {
            hid_setup_device(
                port,
                slot_id,
                port_speed,
                config_hdr.configuration_value,
                hid_iface_num,
                hid_is_boot_kbd,
                hid_int_in_ep,
                &mut hid_rt,
                &mut ep0_ring,
                ep0_ring_phys,
                (hid_kbd_ring_phys, hid_ptr_ring_phys),
                (hid_kbd_report_phys, hid_ptr_report_phys),
                input_ctx_phys,
                data_buf_phys,
                ctx_size,
                &mut cmd_ring,
                cmd_ring_phys,
                db_slot0_offset,
                &mut event_ring,
                event_ring_phys,
                ir0_base,
                &mut mmio,
                db_base,
            );
            continue 'port_scan;
        }

        if !is_mass_storage {
            write("[xhci] port ");
            write_hex32(u32::from(port));
            write(": device class=");
            write_hex8(interface_class);
            write(" — skipping (Phase 2b)\n");
            continue 'port_scan;
        }

        let (bulk_out_ep_num, bulk_out_mps) = match found_bulk_out_ep {
            Some(v) => v,
            None => {
                write("[xhci] port ");
                write_hex32(u32::from(port));
                write(": mass storage: no bulk-OUT endpoint — skip\n");
                continue 'port_scan;
            }
        };
        let (bulk_in_ep_num, bulk_in_mps) = match found_bulk_in_ep {
            Some(v) => v,
            None => {
                write("[xhci] port ");
                write_hex32(u32::from(port));
                write(": mass storage: no bulk-IN endpoint — skip\n");
                continue 'port_scan;
            }
        };

        // DCI = 2*ep_number + direction_bit (1 for IN, 0 for OUT).
        let out_dci: u32 = 2 * u32::from(bulk_out_ep_num);
        let in_dci: u32 = 2 * u32::from(bulk_in_ep_num) + 1;
        // context_entries = highest DCI present.
        let max_dci = core::cmp::max(out_dci, in_dci);
        #[allow(clippy::cast_possible_truncation)]
        let context_entries = max_dci as u8;

        write("[xhci] port ");
        write_hex32(u32::from(port));
        write(": mass storage bulk-OUT EP");
        write_hex32(u32::from(bulk_out_ep_num));
        write(" DCI=");
        write_hex32(out_dci);
        write(" bulk-IN EP");
        write_hex32(u32::from(bulk_in_ep_num));
        write(" DCI=");
        write_hex32(in_dci);
        write("\n");

        // ---- SET_CONFIGURATION ----
        {
            let setup_data = set_configuration_setup(config_hdr.configuration_value);
            // SET_CONFIGURATION is an OUT control transfer with no data phase.
            // TRT = 0 (No Data). We still need a STATUS phase (IN).
            let setup = setup_stage_trb(setup_data, 0, ep0_ring.producer_cycle());
            // Status stage for OUT control with no data = IN direction (dir_in=true).
            let status = status_stage_trb(true, ep0_ring.producer_cycle());

            // Submit SETUP + STATUS (no DATA stage for zero-length OUT).
            let s_idx = ep0_ring.enqueue();
            unsafe {
                write_trb_at(
                    XHCI_EP0_RING_IOVA,
                    s_idx,
                    setup.with_cycle_bit(ep0_ring.producer_cycle()),
                )
            };
            let st_idx = ep0_ring.enqueue();
            unsafe {
                write_trb_at(
                    XHCI_EP0_RING_IOVA,
                    st_idx,
                    status.with_cycle_bit(ep0_ring.producer_cycle()),
                )
            };
            let lslot = ep0_ring.capacity() - 1;
            let ltrb = ep0_ring.build_link_trb(ep0_ring_phys);
            unsafe { write_trb_at(XHCI_EP0_RING_IOVA, lslot, ltrb) };
            if let Some(db_off) = doorbell_offset(slot_id) {
                mmio.write_u32(db_base + db_off, 1);
            }
        }
        // Drain STATUS event for SET_CONFIGURATION.
        {
            let mut p = 0u32;
            while p < CTRL_XFER_POLL_BUDGET {
                p = p.saturating_add(1);
                if let Some(ev) =
                    poll_event_ring(&mut event_ring, event_ring_phys, ir0_base, &mut mmio, 1)
                {
                    if ev.trb_type() == nexacore_driver_xhci::trb::TRB_TYPE_TRANSFER_EVENT {
                        break;
                    }
                } else {
                    task_yield();
                }
            }
        }
        write("[xhci] port ");
        write_hex32(u32::from(port));
        write(": SET_CONFIGURATION done\n");

        // ---- Configure Endpoint: add bulk-IN + bulk-OUT contexts ----
        //
        // Build a new Input Context with:
        //   Input Control Context: add_flags = bit0 (Slot) | bit(out_dci) | bit(in_dci)
        //   Slot Context: context_entries = max_dci
        //   EP contexts: one per DCI from 2 to max_dci (only our two bulk EPs)
        //
        // The bulk-IN and bulk-OUT rings share page 4 upper / page 5 upper
        // respectively. Their physical addresses are pre-computed offsets into
        // the already-mapped pages.
        {
            // SAFETY: XHCI_INPUT_CTX_IOVA is a valid DMA page IOVA; the input
            // context occupies the lower half only (the upper half is the
            // live Bulk-IN ring — see the WS7-06 zeroing notes above).
            let ic_buf: &mut [u8] =
                unsafe { core::slice::from_raw_parts_mut(XHCI_INPUT_CTX_IOVA as *mut u8, 0x800) };

            // Zero the Input Context region first.
            ic_buf.fill(0);

            // add_flags: bit 0 (Slot) + bit out_dci + bit in_dci.
            let add_flags: u32 = 1u32 | (1u32 << out_dci) | (1u32 << in_dci);
            write_input_control_context(ic_buf, ctx_size, add_flags, 0);

            // Slot Context: preserve speed + port; update context_entries.
            write_slot_context(
                &mut ic_buf[ctx_size..],
                ctx_size,
                0,
                port_speed,
                port,
                context_entries,
            );

            // EP0 context (DCI 1) — carried from the Address Device state.
            let ep0_mps = ep0_max_packet_for_speed(port_speed);
            let dcs_ptr = ep0_ring.dequeue_ptr_with_dcs(ep0_ring_phys);
            write_ep0_context(
                &mut ic_buf[2 * ctx_size..],
                ctx_size,
                dcs_ptr,
                ep0_mps,
                true,
            );

            // Bulk-OUT endpoint context at DCI = out_dci.
            // Offset in Input Context = (out_dci + 1) * ctx_size
            // (+1 because index 0 is the Input Control Context).
            let bulk_out_dcs = bulk_out_ring.dequeue_ptr_with_dcs(bulk_out_ring_phys);
            let bulk_out_ctx_off = (usize::try_from(out_dci).unwrap_or(2) + 1) * ctx_size;
            write_endpoint_context(
                &mut ic_buf[bulk_out_ctx_off..],
                ctx_size,
                EndpointType::BulkOut,
                bulk_out_mps,
                0,
                bulk_out_dcs,
            );

            // Bulk-IN endpoint context at DCI = in_dci.
            let bulk_in_dcs = bulk_in_ring.dequeue_ptr_with_dcs(bulk_in_ring_phys);
            let bulk_in_ctx_off = (usize::try_from(in_dci).unwrap_or(3) + 1) * ctx_size;
            write_endpoint_context(
                &mut ic_buf[bulk_in_ctx_off..],
                ctx_size,
                EndpointType::BulkIn,
                bulk_in_mps,
                0,
                bulk_in_dcs,
            );

            // Submit Configure Endpoint command.
            let cfg_ep_trb =
                configure_endpoint_trb(input_ctx_phys, slot_id, cmd_ring.producer_cycle());
            submit_command(
                &mut cmd_ring,
                cmd_ring_phys,
                cfg_ep_trb,
                &mut mmio,
                db_base,
                db_slot0_offset,
            );
        }

        // Wait for Configure Endpoint command completion event.
        let cfg_ep_ok = {
            let mut ok = false;
            let mut p = 0u32;
            while p < ENUM_POLL_BUDGET {
                p = p.saturating_add(1);
                let Some(ev) =
                    poll_event_ring(&mut event_ring, event_ring_phys, ir0_base, &mut mmio, 1)
                else {
                    task_yield();
                    continue;
                };
                if ev.trb_type() == nexacore_driver_xhci::trb::TRB_TYPE_COMMAND_COMPLETION_EVENT {
                    let cc = (ev.dwords()[2] >> 24) as u8;
                    ok = cc == nexacore_driver_xhci::trb::COMPLETION_CODE_SUCCESS;
                    if !ok {
                        write("[xhci] Configure Endpoint failed code=");
                        write_hex8(cc);
                        write("\n");
                    }
                    break;
                }
            }
            ok
        };

        if !cfg_ep_ok {
            write("[xhci] port ");
            write_hex32(u32::from(port));
            write(": Configure Endpoint failed — skip\n");
            continue 'port_scan;
        }

        write("[xhci] port ");
        write_hex32(u32::from(port));
        write(": Configure Endpoint OK\n");

        // ---- BOT storage init: TEST UNIT READY + INQUIRY + READ CAPACITY ----

        let eps = BulkEndpoints {
            out_dci,
            in_dci,
            out_mps: bulk_out_mps,
            in_mps: bulk_in_mps,
        };

        // TEST UNIT READY (tag=1, no data).
        // data_phys is unused (data_len=0) but must be a valid physical address.
        let tur_cdb = cdb_test_unit_ready();
        let tur_ok = bot_execute(
            1,
            0,
            false,
            0,
            &tur_cdb,
            data_buf_phys,      // data_phys: unused (data_len=0)
            data_buf_phys,      // cbw_buf_phys: CBW at +0x000, CSW at +0x040
            XHCI_DATA_BUF_IOVA, // cbw_buf_iova
            &mut bulk_out_ring,
            bulk_out_ring_phys,
            &mut bulk_in_ring,
            bulk_in_ring_phys,
            &eps,
            slot_id,
            &mut event_ring,
            event_ring_phys,
            ir0_base,
            &mut mmio,
            db_base,
            &mut hid_rt,
        );
        if !tur_ok {
            write("[xhci] port ");
            write_hex32(u32::from(port));
            write(": TUR failed (device not ready?)\n");
            // Non-fatal: some devices need a moment. Continue anyway.
        } else {
            write("[xhci] port ");
            write_hex32(u32::from(port));
            write(": TUR OK\n");
        }

        // INQUIRY (tag=2, 36 bytes IN).
        // Physical DMA target: data_buf_phys + 0x80 (controller writes here).
        // CPU reads the response at IOVA: XHCI_DATA_BUF_IOVA + 0x80.
        let inq_cdb = cdb_inquiry(INQUIRY_RESPONSE_MIN_LEN as u8);
        let inq_data_phys = data_buf_phys + 0x80;
        let inq_data_iova = XHCI_DATA_BUF_IOVA + 0x80;
        let inq_ok = bot_execute(
            2,
            INQUIRY_RESPONSE_MIN_LEN as u32,
            true,
            0,
            &inq_cdb,
            inq_data_phys,      // data_phys: physical target for INQUIRY data
            data_buf_phys,      // cbw_buf_phys: CBW at +0x000, CSW at +0x040
            XHCI_DATA_BUF_IOVA, // cbw_buf_iova
            &mut bulk_out_ring,
            bulk_out_ring_phys,
            &mut bulk_in_ring,
            bulk_in_ring_phys,
            &eps,
            slot_id,
            &mut event_ring,
            event_ring_phys,
            ir0_base,
            &mut mmio,
            db_base,
            &mut hid_rt,
        );
        if inq_ok {
            // SAFETY: inq_data_iova is within the data buffer page (IOVA of the
            // same physical frame that received the INQUIRY response); 36 bytes.
            let inq_bytes: [u8; INQUIRY_RESPONSE_MIN_LEN] = unsafe {
                let src = inq_data_iova as *const u8;
                let mut arr = [0u8; INQUIRY_RESPONSE_MIN_LEN];
                for (i, b) in arr.iter_mut().enumerate() {
                    *b = src.add(i).read_volatile();
                }
                arr
            };
            if let Ok(inq) = parse_inquiry(&inq_bytes) {
                write("[xhci] usb-storage: vendor=");
                // Print vendor bytes as ASCII, stopping at first space/NUL.
                for &b in &inq.vendor {
                    if b == b' ' || b == 0 {
                        break;
                    }
                    let s = &[b];
                    if let Ok(ch) = core::str::from_utf8(s) {
                        write(ch);
                    }
                }
                write(" product=");
                for &b in &inq.product {
                    if b == b' ' || b == 0 {
                        break;
                    }
                    let s = &[b];
                    if let Ok(ch) = core::str::from_utf8(s) {
                        write(ch);
                    }
                }
                write("\n");
            }
        }

        // READ CAPACITY(10) (tag=3, 8 bytes IN).
        // Physical DMA target: data_buf_phys + 0xC0 (controller writes here).
        // CPU reads the response at IOVA: XHCI_DATA_BUF_IOVA + 0xC0.
        let rc_cdb = cdb_read_capacity10();
        let rc_data_phys = data_buf_phys + 0xC0;
        let rc_data_iova = XHCI_DATA_BUF_IOVA + 0xC0;
        let rc_ok = bot_execute(
            3,
            8,
            true,
            0,
            &rc_cdb,
            rc_data_phys,       // data_phys: physical target for READ CAPACITY data
            data_buf_phys,      // cbw_buf_phys: CBW at +0x000, CSW at +0x040
            XHCI_DATA_BUF_IOVA, // cbw_buf_iova
            &mut bulk_out_ring,
            bulk_out_ring_phys,
            &mut bulk_in_ring,
            bulk_in_ring_phys,
            &eps,
            slot_id,
            &mut event_ring,
            event_ring_phys,
            ir0_base,
            &mut mmio,
            db_base,
            &mut hid_rt,
        );
        // Parse READ CAPACITY and retain `last_lba` for the self-test below.
        let mut selftest_lba: u32 = 0;
        if rc_ok {
            // SAFETY: rc_data_iova is within the data buffer page (IOVA of the
            // same physical frame that received the READ CAPACITY(10) response).
            let rc_bytes: [u8; 8] = unsafe {
                let src = rc_data_iova as *const u8;
                let mut arr = [0u8; 8];
                for (i, b) in arr.iter_mut().enumerate() {
                    *b = src.add(i).read_volatile();
                }
                arr
            };
            if let Ok((last_lba, block_size)) = parse_read_capacity10(&rc_bytes) {
                write("[xhci] usb-storage: last_lba=");
                write_hex32(last_lba);
                write(" block_size=");
                write_hex32(block_size);
                write("\n");
                // Use last_lba as the scratch target so we don't disturb LBA 0.
                selftest_lba = last_lba;
            }
        }

        write("[xhci] usb-storage: storage init done slot=");
        write_hex32(u32::from(slot_id));
        write("\n");

        // ---- One-shot write/read-back self-test ----
        //
        // Verifies the full BOT R/W path byte-identically on a scratch LBA.
        //
        // DMA layout for the self-test:
        //   data buffer  : page 7 (`data_buf_phys` / `XHCI_DATA_BUF_IOVA`) — 4096 B
        //   CBW/CSW scratch: page 5 lower (`input_ctx_phys` / `XHCI_INPUT_CTX_IOVA`)
        //
        // Page 5 (Input Context) was last written during Configure Endpoint and
        // is not needed again; borrowing its physical frame for the CBW/CSW
        // scratch avoids any layout overlap with the 4 KiB data buffer on page 7.
        //
        // Step 1: READ the scratch LBA into the bounce (save original[0..16]).
        // Step 2: fill bounce with a recognisable pattern, WRITE to scratch LBA.
        // Step 3: zero the bounce, READ the scratch LBA back.
        // Step 4: compare bounce to pattern; log result.
        {
            // 4096-byte block: matches the device's reported block_size.
            const ST_BLOCK_BYTES: u32 = 4096;
            let st_lba = selftest_lba;

            // CBW/CSW scratch: page 5 lower half (Input Context page).
            // This page is fully zeroed and not in active DMA use at this point.
            let st_cbw_phys = input_ctx_phys;
            let st_cbw_iova = XHCI_INPUT_CTX_IOVA;

            // Data buffer: full page 7 (4096 bytes).
            let st_data_phys = data_buf_phys;
            let st_data_iova = XHCI_DATA_BUF_IOVA;

            // ---- Step 1: READ original block ----
            write("[xhci] usb-storage: selftest READ-original lba=");
            write_hex32(st_lba);
            write("\n");
            let rd1_cdb = cdb_read10(st_lba, 1);
            let rd1_ok = bot_execute(
                4,
                ST_BLOCK_BYTES,
                true,
                0,
                &rd1_cdb,
                st_data_phys, // data_phys: full page 7 (4096 B)
                st_cbw_phys,  // cbw_buf_phys: page 5 lower (CBW at +0x000, CSW at +0x040)
                st_cbw_iova,  // cbw_buf_iova
                &mut bulk_out_ring,
                bulk_out_ring_phys,
                &mut bulk_in_ring,
                bulk_in_ring_phys,
                &eps,
                slot_id,
                &mut event_ring,
                event_ring_phys,
                ir0_base,
                &mut mmio,
                db_base,
                &mut hid_rt,
            );
            if !rd1_ok {
                write("[xhci] usb-storage: selftest READ-original failed\n");
            } else {
                // Save original first 16 bytes so they can be logged.
                // SAFETY: st_data_iova is a valid DMA page IOVA; 16 bytes within page.
                let orig16: [u8; 16] = unsafe {
                    let src = st_data_iova as *const u8;
                    let mut arr = [0u8; 16];
                    for (i, b) in arr.iter_mut().enumerate() {
                        *b = src.add(i).read_volatile();
                    }
                    arr
                };
                write("[xhci] usb-storage: selftest orig[0..4]=");
                write_hex32(u32::from_le_bytes([
                    orig16[0], orig16[1], orig16[2], orig16[3],
                ]));
                write("\n");

                // ---- Step 2: fill pattern + WRITE ----
                //
                // Pattern: byte i = (i as u8) ^ 0x5A.
                // SAFETY: st_data_iova is a valid DMA page IOVA; 4096 bytes within page.
                unsafe {
                    let dst = st_data_iova as *mut u8;
                    for i in 0..4096usize {
                        #[allow(clippy::cast_possible_truncation)]
                        dst.add(i).write_volatile((i as u8) ^ 0x5A);
                    }
                }
                write("[xhci] usb-storage: selftest WRITE pattern lba=");
                write_hex32(st_lba);
                write("\n");
                let wr_cdb = cdb_write10(st_lba, 1);
                let wr_ok = bot_execute(
                    5,
                    ST_BLOCK_BYTES,
                    false,
                    0,
                    &wr_cdb,
                    st_data_phys, // data_phys: pattern in page 7 (4096 B)
                    st_cbw_phys,  // cbw_buf_phys
                    st_cbw_iova,  // cbw_buf_iova
                    &mut bulk_out_ring,
                    bulk_out_ring_phys,
                    &mut bulk_in_ring,
                    bulk_in_ring_phys,
                    &eps,
                    slot_id,
                    &mut event_ring,
                    event_ring_phys,
                    ir0_base,
                    &mut mmio,
                    db_base,
                    &mut hid_rt,
                );
                if !wr_ok {
                    write("[xhci] usb-storage: selftest WRITE failed\n");
                } else {
                    // ---- Step 3: zero bounce, READ back ----
                    // SAFETY: st_data_iova is a valid DMA page IOVA; 4096 bytes.
                    unsafe {
                        let dst = st_data_iova as *mut u8;
                        for i in 0..4096usize {
                            dst.add(i).write_volatile(0u8);
                        }
                    }
                    write("[xhci] usb-storage: selftest READ-back lba=");
                    write_hex32(st_lba);
                    write("\n");
                    let rd2_cdb = cdb_read10(st_lba, 1);
                    let rd2_ok = bot_execute(
                        6,
                        ST_BLOCK_BYTES,
                        true,
                        0,
                        &rd2_cdb,
                        st_data_phys, // data_phys: page 7 (device writes here)
                        st_cbw_phys,  // cbw_buf_phys
                        st_cbw_iova,  // cbw_buf_iova
                        &mut bulk_out_ring,
                        bulk_out_ring_phys,
                        &mut bulk_in_ring,
                        bulk_in_ring_phys,
                        &eps,
                        slot_id,
                        &mut event_ring,
                        event_ring_phys,
                        ir0_base,
                        &mut mmio,
                        db_base,
                        &mut hid_rt,
                    );
                    if !rd2_ok {
                        write("[xhci] usb-storage: selftest READ-back failed\n");
                    } else {
                        // ---- Step 4: compare ----
                        // SAFETY: st_data_iova is valid; 4096 bytes within page.
                        let (mismatch_idx, mismatch_wrote, mismatch_got) = unsafe {
                            let src = st_data_iova as *const u8;
                            let mut mis: Option<(usize, u8, u8)> = None;
                            for i in 0..4096usize {
                                #[allow(clippy::cast_possible_truncation)]
                                let expected = (i as u8) ^ 0x5A;
                                let got = src.add(i).read_volatile();
                                if got != expected && mis.is_none() {
                                    mis = Some((i, expected, got));
                                }
                            }
                            match mis {
                                Some((idx, wr, gt)) => (idx, wr, gt),
                                None => (4096, 0, 0), // sentinel: no mismatch
                            }
                        };

                        // Log first 8 bytes of read-back.
                        // SAFETY: st_data_iova is valid; 8 bytes within page.
                        let rb8: [u8; 8] = unsafe {
                            let src = st_data_iova as *const u8;
                            let mut arr = [0u8; 8];
                            for (i, b) in arr.iter_mut().enumerate() {
                                *b = src.add(i).read_volatile();
                            }
                            arr
                        };
                        write("[xhci] usb-storage: readback[0..4]=");
                        write_hex32(u32::from_le_bytes([rb8[0], rb8[1], rb8[2], rb8[3]]));
                        write(" [4..8]=");
                        write_hex32(u32::from_le_bytes([rb8[4], rb8[5], rb8[6], rb8[7]]));
                        write("\n");

                        if mismatch_idx == 4096 {
                            write("[xhci] usb-storage: write/read-back @LBA=");
                            write_hex32(st_lba);
                            write(" BYTE-IDENTICAL (4096 bytes)\n");
                        } else {
                            write("[xhci] usb-storage: write/read-back @LBA=");
                            write_hex32(st_lba);
                            write(" MISMATCH at byte ");
                            write_hex32(mismatch_idx as u32);
                            write(" wrote=");
                            write_hex8(mismatch_wrote);
                            write(" got=");
                            write_hex8(mismatch_got);
                            write("\n");
                        }

                        // ---- Optional step 5: restore original block ----
                        // SAFETY: st_data_iova valid; orig16 has been saved.
                        // We only saved 16 bytes, so restore is skipped (scratch image).
                        // If needed: re-write orig16 to the LBA here.
                        let _ = orig16; // suppress unused warning; restore not required
                    }
                }
            }
        }

        storage_slot_id = Some(slot_id);
        storage_eps = Some(eps);
    } // 'port_scan

    // -------------------------------------------------------------------------
    // 16b. Arm the HID interrupt-IN rings (WS7-06).
    //
    // Done AFTER the whole port scan so no HID transfer event can interleave
    // with the enumeration event loops. From here on, every event-ring drain
    // goes through `poll_event_ring_routed` / `HidRuntime::try_consume`.
    // -------------------------------------------------------------------------
    hid_rt.arm_all(&mut mmio, db_base);

    // -------------------------------------------------------------------------
    // 17. BLK service registration.
    //
    // If no storage device was found, serve HID input alone (WS7-06) — or
    // plain idle when there is no HID either.
    // Otherwise register `usb0` + `usb0-reply` channels and enter the serve loop.
    // -------------------------------------------------------------------------
    let (slot_id, eps) = match (storage_slot_id, storage_eps) {
        (Some(s), Some(e)) => (s, e),
        _ => {
            write("[xhci] no USB storage found — HID-only service\n");
            loop {
                // Route any pending HID events; drop stray non-HID events.
                while poll_event_ring_routed(
                    &mut event_ring,
                    event_ring_phys,
                    ir0_base,
                    &mut mmio,
                    1,
                    &mut hid_rt,
                    db_base,
                )
                .is_some()
                {}
                task_yield();
            }
        }
    };

    // Create the request channel.
    let (channel_id, _) = unsafe {
        syscall5(
            SYS_IPC_CREATE_CHANNEL,
            BLK_CHANNEL_QUEUE_DEPTH,
            BLK_CHANNEL_BACKPRESSURE_BLOCK,
            BLK_CHANNEL_TEE_NOT_BOUND,
            0,
            0,
        )
    };
    if channel_id == u64::MAX {
        write("[xhci] IpcCreateChannel failed for usb0\n");
        loop {
            task_yield();
        }
    }

    // Register `usb0`.
    let (_rax, blk_errno) = unsafe {
        syscall5(
            SYS_BLK_REGISTER,
            USB_DISK_SLOT.as_ptr() as u64,
            USB_DISK_SLOT.len() as u64,
            channel_id,
            0,
            0,
        )
    };
    if blk_errno != 0 {
        write("[xhci] BlkRegister usb0 failed errno=");
        write_hex32(u32::try_from(blk_errno).unwrap_or(0));
        write("\n");
        loop {
            task_yield();
        }
    }

    // Create the reply channel.
    let (reply_channel_id, _) = unsafe {
        syscall5(
            SYS_IPC_CREATE_CHANNEL,
            BLK_CHANNEL_QUEUE_DEPTH,
            BLK_CHANNEL_BACKPRESSURE_BLOCK,
            BLK_CHANNEL_TEE_NOT_BOUND,
            0,
            0,
        )
    };
    if reply_channel_id == u64::MAX {
        write("[xhci] IpcCreateChannel failed for usb0-reply\n");
        loop {
            task_yield();
        }
    }

    // Register `usb0-reply`.
    let (_rax2, blk_reply_errno) = unsafe {
        syscall5(
            SYS_BLK_REGISTER,
            USB_DISK_SLOT_REPLY.as_ptr() as u64,
            USB_DISK_SLOT_REPLY.len() as u64,
            reply_channel_id,
            0,
            0,
        )
    };
    if blk_reply_errno != 0 {
        write("[xhci] BlkRegister usb0-reply failed errno=");
        write_hex32(u32::try_from(blk_reply_errno).unwrap_or(0));
        write("\n");
        loop {
            task_yield();
        }
    }

    write("[xhci] usb-storage: BLK service registered (usb0)\n");

    // -------------------------------------------------------------------------
    // 18. BLK service loop.
    //
    // Receive BlkRequest on `usb0`, execute BOT sequence, send BlkResponse on
    // `usb0-reply`.
    //
    // Dual-address model (ADR-0036 appendix 2):
    //   - `buf_iova` from the BlkRequest is the CALLER's IOVA — it lives in
    //     the caller's address space and cannot be used as a DMA target.
    //     This driver ignores it and uses an internal bounce buffer instead,
    //     matching the NVMe driver's ADR-0036 D3 convention.
    //   - The internal bounce occupies page 7 at physical `data_buf_phys + 0x100`
    //     (IOVA `XHCI_DATA_BUF_IOVA + 0x100`), leaving 3840 bytes.
    //     For count=1 requests with 512-byte physical sectors (8 × 512 = 4096 B)
    //     a 9th DMA page is required; that is a Phase 2b follow-up.
    //     For now: accept count=1 only and return DeviceError if data_len >
    //     BOT_BOUNCE_SIZE.
    //   - For Read: after a successful BOT, the sector data resides at
    //     `XHCI_DATA_BUF_IOVA + 0x100`; it is forwarded to the caller via two
    //     IPC chunks of 2048 B (matching NVMe's ADR-0036 D3 convention).
    //   - For Write: the caller is responsible for having pre-staged data at the
    //     write target; Phase 2a does not implement inbound write data staging.
    //
    // TODO(Phase 2b): allocate a 9th DMA page as a dedicated 4 KiB sector
    // bounce to remove the BOT_BOUNCE_SIZE restriction.
    // -------------------------------------------------------------------------

    /// Maximum data-phase bytes the internal bounce buffer can hold.
    ///
    /// Page 7 (4 KiB) minus the 256-byte prefix reserved for CBW, CSW, and
    /// descriptor scratch leaves 3840 bytes.  Enough for seven 512-byte
    /// sectors but NOT a full 8-sector (4 KiB) BLK transfer.
    const BOT_BOUNCE_SIZE: u32 = 0xF00; // 3840 bytes

    // Physical base of the sector bounce region within page 7.
    let bounce_phys = data_buf_phys + 0x100;

    // IOVA of the sector bounce region (CPU-side reads after Bulk-IN).
    let bounce_iova = XHCI_DATA_BUF_IOVA + 0x100;

    let mut bot_tag: u32 = 10; // start at 10; 1-9 reserved for init

    loop {
        // Poll the request channel.
        // SAFETY: REQ_BUF is a BSS static; single-threaded exclusive access.
        let n = match ipc_try_receive(channel_id, unsafe {
            &mut *core::ptr::addr_of_mut!(REQ_BUF)
        }) {
            Some(n) => n,
            None => {
                // No BLK request pending: route any HID input events that
                // arrived since the last drain (WS7-06), then yield. Stray
                // non-HID events (none are expected between BOT sequences)
                // are dropped by the routed poll.
                while poll_event_ring_routed(
                    &mut event_ring,
                    event_ring_phys,
                    ir0_base,
                    &mut mmio,
                    1,
                    &mut hid_rt,
                    db_base,
                )
                .is_some()
                {}
                task_yield();
                continue;
            }
        };

        // Decode the BlkRequest.
        // SAFETY: REQ_BUF[..n] holds the bytes just copied by the kernel.
        let req = match decode_canonical::<BlkRequest>(unsafe {
            &(*core::ptr::addr_of!(REQ_BUF))[..n]
        }) {
            Ok(r) => r,
            Err(_) => {
                // SAFETY: RESP_BUF exclusive access.
                unsafe { send_blk_response(reply_channel_id, BlkResponse::InvalidArgument) };
                continue;
            }
        };

        // Allocate a BOT tag for this command.
        bot_tag = bot_tag.wrapping_add(1);
        if bot_tag == 0 {
            bot_tag = 1;
        }

        // Compute the data length and direction.
        // `buf_iova` from the request is intentionally ignored — see comment above.
        let (data_len, dir_in) = match &req {
            BlkRequest::Read { count, .. } => (
                count.saturating_mul(nexacore_types::blk::BLOCK_SIZE_BYTES),
                true,
            ),
            BlkRequest::Write { count, .. } => (
                count.saturating_mul(nexacore_types::blk::BLOCK_SIZE_BYTES),
                false,
            ),
            BlkRequest::Flush => (0, false),
            _ => {
                unsafe { send_blk_response(reply_channel_id, BlkResponse::NotSupported) };
                continue;
            }
        };

        // Reject transfers that exceed the bounce buffer.
        if data_len > BOT_BOUNCE_SIZE {
            unsafe { send_blk_response(reply_channel_id, BlkResponse::InvalidArgument) };
            continue;
        }

        // Build SCSI op.
        let scsi_op = match blk_request_to_scsi(&req) {
            Ok(op) => op,
            Err(_) => {
                unsafe { send_blk_response(reply_channel_id, BlkResponse::NotSupported) };
                continue;
            }
        };

        // Execute BOT sequence using the internal bounce buffer as the DMA
        // target.  Physical address `bounce_phys` goes into the TRB;
        // the CPU reads the result via IOVA `bounce_iova`.
        let ok = bot_execute(
            bot_tag,
            data_len,
            dir_in,
            0,
            &scsi_op.cdb[..scsi_op.cdb_len],
            bounce_phys,        // data_phys: physical DMA target for sector data
            data_buf_phys,      // cbw_buf_phys: CBW at +0x000, CSW at +0x040
            XHCI_DATA_BUF_IOVA, // cbw_buf_iova
            &mut bulk_out_ring,
            bulk_out_ring_phys,
            &mut bulk_in_ring,
            bulk_in_ring_phys,
            &eps,
            slot_id,
            &mut event_ring,
            event_ring_phys,
            ir0_base,
            &mut mmio,
            db_base,
            &mut hid_rt,
        );

        if ok {
            let resp = BlkResponse::Ok;
            unsafe { send_blk_response(reply_channel_id, resp) };

            // For Read requests, forward the sector data to the caller as two
            // IPC chunks (ADR-0036 D3: 2 × 2 KiB), matching the NVMe convention.
            if dir_in && data_len > 0 {
                // SAFETY: bounce_iova is a valid DMA IOVA; data_len <= BOT_BOUNCE_SIZE
                // so the slice stays within the mapped page.
                let bounce_slice: &[u8] = unsafe {
                    core::slice::from_raw_parts(bounce_iova as *const u8, data_len as usize)
                };
                let half = (data_len as usize) / 2;
                ipc_send(reply_channel_id, IPC_KIND_REPLY, &bounce_slice[..half]);
                ipc_send(reply_channel_id, IPC_KIND_REPLY, &bounce_slice[half..]);
            }
        } else {
            unsafe {
                send_blk_response(
                    reply_channel_id,
                    BlkResponse::DeviceError(nexacore_types::blk::NON_NVME_DEVICE_ERROR),
                );
            }
        }
    }
}

// =============================================================================
// Panic handler
// =============================================================================

/// On panic, exit with sentinel code 2 (matches NVMe image convention).
#[panic_handler]
fn panic(_info: &PanicInfo<'_>) -> ! {
    // SAFETY: TaskExit terminates the process unconditionally; never returns.
    unsafe { sys_exit(2) }
}
