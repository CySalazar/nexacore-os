//! NexaCore OS virtio-net bootable driver image — M0 service loop.
//!
//! `no_std + no_main` ELF entry that the kernel `DriverLoad (73)` syscall
//! ingests per `NCIP-Driver-Framework-013` § S5.3 step 9. The kernel calls
//! `spawn_from_elf` against this binary, which lands at `_start` in a
//! freshly minted Ring 3 process. Before transferring control the kernel
//! writes the per-driver capability deposit at the well-known user-VA slot
//! [`nexacore_driver_shared::DRIVER_CAP_DEPOSIT_VA`] (P6.7.8.9, NCIP-013 § S5.3
//! step 8); the image reads tokens from that window via
//! [`nexacore_driver_shared::caps::find_token`] and forwards them to the kernel
//! through the `MmioMap (70)` / `DmaMap (71)` / `IrqAttach (72)` syscalls.
//!
//! ## Execution path (M0 — service loop wired)
//!
//! 1. `find_token(ACTION_TAG_MMIO_MAP, ..)` — retrieve the MMIO token.
//! 2. `find_token(ACTION_TAG_DMA_MAP, ..)` — retrieve the DMA token.
//! 3. `find_token(ACTION_TAG_IRQ_ATTACH, ..)` — retrieve the IRQ token.
//! 4. `syscall MmioMap (70)` — map the virtio-net BAR4 region.
//! 5. `syscall DmaMap (71)` — install the 1-page IOVA arena (inside the
//!    kernel driver-DMA window `[DRIVER_DMA_VA_BASE, DRIVER_DMA_VA_END)`).
//! 6. `IpcCreateChannel × 3` — create command, event, and IRQ-notify channels.
//! 7. `syscall IrqAttach (72)` — bind virtio-net IRQ line to the irq channel
//!    (replaces the original `IPC_CHANNEL_PLACEHOLDER = 0`).
//! 8. Drive the [`nexacore_driver_net_virtio::bringup::BringUp`] FSM to
//!    `Phase::DriverOk`.
//! 9. `syscall NetRegister (100)` — register `(cmd_ch, evt_ch, MAC)` in the
//!    kernel NET registry under interface name `"virtio0"`.
//! 10. Enter the service loop:
//!     - Non-blocking `IpcReceive(irq_ch)` → `driver.poll_rx()` →
//!       encode [`NetEvent::FrameReceivedInline`] → `IpcSend(evt_ch)`.
//!     - Blocking `IpcReceive(cmd_ch)` → decode [`NetRequest`] → driver TX →
//!       encode [`NetResponse`] → `IpcSend(cmd_ch)`.
//! 11. `TaskExit(0)` is reached only if the command channel is destroyed
//!     (normal shutdown signal from the kernel). The loop does not exit
//!     otherwise.
//!
//! ## Memory model
//!
//! A 512 KiB bump allocator backs all heap use. The bump allocator never
//! frees individual blocks; each service-loop iteration allocates up to
//! ~6 KiB (one receive buffer + one postcard-encoded event). Over the
//! lifetime of the driver process the allocator will eventually exhaust its
//! arena; at that point `alloc` returns null, the OOM handler triggers the
//! panic handler, and `TaskExit(2)` is issued. For M0 this is acceptable:
//! real traffic volumes over the driver's process lifetime would exhaust the
//! arena only after ~85 000 frames (512 KiB / ~6 KiB per iteration). The
//! TODO to replace the bump allocator with a real slab/ring allocator is
//! tracked in NCIP-015 M1.
//!
//! ## Standalone execution
//!
//! When this binary is executed without going through `DriverLoad` (a
//! diagnostic scenario), `find_token` returns `None` because the deposit
//! page is not mapped; the image then exits with sentinel codes 10/20/30
//! identifying which token is missing. This is the expected behaviour and
//! surfaces loudly so the absence of the loader path is unambiguous.
//!
//! Build:
//!
//! ```sh
//! cargo build --manifest-path crates/nexacore-driver-net-virtio-image/Cargo.toml \
//!             --target x86_64-unknown-none --release
//! ```

#![no_std]
#![no_main]
#![allow(unsafe_code)]
#![warn(missing_docs)]

extern crate alloc;

use alloc::vec::Vec;
use core::alloc::{GlobalAlloc, Layout};
use core::panic::PanicInfo;

use nexacore_driver_net_virtio::bringup::{BringUp, Event, Phase};
use nexacore_driver_net_virtio::driver::{DriverState, VirtioNetDriver};
use nexacore_driver_net_virtio::service_loop::{ServiceLoopError, decode_net_request, encode_rx_event};
use nexacore_driver_shared::{
    ACTION_TAG_DMA_MAP, ACTION_TAG_IRQ_ATTACH, ACTION_TAG_MMIO_MAP, VirtioDeviceInfo,
    caps::find_token, device_info,
};
use nexacore_types::net_channel::NetRequest;

// =============================================================================
// Global allocator — two-class slab backed by static arenas
// =============================================================================
//
// The service loop allocates short-lived `Vec<u8>` IPC payloads (a NetEvent per
// forwarded RX frame ≤ ~1534 B, a NetResponse per command ≤ ~16 B, the decoded
// NetRequest ≤ 1514 B), each allocated, copied into the kernel by `ipc_send`,
// then dropped. The previous bump allocator never reclaimed them → the driver
// OOM'd and panicked (`TaskExit(2)`) shortly after the first TCP SYN, before it
// could RX the SYN-ACK, so the handshake never completed (2026-06-04).
//
// This FREEING allocator reclaims every dropped block. Two size classes (64 B,
// 4096 B) cover all driver allocations with O(1) alloc/free and no
// fragmentation; each uses an intrusive LIFO free list (free block's first word
// = next free address) plus a lazy bump cursor. Blocks are 16-byte aligned
// (arena base `repr(align(16))`, offsets are 64 B/4096 B multiples) which
// satisfies every driver allocation alignment (≤ 8). align > 16 or size > 4096
// (neither occurs — IPC scratch is BSS, frames ≤ 1514) returns null.
//
// SAFETY invariant: every static below is mutated only through `SlabAllocator`;
// the image is single-threaded (one Ring-3 task on one CPU).

/// Slab block size for the small class, in bytes.
const SMALL_BLK: usize = 64;
/// Slab block size for the large class, in bytes.
const LARGE_BLK: usize = 4096;
/// Small-class block count (64 B × 2048 = 128 KiB).
const SMALL_COUNT: usize = 2048;
/// Large-class block count (4096 B × 96 = 384 KiB).
const LARGE_COUNT: usize = 96;

/// 16-byte-aligned static arena so every block offset is 16-aligned.
#[repr(align(16))]
struct Arena<const N: usize>([u8; N]);

static mut SMALL_ARENA: Arena<{ SMALL_BLK * SMALL_COUNT }> = Arena([0u8; SMALL_BLK * SMALL_COUNT]);
static mut LARGE_ARENA: Arena<{ LARGE_BLK * LARGE_COUNT }> = Arena([0u8; LARGE_BLK * LARGE_COUNT]);

/// Free-list head per class: address of the first free block, `0` = empty.
static mut SMALL_FREE: usize = 0;
static mut LARGE_FREE: usize = 0;
/// Bump cursor per class: index of the next never-handed-out block.
static mut SMALL_NEXT: usize = 0;
static mut LARGE_NEXT: usize = 0;

/// Service-loop command-receive buffer (kernel IPC `MAX_PAYLOAD`). In BSS, not
/// on the stack, to keep `_start`'s inlined service-loop frame within the 16 KiB
/// user stack.
///
/// SAFETY: the image is single-threaded (one Ring-3 task); a single `&mut` is
/// taken at the top of the service loop and held for its lifetime.
static mut SVC_CMD_BUF: [u8; 4096] = [0u8; 4096];

/// Service-loop scratch for one received Ethernet frame (max ~1514 + slack).
/// In BSS for the same stack-budget reason as `SVC_CMD_BUF`.
static mut SVC_RX_FRAME: [u8; 1600] = [0u8; 1600];

/// Two-class slab allocator (see the section comment above).
struct SlabAllocator;

impl SlabAllocator {
    /// Pop a block of the class identified by its statics. Null if exhausted.
    ///
    /// # Safety
    ///
    /// The pointers must reference this image's class statics; single-threaded.
    unsafe fn class_alloc(
        free_head_ptr: *mut usize,
        next_ptr: *mut usize,
        arena_base: *mut u8,
        blk: usize,
        count: usize,
    ) -> *mut u8 {
        // SAFETY: single-threaded; pointers are to our own statics.
        unsafe {
            let head = free_head_ptr.read();
            if head != 0 {
                let next_free = (head as *const usize).read();
                free_head_ptr.write(next_free);
                return head as *mut u8;
            }
            let idx = next_ptr.read();
            if idx < count {
                next_ptr.write(idx + 1);
                return arena_base.add(idx * blk);
            }
            core::ptr::null_mut()
        }
    }

    /// Push a freed block onto the class free list.
    ///
    /// # Safety
    ///
    /// `ptr` was returned by `class_alloc` for the same class; single-threaded.
    unsafe fn class_free(free_head_ptr: *mut usize, ptr: *mut u8) {
        // SAFETY: single-threaded; `ptr` is a live block ≥ 8 bytes.
        unsafe {
            let head = free_head_ptr.read();
            (ptr as *mut usize).write(head);
            free_head_ptr.write(ptr as usize);
        }
    }
}

// SAFETY: `SlabAllocator` is a ZST; all mutable state lives in the `static mut`
// class globals above; single-threaded bare-metal target.
unsafe impl GlobalAlloc for SlabAllocator {
    /// Allocate from the smallest fitting class (null on exhaustion / align>16
    /// / size>LARGE_BLK).
    ///
    /// # Safety
    ///
    /// Per `GlobalAlloc` contract: `layout.align()` is a power of two.
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        if layout.align() > 16 {
            return core::ptr::null_mut();
        }
        let size = layout.size();
        // SAFETY: addresses of our own class statics; single-threaded.
        unsafe {
            if size <= SMALL_BLK {
                Self::class_alloc(
                    core::ptr::addr_of_mut!(SMALL_FREE),
                    core::ptr::addr_of_mut!(SMALL_NEXT),
                    core::ptr::addr_of_mut!(SMALL_ARENA).cast::<u8>(),
                    SMALL_BLK,
                    SMALL_COUNT,
                )
            } else if size <= LARGE_BLK {
                Self::class_alloc(
                    core::ptr::addr_of_mut!(LARGE_FREE),
                    core::ptr::addr_of_mut!(LARGE_NEXT),
                    core::ptr::addr_of_mut!(LARGE_ARENA).cast::<u8>(),
                    LARGE_BLK,
                    LARGE_COUNT,
                )
            } else {
                core::ptr::null_mut()
            }
        }
    }

    /// Return a block to its class free list (O(1)).
    ///
    /// # Safety
    ///
    /// Per `GlobalAlloc` contract: `ptr`/`layout` match a prior `alloc`.
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        if ptr.is_null() {
            return;
        }
        let size = layout.size();
        // SAFETY: ptr came from the matching class in `alloc`; single-threaded.
        unsafe {
            if size <= SMALL_BLK {
                Self::class_free(core::ptr::addr_of_mut!(SMALL_FREE), ptr);
            } else if size <= LARGE_BLK {
                Self::class_free(core::ptr::addr_of_mut!(LARGE_FREE), ptr);
            }
        }
    }
}

/// Global allocator instance.
#[global_allocator]
static GLOBAL_ALLOC: SlabAllocator = SlabAllocator;

// =============================================================================
// Syscall numbers (mirrors `nexacore_kernel::syscall::SyscallNumber` — pinned
// here so the image does not pull in the kernel crate, which would create
// a circular workspace dep).  Values verified verbatim against
// `crates/nexacore-kernel/src/syscall.rs`.
// =============================================================================

/// `TaskExit (11)` — terminate the calling task.
const SYS_TASK_EXIT: u64 = 11;

/// `TaskYield (12)` — yield the CPU to the next runnable task.
const SYS_TASK_YIELD: u64 = 12;

/// `IpcCreateChannel (20)` — create a new IPC channel.
///
/// ABI: `(queue_depth, backpressure, tee_bound, send_token_ptr,
///        recv_token_ptr, lens) -> channel_id | SYSCALL_ERROR`.
/// This image uses the legacy MB12 path: `send_token_ptr = 0`,
/// `recv_token_ptr = 0`, `lens = 0` (no signed-token verification).
const SYS_IPC_CREATE_CHANNEL: u64 = 20;

/// `IpcSend (22)` — send a message on a channel.
///
/// ABI: `(channel_id, kind, payload_ptr, payload_len, _, _) -> 0 | SYSCALL_ERROR`.
/// `kind = 2` (Reply) for command-channel response sends;
/// `kind = 3` (Notification) for event-channel sends.
const SYS_IPC_SEND: u64 = 22;

/// `IpcReceive (23)` — receive a message from a channel.
///
/// ABI: `(channel_id, dst_ptr, dst_cap, blocking, _, _) -> bytes_received`.
/// `blocking = 1` parks the task until a message arrives; `blocking = 0`
/// returns immediately, yielding `0` bytes when the queue is empty. (The
/// kernel exposes a dedicated `IpcTryReceive = 24` that returns a sentinel
/// instead of `0`; this driver uses the blocking-flag form of `23` directly
/// and treats a `0`-byte non-blocking read as "nothing pending".)
const SYS_IPC_RECEIVE: u64 = 23;

/// `MmioMap (70)` — map a PCI BAR MMIO region.
const SYS_MMIO_MAP: u64 = 70;

/// `DmaMap (71)` — install an IOMMU DMA window.
const SYS_DMA_MAP: u64 = 71;

/// `IrqAttach (72)` — attach an IRQ line to an IPC channel.
///
/// ABI: `(irq_line, ipc_channel_id, cap_ptr, cap_len, 0) -> 0 | SYSCALL_ERROR`.
const SYS_IRQ_ATTACH: u64 = 72;

/// `NetRegister (100)` — register an interface in the kernel NET registry.
///
/// ABI: `(interface_name_ptr, name_len, channel_id, event_channel_id,
///        mac_ptr, mac_len) -> (rax=0, rdx=errno)`.
const SYS_NET_REGISTER: u64 = 100;

// =============================================================================
// IPC message kind constants (mirrors `MessageKind` in `nexacore-kernel/ipc.rs`).
// =============================================================================

/// `MessageKind::Notification (3)` — used when the driver pushes a
/// `NetEvent::FrameReceivedInline` on the event channel (unsolicited).
const IPC_KIND_NOTIFICATION: u64 = 3;

// =============================================================================
// Driver-specific constants
// =============================================================================

/// virtio-net BAR4 physical base address (Q35 default).
const VIRTIO_BAR4_PHYS_BASE: u64 = 0xFEBC_0000;

/// virtio-net BAR4 length (1 page covers Common + Notify + ISR + Device).
const VIRTIO_BAR4_LEN: u64 = 0x1000;

/// MmioMap flags = 0 (uncached default, no WC opt-in).
const MMIO_FLAGS_DEFAULT: u64 = 0;

/// DMA arena IOVA base. MUST lie inside the kernel's driver-DMA window
/// `[DRIVER_DMA_VA_BASE, DRIVER_DMA_VA_END)` = `[0x100_0000_0000,
/// 0x180_0000_0000)` (`syscall_entry.rs`), else `DmaMap` returns EINVAL.
/// `0x0` was outside the window and made the kernel reject the call
/// (observed on the test VM as the driver exiting `EXIT_DMA_BASE + EINVAL = 82`).
const DMA_IOVA_BASE: u64 = 0x0000_0100_0000_0000;

/// DMA arena length = 1 page (4 KiB).
///
/// The kernel's Phase-1 `DmaMap` requires the arena to be backed by
/// *physically contiguous* frames, but it allocates the leaf page-table
/// frames for the mapping from the SAME bitmap allocator, interleaved with
/// the data frames: data-frame-0 → (map installs 0..3 PT frames) →
/// data-frame-1, which is therefore no longer adjacent to data-frame-0, so
/// the strict-contiguity check aborts with `ENOSPC` for ANY arena larger
/// than one page (observed on the test VM as `EXIT_DMA_BASE + ENOSPC = 88` with a
/// 2 MiB / 512-frame request).
///
/// A single page sidesteps the bug entirely: `dma_map` maps the first frame
/// before the contiguity loop and the loop body never runs for `len == 4096`.
/// One page holds a minimal M0 virtio split-queue (a small desc table +
/// avail + used ring) — enough to prove the kernel→driver→NIC datapath.
///
/// TODO(M1): make `dma_map` pre-reserve the contiguous data frames before
/// installing PTEs (or add a contiguous-alloc API) so multi-page DMA arenas
/// work; then restore a larger arena here for real frame-buffer pools.
const DMA_LEN: u64 = 0x1000;

/// RX DMA arena IOVA base: the second page of the kernel's 2-page DMA scope
/// (`[0x100_0000_0000, 0x100_0000_2000)`). A distinct iova from the TX page so
/// `dma_map`'s duplicate-iova guard accepts both, each individually contiguous.
const RX_DMA_IOVA_BASE: u64 = 0x0000_0100_0000_1000;

/// DMA direction = bidirectional (RX + TX share the arena in M0).
const DMA_DIR_BIDIR: u64 = 2;

/// virtio-net combined MSI-X / INTx IRQ line (Q35 / QEMU default for PCI
/// slot 3). Declared in `manifest.toml` `irq_lines[0].line = 33`.
const IRQ_LINE_VIRTIO_NET: u64 = 33;

// virtio modern Common Configuration register offsets (virtio 1.0 § 4.1.4.3,
// "Common configuration structure layout"), relative to the common_cfg base
// (which is itself `mmio_va + device_info.common_offset`).
/// `device_feature_select` (u32, RW).
const VCFG_DEVICE_FEATURE_SELECT: u64 = 0x00;
/// `device_feature` (u32, RO) — the feature bits for the selected word.
const VCFG_DEVICE_FEATURE: u64 = 0x04;
/// `driver_feature_select` (u32, RW).
const VCFG_DRIVER_FEATURE_SELECT: u64 = 0x08;
/// `driver_feature` (u32, RW) — the feature bits the driver accepts.
const VCFG_DRIVER_FEATURE: u64 = 0x0C;
/// `num_queues` (u16, RO).
const VCFG_NUM_QUEUES: u64 = 0x12;
/// `device_status` (u8, RW).
const VCFG_DEVICE_STATUS: u64 = 0x14;
/// `queue_select` (u16, RW).
const VCFG_QUEUE_SELECT: u64 = 0x16;
/// `queue_size` (u16, RW).
const VCFG_QUEUE_SIZE: u64 = 0x18;
/// `queue_enable` (u16, RW).
const VCFG_QUEUE_ENABLE: u64 = 0x1C;
/// `queue_notify_off` (u16, RO) — multiplier index into the notify window.
const VCFG_QUEUE_NOTIFY_OFF: u64 = 0x1E;
/// `queue_desc` (u64, RW) — physical address of the descriptor table.
const VCFG_QUEUE_DESC: u64 = 0x20;
/// `queue_driver` (u64, RW) — physical address of the avail ring.
const VCFG_QUEUE_DRIVER: u64 = 0x28;
/// `queue_device` (u64, RW) — physical address of the used ring.
const VCFG_QUEUE_DEVICE: u64 = 0x30;

// virtio device_status bits (virtio 1.0 § 2.1).
const VSTATUS_RESET: u8 = 0x00;
const VSTATUS_ACKNOWLEDGE: u8 = 0x01;
const VSTATUS_DRIVER: u8 = 0x02;
const VSTATUS_DRIVER_OK: u8 = 0x04;
const VSTATUS_FEATURES_OK: u8 = 0x08;

/// Exit sentinel: the kernel handed us a null MMIO VA (cannot drive device).
const EXIT_MMIO_VA_NULL: u64 = 3;
/// Exit sentinel: the kernel handed us a null DMA phys base (cannot place rings).
const EXIT_DMA_PHYS_NULL: u64 = 4;
/// Exit sentinel: the device rejected our feature subset (FEATURES_OK cleared).
const EXIT_FEATURES_REJECTED: u64 = 5;

/// virtio-net interface name in the kernel NET registry.
/// Matches `nexacore_types::net_channel::net_channel_name("virtio0")`.
const IFACE_NAME: &[u8] = b"virtio0";

/// This NIC's MAC (the Proxmox test VM net0). Programs the driver and is the RX
/// ingress-filter unicast match (drop traffic meant for other hosts).
const OUR_MAC: [u8; 6] = [0x52, 0x54, 0x00, 0x12, 0x34, 0x56];

/// IPC queue depth for all three driver channels.
/// 64 slots is sufficient for burst absorption in M0.
const IPC_QUEUE_DEPTH: u64 = 64;

/// Backpressure policy = Block (0): the service loop parks on a full send
/// rather than dropping frames or causing an error.
const IPC_BACKPRESSURE_BLOCK: u64 = 0;

/// TEE-bound = false (0) for all driver channels in M0.
const IPC_TEE_BOUND_OFF: u64 = 0;

/// Receive buffer capacity for `IpcReceive` calls.
/// Must be at least `MAX_PAYLOAD = 4096` (per `syscall_entry.rs:438`).
const IPC_MAX_PAYLOAD: usize = 4096;

/// `SYSCALL_ERROR` sentinel returned by the kernel on hard failure.
const SYSCALL_ERROR: u64 = u64::MAX;

// =============================================================================
// TaskExit sentinel codes
// =============================================================================

/// Driver completed service-loop shutdown cleanly (command channel destroyed).
const EXIT_OK: u64 = 0;
/// FSM converged to a terminal `Failed` state.
const EXIT_FSM_FAILED: u64 = 1;
/// No `MmioMap` token in the deposit window (standalone execution).
const EXIT_NO_MMIO_TOKEN: u64 = 10;
/// No `DmaMap` token in the deposit window.
const EXIT_NO_DMA_TOKEN: u64 = 20;
/// No `IrqAttach` token in the deposit window.
const EXIT_NO_IRQ_TOKEN: u64 = 30;
/// Base sentinel: `MmioMap` syscall returned non-zero errno.
const EXIT_MMIO_BASE: u64 = 40;
/// Base sentinel: `DmaMap` syscall returned non-zero errno.
const EXIT_DMA_BASE: u64 = 60;
/// `IpcCreateChannel` failed for command channel.
const EXIT_IPC_CREATE_CMD_FAILED: u64 = 70;
/// `IpcCreateChannel` failed for event channel.
const EXIT_IPC_CREATE_EVT_FAILED: u64 = 71;
/// `IpcCreateChannel` failed for IRQ-notify channel.
const EXIT_IPC_CREATE_IRQ_FAILED: u64 = 72;
/// Base sentinel: `IrqAttach` syscall returned non-zero errno.
const EXIT_IRQ_BASE: u64 = 80;
/// Base sentinel: `NetRegister` syscall returned non-zero errno.
const EXIT_NET_REGISTER_BASE: u64 = 90;

// =============================================================================
// Raw syscall wrappers (System V AMD64 ABI)
// =============================================================================

/// Issue a `syscall` with the given number and up to 5 arguments.
///
/// Returns the `(rax, rdx)` pair — the two-register convention used by all
/// driver-framework and NET-registry syscalls per `NCIP-Driver-Framework-013`
/// § S2 and `NCIP-Driver-Net-015` § S2.
///
/// The System V AMD64 ABI for `syscall`:
/// - Input: `rax = number`, `rdi/rsi/rdx/r10/r8 = a0..a4`.
/// - Output: `rax = return value`, `rdx = errno` (two-register ABI).
/// - Clobbered by CPU: `rcx` (saved RIP), `r11` (saved RFLAGS).
///
/// # Safety
///
/// The caller must ensure all pointer arguments are valid for the duration
/// of the syscall and that `number` is a valid NexaCore OS syscall number with
/// the correct register layout.
#[inline(always)]
unsafe fn syscall5(number: u64, a0: u64, a1: u64, a2: u64, a3: u64, a4: u64) -> (u64, u64) {
    let mut rax: u64 = number;
    let mut rdx_out: u64;
    // SAFETY: `syscall` is the canonical Ring 3 → Ring 0 transition on
    // `x86_64`; rax/rcx/r11 are clobbered by the CPU per the Intel SDM.
    // The kernel's `nexacore_syscall_entry` preserves the rest of the GPR
    // file across the call. Caller contract documented on the function.
    unsafe {
        core::arch::asm!(
            "syscall",
            inout("rax") rax,
            // The kernel's nexacore_syscall_entry SHUFFLES the argument registers
            // (rdi/rsi/rdx/r10/r8/r9) into the SysV C-ABI order and does NOT
            // restore them, so every argument register must be marked as
            // clobbered (`inout … => _`) — otherwise the compiler may keep a
            // live value (e.g. a const it needs after this call) in one of
            // them and read garbage back. This was a real bug: DMA_IOVA_BASE
            // parked in r10/r8 came back as 0xFFFF…EEFC and #PF'd the driver.
            inout("rdi") a0 => _,
            inout("rsi") a1 => _,
            inout("rdx") a2 => rdx_out,
            inout("r10") a3 => _,
            inout("r8")  a4 => _,
            out("r9") _,
            out("rcx") _,
            out("r11") _,
            options(nostack, preserves_flags),
        );
    }
    (rax, rdx_out)
}

/// `TaskExit (11)` — terminate the calling process. Never returns.
///
/// # Safety
///
/// Calling this permanently terminates the driver process. The `code` value
/// is an opaque numeric exit status logged by the kernel.
#[inline(always)]
unsafe fn sys_exit(code: u64) -> ! {
    // SAFETY: TaskExit (11) takes one scalar arg in rdi and never returns.
    // `options(noreturn)` proves to the compiler that control flow ends here.
    unsafe {
        core::arch::asm!(
            "syscall",
            in("rax") SYS_TASK_EXIT,
            in("rdi") code,
            options(noreturn),
        );
    }
}

/// `TaskYield (12)` — cooperatively yield the CPU to the next runnable task.
fn sys_task_yield() {
    // SAFETY: TaskYield takes no arguments. Issued through the generic
    // 6-argument stub ON PURPOSE: the kernel syscall entry SHUFFLES the
    // argument registers (rdi/rsi/rdx/r10/r8/r9) and returns a value pair
    // in rax/rdx WITHOUT restoring any of them, so a minimal `asm!` that
    // clobbers only rcx/r11 lets the compiler keep live values (e.g. the
    // NEXT syscall's arguments) in registers the kernel destroys.
    // Hardware-observed as a boot-timing heisenbug (TASK-13: corrupted
    // input_len -> spurious EINVAL after one ENOENT retry); the generic
    // stub declares the full clobber set.
    let _ = unsafe { syscall5(SYS_TASK_YIELD, 0, 0, 0, 0, 0) };
}

/// `WriteConsole (60)` syscall number — write a byte slice to COM1.
const SYS_WRITE_CONSOLE: u64 = 60;

/// Write `msg` to the kernel console (COM1, best-effort). Used for bring-up
/// diagnostics so a syscall failure is visible verbatim on serial rather than
/// only as an opaque `TaskExit` sentinel.
fn dbg(msg: &str) {
    let b = msg.as_bytes();
    // SAFETY: `b` is valid for the duration of the syscall; WriteConsole takes
    // a (ptr, len) pair and returns normally.
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

/// Write `val` as a fixed 16-digit `0x…` hex string to the console.
fn dbg_hex(val: u64) {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut buf = [0u8; 18];
    buf[0] = b'0';
    buf[1] = b'x';
    let mut i: usize = 0;
    while i < 16 {
        let shift: u32 = (15 - i as u32) * 4;
        #[allow(clippy::cast_possible_truncation, reason = "nibble masked to 0..16")]
        let nibble = ((val >> shift) & 0xF) as usize;
        buf[2 + i] = HEX[nibble];
        i += 1;
    }
    // SAFETY: `buf` is valid ASCII for the syscall duration.
    let _ = unsafe {
        syscall5(
            SYS_WRITE_CONSOLE,
            buf.as_ptr() as u64,
            buf.len() as u64,
            0,
            0,
            0,
        )
    };
}

// =============================================================================
// MMIO register accessors (virtio modern transport)
// =============================================================================
//
// The kernel `MmioMap`s the device BAR into this process at `mmio_va`; the
// common_cfg / notify windows are at `mmio_va + device_info.*_offset`. All
// device-register access MUST be volatile (the compiler must not reorder,
// merge, or elide reads/writes to device memory).

/// Volatile 8-bit write to `addr`.
///
/// # Safety
///
/// `addr` must be a mapped, writable MMIO byte inside the driver's BAR window.
#[inline(always)]
unsafe fn mmio_w8(addr: u64, val: u8) {
    // SAFETY: caller guarantees `addr` is a mapped device register.
    unsafe { core::ptr::write_volatile(addr as *mut u8, val) }
}

/// Volatile 8-bit read from `addr`.
///
/// # Safety
///
/// `addr` must be a mapped, readable MMIO byte inside the driver's BAR window.
#[inline(always)]
unsafe fn mmio_r8(addr: u64) -> u8 {
    // SAFETY: caller guarantees `addr` is a mapped device register.
    unsafe { core::ptr::read_volatile(addr as *const u8) }
}

/// Volatile 16-bit write to `addr`.
///
/// # Safety
///
/// `addr` must be a mapped, writable, 2-byte-aligned MMIO word in the BAR.
#[inline(always)]
unsafe fn mmio_w16(addr: u64, val: u16) {
    // SAFETY: caller guarantees `addr` is a mapped device register.
    unsafe { core::ptr::write_volatile(addr as *mut u16, val) }
}

/// Volatile 16-bit read from `addr`.
///
/// # Safety
///
/// `addr` must be a mapped, readable, 2-byte-aligned MMIO word in the BAR.
#[inline(always)]
unsafe fn mmio_r16(addr: u64) -> u16 {
    // SAFETY: caller guarantees `addr` is a mapped device register.
    unsafe { core::ptr::read_volatile(addr as *const u16) }
}

/// Volatile 32-bit write to `addr`.
///
/// # Safety
///
/// `addr` must be a mapped, writable, 4-byte-aligned MMIO dword in the BAR.
#[inline(always)]
unsafe fn mmio_w32(addr: u64, val: u32) {
    // SAFETY: caller guarantees `addr` is a mapped device register.
    unsafe { core::ptr::write_volatile(addr as *mut u32, val) }
}

/// Volatile 32-bit read from `addr`.
///
/// # Safety
///
/// `addr` must be a mapped, readable, 4-byte-aligned MMIO dword in the BAR.
#[inline(always)]
unsafe fn mmio_r32(addr: u64) -> u32 {
    // SAFETY: caller guarantees `addr` is a mapped device register.
    unsafe { core::ptr::read_volatile(addr as *const u32) }
}

/// Volatile 64-bit write to `addr` as two 32-bit halves (low then high).
///
/// The virtio spec (§ 4.1.4.3) permits 64-bit registers to be written as two
/// 32-bit accesses; doing so avoids relying on the platform honouring a single
/// 8-byte MMIO store.
///
/// # Safety
///
/// `addr` must be a mapped, writable, 4-byte-aligned MMIO qword in the BAR.
#[inline(always)]
unsafe fn mmio_w64_split(addr: u64, val: u64) {
    // SAFETY: caller guarantees `addr`/`addr+4` are mapped device registers.
    unsafe {
        mmio_w32(addr, val as u32);
        mmio_w32(addr + 4, (val >> 32) as u32);
    }
}

/// `IpcCreateChannel (20)` — create a new IPC channel (legacy MB12 path).
///
/// Passes `send_token_ptr = 0` and `recv_token_ptr = 0` to use the MB12
/// open-channel path (no signed-token verification required). Returns the
/// kernel-allocated channel id on success, or [`SYSCALL_ERROR`] on failure.
///
/// # Safety
///
/// No pointer arguments are passed (legacy path). The kernel allocates a
/// fresh channel id; the caller becomes the owner.
#[inline(always)]
unsafe fn ipc_create_channel(queue_depth: u64) -> u64 {
    // SAFETY: No pointer args. ABI: (queue_depth, backpressure, tee_bound,
    //   send_token_ptr=0, recv_token_ptr=0). The 6th arg (lens) defaults to
    //   0 in the r9 register, which syscall5 does not set; the kernel's MB12
    //   path reads lens = 0 as "no tokens", which is correct here.
    let (channel_id, _errno) = unsafe {
        syscall5(
            SYS_IPC_CREATE_CHANNEL,
            queue_depth,            // a0: queue_depth
            IPC_BACKPRESSURE_BLOCK, // a1: backpressure = Block
            IPC_TEE_BOUND_OFF,      // a2: tee_bound = false
            0,                      // a3: send_token_ptr = 0 (legacy MB12)
            0,                      // a4: recv_token_ptr = 0 (legacy MB12)
        )
    };
    channel_id
}

/// `IpcSend (22)` — send a payload on a channel.
///
/// Returns `(0, 0)` on success, `(SYSCALL_ERROR, _)` on failure.
///
/// # Safety
///
/// `payload_ptr` must point to a valid readable buffer of at least
/// `payload_len` bytes for the entire duration of the syscall.
#[inline(always)]
unsafe fn ipc_send(channel_id: u64, kind: u64, payload_ptr: u64, payload_len: u64) -> (u64, u64) {
    // SAFETY: Caller guarantees payload_ptr/payload_len validity.
    // ABI: (channel_id, kind, payload_ptr, payload_len, _, _).
    // `syscall5` places a2 in rdx; the kernel reads rdx as payload_ptr on entry.
    unsafe {
        syscall5(
            SYS_IPC_SEND,
            channel_id,  // a0: channel_id
            kind,        // a1: MessageKind
            payload_ptr, // a2 → rdx: payload pointer
            payload_len, // a3 → r10: payload length
            0,           // a4: unused
        )
    }
}

/// `IpcReceive (23)` — receive a message from a channel.
///
/// Returns `(bytes_received, 0)` on success. When `blocking = true` and the
/// channel is empty, the task parks until a message arrives. When
/// `blocking = false` and the channel is empty, returns `(0, 0)`.
/// Returns `(SYSCALL_ERROR, _)` on hard failure (bad channel id, etc.).
///
/// # Safety
///
/// `dst_ptr` must point to a valid writable buffer of at least `dst_cap`
/// bytes for the entire duration of the syscall.
#[inline(always)]
unsafe fn ipc_receive(channel_id: u64, dst_ptr: u64, dst_cap: u64, blocking: bool) -> (u64, u64) {
    // SAFETY: Caller guarantees dst_ptr/dst_cap validity.
    // ABI: (channel_id, dst_ptr, dst_cap, blocking, _, _).
    unsafe {
        syscall5(
            SYS_IPC_RECEIVE,
            channel_id,                   // a0
            dst_ptr,                      // a1
            dst_cap,                      // a2 → rdx
            if blocking { 1 } else { 0 }, // a3 → r10
            0,                            // a4: unused
        )
    }
}

/// `NetRegister (100)` — register the driver's channels in the kernel NET
/// registry.
///
/// This requires 6 register arguments; `syscall5` only covers 5 (a0..a4 →
/// rdi/rsi/rdx/r10/r8). The 6th argument (`mac_len = 6`) goes in `r9`.
/// We use an inline-asm block directly here to pass all 6.
///
/// Returns `(rax=0, rdx=errno)` where `errno = 0` on success.
///
/// # Safety
///
/// - `name_ptr` must point to a valid UTF-8 byte slice of `name_len` bytes.
/// - `mac_ptr` must point to exactly 6 bytes (MAC address, network byte order).
#[inline(always)]
unsafe fn net_register(
    name_ptr: u64,
    name_len: u64,
    channel_id: u64,
    event_channel_id: u64,
    mac_ptr: u64,
) -> (u64, u64) {
    // SAFETY: all pointer arguments are valid for the duration of the syscall
    // (guaranteed by caller). mac_len is always 6 for a MAC address.
    // ABI: rax=100, rdi=name_ptr, rsi=name_len, rdx=channel_id,
    //      r10=event_channel_id, r8=mac_ptr, r9=mac_len(6).
    let mut rax: u64 = SYS_NET_REGISTER;
    let mut rdx_out: u64;
    unsafe {
        core::arch::asm!(
            "syscall",
            inout("rax") rax,
            // Mark every argument register clobbered: the kernel shuffles and
            // does not restore rdi/rsi/rdx/r10/r8/r9 (see syscall5's note).
            inout("rdi") name_ptr => _,
            inout("rsi") name_len => _,
            inout("rdx") channel_id => rdx_out,
            inout("r10") event_channel_id => _,
            inout("r8")  mac_ptr => _,
            inout("r9")  6u64 => _, // mac_len is always 6 bytes for an Ethernet MAC
            out("rcx") _,
            out("r11") _,
            options(nostack, preserves_flags),
        );
    }
    (rax, rdx_out)
}

// =============================================================================
// TX virtqueue programming + ARP probe (M0 Phase 3 datapath proof)
// =============================================================================

/// `VIRTQ_DESC_F_NEXT` — descriptor chains to `next`.
const VIRTQ_DESC_F_NEXT: u16 = 1;
/// virtio-net header length with `VIRTIO_F_VERSION_1` (num_buffers present),
/// virtio 1.0 § 5.1.6: `{flags, gso_type, hdr_len, gso_size, csum_start,
/// csum_offset, num_buffers}` = 12 bytes.
const VNET_HDR_LEN: usize = 12;
/// TX queue index for virtio-net (transmitq0), virtio-net § 5.1.2.
const TX_QUEUE_IDX: u16 = 1;
/// Small TX ring for M0 — power of two, dwarfed by the 4 KiB DMA arena.
const TX_RING_SIZE: u16 = 16;
/// RX queue index for virtio-net (receiveq0), virtio-net § 5.1.2.
const RX_QUEUE_IDX: u16 = 0;
/// RX ring size: 4 receive buffers (power of two) — ample for the M0 ARP/SYN
/// exchange and fits the one-page RX DMA arena alongside the rings.
const RX_RING_SIZE: u16 = 4;
/// Per-RX-buffer size within the RX arena. 4 × 0x300 = 0xC00, placed after the
/// rings (which end well before OFF_RX_BUF), all inside one 4 KiB page.
const RX_BUF_STRIDE: u64 = 0x300;
/// Offset of the first RX buffer within the RX DMA page.
const OFF_RX_BUF: u64 = 0x200;

// Ring sub-region offsets within the single 4 KiB DMA page. All 64-byte
// aligned and non-overlapping; the frame buffer at 0x200 leaves 0xE00 bytes
// for a frame (far more than the 1514-byte Ethernet max).
const OFF_DESC: u64 = 0x000;
const OFF_AVAIL: u64 = 0x100;
const OFF_USED: u64 = 0x140;
const OFF_FRAME: u64 = 0x200;

/// Persistent real-MMIO TX engine for virtio-net queue 1.
///
/// Programmed ONCE by [`TxEngine::init`] (device-status handshake → queue
/// program → DRIVER_OK), then used for every outbound frame by
/// [`TxEngine::send`]. This is the single TX datapath shared by the boot ARP
/// probe and the service loop, so any frame nexacore-net hands the driver actually
/// hits the wire via the device virtqueue (not the library's in-memory queue).
///
/// One descriptor is reused (single in-flight frame at a time, which suffices
/// for M0's request/response cadence). `avail_idx` is the monotonic producer
/// index; the device's used-ring idx is polled to confirm completion.
struct TxEngine {
    /// Mapped MMIO BAR base (CPU VA).
    mmio_va: u64,
    /// common_cfg block base (`mmio_va + common_offset`).
    common: u64,
    /// Precomputed notify doorbell address for queue 1.
    notify_addr: u64,
    /// DMA arena CPU VA (writes) — identity-mapped to `dma_phys`.
    dma_va: u64,
    /// DMA arena device physical base (ring/buffer addresses for the device).
    dma_phys: u64,
    /// Device MAC, read from device-config at init (Ethernet source address).
    mac: [u8; 6],
    /// Monotonic avail-ring producer index (next slot to publish).
    avail_idx: u16,
}

impl TxEngine {
    /// Bring the device up and program TX queue 1. Returns `None` if the
    /// device-info geometry is absent (cannot locate the notify doorbell).
    ///
    /// # Safety
    ///
    /// `mmio_va` + the offsets in `info` must be a live MmioMap'd BAR; the
    /// status handshake at `_start` (reset → FEATURES_OK) must already have run
    /// on `common`. `[dma_va, dma_va+0x1000)` must be mapped writable, backed
    /// by phys `dma_phys`.
    unsafe fn init(
        mmio_va: u64,
        common: u64,
        info: &VirtioDeviceInfo,
        dma_va: u64,
        dma_phys: u64,
    ) -> Self {
        let notify_off_in_bar = u64::from(info.notify_offset);
        let notify_mult = u64::from(info.notify_off_multiplier);
        let device_off = u64::from(info.device_offset);

        // Read the device MAC from the device-config window (offset 0).
        let mut mac = [0u8; 6];
        let devcfg = mmio_va + device_off;
        for (i, b) in mac.iter_mut().enumerate() {
            // SAFETY: devcfg is inside the mapped BAR.
            *b = unsafe { mmio_r8(devcfg + i as u64) };
        }

        // Zero the used ring idx so completion is detectable, and the avail
        // ring header. (Descriptors are written per-send.)
        let avail = dma_va + OFF_AVAIL;
        let used = dma_va + OFF_USED;
        // SAFETY: avail/used live inside the DMA arena.
        unsafe {
            core::ptr::write_volatile(avail as *mut u16, 0u16); // avail.flags
            core::ptr::write_volatile((avail + 2) as *mut u16, 0u16); // avail.idx
            core::ptr::write_volatile(used as *mut u16, 0u16); // used.flags
            core::ptr::write_volatile((used + 2) as *mut u16, 0u16); // used.idx
        }

        // Program the device's TX queue (queue 1) with device-physical ring
        // addresses, enable it, then read back its notify offset.
        // SAFETY: `common` is the mapped common_cfg block.
        let q_notify_off = unsafe {
            mmio_w16(common + VCFG_QUEUE_SELECT, TX_QUEUE_IDX);
            mmio_w16(common + VCFG_QUEUE_SIZE, TX_RING_SIZE);
            mmio_w64_split(common + VCFG_QUEUE_DESC, dma_phys + OFF_DESC);
            mmio_w64_split(common + VCFG_QUEUE_DRIVER, dma_phys + OFF_AVAIL);
            mmio_w64_split(common + VCFG_QUEUE_DEVICE, dma_phys + OFF_USED);
            mmio_w16(common + VCFG_QUEUE_ENABLE, 1);
            mmio_r16(common + VCFG_QUEUE_NOTIFY_OFF)
        };

        // DRIVER_OK — device is now live.
        // SAFETY: common_cfg write.
        unsafe {
            mmio_w8(
                common + VCFG_DEVICE_STATUS,
                VSTATUS_ACKNOWLEDGE | VSTATUS_DRIVER | VSTATUS_FEATURES_OK | VSTATUS_DRIVER_OK,
            );
        }
        let status_live = unsafe { mmio_r8(common + VCFG_DEVICE_STATUS) };

        let notify_addr = mmio_va + notify_off_in_bar + u64::from(q_notify_off) * notify_mult;
        dbg("[virtio-img] TxEngine init notify_addr=");
        dbg_hex(notify_addr);
        dbg(" status=");
        dbg_hex(u64::from(status_live));
        dbg(" mac=");
        for b in mac {
            dbg_hex(u64::from(b));
        }
        dbg("\n");

        Self {
            mmio_va,
            common,
            notify_addr,
            dma_va,
            dma_phys,
            mac,
            avail_idx: 0,
        }
    }

    /// Transmit one Ethernet frame (`eth_frame` = Ethernet header + payload,
    /// WITHOUT the virtio-net header — this prepends a zeroed 12-byte header).
    /// Posts a descriptor, rings the doorbell, polls the used ring. Returns
    /// `true` if the device consumed the descriptor (frame left the NIC).
    ///
    /// # Safety
    ///
    /// The engine's MMIO/DMA pointers must still be valid (they are for the
    /// lifetime of the driver process).
    unsafe fn send(&mut self, eth_frame: &[u8]) -> bool {
        // Clamp to what fits after the vnet header in the frame sub-region.
        let max_eth = 0x1000 - (OFF_FRAME as usize) - VNET_HDR_LEN;
        let eth_len = eth_frame.len().min(max_eth);
        let frame_base = self.dma_va + OFF_FRAME;

        // SAFETY: frame sub-region is inside the DMA arena.
        unsafe {
            // Zero the 12-byte virtio-net header.
            for i in 0..VNET_HDR_LEN as u64 {
                core::ptr::write_volatile((frame_base + i) as *mut u8, 0u8);
            }
            // Copy the Ethernet frame after the header.
            let eth_dst = frame_base + VNET_HDR_LEN as u64;
            for (i, b) in eth_frame.iter().take(eth_len).enumerate() {
                core::ptr::write_volatile((eth_dst + i as u64) as *mut u8, *b);
            }
        }
        #[allow(clippy::cast_possible_truncation, reason = "eth_len ≤ ~4KiB fits u32")]
        let frame_total = (VNET_HDR_LEN + eth_len) as u32;

        // Reuse descriptor slot 0 (single in-flight frame at a time).
        let slot = self.avail_idx % TX_RING_SIZE;
        let desc = self.dma_va + OFF_DESC + u64::from(slot) * 16;
        // SAFETY: descriptor table inside the DMA arena.
        unsafe {
            core::ptr::write_volatile(desc as *mut u64, self.dma_phys + OFF_FRAME); // addr (phys)
            core::ptr::write_volatile((desc + 8) as *mut u32, frame_total); // len
            core::ptr::write_volatile((desc + 12) as *mut u16, 0u16); // flags: device-readable
            core::ptr::write_volatile((desc + 14) as *mut u16, 0u16); // next
        }

        // Publish into the avail ring: set ring[slot] = desc index, THEN bump
        // avail.idx (publish order matters; x86 TSO + volatile suffices).
        let avail = self.dma_va + OFF_AVAIL;
        let new_idx = self.avail_idx.wrapping_add(1);
        // SAFETY: avail ring inside the DMA arena.
        unsafe {
            core::ptr::write_volatile((avail + 4 + u64::from(slot) * 2) as *mut u16, slot);
            core::ptr::write_volatile((avail + 2) as *mut u16, new_idx);
        }

        // Ring the doorbell.
        // SAFETY: notify_addr is inside the mapped BAR notify window.
        unsafe { mmio_w16(self.notify_addr, TX_QUEUE_IDX) };

        // Poll the used ring until its idx reaches our published count.
        let used = self.dma_va + OFF_USED;
        let mut spins = 0u32;
        let done = loop {
            // SAFETY: used ring inside the DMA arena.
            let used_idx = unsafe { core::ptr::read_volatile((used + 2) as *const u16) };
            if used_idx == new_idx {
                break true;
            }
            spins += 1;
            if spins >= 2_000_000 {
                break false;
            }
        };
        self.avail_idx = new_idx;
        let _ = (self.mmio_va, self.common, VIRTQ_DESC_F_NEXT); // retained for clarity/future use
        done
    }
}

/// Persistent real-MMIO RX engine for virtio-net queue 0.
///
/// Programmed once by [`RxEngine::init`] (program queue 0 + post all RX
/// buffers + ring the doorbell). [`RxEngine::poll`] returns the next received
/// frame (Ethernet bytes, vnet header stripped) and recycles its buffer.
///
/// Layout in the RX DMA page (CPU VA `dma_va` ⇔ device phys `dma_phys`):
/// ```text
///   +0x000  desc[RX_RING_SIZE]   (4 × 16 = 64 B)
///   +0x100  avail ring           (4 + 4×2 = 12 B)
///   +0x140  used ring            (4 + 4×8 = 36 B)
///   +0x200  buf[0..4]            (4 × 0x300 = 0xC00 B, ends 0xE00)
/// ```
struct RxEngine {
    /// Precomputed queue-0 notify doorbell address (re-armed on each recycle).
    notify_addr: u64,
    /// RX DMA arena CPU VA (identity-mapped to the device-physical base used to
    /// program the queue at init; all post-init access is via this VA).
    dma_va: u64,
    /// Last used-ring index we consumed (to detect new completions).
    last_used: u16,
}

impl RxEngine {
    /// Program RX queue 0, post all `RX_RING_SIZE` buffers device-writable, set
    /// the avail idx, and ring the doorbell so the device can fill them.
    ///
    /// # Safety
    ///
    /// `common`/notify must be the live MmioMap'd BAR; `[dma_va, dma_va+0x1000)`
    /// mapped writable, backed by phys `dma_phys`. Call AFTER the device-status
    /// handshake reached FEATURES_OK and BEFORE DRIVER_OK (queues are set up in
    /// virtio 1.0 § 3.1.1 step 7, just before step 8 DRIVER_OK).
    unsafe fn init(
        mmio_va: u64,
        common: u64,
        info: &VirtioDeviceInfo,
        dma_va: u64,
        dma_phys: u64,
    ) -> Self {
        let notify_off_in_bar = u64::from(info.notify_offset);
        let notify_mult = u64::from(info.notify_off_multiplier);

        // Zero used ring header.
        let used = dma_va + OFF_USED;
        let avail = dma_va + OFF_AVAIL;
        // SAFETY: rings inside the RX DMA arena.
        unsafe {
            core::ptr::write_volatile(used as *mut u16, 0u16); // used.flags
            core::ptr::write_volatile((used + 2) as *mut u16, 0u16); // used.idx
            core::ptr::write_volatile(avail as *mut u16, 0u16); // avail.flags
        }

        // Build RX_RING_SIZE descriptors, each pointing at its own buffer and
        // marked device-WRITABLE (VIRTQ_DESC_F_WRITE = 2). Publish all into the
        // avail ring.
        for i in 0..RX_RING_SIZE {
            let buf_phys = dma_phys + OFF_RX_BUF + u64::from(i) * RX_BUF_STRIDE;
            let desc = dma_va + OFF_DESC + u64::from(i) * 16;
            // SAFETY: desc table + avail inside the RX DMA arena.
            unsafe {
                core::ptr::write_volatile(desc as *mut u64, buf_phys); // addr (phys)
                #[allow(clippy::cast_possible_truncation, reason = "stride < u32::MAX")]
                core::ptr::write_volatile((desc + 8) as *mut u32, RX_BUF_STRIDE as u32); // len
                core::ptr::write_volatile((desc + 12) as *mut u16, 2u16); // flags: device-WRITE
                core::ptr::write_volatile((desc + 14) as *mut u16, 0u16); // next
                core::ptr::write_volatile((avail + 4 + u64::from(i) * 2) as *mut u16, i); // ring[i]=i
            }
        }
        // Publish avail.idx = RX_RING_SIZE (all buffers available).
        // SAFETY: avail ring inside the RX DMA arena.
        unsafe { core::ptr::write_volatile((avail + 2) as *mut u16, RX_RING_SIZE) };

        // Program queue 0 registers (device-physical ring addresses).
        // SAFETY: `common` is the mapped common_cfg block.
        let q_notify_off = unsafe {
            mmio_w16(common + VCFG_QUEUE_SELECT, RX_QUEUE_IDX);
            mmio_w16(common + VCFG_QUEUE_SIZE, RX_RING_SIZE);
            mmio_w64_split(common + VCFG_QUEUE_DESC, dma_phys + OFF_DESC);
            mmio_w64_split(common + VCFG_QUEUE_DRIVER, dma_phys + OFF_AVAIL);
            mmio_w64_split(common + VCFG_QUEUE_DEVICE, dma_phys + OFF_USED);
            mmio_w16(common + VCFG_QUEUE_ENABLE, 1);
            mmio_r16(common + VCFG_QUEUE_NOTIFY_OFF)
        };
        let notify_addr = mmio_va + notify_off_in_bar + u64::from(q_notify_off) * notify_mult;

        // Ring the doorbell so the device knows buffers are available.
        // SAFETY: notify_addr inside the mapped BAR notify window.
        unsafe { mmio_w16(notify_addr, RX_QUEUE_IDX) };

        dbg("[virtio-img] RxEngine init notify_addr=");
        dbg_hex(notify_addr);
        dbg("\n");

        Self {
            notify_addr,
            dma_va,
            last_used: 0,
        }
    }

    /// Poll for one received frame. Returns the Ethernet bytes (vnet header
    /// stripped) copied into `out`, or `None` if the used ring has no new
    /// entry. Recycles the consumed buffer back into the avail ring.
    ///
    /// # Safety
    ///
    /// Engine pointers must still be valid (they are for the driver lifetime).
    unsafe fn poll(&mut self, out: &mut [u8]) -> Option<usize> {
        let used = self.dma_va + OFF_USED;
        // SAFETY: used ring inside the RX DMA arena.
        let used_idx = unsafe { core::ptr::read_volatile((used + 2) as *const u16) };
        if used_idx == self.last_used {
            return None;
        }

        // used.ring[slot] = {u32 id, u32 len} at used + 4 + slot*8.
        let slot = u64::from(self.last_used % RX_RING_SIZE);
        let elem = used + 4 + slot * 8;
        // SAFETY: used ring element inside the RX DMA arena.
        let (desc_id, wlen) = unsafe {
            (
                core::ptr::read_volatile(elem as *const u32),
                core::ptr::read_volatile((elem + 4) as *const u32),
            )
        };
        let desc_id = u64::from(desc_id & 0xFFFF);

        // SECURITY: `desc_id` and `wlen` are written by the (untrusted) device
        // into DMA memory. A malformed completion with desc_id ≥ RX_RING_SIZE
        // would index past the buffer region (OOB read / #PF) and corrupt the
        // avail ring on recycle. Reject it: advance last_used so we don't spin,
        // but do NOT touch a buffer/descriptor that doesn't exist.
        if desc_id >= u64::from(RX_RING_SIZE) {
            self.last_used = self.last_used.wrapping_add(1);
            return None;
        }

        // The device wrote `wlen` bytes (vnet hdr + frame) into the buffer for
        // descriptor `desc_id`. Clamp to the per-buffer stride FIRST (a device
        // claiming wlen > stride must not make us read past this buffer into
        // the next slot or off the page), then strip the 12-byte vnet header.
        let buf_va = self.dma_va + OFF_RX_BUF + desc_id * RX_BUF_STRIDE;
        #[allow(clippy::cast_possible_truncation, reason = "RX_BUF_STRIDE fits usize")]
        let total = (wlen as usize).min(RX_BUF_STRIDE as usize);
        let eth_len = total.saturating_sub(VNET_HDR_LEN).min(out.len());
        for (i, b) in out.iter_mut().take(eth_len).enumerate() {
            // SAFETY: desc_id < RX_RING_SIZE and total ≤ RX_BUF_STRIDE, so
            // buf_va + VNET_HDR_LEN + eth_len ≤ buf_va + stride, inside this
            // buffer slot and the DMA page.
            *b = unsafe {
                core::ptr::read_volatile((buf_va + VNET_HDR_LEN as u64 + i as u64) as *const u8)
            };
        }

        // Recycle: re-publish this descriptor into the avail ring and bump idx.
        let avail = self.dma_va + OFF_AVAIL;
        // SAFETY: avail ring inside the RX DMA arena.
        unsafe {
            let cur = core::ptr::read_volatile((avail + 2) as *const u16);
            let ring_slot = u64::from(cur % RX_RING_SIZE);
            #[allow(clippy::cast_possible_truncation, reason = "desc_id < RX_RING_SIZE")]
            core::ptr::write_volatile((avail + 4 + ring_slot * 2) as *mut u16, desc_id as u16);
            core::ptr::write_volatile((avail + 2) as *mut u16, cur.wrapping_add(1));
        }
        // Ring the doorbell so the device re-arms the recycled buffer.
        // SAFETY: notify_addr inside the mapped BAR.
        unsafe { mmio_w16(self.notify_addr, RX_QUEUE_IDX) };

        self.last_used = self.last_used.wrapping_add(1);
        Some(eth_len)
    }
}

/// Boot-time datapath proof: bring up the TX engine and send one broadcast
/// ARP-request for the Ollama host (192.0.2.11). A consumed descriptor ⇒ a
/// real frame left the NIC (observable as ARP who-has on the bridge),
/// independent of the TCP stack.
///
/// Returns the initialised (`TxEngine`, `RxEngine`) so the service loop can
/// keep using them.
///
/// Sequencing (virtio 1.0 § 3.1.1 step 7 → 8): program RX queue 0 FIRST (it
/// does not flip DRIVER_OK), then TX queue 1 (which sets DRIVER_OK last), so
/// both queues are configured before the device goes live.
///
/// # Safety
///
/// Same contract as [`TxEngine::init`]; `tx_dma_*`/`rx_dma_*` are the two
/// distinct one-page DMA arenas.
unsafe fn nic_bringup(
    mmio_va: u64,
    vinfo: &Option<VirtioDeviceInfo>,
    common: u64,
    tx_dma_va: u64,
    tx_dma_phys: u64,
    rx_dma_va: u64,
    rx_dma_phys: u64,
) -> (Option<TxEngine>, Option<RxEngine>) {
    let Some(info) = vinfo.as_ref() else {
        dbg("[virtio-img] NIC bringup abort: no device-info geometry\n");
        return (None, None);
    };
    // RX queue 0 first (no DRIVER_OK), then TX queue 1 (sets DRIVER_OK).
    // SAFETY: caller upholds the MmioMap/DmaMap contract for both arenas.
    let rx = unsafe { RxEngine::init(mmio_va, common, info, rx_dma_va, rx_dma_phys) };
    let mut tx = unsafe { TxEngine::init(mmio_va, common, info, tx_dma_va, tx_dma_phys) };

    // Build a broadcast ARP-request: who-has 192.0.2.11 tell 192.0.2.50.
    let mut frame = [0u8; 42];
    for b in frame.iter_mut().take(6) {
        *b = 0xFF; // broadcast dst
    }
    frame[6..12].copy_from_slice(&tx.mac); // src = our MAC
    frame[12] = 0x08;
    frame[13] = 0x06; // ethertype ARP
    frame[14] = 0x00;
    frame[15] = 0x01; // htype = Ethernet
    frame[16] = 0x08;
    frame[17] = 0x00; // ptype = IPv4
    frame[18] = 0x06; // hlen
    frame[19] = 0x04; // plen
    frame[20] = 0x00;
    frame[21] = 0x01; // op = request
    frame[22..28].copy_from_slice(&tx.mac); // sender HW
    frame[28..32].copy_from_slice(&[192, 0, 2, 50]); // sender IP
    frame[38..42].copy_from_slice(&[192, 0, 2, 11]); // target IP (Ollama)

    // SAFETY: engine pointers are valid.
    let sent = unsafe { tx.send(&frame) };
    dbg(if sent {
        "[virtio-img] ARP probe (FRAME SENT)\n"
    } else {
        "[virtio-img] ARP probe (TIMEOUT — no completion)\n"
    });
    (Some(tx), Some(rx))
}

// =============================================================================
// Driver entry — _start
// =============================================================================

/// ELF entry point.
///
/// The kernel's `spawn_from_elf` jumps here with `rsp = user_stack_top` and
/// the capability deposit window mapped read-only at
/// [`nexacore_driver_shared::DRIVER_CAP_DEPOSIT_VA`].
///
/// `#[unsafe(no_mangle)]` ensures the linker places this symbol at the ELF
/// entry address. `extern "C"` selects the System V AMD64 calling convention.
#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    // ── Step 1: Retrieve capability tokens from the deposit window ────────────
    //
    // Absence of a token means this binary was launched outside `DriverLoad`
    // (standalone diagnostic). Each missing token emits a distinct sentinel.
    let Some(mmio_token) = find_token(ACTION_TAG_MMIO_MAP, |_| true) else {
        // SAFETY: sys_exit diverges unconditionally.
        unsafe { sys_exit(EXIT_NO_MMIO_TOKEN) };
    };
    let Some(dma_token) = find_token(ACTION_TAG_DMA_MAP, |_| true) else {
        unsafe { sys_exit(EXIT_NO_DMA_TOKEN) };
    };
    let Some(irq_token) = find_token(ACTION_TAG_IRQ_ATTACH, |_| true) else {
        unsafe { sys_exit(EXIT_NO_IRQ_TOKEN) };
    };

    // ── Step 1b: Read the virtio modern register geometry the kernel
    // discovered for us (BAR phys + per-structure offsets). A Ring-3 driver
    // cannot read PCI config space, so without this section it has no way to
    // know the firmware-assigned BAR base. Fall back to the legacy hardcoded
    // window only if the section is absent (older kernel).
    // SAFETY: the kernel maps the deposit window read-only at the well-known VA.
    let vinfo = unsafe { device_info::read() };
    let (mmio_phys, mmio_len) = match vinfo {
        Some(i) => (i.bar_phys, i.mmio_len.into()),
        None => (VIRTIO_BAR4_PHYS_BASE, VIRTIO_BAR4_LEN),
    };
    dbg("[virtio-img] devinfo present=");
    dbg_hex(u64::from(vinfo.is_some()));
    dbg(" bar_phys=");
    dbg_hex(mmio_phys);
    dbg(" mmio_len=");
    dbg_hex(mmio_len);
    if let Some(i) = vinfo {
        dbg(" common=");
        dbg_hex(u64::from(i.common_offset));
        dbg(" notify=");
        dbg_hex(u64::from(i.notify_offset));
        dbg(" device=");
        dbg_hex(u64::from(i.device_offset));
        dbg(" nmult=");
        dbg_hex(u64::from(i.notify_off_multiplier));
    }
    dbg("\n");

    // ── Step 2: MmioMap (70) — install the device CSR window ─────────────────
    let (mmio_va, mmio_errno) = unsafe {
        syscall5(
            SYS_MMIO_MAP,
            mmio_phys,
            mmio_len,
            MMIO_FLAGS_DEFAULT,
            mmio_token.as_ptr() as u64,
            mmio_token.len() as u64,
        )
    };
    dbg("[virtio-img] MmioMap -> va=");
    dbg_hex(mmio_va);
    dbg(" errno=");
    dbg_hex(mmio_errno);
    dbg("\n");
    if mmio_errno != 0 {
        unsafe { sys_exit(EXIT_MMIO_BASE + mmio_errno) };
    }
    // A null mapped VA means we cannot touch device registers; bail with a
    // distinct sentinel (immune to console interleave, unlike the printed VA).
    if mmio_va == 0 {
        unsafe { sys_exit(EXIT_MMIO_VA_NULL) };
    }

    // Base of the common-configuration register block within the mapped BAR.
    let common = mmio_va + vinfo.map_or(0u64, |i| u64::from(i.common_offset));

    // ── Step 2b: virtio device-status handshake (virtio 1.0 § 3.1.1 steps
    // 1-4) via the modern common_cfg block. These volatile reads/writes also
    // PROVE the mapped VA is real: a bad VA would #PF here, and the status
    // byte transitions (0 -> 1 -> 3 -> 0xB) are device-sourced and cannot be
    // forged by a wrong mapping.
    // SAFETY: `common` is inside the MmioMap'd BAR window (errno==0, va!=0).
    unsafe {
        // 1. Reset: write 0, then poll device_status until it reads back 0
        //    (virtio 1.0 § 3.1.1 step 1 — reset is not guaranteed synchronous).
        mmio_w8(common + VCFG_DEVICE_STATUS, VSTATUS_RESET);
        let mut s_reset = mmio_r8(common + VCFG_DEVICE_STATUS);
        let mut reset_spins = 0u32;
        while s_reset != 0 && reset_spins < 1_000_000 {
            s_reset = mmio_r8(common + VCFG_DEVICE_STATUS);
            reset_spins += 1;
        }
        // 2. ACKNOWLEDGE.
        mmio_w8(common + VCFG_DEVICE_STATUS, VSTATUS_ACKNOWLEDGE);
        // 3. DRIVER.
        mmio_w8(
            common + VCFG_DEVICE_STATUS,
            VSTATUS_ACKNOWLEDGE | VSTATUS_DRIVER,
        );
        let s_driver = mmio_r8(common + VCFG_DEVICE_STATUS);

        // 4. Feature negotiation. Read device feature word 0, accept the
        //    subset we understand (for M0: accept nothing beyond the mandatory
        //    VIRTIO_F_VERSION_1 in word 1; word 0 we clear so the device sees
        //    no legacy offloads we cannot honour). Minimal but spec-valid:
        //    select word 1, set VIRTIO_F_VERSION_1 (bit 32 -> word1 bit 0).
        mmio_w32(common + VCFG_DEVICE_FEATURE_SELECT, 0);
        let devfeat0 = mmio_r32(common + VCFG_DEVICE_FEATURE);
        mmio_w32(common + VCFG_DEVICE_FEATURE_SELECT, 1);
        let devfeat1 = mmio_r32(common + VCFG_DEVICE_FEATURE);
        // Driver features word 0 = none; word 1 = VIRTIO_F_VERSION_1 (bit 0).
        mmio_w32(common + VCFG_DRIVER_FEATURE_SELECT, 0);
        mmio_w32(common + VCFG_DRIVER_FEATURE, 0);
        mmio_w32(common + VCFG_DRIVER_FEATURE_SELECT, 1);
        mmio_w32(common + VCFG_DRIVER_FEATURE, 1); // VIRTIO_F_VERSION_1
        // 5. FEATURES_OK, then re-read to confirm the device accepted them.
        mmio_w8(
            common + VCFG_DEVICE_STATUS,
            VSTATUS_ACKNOWLEDGE | VSTATUS_DRIVER | VSTATUS_FEATURES_OK,
        );
        let s_featok = mmio_r8(common + VCFG_DEVICE_STATUS);
        let nq = mmio_r16(common + VCFG_NUM_QUEUES);

        dbg("[virtio-img] status reset=");
        dbg_hex(u64::from(s_reset));
        dbg(" driver=");
        dbg_hex(u64::from(s_driver));
        dbg(" featok=");
        dbg_hex(u64::from(s_featok));
        dbg(" devfeat0=");
        dbg_hex(u64::from(devfeat0));
        dbg(" devfeat1=");
        dbg_hex(u64::from(devfeat1));
        dbg(" num_queues=");
        dbg_hex(u64::from(nq));
        dbg("\n");

        if s_featok & VSTATUS_FEATURES_OK == 0 {
            sys_exit(EXIT_FEATURES_REJECTED);
        }
    }

    // ── Step 3: DmaMap (71) — install the 1-page IOVA arena ──────────────────
    // Unconditional bring-up dump: the exact (iova, len, dir, token_len) sent
    // and the (rax, errno) returned, so a non-zero errno is diagnosable from
    // serial alone rather than only as the opaque EXIT_DMA_BASE + errno code.
    dbg("[virtio-img] DmaMap iova=");
    dbg_hex(DMA_IOVA_BASE);
    dbg(" len=");
    dbg_hex(DMA_LEN);
    dbg(" dir=");
    dbg_hex(DMA_DIR_BIDIR);
    dbg(" tok_len=");
    dbg_hex(dma_token.len() as u64);
    dbg("\n");
    let (dma_iova, dma_errno) = unsafe {
        syscall5(
            SYS_DMA_MAP,
            DMA_IOVA_BASE,
            DMA_LEN,
            DMA_DIR_BIDIR,
            dma_token.as_ptr() as u64,
            dma_token.len() as u64,
        )
    };
    dbg("[virtio-img] DmaMap -> rax=");
    dbg_hex(dma_iova);
    dbg(" errno=");
    dbg_hex(dma_errno);
    dbg("\n");
    if dma_errno != 0 {
        unsafe { sys_exit(EXIT_DMA_BASE + dma_errno) };
    }
    // `dma_iova` (rax) is the DMA bus/physical base the DEVICE uses to read the
    // rings; the CPU accesses the same arena at user VA == DMA_IOVA_BASE
    // (identity-mapped by the kernel's dma_map). A null phys means we cannot
    // tell the device where the rings live — bail with a distinct sentinel.
    if dma_iova == 0 {
        unsafe { sys_exit(EXIT_DMA_PHYS_NULL) };
    }

    // ── Step 3a-bis: second DmaMap for the RX arena (page 1 of the 2-page
    // DMA scope). Same token (it covers both pages); distinct iova so the
    // kernel's duplicate-iova guard accepts it.
    let (rx_dma_iova, rx_dma_errno) = unsafe {
        syscall5(
            SYS_DMA_MAP,
            RX_DMA_IOVA_BASE,
            DMA_LEN,
            DMA_DIR_BIDIR,
            dma_token.as_ptr() as u64,
            dma_token.len() as u64,
        )
    };
    dbg("[virtio-img] RX DmaMap -> rax=");
    dbg_hex(rx_dma_iova);
    dbg(" errno=");
    dbg_hex(rx_dma_errno);
    dbg("\n");
    if rx_dma_errno != 0 {
        unsafe { sys_exit(EXIT_DMA_BASE + rx_dma_errno) };
    }
    if rx_dma_iova == 0 {
        unsafe { sys_exit(EXIT_DMA_PHYS_NULL) };
    }

    // ── Step 3b: NIC bring-up — program RX queue 0 + TX queue 1, set DRIVER_OK,
    // and transmit one ARP probe. Real M0 datapath: split virtqueues in the DMA
    // pages, device-physical ring addresses via common_cfg, notify doorbell,
    // used-ring poll. The ARP probe egress is observable on the Proxmox bridge;
    // RX queue 0 lets the device deliver the reply (and the eventual SYN-ACK).
    //
    // SAFETY: `common`/notify are inside the MmioMap'd BAR; the two DMA arenas
    // [DMA_IOVA_BASE,+0x1000) and [RX_DMA_IOVA_BASE,+0x1000) are mapped writable
    // and backed by phys `dma_iova` / `rx_dma_iova`. Returns the persistent TX
    // and RX engines for the service loop.
    let (mut tx_engine, mut rx_engine) = unsafe {
        nic_bringup(
            mmio_va,
            &vinfo,
            common,
            DMA_IOVA_BASE,
            dma_iova,
            RX_DMA_IOVA_BASE,
            rx_dma_iova,
        )
    };

    // ── Step 4: IpcCreateChannel × 3 ─────────────────────────────────────────
    //
    // Create the three channels this driver owns for M0:
    //   cmd_ch — command channel: receives NetRequest, sends NetResponse.
    //   evt_ch — event channel: sends NetEvent::FrameReceivedInline.
    //   irq_ch — IRQ-notify channel: receives 8-byte notifications from the
    //             kernel trampoline when the device asserts the IRQ line.
    let cmd_ch = unsafe { ipc_create_channel(IPC_QUEUE_DEPTH) };
    dbg("[virtio-img] cmd_ch=");
    dbg_hex(cmd_ch);
    dbg("\n");
    if cmd_ch == SYSCALL_ERROR {
        unsafe { sys_exit(EXIT_IPC_CREATE_CMD_FAILED) };
    }

    let evt_ch = unsafe { ipc_create_channel(IPC_QUEUE_DEPTH) };
    dbg("[virtio-img] evt_ch=");
    dbg_hex(evt_ch);
    dbg("\n");
    if evt_ch == SYSCALL_ERROR {
        unsafe { sys_exit(EXIT_IPC_CREATE_EVT_FAILED) };
    }

    let irq_ch = unsafe { ipc_create_channel(IPC_QUEUE_DEPTH) };
    dbg("[virtio-img] irq_ch=");
    dbg_hex(irq_ch);
    dbg("\n");
    if irq_ch == SYSCALL_ERROR {
        unsafe { sys_exit(EXIT_IPC_CREATE_IRQ_FAILED) };
    }

    // ── Step 5: IrqAttach (72) — bind IRQ to the irq channel ─────────────────
    //
    // The kernel trampoline enqueues an 8-byte notification on `irq_ch`
    // whenever the device asserts `IRQ_LINE_VIRTIO_NET`. The service loop
    // polls `irq_ch` (non-blocking) each iteration.
    //
    // This replaces IPC_CHANNEL_PLACEHOLDER = 0 which the kernel rejected.
    let (_irq_vec, irq_errno) = unsafe {
        syscall5(
            SYS_IRQ_ATTACH,
            IRQ_LINE_VIRTIO_NET,       // a0: IRQ line number
            irq_ch,                    // a1: IPC channel to notify on IRQ
            irq_token.as_ptr() as u64, // a2 → rdx: capability token pointer
            irq_token.len() as u64,    // a3 → r10: token length
            0,                         // a4: unused
        )
    };
    if irq_errno != 0 {
        unsafe { sys_exit(EXIT_IRQ_BASE + irq_errno) };
    }

    // ── Step 6: Drive the bring-up FSM to Phase::DriverOk ────────────────────
    //
    // With MMIO + DMA + IRQ installed, the FSM advances through its pure-state
    // phases. The library layer models each step as a state transition; the
    // actual MMIO register writes would happen here in a fully wired driver.
    let mut bringup = BringUp::new();
    while !bringup.phase().is_terminal() {
        match bringup.on_event(Event::Advance) {
            Ok(next) => bringup = next,
            Err(_) => break,
        }
    }

    if !matches!(bringup.phase(), Phase::DriverOk) {
        unsafe { sys_exit(EXIT_FSM_FAILED) };
    }

    // ── Step 7: Construct the driver struct ───────────────────────────────────
    //
    // The MAC address is the confirmed virtio MAC from the Proxmox test VM NIC net0:
    //   52:54:00:12:34:56  (from `qm config <vmid>`, verified 2026-05-29).
    // `nexacore-net` MUST be configured with `InterfaceConfig.mac = 52:54:00:12:34:56`
    // so it binds to this exact interface and not the e1000e NIC (net1).
    // Queue/buffer sizing for M0 must fit the 512 KiB bump heap. The original
    // (256, 256) allocated an RX pool of 256 × DEFAULT_RX_BUFFER_SIZE(2048) =
    // 512 KiB — the ENTIRE heap — plus two 256-entry virtqueues, so
    // VirtioNetDriver::new OOM'd and the panic handler issued TaskExit(2)
    // (observed on the test VM right after irq_ch was created). Use a small ring:
    // 16-entry TX/RX queues + 8 RX buffers (8 × 2048 = 16 KiB) is ample to
    // prove the M0 datapath and leaves the bulk of the heap for the service
    // loop's per-frame Vec allocations. A larger ring returns in M1 alongside
    // the slab/ring allocator (see module doc).
    let mut driver = VirtioNetDriver::new(16, 8);
    driver.mac = OUR_MAC;
    driver.link_up = true;
    driver.state = DriverState::Ready;

    // ── Step 8: NetRegister (100) — publish to kernel NET registry ────────────
    //
    // After this call, `nexacore-net` can resolve "virtio0" → (cmd_ch, evt_ch) via
    // `NetLookup (102)` without knowing the numeric channel ids directly.
    let (_reg_rax, reg_errno) = unsafe {
        net_register(
            IFACE_NAME.as_ptr() as u64, // "virtio0"
            IFACE_NAME.len() as u64,
            cmd_ch,
            evt_ch,
            driver.mac.as_ptr() as u64,
        )
    };
    if reg_errno != 0 {
        unsafe { sys_exit(EXIT_NET_REGISTER_BASE + reg_errno) };
    }

    // ── Step 9: Service loop ──────────────────────────────────────────────────
    //
    // Runs indefinitely until the command channel is destroyed (kernel shutdown
    // signal). Normal operation alternates between:
    //
    //   A) Non-blocking IRQ poll → drain RX completions → emit events.
    //   B) Blocking wait for a NetRequest → driver TX → send NetResponse.
    //
    // ## Memory: per-iteration allocations
    //
    // Each IRQ-triggered `encode_rx_event` allocates a `Vec<u8>` of ~1530
    // bytes that is never freed by the bump allocator. The command path
    // allocates ~2 bytes per response. With 512 KiB total heap, the driver
    // can handle approximately 85 000 RX frames before OOM (see module doc).

    // Large service-loop scratch buffers live in BSS (static mut), NOT on the
    // stack: `_start` already reserves a 4 KiB stack-probe frame and the whole
    // service loop is inlined into it, so a 4 KiB cmd buffer + a frame scratch
    // on the stack overflowed the 16 KiB user stack (observed as a near-null
    // #PF on the test VM). The image is single-threaded (one Ring-3 task), so a
    // `&mut` to each static is uniquely held for the loop's lifetime.
    // SAFETY: single task; these statics are not aliased elsewhere.
    let rx_buf: &mut [u8; IPC_MAX_PAYLOAD] = unsafe { &mut *core::ptr::addr_of_mut!(SVC_CMD_BUF) };
    let rx_frame: &mut [u8; 1600] = unsafe { &mut *core::ptr::addr_of_mut!(SVC_RX_FRAME) };
    let mut irq_buf = [0u8; 8];

    // RX is poll-driven (not IRQ-gated): robust on M0 where MSI-X delivery to
    // the Ring-3 driver is not yet wired. The irq channel is still drained
    // non-blockingly inside the loop so the kernel trampoline's notifications
    // do not back up.
    loop {
        // ── A) Real RX poll ───────────────────────────────────────────────
        // Poll the device's RX virtqueue (queue 0) directly. Each received
        // frame (vnet header already stripped by RxEngine::poll) is forwarded
        // to nexacore-net on the event channel as NetEvent::FrameReceivedInline.
        // This is what delivers the ARP reply / SYN-ACK back to the stack.
        let mut rx_did_work = false;
        if let Some(rx) = rx_engine.as_mut() {
            // Drain a bounded burst per iteration so one busy NIC cannot starve
            // the command path.
            for _ in 0..RX_RING_SIZE {
                // SAFETY: rx engine pointers valid for the driver lifetime.
                let Some(eth_len) = (unsafe { rx.poll(rx_frame.as_mut_slice()) }) else {
                    break;
                };
                let Some(frame_slice) = rx_frame.get(..eth_len) else {
                    continue;
                };
                // RX ingress filter: forward ONLY unicast frames addressed to
                // our MAC. That is everything the M0 outbound datapath needs —
                // the TCP SYN-ACK/data are unicast to us, and an ARP *reply* is
                // unicast to the requester (us), so next-hop resolution still
                // works. Dropping broadcast + multicast removes the bridge flood
                // (ARP-for-others, DHCP, mDNS/SSDP, IPv6-ND) the M0 stack never
                // consumes; left in, each frame allocated a kernel IPC envelope
                // in the kernel's (non-freeing) heap and OOM'd the kernel right
                // after the SYN. A dropped frame is NOT counted as work, so the
                // loop yields instead of busy-spinning the flood at System
                // priority (which starved nexacore-net/netcheck). (2026-06-04)
                if frame_slice.get(..6) != Some(OUR_MAC.as_slice()) {
                    continue;
                }
                rx_did_work = true;
                let encoded: Vec<u8> = match encode_rx_event(frame_slice.to_vec()) {
                    Ok(b) => b,
                    Err(ServiceLoopError::Encode | ServiceLoopError::Decode) => continue,
                };
                let _send_result = unsafe {
                    ipc_send(
                        evt_ch,
                        IPC_KIND_NOTIFICATION,
                        encoded.as_ptr() as u64,
                        encoded.len() as u64,
                    )
                };
            }
        }
        // Drain the IRQ-notify channel (non-blocking) so it does not back up.
        let _ = unsafe {
            ipc_receive(
                irq_ch,
                irq_buf.as_mut_ptr() as u64,
                irq_buf.len() as u64,
                false,
            )
        };

        // ── B) Non-blocking receive on command channel ─────────────────────
        //
        // Non-blocking so the RX poll above runs every iteration (a blocking
        // cmd receive would stall RX while no TX request is pending — then the
        // ARP reply / SYN-ACK would never be delivered to the stack).
        let (cmd_bytes, cmd_err) = unsafe {
            ipc_receive(
                cmd_ch,
                rx_buf.as_mut_ptr() as u64,
                rx_buf.len() as u64,
                false, // non-blocking
            )
        };

        // Channel destroyed or hard error → clean shutdown.
        if cmd_err != 0 || cmd_bytes == SYSCALL_ERROR {
            unsafe { sys_exit(EXIT_OK) };
        }

        // No command this iteration → ALWAYS yield. Bounding the driver's turn
        // to one RX burst (≤ RX_RING_SIZE frames) per schedule keeps it from
        // monopolising a System-priority slice while draining a busy bridge; the
        // RX ring naturally rate-limits ingress (excess flood dropped by the
        // device when buffers are full) and the unicast SYN-ACK still lands
        // within a few turns. `rx_did_work` retained only for diagnostics.
        if cmd_bytes == 0 {
            let _ = rx_did_work;
            sys_task_yield();
            continue;
        }

        // Decode the IPC payload. On failure, reply with InvalidArgument so
        // nexacore-net can detect and log the malformed message.
        let payload = match rx_buf.get(..cmd_bytes as usize) {
            Some(s) => s,
            None => {
                // `cmd_bytes` exceeded our buffer capacity — should be
                // impossible (kernel enforces MAX_PAYLOAD), but handle
                // defensively.
                continue;
            }
        };

        let net_req = match decode_net_request(payload) {
            Ok(r) => r,
            Err(_) => {
                // Malformed / non-request payload: DROP it. We must NOT reply on
                // `cmd_ch` — see the no-reply contract below. Replying here was
                // the M0 kernel-heap OOM root cause: the driver is the sole
                // receiver on `cmd_ch`, so any reply it sent there it then
                // re-received, failed to decode, replied again, ad infinitum —
                // a 66.6M-iteration `ipc_send` storm that leaked the kernel's
                // non-freeing BumpHeap to exhaustion (HW-captured 2026-06-04).
                continue;
            }
        };

        // TX path. For SendFrameInline, transmit through the REAL MMIO TX
        // engine (the virtqueue the device actually drains) when it is up —
        // this is what puts nexacore-net's frames (SYN, ARP, …) on the wire. Fall
        // back to the library's in-memory handle_request only if the engine
        // never initialised (no device-info geometry). All other request
        // variants (GetMac/GetLinkState/…) stay on handle_request.
        //
        // NO-REPLY CONTRACT (M0): `cmd_ch` is a ONE-WAY request channel
        // (nexacore-net → driver). nexacore-net's TX is fire-and-forget — it never
        // receives a reply — and the driver is the SOLE receiver on `cmd_ch`,
        // so any reply the driver sent on `cmd_ch` it would immediately
        // re-receive itself (see the decode-failure drop above). Sending the
        // NetResponse here was the M0 OOM root cause (66.6M-iteration self-feed
        // ipc_send storm, kernel BumpHeap exhausted — HW-captured 2026-06-04).
        // The TX is performed for its side effect (frame on the wire); the
        // response value is intentionally discarded. Query requests that need a
        // reply (GetMac/GetLinkState) return in M1 on a DEDICATED reply channel
        // (mirroring nexacore-net's stack / stack_reply split), never on `cmd_ch`.
        match (&mut tx_engine, &net_req) {
            (Some(tx), NetRequest::SendFrameInline { bytes }) => {
                if !bytes.is_empty() {
                    // SAFETY: tx_engine pointers are valid for the driver's
                    // lifetime (MmioMap'd BAR + DmaMap'd arena).
                    let sent = unsafe { tx.send(bytes) };
                    dbg("[virtio-img] svc TX len=");
                    dbg_hex(bytes.len() as u64);
                    dbg(if sent { " (SENT)\n" } else { " (TIMEOUT)\n" });
                }
            }
            _ => {
                // Non-TX request (or no TX engine): drive the in-memory FSM for
                // its state side effects; the response is discarded (no reply
                // channel in M0 — see the NO-REPLY CONTRACT above).
                let _ = driver.handle_request(&net_req);
            }
        }
    }
}

// =============================================================================
// Panic handler (required by `no_std`)
// =============================================================================

/// Panic handler — exit with sentinel code `2`.
///
/// The panic info is intentionally not formatted because doing so requires
/// an allocator that may itself be in a broken state during a panic.
/// Code `2` is distinct from all normal exit codes and from `EXIT_OK (0)` /
/// `EXIT_FSM_FAILED (1)`.
#[panic_handler]
fn panic(_info: &PanicInfo<'_>) -> ! {
    // SAFETY: TaskExit (11) terminates the process unconditionally.
    unsafe { sys_exit(2) }
}
