//! NexaCore OS NVMe bootable driver image — TASK-14 (ADR-0036) BLK service loop.
//!
//! `no_std + no_main` ELF entry that the kernel `DriverLoad (73)`
//! syscall ingests per `NCIP-Driver-Framework-013` § S5.3 step 9. The
//! kernel calls `spawn_from_elf` against this binary, which lands at
//! `_start` in a freshly minted Ring 3 process. Before transferring
//! control the kernel writes the per-driver capability deposit at the
//! well-known user-VA slot [`nexacore_driver_shared::DRIVER_CAP_DEPOSIT_VA`]
//! (P6.7.8.9, NCIP-013 § S5.3 step 8); the image reads tokens from that
//! window via [`nexacore_driver_shared::caps::find_token`] and forwards them
//! to the kernel through the `MmioMap (70)` / `DmaMap (71)` syscalls.
//!
//! ## DMA dual-address model (ADR-0036 appendix 2)
//!
//! `DmaMap (71)` is a **dual-address** syscall: it returns the allocated
//! **physical** base in `rax` (the IOVA carries the CPU virtual address).
//! Under the IOMMU's TE-off passthrough, the NVMe controller DMAs to the
//! **physical** address — the SLPT iova→phys tree is inert until the
//! operator-gated TE flip. Therefore:
//!
//! - Device-address sites (admin queue base registers, Create-IO-Queue PRPs,
//!   Read/Write/Identify PRP1) are programmed with the **DmaMap-returned phys**.
//! - CPU-access sites (ring slices built via `from_raw_parts[_mut]`,
//!   identify response reads, bounce buffer accesses) use the **iova** —
//!   the kernel maps `iova → phys` in the driver's page table for CPU access.
//!
//! Each of the 8 DMA regions is mapped as a **separate 1-page `DmaMap`** call
//! so the kernel's strictly-contiguous-frame requirement is trivially satisfied
//! (one frame is always contiguous). The one deposited `DmaWindow` token
//! covers the full `[DMA_IOVA_BASE, DMA_IOVA_BASE + 0x8000)` range and can be
//! used for all 8 sub-windows (same one-token-many-submaps pattern as
//! `nexacore-driver-net-virtio-image`'s TX/RX regions). This mirrors the
//! virtio-net driver which keeps `dma_va` (CPU) and `dma_phys` (device)
//! separately.
//!
//! ## Execution path (TASK-14 — Option A cooperative-yield, ADR-0036 D5)
//!
//! Bring-up (steps 1–22) is identical to previous iterations, minus
//! `IrqAttach` (Option A does not use interrupts, ADR-0036 appendix):
//!
//! 1. `find_token(ACTION_TAG_MMIO_MAP, ..)`  — retrieve the MMIO token.
//! 2. `find_token(ACTION_TAG_DMA_MAP, ..)`   — retrieve the DMA token.
//! 3. `syscall MmioMap`   — map the NVMe BAR0 16 KiB CSR window.
//! 4. `syscall DmaMap`    — install the 4 GiB IOVA arena.
//! 5. `syscall IpcCreateChannel(20)` — allocate `nvme0` request channel.
//! 6. `syscall BlkRegister(76)` — register `nvme0` → channel_id.
//! 7. `syscall BlkLookup(78)` — defence-in-depth round-trip for `nvme0`.
//! 8. `syscall IpcCreateChannel(20)` — allocate `nvme0-reply` reply channel
//!    (ADR-0036 D2: separate request / reply queues eliminate kind
//!    contention by construction).
//! 9. `syscall BlkRegister(76)` — register `nvme0-reply` → reply_channel_id.
//! 10. `disable_controller` + `program_admin_queue_bases` +
//!     `program_cc_fields` + `enable_controller` (NVMe 1.4 § 3.1).
//! 11. `check_controller_fatal` — abort if `CSTS.CFS = 1`.
//! 12. `AdminQueuePair::new` — construct the admin queue pair.
//! 13. `encode_identify(IdentifyTarget::Controller)` → poll → validate.
//! 14. `encode_identify(IdentifyTarget::ActiveNsList)` → poll → parse
//!     `first_nsid`.
//! 15. `encode_identify(IdentifyTarget::Namespace{nsid})` → poll →
//!     validate 4 KiB sector (`LBADS = 12`) + MSI-X vector check.
//! 16. `encode_create_io_cq` + `encode_create_io_sq` → poll (IO QID 1).
//! 17. `AdminQueuePair::new_for_qid` — construct the IO queue pair.
//!
//! After bring-up the image prints a ready banner and enters the
//! **BLK service loop** (never exits on success):
//!
//! ```text
//! loop:
//!   IpcTryReceive(nvme0) → decode BlkRequest
//!     Read  {lba,count=1} → encode_read  → submit → drain_io (cooperative
//!                           yield) → IpcSend(nvme0-reply, Ok) + 2 chunks
//!     Write {lba,count=1} → receive 2 chunks from nvme0 → copy to DMA
//!                           bounce buffer → encode_write → drain_io →
//!                           IpcSend(nvme0-reply, Ok)
//!     Flush               → encode_flush → drain_io → IpcSend(nvme0-reply, Ok)
//!     Discard             → IpcSend(nvme0-reply, NotSupported)
//!     else                → TaskYield
//! ```
//!
//! Completion wait (`drain_io`) is **cooperative-yield**: the driver
//! loops on `drain_completion`; when the CQ slot is empty (`Ok(None)`)
//! it calls `TaskYield` so the scheduler can run other tasks between
//! polls. A bounded iteration budget (`DRAIN_IO_BUDGET`) guards against
//! a wedged controller (ADR-0036 D5, Option A).
//!
//! ## Exit codes
//!
//! The service loop normally **never exits**. The driver exits only on
//! fatal bring-up failures (non-zero sentinels documented in the `EXIT_*`
//! constants below). `EXIT_OK (0)` is reserved for a future clean-shutdown
//! path.
//!
//! ## Standalone execution
//!
//! When this binary is executed without going through `DriverLoad` (a
//! diagnostic scenario), `find_token` returns `None` because the deposit
//! page is not mapped; the image then exits with sentinel codes 10/20
//! identifying which token is missing.
//!
//! Build:
//!
//! ```sh
//! cargo build --manifest-path crates/nexacore-driver-nvme-image/Cargo.toml \
//!             --target x86_64-unknown-none --release
//! ```

#![no_std]
#![no_main]
#![allow(unsafe_code)]
#![warn(missing_docs)]

use core::alloc::{GlobalAlloc, Layout};
use core::panic::PanicInfo;

use nexacore_driver_nvme::admin::{
    CIOSQ_QPRIO_MEDIUM, IdentifyTarget, encode_create_io_cq, encode_create_io_sq, encode_identify,
};
use nexacore_driver_nvme::blk_gateway::cqe_to_blk_response;
use nexacore_driver_nvme::controller_regs::{
    CAP_OFFSET, CSTS_OFFSET, VS_OFFSET, cap_dstrd, cap_mpsmin, cap_mqes, vs_major,
};
use nexacore_driver_nvme::identify::{ActiveNsListView, IdentifyController, IdentifyNamespace};
use nexacore_driver_nvme::interrupt::MsixConfig;
use nexacore_driver_nvme::io::{encode_flush, encode_read, encode_write};
use nexacore_driver_nvme::namespace_map::NamespaceDescriptor;
use nexacore_driver_nvme::queue::{
    AdminQueuePair, MmioBackend, MmioReadBackend, PHASE_1_IOCQES_LOG2, PHASE_1_IOSQES_LOG2,
    PHASE_1_MPS_LOG2, check_controller_fatal, disable_controller, enable_controller,
    program_admin_queue_bases, program_cc_fields,
};
use nexacore_driver_shared::{
    ACTION_TAG_DMA_MAP, ACTION_TAG_IRQ_ATTACH, ACTION_TAG_MMIO_MAP, caps::find_token,
};
use nexacore_types::blk::{BlkRequest, BlkResponse};
use nexacore_types::wire::{decode_canonical, encode_into_slice};

// =============================================================================
// Global allocator stub
// =============================================================================

struct PanicOnAlloc;

unsafe impl GlobalAlloc for PanicOnAlloc {
    unsafe fn alloc(&self, _layout: Layout) -> *mut u8 {
        // SAFETY: any reachable allocation is a driver bug — bail loudly.
        panic!("nexacore-driver-nvme-image: heap alloc requested but no allocator is wired");
    }
    unsafe fn dealloc(&self, _ptr: *mut u8, _layout: Layout) {
        // No-op without a heap.
    }
}

#[global_allocator]
static GLOBAL_ALLOC: PanicOnAlloc = PanicOnAlloc;

// =============================================================================
// Syscall numbers
// =============================================================================

/// `TaskExit (11)`.
const SYS_TASK_EXIT: u64 = 11;
/// `TaskYield (12)` — yield the CPU to the next runnable task.
/// Used by the cooperative-yield BLK service loop (ADR-0036 D5, Option A).
const SYS_TASK_YIELD: u64 = 12;
/// `IpcCreateChannel (20)` — allocates the kernel-side BLK channel.
const SYS_IPC_CREATE_CHANNEL: u64 = 20;
/// `IpcSend (22)` — send a message on a channel.
/// ABI (mirrored from `nexacore-runtime-image` + kernel `ipc_handlers::ipc_send`):
/// `rdi=channel_id, rsi=kind, rdx=payload_ptr, r10=payload_len` →
/// `rax=0` on success, `rax=u64::MAX` on error.
/// Source: `crates/nexacore-runtime-image/src/main.rs:254–268` +
///         `crates/nexacore-kernel/src/bare_metal/syscall_entry.rs:752–813`.
const SYS_IPC_SEND: u64 = 22;
/// `IpcTryReceive (24)` — non-blocking receive.
/// ABI (mirrored from `nexacore-runtime-image` + kernel `ipc_handlers::ipc_try_receive`):
/// `rdi=channel_id, rsi=dst_ptr, rdx=dst_cap` →
/// `rax=bytes_copied` on success, `rax=u64::MAX` when queue is empty or on error.
/// Source: `crates/nexacore-runtime-image/src/main.rs:272–295` +
///         `crates/nexacore-kernel/src/bare_metal/syscall_entry.rs:888–928`.
const SYS_IPC_TRY_RECEIVE: u64 = 24;
/// `MmioMap (70)`.
const SYS_MMIO_MAP: u64 = 70;
/// `DmaMap (71)`.
const SYS_DMA_MAP: u64 = 71;
/// `BlkRegister (76)` — records the `nexacore.svc.blk.<disk_slot>` → live
/// `ChannelId` mapping in the kernel BLK registry per
/// `NCIP-Driver-NVMe-014` § S4 + § S6 step 12 (P6.7.10-pre.3).
const SYS_BLK_REGISTER: u64 = 76;
/// `BlkLookup (78)` — read-only resolution of `disk_slot → ChannelId`
/// against the kernel BLK registry (P6.7.10-pre.3).
const SYS_BLK_LOOKUP: u64 = 78;
/// `IrqAttach (72)` — bind an interrupt line to an IPC channel
/// (WS1-07, ADR-0036 D5 / Option B). ABI (kernel
/// `irq_attach_handlers::irq_attach`):
/// `rdi=irq_line, rsi=ipc_channel_id, rdx=cap_ptr, r10=cap_len` →
/// `rax=allocated LAPIC vector (0x40..0xFE)`, `rdx=errno`.
/// The kernel verifies the deposited `Resource::IrqLine` token, binds
/// the vector to the channel in the IRQ routing table, and programs the
/// device's MSI-X table entry 0 (registered at boot, WS1-06) so the
/// device fires the vector on the BSP; each fire enqueues an 8-byte
/// `Notification` message (the vector, LE) on the channel.
const SYS_IRQ_ATTACH: u64 = 72;
/// `WriteConsole (60)` — write bytes to the kernel console (COM1).
const SYS_WRITE_CONSOLE: u64 = 60;

// =============================================================================
// IPC message kind constants (mirror `nexacore_kernel::ipc::MessageKind`)
// =============================================================================

/// `MessageKind::Reply = 2` per `crates/nexacore-kernel/src/ipc.rs:70`.
/// Used by the BLK service loop when sending `BlkResponse` and inline
/// data chunks back to the client on `nvme0-reply`.
const IPC_KIND_REPLY: u64 = 2;

// =============================================================================
// Driver-specific placeholder constants (mirror `manifest.toml`)
// =============================================================================

/// NVMe BAR0 physical base address (QEMU `-device nvme` Q35 default).
const NVME_BAR0_PHYS_BASE: u64 = 0xFEBF_0000;

/// NVMe BAR0 length per NCIP-014 § S1 (16 KiB CSR window).
const NVME_BAR0_LEN: u64 = 0x4000;

/// MmioMap flags = 0 (uncached default).
const MMIO_FLAGS_DEFAULT: u64 = 0;

/// DMA arena IOVA base — the kernel's driver-DMA window
/// `DRIVER_DMA_VA_BASE` (TASK-14, ADR-0036). `DmaMap (71)` rejects any
/// `iova_base < DRIVER_DMA_VA_BASE` (syscall_entry.rs DmaMap validation),
/// so the old `0x0` base was an EINVAL by construction. In this window
/// the kernel maps `user_va == iova`, so the queue/buffer pointers below
/// dereference the very IOVAs the controller is handed.
const DMA_IOVA_BASE: u64 = 0x0000_0100_0000_0000;

/// DMA direction = bidirectional (NVMe reads + writes share the arena).
///
/// Passed to every per-page `dma_map_page` call. The single deposited
/// `DmaWindow` token covers `[DMA_IOVA_BASE, DMA_IOVA_BASE + 0x8000)` and
/// permits all 8 sub-window mappings (one-token-many-submaps pattern,
/// ADR-0036 appendix 2).
const DMA_DIR_BIDIR: u64 = 2;

// =============================================================================
// BLK channel constants (P6.7.10-pre.4, NCIP-Driver-NVMe-014 § S4;
//                        TASK-14 adds reply channel, ADR-0036 D2)
// =============================================================================

/// Disk slot identifier for the single Phase-1 NVMe controller. Matches
/// the canonical channel name `nexacore.svc.blk.nvme0` that
/// `crates/nexacore-kernel/src/services/blk.rs` pre-builds at registration
/// time. The byte slice avoids the heap because this binary cannot
/// allocate (`PanicOnAlloc` global allocator).
const NVME_DISK_SLOT: &[u8] = b"nvme0";

/// Disk slot identifier for the NVMe reply channel (ADR-0036 D2).
/// Clients read completed BlkResponse + data chunks from this channel;
/// separating request and reply queues eliminates kind-contention by
/// construction (TASK-13 lesson).
const NVME_DISK_SLOT_REPLY: &[u8] = b"nvme0-reply";

/// BLK channel queue depth. NCIP-Driver-NVMe-014 § S6 step 12 freezes
/// the value at 1024 — generous for a single-namespace bring-up and
/// matched by the kernel's per-channel `Vec` reserve.
const BLK_CHANNEL_QUEUE_DEPTH: u64 = 1024;

/// `BackpressurePolicy::Block` — the producer parks on a full queue.
/// Matches `NCIP-Driver-NVMe-014` § S4 (`backpressure = true`).
const BLK_CHANNEL_BACKPRESSURE_BLOCK: u64 = 0;

/// Not TEE-bound — the NVMe driver runs in the regular Ring 3 process.
const BLK_CHANNEL_TEE_NOT_BOUND: u64 = 0;

// =============================================================================
// IRQ notification channel constants (WS1-07, ADR-0036 D5 / Option B)
// =============================================================================

/// IRQ-line identifier for the NVMe IO CQ, per the WS1-06 project
/// convention (33 = virtio-net, **34 = NVMe**, 35 = e1000e). MUST match
/// both the `Resource::IrqLine(34)` capability the kernel deposits and
/// the boot-time `msix::register` key — the kernel matches
/// `IrqAttach(irq_line)` against that registration to program the
/// device's MSI-X table.
const NVME_IRQ_LINE: u64 = 34;

/// IRQ notification channel queue depth. The v0.3 single-in-flight
/// model produces at most one outstanding completion notification;
/// 64 absorbs any coalescing burst without ever filling.
const IRQ_CHANNEL_QUEUE_DEPTH: u64 = 64;

/// `BackpressurePolicy::EvictOldest` (= 2 in the `IpcCreateChannel`
/// ABI). The notification producer is the kernel IRQ dispatch path,
/// which must NEVER block; evicting the oldest signal is lossless
/// here because any single notification means exactly "drain the CQ".
const IRQ_CHANNEL_BACKPRESSURE_EVICT_OLDEST: u64 = 2;

// =============================================================================
// NVMe admin queue constants (P6.7.10-pre.17, NCIP-Driver-NVMe-014 § S6)
// =============================================================================

/// Admin Submission Queue depth (NCIP-NVMe-014 § S1 default
/// `admin_sq_depth = 64`).
const NVME_ADMIN_SQ_DEPTH: u32 = 64;

/// Admin Completion Queue depth (NCIP-NVMe-014 § S1 default
/// `admin_cq_depth = 64`).
const NVME_ADMIN_CQ_DEPTH: u32 = 64;

/// IOVA offset (inside the 4 GiB DMA arena) of the Admin Submission
/// Queue data page. Page-aligned to 4 KiB per NVMe 1.4 § 3.1.9.
const NVME_ASQ_IOVA: u64 = DMA_IOVA_BASE;

/// IOVA offset of the Admin Completion Queue data page. Placed
/// 4 KiB past `NVME_ASQ_IOVA` so the two queues live in adjacent
/// 4 KiB regions of the DMA arena.
const NVME_ACQ_IOVA: u64 = DMA_IOVA_BASE + 0x1000;

/// Poll budget for the `CSTS.RDY` enable/disable transitions. NVMe
/// 1.4 § 3.1.6 says the controller MUST respond within `CAP.TO`
/// 500 ms units; QEMU virtualised NVMe responds within
/// microseconds, so `10_000` iterations is generously above any
/// realistic latency.
const NVME_CSTS_POLL_LIMIT: u32 = 10_000;

/// Admin doorbell stride (`CAP.DSTRD` field). Phase-1 pins the
/// expected value to `0` (4-byte stride) per NVMe 1.4 § 3.1.1
/// the most common controller default. A future slice will read
/// `CAP.DSTRD` from BAR0 and propagate it dynamically; for
/// `nexacore-driver-nvme-image` the static value matches both the
/// QEMU virtualised NVMe and every commercial controller's
/// default. P6.7.10-pre.33.
const NVME_ADMIN_DSTRD_DEFAULT: u8 = 0;

/// Backing-page size of the admin SQ + admin CQ in the DMA arena.
/// 64 SQEs × 64 bytes = 4096; 64 CQEs × 16 bytes = 1024. Both
/// queues live inside a single 4 KiB physical page so the IOVAs
/// satisfy the NVMe 1.4 § 3.1.9 page-alignment requirement and
/// the per-queue `&mut [u8]` accessor spans exactly one page.
const NVME_ADMIN_QUEUE_PAGE_BYTES: usize = 4096;

/// IOVA offset (inside the DMA arena) of the response page the
/// controller writes the Identify Controller response into.
/// Placed at offset `0x2000` so it lives in the third 4 KiB page
/// after the ASQ (offset `0x0`) and the ACQ (offset `0x1000`).
/// 4 KiB-aligned by construction per NVMe 1.4 § 5.15 (Identify
/// response is exactly 4 KiB; PRP1 alone covers it; PRP2 is
/// zero). The response itself is not yet parsed by the image —
/// a future slice will use [`nexacore_driver_nvme::identify::ControllerView`]
/// against this page. P6.7.10-pre.33.
const NVME_IDENTIFY_CTRL_RESP_IOVA: u64 = DMA_IOVA_BASE + 0x2000;

/// Poll budget for the Identify Controller completion. Each
/// iteration is a single CSTS-equivalent read of the CQ slot
/// header; QEMU virtualised NVMe completes Identify within tens
/// of microseconds, so `50_000` iterations is generously above
/// any realistic admin-command latency. P6.7.10-pre.33.
const NVME_IDENTIFY_POLL_LIMIT: u32 = 50_000;

/// First CID the image hands out for the Identify Controller
/// command. CID `0` is reserved by `nexacore_types::nvme` (the
/// `RESERVED_DRIVER_OPAQUE_ID`), so the image starts at `1`
/// — matching the `AdminSession::allocate_cid` skip-on-wrap
/// policy that the host-side reference implementation uses.
const NVME_IDENTIFY_FIRST_CID: u16 = 1;

/// IOVA offset (inside the DMA arena) of the response page the
/// controller writes the `Identify(ActiveNsList)` response into.
/// Placed at offset `0x3000` so it lives in the fourth 4 KiB page
/// after the ASQ (`0x0`), the ACQ (`0x1000`), and the Identify
/// Controller response (`0x2000`). 4 KiB-aligned by construction
/// per NVMe 1.4 § 5.15 (Active Namespace ID list response is
/// exactly 4 KiB; PRP1 alone covers it; PRP2 is zero). The page
/// is parsed by [`ActiveNsListView::new`] in
/// step 4.16.d. P6.7.10-pre.34.
const NVME_IDENTIFY_NS_LIST_RESP_IOVA: u64 = DMA_IOVA_BASE + 0x3000;

/// CID the image hands out for the Identify(ActiveNsList)
/// command — `NVME_IDENTIFY_FIRST_CID + 1`. The Phase-1 bring-up
/// issues admin commands strictly serially, so the CID counter
/// is a simple `+1` for each new command; reusing `submit_identify`
/// (the alloc-bound host-side helper) is not possible here because
/// the image runs under `PanicOnAlloc`.
const NVME_IDENTIFY_NS_LIST_CID: u16 = 2;

/// Poll budget for the Identify(ActiveNsList) completion. Same
/// rationale as [`NVME_IDENTIFY_POLL_LIMIT`]: QEMU virtualised
/// NVMe completes admin commands within tens of microseconds,
/// `50_000` iterations is well above any realistic latency.
/// New in P6.7.10-pre.34.
const NVME_IDENTIFY_NS_LIST_POLL_LIMIT: u32 = 50_000;

/// Backing-page size of the `Identify(ActiveNsList)` response —
/// exactly 4 KiB per NVMe 1.4 § 5.15.2 Figure 246. Matches
/// `nexacore_driver_nvme::identify::IDENTIFY_RESPONSE_BYTES`; pinned
/// locally so the slice construction is alloc-free.
/// New in P6.7.10-pre.34.
const NVME_IDENTIFY_NS_LIST_RESP_BYTES: usize = 4096;

/// IOVA offset (inside the DMA arena) of the response page the
/// controller writes the `Identify(Namespace)` response into.
/// Placed at offset `0x4000` so it lives in the fifth 4 KiB page
/// after the ASQ (`0x0`), ACQ (`0x1000`), Identify Controller
/// response (`0x2000`), and Active Namespace List response
/// (`0x3000`). 4 KiB-aligned by construction per NVMe 1.4 § 5.15
/// (Identify response is exactly 4 KiB; PRP1 alone covers it;
/// PRP2 is zero). New in P6.7.10-pre.35.
const NVME_IDENTIFY_NS_RESP_IOVA: u64 = DMA_IOVA_BASE + 0x4000;

/// CID the image hands out for the `Identify(Namespace)` command
/// — `NVME_IDENTIFY_NS_LIST_CID + 1 = 3`. Third admin command in
/// the serial bring-up sequence. New in P6.7.10-pre.35.
const NVME_IDENTIFY_NS_CID: u16 = 3;

/// Poll budget for the `Identify(Namespace)` completion. Same
/// rationale as [`NVME_IDENTIFY_POLL_LIMIT`]: QEMU virtualised
/// NVMe completes admin commands within tens of microseconds.
/// New in P6.7.10-pre.35.
const NVME_IDENTIFY_NS_POLL_LIMIT: u32 = 50_000;

/// Backing-page size of the `Identify(Namespace)` response —
/// exactly 4 KiB per NVMe 1.4 § 5.15.2 Figure 245. New in
/// P6.7.10-pre.35.
const NVME_IDENTIFY_NS_RESP_BYTES: usize = 4096;

// =============================================================================
// IO queue creation constants (P6.7.10-pre.36, NCIP-Driver-NVMe-014 § R2)
// =============================================================================

/// IOVA offset (inside the DMA arena) of the IO Completion Queue data
/// page. Placed at offset `0x5000` so it lives in the sixth 4 KiB
/// page after the ASQ (`0x0`), ACQ (`0x1000`), Identify Controller
/// response (`0x2000`), Active Namespace List response (`0x3000`),
/// and Identify Namespace response (`0x4000`). New in P6.7.10-pre.36.
const NVME_IO_CQ_IOVA: u64 = DMA_IOVA_BASE + 0x5000;

/// IOVA offset of the IO Submission Queue data page. Placed at
/// `0x6000` (seventh 4 KiB page). New in P6.7.10-pre.36.
const NVME_IO_SQ_IOVA: u64 = DMA_IOVA_BASE + 0x6000;

/// IO queue depth for both the IO CQ and IO SQ. Phase-1 pins this
/// to 64 entries per NCIP-Driver-NVMe-014 § R2 (matches the admin
/// queue depth for simplicity; production drivers may use up to
/// 65535). New in P6.7.10-pre.36.
const NVME_IO_QUEUE_DEPTH: u16 = 64;

/// IO CQ/SQ Queue Identifier — Phase-1 creates exactly one IO queue
/// pair with QID 1 per NCIP-014 § R5. New in P6.7.10-pre.36.
const NVME_IO_QID: u16 = 1;

/// MSI-X interrupt vector the IO CQ completions signal on. Phase-1
/// uses vector 0 (shared with the admin CQ); a future multi-queue
/// slice will assign distinct vectors per IO CQ. New in P6.7.10-pre.36.
const NVME_IO_CQ_IRQ_VECTOR: u16 = 0;

/// CID for the `Create I/O Completion Queue` admin command —
/// `NVME_IDENTIFY_NS_CID + 1 = 4`. Fourth admin command in the
/// serial bring-up sequence. New in P6.7.10-pre.36.
const NVME_CREATE_IO_CQ_CID: u16 = 4;

/// CID for the `Create I/O Submission Queue` admin command —
/// `NVME_CREATE_IO_CQ_CID + 1 = 5`. Fifth admin command. New in
/// P6.7.10-pre.36.
const NVME_CREATE_IO_SQ_CID: u16 = 5;

/// Poll budget for the IO queue creation completions. Same rationale
/// as [`NVME_IDENTIFY_POLL_LIMIT`]. New in P6.7.10-pre.36.
const NVME_CREATE_IO_POLL_LIMIT: u32 = 50_000;

// =============================================================================
// IO data buffer constants (TASK-14, ADR-0036 D3 bounce buffer)
// =============================================================================

/// IOVA offset (inside the DMA arena) of the 4 KiB DMA bounce buffer.
/// Used by the BLK service loop for both Read (controller writes here)
/// and Write (driver copies client data here before NVM Write). Placed
/// at `0x7000` (eighth 4 KiB page). Reused from P6.7.10-pre.37.
const NVME_IO_READ_DATA_IOVA: u64 = DMA_IOVA_BASE + 0x7000;

/// DMA bounce buffer size — exactly 4 KiB (one sector at LBADS=12).
const NVME_IO_READ_DATA_BYTES: usize = 4096;

// =============================================================================
// LiveMmioBackend — `MmioBackend` + `MmioReadBackend` impl for the
// live driver (P6.7.10-pre.17)
// =============================================================================

/// Thin newtype wrapping the BAR0 user-VA the kernel returned from
/// `MmioMap`. Implements [`MmioBackend`] (volatile_write) and
/// [`MmioReadBackend`] (volatile_read) so the helpers landed in
/// P6.7.10-pre.11..16 drive the live controller without any
/// shared mutable state.
///
/// The struct is `Copy` so the driver can create two independent
/// instances (one passed as the read backend, one as the write
/// backend) to satisfy the two-mutable-reference signature of
/// `disable_controller`/`enable_controller`. No state is held, so
/// the duplication is zero-cost.
#[derive(Clone, Copy)]
struct LiveMmioBackend {
    mmio_va_base: u64,
}

impl MmioBackend for LiveMmioBackend {
    #[inline]
    fn write_doorbell(&mut self, offset: usize, value: u32) {
        // SAFETY: `mmio_va_base + offset` is inside the BAR0 region
        // the kernel mapped via MmioMap; the controller register
        // file is at least `CONTROLLER_REGISTER_REGION_BYTES` long,
        // and NCIP-014 § S2.2 step 2 marked the region uncached so
        // the volatile_write reaches the hardware directly.
        unsafe {
            let ptr = (self.mmio_va_base as usize + offset) as *mut u32;
            ptr.write_volatile(value);
        }
    }
}

impl MmioReadBackend for LiveMmioBackend {
    #[inline]
    fn read_register(&mut self, offset: usize) -> u32 {
        // SAFETY: same as `write_doorbell` — region is uncached and
        // owned by the kernel mapping; 32-bit aligned reads are
        // mandated by NVMe 1.4 § 3.0.
        unsafe {
            let ptr = (self.mmio_va_base as usize + offset) as *const u32;
            ptr.read_volatile()
        }
    }
}

// =============================================================================
// TaskExit sentinel codes (mirror the virtio-net image)
// =============================================================================

/// No `MmioMap` token in the deposit window.
const EXIT_NO_MMIO_TOKEN: u64 = 10;
/// No `DmaMap` token in the deposit window.
const EXIT_NO_DMA_TOKEN: u64 = 20;
/// Base sentinel: `MmioMap` syscall returned non-zero errno.
const EXIT_MMIO_BASE: u64 = 40;
/// Base sentinel: `DmaMap` syscall returned non-zero errno.
const EXIT_DMA_BASE: u64 = 60;
/// `IpcCreateChannel` returned `u64::MAX` for the primary `nvme0` request
/// channel. Distinct from the errno-based sentinels so triage can tell
/// "channel alloc failed" from "syscall errno N".
const EXIT_IPC_CREATE_FAILED: u64 = 100;
/// Base sentinel: `BlkRegister` returned a non-zero errno for `nvme0`.
/// The exit code = `EXIT_BLK_REGISTER_BASE + errno`. POSIX-aligned errnos the
/// kernel surfaces here: `EINVAL = 22` (disk-slot argument shape),
/// `EEXIST = 17` (slot already taken — another driver got there first),
/// `ENOSPC = 28` (registry capacity), `EACCES = 13` (caller does not
/// own the supplied channel id), `EIO = 5` (defensive internal).
const EXIT_BLK_REGISTER_BASE: u64 = 110;
/// `BlkLookup` returned `ENOENT` (`rdx = 2`). Reachable only if the
/// preceding `BlkRegister` silently dropped the entry — defensive
/// sentinel that should never fire in practice.
const EXIT_BLK_LOOKUP_NOT_FOUND: u64 = 131;
/// `BlkLookup` returned a `channel_id` distinct from the one we
/// registered. Reachable only if the kernel registry's
/// `lookup_disk_slot` regressed; treated as a hard failure because
/// the filesystem service would otherwise dispatch BLK requests to
/// the wrong driver.
const EXIT_BLK_LOOKUP_MISMATCH: u64 = 132;
/// `IpcCreateChannel` returned `u64::MAX` for the `nvme0-reply` reply
/// channel (ADR-0036 D2). Second channel allocation; distinct sentinel
/// from `EXIT_IPC_CREATE_FAILED` so triage can identify which channel
/// failed.
const EXIT_IPC_CREATE_REPLY_FAILED: u64 = 133;
/// Base sentinel: `BlkRegister` returned a non-zero errno for the
/// `nvme0-reply` channel. Exit code = `EXIT_BLK_REGISTER_REPLY_BASE + errno`.
const EXIT_BLK_REGISTER_REPLY_BASE: u64 = 134;
/// `disable_controller` failed (controller did not clear `CSTS.RDY`
/// within the poll budget; see `nexacore_driver_nvme::queue::QueueError`).
const EXIT_NVME_DISABLE_TIMEOUT: u64 = 200;
/// `program_admin_queue_bases` rejected the depths or base
/// addresses (`AdminDepthOutOfRange` / `QueueBaseMisaligned`).
const EXIT_NVME_ADMIN_QUEUE_INVALID: u64 = 210;
/// `program_cc_fields` rejected one of `MPS` / `IOSQES` / `IOCQES`
/// for being outside the 4-bit range per NVMe 1.4 § 3.1.5 — surfaces
/// as `QueueError::AdminDepthOutOfRange`. Reachable only if the
/// Phase-1 constants are corrupted at compile time (the image pins
/// them to spec-mandated values) so this sentinel is defensive
/// against a regression of [`nexacore_driver_nvme::queue::PHASE_1_MPS_LOG2`]
/// / `PHASE_1_IOSQES_LOG2` / `PHASE_1_IOCQES_LOG2`. New in P6.7.10-pre.32.
const EXIT_NVME_CC_FIELDS_INVALID: u64 = 215;
/// `enable_controller` failed (controller did not set `CSTS.RDY`
/// within the poll budget).
const EXIT_NVME_ENABLE_TIMEOUT: u64 = 220;
/// `check_controller_fatal` returned `true` immediately after
/// `enable_controller` succeeded — the controller set `CSTS.RDY`
/// but also raised `CSTS.CFS` (Controller Fatal Status, sticky per
/// NVMe 1.4 § 3.1.6). The bring-up MUST abort because subsequent
/// admin commands would never complete. Reachable when a flaky
/// controller crashes mid-enable but still ticks the RDY bit.
/// New in P6.7.10-pre.32.
const EXIT_NVME_CONTROLLER_FATAL: u64 = 225;
/// `AdminQueuePair::new` rejected the bring-up SQ/CQ depths or
/// the doorbell stride. Reachable only if the Phase-1 admin queue
/// constants are corrupted at compile time; defensive sentinel
/// against a regression of [`NVME_ADMIN_SQ_DEPTH`] /
/// [`NVME_ADMIN_CQ_DEPTH`]. New in P6.7.10-pre.33.
const EXIT_NVME_ADMIN_PAIR_INVALID: u64 = 230;
/// `AdminQueuePair::submit` failed to enqueue the Identify
/// Controller SQE — either the SQ ring is full (impossible at
/// this stage; the ring starts empty) or the SQ data page is
/// undersized. Defensive. New in P6.7.10-pre.33.
const EXIT_NVME_IDENTIFY_SUBMIT_FAILED: u64 = 235;
/// The Identify Controller poll loop exhausted
/// [`NVME_IDENTIFY_POLL_LIMIT`] iterations without observing a
/// matching CQE. Reachable on a controller that NACKs admin
/// commands silently, or a DMA arena mis-programming that
/// prevents the controller from writing the CQ slot. New in
/// P6.7.10-pre.33.
const EXIT_NVME_IDENTIFY_TIMEOUT: u64 = 240;
/// `AdminQueuePair::drain_completion` surfaced a non-timeout
/// error (`CqPageTooSmall` / `DoorbellOffsetOverflow`).
/// Defensive against a regression of the page-size or
/// doorbell-stride constants. New in P6.7.10-pre.33.
const EXIT_NVME_IDENTIFY_DRAIN_FAILED: u64 = 242;
/// Identify Controller completed but the CQE reports a
/// non-success status word (`SCT != 0` or `SC != 0`). The
/// controller actively refused the command — either CDW10/11
/// shape is wrong or the controller has a serious firmware
/// issue. New in P6.7.10-pre.33.
const EXIT_NVME_IDENTIFY_FAILED: u64 = 245;
/// `AdminQueuePair::submit` failed to enqueue the
/// Identify(ActiveNsList) SQE on the second admin slot. Mirrors
/// `EXIT_NVME_IDENTIFY_SUBMIT_FAILED` semantically; distinct
/// sentinel so serial-log triage can tell which command in the
/// bring-up handshake regressed. New in P6.7.10-pre.34.
const EXIT_NVME_NS_LIST_SUBMIT_FAILED: u64 = 250;
/// The Identify(ActiveNsList) poll loop exhausted
/// [`NVME_IDENTIFY_NS_LIST_POLL_LIMIT`] iterations without
/// observing a matching CQE. Same root-cause space as
/// `EXIT_NVME_IDENTIFY_TIMEOUT`: silent NACK or DMA-arena
/// mis-programming, scoped to the second admin command.
/// New in P6.7.10-pre.34.
const EXIT_NVME_NS_LIST_TIMEOUT: u64 = 252;
/// `AdminQueuePair::drain_completion` surfaced a non-timeout
/// error while polling the Identify(ActiveNsList) completion.
/// Defensive against a regression of the page-size or
/// doorbell-stride constants. New in P6.7.10-pre.34.
const EXIT_NVME_NS_LIST_DRAIN_FAILED: u64 = 254;
/// Identify(ActiveNsList) completed but the CQE reports a
/// non-success status word. The controller actively refused the
/// command — either CDW10/11 shape is wrong (CNS = 0x02 must be
/// honoured by any 1.4-compliant controller) or the controller
/// has a serious firmware issue. New in P6.7.10-pre.34.
const EXIT_NVME_NS_LIST_FAILED: u64 = 256;
/// [`ActiveNsListView::new`] returned `IdentifyError::PageTooSmall`.
/// Reachable only if the local slice constructor mis-computes the
/// response-page length; the IOVA region the image hands to the
/// controller is sized exactly [`NVME_IDENTIFY_NS_LIST_RESP_BYTES`]
/// (4 KiB) by construction, so this sentinel is purely defensive
/// against a regression of the constant. New in P6.7.10-pre.34.
const EXIT_NVME_NS_LIST_PARSE_FAILED: u64 = 258;
/// The Active Namespace List parse succeeded but
/// [`ActiveNsListView::first_active_nsid`] returned `None`:
/// the controller reports zero active namespaces, which makes
/// the subsequent `Identify(Namespace)` step impossible. NVMe
/// 1.4 § 5.15.2 permits a controller to expose zero namespaces
/// only as a transient post-format state; reaching this branch
/// during bring-up is a hard failure — the kernel BLK gateway
/// has no namespace to publish. New in P6.7.10-pre.34.
const EXIT_NVME_NS_LIST_EMPTY: u64 = 260;
/// `AdminQueuePair::submit` failed to enqueue the
/// `Identify(Namespace)` SQE on the third admin slot. Mirrors
/// `EXIT_NVME_IDENTIFY_SUBMIT_FAILED` semantically; distinct
/// sentinel so serial-log triage can localise which command in
/// the bring-up handshake regressed. New in P6.7.10-pre.35.
const EXIT_NVME_NS_SUBMIT_FAILED: u64 = 270;
/// The `Identify(Namespace)` poll loop exhausted
/// [`NVME_IDENTIFY_NS_POLL_LIMIT`] iterations without observing
/// a matching CQE. Same root-cause space as
/// `EXIT_NVME_IDENTIFY_TIMEOUT`. New in P6.7.10-pre.35.
const EXIT_NVME_NS_TIMEOUT: u64 = 272;
/// `AdminQueuePair::drain_completion` surfaced a non-timeout
/// error while polling the `Identify(Namespace)` completion.
/// New in P6.7.10-pre.35.
const EXIT_NVME_NS_DRAIN_FAILED: u64 = 274;
/// `Identify(Namespace)` completed but the CQE reports a
/// non-success status word. The controller actively refused the
/// command. New in P6.7.10-pre.35.
const EXIT_NVME_NS_FAILED: u64 = 276;
/// [`IdentifyNamespace::new`] returned
/// `IdentifyError::PageTooSmall`. Purely defensive against a
/// regression of the response-page length constant. New in
/// P6.7.10-pre.35.
const EXIT_NVME_NS_PARSE_FAILED: u64 = 278;
/// [`IdentifyNamespace::validated_byte_size`] returned
/// `IdentifyError::UnsupportedLbads` — the controller's active
/// LBA format does not use 4 KiB sectors (`LBADS != 12`). Per
/// NCIP-014 § S6 step 10 the Phase-1 driver rejects any
/// namespace whose sector size differs from the kernel page
/// size. New in P6.7.10-pre.35.
const EXIT_NVME_NS_UNSUPPORTED_LBADS: u64 = 280;
/// `AdminQueuePair::submit` failed to enqueue the `Create I/O
/// Completion Queue` SQE. New in P6.7.10-pre.36.
const EXIT_NVME_CREATE_IO_CQ_SUBMIT_FAILED: u64 = 290;
/// The `Create I/O Completion Queue` poll loop exhausted
/// [`NVME_CREATE_IO_POLL_LIMIT`]. New in P6.7.10-pre.36.
const EXIT_NVME_CREATE_IO_CQ_TIMEOUT: u64 = 292;
/// `drain_completion` surfaced a non-timeout error while
/// polling the `Create I/O CQ` completion. New in P6.7.10-pre.36.
const EXIT_NVME_CREATE_IO_CQ_DRAIN_FAILED: u64 = 294;
/// `Create I/O Completion Queue` completed but the CQE reports a
/// non-success status word. New in P6.7.10-pre.36.
const EXIT_NVME_CREATE_IO_CQ_FAILED: u64 = 296;
/// `AdminQueuePair::submit` failed to enqueue the `Create I/O
/// Submission Queue` SQE. New in P6.7.10-pre.36.
const EXIT_NVME_CREATE_IO_SQ_SUBMIT_FAILED: u64 = 300;
/// The `Create I/O Submission Queue` poll loop exhausted
/// [`NVME_CREATE_IO_POLL_LIMIT`]. New in P6.7.10-pre.36.
const EXIT_NVME_CREATE_IO_SQ_TIMEOUT: u64 = 302;
/// `drain_completion` surfaced a non-timeout error while
/// polling the `Create I/O SQ` completion. New in P6.7.10-pre.36.
const EXIT_NVME_CREATE_IO_SQ_DRAIN_FAILED: u64 = 304;
/// `Create I/O Submission Queue` completed but the CQE reports a
/// non-success status word. New in P6.7.10-pre.36.
const EXIT_NVME_CREATE_IO_SQ_FAILED: u64 = 306;
/// `AdminQueuePair::new_for_qid` rejected the IO queue pair
/// parameters (depths or doorbell stride out of range). Defensive
/// against a regression of the Phase-1 constants.
const EXIT_NVME_IO_PAIR_INVALID: u64 = 310;
/// `CAP.DSTRD` read from the controller is not the Phase-1
/// expected value (0). New in P6.7.10-pre.41.
const EXIT_NVME_CAP_DSTRD_MISMATCH: u64 = 360;
/// `CAP.MQES` is too small — the controller cannot support the
/// Phase-1 admin queue depth (64). New in P6.7.10-pre.41.
const EXIT_NVME_CAP_MQES_TOO_SMALL: u64 = 362;
/// `CAP.MPSMIN` > 0 — the controller does not support 4 KiB host
/// pages required by the NexaCore OS kernel. New in P6.7.10-pre.41.
const EXIT_NVME_CAP_MPSMIN_UNSUPPORTED: u64 = 364;
/// `VS` register reports major version 0 — the controller does
/// not identify as NVMe 1.0+. New in P6.7.10-pre.41.
const EXIT_NVME_VS_UNSUPPORTED: u64 = 366;
/// `IdentifyController::new` rejected the response page (too small).
/// Defensive. New in P6.7.10-pre.42.
const EXIT_NVME_IDENTIFY_CTRL_PARSE_FAILED: u64 = 368;
/// `IdentifyController::nn()` returned 0 — the controller reports
/// zero namespaces. New in P6.7.10-pre.42.
const EXIT_NVME_IDENTIFY_CTRL_NN_ZERO: u64 = 370;
/// Namespace validation failed: `LBADS != 12` and the namespace
/// is rejected by the multi-namespace validator. New in P6.7.10-pre.46.
const EXIT_NVME_NS_VALIDATION_REJECTED: u64 = 380;
/// MSI-X configuration is invalid — the controller does not
/// support the requested vector index. New in P6.7.10-pre.46.
const EXIT_NVME_MSIX_VECTOR_UNSUPPORTED: u64 = 382;

// =============================================================================
// Raw syscall wrapper
// =============================================================================

/// Issue a `syscall` with the given number and up to 5 arguments. Returns
/// the `(rax, rdx)` pair — the two-register convention used by the
/// driver-framework syscalls per `NCIP-Driver-Framework-013` § S2.
#[inline(always)]
unsafe fn syscall5(number: u64, a0: u64, a1: u64, a2: u64, a3: u64, a4: u64) -> (u64, u64) {
    let mut rax: u64 = number;
    let rdx_out: u64;
    // SAFETY: `syscall` is the canonical Ring 3 → Ring 0 transition on
    // `x86_64`. The kernel entry SHUFFLES the argument registers
    // (rdi/rsi/rdx/r10/r8/r9) and does NOT restore them, so every one of
    // them must be declared clobbered (`inout(...) => _`) — a reduced
    // clobber set lets the compiler keep live values (e.g. the NEXT
    // syscall's arguments) in registers the kernel destroys
    // (hardware-observed heisenbug, ADR-0035/ADR-0036 D8).
    unsafe {
        core::arch::asm!(
            "syscall",
            inout("rax") rax,
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

/// Issue `TaskExit(code)` — diverges on the bare-metal kernel.
#[inline(always)]
unsafe fn sys_exit(code: u64) -> ! {
    // SAFETY: TaskExit terminates the process; Phase 1 ignores the code value.
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
// BSS receive/encode buffers (TASK-14, ADR-0036 D3 inline transport)
// =============================================================================

/// Receive buffer for incoming `BlkRequest` IPC messages.
/// 4096 bytes is the kernel's maximum IPC payload (MAX_PAYLOAD in
/// `crates/nexacore-kernel/src/bare_metal/syscall_entry.rs`). Placed in
/// BSS (zero-initialised by the ELF loader) to avoid stack pressure.
///
/// # Safety
/// Accessed ONLY inside `_start`'s BLK service loop on the single
/// OS thread. No other code path holds a reference to this buffer.
static mut REQ_BUF: [u8; 4096] = [0u8; 4096];

/// Receive buffer for a single inline data chunk (2048 bytes = half a
/// 4 KiB sector). Used when assembling Write payloads from two
/// consecutive IPC messages (ADR-0036 D3: count×2 chunks of 2048 B).
///
/// # Safety
/// Same single-thread guarantee as `REQ_BUF`.
static mut CHUNK_BUF: [u8; 2048] = [0u8; 2048];

/// Encode buffer for `BlkResponse` wire bytes. `encode_into_slice`
/// writes here; the slice is immediately forwarded to `IpcSend`.
/// `BlkResponse` encodes to at most ~4 bytes (discriminant + optional
/// u16 payload), so 64 bytes is ample. Placed in BSS.
///
/// # Safety
/// Same single-thread guarantee as `REQ_BUF`.
static mut RESP_BUF: [u8; 64] = [0u8; 64];

/// Receive buffer for IRQ notification messages (WS1-07, ADR-0036 D5).
/// The kernel's IRQ dispatch enqueues an 8-byte payload (the LAPIC
/// vector, little-endian u64); 16 bytes leaves headroom.
///
/// # Safety
/// Same single-thread guarantee as `REQ_BUF`.
static mut IRQ_NOTIF_BUF: [u8; 16] = [0u8; 16];

// =============================================================================
// Service-loop helpers (TASK-14, ADR-0036 D3/D5)
// =============================================================================

/// Write `msg` to the kernel console (COM1) — best-effort serial audit.
///
/// Uses `WriteConsole (60)` through the full-clobber `syscall5` stub so
/// live values the compiler placed in argument registers before the call
/// are not silently clobbered (ADR-0035 / ADR-0036 D8).
fn write(msg: &str) {
    let b = msg.as_bytes();
    // SAFETY: `b` is a valid slice for the duration of the syscall;
    // `syscall5` declares the full clobber set so the compiler does not
    // assume any register survives the call boundary.
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

/// Write `v` as an 8-digit lowercase hex literal (`0x........`) to the
/// kernel console. Used by the bring-up diagnostics (TASK-14).
fn write_hex32(v: u32) {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut buf = [0u8; 10];
    buf[0] = b'0';
    buf[1] = b'x';
    let mut i = 0;
    while i < 8 {
        let nibble = ((v >> ((7 - i) * 4)) & 0xF) as usize;
        buf[2 + i] = HEX[nibble];
        i += 1;
    }
    if let Ok(s) = core::str::from_utf8(&buf) {
        write(s);
    }
}

/// Yield the CPU to the next runnable task.
///
/// Called from the BLK service loop when the IO CQ has no ready
/// completions (`Ok(None)`) and when the IPC request queue is empty.
/// This is what makes completion-wait cooperative rather than a
/// busy-spin (ADR-0036 D5, Option A — "CPU yielded, not busy-spin").
/// Uses the full-clobber `syscall5` stub per ADR-0035 / ADR-0036 D8.
fn task_yield() {
    // SAFETY: TaskYield takes no meaningful arguments. All six argument
    // positions are zero; the full-clobber stub declares every argument
    // register clobbered so the compiler cannot keep a live value in
    // rdi/rsi/rdx/r10/r8/r9 across this call.
    let _ = unsafe { syscall5(SYS_TASK_YIELD, 0, 0, 0, 0, 0) };
}

/// Send `data` on `channel_id` with IPC message `kind`.
///
/// Returns `true` on success, `false` on any kernel-side error.
///
/// ABI (verified against `crates/nexacore-runtime-image/src/main.rs:254–268`
/// and `crates/nexacore-kernel/src/bare_metal/syscall_entry.rs:752–813`):
/// `rdi=channel_id, rsi=kind, rdx=payload_ptr, r10=payload_len` →
/// `rax=0` success, `rax=u64::MAX` error.
fn ipc_send(channel_id: u64, kind: u64, data: &[u8]) -> bool {
    // SAFETY: `data` is a valid slice for the duration of the syscall.
    // The kernel's `copy_from_user_vec` validates the user-space range
    // internally. Full-clobber stub ensures no live registers are
    // corrupted across the system-call boundary (ADR-0035/ADR-0036 D8).
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
///
/// ABI (verified against `crates/nexacore-runtime-image/src/main.rs:272–295`
/// and `crates/nexacore-kernel/src/bare_metal/syscall_entry.rs:888–928`):
/// `rdi=channel_id, rsi=dst_ptr, rdx=dst_cap` →
/// `rax=bytes_copied` on success, `rax=u64::MAX` when empty or error.
fn ipc_try_receive(channel_id: u64, buf: &mut [u8]) -> Option<usize> {
    // SAFETY: `buf` is a valid writable slice; the kernel writes at most
    // `buf.len()` bytes and validates the pointer range internally via
    // `user_range_ok` + `copy_to_user`. Full-clobber stub per ADR-0035.
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
        // SAFETY: the kernel copies at most `buf.len()` bytes, so
        // `rax as usize` is in `0..=buf.len()`.
        #[allow(
            clippy::cast_possible_truncation,
            reason = "kernel copies at most buf.len() ≤ 4096 bytes"
        )]
        Some(rax as usize)
    }
}

/// Map a single 4 KiB DMA page at `iova` and return the **physical** base
/// address the kernel allocated for it.
///
/// Calls `DmaMap (71)` with a 1-page (`0x1000`) length so the kernel's
/// strictly-contiguous-frame requirement is trivially satisfied — one frame
/// is always contiguous. The deposited `DmaWindow` token (covering
/// `[DMA_IOVA_BASE, DMA_IOVA_BASE + 0x8000)`) permits all 8 sub-windows
/// via the one-token-many-submaps pattern.
///
/// On syscall failure (errno != 0) this function calls `sys_exit` with the
/// `EXIT_DMA_BASE + errno` sentinel and never returns.
///
/// ## Dual-address model
///
/// `DmaMap` returns the allocated **physical** base in `rax`; the driver
/// must program the NVMe controller with this value. The `iova` argument
/// is the CPU virtual address — the kernel maps `iova → phys` in the
/// driver's page table for CPU access (ADR-0036 appendix 2).
///
/// # Safety
///
/// `dma_token` must be a static-lifetime slice from the deposit window (a
/// `[u8]` slice the kernel wrote before spawning `_start`). The syscall
/// reads `dma_token` only for the duration of this call; the slice is not
/// retained.
unsafe fn dma_map_page(iova: u64, dma_token: &[u8]) -> u64 {
    // SAFETY: `syscall5` issues a `syscall` instruction with the full
    // clobber set (ADR-0035/ADR-0036 D8). `dma_token` is valid for the
    // syscall's duration; the kernel copies the token bytes internally via
    // `copy_from_user`. `iova` is within the deposited `DmaWindow` range
    // `[DMA_IOVA_BASE, DMA_IOVA_BASE + 0x8000)`.
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
    // `rax` holds the physical base the kernel allocated for this page.
    phys
}

/// Encode a `BlkResponse` into the static `RESP_BUF` and send it on
/// `reply_channel_id` as an `IPC_KIND_REPLY` message.
///
/// Silently drops the reply on encode failure (response buffer too
/// small — structurally impossible with the current buffer size of 64
/// bytes, but defensively handled).
///
/// # Safety
/// Caller must ensure exclusive access to `RESP_BUF` (single-thread
/// guarantee in the BLK service loop).
unsafe fn send_blk_response(reply_channel_id: u64, resp: BlkResponse) {
    // SAFETY: RESP_BUF is a static BSS buffer accessed only from the
    // single-threaded BLK service loop; no other code path holds a
    // reference to it at this point.
    let resp_buf = unsafe { &mut *core::ptr::addr_of_mut!(RESP_BUF) };
    let Ok(n) = encode_into_slice(&resp, resp_buf) else {
        return;
    };
    ipc_send(reply_channel_id, IPC_KIND_REPLY, &resp_buf[..n]);
}

/// Live IRQ-path state for the completion wait (WS1-07, ADR-0036 D5 /
/// Option B).
struct IrqPath {
    /// Notification channel bound via `IrqAttach (72)`. `0` = IRQ path
    /// inactive (token absent or attach failed) → pure cooperative
    /// polling, exactly the Option A behaviour. Never `0` for a live
    /// channel: kernel channel ids start at 1.
    channel_id: u64,
    /// First `irq=hit` already logged. The proof marker is logged once
    /// (per-op logging would double the serial volume of a 128-read
    /// boot for no additional proof).
    hit_logged: bool,
    /// First `irq=poll-first` already logged (same once-only rule).
    fallback_logged: bool,
    /// Running count of completion notifications actually popped from
    /// the channel across ALL waits — including ones that lose the race
    /// to the (instant, emulated) CQ write and are collected in the
    /// post-completion grace window. This is the DECISIVE MSI-delivery
    /// proof: emulated NVMe CQEs land before the interrupt latency, so
    /// `irq=poll-first` alone cannot distinguish "MSI live but slow" from
    /// "MSI dead". A non-zero total means the device→LAPIC→ISR→IPC chain
    /// fired for real (WS1-06.10).
    notif_total: u64,
    /// `irq=delivered total=N` already logged (logged once, the first
    /// time `notif_total` crosses zero).
    delivered_logged: bool,
}

/// Completion wait: hybrid IRQ + cooperative CQ poll (WS1-07,
/// ADR-0036 D5 / Option B with the bounded-poll liveness of Option A).
///
/// Every iteration first pops the IRQ notification channel (cheap IPC
/// try-receive; the kernel enqueues one 8-byte message per MSI-X fire),
/// then polls the CQ directly, then yields. Liveness therefore NEVER
/// depends on interrupt delivery — with a dead MSI path this loop is
/// byte-for-byte the Option A cooperative drain — while a delivered
/// interrupt is observed and audited:
///
/// - `irq=hit` (once): a notification arrived before the CQE was
///   consumed — MSI-X delivery is live end-to-end (device → LAPIC →
///   kernel ISR → IPC channel → this driver).
/// - `irq=poll-first` (once): the CQ poll won the race and no
///   notification was seen for this command. With working MSI this can
///   happen on raw timing (CQE memory write lands before the vector is
///   serviced); the authoritative MSI proof is the kernel's
///   `[irq] first driver vector fire` line, not this marker.
///
/// After the CQE is consumed the channel is drained of residual
/// notifications (bounded by the channel depth) so a stale signal never
/// satisfies a FUTURE wait before its own interrupt fired.
fn wait_completion(
    irq: &mut IrqPath,
    io_pair: &mut AdminQueuePair,
    mmio_write: &mut LiveMmioBackend,
    io_cq_slice: &[u8],
    expected_cid: u16,
) -> Result<nexacore_driver_nvme::admin::AdminCqeFields, ()> {
    // 5_000_000 iterations is the completion-wait budget (ADR-0036 D5).
    // Each iteration that leaves the CQE pending calls TaskYield before
    // looping, so the CPU is not wasted — budget × yield_overhead bounds
    // worst-case latency against a wedged controller.
    const WAIT_BUDGET: u32 = 5_000_000;
    let mut iters: u32 = 0;
    let mut notified = false;
    let result = loop {
        if iters >= WAIT_BUDGET {
            break Err(());
        }
        iters = iters.saturating_add(1);

        // (1) IRQ notification check — cheap pop, only while armed and
        //     not yet seen for this command.
        if irq.channel_id != 0 && !notified {
            // SAFETY: IRQ_NOTIF_BUF is a static BSS buffer accessed only
            // by this single-threaded wait path.
            if ipc_try_receive(irq.channel_id, unsafe {
                &mut *core::ptr::addr_of_mut!(IRQ_NOTIF_BUF)
            })
            .is_some()
            {
                notified = true;
                if !irq.hit_logged {
                    irq.hit_logged = true;
                    write("[driver-nvme] irq=hit (MSI-X completion delivery live)\n");
                }
            }
        }

        // (2) Direct CQ poll — the liveness backbone (Option A).
        match io_pair.drain_completion(mmio_write, io_cq_slice) {
            Ok(Some(f)) if f.cid == expected_cid => {
                if irq.channel_id != 0 && !notified && !irq.fallback_logged {
                    irq.fallback_logged = true;
                    write("[driver-nvme] irq=poll-first (CQE before notification)\n");
                }
                break Ok(f);
            }
            // A completion for a different CID — skip and keep polling.
            // In the v0.3 single-in-flight model this is impossible, but
            // defensively handled for future multi-CID support.
            Ok(Some(_)) => continue,
            // CQ slot not ready yet — yield the CPU (cooperative).
            Ok(None) => {
                task_yield();
                continue;
            }
            Err(_) => break Err(()),
        }
    };

    // Count the in-loop hit (if any) toward the delivery total.
    if notified {
        irq.notif_total = irq.notif_total.saturating_add(1);
    }

    // Post-completion grace window: the emulated CQE write beats the
    // MSI latency, so a delivered interrupt usually arrives just AFTER
    // the poll consumed the CQE. Give it a brief, bounded window
    // (yield-paced) to land so it is counted as proof rather than
    // silently dropped — this is what makes `notif_total` meaningful
    // (WS1-06.10). The window is short: it adds at most
    // `GRACE_YIELDS` scheduler turns per IO and only when no
    // notification was seen in-loop.
    if irq.channel_id != 0 {
        const GRACE_YIELDS: u32 = 256;
        let mut grace: u32 = 0;
        if !notified {
            while grace < GRACE_YIELDS {
                // SAFETY: same IRQ_NOTIF_BUF single-thread guarantee.
                if ipc_try_receive(irq.channel_id, unsafe {
                    &mut *core::ptr::addr_of_mut!(IRQ_NOTIF_BUF)
                })
                .is_some()
                {
                    irq.notif_total = irq.notif_total.saturating_add(1);
                    break;
                }
                grace = grace.saturating_add(1);
                task_yield();
            }
        }
        // Drain any further coalesced notifications (bounded by depth).
        let mut residual: u64 = 0;
        while residual < IRQ_CHANNEL_QUEUE_DEPTH {
            // SAFETY: same IRQ_NOTIF_BUF single-thread guarantee as above.
            if ipc_try_receive(irq.channel_id, unsafe {
                &mut *core::ptr::addr_of_mut!(IRQ_NOTIF_BUF)
            })
            .is_none()
            {
                break;
            }
            irq.notif_total = irq.notif_total.saturating_add(1);
            residual = residual.saturating_add(1);
        }

        // First time we observe ANY real delivery, log the proof.
        if irq.notif_total > 0 && !irq.delivered_logged {
            irq.delivered_logged = true;
            write("[driver-nvme] irq=delivered (MSI-X reached driver; CQ poll won the race)\n");
        }
    }

    result
}

// =============================================================================
// Driver entry — _start
// =============================================================================

/// ELF entry point. The kernel's `spawn_from_elf` jumps here with
/// `rsp = user_stack_top` and the capability deposit mapped read-only at
/// [`nexacore_driver_shared::DRIVER_CAP_DEPOSIT_VA`].
#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    // Step 1 — Retrieve the MMIO + DMA capability tokens from the
    // deposit. The IrqAttach token (WS1-07, Option B) is looked up
    // later at step 4.21 — it is best-effort (absence falls back to the
    // Option A cooperative-yield completion wait), unlike these two,
    // without which the driver cannot reach the hardware at all.
    let Some(mmio_token) = find_token(ACTION_TAG_MMIO_MAP, |_| true) else {
        // SAFETY: sys_exit diverges.
        unsafe { sys_exit(EXIT_NO_MMIO_TOKEN) };
    };
    let Some(dma_token) = find_token(ACTION_TAG_DMA_MAP, |_| true) else {
        unsafe { sys_exit(EXIT_NO_DMA_TOKEN) };
    };

    // The NVMe BAR0 is firmware-assigned (a 64-bit PCIe BAR can land at a
    // HIGH physical address — e.g. 0x3840_0000_4000 on QEMU pcie.0), so we
    // map the LIVE base the kernel carried in the deposit page's
    // device-info section rather than the hardcoded fallback (TASK-14,
    // ADR-0036). `NVME_BAR0_PHYS_BASE` survives only as a fallback for
    // configurations without a device-info section.
    // SAFETY: the deposit window is mapped read-only at the well-known VA
    // for its full length (kernel contract); `device_info::read` only
    // reads it.
    let bar0_phys = match unsafe { nexacore_driver_shared::device_info::read() } {
        Some(info) if info.bar_phys != 0 => info.bar_phys,
        _ => NVME_BAR0_PHYS_BASE,
    };

    // Step 2 — `MmioMap (70)`: install the NVMe CSR window (16 KiB).
    let (mmio_va, mmio_errno) = unsafe {
        syscall5(
            SYS_MMIO_MAP,
            bar0_phys,
            NVME_BAR0_LEN,
            MMIO_FLAGS_DEFAULT,
            mmio_token.as_ptr() as u64,
            mmio_token.len() as u64,
        )
    };
    if mmio_errno != 0 {
        unsafe { sys_exit(EXIT_MMIO_BASE + mmio_errno) };
    }

    // Step 3 — `DmaMap (71)`: map each DMA region as a **separate 1-page**
    // call, capturing the physical base returned by each. Splitting into
    // individual pages sidesteps the kernel's strictly-contiguous-frame
    // requirement (one frame is always contiguous) that made an 8-page
    // single-call fail late in boot with ENOSPC (ADR-0036 appendix 2,
    // Boot 3 root cause). The deposited `DmaWindow` token covers the full
    // `[DMA_IOVA_BASE, DMA_IOVA_BASE + 0x8000)` range and authorises all 8
    // sub-window mappings (one-token-many-submaps, same pattern as
    // nexacore-driver-net-virtio-image TX/RX).
    //
    // The returned `*_phys` values are programmed into the NVMe controller
    // (device-address sites). The IOVA constants below are the CPU virtual
    // addresses used to access the ring/buffer memory from this process.
    //
    // SAFETY: `dma_token` is a static-lifetime slice from the deposit
    // window; `dma_map_page` reads it only for the duration of each syscall.

    // Admin Submission Queue — 64 × 64 B = 4096 B; 4 KiB-aligned by construction.
    let asq_phys: u64 = unsafe { dma_map_page(NVME_ASQ_IOVA, dma_token) };
    // Admin Completion Queue — 64 × 16 B = 1024 B; same 4 KiB page.
    let acq_phys: u64 = unsafe { dma_map_page(NVME_ACQ_IOVA, dma_token) };
    // Identify Controller response — 4 KiB per NVMe 1.4 § 5.15.
    let idctrl_phys: u64 = unsafe { dma_map_page(NVME_IDENTIFY_CTRL_RESP_IOVA, dma_token) };
    // Identify Active-Namespace-List response — 4 KiB per NVMe 1.4 § 5.15.2.
    let idnslist_phys: u64 = unsafe { dma_map_page(NVME_IDENTIFY_NS_LIST_RESP_IOVA, dma_token) };
    // Identify Namespace response — 4 KiB per NVMe 1.4 § 5.15.2 Figure 245.
    let idns_phys: u64 = unsafe { dma_map_page(NVME_IDENTIFY_NS_RESP_IOVA, dma_token) };
    // IO Completion Queue data page.
    let iocq_phys: u64 = unsafe { dma_map_page(NVME_IO_CQ_IOVA, dma_token) };
    // IO Submission Queue data page.
    let iosq_phys: u64 = unsafe { dma_map_page(NVME_IO_SQ_IOVA, dma_token) };
    // Sector bounce buffer — controller DMA target for Read/Write.
    let bounce_phys: u64 = unsafe { dma_map_page(NVME_IO_READ_DATA_IOVA, dma_token) };

    // Step 4.5 — `IpcCreateChannel (20)`: allocate the kernel-side
    // BLK channel the future filesystem service will attach to. The
    // legacy MB12 fast-path (`send_token_ptr = recv_token_ptr = 0`)
    // returns the channel id in `rax` without requiring a signed
    // capability token; the kernel records the caller as the
    // channel's `owner`, which is exactly the identity
    // `BlkRegister` checks against.
    let (channel_id, _ipc_extra) = unsafe {
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
        unsafe { sys_exit(EXIT_IPC_CREATE_FAILED) };
    }

    // Step 4.6 — `BlkRegister (76)`: record the
    // `nexacore.svc.blk.nvme0` → `channel_id` mapping in the kernel BLK
    // registry per NCIP-Driver-NVMe-014 § S4 + § S6 step 12. The
    // kernel verifies the caller owns `channel_id` (we just created
    // it above, so the ownership check passes by construction); on
    // success the consumer side can resolve the channel via
    // `BlkLookup (78)`.
    let (_blk_register_rax, blk_register_errno) = unsafe {
        syscall5(
            SYS_BLK_REGISTER,
            NVME_DISK_SLOT.as_ptr() as u64,
            NVME_DISK_SLOT.len() as u64,
            channel_id,
            0,
            0,
        )
    };
    if blk_register_errno != 0 {
        unsafe { sys_exit(EXIT_BLK_REGISTER_BASE + blk_register_errno) };
    }

    // Step 4.7 — `BlkLookup (78)`: defence-in-depth round-trip. If
    // the lookup returns a different channel id (or `ENOENT`) then
    // the kernel registry regressed between insert and read and we
    // abort before any FSM advance — the filesystem service would
    // otherwise route requests to the wrong driver. Reachable only
    // on a kernel bug; sentinel exit codes make the failure easy to
    // grep on the serial log.
    let (looked_up_id, blk_lookup_errno) = unsafe {
        syscall5(
            SYS_BLK_LOOKUP,
            NVME_DISK_SLOT.as_ptr() as u64,
            NVME_DISK_SLOT.len() as u64,
            0,
            0,
            0,
        )
    };
    if blk_lookup_errno != 0 {
        unsafe { sys_exit(EXIT_BLK_LOOKUP_NOT_FOUND) };
    }
    if looked_up_id != channel_id {
        unsafe { sys_exit(EXIT_BLK_LOOKUP_MISMATCH) };
    }

    // Step 4.7b — `IpcCreateChannel (20)`: allocate the `nvme0-reply`
    // channel (ADR-0036 D2). Clients receive `BlkResponse` + inline data
    // chunks from this channel. Separate request/reply queues eliminate
    // kind-contention by construction (TASK-13 lesson: IPC receive is a
    // blind pop — request and reply cannot safely share one queue).
    let (reply_channel_id, _reply_ipc_extra) = unsafe {
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
        unsafe { sys_exit(EXIT_IPC_CREATE_REPLY_FAILED) };
    }

    // Step 4.7c — `BlkRegister (76)`: record `nvme0-reply` → reply_channel_id.
    let (_reply_register_rax, reply_register_errno) = unsafe {
        syscall5(
            SYS_BLK_REGISTER,
            NVME_DISK_SLOT_REPLY.as_ptr() as u64,
            NVME_DISK_SLOT_REPLY.len() as u64,
            reply_channel_id,
            0,
            0,
        )
    };
    if reply_register_errno != 0 {
        unsafe { sys_exit(EXIT_BLK_REGISTER_REPLY_BASE + reply_register_errno) };
    }

    // Step 4.8 — P6.7.10-pre.17: construct the live MMIO backend
    // pair against the BAR0 user-VA the kernel returned at step 2.
    // Two zero-sized clones satisfy the two-mutable-reference
    // signature of `disable_controller`/`enable_controller`
    // without aliasing — `LiveMmioBackend` holds no state beyond
    // the `mmio_va_base` field (copied by value).
    let mut mmio_write = LiveMmioBackend {
        mmio_va_base: mmio_va,
    };
    let mut mmio_read = LiveMmioBackend {
        mmio_va_base: mmio_va,
    };

    // Step 4.8.b — P6.7.10-pre.41: read the CAP register (64-bit,
    // NVMe 1.4 § 3.1.1) and validate that the controller's
    // capabilities are compatible with Phase-1 hard-coded
    // parameters. Two 32-bit reads compose the 64-bit value.
    let cap_lo = mmio_read.read_register(CAP_OFFSET) as u64;
    let cap_hi = mmio_read.read_register(CAP_OFFSET + 4) as u64;
    let cap = cap_lo | (cap_hi << 32);

    // Validate DSTRD: Phase-1 hard-codes DSTRD = 0 (4-byte stride).
    if cap_dstrd(cap) != NVME_ADMIN_DSTRD_DEFAULT {
        unsafe { sys_exit(EXIT_NVME_CAP_DSTRD_MISMATCH) };
    }

    // Validate MQES: the controller must support at least 64 entries
    // (the Phase-1 admin queue depth). MQES is zero-based, so
    // MQES >= 63 means the controller supports >= 64 entries.
    if cap_mqes(cap) < (NVME_ADMIN_SQ_DEPTH - 1) as u16 {
        unsafe { sys_exit(EXIT_NVME_CAP_MQES_TOO_SMALL) };
    }

    // Validate MPSMIN: Phase-1 requires 4 KiB host pages (MPS = 0,
    // i.e. MPSMIN must be <= 0). If the controller's minimum page
    // size is larger than 4 KiB, the bring-up cannot proceed.
    if cap_mpsmin(cap) > 0 {
        unsafe { sys_exit(EXIT_NVME_CAP_MPSMIN_UNSUPPORTED) };
    }

    // Step 4.8.c — Read the VS register (32-bit, NVMe 1.4 § 3.1.2)
    // and verify the controller reports NVMe 1.0+.
    let vs = mmio_read.read_register(VS_OFFSET);
    if vs_major(vs) < 1 {
        unsafe { sys_exit(EXIT_NVME_VS_UNSUPPORTED) };
    }

    // Step 4.9 — `disable_controller`: read CC, clear EN bit, write
    // CC back, poll `CSTS.RDY = 0`. Per NCIP-Driver-NVMe-014 § S6
    // step 4 the driver MUST disable the controller before
    // programming AQA / ASQ / ACQ.
    if disable_controller(&mut mmio_write, &mut mmio_read, NVME_CSTS_POLL_LIMIT).is_err() {
        unsafe { sys_exit(EXIT_NVME_DISABLE_TIMEOUT) };
    }

    // Step 4.10 — `program_admin_queue_bases`: write AQA + ASQ + ACQ per
    // NVMe 1.4 § 3.1.7-9. The controller is programmed with the
    // **physical** addresses (`asq_phys`, `acq_phys`) returned by
    // `dma_map_page` at step 3 — the IOVA values are CPU virtual addresses
    // and the controller cannot reach them under TE-off passthrough
    // (ADR-0036 appendix 2). 4 KiB-alignment is guaranteed by construction
    // (each `dma_map_page` call maps exactly one 4 KiB page).
    if program_admin_queue_bases(
        &mut mmio_write,
        asq_phys,
        acq_phys,
        NVME_ADMIN_SQ_DEPTH,
        NVME_ADMIN_CQ_DEPTH,
    )
    .is_err()
    {
        unsafe { sys_exit(EXIT_NVME_ADMIN_QUEUE_INVALID) };
    }

    // Step 4.11 — P6.7.10-pre.32: `program_cc_fields` writes the
    // canonical CC initialisation register with `EN = 0`, packing
    // `MPS`/`IOSQES`/`IOCQES` per NVMe 1.4 § 3.1.5. Goes between
    // `program_admin_queue_bases` and `enable_controller` so the
    // controller observes the queue-entry-size and command-set
    // selections BEFORE the EN transition latches them. The
    // Phase-1 constants are spec-mandated (`MPS = 0` = 4 KiB host
    // pages, `IOSQES = 6` = 64-byte SQE, `IOCQES = 4` = 16-byte CQE)
    // and the helper rejects out-of-range values; the
    // `EXIT_NVME_CC_FIELDS_INVALID` sentinel is therefore defensive
    // against a regression of the pinned constants.
    if program_cc_fields(
        &mut mmio_write,
        PHASE_1_MPS_LOG2,
        PHASE_1_IOSQES_LOG2,
        PHASE_1_IOCQES_LOG2,
    )
    .is_err()
    {
        unsafe { sys_exit(EXIT_NVME_CC_FIELDS_INVALID) };
    }

    // Step 4.12 — `enable_controller`: set CC.EN, poll
    // `CSTS.RDY = 1`. NCIP-Driver-NVMe-014 § S6 step 6.
    if enable_controller(&mut mmio_write, &mut mmio_read, NVME_CSTS_POLL_LIMIT).is_err() {
        unsafe { sys_exit(EXIT_NVME_ENABLE_TIMEOUT) };
    }

    // Step 4.13 — P6.7.10-pre.32: `check_controller_fatal` tripwire.
    // Reads `CSTS` once and aborts the bring-up if `CSTS.CFS = 1`
    // per NVMe 1.4 § 3.1.6. Catches the corner case where the
    // controller raised both `CSTS.RDY` and `CSTS.CFS` in the same
    // register window, which `enable_controller`'s poll loop would
    // accept as success because it only checks the RDY bit. Sticky
    // CFS means any subsequent admin command would block forever;
    // bailing here surfaces the failure cleanly via the sentinel.
    if check_controller_fatal(&mut mmio_read) {
        unsafe { sys_exit(EXIT_NVME_CONTROLLER_FATAL) };
    }

    // Step 4.14 — P6.7.10-pre.33: construct the admin queue pair.
    // `AdminQueuePair::new` is alloc-free — it owns only an
    // `SqRing` + `CqRing` + the doorbell stride; the backing
    // SQ/CQ data pages live in the DMA arena and are accessed
    // via &mut [u8] slices below. Phase-1 dstrd is pinned to 0
    // (4-byte stride) per `NVME_ADMIN_DSTRD_DEFAULT`; a future
    // slice will read `CAP.DSTRD` from BAR0 and propagate it.
    let mut admin_pair = match AdminQueuePair::new(
        NVME_ADMIN_SQ_DEPTH,
        NVME_ADMIN_CQ_DEPTH,
        NVME_ADMIN_DSTRD_DEFAULT,
    ) {
        Ok(p) => p,
        Err(_) => unsafe { sys_exit(EXIT_NVME_ADMIN_PAIR_INVALID) },
    };

    // Step 4.14.b — Acquire &mut [u8] views into the DMA pages backing the
    // ASQ + ACQ using their **IOVA** (CPU virtual address). The kernel maps
    // `iova → phys` in the driver's page table; `asq_phys` / `acq_phys`
    // (the physical bases returned by `dma_map_page`) were written into the
    // ASQ/ACQ controller registers at step 4.10 so the controller and CPU
    // share the same underlying frames via different address spaces.
    //
    // The IOVA constants serve as CPU pointers here — do NOT use the phys
    // values as pointers (they name physical frames, not VA mappings).
    // `NVME_ASQ_IOVA = DMA_IOVA_BASE`, `NVME_ACQ_IOVA = DMA_IOVA_BASE + 0x1000`.
    //
    // SAFETY: each `dma_map_page` call at step 3 installed a kernel-backed,
    // zero-initialised, 4 KiB-aligned page at the respective IOVA.
    // `program_admin_queue_bases` at step 4.10 programmed the controller
    // with the matching `asq_phys`/`acq_phys` physical addresses, so the
    // controller DMAs the same frames the CPU accesses here. The lifetime of
    // the slices ends at `_start`'s `sys_exit`; no other code path holds
    // these pointers.
    let asq_slice: &mut [u8] = unsafe {
        core::slice::from_raw_parts_mut(NVME_ASQ_IOVA as *mut u8, NVME_ADMIN_QUEUE_PAGE_BYTES)
    };
    let acq_slice: &[u8] = unsafe {
        core::slice::from_raw_parts(NVME_ACQ_IOVA as *const u8, NVME_ADMIN_QUEUE_PAGE_BYTES)
    };

    // Step 4.15 — P6.7.10-pre.33: encode + submit the Identify Controller
    // SQE (NVMe 1.4 § 5.15.1). PRP1 is programmed with `idctrl_phys` (the
    // physical base returned by `dma_map_page`) — the controller writes the
    // 4 KiB response to that physical address; the CPU reads the response via
    // the IOVA at step 4.15.d (ADR-0036 appendix 2). PRP2 = 0 (single-page
    // response).
    let identify_sqe = encode_identify(
        IdentifyTarget::Controller,
        idctrl_phys,
        0,
        NVME_IDENTIFY_FIRST_CID,
    );
    if admin_pair
        .submit(&identify_sqe, &mut mmio_write, asq_slice)
        .is_err()
    {
        unsafe { sys_exit(EXIT_NVME_IDENTIFY_SUBMIT_FAILED) };
    }

    // Step 4.15.b — Poll the admin CQ for the matching CID. The
    // loop bounds polling to `NVME_IDENTIFY_POLL_LIMIT` so a
    // misprogrammed controller cannot wedge the bring-up
    // indefinitely. `drain_completion` returns:
    //   - `Ok(Some(fields))` when the current slot has the
    //     expected phase tag and is consumed — the loop matches
    //     on `cid` to skip any stray completion (impossible in
    //     a single-in-flight scenario but defensively coded).
    //   - `Ok(None)` when the slot's phase tag still matches the
    //     previous lap — the controller has not written yet.
    //   - `Err(_)` on a CQ-page bounds or doorbell-stride bug —
    //     reachable only on a constants regression.
    let mut polls: u32 = 0;
    let identify_cqe = loop {
        if polls >= NVME_IDENTIFY_POLL_LIMIT {
            // Diagnostic (TASK-14): on timeout, dump CSTS (CFS bit 1 =
            // controller fatal) and the raw ACQ slot-0 status dword
            // (CQE DW3 at byte 12: phase bit 0, status bits 1..15, cid
            // 16..31). A non-zero DW3 means the controller DID write a
            // completion (phase/drain bug); all-zero means it never
            // processed the SQE (doorbell / SQ-base / PRP issue).
            write("[driver-nvme] identify timeout csts=");
            write_hex32(mmio_read.read_register(CSTS_OFFSET));
            write(" acq.dw0=");
            let dw0 = u32::from_le_bytes([acq_slice[0], acq_slice[1], acq_slice[2], acq_slice[3]]);
            write_hex32(dw0);
            write(" acq.dw3=");
            let dw3 =
                u32::from_le_bytes([acq_slice[12], acq_slice[13], acq_slice[14], acq_slice[15]]);
            write_hex32(dw3);
            write("\n");
            unsafe { sys_exit(EXIT_NVME_IDENTIFY_TIMEOUT) };
        }
        polls = polls.saturating_add(1);
        // Cooperative yield (TASK-14): hand the vCPU to QEMU's NVMe
        // device thread so it can post the completion; a pure busy-spin
        // (no VM-exit) races the device emulation -> intermittent timeout.
        task_yield();

        match admin_pair.drain_completion(&mut mmio_write, acq_slice) {
            Ok(Some(fields)) if fields.cid == NVME_IDENTIFY_FIRST_CID => break fields,
            Ok(Some(_)) => {
                // Stray completion with a non-matching CID —
                // impossible in the single-in-flight Identify
                // scenario but defensively skip-and-keep-polling
                // so a future multi-command pre-amble does not
                // accidentally consume the Identify's CQE.
                continue;
            }
            Ok(None) => continue,
            Err(_) => unsafe { sys_exit(EXIT_NVME_IDENTIFY_DRAIN_FAILED) },
        }
    };

    // Step 4.15.c — Validate the completion status word. NVMe 1.4
    // § 4.6 success = `SCT = 0` (Generic Command Status) AND
    // `SC = 0` (Successful Completion). Any non-zero status
    // means the controller actively refused the command — exit
    // with a distinct sentinel so the serial log triage can
    // distinguish "controller did not respond" (timeout) from
    // "controller responded but command rejected" (this case).
    if !identify_cqe.is_success() {
        unsafe { sys_exit(EXIT_NVME_IDENTIFY_FAILED) };
    }

    // Step 4.15.d — P6.7.10-pre.42: parse the Identify Controller response
    // page and validate `NN > 0` (the controller exposes at least one
    // namespace). The `nn()` accessor reads the 32-bit LE field at offset
    // 516 per NVMe 1.4 § 5.15.2 Figure 247.
    //
    // CPU access uses the **IOVA** (`NVME_IDENTIFY_CTRL_RESP_IOVA`): the
    // kernel maps `iova → idctrl_phys` in the driver's page table; the
    // controller wrote its response to `idctrl_phys`. The IOVA and phys
    // alias the same physical frame (ADR-0036 appendix 2).
    //
    // SAFETY: the `dma_map_page` call at step 3 installed a zero-initialised
    // page at `NVME_IDENTIFY_CTRL_RESP_IOVA`; the controller acknowledged
    // the Identify submission via the matching CQE above, so the DMA write
    // to `idctrl_phys` (= the same physical frame) is complete.
    let ctrl_resp_slice: &[u8] =
        unsafe { core::slice::from_raw_parts(NVME_IDENTIFY_CTRL_RESP_IOVA as *const u8, 4096) };
    let ctrl_view = match IdentifyController::new(ctrl_resp_slice) {
        Ok(v) => v,
        Err(_) => unsafe { sys_exit(EXIT_NVME_IDENTIFY_CTRL_PARSE_FAILED) },
    };
    if ctrl_view.nn() == 0 {
        unsafe { sys_exit(EXIT_NVME_IDENTIFY_CTRL_NN_ZERO) };
    }

    // Step 4.16 — P6.7.10-pre.34: encode + submit the
    // Identify(ActiveNsList) SQE (NVMe 1.4 § 5.15.2). The response
    // is a 4 KiB page laid out as 1024 little-endian 32-bit NSIDs
    // (ascending, NSID = 0 sentinel terminator). PRP2 is zero
    // (single-page response). This is the second real admin
    // command the live image issues end-to-end: the first
    // (Identify Controller) already validated the queue-pair
    // plumbing in pre.33, so any failure surfaced below is
    // squarely a controller-side or DMA-arena regression scoped to
    // the ActiveNsList command.
    // PRP1 = `idnslist_phys` (device-address); CPU reads response at
    // `NVME_IDENTIFY_NS_LIST_RESP_IOVA` (IOVA) in step 4.16.d
    // (ADR-0036 appendix 2).
    let ns_list_sqe = encode_identify(
        IdentifyTarget::ActiveNsList,
        idnslist_phys,
        0,
        NVME_IDENTIFY_NS_LIST_CID,
    );
    if admin_pair
        .submit(&ns_list_sqe, &mut mmio_write, asq_slice)
        .is_err()
    {
        unsafe { sys_exit(EXIT_NVME_NS_LIST_SUBMIT_FAILED) };
    }

    // Step 4.16.b — Poll the admin CQ for the matching CID. Same
    // structure as step 4.15.b: bounded budget, skip strays,
    // continue on `Ok(None)`, exit on `Err(_)`. The CQ slot used
    // by this completion is slot 1 (slot 0 is consumed by the
    // Identify Controller completion above; `drain_completion`
    // advanced `expected_head` internally). The phase tag at
    // slot 1 is still 1 (we are on lap 1 and CQ_DEPTH = 64), so a
    // synthetic empty page would land on the `Ok(None)` path.
    let mut ns_list_polls: u32 = 0;
    let ns_list_cqe = loop {
        if ns_list_polls >= NVME_IDENTIFY_NS_LIST_POLL_LIMIT {
            unsafe { sys_exit(EXIT_NVME_NS_LIST_TIMEOUT) };
        }
        ns_list_polls = ns_list_polls.saturating_add(1);
        // Cooperative yield (TASK-14): hand the vCPU to QEMU's NVMe
        // device thread so it can post the completion; a pure busy-spin
        // (no VM-exit) races the device emulation -> intermittent timeout.
        task_yield();

        match admin_pair.drain_completion(&mut mmio_write, acq_slice) {
            Ok(Some(fields)) if fields.cid == NVME_IDENTIFY_NS_LIST_CID => break fields,
            Ok(Some(_)) => {
                // Stray completion with a non-matching CID — same
                // defensive skip-and-keep-polling as step 4.15.b.
                continue;
            }
            Ok(None) => continue,
            Err(_) => unsafe { sys_exit(EXIT_NVME_NS_LIST_DRAIN_FAILED) },
        }
    };

    // Step 4.16.c — Validate the completion status word. Same
    // semantics as step 4.15.c, with a distinct sentinel so triage
    // can localise which command in the handshake regressed.
    if !ns_list_cqe.is_success() {
        unsafe { sys_exit(EXIT_NVME_NS_LIST_FAILED) };
    }

    // Step 4.16.d — Parse the 4 KiB response page via [`ActiveNsListView`].
    // The view is alloc-free and reads the page lazily on
    // `first_active_nsid()`. CPU access uses the **IOVA**
    // (`NVME_IDENTIFY_NS_LIST_RESP_IOVA`): the kernel maps
    // `iova → idnslist_phys`; the controller wrote the NSID array to
    // `idnslist_phys` (ADR-0036 appendix 2).
    //
    // SAFETY: `dma_map_page` at step 3 installed a zero-initialised page
    // at `NVME_IDENTIFY_NS_LIST_RESP_IOVA`; the controller acknowledged the
    // submission via the matching CQE above, so the DMA write to
    // `idnslist_phys` (the same physical frame) has completed.
    // The slice lifetime ends at `_start`'s `sys_exit`; no other code path
    // holds these bytes.
    let ns_list_slice: &[u8] = unsafe {
        core::slice::from_raw_parts(
            NVME_IDENTIFY_NS_LIST_RESP_IOVA as *const u8,
            NVME_IDENTIFY_NS_LIST_RESP_BYTES,
        )
    };
    let ns_list_view = match ActiveNsListView::new(ns_list_slice) {
        Ok(v) => v,
        Err(_) => unsafe { sys_exit(EXIT_NVME_NS_LIST_PARSE_FAILED) },
    };
    let first_nsid = match ns_list_view.first_active_nsid() {
        Some(nsid) => nsid,
        None => unsafe { sys_exit(EXIT_NVME_NS_LIST_EMPTY) },
    };

    // Step 4.17 — P6.7.10-pre.35: encode + submit the
    // Identify(Namespace) SQE (NVMe 1.4 § 5.15.2 Figure 245)
    // for the first active NSID discovered in step 4.16.d. The
    // 4 KiB response page at `NVME_IDENTIFY_NS_RESP_IOVA` is
    // parsed via `IdentifyNamespace::new` + `validated_byte_size()`
    // to extract the namespace capacity and validate that the
    // active LBA format uses 4 KiB sectors (`LBADS = 12`) per
    // NCIP-014 § S6 step 10.
    // PRP1 = `idns_phys` (device-address); CPU reads response at
    // `NVME_IDENTIFY_NS_RESP_IOVA` (IOVA) in step 4.17.d (ADR-0036 appendix 2).
    let ns_sqe = encode_identify(
        IdentifyTarget::Namespace { nsid: first_nsid },
        idns_phys,
        0,
        NVME_IDENTIFY_NS_CID,
    );
    if admin_pair
        .submit(&ns_sqe, &mut mmio_write, asq_slice)
        .is_err()
    {
        unsafe { sys_exit(EXIT_NVME_NS_SUBMIT_FAILED) };
    }

    // Step 4.17.b — Poll the admin CQ for the matching CID. Same
    // structure as steps 4.15.b and 4.16.b: bounded budget, skip
    // strays, continue on `Ok(None)`, exit on `Err(_)`. The CQ
    // slot used by this completion is slot 2 (slots 0 and 1 were
    // consumed by the Identify Controller and ActiveNsList
    // completions above).
    let mut ns_polls: u32 = 0;
    let ns_cqe = loop {
        if ns_polls >= NVME_IDENTIFY_NS_POLL_LIMIT {
            unsafe { sys_exit(EXIT_NVME_NS_TIMEOUT) };
        }
        ns_polls = ns_polls.saturating_add(1);
        // Cooperative yield (TASK-14): hand the vCPU to QEMU's NVMe
        // device thread so it can post the completion; a pure busy-spin
        // (no VM-exit) races the device emulation -> intermittent timeout.
        task_yield();

        match admin_pair.drain_completion(&mut mmio_write, acq_slice) {
            Ok(Some(fields)) if fields.cid == NVME_IDENTIFY_NS_CID => break fields,
            Ok(Some(_)) => continue,
            Ok(None) => continue,
            Err(_) => unsafe { sys_exit(EXIT_NVME_NS_DRAIN_FAILED) },
        }
    };

    // Step 4.17.c — Validate the completion status word.
    if !ns_cqe.is_success() {
        unsafe { sys_exit(EXIT_NVME_NS_FAILED) };
    }

    // Step 4.17.d — Parse the 4 KiB response page via
    // `IdentifyNamespace::new` and validate that the active LBA
    // format uses 4 KiB sectors per NCIP-014 § S6 step 10. The
    // `validated_byte_size()` call returns the namespace's total
    // byte capacity on success, or `UnsupportedLbads` when the
    // sector size is not 4 KiB — a hard bring-up failure because
    // the kernel BLK gateway cannot translate 512-byte-sector
    // requests to the NexaCore OS 4 KiB page model.
    //
    // CPU access uses the **IOVA** (`NVME_IDENTIFY_NS_RESP_IOVA`): the kernel
    // maps `iova → idns_phys`; the controller wrote the Namespace descriptor
    // to `idns_phys` (ADR-0036 appendix 2).
    //
    // SAFETY: `dma_map_page` at step 3 installed a zero-initialised page at
    // `NVME_IDENTIFY_NS_RESP_IOVA`; the controller acknowledged the submission
    // via the matching CQE above, so the DMA write has completed.
    let ns_resp_slice: &[u8] = unsafe {
        core::slice::from_raw_parts(
            NVME_IDENTIFY_NS_RESP_IOVA as *const u8,
            NVME_IDENTIFY_NS_RESP_BYTES,
        )
    };
    let ns_view = match IdentifyNamespace::new(ns_resp_slice) {
        Ok(v) => v,
        Err(_) => unsafe { sys_exit(EXIT_NVME_NS_PARSE_FAILED) },
    };
    let namespace_byte_size = match ns_view.validated_byte_size() {
        Ok(size) => size,
        Err(_) => unsafe { sys_exit(EXIT_NVME_NS_UNSUPPORTED_LBADS) },
    };

    // Step 4.17.e — P6.7.10-pre.46: multi-namespace validation.
    // Build a NamespaceDescriptor for the first active namespace
    // and verify it passes Phase-1 admission (LBADS=12, NSZE>0).
    // This exercises the namespace_map validation logic in the
    // live bring-up path. The alloc-free NamespaceDescriptor is
    // stack-allocated (no heap).
    let ns_desc = NamespaceDescriptor::from_validated(
        first_nsid,
        ns_view.nsze(),
        ns_view.ncap(),
        ns_view.lbads(),
        namespace_byte_size,
    );
    if ns_desc.nsze() == 0 || ns_desc.lbads() != 12 {
        unsafe { sys_exit(EXIT_NVME_NS_VALIDATION_REJECTED) };
    }

    // Step 4.17.f — P6.7.10-pre.46: MSI-X configuration validation.
    // Verify that Phase-1's hardcoded vector 0 is within the
    // controller's MSI-X table size. This exercises the interrupt
    // module's MsixConfig in the live path.
    let msix_cfg = MsixConfig::phase_1_default();
    if !msix_cfg.supports_vector(NVME_IO_CQ_IRQ_VECTOR) {
        unsafe { sys_exit(EXIT_NVME_MSIX_VECTOR_UNSUPPORTED) };
    }

    // Step 4.18 — P6.7.10-pre.36: Create I/O Completion Queue.
    // Per NVMe 1.4 § 5.3 the IO CQ MUST be created before the matching IO SQ.
    // Phase-1 creates exactly one IO queue pair (QID 1) per NCIP-014 § R2.
    // PRP1 = `iocq_phys` (device-address, returned by `dma_map_page`);
    // CPU accesses the CQ via `NVME_IO_CQ_IOVA` at step 4.20.b
    // (ADR-0036 appendix 2). `physically_contiguous = true` because
    // Phase-1 uses single-page PRP mode.
    let create_cq_sqe = encode_create_io_cq(
        NVME_IO_QID,
        NVME_IO_QUEUE_DEPTH,
        iocq_phys,
        NVME_IO_CQ_IRQ_VECTOR,
        true,
        true,
        NVME_CREATE_IO_CQ_CID,
    );
    if admin_pair
        .submit(&create_cq_sqe, &mut mmio_write, asq_slice)
        .is_err()
    {
        unsafe { sys_exit(EXIT_NVME_CREATE_IO_CQ_SUBMIT_FAILED) };
    }

    // Step 4.18.b — Poll for the Create IO CQ completion. The CQE
    // lands on CQ slot 3 (slots 0–2 consumed by the three Identify
    // completions above).
    let mut cq_create_polls: u32 = 0;
    let cq_create_cqe = loop {
        if cq_create_polls >= NVME_CREATE_IO_POLL_LIMIT {
            unsafe { sys_exit(EXIT_NVME_CREATE_IO_CQ_TIMEOUT) };
        }
        cq_create_polls = cq_create_polls.saturating_add(1);
        // Cooperative yield (TASK-14): hand the vCPU to QEMU's NVMe
        // device thread so it can post the completion; a pure busy-spin
        // (no VM-exit) races the device emulation -> intermittent timeout.
        task_yield();

        match admin_pair.drain_completion(&mut mmio_write, acq_slice) {
            Ok(Some(fields)) if fields.cid == NVME_CREATE_IO_CQ_CID => break fields,
            Ok(Some(_)) => continue,
            Ok(None) => continue,
            Err(_) => unsafe { sys_exit(EXIT_NVME_CREATE_IO_CQ_DRAIN_FAILED) },
        }
    };

    // Step 4.18.c — Validate the completion status word.
    if !cq_create_cqe.is_success() {
        unsafe { sys_exit(EXIT_NVME_CREATE_IO_CQ_FAILED) };
    }

    // Step 4.19 — P6.7.10-pre.36: Create I/O Submission Queue.
    // Per NVMe 1.4 § 5.4 the IO SQ references the IO CQ created in step 4.18
    // via `cq_id = NVME_IO_QID`. Queue priority is `MEDIUM`. PRP1 = `iosq_phys`
    // (device-address); CPU accesses the SQ via `NVME_IO_SQ_IOVA` at step 4.20.b
    // (ADR-0036 appendix 2).
    let create_sq_sqe = encode_create_io_sq(
        NVME_IO_QID,
        NVME_IO_QUEUE_DEPTH,
        iosq_phys,
        NVME_IO_QID,
        CIOSQ_QPRIO_MEDIUM,
        true,
        NVME_CREATE_IO_SQ_CID,
    );
    if admin_pair
        .submit(&create_sq_sqe, &mut mmio_write, asq_slice)
        .is_err()
    {
        unsafe { sys_exit(EXIT_NVME_CREATE_IO_SQ_SUBMIT_FAILED) };
    }

    // Step 4.19.b — Poll for the Create IO SQ completion. The CQE
    // lands on CQ slot 4.
    let mut sq_create_polls: u32 = 0;
    let sq_create_cqe = loop {
        if sq_create_polls >= NVME_CREATE_IO_POLL_LIMIT {
            unsafe { sys_exit(EXIT_NVME_CREATE_IO_SQ_TIMEOUT) };
        }
        sq_create_polls = sq_create_polls.saturating_add(1);
        // Cooperative yield (TASK-14): hand the vCPU to QEMU's NVMe
        // device thread so it can post the completion; a pure busy-spin
        // (no VM-exit) races the device emulation -> intermittent timeout.
        task_yield();

        match admin_pair.drain_completion(&mut mmio_write, acq_slice) {
            Ok(Some(fields)) if fields.cid == NVME_CREATE_IO_SQ_CID => break fields,
            Ok(Some(_)) => continue,
            Ok(None) => continue,
            Err(_) => unsafe { sys_exit(EXIT_NVME_CREATE_IO_SQ_DRAIN_FAILED) },
        }
    };

    // Step 4.19.c — Validate the completion status word.
    if !sq_create_cqe.is_success() {
        unsafe { sys_exit(EXIT_NVME_CREATE_IO_SQ_FAILED) };
    }

    // Step 4.20 — Construct the IO queue pair.
    // The IO queue pair (qid = 1) lives at IO SQ IOVA `0x6000` +
    // IO CQ IOVA `0x5000` in the DMA arena. The bounce buffer lives
    // at IOVA `0x7000` (reused for Read data and Write data).
    let mut io_pair = match AdminQueuePair::new_for_qid(
        NVME_IO_QID,
        u32::from(NVME_IO_QUEUE_DEPTH),
        u32::from(NVME_IO_QUEUE_DEPTH),
        NVME_ADMIN_DSTRD_DEFAULT,
    ) {
        Ok(p) => p,
        Err(_) => unsafe { sys_exit(EXIT_NVME_IO_PAIR_INVALID) },
    };

    // Step 4.20.b — Acquire &mut [u8] views into the IO SQ + CQ data pages
    // using their **IOVA** (CPU virtual address). The kernel maps
    // `NVME_IO_SQ_IOVA → iosq_phys` and `NVME_IO_CQ_IOVA → iocq_phys`.
    // The controller was programmed with the physical addresses (`iosq_phys`,
    // `iocq_phys`) at steps 4.18–4.19; CPU and device thus share the same
    // physical frames via different address spaces (ADR-0036 appendix 2).
    //
    // SAFETY: `dma_map_page` at step 3 installed zero-initialised pages at
    // `NVME_IO_CQ_IOVA` and `NVME_IO_SQ_IOVA`; the controller acknowledged
    // their existence via the matching `Create IO CQ` / `Create IO SQ` CQEs.
    // The slices are non-overlapping (`IO_CQ_IOVA = DMA_IOVA_BASE + 0x5000`,
    // `IO_SQ_IOVA = DMA_IOVA_BASE + 0x6000`).
    let io_sq_slice: &mut [u8] = unsafe {
        core::slice::from_raw_parts_mut(NVME_IO_SQ_IOVA as *mut u8, NVME_IO_READ_DATA_BYTES)
    };
    let io_cq_slice: &[u8] = unsafe {
        core::slice::from_raw_parts(NVME_IO_CQ_IOVA as *const u8, NVME_IO_READ_DATA_BYTES)
    };

    // Acquire a &mut [u8] view into the DMA bounce buffer used by both Read
    // (controller writes here at `bounce_phys`) and Write (driver copies
    // client data here before issuing the NVM Write, which the controller
    // reads from `bounce_phys`). CPU access uses `NVME_IO_READ_DATA_IOVA`
    // (IOVA); the kernel maps `iova → bounce_phys` (ADR-0036 appendix 2).
    //
    // SAFETY: `dma_map_page` at step 3 installed a zero-initialised page at
    // `NVME_IO_READ_DATA_IOVA` (`DMA_IOVA_BASE + 0x7000`, 8th 4 KiB page).
    // The slice is not aliased by any other slice in `_start` — the IO SQ
    // is at `0x6000` and no other mapping uses `0x7000`.
    let dma_bounce: &mut [u8] = unsafe {
        core::slice::from_raw_parts_mut(NVME_IO_READ_DATA_IOVA as *mut u8, NVME_IO_READ_DATA_BYTES)
    };

    // =======================================================================
    // Step 4.21 — IRQ path bring-up (WS1-07, ADR-0036 D5 / Option B).
    //
    // Placed AFTER the controller bring-up on purpose: the admin
    // completions above also signal MSI-X vector 0, so attaching earlier
    // would queue stale notifications that a later IO wait could mistake
    // for its own interrupt. MSI-X stays disabled until the attach
    // (program_vector sets the capability Enable bit), so the admin-phase
    // interrupts are never generated.
    //
    // Best-effort by design: a missing token or failed attach falls back
    // to the pure cooperative-polling completion wait (Option A), logged
    // — never silent (ADR-0036 D5).
    // =======================================================================
    let mut irq_path = IrqPath {
        channel_id: 0,
        hit_logged: false,
        fallback_logged: false,
        notif_total: 0,
        delivered_logged: false,
    };
    if let Some(irq_token) = find_token(ACTION_TAG_IRQ_ATTACH, |_| true) {
        let (irq_channel_id, _irq_extra) = unsafe {
            syscall5(
                SYS_IPC_CREATE_CHANNEL,
                IRQ_CHANNEL_QUEUE_DEPTH,
                IRQ_CHANNEL_BACKPRESSURE_EVICT_OLDEST,
                BLK_CHANNEL_TEE_NOT_BOUND,
                0,
                0,
            )
        };
        if irq_channel_id == u64::MAX {
            write("[driver-nvme] irq channel create failed — polling fallback\n");
        } else {
            let (_vector, irq_errno) = unsafe {
                syscall5(
                    SYS_IRQ_ATTACH,
                    NVME_IRQ_LINE,
                    irq_channel_id,
                    irq_token.as_ptr() as u64,
                    irq_token.len() as u64,
                    0,
                )
            };
            if irq_errno == 0 {
                irq_path.channel_id = irq_channel_id;
                write("[driver-nvme] irq attached line=34 (MSI-X vector bound to IPC channel)\n");
                // The kernel fires an attach self-test IPI on the bound
                // vector (WS1-06.10 guest-chain proof). Give it a few
                // scheduler turns to land, then drain the channel so the
                // first REAL completion wait starts from a clean slate.
                for _ in 0..64 {
                    task_yield();
                }
                let mut residual: u64 = 0;
                while residual < IRQ_CHANNEL_QUEUE_DEPTH {
                    // SAFETY: IRQ_NOTIF_BUF single-thread guarantee (see
                    // its doc); the service loop has not started yet.
                    if ipc_try_receive(irq_channel_id, unsafe {
                        &mut *core::ptr::addr_of_mut!(IRQ_NOTIF_BUF)
                    })
                    .is_none()
                    {
                        break;
                    }
                    residual = residual.saturating_add(1);
                }
            } else {
                write("[driver-nvme] irq attach failed — polling fallback\n");
            }
        }
    } else {
        write("[driver-nvme] no irq token deposited — polling fallback\n");
    }

    // Step 5 — Serial audit: driver is ready.
    write("[driver-nvme] ready disk0 nvme0 + nvme0-reply, entering BLK service loop\n");

    // =======================================================================
    // Step 6 — BLK service loop (TASK-14, ADR-0036 D3 / D5, Option A).
    //
    // The loop receives `BlkRequest` messages on `nvme0` (request channel),
    // drives the IO queue, and sends `BlkResponse` + optional data chunks
    // on `nvme0-reply` (reply channel).
    //
    // Completion wait: cooperative-yield (`drain_io` — see above).
    // The driver NEVER exits this loop on success.
    // =======================================================================

    // Monotonic CID counter. Starts at 1 (0 is the RESERVED_DRIVER_OPAQUE_ID
    // in nexacore_types::nvme). Wraps through 1..=u16::MAX (skip 0 on wrap).
    let mut next_cid: u16 = 1;

    loop {
        // Poll the request channel for the next BlkRequest.
        // SAFETY: REQ_BUF is a static BSS buffer; the BLK service loop
        // is the only code path that accesses it.
        let n = match ipc_try_receive(channel_id, unsafe {
            &mut *core::ptr::addr_of_mut!(REQ_BUF)
        }) {
            Some(n) => n,
            None => {
                // Queue empty — yield the CPU (cooperative, ADR-0036 D5).
                task_yield();
                continue;
            }
        };

        // Decode the BlkRequest. `BlkRequest` is `Copy` + borrows only the
        // input slice (no heap allocation required).
        // SAFETY: REQ_BUF[..n] contains the bytes just copied by the kernel.
        let req = match decode_canonical::<BlkRequest>(unsafe {
            &(*core::ptr::addr_of!(REQ_BUF))[..n]
        }) {
            Ok(r) => r,
            Err(_) => {
                // Malformed request — reply InvalidArgument and continue.
                // SAFETY: RESP_BUF single-thread exclusive access.
                unsafe { send_blk_response(reply_channel_id, BlkResponse::InvalidArgument) };
                continue;
            }
        };

        // Allocate a CID for this IO command. Skip 0 on wrap.
        let cid = next_cid;
        next_cid = next_cid.wrapping_add(1);
        if next_cid == 0 {
            next_cid = 1;
        }

        match req {
            // -------------------------------------------------------------------
            // Read: submit NVM Read, drain cooperatively, reply Ok + 2 chunks.
            // ADR-0036 D3: count == 1 only (v0.3); buf_iova ignored (inline).
            // -------------------------------------------------------------------
            BlkRequest::Read { lba, count, .. } => {
                if count != 1 {
                    unsafe {
                        send_blk_response(reply_channel_id, BlkResponse::InvalidArgument);
                    }
                    continue;
                }
                // Cheap guard: reject obviously out-of-range LBAs (>= 1 TiB
                // in 4 KiB blocks = 256 Mi sectors). Full range-check against
                // ns_desc.nsze() deferred until nexacore-driver-nvme exposes it
                // through the IO path (TODO: use namespace_byte_size).
                if lba >= (1u64 << 28) {
                    unsafe {
                        send_blk_response(reply_channel_id, BlkResponse::OutOfRange);
                    }
                    continue;
                }

                // PRP1 = `bounce_phys` (device-address); CPU reads sector data
                // via `dma_bounce` (IOVA `NVME_IO_READ_DATA_IOVA`) after completion
                // (ADR-0036 appendix 2).
                let read_sqe = encode_read(first_nsid, lba, 1, bounce_phys, 0, cid);
                if io_pair
                    .submit(&read_sqe, &mut mmio_write, io_sq_slice)
                    .is_err()
                {
                    unsafe {
                        send_blk_response(reply_channel_id, BlkResponse::DeviceError(0xFFFF));
                    }
                    continue;
                }

                match wait_completion(
                    &mut irq_path,
                    &mut io_pair,
                    &mut mmio_write,
                    io_cq_slice,
                    cid,
                ) {
                    Ok(f) => {
                        let resp = cqe_to_blk_response(&f);
                        // SAFETY: send_blk_response accesses RESP_BUF exclusively.
                        unsafe { send_blk_response(reply_channel_id, resp) };
                        if matches!(resp, BlkResponse::Ok) {
                            // Send the 4 KiB sector as 2 × 2048 B raw chunks
                            // (ADR-0036 D3: per-chunk size = sector / 2 = 2048 B).
                            ipc_send(reply_channel_id, IPC_KIND_REPLY, &dma_bounce[..2048]);
                            ipc_send(reply_channel_id, IPC_KIND_REPLY, &dma_bounce[2048..4096]);
                            write("[driver-nvme] op=read lba=.. -> Ok\n");
                        } else {
                            write("[driver-nvme] op=read lba=.. -> DeviceError\n");
                        }
                    }
                    Err(()) => {
                        unsafe {
                            send_blk_response(reply_channel_id, BlkResponse::DeviceError(0xFFFF));
                        }
                        write("[driver-nvme] op=read drain_io budget exhausted\n");
                    }
                }
            }

            // -------------------------------------------------------------------
            // Write: receive 2 data chunks, copy to DMA bounce buffer,
            // submit NVM Write, drain cooperatively, reply Ok.
            // ADR-0036 D3: count == 1 only (v0.3).
            // -------------------------------------------------------------------
            BlkRequest::Write { lba, count, .. } => {
                if count != 1 {
                    unsafe {
                        send_blk_response(reply_channel_id, BlkResponse::InvalidArgument);
                    }
                    continue;
                }
                if lba >= (1u64 << 28) {
                    unsafe {
                        send_blk_response(reply_channel_id, BlkResponse::OutOfRange);
                    }
                    continue;
                }

                // Receive the two 2048-byte data chunks from the request
                // channel. Each chunk arrives as a raw IPC message. We poll
                // with a bounded budget (ADR-0036 D3) and yield between polls.
                const CHUNK_RECV_BUDGET: u32 = 2_000_000;

                // Chunk 0 → first 2048 bytes of the bounce buffer.
                let mut got_chunk0 = false;
                let mut chunk_iters: u32 = 0;
                while chunk_iters < CHUNK_RECV_BUDGET {
                    chunk_iters = chunk_iters.saturating_add(1);
                    // SAFETY: CHUNK_BUF is accessed exclusively in this loop.
                    match ipc_try_receive(channel_id, unsafe {
                        &mut *core::ptr::addr_of_mut!(CHUNK_BUF)
                    }) {
                        Some(2048) => {
                            // SAFETY: dma_bounce is the exclusive slice into
                            // the 4 KiB DMA arena; CHUNK_BUF is BSS; slices
                            // do not overlap.
                            unsafe {
                                dma_bounce[..2048]
                                    .copy_from_slice(&*core::ptr::addr_of!(CHUNK_BUF));
                            }
                            got_chunk0 = true;
                            break;
                        }
                        Some(_) | None => {
                            task_yield();
                        }
                    }
                }
                if !got_chunk0 {
                    unsafe {
                        send_blk_response(reply_channel_id, BlkResponse::DeviceError(0xFFFF));
                    }
                    continue;
                }

                // Chunk 1 → second 2048 bytes of the bounce buffer.
                let mut got_chunk1 = false;
                chunk_iters = 0;
                while chunk_iters < CHUNK_RECV_BUDGET {
                    chunk_iters = chunk_iters.saturating_add(1);
                    // SAFETY: CHUNK_BUF exclusive access.
                    match ipc_try_receive(channel_id, unsafe {
                        &mut *core::ptr::addr_of_mut!(CHUNK_BUF)
                    }) {
                        Some(2048) => {
                            // SAFETY: dma_bounce[2048..4096] and CHUNK_BUF do
                            // not overlap.
                            unsafe {
                                dma_bounce[2048..4096]
                                    .copy_from_slice(&*core::ptr::addr_of!(CHUNK_BUF));
                            }
                            got_chunk1 = true;
                            break;
                        }
                        Some(_) | None => {
                            task_yield();
                        }
                    }
                }
                if !got_chunk1 {
                    unsafe {
                        send_blk_response(reply_channel_id, BlkResponse::DeviceError(0xFFFF));
                    }
                    continue;
                }

                // PRP1 = `bounce_phys` (device-address); the driver wrote sector data
                // into `dma_bounce` (IOVA → same physical frame) before this call
                // so the controller reads from the correct physical address
                // (ADR-0036 appendix 2).
                let write_sqe = encode_write(first_nsid, lba, 1, bounce_phys, 0, cid);
                if io_pair
                    .submit(&write_sqe, &mut mmio_write, io_sq_slice)
                    .is_err()
                {
                    unsafe {
                        send_blk_response(reply_channel_id, BlkResponse::DeviceError(0xFFFF));
                    }
                    continue;
                }

                match wait_completion(
                    &mut irq_path,
                    &mut io_pair,
                    &mut mmio_write,
                    io_cq_slice,
                    cid,
                ) {
                    Ok(f) => {
                        let resp = cqe_to_blk_response(&f);
                        // SAFETY: RESP_BUF exclusive access.
                        unsafe { send_blk_response(reply_channel_id, resp) };
                        if matches!(resp, BlkResponse::Ok) {
                            write("[driver-nvme] op=write lba=.. -> Ok\n");
                        } else {
                            write("[driver-nvme] op=write lba=.. -> DeviceError\n");
                        }
                    }
                    Err(()) => {
                        unsafe {
                            send_blk_response(reply_channel_id, BlkResponse::DeviceError(0xFFFF));
                        }
                        write("[driver-nvme] op=write drain_io budget exhausted\n");
                    }
                }
            }

            // -------------------------------------------------------------------
            // Flush: submit NVM Flush, drain cooperatively, reply Ok.
            // -------------------------------------------------------------------
            BlkRequest::Flush => {
                let flush_sqe = encode_flush(first_nsid, cid);
                if io_pair
                    .submit(&flush_sqe, &mut mmio_write, io_sq_slice)
                    .is_err()
                {
                    unsafe {
                        send_blk_response(reply_channel_id, BlkResponse::DeviceError(0xFFFF));
                    }
                    continue;
                }

                match wait_completion(
                    &mut irq_path,
                    &mut io_pair,
                    &mut mmio_write,
                    io_cq_slice,
                    cid,
                ) {
                    Ok(f) => {
                        let resp = cqe_to_blk_response(&f);
                        // SAFETY: RESP_BUF exclusive access.
                        unsafe { send_blk_response(reply_channel_id, resp) };
                        if matches!(resp, BlkResponse::Ok) {
                            write("[driver-nvme] op=flush -> Ok\n");
                        } else {
                            write("[driver-nvme] op=flush -> DeviceError\n");
                        }
                    }
                    Err(()) => {
                        unsafe {
                            send_blk_response(reply_channel_id, BlkResponse::DeviceError(0xFFFF));
                        }
                        write("[driver-nvme] op=flush drain_io budget exhausted\n");
                    }
                }
            }

            // -------------------------------------------------------------------
            // Discard: v0.3 returns NotSupported (ADR-0036 D3).
            // A future slice can implement Dataset Management here.
            // -------------------------------------------------------------------
            BlkRequest::Discard { .. } => {
                // SAFETY: RESP_BUF exclusive access.
                unsafe { send_blk_response(reply_channel_id, BlkResponse::NotSupported) };
                write("[driver-nvme] op=discard -> NotSupported (v0.3)\n");
            }

            // Catch-all for future #[non_exhaustive] variants.
            _ => {
                // SAFETY: RESP_BUF exclusive access.
                unsafe { send_blk_response(reply_channel_id, BlkResponse::NotSupported) };
            }
        }
    }
}

// =============================================================================
// Panic handler (required by `no_std`)
// =============================================================================

/// On panic, exit with a sentinel non-zero code so the kernel boot log
/// can correlate against the bring-up retry counter.
#[panic_handler]
fn panic(_info: &PanicInfo<'_>) -> ! {
    // SAFETY: TaskExit terminates the process unconditionally.
    unsafe { sys_exit(2) }
}
