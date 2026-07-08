//! Userspace process abstraction (MB11, ADR-0004 § 6).
//!
//! A [`ProcessControlBlock`] wraps the MB10 `TaskControlBlock` with
//! the new pieces required to run a Ring 3 process:
//!
//! - A per-process [`AddressSpace`] (its own CR3, kernel-half mirrored).
//! - The user entry-point VA (from the loaded ELF).
//! - The user-mode stack VA (initial RSP target for `iretq`).
//! - A per-process bump counter for additional user stack slots
//!   (Phase 1 single-thread per process; one slot is enough).
//!
//! The kernel scheduler keeps the underlying `TaskControlBlock` on its
//! run queues. The PCB is held in a separate `Vec<ProcessControlBlock>`
//! inside the scheduler so kernel-only tasks (MB10 idle, bootstrap)
//! continue to work unchanged.
//!
//! `spawn_from_elf` is the single high-level entry point. Flow:
//!
//! 1. Build a fresh [`AddressSpace`] with kernel-half cloned.
//! 2. Parse + map_and_load the ELF into that AS.
//! 3. Allocate user stack via [`super::bare_metal::user_stack`].
//! 4. Allocate kernel stack via MB10 path (host-side test stub returns
//!    a sentinel zero).
//! 5. Build the `TaskControlBlock` with `context.rsp = 0` (sentinel —
//!    the first context switch overwrites it; on user-process entry the
//!    iretq trampoline jumps directly to user mode, not via the kernel
//!    `context_switch` asm path).
//! 6. Register the PCB with the scheduler.

#![allow(
    unsafe_code,
    reason = "ELF map+load and PML4 clone require raw page-table writes; SAFETY per fn"
)]
#![allow(
    clippy::doc_markdown,
    reason = "module references AddressSpace, TaskControlBlock, CR3 without ticks in prose"
)]

#[cfg(feature = "bare-metal")]
use alloc::vec::Vec;

#[cfg(feature = "bare-metal")]
use crate::bare_metal::address_space::AddressSpace;
#[cfg(feature = "bare-metal")]
use crate::bare_metal::iommu::PciBdf;
#[cfg(feature = "bare-metal")]
use crate::capabilities::KernelPrincipal;
#[cfg(feature = "bare-metal")]
use crate::ipc::ChannelId;

/// Outstanding `IpcReceive` that this process issued before parking.
///
/// MB12 drain-at-dispatch: when an `IpcReceive` with `blocking = true`
/// hits an empty queue, the syscall handler stores this record on the
/// receiver PCB and parks the task. When a counterpart `IpcSend` later
/// arrives and the scheduler dispatches the receiver, the entry-into-
/// user-mode trampoline reads the slot, copies the message payload from
/// the kernel's IPC buffer into `dst_ptr`, clears the slot, and resumes
/// Ring 3 with the byte count in `rax`.
///
/// The kernel completes the copy itself (rather than re-issuing the
/// syscall on wake-up) because at that moment the receiver's CR3 is
/// active and `dst_ptr` is directly addressable. Re-issuing would
/// require the user code to retry, which neither MB11 nor MB12 model
/// (the user expects `IpcReceive` to return once).
#[cfg(feature = "bare-metal")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PendingReceive {
    /// Channel the task is waiting on.
    pub channel: ChannelId,
    /// User-space VA where the payload should be deposited.
    pub dst_ptr: u64,
    /// Maximum number of bytes the user buffer can hold.
    pub dst_cap: u64,
}

/// One driver-MMIO mapping installed via the `MmioMap` syscall
/// (`NCIP-Driver-Framework-013` § S2.2).
///
/// The kernel records each successful map on the calling process's
/// [`ProcessControlBlock`] so the mapping can be torn down at process
/// exit (§ S2.4).
///
/// Only the user-half VA + length is tracked here — the underlying
/// physical BAR pages are owned by the device, not by the frame
/// allocator, so teardown unmaps the leaf PTEs without returning
/// any frame to [`crate::memory::BitmapFrameAllocator`].
#[cfg(feature = "bare-metal")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MmioMapping {
    /// Page-aligned user VA where the mapping was installed.
    pub va_base: u64,
    /// Number of 4 KiB pages covered by the mapping. The total VA
    /// span is `len_pages * 0x1000` bytes.
    pub len_pages: u32,
}

/// One DMA window installed via the `DmaMap` syscall
/// (`NCIP-Driver-Framework-013` § S3, P6.7.8.3).
///
/// In Phase 1 the kernel runs **without an IOMMU**: the issuer grants the
/// driver an `iova_base` that coincides with the physical-address range
/// the kernel will map into the driver's AS at the same user VA. With
/// `iova == phys == user_va` the device DMA descriptors written by the
/// driver dereference the same phys frames the user-space buffer is
/// backed by. The IOMMU vendor backends (`vtd` / `amdvi`) land later
/// per NCIP-013 § S3.2 and will tighten this to "iova == phys translated
/// through the IOMMU domain page table".
#[cfg(feature = "bare-metal")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DmaMapping {
    /// Page-aligned IOVA (== user VA in the no-IOMMU passthrough mode).
    pub iova_base: u64,
    /// Physical base the contiguous DMA frames were allocated at, and
    /// the bus address the device actually emits (the value `DmaMap`
    /// returns in `rax`, which the driver programs into its descriptors).
    /// The IOMMU second-level page table is keyed on THIS address — the
    /// device addresses memory by physical, not by `iova_base` — so
    /// teardown must clear the SLPT at `phys_base` (WI-7b step 3,
    /// NCIP-026, ADR-0028).
    pub phys_base: u64,
    /// Number of 4 KiB pages covered.
    pub len_pages: u32,
    /// Direction tag (0=ToDevice, 1=FromDevice, 2=Bidirectional). The
    /// kernel does not enforce it in Phase 1; it is retained for
    /// audit-trail purposes and will gate the IOMMU permission bits in
    /// the vendor backends.
    pub direction: u8,
}

/// One IRQ attachment installed via the `IrqAttach` syscall
/// (`NCIP-Driver-Framework-013` § S4, P6.7.8.3).
///
/// Records the (irq_line, vector, channel_id) triple so the kernel can:
///   - reject duplicate attachments (`EBUSY` per § S4.1 "shared IOAPIC
///     line rejection"),
///   - drain pending notifications at process exit,
///   - free the LAPIC vector + IDT slot during teardown.
#[cfg(feature = "bare-metal")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IrqAttachment {
    /// IRQ line / GSI as advertised by the device's MSI-X table or
    /// IOAPIC redirection entry.
    pub irq_line: u16,
    /// LAPIC vector (`0x40..0xFE`) the kernel allocated for this line.
    pub vector: u8,
    /// IPC channel id that receives the `IrqNotification::{Tick,
    /// MissedSince(u32)}` envelope on each fire (NCIP-013 § S4.2,
    /// Appendix B amendment 3).
    pub channel_id: u64,
}

/// A userspace process (`Ring 3`).
#[cfg(feature = "bare-metal")]
#[derive(Debug)]
pub struct ProcessControlBlock {
    /// Underlying kernel-task TCB (carries `TaskId`, scheduler state,
    /// kernel stack VA + phys, and saved `CpuContext`).
    pub task: crate::scheduling::TaskControlBlock,
    /// Process address space (private PML4; kernel-half mirrored).
    pub address_space: AddressSpace,
    /// Initial user-mode RIP (ELF entry point).
    pub user_entry: u64,
    /// Initial user-mode RSP (top of the writable user stack region).
    pub user_stack_top: u64,
    /// Per-process counter for [`super::bare_metal::user_stack`]
    /// slot allocation. Phase 1 single-thread → always 1 after spawn.
    pub next_user_stack_slot: usize,
    /// Authority identifier (32-byte opaque hash). MB12 capability
    /// check compares this against `Channel::send_subject` /
    /// `recv_subject`. Defaults to [`KernelPrincipal::ZERO`] for
    /// processes spawned without a token (developer mode / smoke
    /// tests).
    pub principal: KernelPrincipal,
    /// MB12 drain-at-dispatch slot. `Some` means the process issued
    /// a blocking `IpcReceive` that has not yet delivered. The
    /// scheduler dispatch path clears this and copies the message
    /// payload before returning to Ring 3.
    pub pending_receive: Option<PendingReceive>,
    /// `MmioMap` mappings owned by this process (NCIP-013 § S2.4).
    /// Empty for non-driver processes.
    pub mmio_mappings: Vec<MmioMapping>,
    /// Per-process random offset into the reserved driver MMIO PML4
    /// slot, generated lazily on the first successful `MmioMap`
    /// (NCIP-013 § S2.5). `0` means "not yet randomized"; subsequent
    /// mappings within the same process are allocated linearly from
    /// `mmio_va_cursor`.
    pub mmio_va_cursor: u64,
    /// `DmaMap` windows owned by this process (NCIP-013 § S3.4).
    /// Empty for non-driver processes.
    pub dma_mappings: Vec<DmaMapping>,
    /// `IrqAttach` attachments owned by this process (NCIP-013 § S4.4).
    /// Empty for non-driver processes.
    pub irq_attachments: Vec<IrqAttachment>,
    /// User-VA base of the capability deposit page batch
    /// (P6.7.8.9, [`crate::cap_deposit::DRIVER_CAP_DEPOSIT_VA`]).
    /// `None` for non-driver processes spawned without a deposit
    /// (developer mode, mb11/mb12 userprobe).
    pub cap_deposit_va: Option<u64>,
    /// PCI BDFs bound to this process's IOMMU domain
    /// (P6.7.9-pre.8 — driver PCI bind).
    ///
    /// Populated by the `DriverLoad (73)` syscall handler (see
    /// `crate::bare_metal::syscall_entry`) after a successful spawn
    /// from the manifest's `capabilities.pci_devices` table; the kernel
    /// records the `(bdf, domain)` binding through
    /// [`crate::bare_metal::iommu::iommu_attach_device`] before user
    /// code runs.
    ///
    /// On `TaskExit` the same list drives the symmetric
    /// [`crate::bare_metal::iommu::iommu_detach_device`] calls so the
    /// vendor table does not retain stale entries pointing at a
    /// dead per-process IOMMU domain.
    ///
    /// Empty for non-driver processes (developer mode, mb11/mb12
    /// userprobe, scheduler workers) and for driver processes whose
    /// manifest declares no `PciDevice` resources (rare — every
    /// first-party driver in Phase 1 declares ≥ 1 PCI device).
    pub bound_pci_devices: Vec<PciBdf>,
}

#[cfg(feature = "bare-metal")]
impl ProcessControlBlock {
    /// Spawn a userspace process from an embedded ELF64 binary.
    ///
    /// On success the new task is **registered** with the scheduler
    /// (state `Runnable`, run queue corresponding to `priority`) and
    /// the new `TaskId` is returned.
    ///
    /// # Errors
    ///
    /// - `KernelError::ResourceExhausted` if the frame allocator cannot
    ///   provide a PML4, kernel stack, or user-stack frame.
    /// - `KernelError::InvalidArgument` if the ELF parser rejects the
    ///   binary.
    ///
    /// # Safety
    ///
    /// The caller must ensure that `boot_cr3`, `mapper`, `alloc`, and
    /// `scheduler` are the live kernel singletons (single-CPU, no
    /// aliasing). The new process is launched only at the next
    /// scheduler dispatch; this function does not itself enter Ring 3.
    #[cfg(target_arch = "x86_64")]
    pub unsafe fn spawn_from_elf<const N: usize>(
        elf_bytes: &[u8],
        boot_cr3: crate::memory::PhysAddr,
        mapper: &mut crate::bare_metal::paging::PageMapper,
        alloc: &mut crate::memory::BitmapFrameAllocator<N>,
        scheduler: &mut crate::scheduling::RoundRobinScheduler,
        priority: crate::scheduling::PriorityClass,
        principal: KernelPrincipal,
    ) -> crate::KernelResult<crate::scheduling::TaskId> {
        use crate::{
            KernelError,
            bare_metal::{elf_loader::Elf64, user_stack},
            scheduling::{CpuContext, TaskControlBlock, TaskState},
        };

        let phys_offset = mapper.phys_offset();

        // 1. Kernel stack (MB10 isolated range) — the Ring-3 → Ring-0
        //    interrupt/syscall path uses this via TSS.rsp0 and the
        //    MB13.f `enter_user_mode` trampoline swaps RSP onto it
        //    before reloading CR3.
        //
        //    Mapped FIRST (before cloning the per-process PML4) so the
        //    boot PML4's kernel-stack PML4 entry is populated before
        //    `AddressSpace::new_with_kernel_half` snapshots PML4 indices
        //    256..511. Per-process PML4s share kernel-half PDPTs *by
        //    reference*, but a brand-new PDPT installed in the boot
        //    PML4 *after* a clone does NOT propagate — the clone keeps
        //    its (stale) zero entry. Mapping the kernel stack here
        //    forces the boot PML4 to allocate the kstk-range PDPT
        //    eagerly, so the subsequent clone in step 2 captures it
        //    and every later kstk slot within the same shared PDPT
        //    propagates automatically. (MB13.f finding 2026-05-19.)
        let kernel_stack_va = scheduler
            .allocate_stack_slot()
            .ok_or(KernelError::ResourceExhausted)?;
        // Map the whole writable kernel-stack region (KERNEL_STACK_SIZE, 16 KiB
        // = 4 frames). The frames need not be physically contiguous — only the
        // VA range is. `kernel_stack_va` is the first frame's VA returned by
        // `allocate_stack_slot`; the value recorded in the PCB (also
        // `kernel_stack_va`) is the writable base, and the stack TOP used as the
        // initial RSP is `kernel_stack_va + KERNEL_STACK_SIZE`. The unmapped
        // guard region sits in the `KERNEL_STACK_SIZE` bytes just below the base.
        let kernel_stack_phys;
        {
            use crate::scheduling::KERNEL_STACK_SIZE;
            #[allow(
                clippy::integer_division,
                reason = "KERNEL_STACK_SIZE is a 4 KiB multiple by construction"
            )]
            let pages = KERNEL_STACK_SIZE / 0x1000;
            let mut first_phys: u64 = 0;
            let mut page_i: u64 = 0;
            while page_i < pages {
                let frame = alloc.alloc_frame().ok_or(KernelError::ResourceExhausted)?.0;
                if page_i == 0 {
                    first_phys = frame;
                }
                if !mapper.map_4k(
                    crate::memory::VirtAddr(kernel_stack_va + page_i * 0x1000),
                    crate::memory::PhysAddr(frame),
                    crate::bare_metal::paging::PTE_PRESENT
                        | crate::bare_metal::paging::PTE_WRITABLE
                        | crate::bare_metal::paging::PTE_NO_EXEC,
                    alloc,
                ) {
                    return Err(KernelError::ResourceExhausted);
                }
                page_i += 1;
            }
            kernel_stack_phys = first_phys;
        }

        // 2. Per-process address space + kernel-half clone. The boot
        //    PML4 now has the kstk-range PDPT populated (step 1), so
        //    the clone captures it.
        let address_space = AddressSpace::new_with_kernel_half(boot_cr3, mapper, alloc)
            .ok_or(KernelError::ResourceExhausted)?;

        // 3. Parse + map the ELF into the new AS.
        let elf = Elf64::parse(elf_bytes).map_err(|_| KernelError::InvalidArgument)?;
        let user_entry = elf
            .map_and_load_into(address_space.pml4_phys, mapper, alloc, phys_offset)
            .map_err(|_| KernelError::ResourceExhausted)?;

        // 4. User stack (16 KiB, guard page below) in the user-half VA range.
        let mut next_user_stack_slot: usize = 0;
        let user_stack_top = user_stack::allocate_user_stack(
            &mut next_user_stack_slot,
            &address_space,
            mapper,
            alloc,
        )
        .ok_or(KernelError::ResourceExhausted)?;

        // 5. Allocate a TaskId.
        let id = scheduler.allocate_task_id();

        // Build the underlying TCB. `context.rsp = 0` is a sentinel —
        // the iretq trampoline does not enter via the kernel
        // `context_switch` asm path; instead it builds an iretq frame
        // and jumps directly to Ring 3. The first SYSCALL / interrupt
        // back into the kernel will land on `TSS.rsp0` (the kernel
        // stack top), at which point a kernel `context_switch` push
        // sequence can begin.
        let tcb = TaskControlBlock {
            id,
            state: TaskState::Runnable,
            priority,
            context: CpuContext { rsp: 0 },
            kernel_stack_phys,
            kernel_stack_va,
        };

        // 6. Register the PCB + TCB in the scheduler. The scheduler
        // also enqueues the TaskId on the matching priority queue.
        scheduler.register_process(tcb, priority);

        // Save the PCB inside the scheduler's process table. This is
        // what later context-switch logic uses to (a) reload CR3 via
        // `address_space.activate()` and (b) update `TSS.rsp0`.
        scheduler.attach_process(
            id,
            Self {
                task: TaskControlBlock {
                    id,
                    state: TaskState::Runnable,
                    priority,
                    context: CpuContext { rsp: 0 },
                    kernel_stack_phys,
                    kernel_stack_va,
                },
                address_space,
                user_entry,
                user_stack_top,
                next_user_stack_slot,
                principal,
                pending_receive: None,
                mmio_mappings: Vec::new(),
                mmio_va_cursor: 0,
                dma_mappings: Vec::new(),
                irq_attachments: Vec::new(),
                cap_deposit_va: None,
                bound_pci_devices: Vec::new(),
            },
        );

        Ok(id)
    }
}

#[cfg(all(test, feature = "bare-metal"))]
mod tests {
    use super::*;
    use crate::{
        bare_metal::address_space::AddressSpace,
        ipc::ChannelId,
        memory::PhysAddr,
        scheduling::{PriorityClass, TaskId},
    };

    fn make_pcb() -> ProcessControlBlock {
        ProcessControlBlock {
            task: crate::scheduling::TaskControlBlock {
                id: TaskId(42),
                state: crate::scheduling::TaskState::Runnable,
                priority: PriorityClass::Interactive,
                context: crate::scheduling::CpuContext { rsp: 0 },
                kernel_stack_phys: 0xDEAD_0000,
                kernel_stack_va: 0xFFFF_C000_0000_1000,
            },
            address_space: AddressSpace {
                pml4_phys: PhysAddr(0xBEEF_0000),
            },
            user_entry: 0x4000_0000,
            user_stack_top: 0x0000_0040_0000_8000,
            next_user_stack_slot: 1,
            principal: KernelPrincipal::ZERO,
            pending_receive: None,
            mmio_mappings: Vec::new(),
            mmio_va_cursor: 0,
            dma_mappings: Vec::new(),
            irq_attachments: Vec::new(),
            cap_deposit_va: None,
            bound_pci_devices: Vec::new(),
        }
    }

    #[test]
    fn pcb_fields_round_trip() {
        let pcb = make_pcb();
        assert_eq!(pcb.task.id, TaskId(42));
        assert_eq!(pcb.user_entry, 0x4000_0000);
        assert_eq!(pcb.user_stack_top, 0x0000_0040_0000_8000);
        assert_eq!(pcb.address_space.pml4_phys.0, 0xBEEF_0000);
        assert_eq!(pcb.next_user_stack_slot, 1);
    }

    #[test]
    fn pcb_defaults_to_zero_principal_and_no_pending_receive() {
        let pcb = make_pcb();
        assert_eq!(pcb.principal, KernelPrincipal::ZERO);
        assert_eq!(pcb.pending_receive, None);
    }

    #[test]
    fn pending_receive_holds_userspace_destination() {
        let mut pcb = make_pcb();
        pcb.pending_receive = Some(PendingReceive {
            channel: ChannelId(7),
            dst_ptr: 0x4000_4000,
            dst_cap: 256,
        });
        let pr = pcb.pending_receive.unwrap();
        assert_eq!(pr.channel, ChannelId(7));
        assert_eq!(pr.dst_ptr, 0x4000_4000);
        assert_eq!(pr.dst_cap, 256);
    }

    #[test]
    fn fresh_pcb_has_empty_mmio_table() {
        let pcb = make_pcb();
        assert!(pcb.mmio_mappings.is_empty());
        assert_eq!(pcb.mmio_va_cursor, 0);
    }

    #[test]
    fn mmio_mappings_round_trip() {
        let mut pcb = make_pcb();
        pcb.mmio_mappings.push(MmioMapping {
            va_base: 0x0000_0085_1234_0000,
            len_pages: 2,
        });
        pcb.mmio_va_cursor = 0x0000_0085_1234_2000;
        assert_eq!(pcb.mmio_mappings.len(), 1);
        let first = pcb.mmio_mappings.first().expect("one mapping pushed");
        assert_eq!(first.va_base, 0x0000_0085_1234_0000);
        assert_eq!(first.len_pages, 2);
        assert_eq!(pcb.mmio_va_cursor, 0x0000_0085_1234_2000);
    }

    #[test]
    fn fresh_pcb_has_empty_dma_and_irq_tables() {
        let pcb = make_pcb();
        assert!(pcb.dma_mappings.is_empty());
        assert!(pcb.irq_attachments.is_empty());
    }

    #[test]
    fn dma_mappings_round_trip() {
        let mut pcb = make_pcb();
        pcb.dma_mappings.push(DmaMapping {
            iova_base: 0x1_0000_0000,
            phys_base: 0x2_0000_0000,
            len_pages: 4,
            direction: 2,
        });
        assert_eq!(pcb.dma_mappings.len(), 1);
        let first = pcb.dma_mappings.first().expect("one DMA mapping pushed");
        assert_eq!(first.iova_base, 0x1_0000_0000);
        assert_eq!(first.phys_base, 0x2_0000_0000);
        assert_eq!(first.len_pages, 4);
        assert_eq!(first.direction, 2);
    }

    #[test]
    fn irq_attachments_round_trip() {
        let mut pcb = make_pcb();
        pcb.irq_attachments.push(IrqAttachment {
            irq_line: 33,
            vector: 0x40,
            channel_id: 7,
        });
        assert_eq!(pcb.irq_attachments.len(), 1);
        let first = pcb
            .irq_attachments
            .first()
            .expect("one IRQ attachment pushed");
        assert_eq!(first.irq_line, 33);
        assert_eq!(first.vector, 0x40);
        assert_eq!(first.channel_id, 7);
    }
}
