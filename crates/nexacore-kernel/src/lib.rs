//! # `nexacore-kernel`
//!
//! The NexaCore OS microkernel.
//!
//! Responsibilities (and only these):
//!
//! - Memory management (virtual memory, page tables, allocators)
//! - Process and thread scheduling
//! - Inter-process communication (typed message passing)
//! - Capability-based security primitives
//! - Hardware abstraction interfaces (HAL contracts)
//!
//! Everything else — filesystems, drivers, networking stacks, AI runtime —
//! runs as user-space services communicating via IPC. This minimizes the
//! Trusted Computing Base.
//!
//! ## Status
//!
//! Draft v0.2 — module surface and trait skeletons are landed for memory,
//! scheduling, IPC, capabilities, and syscall dispatch. The crate still
//! compiles in `std` mode by default; the `no_std + no_main` bare-metal
//! transition is gated behind the `bare-metal` feature, which switches
//! `lib.rs` (and every module) to `#![no_std]` and disables anything that
//! pulls in libstd. The transition to a real bare-metal binary lands in
//! P6.1–P6.2 per [`/ncips/ncip-kernel-003.md`](../../../ncips/ncip-kernel-003.md).
//!
//! ## Design rationale
//!
//! 1. **Microkernel**: smaller TCB → smaller attack surface. Faults in a
//!    service crash that service, not the kernel.
//! 2. **Rust + memory safety**: eliminates entire classes of vulnerabilities
//!    that plague C kernels (use-after-free, buffer overflows, data races).
//! 3. **Capability-based security**: the only way to act on a resource is
//!    to present a valid capability. No ambient authority, no superuser.
//! 4. **Message passing IPC**: typed, async-friendly, encryption-aware.
//! 5. **Verifiability over time**: a small kernel is amenable to formal
//!    methods (in line with seL4 prior art). Long-term goal: formal proofs
//!    for the IPC and capability subsystems.
//!
//! ## Modules
//!
//! - [`memory`] — virtual memory, page tables, allocators.
//! - [`scheduling`] — process and thread scheduling.
//! - [`ipc`] — inter-process communication primitives.
//! - [`capabilities`] — kernel-side capability validation and minting.
//! - [`syscall`] — system call dispatch.

#![doc(html_root_url = "https://docs.nexacore-os.org/nexacore-kernel")]
// `no_std` / `no_main` are only meaningful in non-test builds. Tests
// always require `std` (for the test harness) and a `main` (for the
// runner), so we suppress both attributes under `cfg(test)`. Under
// `cargo build --features bare-metal`, the kernel still compiles as
// `no_std + no_main` exactly as P6.1 requires.
#![cfg_attr(all(feature = "bare-metal", not(test)), no_std)]
#![cfg_attr(all(feature = "bare-metal", not(test)), no_main)]
#![deny(missing_docs)]
// `#[cfg(test)]` modules in this crate (arena fixtures in `paging.rs`,
// `elf_loader.rs`, and `memory.rs`) construct synthetic page tables and
// ELF blobs through `std::alloc::Layout`; the assertions themselves rely
// on `unwrap()` / `expect()` to fail the test deterministically when an
// invariant breaks. `clippy::unwrap_used`, `clippy::expect_used`,
// `clippy::panic`, and `clippy::doc_markdown` are silenced for test
// targets only — production code keeps them at workspace-level "warn".
// This `cfg_attr(test, allow(...))` is explicitly whitelisted by ADR-0003.
#![cfg_attr(
    test,
    allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::doc_markdown,
        // Test code in known_issuers uses direct indexing on a known-length static slice.
        clippy::indexing_slicing,
        // Test assertions in services/net use {:?} with a trailing arg instead of inline fmt.
        clippy::uninlined_format_args
    )
)]
// NOTE: per ADR-0003 (no blanket #![allow] in production crates), every
// `pedantic` / `nursery` / `cargo` / `unsafe_code` blanket previously
// suppressed at crate root has been lifted across Step 7.1–7.4. Each
// remaining intentional violation carries a localised
// `#[allow(<lint>, reason = "...")]` attribute at the offending item or
// — for widespread unsafe-density `bare_metal/` modules — at module level.

// `alloc` is available even in `no_std` mode (the bare-metal kernel
// provides its own allocator). In `std` builds, `alloc` is re-exported
// transparently.
extern crate alloc;

pub mod cap_deposit;
pub mod capabilities;
/// Capability forwarding — command → scope registry (T6.3).
///
/// When the NexaCore shell spawns a child command, it queries this registry
/// to determine the minimum capability scope the command requires and
/// attenuates the token accordingly (least-privilege forwarding).
///
/// Not gated behind `bare-metal`: the registry logic is fully testable
/// on host builds.
pub mod capability_forward;
/// Kernel console input ring buffer (T0.2).
pub mod console_input;
pub mod driver_cap_issuer;
pub mod driver_manifest;
/// WS2-16 — PCI device → driver-pack matching + hotplug auto-loader.
///
/// Not gated behind `bare-metal`: the class-aware match table, resolver, and
/// surprise add/remove model are pure `core + alloc` and host-testable; the
/// bare-metal bus walk feeds `driver_match::PciIdent`s in and acts on the
/// returned `driver_match::HotplugAction` via `DriverLoad`.
pub mod driver_match;
/// WS5-08.6 — kernel-side validation of encrypted SDK value types.
///
/// `EncryptedString`/`MaskedSSN`/`TokenizedEmail`/`AttestedHash` are marshalled
/// across the syscall boundary as a self-describing `NCEV` envelope. Not gated
/// behind `bare-metal`: the envelope ABI + fail-closed validator are pure
/// `core + alloc` and host-testable; the syscall dispatcher calls
/// [`encrypted_arg::validate_encrypted_arg`] before a handler sees the bytes.
pub mod encrypted_arg;
pub mod entropy;
/// Per-process file descriptor table (T0.1).
///
/// Ungated: the FD types are useful in host-side tests and in the
/// userspace syscall layer regardless of the `bare-metal` feature.
pub mod fd;
/// Init process wiring — default args and environment for PID 1 (T6.2).
///
/// Describes the boot sequence after initramfs is loaded: build
/// `InitProcessArgs` for `/bin/nexacore-shell` and pass them to the spawner
/// that creates PID 1.
///
/// Not gated behind `bare-metal`: fully testable on host builds.
pub mod init_process;
/// Initramfs flat archive parser and loader (T6.1).
///
/// Parses the `[name_len: u16][name][elf_len: u32][elf]` format and
/// writes each binary into [`vfs::InMemoryVfs`] under `/bin/<name>`.
///
/// Not gated behind `bare-metal`: fully testable on host builds.
pub mod initramfs;
/// WS2-08 — unified input event bus (PS/2 keyboard/mouse + ACPI power/lid/
/// brightness).
///
/// Pure scancode/notify normalizers and display-vs-power routing. Not gated
/// behind `bare-metal`: the normalizers and routing are pure `core` and
/// host-testable; the bare-metal pump / ACPI GPE handler call in.
pub mod input_bus;
pub mod ipc;
/// IRQ-to-IPC routing table (NCIP-013 § S4, P6.7 IRQ-attach wiring).
///
/// Provides [`irq_table::IrqTable`], [`irq_table::IrqBinding`], and
/// [`irq_table::IrqBindError`] — a fixed-size, `no_std`-compatible table
/// that maps hardware interrupt vectors to kernel IPC channels.
///
/// The `#[cfg(test)]` module inside `irq_table` is ungated so that host
/// builds can exercise the bind / unbind / lookup / mask / unmask logic
/// without the full `bare-metal` infrastructure. The kernel-global singletons
/// (`IRQ_TABLE_GLOBAL`, `irq_notify`, `global_bind`, `global_unbind`) are
/// gated behind `bare-metal + target_os = none`.
pub mod irq_table;
pub mod kaslr;
/// WS1-11 — MP kernel-half aliasing hardening (ADR-0004 Alt B → shared-immutable).
///
/// Not gated behind `bare-metal`: the snapshot/verify logic and the MP aliasing
/// model are pure `core` and host-testable; the bare-metal kernel calls
/// [`kernel_half::plan_kernel_map`] as the mutation chokepoint and
/// [`kernel_half::KernelHalfSnapshot::matches_pml4`] to assert the invariant.
pub mod kernel_half;
pub mod known_issuers;
pub mod memory;
/// `/proc`-class metrics & introspection surface (WS12-04).
///
/// Not gated behind `bare-metal`: the schemas, collection logic, and the
/// `/proc` virtual-FS rendering are pure `core + alloc` and host-testable; the
/// bare-metal kernel supplies only the [`metrics::ResourceAccounting`] counters.
pub mod metrics;
pub mod mm;
/// Kernel pipe — unidirectional byte streams (T0.3).
pub mod pipe;
#[cfg(feature = "bare-metal")]
pub mod process;
/// Kernel process table — parent-child tracking and wait/exit bookkeeping (T0.5).
///
/// Not gated behind `bare-metal`: the wait/exit logic is testable on host
/// builds without the full page-table / ELF-loader infrastructure.
pub mod process_table;
pub mod scheduling;
/// WS3-06 — swap format, swap-out/in, zram backend, and victim selection.
pub mod swap;
/// WS1-10 — thermal- and workload-aware scheduling policy layered over the
/// ADR-0025 fairness rotation.
pub mod thermal;
// `services` hosts kernel-side bookkeeping for the well-known
// `nexacore.svc.<kind>.<slot>` IPC-channel namespaces surfaced by user-space
// service drivers (BLK registry as of P6.7.10-pre.2; future NET, GPU, …).
// Gated behind `bare-metal` to match the NCIP-Driver-NVMe-014 § S4 acceptance
// scope — the registry is consumed by the (bare-metal) driver framework
// and has no host-side caller outside the unit tests.
#[cfg(feature = "bare-metal")]
pub mod services;
pub mod syscall;
/// Testable syscall handler logic — bridges userspace syscalls to kernel
/// data structures without requiring the `bare-metal` feature.
///
/// Each `handle_*` method on [`syscall_handlers::KernelState`] corresponds
/// to one syscall number defined in [`syscall::SyscallNumber`]. The bare-metal
/// entry path constructs a `KernelState` view and calls the appropriate
/// handler; host-side tests use [`syscall_handlers::KernelState::new_for_test`].
pub mod syscall_handlers;
/// System V AMD64 ABI stack argument layout builder (T6.4 / user_stack_args).
///
/// Builds the `argc` / `argv[]` / `envp[]` in-memory image that the kernel
/// writes to the top of a new process's user stack before transferring
/// control to `_start`. Fully testable on host builds — not gated behind
/// `bare-metal`.
pub mod user_stack_args;
/// Virtual filesystem layer — in-memory Phase 1 backing store.
///
/// Provides [`vfs::InMemoryVfs`], the kernel-internal filesystem abstraction
/// used by the filesystem syscall handlers (`FsOpen`, `FsStat`, `FsListDir`,
/// `FsCreate`, `FsDelete`, `FsMkdir`). Phase 2 will replace the in-memory
/// implementation with an IPC proxy to the `nexacore-fs` userspace service.
///
/// Ungated: host-side test builds need access to the VFS types without the
/// full `bare-metal` infrastructure.
pub mod vfs;

// Bare-metal runtime: panic handler, global allocator, early console,
// arch intrinsics. Lives only when the `bare-metal` feature is on; the
// inner `#[panic_handler]` and `#[global_allocator]` items are further
// gated `not(test)` to keep `cargo test --all-features` compilable.
//
// Specified by NCIP-Kernel-012 (was NCIP-Kernel-004 — renumbered at
// Draft → Review on 2026-05-14 per NCIP-Process-001 §8.3 to free the
// "004" integer for the canonical NCIP-Serde-004).
#[cfg(feature = "bare-metal")]
pub mod bare_metal;

// -----------------------------------------------------------------------------
// Kernel-wide error type
// -----------------------------------------------------------------------------

/// Kernel-side error discriminant.
///
/// Kept deliberately small and PII-safe. Userspace receives errors in
/// `nexacore_types::NexaCoreError` form via the syscall ABI; this enum is the
/// kernel's internal representation, mapped at the syscall boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum KernelError {
    /// The operation is not yet implemented in this kernel build.
    /// Returned by every scaffold method until its corresponding P6 task
    /// lands.
    NotYetImplemented,
    /// A capability check failed. The caller did not present a valid
    /// capability for the requested operation.
    CapabilityDenied,
    /// A resource is exhausted (out of memory, no free thread slots, IPC
    /// queue full, etc.).
    ResourceExhausted,
    /// Invalid argument from userspace. The syscall layer is supposed to
    /// catch most of these; this variant is for the edge cases the
    /// syscall layer cannot validate without context.
    InvalidArgument,
    /// Internal invariant violation. Indicates a kernel bug.
    Internal,
}

// -----------------------------------------------------------------------------
// Kernel-wide result alias
// -----------------------------------------------------------------------------

/// Standard `Result` type for kernel operations.
pub type KernelResult<T> = Result<T, KernelError>;

// -----------------------------------------------------------------------------
// kmain — kernel main entry, invoked from kernel-runner::kernel_entry
// after BumpHeap::init.
//
// NCIP-Kernel-005 § S3. K4 scope is intentionally minimal: print a
// banner (visible signature of successful boot), record the boot_info
// pointer + memory map size, halt forever. Subsystem init order
// (arch::init, memory::init, scheduling::init, ipc::init,
// capabilities::init) lands in K6+.
// -----------------------------------------------------------------------------

// Physical frame allocator — 4 GiB capacity (16 384 words × 64 bits × 4 KiB).
// All frames start used; kmain calls mark_range_free for each Usable region.
// Safety invariant: single-CPU / no-preemption throughout bare-metal P6 scope.
// Must be wrapped in a spinlock when SMP lands (P6.4+).
/// Capacity of the global frame allocator, in u64 bitmap words.
///
/// 16 384 words × 64 bits/word × 4 KiB/frame = 4 GiB of trackable RAM.
/// Bumping this raises the static-memory footprint linearly.
#[cfg(all(feature = "bare-metal", target_os = "none", not(test)))]
const FRAME_BITMAP_WORDS: usize = 16384;

#[cfg(all(feature = "bare-metal", target_os = "none", not(test)))]
static mut FRAME_ALLOC: memory::BitmapFrameAllocator<{ FRAME_BITMAP_WORDS }> =
    memory::BitmapFrameAllocator::new(memory::PhysAddr(0));

// Cooperative round-robin scheduler — MB6.
// Single-CPU, non-preemptive. Same safety invariant as FRAME_ALLOC.
#[cfg(all(feature = "bare-metal", target_os = "none", not(test)))]
static mut SCHEDULER: scheduling::RoundRobinScheduler = scheduling::RoundRobinScheduler::new();

// Shell terminal support — global instances for the syscall handlers.
//
// None of these types expose a `const fn new()` (they all heap-allocate
// internally via `BTreeMap` / `VecDeque`), so they cannot be placed in a
// `static mut T = T::new()` directly. Instead each is wrapped in
// `Option<T>` initialised to `None` and lazily populated in `kmain` before
// the first userspace task is scheduled. The same single-CPU, no-preemption
// safety invariant that covers `FRAME_ALLOC` and `SCHEDULER` applies here:
// P6 is single-core and interrupts are disabled across syscall dispatch.
#[cfg(all(feature = "bare-metal", target_os = "none", not(test)))]
static mut SHELL_FD_TABLE: Option<fd::FileDescriptorTable> = None;
#[cfg(all(feature = "bare-metal", target_os = "none", not(test)))]
static mut SHELL_PIPE_REGISTRY: Option<pipe::PipeRegistry> = None;
#[cfg(all(feature = "bare-metal", target_os = "none", not(test)))]
static mut SHELL_CONSOLE_INPUT: Option<console_input::ConsoleInputBuffer> = None;
#[cfg(all(feature = "bare-metal", target_os = "none", not(test)))]
static mut SHELL_PROCESS_TABLE: Option<process_table::ProcessTable> = None;
#[cfg(all(feature = "bare-metal", target_os = "none", not(test)))]
static mut SHELL_VFS: Option<vfs::InMemoryVfs> = None;

// MB14.g — the per-CPU tick counter previously lived here as a single
// `pub static mut TICK_COUNT: u64 = 0;` global, written only by the LAPIC
// timer ISR on the BSP. Once APs began servicing their own timers
// (MB14.f) keeping the global meant either racing the AP writers or
// gating them out via `current_cpu().is_bsp()`. MB14.g moves the counter
// into `PerCpu::tick_count` (one atomic per logical CPU) — see
// `bare_metal::per_cpu::PerCpu::inc_tick`. No external readers of the
// old symbol existed at the time of removal (grep `crate::TICK_COUNT`).

// Idle task — lowest-priority loop; runs when no other task is runnable.
#[cfg(all(feature = "bare-metal", target_os = "none", not(test)))]
fn idle_task() -> ! {
    loop {
        // SAFETY: bare-metal ring-0; hlt suspends the CPU until the next
        // interrupt (none enabled in MB6, so this effectively halts forever
        // unless a future milestone enables the LAPIC timer).
        #[allow(unsafe_code, reason = "bare-metal ring-0 hlt; SAFETY comment above")]
        unsafe {
            core::arch::asm!("hlt", options(nomem, nostack, preserves_flags));
        }
    }
}

/// Registers each `Usable` region of the bootloader memory map with the
/// frame allocator, but only after verifying that the region is reachable
/// through the active direct-map at `phys_offset`. A region is included
/// only if both its first and last 4 KiB page translate cleanly via
/// `pager.translate`; otherwise it is skipped entirely.
///
/// Returns `(validated_bytes, skipped_bytes)` — both sums of the raw
/// region sizes, regardless of any subsequent `mark_range_used` reserve.
///
/// This is the MB9 invariant enforcer: every frame the allocator hands
/// out can be written via `phys + phys_offset` without faulting.
#[cfg(all(feature = "bare-metal", target_os = "none", not(test)))]
fn register_direct_mapped_regions(
    alloc: &mut memory::BitmapFrameAllocator<{ FRAME_BITMAP_WORDS }>,
    pager: &bare_metal::paging::PageMapper,
    phys_offset: u64,
    boot_info: &bootloader_api::BootInfo,
) -> (u64, u64) {
    use bootloader_api::info::MemoryRegionKind;

    let mut validated: u64 = 0;
    let mut skipped: u64 = 0;

    for region in boot_info.memory_regions.iter() {
        if region.kind != MemoryRegionKind::Usable {
            continue;
        }
        let size = region.end.saturating_sub(region.start);
        if size == 0 {
            continue;
        }

        // Last page boundary inside the region: align (end - 1) down to 4 KiB.
        let last_page_start = (region.end - 1) & !0xFFF;

        let start_v = memory::VirtAddr(phys_offset.wrapping_add(region.start));
        let last_v = memory::VirtAddr(phys_offset.wrapping_add(last_page_start));

        if pager.translate(start_v).is_some() && pager.translate(last_v).is_some() {
            alloc.mark_range_free(memory::PhysAddr(region.start), size);
            validated += size;
        } else {
            skipped += size;
        }
    }

    (validated, skipped)
}

/// Kernel main — invoked from the runner's `kernel_entry` after the
/// global heap has been initialised.
///
/// At K4/K5 the function:
///
/// 1. Installs the kernel GDT (replaces the bootloader's temporary GDT).
/// 2. Initialises the `BitmapFrameAllocator` from the bootloader memory map.
/// 3. Prints the canonical banner over the early console — five lines required
///    by the K5 QEMU smoke test.
/// 4. Renders a full graphical boot banner on the GOP framebuffer (UEFI path);
///    falls back to VGA text mode when no framebuffer is available.
/// 5. Runs the 5-minute desktop demo, then issues ACPI S5 power-off.
///
/// # Signature stability
///
/// Per `NCIP-Kernel-005` § S3 the first parameter (`boot_info`) is stable
/// for v1.0. The second parameter (`framebuffer`) is an additive extension
/// permitted by NCIP-Kernel-005 § S3 note.
#[cfg(all(feature = "bare-metal", target_os = "none", not(test)))]
// `mb8-smoke` short-circuits kmain via `mb8_smoke::run() -> !`, which makes
// the desktop demo + power-off tail unreachable (and `framebuffer` unused).
// Both are intended under that feature.
#[cfg_attr(feature = "mb8-smoke", allow(unreachable_code, unused_variables))]
#[allow(
    clippy::too_many_lines,
    reason = "kmain is the boot orchestrator; subsystem init must stay in single flow"
)]
#[allow(
    clippy::cognitive_complexity,
    reason = "kmain inlines every subsystem init for single-flow boot ordering; an extraction would obscure the deterministic init sequence the orchestrator must enforce"
)]
pub fn kmain(
    boot_info: &'static bootloader_api::BootInfo,
    framebuffer: Option<bare_metal::graphics::FrameBuffer>,
) -> ! {
    use bare_metal::{arch, demo, early_console, gdt, idt, paging, tss};

    // -------------------------------------------------------------------------
    // GDT: install kernel-controlled segment descriptors (replaces bootloader's
    // temporary GDT). Must be the first action after entering kmain.
    // -------------------------------------------------------------------------
    gdt::gdt_init();

    // -------------------------------------------------------------------------
    // TSS init (MB13.h): populate `TSS.ist1` / `TSS.ist2` with the static
    // IST stack tops, then issue `ltr 0x28` so the CPU's task register
    // points at the static TSS. Without `ltr`, a Ring 3 → Ring 0
    // transition cannot resolve `TSS.rsp0` and cascades silently to a
    // triple fault — the MB13.f post-iretq stall root cause.
    //
    // Must run after `gdt::gdt_init` (which writes the TSS descriptor at
    // slots 5+6) and before `idt::idt_init` (whose #DF / #PF entries
    // reference IST=1 / IST=2 respectively).
    // -------------------------------------------------------------------------
    tss::init_ist_stacks();
    tss::ltr_load();

    // -------------------------------------------------------------------------
    // IDT: load the kernel Interrupt Descriptor Table so that synchronous
    // exceptions (#DE, #DF, #GP, #PF) are caught before they triple-fault.
    // `sti` is NOT issued — interrupts remain disabled throughout the demo.
    // -------------------------------------------------------------------------
    idt::idt_init();

    // -------------------------------------------------------------------------
    // Syscall dispatcher (MB4): configure MSR_LSTAR / MSR_STAR / MSR_FMASK
    // and register INT 0x80 as the compatibility entry vector.
    // -------------------------------------------------------------------------
    bare_metal::syscall_entry::syscall_init();

    // -------------------------------------------------------------------------
    // Baseline CPU hardening (NCIP-Kernel-Sec-026 §S4, WI-4a): enable SMEP +
    // UMIP on the BSP if CPUID reports them. Must run before any Ring-3 task is
    // dispatched. Probe-and-degrade: absent features are skipped.
    let _cpu_baseline = bare_metal::cpu_features::enable_baseline();

    // SMAP (WI-4b): all kernel→user accesses now route through bare_metal::uaccess
    // and IA32_FMASK clears RFLAGS.AC on syscall entry, so SMAP can be enforced.
    // Runs before any user spawn; boot-time user-page writes (ELF load, cap
    // deposit) go via the supervisor direct map, which SMAP does not restrict.
    let _smap_on = bare_metal::cpu_features::enable_smap();

    // -------------------------------------------------------------------------
    // Kernel capability-issuer key (NCIP-Kernel-Sec-026 §S7, WI-6, R1): install a
    // per-boot SECRET signing seed (TEE-derived when a confidential root exists,
    // otherwise hardware entropy) in place of the public CAFEBABE dev constant,
    // and register its public half as the sole trusted capability issuer. Must
    // run BEFORE any driver is spawned/deposited (below): the deposited cap
    // tokens are signed with this key and the mmio/dma/irq path authorises only
    // this issuer, so a token signed with any other key — including the public
    // placeholder — is now rejected.
    let issuer_src = crate::driver_cap_issuer::init_issuer_seed();
    crate::known_issuers::register_kernel_cap_issuer(
        crate::driver_cap_issuer::kernel_issuer_pubkey(),
    );
    early_console::write_str(match issuer_src {
        crate::driver_cap_issuer::IssuerSeedSource::Tee => "[cap] issuer-seed=tee\n",
        crate::driver_cap_issuer::IssuerSeedSource::HwEntropy => "[cap] issuer-seed=hw-entropy\n",
    });

    let region_count = boot_info.memory_regions.iter().count();

    // -------------------------------------------------------------------------
    // Serial output — exact strings required by the K5 smoke-test assertions.
    // Do not rename or reorder these five lines.
    // -------------------------------------------------------------------------
    early_console::write_str("\n[NexaCore OS] kmain entered.\n");
    early_console::write_str("[NexaCore OS] kernel version: ");
    early_console::write_str(env!("CARGO_PKG_VERSION"));
    early_console::write_str("\n[NexaCore OS] memory regions: ");
    early_console::write_usize(region_count);
    early_console::write_str("\n[NexaCore OS] halting (K4 scope ends here).\n");

    // -------------------------------------------------------------------------
    // Page-table mapper (MB2): read current CR3, initialise the walker using
    // the bootloader's direct-map offset. Does not write CR3 — the bootloader
    // page tables remain active; the mapper only adds / walks them.
    //
    // Built BEFORE the frame allocator is filled so that we can validate each
    // Usable region against the active direct-map (MB9). `bootloader 0.11`
    // installs the direct-map via huge pages; `PageMapper::translate` is
    // huge-page aware and resolves those entries correctly.
    // -------------------------------------------------------------------------
    let phys_offset_mb2 = boot_info.physical_memory_offset.into_option().unwrap_or(0);
    // P6.7.8.1 — publish the bootloader direct-map offset to the
    // bare-metal global so the driver-framework syscall handlers
    // (`MmioMap`) can rebuild a `PageMapper` without threading the
    // value through the syscall trampoline. Single-shot write at boot.
    bare_metal::set_phys_offset(phys_offset_mb2);
    let cr3_raw = arch::read_cr3();
    // P6.7.8.8 — publish the boot PML4 physical base so the
    // `DriverLoad (73)` syscall handler can clone the kernel-half into
    // the new driver process's address space without depending on the
    // calling process's CR3 (loader != kernel image).
    bare_metal::set_boot_cr3(cr3_raw);

    // P6.7.9-pre.1 — IOMMU probe.
    //
    // Walks the firmware-supplied RSDP for DMAR (Intel VT-d) and IVRS
    // (AMD-Vi). Selects the right vendor or falls back to Phase 1
    // passthrough mode when no IOMMU is advertised. The selector
    // result is stashed in `bare_metal::iommu::IOMMU_VENDOR` so the
    // upcoming `DmaMap` rewire (P6.7.9-pre.2) can dispatch without an
    // additional ACPI walk.
    //
    // The walk is best-effort: if `BootInfo.rsdp_addr` is `None` (no
    // UEFI RSDP — extremely unusual on the configurations we boot)
    // or any table dereference fails, the global stays at the safe
    // Passthrough default. The `[iommu] vendor=…` log line is the
    // smoke surface emitted regardless of outcome.
    {
        use bare_metal::iommu;
        let rsdp = boot_info.rsdp_addr.into_option();
        // SAFETY: same invariants the FADT walker depends on
        // (firmware-mapped physical-memory window covers the RSDP and
        // the entire RSDT/XSDT chain). The boot pipeline has already
        // validated `physical_memory_offset` via `set_phys_offset`
        // above. When `rsdp` is `None` the closure is never invoked
        // and the safe `PASSTHROUGH` fallback is returned.
        #[allow(
            unsafe_code,
            reason = "ACPI table walk requires dereferencing firmware-supplied physical addresses; same shape as mp::enumerate_cpus"
        )]
        let probe = rsdp.map_or(iommu::ProbeResult::PASSTHROUGH, |rsdp_phys| unsafe {
            iommu::probe(rsdp_phys, phys_offset_mb2)
        });
        // Stash the result so the safe-default global covers the
        // RSDP-missing case too (the bare-metal probe writer is gated
        // on `rsdp.is_some()`).
        iommu::set_iommu_vendor(probe.vendor);
        let unit_count = match probe.vendor {
            iommu::IommuVendor::Intel => probe.drhd_count,
            iommu::IommuVendor::Amd => probe.ivhd_count,
            iommu::IommuVendor::Passthrough => 0,
        };
        iommu::set_iommu_unit_count(unit_count);

        // P6.7.9-pre.4 — swap the kernel-wide IOMMU backend in line
        // with the vendor the firmware advertised. From this point
        // onward `dma_map_handlers::dma_map` routes domain installs +
        // mappings + flushes through the vendor-specific scaffold
        // (VtdBackend / AmdViBackend) instead of the passthrough
        // default. Live MMIO register programming is deferred to
        // P6.7.9-pre.5+ — the scaffolds keep accounting in `Vec`s.
        iommu::install_backend_for_vendor(probe.vendor);

        early_console::write_str("[iommu] vendor=");
        early_console::write_str(probe.vendor.label());
        early_console::write_str(" units=");
        early_console::write_usize(unit_count);
        early_console::write_str("\n");
    }
    // `mut` because MB10's `spawn_kernel_task` will call `pager.map_4k` to
    // map each task's kernel stack into the isolated VA range.
    let mut pager = paging::PageMapper::new(phys_offset_mb2, memory::PhysAddr(cr3_raw & !0xFFF));
    early_console::write_str("[paging] mapper ready  CR3=");
    #[allow(
        clippy::cast_possible_truncation,
        reason = "x86_64 only; usize is u64 on target_os = none x86_64-unknown-none"
    )]
    early_console::write_usize((cr3_raw & !0xFFF) as usize);
    early_console::write_str("\n");

    // -------------------------------------------------------------------------
    // Framebuffer physical address resolution (ADR-0040 D1, TASK-18, DE-C1).
    //
    // The bootloader hands off the framebuffer as a VA pointer only.  We walk
    // the active page tables once NOW (pager is live, before any Ring-3 task is
    // dispatched) to resolve the physical base so the DisplayMap handler can
    // mint a correctly-scoped capability without trusting any user argument for
    // the phys address. If the framebuffer is absent or the walk fails we log
    // it and leave `framebuffer_info()` returning `None` — DisplayMap returns
    // EINVAL in that case.
    // -------------------------------------------------------------------------
    #[cfg(all(feature = "bare-metal", target_os = "none", not(test)))]
    #[allow(
        unsafe_code,
        reason = "set_framebuffer_info is unsafe: single-CPU at-most-once write; same invariant \
                  as other boot-time global stores (FRAME_ALLOC, SCHEDULER, PHYS_OFFSET)"
    )]
    if let Some(ref fb) = framebuffer {
        // Walk the page table to convert the framebuffer VA → phys.
        // `fb.ptr()` is the kernel VA mapped by the bootloader.
        let fb_va = memory::VirtAddr(fb.ptr() as u64);
        if let Some(phys) = pager.translate(fb_va) {
            // len = height * stride * bpp (stride in pixels per the FrameBuffer doc).
            let raw_len = u64::from(fb.height)
                .saturating_mul(u64::from(fb.stride()))
                .saturating_mul(u64::from(fb.bytes_per_px()));
            // Round up to next 4 KiB page boundary.
            let page_len = (raw_len + 0xFFF) & !0xFFF;
            let info = bare_metal::graphics::FramebufferInfo {
                phys_base: phys.0,
                len: page_len,
                width: fb.width,
                height: fb.height,
                stride: fb.stride(),
                bpp: fb.bytes_per_px(),
            };
            // SAFETY: single-CPU boot path; this executes before any Ring-3
            // task is scheduled, so no concurrent read of FRAMEBUFFER_INFO
            // is possible.
            unsafe { bare_metal::graphics::set_framebuffer_info(info) };
            early_console::write_str("[fb] phys_base=");
            #[allow(
                clippy::cast_possible_truncation,
                reason = "splitting u64 into two u32 halves for hex display"
            )]
            {
                bare_metal::early_console::write_usize((phys.0 >> 32) as usize);
                bare_metal::early_console::write_usize((phys.0 & 0xFFFF_FFFF) as usize);
            }
            early_console::write_str(" len=");
            #[allow(
                clippy::cast_possible_truncation,
                reason = "page_len fits usize on x86_64"
            )]
            early_console::write_usize(page_len as usize);
            early_console::write_str("\n");
        } else {
            early_console::write_str("[fb] phys walk FAILED — DisplayMap unavailable\n");
        }
    } else {
        early_console::write_str("[fb] no framebuffer — DisplayMap unavailable\n");
    }

    // -------------------------------------------------------------------------
    // Physical memory map (MB1 + MB9): register Usable regions with the frame
    // allocator, but only those covered by the bootloader's direct-map. A
    // region whose start or last page does not translate is skipped wholesale,
    // guaranteeing every `alloc_frame()` returns a frame writable through
    // `phys + phys_offset` without faulting.
    //
    // Use addr_of_mut! to avoid the Rust-2024 static_mut_refs lint while
    // keeping the single-core safety invariant explicit.
    // -------------------------------------------------------------------------
    // SAFETY: single-core bare-metal, FRAME_ALLOC is not aliased anywhere.
    #[allow(
        unsafe_code,
        reason = "single-core bare-metal aliasing invariant; SAFETY comment above"
    )]
    let alloc = unsafe { &mut *core::ptr::addr_of_mut!(FRAME_ALLOC) };
    let (validated_bytes, skipped_bytes) =
        register_direct_mapped_regions(alloc, &pager, phys_offset_mb2, boot_info);

    // Reserve the low 1 MiB. Independent of the direct-map check: the BIOS
    // area (real-mode IVT, BIOS data, EBDA, video memory) is not safe for
    // kernel storage even where firmware reports it as Usable and the
    // bootloader maps it.
    alloc.mark_range_used(memory::PhysAddr(0), 0x10_0000);

    // Reserve the kernel heap arena. `register_direct_mapped_regions` marks
    // EVERY Usable region free — including the one the runner already handed
    // to `BumpHeap::init` (it is tagged Usable in the same memory map). Left
    // free, the frame allocator would hand heap-backed frames out for page
    // tables and user stacks; once the bump pointer grew into such a frame the
    // two allocators would corrupt each other (root cause of the M0
    // cross-process user-stack #PF, 2026-06-03). `pick_region` is deterministic
    // (same memory map → same `(base, len)`) and returns the SAME capped arena
    // the runner installed, so reserving `[base, base + len)` here marks
    // exactly the heap's bytes used while leaving the rest of the region free.
    #[cfg(all(feature = "bare-metal", target_os = "none", not(test)))]
    {
        let (heap_base_ptr, heap_len) = bare_metal::heap::pick_region(&boot_info.memory_regions);
        alloc.mark_range_used(memory::PhysAddr(heap_base_ptr as u64), heap_len as u64);
        early_console::write_str("[mem] heap arena reserved base=");
        early_console::write_usize(heap_base_ptr as usize);
        early_console::write_str(" len=");
        early_console::write_usize(heap_len);
        early_console::write_str("\n");
    }

    #[allow(
        clippy::cast_possible_truncation,
        clippy::integer_division,
        reason = "MiB value always fits u32; truncation to whole MiB is intentional"
    )]
    let free_mib = (alloc.free_bytes() / (1024 * 1024)) as u32;
    #[allow(
        clippy::cast_possible_truncation,
        clippy::integer_division,
        reason = "MiB value always fits u32; truncation to whole MiB is intentional"
    )]
    let total_mib = (alloc.total_bytes() / (1024 * 1024)) as u32;
    #[allow(
        clippy::cast_possible_truncation,
        clippy::integer_division,
        reason = "MiB value always fits u32; truncation to whole MiB is intentional"
    )]
    let validated_mib = (validated_bytes / (1024 * 1024)) as u32;
    #[allow(
        clippy::cast_possible_truncation,
        clippy::integer_division,
        reason = "MiB value always fits u32; truncation to whole MiB is intentional"
    )]
    let skipped_mib = (skipped_bytes / (1024 * 1024)) as u32;

    // -------------------------------------------------------------------------
    // Serial memory diagnostic — informational, after K5 lines.
    // -------------------------------------------------------------------------
    early_console::write_str("[mem] ");
    early_console::write_usize(free_mib as usize);
    early_console::write_str(" MiB free / ");
    early_console::write_usize(total_mib as usize);
    early_console::write_str(" MiB total\n");
    early_console::write_str("[paging] validated ");
    early_console::write_usize(validated_mib as usize);
    early_console::write_str(" MiB direct-mapped, skipped ");
    early_console::write_usize(skipped_mib as usize);
    early_console::write_str(" MiB unmapped\n");
    early_console::write_str("[idt] loaded  vectors=#DE #DF #GP #PF\n");
    early_console::write_str("[syscall] LSTAR set  INT80=0x80\n");
    early_console::write_str("[build] shell-infra=pending (init deferred to post-sched)\n");

    // -------------------------------------------------------------------------
    // P6.7.9-pre.5 — Intel VT-d live MMIO programming.
    //
    // Allocate the root-table + invalidation-queue frames from the now-
    // initialised FRAME_ALLOC, zero them via the direct map, publish
    // their physical addresses + the firmware-reported unit base to the
    // live `IommuKind::Intel` backend, then drive the activation
    // sequence (RTADDR + GCMD.SRTP + IQA + GCMD.QIE + global IOTLB
    // invalidate). The block is a no-op on AMD / passthrough platforms.
    //
    // `GCMD.TE` is **NOT** raised here; per-domain translation gating
    // lands once the driver framework attaches its first PCI device.
    // Until then the IOMMU stays in pre-translation pass-through at the
    // hardware level — same observable behaviour as before the slice.
    //
    // SAFETY: single-core BSP context; FRAME_ALLOC and IOMMU_BACKEND
    // are not concurrently accessed. `phys_offset_mb2` is the live
    // direct-map offset (set above via `set_phys_offset`). Activation
    // writes go through `core::ptr::write_volatile` against the per-IOMMU
    // MMIO window, which is part of the firmware-mapped direct-map
    // region for q35/Proxmox configurations.
    #[cfg(all(target_arch = "x86_64", target_os = "none"))]
    #[allow(
        unsafe_code,
        reason = "single-core static-mut deref + MMIO volatile writes inside the IOMMU activation path; aliasing invariant in SAFETY comment"
    )]
    if bare_metal::iommu::iommu_unit_base() != 0
        && bare_metal::iommu::iommu_vendor() == bare_metal::iommu::IommuVendor::Intel
    {
        unsafe {
            let fa = &mut *core::ptr::addr_of_mut!(FRAME_ALLOC);
            // Allocate + zero the root-table frame.
            let root_table_phys = fa.alloc_frame().map_or(0, |p| p.0);
            // Allocate + zero the invalidation-queue frame.
            let invalidation_queue_phys = fa.alloc_frame().map_or(0, |p| p.0);
            if root_table_phys != 0 && invalidation_queue_phys != 0 {
                // Zero-fill via the bootloader direct map. 4 KiB per
                // frame.
                let root_va = phys_offset_mb2.wrapping_add(root_table_phys) as *mut u8;
                let iq_va = phys_offset_mb2.wrapping_add(invalidation_queue_phys) as *mut u8;
                core::ptr::write_bytes(root_va, 0u8, 4096);
                core::ptr::write_bytes(iq_va, 0u8, 4096);

                let unit_base = bare_metal::iommu::iommu_unit_base();
                if bare_metal::iommu::prepare_vt_d_unit(
                    unit_base,
                    root_table_phys,
                    invalidation_queue_phys,
                )
                .is_ok()
                {
                    match bare_metal::iommu::activate_intel_vt_d(phys_offset_mb2) {
                        Ok(true) => {
                            early_console::write_str("[iommu] vt-d activated  unit=");
                            #[allow(
                                clippy::cast_possible_truncation,
                                reason = "MMIO base fits 32 bits on x86_64; truncation only affects the log readback, not the live address"
                            )]
                            early_console::write_usize(unit_base as usize);
                            early_console::write_str("\n");
                            // WI-7b — log the hardware-advertised AGAW so the
                            // upcoming per-device confinement uses the right
                            // SLPT level count (CAP.SAGAW, read at activation).
                            early_console::write_str("[iommu] sagaw=");
                            early_console::write_usize(usize::from(
                                bare_metal::iommu::iommu_supported_sagaw(),
                            ));
                            early_console::write_str(" levels=");
                            let lv = bare_metal::iommu::iommu_supported_address_width()
                                .map_or(0, |aw| usize::from(aw.levels()));
                            early_console::write_usize(lv);
                            early_console::write_str("\n");
                        }
                        Ok(false) => {
                            early_console::write_str("[iommu] vt-d activate skip\n");
                        }
                        Err(_) => {
                            early_console::write_str("[iommu] vt-d activate err\n");
                        }
                    }
                } else {
                    early_console::write_str("[iommu] vt-d prepare err\n");
                }
            } else {
                early_console::write_str("[iommu] vt-d alloc err\n");
            }
        }
    }

    // -------------------------------------------------------------------------
    // P6.7.9-pre.6 — AMD-Vi live MMIO programming.
    //
    // Symmetric to the VT-d block above: allocate the device-table,
    // command-buffer, and event-log frames from FRAME_ALLOC, zero them
    // via the direct map, publish their physical addresses + the
    // firmware-reported IVHD base to the live `IommuKind::Amd` backend,
    // then drive the activation sequence (DEV_TAB_BAR + CMD_BUF_BASE +
    // EVENT_LOG_BASE + CTRL.CmdBufEn|EventLogEn + INVALIDATE_DEVTAB
    // pump). The block is a no-op on Intel / passthrough platforms.
    //
    // `CTRL.IommuEn` is **NOT** raised here; per-device translation
    // gating lands once the driver framework attaches its first PCI
    // device. Until then the IOMMU stays in pre-translation
    // pass-through at the hardware level — same observable behaviour
    // as before the slice.
    //
    // SAFETY: single-core BSP context; FRAME_ALLOC and IOMMU_BACKEND
    // are not concurrently accessed. `phys_offset_mb2` is the live
    // direct-map offset (set above via `set_phys_offset`). Activation
    // writes go through `core::ptr::write_volatile` against the
    // per-IOMMU MMIO window, which is part of the firmware-mapped
    // direct-map region for q35/Proxmox configurations.
    #[cfg(all(target_arch = "x86_64", target_os = "none"))]
    #[allow(
        unsafe_code,
        reason = "single-core static-mut deref + MMIO volatile writes inside the AMD-Vi activation path; aliasing invariant in SAFETY comment"
    )]
    if bare_metal::iommu::iommu_unit_base() != 0
        && bare_metal::iommu::iommu_vendor() == bare_metal::iommu::IommuVendor::Amd
    {
        unsafe {
            let fa = &mut *core::ptr::addr_of_mut!(FRAME_ALLOC);
            let device_table_phys = fa.alloc_frame().map_or(0, |p| p.0);
            let command_buffer_phys = fa.alloc_frame().map_or(0, |p| p.0);
            let event_log_phys = fa.alloc_frame().map_or(0, |p| p.0);
            if device_table_phys != 0 && command_buffer_phys != 0 && event_log_phys != 0 {
                let dt_va = phys_offset_mb2.wrapping_add(device_table_phys) as *mut u8;
                let cb_va = phys_offset_mb2.wrapping_add(command_buffer_phys) as *mut u8;
                let el_va = phys_offset_mb2.wrapping_add(event_log_phys) as *mut u8;
                core::ptr::write_bytes(dt_va, 0u8, 4096);
                core::ptr::write_bytes(cb_va, 0u8, 4096);
                core::ptr::write_bytes(el_va, 0u8, 4096);

                let unit_base = bare_metal::iommu::iommu_unit_base();
                if bare_metal::iommu::prepare_amd_vi_unit(
                    unit_base,
                    device_table_phys,
                    command_buffer_phys,
                    event_log_phys,
                )
                .is_ok()
                {
                    match bare_metal::iommu::activate_amd_vi(phys_offset_mb2) {
                        Ok(true) => {
                            early_console::write_str("[iommu] amd-vi activated  unit=");
                            #[allow(
                                clippy::cast_possible_truncation,
                                reason = "MMIO base fits 32 bits on x86_64; truncation only affects the log readback, not the live address"
                            )]
                            early_console::write_usize(unit_base as usize);
                            early_console::write_str("\n");
                        }
                        Ok(false) => {
                            early_console::write_str("[iommu] amd-vi activate skip\n");
                        }
                        Err(_) => {
                            early_console::write_str("[iommu] amd-vi activate err\n");
                        }
                    }
                } else {
                    early_console::write_str("[iommu] amd-vi prepare err\n");
                }
            } else {
                early_console::write_str("[iommu] amd-vi alloc err\n");
            }
        }
    }

    // -------------------------------------------------------------------------
    // Scheduler (MB6): initialise cooperative round-robin scheduler and
    // spawn the idle task using a single 4 KiB kernel stack frame.
    //
    // The kernel-stack frame returned by `alloc_frame()` is guaranteed to
    // live in the bootloader's direct map: MB9's `register_direct_mapped_regions`
    // filters the bitmap to only contain Usable regions whose start and last
    // page are translatable by the active page tables, so writing the stack
    // frame at `phys + phys_offset` cannot fault.
    // -------------------------------------------------------------------------
    // SAFETY: single-CPU, non-preemptive; SCHEDULER and FRAME_ALLOC are not
    // aliased anywhere else at this point. `pager` was constructed above in
    // this same function and is exclusively borrowed across this block.
    #[cfg(target_arch = "x86_64")]
    #[allow(
        unsafe_code,
        reason = "single-core static-mut deref; aliasing invariant in SAFETY comment"
    )]
    unsafe {
        let sched = &mut *core::ptr::addr_of_mut!(SCHEDULER);
        let fa = &mut *core::ptr::addr_of_mut!(FRAME_ALLOC);
        if let Some(phys) = fa.alloc_frame() {
            match sched.spawn_kernel_task(
                idle_task,
                phys.0,
                &mut pager,
                fa,
                scheduling::PriorityClass::Idle,
            ) {
                Ok(_) => {
                    early_console::write_str("[sched] scheduler init  idle task spawned\n");
                    early_console::write_str("[stack] kernel stack VA range = ");
                    #[allow(
                        clippy::cast_possible_truncation,
                        reason = "x86_64 only; usize is u64 on target_os = none"
                    )]
                    early_console::write_usize(scheduling::KERNEL_STACK_VA_BASE as usize);
                    early_console::write_str(" .. ");
                    #[allow(
                        clippy::cast_possible_truncation,
                        reason = "x86_64 only; usize is u64 on target_os = none"
                    )]
                    early_console::write_usize(scheduling::KERNEL_STACK_VA_END as usize);
                    early_console::write_str(" (slot 0)\n");
                }
                Err(_) => early_console::write_str("[sched] scheduler init  idle spawn FAILED\n"),
            }
        } else {
            early_console::write_str("[sched] scheduler init  no frame for idle stack\n");
        }
    }

    // -------------------------------------------------------------------------
    // Bootstrap kmain task (MB8): register the current execution flow as a
    // scheduler-visible task BEFORE `sti`, so that the first LAPIC timer
    // tick has a valid `current` to save state into. Uses the boot stack
    // in-place (no owned frame); the sentinel `rsp = 0` is overwritten by
    // the first `nexacore_context_switch`.
    // -------------------------------------------------------------------------
    #[cfg(target_arch = "x86_64")]
    #[allow(
        unsafe_code,
        reason = "single-core static-mut deref; aliasing invariant in SAFETY comment"
    )]
    unsafe {
        let sched = &mut *core::ptr::addr_of_mut!(SCHEDULER);
        match sched.spawn_bootstrap_task(scheduling::PriorityClass::System) {
            Ok(_) => early_console::write_str("[sched] bootstrap kmain task registered\n"),
            Err(_) => early_console::write_str("[sched] bootstrap kmain task FAILED\n"),
        }
    }

    // -------------------------------------------------------------------------
    // Shell infrastructure initialization — global statics for the syscall
    // handler bridge (fd table, pipe registry, console input, VFS, process
    // table). Placed BEFORE the LAPIC timer / sti so the init runs with
    // interrupts disabled — no timer preemption possible.
    // -------------------------------------------------------------------------
    #[cfg(target_arch = "x86_64")]
    #[allow(
        unsafe_code,
        reason = "single-CPU static-mut init for shell globals; same invariant as SCHEDULER"
    )]
    unsafe {
        // write_volatile prevents LTO from eliminating these stores as
        // dead — the shell_handlers module reads them via addr_of_mut
        // in the syscall dispatch path which LTO cannot prove reachable
        // from kmain's linear flow.
        core::ptr::write_volatile(
            core::ptr::addr_of_mut!(SHELL_VFS),
            Some(vfs::InMemoryVfs::new()),
        );
        if let Some(ref mut v) = *core::ptr::addr_of_mut!(SHELL_VFS) {
            let _ = v.create_directory("/bin");
        }
        core::ptr::write_volatile(
            core::ptr::addr_of_mut!(SHELL_FD_TABLE),
            Some(fd::FileDescriptorTable::new_with_stdio()),
        );
        core::ptr::write_volatile(
            core::ptr::addr_of_mut!(SHELL_PIPE_REGISTRY),
            Some(pipe::PipeRegistry::new()),
        );
        core::ptr::write_volatile(
            core::ptr::addr_of_mut!(SHELL_CONSOLE_INPUT),
            Some(console_input::ConsoleInputBuffer::new()),
        );
        core::ptr::write_volatile(
            core::ptr::addr_of_mut!(SHELL_PROCESS_TABLE),
            Some(process_table::ProcessTable::new()),
        );
        if let Some(ref mut pt) = *core::ptr::addr_of_mut!(SHELL_PROCESS_TABLE) {
            pt.register(
                scheduling::TaskId(1),
                None,
                alloc::string::String::from("nexacore-shell"),
            );
        }
        early_console::write_str("[NexaCore OS] shell infrastructure initialized.\n");

        #[cfg(target_os = "none")]
        {
            const EMBEDDED_INITRAMFS: &[u8] = include_bytes!("embedded_initramfs.bin");
            // justification: EMBEDDED_INITRAMFS is a const whose emptiness is
            // determined at compile time; the branch is intentionally a
            // compile-time guard to skip parsing a zero-byte blob.
            #[allow(clippy::const_is_empty)]
            if !EMBEDDED_INITRAMFS.is_empty() {
                match initramfs::parse_initramfs(EMBEDDED_INITRAMFS) {
                    Ok(entries) => {
                        if let Some(ref mut v) = *core::ptr::addr_of_mut!(SHELL_VFS) {
                            match initramfs::load_into_vfs(&entries, v) {
                                Ok(count) => {
                                    early_console::write_str("[NexaCore OS] initramfs: loaded ");
                                    early_console::write_usize(count);
                                    early_console::write_str(" binaries into /bin/\n");
                                }
                                Err(_) => {
                                    early_console::write_str(
                                        "[NexaCore OS] initramfs: VFS load failed\n",
                                    );
                                }
                            }
                        }
                    }
                    Err(_) => {
                        early_console::write_str("[NexaCore OS] initramfs: parse failed\n");
                    }
                }
            }
        }
    }

    // -------------------------------------------------------------------------
    // LAPIC (MB7): disable legacy 8259 PIC, enable xAPIC, start periodic timer
    // at IDT vector 0x20. Issues `sti` to enable maskable interrupts.
    // -------------------------------------------------------------------------
    // Variables surfaced from the MB14.a/c.1 block down to the desktop
    // demo so the System Info panel can render the BSP LAPIC ID + total
    // logical-CPU count. Default to "single CPU" so MADT-walk failures
    // do not break the panel rendering.
    let mut sysinfo_cpu_total: usize = 1;
    let mut sysinfo_bsp_apic_id: u32 = 0;

    // MB14 panel — collect CPUID once and cache it so render_sysinfo
    // can render the brand/vendor/feature rows without re-issuing
    // CPUID on every redraw.
    #[cfg(target_arch = "x86_64")]
    bare_metal::cpuinfo::init();

    #[cfg(target_arch = "x86_64")]
    {
        if bare_metal::lapic::lapic_init(phys_offset_mb2) {
            early_console::write_str("[lapic] timer started  vector=0x20\n");

            // MB14.f.2 — surface the LAPIC mode the firmware left us in
            // (xAPIC by default on QEMU/Proxmox; x2APIC if a BIOS opts
            // in pre-kernel). The kernel never flips the bit at runtime;
            // every primitive (`lapic_eoi`, `lapic_send_ipi`,
            // `read_lapic_id`, `kernel_ap_lapic_init`) routes via MSRs
            // when this flag is set, and via xAPIC MMIO otherwise.
            early_console::write_str("[mb14.f] lapic_mode=");
            early_console::write_str(if bare_metal::lapic::is_x2apic_enabled() {
                "x2APIC\n"
            } else {
                "xAPIC\n"
            });

            // MB14.a — seed the BSP per-CPU descriptor. LAPIC base is now
            // mapped (lapic_init wrote LAPIC_BASE) so read_lapic_id can
            // observe the physical ID, which the descriptor stores under
            // cpu_id=0 (BSP is always slot 0 in the per-CPU array).
            if let Some(lid) = bare_metal::lapic::read_lapic_id() {
                sysinfo_bsp_apic_id = lid;
                bare_metal::per_cpu::init_bsp(lid);
                early_console::write_str("[mb14.a] BSP cpu_id=0 lapic_id=");
                early_console::write_usize(lid as usize);
                early_console::write_str("\n");

                // MB14.b — wire IA32_GS_BASE + IA32_KERNEL_GS_BASE to
                // the BSP descriptor address. After this returns, any
                // kernel context can recover the active per-CPU pointer
                // with `mov rax, gs:[0]` (encoded inside
                // `per_cpu::current_cpu()`) and `nexacore_syscall_entry`
                // has its `swapgs` ready for the first Ring 3 transition.
                bare_metal::per_cpu::init_gs_base(bare_metal::per_cpu::bsp());
                early_console::write_str("[mb14.b] gs_base=");
                #[allow(
                    clippy::cast_possible_truncation,
                    reason = "x86_64 only; usize is u64 on target_os = none"
                )]
                early_console::write_usize(bare_metal::per_cpu::bsp().self_ptr() as usize);
                early_console::write_str("\n");

                // MB14.c.1 — enumerate logical CPUs via the ACPI MADT.
                // No APs are started here; the figure is logged for
                // verification and consumed in MB14.c.2 (INIT-SIPI
                // orchestrator) and MB14.e (per-CPU run-queues).
                //
                // The MADT walk is best-effort: if RSDP or the
                // physical-memory window is unavailable, or any table
                // in the chain is malformed, we log the failure and
                // fall through to BSP-only operation (same behaviour
                // as MB14.b).
                //
                // SAFETY: the same invariants the FADT walker depends
                // on (see `arch::find_pm1a_cnt_from_fadt`): the
                // bootloader-supplied direct-map covers all ACPI
                // tables, and `rsdp_addr` / `physical_memory_offset`
                // are valid for this boot.
                let rsdp = boot_info.rsdp_addr.into_option();
                if let (Some(rsdp_phys), Some(off)) =
                    (rsdp, boot_info.physical_memory_offset.into_option())
                {
                    // SAFETY: bootloader-supplied direct-map covers all ACPI
                    // tables; same invariants as `arch::acpi_poweroff_from_fadt`.
                    #[allow(
                        unsafe_code,
                        reason = "ACPI MADT walk via bootloader direct map; SAFETY above"
                    )]
                    let topo_opt = unsafe { bare_metal::mp::enumerate_cpus(rsdp_phys, off) };
                    if let Some(topo) = topo_opt {
                        sysinfo_cpu_total = topo.enabled_count();
                        // SAFETY: boot-time, single-threaded; see
                        // `services::sysinfo` module doc.
                        #[allow(
                            unsafe_code,
                            reason = "single-threaded boot write to the SysInfo (114) CPU-count cache"
                        )]
                        unsafe {
                            services::sysinfo::set_cpu_count(sysinfo_cpu_total as u32);
                        }
                        early_console::write_str("[mb14.c.1] MADT cpus=");
                        early_console::write_usize(topo.len());
                        early_console::write_str(" enabled=");
                        early_console::write_usize(topo.enabled_count());
                        early_console::write_str("\n");
                        for cpu in topo.entries() {
                            early_console::write_str("[mb14.c.1]   apic_id=");
                            early_console::write_usize(cpu.apic_id as usize);
                            early_console::write_str(if cpu.x2apic { " (x2apic)" } else { "" });
                            early_console::write_str(if cpu.enabled {
                                " enabled"
                            } else {
                                " disabled"
                            });
                            early_console::write_str("\n");
                        }

                        // MB14.c.2.a — INIT-SIPI-SIPI orchestrator (dry-run).
                        //
                        // No LAPIC MMIO occurs: the orchestrator iterates the
                        // discovered topology, builds + encodes the canonical
                        // INIT/SIPI/SIPI ICR values for every enabled non-BSP
                        // AP, and discards them. The real-mode trampoline at
                        // physical 0x8000 lands in MB14.c.2.b, after which
                        // MB14.c.2.c will flip this call to `StartApsMode::Live`.
                        //
                        // We pass `trampoline_page = 0x08` (corresponding to
                        // the planned 0x0000_8000 physical address) so the
                        // SIPI vector field is already in its canonical form
                        // for the encoder tests. With `mode = DryRun` the
                        // orchestrator is guaranteed to make no MMIO accesses
                        // regardless of trampoline_page — the value is purely
                        // a label for the log.
                        let report = bare_metal::mp::start_aps(
                            &topo,
                            lid,
                            0x08,
                            bare_metal::mp::StartApsMode::DryRun,
                        );
                        early_console::write_str("[mb14.c.2.a] start_aps targeted=");
                        early_console::write_usize(report.targeted);
                        early_console::write_str(" sequenced=");
                        early_console::write_usize(report.sequenced);
                        early_console::write_str(if report.dry_run {
                            " (dry-run)\n"
                        } else {
                            " (live)\n"
                        });

                        // MB14.c.2.b.1 — exercise the pure-function trampoline
                        // builders on the BSP so any cross-build regression
                        // surfaces in the boot log before MB14.c.2.b.2 starts
                        // emplacing the blob at physical 0x8000. No MMIO, no
                        // physical writes — the builders return owned values
                        // that we immediately drop after counting non-zero
                        // bytes for the serial banner.
                        let blob = bare_metal::mp_trampoline::build_trampoline_blob(
                            0x0000_8000,
                            0x0000_9000,
                            0xFFFF_FFFF_8010_0000,
                        );
                        let mut blob_nonzero = 0usize;
                        for byte in &blob {
                            if *byte != 0 {
                                blob_nonzero += 1;
                            }
                        }
                        let gdt = bare_metal::mp_trampoline::build_temp_gdt();
                        early_console::write_str("[mb14.c.2.b.1] trampoline blob bytes=");
                        early_console::write_usize(blob.len());
                        early_console::write_str(" nonzero=");
                        early_console::write_usize(blob_nonzero);
                        early_console::write_str(" gdt_entries=");
                        early_console::write_usize(gdt.len());
                        early_console::write_str(" (builder dry-run)\n");

                        // MB14.c.2.c — live AP wake.
                        //
                        // When the MADT enumerated more than one CPU we
                        // (a) emplace the trampoline + landing stub at
                        // phys 0x8000, (b) fire INIT-SIPI-SIPI on every
                        // enabled non-BSP AP via the LAPIC ICR, and
                        // (c) busy-poll the ack counter at phys 0x8140
                        // until every targeted AP has entered the
                        // landing stub. The AP then switches CR3 to the
                        // active kernel address space and jumps to
                        // `kmain_ap` (a #[naked] cli; hlt; jmp $-2
                        // park loop pending MB14.c.2.d).
                        //
                        // On BSP-only systems (enabled_count == 1) we
                        // skip the live path entirely: there is no AP
                        // to wake and reserving frames for nothing would
                        // waste low memory.
                        if topo.enabled_count() > 1 {
                            #[allow(
                                unsafe_code,
                                reason = "single-core BSP context; FRAME_ALLOC not aliased"
                            )]
                            let fa = unsafe { &mut *core::ptr::addr_of_mut!(FRAME_ALLOC) };

                            // -----------------------------------------------
                            // MB14.c.2.d — per-AP pre-fire wiring.
                            //
                            // For every enabled non-BSP AP in the topology,
                            // we allocate:
                            //   - a per-AP kernel stack (1 frame, no guard;
                            //     guard-page protection lands with the
                            //     per-CPU scheduler in MB14.e)
                            //   - per-AP IST1 / IST2 stacks (1 frame each)
                            //   - a per-AP `PerCpu` slot (in AP_SLOTS)
                            //   - a per-AP TSS (in AP_TSS)
                            //   - a per-AP TSS GDT descriptor (slot
                            //     7 + 2*(cpu_id - 1))
                            //   - an `AP_RUNTIME_CONTROL` slot entry that
                            //     hands the running AP its `cpu_id`,
                            //     `kstack_top`, `&PerCpu`, and TSS selector.
                            //
                            // The BSP also stamps the kernel GDTR / IDTR
                            // pseudo-descriptors into the control block so
                            // every AP `lgdt` / `lidt` against the live
                            // kernel tables (the trampoline's temp GDT is
                            // immediately replaced — the AP no longer
                            // depends on low memory after this point).
                            // -----------------------------------------------
                            let (gdtr_base, gdtr_limit) = bare_metal::gdt::gdt_base_and_limit();
                            let (idtr_base, idtr_limit) = bare_metal::idt::idt_base_and_limit();
                            bare_metal::mp_ap_entry::install_descriptor_tables(
                                gdtr_base, gdtr_limit, idtr_base, idtr_limit,
                            );

                            let mut ap_index: u32 = 1;
                            let mut ap_kstack_failures: usize = 0;
                            let mut ap_ist_failures: usize = 0;
                            for cpu in topo.entries() {
                                if !cpu.enabled || cpu.apic_id == lid {
                                    continue;
                                }
                                let cpu_id = ap_index;
                                ap_index += 1;
                                // 1) Allocate per-AP kernel stack +
                                //    IST stacks via direct-map (single
                                //    frame each). Bail out of this AP
                                //    on allocator exhaustion — the BSP
                                //    will still wake any AP whose
                                //    wiring landed.
                                let Some(kstk_top) =
                                    bare_metal::mp_ap_entry::allocate_ap_stack_frame(
                                        fa,
                                        phys_offset_mb2,
                                    )
                                else {
                                    ap_kstack_failures += 1;
                                    continue;
                                };
                                let Some(ist1_top) =
                                    bare_metal::mp_ap_entry::allocate_ap_stack_frame(
                                        fa,
                                        phys_offset_mb2,
                                    )
                                else {
                                    ap_ist_failures += 1;
                                    continue;
                                };
                                let Some(ist2_top) =
                                    bare_metal::mp_ap_entry::allocate_ap_stack_frame(
                                        fa,
                                        phys_offset_mb2,
                                    )
                                else {
                                    ap_ist_failures += 1;
                                    continue;
                                };
                                // 2) Populate per-AP TSS.
                                let _ = bare_metal::tss::init_ap_tss(
                                    cpu_id, kstk_top, ist1_top, ist2_top,
                                );
                                // 3) Register PerCpu slot.
                                let Some(slot) =
                                    bare_metal::per_cpu::register_ap(cpu_id, cpu.apic_id)
                                else {
                                    continue;
                                };
                                slot.set_kernel_rsp(kstk_top);
                                // 4) Place TSS descriptor into kernel GDT.
                                let tss_base = bare_metal::tss::ap_tss_addr(cpu_id);
                                let _ = bare_metal::gdt::gdt_set_ap_tss(cpu_id, tss_base);
                                // 5) Stamp AP_RUNTIME_CONTROL.
                                let tss_sel = bare_metal::gdt::tss_selector_for_cpu(cpu_id);
                                let per_cpu_ptr =
                                    core::ptr::from_ref::<bare_metal::per_cpu::PerCpu>(slot) as u64;
                                let _ = bare_metal::mp_ap_entry::register_ap_runtime_slot(
                                    cpu_id,
                                    cpu.apic_id,
                                    kstk_top,
                                    per_cpu_ptr,
                                    tss_sel,
                                );
                                early_console::write_str("[mb14.c.2.d] ap cpu_id=");
                                early_console::write_usize(cpu_id as usize);
                                early_console::write_str(" lapic=");
                                early_console::write_usize(cpu.apic_id as usize);
                                early_console::write_str(" kstk_top=");
                                #[allow(
                                    clippy::cast_possible_truncation,
                                    reason = "bare-metal x86_64 target: usize is u64"
                                )]
                                early_console::write_usize(kstk_top as usize);
                                early_console::write_str(" tss_sel=");
                                early_console::write_usize(tss_sel as usize);
                                early_console::write_str("\n");
                            }
                            if ap_kstack_failures > 0 || ap_ist_failures > 0 {
                                early_console::write_str("[mb14.c.2.d] stack alloc failures kstk=");
                                early_console::write_usize(ap_kstack_failures);
                                early_console::write_str(" ist=");
                                early_console::write_usize(ap_ist_failures);
                                early_console::write_str("\n");
                            }

                            let kmain_ap_va =
                                bare_metal::mp_ap_entry::kmain_ap as *const () as usize as u64;
                            match bare_metal::mp_emplacement::place_trampoline_live(
                                fa,
                                &mut pager,
                                cr3_raw & !0xFFF,
                                kmain_ap_va,
                            ) {
                                Ok(emp) => {
                                    early_console::write_str("[mb14.c.2.c] emplaced tramp_paddr=");
                                    early_console::write_usize(emp.trampoline_paddr as usize);
                                    early_console::write_str(" temp_pml4=");
                                    #[allow(
                                        clippy::cast_possible_truncation,
                                        reason = "x86_64; usize is u64 on bare-metal target"
                                    )]
                                    early_console::write_usize(emp.temp_pml4_paddr as usize);
                                    early_console::write_str(" kmain_ap_va=");
                                    #[allow(
                                        clippy::cast_possible_truncation,
                                        reason = "x86_64; usize is u64 on bare-metal target"
                                    )]
                                    early_console::write_usize(kmain_ap_va as usize);
                                    early_console::write_str("\n");

                                    // Fire INIT-SIPI-SIPI on every enabled
                                    // non-BSP AP, then busy-poll the ack
                                    // counter until each one has entered
                                    // the landing stub.
                                    let live_report = bare_metal::mp::start_aps_live(
                                        &topo,
                                        lid,
                                        bare_metal::mp_emplacement::TRAMPOLINE_SIPI_VECTOR,
                                        phys_offset_mb2,
                                    );
                                    early_console::write_str(
                                        "[mb14.c.2.c] start_aps_live targeted=",
                                    );
                                    early_console::write_usize(live_report.targeted);
                                    early_console::write_str(" sequenced=");
                                    early_console::write_usize(live_report.sequenced);
                                    early_console::write_str(" acked=");
                                    early_console::write_usize(live_report.acked);
                                    if live_report.acked == live_report.targeted {
                                        early_console::write_str(" (all APs online)\n");
                                    } else {
                                        early_console::write_str(" (timeout)\n");
                                    }

                                    // MB14.c.2.d — busy-poll the per-AP
                                    // online ack counter (incremented by
                                    // the kmain_ap asm post-ltr). This is
                                    // separate from the landing-stub ack:
                                    // it confirms that the AP completed
                                    // its `lgdt` / `lidt` / `ltr` sequence
                                    // and is parked in the steady-state
                                    // hlt loop. Bounded budget — if an AP
                                    // triple-faults after the landing
                                    // stub, the count stalls but the BSP
                                    // does not hang.
                                    let ap_target = live_report.acked as u64;
                                    let mut iter: u64 = 0;
                                    let mut online: u64 = 0;
                                    while iter < 200_000_000 {
                                        online = bare_metal::per_cpu::ap_online_ack();
                                        if online >= ap_target {
                                            break;
                                        }
                                        core::hint::spin_loop();
                                        iter = iter.wrapping_add(1);
                                    }
                                    early_console::write_str("[mb14.c.2.d] per-AP init online=");
                                    #[allow(
                                        clippy::cast_possible_truncation,
                                        reason = "bare-metal x86_64: usize is u64"
                                    )]
                                    early_console::write_usize(online as usize);
                                    early_console::write_str("/");
                                    #[allow(
                                        clippy::cast_possible_truncation,
                                        reason = "bare-metal x86_64: usize is u64"
                                    )]
                                    early_console::write_usize(ap_target as usize);
                                    if online >= ap_target {
                                        early_console::write_str(" (all APs parked)\n");
                                    } else {
                                        early_console::write_str(" (timeout post-ltr)\n");
                                    }
                                }
                                Err(_e) => {
                                    early_console::write_str(
                                        "[mb14.c.2.c] emplacement FAILED — BSP only\n",
                                    );
                                }
                            }
                        } else {
                            early_console::write_str("[mb14.c.2.c] BSP-only — AP wake skipped\n");
                        }
                    } else {
                        early_console::write_str("[mb14.c.1] MADT walk FAILED — BSP only\n");
                    }
                } else {
                    early_console::write_str(
                        "[mb14.c.1] rsdp / phys_offset unavailable — BSP only\n",
                    );
                }
            } else {
                early_console::write_str(
                    "[mb14.a] read_lapic_id FAILED — descriptor left uninit\n",
                );
            }

            // Enable maskable interrupts — timer can fire from this point on.
            // SAFETY: LAPIC is configured; IDT vector 0x20 handler is installed.
            #[allow(unsafe_code, reason = "sti enable interrupts; SAFETY comment above")]
            unsafe {
                core::arch::asm!("sti", options(nomem, nostack));
            }
            early_console::write_str("[lapic] interrupts enabled\n");

            // MB14.d — TLB shootdown smoke. We issue a benign 4 KiB
            // `invlpg` on a kernel-half address (the trampoline page is
            // mapped both in the BSP's CR3 and unchanged by this call,
            // so the invalidation is observable but inert) and broadcast
            // the IPI on vector `0xFD`. The local `invlpg` always runs;
            // the IPI broadcast occurs only when at least one AP is
            // registered. With MB14.e.1 the AP entry stub now executes
            // `sti` before its `hlt` park, so the 0xFD ISR fires on
            // every AP and `ShootdownReport.acked` reaches `targeted`
            // — the `(all APs acked)` suffix replaces the MB14.d-era
            // `(IRR queued ...)` placeholder.
            {
                let report =
                    mm::flush_tlb_range(crate::memory::VirtAddr(0x0000_0000_0000_8000), 0x1000);
                early_console::write_str("[mb14.d] tlb_shootdown vector=0xFD targeted=");
                early_console::write_usize(report.targeted);
                early_console::write_str(" acked=");
                early_console::write_usize(report.acked);
                early_console::write_str(" local_pages=");
                #[allow(
                    clippy::cast_possible_truncation,
                    reason = "bare-metal x86_64: usize is u64"
                )]
                early_console::write_usize(report.local_pages as usize);
                if report.targeted == 0 {
                    early_console::write_str(" (BSP-only — no broadcast)\n");
                } else if report.complete() {
                    early_console::write_str(" (all APs acked)\n");
                } else {
                    early_console::write_str(" (timeout — AP ISR did not ack)\n");
                }
            }

            // MB14.e.2 + MB14.e.3 — per-CPU run-queue scaffold smoke.
            //
            // Exercise the per-CPU run-queue API on the BSP: enqueue
            // a sentinel task id, pop it locally, then enqueue a
            // second sentinel and steal it from a different (idle) AP
            // slot. No real task is created — the queue stores raw
            // u64 ids, and the bridge to `RoundRobinScheduler` will
            // land in MB14.f when AP dispatch goes live. This boot-log
            // smoke confirms the queue + lock primitives are usable
            // from the kernel runtime (no double-fault, no panic) on
            // top of the lifecycle exercised by host-side tests.
            {
                use scheduling::PriorityClass;
                let bsp_cpu = bare_metal::per_cpu::bsp().cpu_id();
                let _ = bare_metal::per_cpu_run_queue::enqueue_on_cpu(
                    bsp_cpu,
                    0xE_E_E_E_E_2_u64,
                    PriorityClass::Interactive,
                );
                let popped = bare_metal::per_cpu_run_queue::pop_for_cpu(bsp_cpu);
                let local_ok = popped == Some(0xE_E_E_E_E_2);

                // Stealing fallback: enqueue on cpu_id 0 (BSP), then
                // request from cpu_id 1 (likely AP slot or empty AP
                // slot if no APs enumerated) — `pop_for_cpu_with_stealing`
                // must surface the BSP task via the steal path.
                let _ = bare_metal::per_cpu_run_queue::enqueue_on_cpu(
                    0,
                    0xE_E_E_E_E_3_u64,
                    PriorityClass::Background,
                );
                let stolen = bare_metal::per_cpu_run_queue::pop_for_cpu_with_stealing(1);
                let steal_ok = stolen == Some(0xE_E_E_E_E_3);

                early_console::write_str("[mb14.e] per_cpu_run_queue local=");
                early_console::write_str(if local_ok { "ok" } else { "FAIL" });
                early_console::write_str(" steal=");
                early_console::write_str(if steal_ok { "ok" } else { "FAIL" });
                early_console::write_str("\n");
            }

            // MB14.g — per-CPU tick + need_resched + scheduler routing smoke.
            //
            // Reads the BSP's `PerCpu.tick_count` immediately after the
            // LAPIC timer has been armed; the value will be 0 until the
            // first periodic tick fires post-`sti`, but the accessor
            // must return without faulting (proves `gs:[0]` is live and
            // the descriptor layout matches MB14.g additions). The
            // `request_resched` / `take_resched` round-trip exercises
            // the per-CPU flag without depending on a real ISR. The
            // final block calls `SCHEDULER.enqueue_for_cpu` +
            // `pick_next_for_cpu` so any future refactor that breaks
            // the dual-write contract surfaces at boot — not only in
            // the host-side tests.
            {
                let cpu = bare_metal::per_cpu::current_cpu();
                let tick = cpu.tick_count();
                cpu.request_resched();
                let took = cpu.take_resched();
                let took2 = cpu.take_resched();
                early_console::write_str("[mb14.g] per_cpu tick=");
                #[allow(
                    clippy::cast_possible_truncation,
                    reason = "diagnostic write_usize takes usize; tick count fits trivially"
                )]
                early_console::write_usize(tick as usize);
                early_console::write_str(" resched=");
                early_console::write_str(if took && !took2 { "ok" } else { "FAIL" });
                // SAFETY: single-CPU boot path. The static SCHEDULER is
                // not concurrently aliased here — interrupts are still
                // masked (no `sti` yet at this point of `kmain`).
                //
                // The smoke uses a sentinel id outside the
                // `allocate_task_id` sequence so a stale legacy-mirror
                // entry cannot collide with a real task id. We do not
                // populate the TCB pool: `pick_next_for_cpu` only reads
                // the per-CPU dispatch table (and the legacy mirror
                // via retain-by-id), neither of which dereferences the
                // backing TCB. The retain-by-id in `pick_next_for_cpu`
                // sweeps the legacy mirror clean as a side effect.
                #[allow(
                    unsafe_code,
                    reason = "single-CPU access to static mut SCHEDULER before sti"
                )]
                let routed_ok = unsafe {
                    let sched = &mut *core::ptr::addr_of_mut!(SCHEDULER);
                    let sentinel = scheduling::TaskId(0xFFFF_FFFF_FFFF_EE14);
                    let pushed =
                        sched.enqueue_for_cpu(0, sentinel, scheduling::PriorityClass::Background);
                    let picked = sched.pick_next_for_cpu(0);
                    pushed && picked == Some(sentinel)
                };
                early_console::write_str(" sched_route=");
                early_console::write_str(if routed_ok { "ok" } else { "FAIL" });
                early_console::write_str("\n");
            }

            // MB14.h.1 — AP-side observer dispatcher smoke.
            //
            // Enqueue a sentinel task id on the first registered AP
            // (`cpu_id = 1`) and wait for any AP to observe it. The
            // AP's LAPIC periodic timer (armed in `kernel_ap_lapic_init`)
            // fires the `nexacore_lapic_timer_handler` stub, which calls
            // `kernel_check_need_resched`; the MB14.h.1 wire (this
            // milestone) routes the AP branch through
            // `bare_metal::ap_dispatch::kernel_ap_dispatch_observe`,
            // which pops a task id from `per_cpu_run_queue` (with
            // work-stealing fallback) and increments that AP's per-CPU
            // counter — observer-mode only, no context switch
            // (MB14.h.2 ADR-0009).
            //
            // Because `pop_for_cpu_with_stealing` may **steal** the
            // sentinel from `cpu_id=1`'s queue to a sibling AP that
            // happened to fire its timer first, the smoke sums
            // observations across every registered AP slot rather than
            // polling slot `1` alone — the question being answered is
            // "did *any* AP observe the queue?", which is the
            // MB14.h.1 reachability invariant.
            //
            // The poll budget is **anchored on BSP tick count**, not on
            // busy-loop iterations: on QEMU TCG (kvm=0) emulated CPU
            // cycles do not match wall-time, so a fixed iteration count
            // can race past the AP's first LAPIC tick before any AP
            // has had the chance to fire. Using
            // `bsp().tick_count()` as the clock source keeps the
            // budget meaningful on both TCG and KVM: after K BSP ticks
            // the APs have had K equivalent ticks too (the LAPIC
            // periodic timer is per-CPU but armed with identical
            // initial-count + divider on every CPU by
            // `kernel_ap_lapic_init`). K = 32 ticks gives ≈ 5 s on
            // QEMU TCG (≈ 160 ms per tick) and ≈ tens of ms on real
            // silicon, an order of magnitude above the first AP tick.
            //
            // If no AP came online (single-CPU dev VM) the smoke logs
            // `BSP-only` and short-circuits — the BSP must not consume
            // the sentinel itself (its resched trampoline runs the
            // legacy `yield_current` path, not the observer).
            {
                use scheduling::PriorityClass;
                if bare_metal::per_cpu::registered_ap_count() > 0 {
                    const AP_DISPATCH_TICK_BUDGET: u64 = 32;
                    let target_cpu_id: u32 = 1;
                    let _ = bare_metal::per_cpu_run_queue::enqueue_on_cpu(
                        target_cpu_id,
                        0xE_E_E_E_E_4_u64,
                        PriorityClass::Background,
                    );
                    let bsp = bare_metal::per_cpu::bsp();
                    let start_tick = bsp.tick_count();
                    #[allow(
                        clippy::cast_possible_truncation,
                        reason = "MAX_AP_SLOTS = MAX_CPUS - 1 = 31 fits u32 trivially"
                    )]
                    let max_ap = bare_metal::per_cpu::MAX_AP_SLOTS as u32;
                    let observed: u64 = loop {
                        let mut total: u64 = 0;
                        for cpu_id in 1u32..=max_ap {
                            if let Some(slot) = bare_metal::per_cpu::ap_slot(cpu_id) {
                                total = total.saturating_add(slot.dispatch_observations());
                            }
                        }
                        if total > 0 {
                            break total;
                        }
                        if bsp.tick_count().saturating_sub(start_tick) >= AP_DISPATCH_TICK_BUDGET {
                            break total;
                        }
                        core::hint::spin_loop();
                    };
                    early_console::write_str("[mb14.h.1] ap_dispatch observed=");
                    #[allow(
                        clippy::cast_possible_truncation,
                        reason = "diagnostic write_usize takes usize; observation count fits trivially"
                    )]
                    early_console::write_usize(observed as usize);
                    if observed > 0 {
                        early_console::write_str(" (ok)\n");
                    } else {
                        early_console::write_str(" (timeout — AP did not observe)\n");
                    }
                } else {
                    early_console::write_str("[mb14.h.1] ap_dispatch BSP-only — no AP enrolled\n");
                }
            }

            // MB14.h.2 — cross-CPU context switch primitives smoke.
            //
            // Exercise the three new APIs introduced by MB14.h.2 from
            // the BSP so a regression in any of them surfaces as a
            // boot-time `FAIL` rather than a silent triple-fault at
            // the next AP timer tick:
            //
            // 1. `try_acquire_sched_lock` / `release_sched_lock` —
            //    mutual exclusion on the global SCHED_LOCK.
            // 2. `PerCpu::enter_scheduler` / `leave_scheduler` —
            //    per-CPU recursion guard round-trip.
            // 3. `tss::set_rsp0_for_cpu(0, _)` — BSP-side write that
            //    must succeed unconditionally; an out-of-range AP
            //    cpu_id must be rejected.
            //
            // None of the calls cross-CPU here; the bare-metal AP
            // dispatcher (`kernel_ap_dispatch_observe`) is the path
            // that combines all three in production.
            {
                let lock_ok =
                    scheduling::try_acquire_sched_lock() && !scheduling::try_acquire_sched_lock();
                scheduling::release_sched_lock();
                let bsp = bare_metal::per_cpu::bsp();
                let guard_ok = bsp.enter_scheduler() && !bsp.enter_scheduler();
                bsp.leave_scheduler();
                let tss_ok = bare_metal::tss::set_rsp0_for_cpu(0, 0xFFFF_C000_0000_0000)
                    && !bare_metal::tss::set_rsp0_for_cpu(0xFFFF, 0xDEAD_BEEF);
                early_console::write_str("[mb14.h.2] sched_lock=");
                early_console::write_str(if lock_ok { "ok" } else { "FAIL" });
                early_console::write_str(" per_cpu_in_sched=");
                early_console::write_str(if guard_ok { "ok" } else { "FAIL" });
                early_console::write_str(" set_rsp0_for_cpu=");
                early_console::write_str(if tss_ok { "ok" } else { "FAIL" });
                early_console::write_str("\n");
            }
        } else {
            early_console::write_str("[lapic] LAPIC init FAILED — running without timer\n");
        }
    }

    // -------------------------------------------------------------------------
    // P6.7.9-pre.8 — DEV-ONLY driver probe auto-loader.
    //
    // Scans the PCI bus, performs the in-kernel NVMe / virtio-net / e1000e
    // live bring-up (mapping each device's BAR into the boot PML4), then spawns
    // a hand-crafted Ring 3 probe ELF that exercises the full MmioMap (70)
    // syscall path (capability deposit → scope verification → page-table
    // installation).
    //
    // ORDER (2026-05-30): this MUST run BEFORE the first `spawn_from_elf`
    // (the net/shell boot blocks below). The in-kernel NVMe bring-up maps its
    // BAR (VA 0xFFFF_F000_0000_0000, PML4 index 480) into the boot PML4 via
    // `mapper.map_4k` and then reads the controller's CAP register. If any
    // user process has already been spawned, a per-process PML4 clone exists
    // (`AddressSpace::new_with_kernel_half` shallow-copies kernel-half PML4
    // entries by value at spawn time), and once the LAPIC timer preempts kmain
    // into that user task and back, kmain resumes on the user CR3 — whose
    // PML4 lacks the just-added index-480 entry — so the CAP read faults
    // `#PF code=0 cr2=0xFFFF_F000_0000_0000` in Ring 0. Running the probe here,
    // before any clone exists, keeps the entire map+read on the boot CR3 where
    // the mapping is present. (Matches the loader-doc intent and the
    // kstk-first eager-map precedent in process.rs.) Excluded from the
    // mb11/mb12-userprobe smoke builds, where it was previously unreachable.
    //
    // SAFETY: single-CPU; SCHEDULER and FRAME_ALLOC are not aliased.
    // -------------------------------------------------------------------------
    #[cfg(all(
        target_arch = "x86_64",
        target_os = "none",
        not(test),
        not(feature = "mb11-userprobe"),
        not(feature = "mb12-userprobe")
    ))]
    #[allow(
        unsafe_code,
        reason = "single-core static-mut deref for the boot driver probe"
    )]
    unsafe {
        let sched = &mut *core::ptr::addr_of_mut!(SCHEDULER);
        let fa = &mut *core::ptr::addr_of_mut!(FRAME_ALLOC);
        bare_metal::driver_loader::boot_load_driver_probe(&mut pager, fa, sched);
    }

    // -------------------------------------------------------------------------
    // virtio-net driver boot — spawn `/bin/nexacore-driver-net-virtio` (the Ring 3
    // NIC driver) at `System` priority, AFTER the DEV-ONLY probe loader (so the
    // in-kernel NVMe CAP read has already run on the boot CR3 — see the #PF
    // ordering note above) and BEFORE `nexacore-net`, so the driver can register the
    // `virtio0` NET interface before the network stack looks it up.
    //
    // The kernel deposits the driver's `MmioMap`/`DmaMap`/`IrqAttach` capability
    // tokens at the well-known deposit VA (scopes mirror the image's hardcoded
    // BAR 0xFEBC_0000 / 4 GiB DMA arena / IRQ 33). Same cap-deposit machinery
    // the probe loader uses; the image reads the tokens in its `_start`.
    //
    // Additive + best-effort: if `/bin/nexacore-driver-net-virtio` is absent (older
    // initramfs) it logs and the boot continues; `nexacore-net` then reports
    // `virtio0` unregistered and retries in its service loop. Gated off under
    // the userprobe smoke builds so they stay isolated.
    //
    // SAFETY: single-CPU; SHELL_VFS, SCHEDULER, FRAME_ALLOC are not aliased.
    // -------------------------------------------------------------------------
    #[cfg(all(
        target_arch = "x86_64",
        target_os = "none",
        not(test),
        not(feature = "mb11-userprobe"),
        not(feature = "mb12-userprobe")
    ))]
    #[allow(
        unsafe_code,
        reason = "single-core static-mut deref + spawn_from_elf; same invariant as the probe + nexacore-net boot blocks"
    )]
    {
        early_console::write_str(
            "[NexaCore OS] virtio-net boot: checking VFS for /bin/nexacore-driver-net-virtio...\n",
        );

        // SAFETY: single-CPU; SHELL_VFS not aliased.
        let drv_found = unsafe {
            (*core::ptr::addr_of!(SHELL_VFS))
                .as_ref()
                .is_some_and(|v| v.exists("/bin/nexacore-driver-net-virtio"))
        };

        if drv_found {
            // SAFETY: single-CPU; SHELL_VFS read-only; SCHEDULER/FRAME_ALLOC not aliased.
            unsafe {
                'load: {
                    let Some(vfs_ref) = (*core::ptr::addr_of!(SHELL_VFS)).as_ref() else {
                        early_console::write_str("[NexaCore OS] virtio-net boot: VFS vanished\n");
                        break 'load;
                    };
                    let Ok(stat) = vfs_ref.stat("/bin/nexacore-driver-net-virtio") else {
                        early_console::write_str(
                            "[NexaCore OS] virtio-net boot: stat /bin/nexacore-driver-net-virtio failed\n",
                        );
                        break 'load;
                    };
                    #[allow(
                        clippy::cast_possible_truncation,
                        reason = "ELF size bounded by the VFS in-memory allocator; well under usize::MAX"
                    )]
                    let Ok(elf_bytes) = vfs_ref.read_file(stat.inode, 0, stat.size as usize) else {
                        early_console::write_str(
                            "[NexaCore OS] virtio-net boot: read /bin/nexacore-driver-net-virtio failed\n",
                        );
                        break 'load;
                    };

                    let sched = &mut *core::ptr::addr_of_mut!(SCHEDULER);
                    let fa = &mut *core::ptr::addr_of_mut!(FRAME_ALLOC);
                    bare_metal::driver_loader::boot_load_virtio_net_image(
                        &elf_bytes, &mut pager, fa, sched,
                    );
                }
            }
        } else {
            early_console::write_str(
                "[NexaCore OS] virtio-net boot: /bin/nexacore-driver-net-virtio not found in VFS\n",
            );
        }
    }

    // -------------------------------------------------------------------------
    // NVMe driver + NCFS FS service boot (TASK-14, ADR-0036 / TASK-15,
    // ADR-0037 / TASK-22, ADR-0044).
    //
    // Spawn `/bin/nexacore-driver-nvme` (Ring 3 NVMe block driver) at `System`
    // priority, then `/bin/nexacore-fsd` (the NCFS FS service) at `System`.
    // The driver registers `nexacore.svc.blk.nvme0` + `.nvme0-reply` and serves
    // `BlkRequest`/`BlkResponse` (cooperative-yield completion — Option A);
    // nexacore-fsd presents its deposited `IpcSend` token to pass the
    // capability-gated `BlkLookup`, mounts the NCFS volume from disk (or
    // formats a fresh one) + runs the `/test.txt` boot-counter self-check
    // (TASK-15), then — TASK-22 — `NetRegister`s `nexacore.fs`/`nexacore.fs-reply`
    // and serves `FsRequest`/`FsResponse` so apps (the editor) persist files.
    //
    // NOTE (TASK-15): `/bin/nexacore-blkcheck` (the TASK-14 smoke client) is NO
    // LONGER boot-spawned — it writes LBA 42, which overlaps the NCFS
    // volume region (blocks 0..128) the daemon owns, so running both would
    // corrupt the filesystem every boot. blkcheck stays in the initramfs +
    // codebase for NVMe-driver regression smokes (re-enable manually).
    //
    // Both additive + best-effort: absence (older initramfs) logs and boot
    // continues. Same cfg gating + SAFETY invariants as the virtio-net block.
    // -------------------------------------------------------------------------
    #[cfg(all(
        target_arch = "x86_64",
        target_os = "none",
        not(test),
        not(feature = "mb11-userprobe"),
        not(feature = "mb12-userprobe")
    ))]
    #[allow(
        unsafe_code,
        reason = "single-core static-mut deref + spawn_from_elf; same invariant as the virtio-net boot block"
    )]
    {
        // (VFS path, console tag, is_driver) — the NVMe driver MUST spawn
        // before the daemon so `nvme0` is registered when nexacore-fsd looks
        // it up (the daemon also retries on ENOENT, so this is not strictly
        // load-bearing, only faster).
        for (path, tag, is_nvme) in [
            ("/bin/nexacore-driver-nvme", "nvme", true),
            ("/bin/nexacore-fsd", "nexacore-fsd", false),
        ] {
            // SAFETY: single-CPU; SHELL_VFS not aliased.
            let found = unsafe {
                (*core::ptr::addr_of!(SHELL_VFS))
                    .as_ref()
                    .is_some_and(|v| v.exists(path))
            };
            if !found {
                early_console::write_str("[NexaCore OS] ");
                early_console::write_str(tag);
                early_console::write_str(" boot: not found in VFS (older initramfs)\n");
                continue;
            }
            // SAFETY: single-CPU; SHELL_VFS read-only; SCHEDULER/FRAME_ALLOC not aliased.
            unsafe {
                'load: {
                    let Some(vfs_ref) = (*core::ptr::addr_of!(SHELL_VFS)).as_ref() else {
                        break 'load;
                    };
                    let Ok(stat) = vfs_ref.stat(path) else {
                        early_console::write_str("[NexaCore OS] stat failed\n");
                        break 'load;
                    };
                    #[allow(
                        clippy::cast_possible_truncation,
                        reason = "ELF size bounded by the VFS in-memory allocator"
                    )]
                    let Ok(elf_bytes) = vfs_ref.read_file(stat.inode, 0, stat.size as usize) else {
                        early_console::write_str("[NexaCore OS] read failed\n");
                        break 'load;
                    };
                    let sched = &mut *core::ptr::addr_of_mut!(SCHEDULER);
                    let fa = &mut *core::ptr::addr_of_mut!(FRAME_ALLOC);
                    if is_nvme {
                        bare_metal::driver_loader::boot_load_nvme_image(
                            &elf_bytes, &mut pager, fa, sched,
                        );
                    } else {
                        // System (not Background): nexacore-fsd is a one-shot
                        // storage daemon doing ~256 SYNCHRONOUS IPC round-trips
                        // against the System-priority NVMe driver. At Background
                        // the scheduler's 8-pick fairness cycle gives it only
                        // 1/8 of picks, so under concurrent System-task load
                        // (ai-svc/nexacore-net traffic) its reply-polls starve and
                        // the mount intermittently wedges (TASK-15). System
                        // makes it round-robin co-equal with the driver; it
                        // exits after the persistence proof, freeing the slot.
                        bare_metal::driver_loader::boot_load_blk_client_image(
                            &elf_bytes,
                            "nexacore-fsd",
                            scheduling::PriorityClass::System,
                            &mut pager,
                            fa,
                            sched,
                        );
                    }
                }
            }
        }
    }

    // -------------------------------------------------------------------------
    // Display input channel (TASK-18/19, WS7-06) — created HERE, before the
    // xHCI driver spawns, so BOTH producers can reach it: the kernel PS/2
    // input pump (the display boot block below) and the Ring-3 USB HID driver
    // (whose deposit carries the channel id). The channel is no-cap
    // (send/recv tokens = None), so knowing the id is sufficient to produce
    // into it; the display image drains it via `IpcTryReceive (24)`.
    // -------------------------------------------------------------------------
    #[cfg(all(
        target_arch = "x86_64",
        target_os = "none",
        not(test),
        not(feature = "mb11-userprobe"),
        not(feature = "mb12-userprobe")
    ))]
    #[allow(
        unsafe_code,
        reason = "single-core static-mut deref (SCHEDULER, IPC_REGISTRY); SAFETY documented per site"
    )]
    let display_input_ch: ipc::ChannelId = {
        use ipc::{BackpressurePolicy, ChannelPolicy};

        // SAFETY: single-CPU boot path; ipc_registry_mut() is the sole
        // &mut accessor; called before LAPIC enables scheduler preemption.
        unsafe {
            let reg = ipc::ipc_registry_mut();
            let sched = &*core::ptr::addr_of!(SCHEDULER);
            let owner = sched.current_task_id().unwrap_or(scheduling::TaskId(0));
            let policy = ChannelPolicy {
                queue_depth: 64,
                backpressure: BackpressurePolicy::EvictOldest,
                tee_bound: false,
            };
            // create_channel with send_token=None, recv_token=None: no-cap fast path.
            let Ok(id) = reg.create_channel(
                owner,
                policy,
                None,
                None,
                &crate::capabilities::Ed25519CapabilityProvider::placeholder(),
            ) else {
                early_console::write_str("[display] input channel create FAILED — halting\n");
                bare_metal::arch::halt_forever();
            };
            early_console::write_str("[display] input channel created id=");
            #[allow(
                clippy::cast_possible_truncation,
                reason = "channel id fits usize on x86_64"
            )]
            early_console::write_usize(id.0 as usize);
            early_console::write_str("\n");
            id
        }
    };

    // -------------------------------------------------------------------------
    // xHCI USB host controller driver boot (TASK-26, ADR-0048).
    //
    // Spawn `/bin/nexacore-driver-xhci` (Ring 3 xHCI USB driver) at `System`
    // priority. The driver enumerates root-hub ports, runs the Phase-1
    // Enumerator state machine, and logs the discovered device VID/PID.
    // The deposit carries the display input channel id + framebuffer
    // geometry so the HID class driver can produce `DisplayInputEvent`s
    // (WS7-06, ADR-0049 D4).
    //
    // Additive + best-effort: absent image (older initramfs) or missing
    // controller logs and boot continues. Same cfg gating + SAFETY invariants
    // as the NVMe driver block above.
    // -------------------------------------------------------------------------
    #[cfg(all(
        target_arch = "x86_64",
        target_os = "none",
        not(test),
        not(feature = "mb11-userprobe"),
        not(feature = "mb12-userprobe")
    ))]
    #[allow(
        unsafe_code,
        reason = "single-core static-mut deref + spawn_from_elf; same invariant as the NVMe boot block"
    )]
    {
        // SAFETY: single-CPU; SHELL_VFS not aliased.
        let xhci_found = unsafe {
            (*core::ptr::addr_of!(SHELL_VFS))
                .as_ref()
                .is_some_and(|v| v.exists("/bin/nexacore-driver-xhci"))
        };
        if !xhci_found {
            early_console::write_str(
                "[NexaCore OS] xhci boot: not found in VFS (older initramfs)\n",
            );
        } else {
            // SAFETY: single-CPU; SHELL_VFS read-only; SCHEDULER/FRAME_ALLOC not aliased.
            unsafe {
                'xhci_load: {
                    let Some(vfs_ref) = (*core::ptr::addr_of!(SHELL_VFS)).as_ref() else {
                        break 'xhci_load;
                    };
                    let Ok(stat) = vfs_ref.stat("/bin/nexacore-driver-xhci") else {
                        early_console::write_str("[NexaCore OS] xhci: stat failed\n");
                        break 'xhci_load;
                    };
                    #[allow(
                        clippy::cast_possible_truncation,
                        reason = "ELF size bounded by the VFS in-memory allocator"
                    )]
                    let Ok(elf_bytes) = vfs_ref.read_file(stat.inode, 0, stat.size as usize) else {
                        early_console::write_str("[NexaCore OS] xhci: read failed\n");
                        break 'xhci_load;
                    };
                    let sched = &mut *core::ptr::addr_of_mut!(SCHEDULER);
                    let fa = &mut *core::ptr::addr_of_mut!(FRAME_ALLOC);
                    // Framebuffer geometry for absolute-pointer scaling in
                    // the HID driver; (0, 0) when no GOP framebuffer exists
                    // (the driver then skips pointer production).
                    let (fb_w, fb_h) = bare_metal::graphics::framebuffer_info()
                        .map_or((0u32, 0u32), |fb| (fb.width, fb.height));
                    bare_metal::driver_loader::boot_load_xhci_image(
                        &elf_bytes,
                        display_input_ch.0,
                        fb_w,
                        fb_h,
                        &mut pager,
                        fa,
                        sched,
                    );
                }
            }
        }
    }

    // -------------------------------------------------------------------------
    // Network service boot — spawn `/bin/nexacore-net` (the userspace TCP/IP stack)
    // as a Ring 3 process BEFORE the shell, at `System` priority, so it
    // registers its socket-API IPC channels (`nexacore.svc.net.stack` +
    // `.stack.reply`) before any client issues a NET syscall. The service then
    // yields while waiting for the virtio-net driver to register `virtio0`, so
    // it never starves the shell or other tasks (Desktop M0).
    //
    // Additive + best-effort: if `/bin/nexacore-net` is absent (initramfs not
    // rebuilt) it logs and the boot continues. Gated off under
    // `mb12-userprobe` so the IPC smoke build stays isolated.
    //
    // SAFETY: single-CPU; SHELL_VFS, SCHEDULER, FRAME_ALLOC are not aliased.
    // -------------------------------------------------------------------------
    #[cfg(all(
        target_arch = "x86_64",
        target_os = "none",
        not(test),
        not(feature = "mb12-userprobe")
    ))]
    #[allow(
        unsafe_code,
        reason = "single-core static-mut deref + spawn_from_elf; same invariant as the shell boot block"
    )]
    {
        early_console::write_str("[NexaCore OS] net boot: checking VFS for /bin/nexacore-net...\n");

        // SAFETY: single-CPU; SHELL_VFS not aliased.
        let net_found = unsafe {
            (*core::ptr::addr_of!(SHELL_VFS))
                .as_ref()
                .is_some_and(|v| v.exists("/bin/nexacore-net"))
        };

        if net_found {
            // SAFETY: single-CPU; SHELL_VFS read-only; SCHEDULER/FRAME_ALLOC not aliased.
            let spawn_result: Result<scheduling::TaskId, &'static str> = unsafe {
                'spawn: {
                    let Some(vfs_ref) = (*core::ptr::addr_of!(SHELL_VFS)).as_ref() else {
                        break 'spawn Err("VFS vanished");
                    };
                    let Ok(stat) = vfs_ref.stat("/bin/nexacore-net") else {
                        break 'spawn Err("stat /bin/nexacore-net failed");
                    };
                    #[allow(
                        clippy::cast_possible_truncation,
                        reason = "ELF size bounded by the VFS in-memory allocator; well under usize::MAX"
                    )]
                    let Ok(elf_bytes) = vfs_ref.read_file(stat.inode, 0, stat.size as usize) else {
                        break 'spawn Err("read /bin/nexacore-net failed");
                    };

                    let boot_cr3_val = bare_metal::boot_cr3();
                    let phys_off = bare_metal::phys_offset();
                    if boot_cr3_val == 0 || phys_off == 0 {
                        break 'spawn Err("boot_cr3 or phys_offset not set");
                    }
                    let mut net_mapper = bare_metal::paging::PageMapper::new(
                        phys_off,
                        memory::PhysAddr(boot_cr3_val),
                    );
                    let sched = &mut *core::ptr::addr_of_mut!(SCHEDULER);
                    let fa = &mut *core::ptr::addr_of_mut!(FRAME_ALLOC);
                    match process::ProcessControlBlock::spawn_from_elf(
                        &elf_bytes,
                        memory::PhysAddr(boot_cr3_val),
                        &mut net_mapper,
                        fa,
                        sched,
                        scheduling::PriorityClass::System,
                        capabilities::KernelPrincipal::ZERO,
                    ) {
                        Ok(id) => Ok(id),
                        Err(KernelError::ResourceExhausted) => Err("ResourceExhausted (OOM)"),
                        Err(KernelError::InvalidArgument) => Err("InvalidArgument (bad ELF)"),
                        Err(_) => Err("unknown spawn error"),
                    }
                }
            };

            match spawn_result {
                Ok(task_id) => {
                    early_console::write_str(
                        "[NexaCore OS] net boot: nexacore-net spawned as task_id=",
                    );
                    #[allow(
                        clippy::cast_possible_truncation,
                        reason = "task_id.0 is u64; cast to usize is safe on x86_64"
                    )]
                    early_console::write_usize(task_id.0 as usize);
                    early_console::write_str("\n");
                }
                Err(reason) => {
                    early_console::write_str("[NexaCore OS] net boot: spawn failed: ");
                    early_console::write_str(reason);
                    early_console::write_str("\n");
                }
            }
        } else {
            early_console::write_str(
                "[NexaCore OS] net boot: /bin/nexacore-net not found in VFS\n",
            );
        }
    }

    // -------------------------------------------------------------------------
    // Shell boot sequence — attempt to spawn `/bin/nexacore-shell` from the VFS as
    // PID 1 (the init process). This block is additive: if the binary has not
    // been embedded in the VFS (the normal case until the initramfs pipeline is
    // wired in Phase F.2), it logs a diagnostic and falls through to the
    // existing desktop demo. The existing boot path is unaffected.
    //
    // Phase 1 constraint: argv/envp are not forwarded to the child's user
    // stack (that requires access to the child's PML4 after spawn, which is
    // a Phase 2 concern). The shell ELF reads its configuration from
    // hardcoded defaults.
    //
    // SAFETY: single-CPU; SHELL_VFS, SCHEDULER, FRAME_ALLOC are not aliased.
    // -------------------------------------------------------------------------
    #[cfg(all(target_arch = "x86_64", target_os = "none", not(test)))]
    #[allow(
        unsafe_code,
        reason = "single-core static-mut deref + spawn_from_elf; same invariant as driver_loader"
    )]
    {
        early_console::write_str(
            "[NexaCore OS] shell boot: checking VFS for /bin/nexacore-shell...\n",
        );

        // SAFETY: single-CPU; SHELL_VFS not aliased.
        let shell_found = unsafe {
            (*core::ptr::addr_of!(SHELL_VFS))
                .as_ref()
                .is_some_and(|v| v.exists("/bin/nexacore-shell"))
        };

        if shell_found {
            early_console::write_str(
                "[NexaCore OS] shell boot: /bin/nexacore-shell found, spawning...\n",
            );

            // Read the ELF stat and bytes from the VFS.
            // SAFETY: single-CPU; SHELL_VFS read-only in this block.
            let spawn_result: Result<scheduling::TaskId, &'static str> = unsafe {
                let Some(vfs_ref) = (*core::ptr::addr_of!(SHELL_VFS)).as_ref() else {
                    early_console::write_str("[NexaCore OS] shell boot: VFS vanished\n");
                    bare_metal::arch::halt_forever();
                };

                let Ok(stat) = vfs_ref.stat("/bin/nexacore-shell") else {
                    bare_metal::arch::halt_forever();
                };

                #[allow(
                    clippy::cast_possible_truncation,
                    reason = "ELF size is bounded by the VFS in-memory allocator; well under usize::MAX"
                )]
                let Ok(elf_bytes) = vfs_ref.read_file(stat.inode, 0, stat.size as usize) else {
                    bare_metal::arch::halt_forever();
                };

                let boot_cr3_val = bare_metal::boot_cr3();
                let phys_off = bare_metal::phys_offset();

                if boot_cr3_val == 0 || phys_off == 0 {
                    Err("boot_cr3 or phys_offset not set")
                } else {
                    let mut shell_mapper = bare_metal::paging::PageMapper::new(
                        phys_off,
                        memory::PhysAddr(boot_cr3_val),
                    );
                    let sched = &mut *core::ptr::addr_of_mut!(SCHEDULER);
                    let fa = &mut *core::ptr::addr_of_mut!(FRAME_ALLOC);

                    match process::ProcessControlBlock::spawn_from_elf(
                        &elf_bytes,
                        memory::PhysAddr(boot_cr3_val),
                        &mut shell_mapper,
                        fa,
                        sched,
                        scheduling::PriorityClass::Interactive,
                        capabilities::KernelPrincipal::ZERO,
                    ) {
                        Ok(id) => Ok(id),
                        Err(KernelError::ResourceExhausted) => Err("ResourceExhausted (OOM)"),
                        Err(KernelError::InvalidArgument) => Err("InvalidArgument (bad ELF)"),
                        Err(_) => Err("unknown spawn error"),
                    }
                }
            };

            match spawn_result {
                Ok(task_id) => {
                    early_console::write_str("[NexaCore OS] shell boot: shell spawned as task_id=");
                    #[allow(
                        clippy::cast_possible_truncation,
                        reason = "task_id.0 is u64; cast to usize is safe on x86_64"
                    )]
                    early_console::write_usize(task_id.0 as usize);
                    early_console::write_str("\n");

                    // Update the process table entry for PID 1 / the init
                    // process that was pre-registered in kmain with
                    // `nexacore-shell` as a placeholder (no parent). We register
                    // the real task_id returned by spawn_from_elf in addition
                    // to the pre-registered slot so both identifiers work.
                    // If they happen to collide (unlikely), the table deduplicates
                    // by key, so this is harmless.
                    // SAFETY: single-CPU; SHELL_PROCESS_TABLE not aliased.
                    unsafe {
                        if let Some(pt) = (*core::ptr::addr_of_mut!(SHELL_PROCESS_TABLE)).as_mut() {
                            // Register the real spawned task id with no parent
                            // (it is the init process). The placeholder entry
                            // for TaskId(1) registered during shell-infra init
                            // remains for backwards compatibility with any path
                            // that hard-codes task 1.
                            if task_id != scheduling::TaskId(1) {
                                pt.register(
                                    task_id,
                                    None,
                                    alloc::string::String::from("nexacore-shell"),
                                );
                            }
                        }
                    }
                }
                Err(reason) => {
                    early_console::write_str("[NexaCore OS] shell boot: spawn failed: ");
                    early_console::write_str(reason);
                    early_console::write_str("\n");
                    early_console::write_str(
                        "[NexaCore OS] shell boot: falling through to desktop demo\n",
                    );
                }
            }
        } else {
            early_console::write_str(
                "[NexaCore OS] shell boot: /bin/nexacore-shell not found in VFS\n",
            );
            early_console::write_str("[NexaCore OS] shell boot: falling through to desktop demo\n");
        }

        // The Ring 3 shell process has been spawned (if its ELF was present in
        // the VFS) but we do NOT park the bootstrap task here.  The desktop
        // demo's terminal window calls `process_line` directly for every
        // command the user types, providing the Phase 1 interactive interface
        // without depending on the Ring 3 process being scheduled.  The Ring 3
        // process remains in the scheduler queue for future use.
    }

    // -------------------------------------------------------------------------
    // M0 netcheck self-test — spawn `/bin/nexacore-netcheck` (Ring 3) after the
    // shell. It issues NetSocket + NetConnect(192.0.2.11:11434); the kernel
    // relays to nexacore-net, which builds the SYN + ARP request and drives them
    // through the virtio-net driver onto the wire. Additive + best-effort:
    // absence (older initramfs) logs and the boot continues. Same cfg gating
    // as the shell.
    //
    // PRIORITY: netcheck is spawned at `System`, NOT `Interactive`. The
    // scheduler is strict-priority round-robin (scheduling.rs:pick_next /
    // preempt): both the cooperative-yield and timer-preempt paths take the
    // front of the highest non-empty run queue. The boot leaves three busy
    // `System` consumers permanently runnable — the kmain/desktop loop (a tight
    // poll loop that never blocks), the virtio-net driver image, and nexacore-net —
    // so `run_queues[System]` is never empty and `Interactive` tasks starve
    // indefinitely (observed: netcheck spawned but produced zero output across a
    // 35 s window). netcheck must share the System round-robin with the very
    // services it drives; the synchronous NetSocket/NetConnect relay
    // (syscall_entry.rs:net_socket_relay_full) parks netcheck `BlockedOnIpc` and
    // explicitly unparks nexacore-net, so the handoff is correct regardless of
    // class — the only requirement is that netcheck get a first slice at all,
    // which `System` guarantees. (A starvation-free scheduler / blocking idle
    // services are a post-M0 follow-up; demoting kmain is unsafe — the boot
    // sequence relies on it staying non-preempted to avoid the CR3-on-resume
    // #PF, see the P6.7.9-pre.8 note.)
    //
    // SAFETY: single-CPU; SHELL_VFS, SCHEDULER, FRAME_ALLOC are not aliased.
    //
    // GATING (TASK-13, ADR-0035): the spawn is gated behind the
    // `m0-netcheck` feature again — restoring the documented default-off
    // behaviour that was lost when the probe became part of the standard
    // boot during the M0 bring-up. Rationale: the M0 self-test and the AI
    // service's RemoteGpu path (nexacore-runtime-image `mod remote`) are two
    // concurrent TCP clients, and the M0 stack's connection handling is
    // not yet robust under that concurrency (observed: interleaved
    // sessions fail send/recv). The AI path now exercises the SAME
    // syscall→relay→nexacore-net→virtio chain — with a full POST/response
    // round-trip — on every boot, so the probe is redundant outside
    // dedicated M0 smoke builds (`--features m0-netcheck`).
    // -------------------------------------------------------------------------
    #[cfg(all(
        target_arch = "x86_64",
        target_os = "none",
        not(test),
        feature = "m0-netcheck",
        not(feature = "mb11-userprobe"),
        not(feature = "mb12-userprobe")
    ))]
    #[allow(
        unsafe_code,
        reason = "single-core static-mut deref + spawn_from_elf; same invariant as the shell boot block"
    )]
    {
        early_console::write_str(
            "[NexaCore OS] netcheck boot: checking VFS for /bin/nexacore-netcheck...\n",
        );

        // SAFETY: single-CPU; SHELL_VFS not aliased.
        let nc_found = unsafe {
            (*core::ptr::addr_of!(SHELL_VFS))
                .as_ref()
                .is_some_and(|v| v.exists("/bin/nexacore-netcheck"))
        };

        if nc_found {
            // SAFETY: single-CPU; SHELL_VFS read-only; SCHEDULER/FRAME_ALLOC not aliased.
            let spawn_result: Result<scheduling::TaskId, &'static str> = unsafe {
                'spawn: {
                    let Some(vfs_ref) = (*core::ptr::addr_of!(SHELL_VFS)).as_ref() else {
                        break 'spawn Err("VFS vanished");
                    };
                    let Ok(stat) = vfs_ref.stat("/bin/nexacore-netcheck") else {
                        break 'spawn Err("stat /bin/nexacore-netcheck failed");
                    };
                    #[allow(
                        clippy::cast_possible_truncation,
                        reason = "ELF size bounded by the VFS in-memory allocator; well under usize::MAX"
                    )]
                    let Ok(elf_bytes) = vfs_ref.read_file(stat.inode, 0, stat.size as usize) else {
                        break 'spawn Err("read /bin/nexacore-netcheck failed");
                    };

                    let boot_cr3_val = bare_metal::boot_cr3();
                    let phys_off = bare_metal::phys_offset();
                    if boot_cr3_val == 0 || phys_off == 0 {
                        break 'spawn Err("boot_cr3 or phys_offset not set");
                    }
                    let mut nc_mapper = bare_metal::paging::PageMapper::new(
                        phys_off,
                        memory::PhysAddr(boot_cr3_val),
                    );
                    let sched = &mut *core::ptr::addr_of_mut!(SCHEDULER);
                    let fa = &mut *core::ptr::addr_of_mut!(FRAME_ALLOC);
                    match process::ProcessControlBlock::spawn_from_elf(
                        &elf_bytes,
                        memory::PhysAddr(boot_cr3_val),
                        &mut nc_mapper,
                        fa,
                        sched,
                        // Background — netcheck's natural class. The old
                        // "System (not Interactive)" workaround existed only
                        // because strict-priority pick_next starved everything
                        // behind the System busy-poll loops; the TASK-06
                        // fairness rotation (ADR-0025) guarantees Background a
                        // pick per cycle, so the M0 exchange completes without
                        // priority inflation.
                        scheduling::PriorityClass::Background,
                        capabilities::KernelPrincipal::ZERO,
                    ) {
                        Ok(id) => Ok(id),
                        Err(KernelError::ResourceExhausted) => Err("ResourceExhausted (OOM)"),
                        Err(KernelError::InvalidArgument) => Err("InvalidArgument (bad ELF)"),
                        Err(_) => Err("unknown spawn error"),
                    }
                }
            };

            match spawn_result {
                Ok(task_id) => {
                    early_console::write_str("[NexaCore OS] netcheck boot: spawned as task_id=");
                    #[allow(
                        clippy::cast_possible_truncation,
                        reason = "task_id.0 is u64; cast to usize is safe on x86_64"
                    )]
                    early_console::write_usize(task_id.0 as usize);
                    early_console::write_str("\n");
                }
                Err(reason) => {
                    early_console::write_str("[NexaCore OS] netcheck boot: spawn failed: ");
                    early_console::write_str(reason);
                    early_console::write_str("\n");
                }
            }
        } else {
            early_console::write_str(
                "[NexaCore OS] netcheck boot: /bin/nexacore-netcheck not found in VFS\n",
            );
        }
    }

    // -------------------------------------------------------------------------
    // TASK-11 (DE-G6, ADR-0032) — AI runtime service + self-test client.
    //
    // `/bin/nexacore-runtime` is the Ring 3 counterpart of the AI syscall relay
    // (`ai_handlers::ai_relay`): it registers the `"ai"`/`"ai_reply"` channel
    // pair and serves AiSyscallRequests (mock provider until TASK-13 binds
    // the full engine). Spawned at `System` priority like nexacore-net — services
    // must win their first slices to register before clients probe them.
    //
    // `/bin/nexacore-aicheck` issues AiInvoke (80) + the EFAULT/ENOSPC negative
    // tests and prints the outcomes; `Background` priority (TASK-06 fairness
    // guarantees it a pick per rotation; it also retries on ENOENT, so spawn
    // ordering is not load-bearing).
    //
    // Both additive + best-effort: absence (older initramfs) logs and the
    // boot continues. Same cfg gating + SAFETY invariants as the netcheck
    // block above.
    // -------------------------------------------------------------------------
    #[cfg(all(
        target_arch = "x86_64",
        target_os = "none",
        not(test),
        not(feature = "mb11-userprobe"),
        not(feature = "mb12-userprobe")
    ))]
    #[allow(
        unsafe_code,
        reason = "single-core static-mut deref + spawn_from_elf; same invariant as the shell boot block"
    )]
    {
        // (VFS path, console tag, priority class)
        let ai_spawns: [(&str, &str, scheduling::PriorityClass); 2] = [
            (
                "/bin/nexacore-runtime",
                "ai-runtime",
                scheduling::PriorityClass::System,
            ),
            (
                "/bin/nexacore-aicheck",
                "aicheck",
                scheduling::PriorityClass::Background,
            ),
        ];

        for (path, tag, priority) in ai_spawns {
            early_console::write_str("[NexaCore OS] ");
            early_console::write_str(tag);
            early_console::write_str(" boot: checking VFS for ");
            early_console::write_str(path);
            early_console::write_str("...\n");

            // SAFETY: single-CPU; SHELL_VFS not aliased.
            let found = unsafe {
                (*core::ptr::addr_of!(SHELL_VFS))
                    .as_ref()
                    .is_some_and(|v| v.exists(path))
            };
            if !found {
                early_console::write_str("[NexaCore OS] ");
                early_console::write_str(tag);
                early_console::write_str(" boot: not found in VFS (older initramfs)\n");
                continue;
            }

            // SAFETY: single-CPU; SHELL_VFS read-only; SCHEDULER/FRAME_ALLOC
            // not aliased (same invariant as the netcheck block).
            let spawn_result: Result<scheduling::TaskId, &'static str> = unsafe {
                'spawn: {
                    let Some(vfs_ref) = (*core::ptr::addr_of!(SHELL_VFS)).as_ref() else {
                        break 'spawn Err("VFS vanished");
                    };
                    let Ok(stat) = vfs_ref.stat(path) else {
                        break 'spawn Err("stat failed");
                    };
                    #[allow(
                        clippy::cast_possible_truncation,
                        reason = "ELF size bounded by the VFS in-memory allocator; well under usize::MAX"
                    )]
                    let Ok(elf_bytes) = vfs_ref.read_file(stat.inode, 0, stat.size as usize) else {
                        break 'spawn Err("read failed");
                    };

                    let boot_cr3_val = bare_metal::boot_cr3();
                    let phys_off = bare_metal::phys_offset();
                    if boot_cr3_val == 0 || phys_off == 0 {
                        break 'spawn Err("boot_cr3 or phys_offset not set");
                    }
                    let mut mapper = bare_metal::paging::PageMapper::new(
                        phys_off,
                        memory::PhysAddr(boot_cr3_val),
                    );
                    let sched = &mut *core::ptr::addr_of_mut!(SCHEDULER);
                    let fa = &mut *core::ptr::addr_of_mut!(FRAME_ALLOC);
                    match process::ProcessControlBlock::spawn_from_elf(
                        &elf_bytes,
                        memory::PhysAddr(boot_cr3_val),
                        &mut mapper,
                        fa,
                        sched,
                        priority,
                        capabilities::KernelPrincipal::ZERO,
                    ) {
                        Ok(id) => Ok(id),
                        Err(KernelError::ResourceExhausted) => Err("ResourceExhausted (OOM)"),
                        Err(KernelError::InvalidArgument) => Err("InvalidArgument (bad ELF)"),
                        Err(_) => Err("unknown spawn error"),
                    }
                }
            };

            match spawn_result {
                Ok(task_id) => {
                    early_console::write_str("[NexaCore OS] ");
                    early_console::write_str(tag);
                    early_console::write_str(" boot: spawned as task_id=");
                    #[allow(
                        clippy::cast_possible_truncation,
                        reason = "task_id.0 is u64; cast to usize is safe on x86_64"
                    )]
                    early_console::write_usize(task_id.0 as usize);
                    early_console::write_str("\n");
                }
                Err(reason) => {
                    early_console::write_str("[NexaCore OS] ");
                    early_console::write_str(tag);
                    early_console::write_str(" boot: spawn failed: ");
                    early_console::write_str(reason);
                    early_console::write_str("\n");
                }
            }
        }
    }

    // -------------------------------------------------------------------------
    // MB8 smoke (feature-gated): spawn two tight-loop tasks that never yield
    // cooperatively, then enter a halt loop. Any 'A'/'B' interleaving on the
    // serial port proves that the LAPIC timer is preempting them.
    //
    // This branch never returns; the desktop demo + power-off below are
    // unreachable when the feature is on. Without the feature the kernel
    // falls through to the regular boot path.
    // -------------------------------------------------------------------------
    #[cfg(all(
        target_arch = "x86_64",
        target_os = "none",
        feature = "mb8-smoke",
        not(test)
    ))]
    bare_metal::mb8_smoke::run(&mut pager);

    // ELF64 parser probe (MB5): parse a minimal embedded test binary to verify
    // the parser is functional before any real userspace binary arrives.
    {
        use bare_metal::elf_loader;
        // A 120-byte hand-crafted ELF64 binary: ET_EXEC, EM_X86_64,
        // one PT_LOAD segment at 0x4000_0000, entry=0x4000_0000.
        static TEST_ELF: [u8; 120] = [
            0x7f, b'E', b'L', b'F', 2, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x02, 0x00, 0x3E, 0x00,
            0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x40, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x38, 0x00, 0x01, 0x00, 0x40, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x78, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00,
        ];
        if let Ok(elf) = elf_loader::Elf64::parse(&TEST_ELF) {
            early_console::write_str("[elf] probe OK  entry=");
            #[allow(
                clippy::cast_possible_truncation,
                reason = "x86_64 only; usize is u64 on target_os = none"
            )]
            early_console::write_usize(elf.entry_point() as usize);
            early_console::write_str("\n");
        } else {
            early_console::write_str("[elf] probe FAILED\n");
        }
    }

    // -------------------------------------------------------------------------
    // MB11 user-probe (feature-gated): spawn a Ring 3 process that issues
    // `WriteConsole("hello\n")` + `TaskExit(0)`, then transfer to user mode
    // via the `iretq` trampoline. `TaskExit` halts the CPU, so the desktop
    // demo below is unreachable under this feature.
    //
    // Smoke output expected (in addition to existing K5/LAPIC/sched lines):
    //   [user] address space activated cr3 = 0x...
    //   [user] entering Ring 3 rip = 0x40000000
    //   hello
    //   [user] exit=0
    // -------------------------------------------------------------------------
    #[cfg(all(
        target_arch = "x86_64",
        target_os = "none",
        feature = "mb11-userprobe",
        not(test)
    ))]
    #[allow(
        unsafe_code,
        reason = "single-core static-mut deref + Ring 3 entry; SAFETY in block"
    )]
    {
        use bare_metal::userprobe;
        // SAFETY: single-core; SCHEDULER/FRAME_ALLOC not aliased.
        unsafe {
            let sched = &mut *core::ptr::addr_of_mut!(SCHEDULER);
            let fa = &mut *core::ptr::addr_of_mut!(FRAME_ALLOC);
            match userprobe::spawn_userprobe(&mut pager, fa, sched) {
                Ok(task_id) => {
                    early_console::write_str("[user] userprobe spawned  task_id=");
                    #[allow(
                        clippy::cast_possible_truncation,
                        reason = "x86_64 only; usize is u64 on target_os = none"
                    )]
                    early_console::write_usize(task_id.0 as usize);
                    early_console::write_str("\n");
                    if let Some(pcb) = sched.process(task_id) {
                        early_console::write_str("[user] address space activated cr3 = ");
                        #[allow(
                            clippy::cast_possible_truncation,
                            reason = "x86_64 only; usize is u64 on target_os = none"
                        )]
                        early_console::write_usize(pcb.address_space.pml4_phys.0 as usize);
                        early_console::write_str("\n");
                        early_console::write_str("[user] entering Ring 3 rip = ");
                        #[allow(
                            clippy::cast_possible_truncation,
                            reason = "x86_64 only; usize is u64 on target_os = none"
                        )]
                        early_console::write_usize(pcb.user_entry as usize);
                        early_console::write_str("\n");
                        // This dev smoke dispatches the probe via enter_user_mode
                        // directly, bypassing scheduling::yield_current — which is
                        // where SYSCALL_KERNEL_RSP and TSS.rsp0 are normally set for
                        // a user task. Set them here so the probe's first SYSCALL
                        // lands on its kernel stack instead of RSP=0 (#PF), matching
                        // the production dispatch path (NCIP-026 §S4 / kernel-stack
                        // syscall migration).
                        let kstk_top = pcb.task.kernel_stack_va + scheduling::KERNEL_STACK_SIZE;
                        bare_metal::syscall_entry::set_syscall_kernel_rsp(kstk_top);
                        let _ = bare_metal::tss::set_rsp0_for_cpu(0, kstk_top);
                        bare_metal::usermode::enter_user_mode(
                            pcb.user_entry,
                            pcb.user_stack_top,
                            bare_metal::usermode::USER_RFLAGS,
                            pcb.address_space.pml4_phys.0,
                            kstk_top,
                        );
                    } else {
                        early_console::write_str("[user] PCB lookup FAILED\n");
                    }
                }
                Err(_) => early_console::write_str("[user] userprobe spawn FAILED\n"),
            }
        }
    }

    // -------------------------------------------------------------------------
    // MB12-userprobe — cross-process IPC smoke (Track B MB12)
    //
    // Spawns two Ring 3 processes:
    //   - receiver: `IpcReceive(ch=1, buf, 64, blocking=1)` → `WriteConsole` → `TaskExit`
    //   - sender:   `IpcSend(ch=1, kind=3, "ping", 4)` → `TaskExit`
    //
    // The channel is pre-created (open, no capability subject set) by
    // `spawn_userprobe_mb12`. After registering both tasks, `kmain` spawns
    // a bootstrap TCB for itself and `yield_current(Terminated)` to hand
    // the CPU over to the scheduler — the scheduler's MB12.0a/b path then
    // does the CR3 + TSS.rsp0 + iretq trampoline into the first
    // user-vergine task.
    //
    // Expected serial trace (interleaving depends on FIFO order):
    //   [mb12] receiver task_id=N + sender task_id=M + channel id pre-created
    //   ping              (receiver writes after IpcReceive completes)
    //   [user] exit=0     (sender)
    //   [user] exit=0     (receiver)
    //
    // Mutually exclusive with `mb11-userprobe`: when both features are
    // enabled in the same build, the MB11 block above runs first and
    // halts before reaching this code (TaskExit + halt_forever).
    // -------------------------------------------------------------------------
    #[cfg(all(
        target_arch = "x86_64",
        target_os = "none",
        feature = "mb12-userprobe",
        not(feature = "mb11-userprobe"),
        not(test)
    ))]
    #[allow(
        unsafe_code,
        reason = "single-core static-mut deref + Ring 3 entry; SAFETY in block"
    )]
    {
        use bare_metal::userprobe_mb12;
        use scheduling::{PriorityClass, Scheduler, TaskState};
        // SAFETY: single-core; SCHEDULER/FRAME_ALLOC not aliased.
        unsafe {
            let sched = &mut *core::ptr::addr_of_mut!(SCHEDULER);
            let fa = &mut *core::ptr::addr_of_mut!(FRAME_ALLOC);
            match userprobe_mb12::spawn_userprobe_mb12(&mut pager, fa, sched) {
                Ok((receiver_id, sender_id)) => {
                    early_console::write_str("[mb12] receiver task_id=");
                    #[allow(
                        clippy::cast_possible_truncation,
                        reason = "x86_64 only; usize is u64 on target_os = none"
                    )]
                    early_console::write_usize(receiver_id.0 as usize);
                    early_console::write_str("\n[mb12] sender   task_id=");
                    #[allow(
                        clippy::cast_possible_truncation,
                        reason = "x86_64 only; usize is u64 on target_os = none"
                    )]
                    early_console::write_usize(sender_id.0 as usize);
                    early_console::write_str("\n[mb12] channel 1 pre-created\n");

                    // Register the currently-executing `kmain` flow as a
                    // bootstrap task so `yield_current` has a `current` to
                    // save context for. The yield to `Terminated` keeps
                    // kmain off the run queue forever; the scheduler then
                    // dispatches the first user process via the MB12.0a/b
                    // first-dispatch path.
                    let _ = sched.spawn_bootstrap_task(PriorityClass::System);
                    if let Some(kmain_id) = sched.current_task_id() {
                        early_console::write_str("[mb12] handing off to user tasks\n");
                        let _ = sched.yield_current(kmain_id, TaskState::Terminated);
                    }
                    // If we ever return here (no runnable task picked),
                    // fall through to halt_forever below.
                    early_console::write_str("[mb12] all user tasks finished\n");
                }
                Err(_) => early_console::write_str("[mb12] spawn FAILED\n"),
            }
        }
        // Silence the desktop-demo arguments — when `mb12-userprobe`
        // is enabled the desktop never runs, so its inputs would
        // otherwise trip unused-variable warnings.
        let _ = framebuffer;
        let _ = region_count;
        let _ = free_mib;
        let _ = total_mib;
        let _ = phys_offset_mb2;
        // Same: the MB14.a sysinfo carries (BSP LAPIC ID + enabled CPU
        // count) are surfaced only to `render_sysinfo` in the desktop
        // path. Silence them on the mb12-userprobe build to keep the
        // workspace warning-clean.
        let _ = sysinfo_cpu_total;
        let _ = sysinfo_bsp_apic_id;
        // After both user processes terminate (or on spawn failure),
        // park the kernel. `halt_forever` diverges (`-> !`) so the
        // subsequent desktop block becomes unreachable on this build.
        bare_metal::arch::halt_forever();
    }

    // -------------------------------------------------------------------------
    // (The DEV-ONLY driver probe auto-loader was relocated to BEFORE the first
    // `spawn_from_elf` — see the "P6.7.9-pre.8" block earlier in kmain. It must
    // run before any per-process PML4 clone so the in-kernel NVMe BAR mapping
    // stays on the boot CR3 at read time; otherwise kmain, resumed on a user
    // CR3 after a timer preempt, faults #PF on the un-propagated mapping.
    // 2026-05-30.)
    // -------------------------------------------------------------------------

    // -------------------------------------------------------------------------
    // Branded desktop boot (TASK-18/19/20/22, WS7-19) — the DEFAULT graphical
    // boot path. Formerly gated behind the `display-probe` bring-up feature;
    // promoted to the default so a stock ISO boots the branded compositor
    // desktop instead of the `run_desktop` demo (WS7-19: the demo is now only a
    // fallback for image-less builds).
    //
    //   1. Create a NO-CAP `Notification` IPC channel owned by the bootstrap
    //      task. This is the kernel-side display input channel; the display
    //      image drains it via `IpcTryReceive (24)`.
    //   2. Spawn the richest display image present in the initramfs VFS
    //      (`/bin/nexacore-apps-image` preferred; see the read_elf chain) and
    //      deposit a `DisplayMap` capability + the input channel id (the
    //      overloaded VirtioDeviceInfo section carries the display geometry).
    //   3. IF an image was spawned, become its input pump: `ps2_poll()` →
    //      encode a `DisplayInputEvent` → `ipc::send` into the channel →
    //      `sched.yield_current`. This runs FOREVER, so the `run_desktop`
    //      fallback below is reached ONLY when NO display image is present.
    //
    // Compiled out only for the mutually-exclusive `mb11`/`mb12-userprobe`
    // smokes (which drive their own boot wiring) and host tests.
    // -------------------------------------------------------------------------
    #[cfg(all(
        target_arch = "x86_64",
        target_os = "none",
        not(feature = "mb11-userprobe"),
        not(feature = "mb12-userprobe"),
        not(test)
    ))]
    #[allow(
        unsafe_code,
        reason = "single-core static-mut deref (SCHEDULER, FRAME_ALLOC, IPC_REGISTRY); \
                  SAFETY documented per site"
    )]
    {
        use bare_metal::driver_loader;
        use ipc::{ChannelId, MessageEnvelope, MessageKind};
        use nexacore_types::display_channel::{DisplayInputEvent, keycode};
        use scheduling::{Scheduler, TaskState};

        // Step 1: the no-cap input channel — created BEFORE the xHCI driver
        // spawn (see the display-input-channel block above) so the USB HID
        // producer received its id in the deposit; reused here for the
        // display image + the PS/2 pump.
        let input_ch: ChannelId = display_input_ch;

        // Step 2: spawn the richest display image from VFS (if present).
        // `display_spawned` records whether the framebuffer was handed to a
        // Ring-3 image, deciding between the input-pump session and the
        // `run_desktop` fallback below.
        //
        // SAFETY: single-CPU boot path; the kernel singletons are not aliased.
        let display_spawned = unsafe {
            let sched = &mut *core::ptr::addr_of_mut!(SCHEDULER);
            let fa = &mut *core::ptr::addr_of_mut!(FRAME_ALLOC);

            // Prefer the apps shell (`/bin/nexacore-apps-image`, TASK-22:
            // terminal + editor), then the nexacore-ui demo
            // (`/bin/nexacore-ui-demo-image`, TASK-20), then the bare compositor
            // (`/bin/nexacore-display-image`, TASK-19), then the TASK-18
            // `/bin/nexacore-display-probe`. All consume the identical Display-cap
            // + input-channel + framebuffer-geometry deposit, so the boot path
            // is shared. (The NCFS FS service `/bin/nexacore-fsd` runs as a
            // separate non-display BLK-client task — see the spawn block above.)
            let probe_elf_opt = {
                // SAFETY: SHELL_VFS is the boot-init'd VFS singleton (written
                // once before any Ring-3 task runs); reading it here is safe.
                let vfs_ref = &*core::ptr::addr_of!(SHELL_VFS);
                (*vfs_ref).as_ref().and_then(|vfs| {
                    let read_elf = |path: &str| {
                        vfs.stat(path).ok().and_then(|stat| {
                            #[allow(
                                clippy::cast_possible_truncation,
                                reason = "VFS file sizes fit usize on x86_64 (target_os = none)"
                            )]
                            vfs.read_file(stat.inode, 0, stat.size as usize).ok()
                        })
                    };
                    read_elf("/bin/nexacore-apps-image")
                        .or_else(|| read_elf("/bin/nexacore-ui-demo-image"))
                        .or_else(|| read_elf("/bin/nexacore-display-image"))
                        .or_else(|| read_elf("/bin/nexacore-display-probe"))
                })
            };

            if let Some(ref elf_bytes) = probe_elf_opt {
                if let Some(fb_info) = bare_metal::graphics::framebuffer_info() {
                    driver_loader::boot_load_display_probe_image(
                        elf_bytes, fb_info, input_ch, &mut pager, fa, sched,
                    );
                    true
                } else {
                    early_console::write_str(
                        "[display] no FramebufferInfo — skipping display task spawn\n",
                    );
                    false
                }
            } else {
                early_console::write_str(
                    "[display] no display task (nexacore-display-image / -probe) in VFS — skipping\n",
                );
                false
            }
        };

        // Step 3: when a display image was spawned, this bootstrap task becomes
        // its cooperative input pump and runs FOREVER — so the `run_desktop`
        // fallback below is reached ONLY when no display image is present.
        //
        // `ps2_poll()` → encode `DisplayInputEvent` → `ipc::send` → yield.
        // NOT run from the timer ISR (alloc+lock on interrupt path is unsafe).
        //
        // SAFETY: single-CPU; IPC_REGISTRY and SCHEDULER accessed under the
        // single-core no-preemption invariant of each iteration (send
        // completes before yield hands off).
        if display_spawned {
            // Enable both PS/2 ports and track an absolute cursor, accumulated
            // from relative mouse packets and clamped to the framebuffer (start
            // at screen centre). Keyboard make codes share the same channel.
            bare_metal::input::ps2_keyboard_init();
            bare_metal::input::ps2_mouse_init();
            #[allow(
                clippy::cast_possible_wrap,
                reason = "framebuffer dimensions are small positive pixel counts"
            )]
            let (fb_w, fb_h) = bare_metal::graphics::framebuffer_info()
                .map_or((1i32, 1i32), |fb| {
                    (fb.width.max(1) as i32, fb.height.max(1) as i32)
                });
            let mut cursor_x: i32 = fb_w / 2;
            let mut cursor_y: i32 = fb_h / 2;

            loop {
                use bare_metal::input::{Key, ps2_mouse_poll, ps2_poll};

                // Drain the mouse FIRST (input.rs contract), accumulating an
                // absolute position (PS/2 dy is already down-positive).
                #[allow(
                    clippy::cast_sign_loss,
                    reason = "cursor_x/y are clamped to [0, fb-1], so they are non-negative"
                )]
                let mouse_ev = ps2_mouse_poll().map(|m| {
                    cursor_x = (cursor_x + m.dx).clamp(0, fb_w - 1);
                    cursor_y = (cursor_y + m.dy).clamp(0, fb_h - 1);
                    DisplayInputEvent::Pointer {
                        x: cursor_x as u32,
                        y: cursor_y as u32,
                        buttons: m.buttons,
                    }
                });
                // Then the keyboard.
                let key_ev = ps2_poll().map(|key| {
                    let code = match key {
                        Key::Char(c) => c,
                        Key::Escape => keycode::ESCAPE,
                        Key::Enter => keycode::ENTER,
                        Key::Backspace => keycode::BACKSPACE,
                        Key::Tab => keycode::TAB,
                        Key::ArrowUp => keycode::ARROW_UP,
                        Key::ArrowDown => keycode::ARROW_DOWN,
                        Key::ArrowLeft => keycode::ARROW_LEFT,
                        Key::ArrowRight => keycode::ARROW_RIGHT,
                    };
                    DisplayInputEvent::Key {
                        code,
                        pressed: true,
                    }
                });

                // Emit the mouse update before the keystroke this tick.
                for ev in [mouse_ev, key_ev].into_iter().flatten() {
                    if let Ok(payload) = nexacore_types::wire::encode_canonical(&ev) {
                        let envelope = MessageEnvelope {
                            sender: scheduling::TaskId(0),
                            channel: input_ch,
                            kind: MessageKind::Notification,
                            payload,
                        };
                        // SAFETY: single-CPU; ipc_registry_mut() is the sole
                        // &mut accessor; no interrupt handler calls send().
                        let _ = unsafe {
                            ipc::ipc_registry_mut().send(
                                envelope,
                                scheduling::TaskId(0),
                                crate::capabilities::KernelPrincipal::ZERO,
                            )
                        };
                    }
                }

                // Cooperative yield so the display task can drain the channel.
                // SAFETY: single-CPU; SCHEDULER not aliased.
                unsafe {
                    let sched = &mut *core::ptr::addr_of_mut!(SCHEDULER);
                    if let Some(kmain_id) = sched.current_task_id() {
                        let _ = sched.yield_current(kmain_id, TaskState::Runnable);
                    }
                }
            }
        }
    }

    // -------------------------------------------------------------------------
    // Graphical desktop — blocks until the user requests power-off, then
    // draws the power-off overlay before returning.
    //
    // Unreachable when `mb12-userprobe` is on (the MB12 block above
    // ends in `halt_forever` / `-> !`); silence the lint locally so
    // the rest of the kmain body stays warning-clean.
    // -------------------------------------------------------------------------
    // -------------------------------------------------------------------------
    // WI-7b step 3 C1 (NCIP-026 R2, TASK-07, ADR-0028) — IOMMU TE finalize.
    //
    // Operator-gated behind `iommu-te` (OFF by default / in CI). Runs AFTER
    // every device bring-up + the confined driver's IOMMU bind, and BEFORE
    // the desktop loop: installs a passthrough context-entry baseline for
    // every other DMA-capable device, then raises VT-d `GCMD.TE`. The
    // driver's `DmaMap` calls have already run by this point (timer-preempted
    // during the boot spawns), but C1's all-passthrough baseline does not
    // depend on that — it only needs every device to have SOME context entry
    // so the flip cannot fault it.
    //
    // SAFETY: single-CPU boot path; `FRAME_ALLOC` is the live kernel frame
    // allocator and is not otherwise aliased here; the VT-d unit was
    // activated earlier in kmain.
    // -------------------------------------------------------------------------
    #[cfg(all(target_arch = "x86_64", target_os = "none", feature = "iommu-te"))]
    #[allow(
        unsafe_code,
        reason = "single-core static-mut deref into FRAME_ALLOC for the IOMMU TE-finalize boot step"
    )]
    unsafe {
        let fa = &mut *core::ptr::addr_of_mut!(FRAME_ALLOC);
        bare_metal::driver_loader::iommu_finalize_enable_translation(fa);
    }

    #[allow(
        unreachable_code,
        reason = "mb12-userprobe path diverges before reaching the desktop"
    )]
    let exit_action = demo::run_desktop(
        framebuffer,
        region_count,
        free_mib,
        total_mib,
        phys_offset_mb2,
        sysinfo_cpu_total,
        sysinfo_bsp_apic_id,
    );

    let rsdp = boot_info.rsdp_addr.into_option();
    let phys_off = boot_info.physical_memory_offset.into_option();

    match exit_action {
        demo::DesktopExitAction::Reboot => {
            match (rsdp, phys_off) {
                (Some(rsdp_phys), Some(offset)) => {
                    // SAFETY: bootloader maps all physical memory at `offset`;
                    // RSDP and ACPI tables are within that window.
                    #[allow(
                        unsafe_code,
                        reason = "ACPI FADT RESET_REG walk via bootloader direct map"
                    )]
                    unsafe {
                        arch::acpi_reboot_from_fadt(rsdp_phys, offset);
                    }
                }
                _ => arch::acpi_reboot(),
            }
        }
        demo::DesktopExitAction::PowerOff => match (rsdp, phys_off) {
            (Some(rsdp_phys), Some(offset)) => {
                #[allow(unsafe_code, reason = "ACPI table walk via bootloader direct map")]
                unsafe {
                    arch::acpi_poweroff_from_fadt(rsdp_phys, offset);
                }
            }
            _ => arch::acpi_poweroff(),
        },
    }
    arch::halt_forever()
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod sanity {
    use super::KernelError;

    #[test]
    fn kernel_error_is_small() {
        // The error enum should fit in 1 or 2 bytes so it can be returned
        // efficiently from syscall fast-paths.
        assert!(core::mem::size_of::<KernelError>() <= 2);
    }
}
