//! MB14.d — TLB shootdown via broadcast IPI on vector `0xFD`.
//!
//! When the BSP modifies a kernel-half mapping (the kernel half is shared
//! by reference across every per-process PML4 — see [`super::address_space`]
//! ADR-0004 § 4) every other logical CPU may have stale TLB entries
//! covering the affected virtual range. Linux pattern: write the target
//! VA range into a shared descriptor, broadcast a Fixed-delivery IPI on a
//! dedicated vector, and busy-poll an ack counter the handler increments
//! after issuing `invlpg` locally.
//!
//! ## Scope (MB14.d)
//!
//! - Vector [`TLB_SHOOTDOWN_VECTOR`] = `0xFD`, installed in the global
//!   kernel IDT by [`super::idt::idt_init`] hook in MB14.d closure.
//! - Shared [`Shootdown`] descriptor (atomic VA + page count + ack +
//!   generation). Single-writer (BSP) under MB14.d; future MB14.e will
//!   serialise multiple writers via a kernel-level spinlock per the
//!   ADR-0007 roadmap.
//! - [`flush_tlb_range`] entry point: local `invlpg` loop on the BSP,
//!   then `ipi::send_to_all_except_self(0xFD)` + busy-poll the ack
//!   counter against [`super::per_cpu::registered_ap_count`].
//! - 0xFD ISR (asm trampoline + Rust callback) reads the descriptor,
//!   issues `invlpg` per 4 KiB page, EOI's the LAPIC, then `fetch_add(1)`
//!   on the ack counter.
//!
//! ## Why a separate generation counter
//!
//! With multiple in-flight shootdowns (Phase 2 territory) an AP must not
//! ack a previous-generation request — otherwise the BSP races on stale
//! acks. The handler reads `generation` once at entry and acks against
//! that snapshot; the BSP busy-poll predicate is
//! `ack_for_generation == registered_ap_count()`. MB14.d only emits one
//! shootdown at a time (BSP is single-threaded outside IRQs) so the
//! generation field is informational, but the wire is laid for the
//! Phase 2 lock + queue.
//!
//! ## Why this lives outside `mm`
//!
//! `mm` (added later in MB14.d) re-exports [`flush_tlb_range`] as a
//! one-liner so callers say `mm::flush_tlb_range(...)` per the kernel
//! house style; the implementation stays here next to the LAPIC + ISR
//! plumbing.

#![allow(
    unsafe_code,
    reason = "ISR asm stub + raw VA invlpg + LAPIC EOI; SAFETY per call site"
)]

use core::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

use crate::memory::VirtAddr;

/// IDT vector reserved for TLB shootdown broadcasts.
///
/// `0xFD` sits in the high-priority range Intel SDM recommends for
/// kernel-internal IPIs (above the spurious vector 0xFF and below the
/// APIC error vector 0xFE). Pinned as a constant so the IDT installer
/// and the ICR encoder share a single source of truth.
pub const TLB_SHOOTDOWN_VECTOR: u8 = 0xFD;

/// Hard cap on the number of pages a single shootdown can flush before
/// the handler degenerates to a `mov cr3` self-flush.
///
/// 64 pages = 256 KiB. Beyond that the per-`invlpg` cost outstrips a
/// CR3 reload on every CPU; the BSP still issues a per-page broadcast
/// up to this cap, then promotes to a full-flush hint encoded as
/// `page_count = u64::MAX`. The MB14.d handler honours the hint by
/// reloading CR3 from itself (preserving the active address space).
pub const SHOOTDOWN_MAX_PAGES: u64 = 64;

/// Sentinel value for "flush the whole TLB" (descriptor `page_count`).
pub const SHOOTDOWN_FULL_FLUSH: u64 = u64::MAX;

/// Shared shootdown descriptor.
///
/// One global instance (`SHOOTDOWN`); the BSP populates it before
/// raising the IPI, and every AP-side handler reads it (with `Acquire`
/// ordering) before issuing `invlpg` and incrementing [`Self::ack`].
#[repr(C)]
pub struct Shootdown {
    /// First VA in the range to invalidate.
    pub va_start: AtomicU64,
    /// Number of contiguous 4 KiB pages starting at `va_start`. The
    /// special value [`SHOOTDOWN_FULL_FLUSH`] requests a full TLB flush
    /// via CR3 reload.
    pub page_count: AtomicU64,
    /// Monotonic generation counter — bumped by the BSP at the start of
    /// every shootdown so APs can disambiguate stale acks.
    pub generation: AtomicU64,
    /// Number of APs that have acknowledged the current generation.
    /// Reset to 0 by the BSP before raising the IPI.
    pub ack: AtomicUsize,
}

impl Shootdown {
    /// Zero-initialised descriptor (suitable for a `static`).
    #[must_use]
    pub const fn new() -> Self {
        Self {
            va_start: AtomicU64::new(0),
            page_count: AtomicU64::new(0),
            generation: AtomicU64::new(0),
            ack: AtomicUsize::new(0),
        }
    }
}

impl Default for Shootdown {
    fn default() -> Self {
        Self::new()
    }
}

/// Global descriptor read by every CPU's 0xFD handler.
static SHOOTDOWN: Shootdown = Shootdown::new();

/// Read-only accessor for tests + diagnostics.
#[must_use]
pub fn shootdown() -> &'static Shootdown {
    &SHOOTDOWN
}

/// Maximum BSP-side busy-poll iterations while waiting for every AP to
/// ack. Matched against [`super::mp::start_aps_live`] so a stuck AP does
/// not hang boot; ~1 s wall-clock on modern silicon.
const ACK_POLL_ITERATIONS: u64 = 200_000_000;

/// Outcome of a [`flush_tlb_range`] call.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ShootdownReport {
    /// Number of registered APs the BSP expected to ack.
    pub targeted: usize,
    /// Number of APs that acked within `ACK_POLL_ITERATIONS`.
    pub acked: usize,
    /// Number of pages the local CPU `invlpg`-ed before broadcasting.
    pub local_pages: u64,
    /// `true` if the request was a full-flush (`page_count` overflow).
    pub full_flush: bool,
}

impl ShootdownReport {
    /// `true` iff every targeted AP acked.
    #[must_use]
    pub const fn complete(&self) -> bool {
        self.acked >= self.targeted
    }
}

/// Local-CPU only TLB invalidation across `[va_start, va_start + len)`.
///
/// `len` is rounded up to the next 4 KiB page boundary. Returns the
/// page count actually invalidated, or [`SHOOTDOWN_FULL_FLUSH`] if the
/// request exceeded [`SHOOTDOWN_MAX_PAGES`] (in which case the function
/// reloads `CR3` to drop the whole TLB).
///
/// Available on host builds as a page-count compute only — `invlpg` is
/// a privileged Ring-0 instruction so the real loop is gated to
/// `target_os = "none"`.
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
pub fn invalidate_local(va_start: VirtAddr, len: u64) -> u64 {
    let pages = pages_in_range(len);
    if pages > SHOOTDOWN_MAX_PAGES {
        flush_full_local();
        return SHOOTDOWN_FULL_FLUSH;
    }
    for i in 0..pages {
        let va = va_start.0.wrapping_add(i.wrapping_mul(0x1000));
        invlpg_one(va);
    }
    pages
}

/// Host stub for [`invalidate_local`].
///
/// `invlpg` is privileged Ring-0 and would `#GP` (SIGSEGV under Linux)
/// if executed from userspace, so the host test build only computes the
/// page count and reports the same full-flush sentinel the bare-metal
/// path would — keeping the [`ShootdownReport`] shape verifiable
/// without the asm.
#[cfg(not(all(target_arch = "x86_64", target_os = "none")))]
pub fn invalidate_local(_va_start: VirtAddr, len: u64) -> u64 {
    let pages = pages_in_range(len);
    if pages > SHOOTDOWN_MAX_PAGES {
        SHOOTDOWN_FULL_FLUSH
    } else {
        pages
    }
}

/// Public entry point — invalidate `[va_start, va_start + len)` on the
/// local CPU then broadcast a TLB shootdown IPI to every other CPU.
///
/// Returns a [`ShootdownReport`] suitable for the boot-log serial
/// banner. When no APs have been registered (BSP-only boot), the
/// function still issues the local `invlpg` and returns
/// `targeted = 0, acked = 0, complete()`.
#[must_use]
pub fn flush_tlb_range(va_start: VirtAddr, len: u64) -> ShootdownReport {
    let local_pages = invalidate_local(va_start, len);
    let full_flush = local_pages == SHOOTDOWN_FULL_FLUSH;
    let targeted = super::per_cpu::registered_ap_count();

    if targeted == 0 {
        return ShootdownReport {
            targeted: 0,
            acked: 0,
            local_pages,
            full_flush,
        };
    }

    // Populate the descriptor + bump the generation BEFORE raising the
    // IPI so the handler — which acquires `generation` first — observes
    // the new request. `Release` stores pair with `Acquire` loads in
    // [`tlb_shootdown_handler`].
    let req_page_count = if full_flush {
        SHOOTDOWN_FULL_FLUSH
    } else {
        local_pages
    };
    SHOOTDOWN.va_start.store(va_start.0, Ordering::Relaxed);
    SHOOTDOWN
        .page_count
        .store(req_page_count, Ordering::Relaxed);
    SHOOTDOWN.ack.store(0, Ordering::Relaxed);
    let _ = SHOOTDOWN.generation.fetch_add(1, Ordering::Release);

    let sent = super::ipi::send_to_all_except_self(TLB_SHOOTDOWN_VECTOR);
    if !sent {
        // LAPIC unavailable — no broadcast was issued. Surface the
        // local-only result to the caller.
        return ShootdownReport {
            targeted,
            acked: 0,
            local_pages,
            full_flush,
        };
    }

    // Host-build short-circuit. On `target_os = "none"` we busy-poll the
    // real ack counter incremented by the 0xFD handler running on each
    // AP. On any other host the broadcast has no observable side effect
    // (LAPIC unmapped → `send_to_all_except_self` already returned
    // `false` and short-circuited above; this branch is only reachable
    // from a host with a registered AP slot left over by an earlier
    // unit test, in which case we deliberately skip the multi-second
    // busy-loop and report zero acks).
    let acked = if cfg!(all(target_arch = "x86_64", target_os = "none")) {
        busy_wait_for_acks(targeted)
    } else {
        SHOOTDOWN.ack.load(Ordering::Acquire)
    };
    ShootdownReport {
        targeted,
        acked,
        local_pages,
        full_flush,
    }
}

/// Busy-poll the ack counter until either every AP has acknowledged the
/// current generation or [`ACK_POLL_ITERATIONS`] elapses. Returns the
/// observed ack count.
fn busy_wait_for_acks(targeted: usize) -> usize {
    let mut iter: u64 = 0;
    while iter < ACK_POLL_ITERATIONS {
        let acked = SHOOTDOWN.ack.load(Ordering::Acquire);
        if acked >= targeted {
            return acked;
        }
        core::hint::spin_loop();
        iter = iter.wrapping_add(1);
    }
    SHOOTDOWN.ack.load(Ordering::Acquire)
}

/// Round `len` up to the next 4 KiB page boundary.
#[must_use]
pub const fn pages_in_range(len: u64) -> u64 {
    len.wrapping_add(0x0FFF) >> 12
}

#[cfg(all(target_arch = "x86_64", target_os = "none"))]
fn invlpg_one(va: u64) {
    // SAFETY: `invlpg` is a privileged Ring-0 instruction with no side
    // effect beyond invalidating the TLB entry for `va`. `va` may point
    // anywhere — `invlpg` is well-defined for unmapped addresses (it
    // simply does nothing in that case).
    unsafe {
        core::arch::asm!(
            "invlpg [{0}]",
            in(reg) va,
            options(nostack, preserves_flags)
        );
    }
}

#[cfg(all(target_arch = "x86_64", target_os = "none"))]
fn flush_full_local() {
    // SAFETY: reloading CR3 with its current value invalidates every
    // non-global TLB entry — the canonical "full flush" idiom. Ring 0,
    // no side effects beyond the TLB.
    unsafe {
        let cr3: u64;
        core::arch::asm!("mov {0}, cr3", out(reg) cr3, options(nostack, preserves_flags));
        core::arch::asm!("mov cr3, {0}", in(reg) cr3, options(nostack, preserves_flags));
    }
}

// =============================================================================
// 0xFD ISR — assembly trampoline + Rust callback.
// =============================================================================

// Asm stub modelled on `nexacore_lapic_timer_handler`: saves caller-saved
// registers, calls the Rust handler, restores them, `iretq`.
//
// Alignment: same as the timer stub. Interrupt entry pushes 40 bytes
// (SS/RSP/RFLAGS/CS/RIP) → RSP %16 == 8. We push 9 regs × 8 = 72 →
// RSP %16 == (8 + 72) % 16 == 0. `call` pushes 8 → RSP %16 == 8 at
// callee entry, which satisfies the System V AMD64 ABI.
#[cfg(all(target_arch = "x86_64", target_os = "none", not(test)))]
core::arch::global_asm!(
    ".global nexacore_tlb_shootdown_handler",
    "nexacore_tlb_shootdown_handler:",
    "    push rax",
    "    push rcx",
    "    push rdx",
    "    push rsi",
    "    push rdi",
    "    push r8",
    "    push r9",
    "    push r10",
    "    push r11",
    "    call kernel_tlb_shootdown_handler",
    "    pop r11",
    "    pop r10",
    "    pop r9",
    "    pop r8",
    "    pop rdi",
    "    pop rsi",
    "    pop rdx",
    "    pop rcx",
    "    pop rax",
    "    iretq",
);

#[cfg(all(target_arch = "x86_64", target_os = "none", not(test)))]
unsafe extern "C" {
    /// Address of the `nexacore_tlb_shootdown_handler` symbol defined by the
    /// `global_asm!` block above. Used by `idt_init` to install the
    /// 0xFD vector.
    pub fn nexacore_tlb_shootdown_handler();
}

/// Host-side stub — keeps the symbol resolvable from `cargo test
/// --workspace --all-features` builds without pulling in the asm body.
#[cfg(not(all(target_arch = "x86_64", target_os = "none", not(test))))]
#[allow(
    dead_code,
    reason = "host stub keeps the address-of expression valid from idt_init under cargo test"
)]
pub extern "C" fn nexacore_tlb_shootdown_handler() {}

/// Rust callback invoked by the asm trampoline. Single source of truth
/// for what each receiving CPU does on a TLB shootdown IPI.
///
/// 1. Snapshot the descriptor (Acquire on `generation`, Relaxed on the
///    range fields the generation already ordered).
/// 2. Issue per-page `invlpg`, or fall back to CR3 reload on a
///    full-flush request.
/// 3. EOI the LAPIC so the next IPI can be delivered.
/// 4. `fetch_add(1, Release)` on the ack counter.
#[unsafe(no_mangle)]
extern "C" fn kernel_tlb_shootdown_handler() {
    // `generation` ordered-acquire so the va_start/page_count writes
    // the BSP issued *before* bumping generation are visible to us.
    let _gen = SHOOTDOWN.generation.load(Ordering::Acquire);
    let pc = SHOOTDOWN.page_count.load(Ordering::Relaxed);
    let va_start = SHOOTDOWN.va_start.load(Ordering::Relaxed);

    #[cfg(all(target_arch = "x86_64", target_os = "none"))]
    {
        if pc == SHOOTDOWN_FULL_FLUSH || pc > SHOOTDOWN_MAX_PAGES {
            flush_full_local();
        } else {
            for i in 0..pc {
                let va = va_start.wrapping_add(i.wrapping_mul(0x1000));
                invlpg_one(va);
            }
        }
    }
    #[cfg(not(all(target_arch = "x86_64", target_os = "none")))]
    {
        // Host build: `invlpg` / `mov cr3` are privileged Ring-0
        // instructions that would `#GP` (SIGSEGV under Linux) in
        // userspace. Keep the symbol exercised — the descriptor read
        // path is still verified, only the asm-emitting branches are
        // suppressed.
        let _ = (pc, va_start);
    }

    super::lapic::lapic_eoi();
    let _ = SHOOTDOWN.ack.fetch_add(1, Ordering::Release);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pages_in_range_rounds_up_to_page_boundary() {
        assert_eq!(pages_in_range(0), 0);
        assert_eq!(pages_in_range(1), 1);
        assert_eq!(pages_in_range(0x1000), 1);
        assert_eq!(pages_in_range(0x1001), 2);
        assert_eq!(pages_in_range(0x4000), 4);
    }

    #[test]
    fn shootdown_full_flush_sentinel_does_not_collide_with_valid_count() {
        // SHOOTDOWN_FULL_FLUSH must be unambiguously larger than the
        // cap; otherwise a legitimate full-cap request would be
        // misinterpreted as a full-flush. `const _` so clippy treats
        // this as a compile-time assertion rather than a runtime
        // `assert!(true)` it would optimise out.
        const _: () = assert!(SHOOTDOWN_FULL_FLUSH > SHOOTDOWN_MAX_PAGES);
    }

    #[test]
    fn vector_byte_is_0xfd() {
        // MB14.d wire-level pin: the kernel and the encoder MUST agree
        // on 0xFD or the broadcast hits the wrong ISR.
        assert_eq!(TLB_SHOOTDOWN_VECTOR, 0xFD);
    }

    #[test]
    fn report_complete_predicate_matches_targeted_zero() {
        let r = ShootdownReport {
            targeted: 0,
            acked: 0,
            local_pages: 1,
            full_flush: false,
        };
        assert!(r.complete());
    }

    #[test]
    fn report_complete_predicate_matches_acks_equal_targets() {
        let r = ShootdownReport {
            targeted: 3,
            acked: 3,
            local_pages: 1,
            full_flush: false,
        };
        assert!(r.complete());
    }

    #[test]
    fn report_incomplete_when_acks_below_targets() {
        let r = ShootdownReport {
            targeted: 3,
            acked: 1,
            local_pages: 1,
            full_flush: false,
        };
        assert!(!r.complete());
    }

    #[test]
    fn shootdown_default_initial_state_is_zero() {
        let sd = Shootdown::default();
        assert_eq!(sd.va_start.load(Ordering::Relaxed), 0);
        assert_eq!(sd.page_count.load(Ordering::Relaxed), 0);
        assert_eq!(sd.generation.load(Ordering::Relaxed), 0);
        assert_eq!(sd.ack.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn handler_increments_ack_and_observes_generation() {
        // Drive the handler twice; each call must bump `ack` by one,
        // and must observe the generation the BSP-equivalent test
        // wrote prior to invoking the handler.
        let sd = shootdown();
        sd.va_start.store(0xFFFF_8000_0000_1000, Ordering::Relaxed);
        sd.page_count.store(1, Ordering::Relaxed);
        sd.ack.store(0, Ordering::Relaxed);
        let g0 = sd.generation.load(Ordering::Relaxed);
        sd.generation.store(g0.wrapping_add(1), Ordering::Release);

        kernel_tlb_shootdown_handler();
        kernel_tlb_shootdown_handler();

        assert_eq!(sd.ack.load(Ordering::Acquire), 2);
        assert_eq!(sd.generation.load(Ordering::Acquire), g0.wrapping_add(1));
    }

    #[test]
    fn flush_tlb_range_reports_local_pages_and_targeted_count() {
        // The global `registered_ap_count` is shared across the unit
        // test binary; rather than asserting a specific count (which is
        // race-prone vs `per_cpu::tests::*` that register slots), assert
        // the relationships the call must always satisfy: local_pages
        // reflects the requested range, targeted matches the live count
        // at call time, and acked never exceeds targeted.
        let pre_count = super::super::per_cpu::registered_ap_count();
        let r = flush_tlb_range(VirtAddr(0xFFFF_8000_0000_2000), 0x2000);
        assert_eq!(r.local_pages, 2, "two 4 KiB pages in a 0x2000 range");
        assert!(!r.full_flush, "0x2000 stays under SHOOTDOWN_MAX_PAGES");
        assert_eq!(r.targeted, pre_count);
        assert!(r.acked <= r.targeted, "acked must not exceed targeted");
    }

    #[test]
    fn invalidate_local_caps_at_max_pages_and_returns_full_flush_sentinel() {
        // 65 pages (above SHOOTDOWN_MAX_PAGES = 64) → caller is told to
        // treat the request as a full TLB flush.
        let len = (SHOOTDOWN_MAX_PAGES + 1) * 0x1000;
        let r = invalidate_local(VirtAddr(0xFFFF_8000_0000_3000), len);
        assert_eq!(r, SHOOTDOWN_FULL_FLUSH);
    }
}
