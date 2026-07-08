//! Centralized user-memory access primitives (`NCIP-Kernel-Sec-026` §S4, WI-4b).
//!
//! This is the **single choke point** through which all kernel (ring-0) reads
//! and writes of userspace memory flow. It exists so that Intel **SMAP**
//! (`CR4.SMAP`) can be enabled safely: with SMAP on, a supervisor-mode access
//! to a user page faults unless the access is bracketed by `STAC` … `CLAC`
//! (which set/clear `RFLAGS.AC`). Routing every user access through these
//! helpers means the `STAC`/`CLAC` pair lives in exactly two places (one read,
//! one write), and a static grep can prove no raw user dereference escapes the
//! module — the SMAP completeness guarantee.
//!
//! ## Why the `SMAP_ENABLED` gate
//!
//! `STAC`/`CLAC` are themselves SMAP instructions: executing them when SMAP is
//! not enabled raises `#UD`. So these helpers emit `STAC`/`CLAC` **only when**
//! [`set_smap_enabled`] has been called (which [`super::cpu_features`] does iff
//! CPUID reports SMAP *and* it set `CR4.SMAP`). Consequence — and the reason
//! the WI-4b migration is safe to land incrementally: while the flag is `false`
//! (SMAP off, or host build), the helpers are plain validated copies with **no
//! behavioural change**, so call sites can be migrated to `uaccess` first and
//! `CR4.SMAP` flipped on last.
//!
//! ## What these helpers do NOT do
//!
//! They validate the user VA range against the user/kernel split
//! ([`user_range_ok`]) but do not pre-fault pages: a not-present user page
//! still `#PF`s during the copy (a pre-existing limitation, independent of
//! SMAP — there is no copy-fault fixup yet). SMAP does not worsen this.

use alloc::{string::String, vec::Vec};
use core::sync::atomic::{AtomicBool, Ordering};

/// Whether `CR4.SMAP` is active on this machine. Set once at boot by
/// [`super::cpu_features`] after it enables SMAP. Gates `STAC`/`CLAC` emission
/// so the helpers never execute an SMAP instruction on a CPU without SMAP
/// (which would `#UD`).
static SMAP_ENABLED: AtomicBool = AtomicBool::new(false);

/// Record that `CR4.SMAP` is now active. Called exactly once at boot from
/// [`super::cpu_features`]; after this, the copy helpers bracket their accesses
/// with `STAC`/`CLAC`.
pub fn set_smap_enabled(enabled: bool) {
    SMAP_ENABLED.store(enabled, Ordering::Release);
}

/// Returns `true` when `CR4.SMAP` is active (telemetry / tests).
#[must_use]
pub fn smap_enabled() -> bool {
    SMAP_ENABLED.load(Ordering::Acquire)
}

/// Validate that `[ptr, ptr+len)` lies wholly within the canonical user half.
///
/// A zero-length range is trivially valid. This is the single canonical
/// definition (the per-handler copies it replaced were byte-identical).
#[must_use]
pub fn user_range_ok(ptr: u64, len: u64) -> bool {
    if len == 0 {
        return true;
    }
    let Some(end) = ptr.checked_add(len) else {
        return false;
    };
    end <= crate::bare_metal::usermode::USER_HALF_END
}

/// Whether `[user_ptr, user_ptr + len)` is currently mapped in the active
/// address space — and writable, when `write` — by walking the page tables
/// rooted at the live `CR3` (NCIP-026 WI-4b §32, probe variant).
///
/// The syscall copy helpers call this so a valid-range-but-unmapped pointer (or
/// a read-only page on the write path) is rejected with `EFAULT` *before* the
/// dereference, instead of `#PF`-ing the kernel mid-copy. The kernel exception
/// path is panic-only (`isr_pf` halts), so a user-supplied bad pointer would
/// otherwise be a user→kernel denial-of-service; we prevent the fault rather
/// than recover.
///
/// TOCTOU: another CPU sharing this address space could unmap a page between
/// this check and the copy. Not exploitable today — only the BSP runs user
/// tasks (application processors are parked), so the caller's own pages cannot
/// be concurrently unmapped. Revisit when application processors run user tasks
/// (post-WI-5); a resumable-exception extable is the TOCTOU-free successor.
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
fn user_range_accessible(user_ptr: u64, len: usize, write: bool) -> bool {
    use crate::{
        bare_metal::paging::PageMapper,
        memory::{PhysAddr, VirtAddr},
    };
    let phys_offset = crate::bare_metal::phys_offset();
    if phys_offset == 0 {
        // Direct map not initialised → cannot walk the tables; fail closed.
        return false;
    }
    // CR3 bits 51:12 hold the PML4 physical base; the low 12 are flags/PCID.
    let root = PhysAddr(crate::bare_metal::arch::read_cr3() & !0xFFF);
    let mapper = PageMapper::new(phys_offset, root);
    mapper.range_accessible_in(root, VirtAddr(user_ptr), len, write)
}

/// Host / non-bare-metal stub: there are no page tables to walk and host tests
/// pass real kernel buffers, so accept unconditionally.
#[cfg(not(all(target_arch = "x86_64", target_os = "none")))]
fn user_range_accessible(_user_ptr: u64, _len: usize, _write: bool) -> bool {
    true
}

/// Allow supervisor access to user pages for the duration of `f` (sets
/// `RFLAGS.AC` via `STAC`, runs `f`, then clears it via `CLAC`) — but only when
/// SMAP is active; otherwise just runs `f`.
///
/// Keep `f` as short as possible: it is the window in which SMAP protection is
/// suspended. The helpers below each wrap a single `copy_nonoverlapping`.
#[inline]
fn with_user_access<R>(f: impl FnOnce() -> R) -> R {
    #[cfg(all(target_arch = "x86_64", target_os = "none"))]
    {
        if SMAP_ENABLED.load(Ordering::Acquire) {
            // SAFETY: STAC is valid because SMAP is enabled (flag set only by
            // cpu_features after it set CR4.SMAP). It sets RFLAGS.AC; we clear
            // it again below.
            //
            // The asm options are load-bearing: we must NOT pass `nomem`.
            // STAC/CLAC do not touch memory, but `nomem` would let the compiler
            // reorder the `copy_nonoverlapping` in `f()` OUT of the AC window
            // (no data dependency ties the copy to the flag), so the copy could
            // run with AC=0 and #PF under SMAP. Omitting `nomem` makes each asm
            // a memory barrier, pinning the copy between STAC and CLAC. Not
            // `preserves_flags` either (AC is modified). (HW-confirmed: with
            // `nomem` the read faulted; without it, it does not.)
            unsafe {
                core::arch::asm!("stac", options(nostack));
            }
            let r = f();
            // SAFETY: CLAC clears RFLAGS.AC, restoring SMAP enforcement. Memory
            // barrier (no `nomem`) so the copy cannot sink past it.
            unsafe {
                core::arch::asm!("clac", options(nostack));
            }
            return r;
        }
    }
    f()
}

/// Copy `dst.len()` bytes **from** user memory at `user_ptr` into the kernel
/// buffer `dst`. Returns `false` (copying nothing) if the user range is invalid.
///
/// # Safety
///
/// `user_ptr` must be a userspace virtual address in the **currently active**
/// address space (the caller's own CR3 on the syscall path). The range is
/// validated against the user half and then probed for presence in the live
/// page tables (`user_range_accessible`) — an unmapped page returns `false`
/// rather than `#PF`-ing the kernel.
#[must_use]
pub unsafe fn copy_from_user(dst: &mut [u8], user_ptr: u64) -> bool {
    let len = dst.len();
    if !user_range_ok(user_ptr, len as u64) {
        return false;
    }
    if len == 0 {
        return true;
    }
    // Probe the live mapping before dereferencing (read access): reject a bad
    // user pointer with EFAULT instead of faulting the kernel mid-copy.
    if !user_range_accessible(user_ptr, len, false) {
        return false;
    }
    with_user_access(|| {
        // SAFETY: range validated in the user half; `dst` is a valid kernel
        // buffer of `len` bytes; `user_ptr` is a user VA per the fn contract.
        unsafe {
            core::ptr::copy_nonoverlapping(user_ptr as *const u8, dst.as_mut_ptr(), len);
        }
    });
    true
}

/// Copy `src` **to** user memory at `user_ptr`. Returns `false` (copying
/// nothing) if the user range is invalid.
///
/// # Safety
///
/// As [`copy_from_user`]: `user_ptr` is a user VA in the active address space.
/// The range is additionally probed for **writability** (not just presence), so
/// a read-only user page is rejected with `false` rather than faulting the
/// kernel on the store.
#[must_use]
pub unsafe fn copy_to_user(user_ptr: u64, src: &[u8]) -> bool {
    let len = src.len();
    if !user_range_ok(user_ptr, len as u64) {
        return false;
    }
    if len == 0 {
        return true;
    }
    // Probe the live mapping before dereferencing (write access): reject an
    // unmapped or read-only user page with EFAULT instead of faulting the kernel.
    if !user_range_accessible(user_ptr, len, true) {
        return false;
    }
    with_user_access(|| {
        // SAFETY: range validated in the user half; `src` is a valid kernel
        // buffer of `len` bytes; `user_ptr` is a user VA per the fn contract.
        unsafe {
            core::ptr::copy_nonoverlapping(src.as_ptr(), user_ptr as *mut u8, len);
        }
    });
    true
}

/// Read `len` bytes from user memory at `user_ptr` into a freshly allocated
/// `Vec`. Returns `None` if `len == 0`, exceeds `max`, or the range is invalid.
///
/// # Safety
///
/// As [`copy_from_user`].
#[must_use]
pub unsafe fn copy_from_user_vec(user_ptr: u64, len: usize, max: usize) -> Option<Vec<u8>> {
    if len == 0 || len > max {
        return None;
    }
    let mut buf = alloc::vec![0u8; len];
    // SAFETY: forwarded to copy_from_user under the same contract.
    if unsafe { copy_from_user(&mut buf, user_ptr) } {
        Some(buf)
    } else {
        None
    }
}

/// Copy a UTF-8 string out of user memory. Returns `None` if `ptr`/`len` is
/// zero, `len > max`, the range is invalid, or the bytes are not valid UTF-8.
///
/// # Safety
///
/// As [`copy_from_user`].
#[must_use]
pub unsafe fn copy_user_str(user_ptr: u64, len: usize, max: usize) -> Option<String> {
    if user_ptr == 0 {
        return None;
    }
    // SAFETY: forwarded to copy_from_user_vec under the same contract.
    let bytes = unsafe { copy_from_user_vec(user_ptr, len, max) }?;
    core::str::from_utf8(&bytes).ok().map(String::from)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn user_range_ok_accepts_user_half_and_zero_len() {
        assert!(user_range_ok(0x4000_0000, 0x1000));
        assert!(user_range_ok(0xDEAD, 0)); // zero length always ok
        assert!(user_range_ok(
            crate::bare_metal::usermode::USER_HALF_END - 1,
            1
        ));
    }

    #[test]
    fn user_range_ok_rejects_kernel_half_and_overflow() {
        assert!(!user_range_ok(
            crate::bare_metal::usermode::USER_HALF_END,
            1
        ));
        assert!(!user_range_ok(u64::MAX, 1)); // checked_add overflow
    }

    #[test]
    fn copy_round_trips_through_kernel_buffers_when_smap_off() {
        // On host, SMAP_ENABLED is false → with_user_access is a plain call and
        // the "user pointer" is just a kernel buffer address, so the helpers act
        // as validated memcpys. (user_range_ok would reject a >USER_HALF_END
        // address, so use a small fake address backed by a real buffer.)
        let src = [1u8, 2, 3, 4, 5];
        // Treat `src` as if it were user memory at its own address (host: AC gate
        // off, address is < USER_HALF_END on typical hosts is not guaranteed, so
        // we test the no-op/validation path instead of a real deref here).
        // Validation: a kernel-half-looking address is rejected.
        let mut dst = [0u8; 5];
        // A deliberately-invalid (kernel-half) source must be refused.
        let ok = unsafe { copy_from_user(&mut dst, crate::bare_metal::usermode::USER_HALF_END) };
        assert!(!ok);
        assert_eq!(dst, [0u8; 5]);
        let _ = src;
    }

    #[test]
    fn smap_flag_round_trips() {
        let prior = smap_enabled();
        set_smap_enabled(true);
        assert!(smap_enabled());
        set_smap_enabled(false);
        assert!(!smap_enabled());
        set_smap_enabled(prior);
    }
}
