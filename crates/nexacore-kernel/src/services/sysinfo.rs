//! Kernel-side telemetry singleton backing the `SysInfo (114)` syscall.
//!
//! CPU count is resolved once at boot from the MADT walk
//! ([`crate::lib`]'s `sysinfo_cpu_total`) and has no other natural home:
//! unlike `free_mib`/`total_mib` (recomputed live from
//! [`crate::FRAME_ALLOC`] on every `SysInfo` call), the enabled logical-CPU
//! count is not tracked anywhere the syscall handler can re-derive it
//! on demand, so it is cached here exactly once. Mirrors the `static mut` +
//! `unsafe fn` accessor pattern already used by [`crate::services::net`].

#![cfg_attr(
    all(feature = "bare-metal", target_arch = "x86_64"),
    allow(
        unsafe_code,
        reason = "CPU_COUNT static mut singleton + addr_of/addr_of_mut accessor; SAFETY documented at the fn boundary"
    )
)]

#[cfg(all(feature = "bare-metal", target_arch = "x86_64"))]
static mut CPU_COUNT: u32 = 1;

/// Records the enabled logical-CPU count. Called exactly once at boot,
/// immediately after the MADT walk resolves it.
///
/// # Safety
///
/// Must only be called during single-threaded boot, before the `SysInfo`
/// syscall handler can possibly run concurrently.
#[cfg(all(feature = "bare-metal", target_arch = "x86_64"))]
pub unsafe fn set_cpu_count(n: u32) {
    unsafe {
        *core::ptr::addr_of_mut!(CPU_COUNT) = n;
    }
}

/// Reads the enabled logical-CPU count recorded by [`set_cpu_count`].
///
/// # Safety
///
/// Safe to call from the syscall dispatch path: single-CPU,
/// interrupt-masked `SYSCALL` entry, and the value is write-once at boot.
#[cfg(all(feature = "bare-metal", target_arch = "x86_64"))]
pub unsafe fn cpu_count() -> u32 {
    unsafe { *core::ptr::addr_of!(CPU_COUNT) }
}

#[cfg(not(all(feature = "bare-metal", target_arch = "x86_64")))]
pub unsafe fn cpu_count() -> u32 {
    1
}
