//! Wrapper around the `SysInfo (114)` syscall: live CPU/RAM telemetry.
//!
//! Mirrors [`crate::time_monotonic_nanos`] — a thin, allocation-free wrapper
//! around a single read-only syscall, consumed by both the Monitor window
//! and the System Info window so neither duplicates the raw syscall plumbing.

use crate::syscall;

const SYS_SYSINFO: u64 = 114;
const SYSINFO_LEN: usize = 24;

/// Live telemetry read from the kernel via `SysInfo (114)`.
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct SysInfo {
    pub free_mib: u32,
    pub total_mib: u32,
    pub cpu_count: u32,
}

/// Reads live CPU/RAM telemetry from the kernel.
///
/// Returns `None` if the syscall fails (older kernel, or a transient
/// buffer-validation error) — callers fall back to their previous
/// placeholder display.
pub(crate) fn query_sysinfo() -> Option<SysInfo> {
    let mut buf = [0u8; SYSINFO_LEN];
    // SAFETY: buf is a valid, writable 24-byte buffer for the syscall's
    // duration; SysInfo takes no other pointer arguments.
    let (rax, _rdx) = unsafe {
        syscall(
            SYS_SYSINFO,
            buf.as_mut_ptr() as u64,
            buf.len() as u64,
            0,
            0,
            0,
            0,
        )
    };
    if rax != SYSINFO_LEN as u64 {
        return None;
    }
    let free_mib = u64::from_le_bytes(buf[0..8].try_into().ok()?);
    let total_mib = u64::from_le_bytes(buf[8..16].try_into().ok()?);
    let cpu_count = u32::from_le_bytes(buf[16..20].try_into().ok()?);
    Some(SysInfo {
        free_mib: u32::try_from(free_mib).ok()?,
        total_mib: u32::try_from(total_mib).ok()?,
        cpu_count,
    })
}
