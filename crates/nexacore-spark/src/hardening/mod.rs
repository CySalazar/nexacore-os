//! Application-level security hardening.
//!
//! Applies defense-in-depth measures regardless of the active trust
//! tier. These protections mitigate the inherent risk of running on a
//! conventional (untrusted) host OS.
//!
//! ## Measures applied
//!
//! | Measure               | Linux              | Windows            | macOS             |
//! |-----------------------|--------------------|--------------------|-------------------|
//! | Process sandbox       | seccomp-bpf        | AppContainer       | App Sandbox       |
//! | Memory locking        | `mlock`            | `VirtualLock`      | `mlock`           |
//! | Guard pages           | `mmap` + `PROT_NONE` | `VirtualAlloc`   | `mmap`            |
//! | ASLR                  | PIE (default)      | `/DYNAMICBASE`     | PIE (default)     |
//! | No-new-privileges     | `prctl(PR_SET_NO_NEW_PRIVS)` | Restricted token | Hardened Runtime |

/// Applies all available hardening measures for the current platform.
///
/// This function is idempotent and safe to call multiple times.
///
/// # Errors
///
/// Returns an error only if a critical hardening measure fails (e.g.,
/// seccomp installation denied). Non-critical failures (e.g., mlock
/// limit too low) are logged as warnings but do not prevent startup.
//
// `unnecessary_wraps`: Result is intentional API surface; seccomp-bpf
// installation (NCIP-025 Phase 5) will return real errors on failure.
#[allow(
    clippy::unnecessary_wraps,
    reason = "Result is intentional API surface; seccomp/AppContainer installation will return errors"
)]
pub fn apply() -> crate::Result<()> {
    set_no_new_privs();
    lock_sensitive_memory();
    install_sandbox();
    Ok(())
}

/// Prevents the process from gaining new privileges via execve.
fn set_no_new_privs() {
    // TODO(ncip-025-phase-5): Linux: prctl(PR_SET_NO_NEW_PRIVS, 1)
    // via libc crate or raw syscall. This is a one-way privilege
    // reduction that prevents execve from gaining capabilities.
    //
    // Windows: handled by AppContainer restricted token.
    // macOS: handled by Hardened Runtime entitlement.
    tracing::debug!("no-new-privs: not yet implemented");
}

/// Attempts to lock sensitive memory pages to prevent swapping to disk.
fn lock_sensitive_memory() {
    // TODO(ncip-025-phase-5): Implement mlock for key material buffers.
    //
    // Strategy:
    // - Allocate a dedicated "secure heap" region via mmap/VirtualAlloc.
    // - mlock/VirtualLock the region.
    // - All TeeSharedKey, SigningKey, and session key material is
    //   allocated from this region.
    // - On drop, volatile-zero and munlock/VirtualFree.
    tracing::debug!("memory locking: not yet implemented");
}

/// Installs the platform-specific process sandbox.
fn install_sandbox() {
    // TODO(ncip-025-phase-5): Install seccomp-bpf (Linux),
    // AppContainer (Windows), or verify App Sandbox (macOS).
    //
    // Linux seccomp allowlist (~60 syscalls):
    //   read, write, open, close, stat, fstat, mmap, mprotect,
    //   munmap, brk, rt_sigaction, rt_sigprocmask, ioctl (restricted),
    //   socket, connect, sendto, recvfrom, sendmsg, recvmsg, bind,
    //   listen, accept4, getsockopt, setsockopt, clone3, execve (denied),
    //   exit, exit_group, futex, epoll_create1, epoll_ctl, epoll_wait,
    //   getrandom, clock_gettime, ...
    //
    // Windows AppContainer:
    //   CreateRestrictedToken + CreateProcessAsUser with
    //   SECURITY_CAPABILITIES limiting network to mesh ports only.
    //
    // macOS:
    //   Verify com.apple.security.app-sandbox entitlement is active
    //   at runtime via SecTaskCopyValueForEntitlement.
    tracing::debug!("process sandbox: not yet installed");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn apply_does_not_panic() {
        // Hardening should never panic, even if individual measures
        // are unavailable on the test platform.
        apply().expect("hardening should succeed or degrade gracefully");
    }
}
