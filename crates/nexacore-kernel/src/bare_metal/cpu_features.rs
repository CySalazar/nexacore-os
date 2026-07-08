//! Baseline CPU security-feature enablement (`NCIP-Kernel-Sec-026` §S4, WI-4).
//!
//! Probes CPUID and turns on the cheap, universally-available CR4 hardening
//! bits that cost ~0 at runtime:
//!
//! - **SMEP** (Supervisor Mode Execution Prevention, `CR4.SMEP`, bit 20):
//!   the kernel (ring 0) cannot *execute* a user-accessible page. Kills the
//!   classic "ret2user" technique where a kernel bug redirects execution to
//!   attacker-controlled code in a user page. Safe: the kernel never executes
//!   user pages by design (user code runs in ring 3).
//! - **UMIP** (User-Mode Instruction Prevention, `CR4.UMIP`, bit 11): ring 3
//!   cannot run `SGDT/SIDT/SLDT/SMSW/STR`, denying user code the GDT/IDT/LDT
//!   base leaks that defeat KASLR. Safe: ordinary user programs never issue
//!   those privileged-info instructions.
//!
//! **SMAP** (`CR4.SMAP`, bit 21) is intentionally **not** set here — it is
//! enabled by WI-4b, because every legitimate kernel→user memory access must
//! first be bracketed with `STAC`/`CLAC` or the access faults. Enabling it is
//! a separate, boot-critical change.
//!
//! Per §S1.2 (probe-and-degrade) each bit is set **only if CPUID reports it**;
//! an absent feature is skipped (with a logged reduction in defense-in-depth),
//! never assumed — NexaCore runs as an untrusted guest and cannot rely on any
//! particular host CPU feature.

/// `CR4.UMIP` — User-Mode Instruction Prevention (bit 11).
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
const CR4_UMIP: u64 = 1 << 11;
/// `CR4.SMEP` — Supervisor Mode Execution Prevention (bit 20).
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
const CR4_SMEP: u64 = 1 << 20;

/// CPUID.(EAX=7,ECX=0):EBX.SMEP (bit 7).
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
const EBX7_SMEP: u32 = 1 << 7;
/// CPUID.(EAX=7,ECX=0):ECX.UMIP (bit 2).
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
const ECX7_UMIP: u32 = 1 << 2;

/// Enable the SMEP + UMIP baseline on the current CPU when supported, logging
/// the effective posture. Returns the CR4 bits actually set (0 if none were
/// supported), for telemetry and tests.
///
/// Idempotent: re-running ORs the same bits.
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
#[must_use]
pub fn enable_baseline() -> u64 {
    use super::early_console;

    let leaf7 = super::cpuinfo::cpuid(7, 0);
    let smep = leaf7.ebx & EBX7_SMEP != 0;
    let umip = leaf7.ecx & ECX7_UMIP != 0;

    let mut add: u64 = 0;
    if smep {
        add |= CR4_SMEP;
    }
    if umip {
        add |= CR4_UMIP;
    }

    if add != 0 {
        // SAFETY: SMEP/UMIP are defensive CR4 bits permitted in ring 0; setting
        // them cannot fault. Only CPUID-reported bits are OR'd in, so no
        // reserved/unsupported bit is ever written (which would #GP). The
        // read-modify-write preserves every other CR4 bit (PAE, PGE, OSFXSR…).
        unsafe {
            let mut cr4: u64;
            core::arch::asm!("mov {}, cr4", out(reg) cr4, options(nomem, nostack, preserves_flags));
            cr4 |= add;
            core::arch::asm!("mov cr4, {}", in(reg) cr4, options(nomem, nostack, preserves_flags));
        }
    }

    // Telemetry (§S1.2): record the realized posture; only infrastructural
    // feature flags, never user-derived values.
    early_console::write_str("[cpu] baseline SMEP=");
    early_console::write_str(if smep { "on" } else { "unsupported" });
    early_console::write_str(" UMIP=");
    early_console::write_str(if umip { "on" } else { "unsupported" });
    early_console::write_str("\n");

    add
}

/// Host / non-bare-metal stub: writing `CR4` from ring 3 would `#GP`, so this
/// is a no-op returning 0. Lets `kmain` call `enable_baseline()` unconditionally.
#[cfg(not(all(target_arch = "x86_64", target_os = "none")))]
#[must_use]
pub fn enable_baseline() -> u64 {
    0
}

/// `CR4.SMAP` — Supervisor Mode Access Prevention (bit 21).
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
const CR4_SMAP: u64 = 1 << 21;
/// CPUID.(EAX=7,ECX=0):EBX.SMAP (bit 20).
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
const EBX7_SMAP: u32 = 1 << 20;

/// Enable SMAP (`CR4.SMAP`) when CPUID reports it, and tell [`super::uaccess`]
/// to start bracketing user copies with `STAC`/`CLAC` (`NCIP-Kernel-Sec-026`
/// §S4, WI-4b). Returns `true` if SMAP was enabled.
///
/// MUST be called only AFTER every kernel→user memory access has been routed
/// through [`super::uaccess`] (otherwise an un-bracketed access would `#PF`).
/// MUST be called only AFTER [`super::syscall_entry::syscall_init`] has set
/// `IA32_FMASK` to clear `RFLAGS.AC` on syscall entry (so SMAP is enforced in
/// handlers). Probe-and-degrade: if CPUID does not report SMAP, this is a
/// logged no-op and `uaccess` keeps acting as plain validated copies.
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
#[must_use]
pub fn enable_smap() -> bool {
    use super::early_console;

    let leaf7 = super::cpuinfo::cpuid(7, 0);
    let smap = leaf7.ebx & EBX7_SMAP != 0;

    if smap {
        // SAFETY: SMAP is a defensive CR4 bit, CPUID-reported here so the write
        // sets no unsupported bit. The RMW preserves all other CR4 bits. After
        // SMAP is on, CLAC is a valid instruction; we clear RFLAGS.AC so the
        // kernel boot context runs with SMAP enforced (AC=0).
        unsafe {
            let mut cr4: u64;
            core::arch::asm!("mov {}, cr4", out(reg) cr4, options(nomem, nostack, preserves_flags));
            cr4 |= CR4_SMAP;
            core::arch::asm!("mov cr4, {}", in(reg) cr4, options(nomem, nostack, preserves_flags));
            core::arch::asm!("clac", options(nomem, nostack));
        }
        // Now the uaccess helpers may emit STAC/CLAC.
        super::uaccess::set_smap_enabled(true);
    }

    early_console::write_str("[cpu] SMAP=");
    early_console::write_str(if smap { "on" } else { "unsupported" });
    early_console::write_str("\n");

    smap
}

/// Host / non-bare-metal stub for [`enable_smap`].
#[cfg(not(all(target_arch = "x86_64", target_os = "none")))]
#[must_use]
pub fn enable_smap() -> bool {
    false
}
