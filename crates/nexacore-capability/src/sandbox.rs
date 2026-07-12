//! Per-service sandbox profiles + seccomp-class syscall filtering (WS10-07).
//!
//! Defense-in-depth: every user-space service should run at least privilege.
//! A [`ServiceProfile`] declares exactly which syscalls a service is permitted
//! to make; a [`SyscallFilter`] built from it enforces that set **default-deny**
//! — any syscall not explicitly allowed is rejected (WS10-07.4). Profiles are
//! declared in a small text format and parsed with [`ServiceProfile::parse`]
//! (WS10-07.1/.2); baseline profiles for the core services ship as
//! [`net_service_profile`] / [`fs_service_profile`] (WS10-07.6).
//!
//! Namespace isolation (WS10-07.5), service-manager enforcement (WS10-07.7,
//! WS12-01) and the on-VM violation tests (WS10-07.8) build on this data model.
//! Pure logic, `no_std + alloc`, no `unsafe`.

use alloc::{
    collections::BTreeSet,
    string::{String, ToString},
    vec::Vec,
};

/// A per-service sandbox profile: the syscall numbers a service may invoke
/// (WS10-07.1).
///
/// The set is an allow-list; enforcement is default-deny (see [`SyscallFilter`]).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ServiceProfile {
    name: String,
    allowed_syscalls: BTreeSet<u64>,
}

/// An error parsing a [`ServiceProfile`] text profile (WS10-07.2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProfileError {
    /// A `service <name>` header was missing or empty.
    MissingServiceName,
    /// A `syscall <n>` line had no / a non-numeric argument (carries the
    /// 1-based line number).
    InvalidSyscall(usize),
    /// An unrecognised directive keyword (carries the 1-based line number).
    UnknownDirective(usize),
}

impl ServiceProfile {
    /// A profile for `name` with no permitted syscalls (deny-everything).
    #[must_use]
    pub fn new(name: &str) -> Self {
        Self {
            name: name.to_string(),
            allowed_syscalls: BTreeSet::new(),
        }
    }

    /// Permit `syscall` (builder-style).
    #[must_use]
    pub fn allow(mut self, syscall: u64) -> Self {
        self.allowed_syscalls.insert(syscall);
        self
    }

    /// The service this profile applies to.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Whether `syscall` is in the allow-list.
    #[must_use]
    pub fn permits(&self, syscall: u64) -> bool {
        self.allowed_syscalls.contains(&syscall)
    }

    /// The permitted syscall numbers, ascending.
    #[must_use]
    pub fn allowed(&self) -> Vec<u64> {
        self.allowed_syscalls.iter().copied().collect()
    }

    /// Parse a text profile (WS10-07.2).
    ///
    /// Format: one directive per line; `#` starts a comment; blank lines are
    /// ignored.
    ///
    /// ```text
    /// service nexacore-net
    /// syscall 23   # IpcReceive
    /// syscall 24   # IpcSend
    /// ```
    ///
    /// # Errors
    ///
    /// - [`ProfileError::MissingServiceName`] when no `service <name>` header is
    ///   present (or its name is empty).
    /// - [`ProfileError::InvalidSyscall`] for a `syscall` line without a valid
    ///   `u64` argument.
    /// - [`ProfileError::UnknownDirective`] for any other leading keyword.
    pub fn parse(text: &str) -> Result<Self, ProfileError> {
        let mut name: Option<String> = None;
        let mut allowed: BTreeSet<u64> = BTreeSet::new();

        for (idx, raw) in text.lines().enumerate() {
            let line_no = idx + 1;
            // Strip comments and surrounding whitespace.
            let line = raw.split('#').next().unwrap_or("").trim();
            if line.is_empty() {
                continue;
            }
            let mut parts = line.split_whitespace();
            let Some(directive) = parts.next() else {
                continue;
            };
            match directive {
                "service" => {
                    let svc = parts.next().unwrap_or("").trim();
                    if svc.is_empty() {
                        return Err(ProfileError::MissingServiceName);
                    }
                    name = Some(svc.to_string());
                }
                "syscall" => {
                    let n = parts
                        .next()
                        .and_then(|a| a.parse::<u64>().ok())
                        .ok_or(ProfileError::InvalidSyscall(line_no))?;
                    allowed.insert(n);
                }
                _ => return Err(ProfileError::UnknownDirective(line_no)),
            }
        }

        let name = name.ok_or(ProfileError::MissingServiceName)?;
        Ok(Self {
            name,
            allowed_syscalls: allowed,
        })
    }
}

/// The verdict of a [`SyscallFilter`] check (WS10-07.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    /// The syscall is on the profile's allow-list.
    Allow,
    /// The syscall is denied (default-deny: not on the allow-list).
    Deny,
}

/// A seccomp-class syscall filter derived from a [`ServiceProfile`]
/// (WS10-07.3/.4).
///
/// The filter is **default-deny**: [`SyscallFilter::check`] returns
/// [`Verdict::Allow`] only for syscalls the profile explicitly permits, and
/// [`Verdict::Deny`] for everything else — including syscall numbers the profile
/// never mentioned.
#[derive(Debug, Clone)]
pub struct SyscallFilter {
    allowed: BTreeSet<u64>,
}

impl SyscallFilter {
    /// Build a filter enforcing `profile`.
    #[must_use]
    pub fn from_profile(profile: &ServiceProfile) -> Self {
        Self {
            allowed: profile.allowed_syscalls.clone(),
        }
    }

    /// Check `syscall`, returning [`Verdict::Allow`] iff it is permitted.
    #[must_use]
    pub fn check(&self, syscall: u64) -> Verdict {
        if self.allowed.contains(&syscall) {
            Verdict::Allow
        } else {
            Verdict::Deny
        }
    }

    /// Convenience: `true` iff the syscall is allowed.
    #[must_use]
    pub fn is_allowed(&self, syscall: u64) -> bool {
        matches!(self.check(syscall), Verdict::Allow)
    }
}

// --- Baseline core-service profiles (WS10-07.6) ------------------------------
//
// Minimal starting allow-lists for the core services, keyed to the stable
// syscall numbers used across the tree (IpcReceive=23, IpcSend=24,
// IpcCreateChannel=22, MmioMap=70, DmaMap=71, IrqAttach=72, TaskExit=1,
// TaskYield=2). These are the least-privilege baselines the service-manager
// enforcement (WS10-07.7) will load; they tighten as each service's exact
// syscall footprint is audited.

/// `IpcCreateChannel`.
pub const SYS_IPC_CREATE_CHANNEL: u64 = 22;
/// `IpcReceive`.
pub const SYS_IPC_RECEIVE: u64 = 23;
/// `IpcSend`.
pub const SYS_IPC_SEND: u64 = 24;
/// `TaskExit`.
pub const SYS_TASK_EXIT: u64 = 1;
/// `TaskYield`.
pub const SYS_TASK_YIELD: u64 = 2;
/// `MmioMap`.
pub const SYS_MMIO_MAP: u64 = 70;
/// `DmaMap`.
pub const SYS_DMA_MAP: u64 = 71;
/// `IrqAttach`.
pub const SYS_IRQ_ATTACH: u64 = 72;

/// Baseline sandbox profile for `nexacore-net` (WS10-07.6).
///
/// The network service is pure IPC: it serves the socket API over channels and
/// never touches device MMIO/DMA directly (the NIC drivers do). So its baseline
/// grants only the IPC + task-lifecycle syscalls.
#[must_use]
pub fn net_service_profile() -> ServiceProfile {
    ServiceProfile::new("nexacore-net")
        .allow(SYS_IPC_CREATE_CHANNEL)
        .allow(SYS_IPC_RECEIVE)
        .allow(SYS_IPC_SEND)
        .allow(SYS_TASK_YIELD)
        .allow(SYS_TASK_EXIT)
}

/// Baseline sandbox profile for `nexacore-fs` (WS10-07.6).
///
/// The filesystem service talks to the block device via IPC (the NVMe driver
/// owns the hardware), so like `nexacore-net` its baseline is IPC + lifecycle.
#[must_use]
pub fn fs_service_profile() -> ServiceProfile {
    ServiceProfile::new("nexacore-fs")
        .allow(SYS_IPC_CREATE_CHANNEL)
        .allow(SYS_IPC_RECEIVE)
        .allow(SYS_IPC_SEND)
        .allow(SYS_TASK_YIELD)
        .allow(SYS_TASK_EXIT)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_profile_denies_everything() {
        let p = ServiceProfile::new("svc");
        assert_eq!(p.name(), "svc");
        assert!(!p.permits(SYS_IPC_SEND));
        assert!(p.allowed().is_empty());
    }

    #[test]
    fn allow_builds_the_allow_list() {
        let p = ServiceProfile::new("svc").allow(23).allow(24).allow(23);
        assert_eq!(p.allowed(), alloc::vec![23, 24]); // deduped + ascending
        assert!(p.permits(23));
        assert!(!p.permits(70));
    }

    #[test]
    fn filter_is_default_deny() {
        let p = ServiceProfile::new("svc").allow(SYS_IPC_SEND);
        let f = SyscallFilter::from_profile(&p);
        assert_eq!(f.check(SYS_IPC_SEND), Verdict::Allow);
        assert_eq!(f.check(SYS_MMIO_MAP), Verdict::Deny);
        // A syscall number the profile never mentioned is denied.
        assert_eq!(f.check(9999), Verdict::Deny);
        assert!(f.is_allowed(SYS_IPC_SEND));
        assert!(!f.is_allowed(9999));
    }

    #[test]
    fn parse_reads_service_and_syscalls() {
        let text = "\
# net service baseline
service nexacore-net
syscall 22   # IpcCreateChannel
syscall 23   # IpcReceive
syscall 24   # IpcSend
";
        let p = ServiceProfile::parse(text).unwrap();
        assert_eq!(p.name(), "nexacore-net");
        assert_eq!(p.allowed(), alloc::vec![22, 23, 24]);
    }

    #[test]
    fn parse_requires_a_service_name() {
        assert_eq!(
            ServiceProfile::parse("syscall 23"),
            Err(ProfileError::MissingServiceName)
        );
        assert_eq!(
            ServiceProfile::parse("service   \nsyscall 23"),
            Err(ProfileError::MissingServiceName)
        );
    }

    #[test]
    fn parse_rejects_bad_syscall_and_unknown_directive() {
        assert_eq!(
            ServiceProfile::parse("service s\nsyscall notanum"),
            Err(ProfileError::InvalidSyscall(2))
        );
        assert_eq!(
            ServiceProfile::parse("service s\nnamespace mount"),
            Err(ProfileError::UnknownDirective(2))
        );
    }

    #[test]
    fn parse_ignores_comments_and_blanks() {
        let text = "\n# a comment\nservice s\n\nsyscall 1    # TaskExit\n\n";
        let p = ServiceProfile::parse(text).unwrap();
        assert_eq!(p.name(), "s");
        assert_eq!(p.allowed(), alloc::vec![1]);
    }

    #[test]
    fn core_profiles_grant_ipc_but_deny_device_syscalls() {
        for p in [net_service_profile(), fs_service_profile()] {
            let f = SyscallFilter::from_profile(&p);
            assert!(f.is_allowed(SYS_IPC_SEND));
            assert!(f.is_allowed(SYS_IPC_RECEIVE));
            assert!(f.is_allowed(SYS_TASK_EXIT));
            // Device syscalls are NOT in the service baseline (drivers own them).
            assert!(!f.is_allowed(SYS_MMIO_MAP));
            assert!(!f.is_allowed(SYS_DMA_MAP));
            assert!(!f.is_allowed(SYS_IRQ_ATTACH));
        }
    }

    #[test]
    fn parsed_profile_round_trips_through_the_filter() {
        let p = ServiceProfile::parse("service s\nsyscall 70\nsyscall 71").unwrap();
        let f = SyscallFilter::from_profile(&p);
        assert!(f.is_allowed(70));
        assert!(f.is_allowed(71));
        assert!(!f.is_allowed(72));
    }
}
