//! Process-table seam for `ps` / `top` / `kill` (WS8-10.8).
//!
//! Pure `no_std` logic has no ambient kernel to enumerate, so the process facts
//! `ps` and `top` report are obtained through the [`ProcessSource`] seam (host
//! double [`StaticProcessSource`]). This deliberately mirrors the shape of the
//! system monitor's process rows (WS8-05) **without depending on that crate**:
//! the coreutils stay dependency-free, and on hardware the shell bridges this
//! seam to the real process table.
//!
//! ## Integer CPU model
//!
//! CPU usage is carried as **permille** (parts per thousand) in
//! [`ProcessInfo::cpu_permille`], never as a float: `505` permille renders as
//! `50.5%` using integer `div_euclid`/`rem_euclid` (see
//! [`format_percent`](crate::ps::format_percent)). This matches the monitor's
//! `cpu_permille` convention and keeps the whole crate float-free.

use alloc::{
    string::{String, ToString},
    vec::Vec,
};

/// The scheduling state of a process, with its classic single-letter `ps` code.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProcessState {
    /// Runnable or on-CPU (`R`).
    Running,
    /// Interruptible sleep (`S`).
    Sleeping,
    /// Uninterruptible sleep, e.g. blocked on I/O (`D`).
    Waiting,
    /// Stopped by a job-control signal (`T`).
    Stopped,
    /// Terminated but not yet reaped (`Z`).
    Zombie,
}

impl ProcessState {
    /// The single-letter `ps` STAT code for this state.
    #[must_use]
    pub const fn code(self) -> char {
        match self {
            Self::Running => 'R',
            Self::Sleeping => 'S',
            Self::Waiting => 'D',
            Self::Stopped => 'T',
            Self::Zombie => 'Z',
        }
    }
}

/// Facts about a single process (one `ps` / `top` row).
///
/// Mirrors the monitor's process row without depending on it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcessInfo {
    /// Process id.
    pub pid: u64,
    /// Parent process id.
    pub ppid: u64,
    /// The owning principal id (mirrors [`fs::ROOT_OWNER`](crate::fs::ROOT_OWNER)).
    pub owner: u64,
    /// Executable / command name.
    pub name: String,
    /// Scheduling state.
    pub state: ProcessState,
    /// CPU usage in permille (parts per thousand); `1000` == one full core.
    pub cpu_permille: u32,
    /// Resident memory in bytes.
    pub mem_bytes: u64,
}

impl ProcessInfo {
    /// Construct a [`ProcessInfo`] from its fields.
    // `pid` / `ppid` are the canonical process/parent-process field names; the
    // one-letter difference is intrinsic to the domain, not a naming slip.
    #[allow(clippy::similar_names)]
    #[must_use]
    pub fn new(
        pid: u64,
        ppid: u64,
        owner: u64,
        name: &str,
        state: ProcessState,
        cpu_permille: u32,
        mem_bytes: u64,
    ) -> Self {
        Self {
            pid,
            ppid,
            owner,
            name: name.to_string(),
            state,
            cpu_permille,
            mem_bytes,
        }
    }
}

/// The seam that yields the current process table.
pub trait ProcessSource {
    /// A snapshot of every process currently known to the system.
    fn processes(&self) -> Vec<ProcessInfo>;
}

/// A fixed host double for [`ProcessSource`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct StaticProcessSource {
    /// The processes this source always reports.
    procs: Vec<ProcessInfo>,
}

impl StaticProcessSource {
    /// A source that reports `procs`.
    #[must_use]
    pub fn new(procs: Vec<ProcessInfo>) -> Self {
        Self { procs }
    }

    /// Append a process (builder style).
    #[must_use]
    pub fn with(mut self, proc: ProcessInfo) -> Self {
        self.procs.push(proc);
        self
    }
}

impl ProcessSource for StaticProcessSource {
    fn processes(&self) -> Vec<ProcessInfo> {
        self.procs.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn state_codes_match_ps() {
        assert_eq!(ProcessState::Running.code(), 'R');
        assert_eq!(ProcessState::Sleeping.code(), 'S');
        assert_eq!(ProcessState::Waiting.code(), 'D');
        assert_eq!(ProcessState::Stopped.code(), 'T');
        assert_eq!(ProcessState::Zombie.code(), 'Z');
    }

    #[test]
    fn static_source_round_trips_in_order() {
        let source = StaticProcessSource::default()
            .with(ProcessInfo::new(
                1,
                0,
                0,
                "init",
                ProcessState::Sleeping,
                0,
                4096,
            ))
            .with(ProcessInfo::new(
                42,
                1,
                1000,
                "shell",
                ProcessState::Running,
                250,
                65536,
            ));
        let procs = source.processes();
        assert_eq!(procs.len(), 2);
        assert_eq!(procs.first().map(|p| p.pid), Some(1));
        assert_eq!(procs.get(1).map(|p| p.name.as_str()), Some("shell"));
    }
}
