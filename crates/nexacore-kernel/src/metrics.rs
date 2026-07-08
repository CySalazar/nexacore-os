//! `/proc`-class metrics & introspection surface (WS12-04).
//!
//! The kernel exposes per-process and system metrics through a small virtual
//! filesystem modelled on Linux `/proc`, plus a structured snapshot API the
//! system-monitor app (WS8-05) reads directly. The design splits cleanly into
//! three layers so the whole thing is host-testable:
//!
//! 1. **Schemas** (`ProcessMetrics` / `SystemMetrics`) — the data the
//!    surface exposes (WS12-04.1/.2).
//! 2. **Collection** (`MetricsSnapshot::collect`) — assembles a snapshot from
//!    the real kernel `ProcessTable` (process list, names, lifecycle state)
//!    plus a `ResourceAccounting` seam supplying the CPU/memory/fd/IO
//!    counters the bare-metal kernel maintains (WS12-04.4/.5). The seam keeps
//!    the collection logic testable without the live scheduler.
//! 3. **Presentation** (`ProcFs`) — renders the snapshot as a `/proc`-class
//!    virtual FS (`read`/`list`, WS12-04.3) and hands the structured snapshot
//!    to the monitor client (WS12-04.6).
//!
//! The bare-metal kernel provides the production `ResourceAccounting` impl
//! (wired to the scheduler tick accounting, the frame allocator, and the
//! per-process fd tables); host tests use `StaticResourceAccounting`.

use alloc::{
    collections::BTreeMap,
    format,
    string::{String, ToString},
    vec::Vec,
};

use crate::{process_table::ProcessTable, scheduling::TaskId};

// =============================================================================
// Per-process schema (WS12-04.1)
// =============================================================================

/// Lifecycle state of a process as seen by the metrics surface.
///
/// Derived from the [`ProcessTable`] (which tracks the exit code), not the
/// live scheduler run-state: the metrics view distinguishes a running process
/// from an exited-but-not-yet-reaped zombie, which is what a monitor needs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProcessState {
    /// The process is live (no exit code recorded).
    Running,
    /// The process has exited and is awaiting reaping by its parent.
    Zombie,
}

impl ProcessState {
    /// The single-character code used in the `/proc/<pid>/stat` rendering
    /// (`R` running, `Z` zombie), mirroring Linux `proc(5)`.
    #[must_use]
    pub const fn code(self) -> char {
        match self {
            Self::Running => 'R',
            Self::Zombie => 'Z',
        }
    }
}

/// Per-process resource counters supplied by the kernel accounting seam
/// (WS12-04.1).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ProcessResourceUsage {
    /// Cumulative CPU time charged to the process, in microseconds.
    pub cpu_time_micros: u64,
    /// Resident set size (physical memory currently mapped), in bytes.
    pub rss_bytes: u64,
    /// Virtual address space size, in bytes.
    pub virt_bytes: u64,
    /// Number of open file descriptors.
    pub fd_count: u32,
}

/// The full per-process metrics record (WS12-04.1).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProcessMetrics {
    /// Kernel task id (the `<pid>` directory name under `/proc`).
    pub pid: u64,
    /// Human-readable process name.
    pub name: String,
    /// Lifecycle state.
    pub state: ProcessState,
    /// Resource counters.
    pub usage: ProcessResourceUsage,
}

// =============================================================================
// System schema (WS12-04.2)
// =============================================================================

/// System-wide resource counters supplied by the kernel accounting seam
/// (WS12-04.2).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SystemResources {
    /// Total physical memory managed by the kernel, in bytes.
    pub mem_total_bytes: u64,
    /// Physical memory currently allocated, in bytes.
    pub mem_used_bytes: u64,
    /// Cumulative block-layer bytes read since boot.
    pub io_read_bytes: u64,
    /// Cumulative block-layer bytes written since boot.
    pub io_write_bytes: u64,
    /// Time since boot, in microseconds.
    pub uptime_micros: u64,
}

impl SystemResources {
    /// Free physical memory (`total - used`, saturating), in bytes.
    #[must_use]
    pub const fn mem_free_bytes(&self) -> u64 {
        self.mem_total_bytes.saturating_sub(self.mem_used_bytes)
    }
}

/// The full system-wide metrics record (WS12-04.2).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SystemMetrics {
    /// Number of processes known to the kernel (running + zombie).
    pub process_count: u32,
    /// Number of runnable (non-zombie) processes — the instantaneous load.
    pub runnable_count: u32,
    /// System-wide resource counters.
    pub resources: SystemResources,
}

// =============================================================================
// Collection seam (WS12-04.4 / .5)
// =============================================================================

/// The kernel accounting seam: supplies the resource counters the metrics
/// surface cannot read from the [`ProcessTable`] alone (WS12-04.4/.5).
///
/// The bare-metal kernel implements this over the scheduler tick accounting,
/// the frame allocator, and the per-process fd tables; host tests use
/// [`StaticResourceAccounting`].
pub trait ResourceAccounting {
    /// Resource counters for `pid` (all zero if the process is unknown).
    fn process_usage(&self, pid: TaskId) -> ProcessResourceUsage;
    /// System-wide resource counters.
    fn system_resources(&self) -> SystemResources;
}

/// A concrete [`ResourceAccounting`] backed by a populated map — the vehicle
/// the kernel fills from its counters each sample, and the host-test double.
#[derive(Clone, Debug, Default)]
pub struct StaticResourceAccounting {
    /// Per-pid counters; a missing pid reports zero usage.
    per_process: BTreeMap<u64, ProcessResourceUsage>,
    /// System-wide counters.
    system: SystemResources,
}

impl StaticResourceAccounting {
    /// An empty accounting source (all counters zero).
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the system-wide counters (builder style).
    #[must_use]
    pub fn with_system(mut self, system: SystemResources) -> Self {
        self.system = system;
        self
    }

    /// Record per-process counters for `pid`.
    pub fn set_process(&mut self, pid: TaskId, usage: ProcessResourceUsage) {
        self.per_process.insert(pid.0, usage);
    }
}

impl ResourceAccounting for StaticResourceAccounting {
    fn process_usage(&self, pid: TaskId) -> ProcessResourceUsage {
        self.per_process.get(&pid.0).copied().unwrap_or_default()
    }

    fn system_resources(&self) -> SystemResources {
        self.system
    }
}

// =============================================================================
// Snapshot
// =============================================================================

/// An immutable point-in-time view of all metrics (WS12-04.4/.5/.6).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct MetricsSnapshot {
    /// Per-process records, ordered by ascending pid (deterministic).
    processes: Vec<ProcessMetrics>,
    /// System-wide record.
    system: SystemMetrics,
}

impl MetricsSnapshot {
    /// Collect a snapshot from the kernel process table and accounting seam.
    ///
    /// Per-process metrics (WS12-04.4) come from the [`ProcessTable`] (pid,
    /// name, lifecycle state) merged with `acct`'s counters; system metrics
    /// (WS12-04.5) are the process/runnable counts plus `acct`'s system-wide
    /// counters. Processes are ordered by ascending pid.
    #[must_use]
    pub fn collect(table: &ProcessTable, acct: &dyn ResourceAccounting) -> Self {
        let mut processes: Vec<ProcessMetrics> = table
            .list()
            .into_iter()
            .map(|entry| {
                let state = if entry.exit_code.is_some() {
                    ProcessState::Zombie
                } else {
                    ProcessState::Running
                };
                ProcessMetrics {
                    pid: entry.id.0,
                    name: entry.name.clone(),
                    state,
                    usage: acct.process_usage(entry.id),
                }
            })
            .collect();
        processes.sort_by_key(|p| p.pid);

        let process_count = u32::try_from(processes.len()).unwrap_or(u32::MAX);
        let runnable = processes
            .iter()
            .filter(|p| p.state == ProcessState::Running)
            .count();
        let runnable_count = u32::try_from(runnable).unwrap_or(u32::MAX);

        Self {
            processes,
            system: SystemMetrics {
                process_count,
                runnable_count,
                resources: acct.system_resources(),
            },
        }
    }

    /// The per-process records (ascending pid).
    #[must_use]
    pub fn processes(&self) -> &[ProcessMetrics] {
        &self.processes
    }

    /// The system-wide record.
    #[must_use]
    pub const fn system(&self) -> &SystemMetrics {
        &self.system
    }

    /// The record for `pid`, if present.
    #[must_use]
    pub fn process(&self, pid: u64) -> Option<&ProcessMetrics> {
        self.processes.iter().find(|p| p.pid == pid)
    }
}

// =============================================================================
// `/proc`-class virtual FS (WS12-04.3 / .6)
// =============================================================================

/// Error reading a path from the [`ProcFs`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProcFsError {
    /// The path does not exist in the `/proc` tree.
    NotFound,
    /// The path is a directory and cannot be read as a file.
    IsADirectory,
    /// The path is a file and cannot be listed as a directory.
    NotADirectory,
}

/// A read-only `/proc`-class virtual filesystem over a [`MetricsSnapshot`]
/// (WS12-04.3).
///
/// The tree is:
///
/// ```text
/// /proc
/// ├── meminfo          # system memory
/// ├── loadavg          # runnable/total + uptime
/// ├── stat             # system IO + uptime
/// └── <pid>/
///     ├── stat         # one-line summary
///     └── status       # key:value detail
/// ```
///
/// [`read`](ProcFs::read) renders a file; [`list`](ProcFs::list) enumerates a
/// directory; [`snapshot`](ProcFs::snapshot) hands the structured data to the
/// monitor client (WS12-04.6).
#[derive(Clone, Debug)]
pub struct ProcFs {
    /// The snapshot every path is rendered from.
    snapshot: MetricsSnapshot,
}

impl ProcFs {
    /// Wrap an already-collected snapshot.
    #[must_use]
    pub const fn new(snapshot: MetricsSnapshot) -> Self {
        Self { snapshot }
    }

    /// Collect a fresh snapshot from the kernel and wrap it.
    #[must_use]
    pub fn from_kernel(table: &ProcessTable, acct: &dyn ResourceAccounting) -> Self {
        Self::new(MetricsSnapshot::collect(table, acct))
    }

    /// The underlying structured snapshot, for the monitor client (WS12-04.6).
    #[must_use]
    pub const fn snapshot(&self) -> &MetricsSnapshot {
        &self.snapshot
    }

    /// Read the file at `path`, returning its rendered text (WS12-04.3).
    ///
    /// # Errors
    ///
    /// - [`ProcFsError::NotFound`] if no such file exists.
    /// - [`ProcFsError::IsADirectory`] if `path` names a directory.
    pub fn read(&self, path: &str) -> Result<String, ProcFsError> {
        let parts = components(path);
        match parts.as_slice() {
            ["proc"] => Err(ProcFsError::IsADirectory),
            ["proc", "meminfo"] => Ok(self.render_meminfo()),
            ["proc", "loadavg"] => Ok(self.render_loadavg()),
            ["proc", "stat"] => Ok(self.render_system_stat()),
            ["proc", pid] => {
                // A bare `/proc/<pid>` is a directory if the pid exists.
                let pid = parse_pid(pid)?;
                if self.snapshot.process(pid).is_some() {
                    Err(ProcFsError::IsADirectory)
                } else {
                    Err(ProcFsError::NotFound)
                }
            }
            ["proc", pid, "stat"] => {
                let p = self.lookup(pid)?;
                Ok(render_process_stat(p))
            }
            ["proc", pid, "status"] => {
                let p = self.lookup(pid)?;
                Ok(render_process_status(p))
            }
            _ => Err(ProcFsError::NotFound),
        }
    }

    /// List the directory at `path` (WS12-04.3).
    ///
    /// # Errors
    ///
    /// - [`ProcFsError::NotFound`] if no such directory exists.
    /// - [`ProcFsError::NotADirectory`] if `path` names a file.
    pub fn list(&self, path: &str) -> Result<Vec<String>, ProcFsError> {
        let parts = components(path);
        match parts.as_slice() {
            ["proc"] => {
                let mut out: Vec<String> = ["loadavg", "meminfo", "stat"]
                    .iter()
                    .map(ToString::to_string)
                    .collect();
                out.extend(self.snapshot.processes.iter().map(|p| p.pid.to_string()));
                Ok(out)
            }
            ["proc", pid] => {
                let _ = self.lookup(pid)?;
                Ok(["stat", "status"].iter().map(ToString::to_string).collect())
            }
            ["proc", _, "stat" | "status"] => Err(ProcFsError::NotADirectory),
            _ => Err(ProcFsError::NotFound),
        }
    }

    /// Resolve a `<pid>` path component to its record, or `NotFound`.
    fn lookup(&self, pid: &str) -> Result<&ProcessMetrics, ProcFsError> {
        let pid = parse_pid(pid)?;
        self.snapshot.process(pid).ok_or(ProcFsError::NotFound)
    }

    fn render_meminfo(&self) -> String {
        let r = &self.snapshot.system.resources;
        format!(
            "MemTotal: {} kB\nMemUsed: {} kB\nMemFree: {} kB\n",
            kib(r.mem_total_bytes),
            kib(r.mem_used_bytes),
            kib(r.mem_free_bytes()),
        )
    }

    fn render_loadavg(&self) -> String {
        let s = &self.snapshot.system;
        // Simplified: runnable/total processes and uptime, in place of the
        // 1/5/15-minute exponential averages (which need a sampling history).
        format!(
            "{}/{} {} us\n",
            s.runnable_count, s.process_count, s.resources.uptime_micros,
        )
    }

    fn render_system_stat(&self) -> String {
        let r = &self.snapshot.system.resources;
        format!(
            "io_read_bytes {}\nio_write_bytes {}\nuptime_micros {}\nprocesses {}\n",
            r.io_read_bytes, r.io_write_bytes, r.uptime_micros, self.snapshot.system.process_count,
        )
    }
}

// =============================================================================
// Rendering helpers
// =============================================================================

/// Render `/proc/<pid>/stat`: a one-line, space-separated summary mirroring the
/// leading fields of Linux `proc(5)`.
fn render_process_stat(p: &ProcessMetrics) -> String {
    format!(
        "{} ({}) {} {} {} {} {}\n",
        p.pid,
        p.name,
        p.state.code(),
        p.usage.cpu_time_micros,
        p.usage.rss_bytes,
        p.usage.virt_bytes,
        p.usage.fd_count,
    )
}

/// Render `/proc/<pid>/status`: human-readable `Key: value` lines.
fn render_process_status(p: &ProcessMetrics) -> String {
    format!(
        "Name: {}\nState: {}\nPid: {}\nCpuTimeMicros: {}\nVmRSS: {} kB\nVmSize: {} kB\nFDSize: {}\n",
        p.name,
        p.state.code(),
        p.pid,
        p.usage.cpu_time_micros,
        kib(p.usage.rss_bytes),
        kib(p.usage.virt_bytes),
        p.usage.fd_count,
    )
}

/// Split a path into its non-empty `/`-separated components.
fn components(path: &str) -> Vec<&str> {
    path.split('/').filter(|s| !s.is_empty()).collect()
}

/// Parse a `<pid>` path component, mapping a non-numeric component to
/// [`ProcFsError::NotFound`].
fn parse_pid(pid: &str) -> Result<u64, ProcFsError> {
    pid.parse::<u64>().map_err(|_| ProcFsError::NotFound)
}

/// Bytes → kibibytes (rounded down), for the `/proc`-style `kB` renderings.
#[allow(
    clippy::integer_division,
    reason = "proc(5) reports memory in whole kB; the truncation is intended"
)]
const fn kib(bytes: u64) -> u64 {
    bytes / 1024
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::missing_docs_in_private_items
)]
mod tests {
    use super::*;

    fn sample() -> ProcFs {
        let mut table = ProcessTable::new();
        table.register(TaskId(1), None, "init".to_string());
        table.register(TaskId(2), Some(TaskId(1)), "shell".to_string());
        table.register(TaskId(3), Some(TaskId(1)), "monitor".to_string());
        // Process 3 has exited (zombie).
        table.record_exit(TaskId(3), 0);

        let mut acct = StaticResourceAccounting::new().with_system(SystemResources {
            mem_total_bytes: 8 * 1024 * 1024,
            mem_used_bytes: 2 * 1024 * 1024,
            io_read_bytes: 4096,
            io_write_bytes: 8192,
            uptime_micros: 1_000_000,
        });
        acct.set_process(
            TaskId(1),
            ProcessResourceUsage {
                cpu_time_micros: 500,
                rss_bytes: 64 * 1024,
                virt_bytes: 256 * 1024,
                fd_count: 5,
            },
        );
        acct.set_process(
            TaskId(2),
            ProcessResourceUsage {
                cpu_time_micros: 1500,
                rss_bytes: 128 * 1024,
                virt_bytes: 512 * 1024,
                fd_count: 9,
            },
        );
        ProcFs::from_kernel(&table, &acct)
    }

    #[test]
    fn snapshot_collects_per_process_and_system() {
        let fs = sample();
        let snap = fs.snapshot();
        assert_eq!(snap.processes().len(), 3);
        assert_eq!(snap.system().process_count, 3);
        // Two running (init, shell), one zombie (monitor).
        assert_eq!(snap.system().runnable_count, 2);

        let init = snap.process(1).unwrap();
        assert_eq!(init.name, "init");
        assert_eq!(init.state, ProcessState::Running);
        assert_eq!(init.usage.fd_count, 5);

        let monitor = snap.process(3).unwrap();
        assert_eq!(monitor.state, ProcessState::Zombie);
        // Unknown to the accounting source → zero usage.
        assert_eq!(monitor.usage, ProcessResourceUsage::default());
    }

    #[test]
    fn processes_are_ordered_by_pid() {
        let fs = sample();
        let pids: Vec<u64> = fs.snapshot().processes().iter().map(|p| p.pid).collect();
        assert_eq!(pids, [1, 2, 3]);
    }

    #[test]
    fn lists_proc_root() {
        let fs = sample();
        let entries = fs.list("/proc").unwrap();
        for name in ["loadavg", "meminfo", "stat", "1", "2", "3"] {
            assert!(entries.iter().any(|e| e == name), "missing {name}");
        }
    }

    #[test]
    fn lists_per_pid_directory() {
        let fs = sample();
        let entries = fs.list("/proc/1").unwrap();
        assert_eq!(entries, ["stat", "status"]);
        // A non-existent pid is NotFound.
        assert_eq!(fs.list("/proc/99"), Err(ProcFsError::NotFound));
    }

    #[test]
    fn reads_meminfo() {
        let fs = sample();
        let text = fs.read("/proc/meminfo").unwrap();
        // 8 MiB total, 2 MiB used → 6 MiB free, in kB.
        assert!(text.contains("MemTotal: 8192 kB"));
        assert!(text.contains("MemUsed: 2048 kB"));
        assert!(text.contains("MemFree: 6144 kB"));
    }

    #[test]
    fn reads_loadavg() {
        let fs = sample();
        let text = fs.read("/proc/loadavg").unwrap();
        assert!(text.starts_with("2/3 "), "got {text:?}");
    }

    #[test]
    fn reads_process_stat_and_status() {
        let fs = sample();
        let stat = fs.read("/proc/2/stat").unwrap();
        assert!(stat.starts_with("2 (shell) R 1500 "), "got {stat:?}");

        let status = fs.read("/proc/1/status").unwrap();
        assert!(status.contains("Name: init"));
        assert!(status.contains("State: R"));
        assert!(status.contains("FDSize: 5"));
    }

    #[test]
    fn directory_read_and_file_list_are_typed_errors() {
        let fs = sample();
        assert_eq!(fs.read("/proc"), Err(ProcFsError::IsADirectory));
        assert_eq!(fs.read("/proc/1"), Err(ProcFsError::IsADirectory));
        assert_eq!(fs.list("/proc/1/stat"), Err(ProcFsError::NotADirectory));
    }

    #[test]
    fn unknown_paths_are_not_found() {
        let fs = sample();
        assert_eq!(fs.read("/proc/1/bogus"), Err(ProcFsError::NotFound));
        assert_eq!(fs.read("/proc/nope/stat"), Err(ProcFsError::NotFound));
        assert_eq!(fs.read("/sys/whatever"), Err(ProcFsError::NotFound));
    }
}
