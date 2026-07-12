//! `top` / `htop`-like snapshot view over the [`ProcessSource`] seam (WS8-10.8).
//!
//! A single non-interactive snapshot: the process table sorted by CPU or by
//! memory (descending), optionally truncated to the top *N* rows. Sorting uses
//! the integer [`cpu_permille`](crate::process::ProcessInfo::cpu_permille) /
//! `mem_bytes` fields — no floating point — and breaks ties by ascending pid so
//! the ordering is total and deterministic. Rows are rendered by the shared
//! [`ps` table renderer](crate::ps::render_table).

use alloc::vec::Vec;

use crate::{
    process::{ProcessInfo, ProcessSource},
    ps::{PsColumn, render_table},
};

/// Which field `top` sorts by (always descending).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SortKey {
    /// Sort by CPU usage (permille), highest first (the `top` default).
    Cpu,
    /// Sort by resident memory, largest first.
    Memory,
}

/// Return `source`'s processes sorted by `key` (descending), ties broken by
/// ascending pid, truncated to `limit` rows when `Some`.
#[must_use]
pub fn top_processes<S: ProcessSource>(
    source: &S,
    key: SortKey,
    limit: Option<usize>,
) -> Vec<ProcessInfo> {
    let mut procs = source.processes();
    procs.sort_by(|a, b| {
        let primary = match key {
            SortKey::Cpu => b.cpu_permille.cmp(&a.cpu_permille),
            SortKey::Memory => b.mem_bytes.cmp(&a.mem_bytes),
        };
        // Descending primary key, then ascending pid for a total, stable order.
        primary.then_with(|| a.pid.cmp(&b.pid))
    });
    if let Some(n) = limit {
        procs.truncate(n);
    }
    procs
}

/// The default `top` column set: `PID %CPU RSS STAT COMMAND`.
#[must_use]
fn columns() -> Vec<PsColumn> {
    alloc::vec![
        PsColumn::Pid,
        PsColumn::Cpu,
        PsColumn::Rss,
        PsColumn::State,
        PsColumn::Command,
    ]
}

/// Render a `top` snapshot as aligned table lines (header + sorted rows).
#[must_use]
pub fn top<S: ProcessSource>(
    source: &S,
    key: SortKey,
    limit: Option<usize>,
) -> Vec<alloc::string::String> {
    let procs = top_processes(source, key, limit);
    render_table(&procs, &columns())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::process::{ProcessState, StaticProcessSource};

    fn source() -> StaticProcessSource {
        StaticProcessSource::default()
            .with(ProcessInfo::new(
                1,
                0,
                0,
                "init",
                ProcessState::Sleeping,
                10,
                4096,
            ))
            .with(ProcessInfo::new(
                42,
                1,
                1000,
                "build",
                ProcessState::Running,
                800,
                1_000_000,
            ))
            .with(ProcessInfo::new(
                7,
                1,
                1000,
                "editor",
                ProcessState::Sleeping,
                800,
                5_000_000,
            ))
    }

    #[test]
    fn sorts_by_cpu_desc_then_pid_asc() {
        let procs = top_processes(&source(), SortKey::Cpu, None);
        let pids: Vec<u64> = procs.iter().map(|p| p.pid).collect();
        // 42 and 7 both at 800 permille: tie broken by ascending pid (7 before 42).
        assert_eq!(pids, [7, 42, 1]);
    }

    #[test]
    fn sorts_by_memory_desc() {
        let procs = top_processes(&source(), SortKey::Memory, None);
        let pids: Vec<u64> = procs.iter().map(|p| p.pid).collect();
        // editor 5MB, build 1MB, init 4KB.
        assert_eq!(pids, [7, 42, 1]);
    }

    #[test]
    fn limit_truncates_to_top_n() {
        let procs = top_processes(&source(), SortKey::Memory, Some(2));
        let pids: Vec<u64> = procs.iter().map(|p| p.pid).collect();
        assert_eq!(pids, [7, 42]);
    }

    #[test]
    fn top_renders_header_and_rows() {
        let lines = top(&source(), SortKey::Cpu, Some(1));
        assert!(lines.first().is_some_and(|l| l.starts_with("PID")));
        // Only one process row after the header.
        assert_eq!(lines.len(), 2);
        assert!(lines.get(1).is_some_and(|l| l.ends_with("editor")));
        assert!(lines.get(1).is_some_and(|l| l.contains("80.0")));
    }
}
