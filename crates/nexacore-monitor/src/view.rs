//! Presentation models: live CPU/RAM history, disk/net throughput, and the
//! per-process resource table (WS8-05.2/.3/.4).
//!
//! All values are integers: usages are **permille** (‰, 0..=1000) and
//! throughputs are **bytes per second**. No float arithmetic is used, so the
//! views are deterministic and `no_std`-clean. CPU usage and throughput are
//! *rates*, so they are derived from two successive [`SystemSample`]s; memory
//! usage is a level, derived from a single sample.

use alloc::{collections::VecDeque, vec::Vec};

use crate::client::{ProcessSample, SystemSample};

// =============================================================================
// Live series (WS8-05.2)
// =============================================================================

/// A fixed-capacity ring buffer of recent integer-permille readings, backing a
/// live CPU or RAM graph (WS8-05.2).
#[derive(Clone, Debug)]
pub struct LiveSeries {
    /// Most-recent-last readings, capped at `capacity`.
    samples: VecDeque<u32>,
    /// Maximum retained readings.
    capacity: usize,
}

impl LiveSeries {
    /// A new series retaining up to `capacity` readings (clamped to ≥ 1).
    #[must_use]
    pub fn new(capacity: usize) -> Self {
        let capacity = capacity.max(1);
        Self {
            samples: VecDeque::with_capacity(capacity),
            capacity,
        }
    }

    /// Append a reading, evicting the oldest if at capacity.
    pub fn push(&mut self, permille: u32) {
        if self.samples.len() == self.capacity {
            self.samples.pop_front();
        }
        self.samples.push_back(permille);
    }

    /// The readings, oldest first.
    pub fn values(&self) -> impl Iterator<Item = u32> + '_ {
        self.samples.iter().copied()
    }

    /// The most recent reading, if any.
    #[must_use]
    pub fn latest(&self) -> Option<u32> {
        self.samples.back().copied()
    }

    /// The largest retained reading (0 if empty) — the graph's y-scale.
    #[must_use]
    pub fn peak(&self) -> u32 {
        self.samples.iter().copied().max().unwrap_or(0)
    }

    /// Number of retained readings.
    #[must_use]
    pub fn len(&self) -> usize {
        self.samples.len()
    }

    /// Whether the series has no readings.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.samples.is_empty()
    }
}

/// Memory usage of `sample`, in permille of total (0 if total is 0)
/// (WS8-05.2).
#[must_use]
pub fn memory_permille(sample: &SystemSample) -> u32 {
    ratio_permille(sample.mem_used_bytes, sample.mem_total_bytes)
}

/// System-wide CPU usage between two samples, in permille of one core
/// (WS8-05.2).
///
/// Sums each still-present process's CPU-time delta over the wall-clock
/// (uptime) delta. A process absent from `prev` contributes its full `curr`
/// CPU time (it ran entirely within the interval). Returns 0 if the interval
/// has no elapsed time.
#[must_use]
pub fn system_cpu_permille(prev: &SystemSample, curr: &SystemSample) -> u32 {
    let elapsed = curr.uptime_micros.saturating_sub(prev.uptime_micros);
    if elapsed == 0 {
        return 0;
    }
    let mut busy: u64 = 0;
    for p in &curr.processes {
        let before = prev
            .processes
            .iter()
            .find(|q| q.pid == p.pid)
            .map_or(0, |q| q.cpu_time_micros);
        busy = busy.saturating_add(p.cpu_time_micros.saturating_sub(before));
    }
    ratio_permille(busy, elapsed)
}

// =============================================================================
// Disk / network throughput (WS8-05.3)
// =============================================================================

/// Throughput rates derived from two successive samples, in bytes per second
/// (WS8-05.3).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[allow(
    clippy::struct_field_names,
    reason = "the shared `_bps` suffix is the unit (bytes/sec), not redundant noise"
)]
pub struct DiskNetRates {
    /// Block-layer read throughput, bytes/sec.
    pub disk_read_bps: u64,
    /// Block-layer write throughput, bytes/sec.
    pub disk_write_bps: u64,
    /// Network receive throughput, bytes/sec.
    pub net_rx_bps: u64,
    /// Network transmit throughput, bytes/sec.
    pub net_tx_bps: u64,
}

impl DiskNetRates {
    /// Derive throughput rates from the cumulative counters in `prev`/`curr`
    /// over their uptime delta (WS8-05.3). All-zero if no time elapsed.
    #[must_use]
    pub fn between(prev: &SystemSample, curr: &SystemSample) -> Self {
        let elapsed = curr.uptime_micros.saturating_sub(prev.uptime_micros);
        Self {
            disk_read_bps: rate_per_sec(
                curr.io_read_bytes.saturating_sub(prev.io_read_bytes),
                elapsed,
            ),
            disk_write_bps: rate_per_sec(
                curr.io_write_bytes.saturating_sub(prev.io_write_bytes),
                elapsed,
            ),
            net_rx_bps: rate_per_sec(curr.net_rx_bytes.saturating_sub(prev.net_rx_bytes), elapsed),
            net_tx_bps: rate_per_sec(curr.net_tx_bytes.saturating_sub(prev.net_tx_bytes), elapsed),
        }
    }
}

// =============================================================================
// Process table (WS8-05.4)
// =============================================================================

/// The column a [`ProcessTable`] is sorted by.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SortKey {
    /// Ascending pid.
    Pid,
    /// Descending CPU usage (busiest first).
    Cpu,
    /// Descending resident memory (largest first).
    Memory,
}

/// One row of the per-process resource table (WS8-05.4).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProcessRow {
    /// The underlying process sample.
    pub proc: ProcessSample,
    /// CPU usage over the sampling interval, permille of one core.
    pub cpu_permille: u32,
}

/// The per-process resource table (WS8-05.4): one [`ProcessRow`] per process,
/// with CPU usage derived from the interval and a chosen sort order.
#[derive(Clone, Debug, Default)]
pub struct ProcessTable {
    /// The rows, in their current sort order.
    rows: Vec<ProcessRow>,
}

impl ProcessTable {
    /// Build the table from two successive samples so per-process CPU usage can
    /// be derived; rows start in ascending-pid order.
    #[must_use]
    pub fn from_delta(prev: &SystemSample, curr: &SystemSample) -> Self {
        let elapsed = curr.uptime_micros.saturating_sub(prev.uptime_micros);
        let rows = curr
            .processes
            .iter()
            .map(|p| {
                let before = prev
                    .processes
                    .iter()
                    .find(|q| q.pid == p.pid)
                    .map_or(0, |q| q.cpu_time_micros);
                let busy = p.cpu_time_micros.saturating_sub(before);
                ProcessRow {
                    proc: p.clone(),
                    cpu_permille: ratio_permille(busy, elapsed),
                }
            })
            .collect();
        Self { rows }
    }

    /// Build a table from a single sample (CPU usage 0 for every row — no
    /// interval to derive a rate from).
    #[must_use]
    pub fn snapshot(curr: &SystemSample) -> Self {
        let rows = curr
            .processes
            .iter()
            .map(|p| ProcessRow {
                proc: p.clone(),
                cpu_permille: 0,
            })
            .collect();
        Self { rows }
    }

    /// The rows in their current order.
    #[must_use]
    pub fn rows(&self) -> &[ProcessRow] {
        &self.rows
    }

    /// Number of rows.
    #[must_use]
    pub fn len(&self) -> usize {
        self.rows.len()
    }

    /// Whether the table has no rows.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.rows.is_empty()
    }

    /// Re-sort the rows by `key` (consuming-builder style).
    #[must_use]
    pub fn sorted_by(mut self, key: SortKey) -> Self {
        match key {
            SortKey::Pid => self.rows.sort_by_key(|r| r.proc.pid),
            SortKey::Cpu => self.rows.sort_by(|a, b| {
                b.cpu_permille
                    .cmp(&a.cpu_permille)
                    .then(a.proc.pid.cmp(&b.proc.pid))
            }),
            SortKey::Memory => self.rows.sort_by(|a, b| {
                b.proc
                    .rss_bytes
                    .cmp(&a.proc.rss_bytes)
                    .then(a.proc.pid.cmp(&b.proc.pid))
            }),
        }
        self
    }
}

// =============================================================================
// Integer ratio / rate helpers
// =============================================================================

/// `part / whole` as permille (0..), saturating; 0 when `whole` is 0.
#[allow(
    clippy::integer_division,
    reason = "permille is an integer ratio; the truncation is the intended rounding"
)]
fn ratio_permille(part: u64, whole: u64) -> u32 {
    if whole == 0 {
        return 0;
    }
    let pm = part.saturating_mul(1000) / whole;
    u32::try_from(pm).unwrap_or(u32::MAX)
}

/// `delta_bytes` over `delta_micros`, as bytes per second; 0 when no time
/// elapsed.
#[allow(
    clippy::integer_division,
    reason = "a byte/second rate is an integer division; truncation is intended"
)]
fn rate_per_sec(delta_bytes: u64, delta_micros: u64) -> u64 {
    if delta_micros == 0 {
        return 0;
    }
    delta_bytes.saturating_mul(1_000_000) / delta_micros
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::client::ProcessSample;

    fn proc(pid: u64, cpu: u64, rss: u64) -> ProcessSample {
        ProcessSample {
            pid,
            name: alloc::format!("p{pid}"),
            state: 'R',
            cpu_time_micros: cpu,
            rss_bytes: rss,
            virt_bytes: rss.saturating_mul(4),
            fd_count: 3,
        }
    }

    fn sample(uptime: u64, mem_used: u64, procs: Vec<ProcessSample>) -> SystemSample {
        SystemSample {
            uptime_micros: uptime,
            mem_total_bytes: 1000,
            mem_used_bytes: mem_used,
            processes: procs,
            ..SystemSample::default()
        }
    }

    #[test]
    fn live_series_caps_and_tracks_peak() {
        let mut s = LiveSeries::new(3);
        for v in [100, 200, 300, 400] {
            s.push(v);
        }
        // Capacity 3: oldest (100) evicted.
        let vals: Vec<u32> = s.values().collect();
        assert_eq!(vals, [200, 300, 400]);
        assert_eq!(s.latest(), Some(400));
        assert_eq!(s.peak(), 400);
        assert_eq!(s.len(), 3);
    }

    #[test]
    fn memory_permille_is_used_over_total() {
        let s = sample(0, 250, Vec::new());
        assert_eq!(memory_permille(&s), 250); // 250/1000 = 250‰
    }

    #[test]
    fn system_cpu_permille_from_deltas() {
        // 1 process burns 500us of CPU over a 1000us wall interval = 500‰.
        let prev = sample(1000, 0, alloc::vec![proc(1, 1000, 10)]);
        let curr = sample(2000, 0, alloc::vec![proc(1, 1500, 10)]);
        assert_eq!(system_cpu_permille(&prev, &curr), 500);
    }

    #[test]
    fn cpu_permille_zero_when_no_time_elapsed() {
        let prev = sample(1000, 0, alloc::vec![proc(1, 1000, 10)]);
        let curr = sample(1000, 0, alloc::vec![proc(1, 9999, 10)]);
        assert_eq!(system_cpu_permille(&prev, &curr), 0);
    }

    #[test]
    fn new_process_contributes_full_cpu() {
        // pid 2 appears only in curr with 200us of CPU over a 1000us interval.
        let prev = sample(0, 0, alloc::vec![proc(1, 0, 10)]);
        let curr = sample(1000, 0, alloc::vec![proc(1, 0, 10), proc(2, 200, 10)]);
        assert_eq!(system_cpu_permille(&prev, &curr), 200);
    }

    #[test]
    fn disk_net_rates_are_bytes_per_second() {
        let mut prev = sample(0, 0, Vec::new());
        prev.io_read_bytes = 0;
        prev.io_write_bytes = 0;
        prev.net_rx_bytes = 0;
        let mut curr = sample(1_000_000, 0, Vec::new()); // 1 second later
        curr.io_read_bytes = 4096;
        curr.io_write_bytes = 8192;
        curr.net_rx_bytes = 1500;
        let r = DiskNetRates::between(&prev, &curr);
        assert_eq!(r.disk_read_bps, 4096);
        assert_eq!(r.disk_write_bps, 8192);
        assert_eq!(r.net_rx_bps, 1500);
        assert_eq!(r.net_tx_bps, 0);
    }

    #[test]
    fn process_table_sorts_by_cpu_and_memory() {
        let prev = sample(0, 0, alloc::vec![proc(1, 0, 10), proc(2, 0, 50)]);
        let curr = sample(1000, 0, alloc::vec![proc(1, 800, 10), proc(2, 100, 50)]);
        let by_cpu = ProcessTable::from_delta(&prev, &curr).sorted_by(SortKey::Cpu);
        assert_eq!(by_cpu.rows()[0].proc.pid, 1); // 800‰ > 100‰
        assert_eq!(by_cpu.rows()[0].cpu_permille, 800);

        let by_mem = ProcessTable::from_delta(&prev, &curr).sorted_by(SortKey::Memory);
        assert_eq!(by_mem.rows()[0].proc.pid, 2); // rss 50 > 10
    }

    #[test]
    fn process_table_snapshot_has_zero_cpu() {
        let curr = sample(1000, 0, alloc::vec![proc(1, 800, 10)]);
        let t = ProcessTable::snapshot(&curr);
        assert_eq!(t.rows()[0].cpu_permille, 0);
        assert_eq!(t.len(), 1);
    }
}
