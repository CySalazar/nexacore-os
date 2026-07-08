//! Telemetry client: read the `/proc`-class surface (WS12-04) and parse it into
//! a structured sample (WS8-05.1).
//!
//! The monitor never talks to the kernel directly; it reads the stable `/proc`
//! text contract through the [`ProcSource`] seam — on hardware that seam is the
//! kernel VFS reached over IPC; in tests it is an in-memory [`MapProcSource`]
//! holding exactly the text the WS12-04 `ProcFs` emits. Parsing that text here
//! keeps the monitor decoupled from the kernel crate, exactly as a Linux system
//! monitor is decoupled from kernel internals by `/proc`.

use alloc::{
    string::{String, ToString},
    vec::Vec,
};

/// The `/proc`-class transport the monitor reads telemetry through (WS8-05.1).
///
/// The production impl bridges to the kernel VFS over IPC; host tests use
/// [`MapProcSource`].
pub trait ProcSource {
    /// Read the file at `path`, returning its text.
    ///
    /// # Errors
    /// Returns [`ClientError::Source`] if the path cannot be read.
    fn read(&self, path: &str) -> Result<String, ClientError>;

    /// List the directory at `path`.
    ///
    /// # Errors
    /// Returns [`ClientError::Source`] if the path cannot be listed.
    fn list(&self, path: &str) -> Result<Vec<String>, ClientError>;
}

/// Error reading or parsing the telemetry surface.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ClientError {
    /// The underlying [`ProcSource`] failed; carries a static reason.
    Source(&'static str),
}

/// One process's parsed metrics (mirrors WS12-04 `/proc/<pid>/stat`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProcessSample {
    /// Process id.
    pub pid: u64,
    /// Process name.
    pub name: String,
    /// Single-char state code (`R` running, `Z` zombie).
    pub state: char,
    /// Cumulative CPU time, microseconds.
    pub cpu_time_micros: u64,
    /// Resident set size, bytes.
    pub rss_bytes: u64,
    /// Virtual address-space size, bytes.
    pub virt_bytes: u64,
    /// Open file-descriptor count.
    pub fd_count: u32,
}

/// A full point-in-time telemetry sample (system counters + per-process rows).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SystemSample {
    /// Time since boot, microseconds (the wall clock for rate derivation).
    pub uptime_micros: u64,
    /// Total physical memory, bytes.
    pub mem_total_bytes: u64,
    /// Used physical memory, bytes.
    pub mem_used_bytes: u64,
    /// Cumulative block-layer bytes read since boot.
    pub io_read_bytes: u64,
    /// Cumulative block-layer bytes written since boot.
    pub io_write_bytes: u64,
    /// Cumulative network bytes received since boot (0 if the surface omits it).
    pub net_rx_bytes: u64,
    /// Cumulative network bytes transmitted since boot (0 if omitted).
    pub net_tx_bytes: u64,
    /// Per-process rows, ordered by ascending pid.
    pub processes: Vec<ProcessSample>,
}

impl SystemSample {
    /// Free physical memory (`total - used`, saturating), bytes.
    #[must_use]
    pub const fn mem_free_bytes(&self) -> u64 {
        self.mem_total_bytes.saturating_sub(self.mem_used_bytes)
    }
}

/// Reads and parses the `/proc` telemetry surface into a [`SystemSample`]
/// (WS8-05.1).
pub struct MonitorClient<S: ProcSource> {
    /// The transport the client reads through.
    source: S,
}

impl<S: ProcSource> MonitorClient<S> {
    /// A client over `source`.
    pub const fn new(source: S) -> Self {
        Self { source }
    }

    /// Borrow the underlying source.
    pub const fn source(&self) -> &S {
        &self.source
    }

    /// Collect one sample: system counters from `/proc/meminfo` and
    /// `/proc/stat`, then a row per pid from `/proc/<pid>/stat`.
    ///
    /// # Errors
    /// Propagates any [`ProcSource`] read/list failure.
    pub fn sample(&self) -> Result<SystemSample, ClientError> {
        let mut out = SystemSample::default();

        // Memory: "MemTotal: N kB" / "MemUsed: N kB" lines.
        let meminfo = self.source.read("/proc/meminfo")?;
        for line in meminfo.lines() {
            if let Some((key, bytes)) = parse_kb_line(line) {
                match key {
                    "MemTotal" => out.mem_total_bytes = bytes,
                    "MemUsed" => out.mem_used_bytes = bytes,
                    _ => {}
                }
            }
        }

        // System counters: "key value" lines.
        let stat = self.source.read("/proc/stat")?;
        for line in stat.lines() {
            if let Some((key, value)) = parse_kv_line(line) {
                match key {
                    "io_read_bytes" => out.io_read_bytes = value,
                    "io_write_bytes" => out.io_write_bytes = value,
                    "uptime_micros" => out.uptime_micros = value,
                    "net_rx_bytes" => out.net_rx_bytes = value,
                    "net_tx_bytes" => out.net_tx_bytes = value,
                    _ => {}
                }
            }
        }

        // Per-process rows: every numeric entry under /proc is a pid directory.
        let mut processes: Vec<ProcessSample> = Vec::new();
        for entry in self.source.list("/proc")? {
            if entry.parse::<u64>().is_err() {
                continue;
            }
            let mut path = String::with_capacity(7 + entry.len());
            path.push_str("/proc/");
            path.push_str(&entry);
            path.push_str("/stat");
            let text = self.source.read(&path)?;
            if let Some(proc_sample) = parse_process_stat(&text) {
                processes.push(proc_sample);
            }
        }
        processes.sort_by_key(|p| p.pid);
        out.processes = processes;

        Ok(out)
    }
}

/// An in-memory [`ProcSource`] for host tests: maps a path to its file text and
/// a directory to its entries.
#[derive(Clone, Debug, Default)]
pub struct MapProcSource {
    /// `path → file text`.
    files: Vec<(String, String)>,
    /// `dir → entry names`.
    dirs: Vec<(String, Vec<String>)>,
}

impl MapProcSource {
    /// An empty source.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a file's text (builder style).
    #[must_use]
    pub fn with_file(mut self, path: impl Into<String>, text: impl Into<String>) -> Self {
        self.files.push((path.into(), text.into()));
        self
    }

    /// Register a directory's entries (builder style).
    #[must_use]
    pub fn with_dir<I, T>(mut self, path: impl Into<String>, entries: I) -> Self
    where
        I: IntoIterator<Item = T>,
        T: Into<String>,
    {
        self.dirs
            .push((path.into(), entries.into_iter().map(Into::into).collect()));
        self
    }
}

impl ProcSource for MapProcSource {
    fn read(&self, path: &str) -> Result<String, ClientError> {
        self.files
            .iter()
            .find(|(p, _)| p == path)
            .map(|(_, text)| text.clone())
            .ok_or(ClientError::Source("no such proc file"))
    }

    fn list(&self, path: &str) -> Result<Vec<String>, ClientError> {
        self.dirs
            .iter()
            .find(|(p, _)| p == path)
            .map(|(_, entries)| entries.clone())
            .ok_or(ClientError::Source("no such proc directory"))
    }
}

// =============================================================================
// Parsing helpers
// =============================================================================

/// Parse a `"Key: N kB"` line into `(key, bytes)`.
fn parse_kb_line(line: &str) -> Option<(&str, u64)> {
    let (key, rest) = line.split_once(':')?;
    let mut toks = rest.split_whitespace();
    let value: u64 = toks.next()?.parse().ok()?;
    let bytes = if toks.next() == Some("kB") {
        value.saturating_mul(1024)
    } else {
        value
    };
    Some((key.trim(), bytes))
}

/// Parse a `"key value"` line into `(key, value)`.
fn parse_kv_line(line: &str) -> Option<(&str, u64)> {
    let mut toks = line.split_whitespace();
    let key = toks.next()?;
    let value: u64 = toks.next()?.parse().ok()?;
    Some((key, value))
}

/// Parse a `/proc/<pid>/stat` line: `pid (name) state cpu rss virt fds`.
fn parse_process_stat(text: &str) -> Option<ProcessSample> {
    let line = text.lines().next()?;
    let open = line.find('(')?;
    let close = line.rfind(')')?;
    if close < open {
        return None;
    }
    let pid: u64 = line.get(..open)?.trim().parse().ok()?;
    let name = line.get(open.checked_add(1)?..close)?.to_string();
    let mut rest = line.get(close.checked_add(1)?..)?.split_whitespace();
    let state = rest.next()?.chars().next()?;
    let cpu_time_micros: u64 = rest.next()?.parse().ok()?;
    let rss_bytes: u64 = rest.next()?.parse().ok()?;
    let virt_bytes: u64 = rest.next()?.parse().ok()?;
    let fd_count: u32 = rest.next()?.parse().ok()?;
    Some(ProcessSample {
        pid,
        name,
        state,
        cpu_time_micros,
        rss_bytes,
        virt_bytes,
        fd_count,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a source mirroring exactly what the WS12-04 `ProcFs` emits.
    fn proc_surface() -> MapProcSource {
        MapProcSource::new()
            .with_file(
                "/proc/meminfo",
                "MemTotal: 8192 kB\nMemUsed: 2048 kB\nMemFree: 6144 kB\n",
            )
            .with_file(
                "/proc/stat",
                "io_read_bytes 4096\nio_write_bytes 8192\nuptime_micros 1000000\nprocesses 2\n",
            )
            .with_dir("/proc", ["loadavg", "meminfo", "stat", "1", "2"])
            .with_file("/proc/1/stat", "1 (init) R 500 65536 262144 5\n")
            .with_file("/proc/2/stat", "2 (shell) R 1500 131072 524288 9\n")
    }

    #[test]
    fn parses_system_counters() {
        let client = MonitorClient::new(proc_surface());
        let s = client.sample().unwrap();
        assert_eq!(s.mem_total_bytes, 8192 * 1024);
        assert_eq!(s.mem_used_bytes, 2048 * 1024);
        assert_eq!(s.mem_free_bytes(), 6144 * 1024);
        assert_eq!(s.io_read_bytes, 4096);
        assert_eq!(s.io_write_bytes, 8192);
        assert_eq!(s.uptime_micros, 1_000_000);
    }

    #[test]
    fn parses_process_rows_sorted_by_pid() {
        let client = MonitorClient::new(proc_surface());
        let s = client.sample().unwrap();
        assert_eq!(s.processes.len(), 2);
        assert_eq!(s.processes[0].pid, 1);
        assert_eq!(s.processes[0].name, "init");
        assert_eq!(s.processes[0].fd_count, 5);
        assert_eq!(s.processes[1].name, "shell");
        assert_eq!(s.processes[1].cpu_time_micros, 1500);
    }

    #[test]
    fn ignores_non_pid_proc_entries() {
        // "loadavg"/"meminfo"/"stat" are not pids and must be skipped.
        let client = MonitorClient::new(proc_surface());
        let s = client.sample().unwrap();
        assert!(s.processes.iter().all(|p| p.pid == 1 || p.pid == 2));
    }

    #[test]
    fn net_counters_default_to_zero_when_absent() {
        let client = MonitorClient::new(proc_surface());
        let s = client.sample().unwrap();
        assert_eq!(s.net_rx_bytes, 0);
        assert_eq!(s.net_tx_bytes, 0);
    }

    #[test]
    fn net_counters_are_read_when_present() {
        let src = MapProcSource::new()
            .with_file("/proc/meminfo", "MemTotal: 1024 kB\nMemUsed: 0 kB\n")
            .with_file(
                "/proc/stat",
                "uptime_micros 10\nnet_rx_bytes 700\nnet_tx_bytes 300\n",
            )
            .with_dir("/proc", ["stat", "meminfo"]);
        let s = MonitorClient::new(src).sample().unwrap();
        assert_eq!(s.net_rx_bytes, 700);
        assert_eq!(s.net_tx_bytes, 300);
    }

    #[test]
    fn source_read_error_propagates() {
        // A source missing /proc/meminfo surfaces the error.
        let src = MapProcSource::new();
        let err = MonitorClient::new(src).sample().unwrap_err();
        assert!(matches!(err, ClientError::Source(_)));
    }

    #[test]
    fn process_name_with_spaces_parses() {
        let text = "7 (my worker) R 10 20 30 1\n";
        let p = parse_process_stat(text).unwrap();
        assert_eq!(p.pid, 7);
        assert_eq!(p.name, "my worker");
        assert_eq!(p.fd_count, 1);
    }
}
