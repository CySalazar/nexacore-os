//! Process introspection filesystem (`procfs`) — a read-only [`VfsBackend`]
//! rendering live process state as text files (WS3-02.9).
//!
//! procfs is a two-level synthetic namespace mounted at `/proc`: the root lists
//! one directory per process id, and each `/proc/<pid>/` directory exposes a
//! small set of read-only files (`comm`, `cmdline`, `stat`, `status`) that
//! render the process's runtime state on demand. Nothing is stored on disk — a
//! read materialises the current snapshot held in the [`ProcFs`] process table,
//! which the process manager keeps up to date.
//!
//! The rendering mirrors the well-known Linux `/proc` formats closely enough to
//! be familiar (tab-separated `status` keys, NUL-separated `cmdline`, the
//! single-letter state code) without claiming byte-for-byte parity.

use alloc::{
    collections::BTreeMap,
    format,
    string::{String, ToString},
    vec::Vec,
};

use crate::{
    FileType, FsError,
    vfs::{VfsBackend, VfsDirEntry, VfsMetadata},
};

/// The files exposed under each `/proc/<pid>/` directory.
const PROC_FILES: [&str; 4] = ["cmdline", "comm", "stat", "status"];

/// A process's run state (with its Linux-style single-letter code).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProcState {
    /// Running or runnable (`R`).
    Running,
    /// Sleeping / waiting (`S`).
    Sleeping,
    /// Stopped, e.g. by a signal (`T`).
    Stopped,
    /// Terminated but not yet reaped (`Z`).
    Zombie,
}

impl ProcState {
    /// The single-letter state code (`R`/`S`/`T`/`Z`).
    #[must_use]
    pub fn code(self) -> char {
        match self {
            Self::Running => 'R',
            Self::Sleeping => 'S',
            Self::Stopped => 'T',
            Self::Zombie => 'Z',
        }
    }

    /// The human-readable state label.
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            Self::Running => "running",
            Self::Sleeping => "sleeping",
            Self::Stopped => "stopped",
            Self::Zombie => "zombie",
        }
    }
}

/// A snapshot of one process's runtime state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcessInfo {
    /// Process id.
    pub pid: u32,
    /// Parent process id.
    pub ppid: u32,
    /// Command name (`comm`).
    pub name: String,
    /// Run state.
    pub state: ProcState,
    /// Number of threads.
    pub threads: u32,
    /// Virtual memory size in kilobytes.
    pub vm_size_kb: u64,
    /// Full command line (`argv`); empty falls back to `name`.
    pub cmdline: Vec<String>,
}

impl ProcessInfo {
    /// A new process snapshot with defaults (ppid 0, one thread, no memory,
    /// empty command line).
    #[must_use]
    pub fn new(pid: u32, name: &str, state: ProcState) -> Self {
        Self {
            pid,
            ppid: 0,
            name: name.to_string(),
            state,
            threads: 1,
            vm_size_kb: 0,
            cmdline: Vec::new(),
        }
    }

    /// Render the content of the `/proc/<pid>/<file>` node, or `None` if `file`
    /// is not one of [`PROC_FILES`].
    #[must_use]
    fn render(&self, file: &str) -> Option<Vec<u8>> {
        match file {
            "comm" => Some(format!("{}\n", self.name).into_bytes()),
            "cmdline" => Some(self.render_cmdline()),
            "status" => Some(self.render_status()),
            "stat" => Some(self.render_stat()),
            _ => None,
        }
    }

    fn render_cmdline(&self) -> Vec<u8> {
        if self.cmdline.is_empty() {
            return self.name.clone().into_bytes();
        }
        let mut out = Vec::new();
        for arg in &self.cmdline {
            out.extend_from_slice(arg.as_bytes());
            out.push(0); // NUL-separated, with a trailing NUL, like Linux.
        }
        out
    }

    fn render_status(&self) -> Vec<u8> {
        format!(
            "Name:\t{}\nState:\t{} ({})\nPid:\t{}\nPPid:\t{}\nThreads:\t{}\nVmSize:\t{} kB\n",
            self.name,
            self.state.code(),
            self.state.label(),
            self.pid,
            self.ppid,
            self.threads,
            self.vm_size_kb,
        )
        .into_bytes()
    }

    fn render_stat(&self) -> Vec<u8> {
        // A subset of the Linux one-liner: pid (comm) state ppid threads vsize.
        format!(
            "{} ({}) {} {} {} {}\n",
            self.pid,
            self.name,
            self.state.code(),
            self.ppid,
            self.threads,
            self.vm_size_kb.saturating_mul(1024),
        )
        .into_bytes()
    }
}

/// The process introspection filesystem: a table of pid → [`ProcessInfo`].
#[derive(Debug, Clone, Default)]
pub struct ProcFs {
    procs: BTreeMap<u32, ProcessInfo>,
}

impl ProcFs {
    /// An empty process table.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Insert (or replace) a process snapshot, keyed by its pid.
    pub fn insert(&mut self, info: ProcessInfo) {
        self.procs.insert(info.pid, info);
    }

    /// Remove the process `pid`, returning its snapshot if present.
    pub fn remove(&mut self, pid: u32) -> Option<ProcessInfo> {
        self.procs.remove(&pid)
    }

    /// The snapshot for `pid`, if present.
    #[must_use]
    pub fn get(&self, pid: u32) -> Option<&ProcessInfo> {
        self.procs.get(&pid)
    }

    /// The process ids currently present, in ascending order.
    #[must_use]
    pub fn pids(&self) -> Vec<u32> {
        self.procs.keys().copied().collect()
    }

    /// The number of processes.
    #[must_use]
    pub fn len(&self) -> usize {
        self.procs.len()
    }

    /// Whether the process table is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.procs.is_empty()
    }
}

/// Parse a path component as a pid (`/proc/<pid>`).
fn parse_pid(component: &str) -> Option<u32> {
    component.parse::<u32>().ok()
}

/// Copy `content[offset..]` into `buf`, returning the number of bytes copied
/// (0 at or past end-of-file). Bounds-safe: an out-of-range offset yields 0.
fn read_slice(content: &[u8], offset: u64, buf: &mut [u8]) -> usize {
    let start = usize::try_from(offset).unwrap_or(usize::MAX);
    let Some(rest) = content.get(start..) else {
        return 0;
    };
    let n = rest.len().min(buf.len());
    if let (Some(dst), Some(src)) = (buf.get_mut(..n), rest.get(..n)) {
        dst.copy_from_slice(src);
    }
    n
}

impl VfsBackend for ProcFs {
    fn name(&self) -> &'static str {
        "procfs"
    }

    fn metadata(&self, rel: &[&str]) -> Result<VfsMetadata, FsError> {
        match rel {
            // Root, and each existing `/proc/<pid>`, are directories.
            [] => Ok(VfsMetadata {
                file_type: FileType::Directory,
                len: 0,
            }),
            [pid] if parse_pid(pid).is_some_and(|p| self.procs.contains_key(&p)) => {
                Ok(VfsMetadata {
                    file_type: FileType::Directory,
                    len: 0,
                })
            }
            // `/proc/<pid>/<file>` is a regular file sized by its rendered form.
            [pid, file] => {
                let p = parse_pid(pid).ok_or(FsError::FileNotFound)?;
                let proc = self.procs.get(&p).ok_or(FsError::FileNotFound)?;
                let content = proc.render(file).ok_or(FsError::FileNotFound)?;
                Ok(VfsMetadata {
                    file_type: FileType::RegularFile,
                    len: u64::try_from(content.len()).unwrap_or(u64::MAX),
                })
            }
            _ => Err(FsError::FileNotFound),
        }
    }

    fn read_dir(&self, rel: &[&str]) -> Result<Vec<VfsDirEntry>, FsError> {
        match rel {
            [] => Ok(self
                .procs
                .keys()
                .map(|pid| VfsDirEntry {
                    name: format!("{pid}"),
                    file_type: FileType::Directory,
                })
                .collect()),
            [pid] if parse_pid(pid).is_some_and(|p| self.procs.contains_key(&p)) => Ok(PROC_FILES
                .iter()
                .map(|f| VfsDirEntry {
                    name: (*f).to_string(),
                    file_type: FileType::RegularFile,
                })
                .collect()),
            [pid, file]
                if parse_pid(pid).is_some_and(|p| self.procs.contains_key(&p))
                    && PROC_FILES.contains(file) =>
            {
                Err(FsError::NotADirectory)
            }
            _ => Err(FsError::FileNotFound),
        }
    }

    fn read(&self, rel: &[&str], offset: u64, buf: &mut [u8]) -> Result<usize, FsError> {
        match rel {
            [pid, file] => {
                let p = parse_pid(pid).ok_or(FsError::FileNotFound)?;
                let proc = self.procs.get(&p).ok_or(FsError::FileNotFound)?;
                let content = proc.render(file).ok_or(FsError::FileNotFound)?;
                Ok(read_slice(&content, offset, buf))
            }
            // The root and process directories are not files.
            [] => Err(FsError::NotAFile),
            [pid] if parse_pid(pid).is_some_and(|p| self.procs.contains_key(&p)) => {
                Err(FsError::NotAFile)
            }
            _ => Err(FsError::FileNotFound),
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use alloc::boxed::Box;

    use super::*;
    use crate::vfs::MountTable;

    fn sample() -> ProcFs {
        let mut fs = ProcFs::new();
        let mut init = ProcessInfo::new(1, "init", ProcState::Sleeping);
        init.threads = 1;
        init.vm_size_kb = 2048;
        init.cmdline = alloc::vec![String::from("/sbin/init"), String::from("--boot")];
        fs.insert(init);

        let mut shell = ProcessInfo::new(42, "nsh", ProcState::Running);
        shell.ppid = 1;
        fs.insert(shell);
        fs
    }

    #[test]
    fn root_lists_pids_as_directories() {
        let fs = sample();
        assert_eq!(fs.pids(), alloc::vec![1, 42]);
        let mut entries = fs.read_dir(&[]).unwrap();
        entries.sort_by(|a, b| a.name.cmp(&b.name));
        assert_eq!(entries[0].name, "1");
        assert_eq!(entries[0].file_type, FileType::Directory);
        assert_eq!(entries[1].name, "42");
    }

    #[test]
    fn pid_dir_lists_the_proc_files() {
        let fs = sample();
        let mut names: Vec<String> = fs
            .read_dir(&["1"])
            .unwrap()
            .into_iter()
            .map(|e| e.name)
            .collect();
        names.sort();
        assert_eq!(names, alloc::vec!["cmdline", "comm", "stat", "status"]);
        // An unknown pid directory is not found.
        assert_eq!(fs.read_dir(&["999"]).unwrap_err(), FsError::FileNotFound);
    }

    #[test]
    fn status_renders_runtime_state() {
        let fs = sample();
        let mut buf = [0u8; 256];
        let n = fs.read(&["1", "status"], 0, &mut buf).unwrap();
        let text = core::str::from_utf8(&buf[..n]).unwrap();
        assert!(text.contains("Name:\tinit\n"));
        assert!(text.contains("State:\tS (sleeping)\n"));
        assert!(text.contains("PPid:\t0\n"));
        assert!(text.contains("VmSize:\t2048 kB\n"));
    }

    #[test]
    fn cmdline_is_nul_separated_with_fallback() {
        let fs = sample();
        let mut buf = [0u8; 64];
        // pid 1 has an explicit argv.
        let n = fs.read(&["1", "cmdline"], 0, &mut buf).unwrap();
        assert_eq!(&buf[..n], b"/sbin/init\0--boot\0");
        // pid 42 has no argv → falls back to the command name (no NUL).
        let n = fs.read(&["42", "cmdline"], 0, &mut buf).unwrap();
        assert_eq!(&buf[..n], b"nsh");
    }

    #[test]
    fn read_supports_offsets_and_eof() {
        let fs = sample();
        let mut full = [0u8; 64];
        let total = fs.read(&["42", "comm"], 0, &mut full).unwrap();
        assert_eq!(&full[..total], b"nsh\n");
        // Read from an offset.
        let mut part = [0u8; 64];
        let n = fs.read(&["42", "comm"], 2, &mut part).unwrap();
        assert_eq!(&part[..n], b"h\n");
        // Offset at/after EOF yields no bytes.
        assert_eq!(fs.read(&["42", "comm"], 4, &mut part).unwrap(), 0);
        assert_eq!(fs.read(&["42", "comm"], 99, &mut part).unwrap(), 0);
    }

    #[test]
    fn errors_for_directories_and_unknowns() {
        let fs = sample();
        let mut buf = [0u8; 8];
        // Reading a directory is NotAFile; an unknown file is FileNotFound.
        assert_eq!(fs.read(&[], 0, &mut buf).unwrap_err(), FsError::NotAFile);
        assert_eq!(fs.read(&["1"], 0, &mut buf).unwrap_err(), FsError::NotAFile);
        assert_eq!(
            fs.read(&["1", "ghost"], 0, &mut buf).unwrap_err(),
            FsError::FileNotFound
        );
        // read_dir on a file path is NotADirectory.
        assert_eq!(
            fs.read_dir(&["1", "status"]).unwrap_err(),
            FsError::NotADirectory
        );
    }

    #[test]
    fn mounts_under_proc_via_the_vfs() {
        let mut table = MountTable::new();
        table.mount("/proc", Box::new(sample())).unwrap();
        assert_eq!(
            table.metadata("/proc/42").unwrap().file_type,
            FileType::Directory
        );
        let meta = table.metadata("/proc/42/comm").unwrap();
        assert_eq!(meta.file_type, FileType::RegularFile);
        assert_eq!(meta.len, 4); // "nsh\n"
        let mut buf = [0u8; 16];
        let n = table.read("/proc/42/comm", 0, &mut buf).unwrap();
        assert_eq!(&buf[..n], b"nsh\n");
    }
}
