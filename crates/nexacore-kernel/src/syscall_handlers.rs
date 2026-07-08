//! Testable syscall handler logic bridging userspace syscalls to kernel
//! data structures.
//!
//! This module is intentionally **not** gated behind the `bare-metal` feature
//! so the handler logic can be exercised in host-side unit tests without the
//! full page-table / ELF-loader infrastructure.
//!
//! ## Architecture
//!
//! [`crate::syscall_handlers::KernelState`] bundles every subsystem reference a
//! syscall handler needs. Each `handle_*` method is a pure function of that
//! state: given the syscall arguments it mutates the relevant subsystem and
//! returns a [`crate::syscall::SyscallReturn`]. The bare-metal entry path
//! constructs a `KernelState` view over the per-process globals and calls the
//! appropriate handler; the test suite constructs isolated instances via
//! [`crate::syscall_handlers::KernelState::new_for_test`].
//!
//! ## Error mapping
//!
//! Errors from the subsystem layer (e.g. [`crate::vfs::VfsError`],
//! [`crate::pipe::PipeError`]) are mapped to POSIX errno codes defined in
//! [`crate::syscall::syscall_errno`] and returned in the `rdx` field of
//! [`crate::syscall::SyscallReturn`].
//!
//! ## `no_std` compatibility
//!
//! All heap allocation goes through `alloc` types. No `std` import is present.

#![allow(
    clippy::missing_errors_doc,
    reason = "syscall handlers return SyscallReturn; errors are encoded in rdx, not propagated as Result"
)]

use alloc::{
    string::{String, ToString},
    vec::Vec,
};

use crate::{
    console_input::ConsoleInputBuffer,
    fd::{FdFlags, FdKind, FileDescriptor, FileDescriptorTable, OpenFlags, RawFd},
    pipe::{PipeError, PipeId, PipeRegistry},
    process_table::ProcessTable,
    scheduling::TaskId,
    syscall::{SyscallReturn, syscall_errno},
    vfs::{FileType, InMemoryVfs, VfsError},
};

/// Upper bound on the staging buffer a single `read` / `read_console` syscall
/// allocates.
///
/// The caller supplies the requested length; without a cap a hostile or buggy
/// task could request a near-`usize::MAX` read and make the kernel allocate
/// (and, on the pipe path, zero-fill) an arbitrarily large `Vec`, exhausting
/// the bump heap (NCIP-026 R4 — WI-4b review follow-up). `read` is allowed to
/// return fewer bytes than requested, so callers simply loop for more. Mirrors
/// the 1 MiB bound the bare-metal `fd_write` path applies to the write side.
pub const MAX_READ_LEN: usize = 1 << 20;

// ---------------------------------------------------------------------------
// KernelState
// ---------------------------------------------------------------------------

/// Aggregates all kernel subsystem state needed by a syscall handler.
///
/// In the bare-metal kernel this struct is constructed as a short-lived
/// view over the global per-process statics for the duration of a single
/// syscall. In tests, [`KernelState::new_for_test`] creates a
/// fully-isolated instance.
///
/// All fields are `pub` so the bare-metal wiring layer can populate them
/// without an additional builder indirection.
///
/// # Example
///
/// ```rust
/// use nexacore_kernel::syscall_handlers::KernelState;
///
/// let state = KernelState::new_for_test();
/// // stdin/stdout/stderr are pre-opened at fds 0, 1, 2.
/// assert!(state.fd_table.get(nexacore_kernel::fd::RawFd(0)).is_some());
/// ```
pub struct KernelState {
    /// Per-process open file descriptor table.
    pub fd_table: FileDescriptorTable,
    /// Global anonymous-pipe registry.
    pub pipe_registry: PipeRegistry,
    /// Kernel console input ring buffer (keyboard / serial).
    pub console_input: ConsoleInputBuffer,
    /// In-memory virtual filesystem.
    pub vfs: InMemoryVfs,
    /// Kernel process table.
    pub process_table: ProcessTable,
    /// The task ID of the process currently executing the syscall.
    pub current_task: TaskId,
}

impl KernelState {
    /// Construct a `KernelState` suitable for host-side unit tests.
    ///
    /// The returned state has:
    /// - `fd_table`: pre-populated with stdin/stdout/stderr (fds 0, 1, 2).
    /// - `pipe_registry`: empty.
    /// - `console_input`: empty.
    /// - `vfs`: fresh filesystem with root directory only.
    /// - `process_table`: one entry registered as `TaskId(1)` named `"test"`.
    /// - `current_task`: `TaskId(1)`.
    ///
    /// # Example
    ///
    /// ```rust
    /// use nexacore_kernel::syscall_handlers::KernelState;
    ///
    /// let state = KernelState::new_for_test();
    /// let (ret, cwd) = state.handle_get_cwd();
    /// assert_eq!(ret.rdx, 0);
    /// assert_eq!(cwd, "/");
    /// ```
    #[must_use]
    pub fn new_for_test() -> Self {
        let mut process_table = ProcessTable::new();
        process_table.register(TaskId(1), None, "test".into());

        Self {
            fd_table: FileDescriptorTable::new_with_stdio(),
            pipe_registry: PipeRegistry::new(),
            console_input: ConsoleInputBuffer::new(),
            vfs: InMemoryVfs::new(),
            process_table,
            current_task: TaskId(1),
        }
    }

    // -----------------------------------------------------------------------
    // Path resolution helper
    // -----------------------------------------------------------------------

    /// Resolve `path` to an absolute, normalised path string.
    ///
    /// If `path` already starts with `/` it is normalised in place against
    /// the VFS's own normaliser. Otherwise it is resolved relative to the
    /// `current_task`'s current working directory (defaulting to `"/"` when
    /// the process is not registered).
    fn resolve_path(&self, path: &str) -> String {
        let base = self.process_table.get_cwd(self.current_task).unwrap_or("/");
        InMemoryVfs::normalize_path(base, path)
    }

    // -----------------------------------------------------------------------
    // I/O — console
    // -----------------------------------------------------------------------

    /// Read bytes from the kernel console input buffer (line-buffered).
    ///
    /// Drains up to `buf_capacity` bytes from the console ring buffer using
    /// line-buffered mode. Returns the number of bytes read in `rax`.
    /// Returns `SyscallReturn::ok(0)` if the buffer is empty; the caller is
    /// responsible for blocking the task and retrying after new input arrives.
    ///
    /// # Example
    ///
    /// ```rust
    /// use nexacore_kernel::syscall_handlers::KernelState;
    ///
    /// let mut state = KernelState::new_for_test();
    /// state.console_input.push_byte(b'h');
    /// state.console_input.push_byte(b'i');
    /// state.console_input.push_byte(b'\n');
    /// let ret = state.handle_read_console(64);
    /// assert_eq!(ret.rax, 3);
    /// assert_eq!(ret.rdx, 0);
    /// ```
    pub fn handle_read_console(&mut self, buf_capacity: u64) -> SyscallReturn {
        let max = usize::try_from(buf_capacity)
            .unwrap_or(usize::MAX)
            .min(MAX_READ_LEN);
        let bytes = self.console_input.read_bytes(max, true);
        let n = u64::try_from(bytes.len()).unwrap_or(u64::MAX);
        SyscallReturn::ok(n)
    }

    // -----------------------------------------------------------------------
    // I/O — pipe
    // -----------------------------------------------------------------------

    /// Create an anonymous pipe and open both ends as file descriptors.
    ///
    /// Allocates a new pipe in the registry, then opens two fds:
    /// - `rax`: the read end fd.
    /// - `rdx`: the write end fd.
    ///
    /// Both fields carry valid fd numbers on success. On allocation failure
    /// (fd table exhausted) returns `SyscallReturn::err(ENOSPC)`.
    ///
    /// # Example
    ///
    /// ```rust
    /// use nexacore_kernel::syscall_handlers::KernelState;
    ///
    /// let mut state = KernelState::new_for_test();
    /// let ret = state.handle_pipe_create();
    /// assert!(ret.rax >= 3, "read fd must be above stdio range");
    /// assert!(ret.rdx >= 3, "write fd must be above stdio range");
    /// assert_ne!(ret.rax, ret.rdx, "read and write fds must be distinct");
    /// ```
    pub fn handle_pipe_create(&mut self) -> SyscallReturn {
        let pipe_id = self.pipe_registry.create();

        let Ok(rfd) = self.fd_table.open(FileDescriptor {
            kind: FdKind::Pipe {
                pipe_id: pipe_id.0,
                is_read_end: true,
            },
            flags: FdFlags::default(),
        }) else {
            self.pipe_registry.remove(pipe_id);
            return SyscallReturn::err(syscall_errno::ENOSPC);
        };

        let Ok(wfd) = self.fd_table.open(FileDescriptor {
            kind: FdKind::Pipe {
                pipe_id: pipe_id.0,
                is_read_end: false,
            },
            flags: FdFlags::default(),
        }) else {
            // Roll back the read fd we already opened.
            let _ = self.fd_table.close(rfd);
            self.pipe_registry.remove(pipe_id);
            return SyscallReturn::err(syscall_errno::ENOSPC);
        };

        SyscallReturn {
            rax: u64::from(rfd.0),
            rdx: u64::from(wfd.0),
        }
    }

    // -----------------------------------------------------------------------
    // I/O — generic fd read
    // -----------------------------------------------------------------------

    /// Read up to `max_len` bytes from file descriptor `fd`.
    ///
    /// Dispatches on the [`FdKind`]:
    /// - `Console { readable: true }` → drains the console input buffer
    ///   (line-buffered).
    /// - `Console { readable: false }` → write-only console; returns
    ///   `(err(EBADF), empty)`.
    /// - `Pipe { is_read_end: true }` → reads from the pipe ring.
    /// - `Pipe { is_read_end: false }` → write-only end; returns
    ///   `(err(EBADF), empty)`.
    /// - `FsFile` → reads from the VFS at the current offset.
    /// - `IpcChannel` → not yet supported; returns `(err(ENOSYS), empty)`.
    ///
    /// Returns `(SyscallReturn, Vec<u8>)` where `rax` is the byte count and
    /// the `Vec` contains the actual bytes. On error the Vec is empty.
    ///
    /// # Example
    ///
    /// ```rust
    /// use nexacore_kernel::syscall_handlers::KernelState;
    ///
    /// let mut state = KernelState::new_for_test();
    /// state.console_input.push_byte(b'A');
    /// state.console_input.push_byte(b'\n');
    /// let (ret, data) = state.handle_fd_read(0, 64);
    /// assert_eq!(ret.rdx, 0);
    /// assert_eq!(data, b"A\n");
    /// ```
    pub fn handle_fd_read(&mut self, fd: u32, max_len: u64) -> (SyscallReturn, Vec<u8>) {
        let kind = match self.fd_table.get(RawFd(fd)) {
            Some(desc) => desc.kind.clone(),
            None => return (SyscallReturn::err(syscall_errno::EBADF), Vec::new()),
        };

        let max = usize::try_from(max_len)
            .unwrap_or(usize::MAX)
            .min(MAX_READ_LEN);

        match kind {
            FdKind::Console { readable, .. } => {
                if !readable {
                    return (SyscallReturn::err(syscall_errno::EBADF), Vec::new());
                }
                let bytes = self.console_input.read_bytes(max, true);
                let n = u64::try_from(bytes.len()).unwrap_or(u64::MAX);
                (SyscallReturn::ok(n), bytes)
            }

            FdKind::Pipe {
                pipe_id,
                is_read_end,
            } => {
                if !is_read_end {
                    return (SyscallReturn::err(syscall_errno::EBADF), Vec::new());
                }
                let Some(ring) = self.pipe_registry.get_mut(PipeId(pipe_id)) else {
                    return (SyscallReturn::err(syscall_errno::EBADF), Vec::new());
                };
                let mut buf = alloc::vec![0u8; max];
                match ring.read(&mut buf) {
                    Ok(n) => {
                        buf.truncate(n);
                        let count = u64::try_from(n).unwrap_or(u64::MAX);
                        (SyscallReturn::ok(count), buf)
                    }
                    Err(PipeError::BrokenPipe) => {
                        (SyscallReturn::err(syscall_errno::EPIPE), Vec::new())
                    }
                }
            }

            FdKind::FsFile { inode, offset, .. } => {
                match self.vfs.read_file(inode, offset, max) {
                    Ok(bytes) => {
                        let n = bytes.len();
                        // Advance the stored offset inside the fd entry.
                        if let Some(desc) = self.fd_table.get_mut(RawFd(fd)) {
                            if let FdKind::FsFile { offset: off, .. } = &mut desc.kind {
                                *off = offset.saturating_add(u64::try_from(n).unwrap_or(u64::MAX));
                            }
                        }
                        let count = u64::try_from(n).unwrap_or(u64::MAX);
                        (SyscallReturn::ok(count), bytes)
                    }
                    Err(VfsError::NotFound) => {
                        (SyscallReturn::err(syscall_errno::ENOENT), Vec::new())
                    }
                    Err(_) => (SyscallReturn::err(syscall_errno::EIO), Vec::new()),
                }
            }

            FdKind::IpcChannel(_) => (SyscallReturn::err(syscall_errno::ENOSYS), Vec::new()),
        }
    }

    // -----------------------------------------------------------------------
    // I/O — generic fd write
    // -----------------------------------------------------------------------

    /// Write `data` to file descriptor `fd`.
    ///
    /// Dispatches on the [`FdKind`]:
    /// - `Console { writable: true }` → returns `data.len()` (the physical
    ///   write is performed by the bare-metal layer; this handler only
    ///   validates the fd).
    /// - `Console { writable: false }` → read-only console; returns
    ///   `err(EBADF)`.
    /// - `Pipe { is_read_end: false }` → writes to the pipe ring.
    /// - `Pipe { is_read_end: true }` → read-only end; returns `err(EBADF)`.
    /// - `FsFile` → writes to the VFS; advances the offset. In append mode
    ///   the write starts at the current file size.
    /// - `IpcChannel` → returns `err(ENOSYS)`.
    ///
    /// Returns `rax = bytes_written` on success, or `err(errno)` on failure.
    ///
    /// # Example
    ///
    /// ```rust
    /// use nexacore_kernel::syscall_handlers::KernelState;
    ///
    /// let mut state = KernelState::new_for_test();
    /// // Writing to stdout (fd 1) succeeds.
    /// let ret = state.handle_fd_write(1, b"hello");
    /// assert_eq!(ret.rax, 5);
    /// assert_eq!(ret.rdx, 0);
    /// ```
    pub fn handle_fd_write(&mut self, fd: u32, data: &[u8]) -> SyscallReturn {
        let kind = match self.fd_table.get(RawFd(fd)) {
            Some(desc) => desc.kind.clone(),
            None => return SyscallReturn::err(syscall_errno::EBADF),
        };

        match kind {
            FdKind::Console { writable, .. } => {
                if !writable {
                    return SyscallReturn::err(syscall_errno::EBADF);
                }
                // The bare-metal layer performs the actual character output.
                // Here we only validate and account the byte count.
                let n = u64::try_from(data.len()).unwrap_or(u64::MAX);
                SyscallReturn::ok(n)
            }

            FdKind::Pipe {
                pipe_id,
                is_read_end,
            } => {
                if is_read_end {
                    return SyscallReturn::err(syscall_errno::EBADF);
                }
                let Some(ring) = self.pipe_registry.get_mut(PipeId(pipe_id)) else {
                    return SyscallReturn::err(syscall_errno::EBADF);
                };
                match ring.write(data) {
                    Ok(n) => {
                        let count = u64::try_from(n).unwrap_or(u64::MAX);
                        SyscallReturn::ok(count)
                    }
                    Err(PipeError::BrokenPipe) => SyscallReturn::err(syscall_errno::EPIPE),
                }
            }

            FdKind::FsFile {
                inode,
                offset,
                flags,
            } => {
                // In append mode the write position is always end-of-file,
                // regardless of the current offset cursor.
                let write_offset = if flags.has_append() {
                    self.vfs.file_size(inode).unwrap_or(offset)
                } else {
                    offset
                };

                match self.vfs.write_file(inode, write_offset, data) {
                    Ok(n) => {
                        // Advance the stored offset.
                        if let Some(desc) = self.fd_table.get_mut(RawFd(fd)) {
                            if let FdKind::FsFile { offset: off, .. } = &mut desc.kind {
                                *off = write_offset
                                    .saturating_add(u64::try_from(n).unwrap_or(u64::MAX));
                            }
                        }
                        let count = u64::try_from(n).unwrap_or(u64::MAX);
                        SyscallReturn::ok(count)
                    }
                    Err(VfsError::NotFound) => SyscallReturn::err(syscall_errno::ENOENT),
                    Err(_) => SyscallReturn::err(syscall_errno::EIO),
                }
            }

            FdKind::IpcChannel(_) => SyscallReturn::err(syscall_errno::ENOSYS),
        }
    }

    // -----------------------------------------------------------------------
    // fd management — close
    // -----------------------------------------------------------------------

    /// Close file descriptor `fd`.
    ///
    /// If the fd references a pipe end, the corresponding `close_write` or
    /// `close_read` is called on the [`crate::pipe::PipeRing`] so waiting
    /// tasks can be unblocked by the caller (the scheduler wakes the
    /// returned task IDs; this handler discards them — the bare-metal layer
    /// reads them from the ring after the syscall returns).
    ///
    /// Returns `ok(0)` on success, `err(EBADF)` if the fd is not open.
    ///
    /// # Example
    ///
    /// ```rust
    /// use nexacore_kernel::syscall_handlers::KernelState;
    ///
    /// let mut state = KernelState::new_for_test();
    /// let ret = state.handle_fd_close(0);
    /// assert_eq!(ret.rax, 0);
    /// assert_eq!(ret.rdx, 0);
    /// ```
    pub fn handle_fd_close(&mut self, fd: u32) -> SyscallReturn {
        // Capture the kind before closing so we can perform pipe cleanup.
        let kind = match self.fd_table.get(RawFd(fd)) {
            Some(desc) => desc.kind.clone(),
            None => return SyscallReturn::err(syscall_errno::EBADF),
        };

        // Notify the pipe subsystem before removing the fd entry.
        // The woken task list is intentionally dropped here; the bare-metal
        // layer (or the test) must drain waiters after calling this handler
        // if it needs to reschedule.
        if let FdKind::Pipe {
            pipe_id,
            is_read_end,
        } = kind
        {
            if let Some(ring) = self.pipe_registry.get_mut(PipeId(pipe_id)) {
                if is_read_end {
                    let _ = ring.close_read();
                } else {
                    let _ = ring.close_write();
                }
            }
        }

        match self.fd_table.close(RawFd(fd)) {
            Ok(()) => SyscallReturn::ok(0),
            Err(_) => SyscallReturn::err(syscall_errno::EBADF),
        }
    }

    // -----------------------------------------------------------------------
    // fd management — dup / dup2
    // -----------------------------------------------------------------------

    /// Duplicate file descriptor `fd` to the lowest available number.
    ///
    /// Delegates to [`FileDescriptorTable::dup`]. Returns the new fd number
    /// in `rax` on success, or `err(EBADF)` if `fd` is not open.
    ///
    /// # Example
    ///
    /// ```rust
    /// use nexacore_kernel::syscall_handlers::KernelState;
    ///
    /// let mut state = KernelState::new_for_test();
    /// let ret = state.handle_fd_dup(1);
    /// assert_eq!(ret.rdx, 0);
    /// assert!(ret.rax >= 3);
    /// ```
    pub fn handle_fd_dup(&mut self, fd: u32) -> SyscallReturn {
        self.fd_table.dup(RawFd(fd)).map_or_else(
            |_| SyscallReturn::err(syscall_errno::EBADF),
            |new_fd| SyscallReturn::ok(u64::from(new_fd.0)),
        )
    }

    /// Duplicate file descriptor `old_fd` to the specific number `new_fd`.
    ///
    /// If `new_fd` was a pipe end, the pipe is closed first (matching POSIX
    /// `dup2` semantics for resources that require cleanup). The `fd_table`'s
    /// built-in `dup2` handles the silent close; this handler adds the extra
    /// pipe-close step for that case.
    ///
    /// Returns `new_fd` in `rax` on success, or `err(EBADF)` if `old_fd`
    /// is not open.
    ///
    /// # Example
    ///
    /// ```rust
    /// use nexacore_kernel::syscall_handlers::KernelState;
    ///
    /// let mut state = KernelState::new_for_test();
    /// let ret = state.handle_fd_dup2(1, 2);
    /// assert_eq!(ret.rax, 2);
    /// assert_eq!(ret.rdx, 0);
    /// ```
    pub fn handle_fd_dup2(&mut self, old_fd: u32, new_fd: u32) -> SyscallReturn {
        // If new_fd is currently a pipe end, close that pipe end before dup2
        // displaces the entry. The fd_table.dup2 call will then replace the
        // slot without knowing what was there before.
        if let Some(existing) = self.fd_table.get(RawFd(new_fd)) {
            if let FdKind::Pipe {
                pipe_id,
                is_read_end,
            } = existing.kind.clone()
            {
                if let Some(ring) = self.pipe_registry.get_mut(PipeId(pipe_id)) {
                    if is_read_end {
                        let _ = ring.close_read();
                    } else {
                        let _ = ring.close_write();
                    }
                }
            }
        }

        self.fd_table
            .dup2(RawFd(old_fd), RawFd(new_fd))
            .map_or_else(
                |_| SyscallReturn::err(syscall_errno::EBADF),
                |result_fd| SyscallReturn::ok(u64::from(result_fd.0)),
            )
    }

    // -----------------------------------------------------------------------
    // fd management — seek
    // -----------------------------------------------------------------------

    /// Seek within a file-backed file descriptor.
    ///
    /// Only `FsFile` descriptors are seekable. Console and pipe fds return
    /// `err(ESPIPE)`. `IpcChannel` fds return `err(ESPIPE)` as well.
    ///
    /// `whence` values:
    /// - `0` (`SEEK_SET`): new offset = `offset`.
    /// - `1` (`SEEK_CUR`): new offset = `current_offset` + `offset`.
    /// - `2` (`SEEK_END`): new offset = `file_size` + `offset`.
    ///
    /// `offset` is interpreted as a signed value; a negative seek past
    /// position 0 returns `err(EINVAL)`. An unknown `whence` value also
    /// returns `err(EINVAL)`.
    ///
    /// Returns `rax = new_offset` on success.
    ///
    /// # Example
    ///
    /// ```rust
    /// use nexacore_kernel::syscall_handlers::KernelState;
    ///
    /// let mut state = KernelState::new_for_test();
    /// let fd_ret = state.handle_fs_open(
    ///     "/seek.txt",
    ///     nexacore_kernel::fd::OpenFlags::O_RDWR | nexacore_kernel::fd::OpenFlags::O_CREAT,
    /// );
    /// assert_eq!(fd_ret.rdx, 0);
    /// let fd = fd_ret.rax as u32;
    /// state.handle_fd_write(fd, b"hello");
    /// // Seek to beginning.
    /// let seek_ret = state.handle_fd_seek(fd, 0, 0);
    /// assert_eq!(seek_ret.rax, 0);
    /// assert_eq!(seek_ret.rdx, 0);
    /// ```
    pub fn handle_fd_seek(&mut self, fd: u32, offset: i64, whence: u32) -> SyscallReturn {
        const SEEK_SET: u32 = 0;
        const SEEK_CUR: u32 = 1;
        const SEEK_END: u32 = 2;

        let kind = match self.fd_table.get(RawFd(fd)) {
            Some(desc) => desc.kind.clone(),
            None => return SyscallReturn::err(syscall_errno::EBADF),
        };

        match kind {
            FdKind::FsFile {
                inode,
                offset: current_offset,
                ..
            } => {
                let new_offset: Option<u64> = match whence {
                    SEEK_SET => {
                        if offset < 0 {
                            None
                        } else {
                            u64::try_from(offset).ok()
                        }
                    }
                    SEEK_CUR => {
                        // Compute current_offset + offset (signed), check >= 0.
                        let cur = i64::try_from(current_offset).unwrap_or(i64::MAX);
                        cur.checked_add(offset).and_then(|v| u64::try_from(v).ok())
                    }
                    SEEK_END => {
                        let Ok(file_size) = self.vfs.file_size(inode) else {
                            return SyscallReturn::err(syscall_errno::EIO);
                        };
                        let size_i64 = i64::try_from(file_size).unwrap_or(i64::MAX);
                        size_i64
                            .checked_add(offset)
                            .and_then(|v| u64::try_from(v).ok())
                    }
                    _ => return SyscallReturn::err(syscall_errno::EINVAL),
                };

                match new_offset {
                    Some(pos) => {
                        if let Some(desc) = self.fd_table.get_mut(RawFd(fd)) {
                            if let FdKind::FsFile { offset: off, .. } = &mut desc.kind {
                                *off = pos;
                            }
                        }
                        SyscallReturn::ok(pos)
                    }
                    None => SyscallReturn::err(syscall_errno::EINVAL),
                }
            }

            // Pipes and consoles are not seekable.
            FdKind::Console { .. } | FdKind::Pipe { .. } | FdKind::IpcChannel(_) => {
                SyscallReturn::err(syscall_errno::ESPIPE)
            }
        }
    }

    /// Allocate an fd for an already-resolved inode.
    fn open_fd_for_inode(&mut self, inode: u64, open_flags: OpenFlags) -> SyscallReturn {
        let fd_result = self.fd_table.open(FileDescriptor {
            kind: FdKind::FsFile {
                inode,
                offset: 0,
                flags: open_flags,
            },
            flags: FdFlags::default(),
        });
        fd_result.map_or_else(
            |_| SyscallReturn::err(syscall_errno::ENOSPC),
            |fd| SyscallReturn::ok(u64::from(fd.0)),
        )
    }

    // -----------------------------------------------------------------------
    // Filesystem — open
    // -----------------------------------------------------------------------

    /// Open a file at `path` with the given `flags` (an [`OpenFlags`] bitmask).
    ///
    /// Path resolution uses the current task's cwd for relative paths.
    ///
    /// Behaviour:
    /// - If `O_CREAT` is set and the file does not exist, it is created.
    /// - If `O_TRUNC` is set and the file exists, it is truncated to zero
    ///   length before the fd is opened (write is performed by writing an
    ///   empty slice at offset 0, which the VFS treats as a size reset via
    ///   the truncate semantic of `write_file` at offset 0 with no data).
    /// - The initial file offset is 0 unless `O_APPEND` is set, in which
    ///   case it starts at the file size (the actual seek happens on each
    ///   write; the offset stored in the fd is 0 at open time).
    ///
    /// Returns `rax = fd_number` on success, or `err(errno)` on failure.
    ///
    /// # Example
    ///
    /// ```rust
    /// use nexacore_kernel::{fd::OpenFlags, syscall_handlers::KernelState};
    ///
    /// let mut state = KernelState::new_for_test();
    /// let ret = state.handle_fs_open("/tmp.txt", OpenFlags::O_RDWR | OpenFlags::O_CREAT);
    /// assert_eq!(ret.rdx, 0);
    /// assert!(ret.rax >= 3);
    /// ```
    pub fn handle_fs_open(&mut self, path: &str, flags: u32) -> SyscallReturn {
        let abs = self.resolve_path(path);
        let open_flags = OpenFlags(flags);

        // Determine whether the file exists.
        let inode_result = self.vfs.stat(&abs);

        let inode = match inode_result {
            Ok(stat) => {
                // File exists. If it is a directory and write access is
                // requested, reject with EISDIR.
                if stat.file_type == FileType::Directory
                    && (open_flags.is_writable() || open_flags.has_trunc())
                {
                    return SyscallReturn::err(syscall_errno::EINVAL);
                }
                // Truncate if requested: delete and recreate the file.
                if open_flags.has_trunc() && open_flags.is_writable() {
                    let _ = self.vfs.delete(&abs);
                    match self.vfs.create_file(&abs) {
                        Ok(new_inode) => return self.open_fd_for_inode(new_inode, open_flags),
                        Err(_) => return SyscallReturn::err(syscall_errno::EIO),
                    }
                }
                stat.inode
            }
            Err(VfsError::NotFound) => {
                if open_flags.has_create() {
                    // Create the file.
                    match self.vfs.create_file(&abs) {
                        Ok(ino) => ino,
                        Err(VfsError::AlreadyExists) => {
                            // Race-free: some other call created it between
                            // the stat and the create. Retrieve the inode.
                            match self.vfs.stat(&abs) {
                                Ok(s) => s.inode,
                                Err(_) => return SyscallReturn::err(syscall_errno::EIO),
                            }
                        }
                        Err(VfsError::NotADirectory | VfsError::InvalidPath) => {
                            return SyscallReturn::err(syscall_errno::EINVAL);
                        }
                        Err(_) => return SyscallReturn::err(syscall_errno::EIO),
                    }
                } else {
                    return SyscallReturn::err(syscall_errno::ENOENT);
                }
            }
            Err(VfsError::NotADirectory) => return SyscallReturn::err(syscall_errno::EINVAL),
            Err(_) => return SyscallReturn::err(syscall_errno::EIO),
        };

        let fd_result = self.fd_table.open(FileDescriptor {
            kind: FdKind::FsFile {
                inode,
                offset: 0,
                flags: open_flags,
            },
            flags: FdFlags::default(),
        });

        fd_result.map_or_else(
            |_| SyscallReturn::err(syscall_errno::ENOSPC),
            |fd| SyscallReturn::ok(u64::from(fd.0)),
        )
    }

    // -----------------------------------------------------------------------
    // Filesystem — stat
    // -----------------------------------------------------------------------

    /// Stat a file or directory at `path`.
    ///
    /// Returns `(SyscallReturn::ok(0), Some((inode, size, file_type_byte)))` on
    /// success, or `(SyscallReturn::err(ENOENT), None)` when the path does not
    /// exist.
    ///
    /// `file_type_byte`: `0` = regular file, `1` = directory.
    ///
    /// # Example
    ///
    /// ```rust
    /// use nexacore_kernel::syscall_handlers::KernelState;
    ///
    /// let mut state = KernelState::new_for_test();
    /// state.handle_fs_create("/stat_test.txt");
    /// let (ret, info) = state.handle_fs_stat("/stat_test.txt");
    /// assert_eq!(ret.rdx, 0);
    /// let (inode, size, ftype) = info.unwrap();
    /// assert_eq!(size, 0);
    /// assert_eq!(ftype, 0); // regular file
    /// ```
    pub fn handle_fs_stat(&self, path: &str) -> (SyscallReturn, Option<(u64, u64, u8)>) {
        let abs = self.resolve_path(path);
        match self.vfs.stat(&abs) {
            Ok(stat) => {
                let type_byte: u8 = match stat.file_type {
                    FileType::RegularFile => 0,
                    FileType::Directory => 1,
                };
                (
                    SyscallReturn::ok(0),
                    Some((stat.inode, stat.size, type_byte)),
                )
            }
            Err(VfsError::NotFound) => (SyscallReturn::err(syscall_errno::ENOENT), None),
            Err(_) => (SyscallReturn::err(syscall_errno::EIO), None),
        }
    }

    // -----------------------------------------------------------------------
    // Filesystem — list directory
    // -----------------------------------------------------------------------

    /// List the entries of the directory at `path`.
    ///
    /// Returns `(SyscallReturn::ok(count), Vec<String>)` where each element is
    /// a bare entry name (no leading `/`). On error returns
    /// `(err(errno), empty Vec)`.
    ///
    /// # Example
    ///
    /// ```rust
    /// use nexacore_kernel::syscall_handlers::KernelState;
    ///
    /// let mut state = KernelState::new_for_test();
    /// state.handle_fs_create("/a.txt");
    /// let (ret, names) = state.handle_fs_list_dir("/");
    /// assert_eq!(ret.rdx, 0);
    /// assert!(names.contains(&"a.txt".to_string()));
    /// ```
    pub fn handle_fs_list_dir(&self, path: &str) -> (SyscallReturn, Vec<String>) {
        let abs = self.resolve_path(path);
        match self.vfs.list_directory(&abs) {
            Ok(entries) => {
                let names: Vec<String> = entries.into_iter().map(|e| e.name).collect();
                let count = u64::try_from(names.len()).unwrap_or(u64::MAX);
                (SyscallReturn::ok(count), names)
            }
            Err(VfsError::NotFound) => (SyscallReturn::err(syscall_errno::ENOENT), Vec::new()),
            Err(VfsError::NotADirectory) => (SyscallReturn::err(syscall_errno::EINVAL), Vec::new()),
            Err(_) => (SyscallReturn::err(syscall_errno::EIO), Vec::new()),
        }
    }

    // -----------------------------------------------------------------------
    // Filesystem — create / delete / mkdir
    // -----------------------------------------------------------------------

    /// Create an empty regular file at `path`.
    ///
    /// Returns `ok(0)` on success.
    /// Returns `err(EEXIST)` if the path already exists.
    /// Returns `err(ENOENT)` if a parent component does not exist.
    ///
    /// # Example
    ///
    /// ```rust
    /// use nexacore_kernel::syscall_handlers::KernelState;
    ///
    /// let mut state = KernelState::new_for_test();
    /// let ret = state.handle_fs_create("/newfile.txt");
    /// assert_eq!(ret.rax, 0);
    /// assert_eq!(ret.rdx, 0);
    /// ```
    pub fn handle_fs_create(&mut self, path: &str) -> SyscallReturn {
        let abs = self.resolve_path(path);
        match self.vfs.create_file(&abs) {
            Ok(_) => SyscallReturn::ok(0),
            Err(VfsError::AlreadyExists) => SyscallReturn::err(syscall_errno::EEXIST),
            Err(VfsError::NotFound) => SyscallReturn::err(syscall_errno::ENOENT),
            Err(VfsError::NotADirectory | VfsError::InvalidPath) => {
                SyscallReturn::err(syscall_errno::EINVAL)
            }
            Err(_) => SyscallReturn::err(syscall_errno::EIO),
        }
    }

    /// Delete the file or empty directory at `path`.
    ///
    /// Returns `ok(0)` on success.
    /// Returns `err(ENOENT)` if the path does not exist.
    /// Returns `err(ENOTEMPTY)` if the path is a non-empty directory.
    ///
    /// # Example
    ///
    /// ```rust
    /// use nexacore_kernel::syscall_handlers::KernelState;
    ///
    /// let mut state = KernelState::new_for_test();
    /// state.handle_fs_create("/del.txt");
    /// let ret = state.handle_fs_delete("/del.txt");
    /// assert_eq!(ret.rax, 0);
    /// assert_eq!(ret.rdx, 0);
    /// ```
    pub fn handle_fs_delete(&mut self, path: &str) -> SyscallReturn {
        let abs = self.resolve_path(path);
        match self.vfs.delete(&abs) {
            Ok(()) => SyscallReturn::ok(0),
            Err(VfsError::NotFound) => SyscallReturn::err(syscall_errno::ENOENT),
            Err(VfsError::NotEmpty) => SyscallReturn::err(syscall_errno::ENOTEMPTY),
            Err(VfsError::InvalidPath) => SyscallReturn::err(syscall_errno::EINVAL),
            Err(_) => SyscallReturn::err(syscall_errno::EIO),
        }
    }

    /// Create a directory at `path`.
    ///
    /// Returns `ok(0)` on success.
    /// Returns `err(EEXIST)` if the path already exists.
    /// Returns `err(ENOENT)` if a parent component does not exist.
    ///
    /// # Example
    ///
    /// ```rust
    /// use nexacore_kernel::syscall_handlers::KernelState;
    ///
    /// let mut state = KernelState::new_for_test();
    /// let ret = state.handle_fs_mkdir("/mydir");
    /// assert_eq!(ret.rax, 0);
    /// assert_eq!(ret.rdx, 0);
    /// assert!(state.vfs.exists("/mydir"));
    /// ```
    pub fn handle_fs_mkdir(&mut self, path: &str) -> SyscallReturn {
        let abs = self.resolve_path(path);
        match self.vfs.create_directory(&abs) {
            Ok(_) => SyscallReturn::ok(0),
            Err(VfsError::AlreadyExists) => SyscallReturn::err(syscall_errno::EEXIST),
            Err(VfsError::NotFound) => SyscallReturn::err(syscall_errno::ENOENT),
            Err(VfsError::NotADirectory | VfsError::InvalidPath) => {
                SyscallReturn::err(syscall_errno::EINVAL)
            }
            Err(_) => SyscallReturn::err(syscall_errno::EIO),
        }
    }

    // -----------------------------------------------------------------------
    // Process — cwd
    // -----------------------------------------------------------------------

    /// Get the current working directory of `current_task`.
    ///
    /// Returns `(ok(path_len), cwd_string)`. When the process is not
    /// registered, returns `(ok(1), "/")` as a safe fallback.
    ///
    /// # Example
    ///
    /// ```rust
    /// use nexacore_kernel::syscall_handlers::KernelState;
    ///
    /// let state = KernelState::new_for_test();
    /// let (ret, cwd) = state.handle_get_cwd();
    /// assert_eq!(cwd, "/");
    /// assert_eq!(ret.rdx, 0);
    /// ```
    pub fn handle_get_cwd(&self) -> (SyscallReturn, String) {
        let cwd = self
            .process_table
            .get_cwd(self.current_task)
            .unwrap_or("/")
            .to_string();
        let len = u64::try_from(cwd.len()).unwrap_or(u64::MAX);
        (SyscallReturn::ok(len), cwd)
    }

    /// Set the current working directory of `current_task` to `path`.
    ///
    /// The path must resolve to an existing directory in the VFS; otherwise
    /// `err(ENOENT)` is returned. Setting cwd to a regular file returns
    /// `err(EINVAL)`.
    ///
    /// Returns `ok(0)` on success.
    ///
    /// # Example
    ///
    /// ```rust
    /// use nexacore_kernel::syscall_handlers::KernelState;
    ///
    /// let mut state = KernelState::new_for_test();
    /// state.handle_fs_mkdir("/workspace");
    /// let ret = state.handle_set_cwd("/workspace");
    /// assert_eq!(ret.rax, 0);
    /// assert_eq!(ret.rdx, 0);
    /// ```
    pub fn handle_set_cwd(&mut self, path: &str) -> SyscallReturn {
        let abs = self.resolve_path(path);

        match self.vfs.stat(&abs) {
            Ok(stat) => {
                if stat.file_type != FileType::Directory {
                    return SyscallReturn::err(syscall_errno::EINVAL);
                }
            }
            Err(VfsError::NotFound) => return SyscallReturn::err(syscall_errno::ENOENT),
            Err(_) => return SyscallReturn::err(syscall_errno::EIO),
        }

        self.process_table.set_cwd(self.current_task, abs);
        SyscallReturn::ok(0)
    }

    // -----------------------------------------------------------------------
    // Process — wait
    // -----------------------------------------------------------------------

    /// Wait for a child process to exit.
    ///
    /// `child_pid`: target child PID. Pass `0` to wait for any child.
    /// `flags`: bit 0 = `WNOHANG` — if set and no child has exited yet,
    ///   return `ok(0)` with `rdx = 0` immediately instead of blocking.
    ///
    /// On success returns `SyscallReturn { rax: exit_code, rdx: child_pid }`.
    /// When `WNOHANG` is set and no child has exited, returns
    /// `SyscallReturn { rax: 0, rdx: 0 }`.
    ///
    /// Note: `child_pid != 0` targeting is not yet implemented in the
    /// `ProcessTable` API (which only exposes `reap_child` for any child).
    /// This handler currently always waits for any child regardless of
    /// `child_pid`, matching the behaviour of a future implementation that
    /// adds per-PID targeting.
    ///
    /// # Example
    ///
    /// ```rust
    /// use nexacore_kernel::{scheduling::TaskId, syscall_handlers::KernelState};
    ///
    /// let mut state = KernelState::new_for_test();
    /// state
    ///     .process_table
    ///     .register(TaskId(2), Some(TaskId(1)), "child".into());
    /// state.process_table.record_exit(TaskId(2), 42);
    /// let ret = state.handle_process_wait(0, 0);
    /// assert_eq!(ret.rax, 42);
    /// assert_eq!(ret.rdx, 2);
    /// ```
    pub fn handle_process_wait(&mut self, _child_pid: u64, flags: u64) -> SyscallReturn {
        // The WNOHANG flag (bit 0 of flags) is meaningful only to the bare-metal
        // scheduling layer which decides whether to block the calling task.
        // At the kernel-state level the return value is the same in both cases.
        // Suppress the unused-variable warning with an explicit type annotation.
        #[allow(
            clippy::no_effect_underscore_binding,
            reason = "wnohang is documented API surface consumed by the bare-metal caller; not dead code"
        )]
        let _wnohang: bool = flags & 1 != 0;

        if let Some((child_id, exit_code)) = self.process_table.reap_child(self.current_task) {
            SyscallReturn {
                rax: exit_code,
                rdx: child_id.0,
            }
        } else {
            // No exited child: return (0, 0). The bare-metal layer checks
            // `_wnohang` to decide whether to block the calling task.
            SyscallReturn { rax: 0, rdx: 0 }
        }
    }

    // -----------------------------------------------------------------------
    // Process — list
    // -----------------------------------------------------------------------

    /// Return a snapshot of all registered processes.
    ///
    /// Each entry in the returned `Vec` is `(pid, name, has_exited)`.
    ///
    /// # Example
    ///
    /// ```rust
    /// use nexacore_kernel::syscall_handlers::KernelState;
    ///
    /// let state = KernelState::new_for_test();
    /// let (ret, procs) = state.handle_process_list();
    /// assert_eq!(ret.rdx, 0);
    /// assert!(!procs.is_empty());
    /// ```
    pub fn handle_process_list(&self) -> (SyscallReturn, Vec<(u64, String, bool)>) {
        let entries: Vec<(u64, String, bool)> = self
            .process_table
            .list()
            .into_iter()
            .map(|e| (e.id.0, e.name.clone(), e.exit_code.is_some()))
            .collect();
        let count = u64::try_from(entries.len()).unwrap_or(u64::MAX);
        (SyscallReturn::ok(count), entries)
    }

    // -----------------------------------------------------------------------
    // Process — kill
    // -----------------------------------------------------------------------

    /// Record an exit code of 137 (SIGKILL equivalent) for `target_pid`.
    ///
    /// This does not actually terminate the process in a scheduler sense —
    /// the bare-metal layer must remove the task from the run queue after
    /// this call. The handler only records the exit in the process table so
    /// a waiting parent can reap it.
    ///
    /// Returns `ok(0)` on success, `err(ESRCH)` if `target_pid` is not
    /// registered.
    ///
    /// # Example
    ///
    /// ```rust
    /// use nexacore_kernel::{scheduling::TaskId, syscall_handlers::KernelState};
    ///
    /// let mut state = KernelState::new_for_test();
    /// state
    ///     .process_table
    ///     .register(TaskId(5), None, "victim".into());
    /// let ret = state.handle_process_kill(5);
    /// assert_eq!(ret.rax, 0);
    /// assert_eq!(ret.rdx, 0);
    /// ```
    pub fn handle_process_kill(&mut self, target_pid: u64) -> SyscallReturn {
        if self.process_table.get(TaskId(target_pid)).is_none() {
            return SyscallReturn::err(syscall_errno::ESRCH);
        }
        // 137 = 128 + SIGKILL(9): conventional Unix exit-status for SIGKILL.
        self.process_table.record_exit(TaskId(target_pid), 137);
        SyscallReturn::ok(0)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::cast_possible_truncation,
    reason = "test code: unwrap/panic as intended failure mode; fd numbers from SyscallReturn.rax/rdx are always ≤ u32::MAX by construction"
)]
mod tests {
    use super::*;
    use crate::scheduling::TaskId;

    // -----------------------------------------------------------------------
    // Pipe tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_pipe_create_returns_two_fds() {
        let mut state = KernelState::new_for_test();
        let ret = state.handle_pipe_create();
        // rdx carries the write fd on success (non-zero), rax the read fd.
        // Both should be >= 3 (above the stdio range).
        assert_eq!(ret.rdx, 4, "write fd should be 4 (next after read fd 3)");
        // Actually rdx here is the write fd number per handle_pipe_create:
        // SyscallReturn { rax: read_fd, rdx: write_fd }
        // The error check convention: rdx==0 means no error for other handlers,
        // but handle_pipe_create puts the write fd in rdx.
        // Both fds must be valid (>= 3 for the first call after stdio).
        assert!(ret.rax >= 3, "read fd must be at or above fd 3");
        assert!(ret.rdx >= 3, "write fd must be at or above fd 3");
        assert_ne!(ret.rax, ret.rdx, "read and write fds must be distinct");
        // Verify both fds are registered.
        assert!(
            state.fd_table.get(RawFd(ret.rax as u32)).is_some(),
            "read fd must be in table"
        );
        assert!(
            state.fd_table.get(RawFd(ret.rdx as u32)).is_some(),
            "write fd must be in table"
        );
    }

    #[test]
    fn test_pipe_write_read_roundtrip() {
        let mut state = KernelState::new_for_test();
        let create_ret = state.handle_pipe_create();
        let read_fd = create_ret.rax as u32;
        let write_fd = create_ret.rdx as u32;

        let write_ret = state.handle_fd_write(write_fd, b"hello pipe");
        assert_eq!(write_ret.rax, 10);
        assert_eq!(write_ret.rdx, 0);

        let (read_ret, data) = state.handle_fd_read(read_fd, 64);
        assert_eq!(read_ret.rdx, 0);
        assert_eq!(data, b"hello pipe");
    }

    #[test]
    fn test_fd_close_pipe_end() {
        let mut state = KernelState::new_for_test();
        let create_ret = state.handle_pipe_create();
        let read_fd = create_ret.rax as u32;
        let write_fd = create_ret.rdx as u32;

        // Close the read end; the pipe ring should mark read end closed.
        let close_ret = state.handle_fd_close(read_fd);
        assert_eq!(close_ret.rax, 0);
        assert_eq!(close_ret.rdx, 0);
        // fd should be gone.
        assert!(state.fd_table.get(RawFd(read_fd)).is_none());

        // Writing to the write end should now fail with EPIPE.
        let write_ret = state.handle_fd_write(write_fd, b"x");
        assert_eq!(write_ret.rdx, syscall_errno::EPIPE);
    }

    #[test]
    fn test_fd_close_invalid_returns_ebadf() {
        let mut state = KernelState::new_for_test();
        let ret = state.handle_fd_close(99);
        assert_eq!(ret.rdx, syscall_errno::EBADF);
    }

    // -----------------------------------------------------------------------
    // Dup tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_fd_dup_preserves_kind() {
        let mut state = KernelState::new_for_test();
        // dup stdout (fd 1).
        let ret = state.handle_fd_dup(1);
        assert_eq!(ret.rdx, 0);
        let new_fd = ret.rax as u32;
        assert!(new_fd >= 3);
        let desc = state.fd_table.get(RawFd(new_fd)).unwrap();
        if let FdKind::Console { readable, writable } = desc.kind {
            assert!(!readable);
            assert!(writable);
        } else {
            panic!("expected Console kind on dup of stdout");
        }
    }

    #[test]
    fn test_fd_dup2_redirects() {
        let mut state = KernelState::new_for_test();
        // Redirect stderr (fd 2) to point at stdin (fd 0).
        let ret = state.handle_fd_dup2(0, 2);
        assert_eq!(ret.rax, 2);
        assert_eq!(ret.rdx, 0);
        let desc = state.fd_table.get(RawFd(2)).unwrap();
        if let FdKind::Console { readable, writable } = desc.kind {
            assert!(readable, "fd 2 should now be readable (stdin)");
            assert!(!writable);
        } else {
            panic!("expected Console after dup2");
        }
    }

    // -----------------------------------------------------------------------
    // Seek tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_fd_seek_set_cur_end() {
        let mut state = KernelState::new_for_test();
        let fd_ret = state.handle_fs_open("/s.txt", OpenFlags::O_RDWR | OpenFlags::O_CREAT);
        assert_eq!(fd_ret.rdx, 0);
        let fd = fd_ret.rax as u32;

        state.handle_fd_write(fd, b"abcde");

        // SEEK_SET to 2.
        let r = state.handle_fd_seek(fd, 2, 0);
        assert_eq!(r.rax, 2);
        assert_eq!(r.rdx, 0);

        // SEEK_CUR +1 = 3.
        let r2 = state.handle_fd_seek(fd, 1, 1);
        assert_eq!(r2.rax, 3);

        // SEEK_END +0 = 5 (file size).
        let r3 = state.handle_fd_seek(fd, 0, 2);
        assert_eq!(r3.rax, 5);

        // SEEK_END -2 = 3.
        let r4 = state.handle_fd_seek(fd, -2, 2);
        assert_eq!(r4.rax, 3);
    }

    #[test]
    fn test_fd_seek_pipe_returns_espipe() {
        let mut state = KernelState::new_for_test();
        let create_ret = state.handle_pipe_create();
        let read_fd = create_ret.rax as u32;
        let ret = state.handle_fd_seek(read_fd, 0, 0);
        assert_eq!(ret.rdx, syscall_errno::ESPIPE);
    }

    // -----------------------------------------------------------------------
    // Filesystem open/write/read tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_fs_open_create_write_read() {
        let mut state = KernelState::new_for_test();

        let open_ret = state.handle_fs_open("/hello.txt", OpenFlags::O_RDWR | OpenFlags::O_CREAT);
        assert_eq!(open_ret.rdx, 0);
        let fd = open_ret.rax as u32;

        let write_ret = state.handle_fd_write(fd, b"hello");
        assert_eq!(write_ret.rax, 5);

        // Seek back to beginning.
        state.handle_fd_seek(fd, 0, 0);

        let (read_ret, data) = state.handle_fd_read(fd, 64);
        assert_eq!(read_ret.rdx, 0);
        assert_eq!(data, b"hello");
    }

    #[test]
    fn test_fs_stat_existing_file() {
        let mut state = KernelState::new_for_test();
        state.handle_fs_create("/stat_me.txt");
        let (ret, info) = state.handle_fs_stat("/stat_me.txt");
        assert_eq!(ret.rdx, 0);
        let (_, size, ftype) = info.unwrap();
        assert_eq!(size, 0);
        assert_eq!(ftype, 0); // regular file
    }

    #[test]
    fn test_fs_stat_nonexistent_returns_enoent() {
        let state = KernelState::new_for_test();
        let (ret, info) = state.handle_fs_stat("/does_not_exist.txt");
        assert_eq!(ret.rdx, syscall_errno::ENOENT);
        assert!(info.is_none());
    }

    #[test]
    fn test_fs_list_dir_root() {
        let mut state = KernelState::new_for_test();
        state.handle_fs_create("/a.txt");
        state.handle_fs_create("/b.txt");
        let (ret, names) = state.handle_fs_list_dir("/");
        assert_eq!(ret.rdx, 0);
        assert!(names.contains(&"a.txt".to_string()));
        assert!(names.contains(&"b.txt".to_string()));
    }

    #[test]
    fn test_fs_create_and_delete() {
        let mut state = KernelState::new_for_test();
        let create_ret = state.handle_fs_create("/tmp.txt");
        assert_eq!(create_ret.rax, 0);
        assert_eq!(create_ret.rdx, 0);
        assert!(state.vfs.exists("/tmp.txt"));

        let delete_ret = state.handle_fs_delete("/tmp.txt");
        assert_eq!(delete_ret.rax, 0);
        assert_eq!(delete_ret.rdx, 0);
        assert!(!state.vfs.exists("/tmp.txt"));
    }

    #[test]
    fn test_fs_mkdir_and_list() {
        let mut state = KernelState::new_for_test();
        let mkdir_ret = state.handle_fs_mkdir("/mydir");
        assert_eq!(mkdir_ret.rax, 0);
        assert_eq!(mkdir_ret.rdx, 0);
        assert!(state.vfs.exists("/mydir"));

        state.handle_fs_create("/mydir/file.txt");
        let (list_ret, names) = state.handle_fs_list_dir("/mydir");
        assert_eq!(list_ret.rdx, 0);
        assert!(names.contains(&"file.txt".to_string()));
    }

    // -----------------------------------------------------------------------
    // CWD tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_get_set_cwd() {
        let mut state = KernelState::new_for_test();
        let (get_ret, cwd) = state.handle_get_cwd();
        assert_eq!(get_ret.rdx, 0);
        assert_eq!(cwd, "/");

        state.handle_fs_mkdir("/workspace");
        let set_ret = state.handle_set_cwd("/workspace");
        assert_eq!(set_ret.rax, 0);
        assert_eq!(set_ret.rdx, 0);

        let (get_ret2, new_cwd) = state.handle_get_cwd();
        assert_eq!(get_ret2.rdx, 0);
        assert_eq!(new_cwd, "/workspace");
    }

    #[test]
    fn test_set_cwd_nonexistent_returns_enoent() {
        let mut state = KernelState::new_for_test();
        let ret = state.handle_set_cwd("/nonexistent");
        assert_eq!(ret.rdx, syscall_errno::ENOENT);
    }

    // -----------------------------------------------------------------------
    // Process wait tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_process_wait_reaps_child() {
        let mut state = KernelState::new_for_test();
        state
            .process_table
            .register(TaskId(2), Some(TaskId(1)), "child".into());
        state.process_table.record_exit(TaskId(2), 42);

        let ret = state.handle_process_wait(0, 0);
        assert_eq!(ret.rax, 42, "exit code must be in rax");
        assert_eq!(ret.rdx, 2, "child pid must be in rdx");
    }

    #[test]
    fn test_process_wait_wnohang() {
        let mut state = KernelState::new_for_test();
        // Register a child that has NOT exited.
        state
            .process_table
            .register(TaskId(2), Some(TaskId(1)), "running_child".into());

        // WNOHANG = flags bit 0.
        let ret = state.handle_process_wait(0, 1);
        assert_eq!(ret.rax, 0);
        assert_eq!(ret.rdx, 0);
    }

    #[test]
    fn test_process_list_returns_entries() {
        let state = KernelState::new_for_test();
        let (ret, procs) = state.handle_process_list();
        assert_eq!(ret.rdx, 0);
        assert!(!procs.is_empty());
        let (pid, name, exited) = &procs[0];
        assert_eq!(*pid, 1);
        assert_eq!(name, "test");
        assert!(!exited);
    }

    #[test]
    fn test_process_kill_sets_exit_code() {
        let mut state = KernelState::new_for_test();
        state
            .process_table
            .register(TaskId(5), None, "victim".into());
        let ret = state.handle_process_kill(5);
        assert_eq!(ret.rax, 0);
        assert_eq!(ret.rdx, 0);
        // The exit code 137 must be recorded.
        let entry = state.process_table.get(TaskId(5)).unwrap();
        assert_eq!(entry.exit_code, Some(137));
    }

    // -----------------------------------------------------------------------
    // Console read tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_read_console_returns_buffered_data() {
        let mut state = KernelState::new_for_test();
        for &b in b"hello\n" {
            state.console_input.push_byte(b);
        }
        let ret = state.handle_read_console(64);
        assert_eq!(ret.rax, 6); // "hello\n"
        assert_eq!(ret.rdx, 0);
    }

    #[test]
    fn test_fd_read_from_console() {
        let mut state = KernelState::new_for_test();
        state.console_input.push_byte(b'X');
        state.console_input.push_byte(b'\n');
        // fd 0 is stdin (readable console).
        let (ret, data) = state.handle_fd_read(0, 64);
        assert_eq!(ret.rdx, 0);
        assert_eq!(data, b"X\n");
    }

    #[test]
    fn test_fd_write_to_pipe_and_read() {
        let mut state = KernelState::new_for_test();
        let cr = state.handle_pipe_create();
        let rfd = cr.rax as u32;
        let wfd = cr.rdx as u32;

        let wr = state.handle_fd_write(wfd, b"kernel pipe test");
        assert_eq!(wr.rax, 16);

        let (rr, data) = state.handle_fd_read(rfd, 128);
        assert_eq!(rr.rdx, 0);
        assert_eq!(data, b"kernel pipe test");
    }

    #[test]
    fn test_huge_read_len_is_capped_no_oom() {
        // NCIP-026 R4 (WI-4b review #31): without the MAX_READ_LEN cap the pipe
        // path would attempt `vec![0u8; usize::MAX]` and abort. A near-u64::MAX
        // request must be bounded yet still return the few bytes present.
        let mut state = KernelState::new_for_test();
        let cr = state.handle_pipe_create();
        let rfd = cr.rax as u32;
        let wfd = cr.rdx as u32;
        assert_eq!(state.handle_fd_write(wfd, b"abc").rax, 3);

        let (rr, data) = state.handle_fd_read(rfd, u64::MAX);
        assert_eq!(rr.rdx, 0);
        assert_eq!(data, b"abc");

        // Console path likewise survives an enormous request.
        for &b in b"hi\n" {
            state.console_input.push_byte(b);
        }
        let ret = state.handle_read_console(u64::MAX);
        assert_eq!(ret.rax, 3); // "hi\n"
    }

    // -----------------------------------------------------------------------
    // Append / trunc mode tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_fs_open_append_mode() {
        let mut state = KernelState::new_for_test();

        // Create the file and write initial content.
        let fd_ret = state.handle_fs_open("/append.txt", OpenFlags::O_WRONLY | OpenFlags::O_CREAT);
        let fd = fd_ret.rax as u32;
        state.handle_fd_write(fd, b"first");
        state.handle_fd_close(fd);

        // Open in append mode.
        let afd_ret =
            state.handle_fs_open("/append.txt", OpenFlags::O_WRONLY | OpenFlags::O_APPEND);
        let afd = afd_ret.rax as u32;
        state.handle_fd_write(afd, b"second");
        state.handle_fd_close(afd);

        // Open for reading and verify concatenated content.
        let rfd_ret = state.handle_fs_open("/append.txt", OpenFlags::O_RDONLY);
        let rfd = rfd_ret.rax as u32;
        let (_, data) = state.handle_fd_read(rfd, 64);
        assert_eq!(data, b"firstsecond");
    }

    #[test]
    fn test_fs_open_trunc_mode() {
        let mut state = KernelState::new_for_test();

        // Create file with content.
        let fd_ret = state.handle_fs_open("/trunc.txt", OpenFlags::O_WRONLY | OpenFlags::O_CREAT);
        let fd = fd_ret.rax as u32;
        state.handle_fd_write(fd, b"original content");
        state.handle_fd_close(fd);

        // Verify non-empty.
        let (_, info_before) = state.handle_fs_stat("/trunc.txt");
        assert!(info_before.unwrap().1 > 0);

        // Open with O_TRUNC.
        let tfd_ret = state.handle_fs_open("/trunc.txt", OpenFlags::O_WRONLY | OpenFlags::O_TRUNC);
        assert_eq!(tfd_ret.rdx, 0);
        state.handle_fd_close(tfd_ret.rax as u32);

        // File must now be empty.
        let (_, info_after) = state.handle_fs_stat("/trunc.txt");
        assert_eq!(info_after.unwrap().1, 0);
    }
}
