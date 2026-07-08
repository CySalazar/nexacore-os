//! NexaCore OS userspace syscall wrapper library.
//!
//! `nexacore-usys` is the userspace complement of the kernel's syscall ABI defined
//! in `crates/nexacore-kernel/src/syscall.rs`.  It provides:
//!
//! - [`Errno`] — typed error codes matching the kernel's `syscall_errno` module.
//! - [`SysResult`] — a `Result` alias used by all wrapper functions.
//! - [`FileStat`] — file metadata returned by the [`Syscall::stat`] method.
//! - [`flags`] — open/seek/wait flag constants mirroring POSIX values.
//! - [`Syscall`] — a trait abstracting the syscall mechanism; implement it with
//!   `KernelSyscall` in real kernel builds or with a mock in tests.
//! - `KernelSyscall` — the real backend, available when the `bare-metal`
//!   feature is enabled; issues `syscall` instructions via inline `asm!`.
//!
//! # Feature flags
//!
//! | Feature | Effect |
//! |---------|--------|
//! | `bare-metal` | Enables `no_std + alloc` and compiles `KernelSyscall` using `asm!`. |
//!
//! Without the `bare-metal` feature the crate targets `std` and compiles on
//! any developer host, making unit testing possible without a QEMU kernel.
//!
//! # ABI summary
//!
//! NexaCore OS uses the System V AMD64 calling convention for syscalls:
//! - `rax` — syscall number
//! - `rdi`, `rsi`, `rdx`, `r10`, `r8`, `r9` — arguments a0..a5
//! - Return: `rax` = primary result, `rdx` = errno (two-register path)
//!
//! # Example (std, mock-based)
//!
//! ```rust
//! use nexacore_usys::{Errno, SysResult};
//!
//! fn check_ok(r: SysResult<usize>) -> usize {
//!     r.unwrap_or(0)
//! }
//!
//! assert_eq!(check_ok(Ok(42)), 42);
//! assert_eq!(check_ok(Err(Errno::BadFd)), 0);
//! ```

// When the `bare-metal` feature is active we compile for `x86_64-unknown-none`
// which has no std.  The `extern crate alloc` import makes `String`/`Vec`
// available through the kernel's allocator.
#![cfg_attr(feature = "bare-metal", no_std)]
#![deny(missing_docs)]
// The `unsafe_code` workspace lint is set to warn; every unsafe block below
// carries an explicit `// SAFETY:` justification.

#[cfg(feature = "bare-metal")]
extern crate alloc;

// Pull the right `String` / `Vec` into scope depending on whether we have std.
#[cfg(feature = "bare-metal")]
use alloc::{string::String, vec::Vec};
#[cfg(not(feature = "bare-metal"))]
use std::{string::String, vec::Vec};

// ---------------------------------------------------------------------------
// Modules
// ---------------------------------------------------------------------------

/// Socket API wrappers for the NexaCore OS userspace network ABI (N4.1).
///
/// Provides encoding helpers, request builder functions, and the
/// [`crate::net::syscall_nr`] constants that map to kernel syscalls 103–113.
pub mod net;

/// AI syscall wrappers (numbers 80–84) — TASK-11 (DE-G6, ADR-0032).
///
/// Thin wrappers over the kernel→nexacore-runtime AI relay
/// (`AiInvoke`/`AiEmbed` buffer ABI) plus the [`crate::ai::syscall_nr`]
/// constants and the host-testable [`crate::ai::AiInvokeArgs`]
/// argument-shape validation.
pub mod ai;

/// Display syscall wrappers — `DisplayMap (79)` + input-event IPC receiver
/// (TASK-18, DE-C1, ADR-0040 D5).
///
/// Provides `display_map` over syscall 79 and
/// `recv_input_event` over `IpcTryReceive (24)`.
/// The `bare-metal` feature gates the `asm!`-backed implementations;
/// the [`crate::display::syscall_nr`] constants and
/// [`crate::display::ACTION_TAG_DISPLAY_MAP`] are always available.
pub mod display;

// ---------------------------------------------------------------------------
// Errno
// ---------------------------------------------------------------------------

/// Typed error codes for NexaCore OS syscalls.
///
/// Numeric values are deliberately aligned with POSIX / Linux `errno-base.h`
/// to match the kernel's `syscall_errno` constants (see
/// `crates/nexacore-kernel/src/syscall.rs`).  This makes cross-referencing kernel
/// and userspace error paths trivial.
///
/// # Example
///
/// ```rust
/// use nexacore_usys::Errno;
///
/// let e = Errno::from_raw(22);
/// assert_eq!(e, Errno::Invalid);
/// assert_eq!(e.to_string(), "invalid argument");
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u64)]
#[non_exhaustive]
pub enum Errno {
    /// Success (no error). `POSIX: 0`.
    Success = 0,
    /// No such file or directory. `POSIX: ENOENT = 2`.
    NoEntry = 2,
    /// No such process. `POSIX: ESRCH = 3`.
    NoProcess = 3,
    /// System call interrupted. `POSIX: EINTR = 4`.
    Interrupted = 4,
    /// I/O error. `POSIX: EIO = 5`.
    Io = 5,
    /// Bad file descriptor. `POSIX: EBADF = 9`.
    BadFd = 9,
    /// No child processes. `POSIX: ECHILD = 10`.
    NoChild = 10,
    /// Resource temporarily unavailable. `POSIX: EAGAIN = 11`.
    Again = 11,
    /// Permission denied. `POSIX: EACCES = 13`.
    Access = 13,
    /// Bad address (pointer out of range or unmapped). `POSIX: EFAULT = 14`.
    Fault = 14,
    /// File already exists. `POSIX: EEXIST = 17`.
    Exists = 17,
    /// Not a directory. `POSIX: ENOTDIR = 20`.
    NotDir = 20,
    /// Is a directory. `POSIX: EISDIR = 21`.
    IsDir = 21,
    /// Invalid argument. `POSIX: EINVAL = 22`.
    Invalid = 22,
    /// No space left on device. `POSIX: ENOSPC = 28`.
    NoSpace = 28,
    /// Broken pipe. `POSIX: EPIPE = 32`.
    BrokenPipe = 32,
    /// Function not implemented. `POSIX: ENOSYS = 38`.
    NotImpl = 38,
    /// Unknown or unmapped error (catch-all).
    Unknown = 255,
}

impl Errno {
    /// Convert a raw `u64` errno value into an [`Errno`] variant.
    ///
    /// Values that do not match any known POSIX code are mapped to
    /// [`Errno::Unknown`].
    ///
    /// # Example
    ///
    /// ```rust
    /// use nexacore_usys::Errno;
    ///
    /// assert_eq!(Errno::from_raw(0), Errno::Success);
    /// assert_eq!(Errno::from_raw(2), Errno::NoEntry);
    /// assert_eq!(Errno::from_raw(22), Errno::Invalid);
    /// // Any unrecognised code maps to Unknown.
    /// assert_eq!(Errno::from_raw(99), Errno::Unknown);
    /// ```
    #[must_use]
    pub fn from_raw(raw: u64) -> Self {
        match raw {
            0 => Self::Success,
            2 => Self::NoEntry,
            3 => Self::NoProcess,
            4 => Self::Interrupted,
            5 => Self::Io,
            9 => Self::BadFd,
            10 => Self::NoChild,
            11 => Self::Again,
            13 => Self::Access,
            14 => Self::Fault,
            17 => Self::Exists,
            20 => Self::NotDir,
            21 => Self::IsDir,
            22 => Self::Invalid,
            28 => Self::NoSpace,
            32 => Self::BrokenPipe,
            38 => Self::NotImpl,
            _ => Self::Unknown,
        }
    }

    /// Return the raw `u64` numeric code for this errno variant.
    ///
    /// # Example
    ///
    /// ```rust
    /// use nexacore_usys::Errno;
    ///
    /// assert_eq!(Errno::Invalid.as_raw(), 22);
    /// assert_eq!(Errno::Success.as_raw(), 0);
    /// ```
    #[must_use]
    pub const fn as_raw(self) -> u64 {
        self as u64
    }

    /// Return `true` if this errno indicates success (`Errno::Success`).
    ///
    /// # Example
    ///
    /// ```rust
    /// use nexacore_usys::Errno;
    ///
    /// assert!(Errno::Success.is_success());
    /// assert!(!Errno::Io.is_success());
    /// ```
    #[must_use]
    pub const fn is_success(self) -> bool {
        matches!(self, Self::Success)
    }
}

impl core::fmt::Display for Errno {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let msg = match self {
            Self::Success => "success",
            Self::NoEntry => "no such file or directory",
            Self::NoProcess => "no such process",
            Self::Interrupted => "interrupted system call",
            Self::Io => "I/O error",
            Self::BadFd => "bad file descriptor",
            Self::NoChild => "no child processes",
            Self::Again => "resource temporarily unavailable",
            Self::Access => "permission denied",
            Self::Fault => "bad address",
            Self::Exists => "file exists",
            Self::NotDir => "not a directory",
            Self::IsDir => "is a directory",
            Self::Invalid => "invalid argument",
            Self::NoSpace => "no space left on device",
            Self::BrokenPipe => "broken pipe",
            Self::NotImpl => "function not implemented",
            Self::Unknown => "unknown error",
        };
        f.write_str(msg)
    }
}

// ---------------------------------------------------------------------------
// SysResult
// ---------------------------------------------------------------------------

/// Result type for all syscall operations.
///
/// `Ok(T)` carries the successful return value; `Err(Errno)` carries the
/// typed POSIX-aligned error code.
///
/// # Example
///
/// ```rust
/// use nexacore_usys::{Errno, SysResult};
///
/// fn divide(a: usize, b: usize) -> SysResult<usize> {
///     if b == 0 {
///         Err(Errno::Invalid)
///     } else {
///         Ok(a / b)
///     }
/// }
///
/// assert_eq!(divide(10, 2), Ok(5));
/// assert_eq!(divide(10, 0), Err(Errno::Invalid));
/// ```
pub type SysResult<T> = Result<T, Errno>;

// ---------------------------------------------------------------------------
// FileStat
// ---------------------------------------------------------------------------

/// File metadata returned by [`Syscall::stat`].
///
/// The layout mirrors a reduced `struct stat` sufficient for Phase 1
/// filesystem operations.  More fields (permissions, timestamps, link count)
/// will be added in later milestones via a non-breaking struct extension.
///
/// # Example
///
/// ```rust
/// use nexacore_usys::FileStat;
///
/// let st = FileStat {
///     inode: 1,
///     size: 4096,
///     is_dir: true,
/// };
/// assert!(st.is_dir);
/// assert_eq!(st.size, 4096);
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileStat {
    /// Inode number — unique identifier for the filesystem object.
    pub inode: u64,
    /// Size of the file in bytes. For directories this is the size of the
    /// directory metadata block, not the aggregate size of its contents.
    pub size: u64,
    /// `true` if this entry is a directory; `false` for regular files,
    /// symlinks, or device nodes.
    pub is_dir: bool,
}

// ---------------------------------------------------------------------------
// flags
// ---------------------------------------------------------------------------

/// Open, seek, and wait flag constants.
///
/// All constants intentionally mirror their POSIX / Linux `fcntl.h` values so
/// that the userspace ABI is unsurprising to systems programmers.
///
/// # Example
///
/// ```rust
/// use nexacore_usys::flags;
///
/// // Combine flags with bitwise-OR as in POSIX.
/// let create_write = flags::O_WRONLY | flags::O_CREAT | flags::O_TRUNC;
/// assert_ne!(create_write, 0);
/// ```
pub mod flags {
    /// Open for reading only. Equivalent to POSIX `O_RDONLY`.
    pub const O_RDONLY: u32 = 0;
    /// Open for writing only. Equivalent to POSIX `O_WRONLY`.
    pub const O_WRONLY: u32 = 1;
    /// Open for reading and writing. Equivalent to POSIX `O_RDWR`.
    pub const O_RDWR: u32 = 2;
    /// Create the file if it does not exist. Equivalent to POSIX `O_CREAT` (octal 0100).
    pub const O_CREAT: u32 = 0x40;
    /// Truncate the file to zero length on open. Equivalent to POSIX `O_TRUNC` (octal 01000).
    pub const O_TRUNC: u32 = 0x200;
    /// Append writes to the end of the file. Equivalent to POSIX `O_APPEND` (octal 02000).
    pub const O_APPEND: u32 = 0x400;

    /// Seek relative to the beginning of the file. Equivalent to POSIX `SEEK_SET`.
    pub const SEEK_SET: u32 = 0;
    /// Seek relative to the current file position. Equivalent to POSIX `SEEK_CUR`.
    pub const SEEK_CUR: u32 = 1;
    /// Seek relative to the end of the file. Equivalent to POSIX `SEEK_END`.
    pub const SEEK_END: u32 = 2;

    /// Do not block in [`super::Syscall::waitpid`] if no child has exited.
    /// Equivalent to POSIX `WNOHANG`.
    pub const WNOHANG: u64 = 1;
}

// ---------------------------------------------------------------------------
// Syscall trait
// ---------------------------------------------------------------------------

/// Abstraction over the NexaCore OS kernel syscall interface.
///
/// Implementing this trait allows callers (shell commands, daemons, tests) to
/// be independent of whether a real kernel is present.  The two canonical
/// implementations are:
///
/// - `KernelSyscall` — issues real `syscall` instructions; available only
///   when the `bare-metal` feature is enabled.
/// - A user-supplied mock struct — for unit tests on developer hosts.
///
/// # Error handling
///
/// Every method returns a [`SysResult`].  The kernel's two-register return
/// path (`rax = value`, `rdx = errno`) is collapsed here: if `rdx != 0` the
/// implementation constructs `Err(Errno::from_raw(rdx))`; otherwise it
/// constructs `Ok(rax_derived_value)`.
///
/// # Example — minimal mock
///
/// ```rust
/// use nexacore_usys::{Errno, FileStat, SysResult, Syscall};
///
/// struct AlwaysOk;
///
/// impl Syscall for AlwaysOk {
///     fn write(&self, _fd: u32, buf: &[u8]) -> SysResult<usize> {
///         Ok(buf.len())
///     }
///     fn read(&self, _fd: u32, buf: &mut [u8]) -> SysResult<usize> {
///         Ok(buf.len())
///     }
///     fn close(&self, _fd: u32) -> SysResult<()> {
///         Ok(())
///     }
///     fn open(&self, _path: &str, _flags: u32) -> SysResult<u32> {
///         Ok(3)
///     }
///     fn stat(&self, _path: &str) -> SysResult<FileStat> {
///         Ok(FileStat {
///             inode: 1,
///             size: 0,
///             is_dir: false,
///         })
///     }
///     fn listdir(&self, _path: &str) -> SysResult<Vec<String>> {
///         Ok(vec![])
///     }
///     fn mkdir(&self, _path: &str) -> SysResult<()> {
///         Ok(())
///     }
///     fn delete(&self, _path: &str) -> SysResult<()> {
///         Ok(())
///     }
///     fn create(&self, _path: &str) -> SysResult<()> {
///         Ok(())
///     }
///     fn getcwd(&self) -> SysResult<String> {
///         Ok(String::from("/"))
///     }
///     fn setcwd(&self, _path: &str) -> SysResult<()> {
///         Ok(())
///     }
///     fn exit(&self, _code: u32) -> ! {
///         panic!("exit called in test")
///     }
///     fn spawn(&self, _path: &str, _argv: &[&str], _envp: &[&str]) -> SysResult<u64> {
///         Ok(1)
///     }
///     fn waitpid(&self, _pid: u64, _flags: u64) -> SysResult<(u64, u32)> {
///         Ok((1, 0))
///     }
///     fn pipe(&self) -> SysResult<(u32, u32)> {
///         Ok((3, 4))
///     }
///     fn dup2(&self, _old: u32, new: u32) -> SysResult<u32> {
///         Ok(new)
///     }
///     fn seek(&self, _fd: u32, _offset: i64, _whence: u32) -> SysResult<u64> {
///         Ok(0)
///     }
///     fn time_monotonic_nanos(&self) -> u64 {
///         0
///     }
/// }
///
/// let sc = AlwaysOk;
/// assert_eq!(sc.write(1, b"hello"), Ok(5));
/// assert_eq!(sc.getcwd(), Ok(String::from("/")));
/// ```
pub trait Syscall {
    /// Write `buf` to file descriptor `fd`.
    ///
    /// Returns the number of bytes actually written, or an [`Errno`] on
    /// failure.  Partial writes (returned count < `buf.len()`) are valid;
    /// callers must loop.
    ///
    /// Maps to kernel syscall `FdWrite` (number 64).  For the console fds
    /// 0/1/2 the kernel routes through `WriteConsole` (60) internally.
    ///
    /// # Errors
    ///
    /// Returns [`Errno::BadFd`] if `fd` is not open, [`Errno::Fault`] if
    /// `buf` contains an invalid pointer, or [`Errno::BrokenPipe`] if the
    /// read end of a pipe has been closed.
    fn write(&self, fd: u32, buf: &[u8]) -> SysResult<usize>;

    /// Read up to `buf.len()` bytes from file descriptor `fd` into `buf`.
    ///
    /// Returns the number of bytes read (0 = EOF), or an [`Errno`] on failure.
    ///
    /// Maps to kernel syscall `FdRead` (number 63) / `ReadConsole` (61).
    ///
    /// # Errors
    ///
    /// Returns [`Errno::BadFd`] if `fd` is not open, [`Errno::Fault`] if
    /// `buf` is an invalid pointer, or [`Errno::Again`] if the fd is
    /// non-blocking and no data is available.
    fn read(&self, fd: u32, buf: &mut [u8]) -> SysResult<usize>;

    /// Close file descriptor `fd`.
    ///
    /// After a successful call `fd` must not be used again.
    ///
    /// Maps to kernel syscall `FdClose` (number 65).
    ///
    /// # Errors
    ///
    /// Returns [`Errno::BadFd`] if `fd` is not a valid open file descriptor.
    fn close(&self, fd: u32) -> SysResult<()>;

    /// Open the filesystem object at `path` with the given `flags`.
    ///
    /// `flags` is a bitmask of the constants in [`flags`]:
    /// [`flags::O_RDONLY`], [`flags::O_WRONLY`], [`flags::O_RDWR`],
    /// [`flags::O_CREAT`], etc.
    ///
    /// Returns the new file descriptor on success.
    ///
    /// Maps to kernel syscall `FsOpen` (number 90).
    ///
    /// # Errors
    ///
    /// Returns [`Errno::NoEntry`] if the path does not exist (and
    /// [`flags::O_CREAT`] was not set), [`Errno::Access`] if the caller
    /// lacks permission, or [`Errno::Invalid`] for an unrecognised flag
    /// combination.
    fn open(&self, path: &str, flags: u32) -> SysResult<u32>;

    /// Retrieve metadata for the filesystem object at `path`.
    ///
    /// Maps to kernel syscall `FsStat` (number 91).
    ///
    /// # Errors
    ///
    /// Returns [`Errno::NoEntry`] if the path does not exist, or
    /// [`Errno::Access`] if the caller lacks permission to stat it.
    fn stat(&self, path: &str) -> SysResult<FileStat>;

    /// Return a list of entry names (not full paths) inside the directory
    /// at `path`.
    ///
    /// Maps to kernel syscall `FsListDir` (number 92).
    ///
    /// # Errors
    ///
    /// Returns [`Errno::NoEntry`] if the path does not exist,
    /// [`Errno::NotDir`] if the path is not a directory, or
    /// [`Errno::Access`] if the caller lacks read permission.
    fn listdir(&self, path: &str) -> SysResult<Vec<String>>;

    /// Create a new directory at `path`.
    ///
    /// Maps to kernel syscall `FsMkdir` (number 95).
    ///
    /// # Errors
    ///
    /// Returns [`Errno::Exists`] if the path already exists,
    /// [`Errno::NoEntry`] if a parent component is missing, or
    /// [`Errno::Access`] if the caller lacks write permission.
    fn mkdir(&self, path: &str) -> SysResult<()>;

    /// Delete the file or directory at `path`.
    ///
    /// Maps to kernel syscall `FsDelete` (number 94).
    ///
    /// # Errors
    ///
    /// Returns [`Errno::NoEntry`] if the path does not exist,
    /// [`Errno::Access`] if the caller lacks write permission, or
    /// [`Errno::IsDir`] if `path` names a non-empty directory.
    fn delete(&self, path: &str) -> SysResult<()>;

    /// Create a new (empty) regular file at `path`.
    ///
    /// Maps to kernel syscall `FsCreate` (number 93).
    ///
    /// # Errors
    ///
    /// Returns [`Errno::Exists`] if the path already exists,
    /// [`Errno::NoEntry`] if a parent component is missing, or
    /// [`Errno::Access`] if the caller lacks write permission.
    fn create(&self, path: &str) -> SysResult<()>;

    /// Return the current working directory as an absolute path string.
    ///
    /// Maps to kernel syscall `GetCwd` (number 16).
    ///
    /// # Errors
    ///
    /// Returns [`Errno::Io`] if the kernel cannot encode the path as UTF-8,
    /// or [`Errno::Fault`] if the kernel-provided buffer length is invalid.
    fn getcwd(&self) -> SysResult<String>;

    /// Change the current working directory to `path`.
    ///
    /// Maps to kernel syscall `SetCwd` (number 17).
    ///
    /// # Errors
    ///
    /// Returns [`Errno::NoEntry`] if the path does not exist,
    /// [`Errno::NotDir`] if a component of the path is not a directory, or
    /// [`Errno::Access`] if the caller lacks permission.
    fn setcwd(&self, path: &str) -> SysResult<()>;

    /// Terminate the calling process with exit `code`.
    ///
    /// This method never returns.
    ///
    /// Maps to kernel syscall `TaskExit` (number 11).
    fn exit(&self, code: u32) -> !;

    /// Spawn a new child process.
    ///
    /// - `path`  — path to the executable image.
    /// - `argv`  — argument vector (`argv[0]` is conventionally the program name).
    /// - `envp`  — environment variables in `KEY=VALUE` form.
    ///
    /// Returns the PID of the new child process.
    ///
    /// Maps to kernel syscall `ProcessSpawn` (number 14).
    ///
    /// # Errors
    ///
    /// Returns [`Errno::NoEntry`] if the executable is not found,
    /// [`Errno::Access`] if the caller lacks execute permission, or
    /// [`Errno::NoSpace`] if the process table is full.
    fn spawn(&self, path: &str, argv: &[&str], envp: &[&str]) -> SysResult<u64>;

    /// Wait for a child process to change state.
    ///
    /// - `pid`   — the PID to wait for; `u64::MAX` waits for any child.
    /// - `flags` — bitmask of [`flags::WNOHANG`] or `0` for blocking wait.
    ///
    /// Returns `(pid, exit_status)` where `exit_status` is the raw kernel
    /// exit code.
    ///
    /// Maps to kernel syscall `ProcessWait` (number 15).
    ///
    /// # Errors
    ///
    /// Returns [`Errno::NoChild`] if there are no child processes to wait
    /// for, or [`Errno::NoProcess`] if `pid` does not name a child of the
    /// calling process.
    fn waitpid(&self, pid: u64, flags: u64) -> SysResult<(u64, u32)>;

    /// Create an anonymous pipe.
    ///
    /// Returns `(read_fd, write_fd)`.  Data written to `write_fd` can be
    /// read from `read_fd`.
    ///
    /// Maps to kernel syscall `PipeCreate` (number 62).
    ///
    /// # Errors
    ///
    /// Returns [`Errno::NoSpace`] if the file descriptor table is full, or
    /// [`Errno::Fault`] if the kernel-provided output pointers are invalid.
    fn pipe(&self) -> SysResult<(u32, u32)>;

    /// Duplicate file descriptor `old` to file descriptor `new`.
    ///
    /// If `new` is already open it is silently closed first.  Equivalent to
    /// `dup2(2)` in POSIX.  Returns `new` on success.
    ///
    /// Maps to kernel syscall `FdDup2` (number 67).
    ///
    /// # Errors
    ///
    /// Returns [`Errno::BadFd`] if `old` is not a valid open file descriptor.
    fn dup2(&self, old: u32, new: u32) -> SysResult<u32>;

    /// Reposition the file offset of `fd`.
    ///
    /// - `offset` — signed byte offset; interpretation depends on `whence`.
    /// - `whence` — one of [`flags::SEEK_SET`], [`flags::SEEK_CUR`],
    ///   [`flags::SEEK_END`].
    ///
    /// Returns the resulting absolute file position from the beginning of the
    /// file.
    ///
    /// Maps to kernel syscall `FdSeek` (number 68).
    ///
    /// # Errors
    ///
    /// Returns [`Errno::BadFd`] if `fd` is not seekable or not open,
    /// [`Errno::Invalid`] if `whence` is not a recognised constant, or
    /// [`Errno::Invalid`] if the resulting offset would be negative.
    fn seek(&self, fd: u32, offset: i64, whence: u32) -> SysResult<u64>;

    /// Return the monotonic time in nanoseconds since boot.
    ///
    /// This call is infallible: the kernel always has a monotonic clock source
    /// after boot; the worst case is it returns 0.
    ///
    /// Maps to kernel syscall `TimeMonotonicNanos` (number 50).
    fn time_monotonic_nanos(&self) -> u64;
}

// ---------------------------------------------------------------------------
// KernelSyscall — real backend (bare-metal only)
// ---------------------------------------------------------------------------

/// Real syscall backend for the `x86_64-unknown-none` NexaCore OS target.
///
/// Issues native `syscall` instructions using inline `asm!` following the
/// System V AMD64 ABI:
/// - `rax` = syscall number
/// - `rdi`, `rsi`, `rdx`, `r10`, `r8`, `r9` = arguments a0..a5
/// - Return: `rax` = primary result, `rdx` = errno (two-register path)
///
/// This struct is only compiled when the `bare-metal` feature is enabled.
/// On developer-host builds without the feature, use a mock instead.
#[cfg(feature = "bare-metal")]
pub struct KernelSyscall;

// justification: rax/rdx are x86-64 register names used verbatim throughout
// the SysV AMD64 syscall ABI; renaming them (e.g. to reg_a/reg_d) would make
// the code harder to verify against the ABI specification and processor manual.
// unsafe_code: every unsafe block in this impl has a SAFETY comment that
// proves the invariants required by the NexaCore OS kernel ABI.
#[cfg(feature = "bare-metal")]
#[allow(clippy::similar_names, unsafe_code)]
impl KernelSyscall {
    /// Issue a one-register-return syscall.
    ///
    /// Returns the value in `rax` after the `syscall` instruction.
    ///
    /// # Safety
    ///
    /// The caller must ensure:
    /// 1. `number` is a valid NexaCore OS syscall number recognised by the kernel.
    /// 2. All pointer arguments (`a0`..`a2` that represent pointers) are
    ///    valid, non-null, and the caller holds read/write access for the
    ///    duration of the syscall.
    /// 3. Non-pointer arguments satisfy the range constraints documented for
    ///    each syscall variant in `crates/nexacore-kernel/src/syscall.rs`.
    ///
    /// Violating these invariants is undefined behaviour from the kernel's
    /// perspective and may cause EFAULT or EINVAL termination.
    // justification: `&self` is not used here; the method lives on KernelSyscall
    // for logical grouping — it is the building-block called by every Syscall
    // trait method that needs the real `syscall` instruction.
    #[allow(clippy::unused_self)]
    unsafe fn raw_syscall(&self, number: u64, a0: u64, a1: u64, a2: u64) -> u64 {
        // SAFETY: Caller has verified the syscall number and arguments satisfy
        // the NexaCore OS kernel ABI (SysV AMD64: rax=number, rdi=a0, rsi=a1,
        // rdx=a2).  The `syscall` instruction transitions to Ring 0 and back;
        // no memory outside the described buffers is touched by the kernel.
        // Rust 2024: unsafe operations inside `unsafe fn` still require an
        // explicit `unsafe {}` block; `asm!` is an unsafe operation.
        let result: u64;
        unsafe {
            core::arch::asm!(
                "syscall",
                inlateout("rax") number => result,
                in("rdi") a0,
                in("rsi") a1,
                in("rdx") a2,
                // rcx and r11 are clobbered by the syscall instruction per the
                // SysV AMD64 ABI.
                out("rcx") _,
                out("r11") _,
                options(nostack),
            );
        }
        result
    }

    /// Issue a two-register-return syscall (`rax` = value, `rdx` = errno).
    ///
    /// Returns `(rax, rdx)`.
    ///
    /// # Safety
    ///
    /// Same contract as [`Self::raw_syscall`]; additionally, the kernel ABI
    /// for the specific syscall number must use the two-register return
    /// convention documented in `crates/nexacore-kernel/src/syscall.rs`.
    // justification: `&self` is unused — see raw_syscall rationale.
    // justification: 8 arguments are unavoidable; the SysV AMD64 ABI maps
    // syscall number + 6 argument registers (rdi, rsi, rdx, r10, r8, r9)
    // directly onto function parameters to keep the call-site readable.
    #[allow(clippy::unused_self, clippy::too_many_arguments)]
    unsafe fn raw_syscall2(
        &self,
        number: u64,
        a0: u64,
        a1: u64,
        a2: u64,
        a3: u64,
        a4: u64,
        a5: u64,
    ) -> (u64, u64) {
        // SAFETY: See `raw_syscall` — same ABI contract applies. Additional
        // registers r10, r8, r9 carry a3..a5 per the extended SysV AMD64
        // convention documented in `crates/nexacore-kernel/src/syscall.rs`.
        // Rust 2024: explicit `unsafe {}` required even inside `unsafe fn`.
        let rax: u64;
        let rdx: u64;
        unsafe {
            core::arch::asm!(
                "syscall",
                inlateout("rax") number => rax,
                in("rdi") a0,
                in("rsi") a1,
                inlateout("rdx") a2 => rdx,
                in("r10") a3,
                in("r8")  a4,
                in("r9")  a5,
                out("rcx") _,
                out("r11") _,
                options(nostack),
            );
        }
        (rax, rdx)
    }

    /// Decode a two-register return into a [`SysResult`].
    ///
    /// Mirrors the kernel contract: `rdx == 0` means success (apply `map` to
    /// `rax`); otherwise `rdx` holds the errno code.
    fn decode2<T>(rax: u64, rdx: u64, map: impl FnOnce(u64) -> T) -> SysResult<T> {
        if rdx == 0 {
            Ok(map(rax))
        } else {
            Err(Errno::from_raw(rdx))
        }
    }
}

// justification: rax/rdx are x86-64 register names used verbatim throughout
// the SysV AMD64 syscall ABI; renaming them would impair ABI verification.
// unsafe_code: every unsafe block in this impl wraps a call to raw_syscall /
// raw_syscall2, each of which documents its SAFETY contract above.
#[cfg(feature = "bare-metal")]
#[allow(clippy::similar_names, unsafe_code)]
impl Syscall for KernelSyscall {
    fn write(&self, fd: u32, buf: &[u8]) -> SysResult<usize> {
        // SAFETY: buf is a valid Rust slice; ptr and len are correct by construction.
        let (rax, rdx) = unsafe {
            self.raw_syscall2(
                64, // FdWrite
                u64::from(fd),
                buf.as_ptr() as u64,
                buf.len() as u64,
                0,
                0,
                0,
            )
        };
        // justification: this crate targets x86_64-unknown-none where usize ==
        // u64; truncation is structurally impossible on the supported target.
        #[allow(clippy::cast_possible_truncation)]
        Self::decode2(rax, rdx, |n| n as usize)
    }

    fn read(&self, fd: u32, buf: &mut [u8]) -> SysResult<usize> {
        // SAFETY: buf is a valid mutable slice; ptr and len correct by construction.
        let (rax, rdx) = unsafe {
            self.raw_syscall2(
                63, // FdRead
                u64::from(fd),
                buf.as_mut_ptr() as u64,
                buf.len() as u64,
                0,
                0,
                0,
            )
        };
        // justification: x86_64-unknown-none target; usize == u64, no truncation.
        #[allow(clippy::cast_possible_truncation)]
        Self::decode2(rax, rdx, |n| n as usize)
    }

    fn close(&self, fd: u32) -> SysResult<()> {
        // SAFETY: fd is a u32 scalar; no pointer arguments.
        let (rax, rdx) = unsafe { self.raw_syscall2(65, u64::from(fd), 0, 0, 0, 0, 0) };
        Self::decode2(rax, rdx, |_| ())
    }

    fn open(&self, path: &str, flags: u32) -> SysResult<u32> {
        let bytes = path.as_bytes();
        // SAFETY: path bytes pointer is valid for the duration of the syscall;
        // flags is a scalar.
        let (rax, rdx) = unsafe {
            self.raw_syscall2(
                90, // FsOpen
                bytes.as_ptr() as u64,
                bytes.len() as u64,
                u64::from(flags),
                0,
                0,
                0,
            )
        };
        // justification: the kernel guarantees that FsOpen returns a 32-bit fd
        // value; the upper 32 bits of rax are always zero on success.
        #[allow(clippy::cast_possible_truncation)]
        Self::decode2(rax, rdx, |n| n as u32)
    }

    fn stat(&self, path: &str) -> SysResult<FileStat> {
        // The kernel writes a packed struct: [u64 inode, u64 size, u64 is_dir].
        // We allocate on the stack and pass a pointer.  Three u64 avoids
        // alignment surprises across the ABI boundary.
        let mut buf = [0u64; 3];
        let bytes = path.as_bytes();
        // SAFETY: buf is stack-allocated and valid; bytes pointer is valid.
        let (rax, rdx) = unsafe {
            self.raw_syscall2(
                91, // FsStat
                bytes.as_ptr() as u64,
                bytes.len() as u64,
                buf.as_mut_ptr() as u64,
                0,
                0,
                0,
            )
        };
        Self::decode2(rax, rdx, |_| FileStat {
            inode: buf[0],
            size: buf[1],
            is_dir: buf[2] != 0,
        })
    }

    fn listdir(&self, path: &str) -> SysResult<Vec<String>> {
        // Phase 1 stub: the kernel returns a newline-separated list in a
        // heap-allocated buffer.  We allocate 4 KiB, ask the kernel to fill
        // it, then parse.  A future ABI revision will use a cursor-based
        // approach for directories with many entries.
        let mut buf = alloc::vec![0u8; 4096];
        let bytes = path.as_bytes();
        // SAFETY: buf is a valid heap allocation; bytes pointer is valid.
        let (rax, rdx) = unsafe {
            self.raw_syscall2(
                92, // FsListDir
                bytes.as_ptr() as u64,
                bytes.len() as u64,
                buf.as_mut_ptr() as u64,
                buf.len() as u64,
                0,
                0,
            )
        };
        if rdx != 0 {
            return Err(Errno::from_raw(rdx));
        }
        // justification: x86_64-unknown-none target; usize == u64, no truncation.
        // The kernel-returned byte count is bounded by the 4 KiB buffer passed
        // above, so even on hypothetical 32-bit targets the value fits in usize.
        #[allow(clippy::cast_possible_truncation)]
        let filled = rax as usize;
        let slice = buf.get(..filled).ok_or(Errno::Fault)?;
        let text = core::str::from_utf8(slice).map_err(|_| Errno::Io)?;
        Ok(text
            .split('\n')
            .filter(|s| !s.is_empty())
            .map(String::from)
            .collect())
    }

    fn mkdir(&self, path: &str) -> SysResult<()> {
        let bytes = path.as_bytes();
        // SAFETY: bytes pointer is valid for the syscall duration.
        let (rax, rdx) =
            unsafe { self.raw_syscall2(95, bytes.as_ptr() as u64, bytes.len() as u64, 0, 0, 0, 0) };
        Self::decode2(rax, rdx, |_| ())
    }

    fn delete(&self, path: &str) -> SysResult<()> {
        let bytes = path.as_bytes();
        // SAFETY: bytes pointer is valid for the syscall duration.
        let (rax, rdx) =
            unsafe { self.raw_syscall2(94, bytes.as_ptr() as u64, bytes.len() as u64, 0, 0, 0, 0) };
        Self::decode2(rax, rdx, |_| ())
    }

    fn create(&self, path: &str) -> SysResult<()> {
        let bytes = path.as_bytes();
        // SAFETY: bytes pointer is valid for the syscall duration.
        let (rax, rdx) =
            unsafe { self.raw_syscall2(93, bytes.as_ptr() as u64, bytes.len() as u64, 0, 0, 0, 0) };
        Self::decode2(rax, rdx, |_| ())
    }

    fn getcwd(&self) -> SysResult<String> {
        let mut buf = alloc::vec![0u8; 4096];
        // SAFETY: buf is a valid heap allocation.
        let (rax, rdx) =
            unsafe { self.raw_syscall2(16, buf.as_mut_ptr() as u64, buf.len() as u64, 0, 0, 0, 0) };
        if rdx != 0 {
            return Err(Errno::from_raw(rdx));
        }
        // justification: x86_64-unknown-none target; usize == u64, no truncation.
        // The returned length is bounded by the 4 KiB buffer above.
        #[allow(clippy::cast_possible_truncation)]
        let len = rax as usize;
        let slice = buf.get(..len).ok_or(Errno::Fault)?;
        core::str::from_utf8(slice)
            .map(String::from)
            .map_err(|_| Errno::Io)
    }

    fn setcwd(&self, path: &str) -> SysResult<()> {
        let bytes = path.as_bytes();
        // SAFETY: bytes pointer is valid for the syscall duration.
        let (rax, rdx) =
            unsafe { self.raw_syscall2(17, bytes.as_ptr() as u64, bytes.len() as u64, 0, 0, 0, 0) };
        Self::decode2(rax, rdx, |_| ())
    }

    fn exit(&self, code: u32) -> ! {
        // SAFETY: TaskExit (11) takes a single u32 exit code in rdi and never
        // returns; the kernel immediately terminates the calling task.
        // `options(noreturn)` informs the compiler this path diverges.
        unsafe {
            core::arch::asm!(
                "syscall",
                in("rax") 11u64, // TaskExit
                in("rdi") u64::from(code),
                options(noreturn),
            );
        }
    }

    fn spawn(&self, path: &str, argv: &[&str], envp: &[&str]) -> SysResult<u64> {
        // ABI: rdi=path_ptr, rsi=path_len, rdx=argv_ptr, r10=argv_count,
        //      r8=envp_ptr, r9=envp_count.
        // argv and envp are arrays of (ptr: u64, len: u64) pairs.
        let path_bytes = path.as_bytes();
        let mut argv_pairs: alloc::vec::Vec<u64> = alloc::vec::Vec::with_capacity(argv.len() * 2);
        for s in argv {
            let b = s.as_bytes();
            argv_pairs.push(b.as_ptr() as u64);
            argv_pairs.push(b.len() as u64);
        }
        let mut envp_pairs: alloc::vec::Vec<u64> = alloc::vec::Vec::with_capacity(envp.len() * 2);
        for s in envp {
            let b = s.as_bytes();
            envp_pairs.push(b.as_ptr() as u64);
            envp_pairs.push(b.len() as u64);
        }
        // SAFETY: all pointers derived from valid Rust slices; counts match pair counts.
        let (rax, rdx) = unsafe {
            self.raw_syscall2(
                14, // ProcessSpawn
                path_bytes.as_ptr() as u64,
                path_bytes.len() as u64,
                argv_pairs.as_ptr() as u64,
                argv.len() as u64,
                envp_pairs.as_ptr() as u64,
                envp.len() as u64,
            )
        };
        Self::decode2(rax, rdx, |pid| pid)
    }

    fn waitpid(&self, pid: u64, flags: u64) -> SysResult<(u64, u32)> {
        // ABI: rdi=pid, rsi=flags.
        // Return: rax=child_pid (>0) on success, rdx=exit_status.
        // Error:  rax=0, rdx=errno.
        let (rax, rdx) =
            // SAFETY: pid and flags are scalar values; no pointer arguments.
            unsafe { self.raw_syscall2(15, pid, flags, 0, 0, 0, 0) };
        if rax == 0 && rdx != 0 {
            Err(Errno::from_raw(rdx))
        } else {
            // justification: the kernel ProcessWait ABI defines exit_status as
            // a 32-bit value; the upper 32 bits of rdx are always zero.
            #[allow(clippy::cast_possible_truncation)]
            Ok((rax, rdx as u32))
        }
    }

    fn pipe(&self) -> SysResult<(u32, u32)> {
        let mut read_fd: u64 = 0;
        let mut write_fd: u64 = 0;
        // SAFETY: read_fd and write_fd are valid stack locations; pointers correct.
        let (rax, rdx) = unsafe {
            self.raw_syscall2(
                62, // PipeCreate
                core::ptr::addr_of_mut!(read_fd) as u64,
                core::ptr::addr_of_mut!(write_fd) as u64,
                0,
                0,
                0,
                0,
            )
        };
        // justification: the kernel PipeCreate ABI guarantees fd values fit in
        // u32; the upper 32 bits of each output are always zero.
        #[allow(clippy::cast_possible_truncation)]
        Self::decode2(rax, rdx, |_| (read_fd as u32, write_fd as u32))
    }

    fn dup2(&self, old: u32, new: u32) -> SysResult<u32> {
        // SAFETY: old and new are scalar fd values.
        let (rax, rdx) = unsafe {
            self.raw_syscall2(
                67, // FdDup2
                u64::from(old),
                u64::from(new),
                0,
                0,
                0,
                0,
            )
        };
        // justification: FdDup2 returns a 32-bit fd; upper 32 bits are zero.
        #[allow(clippy::cast_possible_truncation)]
        Self::decode2(rax, rdx, |n| n as u32)
    }

    fn seek(&self, fd: u32, offset: i64, whence: u32) -> SysResult<u64> {
        // SAFETY: fd, offset (cast to u64 for the register), and whence are scalars.
        // The kernel receives the signed offset as its bit-pattern in rdx and
        // interprets it as i64 internally.
        // justification: passing i64 as u64 bit-pattern is the documented NexaCore
        // OS syscall ABI for FdSeek; the kernel re-interprets the bits as i64.
        #[allow(clippy::cast_sign_loss)]
        let (rax, rdx) = unsafe {
            self.raw_syscall2(
                68, // FdSeek
                u64::from(fd),
                offset as u64,
                u64::from(whence),
                0,
                0,
                0,
            )
        };
        Self::decode2(rax, rdx, |pos| pos)
    }

    fn time_monotonic_nanos(&self) -> u64 {
        // SAFETY: TimeMonotonicNanos (50) takes no arguments and never fails.
        unsafe { self.raw_syscall(50, 0, 0, 0) }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    // In bare-metal mode the std prelude is absent; `.to_string()` requires
    // `ToString` to be explicitly in scope.
    #[cfg(feature = "bare-metal")]
    use alloc::string::ToString;
    #[cfg(feature = "bare-metal")]
    use alloc::vec;

    use super::*;

    // ---- Errno::from_raw ---------------------------------------------------

    #[test]
    fn errno_from_raw_success() {
        assert_eq!(Errno::from_raw(0), Errno::Success);
    }

    #[test]
    fn errno_from_raw_no_entry() {
        assert_eq!(Errno::from_raw(2), Errno::NoEntry);
    }

    #[test]
    fn errno_from_raw_no_process() {
        assert_eq!(Errno::from_raw(3), Errno::NoProcess);
    }

    #[test]
    fn errno_from_raw_interrupted() {
        assert_eq!(Errno::from_raw(4), Errno::Interrupted);
    }

    #[test]
    fn errno_from_raw_io() {
        assert_eq!(Errno::from_raw(5), Errno::Io);
    }

    #[test]
    fn errno_from_raw_bad_fd() {
        assert_eq!(Errno::from_raw(9), Errno::BadFd);
    }

    #[test]
    fn errno_from_raw_no_child() {
        assert_eq!(Errno::from_raw(10), Errno::NoChild);
    }

    #[test]
    fn errno_from_raw_again() {
        assert_eq!(Errno::from_raw(11), Errno::Again);
    }

    #[test]
    fn errno_from_raw_access() {
        assert_eq!(Errno::from_raw(13), Errno::Access);
    }

    #[test]
    fn errno_from_raw_fault() {
        assert_eq!(Errno::from_raw(14), Errno::Fault);
    }

    #[test]
    fn errno_from_raw_exists() {
        assert_eq!(Errno::from_raw(17), Errno::Exists);
    }

    #[test]
    fn errno_from_raw_not_dir() {
        assert_eq!(Errno::from_raw(20), Errno::NotDir);
    }

    #[test]
    fn errno_from_raw_is_dir() {
        assert_eq!(Errno::from_raw(21), Errno::IsDir);
    }

    #[test]
    fn errno_from_raw_invalid() {
        assert_eq!(Errno::from_raw(22), Errno::Invalid);
    }

    #[test]
    fn errno_from_raw_no_space() {
        assert_eq!(Errno::from_raw(28), Errno::NoSpace);
    }

    #[test]
    fn errno_from_raw_broken_pipe() {
        assert_eq!(Errno::from_raw(32), Errno::BrokenPipe);
    }

    #[test]
    fn errno_from_raw_not_impl() {
        assert_eq!(Errno::from_raw(38), Errno::NotImpl);
    }

    #[test]
    fn errno_from_raw_unknown_high() {
        // Any value not in the known set maps to Unknown.
        assert_eq!(Errno::from_raw(99), Errno::Unknown);
        assert_eq!(Errno::from_raw(255), Errno::Unknown);
        assert_eq!(Errno::from_raw(u64::MAX), Errno::Unknown);
    }

    // ---- Errno::as_raw roundtrip -------------------------------------------

    #[test]
    fn errno_as_raw_roundtrip() {
        // Every non-Unknown variant must round-trip through from_raw.
        let cases: &[(Errno, u64)] = &[
            (Errno::Success, 0),
            (Errno::NoEntry, 2),
            (Errno::NoProcess, 3),
            (Errno::Interrupted, 4),
            (Errno::Io, 5),
            (Errno::BadFd, 9),
            (Errno::NoChild, 10),
            (Errno::Again, 11),
            (Errno::Access, 13),
            (Errno::Fault, 14),
            (Errno::Exists, 17),
            (Errno::NotDir, 20),
            (Errno::IsDir, 21),
            (Errno::Invalid, 22),
            (Errno::NoSpace, 28),
            (Errno::BrokenPipe, 32),
            (Errno::NotImpl, 38),
        ];
        for &(variant, expected_raw) in cases {
            assert_eq!(
                variant.as_raw(),
                expected_raw,
                "as_raw mismatch for {variant:?}"
            );
            assert_eq!(
                Errno::from_raw(variant.as_raw()),
                variant,
                "roundtrip failed for {variant:?}"
            );
        }
    }

    // ---- Errno::is_success -------------------------------------------------

    #[test]
    fn errno_is_success_only_for_success() {
        assert!(Errno::Success.is_success());
        assert!(!Errno::Io.is_success());
        assert!(!Errno::Invalid.is_success());
        assert!(!Errno::Unknown.is_success());
    }

    // ---- Display -----------------------------------------------------------

    #[test]
    fn errno_display_success() {
        assert_eq!(Errno::Success.to_string(), "success");
    }

    #[test]
    fn errno_display_no_entry() {
        assert_eq!(Errno::NoEntry.to_string(), "no such file or directory");
    }

    #[test]
    fn errno_display_invalid() {
        assert_eq!(Errno::Invalid.to_string(), "invalid argument");
    }

    #[test]
    fn errno_display_unknown() {
        assert_eq!(Errno::Unknown.to_string(), "unknown error");
    }

    #[test]
    fn errno_display_all_variants_non_empty() {
        let variants = [
            Errno::Success,
            Errno::NoEntry,
            Errno::NoProcess,
            Errno::Interrupted,
            Errno::Io,
            Errno::BadFd,
            Errno::NoChild,
            Errno::Again,
            Errno::Access,
            Errno::Fault,
            Errno::Exists,
            Errno::NotDir,
            Errno::IsDir,
            Errno::Invalid,
            Errno::NoSpace,
            Errno::BrokenPipe,
            Errno::NotImpl,
            Errno::Unknown,
        ];
        for v in variants {
            assert!(!v.to_string().is_empty(), "Display string empty for {v:?}");
        }
    }

    // ---- SysResult ---------------------------------------------------------

    #[test]
    fn sys_result_ok_carries_value() {
        let r: SysResult<u32> = Ok(42);
        assert_eq!(r, Ok(42));
    }

    #[test]
    fn sys_result_err_carries_errno() {
        let r: SysResult<u32> = Err(Errno::Access);
        assert_eq!(r, Err(Errno::Access));
    }

    #[test]
    fn sys_result_map_on_ok() {
        let r: SysResult<u32> = Ok(10);
        assert_eq!(r.map(|x| x * 2), Ok(20));
    }

    #[test]
    fn sys_result_map_skipped_on_err() {
        let r: SysResult<u32> = Err(Errno::Io);
        assert_eq!(r.map(|x| x * 2), Err(Errno::Io));
    }

    // ---- FileStat ----------------------------------------------------------

    #[test]
    fn file_stat_regular_file() {
        let st = FileStat {
            inode: 42,
            size: 1024,
            is_dir: false,
        };
        assert_eq!(st.inode, 42);
        assert_eq!(st.size, 1024);
        assert!(!st.is_dir);
    }

    #[test]
    fn file_stat_directory() {
        let st = FileStat {
            inode: 1,
            size: 4096,
            is_dir: true,
        };
        assert!(st.is_dir);
    }

    #[test]
    // The clone here is the whole point of the test — it verifies the derived
    // `Clone` impl produces a value equal to the original.  The lint fires
    // because `st` is not consumed after the clone, but dropping both bindings
    // is intentional: we are testing equality, not ownership transfer.
    #[allow(clippy::redundant_clone)]
    fn file_stat_clone_eq() {
        let st = FileStat {
            inode: 7,
            size: 8,
            is_dir: false,
        };
        let st2 = st.clone();
        assert_eq!(st.inode, st2.inode);
        assert_eq!(st.size, st2.size);
        assert_eq!(st.is_dir, st2.is_dir);
    }

    // ---- flags constants ---------------------------------------------------

    #[test]
    fn flags_o_rdonly_is_zero() {
        assert_eq!(flags::O_RDONLY, 0);
    }

    #[test]
    fn flags_o_wronly_is_one() {
        assert_eq!(flags::O_WRONLY, 1);
    }

    #[test]
    fn flags_o_rdwr_is_two() {
        assert_eq!(flags::O_RDWR, 2);
    }

    #[test]
    fn flags_o_creat_posix_value() {
        // POSIX O_CREAT = octal 0100 = decimal 64 = 0x40.
        assert_eq!(flags::O_CREAT, 0x40);
    }

    #[test]
    fn flags_o_trunc_posix_value() {
        // POSIX O_TRUNC = octal 01000 = decimal 512 = 0x200.
        assert_eq!(flags::O_TRUNC, 0x200);
    }

    #[test]
    fn flags_o_append_posix_value() {
        // POSIX O_APPEND = octal 02000 = decimal 1024 = 0x400.
        assert_eq!(flags::O_APPEND, 0x400);
    }

    #[test]
    fn flags_seek_constants() {
        assert_eq!(flags::SEEK_SET, 0);
        assert_eq!(flags::SEEK_CUR, 1);
        assert_eq!(flags::SEEK_END, 2);
    }

    #[test]
    fn flags_wnohang_is_one() {
        assert_eq!(flags::WNOHANG, 1_u64);
    }

    #[test]
    fn flags_can_be_combined_with_bitor() {
        // Ensure the expected combinations do not accidentally overlap bits.
        let create_write = flags::O_WRONLY | flags::O_CREAT | flags::O_TRUNC;
        assert_eq!(create_write, 1 | 0x40 | 0x200);
    }

    // ---- Syscall trait — mock implementation -------------------------------

    /// Minimal mock that returns canned values for every [`Syscall`] method.
    struct MockSyscall {
        /// Canned response for `write`.
        pub write_result: SysResult<usize>,
        /// Canned response for `read`.
        pub read_result: SysResult<usize>,
        /// Canned fd for `open`.
        pub open_fd: SysResult<u32>,
        /// Canned cwd string.
        pub cwd: &'static str,
    }

    impl MockSyscall {
        /// Construct a mock that returns success for every operation.
        fn ok() -> Self {
            Self {
                write_result: Ok(0),
                read_result: Ok(0),
                open_fd: Ok(3),
                cwd: "/home/user",
            }
        }

        /// Construct a mock that returns errors for write/read/open.
        fn failing() -> Self {
            Self {
                write_result: Err(Errno::BrokenPipe),
                read_result: Err(Errno::BadFd),
                open_fd: Err(Errno::Access),
                cwd: "/",
            }
        }
    }

    impl Syscall for MockSyscall {
        fn write(&self, _fd: u32, buf: &[u8]) -> SysResult<usize> {
            // Substitute buf.len() for the Ok payload so callers can verify
            // the correct byte count.
            self.write_result.map(|_| buf.len())
        }

        fn read(&self, _fd: u32, _buf: &mut [u8]) -> SysResult<usize> {
            self.read_result
        }

        fn close(&self, _fd: u32) -> SysResult<()> {
            Ok(())
        }

        fn open(&self, _path: &str, _flags: u32) -> SysResult<u32> {
            self.open_fd
        }

        fn stat(&self, path: &str) -> SysResult<FileStat> {
            if path.is_empty() {
                Err(Errno::NoEntry)
            } else {
                Ok(FileStat {
                    inode: 1,
                    size: 512,
                    is_dir: path.ends_with('/'),
                })
            }
        }

        fn listdir(&self, path: &str) -> SysResult<Vec<String>> {
            if path.is_empty() {
                Err(Errno::NoEntry)
            } else {
                Ok(vec!["a".into(), "b".into()])
            }
        }

        fn mkdir(&self, path: &str) -> SysResult<()> {
            if path.is_empty() {
                Err(Errno::Invalid)
            } else {
                Ok(())
            }
        }

        fn delete(&self, path: &str) -> SysResult<()> {
            if path.is_empty() {
                Err(Errno::Invalid)
            } else {
                Ok(())
            }
        }

        fn create(&self, path: &str) -> SysResult<()> {
            if path.is_empty() {
                Err(Errno::Invalid)
            } else {
                Ok(())
            }
        }

        fn getcwd(&self) -> SysResult<String> {
            Ok(String::from(self.cwd))
        }

        fn setcwd(&self, path: &str) -> SysResult<()> {
            if path.is_empty() {
                Err(Errno::NoEntry)
            } else {
                Ok(())
            }
        }

        #[allow(clippy::panic)]
        fn exit(&self, _code: u32) -> ! {
            // In tests we cannot actually exit; panic so the test framework
            // can catch it via `#[should_panic]`.  The `clippy::panic` lint is
            // suppressed here because this is intentional test-only behaviour
            // that simulates the diverging syscall without calling the kernel.
            panic!("MockSyscall::exit called");
        }

        fn spawn(&self, _path: &str, _argv: &[&str], _envp: &[&str]) -> SysResult<u64> {
            Ok(1234)
        }

        fn waitpid(&self, pid: u64, _flags: u64) -> SysResult<(u64, u32)> {
            if pid == 0 {
                Err(Errno::NoChild)
            } else {
                Ok((pid, 0))
            }
        }

        fn pipe(&self) -> SysResult<(u32, u32)> {
            Ok((3, 4))
        }

        fn dup2(&self, _old: u32, new: u32) -> SysResult<u32> {
            Ok(new)
        }

        fn seek(&self, _fd: u32, offset: i64, whence: u32) -> SysResult<u64> {
            if whence == flags::SEEK_SET {
                Ok(offset.unsigned_abs())
            } else {
                Ok(0)
            }
        }

        fn time_monotonic_nanos(&self) -> u64 {
            42_000_000_000
        }
    }

    #[test]
    fn mock_write_ok_returns_buf_len() {
        let sc = MockSyscall::ok();
        let buf = b"hello world";
        assert_eq!(sc.write(1, buf), Ok(buf.len()));
    }

    #[test]
    fn mock_write_err_propagates() {
        let sc = MockSyscall::failing();
        assert_eq!(sc.write(1, b"x"), Err(Errno::BrokenPipe));
    }

    #[test]
    fn mock_read_err_propagates() {
        let sc = MockSyscall::failing();
        let mut buf = [0u8; 8];
        assert_eq!(sc.read(0, &mut buf), Err(Errno::BadFd));
    }

    #[test]
    fn mock_open_ok_returns_fd() {
        let sc = MockSyscall::ok();
        assert_eq!(sc.open("/tmp/file.txt", flags::O_RDONLY), Ok(3));
    }

    #[test]
    fn mock_open_err_propagates() {
        let sc = MockSyscall::failing();
        assert_eq!(sc.open("/etc/shadow", flags::O_RDONLY), Err(Errno::Access));
    }

    #[test]
    fn mock_stat_empty_path_is_no_entry() {
        let sc = MockSyscall::ok();
        assert_eq!(sc.stat(""), Err(Errno::NoEntry));
    }

    #[test]
    #[allow(clippy::panic)]
    fn mock_stat_dir_detected() {
        let sc = MockSyscall::ok();
        let st = sc.stat("/home/").unwrap_or_else(|e| {
            panic!("stat(/home/) should succeed, got Err({e})");
        });
        assert!(st.is_dir);
    }

    #[test]
    #[allow(clippy::panic)]
    fn mock_stat_file() {
        let sc = MockSyscall::ok();
        let st = sc.stat("/home/user/file.txt").unwrap_or_else(|e| {
            panic!("stat should succeed, got Err({e})");
        });
        assert!(!st.is_dir);
        assert_eq!(st.inode, 1);
    }

    #[test]
    #[allow(clippy::panic)]
    fn mock_listdir_returns_entries() {
        let sc = MockSyscall::ok();
        let entries = sc.listdir("/home").unwrap_or_else(|e| {
            panic!("listdir should succeed, got Err({e})");
        });
        assert_eq!(entries, vec!["a".to_string(), "b".to_string()]);
    }

    #[test]
    fn mock_listdir_empty_path_is_error() {
        let sc = MockSyscall::ok();
        assert_eq!(sc.listdir(""), Err(Errno::NoEntry));
    }

    #[test]
    fn mock_getcwd() {
        let sc = MockSyscall::ok();
        assert_eq!(sc.getcwd(), Ok(String::from("/home/user")));
    }

    #[test]
    fn mock_setcwd_ok() {
        let sc = MockSyscall::ok();
        assert_eq!(sc.setcwd("/tmp"), Ok(()));
    }

    #[test]
    fn mock_setcwd_empty_path_is_error() {
        let sc = MockSyscall::ok();
        assert_eq!(sc.setcwd(""), Err(Errno::NoEntry));
    }

    #[test]
    fn mock_spawn_returns_pid() {
        let sc = MockSyscall::ok();
        assert_eq!(sc.spawn("/bin/ls", &["/bin/ls", "-la"], &[]), Ok(1234));
    }

    #[test]
    fn mock_waitpid_ok() {
        let sc = MockSyscall::ok();
        assert_eq!(sc.waitpid(1234, 0), Ok((1234, 0)));
    }

    #[test]
    fn mock_waitpid_zero_pid_is_error() {
        let sc = MockSyscall::ok();
        assert_eq!(sc.waitpid(0, 0), Err(Errno::NoChild));
    }

    #[test]
    fn mock_pipe_returns_fd_pair() {
        let sc = MockSyscall::ok();
        assert_eq!(sc.pipe(), Ok((3, 4)));
    }

    #[test]
    fn mock_dup2_returns_new_fd() {
        let sc = MockSyscall::ok();
        assert_eq!(sc.dup2(1, 5), Ok(5));
    }

    #[test]
    fn mock_seek_set_returns_offset() {
        let sc = MockSyscall::ok();
        assert_eq!(sc.seek(3, 100, flags::SEEK_SET), Ok(100));
    }

    #[test]
    fn mock_time_monotonic_nanos() {
        let sc = MockSyscall::ok();
        assert_eq!(sc.time_monotonic_nanos(), 42_000_000_000);
    }

    #[test]
    fn mock_mkdir_ok() {
        let sc = MockSyscall::ok();
        assert_eq!(sc.mkdir("/tmp/newdir"), Ok(()));
    }

    #[test]
    fn mock_mkdir_empty_path_is_error() {
        let sc = MockSyscall::ok();
        assert_eq!(sc.mkdir(""), Err(Errno::Invalid));
    }

    #[test]
    fn mock_delete_ok() {
        let sc = MockSyscall::ok();
        assert_eq!(sc.delete("/tmp/file"), Ok(()));
    }

    #[test]
    fn mock_create_ok() {
        let sc = MockSyscall::ok();
        assert_eq!(sc.create("/tmp/newfile"), Ok(()));
    }

    #[test]
    fn mock_close_ok() {
        let sc = MockSyscall::ok();
        assert_eq!(sc.close(3), Ok(()));
    }

    // ---- exit panics in mock (must be last — uses should_panic) ------------

    #[test]
    #[should_panic(expected = "MockSyscall::exit called")]
    fn mock_exit_panics_in_test() {
        let sc = MockSyscall::ok();
        sc.exit(0);
    }
}
