//! Per-process file descriptor table.
//!
//! This module provides the kernel-internal representation of open file
//! descriptors. Every process owns a [`crate::fd::FileDescriptorTable`] stored
//! inside its `ProcessControlBlock`. The table is indexed by
//! [`crate::fd::RawFd`] — a monotonically-assigned `u32` — and each entry
//! records what kind of resource is open ([`crate::fd::FdKind`]) together with
//! per-fd behaviour flags ([`crate::fd::FdFlags`]).
//!
//! ## Design constraints
//!
//! - `no_std` compatible: all heap usage goes through `alloc::collections::BTreeMap`.
//! - No `unsafe` code: the entire module is safe Rust.
//! - No `println!` or `std::` usage: diagnostics are left to the caller.
//!
//! ## fd numbering
//!
//! fd numbers are assigned from a per-table `next_fd` cursor.  When the
//! cursor slot is already occupied (e.g. after a `dup2` that filled it),
//! [`crate::fd::FileDescriptorTable::open`] scans forward until it finds a
//! free slot, then advances `next_fd` past that slot.  This guarantees
//! lowest-available assignment without wrapping the cursor back to zero
//! (which would cause surprising re-use of low fd numbers that were
//! explicitly closed).
//!
//! If no free slot exists below [`u32::MAX`] the call returns
//! `Err(KernelError::ResourceExhausted)`.  In practice a process would
//! have to open 2³²−1 file descriptors simultaneously to reach that
//! condition; the kernel imposes per-process limits at a higher layer.

use alloc::collections::BTreeMap;

use crate::KernelError;

// ---------------------------------------------------------------------------
// RawFd
// ---------------------------------------------------------------------------

/// A raw file-descriptor index as seen by user space and the kernel FD table.
///
/// The value is an opaque `u32`; callers must not assume any relationship
/// between the numeric value and the underlying resource (except that 0, 1,
/// and 2 are the POSIX-conventional stdin/stdout/stderr).
///
/// # Example
///
/// ```rust
/// use nexacore_kernel::fd::RawFd;
///
/// let fd = RawFd(3);
/// assert_eq!(fd.0, 3);
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RawFd(pub u32);

// ---------------------------------------------------------------------------
// FdFlags
// ---------------------------------------------------------------------------

/// Flags that control per-descriptor behaviour, independent of the resource.
///
/// These correspond to the POSIX `FD_CLOEXEC` and `O_NONBLOCK` concepts
/// but are stored as strongly-typed booleans rather than bitfields to avoid
/// masking errors.
///
/// # Example
///
/// ```rust
/// use nexacore_kernel::fd::FdFlags;
///
/// let flags = FdFlags {
///     close_on_exec: true,
///     non_block: false,
/// };
/// assert!(flags.close_on_exec);
/// assert!(!flags.non_block);
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct FdFlags {
    /// Close this descriptor in the child process after a `fork`/`spawn`
    /// (`FD_CLOEXEC`). [`FileDescriptorTable::clone_for_child`] filters
    /// out entries with this flag set.
    pub close_on_exec: bool,
    /// Perform I/O operations in non-blocking mode (`O_NONBLOCK`). The
    /// kernel honours this flag when dispatching read/write syscalls.
    pub non_block: bool,
}

// ---------------------------------------------------------------------------
// OpenFlags
// ---------------------------------------------------------------------------

/// Open-file flags for filesystem-backed file descriptors (`O_*` constants).
///
/// The inner `u32` is a bitfield following the Linux ABI so that user-space
/// syscall stubs can pass `flags` from `open(2)` directly to the kernel
/// without translation.
///
/// Helper methods expose named predicates instead of raw mask checks, which
/// prevents bugs caused by combining incompatible flags.
///
/// # Example
///
/// ```rust
/// use nexacore_kernel::fd::OpenFlags;
///
/// let flags = OpenFlags(OpenFlags::O_RDWR | OpenFlags::O_CREAT);
/// assert!(flags.is_readable());
/// assert!(flags.is_writable());
/// assert!(flags.has_create());
/// assert!(!flags.has_append());
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OpenFlags(pub u32);

impl OpenFlags {
    /// Open the file for reading only.
    pub const O_RDONLY: u32 = 0;
    /// Open the file for writing only.
    pub const O_WRONLY: u32 = 1;
    /// Open the file for both reading and writing.
    pub const O_RDWR: u32 = 2;
    /// Create the file if it does not exist.
    pub const O_CREAT: u32 = 0x40;
    /// Truncate the file to zero length on open (requires write access).
    pub const O_TRUNC: u32 = 0x200;
    /// All writes go to the end of the file.
    pub const O_APPEND: u32 = 0x400;

    // The access-mode mask occupies the two least-significant bits.
    const ACCESS_MASK: u32 = 0x3;

    /// Returns `true` if the file was opened for reading (`O_RDONLY` or
    /// `O_RDWR`).
    #[must_use]
    pub fn is_readable(self) -> bool {
        let mode = self.0 & Self::ACCESS_MASK;
        mode == Self::O_RDONLY || mode == Self::O_RDWR
    }

    /// Returns `true` if the file was opened for writing (`O_WRONLY` or
    /// `O_RDWR`).
    #[must_use]
    pub fn is_writable(self) -> bool {
        let mode = self.0 & Self::ACCESS_MASK;
        mode == Self::O_WRONLY || mode == Self::O_RDWR
    }

    /// Returns `true` if the `O_CREAT` flag is set.
    #[must_use]
    pub fn has_create(self) -> bool {
        self.0 & Self::O_CREAT != 0
    }

    /// Returns `true` if the `O_TRUNC` flag is set.
    #[must_use]
    pub fn has_trunc(self) -> bool {
        self.0 & Self::O_TRUNC != 0
    }

    /// Returns `true` if the `O_APPEND` flag is set.
    #[must_use]
    pub fn has_append(self) -> bool {
        self.0 & Self::O_APPEND != 0
    }
}

// ---------------------------------------------------------------------------
// FdKind
// ---------------------------------------------------------------------------

/// The kind of resource a file descriptor refers to.
///
/// Every variant carries only the information the kernel needs to service
/// read/write/ioctl calls on that descriptor.  Richer state (e.g. the
/// backing `Pipe` struct or an open `Channel` endpoint) lives in the
/// relevant kernel subsystem; this enum records only the stable identifier
/// needed to look it up.
#[derive(Debug, Clone)]
pub enum FdKind {
    /// A kernel console endpoint (serial or framebuffer).
    ///
    /// stdin is `Console { readable: true, writable: false }`;
    /// stdout and stderr are `Console { readable: false, writable: true }`.
    Console {
        /// Whether the console endpoint accepts read operations.
        readable: bool,
        /// Whether the console endpoint accepts write operations.
        writable: bool,
    },

    /// One end of an anonymous pipe.
    Pipe {
        /// Kernel-assigned pipe identifier.  Both ends share this id so the
        /// pipe state can be located in the global pipe table.
        pipe_id: u64,
        /// `true` for the read end, `false` for the write end.
        is_read_end: bool,
    },

    /// An open file on the NexaCore filesystem.
    FsFile {
        /// Inode number on the filesystem.
        inode: u64,
        /// Current byte offset (position for the next read or write).
        offset: u64,
        /// The flags the file was opened with.
        flags: OpenFlags,
    },

    /// One endpoint of an IPC channel.
    ///
    /// The inner value is a [`crate::ipc::ChannelId`] serialised as `u64`
    /// to keep this module free of a direct dependency on the IPC subsystem.
    IpcChannel(u64),
}

// ---------------------------------------------------------------------------
// FileDescriptor
// ---------------------------------------------------------------------------

/// A single open file descriptor: a resource kind plus per-fd flags.
///
/// # Example
///
/// ```rust
/// use nexacore_kernel::fd::{FdFlags, FdKind, FileDescriptor};
///
/// let fd = FileDescriptor {
///     kind: FdKind::Console {
///         readable: true,
///         writable: false,
///     },
///     flags: FdFlags::default(),
/// };
/// assert!(!fd.flags.close_on_exec);
/// ```
#[derive(Debug, Clone)]
pub struct FileDescriptor {
    /// What resource this descriptor refers to.
    pub kind: FdKind,
    /// Behaviour flags for this descriptor.
    pub flags: FdFlags,
}

// ---------------------------------------------------------------------------
// FileDescriptorTable
// ---------------------------------------------------------------------------

/// Per-process table of open file descriptors.
///
/// The table maps [`RawFd`] numbers to [`FileDescriptor`] entries.  It owns
/// the sole kernel-side record of which resources a process has open, and is
/// the source of truth for `close`, `dup`, `dup2`, and `clone_for_child`
/// (fork/spawn) operations.
///
/// # fd assignment
///
/// [`open`](FileDescriptorTable::open) always assigns the lowest available fd
/// number starting from an internal cursor (`next_fd`).  The cursor never
/// resets to zero, so a sequence of open/close/open calls does not re-issue
/// old fd numbers — this avoids a class of use-after-free bugs where stale
/// fd values held by user space accidentally refer to a new resource.
///
/// # Example
///
/// ```rust
/// use nexacore_kernel::fd::{FdFlags, FdKind, FileDescriptor, FileDescriptorTable};
///
/// let mut table = FileDescriptorTable::new_with_stdio();
/// assert!(table.get(nexacore_kernel::fd::RawFd(0)).is_some());
/// assert!(table.get(nexacore_kernel::fd::RawFd(1)).is_some());
/// assert!(table.get(nexacore_kernel::fd::RawFd(2)).is_some());
/// ```
#[derive(Debug, Clone)]
pub struct FileDescriptorTable {
    /// Active entries keyed by the raw fd number.
    entries: BTreeMap<u32, FileDescriptor>,
    /// The next fd number to try when inserting a new descriptor.
    /// Monotonically non-decreasing; scanned forward on collision.
    next_fd: u32,
}

impl FileDescriptorTable {
    // -----------------------------------------------------------------------
    // Constructors
    // -----------------------------------------------------------------------

    /// Creates an empty file descriptor table with no open descriptors.
    ///
    /// Suitable for kernel-internal tasks that do not need user-space I/O.
    ///
    /// # Example
    ///
    /// ```rust
    /// use nexacore_kernel::fd::FileDescriptorTable;
    ///
    /// let table = FileDescriptorTable::new();
    /// assert!(table.iter().next().is_none());
    /// ```
    #[must_use]
    pub fn new() -> Self {
        Self {
            entries: BTreeMap::new(),
            next_fd: 0,
        }
    }

    /// Creates a file descriptor table pre-populated with the three standard
    /// POSIX descriptors:
    ///
    /// - fd 0 — stdin  (`Console { readable: true,  writable: false }`)
    /// - fd 1 — stdout (`Console { readable: false, writable: true  }`)
    /// - fd 2 — stderr (`Console { readable: false, writable: true  }`)
    ///
    /// The internal cursor is set to 3 so the next [`open`](Self::open) call
    /// assigns fd 3.
    ///
    /// # Example
    ///
    /// ```rust
    /// use nexacore_kernel::fd::{FileDescriptorTable, RawFd};
    ///
    /// let table = FileDescriptorTable::new_with_stdio();
    /// assert!(table.get(RawFd(0)).is_some());
    /// assert!(table.get(RawFd(1)).is_some());
    /// assert!(table.get(RawFd(2)).is_some());
    /// assert!(table.get(RawFd(3)).is_none());
    /// ```
    #[must_use]
    pub fn new_with_stdio() -> Self {
        let mut entries = BTreeMap::new();

        entries.insert(
            0,
            FileDescriptor {
                kind: FdKind::Console {
                    readable: true,
                    writable: false,
                },
                flags: FdFlags::default(),
            },
        );
        entries.insert(
            1,
            FileDescriptor {
                kind: FdKind::Console {
                    readable: false,
                    writable: true,
                },
                flags: FdFlags::default(),
            },
        );
        entries.insert(
            2,
            FileDescriptor {
                kind: FdKind::Console {
                    readable: false,
                    writable: true,
                },
                flags: FdFlags::default(),
            },
        );

        Self {
            entries,
            next_fd: 3,
        }
    }

    // -----------------------------------------------------------------------
    // Core operations
    // -----------------------------------------------------------------------

    /// Inserts `descriptor` at the lowest available fd number, starting from
    /// the internal cursor.
    ///
    /// The cursor is advanced past the assigned slot so the next call
    /// continues scanning forward.
    ///
    /// # Errors
    ///
    /// Returns `Err(KernelError::ResourceExhausted)` if every slot from the
    /// cursor to [`u32::MAX`] is already occupied.  In practice a process
    /// would have to hold 2³²−1 simultaneous open descriptors to trigger
    /// this; the kernel enforces a per-process limit at a higher layer.
    ///
    /// # Example
    ///
    /// ```rust
    /// use nexacore_kernel::fd::{FdFlags, FdKind, FileDescriptor, FileDescriptorTable, RawFd};
    ///
    /// let mut table = FileDescriptorTable::new();
    /// let fd = table.open(FileDescriptor {
    ///     kind: FdKind::Console {
    ///         readable: false,
    ///         writable: true,
    ///     },
    ///     flags: FdFlags::default(),
    /// });
    /// assert_eq!(fd, Ok(RawFd(0)));
    /// ```
    pub fn open(&mut self, descriptor: FileDescriptor) -> Result<RawFd, KernelError> {
        use alloc::collections::btree_map::Entry;

        // Scan forward from next_fd until we find a slot that is not in use.
        // The Entry API avoids a double-lookup (contains_key + insert) and
        // satisfies clippy::map_entry in one pattern.
        let mut candidate = self.next_fd;
        loop {
            if let Entry::Vacant(slot) = self.entries.entry(candidate) {
                // Found a free slot — insert and advance the cursor.
                slot.insert(descriptor);
                // Saturate rather than wrap so subsequent calls continue
                // scanning forward without re-issuing low fd numbers.
                self.next_fd = candidate.saturating_add(1);
                return Ok(RawFd(candidate));
            }
            // Slot occupied — try the next one, stopping at u32::MAX.
            match candidate.checked_add(1) {
                Some(next) => candidate = next,
                None => return Err(KernelError::ResourceExhausted),
            }
        }
    }

    /// Closes `fd`, removing it from the table.
    ///
    /// # Errors
    ///
    /// Returns `Err(KernelError::InvalidArgument)` if `fd` is not currently
    /// open in this table.  This matches POSIX `EBADF` semantics.
    ///
    /// # Example
    ///
    /// ```rust
    /// use nexacore_kernel::fd::{FileDescriptorTable, RawFd};
    ///
    /// let mut table = FileDescriptorTable::new_with_stdio();
    /// assert!(table.close(RawFd(0)).is_ok());
    /// assert!(table.close(RawFd(0)).is_err()); // already closed
    /// ```
    pub fn close(&mut self, fd: RawFd) -> Result<(), KernelError> {
        self.entries
            .remove(&fd.0)
            .map(|_| ())
            .ok_or(KernelError::InvalidArgument)
    }

    /// Returns a shared reference to the descriptor at `fd`, or `None` if
    /// `fd` is not open.
    ///
    /// # Example
    ///
    /// ```rust
    /// use nexacore_kernel::fd::{FileDescriptorTable, RawFd};
    ///
    /// let table = FileDescriptorTable::new_with_stdio();
    /// assert!(table.get(RawFd(1)).is_some());
    /// assert!(table.get(RawFd(99)).is_none());
    /// ```
    #[must_use]
    pub fn get(&self, fd: RawFd) -> Option<&FileDescriptor> {
        self.entries.get(&fd.0)
    }

    /// Returns a mutable reference to the descriptor at `fd`, or `None` if
    /// `fd` is not open.
    ///
    /// This is used by subsystems that need to update mutable state inside
    /// an open descriptor (e.g. advancing the file offset for `FsFile`).
    ///
    /// # Example
    ///
    /// ```rust
    /// use nexacore_kernel::fd::{FdKind, FileDescriptorTable, RawFd};
    ///
    /// let mut table = FileDescriptorTable::new_with_stdio();
    /// assert!(table.get_mut(RawFd(2)).is_some());
    /// assert!(table.get_mut(RawFd(99)).is_none());
    /// ```
    pub fn get_mut(&mut self, fd: RawFd) -> Option<&mut FileDescriptor> {
        self.entries.get_mut(&fd.0)
    }

    // -----------------------------------------------------------------------
    // Duplication
    // -----------------------------------------------------------------------

    /// Duplicates `old_fd` to the lowest available fd number (POSIX `dup(2)`).
    ///
    /// The new descriptor inherits the [`FdKind`] of `old_fd` but starts with
    /// cleared [`FdFlags`] (the POSIX-specified behaviour: `FD_CLOEXEC` is
    /// not inherited across `dup`).
    ///
    /// # Errors
    ///
    /// - `Err(KernelError::InvalidArgument)` if `old_fd` is not open.
    /// - `Err(KernelError::ResourceExhausted)` if no fd number is available.
    ///
    /// # Example
    ///
    /// ```rust
    /// use nexacore_kernel::fd::{FileDescriptorTable, RawFd};
    ///
    /// let mut table = FileDescriptorTable::new_with_stdio();
    /// let new_fd = table.dup(RawFd(1)).unwrap();
    /// assert!(new_fd.0 >= 3);
    /// ```
    pub fn dup(&mut self, old_fd: RawFd) -> Result<RawFd, KernelError> {
        // Clone the kind before calling open so we don't hold a borrow
        // on self.entries while mutably modifying the table.
        let kind = self
            .entries
            .get(&old_fd.0)
            .ok_or(KernelError::InvalidArgument)?
            .kind
            .clone();

        self.open(FileDescriptor {
            kind,
            // POSIX: FD_CLOEXEC is cleared on the new descriptor.
            flags: FdFlags::default(),
        })
    }

    /// Duplicates `old_fd` to the specific `new_fd` number (POSIX `dup2(2)`).
    ///
    /// If `new_fd` is already open it is silently closed first.  If
    /// `old_fd == new_fd` the table is left unchanged and `new_fd` is
    /// returned immediately (POSIX no-op semantics).
    ///
    /// The new descriptor inherits [`FdKind`] from `old_fd` and starts with
    /// cleared [`FdFlags`] (same as [`dup`](Self::dup)).
    ///
    /// # Errors
    ///
    /// - `Err(KernelError::InvalidArgument)` if `old_fd` is not open.
    ///
    /// # Example
    ///
    /// ```rust
    /// use nexacore_kernel::fd::{FileDescriptorTable, RawFd};
    ///
    /// let mut table = FileDescriptorTable::new_with_stdio();
    /// // Redirect stderr (fd 2) onto stdout (fd 1).
    /// let result = table.dup2(RawFd(1), RawFd(2));
    /// assert_eq!(result, Ok(RawFd(2)));
    /// ```
    pub fn dup2(&mut self, old_fd: RawFd, new_fd: RawFd) -> Result<RawFd, KernelError> {
        // POSIX: if old_fd == new_fd, return new_fd without doing anything,
        // provided old_fd is valid.
        if old_fd == new_fd {
            return if self.entries.contains_key(&old_fd.0) {
                Ok(new_fd)
            } else {
                Err(KernelError::InvalidArgument)
            };
        }

        // Clone the kind before mutating; avoids conflicting borrows.
        let kind = self
            .entries
            .get(&old_fd.0)
            .ok_or(KernelError::InvalidArgument)?
            .kind
            .clone();

        // Close new_fd if it is currently open (ignore EBADF — it simply
        // was not open, which is fine for dup2).
        self.entries.remove(&new_fd.0);

        self.entries.insert(
            new_fd.0,
            FileDescriptor {
                kind,
                flags: FdFlags::default(),
            },
        );

        Ok(new_fd)
    }

    // -----------------------------------------------------------------------
    // Fork / spawn
    // -----------------------------------------------------------------------

    /// Clones this table for a child process (fork / spawn semantics).
    ///
    /// All open descriptors are deep-cloned **except** those with
    /// [`FdFlags::close_on_exec`] set, which are dropped.  The child's
    /// internal cursor is set to the same value as the parent's, so the
    /// first [`open`](Self::open) call in the child continues from where the
    /// parent left off rather than re-using low fd numbers.
    ///
    /// # Example
    ///
    /// ```rust
    /// use nexacore_kernel::fd::{FdFlags, FdKind, FileDescriptor, FileDescriptorTable, RawFd};
    ///
    /// let mut parent = FileDescriptorTable::new_with_stdio();
    /// // Add a cloexec descriptor.
    /// let _ = parent.open(FileDescriptor {
    ///     kind: FdKind::IpcChannel(42),
    ///     flags: FdFlags {
    ///         close_on_exec: true,
    ///         non_block: false,
    ///     },
    /// });
    ///
    /// let child = parent.clone_for_child();
    /// // stdio is present in the child.
    /// assert!(child.get(RawFd(0)).is_some());
    /// // The cloexec fd is gone.
    /// assert!(child.get(RawFd(3)).is_none());
    /// ```
    #[must_use]
    pub fn clone_for_child(&self) -> Self {
        let entries = self
            .entries
            .iter()
            .filter(|(_, desc)| !desc.flags.close_on_exec)
            .map(|(&k, v)| (k, v.clone()))
            .collect();

        Self {
            entries,
            next_fd: self.next_fd,
        }
    }

    // -----------------------------------------------------------------------
    // Iteration
    // -----------------------------------------------------------------------

    /// Returns an iterator over all open `(RawFd, &FileDescriptor)` pairs,
    /// in ascending fd order.
    ///
    /// # Example
    ///
    /// ```rust
    /// use nexacore_kernel::fd::{FileDescriptorTable, RawFd};
    ///
    /// let table = FileDescriptorTable::new_with_stdio();
    /// let fds: Vec<_> = table.iter().map(|(fd, _)| fd).collect();
    /// assert_eq!(fds, vec![RawFd(0), RawFd(1), RawFd(2)]);
    /// ```
    pub fn iter(&self) -> impl Iterator<Item = (RawFd, &FileDescriptor)> {
        self.entries.iter().map(|(&k, v)| (RawFd(k), v))
    }
}

// Implement Default by delegating to new() so that #[derive(Default)] on
// types containing FileDescriptorTable works without an extra impl block.
impl Default for FileDescriptorTable {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // Helper: a plain writable console descriptor with no special flags.
    fn console_write() -> FileDescriptor {
        FileDescriptor {
            kind: FdKind::Console {
                readable: false,
                writable: true,
            },
            flags: FdFlags::default(),
        }
    }

    // Helper: a readable console descriptor.
    fn console_read() -> FileDescriptor {
        FileDescriptor {
            kind: FdKind::Console {
                readable: true,
                writable: false,
            },
            flags: FdFlags::default(),
        }
    }

    // -----------------------------------------------------------------------
    // new()
    // -----------------------------------------------------------------------

    #[test]
    fn new_creates_empty_table() {
        let table = FileDescriptorTable::new();
        assert_eq!(table.iter().count(), 0);
    }

    // -----------------------------------------------------------------------
    // new_with_stdio()
    // -----------------------------------------------------------------------

    #[test]
    fn new_with_stdio_has_fd_0_1_2() {
        let table = FileDescriptorTable::new_with_stdio();

        // fd 0 — stdin (readable, not writable)
        let fd0 = table.get(RawFd(0)).expect("fd 0 must exist");
        if let FdKind::Console { readable, writable } = fd0.kind {
            assert!(readable, "fd 0 must be readable");
            assert!(!writable, "fd 0 must not be writable");
        } else {
            panic!("fd 0 kind must be Console");
        }

        // fd 1 — stdout (writable, not readable)
        let fd1 = table.get(RawFd(1)).expect("fd 1 must exist");
        if let FdKind::Console { readable, writable } = fd1.kind {
            assert!(!readable, "fd 1 must not be readable");
            assert!(writable, "fd 1 must be writable");
        } else {
            panic!("fd 1 kind must be Console");
        }

        // fd 2 — stderr (same shape as stdout)
        let fd2 = table.get(RawFd(2)).expect("fd 2 must exist");
        if let FdKind::Console { readable, writable } = fd2.kind {
            assert!(!readable, "fd 2 must not be readable");
            assert!(writable, "fd 2 must be writable");
        } else {
            panic!("fd 2 kind must be Console");
        }

        // No fd 3 yet
        assert!(table.get(RawFd(3)).is_none());

        // Exactly three entries
        assert_eq!(table.iter().count(), 3);
    }

    // -----------------------------------------------------------------------
    // open() / close() — basic
    // -----------------------------------------------------------------------

    #[test]
    fn open_assigns_next_fd_and_close_removes_it() {
        let mut table = FileDescriptorTable::new();
        let fd = table.open(console_write()).expect("open must succeed");
        assert_eq!(fd, RawFd(0));
        assert!(table.get(fd).is_some());

        table.close(fd).expect("close must succeed");
        assert!(table.get(fd).is_none());
    }

    #[test]
    fn open_assigns_incrementing_fds() {
        let mut table = FileDescriptorTable::new();
        let fd0 = table.open(console_write()).expect("first open");
        let fd1 = table.open(console_write()).expect("second open");
        let fd2 = table.open(console_write()).expect("third open");
        assert_eq!(fd0, RawFd(0));
        assert_eq!(fd1, RawFd(1));
        assert_eq!(fd2, RawFd(2));
    }

    // -----------------------------------------------------------------------
    // close() error cases
    // -----------------------------------------------------------------------

    #[test]
    fn close_nonexistent_fd_returns_invalid_argument() {
        let mut table = FileDescriptorTable::new();
        let result = table.close(RawFd(99));
        assert_eq!(result, Err(KernelError::InvalidArgument));
    }

    #[test]
    fn double_close_returns_invalid_argument() {
        let mut table = FileDescriptorTable::new_with_stdio();
        table.close(RawFd(0)).expect("first close must succeed");
        let result = table.close(RawFd(0));
        assert_eq!(result, Err(KernelError::InvalidArgument));
    }

    // -----------------------------------------------------------------------
    // dup()
    // -----------------------------------------------------------------------

    #[test]
    fn dup_creates_new_fd_with_same_kind() {
        let mut table = FileDescriptorTable::new_with_stdio();
        // dup stdout (fd 1) — should land at fd 3 (next after stdio)
        let new_fd = table.dup(RawFd(1)).expect("dup must succeed");
        assert!(new_fd.0 >= 3, "dup result must be above the stdio range");
        let desc = table.get(new_fd).expect("dup result must be accessible");
        if let FdKind::Console { readable, writable } = desc.kind {
            assert!(!readable);
            assert!(writable);
        } else {
            panic!("dup result kind must match source");
        }
        // FD_CLOEXEC must be cleared on the duplicate
        assert!(!desc.flags.close_on_exec);
    }

    #[test]
    fn dup_nonexistent_fd_returns_invalid_argument() {
        let mut table = FileDescriptorTable::new();
        let result = table.dup(RawFd(42));
        assert_eq!(result, Err(KernelError::InvalidArgument));
    }

    // -----------------------------------------------------------------------
    // dup2()
    // -----------------------------------------------------------------------

    #[test]
    fn dup2_with_open_target_closes_target_first() {
        let mut table = FileDescriptorTable::new_with_stdio();
        // Redirect stderr (fd 2) to be a copy of stdin (fd 0).
        let result = table.dup2(RawFd(0), RawFd(2));
        assert_eq!(result, Ok(RawFd(2)));
        // fd 2 must now be readable (like fd 0 / stdin).
        let desc = table.get(RawFd(2)).expect("fd 2 must exist after dup2");
        if let FdKind::Console { readable, writable } = desc.kind {
            assert!(readable, "fd 2 must be readable after dup2 from fd 0");
            assert!(!writable, "fd 2 must not be writable after dup2 from fd 0");
        } else {
            panic!("fd 2 kind must be Console after dup2");
        }
    }

    #[test]
    fn dup2_to_same_fd_is_noop() {
        let mut table = FileDescriptorTable::new_with_stdio();
        // dup2(1, 1) must succeed and leave the table unchanged.
        let result = table.dup2(RawFd(1), RawFd(1));
        assert_eq!(result, Ok(RawFd(1)));
        assert_eq!(table.iter().count(), 3, "entry count must be unchanged");
    }

    #[test]
    fn dup2_nonexistent_old_fd_returns_invalid_argument() {
        let mut table = FileDescriptorTable::new();
        let result = table.dup2(RawFd(99), RawFd(0));
        assert_eq!(result, Err(KernelError::InvalidArgument));
    }

    // -----------------------------------------------------------------------
    // clone_for_child()
    // -----------------------------------------------------------------------

    #[test]
    fn clone_for_child_preserves_open_fds() {
        let table = FileDescriptorTable::new_with_stdio();
        let child = table.clone_for_child();
        assert!(child.get(RawFd(0)).is_some());
        assert!(child.get(RawFd(1)).is_some());
        assert!(child.get(RawFd(2)).is_some());
        assert_eq!(child.iter().count(), 3);
    }

    #[test]
    fn clone_for_child_filters_close_on_exec() {
        let mut parent = FileDescriptorTable::new_with_stdio();
        // Add a cloexec IPC channel fd.
        let cloexec_fd = parent
            .open(FileDescriptor {
                kind: FdKind::IpcChannel(42),
                flags: FdFlags {
                    close_on_exec: true,
                    non_block: false,
                },
            })
            .expect("open cloexec fd");

        let child = parent.clone_for_child();

        // stdio must be inherited
        assert!(child.get(RawFd(0)).is_some());
        assert!(child.get(RawFd(1)).is_some());
        assert!(child.get(RawFd(2)).is_some());

        // The cloexec fd must be absent
        assert!(
            child.get(cloexec_fd).is_none(),
            "cloexec fd must not be in child"
        );
        assert_eq!(child.iter().count(), 3);
    }

    // -----------------------------------------------------------------------
    // next_fd skips occupied slots
    // -----------------------------------------------------------------------

    #[test]
    fn open_skips_occupied_slot_after_dup2() {
        let mut table = FileDescriptorTable::new();

        // Open fd 0 normally.
        let fd0 = table.open(console_write()).expect("open fd 0");
        assert_eq!(fd0, RawFd(0));

        // Force fd 1 via dup2 (cursor is at 1, but dup2 sets the target directly).
        table.dup2(RawFd(0), RawFd(1)).expect("dup2 to occupy fd 1");

        // The cursor is still at 1 (dup2 does not advance next_fd).
        // open() must scan past fd 1 and land on fd 2.
        let fd_next = table.open(console_read()).expect("open after dup2 gap");
        assert_eq!(
            fd_next,
            RawFd(2),
            "open must skip the dup2-occupied slot and return the next free fd"
        );
    }

    // -----------------------------------------------------------------------
    // Overflow protection
    // -----------------------------------------------------------------------

    #[test]
    fn open_returns_resource_exhausted_when_no_slot_available() {
        // Build a table with next_fd pinned at u32::MAX and that slot also
        // occupied, leaving no room.
        let mut table = FileDescriptorTable::new();
        // Insert a sentinel at u32::MAX directly.
        table.entries.insert(u32::MAX, console_write());
        table.next_fd = u32::MAX;

        let result = table.open(console_write());
        assert_eq!(
            result,
            Err(KernelError::ResourceExhausted),
            "open must return ResourceExhausted when all fd numbers are exhausted"
        );
    }

    // -----------------------------------------------------------------------
    // OpenFlags helpers
    // -----------------------------------------------------------------------

    #[test]
    fn open_flags_helpers_are_correct() {
        let rdonly = OpenFlags(OpenFlags::O_RDONLY);
        assert!(rdonly.is_readable());
        assert!(!rdonly.is_writable());

        let wronly = OpenFlags(OpenFlags::O_WRONLY);
        assert!(!wronly.is_readable());
        assert!(wronly.is_writable());

        let rdwr = OpenFlags(OpenFlags::O_RDWR);
        assert!(rdwr.is_readable());
        assert!(rdwr.is_writable());

        let with_creat = OpenFlags(OpenFlags::O_RDWR | OpenFlags::O_CREAT);
        assert!(with_creat.has_create());
        assert!(!with_creat.has_trunc());
        assert!(!with_creat.has_append());

        let with_append = OpenFlags(OpenFlags::O_WRONLY | OpenFlags::O_APPEND);
        assert!(with_append.has_append());
        assert!(!with_append.has_create());
        assert!(!with_append.has_trunc());
    }
}
