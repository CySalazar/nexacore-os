//! Kernel pipe — unidirectional byte-stream IPC.
//!
//! ## Design
//!
//! Each pipe is a fixed-capacity ring buffer ([`crate::pipe::PipeRing`])
//! identified by a [`crate::pipe::PipeId`]. The buffer is backed by
//! [`alloc::collections::VecDeque<u8>`] so allocation is deferred to first
//! use and not charged at kernel-init time.
//!
//! **Capacity:** 64 KiB per pipe ([`crate::pipe::PIPE_CAPACITY`]).
//!
//! **Blocking contract (kernel-level):**
//! - A [`crate::pipe::PipeRing::write`] that finds the buffer full returns
//!   `Ok(0)`. The caller must call [`crate::pipe::PipeRing::park_writer`] and
//!   yield the CPU; the scheduler will wake it after a reader drains space.
//! - A [`crate::pipe::PipeRing::read`] that finds the buffer empty AND the
//!   write end still open returns `Ok(0)`. The caller must call
//!   [`crate::pipe::PipeRing::park_reader`] and yield; the scheduler wakes it
//!   after a writer pushes data.
//! - A [`crate::pipe::PipeRing::read`] on an empty buffer whose write end is
//!   closed returns `Ok(0)` — EOF signal.
//!
//! Wait-queue management is intentionally separated from the ring-buffer
//! logic so the kernel scheduler can remain the sole authority over which
//! tasks are parked and runnable.
//!
//! ## Registry
//!
//! [`crate::pipe::PipeRegistry`] is the global table mapping
//! [`crate::pipe::PipeId`] → [`crate::pipe::PipeRing`].
//! The kernel holds a single registry instance in a static. Pipe IDs are
//! monotonically incrementing u64 values; they are never recycled within a
//! boot session to avoid PID/FD-aliasing bugs at the capability layer.

use alloc::{
    collections::{BTreeMap, VecDeque},
    vec::Vec,
};

use crate::scheduling::TaskId;

// ---------------------------------------------------------------------------
// Capacity
// ---------------------------------------------------------------------------

/// Maximum number of bytes a single pipe can buffer.
///
/// 64 KiB matches the traditional POSIX pipe buffer size (Linux default).
/// Raising this constant widens the per-pipe allocation but does not
/// change the ABI.
pub const PIPE_CAPACITY: usize = 65536;

// ---------------------------------------------------------------------------
// PipeId
// ---------------------------------------------------------------------------

/// Unique, monotonically-increasing identifier for a pipe.
///
/// Allocated by [`PipeRegistry::create`]. IDs are never reused within a
/// boot session to prevent aliasing between closed and newly-created pipes
/// at the file-descriptor layer.
///
/// # Examples
///
/// ```
/// use nexacore_kernel::pipe::PipeId;
/// let id = PipeId(42);
/// assert_eq!(id.0, 42);
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct PipeId(pub u64);

// ---------------------------------------------------------------------------
// PipeError
// ---------------------------------------------------------------------------

/// Error type for pipe operations.
///
/// # Examples
///
/// ```
/// use nexacore_kernel::pipe::{PipeError, PipeRing};
/// let mut ring = PipeRing::new();
/// // Close the read end to provoke a broken-pipe error.
/// let _ = ring.close_read();
/// assert_eq!(ring.write(b"hello"), Err(PipeError::BrokenPipe));
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PipeError {
    /// Write was issued to a pipe whose read end has already been closed.
    ///
    /// Maps to POSIX `EPIPE` (errno 32). The kernel should deliver
    /// `SIGPIPE` to POSIX processes and return `EPIPE` from the
    /// write syscall.
    BrokenPipe,
}

// ---------------------------------------------------------------------------
// PipeRing
// ---------------------------------------------------------------------------

/// Unidirectional byte-stream ring buffer.
///
/// The kernel creates one `PipeRing` per [`PipeId`] via [`PipeRegistry::create`].
/// Each pipe has two logical ends: a write end (producer) and a read end
/// (consumer). Both ends are tracked by boolean flags; closing an end wakes
/// any tasks waiting on the opposite end.
///
/// ## Thread-safety
///
/// `PipeRing` is **not** `Sync`. Concurrent access must be mediated by the
/// kernel's global scheduler lock or a spinlock wrapping the registry entry.
///
/// ## Examples
///
/// ```
/// use nexacore_kernel::pipe::PipeRing;
/// let mut ring = PipeRing::new();
/// let written = ring.write(b"hello").unwrap();
/// assert_eq!(written, 5);
/// let mut buf = [0u8; 8];
/// let n = ring.read(&mut buf).unwrap();
/// assert_eq!(n, 5);
/// assert_eq!(&buf[..n], b"hello");
/// ```
#[derive(Debug)]
pub struct PipeRing {
    /// Byte storage. `VecDeque` gives O(1) push-back and pop-front.
    buffer: VecDeque<u8>,
    /// Maximum bytes the buffer may hold.
    capacity: usize,
    /// Whether the write end is still open.
    write_end_open: bool,
    /// Whether the read end is still open.
    read_end_open: bool,
    /// Tasks blocked waiting for data to become available (empty-pipe readers).
    waiters_read: VecDeque<TaskId>,
    /// Tasks blocked waiting for space to become available (full-pipe writers).
    waiters_write: VecDeque<TaskId>,
}

impl PipeRing {
    /// Construct a new, empty pipe ring with the default [`PIPE_CAPACITY`].
    ///
    /// Both ends start open and the wait queues are empty.
    ///
    /// # Examples
    ///
    /// ```
    /// use nexacore_kernel::pipe::PipeRing;
    /// let ring = PipeRing::new();
    /// assert!(ring.is_empty());
    /// assert!(ring.write_end_open());
    /// assert!(ring.read_end_open());
    /// ```
    #[must_use]
    pub fn new() -> Self {
        Self {
            buffer: VecDeque::new(),
            capacity: PIPE_CAPACITY,
            write_end_open: true,
            read_end_open: true,
            waiters_read: VecDeque::new(),
            waiters_write: VecDeque::new(),
        }
    }

    /// Write `data` bytes into the pipe buffer.
    ///
    /// Returns the number of bytes actually written. This may be less than
    /// `data.len()` if the buffer fills up before all bytes are consumed
    /// (partial write). The caller is responsible for re-submitting any
    /// unwritten tail.
    ///
    /// Returns `Ok(0)` when the buffer is already full and the read end is
    /// still open — the caller must park via [`Self::park_writer`] and
    /// reschedule.
    ///
    /// # Errors
    ///
    /// Returns `Err(PipeError::BrokenPipe)` when the read end has been
    /// closed; further writes are permanently impossible.
    ///
    /// # Examples
    ///
    /// ```
    /// use nexacore_kernel::pipe::PipeRing;
    /// let mut ring = PipeRing::new();
    /// assert_eq!(ring.write(b"hi").unwrap(), 2);
    /// ```
    pub fn write(&mut self, data: &[u8]) -> Result<usize, PipeError> {
        // Broken pipe: read end gone, no point buffering.
        if !self.read_end_open {
            return Err(PipeError::BrokenPipe);
        }

        if data.is_empty() {
            return Ok(0);
        }

        // How many bytes can we accept right now?
        let available = self.capacity.saturating_sub(self.buffer.len());
        if available == 0 {
            // Buffer full — caller must block.
            return Ok(0);
        }

        let to_write = data.len().min(available);
        // Use get() to avoid a slice index that could theoretically panic;
        // to_write <= available <= capacity so the get always returns Some,
        // but we fall back to the full slice to satisfy the lint.
        let chunk = data.get(..to_write).unwrap_or(data);
        self.buffer.extend(chunk);
        Ok(to_write)
    }

    /// Read up to `buf.len()` bytes from the pipe buffer.
    ///
    /// Returns the number of bytes placed into `buf`.
    ///
    /// Returns `Ok(0)` in two distinct cases:
    /// 1. The buffer is empty and the write end is still open — caller must
    ///    park via [`Self::park_reader`] and reschedule.
    /// 2. The buffer is empty and the write end is closed — EOF; no more
    ///    data will ever arrive.
    ///
    /// Callers distinguish case 1 from case 2 by checking
    /// [`Self::write_end_open`] after a zero-byte read.
    ///
    /// # Errors
    ///
    /// This function currently never returns `Err`. The `Result` wrapper is
    /// retained for API symmetry with [`Self::write`] so that future error
    /// variants (e.g. a broken-pipe read from a half-closed end) can be added
    /// without a breaking API change.
    ///
    /// # Examples
    ///
    /// ```
    /// use nexacore_kernel::pipe::PipeRing;
    /// let mut ring = PipeRing::new();
    /// ring.write(b"abc").unwrap();
    /// let mut buf = [0u8; 3];
    /// assert_eq!(ring.read(&mut buf).unwrap(), 3);
    /// assert_eq!(&buf, b"abc");
    /// ```
    // The Result wrapper is kept intentionally for future error variants.
    // Clippy flags this as unnecessary but the symmetry with `write` and the
    // planned future-error path justify it.
    #[allow(
        clippy::unnecessary_wraps,
        reason = "Result retained for API symmetry with write(); future error variants expected"
    )]
    pub fn read(&mut self, buf: &mut [u8]) -> Result<usize, PipeError> {
        if buf.is_empty() || self.buffer.is_empty() {
            return Ok(0);
        }

        let to_read = buf.len().min(self.buffer.len());
        // get_mut avoids a potentially-panicking slice index; to_read is
        // bounded by buf.len() so the get always returns Some.
        if let Some(dest) = buf.get_mut(..to_read) {
            for (slot, byte) in dest.iter_mut().zip(self.buffer.drain(..to_read)) {
                *slot = byte;
            }
        }
        Ok(to_read)
    }

    /// Close the write end of the pipe.
    ///
    /// Sets [`Self::write_end_open`] to `false` and drains all parked reader
    /// tasks from the wait queue, returning them so the caller (the kernel
    /// scheduler) can wake them. The readers will observe EOF on their next
    /// [`Self::read`] call if the buffer is empty.
    ///
    /// # Examples
    ///
    /// ```
    /// use nexacore_kernel::{pipe::PipeRing, scheduling::TaskId};
    /// let mut ring = PipeRing::new();
    /// ring.park_reader(TaskId(1));
    /// let woken = ring.close_write();
    /// assert_eq!(woken, vec![TaskId(1)]);
    /// assert!(!ring.write_end_open());
    /// ```
    pub fn close_write(&mut self) -> Vec<TaskId> {
        self.write_end_open = false;
        self.drain_read_waiters()
    }

    /// Close the read end of the pipe.
    ///
    /// Sets [`Self::read_end_open`] to `false` and drains all parked writer
    /// tasks, returning them so the scheduler can wake them. Those writers
    /// will receive `Err(PipeError::BrokenPipe)` on their next
    /// [`Self::write`] call.
    ///
    /// # Examples
    ///
    /// ```
    /// use nexacore_kernel::{pipe::PipeRing, scheduling::TaskId};
    /// let mut ring = PipeRing::new();
    /// ring.park_writer(TaskId(7));
    /// let woken = ring.close_read();
    /// assert_eq!(woken, vec![TaskId(7)]);
    /// assert!(!ring.read_end_open());
    /// ```
    pub fn close_read(&mut self) -> Vec<TaskId> {
        self.read_end_open = false;
        self.drain_write_waiters()
    }

    /// Park a reader task that found the buffer empty.
    ///
    /// The task will be returned by the next call to
    /// [`Self::drain_read_waiters`] (after data is written) or by
    /// [`Self::close_write`] (signaling EOF).
    ///
    /// # Examples
    ///
    /// ```
    /// use nexacore_kernel::{pipe::PipeRing, scheduling::TaskId};
    /// let mut ring = PipeRing::new();
    /// ring.park_reader(TaskId(3));
    /// let woken = ring.drain_read_waiters();
    /// assert_eq!(woken, vec![TaskId(3)]);
    /// ```
    pub fn park_reader(&mut self, task: TaskId) {
        self.waiters_read.push_back(task);
    }

    /// Park a writer task that found the buffer full.
    ///
    /// The task will be returned by the next call to
    /// [`Self::drain_write_waiters`] (after data is read) or by
    /// [`Self::close_read`] (signaling broken pipe).
    ///
    /// # Examples
    ///
    /// ```
    /// use nexacore_kernel::{pipe::PipeRing, scheduling::TaskId};
    /// let mut ring = PipeRing::new();
    /// ring.park_writer(TaskId(5));
    /// let woken = ring.drain_write_waiters();
    /// assert_eq!(woken, vec![TaskId(5)]);
    /// ```
    pub fn park_writer(&mut self, task: TaskId) {
        self.waiters_write.push_back(task);
    }

    /// Drain and return all tasks waiting to read.
    ///
    /// Called by the kernel after a successful [`Self::write`] so any
    /// blocked readers can be rescheduled.
    ///
    /// # Examples
    ///
    /// ```
    /// use nexacore_kernel::{pipe::PipeRing, scheduling::TaskId};
    /// let mut ring = PipeRing::new();
    /// ring.park_reader(TaskId(1));
    /// ring.park_reader(TaskId(2));
    /// let woken = ring.drain_read_waiters();
    /// assert_eq!(woken.len(), 2);
    /// assert!(ring.drain_read_waiters().is_empty());
    /// ```
    pub fn drain_read_waiters(&mut self) -> Vec<TaskId> {
        self.waiters_read.drain(..).collect()
    }

    /// Drain and return all tasks waiting to write.
    ///
    /// Called by the kernel after a successful [`Self::read`] so any
    /// blocked writers can be rescheduled.
    ///
    /// # Examples
    ///
    /// ```
    /// use nexacore_kernel::{pipe::PipeRing, scheduling::TaskId};
    /// let mut ring = PipeRing::new();
    /// ring.park_writer(TaskId(9));
    /// let woken = ring.drain_write_waiters();
    /// assert_eq!(woken.len(), 1);
    /// assert!(ring.drain_write_waiters().is_empty());
    /// ```
    pub fn drain_write_waiters(&mut self) -> Vec<TaskId> {
        self.waiters_write.drain(..).collect()
    }

    /// Returns `true` when the pipe buffer holds no bytes.
    ///
    /// # Examples
    ///
    /// ```
    /// use nexacore_kernel::pipe::PipeRing;
    /// let ring = PipeRing::new();
    /// assert!(ring.is_empty());
    /// ```
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.buffer.is_empty()
    }

    /// Returns `true` when the pipe buffer is at capacity.
    ///
    /// # Examples
    ///
    /// ```
    /// use nexacore_kernel::pipe::{PIPE_CAPACITY, PipeRing};
    /// let mut ring = PipeRing::new();
    /// // Fill to exactly capacity.
    /// let filler = vec![0u8; PIPE_CAPACITY];
    /// ring.write(&filler).unwrap();
    /// assert!(ring.is_full());
    /// ```
    #[must_use]
    pub fn is_full(&self) -> bool {
        self.buffer.len() >= self.capacity
    }

    /// Returns `true` when the write end of the pipe is still open.
    ///
    /// A `false` value combined with [`Self::is_empty`] indicates EOF.
    ///
    /// # Examples
    ///
    /// ```
    /// use nexacore_kernel::pipe::PipeRing;
    /// let mut ring = PipeRing::new();
    /// assert!(ring.write_end_open());
    /// ring.close_write();
    /// assert!(!ring.write_end_open());
    /// ```
    #[must_use]
    pub fn write_end_open(&self) -> bool {
        self.write_end_open
    }

    /// Returns `true` when the read end of the pipe is still open.
    ///
    /// A `false` value means future writes will fail with
    /// [`PipeError::BrokenPipe`].
    ///
    /// # Examples
    ///
    /// ```
    /// use nexacore_kernel::pipe::PipeRing;
    /// let mut ring = PipeRing::new();
    /// assert!(ring.read_end_open());
    /// ring.close_read();
    /// assert!(!ring.read_end_open());
    /// ```
    #[must_use]
    pub fn read_end_open(&self) -> bool {
        self.read_end_open
    }

    /// Returns the number of bytes currently buffered.
    ///
    /// # Examples
    ///
    /// ```
    /// use nexacore_kernel::pipe::PipeRing;
    /// let mut ring = PipeRing::new();
    /// ring.write(b"xyz").unwrap();
    /// assert_eq!(ring.len(), 3);
    /// ```
    #[must_use]
    pub fn len(&self) -> usize {
        self.buffer.len()
    }
}

impl Default for PipeRing {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// PipeRegistry
// ---------------------------------------------------------------------------

/// Global registry mapping [`PipeId`] to [`PipeRing`] for all live pipes.
///
/// The kernel holds exactly one `PipeRegistry` instance. Pipe IDs are issued
/// by [`Self::create`] and are never reused, making stale-FD aliasing
/// detectable at the capability layer.
///
/// ## Examples
///
/// ```
/// use nexacore_kernel::pipe::PipeRegistry;
/// let mut reg = PipeRegistry::new();
/// let id = reg.create();
/// assert!(reg.get(id).is_some());
/// assert!(reg.remove(id));
/// assert!(reg.get(id).is_none());
/// ```
#[derive(Debug)]
pub struct PipeRegistry {
    /// Active pipes keyed by their numeric ID.
    pipes: BTreeMap<u64, PipeRing>,
    /// Monotonic counter for the next pipe ID to issue.
    next_id: u64,
}

impl PipeRegistry {
    /// Construct an empty registry.
    ///
    /// Not `const fn` because `BTreeMap::new()` is not const-stable in
    /// Rust 2024. Callers initialising a static must use
    /// `static mut` + `Option<PipeRegistry>` with lazy init, or a
    /// spinlock-wrapped `Option`.
    ///
    /// # Examples
    ///
    /// ```
    /// use nexacore_kernel::pipe::PipeRegistry;
    /// let reg = PipeRegistry::new();
    /// ```
    #[must_use]
    pub fn new() -> Self {
        Self {
            pipes: BTreeMap::new(),
            next_id: 1,
        }
    }

    /// Allocate a new pipe, insert it into the registry, and return its
    /// [`PipeId`].
    ///
    /// The returned ID is guaranteed to be unique within this boot session.
    ///
    /// # Examples
    ///
    /// ```
    /// use nexacore_kernel::pipe::PipeRegistry;
    /// let mut reg = PipeRegistry::new();
    /// let a = reg.create();
    /// let b = reg.create();
    /// assert_ne!(a, b);
    /// assert!(reg.get(a).is_some());
    /// assert!(reg.get(b).is_some());
    /// ```
    pub fn create(&mut self) -> PipeId {
        let id = self.next_id;
        // Wrapping is acceptable in a kernel context: 2^64 pipes per boot
        // session is practically impossible. We start from 1 so that a
        // zero-initialised FD entry (pipe_id = 0) is never a valid pipe.
        self.next_id = self.next_id.wrapping_add(1);
        self.pipes.insert(id, PipeRing::new());
        PipeId(id)
    }

    /// Look up a pipe by ID, returning a shared reference if found.
    ///
    /// # Examples
    ///
    /// ```
    /// use nexacore_kernel::pipe::PipeRegistry;
    /// let mut reg = PipeRegistry::new();
    /// let id = reg.create();
    /// assert!(reg.get(id).is_some());
    /// ```
    #[must_use]
    pub fn get(&self, id: PipeId) -> Option<&PipeRing> {
        self.pipes.get(&id.0)
    }

    /// Look up a pipe by ID, returning an exclusive reference if found.
    ///
    /// # Examples
    ///
    /// ```
    /// use nexacore_kernel::pipe::PipeRegistry;
    /// let mut reg = PipeRegistry::new();
    /// let id = reg.create();
    /// reg.get_mut(id).unwrap().write(b"test").unwrap();
    /// ```
    #[must_use]
    pub fn get_mut(&mut self, id: PipeId) -> Option<&mut PipeRing> {
        self.pipes.get_mut(&id.0)
    }

    /// Remove a pipe from the registry.
    ///
    /// Returns `true` if a pipe with the given ID was present and has been
    /// removed; `false` if the ID was not found (already removed or never
    /// created).
    ///
    /// # Examples
    ///
    /// ```
    /// use nexacore_kernel::pipe::PipeRegistry;
    /// let mut reg = PipeRegistry::new();
    /// let id = reg.create();
    /// assert!(reg.remove(id));
    /// assert!(!reg.remove(id)); // idempotent on second call
    /// ```
    pub fn remove(&mut self, id: PipeId) -> bool {
        self.pipes.remove(&id.0).is_some()
    }
}

impl Default for PipeRegistry {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // ---- PipeRing basic I/O ----

    #[test]
    fn write_read_roundtrip() {
        let mut ring = PipeRing::new();
        let payload = b"hello world";
        let n = ring.write(payload).unwrap();
        assert_eq!(n, payload.len());

        let mut buf = vec![0u8; payload.len()];
        let r = ring.read(&mut buf).unwrap();
        assert_eq!(r, payload.len());
        assert_eq!(&buf, payload);
    }

    #[test]
    fn partial_read_less_than_written() {
        let mut ring = PipeRing::new();
        ring.write(b"abcde").unwrap();

        let mut buf = [0u8; 3];
        let n = ring.read(&mut buf).unwrap();
        assert_eq!(n, 3);
        assert_eq!(&buf, b"abc");
        // Remaining 2 bytes still buffered.
        assert_eq!(ring.len(), 2);
    }

    #[test]
    fn write_fills_buffer_exactly() {
        let mut ring = PipeRing::new();
        let filler = vec![0xAAu8; PIPE_CAPACITY];
        let written = ring.write(&filler).unwrap();
        assert_eq!(written, PIPE_CAPACITY);
        assert!(ring.is_full());
    }

    #[test]
    fn write_to_full_pipe_returns_zero() {
        let mut ring = PipeRing::new();
        let filler = vec![0u8; PIPE_CAPACITY];
        ring.write(&filler).unwrap();
        // Buffer is full; next write must return Ok(0).
        let n = ring.write(b"x").unwrap();
        assert_eq!(n, 0);
    }

    #[test]
    fn read_from_empty_pipe_returns_zero() {
        let mut ring = PipeRing::new();
        let mut buf = [0u8; 4];
        let n = ring.read(&mut buf).unwrap();
        assert_eq!(n, 0);
        // Write end is still open, so this is a "block" condition, not EOF.
        assert!(ring.write_end_open());
    }

    #[test]
    fn eof_write_end_closed_empty_buffer() {
        let mut ring = PipeRing::new();
        // Close write end without writing anything.
        ring.close_write();
        let mut buf = [0u8; 4];
        let n = ring.read(&mut buf).unwrap();
        // EOF: 0 bytes, write end closed.
        assert_eq!(n, 0);
        assert!(!ring.write_end_open());
    }

    #[test]
    fn write_then_close_write_then_read_returns_data_then_eof() {
        let mut ring = PipeRing::new();
        ring.write(b"data").unwrap();
        ring.close_write();

        // First read returns the buffered data.
        let mut buf = [0u8; 8];
        let n = ring.read(&mut buf).unwrap();
        assert_eq!(n, 4);
        assert_eq!(&buf[..4], b"data");

        // Second read: buffer empty + write end closed = EOF.
        let n2 = ring.read(&mut buf).unwrap();
        assert_eq!(n2, 0);
        assert!(!ring.write_end_open());
    }

    #[test]
    fn broken_pipe_read_end_closed_write_returns_error() {
        let mut ring = PipeRing::new();
        ring.close_read();
        let result = ring.write(b"hello");
        assert_eq!(result, Err(PipeError::BrokenPipe));
    }

    #[test]
    fn close_write_wakes_readers() {
        let mut ring = PipeRing::new();
        ring.park_reader(TaskId(10));
        ring.park_reader(TaskId(20));
        let woken = ring.close_write();
        assert_eq!(woken.len(), 2);
        assert!(woken.contains(&TaskId(10)));
        assert!(woken.contains(&TaskId(20)));
        // Queue is now empty.
        assert!(ring.drain_read_waiters().is_empty());
    }

    #[test]
    fn close_read_wakes_writers() {
        let mut ring = PipeRing::new();
        ring.park_writer(TaskId(30));
        ring.park_writer(TaskId(40));
        let woken = ring.close_read();
        assert_eq!(woken.len(), 2);
        assert!(woken.contains(&TaskId(30)));
        assert!(woken.contains(&TaskId(40)));
        assert!(ring.drain_write_waiters().is_empty());
    }

    #[test]
    fn park_reader_drain_read_waiters_roundtrip() {
        let mut ring = PipeRing::new();
        ring.park_reader(TaskId(1));
        ring.park_reader(TaskId(2));
        ring.park_reader(TaskId(3));
        let woken = ring.drain_read_waiters();
        assert_eq!(woken, vec![TaskId(1), TaskId(2), TaskId(3)]);
        // A second drain must return empty.
        assert!(ring.drain_read_waiters().is_empty());
    }

    #[test]
    fn park_writer_drain_write_waiters_roundtrip() {
        let mut ring = PipeRing::new();
        ring.park_writer(TaskId(100));
        let woken = ring.drain_write_waiters();
        assert_eq!(woken, vec![TaskId(100)]);
        assert!(ring.drain_write_waiters().is_empty());
    }

    // ---- PipeRegistry ----

    #[test]
    fn registry_create_get_remove() {
        let mut reg = PipeRegistry::new();
        let id = reg.create();
        assert!(reg.get(id).is_some());
        assert!(reg.remove(id));
        assert!(reg.get(id).is_none());
    }

    #[test]
    fn registry_remove_nonexistent_returns_false() {
        let mut reg = PipeRegistry::new();
        assert!(!reg.remove(PipeId(9999)));
    }

    #[test]
    fn registry_multiple_pipes_independent() {
        let mut reg = PipeRegistry::new();
        let a = reg.create();
        let b = reg.create();
        assert_ne!(a, b);

        reg.get_mut(a).unwrap().write(b"pipe-a").unwrap();
        reg.get_mut(b).unwrap().write(b"pipe-b").unwrap();

        assert_eq!(reg.get(a).unwrap().len(), 6);
        assert_eq!(reg.get(b).unwrap().len(), 6);

        // Removing one does not affect the other.
        reg.remove(a);
        assert!(reg.get(a).is_none());
        assert!(reg.get(b).is_some());
    }

    #[test]
    fn registry_ids_are_monotonically_increasing() {
        let mut reg = PipeRegistry::new();
        let ids: Vec<PipeId> = (0..5).map(|_| reg.create()).collect();
        for w in ids.windows(2) {
            let a = w.first().expect("window always has first element");
            let b = w.last().expect("window always has last element");
            assert!(a.0 < b.0, "IDs must strictly increase");
        }
    }

    // ---- Accessors ----

    #[test]
    fn is_empty_and_len_consistent() {
        let mut ring = PipeRing::new();
        assert!(ring.is_empty());
        assert_eq!(ring.len(), 0);
        ring.write(b"abc").unwrap();
        assert!(!ring.is_empty());
        assert_eq!(ring.len(), 3);
    }

    #[test]
    fn write_partial_when_near_capacity() {
        // Fill all but 3 bytes, then try to write 10 — should accept 3.
        let mut ring = PipeRing::new();
        let pre = vec![0u8; PIPE_CAPACITY - 3];
        ring.write(&pre).unwrap();
        let n = ring.write(b"1234567890").unwrap();
        assert_eq!(n, 3);
        assert!(ring.is_full());
    }
}
