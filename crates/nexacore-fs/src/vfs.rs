//! Virtual filesystem layer: backend trait, mount table, path normalization
//! (WS3-02, part 1).
//!
//! `nexacore-fs` today is a single-volume service with real CRUD over an
//! in-memory or on-disk backend. To host more than one filesystem at once
//! (NCFS on `/`, a tmpfs on `/tmp`, a devfs on `/dev`) the system needs a
//! **virtual filesystem**: one namespace (`/…`) whose subtrees are served by
//! different backends, chosen by *mount point*.
//!
//! This module provides the namespace machinery that is pure, host-testable
//! logic:
//!
//! - [`VfsBackend`] — the trait every mounted filesystem implements (the file
//!   and directory operations common to all backends).
//! - [`normalize_path`] — canonicalises an absolute path into segments,
//!   resolving `.`/`..`/empty components and rejecting escapes above root.
//! - [`MountTable`] — the mount-point → backend registry, with mount / unmount
//!   and a root mount, and the path-resolution algorithm that walks it to pick
//!   the covering backend.
//! - [`AccessMode`] / [`Capability`] / [`CapabilitySet`] — the capability model
//!   guarding [`FdTable::open`]: a process may open a path only through a held
//!   capability whose subtree covers it and whose mode grants the requested
//!   access (fail-closed).
//! - [`FdTable`] — the per-process file-descriptor table: a process-local
//!   handle space (fds 0/1/2 reserved for stdio) allocating the lowest free
//!   descriptor, decoupled from other processes' tables.
//!
//! The `/dev` (devfs) and `/proc` (process introspection) mount bindings are
//! the remaining parts of WS3-02.

use alloc::{boxed::Box, collections::BTreeMap, string::String, vec::Vec};

use crate::FileType;

/// Errors from VFS namespace operations (mount table and path handling).
///
/// Distinct from [`crate::FsError`], which a *backend* returns for a failed
/// file/directory operation; a `VfsError` is about the namespace itself
/// (malformed path, mount already present, nothing mounted).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VfsError {
    /// The path does not begin with `/` (all VFS paths are absolute).
    NotAbsolute,
    /// The path uses `..` to ascend above the root.
    EscapesRoot,
    /// A path segment contains an interior NUL byte.
    InvalidSegment,
    /// A backend is already mounted at the requested mount point.
    AlreadyMounted,
    /// No backend is mounted at the requested mount point (for unmount).
    NotMounted,
}

/// Metadata a backend reports for a node.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VfsMetadata {
    /// Whether the node is a regular file, directory, or symlink.
    pub file_type: FileType,
    /// Size in bytes (0 for directories).
    pub len: u64,
}

/// A single directory entry returned by [`VfsBackend::read_dir`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VfsDirEntry {
    /// The entry's leaf name (no path separators).
    pub name: String,
    /// The entry's node type.
    pub file_type: FileType,
}

/// Error from a VFS facade operation, distinguishing a namespace failure
/// (bad path / nothing mounted) from a backend's own failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VfsResolveError {
    /// The path could not be resolved to a mounted backend.
    Namespace(VfsError),
    /// The covering backend rejected the operation.
    Backend(crate::FsError),
}

/// The outcome of resolving an absolute path against the mount table: the
/// covering backend, the mount point it was reached through, and the path
/// relative to that mount point.
pub struct Resolved<'a> {
    /// The backend serving the subtree that covers the path.
    pub backend: &'a dyn VfsBackend,
    /// The normalised mount point (segment list) the backend is mounted at.
    pub mount_point: Vec<String>,
    /// The target path relative to `mount_point` (empty at the mount point
    /// itself).
    pub relative: Vec<String>,
}

impl Resolved<'_> {
    /// Borrow the relative segments as `&str` for a [`VfsBackend`] call.
    #[must_use]
    pub fn relative_refs(&self) -> Vec<&str> {
        self.relative.iter().map(String::as_str).collect()
    }
}

/// A mounted filesystem: the file and directory operations common to every
/// backend the VFS can host.
///
/// All paths are **relative to the mount point** and pre-normalised (no `.`,
/// `..`, or empty segments); the empty slice denotes the backend's own root.
/// Backends therefore never parse `.`/`..` themselves — the VFS did it.
pub trait VfsBackend {
    /// A short, stable name for the backend kind (e.g. `"ncfs"`, `"tmpfs"`),
    /// used for introspection and diagnostics.
    fn name(&self) -> &str;

    /// Report metadata for the node at `rel`.
    ///
    /// # Errors
    ///
    /// Returns [`crate::FsError`] if the node does not exist or cannot be
    /// stat-ed.
    fn metadata(&self, rel: &[&str]) -> Result<VfsMetadata, crate::FsError>;

    /// List the directory at `rel`.
    ///
    /// # Errors
    ///
    /// Returns [`crate::FsError`] if `rel` is not a directory or does not exist.
    fn read_dir(&self, rel: &[&str]) -> Result<Vec<VfsDirEntry>, crate::FsError>;

    /// Read up to `buf.len()` bytes from the file at `rel` starting at
    /// `offset`, returning the number of bytes read.
    ///
    /// # Errors
    ///
    /// Returns [`crate::FsError`] if `rel` is not a file or does not exist.
    fn read(&self, rel: &[&str], offset: u64, buf: &mut [u8]) -> Result<usize, crate::FsError>;
}

/// Normalise an absolute path into its canonical segment list.
///
/// Resolves `.` (dropped), `..` (pops the previous segment), and empty
/// segments (collapsed, so `//a///b` → `["a", "b"]`). The root path `/`
/// normalises to the empty vector.
///
/// # Errors
///
/// - [`VfsError::NotAbsolute`] if `path` does not start with `/`.
/// - [`VfsError::EscapesRoot`] if a `..` would ascend above the root.
/// - [`VfsError::InvalidSegment`] if a segment contains an interior NUL.
pub fn normalize_path(path: &str) -> Result<Vec<String>, VfsError> {
    if !path.starts_with('/') {
        return Err(VfsError::NotAbsolute);
    }
    let mut out: Vec<String> = Vec::new();
    for segment in path.split('/') {
        match segment {
            "" | "." => {}
            ".." => {
                if out.pop().is_none() {
                    return Err(VfsError::EscapesRoot);
                }
            }
            other => {
                if other.contains('\0') {
                    return Err(VfsError::InvalidSegment);
                }
                out.push(String::from(other));
            }
        }
    }
    Ok(out)
}

/// The mount-point registry: maps a normalised mount path to the backend that
/// serves the subtree rooted there.
///
/// Keys are normalised segment lists so that the root mount is the empty key
/// and lookups are exact; the resolution algorithm (WS3-02.4) walks the keys
/// to find the longest prefix covering a target path.
#[derive(Default)]
pub struct MountTable {
    mounts: BTreeMap<Vec<String>, Box<dyn VfsBackend>>,
}

impl MountTable {
    /// Create an empty mount table (no root mounted yet).
    #[must_use]
    pub fn new() -> Self {
        Self {
            mounts: BTreeMap::new(),
        }
    }

    /// Create a mount table with `root` mounted at `/`.
    #[must_use]
    pub fn with_root(root: Box<dyn VfsBackend>) -> Self {
        let mut table = Self::new();
        // The root key is the empty segment list; insert cannot conflict on a
        // freshly-created table.
        table.mounts.insert(Vec::new(), root);
        table
    }

    /// Mount `backend` at `path`.
    ///
    /// # Errors
    ///
    /// Propagates [`normalize_path`] errors; returns
    /// [`VfsError::AlreadyMounted`] if a backend is already mounted at the
    /// (normalised) mount point.
    pub fn mount(&mut self, path: &str, backend: Box<dyn VfsBackend>) -> Result<(), VfsError> {
        let key = normalize_path(path)?;
        if self.mounts.contains_key(&key) {
            return Err(VfsError::AlreadyMounted);
        }
        self.mounts.insert(key, backend);
        Ok(())
    }

    /// Unmount the backend at `path`, returning it.
    ///
    /// # Errors
    ///
    /// Propagates [`normalize_path`] errors; returns [`VfsError::NotMounted`]
    /// if nothing is mounted at the (normalised) mount point.
    pub fn unmount(&mut self, path: &str) -> Result<Box<dyn VfsBackend>, VfsError> {
        let key = normalize_path(path)?;
        self.mounts.remove(&key).ok_or(VfsError::NotMounted)
    }

    /// Whether a backend is mounted exactly at `path`.
    ///
    /// # Errors
    ///
    /// Propagates [`normalize_path`] errors.
    pub fn is_mounted(&self, path: &str) -> Result<bool, VfsError> {
        Ok(self.mounts.contains_key(&normalize_path(path)?))
    }

    /// The number of active mounts.
    #[must_use]
    pub fn len(&self) -> usize {
        self.mounts.len()
    }

    /// Whether the table has no mounts.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.mounts.is_empty()
    }

    /// The mount points, as canonical absolute path strings, in sorted order
    /// (root reported as `/`).
    #[must_use]
    pub fn mount_points(&self) -> Vec<String> {
        self.mounts
            .keys()
            .map(|segments| {
                if segments.is_empty() {
                    String::from("/")
                } else {
                    let mut path = String::new();
                    for segment in segments {
                        path.push('/');
                        path.push_str(segment);
                    }
                    path
                }
            })
            .collect()
    }

    /// Resolve an absolute path to the backend that serves it.
    ///
    /// The covering backend is the one whose mount point is the **longest
    /// prefix** of the normalised path; the returned [`Resolved::relative`] is
    /// the remainder below that mount point. With a root mounted at `/`, every
    /// valid path resolves; without one, a path no mount covers is
    /// [`VfsError::NotMounted`].
    ///
    /// # Errors
    ///
    /// Propagates [`normalize_path`] errors; returns [`VfsError::NotMounted`]
    /// if no mount point is a prefix of the path.
    pub fn resolve(&self, path: &str) -> Result<Resolved<'_>, VfsError> {
        let segments = normalize_path(path)?;
        // Longest mount point that is a prefix of `segments`.
        let mut best: Option<&Vec<String>> = None;
        for key in self.mounts.keys() {
            let covers =
                key.len() <= segments.len() && segments.get(..key.len()) == Some(key.as_slice());
            if covers && best.is_none_or(|current| key.len() > current.len()) {
                best = Some(key);
            }
        }
        let key = best.ok_or(VfsError::NotMounted)?;
        let backend = self.mounts.get(key).ok_or(VfsError::NotMounted)?.as_ref();
        let relative = segments.get(key.len()..).unwrap_or_default().to_vec();
        Ok(Resolved {
            backend,
            mount_point: key.clone(),
            relative,
        })
    }

    /// Resolve `path` and return the covering backend's metadata for it.
    ///
    /// # Errors
    ///
    /// [`VfsResolveError::Namespace`] if the path cannot be resolved;
    /// [`VfsResolveError::Backend`] if the backend rejects the stat.
    pub fn metadata(&self, path: &str) -> Result<VfsMetadata, VfsResolveError> {
        let resolved = self.resolve(path).map_err(VfsResolveError::Namespace)?;
        let rel = resolved.relative_refs();
        resolved
            .backend
            .metadata(&rel)
            .map_err(VfsResolveError::Backend)
    }

    /// Resolve `path` and list the covering backend's directory there.
    ///
    /// # Errors
    ///
    /// [`VfsResolveError::Namespace`] if the path cannot be resolved;
    /// [`VfsResolveError::Backend`] if the backend rejects the listing.
    pub fn read_dir(&self, path: &str) -> Result<Vec<VfsDirEntry>, VfsResolveError> {
        let resolved = self.resolve(path).map_err(VfsResolveError::Namespace)?;
        let rel = resolved.relative_refs();
        resolved
            .backend
            .read_dir(&rel)
            .map_err(VfsResolveError::Backend)
    }

    /// Resolve `path` and read from the covering backend's file there.
    ///
    /// # Errors
    ///
    /// [`VfsResolveError::Namespace`] if the path cannot be resolved;
    /// [`VfsResolveError::Backend`] if the backend rejects the read.
    pub fn read(&self, path: &str, offset: u64, buf: &mut [u8]) -> Result<usize, VfsResolveError> {
        let resolved = self.resolve(path).map_err(VfsResolveError::Namespace)?;
        let rel = resolved.relative_refs();
        resolved
            .backend
            .read(&rel, offset, buf)
            .map_err(VfsResolveError::Backend)
    }
}

/// The access a process requests when opening a path, and — as a *grant* — the
/// access a [`Capability`] confers.
///
/// A grant *includes* a request when it confers every right the request needs:
/// [`AccessMode::ReadWrite`] grants both read and write, whereas a read-only
/// grant never authorises a write open. This asymmetry is why open is
/// **fail-closed** — a narrower grant can only refuse a wider request.
///
/// # Example
///
/// ```rust
/// use nexacore_fs::vfs::AccessMode;
///
/// assert!(AccessMode::ReadWrite.grants(AccessMode::Read));
/// assert!(AccessMode::ReadWrite.grants(AccessMode::Write));
/// assert!(!AccessMode::Read.grants(AccessMode::Write));
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AccessMode {
    /// Read access only.
    Read,
    /// Write access only.
    Write,
    /// Both read and write access.
    ReadWrite,
}

impl AccessMode {
    /// Whether this mode confers read access.
    #[must_use]
    pub fn can_read(self) -> bool {
        matches!(self, Self::Read | Self::ReadWrite)
    }

    /// Whether this mode confers write access.
    #[must_use]
    pub fn can_write(self) -> bool {
        matches!(self, Self::Write | Self::ReadWrite)
    }

    /// Whether a grant of `self` authorises an open requesting `requested`:
    /// every right `requested` needs must be present in `self`.
    #[must_use]
    pub fn grants(self, requested: Self) -> bool {
        (!requested.can_read() || self.can_read()) && (!requested.can_write() || self.can_write())
    }
}

/// A capability granting an [`AccessMode`] over a subtree of the namespace.
///
/// The subtree is identified by a normalised path *prefix*: a capability for
/// `/home` covers `/home` itself and everything beneath it, but nothing else.
/// The empty prefix (`/`) covers the whole namespace.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Capability {
    prefix: Vec<String>,
    mode: AccessMode,
}

impl Capability {
    /// Create a capability granting `mode` over the subtree rooted at `path`.
    ///
    /// # Errors
    ///
    /// Propagates [`normalize_path`] errors (`path` must be absolute and must
    /// not escape the root).
    pub fn new(path: &str, mode: AccessMode) -> Result<Self, VfsError> {
        Ok(Self {
            prefix: normalize_path(path)?,
            mode,
        })
    }

    /// The granted access mode.
    #[must_use]
    pub fn mode(&self) -> AccessMode {
        self.mode
    }

    /// The normalised subtree prefix this capability covers (empty = `/`).
    #[must_use]
    pub fn prefix(&self) -> &[String] {
        &self.prefix
    }

    /// Whether this capability's subtree covers the normalised `target` path.
    #[must_use]
    fn covers(&self, target: &[String]) -> bool {
        self.prefix.len() <= target.len()
            && target.get(..self.prefix.len()) == Some(self.prefix.as_slice())
    }
}

/// The set of capabilities a process holds, consulted at open time.
///
/// An open is permitted only if **some** held capability both covers the target
/// path and grants the requested [`AccessMode`]; an empty set permits nothing
/// (deny-by-default).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CapabilitySet {
    grants: Vec<Capability>,
}

impl CapabilitySet {
    /// Create an empty capability set (grants no access).
    #[must_use]
    pub fn new() -> Self {
        Self { grants: Vec::new() }
    }

    /// Add a capability to the set.
    pub fn grant(&mut self, capability: Capability) {
        self.grants.push(capability);
    }

    /// The number of held capabilities.
    #[must_use]
    pub fn len(&self) -> usize {
        self.grants.len()
    }

    /// Whether the set holds no capabilities (and so grants nothing).
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.grants.is_empty()
    }

    /// Whether opening the normalised `target` path with `requested` access is
    /// authorised: fail-closed — at least one held capability must cover the
    /// path with a mode that grants the request.
    #[must_use]
    pub fn permits(&self, target: &[String], requested: AccessMode) -> bool {
        self.grants
            .iter()
            .any(|capability| capability.covers(target) && capability.mode.grants(requested))
    }
}

/// An error from a file-descriptor operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FdError {
    /// The path could not be normalised (see [`VfsError`]).
    Namespace(VfsError),
    /// No held capability authorises the requested access to the path.
    PermissionDenied,
    /// The descriptor is not open in this table.
    BadFd,
}

/// An open file description: the target path, the access it was opened with,
/// and the current byte cursor.
///
/// The description stores the canonical absolute path (not a backend borrow) so
/// the [`FdTable`] stays independent of the [`MountTable`]; the actual backend
/// is resolved from the path when the descriptor is used for I/O.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenFile {
    path: Vec<String>,
    mode: AccessMode,
    offset: u64,
}

impl OpenFile {
    /// The canonical absolute path (normalised segments) this fd refers to.
    #[must_use]
    pub fn path(&self) -> &[String] {
        &self.path
    }

    /// The access mode the fd was opened with.
    #[must_use]
    pub fn mode(&self) -> AccessMode {
        self.mode
    }

    /// The current byte offset (cursor) of the fd.
    #[must_use]
    pub fn offset(&self) -> u64 {
        self.offset
    }

    /// Set the byte offset (e.g. after a seek).
    pub fn set_offset(&mut self, offset: u64) {
        self.offset = offset;
    }

    /// Advance the byte offset by `delta`, saturating at [`u64::MAX`].
    pub fn advance(&mut self, delta: u64) {
        self.offset = self.offset.saturating_add(delta);
    }
}

/// The lowest file descriptor a table allocates; `0`, `1`, and `2` are reserved
/// for standard input, output, and error by convention.
pub const FIRST_FD: u32 = 3;

/// A process-local file-descriptor table.
///
/// Descriptors are a **per-process namespace**: each process owns its own
/// table, so fd `3` in one process is unrelated to fd `3` in another. `open`
/// allocates the lowest free descriptor at or above [`FIRST_FD`] (POSIX
/// lowest-available-fd semantics), reusing numbers freed by `close`.
///
/// # Example
///
/// ```rust
/// use nexacore_fs::vfs::{AccessMode, Capability, CapabilitySet, FdTable};
///
/// let mut caps = CapabilitySet::new();
/// caps.grant(Capability::new("/home", AccessMode::ReadWrite).unwrap());
///
/// let mut fds = FdTable::new();
/// let fd = fds
///     .open("/home/notes.txt", AccessMode::Write, &caps)
///     .unwrap();
/// assert_eq!(fd, 3); // first fd after the reserved stdio range
///
/// // A path outside every granted subtree is refused, fail-closed.
/// assert!(fds.open("/etc/passwd", AccessMode::Read, &caps).is_err());
/// ```
#[derive(Debug, Clone, Default)]
pub struct FdTable {
    open: BTreeMap<u32, OpenFile>,
}

impl FdTable {
    /// Create an empty file-descriptor table.
    #[must_use]
    pub fn new() -> Self {
        Self {
            open: BTreeMap::new(),
        }
    }

    /// The lowest free descriptor at or above [`FIRST_FD`].
    ///
    /// Keys iterate in ascending order, so walking them contiguously from
    /// [`FIRST_FD`] finds the first gap (or the value past the last key).
    fn next_fd(&self) -> u32 {
        use core::cmp::Ordering;
        let mut expected = FIRST_FD;
        for &fd in self.open.keys() {
            match fd.cmp(&expected) {
                Ordering::Equal => expected = expected.saturating_add(1),
                Ordering::Greater => break,
                Ordering::Less => {}
            }
        }
        expected
    }

    /// Open `path` with `mode`, subject to the process's capabilities, and
    /// return the newly allocated descriptor.
    ///
    /// The path is normalised, then checked against `caps` fail-closed: with no
    /// covering, mode-granting capability the open is refused and no descriptor
    /// is allocated. The cursor starts at `0`.
    ///
    /// # Errors
    ///
    /// - [`FdError::Namespace`] if `path` is not a valid absolute path.
    /// - [`FdError::PermissionDenied`] if no held capability authorises the
    ///   requested access.
    pub fn open(
        &mut self,
        path: &str,
        mode: AccessMode,
        caps: &CapabilitySet,
    ) -> Result<u32, FdError> {
        let segments = normalize_path(path).map_err(FdError::Namespace)?;
        if !caps.permits(&segments, mode) {
            return Err(FdError::PermissionDenied);
        }
        let fd = self.next_fd();
        self.open.insert(
            fd,
            OpenFile {
                path: segments,
                mode,
                offset: 0,
            },
        );
        Ok(fd)
    }

    /// Borrow the open file description for `fd`, if open.
    #[must_use]
    pub fn get(&self, fd: u32) -> Option<&OpenFile> {
        self.open.get(&fd)
    }

    /// Mutably borrow the open file description for `fd` (e.g. to advance the
    /// cursor), if open.
    pub fn get_mut(&mut self, fd: u32) -> Option<&mut OpenFile> {
        self.open.get_mut(&fd)
    }

    /// Close `fd`, freeing the descriptor for reuse.
    ///
    /// # Errors
    ///
    /// [`FdError::BadFd`] if `fd` is not open in this table.
    pub fn close(&mut self, fd: u32) -> Result<(), FdError> {
        self.open.remove(&fd).map(|_| ()).ok_or(FdError::BadFd)
    }

    /// The number of currently open descriptors.
    #[must_use]
    pub fn len(&self) -> usize {
        self.open.len()
    }

    /// Whether no descriptors are open.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.open.is_empty()
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use alloc::vec;

    use super::*;

    /// Minimal backend that only carries a name; enough to exercise the table.
    struct StubBackend {
        name: &'static str,
    }

    impl VfsBackend for StubBackend {
        fn name(&self) -> &str {
            self.name
        }
        fn metadata(&self, _rel: &[&str]) -> Result<VfsMetadata, crate::FsError> {
            Ok(VfsMetadata {
                file_type: FileType::Directory,
                len: 0,
            })
        }
        fn read_dir(&self, _rel: &[&str]) -> Result<Vec<VfsDirEntry>, crate::FsError> {
            Ok(Vec::new())
        }
        fn read(
            &self,
            _rel: &[&str],
            _offset: u64,
            _buf: &mut [u8],
        ) -> Result<usize, crate::FsError> {
            Ok(0)
        }
    }

    fn stub(name: &'static str) -> Box<dyn VfsBackend> {
        Box::new(StubBackend { name })
    }

    #[test]
    fn normalize_collapses_and_resolves() {
        assert_eq!(normalize_path("/").unwrap(), Vec::<String>::new());
        assert_eq!(normalize_path("/a/b").unwrap(), vec!["a", "b"]);
        assert_eq!(normalize_path("//a///b/").unwrap(), vec!["a", "b"]);
        assert_eq!(normalize_path("/a/./b").unwrap(), vec!["a", "b"]);
        assert_eq!(normalize_path("/a/b/../c").unwrap(), vec!["a", "c"]);
    }

    #[test]
    fn normalize_rejects_bad_paths() {
        assert_eq!(normalize_path("a/b"), Err(VfsError::NotAbsolute));
        assert_eq!(normalize_path("/.."), Err(VfsError::EscapesRoot));
        assert_eq!(normalize_path("/a/../.."), Err(VfsError::EscapesRoot));
        assert_eq!(normalize_path("/a\0b"), Err(VfsError::InvalidSegment));
    }

    #[test]
    fn root_mount_is_empty_key() {
        let table = MountTable::with_root(stub("ncfs"));
        assert_eq!(table.len(), 1);
        assert!(table.is_mounted("/").unwrap());
        assert_eq!(table.mount_points(), vec!["/"]);
    }

    #[test]
    fn mount_and_unmount_roundtrip() {
        let mut table = MountTable::with_root(stub("ncfs"));
        table.mount("/tmp", stub("tmpfs")).unwrap();
        table.mount("/dev", stub("devfs")).unwrap();
        assert_eq!(table.len(), 3);
        assert!(table.is_mounted("/tmp").unwrap());
        assert_eq!(table.mount_points(), vec!["/", "/dev", "/tmp"]);

        let removed = table.unmount("/tmp").unwrap();
        assert_eq!(removed.name(), "tmpfs");
        assert!(!table.is_mounted("/tmp").unwrap());
        assert_eq!(table.len(), 2);
    }

    #[test]
    fn mount_conflict_and_missing_unmount() {
        let mut table = MountTable::new();
        assert!(table.is_empty());
        table.mount("/data", stub("ncfs")).unwrap();
        // A non-canonical spelling of the same point still conflicts.
        assert_eq!(
            table.mount("/data/", stub("other")).unwrap_err(),
            VfsError::AlreadyMounted
        );
        // `unmount` yields `Box<dyn VfsBackend>` on success (not `Debug`), so
        // compare via `.err()` rather than `unwrap_err()`.
        assert_eq!(table.unmount("/nope").err(), Some(VfsError::NotMounted));
    }

    fn nested_table() -> MountTable {
        let mut table = MountTable::with_root(stub("ncfs"));
        table.mount("/mnt", stub("data")).unwrap();
        table.mount("/mnt/deep", stub("deep")).unwrap();
        table
    }

    #[test]
    fn resolve_picks_longest_prefix() {
        let table = nested_table();

        let deep = table.resolve("/mnt/deep/a/b").unwrap();
        assert_eq!(deep.backend.name(), "deep");
        assert_eq!(deep.mount_point, vec!["mnt", "deep"]);
        assert_eq!(deep.relative, vec!["a", "b"]);

        // /mnt/other is covered by /mnt, not /mnt/deep.
        let mid = table.resolve("/mnt/other").unwrap();
        assert_eq!(mid.backend.name(), "data");
        assert_eq!(mid.relative, vec!["other"]);

        // Anything else falls through to the root mount.
        let root = table.resolve("/etc/hosts").unwrap();
        assert_eq!(root.backend.name(), "ncfs");
        assert_eq!(root.relative, vec!["etc", "hosts"]);
    }

    #[test]
    fn resolve_at_mount_point_has_empty_relative() {
        let table = nested_table();
        let at = table.resolve("/mnt/deep").unwrap();
        assert_eq!(at.backend.name(), "deep");
        assert!(at.relative.is_empty());
        assert!(at.relative_refs().is_empty());
    }

    #[test]
    fn resolve_without_root_can_miss() {
        let mut table = MountTable::new();
        table.mount("/only", stub("x")).unwrap();
        assert_eq!(table.resolve("/only/here").unwrap().backend.name(), "x");
        // `resolve` yields `Resolved` (not `Debug`) on success; compare via
        // `.err()`.
        assert_eq!(
            table.resolve("/elsewhere").err(),
            Some(VfsError::NotMounted)
        );
    }

    #[test]
    fn facade_routes_to_backend_and_maps_errors() {
        let table = nested_table();
        // Stub metadata always reports a directory; this proves the facade
        // resolved and called through to a backend.
        assert_eq!(
            table.metadata("/mnt/deep/x").unwrap().file_type,
            FileType::Directory
        );
        assert!(table.read_dir("/mnt").unwrap().is_empty());

        // A malformed path is a namespace error, not a backend error.
        assert_eq!(
            table.metadata("relative/path").unwrap_err(),
            VfsResolveError::Namespace(VfsError::NotAbsolute)
        );
    }

    #[test]
    fn access_mode_grant_semantics() {
        // ReadWrite grants everything.
        assert!(AccessMode::ReadWrite.grants(AccessMode::Read));
        assert!(AccessMode::ReadWrite.grants(AccessMode::Write));
        assert!(AccessMode::ReadWrite.grants(AccessMode::ReadWrite));
        // Narrow grants only cover their own right.
        assert!(AccessMode::Read.grants(AccessMode::Read));
        assert!(!AccessMode::Read.grants(AccessMode::Write));
        assert!(!AccessMode::Read.grants(AccessMode::ReadWrite));
        assert!(AccessMode::Write.grants(AccessMode::Write));
        assert!(!AccessMode::Write.grants(AccessMode::Read));
    }

    #[test]
    fn capability_covers_subtree_only() {
        let cap = Capability::new("/home", AccessMode::ReadWrite).unwrap();
        assert_eq!(cap.mode(), AccessMode::ReadWrite);
        assert_eq!(cap.prefix(), &[String::from("home")]);

        let mut caps = CapabilitySet::new();
        assert!(caps.is_empty());
        caps.grant(cap);
        assert_eq!(caps.len(), 1);

        // Covered: the mount point itself and anything beneath it.
        assert!(caps.permits(&[String::from("home")], AccessMode::Read));
        assert!(caps.permits(
            &[String::from("home"), String::from("notes.txt")],
            AccessMode::Write
        ));
        // Not covered: a sibling subtree.
        assert!(!caps.permits(&[String::from("etc")], AccessMode::Read));
        // Prefix must be a *segment* prefix, not a string prefix.
        assert!(!caps.permits(&[String::from("homework")], AccessMode::Read));
    }

    #[test]
    fn capability_mode_is_enforced() {
        let mut caps = CapabilitySet::new();
        caps.grant(Capability::new("/data", AccessMode::Read).unwrap());
        let target = [String::from("data"), String::from("x")];
        assert!(caps.permits(&target, AccessMode::Read));
        // A read-only grant never authorises a write open.
        assert!(!caps.permits(&target, AccessMode::Write));
        assert!(!caps.permits(&target, AccessMode::ReadWrite));
    }

    #[test]
    fn empty_capability_set_denies_all() {
        let caps = CapabilitySet::new();
        assert!(!caps.permits(&[String::from("anything")], AccessMode::Read));
        // The whole-namespace request is likewise denied with no grants.
        assert!(!caps.permits(&[], AccessMode::Read));
    }

    #[test]
    fn root_capability_covers_whole_namespace() {
        let mut caps = CapabilitySet::new();
        caps.grant(Capability::new("/", AccessMode::Read).unwrap());
        assert!(caps.permits(&[], AccessMode::Read));
        assert!(caps.permits(
            &[String::from("etc"), String::from("hosts")],
            AccessMode::Read
        ));
        assert!(!caps.permits(&[String::from("etc")], AccessMode::Write));
    }

    fn home_rw_caps() -> CapabilitySet {
        let mut caps = CapabilitySet::new();
        caps.grant(Capability::new("/home", AccessMode::ReadWrite).unwrap());
        caps
    }

    #[test]
    fn fd_table_allocates_lowest_free_fd_from_three() {
        let caps = home_rw_caps();
        let mut fds = FdTable::new();
        assert!(fds.is_empty());

        let a = fds.open("/home/a", AccessMode::Read, &caps).unwrap();
        let b = fds.open("/home/b", AccessMode::Write, &caps).unwrap();
        let c = fds.open("/home/c", AccessMode::ReadWrite, &caps).unwrap();
        // 0/1/2 are reserved for stdio.
        assert_eq!((a, b, c), (3, 4, 5));
        assert_eq!(fds.len(), 3);

        // Closing the middle fd frees it; the next open reuses the lowest gap.
        fds.close(b).unwrap();
        let reused = fds.open("/home/d", AccessMode::Read, &caps).unwrap();
        assert_eq!(reused, 4);
        assert_eq!(fds.len(), 3);
    }

    #[test]
    fn fd_table_open_is_capability_gated() {
        let caps = home_rw_caps();
        let mut fds = FdTable::new();

        // Outside the granted subtree: denied, and no fd is allocated.
        assert_eq!(
            fds.open("/etc/passwd", AccessMode::Read, &caps)
                .unwrap_err(),
            FdError::PermissionDenied
        );
        assert!(fds.is_empty());

        // A malformed path is a namespace error, distinct from a denial.
        assert_eq!(
            fds.open("relative", AccessMode::Read, &caps).unwrap_err(),
            FdError::Namespace(VfsError::NotAbsolute)
        );

        // With no capabilities at all, even a valid path is refused.
        let mut empty_fds = FdTable::new();
        assert_eq!(
            empty_fds
                .open("/home/x", AccessMode::Read, &CapabilitySet::new())
                .unwrap_err(),
            FdError::PermissionDenied
        );
    }

    #[test]
    fn fd_table_tracks_open_file_and_cursor() {
        let caps = home_rw_caps();
        let mut fds = FdTable::new();
        let fd = fds
            .open("/home/./sub/../file", AccessMode::Write, &caps)
            .unwrap();

        let open = fds.get(fd).unwrap();
        // The stored path is normalised.
        assert_eq!(open.path(), &[String::from("home"), String::from("file")]);
        assert_eq!(open.mode(), AccessMode::Write);
        assert_eq!(open.offset(), 0);

        // The cursor advances and seeks via the mutable handle.
        let open = fds.get_mut(fd).unwrap();
        open.advance(10);
        open.advance(5);
        assert_eq!(open.offset(), 15);
        open.set_offset(2);
        assert_eq!(open.offset(), 2);
    }

    #[test]
    fn fd_table_close_rejects_bad_fd() {
        let mut fds = FdTable::new();
        assert_eq!(fds.close(3).unwrap_err(), FdError::BadFd);
        assert!(fds.get(99).is_none());
    }

    #[test]
    fn fd_tables_are_independent_namespaces() {
        let caps = home_rw_caps();
        let mut proc_a = FdTable::new();
        let mut proc_b = FdTable::new();

        let a = proc_a.open("/home/a", AccessMode::Read, &caps).unwrap();
        let b = proc_b.open("/home/b", AccessMode::Read, &caps).unwrap();
        // Both processes independently allocate the same first descriptor.
        assert_eq!(a, b);
        assert_eq!(a, FIRST_FD);
        // fd 3 in A refers to A's file, not B's.
        assert_eq!(
            proc_a.get(a).unwrap().path(),
            &[String::from("home"), String::from("a")]
        );
        assert_eq!(
            proc_b.get(b).unwrap().path(),
            &[String::from("home"), String::from("b")]
        );
    }
}
