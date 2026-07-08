//! Virtual filesystem layer — kernel-side filesystem operations.
//!
//! Phase 1: all operations run against an in-kernel in-memory filesystem.
//! Phase 2: proxied to the nexacore-fs userspace service via IPC.
//!
//! ## Design overview
//!
//! The VFS is structured around a flat inode table. Each inode carries its
//! type, raw data (for regular files), a child-name-to-inode-id map (for
//! directories), and a pointer back to the parent inode. Path resolution
//! always starts from the root inode (id = 1) and walks the children maps.
//!
//! ## Path semantics
//!
//! Paths must be non-empty. Absolute paths start with `/`. Relative paths
//! are resolved against a supplied `base` directory (typically the calling
//! process's cwd). Both `.` and `..` components are normalised away before
//! any inode walk occurs. Double-slashes are collapsed to single slashes.
//!
//! ## no_std compatibility
//!
//! This module uses only `alloc` types and is fully compatible with the
//! bare-metal `x86_64-unknown-none` target used by the kernel image.

use alloc::{
    collections::BTreeMap,
    string::{String, ToString},
    vec::Vec,
};

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

/// Identifies whether an inode represents a regular file or a directory.
///
/// # Example
///
/// ```rust
/// use nexacore_kernel::vfs::FileType;
///
/// let ft = FileType::RegularFile;
/// assert_eq!(ft, FileType::RegularFile);
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileType {
    /// A regular, readable/writable file.
    RegularFile,
    /// A directory that may contain child entries.
    Directory,
}

/// Metadata for a file or directory, as returned by [`InMemoryVfs::stat`].
///
/// Mirrors the subset of POSIX `struct stat` that NexaCore OS requires in
/// Phase 1. Additional fields (permissions, timestamps, link count) will
/// be added when the on-disk format lands in Phase 2.
///
/// # Example
///
/// ```rust
/// use nexacore_kernel::vfs::{FileType, InMemoryVfs};
///
/// let mut vfs = InMemoryVfs::new();
/// vfs.create_file("/hello.txt").unwrap();
/// let stat = vfs.stat("/hello.txt").unwrap();
/// assert_eq!(stat.file_type, FileType::RegularFile);
/// assert_eq!(stat.size, 0);
/// ```
#[derive(Debug, Clone)]
pub struct FileStat {
    /// Inode number identifying this file system object.
    pub inode: u64,
    /// Size of the file in bytes. Always zero for directories.
    pub size: u64,
    /// Whether this is a regular file or a directory.
    pub file_type: FileType,
}

/// A single entry in a directory listing.
///
/// Returned in a [`Vec`] by [`InMemoryVfs::list_directory`].
///
/// # Example
///
/// ```rust
/// use nexacore_kernel::vfs::{FileType, InMemoryVfs};
///
/// let mut vfs = InMemoryVfs::new();
/// vfs.create_file("/a.txt").unwrap();
/// let entries = vfs.list_directory("/").unwrap();
/// assert_eq!(entries.len(), 1);
/// assert_eq!(entries[0].name, "a.txt");
/// assert_eq!(entries[0].file_type, FileType::RegularFile);
/// ```
#[derive(Debug, Clone)]
pub struct DirEntry {
    /// The file-name component only (no leading `/`).
    pub name: String,
    /// Inode number of this entry.
    pub inode: u64,
    /// Whether the entry is a regular file or a directory.
    pub file_type: FileType,
}

/// Error variants returned by VFS operations.
///
/// All variants are deliberately coarse-grained: the kernel does not
/// expose detailed errno values to user-space in Phase 1. Richer error
/// codes are mapped at the syscall boundary.
///
/// # Example
///
/// ```rust
/// use nexacore_kernel::vfs::{InMemoryVfs, VfsError};
///
/// let vfs = InMemoryVfs::new();
/// assert_eq!(vfs.stat("/nonexistent").unwrap_err(), VfsError::NotFound);
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VfsError {
    /// The path does not name an existing file or directory.
    NotFound,
    /// The path names an entry that already exists (e.g. duplicate create).
    AlreadyExists,
    /// A directory was expected but a regular file was found.
    NotADirectory,
    /// A regular file was expected but a directory was found.
    IsADirectory,
    /// A directory delete was attempted but the directory is not empty.
    NotEmpty,
    /// The supplied path string is syntactically invalid (e.g. empty string).
    InvalidPath,
}

// ---------------------------------------------------------------------------
// Private inode representation
// ---------------------------------------------------------------------------

/// An in-memory inode for either a regular file or a directory.
///
/// The `data` field is only meaningful for regular files; for directories
/// it is always empty. The `children` map is only populated for directories.
#[derive(Debug, Clone)]
struct Inode {
    /// Unique inode identifier, stable for the lifetime of the filesystem.
    id: u64,
    /// The last path component this inode was created under.
    ///
    /// For the root inode this is `"/"`.  For all others it is the bare
    /// name without any `/` prefix.  This field is informational — the
    /// canonical name mapping lives in the parent's `children` map.  It is
    /// intentionally kept for Phase 2 debug tooling (`/proc`-style inode
    /// inspection) even though Phase 1 does not read it.
    #[allow(dead_code, reason = "reserved for Phase 2 inode inspection tooling")]
    name: String,
    /// Whether this inode is a file or a directory.
    file_type: FileType,
    /// Raw byte content. Non-empty only for regular files.
    data: Vec<u8>,
    /// Maps child bare names to child inode ids. Non-empty only for directories.
    children: BTreeMap<String, u64>,
    /// Inode id of the parent directory, or `None` for the root.
    parent: Option<u64>,
}

// ---------------------------------------------------------------------------
// InMemoryVfs
// ---------------------------------------------------------------------------

/// In-kernel, in-memory virtual filesystem.
///
/// All data is stored in a flat `BTreeMap<u64, Inode>`. The root directory
/// always lives at inode id 1. New inodes receive monotonically increasing
/// ids starting from 2.
///
/// This implementation is the Phase 1 backing store. In Phase 2 it will be
/// replaced by a proxy that forwards operations to the `nexacore-fs` userspace
/// service via the kernel IPC layer.
///
/// # Thread safety
///
/// `InMemoryVfs` is not `Sync`. In the bare-metal kernel it must live behind
/// a spinlock (same pattern as `ProcessTable`). In host-side tests each test
/// owns its own local instance.
///
/// # Example
///
/// ```rust
/// use nexacore_kernel::vfs::InMemoryVfs;
///
/// let mut vfs = InMemoryVfs::new();
/// vfs.create_file("/hello.txt").unwrap();
/// assert!(vfs.exists("/hello.txt"));
/// ```
#[derive(Debug)]
pub struct InMemoryVfs {
    /// Flat inode store keyed by inode id.
    inodes: BTreeMap<u64, Inode>,
    /// Next inode id to assign. Starts at 2; root occupies id 1.
    next_inode: u64,
}

impl InMemoryVfs {
    /// Creates a new, empty filesystem with only the root directory present.
    ///
    /// The root directory is assigned inode id 1 and represents the path `"/"`.
    ///
    /// # Example
    ///
    /// ```rust
    /// use nexacore_kernel::vfs::{FileType, InMemoryVfs};
    ///
    /// let vfs = InMemoryVfs::new();
    /// let stat = vfs.stat("/").unwrap();
    /// assert_eq!(stat.inode, 1);
    /// assert_eq!(stat.file_type, FileType::Directory);
    /// ```
    #[must_use]
    pub fn new() -> Self {
        let mut inodes = BTreeMap::new();
        inodes.insert(
            1,
            Inode {
                id: 1,
                name: String::from("/"),
                file_type: FileType::Directory,
                data: Vec::new(),
                children: BTreeMap::new(),
                parent: None,
            },
        );
        Self {
            inodes,
            next_inode: 2,
        }
    }

    // -----------------------------------------------------------------------
    // Path utilities (public)
    // -----------------------------------------------------------------------

    /// Normalize a path, resolving `.`, `..`, and consecutive slashes.
    ///
    /// If `path` is absolute (starts with `/`) the `base` argument is
    /// ignored. Otherwise `path` is resolved relative to `base`.
    ///
    /// The returned string always starts with `/` and never has a trailing
    /// slash unless it is the root itself.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use nexacore_kernel::vfs::InMemoryVfs;
    ///
    /// // Absolute path — base is ignored.
    /// assert_eq!(InMemoryVfs::normalize_path("/", "/a/b/../c"), "/a/c");
    ///
    /// // Relative path resolved from base.
    /// assert_eq!(
    ///     InMemoryVfs::normalize_path("/home/user", "docs"),
    ///     "/home/user/docs"
    /// );
    ///
    /// // Dot and double-slash collapse.
    /// assert_eq!(InMemoryVfs::normalize_path("/", "/a//./b"), "/a/b");
    /// ```
    #[must_use]
    pub fn normalize_path(base: &str, path: &str) -> String {
        // Choose the starting point: absolute paths ignore base entirely.
        let raw = if path.starts_with('/') {
            path.to_string()
        } else {
            // Concatenate base + "/" + path.
            let mut s = String::from(base);
            if !s.ends_with('/') {
                s.push('/');
            }
            s.push_str(path);
            s
        };

        // Walk components and resolve . / ..
        let mut stack: Vec<&str> = Vec::new();
        for component in raw.split('/') {
            match component {
                // Skip empty components (from leading `/`, trailing `/`,
                // or doubled `//`) and current-dir `.`.
                "" | "." => {}
                // Parent: pop the last component when possible.
                ".." => {
                    let _ = stack.pop();
                }
                other => stack.push(other),
            }
        }

        if stack.is_empty() {
            // We resolved all the way back to root.
            String::from("/")
        } else {
            let mut result = String::new();
            for component in &stack {
                result.push('/');
                result.push_str(component);
            }
            result
        }
    }

    // -----------------------------------------------------------------------
    // Path utilities (private)
    // -----------------------------------------------------------------------

    /// Resolves an absolute path to its inode id.
    ///
    /// The path is first normalised (see [`normalize_path`]) against the root
    /// so the walk always starts from inode 1. Returns `VfsError::NotFound`
    /// if any component along the path does not exist, and
    /// `VfsError::NotADirectory` if a non-terminal component is a regular
    /// file.
    fn resolve_path(&self, path: &str) -> Result<u64, VfsError> {
        let normalized = Self::normalize_path("/", path);

        // Root is a special case: no components to walk.
        if normalized == "/" {
            return Ok(1);
        }

        let mut current_id: u64 = 1;
        // Skip the leading empty string produced by the leading `/`.
        for component in normalized.split('/').skip(1) {
            if component.is_empty() {
                continue;
            }
            let inode = self.inodes.get(&current_id).ok_or(VfsError::NotFound)?;
            // Intermediate components must be directories.
            if inode.file_type != FileType::Directory {
                return Err(VfsError::NotADirectory);
            }
            // Look up the child name in the directory's children map.
            let child_id = inode
                .children
                .get(component)
                .copied()
                .ok_or(VfsError::NotFound)?;
            current_id = child_id;
        }
        Ok(current_id)
    }

    /// Resolves the parent directory of `path` and returns `(parent_inode_id, child_name)`.
    ///
    /// The child name is the bare last component of the normalised path.
    /// Returns `VfsError::InvalidPath` if the path resolves to the root
    /// (root has no parent). Returns `VfsError::NotADirectory` if any
    /// non-terminal component names a regular file.
    ///
    /// # Panics
    ///
    /// Cannot panic: [`normalize_path`](Self::normalize_path) guarantees the
    /// returned string always starts with `'/'`, so `rfind('/')` always
    /// returns `Some`. The `expect` is a statically-provable invariant
    /// documented here to satisfy `clippy::expect_used`.
    fn resolve_parent(&self, path: &str) -> Result<(u64, String), VfsError> {
        let normalized = Self::normalize_path("/", path);

        if normalized == "/" {
            // The root has no parent; callers must not try to create/delete it
            // via this helper.
            return Err(VfsError::InvalidPath);
        }

        // Split off the last component.
        // `rfind` is guaranteed to find a '/' because normalize_path always
        // returns a string that starts with '/'. The expect message encodes
        // this invariant explicitly.
        #[allow(
            clippy::expect_used,
            reason = "normalize_path guarantees the result starts with '/', so rfind always succeeds"
        )]
        let last_slash = normalized
            .rfind('/')
            .expect("normalized path always contains '/' — invariant of normalize_path");

        let child_name = normalized[last_slash + 1..].to_string();
        if child_name.is_empty() {
            return Err(VfsError::InvalidPath);
        }

        let parent_path = if last_slash == 0 {
            // Parent is root.
            "/"
        } else {
            &normalized[..last_slash]
        };

        let parent_id = self.resolve_path(parent_path)?;

        // Verify the parent is actually a directory.
        let parent_inode = self.inodes.get(&parent_id).ok_or(VfsError::NotFound)?;
        if parent_inode.file_type != FileType::Directory {
            return Err(VfsError::NotADirectory);
        }

        Ok((parent_id, child_name))
    }

    // -----------------------------------------------------------------------
    // Create operations
    // -----------------------------------------------------------------------

    /// Create a regular file at `path`.
    ///
    /// The parent directory must already exist. Returns the new inode id on
    /// success.
    ///
    /// # Errors
    ///
    /// - [`VfsError::NotFound`] — a component of the parent path does not exist.
    /// - [`VfsError::AlreadyExists`] — an entry with the same name already exists.
    /// - [`VfsError::NotADirectory`] — a non-terminal component is a regular file.
    /// - [`VfsError::InvalidPath`] — the path is empty or is the root.
    ///
    /// # Example
    ///
    /// ```rust
    /// use nexacore_kernel::vfs::InMemoryVfs;
    ///
    /// let mut vfs = InMemoryVfs::new();
    /// let inode = vfs.create_file("/readme.md").unwrap();
    /// assert!(inode > 1, "root is inode 1; new files start at 2");
    /// ```
    pub fn create_file(&mut self, path: &str) -> Result<u64, VfsError> {
        self.create_entry(path, FileType::RegularFile)
    }

    /// Create a directory at `path`.
    ///
    /// The parent directory must already exist. Returns the new inode id on
    /// success.
    ///
    /// # Errors
    ///
    /// - [`VfsError::NotFound`] — a component of the parent path does not exist.
    /// - [`VfsError::AlreadyExists`] — an entry with the same name already exists.
    /// - [`VfsError::NotADirectory`] — a non-terminal component is a regular file.
    /// - [`VfsError::InvalidPath`] — the path is empty or is the root.
    ///
    /// # Example
    ///
    /// ```rust
    /// use nexacore_kernel::vfs::{FileType, InMemoryVfs};
    ///
    /// let mut vfs = InMemoryVfs::new();
    /// let inode = vfs.create_directory("/var").unwrap();
    /// let stat = vfs.stat("/var").unwrap();
    /// assert_eq!(stat.file_type, FileType::Directory);
    /// assert_eq!(stat.inode, inode);
    /// ```
    pub fn create_directory(&mut self, path: &str) -> Result<u64, VfsError> {
        self.create_entry(path, FileType::Directory)
    }

    /// Internal helper: create a file or directory entry.
    ///
    /// Shared by `create_file` and `create_directory` to avoid duplicated
    /// inode-id allocation and parent-children-map update logic.
    fn create_entry(&mut self, path: &str, file_type: FileType) -> Result<u64, VfsError> {
        let (parent_id, child_name) = self.resolve_parent(path)?;

        // Check that the name does not already exist under the parent.
        {
            let parent = self.inodes.get(&parent_id).ok_or(VfsError::NotFound)?;
            if parent.children.contains_key(&child_name) {
                return Err(VfsError::AlreadyExists);
            }
        }

        // Allocate a new inode id.
        let new_id = self.next_inode;
        self.next_inode = self.next_inode.saturating_add(1);

        // Insert the new inode.
        self.inodes.insert(
            new_id,
            Inode {
                id: new_id,
                name: child_name.clone(),
                file_type,
                data: Vec::new(),
                children: BTreeMap::new(),
                parent: Some(parent_id),
            },
        );

        // Link from the parent's children map.
        // Re-borrow after the inode insert so Rust does not see a
        // simultaneous mutable borrow through `self.inodes`.
        if let Some(parent) = self.inodes.get_mut(&parent_id) {
            parent.children.insert(child_name, new_id);
        }

        Ok(new_id)
    }

    // -----------------------------------------------------------------------
    // Delete
    // -----------------------------------------------------------------------

    /// Delete the file or empty directory at `path`.
    ///
    /// Attempting to delete the root (`"/"`) returns
    /// [`VfsError::InvalidPath`]. Attempting to delete a non-empty directory
    /// returns [`VfsError::NotEmpty`].
    ///
    /// # Errors
    ///
    /// - [`VfsError::NotFound`] — `path` does not exist.
    /// - [`VfsError::InvalidPath`] — `path` resolves to the root.
    /// - [`VfsError::NotEmpty`] — the target is a non-empty directory.
    ///
    /// # Panics
    ///
    /// Cannot panic: the `rfind('/')` call operates on a string produced by
    /// [`normalize_path`](Self::normalize_path), which always returns a
    /// string that starts with `'/'`. The `expect` encodes a statically
    /// provable invariant.
    ///
    /// # Example
    ///
    /// ```rust
    /// use nexacore_kernel::vfs::InMemoryVfs;
    ///
    /// let mut vfs = InMemoryVfs::new();
    /// vfs.create_file("/tmp.txt").unwrap();
    /// assert!(vfs.exists("/tmp.txt"));
    /// vfs.delete("/tmp.txt").unwrap();
    /// assert!(!vfs.exists("/tmp.txt"));
    /// ```
    pub fn delete(&mut self, path: &str) -> Result<(), VfsError> {
        // Refuse to delete root.
        let normalized = Self::normalize_path("/", path);
        if normalized == "/" {
            return Err(VfsError::InvalidPath);
        }

        let target_id = self.resolve_path(&normalized)?;

        // Check target exists and is not a non-empty directory.
        {
            let target = self.inodes.get(&target_id).ok_or(VfsError::NotFound)?;
            if target.file_type == FileType::Directory && !target.children.is_empty() {
                return Err(VfsError::NotEmpty);
            }
        }

        // Obtain the parent id so we can unlink the child.
        let parent_id = self
            .inodes
            .get(&target_id)
            .and_then(|n| n.parent)
            .ok_or(VfsError::InvalidPath)?;

        // Extract the child name from the normalised path before we mutate
        // the inode map, to avoid any borrow overlap.
        #[allow(
            clippy::expect_used,
            reason = "normalize_path guarantees the result starts with '/', so rfind always succeeds"
        )]
        let child_name: String = {
            let last_slash = normalized
                .rfind('/')
                .expect("normalized path always contains '/' — invariant of normalize_path");
            normalized[last_slash + 1..].to_string()
        };

        // Unlink from parent.
        if let Some(parent) = self.inodes.get_mut(&parent_id) {
            parent.children.remove(&child_name);
        }

        // Remove the inode itself.
        self.inodes.remove(&target_id);
        Ok(())
    }

    // -----------------------------------------------------------------------
    // Queries
    // -----------------------------------------------------------------------

    /// Return metadata for the file or directory at `path`.
    ///
    /// # Errors
    ///
    /// - [`VfsError::NotFound`] — `path` does not exist.
    ///
    /// # Example
    ///
    /// ```rust
    /// use nexacore_kernel::vfs::{FileType, InMemoryVfs};
    ///
    /// let vfs = InMemoryVfs::new();
    /// let stat = vfs.stat("/").unwrap();
    /// assert_eq!(stat.file_type, FileType::Directory);
    /// assert_eq!(stat.inode, 1);
    /// ```
    pub fn stat(&self, path: &str) -> Result<FileStat, VfsError> {
        let id = self.resolve_path(path)?;
        let inode = self.inodes.get(&id).ok_or(VfsError::NotFound)?;
        Ok(FileStat {
            inode: inode.id,
            size: inode.data.len() as u64,
            file_type: inode.file_type,
        })
    }

    /// Return the entries of the directory at `path`.
    ///
    /// Entries are returned in lexicographic order (the natural order of
    /// the `BTreeMap` children map).
    ///
    /// # Errors
    ///
    /// - [`VfsError::NotFound`] — `path` does not exist.
    /// - [`VfsError::NotADirectory`] — `path` names a regular file.
    ///
    /// # Example
    ///
    /// ```rust
    /// use nexacore_kernel::vfs::InMemoryVfs;
    ///
    /// let mut vfs = InMemoryVfs::new();
    /// vfs.create_file("/a.txt").unwrap();
    /// vfs.create_directory("/subdir").unwrap();
    /// let entries = vfs.list_directory("/").unwrap();
    /// assert_eq!(entries.len(), 2);
    /// // BTreeMap order: alphabetical.
    /// assert_eq!(entries[0].name, "a.txt");
    /// assert_eq!(entries[1].name, "subdir");
    /// ```
    pub fn list_directory(&self, path: &str) -> Result<Vec<DirEntry>, VfsError> {
        let id = self.resolve_path(path)?;
        let inode = self.inodes.get(&id).ok_or(VfsError::NotFound)?;
        if inode.file_type != FileType::Directory {
            return Err(VfsError::NotADirectory);
        }

        let mut entries = Vec::with_capacity(inode.children.len());
        for (name, &child_id) in &inode.children {
            let child = self.inodes.get(&child_id).ok_or(VfsError::NotFound)?;
            entries.push(DirEntry {
                name: name.clone(),
                inode: child_id,
                file_type: child.file_type,
            });
        }
        Ok(entries)
    }

    /// Returns `true` if `path` names an existing file or directory.
    ///
    /// # Example
    ///
    /// ```rust
    /// use nexacore_kernel::vfs::InMemoryVfs;
    ///
    /// let mut vfs = InMemoryVfs::new();
    /// assert!(vfs.exists("/"));
    /// assert!(!vfs.exists("/nonexistent"));
    /// vfs.create_file("/foo").unwrap();
    /// assert!(vfs.exists("/foo"));
    /// ```
    #[must_use]
    pub fn exists(&self, path: &str) -> bool {
        self.resolve_path(path).is_ok()
    }

    // -----------------------------------------------------------------------
    // File I/O
    // -----------------------------------------------------------------------

    /// Read up to `len` bytes from inode `inode_id` starting at `offset`.
    ///
    /// Returns an empty [`Vec`] when `offset` is at or beyond the end of
    /// the file. Reads that extend past the end are silently clamped to the
    /// available data.
    ///
    /// # Errors
    ///
    /// - [`VfsError::NotFound`] — `inode_id` does not exist.
    /// - [`VfsError::IsADirectory`] — `inode_id` names a directory.
    ///
    /// # Example
    ///
    /// ```rust
    /// use nexacore_kernel::vfs::InMemoryVfs;
    ///
    /// let mut vfs = InMemoryVfs::new();
    /// let id = vfs.create_file("/data.bin").unwrap();
    /// vfs.write_file(id, 0, b"hello").unwrap();
    /// let out = vfs.read_file(id, 0, 5).unwrap();
    /// assert_eq!(out, b"hello");
    /// ```
    pub fn read_file(&self, inode_id: u64, offset: u64, len: usize) -> Result<Vec<u8>, VfsError> {
        let inode = self.inodes.get(&inode_id).ok_or(VfsError::NotFound)?;
        if inode.file_type == FileType::Directory {
            return Err(VfsError::IsADirectory);
        }

        let data = &inode.data;
        let file_len = data.len() as u64;

        if offset >= file_len || len == 0 {
            return Ok(Vec::new());
        }

        // `offset < file_len <= usize::MAX` on any supported target, so the
        // cast cannot truncate a meaningful value. On 32-bit targets a file
        // cannot exceed `usize::MAX` bytes because the backing `Vec` would
        // have overflowed at write time first.
        #[allow(
            clippy::cast_possible_truncation,
            reason = "offset < file_len <= Vec::len() <= usize::MAX; truncation is impossible"
        )]
        let start = offset as usize;
        let end = start.saturating_add(len).min(data.len());
        // `start` and `end` are both bounded by `data.len()`, so the slice
        // cannot panic.
        Ok(data.get(start..end).unwrap_or_default().to_vec())
    }

    /// Write `data` into inode `inode_id` starting at `offset`.
    ///
    /// If `offset + data.len()` extends past the current file size the file
    /// is grown (zero-padded between the old end and the write start). Returns
    /// the number of bytes written.
    ///
    /// # Errors
    ///
    /// - [`VfsError::NotFound`] — `inode_id` does not exist.
    /// - [`VfsError::IsADirectory`] — `inode_id` names a directory.
    ///
    /// # Example
    ///
    /// ```rust
    /// use nexacore_kernel::vfs::InMemoryVfs;
    ///
    /// let mut vfs = InMemoryVfs::new();
    /// let id = vfs.create_file("/out.txt").unwrap();
    /// let written = vfs.write_file(id, 0, b"world").unwrap();
    /// assert_eq!(written, 5);
    /// assert_eq!(vfs.file_size(id).unwrap(), 5);
    /// ```
    pub fn write_file(
        &mut self,
        inode_id: u64,
        offset: u64,
        data: &[u8],
    ) -> Result<usize, VfsError> {
        let inode = self.inodes.get_mut(&inode_id).ok_or(VfsError::NotFound)?;
        if inode.file_type == FileType::Directory {
            return Err(VfsError::IsADirectory);
        }

        if data.is_empty() {
            return Ok(0);
        }

        // `offset` is a file position. On 32-bit targets any value that
        // overflows `usize` would have caused `Vec::resize` to panic with
        // a capacity-overflow error before we could have gotten here, so
        // the cast is safe in practice.
        #[allow(
            clippy::cast_possible_truncation,
            reason = "offset + data.len() is bounded by Vec capacity which is at most usize::MAX"
        )]
        let start = offset as usize;
        let end = start.saturating_add(data.len());

        // Grow the backing buffer if necessary, zero-filling the gap.
        if end > inode.data.len() {
            inode.data.resize(end, 0u8);
        }

        // `end == start + data.len()` and `inode.data.len() >= end` after
        // the resize, so the slice `start..end` is always in-bounds.
        if let Some(dst) = inode.data.get_mut(start..end) {
            dst.copy_from_slice(data);
        }
        Ok(data.len())
    }

    /// Return the size in bytes of the file at inode `inode_id`.
    ///
    /// # Errors
    ///
    /// - [`VfsError::NotFound`] — `inode_id` does not exist.
    /// - [`VfsError::IsADirectory`] — `inode_id` names a directory.
    ///
    /// # Example
    ///
    /// ```rust
    /// use nexacore_kernel::vfs::InMemoryVfs;
    ///
    /// let mut vfs = InMemoryVfs::new();
    /// let id = vfs.create_file("/empty").unwrap();
    /// assert_eq!(vfs.file_size(id).unwrap(), 0);
    /// ```
    pub fn file_size(&self, inode_id: u64) -> Result<u64, VfsError> {
        let inode = self.inodes.get(&inode_id).ok_or(VfsError::NotFound)?;
        if inode.file_type == FileType::Directory {
            return Err(VfsError::IsADirectory);
        }
        Ok(inode.data.len() as u64)
    }
}

impl Default for InMemoryVfs {
    /// Returns a new, empty filesystem — same as [`InMemoryVfs::new`].
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(
    clippy::indexing_slicing,
    reason = "test assertions use direct indexing for clarity; panics are the desired failure mode"
)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // Constructor
    // -----------------------------------------------------------------------

    #[test]
    fn new_creates_root_directory() {
        let vfs = InMemoryVfs::new();
        let stat = vfs.stat("/").unwrap();
        assert_eq!(stat.inode, 1);
        assert_eq!(stat.file_type, FileType::Directory);
        assert_eq!(stat.size, 0);
    }

    #[test]
    fn default_equals_new() {
        let vfs: InMemoryVfs = InMemoryVfs::default();
        let stat = vfs.stat("/").unwrap();
        assert_eq!(stat.inode, 1);
    }

    // -----------------------------------------------------------------------
    // create_file + stat
    // -----------------------------------------------------------------------

    #[test]
    fn create_file_and_stat() {
        let mut vfs = InMemoryVfs::new();
        let id = vfs.create_file("/hello.txt").unwrap();
        let stat = vfs.stat("/hello.txt").unwrap();
        assert_eq!(stat.inode, id);
        assert_eq!(stat.file_type, FileType::RegularFile);
        assert_eq!(stat.size, 0);
    }

    // -----------------------------------------------------------------------
    // create_directory + stat
    // -----------------------------------------------------------------------

    #[test]
    fn create_directory_and_stat() {
        let mut vfs = InMemoryVfs::new();
        let id = vfs.create_directory("/etc").unwrap();
        let stat = vfs.stat("/etc").unwrap();
        assert_eq!(stat.inode, id);
        assert_eq!(stat.file_type, FileType::Directory);
    }

    // -----------------------------------------------------------------------
    // create_file in subdirectory
    // -----------------------------------------------------------------------

    #[test]
    fn create_file_in_subdirectory() {
        let mut vfs = InMemoryVfs::new();
        vfs.create_directory("/home").unwrap();
        let id = vfs.create_file("/home/readme.txt").unwrap();
        let stat = vfs.stat("/home/readme.txt").unwrap();
        assert_eq!(stat.inode, id);
        assert_eq!(stat.file_type, FileType::RegularFile);
    }

    // -----------------------------------------------------------------------
    // delete file
    // -----------------------------------------------------------------------

    #[test]
    fn delete_file() {
        let mut vfs = InMemoryVfs::new();
        vfs.create_file("/tmp.txt").unwrap();
        assert!(vfs.exists("/tmp.txt"));
        vfs.delete("/tmp.txt").unwrap();
        assert!(!vfs.exists("/tmp.txt"));
    }

    // -----------------------------------------------------------------------
    // delete empty directory
    // -----------------------------------------------------------------------

    #[test]
    fn delete_empty_directory() {
        let mut vfs = InMemoryVfs::new();
        vfs.create_directory("/empty_dir").unwrap();
        assert!(vfs.exists("/empty_dir"));
        vfs.delete("/empty_dir").unwrap();
        assert!(!vfs.exists("/empty_dir"));
    }

    // -----------------------------------------------------------------------
    // delete non-empty directory → error
    // -----------------------------------------------------------------------

    #[test]
    fn delete_non_empty_directory_returns_not_empty() {
        let mut vfs = InMemoryVfs::new();
        vfs.create_directory("/full").unwrap();
        vfs.create_file("/full/child.txt").unwrap();
        let err = vfs.delete("/full").unwrap_err();
        assert_eq!(err, VfsError::NotEmpty);
        // Directory still exists.
        assert!(vfs.exists("/full"));
    }

    // -----------------------------------------------------------------------
    // list_directory
    // -----------------------------------------------------------------------

    #[test]
    fn list_directory_empty_root() {
        let vfs = InMemoryVfs::new();
        let entries = vfs.list_directory("/").unwrap();
        assert!(entries.is_empty());
    }

    #[test]
    fn list_directory_with_entries() {
        let mut vfs = InMemoryVfs::new();
        vfs.create_file("/a.txt").unwrap();
        vfs.create_directory("/subdir").unwrap();
        let entries = vfs.list_directory("/").unwrap();
        assert_eq!(entries.len(), 2);
        // BTreeMap yields lexicographic order.
        assert_eq!(entries[0].name, "a.txt");
        assert_eq!(entries[0].file_type, FileType::RegularFile);
        assert_eq!(entries[1].name, "subdir");
        assert_eq!(entries[1].file_type, FileType::Directory);
    }

    // -----------------------------------------------------------------------
    // read_file / write_file roundtrip
    // -----------------------------------------------------------------------

    #[test]
    fn read_write_roundtrip() {
        let mut vfs = InMemoryVfs::new();
        let id = vfs.create_file("/data.bin").unwrap();
        let written = vfs.write_file(id, 0, b"hello world").unwrap();
        assert_eq!(written, 11);
        let out = vfs.read_file(id, 0, 11).unwrap();
        assert_eq!(out, b"hello world");
    }

    // -----------------------------------------------------------------------
    // write extends file
    // -----------------------------------------------------------------------

    #[test]
    fn write_extends_file() {
        let mut vfs = InMemoryVfs::new();
        let id = vfs.create_file("/grow.bin").unwrap();
        assert_eq!(vfs.file_size(id).unwrap(), 0);
        vfs.write_file(id, 0, b"abc").unwrap();
        assert_eq!(vfs.file_size(id).unwrap(), 3);
        vfs.write_file(id, 3, b"def").unwrap();
        assert_eq!(vfs.file_size(id).unwrap(), 6);
        let out = vfs.read_file(id, 0, 6).unwrap();
        assert_eq!(out, b"abcdef");
    }

    // -----------------------------------------------------------------------
    // write at offset
    // -----------------------------------------------------------------------

    #[test]
    fn write_at_offset() {
        let mut vfs = InMemoryVfs::new();
        let id = vfs.create_file("/patch.bin").unwrap();
        // Write 5 zeroes implicitly via extend.
        vfs.write_file(id, 5, b"XY").unwrap();
        assert_eq!(vfs.file_size(id).unwrap(), 7);
        // The first 5 bytes must be zero-padded.
        let out = vfs.read_file(id, 0, 7).unwrap();
        assert_eq!(&out[..5], &[0u8; 5]);
        assert_eq!(&out[5..], b"XY");
    }

    // -----------------------------------------------------------------------
    // read at offset beyond file → empty
    // -----------------------------------------------------------------------

    #[test]
    fn read_beyond_end_returns_empty() {
        let mut vfs = InMemoryVfs::new();
        let id = vfs.create_file("/short.bin").unwrap();
        vfs.write_file(id, 0, b"hi").unwrap();
        let out = vfs.read_file(id, 100, 10).unwrap();
        assert!(out.is_empty());
    }

    // -----------------------------------------------------------------------
    // stat on nonexistent → NotFound
    // -----------------------------------------------------------------------

    #[test]
    fn stat_nonexistent_returns_not_found() {
        let vfs = InMemoryVfs::new();
        let err = vfs.stat("/nonexistent").unwrap_err();
        assert_eq!(err, VfsError::NotFound);
    }

    // -----------------------------------------------------------------------
    // create duplicate → AlreadyExists
    // -----------------------------------------------------------------------

    #[test]
    fn create_duplicate_returns_already_exists() {
        let mut vfs = InMemoryVfs::new();
        vfs.create_file("/dup.txt").unwrap();
        let err = vfs.create_file("/dup.txt").unwrap_err();
        assert_eq!(err, VfsError::AlreadyExists);
    }

    // -----------------------------------------------------------------------
    // normalize_path: absolute
    // -----------------------------------------------------------------------

    #[test]
    fn normalize_absolute_path() {
        assert_eq!(InMemoryVfs::normalize_path("/", "/a/b/c"), "/a/b/c");
        assert_eq!(InMemoryVfs::normalize_path("/x/y", "/a/b"), "/a/b");
    }

    // -----------------------------------------------------------------------
    // normalize_path: relative
    // -----------------------------------------------------------------------

    #[test]
    fn normalize_relative_path() {
        assert_eq!(
            InMemoryVfs::normalize_path("/home/user", "docs"),
            "/home/user/docs"
        );
        assert_eq!(InMemoryVfs::normalize_path("/", "foo"), "/foo");
    }

    // -----------------------------------------------------------------------
    // normalize_path: with ..
    // -----------------------------------------------------------------------

    #[test]
    fn normalize_path_with_dotdot() {
        assert_eq!(InMemoryVfs::normalize_path("/", "/a/b/../c"), "/a/c");
        assert_eq!(InMemoryVfs::normalize_path("/", "/a/b/../../c"), "/c");
        // .. past root stays at root.
        assert_eq!(InMemoryVfs::normalize_path("/", "/../.."), "/");
    }

    // -----------------------------------------------------------------------
    // normalize_path: with .
    // -----------------------------------------------------------------------

    #[test]
    fn normalize_path_with_dot() {
        assert_eq!(InMemoryVfs::normalize_path("/", "/a/./b"), "/a/b");
        assert_eq!(InMemoryVfs::normalize_path("/x", "./y"), "/x/y");
    }

    // -----------------------------------------------------------------------
    // normalize_path: double slash collapse
    // -----------------------------------------------------------------------

    #[test]
    fn normalize_path_double_slash() {
        assert_eq!(InMemoryVfs::normalize_path("/", "/a//b"), "/a/b");
        assert_eq!(InMemoryVfs::normalize_path("/", "//root"), "/root");
    }

    // -----------------------------------------------------------------------
    // resolve_path: root
    // -----------------------------------------------------------------------

    #[test]
    fn resolve_root_gives_inode_1() {
        let vfs = InMemoryVfs::new();
        let stat = vfs.stat("/").unwrap();
        assert_eq!(stat.inode, 1);
    }

    // -----------------------------------------------------------------------
    // resolve_path: nested
    // -----------------------------------------------------------------------

    #[test]
    fn resolve_nested_path() {
        let mut vfs = InMemoryVfs::new();
        vfs.create_directory("/a").unwrap();
        vfs.create_directory("/a/b").unwrap();
        let id = vfs.create_file("/a/b/c.txt").unwrap();
        let stat = vfs.stat("/a/b/c.txt").unwrap();
        assert_eq!(stat.inode, id);
    }

    // -----------------------------------------------------------------------
    // exists: true/false
    // -----------------------------------------------------------------------

    #[test]
    fn exists_true_and_false() {
        let mut vfs = InMemoryVfs::new();
        assert!(vfs.exists("/"));
        assert!(!vfs.exists("/nope"));
        vfs.create_file("/yes").unwrap();
        assert!(vfs.exists("/yes"));
    }

    // -----------------------------------------------------------------------
    // create nested: parents must exist
    // -----------------------------------------------------------------------

    #[test]
    fn create_nested_without_parent_returns_not_found() {
        let mut vfs = InMemoryVfs::new();
        // /a does not exist, so /a/b/c must fail.
        let err = vfs.create_file("/a/b/c").unwrap_err();
        assert_eq!(err, VfsError::NotFound);
    }

    #[test]
    fn create_deeply_nested_with_parents() {
        let mut vfs = InMemoryVfs::new();
        vfs.create_directory("/a").unwrap();
        vfs.create_directory("/a/b").unwrap();
        let id = vfs.create_file("/a/b/c").unwrap();
        assert!(vfs.exists("/a/b/c"));
        let stat = vfs.stat("/a/b/c").unwrap();
        assert_eq!(stat.inode, id);
    }

    // -----------------------------------------------------------------------
    // delete root → error
    // -----------------------------------------------------------------------

    #[test]
    fn delete_root_returns_invalid_path() {
        let mut vfs = InMemoryVfs::new();
        let err = vfs.delete("/").unwrap_err();
        assert_eq!(err, VfsError::InvalidPath);
    }

    // -----------------------------------------------------------------------
    // multiple files in same directory
    // -----------------------------------------------------------------------

    #[test]
    fn multiple_files_in_same_directory() {
        let mut vfs = InMemoryVfs::new();
        let id1 = vfs.create_file("/f1.txt").unwrap();
        let id2 = vfs.create_file("/f2.txt").unwrap();
        let id3 = vfs.create_file("/f3.txt").unwrap();
        // All three must be distinct inodes.
        assert_ne!(id1, id2);
        assert_ne!(id2, id3);
        let entries = vfs.list_directory("/").unwrap();
        assert_eq!(entries.len(), 3);
        // After deleting one, the other two remain.
        vfs.delete("/f2.txt").unwrap();
        assert!(!vfs.exists("/f2.txt"));
        assert!(vfs.exists("/f1.txt"));
        assert!(vfs.exists("/f3.txt"));
    }

    // -----------------------------------------------------------------------
    // list_directory on a regular file → NotADirectory
    // -----------------------------------------------------------------------

    #[test]
    fn list_directory_on_file_returns_not_a_directory() {
        let mut vfs = InMemoryVfs::new();
        vfs.create_file("/not_a_dir").unwrap();
        let err = vfs.list_directory("/not_a_dir").unwrap_err();
        assert_eq!(err, VfsError::NotADirectory);
    }

    // -----------------------------------------------------------------------
    // file_size on directory → IsADirectory
    // -----------------------------------------------------------------------

    #[test]
    fn file_size_on_directory_returns_is_a_directory() {
        let mut vfs = InMemoryVfs::new();
        vfs.create_directory("/adir").unwrap();
        let stat = vfs.stat("/adir").unwrap();
        let err = vfs.file_size(stat.inode).unwrap_err();
        assert_eq!(err, VfsError::IsADirectory);
    }

    // -----------------------------------------------------------------------
    // read/write on directory → IsADirectory
    // -----------------------------------------------------------------------

    #[test]
    fn read_file_on_directory_returns_is_a_directory() {
        let mut vfs = InMemoryVfs::new();
        vfs.create_directory("/ddir").unwrap();
        let stat = vfs.stat("/ddir").unwrap();
        let err = vfs.read_file(stat.inode, 0, 10).unwrap_err();
        assert_eq!(err, VfsError::IsADirectory);
    }

    #[test]
    fn write_file_on_directory_returns_is_a_directory() {
        let mut vfs = InMemoryVfs::new();
        vfs.create_directory("/wdir").unwrap();
        let stat = vfs.stat("/wdir").unwrap();
        let err = vfs.write_file(stat.inode, 0, b"data").unwrap_err();
        assert_eq!(err, VfsError::IsADirectory);
    }

    // -----------------------------------------------------------------------
    // partial read (clamp at end of file)
    // -----------------------------------------------------------------------

    #[test]
    fn partial_read_clamps_to_file_end() {
        let mut vfs = InMemoryVfs::new();
        let id = vfs.create_file("/partial.bin").unwrap();
        vfs.write_file(id, 0, b"abcde").unwrap();
        // Ask for 100 bytes starting at offset 3 — only 2 bytes remain.
        let out = vfs.read_file(id, 3, 100).unwrap();
        assert_eq!(out, b"de");
    }

    // -----------------------------------------------------------------------
    // delete file removes it from parent listing
    // -----------------------------------------------------------------------

    #[test]
    fn delete_removes_entry_from_parent_listing() {
        let mut vfs = InMemoryVfs::new();
        vfs.create_file("/gone.txt").unwrap();
        let before = vfs.list_directory("/").unwrap();
        assert_eq!(before.len(), 1);
        vfs.delete("/gone.txt").unwrap();
        let after = vfs.list_directory("/").unwrap();
        assert!(after.is_empty());
    }

    // -----------------------------------------------------------------------
    // inode ids are monotonically increasing
    // -----------------------------------------------------------------------

    #[test]
    fn inode_ids_are_monotonically_increasing() {
        let mut vfs = InMemoryVfs::new();
        let id1 = vfs.create_file("/first").unwrap();
        let id2 = vfs.create_file("/second").unwrap();
        let id3 = vfs.create_directory("/third").unwrap();
        assert!(id1 < id2);
        assert!(id2 < id3);
    }
}
