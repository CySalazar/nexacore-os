//! Filesystem seam for the FS-backed coreutils (WS8-10.1).
//!
//! The utilities never touch a real disk directly. They speak to the
//! [`FileSystem`] trait — an abstraction over exactly the operations `ls`, `cp`,
//! `mkdir`, `tree`, … need. On hardware that seam bridges to the kernel VFS over
//! IPC; in host tests it is the in-memory [`MemFs`] double, which holds a whole
//! tree in a `BTreeMap`. This mirrors the `ProcSource` transport seam used by
//! the system monitor: one trait, a production transport, and a deterministic
//! in-memory host double.
//!
//! ## Fail-closed
//!
//! Every operation validates the shape of what it touches and returns a precise
//! [`FsError`] instead of guessing: reading a directory is [`FsError::IsADirectory`],
//! creating an existing entry is [`FsError::AlreadyExists`], removing a
//! non-empty directory is [`FsError::NotEmpty`]. A relative path — one the seam
//! cannot resolve on its own — is [`FsError::InvalidPath`].
//!
//! ## Permissions are capabilities, not Unix bits
//!
//! NexaCore maps access rights to capability tokens, not `rwxr-xr-x` mode bits.
//! [`Capabilities`] is therefore an abstract read/write/execute grant, a
//! deliberate placeholder for the richer capability model; it is intentionally
//! not a numeric mode.

use alloc::{
    collections::BTreeMap,
    string::{String, ToString},
    vec::Vec,
};

use crate::path;

/// The kind of a filesystem entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileKind {
    /// A regular file holding a byte payload.
    File,
    /// A directory containing other entries.
    Dir,
    /// A symbolic link naming a target path (never dereferenced by this seam).
    Symlink,
}

/// Abstract access grant for an entry.
///
/// This is a **placeholder** for NexaCore's capability-token permission model,
/// not a Unix mode. Each flag is a coarse capability the holder of the entry's
/// token would carry; the real system attaches unforgeable tokens rather than
/// three bits, but the utilities only ever need this abstract read/write/execute
/// view for display (`ls -l`, `stat`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Capabilities {
    /// The entry's contents (or listing, for a directory) may be read.
    pub read: bool,
    /// The entry may be written (or, for a directory, have entries added).
    pub write: bool,
    /// The entry may be executed (or, for a directory, traversed).
    pub execute: bool,
}

impl Capabilities {
    /// All capabilities granted (`rwx`).
    #[must_use]
    pub const fn all() -> Self {
        Self {
            read: true,
            write: true,
            execute: true,
        }
    }

    /// Read and write, no execute (`rw-`) — the default for a regular file.
    #[must_use]
    pub const fn read_write() -> Self {
        Self {
            read: true,
            write: true,
            execute: false,
        }
    }

    /// Render as a three-character `rwx`/`-` string for display.
    #[must_use]
    pub fn as_rwx(self) -> String {
        let mut out = String::with_capacity(3);
        out.push(if self.read { 'r' } else { '-' });
        out.push(if self.write { 'w' } else { '-' });
        out.push(if self.execute { 'x' } else { '-' });
        out
    }
}

/// The default owning principal for every entry: the root principal, id `0`.
///
/// This mirrors the `identity` module's root convention. An entry's owner stays
/// [`ROOT_OWNER`] until a `chown`-equivalent reassigns it (see the `perm`
/// module).
pub const ROOT_OWNER: u64 = 0;

/// Metadata describing a single filesystem entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Metadata {
    /// Whether the entry is a file, directory, or symlink.
    pub kind: FileKind,
    /// Payload length in bytes (file), listing byte-count placeholder (dir), or
    /// target-string length (symlink).
    pub len: u64,
    /// Abstract capability grant (see [`Capabilities`]).
    pub capabilities: Capabilities,
}

/// One entry within a directory listing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DirEntry {
    /// The entry's final path component (no slashes).
    pub name: String,
    /// The entry's metadata.
    pub metadata: Metadata,
}

/// A filesystem operation error. Fail-closed: each variant is a specific,
/// non-guessed reason.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FsError {
    /// No entry exists at the given path.
    NotFound,
    /// A directory was required but the entry is not one.
    NotADirectory,
    /// A file was required but the entry is a directory.
    IsADirectory,
    /// An entry already exists where a new one was requested.
    AlreadyExists,
    /// A directory removal was requested but the directory is not empty.
    NotEmpty,
    /// The path was not an absolute, resolvable path (e.g. it was relative, or
    /// it named a symlink the seam declines to dereference).
    InvalidPath,
    /// A byte payload was required to be UTF-8 text but was not.
    InvalidData,
}

impl core::fmt::Display for FsError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let msg = match self {
            Self::NotFound => "no such file or directory",
            Self::NotADirectory => "not a directory",
            Self::IsADirectory => "is a directory",
            Self::AlreadyExists => "file exists",
            Self::NotEmpty => "directory not empty",
            Self::InvalidPath => "invalid path",
            Self::InvalidData => "invalid (non-UTF-8) data",
        };
        f.write_str(msg)
    }
}

/// The operations the FS-backed coreutils require.
///
/// Read-only queries take `&self`; mutations take `&mut self`. All paths must be
/// absolute; a relative path yields [`FsError::InvalidPath`]. Implementors
/// normalize paths internally, so `/a/./b` and `/a/b` name the same entry.
pub trait FileSystem {
    /// Metadata for the entry at `path`.
    ///
    /// # Errors
    /// [`FsError::NotFound`] if nothing exists there, [`FsError::InvalidPath`]
    /// if `path` is not absolute.
    fn metadata(&self, path: &str) -> Result<Metadata, FsError>;

    /// Read the raw bytes of the file at `path`.
    ///
    /// # Errors
    /// [`FsError::IsADirectory`] if `path` is a directory, [`FsError::NotFound`]
    /// if it does not exist, [`FsError::InvalidPath`] if it names a symlink or
    /// is not absolute.
    fn read(&self, path: &str) -> Result<Vec<u8>, FsError>;

    /// Read the file at `path` as UTF-8 text.
    ///
    /// # Errors
    /// Propagates [`read`](FileSystem::read) errors, plus [`FsError::InvalidData`]
    /// if the bytes are not valid UTF-8.
    fn read_to_string(&self, path: &str) -> Result<String, FsError> {
        let bytes = self.read(path)?;
        String::from_utf8(bytes).map_err(|_| FsError::InvalidData)
    }

    /// List the directory at `path`, sorted by entry name.
    ///
    /// # Errors
    /// [`FsError::NotADirectory`] if `path` is not a directory,
    /// [`FsError::NotFound`] if it does not exist.
    fn read_dir(&self, path: &str) -> Result<Vec<DirEntry>, FsError>;

    /// Whether an entry exists at `path` (never errors; a bad path is `false`).
    fn exists(&self, path: &str) -> bool {
        self.metadata(path).is_ok()
    }

    /// Write `bytes` to `path`, creating or truncating a regular file.
    ///
    /// # Errors
    /// [`FsError::IsADirectory`] if `path` is an existing directory,
    /// [`FsError::NotFound`]/[`FsError::NotADirectory`] if the parent is missing
    /// or not a directory.
    fn write(&mut self, path: &str, bytes: &[u8]) -> Result<(), FsError>;

    /// Create an empty directory at `path`.
    ///
    /// # Errors
    /// [`FsError::AlreadyExists`] if something is already there,
    /// [`FsError::NotFound`]/[`FsError::NotADirectory`] if the parent is missing
    /// or not a directory.
    fn create_dir(&mut self, path: &str) -> Result<(), FsError>;

    /// Remove the regular file (or symlink) at `path`.
    ///
    /// # Errors
    /// [`FsError::IsADirectory`] if `path` is a directory, [`FsError::NotFound`]
    /// if it does not exist.
    fn remove_file(&mut self, path: &str) -> Result<(), FsError>;

    /// Remove the empty directory at `path`.
    ///
    /// # Errors
    /// [`FsError::NotADirectory`] if `path` is not a directory,
    /// [`FsError::NotEmpty`] if it still has entries, [`FsError::NotFound`] if it
    /// does not exist.
    fn remove_dir(&mut self, path: &str) -> Result<(), FsError>;

    /// Rename/move `from` to `to`, including a whole subtree if `from` is a
    /// directory.
    ///
    /// # Errors
    /// [`FsError::NotFound`] if `from` is missing, [`FsError::AlreadyExists`] if
    /// `to` already exists, [`FsError::NotFound`]/[`FsError::NotADirectory`] if
    /// `to`'s parent is missing or not a directory.
    fn rename(&mut self, from: &str, to: &str) -> Result<(), FsError>;

    /// Create a symbolic link at `link` naming `target` (which is not
    /// validated — links may dangle, as on a real filesystem).
    ///
    /// # Errors
    /// [`FsError::AlreadyExists`] if `link` exists,
    /// [`FsError::NotFound`]/[`FsError::NotADirectory`] if `link`'s parent is
    /// missing or not a directory.
    fn symlink(&mut self, target: &str, link: &str) -> Result<(), FsError>;

    /// The owning principal id of the entry at `path` (the `chown` subject).
    ///
    /// Unowned-by-anyone-yet entries report [`ROOT_OWNER`].
    ///
    /// # Errors
    /// [`FsError::NotFound`] if nothing exists there, [`FsError::InvalidPath`]
    /// if `path` is not absolute.
    fn owner(&self, path: &str) -> Result<u64, FsError>;

    /// Reassign the owning principal of the entry at `path` (the
    /// `chown`-equivalent). This is a capability operation: it changes *who* the
    /// entry answers to, independent of its [`Capabilities`] grant.
    ///
    /// # Errors
    /// [`FsError::NotFound`] if nothing exists there, [`FsError::InvalidPath`]
    /// if `path` is not absolute.
    fn set_owner(&mut self, path: &str, owner: u64) -> Result<(), FsError>;

    /// Replace the capability grant on the entry at `path` (the
    /// `chmod`-equivalent). Grants and revocations of individual capability
    /// tokens are layered on top of this by the `perm` module.
    ///
    /// # Errors
    /// [`FsError::NotFound`] if nothing exists there, [`FsError::InvalidPath`]
    /// if `path` is not absolute.
    fn set_capabilities(&mut self, path: &str, caps: Capabilities) -> Result<(), FsError>;
}

/// The stored form of a single entry inside [`MemFs`].
#[derive(Debug, Clone, PartialEq, Eq)]
enum Node {
    /// A regular file with its byte payload and capabilities.
    File {
        /// Raw file bytes.
        data: Vec<u8>,
        /// Access grant.
        caps: Capabilities,
    },
    /// A directory (children are found by scanning keys, not stored here).
    Dir {
        /// Access grant.
        caps: Capabilities,
    },
    /// A symlink naming a target path.
    Symlink {
        /// The link target (opaque; never dereferenced).
        target: String,
        /// Access grant.
        caps: Capabilities,
    },
}

impl Node {
    /// Replace this node's capability grant in place (the `chmod`-equivalent's
    /// storage mutation).
    fn set_caps(&mut self, new_caps: Capabilities) {
        match self {
            Self::File { caps, .. } | Self::Dir { caps } | Self::Symlink { caps, .. } => {
                *caps = new_caps;
            }
        }
    }

    /// Derive display [`Metadata`] for this node.
    fn metadata(&self) -> Metadata {
        match self {
            Self::File { data, caps } => Metadata {
                kind: FileKind::File,
                len: data.len() as u64,
                capabilities: *caps,
            },
            Self::Dir { caps } => Metadata {
                kind: FileKind::Dir,
                len: 0,
                capabilities: *caps,
            },
            Self::Symlink { target, caps } => Metadata {
                kind: FileKind::Symlink,
                len: target.len() as u64,
                capabilities: *caps,
            },
        }
    }
}

/// An in-memory [`FileSystem`] for host tests, backed by a `BTreeMap` keyed on
/// normalized absolute paths.
///
/// The root `"/"` always exists. Builder methods (`with_*`) auto-create any
/// missing ancestor directories so tests can register a deep file in one call;
/// they treat their path argument as absolute.
#[derive(Debug, Clone)]
pub struct MemFs {
    /// `normalized absolute path → node`.
    nodes: BTreeMap<String, Node>,
    /// `normalized absolute path → owning principal id`. Entries absent from
    /// this map are owned by [`ROOT_OWNER`]; a `chown` records an override here.
    owners: BTreeMap<String, u64>,
}

impl Default for MemFs {
    fn default() -> Self {
        Self::new()
    }
}

impl MemFs {
    /// A filesystem containing only the root directory.
    #[must_use]
    pub fn new() -> Self {
        let mut nodes = BTreeMap::new();
        nodes.insert(
            String::from("/"),
            Node::Dir {
                caps: Capabilities::all(),
            },
        );
        Self {
            nodes,
            owners: BTreeMap::new(),
        }
    }

    /// Treat `path` as an absolute key, prefixing `/` if it is missing so the
    /// builder stays infallible.
    fn as_key(path: &str) -> String {
        if path::is_absolute(path) {
            path::normalize(path)
        } else {
            let mut abs = String::from("/");
            abs.push_str(path);
            path::normalize(&abs)
        }
    }

    /// Infallibly create every ancestor directory of `key` (mkdir -p style).
    fn ensure_ancestors(&mut self, key: &str) {
        if let Some(parent) = path::parent(key) {
            self.ensure_dir_chain(&parent);
        }
    }

    /// Infallibly ensure `dir` and all its ancestors exist as directories.
    fn ensure_dir_chain(&mut self, dir: &str) {
        if let Some(parent) = path::parent(dir) {
            self.ensure_dir_chain(&parent);
        }
        self.nodes.entry(dir.to_string()).or_insert(Node::Dir {
            caps: Capabilities::all(),
        });
    }

    /// Register a regular file with the given bytes (builder style),
    /// auto-creating ancestor directories.
    #[must_use]
    pub fn with_file(mut self, path: &str, bytes: &[u8]) -> Self {
        let key = Self::as_key(path);
        self.ensure_ancestors(&key);
        self.nodes.insert(
            key,
            Node::File {
                data: bytes.to_vec(),
                caps: Capabilities::read_write(),
            },
        );
        self
    }

    /// Register a regular file from a text payload (builder style).
    #[must_use]
    pub fn with_text_file(self, path: &str, text: &str) -> Self {
        self.with_file(path, text.as_bytes())
    }

    /// Register an **executable** regular file — a file whose capability grant
    /// carries `execute` — auto-creating ancestor directories (builder style).
    ///
    /// This is the host-test counterpart of marking a file executable; utilities
    /// like `which` treat only such files as runnable.
    #[must_use]
    pub fn with_executable_file(mut self, path: &str, bytes: &[u8]) -> Self {
        let key = Self::as_key(path);
        self.ensure_ancestors(&key);
        self.nodes.insert(
            key,
            Node::File {
                data: bytes.to_vec(),
                caps: Capabilities::all(),
            },
        );
        self
    }

    /// Register a directory (builder style), auto-creating ancestors.
    #[must_use]
    pub fn with_dir(mut self, path: &str) -> Self {
        let key = Self::as_key(path);
        self.ensure_dir_chain(&key);
        self
    }

    /// Register a symlink at `link` naming `target` (builder style).
    #[must_use]
    pub fn with_symlink(mut self, link: &str, target: &str) -> Self {
        let key = Self::as_key(link);
        self.ensure_ancestors(&key);
        self.nodes.insert(
            key,
            Node::Symlink {
                target: target.to_string(),
                caps: Capabilities::all(),
            },
        );
        self
    }

    /// Normalize `path` to a key, rejecting non-absolute input (fail-closed).
    fn key(path: &str) -> Result<String, FsError> {
        if path::is_absolute(path) {
            Ok(path::normalize(path))
        } else {
            Err(FsError::InvalidPath)
        }
    }

    /// Whether `key` names an existing directory.
    fn is_dir(&self, key: &str) -> bool {
        matches!(self.nodes.get(key), Some(Node::Dir { .. }))
    }

    /// Validate that `key`'s parent exists and is a directory (write guard).
    fn check_parent_dir(&self, key: &str) -> Result<(), FsError> {
        // The root's parent is the root, so a missing parent means `key` is the
        // root itself and needs no check.
        path::parent(key).map_or(Ok(()), |parent| match self.nodes.get(&parent) {
            Some(Node::Dir { .. }) => Ok(()),
            Some(_) => Err(FsError::NotADirectory),
            None => Err(FsError::NotFound),
        })
    }
}

impl FileSystem for MemFs {
    fn metadata(&self, path: &str) -> Result<Metadata, FsError> {
        let key = Self::key(path)?;
        self.nodes
            .get(&key)
            .map(Node::metadata)
            .ok_or(FsError::NotFound)
    }

    fn read(&self, path: &str) -> Result<Vec<u8>, FsError> {
        let key = Self::key(path)?;
        match self.nodes.get(&key) {
            Some(Node::File { data, .. }) => Ok(data.clone()),
            Some(Node::Dir { .. }) => Err(FsError::IsADirectory),
            // Symlinks are opaque leaves here; the seam does not dereference.
            Some(Node::Symlink { .. }) => Err(FsError::InvalidPath),
            None => Err(FsError::NotFound),
        }
    }

    fn read_dir(&self, path: &str) -> Result<Vec<DirEntry>, FsError> {
        let key = Self::key(path)?;
        match self.nodes.get(&key) {
            Some(Node::Dir { .. }) => {}
            Some(_) => return Err(FsError::NotADirectory),
            None => return Err(FsError::NotFound),
        }
        let mut entries: Vec<DirEntry> = Vec::new();
        for (child_key, node) in &self.nodes {
            if path::parent(child_key).as_deref() == Some(key.as_str()) {
                if let Some(name) = path::file_name(child_key) {
                    entries.push(DirEntry {
                        name,
                        metadata: node.metadata(),
                    });
                }
            }
        }
        // BTreeMap iteration is already key-sorted, which yields name-sorted
        // siblings; sort explicitly to make the contract independent of that.
        entries.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(entries)
    }

    fn write(&mut self, path: &str, bytes: &[u8]) -> Result<(), FsError> {
        let key = Self::key(path)?;
        if self.is_dir(&key) {
            return Err(FsError::IsADirectory);
        }
        self.check_parent_dir(&key)?;
        self.nodes.insert(
            key,
            Node::File {
                data: bytes.to_vec(),
                caps: Capabilities::read_write(),
            },
        );
        Ok(())
    }

    fn create_dir(&mut self, path: &str) -> Result<(), FsError> {
        let key = Self::key(path)?;
        if self.nodes.contains_key(&key) {
            return Err(FsError::AlreadyExists);
        }
        self.check_parent_dir(&key)?;
        self.nodes.insert(
            key,
            Node::Dir {
                caps: Capabilities::all(),
            },
        );
        Ok(())
    }

    fn remove_file(&mut self, path: &str) -> Result<(), FsError> {
        let key = Self::key(path)?;
        match self.nodes.get(&key) {
            Some(Node::Dir { .. }) => Err(FsError::IsADirectory),
            Some(_) => {
                self.nodes.remove(&key);
                self.owners.remove(&key);
                Ok(())
            }
            None => Err(FsError::NotFound),
        }
    }

    fn remove_dir(&mut self, path: &str) -> Result<(), FsError> {
        let key = Self::key(path)?;
        match self.nodes.get(&key) {
            Some(Node::Dir { .. }) => {}
            Some(_) => return Err(FsError::NotADirectory),
            None => return Err(FsError::NotFound),
        }
        if key == "/" {
            return Err(FsError::NotEmpty); // the root can never be removed
        }
        let has_children = self
            .nodes
            .keys()
            .any(|k| path::parent(k).as_deref() == Some(key.as_str()));
        if has_children {
            return Err(FsError::NotEmpty);
        }
        self.nodes.remove(&key);
        self.owners.remove(&key);
        Ok(())
    }

    fn rename(&mut self, from: &str, to: &str) -> Result<(), FsError> {
        let from_key = Self::key(from)?;
        let to_key = Self::key(to)?;
        if !self.nodes.contains_key(&from_key) {
            return Err(FsError::NotFound);
        }
        if self.nodes.contains_key(&to_key) {
            return Err(FsError::AlreadyExists);
        }
        self.check_parent_dir(&to_key)?;

        // Collect the node and, if it is a directory, its whole subtree, then
        // re-key every collected path under the new prefix.
        let mut prefix = from_key.clone();
        prefix.push('/');
        let moved: Vec<String> = self
            .nodes
            .keys()
            .filter(|k| *k == &from_key || k.starts_with(&prefix))
            .cloned()
            .collect();
        for old_key in moved {
            if let Some(node) = self.nodes.remove(&old_key) {
                let new_key = if old_key == from_key {
                    to_key.clone()
                } else if let Some(rest) = old_key.strip_prefix(&prefix) {
                    let mut nk = to_key.clone();
                    nk.push('/');
                    nk.push_str(rest);
                    nk
                } else {
                    old_key.clone()
                };
                self.nodes.insert(new_key, node);
            }
        }
        Ok(())
    }

    fn symlink(&mut self, target: &str, link: &str) -> Result<(), FsError> {
        let key = Self::key(link)?;
        if self.nodes.contains_key(&key) {
            return Err(FsError::AlreadyExists);
        }
        self.check_parent_dir(&key)?;
        self.nodes.insert(
            key,
            Node::Symlink {
                target: target.to_string(),
                caps: Capabilities::all(),
            },
        );
        Ok(())
    }

    fn owner(&self, path: &str) -> Result<u64, FsError> {
        let key = Self::key(path)?;
        if self.nodes.contains_key(&key) {
            Ok(self.owners.get(&key).copied().unwrap_or(ROOT_OWNER))
        } else {
            Err(FsError::NotFound)
        }
    }

    fn set_owner(&mut self, path: &str, owner: u64) -> Result<(), FsError> {
        let key = Self::key(path)?;
        if self.nodes.contains_key(&key) {
            self.owners.insert(key, owner);
            Ok(())
        } else {
            Err(FsError::NotFound)
        }
    }

    fn set_capabilities(&mut self, path: &str, caps: Capabilities) -> Result<(), FsError> {
        let key = Self::key(path)?;
        self.nodes
            .get_mut(&key)
            .map_or(Err(FsError::NotFound), |node| {
                node.set_caps(caps);
                Ok(())
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> MemFs {
        MemFs::new()
            .with_dir("/etc")
            .with_text_file("/etc/hosts", "127.0.0.1 localhost\n")
            .with_text_file("/home/user/notes.txt", "hello\n")
            .with_symlink("/home/user/link", "/etc/hosts")
    }

    #[test]
    fn metadata_reports_kinds_and_len() {
        let fs = sample();
        assert_eq!(fs.metadata("/etc").unwrap().kind, FileKind::Dir);
        let file = fs.metadata("/etc/hosts").unwrap();
        assert_eq!(file.kind, FileKind::File);
        assert_eq!(file.len, 20);
        assert_eq!(
            fs.metadata("/home/user/link").unwrap().kind,
            FileKind::Symlink
        );
    }

    #[test]
    fn read_to_string_round_trips() {
        let fs = sample();
        assert_eq!(
            fs.read_to_string("/home/user/notes.txt").unwrap(),
            "hello\n"
        );
    }

    #[test]
    fn relative_path_is_invalid() {
        let fs = sample();
        assert_eq!(fs.metadata("etc/hosts"), Err(FsError::InvalidPath));
    }

    #[test]
    fn read_directory_is_is_a_directory() {
        let fs = sample();
        assert_eq!(fs.read("/etc"), Err(FsError::IsADirectory));
    }

    #[test]
    fn read_missing_is_not_found() {
        let fs = sample();
        assert_eq!(fs.read("/nope"), Err(FsError::NotFound));
    }

    #[test]
    fn read_dir_lists_sorted_names() {
        let fs = sample();
        let names: Vec<String> = fs
            .read_dir("/home/user")
            .unwrap()
            .into_iter()
            .map(|e| e.name)
            .collect();
        assert_eq!(names, ["link", "notes.txt"]);
    }

    #[test]
    fn read_dir_on_file_is_not_a_directory() {
        let fs = sample();
        assert_eq!(fs.read_dir("/etc/hosts"), Err(FsError::NotADirectory));
    }

    #[test]
    fn write_creates_and_overwrites() {
        let mut fs = sample();
        fs.write("/etc/hosts", b"changed").unwrap();
        assert_eq!(fs.read("/etc/hosts").unwrap(), b"changed");
        fs.write("/etc/new", b"x").unwrap();
        assert_eq!(fs.read("/etc/new").unwrap(), b"x");
    }

    #[test]
    fn write_into_missing_parent_fails() {
        let mut fs = sample();
        assert_eq!(fs.write("/no/where", b"x"), Err(FsError::NotFound));
    }

    #[test]
    fn write_onto_directory_fails() {
        let mut fs = sample();
        assert_eq!(fs.write("/etc", b"x"), Err(FsError::IsADirectory));
    }

    #[test]
    fn create_dir_rejects_existing() {
        let mut fs = sample();
        assert_eq!(fs.create_dir("/etc"), Err(FsError::AlreadyExists));
        fs.create_dir("/etc/sub").unwrap();
        assert_eq!(fs.metadata("/etc/sub").unwrap().kind, FileKind::Dir);
    }

    #[test]
    fn remove_file_and_dir_rules() {
        let mut fs = sample();
        assert_eq!(fs.remove_file("/etc"), Err(FsError::IsADirectory));
        assert_eq!(fs.remove_dir("/etc"), Err(FsError::NotEmpty));
        fs.remove_file("/etc/hosts").unwrap();
        fs.remove_dir("/etc").unwrap();
        assert!(!fs.exists("/etc"));
    }

    #[test]
    fn remove_missing_is_not_found() {
        let mut fs = sample();
        assert_eq!(fs.remove_file("/nope"), Err(FsError::NotFound));
        assert_eq!(fs.remove_dir("/nope"), Err(FsError::NotFound));
    }

    #[test]
    fn rename_moves_subtree() {
        let mut fs = MemFs::new()
            .with_text_file("/a/one.txt", "1")
            .with_text_file("/a/sub/two.txt", "2")
            .with_dir("/dst");
        fs.rename("/a", "/dst/a").unwrap();
        assert!(!fs.exists("/a"));
        assert_eq!(fs.read_to_string("/dst/a/one.txt").unwrap(), "1");
        assert_eq!(fs.read_to_string("/dst/a/sub/two.txt").unwrap(), "2");
    }

    #[test]
    fn rename_onto_existing_fails() {
        let mut fs = sample();
        assert_eq!(
            fs.rename("/etc/hosts", "/home/user/notes.txt"),
            Err(FsError::AlreadyExists)
        );
    }

    #[test]
    fn rename_missing_source_fails() {
        let mut fs = sample();
        assert_eq!(fs.rename("/nope", "/etc/x"), Err(FsError::NotFound));
    }

    #[test]
    fn symlink_creation_and_conflict() {
        let mut fs = sample();
        fs.symlink("/etc/hosts", "/link2").unwrap();
        assert_eq!(fs.metadata("/link2").unwrap().kind, FileKind::Symlink);
        assert_eq!(fs.symlink("/x", "/link2"), Err(FsError::AlreadyExists));
    }

    #[test]
    fn read_through_symlink_is_rejected() {
        let fs = sample();
        assert_eq!(fs.read("/home/user/link"), Err(FsError::InvalidPath));
    }

    #[test]
    fn capabilities_render_as_rwx() {
        assert_eq!(Capabilities::all().as_rwx(), "rwx");
        assert_eq!(Capabilities::read_write().as_rwx(), "rw-");
    }

    #[test]
    fn owner_defaults_to_root_then_reassigns() {
        let mut fs = sample();
        assert_eq!(fs.owner("/etc/hosts"), Ok(ROOT_OWNER));
        fs.set_owner("/etc/hosts", 1000).unwrap();
        assert_eq!(fs.owner("/etc/hosts"), Ok(1000));
    }

    #[test]
    fn owner_of_missing_is_not_found() {
        let mut fs = sample();
        assert_eq!(fs.owner("/nope"), Err(FsError::NotFound));
        assert_eq!(fs.set_owner("/nope", 1), Err(FsError::NotFound));
    }

    #[test]
    fn owner_rejects_relative_path() {
        let fs = sample();
        assert_eq!(fs.owner("etc/hosts"), Err(FsError::InvalidPath));
    }

    #[test]
    fn set_capabilities_replaces_grant() {
        let mut fs = sample();
        assert!(!fs.metadata("/etc/hosts").unwrap().capabilities.execute);
        fs.set_capabilities("/etc/hosts", Capabilities::all())
            .unwrap();
        assert_eq!(
            fs.metadata("/etc/hosts").unwrap().capabilities,
            Capabilities::all()
        );
    }

    #[test]
    fn set_capabilities_on_missing_is_not_found() {
        let mut fs = sample();
        assert_eq!(
            fs.set_capabilities("/nope", Capabilities::all()),
            Err(FsError::NotFound)
        );
    }

    #[test]
    fn removing_entry_clears_recorded_owner() {
        let mut fs = sample();
        fs.set_owner("/etc/hosts", 42).unwrap();
        fs.remove_file("/etc/hosts").unwrap();
        // Recreating at the same path starts from the default owner again.
        fs.write("/etc/hosts", b"x").unwrap();
        assert_eq!(fs.owner("/etc/hosts"), Ok(ROOT_OWNER));
    }
}
