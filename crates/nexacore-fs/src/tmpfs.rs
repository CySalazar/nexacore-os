//! In-memory temporary filesystem (`tmpfs`) — a writable [`VfsBackend`]
//! (WS3-04.1/.2).
//!
//! A tmpfs holds its whole tree in RAM: directories and file bodies live in a
//! [`BTreeMap`] keyed by the file's normalised path segments (the root is the
//! empty key). It is the volatile filesystem the VFS mounts on `/tmp`
//! (WS3-04.2) and, more generally, the reference backend for the
//! [`crate::vfs`] namespace machinery.
//!
//! The type exposes a full CRUD API (`mkdir`/`create`/`write_at`/`read_at`/
//! `remove`/`list`/`stat`), and *also* implements the read-only [`VfsBackend`]
//! trait so a `Tmpfs` can be mounted and read through the VFS. Writes go through
//! the inherent API; wiring a writable VFS write-path through the trait is a
//! later WS3-02 extension.

use alloc::{collections::BTreeMap, string::String, vec::Vec};

use crate::{
    FileType, FsError,
    vfs::{VfsBackend, VfsDirEntry, VfsMetadata},
};

/// A tmpfs node: a directory or a file with an in-memory body.
enum TmpNode {
    /// A directory. Its children are the keys one segment longer.
    Dir,
    /// A regular file holding `len` bytes in memory.
    File(Vec<u8>),
}

impl TmpNode {
    fn file_type(&self) -> FileType {
        match self {
            Self::Dir => FileType::Directory,
            Self::File(_) => FileType::RegularFile,
        }
    }

    fn len(&self) -> u64 {
        match self {
            Self::Dir => 0,
            Self::File(body) => u64::try_from(body.len()).unwrap_or(u64::MAX),
        }
    }
}

/// An in-memory temporary filesystem.
///
/// Paths are normalised segment slices (`&[&str]`) relative to the filesystem
/// root; the empty slice is the root directory, which always exists.
#[derive(Default)]
pub struct Tmpfs {
    nodes: BTreeMap<Vec<String>, TmpNode>,
}

impl Tmpfs {
    /// Create a tmpfs containing only the root directory.
    #[must_use]
    pub fn new() -> Self {
        let mut nodes = BTreeMap::new();
        nodes.insert(Vec::new(), TmpNode::Dir);
        Self { nodes }
    }

    fn key(rel: &[&str]) -> Vec<String> {
        rel.iter().map(|segment| String::from(*segment)).collect()
    }

    /// Verify that the parent of `rel` exists and is a directory (the root has
    /// no parent and always passes).
    fn ensure_parent_dir(&self, rel: &[&str]) -> Result<(), FsError> {
        match rel.split_last() {
            None => Ok(()),
            Some((_, parent)) => match self.nodes.get(&Self::key(parent)) {
                Some(TmpNode::Dir) => Ok(()),
                Some(TmpNode::File(_)) => Err(FsError::NotADirectory),
                None => Err(FsError::FileNotFound),
            },
        }
    }

    /// Whether `key` has any direct child in the tree.
    fn has_children(&self, key: &[String]) -> bool {
        self.nodes
            .keys()
            .any(|k| k.len() == key.len() + 1 && k.get(..key.len()) == Some(key))
    }

    /// Create the directory at `rel`.
    ///
    /// # Errors
    /// [`FsError::FileAlreadyExists`] if the path is taken;
    /// [`FsError::FileNotFound`] / [`FsError::NotADirectory`] if the parent is
    /// missing or not a directory.
    pub fn mkdir(&mut self, rel: &[&str]) -> Result<(), FsError> {
        let key = Self::key(rel);
        if self.nodes.contains_key(&key) {
            return Err(FsError::FileAlreadyExists);
        }
        self.ensure_parent_dir(rel)?;
        self.nodes.insert(key, TmpNode::Dir);
        Ok(())
    }

    /// Create an empty file at `rel`.
    ///
    /// # Errors
    /// [`FsError::FileAlreadyExists`] if the path is taken;
    /// [`FsError::FileNotFound`] / [`FsError::NotADirectory`] if the parent is
    /// missing or not a directory.
    pub fn create(&mut self, rel: &[&str]) -> Result<(), FsError> {
        let key = Self::key(rel);
        if self.nodes.contains_key(&key) {
            return Err(FsError::FileAlreadyExists);
        }
        self.ensure_parent_dir(rel)?;
        self.nodes.insert(key, TmpNode::File(Vec::new()));
        Ok(())
    }

    /// Write `data` to the file at `rel` starting at `offset`, creating the file
    /// if absent and zero-extending the body if the write starts past its end.
    /// Returns the number of bytes written.
    ///
    /// # Errors
    /// [`FsError::NotAFile`] if `rel` is a directory;
    /// [`FsError::FileNotFound`] / [`FsError::NotADirectory`] if the parent is
    /// missing or not a directory; [`FsError::NoSpace`] if the write would
    /// exceed addressable memory.
    pub fn write_at(&mut self, rel: &[&str], offset: u64, data: &[u8]) -> Result<usize, FsError> {
        let key = Self::key(rel);
        if !self.nodes.contains_key(&key) {
            self.ensure_parent_dir(rel)?;
            self.nodes.insert(key.clone(), TmpNode::File(Vec::new()));
        }
        match self.nodes.get_mut(&key) {
            Some(TmpNode::File(body)) => {
                let start = usize::try_from(offset).map_err(|_| FsError::NoSpace)?;
                let end = start.checked_add(data.len()).ok_or(FsError::NoSpace)?;
                if body.len() < end {
                    body.resize(end, 0);
                }
                if let Some(dst) = body.get_mut(start..end) {
                    dst.copy_from_slice(data);
                }
                Ok(data.len())
            }
            Some(TmpNode::Dir) => Err(FsError::NotAFile),
            None => Err(FsError::FileNotFound),
        }
    }

    /// Read up to `out.len()` bytes from the file at `rel` starting at `offset`,
    /// returning the number of bytes read (`0` at or past end of file).
    ///
    /// # Errors
    /// [`FsError::NotAFile`] if `rel` is a directory;
    /// [`FsError::FileNotFound`] if `rel` does not exist.
    pub fn read_at(&self, rel: &[&str], offset: u64, out: &mut [u8]) -> Result<usize, FsError> {
        match self.nodes.get(&Self::key(rel)) {
            Some(TmpNode::File(body)) => {
                let start = usize::try_from(offset)
                    .unwrap_or(usize::MAX)
                    .min(body.len());
                let avail = body.get(start..).unwrap_or(&[]);
                let n = avail.len().min(out.len());
                if let (Some(src), Some(dst)) = (avail.get(..n), out.get_mut(..n)) {
                    dst.copy_from_slice(src);
                }
                Ok(n)
            }
            Some(TmpNode::Dir) => Err(FsError::NotAFile),
            None => Err(FsError::FileNotFound),
        }
    }

    /// Remove the file or empty directory at `rel`.
    ///
    /// # Errors
    /// [`FsError::FileNotFound`] if `rel` does not exist;
    /// [`FsError::DirectoryNotEmpty`] if `rel` is a directory with children.
    pub fn remove(&mut self, rel: &[&str]) -> Result<(), FsError> {
        let key = Self::key(rel);
        match self.nodes.get(&key) {
            None => return Err(FsError::FileNotFound),
            Some(TmpNode::Dir) => {
                if self.has_children(&key) {
                    return Err(FsError::DirectoryNotEmpty);
                }
            }
            Some(TmpNode::File(_)) => {}
        }
        self.nodes.remove(&key);
        Ok(())
    }

    /// List the direct children of the directory at `rel`.
    ///
    /// # Errors
    /// [`FsError::NotADirectory`] if `rel` is a file;
    /// [`FsError::FileNotFound`] if `rel` does not exist.
    pub fn list(&self, rel: &[&str]) -> Result<Vec<VfsDirEntry>, FsError> {
        let key = Self::key(rel);
        match self.nodes.get(&key) {
            Some(TmpNode::Dir) => {
                let mut out = Vec::new();
                for (child_key, node) in &self.nodes {
                    if child_key.len() == key.len() + 1
                        && child_key.get(..key.len()) == Some(key.as_slice())
                    {
                        if let Some(name) = child_key.last() {
                            out.push(VfsDirEntry {
                                name: name.clone(),
                                file_type: node.file_type(),
                            });
                        }
                    }
                }
                Ok(out)
            }
            Some(TmpNode::File(_)) => Err(FsError::NotADirectory),
            None => Err(FsError::FileNotFound),
        }
    }

    /// Report metadata for the node at `rel`.
    ///
    /// # Errors
    /// [`FsError::FileNotFound`] if `rel` does not exist.
    pub fn stat(&self, rel: &[&str]) -> Result<VfsMetadata, FsError> {
        self.nodes
            .get(&Self::key(rel))
            .map_or(Err(FsError::FileNotFound), |node| {
                Ok(VfsMetadata {
                    file_type: node.file_type(),
                    len: node.len(),
                })
            })
    }

    /// Whether a node exists at `rel`.
    #[must_use]
    pub fn exists(&self, rel: &[&str]) -> bool {
        self.nodes.contains_key(&Self::key(rel))
    }
}

impl VfsBackend for Tmpfs {
    fn name(&self) -> &'static str {
        "tmpfs"
    }

    fn metadata(&self, rel: &[&str]) -> Result<VfsMetadata, FsError> {
        self.stat(rel)
    }

    fn read_dir(&self, rel: &[&str]) -> Result<Vec<VfsDirEntry>, FsError> {
        self.list(rel)
    }

    fn read(&self, rel: &[&str], offset: u64, buf: &mut [u8]) -> Result<usize, FsError> {
        self.read_at(rel, offset, buf)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use alloc::boxed::Box;

    use super::*;
    use crate::vfs::MountTable;

    #[test]
    fn crud_roundtrip() {
        let mut fs = Tmpfs::new();
        fs.mkdir(&["docs"]).unwrap();
        fs.create(&["docs", "a.txt"]).unwrap();
        assert_eq!(fs.write_at(&["docs", "a.txt"], 0, b"hello").unwrap(), 5);

        let mut buf = [0u8; 8];
        assert_eq!(fs.read_at(&["docs", "a.txt"], 0, &mut buf).unwrap(), 5);
        assert_eq!(&buf[..5], b"hello");

        // Metadata reflects the write; the directory has size 0.
        assert_eq!(fs.stat(&["docs", "a.txt"]).unwrap().len, 5);
        assert_eq!(fs.stat(&["docs"]).unwrap().file_type, FileType::Directory);

        // Listing the directory shows the file.
        let entries = fs.list(&["docs"]).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].name, "a.txt");
        assert_eq!(entries[0].file_type, FileType::RegularFile);
    }

    #[test]
    fn write_extends_and_offsets() {
        let mut fs = Tmpfs::new();
        // Write-creates the file, zero-extending to reach the offset.
        assert_eq!(fs.write_at(&["log"], 4, b"XY").unwrap(), 2);
        let mut buf = [0xFFu8; 6];
        assert_eq!(fs.read_at(&["log"], 0, &mut buf).unwrap(), 6);
        assert_eq!(&buf, &[0, 0, 0, 0, b'X', b'Y']);
        // Reading past the end yields zero bytes.
        assert_eq!(fs.read_at(&["log"], 100, &mut buf).unwrap(), 0);
    }

    #[test]
    fn error_cases() {
        let mut fs = Tmpfs::new();
        fs.create(&["f"]).unwrap();
        // Duplicate create.
        assert_eq!(fs.create(&["f"]).unwrap_err(), FsError::FileAlreadyExists);
        // A file cannot be a parent.
        assert_eq!(
            fs.create(&["f", "child"]).unwrap_err(),
            FsError::NotADirectory
        );
        // Missing parent directory.
        assert_eq!(
            fs.create(&["ghost", "x"]).unwrap_err(),
            FsError::FileNotFound
        );
        // Reading a directory / a missing file.
        assert_eq!(
            fs.read_at(&[], 0, &mut [0u8; 1]).unwrap_err(),
            FsError::NotAFile
        );
        assert_eq!(fs.stat(&["nope"]).unwrap_err(), FsError::FileNotFound);
    }

    #[test]
    fn remove_respects_directory_emptiness() {
        let mut fs = Tmpfs::new();
        fs.mkdir(&["d"]).unwrap();
        fs.create(&["d", "f"]).unwrap();
        assert_eq!(fs.remove(&["d"]).unwrap_err(), FsError::DirectoryNotEmpty);
        fs.remove(&["d", "f"]).unwrap();
        fs.remove(&["d"]).unwrap();
        assert!(!fs.exists(&["d"]));
        assert_eq!(fs.remove(&["gone"]).unwrap_err(), FsError::FileNotFound);
    }

    #[test]
    fn mounts_and_reads_through_the_vfs() {
        let mut fs = Tmpfs::new();
        fs.create(&["note"]).unwrap();
        fs.write_at(&["note"], 0, b"vfs").unwrap();

        // Mount the populated tmpfs at /tmp and read it back through the VFS
        // routing facade (proves the VfsBackend adapter works end-to-end).
        let mut table = MountTable::new();
        table.mount("/tmp", Box::new(fs)).unwrap();
        assert_eq!(table.metadata("/tmp/note").unwrap().len, 3);
        let mut buf = [0u8; 3];
        assert_eq!(table.read("/tmp/note", 0, &mut buf).unwrap(), 3);
        assert_eq!(&buf, b"vfs");
    }
}
