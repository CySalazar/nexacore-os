//! Device filesystem (`devfs`) — a read-only [`VfsBackend`] exposing device
//! nodes (WS3-04.3/.4).
//!
//! devfs is a flat namespace of named device nodes mounted at `/dev`. It ships
//! with the standard pseudo-devices `null` and `zero` (whose read semantics are
//! implemented here), and drivers register their character/block devices via
//! [`Devfs::register`] so they appear under `/dev` (the mechanism for WS3-04.4;
//! the actual data path for a driver-backed node is the driver's, wired at
//! integration time).
//!
//! Because [`crate::FileType`] models only files and directories, a device node
//! is reported as a [`FileType::RegularFile`]; the [`DeviceKind`] carries the
//! real classification (char vs block, major/minor).

use alloc::{collections::BTreeMap, string::String, vec::Vec};

use crate::{
    FileType, FsError,
    vfs::{VfsBackend, VfsDirEntry, VfsMetadata},
};

/// The kind of a device node, which also determines its read semantics.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeviceKind {
    /// Discards writes and reads as end-of-file (`/dev/null`).
    Null,
    /// Reads as an unbounded stream of zero bytes (`/dev/zero`).
    Zero,
    /// A character device exposed by a driver, identified by `(major, minor)`.
    /// Its data path is the driver's; devfs reads return `0` until wired.
    Char {
        /// Driver major number.
        major: u32,
        /// Device minor number.
        minor: u32,
    },
    /// A block device exposed by a driver, identified by `(major, minor)`.
    /// Its data path is the driver's; devfs reads return `0` until wired.
    Block {
        /// Driver major number.
        major: u32,
        /// Device minor number.
        minor: u32,
    },
}

/// The device filesystem: a flat map of device name → [`DeviceKind`].
#[derive(Debug, Clone, Default)]
pub struct Devfs {
    nodes: BTreeMap<String, DeviceKind>,
}

impl Devfs {
    /// Create a devfs pre-populated with the standard `null` and `zero`
    /// pseudo-devices.
    #[must_use]
    pub fn new() -> Self {
        let mut nodes = BTreeMap::new();
        nodes.insert(String::from("null"), DeviceKind::Null);
        nodes.insert(String::from("zero"), DeviceKind::Zero);
        Self { nodes }
    }

    /// Create an empty devfs (no standard pseudo-devices).
    #[must_use]
    pub fn empty() -> Self {
        Self {
            nodes: BTreeMap::new(),
        }
    }

    /// Register a device node under `name`, replacing any existing node of the
    /// same name (the WS3-04.4 driver-population mechanism).
    pub fn register(&mut self, name: &str, kind: DeviceKind) {
        self.nodes.insert(String::from(name), kind);
    }

    /// Remove the device node `name`, returning its kind if it existed.
    pub fn unregister(&mut self, name: &str) -> Option<DeviceKind> {
        self.nodes.remove(name)
    }

    /// The kind of the device node `name`, if present.
    #[must_use]
    pub fn kind(&self, name: &str) -> Option<DeviceKind> {
        self.nodes.get(name).copied()
    }

    /// The number of registered device nodes.
    #[must_use]
    pub fn len(&self) -> usize {
        self.nodes.len()
    }

    /// Whether no device nodes are registered.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.nodes.is_empty()
    }
}

impl VfsBackend for Devfs {
    fn name(&self) -> &'static str {
        "devfs"
    }

    fn metadata(&self, rel: &[&str]) -> Result<VfsMetadata, FsError> {
        // devfs is flat: `[]` is the root directory; `[name]` is a device node.
        match rel {
            [] => Ok(VfsMetadata {
                file_type: FileType::Directory,
                len: 0,
            }),
            [name] if self.nodes.contains_key(*name) => Ok(VfsMetadata {
                file_type: FileType::RegularFile,
                len: 0,
            }),
            _ => Err(FsError::FileNotFound),
        }
    }

    fn read_dir(&self, rel: &[&str]) -> Result<Vec<VfsDirEntry>, FsError> {
        match rel {
            [] => Ok(self
                .nodes
                .keys()
                .map(|name| VfsDirEntry {
                    name: name.clone(),
                    file_type: FileType::RegularFile,
                })
                .collect()),
            // A device node is not a directory.
            [name] if self.nodes.contains_key(*name) => Err(FsError::NotADirectory),
            _ => Err(FsError::FileNotFound),
        }
    }

    fn read(&self, rel: &[&str], _offset: u64, buf: &mut [u8]) -> Result<usize, FsError> {
        let kind = match rel {
            [name] => self.nodes.get(*name).copied(),
            _ => None,
        }
        .ok_or(FsError::FileNotFound)?;
        match kind {
            // `/dev/zero` fills the buffer with zero bytes.
            DeviceKind::Zero => {
                buf.fill(0);
                Ok(buf.len())
            }
            // `/dev/null` is EOF; driver-backed nodes have no host-side data
            // path yet — all read as no data.
            DeviceKind::Null | DeviceKind::Char { .. } | DeviceKind::Block { .. } => Ok(0),
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use alloc::boxed::Box;

    use super::*;
    use crate::vfs::MountTable;

    #[test]
    fn standard_nodes_present() {
        let fs = Devfs::new();
        assert_eq!(fs.len(), 2);
        assert_eq!(fs.kind("null"), Some(DeviceKind::Null));
        assert_eq!(fs.kind("zero"), Some(DeviceKind::Zero));
        assert_eq!(fs.kind("missing"), None);
    }

    #[test]
    fn null_and_zero_read_semantics() {
        let fs = Devfs::new();
        let mut buf = [0xAAu8; 4];
        // /dev/null → EOF, buffer untouched.
        assert_eq!(fs.read(&["null"], 0, &mut buf).unwrap(), 0);
        assert_eq!(buf, [0xAA; 4]);
        // /dev/zero → fills with zeros.
        assert_eq!(fs.read(&["zero"], 0, &mut buf).unwrap(), 4);
        assert_eq!(buf, [0; 4]);
    }

    #[test]
    fn register_and_unregister_driver_devices() {
        let mut fs = Devfs::empty();
        assert!(fs.is_empty());
        fs.register("sda", DeviceKind::Block { major: 8, minor: 0 });
        fs.register("tty0", DeviceKind::Char { major: 4, minor: 0 });
        assert_eq!(fs.len(), 2);
        assert_eq!(
            fs.kind("sda"),
            Some(DeviceKind::Block { major: 8, minor: 0 })
        );
        // A driver-backed node reads as no-data until its path is wired.
        let mut buf = [1u8; 2];
        assert_eq!(fs.read(&["sda"], 0, &mut buf).unwrap(), 0);
        assert_eq!(
            fs.unregister("sda"),
            Some(DeviceKind::Block { major: 8, minor: 0 })
        );
        assert_eq!(fs.unregister("sda"), None);
        assert_eq!(fs.len(), 1);
    }

    #[test]
    fn enumerates_and_mounts_under_dev() {
        let fs = Devfs::new();
        // Root lists the device nodes.
        let mut names: Vec<String> = fs
            .read_dir(&[])
            .unwrap()
            .into_iter()
            .map(|entry| entry.name)
            .collect();
        names.sort();
        assert_eq!(
            names,
            alloc::vec![String::from("null"), String::from("zero")]
        );
        // A device path is not a directory; an unknown one is not found.
        assert_eq!(fs.read_dir(&["null"]).unwrap_err(), FsError::NotADirectory);
        assert_eq!(fs.metadata(&["ghost"]).unwrap_err(), FsError::FileNotFound);

        // Mount at /dev and read /dev/zero through the VFS facade.
        let mut table = MountTable::new();
        table.mount("/dev", Box::new(fs)).unwrap();
        assert_eq!(
            table.metadata("/dev/zero").unwrap().file_type,
            FileType::RegularFile
        );
        let mut buf = [9u8; 3];
        assert_eq!(table.read("/dev/zero", 0, &mut buf).unwrap(), 3);
        assert_eq!(buf, [0; 3]);
    }
}
