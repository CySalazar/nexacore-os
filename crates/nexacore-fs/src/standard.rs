//! Standard virtual-filesystem mounts: `/dev`, `/proc`, `/tmp` (WS3-02.8).
//!
//! Early in boot the VFS is populated with the synthetic filesystems every
//! process expects to find: the device namespace [`Devfs`] at `/dev`
//! (WS3-02.8), the process-introspection [`ProcFs`] at `/proc` (WS3-02.9), and a
//! writable [`Tmpfs`] scratch area at `/tmp`. [`mount_standard`] performs that
//! wiring in one call so the mount points are consistent across the system, and
//! the canonical paths are exported as constants so callers never hard-code
//! them.

use alloc::boxed::Box;

use crate::{
    devfs::Devfs,
    procfs::ProcFs,
    tmpfs::Tmpfs,
    vfs::{MountTable, VfsError},
};

/// Canonical mount point of the device filesystem ([`Devfs`]).
pub const DEV_MOUNT: &str = "/dev";
/// Canonical mount point of the process-introspection filesystem ([`ProcFs`]).
pub const PROC_MOUNT: &str = "/proc";
/// Canonical mount point of the temporary filesystem ([`Tmpfs`]).
pub const TMP_MOUNT: &str = "/tmp";

/// Mount the standard virtual filesystems into `table`: [`Devfs`] at
/// [`DEV_MOUNT`], [`ProcFs`] at [`PROC_MOUNT`], and a writable [`Tmpfs`] at
/// [`TMP_MOUNT`].
///
/// The `devfs` ships with the `null` and `zero` pseudo-devices; the `procfs`
/// and `tmpfs` start empty and are populated at runtime by the process manager
/// and by writes respectively.
///
/// # Errors
///
/// Propagates [`VfsError::AlreadyMounted`] if any of the three mount points is
/// already taken (e.g. calling this twice on the same table). On error the
/// earlier successful mounts in this call remain in place.
pub fn mount_standard(table: &mut MountTable) -> Result<(), VfsError> {
    table.mount(DEV_MOUNT, Box::new(Devfs::new()))?;
    table.mount(PROC_MOUNT, Box::new(ProcFs::new()))?;
    table.mount(TMP_MOUNT, Box::new(Tmpfs::new()))?;
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::FileType;

    #[test]
    fn mounts_dev_proc_and_tmp() {
        let mut table = MountTable::new();
        mount_standard(&mut table).unwrap();
        assert!(table.is_mounted(DEV_MOUNT).unwrap());
        assert!(table.is_mounted(PROC_MOUNT).unwrap());
        assert!(table.is_mounted(TMP_MOUNT).unwrap());
    }

    #[test]
    fn dev_nodes_resolve_through_the_vfs() {
        let mut table = MountTable::new();
        mount_standard(&mut table).unwrap();
        // /dev/null and /dev/zero are reachable via the mounted devfs.
        assert_eq!(
            table.metadata("/dev/null").unwrap().file_type,
            FileType::RegularFile
        );
        let mut buf = [7u8; 4];
        assert_eq!(table.read("/dev/zero", 0, &mut buf).unwrap(), 4);
        assert_eq!(buf, [0; 4]);
    }

    #[test]
    fn remounting_is_rejected() {
        let mut table = MountTable::new();
        mount_standard(&mut table).unwrap();
        // A second call collides on /dev (the first mount point).
        assert_eq!(
            mount_standard(&mut table).unwrap_err(),
            VfsError::AlreadyMounted
        );
    }
}
