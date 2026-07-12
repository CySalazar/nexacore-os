//! `mount` / `umount` — an in-memory mount-table model (WS8-10.3).
//!
//! This is the **value logic** of mounting: a [`MountTable`] that records which
//! sources are attached at which targets, with which filesystem type and
//! options. It performs no real syscalls — on hardware the shell drives the
//! kernel VFS and mirrors the result into a table shaped like this one; host
//! tests exercise the ordering, listing, and fail-closed rules directly.
//!
//! ## Fail-closed rules
//!
//! - **Double-mount** — mounting onto a target that already carries a mount is
//!   [`MountError::AlreadyMounted`]; the table is unchanged.
//! - **Unknown target** — unmounting a target that is not mounted is
//!   [`MountError::NotMounted`]; the table is unchanged.
//! - **Invalid target** — a non-absolute target is [`MountError::InvalidTarget`].
//!
//! ## Listing
//!
//! A bare `mount` (no arguments) lists the current mounts in mount order, one
//! per line, in the classic Linux shape: `source on target type fstype (options)`.

use alloc::{
    string::{String, ToString},
    vec::Vec,
};

use crate::path;

/// One recorded mount: a `source` attached at `target` with a filesystem type
/// and a comma-separated options string.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MountEntry {
    /// The mounted device or source (e.g. `/dev/sda1`, `tmpfs`).
    pub source: String,
    /// The absolute, normalized mount point.
    pub target: String,
    /// The filesystem type (e.g. `ext4`, `tmpfs`, `ncfs`).
    pub fstype: String,
    /// The comma-separated mount options (e.g. `rw,relatime`); may be empty.
    pub options: String,
}

impl MountEntry {
    /// Render this entry in the classic `mount` listing shape:
    /// `source on target type fstype (options)`.
    #[must_use]
    pub fn to_line(&self) -> String {
        let mut line = String::new();
        line.push_str(&self.source);
        line.push_str(" on ");
        line.push_str(&self.target);
        line.push_str(" type ");
        line.push_str(&self.fstype);
        line.push_str(" (");
        line.push_str(&self.options);
        line.push(')');
        line
    }
}

/// Why a mount-table operation failed. Fail-closed: each variant leaves the table
/// unchanged.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MountError {
    /// The target already carries a mount (double-mount refused).
    AlreadyMounted,
    /// The target is not currently mounted (nothing to unmount).
    NotMounted,
    /// The target was not an absolute path.
    InvalidTarget,
}

impl core::fmt::Display for MountError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let msg = match self {
            Self::AlreadyMounted => "target is already mounted",
            Self::NotMounted => "target is not mounted",
            Self::InvalidTarget => "invalid (non-absolute) mount target",
        };
        f.write_str(msg)
    }
}

/// An ordered, in-memory table of the current mounts.
///
/// Entries are kept in mount order (first mounted first) so a listing is stable
/// and reproducible. Targets are normalized on the way in, so `/mnt` and
/// `/mnt/./` name the same mount point.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MountTable {
    /// The mounts, in the order they were established.
    entries: Vec<MountEntry>,
}

impl MountTable {
    /// An empty mount table.
    #[must_use]
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    /// Attach `source` at `target` with filesystem type `fstype` and `options`.
    ///
    /// The target is normalized before being recorded.
    ///
    /// # Errors
    ///
    /// - [`MountError::InvalidTarget`] if `target` is not absolute.
    /// - [`MountError::AlreadyMounted`] if the (normalized) target already
    ///   carries a mount.
    pub fn mount(
        &mut self,
        source: &str,
        target: &str,
        fstype: &str,
        options: &str,
    ) -> Result<(), MountError> {
        if !path::is_absolute(target) {
            return Err(MountError::InvalidTarget);
        }
        let normalized = path::normalize(target);
        if self.index_of(&normalized).is_some() {
            return Err(MountError::AlreadyMounted);
        }
        self.entries.push(MountEntry {
            source: source.to_string(),
            target: normalized,
            fstype: fstype.to_string(),
            options: options.to_string(),
        });
        Ok(())
    }

    /// Detach the mount at `target`.
    ///
    /// The target is normalized before lookup.
    ///
    /// # Errors
    ///
    /// - [`MountError::InvalidTarget`] if `target` is not absolute.
    /// - [`MountError::NotMounted`] if no mount exists at the (normalized) target.
    pub fn umount(&mut self, target: &str) -> Result<(), MountError> {
        if !path::is_absolute(target) {
            return Err(MountError::InvalidTarget);
        }
        let normalized = path::normalize(target);
        match self.index_of(&normalized) {
            Some(idx) => {
                self.entries.remove(idx);
                Ok(())
            }
            None => Err(MountError::NotMounted),
        }
    }

    /// Whether a mount currently exists at `target` (normalized).
    #[must_use]
    pub fn is_mounted(&self, target: &str) -> bool {
        if !path::is_absolute(target) {
            return false;
        }
        self.index_of(&path::normalize(target)).is_some()
    }

    /// The current mounts, in mount order.
    #[must_use]
    pub fn entries(&self) -> &[MountEntry] {
        &self.entries
    }

    /// Render the current mounts as `mount`-style listing lines, in mount order.
    #[must_use]
    pub fn list_lines(&self) -> Vec<String> {
        self.entries.iter().map(MountEntry::to_line).collect()
    }

    /// The index of the entry whose (already normalized) target equals `target`.
    fn index_of(&self, target: &str) -> Option<usize> {
        self.entries.iter().position(|e| e.target == target)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn table() -> MountTable {
        let mut t = MountTable::new();
        t.mount("/dev/sda1", "/", "ext4", "rw,relatime").unwrap();
        t.mount("tmpfs", "/tmp", "tmpfs", "rw,nosuid").unwrap();
        t
    }

    #[test]
    fn mount_records_in_order() {
        let t = table();
        let targets: Vec<&str> = t.entries().iter().map(|e| e.target.as_str()).collect();
        assert_eq!(targets, ["/", "/tmp"]);
    }

    #[test]
    fn double_mount_is_fail_closed() {
        let mut t = table();
        assert_eq!(
            t.mount("other", "/tmp", "tmpfs", ""),
            Err(MountError::AlreadyMounted)
        );
        // Table is unchanged: still exactly two mounts, original source kept.
        assert_eq!(t.entries().len(), 2);
        assert_eq!(
            t.entries()
                .iter()
                .find(|e| e.target == "/tmp")
                .map(|e| e.source.as_str()),
            Some("tmpfs")
        );
    }

    #[test]
    fn double_mount_detected_after_normalization() {
        let mut t = table();
        assert_eq!(
            t.mount("x", "/tmp/./", "tmpfs", ""),
            Err(MountError::AlreadyMounted)
        );
    }

    #[test]
    fn umount_removes_entry() {
        let mut t = table();
        t.umount("/tmp").unwrap();
        assert!(!t.is_mounted("/tmp"));
        assert!(t.is_mounted("/"));
        assert_eq!(t.entries().len(), 1);
    }

    #[test]
    fn umount_unknown_target_is_fail_closed() {
        let mut t = table();
        assert_eq!(t.umount("/nope"), Err(MountError::NotMounted));
        assert_eq!(t.entries().len(), 2);
    }

    #[test]
    fn non_absolute_target_is_invalid() {
        let mut t = MountTable::new();
        assert_eq!(
            t.mount("s", "relative/path", "ext4", ""),
            Err(MountError::InvalidTarget)
        );
        assert_eq!(t.umount("relative"), Err(MountError::InvalidTarget));
        assert!(!t.is_mounted("relative"));
    }

    #[test]
    fn list_lines_classic_shape() {
        let t = table();
        assert_eq!(
            t.list_lines(),
            [
                "/dev/sda1 on / type ext4 (rw,relatime)",
                "tmpfs on /tmp type tmpfs (rw,nosuid)",
            ]
        );
    }

    #[test]
    fn empty_options_render_as_empty_parens() {
        let mut t = MountTable::new();
        t.mount("proc", "/proc", "proc", "").unwrap();
        assert_eq!(t.list_lines(), ["proc on /proc type proc ()"]);
    }

    #[test]
    fn remount_after_umount_is_allowed() {
        let mut t = table();
        t.umount("/tmp").unwrap();
        assert_eq!(t.mount("tmpfs2", "/tmp", "tmpfs", "ro"), Ok(()));
        assert!(t.is_mounted("/tmp"));
    }

    #[test]
    fn error_display_is_human_readable() {
        use alloc::format;
        assert_eq!(
            format!("{}", MountError::AlreadyMounted),
            "target is already mounted"
        );
        assert_eq!(
            format!("{}", MountError::NotMounted),
            "target is not mounted"
        );
    }
}
