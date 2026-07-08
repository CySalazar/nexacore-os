//! `virtio-fs` host-side backend trait.
//!
//! See `NCIP-Container-006` § 3. The backend implements two operations
//! that map to the guest's filesystem syscalls:
//!
//! - `open(path, flags)` — capability-checked against `fs:read:<path>`
//!   or `fs:write:<path>` (or both). Returns a host-side file handle
//!   that the guest sees as a virtio-fs FD.
//! - `close(handle)` — releases the host-side resource.
//!
//! Capability denial returns `Err(ContainerError::Capability(...))`
//! at the host side; the guest sees a virtio-fs `EACCES` response,
//! which its kernel surfaces to the user app as a regular POSIX
//! `EACCES`. This is the mechanism by which capabilities are enforced
//! **structurally** rather than retroactively.

use std::{
    collections::HashMap,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
};

use parking_lot::Mutex;

use crate::{ContainerError, ContainerResult, caps::GrantedScopes};

/// Opaque host-side file handle. The guest sees it as a virtio-fs FD.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct FsHandle(pub u64);

/// virtio-fs backend trait.
pub trait VirtioFsBackend: Send + Sync {
    /// Open a guest-supplied path with the requested access mode.
    ///
    /// # Errors
    ///
    /// Returns [`ContainerError::Capability`] if the container does
    /// not hold the corresponding `fs:read:<path>` or `fs:write:<path>`
    /// capability, [`ContainerError::Virtio`] for any host-side I/O
    /// failure, or [`ContainerError::NotYetImplemented`] in the
    /// v0.1 scaffold.
    fn open(&self, path: &str, write: bool) -> ContainerResult<FsHandle>;

    /// Close a host-side file handle.
    ///
    /// # Errors
    ///
    /// Returns [`ContainerError::Virtio`] for host-side errors or
    /// [`ContainerError::NotYetImplemented`] in the v0.1 scaffold.
    fn close(&self, handle: FsHandle) -> ContainerResult<()>;
}

/// v0.1 stub implementation. Every call returns
/// [`ContainerError::NotYetImplemented`].
#[derive(Debug, Default)]
pub struct StubVirtioFs;

impl VirtioFsBackend for StubVirtioFs {
    fn open(&self, _path: &str, _write: bool) -> ContainerResult<FsHandle> {
        Err(ContainerError::NotYetImplemented("virtio::fs::open"))
    }
    fn close(&self, _handle: FsHandle) -> ContainerResult<()> {
        Err(ContainerError::NotYetImplemented("virtio::fs::close"))
    }
}

/// Capability-bound `virtio-fs` backend.
///
/// Every `open` is authorized against the container's [`GrantedScopes`]
/// (`Read`/`Write` on a `Filesystem` resource, honouring `/**` globs) and
/// **fails closed** on a path the container was not granted, so the guest sees
/// a structural `EACCES` rather than a retroactive denial. Handles are tracked
/// so `close` rejects unknown FDs. The real host filesystem I/O is wired on the
/// rig; the capability gate is host-tested here.
#[derive(Debug)]
pub struct CapabilityVirtioFs {
    caps: Arc<GrantedScopes>,
    handles: Mutex<HashMap<u64, (String, bool)>>,
    next: AtomicU64,
}

impl CapabilityVirtioFs {
    /// Construct a backend bound to the container's granted capabilities.
    #[must_use]
    pub fn new(caps: Arc<GrantedScopes>) -> Self {
        Self {
            caps,
            handles: Mutex::new(HashMap::new()),
            next: AtomicU64::new(1),
        }
    }

    /// Number of currently-open handles.
    #[must_use]
    pub fn open_handles(&self) -> usize {
        self.handles.lock().len()
    }
}

impl VirtioFsBackend for CapabilityVirtioFs {
    fn open(&self, path: &str, write: bool) -> ContainerResult<FsHandle> {
        if !self.caps.authorize_fs(path, write) {
            return Err(ContainerError::Capability("virtio::fs::open"));
        }
        let id = self.next.fetch_add(1, Ordering::Relaxed);
        self.handles.lock().insert(id, (path.to_owned(), write));
        Ok(FsHandle(id))
    }

    fn close(&self, handle: FsHandle) -> ContainerResult<()> {
        if self.handles.lock().remove(&handle.0).is_some() {
            Ok(())
        } else {
            Err(ContainerError::Virtio("virtio::fs::close::unknown_handle"))
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn stub_open_returns_not_yet_implemented() {
        let b = StubVirtioFs;
        let err = b.open("/tmp/x", false).expect_err("stub");
        assert!(matches!(
            err,
            ContainerError::NotYetImplemented("virtio::fs::open")
        ));
    }

    #[test]
    fn stub_close_returns_not_yet_implemented() {
        let b = StubVirtioFs;
        let err = b.close(FsHandle(0)).expect_err("stub");
        assert!(matches!(
            err,
            ContainerError::NotYetImplemented("virtio::fs::close")
        ));
    }

    #[test]
    fn capability_fs_enforces_grant_and_tracks_handles() {
        use nexacore_capability::scope::{Action, Resource, Scope, TimeWindow};
        let caps = Arc::new(GrantedScopes::from_scopes(vec![Scope {
            action: Action::Read,
            resource: Resource::Filesystem("/data/**".to_owned()),
            window: TimeWindow {
                not_before: 0,
                not_after: u64::MAX,
            },
            caveats: Vec::new(),
        }]));
        let fs = CapabilityVirtioFs::new(caps);
        // Granted read under the glob succeeds.
        let h = fs.open("/data/model.gguf", false).expect("granted read");
        assert_eq!(fs.open_handles(), 1);
        // Write not granted → fail closed.
        assert!(matches!(
            fs.open("/data/model.gguf", true),
            Err(ContainerError::Capability(_))
        ));
        // Path outside the glob → fail closed.
        assert!(matches!(
            fs.open("/etc/shadow", false),
            Err(ContainerError::Capability(_))
        ));
        // Close the open handle; closing again is an error.
        fs.close(h).expect("close");
        assert_eq!(fs.open_handles(), 0);
        assert!(matches!(fs.close(h), Err(ContainerError::Virtio(_))));
    }
}
