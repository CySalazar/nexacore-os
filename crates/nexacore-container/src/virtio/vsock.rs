//! `virtio-vsock` host-side bridge to the NexaCore IPC layer.
//!
//! See `NCIP-Container-006` § 3.

use std::{
    collections::HashSet,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
};

use parking_lot::Mutex;

use crate::{ContainerError, ContainerResult, caps::GrantedScopes};

/// virtio-vsock backend trait — bridges the guest vsock to an NexaCore
/// IPC channel.
pub trait VirtioVsockBackend: Send + Sync {
    /// Connect the guest end of a vsock to an NexaCore IPC channel by id.
    ///
    /// # Errors
    ///
    /// Returns [`ContainerError::Capability`] if the container does
    /// not hold `ipc:channel:<id>`, [`ContainerError::Virtio`] for
    /// transport errors, or [`ContainerError::NotYetImplemented`]
    /// in the v0.1 scaffold.
    fn connect_channel(&self, channel_id: &str) -> ContainerResult<u64>;
}

/// v0.1 stub.
#[derive(Debug, Default)]
pub struct StubVirtioVsock;

impl VirtioVsockBackend for StubVirtioVsock {
    fn connect_channel(&self, _channel_id: &str) -> ContainerResult<u64> {
        Err(ContainerError::NotYetImplemented(
            "virtio::vsock::connect_channel",
        ))
    }
}

/// Capability-bound `virtio-vsock` backend.
///
/// Bridges the guest vsock to a kernel IPC channel only when the container
/// holds an `IpcSend` capability on that numeric `IpcChannel` id; otherwise it
/// **fails closed**. A non-numeric channel string is rejected (the kernel
/// channel namespace is integer-keyed). Live connections are tracked so a
/// repeat connect to the same channel is idempotent. The IPC transport itself
/// is wired on the rig.
#[derive(Debug)]
pub struct CapabilityVirtioVsock {
    caps: Arc<GrantedScopes>,
    connections: Mutex<HashSet<u64>>,
    next: AtomicU64,
}

impl CapabilityVirtioVsock {
    /// Construct a backend bound to the container's granted capabilities.
    #[must_use]
    pub fn new(caps: Arc<GrantedScopes>) -> Self {
        Self {
            caps,
            connections: Mutex::new(HashSet::new()),
            next: AtomicU64::new(1),
        }
    }

    /// Number of live channel connections.
    #[must_use]
    pub fn connection_count(&self) -> usize {
        self.connections.lock().len()
    }
}

impl VirtioVsockBackend for CapabilityVirtioVsock {
    fn connect_channel(&self, channel_id: &str) -> ContainerResult<u64> {
        if !self.caps.authorize_vsock(channel_id) {
            return Err(ContainerError::Capability("virtio::vsock::connect_channel"));
        }
        // `authorize_vsock` already established the id is numeric.
        if let Ok(id) = channel_id.parse::<u64>() {
            self.connections.lock().insert(id);
        }
        Ok(self.next.fetch_add(1, Ordering::Relaxed))
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn stub_connect_channel_returns_not_yet_implemented() {
        let b = StubVirtioVsock;
        let err = b.connect_channel("inference").expect_err("stub");
        assert!(matches!(
            err,
            ContainerError::NotYetImplemented("virtio::vsock::connect_channel")
        ));
    }

    #[test]
    fn capability_vsock_enforces_channel_grant() {
        use nexacore_capability::scope::{Action, Resource, Scope, TimeWindow};
        let caps = Arc::new(GrantedScopes::from_scopes(vec![Scope {
            action: Action::IpcSend,
            resource: Resource::IpcChannel(7),
            window: TimeWindow {
                not_before: 0,
                not_after: u64::MAX,
            },
            caveats: Vec::new(),
        }]));
        let vsock = CapabilityVirtioVsock::new(caps);
        // Granted numeric channel connects.
        vsock.connect_channel("7").expect("granted");
        assert_eq!(vsock.connection_count(), 1);
        // Un-granted channel and non-numeric strings fail closed.
        assert!(matches!(
            vsock.connect_channel("8"),
            Err(ContainerError::Capability(_))
        ));
        assert!(matches!(
            vsock.connect_channel("inference"),
            Err(ContainerError::Capability(_))
        ));
    }
}
