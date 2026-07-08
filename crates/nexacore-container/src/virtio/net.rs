//! `virtio-net` host-side backend trait.
//!
//! See `NCIP-Container-006` § 3. The host-side service runs per-channel
//! firewall rules based on the container's
//! `net:outbound:<host>:<port>` / `net:inbound:<port>` capabilities.

use std::{
    collections::HashMap,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
};

use parking_lot::Mutex;

use crate::{ContainerError, ContainerResult, caps::GrantedScopes};

/// Direction tag for a network flow opened by the container.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FlowDirection {
    /// Container-initiated connection to a remote host.
    Outbound,
    /// Listener accepting connections from the host network.
    Inbound,
}

/// virtio-net backend trait.
pub trait VirtioNetBackend: Send + Sync {
    /// Open a TCP / UDP flow against the host network stack.
    ///
    /// # Errors
    ///
    /// Returns [`ContainerError::Capability`] if the firewall rule
    /// for `direction:host:port` is not granted by the container's
    /// capability set, [`ContainerError::Virtio`] for network errors,
    /// or [`ContainerError::NotYetImplemented`] in the v0.1 scaffold.
    fn open_flow(&self, direction: FlowDirection, host: &str, port: u16) -> ContainerResult<u64>;
}

/// v0.1 stub backend.
#[derive(Debug, Default)]
pub struct StubVirtioNet;

impl VirtioNetBackend for StubVirtioNet {
    fn open_flow(
        &self,
        _direction: FlowDirection,
        _host: &str,
        _port: u16,
    ) -> ContainerResult<u64> {
        Err(ContainerError::NotYetImplemented("virtio::net::open_flow"))
    }
}

/// Capability-bound `virtio-net` backend.
///
/// Enforces the container's per-flow firewall: every `open_flow` is checked
/// against the granted [`GrantedScopes`] (Connect on `Network` for outbound,
/// Listen for inbound) and **fails closed** when no matching capability is
/// held. Authorized flows are tracked by id. The capability decision — the
/// security-relevant boundary — is fully host-tested here; the live socket
/// transport is wired on the rig.
#[derive(Debug)]
pub struct CapabilityVirtioNet {
    caps: Arc<GrantedScopes>,
    flows: Mutex<HashMap<u64, (FlowDirection, String, u16)>>,
    next: AtomicU64,
}

impl CapabilityVirtioNet {
    /// Construct a backend bound to the container's granted capabilities.
    #[must_use]
    pub fn new(caps: Arc<GrantedScopes>) -> Self {
        Self {
            caps,
            flows: Mutex::new(HashMap::new()),
            next: AtomicU64::new(1),
        }
    }

    /// Number of currently-open flows.
    #[must_use]
    pub fn flow_count(&self) -> usize {
        self.flows.lock().len()
    }
}

impl VirtioNetBackend for CapabilityVirtioNet {
    fn open_flow(&self, direction: FlowDirection, host: &str, port: u16) -> ContainerResult<u64> {
        if !self.caps.authorize_net(direction, host, port) {
            return Err(ContainerError::Capability("virtio::net::open_flow"));
        }
        let id = self.next.fetch_add(1, Ordering::Relaxed);
        self.flows
            .lock()
            .insert(id, (direction, host.to_owned(), port));
        Ok(id)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use nexacore_capability::scope::{Action, Resource, Scope, TimeWindow};

    use super::*;

    fn grant(action: Action, resource: Resource) -> Scope {
        Scope {
            action,
            resource,
            window: TimeWindow {
                not_before: 0,
                not_after: u64::MAX,
            },
            caveats: Vec::new(),
        }
    }

    #[test]
    fn stub_open_flow_returns_not_yet_implemented() {
        let b = StubVirtioNet;
        let err = b
            .open_flow(FlowDirection::Outbound, "huggingface.co", 443)
            .expect_err("stub");
        assert!(matches!(
            err,
            ContainerError::NotYetImplemented("virtio::net::open_flow")
        ));
    }

    #[test]
    fn capability_net_allows_granted_flow_denies_others() {
        let caps = Arc::new(GrantedScopes::from_scopes(vec![grant(
            Action::Connect,
            Resource::Network("huggingface.co:443".to_owned()),
        )]));
        let net = CapabilityVirtioNet::new(caps);
        // Granted outbound flow opens and is tracked.
        let id = net
            .open_flow(FlowDirection::Outbound, "huggingface.co", 443)
            .expect("granted");
        assert_eq!(id, 1);
        assert_eq!(net.flow_count(), 1);
        // Un-granted endpoint fails closed.
        let err = net
            .open_flow(FlowDirection::Outbound, "evil.example", 443)
            .expect_err("denied");
        assert!(matches!(err, ContainerError::Capability(_)));
        assert_eq!(net.flow_count(), 1);
    }
}
