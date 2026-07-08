//! Capability binding for virtio backends.
//!
//! See `NCIP-Container-006` § 3 ("virtio device backing and capability
//! binding"). Every guest↔host I/O path is mediated by a host-side backend
//! that performs a **fail-closed** capability check before touching any host
//! resource. The authority is carried by [`nexacore_capability::CapabilityToken`]s
//! granted to the container at launch; this module reduces a token set to the
//! [`Scope`]s it grants and answers per-device authorization questions.
//!
//! Authorization uses the canonical attenuation relation
//! [`Scope::is_subset_of`]: a *request* (e.g. "Connect to `huggingface.co:443`")
//! is permitted iff it is at least as restrictive as some granted scope (e.g.
//! "Connect to `*:443`"). Resource wildcards (`Filesystem("/data/**")`,
//! `Network("*:443")`) are handled inside [`nexacore_capability::Resource::is_subset_of`].
//!
//! Signature / time-window / TEE-binding verification of the tokens themselves
//! is the caller's responsibility (`CapabilityToken::verify_full`); this gate
//! assumes the scopes it is handed have already been validated, and only
//! decides resource authorization.

use nexacore_capability::{
    CapabilityToken,
    scope::{Action, Resource, Scope, TimeWindow},
};

use crate::virtio::net::FlowDirection;

/// The set of [`Scope`]s a container has been granted.
///
/// Constructed from validated capability tokens (or scopes directly for
/// testing). All authorization is **deny-by-default**: an empty grant set
/// authorizes nothing.
#[derive(Debug, Clone, Default)]
pub struct GrantedScopes {
    scopes: Vec<Scope>,
}

impl GrantedScopes {
    /// An empty grant set (authorizes nothing).
    #[must_use]
    pub fn empty() -> Self {
        Self { scopes: Vec::new() }
    }

    /// Build a grant set from a list of scopes.
    #[must_use]
    pub fn from_scopes(scopes: Vec<Scope>) -> Self {
        Self { scopes }
    }

    /// Build a grant set from validated capability tokens. Each token
    /// contributes its single [`Scope`].
    #[must_use]
    pub fn from_tokens(tokens: &[CapabilityToken]) -> Self {
        Self {
            scopes: tokens.iter().map(|t| t.payload.scope.clone()).collect(),
        }
    }

    /// Number of granted scopes.
    #[must_use]
    pub fn len(&self) -> usize {
        self.scopes.len()
    }

    /// Whether the grant set is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.scopes.is_empty()
    }

    /// Core authorization predicate: is `request` permitted by any granted
    /// scope? `request` is permitted iff `request.is_subset_of(granted)` for
    /// some granted scope.
    #[must_use]
    pub fn permits(&self, request: &Scope) -> bool {
        self.scopes.iter().any(|g| request.is_subset_of(g))
    }

    /// Build an unconstrained request scope (open time window, no caveats) for a
    /// concrete `(action, resource)` pair. The maximal window is a subset of
    /// any granted window, so the resource/action match drives the decision.
    fn request(action: Action, resource: Resource) -> Scope {
        Scope {
            action,
            resource,
            // `[0, u64::MAX)` is the widest legal window; it is a subset of any
            // granted window per `TimeWindow::is_subset_of`, so an unexpired
            // grant authorizes it. Built field-wise (the bound is always valid)
            // to avoid an `unwrap` in non-test code.
            window: TimeWindow {
                not_before: 0,
                not_after: u64::MAX,
            },
            caveats: Vec::new(),
        }
    }

    /// Authorize a `virtio-fs` open of `path` for read or write.
    #[must_use]
    pub fn authorize_fs(&self, path: &str, write: bool) -> bool {
        let action = if write { Action::Write } else { Action::Read };
        self.permits(&Self::request(
            action,
            Resource::Filesystem(path.to_owned()),
        ))
    }

    /// Authorize a `virtio-net` flow.
    ///
    /// Outbound flows require `Connect` on `Network("host:port")`; inbound
    /// listeners require `Listen` on the same resource.
    #[must_use]
    pub fn authorize_net(&self, direction: FlowDirection, host: &str, port: u16) -> bool {
        let action = match direction {
            FlowDirection::Outbound => Action::Connect,
            FlowDirection::Inbound => Action::Listen,
        };
        let endpoint = format!("{host}:{port}");
        self.permits(&Self::request(action, Resource::Network(endpoint)))
    }

    /// Authorize a `virtio-vsock` connection to a numeric channel id.
    ///
    /// Requires `IpcSend` on `IpcChannel(id)`. A non-numeric channel string is
    /// denied (the kernel channel namespace is integer-keyed).
    #[must_use]
    pub fn authorize_vsock(&self, channel_id: &str) -> bool {
        let Ok(id) = channel_id.parse::<u64>() else {
            return false;
        };
        self.permits(&Self::request(Action::IpcSend, Resource::IpcChannel(id)))
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    fn scope(action: Action, resource: Resource) -> Scope {
        Scope {
            action,
            resource,
            window: TimeWindow::new(0, u64::MAX).unwrap(),
            caveats: Vec::new(),
        }
    }

    #[test]
    fn empty_grant_denies_everything() {
        let g = GrantedScopes::empty();
        assert!(g.is_empty());
        assert!(!g.authorize_fs("/etc/hosts", false));
        assert!(!g.authorize_net(FlowDirection::Outbound, "huggingface.co", 443));
        assert!(!g.authorize_vsock("7"));
    }

    #[test]
    fn fs_read_grant_allows_exact_path_only() {
        let g = GrantedScopes::from_scopes(vec![scope(
            Action::Read,
            Resource::Filesystem("/data/x".to_owned()),
        )]);
        assert!(g.authorize_fs("/data/x", false));
        // Read grant does not imply write.
        assert!(!g.authorize_fs("/data/x", true));
        // Different path denied.
        assert!(!g.authorize_fs("/data/y", false));
    }

    #[test]
    fn fs_glob_grant_allows_descendants() {
        let g = GrantedScopes::from_scopes(vec![scope(
            Action::Read,
            Resource::Filesystem("/data/**".to_owned()),
        )]);
        assert!(g.authorize_fs("/data/x/y", false));
    }

    #[test]
    fn net_connect_grant_matches_endpoint() {
        let g = GrantedScopes::from_scopes(vec![scope(
            Action::Connect,
            Resource::Network("huggingface.co:443".to_owned()),
        )]);
        assert!(g.authorize_net(FlowDirection::Outbound, "huggingface.co", 443));
        // Wrong port denied.
        assert!(!g.authorize_net(FlowDirection::Outbound, "huggingface.co", 80));
        // Connect grant is not a Listen grant.
        assert!(!g.authorize_net(FlowDirection::Inbound, "huggingface.co", 443));
    }

    #[test]
    fn vsock_grant_matches_channel_and_rejects_non_numeric() {
        let g = GrantedScopes::from_scopes(vec![scope(Action::IpcSend, Resource::IpcChannel(7))]);
        assert!(g.authorize_vsock("7"));
        assert!(!g.authorize_vsock("8"));
        assert!(!g.authorize_vsock("not-a-number"));
    }
}
