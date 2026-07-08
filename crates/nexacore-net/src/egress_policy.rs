//! Default-deny egress policy (WS4-05.2).
//!
//! The network stack egresses nothing by default. An application may open
//! sockets and reach a destination only if it presents a **verified** network
//! capability *and* the destination is in its per-app allow list
//! ([`crate::allowlist::AppAllowList`]).
//!
//! This module is only the policy *decision*. Verifying the capability token
//! itself — signature, attenuation, TEE binding — is `nexacore-capability`'s
//! job at the syscall boundary; pulling that (crypto-bearing) crate into the
//! `no_std` net stack would be the wrong layering. This layer consumes the
//! already-verified yes/no plus the allow list and returns an auditable
//! decision. Wiring it into socket creation is WS4-05.1/.5.

use crate::allowlist::{AppAllowList, EgressTarget};

/// Whether an app presented a verified network capability.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetCapability {
    /// No network capability — the app may not egress at all.
    None,
    /// A verified network capability, governed by the app's allow list.
    Granted,
}

/// Why an egress attempt was denied.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DenyReason {
    /// The app holds no network capability (default-deny).
    NoCapability,
    /// The app has a capability but the target is outside its allow list.
    NotAllowed,
}

/// The outcome of an egress decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EgressDecision {
    /// The connection is permitted.
    Allow,
    /// The connection is denied, with the reason.
    Deny(DenyReason),
}

impl EgressDecision {
    /// Whether the decision permits the connection.
    #[must_use]
    pub fn is_allowed(self) -> bool {
        matches!(self, Self::Allow)
    }
}

/// The default-deny egress policy (WS4-05.2).
pub struct EgressPolicy;

impl EgressPolicy {
    /// Whether an app with capability `cap` may open a socket at all.
    ///
    /// An app with no network capability is denied outright — no socket, no
    /// egress. This is the socket-creation gate (WS4-05.1 binds it in the
    /// syscall path).
    #[must_use]
    pub fn may_open_socket(cap: NetCapability) -> bool {
        matches!(cap, NetCapability::Granted)
    }

    /// Decide whether egress to `target` is permitted.
    ///
    /// Default-deny: with [`NetCapability::None`] the connection is denied
    /// outright and the allow list is not even consulted; with a granted
    /// capability the per-app allow list governs (an empty list still denies
    /// everything).
    #[must_use]
    pub fn evaluate(
        cap: NetCapability,
        allow: &AppAllowList,
        target: &EgressTarget,
    ) -> EgressDecision {
        match cap {
            NetCapability::None => EgressDecision::Deny(DenyReason::NoCapability),
            NetCapability::Granted => {
                if allow.permits(target) {
                    EgressDecision::Allow
                } else {
                    EgressDecision::Deny(DenyReason::NotAllowed)
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::needless_lifetimes,
        clippy::indexing_slicing,
        clippy::panic
    )]

    use super::*;
    use crate::conntrack::Protocol;

    fn updater_list() -> AppAllowList {
        AppAllowList::parse("org.nexacore.updater", "tcp updates.nexacore.com 443\n")
    }

    fn target<'a>(domain: Option<&'a str>, ip: u32, port: u16) -> EgressTarget<'a> {
        EgressTarget {
            protocol: Protocol::Tcp,
            ip,
            domain,
            port,
        }
    }

    #[test]
    fn no_capability_denies_outright_ignoring_allow_list() {
        // Even a target the allow list would permit is denied without a cap.
        let decision = EgressPolicy::evaluate(
            NetCapability::None,
            &updater_list(),
            &target(Some("updates.nexacore.com"), 0, 443),
        );
        assert_eq!(decision, EgressDecision::Deny(DenyReason::NoCapability));
        assert!(!decision.is_allowed());
        assert!(!EgressPolicy::may_open_socket(NetCapability::None));
    }

    #[test]
    fn granted_capability_consults_the_allow_list() {
        let list = updater_list();
        // Permitted target → allowed.
        assert!(
            EgressPolicy::evaluate(
                NetCapability::Granted,
                &list,
                &target(Some("updates.nexacore.com"), 0, 443)
            )
            .is_allowed()
        );
        // Un-listed target → denied as NotAllowed (has a cap, but not this host).
        assert_eq!(
            EgressPolicy::evaluate(
                NetCapability::Granted,
                &list,
                &target(Some("evil.com"), 0, 443)
            ),
            EgressDecision::Deny(DenyReason::NotAllowed)
        );
        assert!(EgressPolicy::may_open_socket(NetCapability::Granted));
    }

    #[test]
    fn granted_capability_with_empty_list_still_denies_all() {
        let empty = AppAllowList::new("locked");
        assert_eq!(
            EgressPolicy::evaluate(
                NetCapability::Granted,
                &empty,
                &target(None, 0x0808_0808, 53)
            ),
            EgressDecision::Deny(DenyReason::NotAllowed)
        );
    }
}
