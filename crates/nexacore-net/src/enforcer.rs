//! Unified network egress enforcer (WS4-05.1/.5).
//!
//! Composes the three egress building blocks into the single decision point the
//! network stack consults: the capability gate ([`crate::egress_policy`]), the
//! per-app allow list ([`crate::allowlist`]), and the stateful connection
//! filter ([`crate::conntrack`]).
//!
//! - **Socket creation** (WS4-05.1): [`NetEnforcer::open_socket`] binds the
//!   network capability and the app's allow list to `socket()`/`connect()` —
//!   no capability means no socket, and a socket may only open to an
//!   allow-listed destination.
//! - **Packet path** (WS4-05.5): [`NetEnforcer::filter`] applies the same
//!   capability + allow-list check to every outbound packet, then the stateful
//!   connection filter, so an unauthorised destination is dropped before it is
//!   ever tracked while replies to authorised flows are admitted.

use crate::{
    allowlist::{AppAllowList, EgressTarget},
    conntrack::{ConnTrack, Direction, Packet, Verdict},
    egress_policy::{DenyReason, EgressDecision, EgressPolicy, NetCapability},
};

/// The unified egress enforcer: capability + allow list at socket creation, and
/// capability + allow list + connection tracking in the packet path.
#[derive(Debug)]
pub struct NetEnforcer {
    conntrack: ConnTrack,
}

impl Default for NetEnforcer {
    fn default() -> Self {
        Self::new()
    }
}

impl NetEnforcer {
    /// A new enforcer with an empty connection table.
    #[must_use]
    pub fn new() -> Self {
        Self {
            conntrack: ConnTrack::new(),
        }
    }

    /// Socket-creation gate (WS4-05.1): bind the network capability and the
    /// app's allow list to `socket()`/`connect()`.
    ///
    /// Returns `Ok(())` if the app may open a socket to `target`. This is the
    /// single call the socket-creation syscall path invokes to enforce egress
    /// policy at bind time (before any packet is sent).
    ///
    /// # Errors
    ///
    /// - [`DenyReason::NoCapability`] if the app holds no network capability.
    /// - [`DenyReason::NotAllowed`] if `target` is not on the app's allow list.
    pub fn open_socket(
        cap: NetCapability,
        allow: &AppAllowList,
        target: &EgressTarget,
    ) -> Result<(), DenyReason> {
        match EgressPolicy::evaluate(cap, allow, target) {
            EgressDecision::Allow => Ok(()),
            EgressDecision::Deny(reason) => Err(reason),
        }
    }

    /// Packet-path filter (WS4-05.5): the capability gate and per-app allow
    /// list applied to every outbound packet, then the stateful connection
    /// filter.
    ///
    /// An app with no capability sends nothing; an outbound packet to a
    /// destination not on the allow list is dropped before it is tracked;
    /// inbound packets are governed solely by connection tracking (they are the
    /// replies to already-authorised outbound flows, so the allow list — which
    /// may carry domain rules unresolvable at packet level — is not re-applied
    /// to them).
    pub fn filter(&mut self, cap: NetCapability, allow: &AppAllowList, packet: &Packet) -> Verdict {
        if !EgressPolicy::may_open_socket(cap) {
            return Verdict::Drop;
        }
        if packet.direction == Direction::Outbound {
            let target = EgressTarget {
                protocol: packet.protocol,
                ip: packet.dst.ip,
                domain: None,
                port: packet.dst.port,
            };
            if !allow.permits(&target) {
                return Verdict::Drop;
            }
        }
        self.conntrack.filter(packet)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::conntrack::{Endpoint, Protocol, TcpFlags};

    const HOST: u32 = 0x0A00_0001; // 10.0.0.1
    const PEER: u32 = 0x5DB8_D822; // 93.184.216.34

    fn allow_https() -> AppAllowList {
        AppAllowList::parse("app", "tcp 93.184.216.34 443")
    }

    fn out_syn() -> Packet {
        Packet {
            protocol: Protocol::Tcp,
            src: Endpoint::new(HOST, 12345),
            dst: Endpoint::new(PEER, 443),
            direction: Direction::Outbound,
            flags: TcpFlags::syn(),
        }
    }

    fn https_target() -> EgressTarget<'static> {
        EgressTarget {
            protocol: Protocol::Tcp,
            ip: PEER,
            domain: None,
            port: 443,
        }
    }

    #[test]
    fn open_socket_binds_capability_and_allow_list() {
        let allow = allow_https();
        // Granted + allow-listed target → permitted.
        assert!(NetEnforcer::open_socket(NetCapability::Granted, &allow, &https_target()).is_ok());
        // Granted but a port not on the list → NotAllowed.
        let other = EgressTarget {
            port: 80,
            ..https_target()
        };
        assert_eq!(
            NetEnforcer::open_socket(NetCapability::Granted, &allow, &other),
            Err(DenyReason::NotAllowed)
        );
        // No capability → no socket at all, even for an allow-listed target.
        assert_eq!(
            NetEnforcer::open_socket(NetCapability::None, &allow, &https_target()),
            Err(DenyReason::NoCapability)
        );
    }

    #[test]
    fn filter_drops_everything_without_capability() {
        let mut e = NetEnforcer::new();
        assert_eq!(
            e.filter(NetCapability::None, &allow_https(), &out_syn()),
            Verdict::Drop
        );
    }

    #[test]
    fn filter_drops_outbound_to_unlisted_destination() {
        let mut e = NetEnforcer::new();
        // Allow list covers a different host → the SYN never gets tracked.
        let allow = AppAllowList::parse("app", "tcp 10.9.9.9 443");
        assert_eq!(
            e.filter(NetCapability::Granted, &allow, &out_syn()),
            Verdict::Drop
        );
    }

    #[test]
    fn filter_admits_authorised_flow_and_its_reply() {
        let mut e = NetEnforcer::new();
        let allow = allow_https();
        // Outbound SYN to an allow-listed target → accepted and tracked.
        assert_eq!(
            e.filter(NetCapability::Granted, &allow, &out_syn()),
            Verdict::Accept
        );
        // The inbound SYN-ACK reply matches the tracked flow → accepted, even
        // though the allow list is not re-evaluated for inbound packets.
        let reply = Packet {
            protocol: Protocol::Tcp,
            src: Endpoint::new(PEER, 443),
            dst: Endpoint::new(HOST, 12345),
            direction: Direction::Inbound,
            flags: TcpFlags::syn_ack(),
        };
        assert_eq!(
            e.filter(NetCapability::Granted, &allow, &reply),
            Verdict::Accept
        );
    }
}
