//! Stateful packet filter / connection tracking (WS4-05.3).
//!
//! A stateful firewall core: it tracks flows by their canonical 5-tuple so that
//! the reply direction of a connection the host initiated is recognised and
//! allowed, while **unsolicited inbound packets are dropped** (default-deny
//! egress-initiated model, WS4-05.2). TCP flows advance through a small state
//! machine (New → Established → Closing → Closed) driven by SYN/ACK/FIN/RST;
//! UDP flows become established once a reply is seen.
//!
//! This is the decision core; wiring it to the socket-creation path and per-app
//! allow lists is WS4-05.1/.5.

use alloc::collections::BTreeMap;

/// The transport protocol of a tracked flow.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Protocol {
    /// TCP (stateful handshake + teardown).
    Tcp,
    /// UDP (pseudo-stateful: established on first reply).
    Udp,
}

/// One endpoint of a flow (`IPv4` address + port).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Endpoint {
    /// `IPv4` address (host byte order).
    pub ip: u32,
    /// Port.
    pub port: u16,
}

impl Endpoint {
    /// An endpoint from an address and port.
    #[must_use]
    pub fn new(ip: u32, port: u16) -> Self {
        Self { ip, port }
    }
}

/// The relevant TCP control flags of a packet.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[allow(clippy::struct_excessive_bools, reason = "the four TCP control flags")]
pub struct TcpFlags {
    /// SYN — connection setup.
    pub syn: bool,
    /// ACK — acknowledgement.
    pub ack: bool,
    /// FIN — graceful close.
    pub fin: bool,
    /// RST — abortive reset.
    pub rst: bool,
}

impl TcpFlags {
    /// A pure SYN (connection open request, no ACK).
    #[must_use]
    pub fn syn() -> Self {
        Self {
            syn: true,
            ..Self::default()
        }
    }

    /// A SYN-ACK (connection open reply).
    #[must_use]
    pub fn syn_ack() -> Self {
        Self {
            syn: true,
            ack: true,
            ..Self::default()
        }
    }

    /// A bare ACK.
    #[must_use]
    pub fn ack() -> Self {
        Self {
            ack: true,
            ..Self::default()
        }
    }
}

/// Which way a packet is travelling relative to this host.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    /// Leaving this host.
    Outbound,
    /// Arriving at this host.
    Inbound,
}

/// A packet presented to the connection tracker.
#[derive(Debug, Clone, Copy)]
pub struct Packet {
    /// Transport protocol.
    pub protocol: Protocol,
    /// Source endpoint.
    pub src: Endpoint,
    /// Destination endpoint.
    pub dst: Endpoint,
    /// Travel direction.
    pub direction: Direction,
    /// TCP flags (ignored for UDP).
    pub flags: TcpFlags,
}

/// The tracked state of a connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnState {
    /// Opened outbound, no reply yet.
    New,
    /// A reply was seen — the connection is live.
    Established,
    /// A FIN was seen — closing.
    Closing,
    /// Fully closed (the entry is removed).
    Closed,
}

/// The filter decision for a packet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    /// Allow the packet.
    Accept,
    /// Drop the packet.
    Drop,
}

/// The canonical key for a flow: protocol plus the two endpoints in a
/// direction-independent order, so both directions map to one entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct FlowKey {
    proto: u8,
    lo: Endpoint,
    hi: Endpoint,
}

fn canonical(pkt: &Packet) -> FlowKey {
    let proto = match pkt.protocol {
        Protocol::Tcp => 6,
        Protocol::Udp => 17,
    };
    let (lo, hi) = if pkt.src <= pkt.dst {
        (pkt.src, pkt.dst)
    } else {
        (pkt.dst, pkt.src)
    };
    FlowKey { proto, lo, hi }
}

/// The stateful connection tracker (WS4-05.3).
#[derive(Debug, Clone, Default)]
pub struct ConnTrack {
    flows: BTreeMap<FlowKey, ConnState>,
}

impl ConnTrack {
    /// An empty tracker.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// The number of tracked flows.
    #[must_use]
    pub fn len(&self) -> usize {
        self.flows.len()
    }

    /// Whether no flows are tracked.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.flows.is_empty()
    }

    /// The tracked state of the flow a packet belongs to, if any.
    #[must_use]
    pub fn state_of(&self, pkt: &Packet) -> Option<ConnState> {
        self.flows.get(&canonical(pkt)).copied()
    }

    /// Advance an existing flow's state for a packet.
    fn advance(protocol: Protocol, state: ConnState, pkt: &Packet) -> ConnState {
        if protocol == Protocol::Udp {
            return match state {
                ConnState::New if pkt.direction == Direction::Inbound => ConnState::Established,
                other => other,
            };
        }
        // TCP.
        if pkt.flags.rst {
            return ConnState::Closed;
        }
        if pkt.flags.fin {
            return if state == ConnState::Closing {
                ConnState::Closed
            } else {
                ConnState::Closing
            };
        }
        match state {
            ConnState::New
                if pkt.direction == Direction::Inbound && pkt.flags.syn && pkt.flags.ack =>
            {
                ConnState::Established
            }
            other => other,
        }
    }

    /// Filter a packet, updating flow state, and return the verdict (WS4-05.3).
    ///
    /// A packet on an existing flow is accepted (including teardown). A new
    /// outbound flow is accepted and tracked (TCP only if it is a genuine SYN
    /// open); a new inbound flow is dropped (unsolicited — default-deny).
    pub fn filter(&mut self, pkt: &Packet) -> Verdict {
        let key = canonical(pkt);
        if let Some(state) = self.flows.get(&key).copied() {
            let next = Self::advance(pkt.protocol, state, pkt);
            if next == ConnState::Closed {
                self.flows.remove(&key);
            } else {
                self.flows.insert(key, next);
            }
            return Verdict::Accept;
        }
        match pkt.direction {
            Direction::Outbound => {
                // A new TCP flow must open with a pure SYN; a stray mid-stream
                // segment with no state is invalid.
                if pkt.protocol == Protocol::Tcp && (!pkt.flags.syn || pkt.flags.ack) {
                    return Verdict::Drop;
                }
                self.flows.insert(key, ConnState::New);
                Verdict::Accept
            }
            // Unsolicited inbound: default-deny.
            Direction::Inbound => Verdict::Drop,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const HOST: u32 = 0xC0A8_0102; // 192.168.1.2
    const PEER: u32 = 0x5DB8_D822; // 93.184.216.34

    fn tcp(direction: Direction, flags: TcpFlags) -> Packet {
        // Outbound: host:12345 -> peer:443. Inbound: the reverse.
        let host = Endpoint::new(HOST, 12345);
        let peer = Endpoint::new(PEER, 443);
        let (src, dst) = match direction {
            Direction::Outbound => (host, peer),
            Direction::Inbound => (peer, host),
        };
        Packet {
            protocol: Protocol::Tcp,
            src,
            dst,
            direction,
            flags,
        }
    }

    fn udp(direction: Direction) -> Packet {
        let host = Endpoint::new(HOST, 5353);
        let peer = Endpoint::new(PEER, 53);
        let (src, dst) = match direction {
            Direction::Outbound => (host, peer),
            Direction::Inbound => (peer, host),
        };
        Packet {
            protocol: Protocol::Udp,
            src,
            dst,
            direction,
            flags: TcpFlags::default(),
        }
    }

    #[test]
    fn tcp_handshake_is_tracked_and_accepted() {
        let mut ct = ConnTrack::new();
        // Outbound SYN opens the flow.
        assert_eq!(
            ct.filter(&tcp(Direction::Outbound, TcpFlags::syn())),
            Verdict::Accept
        );
        assert_eq!(ct.len(), 1);
        assert_eq!(
            ct.state_of(&tcp(Direction::Outbound, TcpFlags::syn())),
            Some(ConnState::New)
        );
        // Inbound SYN-ACK establishes it (reply matches the same flow).
        assert_eq!(
            ct.filter(&tcp(Direction::Inbound, TcpFlags::syn_ack())),
            Verdict::Accept
        );
        assert_eq!(
            ct.state_of(&tcp(Direction::Outbound, TcpFlags::ack())),
            Some(ConnState::Established)
        );
        // Data both ways is accepted.
        assert_eq!(
            ct.filter(&tcp(Direction::Outbound, TcpFlags::ack())),
            Verdict::Accept
        );
        assert_eq!(
            ct.filter(&tcp(Direction::Inbound, TcpFlags::ack())),
            Verdict::Accept
        );
    }

    #[test]
    fn unsolicited_inbound_is_dropped() {
        let mut ct = ConnTrack::new();
        // Inbound SYN with no prior outbound flow → dropped, nothing tracked.
        assert_eq!(
            ct.filter(&tcp(Direction::Inbound, TcpFlags::syn())),
            Verdict::Drop
        );
        assert!(ct.is_empty());
    }

    #[test]
    fn stray_outbound_segment_without_syn_is_dropped() {
        let mut ct = ConnTrack::new();
        // Outbound ACK with no open flow is invalid.
        assert_eq!(
            ct.filter(&tcp(Direction::Outbound, TcpFlags::ack())),
            Verdict::Drop
        );
        assert!(ct.is_empty());
    }

    #[test]
    fn rst_closes_and_removes_the_flow() {
        let mut ct = ConnTrack::new();
        ct.filter(&tcp(Direction::Outbound, TcpFlags::syn()));
        ct.filter(&tcp(Direction::Inbound, TcpFlags::syn_ack()));
        // A FIN moves to Closing (flow still tracked).
        let fin = TcpFlags {
            fin: true,
            ack: true,
            ..TcpFlags::default()
        };
        assert_eq!(ct.filter(&tcp(Direction::Outbound, fin)), Verdict::Accept);
        assert_eq!(
            ct.state_of(&tcp(Direction::Outbound, fin)),
            Some(ConnState::Closing)
        );
        // A RST tears it down entirely.
        let rst = TcpFlags {
            rst: true,
            ..TcpFlags::default()
        };
        assert_eq!(ct.filter(&tcp(Direction::Inbound, rst)), Verdict::Accept);
        assert!(ct.is_empty());
    }

    #[test]
    fn udp_reply_establishes_but_unsolicited_inbound_drops() {
        let mut ct = ConnTrack::new();
        // Outbound query opens the flow.
        assert_eq!(ct.filter(&udp(Direction::Outbound)), Verdict::Accept);
        // Inbound reply is accepted and marks it established.
        assert_eq!(ct.filter(&udp(Direction::Inbound)), Verdict::Accept);
        assert_eq!(
            ct.state_of(&udp(Direction::Outbound)),
            Some(ConnState::Established)
        );

        // A fresh unsolicited inbound UDP packet (different flow) is dropped.
        let mut ct2 = ConnTrack::new();
        assert_eq!(ct2.filter(&udp(Direction::Inbound)), Verdict::Drop);
        assert!(ct2.is_empty());
    }
}
