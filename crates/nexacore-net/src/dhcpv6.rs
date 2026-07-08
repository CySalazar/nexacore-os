//! `DHCPv6` client (WS4-04.6, RFC 8415).
//!
//! A stateless-free alternative to `SLAAC` (see [`crate::slaac`]): the client
//! drives the four-message Solicit → Advertise → Request → Reply exchange to
//! lease a global `IPv6` address from a `DHCPv6` server. This module is the
//! message codec plus the client state machine; it performs no I/O — the caller
//! transmits the returned datagrams and feeds received ones back via
//! [`Dhcpv6Client::handle`].
//!
//! Wire format (RFC 8415 § 8): a 1-byte message type, a 3-byte transaction id,
//! then options encoded as `(2-byte code, 2-byte length, value)`. The leased
//! address travels nested inside an `IA_NA` option's `IAADDR` sub-option.

use alloc::{vec, vec::Vec};

use nexacore_types::net::{Ipv6Addr, MacAddress};

// Option codes (RFC 8415 § 21).
const OPT_CLIENTID: u16 = 1;
const OPT_SERVERID: u16 = 2;
const OPT_IA_NA: u16 = 3;
const OPT_IAADDR: u16 = 5;
const OPT_ELAPSED_TIME: u16 = 8;

/// A `DHCPv6` message type (RFC 8415 § 7.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Dhcpv6MessageType {
    /// Client → server: locate available servers.
    Solicit = 1,
    /// Server → client: a server is available.
    Advertise = 2,
    /// Client → server: request configuration from a chosen server.
    Request = 3,
    /// Server → client: assigned configuration.
    Reply = 7,
}

impl Dhcpv6MessageType {
    /// Map a wire byte to a known message type.
    #[must_use]
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            1 => Some(Self::Solicit),
            2 => Some(Self::Advertise),
            3 => Some(Self::Request),
            7 => Some(Self::Reply),
            _ => None,
        }
    }
}

/// The client state machine states (RFC 8415 § 18.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Dhcpv6State {
    /// No transaction in progress.
    Init,
    /// A Solicit has been sent; awaiting an Advertise.
    Soliciting,
    /// A Request has been sent; awaiting a Reply.
    Requesting,
    /// An address has been leased.
    Bound,
}

/// A leased address with its lifetimes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Dhcpv6Lease {
    /// The assigned `IPv6` address.
    pub addr: Ipv6Addr,
    /// Preferred lifetime in seconds.
    pub preferred_lifetime: u32,
    /// Valid lifetime in seconds.
    pub valid_lifetime: u32,
    /// The serving server's `DUID`.
    pub server_id: Vec<u8>,
}

/// The action a [`Dhcpv6Client`] wants the caller to take after an event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Dhcpv6Result {
    /// Transmit this Solicit datagram (to the all-servers multicast).
    SendSolicit(Vec<u8>),
    /// Transmit this Request datagram.
    SendRequest(Vec<u8>),
    /// The address is leased; configuration is complete.
    Bound(Dhcpv6Lease),
    /// The packet was irrelevant or malformed and was ignored.
    Ignored,
}

/// A `DHCPv6` client state machine.
#[derive(Debug, Clone)]
pub struct Dhcpv6Client {
    /// Current state.
    pub state: Dhcpv6State,
    xid: [u8; 3],
    iaid: u32,
    client_duid: Vec<u8>,
    server_duid: Option<Vec<u8>>,
    offered: Option<OfferedAddr>,
    /// The active lease, present in [`Dhcpv6State::Bound`].
    pub lease: Option<Dhcpv6Lease>,
}

#[derive(Debug, Clone, Copy)]
struct OfferedAddr {
    addr: Ipv6Addr,
    preferred_lifetime: u32,
    valid_lifetime: u32,
}

impl Dhcpv6Client {
    /// Create a client for interface `mac`, using transaction id `xid` (low 24
    /// bits) and identity-association id `iaid`. The client `DUID` is a
    /// link-layer `DUID` (`DUID-LL`) derived from `mac`.
    #[must_use]
    pub fn new(mac: MacAddress, xid: u32, iaid: u32) -> Self {
        let [_, x1, x2, x3] = xid.to_be_bytes();
        Self {
            state: Dhcpv6State::Init,
            xid: [x1, x2, x3],
            iaid,
            client_duid: duid_ll(mac),
            server_duid: None,
            offered: None,
            lease: None,
        }
    }

    /// Build a Solicit message, moving to [`Dhcpv6State::Soliciting`].
    pub fn build_solicit(&mut self) -> Vec<u8> {
        self.state = Dhcpv6State::Soliciting;
        let options = vec![
            (OPT_CLIENTID, self.client_duid.clone()),
            (OPT_ELAPSED_TIME, vec![0, 0]),
            (OPT_IA_NA, encode_ia_na(self.iaid, 0, 0, None)),
        ];
        encode_message(Dhcpv6MessageType::Solicit as u8, self.xid, &options)
    }

    /// Process a received datagram and advance the state machine.
    pub fn handle(&mut self, packet: &[u8]) -> Dhcpv6Result {
        let Some((mtype, xid, opts)) = parse_message(packet) else {
            return Dhcpv6Result::Ignored;
        };
        if xid != self.xid {
            return Dhcpv6Result::Ignored;
        }
        match (self.state, Dhcpv6MessageType::from_u8(mtype)) {
            (Dhcpv6State::Soliciting, Some(Dhcpv6MessageType::Advertise)) => {
                self.on_advertise(&opts)
            }
            (Dhcpv6State::Requesting, Some(Dhcpv6MessageType::Reply)) => self.on_reply(&opts),
            _ => Dhcpv6Result::Ignored,
        }
    }

    fn on_advertise(&mut self, opts: &[(u16, &[u8])]) -> Dhcpv6Result {
        let (Some(server_id), Some(ia_na)) = (
            find_option(opts, OPT_SERVERID),
            find_option(opts, OPT_IA_NA),
        ) else {
            return Dhcpv6Result::Ignored;
        };
        let Some((_, _, _, Some(addr))) = parse_ia_na(ia_na) else {
            return Dhcpv6Result::Ignored;
        };
        self.server_duid = Some(server_id.to_vec());
        self.offered = Some(addr);
        self.state = Dhcpv6State::Requesting;
        Dhcpv6Result::SendRequest(self.build_request(addr))
    }

    fn build_request(&self, addr: OfferedAddr) -> Vec<u8> {
        let mut options = vec![(OPT_CLIENTID, self.client_duid.clone())];
        if let Some(sid) = &self.server_duid {
            options.push((OPT_SERVERID, sid.clone()));
        }
        options.push((OPT_ELAPSED_TIME, vec![0, 0]));
        options.push((
            OPT_IA_NA,
            encode_ia_na(
                self.iaid,
                0,
                0,
                Some((addr.addr, addr.preferred_lifetime, addr.valid_lifetime)),
            ),
        ));
        encode_message(Dhcpv6MessageType::Request as u8, self.xid, &options)
    }

    fn on_reply(&mut self, opts: &[(u16, &[u8])]) -> Dhcpv6Result {
        let Some(ia_na) = find_option(opts, OPT_IA_NA) else {
            return Dhcpv6Result::Ignored;
        };
        let Some((_, _, _, Some(addr))) = parse_ia_na(ia_na) else {
            return Dhcpv6Result::Ignored;
        };
        let lease = Dhcpv6Lease {
            addr: addr.addr,
            preferred_lifetime: addr.preferred_lifetime,
            valid_lifetime: addr.valid_lifetime,
            server_id: self.server_duid.clone().unwrap_or_default(),
        };
        self.state = Dhcpv6State::Bound;
        self.lease = Some(lease.clone());
        Dhcpv6Result::Bound(lease)
    }
}

/// Build a link-layer `DUID` (`DUID-LL`, type 3) over Ethernet (hw type 1).
#[must_use]
pub fn duid_ll(mac: MacAddress) -> Vec<u8> {
    let mut duid = Vec::with_capacity(10);
    duid.extend_from_slice(&3u16.to_be_bytes()); // DUID-LL
    duid.extend_from_slice(&1u16.to_be_bytes()); // hardware type: Ethernet
    duid.extend_from_slice(&mac.0);
    duid
}

/// Encode a message: type, 3-byte transaction id, then `(code, len, value)`
/// options.
fn encode_message(msg_type: u8, xid: [u8; 3], options: &[(u16, Vec<u8>)]) -> Vec<u8> {
    let mut out = Vec::new();
    out.push(msg_type);
    out.extend_from_slice(&xid);
    for (code, value) in options {
        out.extend_from_slice(&code.to_be_bytes());
        out.extend_from_slice(&u16::try_from(value.len()).unwrap_or(u16::MAX).to_be_bytes());
        out.extend_from_slice(value);
    }
    out
}

/// A borrowed list of parsed options, each `(code, value)`.
type DhcpOptions<'a> = Vec<(u16, &'a [u8])>;

/// Parse a message into `(type, transaction-id, options)`, or `None` if
/// truncated. Each option is borrowed as `(code, value)`.
fn parse_message(bytes: &[u8]) -> Option<(u8, [u8; 3], DhcpOptions<'_>)> {
    let msg_type = *bytes.first()?;
    let xid: [u8; 3] = bytes.get(1..4)?.try_into().ok()?;
    let options = parse_options(bytes.get(4..)?)?;
    Some((msg_type, xid, options))
}

/// Parse a `(code, length, value)` option stream.
fn parse_options(mut bytes: &[u8]) -> Option<DhcpOptions<'_>> {
    let mut out = Vec::new();
    while !bytes.is_empty() {
        let code = u16::from_be_bytes(bytes.get(0..2)?.try_into().ok()?);
        let len = usize::from(u16::from_be_bytes(bytes.get(2..4)?.try_into().ok()?));
        let value = bytes.get(4..4 + len)?;
        out.push((code, value));
        bytes = bytes.get(4 + len..)?;
    }
    Some(out)
}

/// Find the first option with `code`.
fn find_option<'a>(opts: &[(u16, &'a [u8])], code: u16) -> Option<&'a [u8]> {
    opts.iter().find(|(c, _)| *c == code).map(|(_, v)| *v)
}

/// Encode an `IA_NA` option value: IAID, T1, T2, then an optional `IAADDR`
/// sub-option.
fn encode_ia_na(iaid: u32, t1: u32, t2: u32, addr: Option<(Ipv6Addr, u32, u32)>) -> Vec<u8> {
    let mut v = Vec::new();
    v.extend_from_slice(&iaid.to_be_bytes());
    v.extend_from_slice(&t1.to_be_bytes());
    v.extend_from_slice(&t2.to_be_bytes());
    if let Some((a, preferred, valid)) = addr {
        let mut iaaddr = Vec::with_capacity(24);
        iaaddr.extend_from_slice(&a.0);
        iaaddr.extend_from_slice(&preferred.to_be_bytes());
        iaaddr.extend_from_slice(&valid.to_be_bytes());
        v.extend_from_slice(&OPT_IAADDR.to_be_bytes());
        v.extend_from_slice(
            &u16::try_from(iaaddr.len())
                .unwrap_or(u16::MAX)
                .to_be_bytes(),
        );
        v.extend_from_slice(&iaaddr);
    }
    v
}

/// Parse an `IA_NA` option value into `(IAID, T1, T2, optional address)`.
fn parse_ia_na(value: &[u8]) -> Option<(u32, u32, u32, Option<OfferedAddr>)> {
    let iaid = u32::from_be_bytes(value.get(0..4)?.try_into().ok()?);
    let t1 = u32::from_be_bytes(value.get(4..8)?.try_into().ok()?);
    let t2 = u32::from_be_bytes(value.get(8..12)?.try_into().ok()?);
    let sub = parse_options(value.get(12..)?)?;
    let addr = match find_option(&sub, OPT_IAADDR) {
        Some(iaaddr) => Some(parse_iaaddr(iaaddr)?),
        None => None,
    };
    Some((iaid, t1, t2, addr))
}

/// Parse an `IAADDR` sub-option value: address, preferred, valid lifetimes.
fn parse_iaaddr(value: &[u8]) -> Option<OfferedAddr> {
    Some(OfferedAddr {
        addr: Ipv6Addr(value.get(0..16)?.try_into().ok()?),
        preferred_lifetime: u32::from_be_bytes(value.get(16..20)?.try_into().ok()?),
        valid_lifetime: u32::from_be_bytes(value.get(20..24)?.try_into().ok()?),
    })
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::indexing_slicing, clippy::panic)]
    use super::*;

    fn mac() -> MacAddress {
        MacAddress([0x02, 0, 0, 0, 0, 0x42])
    }

    fn leased() -> Ipv6Addr {
        Ipv6Addr([0x20, 0x01, 0xd, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10])
    }

    /// A server crafting a reply-style message (Advertise or Reply) carrying an
    /// `IA_NA` with the leased address.
    fn server_message(mtype: Dhcpv6MessageType, xid: [u8; 3], client_duid: &[u8]) -> Vec<u8> {
        let server_duid = duid_ll(MacAddress([0x02, 0, 0, 0, 0, 0x01]));
        let options = vec![
            (OPT_CLIENTID, client_duid.to_vec()),
            (OPT_SERVERID, server_duid),
            (
                OPT_IA_NA,
                encode_ia_na(0x1234, 3600, 5400, Some((leased(), 7200, 14_400))),
            ),
        ];
        encode_message(mtype as u8, xid, &options)
    }

    #[test]
    fn duid_ll_layout() {
        // type 3, hw type 1, then the MAC.
        assert_eq!(duid_ll(mac()), vec![0, 3, 0, 1, 0x02, 0, 0, 0, 0, 0x42]);
    }

    #[test]
    fn solicit_is_well_formed() {
        let mut client = Dhcpv6Client::new(mac(), 0x00AB_CDEF, 0x1234);
        let pkt = client.build_solicit();
        assert_eq!(client.state, Dhcpv6State::Soliciting);
        let (mtype, xid, opts) = parse_message(&pkt).unwrap();
        assert_eq!(mtype, Dhcpv6MessageType::Solicit as u8);
        assert_eq!(xid, [0xAB, 0xCD, 0xEF]);
        assert!(find_option(&opts, OPT_CLIENTID).is_some());
        assert!(find_option(&opts, OPT_IA_NA).is_some());
        assert!(find_option(&opts, OPT_ELAPSED_TIME).is_some());
    }

    #[test]
    fn full_sarr_exchange_leases_address() {
        let mut client = Dhcpv6Client::new(mac(), 0x00AB_CDEF, 0x1234);
        let client_duid = duid_ll(mac());
        let _solicit = client.build_solicit();

        // Server advertises an address.
        let advertise = server_message(Dhcpv6MessageType::Advertise, client.xid, &client_duid);
        let result = client.handle(&advertise);
        let request = match result {
            Dhcpv6Result::SendRequest(req) => req,
            other => panic!("expected SendRequest, got {other:?}"),
        };
        assert_eq!(client.state, Dhcpv6State::Requesting);
        // The Request echoes the server id and the requested address.
        let (mtype, _, opts) = parse_message(&request).unwrap();
        assert_eq!(mtype, Dhcpv6MessageType::Request as u8);
        assert!(find_option(&opts, OPT_SERVERID).is_some());
        let (_, _, _, addr) = parse_ia_na(find_option(&opts, OPT_IA_NA).unwrap()).unwrap();
        assert_eq!(addr.unwrap().addr, leased());

        // Server replies; the client binds the lease.
        let reply = server_message(Dhcpv6MessageType::Reply, client.xid, &client_duid);
        match client.handle(&reply) {
            Dhcpv6Result::Bound(lease) => {
                assert_eq!(lease.addr, leased());
                assert_eq!(lease.preferred_lifetime, 7200);
                assert_eq!(lease.valid_lifetime, 14_400);
                assert!(!lease.server_id.is_empty());
            }
            other => panic!("expected Bound, got {other:?}"),
        }
        assert_eq!(client.state, Dhcpv6State::Bound);
        assert_eq!(client.lease.unwrap().addr, leased());
    }

    #[test]
    fn wrong_transaction_id_is_ignored() {
        let mut client = Dhcpv6Client::new(mac(), 0x00AB_CDEF, 0x1234);
        let _ = client.build_solicit();
        // An advertise with a different xid must be ignored.
        let advertise = server_message(
            Dhcpv6MessageType::Advertise,
            [0x00, 0x00, 0x01],
            &duid_ll(mac()),
        );
        assert_eq!(client.handle(&advertise), Dhcpv6Result::Ignored);
        assert_eq!(client.state, Dhcpv6State::Soliciting);
    }

    #[test]
    fn reply_in_wrong_state_is_ignored() {
        let mut client = Dhcpv6Client::new(mac(), 0x00AB_CDEF, 0x1234);
        let _ = client.build_solicit();
        // A Reply while still Soliciting (skipping the Request) is ignored.
        let reply = server_message(Dhcpv6MessageType::Reply, client.xid, &duid_ll(mac()));
        assert_eq!(client.handle(&reply), Dhcpv6Result::Ignored);
    }

    #[test]
    fn truncated_packet_is_ignored() {
        let mut client = Dhcpv6Client::new(mac(), 1, 1);
        let _ = client.build_solicit();
        assert_eq!(client.handle(&[1, 2]), Dhcpv6Result::Ignored);
        assert_eq!(client.handle(&[]), Dhcpv6Result::Ignored);
    }

    #[test]
    fn ia_na_round_trips() {
        let v = encode_ia_na(7, 100, 200, Some((leased(), 300, 400)));
        let (iaid, t1, t2, addr) = parse_ia_na(&v).unwrap();
        assert_eq!((iaid, t1, t2), (7, 100, 200));
        let addr = addr.unwrap();
        assert_eq!(addr.addr, leased());
        assert_eq!((addr.preferred_lifetime, addr.valid_lifetime), (300, 400));
        // Without an address, the sub-option is absent.
        let (_, _, _, none) = parse_ia_na(&encode_ia_na(7, 0, 0, None)).unwrap();
        assert!(none.is_none());
    }
}
