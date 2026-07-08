//! `IPv6` Neighbor Discovery Protocol (WS4-04.3, RFC 4861).
//!
//! `NDP` is the `IPv6` analogue of `ARP` (see [`crate::arp`]): it resolves a
//! neighbour's link-layer (`MAC`) address, discovers routers, and learns
//! on-link prefixes. Its messages are `ICMPv6` packets (types `133..=137`),
//! built on [`crate::icmpv6`]:
//!
//! - Router Solicitation (`RS`, 133) / Router Advertisement (`RA`, 134)
//! - Neighbor Solicitation (`NS`, 135) / Neighbor Advertisement (`NA`, 136)
//!
//! This module builds and parses those four messages with their options
//! (source/target link-layer address, `MTU`, and prefix information) and keeps
//! a [`NeighborCache`] mapping `IPv6` addresses to link-layer addresses.

use alloc::vec::Vec;

use nexacore_types::net::{Ipv6Addr, MacAddress};

use crate::icmpv6::{self, Icmpv6Header, Icmpv6Type};

// =============================================================================
// Options (RFC 4861 § 4.6)
// =============================================================================

/// An `NDP` option. Encoded as type-length-value with the length measured in
/// 8-byte units (so every option occupies a multiple of 8 bytes).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NdpOption {
    /// Source Link-Layer Address (type 1).
    SourceLinkAddr(MacAddress),
    /// Target Link-Layer Address (type 2).
    TargetLinkAddr(MacAddress),
    /// Prefix Information (type 3): an on-link / autoconfig prefix.
    PrefixInfo(PrefixInfo),
    /// Maximum Transmission Unit (type 5).
    Mtu(u32),
    /// An option this module does not interpret, kept as `(type, raw_body)`
    /// where `raw_body` excludes the 2-byte type/length prefix.
    Unknown(u8, Vec<u8>),
}

/// The payload of a Prefix Information option (RFC 4861 § 4.6.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PrefixInfo {
    /// Number of leading significant bits in [`prefix`](Self::prefix).
    pub prefix_len: u8,
    /// On-link flag (`L`): the prefix is directly reachable on this link.
    pub on_link: bool,
    /// Autonomous flag (`A`): the prefix may be used for `SLAAC` (WS4-04.4).
    pub autonomous: bool,
    /// Seconds the prefix stays valid.
    pub valid_lifetime: u32,
    /// Seconds the prefix stays preferred.
    pub preferred_lifetime: u32,
    /// The advertised prefix.
    pub prefix: Ipv6Addr,
}

impl NdpOption {
    /// Append this option's wire encoding to `out`.
    fn encode(&self, out: &mut Vec<u8>) {
        match self {
            Self::SourceLinkAddr(mac) => encode_lladdr(out, 1, *mac),
            Self::TargetLinkAddr(mac) => encode_lladdr(out, 2, *mac),
            Self::Mtu(mtu) => {
                out.extend_from_slice(&[5, 1, 0, 0]); // type, len=1, reserved(2)
                out.extend_from_slice(&mtu.to_be_bytes());
            }
            Self::PrefixInfo(info) => {
                let mut flags = 0u8;
                if info.on_link {
                    flags |= 0x80;
                }
                if info.autonomous {
                    flags |= 0x40;
                }
                out.extend_from_slice(&[3, 4, info.prefix_len, flags]);
                out.extend_from_slice(&info.valid_lifetime.to_be_bytes());
                out.extend_from_slice(&info.preferred_lifetime.to_be_bytes());
                out.extend_from_slice(&[0, 0, 0, 0]); // reserved
                out.extend_from_slice(&info.prefix.0);
            }
            Self::Unknown(kind, body) => {
                // Length in 8-byte units, including the 2-byte header.
                let units = (body.len() + 2).div_ceil(8);
                out.push(*kind);
                out.push(u8::try_from(units).unwrap_or(0));
                out.extend_from_slice(body);
                // Pad to the 8-byte unit boundary.
                let total = units * 8;
                out.resize(out.len() + total.saturating_sub(body.len() + 2), 0);
            }
        }
    }
}

/// Append a link-layer-address option (`SLLA`/`TLLA`) of the given `kind`.
fn encode_lladdr(out: &mut Vec<u8>, kind: u8, mac: MacAddress) {
    out.push(kind);
    out.push(1); // length = 1 unit (8 bytes: 2 header + 6 MAC)
    out.extend_from_slice(&mac.0);
}

/// Encode a list of options into a contiguous byte buffer.
fn encode_options(options: &[NdpOption]) -> Vec<u8> {
    let mut out = Vec::new();
    for opt in options {
        opt.encode(&mut out);
    }
    out
}

/// Parse an option list. Returns `None` on a malformed (zero-length or
/// truncated) option, so callers can reject the whole message.
fn parse_options(mut bytes: &[u8]) -> Option<Vec<NdpOption>> {
    let mut out = Vec::new();
    while !bytes.is_empty() {
        let kind = *bytes.first()?;
        let units = usize::from(*bytes.get(1)?);
        if units == 0 {
            return None; // zero length is illegal and would loop forever
        }
        let total = units * 8;
        let opt_bytes = bytes.get(..total)?;
        let body = opt_bytes.get(2..)?;
        out.push(decode_option(kind, body));
        bytes = bytes.get(total..)?;
    }
    Some(out)
}

/// Decode one option body (the bytes after the 2-byte type/length prefix).
fn decode_option(kind: u8, body: &[u8]) -> NdpOption {
    match kind {
        1 | 2 => {
            if let Some(mac) = body.get(..6).and_then(|b| b.try_into().ok()) {
                let mac = MacAddress(mac);
                return if kind == 1 {
                    NdpOption::SourceLinkAddr(mac)
                } else {
                    NdpOption::TargetLinkAddr(mac)
                };
            }
            NdpOption::Unknown(kind, body.to_vec())
        }
        3 => decode_prefix_info(body).map_or_else(
            || NdpOption::Unknown(kind, body.to_vec()),
            NdpOption::PrefixInfo,
        ),
        // MTU option body: 2 reserved bytes then the 4-byte MTU.
        5 => body.get(2..6).and_then(|b| b.try_into().ok()).map_or_else(
            || NdpOption::Unknown(kind, body.to_vec()),
            |b| NdpOption::Mtu(u32::from_be_bytes(b)),
        ),
        _ => NdpOption::Unknown(kind, body.to_vec()),
    }
}

/// Decode a Prefix Information option body.
fn decode_prefix_info(body: &[u8]) -> Option<PrefixInfo> {
    let prefix_len = *body.first()?;
    let flags = *body.get(1)?;
    let valid_lifetime = u32::from_be_bytes(body.get(2..6)?.try_into().ok()?);
    let preferred_lifetime = u32::from_be_bytes(body.get(6..10)?.try_into().ok()?);
    // bytes 10..14 reserved
    let prefix = Ipv6Addr(body.get(14..30)?.try_into().ok()?);
    Some(PrefixInfo {
        prefix_len,
        on_link: flags & 0x80 != 0,
        autonomous: flags & 0x40 != 0,
        valid_lifetime,
        preferred_lifetime,
        prefix,
    })
}

// =============================================================================
// Messages
// =============================================================================

/// Flags carried by a Neighbor Advertisement (RFC 4861 § 4.4).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct NaFlags {
    /// Router flag (`R`): the sender is a router.
    pub router: bool,
    /// Solicited flag (`S`): this answers a specific `NS`.
    pub solicited: bool,
    /// Override flag (`O`): update an existing cache entry.
    pub override_flag: bool,
}

impl NaFlags {
    fn to_byte(self) -> u8 {
        let mut b = 0u8;
        if self.router {
            b |= 0x80;
        }
        if self.solicited {
            b |= 0x40;
        }
        if self.override_flag {
            b |= 0x20;
        }
        b
    }

    fn from_byte(b: u8) -> Self {
        Self {
            router: b & 0x80 != 0,
            solicited: b & 0x40 != 0,
            override_flag: b & 0x20 != 0,
        }
    }
}

/// Parameters carried by a Router Advertisement (RFC 4861 § 4.2).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RaConfig {
    /// Default hop limit hosts should use (0 = unspecified).
    pub cur_hop_limit: u8,
    /// Managed-address-configuration flag (`M`): use stateful `DHCPv6`.
    pub managed: bool,
    /// Other-configuration flag (`O`): use `DHCPv6` for other parameters.
    pub other: bool,
    /// Router lifetime in seconds (0 = not a default router).
    pub router_lifetime: u16,
    /// Reachable time in milliseconds.
    pub reachable_time: u32,
    /// Retransmit timer in milliseconds.
    pub retrans_timer: u32,
}

/// A parsed Neighbor Discovery message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NdpMessage {
    /// Router Solicitation.
    RouterSolicitation {
        /// Carried options (e.g. source link-layer address).
        options: Vec<NdpOption>,
    },
    /// Router Advertisement.
    RouterAdvertisement {
        /// Advertised router parameters.
        config: RaConfig,
        /// Carried options (prefix info, `MTU`, source link-layer address).
        options: Vec<NdpOption>,
    },
    /// Neighbor Solicitation.
    NeighborSolicitation {
        /// The address being resolved.
        target: Ipv6Addr,
        /// Carried options (e.g. source link-layer address).
        options: Vec<NdpOption>,
    },
    /// Neighbor Advertisement.
    NeighborAdvertisement {
        /// Advertisement flags.
        flags: NaFlags,
        /// The address this advertisement is for.
        target: Ipv6Addr,
        /// Carried options (e.g. target link-layer address).
        options: Vec<NdpOption>,
    },
}

impl NdpMessage {
    /// Parse a full `ICMPv6` message into a Neighbor Discovery message, or
    /// `None` if it is not a well-formed `NDP` message.
    #[must_use]
    pub fn parse(message: &[u8]) -> Option<Self> {
        let (hdr, body) = Icmpv6Header::parse(message)?;
        match hdr.msg_type {
            Icmpv6Type::ROUTER_SOLICITATION => Some(Self::RouterSolicitation {
                // RS body is reserved(4) + options. The 4 reserved bytes live
                // in the first 4 body bytes (after the 4-byte ICMPv6 rest).
                options: parse_options(body.get(4..)?)?,
            }),
            Icmpv6Type::ROUTER_ADVERTISEMENT => {
                let config = RaConfig {
                    cur_hop_limit: hdr.rest[0],
                    managed: hdr.rest[1] & 0x80 != 0,
                    other: hdr.rest[1] & 0x40 != 0,
                    router_lifetime: u16::from_be_bytes([hdr.rest[2], hdr.rest[3]]),
                    reachable_time: u32::from_be_bytes(body.get(0..4)?.try_into().ok()?),
                    retrans_timer: u32::from_be_bytes(body.get(4..8)?.try_into().ok()?),
                };
                Some(Self::RouterAdvertisement {
                    config,
                    options: parse_options(body.get(8..)?)?,
                })
            }
            Icmpv6Type::NEIGHBOR_SOLICITATION => Some(Self::NeighborSolicitation {
                target: Ipv6Addr(body.get(4..20)?.try_into().ok()?),
                options: parse_options(body.get(20..)?)?,
            }),
            Icmpv6Type::NEIGHBOR_ADVERTISEMENT => Some(Self::NeighborAdvertisement {
                flags: NaFlags::from_byte(hdr.rest[0]),
                target: Ipv6Addr(body.get(4..20)?.try_into().ok()?),
                options: parse_options(body.get(20..)?)?,
            }),
            _ => None,
        }
    }
}

/// Build a Neighbor Solicitation resolving `target`, sent from `src` to `dst`
/// (usually `target`'s solicited-node multicast address).
#[must_use]
pub fn build_neighbor_solicitation(
    src: Ipv6Addr,
    dst: Ipv6Addr,
    target: Ipv6Addr,
    source_lladdr: Option<MacAddress>,
) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(&[0, 0, 0, 0]); // reserved (after the ICMPv6 rest)
    body.extend_from_slice(&target.0);
    if let Some(mac) = source_lladdr {
        body.extend_from_slice(&encode_options(&[NdpOption::SourceLinkAddr(mac)]));
    }
    icmpv6::build_message(
        Icmpv6Type::NEIGHBOR_SOLICITATION,
        0,
        [0; 4],
        &body,
        src,
        dst,
    )
}

/// Build a Neighbor Advertisement for `target`, sent from `src` to `dst`.
#[must_use]
pub fn build_neighbor_advertisement(
    src: Ipv6Addr,
    dst: Ipv6Addr,
    target: Ipv6Addr,
    flags: NaFlags,
    target_lladdr: Option<MacAddress>,
) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(&[0, 0, 0, 0]); // reserved
    body.extend_from_slice(&target.0);
    if let Some(mac) = target_lladdr {
        body.extend_from_slice(&encode_options(&[NdpOption::TargetLinkAddr(mac)]));
    }
    icmpv6::build_message(
        Icmpv6Type::NEIGHBOR_ADVERTISEMENT,
        0,
        [flags.to_byte(), 0, 0, 0],
        &body,
        src,
        dst,
    )
}

/// Build a Router Solicitation, sent from `src` to `dst` (usually the
/// all-routers multicast address).
#[must_use]
pub fn build_router_solicitation(
    src: Ipv6Addr,
    dst: Ipv6Addr,
    source_lladdr: Option<MacAddress>,
) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(&[0, 0, 0, 0]); // reserved
    if let Some(mac) = source_lladdr {
        body.extend_from_slice(&encode_options(&[NdpOption::SourceLinkAddr(mac)]));
    }
    icmpv6::build_message(Icmpv6Type::ROUTER_SOLICITATION, 0, [0; 4], &body, src, dst)
}

/// Build a Router Advertisement, sent from `src` to `dst`.
#[must_use]
pub fn build_router_advertisement(
    src: Ipv6Addr,
    dst: Ipv6Addr,
    config: RaConfig,
    options: &[NdpOption],
) -> Vec<u8> {
    let mut flags = 0u8;
    if config.managed {
        flags |= 0x80;
    }
    if config.other {
        flags |= 0x40;
    }
    let lifetime = config.router_lifetime.to_be_bytes();
    let rest = [config.cur_hop_limit, flags, lifetime[0], lifetime[1]];
    let mut body = Vec::new();
    body.extend_from_slice(&config.reachable_time.to_be_bytes());
    body.extend_from_slice(&config.retrans_timer.to_be_bytes());
    body.extend_from_slice(&encode_options(options));
    icmpv6::build_message(Icmpv6Type::ROUTER_ADVERTISEMENT, 0, rest, &body, src, dst)
}

// =============================================================================
// Neighbor cache (RFC 4861 § 5.1)
// =============================================================================

/// Reachability state of a [`NeighborEntry`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NeighborState {
    /// Address resolution is in progress; no link-layer address yet.
    Incomplete,
    /// The link-layer address is known and recently confirmed.
    Reachable,
    /// The link-layer address is known but may be out of date.
    Stale,
}

/// A neighbor cache entry: a link-layer address and its reachability state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NeighborEntry {
    /// The resolved link-layer address (meaningless while `Incomplete`).
    pub mac: MacAddress,
    /// The reachability state.
    pub state: NeighborState,
}

/// Maps `IPv6` neighbour addresses to their link-layer addresses — the `IPv6`
/// analogue of the `ARP` table.
#[derive(Debug, Default, Clone)]
pub struct NeighborCache {
    entries: alloc::collections::BTreeMap<[u8; 16], NeighborEntry>,
}

impl NeighborCache {
    /// Create an empty neighbor cache.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Record `ip` as resolved to `mac` in the `Reachable` state, e.g. after a
    /// solicited Neighbor Advertisement.
    pub fn insert_reachable(&mut self, ip: Ipv6Addr, mac: MacAddress) {
        self.entries.insert(
            ip.0,
            NeighborEntry {
                mac,
                state: NeighborState::Reachable,
            },
        );
    }

    /// Mark `ip` as `Incomplete` (resolution started) if not already present.
    pub fn start_resolution(&mut self, ip: Ipv6Addr) {
        self.entries.entry(ip.0).or_insert(NeighborEntry {
            mac: MacAddress([0; 6]),
            state: NeighborState::Incomplete,
        });
    }

    /// Look up the cache entry for `ip`, if any.
    #[must_use]
    pub fn lookup(&self, ip: Ipv6Addr) -> Option<&NeighborEntry> {
        self.entries.get(&ip.0)
    }

    /// The resolved link-layer address for `ip`, if it is known (not
    /// `Incomplete`).
    #[must_use]
    pub fn resolve(&self, ip: Ipv6Addr) -> Option<MacAddress> {
        match self.entries.get(&ip.0) {
            Some(e) if e.state != NeighborState::Incomplete => Some(e.mac),
            _ => None,
        }
    }

    /// Number of cached neighbours.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the cache is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::indexing_slicing, clippy::unwrap_used, clippy::panic)]
    use super::*;

    fn host() -> Ipv6Addr {
        Ipv6Addr([0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1])
    }
    fn router() -> Ipv6Addr {
        Ipv6Addr([0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2])
    }
    fn mac() -> MacAddress {
        MacAddress([0x02, 0, 0, 0, 0, 0x11])
    }

    #[test]
    fn neighbor_solicitation_round_trips_with_source_lladdr() {
        let msg = build_neighbor_solicitation(host(), router(), router(), Some(mac()));
        assert!(icmpv6::verify_checksum(host(), router(), &msg));
        match NdpMessage::parse(&msg).unwrap() {
            NdpMessage::NeighborSolicitation { target, options } => {
                assert_eq!(target, router());
                assert_eq!(options, alloc::vec![NdpOption::SourceLinkAddr(mac())]);
            }
            other => panic!("expected NS, got {other:?}"),
        }
    }

    #[test]
    fn neighbor_advertisement_round_trips_with_flags_and_tlla() {
        let flags = NaFlags {
            router: true,
            solicited: true,
            override_flag: false,
        };
        let msg = build_neighbor_advertisement(router(), host(), router(), flags, Some(mac()));
        assert!(icmpv6::verify_checksum(router(), host(), &msg));
        match NdpMessage::parse(&msg).unwrap() {
            NdpMessage::NeighborAdvertisement {
                flags: f,
                target,
                options,
            } => {
                assert_eq!(f, flags);
                assert_eq!(target, router());
                assert_eq!(options, alloc::vec![NdpOption::TargetLinkAddr(mac())]);
            }
            other => panic!("expected NA, got {other:?}"),
        }
    }

    #[test]
    fn router_solicitation_round_trips() {
        let msg = build_router_solicitation(host(), router(), Some(mac()));
        assert!(icmpv6::verify_checksum(host(), router(), &msg));
        match NdpMessage::parse(&msg).unwrap() {
            NdpMessage::RouterSolicitation { options } => {
                assert_eq!(options, alloc::vec![NdpOption::SourceLinkAddr(mac())]);
            }
            other => panic!("expected RS, got {other:?}"),
        }
    }

    #[test]
    fn router_advertisement_round_trips_with_prefix_and_mtu() {
        let config = RaConfig {
            cur_hop_limit: 64,
            managed: false,
            other: true,
            router_lifetime: 1800,
            reachable_time: 30_000,
            retrans_timer: 1000,
        };
        let prefix = PrefixInfo {
            prefix_len: 64,
            on_link: true,
            autonomous: true,
            valid_lifetime: 86_400,
            preferred_lifetime: 14_400,
            prefix: Ipv6Addr([0x20, 0x01, 0xd, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
        };
        let opts = [
            NdpOption::SourceLinkAddr(mac()),
            NdpOption::Mtu(1500),
            NdpOption::PrefixInfo(prefix),
        ];
        let msg = build_router_advertisement(router(), host(), config, &opts);
        assert!(icmpv6::verify_checksum(router(), host(), &msg));
        match NdpMessage::parse(&msg).unwrap() {
            NdpMessage::RouterAdvertisement { config: c, options } => {
                assert_eq!(c, config);
                assert_eq!(options.len(), 3);
                assert_eq!(options[0], NdpOption::SourceLinkAddr(mac()));
                assert_eq!(options[1], NdpOption::Mtu(1500));
                assert_eq!(options[2], NdpOption::PrefixInfo(prefix));
            }
            other => panic!("expected RA, got {other:?}"),
        }
    }

    #[test]
    fn parse_options_rejects_zero_length() {
        // A zero-length option must be rejected (it would otherwise loop).
        assert!(parse_options(&[1, 0, 0, 0, 0, 0, 0, 0]).is_none());
    }

    #[test]
    fn parse_rejects_non_ndp_and_truncated() {
        // An echo request is ICMPv6 but not an NDP message.
        let echo = icmpv6::build_echo_request(host(), router(), 1, 1, &[]);
        assert!(NdpMessage::parse(&echo).is_none());
        assert!(NdpMessage::parse(&[0u8; 4]).is_none());
    }

    #[test]
    fn neighbor_cache_resolves_after_advertisement() {
        let mut cache = NeighborCache::new();
        assert!(cache.is_empty());
        cache.start_resolution(router());
        // Incomplete: address not yet resolvable.
        assert_eq!(cache.resolve(router()), None);
        assert_eq!(
            cache.lookup(router()).unwrap().state,
            NeighborState::Incomplete
        );
        // A solicited advertisement resolves it.
        cache.insert_reachable(router(), mac());
        assert_eq!(cache.resolve(router()), Some(mac()));
        assert_eq!(cache.len(), 1);
        // Unknown neighbours are absent.
        assert_eq!(cache.resolve(host()), None);
    }
}
