//! Network configuration application (TASK-25 / WS4-02).
//!
//! Turns a DHCP lease into the concrete interface + routing + resolver
//! configuration the network service applies (`.3`), provides an RFC 3927
//! link-local fallback so a failed DHCP no longer pins the lab-specific
//! `192.0.2.50` address (`.6`), and models an `/etc`-style network
//! configuration that Settings can read and write (`.5`).
//!
//! All three are pure, host-testable functions/types; the bare-metal
//! `nexacore-net-image` boot path calls them instead of duplicating the logic
//! inline.

use alloc::{
    format,
    string::{String, ToString},
    vec,
    vec::Vec,
};

use nexacore_types::net::{Cidr, Ipv4Addr, MacAddress};

use crate::ip::{InterfaceConfig, Route};

/// Default public resolvers, used only when a lease (or the `/etc` config)
/// supplies none, so name resolution still works.
#[must_use]
pub fn default_dns_servers() -> Vec<Ipv4Addr> {
    vec![Ipv4Addr([1, 1, 1, 1]), Ipv4Addr([8, 8, 8, 8])]
}

/// Count the leading one-bits of a subnet mask to obtain its CIDR prefix length.
///
/// A well-formed mask is a run of ones followed by zeros, so `leading_ones` is
/// exact; a malformed (non-contiguous) mask still yields a sane prefix from its
/// leading run.
#[must_use]
pub fn mask_to_prefix_len(mask: Ipv4Addr) -> u8 {
    // `leading_ones` on the big-endian u32 counts the contiguous high ones and
    // is at most 32, so the u8 conversion never saturates.
    u8::try_from(u32::from_be_bytes(mask.0).leading_ones()).unwrap_or(32)
}

/// Bitwise-AND an address with a mask to obtain the network address.
#[must_use]
fn network_address(ip: Ipv4Addr, mask: Ipv4Addr) -> Ipv4Addr {
    let [a, b, c, d] = ip.0;
    let [ma, mb, mc, md] = mask.0;
    Ipv4Addr([a & ma, b & mb, c & mc, d & md])
}

/// The concrete configuration derived from a DHCP lease, ready to install into
/// the network service.
#[derive(Debug, Clone)]
pub struct AppliedConfig {
    /// The interface configuration (address + CIDR).
    pub interface: InterfaceConfig,
    /// The default route (`0.0.0.0/0` via the leased gateway), if the lease
    /// provided a router.
    pub default_route: Option<Route>,
    /// The resolvers to seed the DNS service with (never empty).
    pub dns_servers: Vec<Ipv4Addr>,
}

/// Apply a DHCP lease to interface `name` with hardware address `mac` and the
/// given `mtu` (WS4-02.3).
///
/// Converts the leased mask to a CIDR, installs a default route via the leased
/// gateway when present, and seeds the resolver with the leased DNS servers
/// (falling back to [`default_dns_servers`] when the lease carried none).
#[must_use]
pub fn apply_lease(
    lease: &crate::dhcp::DhcpLease,
    name: &str,
    mac: MacAddress,
    mtu: u16,
) -> AppliedConfig {
    let prefix = mask_to_prefix_len(lease.subnet_mask);
    let net = network_address(lease.client_ip, lease.subnet_mask);
    // `mask_to_prefix_len` caps at 32, so `Cidr::new` always succeeds; the
    // struct literal is a defensive fallback that cannot actually be reached.
    let cidr = Cidr::new(net, prefix).unwrap_or(Cidr {
        addr: net,
        prefix_len: 24,
    });

    let default_route = lease.gateway.map(|gw| Route {
        destination: default_route_cidr(),
        gateway: Some(gw),
        interface: name.to_string(),
        metric: 100,
    });

    let dns_servers = if lease.dns_servers.is_empty() {
        default_dns_servers()
    } else {
        lease.dns_servers.clone()
    };

    AppliedConfig {
        interface: InterfaceConfig {
            name: name.to_string(),
            ip: lease.client_ip,
            netmask: cidr,
            mac,
            mtu,
        },
        default_route,
        dns_servers,
    }
}

/// Compute an RFC 3927 link-local address (`169.254.1.0`–`169.254.254.255`)
/// deterministically from the MAC, for use when DHCP yields no lease
/// (WS4-02.6).
///
/// This replaces the previous hard-coded lab address `192.0.2.50`: a host
/// with no DHCP server now self-assigns a standard link-local address instead
/// of silently claiming a site-specific IP.
#[must_use]
pub fn link_local_address(mac: MacAddress) -> Ipv4Addr {
    let [.., e, f] = mac.0;
    // Third octet in 1..=254 (0 and 255 are reserved in the link-local block).
    let third = 1 + (e % 254);
    Ipv4Addr([169, 254, third, f])
}

/// Build the full link-local interface configuration (address + `/16`) for a
/// DHCP-less boot (WS4-02.6).
#[must_use]
pub fn link_local_config(name: &str, mac: MacAddress, mtu: u16) -> InterfaceConfig {
    let ip = link_local_address(mac);
    InterfaceConfig {
        name: name.to_string(),
        ip,
        // 169.254.0.0/16 — prefix 16 ≤ 32 is always valid.
        netmask: Cidr {
            addr: Ipv4Addr([169, 254, 0, 0]),
            prefix_len: 16,
        },
        mac,
        mtu,
    }
}

/// The `0.0.0.0/0` default-route destination (prefix 0 is always valid).
fn default_route_cidr() -> Cidr {
    Cidr {
        addr: Ipv4Addr([0, 0, 0, 0]),
        prefix_len: 0,
    }
}

// =============================================================================
// EtcNetworkConfig — /etc-style config exposed via Settings (WS4-02.5)
// =============================================================================

/// A persistent `/etc`-style network configuration surface, akin to
/// `/etc/hostname` + `/etc/resolv.conf`, that Settings can read and write.
///
/// Serialises to a deterministic `key=value` text so it round-trips through the
/// config store (WS17). Empty fields are represented explicitly so a parse of
/// a serialise reproduces the exact struct.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct EtcNetworkConfig {
    /// System hostname.
    pub hostname: String,
    /// Static default gateway override, if any (otherwise DHCP-provided).
    pub gateway: Option<Ipv4Addr>,
    /// Resolver addresses, in preference order.
    pub dns_servers: Vec<Ipv4Addr>,
    /// DNS search domains (e.g. `lan`), in order.
    pub search_domains: Vec<String>,
}

impl EtcNetworkConfig {
    /// Serialise to deterministic `key=value` lines
    /// (`hostname`, `gateway`, `dns`, `search`).
    #[must_use]
    pub fn serialize(&self) -> String {
        let gateway = self.gateway.map(format_ipv4).unwrap_or_default();
        let dns = self
            .dns_servers
            .iter()
            .map(|ip| format_ipv4(*ip))
            .collect::<Vec<_>>()
            .join(",");
        let search = self.search_domains.join(",");
        format!(
            "hostname={}\ngateway={gateway}\ndns={dns}\nsearch={search}\n",
            self.hostname
        )
    }

    /// Parse the `key=value` form produced by [`Self::serialize`]. Unknown keys
    /// are ignored; malformed IP entries are dropped. Returns `None` only if the
    /// input is not line-structured `key=value` text at all.
    #[must_use]
    pub fn parse(text: &str) -> Option<Self> {
        let mut cfg = Self::default();
        let mut saw_kv = false;
        for line in text.lines() {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            let (key, value) = line.split_once('=')?;
            saw_kv = true;
            match key.trim() {
                "hostname" => cfg.hostname = value.trim().to_string(),
                "gateway" => {
                    let v = value.trim();
                    cfg.gateway = if v.is_empty() { None } else { parse_ipv4(v) };
                }
                "dns" => {
                    cfg.dns_servers = value
                        .split(',')
                        .filter_map(|s| parse_ipv4(s.trim()))
                        .collect();
                }
                "search" => {
                    cfg.search_domains = value
                        .split(',')
                        .map(str::trim)
                        .filter(|s| !s.is_empty())
                        .map(ToString::to_string)
                        .collect();
                }
                _ => {}
            }
        }
        if saw_kv { Some(cfg) } else { None }
    }

    /// The effective resolvers: the configured ones, or [`default_dns_servers`]
    /// when none are set — so resolution never silently breaks.
    #[must_use]
    pub fn effective_dns(&self) -> Vec<Ipv4Addr> {
        if self.dns_servers.is_empty() {
            default_dns_servers()
        } else {
            self.dns_servers.clone()
        }
    }
}

/// Format an `IPv4` address as dotted-decimal.
#[must_use]
pub fn format_ipv4(ip: Ipv4Addr) -> String {
    let [a, b, c, d] = ip.0;
    format!("{a}.{b}.{c}.{d}")
}

/// Parse a dotted-decimal `IPv4` address; returns `None` on any malformed part.
#[must_use]
pub fn parse_ipv4(s: &str) -> Option<Ipv4Addr> {
    let mut octets = [0u8; 4];
    let mut count = 0usize;
    for part in s.split('.') {
        let byte = part.parse::<u8>().ok()?;
        let slot = octets.get_mut(count)?;
        *slot = byte;
        count += 1;
    }
    if count == 4 {
        Some(Ipv4Addr(octets))
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::indexing_slicing, clippy::unwrap_used, clippy::expect_used)]

    use super::*;
    use crate::dhcp::DhcpLease;

    fn lease() -> DhcpLease {
        DhcpLease {
            client_ip: Ipv4Addr([10, 0, 5, 42]),
            subnet_mask: Ipv4Addr([255, 255, 255, 0]),
            gateway: Some(Ipv4Addr([10, 0, 5, 1])),
            dns_servers: vec![Ipv4Addr([10, 0, 5, 53])],
            server_ip: Ipv4Addr([10, 0, 5, 1]),
            lease_time_secs: 3600,
            obtained_at: 1000,
        }
    }

    #[test]
    fn mask_to_prefix_len_common_masks() {
        assert_eq!(mask_to_prefix_len(Ipv4Addr([255, 255, 255, 0])), 24);
        assert_eq!(mask_to_prefix_len(Ipv4Addr([255, 255, 0, 0])), 16);
        assert_eq!(mask_to_prefix_len(Ipv4Addr([255, 255, 255, 240])), 28);
        assert_eq!(mask_to_prefix_len(Ipv4Addr([0, 0, 0, 0])), 0);
        assert_eq!(mask_to_prefix_len(Ipv4Addr([255, 255, 255, 255])), 32);
    }

    #[test]
    fn apply_lease_sets_cidr_route_and_dns() {
        let applied = apply_lease(&lease(), "eth0", MacAddress([1, 2, 3, 4, 5, 6]), 1500);
        assert_eq!(applied.interface.ip, Ipv4Addr([10, 0, 5, 42]));
        assert_eq!(applied.interface.netmask.prefix_len, 24);
        // Network address is masked.
        assert_eq!(
            applied.interface.netmask.network_addr(),
            Ipv4Addr([10, 0, 5, 0])
        );
        let route = applied.default_route.expect("default route");
        assert_eq!(route.destination.prefix_len, 0);
        assert_eq!(route.gateway, Some(Ipv4Addr([10, 0, 5, 1])));
        assert_eq!(route.interface, "eth0");
        assert_eq!(applied.dns_servers, vec![Ipv4Addr([10, 0, 5, 53])]);
    }

    #[test]
    fn apply_lease_without_gateway_or_dns_uses_fallbacks() {
        let mut l = lease();
        l.gateway = None;
        l.dns_servers.clear();
        let applied = apply_lease(&l, "eth0", MacAddress([1, 2, 3, 4, 5, 6]), 1500);
        assert!(applied.default_route.is_none());
        assert_eq!(applied.dns_servers, default_dns_servers());
    }

    #[test]
    fn link_local_is_rfc3927_and_deterministic() {
        let mac = MacAddress([0x52, 0x54, 0x00, 0x12, 0x34, 0x56]);
        let ip = link_local_address(mac);
        assert_eq!(ip.0[0], 169);
        assert_eq!(ip.0[1], 254);
        assert!((1..=254).contains(&ip.0[2]));
        // Deterministic.
        assert_eq!(link_local_address(mac), ip);
        // Never the old hard-coded lab address.
        assert_ne!(ip, Ipv4Addr([192, 0, 2, 50]));
        let cfg = link_local_config("eth0", mac, 1500);
        assert_eq!(cfg.netmask.prefix_len, 16);
        assert_eq!(cfg.ip, ip);
    }

    #[test]
    fn etc_config_round_trips() {
        let cfg = EtcNetworkConfig {
            hostname: String::from("nexacore-host"),
            gateway: Some(Ipv4Addr([10, 0, 5, 1])),
            dns_servers: vec![Ipv4Addr([10, 0, 5, 53]), Ipv4Addr([1, 1, 1, 1])],
            search_domains: vec![String::from("lan"), String::from("local")],
        };
        let text = cfg.serialize();
        let parsed = EtcNetworkConfig::parse(&text).expect("parse");
        assert_eq!(parsed, cfg);
    }

    #[test]
    fn etc_config_empty_fields_round_trip() {
        let cfg = EtcNetworkConfig {
            hostname: String::from("h"),
            gateway: None,
            dns_servers: vec![],
            search_domains: vec![],
        };
        let parsed = EtcNetworkConfig::parse(&cfg.serialize()).expect("parse");
        assert_eq!(parsed, cfg);
        assert_eq!(parsed.effective_dns(), default_dns_servers());
    }

    #[test]
    fn parse_rejects_non_kv_text() {
        assert!(EtcNetworkConfig::parse("this is not config").is_none());
        assert!(EtcNetworkConfig::parse("").is_none());
    }

    #[test]
    fn parse_ipv4_round_trip_and_rejects_bad() {
        assert_eq!(parse_ipv4("192.0.2.50"), Some(Ipv4Addr([192, 0, 2, 50])));
        assert_eq!(parse_ipv4("256.0.0.1"), None);
        assert_eq!(parse_ipv4("1.2.3"), None);
        assert_eq!(parse_ipv4("1.2.3.4.5"), None);
        assert_eq!(format_ipv4(Ipv4Addr([8, 8, 4, 4])), "8.8.4.4");
    }
}
