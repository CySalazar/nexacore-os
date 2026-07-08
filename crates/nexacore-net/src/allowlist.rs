//! Per-app network egress allow lists (WS4-05.4).
//!
//! The default-deny egress model (WS4-05.2) needs an explicit statement of what
//! each app may reach. An [`AppAllowList`] is an ordered set of [`EgressRule`]s;
//! a connection is permitted only if some rule matches its target
//! ([`AppAllowList::permits`]) — an empty list denies everything.
//!
//! Each rule is written `<proto> <host> <port>`:
//! - `proto`: `tcp`, `udp`, or `*` (any)
//! - `host`: `*` (any), an `IPv4` address or CIDR (`10.0.0.0/8`), or a domain
//!   suffix (`example.com`, matching it and its subdomains)
//! - `port`: `*`, a number, or an inclusive range `1000-2000`
//!
//! This is the format + matcher; applying it in the socket-creation path and
//! surfacing it in settings / the Helper Impact Dashboard is WS4-05.5/.6.

use alloc::{
    string::{String, ToString},
    vec::Vec,
};

use crate::conntrack::Protocol;

/// How a rule matches the destination host.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HostMatch {
    /// Any host.
    Any,
    /// An `IPv4` prefix (`base`/`prefix`); a bare address is `/32`.
    Cidr {
        /// The network base address.
        base: u32,
        /// The prefix length in bits (0..=32).
        prefix: u8,
    },
    /// A domain and its subdomains (suffix match on a label boundary).
    DomainSuffix(String),
}

impl HostMatch {
    fn matches(&self, ip: u32, domain: Option<&str>) -> bool {
        match self {
            Self::Any => true,
            Self::Cidr { base, prefix } => {
                let mask = if *prefix == 0 {
                    0
                } else {
                    u32::MAX << (32 - u32::from(*prefix))
                };
                (ip & mask) == (base & mask)
            }
            Self::DomainSuffix(suffix) => domain.is_some_and(|d| {
                d.strip_suffix(suffix.as_str())
                    .is_some_and(|rest| rest.is_empty() || rest.ends_with('.'))
            }),
        }
    }
}

/// How a rule matches the destination port.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PortMatch {
    /// Any port.
    Any,
    /// One specific port.
    Exact(u16),
    /// An inclusive range.
    Range(u16, u16),
}

impl PortMatch {
    fn matches(self, port: u16) -> bool {
        match self {
            Self::Any => true,
            Self::Exact(p) => port == p,
            Self::Range(lo, hi) => port >= lo && port <= hi,
        }
    }
}

/// A single egress rule.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EgressRule {
    /// The protocol the rule applies to (`None` = any).
    pub protocol: Option<Protocol>,
    /// The host match.
    pub host: HostMatch,
    /// The port match.
    pub port: PortMatch,
}

/// A connection target being checked against an allow list.
#[derive(Debug, Clone, Copy)]
pub struct EgressTarget<'a> {
    /// The transport protocol.
    pub protocol: Protocol,
    /// The resolved destination `IPv4` address.
    pub ip: u32,
    /// The destination domain, if the connection was made by name.
    pub domain: Option<&'a str>,
    /// The destination port.
    pub port: u16,
}

/// Parse a dotted-quad `IPv4` address to a host-order `u32`.
fn parse_ipv4(s: &str) -> Option<u32> {
    let mut acc = 0u32;
    let mut count = 0u8;
    for part in s.split('.') {
        let octet: u8 = part.parse().ok()?;
        acc = (acc << 8) | u32::from(octet);
        count += 1;
    }
    if count == 4 { Some(acc) } else { None }
}

impl EgressRule {
    /// Whether this rule permits `target`.
    #[must_use]
    pub fn matches(&self, target: &EgressTarget) -> bool {
        if let Some(p) = self.protocol {
            if p != target.protocol {
                return false;
            }
        }
        self.host.matches(target.ip, target.domain) && self.port.matches(target.port)
    }

    /// Parse a `<proto> <host> <port>` rule line.
    ///
    /// Returns `None` if the line does not have three fields or any field is
    /// malformed.
    #[must_use]
    pub fn parse(line: &str) -> Option<Self> {
        let mut fields = line.split_whitespace();
        let proto_s = fields.next()?;
        let host_s = fields.next()?;
        let port_s = fields.next()?;
        if fields.next().is_some() {
            return None; // trailing junk
        }

        let protocol = match proto_s {
            "tcp" => Some(Protocol::Tcp),
            "udp" => Some(Protocol::Udp),
            "*" => None,
            _ => return None,
        };

        let host = if host_s == "*" {
            HostMatch::Any
        } else if let Some((ip_s, prefix_s)) = host_s.split_once('/') {
            let base = parse_ipv4(ip_s)?;
            let prefix: u8 = prefix_s.parse().ok()?;
            if prefix > 32 {
                return None;
            }
            HostMatch::Cidr { base, prefix }
        } else if let Some(base) = parse_ipv4(host_s) {
            HostMatch::Cidr { base, prefix: 32 }
        } else {
            HostMatch::DomainSuffix(host_s.to_string())
        };

        let port = if port_s == "*" {
            PortMatch::Any
        } else if let Some((lo_s, hi_s)) = port_s.split_once('-') {
            PortMatch::Range(lo_s.parse().ok()?, hi_s.parse().ok()?)
        } else {
            PortMatch::Exact(port_s.parse().ok()?)
        };

        Some(Self {
            protocol,
            host,
            port,
        })
    }
}

/// A per-app egress allow list (WS4-05.4).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AppAllowList {
    /// The application this list governs.
    pub app_id: String,
    /// The rules; a target is permitted if any rule matches.
    pub rules: Vec<EgressRule>,
}

impl AppAllowList {
    /// An empty (deny-all) list for `app_id`.
    #[must_use]
    pub fn new(app_id: &str) -> Self {
        Self {
            app_id: app_id.to_string(),
            rules: Vec::new(),
        }
    }

    /// Add a rule.
    pub fn push(&mut self, rule: EgressRule) {
        self.rules.push(rule);
    }

    /// Parse a whole-document allow list (one rule per non-empty, non-`#` line).
    /// Malformed lines are skipped.
    #[must_use]
    pub fn parse(app_id: &str, text: &str) -> Self {
        let mut list = Self::new(app_id);
        for line in text.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            if let Some(rule) = EgressRule::parse(line) {
                list.push(rule);
            }
        }
        list
    }

    /// Whether the app is permitted to reach `target` (default-deny).
    #[must_use]
    pub fn permits(&self, target: &EgressTarget) -> bool {
        self.rules.iter().any(|r| r.matches(target))
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

    fn ip(a: u8, b: u8, c: u8, d: u8) -> u32 {
        u32::from_be_bytes([a, b, c, d])
    }

    fn target<'a>(
        protocol: Protocol,
        ip: u32,
        domain: Option<&'a str>,
        port: u16,
    ) -> EgressTarget<'a> {
        EgressTarget {
            protocol,
            ip,
            domain,
            port,
        }
    }

    #[test]
    fn cidr_rule_matches_protocol_network_and_port() {
        let rule = EgressRule::parse("tcp 10.0.0.0/8 443").unwrap();
        assert!(rule.matches(&target(Protocol::Tcp, ip(10, 1, 2, 3), None, 443)));
        // Wrong network, wrong protocol, wrong port each fail.
        assert!(!rule.matches(&target(Protocol::Tcp, ip(11, 0, 0, 1), None, 443)));
        assert!(!rule.matches(&target(Protocol::Udp, ip(10, 1, 2, 3), None, 443)));
        assert!(!rule.matches(&target(Protocol::Tcp, ip(10, 1, 2, 3), None, 80)));
    }

    #[test]
    fn domain_suffix_matches_on_label_boundary() {
        let rule = EgressRule::parse("* example.com *").unwrap();
        assert!(rule.matches(&target(Protocol::Tcp, 0, Some("example.com"), 443)));
        assert!(rule.matches(&target(Protocol::Udp, 0, Some("api.example.com"), 53)));
        // Not a subdomain, and a look-alike suffix, both fail.
        assert!(!rule.matches(&target(Protocol::Tcp, 0, Some("notexample.com"), 443)));
        assert!(!rule.matches(&target(Protocol::Tcp, 0, Some("example.com.evil.com"), 443)));
        // No domain on the target → domain rule cannot match.
        assert!(!rule.matches(&target(Protocol::Tcp, ip(1, 2, 3, 4), None, 443)));
    }

    #[test]
    fn bare_ip_is_slash_32_and_port_ranges_work() {
        let host = EgressRule::parse("tcp 1.2.3.4 *").unwrap();
        assert_eq!(
            host.host,
            HostMatch::Cidr {
                base: ip(1, 2, 3, 4),
                prefix: 32
            }
        );
        assert!(host.matches(&target(Protocol::Tcp, ip(1, 2, 3, 4), None, 9)));
        assert!(!host.matches(&target(Protocol::Tcp, ip(1, 2, 3, 5), None, 9)));

        let range = EgressRule::parse("udp * 1000-2000").unwrap();
        assert!(range.matches(&target(Protocol::Udp, 0, None, 1500)));
        assert!(!range.matches(&target(Protocol::Udp, 0, None, 2500)));
    }

    #[test]
    fn malformed_rules_are_rejected() {
        assert!(EgressRule::parse("tcp example.com").is_none()); // missing port
        assert!(EgressRule::parse("bogus * *").is_none()); // bad protocol
        assert!(EgressRule::parse("tcp 10.0.0.0/40 *").is_none()); // prefix > 32
        assert!(EgressRule::parse("tcp * nope").is_none()); // bad port
        assert!(EgressRule::parse("tcp * * extra").is_none()); // trailing junk
    }

    #[test]
    fn allow_list_is_default_deny_and_or_of_rules() {
        let list = AppAllowList::parse(
            "org.nexacore.updater",
            "# updates only\ntcp updates.nexacore.com 443\nudp 10.0.0.0/8 53\n",
        );
        assert_eq!(list.rules.len(), 2);
        assert!(list.permits(&target(Protocol::Tcp, 0, Some("updates.nexacore.com"), 443)));
        assert!(list.permits(&target(Protocol::Udp, ip(10, 0, 0, 53), None, 53)));
        // Anything not covered is denied.
        assert!(!list.permits(&target(
            Protocol::Tcp,
            ip(8, 8, 8, 8),
            Some("evil.com"),
            443
        )));
        // An empty list denies everything.
        let empty = AppAllowList::new("locked");
        assert!(!empty.permits(&target(Protocol::Tcp, ip(1, 1, 1, 1), None, 443)));
    }
}
