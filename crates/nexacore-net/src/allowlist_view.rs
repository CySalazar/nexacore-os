//! Presentation surface for per-app allow lists (WS4-05.6).
//!
//! The enforcement core ([`crate::allowlist`], [`crate::egress_policy`],
//! [`crate::enforcer`]) decides *whether* a connection is permitted. This
//! module renders those same per-app allow lists into a stable, UI-agnostic
//! shape that two consumers share:
//!
//! * the **Settings** network panel, which lists each app with its capability
//!   state and human-readable egress rules ([`AppNetworkView`]); and
//! * the **Helper Impact Dashboard**, which needs an aggregate read of how much
//!   network reach the installed apps have — how many can egress at all, how
//!   many are unrestricted, and how many distinct external domains are named —
//!   to score its Egress / Privacy / Capabilities dimensions
//!   ([`NetworkAccessOverview`]).
//!
//! Keeping this projection in the (dep-free `no_std`) net crate means both
//! renderers consume one tested shape rather than each re-deriving policy
//! meaning from raw rules.

use alloc::{
    string::{String, ToString},
    vec::Vec,
};

use crate::{
    allowlist::{AppAllowList, EgressRule, HostMatch, PortMatch},
    conntrack::Protocol,
    egress_policy::NetCapability,
};

/// Render one egress rule as a human-readable `proto host port` line, using
/// friendly tokens (`any`, `1.2.3.0/24`, `*.example.com`, `80`, `1000-2000`).
#[must_use]
pub fn describe_rule(rule: &EgressRule) -> String {
    let mut s = String::new();
    s.push_str(match rule.protocol {
        Some(Protocol::Tcp) => "tcp",
        Some(Protocol::Udp) => "udp",
        None => "any",
    });
    s.push(' ');
    s.push_str(&describe_host(&rule.host));
    s.push(' ');
    s.push_str(&describe_port(rule.port));
    s
}

fn describe_host(host: &HostMatch) -> String {
    match host {
        HostMatch::Any => "any".to_string(),
        HostMatch::Cidr { base, prefix } => {
            let o = base.to_be_bytes();
            let mut s = String::new();
            push_u8(&mut s, o[0]);
            s.push('.');
            push_u8(&mut s, o[1]);
            s.push('.');
            push_u8(&mut s, o[2]);
            s.push('.');
            push_u8(&mut s, o[3]);
            if *prefix != 32 {
                s.push('/');
                push_u8(&mut s, *prefix);
            }
            s
        }
        // Show a domain suffix the way users read it: `*.example.com`.
        HostMatch::DomainSuffix(d) => {
            let mut s = String::from("*.");
            s.push_str(d);
            s
        }
    }
}

fn describe_port(port: PortMatch) -> String {
    match port {
        PortMatch::Any => "any".to_string(),
        PortMatch::Exact(p) => {
            let mut s = String::new();
            push_u16(&mut s, p);
            s
        }
        PortMatch::Range(lo, hi) => {
            let mut s = String::new();
            push_u16(&mut s, lo);
            s.push('-');
            push_u16(&mut s, hi);
            s
        }
    }
}

fn push_u8(s: &mut String, v: u8) {
    push_u16(s, u16::from(v));
}

fn push_u16(s: &mut String, mut v: u16) {
    if v == 0 {
        s.push('0');
        return;
    }
    let mut buf = [0u8; 5];
    let mut i = buf.len();
    while v > 0 {
        i -= 1;
        if let Some(slot) = buf.get_mut(i) {
            *slot = b'0' + (v % 10) as u8;
        }
        v /= 10;
    }
    if let Some(digits) = buf.get(i..) {
        s.push_str(core::str::from_utf8(digits).unwrap_or("0"));
    }
}

/// Whether a rule grants unrestricted reach (any protocol, any host, any port).
#[must_use]
pub fn is_unrestricted_rule(rule: &EgressRule) -> bool {
    rule.protocol.is_none() && rule.host == HostMatch::Any && rule.port == PortMatch::Any
}

/// A single app's network posture, as shown in the Settings network panel.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppNetworkView {
    /// The application id.
    pub app_id: String,
    /// Whether the app holds a network capability at all.
    pub has_capability: bool,
    /// Whether the app can actually egress (capability held *and* at least one
    /// rule — an empty list is deny-all even with a capability).
    pub can_egress: bool,
    /// Whether any rule grants unrestricted reach (`any any any`).
    pub unrestricted: bool,
    /// Number of egress rules.
    pub rule_count: usize,
    /// Human-readable rendering of each rule, in order.
    pub rules: Vec<String>,
    /// Distinct domain suffixes named by the rules (for the privacy readout).
    pub domains: Vec<String>,
}

impl AppNetworkView {
    /// Build a view from an app's capability state and allow list.
    #[must_use]
    pub fn build(capability: NetCapability, list: &AppAllowList) -> Self {
        let has_capability = capability == NetCapability::Granted;
        let rules: Vec<String> = list.rules.iter().map(describe_rule).collect();
        let unrestricted = list.rules.iter().any(is_unrestricted_rule);

        let mut domains: Vec<String> = Vec::new();
        for rule in &list.rules {
            if let HostMatch::DomainSuffix(d) = &rule.host {
                if !domains.iter().any(|existing| existing == d) {
                    domains.push(d.clone());
                }
            }
        }

        Self {
            app_id: list.app_id.clone(),
            has_capability,
            can_egress: has_capability && !list.rules.is_empty(),
            unrestricted,
            rule_count: list.rules.len(),
            rules,
            domains,
        }
    }
}

/// An aggregate view of every app's network access, consumed by the Settings
/// panel (the per-app list) and the Helper Impact Dashboard (the counts).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct NetworkAccessOverview {
    /// Per-app views, in input order.
    pub apps: Vec<AppNetworkView>,
}

impl NetworkAccessOverview {
    /// Build an overview from `(capability, allow_list)` pairs — one per app.
    #[must_use]
    pub fn build(apps: &[(NetCapability, AppAllowList)]) -> Self {
        Self {
            apps: apps
                .iter()
                .map(|(cap, list)| AppNetworkView::build(*cap, list))
                .collect(),
        }
    }

    /// Total number of apps.
    #[must_use]
    pub fn app_count(&self) -> usize {
        self.apps.len()
    }

    /// Number of apps that can actually reach the network.
    #[must_use]
    pub fn apps_with_network(&self) -> usize {
        self.apps.iter().filter(|a| a.can_egress).count()
    }

    /// Number of apps with an unrestricted (`any any any`) rule.
    #[must_use]
    pub fn apps_unrestricted(&self) -> usize {
        self.apps.iter().filter(|a| a.unrestricted).count()
    }

    /// The distinct external domain suffixes named across all apps, sorted.
    #[must_use]
    pub fn distinct_domains(&self) -> Vec<String> {
        let mut all: Vec<String> = Vec::new();
        for app in &self.apps {
            for d in &app.domains {
                if !all.iter().any(|existing| existing == d) {
                    all.push(d.clone());
                }
            }
        }
        all.sort();
        all
    }

    /// A 0–100 network-egress impact score for the Helper Impact Dashboard.
    ///
    /// It rises with the share of apps that can egress and is pushed toward the
    /// maximum by any app holding unrestricted reach — the dashboard maps this
    /// onto its Egress / Privacy / Capabilities dimensions. `0` when no app can
    /// reach the network; `100` when at least one app is unrestricted.
    #[must_use]
    pub fn egress_impact_score(&self) -> u8 {
        if self.app_count() == 0 || self.apps_with_network() == 0 {
            return 0;
        }
        if self.apps_unrestricted() > 0 {
            return 100;
        }
        // Otherwise scale by the fraction of apps that can egress, capped at 90
        // so "constrained but networked" always reads below "unrestricted".
        // Integer division is intentional: this is a floored percentage.
        #[allow(clippy::integer_division)]
        let share = (self.apps_with_network() * 90) / self.app_count();
        u8::try_from(share).unwrap_or(90)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::indexing_slicing)]

    use super::*;

    fn list_with(app: &str, lines: &[&str]) -> AppAllowList {
        let mut l = AppAllowList::new(app);
        for line in lines {
            l.push(EgressRule::parse(line).unwrap());
        }
        l
    }

    #[test]
    fn describes_rules_readably() {
        assert_eq!(
            describe_rule(&EgressRule::parse("tcp 10.0.0.0/8 443").unwrap()),
            "tcp 10.0.0.0/8 443"
        );
        assert_eq!(
            describe_rule(&EgressRule::parse("* 1.2.3.4 *").unwrap()),
            "any 1.2.3.4 any"
        );
        assert_eq!(
            describe_rule(&EgressRule::parse("udp example.com 53").unwrap()),
            "udp *.example.com 53"
        );
        assert_eq!(
            describe_rule(&EgressRule::parse("tcp * 1000-2000").unwrap()),
            "tcp any 1000-2000"
        );
    }

    #[test]
    fn app_view_reports_capability_and_reach() {
        let list = list_with("mail", &["tcp mail.example.com 993", "tcp * 587"]);
        // Granted capability + rules → can egress, not unrestricted.
        let v = AppNetworkView::build(NetCapability::Granted, &list);
        assert!(v.has_capability);
        assert!(v.can_egress);
        assert!(!v.unrestricted);
        assert_eq!(v.rule_count, 2);
        assert_eq!(v.domains, alloc::vec!["mail.example.com".to_string()]);

        // Same rules, no capability → cannot egress.
        let v = AppNetworkView::build(NetCapability::None, &list);
        assert!(!v.has_capability);
        assert!(!v.can_egress);
    }

    #[test]
    fn empty_list_with_capability_cannot_egress() {
        let v = AppNetworkView::build(NetCapability::Granted, &AppAllowList::new("sandboxed"));
        assert!(v.has_capability);
        assert!(!v.can_egress);
        assert_eq!(v.rule_count, 0);
    }

    #[test]
    fn unrestricted_rule_is_flagged() {
        let v = AppNetworkView::build(NetCapability::Granted, &list_with("shell", &["* * *"]));
        assert!(v.unrestricted);
    }

    #[test]
    fn overview_aggregates_for_dashboard() {
        let apps = alloc::vec![
            (
                NetCapability::Granted,
                list_with("mail", &["tcp mail.example.com 993"])
            ),
            (NetCapability::Granted, list_with("browser", &["* * *"])),
            (NetCapability::None, list_with("offline", &["tcp * 80"])),
            (NetCapability::Granted, AppAllowList::new("sandboxed")),
        ];
        let ov = NetworkAccessOverview::build(&apps);
        assert_eq!(ov.app_count(), 4);
        // mail + browser can egress; offline (no cap) and sandboxed (empty) cannot.
        assert_eq!(ov.apps_with_network(), 2);
        assert_eq!(ov.apps_unrestricted(), 1);
        assert_eq!(
            ov.distinct_domains(),
            alloc::vec!["mail.example.com".to_string()]
        );
        // An unrestricted app pins the impact score to the maximum.
        assert_eq!(ov.egress_impact_score(), 100);
    }

    #[test]
    fn impact_score_scales_without_unrestricted() {
        let apps = alloc::vec![
            (NetCapability::Granted, list_with("a", &["tcp * 443"])),
            (NetCapability::None, AppAllowList::new("b")),
        ];
        let ov = NetworkAccessOverview::build(&apps);
        assert_eq!(ov.apps_with_network(), 1);
        assert_eq!(ov.apps_unrestricted(), 0);
        // 1 of 2 apps networked, none unrestricted → (1*90)/2 = 45.
        assert_eq!(ov.egress_impact_score(), 45);
    }

    #[test]
    fn no_network_scores_zero() {
        let apps = alloc::vec![(NetCapability::None, AppAllowList::new("a"))];
        assert_eq!(NetworkAccessOverview::build(&apps).egress_impact_score(), 0);
        assert_eq!(NetworkAccessOverview::default().egress_impact_score(), 0);
    }
}
