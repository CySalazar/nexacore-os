//! Path MTU discovery (WS4-01.6, RFC 1191 / RFC 8201).
//!
//! A sender learns the smallest `MTU` along the path to each destination from
//! `ICMP` feedback — `IPv4` "Fragmentation Needed" (with the DF bit set) or
//! `ICMPv6` "Packet Too Big" — and sizes its packets accordingly so routers
//! never have to fragment.
//!
//! [`PmtuCache`] is the per-destination `PMTU` table: [`report_too_big`] lowers
//! an entry on `ICMP` feedback (never below the protocol minimum), [`get`] /
//! [`effective_mtu`] read it on the send path, and [`age`] expires stale entries
//! so the `PMTU` can be re-probed upward after the path changes (RFC 1191 §6.3).
//!
//! [`report_too_big`]: PmtuCache::report_too_big
//! [`get`]: PmtuCache::get
//! [`effective_mtu`]: PmtuCache::effective_mtu
//! [`age`]: PmtuCache::age

use alloc::collections::BTreeMap;

use nexacore_types::net::IpAddr;

/// The `IPv4` minimum `MTU` a host must support (RFC 791).
pub const MIN_MTU_IPV4: u16 = 68;
/// The `IPv6` minimum `MTU` a link must support (RFC 8200).
pub const MIN_MTU_IPV6: u16 = 1280;
/// The default assumed `MTU` before anything is learned (Ethernet).
pub const DEFAULT_MTU: u16 = 1500;

/// RFC 1191 §7 plateau table, used to step down when an old-style `ICMP`
/// message reports no next-hop `MTU`. Descending.
const PLATEAUS: [u16; 11] = [
    65535, 32000, 17914, 8166, 4352, 2002, 1492, 1006, 508, 296, 68,
];

/// The largest plateau strictly below `mtu` (for next-hop-`MTU`-less reports).
fn plateau_below(mtu: u16) -> u16 {
    PLATEAUS
        .iter()
        .copied()
        .find(|&p| p < mtu)
        .unwrap_or(MIN_MTU_IPV4)
}

/// The protocol-minimum `MTU` floor for a destination's address family.
const fn floor_for(dest: IpAddr) -> u16 {
    match dest {
        IpAddr::V4(_) => MIN_MTU_IPV4,
        IpAddr::V6(_) => MIN_MTU_IPV6,
    }
}

/// A `BTreeMap`-friendly key for an [`IpAddr`] (which is not `Ord`): a family
/// tag byte followed by the address octets (`IPv4` left-aligned, rest zero).
fn cache_key(dest: IpAddr) -> [u8; 17] {
    let mut key = [0u8; 17];
    let (tag, bytes): (u8, &[u8]) = match &dest {
        IpAddr::V4(a) => (4, &a.0),
        IpAddr::V6(a) => (6, &a.0),
    };
    if let Some(first) = key.first_mut() {
        *first = tag;
    }
    if let Some(slot) = key.get_mut(1..=bytes.len()) {
        slot.copy_from_slice(bytes);
    }
    key
}

/// A learned path-`MTU` entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PmtuEntry {
    /// The discovered path `MTU` in bytes.
    pub mtu: u16,
    /// Caller-supplied timestamp of the last update (for [`PmtuCache::age`]).
    pub updated_at: u64,
}

/// Per-destination Path MTU cache (WS4-01.6).
#[derive(Debug, Default, Clone)]
pub struct PmtuCache {
    entries: BTreeMap<[u8; 17], PmtuEntry>,
}

impl PmtuCache {
    /// An empty cache.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// The learned path `MTU` for `dest`, if any.
    #[must_use]
    pub fn get(&self, dest: IpAddr) -> Option<u16> {
        self.entries.get(&cache_key(dest)).map(|e| e.mtu)
    }

    /// The `MTU` to use when sending to `dest` over a link whose `MTU` is
    /// `link_mtu`: the smaller of the learned path `MTU` and the link `MTU`.
    #[must_use]
    pub fn effective_mtu(&self, dest: IpAddr, link_mtu: u16) -> u16 {
        self.get(dest).map_or(link_mtu, |m| m.min(link_mtu))
    }

    /// Record an `ICMP` "packet too big" / "fragmentation needed" for `dest`
    /// and return the new path `MTU`.
    ///
    /// `next_hop_mtu` is the `MTU` the offending router advertised (0 for an
    /// old-style `ICMP` message without one, in which case the next lower
    /// plateau is used). The `PMTU` only ever decreases here and never drops
    /// below the address family's minimum.
    pub fn report_too_big(&mut self, dest: IpAddr, next_hop_mtu: u16, now: u64) -> u16 {
        let floor = floor_for(dest);
        let current = self
            .entries
            .get(&cache_key(dest))
            .map_or(DEFAULT_MTU, |e| e.mtu);
        let candidate = if next_hop_mtu == 0 {
            plateau_below(current)
        } else {
            next_hop_mtu
        };
        // Clamp into `[floor, current]`: never below the minimum, never an
        // increase (a router advertising a larger MTU cannot raise our PMTU).
        let new_mtu = candidate.clamp(floor, current);
        self.entries.insert(
            cache_key(dest),
            PmtuEntry {
                mtu: new_mtu,
                updated_at: now,
            },
        );
        new_mtu
    }

    /// Drop entries older than `max_age` (relative to `now`) so the `PMTU` can
    /// be re-probed upward after a path change. Returns the number removed.
    pub fn age(&mut self, now: u64, max_age: u64) -> usize {
        let before = self.entries.len();
        self.entries
            .retain(|_, e| now.saturating_sub(e.updated_at) < max_age);
        before - self.entries.len()
    }

    /// Forget the learned `PMTU` for `dest`. Returns whether an entry existed.
    pub fn clear(&mut self, dest: IpAddr) -> bool {
        self.entries.remove(&cache_key(dest)).is_some()
    }

    /// The number of cached destinations.
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
    #![allow(clippy::unwrap_used)]
    use nexacore_types::net::{Ipv4Addr, Ipv6Addr};

    use super::*;

    fn v4() -> IpAddr {
        IpAddr::V4(Ipv4Addr([10, 0, 0, 1]))
    }
    fn v6() -> IpAddr {
        IpAddr::V6(Ipv6Addr([
            0x20, 0x01, 0xd, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
        ]))
    }

    #[test]
    fn unknown_destination_uses_link_mtu() {
        let cache = PmtuCache::new();
        assert_eq!(cache.get(v4()), None);
        assert_eq!(cache.effective_mtu(v4(), 1500), 1500);
    }

    #[test]
    fn report_lowers_pmtu_to_next_hop_mtu() {
        let mut cache = PmtuCache::new();
        assert_eq!(cache.report_too_big(v4(), 1400, 0), 1400);
        assert_eq!(cache.get(v4()), Some(1400));
        assert_eq!(cache.effective_mtu(v4(), 1500), 1400);
        // The link MTU still caps it if smaller than the learned PMTU.
        assert_eq!(cache.effective_mtu(v4(), 1200), 1200);
    }

    #[test]
    fn pmtu_never_increases_via_report() {
        let mut cache = PmtuCache::new();
        cache.report_too_big(v4(), 1400, 0);
        // A later report advertising a larger MTU must not raise the PMTU.
        assert_eq!(cache.report_too_big(v4(), 1600, 1), 1400);
        assert_eq!(cache.get(v4()), Some(1400));
    }

    #[test]
    fn report_clamps_to_protocol_minimum() {
        let mut cache = PmtuCache::new();
        // IPv4 floor is 68.
        assert_eq!(cache.report_too_big(v4(), 10, 0), MIN_MTU_IPV4);
        // IPv6 floor is 1280 — a router cannot push it lower.
        assert_eq!(cache.report_too_big(v6(), 500, 0), MIN_MTU_IPV6);
    }

    #[test]
    fn zero_next_hop_uses_plateau_below_current() {
        let mut cache = PmtuCache::new();
        // Old-style ICMP (no next-hop MTU) from the 1500 default → 1492 plateau.
        assert_eq!(cache.report_too_big(v4(), 0, 0), 1492);
        // A second such report steps down again, below 1492 → 1006.
        assert_eq!(cache.report_too_big(v4(), 0, 1), 1006);
    }

    #[test]
    fn aging_expires_stale_entries() {
        let mut cache = PmtuCache::new();
        cache.report_too_big(v4(), 1400, 1_000);
        // Not yet old enough.
        assert_eq!(cache.age(1_500, 600), 0);
        assert_eq!(cache.get(v4()), Some(1400));
        // Past the max age → expired, so the PMTU can be re-probed upward.
        assert_eq!(cache.age(2_000, 600), 1);
        assert_eq!(cache.get(v4()), None);
    }

    #[test]
    fn v4_and_v6_entries_are_independent() {
        let mut cache = PmtuCache::new();
        cache.report_too_big(v4(), 1400, 0);
        cache.report_too_big(v6(), 1300, 0);
        assert_eq!(cache.get(v4()), Some(1400));
        assert_eq!(cache.get(v6()), Some(1300));
        assert_eq!(cache.len(), 2);
        assert!(cache.clear(v4()));
        assert!(!cache.clear(v4()));
        assert_eq!(cache.get(v6()), Some(1300));
    }
}
