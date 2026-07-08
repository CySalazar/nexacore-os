//! ARP table and resolution engine (N2.1).
//!
//! Implements RFC 826 Address Resolution Protocol for IPv4-over-Ethernet.
//! The table stores recently-seen mappings from `IPv4` address to MAC address
//! and drives the request/reply state machine needed to resolve next-hop
//! addresses before sending a frame.
//!
//! ## Entry lifecycle
//!
//! ```text
//! resolve(ip, packet) → Pending   ← ARP request must be sent
//!       │
//!       ▼ (network delivers ARP reply)
//! handle_arp_packet(reply) → UpdatedTable
//!       │
//!       ▼
//! drain_pending(ip) → Vec<PendingPacket>  ← caller sends queued packets
//! ```
//!
//! Entries age through `Reachable → Stale → evicted` via [`ArpTable::expire_stale`].
//!
//! ## Constants
//!
//! - [`ARP_TIMEOUT_SECS`] — time before an entry is marked stale (300 s)
//! - [`ARP_MAX_ENTRIES`] — default maximum table size (256)
//! - [`ARP_MAX_PENDING`] — maximum queued packets per incomplete entry (8)
//!
//! ## Note on map keys
//!
//! [`Ipv4Addr`] does not implement [`Ord`], so the internal table uses
//! `u32` keys (big-endian representation of the address) via the private
//! helper `ip_key`.

use alloc::{collections::BTreeMap, vec::Vec};

use nexacore_types::net::{ArpOperation, ArpPacket, Ipv4Addr, MacAddress};

// =============================================================================
// Constants
// =============================================================================

/// Seconds after which a Reachable ARP entry transitions to Stale.
pub const ARP_TIMEOUT_SECS: u64 = 300;

/// Default maximum number of entries in the ARP table.
pub const ARP_MAX_ENTRIES: usize = 256;

/// Maximum number of packets queued per Incomplete entry.
///
/// If a burst of packets arrives for an unresolved IP before the ARP reply
/// comes back, only this many are queued; the rest are dropped silently.
pub const ARP_MAX_PENDING: usize = 8;

/// Lifetime (seconds) of an unresolved (`Incomplete`) ARP entry before eviction.
///
/// [`ArpTable::expire_stale`] reclaims a stuck entry and its queued packets
/// after this window. ARP on a LAN normally resolves in well under a second; a
/// few seconds of silence means the next hop is unreachable (WS2-02.2). A
/// connection retrying through the entry re-creates it with a fresh timestamp,
/// and TCP's own SYN-retransmit timeout (WS2-02.3) bounds the overall attempt.
pub const ARP_PENDING_TIMEOUT_SECS: u64 = 3;

/// Interval (seconds) between re-transmissions of a still-unanswered ARP
/// request for an `Incomplete` entry (WS2-02.2).
///
/// The first request is sent on the ARP miss; while the entry stays
/// `Incomplete`, [`ArpTable::due_retransmits`] re-emits the who-has roughly
/// once per second so a single dropped request (or reply) does not stall the
/// next hop for the whole [`ARP_PENDING_TIMEOUT_SECS`] window.
pub const ARP_RETRANSMIT_INTERVAL_SECS: u64 = 1;

// =============================================================================
// Internal helpers
// =============================================================================

/// Convert an [`Ipv4Addr`] to a `u32` suitable for use as a [`BTreeMap`] key.
///
/// Uses big-endian (network byte order) representation so that the sort order
/// matches the numeric order of addresses.
#[inline]
fn ip_key(ip: Ipv4Addr) -> u32 {
    u32::from_be_bytes(ip.0)
}

// =============================================================================
// Types
// =============================================================================

/// A single ARP table entry.
#[derive(Debug, Clone)]
pub struct ArpEntry {
    /// The `IPv4` address this entry resolves.
    pub ip: Ipv4Addr,
    /// Resolved MAC address.
    pub mac: MacAddress,
    /// Current state of this entry.
    pub state: ArpState,
    /// Timestamp (in seconds) when this entry was last confirmed reachable.
    ///
    /// For an `Incomplete` entry this is its creation time, from which
    /// [`ArpTable::expire_stale`] ages it toward eviction.
    pub timestamp: u64,
    /// Timestamp (in seconds) when an ARP request was last (re)transmitted for
    /// this entry. Only meaningful while `Incomplete`; drives the periodic
    /// re-transmission in [`ArpTable::due_retransmits`] (WS2-02.2).
    pub last_request: u64,
}

/// Lifecycle state of an [`ArpEntry`].
#[derive(Debug, Clone)]
pub enum ArpState {
    /// ARP request sent, reply not yet received.
    ///
    /// Packets destined for this IP are queued here until the reply arrives.
    Incomplete {
        /// Packets waiting to be sent once the MAC is known.
        pending_packets: Vec<PendingPacket>,
    },
    /// MAC address known and confirmed within [`ARP_TIMEOUT_SECS`].
    Reachable,
    /// Entry has aged past [`ARP_TIMEOUT_SECS`]; will be re-probed on next use.
    Stale,
}

/// A packet whose transmission is deferred pending ARP resolution.
#[derive(Debug, Clone)]
pub struct PendingPacket {
    /// Raw Ethernet payload bytes (IP packet) to be sent once the MAC resolves.
    pub data: Vec<u8>,
    /// The next-hop `IPv4` address this packet should be delivered to.
    pub next_hop_ip: Ipv4Addr,
}

/// Result returned by [`ArpTable::resolve`].
#[derive(Debug, Clone)]
pub enum ArpResolveResult {
    /// The MAC for the requested IP is already known.
    Resolved(MacAddress),
    /// No entry exists yet; the caller should send an ARP request.
    ///
    /// The pending packet (if any) has been enqueued and will be available
    /// via [`ArpTable::drain_pending`] after the reply arrives.
    Pending,
}

/// Result returned by [`ArpTable::handle_arp_packet`].
#[derive(Debug, Clone)]
pub enum ArpHandleResult {
    /// The incoming packet was an ARP Request targeting our IP; the caller
    /// should transmit this reply packet.
    SendReply(ArpPacket),
    /// The table was updated from an ARP Reply (or a gratuitous ARP).
    UpdatedTable,
    /// The packet was not addressed to us or was malformed; no action needed.
    Ignored,
}

// =============================================================================
// ArpTable
// =============================================================================

/// IPv4-to-MAC resolution table.
///
/// Internally the table uses `u32` keys (big-endian `IPv4` address) because
/// [`Ipv4Addr`] does not implement [`Ord`].
///
/// # Examples
///
/// ```
/// use nexacore_net::arp::{ArpResolveResult, ArpTable};
/// use nexacore_types::net::{Ipv4Addr, MacAddress};
///
/// let mut table = ArpTable::new(256);
/// let ip = Ipv4Addr([192, 168, 1, 1]);
/// let mac = MacAddress([0x02, 0, 0, 0, 0, 1]);
///
/// table.insert(ip, mac, 0);
/// match table.resolve(ip, None) {
///     ArpResolveResult::Resolved(m) => assert_eq!(m, mac),
///     ArpResolveResult::Pending => panic!("should be resolved"),
/// }
/// ```
#[derive(Debug, Default)]
pub struct ArpTable {
    /// Map from u32 IP key to the corresponding ARP entry.
    entries: BTreeMap<u32, ArpEntry>,
    /// Upper bound on the number of entries this table will store.
    max_entries: usize,
    /// Most recent time (seconds) seen by [`Self::expire_stale`]. Used to
    /// stamp the creation time of `Incomplete` entries in [`Self::resolve`]
    /// without threading a clock through every caller (mirrors the
    /// `last_now` pattern used by the TCP socket table). 0 until the first
    /// `expire_stale` tick.
    last_now: u64,
}

impl ArpTable {
    /// Construct a new, empty ARP table with `max_entries` capacity.
    #[must_use]
    pub fn new(max_entries: usize) -> Self {
        Self {
            entries: BTreeMap::new(),
            max_entries,
            last_now: 0,
        }
    }

    /// Look up `ip` in the table.
    ///
    /// Returns `None` if no entry exists (including Incomplete entries whose
    /// MAC is not yet known).  Returns `Some` for Reachable and Stale entries
    /// so callers can inspect the [`ArpState`].
    #[must_use]
    pub fn lookup(&self, ip: Ipv4Addr) -> Option<&ArpEntry> {
        self.entries.get(&ip_key(ip))
    }

    /// Resolve `ip` to a MAC address, optionally enqueueing a pending packet.
    ///
    /// Returns [`ArpResolveResult::Resolved`] if a Reachable or Stale entry
    /// exists, or [`ArpResolveResult::Pending`] if an ARP request must be sent.
    ///
    /// When `Pending` is returned, `pending_packet` (if `Some`) is enqueued in
    /// the Incomplete entry.  The caller is responsible for building and sending
    /// the ARP request via [`ArpTable::build_request`].
    pub fn resolve(
        &mut self,
        ip: Ipv4Addr,
        pending_packet: Option<PendingPacket>,
    ) -> ArpResolveResult {
        let key = ip_key(ip);

        // If we already have a resolved entry, return it immediately.
        if let Some(entry) = self.entries.get(&key) {
            match &entry.state {
                ArpState::Reachable | ArpState::Stale => {
                    return ArpResolveResult::Resolved(entry.mac);
                }
                ArpState::Incomplete { .. } => {
                    // Fall through to enqueue the pending packet.
                }
            }
        }

        // Create or update the Incomplete entry. Stamp its creation time with
        // the last tick's clock so `expire_stale` can age it from creation
        // (WS2-02.2) rather than from the epoch. Read `last_now` before the
        // mutable `entries` borrow to avoid borrowing `self` twice.
        let now = self.last_now;
        let entry = self.entries.entry(key).or_insert_with(|| ArpEntry {
            ip,
            mac: MacAddress([0; 6]),
            state: ArpState::Incomplete {
                pending_packets: Vec::new(),
            },
            timestamp: now,
            // The caller emits the initial request right after this returns
            // `Pending`, so stamp it as already sent at creation time.
            last_request: now,
        });

        if let ArpState::Incomplete { pending_packets } = &mut entry.state {
            if let Some(pkt) = pending_packet {
                // Drop oldest packet if queue is full to avoid unbounded memory growth.
                if pending_packets.len() >= ARP_MAX_PENDING {
                    pending_packets.remove(0);
                }
                pending_packets.push(pkt);
            }
        }

        ArpResolveResult::Pending
    }

    /// Process an incoming ARP packet.
    ///
    /// For ARP Requests targeting `our_ip`, returns `SendReply` with the
    /// pre-built reply packet.  For ARP Replies, updates the table and returns
    /// `UpdatedTable`.  Any other packet returns `Ignored`.
    pub fn handle_arp_packet(
        &mut self,
        packet: &ArpPacket,
        our_mac: MacAddress,
        our_ip: Ipv4Addr,
    ) -> ArpHandleResult {
        // We only understand Ethernet/IPv4 ARP.
        if packet.htype != 1 || packet.ptype != 0x0800 {
            return ArpHandleResult::Ignored;
        }

        match packet.operation {
            ArpOperation::REQUEST => {
                if packet.target_ip != our_ip {
                    // Not for us; still update the table with the sender's info.
                    self.insert(packet.sender_ip, packet.sender_mac, 0);
                    return ArpHandleResult::Ignored;
                }
                // Update table with the requester's mapping opportunistically.
                self.insert(packet.sender_ip, packet.sender_mac, 0);
                // Build and return the reply.
                let reply = ArpPacket {
                    htype: 1,
                    ptype: 0x0800,
                    hlen: 6,
                    plen: 4,
                    operation: ArpOperation::REPLY,
                    sender_mac: our_mac,
                    sender_ip: our_ip,
                    target_mac: packet.sender_mac,
                    target_ip: packet.sender_ip,
                };
                ArpHandleResult::SendReply(reply)
            }
            ArpOperation::REPLY => {
                // Learn the sender's mapping.
                self.insert(packet.sender_ip, packet.sender_mac, 0);
                ArpHandleResult::UpdatedTable
            }
            _ => ArpHandleResult::Ignored,
        }
    }

    /// Insert or update an entry with a confirmed MAC address.
    ///
    /// If the entry previously had Incomplete state, the pending packets are
    /// preserved and can be drained by [`ArpTable::drain_pending`].
    pub fn insert(&mut self, ip: Ipv4Addr, mac: MacAddress, timestamp: u64) {
        let key = ip_key(ip);

        // Evict the oldest entry if at capacity and this is a new IP.
        if !self.entries.contains_key(&key) && self.entries.len() >= self.max_entries {
            self.evict_oldest();
        }

        let entry = self.entries.entry(key).or_insert_with(|| ArpEntry {
            ip,
            mac,
            state: ArpState::Reachable,
            timestamp,
            last_request: timestamp,
        });

        // Preserve pending_packets list if transitioning from Incomplete.
        let pending = if let ArpState::Incomplete { pending_packets } = &mut entry.state {
            core::mem::take(pending_packets)
        } else {
            Vec::new()
        };

        entry.ip = ip;
        entry.mac = mac;
        entry.timestamp = timestamp;
        entry.state = if pending.is_empty() {
            ArpState::Reachable
        } else {
            // Keep as Incomplete-with-known-MAC until drain_pending is called.
            ArpState::Incomplete {
                pending_packets: pending,
            }
        };
    }

    /// Drain all pending packets queued for `ip`.
    ///
    /// Called immediately after [`ArpTable::handle_arp_packet`] returns
    /// `UpdatedTable` for a given IP, so the service loop can retransmit them.
    /// After draining, the entry transitions to Reachable.
    pub fn drain_pending(&mut self, ip: Ipv4Addr) -> Vec<PendingPacket> {
        let key = ip_key(ip);
        let Some(entry) = self.entries.get_mut(&key) else {
            return Vec::new();
        };
        let packets = if let ArpState::Incomplete { pending_packets } = &mut entry.state {
            core::mem::take(pending_packets)
        } else {
            Vec::new()
        };
        // Transition to Reachable now that the MAC is known.
        entry.state = ArpState::Reachable;
        packets
    }

    /// Age entries: mark Reachable entries older than `timeout` seconds as
    /// Stale, and remove Stale entries older than `2 * timeout` seconds.
    pub fn expire_stale(&mut self, now: u64, timeout: u64) {
        // Record the clock so `resolve` can stamp new Incomplete entries with a
        // real creation time (WS2-02.2).
        self.last_now = now;
        self.entries.retain(|_, entry| {
            let age = now.saturating_sub(entry.timestamp);
            let twice_timeout = timeout.saturating_mul(2);
            match &entry.state {
                ArpState::Reachable => {
                    if age > twice_timeout {
                        // Very old: remove entirely without transitioning.
                        return false;
                    }
                    if age > timeout {
                        entry.state = ArpState::Stale;
                    }
                    true
                }
                ArpState::Stale => {
                    // Remove stale entries that have aged past 2 × timeout.
                    age <= twice_timeout
                }
                ArpState::Incomplete { .. } => {
                    // Remove stuck unresolved entries (and their queued packets)
                    // after the short pending timeout, measured from the entry's
                    // creation time (stamped in `resolve` from `last_now`).
                    age <= ARP_PENDING_TIMEOUT_SECS
                }
            }
        });
    }

    /// Return the next-hop IPs whose ARP request should be re-transmitted now
    /// (WS2-02.2), updating each entry's last-sent timestamp.
    ///
    /// An `Incomplete` entry is due when at least
    /// [`ARP_RETRANSMIT_INTERVAL_SECS`] have elapsed since its request was last
    /// sent. The caller builds a fresh request for each returned IP via
    /// [`ArpTable::build_request`] and transmits it. Entries that resolve (or
    /// are evicted by [`Self::expire_stale`]) before the interval elapses are
    /// never re-sent.
    pub fn due_retransmits(&mut self, now: u64) -> Vec<Ipv4Addr> {
        let mut due = Vec::new();
        for entry in self.entries.values_mut() {
            if matches!(entry.state, ArpState::Incomplete { .. })
                && now.saturating_sub(entry.last_request) >= ARP_RETRANSMIT_INTERVAL_SECS
            {
                entry.last_request = now;
                due.push(entry.ip);
            }
        }
        due
    }

    /// Build an ARP Request packet.
    ///
    /// The caller should wrap this in an Ethernet frame with destination
    /// `ff:ff:ff:ff:ff:ff` and `EtherType::ARP`, then transmit it.
    #[must_use]
    pub fn build_request(our_mac: MacAddress, our_ip: Ipv4Addr, target_ip: Ipv4Addr) -> ArpPacket {
        ArpPacket {
            htype: 1,
            ptype: 0x0800,
            hlen: 6,
            plen: 4,
            operation: ArpOperation::REQUEST,
            sender_mac: our_mac,
            sender_ip: our_ip,
            target_mac: MacAddress([0; 6]),
            target_ip,
        }
    }

    // -------------------------------------------------------------------------
    // Private helpers
    // -------------------------------------------------------------------------

    /// Evict the entry with the smallest (oldest) timestamp to make room.
    fn evict_oldest(&mut self) {
        // Find the key with the minimum timestamp via linear scan.
        // For ARP_MAX_ENTRIES = 256 this is O(256) — acceptable.
        let oldest_key = self
            .entries
            .iter()
            .min_by_key(|(_, e)| e.timestamp)
            .map(|(&k, _)| k);
        if let Some(k) = oldest_key {
            self.entries.remove(&k);
        }
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::indexing_slicing,
        clippy::cast_possible_truncation,
        clippy::integer_division,
        clippy::map_unwrap_or,
        clippy::similar_names,
        clippy::too_many_lines,
        clippy::cognitive_complexity,
        clippy::cast_possible_wrap,
        clippy::cast_sign_loss,
        clippy::used_underscore_binding
    )]
    #[allow(clippy::wildcard_imports)]
    use super::*;

    fn mac(b: u8) -> MacAddress {
        MacAddress([0x02, 0, 0, 0, 0, b])
    }

    fn ip(a: u8) -> Ipv4Addr {
        Ipv4Addr([192, 168, 1, a])
    }

    #[test]
    fn new_table_is_empty() {
        let table = ArpTable::new(8);
        assert!(table.lookup(ip(1)).is_none());
    }

    #[test]
    fn insert_and_lookup_reachable() {
        let mut table = ArpTable::new(8);
        table.insert(ip(1), mac(1), 100);
        let entry = table.lookup(ip(1)).unwrap();
        assert_eq!(entry.mac, mac(1));
        assert!(matches!(entry.state, ArpState::Reachable));
    }

    #[test]
    fn resolve_known_ip_returns_resolved() {
        let mut table = ArpTable::new(8);
        table.insert(ip(1), mac(1), 0);
        match table.resolve(ip(1), None) {
            ArpResolveResult::Resolved(m) => assert_eq!(m, mac(1)),
            ArpResolveResult::Pending => panic!("expected Resolved"),
        }
    }

    #[test]
    fn resolve_unknown_ip_returns_pending() {
        let mut table = ArpTable::new(8);
        match table.resolve(ip(99), None) {
            ArpResolveResult::Pending => {}
            ArpResolveResult::Resolved(_) => panic!("expected Pending"),
        }
    }

    #[test]
    fn resolve_queues_pending_packet() {
        let mut table = ArpTable::new(8);
        let pkt = PendingPacket {
            data: alloc::vec![1, 2, 3],
            next_hop_ip: ip(1),
        };
        assert!(matches!(
            table.resolve(ip(1), Some(pkt)),
            ArpResolveResult::Pending
        ));
        // Entry should now be Incomplete.
        if let Some(entry) = table.lookup(ip(1)) {
            assert!(matches!(entry.state, ArpState::Incomplete { .. }));
        }
    }

    #[test]
    fn drain_pending_returns_queued_packets() {
        let mut table = ArpTable::new(8);
        let pkt = PendingPacket {
            data: alloc::vec![0xDE, 0xAD],
            next_hop_ip: ip(2),
        };
        let _ = table.resolve(ip(2), Some(pkt));
        // Simulate ARP reply arriving.
        table.insert(ip(2), mac(2), 10);
        let drained = table.drain_pending(ip(2));
        assert_eq!(drained.len(), 1);
        assert_eq!(drained[0].data, alloc::vec![0xDE, 0xAD]);
        // Entry should now be Reachable.
        assert!(matches!(
            table.lookup(ip(2)).unwrap().state,
            ArpState::Reachable
        ));
    }

    #[test]
    fn drain_pending_empty_for_unknown_ip() {
        let mut table = ArpTable::new(8);
        let drained = table.drain_pending(ip(5));
        assert!(drained.is_empty());
    }

    #[test]
    fn handle_arp_request_for_our_ip_returns_reply() {
        let mut table = ArpTable::new(8);
        let our_mac = mac(0xFE);
        let our_ip = ip(1);
        let packet = ArpPacket {
            htype: 1,
            ptype: 0x0800,
            hlen: 6,
            plen: 4,
            operation: ArpOperation::REQUEST,
            sender_mac: mac(2),
            sender_ip: ip(2),
            target_mac: MacAddress([0; 6]),
            target_ip: our_ip,
        };
        let result = table.handle_arp_packet(&packet, our_mac, our_ip);
        assert!(matches!(result, ArpHandleResult::SendReply(_)));
        if let ArpHandleResult::SendReply(reply) = result {
            assert_eq!(reply.sender_mac, our_mac);
            assert_eq!(reply.target_mac, mac(2));
            assert_eq!(reply.operation, ArpOperation::REPLY);
        }
    }

    #[test]
    fn handle_arp_request_for_other_ip_is_ignored() {
        let mut table = ArpTable::new(8);
        let packet = ArpPacket {
            htype: 1,
            ptype: 0x0800,
            hlen: 6,
            plen: 4,
            operation: ArpOperation::REQUEST,
            sender_mac: mac(2),
            sender_ip: ip(2),
            target_mac: MacAddress([0; 6]),
            target_ip: ip(99),
        };
        let result = table.handle_arp_packet(&packet, mac(1), ip(1));
        assert!(matches!(result, ArpHandleResult::Ignored));
    }

    #[test]
    fn handle_arp_reply_updates_table() {
        let mut table = ArpTable::new(8);
        let packet = ArpPacket {
            htype: 1,
            ptype: 0x0800,
            hlen: 6,
            plen: 4,
            operation: ArpOperation::REPLY,
            sender_mac: mac(3),
            sender_ip: ip(3),
            target_mac: mac(1),
            target_ip: ip(1),
        };
        let result = table.handle_arp_packet(&packet, mac(1), ip(1));
        assert!(matches!(result, ArpHandleResult::UpdatedTable));
        assert!(table.lookup(ip(3)).is_some());
    }

    #[test]
    fn build_request_has_correct_fields() {
        let req = ArpTable::build_request(mac(1), ip(1), ip(2));
        assert_eq!(req.operation, ArpOperation::REQUEST);
        assert_eq!(req.sender_mac, mac(1));
        assert_eq!(req.sender_ip, ip(1));
        assert_eq!(req.target_ip, ip(2));
        assert_eq!(req.target_mac, MacAddress([0; 6]));
        assert_eq!(req.htype, 1);
        assert_eq!(req.ptype, 0x0800);
    }

    #[test]
    fn expire_stale_marks_old_entries_stale() {
        let mut table = ArpTable::new(8);
        table.insert(ip(1), mac(1), 0);
        // Advance time past the timeout.
        table.expire_stale(400, ARP_TIMEOUT_SECS);
        assert!(matches!(
            table.lookup(ip(1)).unwrap().state,
            ArpState::Stale
        ));
    }

    #[test]
    fn expire_stale_removes_very_old_entries() {
        let mut table = ArpTable::new(8);
        table.insert(ip(1), mac(1), 0);
        // Age beyond 2 * timeout.
        table.expire_stale(700, ARP_TIMEOUT_SECS);
        assert!(table.lookup(ip(1)).is_none());
    }

    #[test]
    fn table_evicts_oldest_when_at_capacity() {
        let mut table = ArpTable::new(3);
        table.insert(ip(1), mac(1), 10);
        table.insert(ip(2), mac(2), 20);
        table.insert(ip(3), mac(3), 30);
        // Table is full; inserting a 4th should evict ip(1) (timestamp 10).
        table.insert(ip(4), mac(4), 40);
        assert!(table.lookup(ip(1)).is_none());
        assert!(table.lookup(ip(4)).is_some());
    }

    #[test]
    fn pending_queue_drops_oldest_when_full() {
        let mut table = ArpTable::new(8);
        // Fill the queue to ARP_MAX_PENDING.
        for i in 0..ARP_MAX_PENDING {
            #[allow(clippy::cast_possible_truncation)]
            let pkt = PendingPacket {
                data: alloc::vec![i as u8],
                next_hop_ip: ip(10),
            };
            let _ = table.resolve(ip(10), Some(pkt));
        }
        // One more packet; the oldest (data=[0]) should be dropped.
        let extra = PendingPacket {
            data: alloc::vec![0xFF],
            next_hop_ip: ip(10),
        };
        let _ = table.resolve(ip(10), Some(extra));
        // After resolve+insert, drain_pending returns ARP_MAX_PENDING packets.
        table.insert(ip(10), mac(10), 0);
        let drained = table.drain_pending(ip(10));
        assert_eq!(drained.len(), ARP_MAX_PENDING);
        // The last element should be the extra packet we pushed.
        assert_eq!(drained.last().unwrap().data, alloc::vec![0xFF]);
    }

    #[test]
    fn handle_arp_wrong_htype_is_ignored() {
        let mut table = ArpTable::new(8);
        let pkt = ArpPacket {
            htype: 6, // ARCNET — not Ethernet
            ptype: 0x0800,
            hlen: 6,
            plen: 4,
            operation: ArpOperation::REQUEST,
            sender_mac: mac(2),
            sender_ip: ip(2),
            target_mac: MacAddress([0; 6]),
            target_ip: ip(1),
        };
        assert!(matches!(
            table.handle_arp_packet(&pkt, mac(1), ip(1)),
            ArpHandleResult::Ignored
        ));
    }

    #[test]
    fn stale_entry_still_resolves() {
        let mut table = ArpTable::new(8);
        table.insert(ip(1), mac(1), 0);
        table.expire_stale(400, ARP_TIMEOUT_SECS);
        // Stale entries are still usable (just trigger a background re-probe).
        match table.resolve(ip(1), None) {
            ArpResolveResult::Resolved(m) => assert_eq!(m, mac(1)),
            ArpResolveResult::Pending => panic!("stale entry should still resolve"),
        }
    }

    #[test]
    fn incomplete_entry_evicted_after_pending_timeout() {
        // WS2-02.2: an unresolved ARP entry (and its queued packets) must be
        // reclaimed after ARP_PENDING_TIMEOUT_SECS instead of lingering.
        let mut table = ArpTable::new(8);
        // Advance the clock to t=100s, then queue a packet for an unresolved
        // IP: the Incomplete entry is stamped with creation time 100.
        table.expire_stale(100, ARP_TIMEOUT_SECS);
        let pkt = PendingPacket {
            data: alloc::vec![1, 2, 3],
            next_hop_ip: ip(42),
        };
        assert!(matches!(
            table.resolve(ip(42), Some(pkt)),
            ArpResolveResult::Pending
        ));
        assert!(table.lookup(ip(42)).is_some(), "incomplete entry exists");

        // Within the pending window it survives.
        table.expire_stale(100 + ARP_PENDING_TIMEOUT_SECS, ARP_TIMEOUT_SECS);
        assert!(
            table.lookup(ip(42)).is_some(),
            "incomplete entry must survive within the pending timeout"
        );

        // Past the pending window it is evicted along with its queued packets.
        table.expire_stale(100 + ARP_PENDING_TIMEOUT_SECS + 1, ARP_TIMEOUT_SECS);
        assert!(
            table.lookup(ip(42)).is_none(),
            "stuck incomplete entry must be evicted after the pending timeout"
        );
        assert!(
            table.drain_pending(ip(42)).is_empty(),
            "evicted entry must have no pending packets"
        );
    }

    #[test]
    fn arp_request_retransmitted_at_interval_while_pending() {
        // WS2-02.2: while an entry stays Incomplete, the who-has is re-emitted
        // about once per ARP_RETRANSMIT_INTERVAL_SECS.
        let mut table = ArpTable::new(8);
        table.expire_stale(0, ARP_TIMEOUT_SECS); // last_now = 0
        assert!(matches!(
            table.resolve(ip(7), None),
            ArpResolveResult::Pending
        ));

        // Same second as creation: the initial request already went out, so no
        // re-transmission is due.
        assert!(table.due_retransmits(0).is_empty());

        // One interval later it is due exactly once.
        assert_eq!(
            table.due_retransmits(ARP_RETRANSMIT_INTERVAL_SECS),
            alloc::vec![ip(7)]
        );
        // Not due twice within the same second.
        assert!(
            table
                .due_retransmits(ARP_RETRANSMIT_INTERVAL_SECS)
                .is_empty()
        );
        // Due again after another interval.
        assert_eq!(
            table.due_retransmits(ARP_RETRANSMIT_INTERVAL_SECS * 2),
            alloc::vec![ip(7)]
        );
    }

    #[test]
    fn retransmit_stops_once_resolved() {
        let mut table = ArpTable::new(8);
        table.expire_stale(0, ARP_TIMEOUT_SECS);
        assert!(matches!(
            table.resolve(ip(8), None),
            ArpResolveResult::Pending
        ));
        // The ARP reply arrives: the entry becomes Reachable.
        table.insert(ip(8), mac(8), 0);
        // No further re-transmissions, ever.
        assert!(table.due_retransmits(100).is_empty());
    }

    #[test]
    fn retransmit_only_targets_incomplete_entries() {
        let mut table = ArpTable::new(8);
        table.insert(ip(1), mac(1), 0); // Reachable from the start
        assert!(
            table.due_retransmits(1000).is_empty(),
            "resolved entries are never re-probed by due_retransmits"
        );
    }
}
