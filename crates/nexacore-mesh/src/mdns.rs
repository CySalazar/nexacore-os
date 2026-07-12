//! NexaCore device service record for mDNS / DNS-SD LAN discovery (WS6-01.1).
//!
//! Every NexaCore device advertises a [`SERVICE_TYPE`] service on the local
//! network so the other devices of a personal cluster can find it without a
//! central directory. This module defines the [`ServiceRecord`] — the instance
//! name, port, and TXT metadata — plus the DNS-SD TXT wire encoding/decoding.
//!
//! WS6-01.1 is the record definition + TXT codec. WS6-01.2 is the DNS-SD
//! advertisement *packet* ([`encode_advertisement`]) and WS6-01.3 the discovery
//! *parser* ([`parse_advertisement`]) plus the [`PeerInventory`] that tracks
//! discovered peers with TTL expiry. All three are pure `&[u8]`/data logic,
//! host-testable here; only the multicast socket send/receive is the live step
//! layered on top on the VM-103 rig.

use std::{collections::BTreeMap, net::Ipv4Addr, string::String, vec::Vec};

/// The DNS-SD service type NexaCore devices advertise (`_nexacore._tcp`).
pub const SERVICE_TYPE: &str = "_nexacore._tcp.local";

/// Well-known TXT key: the device's mesh node id (hex).
pub const TXT_NODE_ID: &str = "id";
/// Well-known TXT key: the device model / product name.
pub const TXT_MODEL: &str = "model";
/// Well-known TXT key: the OS version.
pub const TXT_VERSION: &str = "ver";
/// Well-known TXT key: the DNS-SD/TXT record format version (per RFC 6763 the
/// first key SHOULD be `txtvers`).
pub const TXT_VERS: &str = "txtvers";

/// A NexaCore device's advertised service record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServiceRecord {
    /// The service instance name (typically the device hostname).
    pub instance: String,
    /// The TCP port the device's cluster service listens on.
    pub port: u16,
    /// TXT metadata as ordered `(key, value)` pairs (value empty = boolean key).
    pub txt: Vec<(String, String)>,
}

impl ServiceRecord {
    /// A new record for `instance` on `port` with empty TXT metadata.
    #[must_use]
    pub fn new(instance: &str, port: u16) -> Self {
        Self {
            instance: instance.to_string(),
            port,
            txt: Vec::new(),
        }
    }

    /// The DNS-SD service type.
    #[must_use]
    pub fn service_type() -> &'static str {
        SERVICE_TYPE
    }

    /// Add or replace a TXT key/value pair (builder-style).
    #[must_use]
    pub fn with_txt(mut self, key: &str, value: &str) -> Self {
        self.set_txt(key, value);
        self
    }

    /// Set (or replace) a TXT key's value.
    pub fn set_txt(&mut self, key: &str, value: &str) {
        if let Some(entry) = self.txt.iter_mut().find(|(k, _)| k == key) {
            entry.1 = value.to_string();
        } else {
            self.txt.push((key.to_string(), value.to_string()));
        }
    }

    /// The value of a TXT key, if present.
    #[must_use]
    pub fn txt_value(&self, key: &str) -> Option<&str> {
        self.txt
            .iter()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v.as_str())
    }

    /// The fully-qualified instance name `"<instance>._nexacore._tcp.local"`.
    #[must_use]
    pub fn fqdn(&self) -> String {
        let mut s = String::with_capacity(self.instance.len() + 1 + SERVICE_TYPE.len());
        s.push_str(&self.instance);
        s.push('.');
        s.push_str(SERVICE_TYPE);
        s
    }

    /// Encode the TXT metadata into the DNS-SD wire form: a sequence of
    /// length-prefixed `key=value` strings (RFC 6763 §6). An entry longer than
    /// 255 bytes is skipped (it cannot be length-prefixed).
    #[must_use]
    pub fn encode_txt(&self) -> Vec<u8> {
        let mut out = Vec::new();
        for (k, v) in &self.txt {
            let entry = if v.is_empty() {
                k.clone()
            } else {
                let mut e = String::with_capacity(k.len() + 1 + v.len());
                e.push_str(k);
                e.push('=');
                e.push_str(v);
                e
            };
            if let Ok(len) = u8::try_from(entry.len()) {
                out.push(len);
                out.extend_from_slice(entry.as_bytes());
            }
        }
        out
    }
}

/// Parse a DNS-SD TXT record blob into ordered `(key, value)` pairs.
///
/// Each entry is a 1-byte length followed by that many bytes of `key=value`
/// (or a bare `key`). A length that runs past the buffer ends the parse (a
/// malformed record cannot cause an over-read); a non-UTF-8 entry is skipped.
#[must_use]
pub fn parse_txt(bytes: &[u8]) -> Vec<(String, String)> {
    let mut out = Vec::new();
    let mut i = 0usize;
    while let Some(&len) = bytes.get(i) {
        let len = len as usize;
        i += 1;
        let Some(chunk) = bytes.get(i..i + len) else {
            break; // declared length overruns the buffer
        };
        i += len;
        if len == 0 {
            continue; // empty string is a valid but ignorable entry
        }
        if let Ok(s) = core::str::from_utf8(chunk) {
            match s.split_once('=') {
                Some((k, v)) => out.push((k.to_string(), v.to_string())),
                None => out.push((s.to_string(), String::new())),
            }
        }
    }
    out
}

// ---------------------------------------------------------------------------
// DNS-SD advertisement packet (WS6-01.2) + discovery parser (WS6-01.3)
// ---------------------------------------------------------------------------

// DNS record TYPE codes (RFC 1035 §3.2.2, RFC 2782 for SRV).
const TYPE_A: u16 = 1;
const TYPE_PTR: u16 = 12;
const TYPE_TXT: u16 = 16;
const TYPE_SRV: u16 = 33;
/// Class IN.
const CLASS_IN: u16 = 1;
/// Class IN with the mDNS cache-flush bit set (RFC 6762 §10.2) — used for the
/// records that uniquely belong to this device (SRV/TXT/A).
const CLASS_IN_FLUSH: u16 = 0x8001;
/// Response header flags: QR=1 (response) + AA=1 (authoritative).
const FLAGS_RESPONSE: u16 = 0x8400;
/// Cap on compression-pointer jumps while reading a name — a loop guard against
/// a malicious packet whose pointers cycle (RFC 1035 §4.1.4).
const MAX_NAME_JUMPS: usize = 128;

/// Encode a NexaCore device's DNS-SD advertisement as an mDNS response packet
/// (WS6-01.2).
///
/// The packet answers with the three records that announce the service:
/// a `PTR` (`_nexacore._tcp.local` → the instance), an `SRV` (priority/weight/
/// port/target `host`), and a `TXT` (the record's metadata). When `addr` is
/// given, an `A` record mapping `host` → `addr` is appended so peers learn the
/// address without a second query. Names are written uncompressed (valid DNS;
/// receivers still handle compression on the wire).
#[must_use]
pub fn encode_advertisement(
    record: &ServiceRecord,
    host: &str,
    addr: Option<Ipv4Addr>,
    ttl: u32,
) -> Vec<u8> {
    let mut out = Vec::new();
    let ancount: u16 = if addr.is_some() { 4 } else { 3 };
    // Header: id=0, flags, qd=0, an=ancount, ns=0, ar=0.
    out.extend_from_slice(&0u16.to_be_bytes());
    out.extend_from_slice(&FLAGS_RESPONSE.to_be_bytes());
    out.extend_from_slice(&0u16.to_be_bytes());
    out.extend_from_slice(&ancount.to_be_bytes());
    out.extend_from_slice(&0u16.to_be_bytes());
    out.extend_from_slice(&0u16.to_be_bytes());

    let fqdn = record.fqdn();
    // PTR: service type → instance fqdn.
    encode_record(&mut out, SERVICE_TYPE, TYPE_PTR, CLASS_IN, ttl, |rd| {
        encode_name(&fqdn, rd);
    });
    // SRV: instance fqdn → priority/weight/port/target.
    encode_record(&mut out, &fqdn, TYPE_SRV, CLASS_IN_FLUSH, ttl, |rd| {
        rd.extend_from_slice(&0u16.to_be_bytes()); // priority
        rd.extend_from_slice(&0u16.to_be_bytes()); // weight
        rd.extend_from_slice(&record.port.to_be_bytes());
        encode_name(host, rd);
    });
    // TXT: instance fqdn → metadata (a single empty string when there is none).
    encode_record(&mut out, &fqdn, TYPE_TXT, CLASS_IN_FLUSH, ttl, |rd| {
        let txt = record.encode_txt();
        if txt.is_empty() {
            rd.push(0);
        } else {
            rd.extend_from_slice(&txt);
        }
    });
    // A: host → IPv4 address (optional).
    if let Some(ip) = addr {
        encode_record(&mut out, host, TYPE_A, CLASS_IN_FLUSH, ttl, |rd| {
            rd.extend_from_slice(&ip.octets());
        });
    }
    out
}

/// Encode one resource record (owner name, type, class, TTL, and RDATA produced
/// by `rdata`) onto `out`.
fn encode_record(
    out: &mut Vec<u8>,
    name: &str,
    rtype: u16,
    class: u16,
    ttl: u32,
    rdata: impl FnOnce(&mut Vec<u8>),
) {
    encode_name(name, out);
    out.extend_from_slice(&rtype.to_be_bytes());
    out.extend_from_slice(&class.to_be_bytes());
    out.extend_from_slice(&ttl.to_be_bytes());
    let mut rd = Vec::new();
    rdata(&mut rd);
    let len = u16::try_from(rd.len()).unwrap_or(0);
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(&rd);
}

/// Encode a dotted DNS name as a sequence of length-prefixed labels terminated
/// by a zero byte. Empty labels are skipped; a label is clamped to 63 bytes.
fn encode_name(name: &str, out: &mut Vec<u8>) {
    for label in name.split('.') {
        if label.is_empty() {
            continue;
        }
        let bytes = label.as_bytes();
        let len = u8::try_from(bytes.len().min(63)).unwrap_or(63);
        if let Some(slice) = bytes.get(..usize::from(len)) {
            out.push(len);
            out.extend_from_slice(slice);
        }
    }
    out.push(0);
}

/// A peer NexaCore device discovered from an mDNS advertisement (WS6-01.3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiscoveredPeer {
    /// The service instance name (device hostname).
    pub instance: String,
    /// The SRV target host name.
    pub host: String,
    /// The advertised service port.
    pub port: u16,
    /// `IPv4` addresses learned from `A` records for `host`.
    pub addrs: Vec<Ipv4Addr>,
    /// The device's TXT metadata.
    pub txt: Vec<(String, String)>,
}

impl DiscoveredPeer {
    /// The device's mesh node id from its TXT metadata, if advertised.
    #[must_use]
    pub fn node_id(&self) -> Option<&str> {
        self.txt
            .iter()
            .find(|(k, _)| k == TXT_NODE_ID)
            .map(|(_, v)| v.as_str())
    }
}

/// Parse an mDNS advertisement packet into the peers it announces (WS6-01.3).
///
/// Correlates the `SRV` (port/host), `TXT` (metadata) and `A` (address) records
/// by owner name. A peer is produced for every `SRV` record — that is the record
/// carrying the port. A malformed packet yields an empty result rather than an
/// error or a panic: every read is bounds-checked and name compression is
/// followed with a jump cap.
#[must_use]
pub fn parse_advertisement(bytes: &[u8]) -> Vec<DiscoveredPeer> {
    let Some(records) = parse_records(bytes) else {
        return Vec::new();
    };
    let mut srv: BTreeMap<String, (u16, String)> = BTreeMap::new();
    let mut txt: BTreeMap<String, Vec<(String, String)>> = BTreeMap::new();
    let mut addrs: BTreeMap<String, Vec<Ipv4Addr>> = BTreeMap::new();
    for r in &records {
        match r.rtype {
            TYPE_SRV => {
                // RDATA: priority(2) weight(2) port(2) target(name).
                if let (Some(port), Some((target, _))) = (
                    read_u16(bytes, r.rdata_start + 4),
                    read_name(bytes, r.rdata_start + 6),
                ) {
                    srv.insert(r.name.clone(), (port, target));
                }
            }
            TYPE_TXT => {
                if let Some(chunk) = bytes.get(r.rdata_start..r.rdata_start + r.rdata_len) {
                    txt.insert(r.name.clone(), parse_txt(chunk));
                }
            }
            TYPE_A => {
                if let Some(&[a, b, c, d]) = bytes.get(r.rdata_start..r.rdata_start + 4) {
                    addrs
                        .entry(r.name.clone())
                        .or_default()
                        .push(Ipv4Addr::new(a, b, c, d));
                }
            }
            _ => {}
        }
    }
    srv.into_iter()
        .map(|(fqdn, (port, host))| DiscoveredPeer {
            instance: instance_of(&fqdn),
            addrs: addrs.get(&host).cloned().unwrap_or_default(),
            port,
            host,
            txt: txt.get(&fqdn).cloned().unwrap_or_default(),
        })
        .collect()
}

/// A parsed resource record header plus the byte range of its RDATA.
struct RawRecord {
    name: String,
    rtype: u16,
    rdata_start: usize,
    rdata_len: usize,
}

/// Parse the answer/authority/additional records of a DNS message, skipping the
/// question section. Returns `None` on any truncation.
fn parse_records(bytes: &[u8]) -> Option<Vec<RawRecord>> {
    let qd = read_u16(bytes, 4)?;
    let an = read_u16(bytes, 6)?;
    let ns = read_u16(bytes, 8)?;
    let ar = read_u16(bytes, 10)?;
    let mut pos = 12usize;
    // Skip the question section: name + qtype(2) + qclass(2).
    for _ in 0..qd {
        let (_, after) = read_name(bytes, pos)?;
        pos = after + 4;
    }
    let total = usize::from(an) + usize::from(ns) + usize::from(ar);
    let mut records = Vec::with_capacity(total);
    for _ in 0..total {
        let (name, after) = read_name(bytes, pos)?;
        let rtype = read_u16(bytes, after)?;
        let rdlen = usize::from(read_u16(bytes, after + 8)?); // skip class(2)+ttl(4)
        let rdata_start = after + 10;
        bytes.get(rdata_start..rdata_start + rdlen)?; // bounds check
        records.push(RawRecord {
            name,
            rtype,
            rdata_start,
            rdata_len: rdlen,
        });
        pos = rdata_start + rdlen;
    }
    Some(records)
}

/// Read a big-endian `u16` at byte offset `pos`, or `None` if out of bounds.
fn read_u16(bytes: &[u8], pos: usize) -> Option<u16> {
    let hi = *bytes.get(pos)?;
    let lo = *bytes.get(pos + 1)?;
    Some(u16::from_be_bytes([hi, lo]))
}

/// Read a DNS name starting at byte `start`, following compression pointers
/// (RFC 1035 §4.1.4). Returns the dotted name and the offset just after the name
/// in the record stream (i.e. after the first pointer, if any). Bounds-safe and
/// loop-guarded.
fn read_name(bytes: &[u8], start: usize) -> Option<(String, usize)> {
    let mut labels: Vec<String> = Vec::new();
    let mut pos = start;
    let mut jumps = 0usize;
    let mut after: Option<usize> = None;
    loop {
        let len = *bytes.get(pos)?;
        if len & 0xC0 == 0xC0 {
            let lo = *bytes.get(pos + 1)?;
            let target = (usize::from(len & 0x3F) << 8) | usize::from(lo);
            if after.is_none() {
                after = Some(pos + 2);
            }
            jumps += 1;
            if jumps > MAX_NAME_JUMPS {
                return None; // pointer loop
            }
            pos = target;
            continue;
        }
        if len == 0 {
            return Some((labels.join("."), after.unwrap_or(pos + 1)));
        }
        let len = usize::from(len);
        if len > 63 {
            return None;
        }
        let label = bytes.get(pos + 1..pos + 1 + len)?;
        labels.push(core::str::from_utf8(label).ok()?.to_string());
        pos = pos + 1 + len;
    }
}

/// The instance name of a service fqdn: `"<instance>._nexacore._tcp.local"` →
/// `"<instance>"` (or the first label if the suffix is absent).
fn instance_of(fqdn: &str) -> String {
    let mut suffix = String::with_capacity(SERVICE_TYPE.len() + 1);
    suffix.push('.');
    suffix.push_str(SERVICE_TYPE);
    fqdn.strip_suffix(&suffix).map_or_else(
        || fqdn.split('.').next().unwrap_or(fqdn).to_string(),
        ToString::to_string,
    )
}

/// A TTL-expiring inventory of peers discovered via mDNS (WS6-01.3).
///
/// Each observed peer is keyed by its instance name; re-observing refreshes its
/// expiry. Time is supplied by the caller (a monotonic tick in the same unit as
/// the TTL), so the inventory is deterministic and host-testable without an
/// ambient clock.
#[derive(Debug, Clone, Default)]
pub struct PeerInventory {
    entries: BTreeMap<String, PeerEntry>,
}

/// An inventory entry: the peer plus the tick at which it expires.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerEntry {
    /// The discovered peer.
    pub peer: DiscoveredPeer,
    /// The tick at or after which the entry is stale.
    pub expires_at: u64,
}

impl PeerInventory {
    /// An empty inventory.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Record (or refresh) a peer seen at tick `now`, valid for `ttl` ticks.
    pub fn observe(&mut self, peer: DiscoveredPeer, now: u64, ttl: u64) {
        let key = peer.instance.clone();
        self.entries.insert(
            key,
            PeerEntry {
                peer,
                expires_at: now.saturating_add(ttl),
            },
        );
    }

    /// Drop every entry whose expiry is at or before `now`.
    pub fn expire(&mut self, now: u64) {
        self.entries.retain(|_, e| e.expires_at > now);
    }

    /// The number of live entries (call [`expire`] first to prune stale ones).
    ///
    /// [`expire`]: PeerInventory::expire
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the inventory is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Whether a peer with `instance` is present.
    #[must_use]
    pub fn contains(&self, instance: &str) -> bool {
        self.entries.contains_key(instance)
    }

    /// The peer with `instance`, if present.
    #[must_use]
    pub fn get(&self, instance: &str) -> Option<&DiscoveredPeer> {
        self.entries.get(instance).map(|e| &e.peer)
    }

    /// All live peers, ordered by instance name.
    #[must_use]
    pub fn peers(&self) -> Vec<&DiscoveredPeer> {
        self.entries.values().map(|e| &e.peer).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn device() -> ServiceRecord {
        ServiceRecord::new("living-room-nexacore", 8443)
            .with_txt(TXT_VERS, "1")
            .with_txt(TXT_NODE_ID, "a1b2c3")
            .with_txt(TXT_MODEL, "NexaCore One")
    }

    #[test]
    fn record_exposes_type_fqdn_and_values() {
        let d = device();
        assert_eq!(ServiceRecord::service_type(), "_nexacore._tcp.local");
        assert_eq!(d.fqdn(), "living-room-nexacore._nexacore._tcp.local");
        assert_eq!(d.port, 8443);
        assert_eq!(d.txt_value(TXT_NODE_ID), Some("a1b2c3"));
        assert_eq!(d.txt_value("absent"), None);
    }

    #[test]
    fn set_txt_replaces_existing_key() {
        let mut d = device();
        d.set_txt(TXT_MODEL, "NexaCore Pro");
        assert_eq!(d.txt_value(TXT_MODEL), Some("NexaCore Pro"));
        // No duplicate key was appended.
        assert_eq!(d.txt.iter().filter(|(k, _)| k == TXT_MODEL).count(), 1);
    }

    #[test]
    fn txt_round_trips_through_the_wire_form() {
        let d = device();
        let encoded = d.encode_txt();
        // First entry: length byte then "txtvers=1".
        assert_eq!(encoded.first().copied(), Some(9));
        let parsed = parse_txt(&encoded);
        assert_eq!(parsed, d.txt);
    }

    #[test]
    fn boolean_key_encodes_without_equals() {
        let d = ServiceRecord::new("x", 1).with_txt("secure", "");
        let encoded = d.encode_txt();
        assert_eq!(&encoded, b"\x06secure");
        assert_eq!(
            parse_txt(&encoded),
            vec![("secure".to_string(), String::new())]
        );
    }

    #[test]
    fn parse_txt_stops_on_overrun_without_panicking() {
        // A length byte of 200 with only a few bytes following.
        let parsed = parse_txt(&[200, b'a', b'b', b'c']);
        assert!(parsed.is_empty());
    }

    // --- WS6-01.2/.3: advertisement packet + discovery ---------------------

    #[test]
    fn advertisement_header_declares_response_and_counts() {
        let rec = ServiceRecord::new("x", 1);
        let pkt = encode_advertisement(&rec, "x.local", None, 120);
        assert_eq!(read_u16(&pkt, 2), Some(FLAGS_RESPONSE));
        assert_eq!(read_u16(&pkt, 4), Some(0)); // qdcount
        assert_eq!(read_u16(&pkt, 6), Some(3)); // ancount: PTR + SRV + TXT
        // With an address, an A record is appended.
        let pkt = encode_advertisement(&rec, "x.local", Some(Ipv4Addr::LOCALHOST), 120);
        assert_eq!(read_u16(&pkt, 6), Some(4));
    }

    #[test]
    fn advertise_then_discover_round_trip() {
        let rec = ServiceRecord::new("living-room", 8443)
            .with_txt(TXT_VERS, "1")
            .with_txt(TXT_NODE_ID, "a1b2c3");
        let pkt = encode_advertisement(
            &rec,
            "living-room.local",
            Some(Ipv4Addr::new(192, 168, 1, 42)),
            120,
        );
        let peers = parse_advertisement(&pkt);
        assert_eq!(peers.len(), 1);
        let Some(p) = peers.first() else { return };
        assert_eq!(p.instance, "living-room");
        assert_eq!(p.host, "living-room.local");
        assert_eq!(p.port, 8443);
        assert_eq!(p.addrs, vec![Ipv4Addr::new(192, 168, 1, 42)]);
        assert_eq!(p.node_id(), Some("a1b2c3"));
        assert_eq!(p.txt, rec.txt);
    }

    #[test]
    fn read_name_follows_compression_pointer() {
        // "ab.local" at offset 0; a pointer to it at offset 10.
        let buf = [
            2, b'a', b'b', 5, b'l', b'o', b'c', b'a', b'l', 0, 0xC0, 0x00,
        ];
        assert_eq!(read_name(&buf, 0), Some(("ab.local".to_string(), 10)));
        // Reading at the pointer resolves the same name; the stream advances
        // past the 2-byte pointer, not the target.
        assert_eq!(read_name(&buf, 10), Some(("ab.local".to_string(), 12)));
    }

    #[test]
    fn read_name_rejects_pointer_loop() {
        // A pointer to itself must not hang.
        assert_eq!(read_name(&[0xC0, 0x00], 0), None);
    }

    #[test]
    fn parse_advertisement_tolerates_malformed_packets() {
        assert!(parse_advertisement(&[]).is_empty());
        assert!(parse_advertisement(&[0, 0, 0]).is_empty()); // shorter than header
        // Header claims one answer but no record follows.
        let hdr = [0, 0, 0x84, 0, 0, 0, 0, 1, 0, 0, 0, 0];
        assert!(parse_advertisement(&hdr).is_empty());
    }

    #[test]
    fn peer_inventory_refreshes_and_expires() {
        let peer = DiscoveredPeer {
            instance: "a".to_string(),
            host: "a.local".to_string(),
            port: 1,
            addrs: vec![],
            txt: vec![],
        };
        let mut inv = PeerInventory::new();
        assert!(inv.is_empty());
        inv.observe(peer.clone(), 0, 120);
        assert!(inv.contains("a"));
        assert_eq!(inv.len(), 1);
        assert_eq!(inv.get("a"), Some(&peer));

        // Not yet expired at tick 100.
        inv.expire(100);
        assert_eq!(inv.len(), 1);
        // Re-observing at 100 refreshes expiry to 220.
        inv.observe(peer, 100, 120);
        inv.expire(150);
        assert_eq!(inv.len(), 1);
        // Past the refreshed expiry it is pruned.
        inv.expire(230);
        assert!(inv.is_empty());
        assert_eq!(inv.peers().len(), 0);
    }
}
