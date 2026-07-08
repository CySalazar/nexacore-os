//! DNS stub resolver (N5.1).
//!
//! Implements RFC 1035 DNS wire encoding for A record (`IPv4` address) queries
//! and response parsing.  This is a stub resolver — it does not perform full
//! recursive resolution; it sends a single UDP query to one of the configured
//! upstream servers and caches the result by TTL.
//!
//! ## Wire format
//!
//! DNS messages on the wire:
//! ```text
//! +---------+-------------------+
//! | Header  | 12 bytes          |
//! +---------+-------------------+
//! | Question| name (labels) +   |
//! |         | QTYPE (2) +       |
//! |         | QCLASS (2)        |
//! +---------+-------------------+
//! | Answer  | name + TYPE +     |
//! | RRs     | CLASS + TTL +     |
//! |         | RDLENGTH + RDATA  |
//! +---------+-------------------+
//! ```
//!
//! ## Pointer compression
//!
//! RFC 1035 §4.1.4 allows name pointers (top 2 bits = `11`). This
//! implementation follows pointers but limits the hop count to
//! `MAX_POINTER_HOPS` to avoid infinite loops on malformed responses.
//!
//! ## Cache
//!
//! Results are cached keyed by the exact query name string (lower-cased).
//! Entries are evicted when `now - cached_at >= ttl` in
//! [`DnsResolver::resolve_cached`].

use alloc::{collections::BTreeMap, string::String, vec::Vec};

use nexacore_types::net::Ipv4Addr;

// =============================================================================
// Constants
// =============================================================================

/// Maximum number of pointer dereferences allowed when decoding a DNS name.
const MAX_POINTER_HOPS: usize = 16;

/// DNS QTYPE for A records.
const QTYPE_A: u16 = 1;
/// DNS QCLASS for Internet.
const QCLASS_IN: u16 = 1;

// =============================================================================
// Types
// =============================================================================

/// A single decoded DNS resource record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsRecord {
    /// Resource record name.
    pub name: String,
    /// Record type (e.g., `1` = A).
    pub rtype: u16,
    /// Record class (e.g., `1` = IN).
    pub rclass: u16,
    /// Time-to-live in seconds.
    pub ttl: u32,
    /// Record data (4 bytes for A records).
    pub rdata: Vec<u8>,
}

/// A cached DNS result.
#[derive(Debug, Clone)]
pub struct DnsCacheEntry {
    /// Resolved `IPv4` addresses.
    pub addresses: Vec<Ipv4Addr>,
    /// Original TTL from the DNS response (seconds).
    pub ttl: u32,
    /// Monotonic timestamp (seconds) when this entry was added to the cache.
    pub cached_at: u64,
}

/// DNS-specific errors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DnsError {
    /// The response packet was shorter than expected.
    Truncated,
    /// An answer section label pointer exceeded `MAX_POINTER_HOPS`.
    PointerLoop,
    /// The DNS server returned a non-zero response code (RCODE).
    ServerError(u8),
    /// No A records were found in the response.
    NoRecords,
    /// The encoded query name contains an invalid label (e.g., empty or too long).
    InvalidName,
}

// =============================================================================
// DnsResolver
// =============================================================================

/// A caching DNS stub resolver.
///
/// # Examples
///
/// ```
/// use nexacore_net::dns::DnsResolver;
/// use nexacore_types::net::Ipv4Addr;
///
/// let mut resolver = DnsResolver::new(vec![Ipv4Addr([8, 8, 8, 8])]);
/// // Build a query for "example.com".
/// let (id, query_bytes) = resolver.build_query("example.com");
/// assert!(!query_bytes.is_empty());
/// ```
#[derive(Debug, Default)]
pub struct DnsResolver {
    /// Upstream DNS server addresses.
    pub servers: Vec<Ipv4Addr>,
    /// Name → cached result.
    cache: BTreeMap<String, DnsCacheEntry>,
    /// Monotonically incrementing query ID.
    next_id: u16,
}

impl DnsResolver {
    /// Construct a new resolver with the given upstream servers.
    #[must_use]
    pub fn new(servers: Vec<Ipv4Addr>) -> Self {
        Self {
            servers,
            cache: BTreeMap::new(),
            next_id: 1,
        }
    }

    /// Return cached addresses for `name` if the entry is still valid.
    ///
    /// `now` is the current monotonic timestamp in seconds.
    #[must_use]
    pub fn resolve_cached(&self, name: &str, now: u64) -> Option<Vec<Ipv4Addr>> {
        let key = name.to_lowercase();
        let entry = self.cache.get(&key)?;
        let age = now.saturating_sub(entry.cached_at);
        if age >= u64::from(entry.ttl) {
            return None;
        }
        Some(entry.addresses.clone())
    }

    /// Build a DNS A-record query for `name`.
    ///
    /// Returns `(query_id, query_bytes)`.  The caller should send `query_bytes`
    /// as a UDP payload to port 53 on one of [`Self::servers`], then pass the
    /// response to [`Self::handle_response`].
    pub fn build_query(&mut self, name: &str) -> (u16, Vec<u8>) {
        let id = self.next_id;
        self.next_id = self.next_id.wrapping_add(1);
        let bytes = encode_dns_query(name, id).unwrap_or_default();
        (id, bytes)
    }

    /// Parse a DNS response and update the cache.
    ///
    /// Returns the list of resolved `IPv4` addresses on success.
    ///
    /// # Errors
    ///
    /// Returns `Err(DnsError::*)` if the response is malformed, indicates a
    /// server error, or contains no A records.
    // `&self` is kept for API symmetry with `query` and `cache_result`;
    // a future version will read the cache to validate duplicate responses.
    #[allow(clippy::unused_self)]
    pub fn handle_response(&self, bytes: &[u8]) -> Result<Vec<Ipv4Addr>, DnsError> {
        let records = decode_dns_response(bytes)?;
        let addrs: Vec<Ipv4Addr> = records
            .iter()
            .filter(|r| r.rtype == QTYPE_A && r.rdata.len() == 4)
            .map(|r| {
                Ipv4Addr([
                    *r.rdata.first().unwrap_or(&0),
                    *r.rdata.get(1).unwrap_or(&0),
                    *r.rdata.get(2).unwrap_or(&0),
                    *r.rdata.get(3).unwrap_or(&0),
                ])
            })
            .collect();
        if addrs.is_empty() {
            return Err(DnsError::NoRecords);
        }
        Ok(addrs)
    }

    /// Store a resolved name in the cache.
    pub fn cache_result(&mut self, name: &str, addrs: Vec<Ipv4Addr>, ttl: u32, now: u64) {
        let key = name.to_lowercase();
        self.cache.insert(
            key,
            DnsCacheEntry {
                addresses: addrs,
                ttl,
                cached_at: now,
            },
        );
    }
}

// =============================================================================
// Wire encoding / decoding
// =============================================================================

/// Encode a DNS A-record query for `name` with the given `id`.
///
/// # Errors
///
/// Returns `None` if `name` contains an empty label or a label exceeding 63
/// bytes (RFC 1035 §3.1), mapped to [`DnsError::InvalidName`].
///
/// # Examples
///
/// ```
/// use nexacore_net::dns::encode_dns_query;
///
/// let bytes = encode_dns_query("example.com", 1).unwrap();
/// // 12-byte header + encoded name + QTYPE (2) + QCLASS (2)
/// assert!(bytes.len() > 12);
/// ```
pub fn encode_dns_query(name: &str, id: u16) -> Result<Vec<u8>, DnsError> {
    let mut out = Vec::new();

    // Header: ID, FLAGS, QDCOUNT, ANCOUNT, NSCOUNT, ARCOUNT.
    let id_bytes = id.to_be_bytes();
    out.push(id_bytes[0]);
    out.push(id_bytes[1]);
    // Flags: RD=1 (recursion desired), all other bits 0.
    out.push(0x01);
    out.push(0x00);
    // QDCOUNT = 1.
    out.push(0x00);
    out.push(0x01);
    // ANCOUNT, NSCOUNT, ARCOUNT = 0.
    out.extend_from_slice(&[0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);

    // Encode the QNAME as length-prefixed labels.
    encode_dns_name(name, &mut out)?;

    // QTYPE = A (1), QCLASS = IN (1) — both fit in u8 (value = 1).
    out.extend_from_slice(&QTYPE_A.to_be_bytes());
    out.extend_from_slice(&QCLASS_IN.to_be_bytes());

    Ok(out)
}

/// Decode a DNS response packet and return the list of resource records.
///
/// # Errors
///
/// Returns `Err(DnsError::*)` on malformed input, pointer loops, or
/// non-zero RCODE.
///
/// # Examples
///
/// ```
/// use nexacore_net::dns::{decode_dns_response, encode_dns_query};
///
/// // We can only test error cases without a live server.
/// let empty: &[u8] = &[];
/// assert!(decode_dns_response(empty).is_err());
/// ```
pub fn decode_dns_response(bytes: &[u8]) -> Result<Vec<DnsRecord>, DnsError> {
    // Minimum DNS header is 12 bytes.
    if bytes.len() < 12 {
        return Err(DnsError::Truncated);
    }

    // Check QR bit (bit 15 of flags) — must be 1 for a response.
    let flags = u16::from_be_bytes([
        *bytes.get(2).ok_or(DnsError::Truncated)?,
        *bytes.get(3).ok_or(DnsError::Truncated)?,
    ]);
    let rcode = (flags & 0x000F) as u8;
    if rcode != 0 {
        return Err(DnsError::ServerError(rcode));
    }

    let qdcount = u16::from_be_bytes([
        *bytes.get(4).ok_or(DnsError::Truncated)?,
        *bytes.get(5).ok_or(DnsError::Truncated)?,
    ]) as usize;
    let ancount = u16::from_be_bytes([
        *bytes.get(6).ok_or(DnsError::Truncated)?,
        *bytes.get(7).ok_or(DnsError::Truncated)?,
    ]) as usize;

    let mut offset = 12usize;

    // Skip question section.
    for _ in 0..qdcount {
        offset = skip_dns_name(bytes, offset)?;
        // QTYPE + QCLASS (4 bytes).
        offset = offset.checked_add(4).ok_or(DnsError::Truncated)?;
        if offset > bytes.len() {
            return Err(DnsError::Truncated);
        }
    }

    // Parse answer section.
    let mut records = Vec::new();
    for _ in 0..ancount {
        let (name, new_offset) = decode_dns_name(bytes, offset)?;
        offset = new_offset;

        if offset + 10 > bytes.len() {
            return Err(DnsError::Truncated);
        }
        let rtype = u16::from_be_bytes([
            *bytes.get(offset).ok_or(DnsError::Truncated)?,
            *bytes.get(offset + 1).ok_or(DnsError::Truncated)?,
        ]);
        let rclass = u16::from_be_bytes([
            *bytes.get(offset + 2).ok_or(DnsError::Truncated)?,
            *bytes.get(offset + 3).ok_or(DnsError::Truncated)?,
        ]);
        let ttl = u32::from_be_bytes([
            *bytes.get(offset + 4).ok_or(DnsError::Truncated)?,
            *bytes.get(offset + 5).ok_or(DnsError::Truncated)?,
            *bytes.get(offset + 6).ok_or(DnsError::Truncated)?,
            *bytes.get(offset + 7).ok_or(DnsError::Truncated)?,
        ]);
        let rdlength = u16::from_be_bytes([
            *bytes.get(offset + 8).ok_or(DnsError::Truncated)?,
            *bytes.get(offset + 9).ok_or(DnsError::Truncated)?,
        ]) as usize;
        offset += 10;
        if offset + rdlength > bytes.len() {
            return Err(DnsError::Truncated);
        }
        let rdata = bytes
            .get(offset..offset + rdlength)
            .ok_or(DnsError::Truncated)?
            .to_vec();
        offset += rdlength;
        records.push(DnsRecord {
            name,
            rtype,
            rclass,
            ttl,
            rdata,
        });
    }

    Ok(records)
}

// =============================================================================
// Private helpers
// =============================================================================

/// Encode `name` as RFC 1035 length-prefixed labels into `out`.
fn encode_dns_name(name: &str, out: &mut Vec<u8>) -> Result<(), DnsError> {
    for label in name.split('.') {
        if label.is_empty() {
            // Allow trailing dot (fully-qualified name) but not empty labels
            // in the middle.
            continue;
        }
        if label.len() > 63 {
            return Err(DnsError::InvalidName);
        }
        // Label length is guaranteed ≤ 63 after the check above.
        #[allow(clippy::cast_possible_truncation)]
        out.push(label.len() as u8);
        out.extend_from_slice(label.as_bytes());
    }
    out.push(0x00); // Root label (end of name).
    Ok(())
}

/// Skip over a DNS name at `offset`, returning the offset after the name.
///
/// Handles pointer compression.
fn skip_dns_name(bytes: &[u8], mut offset: usize) -> Result<usize, DnsError> {
    let mut hops = 0usize;
    loop {
        let b = *bytes.get(offset).ok_or(DnsError::Truncated)?;
        if b & 0xC0 == 0xC0 {
            // Pointer: skip 2 bytes and we're done (pointers are terminal).
            return offset.checked_add(2).ok_or(DnsError::Truncated);
        } else if b == 0 {
            return offset.checked_add(1).ok_or(DnsError::Truncated);
        }
        let label_len = usize::from(b);
        offset = offset
            .checked_add(1 + label_len)
            .ok_or(DnsError::Truncated)?;
        hops += 1;
        if hops > MAX_POINTER_HOPS {
            return Err(DnsError::PointerLoop);
        }
    }
}

/// Decode a DNS name at `offset` in `bytes`, following pointers.
///
/// Returns `(name_string, offset_after_name)`.
fn decode_dns_name(bytes: &[u8], start: usize) -> Result<(String, usize), DnsError> {
    let mut labels: Vec<&str> = Vec::new();
    let mut offset = start;
    // The offset to return (past the first name occurrence, before following
    // any pointers).
    let mut return_offset = None;
    let mut hops = 0usize;

    loop {
        if hops > MAX_POINTER_HOPS {
            return Err(DnsError::PointerLoop);
        }
        let b = *bytes.get(offset).ok_or(DnsError::Truncated)?;
        if b & 0xC0 == 0xC0 {
            // Pointer.
            let ptr_hi = u16::from(b & 0x3F);
            let ptr_lo = u16::from(*bytes.get(offset + 1).ok_or(DnsError::Truncated)?);
            let ptr = usize::from((ptr_hi << 8) | ptr_lo);
            if return_offset.is_none() {
                return_offset = Some(offset.checked_add(2).ok_or(DnsError::Truncated)?);
            }
            offset = ptr;
            hops += 1;
        } else if b == 0 {
            if return_offset.is_none() {
                return_offset = Some(offset.checked_add(1).ok_or(DnsError::Truncated)?);
            }
            break;
        } else {
            let label_len = usize::from(b);
            let label_start = offset.checked_add(1).ok_or(DnsError::Truncated)?;
            let label_end = label_start
                .checked_add(label_len)
                .ok_or(DnsError::Truncated)?;
            let label_bytes = bytes
                .get(label_start..label_end)
                .ok_or(DnsError::Truncated)?;
            // We store the label as a str reference; safe because we only read
            // bytes in-range.
            if let Ok(s) = core::str::from_utf8(label_bytes) {
                labels.push(s);
            }
            offset = label_end;
            hops += 1;
        }
    }

    let name = labels.join(".");
    let final_offset = return_offset.ok_or(DnsError::Truncated)?;
    Ok((name, final_offset))
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
        clippy::used_underscore_binding,
        unused_mut
    )]
    #[allow(clippy::wildcard_imports)]
    use super::*;

    fn make_resolver() -> DnsResolver {
        DnsResolver::new(alloc::vec![Ipv4Addr([8, 8, 8, 8])])
    }

    // -------------------------------------------------------------------------
    // encode_dns_query
    // -------------------------------------------------------------------------

    #[test]
    fn encode_query_starts_with_id() {
        let id: u16 = 0xABCD;
        let bytes = encode_dns_query("example.com", id).unwrap();
        assert_eq!(bytes.first(), Some(&0xAB));
        assert_eq!(bytes.get(1), Some(&0xCD));
    }

    #[test]
    fn encode_query_sets_rd_flag() {
        let bytes = encode_dns_query("example.com", 1).unwrap();
        // Flags byte: 0x01 0x00 (RD=1).
        assert_eq!(bytes.get(2), Some(&0x01));
    }

    #[test]
    fn encode_query_qdcount_is_one() {
        let bytes = encode_dns_query("example.com", 1).unwrap();
        let qdcount = u16::from_be_bytes([*bytes.get(4).unwrap(), *bytes.get(5).unwrap()]);
        assert_eq!(qdcount, 1);
    }

    #[test]
    fn encode_query_ends_with_qtype_a_qclass_in() {
        let bytes = encode_dns_query("example.com", 1).unwrap();
        let n = bytes.len();
        let qtype = u16::from_be_bytes([bytes[n - 4], bytes[n - 3]]);
        let qclass = u16::from_be_bytes([bytes[n - 2], bytes[n - 1]]);
        assert_eq!(qtype, 1); // A
        assert_eq!(qclass, 1); // IN
    }

    #[test]
    fn encode_query_single_label() {
        let bytes = encode_dns_query("localhost", 1).unwrap();
        // 12 (header) + 1+9 (label "localhost") + 1 (root) + 4 (QTYPE+QCLASS)
        assert_eq!(bytes.len(), 12 + 1 + 9 + 1 + 4);
    }

    #[test]
    fn encode_query_fully_qualified_trailing_dot() {
        // Trailing dot should produce the same encoding as without.
        let a = encode_dns_query("example.com", 1).unwrap();
        let b = encode_dns_query("example.com.", 1).unwrap();
        // The name portions should be identical.
        assert_eq!(&a[12..], &b[12..]);
    }

    // -------------------------------------------------------------------------
    // DnsResolver::build_query
    // -------------------------------------------------------------------------

    #[test]
    fn build_query_returns_nonzero_bytes() {
        let mut r = make_resolver();
        let (id, bytes) = r.build_query("google.com");
        assert!(id > 0);
        assert!(!bytes.is_empty());
    }

    #[test]
    fn build_query_increments_id() {
        let mut r = make_resolver();
        let (id1, _) = r.build_query("a.com");
        let (id2, _) = r.build_query("b.com");
        assert_ne!(id1, id2);
    }

    // -------------------------------------------------------------------------
    // Cache
    // -------------------------------------------------------------------------

    #[test]
    fn cache_result_stores_and_resolve_cached_returns_it() {
        let mut r = make_resolver();
        let addrs = alloc::vec![Ipv4Addr([1, 1, 1, 1])];
        r.cache_result("example.com", addrs.clone(), 300, 0);
        let cached = r.resolve_cached("example.com", 100).unwrap();
        assert_eq!(cached, addrs);
    }

    #[test]
    fn cache_entry_expires_after_ttl() {
        let mut r = make_resolver();
        r.cache_result("example.com", alloc::vec![Ipv4Addr([1, 1, 1, 1])], 60, 0);
        // Past TTL.
        assert!(r.resolve_cached("example.com", 61).is_none());
    }

    #[test]
    fn resolve_cached_case_insensitive() {
        let mut r = make_resolver();
        r.cache_result("EXAMPLE.COM", alloc::vec![Ipv4Addr([2, 2, 2, 2])], 300, 0);
        // Key is stored lower-cased; lookup should normalise too.
        let result = r.resolve_cached("example.com", 0);
        assert!(result.is_some());
    }

    #[test]
    fn resolve_cached_returns_none_for_unknown_name() {
        let r = make_resolver();
        assert!(r.resolve_cached("unknown.example", 0).is_none());
    }

    // -------------------------------------------------------------------------
    // decode_dns_response (synthetic packets)
    // -------------------------------------------------------------------------

    /// Build a minimal valid DNS response containing one A record.
    fn make_a_response(id: u16, name: &str, addr: [u8; 4], ttl: u32) -> Vec<u8> {
        let mut pkt = Vec::new();
        // Header.
        pkt.extend_from_slice(&id.to_be_bytes());
        pkt.push(0x81); // QR=1, OPCODE=0, AA=0, TC=0, RD=1
        pkt.push(0x80); // RA=1, Z=0, RCODE=0
        pkt.extend_from_slice(&[0x00, 0x01]); // QDCOUNT=1
        pkt.extend_from_slice(&[0x00, 0x01]); // ANCOUNT=1
        pkt.extend_from_slice(&[0x00, 0x00]); // NSCOUNT
        pkt.extend_from_slice(&[0x00, 0x00]); // ARCOUNT
        // Question.
        encode_dns_name(name, &mut pkt).unwrap();
        pkt.extend_from_slice(&[0x00, 0x01]); // QTYPE A
        pkt.extend_from_slice(&[0x00, 0x01]); // QCLASS IN
        // Answer: use a pointer back to the question name (offset 12).
        pkt.push(0xC0);
        pkt.push(0x0C); // Pointer to offset 12.
        pkt.extend_from_slice(&[0x00, 0x01]); // TYPE A
        pkt.extend_from_slice(&[0x00, 0x01]); // CLASS IN
        pkt.extend_from_slice(&ttl.to_be_bytes());
        pkt.extend_from_slice(&[0x00, 0x04]); // RDLENGTH 4
        pkt.extend_from_slice(&addr);
        pkt
    }

    #[test]
    fn decode_response_parses_a_record() {
        let pkt = make_a_response(42, "example.com", [93, 184, 216, 34], 300);
        let records = decode_dns_response(&pkt).unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].rtype, 1);
        assert_eq!(records[0].rdata, alloc::vec![93, 184, 216, 34]);
        assert_eq!(records[0].ttl, 300);
    }

    #[test]
    fn decode_response_rejects_empty_input() {
        assert!(matches!(decode_dns_response(&[]), Err(DnsError::Truncated)));
    }

    #[test]
    fn decode_response_rejects_non_zero_rcode() {
        // RCODE=3 (NXDOMAIN).
        let mut pkt = make_a_response(1, "missing.example", [0, 0, 0, 0], 0);
        // Patch flags to set RCODE=3.
        pkt[3] = 0x83;
        assert!(matches!(
            decode_dns_response(&pkt),
            Err(DnsError::ServerError(3))
        ));
    }

    #[test]
    fn handle_response_extracts_ipv4_addrs() {
        let mut r = make_resolver();
        let pkt = make_a_response(1, "host.local", [10, 0, 0, 1], 60);
        let addrs = r.handle_response(&pkt).unwrap();
        assert_eq!(addrs, alloc::vec![Ipv4Addr([10, 0, 0, 1])]);
    }

    #[test]
    fn handle_response_no_a_records_returns_error() {
        // Build a response with ANCOUNT=0.
        let mut pkt = make_a_response(1, "empty.example", [0; 4], 0);
        // Set ANCOUNT to 0 in the header (byte 7 = lo byte of ANCOUNT).
        pkt[7] = 0x00;
        // Truncate everything after the question section.
        // "empty.example" → \x05empty\x07example\x00 = 15 bytes; QTYPE+QCLASS = 4 bytes.
        // Header = 12 bytes. Total question end = 12 + 15 + 4 = 31 bytes.
        pkt.truncate(31);
        // decode_dns_response should return Ok([]) since ANCOUNT=0 and no answer section.
        // handle_response should return Err(DnsError::NoRecords) since addrs is empty.
        let r = make_resolver();
        let result = r.handle_response(&pkt);
        assert!(matches!(result, Err(DnsError::NoRecords)));
    }

    #[test]
    fn encode_query_label_too_long_returns_error() {
        let long_label = "a".repeat(64);
        let name = alloc::format!("{long_label}.com");
        let result = encode_dns_query(&name, 1);
        assert!(matches!(result, Err(DnsError::InvalidName)));
    }

    #[test]
    fn decode_response_pointer_followed_correctly() {
        let pkt = make_a_response(5, "ptr.test", [192, 168, 1, 1], 100);
        let records = decode_dns_response(&pkt).unwrap();
        // Pointer in answer section should be resolved to the question name.
        assert_eq!(records[0].rdata, alloc::vec![192, 168, 1, 1]);
    }

    #[test]
    fn new_resolver_has_correct_servers() {
        let servers = alloc::vec![Ipv4Addr([1, 1, 1, 1]), Ipv4Addr([8, 8, 8, 8])];
        let r = DnsResolver::new(servers.clone());
        assert_eq!(r.servers, servers);
    }

    #[test]
    fn cache_result_and_handle_response_consistency() {
        let mut r = make_resolver();
        let pkt = make_a_response(1, "consistent.example", [10, 20, 30, 40], 120);
        let addrs = r.handle_response(&pkt).unwrap();
        r.cache_result("consistent.example", addrs.clone(), 120, 0);
        let cached = r.resolve_cached("consistent.example", 50).unwrap();
        assert_eq!(cached, addrs);
    }
}
