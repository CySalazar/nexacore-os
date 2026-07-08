//! IEEE 802.11 MAC-header and management-frame parsing (WS2-11.4 / WS2-11.5).
//!
//! * [`MacHeader`] decodes the 24-byte management/data MAC header (frame
//!   control, addresses, sequence).
//! * [`InformationElements`] iterates the `(id, len, value)` TLV elements in a
//!   management-frame body.
//! * [`Beacon`] parses a beacon / probe-response into a scan result (SSID,
//!   channel, capabilities, RSN presence) — WS2-11.4.
//! * [`build_auth`] / [`parse_auth`] and [`build_assoc_request`] /
//!   [`parse_assoc_response`] cover the 802.11 authentication and association
//!   exchange — WS2-11.5.
//!
//! All parsers are bounds-checked and borrow from the input; builders return a
//! freshly-allocated frame. Multi-byte fields are little-endian (802.11 wire).

// Lengths are bounded by the 802.11 frame size (< 4 KiB); the `as u8` casts on
// element lengths are range-checked by the callers.
#![allow(clippy::cast_possible_truncation)]

use alloc::vec::Vec;

/// MAC address (6 octets).
pub type MacAddr = [u8; 6];

/// Length of the (non-QoS) 802.11 MAC header in bytes.
pub const MAC_HEADER_LEN: usize = 24;

/// 802.11 frame type (frame-control bits 2–3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrameType {
    /// Management frame (beacon, probe, auth, assoc, …).
    Management,
    /// Control frame (ACK, RTS, CTS, …).
    Control,
    /// Data frame.
    Data,
    /// Reserved / extension type.
    Reserved,
}

/// Management-frame subtype (frame-control bits 4–7), the ones the supplicant
/// cares about.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MgmtSubtype {
    /// Association request (0).
    AssocRequest,
    /// Association response (1).
    AssocResponse,
    /// Probe request (4).
    ProbeRequest,
    /// Probe response (5).
    ProbeResponse,
    /// Beacon (8).
    Beacon,
    /// Authentication (11).
    Authentication,
    /// Deauthentication (12).
    Deauthentication,
    /// Any other management subtype.
    Other(u8),
}

impl MgmtSubtype {
    #[must_use]
    fn from_bits(subtype: u8) -> Self {
        match subtype {
            0 => Self::AssocRequest,
            1 => Self::AssocResponse,
            4 => Self::ProbeRequest,
            5 => Self::ProbeResponse,
            8 => Self::Beacon,
            11 => Self::Authentication,
            12 => Self::Deauthentication,
            other => Self::Other(other),
        }
    }
}

/// Parsed 802.11 MAC header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MacHeader {
    /// Raw frame-control field (little-endian).
    pub frame_control: u16,
    /// Duration / association-id field.
    pub duration: u16,
    /// Address 1 (receiver / destination).
    pub addr1: MacAddr,
    /// Address 2 (transmitter / source).
    pub addr2: MacAddr,
    /// Address 3 (BSSID for the common cases).
    pub addr3: MacAddr,
    /// Sequence-control field.
    pub seq_control: u16,
}

impl MacHeader {
    /// Parse a MAC header from the front of `buf`, or `None` if too short.
    #[must_use]
    pub fn parse(buf: &[u8]) -> Option<Self> {
        let h = buf.get(..MAC_HEADER_LEN)?;
        let frame_control = u16::from_le_bytes([*h.first()?, *h.get(1)?]);
        let duration = u16::from_le_bytes([*h.get(2)?, *h.get(3)?]);
        let addr1: MacAddr = h.get(4..10)?.try_into().ok()?;
        let addr2: MacAddr = h.get(10..16)?.try_into().ok()?;
        let addr3: MacAddr = h.get(16..22)?.try_into().ok()?;
        let seq_control = u16::from_le_bytes([*h.get(22)?, *h.get(23)?]);
        Some(Self {
            frame_control,
            duration,
            addr1,
            addr2,
            addr3,
            seq_control,
        })
    }

    /// The frame type (bits 2–3 of frame control).
    #[must_use]
    pub const fn frame_type(self) -> FrameType {
        match (self.frame_control >> 2) & 0b11 {
            0 => FrameType::Management,
            1 => FrameType::Control,
            2 => FrameType::Data,
            _ => FrameType::Reserved,
        }
    }

    /// The management subtype (bits 4–7 of frame control).
    #[must_use]
    pub fn mgmt_subtype(self) -> MgmtSubtype {
        MgmtSubtype::from_bits(((self.frame_control >> 4) & 0b1111) as u8)
    }

    /// `true` if the Protected-Frame bit (frame-control bit 14) is set.
    #[must_use]
    pub const fn protected(self) -> bool {
        self.frame_control & (1 << 14) != 0
    }
}

/// Build a 24-byte management MAC header with the given subtype and addresses.
#[must_use]
pub fn build_mgmt_header(
    subtype: u8,
    da: MacAddr,
    sa: MacAddr,
    bssid: MacAddr,
    seq: u16,
) -> Vec<u8> {
    // Frame control: type=Management(0), subtype in bits 4–7.
    let fc: u16 = (u16::from(subtype) & 0b1111) << 4;
    let mut v = Vec::with_capacity(MAC_HEADER_LEN);
    v.extend_from_slice(&fc.to_le_bytes());
    v.extend_from_slice(&0u16.to_le_bytes()); // duration
    v.extend_from_slice(&da);
    v.extend_from_slice(&sa);
    v.extend_from_slice(&bssid);
    v.extend_from_slice(&(seq << 4).to_le_bytes()); // fragment 0
    v
}

// ===========================================================================
// Information elements (TLV)
// ===========================================================================

/// Well-known information-element ids.
pub mod eid {
    /// SSID element (id 0).
    pub const SSID: u8 = 0;
    /// Supported rates (id 1).
    pub const SUPPORTED_RATES: u8 = 1;
    /// DS parameter set — carries the channel (id 3).
    pub const DS_PARAM: u8 = 3;
    /// RSN element — WPA2/WPA3 security parameters (id 48).
    pub const RSN: u8 = 48;
    /// Vendor-specific element, e.g. WPA1 (id 221).
    pub const VENDOR: u8 = 221;
}

/// Iterator over the `(id, value)` information elements in a frame body.
#[derive(Debug, Clone)]
pub struct InformationElements<'a> {
    rest: &'a [u8],
}

impl<'a> InformationElements<'a> {
    /// Iterate the IEs in `body` (the bytes after a management frame's fixed
    /// fields).
    #[must_use]
    pub const fn new(body: &'a [u8]) -> Self {
        Self { rest: body }
    }

    /// Find the first element with id `id`, returning its value bytes.
    #[must_use]
    pub fn lookup(self, id: u8) -> Option<&'a [u8]> {
        self.into_iter()
            .find_map(|(eid, v)| (eid == id).then_some(v))
    }
}

impl<'a> Iterator for InformationElements<'a> {
    type Item = (u8, &'a [u8]);

    fn next(&mut self) -> Option<Self::Item> {
        let id = *self.rest.first()?;
        let len = *self.rest.get(1)? as usize;
        let value = self.rest.get(2..2 + len)?;
        self.rest = self.rest.get(2 + len..).unwrap_or(&[]);
        Some((id, value))
    }
}

/// Build an information element: `id`, length, value. Values longer than 255
/// bytes are truncated to the 8-bit length field.
#[must_use]
pub fn build_ie(id: u8, value: &[u8]) -> Vec<u8> {
    let len = value.len().min(255);
    let mut v = Vec::with_capacity(2 + len);
    v.push(id);
    v.push(len as u8);
    v.extend_from_slice(value.get(..len).unwrap_or(value));
    v
}

// ===========================================================================
// Beacon / probe-response (scan result) — WS2-11.4
// ===========================================================================

/// Capability-info bit: the BSS requires privacy (WEP/WPA) — frame body bit 4.
pub const CAP_PRIVACY: u16 = 1 << 4;

/// A parsed beacon / probe-response: the fields the scanner shows the user.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Beacon<'a> {
    /// BSSID (the AP's MAC, from header address 3).
    pub bssid: MacAddr,
    /// SSID bytes (may be empty for a hidden network).
    pub ssid: &'a [u8],
    /// Operating channel, from the DS-parameter element if present.
    pub channel: Option<u8>,
    /// Beacon interval in TUs (1024 µs units).
    pub interval: u16,
    /// Raw capability-info field.
    pub capability: u16,
    /// Whether an RSN element (WPA2/WPA3) is present.
    pub rsn: bool,
}

impl<'a> Beacon<'a> {
    /// Parse a full beacon / probe-response frame (MAC header + fixed fields +
    /// IEs). Returns `None` if the frame is not a beacon/probe-response or is
    /// truncated.
    #[must_use]
    pub fn parse(frame: &'a [u8]) -> Option<Self> {
        let hdr = MacHeader::parse(frame)?;
        if hdr.frame_type() != FrameType::Management {
            return None;
        }
        match hdr.mgmt_subtype() {
            MgmtSubtype::Beacon | MgmtSubtype::ProbeResponse => {}
            _ => return None,
        }
        // Fixed fields: timestamp(8) + beacon interval(2) + capability(2).
        let body = frame.get(MAC_HEADER_LEN..)?;
        let interval = u16::from_le_bytes([*body.get(8)?, *body.get(9)?]);
        let capability = u16::from_le_bytes([*body.get(10)?, *body.get(11)?]);
        let ies = body.get(12..)?;

        let ssid = InformationElements::new(ies)
            .lookup(eid::SSID)
            .unwrap_or(&[]);
        let channel = InformationElements::new(ies)
            .lookup(eid::DS_PARAM)
            .and_then(|v| v.first().copied());
        let rsn = InformationElements::new(ies).lookup(eid::RSN).is_some();

        Some(Self {
            bssid: hdr.addr3,
            ssid,
            channel,
            interval,
            capability,
            rsn,
        })
    }

    /// `true` if the BSS advertises privacy (encrypted).
    #[must_use]
    pub const fn privacy(&self) -> bool {
        self.capability & CAP_PRIVACY != 0
    }
}

// ===========================================================================
// Authentication — WS2-11.5
// ===========================================================================

/// 802.11 authentication algorithm numbers.
pub mod auth_algo {
    /// Open-system authentication.
    pub const OPEN: u16 = 0;
    /// Shared-key authentication (WEP, legacy).
    pub const SHARED_KEY: u16 = 1;
    /// Simultaneous Authentication of Equals (WPA3).
    pub const SAE: u16 = 3;
}

/// 802.11 status code `Success`.
pub const STATUS_SUCCESS: u16 = 0;

/// Subtype value for an authentication management frame.
pub const SUBTYPE_AUTH: u8 = 11;
/// Subtype value for an association-request management frame.
pub const SUBTYPE_ASSOC_REQ: u8 = 0;
/// Subtype value for an association-response management frame.
pub const SUBTYPE_ASSOC_RESP: u8 = 1;

/// A parsed authentication frame body.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Auth {
    /// Authentication algorithm number ([`auth_algo`]).
    pub algorithm: u16,
    /// Authentication transaction sequence number (1-based).
    pub seq: u16,
    /// Status code (`0` = success).
    pub status: u16,
}

/// Build an authentication frame (header + body) from `sta` to `bssid`.
#[must_use]
pub fn build_auth(
    sta: MacAddr,
    bssid: MacAddr,
    algorithm: u16,
    seq: u16,
    frame_seq: u16,
) -> Vec<u8> {
    let mut v = build_mgmt_header(SUBTYPE_AUTH, bssid, sta, bssid, frame_seq);
    v.extend_from_slice(&algorithm.to_le_bytes());
    v.extend_from_slice(&seq.to_le_bytes());
    v.extend_from_slice(&STATUS_SUCCESS.to_le_bytes());
    v
}

/// Parse the authentication body of a received auth frame.
#[must_use]
pub fn parse_auth(frame: &[u8]) -> Option<Auth> {
    let hdr = MacHeader::parse(frame)?;
    if hdr.mgmt_subtype() != MgmtSubtype::Authentication {
        return None;
    }
    let body = frame.get(MAC_HEADER_LEN..)?;
    let algorithm = u16::from_le_bytes([*body.first()?, *body.get(1)?]);
    let seq = u16::from_le_bytes([*body.get(2)?, *body.get(3)?]);
    let status = u16::from_le_bytes([*body.get(4)?, *body.get(5)?]);
    Some(Auth {
        algorithm,
        seq,
        status,
    })
}

/// A parsed association-response body.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AssocResponse {
    /// Capability info echoed by the AP.
    pub capability: u16,
    /// Status code (`0` = success).
    pub status: u16,
    /// Association id (lower 14 bits significant) assigned on success.
    pub aid: u16,
}

/// Build an association request: capability + listen interval + SSID and RSN
/// information elements.
#[must_use]
pub fn build_assoc_request(
    sta: MacAddr,
    bssid: MacAddr,
    capability: u16,
    listen_interval: u16,
    ssid: &[u8],
    rsn_ie: &[u8],
    frame_seq: u16,
) -> Vec<u8> {
    let mut v = build_mgmt_header(SUBTYPE_ASSOC_REQ, bssid, sta, bssid, frame_seq);
    v.extend_from_slice(&capability.to_le_bytes());
    v.extend_from_slice(&listen_interval.to_le_bytes());
    v.extend_from_slice(&build_ie(eid::SSID, ssid));
    if !rsn_ie.is_empty() {
        v.extend_from_slice(&build_ie(eid::RSN, rsn_ie));
    }
    v
}

/// Parse an association-response frame.
#[must_use]
pub fn parse_assoc_response(frame: &[u8]) -> Option<AssocResponse> {
    let hdr = MacHeader::parse(frame)?;
    if hdr.mgmt_subtype() != MgmtSubtype::AssocResponse {
        return None;
    }
    let body = frame.get(MAC_HEADER_LEN..)?;
    let capability = u16::from_le_bytes([*body.first()?, *body.get(1)?]);
    let status = u16::from_le_bytes([*body.get(2)?, *body.get(3)?]);
    let aid = u16::from_le_bytes([*body.get(4)?, *body.get(5)?]) & 0x3FFF;
    Some(AssocResponse {
        capability,
        status,
        aid,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const STA: MacAddr = [0x02, 0x11, 0x22, 0x33, 0x44, 0x55];
    const AP: MacAddr = [0x06, 0xaa, 0xbb, 0xcc, 0xdd, 0xee];

    #[test]
    fn mac_header_round_trip_via_builder() {
        let f = build_mgmt_header(SUBTYPE_AUTH, AP, STA, AP, 7);
        let h = MacHeader::parse(&f).unwrap();
        assert_eq!(h.frame_type(), FrameType::Management);
        assert_eq!(h.mgmt_subtype(), MgmtSubtype::Authentication);
        assert_eq!(h.addr2, STA);
        assert_eq!(h.addr3, AP);
        assert!(!h.protected());
    }

    #[test]
    fn ie_iterator_walks_elements() {
        let mut body = Vec::new();
        body.extend_from_slice(&build_ie(eid::SSID, b"NexaNet"));
        body.extend_from_slice(&build_ie(eid::DS_PARAM, &[6]));
        let mut it = InformationElements::new(&body);
        assert_eq!(it.next(), Some((eid::SSID, &b"NexaNet"[..])));
        assert_eq!(it.next(), Some((eid::DS_PARAM, &[6u8][..])));
        assert_eq!(it.next(), None);
    }

    #[test]
    fn ie_iterator_stops_on_truncated_element() {
        // id=0, len=10 but only 2 value bytes present → no element yielded.
        let body = [0u8, 10, 0xaa, 0xbb];
        let mut it = InformationElements::new(&body);
        assert_eq!(it.next(), None);
    }

    fn make_beacon(ssid: &[u8], channel: u8, with_rsn: bool) -> Vec<u8> {
        let mut f = build_mgmt_header(8 /* beacon */, [0xff; 6], AP, AP, 1);
        f.extend_from_slice(&0u64.to_le_bytes()); // timestamp
        f.extend_from_slice(&100u16.to_le_bytes()); // beacon interval
        f.extend_from_slice(&CAP_PRIVACY.to_le_bytes()); // capability
        f.extend_from_slice(&build_ie(eid::SSID, ssid));
        f.extend_from_slice(&build_ie(eid::DS_PARAM, &[channel]));
        if with_rsn {
            f.extend_from_slice(&build_ie(eid::RSN, &[0x01, 0x00]));
        }
        f
    }

    #[test]
    fn beacon_parse_extracts_scan_fields() {
        let f = make_beacon(b"NexaNet", 11, true);
        let b = Beacon::parse(&f).unwrap();
        assert_eq!(b.bssid, AP);
        assert_eq!(b.ssid, b"NexaNet");
        assert_eq!(b.channel, Some(11));
        assert_eq!(b.interval, 100);
        assert!(b.rsn);
        assert!(b.privacy());
    }

    #[test]
    fn beacon_parse_handles_hidden_ssid_and_no_rsn() {
        let f = make_beacon(b"", 1, false);
        let b = Beacon::parse(&f).unwrap();
        assert!(b.ssid.is_empty());
        assert!(!b.rsn);
        assert_eq!(b.channel, Some(1));
    }

    #[test]
    fn beacon_parse_rejects_non_beacon() {
        let auth = build_auth(STA, AP, auth_algo::OPEN, 1, 0);
        assert!(Beacon::parse(&auth).is_none());
    }

    #[test]
    fn auth_round_trips() {
        let f = build_auth(STA, AP, auth_algo::SAE, 1, 3);
        let a = parse_auth(&f).unwrap();
        assert_eq!(a.algorithm, auth_algo::SAE);
        assert_eq!(a.seq, 1);
        assert_eq!(a.status, STATUS_SUCCESS);
    }

    #[test]
    fn assoc_request_then_response() {
        let req = build_assoc_request(STA, AP, CAP_PRIVACY, 10, b"NexaNet", &[0x01, 0x00], 5);
        let h = MacHeader::parse(&req).unwrap();
        assert_eq!(h.mgmt_subtype(), MgmtSubtype::AssocRequest);
        // The SSID IE must be present in the request body.
        let body = &req[MAC_HEADER_LEN + 4..];
        assert_eq!(
            InformationElements::new(body).lookup(eid::SSID),
            Some(&b"NexaNet"[..])
        );

        // Build a matching response by hand and parse it.
        let mut resp = build_mgmt_header(SUBTYPE_ASSOC_RESP, STA, AP, AP, 6);
        resp.extend_from_slice(&CAP_PRIVACY.to_le_bytes());
        resp.extend_from_slice(&STATUS_SUCCESS.to_le_bytes());
        resp.extend_from_slice(&(0xC001u16).to_le_bytes()); // AID with top bits set
        let parsed = parse_assoc_response(&resp).unwrap();
        assert_eq!(parsed.status, STATUS_SUCCESS);
        assert_eq!(parsed.aid, 0x0001, "AID masks to lower 14 bits");
    }
}
