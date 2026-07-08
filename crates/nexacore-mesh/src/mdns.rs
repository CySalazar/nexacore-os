//! NexaCore device service record for mDNS / DNS-SD LAN discovery (WS6-01.1).
//!
//! Every NexaCore device advertises a [`SERVICE_TYPE`] service on the local
//! network so the other devices of a personal cluster can find it without a
//! central directory. This module defines the [`ServiceRecord`] — the instance
//! name, port, and TXT metadata — plus the DNS-SD TXT wire encoding/decoding.
//!
//! WS6-01.1 is the record definition + TXT codec (host-testable here). Actually
//! transmitting the multicast advertisement (WS6-01.2) and receiving/collecting
//! peer records (WS6-01.3) is the live-network step layered on top.

use std::{string::String, vec::Vec};

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
}
