//! DNS-SD (`_ipp._tcp`) printer-discovery model (WS2-13.2).
//!
//! IPP printers advertise over mDNS/DNS-SD as `_ipp._tcp` (and `_ipps._tcp`)
//! services. The live multicast query/response is the network/device side; this
//! module models a discovered service and parses the DNS-SD TXT record (the
//! `key=value` pairs that carry `rp` — the resource path — and `pdl` — the
//! supported document formats), which is pure and host-testable.

use alloc::{string::String, vec::Vec};

/// A printer discovered via DNS-SD (WS2-13.2).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DiscoveredPrinter {
    /// The service instance name (e.g. `"Office Laser"`).
    pub instance: String,
    /// The target host (A/AAAA target of the SRV record).
    pub host: String,
    /// The IPP port (usually 631).
    pub port: u16,
    /// Parsed TXT key/value pairs.
    pub txt: Vec<(String, String)>,
}

impl DiscoveredPrinter {
    /// Build the `ipp://` URI for this printer using its `rp` (resource-path)
    /// TXT key, defaulting to `ipp/print`.
    #[must_use]
    pub fn uri(&self) -> String {
        let rp = self.txt_get("rp").unwrap_or("ipp/print");
        let mut uri = String::from("ipp://");
        uri.push_str(&self.host);
        if self.port != 631 {
            uri.push(':');
            uri.push_str(&itoa(self.port));
        }
        uri.push('/');
        uri.push_str(rp);
        uri
    }

    /// Look up a TXT key (case-sensitive per DNS-SD convention for IPP keys).
    #[must_use]
    pub fn txt_get(&self, key: &str) -> Option<&str> {
        self.txt
            .iter()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v.as_str())
    }

    /// The supported document formats from the `pdl` TXT key (comma-separated).
    #[must_use]
    pub fn document_formats(&self) -> Vec<&str> {
        self.txt_get("pdl")
            .map(|p| p.split(',').collect())
            .unwrap_or_default()
    }
}

/// Parse a DNS-SD TXT record (a sequence of length-prefixed `key=value`
/// strings) into key/value pairs (WS2-13.2).
///
/// Each entry is a 1-byte length followed by that many bytes of `key=value`
/// (or a bare `key`, which yields an empty value). Entries that overrun the
/// buffer are skipped.
#[must_use]
pub fn parse_txt(record: &[u8]) -> Vec<(String, String)> {
    let mut out = Vec::new();
    let mut i = 0usize;
    while let Some(&len) = record.get(i) {
        let start = i + 1;
        let end = start + len as usize;
        let Some(entry) = record.get(start..end) else {
            break;
        };
        if let Ok(text) = core::str::from_utf8(entry) {
            let (k, v) = text.split_once('=').unwrap_or((text, ""));
            if !k.is_empty() {
                out.push((String::from(k), String::from(v)));
            }
        }
        i = end;
    }
    out
}

/// Minimal `u16` → decimal string (no_std-friendly, avoids `format!`).
fn itoa(mut n: u16) -> String {
    if n == 0 {
        return String::from("0");
    }
    let mut digits = [0u8; 5];
    let mut i = digits.len();
    while n > 0 {
        i -= 1;
        if let Some(d) = digits.get_mut(i) {
            *d = b'0' + (n % 10) as u8;
        }
        n /= 10;
    }
    core::str::from_utf8(digits.get(i..).unwrap_or(b"0"))
        .map(String::from)
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a TXT record from `key=value` literals (1-byte length prefixes).
    fn txt(entries: &[&str]) -> Vec<u8> {
        let mut out = Vec::new();
        for e in entries {
            out.push(e.len() as u8);
            out.extend_from_slice(e.as_bytes());
        }
        out
    }

    fn printer() -> DiscoveredPrinter {
        let record = txt(&[
            "rp=ipp/print",
            "pdl=application/pdf,image/pwg-raster",
            "ty=Office Laser",
        ]);
        DiscoveredPrinter {
            instance: String::from("Office Laser"),
            host: String::from("laser.local"),
            port: 631,
            txt: parse_txt(&record),
        }
    }

    #[test]
    fn parse_txt_splits_key_value() {
        let pairs = parse_txt(&txt(&["rp=ipp/print", "air=none", "flag"]));
        assert_eq!(pairs[0], (String::from("rp"), String::from("ipp/print")));
        assert_eq!(pairs[1], (String::from("air"), String::from("none")));
        assert_eq!(pairs[2], (String::from("flag"), String::new()));
    }

    #[test]
    fn parse_txt_skips_overrunning_entry() {
        // length byte claims 50 bytes but only 3 follow → skipped, no panic.
        let pairs = parse_txt(&[50, b'a', b'=', b'b']);
        assert!(pairs.is_empty());
    }

    #[test]
    fn uri_uses_resource_path() {
        assert_eq!(printer().uri(), "ipp://laser.local/ipp/print");
    }

    #[test]
    fn uri_includes_nonstandard_port() {
        let mut p = printer();
        p.port = 8631;
        assert_eq!(p.uri(), "ipp://laser.local:8631/ipp/print");
    }

    #[test]
    fn document_formats_from_pdl() {
        assert_eq!(
            printer().document_formats(),
            alloc::vec!["application/pdf", "image/pwg-raster"]
        );
    }
}
