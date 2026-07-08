//! Structured log record schema (WS12-03.1).
//!
//! A [`LogRecord`] is a journald-style structured entry: a monotonic sequence
//! number, a timestamp, a syslog [`Severity`], the emitting service name, a
//! human-readable message, and arbitrary structured `key=value` fields. Records
//! serialise to a self-describing length-prefixed binary form so they survive
//! being written to a persistent ring and read back after a reboot.

use alloc::{
    string::{String, ToString},
    vec::Vec,
};

/// Syslog-style severity levels (RFC 5424 § 6.2.1), most severe first.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u8)]
pub enum Severity {
    /// System is unusable.
    Emergency = 0,
    /// Action must be taken immediately.
    Alert = 1,
    /// Critical conditions.
    Critical = 2,
    /// Error conditions.
    Error = 3,
    /// Warning conditions.
    Warning = 4,
    /// Normal but significant condition.
    Notice = 5,
    /// Informational messages.
    Info = 6,
    /// Debug-level messages.
    Debug = 7,
}

impl Severity {
    /// Decode a severity byte.
    #[must_use]
    pub const fn from_u8(b: u8) -> Option<Self> {
        Some(match b {
            0 => Self::Emergency,
            1 => Self::Alert,
            2 => Self::Critical,
            3 => Self::Error,
            4 => Self::Warning,
            5 => Self::Notice,
            6 => Self::Info,
            7 => Self::Debug,
            _ => return None,
        })
    }

    /// The lowercase syslog keyword for this severity.
    #[must_use]
    pub const fn keyword(self) -> &'static str {
        match self {
            Self::Emergency => "emerg",
            Self::Alert => "alert",
            Self::Critical => "crit",
            Self::Error => "err",
            Self::Warning => "warning",
            Self::Notice => "notice",
            Self::Info => "info",
            Self::Debug => "debug",
        }
    }

    /// Whether this severity is at least as severe as `threshold`.
    ///
    /// Because lower numeric values are more severe, "at least as severe" means
    /// a numerically smaller-or-equal level.
    #[must_use]
    pub const fn at_least(self, threshold: Self) -> bool {
        (self as u8) <= (threshold as u8)
    }
}

/// A single structured log entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LogRecord {
    /// Monotonic sequence number, assigned by the ingestion bus. `0` before
    /// ingestion.
    pub seq: u64,
    /// Timestamp in nanoseconds since an arbitrary but monotone epoch.
    pub timestamp_ns: u64,
    /// Severity level.
    pub severity: Severity,
    /// Emitting service / unit name (e.g. `"net"`, `"kernel"`).
    pub service: String,
    /// Free-text message.
    pub message: String,
    /// Structured fields as ordered `(key, value)` pairs.
    pub fields: Vec<(String, String)>,
}

impl LogRecord {
    /// Build a record with no structured fields and `seq = 0` (the bus assigns
    /// the real sequence number on ingestion).
    #[must_use]
    pub fn new(timestamp_ns: u64, severity: Severity, service: &str, message: &str) -> Self {
        Self {
            seq: 0,
            timestamp_ns,
            severity,
            service: service.to_string(),
            message: message.to_string(),
            fields: Vec::new(),
        }
    }

    /// Attach a structured field (builder style).
    #[must_use]
    pub fn with_field(mut self, key: &str, value: &str) -> Self {
        self.fields.push((key.to_string(), value.to_string()));
        self
    }

    /// Serialise to the self-describing binary form.
    ///
    /// Layout: `seq(8) || ts(8) || severity(1) || svc || msg || nfields(2) ||
    /// (key, value)*`, where every string is a `u16`-length-prefixed UTF-8 run.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&self.seq.to_be_bytes());
        out.extend_from_slice(&self.timestamp_ns.to_be_bytes());
        out.push(self.severity as u8);
        put_str(&mut out, &self.service);
        put_str(&mut out, &self.message);
        // Field count, clamped to u16 (records with more are truncated on
        // encode — the bus caps field counts well below this).
        let n = u16::try_from(self.fields.len()).unwrap_or(u16::MAX);
        out.extend_from_slice(&n.to_be_bytes());
        for (k, v) in self.fields.iter().take(n as usize) {
            put_str(&mut out, k);
            put_str(&mut out, v);
        }
        out
    }

    /// Parse the binary form, returning the record and the number of bytes
    /// consumed. Fails closed (`None`) on any truncation or invalid field.
    #[must_use]
    pub fn decode(buf: &[u8]) -> Option<(Self, usize)> {
        let mut pos = 0usize;
        let seq = read_u64(buf, &mut pos)?;
        let timestamp_ns = read_u64(buf, &mut pos)?;
        let sev_byte = read_u8(buf, &mut pos)?;
        let severity = Severity::from_u8(sev_byte)?;
        let service = read_str(buf, &mut pos)?;
        let message = read_str(buf, &mut pos)?;
        let nfields = read_u16(buf, &mut pos)? as usize;
        let mut fields = Vec::with_capacity(nfields);
        for _ in 0..nfields {
            let k = read_str(buf, &mut pos)?;
            let v = read_str(buf, &mut pos)?;
            fields.push((k, v));
        }
        Some((
            Self {
                seq,
                timestamp_ns,
                severity,
                service,
                message,
                fields,
            },
            pos,
        ))
    }
}

fn put_str(out: &mut Vec<u8>, s: &str) {
    let bytes = s.as_bytes();
    let n = u16::try_from(bytes.len()).unwrap_or(u16::MAX);
    out.extend_from_slice(&n.to_be_bytes());
    // `take(n)` avoids slice indexing; when the string fits (the common case)
    // this copies all of it, otherwise it truncates to the u16 cap.
    out.extend(bytes.iter().take(n as usize).copied());
}

fn read_u8(buf: &[u8], pos: &mut usize) -> Option<u8> {
    let b = buf.get(*pos).copied()?;
    *pos += 1;
    Some(b)
}

fn read_u16(buf: &[u8], pos: &mut usize) -> Option<u16> {
    let end = pos.checked_add(2)?;
    let slice = buf.get(*pos..end)?;
    let arr: [u8; 2] = slice.try_into().ok()?;
    *pos = end;
    Some(u16::from_be_bytes(arr))
}

fn read_u64(buf: &[u8], pos: &mut usize) -> Option<u64> {
    let end = pos.checked_add(8)?;
    let slice = buf.get(*pos..end)?;
    let arr: [u8; 8] = slice.try_into().ok()?;
    *pos = end;
    Some(u64::from_be_bytes(arr))
}

fn read_str(buf: &[u8], pos: &mut usize) -> Option<String> {
    let n = read_u16(buf, pos)? as usize;
    let end = pos.checked_add(n)?;
    let slice = buf.get(*pos..end)?;
    let s = core::str::from_utf8(slice).ok()?.to_string();
    *pos = end;
    Some(s)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::indexing_slicing)]

    use super::*;

    #[test]
    fn severity_ordering_and_threshold() {
        assert!(Severity::Error < Severity::Warning); // Error is more severe
        assert!(Severity::Error.at_least(Severity::Warning));
        assert!(!Severity::Info.at_least(Severity::Warning));
        assert!(Severity::Emergency.at_least(Severity::Debug));
    }

    #[test]
    fn severity_byte_round_trip() {
        for b in 0u8..=7 {
            let s = Severity::from_u8(b).unwrap();
            assert_eq!(s as u8, b);
        }
        assert_eq!(Severity::from_u8(8), None);
    }

    #[test]
    fn record_encode_decode_round_trips() {
        let rec = LogRecord::new(123_456, Severity::Warning, "net", "link down")
            .with_field("iface", "eth0")
            .with_field("code", "42");
        let bytes = rec.encode();
        let (parsed, consumed) = LogRecord::decode(&bytes).unwrap();
        assert_eq!(consumed, bytes.len());
        assert_eq!(parsed, rec);
    }

    #[test]
    fn decode_rejects_truncation_and_bad_severity() {
        let rec = LogRecord::new(1, Severity::Info, "svc", "msg");
        let bytes = rec.encode();
        assert!(LogRecord::decode(&bytes[..bytes.len() - 1]).is_none());
        let mut bad = bytes;
        bad[16] = 9; // severity byte out of range
        assert!(LogRecord::decode(&bad).is_none());
    }

    #[test]
    fn utf8_message_survives_round_trip() {
        let rec = LogRecord::new(9, Severity::Notice, "ui", "caffè ☕ 完成");
        let (parsed, _) = LogRecord::decode(&rec.encode()).unwrap();
        assert_eq!(parsed.message, "caffè ☕ 完成");
    }
}
