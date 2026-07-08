//! Canonical persistent configuration stored in `NCFS`.
//!
//! TASK-23 (DE-D3, ADR-0045) introduces the first user-editable, on-disk
//! configuration: the **AI endpoint** the runtime talks to. The Settings
//! app writes it; the runtime (`nexacore-runtime-image`) reads it at boot.
//! Both go through the `NCFS` FS service ([`crate::fs_service`]) at the
//! canonical path [`AI_CONFIG_PATH`], postcard-encoded via
//! [`crate::wire::encode_canonical`] (NCIP-Serde-004).
//!
//! ## Fail-safe contract
//!
//! A reader MUST treat an absent or undecodable config as
//! [`AiEndpointConfig::default`] (a logged warning, never a hard fail) —
//! the runtime always has a working endpoint. A WRITER (Settings) MUST
//! [`AiEndpointConfig::validate`] before persisting: an invalid endpoint
//! is rejected with a message and NEVER written. This is the security
//! invariant ("config corrotta → default sicuri + warning"; "endpoint
//! malformato → rifiuto, mai scrittura di config invalida").

use alloc::string::String;

use serde::{Deserialize, Serialize};

/// Canonical `NCFS` path of the AI endpoint config.
///
/// A ROOT-level path on purpose: the `nexacore-fs` on-disk format (TASK-15)
/// reconstructs every inode's path from its basename at mount time
/// (`deserialize_inodes` rebuilds `"/" + name`), so a NESTED file would
/// flatten to root on remount and break reboot persistence. Full nested-path
/// persistence is a tracked `nexacore-fs` follow-up (ADR-0045); until then the
/// config lives at the root, where it round-trips correctly.
pub const AI_CONFIG_PATH: &str = "/ai.cfg";

/// Directory a future nested-config layout would use. Unused while
/// [`AI_CONFIG_PATH`] is root-level (see its note); kept for the follow-up.
pub const CONFIG_DIR: &str = "/config";

/// Maximum length (bytes) of the `host` / `model` strings — bounds the
/// postcard payload and rejects absurd input.
pub const CONFIG_MAX_STR: usize = 128;

/// Why an [`AiEndpointConfig`] failed [`AiEndpointConfig::validate`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub enum ConfigError {
    /// `host` is empty or longer than [`CONFIG_MAX_STR`].
    BadHost,
    /// `host` is not a dotted-quad `IPv4` (`a.b.c.d`, each `0..=255`).
    HostNotIpv4,
    /// `port` is zero.
    BadPort,
    /// `model` is empty or longer than [`CONFIG_MAX_STR`].
    BadModel,
}

/// The AI backend endpoint the runtime connects to.
///
/// `host` is a dotted-quad `IPv4` string (the runtime resolves it to the
/// 4 address bytes via [`AiEndpointConfig::to_connect_addr`]); `port` is
/// the TCP port; `model` is the model name sent to the backend.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AiEndpointConfig {
    /// Backend host as a dotted-quad `IPv4` string, e.g. `"127.0.0.1"`.
    pub host: String,
    /// Backend TCP port, e.g. `11434`.
    pub port: u16,
    /// Model name, e.g. `"gemma4:latest"`.
    pub model: String,
}

impl Default for AiEndpointConfig {
    /// The built-in fallback (the M0/M1 LAN Ollama endpoint). Used whenever
    /// the on-disk config is absent or corrupt.
    fn default() -> Self {
        Self {
            host: String::from("127.0.0.1"),
            port: 11434,
            model: String::from("gemma4:latest"),
        }
    }
}

impl AiEndpointConfig {
    /// Validate user-supplied values before persisting. Returns the parsed
    /// 4 `IPv4` octets on success so a caller need not re-parse.
    ///
    /// # Errors
    /// [`ConfigError`] for an empty/oversized host, a non-`IPv4` host, a zero
    /// port, or an empty/oversized model.
    pub fn validate(&self) -> Result<[u8; 4], ConfigError> {
        if self.host.is_empty() || self.host.len() > CONFIG_MAX_STR {
            return Err(ConfigError::BadHost);
        }
        let octets = parse_ipv4(&self.host).ok_or(ConfigError::HostNotIpv4)?;
        if self.port == 0 {
            return Err(ConfigError::BadPort);
        }
        if self.model.is_empty() || self.model.len() > CONFIG_MAX_STR {
            return Err(ConfigError::BadModel);
        }
        Ok(octets)
    }

    /// The 6-byte connect address (`[ip0, ip1, ip2, ip3, port_hi, port_lo]`,
    /// port big-endian) the runtime's socket layer expects.
    ///
    /// # Errors
    /// [`ConfigError`] if [`Self::validate`] fails (an invalid config never
    /// yields an address).
    pub fn to_connect_addr(&self) -> Result<[u8; 6], ConfigError> {
        let [a, b, c, d] = self.validate()?;
        let port = self.port.to_be_bytes();
        Ok([a, b, c, d, port[0], port[1]])
    }
}

/// Parse a dotted-quad `IPv4` string into 4 octets (`no_std`, no allocation).
/// Returns `None` on any malformation (wrong segment count, non-digit,
/// out-of-range octet, empty segment, leading zeros beyond a single `0`).
fn parse_ipv4(s: &str) -> Option<[u8; 4]> {
    let mut octets = [0u8; 4];
    let mut count = 0usize;
    for seg in s.split('.') {
        let bytes = seg.as_bytes();
        if count >= 4 || bytes.is_empty() || bytes.len() > 3 {
            return None;
        }
        // Reject leading zeros (e.g. "01") to keep parsing unambiguous.
        if bytes.len() > 1 && bytes.first() == Some(&b'0') {
            return None;
        }
        let mut val: u16 = 0;
        for &byte in bytes {
            if !byte.is_ascii_digit() {
                return None;
            }
            val = val * 10 + u16::from(byte - b'0');
        }
        if val > 255 {
            return None;
        }
        // `count < 4` (checked above) so the slot exists; `val <= 255` so the
        // cast is exact — both bounds enforced, no panic path.
        let slot = octets.get_mut(count)?;
        #[allow(
            clippy::cast_possible_truncation,
            reason = "val <= 255 checked immediately above; the cast is exact"
        )]
        {
            *slot = val as u8;
        }
        count += 1;
    }
    if count == 4 { Some(octets) } else { None }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wire::{decode_canonical, encode_canonical};

    #[test]
    fn default_is_valid_and_round_trips() {
        let cfg = AiEndpointConfig::default();
        assert_eq!(cfg.validate().expect("default valid"), [127, 0, 0, 1]);
        let bytes = encode_canonical(&cfg).expect("encode");
        let back: AiEndpointConfig = decode_canonical(&bytes).expect("decode");
        assert_eq!(back, cfg);
        assert_eq!(
            cfg.to_connect_addr().expect("addr"),
            [127, 0, 0, 1, 0x2C, 0xAA] // 11434 = 0x2CAA
        );
    }

    #[test]
    fn rejects_malformed_endpoints() {
        let cfg = |host: &str, port: u16, model: &str| AiEndpointConfig {
            host: String::from(host),
            port,
            model: String::from(model),
        };
        // Empty host.
        assert_eq!(cfg("", 11434, "m").validate(), Err(ConfigError::BadHost));
        // Non-IPv4 host.
        assert_eq!(
            cfg("not.an.ip.addr", 11434, "m").validate(),
            Err(ConfigError::HostNotIpv4)
        );
        // Octet out of range.
        assert_eq!(
            cfg("192.0.2.999", 11434, "m").validate(),
            Err(ConfigError::HostNotIpv4)
        );
        // Zero port.
        assert_eq!(
            cfg("127.0.0.1", 0, "m").validate(),
            Err(ConfigError::BadPort)
        );
        // Empty model.
        assert_eq!(
            cfg("127.0.0.1", 11434, "").validate(),
            Err(ConfigError::BadModel)
        );
    }

    #[test]
    fn corrupt_bytes_decode_fails_caller_uses_default() {
        // A reader feeds garbage; decode fails → the caller substitutes the
        // default (the fail-safe contract, exercised here explicitly).
        let garbage = [0xFFu8, 0x00, 0x13, 0x37, 0x42];
        let decoded: Result<AiEndpointConfig, _> = decode_canonical(&garbage);
        let cfg = decoded.unwrap_or_default();
        assert_eq!(cfg, AiEndpointConfig::default());
    }

    #[test]
    fn ipv4_parser_edge_cases() {
        assert_eq!(parse_ipv4("0.0.0.0"), Some([0, 0, 0, 0]));
        assert_eq!(parse_ipv4("255.255.255.255"), Some([255, 255, 255, 255]));
        assert_eq!(parse_ipv4("10.0.0.1"), Some([10, 0, 0, 1]));
        assert_eq!(parse_ipv4("1.2.3"), None); // too few
        assert_eq!(parse_ipv4("1.2.3.4.5"), None); // too many
        assert_eq!(parse_ipv4("1.2.3."), None); // empty trailing
        assert_eq!(parse_ipv4("1.2.3.256"), None); // out of range
        assert_eq!(parse_ipv4("1.2.3.01"), None); // leading zero
        assert_eq!(parse_ipv4("a.b.c.d"), None); // non-digit
    }
}
