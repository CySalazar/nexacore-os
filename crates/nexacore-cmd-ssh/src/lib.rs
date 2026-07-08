//! # `nexacore-cmd-ssh`
//!
//! SSH client command scaffold for NexaCore OS — packet framing and types only.
//!
//! This crate provides the SSH-2 binary packet framing layer (RFC 4253 §6)
//! and the basic type definitions required to start an SSH session.  Full
//! protocol state machines (key exchange, user authentication, channel
//! multiplexing) are out of scope for this scaffold and will be added in a
//! future sprint.
//!
//! ## Binary packet format (RFC 4253 §6)
//!
//! ```text
//! uint32  packet_length    — byte count of (padding_length + payload + padding)
//! byte    padding_length   — number of random padding bytes (1 ≤ pad ≤ 255)
//! byte[n] payload          — n = packet_length - padding_length - 1
//! byte[p] random padding   — p = padding_length bytes (ignored by receiver)
//! byte[m] mac              — m bytes; 0 when MAC is not yet negotiated
//! ```
//!
//! The `encode_packet` / `decode_packet` functions implement the framing for
//! the *unencrypted* phase only (before key exchange completes).  MAC is
//! therefore always absent (`m = 0`) in this scaffold.
//!
//! ## Modules / responsibilities
//!
//! | Item | Description |
//! |------|-------------|
//! | [`SSH_VERSION_STRING`] | Client identification string |
//! | [`SshConfig`] | Connection parameters |
//! | [`SshPacket`] | Binary packet: payload + padding |
//! | [`encode_packet`] | Serialise a payload to a framed SSH binary packet |
//! | [`decode_packet`] | Deserialise the first packet from a byte slice |
//! | [`parse_args`] | Parse `ssh [user@]host [:port]` arguments |
//! | [`SshError`] | Typed errors |
//!
//! ## RFC references
//!
//! - RFC 4253 — The Secure Shell (SSH) Transport Layer Protocol

#![no_std]
#![forbid(unsafe_code)]
#![deny(missing_docs)]
#![cfg_attr(
    test,
    allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::unnecessary_wraps,
        clippy::indexing_slicing,
    )
)]

extern crate alloc;

use alloc::{
    string::{String, ToString},
    vec::Vec,
};

use nexacore_types::net::Ipv4Addr;

// =============================================================================
// Constants
// =============================================================================

/// SSH client identification string transmitted immediately after the TCP
/// connection is established (RFC 4253 §4.2).
///
/// The string must be at most 255 characters (including `\r\n`) and must
/// conform to `SSH-protoversion-softwareversion [SP comments] CR LF`.
///
/// # Examples
///
/// ```
/// use nexacore_cmd_ssh::SSH_VERSION_STRING;
///
/// assert!(SSH_VERSION_STRING.starts_with("SSH-2.0-"));
/// assert!(SSH_VERSION_STRING.ends_with("\r\n"));
/// ```
pub const SSH_VERSION_STRING: &str = "SSH-2.0-NexaCoreOS_0.1\r\n";

// =============================================================================
// SshConfig
// =============================================================================

/// Connection parameters for an SSH session.
///
/// # Examples
///
/// ```
/// use nexacore_cmd_ssh::{SshConfig, parse_args};
/// use nexacore_types::net::Ipv4Addr;
///
/// let cfg = parse_args(&["admin", "192.168.1.1"]).unwrap();
/// assert_eq!(cfg.username, "admin");
/// assert_eq!(cfg.host, Ipv4Addr([192, 168, 1, 1]));
/// assert_eq!(cfg.port, 22);
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SshConfig {
    /// Target host `IPv4` address.
    pub host: Ipv4Addr,
    /// Target TCP port (default 22).
    pub port: u16,
    /// Remote username to authenticate as.
    pub username: String,
}

// =============================================================================
// SshPacket
// =============================================================================

/// An SSH-2 binary packet (RFC 4253 §6).
///
/// Contains the payload bytes and the random padding bytes separately so
/// callers can inspect or modify them before framing.
///
/// # Examples
///
/// ```
/// use nexacore_cmd_ssh::{SshPacket, decode_packet, encode_packet};
///
/// let payload = b"hello";
/// let encoded = encode_packet(payload, 8);
/// let (pkt, consumed) = decode_packet(&encoded).unwrap();
/// assert_eq!(pkt.payload, payload);
/// assert_eq!(consumed, encoded.len());
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SshPacket {
    /// The SSH payload bytes.
    pub payload: Vec<u8>,
    /// Random padding bytes appended to the payload.
    pub padding: Vec<u8>,
}

// =============================================================================
// Packet framing
// =============================================================================

/// Encode a payload into an SSH-2 binary packet frame.
///
/// The `block_size` parameter determines the minimum cipher block alignment.
/// For the unencrypted phase the SSH-2 spec mandates a minimum block size of
/// 8 bytes.  The function calculates the minimum padding required such that
/// `1 + payload.len() + padding_length` is a multiple of `block_size`, with
/// at least 4 bytes of padding (RFC 4253 §6).
///
/// The MAC portion is empty because encryption has not yet been negotiated.
///
/// # Panics (compile-time note)
///
/// This function does not panic.  `block_size` is clamped to a minimum of 8
/// to satisfy the RFC minimum.  All arithmetic is performed with saturating or
/// explicitly-sized operations.
///
/// # Examples
///
/// ```
/// use nexacore_cmd_ssh::{decode_packet, encode_packet};
///
/// let payload = b"test payload";
/// let frame = encode_packet(payload, 8);
/// // Frame starts with a 4-byte big-endian packet_length.
/// let plen = u32::from_be_bytes([frame[0], frame[1], frame[2], frame[3]]) as usize;
/// // Total frame = 4 (length field) + plen.
/// assert_eq!(frame.len(), 4 + plen);
/// // Round-trip must recover the payload.
/// let (pkt, _) = decode_packet(&frame).unwrap();
/// assert_eq!(pkt.payload, payload);
/// ```
#[must_use]
pub fn encode_packet(payload: &[u8], block_size: usize) -> Vec<u8> {
    // Enforce RFC 4253 §6: block_size minimum is 8.
    let bsize = if block_size < 8 { 8 } else { block_size };

    // The "packet_length" field covers: padding_length (1) + payload + padding.
    // We must choose padding_length such that 1 + payload.len() + padding_length
    // is a multiple of bsize, with padding_length >= 4.
    //
    // Compute `need = bsize - ((1 + payload.len()) % bsize)` mod bsize.
    // If need < 4, add one extra bsize.
    let raw_need = bsize.saturating_sub((1 + payload.len()) % bsize) % bsize;
    let padding_len = if raw_need < 4 {
        raw_need + bsize
    } else {
        raw_need
    };

    let packet_length = 1 + payload.len() + padding_len;

    // packet_length must fit in u32 (RFC 4253 §6: max 35000 bytes for this scaffold).
    // For the scaffold we accept any length that fits in u32.
    #[allow(clippy::cast_possible_truncation)]
    let plen_u32 = packet_length as u32;
    let plen_be = plen_u32.to_be_bytes();

    // Padding bytes: RFC 4253 §6 says padding SHOULD be filled with random
    // bytes; for the scaffold (pre-encryption) we use zero bytes.
    let padding = alloc::vec![0u8; padding_len];

    let mut frame = Vec::with_capacity(4 + packet_length);
    frame.extend_from_slice(&plen_be);
    // padding_length byte.
    #[allow(clippy::cast_possible_truncation)]
    frame.push(padding_len as u8);
    frame.extend_from_slice(payload);
    frame.extend_from_slice(&padding);
    frame
}

/// Decode the first SSH-2 binary packet from a byte slice.
///
/// Returns `Some((packet, consumed_bytes))` where `consumed_bytes` is the
/// total number of bytes consumed from the front of `data` (including the
/// 4-byte length prefix).
///
/// Returns `None` when:
/// - The buffer has fewer than 5 bytes (too short to hold length + `padding_len`).
/// - The `packet_length` field would require more bytes than are available.
/// - `padding_length` is larger than `packet_length - 1` (malformed).
///
/// # Examples
///
/// ```
/// use nexacore_cmd_ssh::{decode_packet, encode_packet};
///
/// let payload = b"SSH test payload";
/// let frame = encode_packet(payload, 8);
/// let (pkt, consumed) = decode_packet(&frame).unwrap();
/// assert_eq!(pkt.payload, payload);
/// assert_eq!(consumed, frame.len());
/// ```
#[must_use]
pub fn decode_packet(data: &[u8]) -> Option<(SshPacket, usize)> {
    // Need at least 4 bytes for packet_length + 1 byte for padding_length.
    if data.len() < 5 {
        return None;
    }

    // Read the 4-byte big-endian packet_length.
    let len_bytes: [u8; 4] = [*data.first()?, *data.get(1)?, *data.get(2)?, *data.get(3)?];
    let packet_length = u32::from_be_bytes(len_bytes) as usize;

    // Total frame = 4 + packet_length.
    let total = 4 + packet_length;
    if data.len() < total {
        return None;
    }

    // padding_length is the byte immediately after the length field.
    let padding_length = *data.get(4)? as usize;
    if padding_length + 1 > packet_length {
        // Malformed: padding cannot exceed the remaining space.
        return None;
    }

    let payload_length = packet_length - 1 - padding_length;

    // payload starts at offset 5.
    let payload = data.get(5..5 + payload_length)?.to_vec();
    let padding = data
        .get(5 + payload_length..5 + payload_length + padding_length)?
        .to_vec();

    Some((SshPacket { payload, padding }, total))
}

// =============================================================================
// SshError
// =============================================================================

/// Errors returned by [`parse_args`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SshError {
    /// No host was provided.
    MissingHost,
    /// The host address could not be parsed as an `IPv4` address.
    InvalidHost,
    /// The port value could not be parsed as a `u16`.
    InvalidPort,
    /// A required argument was missing after a flag.
    MissingArgument,
    /// An unrecognised flag was encountered.
    UnknownFlag,
}

// =============================================================================
// Argument parsing
// =============================================================================

/// Parse command-line arguments for the `ssh` command.
///
/// Supported argument forms:
///
/// ```text
/// ssh <host>
/// ssh <user> <host>
/// ssh <user> <host> <port>
/// ssh [-p <port>] [<user>@]<host>
/// ```
///
/// The `user@host` shorthand splits on `@`; host without `@` uses the empty
/// string as the username.  Port defaults to `22`.
///
/// # Errors
///
/// Returns an [`SshError`] when arguments cannot be parsed.
///
/// # Examples
///
/// ```
/// use nexacore_cmd_ssh::{SshError, parse_args};
/// use nexacore_types::net::Ipv4Addr;
///
/// let cfg = parse_args(&["admin", "192.168.1.1"]).unwrap();
/// assert_eq!(cfg.username, "admin");
/// assert_eq!(cfg.host, Ipv4Addr([192, 168, 1, 1]));
/// assert_eq!(cfg.port, 22);
///
/// let cfg = parse_args(&["-p", "2222", "192.168.1.1"]).unwrap();
/// assert_eq!(cfg.port, 2222);
///
/// assert_eq!(parse_args(&[]), Err(SshError::MissingHost));
/// ```
pub fn parse_args(args: &[&str]) -> Result<SshConfig, SshError> {
    let mut port: u16 = 22;
    let mut positional: Vec<&str> = Vec::new();
    let mut idx = 0usize;

    while idx < args.len() {
        let arg = args.get(idx).copied().unwrap_or("");
        match arg {
            "-p" => {
                idx += 1;
                let p = args.get(idx).ok_or(SshError::MissingArgument)?;
                port = p.parse::<u16>().map_err(|_| SshError::InvalidPort)?;
            }
            s if s.starts_with('-') => return Err(SshError::UnknownFlag),
            s => positional.push(s),
        }
        idx += 1;
    }

    match positional.len() {
        0 => Err(SshError::MissingHost),
        1 => {
            // Could be "user@host" or just "host".
            let first = positional.first().copied().unwrap_or("");
            let (username, host_str) = parse_user_at_host(first);
            let host = host_str
                .parse::<Ipv4Addr>()
                .map_err(|_| SshError::InvalidHost)?;
            Ok(SshConfig {
                host,
                port,
                username,
            })
        }
        2 => {
            // "user host" — no @ form.
            let username = positional.first().copied().unwrap_or("").to_string();
            let host_str = positional.get(1).copied().unwrap_or("");
            let host = host_str
                .parse::<Ipv4Addr>()
                .map_err(|_| SshError::InvalidHost)?;
            Ok(SshConfig {
                host,
                port,
                username,
            })
        }
        _ => {
            // "user host port" — explicit port as third positional.
            let username = positional.first().copied().unwrap_or("").to_string();
            let host_str = positional.get(1).copied().unwrap_or("");
            let port_str = positional.get(2).copied().unwrap_or("22");
            let host = host_str
                .parse::<Ipv4Addr>()
                .map_err(|_| SshError::InvalidHost)?;
            let explicit_port = port_str.parse::<u16>().map_err(|_| SshError::InvalidPort)?;
            Ok(SshConfig {
                host,
                port: explicit_port,
                username,
            })
        }
    }
}

/// Split an `[user@]host` string into `(username, host)`.
///
/// Returns `("", host)` when no `@` is present.
fn parse_user_at_host(s: &str) -> (String, &str) {
    s.find('@').map_or_else(
        || (String::new(), s),
        |pos| {
            let user = s.get(..pos).unwrap_or("").to_string();
            let host = s.get(pos + 1..).unwrap_or("");
            (user, host)
        },
    )
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use alloc::vec;

    use super::*;

    // -------------------------------------------------------------------------
    // Version string
    // -------------------------------------------------------------------------

    #[test]
    fn version_string_starts_with_ssh_2() {
        assert!(SSH_VERSION_STRING.starts_with("SSH-2.0-"));
    }

    #[test]
    fn version_string_ends_with_crlf() {
        assert!(SSH_VERSION_STRING.ends_with("\r\n"));
    }

    // -------------------------------------------------------------------------
    // Packet framing roundtrip
    // -------------------------------------------------------------------------

    #[test]
    fn encode_decode_roundtrip_short_payload() {
        let payload = b"hello";
        let frame = encode_packet(payload, 8);
        let (pkt, consumed) = decode_packet(&frame).unwrap();
        assert_eq!(pkt.payload, payload);
        assert_eq!(consumed, frame.len());
    }

    #[test]
    fn encode_decode_roundtrip_empty_payload() {
        let frame = encode_packet(&[], 8);
        let (pkt, consumed) = decode_packet(&frame).unwrap();
        assert!(pkt.payload.is_empty());
        assert_eq!(consumed, frame.len());
    }

    #[test]
    fn encode_decode_roundtrip_exact_block_boundary() {
        // 7-byte payload: with 1 byte for padding_length = 8, need 4+ pad bytes.
        let payload = b"1234567";
        let frame = encode_packet(payload, 8);
        let (pkt, _) = decode_packet(&frame).unwrap();
        assert_eq!(pkt.payload, payload);
    }

    #[test]
    fn encode_minimum_padding_at_least_4() {
        // RFC 4253 §6: padding_length must be >= 4.
        let frame = encode_packet(b"abc", 8);
        let padding_len = frame[4] as usize;
        assert!(padding_len >= 4, "padding_len={padding_len}");
    }

    #[test]
    fn decode_too_short_returns_none() {
        let short = [0u8; 3];
        assert!(decode_packet(&short).is_none());
    }

    #[test]
    fn decode_insufficient_data_returns_none() {
        // Claim a large packet_length but provide insufficient bytes.
        let mut fake = vec![0u8, 0u8, 0u8, 100u8, 4u8]; // packet_length=100, padding=4
        fake.resize(20, 0u8); // only 20 bytes total — far less than 4+100
        assert!(decode_packet(&fake).is_none());
    }

    // -------------------------------------------------------------------------
    // Argument parsing
    // -------------------------------------------------------------------------

    #[test]
    fn parse_args_user_and_host() {
        let cfg = parse_args(&["admin", "192.168.1.1"]).unwrap();
        assert_eq!(cfg.username, "admin");
        assert_eq!(cfg.host, Ipv4Addr([192, 168, 1, 1]));
        assert_eq!(cfg.port, 22);
    }

    #[test]
    fn parse_args_port_flag() {
        let cfg = parse_args(&["-p", "2222", "192.168.1.1"]).unwrap();
        assert_eq!(cfg.port, 2222);
    }

    #[test]
    fn parse_args_missing_host() {
        assert_eq!(parse_args(&[]), Err(SshError::MissingHost));
    }

    #[test]
    fn parse_args_unknown_flag() {
        assert_eq!(parse_args(&["-z", "host"]), Err(SshError::UnknownFlag));
    }
}
