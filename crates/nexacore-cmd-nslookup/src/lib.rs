//! # `nexacore-cmd-nslookup`
//!
//! DNS lookup command for NexaCore OS.
//!
//! Provides type definitions, result formatting, and argument parsing for the
//! `nslookup` utility.  No I/O or DNS wire protocol is implemented here; the
//! caller performs the actual DNS resolution and passes results to the
//! formatting helpers.
//!
//! ## Modules / responsibilities
//!
//! | Item | Description |
//! |------|-------------|
//! | [`NslookupConfig`] | Query parameters |
//! | [`QueryType`] | DNS record types supported |
//! | [`format_result`] | Format a DNS answer for display |
//! | [`parse_args`] | Parse `nslookup [-type=<t>] [-server=<ip>] <host>` |
//! | [`NslookupError`] | Typed errors from [`parse_args`] |
//!
//! ## RFC references
//!
//! - RFC 1035 — Domain Names — Implementation and Specification

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
    format,
    string::{String, ToString},
};

use nexacore_types::net::Ipv4Addr;

// =============================================================================
// QueryType
// =============================================================================

/// The DNS record type to query.
///
/// # Examples
///
/// ```
/// use nexacore_cmd_nslookup::QueryType;
///
/// assert_eq!(QueryType::default(), QueryType::A);
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum QueryType {
    /// `IPv4` host address record.
    #[default]
    A,
    /// `IPv6` host address record.
    Aaaa,
    /// Mail exchange record.
    Mx,
    /// Reverse DNS (pointer) record.
    Ptr,
    /// Text record.
    Txt,
}

impl QueryType {
    /// Return the conventional DNS type string for display.
    ///
    /// # Examples
    ///
    /// ```
    /// use nexacore_cmd_nslookup::QueryType;
    ///
    /// assert_eq!(QueryType::Mx.as_str(), "MX");
    /// ```
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::A => "A",
            Self::Aaaa => "AAAA",
            Self::Mx => "MX",
            Self::Ptr => "PTR",
            Self::Txt => "TXT",
        }
    }
}

// =============================================================================
// NslookupConfig
// =============================================================================

/// Configuration for an `nslookup` query.
///
/// # Examples
///
/// ```
/// use nexacore_cmd_nslookup::{NslookupConfig, QueryType, parse_args};
/// use nexacore_types::net::Ipv4Addr;
///
/// let cfg = parse_args(&["example.com"]).unwrap();
/// assert_eq!(cfg.hostname, "example.com");
/// assert_eq!(cfg.query_type, QueryType::A);
/// assert!(cfg.server.is_none());
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NslookupConfig {
    /// Hostname or IP address to look up.
    pub hostname: String,
    /// DNS record type to query.
    pub query_type: QueryType,
    /// Optional DNS server to query (uses system default when `None`).
    pub server: Option<Ipv4Addr>,
}

// =============================================================================
// Output formatting
// =============================================================================

/// Format the result of a DNS lookup for display.
///
/// Produces output of the form:
///
/// ```text
/// Server:   8.8.8.8
/// Address:  8.8.8.8#53
///
/// Name:     example.com
/// Address:  93.184.216.34
/// (Query time: 12 ms)
/// ```
///
/// # Examples
///
/// ```
/// use nexacore_cmd_nslookup::format_result;
/// use nexacore_types::net::Ipv4Addr;
///
/// let out = format_result(
///     "example.com",
///     &[Ipv4Addr([93, 184, 216, 34])],
///     Ipv4Addr([8, 8, 8, 8]),
///     12,
/// );
/// assert!(out.contains("example.com"));
/// assert!(out.contains("93.184.216.34"));
/// assert!(out.contains("8.8.8.8"));
/// ```
#[must_use]
pub fn format_result(
    hostname: &str,
    addresses: &[Ipv4Addr],
    server: Ipv4Addr,
    time_ms: u64,
) -> String {
    let mut out = format!("Server:   {server}\nAddress:  {server}#53\n\nName:     {hostname}\n");
    for addr in addresses {
        out.push_str(&format!("Address:  {addr}\n"));
    }
    out.push_str(&format!("(Query time: {time_ms} ms)"));
    out
}

// =============================================================================
// NslookupError
// =============================================================================

/// Errors returned by [`parse_args`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NslookupError {
    /// No hostname was provided.
    MissingHostname,
    /// The `-server=<ip>` value could not be parsed as an `IPv4` address.
    InvalidServer,
    /// The `-type=<t>` value is not a recognised DNS record type.
    InvalidType,
    /// An unrecognised flag was encountered.
    UnknownFlag,
}

// =============================================================================
// Argument parsing
// =============================================================================

/// Parse command-line arguments for the `nslookup` command.
///
/// Supported flags (in any order before the hostname):
///
/// | Flag | Effect |
/// |------|--------|
/// | `-type=<t>` | DNS record type (`A`, `AAAA`, `MX`, `PTR`, `TXT`) |
/// | `-server=<ip>` | `IPv4` address of the DNS server to query |
///
/// The first non-flag argument is the hostname to look up.
///
/// # Errors
///
/// Returns a [`NslookupError`] variant when any argument is invalid.
///
/// # Examples
///
/// ```
/// use nexacore_cmd_nslookup::{NslookupError, QueryType, parse_args};
/// use nexacore_types::net::Ipv4Addr;
///
/// let cfg = parse_args(&["example.com"]).unwrap();
/// assert_eq!(cfg.hostname, "example.com");
/// assert_eq!(cfg.query_type, QueryType::A);
///
/// let cfg = parse_args(&["-type=MX", "-server=8.8.8.8", "example.com"]).unwrap();
/// assert_eq!(cfg.query_type, QueryType::Mx);
/// assert_eq!(cfg.server, Some(Ipv4Addr([8, 8, 8, 8])));
///
/// assert_eq!(parse_args(&[]), Err(NslookupError::MissingHostname));
/// ```
pub fn parse_args(args: &[&str]) -> Result<NslookupConfig, NslookupError> {
    let mut cfg = NslookupConfig {
        hostname: String::new(),
        query_type: QueryType::A,
        server: None,
    };
    let mut found_host = false;

    for &arg in args {
        if arg.starts_with("-type=") {
            let t = arg.get(6..).unwrap_or("");
            cfg.query_type = match t {
                "A" => QueryType::A,
                "AAAA" => QueryType::Aaaa,
                "MX" => QueryType::Mx,
                "PTR" => QueryType::Ptr,
                "TXT" => QueryType::Txt,
                _ => return Err(NslookupError::InvalidType),
            };
        } else if arg.starts_with("-server=") {
            let ip_str = arg.get(8..).unwrap_or("");
            let ip = ip_str
                .parse::<Ipv4Addr>()
                .map_err(|_| NslookupError::InvalidServer)?;
            cfg.server = Some(ip);
        } else if arg.starts_with('-') {
            return Err(NslookupError::UnknownFlag);
        } else {
            cfg.hostname = arg.to_string();
            found_host = true;
        }
    }

    if !found_host {
        return Err(NslookupError::MissingHostname);
    }
    Ok(cfg)
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use alloc::vec;

    use super::*;

    // -------------------------------------------------------------------------
    // QueryType helpers
    // -------------------------------------------------------------------------

    #[test]
    fn query_type_as_str() {
        assert_eq!(QueryType::A.as_str(), "A");
        assert_eq!(QueryType::Aaaa.as_str(), "AAAA");
        assert_eq!(QueryType::Mx.as_str(), "MX");
        assert_eq!(QueryType::Ptr.as_str(), "PTR");
        assert_eq!(QueryType::Txt.as_str(), "TXT");
    }

    #[test]
    fn query_type_default_is_a() {
        assert_eq!(QueryType::default(), QueryType::A);
    }

    // -------------------------------------------------------------------------
    // Formatting
    // -------------------------------------------------------------------------

    #[test]
    fn format_result_contains_server_and_hostname() {
        let out = format_result("example.com", &[], Ipv4Addr([8, 8, 8, 8]), 10);
        assert!(out.contains("8.8.8.8"), "got: {out}");
        assert!(out.contains("example.com"), "got: {out}");
    }

    #[test]
    fn format_result_shows_addresses() {
        let addrs = vec![Ipv4Addr([93, 184, 216, 34])];
        let out = format_result("example.com", &addrs, Ipv4Addr([8, 8, 8, 8]), 5);
        assert!(out.contains("93.184.216.34"), "got: {out}");
    }

    #[test]
    fn format_result_shows_query_time() {
        let out = format_result("host", &[], Ipv4Addr([1, 1, 1, 1]), 99);
        assert!(out.contains("99 ms"), "got: {out}");
    }

    // -------------------------------------------------------------------------
    // Argument parsing
    // -------------------------------------------------------------------------

    #[test]
    fn parse_args_simple_hostname() {
        let cfg = parse_args(&["example.com"]).unwrap();
        assert_eq!(cfg.hostname, "example.com");
        assert_eq!(cfg.query_type, QueryType::A);
        assert!(cfg.server.is_none());
    }

    #[test]
    fn parse_args_type_mx() {
        let cfg = parse_args(&["-type=MX", "example.com"]).unwrap();
        assert_eq!(cfg.query_type, QueryType::Mx);
    }

    #[test]
    fn parse_args_server() {
        let cfg = parse_args(&["-server=8.8.8.8", "example.com"]).unwrap();
        assert_eq!(cfg.server, Some(Ipv4Addr([8, 8, 8, 8])));
    }

    #[test]
    fn parse_args_missing_hostname() {
        assert_eq!(parse_args(&[]), Err(NslookupError::MissingHostname));
    }

    #[test]
    fn parse_args_invalid_server() {
        assert_eq!(
            parse_args(&["-server=not-an-ip", "host"]),
            Err(NslookupError::InvalidServer)
        );
    }

    #[test]
    fn parse_args_invalid_type() {
        assert_eq!(
            parse_args(&["-type=BOGUS", "host"]),
            Err(NslookupError::InvalidType)
        );
    }
}
