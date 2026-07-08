//! # `nexacore-cmd-curl`
//!
//! Minimal HTTP/1.1 client command for NexaCore OS.
//!
//! Provides HTTP request serialisation, response parsing, URL decomposition,
//! and command-line argument parsing.  No I/O is performed; the caller is
//! responsible for the actual TCP connection and byte transfer.
//!
//! ## Modules / responsibilities
//!
//! | Item | Description |
//! |------|-------------|
//! | [`HttpMethod`] | HTTP verbs supported |
//! | [`HttpRequest`] | All fields needed to build a request |
//! | [`HttpResponse`] | Parsed HTTP/1.1 response |
//! | [`CurlConfig`] | Session parameters |
//! | [`build_request`] | Serialise an [`HttpRequest`] to HTTP/1.1 wire bytes |
//! | [`parse_response`] | Parse a raw HTTP/1.1 response byte slice |
//! | [`parse_url`] | Decompose `http://host[:port]/path` into parts |
//! | [`parse_scheme`] | Scheme-aware decomposition (`http`/`https`, default ports) |
//! | [`parse_args`] | Parse `curl [-X method] [-H header] [-d body] <url>` |
//! | [`CurlError`] | Typed errors |
//!
//! HTTPS fetches (WS4-03.8) are handled by the optional `tls` feature, which
//! adds a `tls` module tunnelling requests through a `nexacore-tls` TLS 1.3
//! session. The default build stays dependency-free and bare-metal-buildable.
//!
//! ## RFC references
//!
//! - RFC 7230 — HTTP/1.1: Message Syntax and Routing
//! - RFC 3986 — Uniform Resource Identifier (URI): Generic Syntax

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
    vec::Vec,
};

// =============================================================================
// HttpMethod
// =============================================================================

/// An HTTP request method.
///
/// # Examples
///
/// ```
/// use nexacore_cmd_curl::HttpMethod;
///
/// assert_eq!(HttpMethod::Get.as_str(), "GET");
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum HttpMethod {
    /// HTTP GET.
    #[default]
    Get,
    /// HTTP POST.
    Post,
    /// HTTP HEAD.
    Head,
    /// HTTP PUT.
    Put,
    /// HTTP DELETE.
    Delete,
}

impl HttpMethod {
    /// Return the HTTP method string (e.g. `"GET"`).
    ///
    /// # Examples
    ///
    /// ```
    /// use nexacore_cmd_curl::HttpMethod;
    ///
    /// assert_eq!(HttpMethod::Post.as_str(), "POST");
    /// assert_eq!(HttpMethod::Delete.as_str(), "DELETE");
    /// ```
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Get => "GET",
            Self::Post => "POST",
            Self::Head => "HEAD",
            Self::Put => "PUT",
            Self::Delete => "DELETE",
        }
    }
}

// =============================================================================
// HttpRequest
// =============================================================================

/// All information needed to construct an HTTP/1.1 request.
///
/// # Examples
///
/// ```
/// use nexacore_cmd_curl::{HttpMethod, HttpRequest};
///
/// let req = HttpRequest {
///     method: HttpMethod::Get,
///     host: String::from("example.com"),
///     port: 80,
///     path: String::from("/"),
///     headers: vec![],
///     body: None,
/// };
/// assert_eq!(req.method, HttpMethod::Get);
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpRequest {
    /// HTTP method.
    pub method: HttpMethod,
    /// Target hostname (used for the `Host` header).
    pub host: String,
    /// TCP port number (typically 80 for HTTP, 443 for HTTPS).
    pub port: u16,
    /// Request path (e.g. `"/index.html"`).
    pub path: String,
    /// Additional headers as `(name, value)` pairs.
    pub headers: Vec<(String, String)>,
    /// Optional request body bytes.
    pub body: Option<Vec<u8>>,
}

// =============================================================================
// HttpResponse
// =============================================================================

/// A parsed HTTP/1.1 response.
///
/// # Examples
///
/// ```
/// use nexacore_cmd_curl::HttpResponse;
///
/// let resp = HttpResponse {
///     status_code: 200,
///     status_text: String::from("OK"),
///     headers: vec![],
///     body: vec![],
/// };
/// assert_eq!(resp.status_code, 200);
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpResponse {
    /// HTTP status code (e.g. `200`, `404`).
    pub status_code: u16,
    /// Status reason phrase (e.g. `"OK"`, `"Not Found"`).
    pub status_text: String,
    /// Response headers as `(name, value)` pairs.
    pub headers: Vec<(String, String)>,
    /// Response body bytes.
    pub body: Vec<u8>,
}

// =============================================================================
// CurlConfig
// =============================================================================

/// Session configuration for the `curl` command.
///
/// # Examples
///
/// ```
/// use nexacore_cmd_curl::{CurlConfig, HttpMethod, parse_args};
///
/// let cfg = parse_args(&["http://example.com/"]).unwrap();
/// assert_eq!(cfg.method, HttpMethod::Get);
/// assert_eq!(cfg.url, "http://example.com/");
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CurlConfig {
    /// Target URL.
    pub url: String,
    /// HTTP method.
    pub method: HttpMethod,
    /// Additional request headers.
    pub headers: Vec<(String, String)>,
    /// Optional request body.
    pub body: Option<Vec<u8>>,
}

// =============================================================================
// Request serialisation
// =============================================================================

/// Serialise an [`HttpRequest`] to HTTP/1.1 wire format bytes.
///
/// The generated request always includes:
/// - A request line: `METHOD path HTTP/1.1\r\n`
/// - A `Host` header derived from [`HttpRequest::host`] and [`HttpRequest::port`]
///   (the port is omitted for the scheme defaults 80/443 to match browsers).
/// - A `Content-Length` header when a body is present.
/// - `Connection: close` to signal that the connection will not be reused
///   (this is appropriate for the single-shot CLI use-case).
/// - All caller-supplied extra headers.
/// - An empty line (`\r\n`) terminating the header section.
/// - The body bytes, if any.
///
/// # Examples
///
/// ```
/// use nexacore_cmd_curl::{HttpMethod, HttpRequest, build_request};
///
/// let req = HttpRequest {
///     method: HttpMethod::Get,
///     host: String::from("example.com"),
///     port: 80,
///     path: String::from("/"),
///     headers: vec![],
///     body: None,
/// };
/// let bytes = build_request(&req);
/// let text = core::str::from_utf8(&bytes).unwrap();
/// assert!(text.starts_with("GET / HTTP/1.1\r\n"));
/// assert!(text.contains("Host: example.com\r\n"));
/// assert!(text.contains("Connection: close\r\n"));
/// ```
#[must_use]
pub fn build_request(req: &HttpRequest) -> Vec<u8> {
    let path = if req.path.is_empty() { "/" } else { &req.path };
    let method = req.method.as_str();

    // Host header: omit the port when it is a default (80 for HTTP, 443 for
    // HTTPS) to match browser behaviour.
    let host_header = if req.port == 80 || req.port == 443 {
        req.host.clone()
    } else {
        format!("{}:{}", req.host, req.port)
    };

    let mut out = String::new();
    out.push_str(&format!("{method} {path} HTTP/1.1\r\n"));
    out.push_str(&format!("Host: {host_header}\r\n"));
    out.push_str("Connection: close\r\n");

    // Caller-supplied headers.
    for (name, value) in &req.headers {
        out.push_str(&format!("{name}: {value}\r\n"));
    }

    // Body length header.
    if let Some(body) = &req.body {
        out.push_str(&format!("Content-Length: {}\r\n", body.len()));
    }

    // End of headers.
    out.push_str("\r\n");

    let mut bytes: Vec<u8> = out.into_bytes();
    if let Some(body) = &req.body {
        bytes.extend_from_slice(body);
    }
    bytes
}

// =============================================================================
// Response parsing
// =============================================================================

/// Parse a raw HTTP/1.1 response byte slice.
///
/// Returns `Some(HttpResponse)` when the response contains a valid status line
/// and a complete header section terminated by `\r\n\r\n`.  Everything after
/// the header section is treated as the body.
///
/// Returns `None` when:
/// - The data does not contain `\r\n\r\n` (incomplete response).
/// - The status line is not `HTTP/1.1 <code> <text>`.
/// - The status code is not a valid three-digit decimal number.
///
/// # Examples
///
/// ```
/// use nexacore_cmd_curl::parse_response;
///
/// let raw = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nHello";
/// let resp = parse_response(raw).unwrap();
/// assert_eq!(resp.status_code, 200);
/// assert_eq!(resp.status_text, "OK");
/// assert_eq!(resp.body, b"Hello");
/// ```
#[must_use]
pub fn parse_response(data: &[u8]) -> Option<HttpResponse> {
    // Locate the end of the header section.
    let sep = find_double_crlf(data)?;
    let header_bytes = data.get(..sep)?;
    let body = data.get(sep + 4..).unwrap_or(&[]).to_vec();

    // Convert header block to UTF-8; HTTP headers must be ASCII/Latin-1 but we
    // accept valid UTF-8 as a superset.
    let header_text = core::str::from_utf8(header_bytes).ok()?;
    let mut lines = header_text.split("\r\n");

    // Parse status line: "HTTP/1.1 <code> <text...>"
    let status_line = lines.next()?;
    let mut parts = status_line.splitn(3, ' ');
    let _version = parts.next()?; // "HTTP/1.1"
    let code_str = parts.next()?;
    let reason = parts.next().unwrap_or("").to_string();
    let status_code = code_str.parse::<u16>().ok()?;

    // Parse header fields.
    let mut headers: Vec<(String, String)> = Vec::new();
    for line in lines {
        if line.is_empty() {
            break;
        }
        if let Some(colon) = line.find(':') {
            let name = line.get(..colon).unwrap_or("").trim().to_string();
            let value = line.get(colon + 1..).unwrap_or("").trim().to_string();
            headers.push((name, value));
        }
    }

    Some(HttpResponse {
        status_code,
        status_text: reason,
        headers,
        body,
    })
}

/// Locate the byte offset of `\r\n\r\n` in `data`.
///
/// Returns `None` when the double CRLF is absent (the response is incomplete).
fn find_double_crlf(data: &[u8]) -> Option<usize> {
    // Search for the 4-byte sequence 0x0D 0x0A 0x0D 0x0A.
    let mut i = 0usize;
    while i + 3 < data.len() {
        if data.get(i).copied() == Some(b'\r')
            && data.get(i + 1).copied() == Some(b'\n')
            && data.get(i + 2).copied() == Some(b'\r')
            && data.get(i + 3).copied() == Some(b'\n')
        {
            return Some(i);
        }
        i += 1;
    }
    None
}

// =============================================================================
// URL parsing
// =============================================================================

/// Decompose an HTTP URL into `(host, port, path)`.
///
/// Supports `http://` URLs only.  The port defaults to `80` when not specified.
/// The path defaults to `"/"` when absent.
///
/// Returns `None` when the URL does not start with `http://` or the host
/// portion is empty.
///
/// # Examples
///
/// ```
/// use nexacore_cmd_curl::parse_url;
///
/// assert_eq!(
///     parse_url("http://example.com/index.html"),
///     Some((
///         String::from("example.com"),
///         80u16,
///         String::from("/index.html")
///     ))
/// );
/// assert_eq!(
///     parse_url("http://10.0.0.1:8080/api"),
///     Some((String::from("10.0.0.1"), 8080u16, String::from("/api")))
/// );
/// assert_eq!(parse_url("https://secure.example.com/"), None);
/// ```
#[must_use]
pub fn parse_url(url: &str) -> Option<(String, u16, String)> {
    let rest = url.strip_prefix("http://")?;
    // Find the start of the path (first '/') after the authority.
    let (authority, path) = rest.find('/').map_or((rest, "/"), |pos| {
        let auth = rest.get(..pos).unwrap_or("");
        let p = rest.get(pos..).unwrap_or("/");
        (auth, p)
    });

    if authority.is_empty() {
        return None;
    }

    // Split authority on ':' to separate host from optional port.
    let (host, port) = authority.find(':').map_or_else(
        || (authority.to_string(), 80u16),
        |pos| {
            let h = authority.get(..pos).unwrap_or("").to_string();
            let p_str = authority.get(pos + 1..).unwrap_or("80");
            let p = p_str.parse::<u16>().unwrap_or(80);
            (h, p)
        },
    );

    Some((host, port, path.to_string()))
}

// =============================================================================
// Scheme + scheme-aware URL parsing (WS4-03.8)
// =============================================================================

/// URL scheme understood by the client.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scheme {
    /// Plaintext HTTP (default port 80).
    Http,
    /// HTTP over TLS 1.3 (default port 443); requires the `tls` feature to
    /// actually transport data through the `tls` module.
    Https,
}

impl Scheme {
    /// The default TCP port for this scheme.
    #[must_use]
    pub const fn default_port(self) -> u16 {
        match self {
            Self::Http => 80,
            Self::Https => 443,
        }
    }

    /// Whether this scheme requires a TLS tunnel.
    #[must_use]
    pub const fn is_secure(self) -> bool {
        matches!(self, Self::Https)
    }
}

/// Decompose a `http://` or `https://` URL into `(scheme, host, port, path)`.
///
/// Unlike [`parse_url`] (which is HTTP-only for backward compatibility), this
/// recognises both schemes and applies the scheme's default port when none is
/// given. `https` URLs resolve to port 443 and mark the connection as needing
/// the TLS stack (see the `tls` module).
///
/// # Examples
///
/// ```
/// use nexacore_cmd_curl::{Scheme, parse_scheme};
///
/// let (s, host, port, path) = parse_scheme("https://secure.example.com/x").unwrap();
/// assert_eq!(s, Scheme::Https);
/// assert_eq!(host, "secure.example.com");
/// assert_eq!(port, 443);
/// assert_eq!(path, "/x");
/// ```
#[must_use]
pub fn parse_scheme(url: &str) -> Option<(Scheme, String, u16, String)> {
    let (scheme, rest) = if let Some(r) = url.strip_prefix("https://") {
        (Scheme::Https, r)
    } else if let Some(r) = url.strip_prefix("http://") {
        (Scheme::Http, r)
    } else {
        return None;
    };

    // Split authority from path at the first '/'.
    let (authority, path) = rest.find('/').map_or((rest, "/"), |pos| {
        let auth = rest.get(..pos).unwrap_or("");
        let p = rest.get(pos..).unwrap_or("/");
        (auth, p)
    });
    if authority.is_empty() {
        return None;
    }

    // Split authority into host and optional port.
    let (host, port) = authority.find(':').map_or_else(
        || (authority.to_string(), scheme.default_port()),
        |pos| {
            let h = authority.get(..pos).unwrap_or("").to_string();
            let p_str = authority.get(pos + 1..).unwrap_or("");
            let p = p_str
                .parse::<u16>()
                .unwrap_or_else(|_| scheme.default_port());
            (h, p)
        },
    );
    if host.is_empty() {
        return None;
    }

    Some((scheme, host, port, path.to_string()))
}

// =============================================================================
// CurlError
// =============================================================================

/// Errors returned by [`parse_args`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CurlError {
    /// No URL was provided.
    MissingUrl,
    /// An unrecognised HTTP method was specified via `-X`.
    InvalidMethod,
    /// A `-H <header>` argument did not contain a `:` separator.
    InvalidHeader,
    /// A required argument was missing after a flag.
    MissingArgument,
    /// An unrecognised flag was encountered.
    UnknownFlag,
}

// =============================================================================
// Argument parsing
// =============================================================================

/// Parse command-line arguments for the `curl` command.
///
/// Supported flags:
///
/// | Flag | Argument | Effect |
/// |------|----------|--------|
/// | `-X` | `<METHOD>` | Set HTTP method (default: `GET`) |
/// | `-H` | `<Name: Value>` | Add a request header |
/// | `-d` | `<data>` | Set request body (sets method to POST unless `-X` given) |
///
/// The first non-flag argument is the target URL.
///
/// # Errors
///
/// Returns a [`CurlError`] when arguments cannot be parsed.
///
/// # Examples
///
/// ```
/// use nexacore_cmd_curl::{CurlError, HttpMethod, parse_args};
///
/// let cfg = parse_args(&["http://example.com/"]).unwrap();
/// assert_eq!(cfg.url, "http://example.com/");
/// assert_eq!(cfg.method, HttpMethod::Get);
///
/// let cfg = parse_args(&["-X", "POST", "-d", "hello", "http://example.com/"]).unwrap();
/// assert_eq!(cfg.method, HttpMethod::Post);
/// assert_eq!(cfg.body, Some(b"hello".to_vec()));
///
/// assert_eq!(parse_args(&[]), Err(CurlError::MissingUrl));
/// ```
pub fn parse_args(args: &[&str]) -> Result<CurlConfig, CurlError> {
    let mut url: Option<String> = None;
    let mut method = HttpMethod::Get;
    let mut headers: Vec<(String, String)> = Vec::new();
    let mut body: Option<Vec<u8>> = None;
    let mut explicit_method = false;
    let mut idx = 0usize;

    while idx < args.len() {
        let arg = args.get(idx).copied().unwrap_or("");
        match arg {
            "-X" => {
                idx += 1;
                let m = args.get(idx).ok_or(CurlError::MissingArgument)?;
                method = match *m {
                    "GET" => HttpMethod::Get,
                    "POST" => HttpMethod::Post,
                    "HEAD" => HttpMethod::Head,
                    "PUT" => HttpMethod::Put,
                    "DELETE" => HttpMethod::Delete,
                    _ => return Err(CurlError::InvalidMethod),
                };
                explicit_method = true;
            }
            "-H" => {
                idx += 1;
                let hdr = args.get(idx).ok_or(CurlError::MissingArgument)?;
                let colon = hdr.find(':').ok_or(CurlError::InvalidHeader)?;
                let name = hdr.get(..colon).unwrap_or("").trim().to_string();
                let value = hdr.get(colon + 1..).unwrap_or("").trim().to_string();
                headers.push((name, value));
            }
            "-d" => {
                idx += 1;
                let data = args.get(idx).ok_or(CurlError::MissingArgument)?;
                body = Some(data.as_bytes().to_vec());
                // Implicitly switch to POST when body is set and method was not
                // explicitly specified.
                if !explicit_method {
                    method = HttpMethod::Post;
                }
            }
            s if s.starts_with('-') => return Err(CurlError::UnknownFlag),
            s => url = Some(s.to_string()),
        }
        idx += 1;
    }

    let url = url.ok_or(CurlError::MissingUrl)?;
    Ok(CurlConfig {
        url,
        method,
        headers,
        body,
    })
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use alloc::{string::String, vec};

    use super::*;

    // -------------------------------------------------------------------------
    // URL parsing
    // -------------------------------------------------------------------------

    #[test]
    fn parse_url_simple() {
        assert_eq!(
            parse_url("http://example.com/"),
            Some((String::from("example.com"), 80, String::from("/")))
        );
    }

    #[test]
    fn parse_url_with_port() {
        assert_eq!(
            parse_url("http://10.0.0.1:8080/api/v1"),
            Some((String::from("10.0.0.1"), 8080, String::from("/api/v1")))
        );
    }

    #[test]
    fn parse_url_no_path_defaults_to_slash() {
        let (host, port, path) = parse_url("http://example.com").unwrap();
        assert_eq!(host, "example.com");
        assert_eq!(port, 80);
        assert_eq!(path, "/");
    }

    #[test]
    fn parse_url_https_returns_none() {
        assert!(parse_url("https://example.com/").is_none());
    }

    #[test]
    fn parse_url_empty_host_returns_none() {
        assert!(parse_url("http:///path").is_none());
    }

    // -------------------------------------------------------------------------
    // Request construction
    // -------------------------------------------------------------------------

    #[test]
    fn build_request_get_basic() {
        let req = HttpRequest {
            method: HttpMethod::Get,
            host: String::from("example.com"),
            port: 80,
            path: String::from("/"),
            headers: vec![],
            body: None,
        };
        let bytes = build_request(&req);
        let text = core::str::from_utf8(&bytes).unwrap();
        assert!(text.starts_with("GET / HTTP/1.1\r\n"), "got: {text}");
        assert!(text.contains("Host: example.com\r\n"), "got: {text}");
        assert!(text.contains("Connection: close\r\n"), "got: {text}");
        assert!(text.ends_with("\r\n\r\n"), "got: {text}");
    }

    #[test]
    fn build_request_non_default_port_included_in_host_header() {
        let req = HttpRequest {
            method: HttpMethod::Get,
            host: String::from("example.com"),
            port: 8080,
            path: String::from("/api"),
            headers: vec![],
            body: None,
        };
        let bytes = build_request(&req);
        let text = core::str::from_utf8(&bytes).unwrap();
        assert!(text.contains("Host: example.com:8080\r\n"), "got: {text}");
    }

    #[test]
    fn build_request_with_body_sets_content_length() {
        let req = HttpRequest {
            method: HttpMethod::Post,
            host: String::from("example.com"),
            port: 80,
            path: String::from("/"),
            headers: vec![],
            body: Some(b"hello".to_vec()),
        };
        let bytes = build_request(&req);
        let text = core::str::from_utf8(&bytes).unwrap();
        assert!(text.contains("Content-Length: 5\r\n"), "got: {text}");
        assert!(bytes.ends_with(b"hello"));
    }

    #[test]
    fn build_request_extra_headers_included() {
        let req = HttpRequest {
            method: HttpMethod::Get,
            host: String::from("example.com"),
            port: 80,
            path: String::from("/"),
            headers: vec![(String::from("Accept"), String::from("text/html"))],
            body: None,
        };
        let bytes = build_request(&req);
        let text = core::str::from_utf8(&bytes).unwrap();
        assert!(text.contains("Accept: text/html\r\n"), "got: {text}");
    }

    // -------------------------------------------------------------------------
    // Response parsing
    // -------------------------------------------------------------------------

    #[test]
    fn parse_response_basic_200() {
        let raw = b"HTTP/1.1 200 OK\r\n\r\n";
        let resp = parse_response(raw).unwrap();
        assert_eq!(resp.status_code, 200);
        assert_eq!(resp.status_text, "OK");
        assert!(resp.body.is_empty());
    }

    #[test]
    fn parse_response_with_body() {
        let raw = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nHello";
        let resp = parse_response(raw).unwrap();
        assert_eq!(resp.status_code, 200);
        assert_eq!(resp.body, b"Hello");
    }

    #[test]
    fn parse_response_404() {
        let raw = b"HTTP/1.1 404 Not Found\r\n\r\n";
        let resp = parse_response(raw).unwrap();
        assert_eq!(resp.status_code, 404);
        assert_eq!(resp.status_text, "Not Found");
    }

    #[test]
    fn parse_response_parses_headers() {
        let raw = b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nX-Foo: bar\r\n\r\n";
        let resp = parse_response(raw).unwrap();
        assert_eq!(resp.headers.len(), 2);
        assert_eq!(
            resp.headers[0],
            (String::from("Content-Type"), String::from("text/html"))
        );
    }

    #[test]
    fn parse_response_incomplete_returns_none() {
        let raw = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n";
        assert!(parse_response(raw).is_none());
    }

    #[test]
    fn parse_response_invalid_status_line_returns_none() {
        let raw = b"BOGUS\r\n\r\n";
        assert!(parse_response(raw).is_none());
    }

    // -------------------------------------------------------------------------
    // Argument parsing
    // -------------------------------------------------------------------------

    #[test]
    fn parse_args_simple_url() {
        let cfg = parse_args(&["http://example.com/"]).unwrap();
        assert_eq!(cfg.url, "http://example.com/");
        assert_eq!(cfg.method, HttpMethod::Get);
    }

    #[test]
    fn parse_args_explicit_method() {
        let cfg = parse_args(&["-X", "DELETE", "http://example.com/res"]).unwrap();
        assert_eq!(cfg.method, HttpMethod::Delete);
    }

    #[test]
    fn parse_args_body_sets_post() {
        let cfg = parse_args(&["-d", "data=1", "http://example.com/"]).unwrap();
        assert_eq!(cfg.method, HttpMethod::Post);
        assert_eq!(cfg.body, Some(b"data=1".to_vec()));
    }

    #[test]
    fn parse_args_body_explicit_method_overrides() {
        let cfg = parse_args(&["-X", "PUT", "-d", "x", "http://example.com/"]).unwrap();
        assert_eq!(cfg.method, HttpMethod::Put);
    }

    #[test]
    fn parse_args_header() {
        let cfg = parse_args(&["-H", "Accept: application/json", "http://example.com/"]).unwrap();
        assert_eq!(cfg.headers.len(), 1);
        assert_eq!(cfg.headers[0].0, "Accept");
        assert_eq!(cfg.headers[0].1, "application/json");
    }

    #[test]
    fn parse_args_missing_url() {
        assert_eq!(parse_args(&[]), Err(CurlError::MissingUrl));
    }

    #[test]
    fn parse_args_invalid_method() {
        assert_eq!(
            parse_args(&["-X", "PATCH", "http://example.com/"]),
            Err(CurlError::InvalidMethod)
        );
    }

    #[test]
    fn parse_args_invalid_header_no_colon() {
        assert_eq!(
            parse_args(&["-H", "NoColon", "http://example.com/"]),
            Err(CurlError::InvalidHeader)
        );
    }

    #[test]
    fn parse_args_unknown_flag() {
        assert_eq!(
            parse_args(&["-z", "http://example.com/"]),
            Err(CurlError::UnknownFlag)
        );
    }

    #[test]
    fn parse_scheme_https_defaults_to_443() {
        let (s, host, port, path) = parse_scheme("https://secure.example.com/a").unwrap();
        assert_eq!(s, Scheme::Https);
        assert!(s.is_secure());
        assert_eq!(host, "secure.example.com");
        assert_eq!(port, 443);
        assert_eq!(path, "/a");
    }

    #[test]
    fn parse_scheme_http_defaults_to_80() {
        let (s, host, port, path) = parse_scheme("http://example.com/").unwrap();
        assert_eq!(s, Scheme::Http);
        assert!(!s.is_secure());
        assert_eq!(host, "example.com");
        assert_eq!(port, 80);
        assert_eq!(path, "/");
    }

    #[test]
    fn parse_scheme_explicit_port_overrides_default() {
        let (s, host, port, _path) = parse_scheme("https://h.example:8443/").unwrap();
        assert_eq!(s, Scheme::Https);
        assert_eq!(host, "h.example");
        assert_eq!(port, 8443);
    }

    #[test]
    fn parse_scheme_rejects_unknown_scheme_and_empty_host() {
        assert_eq!(parse_scheme("ftp://example.com/"), None);
        assert_eq!(parse_scheme("https:///path"), None);
    }
}

// =============================================================================
// HTTPS transport over TLS 1.3 (WS4-03.8, `tls` feature)
// =============================================================================

/// HTTPS fetch: tunnel HTTP/1.1 request/response bytes through a TLS 1.3
/// [`nexacore_tls`] client stream.
///
/// This is the integration point between the `curl` command and the TLS stack.
/// The command still builds the request and parses the response with
/// [`build_request`] / [`parse_response`]; this module only changes the
/// *transport* from a raw TCP socket to a TLS session. It is gated behind the
/// `tls` feature so the default build stays dependency-free and
/// bare-metal-buildable.
#[cfg(feature = "tls")]
pub mod tls {
    use alloc::vec::Vec;

    use nexacore_tls::{
        certstore::CertVerifier,
        client::ClientConfig,
        error::TlsResult,
        stream::{RecordTransport, TlsClientStream},
    };

    use super::{HttpRequest, HttpResponse, build_request, parse_response};

    /// An HTTPS connection: a TLS 1.3 client stream that speaks HTTP/1.1.
    pub struct HttpsConnection<T: RecordTransport, V: CertVerifier> {
        stream: TlsClientStream<T, V>,
    }

    impl<T: RecordTransport, V: CertVerifier> HttpsConnection<T, V> {
        /// Perform the TLS handshake over `transport`, authenticating the
        /// server against `config`'s trust store.
        ///
        /// # Errors
        /// Any [`nexacore_tls::error::TlsError`] from the handshake.
        pub fn connect(config: ClientConfig, verifier: V, transport: T) -> TlsResult<Self> {
            let stream = TlsClientStream::connect(config, verifier, transport)?;
            Ok(Self { stream })
        }

        /// The negotiated ALPN protocol, if any.
        #[must_use]
        pub fn alpn_protocol(&self) -> Option<&[u8]> {
            self.stream.alpn_protocol()
        }

        /// Serialise `req` and send it as encrypted application data.
        ///
        /// # Errors
        /// Any [`nexacore_tls::error::TlsError`] from sealing/transport.
        pub fn send_request(&mut self, req: &HttpRequest) -> TlsResult<()> {
            let bytes = build_request(req);
            self.stream.write(&bytes)
        }

        /// Read encrypted application-data records until a full HTTP/1.1
        /// response can be parsed, returning it.
        ///
        /// # Errors
        /// Any [`nexacore_tls::error::TlsError`] from the transport; returns
        /// `Ok(None)` only if the stream yields a parseable-as-empty buffer.
        pub fn recv_response(&mut self) -> TlsResult<Option<HttpResponse>> {
            let mut buf = Vec::new();
            loop {
                let chunk = self.stream.read()?;
                buf.extend_from_slice(&chunk);
                if let Some(resp) = parse_response(&buf) {
                    return Ok(Some(resp));
                }
            }
        }
    }
}

#[cfg(all(test, feature = "tls"))]
mod tls_tests {
    extern crate std;

    use alloc::{string::String, vec, vec::Vec};
    use std::sync::mpsc::{Receiver, Sender};

    use nexacore_crypto::signing::NexaCoreSigningKey;
    use nexacore_tls::{
        certstore::{CertStore, NexaCertTbs, NexaCertVerifier, encode_nexacert},
        client::ClientConfig,
        error::TlsResult,
        server::ServerConfig,
        stream::RecordTransport,
    };

    use super::{HttpMethod, HttpRequest, tls::HttpsConnection};

    struct ChannelTransport {
        tx: Sender<Vec<u8>>,
        rx: Receiver<Vec<u8>>,
    }
    impl RecordTransport for ChannelTransport {
        fn send(&mut self, record: &[u8]) -> TlsResult<()> {
            self.tx
                .send(record.to_vec())
                .map_err(|_| nexacore_tls::error::TlsError::Closed)
        }
        fn recv_record(&mut self) -> TlsResult<Vec<u8>> {
            self.rx
                .recv()
                .map_err(|_| nexacore_tls::error::TlsError::Closed)
        }
    }

    fn pki() -> (nexacore_tls::auth::ServerCredentials, CertStore) {
        let root = NexaCoreSigningKey::from_bytes([1u8; 32]);
        let leaf = NexaCoreSigningKey::from_bytes([2u8; 32]);
        let tbs = NexaCertTbs {
            subject: b"api.nexacore.lan".to_vec(),
            issuer: b"Root".to_vec(),
            subject_spki: leaf.verifying_key().as_bytes(),
            not_before: 0,
            not_after: 1_000_000,
            is_ca: false,
            path_len: 0,
        }
        .encode()
        .unwrap();
        let sig = root.sign(&tbs).to_bytes();
        let cert = encode_nexacert(&tbs, &sig).unwrap();
        let creds = nexacore_tls::auth::ServerCredentials {
            signing_key: leaf,
            chain: vec![cert],
        };
        let mut store = CertStore::new();
        store.add_anchor(b"Root".to_vec(), root.verifying_key().as_bytes());
        (creds, store)
    }

    #[test]
    fn curl_fetches_over_a_real_tls_tunnel() {
        let (creds, store) = pki();
        let (c2s_tx, c2s_rx) = std::sync::mpsc::channel();
        let (s2c_tx, s2c_rx) = std::sync::mpsc::channel();
        let client_transport = ChannelTransport {
            tx: c2s_tx,
            rx: s2c_rx,
        };
        let server_transport = ChannelTransport {
            tx: s2c_tx,
            rx: c2s_rx,
        };

        // TLS server thread: complete the handshake, read the HTTP request,
        // reply with a canned HTTP/1.1 response.
        let server = std::thread::spawn(move || {
            use nexacore_tls::stream::TlsServerStream;
            let mut srv = TlsServerStream::accept(
                ServerConfig {
                    credentials: creds,
                    alpn: vec![b"http/1.1".to_vec()],
                },
                server_transport,
            )
            .unwrap();
            let req = srv.read().unwrap();
            let text = core::str::from_utf8(&req).unwrap();
            assert!(text.starts_with("GET /index.html HTTP/1.1\r\n"));
            assert!(text.contains("Host: api.nexacore.lan\r\n"));
            srv.write(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello")
                .unwrap();
        });

        let cfg = ClientConfig {
            server_name: Some(b"api.nexacore.lan".to_vec()),
            alpn: vec![b"http/1.1".to_vec()],
            store,
            now: 500,
        };
        let mut https = HttpsConnection::connect(cfg, NexaCertVerifier, client_transport).unwrap();
        assert_eq!(https.alpn_protocol(), Some(b"http/1.1".as_slice()));

        let req = HttpRequest {
            method: HttpMethod::Get,
            host: String::from("api.nexacore.lan"),
            port: 443,
            path: String::from("/index.html"),
            headers: vec![],
            body: None,
        };
        https.send_request(&req).unwrap();
        let resp = https.recv_response().unwrap().unwrap();
        assert_eq!(resp.status_code, 200);
        assert_eq!(resp.body, b"hello");

        server.join().unwrap();
    }
}
