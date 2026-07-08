//! TLS 1.3 handshake messages (RFC 8446 § 4).
//!
//! Encode/decode for the messages this stack drives: `ClientHello`,
//! `ServerHello`, `EncryptedExtensions`, `Certificate`, `CertificateVerify`,
//! and `Finished`, plus the extensions needed to negotiate
//! `TLS_CHACHA20_POLY1305_SHA256` over `x25519` with `ed25519` authentication
//! (`supported_versions`, `supported_groups`, `signature_algorithms`,
//! `key_share`, `server_name`, and ALPN).
//!
//! Every message is framed as `HandshakeType(1) || length(3) || body`. The raw
//! framed bytes are what feed the transcript hash, so `encode` returns the full
//! framed message and the state machines append it verbatim.

use alloc::vec::Vec;

use crate::{
    alpn,
    codec::{Reader, Writer},
    error::{TlsError, TlsResult},
    params::{GROUP_X25519, TLS13_VERSION},
};

/// Handshake message type (RFC 8446 § 4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum HandshakeType {
    /// `ClientHello`.
    ClientHello = 1,
    /// `ServerHello`.
    ServerHello = 2,
    /// `EncryptedExtensions`.
    EncryptedExtensions = 8,
    /// `Certificate`.
    Certificate = 11,
    /// `CertificateVerify`.
    CertificateVerify = 15,
    /// `Finished`.
    Finished = 20,
}

impl HandshakeType {
    /// Decode a handshake-type byte.
    ///
    /// # Errors
    /// [`TlsError::BadValue`] for an unsupported type.
    pub const fn from_byte(b: u8) -> TlsResult<Self> {
        Ok(match b {
            1 => Self::ClientHello,
            2 => Self::ServerHello,
            8 => Self::EncryptedExtensions,
            11 => Self::Certificate,
            15 => Self::CertificateVerify,
            20 => Self::Finished,
            _ => return Err(TlsError::BadValue),
        })
    }
}

// Extension code points (RFC 8446 § 4.2).
const EXT_SERVER_NAME: u16 = 0;
const EXT_SUPPORTED_GROUPS: u16 = 10;
const EXT_SIGNATURE_ALGORITHMS: u16 = 13;
const EXT_ALPN: u16 = 16;
const EXT_SUPPORTED_VERSIONS: u16 = 43;
const EXT_KEY_SHARE: u16 = 51;

const LEGACY_VERSION: u16 = 0x0303;

/// Wrap a handshake body in its `type || length(3) || body` frame.
///
/// # Errors
/// [`TlsError::BadValue`] if the body exceeds `2^24 - 1` bytes.
pub fn encode_handshake(msg_type: HandshakeType, body: &[u8]) -> TlsResult<Vec<u8>> {
    let mut w = Writer::new();
    w.u8(msg_type as u8);
    w.vec_u24(body)?;
    Ok(w.into_bytes())
}

/// Split a buffer of one or more concatenated framed handshake messages into
/// `(type, body)` pairs. Used for the server's coalesced encrypted flight.
///
/// # Errors
/// [`TlsError::Decode`] on truncation or [`TlsError::BadValue`] on an unknown
/// handshake type.
pub fn split_messages(buf: &[u8]) -> TlsResult<Vec<(HandshakeType, Vec<u8>)>> {
    let mut r = Reader::new(buf);
    let mut out = Vec::new();
    while !r.is_empty() {
        let ty = HandshakeType::from_byte(r.u8()?)?;
        let body = r.vec_u24()?;
        out.push((ty, body.to_vec()));
    }
    Ok(out)
}

/// A minimally-parsed `ClientHello` carrying just the fields this stack acts on.
#[derive(Debug, Clone)]
pub struct ClientHello {
    /// 32-byte client random.
    pub random: [u8; 32],
    /// Legacy session id (echoed by the server for middlebox compatibility).
    pub legacy_session_id: Vec<u8>,
    /// Offered cipher-suite code points.
    pub cipher_suites: Vec<u16>,
    /// Offered `key_share` group.
    pub key_share_group: u16,
    /// The `key_share` public key bytes for `key_share_group`.
    pub key_share: Vec<u8>,
    /// Offered protocol versions (`supported_versions`).
    pub supported_versions: Vec<u16>,
    /// Offered named groups.
    pub supported_groups: Vec<u16>,
    /// Offered signature schemes.
    pub signature_algorithms: Vec<u16>,
    /// Optional SNI host name.
    pub server_name: Option<Vec<u8>>,
    /// Offered ALPN protocol names (may be empty).
    pub alpn: Vec<Vec<u8>>,
}

impl ClientHello {
    /// Encode the full framed `ClientHello` handshake message.
    ///
    /// # Errors
    /// [`TlsError::BadValue`] on any length overflow.
    pub fn encode(&self) -> TlsResult<Vec<u8>> {
        let mut b = Writer::new();
        b.u16(LEGACY_VERSION);
        b.bytes(&self.random);
        b.vec_u8(&self.legacy_session_id)?;

        // cipher_suites: u16-length-prefixed list of u16 code points.
        let mut cs = Writer::new();
        for c in &self.cipher_suites {
            cs.u16(*c);
        }
        b.vec_u16(&cs.into_bytes())?;

        // legacy_compression_methods = { null }.
        b.vec_u8(&[0u8])?;

        // extensions.
        let mut ext = Writer::new();
        write_supported_versions_client(&mut ext, &self.supported_versions)?;
        write_u16_list_ext(&mut ext, EXT_SUPPORTED_GROUPS, &self.supported_groups)?;
        write_u16_list_ext(
            &mut ext,
            EXT_SIGNATURE_ALGORITHMS,
            &self.signature_algorithms,
        )?;
        write_key_share_client(&mut ext, self.key_share_group, &self.key_share)?;
        if let Some(name) = &self.server_name {
            write_server_name(&mut ext, name)?;
        }
        if !self.alpn.is_empty() {
            let refs: Vec<&[u8]> = self.alpn.iter().map(Vec::as_slice).collect();
            let body = alpn::encode_protocol_list(&refs)?;
            write_ext(&mut ext, EXT_ALPN, &body)?;
        }
        b.vec_u16(&ext.into_bytes())?;

        encode_handshake(HandshakeType::ClientHello, &b.into_bytes())
    }

    /// Parse a `ClientHello` handshake body (no outer frame).
    ///
    /// # Errors
    /// [`TlsError::Decode`] on truncation.
    pub fn parse(body: &[u8]) -> TlsResult<Self> {
        let mut r = Reader::new(body);
        let _legacy = r.u16()?;
        let random: [u8; 32] = r.take(32)?.try_into().map_err(|_| TlsError::Decode)?;
        let legacy_session_id = r.vec_u8()?.to_vec();

        let cs_body = r.vec_u16()?;
        let cipher_suites = parse_u16_list(cs_body)?;

        let _compression = r.vec_u8()?;

        let ext_body = r.vec_u16()?;
        let mut ch = Self {
            random,
            legacy_session_id,
            cipher_suites,
            key_share_group: 0,
            key_share: Vec::new(),
            supported_versions: Vec::new(),
            supported_groups: Vec::new(),
            signature_algorithms: Vec::new(),
            server_name: None,
            alpn: Vec::new(),
        };
        parse_client_extensions(ext_body, &mut ch)?;
        Ok(ch)
    }
}

/// A minimally-parsed `ServerHello`.
#[derive(Debug, Clone)]
pub struct ServerHello {
    /// 32-byte server random.
    pub random: [u8; 32],
    /// Echoed legacy session id.
    pub legacy_session_id: Vec<u8>,
    /// Selected cipher suite.
    pub cipher_suite: u16,
    /// Selected version (`supported_versions`), expected `0x0304`.
    pub selected_version: u16,
    /// Selected `key_share` group.
    pub key_share_group: u16,
    /// Server `key_share` public key bytes.
    pub key_share: Vec<u8>,
}

impl ServerHello {
    /// Encode the full framed `ServerHello`.
    ///
    /// # Errors
    /// [`TlsError::BadValue`] on any length overflow.
    pub fn encode(&self) -> TlsResult<Vec<u8>> {
        let mut b = Writer::new();
        b.u16(LEGACY_VERSION);
        b.bytes(&self.random);
        b.vec_u8(&self.legacy_session_id)?;
        b.u16(self.cipher_suite);
        b.u8(0); // legacy_compression_method

        let mut ext = Writer::new();
        // supported_versions (ServerHello form): the single selected version.
        {
            let mut ed = Writer::new();
            ed.u16(self.selected_version);
            write_ext(&mut ext, EXT_SUPPORTED_VERSIONS, &ed.into_bytes())?;
        }
        write_key_share_server(&mut ext, self.key_share_group, &self.key_share)?;
        b.vec_u16(&ext.into_bytes())?;

        encode_handshake(HandshakeType::ServerHello, &b.into_bytes())
    }

    /// Parse a `ServerHello` handshake body.
    ///
    /// # Errors
    /// [`TlsError::Decode`] on truncation, [`TlsError::BadValue`] on a bad
    /// field.
    pub fn parse(body: &[u8]) -> TlsResult<Self> {
        let mut r = Reader::new(body);
        let _legacy = r.u16()?;
        let random: [u8; 32] = r.take(32)?.try_into().map_err(|_| TlsError::Decode)?;
        let legacy_session_id = r.vec_u8()?.to_vec();
        let cipher_suite = r.u16()?;
        let _compression = r.u8()?;

        let ext_body = r.vec_u16()?;
        let mut selected_version = 0u16;
        let mut key_share_group = 0u16;
        let mut key_share = Vec::new();
        let mut er = Reader::new(ext_body);
        while !er.is_empty() {
            let ext_type = er.u16()?;
            let ext_data = er.vec_u16()?;
            match ext_type {
                EXT_SUPPORTED_VERSIONS => {
                    let mut d = Reader::new(ext_data);
                    selected_version = d.u16()?;
                }
                EXT_KEY_SHARE => {
                    let mut d = Reader::new(ext_data);
                    key_share_group = d.u16()?;
                    key_share = d.vec_u16()?.to_vec();
                }
                _ => {}
            }
        }
        Ok(Self {
            random,
            legacy_session_id,
            cipher_suite,
            selected_version,
            key_share_group,
            key_share,
        })
    }
}

/// Encode `EncryptedExtensions` carrying an optional negotiated ALPN protocol.
///
/// # Errors
/// [`TlsError::BadValue`] on length overflow.
pub fn encode_encrypted_extensions(alpn_selected: Option<&[u8]>) -> TlsResult<Vec<u8>> {
    let mut ext = Writer::new();
    if let Some(proto) = alpn_selected {
        let body = alpn::encode_protocol_list(&[proto])?;
        write_ext(&mut ext, EXT_ALPN, &body)?;
    }
    let mut b = Writer::new();
    b.vec_u16(&ext.into_bytes())?;
    encode_handshake(HandshakeType::EncryptedExtensions, &b.into_bytes())
}

/// Parse `EncryptedExtensions`, returning the negotiated ALPN protocol if any.
///
/// # Errors
/// [`TlsError::Decode`] on truncation.
pub fn parse_encrypted_extensions(body: &[u8]) -> TlsResult<Option<Vec<u8>>> {
    let mut r = Reader::new(body);
    let ext_body = r.vec_u16()?;
    let mut er = Reader::new(ext_body);
    let mut alpn_selected = None;
    while !er.is_empty() {
        let ext_type = er.u16()?;
        let ext_data = er.vec_u16()?;
        if ext_type == EXT_ALPN {
            let names = alpn::parse_protocol_list(ext_data)?;
            alpn_selected = names.into_iter().next();
        }
    }
    Ok(alpn_selected)
}

/// Encode a `Certificate` message from a chain of DER/opaque certificate
/// entries (leaf first). Each entry carries an empty extension block.
///
/// # Errors
/// [`TlsError::BadValue`] on length overflow.
pub fn encode_certificate(chain: &[Vec<u8>]) -> TlsResult<Vec<u8>> {
    let mut b = Writer::new();
    b.vec_u8(&[])?; // certificate_request_context = empty
    let mut list = Writer::new();
    for cert in chain {
        list.vec_u24(cert)?; // cert_data
        list.vec_u16(&[])?; // per-cert extensions = empty
    }
    b.vec_u24(&list.into_bytes())?;
    encode_handshake(HandshakeType::Certificate, &b.into_bytes())
}

/// Parse a `Certificate` message into its ordered chain of entry bytes.
///
/// # Errors
/// [`TlsError::Decode`] on truncation.
pub fn parse_certificate(body: &[u8]) -> TlsResult<Vec<Vec<u8>>> {
    let mut r = Reader::new(body);
    let _ctx = r.vec_u8()?;
    let list = r.vec_u24()?;
    let mut lr = Reader::new(list);
    let mut chain = Vec::new();
    while !lr.is_empty() {
        let cert = lr.vec_u24()?;
        let _exts = lr.vec_u16()?;
        chain.push(cert.to_vec());
    }
    Ok(chain)
}

/// Encode a `CertificateVerify` message.
///
/// # Errors
/// [`TlsError::BadValue`] on length overflow.
pub fn encode_certificate_verify(scheme: u16, signature: &[u8]) -> TlsResult<Vec<u8>> {
    let mut b = Writer::new();
    b.u16(scheme);
    b.vec_u16(signature)?;
    encode_handshake(HandshakeType::CertificateVerify, &b.into_bytes())
}

/// Parse a `CertificateVerify` into `(scheme, signature)`.
///
/// # Errors
/// [`TlsError::Decode`] on truncation.
pub fn parse_certificate_verify(body: &[u8]) -> TlsResult<(u16, Vec<u8>)> {
    let mut r = Reader::new(body);
    let scheme = r.u16()?;
    let sig = r.vec_u16()?.to_vec();
    Ok((scheme, sig))
}

/// Encode a `Finished` message from its verify-data.
///
/// # Errors
/// [`TlsError::BadValue`] on length overflow.
pub fn encode_finished(verify_data: &[u8]) -> TlsResult<Vec<u8>> {
    encode_handshake(HandshakeType::Finished, verify_data)
}

// ---- extension writers ------------------------------------------------------

fn write_ext(w: &mut Writer, ext_type: u16, ext_data: &[u8]) -> TlsResult<()> {
    w.u16(ext_type);
    w.vec_u16(ext_data)
}

fn write_u16_list_ext(w: &mut Writer, ext_type: u16, values: &[u16]) -> TlsResult<()> {
    let mut list = Writer::new();
    for v in values {
        list.u16(*v);
    }
    let mut ed = Writer::new();
    ed.vec_u16(&list.into_bytes())?;
    write_ext(w, ext_type, &ed.into_bytes())
}

fn write_supported_versions_client(w: &mut Writer, versions: &[u16]) -> TlsResult<()> {
    let mut list = Writer::new();
    for v in versions {
        list.u16(*v);
    }
    let mut ed = Writer::new();
    ed.vec_u8(&list.into_bytes())?;
    write_ext(w, EXT_SUPPORTED_VERSIONS, &ed.into_bytes())
}

fn write_key_share_client(w: &mut Writer, group: u16, key: &[u8]) -> TlsResult<()> {
    let mut entry = Writer::new();
    entry.u16(group);
    entry.vec_u16(key)?;
    let mut ed = Writer::new();
    ed.vec_u16(&entry.into_bytes())?; // client_shares
    write_ext(w, EXT_KEY_SHARE, &ed.into_bytes())
}

fn write_key_share_server(w: &mut Writer, group: u16, key: &[u8]) -> TlsResult<()> {
    let mut ed = Writer::new();
    ed.u16(group);
    ed.vec_u16(key)?;
    write_ext(w, EXT_KEY_SHARE, &ed.into_bytes())
}

fn write_server_name(w: &mut Writer, host: &[u8]) -> TlsResult<()> {
    let mut entry = Writer::new();
    entry.u8(0); // name_type = host_name
    entry.vec_u16(host)?;
    let mut ed = Writer::new();
    ed.vec_u16(&entry.into_bytes())?; // ServerNameList
    write_ext(w, EXT_SERVER_NAME, &ed.into_bytes())
}

// ---- extension parsers ------------------------------------------------------

fn parse_u16_list(body: &[u8]) -> TlsResult<Vec<u16>> {
    let mut r = Reader::new(body);
    let mut out = Vec::new();
    while !r.is_empty() {
        out.push(r.u16()?);
    }
    Ok(out)
}

fn parse_client_extensions(ext_body: &[u8], ch: &mut ClientHello) -> TlsResult<()> {
    let mut er = Reader::new(ext_body);
    while !er.is_empty() {
        let ext_type = er.u16()?;
        let ext_data = er.vec_u16()?;
        match ext_type {
            EXT_SUPPORTED_VERSIONS => {
                let mut d = Reader::new(ext_data);
                let list = d.vec_u8()?;
                ch.supported_versions = parse_u16_list(list)?;
            }
            EXT_SUPPORTED_GROUPS => {
                let mut d = Reader::new(ext_data);
                let list = d.vec_u16()?;
                ch.supported_groups = parse_u16_list(list)?;
            }
            EXT_SIGNATURE_ALGORITHMS => {
                let mut d = Reader::new(ext_data);
                let list = d.vec_u16()?;
                ch.signature_algorithms = parse_u16_list(list)?;
            }
            EXT_KEY_SHARE => {
                let mut d = Reader::new(ext_data);
                let shares = d.vec_u16()?;
                let mut sr = Reader::new(shares);
                // Take the first (and, for us, only) share whose group is x25519.
                while !sr.is_empty() {
                    let group = sr.u16()?;
                    let key = sr.vec_u16()?;
                    if group == GROUP_X25519 && ch.key_share.is_empty() {
                        ch.key_share_group = group;
                        ch.key_share = key.to_vec();
                    }
                }
            }
            EXT_SERVER_NAME => {
                let mut d = Reader::new(ext_data);
                let list = d.vec_u16()?;
                let mut lr = Reader::new(list);
                let name_type = lr.u8()?;
                let host = lr.vec_u16()?;
                if name_type == 0 {
                    ch.server_name = Some(host.to_vec());
                }
            }
            EXT_ALPN => {
                ch.alpn = alpn::parse_protocol_list(ext_data)?;
            }
            _ => {}
        }
    }
    // The version marker for TLS 1.3 must be present.
    if !ch.supported_versions.contains(&TLS13_VERSION) {
        return Err(TlsError::NoCommonParameters);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::params::{CIPHER_CHACHA20_POLY1305_SHA256, SIG_ED25519};

    fn sample_client_hello() -> ClientHello {
        ClientHello {
            random: [0xAB; 32],
            legacy_session_id: alloc::vec![1, 2, 3, 4],
            cipher_suites: alloc::vec![CIPHER_CHACHA20_POLY1305_SHA256],
            key_share_group: GROUP_X25519,
            key_share: alloc::vec![0x07; 32],
            supported_versions: alloc::vec![TLS13_VERSION],
            supported_groups: alloc::vec![GROUP_X25519],
            signature_algorithms: alloc::vec![SIG_ED25519],
            server_name: Some(b"example.com".to_vec()),
            alpn: alloc::vec![b"h2".to_vec(), b"http/1.1".to_vec()],
        }
    }

    fn body_of(framed: &[u8]) -> Vec<u8> {
        let msgs = split_messages(framed).unwrap();
        msgs.into_iter().next().unwrap().1
    }

    #[test]
    fn client_hello_round_trips() {
        let ch = sample_client_hello();
        let framed = ch.encode().unwrap();
        let msgs = split_messages(&framed).unwrap();
        assert_eq!(msgs.len(), 1);
        assert_eq!(msgs[0].0, HandshakeType::ClientHello);

        let parsed = ClientHello::parse(&msgs[0].1).unwrap();
        assert_eq!(parsed.random, ch.random);
        assert_eq!(parsed.legacy_session_id, ch.legacy_session_id);
        assert_eq!(parsed.cipher_suites, ch.cipher_suites);
        assert_eq!(parsed.key_share_group, GROUP_X25519);
        assert_eq!(parsed.key_share, ch.key_share);
        assert_eq!(parsed.supported_versions, ch.supported_versions);
        assert_eq!(parsed.supported_groups, ch.supported_groups);
        assert_eq!(parsed.signature_algorithms, ch.signature_algorithms);
        assert_eq!(
            parsed.server_name.as_deref(),
            Some(b"example.com".as_slice())
        );
        assert_eq!(parsed.alpn, ch.alpn);
    }

    #[test]
    fn server_hello_round_trips() {
        let sh = ServerHello {
            random: [0xCD; 32],
            legacy_session_id: alloc::vec![9, 9],
            cipher_suite: CIPHER_CHACHA20_POLY1305_SHA256,
            selected_version: TLS13_VERSION,
            key_share_group: GROUP_X25519,
            key_share: alloc::vec![0x33; 32],
        };
        let framed = sh.encode().unwrap();
        let parsed = ServerHello::parse(&body_of(&framed)).unwrap();
        assert_eq!(parsed.random, sh.random);
        assert_eq!(parsed.cipher_suite, CIPHER_CHACHA20_POLY1305_SHA256);
        assert_eq!(parsed.selected_version, TLS13_VERSION);
        assert_eq!(parsed.key_share_group, GROUP_X25519);
        assert_eq!(parsed.key_share, sh.key_share);
    }

    #[test]
    fn encrypted_extensions_alpn_round_trips() {
        let ee = encode_encrypted_extensions(Some(b"h2")).unwrap();
        let alpn = parse_encrypted_extensions(&body_of(&ee)).unwrap();
        assert_eq!(alpn.as_deref(), Some(b"h2".as_slice()));

        let ee_none = encode_encrypted_extensions(None).unwrap();
        assert_eq!(
            parse_encrypted_extensions(&body_of(&ee_none)).unwrap(),
            None
        );
    }

    #[test]
    fn certificate_chain_round_trips() {
        let chain = alloc::vec![alloc::vec![1u8, 2, 3], alloc::vec![4u8, 5]];
        let msg = encode_certificate(&chain).unwrap();
        let parsed = parse_certificate(&body_of(&msg)).unwrap();
        assert_eq!(parsed, chain);
    }

    #[test]
    fn certificate_verify_round_trips() {
        let sig = alloc::vec![0x55u8; 64];
        let msg = encode_certificate_verify(SIG_ED25519, &sig).unwrap();
        let (scheme, out) = parse_certificate_verify(&body_of(&msg)).unwrap();
        assert_eq!(scheme, SIG_ED25519);
        assert_eq!(out, sig);
    }

    #[test]
    fn client_hello_without_tls13_marker_is_rejected() {
        let mut ch = sample_client_hello();
        ch.supported_versions = alloc::vec![0x0303];
        let framed = ch.encode().unwrap();
        let body = body_of(&framed);
        assert_eq!(
            ClientHello::parse(&body).err(),
            Some(TlsError::NoCommonParameters)
        );
    }
}
