//! ALPN — Application-Layer Protocol Negotiation (RFC 7301).
//!
//! The client advertises an ordered `ProtocolNameList` in a
//! `application_layer_protocol_negotiation(16)` extension; the server picks one
//! and echoes it in `EncryptedExtensions`. Selection here follows the server's
//! preference order (the robust choice — the server, not the client, decides),
//! and is fail-closed: if a server is configured with an ALPN list and shares
//! no protocol with the client, the handshake aborts with
//! `no_application_protocol`.

use alloc::vec::Vec;

use crate::{
    codec::{Reader, Writer},
    error::{TlsError, TlsResult},
};

/// Encode a `ProtocolNameList`: a `u16`-length-prefixed sequence of
/// `u8`-length-prefixed protocol names.
///
/// # Errors
/// [`TlsError::BadValue`] if any name is empty or longer than 255 bytes, or if
/// the overall list overflows its `u16` length.
pub fn encode_protocol_list(protocols: &[&[u8]]) -> TlsResult<Vec<u8>> {
    let mut inner = Writer::new();
    for p in protocols {
        if p.is_empty() {
            return Err(TlsError::BadValue);
        }
        inner.vec_u8(p)?;
    }
    let mut out = Writer::new();
    out.vec_u16(&inner.into_bytes())?;
    Ok(out.into_bytes())
}

/// Parse a `ProtocolNameList` into its constituent names.
///
/// # Errors
/// [`TlsError::Decode`] on truncation, or [`TlsError::BadValue`] if a name is
/// empty.
pub fn parse_protocol_list(body: &[u8]) -> TlsResult<Vec<Vec<u8>>> {
    let mut outer = Reader::new(body);
    let list = outer.vec_u16()?;
    if !outer.is_empty() {
        return Err(TlsError::Decode);
    }
    let mut names = Vec::new();
    let mut r = Reader::new(list);
    while !r.is_empty() {
        let name = r.vec_u8()?;
        if name.is_empty() {
            return Err(TlsError::BadValue);
        }
        names.push(name.to_vec());
    }
    Ok(names)
}

/// Server-side ALPN selection: return the first entry of `server_prefs` that
/// the client also offered.
///
/// Returns `Ok(None)` when the server expresses no preference (`server_prefs`
/// empty) — ALPN is then simply not negotiated. Returns the agreed protocol
/// otherwise.
///
/// # Errors
/// [`TlsError::PeerAlert`] with `no_application_protocol` when the server has
/// preferences but none intersect the client's offer (fail-closed).
pub fn select<'a>(
    server_prefs: &'a [&'a [u8]],
    client_offer: &[Vec<u8>],
) -> TlsResult<Option<&'a [u8]>> {
    if server_prefs.is_empty() {
        return Ok(None);
    }
    for pref in server_prefs {
        if client_offer.iter().any(|c| c.as_slice() == *pref) {
            return Ok(Some(pref));
        }
    }
    Err(TlsError::PeerAlert(
        crate::alert::AlertDescription::NoApplicationProtocol,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn protocol_list_round_trips() {
        let encoded = encode_protocol_list(&[b"h2", b"http/1.1"]).unwrap();
        let names = parse_protocol_list(&encoded).unwrap();
        assert_eq!(names, alloc::vec![b"h2".to_vec(), b"http/1.1".to_vec()]);
    }

    #[test]
    fn server_preference_wins() {
        // Server prefers h2; client offers both — h2 chosen even though it is
        // second in the client list.
        let client = alloc::vec![b"http/1.1".to_vec(), b"h2".to_vec()];
        let chosen = select(&[b"h2", b"http/1.1"], &client).unwrap();
        assert_eq!(chosen, Some(b"h2".as_slice()));
    }

    #[test]
    fn no_server_preference_means_unnegotiated() {
        let client = alloc::vec![b"h2".to_vec()];
        assert_eq!(select(&[], &client).unwrap(), None);
    }

    #[test]
    fn no_overlap_fails_closed() {
        let client = alloc::vec![b"spdy/3".to_vec()];
        let err = select(&[b"h2"], &client).unwrap_err();
        assert_eq!(
            err,
            TlsError::PeerAlert(crate::alert::AlertDescription::NoApplicationProtocol)
        );
    }

    #[test]
    fn empty_protocol_name_rejected() {
        assert!(encode_protocol_list(&[b""]).is_err());
    }
}
