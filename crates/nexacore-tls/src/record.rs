//! TLS 1.3 record layer (RFC 8446 § 5).
//!
//! Two concerns live here:
//!
//! * **Framing** — every record on the wire is `ContentType(1) ||
//!   legacy_version(2) || length(2) || fragment`. Plaintext records carry the
//!   real content type (used for `ClientHello`/`ServerHello` and the dummy
//!   `change_cipher_spec`); protected records are always stamped
//!   `application_data`.
//! * **Protection** — once traffic keys exist, a record is sealed with
//!   `TLS_CHACHA20_POLY1305_SHA256`. The plaintext is wrapped in a
//!   `TLSInnerPlaintext` (`content || real_type || zero-padding`), the
//!   per-record nonce is `static_iv XOR seq_be`, and the 5-byte ciphertext
//!   header is the AEAD associated data.
//!
//! The maximum plaintext fragment is `2^14` bytes. The sequence number is a
//! monotone `u64` that resets on a key change and is never allowed to wrap
//! (fail-closed via [`TlsError::SequenceOverflow`]).

use alloc::vec::Vec;

use nexacore_crypto::aead::{
    self, NONCE_LEN, NexaCoreAeadKey, NexaCoreCiphertext, NexaCoreNonce, TAG_LEN,
};

use crate::error::{TlsError, TlsResult};

/// TLS 1.3 legacy record version, pinned to `TLS 1.2` (0x0303) on the wire for
/// middlebox compatibility. The real version lives in the `supported_versions`
/// extension.
pub const LEGACY_RECORD_VERSION: [u8; 2] = [0x03, 0x03];

/// Maximum plaintext fragment length (`2^14`).
pub const MAX_FRAGMENT: usize = 1 << 14;

/// Fixed record header length in bytes.
pub const HEADER_LEN: usize = 5;

/// TLS record content type (RFC 8446 § 5.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ContentType {
    /// Legacy `change_cipher_spec` — a single-byte dummy in TLS 1.3.
    ChangeCipherSpec = 20,
    /// Alert protocol.
    Alert = 21,
    /// Handshake protocol.
    Handshake = 22,
    /// Application data (and every protected record).
    ApplicationData = 23,
}

impl ContentType {
    /// Decode a content-type byte.
    ///
    /// # Errors
    /// Returns [`TlsError::BadValue`] for the reserved `invalid(0)` code or any
    /// unassigned value.
    pub const fn from_byte(b: u8) -> TlsResult<Self> {
        Ok(match b {
            20 => Self::ChangeCipherSpec,
            21 => Self::Alert,
            22 => Self::Handshake,
            23 => Self::ApplicationData,
            _ => return Err(TlsError::BadValue),
        })
    }
}

/// Serialize a plaintext record: `type || 0x0303 || len || fragment`.
///
/// # Errors
/// Returns [`TlsError::BadValue`] if `fragment` exceeds [`MAX_FRAGMENT`].
pub fn encode_plaintext(content_type: ContentType, fragment: &[u8]) -> TlsResult<Vec<u8>> {
    if fragment.len() > MAX_FRAGMENT {
        return Err(TlsError::BadValue);
    }
    let len = u16::try_from(fragment.len()).map_err(|_| TlsError::BadValue)?;
    let mut out = Vec::with_capacity(HEADER_LEN + fragment.len());
    out.push(content_type as u8);
    out.extend_from_slice(&LEGACY_RECORD_VERSION);
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(fragment);
    Ok(out)
}

/// A parsed record header plus the byte offset where the next record begins.
#[derive(Debug, Clone, Copy)]
pub struct RecordHeader {
    /// The record's content type.
    pub content_type: ContentType,
    /// The fragment length declared in the header.
    pub length: usize,
}

/// Parse the 5-byte header of the record at the front of `buf`.
///
/// Does not consume the fragment; the caller checks `buf` holds
/// `HEADER_LEN + length` bytes before slicing the body out.
///
/// # Errors
/// Returns [`TlsError::Decode`] if fewer than [`HEADER_LEN`] bytes are present,
/// [`TlsError::BadValue`] for an unknown content type, or [`TlsError::BadValue`]
/// if the declared length exceeds the ciphertext cap.
pub fn parse_header(buf: &[u8]) -> TlsResult<RecordHeader> {
    let header = buf.get(..HEADER_LEN).ok_or(TlsError::Decode)?;
    let (ct, rest) = header.split_first().ok_or(TlsError::Decode)?;
    let content_type = ContentType::from_byte(*ct)?;
    // rest = version(2) || length(2)
    let len_bytes = rest.get(2..4).ok_or(TlsError::Decode)?;
    let len = match len_bytes {
        [hi, lo] => (usize::from(*hi) << 8) | usize::from(*lo),
        _ => return Err(TlsError::Decode),
    };
    // Protected records add a content-type byte plus the AEAD tag, so the
    // ceiling is one fragment plus 256 bytes of slack (RFC 8446 § 5.2).
    if len > MAX_FRAGMENT + 256 {
        return Err(TlsError::BadValue);
    }
    Ok(RecordHeader {
        content_type,
        length: len,
    })
}

/// Split the single record at the front of `buf` into its content type, its
/// 5-byte header (the AEAD associated data for protected records), and its
/// body. Requires `buf` to contain the whole record.
///
/// # Errors
/// Returns [`TlsError::Decode`] if the buffer is shorter than the declared
/// record, or [`TlsError::BadValue`] on a bad header.
pub fn read_record(buf: &[u8]) -> TlsResult<(ContentType, &[u8], &[u8])> {
    let hdr = parse_header(buf)?;
    let header = buf.get(..HEADER_LEN).ok_or(TlsError::Decode)?;
    let end = HEADER_LEN.checked_add(hdr.length).ok_or(TlsError::Decode)?;
    let body = buf.get(HEADER_LEN..end).ok_or(TlsError::Decode)?;
    Ok((hdr.content_type, header, body))
}

/// Per-direction AEAD state: the traffic key, static IV, and record sequence
/// counter for one endpoint's write (equivalently the peer's read) direction.
pub struct DirectionKeys {
    key: NexaCoreAeadKey,
    iv: [u8; NONCE_LEN],
    seq: u64,
}

impl DirectionKeys {
    /// Construct direction keys from a derived traffic key and IV.
    #[must_use]
    pub fn new(key: NexaCoreAeadKey, iv: [u8; NONCE_LEN]) -> Self {
        Self { key, iv, seq: 0 }
    }

    /// Compute the nonce for the current sequence number: the 64-bit sequence
    /// number, right-aligned in a 12-byte field, combined via XOR with the IV.
    fn current_nonce(&self) -> NexaCoreNonce {
        let mut nonce = self.iv;
        let seq_be = self.seq.to_be_bytes();
        // XOR the 8 sequence bytes into the low 8 bytes of the 12-byte IV,
        // leaving the leading 4 bytes untouched (no slice indexing).
        nonce
            .iter_mut()
            .skip(NONCE_LEN - 8)
            .zip(seq_be.iter())
            .for_each(|(n, s)| *n ^= *s);
        NexaCoreNonce::from_bytes(nonce)
    }

    /// Advance the sequence counter, failing closed on overflow.
    fn bump_seq(&mut self) -> TlsResult<()> {
        self.seq = self.seq.checked_add(1).ok_or(TlsError::SequenceOverflow)?;
        Ok(())
    }

    /// Seal a plaintext fragment of `content_type` into a full protected
    /// record (header + ciphertext + tag), stamped `application_data`.
    ///
    /// # Errors
    /// Returns [`TlsError::BadValue`] if the resulting record is too large,
    /// [`TlsError::SequenceOverflow`] on counter exhaustion, or
    /// [`TlsError::Crypto`] on an AEAD failure.
    pub fn seal(&mut self, content_type: ContentType, plaintext: &[u8]) -> TlsResult<Vec<u8>> {
        // TLSInnerPlaintext = content || type (no zero padding is added; it is
        // optional and interoperable to omit it).
        let inner_len = plaintext.len() + 1;
        let cipher_len = inner_len + TAG_LEN;
        if cipher_len > MAX_FRAGMENT + 256 {
            return Err(TlsError::BadValue);
        }
        let cipher_len_u16 = u16::try_from(cipher_len).map_err(|_| TlsError::BadValue)?;

        // AAD = the ciphertext record header (type=application_data).
        let mut aad = Vec::with_capacity(HEADER_LEN);
        aad.push(ContentType::ApplicationData as u8);
        aad.extend_from_slice(&LEGACY_RECORD_VERSION);
        aad.extend_from_slice(&cipher_len_u16.to_be_bytes());

        let mut inner = Vec::with_capacity(inner_len);
        inner.extend_from_slice(plaintext);
        inner.push(content_type as u8);

        let nonce = self.current_nonce();
        let ct = aead::seal(&self.key, &nonce, &aad, &inner).map_err(|_| TlsError::Crypto)?;
        self.bump_seq()?;

        let mut out = Vec::with_capacity(HEADER_LEN + ct.as_bytes().len());
        out.extend_from_slice(&aad);
        out.extend_from_slice(ct.as_bytes());
        Ok(out)
    }

    /// Open a protected record: verify + decrypt, strip the padding, and
    /// recover the real content type. `header` is the 5 header bytes, `body`
    /// the ciphertext+tag.
    ///
    /// # Errors
    /// Returns [`TlsError::DecryptFailed`] on any authentication failure,
    /// [`TlsError::Decode`] if the inner plaintext is empty (no type byte),
    /// [`TlsError::BadValue`] for an unknown recovered content type, or
    /// [`TlsError::SequenceOverflow`] on counter exhaustion.
    pub fn open(&mut self, header: &[u8], body: &[u8]) -> TlsResult<(ContentType, Vec<u8>)> {
        let aad = header.get(..HEADER_LEN).ok_or(TlsError::Decode)?;
        let nonce = self.current_nonce();
        let ct = NexaCoreCiphertext::from_bytes(body.to_vec());
        let mut inner =
            aead::open(&self.key, &nonce, aad, &ct).map_err(|_| TlsError::DecryptFailed)?;
        self.bump_seq()?;

        // Strip optional trailing zero padding; the last non-zero byte is the
        // real content type.
        while inner.last() == Some(&0) {
            inner.pop();
        }
        let type_byte = inner.pop().ok_or(TlsError::Decode)?;
        let content_type = ContentType::from_byte(type_byte)?;
        Ok((content_type, inner))
    }

    /// The current sequence number (records sealed/opened so far).
    #[must_use]
    pub const fn sequence(&self) -> u64 {
        self.seq
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn keys() -> (DirectionKeys, DirectionKeys) {
        let key = NexaCoreAeadKey::from_bytes([0x11u8; 32]);
        let key2 = NexaCoreAeadKey::from_bytes([0x11u8; 32]);
        let iv = [0x22u8; NONCE_LEN];
        (DirectionKeys::new(key, iv), DirectionKeys::new(key2, iv))
    }

    #[test]
    fn seal_then_open_round_trips_with_content_type() {
        let (mut w, mut r) = keys();
        let record = w.seal(ContentType::Handshake, b"hello tls").unwrap();
        let (ct, header, body) = read_record(&record).unwrap();
        assert_eq!(ct, ContentType::ApplicationData); // stamped on the wire
        let (inner_ct, pt) = r.open(header, body).unwrap();
        assert_eq!(inner_ct, ContentType::Handshake);
        assert_eq!(pt, b"hello tls");
    }

    #[test]
    fn sequence_advances_on_each_record() {
        let (mut w, mut r) = keys();
        let r0 = w.seal(ContentType::ApplicationData, b"a").unwrap();
        let r1 = w.seal(ContentType::ApplicationData, b"b").unwrap();
        assert_eq!(w.sequence(), 2);
        // Records use different nonces, so they differ even for similar input.
        assert_ne!(r0, r1);
        let (_c, h0, b0) = read_record(&r0).unwrap();
        let (_c, h1, b1) = read_record(&r1).unwrap();
        assert_eq!(r.open(h0, b0).unwrap().1, b"a");
        assert_eq!(r.open(h1, b1).unwrap().1, b"b");
    }

    #[test]
    fn tampered_ciphertext_fails_to_open() {
        let (mut w, mut r) = keys();
        let mut record = w.seal(ContentType::ApplicationData, b"secret").unwrap();
        // Flip a byte in the ciphertext body.
        let last = record.len() - 1;
        record[last] ^= 0x01;
        let (_ct, header, body) = read_record(&record).unwrap();
        assert_eq!(r.open(header, body), Err(TlsError::DecryptFailed));
    }

    #[test]
    fn wrong_key_fails_to_open() {
        let mut w = DirectionKeys::new(NexaCoreAeadKey::from_bytes([1u8; 32]), [0u8; NONCE_LEN]);
        let mut r = DirectionKeys::new(NexaCoreAeadKey::from_bytes([2u8; 32]), [0u8; NONCE_LEN]);
        let record = w.seal(ContentType::ApplicationData, b"x").unwrap();
        let (_ct, header, body) = read_record(&record).unwrap();
        assert_eq!(r.open(header, body), Err(TlsError::DecryptFailed));
    }

    #[test]
    fn desynced_sequence_breaks_aead() {
        // If the reader's sequence gets ahead, the nonce differs and open fails.
        let (mut w, mut r) = keys();
        let record = w.seal(ContentType::ApplicationData, b"one").unwrap();
        // Advance the reader without opening the first record.
        let _ = r.seal(ContentType::ApplicationData, b"noise");
        let (_ct, header, body) = read_record(&record).unwrap();
        assert_eq!(r.open(header, body), Err(TlsError::DecryptFailed));
    }

    #[test]
    fn header_parse_rejects_short_and_bad_type() {
        assert_eq!(parse_header(&[23, 3, 3]).err(), Some(TlsError::Decode));
        assert_eq!(
            parse_header(&[99, 3, 3, 0, 1]).err(),
            Some(TlsError::BadValue)
        );
    }

    #[test]
    fn plaintext_encode_round_trips() {
        let rec = encode_plaintext(ContentType::Handshake, b"abc").unwrap();
        let (ct, _h, body) = read_record(&rec).unwrap();
        assert_eq!(ct, ContentType::Handshake);
        assert_eq!(body, b"abc");
    }
}
