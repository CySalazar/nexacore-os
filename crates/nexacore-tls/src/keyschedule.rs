//! TLS 1.3 key schedule (RFC 8446 § 7.1) for `TLS_CHACHA20_POLY1305_SHA256`.
//!
//! The schedule is a chain of `HKDF-Extract` / `Derive-Secret` steps that
//! turns the `(EC)DHE` shared secret and the running handshake transcript into
//! traffic secrets, from which per-record AEAD keys and IVs are expanded.
//!
//! ```text
//!            0
//!            |
//!  PSK=0 -> Extract  = Early Secret
//!            |
//!         Derive-Secret(., "derived", "")
//!            |
//!  ECDHE ->  Extract  = Handshake Secret --> c/s hs traffic secrets
//!            |
//!         Derive-Secret(., "derived", "")
//!            |
//!  0     ->  Extract  = Master Secret     --> c/s ap traffic secrets
//! ```
//!
//! Every derivation is deterministic, so a client and a server that agree on
//! the `ECDHE` secret and the transcript necessarily agree on every key. That
//! property is what the end-to-end handshake tests exploit.
//!
//! `Finished` verify-data is `HMAC-Hash(finished_key, Transcript-Hash)`. Since
//! `HKDF-Extract(salt, ikm) == HMAC-Hash(salt, ikm)` (RFC 5869 § 2.2), the MAC
//! is computed as [`nexacore_crypto::kdf::hkdf_extract`] with the finished key
//! as the salt — no separate HMAC primitive is required.

use alloc::vec::Vec;

use nexacore_crypto::{
    aead::{KEY_LEN, NONCE_LEN, NexaCoreAeadKey},
    hash::{HASH_LEN, NexaCoreHash, Sha256H},
    kdf::{hkdf_expand, hkdf_extract},
};

use crate::{
    error::{TlsError, TlsResult},
    record::DirectionKeys,
};

/// A 32-byte traffic secret; the source of a direction's AEAD key + IV and its
/// `Finished` key.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct TrafficSecret(pub [u8; HASH_LEN]);

impl core::fmt::Debug for TrafficSecret {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // Never leak key material into logs.
        f.write_str("TrafficSecret(<redacted>)")
    }
}

impl TrafficSecret {
    /// Expand the ChaCha20 traffic key from this secret
    /// (`HKDF-Expand-Label(secret, "key", "", 32)`).
    ///
    /// # Errors
    /// Returns [`TlsError::Crypto`] on HKDF failure.
    pub fn aead_key(&self) -> TlsResult<NexaCoreAeadKey> {
        let bytes = hkdf_expand_label(&self.0, b"key", b"", KEY_LEN)?;
        let arr: [u8; KEY_LEN] = bytes.as_slice().try_into().map_err(|_| TlsError::Crypto)?;
        Ok(NexaCoreAeadKey::from_bytes(arr))
    }

    /// Expand the record IV from this secret
    /// (`HKDF-Expand-Label(secret, "iv", "", 12)`).
    ///
    /// # Errors
    /// Returns [`TlsError::Crypto`] on HKDF failure.
    pub fn iv(&self) -> TlsResult<[u8; NONCE_LEN]> {
        let bytes = hkdf_expand_label(&self.0, b"iv", b"", NONCE_LEN)?;
        bytes.as_slice().try_into().map_err(|_| TlsError::Crypto)
    }

    /// Build the per-direction record protection state (fresh sequence 0).
    ///
    /// # Errors
    /// Returns [`TlsError::Crypto`] on HKDF failure.
    pub fn direction_keys(&self) -> TlsResult<DirectionKeys> {
        Ok(DirectionKeys::new(self.aead_key()?, self.iv()?))
    }

    /// Expand the `Finished` key
    /// (`HKDF-Expand-Label(secret, "finished", "", 32)`).
    ///
    /// # Errors
    /// Returns [`TlsError::Crypto`] on HKDF failure.
    pub fn finished_key(&self) -> TlsResult<[u8; HASH_LEN]> {
        let bytes = hkdf_expand_label(&self.0, b"finished", b"", HASH_LEN)?;
        bytes.as_slice().try_into().map_err(|_| TlsError::Crypto)
    }

    /// Compute the `Finished` verify-data over a transcript hash:
    /// `HMAC-SHA256(finished_key, transcript_hash)`.
    ///
    /// # Errors
    /// Returns [`TlsError::Crypto`] on HKDF failure.
    pub fn verify_data(&self, transcript_hash: &[u8; HASH_LEN]) -> TlsResult<[u8; HASH_LEN]> {
        let fk = self.finished_key()?;
        Ok(hkdf_extract(&fk, transcript_hash))
    }
}

/// `HKDF-Expand-Label(Secret, Label, Context, Length)` (RFC 8446 § 7.1).
///
/// Builds the `HkdfLabel` structure — `uint16 length`, a length-prefixed
/// `"tls13 " || label`, and a length-prefixed `context` — and runs
/// `HKDF-Expand`.
///
/// # Errors
/// Returns [`TlsError::BadValue`] if the label or context lengths overflow
/// their single-byte length prefixes, or [`TlsError::Crypto`] on HKDF failure.
pub fn hkdf_expand_label(
    secret: &[u8; HASH_LEN],
    label: &[u8],
    context: &[u8],
    length: usize,
) -> TlsResult<Vec<u8>> {
    let length_u16 = u16::try_from(length).map_err(|_| TlsError::BadValue)?;
    // full_label = "tls13 " + label, must fit 7..=255.
    let full_label_len = 6usize.checked_add(label.len()).ok_or(TlsError::BadValue)?;
    let full_label_len_u8 = u8::try_from(full_label_len).map_err(|_| TlsError::BadValue)?;
    let context_len_u8 = u8::try_from(context.len()).map_err(|_| TlsError::BadValue)?;

    let mut info = Vec::with_capacity(2 + 1 + full_label_len + 1 + context.len());
    info.extend_from_slice(&length_u16.to_be_bytes());
    info.push(full_label_len_u8);
    info.extend_from_slice(b"tls13 ");
    info.extend_from_slice(label);
    info.push(context_len_u8);
    info.extend_from_slice(context);

    hkdf_expand(secret, &info, length).map_err(|_| TlsError::Crypto)
}

/// `Derive-Secret(Secret, Label, Messages)`
/// = `HKDF-Expand-Label(Secret, Label, Transcript-Hash(Messages), Hash.length)`.
///
/// # Errors
/// Returns [`TlsError::Crypto`] on HKDF failure.
pub fn derive_secret(
    secret: &[u8; HASH_LEN],
    label: &[u8],
    transcript_hash: &[u8; HASH_LEN],
) -> TlsResult<[u8; HASH_LEN]> {
    let bytes = hkdf_expand_label(secret, label, transcript_hash, HASH_LEN)?;
    bytes.as_slice().try_into().map_err(|_| TlsError::Crypto)
}

/// The SHA-256 transcript hash of the concatenated handshake messages so far.
#[must_use]
pub fn transcript_hash(messages: &[u8]) -> [u8; HASH_LEN] {
    Sha256H::hash(messages)
}

/// The full TLS 1.3 key schedule for one connection. Advanced in three stages
/// (early → handshake → master) as the handshake progresses.
pub struct KeySchedule {
    /// The secret carried forward to the next `Extract` after `Derive-Secret(.,
    /// "derived", "")` is applied.
    current: [u8; HASH_LEN],
}

impl KeySchedule {
    /// Stage 0: compute the Early Secret with no PSK
    /// (`HKDF-Extract(0, 0)`), ready to absorb the ECDHE secret next.
    #[must_use]
    pub fn new() -> Self {
        let zero = [0u8; HASH_LEN];
        let early = hkdf_extract(&zero, &zero);
        Self { current: early }
    }

    /// The Early Secret (stage 0), exposed for testing against known vectors.
    #[must_use]
    pub const fn early_secret(&self) -> [u8; HASH_LEN] {
        self.current
    }

    /// Stage 1: mix in the ECDHE shared secret to produce the Handshake Secret
    /// and the client/server handshake traffic secrets bound to the
    /// `ClientHello..ServerHello` transcript.
    ///
    /// Returns `(client_hs_traffic, server_hs_traffic)`.
    ///
    /// # Errors
    /// Returns [`TlsError::Crypto`] on HKDF failure.
    pub fn derive_handshake_secrets(
        &mut self,
        ecdhe: &[u8; 32],
        transcript_hash: &[u8; HASH_LEN],
    ) -> TlsResult<(TrafficSecret, TrafficSecret)> {
        let derived = derive_secret(&self.current, b"derived", &transcript_hash_empty())?;
        let handshake = hkdf_extract(&derived, ecdhe);
        let client = derive_secret(&handshake, b"c hs traffic", transcript_hash)?;
        let server = derive_secret(&handshake, b"s hs traffic", transcript_hash)?;
        self.current = handshake;
        Ok((TrafficSecret(client), TrafficSecret(server)))
    }

    /// Stage 2: derive the Master Secret and the client/server application
    /// traffic secrets bound to the `ClientHello..server Finished` transcript.
    ///
    /// Returns `(client_ap_traffic, server_ap_traffic)`.
    ///
    /// # Errors
    /// Returns [`TlsError::Crypto`] on HKDF failure.
    pub fn derive_application_secrets(
        &mut self,
        transcript_hash: &[u8; HASH_LEN],
    ) -> TlsResult<(TrafficSecret, TrafficSecret)> {
        let derived = derive_secret(&self.current, b"derived", &transcript_hash_empty())?;
        let zero = [0u8; HASH_LEN];
        let master = hkdf_extract(&derived, &zero);
        let client = derive_secret(&master, b"c ap traffic", transcript_hash)?;
        let server = derive_secret(&master, b"s ap traffic", transcript_hash)?;
        self.current = master;
        Ok((TrafficSecret(client), TrafficSecret(server)))
    }
}

impl Default for KeySchedule {
    fn default() -> Self {
        Self::new()
    }
}

/// SHA-256 of the empty string — the `Messages` argument to the two
/// `Derive-Secret(., "derived", "")` steps.
fn transcript_hash_empty() -> [u8; HASH_LEN] {
    Sha256H::hash(&[])
}

#[cfg(test)]
mod tests {
    use super::*;

    // Well-known TLS 1.3 constants (RFC 8446 § 7.1 / RFC 8448):
    //   Early Secret = HKDF-Extract(0, 0)
    //     = 33ad0a1c607ec03b09e6cd9893680ce210adf300aa1f2660e1b22e10f170f92a
    //   derived = Derive-Secret(Early, "derived", "")
    //     = 6f2615a108c702c5678f54fc9dbab69716c076189c48250cebeac3576c3611ba

    #[test]
    fn early_secret_matches_rfc8446() {
        let ks = KeySchedule::new();
        let expected =
            hex::decode("33ad0a1c607ec03b09e6cd9893680ce210adf300aa1f2660e1b22e10f170f92a")
                .unwrap();
        assert_eq!(ks.early_secret().as_slice(), expected.as_slice());
    }

    #[test]
    fn derived_secret_matches_rfc8446() {
        let early: [u8; HASH_LEN] =
            hex::decode("33ad0a1c607ec03b09e6cd9893680ce210adf300aa1f2660e1b22e10f170f92a")
                .unwrap()
                .try_into()
                .unwrap();
        let empty_hash = Sha256H::hash(&[]);
        let derived = derive_secret(&early, b"derived", &empty_hash).unwrap();
        let expected =
            hex::decode("6f2615a108c702c5678f54fc9dbab69716c076189c48250cebeac3576c3611ba")
                .unwrap();
        assert_eq!(derived.as_slice(), expected.as_slice());
    }

    #[test]
    fn expand_label_wire_format_is_exact() {
        // HkdfLabel for length=16, label="key", context="":
        //   00 10 | 09 | "tls13 key" | 00
        // We reconstruct the info by expanding a known secret and comparing to
        // a manual HKDF-Expand over the hand-built label.
        let secret = [7u8; HASH_LEN];
        let out = hkdf_expand_label(&secret, b"key", b"", 16).unwrap();
        let mut info = alloc::vec::Vec::new();
        info.extend_from_slice(&16u16.to_be_bytes());
        info.push(9); // len("tls13 key")
        info.extend_from_slice(b"tls13 key");
        info.push(0); // empty context
        let manual = nexacore_crypto::kdf::hkdf_expand(&secret, &info, 16).unwrap();
        assert_eq!(out, manual);
        assert_eq!(out.len(), 16);
    }

    #[test]
    fn traffic_secret_key_and_iv_have_right_lengths() {
        let ts = TrafficSecret([0x2au8; HASH_LEN]);
        let _key = ts.aead_key().unwrap();
        let iv = ts.iv().unwrap();
        assert_eq!(iv.len(), NONCE_LEN);
        // Deterministic: same secret → same key/iv.
        let iv2 = TrafficSecret([0x2au8; HASH_LEN]).iv().unwrap();
        assert_eq!(iv, iv2);
    }

    #[test]
    fn finished_verify_data_is_deterministic_and_key_bound() {
        let a = TrafficSecret([1u8; HASH_LEN]);
        let b = TrafficSecret([2u8; HASH_LEN]);
        let th = [9u8; HASH_LEN];
        assert_eq!(a.verify_data(&th).unwrap(), a.verify_data(&th).unwrap());
        assert_ne!(a.verify_data(&th).unwrap(), b.verify_data(&th).unwrap());
    }
}
