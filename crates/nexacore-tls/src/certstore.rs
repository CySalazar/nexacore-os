//! Certificate store and chain verification (WS4-03.5/.6).
//!
//! Full X.509/DER parsing with RSA and ECDSA is out of reach here:
//! `nexacore-crypto` provides `ed25519` and `x25519` only, and no ASN.1
//! decoder. Interop with a real OpenSSL certificate chain (WS4-03.10) is
//! therefore the deferred, rig-side goal.
//!
//! What *is* implemented — and host-tested — is the certificate **path
//! logic**: parsing a compact NexaCore certificate, chaining each cert's
//! signature to its issuer, terminating at a configured trust anchor,
//! enforcing the validity window, the CA/basic-constraints flag, path-length
//! limits, and the leaf subject-name (SNI) match. The certificate *format* is
//! isolated behind [`CertVerifier`] so a future X.509 backend can slot in
//! without touching the path-building code.
//!
//! The bundled `NexaCert` format is a length-prefixed `TBS || signature`
//! where the issuer signs the TBS with `ed25519`. It is deliberately minimal:
//! subject/issuer distinguished names are opaque byte strings, validity is a
//! `u64` epoch window, and `is_ca` + `path_len` model basic constraints.

use alloc::vec::Vec;

use nexacore_crypto::signing::{
    NexaCoreSignature, NexaCoreVerifyingKey, SIGNATURE_LEN, VERIFYING_KEY_LEN,
};

use crate::{
    codec::{Reader, Writer},
    error::{TlsError, TlsResult},
};

/// A parsed certificate in a format-agnostic shape.
///
/// Carries the fields the path logic needs plus the exact bytes that were
/// signed (`tbs`) and the signature over them.
#[derive(Debug, Clone)]
pub struct ParsedCert {
    /// Subject distinguished name (opaque).
    pub subject: Vec<u8>,
    /// Issuer distinguished name (opaque); must match the parent's subject.
    pub issuer: Vec<u8>,
    /// Subject public key (`ed25519`, 32 bytes) — used to verify a child.
    pub subject_spki: [u8; VERIFYING_KEY_LEN],
    /// Validity start (inclusive), seconds since the Unix epoch.
    pub not_before: u64,
    /// Validity end (inclusive), seconds since the Unix epoch.
    pub not_after: u64,
    /// Whether this cert may act as a CA (sign other certs).
    pub is_ca: bool,
    /// Max number of intermediate CAs permitted below this one.
    pub path_len: u8,
    /// The exact bytes covered by the signature.
    pub tbs: Vec<u8>,
    /// The issuer's `ed25519` signature over `tbs`.
    pub signature: [u8; SIGNATURE_LEN],
}

/// A pluggable certificate backend.
///
/// It parses a wire certificate and verifies a signature under an issuer public
/// key. Swapping this for an X.509 backend leaves the path logic in
/// [`verify_chain`] unchanged.
pub trait CertVerifier {
    /// Parse one wire certificate into a [`ParsedCert`].
    ///
    /// # Errors
    /// [`TlsError::BadCertificate`] if the bytes are not a well-formed cert.
    fn parse(&self, der: &[u8]) -> TlsResult<ParsedCert>;

    /// Verify `signature` over `message` under the issuer's public key.
    /// Returns `true` iff the signature is valid.
    fn verify(
        &self,
        issuer_spki: &[u8; VERIFYING_KEY_LEN],
        message: &[u8],
        signature: &[u8; SIGNATURE_LEN],
    ) -> bool;
}

/// A trust anchor: a distinguished name bound to an `ed25519` public key.
#[derive(Debug, Clone)]
pub struct TrustAnchor {
    /// The anchor's subject distinguished name.
    pub name: Vec<u8>,
    /// The anchor's `ed25519` public key.
    pub spki: [u8; VERIFYING_KEY_LEN],
}

/// A set of trust anchors. Verification succeeds only if a chain terminates at
/// a cert issued by one of these anchors.
#[derive(Debug, Clone, Default)]
pub struct CertStore {
    anchors: Vec<TrustAnchor>,
}

impl CertStore {
    /// An empty store (rejects every chain — fail-closed).
    #[must_use]
    pub const fn new() -> Self {
        Self {
            anchors: Vec::new(),
        }
    }

    /// Add a trust anchor.
    pub fn add_anchor(&mut self, name: Vec<u8>, spki: [u8; VERIFYING_KEY_LEN]) {
        self.anchors.push(TrustAnchor { name, spki });
    }

    /// Number of configured anchors.
    #[must_use]
    pub fn len(&self) -> usize {
        self.anchors.len()
    }

    /// Whether the store is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.anchors.is_empty()
    }

    /// Find an anchor by issuer name.
    fn find(&self, name: &[u8]) -> Option<&TrustAnchor> {
        self.anchors.iter().find(|a| a.name.as_slice() == name)
    }
}

/// Verify a certificate chain (leaf first) against `store` at time `now`,
/// requiring the leaf's subject to equal `expected_name` when it is `Some`.
///
/// The logic:
/// 1. Parse every cert.
/// 2. For each cert, verify its signature under the next cert's public key,
///    or — for the last cert — under the matching trust anchor's key.
/// 3. Every cert must be within its validity window at `now`.
/// 4. Every non-leaf cert must be a CA, and path-length constraints hold.
/// 5. The leaf subject must match `expected_name` (SNI binding).
///
/// # Errors
/// [`TlsError::BadCertificate`] for any structural, validity, constraint, or
/// path failure; [`TlsError::BadSignature`] for a signature that does not
/// verify. The distinction is internal only.
pub fn verify_chain<V: CertVerifier>(
    verifier: &V,
    chain: &[Vec<u8>],
    store: &CertStore,
    now: u64,
    expected_name: Option<&[u8]>,
) -> TlsResult<ParsedCert> {
    let (leaf_bytes, rest) = chain.split_first().ok_or(TlsError::BadCertificate)?;
    let leaf = verifier.parse(leaf_bytes)?;

    // Parse the full chain up front.
    let mut parsed = Vec::with_capacity(chain.len());
    parsed.push(leaf.clone());
    for c in rest {
        parsed.push(verifier.parse(c)?);
    }

    // Validity + CA constraints for every cert.
    for (i, cert) in parsed.iter().enumerate() {
        if now < cert.not_before || now > cert.not_after {
            return Err(TlsError::BadCertificate);
        }
        // Non-leaf certs must be CAs and satisfy the path-length budget.
        if i > 0 {
            if !cert.is_ca {
                return Err(TlsError::BadCertificate);
            }
            // Intermediates below this CA (excluding leaf and this cert).
            let intermediates_below = i.saturating_sub(1);
            if usize::from(cert.path_len) < intermediates_below {
                return Err(TlsError::BadCertificate);
            }
        }
    }

    // Chain each cert's signature to its issuer.
    for i in 0..parsed.len() {
        let cert = parsed.get(i).ok_or(TlsError::BadCertificate)?;
        let issuer_spki = if let Some(parent) = parsed.get(i + 1) {
            // issuer name must match the parent's subject.
            if cert.issuer.as_slice() != parent.subject.as_slice() {
                return Err(TlsError::BadCertificate);
            }
            parent.subject_spki
        } else {
            // Last cert: must be issued by a known trust anchor.
            let anchor = store.find(&cert.issuer).ok_or(TlsError::BadCertificate)?;
            anchor.spki
        };
        if !verifier.verify(&issuer_spki, &cert.tbs, &cert.signature) {
            return Err(TlsError::BadSignature);
        }
    }

    // Leaf subject / SNI binding.
    if let Some(name) = expected_name {
        if leaf.subject.as_slice() != name {
            return Err(TlsError::BadCertificate);
        }
    }

    Ok(leaf)
}

// ---- NexaCert: the bundled ed25519 certificate format -----------------------

/// The `TBS` (to-be-signed) portion of a `NexaCert`, carrying the certified
/// facts. Encodes deterministically so the signer and verifier agree byte for
/// byte.
#[derive(Debug, Clone)]
pub struct NexaCertTbs {
    /// Subject distinguished name.
    pub subject: Vec<u8>,
    /// Issuer distinguished name.
    pub issuer: Vec<u8>,
    /// Subject `ed25519` public key.
    pub subject_spki: [u8; VERIFYING_KEY_LEN],
    /// Validity start (Unix seconds).
    pub not_before: u64,
    /// Validity end (Unix seconds).
    pub not_after: u64,
    /// CA flag.
    pub is_ca: bool,
    /// Path-length constraint.
    pub path_len: u8,
}

impl NexaCertTbs {
    /// Serialize the TBS deterministically.
    ///
    /// # Errors
    /// [`TlsError::BadValue`] on a name longer than 65535 bytes.
    pub fn encode(&self) -> TlsResult<Vec<u8>> {
        let mut w = Writer::new();
        w.vec_u16(&self.subject)?;
        w.vec_u16(&self.issuer)?;
        w.bytes(&self.subject_spki);
        w.bytes(&self.not_before.to_be_bytes());
        w.bytes(&self.not_after.to_be_bytes());
        w.u8(u8::from(self.is_ca));
        w.u8(self.path_len);
        Ok(w.into_bytes())
    }
}

/// Encode a full `NexaCert` wire certificate = `tbs_len(u16) || tbs ||
/// signature(64)`.
///
/// # Errors
/// [`TlsError::BadValue`] on length overflow.
pub fn encode_nexacert(tbs: &[u8], signature: &[u8; SIGNATURE_LEN]) -> TlsResult<Vec<u8>> {
    let mut w = Writer::new();
    w.vec_u16(tbs)?;
    w.bytes(signature);
    Ok(w.into_bytes())
}

/// The [`CertVerifier`] backend for the bundled `ed25519` `NexaCert` format.
#[derive(Debug, Clone, Copy, Default)]
pub struct NexaCertVerifier;

impl CertVerifier for NexaCertVerifier {
    fn parse(&self, der: &[u8]) -> TlsResult<ParsedCert> {
        let mut r = Reader::new(der);
        let tbs = r.vec_u16().map_err(|_| TlsError::BadCertificate)?;
        let sig_bytes = r
            .take(SIGNATURE_LEN)
            .map_err(|_| TlsError::BadCertificate)?;
        if !r.is_empty() {
            return Err(TlsError::BadCertificate);
        }
        let signature: [u8; SIGNATURE_LEN] =
            sig_bytes.try_into().map_err(|_| TlsError::BadCertificate)?;

        // Parse the TBS fields.
        let mut tr = Reader::new(tbs);
        let subject = tr.vec_u16().map_err(|_| TlsError::BadCertificate)?.to_vec();
        let issuer = tr.vec_u16().map_err(|_| TlsError::BadCertificate)?.to_vec();
        let spki_bytes = tr
            .take(VERIFYING_KEY_LEN)
            .map_err(|_| TlsError::BadCertificate)?;
        let subject_spki: [u8; VERIFYING_KEY_LEN] = spki_bytes
            .try_into()
            .map_err(|_| TlsError::BadCertificate)?;
        let nb = tr.take(8).map_err(|_| TlsError::BadCertificate)?;
        let na = tr.take(8).map_err(|_| TlsError::BadCertificate)?;
        let not_before = u64::from_be_bytes(nb.try_into().map_err(|_| TlsError::BadCertificate)?);
        let not_after = u64::from_be_bytes(na.try_into().map_err(|_| TlsError::BadCertificate)?);
        let is_ca = tr.u8().map_err(|_| TlsError::BadCertificate)? != 0;
        let path_len = tr.u8().map_err(|_| TlsError::BadCertificate)?;
        if !tr.is_empty() {
            return Err(TlsError::BadCertificate);
        }

        Ok(ParsedCert {
            subject,
            issuer,
            subject_spki,
            not_before,
            not_after,
            is_ca,
            path_len,
            tbs: tbs.to_vec(),
            signature,
        })
    }

    fn verify(
        &self,
        issuer_spki: &[u8; VERIFYING_KEY_LEN],
        message: &[u8],
        signature: &[u8; SIGNATURE_LEN],
    ) -> bool {
        let Ok(vk) = NexaCoreVerifyingKey::from_bytes(issuer_spki) else {
            return false;
        };
        let sig = NexaCoreSignature::from_bytes(*signature);
        vk.verify(message, &sig).is_ok()
    }
}

#[cfg(test)]
mod tests {
    use nexacore_crypto::signing::NexaCoreSigningKey;

    use super::*;

    struct Entity {
        key: NexaCoreSigningKey,
        name: Vec<u8>,
    }

    impl Entity {
        fn new(seed: u8, name: &[u8]) -> Self {
            Self {
                key: NexaCoreSigningKey::from_bytes([seed; 32]),
                name: name.to_vec(),
            }
        }

        fn spki(&self) -> [u8; VERIFYING_KEY_LEN] {
            self.key.verifying_key().as_bytes()
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn issue(
        subject: &Entity,
        issuer: &Entity,
        not_before: u64,
        not_after: u64,
        is_ca: bool,
        path_len: u8,
    ) -> Vec<u8> {
        let tbs = NexaCertTbs {
            subject: subject.name.clone(),
            issuer: issuer.name.clone(),
            subject_spki: subject.spki(),
            not_before,
            not_after,
            is_ca,
            path_len,
        }
        .encode()
        .unwrap();
        let sig = issuer.key.sign(&tbs).to_bytes();
        encode_nexacert(&tbs, &sig).unwrap()
    }

    fn store_with(root: &Entity) -> CertStore {
        let mut s = CertStore::new();
        s.add_anchor(root.name.clone(), root.spki());
        s
    }

    #[test]
    fn direct_leaf_from_anchor_verifies() {
        let root = Entity::new(1, b"Root CA");
        let leaf = Entity::new(2, b"leaf.example.com");
        let cert = issue(&leaf, &root, 0, 1000, false, 0);
        let store = store_with(&root);
        let out = verify_chain(
            &NexaCertVerifier,
            &[cert],
            &store,
            500,
            Some(b"leaf.example.com"),
        )
        .unwrap();
        assert_eq!(out.subject, b"leaf.example.com");
    }

    #[test]
    fn intermediate_chain_verifies() {
        let root = Entity::new(1, b"Root CA");
        let inter = Entity::new(2, b"Intermediate CA");
        let leaf = Entity::new(3, b"leaf.example.com");
        let leaf_cert = issue(&leaf, &inter, 0, 1000, false, 0);
        let inter_cert = issue(&inter, &root, 0, 1000, true, 1);
        let store = store_with(&root);
        assert!(
            verify_chain(
                &NexaCertVerifier,
                &[leaf_cert, inter_cert],
                &store,
                500,
                Some(b"leaf.example.com"),
            )
            .is_ok()
        );
    }

    #[test]
    fn expired_certificate_rejected() {
        let root = Entity::new(1, b"Root CA");
        let leaf = Entity::new(2, b"leaf.example.com");
        let cert = issue(&leaf, &root, 0, 100, false, 0);
        let store = store_with(&root);
        assert_eq!(
            verify_chain(&NexaCertVerifier, &[cert], &store, 500, None).err(),
            Some(TlsError::BadCertificate)
        );
    }

    #[test]
    fn wrong_expected_name_rejected() {
        let root = Entity::new(1, b"Root CA");
        let leaf = Entity::new(2, b"leaf.example.com");
        let cert = issue(&leaf, &root, 0, 1000, false, 0);
        let store = store_with(&root);
        assert_eq!(
            verify_chain(&NexaCertVerifier, &[cert], &store, 500, Some(b"evil.com")).err(),
            Some(TlsError::BadCertificate)
        );
    }

    #[test]
    fn untrusted_issuer_rejected() {
        let root = Entity::new(1, b"Root CA");
        let other = Entity::new(9, b"Other CA");
        let leaf = Entity::new(2, b"leaf.example.com");
        let cert = issue(&leaf, &root, 0, 1000, false, 0);
        // Store trusts a different CA.
        let store = store_with(&other);
        assert_eq!(
            verify_chain(&NexaCertVerifier, &[cert], &store, 500, None).err(),
            Some(TlsError::BadCertificate)
        );
    }

    #[test]
    fn tampered_signature_rejected() {
        let root = Entity::new(1, b"Root CA");
        let leaf = Entity::new(2, b"leaf.example.com");
        let mut cert = issue(&leaf, &root, 0, 1000, false, 0);
        let last = cert.len() - 1;
        cert[last] ^= 0x01;
        let store = store_with(&root);
        assert_eq!(
            verify_chain(&NexaCertVerifier, &[cert], &store, 500, None).err(),
            Some(TlsError::BadSignature)
        );
    }

    #[test]
    fn non_ca_intermediate_rejected() {
        let root = Entity::new(1, b"Root CA");
        let inter = Entity::new(2, b"Intermediate");
        let leaf = Entity::new(3, b"leaf.example.com");
        let leaf_cert = issue(&leaf, &inter, 0, 1000, false, 0);
        // Intermediate is NOT a CA.
        let inter_cert = issue(&inter, &root, 0, 1000, false, 0);
        let store = store_with(&root);
        assert_eq!(
            verify_chain(
                &NexaCertVerifier,
                &[leaf_cert, inter_cert],
                &store,
                500,
                None
            )
            .err(),
            Some(TlsError::BadCertificate)
        );
    }

    #[test]
    fn empty_store_rejects_everything() {
        let root = Entity::new(1, b"Root CA");
        let leaf = Entity::new(2, b"leaf.example.com");
        let cert = issue(&leaf, &root, 0, 1000, false, 0);
        let store = CertStore::new();
        assert!(verify_chain(&NexaCertVerifier, &[cert], &store, 500, None).is_err());
    }
}
