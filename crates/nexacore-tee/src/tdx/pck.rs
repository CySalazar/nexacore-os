//! PCK certificate-chain verification structure (WS10-01.6).
//!
//! A TDX quote's certification data carries the PCK certificate chain
//! (leaf PCK → Intel SGX intermediate CA → Intel SGX Root CA, PEM-encoded).
//! Verifying it means: the names chain (each cert's issuer is the next cert's
//! subject), every signature checks out under the issuer's key, and the root is
//! the **pinned** Intel SGX Root CA.
//!
//! The cryptographic step — DER/X.509 parsing and ECDSA-P-256 signature
//! verification — needs primitives `nexacore-crypto` does not yet expose, so it
//! is delegated to the [`CertVerifier`] seam (library-gated; the real verifier
//! lands with the ECDSA/X.509 dependency).  The **chain-walk policy** — name
//! chaining, self-signed-root requirement, root pinning, and the order in which
//! the verifier is consulted — is pure and host-testable, and lives here, along
//! with the PEM block splitting that feeds it.

use alloc::vec::Vec;

/// A certificate reduced to what the chain walk needs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Certificate {
    /// DER-encoded subject distinguished name.
    pub subject: Vec<u8>,
    /// DER-encoded issuer distinguished name.
    pub issuer: Vec<u8>,
    /// SHA-256 fingerprint of the full DER certificate (root pinning key).
    pub fingerprint: [u8; 32],
    /// The raw DER bytes (handed to the [`CertVerifier`]).
    pub der: Vec<u8>,
}

impl Certificate {
    /// `true` if this certificate is self-signed (issuer == subject).
    #[must_use]
    pub fn is_self_signed(&self) -> bool {
        self.subject == self.issuer
    }
}

/// Verifies that one certificate was issued (signed) by another.
///
/// The real implementation parses the DER and checks the ECDSA-P-256 signature
/// over the TBS region using the issuer's public key; it is library-gated.
pub trait CertVerifier {
    /// `true` if `cert`'s signature is valid under `issuer`'s public key.
    fn verify_issued(&self, cert: &Certificate, issuer: &Certificate) -> bool;
}

/// Why a PCK chain failed verification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PckError {
    /// The chain had no certificates.
    EmptyChain,
    /// A certificate's issuer name did not match the next certificate's subject.
    NameChainBroken,
    /// A certificate's signature did not verify under its issuer.
    BadSignature,
    /// The terminal certificate was not self-signed (not a root).
    RootNotSelfSigned,
    /// The terminal certificate was not the pinned Intel SGX Root CA.
    UntrustedRoot,
}

impl core::fmt::Display for PckError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let msg = match self {
            Self::EmptyChain => "empty PCK chain",
            Self::NameChainBroken => "PCK issuer/subject name chain broken",
            Self::BadSignature => "PCK certificate signature invalid",
            Self::RootNotSelfSigned => "PCK chain root is not self-signed",
            Self::UntrustedRoot => "PCK chain root is not the pinned Intel SGX Root CA",
        };
        f.write_str(msg)
    }
}

impl core::error::Error for PckError {}

/// Verify a leaf-first PCK certificate chain (WS10-01.6).
///
/// Checks, in order: non-empty; for each adjacent pair the child's issuer name
/// equals the parent's subject name and the child's signature verifies under
/// the parent; the terminal certificate is self-signed; and its fingerprint is
/// the pinned `root_fingerprint`.  The root's own (self) signature is verified
/// too.
///
/// # Errors
/// Returns the first [`PckError`] encountered.
pub fn verify_chain<V: CertVerifier>(
    chain: &[Certificate],
    root_fingerprint: &[u8; 32],
    verifier: &V,
) -> Result<(), PckError> {
    let root = chain.last().ok_or(PckError::EmptyChain)?;

    // Each non-root cert must be name-chained to, and signed by, its successor.
    for pair in chain.windows(2) {
        let [cert, issuer] = pair else {
            return Err(PckError::EmptyChain);
        };
        if cert.issuer != issuer.subject {
            return Err(PckError::NameChainBroken);
        }
        if !verifier.verify_issued(cert, issuer) {
            return Err(PckError::BadSignature);
        }
    }

    // The terminal certificate must be a self-signed, pinned root.
    if !root.is_self_signed() {
        return Err(PckError::RootNotSelfSigned);
    }
    if root.fingerprint != *root_fingerprint {
        return Err(PckError::UntrustedRoot);
    }
    if !verifier.verify_issued(root, root) {
        return Err(PckError::BadSignature);
    }

    Ok(())
}

/// Split a PEM blob into the base64 payloads of its `CERTIFICATE` blocks.
///
/// Returns one `Vec<u8>` per `-----BEGIN CERTIFICATE-----` / `-----END
/// CERTIFICATE-----` block, containing the inner base64 with line breaks
/// stripped (the DER decode of each is the library-gated step).
#[must_use]
pub fn split_pem_certs(pem: &[u8]) -> Vec<Vec<u8>> {
    const BEGIN: &str = "-----BEGIN CERTIFICATE-----";
    const END: &str = "-----END CERTIFICATE-----";
    let Ok(text) = core::str::from_utf8(pem) else {
        return Vec::new();
    };

    let mut out = Vec::new();
    let mut rest = text;
    while let Some(begin) = rest.find(BEGIN) {
        let Some(after_begin) = rest.get(begin + BEGIN.len()..) else {
            break;
        };
        let Some(end) = after_begin.find(END) else {
            break;
        };
        let body = after_begin.get(..end).unwrap_or("");
        let payload: Vec<u8> = body.bytes().filter(|b| !b.is_ascii_whitespace()).collect();
        if !payload.is_empty() {
            out.push(payload);
        }
        rest = after_begin.get(end + END.len()..).unwrap_or("");
    }
    out
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::missing_docs_in_private_items
)]
mod tests {
    use super::*;

    fn cert(subject: &[u8], issuer: &[u8], fp: u8) -> Certificate {
        Certificate {
            subject: subject.to_vec(),
            issuer: issuer.to_vec(),
            fingerprint: [fp; 32],
            der: alloc::vec![fp; 8],
        }
    }

    /// A verifier that accepts every signature (isolates the walk policy).
    struct AcceptAll;
    impl CertVerifier for AcceptAll {
        fn verify_issued(&self, _cert: &Certificate, _issuer: &Certificate) -> bool {
            true
        }
    }

    /// A verifier that rejects a named subject's signature.
    struct RejectSubject(Vec<u8>);
    impl CertVerifier for RejectSubject {
        fn verify_issued(&self, cert: &Certificate, _issuer: &Certificate) -> bool {
            cert.subject != self.0
        }
    }

    fn good_chain() -> Vec<Certificate> {
        alloc::vec![
            cert(b"PCK", b"Intermediate", 1),
            cert(b"Intermediate", b"Root", 2),
            cert(b"Root", b"Root", 3),
        ]
    }

    #[test]
    fn accepts_a_well_formed_pinned_chain() {
        let chain = good_chain();
        assert_eq!(verify_chain(&chain, &[3; 32], &AcceptAll), Ok(()));
    }

    #[test]
    fn rejects_broken_name_chain() {
        let mut chain = good_chain();
        chain[0].issuer = b"WrongCA".to_vec();
        assert_eq!(
            verify_chain(&chain, &[3; 32], &AcceptAll),
            Err(PckError::NameChainBroken)
        );
    }

    #[test]
    fn rejects_bad_signature() {
        let chain = good_chain();
        let verifier = RejectSubject(b"Intermediate".to_vec());
        assert_eq!(
            verify_chain(&chain, &[3; 32], &verifier),
            Err(PckError::BadSignature)
        );
    }

    #[test]
    fn rejects_unpinned_root() {
        let chain = good_chain();
        assert_eq!(
            verify_chain(&chain, &[9; 32], &AcceptAll),
            Err(PckError::UntrustedRoot)
        );
    }

    #[test]
    fn rejects_non_self_signed_root() {
        let mut chain = good_chain();
        chain[2].issuer = b"SomethingElse".to_vec();
        assert_eq!(
            verify_chain(&chain, &[3; 32], &AcceptAll),
            Err(PckError::RootNotSelfSigned)
        );
    }

    #[test]
    fn empty_chain_is_rejected() {
        assert_eq!(
            verify_chain(&[], &[0; 32], &AcceptAll),
            Err(PckError::EmptyChain)
        );
    }

    #[test]
    fn splits_pem_blocks() {
        let pem = b"-----BEGIN CERTIFICATE-----\nAAAA\nBBBB\n-----END CERTIFICATE-----\n\
                    -----BEGIN CERTIFICATE-----\nCCCC\n-----END CERTIFICATE-----\n";
        let blocks = split_pem_certs(pem);
        assert_eq!(blocks.len(), 2);
        assert_eq!(blocks[0], b"AAAABBBB");
        assert_eq!(blocks[1], b"CCCC");
    }
}
