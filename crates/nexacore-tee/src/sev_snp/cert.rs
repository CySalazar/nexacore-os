//! VCEK/VLEK fetch keying and the ARK→ASK→VCEK chain (WS10-02.5, .6, .7).
//!
//! An SNP report is signed by the platform's **VCEK** (Versioned Chip
//! Endorsement Key), itself certified by AMD's **ASK** (SEV intermediate),
//! certified by the self-signed **ARK** (AMD Root Key).  Verification means:
//! fetch the VCEK for this chip at the reported TCB from the AMD **KDS**, then
//! walk VCEK → ASK → ARK checking names, signatures, and that the root is the
//! pinned ARK.
//!
//! The KDS *URL derivation* (from `CHIP_ID` + `REPORTED_TCB`) and the
//! *chain-walk policy* are pure and host-testable, and live here.  The HTTP
//! fetch (`std` + TLS) and the *cryptographic* ECDSA-P-384 / X.509 verification
//! (which `nexacore-crypto` does not yet provide) are delegated — to the caller
//! and to the [`CertVerifier`] seam respectively (library-gated).

use alloc::{format, string::String, vec::Vec};

/// AMD EPYC generations that expose SNP, as the KDS path segment uses them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AmdProduct {
    /// 3rd-gen EPYC (Milan).
    Milan,
    /// 4th-gen EPYC (Genoa).
    Genoa,
    /// Cloud-native 4th-gen (Bergamo).
    Bergamo,
    /// Edge 4th-gen (Siena).
    Siena,
    /// 5th-gen EPYC (Turin).
    Turin,
}

impl AmdProduct {
    /// The product name segment used in KDS URLs.
    #[must_use]
    pub const fn kds_name(self) -> &'static str {
        match self {
            Self::Milan => "Milan",
            Self::Genoa => "Genoa",
            Self::Bergamo => "Bergamo",
            Self::Siena => "Siena",
            Self::Turin => "Turin",
        }
    }
}

/// The four security-patch levels packed into a `REPORTED_TCB` value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TcbVersion {
    /// Boot-loader SPL.
    pub bootloader: u8,
    /// TEE SPL.
    pub tee: u8,
    /// SNP firmware SPL.
    pub snp: u8,
    /// Microcode SPL.
    pub microcode: u8,
}

impl TcbVersion {
    /// Decode a `REPORTED_TCB` u64 (AMD layout: BL\[0\], TEE\[8\], SNP\[48\],
    /// MICROCODE\[56\]).
    #[must_use]
    pub const fn from_reported_tcb(reported_tcb: u64) -> Self {
        let bytes = reported_tcb.to_le_bytes();
        Self {
            bootloader: bytes[0],
            tee: bytes[1],
            snp: bytes[6],
            microcode: bytes[7],
        }
    }
}

/// Base URL of the AMD Key Distribution Service.
pub const KDS_BASE: &str = "https://kdsintf.amd.com";

/// Lower-case hex of a byte slice.
fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        s.push(char::from_digit(u32::from(b >> 4), 16).unwrap_or('0'));
        s.push(char::from_digit(u32::from(b & 0x0F), 16).unwrap_or('0'));
    }
    s
}

/// Build the AMD KDS URL that returns the VCEK certificate for a chip at a TCB
/// (WS10-02.5).
///
/// `…/vcek/v1/{product}/{chip_id_hex}?blSPL=..&teeSPL=..&snpSPL=..&ucodeSPL=..`.
#[must_use]
pub fn vcek_url(product: AmdProduct, chip_id: &[u8; 64], tcb: TcbVersion) -> String {
    format!(
        "{base}/vcek/v1/{prod}/{chip}?blSPL={bl}&teeSPL={tee}&snpSPL={snp}&ucodeSPL={uc}",
        base = KDS_BASE,
        prod = product.kds_name(),
        chip = hex(chip_id),
        bl = tcb.bootloader,
        tee = tcb.tee,
        snp = tcb.snp,
        uc = tcb.microcode,
    )
}

/// Build the AMD KDS URL for the ASK+ARK certificate chain of a product.
#[must_use]
pub fn cert_chain_url(product: AmdProduct) -> String {
    format!("{KDS_BASE}/vcek/v1/{}/cert_chain", product.kds_name())
}

/// A certificate reduced to what the chain walk needs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Certificate {
    /// DER-encoded subject distinguished name.
    pub subject: Vec<u8>,
    /// DER-encoded issuer distinguished name.
    pub issuer: Vec<u8>,
    /// SHA-384 fingerprint of the DER certificate (ARK pinning key).
    pub fingerprint: [u8; 48],
    /// Raw DER bytes (handed to the [`CertVerifier`]).
    pub der: Vec<u8>,
}

impl Certificate {
    /// `true` if this certificate is self-signed (issuer == subject).
    #[must_use]
    pub fn is_self_signed(&self) -> bool {
        self.subject == self.issuer
    }
}

/// Verifies one certificate (or the report) was signed by an issuer key.
///
/// The real implementation parses DER and checks the ECDSA-P-384 signature; it
/// is library-gated (WS10-02.6).
pub trait CertVerifier {
    /// `true` if `cert`'s signature is valid under `issuer`'s public key.
    fn verify_issued(&self, cert: &Certificate, issuer: &Certificate) -> bool;
    /// `true` if `signed_region` is correctly signed by `vcek` (the report
    /// signature, ECDSA-P-384; WS10-02.6).
    fn verify_report(&self, signed_region: &[u8], signature: &[u8], vcek: &Certificate) -> bool;
}

/// Why an AMD certificate chain failed verification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AmdChainError {
    /// The chain had no certificates.
    EmptyChain,
    /// A certificate's issuer name did not match the next certificate's subject.
    NameChainBroken,
    /// A certificate's signature did not verify under its issuer.
    BadSignature,
    /// The terminal certificate (ARK) was not self-signed.
    RootNotSelfSigned,
    /// The terminal certificate was not the pinned AMD Root Key.
    UntrustedRoot,
}

impl core::fmt::Display for AmdChainError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let msg = match self {
            Self::EmptyChain => "empty AMD certificate chain",
            Self::NameChainBroken => "AMD issuer/subject name chain broken",
            Self::BadSignature => "AMD certificate signature invalid",
            Self::RootNotSelfSigned => "AMD chain root (ARK) is not self-signed",
            Self::UntrustedRoot => "AMD chain root is not the pinned ARK",
        };
        f.write_str(msg)
    }
}

impl core::error::Error for AmdChainError {}

/// Verify a leaf-first AMD chain `[VCEK, ASK, ARK]` against the pinned ARK
/// fingerprint (WS10-02.7).
///
/// # Errors
/// Returns the first [`AmdChainError`] encountered.
pub fn verify_chain<V: CertVerifier>(
    chain: &[Certificate],
    ark_fingerprint: &[u8; 48],
    verifier: &V,
) -> Result<(), AmdChainError> {
    let root = chain.last().ok_or(AmdChainError::EmptyChain)?;

    for pair in chain.windows(2) {
        let [cert, issuer] = pair else {
            return Err(AmdChainError::EmptyChain);
        };
        if cert.issuer != issuer.subject {
            return Err(AmdChainError::NameChainBroken);
        }
        if !verifier.verify_issued(cert, issuer) {
            return Err(AmdChainError::BadSignature);
        }
    }

    if !root.is_self_signed() {
        return Err(AmdChainError::RootNotSelfSigned);
    }
    if root.fingerprint != *ark_fingerprint {
        return Err(AmdChainError::UntrustedRoot);
    }
    if !verifier.verify_issued(root, root) {
        return Err(AmdChainError::BadSignature);
    }

    Ok(())
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::missing_docs_in_private_items
)]
mod tests {
    use super::*;

    #[test]
    fn decodes_reported_tcb() {
        // BL=0x12 TEE=0x34 SNP=0x56 MICROCODE=0x78.
        let reported = u64::from_le_bytes([0x12, 0x34, 0, 0, 0, 0, 0x56, 0x78]);
        let tcb = TcbVersion::from_reported_tcb(reported);
        assert_eq!(tcb.bootloader, 0x12);
        assert_eq!(tcb.tee, 0x34);
        assert_eq!(tcb.snp, 0x56);
        assert_eq!(tcb.microcode, 0x78);
    }

    #[test]
    fn builds_vcek_url() {
        let chip = [0xABu8; 64];
        let tcb = TcbVersion {
            bootloader: 3,
            tee: 0,
            snp: 20,
            microcode: 209,
        };
        let url = vcek_url(AmdProduct::Milan, &chip, tcb);
        assert!(url.starts_with("https://kdsintf.amd.com/vcek/v1/Milan/"));
        assert!(url.contains(&"ab".repeat(64)));
        assert!(url.ends_with("?blSPL=3&teeSPL=0&snpSPL=20&ucodeSPL=209"));
    }

    #[test]
    fn builds_cert_chain_url() {
        assert_eq!(
            cert_chain_url(AmdProduct::Genoa),
            "https://kdsintf.amd.com/vcek/v1/Genoa/cert_chain"
        );
    }

    struct AcceptAll;
    impl CertVerifier for AcceptAll {
        fn verify_issued(&self, _c: &Certificate, _i: &Certificate) -> bool {
            true
        }
        fn verify_report(&self, _r: &[u8], _s: &[u8], _v: &Certificate) -> bool {
            true
        }
    }

    struct RejectSubject(Vec<u8>);
    impl CertVerifier for RejectSubject {
        fn verify_issued(&self, c: &Certificate, _i: &Certificate) -> bool {
            c.subject != self.0
        }
        fn verify_report(&self, _r: &[u8], _s: &[u8], _v: &Certificate) -> bool {
            true
        }
    }

    fn cert(subject: &[u8], issuer: &[u8], fp: u8) -> Certificate {
        Certificate {
            subject: subject.to_vec(),
            issuer: issuer.to_vec(),
            fingerprint: [fp; 48],
            der: alloc::vec![fp; 8],
        }
    }

    fn good_chain() -> Vec<Certificate> {
        alloc::vec![
            cert(b"VCEK", b"ASK", 1),
            cert(b"ASK", b"ARK", 2),
            cert(b"ARK", b"ARK", 3),
        ]
    }

    #[test]
    fn accepts_pinned_chain() {
        assert_eq!(verify_chain(&good_chain(), &[3; 48], &AcceptAll), Ok(()));
    }

    #[test]
    fn rejects_broken_name_chain() {
        let mut chain = good_chain();
        chain[0].issuer = b"Rogue".to_vec();
        assert_eq!(
            verify_chain(&chain, &[3; 48], &AcceptAll),
            Err(AmdChainError::NameChainBroken)
        );
    }

    #[test]
    fn rejects_bad_signature() {
        assert_eq!(
            verify_chain(&good_chain(), &[3; 48], &RejectSubject(b"ASK".to_vec())),
            Err(AmdChainError::BadSignature)
        );
    }

    #[test]
    fn rejects_unpinned_ark() {
        assert_eq!(
            verify_chain(&good_chain(), &[9; 48], &AcceptAll),
            Err(AmdChainError::UntrustedRoot)
        );
    }
}
