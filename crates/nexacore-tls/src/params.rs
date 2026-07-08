//! Negotiated TLS 1.3 parameters.
//!
//! This stack supports exactly one of each negotiable dimension, chosen to
//! match the primitives `nexacore-crypto` exposes:
//!
//! | Dimension | Value | Code point |
//! |-----------|-------|-----------|
//! | Cipher suite | `TLS_CHACHA20_POLY1305_SHA256` | `0x1303` |
//! | Key exchange group | `x25519` | `0x001D` |
//! | Signature scheme | `ed25519` | `0x0807` |
//! | Protocol version | `TLS 1.3` | `0x0304` |
//!
//! Negotiation is therefore a membership test: the peer's offered lists must
//! contain our one supported value, else the handshake fails closed with
//! [`TlsError::NoCommonParameters`].

use crate::error::{TlsError, TlsResult};

/// TLS 1.3 protocol version code point (`supported_versions`).
pub const TLS13_VERSION: u16 = 0x0304;

/// `TLS_CHACHA20_POLY1305_SHA256` cipher suite code point.
pub const CIPHER_CHACHA20_POLY1305_SHA256: u16 = 0x1303;

/// `x25519` named group code point.
pub const GROUP_X25519: u16 = 0x001D;

/// `ed25519` signature scheme code point.
pub const SIG_ED25519: u16 = 0x0807;

/// The single supported cipher suite.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CipherSuite {
    /// `TLS_CHACHA20_POLY1305_SHA256`.
    ChaCha20Poly1305Sha256,
}

impl CipherSuite {
    /// The wire code point.
    #[must_use]
    pub const fn code(self) -> u16 {
        match self {
            Self::ChaCha20Poly1305Sha256 => CIPHER_CHACHA20_POLY1305_SHA256,
        }
    }

    /// Select our supported suite from a peer's offered list (big-endian
    /// `u16` code points).
    ///
    /// # Errors
    /// [`TlsError::NoCommonParameters`] if the list does not contain our suite.
    pub fn select(offered: &[u16]) -> TlsResult<Self> {
        if offered.contains(&CIPHER_CHACHA20_POLY1305_SHA256) {
            Ok(Self::ChaCha20Poly1305Sha256)
        } else {
            Err(TlsError::NoCommonParameters)
        }
    }
}

/// The single supported key-exchange group.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NamedGroup {
    /// `x25519`.
    X25519,
}

impl NamedGroup {
    /// The wire code point.
    #[must_use]
    pub const fn code(self) -> u16 {
        match self {
            Self::X25519 => GROUP_X25519,
        }
    }

    /// Select our supported group from a peer's offered list.
    ///
    /// # Errors
    /// [`TlsError::NoCommonParameters`] if the list lacks `x25519`.
    pub fn select(offered: &[u16]) -> TlsResult<Self> {
        if offered.contains(&GROUP_X25519) {
            Ok(Self::X25519)
        } else {
            Err(TlsError::NoCommonParameters)
        }
    }
}

/// The single supported signature scheme.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignatureScheme {
    /// `ed25519` (PureEdDSA over Curve25519).
    Ed25519,
}

impl SignatureScheme {
    /// The wire code point.
    #[must_use]
    pub const fn code(self) -> u16 {
        match self {
            Self::Ed25519 => SIG_ED25519,
        }
    }

    /// Select `ed25519` from a peer's offered `signature_algorithms` list.
    ///
    /// # Errors
    /// [`TlsError::NoCommonParameters`] if the list lacks `ed25519`.
    pub fn select(offered: &[u16]) -> TlsResult<Self> {
        if offered.contains(&SIG_ED25519) {
            Ok(Self::Ed25519)
        } else {
            Err(TlsError::NoCommonParameters)
        }
    }
}
