//! Transport error type.

use core::fmt;

/// An SSH transport-layer error.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SshError {
    /// A read hit the end of the buffer before the expected bytes.
    ShortBuffer,
    /// A protocol rule was violated (with a short static tag).
    Protocol(&'static str),
    /// Algorithm negotiation failed: no algorithm in common.
    NoCommonAlgorithm(&'static str),
    /// The host-key signature over the exchange hash did not verify.
    BadSignature,
    /// AEAD open failed (tampering, wrong key, or truncation).
    Decrypt,
    /// The peer's identification string was malformed or unsupported.
    BadIdentification,
    /// The underlying byte transport failed (I/O).
    Transport,
}

impl fmt::Display for SshError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ShortBuffer => write!(f, "short buffer"),
            Self::Protocol(t) => write!(f, "protocol error: {t}"),
            Self::NoCommonAlgorithm(k) => write!(f, "no common {k} algorithm"),
            Self::BadSignature => write!(f, "host-key signature verification failed"),
            Self::Decrypt => write!(f, "packet decryption failed"),
            Self::BadIdentification => write!(f, "malformed identification string"),
            Self::Transport => write!(f, "transport I/O error"),
        }
    }
}

impl core::error::Error for SshError {}
