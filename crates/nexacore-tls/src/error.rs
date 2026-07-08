//! TLS error taxonomy.
//!
//! A single [`TlsError`] enum spans the whole stack — record framing,
//! handshake parsing, key-schedule failures, certificate verification, and
//! peer-sent alerts. Errors are fail-closed: any parse ambiguity, unexpected
//! message, or authentication failure aborts the connection rather than
//! guessing. Variants deliberately avoid carrying attacker-influenced detail
//! that could turn into a padding/timing oracle (RFC 8446 § 5.2, § 6.2).

use crate::alert::AlertDescription;

/// Result alias for the TLS stack.
pub type TlsResult<T> = core::result::Result<T, TlsError>;

/// Everything that can go wrong in the TLS 1.3 state machine.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TlsError {
    /// A record or handshake structure was truncated or malformed.
    Decode,
    /// A field held a value outside the range this implementation accepts
    /// (e.g. an unsupported legacy TLS version in a record header).
    BadValue,
    /// The peer offered no cipher suite, group, or signature scheme we
    /// support. TLS 1.3 with `TLS_CHACHA20_POLY1305_SHA256` + `x25519` +
    /// `ed25519` is the required common ground.
    NoCommonParameters,
    /// A handshake message arrived out of the order the state machine expects.
    UnexpectedMessage,
    /// AEAD open failed: tag mismatch, wrong key, or tampering. Opaque by
    /// design — never distinguishes the cause.
    DecryptFailed,
    /// The record sequence number space was exhausted (2^64 records). A
    /// key update is mandatory well before this; hitting it is fail-closed.
    SequenceOverflow,
    /// A `Finished` MAC did not verify — the transcript or keys diverged.
    BadFinished,
    /// Certificate chain verification failed (bad signature, no path to a
    /// trust anchor, or a violated constraint).
    BadCertificate,
    /// The `CertificateVerify` signature over the transcript did not verify.
    BadSignature,
    /// A cryptographic primitive reported an internal failure.
    Crypto,
    /// The peer sent a fatal alert; the description is preserved for logging.
    PeerAlert(AlertDescription),
    /// The connection was used after the handshake failed or closed.
    Closed,
}

impl TlsError {
    /// Map this error to the alert this endpoint should send the peer.
    ///
    /// RFC 8446 § 6 defines the alert taxonomy. Parse failures map to
    /// `decode_error`, authentication failures to `bad_record_mac` /
    /// `decrypt_error`, and negotiation failures to `handshake_failure`.
    #[must_use]
    pub const fn to_alert(self) -> AlertDescription {
        match self {
            Self::Decode | Self::BadValue => AlertDescription::DecodeError,
            Self::NoCommonParameters => AlertDescription::HandshakeFailure,
            Self::UnexpectedMessage => AlertDescription::UnexpectedMessage,
            Self::DecryptFailed | Self::SequenceOverflow => AlertDescription::BadRecordMac,
            Self::BadFinished | Self::BadSignature => AlertDescription::DecryptError,
            Self::BadCertificate => AlertDescription::BadCertificate,
            Self::Crypto | Self::Closed => AlertDescription::InternalError,
            Self::PeerAlert(desc) => desc,
        }
    }
}
