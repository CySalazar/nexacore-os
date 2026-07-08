//! TLS alert protocol (RFC 8446 § 6).
//!
//! Alerts are 2-byte records (`AlertLevel`, `AlertDescription`) carried in the
//! `alert` content type. In TLS 1.3 all alerts except `close_notify` and
//! `user_canceled` are fatal, and the level byte is effectively vestigial —
//! receivers act on the description. We still model both bytes for wire
//! fidelity and interop.

use crate::error::{TlsError, TlsResult};

/// Alert level. TLS 1.3 treats every alert other than `close_notify` /
/// `user_canceled` as fatal regardless of this byte, but it is still encoded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum AlertLevel {
    /// Warning-level alert (only meaningful for `close_notify`).
    Warning = 1,
    /// Fatal alert — the connection MUST be torn down.
    Fatal = 2,
}

/// Alert description codes (RFC 8446 § 6, subset used by this stack).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum AlertDescription {
    /// Graceful connection closure notification.
    CloseNotify = 0,
    /// An unexpected message was received.
    UnexpectedMessage = 10,
    /// A record failed its AEAD authentication.
    BadRecordMac = 20,
    /// A record could not be decrypted.
    DecryptError = 51,
    /// The handshake could not negotiate an acceptable set of parameters.
    HandshakeFailure = 40,
    /// A certificate was corrupt, or contained an unsupported signature.
    BadCertificate = 42,
    /// No certificate chained to a configured trust anchor.
    UnknownCa = 48,
    /// A message could not be decoded.
    DecodeError = 50,
    /// The protocol version or a required extension was unsupported.
    ProtocolVersion = 70,
    /// No application protocol in common (ALPN).
    NoApplicationProtocol = 120,
    /// An internal error unrelated to the peer or protocol.
    InternalError = 80,
}

impl AlertDescription {
    /// Decode a description byte, rejecting unknown codes.
    ///
    /// # Errors
    /// Returns [`TlsError::BadValue`] for an unrecognised description.
    pub const fn from_byte(b: u8) -> TlsResult<Self> {
        Ok(match b {
            0 => Self::CloseNotify,
            10 => Self::UnexpectedMessage,
            20 => Self::BadRecordMac,
            51 => Self::DecryptError,
            40 => Self::HandshakeFailure,
            42 => Self::BadCertificate,
            48 => Self::UnknownCa,
            50 => Self::DecodeError,
            70 => Self::ProtocolVersion,
            120 => Self::NoApplicationProtocol,
            80 => Self::InternalError,
            _ => return Err(TlsError::BadValue),
        })
    }

    /// Whether this description is `close_notify` (the only routine, non-error
    /// alert in TLS 1.3).
    #[must_use]
    pub const fn is_close_notify(self) -> bool {
        matches!(self, Self::CloseNotify)
    }
}

/// A fully-formed alert message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Alert {
    /// Fatal / warning level byte.
    pub level: AlertLevel,
    /// The specific alert.
    pub description: AlertDescription,
}

impl Alert {
    /// Build a fatal alert.
    #[must_use]
    pub const fn fatal(description: AlertDescription) -> Self {
        Self {
            level: AlertLevel::Fatal,
            description,
        }
    }

    /// Build the routine `close_notify` (warning-level) alert.
    #[must_use]
    pub const fn close_notify() -> Self {
        Self {
            level: AlertLevel::Warning,
            description: AlertDescription::CloseNotify,
        }
    }

    /// Serialize to the 2-byte alert body.
    #[must_use]
    pub const fn encode(self) -> [u8; 2] {
        [self.level as u8, self.description as u8]
    }

    /// Parse a 2-byte alert body.
    ///
    /// # Errors
    /// Returns [`TlsError::Decode`] if the slice is not exactly 2 bytes, or
    /// [`TlsError::BadValue`] for an unknown level/description.
    pub fn decode(body: &[u8]) -> TlsResult<Self> {
        let [level, desc] = body else {
            return Err(TlsError::Decode);
        };
        let (level, desc) = (*level, *desc);
        let level = match level {
            1 => AlertLevel::Warning,
            2 => AlertLevel::Fatal,
            _ => return Err(TlsError::BadValue),
        };
        Ok(Self {
            level,
            description: AlertDescription::from_byte(desc)?,
        })
    }
}
