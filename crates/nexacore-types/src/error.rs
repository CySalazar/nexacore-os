//! Top-level error taxonomy for NexaCore OS.
//!
//! [`NexaCoreError`] is the cross-workspace error type. Each variant covers a
//! distinct subsystem and carries a discriminant (one of the
//! `*ErrorKind` enums in this module) that identifies the category of
//! failure at a granularity rich enough for pattern matching but coarse
//! enough that no sensitive data can leak.
//!
//! # Why discriminants instead of nested error types?
//!
//! `nexacore-types` sits at the bottom of the dependency graph. If we tried
//! to embed `nexacore-crypto::Error` inside `NexaCoreError::Crypto`, we would
//! introduce a circular dependency. Instead, downstream crates define
//! their own detailed error types and implement `From<MyError> for
//! NexaCoreError` locally, mapping to the appropriate kind discriminant plus
//! a static, audit-reviewed `context` slug.
//!
//! # PII-safety contract
//!
//! Error messages MUST NOT contain runtime data that could expose:
//!
//! * Cryptographic key material (private keys, session keys, IVs).
//! * Decrypted plaintext (PII, model inputs/outputs, prompts).
//! * Capability tokens, signatures, or attestation quotes.
//! * Network endpoints in formats that can correlate users
//!   (raw IP addresses, geolocations).
//!
//! Enforcement: the `context` field on every variant is a `&'static str`,
//! which forces the value to be a compile-time literal. A code reviewer
//! can therefore audit every error site by `grep`-ing for `NexaCoreError::`.
//! If you need to attach dynamic detail for debugging, use the `tracing`
//! crate instead — never the error message.
//!
//! # Result alias
//!
//! Use [`Result<T>`] across the workspace instead of `core::result::Result`
//! when the error type is `NexaCoreError`.

// `thiserror` derives `core::error::Error` directly when the `default-features`
// flag is off (Rust 1.81+). We explicitly use `thiserror::Error` to keep the
// derive ergonomics; no `std` is pulled in.
use thiserror::Error;

// =============================================================================
// Result alias.
// =============================================================================

/// Workspace-wide `Result` alias bound to [`NexaCoreError`].
///
/// Every fallible API in the NexaCore OS workspace returns this type. Mixing
/// custom result aliases per crate fragments the surface; a single alias
/// keeps `?` ergonomic across crate boundaries.
pub type Result<T> = core::result::Result<T, NexaCoreError>;

// =============================================================================
// Subsystem error-kind discriminants.
// =============================================================================
//
// Each `*ErrorKind` enum is exhaustively documented because it is the
// permanent symbolic vocabulary downstream code pattern-matches against.
// Adding a variant is a backwards-compatible addition; renaming or
// removing one is a breaking change.

/// Categories of cryptographic failure.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum CryptoErrorKind {
    /// AEAD decryption failed (invalid tag or wrong key).
    DecryptionFailure,
    /// Signature verification failed.
    InvalidSignature,
    /// Provided key has the wrong length or format.
    InvalidKey,
    /// Provided nonce has the wrong length, was reused, or counter overflowed.
    InvalidNonce,
    /// Key derivation function failed (output length, salt, params).
    KdfFailure,
    /// CSPRNG returned an error or insufficient entropy.
    RngFailure,
    /// Algorithm was negotiated out (e.g., deprecated cipher suite).
    AlgorithmDisabled,
    /// Internal cryptographic invariant was violated (treat as bug).
    InternalInvariant,
}

/// Categories of capability-token failure.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum CapabilityErrorKind {
    /// Token expired (`now >= not_after`).
    Expired,
    /// Token not yet valid (`now < not_before`).
    NotYetValid,
    /// Signature on the token does not verify.
    InvalidSignature,
    /// Requested action/resource is outside the token's scope.
    ScopeViolation,
    /// Attempted attenuation would broaden, not restrict, the parent scope.
    AttenuationViolation,
    /// Token's bound TEE attestation does not match the calling node.
    AttestationMismatch,
    /// Token has been revoked.
    Revoked,
    /// Token format/encoding could not be parsed.
    MalformedToken,
}

/// Categories of identifier-handling failure.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum IdentityErrorKind {
    /// Identifier byte length is wrong for its type.
    InvalidLength,
    /// Identifier could not be decoded from its hex / serialized form.
    InvalidEncoding,
    /// Identifier could not be derived from its source (e.g., bad quote).
    DerivationFailure,
}

/// Categories of inter-process / inter-crate IPC failure.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum IpcErrorKind {
    /// Channel was closed before the message could be delivered.
    ChannelClosed,
    /// Message exceeded the configured maximum size.
    MessageTooLarge,
    /// Wire-protocol violation (unexpected message kind, bad framing).
    ProtocolViolation,
    /// Recipient did not respond within the deadline.
    Timeout,
}

/// Categories of mesh-protocol failure.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum MeshErrorKind {
    /// Mesh handshake failed (mutual auth, attestation freshness, etc.).
    HandshakeFailed,
    /// Peer is currently unreachable.
    PeerUnreachable,
    /// Protocol versions could not be negotiated.
    ProtocolMismatch,
    /// Peer attestation is stale (older than the freshness window).
    AttestationStale,
    /// Peer attempted a downgrade (older protocol/cipher).
    DowngradeAttempt,
}

/// Categories of TEE-related failure.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum TeeErrorKind {
    /// No attestable TEE is available on this host (mesh participation
    /// requires one — see `/docs/07-hardware-requirements.md`).
    AttestationUnavailable,
    /// Attestation quote failed verification.
    AttestationInvalid,
    /// Measurement value did not match the expected policy.
    MeasurementMismatch,
    /// Sealing operation failed (data could not be bound to the TEE).
    SealingFailed,
    /// Unsealing operation failed (data was bound to a different TEE).
    UnsealingFailed,
    /// TEE backend is in an unrecoverable state (firmware bug, etc.).
    BackendFailure,
}

/// Categories of HAL (hardware abstraction layer) failure.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum HalErrorKind {
    /// Requested hardware is not available on this host.
    HardwareUnavailable,
    /// I/O failure when communicating with the device.
    Io,
    /// Device reported an unrecoverable failure.
    DeviceFailure,
}

/// Categories of tokenization-service failure.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum TokenizationErrorKind {
    /// Token does not resolve to any known plaintext mapping.
    TokenNotFound,
    /// Construction of an encrypted type was attempted outside the
    /// tokenization service. This indicates a bypass attempt and is
    /// always an audit-worthy event.
    ConstructionForbidden,
    /// Tokenization service is offline or its TEE is not attestable.
    ServiceUnavailable,
}

/// Categories of canonical wire-encoding failure.
///
/// Emitted by [`crate::wire::encode_canonical`] and
/// [`crate::wire::decode_canonical`]. Every variant maps to a
/// `postcard::Error` family member, but the enum is intentionally
/// abstracted so a future encoder swap (under an NCIP) does not break
/// downstream pattern matches.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum WireErrorKind {
    /// Encoder failed to produce bytes (allocation failure, serializer
    /// error in a `Serialize` impl, etc.). Treat as an internal bug —
    /// every `Serialize` impl in NexaCore OS is total over its domain.
    EncodeFailed,
    /// Decoder failed to parse the input bytes into the target type.
    /// Maps to `postcard::Error::DeserializeBadEncoding` and friends.
    DecodeFailed,
    /// Decoder produced a value but the input contained trailing bytes
    /// past the canonical encoding. Canonical encodings forbid trailing
    /// data so any tail indicates either a framing error or an attempt
    /// to smuggle data past a signature pre-image.
    TrailingBytes,
}

/// Categories of policy / consent failure.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum PolicyErrorKind {
    /// Action is denied by the active policy DSL.
    AccessDenied,
    /// Action would exceed the configured privacy budget.
    BudgetExceeded,
    /// User has not granted consent for this action.
    ConsentDenied,
    /// Required policy is missing from the active configuration.
    PolicyMissing,
}

// =============================================================================
// NexaCoreError enum.
// =============================================================================

/// The top-level NexaCore OS error type.
///
/// Every fallible operation across the workspace eventually returns an
/// `NexaCoreError`. Domain-specific error types defined in other crates
/// implement `From<DomainError> for NexaCoreError` and map to the appropriate
/// variant + `*ErrorKind` discriminant (one of the kind enums in this
/// module).
///
/// # Pattern-matching contract
///
/// Variants are `#[non_exhaustive]` so adding a new subsystem error
/// category in the future is not a breaking change. Downstream
/// pattern-match sites should always include a `_ => ...` arm.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum NexaCoreError {
    /// Cryptographic primitive failure.
    #[error("crypto: {kind:?} (context: {context})")]
    Crypto {
        /// The category of cryptographic failure.
        kind: CryptoErrorKind,
        /// Static, audit-reviewed identifier of the failing call site.
        context: &'static str,
    },

    /// Capability-token failure (issuance, validation, attenuation).
    #[error("capability: {kind:?} (context: {context})")]
    Capability {
        /// The category of capability failure.
        kind: CapabilityErrorKind,
        /// Static, audit-reviewed identifier of the failing call site.
        context: &'static str,
    },

    /// Identifier-handling failure.
    #[error("identity: {kind:?} (context: {context})")]
    Identity {
        /// The category of identity failure.
        kind: IdentityErrorKind,
        /// Static, audit-reviewed identifier of the failing call site.
        context: &'static str,
    },

    /// IPC / inter-crate channel failure.
    #[error("ipc: {kind:?} (context: {context})")]
    Ipc {
        /// The category of IPC failure.
        kind: IpcErrorKind,
        /// Static, audit-reviewed identifier of the failing call site.
        context: &'static str,
    },

    /// Mesh-protocol failure.
    #[error("mesh: {kind:?} (context: {context})")]
    Mesh {
        /// The category of mesh failure.
        kind: MeshErrorKind,
        /// Static, audit-reviewed identifier of the failing call site.
        context: &'static str,
    },

    /// TEE / attestation failure.
    #[error("tee: {kind:?} (context: {context})")]
    Tee {
        /// The category of TEE failure.
        kind: TeeErrorKind,
        /// Static, audit-reviewed identifier of the failing call site.
        context: &'static str,
    },

    /// Hardware abstraction layer failure.
    #[error("hal: {kind:?} (context: {context})")]
    Hal {
        /// The category of HAL failure.
        kind: HalErrorKind,
        /// Static, audit-reviewed identifier of the failing call site.
        context: &'static str,
    },

    /// Tokenization-service failure.
    #[error("tokenization: {kind:?} (context: {context})")]
    Tokenization {
        /// The category of tokenization failure.
        kind: TokenizationErrorKind,
        /// Static, audit-reviewed identifier of the failing call site.
        context: &'static str,
    },

    /// Policy / consent failure.
    #[error("policy: {kind:?} (context: {context})")]
    Policy {
        /// The category of policy failure.
        kind: PolicyErrorKind,
        /// Static, audit-reviewed identifier of the failing call site.
        context: &'static str,
    },

    /// Canonical wire-encoding failure (encode/decode round-trip).
    ///
    /// Emitted by [`crate::wire::encode_canonical`] /
    /// [`crate::wire::decode_canonical`]. See [`WireErrorKind`] for
    /// the kind discriminant.
    #[error("wire: {kind:?} (context: {context})")]
    Wire {
        /// The category of wire-encoding failure.
        kind: WireErrorKind,
        /// Static, audit-reviewed identifier of the failing call site.
        context: &'static str,
    },

    /// Internal invariant violation.
    ///
    /// Reaching this variant indicates a bug in NexaCore OS itself, not a
    /// user-recoverable condition. The `context` slug should identify
    /// the violated invariant for triage.
    #[error("internal invariant violated: {context}")]
    Internal {
        /// Static, audit-reviewed identifier of the violated invariant.
        context: &'static str,
    },
}

// =============================================================================
// Convenience constructors.
// =============================================================================
//
// These constructors are syntactic sugar for the most common error sites.
// They exist to keep call sites short while still surfacing the
// discriminant + context pair explicitly.

impl NexaCoreError {
    /// Construct a [`NexaCoreError::Crypto`] error with the given kind and
    /// static context slug.
    #[must_use]
    pub const fn crypto(kind: CryptoErrorKind, context: &'static str) -> Self {
        Self::Crypto { kind, context }
    }

    /// Construct a [`NexaCoreError::Capability`] error with the given kind and
    /// static context slug.
    #[must_use]
    pub const fn capability(kind: CapabilityErrorKind, context: &'static str) -> Self {
        Self::Capability { kind, context }
    }

    /// Construct a [`NexaCoreError::Identity`] error with the given kind and
    /// static context slug.
    #[must_use]
    pub const fn identity(kind: IdentityErrorKind, context: &'static str) -> Self {
        Self::Identity { kind, context }
    }

    /// Construct a [`NexaCoreError::Ipc`] error with the given kind and
    /// static context slug.
    #[must_use]
    pub const fn ipc(kind: IpcErrorKind, context: &'static str) -> Self {
        Self::Ipc { kind, context }
    }

    /// Construct a [`NexaCoreError::Mesh`] error with the given kind and
    /// static context slug.
    #[must_use]
    pub const fn mesh(kind: MeshErrorKind, context: &'static str) -> Self {
        Self::Mesh { kind, context }
    }

    /// Construct a [`NexaCoreError::Tee`] error with the given kind and
    /// static context slug.
    #[must_use]
    pub const fn tee(kind: TeeErrorKind, context: &'static str) -> Self {
        Self::Tee { kind, context }
    }

    /// Construct a [`NexaCoreError::Hal`] error with the given kind and
    /// static context slug.
    #[must_use]
    pub const fn hal(kind: HalErrorKind, context: &'static str) -> Self {
        Self::Hal { kind, context }
    }

    /// Construct a [`NexaCoreError::Tokenization`] error with the given kind
    /// and static context slug.
    #[must_use]
    pub const fn tokenization(kind: TokenizationErrorKind, context: &'static str) -> Self {
        Self::Tokenization { kind, context }
    }

    /// Construct a [`NexaCoreError::Policy`] error with the given kind and
    /// static context slug.
    #[must_use]
    pub const fn policy(kind: PolicyErrorKind, context: &'static str) -> Self {
        Self::Policy { kind, context }
    }

    /// Construct a [`NexaCoreError::Wire`] error with the given kind and
    /// static context slug.
    #[must_use]
    pub const fn wire(kind: WireErrorKind, context: &'static str) -> Self {
        Self::Wire { kind, context }
    }

    /// Construct a [`NexaCoreError::Internal`] error with the given context
    /// slug. Reserve for unrecoverable invariant violations.
    #[must_use]
    pub const fn internal(context: &'static str) -> Self {
        Self::Internal { context }
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use alloc::format;

    use super::*;

    #[test]
    fn error_display_contains_kind_and_context() {
        let err = NexaCoreError::crypto(CryptoErrorKind::InvalidKey, "aead::seal");
        let s = format!("{err}");
        assert!(s.contains("crypto"));
        assert!(s.contains("InvalidKey"));
        assert!(s.contains("aead::seal"));
    }

    #[test]
    fn error_display_does_not_panic_on_internal() {
        let err = NexaCoreError::internal("scope_intersection_must_not_be_empty");
        let s = format!("{err}");
        assert!(s.contains("internal invariant"));
        assert!(s.contains("scope_intersection_must_not_be_empty"));
    }

    // The PII-safety contract is enforced at the type level: every
    // variant's `context` is `&'static str`, so dynamic data cannot be
    // placed there. The compile-fail test in `tests/compile_fail/` will
    // assert that constructing an error with a runtime String fails to
    // compile (see nexacore-types/tests/trybuild_compile_fail.rs).

    #[test]
    fn result_alias_round_trip() {
        fn returns_ok() -> Result<u32> {
            Ok(42)
        }
        fn returns_err() -> Result<u32> {
            Err(NexaCoreError::policy(PolicyErrorKind::AccessDenied, "test"))
        }
        assert_eq!(returns_ok().unwrap(), 42);
        assert!(returns_err().is_err());
    }

    // Smoke test: each variant builds and Debug-formats.
    #[test]
    fn all_variants_format() {
        let variants: [NexaCoreError; 11] = [
            NexaCoreError::crypto(CryptoErrorKind::DecryptionFailure, "x"),
            NexaCoreError::capability(CapabilityErrorKind::Expired, "x"),
            NexaCoreError::identity(IdentityErrorKind::InvalidLength, "x"),
            NexaCoreError::ipc(IpcErrorKind::ChannelClosed, "x"),
            NexaCoreError::mesh(MeshErrorKind::HandshakeFailed, "x"),
            NexaCoreError::tee(TeeErrorKind::AttestationInvalid, "x"),
            NexaCoreError::hal(HalErrorKind::Io, "x"),
            NexaCoreError::tokenization(TokenizationErrorKind::TokenNotFound, "x"),
            NexaCoreError::policy(PolicyErrorKind::AccessDenied, "x"),
            NexaCoreError::wire(WireErrorKind::DecodeFailed, "x"),
            NexaCoreError::internal("x"),
        ];
        for v in &variants {
            let _ = format!("{v}");
            let _ = format!("{v:?}");
        }
    }
}

// `core::error::Error` impl note: thiserror v2 with `default-features = false`
// derives `core::error::Error` automatically since Rust 1.81. We are on MSRV
// 1.85, so this Just Works. No manual `impl Error` needed.
//
// `core::fmt::Display` is provided by the `#[error(...)]` attribute on each
// variant. We deliberately do not implement custom Display formatting beyond
// the kind+context pair to keep error output predictable for log scrapers.
