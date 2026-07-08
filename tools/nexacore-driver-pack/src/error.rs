//! Error types for `nexacore-driver-pack`.
//!
//! [`PackError`] covers every failure mode from CLI argument parsing to
//! binary blob output. Each variant is mapped to a documented shell exit
//! code by [`PackError::exit_code`]; callers in `main` use that mapping
//! to exit cleanly rather than panic.

use thiserror::Error;

/// All errors that can occur during `nexacore-driver-pack` operation.
///
/// ## Exit-code mapping
///
/// | Code | Category | Variants |
/// |------|----------|----------|
/// | 1 | Usage / I/O | `MissingArg`, `UnknownArg`, `Io`, `OutputPath` |
/// | 2 | Manifest parse | `ManifestParse`, `InvalidIssuerKeyLen`, `IssuerKeyHexDecode` |
/// | 3 | Signing key | `SigningKeyBadLength`, `SigningKeyHexDecode`, `IssuerKeyMismatch` |
/// | 4 | Pack build / write | `PostcardEncode`, `ManifestTooLarge`, `PackTooLarge`, `OffsetOverflow` |
#[derive(Debug, Error)]
pub enum PackError {
    // -------------------------------------------------------------------------
    // Code 1 — usage / I/O
    // -------------------------------------------------------------------------
    /// A required CLI flag was absent.
    #[error("missing required argument: --{0}")]
    MissingArg(&'static str),

    /// An unrecognized CLI flag was encountered.
    #[error("unknown argument: {0}")]
    UnknownArg(String),

    /// An I/O failure reading or writing a file.
    #[error("I/O error on {path}: {source}")]
    Io {
        /// Path to the file that triggered the error.
        path: String,
        /// Underlying OS error.
        #[source]
        source: std::io::Error,
    },

    /// The output path is unusable (no parent directory or no file-name
    /// component).
    #[error("cannot use output path {path}: {msg}")]
    OutputPath {
        /// The problematic output path as a string.
        path: String,
        /// Human-readable explanation.
        msg: String,
    },

    // -------------------------------------------------------------------------
    // Code 2 — manifest parse
    // -------------------------------------------------------------------------
    /// The JSON manifest could not be deserialized.
    #[error("manifest parse error in {path}: {source}")]
    ManifestParse {
        /// Path to the manifest file.
        path: String,
        /// Underlying `serde_json` error.
        #[source]
        source: serde_json::Error,
    },

    /// The TOML manifest could not be deserialized. Carries the
    /// `toml` crate's error message as a `String` (not as the
    /// concrete `toml::de::Error` type) so the error enum stays
    /// non-`#[non_exhaustive]`-safe across `toml` crate minor
    /// version bumps. New in TASK-007 follow-through.
    #[error("manifest parse error in {path}: {msg}")]
    ManifestParseToml {
        /// Path to the manifest file.
        path: String,
        /// Underlying `toml` crate error message.
        msg: String,
    },

    /// The manifest's `nexacore_issuer_pubkey` field was not exactly 64 hex chars.
    #[error(
        "invalid nexacore_issuer_pubkey in manifest: expected 64 hex chars, \
         got {len} chars (value: {snippet:?}…)"
    )]
    InvalidIssuerKeyLen {
        /// Actual character count.
        len: usize,
        /// First 16 characters of the field for context.
        snippet: String,
    },

    /// The manifest's `nexacore_issuer_pubkey` field contained a non-hex character.
    #[error(
        "invalid nexacore_issuer_pubkey in manifest: non-hex character at byte \
         position {pos} (0-indexed)"
    )]
    IssuerKeyHexDecode {
        /// Byte offset of the offending character in the hex string.
        pos: usize,
    },

    // -------------------------------------------------------------------------
    // Code 3 — signing key
    // -------------------------------------------------------------------------
    /// The `--signing-key` file did not contain exactly 64 hex chars.
    #[error(
        "signing key file has {len} non-whitespace chars; \
         expected exactly 64 (= 32 raw bytes in hex)"
    )]
    SigningKeyBadLength {
        /// Actual character count (after trimming whitespace).
        len: usize,
    },

    /// The `--signing-key` file contained a non-hex character.
    #[error(
        "signing key file contains non-hex character at byte position {pos} \
         (0-indexed)"
    )]
    SigningKeyHexDecode {
        /// Byte offset of the offending character.
        pos: usize,
    },

    /// The verifying key derived from `--signing-key` does not match the
    /// `nexacore_issuer_pubkey` field in the JSON manifest.
    ///
    /// The kernel checks the manifest's `nexacore_issuer_pubkey` against
    /// `KNOWN_ISSUERS` and then verifies the signature under that key.
    /// If the signer's key does not match the declared issuer, the
    /// signature will not verify at `DriverLoad` — this error catches
    /// the inconsistency early.
    #[error(
        "signing key mismatch: manifest declares nexacore_issuer_pubkey = {manifest_pubkey}, \
         but --signing-key corresponds to {signing_key_pubkey}; \
         the kernel would reject this blob (NCIP-013 § S5.4)"
    )]
    IssuerKeyMismatch {
        /// Hex-encoded verifying key declared in the JSON manifest.
        manifest_pubkey: String,
        /// Hex-encoded verifying key derived from the signing seed.
        signing_key_pubkey: String,
    },

    // -------------------------------------------------------------------------
    // Code 4 — pack build / write
    // -------------------------------------------------------------------------
    /// Postcard encoding of `DriverManifestBody` failed.
    #[error("postcard encoding of DriverManifestBody failed: {msg}")]
    PostcardEncode {
        /// Error message from the postcard encoder.
        msg: String,
    },

    /// The postcard-encoded manifest section exceeds the 16 KiB cap from
    /// NCIP-013 § S5.5.
    #[error(
        "manifest.pc is {actual} bytes, exceeds the {limit}-byte cap \
         (NCIP-013 § S5.5)"
    )]
    ManifestTooLarge {
        /// Actual encoded size in bytes.
        actual: usize,
        /// Maximum allowed size.
        limit: u64,
    },

    /// The total `.opack` blob would exceed the 32 MiB cap from
    /// NCIP-013 § S5.2.
    #[error(
        "pack blob would be {actual} bytes, exceeds the {limit}-byte cap \
         (NCIP-013 § S5.2)"
    )]
    PackTooLarge {
        /// Projected total size in bytes.
        actual: u64,
        /// Maximum allowed size.
        limit: u64,
    },

    /// An arithmetic overflow occurred computing a blob section offset.
    ///
    /// In practice this means the manifest or image is impossibly large
    /// (> 2^64 bytes), but the check is present for correctness under all
    /// input combinations.
    #[error(
        "integer overflow computing {section} offset — \
         manifest or image is impossibly large"
    )]
    OffsetOverflow {
        /// Which section (`"signature"`, `"image"`, or `"total"`) triggered
        /// the overflow.
        section: &'static str,
    },
}

impl PackError {
    /// Return the shell exit code appropriate for this error.
    ///
    /// | Code | Category |
    /// |------|----------|
    /// | 1 | Usage or I/O |
    /// | 2 | Manifest parse |
    /// | 3 | Signing key |
    /// | 4 | Pack build / write |
    #[must_use]
    pub fn exit_code(&self) -> i32 {
        match self {
            Self::MissingArg(_)
            | Self::UnknownArg(_)
            | Self::Io { .. }
            | Self::OutputPath { .. } => 1,
            Self::ManifestParse { .. }
            | Self::ManifestParseToml { .. }
            | Self::InvalidIssuerKeyLen { .. }
            | Self::IssuerKeyHexDecode { .. } => 2,
            Self::SigningKeyBadLength { .. }
            | Self::SigningKeyHexDecode { .. }
            | Self::IssuerKeyMismatch { .. } => 3,
            Self::PostcardEncode { .. }
            | Self::ManifestTooLarge { .. }
            | Self::PackTooLarge { .. }
            | Self::OffsetOverflow { .. } => 4,
        }
    }
}
