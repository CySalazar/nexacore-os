//! OCI image references and the NexaCore extension manifest.
//!
//! See `NCIP-Container-006` § 7 ("OCI image compatibility").
//!
//! `NexaCoreContainer` reads OCI Image Format v1 images directly. Standard
//! Docker / Podman images work without modification; an optional NexaCore
//! extension manifest in the image annotations declares the capability
//! set the image expects, the minimum guest kernel version, and a
//! signing fingerprint.

use crate::ContainerError;

/// Strongly-typed OCI image reference of the form
/// `registry/namespace/name:tag` or `registry/namespace/name@digest`.
///
/// This newtype's purpose is to prevent accidental use of an
/// unvalidated `String` as an image reference at the API boundary. The
/// v0.1 parser performs **structural validation only** (non-empty,
/// reasonable length, contains a `:` or `@`); full OCI reference
/// grammar validation lands in a follow-up NCIP alongside the actual
/// image fetch / cache implementation.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct OciImageRef(String);

impl OciImageRef {
    /// Maximum length we accept for an OCI image reference.
    ///
    /// The OCI distribution spec allows up to 255 characters in the
    /// repository name; we add slack for the digest portion. A more
    /// rigorous parser lands with the OCI fetch implementation.
    pub const MAX_LEN: usize = 512;

    /// Parse an OCI image reference. The current implementation
    /// performs only structural validation; a future NCIP introduces
    /// full OCI reference grammar validation when the image fetch
    /// path lands.
    ///
    /// # Errors
    ///
    /// Returns [`ContainerError::Image`] if `raw` is empty, longer
    /// than [`Self::MAX_LEN`], or does not contain either a `:` (tag)
    /// or `@` (digest) separator.
    pub fn parse(raw: &str) -> Result<Self, ContainerError> {
        if raw.is_empty() {
            return Err(ContainerError::Image("image::parse::empty"));
        }
        if raw.len() > Self::MAX_LEN {
            return Err(ContainerError::Image("image::parse::too_long"));
        }
        if !raw.contains(':') && !raw.contains('@') {
            return Err(ContainerError::Image("image::parse::missing_separator"));
        }
        Ok(Self(raw.to_owned()))
    }

    /// Borrow the raw reference string. Audit-log / tracing use only —
    /// never re-parse this as a fresh `OciImageRef` (call sites
    /// MUST keep the original instance).
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl core::fmt::Display for OciImageRef {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(&self.0)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn parse_accepts_tag_form() {
        let r = OciImageRef::parse("alpine:latest").expect("parses");
        assert_eq!(r.as_str(), "alpine:latest");
    }

    #[test]
    fn parse_accepts_digest_form() {
        let r = OciImageRef::parse(
            "alpine@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        )
        .expect("parses");
        assert!(r.as_str().contains('@'));
    }

    #[test]
    fn parse_accepts_registry_form() {
        let r = OciImageRef::parse("ghcr.io/cysalazar/nexacore-guest-linux:v6.10-stable")
            .expect("parses");
        assert_eq!(
            r.as_str(),
            "ghcr.io/cysalazar/nexacore-guest-linux:v6.10-stable"
        );
    }

    #[test]
    fn parse_rejects_empty() {
        let err = OciImageRef::parse("").expect_err("must reject");
        assert!(matches!(err, ContainerError::Image("image::parse::empty")));
    }

    #[test]
    fn parse_rejects_too_long() {
        let huge = "a".repeat(OciImageRef::MAX_LEN + 1) + ":tag";
        let err = OciImageRef::parse(&huge).expect_err("must reject");
        assert!(matches!(
            err,
            ContainerError::Image("image::parse::too_long")
        ));
    }

    #[test]
    fn parse_rejects_missing_separator() {
        let err = OciImageRef::parse("plainname").expect_err("must reject");
        assert!(matches!(
            err,
            ContainerError::Image("image::parse::missing_separator")
        ));
    }

    #[test]
    fn display_round_trips() {
        let r = OciImageRef::parse("alpine:latest").expect("parses");
        assert_eq!(format!("{r}"), "alpine:latest");
    }
}
