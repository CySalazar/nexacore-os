//! Personal-cluster mTLS certificate profile (WS6-01.4).
//!
//! The Tier-1 personal cluster authenticates its devices to one another with
//! mutual TLS. This module defines the *profile* those certificates must satisfy
//! — the semantic policy, not the cryptography: naming/identity binding, a
//! bounded validity window, the right key-usage and extended-key-usage bits, and
//! membership in the expected cluster.
//!
//! Signature-chain verification (that the certificate is genuinely signed by the
//! cluster CA) is done by a vetted X.509/crypto library and is out of scope here
//! — and under the WS10-03 crypto review. [`CertFields`] models the already-
//! parsed, already-verified fields of such a certificate; [`CertProfile::validate`]
//! then checks them against the cluster's policy, collecting *every* violation so
//! an operator sees all problems at once rather than one at a time.

use std::{string::String, vec::Vec};

/// The X.509 `KeyUsage` bits relevant to an mTLS endpoint certificate.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct KeyUsage {
    /// The `digitalSignature` bit (required for TLS 1.3 signatures).
    pub digital_signature: bool,
    /// The `keyEncipherment` bit (RSA key transport; unused by ECDHE suites).
    pub key_encipherment: bool,
    /// The `keyAgreement` bit (ECDH key agreement).
    pub key_agreement: bool,
}

/// The `ExtendedKeyUsage` purposes relevant to mutual TLS.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ExtKeyUsage {
    /// The `id-kp-clientAuth` purpose.
    pub client_auth: bool,
    /// The `id-kp-serverAuth` purpose.
    pub server_auth: bool,
}

/// The already-parsed, already-verified fields of a cluster certificate that the
/// profile inspects (WS6-01.4).
///
/// This deliberately carries only the semantic fields the *policy* cares about;
/// the raw certificate, its signature and its chain are handled upstream.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertFields {
    /// The mesh node id the certificate binds to (from the subject / a SAN URI).
    pub node_id: Option<String>,
    /// The cluster id the certificate declares membership in.
    pub cluster_id: Option<String>,
    /// `notBefore` as a Unix timestamp (seconds).
    pub not_before: u64,
    /// `notAfter` as a Unix timestamp (seconds).
    pub not_after: u64,
    /// Whether this is a CA certificate (endpoints must present a leaf).
    pub is_ca: bool,
    /// The certificate's `KeyUsage` bits.
    pub key_usage: KeyUsage,
    /// The certificate's `ExtendedKeyUsage` purposes.
    pub ext_key_usage: ExtKeyUsage,
}

impl CertFields {
    /// A minimal fields set that conforms to [`CertProfile::personal_cluster`]
    /// for `cluster_id`/`node_id`, valid across `[not_before, not_after]`.
    ///
    /// Useful as a starting point (in tests and tooling) to then mutate one
    /// field and observe the resulting violation.
    #[must_use]
    pub fn conforming(cluster_id: &str, node_id: &str, not_before: u64, not_after: u64) -> Self {
        Self {
            node_id: Some(node_id.to_string()),
            cluster_id: Some(cluster_id.to_string()),
            not_before,
            not_after,
            is_ca: false,
            key_usage: KeyUsage {
                digital_signature: true,
                key_encipherment: false,
                key_agreement: true,
            },
            ext_key_usage: ExtKeyUsage {
                client_auth: true,
                server_auth: true,
            },
        }
    }
}

/// A way in which a certificate fails the [`CertProfile`] (WS6-01.4).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CertViolation {
    /// `now` is before `notBefore`.
    NotYetValid,
    /// `now` is after `notAfter`.
    Expired,
    /// `notAfter` is before `notBefore` — a nonsensical validity window.
    InvalidValidityWindow,
    /// The validity period exceeds the profile's maximum (certs must be
    /// short-lived so they rotate).
    ValidityTooLong,
    /// No node id is bound in the certificate.
    MissingNodeId,
    /// The certificate declares a different cluster than expected.
    ClusterMismatch {
        /// The cluster id the profile requires.
        expected: String,
        /// The cluster id the certificate declared, if any.
        found: Option<String>,
    },
    /// The certificate is a CA certificate but a leaf was required.
    IsCa,
    /// The `digitalSignature` `KeyUsage` bit is missing.
    MissingDigitalSignature,
    /// The `clientAuth` `ExtendedKeyUsage` is missing (mTLS needs it).
    MissingClientAuth,
    /// The `serverAuth` `ExtendedKeyUsage` is missing (mTLS needs it).
    MissingServerAuth,
}

/// The certificate profile a personal-cluster mTLS endpoint certificate must
/// satisfy (WS6-01.4).
// The four `require_*`/`reject_*` fields are independent policy toggles, not a
// state machine — a struct of flags is the clearest model.
#[allow(clippy::struct_excessive_bools)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertProfile {
    /// The cluster the certificate must belong to.
    pub cluster_id: String,
    /// The maximum allowed validity period, in seconds.
    pub max_validity_secs: u64,
    /// Require the `digitalSignature` `KeyUsage` bit.
    pub require_digital_signature: bool,
    /// Require the `clientAuth` `ExtendedKeyUsage`.
    pub require_client_auth: bool,
    /// Require the `serverAuth` `ExtendedKeyUsage`.
    pub require_server_auth: bool,
    /// Reject CA certificates (endpoints must present a leaf).
    pub reject_ca: bool,
}

/// 90 days in seconds — the default maximum validity for a cluster endpoint
/// certificate (short-lived, so compromise windows and rotation stay tight).
pub const DEFAULT_MAX_VALIDITY_SECS: u64 = 90 * 24 * 60 * 60;

impl CertProfile {
    /// The default personal-cluster endpoint profile for `cluster_id`: a
    /// short-lived leaf certificate that binds a node id and is valid for both
    /// TLS roles (mutual auth).
    #[must_use]
    pub fn personal_cluster(cluster_id: &str) -> Self {
        Self {
            cluster_id: cluster_id.to_string(),
            max_validity_secs: DEFAULT_MAX_VALIDITY_SECS,
            require_digital_signature: true,
            require_client_auth: true,
            require_server_auth: true,
            reject_ca: true,
        }
    }

    /// Validate `fields` against this profile at time `now` (Unix seconds),
    /// returning every violation found (WS6-01.4).
    ///
    /// # Errors
    ///
    /// Returns the non-empty list of [`CertViolation`]s when the certificate
    /// does not conform; `Ok(())` when it satisfies every rule.
    pub fn validate(&self, fields: &CertFields, now: u64) -> Result<(), Vec<CertViolation>> {
        let mut v = Vec::new();

        // Validity window.
        if now < fields.not_before {
            v.push(CertViolation::NotYetValid);
        }
        if now > fields.not_after {
            v.push(CertViolation::Expired);
        }
        if fields.not_after < fields.not_before {
            v.push(CertViolation::InvalidValidityWindow);
        } else if fields.not_after - fields.not_before > self.max_validity_secs {
            v.push(CertViolation::ValidityTooLong);
        }

        // Identity binding.
        if fields.node_id.as_deref().unwrap_or("").is_empty() {
            v.push(CertViolation::MissingNodeId);
        }
        if fields.cluster_id.as_deref() != Some(self.cluster_id.as_str()) {
            v.push(CertViolation::ClusterMismatch {
                expected: self.cluster_id.clone(),
                found: fields.cluster_id.clone(),
            });
        }

        // Constraints / usage.
        if self.reject_ca && fields.is_ca {
            v.push(CertViolation::IsCa);
        }
        if self.require_digital_signature && !fields.key_usage.digital_signature {
            v.push(CertViolation::MissingDigitalSignature);
        }
        if self.require_client_auth && !fields.ext_key_usage.client_auth {
            v.push(CertViolation::MissingClientAuth);
        }
        if self.require_server_auth && !fields.ext_key_usage.server_auth {
            v.push(CertViolation::MissingServerAuth);
        }

        if v.is_empty() { Ok(()) } else { Err(v) }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const CLUSTER: &str = "home-cluster-7f3a";
    const NODE: &str = "node-a1b2c3";
    // A validity window well within the 90-day default.
    const NBF: u64 = 1_000_000;
    const NAF: u64 = NBF + 30 * 24 * 60 * 60; // +30 days
    const NOW: u64 = NBF + 24 * 60 * 60; // 1 day in

    fn violations(p: &CertProfile, f: &CertFields, now: u64) -> Vec<CertViolation> {
        match p.validate(f, now) {
            Ok(()) => Vec::new(),
            Err(v) => v,
        }
    }

    #[test]
    fn conforming_certificate_passes() {
        let p = CertProfile::personal_cluster(CLUSTER);
        let f = CertFields::conforming(CLUSTER, NODE, NBF, NAF);
        assert!(p.validate(&f, NOW).is_ok());
    }

    #[test]
    fn expired_and_not_yet_valid_are_detected() {
        let p = CertProfile::personal_cluster(CLUSTER);
        let f = CertFields::conforming(CLUSTER, NODE, NBF, NAF);
        assert!(violations(&p, &f, NBF - 1).contains(&CertViolation::NotYetValid));
        assert!(violations(&p, &f, NAF + 1).contains(&CertViolation::Expired));
    }

    #[test]
    fn overlong_validity_is_rejected() {
        let p = CertProfile::personal_cluster(CLUSTER);
        // 200 days > 90-day maximum.
        let f = CertFields::conforming(CLUSTER, NODE, NBF, NBF + 200 * 24 * 60 * 60);
        assert!(violations(&p, &f, NOW).contains(&CertViolation::ValidityTooLong));
    }

    #[test]
    fn inverted_validity_window_is_rejected() {
        let p = CertProfile::personal_cluster(CLUSTER);
        let mut f = CertFields::conforming(CLUSTER, NODE, NBF, NAF);
        f.not_after = NBF - 1; // notAfter before notBefore
        let vs = violations(&p, &f, NOW);
        assert!(vs.contains(&CertViolation::InvalidValidityWindow));
        // An inverted window must not also be reported as merely too long.
        assert!(!vs.contains(&CertViolation::ValidityTooLong));
    }

    #[test]
    fn missing_node_id_is_detected() {
        let p = CertProfile::personal_cluster(CLUSTER);
        let mut f = CertFields::conforming(CLUSTER, NODE, NBF, NAF);
        f.node_id = None;
        assert!(violations(&p, &f, NOW).contains(&CertViolation::MissingNodeId));
        f.node_id = Some(String::new()); // empty is also missing
        assert!(violations(&p, &f, NOW).contains(&CertViolation::MissingNodeId));
    }

    #[test]
    fn cluster_mismatch_reports_expected_and_found() {
        let p = CertProfile::personal_cluster(CLUSTER);
        let mut f = CertFields::conforming(CLUSTER, NODE, NBF, NAF);
        f.cluster_id = Some("other-cluster".to_string());
        assert!(
            violations(&p, &f, NOW).contains(&CertViolation::ClusterMismatch {
                expected: CLUSTER.to_string(),
                found: Some("other-cluster".to_string()),
            })
        );
    }

    #[test]
    fn ca_certificate_is_rejected_for_endpoints() {
        let p = CertProfile::personal_cluster(CLUSTER);
        let mut f = CertFields::conforming(CLUSTER, NODE, NBF, NAF);
        f.is_ca = true;
        assert!(violations(&p, &f, NOW).contains(&CertViolation::IsCa));
    }

    #[test]
    fn mtls_requires_both_client_and_server_auth() {
        let p = CertProfile::personal_cluster(CLUSTER);
        let mut f = CertFields::conforming(CLUSTER, NODE, NBF, NAF);
        f.ext_key_usage.server_auth = false;
        assert!(violations(&p, &f, NOW).contains(&CertViolation::MissingServerAuth));
        f.ext_key_usage.client_auth = false;
        let vs = violations(&p, &f, NOW);
        assert!(vs.contains(&CertViolation::MissingClientAuth));
        assert!(vs.contains(&CertViolation::MissingServerAuth));
    }

    #[test]
    fn missing_digital_signature_is_detected() {
        let p = CertProfile::personal_cluster(CLUSTER);
        let mut f = CertFields::conforming(CLUSTER, NODE, NBF, NAF);
        f.key_usage.digital_signature = false;
        assert!(violations(&p, &f, NOW).contains(&CertViolation::MissingDigitalSignature));
    }

    #[test]
    fn all_violations_accumulate() {
        let p = CertProfile::personal_cluster(CLUSTER);
        // Broken in several ways at once.
        let f = CertFields {
            node_id: None,
            cluster_id: None,
            not_before: NBF,
            not_after: NBF - 1, // inverted
            is_ca: true,
            key_usage: KeyUsage::default(),
            ext_key_usage: ExtKeyUsage::default(),
        };
        let vs = violations(&p, &f, NOW);
        // Every independent rule fired.
        assert!(vs.contains(&CertViolation::InvalidValidityWindow));
        assert!(vs.contains(&CertViolation::MissingNodeId));
        assert!(vs.contains(&CertViolation::IsCa));
        assert!(vs.contains(&CertViolation::MissingDigitalSignature));
        assert!(vs.contains(&CertViolation::MissingClientAuth));
        assert!(vs.contains(&CertViolation::MissingServerAuth));
        assert!(vs.len() >= 6);
    }
}
