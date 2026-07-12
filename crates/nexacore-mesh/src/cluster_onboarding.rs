//! Personal-cluster device onboarding flow (WS6-01.7).
//!
//! Onboarding is how a new NexaCore device is admitted to the personal cluster:
//! it is the trust-establishment orchestration that ties together the pieces
//! built for WS6-01. A device is admitted only when it clears **every** gate, in
//! order and fail-closed:
//!
//! 1. its certificate chain verifies (a vetted X.509/signature check — WS6-01.4);
//! 2. the certificate satisfies the cluster [`CertProfile`] (WS6-01.4);
//! 3. the certificate binds the node id the device claims;
//! 4. its TEE attestation verifies (WS6-01.6);
//! 5. it does not conflict with an existing pin (WS6-01.8).
//!
//! Only then is the device's identity pinned in the [`TrustStore`] and the device
//! marked onboarded. The pin is the **last** step — never before verification —
//! and onboarding will **not** silently overwrite an existing, different pin (a
//! re-onboard with a new key is a conflict, not automatic trust).
//!
//! The cryptography itself — certificate-chain verification and TEE attestation —
//! lives behind the [`ChainVerifier`] and [`AttestationVerifier`] traits, backed
//! at the app layer by vetted primitives (`ed25519-dalek`, `nexacore-tee`). This
//! module is the pure, host-testable *policy*; the crypto seams and this flow
//! remain subject to the WS10-03 crypto review before production use.

use std::{string::String, vec::Vec};

use crate::{
    cluster_cert::{CertFields, CertProfile, CertViolation},
    cluster_trust::TrustStore,
};

/// Verifies that a certificate's signature chain is anchored in the cluster CA
/// (WS6-01.7).
///
/// Implemented at the app layer over a vetted X.509 / `ed25519-dalek` verifier;
/// the onboarding flow only consults the boolean result.
pub trait ChainVerifier {
    /// Whether `cert`'s chain verifies against the trusted cluster CA.
    fn verify_chain(&self, cert: &CertFields) -> bool;
}

/// Verifies a device's TEE attestation evidence (WS6-01.6/.7).
///
/// Implemented at the app layer over `nexacore-tee` (SEV-SNP / TDX / software
/// fallback); the onboarding flow only consults the boolean result.
pub trait AttestationVerifier {
    /// Whether `evidence` is a valid attestation that binds `node_id`.
    fn verify_attestation(&self, node_id: &str, evidence: &[u8]) -> bool;
}

/// The credentials a device presents when it asks to join the cluster.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceCredentials {
    /// The mesh node id the device claims.
    pub node_id: String,
    /// The device's public-key fingerprint (opaque bytes) to be pinned.
    pub fingerprint: Vec<u8>,
    /// The parsed fields of the device's certificate (WS6-01.4).
    pub cert: CertFields,
    /// The device's TEE attestation evidence (opaque bytes).
    pub attestation_evidence: Vec<u8>,
}

/// Why an onboarding attempt was rejected (WS6-01.7).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OnboardRejection {
    /// The certificate chain did not verify against the cluster CA.
    ChainUnverified,
    /// The certificate did not satisfy the cluster profile.
    CertProfile(Vec<CertViolation>),
    /// The certificate does not bind the node id the device claimed.
    IdentityMismatch,
    /// The device's TEE attestation did not verify.
    AttestationUnverified,
    /// The node id is already pinned to a different fingerprint (a re-onboard
    /// with a new key must be handled explicitly, not silently).
    FingerprintConflict,
}

/// The outcome of an onboarding attempt (WS6-01.7).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OnboardOutcome {
    /// The device passed every gate and its identity was pinned.
    Onboarded {
        /// The onboarded device's node id.
        node_id: String,
        /// The pinned fingerprint.
        fingerprint: Vec<u8>,
    },
    /// The device was rejected, with the reason.
    Rejected(OnboardRejection),
}

impl OnboardOutcome {
    /// Whether the device was successfully onboarded.
    #[must_use]
    pub fn is_onboarded(&self) -> bool {
        matches!(self, Self::Onboarded { .. })
    }
}

/// The onboarding orchestrator: it holds the cluster's certificate profile and a
/// mutable trust store, and admits devices through the fail-closed flow
/// (WS6-01.7).
///
/// Exposes [`onboard`] as the single API the add-device UX (WS7 / WS16) drives.
///
/// [`onboard`]: Onboarding::onboard
pub struct Onboarding<'a> {
    profile: &'a CertProfile,
    trust: &'a mut TrustStore,
}

impl<'a> Onboarding<'a> {
    /// A new orchestrator over `profile` and `trust`.
    pub fn new(profile: &'a CertProfile, trust: &'a mut TrustStore) -> Self {
        Self { profile, trust }
    }

    /// Attempt to onboard a device presenting `creds`, at time `now` (Unix
    /// seconds), using the injected `chain` and `attest` verifiers (WS6-01.7).
    ///
    /// Every gate is checked in order and fail-closed; the identity is pinned
    /// only after all of them pass, and never overwrites a conflicting pin.
    pub fn onboard(
        &mut self,
        creds: &DeviceCredentials,
        now: u64,
        chain: &dyn ChainVerifier,
        attest: &dyn AttestationVerifier,
    ) -> OnboardOutcome {
        // 1. Certificate chain must verify against the cluster CA.
        if !chain.verify_chain(&creds.cert) {
            return OnboardOutcome::Rejected(OnboardRejection::ChainUnverified);
        }
        // 2. Certificate must satisfy the cluster profile.
        if let Err(violations) = self.profile.validate(&creds.cert, now) {
            return OnboardOutcome::Rejected(OnboardRejection::CertProfile(violations));
        }
        // 3. The certificate must bind the node id the device claims.
        if creds.cert.node_id.as_deref() != Some(creds.node_id.as_str()) {
            return OnboardOutcome::Rejected(OnboardRejection::IdentityMismatch);
        }
        // 4. TEE attestation must verify.
        if !attest.verify_attestation(&creds.node_id, &creds.attestation_evidence) {
            return OnboardOutcome::Rejected(OnboardRejection::AttestationUnverified);
        }
        // 5. Must not conflict with an existing pin (no silent key change).
        if let Some(pinned) = self.trust.fingerprint_of(&creds.node_id) {
            if pinned != creds.fingerprint.as_slice() {
                return OnboardOutcome::Rejected(OnboardRejection::FingerprintConflict);
            }
        }
        // All gates passed — pin the identity (the authorised trust step) last.
        self.trust.pin(&creds.node_id, &creds.fingerprint);
        OnboardOutcome::Onboarded {
            node_id: creds.node_id.clone(),
            fingerprint: creds.fingerprint.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cluster_cert::CertFields;

    const CLUSTER: &str = "home-cluster-7f3a";
    const NODE: &str = "node-a1b2c3";
    const NBF: u64 = 1_000_000;
    const NAF: u64 = NBF + 30 * 24 * 60 * 60;
    const NOW: u64 = NBF + 24 * 60 * 60;
    const FP: &[u8] = &[1, 2, 3, 4];

    /// A verifier with a fixed answer.
    struct Fixed(bool);
    impl ChainVerifier for Fixed {
        fn verify_chain(&self, _cert: &CertFields) -> bool {
            self.0
        }
    }
    impl AttestationVerifier for Fixed {
        fn verify_attestation(&self, _node_id: &str, _evidence: &[u8]) -> bool {
            self.0
        }
    }

    fn creds() -> DeviceCredentials {
        DeviceCredentials {
            node_id: NODE.to_string(),
            fingerprint: FP.to_vec(),
            cert: CertFields::conforming(CLUSTER, NODE, NBF, NAF),
            attestation_evidence: vec![0xAA, 0xBB],
        }
    }

    #[test]
    fn full_pass_onboards_and_pins_last() {
        let profile = CertProfile::personal_cluster(CLUSTER);
        let mut trust = TrustStore::new(false); // TOFU off: only onboarding admits
        let ok = Fixed(true);
        let outcome = {
            let mut ob = Onboarding::new(&profile, &mut trust);
            ob.onboard(&creds(), NOW, &ok, &ok)
        };
        assert_eq!(
            outcome,
            OnboardOutcome::Onboarded {
                node_id: NODE.to_string(),
                fingerprint: FP.to_vec(),
            }
        );
        assert!(outcome.is_onboarded());
        // The identity is now pinned and trusted.
        assert!(trust.is_trusted(NODE, FP));
    }

    #[test]
    fn unverified_chain_is_rejected_before_pinning() {
        let profile = CertProfile::personal_cluster(CLUSTER);
        let mut trust = TrustStore::new(false);
        let bad = Fixed(false);
        let ok = Fixed(true);
        let outcome = {
            let mut ob = Onboarding::new(&profile, &mut trust);
            ob.onboard(&creds(), NOW, &bad, &ok)
        };
        assert_eq!(
            outcome,
            OnboardOutcome::Rejected(OnboardRejection::ChainUnverified)
        );
        // Nothing was pinned.
        assert!(!trust.contains(NODE));
    }

    #[test]
    fn nonconforming_certificate_is_rejected() {
        let profile = CertProfile::personal_cluster(CLUSTER);
        let mut trust = TrustStore::new(false);
        let ok = Fixed(true);
        let mut c = creds();
        c.cert.cluster_id = Some("other-cluster".to_string()); // wrong cluster
        let outcome = {
            let mut ob = Onboarding::new(&profile, &mut trust);
            ob.onboard(&c, NOW, &ok, &ok)
        };
        assert!(matches!(
            outcome,
            OnboardOutcome::Rejected(OnboardRejection::CertProfile(_))
        ));
        assert!(!trust.contains(NODE));
    }

    #[test]
    fn certificate_must_bind_the_claimed_node_id() {
        let profile = CertProfile::personal_cluster(CLUSTER);
        let mut trust = TrustStore::new(false);
        let ok = Fixed(true);
        let mut c = creds();
        // The cert binds a different node id than the device claims.
        c.cert.node_id = Some("node-imposter".to_string());
        let outcome = {
            let mut ob = Onboarding::new(&profile, &mut trust);
            ob.onboard(&c, NOW, &ok, &ok)
        };
        assert_eq!(
            outcome,
            OnboardOutcome::Rejected(OnboardRejection::IdentityMismatch)
        );
    }

    #[test]
    fn failed_attestation_is_rejected() {
        let profile = CertProfile::personal_cluster(CLUSTER);
        let mut trust = TrustStore::new(false);
        let ok = Fixed(true);
        let no_attest = Fixed(false);
        let outcome = {
            let mut ob = Onboarding::new(&profile, &mut trust);
            ob.onboard(&creds(), NOW, &ok, &no_attest)
        };
        assert_eq!(
            outcome,
            OnboardOutcome::Rejected(OnboardRejection::AttestationUnverified)
        );
        assert!(!trust.contains(NODE));
    }

    #[test]
    fn conflicting_fingerprint_is_rejected_not_overwritten() {
        let profile = CertProfile::personal_cluster(CLUSTER);
        let mut trust = TrustStore::new(false);
        // The node is already pinned to a different key.
        trust.pin(NODE, &[9, 9, 9, 9]);
        let ok = Fixed(true);
        let outcome = {
            let mut ob = Onboarding::new(&profile, &mut trust);
            ob.onboard(&creds(), NOW, &ok, &ok)
        };
        assert_eq!(
            outcome,
            OnboardOutcome::Rejected(OnboardRejection::FingerprintConflict)
        );
        // The original pin is intact.
        assert_eq!(trust.fingerprint_of(NODE), Some([9, 9, 9, 9].as_slice()));
    }

    #[test]
    fn re_onboarding_the_same_key_is_idempotent() {
        let profile = CertProfile::personal_cluster(CLUSTER);
        let mut trust = TrustStore::new(false);
        let ok = Fixed(true);
        {
            let mut ob = Onboarding::new(&profile, &mut trust);
            assert!(ob.onboard(&creds(), NOW, &ok, &ok).is_onboarded());
        }
        // Presenting the same fingerprint again is accepted (no conflict).
        let mut ob = Onboarding::new(&profile, &mut trust);
        assert!(ob.onboard(&creds(), NOW, &ok, &ok).is_onboarded());
    }
}
