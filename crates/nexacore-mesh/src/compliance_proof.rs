//! Compliance proof envelope handling (WS6-06).
//!
//! Every mesh payload carries a **compliance proof**: an attestation by the
//! producing node that the payload was handled according to NexaCore OS policy
//! (processed inside a TEE, PII tokenized, consent recorded, audit-logged).
//! Honest nodes reject payloads whose proof is missing or invalid (WS6-06.4),
//! so a non-compliant fork cannot pollute the mesh.
//!
//! This module defines the **v1 signature-based proof schema** (WS6-06.1): a
//! [`ComplianceClaim`] bound to a payload, signed by the producer into a
//! [`ComplianceProof`]. A later revision swaps the signature for a transparent
//! STARK (NCIP-Crypto-002, WS6-06.5/.6) behind the same verify interface;
//! generating proofs at payload production (WS6-06.2) and verifying them on
//! receipt (WS6-06.3) build on the types here.
//!
//! # Identity binding
//!
//! As with [`crate::credits`], the proof carries the producer's verifying key
//! and [`verify`](ComplianceProof::verify) checks that the claim's `producer`
//! id equals [`NodeId::from_key_material`] of that key — a node cannot attest
//! compliance on behalf of an identity it does not control.
//!
//! # Wire format
//!
//! On-the-wire encoding is added with the transport (WS6-04.6) under the
//! serialization NCIP; no serde derives are committed here.
//! [`ComplianceClaim::signing_bytes`] is the canonical signed byte layout.

use nexacore_crypto::{
    hash::{HASH_LEN, domain_separated_hash},
    signing::{
        NexaCoreSignature, NexaCoreSigningKey, NexaCoreVerifyingKey, SIGNATURE_LEN,
        VERIFYING_KEY_LEN,
    },
};

use crate::discovery::NodeId;

/// Domain tag for compliance-claim signing bytes (terminated so it cannot be a
/// prefix of the fields that follow).
const CLAIM_DOMAIN: &[u8] = b"nexacore-mesh::compliance-proof::v1\x00";

/// Hash domain binding a claim to the payload it certifies.
const PAYLOAD_DOMAIN: &str = "nexacore-mesh::compliance::payload::v1";

/// The compliance attributes a producer attests about a payload (WS6-06.1).
///
/// Each flag asserts that the corresponding policy control was applied while
/// producing the payload. A receiver's policy decides which flags it requires
/// (WS6-06.4).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
#[allow(
    clippy::struct_excessive_bools,
    reason = "a set of independent policy flags, not state"
)]
pub struct ComplianceAttributes {
    /// The payload was produced inside an attested TEE.
    pub processed_in_tee: bool,
    /// Personally identifiable information was tokenized.
    pub pii_tokenized: bool,
    /// User consent for the processing was recorded.
    pub consent_recorded: bool,
    /// The processing was written to the audit log.
    pub audit_logged: bool,
}

impl ComplianceAttributes {
    /// Pack the flags into a single byte for the canonical signing layout
    /// (bit 0 = `processed_in_tee` … bit 3 = `audit_logged`).
    #[must_use]
    pub fn bits(self) -> u8 {
        u8::from(self.processed_in_tee)
            | (u8::from(self.pii_tokenized) << 1)
            | (u8::from(self.consent_recorded) << 2)
            | (u8::from(self.audit_logged) << 3)
    }

    /// Whether `self` asserts every flag that `required` sets (`self` is a
    /// superset of `required`).
    #[must_use]
    pub fn contains(self, required: Self) -> bool {
        (self.bits() & required.bits()) == required.bits()
    }
}

/// What a compliance proof attests about one mesh payload (WS6-06.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ComplianceClaim {
    /// The node that produced the payload and signs this claim.
    pub producer: NodeId,
    /// `BLAKE3` domain-separated hash of the payload this claim certifies.
    pub payload_hash: [u8; HASH_LEN],
    /// The policy version the producer applied.
    pub policy_version: u32,
    /// The attested compliance controls.
    pub attributes: ComplianceAttributes,
    /// Caller-supplied production time in milliseconds.
    pub timestamp: u64,
}

impl ComplianceClaim {
    /// The `BLAKE3` domain-separated hash binding a claim to `payload`.
    #[must_use]
    pub fn payload_hash(payload: &[u8]) -> [u8; HASH_LEN] {
        domain_separated_hash(PAYLOAD_DOMAIN, payload)
    }

    /// Build a claim certifying `payload`.
    #[must_use]
    pub fn for_payload(
        producer: NodeId,
        payload: &[u8],
        policy_version: u32,
        attributes: ComplianceAttributes,
        timestamp: u64,
    ) -> Self {
        Self {
            producer,
            payload_hash: Self::payload_hash(payload),
            policy_version,
            attributes,
            timestamp,
        }
    }

    /// The canonical, domain-separated bytes the signature covers.
    #[must_use]
    pub fn signing_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(CLAIM_DOMAIN.len() + 32 + HASH_LEN + 4 + 1 + 8);
        buf.extend_from_slice(CLAIM_DOMAIN);
        buf.extend_from_slice(self.producer.as_bytes());
        buf.extend_from_slice(&self.payload_hash);
        buf.extend_from_slice(&self.policy_version.to_le_bytes());
        buf.push(self.attributes.bits());
        buf.extend_from_slice(&self.timestamp.to_le_bytes());
        buf
    }

    /// Sign this claim with the producer's identity key.
    ///
    /// The caller must ensure `self.producer` is the [`NodeId`] derived from
    /// `key`'s verifying key; [`ComplianceProof::verify`] rejects any mismatch.
    #[must_use]
    pub fn sign(&self, key: &NexaCoreSigningKey) -> ComplianceProof {
        let signature = key.sign(&self.signing_bytes());
        ComplianceProof {
            claim: *self,
            signer_key: key.verifying_key().as_bytes(),
            signature: signature.to_bytes(),
        }
    }
}

/// Why a [`ComplianceProof`] failed verification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ProofError {
    /// The embedded producer verifying key is not a valid key.
    #[error("producer verifying key is malformed")]
    InvalidKey,
    /// The claim's `producer` id is not the hash of the signer key.
    #[error("claim producer id does not match the signer key")]
    IdMismatch,
    /// The signature does not match the claim under the producer key.
    #[error("compliance proof signature verification failed")]
    BadSignature,
    /// The claim's payload hash does not match the payload presented.
    #[error("compliance proof does not certify this payload")]
    PayloadMismatch,
}

/// A [`ComplianceClaim`] signed by its producer (WS6-06.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ComplianceProof {
    claim: ComplianceClaim,
    signer_key: [u8; VERIFYING_KEY_LEN],
    signature: [u8; SIGNATURE_LEN],
}

impl ComplianceProof {
    /// The certified claim.
    #[must_use]
    pub const fn claim(&self) -> &ComplianceClaim {
        &self.claim
    }

    /// The producer's verifying key bytes.
    #[must_use]
    pub const fn signer_key(&self) -> &[u8; VERIFYING_KEY_LEN] {
        &self.signer_key
    }

    /// The signature bytes.
    #[must_use]
    pub const fn signature(&self) -> &[u8; SIGNATURE_LEN] {
        &self.signature
    }

    /// Verify the proof: the signer key must be valid, the `producer` id must be
    /// the hash of that key (identity binding), and the signature must match the
    /// canonical [`ComplianceClaim::signing_bytes`].
    ///
    /// This does **not** check that the claim certifies any particular payload —
    /// use [`verify_for_payload`](ComplianceProof::verify_for_payload) for that.
    ///
    /// # Errors
    ///
    /// Returns the [`ProofError`] for the first check that failed.
    pub fn verify(&self) -> Result<(), ProofError> {
        let key = NexaCoreVerifyingKey::from_bytes(&self.signer_key)
            .map_err(|_| ProofError::InvalidKey)?;
        if self.claim.producer != NodeId::from_key_material(&self.signer_key) {
            return Err(ProofError::IdMismatch);
        }
        let signature = NexaCoreSignature::from_bytes(self.signature);
        key.verify(&self.claim.signing_bytes(), &signature)
            .map_err(|_| ProofError::BadSignature)
    }

    /// [`verify`](ComplianceProof::verify) the proof and additionally confirm it
    /// certifies `payload` (the claim's payload hash matches).
    ///
    /// # Errors
    ///
    /// Returns [`ProofError::PayloadMismatch`] if the payload does not match, or
    /// any error from [`verify`](ComplianceProof::verify).
    pub fn verify_for_payload(&self, payload: &[u8]) -> Result<(), ProofError> {
        self.verify()?;
        if self.claim.payload_hash == ComplianceClaim::payload_hash(payload) {
            Ok(())
        } else {
            Err(ProofError::PayloadMismatch)
        }
    }
}

/// A receiver's compliance policy: the minimum bar an incoming payload's proof
/// must clear to be accepted (WS6-06.4).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ReceiverPolicy {
    /// Attributes the producer must have attested (all of them).
    pub required: ComplianceAttributes,
    /// The minimum policy version the producer must have applied.
    pub min_policy_version: u32,
}

impl ReceiverPolicy {
    /// A policy requiring `required` attributes and at least `min_policy_version`.
    #[must_use]
    pub const fn new(required: ComplianceAttributes, min_policy_version: u32) -> Self {
        Self {
            required,
            min_policy_version,
        }
    }
}

/// Why a [`ComplianceEnvelope`] was rejected on receipt (WS6-06.4).
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum AcceptError {
    /// The compliance proof did not verify against the payload.
    #[error("invalid compliance proof: {0}")]
    Proof(#[from] ProofError),
    /// The producer applied an older policy version than the receiver requires.
    #[error("policy version {got} is below the required {required}")]
    PolicyVersionTooOld {
        /// The receiver's minimum policy version.
        required: u32,
        /// The version the producer attested.
        got: u32,
    },
    /// The producer did not attest every attribute the receiver requires.
    #[error("attested attributes do not meet the receiver policy")]
    AttributesNotMet,
}

/// A mesh payload travelling with its compliance proof (WS6-06.2/.3).
///
/// [`seal`](ComplianceEnvelope::seal) wraps a payload at production
/// (WS6-06.2); [`accept`](ComplianceEnvelope::accept) verifies it on receipt
/// against a [`ReceiverPolicy`] and is the rejection point for missing-flag,
/// stale-policy, or cryptographically-invalid payloads (WS6-06.3/.4). A bare
/// payload that arrives without an envelope simply never decodes into one, so
/// it cannot enter an honest node.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ComplianceEnvelope {
    payload: Vec<u8>,
    proof: ComplianceProof,
}

impl ComplianceEnvelope {
    /// Produce an envelope: hash and sign `payload` under the producer's `key`,
    /// attesting `attributes` and `policy_version` (WS6-06.2). The producer id
    /// is derived from `key`, so it always matches the signature.
    #[must_use]
    pub fn seal(
        payload: Vec<u8>,
        key: &NexaCoreSigningKey,
        policy_version: u32,
        attributes: ComplianceAttributes,
        timestamp: u64,
    ) -> Self {
        let vk = key.verifying_key().as_bytes();
        let producer = NodeId::from_key_material(&vk);
        let proof =
            ComplianceClaim::for_payload(producer, &payload, policy_version, attributes, timestamp)
                .sign(key);
        Self { payload, proof }
    }

    /// The carried payload bytes (without verifying — prefer
    /// [`accept`](ComplianceEnvelope::accept)).
    #[must_use]
    pub fn payload(&self) -> &[u8] {
        &self.payload
    }

    /// The attached proof.
    #[must_use]
    pub const fn proof(&self) -> &ComplianceProof {
        &self.proof
    }

    /// Verify the envelope against `policy` and, if it passes, return the
    /// payload (WS6-06.3/.4).
    ///
    /// # Errors
    ///
    /// Returns [`AcceptError::Proof`] if the proof is invalid or does not
    /// certify the payload, [`AcceptError::PolicyVersionTooOld`] if the producer
    /// applied too old a policy, or [`AcceptError::AttributesNotMet`] if a
    /// required attribute was not attested.
    pub fn accept(&self, policy: ReceiverPolicy) -> Result<&[u8], AcceptError> {
        self.proof.verify_for_payload(&self.payload)?;
        let claim = self.proof.claim();
        if claim.policy_version < policy.min_policy_version {
            return Err(AcceptError::PolicyVersionTooOld {
                required: policy.min_policy_version,
                got: claim.policy_version,
            });
        }
        if !claim.attributes.contains(policy.required) {
            return Err(AcceptError::AttributesNotMet);
        }
        Ok(&self.payload)
    }
}

/// Abstract proof-system interface — the producer side (WS6-06.6).
///
/// Decouples proof *generation* from the concrete scheme so v1.x can swap the
/// signature scheme for a transparent STARK (NCIP-Crypto-002) without touching
/// callers. The v1 implementation is [`SignatureProver`]; a STARK prover will
/// implement this trait with its own [`Proof`](ComplianceProver::Proof) type.
pub trait ComplianceProver {
    /// The proof artefact this system produces.
    type Proof;

    /// Produce a proof attesting `claim`.
    fn prove(&self, claim: &ComplianceClaim) -> Self::Proof;
}

/// Abstract proof-system interface — the verifier side (WS6-06.6).
///
/// The counterpart to [`ComplianceProver`]. The v1 implementation is
/// [`SignatureVerifier`].
pub trait ComplianceVerifier {
    /// The proof artefact this system verifies (matches the prover's `Proof`).
    type Proof;
    /// The error returned on a failed verification.
    type Error;

    /// Verify that `proof` is a well-formed, authentic compliance proof.
    ///
    /// # Errors
    ///
    /// Returns [`Self::Error`] if the proof does not verify.
    fn verify(&self, proof: &Self::Proof) -> Result<(), Self::Error>;

    /// Verify that `proof` is authentic *and* certifies `payload`.
    ///
    /// # Errors
    ///
    /// Returns [`Self::Error`] if the proof does not verify or does not bind to
    /// `payload`.
    fn verify_for_payload(&self, proof: &Self::Proof, payload: &[u8]) -> Result<(), Self::Error>;
}

/// The v1 signature-based [`ComplianceProver`] — signs claims with the
/// producer's identity key (WS6-06.6).
pub struct SignatureProver<'k> {
    key: &'k NexaCoreSigningKey,
}

impl<'k> SignatureProver<'k> {
    /// A prover that signs with `key`.
    #[must_use]
    pub const fn new(key: &'k NexaCoreSigningKey) -> Self {
        Self { key }
    }
}

impl ComplianceProver for SignatureProver<'_> {
    type Proof = ComplianceProof;

    fn prove(&self, claim: &ComplianceClaim) -> ComplianceProof {
        claim.sign(self.key)
    }
}

/// The v1 signature-based [`ComplianceVerifier`] (WS6-06.6). Stateless: it
/// checks the signature and identity binding carried in each proof.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct SignatureVerifier;

impl ComplianceVerifier for SignatureVerifier {
    type Proof = ComplianceProof;
    type Error = ProofError;

    fn verify(&self, proof: &ComplianceProof) -> Result<(), ProofError> {
        proof.verify()
    }

    fn verify_for_payload(
        &self,
        proof: &ComplianceProof,
        payload: &[u8],
    ) -> Result<(), ProofError> {
        proof.verify_for_payload(payload)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn keyed_producer() -> (NexaCoreSigningKey, NodeId) {
        let key = NexaCoreSigningKey::generate();
        let id = NodeId::from_key_material(&key.verifying_key().as_bytes());
        (key, id)
    }

    fn attrs() -> ComplianceAttributes {
        ComplianceAttributes {
            processed_in_tee: true,
            pii_tokenized: true,
            consent_recorded: true,
            audit_logged: false,
        }
    }

    #[test]
    fn attribute_bits_pack_each_flag() {
        let a = ComplianceAttributes {
            processed_in_tee: true,
            pii_tokenized: false,
            consent_recorded: true,
            audit_logged: true,
        };
        // bit0 + bit2 + bit3 = 1 + 4 + 8 = 13.
        assert_eq!(a.bits(), 0b1101);
        assert_eq!(ComplianceAttributes::default().bits(), 0);
    }

    #[test]
    fn signing_bytes_are_domain_separated() {
        let (_, producer) = keyed_producer();
        let claim = ComplianceClaim::for_payload(producer, b"payload", 1, attrs(), 0);
        assert!(claim.signing_bytes().starts_with(CLAIM_DOMAIN));
    }

    #[test]
    fn signed_proof_verifies() {
        let (key, producer) = keyed_producer();
        let claim =
            ComplianceClaim::for_payload(producer, b"the-payload", 3, attrs(), 1_700_000_000);
        let proof = claim.sign(&key);
        assert_eq!(proof.verify(), Ok(()));
        assert_eq!(proof.claim(), &claim);
    }

    #[test]
    fn verify_for_payload_matches_only_the_certified_payload() {
        let (key, producer) = keyed_producer();
        let proof =
            ComplianceClaim::for_payload(producer, b"real-payload", 1, attrs(), 0).sign(&key);
        assert_eq!(proof.verify_for_payload(b"real-payload"), Ok(()));
        assert_eq!(
            proof.verify_for_payload(b"other-payload"),
            Err(ProofError::PayloadMismatch)
        );
    }

    #[test]
    fn tampering_with_the_claim_breaks_the_signature() {
        let (key, producer) = keyed_producer();
        let mut proof = ComplianceClaim::for_payload(producer, b"p", 1, attrs(), 0).sign(&key);
        // Forge a higher policy version after signing.
        proof.claim.policy_version = 99;
        assert_eq!(proof.verify(), Err(ProofError::BadSignature));
    }

    #[test]
    fn flipping_an_attribute_breaks_the_signature() {
        let (key, producer) = keyed_producer();
        let mut proof = ComplianceClaim::for_payload(producer, b"p", 1, attrs(), 0).sign(&key);
        proof.claim.attributes.audit_logged = true; // was false
        assert_eq!(proof.verify(), Err(ProofError::BadSignature));
    }

    #[test]
    fn producer_id_not_matching_the_key_is_rejected() {
        let (key, _real) = keyed_producer();
        // Claim a producer id the signer does not control.
        let proof = ComplianceClaim::for_payload(NodeId::ZERO, b"p", 1, attrs(), 0).sign(&key);
        assert_eq!(proof.verify(), Err(ProofError::IdMismatch));
    }

    #[test]
    fn attributes_contains_is_a_superset_check() {
        let all = ComplianceAttributes {
            processed_in_tee: true,
            pii_tokenized: true,
            consent_recorded: true,
            audit_logged: true,
        };
        let need_tee = ComplianceAttributes {
            processed_in_tee: true,
            ..ComplianceAttributes::default()
        };
        assert!(all.contains(need_tee));
        assert!(all.contains(ComplianceAttributes::default()));
        assert!(!need_tee.contains(all));
    }

    // --- Envelope seal / accept (WS6-06.2 / .3 / .4) ------------------------

    #[test]
    fn sealed_envelope_is_accepted_by_a_permissive_policy() {
        let (key, _) = keyed_producer();
        let env = ComplianceEnvelope::seal(b"workload".to_vec(), &key, 2, attrs(), 0);
        assert_eq!(
            env.accept(ReceiverPolicy::default()),
            Ok(b"workload".as_slice())
        );
        assert_eq!(env.payload(), b"workload");
    }

    #[test]
    fn accept_enforces_required_attributes() {
        let (key, _) = keyed_producer();
        // Producer attested everything except audit_logged (see `attrs()`).
        let env = ComplianceEnvelope::seal(b"w".to_vec(), &key, 1, attrs(), 0);
        // Requiring audit_logged → rejected.
        let policy = ReceiverPolicy::new(
            ComplianceAttributes {
                audit_logged: true,
                ..ComplianceAttributes::default()
            },
            0,
        );
        assert_eq!(env.accept(policy), Err(AcceptError::AttributesNotMet));
        // Requiring only TEE processing → accepted.
        let ok_policy = ReceiverPolicy::new(
            ComplianceAttributes {
                processed_in_tee: true,
                ..ComplianceAttributes::default()
            },
            0,
        );
        assert!(env.accept(ok_policy).is_ok());
    }

    #[test]
    fn accept_enforces_minimum_policy_version() {
        let (key, _) = keyed_producer();
        let env = ComplianceEnvelope::seal(b"w".to_vec(), &key, 2, attrs(), 0);
        assert_eq!(
            env.accept(ReceiverPolicy::new(ComplianceAttributes::default(), 5)),
            Err(AcceptError::PolicyVersionTooOld {
                required: 5,
                got: 2,
            })
        );
        assert!(
            env.accept(ReceiverPolicy::new(ComplianceAttributes::default(), 2))
                .is_ok()
        );
    }

    #[test]
    fn accept_rejects_a_tampered_payload() {
        let (key, _) = keyed_producer();
        let mut env = ComplianceEnvelope::seal(b"original".to_vec(), &key, 1, attrs(), 0);
        env.payload = b"tampered".to_vec();
        assert_eq!(
            env.accept(ReceiverPolicy::default()),
            Err(AcceptError::Proof(ProofError::PayloadMismatch))
        );
    }

    #[test]
    fn accept_rejects_a_tampered_proof() {
        let (key, _) = keyed_producer();
        let mut env = ComplianceEnvelope::seal(b"w".to_vec(), &key, 1, attrs(), 0);
        env.proof.claim.policy_version = 99; // break the signature
        assert_eq!(
            env.accept(ReceiverPolicy::default()),
            Err(AcceptError::Proof(ProofError::BadSignature))
        );
    }

    // --- Abstract proof-system interface (WS6-06.6) -------------------------

    /// Generic helper: attest a claim through any prover, demonstrating the
    /// interface is usable without knowing the concrete scheme.
    fn attest<P: ComplianceProver>(prover: &P, claim: &ComplianceClaim) -> P::Proof {
        prover.prove(claim)
    }

    #[test]
    fn signature_scheme_implements_the_abstract_interface() {
        let (key, producer) = keyed_producer();
        let claim = ComplianceClaim::for_payload(producer, b"payload", 1, attrs(), 0);

        let prover = SignatureProver::new(&key);
        let proof = attest(&prover, &claim);

        let verifier = SignatureVerifier;
        assert_eq!(verifier.verify(&proof), Ok(()));
        assert_eq!(verifier.verify_for_payload(&proof, b"payload"), Ok(()));
        assert_eq!(
            verifier.verify_for_payload(&proof, b"wrong"),
            Err(ProofError::PayloadMismatch)
        );
    }

    #[test]
    fn abstract_verifier_rejects_a_forged_proof() {
        let (key, _) = keyed_producer();
        // A claim whose producer id does not match the signing key.
        let claim = ComplianceClaim::for_payload(NodeId::ZERO, b"p", 1, attrs(), 0);
        let proof = SignatureProver::new(&key).prove(&claim);
        assert_eq!(
            SignatureVerifier.verify(&proof),
            Err(ProofError::IdMismatch)
        );
    }
}
