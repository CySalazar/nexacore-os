//! NexaCore mesh handshake state machine (WS6-03.1).
//!
//! Translates the Tamarin-proven handshake spec (`docs/protocol/handshake.md`,
//! `/protocol-proofs/handshake.spthy` — invariants I1–I8) into an executable,
//! host-testable state machine that layers on top of the Noise substrate
//! ([`crate::mesh_handshake`], WS6-03.2). It drives the `m1 → m2 → m3` exchange
//! (spec §5) and enforces every receiver-side check (spec §4), aborting fatally —
//! and fail-closed — with a reason mapped to the invariant it protects.
//!
//! The cryptography is **not** implemented here: signature verification
//! (`ed25519-dalek verify_strict`, §4.4 → I1), TEE-quote validation (§4.3 → I3),
//! ephemeral-key sanity (§4.2), DH/AEAD/KDF, and cross-session nonce uniqueness
//! (§I4) are performed by the crypto/attestation layer and delivered to this
//! machine as *verified results*. What this machine owns is the protocol logic
//! the proof constrains: message ordering, the protocol-version pin (I7, no
//! silent downgrade), attestation/signature/freshness gating (I1/I3/I4),
//! measurement-root binding (I8), and the handshake timeout (§5). It remains
//! subject to the WS10-03 crypto review before production.

use std::string::String;

/// The pinned protocol version (spec §4.1). Only this version is negotiated.
pub const PROTO_VERSION: &str = "NexaCore-PROTO-v0.2";

/// The removed prior version (spec §4.1): a peer announcing it MUST be rejected
/// (no silent downgrade).
pub const REJECTED_VERSION: &str = "NexaCore-PROTO-v0.1";

/// Default handshake timeout in seconds (spec §5, `T_handshake`).
pub const HANDSHAKE_TIMEOUT_SECS: u64 = 5;

/// The role a party plays in the handshake.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    /// Sends `m1` and `m3`.
    Initiator,
    /// Sends `m2`.
    Responder,
}

/// Why the handshake aborted, each mapped to the invariant / rule it protects
/// (WS6-03.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AbortReason {
    /// Protocol version was not the pinned [`PROTO_VERSION`], or was the removed
    /// [`REJECTED_VERSION`] (I7 / §4.1 — no silent downgrade).
    VersionMismatch,
    /// The peer ephemeral key failed the low-order-point sanity check (§4.2).
    LowOrderEphemeralKey,
    /// TEE quote validation failed (I3 / §4.3).
    AttestationInvalid,
    /// `ed25519` transcript signature verification failed (I1 / §4.4).
    SignatureInvalid,
    /// The peer nonce was not fresh — a replayed quote/handshake (I4).
    ReplayedNonce,
    /// The peer measurement root did not match the local view (I8 / §4.5).
    MeasurementRootMismatch,
    /// The `measurement_ack` did not match on both sides (§3.3).
    MeasurementAckMismatch,
    /// A message arrived out of the expected order (§5).
    OutOfOrder,
    /// The handshake exceeded [`HANDSHAKE_TIMEOUT_SECS`] (§5).
    Timeout,
}

/// The handshake state (spec §5), from one party's perspective.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HandshakeState {
    /// No message exchanged yet.
    Start,
    /// Initiator has sent `m1` and awaits `m2`.
    AwaitingM2,
    /// Responder has accepted `m1`, sent `m2`, and awaits `m3`.
    AwaitingM3,
    /// The handshake completed; the session is active.
    SessionActive,
    /// The handshake aborted (terminal); no further transition succeeds.
    Aborted(AbortReason),
}

/// The verified contents of `m1` the state machine inspects (I1/I3/I4/I7, §4.2).
///
/// The boolean fields are the *results* of the crypto/attestation layer; the
/// `proto_version` is checked by the machine itself (I7).
#[allow(clippy::struct_excessive_bools)] // a bundle of independent verification results
#[derive(Debug, Clone)]
pub struct IncomingM1 {
    /// The peer's declared protocol version (I7).
    pub proto_version: String,
    /// Whether `epk_A` passed the low-order-point check (§4.2).
    pub epk_valid: bool,
    /// Whether `Quote_A` validated (I3 / §4.3).
    pub quote_verified: bool,
    /// Whether `Sig_A(transcript)` verified (I1 / §4.4).
    pub signature_verified: bool,
    /// Whether `nonce_A` is fresh — not a cross-session replay (I4).
    pub nonce_fresh: bool,
}

/// The verified contents of `m2` the state machine inspects (I1/I3/I4/I8, §4.2).
#[allow(clippy::struct_excessive_bools)]
#[derive(Debug, Clone)]
pub struct IncomingM2 {
    /// Whether `epk_B` passed the low-order-point check (§4.2).
    pub epk_valid: bool,
    /// Whether `Quote_B` validated (I3 / §4.3).
    pub quote_verified: bool,
    /// Whether `Sig_B(transcript)` verified (I1 / §4.4).
    pub signature_verified: bool,
    /// Whether `nonce_B` is fresh (I4).
    pub nonce_fresh: bool,
    /// The 32-byte measurement Merkle root `B` committed (I8 / §4.5).
    pub measurement_root: [u8; 32],
}

/// The verified contents of `m3` the state machine inspects (I1, §3.3).
#[derive(Debug, Clone)]
pub struct IncomingM3 {
    /// Whether `Sig_A(transcript)` verified (I1 / §4.4).
    pub signature_verified: bool,
    /// Whether the `measurement_ack` matched the locally-computed value (§3.3).
    pub measurement_ack_matches: bool,
}

/// The NexaCore mesh handshake state machine (WS6-03.1).
#[derive(Debug, Clone)]
pub struct HandshakeMachine {
    role: Role,
    state: HandshakeState,
    local_measurement_root: [u8; 32],
    started_at: u64,
    timeout_secs: u64,
}

impl HandshakeMachine {
    /// A new machine for `role`, started at `now` (Unix seconds), committing the
    /// local measurement root that the peer's root is bound against (I8).
    #[must_use]
    pub fn new(role: Role, local_measurement_root: [u8; 32], now: u64) -> Self {
        Self {
            role,
            state: HandshakeState::Start,
            local_measurement_root,
            started_at: now,
            timeout_secs: HANDSHAKE_TIMEOUT_SECS,
        }
    }

    /// Override the handshake timeout (spec §5 is configurable per deployment).
    #[must_use]
    pub fn with_timeout(mut self, timeout_secs: u64) -> Self {
        self.timeout_secs = timeout_secs;
        self
    }

    /// The current state.
    #[must_use]
    pub fn state(&self) -> HandshakeState {
        self.state
    }

    /// Whether the session is established.
    #[must_use]
    pub fn is_established(&self) -> bool {
        self.state == HandshakeState::SessionActive
    }

    /// Whether the handshake has aborted.
    #[must_use]
    pub fn is_aborted(&self) -> bool {
        matches!(self.state, HandshakeState::Aborted(_))
    }

    /// Record an abort and return its reason.
    fn abort(&mut self, reason: AbortReason) -> Result<(), AbortReason> {
        self.state = HandshakeState::Aborted(reason);
        Err(reason)
    }

    /// Common precheck for every transition: already-aborted is terminal, the
    /// state must be `expected`, the role must be `role`, and the handshake must
    /// not have timed out (§5).
    fn precheck(
        &mut self,
        now: u64,
        role: Role,
        expected: HandshakeState,
    ) -> Result<(), AbortReason> {
        if self.is_aborted() {
            // Stay aborted; report the original reason.
            if let HandshakeState::Aborted(r) = self.state {
                return Err(r);
            }
        }
        if self.role != role || self.state != expected {
            return self.abort(AbortReason::OutOfOrder);
        }
        if now.saturating_sub(self.started_at) > self.timeout_secs {
            return self.abort(AbortReason::Timeout);
        }
        Ok(())
    }

    /// Initiator: send `m1` (`Start → AwaitingM2`).
    ///
    /// # Errors
    ///
    /// [`AbortReason::OutOfOrder`] if not an initiator in `Start`.
    pub fn initiator_send_m1(&mut self, now: u64) -> Result<(), AbortReason> {
        self.precheck(now, Role::Initiator, HandshakeState::Start)?;
        self.state = HandshakeState::AwaitingM2;
        Ok(())
    }

    /// Responder: receive and validate `m1`, then send `m2`
    /// (`Start → AwaitingM3`). Enforces I7, §4.2, I3, I1, I4.
    ///
    /// # Errors
    ///
    /// The matching [`AbortReason`] on the first failed check.
    pub fn responder_recv_m1(&mut self, m1: &IncomingM1, now: u64) -> Result<(), AbortReason> {
        self.precheck(now, Role::Responder, HandshakeState::Start)?;
        self.check_version(&m1.proto_version)?;
        if !m1.epk_valid {
            return self.abort(AbortReason::LowOrderEphemeralKey);
        }
        if !m1.quote_verified {
            return self.abort(AbortReason::AttestationInvalid);
        }
        if !m1.signature_verified {
            return self.abort(AbortReason::SignatureInvalid);
        }
        if !m1.nonce_fresh {
            return self.abort(AbortReason::ReplayedNonce);
        }
        self.state = HandshakeState::AwaitingM3;
        Ok(())
    }

    /// Initiator: receive and validate `m2`, then send `m3`
    /// (`AwaitingM2 → SessionActive`). Enforces §4.2, I3, I1, I4, I8.
    ///
    /// # Errors
    ///
    /// The matching [`AbortReason`] on the first failed check.
    pub fn initiator_recv_m2(&mut self, m2: &IncomingM2, now: u64) -> Result<(), AbortReason> {
        self.precheck(now, Role::Initiator, HandshakeState::AwaitingM2)?;
        if !m2.epk_valid {
            return self.abort(AbortReason::LowOrderEphemeralKey);
        }
        if !m2.quote_verified {
            return self.abort(AbortReason::AttestationInvalid);
        }
        if !m2.signature_verified {
            return self.abort(AbortReason::SignatureInvalid);
        }
        if !m2.nonce_fresh {
            return self.abort(AbortReason::ReplayedNonce);
        }
        // I8: the peer's measurement root must match the local view (§4.5). The
        // Δ_measurement_window refresh/retry is an app-layer concern; the machine
        // is strict/fail-closed.
        if m2.measurement_root != self.local_measurement_root {
            return self.abort(AbortReason::MeasurementRootMismatch);
        }
        self.state = HandshakeState::SessionActive;
        Ok(())
    }

    /// Responder: receive and validate `m3` (`AwaitingM3 → SessionActive`).
    /// Enforces I1 and the `measurement_ack` agreement (§3.3).
    ///
    /// # Errors
    ///
    /// The matching [`AbortReason`] on the first failed check.
    pub fn responder_recv_m3(&mut self, m3: &IncomingM3, now: u64) -> Result<(), AbortReason> {
        self.precheck(now, Role::Responder, HandshakeState::AwaitingM3)?;
        if !m3.signature_verified {
            return self.abort(AbortReason::SignatureInvalid);
        }
        if !m3.measurement_ack_matches {
            return self.abort(AbortReason::MeasurementAckMismatch);
        }
        self.state = HandshakeState::SessionActive;
        Ok(())
    }

    /// I7 / §4.1: the version must be the pinned one; the removed prior version
    /// (and anything else) is rejected — no silent downgrade.
    fn check_version(&mut self, version: &str) -> Result<(), AbortReason> {
        if version != PROTO_VERSION {
            return self.abort(AbortReason::VersionMismatch);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ROOT: [u8; 32] = [7u8; 32];
    const NOW: u64 = 1_000_000;

    fn good_m1() -> IncomingM1 {
        IncomingM1 {
            proto_version: PROTO_VERSION.to_string(),
            epk_valid: true,
            quote_verified: true,
            signature_verified: true,
            nonce_fresh: true,
        }
    }

    fn good_m2() -> IncomingM2 {
        IncomingM2 {
            epk_valid: true,
            quote_verified: true,
            signature_verified: true,
            nonce_fresh: true,
            measurement_root: ROOT,
        }
    }

    fn good_m3() -> IncomingM3 {
        IncomingM3 {
            signature_verified: true,
            measurement_ack_matches: true,
        }
    }

    #[test]
    fn full_handshake_establishes_on_both_sides() {
        // Initiator drives m1 → (recv m2) → active.
        let mut initiator = HandshakeMachine::new(Role::Initiator, ROOT, NOW);
        assert_eq!(initiator.initiator_send_m1(NOW), Ok(()));
        assert_eq!(initiator.state(), HandshakeState::AwaitingM2);
        assert_eq!(initiator.initiator_recv_m2(&good_m2(), NOW), Ok(()));
        assert!(initiator.is_established());

        // Responder drives (recv m1) → (recv m3) → active.
        let mut responder = HandshakeMachine::new(Role::Responder, ROOT, NOW);
        assert_eq!(responder.responder_recv_m1(&good_m1(), NOW), Ok(()));
        assert_eq!(responder.state(), HandshakeState::AwaitingM3);
        assert_eq!(responder.responder_recv_m3(&good_m3(), NOW), Ok(()));
        assert!(responder.is_established());
    }

    #[test]
    fn version_downgrade_is_rejected_no_silent_fallback() {
        let mut responder = HandshakeMachine::new(Role::Responder, ROOT, NOW);
        let mut m1 = good_m1();
        m1.proto_version = REJECTED_VERSION.to_string();
        assert_eq!(
            responder.responder_recv_m1(&m1, NOW),
            Err(AbortReason::VersionMismatch)
        );
        assert!(responder.is_aborted());
        // An unknown version is likewise rejected.
        let mut r2 = HandshakeMachine::new(Role::Responder, ROOT, NOW);
        let mut m1b = good_m1();
        m1b.proto_version = "NexaCore-PROTO-v9.9".to_string();
        assert_eq!(
            r2.responder_recv_m1(&m1b, NOW),
            Err(AbortReason::VersionMismatch)
        );
    }

    #[test]
    fn each_m1_invariant_failure_maps_to_its_reason() {
        let cases = [
            (
                IncomingM1 {
                    epk_valid: false,
                    ..good_m1()
                },
                AbortReason::LowOrderEphemeralKey,
            ),
            (
                IncomingM1 {
                    quote_verified: false,
                    ..good_m1()
                },
                AbortReason::AttestationInvalid,
            ),
            (
                IncomingM1 {
                    signature_verified: false,
                    ..good_m1()
                },
                AbortReason::SignatureInvalid,
            ),
            (
                IncomingM1 {
                    nonce_fresh: false,
                    ..good_m1()
                },
                AbortReason::ReplayedNonce,
            ),
        ];
        for (m1, expected) in cases {
            let mut r = HandshakeMachine::new(Role::Responder, ROOT, NOW);
            assert_eq!(r.responder_recv_m1(&m1, NOW), Err(expected));
            assert!(r.is_aborted());
        }
    }

    #[test]
    fn measurement_root_mismatch_aborts_initiator() {
        let mut initiator = HandshakeMachine::new(Role::Initiator, ROOT, NOW);
        initiator.initiator_send_m1(NOW).ok();
        let mut m2 = good_m2();
        m2.measurement_root = [0u8; 32]; // differs from local ROOT
        assert_eq!(
            initiator.initiator_recv_m2(&m2, NOW),
            Err(AbortReason::MeasurementRootMismatch)
        );
    }

    #[test]
    fn measurement_ack_mismatch_aborts_responder() {
        let mut responder = HandshakeMachine::new(Role::Responder, ROOT, NOW);
        responder.responder_recv_m1(&good_m1(), NOW).ok();
        let mut m3 = good_m3();
        m3.measurement_ack_matches = false;
        assert_eq!(
            responder.responder_recv_m3(&m3, NOW),
            Err(AbortReason::MeasurementAckMismatch)
        );
    }

    #[test]
    fn out_of_order_message_aborts() {
        // Initiator receiving m2 before sending m1.
        let mut initiator = HandshakeMachine::new(Role::Initiator, ROOT, NOW);
        assert_eq!(
            initiator.initiator_recv_m2(&good_m2(), NOW),
            Err(AbortReason::OutOfOrder)
        );
        // Responder receiving m3 before m1.
        let mut responder = HandshakeMachine::new(Role::Responder, ROOT, NOW);
        assert_eq!(
            responder.responder_recv_m3(&good_m3(), NOW),
            Err(AbortReason::OutOfOrder)
        );
    }

    #[test]
    fn timeout_aborts_the_handshake() {
        let mut initiator = HandshakeMachine::new(Role::Initiator, ROOT, NOW);
        initiator.initiator_send_m1(NOW).ok();
        // m2 arrives after the timeout window.
        let late = NOW + HANDSHAKE_TIMEOUT_SECS + 1;
        assert_eq!(
            initiator.initiator_recv_m2(&good_m2(), late),
            Err(AbortReason::Timeout)
        );
        assert!(initiator.is_aborted());
    }

    #[test]
    fn aborted_machine_stays_aborted() {
        let mut responder = HandshakeMachine::new(Role::Responder, ROOT, NOW);
        let mut m1 = good_m1();
        m1.signature_verified = false;
        assert_eq!(
            responder.responder_recv_m1(&m1, NOW),
            Err(AbortReason::SignatureInvalid)
        );
        // Any further transition returns the original abort reason, not success.
        assert_eq!(
            responder.responder_recv_m3(&good_m3(), NOW),
            Err(AbortReason::SignatureInvalid)
        );
        assert!(!responder.is_established());
    }

    #[test]
    fn configurable_timeout_is_honored() {
        let mut initiator = HandshakeMachine::new(Role::Initiator, ROOT, NOW).with_timeout(60);
        initiator.initiator_send_m1(NOW).ok();
        // Within the extended window.
        assert_eq!(initiator.initiator_recv_m2(&good_m2(), NOW + 30), Ok(()));
        assert!(initiator.is_established());
    }
}
