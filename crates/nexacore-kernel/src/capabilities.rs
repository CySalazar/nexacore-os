//! Kernel-side capability validation and minting.
//!
//! ## Status
//!
//! Two layers coexist here:
//!
//! 1. **Long-term capability table (P6.5+ scaffold).** Master signing
//!    keys held in TPM/Secure Enclave, indexed by `KernelCapabilityId`.
//!    Trait surface only; implementation lands with `nexacore-capability`
//!    integration (MB13+).
//! 2. **MB12 / MB13 IPC capability check.** The
//!    [`KernelCapabilityCheck`] trait + [`Ed25519CapabilityProvider`]
//!    implementation enable cross-process IPC gating. `Ed25519CapabilityProvider`
//!    is the canonical boot-time provider as of MB13.e; its per-IPC
//!    `verify` impl is O(1) shape-matching, while one-shot signature /
//!    time-window / TEE-binding verification happens at channel
//!    creation via `verify_signed_token`. The historical
//!    `StubCapabilityProvider` survives only behind `#[cfg(test)]` for
//!    unit-test scaffolding. ADR-0005 captures the original security
//!    argument; ADR-0006 documents the MB13.e migration closure.
//!
//! ## Design rationale (long-term, layer 1)
//!
//! - **Master signing keys never leave the kernel.** The kernel holds
//!   the signing keys inside the TPM or Secure Enclave; minting a
//!   capability requires the kernel to sign on behalf of an authorized
//!   caller. This makes the kernel's TCB the root of all capability
//!   trust.
//! - **Revocation lists.** A short-TTL revocation list per (subject,
//!   action) pair invalidates leaked capabilities quickly without
//!   storing them all.
//! - **TEE binding.** A capability is valid only when invoked from
//!   inside the TEE whose attestation the capability was minted
//!   against. The kernel cross-checks the calling TEE measurement on
//!   every validation.

#![allow(
    clippy::missing_errors_doc,
    reason = "trait scaffold methods return NotYetImplemented until NCIP activates P6.5+"
)]

use crate::KernelResult;

// -----------------------------------------------------------------------------
// Capability identifier (kernel-side)
// -----------------------------------------------------------------------------

/// Kernel-internal capability identifier. Maps 1:1 to the userspace
/// `nexacore_capability::token::CapabilityId` but lives in a separate type
/// to prevent accidental confusion across the boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct KernelCapabilityId(pub u128);

// -----------------------------------------------------------------------------
// Capability table trait
// -----------------------------------------------------------------------------

/// Kernel capability table. Holds minted capabilities indexed by ID,
/// plus the revocation list.
pub trait CapabilityTable {
    /// Validates that `id` is currently a valid capability. Returns
    /// `Ok(())` if valid, `Err(CapabilityDenied)` otherwise. The
    /// implementation MUST also check that the calling TEE measurement
    /// matches the measurement the capability was minted against.
    fn validate(&self, id: KernelCapabilityId) -> KernelResult<()>;

    /// Records a capability as revoked. Subsequent `validate` calls
    /// for this id return `CapabilityDenied`.
    fn revoke(&mut self, id: KernelCapabilityId) -> KernelResult<()>;

    /// Returns the current size of the revocation list. Useful for
    /// alerting on suspicious activity (e.g., mass revocation).
    fn revocation_list_size(&self) -> usize;
}

// =============================================================================
// MB12 — Lightweight IPC capability check
// =============================================================================
//
// What's here, and what's not:
//
// - Subject identifier ([`KernelPrincipal`]) — a 32-byte opaque hash that
//   names a userspace authority. The kernel does not interpret the bits;
//   it only compares two principals for equality.
// - A two-variant [`KernelAction`] enum (`IpcSend` / `IpcRecv`) and a
//   one-variant [`KernelResource`] enum (`IpcChannel(u64)`). Mirror of
//   `nexacore-capability`'s vocabulary, restricted to what MB12 actually
//   uses.
// - A [`KernelCapabilityCheck`] trait + the canonical
//   [`Ed25519CapabilityProvider`] implementation. Per-IPC checks are
//   O(1) shape-matching on action/resource; full Ed25519 signature
//   verification + time window + TEE binding happens once per channel
//   at creation via `verify_signed_token`. The legacy
//   `StubCapabilityProvider` is `#[cfg(test)]`-only as of MB13.e.
//
// Why this is sound enough for Phase 1:
//
// - The `MessageEnvelope::sender` field is stamped by the kernel from
//   the active task id at SYSCALL entry, so it cannot be forged from
//   userspace.
// - Per-process CR3 (MB11) means a process cannot read or write another
//   process's address space without going through these syscalls — the
//   capability check is the only gate.
// - The token is held entirely inside the kernel after
//   `IpcCreateChannel`. Userspace cannot replay or mutate it.

/// 32-byte opaque principal identifier.
///
/// In MB13, this becomes a thin wrapper around
/// `nexacore_types::identity::NodeId`. For MB12 the kernel only needs byte
/// equality, so the bare-bones newtype here keeps `nexacore-types` (with
/// `id-generation` → `getrandom`) out of the kernel's bare-metal build.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct KernelPrincipal([u8; 32]);

impl KernelPrincipal {
    /// Construct a principal from a raw 32-byte hash.
    ///
    /// `from_bytes([0; 32])` is the conventional "unauthenticated kernel
    /// task" principal used for `kmain`, the idle task, and any
    /// kernel-spawned worker that has no userspace counterpart.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Borrow the underlying bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// The all-zero principal — kernel-internal tasks (idle, bootstrap)
    /// adopt this so they can hold a PCB-shaped principal field without
    /// any authentication step.
    pub const ZERO: Self = Self([0u8; 32]);
}

/// What an IPC capability authorises.
///
/// MB12 only needs the send/recv pair; expanding the enum is an
/// `#[non_exhaustive]`-friendly additive change.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum KernelAction {
    /// May enqueue a message on the channel.
    IpcSend,
    /// May dequeue messages from the channel.
    IpcRecv,
}

/// The resource a [`KernelAction`] applies to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum KernelResource {
    /// A specific IPC channel, identified by its kernel-allocated id.
    IpcChannel(u64),
}

/// Kernel-side capability token presented at `IpcCreateChannel`.
///
/// The kernel stores `subject` inside the channel entry (one slot per
/// direction) and compares each subsequent send/recv against the
/// running task's PCB principal.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct KernelCapabilityToken {
    /// The authorised principal.
    pub subject: KernelPrincipal,
    /// The authorised action.
    pub action: KernelAction,
    /// The resource the action applies to.
    pub resource: KernelResource,
}

/// Verification outcome.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CapabilityVerdict {
    /// The token is valid and authorises the requested action.
    Authorised,
    /// The token is rejected (signature failed in MB13; action/resource
    /// shape mismatch in MB12).
    Denied,
}

/// Kernel-side capability verifier.
///
/// The canonical production implementation is
/// [`Ed25519CapabilityProvider`] — it runs real Ed25519 signature +
/// time-window + TEE-binding verification at channel creation, then
/// falls back to O(1) action/resource shape-matching for the per-IPC
/// hot path. `StubCapabilityProvider` remains as a `#[cfg(test)]`-only
/// mock for unit tests that do not need to exercise the signature
/// path.
pub trait KernelCapabilityCheck {
    /// Verify that `token` authorises `action` on `resource`.
    fn verify(
        &self,
        token: &KernelCapabilityToken,
        action: KernelAction,
        resource: KernelResource,
    ) -> CapabilityVerdict;
}

/// Test-only mock that trusts the token verbatim.
///
/// Verifies only that the token's `action`/`resource` fields match
/// the requested operation. Kept behind `#[cfg(test)]` so it cannot
/// be reached from production boot wiring —
/// [`Ed25519CapabilityProvider`] is the canonical provider as of
/// MB13.e. Used by unit tests that want shape-match semantics
/// without dragging the Ed25519 verification path into the assertion.
#[cfg(test)]
#[derive(Debug, Default, Clone, Copy)]
pub struct StubCapabilityProvider;

#[cfg(test)]
impl KernelCapabilityCheck for StubCapabilityProvider {
    fn verify(
        &self,
        token: &KernelCapabilityToken,
        action: KernelAction,
        resource: KernelResource,
    ) -> CapabilityVerdict {
        if token.action == action && token.resource == resource {
            CapabilityVerdict::Authorised
        } else {
            CapabilityVerdict::Denied
        }
    }
}

// =============================================================================
// MB13.c — Ed25519CapabilityProvider
// =============================================================================
//
// What this delivers vs. what's still pending:
//
// - **Delivered (MB13.c):** real Ed25519 signature verification of
//   `nexacore_capability::CapabilityToken` blobs presented to the kernel.
//   The provider also wraps the existing per-IPC shape-matching path so
//   it is a drop-in replacement for the legacy stub without touching
//   the IPC registry.
// - **Delivered (MB13.d):** the `IpcCreateChannel` syscall ABI extension
//   that plumbs signed tokens from user space into the kernel and runs
//   them through `verify_signed_token` at channel creation.
// - **Delivered (MB13.e):** the boot wiring now hands an
//   `Ed25519CapabilityProvider` to every `IpcCreateChannel` path; the
//   historical `StubCapabilityProvider` is `#[cfg(test)]`-only.
//
// Design rationale:
//
// - Per-IPC checks (`KernelCapabilityCheck::verify`) stay O(1) shape
//   matching — re-verifying an Ed25519 signature on every IPC send/recv
//   would add ~50 µs per call (RustCrypto soft backend on bare-metal)
//   for no security benefit, because the signature is invariant once
//   accepted at channel creation.
// - Signature verification is exposed as a dedicated method
//   `verify_signed_token` that the MB13.d `IpcCreateChannel` handler
//   will call ONCE per channel.
// - The provider carries the kernel's own `NodeId` (used as the TEE
//   attestation source against which `payload.subject` is matched).
//   For MB13.c this is a fixed all-zero placeholder until `nexacore-tee`
//   (P5) supplies a real attested identity.

/// MB13.c — Ed25519-backed capability verifier.
///
/// Verifies the signature, time window, and TEE-binding of an
/// [`nexacore_capability::CapabilityToken`] by delegating to
/// [`nexacore_capability::CapabilityToken::verify_full`] with a fixed
/// `StubAttestation` sourced from `self.node_id` and an empty
/// `RevocationList`. Per-IPC checks fall back to the same
/// shape-matching semantics as the test-only `StubCapabilityProvider`.
#[derive(Debug, Clone, Copy)]
pub struct Ed25519CapabilityProvider {
    /// `NodeId` this kernel claims as its TEE attestation identity. For
    /// MB13.c this is the all-zero placeholder; a real attested value
    /// will come from `nexacore-tee` (P5) once a TEE backend lands.
    node_id_bytes: [u8; 32],
}

impl Ed25519CapabilityProvider {
    /// Construct a provider bound to the supplied 32-byte TEE
    /// attestation hash.
    #[must_use]
    pub const fn with_node_id(node_id_bytes: [u8; 32]) -> Self {
        Self { node_id_bytes }
    }

    /// Construct a provider bound to the all-zero placeholder node id.
    /// MB13.c uses this until `nexacore-tee` provides a real attested id.
    #[must_use]
    pub const fn placeholder() -> Self {
        Self::with_node_id([0u8; 32])
    }

    /// Borrow the 32-byte TEE attestation hash this provider claims.
    /// Used by `DriverLoad` (P6.7.8.9) to set the `subject` of every
    /// minted capability token so it verifies under this provider.
    #[must_use]
    pub const fn node_id_bytes(&self) -> [u8; 32] {
        self.node_id_bytes
    }

    /// Verify the token's signature only (no time / TEE / revocation
    /// checks).
    ///
    /// Used by tests and by paths that have already validated the time
    /// window through a separate clock source.
    #[must_use]
    #[allow(
        clippy::unused_self,
        reason = "Signature verification reads the token's embedded `issuer` key only; the \
                  provider's stored `node_id_bytes` becomes relevant only in `verify_signed_token`. \
                  Keeping the method on `&self` mirrors the `verify_signed_token` shape so callers \
                  can swap between the two without restructuring."
    )]
    pub fn verify_signature_only(
        &self,
        token: &nexacore_capability::CapabilityToken,
    ) -> CapabilityVerdict {
        match token.verify_signature() {
            Ok(()) => CapabilityVerdict::Authorised,
            Err(_) => CapabilityVerdict::Denied,
        }
    }

    /// Full verification: signature, time window, TEE binding, and
    /// revocation status — i.e. exactly what
    /// [`nexacore_capability::CapabilityToken::verify_full`] checks.
    ///
    /// The TEE attestation source is a `StubAttestation` bound to
    /// `self.node_id_bytes`; the revocation list is empty (per-channel
    /// revocation lands with MB13.d). Callers MUST supply a monotonic
    /// `now` — at boot the kernel uses RTC seconds via
    /// `crate::bare_metal::arch::rtc_seconds`.
    #[must_use]
    pub fn verify_signed_token(
        &self,
        token: &nexacore_capability::CapabilityToken,
        now: u64,
    ) -> CapabilityVerdict {
        let attestation = nexacore_capability::tee::StubAttestation {
            fixed_node_id: nexacore_types::identity::NodeId::from_attestation_hash(
                self.node_id_bytes,
            ),
        };
        let revocation = nexacore_capability::revocation::RevocationList::new();
        match token.verify_full(now, &attestation, &revocation) {
            Ok(()) => CapabilityVerdict::Authorised,
            Err(_) => CapabilityVerdict::Denied,
        }
    }
}

impl Default for Ed25519CapabilityProvider {
    fn default() -> Self {
        Self::placeholder()
    }
}

impl KernelCapabilityCheck for Ed25519CapabilityProvider {
    #[allow(
        clippy::unused_self,
        reason = "Per-IPC path is O(1) shape-match; the provider's `node_id_bytes` is consumed \
                  by `verify_signed_token` at channel creation, not on the hot path."
    )]
    fn verify(
        &self,
        token: &KernelCapabilityToken,
        action: KernelAction,
        resource: KernelResource,
    ) -> CapabilityVerdict {
        // Per-IPC path: O(1) action/resource shape match. Ed25519
        // signature verification is a one-shot operation done at
        // channel creation via `verify_signed_token` (MB13.d).
        if token.action == action && token.resource == resource {
            CapabilityVerdict::Authorised
        } else {
            CapabilityVerdict::Denied
        }
    }
}

// =============================================================================
// MB13.d — Signed-token decoding helper
// =============================================================================

/// Decode a postcard-encoded [`nexacore_capability::CapabilityToken`] and run
/// full Ed25519 verification (signature + time window + TEE binding) via
/// [`Ed25519CapabilityProvider::verify_signed_token`].
///
/// Used by [`crate::ipc::KernelIpcRegistry::create_channel_signed`] (and
/// transitively by the `IpcCreateChannel(20)` syscall handler) to lift
/// a userspace-presented token into a [`KernelPrincipal`] suitable for
/// the existing per-IPC `subject == requester` gate.
///
/// The kernel does *not* require the embedded `Resource::IpcChannel(_)`
/// id to match the freshly-allocated channel id: user space cannot
/// predict the monotonic next id at mint time. The kernel verifies the
/// token's authenticity (the signature binds it to a specific subject +
/// node attestation) and rebinds it to whatever channel the call creates.
/// Per-IPC checks still enforce `send/recv_subject == caller_principal`,
/// so the attenuation guarantee is preserved.
///
/// # Errors
///
/// - [`crate::KernelError::InvalidArgument`] when postcard decoding
///   fails (malformed bytes, truncation, trailing data).
/// - [`crate::KernelError::CapabilityDenied`] when signature / time /
///   TEE verification fails, or when the token's scope action does not
///   match `expected_action`, or its resource is not
///   `Resource::IpcChannel(_)`.
pub fn decode_and_authenticate_token(
    bytes: &[u8],
    expected_action: KernelAction,
    provider: &Ed25519CapabilityProvider,
    now: u64,
) -> KernelResult<KernelPrincipal> {
    use nexacore_capability::{
        CapabilityToken,
        scope::{Action, Resource},
    };

    use crate::KernelError;

    let token: CapabilityToken =
        nexacore_types::wire::decode_canonical(bytes).map_err(|_| KernelError::InvalidArgument)?;

    if provider.verify_signed_token(&token, now) != CapabilityVerdict::Authorised {
        return Err(KernelError::CapabilityDenied);
    }

    let expected_user_action = match expected_action {
        KernelAction::IpcSend => Action::IpcSend,
        KernelAction::IpcRecv => Action::IpcRecv,
    };
    if token.payload.scope.action != expected_user_action {
        return Err(KernelError::CapabilityDenied);
    }

    if !matches!(token.payload.scope.resource, Resource::IpcChannel(_)) {
        return Err(KernelError::CapabilityDenied);
    }

    let subject_bytes = *token.payload.subject.as_bytes();
    Ok(KernelPrincipal::from_bytes(subject_bytes))
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kernel_capability_id_round_trips() {
        let id = KernelCapabilityId(0x0123_4567_89AB_CDEF_FEDC_BA98_7654_3210u128);
        assert_eq!(id.0, 0x0123_4567_89AB_CDEF_FEDC_BA98_7654_3210u128);
    }

    #[test]
    fn kernel_principal_zero_is_all_zeroes() {
        assert_eq!(KernelPrincipal::ZERO.as_bytes(), &[0u8; 32]);
    }

    #[test]
    fn stub_authorises_matching_action_and_resource() {
        let token = KernelCapabilityToken {
            subject: KernelPrincipal::from_bytes([0x42; 32]),
            action: KernelAction::IpcSend,
            resource: KernelResource::IpcChannel(7),
        };
        let v = StubCapabilityProvider.verify(
            &token,
            KernelAction::IpcSend,
            KernelResource::IpcChannel(7),
        );
        assert_eq!(v, CapabilityVerdict::Authorised);
    }

    #[test]
    fn stub_denies_action_mismatch() {
        let token = KernelCapabilityToken {
            subject: KernelPrincipal::from_bytes([0x42; 32]),
            action: KernelAction::IpcSend,
            resource: KernelResource::IpcChannel(7),
        };
        let v = StubCapabilityProvider.verify(
            &token,
            KernelAction::IpcRecv,
            KernelResource::IpcChannel(7),
        );
        assert_eq!(v, CapabilityVerdict::Denied);
    }

    #[test]
    fn stub_denies_resource_mismatch() {
        let token = KernelCapabilityToken {
            subject: KernelPrincipal::from_bytes([0x42; 32]),
            action: KernelAction::IpcSend,
            resource: KernelResource::IpcChannel(7),
        };
        let v = StubCapabilityProvider.verify(
            &token,
            KernelAction::IpcSend,
            KernelResource::IpcChannel(8),
        );
        assert_eq!(v, CapabilityVerdict::Denied);
    }

    // -------------------------------------------------------------------
    // MB13.c — Ed25519CapabilityProvider
    // -------------------------------------------------------------------
    //
    // The host test build has the full `nexacore-capability` userspace
    // features (`mint`, `id-generation`, `rng`) available, so we can
    // mint real Ed25519-signed tokens and exercise the verify path
    // end-to-end. The bare-metal build of `nexacore-kernel` does not
    // include these tests (the `cfg(test)` gate keeps them off).

    use nexacore_capability::{
        CapabilityToken,
        scope::{Action, Resource, Scope, TimeWindow},
    };
    use nexacore_crypto::signing::NexaCoreSigningKey;
    use nexacore_types::identity::NodeId;

    fn fresh_ipc_token(channel_id: u64) -> (CapabilityToken, NodeId, NexaCoreSigningKey, u64) {
        let issuer_key = NexaCoreSigningKey::generate();
        let node_bytes = [0xAB; 32];
        let node_id = NodeId::from_attestation_hash(node_bytes);
        let scope = Scope {
            action: Action::IpcSend,
            resource: Resource::IpcChannel(channel_id),
            window: TimeWindow::new(100, 200).expect("valid window"),
            caveats: alloc::vec::Vec::new(),
        };
        let token = CapabilityToken::mint(&issuer_key, node_id, scope, None).expect("mint");
        // `now` chosen inside the window.
        (token, node_id, issuer_key, 150)
    }

    #[test]
    fn ed25519_signature_only_accepts_freshly_minted_token() {
        let (token, _node, _key, _now) = fresh_ipc_token(7);
        let provider = Ed25519CapabilityProvider::placeholder();
        assert_eq!(
            provider.verify_signature_only(&token),
            CapabilityVerdict::Authorised
        );
    }

    #[test]
    fn ed25519_signature_only_rejects_tampered_payload() {
        let (mut token, _node, _key, _now) = fresh_ipc_token(7);
        // Mutate the scope window so the signature pre-image changes.
        token.payload.scope.window = TimeWindow::new(0, u64::MAX).expect("widened window");
        let provider = Ed25519CapabilityProvider::placeholder();
        assert_eq!(
            provider.verify_signature_only(&token),
            CapabilityVerdict::Denied
        );
    }

    #[test]
    fn ed25519_verify_full_accepts_inside_window_with_matching_node() {
        let (token, node, _key, now) = fresh_ipc_token(7);
        let provider = Ed25519CapabilityProvider::with_node_id(*node.as_bytes());
        assert_eq!(
            provider.verify_signed_token(&token, now),
            CapabilityVerdict::Authorised
        );
    }

    #[test]
    fn ed25519_verify_full_rejects_outside_window() {
        let (token, node, _key, _now) = fresh_ipc_token(7);
        let provider = Ed25519CapabilityProvider::with_node_id(*node.as_bytes());
        // `now = 50` is before the token's `not_before = 100`.
        assert_eq!(
            provider.verify_signed_token(&token, 50),
            CapabilityVerdict::Denied
        );
        // `now = 250` is past the token's `not_after = 200`.
        assert_eq!(
            provider.verify_signed_token(&token, 250),
            CapabilityVerdict::Denied
        );
    }

    #[test]
    fn ed25519_verify_full_rejects_attestation_mismatch() {
        // Mint a token bound to `node_a`; verify with a provider
        // pretending to be `node_b`. TEE binding must fail.
        let (token, _node_a, _key, now) = fresh_ipc_token(7);
        let provider = Ed25519CapabilityProvider::with_node_id([0xCC; 32]);
        assert_eq!(
            provider.verify_signed_token(&token, now),
            CapabilityVerdict::Denied
        );
    }

    #[test]
    fn ed25519_per_ipc_check_matches_stub_semantics() {
        // The per-IPC `verify` call MUST keep shape-matching semantics
        // so Ed25519CapabilityProvider can drop-in replace
        // StubCapabilityProvider without regressing MB12 behaviour.
        let token = KernelCapabilityToken {
            subject: KernelPrincipal::from_bytes([0x42; 32]),
            action: KernelAction::IpcSend,
            resource: KernelResource::IpcChannel(11),
        };
        let provider = Ed25519CapabilityProvider::placeholder();
        assert_eq!(
            provider.verify(
                &token,
                KernelAction::IpcSend,
                KernelResource::IpcChannel(11)
            ),
            CapabilityVerdict::Authorised
        );
        assert_eq!(
            provider.verify(
                &token,
                KernelAction::IpcRecv,
                KernelResource::IpcChannel(11)
            ),
            CapabilityVerdict::Denied
        );
        assert_eq!(
            provider.verify(
                &token,
                KernelAction::IpcSend,
                KernelResource::IpcChannel(12)
            ),
            CapabilityVerdict::Denied
        );
    }

    #[test]
    fn ed25519_verify_full_half_open_window_boundary() {
        // TimeWindow is half-open [not_before, not_after).
        let (token, node, _key, _now) = fresh_ipc_token(7);
        let provider = Ed25519CapabilityProvider::with_node_id(*node.as_bytes());
        // At `not_before = 100` — inclusive, token valid.
        assert_eq!(
            provider.verify_signed_token(&token, 100),
            CapabilityVerdict::Authorised
        );
        // One tick before `not_before` — invalid.
        assert_eq!(
            provider.verify_signed_token(&token, 99),
            CapabilityVerdict::Denied
        );
        // Last valid tick: `not_after - 1 = 199`.
        assert_eq!(
            provider.verify_signed_token(&token, 199),
            CapabilityVerdict::Authorised
        );
        // At `not_after = 200` — exclusive, expired.
        assert_eq!(
            provider.verify_signed_token(&token, 200),
            CapabilityVerdict::Denied
        );
    }

    #[test]
    fn stub_provider_authorises_any_subject() {
        let token_a = KernelCapabilityToken {
            subject: KernelPrincipal::from_bytes([0x00; 32]),
            action: KernelAction::IpcSend,
            resource: KernelResource::IpcChannel(1),
        };
        let token_b = KernelCapabilityToken {
            subject: KernelPrincipal::from_bytes([0xFF; 32]),
            action: KernelAction::IpcSend,
            resource: KernelResource::IpcChannel(1),
        };
        let stub = StubCapabilityProvider;
        assert_eq!(
            stub.verify(
                &token_a,
                KernelAction::IpcSend,
                KernelResource::IpcChannel(1)
            ),
            CapabilityVerdict::Authorised
        );
        assert_eq!(
            stub.verify(
                &token_b,
                KernelAction::IpcSend,
                KernelResource::IpcChannel(1)
            ),
            CapabilityVerdict::Authorised
        );
    }
}
