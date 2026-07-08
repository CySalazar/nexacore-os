//! Macaroons-style attenuation: derive a child capability that is a
//! strict restriction of its parent.
//!
//! # The invariant
//!
//! For any parent capability `P` and any child `C` produced by
//! [`attenuate`], the following holds:
//!
//! ```text
//! C.scope ⊆ P.scope
//! ```
//!
//! Concretely: every (action, resource, time, caveat) request that
//! `C` would authorise is also authorised by `P`. This is the
//! security-critical property of attenuation; the property test in
//! the `tests` module exercises it on randomized inputs.
//!
//! # Why "monotonic"?
//!
//! Each caveat the child applies can only **tighten** an existing
//! field — narrow the time window, narrow the resource pattern, add
//! a binding. There is no caveat in the vocabulary that can broaden
//! a parent scope. Combined with signature verification of the
//! complete chain at use time, this rules out privilege escalation
//! through attenuation.

#[cfg(feature = "mint")]
use nexacore_crypto::signing::NexaCoreSigningKey;
use nexacore_types::error::{CapabilityErrorKind, NexaCoreError, Result};

#[cfg(feature = "mint")]
use crate::token::TokenPayload;
use crate::{
    scope::{Caveat, Resource, Scope},
    token::CapabilityToken,
};

// =============================================================================
// Caveat application — tighten one dimension of a Scope.
// =============================================================================

/// Apply a caveat to `scope`, producing a strictly more restrictive
/// scope. Always returns a child that is a subset of the input.
///
/// # Errors
///
/// Returns [`NexaCoreError::Capability`] with
/// [`CapabilityErrorKind::AttenuationViolation`] if the caveat would
/// produce an empty / invalid window (e.g., `ExpiresAt(t)` where
/// `t < not_before`).
pub fn apply_caveat(scope: &Scope, caveat: &Caveat) -> Result<Scope> {
    let mut child = scope.clone();
    match caveat {
        Caveat::ExpiresAt(t) => {
            // Narrow `not_after` only if `t` is earlier than the
            // current `not_after`. Never widen.
            if *t < child.window.not_after {
                child.window.not_after = *t;
            }
        }
        Caveat::NotBefore(t) => {
            // Push `not_before` forward only if `t` is later than
            // the current `not_before`. Never widen.
            if *t > child.window.not_before {
                child.window.not_before = *t;
            }
        }
        Caveat::BoundToNode(_) | Caveat::BoundToSession(_) | Caveat::Custom { .. } => {
            // These caveats restrict the *use* of the capability
            // (binding it to a specific node/session/predicate)
            // rather than narrowing the scope dimensions. They are
            // recorded as caveats and checked at use time.
        }
    }

    // Validate the resulting window. An inverted window means the
    // caveat shrunk the scope to nothing, which we treat as an
    // attenuation error: callers should not produce an unusable
    // child.
    if child.window.not_before > child.window.not_after {
        return Err(NexaCoreError::capability(
            CapabilityErrorKind::AttenuationViolation,
            "attenuation::apply_caveat::window_inverted",
        ));
    }

    // Append the caveat to the child's caveats list (preserving
    // order for canonical encoding).
    if !child.caveats.contains(caveat) {
        child.caveats.push(caveat.clone());
    }

    // Defence-in-depth: assert the invariant. If we ever introduce a
    // caveat kind that broadens, this catches it before signing.
    if !child.is_subset_of(scope) {
        return Err(NexaCoreError::capability(
            CapabilityErrorKind::AttenuationViolation,
            "attenuation::apply_caveat::invariant_broken",
        ));
    }

    Ok(child)
}

/// Apply a sequence of caveats in order. Equivalent to folding
/// [`apply_caveat`] over the input.
///
/// # Errors
///
/// Returns the first [`apply_caveat`] error encountered.
pub fn apply_caveats(scope: &Scope, caveats: &[Caveat]) -> Result<Scope> {
    let mut current = scope.clone();
    for c in caveats {
        current = apply_caveat(&current, c)?;
    }
    Ok(current)
}

/// Restrict the resource of a scope to a more specific value.
///
/// # Errors
///
/// Returns [`NexaCoreError::Capability`] with
/// [`CapabilityErrorKind::AttenuationViolation`] if `new_resource` is
/// not a subset of the current scope's resource.
pub fn restrict_resource(scope: &Scope, new_resource: Resource) -> Result<Scope> {
    if !new_resource.is_subset_of(&scope.resource) {
        return Err(NexaCoreError::capability(
            CapabilityErrorKind::AttenuationViolation,
            "attenuation::restrict_resource::not_a_subset",
        ));
    }
    let mut child = scope.clone();
    child.resource = new_resource;
    Ok(child)
}

// =============================================================================
// Token-level attenuation
// =============================================================================

/// Produce a child capability token by applying `caveats` to the
/// parent's scope and signing the result with `issuer_key`.
///
/// The caller can attenuate using any signing key — typically the
/// same issuer key as the parent (centralized issuance) or a
/// delegate's key (distributed issuance with per-node attenuation).
/// Verification only requires the chain of signatures to be valid;
/// it does not require the same key throughout.
///
/// # Errors
///
/// Returns [`NexaCoreError::Capability`] on any of:
/// * The caveat sequence cannot be applied (`AttenuationViolation`).
/// * The new payload cannot be canonicalised (`MalformedToken`).
///
/// # Feature gating
///
/// Available only under `feature = "mint"` (default-on for the
/// userspace build). Verify-only bare-metal consumers (the kernel)
/// disable this path because minting a child id requires a CSPRNG.
#[cfg(feature = "mint")]
pub fn attenuate(
    parent: &CapabilityToken,
    issuer_key: &NexaCoreSigningKey,
    caveats: &[Caveat],
) -> Result<CapabilityToken> {
    let new_scope = apply_caveats(&parent.payload.scope, caveats)?;
    // Final guard: the new scope must be a subset of the parent's.
    if !new_scope.is_subset_of(&parent.payload.scope) {
        return Err(NexaCoreError::capability(
            CapabilityErrorKind::AttenuationViolation,
            "attenuation::attenuate::scope_not_subset",
        ));
    }
    let payload = TokenPayload {
        id: nexacore_types::identity::CapabilityId::new(),
        subject: parent.payload.subject,
        issuer: issuer_key.verifying_key(),
        parent: Some(parent.payload.id),
        scope: new_scope,
    };
    CapabilityToken::sign_payload(issuer_key, payload)
}

/// Verify that `child.scope ⊆ parent.scope` AND `child.parent ==
/// Some(parent.id)`. Useful for replaying an attenuation chain at
/// use time when both ends are present.
///
/// Does NOT verify either token's signature; that is the caller's
/// responsibility (typically [`CapabilityToken::verify_signature`]
/// on each token in the chain).
///
/// # Errors
///
/// Returns [`NexaCoreError::Capability`] with
/// [`CapabilityErrorKind::AttenuationViolation`] if the relationship
/// does not hold.
pub fn verify_chain_link(parent: &CapabilityToken, child: &CapabilityToken) -> Result<()> {
    if child.payload.parent != Some(parent.payload.id) {
        return Err(NexaCoreError::capability(
            CapabilityErrorKind::AttenuationViolation,
            "attenuation::verify_chain_link::parent_id_mismatch",
        ));
    }
    if !child.payload.scope.is_subset_of(&parent.payload.scope) {
        return Err(NexaCoreError::capability(
            CapabilityErrorKind::AttenuationViolation,
            "attenuation::verify_chain_link::scope_not_subset",
        ));
    }
    Ok(())
}

// Re-export the type used by users to plug in domain-specific caveat
// predicates. The full predicate-evaluation engine ships in Phase 2;
// for now this is just a marker trait.

/// Trait implemented by domain-specific predicates that evaluate a
/// [`Caveat::Custom`] tag against the current request context.
///
/// Implementations live outside this crate (in the consumer's domain
/// crate). The trait is here only so the capability layer's API
/// surface mentions it consistently.
pub trait CaveatPredicate {
    /// The custom-caveat tag this predicate handles.
    const TAG: &'static str;

    /// Evaluate the predicate against the caveat payload and the
    /// current request context. Returns `Ok(())` if the caveat
    /// holds, `Err(NexaCoreError)` otherwise.
    ///
    /// # Errors
    ///
    /// Implementation-defined. Conventional return is
    /// [`NexaCoreError::Capability`] with
    /// [`CapabilityErrorKind::ScopeViolation`].
    fn evaluate(&self, payload: &[u8]) -> Result<()>;
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use alloc::{string::ToString, vec};

    use nexacore_types::identity::NodeId;
    use proptest::prelude::*;

    use super::*;
    use crate::scope::{Action, Resource, TimeWindow};

    fn parent_scope() -> Scope {
        Scope {
            action: Action::Read,
            resource: Resource::Filesystem("/data/**".to_string()),
            window: TimeWindow::new(100, 1_000).unwrap(),
            caveats: vec![],
        }
    }

    // ---- Window-tightening caveats ------------------------------------------

    #[test]
    fn expires_at_narrows_window() {
        let p = parent_scope();
        let c = apply_caveat(&p, &Caveat::ExpiresAt(500)).unwrap();
        assert_eq!(c.window.not_after, 500);
        assert!(c.is_subset_of(&p));
    }

    #[test]
    fn expires_at_does_not_widen() {
        let p = parent_scope();
        let c = apply_caveat(&p, &Caveat::ExpiresAt(2_000)).unwrap();
        // Must not widen — keep the parent's not_after.
        assert_eq!(c.window.not_after, 1_000);
    }

    #[test]
    fn not_before_narrows_window() {
        let p = parent_scope();
        let c = apply_caveat(&p, &Caveat::NotBefore(200)).unwrap();
        assert_eq!(c.window.not_before, 200);
        assert!(c.is_subset_of(&p));
    }

    #[test]
    fn not_before_does_not_widen() {
        let p = parent_scope();
        let c = apply_caveat(&p, &Caveat::NotBefore(50)).unwrap();
        assert_eq!(c.window.not_before, 100);
    }

    #[test]
    fn caveat_pair_is_appended() {
        let p = parent_scope();
        let c = apply_caveats(&p, &[Caveat::NotBefore(200), Caveat::ExpiresAt(500)]).unwrap();
        assert_eq!(c.window.not_before, 200);
        assert_eq!(c.window.not_after, 500);
        assert_eq!(c.caveats.len(), 2);
        assert!(c.is_subset_of(&p));
    }

    #[test]
    fn binding_caveats_are_recorded() {
        let p = parent_scope();
        let node = NodeId::from_attestation_hash([1u8; 32]);
        let c = apply_caveat(&p, &Caveat::BoundToNode(node)).unwrap();
        assert!(c.caveats.contains(&Caveat::BoundToNode(node)));
        // Window unchanged.
        assert_eq!(c.window, p.window);
        assert!(c.is_subset_of(&p));
    }

    // ---- Resource restriction -----------------------------------------------

    #[test]
    fn restrict_resource_to_subset_succeeds() {
        let p = parent_scope();
        let r = Resource::Filesystem("/data/x".to_string());
        let c = restrict_resource(&p, r.clone()).unwrap();
        assert_eq!(c.resource, r);
        assert!(c.is_subset_of(&p));
    }

    #[test]
    fn restrict_resource_to_non_subset_fails() {
        let p = parent_scope();
        let outside = Resource::Filesystem("/etc/passwd".to_string());
        let err = restrict_resource(&p, outside).unwrap_err();
        match err {
            NexaCoreError::Capability { kind, .. } => {
                assert_eq!(kind, CapabilityErrorKind::AttenuationViolation);
            }
            _ => panic!("expected Capability::AttenuationViolation"),
        }
    }

    // ---- Token attenuation --------------------------------------------------

    #[test]
    fn attenuate_produces_subset_token() {
        let sk = NexaCoreSigningKey::generate();
        let parent = CapabilityToken::mint(
            &sk,
            NodeId::from_attestation_hash([0xAA; 32]),
            parent_scope(),
            None,
        )
        .unwrap();
        let child = attenuate(&parent, &sk, &[Caveat::ExpiresAt(500)]).unwrap();

        // Signature on the child verifies.
        child.verify_signature().unwrap();
        // Chain link is correct.
        verify_chain_link(&parent, &child).unwrap();
        // Scope is a strict subset.
        assert!(child.payload.scope.is_subset_of(&parent.payload.scope));
        assert_eq!(child.payload.scope.window.not_after, 500);
    }

    // ---- THE security-critical property -------------------------------------

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(64))]

        // For any random parent scope and any sequence of well-formed
        // caveats, the derived child scope is ALWAYS a subset of the
        // parent. This is the property the Macaroons design promises.
        #[test]
        fn attenuation_is_monotonic(
            nbf in 0u64..1_000_000,
            duration in 1u64..1_000_000,
            // Bias toward window-tightening caveats; binding caveats
            // are tested separately above.
            shrink_exp in proptest::option::of(0u64..2_000_000),
            shrink_nbf in proptest::option::of(0u64..2_000_000),
        ) {
            let parent = Scope {
                action: Action::Read,
                resource: Resource::Any,
                window: TimeWindow::new(nbf, nbf.saturating_add(duration)).unwrap(),
                caveats: vec![],
            };
            let mut caveats = vec![];
            if let Some(t) = shrink_exp { caveats.push(Caveat::ExpiresAt(t)); }
            if let Some(t) = shrink_nbf { caveats.push(Caveat::NotBefore(t)); }

            // The application can fail (window inversion). When it
            // succeeds, the child MUST be a subset of the parent.
            if let Ok(child) = apply_caveats(&parent, &caveats) {
                prop_assert!(child.is_subset_of(&parent),
                    "child scope is not a subset of parent: child={child:?}, parent={parent:?}");
            }
        }

        // Adversarial: 100 random tampered children must be rejected by
        // chain-link verification. We tamper by producing a child whose
        // window is broader than the parent's; `verify_chain_link`
        // must catch it.
        #[test]
        fn tampered_child_rejected_by_chain_link(
            parent_nbf in 100u64..1000,
            parent_dur in 100u64..1000,
            broaden in 1u64..500,
        ) {
            let sk = NexaCoreSigningKey::generate();
            let parent_scope = Scope {
                action: Action::Read,
                resource: Resource::Any,
                window: TimeWindow::new(parent_nbf, parent_nbf + parent_dur).unwrap(),
                caveats: vec![],
            };
            let parent = CapabilityToken::mint(
                &sk, NodeId::from_attestation_hash([1u8; 32]), parent_scope.clone(), None
            ).unwrap();

            // Build a malicious child with a broader window than
            // parent allows.
            let bad_scope = Scope {
                window: crate::scope::TimeWindow::new(
                    parent_scope.window.not_before.saturating_sub(broaden),
                    parent_scope.window.not_after + broaden,
                ).unwrap(),
                ..parent_scope
            };
            let bad_payload = TokenPayload {
                id: nexacore_types::identity::CapabilityId::new(),
                subject: parent.payload.subject,
                issuer: sk.verifying_key(),
                parent: Some(parent.payload.id),
                scope: bad_scope,
            };
            let bad_child = CapabilityToken::sign_payload(&sk, bad_payload).unwrap();

            // Signature verifies (we signed it ourselves), but chain-
            // link verification MUST reject it.
            bad_child.verify_signature().unwrap();
            prop_assert!(verify_chain_link(&parent, &bad_child).is_err());
        }

        // Resource-restriction soundness + honesty (WS13-02.6), the
        // numeric-range counterpart to the time-window monotonicity above.
        // For a random parent MMIO region and a random restriction target,
        // `restrict_resource` MUST (a) succeed exactly when the target range
        // lies entirely inside the parent range — never widening authority —
        // and (b) when it succeeds, yield a scope that is a subset of the
        // parent.
        #[test]
        fn restrict_resource_mmio_range_is_sound_and_honest(
            p_base in 0u64..1000, p_pages in 1u64..1000,
            c_base in 0u64..1000, c_pages in 1u64..1000,
        ) {
            const PAGE: u64 = 4096;
            let parent_base = p_base * PAGE;
            let parent_len = p_pages * PAGE;
            let child_base = c_base * PAGE;
            let child_len = c_pages * PAGE;

            let parent = Scope {
                action: Action::MmioMap,
                resource: Resource::MmioRegion { phys_base: parent_base, len: parent_len },
                window: TimeWindow::new(0, 1_000_000).unwrap(),
                caveats: vec![],
            };
            let child_res = Resource::MmioRegion { phys_base: child_base, len: child_len };

            // Ground truth: [child_base, child_end) ⊆ [parent_base, parent_end).
            let parent_end = parent_base.saturating_add(parent_len);
            let child_end = child_base.saturating_add(child_len);
            let contained = child_base >= parent_base && child_end <= parent_end;

            match restrict_resource(&parent, child_res) {
                Ok(child) => {
                    // Honest: only succeeds on a genuinely contained subrange.
                    prop_assert!(contained,
                        "restrict_resource widened authority: child range escapes the parent");
                    // Sound: the derived scope never widens the parent.
                    prop_assert!(child.is_subset_of(&parent),
                        "derived child scope is not a subset of the parent");
                }
                Err(_) => {
                    // It may only reject a non-contained range.
                    prop_assert!(!contained,
                        "restrict_resource rejected a contained subrange");
                }
            }
        }
    }
}
