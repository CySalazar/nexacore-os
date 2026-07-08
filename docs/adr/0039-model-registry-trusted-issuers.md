# ADR-0039: ModelRegistry Trusted-Issuer Allowlist (TASK-17 Phase-2 Gate)

**Status:** Accepted
**Date:** 2026-06-08
**Deciders:** agent analysis under operator-approved PLAN.md TASK-17
**Refs:** PLAN.md TASK-17 (Phase 2 completion gate), NCIP-Phase2-Entry-021 §S4,
`crates/nexacore-runtime/src/lib.rs` (`model` module), ADR-0033 (model attestation)

## Context

TASK-17 is the Phase-2 completion gate. One acceptance criterion for model
attestation is: *"firma di issuer non noto → rifiutato"* (a manifest from an
unknown issuer must be rejected), with the registry verifying *"la firma del
manifest prima del load — chiave di firma da configurazione, fail-closed"*.

The existing `ModelRegistry::register` (lib.rs) already verifies the
manifest's Ed25519 self-signature (`signing_key.verify(&hash, &signature)`)
and rejects on failure — covering *"manifest con 1 byte alterato → load
rifiutato"*. But it accepts ANY internally-consistent issuer: a manifest
signed by an attacker-controlled key whose own `signing_key` is embedded in
the manifest verifies fine. There was no notion of a *trusted* issuer set,
so "unknown issuer" could not be rejected.

## Decision

Add an **opt-in trusted-issuer allowlist** to `ModelRegistry`:

- A `trusted_issuers: Option<BTreeSet<[u8; 32]>>` field (raw Ed25519
  verifying-key bytes).
- `ModelRegistry::new()` → `None`: self-signature verification only (the
  pre-gate behaviour, preserved so the existing call sites and tests — which
  register manifests under ad-hoc keys — keep working).
- `ModelRegistry::with_trusted_issuers(issuers)` → `Some(set)`: in addition
  to the self-signature, `register` requires the manifest's `signing_key` to
  be in the set. **Fail-closed**: an empty allowlist rejects every manifest;
  an unknown-but-self-consistent issuer is refused (`NexaCoreError::Crypto {
  InvalidSignature }` with a distinct context string).

This is the smallest change that closes the gate without disturbing the
verified self-signature path. The allowlist is the deployment's
"signing key from configuration": a production node constructs the registry
with its trusted publisher keys; a test or single-trust-domain deployment
uses `new()`.

## Alternatives considered

- **Make the allowlist mandatory (`new()` enforces it)** — rejected: it would
  break every existing registration site and test that mints ad-hoc keys, and
  forces a key-distribution mechanism this gate task is not scoped to build.
  Opt-in keeps backward compatibility while making the fail-closed posture
  available and tested.
- **Wire the kernel's `known_issuers` table in** — rejected: that table is the
  per-boot kernel capability signer set (Ring-0 concern); model-publisher
  trust is a userspace-runtime configuration concern. Coupling them would
  conflate two distinct trust roots.
- **A new `NexaCoreError` variant for untrusted issuer** — deferred: `NexaCoreError`
  is `#[non_exhaustive]` but adding a variant is a wider change; reusing
  `CryptoErrorKind::InvalidSignature` with a distinct `context` string ("issuer
  not in trusted allowlist") is accurate (a valid-but-untrusted signature is
  not an acceptable signature for this trust domain) and audit-greppable.

## Consequences

- `ModelRegistry` gains `with_trusted_issuers` + the allowlist check in
  `register`; `new()` is unchanged in behaviour. Four new tests:
  trusted-issuer accepted, unknown-issuer rejected, empty-allowlist rejects
  all, no-allowlist accepts any valid issuer.
- Production deployments can now pin model publishers; the gate's
  "unknown issuer → rejected" criterion is satisfied and tested.
- A future ADR may promote the allowlist to mandatory once a model-publisher
  key-distribution/attestation story lands (out of TASK-17 scope).
