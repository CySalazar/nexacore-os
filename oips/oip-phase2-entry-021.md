---
ncip: 21
title: Phase 2 Entry — AI Runtime Service Foundation
track: Standards Track
status: Draft
authors:
  - cySalazar <hello@nexacoreos.com>
created: 2026-05-24
updated: 2026-05-24
requires:
  - 18
  - 2
supersedes: ~
superseded-by: ~
discussion: ~
license: CC0-1.0
---

# NCIP-Phase2-Entry-021 — Phase 2 Entry: AI Runtime Service Foundation

## Abstract

This NCIP formally ratifies the transition of NexaCore OS from **Phase 1 (Microkernel
POC)** to **Phase 2 (AI Runtime Service and Tier 0)**. Phase 1 has reached
approximately 99.99% completion: all kernel milestones (MB1–MB14), the capability
system, IPC, memory management, multi-processor scheduling, the driver framework
(virtio-net, NVMe, e1000e), and Wave 1–4 deliverables are merged and validated on
Proxmox hardware. The project is ready to begin Phase 2 per the roadmap at
[`docs/06-roadmap.md`](../docs/06-roadmap.md).

Phase 2 introduces three foundational crates: the **AI Runtime Service**
(`nexacore-runtime`), the **Tensor HAL** (`nexacore-hal::tensor`), and the **PII
Tokenization Service** (`nexacore-tokenization`). The central architectural commitment
is **Tier 0 (local-only) inference first**: no inference data leaves the device
unencrypted, no network egress occurs during a Tier 0 inference session, and every
model loaded into the runtime MUST carry a valid Ed25519 signature. This NCIP
defines the scope, deliverables, timeline, acceptance criteria, and test
requirements that govern Phase 2 entry.

---

## Motivation

### M1. Phase 1 is operationally complete

The kernel milestones MB1 through MB14, including the final MB14.h.2 cycle
(cross-CPU context switch, per-CPU scheduling dispatch loop), are merged onto
`main` and validated on the Proxmox target (the test VM, proxmox.internal). Wave 4 is
closed: NCFS v0 skeleton (TASK-011), NCIP-Crypto-002 Draft → Active (TASK-020),
and postcard wire-format alignment (TASK-022) are all merged. The remaining Phase 1
items (P5.2/P5.3 TEE hardware backends, P6.8 external security audit) are
funding-dependent and do not block Phase 2.

Delaying Phase 2 until every Phase 1 item resolves would stall the project
indefinitely on externally-gated milestones. The remaining items are tracked in
[`docs/06-roadmap.md`](../docs/06-roadmap.md) and will be completed asynchronously.

### M2. AI Runtime is the project's primary differentiating feature

[`docs/06-roadmap.md`](../docs/06-roadmap.md) Phase 2 (months 18–30) is defined
around the AI Runtime Service: model lifecycle, inference scheduling, tier routing,
and the privacy-preserving tokenization pipeline. These capabilities are what
distinguish NexaCore OS from a general-purpose microkernel. Building them on top of the
now-proven Phase 1 primitives (capability system, IPC channels, NVMe I/O path,
driver framework) is the right time: the foundation is solid and the Phase 2
dependencies are ready.

### M3. Tier 0 local-only inference provides a hardened starting point

[`docs/02-architecture.md`](../docs/02-architecture.md) § Execution tiers defines
three tiers: Tier 0 (local device), Tier 1 (cluster / private cloud), Tier 2
(public cloud). Starting with Tier 0 allows the full security model — model
attestation, token vault TEE boundary, no-egress inference — to be validated in the
simplest possible network topology before Tier 1 and Tier 2 networking complexity is
layered on. A Tier 1 mistake can expose data across a cluster; a Tier 0 mistake is
contained to a single device.

### M4. The tokenization service is a hard dependency for privacy compliance

[`docs/04-security-model.md`](../docs/04-security-model.md) § Tokenization service
specifies that PII MUST be tokenized before it enters any model context. Without
`nexacore-tokenization`, inference pipelines would either: (a) pass raw PII to the
model, violating GDPR/HIPAA/PCI obligations, or (b) stall waiting for a vault that
does not exist. Scaffolding the service in Phase 2 Sprint 1 and growing it to full
NER + policy enforcement by Sprint 4 removes this blocker from the critical path.

---

## Specification

### S1. Phase 2 scope

Phase 2 MUST deliver the following crates to production-ready status (as defined
in §S4) before Phase 2 is declared complete:

1. **`nexacore-runtime`** — AI Runtime Service: model registry, inference pipeline,
   tier router (Tier 0 only in Phase 2).

2. **`nexacore-hal::tensor`** — Tensor Hardware Abstraction Layer: `TensorBackend`
   trait, CPU backend with SIMD-aware dispatch (AVX2 / AVX-512 / NEON), GPU and
   NPU backends scaffolded with `unimplemented!()` stubs for Phase 3.

3. **`nexacore-tokenization`** — PII Tokenization Service: TEE-resident token vault
   with seal/unseal via `TeeBackend` trait, named-entity recognition (NER) stub,
   GDPR/HIPAA/PCI policy presets.

4. **`nexacore-types::encrypted`** — Encrypted-by-default data types (already
   scaffolded in `crates/nexacore-types`); integration with `nexacore-tokenization`
   finalized in Phase 2 Sprint 4.

Phase 2 MUST NOT introduce Tier 1 (cluster) or Tier 2 (public cloud) inference
scheduling. Tier 1/2 entry MUST be gated by a separate NCIP filed at Phase 3 entry.

### S2. Deliverables and acceptance criteria

Each deliverable below MUST satisfy its acceptance criteria before Phase 2 is
declared complete. "Passes `cargo test`" means zero test failures with the
`--workspace` flag and zero ignored tests in the crate's own test suite.

#### S2.1. `nexacore-runtime` v0.3.0

- **`ModelRegistry`**: stores signed model manifests; MUST reject any manifest
  whose Ed25519 signature does not verify against the operator's signing key
  embedded in the NexaCore OS build. Duplicate model IDs MUST be rejected. The
  registry MUST be serializable to/from postcard wire format for persistence in
  `NCFS` (via the in-memory BLK channel).

- **`InferencePipeline`**: accepts a `PipelineRequest` containing a model ID and
  a tokenized input context; dispatches to the registered `TensorBackend` via
  `nexacore-hal::tensor`; returns a `PipelineResponse` containing the output tensor
  and latency metadata. The pipeline MUST NOT accept raw PII in the input
  context; callers MUST tokenize first via `nexacore-tokenization`.

- **`TierRouter`**: routes inference requests to the appropriate execution tier.
  In Phase 2 the router MUST only route to Tier 0 (local CPU). Any request that
  would require Tier 1 or Tier 2 MUST be rejected with `Err(TierUnavailable)`.

- **Acceptance criterion**: `nexacore-runtime` passes `cargo test` with 0 failures;
  a tampered manifest (any byte flipped in the signature) is rejected by
  `ModelRegistry::register`; `InferencePipeline` returns a valid
  `PipelineResponse` for a registered model with a tokenized input.

#### S2.2. `nexacore-hal` v0.3.0 — `tensor` module

- **`TensorBackend` trait**: defines `dispatch(&self, op: TensorOp) ->
  Result<Tensor, HalError>`. MUST be object-safe (no generic methods on the
  trait itself; generics live on helper functions). All backends MUST implement
  this trait.

- **`CpuBackend`**: selects SIMD codepath at runtime via CPUID: AVX-512 >
  AVX2 > scalar fallback on x86_64; NEON on AArch64; scalar fallback otherwise.
  SIMD dispatch MUST be done via `std::is_x86_feature_detected!` or equivalent
  platform intrinsic — MUST NOT hard-code an ISA assumption at compile time.
  All `unsafe` SIMD blocks MUST carry a `// SAFETY:` comment citing the feature
  guard that proves the intrinsic is available.

- **`GpuBackend` / `NpuBackend`**: scaffolded structs that return
  `Err(HalError::Unimplemented)` for all operations. Marked
  `#[doc = "Phase 3 placeholder — not implemented"]`. MUST compile cleanly.

- **Acceptance criterion**: `nexacore-hal` passes `cargo test` with 0 failures;
  `CpuBackend` resolves to the correct SIMD variant on the CI host; an
  `unimplemented` backend returns `HalError::Unimplemented` without panicking.

#### S2.3. `nexacore-tokenization` v0.3.0

- **`TokenVault`**: TEE-resident store for PII tokens. Seal/unseal operations
  MUST go through the `TeeBackend` trait; the production backend is the
  platform TEE (SGX or TrustZone per device); Phase 2 ships a `MockTeeBackend`
  that stores the sealed blob in RAM for testing. The vault MUST enforce that
  tokens are only unsealed inside a valid TEE enclave boundary (checked via
  `TeeBackend::is_trusted`). Token creation MUST generate a stable opaque
  identifier that cannot be reversed without the vault key.

- **`NerClassifier`**: Named-entity recognition stub. In Phase 2 this is a
  rule-based classifier covering the entity classes required by the policy
  presets (person names, email addresses, phone numbers, SSNs, credit card
  numbers, IBANs). A model-based NER is deferred to Phase 3.

- **`PolicyEngine`**: applies configurable PII handling policies. MUST ship
  three presets: `GdprPolicy`, `HipaaPolicy`, `PciDssPolicy`. Each preset MUST
  specify which entity classes are tokenizable, which are redacted-on-sight, and
  which trigger a `PolicyViolation` error blocking the pipeline.

- **Acceptance criterion**: `nexacore-tokenization` passes `cargo test` with 0
  failures; `TokenVault` seal/unseal round-trips correctly via `MockTeeBackend`;
  all three policy presets reject the appropriate PII entity classes.

#### S2.4. End-to-end integration test

A test in `tests/integration/` (workspace-level) MUST exercise the full round-trip:

1. Register a model in `ModelRegistry` with a valid Ed25519 manifest.
2. Submit a `PipelineRequest` containing raw text with a synthetic PII entity.
3. `nexacore-tokenization` tokenizes the PII entity before the request reaches the
   pipeline.
4. `InferencePipeline` dispatches via `CpuBackend`.
5. The response is detokenized and verified against the expected output.
6. Assert: no raw PII appears in the `PipelineRequest` received by the pipeline.

### S3. Sprint timeline

| Sprint | Weeks | Scope |
|---|---|---|
| **Sprint 1** | 1–2 | Foundation scaffolds expanded: `nexacore-runtime` type skeletons, `nexacore-hal::tensor` trait, `nexacore-tokenization` vault interface. This NCIP activates at Sprint 1 start. |
| **Sprint 2** | 3–4 | Real tensor dispatch + model loading: `CpuBackend` SIMD detection live, `ModelRegistry` Ed25519 verification wired. |
| **Sprint 3** | 5–6 | Inference pipeline end-to-end: `InferencePipeline` integrated with `CpuBackend`, `TierRouter` Tier 0 complete. |
| **Sprint 4** | 7–8 | Tokenization integration + privacy budget v0: `NerClassifier` rule-based stubs complete, `PolicyEngine` three presets enforced, `nexacore-types::encrypted` integration. |
| **Sprint 5** | 9–10 | Integration tests + hardening: end-to-end test (§S2.4) passing, clippy clean, all doctests present, no `unsafe` in Phase 2 crates. |

### S4. Phase 2 completion gate

Phase 2 is declared complete when ALL of the following hold simultaneously:

1. `nexacore-runtime`, `nexacore-hal` (tensor module), and `nexacore-tokenization` each pass
   `cargo test --workspace` with 0 failures and 0 ignored tests in their own
   test suite.
2. The Ed25519 manifest verification in `ModelRegistry` rejects a tampered
   manifest (any single-byte mutation in the signature field).
3. `TokenVault` seal/unseal round-trips correctly via `MockTeeBackend` with at
   least 5 distinct token types (covering all NER entity classes in §S2.3).
4. The end-to-end integration test (§S2.4) passes.
5. No `unsafe` code exists in `nexacore-runtime`, `nexacore-hal::tensor`, or
   `nexacore-tokenization`. `nexacore-hal::tensor`'s `CpuBackend` SIMD blocks are
   exempt only if each block carries a `// SAFETY:` comment proving the feature
   guard.
6. `cargo clippy --workspace --all-targets -- -D warnings` passes with zero
   diagnostics.
7. Every public item in all three crates carries a `///` doc comment.

#### Gate status — TASK-17 (2026-06-08, ADR-0039)

All seven criteria are MET (verified on the commit closing TASK-17):

1. ✅ Workspace tests green (`cargo test --workspace`, 0 failures) — incl.
   `nexacore-runtime`, `nexacore-hal::tensor`, `nexacore-tokenization`.
2. ✅ `ModelRegistry` rejects a tampered manifest — `registry_register_
   tampered_hash_fails` + `registry_register_invalid_signature_fails`. TASK-17
   ALSO added a **trusted-issuer allowlist** (ADR-0039): `register` refuses a
   valid-but-untrusted issuer (`registry_register_unknown_issuer_rejected`,
   `registry_empty_allowlist_rejects_all`), closing "firma di issuer non noto
   → rifiutato".
3. ✅ `TokenVault` seal/unseal round-trips ALL NER entity classes via
   `MockTeeBackend` — `vault::tests::seal_unseal_round_trip_all_entity_classes`
   (PersonName, Email, Phone, Ssn, CreditCard, Address, Custom). Sealed-key
   cleartext-leak guard: `nexacore-tee` `shared_key_debug_is_redacted`.
4. ✅ End-to-end zero-PII boundary test — `e2e_inference::e2e_zero_pii_
   inference_boundary`: PII text → tokenization (GDPR) → BPE → forward →
   decode, asserting the raw email/phone never cross into or out of the model.
5. ✅ No `unsafe` in the three crates (tensor SIMD blocks carry `// SAFETY:`).
6. ✅ `cargo clippy --workspace --all-targets --all-features -- -D warnings`
   clean (the local pre-push gate).
7. ✅ Public items documented (doc-strict CI).

**P1.1–P1.3 audit:** re-verified against current code; all implementation
sub-tasks present + tested (see the backlog P1 section). Two acceptance items
remain OPEN as tracked exceptions, NOT blockers for the inference-gate
criteria above: the external **cryptographer review (P3.2)** and the
**per-primitive `cargo bench` baselines** for `nexacore-crypto`.

---

## Rationale

### R1. Why Tier 0 before Tier 1

Tier 0 (local-only inference) is the most constrained execution environment in
the tier model: no network egress, no distributed coordination, no peer trust
assumptions. Proving correctness and security in this environment first means the
Phase 2 threat surface is bounded to a single device under a single user's physical
control. Bugs discovered at Tier 0 are contained; bugs discovered first at Tier 1
(cluster) could expose data across multiple nodes before detection.

The alternative — starting with Tier 1 to exercise the full routing logic — was
rejected because Tier 1 requires a mesh protocol that is not yet production-ready
(per [`docs/03-mesh-protocol.md`](../docs/03-mesh-protocol.md)) and because
getting cluster coordination correct before the local inference pipeline exists
produces a system that cannot be tested in isolation.

### R2. Why Ed25519 for model attestation

Ed25519 is already used by `nexacore-crypto` for capability signing (NCIP-Crypto-002).
Re-using the same signature scheme for model manifests means the verification
infrastructure (key management, RNG, side-channel mitigations) is shared and
already audited. RSA-2048 was considered and rejected: same security level as
Ed25519 at 2–3× the signature size and 10–20× the verification cost. ECDSA over
P-256 was considered and rejected: implementation complexity (cofactor issues,
malleability) makes P-256 harder to implement correctly than Ed25519 in a
`no_std` environment.

### R3. Why a rule-based NER stub in Phase 2 instead of a model-based classifier

A model-based NER classifier introduces a circular dependency: the AI Runtime
Service that loads models must itself be bootstrapped before it can load the NER
model. Phase 2 breaks this circularity by shipping a rule-based classifier for the
limited set of PII entity classes required by GDPR/HIPAA/PCI. The rule-based
approach handles structured PII (SSNs, credit card numbers, IBANs, phone numbers,
email addresses) with high precision via regex patterns — the exact category where
rule-based methods outperform neural classifiers at low false-negative cost. A
model-based NER for free-text PII (person names in arbitrary prose) is deferred to
Phase 3, when the runtime is ready to host it without circularity.

### R4. Why `MockTeeBackend` rather than deferring tokenization to Phase 3

Deferring the vault to Phase 3 was considered. Rejected because: (a) the
`PolicyEngine` must exercise the vault seal/unseal path to be meaningfully testable;
(b) the interface between `InferencePipeline` and `nexacore-tokenization` must be
stabilized in Phase 2 to avoid a breaking API change at Phase 3 entry; (c) the
`MockTeeBackend` costs near-zero to implement (in-memory blob storage) and
provides a complete contract for Phase 3's real TEE backend to satisfy. Postponing
the vault interface means two costly API-redesign rounds instead of one.

### R5. Why the remaining Phase 1 items do not block Phase 2 entry

P5.2/P5.3 (TEE hardware backends for SGX and TrustZone) are gated on hardware
procurement funding. P6.8 (external security audit) is gated on audit-firm
engagement funding. Neither item changes the Phase 1 API surface — both are
purely additive backends and quality-assurance activities. Waiting for
funding-dependent items before beginning Phase 2 would be equivalent to halting
development on an external budget constraint, with no guarantee of timeline.
The `MockTeeBackend` pattern means Phase 2 development proceeds against a testable
interface that the real TEE backend will satisfy when hardware is available.

---

## Backwards Compatibility

Phase 1 kernel interfaces are unchanged. `nexacore-runtime`, `nexacore-hal::tensor`, and
`nexacore-tokenization` are new user-space crates with no prior public API. The
`nexacore-hal` crate's existing (non-tensor) modules are not modified by this NCIP.

The `nexacore-types::encrypted` integration (§S1, item 4) may require additive
changes to `crates/nexacore-types`. These changes MUST be strictly additive (no
removals, no signature changes to existing public items) and MUST be coordinated
with the nexacore-types owner before landing.

No breaking changes are introduced to any Phase 1 crate.

---

## Test Cases

### T1. Model signature verification

- **T1.1** `ModelRegistry::register` with a valid Ed25519 manifest and correct
  signature MUST return `Ok(model_id)`.
- **T1.2** `ModelRegistry::register` with a manifest whose signature has a
  single-byte mutation at any position MUST return `Err(SignatureInvalid)`.
- **T1.3** `ModelRegistry::register` with a duplicate model ID MUST return
  `Err(ModelAlreadyRegistered)`.

### T2. Token vault seal/unseal

- **T2.1** `TokenVault::seal(token_value)` via `MockTeeBackend` MUST produce a
  sealed blob that cannot be decoded as plaintext.
- **T2.2** `TokenVault::unseal(sealed_blob)` via `MockTeeBackend` MUST return
  the original `token_value`.
- **T2.3** `TokenVault::unseal` with a tampered sealed blob MUST return
  `Err(VaultIntegrityError)`.
- **T2.4** Round-trip over all NER entity classes MUST succeed: person name,
  email address, phone number, SSN, credit card number, IBAN.

### T3. Inference pipeline

- **T3.1** An `InferencePipeline` with a registered model and a fully-tokenized
  request MUST return `Ok(PipelineResponse)` without panicking.
- **T3.2** An `InferencePipeline` request containing raw PII (detected by the
  `PolicyEngine`) MUST return `Err(RawPiiDetected)` before reaching the tensor
  backend.
- **T3.3** `TierRouter` with a Tier 1 request in Phase 2 MUST return
  `Err(TierUnavailable)`.

### T4. SIMD dispatch

- **T4.1** On an AVX2-capable host, `CpuBackend::dispatch` MUST select the AVX2
  codepath (verified via a test-mode feature flag or tracing instrumentation).
- **T4.2** On a host without AVX2/NEON, `CpuBackend::dispatch` MUST fall back to
  the scalar codepath without panicking.

### T5. End-to-end integration (§S2.4)

The integration test at `tests/integration/phase2_e2e.rs` MUST:

- **T5.1** Complete without any `panic!` or `unwrap` failure.
- **T5.2** Assert that the `PipelineRequest` received by the `InferencePipeline`
  contains no raw PII string that was present in the original input.
- **T5.3** Assert that detokenizing the response recovers the original PII value.

---

## Reference Implementation

- **`crates/nexacore-runtime`**: scaffolded at Phase 2 Sprint 1; v0.3.0 target for
  Phase 2 completion gate.
- **`crates/nexacore-hal`** (`tensor` module): expanded at Phase 2 Sprint 1.
- **`crates/nexacore-tokenization`**: scaffolded at Phase 2 Sprint 1; v0.3.0 target.
- **`tests/integration/phase2_e2e.rs`**: added at Sprint 5.
- Development plan tracking: Phase 2 entries in the project backlog.

---

## Security Considerations

### SC1. Model attestation is a hard requirement — no unsigned models

Every model loaded into `ModelRegistry` MUST carry a valid Ed25519 signature
from the operator signing key. An unsigned model load path MUST NOT exist. This
requirement protects against model-substitution attacks (adversary swaps a
legitimate model for a backdoored one on disk) and against dependency-confusion
attacks (adversary publishes a plausible model ID to a registry the runtime
consults). The signing key MUST be stored in the TEE key store, not on the host
filesystem. Key rotation policy is out of scope for this NCIP and MUST be addressed
in a follow-up NCIP before Phase 2 completion.

### SC2. Token vault boundary enforcement

The `TokenVault` MUST only unseal tokens when `TeeBackend::is_trusted` returns
`true`. A `MockTeeBackend` in production (non-test) builds MUST be a compile
error, enforced by a `#[cfg(not(test))]` guard on the mock type. Leaking PII
outside the vault boundary — via logging, debug formatting, or error messages —
is a critical defect and MUST be caught by the `PolicyEngine` before any
pipeline invocation.

### SC3. No network egress during Tier 0 inference

The `TierRouter` in Phase 2 MUST enforce the Tier 0 constraint at the type level:
`Tier0Request` and `Tier1Request` MUST be distinct types, not a runtime flag on
a common type. This prevents a flag-flip bug from accidentally routing Tier 0
inference over the network. The compiler MUST reject a Tier 0 request being
passed to the Tier 1 dispatch path.

### SC4. SIMD unsafe blocks require feature guards

Every `unsafe` block in `CpuBackend` that uses SIMD intrinsics MUST be guarded
by a runtime feature check (`std::is_x86_feature_detected!("avx2")` or
equivalent). The `// SAFETY:` comment MUST cite the specific guard and explain
why the feature check provides the required invariant. An unguarded SIMD block
is an illegal instruction on CPUs that do not support the feature and MUST be
treated as a critical bug.

### SC5. No PII in error messages or log output

`tracing` instrumentation in `nexacore-tokenization` and `nexacore-runtime` MUST NOT
log token values, PII entity strings, or model input/output tensors at any log
level. Structured logging of metadata (model ID, latency, entity class without
value) is permitted. This requirement MUST be enforced in code review and in the
Phase 2 completion gate checklist.

### SC6. Threat model alignment

Phase 2 crates operate under adversary classes A1 (physical access) and A4
(compromised user-space service) from
[`docs/04a-threat-model.md`](../docs/04a-threat-model.md). The TEE vault
boundary (SC2) addresses A1 for token data; the type-level Tier 0 enforcement
(SC3) addresses A4 for inference routing. Adversary class A5 (supply-chain:
malicious model) is addressed by SC1.

---

## Privacy Considerations

### PC1. PII never leaves the device unencrypted

The Tier 0 constraint (§S1, §SC3) ensures that model inputs (which may contain
tokenized PII references) never transit a network interface during Phase 2. The
token vault (§S2.3) ensures that PII values are sealed before storage and
unsealed only inside the TEE boundary. These two controls together satisfy the
GDPR Article 5(1)(f) "integrity and confidentiality" principle for the Phase 2
threat model.

### PC2. Token identifiers must not be reversible without the vault key

Token identifiers generated by `TokenVault` MUST be opaque pseudonyms — they
MUST NOT be derivable from the original PII value without possession of the vault
key. This satisfies the GDPR pseudonymization requirement under Article 4(5) and
Article 25 (data protection by design). A token that encodes a hash of the PII
value without a secret key component would be a pseudonym only under the assumption
of preimage resistance, which is insufficient given modern GPU-based dictionary
attacks on known PII formats (SSNs, credit card numbers). The vault key MUST be a
randomly generated symmetric key sealed in the TEE.

### PC3. NER rule-based classifier: false-negative risk and documentation

The rule-based `NerClassifier` in Phase 2 has known limitations for free-text
person names and organization names in arbitrary prose. The `PolicyEngine` MUST
expose a `Policy::strict_mode` flag that, when enabled, passes all unrecognized
text through a `PolicyViolation::UnclassifiedContent` error rather than allowing
it through. Documentation MUST clearly state that Phase 2's NER covers only
structured PII entity classes and that strict mode is RECOMMENDED for HIPAA and
GDPR processing contexts.

### PC4. Model weights as privacy-sensitive data

AI model weights can encode memorized training data (Carlini et al., 2021;
Carlini et al., 2023). `nexacore-runtime` MUST store model weights in `NCFS`
(Phase 2: in-memory BLK channel) under the same AEAD protection applied to user
data. Model weight files MUST NOT be accessible to user-space processes outside
the `nexacore-runtime` service boundary. Weight exfiltration via the inference API
is an out-of-scope threat for Phase 2 but MUST be documented as a known risk
to address in Phase 3.

### PC5. Audit log entries for vault operations

Every `TokenVault::seal` and `TokenVault::unseal` operation MUST emit a
structured audit event containing: timestamp, operation type, entity class
(without the entity value), and the requesting pipeline ID. PII entity values
MUST NOT appear in audit logs. This satisfies the GDPR Article 30 records-of-
processing requirement and provides forensic traceability without creating a
secondary PII exposure surface.

---

## Copyright

This NCIP is released into the public domain under
[CC0-1.0](https://creativecommons.org/publicdomain/zero/1.0/).
