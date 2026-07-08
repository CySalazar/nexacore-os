# ADR-0019 — Phase 2 Entry Rationale

**Status:** Accepted
**Date:** 2026-05-24
**Context:** Phase 1 completion, Phase 2 AI Runtime Foundation entry

## Context

NexaCore OS Phase 1 (Microkernel POC) has reached approximately 99.99% completion:

- Kernel milestones MB1–MB14 are merged, including the final MB14.h.2 cycle
  (cross-CPU context switch, per-CPU dispatch loop).
- Capability system (MB13), IPC message passing (MB12), memory management
  (MB11 per-process CR3), and multi-processor AP startup (MB14) are
  operational.
- Driver framework (NCIP-Driver-Framework-013) validated with three production
  drivers: virtio-net, NVMe, e1000e — all three live-bringup-tested on Proxmox
  (the test VM, proxmox.internal).
- Wave 4 is closed: NCFS v0 skeleton (TASK-011 / ADR-0018), NCIP-Crypto-002
  Draft → Active (TASK-020), postcard wire-format alignment (TASK-022).
- NCIP-FS-018 is Active, committing the project to native NCFS as the
  canonical persistent filesystem.

Remaining Phase 1 items are funding-dependent:
- P5.2/P5.3: TEE hardware backends (SGX, TrustZone) — requires hardware
  procurement budget.
- P6.8: External security audit — requires audit-firm engagement budget.

Neither item modifies the kernel API surface or blocks Phase 2 crate
development.

The roadmap at `docs/06-roadmap.md` places Phase 2 (months 18–30) squarely
on AI Runtime Service, Tier 0 local inference, PII tokenization, and the
Tensor HAL. `docs/02-architecture.md` § Execution tiers defines the Tier 0
(local-only), Tier 1 (cluster), and Tier 2 (public cloud) model. `docs/04-
security-model.md` § Tokenization service defines the PII vault boundary.

## Decision

Enter Phase 2 with the following focus:

1. **`nexacore-runtime`**: AI Runtime Service — `ModelRegistry` (Ed25519 manifest
   verification), `InferencePipeline`, `TierRouter` (Tier 0 local-only).

2. **`nexacore-hal::tensor`**: Tensor Hardware Abstraction Layer —
   `TensorBackend` trait, `CpuBackend` with runtime SIMD detection
   (AVX2 / AVX-512 / NEON), GPU/NPU stubs for Phase 3.

3. **`nexacore-tokenization`**: PII Tokenization Service — `TokenVault` with
   `TeeBackend` trait (production: TEE enclave; Phase 2: `MockTeeBackend`),
   rule-based `NerClassifier`, `PolicyEngine` with GDPR/HIPAA/PCI presets.

**Tier 0 (local-only) first.** No network inference routing in Phase 2.
The `TierRouter` enforces Tier 0 at the type level; Tier 1/2 routing is
deferred to Phase 3.

Phase 2 entry is formally ratified by NCIP-Phase2-Entry-021 (Draft, filed
2026-05-24).

## Alternatives Considered

### 1. Complete all remaining Phase 1 items before entering Phase 2

**Rejected.** The remaining items (P5.2/P5.3 TEE hardware backends, P6.8
external audit) are gated on external budget decisions, not on engineering
readiness. Waiting for them before starting Phase 2 would halt development
on a timeline controlled by funding availability rather than technical
progress. The `MockTeeBackend` design allows Phase 2 development to proceed
against a complete, testable TEE interface that the real hardware backend
will satisfy when hardware is procured.

### 2. Jump directly to NCFS on-disk format (Phase 3 scope)

**Rejected.** The on-disk format for NCFS v1 depends on `NCIP-Crypto-002`
reaching Active status (the AEAD primitive selection) and the NexaCoreCapability
encoding rules stabilizing during the MB13 follow-up. NCIP-FS-018 §R3
explicitly defers on-disk format to `NCIP-FS-Wire-NNN` to be filed at Phase
3 entry. Beginning on-disk format work now would lock cryptographic
primitives before the design is ready, risking a forced reformat at Phase 3
that breaks early adopters. More importantly, the AI Runtime Service is the
project's primary differentiating feature (per `docs/06-roadmap.md`); the
filesystem is infrastructure for it, not the deliverable.

### 3. Begin with Tier 1 (cluster inference) instead of Tier 0 (local)

**Rejected.** Tier 1 requires a production-ready mesh protocol
(`docs/03-mesh-protocol.md`), distributed coordination, and multi-node
trust assumptions — none of which are available at Phase 2 entry. Starting
with Tier 1 before Tier 0 means building distributed-system complexity on
top of an inference pipeline that has never been verified end-to-end in
isolation. A bug at Tier 1 can expose inference data across a cluster; a
bug at Tier 0 is bounded to a single device. Tier 0 first allows the full
security model (attestation, vault boundary, no-egress) to be validated in
the simplest environment.

## Consequences

### Positive

- Phase 2 development begins on a proven microkernel foundation with no
  kernel-API changes required.
- The `MockTeeBackend` pattern decouples Phase 2 progress from TEE hardware
  availability.
- Tier 0 enforcement at the type level (`Tier0Request` / `Tier1Request` as
  distinct types) makes the Tier 0 constraint a compile-time guarantee, not
  a runtime flag that could be accidentally bypassed.
- The rule-based `NerClassifier` avoids the circular-dependency problem (the
  AI Runtime cannot load the NER model before the AI Runtime exists).
- NCIP-Phase2-Entry-021 provides a formal acceptance gate with binary
  pass/fail criteria, preventing Phase 2 from being declared "complete" by
  convention rather than by tested deliverables.

### Negative / Deferred

- P5.2/P5.3 (TEE hardware backends) remain deferred until funding. The
  `MockTeeBackend` is not a production TEE; real hardware validation of the
  vault boundary will not occur until Phase 2 TEE enablement is funded.
- P6.8 (external security audit) remains deferred. Phase 2 code will not
  have had an external audit before it ships; internal review and the
  Phase 5 audit plan remain the primary quality gate.
- Model-based NER (free-text person-name and organization-name detection) is
  deferred to Phase 3. HIPAA and GDPR users who process unstructured prose
  PII MUST use `Policy::strict_mode` in Phase 2, which blocks unclassified
  content from entering the inference pipeline.
- NCFS on-disk format remains unspecified until `NCIP-FS-Wire-NNN` is filed
  at Phase 3 entry. Phase 2's `nexacore-runtime` uses the in-memory NCFS v0
  BLK channel for model weight storage.
