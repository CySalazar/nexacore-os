# Roadmap

**Status:** Draft v0.1

## Overview

NexaCore OS is a multi-year, multi-phase project. The roadmap below is high-level and indicative. Specific milestones will be detailed at the start of each phase via NCIPs.

## Phases

### Phase 0 — Foundation (months 0–6)

**Goal:** establish legal, financial, and organizational foundation.

Key deliverables:

- Stichting NexaCore established in the Netherlands with ANBI status pursued.
- Initial funding secured (target: 6 months runway, ~€350K).
- Core team assembled: Lead Architect (founder) + 2 senior Rust engineers + 1 cryptographer.
- All `/docs` finalized to v0.1.
- Public repository live with Apache-2.0 license.
- NCIP process documented and operational; [`NCIP-Process-001`](../oips/oip-process-001.md) `Active` since 2026-05-10 (under bootstrap fiat clause; first formal vote deferred to first non-`Meta` NCIP filed).
- Foundation bylaws published.

### Phase 1 — Microkernel proof-of-concept (months 6–18)

**Goal:** custom Rust microkernel boots on bare-metal x86_64 with TEE and basic services.

**Tracking status (updated 2026-07-12, post `v0.3.0-alpha.2`):** measured on two independent axes, because a single percentage conflates implementation effort with capability maturity.

- **Engineering tasks:** ≈ 99 % of the planned Phase-1 implementation work is complete. The open items are P6.7.8.10 (driver-shared SDK helper that consumes the capability deposit window) and P6.7.9 (driver live bring-up + Proxmox hardware smoke).
- **Phase-1 acceptance criteria:** 4 of 6 satisfied. The two open criteria are hardware TEE attestation (Intel TDX / AMD SEV-SNP, P5.2/P5.3) and the first external security audit (P6.8) — both funding-dependent, and both carrying architectural weight far above their task count. The project therefore does **not** claim Phase 1 "closed" on task-count alone.

Key deliverables:

- ✅ Microkernel boots on x86_64 hardware (UEFI, `bootloader 0.11`); ⬜ Intel TDX / AMD SEV-SNP TEE attestation (funding-dependent, P5.2/P5.3).
- ✅ IPC primitives operational (typed message passing) — MB12.
- ✅ Capability-based security primitives implemented — MB13 + P6.7.8.9 capability deposit trampoline.
- ✅ Memory management, scheduling, interrupt handling — MB1–MB14.
- 🔄 Drivers (in user space): NVMe storage, Ethernet/Wi-Fi networking, TEE. virtio-net + NVMe + e1000e scaffolds + bootable image siblings landed (P6.7.8.0–7); `DriverLoad (73)` syscall handler + capability deposit trampoline landed (P6.7.8.8–9); next is the driver-shared SDK helper (P6.7.8.10) and live driver bring-up + Proxmox hardware smoke (P6.7.9). TEE backend gated on P5.2/P5.3.
- ✅ Boot loader (UEFI-based) — `kernel-runner` + `bootloader 0.11`.
- ✅ Minimal shell sufficient for development — `nexacore-shell` is a full POSIX-style REPL (lexer/parser, expansion, pipelines, job control, builtins) integrated into the desktop terminal.
- ✅ No AI yet — respected.
- ⬜ First external security audit of kernel + capability system (P6.8, funding-dependent).

### Phase 2 — AI Runtime Service and Tier 0 (months 18–30)

**Goal:** local-only AI inference operational; encrypted-by-default data types in OS API.

Key deliverables:

- AI Runtime Service integrated and exposed via system calls.
- Tensor HAL with CPU + GPU + NPU dispatch (via existing wrappers).
- Local-only inference (Tier 0) operational.
- Reference MoE model selected, signed, distributed.
- Encrypted-by-default data types in OS API (`EncryptedString`, `MaskedSSN`, etc.).
- Tokenization service (local NER classifier + token vault).
- Privacy budget accountant (initial implementation).
- First external security audit of AI Runtime + tokenization.

### Phase 3 — Personal Cluster, Tier 1 (months 30–36)

**Goal:** LAN-based device clustering operational.

Key deliverables:

- mDNS discovery of NexaCore OS devices on LAN.
- mTLS between devices with TEE attestation.
- Pipeline parallelism for medium-sized models across devices.
- Workspace synchronization (basic).
- User onboarding flow for adding devices to personal cluster.

### Phase 4 — Federated Mesh v1, Tier 2 (months 36–48)

**Goal:** P2P mesh operational; v1 release.

Key deliverables:

- Kademlia DHT discovery.
- QUIC + Noise transport with mutual TEE attestation.
- Compliance proofs (signature-based for v1; zk-SNARK-based deferred to v1.x).
- TEE-only decryption envelopes.
- Compute credits ledger (gossip-replicated, signed).
- Reputation system.
- Onion routing (3-hop) for sensitive workloads.
- MoE expert distribution and routing.
- Inference verification via redundancy.
- **v1.0 release: inference-only.**
- Comprehensive external security audit.

### Phase 5 — Hardware expansion v1.1 (year 4)

**Goal:** broaden hardware support.

Key deliverables:

- Apple Silicon support (M-series) with Secure Enclave attestation.
- Performance optimization based on v1 production usage.
- Improved tokenization classifiers.
- v1.1 release.

### Phase 6 — Federated Training v2 (year 4–5+)

**Goal:** federated training across the mesh; community-trained models.

Key deliverables:

- Secure aggregation for gradients.
- Differential privacy noise injection on gradients.
- DiLoCo-style relaxed-sync training across the mesh.
- Expert-level training for MoE (different clusters specialize on different experts).
- Versioned model registry with community fork/merge.
- Training data governance (PII screening, dataset cards mandatory).
- v2.0 release.

### Phase 7 and beyond

Possible directions (subject to NCIP and community direction):

- ARMv9 CCA support (when consumer hardware matures).
- POSIX compatibility layer for legacy software.
- Self-sustaining mesh fee for ongoing development funding.
- Alternative model architectures (state-space models, hybrid).

## Version scope summary

| Version | Inference | Training | Hardware | Tiers | ETA |
|---------|-----------|----------|----------|-------|-----|
| v0.1 | Spec only | — | x86_64 design | All specified | Q4 2026 |
| v1.0 | Yes | No | x86_64 with TEE | 0, 1, 2, 3 | Q4 2030 |
| v1.1 | Yes | No | + Apple Silicon | 0, 1, 2, 3 | Q2 2031 |
| v2.0 | Yes | Yes | + ARM64 server | 0, 1, 2, 3 | Q4 2031 |
| v2.1 | Yes | Yes | + ARMv9 CCA consumer | 0, 1, 2, 3 | TBD |

ETAs are indicative and subject to revision after Phase 0 funding outcomes.

## Stop conditions

The project will publicly evaluate at each phase whether to continue, pivot, or wind down. Triggers for re-evaluation:

- Inability to secure funding for ≥6 months runway despite documented effort.
- Major TEE security breach making attestation untrustworthy across all supported vendors.
- Discovery that a core architectural assumption is fundamentally broken (e.g., MoE distribution proves infeasible in production).
- Loss of core team members without replacement plan.

In any of these cases, the Foundation board will publish a transparent status report and decide on path forward (pivot, hibernate, wind-down) within 90 days.

## Communication cadence

- **Monthly engineering update** (during active phases).
- **Quarterly board meeting summary**.
- **Annual transparency report** (financials, security, progress).
- **NCIP discussions ongoing** in public forum.
