# Glossary

**Status:** Draft v0.1

Terms specific to NexaCore OS, or used in this project with project-specific meaning. Cross-reference for unfamiliar acronyms encountered in other documents.

---

## A

**Agent**
A first-class OS primitive representing an autonomous AI-driven entity with declared policy, persistent context, capability tokens, and computational budget. Distinct from a process or thread; agents may compose actions across many resources.

**Apache-2.0**
Apache License, Version 2.0. The license for NexaCore OS source code. Permissive; allows use, modification, and redistribution (including in proprietary products) with patent protection and attribution requirements.

**AI Runtime Service**
The privileged user-space service that exposes AI as a system primitive. Manages model lifecycle, inference scheduling, capability validation, and routing decisions.

**ANBI**
*Algemeen Nut Beogende Instelling* — Dutch designation for charitable organizations. Stichting NexaCore may pursue ANBI status for tax benefits and donation deductibility.

**Attestation (remote)**
A cryptographic proof produced by a TEE that a specific binary is running on genuine, unmodified hardware in a specific configuration. Required for NexaCore OS mesh participation.

## B

**BDFL**
*Benevolent Dictator For Life*. A common open-source governance pattern. NexaCore OS uses a *time-limited* version: founder has BDFL-style authority for years 1–5 only, then transitions out.

**Blessed model registry**
Stichting NexaCore's curated list of officially-recommended, signed, audited AI models. Distinct from the broader open registry where anyone can publish signed models.

## C

**Capability token**
A signed structure granting a specific actor the right to perform a specific action on a specific resource for a bounded time. Replaces traditional Unix permissions for AI workloads.

**Cap'n Proto**
A serialization protocol providing typed messages with zero-copy reads. Candidate wire format for NexaCore OS IPC.

**CCA**
*Confidential Compute Architecture*. ARMv9's TEE technology, providing Realms for confidential workloads.

**Compliance proof**
A zero-knowledge proof or signature attached to every mesh payload, demonstrating that PII has been tokenized and protocol-mandated encryption rules followed. Honest nodes reject payloads without valid compliance proofs.

**Compute credit**
Unit of accounting for compute exchanged on the NexaCore OS mesh. Tit-for-tat ledger; not a tradeable currency.

## D

**DHT**
*Distributed Hash Table*. Used for peer discovery in the NexaCore OS mesh (Kademlia variant).

**DiLoCo**
*Distributed Low-Communication training*. A relaxed-synchronization approach to federated training enabling efficient distributed training over high-latency networks.

## E

**EAR**
*Encrypted-At-Rest*. Default state for sensitive data in NexaCore OS storage.

**Encrypted-by-default data type**
OS-level type that cannot be instantiated with plaintext PII outside an attested TEE. Examples: `EncryptedString`, `MaskedSSN`, `TokenizedEmail`.

**Expert (in MoE)**
A sub-network within a Mixture-of-Experts model. Only a subset of experts is active per token, enabling efficient distribution across mesh nodes.

## F

**FPE**
*Format-Preserving Encryption*. Encryption scheme that produces ciphertext in the same format as plaintext (e.g., encrypted email looks like an email). NIST-approved algorithms: FF1, FF3-1.

**Federated mesh**
Tier 2 in the NexaCore OS execution tier model. Opt-in P2P network of NexaCore OS instances providing collective compute.

**Foundation**
Stichting NexaCore, the Dutch nonprofit foundation that operates the project. See [05-governance.md](./05-governance.md).

## G

**Granite Rapids**
Future Intel processor generation (post-Emerald Rapids) with TDX support.

## H

**HAL**
*Hardware Abstraction Layer*. NexaCore OS has separate HALs for tensors, network, storage, and TEE.

## I

**IPC**
*Inter-Process Communication*. In NexaCore OS microkernel: typed message passing.

## K

**Kademlia**
A DHT protocol used by NexaCore OS for peer discovery on the federated mesh.

## L

**Linus-style governance**
A BDFL-type governance pattern named after Linus Torvalds. NexaCore OS adopts a time-limited variant with explicit sunset clauses.

## M

**Mesh**
The collective of NexaCore OS instances participating in P2P inference (and, in v2, training). Also: Tier 2 in the execution tier model.

**MoE**
*Mixture of Experts*. Architecture where a model has many "experts" but only a few are active per inference, enabling efficient distribution across nodes. Reference architecture for NexaCore OS public models.

**MSRV**
*Minimum Supported Rust Version*. The earliest Rust toolchain version required to build NexaCore OS.

## N

**Noise Protocol Framework**
A framework for building cryptographic protocols. Used by NexaCore OS for handshakes and key agreement on the mesh.

## O

**NCIP**
*NexaCore Improvement Proposal*. The community process for evolving the protocol. Modeled on IETF RFCs and Bitcoin BIPs.

**Onion routing**
Multi-hop routing where each hop knows only the previous and next, never the origin and destination simultaneously. Used optionally in NexaCore OS for sensitive workloads.

## P

**Personal Cluster**
Tier 1 in the execution model. The user's own devices, on the same LAN, forming a private mesh. Aggregates VRAM and compute across personal devices.

**Pipeline parallelism**
Model distribution strategy where layers are split across nodes. Used in NexaCore OS Tier 1 and dense-model scenarios.

**Privacy budget**
Per-user accountant tracking information disclosure to external parties. When exhausted, queries are refused or downgraded to local-only.

**Proof-of-uptime**
A node's continuous network presence used as a signal in voting weight and reputation. Sybil-resistant when combined with TEE attestation.

**Proof-of-contribution**
Compute work demonstrably delivered to the mesh, used as a signal in voting weight.

## Q

**QUIC**
The transport protocol used by NexaCore OS for mesh communication. Provides multiplexed streams with built-in encryption.

**Quadratic voting**
A voting system where vote weight scales sublinearly with stake/contribution, reducing concentration of decision power. Used in NCIP voting.

## R

**Realm (ARM CCA)**
A confidential execution environment in ARMv9 with CCA. The ARM equivalent of Intel TDX trust domains.

**Reputation**
Per-node score derived deterministically from observable signals: uptime, successful completions, peer consistency, time in network. Locally computed, gossiped but not centrally authoritative.

## S

**SEV-SNP**
*Secure Encrypted Virtualization — Secure Nested Paging*. AMD's TEE technology for confidential VMs.

**Sigstore**
A signature transparency infrastructure. Inspiration for NexaCore OS model signing system.

**Stichting**
Dutch nonprofit foundation legal form. Used by Stichting NexaCore.

**STARK**
*Scalable Transparent ARgument of Knowledge*. A zero-knowledge proof system without trusted setup. Candidate for compliance proofs.

## T

**Taint tracking**
A programming-language and OS-level technique tagging data with provenance metadata. Used in NexaCore OS to mark untrusted data flowing toward AI models.

**TDX**
*Intel Trust Domain Extensions*. Intel's TEE for confidential computing on Sapphire Rapids and later.

**TEE**
*Trusted Execution Environment*. Hardware-isolated execution context that protects confidentiality and integrity of code and data, even from privileged software.

**Tensor HAL**
Hardware Abstraction Layer for AI accelerators. Dispatches inference workloads across CPU/GPU/NPU.

**Tier 0 / 1 / 2 / 3**
Execution tiers in NexaCore OS:
- Tier 0: Local-only (default).
- Tier 1: Personal Cluster (LAN-only across user's own devices).
- Tier 2: Federated Mesh (P2P opt-in).
- Tier 3: Commercial cloud (last resort, opt-in).

**Tokenization (PII)**
Replacement of PII with deterministic tokens at the OS API level. PII never leaves the user's TEE; only tokens flow through the system.

**TPM 2.0**
*Trusted Platform Module 2.0*. Hardware module storing keys and providing measured boot. Used by NexaCore OS for capability key storage and audit log anchoring.

## V

**Veto (founder)**
The time-limited authority of the founder (years 1–5) to *block* protocol breaking changes. Cannot impose changes. Sunsets at year 5 by Stichting bylaws.

## W

**WASM**
WebAssembly. Candidate technology for agent sandboxing in NexaCore OS. Trade-offs against process-level isolation are an open question.

## Z

**zk-SNARK**
*Zero-Knowledge Succinct Non-interactive ARgument of Knowledge*. Cryptographic proof system. Candidate for NexaCore OS compliance proofs requiring complex predicates.

**Zero-Trust**
Architectural principle that no actor — including peers within the network — is trusted by default. NexaCore OS mesh protocol embodies zero-trust through TEE attestation, capability tokens, and compliance proofs for every payload.
