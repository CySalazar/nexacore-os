# Architecture Overview

**Status:** Draft v0.1.1 — foundational layer implemented (P1, 2026-05-10).

## Executive summary

NexaCore OS is structured in concentric layers, from a custom Rust microkernel up to the application layer. AI is a first-class kernel concept, not a userspace addition. Computation can happen entirely on the local device, distributed across the user's own devices on a personal LAN cluster, federated across the global P2P mesh, or — as a last resort — sent to commercial cloud providers.

## Implementation status

| Layer | Crates | State (2026-05-20, post `v0.3.0-alpha.1` + P6.7.8.9) |
|---|---|---|
| Foundational | `nexacore-types`, `nexacore-crypto`, `nexacore-capability` | **Implemented** (P1 closed). `no_std + alloc`, RFC test vectors per primitive. `nexacore-crypto` carries the `AWAITING_CRYPTO_REVIEW` marker pending P3.2 cryptographer review. |
| TEE root of trust | `nexacore-tee` | Trait surface declared (`nexacore_capability::tee::AttestationSource` + `StubAttestation`); concrete Intel TDX / AMD SEV-SNP backends land in P5.2 / P5.3 (funding-dependent). |
| **Microkernel** | `nexacore-kernel` | **MB1–MB14 cycle closed (v0.3.0-alpha.1, 2026-05-20).** Bare-metal `no_std + no_main` on `x86_64-unknown-none` via UEFI (`bootloader 0.11`). Frame allocator, 4-level paging, IDT, SYSCALL/SYSRET + INT 0x80, ELF64 loader, scheduler, LAPIC preemption, Ring 3 + per-process CR3, IPC + multi-task, kernel-stack isolation, MP boot (AP INIT-SIPI live), TLB shootdown, per-CPU run queues, x2APIC, AP dispatch + cross-CPU context switch (MB14.h.2 + `SCHED_LOCK`). Track A desktop (GOP framebuffer, bitmap font, software cursor, PS/2 + VirtIO tablet, widget toolkit, WM, RTC clock, ACPI S5, Build Info panel) all live. |
| **User-space driver framework** | `nexacore-kernel` (`driver_manifest`, `cap_deposit`, `driver_cap_issuer`, `entropy`, `known_issuers`), `nexacore-driver-net-virtio`, `nexacore-driver-nvme`, `nexacore-driver-e1000e` (+ workspace-excluded bootable `*-image` siblings) | **`NCIP-013/014/015/016` Active.** Full `NCIP-013` syscall set wired: `MmioMap (70)`, `DmaMap (71)`, `IrqAttach (72)`, `DriverLoad (73)`. Kernel-side capability infrastructure: `ChaCha20Rng` CSPRNG seeded from `RDRAND` + `RDTSC`, Ed25519 driver-capability issuer signing key, 32 KiB read-only capability deposit window mapped per driver at user-VA `0x0010_0000`. Three first-party driver scaffolds + bring-up FSMs + bootable image siblings landed (P6.7.8.0–9). Next: P6.7.8.10 driver-shared SDK helper for token lookup, then live driver bring-up + Proxmox hardware smoke. |
| Hardware Abstraction | `nexacore-hal` | Stub. P6–P7. |
| System services | `nexacore-runtime`, `nexacore-mesh`, `nexacore-tokenization` | Stubs. Phase 2+. The `nexacore-tokenization` crate is the only one authorised to enable `nexacore-types`'s `_tokenization_provider` feature flag (the construction gate for `EncryptedString` and friends). |
| User-facing | `nexacore-sdk`, `nexacore-agent`, `nexacore-shell` | Stubs. Phase 2+. |

See [`/CHANGELOG.md`](../CHANGELOG.md) for the per-release record.

## High-level system layers

```
┌─────────────────────────────────────────────────────────────────────┐
│                  Applications and Agents (userspace)                │
├─────────────────────────────────────────────────────────────────────┤
│   Application SDK   │   Agent Framework    │   System UI / Shell   │
├─────────────────────────────────────────────────────────────────────┤
│  AI Runtime  │  Mesh Protocol  │  Filesystem  │  Networking  │ ... │
│   Service    │     Service     │   Service    │    Service   │     │
├─────────────────────────────────────────────────────────────────────┤
│             Microkernel — Rust, message-passing IPC                 │
│   Memory mgmt │ Scheduling │ Capabilities │ IPC primitives          │
├─────────────────────────────────────────────────────────────────────┤
│   Tensor HAL  │   Network HAL   │   Storage HAL  │   TEE HAL        │
├─────────────────────────────────────────────────────────────────────┤
│   Hardware: CPU + NPU/GPU + TEE + Secure Storage + Network          │
└─────────────────────────────────────────────────────────────────────┘
```

### Microkernel (Rust)

NexaCore OS is built on a microkernel architecture, written entirely in Rust (2024 edition). The kernel is responsible only for:

- Memory management (virtual memory, page tables, allocators)
- Process and thread scheduling
- Inter-process communication (typed message passing)
- Capability-based security primitives
- Hardware abstraction interfaces (HAL contracts)

Everything else — filesystems, drivers, networking stacks, AI runtime — runs as user-space services communicating via IPC. This minimizes the trusted computing base (TCB) and provides strong isolation between subsystems.

The microkernel choice is motivated by:

- **Security**: smaller TCB → smaller attack surface.
- **Stability**: faults in one service do not crash the kernel.
- **Modularity**: services can evolve and be replaced without kernel changes.
- **Verifiability**: a small kernel is amenable to formal methods over time.

### AI Runtime Service

A privileged user-space service that exposes AI as a system primitive. Responsibilities:

- Model lifecycle (load, unload, version, attest)
- Inference scheduling across available accelerators
- Capability validation for AI invocations
- Routing decisions across execution tiers
- Tokenization and encrypted-data-type support

System calls exposed to applications:

- `ai_invoke(model, prompt, capability) -> response`
- `ai_stream(model, prompt, capability) -> stream<token>`
- `ai_embed(model, text, capability) -> vector`
- `ai_classify(model, input, capability) -> label`
- `ai_transcribe(model, audio, capability) -> text`

All calls take a capability token; the AI Runtime Service refuses calls without valid capabilities.

### Mesh Protocol Service

Manages all peer-to-peer interactions: discovery, authentication, routing, compute credit accounting, compliance proof generation and verification. Detailed in [03-mesh-protocol.md](./03-mesh-protocol.md).

### Tensor HAL

Hardware Abstraction Layer for AI accelerators. Processes targeting AI workloads do not need to know whether inference runs on CPU AVX-512, integrated GPU, discrete GPU, or NPU. The HAL handles dispatch and resource allocation.

Supported backends (planned for v1):

- CPU (with AVX-512 / AVX2 fallback)
- NVIDIA CUDA (via wrapper, runtime-loaded)
- AMD ROCm (via wrapper, runtime-loaded)
- Apple Metal (v1.1+)
- Intel/AMD integrated GPU via Vulkan compute

### TEE HAL

Hardware Abstraction Layer for Trusted Execution Environments. Provides a uniform API for:

- Generating remote attestation reports
- Provisioning sealed keys
- Executing confidential workloads
- Sealed memory regions

Supported TEEs (v1):

- Intel TDX
- AMD SEV-SNP

Future (v1.1+): Apple Secure Enclave, ARMv9 CCA Realms.

## Execution tiers

NexaCore OS evaluates each AI workload against four execution tiers and selects the most appropriate based on workload sensitivity, user policy, available resources, and latency requirements.

### Tier 0 — Local-only (default)

The workload runs entirely on the local device. No network involved. Used for:

- Lightweight assistants (autocomplete, classification, embedding)
- Sensitive data that must never leave the device
- Offline operation
- Real-time interactive workloads

**Constraints:** limited by local hardware capacity. Suitable for models up to ~8B parameters (quantized).

### Tier 1 — Personal Cluster

The user's own devices (laptop + desktop + tablet + phone) discover each other via mDNS on the local network and form a private cluster, encrypted with mTLS. Models are split across devices using pipeline parallelism.

**Constraints:** requires LAN. Latency between devices must be < 5ms. Suitable for models up to ~70B parameters using aggregated VRAM.

### Tier 2 — Federated Mesh (opt-in)

Opt-in P2P network of NexaCore OS instances. Detailed in [03-mesh-protocol.md](./03-mesh-protocol.md). Uses MoE expert distribution: each expert (or expert group) is hosted on different nodes; only 2 of N experts are active per token.

**Constraints:** higher latency (≥30ms RTT typical). Best for asynchronous, long-form workloads. Suitable for models 100B+ parameters.

**Privacy:** all payloads are wrapped in TEE-only decryption envelopes; PII is tokenized; compliance proofs are mandatory. See [04-security-model.md](./04-security-model.md).

### Tier 3 — Commercial cloud (opt-in, last resort)

Used only when explicitly authorized by the user for a specific query, or when no other tier is feasible and the user has pre-approved cloud fallback. Always requires explicit consent. Privacy budget consumption is tracked.

## Model architecture: MoE-first

The reference public model for NexaCore OS uses a Mixture of Experts (MoE) architecture:

- 16 to 32 experts per layer (final number set by reference model selection at v1 implementation)
- Top-2 expert selection per token (sparse activation)
- Expert weights distributable across mesh nodes
- Only 2 of N experts active per token → minimal cross-node traffic per inference step

This architecture is chosen because it natively supports fragmentation across the federated mesh. Pipeline parallelism remains usable for personal cluster scenarios, where latency is low and dense models can be efficiently split layer-wise.

Dense models (non-MoE) are supported as second-class citizens: they can run locally or in personal cluster, but are not first-class for federated mesh.

## Privacy primitives (architectural)

The architecture mandates that PII never travels in cleartext over the mesh. This is enforced at the protocol level by:

1. **Encrypted-by-default data types** at OS API level (`EncryptedString`, `MaskedSSN`, `TokenizedEmail`, etc.).
2. **Tokenization service** that replaces PII with deterministic tokens before any inference.
3. **Format-preserving encryption** (FF1, FF3-1) for routing metadata.
4. **Compliance proofs** (zk-SNARKs or signatures) attached to every mesh payload.
5. **TEE-only decryption envelope** — sensitive data is decryptable only inside attested enclaves.

Detailed in [04-security-model.md](./04-security-model.md).

## Capability-based security

Every system action requires a capability token: a cryptographically signed structure that names the action, the actor, the resource, and time bounds. Capabilities are issued by the kernel, stored in TPM/Secure Enclave, and verified at every boundary.

This replaces the traditional Unix permission model, which is insufficient for AI agents that may compose actions across many resources.

Capability properties:

- **Scoped**: name a specific action and resource.
- **Time-bounded**: short TTL (minutes), refreshed as needed.
- **Attenuable**: an agent can derive a more restricted child capability for a sub-agent (Macaroons-style).
- **Revocable**: short TTL + revocation list ensures fast revocation.

## Implementation choices (committed)

| Decision | Choice | Rationale |
|---|---|---|
| Language | Rust 2024 edition | Memory safety + performance + crypto ecosystem |
| Architecture | Custom microkernel | Minimal TCB, full control, generational stability |
| Initial hardware | x86_64 with TDX/SEV-SNP | TEE-attestable, mainstream developer hardware |
| Model architecture | MoE | Mesh-friendly fragmentation |
| License | Apache-2.0 | Mission protection + funding flexibility |

See [09-tech-specifications.md](./09-tech-specifications.md) for exact versions.

## NexaCore App Mesh — the user-facing AI-native layer

NexaCore OS treats application discovery, installation, generation, and marketplace curation as **integrated OS primitives**, not as orthogonal apps. The five components are governed by five NCIPs filed 2026-05-12:

```
┌────────────────────────────────────────────────────────────────────┐
│  NexaCore Helper (NCIP-Helper-007)                                       │
│  • detects need (file-failure / explicit-invoke / watch opt-in)     │
│  • 3 autonomy levels: Autonomous / Guided (default) / Inform        │
│  • mandatory Impact Dashboard (Privacy / Trust / Cost / Time)       │
│  • escalation taxonomy for destructive / privacy / cap-escalation   │
│  • 30s undo window in Autonomous mode                               │
└───────────────────────────────┬────────────────────────────────────┘
                                ▼
              ┌─────────────────┴─────────────────┐
              │                                   │
   ┌──────────▼──────────┐         ┌──────────────▼──────────────┐
   │ nexacore-pkg (008)      │         │ nexacore-forge (009)            │
   │ content-addressed   │         │ Rust → WASM/ELF on-demand   │
   │ federated package   │         │ generation pipeline; LLM    │
   │ manager, Sigstore   │         │ source gen + static analysis│
   │ + CT log mandatory; │         │ + capability inference +    │
   │ capability manifest │         │ TEE-bound ephemeral signing │
   │ atomic upgrade      │         │ + mandatory first-run review│
   └──────────┬──────────┘         └──────────────┬──────────────┘
              │                                   │
              ▼                                   ▼
   ┌──────────────────────────────────────────────────────────────┐
   │ nexacore-market (NCIP-Market-010)                                  │
   │ Stichting-curated marketplace + community-federated optional  │
   │ Bronze / Silver / Gold / Stichting-Curated tiers              │
   │ continuous CVE scan with public SLA (Critical: 14d)           │
   │ 0% OSS / 10% commercial / 0% Stichting-sponsored commission   │
   └──────────────────────────┬────────────────────────────────────┘
                              ▼
   ┌──────────────────────────────────────────────────────────────┐
   │ NexaCore* flagship apps (NCIP-Flagship-011)                        │
   │ NexaCoreCode (Codium-in-container Phase 1, Tauri-native Phase 2)  │
   │ NexaCoreShell · NexaCoreMail · NexaCoreNotes · NexaCoreDocs · NexaCorePhotos …    │
   │ Stichting-Curated tier in nexacore-market; Apache-2.0; no telemetry │
   └──────────────────────────────────────────────────────────────┘
```

The same `NexaCoreContainer` engine (per [NCIP-Container-006](../oips/oip-container-006.md))
runs Linux apps from nexacore-pkg, Windows apps via Wine-in-container, AOT-generated apps from nexacore-forge, and flagship apps. The Helper, Pkg, Forge, Market, and Flagship layers all converge on a single execution substrate.

This synthesis — agentic discovery + federated package manager + generation pipeline + Foundation-curated marketplace + flagship reference apps — has no equivalent in Windows / macOS / Linux today, and is the single most distinguishing feature of NexaCore OS at the user-experience layer.

## Open architectural questions

These will be resolved during Phase 1 implementation, captured as NCIPs:

- **IPC message format**: Cap'n Proto vs. custom binary format. Cap'n Proto is mature; custom can be more compact.
- **Driver model**: separate processes per driver (max isolation, higher overhead) vs. driver service composition.
- **Boot architecture**: UEFI-only vs. UEFI + legacy BIOS support. Likely UEFI-only given hardware baseline.
- ~~**Filesystem**: native NexaCore FS vs. existing options (ZFS port, ext4 via compatibility).~~ **Resolved by [`NCIP-FS-018`](../oips/oip-fs-018.md) (Active, 2026-05-22, §5.3 ¶1 ballot):** native `NCFS` is the single canonical persistent filesystem (Rust, user-space behind the BLK channel of [`NCIP-Driver-NVMe-014`](../oips/oip-driver-nvme-014.md), CoW, capability-bound, AEAD-integrity, per-volume confidentiality), delivered phased v0 (Phase 2, in-memory) → v1 (Phase 3, persistent, on-disk format frozen by `NCIP-FS-Wire-NNN` follow-up) → v2 (Phase 4+, mesh-replicated). Quantitative parameters frozen in NCIP-FS-018 §S1.1 (4 KiB fixed block size, 64 ZiB max volume, 8 EiB max file, BLAKE3-keyed MAC 256-bit integrity, 32-byte capability fingerprint, no hard links, default-off opt-in ZSTD compression, no v1 dedup, no v1 multi-device). Foreign filesystems (ext4, NTFS) admitted only as **read-only compatibility user-space services** behind a `READONLY_COMPAT_FS` capability, scheduled no earlier than Phase 3 (`NCIP-FS-Compat-Ext4-NNN`, `NCIP-FS-Compat-NTFS-NNN` follow-ups). **ZFS port rejected for v0–v2** on Apache-2.0/CDDL license incompatibility, port effort, and absence of capability binding; revisitable in v3.x. **Wire-format status (2026-06-12, ADR-0051):** the v1 on-disk format ([`NCIP-FS-Wire-023`](../oips/oip-fs-wire-023.md), Active, + encoding-v2 erratum) does not yet reach several §S1.1 parameters; the reconciliation format v3 is [`NCIP-FS-Wire-027`](../oips/oip-fs-wire-027.md) (Draft — dual-superblock CoW root commit, extents, NFC directory objects, capability fingerprint, Merkle integrity, mandatory AEAD), gated on independent review per [`NCIP-Review-Gate-028`](../oips/oip-review-gate-028.md). The live specified-vs-implemented state per §S1.1 parameter is tracked in [`docs/ncfs-compliance-matrix.md`](./omnifs-compliance-matrix.md).
- ~~**POSIX compatibility layer**: yes/no/partial. Affects userspace porting effort vs. ideological purity.~~ **Resolved by [`NCIP-Container-006`](../oips/oip-container-006.md) (2026-05-12):** no POSIX in the NexaCore kernel; POSIX exists only inside guest Linux of NexaCoreContainers (micro-VM container engine with capability-bound virtio I/O). Linux apps and Windows apps (via Wine-in-container) are first-class via this path.
