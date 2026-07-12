# Architecture Overview

**Status:** Draft v0.2.0 — foundational, kernel, driver, networking, storage, AI-runtime and desktop layers implemented (2026-07-12).

## Executive summary

NexaCore OS is structured in concentric layers, from a custom Rust microkernel up to the application layer. AI is a first-class kernel concept, not a userspace addition. Computation can happen entirely on the local device, distributed across the user's own devices on a personal LAN cluster, federated across the global P2P mesh, or — as a last resort — sent to commercial cloud providers.

## Implementation status

Snapshot 2026-07-12. The workspace holds **86 crate packages** (56 workspace members plus 15 workspace-excluded bootable `*-image` siblings and support crates), **~7,700 tests**, and a **96-entry kernel syscall surface** (70-syscall frozen ABI v2, see [15-syscall-abi.md](./15-syscall-abi.md)). "Host core" means the crate carries the full auditable, host-tested logic (`no_std + alloc`); the privileged MMIO/DMA/IRQ execution lives in the matching Ring-3 `*-image` sibling.

| Layer | Crates | State |
|---|---|---|
| Foundational | `nexacore-types`, `nexacore-crypto`, `nexacore-capability` | **Implemented.** `no_std + alloc`, RFC/KAT test vectors per primitive. `nexacore-crypto` composes the RustCrypto family (ChaCha20-Poly1305, Ed25519, x25519, HKDF/Argon2, SHA-2/3, BLAKE3, FPE) plus post-quantum ML-DSA-65 (FIPS 204) and ML-KEM-768 (FIPS 203); it still carries the `AWAITING_CRYPTO_REVIEW` marker pending external cryptographer sign-off (`snark.rs` is a deliberate Phase-4 placeholder). `nexacore-capability` implements Macaroons-style attenuable tokens (postcard wire, Ed25519, caveats, TTL, revocation/CRL, sandbox). |
| **Microkernel** | `nexacore-kernel` | **Implemented (~74k LOC).** Bare-metal `no_std + no_main` on `x86_64-unknown-none` via UEFI (`bootloader 0.11`). MB1–MB14 cycle closed: frame allocator, 4-level paging, IDT, SYSCALL/SYSRET + INT 0x80, ELF64 loader, scheduler, LAPIC preemption, Ring 3 + per-process CR3, IPC + pipes + fds, kernel-stack isolation, MP boot (AP INIT-SIPI live), TLB shootdown, per-CPU run queues, x2APIC, cross-CPU context switch. Since then: per-device IOMMU (VT-d + AMD-Vi), PCI ECAM scan, MSI-X, S4 hibernate (`hibernate.rs`) and a device suspend/resume PM framework (`power.rs`), plus the Track-A desktop stack (GOP framebuffer, fonts, cursor, PS/2 + USB HID tablet, WM). |
| User-space drivers | `nexacore-driver-nvme`, `-net-virtio`, `-e1000e`, `-wifi`, `-ahci`, `-tpm`, `-audio`, `-gpu`, `-shared` (+ bootable `*-image` siblings) | **Host cores implemented; hardware execution in the `*-image` siblings.** Full `NCIP-013` syscall set wired (`MmioMap`/`DmaMap`/`IrqAttach`/`DriverLoad`), kernel CSPRNG (`RDRAND+RDTSC → ChaCha20Rng`), Ed25519 capability issuer + 32 KiB read-only deposit window at user-VA `0x0010_0000`. NVMe / virtio-net / e1000e host cores + bring-up FSMs are substantial and live on Proxmox; `-wifi` (WPA2/WPA3 supplicant + 802.11), `-tpm` (TPM 2.0 TIS/CRB + PCR + quote), `-audio` (HDA/virtio-snd + mixer), `-gpu` (virtio-gpu), and `-shared` (capability-deposit SDK) carry host-tested cores. `-ahci` is the least complete (byte-layout core only). |
| Filesystems | `nexacore-fs`, `nexacore-fatfs`, `nexacore-extfs`, `nexacore-ntfs` | **Implemented.** `nexacore-fs` is the native NCFS service (in-memory CRUD + on-disk v3 format: superblock, inodes, extents, dirents, B-tree, Merkle integrity, compression, block crypto, snapshots, mkfs) over a `BlockDevice` seam per `NCIP-FS-018`/`-Wire-027`. Foreign filesystems ship as read-only compatibility readers: FAT12/16/32 (+ mkfat + write), ext2/3/4, and NTFS. |
| Networking | `nexacore-net`, `nexacore-tls`, `nexacore-ssh`, `nexacore-mesh` | **Implemented, except mesh (partial).** `nexacore-net` is a full dual-stack userspace TCP/IP (ARP, IPv4/IPv6, ICMP/ICMPv6, UDP, RFC-793 TCP + Reno, DNS, DHCPv4/v6, NDP/SLAAC, PMTU, conntrack, firewall, socket API). `nexacore-tls` is TLS 1.3 client+server (record layer, HKDF schedule, ALPN, cert path; single cipher suite). `nexacore-ssh` is SSH-2 end-to-end (curve25519 kex, Ed25519 host key, ChaCha20-Poly1305, publickey/password userauth, RFC-4254 channels; NexaCore AEAD profile, not OpenSSH-interop). `nexacore-mesh` is **partial**: discovery (Kademlia DHT, mDNS), the handshake suite, and cluster trust/onboarding are real; `transport` (QUIC+Noise), `routing`, and the top-level `attestation` module remain Phase-4 stubs. |
| AI runtime & tokenization | `nexacore-runtime`, `nexacore-hal`, `nexacore-tokenization`, `nexacore-context` | **Implemented.** `nexacore-runtime` runs a real `no_std` CPU inference chain (GGUF parse, tensor dequant, byte-level BPE, transformer forward, greedy decode — golden `"ab"`→`"dddd"`) plus std providers (`LocalCpuProvider`, `OllamaProvider`) behind a resilient `BackendRouter`; the Ring-3 `nexacore-runtime-image` serves `AiInvoke` with the real CPU engine on hardware. `nexacore-hal` carries a tensor/transformer core (network/storage HAL still scaffold). `nexacore-tokenization` gates `nexacore-types`'s `_tokenization_provider` flag and implements on-device PII detection, a TEE-sealed vault, policy/egress guards. `nexacore-context` is the local-first personal-context store (at-rest crypto, capability + privacy-budget query gate, export/erase). |
| Agents & workflow | `nexacore-agent`, `nexacore-workflow`, `nexacore-sdk` | **Implemented (SDK partial).** `nexacore-agent` is the five-agent framework (orchestrator/guidance/sysadmin/security/task, mode manager, inter-agent protocol, per-agent policy/budget/sandbox, differential-privacy accountant). `nexacore-workflow` is a declarative trigger→steps→actions engine with a capability + Impact gate. `nexacore-sdk`'s `ai`/`agent` bridges are real; its `data` module is a Phase-2 stub. |
| Desktop, UI & media | `nexacore-display`, `nexacore-ui`, `nexacore-desktop-shell`, `nexacore-text`, `nexacore-image`, `nexacore-doc`, `nexacore-media`, `nexacore-fonts` | **Implemented.** `nexacore-display` is a full userspace compositor/WM (damage tracking, surfaces, focus/input routing, glyf font raster/shaping, IME/keymap, effects). `nexacore-ui` is the retained-mode brand toolkit (canvas, widgets, dock/launcher/tray/toast/chat/settings/i18n). `nexacore-text` (PieceTable editor + syntax highlight + AI actions), `nexacore-image` (viewer/editor core), `nexacore-doc` (PDF viewer), and `nexacore-media` (demux + bitstream parsers + AV-sync; codec libs trait-gated) round out the native apps. |
| Userland & services | `nexacore-shell`, `nexacore-usys`, `nexacore-init`, `nexacore-installer`, `nexacore-print`, `nexacore-pkg`, `nexacore-cmd-*` | **Implemented (a few network commands partial).** `nexacore-shell` is a full POSIX-style shell (lexer/parser, expansion, pipelines, job control, ~15 builtins, 454 tests). `nexacore-usys` is the userspace syscall ABI library; `nexacore-init` is the PID-1 supervisor (manifests, dependency graph, health checks, socket activation). `nexacore-installer` builds spec-correct GPT layouts + A/B slots; `nexacore-print` is an IPP stack; `nexacore-pkg` is the content-addressed federated package manager. The `nexacore-cmd-*` family are `no_std` pure-logic tools (ping/traceroute/nslookup/netstat/route/ifconfig/curl/wget complete; `-ssh`/`-scp`/`-nc` parse + frame only, transfer deferred). |
| Container & TEE | `nexacore-container`, `nexacore-tee` | **Partial.** `nexacore-container` is the micro-VM engine (KVM lifecycle, virtio fs/gpu/net/vsock backends, appbridge, Wine-in-container, CLI); confidential-VM (TDX/SEV-SNP) + per-container attestation return `NotYetImplemented`. `nexacore-tee` exposes a vendor-neutral `TeeBackend` with a fully working `MockTeeBackend`; the Intel TDX and AMD SEV-SNP backends are feature-gated scaffolds. |
| Host companion | `nexacore-spark`, `nexacore-crypto`/mesh clients | **Partial.** `nexacore-spark` is the host desktop companion (platform detection, tier-based backend provisioning, signed auto-update); its mesh-connect and tray UI remain placeholders. |

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
