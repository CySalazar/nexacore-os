---
ncip: 6
title: NexaCoreContainer — Native Container Engine with Linux/Windows Compatibility
track: Standards Track
status: Draft
authors:
  - cySalazar <hello@nexacoreos.com>
created: 2026-05-12
updated: 2026-05-12
requires:
  - NCIP-Process-001
  - NCIP-Kernel-003
supersedes: ~
superseded-by: ~
discussion: https://github.com/CySalazar/nexacore-os/discussions (TBD link)
license: CC0-1.0
---

# NCIP-Container-006 — NexaCoreContainer: Native Container Engine with Linux/Windows Compatibility

## Abstract

This NCIP commits NexaCore OS to a **native container engine** named
**`nexacore-container`** as the canonical path for executing Linux and Windows
applications on NexaCore OS. The engine implements **micro-VM container
isolation** (Firecracker/Kata Containers pattern) with:

- A signed minimal **guest Linux kernel image** maintained by Stichting NexaCore.
- **virtio-only I/O** through capability-bound backends in NexaCore userspace.
- **Per-container TEE attestation** on TDX / SEV-SNP capable hosts.
- An **OCI-compatible image format** plus an NexaCore-native extension that
  declares the capability set the container needs.
- **Wine pre-baked images** (`nexacore/linux-wine:N-stable`) for Windows
  application support without a Windows kernel anywhere in NexaCore.

This NCIP **supersedes the open architectural question on POSIX compatibility**
in [`docs/02-architecture.md`](../docs/02-architecture.md) § "Open
architectural questions": the NexaCore kernel does not expose a POSIX ABI;
POSIX/Linux semantics live inside guest Linux of each container, isolated
by HW VM boundary and bound by NexaCore capabilities.

## Motivation

Phase 5+ targets mainstream adoption (≥ 10K mesh nodes within 12 months of
v1.0 per [`docs/06-roadmap.md`](../docs/06-roadmap.md)). Mainstream adoption
without **any** Linux/Windows app compatibility is implausible — the user
base that would tolerate "no existing app works" is well below the project's
generational adoption target.

The previous tentative answer (in `docs/02-architecture.md` open questions)
was "POSIX compatibility: yes / no / partial". Each branch had material
drawbacks:

| Approach | Drawback |
|---|---|
| **Full POSIX in kernel** | Doubles kernel ABI; legacy semantics (`fork`/`setuid`/`/proc`) leak into the NexaCore capability model |
| **Partial POSIX shim** | Leaky abstraction (WSL1 abandoned for this reason); coverage 60-80% |
| **No POSIX at all** | Ecosystem isolation (Plan9 risk) |

The container engine resolves the tension structurally: **POSIX exists, but
only inside guest Linux of micro-VMs, never in the NexaCore kernel**. The user
gets full Linux compatibility (≥ 99% per guest kernel coverage); the NexaCore
kernel stays capability-pure.

This pattern is the state-of-the-art for confidential workloads in industry
as of 2026:

- **AWS Firecracker** (2018) — micro-VM for serverless. Production.
- **Kata Containers** (2017) — micro-VM Linux containers. Production at scale.
- **Apple Container Framework** (2024) — micro-VM containers on macOS with
  Rosetta translation. Production.
- **Windows Hyper-V Containers** (2016) — Windows containers in micro-VMs.
  Production.
- **Confidential Containers (CoCo)** Linux Foundation project — TEE-attested
  containers using TDX / SEV-SNP. Production preview.

NexaCore inherits this pattern and **extends it with mandatory TEE attestation
per-container** as default behaviour (not opt-in).

## Specification

### 1. Container model

Each **NexaCoreContainer** is a micro-VM with:

```
┌────────────────────────────────────────────────────────────────┐
│  User application (Docker image, statically-linked, …)         │
├────────────────────────────────────────────────────────────────┤
│  Guest Linux kernel (nexacore-guest-linux-vN.M, signed, ~10-20MB)  │
│  → standard POSIX, /proc, /sys, fork/exec, namespaces          │
├────────────────────────────────────────────────────────────────┤
│  virtio-fs   virtio-net   virtio-vsock   virtio-gpu (optional) │  ← Capability boundary
├────────────────────────────────────────────────────────────────┤
│  Hypervisor                                                     │
│    • KVM-style on VT-x / AMD-V (default)                       │
│    • Intel TDX confidential VM (when --tee-attested + capable) │
│    • AMD SEV-SNP confidential VM (when --tee-attested + capable)│
│  → boundary HW (VM-exit/entry), per-VM measurement              │
├────────────────────────────────────────────────────────────────┤
│  nexacore-container userspace service (Rust, no_std-not-required)  │
│    • capability validation (every action)                       │
│    • lifecycle (provision → run → suspend → terminate)         │
│    • OCI image management + cache                              │
│    • virtio device backing (sourced from NexaCore capabilities)    │
├────────────────────────────────────────────────────────────────┤
│  Microkernel NexaCore (capability, IPC, scheduling)                 │
└────────────────────────────────────────────────────────────────┘
```

Key invariants:

- **One container = one micro-VM**. No multi-container-per-VM (Kata-style
  shared-kernel pods are not supported in v1.x; can revisit per NCIP).
- **virtio-only host↔guest I/O**. No PCI device passthrough in v1.x. GPU
  is exposed via virtio-gpu (virgl-style), not direct.
- **Stichting-signed guest kernel only**. Users cannot ship their own
  kernel in v1.x. A future NCIP can lift this for advanced users with
  explicit risk acknowledgement.
- **Capabilities declared at launch, enforced for the container lifetime**.
  Mid-lifetime capability expansion is denied; create a new container.

### 2. Guest Linux image

The Foundation maintains a single canonical guest image, versioned:

`nexacore-guest-linux-v6.10-stable` (example for Linux 6.10 LTS).

Composition:

- **Linux LTS kernel** (currently 6.10 LTS line; we follow Linux LTS cadence).
- **musl libc** (not glibc — smaller surface, simpler license).
- **busybox** as init + base userland.
- **virtio guest drivers** compiled in (virtio-fs, virtio-net, virtio-vsock,
  virtio-gpu, virtio-rng).
- Stripped: no audio, no Bluetooth, no Wi-Fi, no legacy buses, no `/proc`
  features beyond what containerd needs.
- Total compressed: target ≤ 20MB.

Distribution:

- Built reproducibly from Foundation source repo `nexacore-guest-linux`.
- Signed at build time with the Stichting release key (SSH + Sigstore).
- Hash published in a Certificate-Transparency-style log (see
  [`docs/04-security-model.md`](../docs/04-security-model.md) § "Model attestation"
  — same infrastructure repurposed).
- Container engine refuses to boot unsigned or mis-measured kernel images.

Update cadence:

- **Quarterly** for security patches and LTS minor bumps.
- **Out-of-band emergency** within 14 days for critical CVE.
- Existing containers continue to run on their pinned kernel version; a
  separate process re-signs and audits the in-use kernel inventory.

### 3. virtio device backing and capability binding

Every virtio device exposed to a guest is backed by an **NexaCore userspace
service** that enforces capability scope on the host side. The guest sees
a generic virtio device; the host side translates each guest request to
a capability check + NexaCore primitive call.

| Virtio device | Host-side backing | Capability required |
|---|---|---|
| `virtio-fs` | `nexacore-fs` userspace driver | `fs:read:<path>` / `fs:write:<path>` (scoped) |
| `virtio-net` | NexaCore network stack with per-channel firewall rules | `net:outbound:<host>:<port>` / `net:inbound:<port>` |
| `virtio-vsock` | NexaCore IPC bridge (Cap'n Proto channel) | `ipc:channel:<channel-id>` |
| `virtio-gpu` (optional) | NexaCore tensor HAL GPU dispatch | `gpu:shared` / `gpu:exclusive:<gpu-id>` |
| `virtio-rng` | Kernel `getrandom` source | (always granted; entropy is free) |
| `virtio-balloon` | Host memory reclaim | `mem:balloon` (granted by default) |

The container does **not** see "the host filesystem" or "the host network".
It sees only the slices the user explicitly granted. A misbehaving container
is blocked at the virtio boundary, not after-the-fact by a sandboxing
mechanism.

### 4. CLI surface

A single command, `nexacore-container`, provides the user-facing API:

```bash
nexacore-container run my-python-ml \
    --image=python:3.12-slim \
    --fs-read=/data/dataset \
    --fs-write=/data/output \
    --network=outbound:huggingface.co:443 \
    --network=outbound:pypi.org:443 \
    --gpu=shared \
    --memory=8GB \
    --cpus=4 \
    --tee-required
```

Capabilities can be grouped via **profiles** for common use cases:

```bash
nexacore-container run my-app --profile=desktop-app --image=libreoffice
```

Built-in profiles (v1.x):

| Profile | Capabilities granted |
|---|---|
| `desktop-app` | `fs:read:/home/<user>/Documents`, `fs:write:/home/<user>/Documents`, `gpu:shared`, `net:outbound:*:443` |
| `cli-tool` | `fs:read:cwd`, `fs:write:cwd`, no network |
| `network-service` | `net:inbound:<user-port>`, `fs:read:/etc/<service>/`, `fs:write:/var/log/<service>/` |
| `ai-workload` | `gpu:shared`, `net:outbound:huggingface.co:443`, `fs:read:/data/models`, `fs:write:/data/output` |
| `windows-app` (alias to `desktop-app` + Wine image) | as above + `nexacore/linux-wine:N-stable` base image |

Custom profiles live in `~/.config/nexacore-container/profiles/`.

### 5. Lifecycle states

```
                ┌──────────┐
   nexacore-container run ────►│ Pending  │
                           └────┬─────┘
                                │ image cached, capabilities validated
                                ▼
                           ┌──────────┐
                           │ Provisioning │
                           └────┬─────┘
                                │ guest kernel + image staged
                                ▼
                           ┌──────────┐
                ┌─────────►│ Running  │◄──────────────┐
                │          └────┬─────┘               │
                │               │ nexacore-container       │
       │ nexacore-container         │   pause              │ nexacore-container
       │   resume              ▼                       │   stop
                           ┌──────────┐                │
                └──────────│Suspended │                │
                           └────┬─────┘                │
                                │                      │
                                ▼                      ▼
                           ┌──────────┐          ┌──────────┐
                           │Snapshotted│         │Terminating│
                           └────┬─────┘          └────┬─────┘
                                │                     │
                                ▼                     ▼
                           ┌──────────────────────────────┐
                           │       Terminated             │
                           └──────────────────────────────┘
```

- **Suspended**: memory pause via `VMPAUSE` (TDX) / equivalent; no CPU
  burn; fast resume.
- **Snapshotted**: full state captured to disk (memory + disk + vCPU
  state), sealed under `SealPolicy { tee_family, current_measurement }`
  (see `nexacore-tee::SealedBlob`).
- **Terminated**: resources released; per-policy retain or discard the
  snapshot.

### 6. Per-container TEE attestation

On TEE-capable hardware (`--tee-required` flag, or host policy default),
the container runs inside a **confidential VM**:

- **Intel TDX**: container = TDX trust domain. Measurement covers guest
  kernel + initrd + first-stage init.
- **AMD SEV-SNP**: container = SEV-SNP guest. Measurement covers guest
  kernel + initrd.

The host generates an attestation quote that includes:

- Host TEE measurement (from `nexacore-tee::TeeBackend::attest`).
- Guest kernel image hash (signed by Stichting).
- Container image hash (OCI digest).
- Capability set granted (Cap'n Proto serialized, hashed).
- A nonce supplied by the verifier (peer in mesh, or local audit).

Mesh peers verify the quote before accepting work-offloading to the
container. This is **distinct** from the host's mesh attestation: a node
can be a trusted mesh participant overall while specific containers on it
are independently attestable.

### 7. OCI image compatibility

NexaCoreContainer reads **OCI Image Format v1** images directly. Standard
Docker / Podman images work without modification.

NexaCore extension manifest (optional, in image annotations):

```json
{
  "io.nexacore-os.capabilities-required": [
    "fs:read:/data",
    "net:outbound:huggingface.co:443"
  ],
  "io.nexacore-os.tee-required": "tdx-or-sev-snp",
  "io.nexacore-os.guest-kernel-min-version": "v6.10-stable",
  "io.nexacore-os.signed-by": "ed25519:<fingerprint>"
}
```

When present, the engine validates capability declarations against
user-supplied flags and refuses to launch if user grants are insufficient.

### 8. Wine integration for Windows applications

The Foundation publishes a maintained image:

`nexacore/linux-wine:N-stable` (currently `nexacore/linux-wine:11-stable` for
Wine 11.x LTS line).

The image bundles:

- Wine current stable.
- DXVK (Vulkan-based DirectX 8/9/10/11 translation).
- VKD3D-Proton (Vulkan-based DirectX 12 translation).
- musl + standard Linux userland (the rest of the guest).
- Prefix initialization script that auto-populates a Wine prefix on
  first run.

User experience:

```bash
nexacore-container run-windows photoshop.exe \
    --wine-prefix=/home/<user>/.wine/photoshop \
    --profile=windows-app
```

Behind the scenes this expands to a regular `nexacore-container run` with
`--image=nexacore/linux-wine:11-stable` and Wine launched against the
provided `.exe`. The user sees a Windows app integrated with the NexaCore
desktop via virtio-gpu surfaces.

**Compatibility ceiling**: Wine covers ~85-95% of productivity Win32
applications and ~75-90% of games (via DXVK / VKD3D-Proton, per Steam
Deck / ProtonDB data). Apps requiring kernel-mode drivers (anti-cheat,
some DRM, virtual hardware drivers) cannot run via Wine; these need the
v2.x fallback path (user-licensed Windows in a container — see future
work).

### 9. macOS application compatibility — NOT supported

macOS is closed-source and Apple does not license its kernel or
frameworks for redistribution. NexaCore does **not** support macOS app
execution. Users who require macOS apps run macOS on their own hardware
(out of scope for NexaCore OS).

### 10. Reference implementation: `nexacore-container` crate

The implementation lives in `crates/nexacore-container/`:

```
crates/nexacore-container/
├── Cargo.toml
├── src/
│   ├── lib.rs          # Public API
│   ├── engine.rs       # Hypervisor abstraction (KVM, TDX, SEV-SNP)
│   ├── image.rs        # OCI image fetch + cache + verify
│   ├── lifecycle.rs    # State machine (Pending → Running → …)
│   ├── virtio/
│   │   ├── fs.rs       # virtio-fs backend (capability-checked)
│   │   ├── net.rs      # virtio-net backend (firewall-aware)
│   │   ├── vsock.rs    # virtio-vsock to NexaCore IPC bridge
│   │   ├── gpu.rs      # virtio-gpu backend (HAL TensorBackend)
│   │   └── rng.rs      # virtio-rng (nexacore-crypto rand source)
│   ├── attestation.rs  # Per-container quote generation
│   ├── profile.rs      # Capability profile parsing + binding
│   └── cli/
│       ├── mod.rs
│       ├── run.rs
│       ├── run_windows.rs
│       ├── ps.rs
│       └── …
└── tests/
    ├── mock_oci_image.rs
    ├── capability_binding.rs
    └── lifecycle_state_machine.rs
```

Hypervisor backend selection is feature-gated:

```toml
[features]
default      = ["kvm"]
kvm          = ["kvm-ioctls", "kvm-bindings"]
tdx          = ["kvm", "tdx-attest-rs"]   # transitively pulls KVM
sev-snp      = ["kvm", "sev"]
all-backends = ["kvm", "tdx", "sev-snp"]
```

Hand-off to mesh:

- A running container can be a **mesh participant peer** in its own
  right, separate from the host. Its attestation is what other peers
  verify.
- Mesh-offloaded inference: the host can offload AI work to a peer's
  container, with attestation verifying that the peer's container has
  the expected model + capability set.

## Rationale

### Why micro-VM rather than namespace-based containers?

| Concern | Namespace (Docker default) | Micro-VM (this NCIP) |
|---|---|---|
| Kernel attack surface | Shared with host → entire Linux kernel is TCB for every container | Each VM has its own kernel; host kernel is NexaCore (not Linux) |
| Container escape track record | CVE-2024-21626 (runc), CVE-2022-0492 (cgroup), …continuous | VM-escape CVEs exist but rarer; hypervisor smaller than full kernel |
| TEE confidential mode | Not natively; requires CoCo overlay | Native |
| Startup latency | ~10ms | 100-300ms (acceptable for desktop / batch; not for FaaS scale-from-zero) |
| Memory overhead | ~10MB / container | 50-150MB / container |
| Workload fit | High-density many-small-containers (k8s pods) | Desktop apps, AI workloads, occasional services |

NexaCore's target workload is **desktop and AI**, not high-density services.
Micro-VM is the better fit by far.

### Why mandatory TEE attestation when capable?

Aligning with the project security stance: **trust is mathematically
required, not assumed**. If hardware supports per-VM TEE attestation
(TDX / SEV-SNP) and the user does not explicitly opt out, the container
runs as a confidential VM. The cost is ~5-10% performance overhead
(documented Intel TDX figures); the benefit is HW-attested isolation
from the host OS.

Users on non-TEE hardware (older systems, ARM v1.x) get plain KVM
isolation, with a warning logged. Production mesh participation requires
TEE-attested mode (per host hardware requirements).

### Why no namespace-based fallback?

We deliberately do not implement a "fast path" using NexaCore userspace
namespaces (analogous to Linux namespaces). Reasons:

- NexaCore's capability model already provides per-process resource scoping;
  duplicating with another abstraction is wasteful.
- A "fast path" that's less secure invites users to take the fast path
  by default, eroding the security baseline.
- Startup latency 100-300ms is acceptable for desktop and AI workloads
  (the project's target). FaaS-scale spawn rates are not in scope for v1.x.

## Backwards Compatibility

Not applicable: there is no pre-existing container engine in NexaCore OS.

This NCIP **resolves** a previously-open architectural question on POSIX
compatibility. The decision in [`docs/02-architecture.md`](../docs/02-architecture.md)
§ "Open architectural questions" — "POSIX compatibility: yes/no/partial"
— is hereby answered: **POSIX exists only inside guest Linux of NexaCoreContainers,
never in the NexaCore kernel**.

The architecture document is updated to reflect this resolution in a
separate commit landing with this NCIP.

## Test Cases

1. **OCI image fetch + run.** `nexacore-container run --image=alpine:latest`
   pulls the image and runs `sh` to completion. End-to-end smoke test.

2. **Capability denial.** Container declares `fs:read:/data` but tries
   to read `/etc/passwd` inside guest. virtio-fs returns `EACCES`; the
   guest kernel passes it through; the app fails as expected.

3. **Capability propagation.** Container declares `net:outbound:huggingface.co:443`.
   `curl https://huggingface.co/` succeeds; `curl https://google.com/`
   fails at the virtio-net firewall.

4. **TEE attestation.** On a TDX-capable host, running with `--tee-required`
   produces a quote whose `report_data` field contains
   `hash(guest_kernel || image_digest || capability_set)`. Verified by a
   peer using `nexacore_tee::TeeBackend::verify_quote`.

5. **Wine integration.** `nexacore-container run-windows notepad.exe` boots
   the Wine container and successfully runs Notepad (verified via
   virtio-gpu surface).

6. **Lifecycle: suspend/resume.** Container snapshotted in `Running`,
   resumed after host reboot, recovers state correctly. Snapshot is
   sealed and unsealable only on the same measurement.

7. **Mesh interop.** A container on host A can be a mesh peer that host
   B offloads work to, with B verifying A's container attestation.

8. **Negative: corrupted guest kernel.** Engine refuses to boot a
   container whose guest kernel image hash does not match the
   Stichting-signed manifest.

9. **Negative: capability escalation in-flight.** Attempt to
   `nexacore-container set-capability <running-container> fs:write:/etc`
   is denied; runtime capability set is immutable.

10. **Performance baseline.** Container startup (image cached, capabilities
    bound, guest kernel boot to first user code) ≤ 500ms on a 2024-class
    workstation. Documented in `docs/audits/container-perf-2026-XX.md`.

## Reference Implementation

To land before activation (`Draft → Review → Active` per `NCIP-Process-001`):

- `crates/nexacore-container/` skeleton with feature-gated backends.
- Hypervisor backend: KVM via `kvm-ioctls` (Rust crate, maintained by
  the cloud-hypervisor / Firecracker community).
- TDX feature gating via `tdx-attest-rs` (Intel-maintained).
- SEV-SNP via `sev` crate (Red Hat-maintained).
- Reference Guest Linux image build at `nexacore-guest-linux/` (separate repo).
- CLI `nexacore-container` and the documented profiles.
- Integration tests under `crates/nexacore-container/tests/` covering test
  cases 1-9 (case 10 lands in CI as a regression baseline).

Estimated effort: **12-18 engineer-months**, of which ~3-4 are the
guest Linux image build pipeline and ~5-6 are the virtio backends.

## Security Considerations

- **Guest kernel supply chain.** Compromise of the Stichting-signed guest
  kernel compromises every container. Mitigation: reproducible builds,
  CT-style transparency log, mandatory hash verification at launch,
  refusal to boot unsigned kernels.
- **Hypervisor as TCB.** The host hypervisor is now in NexaCore's TCB. We
  use KVM (battle-tested ~20 years) and accept this. SEV-SNP / TDX
  attestation cover the guest but not the hypervisor itself; host TEE
  attestation (from `nexacore-tee`) covers the hypervisor.
- **virtio backend bugs.** A bug in a virtio backend running in NexaCore
  userspace is a capability violation surface. Mitigation: each backend
  is its own capability-scoped service; bugs are bounded by the backend's
  capability set, not the engine's.
- **Wine surface area.** Wine is a large attack surface. Mitigation:
  Wine runs **inside the guest**, behind the VM boundary; a Wine bug
  cannot escape the container without also breaking the hypervisor +
  the guest kernel + the capability boundary. Defense in depth.
- **Side channels across VMs.** Spectre-class attacks within shared CPU
  hardware. Mitigation: scheduler isolates AI-workload class containers
  on dedicated cores when `--tee-required` is set; TDX / SEV-SNP harden
  cache partitioning.

## Privacy Considerations

- **Image fetch metadata.** Pulling OCI images leaks the image identity
  to the registry. Mitigation: registries are pinned in NexaCore capability
  policy; user grants `net:outbound:<registry>:443` explicitly.
- **Container payload privacy on mesh.** A mesh peer offloading work to
  a remote container sends payload via the existing mesh privacy
  primitives (tokenization + STARK compliance proofs + TEE-only
  envelopes). Container engine does not weaken these guarantees.
- **Container telemetry on disk.** Audit log of container lifecycle is
  written to NexaCore audit log (Merkle tree, TPM-anchored). The audit
  log content is user-readable but not network-exported by default.

## Future Work

Tracked as follow-up NCIPs to be filed when their phase approaches:

- **NCIP-AOT-Wine-XXX** (Phase 6) — AOT packager that takes a Windows
  `.exe` + Wine + a Win32 shim and produces a single NexaCore-native ELF
  binary, eliminating the container layer for specific apps. Reduces
  startup latency from 100-300ms to 10-30ms for the packaged apps.
  Coverage equals Wine coverage at AOT-bake time.
- **NCIP-Cross-ISA-XXX** (v1.1+, when NexaCore lands on ARM64) — Rosetta-style
  ISA translation for NexaCore binaries (x86_64 → ARM64) on multi-arch hosts.
  Scope is NexaCore-to-NexaCore ISA, not Linux/Windows ABI.
- **NCIP-Container-Networking-XXX** (Phase 5 mid) — detailed CNI-style
  networking spec, IPAM, container-to-container service mesh.
- **NCIP-Container-Storage-XXX** (Phase 5 mid) — persistent volumes,
  snapshot policies, capability-scoped block devices.
- **NCIP-Container-BYOLinux-XXX** (Phase 6 or later) — user-supplied
  guest kernel images with explicit risk acknowledgement. v1.x only
  ships the Stichting-signed kernel.
- **NCIP-Container-Windows-VM-XXX** (Phase 6+) — user-licensed Windows
  guest in a container for the ~5-15% of Windows apps Wine cannot
  handle. User brings Microsoft license; Foundation distributes nothing
  Microsoft.

## cyDock Evolution Path (informational, not part of this NCIP's spec)

A separate sister project `cySalazar/cyDock` (Rust + React, Apache-2.0)
already implements a **container management plane** for containerd-based
hosts. cyDock is **not** a container engine and is not the basis for
`nexacore-container` (which is built from scratch per this NCIP).

cyDock has a natural evolution path:

- **Today**: cyDock targets containerd on Linux hosts (independent project).
- **Phase 5** (post-`nexacore-container` engine stable): a fork `cyDock-nexacore`
  retargets the backend from containerd-gRPC to the `nexacore-container`
  REST API. The TypeScript/React frontend is largely reusable. Backend
  refactor scope: ~3-4 months for a single engineer.
- **Phase 6+**: cyDock-nexacore becomes the official NexaCore OS container
  management UI. The original cyDock repo either deprecates or
  bifurcates.

cyDock's salvageable patterns for `nexacore-container` design reference
(not code-reuse):

- The `ContainerRuntime` trait shape (in `cydock-runtime/src/lib.rs`).
- OCI manifest parsing via `oci-spec` crate.
- SQLite-backed audit/persistence pattern.
- mTLS + auto-cert pattern (`rustls + rcgen`) for the management API.
- CLI / Web API dual-frontend layering.

License: cyDock is Apache-2.0, one-way compatible with NexaCore's Apache-2.0
for a derivative work `cyDock-nexacore`.

## Copyright

This NCIP is licensed under CC0 1.0 Universal.
