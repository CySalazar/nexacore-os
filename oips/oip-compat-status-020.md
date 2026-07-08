---
ncip: 20
title: Linux and Windows application compatibility — canonical status note
track: Informational
status: Draft
authors:
  - cySalazar <hello@nexacoreos.com>
created: 2026-05-22
updated: 2026-05-22
requires:
  - NCIP-Process-001
  - NCIP-Container-006
supersedes: ~
superseded-by: ~
discussion: https://github.com/CySalazar/nexacore-os/discussions (TBD link)
license: CC0-1.0
---

## Abstract

This Informational NCIP gives a single, citable answer to a recurring question:
"Will NexaCore OS support Linux and Windows applications, and if so, how?" The answer
already exists, distributed across `ncips/ncip-container-006.md` (the normative
specification) and `docs/02-architecture.md` (the open-questions note that
NCIP-006 closes). This note collects the answer in one place, restates the
deliberate **no kernel POSIX/Win32 shim** stance, and lists what is still
unbuilt versus what is decided.

The note is **not normative**. It changes no specification. It is filed so that
"why doesn't NexaCore just ship a Wine-equivalent in the kernel?" has a permanent
citable response and so that new contributors can find the answer without
re-reading the full NCIP-006.

---

## Motivation

The question "what about Linux and Windows apps?" arrives from three audiences:

- **Prospective users** who want to know whether their existing software keeps
  working.
- **Prospective contributors** who consider building a personality / binfmt /
  syscall-translator-in-kernel and need to learn early that this is out of
  scope.
- **Funding and grant reviewers** who need a one-page summary of the ecosystem
  story.

Today the answer requires reading NCIP-006 in full (~700 lines). A short
Informational pointer removes that friction.

The note also addresses a specific user-facing query raised on branch
`claude/nexacore-os-features-analysis-Syk8p` on 2026-05-22: "Does it make sense to
have a Wine-equivalent for both Linux and Windows on NexaCore?" The answer turns out
to be "yes, and it is already specified; here is where."

---

## Specification

This is an Informational NCIP. The text below is descriptive, not normative.
Normative statements live in `ncips/ncip-container-006.md`.

### 1. The chosen path, in one sentence

Linux and Windows applications run inside per-app **micro-VM containers**
(`NexaCoreContainer`, NCIP-006); each container boots a Stichting-signed guest Linux
kernel; Windows apps additionally run under **Wine + DXVK + VKD3D-Proton**
inside the guest. The NexaCore microkernel itself exposes no POSIX or Win32 surface.

### 2. End-to-end flow

```
   Linux app                            Windows app
   ─────────                            ───────────
       │                                     │
       │ ELF                                 │ PE
       ▼                                     ▼
   ┌──────────────────────────────┐     ┌────────────────────────────────────┐
   │ guest Linux (Stichting-signed)│     │ guest Linux (Stichting-signed)     │
   │ standard POSIX, /proc, fork  │     │   + Wine + DXVK + VKD3D-Proton     │
   │                              │     │   prefix init script               │
   └──────────────┬───────────────┘     └──────────────────┬─────────────────┘
                  │                                        │
                  ▼                                        ▼
   ┌─────────────────────────────────────────────────────────────────────┐
   │ virtio devices (fs / net / vsock / gpu / rng) — capability-checked  │
   ├─────────────────────────────────────────────────────────────────────┤
   │ hypervisor: KVM (default) | Intel TDX | AMD SEV-SNP                 │
   ├─────────────────────────────────────────────────────────────────────┤
   │ nexacore-container userspace service (capability-bound)                 │
   ├─────────────────────────────────────────────────────────────────────┤
   │ NexaCore microkernel — capability, IPC, scheduling — POSIX-free         │
   └─────────────────────────────────────────────────────────────────────┘
```

User-facing surfaces (per NCIP-006 § 8):

```bash
# Linux app
nexacore-container run docker.io/library/gimp:latest

# Windows app
nexacore-container run-windows photoshop.exe \
    --wine-prefix=/home/<user>/.wine/photoshop \
    --profile=windows-app
```

The Windows command expands internally to a regular `nexacore-container run` against
`nexacore/linux-wine:N-stable` (currently `nexacore/linux-wine:11-stable`).

### 3. What is decided

- Linux compatibility uses **real Linux** (the signed guest kernel), not an
  emulation shim. Expected coverage ≥ 99 % of applications that target the
  guest kernel's version line.
- Windows compatibility uses **Wine LTS** inside guest Linux, with DXVK
  (DirectX 8/9/10/11) and VKD3D-Proton (DirectX 12). Expected coverage per
  Steam Deck / ProtonDB data: ~85–95 % productivity Win32, ~75–90 % gaming
  (`ncips/ncip-container-006.md:328–333`).
- Each container is a **micro-VM** with virtio-only I/O and per-container TEE
  attestation on TDX / SEV-SNP capable hardware.
- The maintained Wine image is published as `nexacore/linux-wine:N-stable` by the
  Stichting.

### 4. What is explicitly **not** going to happen

Per `ncips/ncip-container-006.md` § 2:

| Rejected approach | Reason |
|---|---|
| Full POSIX in the NexaCore kernel | Doubles the kernel ABI; legacy semantics (`fork`/`setuid`/`/proc`) leak into the capability model. |
| Partial POSIX shim in NexaCore userspace | Leaky abstraction; WSL1 was abandoned for the same reason; coverage ceiling ~60–80 %. |
| `binfmt_misc`-style interpreter selection inside NexaCore kernel | Adds a per-format dispatcher to the kernel for no isolation gain. |
| Namespace-based isolation (chroot/cgroup-style) as a fallback to VM isolation | Explicitly disallowed (`ncips/ncip-container-006.md` anti-pattern section). |
| Native Wine running directly on the NexaCore kernel | Wine depends on Linux syscall semantics; running it natively would require precisely the POSIX shim we just rejected. |
| macOS application support | Apple does not license its kernel or frameworks; out of scope (`ncips/ncip-container-006.md` § 9). |

### 5. Known ceilings of the chosen path

- **Windows kernel-mode drivers** cannot run under Wine. Affected: anti-cheat,
  some DRM, virtual-hardware drivers.
- **DAW-style hard-real-time audio** inside a micro-VM is harder than on bare
  Linux (this is a virtualization property, not a Wine property).
- **GPU passthrough** is not supported in v1.x (virtio-gpu / virgl only). Some
  high-end games and CUDA workloads will see lower throughput than on bare
  Linux.

A future v2.x NCIP may add a "user-licensed Windows in a container" path for the
first ceiling (`ncips/ncip-container-006.md` § 8 closing paragraph). The other two
are accepted trade-offs.

### 6. What is decided but not yet built

Tracked in the backlog:

| Phase | Item | Notes |
|---|---|---|
| P8.1 | `nexacore-container` engine skeleton, KVM backend | crate exists, backends scaffolded. |
| P8.2 | TDX / SEV-SNP backends | feature-gated, blocked on access to TDX/SEV-SNP hardware. |
| P8.3 | Signed guest Linux build pipeline | reproducible build + Stichting signing key. |
| P8.4 | virtio backends (fs, net, vsock, gpu, rng) | one crate per device. |
| P8.5 | OCI image management + cache + signature verification | |
| P8.6 | `nexacore/linux-wine:11-stable` image build | blocked on P8.3. |

Estimated residual work: ~20–30 engineer-months to a production-ready
implementation.

---

## Rationale

The "container + Wine" answer is preferred to two alternatives.

### Alternative A — native Wine on the NexaCore kernel

A user-facing port of Wine that runs without a guest Linux. Wine in this form
would need:

- A POSIX shim broad enough to support glibc + Wine's own Linux syscall use.
- A binfmt-like loader that knows about PE files.
- A graphics stack equivalent to Linux's Vulkan / Wayland / X11.

Each of those is a major engineering investment that delivers a strictly worse
result than running real Linux + real Wine inside a micro-VM. The kernel ABI
would balloon; the security review story would weaken; the porting cost would
be permanent. Rejected.

### Alternative B — userspace syscall translator (Rosetta-style)

A userspace translator that intercepts and rewrites Linux or Windows syscalls
into NexaCore capability calls. Pros: smaller kernel surface than option A. Cons:

- Coverage ceiling identical to WSL1 (~60–80 %).
- Compatibility regressions on every Linux release.
- Translator becomes a security-sensitive surface itself: every translated
  syscall is a potential capability-escalation gadget.

Rejected for the same reason WSL1 was retired.

### Why "container + Wine" wins on every axis

- **Coverage.** Real Linux + real Wine ⇒ ~99 % of Linux apps and ~85–95 % of
  productivity Win32 apps with effectively zero per-release maintenance cost
  on the NexaCore side.
- **Isolation.** Hardware VM boundary plus per-container TEE attestation is
  strictly stronger than any in-kernel or in-userspace shim.
- **Maintenance load on the NexaCore team.** Tracking Linux kernel releases and
  Wine releases is a known, well-scoped activity. Maintaining a POSIX shim or
  a syscall translator is open-ended.
- **Re-use of industry investment.** AWS Firecracker, Kata Containers, Apple
  Container Framework, Hyper-V Containers, Confidential Containers — the
  micro-VM pattern is the production state of the art as of 2026
  (`ncips/ncip-container-006.md:67–78`).

---

## Backwards Compatibility

N/A — Informational note. No prior compatibility behaviour exists in NexaCore.
This NCIP does not change any specification; it only restates an existing one.

---

## Test Cases

N/A — process / informational, no new testable invariant. The testable
invariants live in NCIP-Container-006 § 13 ("Test plan") and are not duplicated
here.

---

## Reference Implementation

N/A — Informational note. The reference implementation tracked here is the one
defined by NCIP-Container-006 itself (`crates/nexacore-container/`).

---

## Security Considerations

This note introduces no new security surface. The relevant analysis lives in:

- `ncips/ncip-container-006.md` § "Security Considerations" (per-container TEE
  attestation, virtio capability binding, no PCI passthrough, signed guest
  kernel).
- `docs/04-security-model.md` (capability model, attestation chain).
- `docs/04a-threat-model.md` (adversary classes, including the supply chain of
  guest images).

One observation worth recording: because the chosen path runs proprietary
Windows software **inside** an NexaCore-controlled guest Linux, the trust boundary
is strictly tighter than running the same software natively on Windows. The
guest kernel is small and Stichting-signed; the virtio I/O surface is
capability-bound; on TDX / SEV-SNP hardware the whole guest is a confidential
VM measured at launch.

---

## Privacy Considerations

This note introduces no new privacy surface. The relevant analysis lives in
`ncips/ncip-container-006.md` § "Privacy Considerations" (container egress
policies, network capability, no implicit telemetry from guest to NexaCore), and
in `docs/04-security-model.md` (encrypted-by-default data types, tokenization).

One observation worth recording: when a Windows app inside Wine attempts to
phone home (telemetry, license check), it is constrained by the host
container's `net:outbound:*` capability set, declared at launch. The NexaCore host
cannot prevent the app from trying, but it can — and by default does — refuse
the egress. The privacy story is therefore stronger than running the same app
on a Windows host that grants network access by default.

---

## Copyright

This NCIP is released into the public domain under
[CC0-1.0](https://creativecommons.org/publicdomain/zero/1.0/).
