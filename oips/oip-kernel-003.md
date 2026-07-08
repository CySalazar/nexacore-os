---
ncip: 3
title: UEFI Bootloader Selection and Kernel `no_std` Transition Plan
track: Standards Track
status: Active
authors:
  - cySalazar <hello@nexacoreos.com>
created: 2026-05-10
updated: 2026-05-16
requires:
  - NCIP-Process-001
supersedes: ~
superseded-by: ~
discussion: https://github.com/CySalazar/nexacore-os/discussions (TBD link)
license: CC0-1.0
---

# NCIP-Kernel-003 — UEFI Bootloader Selection and Kernel `no_std` Transition Plan

## Abstract

This NCIP commits NexaCore OS to:

1. **A UEFI-only boot path** (no legacy BIOS support).
2. **The `bootloader` crate v0.11+ (`bootloader_api`-style)** as the
   reference bootloader for v1.0, with a documented evaluation point at
   v1.x for moving to `Limine` if community experience favours it.
3. **A phased `no_std` transition** for the `nexacore-kernel` crate, governed
   by the `bare-metal` feature flag (already in `Cargo.toml`).

The NCIP is `Process`-category because it describes how the kernel
implementation proceeds, not a wire-protocol change.

## Motivation

`nexacore-kernel` is currently a normal Rust library that compiles in `std`.
For the v1.0 release the kernel must:

- Boot on bare-metal x86_64.
- Run in `no_std + no_main` mode.
- Hand-off cleanly from a UEFI bootloader.

The choice of bootloader is the single biggest decision because it sets:

- The hand-off ABI (memory map format, ACPI / SMBIOS pointer location,
  framebuffer description, etc.).
- The build pipeline (do we cross-compile via `cargo` + a custom target
  spec, or use a separate bootloader build?).
- The community we inherit (each bootloader's documentation, examples,
  and bug-fix cadence).

This NCIP locks the choice for v1.0 and documents the criteria under which
v1.x could switch.

## Specification

### 1. UEFI-only

The v1.0 kernel **does not support legacy BIOS boot**. UEFI is universal
on the target hardware baseline (Intel TDX-capable x86_64, AMD SEV-SNP-
capable x86_64; both require UEFI per their TEE attestation chains).

Rationale: legacy BIOS pre-dates TPM 2.0 / Secure Boot infrastructure,
which the project policy requires (see
[`docs/04-security-model.md`](../docs/04-security-model.md) § "Capability-
based access control"). Supporting BIOS in v1 doubles the test matrix for
zero security benefit.

### 2. Bootloader: `bootloader` crate v0.11+

| Candidate | Pro | Con |
|---|---|---|
| **`bootloader` crate (rust-osdev)** | Pure Rust, well-documented for `redox`/`Theseus`-style kernels, v0.11+ uses `bootloader_api` with a clean hand-off ABI. License Apache/MIT. | Less battle-tested than Limine; smaller ecosystem. |
| **Limine** | C-based, mature, used by many hobby kernels; rich protocol (framebuffer, SMP, ACPI). License BSD-2. | Adds a non-Rust dependency. Cross-language complicates reproducible builds. |
| **GRUB2 + Multiboot2** | Ubiquitous, well-known. | C, GPL-3 (incompatible with project's Apache-2.0 licensing for any code we would patch upstream). License conflict is the blocker. |
| **Custom UEFI loader (`uefi-rs`)** | Maximum control, pure Rust. | Significant additional engineering scope; we would be re-implementing what `bootloader` already provides. |

**Decision: `bootloader` crate v0.11+.** The pure-Rust path eliminates
cross-language build complexity, the license is compatible, and the
hand-off ABI is sufficient for v1.0.

**Re-evaluation trigger (v1.x):** if the `bootloader` crate becomes
unmaintained, or if community experience shows Limine offers materially
better SMP / ACPI support than `bootloader` can match within reasonable
maintenance burden, a follow-up NCIP may switch. This is not a forecast;
it is an explicit opt-in to revisit.

### 3. `no_std` transition plan

The `nexacore-kernel` crate is the **only** workspace member that needs the
`bare-metal` mode (`#![no_std] + #![no_main]`). Foundational crates
(`nexacore-types`, `nexacore-crypto`, `nexacore-capability`, `nexacore-tee`) are already
`no_std + alloc`. The transition proceeds in five steps:

| Step | Owner | Gate |
|---|---|---|
| **K1.** Add `bare-metal` feature to `nexacore-kernel/Cargo.toml`. | Done in this NCIP's reference impl. | merged |
| **K2.** Wire `lib.rs` to switch on the feature (`#![cfg_attr(feature = "bare-metal", no_std)]`). | Done in this NCIP's reference impl. | merged |
| **K3.** Build under the feature: `cargo build --target x86_64-unknown-none --features bare-metal`. Fails today because we have not yet introduced the panic handler, the allocator, and the entry point. | Kernel engineer (P6 hire). | ✅ NCIP-Kernel-012 Active (PR #21) |
| **K4.** Integrate `bootloader` crate v0.11+ in a `kernel/` runner crate adjacent to `nexacore-kernel`. The runner provides the `_start` entry point and forwards to the kernel's `kmain`. | Kernel engineer. | ✅ NCIP-Kernel-005 Review; kernel-runner operativo (PR #25) |
| **K5.** Smoke-test in QEMU via `qemu-system-x86_64` with `-bios OVMF`. CI runs the smoke test on every push. | Kernel engineer + CI. | ✅ PR #25; CI run 25888095006 — 5/5 banner lines green |

K3, K4, K5 land as separate NCIPs because each is independently
substantive.

### 4. Target spec

The kernel is built against the built-in target
`x86_64-unknown-none`. This target:

- Disables the standard library.
- Disables the C runtime startup.
- Provides only `core` and `alloc` (when the allocator is provided).
- Is part of stable Rust as of 1.83 — no nightly required.

We do not require a custom target JSON. If a future hardware target
(e.g., AArch64) needs custom flags, an additional NCIP defines the
target spec at that time.

### 5. Allocator

Inside `bare-metal`, the kernel provides a global allocator implementing
`core::alloc::GlobalAlloc`. The v1 reference allocator is a **bump
allocator backed by the kernel's physical-memory free list**. Slab
allocation is a v1.x improvement.

A bump allocator is sufficient because the kernel itself does not perform
many small allocations: most kernel state is statically sized (the IPC
queues, the task table, the capability table). Userspace allocators are
a separate concern; they live in userspace.

### 6. Panic handler

The kernel panic handler:

1. Disables interrupts.
2. Writes a structured panic record to the early-boot console (serial
   on first available COM port, plus the framebuffer if mapped).
3. Halts the CPU (`hlt` in a loop).

The structured panic record is `bincode`-encoded so it can be parsed by
the audit-log forensics pipeline. Format:
`{kernel_version, panic_file_line, message, optional_stack_dump}`.

The panic handler MUST NOT allocate. Buffers are statically allocated.

### 7. Boot hand-off ABI

The `bootloader` crate hands a `BootInfo` struct to the kernel's entry
point. Fields the kernel uses:

- `memory_regions`: physical memory map. Kernel builds its free-list
  from this.
- `framebuffer`: early console.
- `rsdp_addr`: pointer to the ACPI RSDP for device discovery.

This ABI is stable across `bootloader` v0.11 patch releases; minor-
version updates require revisiting K5.

## Rationale

The decisive question was UEFI-only-vs-legacy-BIOS and bootloader-crate-
vs-Limine. The TEE-required hardware baseline obsoletes BIOS, and the
pure-Rust path obsoletes Limine for v1.0 — both decisions reduce risk
rather than chase optimisation.

## Backwards Compatibility

Not applicable: there is no pre-existing kernel boot path.

## Test Cases

1. **QEMU smoke test.** `cargo run -p kernel-runner` (where
   `kernel-runner` is the K4 deliverable) boots the kernel under
   `qemu-system-x86_64 -bios OVMF` and prints a recognizable banner.
2. **Panic test.** Triggering a panic in `kmain` produces the expected
   serial-console output and halts cleanly.
3. **Memory-map parsing.** Unit test on a synthetic `BootInfo` confirms
   the free-list builder produces the expected regions.

## Reference Implementation

Landed in this commit:

- `crates/nexacore-kernel/Cargo.toml` — `bare-metal` feature.
- `crates/nexacore-kernel/src/lib.rs` — `cfg_attr` switching on the feature.

All reference-implementation deliverables have landed as of 2026-05-15:

- `kernel-runner/` crate — entry point, bootloader integration, QEMU runner config (PR #25).
- Panic handler + bump allocator — `NCIP-Kernel-012` Active (PR #21).
- K5 QEMU smoke test — CI run 25888095006; 5/5 banner lines present and in order.

## Security Considerations

- **Boot supply chain.** Compromise of the `bootloader` crate would
  compromise the boot path. Mitigation: pin `bootloader` exact version,
  verify checksum in CI, mirror to a local crate registry if upstream
  becomes unmaintained.
- **Secure Boot.** The kernel binary is signed at build time with the
  Stichting NexaCore release key. The Secure Boot chain is established by:
  Platform Key → Key Exchange Key → DB → Stichting NexaCore release key. A
  follow-up NCIP defines the Stichting NexaCore release-key management.
- **Memory disclosure.** The kernel zeroes freed physical pages before
  returning them to the free list, preventing user-to-user disclosure
  through page reuse.

## Privacy Considerations

This NCIP scopes the **kernel boot chain and `no_std` transition**; it
does NOT introduce any user-data flows, persistent identifiers, or
network exchanges. The privacy surface is therefore intentionally
narrow:

- **Boot-time identifiers.** UEFI exposes platform identifiers
  (MAC address of the firmware-managed NIC, vendor / device strings,
  serial numbers via SMBIOS) to early boot code. The kernel MUST NOT
  read or persist these identifiers during the boot path covered by
  this NCIP. Any subsystem that later needs a stable platform identity
  derives it from the TEE attestation (`nexacore-tee`), not from
  firmware-leaked metadata.
- **Boot logs.** The early-boot serial / framebuffer log carries
  kernel-internal state (memory map, allocator size class, page-table
  layout). These are infrastructural, not user data, and the v1
  policy is: log only at boot to a host-local destination, NEVER ship
  off-device, NEVER include any value derived from a user-managed
  capability or session.
- **Allocator zeroization.** Already covered under § Security
  Considerations (memory disclosure); restated here because page-reuse
  leakage is also a privacy concern when allocations cross trust
  boundaries (e.g., a kernel buffer reused for an IPC message that
  later reaches a user-space service).
- **Sealed-key residency.** The boot path provisions the per-node
  TEE-sealed signing key. The key MUST be sealed under a
  `SealPolicy` (`nexacore-tee::SealPolicy`) bound to the current
  measurement; an attacker that swaps the kernel binary cannot
  unseal the prior key. This is the privacy-relevant property: a
  device's signing identity does not survive an unauthorized kernel
  swap.
- **No phone-home.** The boot path makes zero outbound network
  connections. Network bring-up, NTP synchronization, and any
  attestation-service contact happen later in user space, governed
  by their own NCIPs.

The full privacy surface for the kernel ABI (syscalls, IPC, capability
delegation) is the scope of `NCIP-Kernel-012` and successors, which
inherit this NCIP's narrow privacy contract as a baseline.

## Amendment History

| Date | Change | Notes |
|---|---|---|
| 2026-05-15 | Review → Last Call | 48-hour Solo Founder Fast-Track §5.5; window opens 2026-05-15, closes 2026-05-17. |
| 2026-05-16 | Last Call → Active | 48-hour window elapsed; no objections received; P6.2 gate closed. |

## Copyright

This NCIP is licensed under CC0 1.0 Universal.
