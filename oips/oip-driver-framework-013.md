---
ncip: 13
title: User-space driver framework — capabilities, MMIO, DMA/IOMMU, IRQ routing, manifest
track: Standards Track
status: Active
authors:
  - cySalazar <hello@nexacoreos.com>
created: 2026-05-20
updated: 2026-05-20
activated: 2026-05-20
requires:
  - 3
  - 5
  - 12
supersedes: ~
superseded-by: ~
discussion: https://github.com/CySalazar/nexacore-os/discussions (TBD link)
license: CC0-1.0
---

## Abstract

`docs/06-roadmap.md` § "Phase 1 — Microkernel proof-of-concept" lists **"Drivers
(in user space): NVMe storage, Ethernet/Wi-Fi networking, TEE"** as a phase-closure
deliverable. The microkernel principle — every component outside the
trusted-computing-base (TCB) — is the load-bearing architectural decision behind
this requirement, and is the reason no driver currently lives in `nexacore-kernel`
beyond the early-boot framebuffer / serial / PS/2 / VirtIO-tablet input minima
needed for the demo desktop (`docs/02-architecture.md` § 2.3).

This NCIP — `NCIP-Driver-Framework-013` — specifies the **kernel-side contract**
that user-space drivers MUST honor and the **driver-side contract** that the
kernel exposes. Five normative surfaces are locked here:

1. **Capability scope extensions** — `Action::{MmioMap, DmaMap, IrqAttach,
   PciConfigRead, PciConfigWrite}` and `Resource::{PciDevice, MmioRegion,
   DmaWindow, IrqLine}`, with subset rules and Ed25519-signed token issuance.
2. **MMIO mapping syscall (`SyscallNo::MmioMap = 70`)** — a kernel-mediated path
   for a user driver to obtain a write-back-uncached page mapping for a PCI BAR
   range, with bounds-checking against the PCI ECAM and against the per-device
   capability scope.
3. **DMA / IOMMU model** — VT-d (Intel) and AMD-Vi domains, one IOMMU group per
   driver process, kernel-allocated DMA windows, no shared mappings across
   driver processes.
4. **IRQ routing** — IOAPIC line-based, MSI / MSI-X message-based; a per-driver
   IPC channel that the kernel writes one zero-length message into per interrupt;
   policy on coalescing and on shared-line rejection.
5. **Driver manifest + Ed25519-signed image** — a TOML manifest declaring
   `(vendor_id, device_id)` matchers, requested capabilities, and the runtime
   `nexacore_image_hash`; signature verified by `nexacore-kernel` at `DriverLoad`.

The contract is deliberately **kernel-mediated everywhere it crosses an isolation
boundary** (MMIO mapping, DMA window install, IRQ vector allocation). The
microkernel never trusts a driver's claim about which device it owns; every claim
is cross-checked against the signed capability token and the PCI enumeration that
the kernel performs at boot.

The NCIP defers three sub-decisions to follow-up NCIPs filed against this one:
`NCIP-Driver-NVMe-XXX` (storage), `NCIP-Driver-Net-XXX` (Ethernet / Wi-Fi),
`NCIP-Driver-TEE-XXX` (real TDX / SEV-SNP backend). Each will inherit the
framework specified here and add device-specific manifest fields and IPC
channel shapes.

---

## Motivation

### M1. The Phase 1 deliverable is explicit and load-bearing

`docs/06-roadmap.md` lists user-space drivers as a Phase 1 deliverable — not
Phase 2. The roadmap was approved before any kernel code was written; the
choice is not negotiable mid-phase without an NCIP that explicitly amends it
(`NCIP-Process-001` § 3.b).

the backlog § "Phase 1 closure roadmap" Sprint 7 (`P6.7 — Userspace driver model`)
sequences this work after MB13 (real capability dispatch) and MB14 (MP/AP enable
+ TLB shootdown). Both prerequisites are now closed (v0.3.0-alpha.1 released
2026-05-20, MB14.a-h.2 inclusive). The technical gating is therefore removed.

### M2. The bring-up sequence is well-defined but unspecified

The five surfaces this NCIP locks are individually obvious from the microkernel
literature (L4, seL4, Genode, Redox). What is **not** obvious is the precise
shape of each one in the NexaCore OS context:

- **Capability scope** must extend `nexacore-capability::scope::{Action,Resource}`
  without breaking the wire format (see `ncips/ncip-serde-004.md` § S2 canonical
  encoding). `#[non_exhaustive]` enums give a path; the NCIP must enumerate the
  variants and their `Subset` semantics.
- **MMIO syscall** must be added to the `SyscallNo` enum (`crates/nexacore-kernel/
  src/bare_metal/syscall_entry.rs`) at a stable number. The current enum reserves
  20 (`IpcCreateChannel`, MB13.d) and 21 (`IpcReceive`, MB12). 22 is the next
  free slot.
- **DMA / IOMMU** has two vendor-specific paths (Intel VT-d ↔ AMD-Vi). Both
  expose a per-device PASID table; the NCIP must decide whether NexaCore OS uses
  PASID-tagged shared mappings (allows fine-grained sub-process sharing,
  expensive on context switch) or one root domain per driver process (coarser
  but matches the existing per-process CR3 invariant from MB11).
- **IRQ routing** has policy choices that affect determinism: shared lines must
  either fan-out to every claimant (current Linux behavior) or be rejected at
  capability-issuance time (current seL4 behavior). The NCIP must pick.
- **Driver manifest + signing** crosses into supply-chain hardening. The
  manifest schema must be locked here so `NCIP-Driver-NVMe-XXX` (and siblings)
  do not each invent their own.

### M3. Five concrete bugs / regressions this NCIP forecloses

These are not hypothetical — each is traceable to an actual issue or to a known
sharp edge in `nexacore-kernel`:

1. **VirtIO BAR > 4 GiB phys regression (v0.2.0 → v0.3.0-alpha.1)**. On Proxmox
   q35 with 4 GiB RAM, OVMF places the `virtio-tablet-pci` 64-bit prefetchable
   BAR at ~ 60 GiB phys, above the bootloader 0.11 `MemoryRegionKind::Usable`
   direct map. The kernel's first MMIO write `#PF`-ed on an unmapped PML4 entry.
   `virtio_tablet::ensure_mmio_page_mapped` was added as a point fix
   (commit `c8b5e6c`, see `progress-nexacore.md` § 2026-05-20). A user-space driver
   path that always goes through the kernel's `MmioMap` syscall forecloses this
   class of regression — the kernel is the single authority that decides where
   each BAR lands in VA space and ensures the PT is walked-and-mapped exactly
   once.

2. **DMA confused-deputy.** A driver that accepts a DMA target buffer pointer
   from a sibling user process can be tricked into writing into kernel memory
   if the address is rebound. The IOMMU domain per driver process forecloses
   this: a driver's bus-master writes are filtered through its own page table,
   which only contains pages the kernel explicitly granted.

3. **IRQ replay / spoofing.** A malicious user that can write to an `IrqLine`
   capability could synthesize phantom interrupts to a driver and induce it
   to perform spurious actions. The NCIP specifies that `IrqAttach` produces a
   one-way `IpcReceive`-style endpoint; the user cannot synthesize messages on
   it because the IPC kernel ABI rejects writes from non-attached endpoints
   (already enforced by MB12 IPC, see `crates/nexacore-kernel/src/ipc.rs`).

4. **Signed-driver substitution / TOCTOU.** A driver image swapped on disk
   between manifest verification and `DriverLoad` syscall would defeat the
   signature check. The NCIP specifies that the kernel computes
   `BLAKE3(nexacore_image)` at load time, compares it to the manifest's
   `nexacore_image_hash`, and refuses the load on mismatch — no on-disk recheck
   between manifest read and image load (the entire critical section is
   in-kernel and atomic from user view).

5. **Capability scope drift.** Without explicit MMIO/DMA/IRQ scope, a driver
   process holds the implicit "user-space process" capability from the
   existing MB12 token, which is permissive enough that a malicious driver
   could open IPC channels to non-driver processes and exfiltrate device
   state. The new scope variants are subset-strict (`IrqLine(L1)` is not a
   subset of `IrqLine(L2)` unless `L1 == L2`), so a NVMe-driver token cannot
   masquerade as an Ethernet-driver token.

### M4. External pressure: P6.8 audit cannot start without this contract

the backlog P6.8 (first external security audit of kernel + capability system)
is blocked-on P4 funding + P6.7 done. An auditor reading the codebase today
finds no specification of what a driver is allowed to do — only the absence
of drivers. Locking the contract here makes the audit tractable: the auditor
checks the implementation against this NCIP, not against an unwritten model.

---

## Specification

> **Normative keywords.** RFC 2119 / RFC 8174 (MUST, MUST NOT, SHOULD,
> SHOULD NOT, MAY).

### S1. Capability scope extensions

`crates/nexacore-capability/src/scope.rs` is extended with the following variants,
all `#[non_exhaustive]` to preserve postcard wire-format compatibility per
`NCIP-Serde-004` § S2:

```rust
#[non_exhaustive]
pub enum Action {
    // ... pre-existing variants ...
    MmioMap,           // map a PCI BAR range read/write into the caller AS
    DmaMap,            // install a DMA window in the caller's IOMMU domain
    IrqAttach,         // attach the caller's IPC endpoint to an IRQ vector
    PciConfigRead,     // read PCI configuration space
    PciConfigWrite,    // write PCI configuration space
    DriverLoad,        // request the kernel to load a signed driver image
    DriverUnload,      // request the kernel to unload a driver
}

#[non_exhaustive]
pub enum Resource {
    // ... pre-existing variants ...
    PciDevice {
        segment: u16,
        bus: u8,
        device: u8,
        function: u8,
    },
    MmioRegion {
        phys_base: u64,
        len: u64,
    },
    DmaWindow {
        iova_base: u64,
        len: u64,
    },
    IrqLine(u16),       // IOAPIC line OR allocated MSI vector
}
```

**S1.1 (Subset semantics).** For each new `Resource` variant, the subset
relation MUST be:

| Variant | Subset rule |
|---|---|
| `PciDevice` | byte-exact equality of all four fields |
| `MmioRegion` | inclusive range `phys_base..phys_base+len` is contained |
| `DmaWindow`  | inclusive range `iova_base..iova_base+len` is contained |
| `IrqLine`    | byte-exact equality of the `u16` |

Rationale: PCI BDF and IRQ lines are atomic identifiers; ranges have natural
sub-range semantics. The strict-equality choice for `PciDevice` is deliberate:
a driver that holds the `(0,0,1,0)` capability MUST NOT be allowed to perform
PCI config writes against `(0,0,1,1)` even if the same physical device
exposes both functions, because the BDF is the boundary the IOMMU enforces.

**S1.2 (Token minting).** Tokens carrying any of the new variants MUST be
minted by an Ed25519 capability provider (`Ed25519CapabilityProvider` from
MB13.c), MUST carry a `not_after` ≤ 90 days from `not_before`, and MUST carry
a `subject` equal to the driver process's `NodeId`. Long-lived tokens
(`not_after - not_before > 90 days`) MUST be rejected at issuance.

**S1.3 (Token attenuation).** Attenuation MUST follow the existing
`nexacore-capability::attenuation::attenuate` semantics: a child token's
`scope.resource` MUST be a `Subset` of the parent, the `not_after` MUST be
≤ the parent's `not_after`, and the child's `subject` MUST equal the
parent's `subject`. This is the existing wire contract, not new.

### S2. `MmioMap` syscall (`SyscallNo = 70`)

A new x86_64 syscall is added to `crates/nexacore-kernel/src/bare_metal/
syscall_entry.rs`. ABI follows the existing convention (`rdi`=syscall number,
`rsi..r9`=arguments, return in `rax`):

```
SyscallNo::MmioMap = 70

Arguments:
  rsi = phys_base    : u64       — must be page-aligned (0x1000)
  rdx = len          : u64       — must be a multiple of 0x1000
  rcx = flags        : u64       — bit 0 = WC (write-combining), bit 1..63 = reserved (must be 0)
  r8  = cap_ptr      : *const u8 — pointer to postcard-encoded CapabilityToken
  r9  = cap_len      : u64       — length of the postcard-encoded token

Return:
  rax = va_base      : u64       — page-aligned user VA at which the mapping landed
                                   OR 0 on error (error code in rdx)
  rdx = error_code   : u64       — see Errors table; 0 on success
```

**S2.1 (Authorization).** The kernel MUST:

1. Decode the capability token via `nexacore_types::wire::decode_canonical`.
2. Verify the signature, time window, TEE binding via
   `Ed25519CapabilityProvider::verify_signed_token` (MB13.c path).
3. Verify the token's `scope.action` is exactly `Action::MmioMap`.
4. Verify the token's `scope.resource` is `Resource::MmioRegion` and that
   `[phys_base, phys_base+len)` is a `Subset` of the token's resource range.

Any failure MUST return `EACCES` (error code 13) without mapping anything.

**S2.2 (Mapping policy).** On authorization success, the kernel MUST:

1. Allocate `len / 0x1000` contiguous user VA pages from the per-process
   driver VA range `0x0000_0080_0000_0000..0x0000_0080_0000_0000 + 0x80_0000_0000`
   (one PML4 slot = 512 GiB reserved for driver MMIO). The base of this
   range within the reserved slot is randomized per driver process per
   § S2.5.
2. For each page, install the mapping in the caller's AddressSpace via
   `PageMapper::map_4k_into` with flags `PTE_PRESENT | PTE_WRITABLE |
   PTE_USER | PTE_NX` (no execute), and additionally `PTE_PCD | PTE_PWT`
   (cache-disable, write-through) if `flags & 1 == 0` (default
   uncached). If `flags & 1 == 1` (WC requested), set the PAT bits for
   write-combining — implementation MAY defer this if PAT is not yet
   configured; in that case the request MUST be rejected with `ENOSYS`
   (error code 38).
3. Track the mapping in a per-process `MmioMapTable` so the kernel can
   tear it down at process exit (without this, a process crash would leak
   the mapping forever).
4. Return the page-aligned VA in `rax`.

**S2.3 (Errors).**

| Error code | Meaning |
|---|---|
| 0  | Success |
| 13 | `EACCES` — token verification failed |
| 14 | `EFAULT` — `cap_ptr` is not a valid user pointer or `cap_len > 1024` |
| 22 | `EINVAL` — `phys_base` or `len` not page-aligned, or `flags` reserved bits non-zero |
| 38 | `ENOSYS` — WC flag set but PAT not configured |
| 28 | `ENOSPC` — driver VA range exhausted |

**S2.4 (Lifecycle).** A mapping installed by `MmioMap` MUST be torn down by
the kernel at process exit. The NCIP does not specify a `MmioUnmap` syscall —
short-lived per-mapping VA is wasteful but acceptable; long-lived drivers
get one mapping per BAR for their lifetime. A future NCIP MAY add an explicit
unmap path if the VA-pressure model changes.

**S2.5 (VA randomization).** The base VA of the first `MmioMap` for a given
driver process MUST be randomized within the reserved range (§ S2.2) with
4 KiB granularity, using `crates/nexacore-kernel/src/kaslr.rs::KaslrRng`.
Subsequent mappings for the same process are allocated linearly from the
randomized base (deterministic relative to the first mapping, randomized
absolute). Rationale: defends against bug-class exploits that rely on
knowing absolute BAR addresses; cost is one `rdrand` per driver process
at spawn.

### S3. DMA / IOMMU model

**S3.1 (Domain-per-driver).** NexaCore OS uses **one IOMMU domain per driver
process**. The domain's PASID table is owned by the kernel; the driver process
cannot directly write to it. Rationale:

- Matches the existing per-process CR3 invariant (MB11 ADR-0004 § 4).
- Avoids the PASID-tagged-shared-mapping complexity at the cost of one
  domain switch per driver context switch (acceptable: drivers are pinned
  to a CPU and rarely migrate).
- Defense-in-depth: even if a driver process is compromised, its bus-master
  writes are filtered through its own IOMMU page table; the attacker cannot
  reach kernel memory or other driver memory through DMA.

**S3.2 (`DmaMap` syscall, `SyscallNo = 71`).**

```
SyscallNo::DmaMap = 71

Arguments:
  rsi = user_va      : u64       — page-aligned user VA the driver wants to expose
  rdx = len          : u64       — multiple of 0x1000
  rcx = direction    : u64       — 0=ToDevice, 1=FromDevice, 2=Bidirectional
  r8  = cap_ptr      : *const u8 — CapabilityToken with Action::DmaMap
  r9  = cap_len      : u64

Return:
  rax = iova         : u64       — IOMMU virtual address the device should use
                                   OR 0 on error
  rdx = error_code   : u64
```

**S3.3 (Mapping policy).** The kernel MUST:

1. Verify the token (Action=DmaMap, Resource=DmaWindow contains
   `[iova, iova+len)` for some kernel-chosen `iova`).
2. Walk the caller's PT to verify each VA page is mapped read/write user.
3. For each page, install an IOMMU PT entry mapping `iova + offset` →
   `phys(user_va + offset)` with permissions consistent with `direction`
   (ToDevice → read-only by device; FromDevice → write-only by device;
   Bidirectional → read+write).
4. Return `iova`.

**S3.4 (Lifecycle).** The kernel MUST tear down the IOMMU mapping at
process exit. If the driver process exits while a DMA transaction is in
flight, the IOMMU MUST raise an unrecoverable fault and the kernel MUST
log it via `early_console::emit` and halt the device via a kernel-mediated
PCI config write to the device's command register (clearing the bus-master
bit). This is a defense against compromised-driver scenarios.

**S3.5 (Vendor backends).** Two backends are required:

- **Intel VT-d** (`crates/nexacore-kernel/src/bare_metal/iommu/vtd.rs`, new) —
  drives the DMAR ACPI table, programs the IOMMU root table at boot,
  maintains the per-driver-domain context-entry table.
- **AMD-Vi** (`crates/nexacore-kernel/src/bare_metal/iommu/amdvi.rs`, new) —
  drives the IVRS ACPI table, equivalent semantics.

The kernel MUST detect the vendor at boot and select the backend; presence
of neither (e.g., QEMU without `-device intel-iommu`) MUST result in the
`DmaMap` syscall returning `ENOSYS`. This is a deliberate hard fail:
running drivers without IOMMU protection is unsafe.

### S4. IRQ routing

**S4.1 (`IrqAttach` syscall, `SyscallNo = 72`).**

```
SyscallNo::IrqAttach = 72

Arguments:
  rsi = irq_line     : u64       — IOAPIC line (0..255) or MSI vector (0x40..0xFE)
  rdx = ipc_endpoint : u64       — IPC channel ID the driver wants to receive notifications on
  rcx = cap_ptr      : *const u8 — CapabilityToken with Action::IrqAttach
  r8  = cap_len      : u64

Return:
  rax = vector       : u64       — actual interrupt vector allocated (for MSI)
                                   OR equal to irq_line (for IOAPIC) on success
                                   OR 0 on error
  rdx = error_code   : u64
```

**S4.2 (Allocation policy).** The kernel MUST:

1. Verify the token (Action=IrqAttach, Resource=IrqLine(`irq_line`)).
2. For IOAPIC lines: program the IOAPIC redirection-table entry to deliver
   `vector = irq_line + 0x20` (offset to avoid CPU exception range) to a
   single CPU (the BSP for now, see S4.5).
3. For MSI vectors: allocate the next free vector in `0x40..0xFE` (the
   kernel maintains a bitmap), program the device's MSI capability via
   PCI config writes, return the allocated vector.
4. Install an IDT entry pointing at a trampoline that:
   - acks the LAPIC,
   - enqueues a zero-length IPC message on `ipc_endpoint`,
   - returns from interrupt.

**S4.3 (Shared lines: rejection).** If the IOAPIC line is already attached
to a driver, the second `IrqAttach` MUST return `EBUSY` (error code 16).
Rationale (chosen over Linux fan-out behavior): determinism. A driver that
relies on shared-line semantics is hard to reason about for the auditor; a
driver that gets `EBUSY` either retries (the previous driver crashed and
the kernel reclaimed the line) or aborts (the line is genuinely contested,
and the user must resolve via OS-level configuration). MSI / MSI-X vectors
are inherently non-shared, so this restriction does not apply to them.

**S4.4 (Coalescing).** If interrupts arrive faster than the driver drains
its IPC channel, the kernel MUST coalesce: the IPC queue has a fixed depth
(`IPC_DRIVER_IRQ_DEPTH = 64`); on overflow the kernel atomically increments
a per-channel `missed_since_last_drain` counter. The next successful enqueue
(after the consumer drains) is emitted as `IrqNotification::MissedSince(n)`
instead of the usual `IrqNotification::Tick`, then `missed_since_last_drain`
is reset to 0. The IRQ channel message shape is locked in § S4.6.

**S4.5 (CPU affinity).** This NCIP locks affinity to **BSP only** for v0.3.
A future NCIP MAY introduce per-driver CPU affinity once MB14.h.2-equivalent
cross-CPU dispatch is validated under sustained load. For now, all IRQs
land on BSP, all driver IPC drains happen on BSP. This is a deliberate
simplification — multi-core IRQ routing is a known complexity sink in
both Linux and seL4 and is not on the Phase 1 critical path.

**S4.6 (IRQ channel message shape).** The IPC channel attached via
`IrqAttach` (§ S4.1) carries messages of the following postcard-encoded
shape:

```rust
#[non_exhaustive]
#[repr(C)]
pub enum IrqNotification {
    Tick,                  // single delivered interrupt since last drain
    MissedSince(u32),      // N additional interrupts were coalesced since the last enqueue
}
```

Both variants encode via postcard to a single byte (discriminant) plus
the optional `u32`. Drivers MUST handle both variants; a driver that only
handles `Tick` MUST be rejected by `nexacore-driver-pack lint` (build-time
check, not kernel-enforced). This makes IRQ loss visible **in-band on the
channel itself**; no separate stats syscall is needed.

### S5. Driver manifest + signed image

**S5.1 (Manifest schema).** A driver image MUST be accompanied by an
**NexaCore-Pack v1** binary container (§ S5.5). The container embeds a
postcard-encoded canonical manifest. The TOML schema below is the
**developer-authored source format**: it is consumed by the
`nexacore-driver-pack` build tool (user-space, NexaCore Forge) and compiled
offline into the canonical postcard payload that the NexaCore-Pack carries.
The kernel does NOT parse TOML; it only validates the NexaCore-Pack header
and decodes the postcard manifest. Schema file location:
`docs/protocol/driver-manifest-v1.toml`.

```toml
# nexacore-driver-manifest v1

[meta]
name           = "nexacore-driver-nvme"        # human-readable identifier
version        = "0.1.0"                    # semver
nexacore_image_hash = "<64-hex-char BLAKE3 of the ELF image>"
nexacore_signature  = "<base64 Ed25519 signature over (meta + capabilities + matchers) by issuer>"
nexacore_issuer_pubkey = "<base64 Ed25519 public key>"

[capabilities]
# Each entry is a capability the driver REQUESTS at load time. The kernel
# MUST refuse the load if any requested capability is not provable as a
# subset of the issuer's existing capabilities.
mmio_regions  = [ { phys_base = "0xfebd0000", len = "0x4000" } ]
dma_windows   = [ { iova_base = "0x0",        len = "0x40000000" } ]
irq_lines     = [ 11, 12 ]
pci_devices   = [ { segment = 0, bus = 0, device = 1, function = 0 } ]

[matchers]
# Devices the driver can claim. Empty arrays mean "no auto-claim".
pci_vendor_device = [ { vendor = "0x8086", device = "0x0a54" } ]  # Intel NVMe
acpi_hid          = [ ]
```

**S5.2 (`DriverLoad` syscall, `SyscallNo = 73`).** A privileged user (one
holding `Action::DriverLoad` on `Resource::Any`) MAY load a driver via:

```
SyscallNo::DriverLoad = 73

Arguments:
  rsi = pack_ptr     : *const u8 — NexaCore-Pack v1 binary blob (§ S5.5)
  rdx = pack_len     : u64       — must be ≤ 32 MiB (header + manifest + sig + image)
  rcx = cap_ptr      : *const u8 — CapabilityToken with Action::DriverLoad
  r8  = cap_len      : u64

Return:
  rax = pid          : u64       — PID of the spawned driver process, 0 on error
  rdx = error_code   : u64
```

**S5.3 (Load-time verification).** The kernel MUST atomically:

1. Verify `Action::DriverLoad` token.
2. Validate `pack_ptr` lies fully within the calling process's address
   space and `pack_len ≤ 32 MiB`; fault → `EFAULT` (14).
3. Parse the NexaCore-Pack v1 header (fixed 64 bytes, § S5.5); reject
   malformed magic / version / size fields with `EINVAL` (22). **No
   allocations on the failure path.**
4. Decode `manifest.pc` via
   `nexacore_types::wire::decode_canonical::<DriverManifestV1>`; postcard
   decode failure → `EINVAL`.
5. Verify the Ed25519 signature `manifest.sig` over `manifest.pc` bytes
   using the manifest's `nexacore_issuer_pubkey`; failure → `EACCES` (13).
6. Verify `nexacore_issuer_pubkey` is present in the kernel-static
   `KNOWN_ISSUERS` table (§ S5.4); unknown issuer → `EACCES`.
7. Compute `BLAKE3(image.elf)` over the bytes pointed to by the header's
   `image_offset / image_len` fields; compare to `meta.nexacore_image_hash`;
   mismatch → `EINVAL`.
8. For each requested capability, mint an attenuated child token bound
   to the new driver process's NodeId, scope from the manifest, lifetime
   = 90 days. These tokens are pre-installed in the driver's initial
   capability namespace so it does not need to perform discovery.
9. Spawn the driver process via the existing `process::spawn_from_elf`
   path (MB11.4), enroll in the scheduler, return its PID.

The kernel MUST hold no locks across user-pointer reads. Any failure in
steps 2–8 MUST cause the entire load to abort with no side effect on
IOMMU domains, page tables, or scheduler state.

**S5.4 (Known-issuer table).** The kernel MUST ship with a static list of
known driver-issuer public keys, baked in at compile time. Initial issuers
(populated by follow-up NCIPs):

- Stichting NexaCore signing key (for first-party drivers shipped with the OS).
- Per-vendor signing keys for whitelisted hardware vendors (e.g., Intel,
  AMD, Mellanox), each enrolled by its own NCIP via the standard process.

A driver signed by an unknown key MUST be refused. Trust-on-first-use
(TOFU) is NOT permitted for drivers. Rationale: drivers run with
elevated capabilities (MMIO, DMA, IRQ), so the trust base must be small
and explicit, not learned.

**S5.5 (NexaCore-Pack v1 binary format).** The on-disk artifact loaded by
`DriverLoad` (§ S5.2) is a single binary blob with the following layout
(all multi-byte integers little-endian):

```
Offset  Size  Field
─────── ───── ─────────────────────────────────────────────────────────
0x00    8     magic              = b"OMNIPACK"
0x08    4     version            = 1u32
0x0C    4     flags              reserved, MUST be 0
0x10    8     manifest_offset    (from start of pack)
0x18    8     manifest_len       (postcard bytes, ≤ 16 KiB)
0x20    8     signature_offset
0x28    8     signature_len      = 64 (Ed25519)
0x30    8     image_offset
0x38    8     image_len          (ELF bytes, ≤ 32 MiB − header − manifest − sig)
0x40    ...   manifest.pc        postcard canonical encoding of DriverManifestV1
...     ...   signature          raw Ed25519 over manifest.pc, 64 bytes
...     ...   image.elf          loaded by spawn_from_elf
```

All three `<section>_offset` values MUST point inside the blob; all three
`[offset, offset + len)` ranges MUST be disjoint and contained in
`[0x40, pack_len)`. Violations → `EINVAL` at S5.3 step 3.

`DriverManifestV1` is the postcard-canonicalizable Rust struct
corresponding 1:1 to the TOML schema in § S5.1 (all fields are simple
scalars and vectors). The build tool `nexacore-driver-pack` (user-space, NexaCore
Forge) is the authoritative producer of NexaCore-Pack v1 blobs; the kernel
is a pure consumer.

### S6. IPC ABI extension: driver-server channels

The existing `IpcCreateChannel` (MB13.d) is sufficient as-is for
driver↔userspace and driver↔driver IPC. No new IPC syscall is required.
This NCIP locks the **channel-naming convention** so that the userspace
service-locator can find the right driver:

| Channel name | Direction | Owner | Description |
|---|---|---|---|
| `nexacore.driver.<name>.cmd` | client→driver | driver process | command channel |
| `nexacore.driver.<name>.evt` | driver→clients (broadcast) | driver process | event channel |
| `nexacore.driver.<name>.irq` | kernel→driver | driver process | IRQ notification (S4.2) |

The IPC namespace registry (a flat `BTreeMap<String, ChannelId>`, see
`crates/nexacore-kernel/src/ipc.rs`) MUST reject duplicate registrations —
two drivers cannot claim the same `<name>`.

### S7. Initial first-party drivers (numbering)

The framework specified above is exercised by three first-party drivers,
each in its own follow-up NCIP:

- `NCIP-Driver-NVMe-XXX` (next free integer at filing) — Intel/Samsung NVMe
  storage controllers, BLK channel ABI, file-system mediation deferred.
- `NCIP-Driver-Net-XXX` — virtio-net (host) + Intel e1000e (bare metal) +
  Mellanox ConnectX (server class) — phased delivery.
- `NCIP-Driver-TEE-XXX` — promote the existing stub TEE backend to a real
  driver: Intel TDX module loading via `IpcCreateChannel` + DMA windows
  for the attestation report flow. Replaces the `StubAttestation` path
  used by MB13.c.

Each follow-up NCIP MUST cite this NCIP in its `requires:` frontmatter.

---

## Rationale

### R1. Why microkernel + user-space drivers (not in-kernel)

NexaCore OS's threat model (`docs/04-security-model.md` § 2) names "compromised
driver" as adversary class C-3 (kernel-resident, RW everywhere). The
microkernel architecture demotes drivers to user processes, shrinking C-3
to "compromised driver process with capability-restricted MMIO/DMA/IRQ
access". Without user-space drivers, the entire kernel inherits every
driver's bug surface — a class of issue with a long incident history in
the Linux kernel.

The standard counter-argument (performance) is mitigated by:

- IPC fast-path: MB12 message-passing is already optimized for short
  fixed-shape messages.
- Per-driver CPU pinning (S4.5 BSP-only for now, future per-driver
  affinity): driver code stays hot in one CPU's L1/L2.
- DMA: the user-space driver only orchestrates DMA setup; the data path
  is bus-master writes by hardware, identical performance to in-kernel.

NCIP-Kernel-003 already committed to user-space drivers; this NCIP is the
specification, not the policy decision.

### R2. Why domain-per-driver (not PASID-tagged shared mappings)

VT-d and AMD-Vi both support PASID (Process Address Space Identifier),
which enables a single IOMMU domain to filter bus-master writes by
PASID. This would allow fine-grained sub-process DMA sharing (a useful
property for, e.g., a shared NVMe buffer pool serving multiple
filesystems).

We chose domain-per-driver for three reasons:

1. **Simplicity matches MB11 invariant.** Per-process CR3 + per-process
   IOMMU domain is symmetric; PASID requires a second indirection that
   is hard to reason about.
2. **Auditor surface area.** PASID-tagged sharing requires a kernel
   mechanism for "this PASID may DMA-share with that PASID", which is a
   new authorization surface. We don't need it for Phase 1 closure.
3. **PASID hardware is patchy.** Older Xeon (pre-Sapphire Rapids)
   supports PASID but the corner cases are fragile; AMD-Vi PASID was
   only stabilized in Zen 4. Domain-per-driver works on every IOMMU-capable
   CPU since Ivy Bridge / Bulldozer.

A future NCIP MAY introduce PASID-tagged sharing for the NVMe→FS
fast-path if benchmarks demand it.

### R3. Why shared-IRQ-line rejection (not Linux-style fan-out)

Linux's fan-out model treats every shared-line claimant as a polling
callback; each driver inspects its device's status register, returns
"handled" or "not mine", and the kernel walks the chain. This works
in practice but has three properties we reject:

1. **Non-determinism.** Adding a driver changes the latency budget of
   every other driver on the same line.
2. **Trust transitivity.** A buggy/malicious driver in the chain can
   stall the chain for every other driver.
3. **Spec ambiguity.** "What is the interrupt vector for this driver"
   has no single answer.

`EBUSY` on conflict (S4.3) is a hard property: the kernel guarantees
that a successful `IrqAttach` gives the driver exclusive ownership of
that line for its lifetime. Userspace handles the failure case by
remapping (where possible) or by surfacing a configuration error to
the operator.

### R4. Why TOML for the manifest (not JSON / CBOR / postcard)

The manifest is a developer-authored document, read by humans during
driver bring-up and by the kernel at load time. TOML wins on:

- **Human readability** (vs CBOR / postcard, which are binary).
- **Strict schema** (vs JSON, which has number-type ambiguity).
- **Existing crate** (`toml`, well-audited, `no_std + alloc` capable).

The on-disk artifact loaded by the kernel is the **NexaCore-Pack v1** binary
container (§ S5.5), not raw TOML. The TOML schema in S5.1 is the
developer-authored *source* format, compiled offline by `nexacore-driver-pack`
(a user-space build tool) into the canonical postcard payload that the
NexaCore-Pack carries. The kernel never parses TOML — this keeps the
pre-authentication parser surface minimal (NexaCore-Pack header decoder +
postcard decoder, both ~300 LoC each, vs. the `toml` crate's ~3000 LoC
including its dependency stack). Same pattern as Device Tree (DTS source
→ DTB binary) and seL4 (capDL source → capdl-loader binary).

### R5. Why a static `KNOWN_ISSUERS` table (not a CA chain)

NCIP-Driver-Framework expects ≤ 10 issuers in the v0.3 era (Stichting
NexaCore + 3–5 hardware vendors). A static compile-time table is:

- Atomic with the kernel image (verified by the boot signature).
- Has no runtime trust-acquisition path (no TOFU, no DNS, no
  certificate transparency log).
- Auditable in one location.

Once the issuer count scales beyond ~50 (Phase 4+ federated drivers),
a follow-up NCIP MAY introduce a CA-like hierarchy with revocation. For
now, simplicity wins.

### R6. What we are NOT doing in this NCIP

- **No driver isolation across CPU sibling threads.** SMT side-channel
  defense is deferred to a future hardening NCIP.
- **No driver memory pinning.** Drivers MAY page-fault; their pages are
  swappable. (No swap is implemented either, so this is moot until Phase 2.)
- **No driver hot-reload.** A `DriverUnload + DriverLoad` cycle is the
  upgrade path; live patching is out of scope.
- **No userspace driver discovery service.** `docs/protocol/
  service-locator-v1.md` is a follow-up; for v0.3 the channel-naming
  convention (S6) is sufficient.
- **No graphics driver.** GPUs are Phase 2 (AI Runtime needs CUDA / ROCm
  abstractions); this NCIP locks the contract for non-GPU device classes.

### R7. Future Work — anticipated follow-up NCIPs

The framework specified here is sufficient for the three Phase 1 drivers
(014/015/016) but anticipates the following follow-ups, named here so the
audit (P6.8) can reference them:

- **`NCIP-Kernel-XXX` (ring-buffer IPC for high-throughput drivers).** The
  single-message IPC model used by 014/015/016 is sufficient for Phase 1
  functional closure but caps NVMe/Net throughput at ~200k ops/s due to
  the IPC round-trip cost. A shared SPSC ring (submission + completion)
  with a single doorbell IPC notification is the standard solution (cf.
  SPDK, io_uring, Linux VFIO). Filed as future work because Phase 1 has
  no IOPS target; v0.3 driver performance numbers will quantify the gap.
- **`NCIP-Driver-Framework-XXX` (PASID-tagged sharing for DMA fast-paths).**
  Useful once NVMe→FS data paths exist and benchmarks demand shared
  zero-copy buffers. Cf. § R2.
- **`NCIP-Driver-Framework-XXX` (per-driver CPU affinity).** Relaxes § S4.5
  BSP-only restriction once MB14.h.2 cross-CPU dispatch is validated under
  sustained load.

---

## Backwards Compatibility

N/A — first introduction of the user-space driver framework. No prior
driver-loading mechanism exists in `nexacore-kernel`; the early-boot
framebuffer, COM1, PS/2, and VirtIO-tablet code paths are kernel-resident
and remain so (they bootstrap before any user process exists).

The capability scope extensions in S1 ARE `#[non_exhaustive]` additions
to existing enums, and per `NCIP-Serde-004` § S2 the postcard wire format
remains stable across `#[non_exhaustive]` additions because postcard
encodes only the discriminant index — old verifiers reject the new
discriminant with a deserialization error (graceful degradation: an
old verify-only client sees an unknown action and rejects the token,
which is the correct behavior).

---

## Test Cases

### TC1. Capability scope round-trip (canonical encoding)

For each new `Action` and `Resource` variant, the postcard
encoded-then-decoded round trip MUST be byte-identical. Test pinned
under `crates/nexacore-capability/tests/wire_format_v0_3.rs` (new file,
follow-up).

### TC2. MmioMap authorization matrix

The 5-cell matrix `{valid token, missing token, token with wrong
Action, token with wrong Resource range, token expired}` × `{valid args,
mis-aligned args}` MUST be exercised. 9 of the 10 cells return error;
exactly 1 returns success. Test under
`crates/nexacore-kernel/tests/mmio_map.rs` (host-side, follow-up).

### TC3. DMA confused-deputy

A driver process P1 obtains a `DmaMap` token for IOVA range
`[0x1000, 0x2000)`. A second process P2, with no DmaMap capability,
attempts to invoke `DmaMap(0x1000, 0x1000, ToDevice, P1's-token)`.
The syscall MUST return `EACCES` because the token's `subject` is
P1's NodeId, not P2's. Test under
`crates/nexacore-kernel/tests/dma_subject_check.rs` (host-side, follow-up).

### TC4. IRQ shared-line rejection

Driver P1 attaches to `IrqLine(11)`. Driver P2 attempts to attach to
the same line. P2 MUST receive `EBUSY`. Test under
`crates/nexacore-kernel/tests/irq_busy.rs` (host-side, follow-up).

### TC5. Driver manifest TOCTOU resistance

The kernel computes `BLAKE3(image)` over the kernel-side copy of the
image bytes, not over a re-read from disk. Test: invoke `DriverLoad`
with image bytes whose first 16 bytes do not match the manifest hash;
expect `EINVAL`. The test MUST also verify that no IOMMU domain is
installed and no PT is touched after the failure (i.e., atomicity).
Test under `crates/nexacore-kernel/tests/driver_load_atomicity.rs`
(host-side, follow-up).

### TC6. Unknown-issuer rejection

`DriverLoad` with a manifest signed by an issuer not in
`KNOWN_ISSUERS` MUST be rejected with `EACCES`. Test under
`crates/nexacore-kernel/tests/driver_load_issuer.rs` (host-side,
follow-up).

Hardware smoke (gated on hardware availability): a real Intel NVMe
device on the Proxmox test VM (or equivalent passthrough host) loads
the future `nexacore-driver-nvme` and produces a `read 4K @ LBA 0`
followed by a `write 4K @ LBA <test_lba>` round-trip. This is
exercised by `NCIP-Driver-NVMe-XXX`, not by this NCIP.

---

## Reference Implementation

N/A at filing time (this NCIP is the **specification**; the implementation
follows in `NCIP-Driver-NVMe-XXX` and the framework-side patches it
depends on).

The framework-side patches expected at the next implementation cycle:

- `crates/nexacore-capability/src/scope.rs` — new `Action` and `Resource`
  variants per S1.
- `crates/nexacore-kernel/src/bare_metal/syscall_entry.rs` — three new
  syscall handlers (S2, S3, S4) and one for `DriverLoad` (S5).
- `crates/nexacore-kernel/src/bare_metal/iommu/{vtd.rs,amdvi.rs}` — new
  vendor backends per S3.5.
- `crates/nexacore-kernel/src/driver_manifest.rs` — new module for S5.1
  parsing and S5.3 verification.
- `crates/nexacore-kernel/src/known_issuers.rs` — generated by
  `build.rs` from `docs/protocol/driver-issuers.toml` per S5.4.
- `docs/protocol/driver-manifest-v1.toml` — committed schema example
  + per-field documentation.
- `docs/protocol/driver-issuers.toml` — committed initial issuer list
  (starts with Stichting NexaCore placeholder pubkey, replaced at
  Stichting incorporation per P4.1).

Tracking branch (TBD at implementation kickoff):
`feat/kernel-p6-7-driver-framework` (sibling to the closed
`feat/kernel-mb11-userspace`).

---

## Security Considerations

### SC1. Threat model alignment

Per `docs/04a-threat-model.md` adversary classes:

- **C-1 (local-user, no caps)** — cannot invoke `MmioMap`/`DmaMap`/
  `IrqAttach`/`DriverLoad` because they hold no token with those
  actions. The token verification path is identical to MB13.c.
- **C-2 (local-user, partial caps)** — bounded by capability
  attenuation: a token MUST be a strict subset of its parent, so
  privilege escalation across the driver boundary requires forging
  Ed25519 signatures (computationally infeasible) or exploiting a
  kernel bug in the verification path (the audit target P6.8).
- **C-3 (compromised driver)** — bounded by IOMMU domain isolation
  (S3.1) and capability scope (S1). A compromised NVMe driver
  cannot DMA into kernel memory, cannot send phantom interrupts on
  another driver's IRQ line, and cannot exfiltrate device state to
  non-IPC-connected processes.
- **C-4 (compromised kernel)** — out of scope; this NCIP does not
  defend against C-4 (no architecture can, short of formal verification).
- **C-5 (compromised hardware)** — partially mitigated: TDX/SEV-SNP
  attestation covers the OS-firmware-CPU boundary; rogue PCI devices
  are filtered by the IOMMU but a malicious device that re-enumerates
  itself with a different vendor/device ID after capability issuance
  could in principle subvert the matcher. Future work: ATS (Address
  Translation Services) revalidation, out of scope here.

### SC2. Failure modes and blast radius

| Failure mode | Blast radius | Mitigation |
|---|---|---|
| Capability token forged | One driver process | Ed25519 + 90-day expiry |
| IOMMU misconfiguration at boot | All drivers | Boot-time self-test; hard halt on failure |
| MSI vector exhaustion | New driver loads fail | `ENOSPC` returned; existing drivers unaffected |
| Manifest signature bypass | One driver image | `KNOWN_ISSUERS` static table; no TOFU |
| IRQ storm from rogue device | One driver IPC channel saturated | Coalescing + `missed_count` |
| DMA into kernel memory | Theoretically blocked by IOMMU | Hard halt on IOMMU fault + device disable |

### SC3. Cryptographic considerations

- Ed25519 verification is constant-time via `ed25519-dalek` (already
  RFC-vector-pinned by `nexacore-crypto` per `NCIP-Kernel-012` § S3).
- BLAKE3 hashing is constant-time over secret inputs; the driver image
  hash is not secret but the constant-time property eliminates a class
  of cache-timing leaks.
- The Ed25519 signing keys for `KNOWN_ISSUERS` are HSM-resident
  (Stichting NexaCore key per P4.1); never loaded into the kernel.
- No new primitives — all cryptography reuses `nexacore-crypto`'s audited
  surface.

### SC4. Side-channel considerations

- **Spectre v1 (bounds check bypass).** The MMIO/DMA argument
  validation paths perform bounds checks; the speculative path past a
  failed check is irrelevant because the failed-check arm returns
  without touching the resource. No speculative leak.
- **SMT cross-thread leakage.** A driver pinned to BSP shares L1/L2
  with non-driver code on BSP's sibling. This is partially mitigated
  by pinning drivers to BSP only and partially deferred to the
  hardening NCIP (R6).
- **Side-channels via IRQ timing.** A driver that times its IRQ
  arrivals can infer activity on adjacent IRQ lines (a class of
  Linux Spectre-style leaks). Mitigation: drivers MUST run as
  unprivileged from the cap-system POV; the OS user has no oracle.

---

## Privacy Considerations

### PC1. Personal data flows

Drivers MAY handle personal data in transit (e.g., a network driver
sees packet payloads). The driver-framework contract does NOT
mandate encryption of in-transit data — that is the higher layer's
responsibility (TLS, NexaCore Mesh handshake per `docs/03-mesh-protocol.md`).

This NCIP locks ONE invariant relevant to privacy: a driver MUST
NOT have IPC visibility into channels it did not create or attach
to. The IPC namespace from S6 enforces this; the kernel rejects
attempts to read a channel without an attached endpoint.

### PC2. Metadata exposure

Driver loads are logged by the kernel via `early_console::emit` (the
existing serial-port trace). This log includes the driver name and
PID but NOT the manifest contents or the signature blob. Operators
who consider driver-load history sensitive (e.g., to obscure which
hardware is present in the system) can disable the log at compile
time via a future kernel feature flag (`silent-driver-load`,
follow-up).

### PC3. Linkability / unlinkability

The driver subject NodeId is derived from the TEE attestation report
(per `nexacore-types::identity::NodeId`); it is stable across boots on
the same hardware. A driver's NodeId is therefore a stable
fingerprint of that hardware. This is not new (every NexaCore OS process
has the same property), but it bears noting for any future federation
work where drivers may need to authenticate to remote services.

### PC4. GDPR / regulatory implications

- **Data minimization:** drivers see only the data the kernel
  routes to them via IPC + DMA; no broadcast-to-all-drivers channel
  exists.
- **Purpose limitation:** each driver's capability scope is
  declared in the manifest (S5.1) and enforced by the kernel; a
  driver cannot exceed the declared scope without re-loading with
  a new manifest, which is an auditable event.
- **Retention:** drivers do not persist data without a separate
  storage capability (NVMe driver → file-system service → user
  data); retention policies are enforced at the file-system layer,
  out of scope here.

---

## Appendix A — Editorial Reconciliations

### A1. Syscall number reconciliation (2026-05-20, founder fast-path)

The first `Draft` of this NCIP (2026-05-20, commit `bb4b9a1`) proposed
`SyscallNo::{MmioMap = 22, DmaMap = 23, IrqAttach = 24, DriverLoad = 25}`.
At the `Last Call → Active` promotion via founder fast-path on
2026-05-20, an editorial review surfaced a collision: those slots are
already locked in `crates/nexacore-kernel/src/syscall.rs` by the MB12 IPC
block (`IpcSend = 22`, `IpcReceive = 23`) and the surrounding `Cap*`
(30–32) / `Tee*` (40–43) / `Time*` (50) / `WriteConsole` (60) groups.
The MB12 numbers are part of the v0.1 ABI surface and are explicitly
declared immutable by `crates/nexacore-kernel/src/syscall.rs` doc-comment
("**Stable numeric ABI.** Syscall numbers are immutable after v1.0;
adding a syscall is an NCIP").

To avoid breaking the v0.1 IPC ABI while still allocating contiguous,
auditable numbers for the driver framework, this NCIP is editorially
amended to use the next free decade `7x`:

| Variant      | Original (Draft) | Corrected (Active) |
|--------------|------------------|--------------------|
| `MmioMap`    | `22`             | **`70`**           |
| `DmaMap`     | `23`             | **`71`**           |
| `IrqAttach`  | `24`             | **`72`**           |
| `DriverLoad` | `25`             | **`73`**           |

`NCIP-Driver-TEE-016` § S5.3 / S6.3 carries the same editorial fix:
`TeeTdcall = 26 → 74`, `TeeMsr = 27 → 75`.

This reconciliation is editorial only (numbering of a not-yet-Active
ABI surface, no behavioural change, no impact on `Test Cases` TC1–TC6
which never pin numeric values). Per `NCIP-Process-001` §5.3 ("Editorial
changes during Last Call MAY be applied without reopening the window
if they do not alter normative semantics"), it does not require a new
Last Call window.

The grouping convention is preserved and extended:
- `00–09`: reserved
- `10–19`: scheduling/process
- `20–29`: IPC (v0.1, MB12-locked)
- `30–39`: capabilities (v0.1)
- `40–49`: TEE attestation (v0.1)
- `50–59`: time (v0.1)
- `60–69`: I/O (v0.1)
- **`70–79`: driver framework (NCIP-013 + NCIP-016)**
- `80+`: reserved for future NCIPs

---

## Appendix B — Bootstrap fast-path amendments

### B1. Driver loader hardening + ABI cleanup (2026-05-20)

Four normative amendments applied in-place to this NCIP at `Active` state,
under the Bootstrap Period authority of NCIP-Process-001 §6.3 (§5.5 Solo
Founder Fast-Track lineage). Unlike the editorial syscall renumbering in
Appendix A1, these amendments alter normative semantics: the `DriverLoad`
ABI shape, the MMIO VA range, the IRQ coalescing/notification protocol,
and a documentary forecast of follow-up NCIPs.

They were filed and applied the same calendar day as the original
activation; no driver implementation was deployed at the time of
amendment (zero deployment impact, zero in-flight migration risk).

| # | Sections | Change | Effect |
|---|---|---|---|
| 1 | § S5.1, § S5.2, § S5.3, § S5.5 (new), § R4 | `DriverLoad` accepts an `NexaCore-Pack v1` binary container (§ S5.5); kernel no longer parses TOML at the pre-authentication boundary (TOML retained as developer-side source format, compiled offline by `nexacore-driver-pack`). | Pre-authentication parser surface reduced from ~3000 LoC (`toml` crate + transitive deps) to ~300 LoC (NexaCore-Pack header + postcard decoder). |
| 2 | § S2.2 step 1, § S2.5 (new) | Driver VA range widened from 2 GiB to one PML4 slot (512 GiB); base randomized per driver process via `KaslrRng`. | Future-proofing for high-BAR devices (Mellanox, future GPU at Phase 2) + defense-in-depth against bug-class exploits with absolute-address oracles. |
| 3 | § S4.4, § S4.6 (new) | `IrqNotification::{Tick, MissedSince(u32)}` shape locked. Missed-IRQ accounting moves from a deferred sidecar syscall (was rinviato a `NCIP-Driver-NVMe-XXX`) to in-band channel messages. | IRQ-loss observability becomes a framework property, not per-driver; scope correction. |
| 4 | § R7 (new) | Names three anticipated follow-up NCIPs: ring-IPC for high-throughput drivers, PASID-tagged DMA sharing, per-driver CPU affinity. | Documentary; no normative effect on this NCIP. Audit hygiene for P6.8. |

These amendments inherit the Bootstrap Period's provisional status:
they are subject to the **mandatory post-Bootstrap re-ratification**
clause of NCIP-Process-001 §5.5.e alongside the original 013 activation
ballot.

**No follow-up NCIP (014/015/016) requires changes.** Cross-references:

- `NCIP-013 § S5.1` (cited by 014:155, 015:135, 016:116) — still valid;
  TOML schema retained as developer-side source format.
- `NCIP-013 § S5.3` (cited by 014:194) — still valid; verification flow
  extant with steps reordered to validate the container before the
  manifest.
- `NCIP-013 § S4.x` (cited by 014:334, 014:352, 015:227, 015:278) —
  section numbering preserved; new § S4.6 is additive.
- `NCIP-013 § S2.4` (cited by 014:406) — still valid; lifecycle policy
  unchanged.

Implementation tracking branch (when work starts, P6.7.1):
`feat/kernel-p6-7-driver-framework`. The `nexacore-driver-pack` build tool
becomes a Phase 1 closure prerequisite; its filing is anticipated in
P6.7 task decomposition (separate from this errata).

---

## Copyright

This NCIP is released into the public domain under
[CC0-1.0](https://creativecommons.org/publicdomain/zero/1.0/).
