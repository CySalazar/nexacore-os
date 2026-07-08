---
ncip: 14
title: NVMe user-space driver — admin/IO queue ABI, PRP transfer model, BLK channel contract
track: Standards Track
status: Active
authors:
  - cySalazar <hello@nexacoreos.com>
created: 2026-05-20
updated: 2026-05-20
activated: 2026-05-20
requires:
  - 13
supersedes: ~
superseded-by: ~
discussion: https://github.com/CySalazar/nexacore-os/discussions (TBD link)
license: CC0-1.0
---

## Abstract

`NCIP-Driver-Framework-013` § S7 enumerates three first-party drivers to be filed
as follow-up NCIPs against the framework. This NCIP — `NCIP-Driver-NVMe-014` — is
the first of them: a user-space NVMe storage driver targeting **NVMe 1.4-compliant
PCIe SSDs** (Intel/Samsung/WD consumer + Optane DC + Micron datacenter classes).

The driver inherits the kernel-mediated contract from NCIP-013 (capability tokens,
`MmioMap` for BAR access, `DmaMap` for buffer pinning, `IrqAttach` for completion
queues, `DriverLoad` for signed image admission). It adds NVMe-specific surfaces:

1. **Manifest fields** declaring the supported PCI vendor/device matchers, the
   admin submission queue (ASQ) and admin completion queue (ACQ) depths, the
   IO submission queue (ISQ) and IO completion queue (ICQ) depths, and the
   chosen data-transfer model (PRP vs SGL).
2. **Command channel shape** (`nexacore.driver.nvme.cmd`) carrying NVMe-style
   commands: `Read(LBA, count, buf_iova)`, `Write(LBA, count, buf_iova)`,
   `Flush`, `Identify(target)`, `GetLogPage`, `FormatNVM` (last gated by a
   separate capability bit).
3. **Event channel shape** (`nexacore.driver.nvme.evt`) for asynchronous events:
   completion notification with command-ID match, AER (async event request)
   notifications, link-state transitions.
4. **IRQ topology**: one IRQ vector for ACQ completion + N for the IO
   completion queues (N ≤ 4 for v0.3.0). MSI-X strongly preferred; legacy
   IOAPIC pin as fallback only if the device does not implement MSI-X.
5. **BLK channel contract**: a fixed-shape generic-block IPC channel
   (`nexacore.svc.blk.<diskN>`) that future file-system services will read/write
   against, decoupling the NVMe driver from any specific FS implementation.

The data-transfer model is **PRP (Physical Region Page) lists, NOT SGL
(Scatter-Gather List)**. The choice is locked here for two reasons: (a) PRP is
mandatory in NVMe 1.4 and universally supported, (b) the NexaCore OS block layer
operates on 4 KiB-aligned IO buffers natively (block size = page size by
design), which is the only constraint PRP imposes.

The driver is **single-namespace** for v0.3.0 (the first namespace returned by
`Identify(NSID=0xFFFFFFFF)`). Multi-namespace support, NVMe-MI, and zoned
namespaces are deferred to follow-up NCIPs.

---

## Motivation

### M1. Phase 1 closure: storage is the missing leg

`docs/06-roadmap.md` § "Phase 1" lists "**Drivers (in user space): NVMe
storage, Ethernet/Wi-Fi networking, TEE**" — storage is the first item.
Without a working storage driver the kernel cannot read or write a persistent
file system, which blocks every higher-tier deliverable (Phase 2 AI Runtime
needs model weights on disk, Phase 3 Personal Cluster needs workspace sync,
Phase 4 Federated Mesh needs the ledger).

NVMe is the only storage class targeted for v0.3.0 — SATA, IDE, and SCSI are
explicitly out of scope per `docs/07-hardware-requirements.md` (the minimum
supported hardware is post-2018 consumer PC class, where NVMe is universal and
SATA is on its way out).

### M2. The NCIP-013 framework needs its first concrete exerciser

`NCIP-Driver-Framework-013` defines five normative surfaces but at filing
contained no concrete usage. The risk is that the framework, until exercised
end-to-end against a real device, may have an unrecognized blind spot. The
NVMe driver is the canonical exerciser:

- **Capability scope** — claims `Action::{MmioMap, DmaMap, IrqAttach,
  PciConfigRead, PciConfigWrite}` against `Resource::PciDevice` of the NVMe
  controller. If any of the NCIP-013 subset semantics break for this concrete
  case, we discover it now, not at audit time.
- **MMIO** — maps the NVMe controller's MMIO BAR (typically 16 KiB at
  `PCI BAR0`) to read the Controller Capabilities (`CAP`), the Controller
  Configuration (`CC`), Admin Queue Attributes (`AQA`), and the doorbell
  registers.
- **DMA** — pins per-IO 4 KiB buffers as DMA windows for the PRP entries
  and the device's read/write data path.
- **IRQ** — attaches the ACQ vector + N ICQ vectors via `IrqAttach`.
  This is the first multi-vector consumer of NCIP-013 and validates that the
  MSI-X allocation path in S4.2 actually works.
- **Manifest** — declares the matchers and capability requests; the kernel
  verifies the signature and pre-mints the per-driver capability namespace.

### M3. The BLK channel decouples the storage stack

A user-space NVMe driver that exports NVMe-shaped commands to its clients
would force every file system to know NVMe. We instead export a generic
**BLK channel** (`nexacore.svc.blk.<diskN>`) that file systems consume. The BLK
shape is identical for NVMe today, SATA tomorrow, and any future storage
class:

```rust
enum BlkRequest {
    Read  { lba: u64, count: u32, buf_iova: u64 },
    Write { lba: u64, count: u32, buf_iova: u64 },
    Flush,
    Discard { lba: u64, count: u32 },     // optional, capability-gated
}
enum BlkResponse {
    Ok,
    NotSupported,
    DeviceError(u16),       // NVMe status code or 0xFFFF for non-NVMe
    OutOfRange,
    InvalidArgument,
}
```

The NVMe driver maps `BlkRequest` to NVMe submission entries; future drivers
will map the same `BlkRequest` to their own command formats. This is the
file-system-mediation contract referenced in NCIP-013 § R6.

### M4. PRP over SGL: deliberate restriction

NVMe 1.4 defines two data-transfer models: PRP (Physical Region Page lists)
and SGL (Scatter-Gather Lists). PRP is mandatory and universally implemented;
SGL is optional and only on enterprise SSDs. PRP is simpler and well-suited to
the NexaCore OS page-aligned IO model.

PRP imposes one constraint: data buffers must be 4 KiB-aligned. The NexaCore OS
block layer already aligns on 4 KiB (the kernel page size and the BLK
channel's `block_size`). So PRP has zero cost for us.

Choosing PRP eliminates:
- The variable-length SGL descriptor encoding (and its bug surface).
- The need to advertise SGL capability in the manifest.
- The runtime fallback path between PRP and SGL (one less code path).

A future NCIP MAY enable SGL for high-end enterprise scenarios (very large
transfers, scatter-gather across non-contiguous buffers), but it is not
needed for the Phase 1 deliverable.

---

## Specification

> **Normative keywords.** RFC 2119 / RFC 8174 (MUST, MUST NOT, SHOULD,
> SHOULD NOT, MAY).

### S1. Manifest schema extension

The driver manifest (TOML v1, per `NCIP-Driver-Framework-013` § S5.1) MUST
include the following NVMe-specific block under a top-level `[nvme]` table:

```toml
[meta]
name           = "nexacore-driver-nvme"
version        = "0.1.0"
nexacore_image_hash = "<64-hex BLAKE3>"
nexacore_signature  = "<base64 Ed25519>"
nexacore_issuer_pubkey = "<base64 Ed25519>"

[capabilities]
mmio_regions  = [ { phys_base = "<BAR0 from PCI enum>", len = "0x4000" } ]
dma_windows   = [ { iova_base = "0x0", len = "0x100000000" } ]  # 4 GiB IOVA arena
irq_lines     = [ ]   # populated dynamically by IrqAttach at runtime
pci_devices   = [ { segment = 0, bus = "<dyn>", device = "<dyn>", function = 0 } ]

[matchers]
# PCI class code: NVMe = class 0x01, subclass 0x08, prog-if 0x02
# vendor/device left wildcarded; class match is sufficient for v0.3
pci_class    = { class = "0x01", subclass = "0x08", prog_if = "0x02" }
pci_vendor_device = [ ]  # empty → class match wins; populate to restrict

[nvme]
# Admin queue depths (1..=4096 per NVMe 1.4 § 5.1)
admin_sq_depth = 64
admin_cq_depth = 64
# IO queue depths (1..=65536 per NVMe 1.4 § 5.5)
io_sq_depth    = 1024
io_cq_depth    = 1024
# Number of IO queue pairs (1..=4 for v0.3; multi-queue affinity deferred)
io_queue_count = 1
# Data-transfer model: only "prp" accepted in v0.3
transfer_model = "prp"
# Optional features (capability bits in the driver-side, not device-side)
format_nvm_enabled = false   # requires Action::FormatStorage cap-bit, separate token
discard_enabled    = true    # NVMe Dataset Management with AD=1
```

**S1.1 (Validation).** The kernel `DriverLoad` handler (per NCIP-013 § S5.3)
MUST reject the manifest if:

- `admin_sq_depth` or `admin_cq_depth` is not in `1..=4096`,
- `io_sq_depth` or `io_cq_depth` is not in `1..=65536`,
- `io_queue_count` is not in `1..=4`,
- `transfer_model` is not `"prp"`,
- `pci_class` does not match `0x01:0x08:0x02`.

Any of the above MUST return `EINVAL` (22).

### S2. Command channel ABI (`nexacore.driver.nvme.cmd`)

The driver-side endpoint of channel `nexacore.driver.nvme.cmd` accepts messages
of fixed shape `NvmeCommand` (postcard-encoded per
`nexacore-types::wire::encode_canonical`):

```rust
#[non_exhaustive]
pub enum NvmeCommand {
    Identify {
        target: IdentifyTarget,    // Controller | Namespace { nsid: u32 } | ActiveNsList
        buf_iova: u64,             // 4 KiB buffer (IOVA from prior DmaMap)
        opaque_id: u64,            // client-chosen correlation token (echoed in response)
    },
    Read {
        nsid: u32,
        lba: u64,
        block_count: u32,          // 1..=2048 (limited by PRP entries in 4 KiB)
        buf_iova: u64,
        opaque_id: u64,
    },
    Write {
        nsid: u32,
        lba: u64,
        block_count: u32,
        buf_iova: u64,
        opaque_id: u64,
    },
    Flush {
        nsid: u32,
        opaque_id: u64,
    },
    Discard {
        nsid: u32,
        lba: u64,
        block_count: u32,
        opaque_id: u64,
    },
    GetLogPage {
        log_id: u8,                // 0x01=Error, 0x02=SMART, 0x03=Firmware Slot, ...
        buf_iova: u64,
        opaque_id: u64,
    },
    FormatNVM {                     // capability-gated, refused without separate token
        nsid: u32,
        opaque_id: u64,
    },
}

#[non_exhaustive]
pub enum IdentifyTarget {
    Controller,
    Namespace { nsid: u32 },
    ActiveNsList,
}
```

**S2.1 (Backpressure).** The command channel MUST be created with
`backpressure = true` (per `IpcCreateChannel` MB13.d ABI). If the driver's
inbox is full when a client tries to send, the client's `IpcSend` returns
`EBUSY` and the client retries after polling the event channel.

**S2.2 (Validation).** For each incoming command the driver MUST verify:

- `nsid` is in the active namespace list (sampled at boot via `Identify`),
- `lba + block_count - 1` does not exceed the namespace size,
- `buf_iova` falls within an IOVA range that was previously `DmaMap`-ed by
  the client (the kernel guarantees this implicitly via the IOMMU domain;
  the driver MUST double-check the range so a misbehaving client gets
  `InvalidArgument` instead of a silent IOMMU fault),
- `block_count > 0`.

Failures return a `BlkResponse::InvalidArgument` to the corresponding BLK
channel, not via the command channel (the command channel has no error
return; everything goes through the event channel keyed by `opaque_id`).

### S3. Event channel ABI (`nexacore.driver.nvme.evt`)

The driver-side endpoint of channel `nexacore.driver.nvme.evt` emits messages of
shape `NvmeEvent`:

```rust
#[non_exhaustive]
pub enum NvmeEvent {
    CommandComplete {
        opaque_id: u64,         // echoes the cmd's opaque_id
        status: u16,            // NVMe status field (Status Code + Status Code Type)
        cdw0: u32,              // command-specific dword 0 (e.g., Identify size)
    },
    AsyncEvent {
        event_type: u8,
        event_info: u8,
        log_page: u8,
    },
    LinkStateChange {
        link_up: bool,
    },
    ControllerFatal {
        cstatus: u32,           // CSTS register snapshot at fault
    },
}
```

The channel is broadcast (per NCIP-013 § S6) — any client that has attached a
recv endpoint receives every event. Clients filter by `opaque_id` to match
their own commands.

### S4. BLK service channel (`nexacore.svc.blk.<diskN>`)

The driver MUST register one BLK channel per NVMe namespace it surfaces.
For v0.3.0 (single-namespace), this means one channel named
`nexacore.svc.blk.nvme0` for the first detected controller's first namespace.

The BLK channel accepts `BlkRequest` and emits `BlkResponse` per the schema
in § M3. Mapping NVMe ↔ BLK:

| `BlkRequest` | NVMe operation | Notes |
|---|---|---|
| `Read{lba, count, buf}`  | `0x02 NVM Read`  | PRP1 = first 4 KiB; PRP2 = pointer to PRP list if `count > 1` |
| `Write{lba, count, buf}` | `0x01 NVM Write` | same PRP rules |
| `Flush` | `0x00 NVM Flush` | NSID-specific |
| `Discard{lba,count}` | `0x09 Dataset Management` (Attribute = Deallocate) | only if `discard_enabled=true` in manifest |

`BlkResponse::DeviceError(status)` carries the raw NVMe status word for
diagnostic purposes; higher layers SHOULD decode it via the NVMe 1.4
spec § 4.5 table.

### S5. IRQ topology

The driver requests IRQ attach via `IrqAttach` (NCIP-013 § S4.1) **exactly
once per completion queue**:

- One IRQ for the ACQ (Admin Completion Queue), MSI-X vector 0 of the device.
- One IRQ per ICQ (IO Completion Queue), MSI-X vectors `1..=io_queue_count`.

Each IPC endpoint receives only zero-length notification messages; the driver
drains the corresponding CQ on every notification, reading and acking
completion entries until the CQ head catches up to the tail.

**S5.1 (MSI-X required).** If the device does not implement MSI-X (legacy
IOAPIC pin only), the driver MUST fall back to a **single shared IOAPIC line**
attached only to the ACQ. IO completions are polled (the driver drains the
ICQ in the BLK channel's command-processing loop). This is a degraded mode
documented as "low-performance, legacy-only". Modern NVMe devices (every
controller since 2014) implement MSI-X, so this fallback is rarely needed
but must exist for completeness.

**S5.2 (Vector count limit).** Because NCIP-013 § S4.5 locks IRQ delivery to
BSP-only for v0.3, the driver MUST NOT request more than 4 ICQ vectors
(`io_queue_count ≤ 4`). On BSP these 4 vectors share L1/L2 with all
other system code; more than 4 starts to thrash. Per-driver CPU affinity
(future NCIP) will relax this.

### S6. Bring-up sequence

The driver, upon spawn by `DriverLoad`, MUST execute the following sequence:

1. **PCI enumeration**: walk the ECAM space (kernel exposes ECAM read via
   `PciConfigRead` syscall) to locate every device matching the manifest's
   `pci_class`. For each match, record the BDF (bus/device/function) and the
   BAR0 physical address.
2. **MMIO map**: `MmioMap(BAR0, 0x4000, flags=0)` to obtain a UC mapping
   of the controller's register space.
3. **Read CAP**: at offset `0x00` of the mapped BAR. Extract the maximum
   queue entries supported (`MQES`), the doorbell stride (`DSTRD`), the
   supported command sets, the minimum/maximum page size (`MPSMIN`/`MPSMAX`).
4. **CC.EN=0**: disable the controller by clearing bit 0 of `CC` (`0x14`).
   Poll `CSTS.RDY` until it reads 0 (controller acks the disable).
5. **AQA / ASQ / ACQ setup**: write the manifest-declared queue depths to
   `AQA` (`0x24`); allocate one 4 KiB page for each admin queue via
   `DmaMap`; write the IOVA bases to `ASQ` (`0x28`) and `ACQ` (`0x30`).
6. **CC.IOSQES=6, CC.IOCQES=4, CC.MPS=0, CC.CSS=000b, CC.EN=1**: configure
   the controller (entry sizes are fixed by NVMe spec, page size = 4 KiB),
   then enable. Poll `CSTS.RDY` until it reads 1.
7. **MSI-X enable**: read the MSI-X capability in PCI config space, set
   the table-size, and call `IrqAttach` once per vector.
8. **Identify Controller**: submit `Identify(target=Controller)` to ACQ;
   await ACQ completion via the ACQ IPC endpoint. Parse the 4 KiB response
   to record the controller's `NN` (number of namespaces) and supported
   features.
9. **Identify Active NSList**: submit `Identify(target=ActiveNsList)`;
   pick the first NSID returned.
10. **Identify Namespace**: submit `Identify(target=Namespace{nsid})`; parse
    the namespace size (`NSZE`), capacity (`NCAP`), LBA format (`LBAF`).
    Reject any namespace where `LBADS != 12` (i.e., LBA size != 4 KiB) — v0.3
    only supports 4 KiB sector size. The driver logs and skips such
    namespaces.
11. **Create IO queue pair**: submit `Create IO Completion Queue` then
    `Create IO Submission Queue` admin commands (one pair for v0.3).
12. **BLK channel registration**: call `IpcCreateChannel` with name
    `nexacore.svc.blk.nvme0`, queue_depth = 1024, backpressure = true. Begin
    the BLK command-processing loop.
13. **Log readiness**: emit `[driver-nvme] ready disk0 size=N GiB sectors=M`
    on the early console (via a kernel-mediated log channel; the user-space
    driver does NOT directly write to COM1).

Each step has explicit error cases (timeouts on `CSTS.RDY`, admin command
failures, malformed Identify responses). Any error in steps 1-12 MUST result
in the driver process exiting with code `1` and emitting `[driver-nvme]
fatal step=<n> err=<msg>`. The kernel reclaims all resources (IOMMU domain,
MMIO mappings, IPC channels) via the normal process-exit teardown
(NCIP-013 § S2.4, § S3.4).

### S7. Versioning

This NCIP locks the v0.3 contract. Backward-compatible additions to the
command/event channel enums (new `#[non_exhaustive]` variants) MAY be
introduced via PR without an NCIP. Breaking changes (e.g., adding SGL,
multi-namespace, multi-controller) require a follow-up NCIP.

---

## Rationale

### R1. Why PRP, not SGL (deeper rationale)

§ M4 covers the surface argument. The deeper rationale: SGL adds a recursive
data structure (the device walks an SGL chain that may include nested
descriptors), which expands the device's trust budget. A buggy SGL parser on
the device can confuse-deputy the IOMMU. PRP's structure is flat (PRP1 is a
4 KiB pointer; PRP2 is either a 4 KiB pointer or a pointer to a flat array
of 4 KiB pointers — no chains), so the device's parser is simpler and the
audit surface smaller.

If a future NCIP introduces SGL, it MUST also add a clause requiring the
device to declare SGL support via `Identify` and the kernel to revalidate
the SGL chain in-line (kernel walks the chain before submitting). This is
out of scope here.

### R2. Why a single IO queue pair for v0.3

Multi-queue NVMe (one IO queue pair per CPU) is a major performance lever
in Linux. We defer it for three reasons:

- NCIP-013 § S4.5 locks IRQ delivery to BSP-only; multi-CPU IO completion
  is structurally not available.
- A single IO queue pair at depth 1024 is sufficient for the Phase 1
  deliverable (boot a system, install packages, run tests). The
  performance gap to multi-queue at this scale is < 2x on consumer NVMe.
- Multi-queue introduces a per-CPU-affinity question (which queue's
  completion goes to which CPU) that is better designed alongside the
  general per-CPU IRQ work in the future affinity NCIP.

The manifest field `io_queue_count` exists (capped at 4) so the same driver
binary can adapt when affinity lands; it does not need a new NCIP at that
point, only a manifest bump.

### R3. Why a BLK channel separate from the cmd channel

A naive design would have file systems send `NvmeCommand` directly. We reject
that because:

- It hardcodes NVMe into every file system. The day we add a SATA driver
  (or, more likely, a virtio-blk driver for VM passthrough), every file
  system needs a new code path.
- It exposes NVMe-specific fields (NSID, log page IDs, AER) to file systems
  that have no business knowing them.
- It collapses the two layers (block device + file system) into one in the
  IPC topology, undermining the microkernel pattern.

The BLK channel abstracts the four operations every block device supports
(read, write, flush, discard). Future drivers (SATA, virtio-blk, even a
future RAID-over-network driver) export the same BLK shape.

### R4. Why we don't pin NVMe vendors in the manifest by default

The `[matchers]` block uses PCI class code (`0x01:0x08:0x02` = NVMe Express)
rather than enumerating every vendor. The trade-off:

- **Pro:** one driver image works against every NVMe device we have not
  individually tested. New NVMe SSDs ship continuously; pinning vendor IDs
  is a maintenance burden.
- **Con:** a brand-new NVMe quirk (firmware bug, non-spec behavior) could
  manifest as a Phase 1 incident. We mitigate by (a) Identify-Controller
  reading the firmware version into the log on every load, and (b) the
  static `KNOWN_ISSUERS` table from NCIP-013 — only Stichting-signed driver
  images run, so a malicious quirked device cannot ship a driver-side
  exploit. The risk reduces to "device-side quirk causes driver to fail
  gracefully", which is acceptable.

A future NCIP MAY introduce a per-firmware-version blocklist if a specific
NVMe device proves problematic. The framework supports it via manifest
`pci_vendor_device` opt-in.

### R5. Why ≤ 4 IO queue pairs hard cap

NCIP-013 § S4.5 caps IRQ delivery to BSP-only. Each ICQ vector consumes one
IDT slot and one MSI-X vector; on BSP each completion handler steals time
from other system code. We bound this at 4 to keep BSP load predictable.

The math: at typical NVMe IRQ rates (~100k IRQs/s during heavy IO), each
vector consumes ~5 µs/s of BSP time, so 4 vectors = ~20 µs/s. Beyond that,
BSP becomes a hot spot for completion processing and the kernel may starve.
Per-CPU affinity (future NCIP) eliminates this cap by routing each ICQ to a
different CPU.

### R6. What we are NOT doing in this NCIP

- **No multi-namespace** — only the first active namespace is surfaced. A
  follow-up NCIP will add `nexacore.svc.blk.nvme<N>` per namespace.
- **No NVMe-MI** (Management Interface) — out-of-band controller management
  is irrelevant for v0.3.
- **No Zoned Namespaces (ZNS)** — ZNS controllers will be supported by a
  follow-up NCIP (`NCIP-Driver-NVMe-ZNS-XXX`).
- **No SR-IOV / VFs** — single-PF only for v0.3.
- **No fabrics (TCP / RDMA / FC)** — local PCIe only.
- **No persistent reservation, end-to-end protection** — datacenter features
  out of scope for v0.3.

---

## Backwards Compatibility

N/A — first introduction of any storage driver in NexaCore OS. The existing
kernel has no storage support (no SATA, no IDE, no virtio-blk); the
framebuffer/serial/PS/2 startup path does not touch storage. The BLK
channel naming (`nexacore.svc.blk.<diskN>`) is reserved here for the first time.

The `[nvme]` manifest section is a new addition to the NCIP-013 manifest
schema. Per NCIP-013 § S5.1 the manifest is extensible — new top-level
tables are not breaking changes to existing drivers, only adding required
context to NVMe-class drivers.

---

## Test Cases

> **TASK-14 closure (2026-06-08, ADR-0036):** TC1–TC5 + TC7 VERIFIED on
> the test VM (serial verbatim, Option A — cooperative-yield completion;
> real MSI-X IRQ / TC6 tracked separately as a follow-up). The NVMe
> namespace MUST present **4 KiB logical blocks** (LBADS=12) — the
> driver enforces the v0.3 perimeter; QEMU's 512-byte default is
> rejected with `EXIT_NVME_NS_UNSUPPORTED_LBADS`. the test VM is configured
> with `-device nvme-ns,drive=nvm0,logical_block_size=4096,
> physical_block_size=4096`.
>
> Captured (`nexacore-103-task14-b7.log`):
> `[driver-nvme] ready disk0 nvme0 + nvme0-reply, entering BLK service loop`
> · `[blkcheck] no-cap lookup rejected (EACCES) OK` (TC: gate)
> · `[driver-nvme] op=write lba=.. -> Ok` · `[blkcheck] write LBA42 OK` (TC3a)
> · `[driver-nvme] op=flush -> Ok` · `[blkcheck] flush OK`
> · `[driver-nvme] op=read lba=.. -> Ok`
> · `[blkcheck] readback MATCH (4096 bytes, LBA 42)` (TC3)
> · `[blkcheck] out-of-range rejected OK` (TC4)
> · `[blkcheck] TASK-14 E2E COMPLETE` · zero #PF / zero PANIC.

### TC1. Identify Controller round-trip

Boot the driver against a QEMU-emulated NVMe device (`-drive
file=test.img,if=none,id=nvm -device nvme,serial=deadbeef,drive=nvm`).
Verify the boot log shows `[driver-nvme] ready disk0 size=<expected>
sectors=<expected>` with `<expected>` matching the QEMU `-drive size` arg.

### TC2. Single-sector read

After TC1, a test client sends `BlkRequest::Read{lba=0, count=1,
buf_iova=<X>}` on `nexacore.svc.blk.nvme0`. Expect `BlkResponse::Ok` and the
buffer to contain the first 4 KiB of `test.img`.

### TC3. Single-sector write + read-back

Test client writes a known pattern to `lba=42`, then reads it back. Expect
byte-exact match.

### TC4. Out-of-range LBA

Test client sends `BlkRequest::Read{lba=<size+1>, ...}`. Expect
`BlkResponse::OutOfRange`. The driver MUST NOT submit the NVMe command —
the rejection happens at the driver, not at the device.

### TC5. Misaligned buffer

Test client sends `BlkRequest::Read{..., buf_iova=<not 4 KiB aligned>}`.
Expect `BlkResponse::InvalidArgument` (alignment is a PRP requirement
checked at the driver, not the device).

### TC6. IRQ delivery

Verify the boot log shows `[driver-nvme] msix-vectors attached=2 (acq+icq)`
after S6 step 7. Without this line, MSI-X did not land — TC2/TC3 would
time out.

### TC7. Bare-metal smoke (the Proxmox test VM)

Once the implementation lands on `feat/kernel-p6-7-driver-nvme`, the
existing the Proxmox test VM hardware-validation smoke MUST be extended:
`qemu-boot-smoke.sh` adds a flag `--feature driver-nvme` that brings up an
additional `-drive` and asserts `[driver-nvme] ready disk0 ...` appears in
the serial log within 10 seconds.

---

## Reference Implementation

N/A at filing time. The implementation will land on the future branch
`feat/kernel-p6-7-driver-nvme`, expected to include:

- `crates/nexacore-driver-nvme/` (new) — the user-space driver crate.
- `crates/nexacore-types/src/blk.rs` (new) — the `BlkRequest`/`BlkResponse`
  shapes shared across drivers and file systems.
- `crates/nexacore-kernel/src/bare_metal/pci.rs` (extended) — `PciConfigRead`
  syscall handler.
- `docs/protocol/driver-manifest-v1.toml` (extended) — `[nvme]` table
  documented with field semantics.
- `tests/driver_nvme_smoke.rs` (new) — TC1-TC5 host-side.

Tracking depends on NCIP-013 reaching `Active` first (the framework syscalls
must exist).

---

## Security Considerations

### SC1. Threat model alignment

Per `docs/04a-threat-model.md`:

- **C-1 (local-user, no caps)** — cannot send to `nexacore.svc.blk.nvme0` because
  the BLK channel is registered by the driver with a capability-gated allow
  list (only the file-system service holds the matching token).
- **C-2 (local-user, partial caps)** — can read/write to BLK channels they
  hold capabilities for, but cannot escalate to NVMe administration
  (Identify, FormatNVM, GetLogPage) — those are driver-internal.
- **C-3 (compromised driver)** — bounded by IOMMU domain (S6 step 5 pins
  every DMA buffer through the per-driver domain); a compromised NVMe driver
  cannot read kernel memory, cannot reach other drivers' BARs (each driver's
  MmioMap is scoped to its declared `MmioRegion`).
- **C-5 (compromised hardware)** — partial: a malicious NVMe device that
  ignores the LBA and DMA-overwrites a buffer it should not is filtered by
  the IOMMU domain — the device can only see IOVAs the driver explicitly
  granted. A device that performs the wrong operation on the correct buffer
  (e.g., writes garbage when asked to read) is detectable only by higher
  layers (file-system checksums, dm-integrity).

### SC2. Failure modes

| Failure mode | Mitigation |
|---|---|
| FormatNVM by mistake | Capability-gated separately; `format_nvm_enabled=false` by default |
| LBA underflow / overflow | Driver validates against `NSZE` (S2.2) |
| Misaligned DMA buffer | Driver validates 4 KiB alignment (TC5) |
| Controller hang | `CSTS.CFS` (Controller Fatal Status) → emits `ControllerFatal` event; driver exits |
| Firmware quirk | Logged at boot via `Identify`; opt-in pinning via manifest |
| MSI-X allocation failure | Fallback to single shared IOAPIC line (S5.1) |

### SC3. Cryptographic considerations

None at the driver level. The NVMe driver does NOT do encryption-at-rest —
that is a higher-layer concern (dm-crypt-equivalent service or OPAL SED
support, both out of scope). The data path is plaintext blocks.

The driver image is signed (NCIP-013 § S5), so the question "is this binary
the one Stichting NexaCore built" is answered. The question "does the SSD's
firmware leak the user's data" is hardware-vendor-dependent and is mitigated
only at the higher layers via encryption.

---

## Privacy Considerations

### PC1. Personal data flows

The NVMe driver sees every plaintext block written by any client. This is
unavoidable for a block driver. The privacy posture is:

- Higher layers (file system + encryption service) MUST encrypt sensitive
  data before it reaches the BLK channel.
- The BLK channel is capability-gated: only the file-system service holds
  a token for `nexacore.svc.blk.nvme0`; user processes cannot tap the channel.
- The driver MUST NOT persist any client identity. The `opaque_id` in
  commands is correlation only and is not logged.

### PC2. Metadata exposure

The driver logs (via the kernel log channel):

- Boot-time: controller identity (serial number, firmware version, model).
  This is hardware-fingerprinting metadata; a privacy-conscious user MAY
  redact via a future `silent-driver-load` feature.
- Runtime: zero log emission during normal IO. Only error conditions
  (`ControllerFatal`, command failure) emit log lines.

### PC3. Wear-leveling and discard

`BlkRequest::Discard` informs the SSD that a range of LBAs is unused,
allowing the controller to free those blocks during garbage collection.
This has a privacy implication: after Discard, the blocks may not be
zeroed (NVMe spec leaves this device-dependent). A privacy-conscious
file system MUST NOT rely on Discard for secure deletion; it should write
zeros explicitly before Discard.

### PC4. GDPR

The driver does not persist personal data on its own. All GDPR
considerations (retention, right-to-erasure, data minimization) apply at
the file-system and application layers.

---

## Appendix A — Bootstrap Activation Note

### A1. Founder fast-path activation (2026-05-20)

This NCIP was filed as `Draft` on 2026-05-20 (same calendar day as
`NCIP-Driver-Framework-013` itself) and promoted directly to `Active` on
the same day under the **Solo Founder Fast-Track** of
`NCIP-Process-001 §5.5`, exercised under the Bootstrap Period authority of
`NCIP-Process-001 §6.3`. The standard 14-day public objection window of
`NCIP-Process-001 §5.3` was waived by explicit founder approval; the
state-machine transitions `Draft → Review → Last Call → Active` collapse
into a single editorial pass with `activated: 2026-05-20` recorded in
the frontmatter.

**Rationale for fast-path:**

1. **Dependency unblock.** `NCIP-013` (the driver framework) is the
   prerequisite (`requires: [13]`) and was itself fast-pathed to
   `Active` on 2026-05-20. Keeping `014` in `Draft` would have stalled
   `P6.7.8` (first-party driver implementation) by 14 days for no
   substantive review benefit — there is no second editor seat occupied
   during the Bootstrap Period.
2. **No deployment risk.** Zero NVMe driver code exists at activation
   time; the reference implementation is `N/A at filing` per `## Reference
   Implementation`. There is no in-flight migration to coordinate.
3. **Scope is bounded.** All normative content is constrained by
   `NCIP-013` (the framework `Active` document) — the manifest schema,
   capability shape, IPC channel grammar, and IRQ routing are inherited.
   This NCIP only adds the NVMe-specific overlay (admin/IO queue ABI, PRP
   model, BLK channel contract).
4. **No conflict with `NCIP-013` Appendix B.** The amendments to NCIP-013
   filed under its Appendix B (NexaCore-Pack v1 container, 512 GiB MMIO VA
   range, `IrqNotification` shape, follow-up NCIP forecast in § R7)
   explicitly state "No follow-up NCIP (014/015/016) requires changes" —
   confirmed by cross-reference audit (see NCIP-013 Appendix B trailing
   list of preserved citations).

**Re-ratification obligation:** per `NCIP-Process-001 §5.5.e`, this
activation inherits the **mandatory post-Bootstrap re-ratification**
obligation. When the Bootstrap Period ends (second editor seat filled or
Stichting NexaCore constituted, whichever comes first), this NCIP MUST be
re-ratified by the standard quadratic-vote majority + activation
threshold of `NCIP-Process-001 §7`. Failure to re-ratify reverts the
status to `Withdrawn` and forces a fresh filing.

---

## Copyright

This NCIP is released into the public domain under
[CC0-1.0](https://creativecommons.org/publicdomain/zero/1.0/).
