# ADR-0036: NVMe BLK Service Loop, MSI-X Delivery, and Capability-Gated Attach (TASK-14)

**Status:** Accepted
**Date:** 2026-06-07
**Deciders:** agent analysis under operator-approved PLAN.md TASK-14
**Refs:** PLAN.md TASK-14 (DE-B1+DE-B2), NCIP-Driver-NVMe-014 v0.3 (§S4–S6,
TC1–TC7), NCIP-013 (driver framework), NCIP-026 WI-3/WI-6 (issuers),
ADR-0024 (M0 datapath: boot-spawn + deposit), ADR-0035 (clobber lesson)

## Context

TASK-14 closes the Ring 3 NVMe IPC loop: a client sends `BlkRequest` on
`nexacore.svc.blk.nvme0`, the driver drives the IO queue, completes via IRQ,
and replies `BlkResponse`; sector access must be capability-gated.

Recon (agent team, file:line evidence) established that MOST of the
machinery exists: the `nexacore-driver-nvme` library is complete (bring-up
FSM, Read/Write/Flush/Identify/Discard encoders, `AdminQueuePair`
submit/drain, PRP derivation, `blk_gateway` BlkRequest→SQE bridge,
`BlkChannelHandler` validation — 464 tests); the kernel has
`BlkChannelRegistry` + `BlkRegister(76)`/`BlkLookup(78)` + `irq_table` +
`IrqAttach(72)`; the image already performs the full 22-step bring-up
INCLUDING live LBA-0 IO and BLK channel registration — then exits.
the test VM already carries a QEMU NVMe controller (`NexaCore-NVME0`, 1 GiB raw
backing) used by the in-kernel diagnostics probe.

Gaps found:

1. **No interrupt is ever delivered**: `IrqAttach` allocates a LAPIC
   vector and installs the IDT trampoline, but NOTHING programs the
   device's MSI-X table — QEMU's NVMe asserts MSI-X (exclusive BAR per
   QEMU's `msix_init_exclusive_bar`), so without table programming the
   completion IRQ never fires. The image also passes a PLACEHOLDER
   channel id to `IrqAttach`.
2. **No reply path**: the registry holds ONE channel per disk; with the
   blind-pop IPC receive (no kind/receiver filtering — TASK-13 lesson),
   request and reply cannot share a queue safely.
3. **No data transport**: `BlkRequest::{Read,Write}` carry `buf_iova`,
   but no client↔driver shared memory exists yet (M2 scope), and the
   IPC envelope is bounded at 4096 B — a 4 KiB sector plus headers does
   not fit in one message.
4. **No capability gate on attach**: `BlkLookup(78)` resolves a name to
   a `ChannelId` for ANY caller.
5. The image's `syscall5` stub regressed to the reduced-clobber pattern
   (the exact systemic bug fixed in ADR-0035 across five other images).

## Decisions

### D1 — Boot-spawn + capability deposit (no DriverLoad churn)

The NVMe driver image is packed into the initramfs and spawned from
`kmain` exactly like the virtio-net driver (ADR-0024 pattern): the
kernel locates the NVMe function during the PCI scan, deposits
attenuated `MmioMap`/`DmaMap`/`IrqAttach` tokens (per-boot issuer,
NCIP-026 WI-6) and spawns `/bin/nexacore-driver-nvme` at `System` priority.
`DriverLoad(73)` migration stays deferred to M2 (per ADR-0024).

### D2 — Reply channel: second registry slot `nvme0-reply`

The driver creates TWO channels and registers BOTH in the BLK registry:
`nvme0` (requests, driver receives) and `nvme0-reply` (replies, client
receives). This mirrors the proven `ai`/`ai_reply` rendezvous, costs no
new kernel machinery (the slot alphabet `[A-Za-z0-9_-]` admits the
name), and eliminates request/reply queue contention by construction.
Multi-client reply routing is NOT a TASK-14 concern: M2's filesystem is
the single production client (same pairing).

### D3 — Inline data transport (TASK-14 perimeter)

Sector payloads travel INSIDE the IPC messages, chunked under the
4096-byte envelope bound:

```text
Write: [BlkRequest::Write{lba,count,buf_iova=0}] then count×2 chunks
       [2048 B data] on the request channel (driver bounce-buffers into
       its DMA arena, then issues NVM Write)
Read : [BlkRequest::Read{lba,count,buf_iova=0}] → driver issues NVM
       Read into its bounce buffer → [BlkResponse::Ok] then count×2
       chunks [2048 B data] on the reply channel
```

`buf_iova` is 0 on this transport (the driver's own bounce IOVA is
used; the field becomes meaningful again with M2's kernel-mediated
shared windows). Rationale: zero new wire types, zero shared-memory
machinery before M2, full byte-exactness verifiable from the CLIENT
(PLAN acceptance). The chunk framing is documented in NCIP-014 §S4 as
the v0.3 transport; per-chunk size 2048 = sector/2.

### D4 — MSI-X programming lives in the KERNEL (`IrqAttach`)

`IrqAttach(72)` already verifies the deposited capability token; the
handler now additionally extracts the PCI BDF from the token's
`Resource::PciDevice` and programs the device's MSI-X entry for the
allocated vector: walk the PCI capability list (id 0x11), map the table
BAR/offset, write entry 0 (`addr=0xFEE0_0000` BSP, `data=vector`,
unmasked), set Message-Control Enable, clear Function Mask. Kernel-side
because (a) the kernel owns PCI config space and the IRQ vector
allocation — a driver must NOT choose MSI addresses/vectors (spoofing
surface); (b) the BAR4 MSI-X table sits OUTSIDE the BAR0 window the
driver's MMIO token grants. INTx is not used (QEMU NVMe is MSI-X-first;
IOAPIC routing stays out of scope).

### D5 — Completion wait: IRQ-first with bounded drain fallback

The image creates a dedicated IRQ channel BEFORE `IrqAttach` (replacing
the placeholder) and binds the IO CQ vector to it. Per request:
submit → wait for the IRQ notification (`IpcTryReceive(irq_ch)` +
`TaskYield`, bounded budget) → drain the CQ. The serial audit line
records the wait outcome (`irq=hit` vs `irq=budget-drain`), so the
hardware capture PROVES the interrupt path (TC6/PLAN "niente polling");
the bounded fallback only guarantees liveness against lost interrupts
and is loudly logged, never silent.

### D6 — Capability gate on `BlkLookup(78)` (fail-closed)

`BlkLookup` gains `args[2..3] = (cap_ptr, cap_len)`:

- caller == registered channel owner → allowed without token (the
  driver's own defence-in-depth round-trip keeps working);
- otherwise the caller MUST present a postcard `CapabilityToken` with
  `KernelAction::IpcSend` whose signature verifies against the PER-BOOT
  kernel capability issuer (`is_kernel_cap_issuer`, NCIP-026 WI-6 — NOT
  the static manifest allowlist) and whose validity window covers now;
- missing/malformed/foreign-issuer token → `EACCES` (fail-closed).

The smoke client receives its token via the SAME deposit-window
mechanism drivers use (`cap_deposit` at spawn, action tag `IpcSend`).
This reuses the existing verify path end-to-end; finer-grained
per-channel resources can attenuate later without ABI changes.

### D7 — `nexacore-blkcheck-image`: the TASK-14 smoke client

New Ring 3 client image (full-clobber stubs from day one — ADR-0035
lesson): ① negative: `BlkLookup` WITHOUT token → expect `EACCES`
(PLAN negative criterion); ② lookup with deposited token → channel
pair; ③ `Write` LBA 42 with a seeded 4096-byte pattern (inline
chunks); ④ `Flush`; ⑤ `Read` LBA 42 back; ⑥ byte-compare, print
`[blkcheck] readback MATCH` + the audit trail. Spawned at `Background`
priority after the NVMe driver.

### D8 — Fix the image's `syscall5` clobber defect

`nexacore-driver-nvme-image`'s `syscall5` declares `in(...)` argument
registers (reduced clobbers) — the exact ADR-0035 systemic bug. Fixed
to the full-clobber form before any new code lands on it. (Audited
`nexacore-driver-e1000e-image` too: only its noreturn `TASK_EXIT` stub is
minimal — unaffected.)

## Alternatives considered

- **Driver-side MSI-X programming** — rejected: needs PCI config write
  + BAR4 mapping grants the driver should not hold; lets a driver point
  MSI at arbitrary addresses/vectors.
- **Single shared channel with kind-filtering** — rejected: IPC receive
  is a blind pop (TASK-13); filtering at every consumer reintroduces
  the exact failure class just fixed.
- **Kernel-mediated shared DMA window now** — rejected: that is M2
  machinery (mount path); inline chunking proves byte-exact E2E today
  with zero new attack surface.
- **New `BlkAttach` syscall** — rejected: extending `BlkLookup`'s
  unused args keeps the syscall table stable (numbers are ABI).

## Consequences

- NCIP-014 §S4 gains the v0.3 inline-chunk transport note; TC1–TC7
  become closable on the test VM.
- `IrqAttach` becomes device-aware (BDF from token resource) — the same
  path will serve e1000e/xhci MSI-X later (TASK-26).
- The blkcheck deposit gives the FIRST non-driver task a capability via
  the deposit window — the pattern M2's filesystem service will reuse.
- The in-kernel NVMe diagnostics probe must stop disabling the
  controller at boot (it resets CC) — bring-up ownership moves wholly
  to the Ring 3 driver; the probe becomes read-only.


## Status appendix — foundation landed, hardware loop deferred (2026-06-07)

This iteration landed the host-verifiable, build-green FOUNDATION and
STOPPED before the hardware smoke, on a deliberate scope judgment
surfaced to the operator (see below). What landed:

- **`syscall5` clobber fix** in `nexacore-driver-nvme-image` — the exact
  ADR-0035 reduced-clobber defect (it had regressed); all argument
  registers now declared clobbered.
- **`IrqAttach` IRQ-routing fix** — the handler populated the
  `allocate_vector` slot table but NEVER called
  `irq_table::global_bind`, so a fired interrupt resolved to "spurious"
  and never reached the driver's channel. Now bound. (This gap meant NO
  IrqAttach had ever delivered an interrupt.)
- **`bare_metal::msix` module + `arch::pci_cfg_write32`** — the
  kernel-side MSI-X programming mechanism (boot-time table mapping
  registration + attach-time entry write + capability enable, PCI cap
  walk). Correct, build-green; the boot-time `register` call site is the
  remaining wiring (the module is dormant until a device registers).
- **`BlkLookup(78)` capability gate (D6)** — fail-closed: owner without
  token allowed; any other caller needs a valid per-boot-issuer
  `IpcSend` token, else `EACCES`. Closes the DE-B2 "client senza
  capability → attach rifiutato" criterion in code.
- **`nexacore-blkcheck-image`** — the TASK-14 smoke client (built,
  full-clobber stubs, staged in the workspace exclude list).

**Architectural finding surfaced to the operator:** NO device in the OS
has ever delivered an interrupt to Ring 3 — virtio-net and e1000e both
poll; MSI-X table programming did not exist anywhere before this module.
The PLAN's "IRQ path attivo (niente polling)" therefore requires
first-ever-in-OS MSI-X interrupt delivery, which — combined with a new
boot-spawned driver, a 2-channel block rendezvous, and inline sector
chunking — is a hardware-debug campaign, not a single autonomous pass.

**Decision requested:** split TASK-14 into (A) the service loop +
gating + byte-identical sector RW with COOPERATIVE-YIELD completion
(tractable now, CPU yielded between CQ drains — not busy-spin) and
(B) real MSI-X interrupt delivery ("niente polling", the hard part), or
commit to the full (A+B) hardware campaign in one go. The foundation
above de-risks either path.

## Status appendix 2 — Option A landed to the HW-blocker (2026-06-07)

Operator chose **Option A** (service loop + gating + byte-identical RW with
cooperative-yield completion; real MSI-X IRQ tracked separately). The full
Option-A stack was implemented and is host-green; three the test VM smoke boots
drove out two image bugs (both fixed) and root-caused a third — a genuine
DMA-addressing flaw in the NVMe image that needs a dedicated rework.

**Implemented + host-verified (workspace 4280/0, kernel bare-metal 1077/0,
fmt/clippy host+bare-metal clean):**

- **Kernel boot-spawn** of `/bin/nexacore-driver-nvme` (System) + `/bin/nexacore-blkcheck`
  (Background) in `kmain`, mirroring the virtio-net deposit path (ADR-0024).
- **Kernel `cap_deposit` IpcSend token** (`ACTION_TAG_IPC_SEND = 6`,
  `Resource::IpcChannel`, `DriverCapabilities::ipc_send_channels`) so a
  NON-driver task (blkcheck / future FS) gets a token to pass the gate.
- **`BlkLookup(78)` capability gate** (D6, fail-closed) — landed in the
  prior commit, exercised by blkcheck's negative test.
- **NVMe in-kernel probe made READ-ONLY** — bring-up ownership moved
  wholly to the Ring 3 driver (no double disable/enable).
- **NVMe image: service-loop rewrite** (cooperative-yield `drain_io`,
  `nvme0` + `nvme0-reply` channels, inline 2×2048 B sector chunking,
  IrqAttach removed) + **live-BAR fix** (reads BAR0 phys from the deposit
  device-info section instead of hardcoding `0xFEBF_0000`).
- **`nexacore-blkcheck-image`** smoke client.

**HW boots (serial captures):**

1. Boot 1 — `MmioMap` EACCES (exit 53): image hardcoded BAR0 `0xFEBF_0000`
   but the live PCIe BAR is `0x3840_0000_4000` (64-bit BAR placed high on
   `pcie.0`). **Fixed:** kernel deposits the live BAR in the device-info
   section; image maps `device_info::read().bar_phys`.
2. Boot 2 — `DmaMap` EINVAL (exit 82): image mapped `iova = 0x0`, but the
   handler requires `iova >= DRIVER_DMA_VA_BASE (0x100_0000_0000)`.
   **Fixed:** rebased all 8 DMA regions onto the driver-DMA window.
3. Boot 3 — `DmaMap` ENOSPC (exit 88): one 8-page map needs 8
   *strictly-contiguous* frames (kernel enforces contiguity for the
   device's no-IOMMU view), unavailable that late in boot.

**ROOT CAUSE (the real blocker, surfaced to the operator):** the NVMe
image's DMA addressing is wrong for real hardware. The kernel `DmaMap`
contract (verified in `syscall_entry.rs` ~1582–1626 + the virtio-net image
~1007) is a **dual-address** model:

- `DmaMap` returns the allocated **physical** base in `rax`;
- under TE-off **passthrough** the device DMAs to that **phys**, not to the
  iova (the SLPT iova→phys tree is inert until the operator-gated TE flip);
- the driver must program the controller (ASQ/ACQ base registers, Create-IO-
  Queue PRPs, Read/Write/Identify PRP1) with the **returned phys**, and use
  the **iova** (high VA) only as its CPU pointer.

The NVMe image instead programs the controller with the **iova**
(`0x100_0000_…`, no RAM there under passthrough) — so even past the MMIO/DMA
syscall checks, the controller's DMA would never reach the buffers. (The
image was evidently only host-unit-tested, never HW-verified for live
controller DMA.) virtio-net gets this right by keeping `dma_va` (CPU) and
`dma_phys` (device) separately.

**Remaining work (a focused follow-up, NOT one-pass-in-loop):** rework the
NVMe DMA to the dual-address model — map each region as a separate 1-page
`DmaMap` (dodging the contiguity limit), capture each returned phys, program
the controller with phys and access rings/buffers via the iova. This very
likely needs the `nexacore-driver-nvme` queue/PRP API to thread device-phys
separately from the CPU-iova (the `AdminQueuePair`/`IoSession` abstractions
currently take a single address per queue). That API change + the image
rewiring is a dedicated session; the kernel side (above) is complete and
de-risks it. TASK-14 stays `[~]`.


## Status appendix 3 — TASK-14 CLOSED (2026-06-08)

The dual-address DMA rework landed and TASK-14 is **complete and
hardware-verified** on the test VM. Boots 4–7 drove out the remaining issues:

- **Boot 4** — dual-address DMA fix worked (per-region 1-page `DmaMap`,
  controller programmed with the `DmaMap`-returned PHYS, CPU access via
  the iova). Past all DMA errors into real controller operation;
  `EXIT_NVME_IDENTIFY_TIMEOUT`.
- **Boots 5–6 root cause** — the admin bring-up busy-polled the CQ with
  NO `task_yield`; under QEMU's single-vCPU model the NVMe device-
  emulation thread cannot process the SQ while the vCPU busy-spins (no
  VM-exit) → intermittent completion timeout. **Fixed:** the 5 admin
  bring-up poll loops now yield each iteration (cooperative, like the IO
  service loop). All admin commands (Identify Controller / NS-List /
  Identify Namespace / Create IO CQ+SQ) then complete reliably.
- **Boot 7 — root cause + fix** — `EXIT_NVME_NS_UNSUPPORTED_LBADS`: QEMU's
  NVMe default is 512-byte blocks (LBADS=9) but the driver enforces the
  NCIP-014 v0.3 perimeter (4 KiB blocks, LBADS=12). **Fixed (config):**
  the test VM reconfigured to present a 4 KiB-block namespace
  (`-device nvme-ns,drive=nvm0,logical_block_size=4096,
  physical_block_size=4096`; args backup on the host at
  `/tmp/vm103_args_backup_task14.txt`).

**VERIFIED on the test VM** (serial verbatim, zero #PF / zero PANIC):
capability gate (`no-cap → EACCES`), `BlkLookup(cap)` for both channels,
write LBA 42 → flush → read-back **byte-identical (4096 bytes)**,
out-of-range → `OutOfRange`. Completion is cooperative-yield CQ drain
(Option A — CPU yielded between drains, not busy-spin); real MSI-X
interrupt delivery remains a tracked follow-up (the `bare_metal::msix`
mechanism + `IrqAttach` `global_bind` fix from the prior commit are the
foundation for it). DE-B1/DE-B2 closed.
