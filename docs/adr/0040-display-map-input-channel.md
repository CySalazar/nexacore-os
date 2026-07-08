# ADR-0040: Display-Map Syscall + Input-Event IPC Channel (TASK-18, DE-C1)

**Status:** Accepted
**Date:** 2026-06-08
**Deciders:** agent analysis under operator-approved PLAN.md TASK-18
**Refs:** PLAN.md TASK-18 (DE-C1, M3), NCIP-013 (Ring-3 driver framework /
capability deposit), ADR-0031/0036 (BLK service IPC), ADR-0024 (boot-spawn +
deposit), `docs/03-mesh-protocol.md` (wire conventions)

## Context

TASK-18 opens M3 (userspace display server). It must expose the MINIMAL
kernel primitives a Ring-3 compositor needs — and ONLY those; the compositor
itself is TASK-19. Two primitives:

1. **Framebuffer map**: map the GOP linear framebuffer into the compositor's
   Ring-3 address space, NX (never executable), gated by a `Display`
   capability so only an authorised task can map it.
2. **Input channel**: deliver keyboard/mouse events from the kernel to the
   compositor over an IPC channel (postcard wire type, ≤ 4096 B).

Recon (agent-team, file:line) established:

- `MmioMap (70)` (`syscall_entry.rs:1092`) is the exact template: it
  copies+verifies a capability token (per-boot kernel issuer, action +
  resource-subset check) and maps phys→user 4 KiB pages with
  `PTE_PRESENT | PTE_WRITABLE | PTE_USER | PTE_NO_EXEC | PTE_PCD | PTE_PWT`,
  allocating user VAs from the driver-MMIO window `[0x80_0000_0000,
  0x100_0000_0000)`.
- **The kernel does NOT store the framebuffer physical address** — the
  bootloader hands off only a kernel VA (post-mapped). `graphics.rs`
  `FrameBuffer` holds width/height/stride/bpp/format + a `*mut u8` VA.
- There is **no `Display` capability** — `nexacore-capability::scope` has no
  framebuffer Action/Resource.
- Kernel→Ring-3 push is `ipc::send` with `MessageKind::Notification`
  (`ipc.rs:496`); a Ring-3 task drains via `IpcTryReceive (24)`. Channel IDs
  are shared by depositing them (the BLK precedent).
- The probe-image + initramfs + boot-spawn + `nexacore-usys` wrapper patterns are
  established (nexacore-fsd/blkcheck, `nexacore-usys::{ai,net}`).
- Next free syscall number: **79** (70–78 used; 80–84 AI; 90+ FS/NET).

## Decisions

### D1 — Framebuffer phys discovered by page-table walk at boot

Because the bootloader exposes only a VA, the kernel translates the
framebuffer VA → phys ONCE at boot (active-mapper `translate_addr`) and
stores a `FramebufferInfo { phys_base, len, width, height, stride, bpp,
format }` in a kernel global. `len = height * stride * bpp` (page-rounded).
This is robust (uses the live page tables, not a bootloader-format
assumption) and gives the kernel the phys+len it must mint into the `Display`
capability and validate at map time.

### D2 — `DisplayMap (79)` syscall — MmioMap mirror with NX

A new syscall `DisplayMap = 79` mirrors `MmioMap` exactly:
- ABI: `a0 = offset` (into the framebuffer, page-aligned, default 0),
  `a1 = len` (multiple of 4 KiB, ≤ framebuffer len), `a2 = flags` (reserved,
  0), `a3 = cap_ptr`, `a4 = cap_len`. Returns `rax = user VA`, `rdx = errno`.
  (Offset+len rather than raw phys: the caller names a sub-window of THE
  framebuffer, the kernel supplies the phys base from `FramebufferInfo` — the
  caller never chooses an arbitrary phys, shrinking the trust surface vs
  MmioMap.)
- Verifies the capability token: per-boot kernel issuer, `Action::DisplayMap`,
  and `Resource::Framebuffer { phys_base, len }` whose range CONTAINS
  `[fb_phys + offset, fb_phys + offset + len)`. Missing/invalid/foreign-issuer
  token → `EACCES`. Out-of-range offset/len, misalignment → `EINVAL`, and the
  mapping is **all-or-nothing** (rollback on partial failure, like MmioMap).
- Maps with `PTE_PRESENT | PTE_WRITABLE | PTE_USER | PTE_NO_EXEC | PTE_PCD |
  PTE_PWT`. **NX is mandatory** — the framebuffer is data, never code (W^X for
  the compositor's video memory). PCD+PWT (uncached) gives the compositor's
  writes immediate scanout visibility without the PAT/write-combining setup
  Phase 1 lacks (correct, just not WC-fast — acceptable for the probe and an
  early compositor).

### D3 — `Display` capability (Action + Resource)

`nexacore-capability::scope` gains `Action::DisplayMap` and `Resource::Framebuffer
{ phys_base: u64, len: u64 }` (range-subset `is_subset_of`, like MmioRegion/
DmaWindow). `cap_deposit` gains `ACTION_TAG_DISPLAY_MAP = 7` +
`RESOURCE_TAG_FRAMEBUFFER = 7` and an encoder arm. `DriverCapabilities` gains
a `framebuffer_regions: Vec<Resource>` field (`#[serde(default)]`, empty for
all existing manifests). The kernel deposits the `Display` cap (scoped to the
real `FramebufferInfo` phys+len) into the compositor at spawn, same path as
the MMIO/DMA/IpcSend deposits.

### D4 — Input-event channel: kernel pump → Notification → Ring-3

- New wire type `nexacore-types::display_channel::DisplayInputEvent`
  (`#[non_exhaustive]` postcard enum): `Key { code: u8, pressed: bool }` and
  `Pointer { x: u32, y: u32, buttons: u8 }`. ≤ 4096 B, `no_std`-clean (serde
  only). Exported from `nexacore-types::lib`.
- At boot the kernel creates a `Notification` channel it owns, and deposits
  the channel id to the display task (an `IpcChannel` capability, the BLK
  precedent — the probe reads it from the deposit window).
- A **kernel input pump** runs in `kmain`'s tail on the display-probe path
  (gated, in place of the in-kernel desktop): it polls `input::ps2_poll()`
  (and optionally the pointer), encodes a `DisplayInputEvent`, and
  `ipc::send`s it as a `Notification` into the channel, then `task_yield`s so
  the probe runs. The probe drains via `IpcTryReceive (24)`. Pumping from a
  cooperative kmain loop (NOT the timer ISR) keeps `ipc::send`'s allocation
  off the interrupt path.

### D5 — `nexacore-usys::display` wrapper + `nexacore-display-probe` image

- `nexacore-usys::display`: thin typed wrappers — `display_map(offset, len, cap)
  -> *mut u8` over syscall 79, and an input receiver over `IpcTryReceive (24)`
  that decodes `DisplayInputEvent`.
- `nexacore-display-probe` (new workspace-excluded `no_std` image, the
  nexacore-fsd/blkcheck template): reads its deposited `Display` cap + input
  channel id, `DisplayMap`s the framebuffer, writes a visible pixel pattern
  (e.g. colour bars / a filled rectangle), then drains the input channel and
  logs received keys to the serial console. This is the VM-103 acceptance
  artifact (serial capture + annotated visual check).

### D6 — Syscall-number stability

`DisplayMap = 79` is pinned in the `syscall` number enum + its
`syscall_numbers_are_stable` test (the 24/73 pattern). The input path reuses
`IpcTryReceive (24)` — no new number for input.

## Alternatives considered

- **Pass a raw phys to DisplayMap (like MmioMap)** — rejected: the framebuffer
  is a single well-known region; letting the caller name only an offset into
  the kernel-known framebuffer (D2) removes "map arbitrary phys" from the
  display capability's power, a strictly smaller trust surface.
- **Reverse-map framebuffer phys via `physical_memory_offset` arithmetic** —
  rejected vs the page-table walk (D1): the bootloader may map the framebuffer
  at a dedicated VA outside the phys-offset window; the walk is correct
  regardless.
- **Deliver input from the timer ISR** — rejected: `ipc::send` allocates and
  takes registry locks; doing that in interrupt context is unsafe. The
  cooperative kmain pump (D4) is allocation-safe.
- **Cached (write-back) framebuffer mapping** — rejected for Phase 1: without
  explicit cache flushes the scanout could read stale RAM; uncached (PCD+PWT)
  is immediately coherent. Write-combining via PAT is a later perf ADR.
- **Reuse `Action::MmioMap` for the framebuffer** — rejected: a distinct
  `Display`/`Framebuffer` capability lets a compositor map the screen WITHOUT
  also being able to map arbitrary device MMIO. Least privilege.

## Consequences

- nexacore-capability: +1 Action, +1 Resource (both `#[non_exhaustive]` enums, so
  additive); +1 `is_subset_of` arm; tests.
- nexacore-kernel: `FramebufferInfo` global + boot-time phys walk; `DisplayMap`
  handler + dispatch + stability test; `cap_deposit` tags + encoder arm;
  `DriverCapabilities.framebuffer_regions`; the input channel + kmain pump +
  boot-spawn of the probe.
- nexacore-types: `display_channel` module. nexacore-usys: `display` module.
- New `nexacore-display-probe` image + initramfs entry; VM-103 verification.
- The compositor (TASK-19) consumes exactly these primitives; no compositor
  policy leaks into the kernel.

## Verification appendix — TASK-18 CLOSED (2026-06-08)

Implemented (foundation in-session; kernel-side + probe/usys by the
agent team) and **hardware-verified on the test VM**, zero #PF / zero PANIC.

Serial capture (`nexacore-display-probe`, boot-spawned under the kernel
`display-probe` feature):

```
[driver-loader] display-probe: depositing DisplayMap+IpcSend caps
[driver-loader] display-probe spawned  task_id=11
[display-probe] start
[display-probe] input_channel_id=0xa fb_width=0x500 fb_height=0x320 \
                fb_stride=0x500 fb_bpp=0x4 fb_len=0x3e8000
[display-probe] Display cap found, len=0xa4
[display-probe] DisplayMap OK user_va=0xbd74a9f000
[display-probe] framebuffer painted 1280x800
[display-probe] waiting for input events (channel=0xa)...
   ( qm sendkey 103 a b c d e ret esc )
[display-probe] key code=0x61 pressed=1   # 'a'
[display-probe] key code=0x62 pressed=1   # 'b'
[display-probe] key code=0x63 pressed=1   # 'c'
[display-probe] key code=0x64 pressed=1   # 'd'
[display-probe] key code=0x65 pressed=1   # 'e'
[display-probe] received 5 input events — TASK-18 OK
[display-probe] key code=0x0d pressed=1   # Enter -> keycode::ENTER
[display-probe] key code=0x1b pressed=1   # Escape -> keycode::ESCAPE
[display-probe] done
```

Visual proof: a screendump showed the probe's pattern exactly — red /
green / blue colour-thirds across the 1280×800 screen with a white
100×100 box at the top-left — confirming a Ring-3 task wrote pixels
through the `DisplayMap`ped (NX, user) framebuffer.

So all three acceptance criteria hold: (1) the Ring-3 probe maps the
framebuffer and writes a visible pattern; (2) it receives keyboard events
from the input channel (printable ASCII pass-through + Enter/Escape
keycode mapping); (3) the path is capability-gated (a `Display` cap is
deposited and verified; the probe presents it to `DisplayMap`). The
geometry the probe read (1280×800, stride 1280, 4 bpp,
`len = 0x3E8000 = 1280·800·4`) is exactly the boot framebuffer. The
input was injected with `qm sendkey` since the test VM is headless.

Unit tests cover the wire round-trip (`display_channel`), the
`Resource::Framebuffer` range-subset (`scope_display_map_*`), the
syscall-number stability assert (`DisplayMap = 79`), and the kernel
`DisplayMap` routing. The compositor (TASK-19) consumes exactly these
primitives.
