# 13 — Display Server ABI (M3 / DE-C1)

> **Status:** stable for the primitives introduced in TASK-18 (DE-C1).
> This is an early, scoped slice of the full DE-H2 Ring-3 ABI reference —
> it documents ONLY the display-map syscall and the input-event channel.
> Design rationale: [`docs/adr/0040-display-map-input-channel.md`](./adr/0040-display-map-input-channel.md).

The display server primitives let a Ring-3 compositor (TASK-19) put pixels
on screen and receive input, while the kernel keeps ownership of the
framebuffer's physical pages and the input hardware. Two primitives:
a framebuffer-mapping syscall and a kernel→compositor input channel.

## 1. `DisplayMap` — syscall 79

Maps the GOP framebuffer (or a page-aligned sub-window of it) into the
calling task's address space. The mapping is **NX** (never executable),
user-writable, and uncached (`PCD|PWT`) so writes reach the scanout
immediately. Mirrors `MmioMap (70)` but the caller names only an *offset*
into the kernel-known framebuffer — it can never choose an arbitrary
physical address (least privilege).

| Register | In | Out |
|----------|----|-----|
| `rax` | `79` (syscall number) | user virtual address of the mapping, or `0` on error |
| `rdi` | `offset` — byte offset into the framebuffer; 4 KiB-aligned | — |
| `rsi` | `len` — bytes to map; non-zero, 4 KiB-aligned; `offset + len ≤ fb_len` | — |
| `rdx` | `flags` — reserved, MUST be `0` | `errno` (`0` on success) |
| `r10` | `cap_ptr` — user pointer to the postcard-encoded capability token | — |
| `r8`  | `cap_len` — token length in bytes (≤ 1024) | — |

**Authorisation.** The token must verify under the per-boot kernel
capability issuer, carry `Action::DisplayMap`, and its
`Resource::Framebuffer { phys_base, len }` scope must *contain*
`[fb_phys + offset, fb_phys + offset + len)`. Any failure → `EACCES`.

**Errors.** `EACCES` (missing/invalid/foreign-issuer/wrong-action/
out-of-scope token); `EINVAL` (misaligned `offset`/`len`, zero `len`,
non-zero `flags`, or `offset + len` past the framebuffer end); `ENODEV`
(no framebuffer present — VGA-text fallback); `ENOSPC` (no free user-VA
window / frame mapping failed). Mapping is **all-or-nothing**: a partial
failure rolls back every page already installed.

The framebuffer geometry a compositor needs to interpret the mapped bytes
(`width`, `height`, `stride`, `bytes_per_pixel`) is delivered out-of-band
in the capability deposit (see §3); the pixel at `(x, y)` lives at
`base + (y * stride + x) * bytes_per_pixel`.

## 2. Input-event channel (kernel → compositor)

Keyboard (and, later, pointer) events are delivered over an IPC channel
the kernel owns and the compositor drains with `IpcTryReceive (24)`. Each
message is a `MessageKind::Notification` whose payload is a single
postcard-encoded [`nexacore_types::display_channel::DisplayInputEvent`]:

```rust
#[non_exhaustive]
enum DisplayInputEvent {
    Key { code: u8, pressed: bool },        // printable keys carry ASCII;
                                            // Esc/Enter/Bksp/Tab use ASCII
                                            // control codes; arrows use 0x80..=0x83
    Pointer { x: u32, y: u32, buttons: u8 },// absolute coords; buttons bit0=L,1=R,2=M
}
```

The encoded event is ≤ `DisplayInputEvent::MAX_EVENT_BYTES` (32 B) and
always fits one IPC message (4 KiB Phase-1 payload cap). The kernel pumps
events cooperatively (it polls the PS/2 controller and `ipc::send`s each
event from a normal kernel context, never from an interrupt handler). The
compositor receives the channel id out-of-band in its deposit (§3) and
polls; an empty queue returns `EAGAIN`/`Ok(None)`.

## 3. Capability + parameter deposit

At spawn the kernel deposits, into the compositor's capability window
(`DRIVER_CAP_DEPOSIT_VA = 0x10_0000`):

- a `DisplayMap` capability scoped to the whole framebuffer
  (`Resource::Framebuffer { phys_base, len }`), found Ring-3-side via
  `nexacore_driver_shared::caps::find_token(ACTION_TAG_DISPLAY_MAP = 7)`; and
- a `VirtioDeviceInfo` section (read via
  `nexacore_driver_shared::device_info::read()`) carrying the input channel id
  and the framebuffer geometry. For the display path the fields are
  interpreted as: `bar_phys` = input channel id; `common_offset` = width;
  `notify_offset` = height; `isr_offset` = stride (pixels/row);
  `device_offset` = bytes-per-pixel; `mmio_len` = framebuffer byte length.

## 4. `nexacore-usys::display`

Typed Ring-3 wrappers (bare-metal feature): `display_map(offset, len, cap)
→ *mut u8` over syscall 79, and `recv_input_event(channel_id, buf) →
Option<DisplayInputEvent>` over `IpcTryReceive (24)`.

## Verification (TASK-18, the test VM)

The `nexacore-display-probe` image (boot-spawned under the kernel
`display-probe` feature) read its deposited geometry (1280×800, 4 bpp,
`len = 0x3E8000`), `DisplayMap`ped the framebuffer, painted RGB
colour-thirds + a white box (visible on screen), and received injected
keystrokes (`a b c d e`, then Enter `0x0D` / Escape `0x1B`) over the input
channel — zero page faults. See ADR-0040 for the captured serial log.
