# ADR-0041: `nexacore-display` Userspace Compositor + Window Manager (TASK-19, DE-C2/DE-C3)

**Status:** Accepted
**Date:** 2026-06-08
**Deciders:** agent analysis under operator-approved PLAN.md TASK-19
**Refs:** PLAN.md TASK-19 (DE-C2+DE-C3, M3), ADR-0040 (display-map +
input-event primitives, TASK-18), `docs/13-display-server-abi.md`,
`docs/plans/desktop-environment-the development plan` §DE-C

## Context

TASK-18 gave the kernel primitives: `DisplayMap (79)` (map the framebuffer
into Ring 3, NX, capability-gated) and an input-event IPC channel
(`DisplayInputEvent` notifications). TASK-19 builds the Ring-3 **compositor +
window manager** on top: a new `nexacore-display` crate that owns the framebuffer,
composites windows with **damage tracking** + **double buffering**, and runs a
**window manager** (lifecycle, focus, z-order, input routing to the focused
window). A client⇄compositor IPC protocol is defined and documented.

Design forces:
- The compositor is `no_std + alloc`, runs in Ring 3, and must be
  **host-testable** (the acceptance unit tests — damage, z-order/focus, input
  routing, clamp — run on the dev host, not on hardware).
- **Never trust the client.** Shared buffers are validated for size; client
  damage rects and window geometry are clamped to bounds before use.
- It consumes ONLY the TASK-18 primitives + `nexacore-usys::display`.

## Decisions

### D1 — Crate layout: a host-testable core + a bootable image

`crates/nexacore-display/` (`no_std + alloc`, builds for both host and
`x86_64-unknown-none`) holds the pure logic, split into modules:
- `geometry`: `Rect { x: i32, y: i32, w: u32, h: u32 }` with
  `intersect`/`union`/`clamp_to`/`contains`/`is_empty`; `DamageRegion` (a
  bounded set of dirty rects with coalescing + screen-clamp).
- `surface`: `Surface { id, width, height, pixels: Vec<u32> }` — a window's
  ARGB content buffer; `commit` validates `pixels.len() == width*height`.
- `window`: `Window { id, x, y, z, surface, visible, title }`.
- `wm`: `WindowManager` — z-ordered windows, focus, `create`/`destroy`/
  `move_to`/`raise`/`set_focus`/`cycle_focus`, `hit_test`, and input routing
  (`route_input(ev) -> Option<WindowId>` — keys go to the focused window only).
- `compositor`: `Compositor` — owns the WM + accumulated `DamageRegion`;
  `composite(back: &mut [u32], screen_w, screen_h)` paints ONLY the dirty
  rects, back-to-front by z-order, then clears damage. Double buffering is the
  image's responsibility (composite into a back buffer, copy the dirty rects
  to the mapped framebuffer front) — the core stays allocation-light and
  framebuffer-agnostic.

The bootable `crates/nexacore-display-image/` (workspace-excluded, like the other
`*-image`s) maps the framebuffer via `nexacore-usys::display`, drives the
`Compositor`, drains the input channel, and is the VM-103 artifact.

### D2 — Damage tracking + double buffering

The compositor never repaints the whole screen. Each mutation (surface
commit, window move/raise/destroy, focus change) adds the affected screen
rect(s) to `DamageRegion`. `composite` walks windows back-to-front and, for
each, paints the intersection of (window rect ∩ each damage rect) into the
back buffer; the image then copies exactly those dirty rects to the
framebuffer. Closing a window damages the region it occupied so the windows
behind are recomposed there — **no ghosting**. `DamageRegion` coalesces and
caps its rect count (merging to the bounding box past a small limit) so a
malicious flood of tiny rects cannot exhaust memory.

### D3 — Window manager: focus, z-order, input routing

Windows carry a `z` order; the WM keeps them sorted and `raise` moves a
window to the top (and damages it). Exactly one window is focused; `set_focus`
/`cycle_focus` (Tab) move focus and damage the old + new focused window (so a
focus border can redraw). `route_input` returns the focused window id for key
events (pointer events route by `hit_test` to the window under the cursor) —
**keys never reach an unfocused window**. Destroying a window clears focus to
the next top-most.

### D4 — Never trust the client: clamp + size-validate

Every client-supplied value is clamped/validated before use:
- A surface commit requires `pixels.len() == width * height` (else rejected —
  no partial/over-read).
- Client damage rects are intersected with the surface bounds, then mapped to
  screen and intersected with the screen bounds — an out-of-bounds rect
  becomes a clamped (possibly empty) rect, never an out-of-bounds write.
- Window geometry is clamped to the screen on move.
This is the security-critical invariant the host tests target (a "malicious
client" with a rect past the surface/screen edge must not cause an
out-of-bounds composite).

### D5 — Client⇄compositor IPC protocol (defined now; in-process test surfaces for v1)

The wire protocol lives in `nexacore-types` (`display_protocol` module,
`#[non_exhaustive]` postcard enums):
- Client→compositor: `CreateSurface { width, height }`,
  `Commit { surface_id, damage: heapless/bounded Vec<Rect> }`,
  `Destroy { surface_id }`, `Move { surface_id, x, y }`.
- Compositor→client: `SurfaceCreated { surface_id }`,
  `Input(DisplayInputEvent)` (routed to the focused client),
  `Closed { surface_id }`, `Configure { surface_id, width, height }`.
The protocol is DEFINED + DOCUMENTED now. The TASK-19 acceptance image drives
**three in-process test surfaces** through the same `Compositor`/WM API the
IPC handlers will call (the commit/clamp path is identical), which fully
exercises compositing + WM + damage + input routing + clamp on hardware.
Multi-process clients speaking the IPC protocol arrive with the first real
apps (TASK-20 `nexacore-ui`); wiring the compositor's IPC receive-loop to spawn/
serve external client tasks is that follow-up, not TASK-19. This keeps
TASK-19 to "the compositor renders + manages windows", verifiable end-to-end,
without also shipping a multi-process client runtime in the same task.

## Alternatives considered

- **Whole-screen repaint each frame** — rejected: the spec mandates damage
  tracking ("solo le rect sporche ricomposte"); full repaint also flickers and
  wastes the uncached-framebuffer write bandwidth.
- **Multi-process clients over IPC in TASK-19** — deferred to TASK-20 (D5):
  there are no real apps yet, and the compositor + WM + damage + clamp (the
  TASK-19 substance + every acceptance test) are fully delivered with
  in-process test surfaces through the identical commit/clamp path.
- **Reusing the kernel `wm.rs`** — rejected: that is the in-kernel
  Ring-0 desktop (no surfaces, no damage, no double buffer, draws straight to
  the framebuffer). The userspace compositor is a distinct, richer design;
  `wm.rs` is only a reference.
- **Trusting client rects and bounds-checking at blit time only** — rejected:
  clamp at the API boundary (D4) is defence-in-depth and makes the invariant
  unit-testable independent of the blitter.

## Consequences

- New `crates/nexacore-display` (host + bare-metal) with unit tests for damage,
  z-order/focus, input routing, and clamp.
- `nexacore-types::display_protocol` wire types (defined + documented).
- New `crates/nexacore-display-image` + initramfs entry + a kernel boot-spawn
  (it needs the `Display` cap + input channel — reuse the TASK-18
  `display-probe` deposit path, renamed/parameterised, OR a sibling feature).
- VM-103 verification: 3 windows, focus switch via real input, close without
  ghosting, zero #PF.
- TASK-20 (`nexacore-ui`) builds real apps that become the first multi-process
  clients over the `display_protocol` (D5).

## Verification appendix — TASK-19 CLOSED (2026-06-08)

Implemented (crate + protocol + image by the agent team; the ghosting fix +
no-ghost test in-session) and **hardware-verified on the test VM**, zero #PF.

`nexacore-display` host tests (55 unit + 30 doctests) cover the acceptance:
damage = only-dirty-rects, z-order overlap, focus + input routing to the
focused window only, malicious-client clamp (`Rect{x:-1000,y:-1000,
w:100000,h:100000}` does not panic and every painted rect ⊆ screen),
wrong-length commit → `Err(InvalidSize)`, and **closing a window leaves no
ghost**. `nexacore-types::display_protocol` round-trips (11 tests).

the test VM (`nexacore-display-image` boot-spawned under the kernel `display-probe`
feature; serial + three screendumps):

```
[nexacore-display] DisplayMap OK front_va=0x...
[nexacore-display] composited 5 dirty rects
[nexacore-display] initial frame presented (3 windows, focus=A)
   ( qm sendkey 103 tab )
[nexacore-display] composited 2 dirty rects        # old + new focus border
[nexacore-display] focus -> 1                       # focus A -> B
   ( qm sendkey 103 c )
[nexacore-display] composited 1 dirty rects
[nexacore-display] closed window, recomposed        # B destroyed; area recomposed
```

Screenshots confirmed: (1) three overlapping windows — blue A (cyan focus
border), green B, orange C — z-ordered with correct overlap; (2) after Tab
the focus border moved A→B; (3) after closing B the green window vanished and
its vacated area showed the **dark desktop background** (not a green ghost),
with A/C intact and focus moved to C.

**Ghosting fix:** the compositor's `composite()` now fills each dirty rect
with `DESKTOP_BACKGROUND` BEFORE compositing windows over it, so a vacated
area shows the desktop rather than the closed window's stale pixels (the
`closing_window_leaves_no_ghost` unit test pins this).

Scope note (D5): the three test windows are in-process surfaces driven through
the same `Compositor`/WM commit+clamp path the IPC handlers will use; the
`display_protocol` wire types are defined + documented. Multi-process clients
over IPC arrive with the first real apps (TASK-20 `nexacore-ui`).
