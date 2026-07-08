# ADR-0042: `nexacore-ui` Widget Toolkit + Text Rendering (TASK-20, DE-C4/DE-C5)

**Status:** Accepted
**Date:** 2026-06-08
**Deciders:** agent analysis under operator-approved PLAN.md TASK-20
**Refs:** PLAN.md TASK-20 (DE-C4+DE-C5, M3), ADR-0041 (`nexacore-display`
compositor, TASK-19), ADR-0040 (display primitives), `brand/colors/palette.md`,
`brand/typography/`, `docs/plans/desktop-environment-the development plan` §DE-C

## Context

TASK-19 gave the Ring-3 compositor + window manager (`nexacore-display`). TASK-20
builds the **GUI toolkit** on top: a new `nexacore-ui` crate with base widgets
(label, button, text input, list, container), a layout engine, event
handling, a brand theme, and **real text rendering** with brand typography.

Forces / facts (recon):
- `nexacore-ui` is `no_std + alloc`, host-testable (the acceptance — deterministic
  layout, event dispatch, UTF-8 text measurement, a golden render hash — runs
  on the host).
- `font8x8` (v0.3, `no_std`, compile-time `const` glyph array) is already a
  workspace dependency (the kernel banner uses it). It is the obvious embedded
  raster font.
- The brand palette (`brand/colors/palette.md`): **petrol** `#0F4C5C`
  (primary), **cream** `#F4EBD0` (canvas), **brick** `#C03221` (accent),
  **sage** `#7A9E7E` (success), **charcoal** `#1F2421` (text).
- `nexacore-display::Surface` is committed via a full `&[u32]` slice (no mutable
  pixel accessor), so widgets render into their own pixel buffer that the app
  then commits.

## Decisions

### D1 — `nexacore-ui` crate: render into a `Canvas`, decoupled from the compositor

`crates/nexacore-ui/` (`no_std + alloc`, host + `x86_64-unknown-none`) renders into
a `Canvas` — a borrowed `&mut [u32]` ARGB pixel buffer + `width`/`height` —
NOT directly into a compositor `Surface`. This keeps the toolkit testable in
isolation (a golden test renders into a `Vec<u32>` and hashes it) and lets the
demo app copy the finished canvas into an `nexacore-display::Surface` it commits.
`nexacore-ui` depends on `nexacore-display` (for `geometry::Rect`) and `nexacore-types`
(`display_channel::DisplayInputEvent` for events) + `font8x8`.

Modules: `color` (brand palette consts), `canvas` (`Canvas::fill_rect`,
`draw_glyph`, `blit`), `text` (measure + draw), `theme`, `widget`, `layout`.

### D2 — Text rendering: `font8x8`, UTF-8-aware, integer-scalable

Text is rendered with `font8x8` (8×8 monospace), integer-scaled (`scale: u32`)
so headings can be larger. The renderer is **UTF-8-aware**: it iterates
`str::chars()` (codepoints, not bytes), maps each to a glyph, and falls back to
a visible `?`-box glyph for codepoints outside the font's range. `measure_text`
therefore counts CODEPOINTS (a multibyte char like `é` is width 1 glyph, not 2),
returning `(glyphs * 8 * scale, 8 * scale)`. This is the security-relevant
boundary: measurement and rasterization are bounded by the codepoint count and
the fixed 8×8 glyph, never by raw byte length, and every glyph write is
bounds-checked against the canvas.

**Brand typography scope:** the *brand colours* (charcoal text on cream/petrol
surfaces, petrol headings, brick for danger) are applied now; the *brand
typeface* (a real TrueType face from `brand/typography/`) is the DE-C5
"TrueType backend later" follow-up — `font8x8` is the raster stand-in. The
`text` module's API (`measure_text`/`draw_text` taking a font handle) is shaped
so a TrueType rasterizer can drop in behind it without changing callers.

### D3 — Brand theme

A `Theme` struct carries the brand palette + spacing + default text scale; a
`Theme::nexacore()` default uses petrol/cream/charcoal/brick/sage from
`brand/colors`. Widgets read colours from the theme (no hard-coded colours in
widget code) so a future light/dark or re-brand is a one-struct change.

### D4 — Widgets: a `Widget` tree with measure → layout → render → hit-test

Base widgets: `Label{text}`, `Button{text,id}`, `TextInput{text,cursor}`,
`List{items}`, `Container{children, direction, padding, spacing}`. The model is
a retained tree:
- `measure(&self, theme) -> Size` — intrinsic size (text-driven for label/
  button/input; sum/max of children for a container).
- `layout(&mut self, bounds: Rect, theme)` — assigns each widget (and
  recursively each child) a concrete screen `Rect` by a deterministic
  vertical/horizontal stack with padding+spacing. Layout is PURE (same tree +
  bounds → same rects), which the golden layout test pins.
- `render(&self, canvas, theme)` — paints the widget's rect (background, text,
  border) into the canvas; containers paint children.
- `hit_test(&self, point) -> Option<WidgetId>` / `dispatch_click(point)` —
  returns the id of the deepest widget whose laid-out rect contains the point
  (the "correct widget's handler" the acceptance asks for). Buttons/inputs are
  interactive; labels/containers are pass-through.

Widget ids are caller-assigned (`WidgetId(u32)`); the app maps an id to an
action. This keeps `nexacore-ui` `no_std`-friendly (no boxed closures required for
the core, though a handler-callback convenience can wrap it) and the dispatch
deterministically testable.

### D5 — Font asset safety

`font8x8` is a compile-time `const` table — there is NO runtime parse, so the
"trusted-but-bounds-checked, no input-proportional allocation" requirement is
satisfied trivially (the only sizes are the codepoint count and the fixed
glyph). The future TrueType backend MUST bounds-check every table offset and
cap glyph/outline counts; that constraint is recorded here for D2's follow-up.

### D6 — Hardware demo

A new `nexacore-ui-demo-image` (compositor + toolkit in-process, like the TASK-19
image) renders a window whose content is an `nexacore-ui` widget tree — a brand
title label, a button, and a text input with readable text — composites it,
and routes input (a click activates the button; keys feed the focused text
input). The kernel display boot-spawn prefers `nexacore-ui-demo-image` over the
TASK-19 `nexacore-display-image`. This is the VM-103 acceptance artifact ("finestra
demo con widget interattivi e testo leggibile").

## Alternatives considered

- **Embed a TrueType brand face now** — deferred (D2): a `no_std` TTF
  parser+rasterizer (hinting, kerning, anti-aliasing) is a large, security-
  sensitive sub-project; `font8x8` gives readable, deterministic, golden-
  testable text today, and the `text` API is TTF-ready.
- **Immediate-mode GUI (egui-style)** — rejected for v1: a retained widget tree
  makes the deterministic-layout and click-dispatch acceptance tests
  straightforward and matches the "tree di widget → rects" golden test the PLAN
  specifies.
- **Render straight into `nexacore-display::Surface`** — rejected: a borrowed
  `Canvas` keeps `nexacore-ui` independent of the compositor and trivially
  unit-testable (hash a `Vec<u32>`); the app bridges canvas → surface.
- **Boxed `dyn Fn` click handlers in the core** — avoided in the core: id-based
  dispatch is `no_std`-clean and testable; a closure-wrapper can sit on top in
  the app layer.

## Consequences

- New `crates/nexacore-ui` (host + bare-metal) with unit tests: deterministic
  layout (golden tree→rects), click dispatch (→ correct widget id), UTF-8
  measurement (incl. multibyte), and a golden render hash for a sample string.
- New `crates/nexacore-ui-demo-image` + initramfs entry; the kernel display
  boot-spawn prefers it. VM-103 verification (interactive widgets + readable
  text, annotated screenshot).
- The brand typeface (TrueType) + anti-aliasing is the tracked DE-C5 follow-up;
  TASK-21 (DE-C6) adds the status bar with the AI-backend indicator on top of
  this toolkit.

## Verification appendix — TASK-20 CLOSED (2026-06-08)

Implemented (crate + demo image by the agent team) and **hardware-verified on
the test VM**, zero #PF.

`nexacore-ui` host tests (10 unit + 24 doctests) cover the acceptance:
deterministic layout (golden widget-tree → rects, pure/re-runnable), click
dispatch (→ the correct interactive widget's `WidgetId`; empty/label → `None`),
UTF-8 text measurement (`"café"` = 4 glyphs not 5 bytes), and a golden render
hash (`"NexaCore"` → FNV-1a `0x1C90CC1A`, with a non-blank/not-all-text assertion).
Off-canvas draws are bounds-checked (no panic, no OOB). No `unsafe`.

the test VM (`nexacore-ui-demo-image` boot-spawned as the preferred display task;
serial + two screendumps):

```
[nexacore-ui-demo] DisplayMap OK front_va=0x...
[nexacore-ui-demo] ready -- widget UI presented
   ( qm sendkey 103 h e l l o )
[nexacore-ui-demo] input_text len=4
[nexacore-ui-demo] input_text len=5
   ( qm sendkey 103 ret )
[nexacore-ui-demo] submitted: hello
```

Screenshots confirmed: a petrol-themed window (cyan compositor focus border)
with the readable title **"NexaCore OS -- nexacore-ui demo"**, a cream `TextInput`, a
**brick-red "Submit" `Button`** (the brand accent), and a status `Label` — all
in legible font8x8 (scale 2) brand-coloured text. After typing, the
`TextInput` showed **"hello"** with a cursor and the status `Label` updated to
**"submitted: hello"** — proving interactive widgets + real text rendering
driven by live keyboard input through the full stack (kernel input pump →
display IPC → compositor → nexacore-ui).

Scope note (D2): text is the `font8x8` raster stand-in; the brand TrueType
typeface + anti-aliasing is the tracked DE-C5 follow-up. TASK-21 (DE-C6) adds
the AI-backend status bar on this toolkit.
