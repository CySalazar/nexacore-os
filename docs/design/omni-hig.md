# NexaCore Human Interface Guidelines

**Status:** Draft v0.1 — design language consolidation (WS7-00).
**Last updated:** 2026-06-23
**Direction:** C — Civic Tech / Generational.
**Authoritative sources:** [`brand/STRATEGY.md`](../../brand/STRATEGY.md), [`brand/colors/`](../../brand/colors/), [`brand/typography/`](../../brand/typography/), [`brand/icons/`](../../brand/icons/).
**Owner:** Lead Architect (cySalazar) for years 1–5. After 2031-05-09, the NexaCore Foundation Director.

> This document is the consolidated Human Interface Guidelines for NexaCore OS. It is the human-readable specification of the design language. The machine-consumable design-token module — the values below expressed as a typed Rust API — lives in the `nexacore-ui` crate ([`crates/nexacore-ui`](../../crates/nexacore-ui)) and is consumed by the theme engine (WS17-03). When this document and the brand pack disagree, the brand pack wins and this file is updated to match. When this document and the `nexacore-ui` token module disagree, this document wins and the crate is updated to match.

---

## Executive summary

NexaCore OS targets the visual and interaction quality of a modern desktop platform without copying one. The reference for "quality" is rendering fidelity — soft shadows, rounded surfaces, vibrancy, spring-physics motion — not a borrowed aesthetic. The aesthetic is NexaCore's own: a **civic-tech, generational** design language anchored on Mozilla, Wikimedia, GOV.UK, the Internet Archive, and the Long Now Foundation, with a warm paper canvas, a sober petrol structure, and a single reserved red.

Everything in this document is grounded in the brand pack. Where the brand pack does not specify a value — spacing, elevation, corner radii, motion, materials, interactive states, density — this document defines it, derives it from the brand personality, and flags it explicitly in [§13 Source traceability](#13-source-traceability) so the `nexacore-ui` token module can reconcile against a single source.

---

## Table of contents

1. [Design principles](#1-design-principles)
2. [Grid and spacing](#2-grid-and-spacing)
3. [Typography](#3-typography)
4. [Color](#4-color)
5. [Elevation and shadows](#5-elevation-and-shadows)
6. [Corner radii](#6-corner-radii)
7. [Motion](#7-motion)
8. [Materials — translucency and vibrancy](#8-materials--translucency-and-vibrancy)
9. [Interactive states](#9-interactive-states)
10. [Density modes](#10-density-modes)
11. [Iconography](#11-iconography)
12. [Reference component contract](#12-reference-component-contract)
13. [Source traceability](#13-source-traceability)

---

## 1. Design principles

The interface inherits the five brand attributes from [`brand/STRATEGY.md` §4](../../brand/STRATEGY.md). Each attribute resolves to a concrete interface rule, not a mood. The personality is not decorative language; it is the acceptance criteria for every screen.

### 1.1 The five attributes, as interface rules

| Attribute | Interface rule |
|---|---|
| **Patient** | Generous whitespace. No motion that signals velocity or urgency. Animations settle, they do not snap or bounce hard. Stable type weights — no weight changes on hover. |
| **Rigorous** | A visible, consistent grid. One spacing scale, one type scale, one radius scale. Every measurement traces to a token. Nothing is hand-placed. |
| **Severe** | Minimal ornament. High-contrast, legible-first surfaces. No decorative illustration, no gradients as decoration, no glow. Tight, deliberate spacing in chrome. |
| **Open** | Every visual is tokenized and source-controlled. No hex literals in product code; the semantic token is the only public surface. |
| **Honest** | Status is part of the chrome, never hidden. Danger looks like danger (brick), success looks like success (sage). Disabled states are unmistakably non-interactive. |

### 1.2 What NexaCore is not (interface anti-personality)

Derived from [`brand/STRATEGY.md` §4.2](../../brand/STRATEGY.md). These are hard prohibitions, not preferences.

- **Not excited.** No neon, no pulsing motion, no superlative microcopy, no exclamation marks anywhere in the UI — including error toasts and empty states.
- **Not friendly-startup.** No mascots, no rounded geometric display sans, no decorative gradients, no "we love you" copy.
- **Not cypherpunk.** No black-and-green terminal chrome by default, no glitch effects, no Matrix references.
- **Not corporate-confident.** No stock imagery, no logo walls, no flat-illustration scenes.
- **Not crypto-finance.** No hexagonal honeycomb motifs, no coin/chain iconography, no token-chart visuals.

### 1.3 Default theme posture

The default theme is **light**: a warm cream canvas with petrol structure and charcoal text. Dark mode is a first-class peer (defined in the brand tokens), not an afterthought. The theme engine (WS17-03) selects between light and dark, applies accent and density overrides, and toggles materials on or off — all by re-binding the semantic tokens in [§4](#4-color), never by introducing new colors.

### 1.4 Accessibility as a floor

From [`brand/typography/typography.md`](../../brand/typography/typography.md) and [`brand/colors/palette.md`](../../brand/colors/palette.md):

- Minimum body text size: **16 px**. Smaller body text is forbidden.
- Minimum interactive target: **44 × 44 px** (WCAG 2.5.5 AAA).
- Body text contrast target: **AAA**; AA is the absolute floor for any text.
- Reading/focus order in the accessibility tree matches visual order.
- A dedicated high-contrast theme (WS7-16.6) is derived from these tokens, not bolted on.

---

## 2. Grid and spacing

> **Brand status:** the brand pack does not define a spacing system. This section is introduced by the HIG (WS7-00.1), derived from the "Rigorous" (visible grid) and "Patient" (generous whitespace) brand attributes. See [§13](#13-source-traceability).

### 2.1 Base unit

The spacing system is built on an **8 px base unit**. Every margin, padding, gap, and component dimension is a multiple of 8 px. A single **4 px half-step** is permitted for dense control internals (icon-to-label gaps, status-pill padding) and nowhere else. Layout never uses arbitrary pixel values.

### 2.2 Spacing scale

A linear-then-doubling scale keyed to the 8 px base. Token names use a `space-*` index that maps to multiples of the base.

| Token | Value | Multiple | Typical use |
|---|---|---|---|
| `space-0` | 0 px | 0 | Reset / flush |
| `space-px` | 1 px | — | Hairline borders only |
| `space-0.5` | 4 px | 0.5× | Half-step: pill padding, icon-label gap (dense controls only) |
| `space-1` | 8 px | 1× | Tight gaps inside a control, list-row inner padding |
| `space-2` | 16 px | 2× | Default gap between related controls; card inner padding |
| `space-3` | 24 px | 3× | Group spacing; toolbar horizontal padding |
| `space-4` | 32 px | 4× | Section spacing inside a panel |
| `space-5` | 40 px | 5× | Large section spacing |
| `space-6` | 48 px | 6× | Window content inset (regular density) |
| `space-8` | 64 px | 8× | Major layout regions |
| `space-10` | 80 px | 10× | Page-level rhythm, splash spacing |

### 2.3 Layout grid

| Aspect | Specification |
|---|---|
| Column module | 8 px base; layout columns are 12-up within a content region |
| Gutter | `space-3` (24 px) at regular density, `space-2` (16 px) at compact |
| Content max measure | Body text constrained to **65ch** (45–75 characters/line) per [`brand/typography/typography.md`](../../brand/typography/typography.md) |
| Window content inset | `space-6` (48 px) regular, `space-4` (32 px) compact, `space-3` (24 px) on small windows |
| Touch/click target | ≥ 44 × 44 px regardless of visual control size; padding extends the hit area when the glyph is smaller |

### 2.4 Rules

1. Spacing is additive from the scale; never interpolate a value that is not a token.
2. Whitespace is a primary tool, not leftover space — the "Patient" attribute means generous default spacing, tightened only in dense chrome.
3. The 4 px half-step is the only sub-8 px value permitted, and only inside controls.

---

## 3. Typography

Authoritative source: [`brand/typography/typography.md`](../../brand/typography/typography.md) and [`brand/typography/type-tokens.css`](../../brand/typography/type-tokens.css). All values below are restated from the brand pack without change.

### 3.1 Families — one role each

| Family | Role | Stack fallback |
|---|---|---|
| **Source Serif 4** | Display, document headlines, long-form prose, wordmark | `'Source Serif Pro', Georgia, 'Times New Roman', serif` |
| **Inter** | UI chrome, navigation, captions, body where serif is too literary | `-apple-system, BlinkMacSystemFont, 'Segoe UI', 'Helvetica Neue', Arial, sans-serif` |
| **IBM Plex Mono** | Code, terminal output, technical labels, metadata, status pills | `ui-monospace, 'SF Mono', 'Cascadia Mono', 'Roboto Mono', Menlo, Consolas, monospace` |

All three are SIL OFL 1.1 — coherent with the Apache-2.0 codebase and CC0 protocol specs. Mixing a role to a different family (e.g. serif body in two faces, or a geometric sans replacing Inter) is a brand error.

### 3.2 Type scale — modular 1.250 (major third)

| Token | Size (px / rem) | Use |
|---|---|---|
| `text-xs` | 12 px / 0.75 rem | Captions, metadata, footnotes, status pills |
| `text-sm` | 14 px / 0.875 rem | UI default, table cells, secondary text |
| `text-base` | 16 px / 1 rem | Body text default (minimum body size) |
| `text-lg` | 20 px / 1.25 rem | Lede paragraph, callout |
| `text-xl` | 25 px / 1.5625 rem | Section headings (h3) |
| `text-2xl` | 31 px / 1.953 rem | Sub-headings (h2) |
| `text-3xl` | 39 px / 2.441 rem | Page headings (h1) |
| `text-4xl` | 49 px / 3.052 rem | Hero headings |
| `text-5xl` | 61 px / 3.815 rem | Splash hero (rare) |

### 3.3 Weights

| Token | Value | Note |
|---|---|---|
| `weight-regular` | 400 | Body, code |
| `weight-medium` | 500 | UI labels; sans when paired with serif |
| `weight-semibold` | 600 | Sub-headings (h4/h5/h6), pull quotes |
| `weight-bold` | 700 | Display headings; serif when paired with sans |

`font-weight: 900` is forbidden anywhere ([`typography.md` Anti-patterns](../../brand/typography/typography.md)).

### 3.4 Line-height

| Token | Value | Use |
|---|---|---|
| `leading-tight` | 1.15 | Display (text-2xl and up) |
| `leading-snug` | 1.4 | UI text in interface chrome |
| `leading-normal` | 1.55 | Body text (text-base, text-sm) |
| `leading-relaxed` | 1.6 | Code blocks (Plex Mono) |

### 3.5 Letter-spacing (tracking)

| Token | Value | Context |
|---|---|---|
| `tracking-tight` | -0.015em | Display headings (text-3xl+), wordmark |
| `tracking-normal` | 0 | Body (Source Serif, Inter) — never adjust |
| `tracking-wide` | +0.06em | All-caps UI labels (text-xs), document fingerprint |
| `tracking-wider` | +0.08em | All-caps section labels (text-sm), status pills |
| `tracking-widest` | +0.12em | Reserved |

### 3.6 Pairing and constraints

1. Serif sets the voice; sans carries the work. Source Serif 4 for things the reader pauses on, Inter for things the reader scans.
2. Mono carries only technical content — never body prose.
3. One face per role per page.
4. When serif and sans appear together: serif 700, sans 500.
5. Italics in Source Serif 4 only.
6. All-caps text must not exceed `text-sm`. All-caps body is a brand error.
7. No underlined non-link text, no drop caps, ligatures always on for prose (off for code).

---

## 4. Color

Authoritative source: [`brand/colors/tokens.json`](../../brand/colors/tokens.json), [`brand/colors/tokens.css`](../../brand/colors/tokens.css), [`brand/colors/palette.md`](../../brand/colors/palette.md). All values below are restated from the brand pack without change.

**Production code MUST use semantic tokens, never core-scale values directly.** The core ramps exist to define the semantic tokens and to give the theme engine a fixed vocabulary; product surfaces bind only to the semantic layer.

### 4.1 Core ramps

#### Petrol — primary brand hue (headings, links, structural lines)

| Step | Hex | Step | Hex |
|---|---|---|---|
| 50 | `#E6EEF0` | 500 | `#0F4C5C` *(canonical)* |
| 100 | `#C5D6DB` | 600 | `#0C3E4B` |
| 200 | `#94B3BC` | 700 | `#0A323C` |
| 300 | `#6390A0` | 800 | `#07242C` |
| 400 | `#386F82` | 900 | `#051921` |

#### Cream — warm canvas

| Step | Hex | Step | Hex |
|---|---|---|---|
| 50 | `#FDFBF4` | 400 | `#E8DAB1` |
| 100 | `#FAF5E6` | 500 | `#D9C68A` |
| 200 | `#F8F0DA` | 600 | `#B5A26B` |
| 300 | `#F4EBD0` *(canonical)* | 700 | `#8F7F50` |

#### Brick — Mission Anchor accent (singular reserved red)

| Step | Hex | Step | Hex |
|---|---|---|---|
| 50 | `#F8E1DE` | 500 | `#C03221` *(canonical)* |
| 100 | `#EFB7B0` | 700 | `#8F2519` |
| 300 | `#D85C50` | 900 | `#5C1710` |

#### Sage — community / success / status-OK

| Step | Hex | Step | Hex |
|---|---|---|---|
| 50 | `#EAF1EB` | 500 | `#7A9E7E` *(canonical)* |
| 100 | `#C6D8C8` | 700 | `#587657` |
| 300 | `#9CBC9F` | 900 | `#2E4E2D` |

#### Charcoal — body text + dark surfaces

| Step | Hex | Step | Hex |
|---|---|---|---|
| 50 | `#F2F3F2` | 500 | `#3E423E` |
| 100 | `#DCDEDC` | 600 | `#2D312D` |
| 200 | `#B3B7B3` | 700 | `#252925` |
| 300 | `#888D88` | 800 | `#1F2421` *(canonical)* |
| 400 | `#5E635E` | 900 | `#14171A` |
| | | 950 | `#0A0B0C` |

Neutrals: `white #FFFFFF`, `black #000000`.

### 4.2 The single-red rule

**Brick is the only warm accent in the system.** It is never decorative. It is reserved for the Mission Anchor mark, governance-status pills, critical alerts, and intentional "this matters" signals. To add warmth, use `cream-600` or `sage-500` — never brick. This rule is load-bearing: it is why brick also serves as the focus-ring color ([§9](#9-interactive-states)) — the one reserved color is the one that draws the eye.

### 4.3 Semantic tokens (light mode)

| Token | Resolves to | Hex | Purpose |
|---|---|---|---|
| `bg-canvas` | cream-300 | `#F4EBD0` | Window/page background |
| `bg-surface` | white | `#FFFFFF` | Cards, panels, raised surfaces |
| `bg-surface-2` | cream-100 | `#FAF5E6` | Recessed/secondary surface |
| `bg-inverse` | charcoal-800 | `#1F2421` | Inverted surfaces (tooltips, inverse chrome) |
| `bg-code` | petrol-50 | `#E6EEF0` | Code block background |
| `text-primary` | charcoal-800 | `#1F2421` | Body text |
| `text-secondary` | charcoal-500 | `#3E423E` | Secondary text |
| `text-tertiary` | charcoal-300 | `#888D88` | Tertiary / placeholder |
| `text-inverse` | cream-300 | `#F4EBD0` | Text on inverse surfaces |
| `text-accent` | petrol-500 | `#0F4C5C` | Headings, emphasis |
| `text-link` | petrol-500 | `#0F4C5C` | Links |
| `text-link-hover` | petrol-700 | `#0A323C` | Link hover |
| `border-default` | charcoal-100 | `#DCDEDC` | Default 1 px borders |
| `border-strong` | charcoal-300 | `#888D88` | Emphasized borders |
| `border-accent` | petrol-300 | `#6390A0` | Accent borders, left rules |
| `rule` | petrol-200 | `#94B3BC` | Horizontal rules, dividers |
| `status-success` | sage-500 | `#7A9E7E` | Success state |
| `status-warning` | (literal) | `#B58D32` | Warning state |
| `status-danger` | brick-500 | `#C03221` | Danger/error state |
| `status-info` | petrol-500 | `#0F4C5C` | Informational state |
| `status-neutral` | charcoal-300 | `#888D88` | Neutral/disabled state |
| `anchor` | brick-500 | `#C03221` | Mission Anchor signaling |
| `focus-ring` | brick-500 | `#C03221` | Keyboard focus indicator |

### 4.4 Semantic tokens (dark mode)

The dark theme re-binds the same semantic tokens; it never introduces new colors.

| Token | Resolves to | Hex |
|---|---|---|
| `bg-canvas` | charcoal-900 | `#14171A` |
| `bg-surface` | charcoal-800 | `#1F2421` |
| `bg-surface-2` | charcoal-700 | `#252925` |
| `bg-inverse` | cream-300 | `#F4EBD0` |
| `bg-code` | petrol-900 | `#051921` |
| `text-primary` | cream-300 | `#F4EBD0` |
| `text-secondary` | cream-500 | `#D9C68A` |
| `text-tertiary` | charcoal-300 | `#888D88` |
| `text-accent` | cream-300 | `#F4EBD0` |
| `text-link` | cream-400 | `#E8DAB1` |
| `text-link-hover` | cream-300 | `#F4EBD0` |
| `border-default` | charcoal-700 | `#252925` |
| `border-strong` | charcoal-500 | `#3E423E` |
| `border-accent` | petrol-300 | `#6390A0` |
| `rule` | charcoal-700 | `#252925` |

### 4.5 WCAG contrast (from the brand contrast matrix)

AAA is the target for body text. Ratios below are computed by the brand pack against the canonical canvas/surface colors ([`brand/colors/palette.md`](../../brand/colors/palette.md)).

**On `bg-canvas` cream-300 (`#F4EBD0`):**

| Foreground | Hex | Contrast | Verdict |
|---|---|---|---|
| text-primary (charcoal-800) | `#1F2421` | 12.2 : 1 | **AAA** all sizes |
| text-secondary (charcoal-500) | `#3E423E` | 7.9 : 1 | **AAA** body |
| text-tertiary (charcoal-300) | `#888D88` | 2.5 : 1 | Fail body; OK 18pt+/14pt-bold only |
| text-accent / link (petrol-500) | `#0F4C5C` | 9.4 : 1 | **AAA** all sizes |
| link-hover (petrol-700) | `#0A323C` | 12.6 : 1 | **AAA** all sizes |
| danger/anchor (brick-500) | `#C03221` | 4.7 : 1 | AA body, **AAA** large |
| success-strong (sage-700) | `#587657` | 4.6 : 1 | AA body, **AAA** large |

**On `bg-surface` white (`#FFFFFF`):**

| Foreground | Hex | Contrast | Verdict |
|---|---|---|---|
| charcoal-800 | `#1F2421` | 14.6 : 1 | **AAA** all sizes |
| petrol-500 | `#0F4C5C` | 11.2 : 1 | **AAA** all sizes |
| brick-500 | `#C03221` | 5.6 : 1 | AA body, **AAA** large |
| sage-700 | `#587657` | 5.5 : 1 | AA body |

**On dark canvas charcoal-900 (`#14171A`):**

| Foreground | Hex | Contrast | Verdict |
|---|---|---|---|
| cream-300 | `#F4EBD0` | 11.8 : 1 | **AAA** all sizes |
| cream-500 | `#D9C68A` | 9.2 : 1 | **AAA** all sizes |
| petrol-200 | `#94B3BC` | 7.4 : 1 | **AAA** body |
| brick-300 | `#D85C50` | 5.1 : 1 | AA body |

**Forbidden combinations** (vibration or insufficient contrast): brick-500 on petrol-500 (2.1 : 1), sage-300 on cream-300 (1.6 : 1), petrol-500 on charcoal-900 (1.9 : 1), and any gradient between brick and sage. Practical rule from the brand pack: if a pairing has to be checked against the matrix, it is probably wrong — default to charcoal-800 on cream-300 for body, petrol-500 for headings/links, brick-500 only when meaning demands it.

---

## 5. Elevation and shadows

> **Brand status:** the brand pack does not define an elevation system. This section is introduced by the HIG (WS7-00.4). Shadow color is derived from the brand palette (cool petrol-shifted shadow over warm cream, never neutral black, which reads as cheap on a warm canvas). The restraint — low opacity, soft blur, no hard drop shadows — follows the "Severe / minimal ornament" attribute. See [§13](#13-source-traceability).

### 5.1 Z-levels

Five elevation levels plus a flush baseline. Each level defines a single primary shadow; the two highest levels add a tight contact (ambient) shadow for definition. Shadows are rendered by the GPU compositor (WS7-01.7) as soft, never as a 1 px hard offset.

| Level | Role | Y-offset | Blur | Spread | Opacity | Contact shadow (Y / blur / opacity) |
|---|---|---|---|---|---|---|
| `elevation-0` | Flush — on-canvas, no lift (uses `border-default` instead) | 0 | 0 | 0 | 0 | — |
| `elevation-1` | Resting card / list row hover | 1 px | 2 px | 0 | 0.06 | — |
| `elevation-2` | Raised card, toolbar separation | 2 px | 6 px | 0 | 0.08 | — |
| `elevation-3` | Popover, dropdown, tooltip | 4 px | 12 px | -1 px | 0.10 | 1 px / 2 px / 0.06 |
| `elevation-4` | Dialog, modal sheet | 8 px | 24 px | -2 px | 0.12 | 2 px / 4 px / 0.08 |
| `elevation-5` | Dragged window, active window focus | 16 px | 48 px | -4 px | 0.16 | 2 px / 6 px / 0.10 |

### 5.2 Shadow color

| Theme | Shadow base | Note |
|---|---|---|
| Light | `petrol-900` `#051921` at the per-level opacity | Cool-shifted, harmonizes with cream canvas; never pure black |
| Dark | `black` `#000000` at the per-level opacity, +1 step opacity | Dark surfaces need a deeper shadow to separate; borders carry more of the work |

### 5.3 Rules

1. Elevation communicates layering, not decoration. Do not stack more than two elevation levels in one visual region.
2. A focused/active window uses `elevation-5`; unfocused windows drop to `elevation-3` to recede.
3. On dark surfaces, prefer `border-strong` over shadow where a shadow would be invisible.
4. No inner shadows except the single pressed-state inset in [§9](#9-interactive-states).

---

## 6. Corner radii

> **Brand status:** the icon system specifies round caps/joins ("round corners read as patient") in [`brand/icons/README.md`](../../brand/icons/README.md); the brand status-pill uses a 2 px radius ([`brand/typography/typography.md`](../../brand/typography/typography.md)). The full radius scale below is introduced by the HIG (WS7-00.5), extending those two fixed points. The "patient, not sharp" rationale is from the icon system. See [§13](#13-source-traceability).

### 6.1 Radius scale

| Token | Value | Use |
|---|---|---|
| `radius-none` | 0 px | Flush table cells, full-bleed regions, hairline rules |
| `radius-xs` | 2 px | Status pills (fixed by brand), checkboxes, tags |
| `radius-sm` | 4 px | Inputs, small buttons, menu items |
| `radius-md` | 8 px | Buttons, cards, list containers, popovers |
| `radius-lg` | 12 px | Dialogs, panels, sheets |
| `radius-xl` | 16 px | Window corners |
| `radius-full` | 9999 px | Pills, avatars, circular icon buttons |

### 6.2 Rules

1. Window corners are `radius-xl` (16 px), clipped by the compositor (WS7-01.8).
2. Containers and their contents nest: a control inside a card uses a radius one step below its container so the inner radius visually concentrically aligns (e.g. `radius-md` button inside a `radius-lg` dialog).
3. Radius is uniform across all four corners except where a surface is docked to an edge (a bottom sheet keeps top corners rounded, bottom corners square).
4. Sharp corners (`radius-none`) read as "warning/system-critical" — use only where that meaning is intended or where the surface is full-bleed.

---

## 7. Motion

> **Brand status:** the brand explicitly constrains motion in [`brand/STRATEGY.md` §4.1](../../brand/STRATEGY.md) ("no motion design suggesting velocity", "Patient") and §4.2 (no pulsing motion). The named curves, durations, and spring constants below are introduced by the HIG (WS7-00.6) within those constraints. See [§13](#13-source-traceability).

Motion must feel patient and settled. It exists to maintain spatial continuity and to confirm state changes — never to entertain, never to suggest speed. The compositor implements spring-physics transitions (WS7-01.9); CSS-style easing curves are provided for non-physical, duration-based transitions.

### 7.1 Easing curves

| Token | cubic-bezier | Character | Use |
|---|---|---|---|
| `ease-standard` | `(0.4, 0.0, 0.2, 1)` | Symmetric ease-in-out, calm | Default for most property transitions |
| `ease-decelerate` | `(0.0, 0.0, 0.2, 1)` | Enters fast, settles slow | Elements entering the screen |
| `ease-accelerate` | `(0.4, 0.0, 1, 1)` | Eases in, exits quick | Elements leaving the screen |
| `ease-emphasized` | `(0.2, 0.0, 0, 1)` | Pronounced settle, no overshoot | Large surfaces (dialogs, sheets) |

No `ease` curve overshoots. Overshoot, where wanted, comes from the spring system (§7.3) with low energy — never from an easing curve, which would read as "bouncy / excited".

### 7.2 Durations

| Token | Value | Use |
|---|---|---|
| `duration-instant` | 0 ms | State changes that must not animate (focus ring appearance) |
| `duration-fast` | 120 ms | Hover, small color/opacity changes, pressed feedback |
| `duration-base` | 200 ms | Default — most transitions, control state changes |
| `duration-slow` | 280 ms | Popovers, dropdowns, tooltips entering |
| `duration-slower` | 400 ms | Dialogs, sheets, window open/close |
| `duration-deliberate` | 600 ms | Large/rare transitions where the "Patient" attribute is the point |

### 7.3 Spring physics (micro-interactions)

For micro-interactions and live-resize/drag continuity (WS7-01.9, WS7-01.10), the compositor uses a critically-or-slightly-underdamped spring. Springs are specified by stiffness, damping, and mass. Defaults are tuned to settle without a perceptible bounce (the "Patient" constraint forbids energetic overshoot).

| Token | Stiffness | Damping | Mass | Damping ratio | Character |
|---|---|---|---|---|---|
| `spring-subtle` | 240 | 30 | 1 | ~0.97 | Near-critical; control press/release, toggles |
| `spring-default` | 200 | 26 | 1 | ~0.92 | Slight settle; window snap, panel slide |
| `spring-gentle` | 160 | 24 | 1 | ~0.95 | Soft, slow; large sheets, drawer |
| `spring-resize` | 300 | 34 | 1 | ~0.98 | Tracks pointer during live resize, minimal lag |

Damping ratios are kept at ≥ 0.9 by policy: no spring in the default system bounces visibly. A more energetic spring would violate the brand's anti-velocity stance and is only permitted behind an explicit theme opt-in.

### 7.4 Rules

1. Respect `prefers-reduced-motion`: when set, all spring and slide motion collapses to a `duration-fast` opacity cross-fade, and decorative motion is removed entirely.
2. Never animate the focus ring's appearance — it must be instant for accessibility.
3. One motion per interaction. Do not compose multiple simultaneous animations on a single element.
4. Motion confirms a state change the user caused; it never plays unprompted (no idle/ambient animation).

---

## 8. Materials — translucency and vibrancy

> **Brand status:** translucency/vibrancy is named as a compositor capability in the development plan (WS7-01.6) but the brand pack does not specify blur or tint levels. This section is introduced by the HIG (WS7-00.7). Tint colors are bound to existing brand semantic tokens; only blur radii and tint opacities are HIG-defined. See [§13](#13-source-traceability).

Materials are GPU-composited translucent surfaces that blur and tint the content behind them (WS7-01.6). They give depth without ornament. Materials are **optional** — the theme engine (WS17-03) can disable them globally, in which case every material falls back to its **opaque equivalent** (the listed solid token), with no loss of legibility or contrast. Text never sits directly on a blurred backdrop without the material's tint layer guaranteeing contrast.

### 8.1 Material levels

| Token | Backdrop blur | Tint token | Tint opacity | Opaque fallback | Use |
|---|---|---|---|---|---|
| `material-thin` | 8 px | `bg-surface` | 60% | `bg-surface` | Inline overlays, hover surfaces |
| `material-regular` | 20 px | `bg-surface` | 75% | `bg-surface` | Popovers, dropdowns, menus |
| `material-thick` | 30 px | `bg-canvas` | 85% | `bg-canvas` | Sidebars, toolbars, window chrome |
| `material-chrome` | 40 px | `bg-canvas` | 92% | `bg-canvas` | Title bars, the top-level menu bar, dock |
| `material-scrim` | 0 px | `bg-inverse` | 40% | `bg-inverse` @ 40% | Modal backdrop dimming behind dialogs |

### 8.2 Vibrancy

"Vibrancy" is the rule that text and icons over a material adopt a tuned variant of the foreground token so they remain legible against the blurred, variable backdrop:

| Backdrop tendency | Vibrant foreground | Source |
|---|---|---|
| Light material (cream/white tint) | `text-primary` at full strength; secondary uses `text-secondary` | brand semantic tokens |
| Dark material (`bg-inverse` tint) | `text-inverse` (cream-300) | brand semantic tokens |

Vibrancy never introduces a new color; it selects between the existing primary/secondary/inverse text tokens based on the material's tint luminance, and the tint opacity is set high enough (≥ 60%) that the chosen token always clears the WCAG floor in [§4.5](#45-wcag-contrast-from-the-brand-contrast-matrix).

### 8.3 Rules

1. Materials are a quality enhancement, not a dependency. The UI must be fully usable with materials off (CPU-fallback compositing, low-power mode, or user preference).
2. Never place AAA-required body text on a material thinner than `material-thick`; reserve thin/regular materials for chrome, controls, and short labels.
3. One material per surface. Do not stack a `material-regular` popover on a `material-thick` sidebar and expect predictable contrast — the popover tints against the already-tinted sidebar's resolved color.
4. The scrim is the only material with zero blur; it dims, it does not frost.

---

## 9. Interactive states

> **Brand status:** focus-ring color (brick-500) and the 44 px minimum target are from the brand pack. The state-overlay opacities, the pressed inset, and the disabled treatment below are introduced by the HIG (WS7-00.8). See [§13](#13-source-traceability).

Every interactive control defines five states. States are expressed as **overlays and token swaps over the control's resting style**, so a single control definition stays consistent across light/dark/high-contrast themes.

### 9.1 State model

| State | Treatment | Tokens / values |
|---|---|---|
| **Rest** | Base style | Control's resting `bg` / `text` / `border` tokens |
| **Hover** | Subtle lift + overlay | `text-primary` overlay at 6% over the surface; `elevation-1` if the control was flush; transition `duration-fast` / `ease-standard` |
| **Focus (keyboard)** | Visible focus ring | 2 px `focus-ring` (brick-500) ring, 2 px offset (`focus-ring-offset` = `bg-canvas`); appears **instantly** (`duration-instant`); never suppressed for keyboard users |
| **Pressed** | Recede inward | `text-primary` overlay at 12%; single inner inset shadow (Y 1 px / blur 2 px / 0.10); scale 0.98 via `spring-subtle`; transition `duration-fast` |
| **Disabled** | Unmistakably inert | Opacity 0.40 of resting style; `text-tertiary` for any text; no hover/press/focus response; `cursor: not-allowed`; removed from focus order |

### 9.2 Selected / active (toggle and selection controls)

| State | Treatment |
|---|---|
| **Selected** | `bg` swaps to `status-info`/`text-accent` (petrol-500) tint at 12%; text to `text-accent`; left/edge marker in `border-accent` for list selection |
| **Active toggle (on)** | Track/fill `status-info` (petrol-500); thumb `bg-surface`; transition via `spring-subtle` |

### 9.3 Rules

1. **Focus is sacred.** The keyboard focus ring is always brick-500, always instant, always 2 px with 2 px offset, and is never removed — only mouse/touch interaction may suppress the ring (`:focus-visible` semantics), keyboard never.
2. Hover is the only state that may add elevation; pressed always recedes (inset), never lifts.
3. Hover and pressed are overlay-based so they compose correctly over any resting color, including status-colored controls.
4. Disabled controls are removed from the focus/accessibility tree, not merely greyed.
5. Mouse hover effects do not apply on touch input; touch uses pressed feedback directly.

---

## 10. Density modes

> **Brand status:** density is named in the development plan (WS7-00.8) and the "Patient / generous whitespace" attribute argues for `regular` as default; the specific control heights and inset values are introduced by the HIG. See [§13](#13-source-traceability).

The theme engine (WS17-03) exposes a density setting. Density changes **spacing and control dimensions only** — never type sizes (which stay on the brand scale) and never the 44 px minimum hit target.

| Property | Compact | Regular *(default)* | Comfortable |
|---|---|---|---|
| Control height (button, input) | 32 px | 40 px | 48 px |
| List row height | 32 px | 40 px | 52 px |
| Window content inset | `space-3` (24 px) | `space-6` (48 px) | `space-8` (64 px) |
| Default control gap | `space-1` (8 px) | `space-2` (16 px) | `space-3` (24 px) |
| Toolbar height | 40 px | 48 px | 56 px |
| Minimum hit target | 44 px (hit area extends beyond the 32 px visual) | 44 px | 48 px |

### 10.1 Rules

1. `regular` is the default — it matches the "Patient / generous whitespace" attribute.
2. `compact` reduces visual size but **never** the 44 px hit target; padding extends the clickable area past the visual control.
3. Type sizes are density-invariant: a `compact` button still uses `text-sm`, it is simply less padded.
4. Density is a single global axis; individual surfaces may not opt to a different density than the system setting (one exception: data-dense tables may force `compact` row height with documented justification).

---

## 11. Iconography

Authoritative source: [`brand/icons/README.md`](../../brand/icons/README.md) and [`brand/icons/icons.svg`](../../brand/icons/icons.svg). Values below are restated from the brand pack without change.

### 11.1 Geometry and behavior

| Aspect | Specification |
|---|---|
| Grid | 24 × 24 viewBox |
| Stroke | 1.5 px baseline at 24 px, `stroke="currentColor"` |
| Fill | `fill="none"` — line-based icons only |
| Caps / joins | Round (round reads "patient"; sharp reads "warning") |
| Color | Inherited from context via `currentColor`; single-color always, no multi-color, no fill states |
| License | SIL OFL 1.1 |

### 11.2 Render sizes

Icons are authored once at 24 px and rendered at standard steps that align to the spacing grid. Stroke weight is held visually consistent across sizes by the renderer.

| Size | Use |
|---|---|
| 16 px | Inline with `text-sm`/`text-xs`, dense toolbars, status pills |
| 20 px | Inline with `text-base`, menu items |
| 24 px | Default — toolbar buttons, list-row leading icons |
| 32 px | Large buttons, empty-state glyphs |
| 48 px | Dialog headers, feature illustrations (sparingly) |

### 11.3 Symbol catalog

The brand sprite ships 16 symbols indexing core NexaCore concepts: `nexacore-mesh`, `nexacore-node`, `nexacore-local-first`, `nexacore-cloud-deny`, `nexacore-attestation`, `nexacore-tee`, `nexacore-kernel`, `nexacore-agent`, `nexacore-inference`, `nexacore-encryption`, `nexacore-mesh-route`, `nexacore-governance`, `nexacore-fork`, `nexacore-ncip`, `nexacore-zk`, `nexacore-anchor`. The full table with usage guidance is in [`brand/icons/README.md`](../../brand/icons/README.md).

### 11.4 Rules

1. Single-color always — `currentColor` only. No filled glyphs, no multi-color glyphs.
2. Abstract over literal: icons index concepts, they do not illustrate scenes.
3. No decorative iconography (sparkles, lightbulbs, rockets), no anthropomorphic AI mascots, no money/finance glyphs.
4. New icons require the concept to appear in [`brand/STRATEGY.md` §8](../../brand/STRATEGY.md) (Lexicon) before being drawn; adding an icon follows the process in [`brand/icons/README.md`](../../brand/icons/README.md) and the brand icon set for WS7-05.

---

## 12. Reference component contract

WS7-00.11 validates this HIG against a reference component — a window with a toolbar, a list, and a dialog — rendered by `nexacore-ui` and compared golden-image against the brand mockups. That component is the executable acceptance test for this document. It must demonstrate, at minimum:

| Element | Tokens exercised |
|---|---|
| Window | `radius-xl`, `elevation-5` (focused) / `elevation-3` (unfocused), `material-chrome` title bar, `bg-canvas` |
| Toolbar | `material-thick`, toolbar height per density, 24 px icons, `space-3` padding |
| List | row height per density, `elevation-1` on hover, selected state ([§9.2](#92-selected--active-toggle-and-selection-controls)), `text-sm` rows |
| Dialog | `radius-lg`, `elevation-4`, `material-scrim` backdrop, `space-6` inset, focus ring on primary action |
| Buttons | five interactive states ([§9](#9-interactive-states)), `radius-md`, `spring-subtle` press |
| Typography | Source Serif 4 dialog title, Inter body/controls, Plex Mono any status pill |

A signed design review accompanies the golden comparison, per WS7-00's verification clause in the development plan.

---

## 13. Source traceability

Every token in this document either restates a value from the brand pack or is introduced by the HIG within a brand-stated constraint. This table lets the `nexacore-ui` token module (WS7-00.10) and the theme engine (WS17-03) reconcile against a single source.

| Section | Status | Source / basis |
|---|---|---|
| §1 Principles | **Restated** | `brand/STRATEGY.md` §4 (five attributes), §4.2 (anti-personality) |
| §1.4 Accessibility floor | **Restated** | `brand/typography/typography.md`, `brand/colors/palette.md` |
| §2 Grid & spacing | **HIG-introduced** | Brand pack has no spacing system. 8 px base derived from "Rigorous / visible grid" + "Patient / generous whitespace". Reconcile with `nexacore-ui`. |
| §3 Typography | **Restated** | `brand/typography/typography.md`, `brand/typography/type-tokens.css` — verbatim |
| §4 Color (ramps, semantic, dark, WCAG) | **Restated** | `brand/colors/tokens.json`, `tokens.css`, `palette.md` — verbatim |
| §5 Elevation & shadows | **HIG-introduced** | Brand pack has no elevation system. Levels/blur/opacity defined here; shadow color bound to `petrol-900` (brand). Restraint follows "Severe / minimal ornament". Reconcile with `nexacore-ui`. |
| §6 Corner radii | **Mixed** | `radius-xs` 2 px fixed by brand status-pill; round-not-sharp rationale from `brand/icons/README.md`. Full scale (sm/md/lg/xl) HIG-introduced. Reconcile with `nexacore-ui`. |
| §7 Motion | **HIG-introduced** | Brand constrains motion ("no velocity", "Patient", no pulsing) in `STRATEGY.md` §4.1–4.2; named curves/durations/springs defined here within that constraint. Reconcile with `nexacore-ui` + WS7-01.9. |
| §8 Materials | **HIG-introduced** | Capability named in the development plan WS7-01.6; tints bound to brand semantic tokens, blur radii + opacities HIG-defined. Reconcile with `nexacore-ui` + WS7-01.6. |
| §9 Interactive states | **Mixed** | focus-ring color (brick-500), 44 px target from brand. Overlay opacities, pressed inset, disabled treatment HIG-introduced. Reconcile with `nexacore-ui`. |
| §10 Density | **HIG-introduced** | Named in the development plan WS7-00.8; default `regular` argued from "Patient". Control heights/insets HIG-defined. Reconcile with `nexacore-ui`. |
| §11 Iconography | **Restated** | `brand/icons/README.md`, `brand/icons/icons.svg` — verbatim |

**Reconciliation note for the orchestrator (WS7-00.10):** the HIG-introduced sections (§2 spacing, §5 elevation, §6 radius scale, §7 motion, §8 materials, §9 state overlays, §10 density) are the values the Rust token module in `crates/nexacore-ui` should adopt as canonical, since the brand pack is silent on them. The restated sections (§3, §4, §11) MUST match the brand pack byte-for-byte; if the `nexacore-ui` crate diverges from the brand pack on those, the brand pack is authoritative and both the crate and this document defer to it.

---

## Related work

| Workstream | Relationship |
|---|---|
| WS7-00.10 | Generates the machine-consumable design-token module in `crates/nexacore-ui` from this document |
| WS7-00.11 | Reference component (window + toolbar + list + dialog), golden-image validated vs brand mockups |
| WS7-01 | GPU compositor implementing soft shadows (§5), rounded clipping (§6), spring motion (§7), materials (§8) |
| WS7-03 | Typography rendering (TrueType, anti-aliasing) for the type system in §3 |
| WS7-05 | Brand icon set with size/weight variants from §11 |
| WS7-16.6 | High-contrast theme derived from the §4 tokens and §4.5 contrast floor |
| WS17-03 | Theme engine consuming the `nexacore-ui` token module: light/dark, accent, density (§10), materials on/off (§8) |

---

`docs/design/nexacore-hig.md · v0.1 · 2026-06-23 · NexaCore OS`
