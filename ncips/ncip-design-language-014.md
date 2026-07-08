---
ncip: 14
title: Design Language — Tokens for Color, Space, Typography, Motion
track: Standards Track
status: Review
authors: [hello@nexacoreos.com]
created: 2026-07-02
license: CC0-1.0
---

## Abstract

This NCIP specifies the NexaCore **design language** as a frozen set of design
tokens: the color palette (five semantic scales plus semantic aliases), the
8-point spacing scale, the typographic system (font families, a modular type
scale, line-height and letter-spacing steps), and the shared motion/elevation
primitives. Tokens are the single source of truth every NexaCore surface — the
compositor UI, native apps, and the website — references by name, so the product
looks like one system rather than many.

## Motivation

A "100% daily-use, macOS-grade" desktop needs visual consistency that survives
dozens of components authored over years. Hard-coded colors and ad-hoc spacing
diverge immediately; a named token layer makes consistency the path of least
resistance and makes global re-theming (light/dark, high-contrast a11y) a change
in one place. Freezing the tokens as a lintable contract also lets the website
and the OS share exact values.

## Specification

### Color

Colors are `0xAARRGGBB` `u32` constants (premultiplied-friendly, alpha-first).
Five perceptual scales, each with numbered stops (`50`…`900`, darker as the
number grows): **Petrol** (primary brand), **Cream** (warm neutral surface),
**Brick** (error/destructive), **Sage** (success/positive), **Charcoal**
(text/neutral). Semantic aliases (`BG_SURFACE`, `STATUS_WARNING`, …) name a *role*
and resolve to a scale stop, so components reference intent, not a raw hue.

### Spacing

An 8-point grid: `space::BASE = 8`. Steps `S0`(0), `PX`(1), `HALF`(4),
`S1`(8) … `S10`(80). Layout MUST compose from these steps rather than arbitrary
pixel values.

### Typography

Font families: `FONT_DISPLAY`, `FONT_BODY` (Inter stack), `FONT_MONO` (IBM Plex
Mono stack). A modular type scale `SCALE_PX = [12, 14, 16, 20, 25, 31, 39, 49,
61]` (≈1.25 ratio) with named aliases `TEXT_XS`…`TEXT_5XL`. Line-height steps
`LEADING_TIGHT`(1.15)…`LEADING_RELAXED`(1.6) and letter-spacing steps
`TRACKING_TIGHT`(−0.015)…`TRACKING_WIDEST`(0.12).

### Motion and elevation

Shared spring/elevation primitives are consumed by the compositor
(`nexacore-display`, WS7-01) via raw values mirroring these tokens (the display
layer sits below `nexacore-ui` and cannot import the token module, so the token
values are duplicated as constants there and the binding happens in the UI
layer). Animations are vsync-locked (WS7-12).

## Rationale

`u32` `AARRGGBB` constants match the compositor's pixel format directly (no
conversion on the paint path). Alpha-first, premultiply-friendly ordering suits
the blend routines in `nexacore-display::color`. The 8-point grid and 1.25
modular scale are chosen because they compose cleanly at all HiDPI scale factors
(WS7-04) — every step stays integral at 1×/2× and near-integral at 1.5×. Naming
roles (semantic aliases) rather than hues is what makes a future re-theme a
one-file change.

## Backwards Compatibility

N/A — the tokens are the baseline design contract; there is no prior public token
API to preserve. The compositor's mirrored constants are kept in sync with these
by review.

## Test Cases

Host tests in `crates/nexacore-ui/src/tokens.rs` (and its consumers) assert token
availability and, for contrast-sensitive pairs, that foreground/background token
combinations meet the accessibility contrast ratio computed by
`nexacore-ui::a11y` (NCIP-010). The build fails (`deny(missing_docs)`) if any
token lacks documentation.

## Reference Implementation

`crates/nexacore-ui/src/tokens.rs` (module `nexacore_ui::tokens`, submodules
`color`, `space`, `typography`, …). Plan task WS7-00. The website's `tokens.css`
mirrors the same values for the public site.

## Security Considerations

Design tokens are static presentation constants with no runtime authority, no
input parsing, and no effect on the capability model, so they add no direct
attack surface. The security-relevant property they *do* carry is legibility:
because contrast-bearing color tokens exist and are paired with the
accessibility contrast check (NCIP-010), security-critical UI — permission
prompts, escalation dialogs, and warnings — can be guaranteed to render at a
readable contrast rather than being defeated by an illegible theme. Consumers
MUST use the status/semantic tokens for such UI rather than arbitrary colors.

## Privacy Considerations

Tokens carry no user data and emit no telemetry; referencing a token reveals
nothing about a user. Theme selection (light/dark/high-contrast), when added, is
a purely local preference stored through the configuration store (NCIP-015) and
MUST NOT be transmitted or used as a fingerprinting signal.

## Copyright

This document is placed in the public domain under CC0-1.0.
