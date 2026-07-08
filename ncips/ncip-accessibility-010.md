---
ncip: 10
title: Accessibility — Tree, Focus, Screen Reader, Contrast, Text Scale
track: Standards Track
status: Review
authors: [hello@nexacoreos.com]
created: 2026-06-29
license: CC0-1.0
---

## Abstract

This NCIP specifies the **accessibility (a11y) subsystem** of the NexaCore
desktop: the accessibility tree that exposes each UI control's role and label,
keyboard focus traversal, the screen-reader announcement contract over a
text-to-speech seam, the high-contrast theme with a guaranteed minimum contrast
ratio, and interface text scaling. It makes accessibility a frozen, testable
contract rather than a per-application afterthought.

## Motivation

Accessibility that is bolted on per-application is inconsistent and frequently
absent. For a system targeting a 25-year lifetime and mainstream adoption, the
desktop must expose a uniform, machine-readable accessibility surface that
assistive technology can rely on, and must guarantee baseline affordances
(keyboard-only operation, legible contrast, scalable text) at the toolkit level.
This NCIP fixes that surface so every first-party app — and any third-party app
built on the toolkit — is accessible by construction.

## Specification

### Accessibility tree

- `A11yTree` is a tree of `A11yNode`s; each node carries a `Role` (e.g. button,
  text field, list, heading) and a human-readable label.
- Assistive technology reads the tree to present the UI; the focused node's role
  and label are the unit of announcement.

### Focus

- `FocusManager` owns the keyboard focus and implements traversal in reading
  order: <kbd>Tab</kbd> advances, <kbd>Shift</kbd>+<kbd>Tab</kbd> retreats, via
  `handle_key`. Traversal is total — every interactive node is reachable, and
  the focused node is always defined.
- A focus change yields a `FocusChange` describing the newly-focused node, from
  which an announcement is derived.

### Screen reader

- `ScreenReader` turns a focus change (or an explicit message) into an
  `announcement_request`, delivered to a `TtsEngine` seam. The text-to-speech
  backend is library-gated behind `TtsEngine`; the announcement *contract*
  (what is announced, in what order) is specified here and host-tested.

### Contrast

- `high_contrast_theme` provides a palette whose every foreground/background
  pair meets a minimum contrast ratio, computed by `contrast_ratio_permille`
  (an integer permille luminance ratio, so the check is `no_std`/float-free).
- A conforming theme MUST NOT ship a text/background pair below the minimum
  ratio constant.

### Text scale

- `TextScale` scales interface text by an integer factor without re-laying-out
  to an illegible state; layouts MUST accommodate the supported scale range.

## Rationale

A toolkit-level accessibility tree is the only way to get *consistent* assistive
support — per-app a11y inevitably drifts. Integer-permille contrast keeps the
luminance math `no_std` and deterministic (no floats), matching the rest of the
display stack. Putting TTS behind a `TtsEngine` seam keeps the announcement
logic host-testable and lets the speech backend be chosen/vetted independently,
exactly as the media and PDF codecs are gated. Total focus traversal guarantees
keyboard-only operability, the foundational a11y requirement.

## Backwards Compatibility

N/A — the accessibility subsystem is additive: it introduces new toolkit
surfaces (`A11yTree`, `FocusManager`, `ScreenReader`, high-contrast theme,
`TextScale`) without changing any existing rendering or input contract. Apps
that do not yet populate roles/labels degrade to an unlabelled but still
focusable tree.

## Test Cases

Covered by the host tests in `crates/nexacore-ui/src/a11y.rs`, including focus
traversal order via `FocusManager::handle_key`, the `FocusChange` →
`announcement_request` derivation, `contrast_ratio_permille` meeting the
high-contrast minimum, and `TextScale` bounds.

## Reference Implementation

- `crates/nexacore-ui/src/a11y.rs` — `A11yTree`/`A11yNode`/`Role`, `FocusManager`,
  `ScreenReader` + `TtsEngine` seam, `high_contrast_theme` +
  `contrast_ratio_permille`, `TextScale`.
- Key-driven focus traversal consumes the input stack (NCIP-Input-Stack-009)
  via the display-server channel (NCIP-Display-ABI-008).

## Security Considerations

The screen reader announces the focused control's label, which for a password
or other sensitive field could leak content through audio. A conforming
implementation MUST mark sensitive nodes so the screen reader announces a role
(e.g. "password field") without speaking the entered value. The accessibility
tree exposes only UI structure, not application data, and is consumed in-process
by the toolkit — it is not a cross-process broadcast surface.

## Privacy Considerations

Accessibility metadata (roles, labels, focus position) can reveal what a user is
doing. The accessibility tree is in-process toolkit state and is not logged or
forwarded off-device by this subsystem. Spoken announcements are transient and
local; the sensitive-node rule above prevents secret content from being voiced.

## Copyright

This document is placed in the public domain under
[CC0-1.0](https://creativecommons.org/publicdomain/zero/1.0/).
