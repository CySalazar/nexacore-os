---
ncip: 8
title: Display-Server ABI — Compositor Input/Output Channel
track: Standards Track
status: Review
authors: [hello@nexacoreos.com]
created: 2026-06-29
license: CC0-1.0
---

## Abstract

This NCIP specifies the **display-server ABI**: the stable contract between the
NexaCore microkernel and the Ring-3 compositor. It defines the named IPC channel
over which the kernel delivers input events to the compositor, the
`DisplayInputEvent` wire type and its canonical postcard encoding, the logical
key-code space, and the bounded event size. It freezes what was previously an
ad-hoc, code-only convention (`crates/nexacore-types/src/display_channel.rs` and
`docs/13-display-server-abi.md`) into a lintable specification so the compositor
and the kernel can evolve independently against a versioned surface.

## Motivation

The desktop compositor runs in Ring 3 and receives every keyboard and pointer
event from the kernel's input subsystem over IPC. Until now the event type, its
encoding, the key-code numbering, and the channel name lived only in source and
a prose doc, with no frozen, machine-checkable contract. New input event kinds
(navigation keys, key-release edges, future touch) have been added incrementally
without a versioning discipline, and a third-party or alternative compositor had
no normative surface to target. This NCIP makes the ABI explicit, bounded, and
forward-compatible.

## Specification

### Channel

- The kernel delivers input to the compositor over the IPC channel named
  `nexacore.display.input` (constant `display_channel::CHANNEL_NAME`).
- Each event is the payload of a single `MessageKind::Notification` IPC message.

### Event type

`DisplayInputEvent` is a `#[non_exhaustive]` enum with two variants:

- `Key { code: u8, pressed: bool }` — a keyboard key transition. `code` is a
  logical key code (see below). `pressed` is `true` on make (press), `false` on
  break (release).
- `Pointer { x: u32, y: u32, buttons: u8 }` — an absolute-coordinate pointer
  update. `x`/`y` are pixels in `0..screen_dimension`; `buttons` is a mask with
  bit 0 = left, bit 1 = right, bit 2 = middle.

The enum is `#[non_exhaustive]`: receivers MUST tolerate unknown future
variants (a conforming compositor ignores variants it does not recognize rather
than failing).

### Encoding

Events are serialized with the workspace canonical postcard encoding
(`nexacore_types::wire::encode_canonical`) and decoded with `decode_canonical`.
A conforming encoder MUST NOT emit an event whose encoded length exceeds
`display_channel::MAX_EVENT_BYTES` (32 bytes); a conforming receiver MAY use a
fixed-size receive buffer of that length.

### Key-code space

Printable keys carry their 7-bit ASCII byte directly in `Key::code`.
Non-printable control and navigation keys use the `display_channel::keycode`
constants: `ESCAPE = 0x1B`, `ENTER = 0x0D`, `BACKSPACE = 0x08`, `TAB = 0x09`
(the ASCII control codes), and the four arrows in the private `0x80..=0x83`
range (`ARROW_UP`, `ARROW_DOWN`, `ARROW_LEFT`, `ARROW_RIGHT`) so they never
collide with printable ASCII.

### Versioning

The ABI is identified by this NCIP number. Adding a new `DisplayInputEvent`
variant or a new reserved key code is a backward-compatible minor change
(receivers ignore unknown variants/codes). Changing the meaning or encoding of
an existing variant, or lowering `MAX_EVENT_BYTES`, is a breaking change that
requires a superseding NCIP.

## Rationale

Absolute pointer coordinates (rather than deltas) keep the compositor free of
acceleration/clamping policy in the wire type — the kernel-side input
normalization owns that. A flat `u8` key-code space (ASCII for printables, a
small private range for navigation) avoids a large keysym table at the ABI
boundary while remaining unambiguous. `#[non_exhaustive]` plus a fixed
`MAX_EVENT_BYTES` makes the surface both extensible and safe for a fixed receive
buffer. Postcard canonical encoding is already the workspace's wire standard, so
the channel introduces no new serialization dependency.

## Backwards Compatibility

This NCIP documents the existing, shipped contract; it introduces no change to
the wire type or encoding. The `pressed` flag already existed for exactly the
key-release edge that the WS2-08 unified input bus now produces, so enabling
key-up delivery is additive — a compositor that previously saw only presses
continues to function and now additionally observes releases.

## Test Cases

Covered by the host tests in `crates/nexacore-types/src/display_channel.rs`:

- `key_event_round_trips` — a `Key` event encodes and decodes byte-identically
  and fits `MAX_EVENT_BYTES`.
- `pointer_event_round_trips` — a `Pointer` event round-trips and fits the bound.
- `max_event_bytes_bounds_worst_case` — the widest event (two `u32::MAX`
  coordinates + full button mask) stays within `MAX_EVENT_BYTES`.
- `navigation_keycodes_are_distinct_from_printable_ascii` — the arrow codes do
  not collide with printable ASCII.

## Reference Implementation

- Wire type, channel name, key-code space, size bound:
  `crates/nexacore-types/src/display_channel.rs`.
- Kernel-side normalization feeding the channel: `crates/nexacore-kernel/src/input_bus.rs`
  (`UnifiedInputEvent::to_display`, `route`), specified by NCIP-Input-Stack-009.
- Prose companion: `docs/13-display-server-abi.md`.

## Security Considerations

The channel is capability-gated: only the task holding the display-input
capability (the compositor) receives events, so a malicious Ring-3 process
cannot subscribe to the user's keystrokes. The fixed `MAX_EVENT_BYTES` bound and
the fixed-size receive buffer it permits remove a class of unbounded-allocation
and buffer-overrun risks at the boundary. Because events are `#[non_exhaustive]`,
a receiver that ignores unknown variants cannot be driven into undefined
behaviour by a future kernel that emits a variant it does not understand.

## Privacy Considerations

Keystrokes and pointer activity are sensitive: they can reveal typed secrets and
user intent. Restricting delivery to the single capability-holding compositor —
rather than a broadcast — is the privacy boundary. No input event is logged or
forwarded off-device by this ABI; any downstream handling (e.g. text fields)
remains subject to the system's tokenization and privacy-budget rules.

## Copyright

This document is placed in the public domain under
[CC0-1.0](https://creativecommons.org/publicdomain/zero/1.0/).
