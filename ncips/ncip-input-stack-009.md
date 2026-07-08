---
ncip: 9
title: Input Stack — Unified Event Bus (PS/2, USB-HID, ACPI)
track: Standards Track
status: Review
authors: [hello@nexacoreos.com]
created: 2026-06-29
license: CC0-1.0
---

## Abstract

This NCIP specifies the **unified input stack**: the one normalized event format
that every NexaCore OS input source — PS/2 keyboard/mouse, USB-HID, and ACPI
system keys (power, lid, brightness) — funnels into, the pure normalizers that
produce it from raw device bytes, and the routing that splits the stream into
the display-server channel (keys/pointer) versus the power-management path
(system events). It frees per-source decoding from being scattered in-kernel and
gives every source a single, host-testable contract.

## Motivation

Input arrived through divergent paths: the PS/2 pump decoded scancodes in-kernel
and discarded key-release edges, the USB-HID stack produced its own events, and
there was no path at all for ACPI system keys (power button, lid, brightness).
Each source had bespoke decoding with no shared normalized form, so the
compositor and the power-management subsystem could not be fed from one place.
This NCIP defines the common `UnifiedInputEvent`, makes the per-source decoders
pure functions (so the bare-metal pump and ACPI GPE handler become thin shells),
and recovers key-release delivery that the legacy PS/2 path dropped.

## Specification

### Unified event

`UnifiedInputEvent { source: InputSource, payload: InputPayload }` is the single
internal event every source produces:

- `InputSource ∈ { Ps2Keyboard, Ps2Mouse, Usb, Acpi }` — the origin tag.
- `InputPayload`:
  - `Key { code: u8, pressed: bool }` — a key transition; `code` uses the
    NCIP-Display-ABI-008 key-code space; `pressed` distinguishes make from break.
  - `Pointer { x: u32, y: u32, buttons: u8 }` — an absolute pointer update.
  - `System(SystemEvent)` where
    `SystemEvent ∈ { PowerButton, LidOpened, LidClosed, BrightnessUp, BrightnessDown }`.

`UnifiedInputEvent::to_display()` projects the `Key`/`Pointer` subset to a
`DisplayInputEvent` (NCIP-Display-ABI-008) and returns `None` for `System`.

### PS/2 normalization

`normalize_ps2_scancode(scancode, extended) -> Ps2Decode` is a pure function of
a single Set-1 scancode byte plus the caller's running `extended` state:

- `0xE0` yields `Ps2Decode::ExtendedPrefix`; the caller sets `extended = true`
  for the next byte.
- Bit 7 of a non-prefix byte selects make (clear → `pressed = true`) vs break
  (set → `pressed = false`). Key-release is therefore delivered, not dropped.
- The base code maps to a key: control keys (`0x01/0x1C/0x0E/0x0F` →
  Escape/Enter/Backspace/Tab), the extended arrow cluster
  (`0x48/0x50/0x4B/0x4D`), and the US-QWERTY alphanumeric rows to unshifted
  ASCII. Unmapped bytes yield `Ps2Decode::Ignored`.

### ACPI normalization

`normalize_acpi_notify(device, code, lid_open) -> Option<SystemEvent>` decodes
an ACPI `Notify(device, code)`:

- `PowerButton` + `0x80` → `PowerButton`.
- `Lid` + `0x80` → `LidOpened`/`LidClosed`, per the `_LID` state the caller
  read and passes as `lid_open`.
- `Video` + `0x86`/`0x87` → `BrightnessUp`/`BrightnessDown`.
- Any other pair → `None`.

### Routing

`route(event) -> InputRoute` is the single dispatch point: `Key`/`Pointer`
become `InputRoute::Display(DisplayInputEvent)` (forwarded over the
display-input channel); `System` becomes `InputRoute::Power(SystemEvent)`
(handed to power-management, e.g. `PowerButton` → orderly ACPI S5).

## Rationale

Making the normalizers pure (no port I/O, no statics) is what lets them be
host-tested exhaustively while the bare-metal pump and ACPI GPE handler shrink
to "read a register, call the decoder". A source tag on every event preserves
provenance for policy (e.g. distinguishing a synthetic from a physical event)
without a separate channel per source. Routing through one function keeps the
display-vs-power split in a single auditable place rather than smeared across
each source's handler.

## Backwards Compatibility

The unified event is a superset of the existing `DisplayInputEvent`, and
`to_display()` is the lossless projection back to it, so the existing compositor
contract (NCIP-Display-ABI-008) is unchanged. Recovering key-release edges is
additive (see NCIP-Display-ABI-008 § Backwards Compatibility). The legacy
in-kernel PS/2 `decode` remains until the pump is reworked onto the pure
normalizer; both produce the same key codes.

## Test Cases

Covered by the host tests in `crates/nexacore-kernel/src/input_bus.rs`:

- `ps2_make_code_decodes_to_press` / `ps2_break_code_decodes_to_release` — make
  vs break edges.
- `ps2_control_keys_use_keycode_space` — control keys map to the shared key-code
  space.
- `ps2_extended_prefix_then_arrow` — `0xE0` prefix then arrow vs numpad.
- `acpi_power_button_normalizes`, `acpi_lid_uses_read_state`,
  `acpi_brightness_keys_normalize`, `acpi_unknown_pair_is_none` — ACPI decode.
- `keys_route_to_display_system_routes_to_power`,
  `system_event_has_no_display_projection` — routing.

## Reference Implementation

- `crates/nexacore-kernel/src/input_bus.rs` — `UnifiedInputEvent`, `InputSource`,
  `SystemEvent`, `normalize_ps2_scancode`, `normalize_acpi_notify`, `route`.
- `crates/nexacore-kernel/src/bare_metal/input.rs` — the bare-metal PS/2 pump that
  the pure normalizer is factored out of.
- Display projection target: NCIP-Display-ABI-008.

## Security Considerations

The power-management routing means a `PowerButton` event triggers an orderly
shutdown path rather than an unconditional poweroff, so a stray ACPI notification
cannot corrupt state mid-write. Input events remain capability-gated at the
display channel (NCIP-Display-ABI-008); the unified bus does not widen who can
observe keystrokes. The normalizers are total functions over their byte inputs
(every input maps to a defined `Ignored`/`None`/event outcome), so malformed
device bytes cannot drive undefined behaviour.

## Privacy Considerations

The same keystroke-sensitivity applies as in NCIP-Display-ABI-008: the unified
bus carries raw key codes only as far as the routing point, which forwards the
keyboard/pointer subset solely to the capability-holding compositor and never
logs or forwards them off-device. System events (power/lid/brightness) carry no
user content.

## Copyright

This document is placed in the public domain under
[CC0-1.0](https://creativecommons.org/publicdomain/zero/1.0/).
