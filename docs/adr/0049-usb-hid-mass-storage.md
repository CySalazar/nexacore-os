# ADR-0049: USB HID + Mass Storage Class Drivers (TASK-27, DE-E3+E4)

**Status:** Accepted
**Date:** 2026-06-08
**Deciders:** agent analysis under operator-approved PLAN.md TASK-27
**Refs:** PLAN.md TASK-27 (DE-E3+E4, M5), ADR-0048 (xHCI driver, TASK-26),
ADR-0040/0041 (display input channel, TASK-18/19), ADR-0036 (NVMe BLK service,
TASK-14), `crates/nexacore-driver-xhci`, `nexacore_types::{display_channel,blk}`

## Context

On top of the xHCI driver (TASK-26: controller bring-up + EP0-control
enumeration), TASK-27 adds the two device classes a usable computer needs:
(DE-E3) a **HID boot-protocol** driver (keyboard/mouse) feeding the display
server's input channel, and (DE-E4) a **Mass Storage** (BOT/SCSI) driver exposed
as a BLK block service. Both run over the SAME xHCI controller (one keyboard +
one storage stick enumerate on `xhci0`).

Recon (file:line-cited):
- The xHCI lib already has the `EndpointType` enum (Control/Bulk/Interrupt
  In/Out), a per-endpoint `TransferRing`, and `descriptor::walk_config_
  descriptors` (yields Interface + Endpoint items). MISSING: a generic non-EP0
  endpoint-context builder, a `configure_endpoint_trb`, a `normal_trb` (bulk/
  interrupt data), and the enumerate extension (CONFIGURATION descriptor read +
  `SET_CONFIGURATION` + multi-interface).
- HID sink: `nexacore_types::display_channel` — channel `"nexacore.display.input"`,
  `DisplayInputEvent::{Key{code,pressed}, Pointer{x,y,buttons}}` (postcard
  Notification). Printable keys carry ASCII; arrows are `0x80..0x83`; Esc/Enter/
  Backspace/Tab are `0x1B/0x0D/0x08/0x09`. A Ring-3 producer `IpcSend`s events.
- Storage sink: `nexacore_types::blk` — `BlkRegister(76)` `"nexacore.svc.blk.usb0"`,
  serve `BlkRequest::{Read,Write,Flush}` / `BlkResponse` with `BLOCK_SIZE_BYTES
  = 4096` and a `buf_iova` DMA buffer (the NVMe image is the reference loop).
- HID boot: interface class `0x03`/sub `0x01`/proto `1`(kbd)|`2`(mouse); 8-byte
  keyboard report (modifier, reserved, 6 keycodes); `SET_PROTOCOL(boot)` +
  `SET_IDLE(0)`; interrupt-IN polling; key-down/up via diffing consecutive
  reports.
- Mass Storage: interface class `0x08`/sub `0x06`/proto `0x50` (BOT); CBW (31 B,
  sig `0x43425355`) → data (bulk IN/OUT) → CSW (13 B, sig `0x53425355`); SCSI
  INQUIRY / TEST UNIT READY / READ CAPACITY(10) / READ(10) / WRITE(10).
- the test VM test devices: a high-speed `usb-kbd` AND a **SuperSpeed** (5 Gbps)
  `usb-storage` (4096-byte sectors) — so enumeration must be **speed-aware**
  (TASK-26 hardcoded HS / EP0-MPS 64).

## Decisions

### D1 — `hid` + `storage` as modules in `nexacore-driver-xhci` (not separate crates)

The class logic lives in `crates/nexacore-driver-xhci/src/{hid.rs, storage.rs}` (lib,
host-testable), NOT in separate driver crates, because ONE `nexacore-driver-xhci-
image` enumerates BOTH devices on the same controller and dispatches by interface
class. Separate crates would imply independent drivers, which contradicts the
single-controller reality. The image links the lib and runs both state machines.

### D2 — xHCI transfer-endpoint infrastructure (lib)

Add to the lib: `context::write_endpoint_context(buf, ctx_size, ep_type,
max_packet_size, interval, tr_dequeue_ptr_with_dcs, dci)` (generalises the EP0
builder to Bulk/Interrupt IN/OUT); `trb::configure_endpoint_trb(input_ctx_ptr,
slot_id, cycle)` (the Configure Endpoint command, type 12); `trb::normal_trb(
data_ptr, len, dir, ioc, cycle)` (type 1, the bulk/interrupt data TRB). Each
endpoint gets its own `TransferRing`; the device-context-index (DCI) is
`2*ep_num + dir_in` for the doorbell target.

### D3 — Enumeration extension: configuration + SET_CONFIGURATION + speed-aware

The `Enumerator` is extended past the device descriptor to: `GET_DESCRIPTOR(
Configuration)` (full `wTotalLength`), walk it (interface + endpoint descriptors
via the existing walker) to record each interface's class/subclass/protocol and
its IN/OUT endpoints + max packet sizes, then issue `SET_CONFIGURATION(
bConfigurationValue)`. The result the image consumes is a small enumerated-device
record `{ slot_id, speed, class, subclass, protocol, endpoints[] }`. Enumeration
is **speed-aware**: the slot-context speed + the EP0 max-packet-size derive from
the `PORTSC` port speed (HS→64, SuperSpeed→512), and the image enumerates ALL
connected root-hub ports (not just the first), dispatching each by class.

### D4 — HID class driver (DE-E3) → `nexacore.display.input`

For a HID boot interface: Configure Endpoint (the interrupt-IN EP), `SET_PROTOCOL
(boot)` + `SET_IDLE(0)` on EP0, then poll the interrupt-IN transfer ring (a
`normal_trb` pointing at an 8-byte report buffer, doorbell, await the transfer
event). `hid::parse_keyboard_report` + a `HidKeyboardState` that DIFFS the 6
keycode slots against the previous report → `Key{code,pressed}` events (down on
appear, up on disappear); `hid::parse_mouse_report` → pointer button/delta. A
`hid::usage_to_keycode` maps HID usage IDs to the display keycode encoding
(ASCII + the `0x80..0x83`/`0x1B`/`0x0D`/… set). The image postcard-encodes each
`DisplayInputEvent` and `IpcSend`s it to the `"nexacore.display.input"` channel so
the terminal (TASK-22) sees typed characters.

### D5 — Mass Storage class driver (DE-E4) → BLK service `usb0`

For a Mass Storage BOT interface: Configure Endpoint (bulk IN + bulk OUT), then
`BlkRegister` `"usb0"` (+ a reply channel, the NVMe two-channel pattern) and a
serve loop. `storage` provides CBW/CSW codecs (`encode_cbw`, `parse_csw`, the
dCBWSignature/dCSWSignature magic), the SCSI CDB builders (INQUIRY, TEST UNIT
READY, READ CAPACITY(10), READ(10), WRITE(10)), and `blk_request_to_scsi` /
`csw_to_blk_response`. A `BlkRequest::Read{lba,count,buf_iova}` → CBW(READ(10),
count×4096) on bulk OUT → data into `buf_iova` on bulk IN → CSW on bulk IN →
`BlkResponse::Ok`/`DeviceError`. The device is configured with 4096-byte sectors
(matching `BLOCK_SIZE_BYTES`); a non-4096 device would need block translation
(out of scope — the test stick is 4096). At start the driver issues TEST UNIT
READY + READ CAPACITY to confirm the geometry.

### D6 — Error handling + untrusted-input discipline (security)

CSW with `bCSWStatus != 0` → `BlkResponse::DeviceError` (a phase error triggers a
bulk-endpoint `CLEAR_FEATURE(HALT)` reset-recovery, bounded retries); a tag
mismatch is rejected. Every device-written byte (HID reports, INQUIRY/READ
CAPACITY data, the CSW) is length- and signature-checked before use — a short or
malformed report/CSW yields a typed `Err`, never a panic or over-read. The HID
keycode diff ignores the rollover error code (`0x01`) phantom state.

### D7 — Scope boundary

In scope: HID **boot** protocol (keyboard + mouse; not full report-descriptor
parsing), single-LUN BOT/SCSI with the five commands above, 4096-byte-sector
storage, root-hub (non-hub) devices. Out of scope (follow-ups): full HID report
descriptors, multi-LUN, non-4096 sectors with translation, external hubs,
MSI-X (the image keeps cooperative event-ring polling).

## Alternatives considered

- **Separate `nexacore-driver-usb-hid` / `nexacore-driver-usb-storage` crates** —
  rejected (D1): one controller/one image services both; separate crates imply
  independent drivers.
- **A new `usb` service channel for HID** — rejected: the display already has
  `"nexacore.display.input"`; HID feeds the SAME sink as PS/2 so apps need no change.
- **A distinct USB block ABI** — rejected: reusing `BlkRequest`/`BlkResponse`
  means the FS (TASK-15) mounts a USB stick exactly like NVMe.
- **Translating 512-byte sectors** — deferred: the test stick is configured
  4096; translation is a follow-up.

## Consequences

- `nexacore-driver-xhci`: + `hid` + `storage` modules (host-tested: report decode +
  keycode diff, CBW/CSW round-trip + SCSI CDBs + error paths), + transfer-EP
  infra (`write_endpoint_context`, `configure_endpoint_trb`, `normal_trb`), +
  enumerate extension (config descriptor, SET_CONFIGURATION, speed-aware,
  multi-interface).
- `nexacore-driver-xhci-image`: multi-device enumeration + class dispatch; a HID
  service (interrupt-IN poll → `DisplayInputEvent` → `nexacore.display.input`) and a
  Mass Storage service (bulk BOT → BLK `usb0`).
- the test VM: typing on the USB keyboard reaches the terminal (TASK-22); the test USB
  stick does a sector read + a write/read-back byte-identical via BLK (verbatim
  captures), `Page Fault = 0`.
- Full HID report descriptors, multi-LUN, sector translation, external hubs, and
  MSI-X are tracked follow-ups.
