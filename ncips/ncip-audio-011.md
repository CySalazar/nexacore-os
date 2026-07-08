---
ncip: 11
title: Audio Stack — DE-H2 ABI, Mixer, Device Routing, HDA/virtio-snd Codecs
track: Standards Track
status: Review
authors: [hello@nexacoreos.com]
created: 2026-06-29
license: CC0-1.0
---

## Abstract

This NCIP specifies the **audio subsystem** of NexaCore OS: the DE-H2
userspace↔kernel audio ABI (PCM stream open/close, format negotiation, volume),
the user-space mixer that sums per-application PCM streams with saturating
integer arithmetic, device routing (output/input default selection), and the
on-the-wire command codecs for the two supported audio devices — the Intel HDA
controller (CORB/RIRB verbs, Buffer Descriptor Lists) and the virtio-snd
paravirtual device (control/tx/rx messages). It freezes the byte layouts and
mixing semantics as a testable contract.

## Motivation

Before this NCIP NexaCore had no audio: no driver, no mixer, no playback/capture
ABI. A "100% daily-use" desktop and the `ai_transcribe` capability both require
audio. Without a frozen contract, each application would re-derive PCM framing
and each device backend would risk incompatible volume/mix behaviour (notably
integer overflow producing audible artefacts or cross-stream noise injection).
This NCIP fixes the ABI and the mixer's numerical behaviour so applications,
the mixer service, and the device drivers interoperate deterministically.

## Specification

### DE-H2 audio ABI

A PCM stream is described by a `PcmFormat` (`S16Le`, `S24Le`, `S32Le`, `F32Le`)
and a channel count; `frame_bytes = bytes_per_sample(format) * channels`.
`S16Le` occupies 2 bytes/sample; the wider formats occupy 4. Userspace issues
`AudioRequest`:

- `OpenPlayback { format, rate_hz, channels }` / `OpenCapture { … }` → the
  kernel replies `AudioResponse::Opened { stream_id }`.
- `SetVolume { stream_id, percent }` — `percent` is clamped to `0..=100`.
- `Close { stream_id }`.

Responses are `Opened { stream_id }`, `Ok`, or `Error { reason }` where `reason`
is a PII-safe `&'static str`. The canonical wire encoding routes through
`nexacore-types::wire` (postcard) at the syscall boundary, per `NCIP-Serde-004`.

### Mixer

The mixer sums signed-16-bit PCM streams sample-wise. Each stream may carry a
`Volume` (a percentage `0..=100`); `Volume::apply(sample) = sample * percent /
100`, computed in `i32` and truncated toward zero. Stream summation MUST be
**saturating** at the `i16` range: a sum exceeding `i16::MAX`/`i16::MIN` clamps
to the rail rather than wrapping. The output length equals the longest input;
shorter streams contribute silence past their end.

### Device routing

The audio service tracks registered output and input devices and one default
per direction. Routing is **fail-closed**: with no device registered for a
direction, the default is absent and a stream is left unrouted (never routed to
a device that was not enumerated). The first device registered in a direction
becomes that direction's default; switching the default to an unregistered
device is refused.

### HDA codec

A codec verb is the 32-bit value `cad[31:28] | nid[27:20] | verb[19:8] |
payload[7:0]` written into the CORB ring. A RIRB response is a 64-bit value
`response | resp_ex << 32`, where `resp_ex[3:0]` is the codec address and bit 4
marks an unsolicited response. The `STATESTS` bitmap enumerates present codecs
(bit `n` ⇒ codec at address `n`, `n ∈ 0..=14`). HDA DMA streams are fed by a
Buffer Descriptor List of 16-byte entries `addr: u64, length: u32, flags: u32`
where flag bit 0 is interrupt-on-completion.

### virtio-snd

Control requests use a 4-byte `virtio_snd_hdr` code (`PCM_INFO` `0x0100` …
`PCM_STOP` `0x0105`); responses use the status range (`OK` `0x8000` …). A
`PCM_SET_PARAMS` request is the 24-byte structure `code, stream_id,
buffer_bytes, period_bytes, features, channels, format, rate, padding`. PCM data
on the tx (playback) and rx (capture) queues is prefixed by a 4-byte
`virtio_snd_pcm_xfer` header carrying the `stream_id`.

## Rationale

The mixer is specified as integer + saturating because (a) it must run with no
FPU assumptions in any context and (b) wrap-around on overflow is both an
audible defect and a cross-stream integrity hazard — a loud or malicious stream
could inject wrap noise into the shared mix. Fail-closed routing mirrors the
capability model used elsewhere in NexaCore: absence of an explicit grant
(here, an enumerated device) denies rather than guesses. The HDA and virtio-snd
byte layouts follow their respective upstream specifications verbatim so the
driver is interoperable with real and emulated hardware.

## Backwards Compatibility

N/A — this is the first audio specification; there is no prior audio ABI to
remain compatible with. Future format or request additions are additive: the
`PcmFormat` and `AudioRequest`/`AudioResponse` enums gain variants behind a
version bump, never re-number existing ones.

## Test Cases

The reference implementation's unit tests cover: per-format frame sizing; mixer
summing, saturation (no wrap), longest-stream length, and weighted (volume)
mixing; volume clamping and symmetric scaling of negative samples; fail-closed
routing (empty router routes nothing; unregistered default refused;
per-direction independence); HDA verb encoding and RIRB/`STATESTS` decoding; BDL
entry layout and IOC flag; and the virtio-snd `PCM_SET_PARAMS` / `PcmXferHdr`
byte layouts.

## Reference Implementation

`crates/nexacore-driver-audio` (`nexacore-driver-audio`, `no_std + alloc`): `abi.rs`
(DE-H2), `mixer.rs` (`Mixer`, `Volume`), `routing.rs` (`AudioRouter`), `hda.rs`
(`make_verb`, `decode_response`, `present_codecs`, BDL in `bdl.rs`),
`virtio_snd.rs` (control/PCM messages). The MMIO/DMA bring-up, the
buffer-completion IRQ, and the live tone/loopback verification on the VM-103 rig
are device-side and tracked separately (WS2-10.7, WS2-10.12).

## Security Considerations

The mixer's saturating arithmetic prevents a stream from injecting wrap-around
noise into the shared output. Routing is fail-closed, so a stream is never
attached to a device the user did not enumerate. Per-application volume is
clamped to a valid range, so a malformed request cannot scale a stream past
unity. Device backends remain capability-mediated by the surrounding service;
this NCIP specifies only the codecs and mixing, not privilege.

## Privacy Considerations

Captured audio is sensitive personal data. Capture streams MUST be opened only
under an explicit microphone capability granted to the requesting application;
the routing service exposes device identifiers (opaque integers) but never
captured sample content to unrelated streams. Error responses carry only static
slugs, never sample data or device paths.

## Copyright

This document is licensed CC0-1.0. The reference implementation is Apache-2.0.
