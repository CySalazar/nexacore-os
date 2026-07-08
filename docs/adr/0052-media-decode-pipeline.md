# ADR-0052: Media decode pipeline — library vetting and trait boundary

**Status:** Accepted
**Date:** 2026-06-28
**Deciders:** agent analysis under operator-approved the development plan WS8-02
**Refs:** the development plan WS8-02 (media player), WS2-09 (virtio-snd), WS2-10
(virtio-gpu), ADR-0041 (`nexacore-display` compositor), ADR-0042
(`nexacore-ui`), WS5-03 (`Transcriber` model-gated seam precedent),
`crates/nexacore-media/*`

## Context

WS8-02 requires a media player that plays the common web/desktop formats —
containers MP4, MKV and WebM carrying H.264 / VP9 video and AAC / Opus audio —
on the test VM with the picture on virtio-gpu (WS2-10) and the sound on virtio-snd
(WS2-09), kept in lip-sync.

NexaCore is a from-scratch, capability-secured OS whose Ring-3 components are
`no_std + alloc` and whose security posture (the backlog P5, the driver framework
NCIP-013) is **memory-safety first**: production code is pure Rust, `unsafe` is
`warn`-gated and justified per block. A full video/audio codec is, by contrast,
tens of thousands of lines of performance-critical C (libavcodec, dav1d,
libvpx, openh264) — exactly the kind of large untrusted attack surface the
project keeps out of the trusted path.

Two questions had to be answered before any code (WS8-02.1):

1. **Which decode library**, and on what vetting criteria?
2. **Where is the trust boundary** so that (a) a codec defect cannot corrupt the
   kernel or another app, and (b) the player's own logic stays host-testable and
   the bare-metal target stays `no_std`-clean?

## Decisions

### 1. Library vetting criteria (WS8-02.1)

A decode library is admissible only if it satisfies, in priority order
(Security > Stability > Performance):

| Criterion | Requirement |
|-----------|-------------|
| License | Permissive (MIT / Apache-2.0 / BSD / ISC); no copyleft in the image. |
| Memory safety | Pure Rust preferred. A C decoder is admissible **only** sandboxed in a capability-bound userspace service (the NexaCoreContainer pattern of WS8-01), never linked into the kernel or a privileged process. |
| `no_std` / `alloc` | The container/parse layer must build for `x86_64-unknown-none`. The pixel/PCM decode core may require `std`/SIMD and therefore runs in its own service. |
| Maintenance | Active upstream, CVE-responsive, reproducible builds. |
| Determinism | Bit-exact, single-threaded-reproducible output for the host test/golden harness. |

**Selected direction (stage 1):** pure-Rust [`symphonia`] for demux + audio
(AAC/Opus/MP3/FLAC/Vorbis; Apache-2.0; `no_std`-friendly probe/format layer)
and pure-Rust video where it exists, with C decoders (dav1d for AV1, openh264
for H.264) admitted **only** behind the sandboxed-service boundary below. The
binding is deferred behind the traits in decision 2, so the concrete library is
swappable without touching the player — the vetting fixes the *criteria* and the
*boundary*, not an irreversible dependency.

### 2. The decode library is library-gated behind traits

`crates/nexacore-media` (`nexacore-media`, `no_std + alloc`) is the **host-testable
core** and decodes nothing itself. It owns:

- **Container demuxers** (`container.rs`): ISO-BMFF (MP4) box + sample-table
  reconstruction and EBML (MKV/WebM) walking into `Track`s and time-ordered
  `Packet`s. Pure parsing — fully host-tested.
- **Codec header parsers** (`codec.rs`): H.264 SPS, VP9 uncompressed frame
  header, Opus `OpusHead`, AAC ADTS — enough to size GPU surfaces, configure the
  sound card, and find key-frames *before* the heavy decoder runs.
- **Decoder traits** (`decode.rs`): `VideoDecoder` / `AudioDecoder` are the seam
  where the vetted library binds in. The player drives the traits; the host
  tests drive mocks. This mirrors the WS5-03 precedent where the real ASR model
  lives behind `Transcriber` while the DSP path is host-tested.

Consequence: a codec defect is confined to the decoder implementation (and, for
C decoders, to its sandbox), and the entire orchestration is provable on the
developer host with zero hardware.

### 3. Hardware-accelerated decode with software fallback (WS8-02.8)

`DecoderSelector` consults an `HwProbe` (GPU decode capability) and a
`DecoderFactory`: it prefers a hardware decoder when the probe reports support
**and** the factory can instantiate one, and otherwise falls back to software —
returning `None` only when neither path can build a decoder. The fallback is
exercised by host tests (probe-says-yes-but-construction-declines still yields a
software decoder).

### 4. Output sinks abstract virtio-gpu / virtio-snd (WS8-02.5 / WS8-02.6)

`VideoSink` (→ virtio-gpu, bridged to the `nexacore-display` compositor) and
`AudioSink` (→ virtio-snd) are traits. The host-testable part — the
present/drop/hold scheduling and the audio-buffer fill that drives the master
clock — lives in `sink.rs` with `Headless*` reference implementations; the real
device bridges live in the bootable image crate and are validated on the test VM
(WS8-02.10).

### 5. Integer-microsecond A/V sync (WS8-02.7)

The `AvSyncClock` is **audio-mastered** and uses **integer microseconds**
throughout (no floating point), so the present/drop/wait decision is
deterministic and identical on the host and on `x86_64-unknown-none`. Audio runs
free (resampling audio is lossy); each decoded audio frame advances the master
clock, and video frames are presented, dropped (late beyond the drop threshold),
or held (early) relative to it. The PCM contract reuses
`nexacore_types::ai::{AudioFormat, PcmEncoding}` from WS5-03 rather than
inventing a parallel type.

## Consequences

- **Positive:** the player's demux/parse/sync/playlist logic is fully host-test
  covered; the bare-metal target builds `no_std`; the heavy/untrusted codec is
  isolated and swappable; reusing the WS5-03 audio types keeps the type system
  coherent.
- **Negative / follow-ups:** MP4 composition offsets (`ctts`, B-frame PTS
  reorder) use DTS-as-PTS for now; Matroska Xiph/EBML lacing emits the laced
  payload as a single packet; the concrete `symphonia`/dav1d/openh264 binding,
  the sandboxed-service packaging, and the virtio-gpu/snd bridges are the
  remaining non-host work landed on the test VM (WS8-02.10).
- **Reversibility:** because the library sits behind `VideoDecoder` /
  `AudioDecoder`, swapping the chosen decoder (or moving a codec in/out of the
  sandbox) is a localised change that cannot reach the player or the kernel.

[`symphonia`]: https://github.com/pdeljanov/Symphonia
