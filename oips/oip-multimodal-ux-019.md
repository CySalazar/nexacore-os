---
ncip: 19
title: Multichannel user experience — voice, vision, messaging, and A11y as first-class OS surfaces
track: Standards Track
status: Draft
authors:
  - cySalazar <hello@nexacoreos.com>
created: 2026-05-22
updated: 2026-05-22
requires:
  - NCIP-Process-001
  - NCIP-Helper-007
  - NCIP-Container-006
supersedes: ~
superseded-by: ~
discussion: https://github.com/CySalazar/nexacore-os/discussions (TBD link)
license: CC0-1.0
---

## Abstract

This NCIP commits NexaCore OS to a first-class **multichannel user-interaction surface**
that lets a user drive the system by **voice** (push-to-talk speech-to-text and
text-to-speech), **vision** (opt-in webcam capture for contextual prompts), **text**
(the existing intent-based shell), and **outbound messaging** (email, Matrix,
Telegram, optionally WhatsApp via supported Business APIs), with **accessibility
(A11y)** — screen reading, live captioning, voice-driven navigation — treated as a
canonical consumer of the same stack rather than a bolt-on.

The design adds two HAL traits (`AudioDevice`, `VideoDevice`), three AI Runtime
syscalls (`ai_listen`, `ai_speak`, `ai_see`) peer to the already-declared
`ai_transcribe`, new capability variants (`AudioCapture`, `AudioPlayback`,
`VideoCapture`, `Notify`, `MessagingEgress(Channel)`), and a normative intent
pipeline that reuses the NCIP-Helper-007 autonomy levels and Impact Dashboard. All
ML inference runs **Tier 0 (on-device) by default**; PII flowing toward third-party
messaging providers is **mandatorily tokenized**; no closed proprietary messaging
client lives in the NexaCore TCB.

---

## Motivation

Two project-level forces push for this NCIP:

1. **Stated ambition meets a missing UX layer.** NexaCore's vision (`docs/01-vision.md`)
   targets mainstream adoption with privacy-by-construction. Mainstream voice and
   visual assistants exist on every competing OS (Cortana, Siri, Google Assistant),
   yet all of them route user audio to a cloud backend. NexaCore can offer the same
   ergonomics with no exfiltration. Without this NCIP, voice and vision remain
   nowhere on the roadmap and the existing `ai_transcribe` syscall
   (`docs/02-architecture.md:78`) has no microphone to consume from.
2. **Accessibility.** Today the codebase contains zero references to A11y, screen
   readers, or captioning. For a production OS targeting "10M+ users over 25 years"
   (`docs/01-vision.md`) this is a structural gap. The same audio stack that powers
   voice control trivially powers a native screen reader and live captioning — A11y
   is the cheapest possible follow-on, not a separate engineering programme.

Concrete evidence of the current gap, as of 2026-05-22:

- `crates/nexacore-hal/src/lib.rs` exposes only `tensor`, `network`, `storage`, `tee`. No
  `AudioDevice`, no `VideoDevice`, no generic human-input-device trait.
- No driver crate covers audio or video; no USB host controller is present.
- Repository-wide search for `microphone|webcam|voice|stt|tts|whisper|telegram|
  whatsapp|smtp|imap|notification|accessibility|screen reader` returns zero matches
  in code.
- `ai_transcribe(model, audio, capability) -> text` is declared in
  `docs/02-architecture.md:78` but has no caller and no audio source.

Cloud-bound assistants are the cautionary case: Windows Copilot, Siri, and Google
Assistant all require third-party data flows by default. NexaCore's pitch — "a voice
assistant that cannot phone home unless you explicitly opt in" — is achievable only
if the OS owns the audio path end-to-end.

---

## Specification

The keywords MUST, SHOULD, MAY follow RFC 2119.

### 1. HAL surface

#### 1.1 `AudioDevice` trait

A new `AudioDevice` trait MUST be added to `nexacore-hal` and MUST live alongside the
existing `tensor`/`network`/`storage`/`tee` HAL surfaces. The trait MUST expose:

- `open(direction: Direction, format: PcmFormat) -> Result<Stream>` where
  `Direction ∈ {Capture, Playback, Duplex}` and `PcmFormat` carries sample-rate,
  channel-count, sample-format (s16le/f32le minimum).
- `read(stream, buf) -> Result<usize>` and `write(stream, buf) -> Result<usize>`
  for capture and playback respectively.
- `close(stream) -> Result<()>`.
- `enumerate() -> Vec<DeviceInfo>` where `DeviceInfo` includes a stable opaque
  device id (the kernel-attested hash of bus path + descriptor), human label, and
  the formats the device supports.

The trait MUST NOT expose IRQ numbers, MMIO pointers, or DMA addresses to its
callers; those remain inside the user-mode driver process.

#### 1.2 `VideoDevice` trait

A new `VideoDevice` trait MUST be added to `nexacore-hal` with:

- `open(format: PixelFormat, resolution: Resolution, fps: u32) -> Result<Stream>`.
- `read_frame(stream, buf) -> Result<FrameMeta>` returning a frame and its
  monotonic-clock timestamp.
- `controls(stream) -> ControlSurface` for exposure / focus / white balance.
- `close(stream) -> Result<()>`.
- `enumerate()` as above.

Minimum required `PixelFormat` set: `Yuyv422`, `Nv12`, `Mjpeg`. Drivers MAY add
more.

#### 1.3 Driver location and isolation

Driver implementations MUST run as user-mode driver processes bound by per-domain
IOMMU (compatible with the work landing at P6.7.9-pre.10). Drivers MUST NOT run in
kernel mode. The first reference driver SHOULD be **USB Audio Class 1.0** for audio
and **USB Video Class 1.1** for video, because those classes cover the broadest
hardware base with the smallest driver footprint. On-SoC codec and on-SoC ISP
drivers MAY follow in subsequent NCIPs.

### 2. Capabilities

The following capability variants MUST be added to the kernel capability system in
`crates/nexacore-kernel/src/capabilities.rs`, peers of the existing `IpcSend`/`IpcRecv`
variants:

| Variant | Resource type | Semantics |
|---|---|---|
| `AudioCapture` | `AudioDevice(DeviceId)` | Allows reading PCM samples from a specific audio device. |
| `AudioPlayback` | `AudioDevice(DeviceId)` | Allows writing PCM samples to a specific audio device. |
| `VideoCapture` | `VideoDevice(DeviceId)` | Allows reading video frames from a specific video device. |
| `Notify` | `NotificationChannel(ChannelId)` | Allows posting user-visible notifications on a per-app channel. |
| `MessagingEgress` | `MessagingChannel(ChannelKind)` | Allows sending an outbound message via a specified channel kind. |

Where `ChannelKind` is the enum:

```rust
enum ChannelKind {
    Email,        // SMTP via local adapter or container
    Matrix,       // open-protocol, preferred default
    Telegram,     // Telegram Bot API only
    WhatsApp,     // WhatsApp Business API only
    Sms,          // via a connected modem or carrier bridge
    Custom(u32),  // adapter-defined, must be registered
}
```

Requirements on all five new capability variants:

- Default policy MUST be **deny**.
- TTL SHOULD be ≤ 30 minutes by default; the user MAY raise per-context.
- Capabilities MUST be attenuable (Macaroons-style, as the existing capability
  system).
- Capability grants for `AudioCapture` and `VideoCapture` that exceed 60 minutes,
  or that request continuous capture, MUST be classified as
  **Privacy-violating** under NCIP-Helper-007 § 3 and therefore MUST escalate to
  at least `Guided`.

### 3. AI Runtime syscalls

The AI Runtime Service (`crates/nexacore-runtime`) MUST add three syscalls peer to the
already-declared `ai_invoke` / `ai_stream` / `ai_embed` / `ai_classify` /
`ai_transcribe` (`docs/02-architecture.md:74–78`):

- `ai_listen(model, audio_cap, opts) -> Stream<Utterance>` — push-to-talk speech
  capture + on-device STT. `audio_cap` MUST be a valid `AudioCapture` capability.
- `ai_speak(model, text, audio_cap, opts) -> Result<()>` — on-device TTS to a
  playback device. `audio_cap` MUST be a valid `AudioPlayback` capability.
- `ai_see(model, video_cap, opts) -> Stream<VisionEvent>` — opt-in vision events
  (object detection, scene classification, document OCR) from a webcam.
  `video_cap` MUST be a valid `VideoCapture` capability.

All three calls MUST refuse without a valid capability; the AI Runtime MUST log
each invocation to the per-user audit log; Tier 0 MUST be the default execution
tier; routing to Tier 1+ MUST require an explicit user policy.

Reference candidate models (informative, not normative):

- STT: Whisper-tiny class (~39M params, ~80MB quantized).
- TTS: Piper class (~60M params, ~120MB).
- Vision: Mobile-classifier class (e.g. MobileNetV3 / EfficientNet-lite,
  ~5–20M params, ~10–40MB quantized).

All three classes fit the Tier 0 envelope on commodity laptops without breaking
the `tokens-per-second-per-watt` first-order metric (`docs/01-vision.md`).

### 4. Intent pipeline (normative)

Every voice or vision invocation that produces an actionable intent MUST flow
through this pipeline before any side-effecting operation:

```
ai_listen / ai_see  →  nexacore-tokenization (PII → token)  →  nexacore-agent planner
   →  Impact Dashboard (NCIP-Helper-007)  →  user approval  →  capability-bound exec
   →  per-user audit log
```

Requirements:

1. The planner MUST tag every plan with the **input channel** (`voice`, `vision`,
   `text`) and the **source device id**. Provenance MUST be visible in the Impact
   Dashboard.
2. Any plan whose action class falls under NCIP-Helper-007 § 3 (Destructive,
   Privacy-violating, Capability-escalation, Borderline) MUST be presented in at
   least `Guided` mode regardless of the user's configured autonomy level.
3. "Send a message on the user's behalf to a third party" is by definition
   **Destructive** per NCIP-Helper-007 § 3 and MUST NOT be silently auto-executed.
4. The Impact Dashboard MUST score Privacy / Trust / Cost / Time for every plan,
   exactly as NCIP-Helper-007 § 4 specifies. This NCIP does not redefine those
   scores.
5. The audit log entry MUST include: input channel, source device id, transcribed
   text (post-tokenization), generated plan, capability set requested, user
   decision, executor result.

### 5. Messaging egress policy

For any plan that requests a `MessagingEgress(Channel)` capability:

- The adapter that materializes the egress MUST run **userspace**, never in the
  microkernel TCB.
- The adapter SHOULD run inside an `NexaCoreContainer` (NCIP-Container-006) when it
  links proprietary or third-party libraries. SMTP / Matrix adapters MAY run as
  native userspace services because their protocols are open.
- Outbound message bodies MUST be passed through `nexacore-tokenization` **before**
  the adapter sees them, unless the user has set a per-context override that
  permits raw PII egress for the specific channel. The default policy is
  `tokenize-or-refuse`.
- Per-channel rules:
  - `Email` — SMTP/IMAP via sandboxed adapter; PGP/S-MIME signing SHOULD be
    available; MUST default to STARTTLS-required.
  - `Matrix` — preferred open-protocol default; end-to-end encryption MUST be
    enabled.
  - `Telegram` — Bot API only; the user's personal Telegram account is **not**
    accessed by NexaCore; the user explicitly provisions a bot token.
  - `WhatsApp` — WhatsApp Business API only; same provisioning rule as Telegram.
    Personal WhatsApp accounts are out of scope for this NCIP.
  - `Sms` — via connected modem (PPP / RIL-equivalent) or an explicit
    carrier-bridge adapter.
  - `Custom(u32)` — adapter MUST register a manifest with the same fields as the
    NCIP-Container-006 `io.nexacore-os.capabilities-required` annotation.

### 6. Accessibility minima

Implementations claiming compliance with this NCIP MUST provide, on at least one
reference hardware target:

- A **native screen reader** consuming `ai_speak`, navigating the shell intent UI,
  driven by a `Tab`-equivalent and arrow-key navigation that also responds to
  voice intents ("read next", "stop").
- **Live captioning** for any system-initiated audio output (system notification,
  TTS reading) via `ai_listen` on the playback channel.
- **High-contrast and reduced-motion** profiles selectable from `nexacore-shell`
  without restart.

Captioning SHOULD also be available for incoming voice messages received via
`MessagingEgress` channels that support voice notes.

### 7. Wake-word and continuous listening

Wake-word ("Hey NexaCore") and continuous listening are **explicitly out of scope** for
this NCIP. They MAY be introduced by a future NCIP that:

- Requires opt-in beyond `Autonomous`.
- Routes the always-on inference into a dedicated low-power VAD model inside the
  TEE so that PCM samples never leave the secure boundary until a confirmed wake.
- Re-classifies "watch-always-on" as the same privacy class as in
  NCIP-Helper-007 § 1.

Until that NCIP lands, voice input MUST be **push-to-talk** (hardware key, hotkey,
or sustained activation gesture).

---

## Rationale

Two design forks were seriously considered and rejected.

### Alternative A — leave audio/video entirely to userspace, no new HAL traits

Pros: smallest kernel surface; no new capability variants.

Cons:

- Without HAL traits, every audio app reinvents PCM plumbing and every webcam app
  reinvents V4L2-equivalent code; this duplicates effort and produces inconsistent
  security review surfaces.
- Capability tokens lose meaning if every adapter declares its own device-id
  format; you cannot revoke "microphone access" centrally.
- Accessibility apps cannot be policy-blessed (system-trust) if they go through a
  third-party userspace audio layer that the NexaCore kernel cannot reason about.

This is the WSL1 / leaky-shim risk in another guise.

### Alternative B — route audio/video through a PulseAudio-or-PipeWire-equivalent inside an NexaCoreContainer

Pros: reuses an existing well-known userspace stack.

Cons:

- Pulls thousands of lines of Linux userspace into the boot path of any A11y
  consumer. Heavy compared to a thin user-mode USB Audio driver against a small
  trait.
- A11y latency is dominated by the audio plumbing; container-bound audio adds
  ≥ 20–50 ms typical, which is noticeable for a screen reader.
- Forces every voice or A11y interaction to start a micro-VM. This is the wrong
  power profile for laptops and handhelds.

NexaCoreContainer remains the right place for proprietary or third-party messaging
adapters (per § 5), but not for the audio path itself.

### Why reuse NCIP-Helper-007 verbatim

NCIP-Helper-007 already specifies three autonomy levels, an escalation taxonomy,
and an Impact Dashboard. Inventing a parallel UX policy surface for voice would
fragment user expectations and double the audit story. Reuse is the right call.

### Why exclude wake-word from MVP

Continuous listening is the single largest privacy hazard a voice OS can have. It
deserves its own NCIP, its own threat model section, and its own TEE story.
Push-to-talk delivers the ergonomic win without the hazard.

---

## Backwards Compatibility

N/A — first introduction. No prior audio, video, messaging, or A11y surface
exists. The new HAL traits and capability variants are additive; the existing
`tensor`/`network`/`storage`/`tee` HAL traits and `IpcSend`/`IpcRecv` capability
variants are unchanged. The already-declared `ai_transcribe` syscall keeps its
signature; the new `ai_listen` is a peer that may share underlying models.

---

## Test Cases

A reference test suite SHOULD include:

1. **STT correctness.** Whisper-tiny class model transcribes a fixed clip
   (LibriSpeech `dev-clean` sample, declared in test vectors) within an acceptable
   word-error-rate bound on the reference Tier-0 hardware.
2. **TTS correctness.** Piper-class model produces audible output for a fixed
   input sentence; output bit-depth and sample rate match the requested
   `PcmFormat`.
3. **Vision correctness.** Mobile-classifier-class model labels a known image set
   above a declared top-1 accuracy floor.
4. **Capability enforcement.** `ai_listen` MUST fail with `CapabilityDenied`
   without a valid `AudioCapture` capability, and MUST fail with
   `CapabilityExpired` after the capability TTL elapses.
5. **Tokenize-or-refuse on messaging egress.** An attempt to send a message
   containing a name registered in `nexacore-tokenization` MUST either be tokenized
   pre-egress or refused; the audit log MUST record the outcome.
6. **Impact Dashboard gating.** A plan classified as Destructive MUST NOT
   auto-execute in `Autonomous` mode and MUST present a `Guided` prompt.
7. **A11y minima.** With the screen reader enabled, every reachable shell control
   MUST be announceable, and live captioning MUST follow system audio output
   within 200 ms.
8. **Provenance binding.** The planner MUST not act on a plan whose recorded
   input channel does not match a held capability (e.g. a "voice" plan without a
   valid `AudioCapture`).

---

## Reference Implementation

N/A at filing time. A reference implementation will land on a follow-up branch
after Last Call. Suggested crate layout (informative):

```
crates/nexacore-hal/src/audio.rs       — AudioDevice trait
crates/nexacore-hal/src/video.rs       — VideoDevice trait
crates/nexacore-driver-usb-audio/      — USB Audio Class 1.0 user-mode driver
crates/nexacore-driver-usb-video/      — USB Video Class 1.1 user-mode driver
crates/nexacore-runtime/src/listen.rs  — ai_listen impl + Whisper-tiny binding
crates/nexacore-runtime/src/speak.rs   — ai_speak impl + Piper binding
crates/nexacore-runtime/src/see.rs     — ai_see impl + mobile-classifier binding
crates/nexacore-messaging/             — adapter framework + Matrix reference adapter
crates/nexacore-a11y/                  — screen reader + captioning reference
```

---

## Security Considerations

Adversary classes mapped to `docs/04a-threat-model.md`:

- **A2 — adversarial multimodal input.** Audio prompt injection, image prompt
  injection, voice deepfake spoofing. Mitigations: input pre-processing
  (randomized smoothing on vision; spectral anomaly detection on audio),
  provenance binding (every plan tagged with input channel + source device id),
  and **multi-model agreement** for any plan in the NCIP-Helper-007 escalation
  taxonomy. Plans whose source channel cannot be attested MUST NOT execute
  Destructive actions.
- **A4 — driver supply chain.** USB Audio / USB Video classes have a long CVE
  history. Mitigations: user-mode driver processes with per-domain IOMMU (the
  work landing at P6.7.9-pre.10), small drivers, Stichting signing of reference
  drivers.
- **A6 — proprietary messaging client compromise.** Any closed messaging client
  MUST be confined to an NexaCoreContainer with declared egress capability; a
  compromised client MUST NOT be able to read other channels, files outside its
  prefix, or audio/video devices.
- **A7 — capability replay.** All new capabilities inherit the existing TTL +
  revocation list. `AudioCapture` and `VideoCapture` SHOULD use TTL ≤ 5 minutes
  for one-shot prompts.

Failure modes and blast radius:

- Compromised USB Audio driver: capture of the user's microphone for the session.
  Bounded by per-domain IOMMU; cannot read other devices' DMA.
- Compromised Telegram bot adapter inside an NexaCoreContainer: leak of messages
  routed through that adapter. Bounded by the container's declared
  `MessagingEgress(Telegram)` capability; cannot exfiltrate audio or files.
- Compromised on-device STT model: incorrect transcription that the planner
  acts on. Mitigated by the Impact Dashboard step and by multi-model agreement
  for high-stakes intents.

Cryptographic considerations:

- All adapters running outside an NexaCoreContainer MUST link `nexacore-crypto`'s
  RustCrypto-based primitives, not bundled or vendored crypto.
- TLS for messaging adapters MUST chain to the system trust store; pinned
  certificates SHOULD be allowed per channel.

---

## Privacy Considerations

Personal-data flows introduced or changed:

- **Audio capture.** PCM samples enter the AI Runtime, are consumed by STT, and
  MUST NOT leave the device by default. The STT transcript is the canonical
  representation downstream.
- **Video capture.** Frames enter the AI Runtime, are consumed by vision
  inference, and MUST NOT leave the device by default. Only structured
  `VisionEvent`s (labels, bounding boxes, OCR text) flow downstream.
- **Transcripts → planner.** Transcripts flow through `nexacore-tokenization` before
  the planner reasons about them; PII is replaced by deterministic tokens.
- **Outbound messaging.** Bodies are tokenized pre-egress per § 5; raw PII egress
  requires an explicit per-context override.

Metadata exposure:

- Per-channel messaging adapters expose at minimum the destination address and a
  rough timestamp to the third-party provider. The NCIP cannot eliminate this
  without renouncing the protocol; it MUST be disclosed in the Impact Dashboard
  scoring for the channel.
- Notification channels expose per-app channel ids to the user; NexaCore MUST NOT
  expose them across user accounts.

Linkability / unlinkability:

- The deterministic token from `nexacore-tokenization` is per-user-vault scoped, so
  it does not link the same person across users.
- Per-channel adapters MUST NOT share identifiers across channels; NexaCore MUST NOT
  insert a system-wide tracking identifier into messaging headers.

GDPR / regulatory implications:

- **Data minimization.** Tokenization before egress satisfies the principle.
- **Purpose limitation.** Each capability grant MUST declare the purpose visible
  in the Impact Dashboard; the user can revoke.
- **Retention.** Audit log entries containing transcripts are subject to the
  same retention policy as other per-user audit data; this NCIP does not change
  retention.

---

## Copyright

This NCIP is released into the public domain under
[CC0-1.0](https://creativecommons.org/publicdomain/zero/1.0/).
