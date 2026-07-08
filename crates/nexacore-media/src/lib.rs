//! # `nexacore-media`
//!
//! Host-testable core of the NexaCore media player (WS8-02, ADR-0052).
//!
//! ## Purpose
//!
//! This crate provides the **device- and library-independent** half of the
//! media player.  Every effect that needs a real codec library, GPU, or sound
//! card sits behind a trait so the orchestration logic stays host-testable:
//!
//! * **[`container`]** — [`container::Demuxer`]: ISO-BMFF (MP4), EBML
//!   (MKV/WebM) container parsing into [`container::Track`]s and elementary
//!   [`container::Packet`]s (WS8-02.2).
//! * **[`codec`]** — bitstream header parsers that recover stream parameters
//!   without a full decoder: H.264 SPS dimensions, VP9 uncompressed frame
//!   header, Opus ID header, AAC ADTS header (WS8-02.3 / WS8-02.4, header
//!   level).
//! * **[`decode`]** — [`decode::VideoDecoder`] / [`decode::AudioDecoder`]
//!   traits, the [`decode::VideoFrame`] / [`decode::AudioFrame`] outputs, and
//!   [`decode::DecoderSelector`] which prefers a hardware-accelerated backend
//!   and falls back to software (WS8-02.3 / WS8-02.4 / WS8-02.8).
//! * **[`sink`]** — [`sink::VideoSink`] (→ virtio-gpu, WS2-10) and
//!   [`sink::AudioSink`] (→ virtio-snd, WS2-09) traits plus the present/queue
//!   scheduling logic, host-tested with mock sinks (WS8-02.5 / WS8-02.6).
//! * **[`sync`]** — [`sync::AvSyncClock`]: an integer-microsecond
//!   audio-mastered clock that decides, per video frame, whether to present,
//!   drop, or repeat it to stay in lip-sync (WS8-02.7).
//! * **[`playlist`]** — [`playlist::Playlist`]: the add / remove / reorder /
//!   seek model with repeat and shuffle modes (WS8-02.9).
//! * **[`player`]** — [`player::MediaPlayer`]: the top-level state machine that
//!   wires demux → decode → sync → sink over the playlist, host-tested
//!   end-to-end with mock backends.
//!
//! ## Architecture reference
//!
//! See [`ADR-0052`](../../../docs/adr/0052-media-decode-pipeline.md) for the
//! decode-library vetting (WS8-02.1) and the trait-boundary rationale.  The
//! real codec library binding is *library-gated* behind the decoder traits,
//! consistent with the WS5-03 ASR model living behind `Transcriber`.
//!
//! ## `no_std` + `alloc`
//!
//! This crate compiles for both the developer host (`x86_64-unknown-linux-gnu`)
//! and the bare-metal Ring-3 target (`x86_64-unknown-none`).  It uses
//! `alloc::{string::String, vec::Vec}` but no `std` API, and performs **no
//! floating-point arithmetic** (all timing is integer microseconds) so it is
//! deterministic across targets.
//!
//! ## Quick start
//!
//! ```
//! use nexacore_media::playlist::{Playlist, RepeatMode};
//!
//! let mut pl = Playlist::new();
//! pl.push("intro.webm");
//! pl.push("feature.mp4");
//! pl.set_repeat(RepeatMode::All);
//!
//! assert_eq!(pl.current().map(|e| e.uri.as_str()), Some("intro.webm"));
//! assert_eq!(pl.advance().map(|e| e.uri.as_str()), Some("feature.mp4"));
//! // Repeat-all wraps back to the first entry.
//! assert_eq!(pl.advance().map(|e| e.uri.as_str()), Some("intro.webm"));
//! ```

#![doc(html_root_url = "https://docs.nexacore-os.org/nexacore-media")]
#![no_std]
#![deny(missing_docs)]
#![cfg_attr(
    test,
    allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::indexing_slicing,
        clippy::missing_docs_in_private_items,
    )
)]

// `alloc` provides `String`, `Vec`, and `Box` without `std`.
extern crate alloc;

pub mod codec;
pub mod container;
pub mod decode;
pub mod player;
pub mod playlist;
pub mod sink;
pub mod sync;

mod reader;

#[cfg(test)]
mod tests;
