//! Decoder traits and the hardware/software backend selector (WS8-02.3 /
//! WS8-02.4 / WS8-02.8).
//!
//! The vetted decode library (ADR-0052) is *library-gated*: the actual pixel
//! and PCM decode lives behind the [`VideoDecoder`] / [`AudioDecoder`] traits,
//! exactly as the WS5-03 ASR model lives behind `Transcriber`.  This keeps the
//! orchestration — backend probing, hardware-accelerated selection with a
//! software fallback (WS8-02.8), and the frame contract the [`crate::sink`]
//! consumes — host-testable with mock decoders.

use alloc::{boxed::Box, vec::Vec};

use nexacore_types::ai::AudioFormat;

use crate::{
    codec::{AudioCodec, VideoCodec},
    container::Packet,
};

/// Pixel layout of a decoded [`VideoFrame`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PixelFormat {
    /// Planar Y/U/V 4:2:0 (the common decoder output).
    I420,
    /// Semi-planar Y + interleaved UV 4:2:0 (common hardware output).
    Nv12,
    /// Packed 32-bit ARGB (ready for the compositor).
    Argb8888,
}

/// A decoded video frame ready for presentation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VideoFrame {
    /// Width in luma samples.
    pub width: u32,
    /// Height in luma samples.
    pub height: u32,
    /// Presentation timestamp in microseconds.
    pub pts_us: i64,
    /// Pixel layout of [`data`](VideoFrame::data).
    pub format: PixelFormat,
    /// Frame bytes in the declared [`format`](VideoFrame::format).
    pub data: Vec<u8>,
}

/// A decoded audio frame (interleaved PCM).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AudioFrame {
    /// Presentation timestamp in microseconds.
    pub pts_us: i64,
    /// PCM layout (sample-rate, channels, encoding) — reuses the WS5-03 type.
    pub format: AudioFormat,
    /// Interleaved PCM bytes in the declared [`format`](AudioFrame::format).
    pub pcm: Vec<u8>,
}

/// Why a decode call could not produce a frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DecodeError {
    /// The decoder does not handle this codec.
    UnsupportedCodec,
    /// The packet bytes were not valid for the codec.
    Malformed,
    /// The decoder needs more packets before it can emit a frame (normal for
    /// B-frame reordering / audio priming).
    NeedMoreData,
}

impl core::fmt::Display for DecodeError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let msg = match self {
            Self::UnsupportedCodec => "unsupported codec",
            Self::Malformed => "malformed packet",
            Self::NeedMoreData => "need more data",
        };
        f.write_str(msg)
    }
}

impl core::error::Error for DecodeError {}

/// A video decoder for one elementary stream.
///
/// Implementations wrap the vetted library; `decode` may return `Ok(None)`
/// while it buffers reordered frames, which [`flush`](VideoDecoder::flush)
/// drains at end-of-stream.
pub trait VideoDecoder {
    /// The codec this decoder handles.
    fn codec(&self) -> VideoCodec;
    /// Decode one packet, optionally yielding a frame.
    ///
    /// # Errors
    /// Returns [`DecodeError`] when the codec is unsupported or the packet is
    /// malformed.
    fn decode(&mut self, packet: &Packet) -> Result<Option<VideoFrame>, DecodeError>;
    /// Drain any frames held in the reorder buffer at end-of-stream.
    fn flush(&mut self) -> Vec<VideoFrame>;
}

/// An audio decoder for one elementary stream.
pub trait AudioDecoder {
    /// The codec this decoder handles.
    fn codec(&self) -> AudioCodec;
    /// Decode one packet, optionally yielding PCM.
    ///
    /// # Errors
    /// Returns [`DecodeError`] when the codec is unsupported or the packet is
    /// malformed.
    fn decode(&mut self, packet: &Packet) -> Result<Option<AudioFrame>, DecodeError>;
}

/// Which decode path a stream was bound to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Acceleration {
    /// A hardware-accelerated decoder (e.g. virtio-gpu / VA-API class).
    Hardware,
    /// A pure-software decoder.
    Software,
}

/// Probes the platform for hardware decode support.
///
/// The bare-metal implementation queries the GPU's decode capabilities; the
/// host test implementation answers from a fixed capability set.
pub trait HwProbe {
    /// `true` if a hardware video decoder exists for `codec`.
    fn supports_video(&self, codec: VideoCodec) -> bool;
    /// `true` if a hardware audio decoder exists for `codec`.
    fn supports_audio(&self, codec: AudioCodec) -> bool;
}

/// Constructs concrete decoders for a codec on a chosen path.
///
/// This is the seam where the vetted library binds in; a factory may decline
/// (`None`) a request — e.g. no hardware decoder is actually instantiable — and
/// the selector falls back to software.
pub trait DecoderFactory {
    /// Build a video decoder for `codec` on the `acceleration` path.
    fn create_video(
        &self,
        codec: VideoCodec,
        acceleration: Acceleration,
    ) -> Option<Box<dyn VideoDecoder>>;
    /// Build an audio decoder for `codec` on the `acceleration` path.
    fn create_audio(
        &self,
        codec: AudioCodec,
        acceleration: Acceleration,
    ) -> Option<Box<dyn AudioDecoder>>;
}

/// A constructed video decoder plus the path it was bound to.
pub struct SelectedVideo {
    /// The chosen decode path.
    pub acceleration: Acceleration,
    /// The constructed decoder.
    pub decoder: Box<dyn VideoDecoder>,
}

/// A constructed audio decoder plus the path it was bound to.
pub struct SelectedAudio {
    /// The chosen decode path.
    pub acceleration: Acceleration,
    /// The constructed decoder.
    pub decoder: Box<dyn AudioDecoder>,
}

/// Chooses a decode backend, preferring hardware and falling back to software
/// (WS8-02.8).
pub struct DecoderSelector<'a, P: HwProbe, F: DecoderFactory> {
    probe: &'a P,
    factory: &'a F,
}

impl<'a, P: HwProbe, F: DecoderFactory> DecoderSelector<'a, P, F> {
    /// Bind the selector to a capability probe and a decoder factory.
    pub const fn new(probe: &'a P, factory: &'a F) -> Self {
        Self { probe, factory }
    }

    /// Select and construct a video decoder for `codec`.
    ///
    /// Tries the hardware path first when the probe reports support and the
    /// factory can instantiate it; otherwise falls back to software.  Returns
    /// `None` only if neither path can build a decoder.
    pub fn select_video(&self, codec: VideoCodec) -> Option<SelectedVideo> {
        if self.probe.supports_video(codec) {
            if let Some(decoder) = self.factory.create_video(codec, Acceleration::Hardware) {
                return Some(SelectedVideo {
                    acceleration: Acceleration::Hardware,
                    decoder,
                });
            }
        }
        let decoder = self.factory.create_video(codec, Acceleration::Software)?;
        Some(SelectedVideo {
            acceleration: Acceleration::Software,
            decoder,
        })
    }

    /// Select and construct an audio decoder for `codec` (hardware-preferred,
    /// software fallback).
    pub fn select_audio(&self, codec: AudioCodec) -> Option<SelectedAudio> {
        if self.probe.supports_audio(codec) {
            if let Some(decoder) = self.factory.create_audio(codec, Acceleration::Hardware) {
                return Some(SelectedAudio {
                    acceleration: Acceleration::Hardware,
                    decoder,
                });
            }
        }
        let decoder = self.factory.create_audio(codec, Acceleration::Software)?;
        Some(SelectedAudio {
            acceleration: Acceleration::Software,
            decoder,
        })
    }
}
