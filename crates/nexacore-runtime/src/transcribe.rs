//! Transcribe path: turn a captured audio buffer into text (WS5-03.9).
//!
//! Speech-to-text has two halves. The **front-end** is deterministic DSP:
//! decode the captured PCM buffer (the [`AudioBufferRef`] the WS2-10 audio
//! stack fills, described by an `AudioFormat`) into a normalized mono `f32`
//! sample stream, then resample it to the acoustic model's expected rate
//! (16 kHz for speech models). The **acoustic model** (a Whisper-class encoder
//! + autoregressive decoder + detokenizer) is a large, model-gated effect, so
//! the path takes it behind the `Transcriber` trait — exactly the way the
//! rest of the engine puts effects behind traits.
//!
//! `transcribe_sync` wires the two halves: `decode → resample → model`. The
//! front-end is fully host-testable (exact DSP), and the orchestration is
//! host-testable against a mock `Transcriber`; the real model lands with the
//! GGUF audio-model work. `no_std + alloc`.
//!
//! [`AudioBufferRef`]: nexacore_types::ai::AudioBufferRef

// DSP front-end: float sample maths plus bounded index/rate casts between the
// sample count, the integer rates, and the interpolation positions. The model
// effect stays behind `Transcriber`, so the maths here is pure and
// host-testable.
//
// `suboptimal_flops` would have us fuse the interpolation into `f32::mul_add`,
// but that method lives in `std`/libm and is unavailable on the `no_std`
// target (the reason `nexacore_hal::math` exists), so it is allowed here.
#![allow(
    clippy::float_arithmetic,
    clippy::cast_precision_loss,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::integer_division,
    clippy::suboptimal_flops
)]

#[cfg(not(feature = "std"))]
use alloc::{string::String, vec::Vec};

use nexacore_types::{
    ai::{AudioFormat, PcmEncoding},
    error::{HalErrorKind, NexaCoreError, Result},
};

/// The text result of transcribing an audio sample stream.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Transcript {
    /// The transcribed text.
    pub text: String,
    /// The detected BCP-47 language, when the model reports one.
    pub language: Option<String>,
}

/// An acoustic speech-to-text model — the effect behind the transcribe path.
///
/// The real implementation (a Whisper-class model) is model-gated; the engine
/// path is generic over this trait so it stays host-testable with a mock.
pub trait Transcriber {
    /// Transcribes a mono `[-1.0, 1.0]` sample stream at `sample_rate` Hz.
    ///
    /// `language` is an optional BCP-47 hint; the model may ignore it.
    ///
    /// # Errors
    ///
    /// Implementation-defined; propagated unchanged by [`transcribe_sync`].
    fn transcribe(
        &self,
        samples: &[f32],
        sample_rate: u32,
        language: Option<&str>,
    ) -> Result<Transcript>;
}

/// Decodes interleaved PCM `bytes` (laid out per `format`) into a mono
/// `[-1.0, 1.0]` `f32` sample stream, averaging channels down to mono.
///
/// `S16Le` samples are scaled by `1/32768`; `F32Le` samples pass through.
///
/// # Errors
///
/// Fails if the format has zero channels or `bytes.len()` is not a whole
/// number of frames for the format.
pub fn decode_pcm_mono(bytes: &[u8], format: AudioFormat) -> Result<Vec<f32>> {
    let channels = usize::from(format.channels);
    if channels == 0 {
        return Err(NexaCoreError::hal(
            HalErrorKind::DeviceFailure,
            "transcribe::decode::no_channels",
        ));
    }
    let bps = format.encoding.bytes_per_sample();
    let frame = format.frame_size();
    if frame == 0 || bytes.len().checked_rem(frame) != Some(0) {
        return Err(NexaCoreError::hal(
            HalErrorKind::DeviceFailure,
            "transcribe::decode::unaligned",
        ));
    }

    let mut out = Vec::with_capacity(bytes.chunks_exact(frame).len());
    for frame_bytes in bytes.chunks_exact(frame) {
        let mut acc = 0.0_f32;
        for ch in 0..channels {
            let start = ch * bps;
            let sample = frame_bytes.get(start..start + bps).ok_or_else(|| {
                NexaCoreError::hal(HalErrorKind::DeviceFailure, "transcribe::decode::frame_oob")
            })?;
            acc += decode_sample(sample, format.encoding)?;
        }
        out.push(acc / channels as f32);
    }
    Ok(out)
}

/// Linearly resamples a mono sample stream from `src_rate` to `dst_rate`.
///
/// Identity (a clone) when the rates match or the input is empty. Output length
/// is `samples.len() * dst_rate / src_rate`; each output sample is a linear
/// interpolation of its two neighbouring input samples (the tail clamps to the
/// last input sample).
///
/// # Errors
///
/// Fails if either rate is zero.
pub fn resample_linear(samples: &[f32], src_rate: u32, dst_rate: u32) -> Result<Vec<f32>> {
    if src_rate == 0 || dst_rate == 0 {
        return Err(NexaCoreError::hal(
            HalErrorKind::DeviceFailure,
            "transcribe::resample::zero_rate",
        ));
    }
    if samples.is_empty() || src_rate == dst_rate {
        return Ok(samples.to_vec());
    }

    let src_len = samples.len() as u64;
    let out_len = (src_len * u64::from(dst_rate) / u64::from(src_rate)) as usize;
    if out_len == 0 {
        return Ok(Vec::new());
    }

    // Source samples advanced per output sample.
    let step = src_rate as f32 / dst_rate as f32;
    let mut out = Vec::with_capacity(out_len);
    for i in 0..out_len {
        let pos = i as f32 * step;
        let idx = pos as usize;
        let frac = pos - idx as f32;
        let a = samples.get(idx).copied().unwrap_or(0.0);
        // Clamp past the end to the last sample so the tail does not dip to 0.
        let b = samples.get(idx + 1).copied().unwrap_or(a);
        out.push(a + (b - a) * frac);
    }
    Ok(out)
}

/// End-to-end transcribe path: decode the captured PCM `bytes`, resample to the
/// model's `target_rate`, and run the acoustic `model`.
///
/// # Errors
///
/// Propagates decode, resample, and model errors.
pub fn transcribe_sync<T: Transcriber + ?Sized>(
    model: &T,
    bytes: &[u8],
    format: AudioFormat,
    target_rate: u32,
    language: Option<&str>,
) -> Result<Transcript> {
    let mono = decode_pcm_mono(bytes, format)?;
    let resampled = resample_linear(&mono, format.sample_rate, target_rate)?;
    model.transcribe(&resampled, target_rate, language)
}

/// Decodes one little-endian PCM sample to `f32`.
fn decode_sample(bytes: &[u8], encoding: PcmEncoding) -> Result<f32> {
    match encoding {
        PcmEncoding::S16Le => {
            let arr: [u8; 2] = bytes.try_into().map_err(|_| {
                NexaCoreError::hal(HalErrorKind::DeviceFailure, "transcribe::decode::s16_chunk")
            })?;
            Ok(f32::from(i16::from_le_bytes(arr)) / 32768.0)
        }
        PcmEncoding::F32Le => {
            let arr: [u8; 4] = bytes.try_into().map_err(|_| {
                NexaCoreError::hal(HalErrorKind::DeviceFailure, "transcribe::decode::f32_chunk")
            })?;
            Ok(f32::from_le_bytes(arr))
        }
    }
}

#[cfg(test)]
mod tests {
    #[cfg(not(feature = "std"))]
    use alloc::{string::String, vec, vec::Vec};
    use core::cell::Cell;

    use super::*;

    fn fmt(sample_rate: u32, channels: u8, encoding: PcmEncoding) -> AudioFormat {
        AudioFormat {
            sample_rate,
            channels,
            encoding,
        }
    }

    fn s16_le(v: i16) -> [u8; 2] {
        v.to_le_bytes()
    }

    #[test]
    fn decode_s16_mono_normalizes() {
        // 0, +half, -half, near +full.
        let mut bytes = Vec::new();
        for v in [0_i16, 16_384, -16_384, 32_767] {
            bytes.extend_from_slice(&s16_le(v));
        }
        let mono = decode_pcm_mono(&bytes, fmt(16_000, 1, PcmEncoding::S16Le)).unwrap();
        assert_eq!(mono.len(), 4);
        assert!((mono[0] - 0.0).abs() < 1e-6);
        assert!((mono[1] - 0.5).abs() < 1e-6);
        assert!((mono[2] + 0.5).abs() < 1e-6);
        assert!((mono[3] - 32_767.0 / 32_768.0).abs() < 1e-6);
    }

    #[test]
    fn decode_s16_stereo_downmixes() {
        // Two frames: (L,R) = (1.0, 0.0) -> 0.5 ; (-1.0, 1.0) -> 0.0
        let mut bytes = Vec::new();
        for v in [32_767_i16, 0, -32_768, 32_767] {
            bytes.extend_from_slice(&s16_le(v));
        }
        let mono = decode_pcm_mono(&bytes, fmt(48_000, 2, PcmEncoding::S16Le)).unwrap();
        assert_eq!(mono.len(), 2);
        // (0.99997 + 0) / 2 ~ 0.5
        assert!((mono[0] - (32_767.0 / 32_768.0) / 2.0).abs() < 1e-6);
        // (-1.0 + 0.99997) / 2 ~ 0
        assert!(mono[1].abs() < 1e-3);
    }

    #[test]
    fn decode_f32_mono_passes_through() {
        let mut bytes = Vec::new();
        for v in [0.0_f32, 0.25, -0.75] {
            bytes.extend_from_slice(&v.to_le_bytes());
        }
        let mono = decode_pcm_mono(&bytes, fmt(16_000, 1, PcmEncoding::F32Le)).unwrap();
        assert_eq!(mono, vec![0.0, 0.25, -0.75]);
    }

    #[test]
    fn decode_rejects_unaligned_and_zero_channels() {
        // 3 bytes is not a whole S16 frame (2 bytes/frame).
        assert!(decode_pcm_mono(&[0, 0, 0], fmt(16_000, 1, PcmEncoding::S16Le)).is_err());
        // Zero channels -> frame_size 0 -> rejected.
        assert!(decode_pcm_mono(&[0, 0], fmt(16_000, 0, PcmEncoding::S16Le)).is_err());
    }

    #[test]
    fn resample_identity_when_rates_match() {
        let s = [0.0_f32, 1.0, 2.0];
        assert_eq!(
            resample_linear(&s, 16_000, 16_000).unwrap(),
            vec![0.0, 1.0, 2.0]
        );
        assert!(resample_linear(&[], 8_000, 16_000).unwrap().is_empty());
    }

    #[test]
    fn resample_upsamples_2x_with_interpolation() {
        // [0, 1] at 1 Hz -> 2 Hz: out_len = 2*2/1 = 4, step = 0.5.
        // pos 0,0.5,1.0,1.5 -> 0, 0.5, 1, (clamp) 1.
        let out = resample_linear(&[0.0, 1.0], 1, 2).unwrap();
        assert_eq!(out.len(), 4);
        assert!((out[0] - 0.0).abs() < 1e-6);
        assert!((out[1] - 0.5).abs() < 1e-6);
        assert!((out[2] - 1.0).abs() < 1e-6);
        assert!((out[3] - 1.0).abs() < 1e-6);
    }

    #[test]
    fn resample_downsamples_2x() {
        // [0,1,2,3] at 4 Hz -> 2 Hz: out_len = 4*2/4 = 2, step = 2.0 -> [0, 2].
        let out = resample_linear(&[0.0, 1.0, 2.0, 3.0], 4, 2).unwrap();
        assert_eq!(out, vec![0.0, 2.0]);
    }

    #[test]
    fn resample_rejects_zero_rate() {
        assert!(resample_linear(&[0.0, 1.0], 0, 16_000).is_err());
        assert!(resample_linear(&[0.0, 1.0], 16_000, 0).is_err());
    }

    // --- orchestration against a mock model ---------------------------------

    struct MockTranscriber {
        seen_len: Cell<usize>,
        seen_rate: Cell<u32>,
    }

    impl Transcriber for MockTranscriber {
        fn transcribe(
            &self,
            samples: &[f32],
            sample_rate: u32,
            _language: Option<&str>,
        ) -> Result<Transcript> {
            self.seen_len.set(samples.len());
            self.seen_rate.set(sample_rate);
            Ok(Transcript {
                text: String::from("hello world"),
                language: Some(String::from("en")),
            })
        }
    }

    #[test]
    fn transcribe_sync_decodes_resamples_then_calls_model() {
        // 4 mono S16 samples at 8 kHz, target 16 kHz -> 8 resampled samples.
        let mut bytes = Vec::new();
        for v in [0_i16, 8_000, -8_000, 16_000] {
            bytes.extend_from_slice(&s16_le(v));
        }
        let model = MockTranscriber {
            seen_len: Cell::new(0),
            seen_rate: Cell::new(0),
        };
        let out = transcribe_sync(
            &model,
            &bytes,
            fmt(8_000, 1, PcmEncoding::S16Le),
            16_000,
            Some("en"),
        )
        .unwrap();
        assert_eq!(out.text, "hello world");
        assert_eq!(out.language.as_deref(), Some("en"));
        // 4 samples * 16000 / 8000 = 8 samples handed to the model at 16 kHz.
        assert_eq!(model.seen_len.get(), 8);
        assert_eq!(model.seen_rate.get(), 16_000);
    }

    #[test]
    fn transcribe_sync_propagates_decode_error() {
        let model = MockTranscriber {
            seen_len: Cell::new(0),
            seen_rate: Cell::new(0),
        };
        // 3 bytes is not a whole S16 frame.
        let err = transcribe_sync(
            &model,
            &[0, 0, 0],
            fmt(8_000, 1, PcmEncoding::S16Le),
            16_000,
            None,
        );
        assert!(err.is_err());
        // The model was never reached.
        assert_eq!(model.seen_len.get(), 0);
    }
}
