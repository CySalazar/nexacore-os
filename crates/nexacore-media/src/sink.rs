//! Output sinks: video → virtio-gpu (WS8-02.5), audio → virtio-snd (WS8-02.6).
//!
//! The device-bound half (mapping a [`VideoFrame`] onto a compositor surface
//! and presenting it via virtio-gpu, or pushing PCM into the virtio-snd ring)
//! lives in the bootable image crate and is exercised on the test VM (WS8-02.10).
//! What is host-testable, and lives here, is the **scheduling**:
//!
//! * the [`VideoSink`] / [`AudioSink`] trait contracts,
//! * [`present_scheduled`], which consults the [`AvSyncClock`] to present,
//!   drop, or hold back each video frame, and
//! * reference [`HeadlessVideoSink`] / [`HeadlessAudioSink`] implementations
//!   that record what was presented/queued and model the audio buffer fill the
//!   sync clock is mastered on.

use nexacore_types::ai::AudioFormat;

use crate::{
    decode::{AudioFrame, VideoFrame},
    sync::{AvSyncClock, FrameAction},
};

/// Why a sink could not accept a frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SinkError {
    /// The frame's pixel format / PCM layout is not one the device accepts.
    UnsupportedFormat,
    /// The device queue is full; retry after draining.
    QueueFull,
    /// The underlying device reported an error.
    Device,
}

impl core::fmt::Display for SinkError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let msg = match self {
            Self::UnsupportedFormat => "unsupported format",
            Self::QueueFull => "queue full",
            Self::Device => "device error",
        };
        f.write_str(msg)
    }
}

impl core::error::Error for SinkError {}

/// A presentation surface for decoded video (the virtio-gpu bridge).
pub trait VideoSink {
    /// Present `frame` to the screen.
    ///
    /// # Errors
    /// Returns [`SinkError`] if the device rejects the frame.
    fn present(&mut self, frame: &VideoFrame) -> Result<(), SinkError>;
}

/// An audio output ring (the virtio-snd bridge).
pub trait AudioSink {
    /// Queue `frame`'s PCM for playback.
    ///
    /// # Errors
    /// Returns [`SinkError`] if the device rejects the PCM.
    fn queue(&mut self, frame: &AudioFrame) -> Result<(), SinkError>;

    /// Microseconds of audio currently buffered ahead of the playhead.
    ///
    /// The player uses this to advance the [`AvSyncClock`] master: the audio
    /// playback position is `total_queued − queued_ahead`.
    fn queued_us(&self) -> i64;
}

/// Present (or drop/hold) one video frame according to the sync clock
/// (WS8-02.5 + WS8-02.7 wiring).
///
/// Returns the [`FrameAction`] the clock decided.  On [`FrameAction::Present`]
/// the frame is pushed to `sink`; a sink error is propagated.  On
/// [`FrameAction::Drop`] / [`FrameAction::Wait`] the sink is not touched (the
/// caller sleeps for `Wait { delay_us }` and re-offers the same frame).
///
/// # Errors
/// Propagates a [`SinkError`] from `sink.present`.
pub fn present_scheduled<S: VideoSink>(
    sink: &mut S,
    clock: &mut AvSyncClock,
    frame: &VideoFrame,
) -> Result<FrameAction, SinkError> {
    let action = clock.decide(frame.pts_us);
    if action == FrameAction::Present {
        sink.present(frame)?;
    }
    Ok(action)
}

/// A headless [`VideoSink`] that records presentation activity (host tests and
/// the audio-less / off-screen case).
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct HeadlessVideoSink {
    /// Number of frames presented.
    pub presented: u64,
    /// Dimensions of the most recently presented frame, if any.
    pub last_dimensions: Option<(u32, u32)>,
    /// PTS of the most recently presented frame, if any.
    pub last_pts_us: Option<i64>,
}

impl HeadlessVideoSink {
    /// A fresh sink with no presentations recorded.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
}

impl VideoSink for HeadlessVideoSink {
    fn present(&mut self, frame: &VideoFrame) -> Result<(), SinkError> {
        self.presented += 1;
        self.last_dimensions = Some((frame.width, frame.height));
        self.last_pts_us = Some(frame.pts_us);
        Ok(())
    }
}

/// A headless [`AudioSink`] that models a buffer of queued PCM (host tests and
/// the off-screen case).  It tracks total queued duration and how much has been
/// "consumed" by the (simulated) playhead.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct HeadlessAudioSink {
    format: Option<AudioFormat>,
    total_queued_us: i64,
    consumed_us: i64,
    /// Number of frames queued.
    pub queued_frames: u64,
}

impl HeadlessAudioSink {
    /// A fresh sink with an empty buffer.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// PCM duration of a frame in microseconds, from its sample count and rate.
    fn frame_duration_us(frame: &AudioFrame) -> i64 {
        let frame_size = frame.format.frame_size();
        let rate = frame.format.sample_rate;
        if frame_size == 0 || rate == 0 {
            return 0;
        }
        let num_frames = frame.pcm.len().checked_div(frame_size).unwrap_or(0);
        let micros = u128::from(u64::try_from(num_frames).unwrap_or(0))
            .checked_mul(1_000_000)
            .and_then(|n| n.checked_div(u128::from(rate)))
            .unwrap_or(0);
        i64::try_from(micros).unwrap_or(i64::MAX)
    }

    /// Advance the simulated playhead by `elapsed_us` (clamped to what is
    /// buffered).  Drives the audio master clock in host tests.
    pub fn advance_playhead(&mut self, elapsed_us: i64) {
        self.consumed_us = self
            .consumed_us
            .saturating_add(elapsed_us)
            .min(self.total_queued_us);
    }

    /// The simulated audio playback position (master clock value).
    #[must_use]
    pub const fn playhead_us(&self) -> i64 {
        self.consumed_us
    }

    /// The PCM format last queued, if any.
    #[must_use]
    pub const fn format(&self) -> Option<AudioFormat> {
        self.format
    }
}

impl AudioSink for HeadlessAudioSink {
    fn queue(&mut self, frame: &AudioFrame) -> Result<(), SinkError> {
        self.format = Some(frame.format);
        self.total_queued_us = self
            .total_queued_us
            .saturating_add(Self::frame_duration_us(frame));
        self.queued_frames += 1;
        Ok(())
    }

    fn queued_us(&self) -> i64 {
        self.total_queued_us.saturating_sub(self.consumed_us)
    }
}
