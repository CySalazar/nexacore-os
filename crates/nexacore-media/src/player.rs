//! Top-level player orchestration: transport state + the playback pump.
//!
//! [`MediaPlayer`] is the transport state machine over a [`Playlist`]
//! (idle → playing ⇄ paused → ended, with end-of-stream advancing the list).
//! [`run_session`] is the host-testable wire that pumps one item end-to-end —
//! demux → decode → A/V-sync → sink — proving the WS8-02 pipeline fits together
//! with mock backends, before the real library and virtio devices arrive
//! (WS8-02.10).

use crate::{
    container::{Demuxer, TrackKind},
    decode::{AudioDecoder, VideoDecoder},
    playlist::{Playlist, PlaylistEntry},
    sink::{AudioSink, VideoSink, present_scheduled},
    sync::{AvSyncClock, FrameAction},
};

/// Transport state of the player.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum PlayerState {
    /// Nothing loaded / stopped.
    #[default]
    Idle,
    /// Actively playing.
    Playing,
    /// Paused (position retained).
    Paused,
    /// The current item reached its end.
    Ended,
}

/// The media-player transport over a playlist.
#[derive(Debug, Clone, Default)]
pub struct MediaPlayer {
    playlist: Playlist,
    state: PlayerState,
    position_us: i64,
}

impl MediaPlayer {
    /// A new, idle player with an empty playlist.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// A player initialised with `playlist` (still idle).
    #[must_use]
    pub const fn with_playlist(playlist: Playlist) -> Self {
        Self {
            playlist,
            state: PlayerState::Idle,
            position_us: 0,
        }
    }

    /// Shared access to the playlist.
    #[must_use]
    pub const fn playlist(&self) -> &Playlist {
        &self.playlist
    }

    /// Mutable access to the playlist (enqueue / reorder / shuffle).
    pub const fn playlist_mut(&mut self) -> &mut Playlist {
        &mut self.playlist
    }

    /// Current transport state.
    #[must_use]
    pub const fn state(&self) -> PlayerState {
        self.state
    }

    /// Current playback position within the item, in microseconds.
    #[must_use]
    pub const fn position_us(&self) -> i64 {
        self.position_us
    }

    /// The item currently loaded, if any.
    #[must_use]
    pub fn current(&self) -> Option<&PlaylistEntry> {
        self.playlist.current()
    }

    /// Begin (or resume) playback.  No-op with an empty playlist.
    pub fn play(&mut self) {
        if self.playlist.is_empty() {
            return;
        }
        self.state = PlayerState::Playing;
    }

    /// Pause, retaining position.  Only meaningful while playing.
    pub fn pause(&mut self) {
        if self.state == PlayerState::Playing {
            self.state = PlayerState::Paused;
        }
    }

    /// Stop and rewind to the start of the current item.
    pub fn stop(&mut self) {
        self.state = PlayerState::Idle;
        self.position_us = 0;
    }

    /// Update the reported playback position (driven by the audio playhead).
    pub fn set_position_us(&mut self, position_us: i64) {
        self.position_us = position_us;
    }

    /// Signal end-of-stream for the current item.
    ///
    /// Advances the playlist (honouring its repeat mode); if another item
    /// follows, playback continues from its start and the player stays
    /// `Playing`.  At the tail with repeat off, [`Playlist::advance`] yields
    /// `None` and the player goes to [`PlayerState::Ended`].
    ///
    /// [`Playlist::advance`]: crate::playlist::Playlist::advance
    pub fn on_end_of_stream(&mut self) {
        self.position_us = 0;
        if self.playlist.advance().is_some() {
            self.state = PlayerState::Playing;
        } else {
            self.state = PlayerState::Ended;
        }
    }
}

/// What [`run_session`] observed pumping one item.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SessionSummary {
    /// Video frames presented to the sink.
    pub video_presented: u64,
    /// Video frames dropped for being late.
    pub video_dropped: u64,
    /// Video frames held back (early) at least once.
    pub video_waited: u64,
    /// Audio frames queued to the sink.
    pub audio_queued: u64,
    /// Packets that produced a decode error (skipped).
    pub decode_errors: u64,
}

/// Pump one demuxed item end-to-end through decode → A/V-sync → sinks.
///
/// Audio is the master clock: each decoded audio frame advances the
/// [`AvSyncClock`] to its presentation time, and every video frame is then
/// presented, dropped, or (in principle) delayed relative to that master via
/// [`present_scheduled`].  Packets for tracks other than the chosen video/audio
/// track are ignored; decode errors are counted and skipped (the pump is
/// resilient to a single bad packet).
///
/// The decoders and sinks are injected, so the real library/virtio backends and
/// the host mocks run the identical orchestration.
pub fn run_session<VD, AD, VS, AS>(
    demux: &Demuxer,
    video_decoder: &mut VD,
    audio_decoder: &mut AD,
    video_sink: &mut VS,
    audio_sink: &mut AS,
    clock: &mut AvSyncClock,
) -> SessionSummary
where
    VD: VideoDecoder,
    AD: AudioDecoder,
    VS: VideoSink,
    AS: AudioSink,
{
    let mut summary = SessionSummary::default();
    let video_id = demux.video_track().map(|t| t.id);
    let audio_id = demux.audio_track().map(|t| t.id);

    for packet in demux.packets() {
        let kind = track_kind(demux, packet.track_id);
        if Some(packet.track_id) == audio_id && kind == Some(TrackKind::Audio) {
            match audio_decoder.decode(packet) {
                Ok(Some(frame)) => {
                    // Audio is the master: advance the clock to this frame.
                    clock.set_master_us(frame.pts_us);
                    if audio_sink.queue(&frame).is_ok() {
                        summary.audio_queued += 1;
                    }
                }
                Ok(None) => {}
                Err(_) => summary.decode_errors += 1,
            }
        } else if Some(packet.track_id) == video_id && kind == Some(TrackKind::Video) {
            match video_decoder.decode(packet) {
                Ok(Some(frame)) => match present_scheduled(video_sink, clock, &frame) {
                    Ok(FrameAction::Present) => summary.video_presented += 1,
                    Ok(FrameAction::Drop) => summary.video_dropped += 1,
                    Ok(FrameAction::Wait { .. }) => summary.video_waited += 1,
                    Err(_) => summary.decode_errors += 1,
                },
                Ok(None) => {}
                Err(_) => summary.decode_errors += 1,
            }
        }
    }

    // Drain the video reorder buffer at end-of-stream.
    for frame in video_decoder.flush() {
        match present_scheduled(video_sink, clock, &frame) {
            Ok(FrameAction::Present) => summary.video_presented += 1,
            Ok(FrameAction::Drop) => summary.video_dropped += 1,
            Ok(FrameAction::Wait { .. }) => summary.video_waited += 1,
            Err(_) => summary.decode_errors += 1,
        }
    }

    summary
}

/// Look up a track's kind by id.
fn track_kind(demux: &Demuxer, track_id: u32) -> Option<TrackKind> {
    demux
        .tracks()
        .iter()
        .find(|t| t.id == track_id)
        .map(|t| t.kind)
}
