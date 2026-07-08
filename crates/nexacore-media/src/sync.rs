//! Audio-mastered A/V synchronisation clock (WS8-02.7).
//!
//! Lip-sync is kept by slaving video presentation to a **master clock**.  When
//! an audio track is present the master is the audio playback position (audio
//! is hard to resample without artefacts, so it runs free and video follows);
//! with no audio the player feeds a monotonic wall clock instead.  For each
//! decoded video frame the clock answers one question — *present it now, drop
//! it (we are late), or wait (we are early)?*
//!
//! All timing is **integer microseconds** so the decision is deterministic and
//! identical on the host and on the bare-metal target (no floating point).

/// What to do with a video frame relative to the master clock.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrameAction {
    /// The frame is within the sync window — show it now.
    Present,
    /// The frame's presentation time is already in the past beyond the drop
    /// threshold — discard it to catch up.
    Drop,
    /// The frame is ahead of the master clock — wait `delay_us` before showing.
    Wait {
        /// Microseconds to wait until the frame is due.
        delay_us: i64,
    },
}

/// Tunable thresholds for the sync decision (microseconds).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SyncThresholds {
    /// A frame whose drift is within `±present_window_us` is shown immediately.
    pub present_window_us: i64,
    /// A frame later than `-drop_threshold_us` of drift is dropped.
    pub drop_threshold_us: i64,
}

impl Default for SyncThresholds {
    fn default() -> Self {
        // 40 ms present window (~one frame at 25 fps); drop once >100 ms late.
        Self {
            present_window_us: 40_000,
            drop_threshold_us: 100_000,
        }
    }
}

/// Running counters describing what the clock decided over a session.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SyncStats {
    /// Frames presented.
    pub presented: u64,
    /// Frames dropped for being late.
    pub dropped: u64,
    /// Times a frame was held back (early).
    pub waited: u64,
}

/// An audio-mastered synchronisation clock.
#[derive(Debug, Clone)]
pub struct AvSyncClock {
    master_us: i64,
    thresholds: SyncThresholds,
    stats: SyncStats,
}

impl Default for AvSyncClock {
    fn default() -> Self {
        Self::new()
    }
}

impl AvSyncClock {
    /// Create a clock at master time 0 with default thresholds.
    #[must_use]
    pub fn new() -> Self {
        Self {
            master_us: 0,
            thresholds: SyncThresholds::default(),
            stats: SyncStats::default(),
        }
    }

    /// Create a clock with custom thresholds.
    #[must_use]
    pub fn with_thresholds(thresholds: SyncThresholds) -> Self {
        Self {
            master_us: 0,
            thresholds,
            stats: SyncStats::default(),
        }
    }

    /// Advance/​set the master clock to `master_us` (audio position or wall clock).
    pub fn set_master_us(&mut self, master_us: i64) {
        self.master_us = master_us;
    }

    /// The current master clock value.
    #[must_use]
    pub const fn master_us(&self) -> i64 {
        self.master_us
    }

    /// Drift of a video frame relative to the master clock.
    ///
    /// Positive means the frame is **ahead** (its PTS is in the future); negative
    /// means it is **behind** (late).
    #[must_use]
    pub const fn drift_us(&self, frame_pts_us: i64) -> i64 {
        frame_pts_us.saturating_sub(self.master_us)
    }

    /// Decide what to do with a video frame, **without** mutating statistics.
    #[must_use]
    pub const fn classify(&self, frame_pts_us: i64) -> FrameAction {
        let drift = self.drift_us(frame_pts_us);
        if drift < -self.thresholds.drop_threshold_us {
            FrameAction::Drop
        } else if drift > self.thresholds.present_window_us {
            FrameAction::Wait { delay_us: drift }
        } else {
            FrameAction::Present
        }
    }

    /// Decide what to do with a video frame and record the outcome in [`stats`].
    ///
    /// [`stats`]: AvSyncClock::stats
    pub fn decide(&mut self, frame_pts_us: i64) -> FrameAction {
        let action = self.classify(frame_pts_us);
        match action {
            FrameAction::Present => self.stats.presented += 1,
            FrameAction::Drop => self.stats.dropped += 1,
            FrameAction::Wait { .. } => self.stats.waited += 1,
        }
        action
    }

    /// The accumulated decision statistics.
    #[must_use]
    pub const fn stats(&self) -> SyncStats {
        self.stats
    }
}
