//! Presentation: triple buffering (WS7-01.4), adaptive frame cadence
//! (WS7-01.5) and FPS / frame-time instrumentation (WS7-01.12).
//!
//! These are the host-testable state machines of the present path; issuing the
//! actual vsync-synchronised flip is the GPU backend's job (rig, WS7-01.2 /
//! WS7-01.13).
//!
//! * [`TripleBuffer`] rotates three slots so the compositor can render the next
//!   frame while one frame is scanned out and one is held ready — the flip
//!   happens only at vsync, so the scanned-out (front) slot is never written
//!   mid-frame (tear-free).
//! * [`AdaptiveCadence`] varies the frame interval with on-screen activity
//!   (ProMotion-style: full refresh while animating, ramping down to a low idle
//!   rate to save power), within a hardware [`RefreshRange`].
//! * [`FrameStats`] keeps a sliding window of frame durations and derives
//!   FPS (milli-fps, integer), frame-time min/avg/max and dropped/janky counts.

#![allow(clippy::cast_possible_truncation, clippy::integer_division)]

use alloc::collections::VecDeque;

/// A three-slot buffer chain for tear-free presentation.
///
/// Invariant: the `front` slot (being scanned out) is never the `back` slot the
/// compositor renders into, so a frame is never torn. The flip is deferred to
/// [`TripleBuffer::on_vsync`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TripleBuffer {
    front: u8,
    back: u8,
    spare: u8,
    pending: bool,
}

impl Default for TripleBuffer {
    fn default() -> Self {
        Self::new()
    }
}

impl TripleBuffer {
    /// A fresh chain: slot 0 scanned out, slot 1 for rendering, slot 2 spare.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            front: 0,
            back: 1,
            spare: 2,
            pending: false,
        }
    }

    /// The slot currently scanned out to the display.
    #[must_use]
    pub const fn front(self) -> u8 {
        self.front
    }

    /// The slot the compositor should render the next frame into.
    #[must_use]
    pub const fn back(self) -> u8 {
        self.back
    }

    /// `true` once a rendered frame is waiting for the next vsync flip.
    #[must_use]
    pub const fn has_pending(self) -> bool {
        self.pending
    }

    /// Mark the `back` frame finished and ready to present at the next vsync.
    /// Calling twice without a vsync just keeps the latest (the newer frame
    /// supersedes the older pending one — no tearing, no extra latency).
    pub const fn submit(&mut self) {
        self.pending = true;
    }

    /// Apply a vsync: if a frame is pending, flip it to `front` and rotate a new
    /// slot in for rendering. Returns `true` if the displayed frame changed.
    ///
    /// Rotation: the just-finished `back` becomes `front`; the old `front`
    /// becomes the `spare`; the old `spare` becomes the new `back`. The
    /// compositor can immediately render into the new `back` while `front` is
    /// scanned out — three slots in flight, never blocking on the display.
    pub const fn on_vsync(&mut self) -> bool {
        if !self.pending {
            return false;
        }
        let new_front = self.back;
        let new_back = self.spare;
        self.spare = self.front;
        self.front = new_front;
        self.back = new_back;
        self.pending = false;
        true
    }
}

/// The display's supported refresh range, in Hz (e.g. `24..=120` ProMotion).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RefreshRange {
    /// Lowest refresh the panel will hold at idle.
    pub min_hz: u16,
    /// Highest refresh the panel supports.
    pub max_hz: u16,
}

impl RefreshRange {
    /// A fixed-refresh display (`hz` for both bounds).
    #[must_use]
    pub const fn fixed(hz: u16) -> Self {
        Self {
            min_hz: hz,
            max_hz: hz,
        }
    }

    /// A ProMotion-class adaptive panel (`24..=120` Hz).
    #[must_use]
    pub const fn promotion() -> Self {
        Self {
            min_hz: 24,
            max_hz: 120,
        }
    }
}

/// Convert a refresh rate to a frame interval in microseconds (`0` Hz → `0`).
#[must_use]
pub const fn interval_us(hz: u16) -> u32 {
    if hz == 0 { 0 } else { 1_000_000 / hz as u32 }
}

/// What the desktop is doing this frame, driving the adaptive refresh.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Activity {
    /// Animations / video / live resize in flight → run at max refresh.
    Animating,
    /// Discrete user input (scroll, drag) → run at max refresh for snappiness.
    Interacting,
    /// Nothing changing → ramp down toward the idle rate to save power.
    Idle,
}

/// Variable-refresh cadence within a [`RefreshRange`] (WS7-01.5).
///
/// Active frames run at `max_hz`. After `idle_grace` consecutive idle frames the
/// cadence steps down toward `min_hz`, so a still desktop costs little power but
/// the first frame of any motion is already at full rate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AdaptiveCadence {
    range: RefreshRange,
    idle_grace: u16,
    idle_run: u16,
    current_hz: u16,
}

impl AdaptiveCadence {
    /// New cadence starting at the panel's max refresh.
    #[must_use]
    pub const fn new(range: RefreshRange) -> Self {
        Self {
            range,
            idle_grace: 8,
            idle_run: 0,
            current_hz: range.max_hz,
        }
    }

    /// The refresh the next frame should target, in Hz.
    #[must_use]
    pub const fn current_hz(&self) -> u16 {
        self.current_hz
    }

    /// Feed this frame's activity and return the interval (µs) until the next
    /// frame should be produced.
    pub fn tick(&mut self, activity: Activity) -> u32 {
        match activity {
            Activity::Animating | Activity::Interacting => {
                self.idle_run = 0;
                self.current_hz = self.range.max_hz;
            }
            Activity::Idle => {
                self.idle_run = self.idle_run.saturating_add(1);
                if self.idle_run >= self.idle_grace {
                    // Halve the rate each idle grace period, floored at min_hz.
                    let halved = (self.current_hz / 2).max(self.range.min_hz);
                    self.current_hz = halved;
                    self.idle_run = 0;
                }
            }
        }
        interval_us(self.current_hz)
    }
}

/// Sliding-window FPS and frame-time instrumentation (WS7-01.12).
///
/// Records each frame's duration in microseconds and derives FPS and frame-time
/// statistics over the last `capacity` frames. A frame longer than `target_us`
/// is a *drop*; longer than `1.5 × target_us` is *jank*. Integer-only.
#[derive(Debug, Clone)]
pub struct FrameStats {
    window: VecDeque<u32>,
    capacity: usize,
    target_us: u32,
    dropped: u64,
    janky: u64,
    total: u64,
}

impl FrameStats {
    /// New stats over a `capacity`-frame window with a `target_hz` budget.
    #[must_use]
    pub fn new(capacity: usize, target_hz: u16) -> Self {
        Self {
            window: VecDeque::new(),
            capacity: capacity.max(1),
            target_us: interval_us(target_hz).max(1),
            dropped: 0,
            janky: 0,
            total: 0,
        }
    }

    /// Record one frame's render-to-present duration in microseconds.
    pub fn record(&mut self, frame_us: u32) {
        if self.window.len() >= self.capacity {
            self.window.pop_front();
        }
        self.window.push_back(frame_us);
        self.total = self.total.saturating_add(1);
        if frame_us > self.target_us {
            self.dropped = self.dropped.saturating_add(1);
        }
        if frame_us > self.target_us.saturating_mul(3) / 2 {
            self.janky = self.janky.saturating_add(1);
        }
    }

    /// Mean frame time over the window, in microseconds (`0` if empty).
    #[must_use]
    pub fn avg_us(&self) -> u32 {
        if self.window.is_empty() {
            return 0;
        }
        let sum: u64 = self.window.iter().map(|&u| u64::from(u)).sum();
        (sum / self.window.len() as u64) as u32
    }

    /// Shortest frame in the window, in microseconds.
    #[must_use]
    pub fn min_us(&self) -> u32 {
        self.window.iter().copied().min().unwrap_or(0)
    }

    /// Longest frame in the window, in microseconds.
    #[must_use]
    pub fn max_us(&self) -> u32 {
        self.window.iter().copied().max().unwrap_or(0)
    }

    /// FPS over the window in **milli-fps** (`60_000` = 60.0 fps), from the mean
    /// frame time. `0` if no frames recorded.
    #[must_use]
    pub fn fps_milli(&self) -> u32 {
        let avg = self.avg_us();
        if avg == 0 {
            0
        } else {
            // fps = 1e6 / avg_us ⇒ milli-fps = 1e9 / avg_us.
            (1_000_000_000u64 / u64::from(avg)) as u32
        }
    }

    /// Total frames that missed the target budget since creation.
    #[must_use]
    pub const fn dropped(&self) -> u64 {
        self.dropped
    }

    /// Total janky frames (> 1.5 × budget) since creation.
    #[must_use]
    pub const fn janky(&self) -> u64 {
        self.janky
    }

    /// Total frames recorded since creation.
    #[must_use]
    pub const fn total(&self) -> u64 {
        self.total
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn triple_buffer_front_never_equals_back() {
        let mut tb = TripleBuffer::new();
        for _ in 0..20 {
            assert_ne!(tb.front(), tb.back(), "tear-free invariant");
            tb.submit();
            tb.on_vsync();
        }
    }

    #[test]
    fn submitted_frame_becomes_front_at_vsync() {
        let mut tb = TripleBuffer::new();
        let rendered = tb.back();
        tb.submit();
        assert!(tb.has_pending());
        assert!(tb.on_vsync());
        assert_eq!(tb.front(), rendered, "the rendered slot is now scanned out");
        assert!(!tb.has_pending());
        // New back is a different slot, ready for the next frame.
        assert_ne!(tb.back(), tb.front());
    }

    #[test]
    fn vsync_without_pending_is_noop() {
        let mut tb = TripleBuffer::new();
        let before = tb;
        assert!(!tb.on_vsync());
        assert_eq!(tb, before);
    }

    #[test]
    fn all_three_slots_get_used_over_time() {
        let mut tb = TripleBuffer::new();
        let mut seen = [false; 3];
        for _ in 0..6 {
            seen[tb.back() as usize] = true;
            tb.submit();
            tb.on_vsync();
        }
        assert!(
            seen.iter().all(|&s| s),
            "triple buffering rotates all slots"
        );
    }

    #[test]
    fn interval_us_matches_common_rates() {
        assert_eq!(interval_us(60), 16_666);
        assert_eq!(interval_us(120), 8_333);
        assert_eq!(interval_us(0), 0);
    }

    #[test]
    fn cadence_runs_full_rate_while_animating() {
        let mut c = AdaptiveCadence::new(RefreshRange::promotion());
        let iv = c.tick(Activity::Animating);
        assert_eq!(c.current_hz(), 120);
        assert_eq!(iv, interval_us(120));
    }

    #[test]
    fn cadence_ramps_down_when_idle_then_snaps_back() {
        let mut c = AdaptiveCadence::new(RefreshRange::promotion());
        // Stay idle long enough to step down at least once.
        for _ in 0..40 {
            c.tick(Activity::Idle);
        }
        assert!(c.current_hz() < 120, "idle should reduce refresh");
        assert!(c.current_hz() >= 24, "never below min");
        // First active frame jumps straight back to max.
        c.tick(Activity::Interacting);
        assert_eq!(c.current_hz(), 120);
    }

    #[test]
    fn frame_stats_fps_and_drops() {
        let mut s = FrameStats::new(120, 60); // 60 Hz budget = 16_666 µs
        for _ in 0..60 {
            s.record(16_666); // exactly on budget
        }
        let fps = s.fps_milli();
        assert!((59_000..=61_000).contains(&fps), "≈60 fps, got {fps}");
        assert_eq!(s.dropped(), 0);
        // A long frame is a drop and (well past 1.5×) jank.
        s.record(40_000);
        assert_eq!(s.dropped(), 1);
        assert_eq!(s.janky(), 1);
        assert_eq!(s.max_us(), 40_000);
        assert_eq!(s.total(), 61);
    }

    #[test]
    fn frame_stats_window_evicts_oldest() {
        let mut s = FrameStats::new(3, 60);
        s.record(10_000);
        s.record(20_000);
        s.record(30_000);
        s.record(40_000); // evicts 10_000
        assert_eq!(s.min_us(), 20_000);
        assert_eq!(s.max_us(), 40_000);
        assert_eq!(s.total(), 4); // total is cumulative, window is bounded
    }
}
