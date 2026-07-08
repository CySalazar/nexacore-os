//! On-screen toast animation lifecycle (WS7-10.3).
//!
//! A toast fades/settles in, dwells, then fades out, driven by the HIG motion
//! tokens ([`crate::tokens::motion`]): it enters with the *decelerate* easing
//! and leaves with the *accelerate* easing — calm, no overshoot (brand DNA).
//! [`ToastAnim`] is a pure timing model: given the elapsed time it reports the
//! [`ToastPhase`] and an eased `opacity` the compositor applies to the toast
//! surface (rendered from a [`crate::notification::Notification`]).
//!
//! `no_std`, pure arithmetic.

#![allow(
    clippy::cast_precision_loss,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::float_arithmetic,
    // The `_ms` suffix documents the unit on every duration field.
    clippy::struct_field_names,
    // Endpoint opacities are exact (`0.0` / `1.0`) — exact test comparisons.
    clippy::float_cmp
)]

use crate::tokens::motion;

/// Default dwell (fully-visible) time before a toast auto-dismisses, in ms.
pub const DEFAULT_DWELL_MS: u16 = 4000;

/// The phase of a toast's life at a given time.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ToastPhase {
    /// Animating in.
    Entering,
    /// Fully visible (dwelling).
    Visible,
    /// Animating out.
    Exiting,
    /// Finished — should be removed.
    Done,
}

/// The timing of a toast animation: enter, dwell, and exit durations (ms).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ToastAnim {
    /// Enter (fade/settle in) duration.
    pub enter_ms: u16,
    /// Dwell (fully visible) duration.
    pub dwell_ms: u16,
    /// Exit (fade out) duration.
    pub exit_ms: u16,
}

impl Default for ToastAnim {
    fn default() -> Self {
        Self::standard()
    }
}

impl ToastAnim {
    /// The standard toast timing from the HIG motion tokens: a *slow* enter, a
    /// 4 s dwell, and a *fast* exit.
    #[must_use]
    pub fn standard() -> Self {
        Self {
            enter_ms: motion::DUR_SLOW_MS,
            dwell_ms: DEFAULT_DWELL_MS,
            exit_ms: motion::DUR_FAST_MS,
        }
    }

    /// A custom timing.
    #[must_use]
    pub fn new(enter_ms: u16, dwell_ms: u16, exit_ms: u16) -> Self {
        Self {
            enter_ms,
            dwell_ms,
            exit_ms,
        }
    }

    /// Total on-screen lifetime in ms.
    #[must_use]
    pub fn total_ms(self) -> u32 {
        u32::from(self.enter_ms) + u32::from(self.dwell_ms) + u32::from(self.exit_ms)
    }

    /// The phase at `elapsed_ms` since the toast appeared.
    #[must_use]
    pub fn phase(self, elapsed_ms: u32) -> ToastPhase {
        let enter = u32::from(self.enter_ms);
        let visible_end = enter + u32::from(self.dwell_ms);
        let exit_end = visible_end + u32::from(self.exit_ms);
        if elapsed_ms < enter {
            ToastPhase::Entering
        } else if elapsed_ms < visible_end {
            ToastPhase::Visible
        } else if elapsed_ms < exit_end {
            ToastPhase::Exiting
        } else {
            ToastPhase::Done
        }
    }

    /// The eased opacity `[0.0, 1.0]` to draw the toast with at `elapsed_ms`:
    /// `0 → 1` (decelerate) while entering, `1` while visible, `1 → 0`
    /// (accelerate) while exiting, `0` once done.
    #[must_use]
    pub fn opacity(self, elapsed_ms: u32) -> f32 {
        let enter = u32::from(self.enter_ms);
        let visible_end = enter + u32::from(self.dwell_ms);
        let exit_end = visible_end + u32::from(self.exit_ms);
        match self.phase(elapsed_ms) {
            ToastPhase::Entering => {
                let p = if enter == 0 {
                    1.0
                } else {
                    elapsed_ms as f32 / enter as f32
                };
                motion::EASE_DECELERATE.ease(p)
            }
            ToastPhase::Visible => 1.0,
            ToastPhase::Exiting => {
                let span = exit_end - visible_end;
                let p = if span == 0 {
                    1.0
                } else {
                    (elapsed_ms - visible_end) as f32 / span as f32
                };
                1.0 - motion::EASE_ACCELERATE.ease(p)
            }
            ToastPhase::Done => 0.0,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn standard_total_is_enter_plus_dwell_plus_exit() {
        let a = ToastAnim::standard();
        assert_eq!(
            a.total_ms(),
            u32::from(motion::DUR_SLOW_MS)
                + u32::from(DEFAULT_DWELL_MS)
                + u32::from(motion::DUR_FAST_MS)
        );
    }

    #[test]
    fn phases_follow_the_timeline() {
        let a = ToastAnim::new(100, 200, 100); // total 400
        assert_eq!(a.phase(0), ToastPhase::Entering);
        assert_eq!(a.phase(99), ToastPhase::Entering);
        assert_eq!(a.phase(100), ToastPhase::Visible);
        assert_eq!(a.phase(299), ToastPhase::Visible);
        assert_eq!(a.phase(300), ToastPhase::Exiting);
        assert_eq!(a.phase(399), ToastPhase::Exiting);
        assert_eq!(a.phase(400), ToastPhase::Done);
        assert_eq!(a.phase(99_999), ToastPhase::Done);
    }

    #[test]
    fn opacity_rises_then_holds_then_falls() {
        let a = ToastAnim::new(100, 200, 100);
        // Enter: 0 at start, full by the end, monotonic non-decreasing.
        assert!(a.opacity(0) <= 0.02);
        let mid_enter = a.opacity(50);
        assert!(mid_enter > 0.0 && mid_enter < 1.0, "mid_enter={mid_enter}");
        assert!(a.opacity(99) >= mid_enter);
        // Visible: full.
        assert!(a.opacity(150) > 0.999);
        // Exit: falls back toward 0.
        let mid_exit = a.opacity(350);
        assert!(mid_exit > 0.0 && mid_exit < 1.0, "mid_exit={mid_exit}");
        assert!(a.opacity(350) <= a.opacity(310));
        // Done: zero.
        assert_eq!(a.opacity(400), 0.0);
    }

    #[test]
    fn zero_enter_is_immediately_opaque() {
        let a = ToastAnim::new(0, 100, 0);
        assert!(a.opacity(0) > 0.999);
    }
}
