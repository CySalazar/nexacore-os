//! Pointer motion acceleration (WS7-06.4).
//!
//! Raw relative deltas from an HID mouse (`dx`, `dy` per report) are scaled by a
//! speed-dependent *sensitivity curve* before they move the on-screen pointer:
//! slow motion stays 1:1 for precision, fast motion is amplified so the pointer
//! crosses the screen without lifting the mouse. The curve is piecewise: below
//! `threshold` the base multiplier applies; above it the multiplier grows
//! linearly with speed up to a clamp.
//!
//! All arithmetic is fixed-point in thousandths (`_milli`; `1000` = ×1.0) — no
//! floats in the `no_std` display stack. Because a scaled delta rarely lands on
//! a whole pixel, the sub-pixel remainder is **accumulated** across reports so
//! slow drift is never silently discarded.
//!
//! The accelerated `(dx, dy)` feeds [`PointerState`] (WS7-06.3), which tracks
//! the absolute on-screen position and emits the `DisplayInputEvent::Pointer`
//! routed by [`crate::wm`]. This module also hosts the [`KeyRepeater`] state
//! machine (WS7-06.5): a held key emits synthetic repeats after a configurable
//! delay, then at a configurable rate.

use nexacore_types::display_channel::DisplayInputEvent;

/// The tunable sensitivity curve.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PointerAccelConfig {
    /// Base multiplier in thousandths applied at or below `threshold`
    /// (`1000` = ×1.0).
    pub base_milli: u32,
    /// Speed (in `|dx| + |dy|` units per report) at/below which no acceleration
    /// beyond `base_milli` is applied.
    pub threshold: u32,
    /// Added multiplier (thousandths) per unit of speed above `threshold`.
    pub gain_milli: u32,
    /// Upper clamp on the total multiplier in thousandths.
    pub max_milli: u32,
}

impl Default for PointerAccelConfig {
    /// A sane desktop default: 1:1 up to speed 4, then ramping to a ×3 clamp.
    fn default() -> Self {
        Self {
            base_milli: 1000,
            threshold: 4,
            gain_milli: 200,
            max_milli: 3000,
        }
    }
}

impl PointerAccelConfig {
    /// The multiplier (thousandths) this curve applies at `speed`.
    #[must_use]
    pub fn multiplier_milli(&self, speed: u32) -> u32 {
        if speed <= self.threshold {
            self.base_milli
        } else {
            let extra = self.gain_milli.saturating_mul(speed - self.threshold);
            self.base_milli.saturating_add(extra).min(self.max_milli)
        }
    }
}

/// A stateful pointer accelerator: applies the curve and carries the sub-pixel
/// remainder between reports (WS7-06.4).
#[derive(Debug, Clone, Copy)]
pub struct PointerAccelerator {
    config: PointerAccelConfig,
    /// Accumulated sub-pixel remainder in thousandths, per axis.
    rem_x: i64,
    rem_y: i64,
}

impl PointerAccelerator {
    /// A new accelerator with the given curve.
    #[must_use]
    pub fn new(config: PointerAccelConfig) -> Self {
        Self {
            config,
            rem_x: 0,
            rem_y: 0,
        }
    }

    /// The active configuration.
    #[must_use]
    pub fn config(&self) -> PointerAccelConfig {
        self.config
    }

    /// Replace the curve (clears the carried remainder so the next report is not
    /// scaled by the previous curve's leftover).
    pub fn set_config(&mut self, config: PointerAccelConfig) {
        self.config = config;
        self.reset();
    }

    /// Discard the accumulated sub-pixel remainder (e.g. on focus loss).
    pub fn reset(&mut self) {
        self.rem_x = 0;
        self.rem_y = 0;
    }

    /// Accelerate one raw `(dx, dy)` report into whole-pixel pointer motion,
    /// carrying the sub-pixel remainder to the next call.
    pub fn apply(&mut self, dx: i32, dy: i32) -> (i32, i32) {
        let speed = dx.unsigned_abs() + dy.unsigned_abs();
        let mult = i64::from(self.config.multiplier_milli(speed));
        let (out_x, rem_x) = Self::scale_axis(dx, mult, self.rem_x);
        let (out_y, rem_y) = Self::scale_axis(dy, mult, self.rem_y);
        self.rem_x = rem_x;
        self.rem_y = rem_y;
        (out_x, out_y)
    }

    /// Scale one axis: `delta * mult / 1000`, adding the prior remainder and
    /// returning `(whole_pixels, new_remainder)`. Truncation is toward zero so a
    /// negative delta carries a negative remainder — the sign stays consistent.
    #[allow(
        clippy::integer_division,
        reason = "fixed-point thousandths → whole pixels; remainder is preserved separately"
    )]
    #[allow(
        clippy::cast_possible_truncation,
        reason = "value is clamped to the i32 range immediately before the cast"
    )]
    fn scale_axis(delta: i32, mult_milli: i64, rem: i64) -> (i32, i64) {
        let scaled = i64::from(delta) * mult_milli + rem;
        let whole = scaled / 1000;
        let new_rem = scaled - whole * 1000;
        // `whole` is bounded by the i32 delta times the max multiplier / 1000;
        // clamp defensively so a pathological config cannot overflow the event.
        let out = whole.clamp(i64::from(i32::MIN), i64::from(i32::MAX)) as i32;
        (out, new_rem)
    }
}

impl Default for PointerAccelerator {
    fn default() -> Self {
        Self::new(PointerAccelConfig::default())
    }
}

// =============================================================================
// Pointer state: relative HID motion → absolute screen position (WS7-06.3)
// =============================================================================

/// Tracks the absolute pointer position on a screen and turns relative HID
/// mouse reports into [`DisplayInputEvent::Pointer`] events (WS7-06.3).
///
/// Raw `(dx, dy)` deltas are run through the [`PointerAccelerator`] sensitivity
/// curve, added to the current position, and clamped to the screen so the
/// pointer can never leave the visible area. The button mask (bit 0 = left,
/// 1 = right, 2 = middle) is carried through unchanged.
#[derive(Debug, Clone, Copy)]
pub struct PointerState {
    x: u32,
    y: u32,
    /// Exclusive screen bounds; valid positions are `0..width` × `0..height`.
    width: u32,
    height: u32,
    accel: PointerAccelerator,
}

impl PointerState {
    /// A new pointer for a `width × height` screen, starting at the centre.
    ///
    /// Dimensions are floored at `1` so the valid range is never empty.
    #[must_use]
    #[allow(
        clippy::integer_division,
        reason = "centre pixel; half-pixel bias is irrelevant"
    )]
    pub fn new(width: u32, height: u32, accel: PointerAccelerator) -> Self {
        let width = width.max(1);
        let height = height.max(1);
        Self {
            x: width / 2,
            y: height / 2,
            width,
            height,
            accel,
        }
    }

    /// The current absolute position `(x, y)`.
    #[must_use]
    pub fn position(&self) -> (u32, u32) {
        (self.x, self.y)
    }

    /// Warp the pointer to `(x, y)`, clamped to the screen.
    pub fn set_position(&mut self, x: u32, y: u32) {
        self.x = x.min(self.width - 1);
        self.y = y.min(self.height - 1);
    }

    /// Update the screen bounds (e.g. resolution change) and clamp the current
    /// position into the new area.
    pub fn set_bounds(&mut self, width: u32, height: u32) {
        self.width = width.max(1);
        self.height = height.max(1);
        self.x = self.x.min(self.width - 1);
        self.y = self.y.min(self.height - 1);
    }

    /// Apply a relative mouse report: accelerate `(dx, dy)`, move the clamped
    /// position, and return the resulting pointer event with `buttons`.
    pub fn motion(&mut self, dx: i32, dy: i32, buttons: u8) -> DisplayInputEvent {
        let (ax, ay) = self.accel.apply(dx, dy);
        self.x = clamp_add(self.x, ax, self.width);
        self.y = clamp_add(self.y, ay, self.height);
        DisplayInputEvent::Pointer {
            x: self.x,
            y: self.y,
            buttons,
        }
    }
}

/// Add a signed delta to an unsigned coordinate, saturating into `0..bound`.
fn clamp_add(pos: u32, delta: i32, bound: u32) -> u32 {
    let next = i64::from(pos) + i64::from(delta);
    let max = i64::from(bound.saturating_sub(1));
    // The clamp guarantees `0..=max`, which fits `u32`, so the conversion never
    // fails; the fallback is unreachable.
    u32::try_from(next.clamp(0, max)).unwrap_or(0)
}

// =============================================================================
// Key repeat (WS7-06.5)
// =============================================================================

/// The configurable key-repeat timing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KeyRepeatConfig {
    /// Delay (ms) after key-down before the first repeat fires.
    pub delay_ms: u32,
    /// Interval (ms) between repeats after the first.
    pub interval_ms: u32,
}

impl Default for KeyRepeatConfig {
    /// A typical desktop default: 500 ms to the first repeat, then ~30/s.
    fn default() -> Self {
        Self {
            delay_ms: 500,
            interval_ms: 33,
        }
    }
}

/// The currently held, repeating key.
#[derive(Debug, Clone, Copy)]
struct HeldKey {
    key: u32,
    pressed_at_ms: u64,
    /// How many repeat events have already been emitted for this hold.
    emitted: u32,
}

/// A key-repeat state machine (WS7-06.5).
///
/// Only the most recently pressed key repeats (typical keyboard behaviour):
/// pressing a second key while one is held hands the repeat to the new key.
/// [`Self::poll`] is driven by the compositor's frame/timer tick and returns how
/// many synthetic key events to emit for the held key since the last poll.
#[derive(Debug, Clone, Copy)]
pub struct KeyRepeater {
    config: KeyRepeatConfig,
    held: Option<HeldKey>,
}

impl KeyRepeater {
    /// A new repeater with the given timing.
    #[must_use]
    pub fn new(config: KeyRepeatConfig) -> Self {
        Self { config, held: None }
    }

    /// The active configuration.
    #[must_use]
    pub fn config(&self) -> KeyRepeatConfig {
        self.config
    }

    /// Replace the timing; the held key keeps repeating under the new config.
    pub fn set_config(&mut self, config: KeyRepeatConfig) {
        self.config = config;
    }

    /// The key currently repeating, if any.
    #[must_use]
    pub fn held_key(&self) -> Option<u32> {
        self.held.map(|h| h.key)
    }

    /// Register a key-down at `now_ms`; this key becomes the one that repeats.
    pub fn press(&mut self, key: u32, now_ms: u64) {
        self.held = Some(HeldKey {
            key,
            pressed_at_ms: now_ms,
            emitted: 0,
        });
    }

    /// Register a key-up. If it is the repeating key, repeats stop; a release of
    /// a non-repeating key is ignored (the held key keeps repeating).
    pub fn release(&mut self, key: u32) {
        if self.held.is_some_and(|h| h.key == key) {
            self.held = None;
        }
    }

    /// Advance the clock to `now_ms` and return how many repeat events should be
    /// emitted for the held key since the last poll (0 before the initial delay,
    /// or when no key is held).
    #[allow(
        clippy::integer_division,
        reason = "whole repeats elapsed since the delay; sub-interval time carries via `emitted`"
    )]
    pub fn poll(&mut self, now_ms: u64) -> u32 {
        let Some(held) = self.held.as_mut() else {
            return 0;
        };
        let elapsed = now_ms.saturating_sub(held.pressed_at_ms);
        let delay = u64::from(self.config.delay_ms);
        if elapsed < delay {
            return 0;
        }
        let interval = u64::from(self.config.interval_ms).max(1);
        // The first repeat is due at `delay`, the next every `interval` after.
        let due = 1 + (elapsed - delay) / interval;
        let due = u32::try_from(due).unwrap_or(u32::MAX);
        let new = due.saturating_sub(held.emitted);
        held.emitted = due;
        new
    }
}

impl Default for KeyRepeater {
    fn default() -> Self {
        Self::new(KeyRepeatConfig::default())
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn curve_is_flat_below_threshold_and_clamped_above() {
        let cfg = PointerAccelConfig::default(); // base 1000, thr 4, gain 200, max 3000
        assert_eq!(cfg.multiplier_milli(0), 1000);
        assert_eq!(cfg.multiplier_milli(4), 1000); // at threshold, still base
        assert_eq!(cfg.multiplier_milli(5), 1200); // 1000 + 200*1
        assert_eq!(cfg.multiplier_milli(14), 3000); // 1000 + 200*10 = 3000 (== max)
        assert_eq!(cfg.multiplier_milli(1000), 3000); // clamped
    }

    #[test]
    fn slow_motion_is_one_to_one() {
        let mut acc = PointerAccelerator::default();
        // speed 1 (<= threshold) → ×1.0, no remainder.
        assert_eq!(acc.apply(1, 0), (1, 0));
        assert_eq!(acc.apply(0, -1), (0, -1));
    }

    #[test]
    fn sub_pixel_remainder_accumulates_across_reports() {
        // A curve that yields ×1.5 at speed 1: base 1000, threshold 0, gain 500.
        let cfg = PointerAccelConfig {
            base_milli: 1000,
            threshold: 0,
            gain_milli: 500,
            max_milli: 100_000,
        };
        let mut acc = PointerAccelerator::new(cfg);
        // dx=1 at speed 1 → 1500 milli → 1 px out, 500 remainder.
        assert_eq!(acc.apply(1, 0), (1, 0));
        // Next identical report: 1500 + 500 carried = 2000 → 2 px out, 0 rem.
        assert_eq!(acc.apply(1, 0), (2, 0));
        // Over the two reports 2 raw px became 3 → the ×1.5 average is exact.
    }

    #[test]
    fn negative_remainder_is_symmetric() {
        let cfg = PointerAccelConfig {
            base_milli: 1000,
            threshold: 0,
            gain_milli: 500,
            max_milli: 100_000,
        };
        let mut acc = PointerAccelerator::new(cfg);
        assert_eq!(acc.apply(-1, 0), (-1, 0)); // -1500 → -1 px, -500 rem
        assert_eq!(acc.apply(-1, 0), (-2, 0)); // -1500 + -500 = -2000 → -2 px
    }

    #[test]
    fn reset_and_set_config_clear_the_remainder() {
        let cfg = PointerAccelConfig {
            base_milli: 1000,
            threshold: 0,
            gain_milli: 500,
            max_milli: 100_000,
        };
        let mut acc = PointerAccelerator::new(cfg);
        assert_eq!(acc.apply(1, 0), (1, 0)); // leaves rem 500
        acc.reset();
        // With the remainder cleared the next report starts fresh (1 px, not 2).
        assert_eq!(acc.apply(1, 0), (1, 0));
        // set_config also clears the remainder and swaps the curve.
        acc.apply(1, 0);
        acc.set_config(PointerAccelConfig::default());
        assert_eq!(acc.config(), PointerAccelConfig::default());
        assert_eq!(acc.apply(1, 0), (1, 0)); // default is ×1.0 at speed 1
    }

    // --- Key repeat (WS7-06.5) ----------------------------------------------

    fn repeater() -> KeyRepeater {
        KeyRepeater::new(KeyRepeatConfig {
            delay_ms: 500,
            interval_ms: 100,
        })
    }

    #[test]
    fn no_repeats_before_the_initial_delay() {
        let mut kr = repeater();
        kr.press(65, 0);
        assert_eq!(kr.held_key(), Some(65));
        assert_eq!(kr.poll(100), 0);
        assert_eq!(kr.poll(499), 0);
        // At exactly the delay the first repeat fires.
        assert_eq!(kr.poll(500), 1);
        // Polling again with no time passed emits nothing more.
        assert_eq!(kr.poll(500), 0);
    }

    #[test]
    fn repeats_accrue_at_the_configured_rate() {
        let mut kr = repeater();
        kr.press(65, 0);
        assert_eq!(kr.poll(500), 1); // first repeat at the delay
        // 700ms: due = 1 + (700-500)/100 = 3; already emitted 1 → 2 more.
        assert_eq!(kr.poll(700), 2);
        // 750ms: due still 3 → nothing new.
        assert_eq!(kr.poll(750), 0);
        // 800ms: due = 1 + 300/100 = 4 → 1 more.
        assert_eq!(kr.poll(800), 1);
    }

    #[test]
    fn release_stops_repeats_only_for_the_held_key() {
        let mut kr = repeater();
        kr.press(65, 0);
        // Releasing a different key does not stop the held key.
        kr.release(66);
        assert_eq!(kr.held_key(), Some(65));
        assert_eq!(kr.poll(550), 1); // first repeat at 500, next not until 600
        // Releasing the held key stops repeats.
        kr.release(65);
        assert_eq!(kr.held_key(), None);
        assert_eq!(kr.poll(2000), 0);
    }

    #[test]
    fn pressing_a_second_key_hands_over_the_repeat() {
        let mut kr = repeater();
        kr.press(65, 0);
        assert_eq!(kr.poll(550), 1);
        // A new key-down takes over and resets the repeat timing.
        kr.press(66, 1000);
        assert_eq!(kr.held_key(), Some(66));
        assert_eq!(kr.poll(1400), 0); // 400ms < delay for the new key
        assert_eq!(kr.poll(1500), 1); // first repeat of the new key
    }

    // --- Pointer state (WS7-06.3) -------------------------------------------

    /// A pointer on a 100×100 screen with a 1:1 (no-accel) curve for exact math.
    fn flat_pointer() -> PointerState {
        let flat = PointerAccelConfig {
            base_milli: 1000,
            threshold: u32::MAX,
            gain_milli: 0,
            max_milli: 1000,
        };
        PointerState::new(100, 100, PointerAccelerator::new(flat))
    }

    #[test]
    fn pointer_starts_centred_and_moves_relative() {
        let mut p = flat_pointer();
        assert_eq!(p.position(), (50, 50));
        let ev = p.motion(5, -10, 0b001);
        assert_eq!(
            ev,
            DisplayInputEvent::Pointer {
                x: 55,
                y: 40,
                buttons: 0b001
            }
        );
        assert_eq!(p.position(), (55, 40));
    }

    #[test]
    fn pointer_is_clamped_to_the_screen() {
        let mut p = flat_pointer();
        // Slam far past the top-left corner: clamps to (0, 0).
        p.motion(-1000, -1000, 0);
        assert_eq!(p.position(), (0, 0));
        // Slam past the bottom-right: clamps to (width-1, height-1).
        let ev = p.motion(1000, 1000, 0b010);
        assert_eq!(
            ev,
            DisplayInputEvent::Pointer {
                x: 99,
                y: 99,
                buttons: 0b010
            }
        );
    }

    #[test]
    fn set_position_and_bounds_clamp() {
        let mut p = flat_pointer();
        p.set_position(200, 3); // x clamps to 99, y stays 3
        assert_eq!(p.position(), (99, 3));
        // Shrinking the screen pulls the pointer inside the new area.
        p.set_bounds(40, 40);
        assert_eq!(p.position(), (39, 3));
    }

    #[test]
    fn buttons_pass_through_unchanged() {
        let mut p = flat_pointer();
        let ev = p.motion(0, 0, 0b101); // left + middle
        assert_eq!(
            ev,
            DisplayInputEvent::Pointer {
                x: 50,
                y: 50,
                buttons: 0b101
            }
        );
    }
}
