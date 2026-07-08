//! System tray: status-bar indicator slots and their state (WS7-10.5 / .6).
//!
//! The tray is the right-hand region of the status bar holding small indicator
//! glyphs. [`Tray`] lays out a row of equal-width [slots] right-aligned in a
//! bounds rectangle (WS7-10.5); [`TrayIndicator`] models each indicator's
//! state — network, audio, battery, and the AI backend
//! ([`crate::status_bar::BackendState`]) — and reports a stable glyph name and
//! whether it needs attention (WS7-10.6).
//!
//! `no_std + alloc`, pure logic; the compositor draws the glyphs into the slot
//! rects.
//!
//! [slots]: Tray::slot_rects

// Slot counts and pixel offsets are bounded by the (validated) tray geometry;
// the `u32`→`i32` casts follow a `total > bounds.w` guard so the subtraction is
// non-negative.
#![allow(clippy::cast_possible_truncation, clippy::cast_possible_wrap)]

use alloc::vec::Vec;

use nexacore_display::geometry::Rect;

use crate::status_bar::BackendState;

/// Network connectivity bucket.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetworkState {
    /// No link.
    Disconnected,
    /// Weak signal.
    Weak,
    /// Fair signal.
    Fair,
    /// Strong signal.
    Strong,
}

/// Battery charge state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BatteryState {
    /// Charge percentage `0..=100`.
    pub percent: u8,
    /// `true` while charging / on AC.
    pub charging: bool,
}

/// Audio output state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AudioState {
    /// Output volume `0..=100`.
    pub volume: u8,
    /// `true` when muted.
    pub muted: bool,
}

/// A single tray indicator and its current state (WS7-10.6).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrayIndicator {
    /// Network connectivity.
    Network(NetworkState),
    /// Audio output.
    Audio(AudioState),
    /// Battery charge.
    Battery(BatteryState),
    /// AI backend health (shared with [`crate::status_bar`]).
    AiBackend(BackendState),
}

/// Battery percentage at or below which the battery indicator alerts.
pub const BATTERY_LOW_PERCENT: u8 = 15;

impl TrayIndicator {
    /// A stable glyph name the renderer maps to an icon, chosen by state.
    #[must_use]
    pub fn glyph(self) -> &'static str {
        match self {
            Self::Network(NetworkState::Disconnected) => "network-off",
            Self::Network(NetworkState::Weak) => "network-weak",
            Self::Network(NetworkState::Fair) => "network-fair",
            Self::Network(NetworkState::Strong) => "network-strong",
            Self::Audio(AudioState { muted: true, .. }) => "audio-muted",
            Self::Audio(AudioState { volume: 0, .. }) => "audio-off",
            Self::Audio(_) => "audio-on",
            Self::Battery(BatteryState { charging: true, .. }) => "battery-charging",
            Self::Battery(BatteryState { percent, .. }) if percent <= BATTERY_LOW_PERCENT => {
                "battery-low"
            }
            Self::Battery(_) => "battery",
            Self::AiBackend(BackendState::Gpu) => "ai-gpu",
            Self::AiBackend(BackendState::CpuDegraded) => "ai-cpu-degraded",
            Self::AiBackend(BackendState::Unknown) => "ai-unknown",
        }
    }

    /// `true` if the indicator needs the user's attention (low battery,
    /// disconnected, muted, or a degraded AI backend) — the renderer tints
    /// these with the alert color.
    #[must_use]
    pub fn is_alert(self) -> bool {
        match self {
            Self::Network(NetworkState::Disconnected) => true,
            Self::Audio(AudioState { muted, .. }) => muted,
            Self::Battery(BatteryState { percent, charging }) => {
                !charging && percent <= BATTERY_LOW_PERCENT
            }
            Self::AiBackend(state) => state == BackendState::CpuDegraded,
            Self::Network(_) => false,
        }
    }
}

/// The status-bar tray: an ordered row of indicator slots (WS7-10.5).
#[derive(Debug, Clone)]
pub struct Tray {
    indicators: Vec<TrayIndicator>,
    slot_w: u32,
    gap: u32,
}

impl Tray {
    /// Create an empty tray with `slot_w`-wide slots separated by `gap` px.
    #[must_use]
    pub fn new(slot_w: u32, gap: u32) -> Self {
        Self {
            indicators: Vec::new(),
            slot_w,
            gap,
        }
    }

    /// Append an indicator slot (leftmost-added is leftmost in the row).
    pub fn push(&mut self, indicator: TrayIndicator) {
        self.indicators.push(indicator);
    }

    /// The indicators, in row order (left to right).
    #[must_use]
    pub fn indicators(&self) -> &[TrayIndicator] {
        &self.indicators
    }

    /// Number of slots.
    #[must_use]
    pub fn len(&self) -> usize {
        self.indicators.len()
    }

    /// `true` if there are no indicators.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.indicators.is_empty()
    }

    /// Lay the slots out **right-aligned** within `bounds`: the row of
    /// equal-width slots is flush to the right edge, vertically filling the
    /// bounds height. Returns one [`Rect`] per indicator, in row order. An
    /// empty tray (or a row wider than `bounds`) yields an empty `Vec`.
    #[must_use]
    pub fn slot_rects(&self, bounds: Rect) -> Vec<Rect> {
        let n = self.indicators.len() as u32;
        if n == 0 || self.slot_w == 0 {
            return Vec::new();
        }
        // Total row width: n slots + (n-1) gaps.
        let total = self.slot_w * n + self.gap * n.saturating_sub(1);
        if total > bounds.w {
            return Vec::new();
        }
        // Right-align: the last slot's right edge meets `bounds`' right edge.
        let start_x = bounds.x + (bounds.w - total) as i32;
        let mut rects = Vec::with_capacity(self.indicators.len());
        for i in 0..n {
            let x = start_x + (i * (self.slot_w + self.gap)) as i32;
            rects.push(Rect {
                x,
                y: bounds.y,
                w: self.slot_w,
                h: bounds.h,
            });
        }
        rects
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn glyph_reflects_state() {
        assert_eq!(
            TrayIndicator::Network(NetworkState::Strong).glyph(),
            "network-strong"
        );
        assert_eq!(
            TrayIndicator::Audio(AudioState {
                volume: 50,
                muted: true
            })
            .glyph(),
            "audio-muted"
        );
        assert_eq!(
            TrayIndicator::Battery(BatteryState {
                percent: 10,
                charging: false
            })
            .glyph(),
            "battery-low"
        );
        assert_eq!(
            TrayIndicator::Battery(BatteryState {
                percent: 10,
                charging: true
            })
            .glyph(),
            "battery-charging"
        );
        assert_eq!(
            TrayIndicator::AiBackend(BackendState::Gpu).glyph(),
            "ai-gpu"
        );
    }

    #[test]
    fn alert_conditions() {
        assert!(TrayIndicator::Network(NetworkState::Disconnected).is_alert());
        assert!(!TrayIndicator::Network(NetworkState::Strong).is_alert());
        assert!(
            TrayIndicator::Audio(AudioState {
                volume: 30,
                muted: true
            })
            .is_alert()
        );
        assert!(
            TrayIndicator::Battery(BatteryState {
                percent: 5,
                charging: false
            })
            .is_alert()
        );
        // Low but charging ⇒ not an alert.
        assert!(
            !TrayIndicator::Battery(BatteryState {
                percent: 5,
                charging: true
            })
            .is_alert()
        );
        assert!(TrayIndicator::AiBackend(BackendState::CpuDegraded).is_alert());
        assert!(!TrayIndicator::AiBackend(BackendState::Gpu).is_alert());
    }

    #[test]
    fn slot_rects_are_right_aligned_with_gaps() {
        let mut tray = Tray::new(20, 4);
        tray.push(TrayIndicator::Network(NetworkState::Strong));
        tray.push(TrayIndicator::Audio(AudioState {
            volume: 50,
            muted: false,
        }));
        tray.push(TrayIndicator::AiBackend(BackendState::Gpu));
        assert_eq!(tray.len(), 3);
        // Bounds 200 wide; row = 3*20 + 2*4 = 68; start_x = 0 + (200-68) = 132.
        let bounds = Rect {
            x: 0,
            y: 2,
            w: 200,
            h: 24,
        };
        let rects = tray.slot_rects(bounds);
        assert_eq!(rects.len(), 3);
        assert_eq!(
            rects[0],
            Rect {
                x: 132,
                y: 2,
                w: 20,
                h: 24
            }
        );
        assert_eq!(
            rects[1],
            Rect {
                x: 156,
                y: 2,
                w: 20,
                h: 24
            }
        );
        assert_eq!(
            rects[2],
            Rect {
                x: 180,
                y: 2,
                w: 20,
                h: 24
            }
        );
        // Last slot's right edge meets the bounds' right edge.
        assert_eq!(rects[2].x + rects[2].w as i32, bounds.x + bounds.w as i32);
    }

    #[test]
    fn slot_rects_empty_when_no_room_or_no_slots() {
        let empty = Tray::new(20, 4);
        assert!(
            empty
                .slot_rects(Rect {
                    x: 0,
                    y: 0,
                    w: 100,
                    h: 24
                })
                .is_empty()
        );

        let mut tray = Tray::new(60, 8);
        tray.push(TrayIndicator::Network(NetworkState::Fair));
        tray.push(TrayIndicator::Network(NetworkState::Fair));
        // row = 2*60 + 8 = 128 > 100 ⇒ no room.
        assert!(
            tray.slot_rects(Rect {
                x: 0,
                y: 0,
                w: 100,
                h: 24
            })
            .is_empty()
        );
    }
}
