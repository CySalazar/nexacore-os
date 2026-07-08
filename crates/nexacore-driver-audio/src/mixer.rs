//! User-space mixer: stream summing + per-app volume (WS2-10.9, .10).
//!
//! The mixer sums several apps' signed-16-bit PCM streams into one output,
//! applying each stream's [`Volume`] and **saturating** at the i16 range so a
//! loud mix clips instead of wrapping (a wrap would be an audible pop and, for
//! a malicious app, a way to inject noise into others' audio). All arithmetic
//! is fixed-point integer; no floats, no `unsafe`.

use alloc::{vec, vec::Vec};

/// Per-app playback volume, as a percentage 0..=100.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Volume(u8);

impl Volume {
    /// Full volume (100%).
    pub const FULL: Self = Self(100);
    /// Muted (0%).
    pub const MUTED: Self = Self(0);

    /// Construct from a percentage, clamping to 0..=100.
    #[must_use]
    pub fn percent(p: u8) -> Self {
        Self(p.min(100))
    }

    /// The clamped percentage.
    #[must_use]
    pub fn as_percent(self) -> u8 {
        self.0
    }

    /// Scale a single sample by this volume (rounding toward zero).
    #[must_use]
    pub fn apply(self, sample: i16) -> i16 {
        // Widen to i32 so the multiply cannot overflow, divide by 100.
        ((i32::from(sample) * i32::from(self.0)) / 100) as i16
    }
}

/// A stateless PCM mixer over signed-16-bit samples.
#[derive(Debug, Default, Clone, Copy)]
pub struct Mixer;

impl Mixer {
    /// Sum equal-weight streams sample-wise, saturating at the i16 range. The
    /// output length is the longest input (shorter streams contribute silence
    /// past their end).
    #[must_use]
    pub fn mix(streams: &[&[i16]]) -> Vec<i16> {
        let len = streams.iter().map(|s| s.len()).max().unwrap_or(0);
        let mut out = vec![0i16; len];
        for stream in streams {
            for (o, &s) in out.iter_mut().zip(stream.iter()) {
                *o = o.saturating_add(s);
            }
        }
        out
    }

    /// Sum streams with per-stream [`Volume`], saturating at the i16 range.
    #[must_use]
    pub fn mix_weighted(streams: &[(&[i16], Volume)]) -> Vec<i16> {
        let len = streams.iter().map(|(s, _)| s.len()).max().unwrap_or(0);
        let mut out = vec![0i16; len];
        for (stream, vol) in streams {
            for (o, &s) in out.iter_mut().zip(stream.iter()) {
                *o = o.saturating_add(vol.apply(s));
            }
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn volume_scales_and_clamps_percent() {
        assert_eq!(Volume::percent(200).as_percent(), 100);
        assert_eq!(Volume::FULL.apply(1000), 1000);
        assert_eq!(Volume::percent(50).apply(1000), 500);
        assert_eq!(Volume::MUTED.apply(1000), 0);
        // Negative samples scale symmetrically (toward zero).
        assert_eq!(Volume::percent(50).apply(-1000), -500);
    }

    #[test]
    fn mix_sums_streams() {
        let a = [100i16, 200, 300];
        let b = [10i16, 20, 30];
        let out = Mixer::mix(&[&a, &b]);
        assert_eq!(out, vec![110, 220, 330]);
    }

    #[test]
    fn mix_saturates_instead_of_wrapping() {
        let a = [i16::MAX, i16::MIN];
        let b = [1000i16, -1000];
        let out = Mixer::mix(&[&a, &b]);
        // Would wrap without saturation; instead clamps to the rail.
        assert_eq!(out, vec![i16::MAX, i16::MIN]);
    }

    #[test]
    fn mix_uses_longest_stream_length() {
        let a = [1i16, 2, 3, 4];
        let b = [10i16, 10];
        let out = Mixer::mix(&[&a, &b]);
        assert_eq!(out, vec![11, 12, 3, 4]);
    }

    #[test]
    fn weighted_mix_applies_volume() {
        let a = [1000i16, 1000];
        let b = [1000i16, 1000];
        let out = Mixer::mix_weighted(&[(&a, Volume::percent(50)), (&b, Volume::percent(25))]);
        assert_eq!(out, vec![750, 750]); // 500 + 250
    }
}
