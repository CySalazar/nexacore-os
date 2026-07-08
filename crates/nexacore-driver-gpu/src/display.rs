//! Display enumeration and resolution selection (WS2-09.9, host side).
//!
//! [`DisplayInfo`] wraps a parsed `GET_DISPLAY_INFO` response; [`select_mode`]
//! is the pure modesetting *policy* — choosing the resolution to drive a
//! scanout at — which is unit-tested here. Programming the chosen mode into the
//! device (the actual `SET_SCANOUT` against live hardware) is rig-side.

use alloc::vec::Vec;

use crate::protocol::{ParsedScanout, Rect, parse_display_info};

/// A selectable scanout mode (resolution). virtio-gpu does not advertise refresh
/// rate, so only the pixel dimensions are modelled.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ScanoutMode {
    /// Width in pixels.
    pub width: u32,
    /// Height in pixels.
    pub height: u32,
}

impl ScanoutMode {
    /// Pixel area (`width * height`), used to rank candidate modes.
    #[must_use]
    pub fn area(self) -> u64 {
        u64::from(self.width) * u64::from(self.height)
    }
}

/// Parsed display topology from a `GET_DISPLAY_INFO` response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DisplayInfo {
    scanouts: Vec<ParsedScanout>,
}

impl DisplayInfo {
    /// Parse from a raw `VIRTIO_GPU_RESP_OK_DISPLAY_INFO` response buffer.
    #[must_use]
    pub fn from_response(resp: &[u8]) -> Option<Self> {
        Some(Self {
            scanouts: parse_display_info(resp)?,
        })
    }

    /// All scanout slots (always [`crate::protocol::MAX_SCANOUTS`] long).
    #[must_use]
    pub fn scanouts(&self) -> &[ParsedScanout] {
        &self.scanouts
    }

    /// The number of enabled (connected) scanouts.
    #[must_use]
    pub fn enabled_count(&self) -> usize {
        self.scanouts.iter().filter(|s| s.enabled).count()
    }

    /// The preferred rectangle of scanout `id`, if it is enabled.
    #[must_use]
    pub fn preferred_rect(&self, id: usize) -> Option<Rect> {
        self.scanouts.get(id).filter(|s| s.enabled).map(|s| s.rect)
    }

    /// The preferred mode (resolution) of scanout `id`, if enabled.
    #[must_use]
    pub fn preferred_mode(&self, id: usize) -> Option<ScanoutMode> {
        self.preferred_rect(id).map(|r| ScanoutMode {
            width: r.width,
            height: r.height,
        })
    }
}

/// Select the best mode that fits within `max_width` × `max_height`.
///
/// Picks the largest-area candidate not exceeding either bound; ties break
/// toward the wider mode, then taller. Returns `None` if no candidate fits
/// (the caller then falls back to a safe default such as 1024×768).
#[must_use]
pub fn select_mode(
    candidates: &[ScanoutMode],
    max_width: u32,
    max_height: u32,
) -> Option<ScanoutMode> {
    candidates
        .iter()
        .copied()
        .filter(|m| m.width <= max_width && m.height <= max_height && m.width > 0 && m.height > 0)
        .max_by(|a, b| {
            a.area()
                .cmp(&b.area())
                .then(a.width.cmp(&b.width))
                .then(a.height.cmp(&b.height))
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::{Rect, build_display_info_resp};

    #[test]
    fn display_info_reports_enabled_and_preferred() {
        let scanouts = [
            ParsedScanout {
                rect: Rect::sized(3840, 2160),
                enabled: true,
            },
            ParsedScanout {
                rect: Rect::sized(1920, 1080),
                enabled: false,
            },
        ];
        let resp = build_display_info_resp(&scanouts);
        let info = DisplayInfo::from_response(&resp).expect("parse");
        assert_eq!(info.enabled_count(), 1);
        assert_eq!(
            info.preferred_mode(0),
            Some(ScanoutMode {
                width: 3840,
                height: 2160
            })
        );
        // Scanout 1 is disabled → no preferred mode.
        assert_eq!(info.preferred_mode(1), None);
    }

    #[test]
    fn select_mode_picks_largest_that_fits() {
        let modes = [
            ScanoutMode {
                width: 1280,
                height: 720,
            },
            ScanoutMode {
                width: 1920,
                height: 1080,
            },
            ScanoutMode {
                width: 3840,
                height: 2160,
            },
        ];
        // Bounded to 1080p → picks 1920×1080, not the 4K mode.
        assert_eq!(
            select_mode(&modes, 1920, 1080),
            Some(ScanoutMode {
                width: 1920,
                height: 1080
            })
        );
        // Tiny budget → smallest fits.
        assert_eq!(
            select_mode(&modes, 1366, 768),
            Some(ScanoutMode {
                width: 1280,
                height: 720
            })
        );
        // Nothing fits.
        assert_eq!(select_mode(&modes, 640, 480), None);
    }
}
