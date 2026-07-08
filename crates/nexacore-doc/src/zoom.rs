//! Zoom + fit-to-width/page (WS8-04.7).
//!
//! Zoom is expressed in **permille** (1000 = 100 %), integer-only, so the crate
//! stays `no_std` and deterministic. 100 % is defined as "one PDF point renders
//! to one screen pixel" (72 dpi), the natural baseline for the layout math.

use crate::model::PointSize;

/// Minimum zoom (10 %).
pub const MIN_SCALE_PERMILLE: u32 = 100;

/// Maximum zoom (800 %).
pub const MAX_SCALE_PERMILLE: u32 = 8000;

/// A page size in screen pixels at 100 % (numerically equal to its
/// [`PointSize`] under the 1-point-per-pixel baseline).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PxSize {
    /// Width in pixels at 100 %.
    pub width: u32,
    /// Height in pixels at 100 %.
    pub height: u32,
}

impl From<PointSize> for PxSize {
    fn from(p: PointSize) -> Self {
        Self {
            width: p.width,
            height: p.height,
        }
    }
}

/// The visible viewport (content area) in pixels, minus any chrome.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Viewport {
    /// Content-area width in pixels.
    pub width: u32,
    /// Content-area height in pixels.
    pub height: u32,
}

/// How the document scales to the viewport.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ZoomMode {
    /// An explicit zoom in permille (1000 = 100 %).
    Custom(u32),
    /// Scale so the page width exactly fills the viewport width.
    FitWidth,
    /// Scale so the whole page fits within the viewport (both dimensions).
    FitPage,
}

/// Clamp a permille scale to `[MIN_SCALE_PERMILLE, MAX_SCALE_PERMILLE]`.
#[must_use]
pub fn clamp_scale(permille: u32) -> u32 {
    permille.clamp(MIN_SCALE_PERMILLE, MAX_SCALE_PERMILLE)
}

/// Resolve a [`ZoomMode`] to a concrete scale in permille for `page` shown in
/// `viewport`. The result is always clamped to the supported range.
///
/// A zero-sized page or viewport falls back to 100 % (`1000`) — there is no
/// meaningful fit ratio to compute.
#[must_use]
pub fn resolve_scale_permille(mode: ZoomMode, page: PxSize, viewport: Viewport) -> u32 {
    let scale = match mode {
        ZoomMode::Custom(p) => p,
        ZoomMode::FitWidth => fit_ratio(viewport.width, page.width),
        ZoomMode::FitPage => {
            let w = fit_ratio(viewport.width, page.width);
            let h = fit_ratio(viewport.height, page.height);
            w.min(h)
        }
    };
    clamp_scale(scale)
}

/// `available / content` as a permille ratio, saturating. Returns 1000 (100 %)
/// when `content` is zero (no meaningful ratio).
fn fit_ratio(available: u32, content: u32) -> u32 {
    if content == 0 {
        return 1000;
    }
    // permille = available * 1000 / content, in u64 to avoid overflow.
    let r = u64::from(available)
        .saturating_mul(1000)
        .checked_div(u64::from(content))
        .unwrap_or(1000);
    // Saturate into u32 before the caller clamps to MAX.
    u32::try_from(r).unwrap_or(MAX_SCALE_PERMILLE)
}

/// Apply a permille scale to a length, rounding to nearest pixel.
#[must_use]
pub fn scale_length(length: u32, permille: u32) -> u32 {
    let v = u64::from(length).saturating_mul(u64::from(permille)) + 500;
    u32::try_from(v / 1000).unwrap_or(u32::MAX)
}

/// The on-screen pixel size of `page` at `permille` zoom.
#[must_use]
pub fn scaled_page(page: PxSize, permille: u32) -> PxSize {
    PxSize {
        width: scale_length(page.width, permille),
        height: scale_length(page.height, permille),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const A4: PxSize = PxSize {
        width: 595,
        height: 842,
    };

    #[test]
    fn fit_width_fills_viewport_width() {
        // viewport 1190 wide vs 595-pt page → exactly 200 %.
        let vp = Viewport {
            width: 1190,
            height: 400,
        };
        assert_eq!(resolve_scale_permille(ZoomMode::FitWidth, A4, vp), 2000);
    }

    #[test]
    fn fit_page_uses_the_limiting_dimension() {
        // Wide-but-short viewport: height is the limiter.
        let vp = Viewport {
            width: 5950,
            height: 842,
        };
        // width ratio = 1000%, height ratio = 100% → min = 100%.
        assert_eq!(resolve_scale_permille(ZoomMode::FitPage, A4, vp), 1000);
    }

    #[test]
    fn custom_zoom_is_clamped() {
        let vp = Viewport {
            width: 100,
            height: 100,
        };
        assert_eq!(
            resolve_scale_permille(ZoomMode::Custom(50), A4, vp),
            MIN_SCALE_PERMILLE
        );
        assert_eq!(
            resolve_scale_permille(ZoomMode::Custom(99_999), A4, vp),
            MAX_SCALE_PERMILLE
        );
        assert_eq!(resolve_scale_permille(ZoomMode::Custom(1500), A4, vp), 1500);
    }

    #[test]
    fn zero_page_falls_back_to_100_percent() {
        let zero = PxSize {
            width: 0,
            height: 0,
        };
        let vp = Viewport {
            width: 800,
            height: 600,
        };
        assert_eq!(resolve_scale_permille(ZoomMode::FitWidth, zero, vp), 1000);
        assert_eq!(resolve_scale_permille(ZoomMode::FitPage, zero, vp), 1000);
    }

    #[test]
    fn scale_length_rounds_to_nearest() {
        assert_eq!(scale_length(100, 1000), 100); // 100%
        assert_eq!(scale_length(100, 1500), 150); // 150%
        assert_eq!(scale_length(3, 1500), 5); // 4.5 → 5 (round)
        assert_eq!(scaled_page(A4, 2000).width, 1190);
    }
}
