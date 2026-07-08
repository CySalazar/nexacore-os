//! Per-window clipping — the *no desktop-in-desktop* rule (WS9-03.4).
//!
//! The guest renders **all** of its windows into one framebuffer (its headless
//! compositor's output). To integrate a single application window into the
//! NexaCore desktop, the host must sample **only that window's sub-rectangle**
//! of the guest framebuffer and present it as one surface. Presenting the
//! guest's whole output as a surface would nest an entire desktop inside the
//! host desktop — exactly what WS9-03 must avoid.
//!
//! [`WindowClip::compute`] turns a window's guest-framebuffer rectangle into
//! the **source rectangle** the host surface samples, clamped to the
//! framebuffer, and **rejects** any window that (nearly) covers the whole
//! output as a desktop-in-desktop.

use super::{AppBridgeError, AppBridgeResult, Rect, Size};

/// The clip solver: converts a window's guest-framebuffer rect into the source
/// rect a host surface samples, enforcing the no-desktop-in-desktop rule.
///
/// The rule is a coverage threshold: a window whose clamped area is at least
/// [`WindowClip::coverage_threshold_permille`] of the guest output area is
/// treated as the guest's root/background surface and rejected. The default
/// threshold is 95 % (`950‰`).
#[derive(Debug, Clone, Copy)]
pub struct WindowClip {
    coverage_threshold_permille: u32,
}

impl Default for WindowClip {
    fn default() -> Self {
        Self {
            coverage_threshold_permille: 950,
        }
    }
}

impl WindowClip {
    /// A clip solver with an explicit coverage threshold (in permille of the
    /// output area). Values are clamped to `1..=1000`.
    #[must_use]
    pub fn with_threshold(permille: u32) -> Self {
        Self {
            coverage_threshold_permille: permille.clamp(1, 1000),
        }
    }

    /// The configured desktop-in-desktop coverage threshold, in permille.
    #[must_use]
    pub fn coverage_threshold_permille(self) -> u32 {
        self.coverage_threshold_permille
    }

    /// Compute the source rectangle for a window within the guest framebuffer.
    ///
    /// `guest_rect` is the window's position within the framebuffer of size
    /// `output`. The returned rect is `guest_rect` clamped to the framebuffer.
    ///
    /// # Errors
    ///
    /// - [`AppBridgeError::OutOfBounds`] if the window lies entirely outside the
    ///   framebuffer, or the output has zero area.
    /// - [`AppBridgeError::DesktopInDesktop`] if the clamped window covers at
    ///   least the coverage threshold of the output area.
    pub fn compute(self, output: Size, guest_rect: Rect) -> AppBridgeResult<Rect> {
        if output.is_empty() {
            return Err(AppBridgeError::OutOfBounds);
        }
        let output_rect = Rect::new(0, 0, output.w, output.h);
        let clipped = guest_rect
            .intersect(output_rect)
            .ok_or(AppBridgeError::OutOfBounds)?;

        // Coverage = clipped_area / output_area, compared in permille without
        // floating point: clipped_area * 1000 >= threshold * output_area.
        let clipped_area = clipped.area();
        let output_area = output_rect.area();
        if clipped_area.saturating_mul(1000)
            >= u64::from(self.coverage_threshold_permille).saturating_mul(output_area)
        {
            return Err(AppBridgeError::DesktopInDesktop);
        }
        Ok(clipped)
    }

    /// Whether a window's rect would be accepted (does not raise an error).
    #[must_use]
    pub fn accepts(self, output: Size, guest_rect: Rect) -> bool {
        self.compute(output, guest_rect).is_ok()
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]
mod tests {
    use super::*;

    const OUT: Size = Size { w: 1920, h: 1080 };

    #[test]
    fn ordinary_window_clips_to_itself() {
        let clip = WindowClip::default();
        let r = Rect::new(100, 100, 400, 300);
        assert_eq!(clip.compute(OUT, r).unwrap(), r);
    }

    #[test]
    fn window_partly_offscreen_is_clamped() {
        let clip = WindowClip::default();
        // Window straddles the right edge.
        let r = Rect::new(1800, 100, 400, 300);
        let got = clip.compute(OUT, r).unwrap();
        assert_eq!(got, Rect::new(1800, 100, 120, 300));
    }

    #[test]
    fn fullscreen_window_is_desktop_in_desktop() {
        let clip = WindowClip::default();
        let r = Rect::new(0, 0, 1920, 1080);
        assert_eq!(clip.compute(OUT, r), Err(AppBridgeError::DesktopInDesktop));
    }

    #[test]
    fn nearly_fullscreen_window_is_rejected() {
        let clip = WindowClip::default();
        // 98 % coverage → above the 95 % default threshold.
        let r = Rect::new(0, 0, 1920, 1060);
        assert_eq!(clip.compute(OUT, r), Err(AppBridgeError::DesktopInDesktop));
    }

    #[test]
    fn large_but_sub_threshold_window_is_accepted() {
        let clip = WindowClip::default();
        // ~89 % coverage → below the 95 % default threshold.
        let r = Rect::new(0, 0, 1920, 960);
        assert!(clip.accepts(OUT, r));
    }

    #[test]
    fn fully_offscreen_is_out_of_bounds() {
        let clip = WindowClip::default();
        let r = Rect::new(4000, 4000, 100, 100);
        assert_eq!(clip.compute(OUT, r), Err(AppBridgeError::OutOfBounds));
    }

    #[test]
    fn custom_threshold_is_respected() {
        // A strict 50 % threshold rejects a 60 %-coverage window.
        let clip = WindowClip::with_threshold(500);
        let r = Rect::new(0, 0, 1920, 700); // ~65 %
        assert_eq!(clip.compute(OUT, r), Err(AppBridgeError::DesktopInDesktop));
    }
}
