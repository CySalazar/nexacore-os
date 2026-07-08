//! [`Viewport`] — integer zoom/pan transform (WS8-03.3).
//!
//! Zoom is expressed in **permille** (`1000` = 100%) so the whole viewport is
//! integer math — no floating point, `no_std`-clean and deterministic. The
//! viewport maps image-space pixel coordinates to on-screen coordinates and
//! back, and computes a fit-to-screen zoom.

/// Smallest allowed zoom (10%).
pub const MIN_ZOOM_PERMILLE: u32 = 100;
/// Largest allowed zoom (3200%).
pub const MAX_ZOOM_PERMILLE: u32 = 32_000;
/// 100% zoom.
pub const UNIT_ZOOM_PERMILLE: u32 = 1000;

/// An integer zoom/pan transform over an image (WS8-03.3).
///
/// `pan` is the screen-space offset (in pixels) of the image origin. A positive
/// `pan_x` shifts the image to the right.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Viewport {
    /// Zoom factor in permille (`1000` = 100%).
    pub zoom_permille: u32,
    /// Screen-space x offset of the image origin, in pixels.
    pub pan_x: i32,
    /// Screen-space y offset of the image origin, in pixels.
    pub pan_y: i32,
}

impl Default for Viewport {
    fn default() -> Self {
        Self::new()
    }
}

impl Viewport {
    /// A reset viewport: 100% zoom, no pan.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            zoom_permille: UNIT_ZOOM_PERMILLE,
            pan_x: 0,
            pan_y: 0,
        }
    }

    /// Set the zoom, clamped to `[MIN_ZOOM_PERMILLE, MAX_ZOOM_PERMILLE]`.
    pub fn set_zoom(&mut self, permille: u32) {
        self.zoom_permille = permille.clamp(MIN_ZOOM_PERMILLE, MAX_ZOOM_PERMILLE);
    }

    /// Multiply the zoom by 1.25× (clamped), keeping the image point under
    /// screen-space `(anchor_x, anchor_y)` fixed.
    pub fn zoom_in(&mut self, anchor_x: i32, anchor_y: i32) {
        self.zoom_about(self.zoom_permille * 5 / 4, anchor_x, anchor_y);
    }

    /// Multiply the zoom by 0.8× (clamped), keeping the anchor point fixed.
    pub fn zoom_out(&mut self, anchor_x: i32, anchor_y: i32) {
        self.zoom_about(self.zoom_permille * 4 / 5, anchor_x, anchor_y);
    }

    /// Set the zoom to `new_permille` (clamped) while keeping the image point
    /// currently under screen `(anchor_x, anchor_y)` under the same screen point.
    pub fn zoom_about(&mut self, new_permille: u32, anchor_x: i32, anchor_y: i32) {
        let (img_x, img_y) = self.screen_to_image(anchor_x, anchor_y);
        self.set_zoom(new_permille);
        // Re-derive pan so (img_x, img_y) maps back to (anchor_x, anchor_y).
        let scaled_x = img_x * self.zoom_permille as i32 / UNIT_ZOOM_PERMILLE as i32;
        let scaled_y = img_y * self.zoom_permille as i32 / UNIT_ZOOM_PERMILLE as i32;
        self.pan_x = anchor_x - scaled_x;
        self.pan_y = anchor_y - scaled_y;
    }

    /// Translate the view by `(dx, dy)` screen pixels.
    pub fn pan(&mut self, dx: i32, dy: i32) {
        self.pan_x += dx;
        self.pan_y += dy;
    }

    /// Map an image-space pixel to its screen-space position.
    #[must_use]
    pub fn image_to_screen(&self, x: u32, y: u32) -> (i32, i32) {
        let sx = x as i32 * self.zoom_permille as i32 / UNIT_ZOOM_PERMILLE as i32 + self.pan_x;
        let sy = y as i32 * self.zoom_permille as i32 / UNIT_ZOOM_PERMILLE as i32 + self.pan_y;
        (sx, sy)
    }

    /// Map a screen-space position back to image-space (integer-rounded).
    #[must_use]
    pub fn screen_to_image(&self, sx: i32, sy: i32) -> (i32, i32) {
        let x = (sx - self.pan_x) * UNIT_ZOOM_PERMILLE as i32 / self.zoom_permille as i32;
        let y = (sy - self.pan_y) * UNIT_ZOOM_PERMILLE as i32 / self.zoom_permille as i32;
        (x, y)
    }

    /// The largest zoom (permille) at which an `image_w × image_h` image fits
    /// entirely within a `screen_w × screen_h` viewport (WS8-03.3 fit-to-screen).
    ///
    /// Returns [`UNIT_ZOOM_PERMILLE`] for a degenerate (zero) input.
    #[must_use]
    pub fn fit_zoom(image_w: u32, image_h: u32, screen_w: u32, screen_h: u32) -> u32 {
        if image_w == 0 || image_h == 0 || screen_w == 0 || screen_h == 0 {
            return UNIT_ZOOM_PERMILLE;
        }
        let zx = screen_w as u64 * UNIT_ZOOM_PERMILLE as u64 / image_w as u64;
        let zy = screen_h as u64 * UNIT_ZOOM_PERMILLE as u64 / image_h as u64;
        let z = zx.min(zy) as u32;
        z.clamp(MIN_ZOOM_PERMILLE, MAX_ZOOM_PERMILLE)
    }

    /// Reset to 100% zoom and centre an `image_w × image_h` image in a
    /// `screen_w × screen_h` viewport at fit-zoom.
    pub fn fit_and_centre(&mut self, image_w: u32, image_h: u32, screen_w: u32, screen_h: u32) {
        self.set_zoom(Self::fit_zoom(image_w, image_h, screen_w, screen_h));
        let scaled_w = image_w as i32 * self.zoom_permille as i32 / UNIT_ZOOM_PERMILLE as i32;
        let scaled_h = image_h as i32 * self.zoom_permille as i32 / UNIT_ZOOM_PERMILLE as i32;
        self.pan_x = (screen_w as i32 - scaled_w) / 2;
        self.pan_y = (screen_h as i32 - scaled_h) / 2;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_is_unit_no_pan() {
        let v = Viewport::new();
        assert_eq!(v.zoom_permille, UNIT_ZOOM_PERMILLE);
        assert_eq!((v.pan_x, v.pan_y), (0, 0));
    }

    #[test]
    fn set_zoom_clamps() {
        let mut v = Viewport::new();
        v.set_zoom(5);
        assert_eq!(v.zoom_permille, MIN_ZOOM_PERMILLE);
        v.set_zoom(999_999);
        assert_eq!(v.zoom_permille, MAX_ZOOM_PERMILLE);
    }

    #[test]
    fn image_to_screen_applies_zoom_and_pan() {
        let mut v = Viewport::new();
        v.set_zoom(2000); // 200%
        v.pan(10, 20);
        assert_eq!(v.image_to_screen(5, 5), (5 * 2 + 10, 5 * 2 + 20));
    }

    #[test]
    fn screen_to_image_is_inverse_at_unit() {
        let mut v = Viewport::new();
        v.pan(7, 9);
        let (ix, iy) = v.screen_to_image(20, 30);
        assert_eq!((ix, iy), (13, 21));
        assert_eq!(v.image_to_screen(13, 21), (20, 30));
    }

    #[test]
    fn zoom_about_keeps_anchor_point_fixed() {
        let mut v = Viewport::new();
        // The image point currently under screen (40, 40)...
        let before = v.screen_to_image(40, 40);
        v.zoom_about(2500, 40, 40);
        // ...maps back to (approximately) the same screen point.
        let after = v.image_to_screen(before.0 as u32, before.1 as u32);
        assert!((after.0 - 40).abs() <= 1, "x anchor drifted: {after:?}");
        assert!((after.1 - 40).abs() <= 1, "y anchor drifted: {after:?}");
    }

    #[test]
    fn fit_zoom_picks_limiting_dimension() {
        // 1000×500 image into a 500×500 viewport: width limits → 50% (500).
        assert_eq!(Viewport::fit_zoom(1000, 500, 500, 500), 500);
        // 500×1000 into 500×500: height limits → 50%.
        assert_eq!(Viewport::fit_zoom(500, 1000, 500, 500), 500);
    }

    #[test]
    fn fit_zoom_degenerate_returns_unit() {
        assert_eq!(Viewport::fit_zoom(0, 10, 10, 10), UNIT_ZOOM_PERMILLE);
        assert_eq!(Viewport::fit_zoom(10, 10, 0, 10), UNIT_ZOOM_PERMILLE);
    }

    #[test]
    fn fit_and_centre_centres_the_image() {
        let mut v = Viewport::new();
        v.fit_and_centre(100, 100, 400, 400);
        // fit zoom = 400% (4000), scaled image = 400×400 → fills exactly, pan 0.
        assert_eq!(v.zoom_permille, 4000);
        assert_eq!((v.pan_x, v.pan_y), (0, 0));
    }
}
