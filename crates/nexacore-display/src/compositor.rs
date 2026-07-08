//! Compositor: damage-driven back-to-front compositing.
//!
//! [`Compositor`] owns the [`WindowManager`] and the accumulated
//! [`DamageRegion`].  Every mutating operation records the affected screen
//! rect(s) in the damage region so that the next call to [`Compositor::composite`]
//! can repaint only the dirty areas.
//!
//! # Double-buffering contract
//!
//! The compositor writes into a *back buffer* (`back: &mut [u32]`, owned by
//! the caller — typically the bootable image).  After `composite` returns, the
//! image copies the listed dirty rects from the back buffer to the mapped
//! framebuffer (the "front" buffer).  This crate does not touch the
//! framebuffer directly; it stays allocation-light and framebuffer-agnostic
//! (ADR-0041 D1).
//!
//! # Security invariants (ADR-0041 D4)
//!
//! * A client damage rect that extends outside the surface is intersected with
//!   the surface bounds, translated to screen coordinates, then intersected
//!   with the screen bounds.  An out-of-bounds client rect becomes a
//!   clamped/empty rect — it never becomes an out-of-bounds framebuffer index.
//! * The back-buffer write uses bounds-checked slice indexing; no `unsafe`.
//! * A pixel slice of the wrong length is rejected by [`crate::surface::Surface::commit`]
//!   before any write occurs.
//!
//! # Focus border
//!
//! `composite` draws a 2-pixel solid border in `FOCUS_BORDER_COLOR` around
//! the focused window.  This is intentionally simple: the border is painted
//! as four filled rectangles at the window edges.  The border pixels are
//! written only within the damage region that triggered the repaint.
//!
//! # `no_std` compatibility
//!
//! Uses only `alloc::vec::Vec`; no `std` API is required.

use alloc::vec::Vec;

use crate::{
    DisplayError,
    effects::{RoundedRect, Shadow, shadow_alpha_at, shadow_bounds},
    geometry::{DamageRegion, Rect},
    surface::WindowId,
    window::Window,
    wm::WindowManager,
};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// ARGB colour of the 2-pixel active-window border — the petrol accent border
/// token (brand "leads/active" hue; the reserved brick red is kept for
/// governance/critical status, never window chrome).
pub const FOCUS_BORDER_COLOR: u32 = crate::tokens::BORDER_ACCENT;

/// Desktop background colour (ARGB), painted into every dirty rect first — the
/// brand dark canvas (charcoal-900).
///
/// Clearing a dirty rect to this colour BEFORE compositing windows over it is
/// what makes a close (or move) leave no ghost: the area a window vacated
/// shows the desktop, then only the windows still covering it repaint there.
pub const DESKTOP_BACKGROUND: u32 = crate::tokens::DESKTOP_CANVAS;

/// Optional window decoration applied when [`Compositor::decoration`] is set.
///
/// A soft drop shadow behind each window plus rounded outer corners, giving
/// windows depth and a modern silhouette.
///
/// Opt-in — the default (`None`) keeps the plain opaque-rectangle blit so the
/// damage-driven, pixel-exact compositor tests are unaffected. The shell turns
/// it on for the branded desktop.
#[derive(Debug, Clone, Copy)]
pub struct WindowDecoration {
    /// Outer corner radius in pixels.
    pub radius: u32,
    /// Drop shadow cast behind every window.
    pub shadow: Shadow,
    /// Optional 1px border colour (`0xAARRGGBB`) stroked just inside each
    /// window's outer edge (mockup: every window div gets
    /// `border:1px solid var(--border-default)`). `None` disables it —
    /// existing callers that don't want a border keep the old plain-blit
    /// look by passing `None` here.
    pub border: Option<u32>,
}

/// Blends `src` (opaque RGB) over `dst` by coverage/alpha `a` (0..=255) in sRGB
/// space. Fast path for `a == 0` / `a == 255`. Result is always opaque.
#[must_use]
#[allow(
    clippy::integer_division,
    reason = "8-bit alpha blend; /255 rounds toward zero, imperceptible for shadow/edge AA"
)]
fn blend_argb(src: u32, dst: u32, a: u8) -> u32 {
    if a == 0 {
        return dst;
    }
    if a == 0xFF {
        return 0xFF00_0000 | (src & 0x00FF_FFFF);
    }
    let a = u32::from(a);
    let ia = 255 - a;
    let sr = (src >> 16) & 0xFF;
    let sg = (src >> 8) & 0xFF;
    let sb = src & 0xFF;
    let dr = (dst >> 16) & 0xFF;
    let dg = (dst >> 8) & 0xFF;
    let db = dst & 0xFF;
    let r = (sr * a + dr * ia) / 255;
    let g = (sg * a + dg * ia) / 255;
    let b = (sb * a + db * ia) / 255;
    0xFF00_0000 | (r << 16) | (g << 8) | b
}

/// Width of the focus border in pixels.
const BORDER_PX: u32 = 2;

// ---------------------------------------------------------------------------
// Compositor
// ---------------------------------------------------------------------------

/// The NexaCore OS userspace compositor.
///
/// Owns the [`WindowManager`] (windows, focus, z-order, input routing) and
/// the accumulated [`DamageRegion`].  Callers drive the compositor by:
///
/// 1. Calling mutating operations (`commit_surface`, `move_window`, etc.),
///    each of which records damage.
/// 2. Calling [`Compositor::composite`] to repaint the dirty region into a
///    back buffer and receive the list of painted rects.
/// 3. Copying only those rects from the back buffer to the framebuffer.
///
/// # Example
///
/// ```
/// use nexacore_display::{
///     compositor::Compositor,
///     geometry::Rect,
///     surface::{Surface, SurfaceId},
/// };
///
/// let mut comp = Compositor::new(320, 240);
/// let surface = Surface::new(SurfaceId(0), 100, 80);
/// let id = comp.wm.create_window(10, 10, surface, String::from("w"));
/// comp.commit_surface(id, &[0xFF_FF_00_00u32; 8000], &[])
///     .unwrap();
/// let mut back = vec![0u32; 320 * 240];
/// let dirty = comp.composite(&mut back).unwrap();
/// assert!(!dirty.is_empty());
/// ```
pub struct Compositor {
    /// The window manager — owns all windows, focus, and z-order.
    pub wm: WindowManager,
    /// Accumulated dirty rects since the last `composite` call.
    damage: DamageRegion,
    /// The screen rectangle (`0, 0, screen_w, screen_h`).
    pub screen: Rect,
    /// Optional shadow + rounded-corner decoration applied to every window.
    /// `None` (default) = plain opaque blit.
    pub decoration: Option<WindowDecoration>,
    /// Screen-sized ARGB backdrop installed by [`Compositor::set_wallpaper_image`].
    ///
    /// When `Some`, it is always exactly `screen.w * screen.h` elements —
    /// [`Compositor::set_wallpaper_image`] only ever stores a buffer that has
    /// already been validated or resampled to that exact size. `None` (the
    /// default) keeps the procedural [`crate::wallpaper`] gradient backdrop.
    wallpaper_image: Option<Vec<u32>>,
}

impl Compositor {
    /// Creates a compositor for a screen of `screen_w × screen_h` pixels.
    ///
    /// # Example
    ///
    /// ```
    /// use nexacore_display::compositor::Compositor;
    /// let comp = Compositor::new(1920, 1080);
    /// assert_eq!(comp.screen.w, 1920);
    /// assert_eq!(comp.screen.h, 1080);
    /// ```
    #[must_use]
    pub fn new(screen_w: u32, screen_h: u32) -> Self {
        let screen = Rect {
            x: 0,
            y: 0,
            w: screen_w,
            h: screen_h,
        };
        Self {
            wm: WindowManager::new(screen),
            damage: DamageRegion::new(),
            screen,
            decoration: None,
            wallpaper_image: None,
        }
    }

    // -----------------------------------------------------------------------
    // Surface commit
    // -----------------------------------------------------------------------

    /// Commits new pixel content for the surface of window `window_id`.
    ///
    /// `pixels` must have exactly `surface.width * surface.height` elements;
    /// any other length is rejected with [`DisplayError::InvalidSize`] before
    /// any write occurs.
    ///
    /// Each rect in `client_damage` is:
    /// 1. Intersected with the surface bounds (untrusted client data).
    /// 2. Translated to screen coordinates.
    /// 3. Intersected with the screen bounds.
    /// 4. If non-empty, added to the compositor's [`DamageRegion`].
    ///
    /// If `client_damage` is empty, the entire window rect is added to damage.
    ///
    /// # Errors
    ///
    /// * [`DisplayError::UnknownWindow`] — `window_id` is not found.
    /// * [`DisplayError::InvalidSize`] — `pixels.len() != width * height`.
    pub fn commit_surface(
        &mut self,
        window_id: WindowId,
        pixels: &[u32],
        client_damage: &[Rect],
    ) -> Result<(), DisplayError> {
        // Validate window exists before touching anything.
        let win = self
            .wm
            .window_mut(window_id)
            .ok_or(DisplayError::UnknownWindow(window_id))?;

        // Validate and commit pixels (rejects wrong-length slices atomically).
        win.surface.commit(pixels)?;

        // Record damage.  Snapshot position + surface bounds before releasing
        // the borrow on `wm`.
        let win_x = win.x;
        let win_y = win.y;
        let surf_w = win.surface.width;
        let surf_h = win.surface.height;
        let surf_rect = Rect {
            x: 0,
            y: 0,
            w: surf_w,
            h: surf_h,
        };

        if client_damage.is_empty() {
            // Whole window is dirty.
            let screen_rect = Rect {
                x: win_x,
                y: win_y,
                w: surf_w,
                h: surf_h,
            };
            if let Some(clamped) = screen_rect.clamp_to(&self.screen) {
                self.damage.add(clamped);
            }
        } else {
            for &dr in client_damage {
                // Step 1: clamp to surface bounds.
                let Some(in_surf) = dr.clamp_to(&surf_rect) else {
                    continue; // entirely outside the surface
                };
                // Step 2: translate to screen coordinates.
                let in_screen = Rect {
                    x: in_surf.x + win_x,
                    y: in_surf.y + win_y,
                    w: in_surf.w,
                    h: in_surf.h,
                };
                // Step 3: clamp to screen.
                if let Some(final_rect) = in_screen.clamp_to(&self.screen) {
                    self.damage.add(final_rect);
                }
            }
        }
        Ok(())
    }

    // -----------------------------------------------------------------------
    // WM operations — each one accumulates damage
    // -----------------------------------------------------------------------

    /// Moves window `id` to `(x, y)` and damages both the old and new rects.
    ///
    /// # Errors
    ///
    /// Returns [`DisplayError::UnknownWindow`] if `id` is not found.
    pub fn move_window(&mut self, id: WindowId, x: i32, y: i32) -> Result<(), DisplayError> {
        // move_to returns the old rect; the new rect is computed after.
        let old_rect = self.wm.move_to(id, x, y)?;
        let new_rect = self.wm.window(id).map_or(old_rect, Window::screen_rect);

        // Damage old position (windows behind need recompositing there).
        if let Some(r) = old_rect.clamp_to(&self.screen) {
            self.damage.add(r);
        }
        // Damage new position (the window itself needs painting there).
        if let Some(r) = new_rect.clamp_to(&self.screen) {
            self.damage.add(r);
        }
        Ok(())
    }

    /// Raises window `id` to the top of the z-order and damages its rect.
    ///
    /// # Errors
    ///
    /// Returns [`DisplayError::UnknownWindow`] if `id` is not found.
    pub fn raise(&mut self, id: WindowId) -> Result<(), DisplayError> {
        self.wm.raise(id)?;
        if let Some(r) = self.wm.window(id).map(Window::screen_rect) {
            if let Some(clamped) = r.clamp_to(&self.screen) {
                self.damage.add(clamped);
            }
        }
        Ok(())
    }

    /// Sets focus to `id` and damages the old + new focused window rects.
    ///
    /// Damaging both rects ensures a focus border is redrawn on the newly
    /// focused window and removed from the previously focused one (ADR-0041 D3).
    ///
    /// # Errors
    ///
    /// Returns [`DisplayError::UnknownWindow`] if `id` is not found.
    pub fn set_focus(&mut self, id: WindowId) -> Result<(), DisplayError> {
        let (old, new) = self.wm.set_focus(id)?;
        // Damage old focused window so its focus border disappears.
        if let Some(old_id) = old {
            if old_id != new {
                if let Some(r) = self.wm.window(old_id).map(Window::screen_rect) {
                    if let Some(clamped) = r.clamp_to(&self.screen) {
                        self.damage.add(clamped);
                    }
                }
            }
        }
        // Damage new focused window so its focus border appears.
        if let Some(r) = self.wm.window(new).map(Window::screen_rect) {
            if let Some(clamped) = r.clamp_to(&self.screen) {
                self.damage.add(clamped);
            }
        }
        Ok(())
    }

    /// Cycles focus to the next window (Tab semantics) and damages old + new.
    ///
    /// No-op if there are no windows.
    pub fn cycle_focus(&mut self) {
        let old = self.wm.focused();
        let new = self.wm.cycle_focus();

        // Damage the old focused window.
        if let Some(oid) = old {
            if let Some(r) = self.wm.window(oid).map(Window::screen_rect) {
                if let Some(clamped) = r.clamp_to(&self.screen) {
                    self.damage.add(clamped);
                }
            }
        }
        // Damage the new focused window.
        if let Some(nid) = new {
            if let Some(r) = self.wm.window(nid).map(Window::screen_rect) {
                if let Some(clamped) = r.clamp_to(&self.screen) {
                    self.damage.add(clamped);
                }
            }
        }
    }

    /// Destroys window `id` and damages the screen region it occupied.
    ///
    /// Damaging the old rect ensures the windows behind are recomposed there
    /// — no ghosting (ADR-0041 D2).
    ///
    /// # Errors
    ///
    /// Returns [`DisplayError::UnknownWindow`] if `id` is not found.
    pub fn destroy(&mut self, id: WindowId) -> Result<(), DisplayError> {
        // Snapshot the rect before destroying.
        let old_rect = self.wm.window(id).map(Window::screen_rect);
        self.wm.destroy(id)?;
        if let Some(r) = old_rect {
            if let Some(clamped) = r.clamp_to(&self.screen) {
                self.damage.add(clamped);
            }
        }
        Ok(())
    }

    // -----------------------------------------------------------------------
    // Compositing
    // -----------------------------------------------------------------------

    /// Composites all dirty rects into `back` and returns the list of painted rects.
    ///
    /// Algorithm (ADR-0041 D1 + D2):
    ///
    /// 1. Clamp the damage region to the screen (defence-in-depth; should be
    ///    redundant but ensures no stale out-of-screen rect can slip through).
    /// 2. For each dirty rect `dr`:
    ///    a. Walk windows back-to-front (ascending z).
    ///    b. For each visible window, compute `window.screen_rect() ∩ dr`.
    ///    c. For each pixel in that intersection, copy the window's ARGB pixel
    ///       into `back` at the corresponding framebuffer position.
    ///    d. If the window is focused, paint the 2-pixel border.
    /// 3. Collect all dirty rects into the return list.
    /// 4. Clear the damage region.
    ///
    /// `back` must have exactly `screen.w * screen.h` `u32` pixels.  Returns
    /// [`DisplayError::BackBufferTooSmall`] if it is smaller (painting would
    /// be truncated).
    ///
    /// # Errors
    ///
    /// * [`DisplayError::BackBufferTooSmall`] if `back.len() < screen.w * screen.h`.
    pub fn composite(&mut self, back: &mut [u32]) -> Result<Vec<Rect>, DisplayError> {
        let expected_len = (self.screen.w as usize).saturating_mul(self.screen.h as usize);
        if back.len() < expected_len {
            return Err(DisplayError::BackBufferTooSmall);
        }

        // Clamp all damage rects to the screen (defence-in-depth).
        self.damage.clamp_all_to(&self.screen);

        // Collect the dirty rects we will paint (cloned before clearing).
        let dirty: Vec<Rect> = self.damage.iter().copied().collect();

        let focused_id = self.wm.focused();
        let decoration = self.decoration;

        // For each dirty rect, repaint by walking windows bottom to top.
        for &dr in &dirty {
            // Paint the branded wallpaper into the dirty rect FIRST, so any part
            // of it no longer covered by a window (e.g. after a close or move)
            // shows the desktop backdrop instead of the vacating window's stale
            // pixels (no ghosting). Windows then composite over the backdrop.
            fill_rect_wallpaper(
                back,
                self.screen.w,
                self.screen.h,
                &dr,
                self.wallpaper_image.as_deref(),
            );

            // Windows in z order (bottom → top).
            let windows: Vec<&Window> = self.wm.windows_bottom_to_top().collect();
            for win in &windows {
                if !win.visible {
                    continue;
                }
                let win_rect = win.screen_rect();

                if let Some(dec) = decoration {
                    // Decorated: soft drop shadow behind the window (over the
                    // wallpaper and any lower window), then the window blitted
                    // with AA-rounded outer corners. Focus is conveyed by z-order
                    // (the focused window is raised to the front).
                    paint_shadow(
                        back,
                        self.screen.w,
                        self.screen.h,
                        &win_rect,
                        dec.shadow,
                        &dr,
                    );
                    if let Some(paint_rect) = win_rect.intersect(&dr) {
                        blit_rect_rounded(
                            back,
                            self.screen.w,
                            win,
                            &paint_rect,
                            &win_rect,
                            dec.radius,
                            dec.border,
                        );
                    }
                } else {
                    // Plain: opaque blit + square focus border (default; keeps the
                    // pixel-exact tests unchanged).
                    let Some(paint_rect) = win_rect.intersect(&dr) else {
                        continue;
                    };
                    blit_rect(back, self.screen.w, win, &paint_rect);

                    if Some(win.id) == focused_id {
                        paint_focus_border(
                            back,
                            self.screen.w,
                            &win_rect,
                            &dr,
                            self.screen.w,
                            self.screen.h,
                        );
                    }
                }
            }
        }

        self.damage.clear();
        Ok(dirty)
    }

    /// Marks the entire screen dirty so the next [`Compositor::composite`]
    /// repaints — and the caller blits — every pixel.
    ///
    /// Called once at startup to lay down the full wallpaper and overwrite
    /// whatever the bootloader/kernel left in the framebuffer; without it a
    /// damage-driven first frame only touches the window rects and stale console
    /// text shows through the gaps.
    pub fn damage_all(&mut self) {
        self.damage.add(self.screen);
    }

    /// Marks a single screen-space `rect` dirty so the next
    /// [`Compositor::composite`] repaints it. `rect` need not be pre-clamped —
    /// `composite` clamps all damage to the screen. Used by the shell to repair
    /// the footprint a hardware-cursor overlay leaves behind as it moves,
    /// without repainting the whole screen.
    pub fn damage(&mut self, rect: Rect) {
        self.damage.add(rect);
    }

    /// Installs `img` as the desktop wallpaper, resampling it to the screen
    /// size when needed (bilinear). On resampling failure the procedural
    /// gradient stays in effect. Damages the whole screen so the next
    /// [`Compositor::composite`] repaints the backdrop.
    pub fn set_wallpaper_image(&mut self, img: crate::wallpaper::WallpaperImage) {
        let need = (self.screen.w as usize).saturating_mul(self.screen.h as usize);
        let buf = if img.w == self.screen.w && img.h == self.screen.h {
            (img.pixels.len() == need).then_some(img.pixels)
        } else {
            crate::scale::resample_bilinear(&img.pixels, img.w, img.h, self.screen.w, self.screen.h)
        };
        if let Some(buf) = buf {
            self.wallpaper_image = Some(buf);
            self.damage_all();
        }
    }
}

// ---------------------------------------------------------------------------
// Private helpers
// ---------------------------------------------------------------------------

/// Copies pixels from `win.surface` into `back` for the area covered by
/// `paint_rect` (which is already intersected with both the window rect and
/// the damage rect, and is guaranteed to lie within screen bounds).
///
/// All indexing is bounds-checked by the Rust compiler via slice indexing.
/// Fill a screen-space `rect` in the back buffer with the desktop backdrop.
///
/// When `wallpaper` is `Some` (an image installed via
/// [`Compositor::set_wallpaper_image`], always exactly `screen_w * screen_h`
/// pixels), each row segment is copied straight from it. Otherwise this falls
/// back to the petrol-800 → charcoal-900 vertical gradient
/// ([`crate::wallpaper::gradient_at`]) exactly as before image wallpapers
/// existed; since that gradient is vertical, each row's colour is computed
/// once and reused across the row.
///
/// `rect` is assumed clamped to the screen (non-negative, within bounds) by
/// the caller; every write is still bounds-checked via `get`/`get_mut` so a
/// stray rect (or a `wallpaper` buffer of the wrong length) can never index
/// out of either buffer.
fn fill_rect_wallpaper(
    back: &mut [u32],
    screen_w: u32,
    screen_h: u32,
    rect: &Rect,
    wallpaper: Option<&[u32]>,
) {
    if rect.is_empty() {
        return;
    }
    // `rect` is clamped to the screen before this call, so x/y are ≥ 0.
    #[allow(clippy::cast_sign_loss)]
    let base_x = rect.x.max(0) as u32;
    #[allow(clippy::cast_sign_loss)]
    let base_y = rect.y.max(0) as u32;
    for row in 0..rect.h {
        let dst_y = base_y + row;
        let row_base = (dst_y as usize) * (screen_w as usize);
        if let Some(buf) = wallpaper {
            // Image backdrop: copy the row segment straight from the stored
            // screen-sized buffer. `get` bounds-checks every access, so a
            // buffer shorter than `screen_w * screen_h` (should never happen —
            // `set_wallpaper_image` only stores validated/resampled buffers of
            // exactly that size) degrades to a partial/no-op fill rather than
            // an out-of-bounds read.
            for col in 0..rect.w {
                let dst_x = base_x + col;
                let dst_idx = row_base + (dst_x as usize);
                let Some(&color) = buf.get(dst_idx) else {
                    continue;
                };
                if let Some(slot) = back.get_mut(dst_idx) {
                    *slot = color;
                }
            }
        } else {
            let color = crate::wallpaper::gradient_at(dst_y, screen_h);
            for col in 0..rect.w {
                let dst_x = base_x + col;
                let dst_idx = row_base + (dst_x as usize);
                if let Some(slot) = back.get_mut(dst_idx) {
                    *slot = color;
                }
            }
        }
    }
}

fn blit_rect(back: &mut [u32], screen_w: u32, win: &Window, paint_rect: &Rect) {
    // paint_rect is guaranteed non-empty (callers check) and within screen.
    // The `.max(0)` guards against negative values when the window origin is
    // negative; the subsequent `as u32` cast is safe because the value is ≥ 0.
    let off_x = (paint_rect.x - win.x).max(0);
    let off_y = (paint_rect.y - win.y).max(0);
    // Safe: both values are ≥ 0 (guarded above) and the window dimensions are u32.
    #[allow(clippy::cast_sign_loss)]
    let src_col_start = off_x as u32;
    #[allow(clippy::cast_sign_loss)]
    let src_row_start = off_y as u32;
    // paint_rect.x is a screen coordinate inside the screen bounds (clamped before
    // this call), so it is always non-negative; the cast is safe.
    #[allow(clippy::cast_sign_loss)]
    let dst_col_base = paint_rect.x as u32;
    #[allow(clippy::cast_sign_loss)]
    let dst_row_base = paint_rect.y as u32;

    for row in 0..paint_rect.h {
        let src_y = src_row_start + row;
        let dst_y = dst_row_base + row;

        for col in 0..paint_rect.w {
            let src_x = src_col_start + col;
            let dst_x = dst_col_base + col;

            // Bounds-checked read from surface.
            let Some(pixel) = win.surface.pixel(src_x, src_y) else {
                continue; // surface pixel out of bounds — skip
            };

            // Bounds-checked write into the back buffer.
            let dst_idx = (dst_y as usize) * (screen_w as usize) + (dst_x as usize);
            if let Some(slot) = back.get_mut(dst_idx) {
                *slot = pixel;
            }
        }
    }
}

/// Paints `win_rect`'s soft drop shadow into `back`, clipped to `dr` and the
/// screen. Blended over whatever is already there (wallpaper / lower windows);
/// the window is blitted over it afterwards.
#[allow(
    clippy::cast_sign_loss,
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    reason = "shadow bounds are clamped to the screen before indexing"
)]
fn paint_shadow(
    back: &mut [u32],
    screen_w: u32,
    screen_h: u32,
    win_rect: &Rect,
    shadow: Shadow,
    dr: &Rect,
) {
    let bounds = shadow_bounds(*win_rect, shadow);
    let Some(area) = bounds.intersect(dr) else {
        return;
    };
    let x0 = area.x.max(0);
    let y0 = area.y.max(0);
    let x1 = (area.x + area.w as i32).min(screen_w as i32);
    let y1 = (area.y + area.h as i32).min(screen_h as i32);
    let mut py = y0;
    while py < y1 {
        let mut px = x0;
        while px < x1 {
            let a = shadow_alpha_at(*win_rect, shadow, px, py);
            if a != 0 {
                let idx = (py as usize) * (screen_w as usize) + (px as usize);
                if let Some(slot) = back.get_mut(idx) {
                    *slot = blend_argb(shadow.color, *slot, a);
                }
            }
            px += 1;
        }
        py += 1;
    }
}

/// Like [`blit_rect`] but blends each pixel by the window's rounded-corner
/// coverage, so the outer corners fade to the background — an AA-rounded window.
#[allow(
    clippy::cast_sign_loss,
    clippy::cast_possible_wrap,
    reason = "paint_rect is clamped to the screen and window bounds by the caller"
)]
fn blit_rect_rounded(
    back: &mut [u32],
    screen_w: u32,
    win: &Window,
    paint_rect: &Rect,
    win_rect: &Rect,
    radius: u32,
    border: Option<u32>,
) {
    let rr = RoundedRect::new(*win_rect, radius);
    // A 1px-inset rounded rect: the part of `rr`'s coverage NOT also covered
    // by this one is the border ring — a hard-edged 1px band on the
    // straight sides, an AA'd ring on the rounded corners (both share the
    // same `coverage_at` corner-arc maths, so the ring stays exactly 1px
    // wide all the way around).
    let inner_rr = border.map(|_| {
        let inset = Rect {
            x: win_rect.x + 1,
            y: win_rect.y + 1,
            w: win_rect.w.saturating_sub(2),
            h: win_rect.h.saturating_sub(2),
        };
        RoundedRect::new(inset, radius.saturating_sub(1))
    });
    let off_x = (paint_rect.x - win.x).max(0);
    let off_y = (paint_rect.y - win.y).max(0);
    let src_col_start = off_x as u32;
    let src_row_start = off_y as u32;
    let dst_col_base = paint_rect.x.max(0) as u32;
    let dst_row_base = paint_rect.y.max(0) as u32;

    for row in 0..paint_rect.h {
        let src_y = src_row_start + row;
        let dst_y = dst_row_base + row;
        for col in 0..paint_rect.w {
            let src_x = src_col_start + col;
            let dst_x = dst_col_base + col;
            let cov = rr.coverage_at(dst_x as i32, dst_y as i32);
            if cov == 0 {
                continue;
            }
            let Some(pixel) = win.surface.pixel(src_x, src_y) else {
                continue;
            };
            let dst_idx = (dst_y as usize) * (screen_w as usize) + (dst_x as usize);
            if let Some(slot) = back.get_mut(dst_idx) {
                *slot = if cov == 0xFF {
                    0xFF00_0000 | (pixel & 0x00FF_FFFF)
                } else {
                    blend_argb(pixel, *slot, cov)
                };
                if let (Some(border_color), Some(inner)) = (border, &inner_rr) {
                    let inner_cov = inner.coverage_at(dst_x as i32, dst_y as i32);
                    let ring_cov = cov.saturating_sub(inner_cov);
                    if ring_cov > 0 {
                        *slot = blend_argb(border_color, *slot, ring_cov);
                    }
                }
            }
        }
    }
}

/// Paints the 2-pixel focus border around `win_rect` in the area of `dr`.
///
/// The border is rendered as four filled strip rectangles (top, bottom, left,
/// right).  Each strip is clipped to `dr` before being written into `back`,
/// so pixels outside the damage region are never touched (ADR-0041 D2).
fn paint_focus_border(
    back: &mut [u32],
    screen_w: u32,
    win_rect: &Rect,
    dr: &Rect,
    back_w: u32,
    back_h: u32,
) {
    let screen = Rect {
        x: 0,
        y: 0,
        w: back_w,
        h: back_h,
    };
    // The four border strips:
    // top strip:    win_rect.x .. win_rect.x+w, win_rect.y .. win_rect.y+BORDER_PX
    // bottom strip: same x range, win_rect.bottom()-BORDER_PX .. win_rect.bottom()
    // left strip:   win_rect.x .. win_rect.x+BORDER_PX, full height
    // right strip:  win_rect.right()-BORDER_PX .. win_rect.right(), full height
    let bpx = BORDER_PX.min(win_rect.w).min(win_rect.h);

    // Construct the four strip rects (all in screen coordinates).
    // The bottom/right positions are computed in i64 and then cast to i32.
    // The casts are safe: bpx ≤ win_rect.h/w ≤ u32::MAX, and win_rect.bottom()/
    // right() are within screen bounds (the compositor always clamps rects to
    // the screen before painting), so the difference fits in i32.
    #[allow(clippy::cast_possible_truncation)]
    let bottom_y = (win_rect.bottom() - i64::from(bpx)) as i32;
    #[allow(clippy::cast_possible_truncation)]
    let right_x = (win_rect.right() - i64::from(bpx)) as i32;

    let border_rects = [
        // top
        Rect {
            x: win_rect.x,
            y: win_rect.y,
            w: win_rect.w,
            h: bpx,
        },
        // bottom
        Rect {
            x: win_rect.x,
            y: bottom_y,
            w: win_rect.w,
            h: bpx,
        },
        // left
        Rect {
            x: win_rect.x,
            y: win_rect.y,
            w: bpx,
            h: win_rect.h,
        },
        // right
        Rect {
            x: right_x,
            y: win_rect.y,
            w: bpx,
            h: win_rect.h,
        },
    ];

    for strip in &border_rects {
        // Clip the strip to both the damage rect and the screen.
        let Some(clipped) = strip.intersect(dr).and_then(|r| r.clamp_to(&screen)) else {
            continue;
        };
        // Paint the clipped strip.  `clipped` was produced by `clamp_to(&screen)`
        // so clipped.x ≥ 0 and clipped.y ≥ 0; the sign-loss cast is safe.
        #[allow(clippy::cast_sign_loss)]
        let row_base = clipped.y as u32;
        #[allow(clippy::cast_sign_loss)]
        let col_base = clipped.x as u32;
        for row in 0..clipped.h {
            let dst_y = row_base + row;
            for col in 0..clipped.w {
                let dst_x = col_base + col;
                let dst_idx = (dst_y as usize) * (screen_w as usize) + (dst_x as usize);
                if let Some(slot) = back.get_mut(dst_idx) {
                    *slot = FOCUS_BORDER_COLOR;
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unreadable_literal)]
mod tests {
    use alloc::{vec, vec::Vec};

    use super::*;
    use crate::surface::{Surface, SurfaceId};

    fn make_compositor(w: u32, h: u32) -> Compositor {
        Compositor::new(w, h)
    }

    fn add_window(comp: &mut Compositor, x: i32, y: i32, w: u32, h: u32, color: u32) -> WindowId {
        let count = comp.wm.windows_bottom_to_top().count();
        // Count is bounded by MAX_DAMAGE_RECTS (≪ u32::MAX) in tests.
        #[allow(clippy::cast_possible_truncation)]
        let sid = SurfaceId(count as u32);
        let surface = Surface::new(sid, w, h);
        let id = comp
            .wm
            .create_window(x, y, surface, alloc::string::String::new());
        let pixels = vec![color; (w * h) as usize];
        comp.commit_surface(id, &pixels, &[]).unwrap();
        id
    }

    // -----------------------------------------------------------------------
    // ACCEPTANCE TEST 1: damage — only dirty rects are returned and painted
    // -----------------------------------------------------------------------

    #[test]
    fn composite_returns_only_dirty_rect_not_whole_screen() {
        let sw = 200u32;
        let sh = 200u32;
        let mut comp = make_compositor(sw, sh);

        // Create a 100×100 red window at (0,0), commit whole.
        let id = add_window(&mut comp, 0, 0, 100, 100, 0xFFFF0000);
        let mut back = vec![0u32; (sw * sh) as usize];
        // Drain initial damage.
        comp.composite(&mut back).unwrap();

        // Now commit only a small sub-rect: columns 10..20, rows 5..15 in the surface.
        let small_damage = [Rect {
            x: 10,
            y: 5,
            w: 10,
            h: 10,
        }];
        comp.commit_surface(id, &vec![0xFFFF0000u32; 10_000], &small_damage)
            .unwrap();

        // Save pre-composite state to detect untouched pixels later.
        let back_before: Vec<u32> = back.clone();

        let dirty = comp.composite(&mut back).unwrap();

        // The dirty list must contain exactly one rect and it must be small
        // (definitely not the whole 200×200 screen or the whole 100×100 window).
        assert_eq!(dirty.len(), 1, "expected exactly one dirty rect");
        let dr = dirty[0];
        // The painted rect must be ≤ the small_damage rect translated to screen
        // (which is also at 10,5 since the window is at 0,0).
        assert!(dr.w <= 10 && dr.h <= 10, "dirty rect too large: {dr:?}");

        // Pixels OUTSIDE the dirty rect must be unchanged.
        // Screen coords (0..200) fit in i32; casts are safe.
        #[allow(clippy::cast_possible_wrap)]
        for y in 0..sh {
            #[allow(clippy::cast_possible_wrap)]
            for x in 0..sw {
                let idx = (y * sw + x) as usize;
                let in_dirty = dr.contains_point(x as i32, y as i32);
                if !in_dirty {
                    assert_eq!(
                        back[idx], back_before[idx],
                        "pixel at ({x},{y}) changed outside dirty rect {dr:?}"
                    );
                }
            }
        }
    }

    // -----------------------------------------------------------------------
    // ACCEPTANCE TEST 2: z-order — top window wins in overlap
    // -----------------------------------------------------------------------

    #[test]
    fn composite_top_window_wins_in_overlap() {
        let sw = 200u32;
        let sh = 200u32;
        let mut comp = make_compositor(sw, sh);

        // Bottom window: green, covers [0,0..100,100].
        let _bot = add_window(&mut comp, 0, 0, 100, 100, 0xFF00FF00);
        // Top window: red, covers [50,50..150,150] — overlaps bottom.
        let _top = add_window(&mut comp, 50, 50, 100, 100, 0xFFFF0000);

        let mut back = vec![0u32; (sw * sh) as usize];
        comp.composite(&mut back).unwrap();

        // In the overlap region [50,50..100,100], the red (top) window must win.
        // The top window (red) is also the focused window, so its 2-pixel border
        // will be painted FOCUS_BORDER_COLOR.  Check the interior pixels only
        // (i.e. skip the first/last BORDER_PX rows/cols of the red window, which
        // start at (50,50) and extend to (150,150) in screen space).
        let border = BORDER_PX;
        for y in (50 + border)..100u32 {
            for x in (50 + border)..100u32 {
                let idx = (y * sw + x) as usize;
                let pixel = back[idx];
                // Interior pixels must be red OR the focus border color.
                // The z-order invariant is: the red (top) window's pixels win
                // over the green (bottom) window.  The focus border is ALSO on
                // the red window so it's still "the top window wins".
                assert_ne!(
                    pixel, 0xFF00FF00,
                    "overlap interior pixel at ({x},{y}) should NOT be green (bottom window won)"
                );
            }
        }

        // Outside the overlap but inside bottom window, green should be visible.
        let idx = (10 * sw + 10) as usize;
        assert_eq!(back[idx], 0xFF00FF00, "non-overlap pixel should be green");
    }

    // -----------------------------------------------------------------------
    // ACCEPTANCE TEST 2b: closing a window leaves NO ghost
    // -----------------------------------------------------------------------

    #[test]
    fn closing_window_leaves_no_ghost() {
        let sw = 200u32;
        let sh = 200u32;
        let mut comp = make_compositor(sw, sh);

        // Bottom window: green [0,0..100,100].
        let bot = add_window(&mut comp, 0, 0, 100, 100, 0xFF00FF00);
        // Top window: red [50,50..150,150] — overlaps `bot` in [50,50..100,100]
        // and covers empty desktop in [100,100..150,150].
        let top = add_window(&mut comp, 50, 50, 100, 100, 0xFFFF0000);
        comp.set_focus(bot).unwrap(); // keep focus off the window we destroy
        let mut back = vec![0u32; (sw * sh) as usize];
        comp.composite(&mut back).unwrap();

        // Destroy the top (red) window and recomposite.
        comp.destroy(top).unwrap();
        comp.composite(&mut back).unwrap();

        // (a) In the red window's EXCLUSIVE area (over empty desktop, e.g.
        // (130,130)), the pixel must now be the desktop background — NOT a
        // leftover red ghost.
        let excl_idx = (130 * sw + 130) as usize;
        assert_eq!(
            back[excl_idx],
            crate::wallpaper::gradient_at(130, sh),
            "closed window's exclusive area must clear to the wallpaper (no ghost)"
        );
        assert_ne!(back[excl_idx], 0xFFFF0000, "red must not ghost after close");

        // (b) In the former overlap (e.g. (70,70)), the green (bottom) window
        // must now show through.
        let overlap_idx = (70 * sw + 70) as usize;
        assert_eq!(
            back[overlap_idx], 0xFF00FF00,
            "window behind must recompose where the closed window was"
        );
    }

    // -----------------------------------------------------------------------
    // ACCEPTANCE TEST 3: focus + input routing
    // -----------------------------------------------------------------------

    #[test]
    fn cycle_focus_advances_and_key_routes_to_focused_only() {
        use nexacore_types::display_channel::DisplayInputEvent;

        let sw = 400u32;
        let sh = 300u32;
        let mut comp = make_compositor(sw, sh);

        let a = add_window(&mut comp, 0, 0, 100, 80, 0xFF111111);
        let b = add_window(&mut comp, 200, 0, 100, 80, 0xFF222222);
        // b was just created and has higher z, so b has focus.
        assert_eq!(comp.wm.focused(), Some(b));

        // Cycle: b → a.
        comp.cycle_focus();
        let focused_after_cycle = comp.wm.focused().expect("focus must exist after cycle");
        assert_ne!(
            focused_after_cycle, b,
            "focus should have moved away from b"
        );

        // Key always goes to the focused window.
        let ev = DisplayInputEvent::Key {
            code: b'x',
            pressed: true,
        };
        let routed = comp.wm.route_input(&ev);
        assert_eq!(routed, comp.wm.focused());
        assert_ne!(routed, Some(b), "key must NOT route to unfocused window b");

        // Force focus to a, then verify routing again.
        comp.set_focus(a).unwrap();
        assert_eq!(comp.wm.route_input(&ev), Some(a));

        // Pointer hit-test (separate from focus).
        let ptr = DisplayInputEvent::Pointer {
            x: 250,
            y: 40,
            buttons: 0,
        };
        // Point (250,40) is inside window b.
        assert_eq!(comp.wm.route_input(&ptr), Some(b));

        // Pointer on empty desktop.
        let empty_ptr = DisplayInputEvent::Pointer {
            x: 350,
            y: 200,
            buttons: 0,
        };
        assert_eq!(comp.wm.route_input(&empty_ptr), None);
    }

    // -----------------------------------------------------------------------
    // ACCEPTANCE TEST 4: malicious client — clamp, no panic, all rects ⊆ screen
    // -----------------------------------------------------------------------

    #[test]
    fn malicious_client_damage_rect_does_not_panic_and_stays_within_screen() {
        let sw = 1920u32;
        let sh = 1080u32;
        let mut comp = make_compositor(sw, sh);

        let win_w = 200u32;
        let win_h = 150u32;
        let id = add_window(&mut comp, 50, 50, win_w, win_h, 0xFF0000FF);

        let mut back = vec![0u32; (sw * sh) as usize];
        // Drain initial full-window damage.
        comp.composite(&mut back).unwrap();

        // Malicious client damage rect: far outside surface AND screen.
        let evil_damage = [Rect {
            x: -1000,
            y: -1000,
            w: 100_000,
            h: 100_000,
        }];

        // Must not panic.  Build the pixel slice dynamically (array literal
        // size must be const, but win_w/win_h are runtime values).
        let evil_pixels = vec![0xFF0000FFu32; (win_w * win_h) as usize];
        comp.commit_surface(id, &evil_pixels, &evil_damage).unwrap();

        let dirty = comp.composite(&mut back).unwrap();

        // Every painted rect must lie entirely within the screen.
        let screen = Rect {
            x: 0,
            y: 0,
            w: sw,
            h: sh,
        };
        for dr in &dirty {
            assert!(
                dr.x >= screen.x,
                "dirty rect left edge {dr:?} outside screen"
            );
            assert!(
                dr.y >= screen.y,
                "dirty rect top edge {dr:?} outside screen"
            );
            assert!(
                dr.right() <= screen.right(),
                "dirty rect right edge {dr:?} outside screen"
            );
            assert!(
                dr.bottom() <= screen.bottom(),
                "dirty rect bottom edge {dr:?} outside screen"
            );
        }
    }

    #[test]
    fn commit_surface_wrong_pixel_length_is_err() {
        let mut comp = make_compositor(100, 100);
        let id = add_window(&mut comp, 0, 0, 50, 50, 0xFF000000);
        // Correct size is 50*50 = 2500. Provide wrong sizes.
        assert!(matches!(
            comp.commit_surface(id, &[0u32; 2499], &[]),
            Err(DisplayError::InvalidSize)
        ));
        assert!(matches!(
            comp.commit_surface(id, &[0u32; 2501], &[]),
            Err(DisplayError::InvalidSize)
        ));
        // Correct size succeeds.
        assert!(comp.commit_surface(id, &[0u32; 2500], &[]).is_ok());
    }

    // -----------------------------------------------------------------------
    // ACCEPTANCE TEST 5: destroy clears focus; move clamps; raise changes z
    // -----------------------------------------------------------------------

    #[test]
    fn destroy_clears_focus_to_next_topmost() {
        let mut comp = make_compositor(400, 300);
        let a = add_window(&mut comp, 0, 0, 50, 50, 0xFF111111);
        let b = add_window(&mut comp, 10, 10, 50, 50, 0xFF222222);
        // b is focused (created last, highest z).
        assert_eq!(comp.wm.focused(), Some(b));
        comp.destroy(b).unwrap();
        // Focus should fall to a.
        assert_eq!(comp.wm.focused(), Some(a));
    }

    #[test]
    fn destroy_unknown_window_is_error() {
        let mut comp = make_compositor(200, 200);
        assert!(matches!(
            comp.destroy(WindowId(999)),
            Err(DisplayError::UnknownWindow(_))
        ));
    }

    #[test]
    fn move_window_clamps_to_screen() {
        let sw = 800u32;
        let sh = 600u32;
        let mut comp = make_compositor(sw, sh);
        let id = add_window(&mut comp, 0, 0, 50, 50, 0xFF000000);
        // Move far outside screen.
        comp.move_window(id, -99_999, -99_999).unwrap();
        let win = comp.wm.window(id).unwrap();
        assert!(win.x >= 0, "x must be clamped: {}", win.x);
        assert!(win.y >= 0, "y must be clamped: {}", win.y);
    }

    #[test]
    fn raise_changes_z_order() {
        let mut comp = make_compositor(400, 300);
        let a = add_window(&mut comp, 0, 0, 50, 50, 0xFF111111);
        let _b = add_window(&mut comp, 5, 5, 50, 50, 0xFF222222);
        // b is on top after creation.  Raise a.
        comp.raise(a).unwrap();
        let top = comp.wm.windows_bottom_to_top().last().unwrap();
        assert_eq!(top.id, a, "after raise, a should be on top");
    }

    #[test]
    fn composite_back_buffer_too_small_returns_error() {
        let mut comp = make_compositor(100, 100);
        let mut small = vec![0u32; 99 * 100]; // one pixel short
        assert!(matches!(
            comp.composite(&mut small),
            Err(DisplayError::BackBufferTooSmall)
        ));
    }

    #[test]
    fn composite_empty_damage_returns_empty_dirty_list() {
        let mut comp = make_compositor(200, 200);
        let mut back = vec![0u32; 200 * 200];
        // No windows, no operations → damage region is empty.
        let dirty = comp.composite(&mut back).unwrap();
        assert!(dirty.is_empty());
    }

    #[test]
    fn destroy_damages_old_rect_no_ghosting() {
        let sw = 200u32;
        let sh = 200u32;
        let mut comp = make_compositor(sw, sh);

        // Red window at (20,20), 40×40.
        let id = add_window(&mut comp, 20, 20, 40, 40, 0xFFFF0000);
        let mut back = vec![0u32; (sw * sh) as usize];
        comp.composite(&mut back).unwrap();

        // Now destroy the window.
        comp.destroy(id).unwrap();
        let dirty = comp.composite(&mut back).unwrap();

        // The dirty list should contain the old window rect (so the background
        // behind it gets recomposed).
        assert!(
            !dirty.is_empty(),
            "destroy should produce damage so no ghosting occurs"
        );
    }

    // -----------------------------------------------------------------------
    // Image wallpaper (M2 Task 2)
    // -----------------------------------------------------------------------

    #[test]
    fn wallpaper_image_replaces_gradient_in_damage_repaint() {
        let (sw, sh) = (64u32, 48u32);
        let mut c = Compositor::new(sw, sh);
        let img = crate::wallpaper::WallpaperImage {
            w: sw,
            h: sh,
            pixels: alloc::vec![0xFF12_3456; (sw * sh) as usize],
        };
        c.set_wallpaper_image(img);
        let mut back = alloc::vec![0u32; (sw * sh) as usize];
        c.composite(&mut back).unwrap();
        assert_eq!(back[0], 0xFF12_3456);
        assert_eq!(back[(sw * sh - 1) as usize], 0xFF12_3456);
    }

    #[test]
    fn wallpaper_image_is_resampled_to_screen_size() {
        let mut c = Compositor::new(64, 48);
        let img = crate::wallpaper::WallpaperImage {
            w: 32,
            h: 24,
            pixels: alloc::vec![0xFFAA_BBCC; 32 * 24],
        };
        c.set_wallpaper_image(img);
        let mut back = alloc::vec![0u32; 64 * 48];
        c.composite(&mut back).unwrap();
        // A uniform source stays uniform under bilinear resampling.
        assert_eq!(back[0], 0xFFAA_BBCC);
        assert_eq!(back[64 * 48 - 1], 0xFFAA_BBCC);
    }

    // -----------------------------------------------------------------------
    // Window border (WS7 desktop M7)
    // -----------------------------------------------------------------------

    #[test]
    fn decorated_window_draws_a_one_pixel_border_ring() {
        let sw = 200u32;
        let sh = 200u32;
        let mut comp = make_compositor(sw, sh);
        comp.decoration = Some(WindowDecoration {
            radius: 0,
            shadow: Shadow {
                offset_y: 0,
                blur: 0,
                spread: 0,
                color: 0x0000_0000,
            },
            border: Some(0xFF00_00FF),
        });
        let _id = add_window(&mut comp, 20, 20, 60, 60, 0xFFFF_0000);
        let mut back = vec![0xFF00_0000u32; (sw * sh) as usize];
        comp.composite(&mut back).unwrap();

        #[allow(
            clippy::cast_sign_loss,
            reason = "test-only indices are always non-negative"
        )]
        let idx = |x: i32, y: i32| (y as usize) * (sw as usize) + (x as usize);
        assert_eq!(
            back[idx(50, 20)],
            0xFF00_00FF,
            "top edge row must be the border colour"
        );
        assert_eq!(
            back[idx(20, 50)],
            0xFF00_00FF,
            "left edge column must be the border colour"
        );
        assert_eq!(
            back[idx(50, 21)],
            0xFFFF_0000,
            "one pixel inside the border must be window content"
        );
        assert_eq!(
            back[idx(50, 50)],
            0xFFFF_0000,
            "window interior stays window content"
        );
    }
}
