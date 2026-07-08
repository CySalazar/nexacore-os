//! Window frame geometry, hit-testing, and rendering (mockup parity).
//!
//! The mockup's titlebar: 42px tall, title at the left, and a pill button
//! group at the right — three 30×24 buttons (minimize, maximize, close) with
//! a 2px gap inside a 3px-padded 11px-radius container, 14px from the right
//! window edge. Everything below the titlebar is app content.

use nexacore_display::{font::Font, geometry::Rect};
use nexacore_ui::{canvas::Canvas, text::draw_text_aa};

use crate::{stroke::stroke_line, tokens::ShellTokens};

/// Titlebar height in pixels (mockup: 42px).
pub const TITLEBAR_H: u32 = 42;
/// Window corner radius in pixels (mockup: 17px).
pub const FRAME_RADIUS: u32 = 17;

/// Button size and pill-group metrics (mockup values).
const BTN_W: u32 = 30;
const BTN_H: u32 = 24;
const BTN_GAP: u32 = 2;
const GROUP_PAD: u32 = 3;
/// Distance from the group's right edge to the window's right edge.
const GROUP_MARGIN_RIGHT: u32 = 14;

/// One of the three titlebar buttons, in left-to-right order.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrameButton {
    /// Collapse the window to the (future) dock.
    Minimize,
    /// Toggle maximized ↔ restored.
    Maximize,
    /// Close the window.
    Close,
}

/// What a window-local point lands on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrameHit {
    /// A titlebar button.
    Button(FrameButton),
    /// The draggable titlebar area (everything in the bar except buttons).
    Drag,
    /// The app content region (or outside the window).
    Content,
}

/// The pill group's bounding rect (window-local).
#[must_use]
fn group_rect(win_w: u32) -> Rect {
    let w = GROUP_PAD * 2 + BTN_W * 3 + BTN_GAP * 2; // 100
    let h = BTN_H + GROUP_PAD * 2; // 30
    #[allow(
        clippy::cast_possible_wrap,
        clippy::integer_division,
        reason = "small positive pixel metrics; halving a small height truncates harmlessly"
    )]
    Rect {
        x: win_w.saturating_sub(GROUP_MARGIN_RIGHT + w) as i32,
        y: TITLEBAR_H.saturating_sub(h) as i32 / 2,
        w,
        h,
    }
}

/// The window-local rect of button `b` for a window `win_w` pixels wide.
#[must_use]
pub fn button_rect(win_w: u32, b: FrameButton) -> Rect {
    let g = group_rect(win_w);
    let index: u32 = match b {
        FrameButton::Minimize => 0,
        FrameButton::Maximize => 1,
        FrameButton::Close => 2,
    };
    #[allow(clippy::cast_possible_wrap, reason = "small positive pixel metrics")]
    Rect {
        x: g.x + (GROUP_PAD + index * (BTN_W + BTN_GAP)) as i32,
        y: g.y + GROUP_PAD as i32,
        w: BTN_W,
        h: BTN_H,
    }
}

/// Resolves a window-local point to a frame hit.
#[must_use]
pub fn hit_test(win_w: u32, x: i32, y: i32) -> FrameHit {
    #[allow(clippy::cast_possible_wrap, reason = "small positive pixel metrics")]
    let (w, bar_h) = (win_w as i32, TITLEBAR_H as i32);
    if x < 0 || x >= w || y < 0 || y >= bar_h {
        return FrameHit::Content;
    }
    for b in [
        FrameButton::Minimize,
        FrameButton::Maximize,
        FrameButton::Close,
    ] {
        let r = button_rect(win_w, b);
        #[allow(clippy::cast_possible_wrap, reason = "small positive pixel metrics")]
        if x >= r.x && x < r.x + r.w as i32 && y >= r.y && y < r.y + r.h as i32 {
            return FrameHit::Button(b);
        }
    }
    FrameHit::Drag
}

/// Which titlebar treatment a window gets.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrameVariant {
    /// Light/dark surface titlebar (most apps).
    Standard,
    /// The Terminal's always-dark titlebar.
    Terminal,
}

/// Title text size in px (mockup: 13px titles).
const TITLE_PX: f32 = 13.0;
/// Focus accent: 2px brick band inset 16px from each side (mockup).
const ACCENT_INSET: i32 = 16;
const ACCENT_H: u32 = 2;

/// A window's frame: title, focus, hover state, and variant.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WindowFrame<'a> {
    /// Title shown at the left of the bar.
    pub title: &'a str,
    /// Whether the window has focus (drives the brick accent + title colour).
    pub focused: bool,
    /// Which button, if any, the pointer is over (hover fill).
    pub hover: Option<FrameButton>,
    /// Titlebar treatment.
    pub variant: FrameVariant,
}

impl WindowFrame<'_> {
    /// Renders the titlebar into the top `TITLEBAR_H` rows of `canvas`.
    ///
    /// The caller has already filled the window background; this paints the
    /// bar fill, the soft bottom hairline, the focus accent, the title, and
    /// the three-button pill group with `hover` highlighting.
    #[allow(
        clippy::cast_possible_wrap,
        clippy::cast_sign_loss,
        clippy::float_arithmetic,
        clippy::cast_precision_loss,
        clippy::cast_possible_truncation,
        clippy::too_many_lines,
        reason = "small positive pixel metrics and glyph geometry; the titlebar paints \
                  bar fill, accent, title, and three buttons in one pass by design"
    )]
    pub fn render(
        &self,
        canvas: &mut Canvas<'_>,
        tokens: &ShellTokens,
        font: &Font<'_>,
        win_w: u32,
    ) {
        let (bar_bg, title_color) = match self.variant {
            FrameVariant::Standard => (
                tokens.titlebar_bg,
                if self.focused {
                    tokens.text_primary
                } else {
                    tokens.text_tertiary
                },
            ),
            FrameVariant::Terminal => (
                tokens.titlebar_bg_term,
                if self.focused {
                    tokens.text_secondary
                } else {
                    tokens.text_tertiary
                },
            ),
        };

        // Bar fill + bottom hairline.
        canvas.fill_rect(
            &Rect {
                x: 0,
                y: 0,
                w: win_w,
                h: TITLEBAR_H,
            },
            bar_bg,
        );
        canvas.fill_rect(
            &Rect {
                x: 0,
                y: TITLEBAR_H as i32 - 1,
                w: win_w,
                h: 1,
            },
            tokens.border_soft,
        );

        // Focus accent along the very top, inset from the corners.
        if self.focused {
            let w = win_w.saturating_sub(2 * ACCENT_INSET as u32);
            canvas.fill_rect(
                &Rect {
                    x: ACCENT_INSET,
                    y: 0,
                    w,
                    h: ACCENT_H,
                },
                tokens.brick,
            );
        }

        // Title, left-aligned at the mockup's 14px padding; baseline centred.
        let baseline = (TITLEBAR_H as f32 * 0.5 + TITLE_PX * 0.36) as i32;
        let _ = draw_text_aa(
            canvas,
            14,
            baseline,
            self.title,
            font,
            TITLE_PX,
            title_color,
        );

        // Pill group backdrop.
        let g = group_rect(win_w);
        canvas.fill_rounded_rect(&g, 11, tokens.btn_group_bg);

        // Buttons: hover fill + stroked glyph.
        for b in [
            FrameButton::Minimize,
            FrameButton::Maximize,
            FrameButton::Close,
        ] {
            let r = button_rect(win_w, b);
            let hovered = self.hover == Some(b);
            if hovered {
                let fill = match b {
                    FrameButton::Minimize => tokens.btn_hover_min,
                    FrameButton::Maximize => tokens.btn_hover_max,
                    FrameButton::Close => tokens.btn_hover_close,
                };
                canvas.fill_rounded_rect(&r, 7, fill);
            }
            let glyph = if hovered && b == FrameButton::Close {
                0xFFFF_FFFF
            } else {
                tokens.text_tertiary
            };
            let cx = r.x as f32 + r.w as f32 * 0.5;
            let cy = r.y as f32 + r.h as f32 * 0.5;
            match b {
                // Chevron down (mockup minimize icon).
                FrameButton::Minimize => {
                    stroke_line(canvas, cx - 3.5, cy - 1.5, cx, cy + 2.0, 1.6, glyph);
                    stroke_line(canvas, cx, cy + 2.0, cx + 3.5, cy - 1.5, 1.6, glyph);
                }
                // Four corner brackets (mockup maximize icon), 9×9 box.
                FrameButton::Maximize => {
                    let s = 4.5_f32; // half-size
                    let a = 2.5_f32; // bracket arm length
                    for (sx, sy) in [(-1.0_f32, -1.0_f32), (1.0, -1.0), (-1.0, 1.0), (1.0, 1.0)] {
                        let corner_x = cx + sx * s;
                        let corner_y = cy + sy * s;
                        stroke_line(
                            canvas,
                            corner_x,
                            corner_y,
                            corner_x - sx * a,
                            corner_y,
                            1.5,
                            glyph,
                        );
                        stroke_line(
                            canvas,
                            corner_x,
                            corner_y,
                            corner_x,
                            corner_y - sy * a,
                            1.5,
                            glyph,
                        );
                    }
                }
                // X (mockup close icon).
                FrameButton::Close => {
                    stroke_line(canvas, cx - 3.5, cy - 3.5, cx + 3.5, cy + 3.5, 1.7, glyph);
                    stroke_line(canvas, cx + 3.5, cy - 3.5, cx - 3.5, cy + 3.5, 1.7, glyph);
                }
            }
        }
    }
}

#[cfg(test)]
#[allow(
    clippy::cast_possible_wrap,
    reason = "test literals are small positive pixel metrics"
)]
mod geometry_tests {
    use super::*;

    const W: u32 = 486; // mockup Terminal width

    #[test]
    fn buttons_sit_right_aligned_in_the_titlebar() {
        let close = button_rect(W, FrameButton::Close);
        // group right edge is 14px from the window edge (mockup padding)
        assert_eq!(close.x + close.w as i32, (W - 14 - 3) as i32);
        assert_eq!(close.w, 30);
        assert_eq!(close.h, 24);
        // vertically centred in the 42px bar: (42-24)/2 = 9
        assert_eq!(close.y, 9);
        let min = button_rect(W, FrameButton::Minimize);
        let max = button_rect(W, FrameButton::Maximize);
        assert!(min.x < max.x && max.x < close.x, "order: min, max, close");
    }

    #[test]
    fn hit_test_resolves_buttons_drag_and_content() {
        let c = button_rect(W, FrameButton::Close);
        let inside = hit_test(W, c.x + 15, c.y + 12);
        assert_eq!(inside, FrameHit::Button(FrameButton::Close));
        assert_eq!(hit_test(W, 20, 20), FrameHit::Drag);
        // Bar/content boundary: the last in-bar row is Drag, the first row
        // below the 42px titlebar is Content.
        assert_eq!(hit_test(W, 20, 41), FrameHit::Drag);
        assert_eq!(hit_test(W, 20, 42), FrameHit::Content);
        assert_eq!(hit_test(W, 20, TITLEBAR_H as i32 + 1), FrameHit::Content);
        assert_eq!(
            hit_test(W, -1, 20),
            FrameHit::Content,
            "outside is content/none"
        );
    }
}

#[cfg(test)]
mod render_tests {
    use nexacore_display::font::Font;
    use nexacore_ui::canvas::Canvas;

    use super::*;
    use crate::tokens::ShellTokens;

    const W: u32 = 300;
    const H: u32 = 80;

    fn render(focused: bool, hover: Option<FrameButton>) -> alloc::vec::Vec<u32> {
        let t = ShellTokens::dark();
        let font = Font::parse(nexacore_fonts::BRAND_UI).unwrap();
        let mut buf = alloc::vec![t.bg_surface; (W * H) as usize];
        {
            let mut c = Canvas::new(&mut buf, W, H).unwrap();
            let f = WindowFrame {
                title: "Files",
                focused,
                hover,
                variant: FrameVariant::Standard,
            };
            f.render(&mut c, &t, &font, W);
        }
        buf
    }

    #[test]
    fn focus_accent_appears_only_when_focused() {
        let focused = render(true, None);
        let blurred = render(false, None);
        let brick = ShellTokens::dark().brick;
        assert!(
            focused.iter().any(|&p| p == brick),
            "focused bar has brick accent"
        );
        assert!(!blurred.iter().any(|&p| p == brick), "blurred bar has none");
    }

    #[test]
    fn close_hover_fills_brick() {
        let hovered = render(true, Some(FrameButton::Close));
        let plain = render(true, None);
        let brick = ShellTokens::dark().btn_hover_close;
        let count_h = hovered.iter().filter(|&&p| p == brick).count();
        let count_p = plain.iter().filter(|&&p| p == brick).count();
        assert!(count_h > count_p + 100, "close hover paints a brick pill");
    }
}
