//! Branded window chrome — titlebar + focus ring (WS7-19.8).
//!
//! Draws the decoration around a window: a rounded dark-material titlebar with
//! traffic-light controls (close = brick, minimize = goldenrod, maximize =
//! sage) and a centred title, plus — when the window is focused — a brick focus
//! accent. Everything routes through the anti-aliased, linear-blended
//! [`crate::canvas::Canvas`] primitives, so corners and the ring are smooth.

use alloc::string::String;

use nexacore_display::{geometry::Rect, tokens};

use crate::{
    canvas::Canvas,
    text::{draw_text, measure_text},
    theme::Theme,
};

/// Diameter of a traffic-light control dot, in pixels.
const CONTROL_D: u32 = 12;
/// Gap between control dots, in pixels.
const CONTROL_GAP: u32 = 8;

/// A window's chrome: its title and focus state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WindowChrome {
    /// The window title shown centred in the titlebar.
    pub title: String,
    /// Whether the window currently has focus (drives the focus accent and
    /// title brightness).
    pub focused: bool,
}

impl WindowChrome {
    /// Creates chrome for a window.
    #[must_use]
    pub fn new(title: impl Into<String>, focused: bool) -> Self {
        Self {
            title: title.into(),
            focused,
        }
    }

    /// Renders the titlebar into `titlebar_rect`.
    ///
    /// The titlebar is a rounded dark-material surface (a soft shadow gives it
    /// lift). Three traffic-light controls sit at the left; the title is centred
    /// in `TEXT_ON_DARK` when focused and the dimmer `TEXT_ON_DARK_SECONDARY`
    /// when not. A focused window also gets a 2-px brick focus accent along the
    /// top of the bar.
    #[allow(
        clippy::cast_possible_wrap,
        clippy::cast_sign_loss,
        clippy::cast_possible_truncation,
        clippy::integer_division,
        reason = "chrome geometry uses small positive pixel values; centring halves are exact"
    )]
    pub fn render(&self, canvas: &mut Canvas<'_>, theme: &Theme, titlebar_rect: &Rect) {
        // Elevated rounded material bar.
        canvas.draw_shadow(titlebar_rect, theme.elevation);
        canvas.fill_rounded_rect(titlebar_rect, theme.radius, tokens::SURFACE_DARK);

        // Focus accent: a brick band along the top edge (inset by the radius so
        // it hugs the rounded corners).
        if self.focused {
            let inset = theme.radius.min(titlebar_rect.w / 2) as i32;
            let accent = Rect {
                x: titlebar_rect.x + inset,
                y: titlebar_rect.y,
                w: titlebar_rect.w.saturating_sub(2 * theme.radius),
                h: 2,
            };
            canvas.fill_rect(&accent, tokens::FOCUS_RING);
        }

        // Traffic-light controls at the left, vertically centred.
        let cy = titlebar_rect.y + (titlebar_rect.h.saturating_sub(CONTROL_D) / 2) as i32;
        let mut cx = titlebar_rect.x + theme.padding as i32;
        for color in [tokens::BRICK_500, tokens::STATUS_WARNING, tokens::SAGE_500] {
            let dot = Rect {
                x: cx,
                y: cy,
                w: CONTROL_D,
                h: CONTROL_D,
            };
            // A dot is a fully-rounded square (radius = half side).
            canvas.fill_rounded_rect(&dot, CONTROL_D / 2, color);
            cx += (CONTROL_D + CONTROL_GAP) as i32;
        }

        // Centred title.
        let title_color = if self.focused {
            tokens::TEXT_ON_DARK
        } else {
            tokens::TEXT_ON_DARK_SECONDARY
        };
        let (tw, th) = measure_text(&self.title, theme.text_scale);
        let tx = titlebar_rect.x + (titlebar_rect.w.saturating_sub(tw) / 2) as i32;
        let ty = titlebar_rect.y + (titlebar_rect.h.saturating_sub(th) / 2) as i32;
        draw_text(canvas, tx, ty, &self.title, title_color, theme.text_scale);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const BG: u32 = 0xFF14_171A;

    fn render_bar(focused: bool) -> alloc::vec::Vec<u32> {
        let chrome = WindowChrome::new("Files", focused);
        let mut buf = alloc::vec![BG; 240 * 32];
        {
            let mut c = Canvas::new(&mut buf, 240, 32).unwrap();
            chrome.render(
                &mut c,
                &Theme::nexacore(),
                &Rect {
                    x: 0,
                    y: 0,
                    w: 240,
                    h: 32,
                },
            );
        }
        buf
    }

    #[test]
    fn draws_traffic_light_controls() {
        let buf = render_bar(true);
        assert!(buf.iter().any(|&p| p == tokens::BRICK_500), "no close dot");
        assert!(
            buf.iter().any(|&p| p == tokens::STATUS_WARNING),
            "no minimize dot"
        );
        assert!(
            buf.iter().any(|&p| p == tokens::SAGE_500),
            "no maximize dot"
        );
    }

    #[test]
    fn focus_state_changes_the_chrome() {
        let focused = render_bar(true);
        let unfocused = render_bar(false);
        // The focus accent (brick band) appears only when focused, so the two
        // renders differ.
        assert_ne!(focused, unfocused, "focus state must change the chrome");
    }
}
