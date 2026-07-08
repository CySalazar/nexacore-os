//! Brand theme: palette + spacing for widget rendering.
//!
//! A [`Theme`] is the single source of truth for every colour and spacing
//! decision that widgets make.  Widgets **never** hard-code colours; they
//! always read from `theme.*`.  This means a future re-brand, dark-mode
//! toggle, or accessibility override is a one-struct change.
//!
//! ## Default theme — `Theme::nexacore()`
//!
//! The default theme implements the NexaCore OS brand (ADR-0042 D3):
//!
//! | Role | Colour | Hex | WCAG note |
//! |------|--------|-----|-----------|
//! | `bg_canvas` | cream | `#F4EBD0` | page background |
//! | `bg_surface` | petrol | `#0F4C5C` | widget surfaces |
//! | `text` | charcoal | `#1F2421` | charcoal-on-cream is 12.2:1 → AAA |
//! | `accent` | brick | `#C03221` | danger/button accent |
//! | `success` | sage | `#7A9E7E` | success state |
//! | `border` | petrol-700 | `#0A323C` | widget borders |
//!
//! ## Example
//!
//! ```
//! use nexacore_ui::{
//!     color::{BRICK, CHARCOAL, CREAM, PETROL, PETROL_700, SAGE},
//!     theme::Theme,
//! };
//!
//! let t = Theme::nexacore();
//! assert_eq!(t.bg_canvas, CREAM);
//! assert_eq!(t.bg_surface, PETROL);
//! assert_eq!(t.text, CHARCOAL);
//! assert_eq!(t.accent, BRICK);
//! assert_eq!(t.success, SAGE);
//! assert_eq!(t.border, PETROL_700);
//! assert_eq!(t.text_scale, 2);
//! assert_eq!(t.padding, 8);
//! assert_eq!(t.spacing, 6);
//! ```

use nexacore_display::effects::Shadow;

use crate::color::{BRICK, CHARCOAL, CREAM, PETROL, PETROL_700, SAGE};

// ---------------------------------------------------------------------------
// Theme
// ---------------------------------------------------------------------------

/// Visual theme: brand palette + layout spacing parameters.
///
/// All fields are `pub` for direct read access in widget rendering and layout
/// code.  Mutation is the caller's responsibility — create a new [`Theme`] for
/// each distinct look.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Theme {
    /// Background colour for the application canvas (page background).
    pub bg_canvas: u32,
    /// Background colour for widget surfaces (cards, panels, buttons).
    pub bg_surface: u32,
    /// Primary text colour.
    pub text: u32,
    /// Accent / danger / button-active colour.
    pub accent: u32,
    /// Success / OK state colour.
    pub success: u32,
    /// Widget border colour.
    pub border: u32,
    /// Integer scale applied to all text rendering (1 = 8×8 px, 2 = 16×16 px).
    pub text_scale: u32,
    /// Inner padding (pixels) inside widgets between the border and content.
    pub padding: u32,
    /// Gap (pixels) between sibling widgets in a container.
    pub spacing: u32,
    /// Corner radius (pixels) for rounded widget surfaces (cards, buttons,
    /// inputs). `0` yields square corners.
    pub radius: u32,
    /// Drop shadow cast by elevated surfaces, giving the desktop depth
    /// (WS7-19.4). Painted before the surface so the surface sits over it.
    pub elevation: Shadow,
}

impl Theme {
    /// Returns the canonical NexaCore OS brand theme.
    ///
    /// Contrast rationale (WCAG 2.1, from `brand/colors/palette.md`):
    /// - `text` (charcoal `#1F2421`) on `bg_canvas` (cream `#F4EBD0`): 12.2:1 — **AAA** all sizes.
    /// - `text` on `bg_surface` (petrol `#0F4C5C`): insufficient alone; use `bg_canvas` for text fields.
    /// - `accent` (brick `#C03221`) on `bg_canvas`: 4.7:1 — AA body, AAA large.
    /// - `border` (petrol-700 `#0A323C`) on `bg_canvas`: 12.6:1 — **AAA** all sizes.
    ///
    /// `text_scale = 2` gives 16×16 px glyphs — comfortably readable on
    /// 1024×768+ framebuffers.  `padding = 8` / `spacing = 6` follow the
    /// brand spacing grid.
    ///
    /// # Example
    ///
    /// ```
    /// use nexacore_ui::theme::Theme;
    ///
    /// let t = Theme::nexacore();
    /// assert_eq!(t.text_scale, 2);
    /// assert_eq!(t.padding, 8);
    /// ```
    #[must_use]
    pub const fn nexacore() -> Self {
        Self {
            bg_canvas: CREAM,
            bg_surface: PETROL,
            text: CHARCOAL,
            accent: BRICK,
            success: SAGE,
            border: PETROL_700,
            text_scale: 2,
            padding: 8,
            spacing: 6,
            radius: 6,
            elevation: Shadow {
                offset_y: 2,
                blur: 6,
                spread: 0,
                color: 0x4000_0000, // 25% black, soft
            },
        }
    }
}
