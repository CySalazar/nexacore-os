//! NexaCore design tokens — the machine-consumable layer of the NexaCore Design
//! Language / Human Interface Guidelines (WS7-00).
//!
//! This module is the typed encoding of the tokens specified in
//! `docs/design/nexacore-hig.md`. The HIG is the canonical human-readable spec:
//! when this module and the HIG disagree, the HIG wins and this module is
//! updated to match. The brand source of truth for color + typography is
//! `brand/` (`brand/colors/tokens.json`, `brand/typography/type-tokens.css`).
//!
//! ## Provenance
//!
//! - **Color** (§ [`color`]) mirrors `brand/colors/tokens.json` (core ramps +
//!   semantic tokens), encoded as `0xAARRGGBB`.
//! - **Typography** (§ [`typography`]) mirrors `brand/typography/type-tokens.css`.
//! - **Spacing, radii, elevation, motion, materials, states, density** are
//!   HIG-introduced (the brand pack specifies only color + type). They encode
//!   `docs/design/nexacore-hig.md` §§2,5–10, derived from the Direction-C civic-tech
//!   design DNA in `brand/STRATEGY.md`: generous whitespace, restrained motion
//!   that never suggests velocity, minimal ornament, stable type weights.
//!
//! Colors are `0xAARRGGBB` `u32` to match [`crate::color`] and the framebuffer;
//! shadow/material alphas carry per-token opacity.

// ===========================================================================
// Color — mirrors brand/colors/tokens.json (HIG §4)
// ===========================================================================

/// Color tokens: core ramps + semantic roles.
///
/// Re-exported from the canonical source of truth in
/// [`nexacore_display::tokens`] (WS7-19.1) so the brand ramp is defined exactly
/// once for the whole graphics stack — the compositor consumes the same module.
pub mod color {
    pub use nexacore_display::tokens::*;
}

// ===========================================================================
// Spacing — 8 px base grid (HIG §2)
// ===========================================================================

/// Spacing scale in logical pixels, base unit [`space::BASE`] = 8 px (HIG §2.2).
///
/// Every step is a multiple of 8 except [`space::PX`] (1 px hairline) and [`space::HALF`]
/// (4 px, dense control internals only). Token names follow the HIG `space-*`
/// index. "Generous whitespace" (brand DNA) means layout prefers the larger
/// steps.
pub mod space {
    /// The grid base unit.
    pub const BASE: u16 = 8;
    /// `space-0` — 0 px (reset / flush).
    pub const S0: u16 = 0;
    /// `space-px` — 1 px (hairline borders only).
    pub const PX: u16 = 1;
    /// `space-0.5` — 4 px half-step (dense control internals only).
    pub const HALF: u16 = 4;
    /// `space-1` — 8 px (1× base).
    pub const S1: u16 = 8;
    /// `space-2` — 16 px (2× base).
    pub const S2: u16 = 16;
    /// `space-3` — 24 px (3× base).
    pub const S3: u16 = 24;
    /// `space-4` — 32 px (4× base).
    pub const S4: u16 = 32;
    /// `space-5` — 40 px (5× base).
    pub const S5: u16 = 40;
    /// `space-6` — 48 px (6× base).
    pub const S6: u16 = 48;
    /// `space-8` — 64 px (8× base).
    pub const S8: u16 = 64;
    /// `space-10` — 80 px (10× base).
    pub const S10: u16 = 80;
}

// ===========================================================================
// Typography — mirrors brand/typography/type-tokens.css (HIG §3)
// ===========================================================================

/// Typographic tokens: family stacks, a 1.250 modular size scale, line heights,
/// tracking and weights (`brand/typography/type-tokens.css`).
pub mod typography {
    /// Display / heading family stack (Source Serif 4).
    pub const FONT_DISPLAY: &str =
        "'Source Serif 4', 'Source Serif Pro', 'Georgia', 'Times New Roman', serif";
    /// Body / UI family stack (Inter).
    pub const FONT_BODY: &str = "'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', 'Helvetica Neue', Arial, sans-serif";
    /// Monospace family stack (IBM Plex Mono).
    pub const FONT_MONO: &str = "'IBM Plex Mono', ui-monospace, 'SF Mono', 'Cascadia Mono', 'Roboto Mono', 'Menlo', 'Consolas', monospace";

    /// Modular type scale (ratio 1.250), in logical pixels at a 16 px base.
    /// Index 0 = xs (12) … index 8 = 5xl (61).
    pub const SCALE_PX: [u16; 9] = [12, 14, 16, 20, 25, 31, 39, 49, 61];

    /// `xs` — 12 px.
    pub const TEXT_XS: u16 = 12;
    /// `sm` — 14 px.
    pub const TEXT_SM: u16 = 14;
    /// `base` — 16 px (body default).
    pub const TEXT_BASE: u16 = 16;
    /// `lg` — 20 px.
    pub const TEXT_LG: u16 = 20;
    /// `xl` — 25 px.
    pub const TEXT_XL: u16 = 25;
    /// `2xl` — 31 px.
    pub const TEXT_2XL: u16 = 31;
    /// `3xl` — 39 px.
    pub const TEXT_3XL: u16 = 39;
    /// `4xl` — 49 px.
    pub const TEXT_4XL: u16 = 49;
    /// `5xl` — 61 px.
    pub const TEXT_5XL: u16 = 61;

    /// Line height: tight (display).
    pub const LEADING_TIGHT: f32 = 1.15;
    /// Line height: snug (headings).
    pub const LEADING_SNUG: f32 = 1.4;
    /// Line height: normal (body default).
    pub const LEADING_NORMAL: f32 = 1.55;
    /// Line height: relaxed (long-form).
    pub const LEADING_RELAXED: f32 = 1.6;

    /// Letter spacing (em): tight (display).
    pub const TRACKING_TIGHT: f32 = -0.015;
    /// Letter spacing (em): normal.
    pub const TRACKING_NORMAL: f32 = 0.0;
    /// Letter spacing (em): wide (labels).
    pub const TRACKING_WIDE: f32 = 0.06;
    /// Letter spacing (em): wider.
    pub const TRACKING_WIDER: f32 = 0.08;
    /// Letter spacing (em): widest (eyebrow caps).
    pub const TRACKING_WIDEST: f32 = 0.12;

    /// Font weights used by the toolkit (stable weights — brand DNA).
    pub mod weight {
        /// Regular.
        pub const REGULAR: u16 = 400;
        /// Medium.
        pub const MEDIUM: u16 = 500;
        /// Semibold.
        pub const SEMIBOLD: u16 = 600;
        /// Bold.
        pub const BOLD: u16 = 700;
    }
}

// ===========================================================================
// Corner radii (HIG §6)
// ===========================================================================

/// Corner-radius tokens in logical pixels (HIG §6.1).
pub mod radius {
    /// `radius-none` — square (0 px); full-bleed / warning surfaces.
    pub const NONE: u16 = 0;
    /// `radius-xs` — 2 px; status pills (brand-fixed), checkboxes, tags.
    pub const XS: u16 = 2;
    /// `radius-sm` — 4 px; inputs, small buttons, menu items.
    pub const SM: u16 = 4;
    /// `radius-md` — 8 px; buttons, cards, list containers, popovers.
    pub const MD: u16 = 8;
    /// `radius-lg` — 12 px; dialogs, panels, sheets.
    pub const LG: u16 = 12;
    /// `radius-xl` — 16 px; window corners (HIG §6.2).
    pub const XL: u16 = 16;
    /// Window corner radius — `radius-xl` (HIG §6.2 rule 1).
    pub const WINDOW: u16 = XL;
    /// `radius-full` — pills, avatars, circular buttons (renderer clamps to
    /// height/2).
    pub const FULL: u16 = 9999;
}

// ===========================================================================
// Elevation & shadows (HIG §5)
// ===========================================================================

/// A soft drop shadow: vertical offset, blur radius, spread (all px) and an
/// `0xAARRGGBB` color whose alpha carries the shadow opacity.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Shadow {
    /// Vertical offset in px (shadows fall downward).
    pub offset_y: i16,
    /// Gaussian blur radius in px.
    pub blur: u16,
    /// Spread in px.
    pub spread: i16,
    /// Shadow color, `0xAARRGGBB` (alpha = opacity).
    pub color: u32,
}

/// One elevation level: a primary shadow plus an optional tight contact
/// (ambient) shadow used by the higher levels for definition (HIG §5.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Elevation {
    /// The primary drop shadow.
    pub primary: Shadow,
    /// Optional tight ambient/contact shadow (levels 3–5).
    pub contact: Option<Shadow>,
}

/// Elevation tokens (HIG §5).
///
/// Six levels (0 = flush). Shadows are restrained and soft (civic-tech calm):
/// low opacity, soft blur, cool-shifted petrol-900 tint over the warm canvas —
/// never neutral black, never a hard 1 px offset.
pub mod elevation {
    use super::{Elevation, Shadow};

    /// Petrol-900 RGB with no alpha; combined with a per-level opacity byte.
    const TINT: u32 = 0x0005_1921;

    /// Build a petrol-900 shadow with the given geometry and `alpha` opacity.
    const fn shadow(offset_y: i16, blur: u16, spread: i16, alpha: u32) -> Shadow {
        Shadow {
            offset_y,
            blur,
            spread,
            color: (alpha << 24) | TINT,
        }
    }

    /// Level 0 — flush (no shadow; use `border-default` for separation).
    pub const Z0: Option<Elevation> = None;
    /// Level 1 — resting card / list-row hover (opacity 0.06).
    pub const Z1: Elevation = Elevation {
        primary: shadow(1, 2, 0, 0x0F),
        contact: None,
    };
    /// Level 2 — raised card / toolbar separation (opacity 0.08).
    pub const Z2: Elevation = Elevation {
        primary: shadow(2, 6, 0, 0x14),
        contact: None,
    };
    /// Level 3 — popover / dropdown / tooltip (0.10 + contact 0.06).
    pub const Z3: Elevation = Elevation {
        primary: shadow(4, 12, -1, 0x1A),
        contact: Some(shadow(1, 2, 0, 0x0F)),
    };
    /// Level 4 — dialog / modal sheet (0.12 + contact 0.08).
    pub const Z4: Elevation = Elevation {
        primary: shadow(8, 24, -2, 0x1F),
        contact: Some(shadow(2, 4, 0, 0x14)),
    };
    /// Level 5 — dragged / focused window (0.16 + contact 0.10).
    pub const Z5: Elevation = Elevation {
        primary: shadow(16, 48, -4, 0x29),
        contact: Some(shadow(2, 6, 0, 0x1A)),
    };
}

// ===========================================================================
// Motion (HIG §7)
// ===========================================================================

/// A cubic-Bézier easing curve (the two control points; endpoints are fixed at
/// (0,0) and (1,1)).
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Easing {
    /// First control point x.
    pub x1: f32,
    /// First control point y.
    pub y1: f32,
    /// Second control point x.
    pub x2: f32,
    /// Second control point y.
    pub y2: f32,
}

impl Easing {
    /// Evaluate the easing curve at time progress `t` (clamped to `[0, 1]`),
    /// returning the eased value in `[0, 1]`.
    ///
    /// Solves the cubic-Bézier `x(u) = t` for the curve parameter `u` with a
    /// few Newton iterations (control points `(x1,y1)`/`(x2,y2)`, endpoints
    /// fixed at `(0,0)`/`(1,1)`), then returns `y(u)`. Pure arithmetic — no
    /// transcendental functions, so it stays `no_std` without `libm`.
    #[must_use]
    #[allow(clippy::float_arithmetic)]
    pub fn ease(self, t: f32) -> f32 {
        let t = t.clamp(0.0, 1.0);
        // Bézier component along one axis (`p0 = 0`, `p3 = 1`).
        let bez = |p1: f32, p2: f32, u: f32| {
            let v = 1.0 - u;
            3.0 * v * v * u * p1 + 3.0 * v * u * u * p2 + u * u * u
        };
        // Its derivative w.r.t. `u`.
        let dbez = |p1: f32, p2: f32, u: f32| {
            let v = 1.0 - u;
            3.0 * v * v * p1 + 6.0 * v * u * (p2 - p1) + 3.0 * u * u * (1.0 - p2)
        };
        let mut u = t; // a good initial guess for monotone time curves
        for _ in 0..6 {
            let dx = dbez(self.x1, self.x2, u);
            if dx > -1e-6 && dx < 1e-6 {
                break;
            }
            u -= (bez(self.x1, self.x2, u) - t) / dx;
            u = u.clamp(0.0, 1.0);
        }
        bez(self.y1, self.y2, u).clamp(0.0, 1.0)
    }
}

/// Spring parameters for physically-based transitions (gentle, not bouncy —
/// brand DNA forbids motion that suggests velocity).
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Spring {
    /// Stiffness (higher = faster).
    pub stiffness: f32,
    /// Damping (higher = less oscillation; >= critical → no overshoot).
    pub damping: f32,
    /// Mass.
    pub mass: f32,
}

/// Motion tokens (HIG §7): durations (ms), easing curves and springs.
///
/// Durations are short and calm; no easing curve overshoots and every spring's
/// damping ratio is ≥ 0.9 — motion never suggests velocity (brand DNA).
pub mod motion {
    use super::{Easing, Spring};

    /// `duration-instant` — 0 ms (focus ring; must not animate).
    pub const DUR_INSTANT_MS: u16 = 0;
    /// `duration-fast` — 120 ms (hover, pressed feedback, small fades).
    pub const DUR_FAST_MS: u16 = 120;
    /// `duration-base` — 200 ms (default for most transitions).
    pub const DUR_BASE_MS: u16 = 200;
    /// `duration-slow` — 280 ms (popovers, dropdowns, tooltips entering).
    pub const DUR_SLOW_MS: u16 = 280;
    /// `duration-slower` — 400 ms (dialogs, sheets, window open/close).
    pub const DUR_SLOWER_MS: u16 = 400;
    /// `duration-deliberate` — 600 ms (large/rare "Patient" transitions).
    pub const DUR_DELIBERATE_MS: u16 = 600;

    /// `ease-standard` — symmetric ease-in-out (default).
    pub const EASE_STANDARD: Easing = Easing {
        x1: 0.4,
        y1: 0.0,
        x2: 0.2,
        y2: 1.0,
    };
    /// `ease-decelerate` — entering elements (ease-out).
    pub const EASE_DECELERATE: Easing = Easing {
        x1: 0.0,
        y1: 0.0,
        x2: 0.2,
        y2: 1.0,
    };
    /// `ease-accelerate` — exiting elements (ease-in).
    pub const EASE_ACCELERATE: Easing = Easing {
        x1: 0.4,
        y1: 0.0,
        x2: 1.0,
        y2: 1.0,
    };
    /// `ease-emphasized` — large surfaces, pronounced settle, no overshoot.
    pub const EASE_EMPHASIZED: Easing = Easing {
        x1: 0.2,
        y1: 0.0,
        x2: 0.0,
        y2: 1.0,
    };

    /// `spring-subtle` — near-critical; control press/release, toggles.
    pub const SPRING_SUBTLE: Spring = Spring {
        stiffness: 240.0,
        damping: 30.0,
        mass: 1.0,
    };
    /// `spring-default` — slight settle; window snap, panel slide.
    pub const SPRING_DEFAULT: Spring = Spring {
        stiffness: 200.0,
        damping: 26.0,
        mass: 1.0,
    };
    /// `spring-gentle` — soft, slow; large sheets, drawers.
    pub const SPRING_GENTLE: Spring = Spring {
        stiffness: 160.0,
        damping: 24.0,
        mass: 1.0,
    };
    /// `spring-resize` — tracks the pointer during live resize, minimal lag.
    pub const SPRING_RESIZE: Spring = Spring {
        stiffness: 300.0,
        damping: 34.0,
        mass: 1.0,
    };
}

// ===========================================================================
// Materials — translucency / vibrancy (HIG §8)
// ===========================================================================

/// A translucency material: a background blur radius plus a tint color whose
/// alpha sets the tint strength over the blurred backdrop.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Material {
    /// Backdrop Gaussian blur radius in px.
    pub blur: u16,
    /// Tint color, `0xAARRGGBB` (alpha = tint strength).
    pub tint: u32,
}

/// Material tokens (HIG §8.1).
///
/// Subtle, legible translucency over a blurred backdrop — not heavy frosted
/// glass. Each material falls back to its opaque tint when the compositor
/// disables blur. Tint colors are brand semantic tokens at the listed opacity.
pub mod material {
    use super::Material;

    /// `material-thin` — inline overlays / hover surfaces (surface @ 60%).
    pub const THIN: Material = Material {
        blur: 8,
        tint: 0x99FF_FFFF,
    };
    /// `material-regular` — popovers / dropdowns / menus (surface @ 75%).
    pub const REGULAR: Material = Material {
        blur: 20,
        tint: 0xBFFF_FFFF,
    };
    /// `material-thick` — sidebars / toolbars / window chrome (canvas @ 85%).
    pub const THICK: Material = Material {
        blur: 30,
        tint: 0xD9F4_EBD0,
    };
    /// `material-chrome` — title bars / menu bar / dock (canvas @ 92%).
    pub const CHROME: Material = Material {
        blur: 40,
        tint: 0xEBF4_EBD0,
    };
    /// `material-scrim` — modal backdrop dimming (inverse @ 40%, no blur).
    pub const SCRIM: Material = Material {
        blur: 0,
        tint: 0x661F_2421,
    };
}

// ===========================================================================
// Interactive states (HIG §9)
// ===========================================================================

/// Interactive-state overlay / opacity tokens.
///
/// Applied on top of a control's base fill: `hover`/`pressed` are
/// `text-primary` overlay alphas, `disabled` scales overall opacity, and
/// `focus` is rendered as a ring in [`color::FOCUS_RING`] (HIG §9.1).
pub mod state {
    /// `text-primary` overlay alpha (0.0–1.0) added on hover.
    pub const HOVER_OVERLAY_ALPHA: f32 = 0.06;
    /// `text-primary` overlay alpha added on press.
    pub const PRESSED_OVERLAY_ALPHA: f32 = 0.12;
    /// Overall opacity multiplier for disabled controls.
    pub const DISABLED_OPACITY: f32 = 0.40;
    /// Pressed-state inward scale.
    pub const PRESSED_SCALE: f32 = 0.98;
    /// Focus-ring width in px.
    pub const FOCUS_RING_WIDTH: u16 = 2;
    /// Focus-ring offset (gap between control edge and ring) in px.
    pub const FOCUS_RING_OFFSET: u16 = 2;
}

// ===========================================================================
// Density (HIG §10)
// ===========================================================================

/// UI density mode (HIG §10). Density changes spacing and control dimensions
/// only — never type sizes, never the 44 px minimum hit target.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Density {
    /// Information-dense (tables, pro tools).
    Compact,
    /// Comfortable default.
    #[default]
    Regular,
    /// Extra roomy (touch / accessibility).
    Comfortable,
}

impl Density {
    /// Control height (button, input) in px (HIG §10 table).
    #[must_use]
    pub const fn control_height(self) -> u16 {
        match self {
            Self::Compact => 32,
            Self::Regular => 40,
            Self::Comfortable => 48,
        }
    }

    /// List-row height in px.
    #[must_use]
    pub const fn row_height(self) -> u16 {
        match self {
            Self::Compact => 32,
            Self::Regular => 40,
            Self::Comfortable => 52,
        }
    }

    /// Window content inset in px (a [`space`] token).
    #[must_use]
    pub const fn window_inset(self) -> u16 {
        match self {
            Self::Compact => space::S3,     // 24
            Self::Regular => space::S6,     // 48
            Self::Comfortable => space::S8, // 64
        }
    }

    /// Default gap between controls in px (a [`space`] token).
    #[must_use]
    pub const fn control_gap(self) -> u16 {
        match self {
            Self::Compact => space::S1,     // 8
            Self::Regular => space::S2,     // 16
            Self::Comfortable => space::S3, // 24
        }
    }

    /// Minimum hit target in px — never below 44 regardless of visual size.
    #[must_use]
    pub const fn min_hit_target(self) -> u16 {
        match self {
            Self::Compact | Self::Regular => 44,
            Self::Comfortable => 48,
        }
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    // These tests pin invariants between compile-time token constants; clippy
    // would otherwise flag the const comparisons as `assert!(true)`.
    #![allow(
        clippy::assertions_on_constants,
        reason = "tests pin ordering/equality invariants between token consts"
    )]

    use super::*;

    #[test]
    fn canonical_core_colors_match_brand() {
        assert_eq!(color::PETROL_500, 0xFF0F_4C5C);
        assert_eq!(color::CREAM_300, 0xFFF4_EBD0);
        assert_eq!(color::BRICK_500, 0xFFC0_3221);
        assert_eq!(color::SAGE_500, 0xFF7A_9E7E);
        assert_eq!(color::CHARCOAL_800, 0xFF1F_2421);
        assert_eq!(color::PETROL_900, 0xFF05_1921);
        assert_eq!(color::WHITE, 0xFFFF_FFFF);
    }

    #[test]
    fn semantic_tokens_resolve_to_core_ramp_steps() {
        assert_eq!(color::BG_CANVAS, color::CREAM_300);
        assert_eq!(color::BG_SURFACE, color::WHITE);
        assert_eq!(color::TEXT_PRIMARY, color::CHARCOAL_800);
        assert_eq!(color::TEXT_ACCENT, color::PETROL_500);
        assert_eq!(color::STATUS_SUCCESS, color::SAGE_500);
        assert_eq!(color::STATUS_DANGER, color::BRICK_500);
        // The Mission Anchor and the focus ring are the singular brand red.
        assert_eq!(color::ANCHOR, color::BRICK_500);
        assert_eq!(color::FOCUS_RING, color::BRICK_500);
    }

    #[test]
    fn opaque_color_tokens_are_fully_opaque_argb() {
        for c in [
            color::PETROL_50,
            color::PETROL_900,
            color::CREAM_300,
            color::BRICK_500,
            color::SAGE_500,
            color::CHARCOAL_950,
            color::BG_CANVAS,
            color::TEXT_PRIMARY,
            color::BORDER_RULE,
            color::STATUS_WARNING,
        ] {
            assert_eq!(c >> 24, 0xFF, "token {c:#010X} must be fully opaque");
        }
    }

    #[test]
    fn spacing_is_on_the_8px_grid() {
        assert_eq!(space::BASE, 8);
        // Every step from `space-1` up is a multiple of 8.
        for s in [
            space::S1,
            space::S2,
            space::S3,
            space::S4,
            space::S5,
            space::S6,
            space::S8,
            space::S10,
        ] {
            assert_eq!(s % space::BASE, 0, "{s} must be a multiple of 8");
        }
        // Sub-8 px steps are exactly the hairline and the 4 px half-step.
        assert_eq!(space::PX, 1);
        assert_eq!(space::HALF, 4);
        // HIG §2.2 canonical values.
        assert_eq!(space::S5, 40);
        assert_eq!(space::S10, 80);
    }

    #[test]
    fn type_scale_is_monotonic_and_anchored_at_16() {
        assert_eq!(typography::TEXT_BASE, 16);
        assert_eq!(typography::SCALE_PX[2], typography::TEXT_BASE);
        for w in typography::SCALE_PX.windows(2) {
            assert!(w[1] > w[0], "type scale must be strictly increasing");
        }
        assert_eq!(
            typography::SCALE_PX.first().copied(),
            Some(typography::TEXT_XS)
        );
        assert_eq!(
            typography::SCALE_PX.last().copied(),
            Some(typography::TEXT_5XL)
        );
    }

    #[test]
    fn radii_increase_with_container_size() {
        assert!(radius::XS < radius::SM);
        assert!(radius::SM < radius::MD);
        assert!(radius::MD < radius::LG);
        assert!(radius::LG < radius::XL);
        assert_eq!(radius::MD, 8, "default control radius is 8 px");
        // HIG §6.2 rule 1: window corners are radius-xl.
        assert_eq!(radius::WINDOW, radius::XL);
    }

    #[test]
    fn elevation_levels_deepen_monotonically() {
        // Higher elevation → larger blur and stronger (higher-alpha) shadow.
        assert!(elevation::Z1.primary.blur < elevation::Z2.primary.blur);
        assert!(elevation::Z2.primary.blur < elevation::Z3.primary.blur);
        assert!(elevation::Z3.primary.blur < elevation::Z4.primary.blur);
        assert!(elevation::Z4.primary.blur < elevation::Z5.primary.blur);
        assert!((elevation::Z1.primary.color >> 24) < (elevation::Z5.primary.color >> 24));
        // Levels 1–2 have no contact shadow; 3–5 do (HIG §5.1).
        assert!(elevation::Z1.contact.is_none());
        assert!(elevation::Z2.contact.is_none());
        assert!(elevation::Z3.contact.is_some());
        assert!(elevation::Z5.contact.is_some());
        assert!(elevation::Z0.is_none());
        // Shadow tint is petrol-900 (RGB matches, alpha varies).
        assert_eq!(elevation::Z4.primary.color & 0x00FF_FFFF, 0x0005_1921);
    }

    #[test]
    fn motion_durations_are_calm_and_ordered() {
        assert!(motion::DUR_FAST_MS < motion::DUR_BASE_MS);
        assert!(motion::DUR_BASE_MS < motion::DUR_SLOW_MS);
        assert!(motion::DUR_SLOW_MS < motion::DUR_SLOWER_MS);
        assert!(motion::DUR_SLOWER_MS < motion::DUR_DELIBERATE_MS);
        // Default UI springs do not bounce: damping ratio ζ = c / (2√(k·m)) ≥ 0.9.
        for s in [
            motion::SPRING_SUBTLE,
            motion::SPRING_DEFAULT,
            motion::SPRING_GENTLE,
            motion::SPRING_RESIZE,
        ] {
            let critical = 2.0 * (s.stiffness * s.mass).sqrt();
            assert!(
                s.damping / critical >= 0.9,
                "spring must be near-critically damped (no visible bounce)"
            );
        }
    }

    #[test]
    fn materials_have_increasing_blur_and_tint() {
        assert!(material::THIN.blur < material::REGULAR.blur);
        assert!(material::REGULAR.blur < material::THICK.blur);
        assert!(material::THICK.blur < material::CHROME.blur);
        // Tint strength (alpha) grows from thin → chrome.
        assert!((material::THIN.tint >> 24) < (material::CHROME.tint >> 24));
        // The scrim is the only zero-blur material (it dims, not frosts).
        assert_eq!(material::SCRIM.blur, 0);
    }

    #[test]
    fn interactive_state_alphas_are_ordered() {
        assert!(state::HOVER_OVERLAY_ALPHA < state::PRESSED_OVERLAY_ALPHA);
        assert!(state::DISABLED_OPACITY < 1.0);
        assert!((state::DISABLED_OPACITY - 0.40).abs() < f32::EPSILON);
        assert!(state::FOCUS_RING_WIDTH > 0);
        assert!(state::PRESSED_SCALE < 1.0);
    }

    #[test]
    fn density_metrics_are_ordered_and_on_grid() {
        assert!(Density::Compact.row_height() < Density::Regular.row_height());
        assert!(Density::Regular.row_height() < Density::Comfortable.row_height());
        assert!(Density::Compact.control_height() < Density::Comfortable.control_height());
        assert_eq!(Density::default(), Density::Regular);
        // Density maps to spacing tokens (HIG §10).
        assert_eq!(Density::Regular.window_inset(), space::S6);
        assert_eq!(Density::Regular.control_gap(), space::S2);
        // The 44 px minimum hit target is never reduced below 44.
        assert!(Density::Compact.min_hit_target() >= 44);
    }
}
