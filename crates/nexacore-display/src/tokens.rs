//! Canonical brand color tokens (WS7-19.1) — the single source of truth.
//!
//! These packed `0xAARRGGBB` constants are the one authoritative encoding of the
//! NexaCore brand palette for the whole graphics stack: the compositor uses them
//! directly, and `nexacore-ui` re-exports them (its `color` / `tokens::color`
//! modules are thin re-exports of this module) so there is exactly one place the
//! brand colors are defined. This ends the previous drift risk where the ramp
//! was hand-copied into two crates.
//!
//! Values mirror `brand/colors/tokens.json` (Direction C — Civic Tech /
//! Generational). A drift-guard test asserts the canonical hues match that file.
//!
//! Semantic aliases follow the light-mode defaults; dark-surface roles used by
//! the compositor/desktop (a charcoal-900 canvas) are named explicitly.

// ---- core ramp: petrol (primary brand hue) ---------------------------------
/// Petrol 50.
pub const PETROL_50: u32 = 0xFFE6_EEF0;
/// Petrol 100.
pub const PETROL_100: u32 = 0xFFC5_D6DB;
/// Petrol 200.
pub const PETROL_200: u32 = 0xFF94_B3BC;
/// Petrol 300.
pub const PETROL_300: u32 = 0xFF63_90A0;
/// Petrol 400.
pub const PETROL_400: u32 = 0xFF38_6F82;
/// Petrol 500 — canonical petrol.
pub const PETROL_500: u32 = 0xFF0F_4C5C;
/// Petrol 600.
pub const PETROL_600: u32 = 0xFF0C_3E4B;
/// Petrol 700.
pub const PETROL_700: u32 = 0xFF0A_323C;
/// Petrol 800.
pub const PETROL_800: u32 = 0xFF07_242C;
/// Petrol 900.
pub const PETROL_900: u32 = 0xFF05_1921;

// ---- core ramp: cream (warm canvas) ----------------------------------------
/// Cream 50.
pub const CREAM_50: u32 = 0xFFFD_FBF4;
/// Cream 100.
pub const CREAM_100: u32 = 0xFFFA_F5E6;
/// Cream 200.
pub const CREAM_200: u32 = 0xFFF8_F0DA;
/// Cream 300 — canonical cream.
pub const CREAM_300: u32 = 0xFFF4_EBD0;
/// Cream 400.
pub const CREAM_400: u32 = 0xFFE8_DAB1;
/// Cream 500.
pub const CREAM_500: u32 = 0xFFD9_C68A;
/// Cream 600.
pub const CREAM_600: u32 = 0xFFB5_A26B;
/// Cream 700.
pub const CREAM_700: u32 = 0xFF8F_7F50;

// ---- core ramp: brick (Mission Anchor — reserved governance red) -----------
/// Brick 50.
pub const BRICK_50: u32 = 0xFFF8_E1DE;
/// Brick 100.
pub const BRICK_100: u32 = 0xFFEF_B7B0;
/// Brick 300.
pub const BRICK_300: u32 = 0xFFD8_5C50;
/// Brick 500 — canonical brick (Mission Anchor accent).
pub const BRICK_500: u32 = 0xFFC0_3221;
/// Brick 700.
pub const BRICK_700: u32 = 0xFF8F_2519;
/// Brick 900.
pub const BRICK_900: u32 = 0xFF5C_1710;

// ---- core ramp: sage (community / success) ---------------------------------
/// Sage 50.
pub const SAGE_50: u32 = 0xFFEA_F1EB;
/// Sage 100.
pub const SAGE_100: u32 = 0xFFC6_D8C8;
/// Sage 300.
pub const SAGE_300: u32 = 0xFF9C_BC9F;
/// Sage 500 — canonical sage.
pub const SAGE_500: u32 = 0xFF7A_9E7E;
/// Sage 700.
pub const SAGE_700: u32 = 0xFF58_7657;
/// Sage 900.
pub const SAGE_900: u32 = 0xFF2E_4E2D;

// ---- core ramp: charcoal (body text + dark surfaces) -----------------------
/// Charcoal 50.
pub const CHARCOAL_50: u32 = 0xFFF2_F3F2;
/// Charcoal 100.
pub const CHARCOAL_100: u32 = 0xFFDC_DEDC;
/// Charcoal 200.
pub const CHARCOAL_200: u32 = 0xFFB3_B7B3;
/// Charcoal 300.
pub const CHARCOAL_300: u32 = 0xFF88_8D88;
/// Charcoal 400.
pub const CHARCOAL_400: u32 = 0xFF5E_635E;
/// Charcoal 500.
pub const CHARCOAL_500: u32 = 0xFF3E_423E;
/// Charcoal 600.
pub const CHARCOAL_600: u32 = 0xFF2D_312D;
/// Charcoal 700.
pub const CHARCOAL_700: u32 = 0xFF25_2925;
/// Charcoal 800 — canonical charcoal.
pub const CHARCOAL_800: u32 = 0xFF1F_2421;
/// Charcoal 900 — dark-mode canvas.
pub const CHARCOAL_900: u32 = 0xFF14_171A;
/// Charcoal 950.
pub const CHARCOAL_950: u32 = 0xFF0A_0B0C;

// ---- neutrals --------------------------------------------------------------
/// Opaque white.
pub const WHITE: u32 = 0xFFFF_FFFF;
/// Opaque black.
pub const BLACK: u32 = 0xFF00_0000;

// ---- semantic tokens (light-mode defaults) ---------------------------------
/// Page/background canvas.
pub const BG_CANVAS: u32 = CREAM_300;
/// Raised surface.
pub const BG_SURFACE: u32 = WHITE;
/// Secondary surface tint.
pub const BG_SURFACE_2: u32 = CREAM_100;
/// Inverse (dark) surface.
pub const BG_INVERSE: u32 = CHARCOAL_800;
/// Code-block background.
pub const BG_CODE: u32 = PETROL_50;
/// Primary body text.
pub const TEXT_PRIMARY: u32 = CHARCOAL_800;
/// Secondary text.
pub const TEXT_SECONDARY: u32 = CHARCOAL_500;
/// Tertiary text.
pub const TEXT_TERTIARY: u32 = CHARCOAL_300;
/// Text on inverse surfaces.
pub const TEXT_INVERSE: u32 = CREAM_300;
/// Accent text.
pub const TEXT_ACCENT: u32 = PETROL_500;
/// Link text.
pub const TEXT_LINK: u32 = PETROL_500;
/// Hovered link text.
pub const TEXT_LINK_HOVER: u32 = PETROL_700;
/// Default border.
pub const BORDER_DEFAULT: u32 = CHARCOAL_100;
/// Strong border.
pub const BORDER_STRONG: u32 = CHARCOAL_300;
/// Accent border.
pub const BORDER_ACCENT: u32 = PETROL_300;
/// Hairline rule.
pub const BORDER_RULE: u32 = PETROL_200;
/// Success status.
pub const STATUS_SUCCESS: u32 = SAGE_500;
/// Warning status (goldenrod — the one non-ramp status hue).
pub const STATUS_WARNING: u32 = 0xFFB5_8D32;
/// Danger status.
pub const STATUS_DANGER: u32 = BRICK_500;
/// Info status.
pub const STATUS_INFO: u32 = PETROL_500;
/// Neutral status.
pub const STATUS_NEUTRAL: u32 = CHARCOAL_300;
/// Mission Anchor.
pub const ANCHOR: u32 = BRICK_500;
/// Focus ring.
pub const FOCUS_RING: u32 = BRICK_500;

// ---- dark-surface / desktop roles (used by the compositor) -----------------
/// The desktop canvas behind all windows — the dark-mode canvas (charcoal-900).
pub const DESKTOP_CANVAS: u32 = CHARCOAL_900;
/// Text on the dark desktop / dark surfaces (cream-300).
pub const TEXT_ON_DARK: u32 = CREAM_300;
/// Secondary text on dark surfaces (cream-500).
pub const TEXT_ON_DARK_SECONDARY: u32 = CREAM_500;
/// Window chrome / raised dark surface (charcoal-800).
pub const SURFACE_DARK: u32 = CHARCOAL_800;

#[cfg(test)]
mod tests {
    use super::*;

    /// The canonical hues must match `brand/colors/tokens.json`. `include_str`
    /// binds the Rust source of truth to the brand pack: editing either without
    /// the other fails the gate.
    #[test]
    fn canonical_hues_match_brand_tokens_json() {
        const JSON: &str = include_str!("../../../brand/colors/tokens.json");
        // (rust constant, expected "#RRGGBB" in the brand pack)
        let pairs = [
            (PETROL_500, "#0F4C5C"),
            (CREAM_300, "#F4EBD0"),
            (BRICK_500, "#C03221"),
            (SAGE_500, "#7A9E7E"),
            (CHARCOAL_800, "#1F2421"),
            (CHARCOAL_900, "#14171A"),
        ];
        for (argb, hex) in pairs {
            // The Rust constant's RGB equals the documented hex.
            let rgb = argb & 0x00FF_FFFF;
            let expected = u32::from_str_radix(hex.trim_start_matches('#'), 16).unwrap();
            assert_eq!(rgb, expected, "constant {argb:#010X} != {hex}");
            // And that hex is present in the brand token file.
            assert!(JSON.contains(hex), "brand tokens.json missing {hex}");
        }
    }

    #[test]
    fn semantic_aliases_resolve_to_ramp() {
        assert_eq!(BG_CANVAS, CREAM_300);
        assert_eq!(TEXT_PRIMARY, CHARCOAL_800);
        assert_eq!(FOCUS_RING, BRICK_500);
        assert_eq!(DESKTOP_CANVAS, CHARCOAL_900);
        assert_eq!(TEXT_ON_DARK, CREAM_300);
    }

    #[test]
    fn all_tokens_are_opaque() {
        for c in [
            PETROL_500,
            CREAM_300,
            BRICK_500,
            SAGE_500,
            CHARCOAL_900,
            DESKTOP_CANVAS,
        ] {
            assert_eq!(c >> 24, 0xFF, "token {c:#010X} is not opaque");
        }
    }
}
