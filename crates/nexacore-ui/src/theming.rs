//! Theme engine (WS17-03).
//!
//! Resolves the NexaCore design tokens ([`crate::tokens`]) into a concrete
//! [`ResolvedTheme`] under user settings — light/dark, custom themes, per-app
//! overrides, accent color, density, system font, and a materials on/off
//! toggle — with hot-reload (a generation counter) and persistence to the
//! `nexacore-config` store.
//!
//! The engine never invents colors: dark mode re-binds the same semantic
//! tokens to the core ramps per `docs/design/nexacore-hig.md` §4.4.

use alloc::{collections::BTreeMap, string::String};

use nexacore_config::{ConfigBackend, ConfigStore, ConfigValue, Key, UserId};

use crate::tokens::{Density, color};

// ---------------------------------------------------------------------------
// Settings (WS17-03.3/.6/.7/.8/.9 + custom)
// ---------------------------------------------------------------------------

/// The user's light/dark preference. `Auto` resolves via a "prefers dark"
/// signal supplied at resolve time (WS17-03.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ThemePreference {
    /// Always light.
    Light,
    /// Always dark.
    Dark,
    /// Follow the system "prefers dark" signal.
    #[default]
    Auto,
}

/// The concrete mode a theme resolved to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ThemeMode {
    /// Light.
    Light,
    /// Dark.
    Dark,
}

/// System font selection (WS17-03.8); maps to a [`crate::tokens::typography`]
/// family stack.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SystemFont {
    /// Inter (UI / body) — the default.
    #[default]
    Sans,
    /// Source Serif 4 (display).
    Serif,
    /// IBM Plex Mono (monospace).
    Mono,
}

impl SystemFont {
    /// The CSS family stack for this font.
    #[must_use]
    pub const fn stack(self) -> &'static str {
        match self {
            Self::Sans => crate::tokens::typography::FONT_BODY,
            Self::Serif => crate::tokens::typography::FONT_DISPLAY,
            Self::Mono => crate::tokens::typography::FONT_MONO,
        }
    }
}

/// A custom theme: partial overrides of semantic colors applied on top of the
/// resolved light/dark base (WS17-03.4). `None` fields keep the base value.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct CustomTheme {
    /// Override the UI accent.
    pub accent: Option<u32>,
    /// Override the canvas background.
    pub bg_canvas: Option<u32>,
    /// Override the surface background.
    pub bg_surface: Option<u32>,
    /// Override the primary text color.
    pub text_primary: Option<u32>,
    /// Override the default border color.
    pub border_default: Option<u32>,
}

impl CustomTheme {
    /// Apply these overrides onto a resolved theme.
    fn apply_to(&self, t: &mut ResolvedTheme) {
        if let Some(c) = self.accent {
            t.accent = c;
        }
        if let Some(c) = self.bg_canvas {
            t.bg_canvas = c;
        }
        if let Some(c) = self.bg_surface {
            t.bg_surface = c;
        }
        if let Some(c) = self.text_primary {
            t.text_primary = c;
        }
        if let Some(c) = self.border_default {
            t.border_default = c;
        }
    }
}

/// User-facing theme settings (WS17-03).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ThemeSettings {
    /// Light/dark/auto preference (WS17-03.3).
    pub preference: ThemePreference,
    /// Runtime accent override; `None` keeps the brand default (WS17-03.6).
    pub accent: Option<u32>,
    /// UI density (WS17-03.7).
    pub density: Density,
    /// System font (WS17-03.8).
    pub font: SystemFont,
    /// Whether translucency/vibrancy materials are enabled (WS17-03.9).
    pub materials_enabled: bool,
    /// Optional global custom theme overrides (WS17-03.4).
    pub custom: Option<CustomTheme>,
}

impl Default for ThemeSettings {
    fn default() -> Self {
        Self {
            preference: ThemePreference::Auto,
            accent: None,
            density: Density::Regular,
            font: SystemFont::Sans,
            materials_enabled: true,
            custom: None,
        }
    }
}

// ---------------------------------------------------------------------------
// Resolved theme (WS17-03.1/.2)
// ---------------------------------------------------------------------------

/// A fully-resolved theme: the concrete token values a widget reads. Produced
/// by [`ThemeEngine::resolve`] from the design tokens + settings (WS17-03.1/.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResolvedTheme {
    /// The mode this resolved to.
    pub mode: ThemeMode,
    /// Page/canvas background.
    pub bg_canvas: u32,
    /// Widget surface background.
    pub bg_surface: u32,
    /// Secondary raised surface.
    pub bg_surface_2: u32,
    /// Inverse surface.
    pub bg_inverse: u32,
    /// Code background.
    pub bg_code: u32,
    /// Primary text.
    pub text_primary: u32,
    /// Secondary text.
    pub text_secondary: u32,
    /// Tertiary text.
    pub text_tertiary: u32,
    /// Text on an inverse surface.
    pub text_inverse: u32,
    /// Default border.
    pub border_default: u32,
    /// Strong border.
    pub border_strong: u32,
    /// Accent border.
    pub border_accent: u32,
    /// The UI accent color.
    pub accent: u32,
    /// Success status.
    pub success: u32,
    /// Warning status.
    pub warning: u32,
    /// Danger status.
    pub danger: u32,
    /// Info status.
    pub info: u32,
    /// Resolved UI density.
    pub density: Density,
    /// Whether materials are enabled.
    pub materials_enabled: bool,
    /// Resolved font family stack.
    pub font_stack: &'static str,
}

impl ResolvedTheme {
    /// The light-mode semantic base (HIG §4.3 / `tokens::color`).
    fn light_base() -> Self {
        Self {
            mode: ThemeMode::Light,
            bg_canvas: color::BG_CANVAS,
            bg_surface: color::BG_SURFACE,
            bg_surface_2: color::BG_SURFACE_2,
            bg_inverse: color::BG_INVERSE,
            bg_code: color::BG_CODE,
            text_primary: color::TEXT_PRIMARY,
            text_secondary: color::TEXT_SECONDARY,
            text_tertiary: color::TEXT_TERTIARY,
            text_inverse: color::TEXT_INVERSE,
            border_default: color::BORDER_DEFAULT,
            border_strong: color::BORDER_STRONG,
            border_accent: color::BORDER_ACCENT,
            accent: color::TEXT_ACCENT,
            success: color::STATUS_SUCCESS,
            warning: color::STATUS_WARNING,
            danger: color::STATUS_DANGER,
            info: color::STATUS_INFO,
            density: Density::Regular,
            materials_enabled: true,
            font_stack: SystemFont::Sans.stack(),
        }
    }

    /// The dark-mode semantic base — re-binds the same tokens to the ramps per
    /// `docs/design/nexacore-hig.md` §4.4 (never new colors).
    fn dark_base() -> Self {
        Self {
            mode: ThemeMode::Dark,
            bg_canvas: color::CHARCOAL_900,
            bg_surface: color::CHARCOAL_800,
            bg_surface_2: color::CHARCOAL_700,
            bg_inverse: color::CREAM_300,
            bg_code: color::PETROL_900,
            text_primary: color::CREAM_300,
            text_secondary: color::CREAM_500,
            text_tertiary: color::CHARCOAL_300,
            text_inverse: color::CHARCOAL_800,
            border_default: color::CHARCOAL_700,
            border_strong: color::CHARCOAL_500,
            border_accent: color::PETROL_300,
            // In dark mode text-accent re-binds to cream-300; the UI accent
            // (a chromatic highlight) stays petrol so it reads on dark chrome.
            accent: color::PETROL_300,
            success: color::STATUS_SUCCESS,
            warning: color::STATUS_WARNING,
            danger: color::STATUS_DANGER,
            info: color::STATUS_INFO,
            density: Density::Regular,
            materials_enabled: true,
            font_stack: SystemFont::Sans.stack(),
        }
    }
}

// ---------------------------------------------------------------------------
// The engine (WS17-03.2/.5/.10)
// ---------------------------------------------------------------------------

/// The theme engine: holds the current settings + per-app overrides and a
/// monotonic `generation` that bumps on every change so consumers can
/// hot-reload without restarting (WS17-03.10).
#[derive(Debug, Clone, Default)]
pub struct ThemeEngine {
    settings: ThemeSettings,
    app_overrides: BTreeMap<String, CustomTheme>,
    generation: u64,
}

impl ThemeEngine {
    /// A new engine with the given base settings.
    #[must_use]
    pub fn new(settings: ThemeSettings) -> Self {
        Self {
            settings,
            app_overrides: BTreeMap::new(),
            generation: 0,
        }
    }

    /// The current settings.
    #[must_use]
    pub fn settings(&self) -> &ThemeSettings {
        &self.settings
    }

    /// The current generation. A consumer that cached a resolved theme can
    /// compare this to detect a change and re-[`resolve`](Self::resolve)
    /// (WS17-03.10 — hot-reload signal).
    #[must_use]
    pub fn generation(&self) -> u64 {
        self.generation
    }

    fn bump(&mut self) {
        self.generation = self.generation.wrapping_add(1);
    }

    /// Replace the whole settings block (bumps the generation).
    pub fn set_settings(&mut self, settings: ThemeSettings) {
        self.settings = settings;
        self.bump();
    }

    /// Set the light/dark preference (WS17-03.3).
    pub fn set_preference(&mut self, preference: ThemePreference) {
        self.settings.preference = preference;
        self.bump();
    }

    /// Set the runtime accent override (WS17-03.6).
    pub fn set_accent(&mut self, accent: Option<u32>) {
        self.settings.accent = accent;
        self.bump();
    }

    /// Set the UI density (WS17-03.7).
    pub fn set_density(&mut self, density: Density) {
        self.settings.density = density;
        self.bump();
    }

    /// Set the system font (WS17-03.8).
    pub fn set_font(&mut self, font: SystemFont) {
        self.settings.font = font;
        self.bump();
    }

    /// Toggle translucency/vibrancy materials (WS17-03.9).
    pub fn set_materials_enabled(&mut self, enabled: bool) {
        self.settings.materials_enabled = enabled;
        self.bump();
    }

    /// Install (or replace) a per-app theme override (WS17-03.5).
    pub fn set_app_override(&mut self, app: &str, custom: CustomTheme) {
        self.app_overrides.insert(String::from(app), custom);
        self.bump();
    }

    /// Remove a per-app override.
    pub fn clear_app_override(&mut self, app: &str) {
        if self.app_overrides.remove(app).is_some() {
            self.bump();
        }
    }

    /// Resolve the system theme (WS17-03.2). `prefers_dark` decides `Auto`.
    #[must_use]
    pub fn resolve(&self, prefers_dark: bool) -> ResolvedTheme {
        self.resolve_inner(None, prefers_dark)
    }

    /// Resolve the theme for a specific app, applying its per-app override on
    /// top of the system theme (WS17-03.5).
    #[must_use]
    pub fn resolve_for_app(&self, app: &str, prefers_dark: bool) -> ResolvedTheme {
        self.resolve_inner(Some(app), prefers_dark)
    }

    fn resolve_inner(&self, app: Option<&str>, prefers_dark: bool) -> ResolvedTheme {
        let mode = match self.settings.preference {
            ThemePreference::Light => ThemeMode::Light,
            ThemePreference::Dark => ThemeMode::Dark,
            ThemePreference::Auto => {
                if prefers_dark {
                    ThemeMode::Dark
                } else {
                    ThemeMode::Light
                }
            }
        };
        let mut theme = match mode {
            ThemeMode::Light => ResolvedTheme::light_base(),
            ThemeMode::Dark => ResolvedTheme::dark_base(),
        };

        // Settings that are independent of the color base.
        theme.density = self.settings.density;
        theme.materials_enabled = self.settings.materials_enabled;
        theme.font_stack = self.settings.font.stack();

        // Accent: explicit setting wins over the mode default (WS17-03.6).
        if let Some(a) = self.settings.accent {
            theme.accent = a;
        }
        // Global custom overrides (WS17-03.4).
        if let Some(custom) = self.settings.custom {
            custom.apply_to(&mut theme);
        }
        // Per-app overrides on top (WS17-03.5).
        if let Some(app) = app {
            if let Some(custom) = self.app_overrides.get(app) {
                custom.apply_to(&mut theme);
            }
        }
        theme
    }
}

// ---------------------------------------------------------------------------
// Persistence to the config store (WS17-03.11)
// ---------------------------------------------------------------------------

/// Config keys used to persist [`ThemeSettings`] (WS17-03.11). A caller
/// registers schemas for these (see `register_theme_schema`).
pub mod keys {
    /// `desktop.theme.mode` — enum `light` | `dark` | `auto`.
    pub const MODE: &str = "desktop.theme.mode";
    /// `desktop.theme.density` — int `0` (compact) | `1` (regular) | `2` (comfortable).
    pub const DENSITY: &str = "desktop.theme.density";
    /// `desktop.theme.materials` — bool.
    pub const MATERIALS: &str = "desktop.theme.materials";
    /// `desktop.theme.font` — enum `sans` | `serif` | `mono`.
    pub const FONT: &str = "desktop.theme.font";
    /// `desktop.theme.accent` — int ARGB, or `-1` for the brand default.
    pub const ACCENT: &str = "desktop.theme.accent";
}

impl ThemeSettings {
    /// Load theme settings from the `nexacore-config` store for `user` (WS17-03.11).
    ///
    /// Missing or unreadable keys fall back to [`ThemeSettings::default`] /
    /// the per-field default, so this never fails.
    #[must_use]
    pub fn load_from_config<B: ConfigBackend>(
        store: &ConfigStore<B>,
        user: Option<UserId>,
    ) -> Self {
        let mut s = Self::default();
        let get = |name: &str| Key::new(name).ok().and_then(|k| store.get(&k, user).ok());

        if let Some(ConfigValue::Str(m)) = get(keys::MODE) {
            s.preference = match m.as_str() {
                "light" => ThemePreference::Light,
                "dark" => ThemePreference::Dark,
                _ => ThemePreference::Auto,
            };
        }
        if let Some(ConfigValue::Int(d)) = get(keys::DENSITY) {
            s.density = match d {
                0 => Density::Compact,
                2 => Density::Comfortable,
                _ => Density::Regular,
            };
        }
        if let Some(ConfigValue::Bool(b)) = get(keys::MATERIALS) {
            s.materials_enabled = b;
        }
        if let Some(ConfigValue::Str(f)) = get(keys::FONT) {
            s.font = match f.as_str() {
                "serif" => SystemFont::Serif,
                "mono" => SystemFont::Mono,
                _ => SystemFont::Sans,
            };
        }
        if let Some(ConfigValue::Int(a)) = get(keys::ACCENT) {
            // -1 (or any negative) = brand default; otherwise low 32 bits = ARGB.
            s.accent = u32::try_from(a).ok();
        }
        s
    }
}

#[cfg(test)]
mod tests {
    use alloc::string::ToString;

    use nexacore_config::{AllowAll, KeySchema, MemoryBackend, SchemaRegistry, ValueType};

    use super::*;

    #[test]
    fn light_and_dark_rebind_semantic_tokens() {
        let eng = ThemeEngine::new(ThemeSettings::default());
        // preference Auto → prefers_dark decides.
        let light = eng.resolve(false);
        let dark = eng.resolve(true);
        assert_eq!(light.mode, ThemeMode::Light);
        assert_eq!(dark.mode, ThemeMode::Dark);
        // Light canvas is cream; dark canvas is charcoal (HIG §4.3/§4.4).
        assert_eq!(light.bg_canvas, color::CREAM_300);
        assert_eq!(dark.bg_canvas, color::CHARCOAL_900);
        assert_eq!(light.text_primary, color::CHARCOAL_800);
        assert_eq!(dark.text_primary, color::CREAM_300);
    }

    #[test]
    fn preference_overrides_prefers_dark() {
        let mut eng = ThemeEngine::new(ThemeSettings::default());
        eng.set_preference(ThemePreference::Dark);
        // Even with prefers_dark = false, an explicit Dark wins.
        assert_eq!(eng.resolve(false).mode, ThemeMode::Dark);
        eng.set_preference(ThemePreference::Light);
        assert_eq!(eng.resolve(true).mode, ThemeMode::Light);
    }

    #[test]
    fn accent_override_applies_and_bumps_generation() {
        let mut eng = ThemeEngine::new(ThemeSettings::default());
        let g0 = eng.generation();
        assert_eq!(eng.resolve(false).accent, color::TEXT_ACCENT);
        eng.set_accent(Some(color::SAGE_500));
        assert!(eng.generation() > g0, "a change must bump the generation");
        assert_eq!(eng.resolve(false).accent, color::SAGE_500);
    }

    #[test]
    fn density_font_materials_are_applied() {
        let mut eng = ThemeEngine::new(ThemeSettings::default());
        eng.set_density(Density::Compact);
        eng.set_font(SystemFont::Mono);
        eng.set_materials_enabled(false);
        let t = eng.resolve(false);
        assert_eq!(t.density, Density::Compact);
        assert_eq!(t.font_stack, crate::tokens::typography::FONT_MONO);
        assert!(!t.materials_enabled);
    }

    #[test]
    fn custom_theme_overrides_base() {
        let custom = CustomTheme {
            accent: Some(0xFF12_3456),
            bg_canvas: Some(0xFF00_0000),
            ..CustomTheme::default()
        };
        let settings = ThemeSettings {
            custom: Some(custom),
            ..ThemeSettings::default()
        };
        let eng = ThemeEngine::new(settings);
        let t = eng.resolve(false);
        assert_eq!(t.accent, 0xFF12_3456);
        assert_eq!(t.bg_canvas, 0xFF00_0000);
        // Untouched fields keep the base.
        assert_eq!(t.text_primary, color::TEXT_PRIMARY);
    }

    #[test]
    fn per_app_override_only_affects_that_app() {
        let mut eng = ThemeEngine::new(ThemeSettings::default());
        eng.set_app_override(
            "nexacore-terminal",
            CustomTheme {
                bg_canvas: Some(color::PETROL_900),
                ..CustomTheme::default()
            },
        );
        let term = eng.resolve_for_app("nexacore-terminal", false);
        let other = eng.resolve_for_app("nexacore-text", false);
        let system = eng.resolve(false);
        assert_eq!(term.bg_canvas, color::PETROL_900);
        assert_eq!(other.bg_canvas, color::CREAM_300);
        assert_eq!(system.bg_canvas, color::CREAM_300);
    }

    #[test]
    fn hot_reload_generation_changes_on_every_mutation() {
        let mut eng = ThemeEngine::new(ThemeSettings::default());
        let g0 = eng.generation();
        eng.set_density(Density::Comfortable);
        let g1 = eng.generation();
        assert!(g1 > g0, "density change must bump the generation");
        eng.set_preference(ThemePreference::Dark);
        let g2 = eng.generation();
        assert!(g2 > g1, "preference change must bump the generation");
        eng.set_app_override("x", CustomTheme::default());
        assert!(
            eng.generation() > g2,
            "app override must bump the generation"
        );
    }

    fn theme_store() -> ConfigStore<MemoryBackend> {
        let mut reg = SchemaRegistry::new();
        reg.register(
            Key::new(keys::MODE).unwrap(),
            KeySchema::new(
                ValueType::Enum(&["light", "dark", "auto"]),
                ConfigValue::Str("auto".to_string()),
                "theme mode",
            )
            .unwrap(),
        );
        reg.register(
            Key::new(keys::DENSITY).unwrap(),
            KeySchema::new(
                ValueType::Int { min: 0, max: 2 },
                ConfigValue::Int(1),
                "density",
            )
            .unwrap(),
        );
        reg.register(
            Key::new(keys::MATERIALS).unwrap(),
            KeySchema::new(ValueType::Bool, ConfigValue::Bool(true), "materials").unwrap(),
        );
        ConfigStore::new(reg, MemoryBackend::new())
    }

    #[test]
    fn load_from_config_reads_persisted_settings() {
        let mut store = theme_store();
        store
            .set(
                &Key::new(keys::MODE).unwrap(),
                ConfigValue::Str("dark".to_string()),
                &AllowAll,
            )
            .unwrap();
        store
            .set(
                &Key::new(keys::DENSITY).unwrap(),
                ConfigValue::Int(0),
                &AllowAll,
            )
            .unwrap();
        store
            .set(
                &Key::new(keys::MATERIALS).unwrap(),
                ConfigValue::Bool(false),
                &AllowAll,
            )
            .unwrap();

        let s = ThemeSettings::load_from_config(&store, None);
        assert_eq!(s.preference, ThemePreference::Dark);
        assert_eq!(s.density, Density::Compact);
        assert!(!s.materials_enabled);

        // The engine built from persisted settings resolves to dark/compact.
        let t = ThemeEngine::new(s).resolve(false);
        assert_eq!(t.mode, ThemeMode::Dark);
        assert_eq!(t.density, Density::Compact);
    }

    #[test]
    fn load_from_config_defaults_when_unset() {
        let store = theme_store();
        let s = ThemeSettings::load_from_config(&store, None);
        // Unset keys → schema defaults (auto / regular / materials on).
        assert_eq!(s.preference, ThemePreference::Auto);
        assert_eq!(s.density, Density::Regular);
        assert!(s.materials_enabled);
    }
}
