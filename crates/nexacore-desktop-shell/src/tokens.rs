//! Shell design tokens: the mockup's `:root` / `[data-theme="dark"]` custom
//! properties as ARGB constants, one struct per theme.
//!
//! Translucent mockup colours (`--chrome-bg`, terminal titlebar) are
//! **pre-blended to opaque** over their Milestone-1 backdrop because the
//! software renderer fills them without a wallpaper behind; real
//! wallpaper-backed blending arrives with the image-wallpaper milestone.

/// One theme's worth of shell colours (ARGB `u32`, alpha in the top byte).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ShellTokens {
    /// Desktop backdrop behind everything (`--bg-canvas`).
    pub bg_canvas: u32,
    /// Window/content surface (`--bg-surface`).
    pub bg_surface: u32,
    /// Secondary surface: sidebars, strips (`--bg-surface-2`).
    pub bg_surface_2: u32,
    /// Primary text (`--text-primary`).
    pub text_primary: u32,
    /// Secondary text (`--text-secondary`).
    pub text_secondary: u32,
    /// Tertiary/dim text and button glyphs (`--text-tertiary`).
    pub text_tertiary: u32,
    /// Accent text/links (`--text-accent`).
    pub text_accent: u32,
    /// Default border (`--border-default`).
    pub border_default: u32,
    /// Soft hairline border (`--border-soft`).
    pub border_soft: u32,
    /// Standard window titlebar fill (pre-blended `--chrome-bg`).
    pub titlebar_bg: u32,
    /// Terminal window titlebar fill (pre-blended `rgba(6,20,26,0.72)`).
    pub titlebar_bg_term: u32,
    /// Terminal content background (`--term-bg`).
    pub term_bg: u32,
    /// Brand petrol (`--petrol`).
    pub petrol: u32,
    /// Brand brick — focus accent, close-hover (`--brick`).
    pub brick: u32,
    /// Brand sage — running/OK (`--sage`).
    pub sage: u32,
    /// Strong sage for text on light (`--sage-700`).
    pub sage_700: u32,
    /// Goldenrod warning — minimize hover (`--warning`).
    pub warning: u32,
    /// Titlebar button-group pill fill (pre-blended `rgba(127,133,130,0.10)`).
    pub btn_group_bg: u32,
    /// Minimize-button hover fill (pre-blended `rgba(181,141,50,0.20)`).
    pub btn_hover_min: u32,
    /// Maximize-button hover fill (pre-blended `rgba(122,158,126,0.22)`).
    pub btn_hover_max: u32,
    /// Close-button hover fill (solid brick).
    pub btn_hover_close: u32,
    /// Window drop-shadow colour (ARGB with alpha, fed to `Shadow`).
    pub window_shadow: u32,
}

impl ShellTokens {
    /// Dark theme (mockup default).
    #[must_use]
    pub const fn dark() -> Self {
        Self {
            bg_canvas: 0xFF14_171A,
            bg_surface: 0xFF1E_2225,
            bg_surface_2: 0xFF25_2A2C,
            text_primary: 0xFFF4_EBD0,
            text_secondary: 0xFFD0_CBB8,
            text_tertiary: 0xFF8A_8F86,
            text_accent: 0xFFF4_EBD0,
            border_default: 0xFF2C_3134,
            border_soft: 0xFF26_2B2E,
            // rgba(18,21,24,0.64) over bg_surface #1E2225 → #161A1D
            titlebar_bg: 0xFF16_1A1D,
            // rgba(6,20,26,0.72) over term_bg #06141A → fg equals backdrop, so
            // the blend is exactly #06141A.
            titlebar_bg_term: 0xFF06_141A,
            term_bg: 0xFF06_141A,
            petrol: 0xFF0F_4C5C,
            brick: 0xFFC0_3221,
            sage: 0xFF7A_9E7E,
            sage_700: 0xFF58_7657,
            warning: 0xFFB5_8D32,
            // rgba(127,133,130,0.10) over titlebar #161A1D → #212527
            btn_group_bg: 0xFF21_2527,
            // rgba(181,141,50,0.20) over group bg #212527 → #3F3A29
            btn_hover_min: 0xFF3F_3A29,
            // rgba(122,158,126,0.22) over group bg #212527 → #35403A
            btn_hover_max: 0xFF35_403A,
            btn_hover_close: 0xFFC0_3221,
            // rgba(0,0,0,0.62)
            window_shadow: 0x9E00_0000,
        }
    }

    /// Light theme.
    #[must_use]
    pub const fn light() -> Self {
        Self {
            bg_canvas: 0xFFF4_EBD0,
            bg_surface: 0xFFFF_FFFF,
            bg_surface_2: 0xFFFA_F6EA,
            text_primary: 0xFF1F_2421,
            text_secondary: 0xFF3E_423E,
            text_tertiary: 0xFF8A_8F86,
            text_accent: 0xFF0F_4C5C,
            border_default: 0xFFE7_DFC8,
            border_soft: 0xFFEF_E9D8,
            // rgba(250,245,230,0.72) over bg_surface #FFFFFF → #FBF8ED
            titlebar_bg: 0xFFFB_F8ED,
            // rgba(6,20,26,0.72) over term_bg #06202A → #06171E
            titlebar_bg_term: 0xFF06_171E,
            term_bg: 0xFF06_202A,
            petrol: 0xFF0F_4C5C,
            brick: 0xFFC0_3221,
            sage: 0xFF7A_9E7E,
            sage_700: 0xFF58_7657,
            warning: 0xFFB5_8D32,
            // rgba(127,133,130,0.10) over titlebar #FBF8ED → #EFEDE2
            btn_group_bg: 0xFFEF_EDE2,
            // rgba(181,141,50,0.20) over group bg #EFEDE2 → #E3DABF
            btn_hover_min: 0xFFE3_DABF,
            // rgba(122,158,126,0.22) over group bg #EFEDE2 → #D5DCCC
            btn_hover_max: 0xFFD5_DCCC,
            btn_hover_close: 0xFFC0_3221,
            // rgba(5,25,33,0.30)
            window_shadow: 0x4D05_1921,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::ShellTokens;

    #[test]
    fn dark_and_light_are_distinct_and_branded() {
        let d = ShellTokens::dark();
        let l = ShellTokens::light();
        assert_eq!(d.bg_canvas, 0xFF14_171A);
        assert_eq!(l.bg_canvas, 0xFFF4_EBD0);
        assert_eq!(d.brick, l.brick, "brand accents are theme-invariant");
        assert_eq!(d.brick, 0xFFC0_3221);
        assert_ne!(d.bg_surface, l.bg_surface);
        assert_ne!(d.titlebar_bg, l.titlebar_bg);
    }

    #[test]
    fn titlebar_colors_are_opaque_preblends() {
        // M1 has no wallpaper-backed translucency: every titlebar colour must
        // be fully opaque (alpha 0xFF) so plain fills render correctly.
        for t in [ShellTokens::dark(), ShellTokens::light()] {
            assert_eq!(t.titlebar_bg >> 24, 0xFF);
            assert_eq!(t.titlebar_bg_term >> 24, 0xFF);
        }
    }
}
