//! `HiDPI` scale propagation and density-aware asset selection (WS7-04).
//!
//! The compositor (`nexacore-display`) derives a per-output [`ScaleFactor`] and
//! propagates it into the toolkit (WS7-04.1). Widgets lay out in logical pixels
//! and use the factor to pick density-appropriate assets ([`AssetDensity`],
//! WS7-04.2) and to map logical [`crate::layout::Size`]s to device pixels
//! ([`Size::scaled`], WS7-04.3). The pixel-level integer/fractional resampling
//! lives in the compositor (`nexacore_display::scale`).

pub use nexacore_display::scale::ScaleFactor;

use crate::layout::Size;

/// The discrete asset density a renderer selects for a given scale factor.
///
/// Assets are authored at 1×/2×/3× (`"@1x"`/`"@2x"`/`"@3x"`). The toolkit picks
/// the smallest bucket that is still ≥ the output scale, so an asset is at
/// worst downscaled (sharp) rather than upscaled (blurry), capped at 3×
/// (WS7-04.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AssetDensity {
    /// Standard-density assets (`"@1x"`).
    X1,
    /// Double-density assets (`"@2x"`).
    X2,
    /// Triple-density assets (`"@3x"`).
    X3,
}

impl AssetDensity {
    /// Select the density bucket for `scale`: the factor rounded up, capped at
    /// 3× (so `1.0 → X1`, `1.25/1.5/2.0 → X2`, `> 2.0 → X3`). Expressed with
    /// comparisons (no `f32::ceil`, which is `std`-only) so it stays `no_std`.
    #[must_use]
    pub fn for_scale(scale: ScaleFactor) -> Self {
        let v = scale.value();
        if v <= 1.0 {
            Self::X1
        } else if v <= 2.0 {
            Self::X2
        } else {
            Self::X3
        }
    }

    /// The integer density multiplier (`1`, `2`, or `3`).
    #[must_use]
    pub fn factor(self) -> u32 {
        match self {
            Self::X1 => 1,
            Self::X2 => 2,
            Self::X3 => 3,
        }
    }

    /// The conventional asset-name suffix (`"@1x"` / `"@2x"` / `"@3x"`).
    #[must_use]
    pub fn suffix(self) -> &'static str {
        match self {
            Self::X1 => "@1x",
            Self::X2 => "@2x",
            Self::X3 => "@3x",
        }
    }
}

impl Size {
    /// Map this logical size to device pixels for `scale`, rounding each
    /// dimension to the nearest whole device pixel (WS7-04.3).
    #[must_use]
    pub fn scaled(self, scale: ScaleFactor) -> Self {
        Self {
            w: scale.scale_length(self.w),
            h: scale.scale_length(self.h),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn asset_density_picks_smallest_bucket_ge_scale() {
        assert_eq!(AssetDensity::for_scale(ScaleFactor::ONE), AssetDensity::X1);
        assert_eq!(
            AssetDensity::for_scale(ScaleFactor::new(1.5).unwrap()),
            AssetDensity::X2
        );
        assert_eq!(
            AssetDensity::for_scale(ScaleFactor::integer(2)),
            AssetDensity::X2
        );
        assert_eq!(
            AssetDensity::for_scale(ScaleFactor::new(2.5).unwrap()),
            AssetDensity::X3
        );
        assert_eq!(
            AssetDensity::for_scale(ScaleFactor::integer(3)),
            AssetDensity::X3
        );
        assert_eq!(
            AssetDensity::for_scale(ScaleFactor::integer(5)),
            AssetDensity::X3
        );
    }

    #[test]
    fn asset_density_factor_and_suffix() {
        assert_eq!(AssetDensity::X1.factor(), 1);
        assert_eq!(AssetDensity::X2.factor(), 2);
        assert_eq!(AssetDensity::X3.factor(), 3);
        assert_eq!(AssetDensity::X2.suffix(), "@2x");
    }

    #[test]
    fn size_scales_to_device_pixels() {
        let logical = Size { w: 100, h: 40 };
        assert_eq!(
            logical.scaled(ScaleFactor::integer(2)),
            Size { w: 200, h: 80 }
        );
        // 1.5× rounds 100→150 and 40→60.
        assert_eq!(
            logical.scaled(ScaleFactor::new(1.5).unwrap()),
            Size { w: 150, h: 60 }
        );
    }

    #[test]
    fn scale_factor_is_reexported_for_propagation() {
        // The per-output factor defined by the compositor is usable here:
        // it propagated into the toolkit (WS7-04.1). Exercise it through an
        // integer-valued mapping to avoid a direct f32 comparison.
        let from_compositor = ScaleFactor::new(2.0).unwrap();
        assert_eq!(from_compositor.scale_length(10), 20);
    }
}
