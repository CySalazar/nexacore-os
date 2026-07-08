//! Color-managed compositing pipeline (WS7-02).
//!
//! macOS-grade rendering needs accurate, wide-gamut color. This module is the
//! `no_std + alloc`, host-testable color core the compositor (WS7-01) drives at
//! the blending and presentation stages. It is intentionally backend-agnostic:
//! every transform here is pure math over the compositor's `0xAA_RR_GG_BB`
//! ARGB8888 `u32` pixels ([`crate::surface::Surface`]), so it is fully testable
//! on the host before the GPU presentation path lands.
//!
//! What it provides:
//!
//! * **Transfer functions** — the sRGB EOTF/OETF (also used by Display P3),
//!   converting between encoded values and linear light (WS7-02.2).
//! * **Linear-light alpha compositing** — [`blend_over_linear`] blends in
//!   linear space (gamma-correct), not in the encoded domain (WS7-02.2).
//! * **Gamut matrices** — linear sRGB and Display P3 to/from the CIE XYZ (D65)
//!   profile-connection space, the compositor's device-independent working
//!   space (WS7-02.3 / WS7-02.4).
//! * **ICC profile parsing** — [`parse_icc`] reduces a matrix/TRC display
//!   profile to its colorant matrix, white point, and tone gamma (WS7-02.1).
//! * **Per-output pipeline + presentation** — [`ColorPipeline`] / [`present`]
//!   convert source pixels into a specific output profile's encoding at the
//!   presentation stage (WS7-02.5).
//!
//! The actual GPU wiring of the presentation stage is WS7-01; this module is
//! the color math it calls.

// Color management is inherently floating-point and quantizes linear light to
// 8-bit channels; the channel casts are bounded ([0,1] → [0,255]) and the
// matrix indices are compile-time constants on fixed-size arrays.
#![allow(
    clippy::float_arithmetic,
    clippy::cast_precision_loss,
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_sign_loss
)]

use libm::powf;

// =============================================================================
// Errors
// =============================================================================

/// Errors produced by ICC parsing and color-pipeline operations.
///
/// Variants identify the failure category only; none carry runtime secret
/// data (ADR-0041 security model).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ColorError {
    /// The byte slice is shorter than the mandatory 128-byte ICC header.
    TruncatedHeader,
    /// The `acsp` profile signature (offset 36) is absent or wrong.
    BadSignature,
    /// The tag table is truncated or declares more tags than the data holds.
    TruncatedTagTable,
    /// A required RGB colorant tag (`rXYZ` / `gXYZ` / `bXYZ`) is missing.
    MissingColorant,
    /// A tag's payload is truncated or has an unexpected type signature.
    MalformedTag,
    /// [`present`] was given source and destination buffers of unequal length.
    SizeMismatch,
}

impl core::fmt::Display for ColorError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let msg = match self {
            Self::TruncatedHeader => "color: ICC data shorter than the 128-byte header",
            Self::BadSignature => "color: ICC 'acsp' signature missing or invalid",
            Self::TruncatedTagTable => "color: ICC tag table truncated",
            Self::MissingColorant => "color: ICC profile missing an RGB colorant tag",
            Self::MalformedTag => "color: ICC tag payload malformed",
            Self::SizeMismatch => "color: present() source/destination length mismatch",
        };
        f.write_str(msg)
    }
}

impl core::error::Error for ColorError {}

// =============================================================================
// 8-bit channel <-> unit interval
// =============================================================================

/// Convert an 8-bit channel value to the unit interval `[0.0, 1.0]`.
#[inline]
#[must_use]
pub fn u8_to_unit(v: u8) -> f32 {
    f32::from(v) / 255.0
}

/// Convert a unit-interval value to an 8-bit channel, clamping to `[0, 255]`
/// and rounding half-up. Out-of-range inputs are clipped (gamut clip).
#[inline]
#[must_use]
pub fn unit_to_u8(v: f32) -> u8 {
    (v.clamp(0.0, 1.0) * 255.0 + 0.5) as u8
}

// =============================================================================
// Rgba8 — unpacked ARGB8888 pixel
// =============================================================================

/// A straight-alpha 8-bit color unpacked from a compositor `0xAA_RR_GG_BB`
/// ARGB8888 `u32` pixel.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Rgba8 {
    /// Alpha channel (`0` transparent, `255` opaque).
    pub a: u8,
    /// Red channel.
    pub r: u8,
    /// Green channel.
    pub g: u8,
    /// Blue channel.
    pub b: u8,
}

impl Rgba8 {
    /// Unpack a `0xAA_RR_GG_BB` ARGB8888 pixel.
    #[inline]
    #[must_use]
    pub const fn from_argb(p: u32) -> Self {
        Self {
            a: (p >> 24) as u8,
            r: (p >> 16) as u8,
            g: (p >> 8) as u8,
            b: p as u8,
        }
    }

    /// Pack back into a `0xAA_RR_GG_BB` ARGB8888 pixel.
    #[inline]
    #[must_use]
    pub const fn to_argb(self) -> u32 {
        ((self.a as u32) << 24) | ((self.r as u32) << 16) | ((self.g as u32) << 8) | (self.b as u32)
    }
}

// =============================================================================
// Transfer functions (sRGB / Display P3 share the sRGB transfer) — WS7-02.2
// =============================================================================

/// sRGB **EOTF**: decode an encoded channel `[0,1]` to linear light `[0,1]`.
///
/// Piecewise per IEC 61966-2-1. Display P3 uses the same transfer function, so
/// this also decodes P3-encoded channels.
#[must_use]
pub fn srgb_to_linear(c: f32) -> f32 {
    let c = c.clamp(0.0, 1.0);
    if c <= 0.040_45 {
        c / 12.92
    } else {
        powf((c + 0.055) / 1.055, 2.4)
    }
}

/// sRGB **OETF**: encode a linear-light channel `[0,1]` back to the encoded
/// domain `[0,1]`. Inverse of [`srgb_to_linear`].
#[must_use]
pub fn linear_to_srgb(c: f32) -> f32 {
    let c = c.clamp(0.0, 1.0);
    if c <= 0.003_130_8 {
        12.92 * c
    } else {
        1.055 * powf(c, 1.0 / 2.4) - 0.055
    }
}

// =============================================================================
// Linear-light alpha compositing — WS7-02.2
// =============================================================================

/// Composite `src` **over** `dst` (straight alpha) in **linear light**.
///
/// Both pixels are ARGB8888. Each channel is decoded to linear with the sRGB
/// EOTF, combined with the Porter–Duff *over* operator, then re-encoded — so
/// the blend is gamma-correct (a 50%-opacity white over black yields ~`188`,
/// not the `128` of a naive encoded-domain average). Returns a fully
/// transparent pixel when the composited alpha is ~0.
#[must_use]
pub fn blend_over_linear(src: u32, dst: u32) -> u32 {
    let s = Rgba8::from_argb(src);
    let d = Rgba8::from_argb(dst);
    let sa = u8_to_unit(s.a);
    let da = u8_to_unit(d.a);
    let out_a = sa + da * (1.0 - sa);
    if out_a <= f32::EPSILON {
        return 0;
    }
    let channel = |sc: u8, dc: u8| -> u8 {
        let sl = srgb_to_linear(u8_to_unit(sc));
        let dl = srgb_to_linear(u8_to_unit(dc));
        let out = (sl * sa + dl * da * (1.0 - sa)) / out_a;
        unit_to_u8(linear_to_srgb(out))
    };
    Rgba8 {
        a: unit_to_u8(out_a),
        r: channel(s.r, d.r),
        g: channel(s.g, d.g),
        b: channel(s.b, d.b),
    }
    .to_argb()
}

// =============================================================================
// Gamut matrices (linear RGB <-> CIE XYZ, D65) — WS7-02.3 / WS7-02.4
// =============================================================================

/// A 3×3 row-major matrix of `f32`, used for linear color-space conversions.
pub type Mat3 = [[f32; 3]; 3];

/// Multiply a 3×3 matrix by a column vector.
#[must_use]
fn mat3_mul_vec(m: &Mat3, v: [f32; 3]) -> [f32; 3] {
    [
        m[0][0] * v[0] + m[0][1] * v[1] + m[0][2] * v[2],
        m[1][0] * v[0] + m[1][1] * v[1] + m[1][2] * v[2],
        m[2][0] * v[0] + m[2][1] * v[1] + m[2][2] * v[2],
    ]
}

/// Linear sRGB → CIE XYZ (D65). IEC 61966-2-1 primaries.
pub const SRGB_TO_XYZ: Mat3 = [
    [0.412_456_4, 0.357_576_1, 0.180_437_5],
    [0.212_672_9, 0.715_152_2, 0.072_175],
    [0.019_333_9, 0.119_192, 0.950_304_1],
];

/// CIE XYZ (D65) → linear sRGB. Inverse of [`SRGB_TO_XYZ`].
pub const XYZ_TO_SRGB: Mat3 = [
    [3.240_454, -1.537_139, -0.498_531_4],
    [-0.969_266, 1.876_011, 0.041_556],
    [0.055_643_4, -0.204_025_9, 1.057_225],
];

/// Linear Display P3 → CIE XYZ (D65). SMPTE RP 431-2 primaries, D65 white,
/// sRGB transfer (Apple "Display P3").
pub const DISPLAY_P3_TO_XYZ: Mat3 = [
    [0.486_570_9, 0.265_667_7, 0.198_217_3],
    [0.228_974_6, 0.691_738_5, 0.079_286_9],
    [0.0, 0.045_113_4, 1.043_944],
];

/// CIE XYZ (D65) → linear Display P3. Inverse of [`DISPLAY_P3_TO_XYZ`].
pub const XYZ_TO_DISPLAY_P3: Mat3 = [
    [2.493_497, -0.931_383_6, -0.402_710_8],
    [-0.829_489, 1.762_664, 0.023_624_7],
    [0.035_845_8, -0.076_172_4, 0.956_884_5],
];

// =============================================================================
// ColorSpace — a display space reachable through the XYZ connection space
// =============================================================================

/// A display color space the pipeline converts through the CIE XYZ (D65)
/// profile-connection space.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ColorSpace {
    /// IEC 61966-2-1 sRGB.
    Srgb,
    /// Apple "Display P3" (DCI-P3 primaries, D65 white, sRGB transfer).
    DisplayP3,
}

impl ColorSpace {
    /// The linear-RGB → XYZ matrix for this space (WS7-02.3 / WS7-02.4).
    #[must_use]
    pub const fn to_xyz_matrix(self) -> Mat3 {
        match self {
            Self::Srgb => SRGB_TO_XYZ,
            Self::DisplayP3 => DISPLAY_P3_TO_XYZ,
        }
    }

    /// The XYZ → linear-RGB matrix for this space (output mapping).
    #[must_use]
    pub const fn xyz_to_rgb_matrix(self) -> Mat3 {
        match self {
            Self::Srgb => XYZ_TO_SRGB,
            Self::DisplayP3 => XYZ_TO_DISPLAY_P3,
        }
    }
}

// =============================================================================
// ColorPipeline — per-output presentation transform — WS7-02.5
// =============================================================================

/// A presentation-stage color pipeline: it converts source pixels into a
/// specific output color space's encoding, routing through linear-light XYZ
/// (the compositor working space).
///
/// This is the per-output profile applied at the presentation stage: a desktop
/// authored in sRGB is mapped to a Display P3 panel (or vice-versa) with
/// gamut-correct, gamma-correct math. Out-of-gamut results are clipped to the
/// valid range.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ColorPipeline {
    /// Color space the source pixels are authored in.
    pub source: ColorSpace,
    /// Color space of the output device (the per-output profile).
    pub output: ColorSpace,
}

impl ColorPipeline {
    /// Build a pipeline from `source` to `output`.
    #[must_use]
    pub const fn new(source: ColorSpace, output: ColorSpace) -> Self {
        Self { source, output }
    }

    /// Convert one ARGB8888 source pixel to the output space's encoding.
    ///
    /// Alpha is preserved verbatim; the RGB channels are decoded to linear,
    /// taken to XYZ via the source primaries, mapped to the output primaries,
    /// clipped to gamut, and re-encoded.
    #[must_use]
    pub fn convert_pixel(self, src: u32) -> u32 {
        let c = Rgba8::from_argb(src);
        let lin = [
            srgb_to_linear(u8_to_unit(c.r)),
            srgb_to_linear(u8_to_unit(c.g)),
            srgb_to_linear(u8_to_unit(c.b)),
        ];
        let xyz = mat3_mul_vec(&self.source.to_xyz_matrix(), lin);
        let out_lin = mat3_mul_vec(&self.output.xyz_to_rgb_matrix(), xyz);
        Rgba8 {
            a: c.a,
            r: unit_to_u8(linear_to_srgb(out_lin[0])),
            g: unit_to_u8(linear_to_srgb(out_lin[1])),
            b: unit_to_u8(linear_to_srgb(out_lin[2])),
        }
        .to_argb()
    }
}

/// Apply a [`ColorPipeline`] across a framebuffer at the presentation stage,
/// writing converted pixels into `dst` (WS7-02.5).
///
/// `src` and `dst` must have equal length.
///
/// # Errors
///
/// Returns [`ColorError::SizeMismatch`] if the buffers differ in length.
pub fn present(pipeline: ColorPipeline, src: &[u32], dst: &mut [u32]) -> Result<(), ColorError> {
    if src.len() != dst.len() {
        return Err(ColorError::SizeMismatch);
    }
    for (d, &s) in dst.iter_mut().zip(src.iter()) {
        *d = pipeline.convert_pixel(s);
    }
    Ok(())
}

// =============================================================================
// ICC profile parsing (matrix/TRC display profiles) — WS7-02.1
// =============================================================================

/// `acsp` — the ICC profile file signature at header offset 36.
const ICC_SIGNATURE: u32 = 0x6163_7370;
/// `rXYZ` red colorant tag signature.
const SIG_RXYZ: u32 = 0x7258_595a;
/// `gXYZ` green colorant tag signature.
const SIG_GXYZ: u32 = 0x6758_595a;
/// `bXYZ` blue colorant tag signature.
const SIG_BXYZ: u32 = 0x6258_595a;
/// `wtpt` media white-point tag signature.
const SIG_WTPT: u32 = 0x7774_7074;
/// `rTRC` red tone-reproduction-curve tag signature.
const SIG_RTRC: u32 = 0x7254_5243;
/// `XYZ ` tag type signature.
const TYPE_XYZ: u32 = 0x5859_5a20;
/// `curv` tag type signature.
const TYPE_CURV: u32 = 0x6375_7276;

/// A parsed ICC display profile, reduced to its matrix/TRC model.
///
/// This is the internal representation the compositor keeps for matrix-based
/// RGB display profiles (which sRGB and Display P3 v2/v4 profiles are). It is
/// not a full ICC CMM: LUT-based (`mft1`/`mAB `) profiles are out of scope.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct IccProfile {
    /// Declared profile size in bytes (header offset 0).
    pub size: u32,
    /// Data color space `FourCC` (header offset 16, e.g. `RGB ` = `0x5247_4220`).
    pub data_color_space: u32,
    /// Profile connection space `FourCC` (header offset 20, e.g. `XYZ `).
    pub pcs: u32,
    /// Linear-RGB → XYZ matrix assembled from the `rXYZ`/`gXYZ`/`bXYZ`
    /// colorant columns.
    pub rgb_to_xyz: Mat3,
    /// Media white point (`wtpt`), or the D50 PCS white if the tag is absent.
    pub white_point: [f32; 3],
    /// Single-value tone gamma from `rTRC`, when the curve reduces to one
    /// (`None` for identity-less LUT curves not modelled here).
    pub gamma: Option<f32>,
}

/// Read a big-endian `u32` at `off`, or `None` if out of bounds.
fn be_u32(b: &[u8], off: usize) -> Option<u32> {
    let end = off.checked_add(4)?;
    let arr: [u8; 4] = b.get(off..end)?.try_into().ok()?;
    Some(u32::from_be_bytes(arr))
}

/// Decode an s15Fixed16 fixed-point number at `off` to `f32`.
fn s15fixed16(b: &[u8], off: usize) -> Option<f32> {
    let raw = be_u32(b, off)? as i32;
    Some(raw as f32 / 65536.0)
}

/// Read the first `XYZNumber` of an `XYZType` tag body at `off`.
fn read_xyz_tag(b: &[u8], off: usize) -> Option<[f32; 3]> {
    if be_u32(b, off)? != TYPE_XYZ {
        return None;
    }
    Some([
        s15fixed16(b, off.checked_add(8)?)?,
        s15fixed16(b, off.checked_add(12)?)?,
        s15fixed16(b, off.checked_add(16)?)?,
    ])
}

/// Reduce a `curveType` tag body at `off` to a single gamma, when possible.
///
/// `count == 0` is the identity curve (gamma `1.0`); `count == 1` carries a
/// `u8Fixed8Number` gamma; longer LUT curves are not reduced (`None`).
fn read_curve_gamma(b: &[u8], off: usize) -> Option<f32> {
    if be_u32(b, off)? != TYPE_CURV {
        return None;
    }
    match be_u32(b, off.checked_add(8)?)? {
        0 => Some(1.0),
        1 => {
            let at = off.checked_add(12)?;
            let arr: [u8; 2] = b.get(at..at.checked_add(2)?)?.try_into().ok()?;
            Some(f32::from(u16::from_be_bytes(arr)) / 256.0)
        }
        _ => None,
    }
}

/// Parse an ICC matrix/TRC display profile into an [`IccProfile`] (WS7-02.1).
///
/// Validates the 128-byte header and the `acsp` signature, then walks the tag
/// table extracting the RGB colorant matrix, white point, and red tone gamma.
///
/// # Errors
///
/// - [`ColorError::TruncatedHeader`] if `bytes` is shorter than 128 bytes or a
///   header field runs past the end.
/// - [`ColorError::BadSignature`] if the `acsp` signature is wrong.
/// - [`ColorError::TruncatedTagTable`] if the tag table runs past the end.
/// - [`ColorError::MissingColorant`] if any of `rXYZ`/`gXYZ`/`bXYZ` is absent
///   or malformed.
pub fn parse_icc(bytes: &[u8]) -> Result<IccProfile, ColorError> {
    if bytes.len() < 128 {
        return Err(ColorError::TruncatedHeader);
    }
    let size = be_u32(bytes, 0).ok_or(ColorError::TruncatedHeader)?;
    if be_u32(bytes, 36).ok_or(ColorError::TruncatedHeader)? != ICC_SIGNATURE {
        return Err(ColorError::BadSignature);
    }
    let data_color_space = be_u32(bytes, 16).ok_or(ColorError::TruncatedHeader)?;
    let pcs = be_u32(bytes, 20).ok_or(ColorError::TruncatedHeader)?;

    let tag_count = be_u32(bytes, 128).ok_or(ColorError::TruncatedTagTable)?;
    let mut rxyz = None;
    let mut gxyz = None;
    let mut bxyz = None;
    let mut wtpt = None;
    let mut gamma = None;
    for i in 0..tag_count {
        // Tag table starts at offset 132; each entry is 12 bytes
        // (signature, offset, size).
        let entry = 132usize
            .checked_add(
                (i as usize)
                    .checked_mul(12)
                    .ok_or(ColorError::TruncatedTagTable)?,
            )
            .ok_or(ColorError::TruncatedTagTable)?;
        let sig = be_u32(bytes, entry).ok_or(ColorError::TruncatedTagTable)?;
        let offset = be_u32(
            bytes,
            entry.checked_add(4).ok_or(ColorError::TruncatedTagTable)?,
        )
        .ok_or(ColorError::TruncatedTagTable)? as usize;
        match sig {
            SIG_RXYZ => rxyz = read_xyz_tag(bytes, offset),
            SIG_GXYZ => gxyz = read_xyz_tag(bytes, offset),
            SIG_BXYZ => bxyz = read_xyz_tag(bytes, offset),
            SIG_WTPT => wtpt = read_xyz_tag(bytes, offset),
            SIG_RTRC => gamma = read_curve_gamma(bytes, offset),
            _ => {}
        }
    }

    let (Some(rx), Some(gx), Some(bx)) = (rxyz, gxyz, bxyz) else {
        return Err(ColorError::MissingColorant);
    };
    // Each colorant is a column of the linear-RGB → XYZ matrix.
    let rgb_to_xyz = [
        [rx[0], gx[0], bx[0]],
        [rx[1], gx[1], bx[1]],
        [rx[2], gx[2], bx[2]],
    ];

    Ok(IccProfile {
        size,
        data_color_space,
        pcs,
        rgb_to_xyz,
        // D50 PCS reference white, used when the profile omits `wtpt`.
        white_point: wtpt.unwrap_or([0.9642, 1.0, 0.8249]),
        gamma,
    })
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use alloc::{vec, vec::Vec};

    use super::*;

    /// Absolute tolerance for linear-space comparisons (≈ 1 LSB of 8-bit).
    const EPS: f32 = 2e-3;

    fn approx(a: f32, b: f32, eps: f32) -> bool {
        (a - b).abs() <= eps
    }

    fn vec_approx(a: [f32; 3], b: [f32; 3], eps: f32) -> bool {
        approx(a[0], b[0], eps) && approx(a[1], b[1], eps) && approx(a[2], b[2], eps)
    }

    // ---- Transfer functions (WS7-02.2) --------------------------------------

    #[test]
    fn srgb_transfer_endpoints_and_round_trip() {
        assert!(approx(srgb_to_linear(0.0), 0.0, EPS));
        assert!(approx(srgb_to_linear(1.0), 1.0, EPS));
        assert!(approx(linear_to_srgb(0.0), 0.0, EPS));
        assert!(approx(linear_to_srgb(1.0), 1.0, EPS));
        // Encoded 0.5 decodes to ~0.214 linear; round-trips back.
        let lin = srgb_to_linear(0.5);
        assert!(approx(lin, 0.214_041, 1e-3), "lin={lin}");
        assert!(approx(linear_to_srgb(lin), 0.5, 1e-3));
    }

    #[test]
    fn linear_half_encodes_above_naive_midpoint() {
        // Linear 0.5 encodes to ~0.7353 (≈188/255), well above the naive 0.5.
        assert!(approx(linear_to_srgb(0.5), 0.735_357, 1e-3));
    }

    // ---- Channel packing ----------------------------------------------------

    #[test]
    fn rgba8_pack_unpack_round_trip() {
        let p = 0x80_12_34_56u32;
        let c = Rgba8::from_argb(p);
        assert_eq!(
            c,
            Rgba8 {
                a: 0x80,
                r: 0x12,
                g: 0x34,
                b: 0x56
            }
        );
        assert_eq!(c.to_argb(), p);
    }

    #[test]
    fn unit_u8_round_trips_and_clamps() {
        assert_eq!(unit_to_u8(0.0), 0);
        assert_eq!(unit_to_u8(1.0), 255);
        assert_eq!(unit_to_u8(-1.0), 0);
        assert_eq!(unit_to_u8(2.0), 255);
        assert_eq!(unit_to_u8(u8_to_unit(200)), 200);
    }

    // ---- Linear blending (WS7-02.2) -----------------------------------------

    #[test]
    fn blend_half_white_over_black_is_gamma_correct() {
        // 50%-opacity white over opaque black: linear blend ⇒ ~188, NOT 128.
        let src = 0x80_FF_FF_FFu32; // alpha 128 white
        let dst = 0xFF_00_00_00u32; // opaque black
        let out = Rgba8::from_argb(blend_over_linear(src, dst));
        assert_eq!(out.a, 255);
        assert!(
            (185..=190).contains(&out.r),
            "gamma-correct grey expected ~188, got {}",
            out.r
        );
        // A naive encoded-domain average would land near 128 — assert we are
        // clearly above it.
        assert!(out.r > 160, "linear blend must exceed naive midpoint");
        assert_eq!(out.r, out.g);
        assert_eq!(out.g, out.b);
    }

    #[test]
    fn blend_opaque_src_returns_src() {
        let src = 0xFF_AB_CD_EFu32;
        let dst = 0xFF_11_22_33u32;
        assert_eq!(blend_over_linear(src, dst), src);
    }

    #[test]
    fn blend_transparent_src_returns_dst() {
        let src = 0x00_AB_CD_EFu32;
        let dst = 0xFF_11_22_33u32;
        assert_eq!(blend_over_linear(src, dst), dst);
    }

    // ---- Gamut matrices (WS7-02.3 / .4) -------------------------------------

    #[test]
    fn srgb_white_maps_to_d65() {
        let xyz = mat3_mul_vec(&SRGB_TO_XYZ, [1.0, 1.0, 1.0]);
        assert!(
            vec_approx(xyz, [0.950_47, 1.0, 1.088_83], EPS),
            "xyz={xyz:?}"
        );
    }

    #[test]
    fn srgb_matrix_round_trips_through_xyz() {
        let rgb = [0.25, 0.5, 0.75];
        let xyz = mat3_mul_vec(&SRGB_TO_XYZ, rgb);
        let back = mat3_mul_vec(&XYZ_TO_SRGB, xyz);
        assert!(vec_approx(back, rgb, EPS), "back={back:?}");
    }

    #[test]
    fn p3_matrix_round_trips_through_xyz() {
        let rgb = [0.2, 0.6, 0.9];
        let xyz = mat3_mul_vec(&DISPLAY_P3_TO_XYZ, rgb);
        let back = mat3_mul_vec(&XYZ_TO_DISPLAY_P3, xyz);
        assert!(vec_approx(back, rgb, EPS), "back={back:?}");
    }

    // ---- Pipeline / presentation (WS7-02.5) ---------------------------------

    #[test]
    fn pipeline_srgb_to_srgb_is_identity() {
        let pipe = ColorPipeline::new(ColorSpace::Srgb, ColorSpace::Srgb);
        for &p in &[
            0xFF_FF_00_00u32,
            0xFF_00_FF_00,
            0xFF_00_00_FF,
            0xFF_80_40_C0,
        ] {
            let out = Rgba8::from_argb(pipe.convert_pixel(p));
            let inp = Rgba8::from_argb(p);
            // Allow ±1 LSB for the encode/decode/matrix round trip.
            assert_eq!(out.a, inp.a);
            assert!(out.r.abs_diff(inp.r) <= 1, "r {} vs {}", out.r, inp.r);
            assert!(out.g.abs_diff(inp.g) <= 1, "g {} vs {}", out.g, inp.g);
            assert!(out.b.abs_diff(inp.b) <= 1, "b {} vs {}", out.b, inp.b);
        }
    }

    #[test]
    fn pipeline_srgb_red_into_p3_stays_in_gamut_and_round_trips() {
        // sRGB primaries lie inside the wider P3 gamut, so sRGB red maps to a
        // smaller, valid P3 red coordinate (red still dominant), and the
        // inverse pipeline recovers the original within tolerance.
        let to_p3 = ColorPipeline::new(ColorSpace::Srgb, ColorSpace::DisplayP3);
        let red = 0xFF_FF_00_00u32;
        let in_p3 = Rgba8::from_argb(to_p3.convert_pixel(red));
        assert!(
            in_p3.r > in_p3.g && in_p3.r > in_p3.b,
            "red must dominate: {in_p3:?}"
        );
        assert!(in_p3.r < 255, "sRGB red is inside P3 ⇒ encoded red < full");

        let back = ColorPipeline::new(ColorSpace::DisplayP3, ColorSpace::Srgb);
        let recovered = Rgba8::from_argb(back.convert_pixel(in_p3.to_argb()));
        assert!(recovered.r.abs_diff(0xFF) <= 2, "r={}", recovered.r);
        assert!(recovered.g <= 2, "g={}", recovered.g);
        assert!(recovered.b <= 2, "b={}", recovered.b);
    }

    #[test]
    fn present_converts_buffer_and_rejects_size_mismatch() {
        let pipe = ColorPipeline::new(ColorSpace::Srgb, ColorSpace::Srgb);
        let src = [0xFF_10_20_30u32, 0xFF_40_50_60];
        let mut dst = [0u32; 2];
        present(pipe, &src, &mut dst).unwrap();
        assert_eq!(Rgba8::from_argb(dst[0]).a, 0xFF);

        let mut wrong = [0u32; 1];
        assert_eq!(
            present(pipe, &src, &mut wrong),
            Err(ColorError::SizeMismatch)
        );
    }

    // ---- Color target on emulated P3 output (WS7-02.6) ----------------------

    #[test]
    fn color_target_within_tolerance_on_emulated_p3() {
        // Emulated P3 output: each sRGB target swatch must render to the P3
        // encoding within ≤2 LSB/channel of an independently-computed golden
        // value (reference matrices evaluated in f64; pipeline runs in f32).
        // This is the tolerance gate for the presentation stage before a real
        // P3 panel exists (WS7-02.6). A full sRGB→P3→sRGB round trip is NOT
        // used here: recovering a near-zero channel of a saturated primary
        // amplifies the 8-bit intermediate quantization through the steep
        // low-end of the transfer function, which is a property of 8-bit
        // intermediates, not a pipeline defect — see the dedicated round-trip
        // property test below for the in-gamut/dominant-channel checks.
        let to_p3 = ColorPipeline::new(ColorSpace::Srgb, ColorSpace::DisplayP3);
        // (source sRGB, golden P3-encoded) pairs.
        let targets = [
            (0xFF_FF_FF_FFu32, 0xFF_FF_FF_FFu32), // white
            (0xFF_00_00_00, 0xFF_00_00_00),       // black
            (0xFF_FF_00_00, 0xFF_EA_33_23),       // red
            (0xFF_00_FF_00, 0xFF_75_FB_4C),       // green
            (0xFF_00_00_FF, 0xFF_00_00_F5),       // blue
            (0xFF_C0_60_30, 0xFF_B4_65_3B),       // mid tone
            (0xFF_20_80_A0, 0xFF_3F_7E_9D),       // teal
        ];
        for &(src, golden) in &targets {
            let got = Rgba8::from_argb(to_p3.convert_pixel(src));
            let want = Rgba8::from_argb(golden);
            assert_eq!(got.a, want.a, "{src:08X} alpha");
            assert!(
                got.r.abs_diff(want.r) <= 2,
                "{src:08X} r: {} vs {}",
                got.r,
                want.r
            );
            assert!(
                got.g.abs_diff(want.g) <= 2,
                "{src:08X} g: {} vs {}",
                got.g,
                want.g
            );
            assert!(
                got.b.abs_diff(want.b) <= 2,
                "{src:08X} b: {} vs {}",
                got.b,
                want.b
            );
        }
    }

    // ---- ICC parsing (WS7-02.1) ---------------------------------------------

    /// Encode an s15Fixed16 value (big-endian).
    fn enc_s15(v: f32) -> [u8; 4] {
        ((v * 65536.0).round() as i32).to_be_bytes()
    }

    /// Build a minimal but well-formed ICC RGB/XYZ matrix profile carrying the
    /// sRGB colorants in `rXYZ`/`gXYZ`/`bXYZ`.
    fn build_srgb_icc() -> Vec<u8> {
        // 128-byte header + tag table (3 tags) + three XYZType tags.
        let header_len = 128usize;
        let tag_count = 3u32;
        let table_len = 4 + (tag_count as usize) * 12; // count + entries
        let data_start = header_len + table_len;
        let xyz_tag_len = 20usize; // 8-byte header + one XYZNumber (12)

        let mut buf = vec![0u8; data_start + 3 * xyz_tag_len];

        // Header: signature 'acsp' @36, color space 'RGB ' @16, PCS 'XYZ ' @20.
        buf[36..40].copy_from_slice(&ICC_SIGNATURE.to_be_bytes());
        buf[16..20].copy_from_slice(&0x5247_4220u32.to_be_bytes()); // 'RGB '
        buf[20..24].copy_from_slice(&TYPE_XYZ.to_be_bytes());
        let total = (data_start + 3 * xyz_tag_len) as u32;
        buf[0..4].copy_from_slice(&total.to_be_bytes());

        // Tag table @128.
        buf[128..132].copy_from_slice(&tag_count.to_be_bytes());
        let sigs = [SIG_RXYZ, SIG_GXYZ, SIG_BXYZ];
        // sRGB colorant columns (rXYZ, gXYZ, bXYZ).
        let cols = [
            [0.412_456_4, 0.212_672_9, 0.019_333_9],
            [0.357_576_1, 0.715_152_2, 0.119_192],
            [0.180_437_5, 0.072_175, 0.950_304_1],
        ];
        for (i, (sig, col)) in sigs.iter().zip(cols.iter()).enumerate() {
            let entry = 132 + i * 12;
            let tag_off = data_start + i * xyz_tag_len;
            buf[entry..entry + 4].copy_from_slice(&sig.to_be_bytes());
            buf[entry + 4..entry + 8].copy_from_slice(&(tag_off as u32).to_be_bytes());
            buf[entry + 8..entry + 12].copy_from_slice(&(xyz_tag_len as u32).to_be_bytes());
            // XYZType body.
            buf[tag_off..tag_off + 4].copy_from_slice(&TYPE_XYZ.to_be_bytes());
            buf[tag_off + 8..tag_off + 12].copy_from_slice(&enc_s15(col[0]));
            buf[tag_off + 12..tag_off + 16].copy_from_slice(&enc_s15(col[1]));
            buf[tag_off + 16..tag_off + 20].copy_from_slice(&enc_s15(col[2]));
        }
        buf
    }

    #[test]
    fn icc_parse_minimal_srgb_profile() {
        let bytes = build_srgb_icc();
        let p = parse_icc(&bytes).unwrap();
        assert_eq!(p.data_color_space, 0x5247_4220); // 'RGB '
        assert_eq!(p.pcs, TYPE_XYZ);
        // The reconstructed matrix matches the built-in sRGB → XYZ matrix.
        for (got_row, want_row) in p.rgb_to_xyz.iter().zip(SRGB_TO_XYZ.iter()) {
            for (got, want) in got_row.iter().zip(want_row.iter()) {
                assert!(approx(*got, *want, 1e-3), "matrix cell {got} vs {want}");
            }
        }
    }

    #[test]
    fn icc_parse_rejects_truncated_header() {
        assert_eq!(parse_icc(&[0u8; 64]), Err(ColorError::TruncatedHeader));
    }

    #[test]
    fn icc_parse_rejects_bad_signature() {
        let mut bytes = build_srgb_icc();
        bytes[36] ^= 0xFF; // corrupt 'acsp'
        assert_eq!(parse_icc(&bytes), Err(ColorError::BadSignature));
    }

    #[test]
    fn icc_parse_rejects_missing_colorant() {
        let mut bytes = build_srgb_icc();
        // Zero the tag count ⇒ no colorant tags found.
        bytes[128..132].copy_from_slice(&0u32.to_be_bytes());
        assert_eq!(parse_icc(&bytes), Err(ColorError::MissingColorant));
    }
}
