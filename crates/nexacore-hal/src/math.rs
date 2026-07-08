//! Transcendental float shim — `std` vs `libm` dispatch.
//!
//! On stable Rust 1.85 the methods `f32::sqrt`, `f32::exp`, `f32::sin`,
//! `f32::cos`, and `f32::powf` live in **`std`**, not in `core`.  They are
//! therefore unavailable in `no_std` builds until the `core_float_math`
//! feature is stabilised (tracking issue rust-lang/rust#137578).
//!
//! This shim provides a single call-site for every transcendental used by the
//! inference engine:
//!
//! - **`std` build** (`feature = "std"`): delegates to the inherent `f32`
//!   methods — no extra dependency, bit-identical to the original code.
//! - **`no_std` build**: delegates to [`libm`] (pure-Rust, no_std, MIT/Apache-2.0).
//!   `libm` results are bit-identical to the GNU libm reference implementation
//!   on x86_64; they may differ from the `std` path by ≤ 1 ULP due to
//!   different intermediate rounding.  The golden test for the CPU engine
//!   (`"ab" → "dddd"`) pins the **std** path; Ring 3 uses the libm path and
//!   the test suite notes any divergence rather than papering over it
//!   (ADR-0034 §"Golden invariance").
//!
//! ## Usage
//!
//! ```
//! use nexacore_hal::math;
//!
//! let x = 4.0_f32;
//! assert!((math::sqrt(x) - 2.0).abs() < 1e-6);
//! ```
//!
//! ## References
//!
//! - TASK-13-pre / ADR-0034 — `no_std` inference engine port
//! - rust-lang/rust#137578 — `core_float_math` tracking issue

// Float arithmetic is by definition pervasive here; suppress the lint for the
// whole module to avoid decorator noise on every function body.
#![allow(clippy::float_arithmetic)]

// =============================================================================
// sqrt
// =============================================================================

/// Compute the square root of `x`.
///
/// # Example
///
/// ```
/// use nexacore_hal::math;
///
/// assert!((math::sqrt(9.0_f32) - 3.0_f32).abs() < 1e-6_f32);
/// ```
#[inline]
pub fn sqrt(x: f32) -> f32 {
    #[cfg(feature = "std")]
    {
        x.sqrt()
    }
    #[cfg(not(feature = "std"))]
    {
        libm::sqrtf(x)
    }
}

// =============================================================================
// exp
// =============================================================================

/// Compute `e^x` (the natural exponential).
///
/// # Example
///
/// ```
/// use nexacore_hal::math;
///
/// // e^0 == 1.0
/// assert!((math::exp(0.0_f32) - 1.0_f32).abs() < 1e-6_f32);
/// ```
#[inline]
pub fn exp(x: f32) -> f32 {
    #[cfg(feature = "std")]
    {
        x.exp()
    }
    #[cfg(not(feature = "std"))]
    {
        libm::expf(x)
    }
}

// =============================================================================
// sin
// =============================================================================

/// Compute the sine of `x` (radians).
///
/// # Example
///
/// ```
/// use nexacore_hal::math;
///
/// // sin(0) == 0
/// assert!(math::sin(0.0_f32).abs() < 1e-6_f32);
/// ```
#[inline]
pub fn sin(x: f32) -> f32 {
    #[cfg(feature = "std")]
    {
        x.sin()
    }
    #[cfg(not(feature = "std"))]
    {
        libm::sinf(x)
    }
}

// =============================================================================
// cos
// =============================================================================

/// Compute the cosine of `x` (radians).
///
/// # Example
///
/// ```
/// use nexacore_hal::math;
///
/// // cos(0) == 1
/// assert!((math::cos(0.0_f32) - 1.0_f32).abs() < 1e-6_f32);
/// ```
#[inline]
pub fn cos(x: f32) -> f32 {
    #[cfg(feature = "std")]
    {
        x.cos()
    }
    #[cfg(not(feature = "std"))]
    {
        libm::cosf(x)
    }
}

// =============================================================================
// powf
// =============================================================================

/// Raise `base` to the power `exp` (`base^exp`).
///
/// # Example
///
/// ```
/// use nexacore_hal::math;
///
/// assert!((math::powf(2.0_f32, 10.0_f32) - 1024.0_f32).abs() < 1e-3_f32);
/// ```
#[inline]
pub fn powf(base: f32, exp: f32) -> f32 {
    #[cfg(feature = "std")]
    {
        base.powf(exp)
    }
    #[cfg(not(feature = "std"))]
    {
        libm::powf(base, exp)
    }
}

// =============================================================================
// round
// =============================================================================

/// Round `x` to the nearest integer, with ties away from zero.
///
/// Matches the semantics of `f32::round` (std) and `libm::roundf`
/// (`no_std`) — both implement IEEE 754 `roundToIntegralTiesToAway`, so the
/// two paths are bit-identical.
///
/// # Example
///
/// ```
/// use nexacore_hal::math;
///
/// assert!((math::round(2.5_f32) - 3.0_f32).abs() < f32::EPSILON);
/// assert!((math::round(-2.5_f32) + 3.0_f32).abs() < f32::EPSILON);
/// ```
#[inline]
#[must_use]
pub fn round(x: f32) -> f32 {
    #[cfg(feature = "std")]
    {
        x.round()
    }
    #[cfg(not(feature = "std"))]
    {
        libm::roundf(x)
    }
}

// =============================================================================
// mul_add (fused multiply-add)
// =============================================================================

/// Compute `a * b + c` with a single rounding step (fused multiply-add).
///
/// Matches the semantics of `f32::mul_add` (std) and `libm::fmaf`
/// (`no_std`) — both compute the infinitely-precise product-sum rounded
/// once, so the two paths are bit-identical.
///
/// # Example
///
/// ```
/// use nexacore_hal::math;
///
/// assert!((math::mul_add(2.0_f32, 3.0_f32, 1.0_f32) - 7.0_f32).abs() < f32::EPSILON);
/// ```
#[inline]
#[must_use]
pub fn mul_add(a: f32, b: f32, c: f32) -> f32 {
    #[cfg(feature = "std")]
    {
        a.mul_add(b, c)
    }
    #[cfg(not(feature = "std"))]
    {
        libm::fmaf(a, b, c)
    }
}

// =============================================================================
// tanh (needed by GeLU in exec_gelu / transformer softmax paths)
// =============================================================================

/// Compute the hyperbolic tangent of `x`.
///
/// # Example
///
/// ```
/// use nexacore_hal::math;
///
/// // tanh(0) == 0
/// assert!(math::tanh(0.0_f32).abs() < 1e-6_f32);
/// ```
#[inline]
pub fn tanh(x: f32) -> f32 {
    #[cfg(feature = "std")]
    {
        x.tanh()
    }
    #[cfg(not(feature = "std"))]
    {
        libm::tanhf(x)
    }
}
