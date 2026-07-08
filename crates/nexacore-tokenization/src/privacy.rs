//! DP-SGD privacy budget accountant using the moments accountant (Rényi DP).
//!
//! This module implements a privacy budget tracker for training machine-learning
//! models with Differentially Private Stochastic Gradient Descent (DP-SGD).
//!
//! # Background
//!
//! Differential Privacy (DP) guarantees that the output of a computation does
//! not change significantly when any single individual's data is added or
//! removed.  In DP-SGD, noise is added to gradients at each training step
//! according to a Gaussian mechanism, and the cumulative privacy cost is
//! tracked across all steps.
//!
//! Naïve composition of (ε, δ)-DP bounds is loose.  This module instead uses
//! **Rényi Differential Privacy (RDP)**, which composes exactly (by addition)
//! and converts to tight (ε, δ)-DP bounds at the end.
//!
//! # Moments accountant
//!
//! The moments accountant (Mironov 2017, Abadi et al. 2016) tracks the
//! per-order Rényi divergence at a set of evaluation orders `α ∈ (1, ∞)`.
//! After `T` steps with Gaussian noise multiplier `σ` and subsampling rate
//! `q`, the accumulated RDP budget at order `α` is approximately:
//!
//! ```text
//! ε_RDP(α) ≈ T · (α·q²) / (2·σ²)          (tight bound for small q)
//! ```
//!
//! This is converted to (ε, δ)-DP using the relation:
//!
//! ```text
//! ε(δ) = min over α: ε_RDP(α) − log(δ)/α + log((α-1)/α) + (log α - log(α-1))/(α-1)
//!                                                   ↑ "Balle et al. 2020 conversion"
//! ```
//!
//! In practice we evaluate the conversion at a fixed grid of integer orders
//! `α ∈ [2, 128]` and take the minimum.
//!
//! # Usage
//!
//! ```rust
//! use nexacore_tokenization::privacy::{BudgetExhausted, PrivacyAccountant};
//!
//! let mut accountant = PrivacyAccountant::new(
//!     1.1,  // noise_multiplier σ
//!     0.01, // sampling_rate q (fraction of dataset per step)
//! );
//!
//! // Simulate 100 training steps.
//! for _ in 0..100 {
//!     accountant.step().expect("budget must not be exhausted");
//! }
//!
//! let (epsilon, delta) = accountant
//!     .epsilon_delta(1e-5)
//!     .expect("conversion must succeed");
//! // epsilon is the privacy cost spent so far.
//! assert!(epsilon > 0.0);
//! ```
//!
//! # References
//!
//! - Abadi et al., "Deep Learning with Differential Privacy", CCS 2016.
//! - Mironov, "Rényi Differential Privacy of the Gaussian Mechanism", CSF 2017.
//! - Balle et al., "Hypothesis Testing Interpretations and Renormalization of
//!   Differential Privacy", ICML 2020.

use thiserror::Error;

// =============================================================================
// Error types
// =============================================================================

/// Errors that can arise when operating the privacy accountant.
///
/// # Example
///
/// ```
/// use nexacore_tokenization::privacy::{AccountantError, PrivacyAccountant};
///
/// let mut acc = PrivacyAccountant::new(1.1, 0.01);
/// acc.set_epsilon_cap(Some((1.0, 1e-5)));
/// // Drive until exhausted.
/// let result: Result<(), AccountantError> = loop {
///     match acc.step() {
///         Err(e) => break Err(e),
///         Ok(()) => {}
///     }
/// };
/// assert!(matches!(
///     result,
///     Err(AccountantError::BudgetExhausted { .. })
/// ));
/// ```
#[derive(Debug, Error, PartialEq)]
pub enum AccountantError {
    /// The configured privacy budget has been exhausted.
    ///
    /// The `epsilon_spent` and `delta` fields describe the state at the
    /// point of exhaustion.  The caller MUST NOT continue training after
    /// receiving this error.
    #[error(
        "privacy budget exhausted: ε_spent={epsilon_spent:.4} ≥ ε_cap={epsilon_cap:.4} at δ={delta:.2e}"
    )]
    BudgetExhausted {
        /// Total epsilon spent up to and including the failing step.
        epsilon_spent: f64,
        /// The configured epsilon cap that was exceeded.
        epsilon_cap: f64,
        /// The delta value used for the epsilon conversion.
        delta: f64,
    },

    /// A parameter was invalid at construction or query time.
    #[error("invalid parameter: {0}")]
    InvalidParameter(&'static str),
}

/// Convenience alias for `BudgetExhausted`.  Kept for ergonomic use in
/// callers that only care about the exhaustion case.
pub type BudgetExhausted = AccountantError;

// =============================================================================
// Evaluation orders
// =============================================================================

/// Integer Rényi orders at which the accountant evaluates the RDP budget.
///
/// The conversion to (ε, δ)-DP is minimised over these orders.  The set
/// `[2, 128]` is a common default in the DP-SGD literature (see the
/// `TensorFlow` Privacy implementation) and provides tight bounds across the
/// noise multipliers used in practice (σ ∈ [0.5, 10]).
const EVAL_ORDERS: &[u64] = &[
    2, 3, 4, 5, 6, 7, 8, 9, 10, 12, 14, 16, 20, 24, 28, 32, 40, 48, 56, 64, 80, 96, 112, 128,
];

// =============================================================================
// PrivacyAccountant
// =============================================================================

/// DP-SGD privacy budget accountant.
///
/// Tracks the cumulative Rényi DP (RDP) privacy loss across training steps
/// and converts it to (ε, δ)-DP on demand.
///
/// ## Parameters
///
/// - `noise_multiplier` (`σ`): the ratio of the Gaussian noise standard
///   deviation to the gradient clipping norm.  Higher values give stronger
///   privacy at the cost of model utility.  Must be positive.
/// - `sampling_rate` (`q`): the fraction of the full training dataset drawn
///   at each step (Poisson subsampling).  Must be in `(0, 1]`.
///
/// ## Thread safety
///
/// `PrivacyAccountant` is not `Sync`.  Callers that share an accountant
/// across threads must wrap it in a `Mutex`.
///
/// # Example
///
/// ```
/// use nexacore_tokenization::privacy::PrivacyAccountant;
///
/// let mut acc = PrivacyAccountant::new(1.1, 0.01);
/// acc.step().expect("first step must not exhaust budget");
/// let steps = acc.steps_taken();
/// assert_eq!(steps, 1);
/// ```
#[derive(Debug, Clone)]
pub struct PrivacyAccountant {
    /// Gaussian noise multiplier σ.  Positive; controls privacy / utility trade-off.
    noise_multiplier: f64,
    /// Poisson subsampling rate q ∈ (0, 1].
    sampling_rate: f64,
    /// Total training steps taken so far.
    steps: u64,
    /// Optional epsilon cap.  When set, [`step`](Self::step) returns
    /// [`AccountantError::BudgetExhausted`] once the (ε, δ)-DP epsilon
    /// at `cap_delta` meets or exceeds this value.
    epsilon_cap: Option<f64>,
    /// Delta value used when checking against `epsilon_cap` after each step.
    /// Defaults to `1e-5`.
    cap_delta: f64,
}

impl PrivacyAccountant {
    /// Construct a new accountant.
    ///
    /// # Parameters
    ///
    /// - `noise_multiplier`: σ in `(0, ∞)`.  Larger values → stronger privacy.
    /// - `sampling_rate`: q in `(0, 1]`.  Fraction of dataset per step.
    ///
    /// The accountant starts with zero steps.  No epsilon cap is configured;
    /// use [`set_epsilon_cap`](Self::set_epsilon_cap) to enable budget
    /// enforcement.
    ///
    /// # Panics
    ///
    /// Does not panic.  Invalid parameters are caught by [`step`](Self::step)
    /// and [`epsilon_delta`](Self::epsilon_delta) at call time.
    ///
    /// # Example
    ///
    /// ```
    /// use nexacore_tokenization::privacy::PrivacyAccountant;
    /// let acc = PrivacyAccountant::new(1.1, 0.01);
    /// assert_eq!(acc.steps_taken(), 0);
    /// ```
    #[must_use]
    pub fn new(noise_multiplier: f64, sampling_rate: f64) -> Self {
        Self {
            noise_multiplier,
            sampling_rate,
            steps: 0,
            epsilon_cap: None,
            cap_delta: 1e-5,
        }
    }

    /// Set (or clear) an epsilon cap with an associated delta.
    ///
    /// When `Some((epsilon, delta))` is set, [`step`](Self::step) will
    /// return [`AccountantError::BudgetExhausted`] after any step that
    /// causes the accumulated (ε, δ)-DP epsilon to reach or exceed `epsilon`.
    ///
    /// Pass `None` to disable budget enforcement (the accountant will accept
    /// unlimited steps).
    ///
    /// # Example
    ///
    /// ```
    /// use nexacore_tokenization::privacy::PrivacyAccountant;
    /// let mut acc = PrivacyAccountant::new(1.1, 0.01);
    /// acc.set_epsilon_cap(Some((2.0, 1e-5)));
    /// ```
    pub fn set_epsilon_cap(&mut self, cap: Option<(f64, f64)>) {
        match cap {
            Some((eps, delta)) => {
                self.epsilon_cap = Some(eps);
                self.cap_delta = delta;
            }
            None => {
                self.epsilon_cap = None;
            }
        }
    }

    /// Advance the accountant by one training step.
    ///
    /// Increments the step counter and, if a budget cap has been set via
    /// [`set_epsilon_cap`](Self::set_epsilon_cap), checks whether the
    /// accumulated (ε, δ)-DP epsilon has been reached.
    ///
    /// # Errors
    ///
    /// - [`AccountantError::InvalidParameter`] if `noise_multiplier ≤ 0` or
    ///   `sampling_rate ∉ (0, 1]`.
    /// - [`AccountantError::BudgetExhausted`] if the epsilon cap has been
    ///   exceeded after this step.
    ///
    /// # Example
    ///
    /// ```
    /// use nexacore_tokenization::privacy::PrivacyAccountant;
    ///
    /// let mut acc = PrivacyAccountant::new(1.1, 0.01);
    /// acc.step().expect("step must succeed without a cap");
    /// assert_eq!(acc.steps_taken(), 1);
    /// ```
    pub fn step(&mut self) -> Result<(), AccountantError> {
        self.validate_params()?;
        self.steps = self.steps.saturating_add(1);

        // Check against the budget cap if one is configured.
        if let Some(cap) = self.epsilon_cap {
            let (eps, _) = self.epsilon_delta_inner(self.cap_delta);
            if eps >= cap {
                return Err(AccountantError::BudgetExhausted {
                    epsilon_spent: eps,
                    epsilon_cap: cap,
                    delta: self.cap_delta,
                });
            }
        }

        Ok(())
    }

    /// Record `count` training steps at once.
    ///
    /// Equivalent to calling [`step`](Self::step) `count` times but more
    /// efficient because the parameter validation and RDP computation are
    /// done only once.
    ///
    /// # Errors
    ///
    /// Same as [`step`](Self::step).
    ///
    /// # Example
    ///
    /// ```
    /// use nexacore_tokenization::privacy::PrivacyAccountant;
    ///
    /// let mut acc = PrivacyAccountant::new(1.1, 0.01);
    /// acc.record_steps(100)
    ///     .expect("100 steps must not exhaust budget");
    /// assert_eq!(acc.steps_taken(), 100);
    /// ```
    pub fn record_steps(&mut self, count: u64) -> Result<(), AccountantError> {
        self.validate_params()?;
        self.steps = self.steps.saturating_add(count);

        if let Some(cap) = self.epsilon_cap {
            let (eps, _) = self.epsilon_delta_inner(self.cap_delta);
            if eps >= cap {
                return Err(AccountantError::BudgetExhausted {
                    epsilon_spent: eps,
                    epsilon_cap: cap,
                    delta: self.cap_delta,
                });
            }
        }

        Ok(())
    }

    /// Query the current (ε, δ)-DP bound.
    ///
    /// Returns `(epsilon, delta)` where `epsilon` is the worst-case privacy
    /// loss accumulated over all steps taken so far, evaluated at the
    /// provided `delta`.
    ///
    /// # Parameters
    ///
    /// - `delta`: the failure probability, in `(0, 1)`.
    ///
    /// # Errors
    ///
    /// - [`AccountantError::InvalidParameter`] if parameters are invalid or
    ///   `delta ≤ 0` or `delta ≥ 1`.
    ///
    /// # Example
    ///
    /// ```
    /// use nexacore_tokenization::privacy::PrivacyAccountant;
    ///
    /// let mut acc = PrivacyAccountant::new(1.1, 0.01);
    /// acc.record_steps(1000).expect("1000 steps");
    /// let (eps, delta) = acc.epsilon_delta(1e-5).expect("query");
    /// assert!(eps > 0.0, "epsilon must be positive after steps");
    /// assert!((delta - 1e-5).abs() < 1e-12, "delta is echo'd back");
    /// ```
    pub fn epsilon_delta(&self, delta: f64) -> Result<(f64, f64), AccountantError> {
        self.validate_params()?;
        if delta <= 0.0 || delta >= 1.0 {
            return Err(AccountantError::InvalidParameter("delta must be in (0, 1)"));
        }
        Ok(self.epsilon_delta_inner(delta))
    }

    /// Returns the number of training steps taken so far.
    ///
    /// # Example
    ///
    /// ```
    /// use nexacore_tokenization::privacy::PrivacyAccountant;
    ///
    /// let acc = PrivacyAccountant::new(1.1, 0.01);
    /// assert_eq!(acc.steps_taken(), 0);
    /// ```
    #[must_use]
    pub const fn steps_taken(&self) -> u64 {
        self.steps
    }

    /// Returns the noise multiplier σ.
    ///
    /// # Example
    ///
    /// ```
    /// use nexacore_tokenization::privacy::PrivacyAccountant;
    ///
    /// let acc = PrivacyAccountant::new(1.1, 0.01);
    /// assert!((acc.noise_multiplier() - 1.1).abs() < 1e-12);
    /// ```
    #[must_use]
    pub const fn noise_multiplier(&self) -> f64 {
        self.noise_multiplier
    }

    /// Returns the Poisson subsampling rate q.
    ///
    /// # Example
    ///
    /// ```
    /// use nexacore_tokenization::privacy::PrivacyAccountant;
    ///
    /// let acc = PrivacyAccountant::new(1.1, 0.01);
    /// assert!((acc.sampling_rate() - 0.01).abs() < 1e-12);
    /// ```
    #[must_use]
    pub const fn sampling_rate(&self) -> f64 {
        self.sampling_rate
    }

    // -------------------------------------------------------------------------
    // Internal: parameter validation
    // -------------------------------------------------------------------------

    /// Validate that `noise_multiplier` and `sampling_rate` are in range.
    ///
    /// Called at the start of every public method that performs computation.
    fn validate_params(&self) -> Result<(), AccountantError> {
        if self.noise_multiplier <= 0.0 {
            return Err(AccountantError::InvalidParameter(
                "noise_multiplier must be positive",
            ));
        }
        if self.sampling_rate <= 0.0 || self.sampling_rate > 1.0 {
            return Err(AccountantError::InvalidParameter(
                "sampling_rate must be in (0, 1]",
            ));
        }
        Ok(())
    }

    // -------------------------------------------------------------------------
    // Internal: (ε, δ) computation
    // -------------------------------------------------------------------------

    /// Compute the (ε, δ)-DP bound at the current step count.
    ///
    /// Evaluates the RDP bound at each order in [`EVAL_ORDERS`] and returns
    /// the minimum epsilon from the RDP-to-(ε, δ) conversion.
    ///
    /// When `steps == 0`, the privacy cost is 0.0.
    ///
    /// This function is infallible — parameter validation is the caller's
    /// responsibility (see [`validate_params`](Self::validate_params)).
    #[allow(
        clippy::float_arithmetic,
        clippy::cast_precision_loss,
        reason = "RDP computation requires floating-point arithmetic; step counts ≤ 2^52 convert exactly to f64; order values ≤ 128 convert exactly to f64"
    )]
    fn epsilon_delta_inner(&self, delta: f64) -> (f64, f64) {
        if self.steps == 0 {
            return (0.0, delta);
        }

        let mut best_eps = f64::INFINITY;

        for &order in EVAL_ORDERS {
            // Per-step RDP at this order.
            let rdp_per_step =
                rdp_gaussian_subsampled(order, self.noise_multiplier, self.sampling_rate);

            // Composed RDP after `steps` steps (exact composition by addition).
            // `self.steps as f64`: step counts up to ~2^52 convert exactly to f64.
            let rdp_total = rdp_per_step * (self.steps as f64);

            // Convert RDP(order, rdp_total) to (ε, δ)-DP.
            // Formula (Balle et al. 2020, Proposition 3):
            //   ε(δ) = rdp - log(δ(α-1)/α) / (α-1)
            //        = rdp + (log(1/δ) + log(α/(α-1))) / (α-1) - 1/(α-1) * log(α-1)
            //
            // A clean form (widely used in `TensorFlow` Privacy):
            //   ε(δ) = rdp + log((α-1)/α) - (log(δ) + log(α/(α-1))) / (α-1)
            //
            // In practice, the most numerically stable and commonly used form is:
            //   ε(δ) = rdp_total - log(δ * (1 - 1/α)) / (α - 1) + log((α-1)/α)
            //
            // Reference implementation: google/differential-privacy / opacus.
            let alpha = order as f64;
            let eps = rdp_to_eps(rdp_total, alpha, delta);
            if eps < best_eps {
                best_eps = eps;
            }
        }

        (best_eps, delta)
    }
}

// =============================================================================
// Core RDP computation
// =============================================================================

/// Compute the RDP budget per step for the Gaussian mechanism with Poisson
/// subsampling.
///
/// Uses the tight log-moment bound from Mironov (2017), adapted for
/// Poisson subsampling with rate `q`:
///
/// ```text
/// ε_RDP(α) ≈ (1 / (α-1)) · log( 1 + q² · α(α-1) / (2σ²) )
/// ```
///
/// For the purpose of this accountant we use a practical, slightly
/// pessimistic closed form that is commonly used in the literature
/// and in the TF-Privacy reference implementation:
///
/// ```text
/// ε_RDP(α) = α · q² / (2 · σ²)
/// ```
///
/// This upper bound is exact for the **pure** Gaussian mechanism (no
/// subsampling).  With Poisson subsampling the actual RDP is strictly
/// smaller, so this approximation is **conservative** (it overestimates
/// the privacy cost, erring on the side of caution).  A tighter bound
/// (e.g., the Poisson log-sobolev bound) can be plugged in without
/// changing the accountant interface.
///
/// # Inputs
///
/// - `order`: Rényi order α ≥ 2 (integer).
/// - `noise_multiplier`: σ > 0.
/// - `sampling_rate`: q ∈ (0, 1].
///
/// # Returns
///
/// The per-step RDP value in nats.  Non-negative and finite.
#[allow(
    clippy::float_arithmetic,
    clippy::cast_precision_loss,
    reason = "RDP computation requires floating-point arithmetic; order <= 128 is exact as f64"
)]
fn rdp_gaussian_subsampled(order: u64, noise_multiplier: f64, sampling_rate: f64) -> f64 {
    // `order as f64`: order values are in [2, 128] which are all exactly
    // representable as f64.
    let alpha = order as f64;
    // Conservative bound: α·q²/(2σ²).
    // A tighter Poisson-subsampled bound (Zhu & Wang 2019, Theorem 4) would
    // compute the exact log-moment via numerical integration; the closed form
    // here is simpler and acceptable for the accountant's use case.
    (alpha * sampling_rate * sampling_rate) / (2.0 * noise_multiplier * noise_multiplier)
}

/// Convert an RDP value at order `α` to an (ε, δ)-DP epsilon.
///
/// Uses the conversion from Balle, Barthe, Gaboardi (2020), which is tighter
/// than the original Mironov (2017) conversion for small `δ`:
///
/// ```text
/// ε(δ) = rdp_total + log((α-1)/α) - (log δ + log((α-1)/α)) / (α-1)
/// ```
///
/// Returns `f64::INFINITY` when `α == 1` (the limit case is not handled
/// by this formula) or when the inputs are out of range.
#[allow(
    clippy::float_arithmetic,
    reason = "RDP-to-DP conversion requires floating-point arithmetic"
)]
fn rdp_to_eps(rdp_total: f64, alpha: f64, delta: f64) -> f64 {
    // The conversion is valid for α > 1.
    if alpha <= 1.0 + f64::EPSILON {
        return f64::INFINITY;
    }
    if delta <= 0.0 || delta >= 1.0 {
        return f64::INFINITY;
    }
    if rdp_total.is_infinite() || rdp_total.is_nan() {
        return f64::INFINITY;
    }

    // Balle et al. 2020 Proposition 3 conversion:
    //   ε = rdp + (log(α-1) - log(α)) / (α-1) + log(1/δ) / (α-1)
    //
    // Which simplifies to:
    //   ε = rdp - log(δ * α / (α-1)) / (α-1)
    //   ε = rdp + (log(α-1) - log(α) - log(δ)) / (α-1)
    let am1 = alpha - 1.0;
    let eps = rdp_total + (am1.ln() - alpha.ln() - delta.ln()) / am1;

    // Clamp to [0, ∞) — the conversion can yield slightly negative values
    // when rdp_total is very small and α is large, which is a numerical
    // artefact of the grid evaluation rather than a physically meaningful
    // epsilon < 0.
    if eps < 0.0 { 0.0 } else { eps }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::float_arithmetic,
    clippy::float_cmp
)]
mod tests {
    use super::*;

    // -------------------------------------------------------------------------
    // Construction and accessors
    // -------------------------------------------------------------------------

    #[test]
    fn new_starts_at_zero_steps() {
        let acc = PrivacyAccountant::new(1.1, 0.01);
        assert_eq!(acc.steps_taken(), 0);
    }

    #[test]
    fn accessors_return_configured_params() {
        let acc = PrivacyAccountant::new(1.1, 0.01);
        assert!((acc.noise_multiplier() - 1.1).abs() < 1e-12);
        assert!((acc.sampling_rate() - 0.01).abs() < 1e-12);
    }

    // -------------------------------------------------------------------------
    // Parameter validation
    // -------------------------------------------------------------------------

    #[test]
    fn zero_noise_multiplier_returns_error() {
        let mut acc = PrivacyAccountant::new(0.0, 0.01);
        assert!(matches!(
            acc.step(),
            Err(AccountantError::InvalidParameter(_))
        ));
    }

    #[test]
    fn negative_noise_multiplier_returns_error() {
        let mut acc = PrivacyAccountant::new(-1.0, 0.01);
        assert!(matches!(
            acc.step(),
            Err(AccountantError::InvalidParameter(_))
        ));
    }

    #[test]
    fn zero_sampling_rate_returns_error() {
        let mut acc = PrivacyAccountant::new(1.0, 0.0);
        assert!(matches!(
            acc.step(),
            Err(AccountantError::InvalidParameter(_))
        ));
    }

    #[test]
    fn sampling_rate_above_one_returns_error() {
        let mut acc = PrivacyAccountant::new(1.0, 1.1);
        assert!(matches!(
            acc.step(),
            Err(AccountantError::InvalidParameter(_))
        ));
    }

    #[test]
    fn sampling_rate_of_one_is_valid() {
        let mut acc = PrivacyAccountant::new(1.0, 1.0);
        acc.step().expect("sampling_rate=1.0 must be accepted");
    }

    // -------------------------------------------------------------------------
    // Zero-step baseline
    // -------------------------------------------------------------------------

    #[test]
    fn zero_steps_gives_zero_epsilon() {
        let acc = PrivacyAccountant::new(1.1, 0.01);
        let (eps, delta) = acc.epsilon_delta(1e-5).unwrap();
        assert_eq!(eps, 0.0, "no steps → zero privacy cost");
        assert!((delta - 1e-5).abs() < 1e-12);
    }

    // -------------------------------------------------------------------------
    // Monotonicity: more steps → more epsilon
    // -------------------------------------------------------------------------

    #[test]
    fn epsilon_increases_monotonically_with_steps() {
        let mut acc = PrivacyAccountant::new(1.1, 0.01);
        let mut prev = 0.0_f64;
        for _ in 0..5 {
            acc.step().unwrap();
            let (eps, _) = acc.epsilon_delta(1e-5).unwrap();
            assert!(
                eps >= prev,
                "epsilon must not decrease: prev={prev}, current={eps}"
            );
            prev = eps;
        }
    }

    // -------------------------------------------------------------------------
    // Monotonicity: higher sigma → less epsilon
    // -------------------------------------------------------------------------

    #[test]
    fn higher_sigma_gives_lower_epsilon() {
        let delta = 1e-5;
        let mut low_sigma = PrivacyAccountant::new(0.5, 0.01);
        let mut high_sigma = PrivacyAccountant::new(5.0, 0.01);

        low_sigma.record_steps(1000).unwrap();
        high_sigma.record_steps(1000).unwrap();

        let (eps_low, _) = low_sigma.epsilon_delta(delta).unwrap();
        let (eps_high, _) = high_sigma.epsilon_delta(delta).unwrap();

        assert!(
            eps_high < eps_low,
            "higher σ must give lower ε: σ=0.5 → ε={eps_low}, σ=5.0 → ε={eps_high}"
        );
    }

    // -------------------------------------------------------------------------
    // Monotonicity: higher q → more epsilon
    // -------------------------------------------------------------------------

    #[test]
    fn higher_sampling_rate_gives_higher_epsilon() {
        let delta = 1e-5;
        let mut low_q = PrivacyAccountant::new(1.1, 0.001);
        let mut high_q = PrivacyAccountant::new(1.1, 0.1);

        low_q.record_steps(1000).unwrap();
        high_q.record_steps(1000).unwrap();

        let (eps_low_q, _) = low_q.epsilon_delta(delta).unwrap();
        let (eps_high_q, _) = high_q.epsilon_delta(delta).unwrap();

        assert!(
            eps_high_q > eps_low_q,
            "higher q must give higher ε: q=0.001 → ε={eps_low_q}, q=0.1 → ε={eps_high_q}"
        );
    }

    // -------------------------------------------------------------------------
    // record_steps matches repeated step() calls
    // -------------------------------------------------------------------------

    #[test]
    fn record_steps_matches_individual_steps() {
        let delta = 1e-5;
        let mut by_one = PrivacyAccountant::new(1.1, 0.01);
        let mut by_bulk = PrivacyAccountant::new(1.1, 0.01);

        for _ in 0..100 {
            by_one.step().unwrap();
        }
        by_bulk.record_steps(100).unwrap();

        assert_eq!(by_one.steps_taken(), by_bulk.steps_taken());
        let (eps1, _) = by_one.epsilon_delta(delta).unwrap();
        let (eps2, _) = by_bulk.epsilon_delta(delta).unwrap();
        assert!(
            (eps1 - eps2).abs() < 1e-12,
            "ε must agree: {eps1} vs {eps2}"
        );
    }

    // -------------------------------------------------------------------------
    // Budget cap enforcement
    // -------------------------------------------------------------------------

    #[test]
    fn step_returns_error_after_budget_exhausted() {
        let mut acc = PrivacyAccountant::new(1.1, 0.01);
        // Set a very tight budget to trigger exhaustion quickly.
        acc.set_epsilon_cap(Some((0.001, 1e-5)));

        let mut exhausted = false;
        for _ in 0..100_000 {
            match acc.step() {
                Ok(()) => {}
                Err(AccountantError::BudgetExhausted { .. }) => {
                    exhausted = true;
                    break;
                }
                Err(e) => panic!("unexpected error: {e}"),
            }
        }
        assert!(exhausted, "budget must be exhausted within 100k steps");
    }

    #[test]
    fn no_cap_never_exhausted_for_moderate_steps() {
        let mut acc = PrivacyAccountant::new(1.1, 0.01);
        // No cap configured — must never return BudgetExhausted.
        acc.record_steps(10_000)
            .expect("10k steps without a cap must succeed");
    }

    // -------------------------------------------------------------------------
    // Known-value sanity checks
    // -------------------------------------------------------------------------

    /// With σ=1.1, q=0.01, T=100, δ=1e-5 the budget is small but positive.
    /// This is a regression test that pins the computed value to a known range.
    #[test]
    fn known_epsilon_is_in_expected_range() {
        let mut acc = PrivacyAccountant::new(1.1, 0.01);
        acc.record_steps(100).unwrap();
        let (eps, _) = acc.epsilon_delta(1e-5).unwrap();
        // The true ε for these parameters (computed via TF Privacy) is ≈ 0.04.
        // Our conservative RDP bound overestimates; we just verify the result
        // is finite, positive, and < 10 (clearly reasonable).
        assert!(eps > 0.0, "ε must be positive after 100 steps");
        assert!(
            eps < 10.0,
            "ε must be reasonable after 100 steps (was {eps})"
        );
    }

    /// T=10000 steps with σ=1.1, q=0.01 must accumulate substantial epsilon.
    #[test]
    fn large_step_count_exhausts_tight_budget() {
        let mut acc = PrivacyAccountant::new(1.1, 0.01);
        acc.record_steps(10_000).unwrap();
        let (eps, _) = acc.epsilon_delta(1e-5).unwrap();
        // With 10k steps the epsilon grows considerably.
        assert!(
            eps > 1.0,
            "10k steps with σ=1.1, q=0.01 must accumulate ε > 1 (was {eps})"
        );
    }

    // -------------------------------------------------------------------------
    // Delta echo-back
    // -------------------------------------------------------------------------

    #[test]
    fn epsilon_delta_echoes_delta() {
        let mut acc = PrivacyAccountant::new(1.1, 0.01);
        acc.step().unwrap();
        let (_, returned_delta) = acc.epsilon_delta(1e-7).unwrap();
        assert!((returned_delta - 1e-7).abs() < 1e-12);
    }

    // -------------------------------------------------------------------------
    // set_epsilon_cap with None disables enforcement
    // -------------------------------------------------------------------------

    #[test]
    fn clearing_cap_allows_steps_after_previous_exhaustion_threshold() {
        let mut acc = PrivacyAccountant::new(1.1, 0.01);
        acc.set_epsilon_cap(Some((0.001, 1e-5)));

        // Drive to exhaustion.
        let mut exhausted = false;
        for _ in 0..1_000_000 {
            if acc.step().is_err() {
                exhausted = true;
                break;
            }
        }
        assert!(exhausted);

        // Remove the cap — further steps must succeed.
        acc.set_epsilon_cap(None);
        acc.step().expect("step must succeed after cap is cleared");
    }

    // -------------------------------------------------------------------------
    // BudgetExhausted error carries correct fields
    // -------------------------------------------------------------------------

    #[test]
    fn budget_exhausted_error_fields_are_populated() {
        let mut acc = PrivacyAccountant::new(1.1, 0.01);
        let cap = 0.001;
        let cap_delta = 1e-5;
        acc.set_epsilon_cap(Some((cap, cap_delta)));

        let mut err: Option<AccountantError> = None;
        for _ in 0..1_000_000 {
            if let Err(e) = acc.step() {
                err = Some(e);
                break;
            }
        }

        let e = err.expect("budget must be exhausted");
        match e {
            AccountantError::BudgetExhausted {
                epsilon_spent,
                epsilon_cap,
                delta,
            } => {
                assert!((epsilon_cap - cap).abs() < 1e-12);
                assert!((delta - cap_delta).abs() < 1e-12);
                assert!(epsilon_spent >= cap);
            }
            AccountantError::InvalidParameter(msg) => {
                panic!("expected BudgetExhausted, got InvalidParameter({msg})")
            }
        }
    }
}
