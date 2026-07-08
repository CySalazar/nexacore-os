//! Spring-physics animation engine for compositor transitions (WS7-01.9).
//!
//! Window snaps, panel slides, sheet presentations and live-resize tracking are
//! driven by critically- (or near-critically-) damped springs — the brand DNA
//! forbids bouncy motion that "suggests velocity" (WS7-00 §7). A [`Spring`]
//! mirrors the WS7-00 `tokens::Spring` (stiffness / damping / mass) by value;
//! [`SpringState`] integrates one scalar toward a target.
//!
//! Integration is semi-implicit (symplectic) Euler — stable for the stiff,
//! well-damped springs the HIG uses, and cheap enough to step per frame. Pure
//! `f32` math via `libm`; `no_std`.

// Physics is inherently floating-point; `libm` keeps it `no_std`.
#![allow(
    clippy::float_arithmetic,
    clippy::cast_precision_loss,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss
)]

/// Maximum integration sub-step (1 ms): a long frame is split into steps no
/// larger than this so stiff springs stay numerically stable.
const MAX_SUBSTEP_S: f32 = 0.001;

/// Spring parameters (mirrors WS7-00 `tokens::Spring`): higher stiffness settles
/// faster, higher damping reduces oscillation, mass scales inertia.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Spring {
    /// Stiffness `k` (higher = faster).
    pub stiffness: f32,
    /// Damping `c` (>= critical → no overshoot).
    pub damping: f32,
    /// Mass `m`.
    pub mass: f32,
}

impl Spring {
    /// Build a spring; non-finite or non-positive `stiffness`/`mass` are floored
    /// to small positive values so integration stays well-defined.
    #[must_use]
    pub fn new(stiffness: f32, damping: f32, mass: f32) -> Self {
        Self {
            stiffness: if stiffness.is_finite() && stiffness > 0.0 {
                stiffness
            } else {
                1.0
            },
            damping: if damping.is_finite() && damping >= 0.0 {
                damping
            } else {
                0.0
            },
            mass: if mass.is_finite() && mass > 0.0 {
                mass
            } else {
                1.0
            },
        }
    }

    /// A critically-damped spring (damping ratio exactly `1.0`): the fastest
    /// settle with **no overshoot** — `c = 2·√(k·m)`.
    #[must_use]
    pub fn critically_damped(stiffness: f32, mass: f32) -> Self {
        let s = if stiffness.is_finite() && stiffness > 0.0 {
            stiffness
        } else {
            1.0
        };
        let m = if mass.is_finite() && mass > 0.0 {
            mass
        } else {
            1.0
        };
        Self {
            stiffness: s,
            damping: 2.0 * libm::sqrtf(s * m),
            mass: m,
        }
    }

    /// Damping ratio `ζ = c / (2·√(k·m))`. `< 1` underdamped (overshoots),
    /// `== 1` critical, `> 1` overdamped.
    #[must_use]
    pub fn damping_ratio(&self) -> f32 {
        let denom = 2.0 * libm::sqrtf(self.stiffness * self.mass);
        if denom > 0.0 {
            self.damping / denom
        } else {
            0.0
        }
    }
}

/// One scalar value integrating toward a target under a [`Spring`].
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct SpringState {
    /// Current value.
    pub value: f32,
    /// Current velocity.
    pub velocity: f32,
    /// Target the spring pulls toward.
    pub target: f32,
}

impl SpringState {
    /// Start at rest at `value`, with `target = value`.
    #[must_use]
    pub const fn at(value: f32) -> Self {
        Self {
            value,
            velocity: 0.0,
            target: value,
        }
    }

    /// Retarget without disturbing the current value/velocity (the spring will
    /// chase the new target from wherever it is — smooth interruption).
    pub fn set_target(&mut self, target: f32) {
        if target.is_finite() {
            self.target = target;
        }
    }

    /// Advance the simulation by `dt` seconds under `spring` (semi-implicit
    /// Euler). Large `dt` is sub-stepped at ~1 kHz so stiff springs stay stable.
    pub fn step(&mut self, spring: Spring, dt: f32) {
        if !dt.is_finite() || dt <= 0.0 {
            return;
        }
        let steps = libm::ceilf(dt / MAX_SUBSTEP_S) as u32;
        let steps = steps.clamp(1, 1024);
        let h = dt / steps as f32;
        for _ in 0..steps {
            let force =
                -spring.stiffness * (self.value - self.target) - spring.damping * self.velocity;
            let accel = force / spring.mass;
            self.velocity += accel * h; // velocity first (semi-implicit)
            self.value += self.velocity * h;
        }
    }

    /// `true` once the value is within `eps` of the target and nearly at rest
    /// (`|velocity| < eps_vel`). When settled, the compositor snaps the value to
    /// the target and stops animating (saving frames via [`crate::present`]).
    #[must_use]
    pub fn settled(&self, eps: f32, eps_vel: f32) -> bool {
        libm::fabsf(self.value - self.target) <= eps && libm::fabsf(self.velocity) <= eps_vel
    }

    /// Snap exactly to the target and zero the velocity (end-of-animation).
    pub fn snap_to_target(&mut self) {
        self.value = self.target;
        self.velocity = 0.0;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn critically_damped_has_unit_ratio() {
        let s = Spring::critically_damped(200.0, 1.0);
        let r = s.damping_ratio();
        assert!((r - 1.0).abs() < 1e-3, "ratio {r}");
    }

    #[test]
    fn spring_new_floors_bad_inputs() {
        let s = Spring::new(f32::NAN, -5.0, 0.0);
        assert!(s.stiffness > 0.0 && s.damping >= 0.0 && s.mass > 0.0);
    }

    #[test]
    fn critically_damped_converges_without_overshoot() {
        let spring = Spring::critically_damped(200.0, 1.0);
        let mut st = SpringState::at(0.0);
        st.set_target(1.0);
        let mut max_value = 0.0f32;
        for _ in 0..600 {
            st.step(spring, 1.0 / 120.0);
            if st.value > max_value {
                max_value = st.value;
            }
        }
        // Reached the target…
        assert!(
            st.settled(1e-3, 1e-3),
            "value {} vel {}",
            st.value,
            st.velocity
        );
        // …and never overshot beyond a negligible tolerance (no bounce).
        assert!(max_value <= 1.0 + 1e-3, "overshoot to {max_value}");
    }

    #[test]
    fn token_like_spring_settles_to_target() {
        // The WS7-00 spring-default (ζ ≈ 0.92): well-damped, settles cleanly.
        let spring = Spring::new(200.0, 26.0, 1.0);
        assert!(spring.damping_ratio() > 0.9);
        let mut st = SpringState::at(100.0);
        st.set_target(540.0);
        for _ in 0..480 {
            st.step(spring, 1.0 / 120.0);
        }
        assert!((st.value - 540.0).abs() < 1.0, "settled at {}", st.value);
    }

    #[test]
    fn retarget_midflight_is_smooth() {
        let spring = Spring::critically_damped(180.0, 1.0);
        let mut st = SpringState::at(0.0);
        st.set_target(1.0);
        for _ in 0..30 {
            st.step(spring, 1.0 / 120.0);
        }
        let mid = st.value;
        assert!(mid > 0.0 && mid < 1.0, "in flight at {mid}");
        // Retarget back toward 0 — value continues from where it was.
        st.set_target(0.0);
        for _ in 0..600 {
            st.step(spring, 1.0 / 120.0);
        }
        assert!(st.settled(1e-3, 1e-3) && st.value.abs() < 1e-3);
    }

    #[test]
    fn zero_or_negative_dt_is_noop() {
        let spring = Spring::critically_damped(200.0, 1.0);
        let mut st = SpringState::at(0.0);
        st.set_target(1.0);
        let before = st;
        st.step(spring, 0.0);
        st.step(spring, -1.0);
        assert_eq!(st, before);
    }

    #[test]
    fn snap_to_target_ends_motion() {
        let mut st = SpringState::at(0.0);
        st.set_target(42.0);
        st.snap_to_target();
        assert!(st.settled(0.0, 0.0));
        assert!((st.value - 42.0).abs() < f32::EPSILON);
    }
}
