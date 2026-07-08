//! # `nexacore-bench`
//!
//! Performance baseline schema + regression-gate comparator (WS13-07).
//!
//! The OS benchmarks — boot time, IPC throughput, inference tok/s, filesystem
//! IOPS — are measured in QEMU / on the rig (WS13-07.1–.4) and emit a
//! [`BenchReport`] in this schema. The **gate** here is pure, deterministic, and
//! host-testable: given the current report, a committed [`BenchReport`] baseline
//! (WS13-07.5) and per-metric [`Thresholds`] (WS13-07.6), [`evaluate`] decides
//! whether any metric regressed beyond its threshold (WS13-07.8) — the same
//! check the CI job runs (WS13-07.7) and the "deliberate slowdown" test trips
//! (WS13-07.10).

// Performance ratios are inherently fractional; this is a host CLI tool (not
// kernel code), so floating point and float comparisons are appropriate here.
#![allow(clippy::float_arithmetic, clippy::cast_precision_loss)]
#![allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]

use serde::{Deserialize, Serialize};

/// Whether a smaller or larger value is better for a metric.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Direction {
    /// Lower is better (latency, boot time, IOPS-latency).
    LowerIsBetter,
    /// Higher is better (throughput, tok/s, IOPS).
    HigherIsBetter,
}

/// One measured performance metric.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Metric {
    /// Stable metric id (e.g. `"boot_time_ms"`, `"inference_tok_s"`).
    pub name: String,
    /// The measured value.
    pub value: f64,
    /// Human-readable unit (e.g. `"ms"`, `"tok/s"`, `"iops"`).
    pub unit: String,
    /// Which direction counts as an improvement.
    pub direction: Direction,
}

/// A full benchmark run: a set of metrics tagged with the commit they measured.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct BenchReport {
    /// The commit (or label) the run measured.
    pub commit: String,
    /// The measured metrics.
    pub metrics: Vec<Metric>,
}

impl BenchReport {
    /// Find a metric by name.
    #[must_use]
    pub fn metric(&self, name: &str) -> Option<&Metric> {
        self.metrics.iter().find(|m| m.name == name)
    }

    /// Parse a report from JSON.
    ///
    /// # Errors
    ///
    /// Propagates [`serde_json::Error`] on malformed input.
    pub fn from_json(json: &str) -> Result<Self, serde_json::Error> {
        serde_json::from_str(json)
    }

    /// Serialize the report to pretty JSON.
    ///
    /// # Errors
    ///
    /// Propagates [`serde_json::Error`].
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(self)
    }
}

/// Per-metric regression threshold override.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Threshold {
    /// The metric id this override applies to.
    pub metric: String,
    /// Max allowed regression for this metric, in permille (`50` = 5 %).
    pub max_regression_permille: u32,
}

/// The regression budget: a default plus per-metric overrides (WS13-07.6).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Thresholds {
    /// Max allowed regression for any metric without an override, in permille.
    pub default_max_regression_permille: u32,
    /// Per-metric overrides.
    #[serde(default)]
    pub per_metric: Vec<Threshold>,
}

impl Thresholds {
    /// The allowed regression budget (permille) for `metric`.
    #[must_use]
    pub fn allowed_for(&self, metric: &str) -> u32 {
        self.per_metric
            .iter()
            .find(|t| t.metric == metric)
            .map_or(self.default_max_regression_permille, |t| {
                t.max_regression_permille
            })
    }

    /// Parse thresholds from JSON.
    ///
    /// # Errors
    ///
    /// Propagates [`serde_json::Error`].
    pub fn from_json(json: &str) -> Result<Self, serde_json::Error> {
        serde_json::from_str(json)
    }
}

/// The gate's verdict for one metric.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct MetricVerdict {
    /// Metric id.
    pub name: String,
    /// Baseline value.
    pub baseline: f64,
    /// Current value.
    pub current: f64,
    /// Regression in permille (positive = worse than baseline, negative =
    /// improvement). Saturated to the integer permille.
    pub regression_permille: i64,
    /// The allowed regression budget (permille) for this metric.
    pub allowed_permille: u32,
    /// Whether this metric regressed beyond its budget.
    pub regressed: bool,
    /// Set when the current run is missing this baseline metric (treated as a
    /// regression — the gate cannot confirm the metric held).
    pub missing: bool,
}

/// The overall gate report (WS13-07.8).
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct GateReport {
    /// Per-metric verdicts (one per baseline metric).
    pub verdicts: Vec<MetricVerdict>,
    /// `true` if no metric regressed beyond its budget.
    pub passed: bool,
}

impl GateReport {
    /// The metrics that regressed beyond budget (or went missing).
    #[must_use]
    pub fn regressions(&self) -> Vec<&MetricVerdict> {
        self.verdicts.iter().filter(|v| v.regressed).collect()
    }
}

/// Compute the regression of `current` versus `baseline` in permille, where a
/// positive result means *worse* (accounting for the metric's [`Direction`]).
fn regression_permille(baseline: f64, current: f64, direction: Direction) -> i64 {
    if baseline == 0.0 {
        // A zero baseline can't be ratioed; any positive current is "worse".
        return if current > 0.0 { i64::MAX } else { 0 };
    }
    // Fraction by which the value moved in the *worse* direction.
    let worse_delta = match direction {
        Direction::LowerIsBetter => current - baseline, // higher = worse
        Direction::HigherIsBetter => baseline - current, // lower = worse
    };
    (worse_delta / baseline * 1000.0).round() as i64
}

/// Evaluate the current run against the baseline under the thresholds
/// (WS13-07.8). The gate passes iff no baseline metric regressed beyond its
/// budget and none went missing.
#[must_use]
pub fn evaluate(
    current: &BenchReport,
    baseline: &BenchReport,
    thresholds: &Thresholds,
) -> GateReport {
    let mut verdicts = Vec::with_capacity(baseline.metrics.len());
    let mut passed = true;
    for base in &baseline.metrics {
        let allowed = thresholds.allowed_for(&base.name);
        if let Some(cur) = current.metric(&base.name) {
            let reg = regression_permille(base.value, cur.value, base.direction);
            let regressed = reg > i64::from(allowed);
            if regressed {
                passed = false;
            }
            verdicts.push(MetricVerdict {
                name: base.name.clone(),
                baseline: base.value,
                current: cur.value,
                regression_permille: reg,
                allowed_permille: allowed,
                regressed,
                missing: false,
            });
        } else {
            // Missing metric: cannot confirm it held → fail closed.
            passed = false;
            verdicts.push(MetricVerdict {
                name: base.name.clone(),
                baseline: base.value,
                current: 0.0,
                regression_permille: i64::MAX,
                allowed_permille: allowed,
                regressed: true,
                missing: true,
            });
        }
    }
    GateReport { verdicts, passed }
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::float_cmp,
        clippy::indexing_slicing,
        clippy::redundant_clone,
        clippy::unwrap_used
    )]
    use super::*;

    fn report(values: &[(&str, f64, Direction)]) -> BenchReport {
        BenchReport {
            commit: "test".into(),
            metrics: values
                .iter()
                .map(|(n, v, d)| Metric {
                    name: (*n).into(),
                    value: *v,
                    unit: "u".into(),
                    direction: *d,
                })
                .collect(),
        }
    }

    fn thresholds(default: u32) -> Thresholds {
        Thresholds {
            default_max_regression_permille: default,
            per_metric: Vec::new(),
        }
    }

    #[test]
    fn no_change_passes() {
        let base = report(&[("boot_ms", 1000.0, Direction::LowerIsBetter)]);
        let cur = base.clone();
        let g = evaluate(&cur, &base, &thresholds(50));
        assert!(g.passed);
        assert_eq!(g.verdicts[0].regression_permille, 0);
    }

    #[test]
    fn improvement_is_negative_regression_and_passes() {
        let base = report(&[("tok_s", 100.0, Direction::HigherIsBetter)]);
        let cur = report(&[("tok_s", 120.0, Direction::HigherIsBetter)]);
        let g = evaluate(&cur, &base, &thresholds(50));
        assert!(g.passed);
        assert_eq!(g.verdicts[0].regression_permille, -200); // 20% better
    }

    #[test]
    fn deliberate_slowdown_trips_the_gate() {
        // WS13-07.10 — boot time 10% slower with a 5% budget must fail.
        let base = report(&[("boot_ms", 1000.0, Direction::LowerIsBetter)]);
        let cur = report(&[("boot_ms", 1100.0, Direction::LowerIsBetter)]);
        let g = evaluate(&cur, &base, &thresholds(50)); // 50‰ = 5%
        assert!(!g.passed);
        assert_eq!(g.verdicts[0].regression_permille, 100); // 10%
        assert!(g.verdicts[0].regressed);
        assert_eq!(g.regressions().len(), 1);
    }

    #[test]
    fn throughput_drop_trips_the_gate() {
        // tok/s dropping 15% with a 10% budget fails.
        let base = report(&[("tok_s", 200.0, Direction::HigherIsBetter)]);
        let cur = report(&[("tok_s", 170.0, Direction::HigherIsBetter)]);
        let g = evaluate(&cur, &base, &thresholds(100));
        assert!(!g.passed);
        assert_eq!(g.verdicts[0].regression_permille, 150);
    }

    #[test]
    fn within_budget_passes() {
        // 3% slower with a 5% budget passes.
        let base = report(&[("ipc_mb_s", 1000.0, Direction::HigherIsBetter)]);
        let cur = report(&[("ipc_mb_s", 970.0, Direction::HigherIsBetter)]);
        let g = evaluate(&cur, &base, &thresholds(50));
        assert!(g.passed);
        assert_eq!(g.verdicts[0].regression_permille, 30);
    }

    #[test]
    fn per_metric_override_applies() {
        let base = report(&[("flaky", 100.0, Direction::HigherIsBetter)]);
        let cur = report(&[("flaky", 80.0, Direction::HigherIsBetter)]); // 20% worse
        let mut t = thresholds(50); // default 5% would fail
        t.per_metric.push(Threshold {
            metric: "flaky".into(),
            max_regression_permille: 250, // 25% budget → passes
        });
        assert!(evaluate(&cur, &base, &t).passed);
    }

    #[test]
    fn missing_metric_fails_closed() {
        let base = report(&[("boot_ms", 1000.0, Direction::LowerIsBetter)]);
        let cur = report(&[("other", 1.0, Direction::LowerIsBetter)]);
        let g = evaluate(&cur, &base, &thresholds(50));
        assert!(!g.passed);
        assert!(g.verdicts[0].missing);
    }

    #[test]
    fn json_round_trips() {
        let base = report(&[("boot_ms", 1234.0, Direction::LowerIsBetter)]);
        let json = base.to_json().unwrap();
        let back = BenchReport::from_json(&json).unwrap();
        assert_eq!(back, base);
    }
}
