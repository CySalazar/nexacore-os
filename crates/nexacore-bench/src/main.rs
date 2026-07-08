//! `nexacore-bench-gate` — the CI regression-gate CLI (WS13-07.7/.8).
//!
//! Usage:
//!
//! ```text
//! nexacore-bench-gate <current.json> <baseline.json> <thresholds.json>
//! ```
//!
//! Reads the current benchmark run, the committed baseline, and the regression
//! thresholds, runs [`nexacore_bench::evaluate`], prints a per-metric table, and
//! exits `0` (gate passed) or `1` (a metric regressed beyond budget) so a CI job
//! fails on a performance regression (WS13-07.8/.10).

// This is a host CLI: stdout (the gate table / verdict) and stderr (usage /
// errors) ARE its interface, so the workspace's no-stray-prints policy is
// deliberately relaxed here.
#![allow(clippy::disallowed_macros)]

use std::process::ExitCode;

use nexacore_bench::{BenchReport, Thresholds, evaluate};

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();
    let [_, current, baseline, thresholds] = args.as_slice() else {
        eprintln!("usage: nexacore-bench-gate <current.json> <baseline.json> <thresholds.json>");
        return ExitCode::from(2);
    };

    let current = match read_report(current) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("error: cannot read current report {current}: {e}");
            return ExitCode::from(2);
        }
    };
    let baseline = match read_report(baseline) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("error: cannot read baseline {baseline}: {e}");
            return ExitCode::from(2);
        }
    };
    let thresholds = match read_thresholds(thresholds) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("error: cannot read thresholds {thresholds}: {e}");
            return ExitCode::from(2);
        }
    };

    let report = evaluate(&current, &baseline, &thresholds);
    println!(
        "perf gate: baseline={} current={}",
        baseline.commit, current.commit
    );
    for v in &report.verdicts {
        let status = if v.missing {
            "MISSING"
        } else if v.regressed {
            "REGRESSED"
        } else {
            "ok"
        };
        println!(
            "  {status:>9}  {name:<20} baseline={base:>12.3} current={cur:>12.3} \
             reg={reg}\u{2030} budget={budget}\u{2030}",
            name = v.name,
            base = v.baseline,
            cur = v.current,
            reg = v.regression_permille,
            budget = v.allowed_permille,
        );
    }

    if report.passed {
        println!("perf gate: PASS");
        ExitCode::SUCCESS
    } else {
        println!(
            "perf gate: FAIL ({} regression(s))",
            report.regressions().len()
        );
        ExitCode::FAILURE
    }
}

fn read_report(path: &str) -> Result<BenchReport, String> {
    let json = std::fs::read_to_string(path).map_err(|e| e.to_string())?;
    BenchReport::from_json(&json).map_err(|e| e.to_string())
}

fn read_thresholds(path: &str) -> Result<Thresholds, String> {
    let json = std::fs::read_to_string(path).map_err(|e| e.to_string())?;
    Thresholds::from_json(&json).map_err(|e| e.to_string())
}
