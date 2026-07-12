//! Build-time metadata injector for the System Info window.
//!
//! Emits a handful of `cargo:rustc-env=…` lines so the desktop shell can
//! surface the originating git commit, branch, and build timestamp via
//! `env!()` macros — no runtime dependency on git or std on the bare-metal
//! side. Ports the same pattern already used by `crates/nexacore-kernel/build.rs`
//! for its bare-metal "Build Info" debug panel.
//!
//! All values fall back to a stable `"unknown"` placeholder so that
//! tarball / out-of-tree builds (no `.git/`) still compile cleanly.
//!
//! Rebuilds are pinned to `HEAD` + the indexed/working tree so a git
//! `commit`/`checkout` invalidates the embedded metadata.

// Build scripts run on the host with std — the workspace lints (intended
// for the no_std desktop-shell binary) are not load-bearing here.
#![allow(
    clippy::integer_division,
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_sign_loss,
    clippy::missing_docs_in_private_items,
    clippy::similar_names,
    clippy::disallowed_macros,
    clippy::disallowed_methods,
    clippy::many_single_char_names
)]

use std::{
    process::Command,
    time::{SystemTime, UNIX_EPOCH},
};

fn main() {
    // Re-run when HEAD or the index move — see `omni-kernel/build.rs` for the
    // detailed rationale (same three watches, same crate depth under
    // `crates/`, so the same relative path resolves).
    println!("cargo:rerun-if-changed=../../.git/HEAD");
    println!("cargo:rerun-if-changed=../../.git/logs/HEAD");
    println!("cargo:rerun-if-changed=../../.git/index");
    // The `--remote-build` deploy path builds from a tarball with no `.git/`
    // (224 MiB, intentionally excluded from the sync), so `git` here would
    // resolve to "unknown". `deploy-proxmox.sh` instead passes the *local*
    // branch/hash through these env vars; prefer them when set.
    println!("cargo:rerun-if-env-changed=NEXACORE_GIT_HASH");
    println!("cargo:rerun-if-env-changed=NEXACORE_GIT_BRANCH");
    // On `--remote-build` the target dir is cached across deploys and the
    // `.git/` watches above don't exist in the tarball, so `SystemTime::now()`
    // below can freeze at a *previous* build's date. `deploy-proxmox.sh` passes
    // a fresh `NEXACORE_BUILD_DATE` on every run; because its value changes each
    // time, this watch forces build.rs to re-run and re-embed a current date.
    println!("cargo:rerun-if-env-changed=NEXACORE_BUILD_DATE");

    let git_hash = env_nonempty("NEXACORE_GIT_HASH")
        .or_else(|| run_git(&["rev-parse", "--short=7", "HEAD"]))
        .unwrap_or_else(|| "unknown".into());
    let git_branch = env_nonempty("NEXACORE_GIT_BRANCH")
        .or_else(|| run_git(&["rev-parse", "--abbrev-ref", "HEAD"]))
        .unwrap_or_else(|| "unknown".into());
    // The injected hash already carries any dirtiness the caller chose to
    // encode; only append `+dirty` when we resolved the hash from a live repo.
    let git_dirty = if env_nonempty("NEXACORE_GIT_HASH").is_some() {
        ""
    } else {
        match run_git(&["status", "--porcelain"]) {
            Some(s) if s.is_empty() => "",
            Some(_) => "+dirty",
            None => "",
        }
    };
    let git_desc = format!("{git_hash}{git_dirty}");

    // Prefer an injected build date (the `--remote-build` deploy path passes a
    // fresh one so the cached target dir can't serve a stale timestamp); fall
    // back to the host wall clock for ordinary local builds. The env value may
    // be either a preformatted `YYYY-MM-DD HH:MM UTC` string or a raw unix-secs
    // integer — accept both.
    let build_date = env_nonempty("NEXACORE_BUILD_DATE")
        .map(|v| match v.parse::<u64>() {
            Ok(secs) => format_utc_date(secs),
            Err(_) => v,
        })
        .unwrap_or_else(|| {
            format_utc_date(
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .map(|d| d.as_secs())
                    .unwrap_or(0),
            )
        });

    let rustc_version = Command::new("rustc")
        .arg("-V")
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|| "unknown".into());

    println!("cargo:rustc-env=NEXACORE_GIT_HASH={git_desc}");
    println!("cargo:rustc-env=NEXACORE_GIT_BRANCH={git_branch}");
    println!("cargo:rustc-env=NEXACORE_BUILD_DATE={build_date}");
    println!("cargo:rustc-env=NEXACORE_RUSTC_VERSION={rustc_version}");
}

/// Returns the value of environment variable `key` if it is set and not empty
/// (after trimming), else `None`.
fn env_nonempty(key: &str) -> Option<String> {
    std::env::var(key).ok().and_then(|v| {
        let t = v.trim();
        if t.is_empty() {
            None
        } else {
            Some(t.to_string())
        }
    })
}

fn run_git(args: &[&str]) -> Option<String> {
    let out = Command::new("git").args(args).output().ok()?;
    if !out.status.success() {
        return None;
    }
    let s = String::from_utf8(out.stdout).ok()?;
    Some(s.trim().to_string())
}

fn format_utc_date(unix_secs: u64) -> String {
    const SECS_PER_DAY: u64 = 86_400;
    let days = unix_secs / SECS_PER_DAY;
    let secs_today = unix_secs % SECS_PER_DAY;
    let h = secs_today / 3600;
    let m = (secs_today % 3600) / 60;

    // Civil-from-days, Howard Hinnant's algorithm.
    let z = days as i64 + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m_civ = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = if m_civ <= 2 { y + 1 } else { y };

    format!("{year:04}-{m_civ:02}-{d:02} {h:02}:{m:02} UTC")
}
