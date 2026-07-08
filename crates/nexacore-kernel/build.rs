//! Build-time metadata injector for the desktop "Build Info" panel.
//!
//! Emits a handful of `cargo:rustc-env=…` lines so the kernel can surface
//! the originating git commit, branch, and build timestamp via `env!()`
//! macros — no runtime dependency on git or std on the bare-metal side.
//!
//! All values fall back to a stable `"unknown"` placeholder so that
//! tarball / out-of-tree builds (no `.git/`) still compile cleanly.
//!
//! Rebuilds are pinned to `HEAD` + the indexed/working tree so a git
//! `commit`/`checkout` invalidates the embedded metadata.

// Build scripts run on the host with std — the workspace lints (intended
// for the no_std kernel) are not load-bearing here.
#![allow(
    clippy::integer_division,
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_sign_loss,
    clippy::missing_docs_in_private_items,
    clippy::similar_names,
    // build.rs talks to Cargo via `cargo:` lines on stdout — `println!`
    // IS the protocol. The workspace `disallowed_macros` /
    // `disallowed_methods` lints target runtime kernel code, not host
    // build scripts.
    clippy::disallowed_macros,
    clippy::disallowed_methods,
    clippy::many_single_char_names
)]

use std::{
    process::Command,
    time::{SystemTime, UNIX_EPOCH},
};

fn main() {
    // Re-run when the HEAD or the index move (covers `git commit`, `checkout`,
    // and rebases).
    //
    // - `.git/HEAD` itself only contains `ref: refs/heads/<branch>` and does
    //   NOT change mtime on `git commit` to the same branch (only on branch
    //   switches). Watching it alone leaks the wrong commit hash into the
    //   embedded `NEXACORE_GIT_HASH` when the same shell rebuilds after a
    //   same-branch commit — observed 2026-05-22 P6.7.9-pre.8.
    // - `.git/logs/HEAD` is the HEAD reflog: an append-only file that gets a
    //   fresh trailing record on EVERY HEAD-affecting operation (commit,
    //   checkout, reset, merge, amend). Its mtime is therefore the reliable
    //   "did HEAD move?" signal — at the cost of one extra newline of churn
    //   per commit, which is fine for a build-script rerun trigger.
    // - `.git/index` covers staging-area changes (dirty-flag refresh).
    //
    // The `.git/HEAD` watch is retained so a `git checkout <branch>` still
    // forces a rerun even on repos where the reflog is disabled
    // (`core.logAllRefUpdates = false`, rare).
    println!("cargo:rerun-if-changed=../../.git/HEAD");
    println!("cargo:rerun-if-changed=../../.git/logs/HEAD");
    println!("cargo:rerun-if-changed=../../.git/index");

    let git_hash = run_git(&["rev-parse", "--short=7", "HEAD"]).unwrap_or_else(|| "unknown".into());
    let git_branch =
        run_git(&["rev-parse", "--abbrev-ref", "HEAD"]).unwrap_or_else(|| "unknown".into());
    let git_dirty = match run_git(&["status", "--porcelain"]) {
        Some(s) if s.is_empty() => "",
        Some(_) => "+dirty",
        None => "",
    };
    let git_desc = format!("{git_hash}{git_dirty}");

    // UTC unix timestamp → "YYYY-MM-DD HH:MM" via a tiny local impl (avoid
    // pulling chrono as a build dep for ~30 lines of arithmetic).
    let build_date = format_utc_date(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0),
    );

    println!("cargo:rustc-env=NEXACORE_GIT_HASH={git_desc}");
    println!("cargo:rustc-env=NEXACORE_GIT_BRANCH={git_branch}");
    println!("cargo:rustc-env=NEXACORE_BUILD_DATE={build_date}");
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
