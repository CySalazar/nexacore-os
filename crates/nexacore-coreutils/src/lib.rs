//! # `nexacore-coreutils`
//!
//! Implementations of the classic POSIX/GNU coreutils (workstream WS8-10).
//!
//! The crate has two families of utilities:
//!
//! - **Text-stream** utilities work on in-memory text: a `&str` (or a slice of
//!   lines) in, an options struct parsed from Linux-style flags, a
//!   `String`/`Vec<String>` out. They need no filesystem at all.
//! - **Filesystem-backed** utilities work over the [`fs::FileSystem`] seam — an
//!   abstraction of the operations `ls`, `cp`, `mkdir`, `tree`, … need. On
//!   hardware that seam bridges to the kernel VFS; host tests drive the
//!   in-memory [`fs::MemFs`] double. Paths are pure strings handled by [`path`].
//!
//! ## Modules
//!
//! | Module | Utility | Subtask |
//! |--------|---------|---------|
//! | [`sort`]  | `sort` — lexical / numeric / reverse / unique | WS8-10.5 |
//! | [`uniq`]  | `uniq` — adjacent dedup, count, only-dup, only-unique | WS8-10.5 |
//! | [`cut`]   | `cut` — field (`-f`/`-d`) and char (`-c`) selection | WS8-10.5 |
//! | [`tr`]    | `tr` — translate / delete / squeeze character sets | WS8-10.5 |
//! | [`diff`]  | `diff` — line diff via LCS, change-list output | WS8-10.5 |
//! | [`xargs`] | `xargs` — split input into argv batches (`-n`/`-d`) | WS8-10.5 |
//! | [`sed`]   | `sed`-lite — `s/pat/rep/[g]` with line addressing | WS8-10.7 |
//! | [`awk`]   | `awk`-lite — `$N` / `NR` / `NF` / `print`, `-F` | WS8-10.7 |
//! | [`grep`]  | `grep` — literal line match, `-i`/`-v`/`-n`/`-c`/`-w` | WS8-10.4 |
//! | [`head`]  | `head` — first `-n` lines / `-c` bytes, multi-input | WS8-10.4 |
//! | [`tail`]  | `tail` — last `-n` lines / `-c` bytes, multi-input | WS8-10.4 |
//! | [`wc`]    | `wc` — `-l`/`-w`/`-c`/`-m` counts with total row | WS8-10.4 |
//! | [`find`]  | `find` — subtree walk, `-name`/`-type`/`-maxdepth` | WS8-10.4 |
//! | [`pager`] | `less`/`more` — viewport state machine | WS8-10.6 |
//! | [`path`]    | path-string helper — normalize / join / split | WS8-10.1 |
//! | [`fs`]      | filesystem seam + `MemFs` in-memory double | WS8-10.1 |
//! | [`ls`]      | `ls` — `-l` / `-a` / `-1` directory listing | WS8-10.1 |
//! | [`nav`]     | `cd` / `pwd` — current-working-directory model | WS8-10.1 |
//! | [`cat`]     | `cat` — concatenate file contents | WS8-10.1 |
//! | [`fileops`] | `cp` / `mv` / `rm` — copy / move / remove | WS8-10.1 |
//! | [`dirops`]  | `mkdir` / `rmdir` / `touch` / `ln` | WS8-10.2 |
//! | [`stat`]    | `stat` — format entry metadata | WS8-10.2 |
//! | [`tree`]    | `tree` — recursive indented listing | WS8-10.2 |
//! | [`du`]      | `du` — recursive disk usage over the FS seam | WS8-10.3 |
//! | [`df`]      | `df` — filesystem usage report over a statfs seam | WS8-10.3 |
//! | [`mount`]   | `mount`/`umount` — in-memory mount-table model | WS8-10.3 |
//! | [`env`]      | `env` / `export` — environment model + `NAME=val cmd` | WS8-10.9 |
//! | [`which`]    | `which` — locate an executable on a `PATH` | WS8-10.9 |
//! | [`identity`] | `whoami` / `id` — the current principal + roles | WS8-10.9 |
//! | [`uname`]    | `uname` — format injected `SystemInfo` | WS8-10.10 |
//! | [`date`]     | `date` — format an injected epoch over a `Clock` seam | WS8-10.10 |
//! | [`uptime`]   | `uptime` — format an injected uptime + load | WS8-10.10 |
//! | [`man`]      | `man` — page lookup via a `ManSource` seam | WS8-10.10 |
//! | [`perm`]     | `chmod`/`chown` on capability tokens (not Unix bits) | WS8-10.11 |
//! | [`process`]  | process-table seam + `ProcessInfo` + host double | WS8-10.8 |
//! | [`ps`]       | `ps` — tabular process listing, `-o` columns | WS8-10.8 |
//! | [`top`]      | `top`/`htop`-like CPU/memory-sorted snapshot | WS8-10.8 |
//! | [`kill`]     | `kill` — capability-gated signal delivery | WS8-10.8 |
//! | [`jobs`]     | `jobs` — format an injected shell job table | WS8-10.8 |
//!
//! ## Design constraints
//!
//! - **`no_std` + `alloc`**, dependency-free, so it builds for
//!   `x86_64-unknown-none` as well as the developer host.
//! - **No `unsafe`**: `#![forbid(unsafe_code)]` is set unconditionally.
//! - **No integer division, no floating point**: numeric `sort` parses to
//!   `i64` and compares integers; nothing here needs division.
//! - **Total functions**: no `unwrap`/`panic` in library code; fallible
//!   parsing returns [`CoreError`].

#![no_std]
#![forbid(unsafe_code)]
#![deny(missing_docs)]
#![cfg_attr(
    test,
    allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::unnecessary_wraps,
        clippy::indexing_slicing,
        clippy::missing_docs_in_private_items,
    )
)]

extern crate alloc;

use alloc::{string::String, vec::Vec};

pub mod awk;
pub mod cat;
pub mod cut;
pub mod date;
pub mod df;
pub mod diff;
pub mod dirops;
pub mod du;
pub mod env;
pub mod fileops;
pub mod find;
pub mod fs;
pub mod grep;
pub mod head;
pub mod identity;
pub mod jobs;
pub mod kill;
pub mod ls;
pub mod man;
pub mod mount;
pub mod nav;
pub mod pager;
pub mod path;
pub mod perm;
pub mod process;
pub mod ps;
pub mod sed;
pub mod sort;
pub mod stat;
pub mod tail;
pub mod top;
pub mod tr;
pub mod tree;
pub mod uname;
pub mod uniq;
pub mod uptime;
pub mod wc;
pub mod which;
pub mod xargs;

/// Error returned by the fallible parsers in this crate (flag parsing and
/// `sed`/`awk` program parsing).
///
/// The utilities themselves are total once configured, so this type only
/// surfaces at the configuration boundary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CoreError {
    /// A flag or argument was malformed or unrecognised.
    InvalidArgument,
    /// A flag that requires a value was given none.
    MissingValue,
    /// A value expected to be numeric could not be parsed.
    InvalidNumber,
    /// A `sed` or `awk` program was syntactically invalid.
    InvalidProgram,
    /// A character range (e.g. `z-a`) had its endpoints reversed.
    InvalidRange,
}

impl core::fmt::Display for CoreError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let msg = match self {
            Self::InvalidArgument => "invalid argument",
            Self::MissingValue => "missing value for flag",
            Self::InvalidNumber => "invalid number",
            Self::InvalidProgram => "invalid program",
            Self::InvalidRange => "invalid character range",
        };
        f.write_str(msg)
    }
}

/// Split `input` into logical lines.
///
/// Lines are separated by `\n`. A single trailing newline is treated as a line
/// terminator (not the start of an extra empty line), matching how the classic
/// tools treat a well-formed text stream. Interior empty lines are preserved.
/// An empty input yields no lines.
#[must_use]
pub fn split_lines(input: &str) -> Vec<&str> {
    if input.is_empty() {
        return Vec::new();
    }
    let mut lines: Vec<&str> = input.split('\n').collect();
    if input.ends_with('\n') {
        lines.pop();
    }
    lines
}

/// Join `lines` back into a single `String`, one `\n` between each and a
/// trailing `\n` after the last line (the canonical text-stream shape).
///
/// An empty slice yields an empty `String`.
#[must_use]
pub fn join_lines(lines: &[String]) -> String {
    let mut out = String::new();
    for line in lines {
        out.push_str(line);
        out.push('\n');
    }
    out
}
