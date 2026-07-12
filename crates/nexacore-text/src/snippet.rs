//! Inline execution of ncScript snippets (WS8-08.9).
//!
//! The editor can run a selected ncScript (`.oss`, WS18) snippet inline and
//! splice its output back over the selection — "select some script, run it,
//! keep the result". Because `nexacore-text` stays dependency-free, the script
//! engine is reached through a *local* seam, the [`NcScriptRunner`] trait: the
//! production implementation is wired elsewhere (to `nexacore-script`), while
//! host tests pass a lightweight double.
//!
//! [`run_selection`] validates the selection range against the text
//! (fail-closed: empty or out-of-range selections return a typed
//! [`SnippetError`], never a panic or an index), invokes the runner, and returns
//! the [`Replacement`] to splice in. It never edits the buffer itself — the
//! caller splices the replacement into the [`crate::buffer::PieceTable`].
//!
//! ## Failed-run policy (fail-closed)
//!
//! A runner may *succeed at running* a snippet that itself exits with a non-zero
//! status. In that case [`run_selection`] **surfaces the failure as
//! [`SnippetError::Failed`] and does not produce a [`Replacement`]** — the
//! user's source code is left untouched rather than being overwritten with error
//! output. Only a clean run (status `0`) yields a replacement.

use alloc::string::String;

pub use crate::ai_actions::Replacement;

/// The result of running a snippet: its captured `stdout` and exit `status`.
///
/// `status` follows the usual process convention: `0` means success, any other
/// value means the snippet reported a failure. A successful run's `stdout` is
/// what gets spliced back over the selection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScriptOutput {
    /// The text the snippet emitted on standard output.
    pub stdout: String,
    /// The snippet's exit status; `0` is success, non-zero is failure.
    pub status: i32,
}

impl ScriptOutput {
    /// A successful (`status == 0`) output carrying `stdout`.
    #[must_use]
    pub fn ok(stdout: &str) -> Self {
        Self {
            stdout: String::from(stdout),
            status: 0,
        }
    }

    /// Whether this output represents a successful run (`status == 0`).
    #[must_use]
    pub fn is_success(&self) -> bool {
        self.status == 0
    }
}

/// Why a snippet could not be run into a replacement.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SnippetError {
    /// The selection was empty, so there is no snippet to run.
    EmptySelection,
    /// The selection range was out of bounds or not on UTF-8 char boundaries.
    OutOfRange,
    /// No runner was available to service the request.
    RunnerUnavailable(String),
    /// The runner ran the snippet but it reported a non-zero exit status.
    ///
    /// Per the fail-closed policy the selection is left untouched; `message`
    /// carries whatever diagnostic text the run produced.
    Failed {
        /// The non-zero exit status the snippet reported.
        status: i32,
        /// Diagnostic text captured from the failed run.
        message: String,
    },
}

/// A runner that executes an ncScript snippet and reports its output.
///
/// This is the local, dependency-free seam. The real implementation is injected
/// by higher layers (which own the `nexacore-script` engine); host tests pass a
/// double.
pub trait NcScriptRunner {
    /// Run `source` and return its [`ScriptOutput`].
    ///
    /// # Errors
    /// Returns [`SnippetError::RunnerUnavailable`] if the engine cannot service
    /// the request at all. A snippet that runs but exits non-zero is *not* an
    /// error here — it is reported through [`ScriptOutput::status`].
    fn run(&self, source: &str) -> Result<ScriptOutput, SnippetError>;
}

/// Validate `selection` against `text`, run it via `runner`, and return the
/// [`Replacement`] to splice in.
///
/// This computes the replacement only; it does not mutate any buffer. The
/// `selection` is a `[start, end)` byte range into `text`. On a clean run the
/// snippet's `stdout` replaces exactly that range.
///
/// # Errors
/// - [`SnippetError::OutOfRange`] if `start > end`, `end` exceeds `text`, or
///   either endpoint is not a UTF-8 character boundary.
/// - [`SnippetError::EmptySelection`] if the range is valid but empty.
/// - [`SnippetError::RunnerUnavailable`] if the runner cannot service the run.
/// - [`SnippetError::Failed`] if the snippet runs but exits non-zero; the
///   selection is left untouched (fail-closed).
pub fn run_selection<R: NcScriptRunner + ?Sized>(
    runner: &R,
    text: &str,
    selection: (usize, usize),
) -> Result<Replacement, SnippetError> {
    let (start, end) = selection;
    // Fail closed on any malformed range before touching the runner.
    if start > end || end > text.len() {
        return Err(SnippetError::OutOfRange);
    }
    if !text.is_char_boundary(start) || !text.is_char_boundary(end) {
        return Err(SnippetError::OutOfRange);
    }
    let slice = text.get(start..end).ok_or(SnippetError::OutOfRange)?;
    if slice.is_empty() {
        return Err(SnippetError::EmptySelection);
    }
    let output = runner.run(slice)?;
    if !output.is_success() {
        // Fail-closed: do not overwrite the user's code with error output.
        return Err(SnippetError::Failed {
            status: output.status,
            message: output.stdout,
        });
    }
    Ok(Replacement {
        text: output.stdout,
        range: (start, end),
    })
}

#[cfg(test)]
mod tests {
    use alloc::{format, string::ToString};

    use super::*;

    /// A runner that echoes the source wrapped in `run(...)`, always succeeding.
    struct EchoRunner;

    impl NcScriptRunner for EchoRunner {
        fn run(&self, source: &str) -> Result<ScriptOutput, SnippetError> {
            Ok(ScriptOutput::ok(&format!("run({source})")))
        }
    }

    /// A runner that is entirely unavailable.
    struct DownRunner;

    impl NcScriptRunner for DownRunner {
        fn run(&self, _source: &str) -> Result<ScriptOutput, SnippetError> {
            Err(SnippetError::RunnerUnavailable("no engine".to_string()))
        }
    }

    /// A runner whose snippet always exits non-zero.
    struct FailingRunner;

    impl NcScriptRunner for FailingRunner {
        fn run(&self, _source: &str) -> Result<ScriptOutput, SnippetError> {
            Ok(ScriptOutput {
                stdout: "boom".to_string(),
                status: 2,
            })
        }
    }

    #[test]
    fn happy_path_returns_output_and_range() {
        let text = "let x = 1";
        let out = run_selection(&EchoRunner, text, (0, text.len())).unwrap();
        assert_eq!(out.text, "run(let x = 1)");
        assert_eq!(out.range, (0, 9));
    }

    #[test]
    fn only_the_selection_is_run() {
        let text = "prefix|let y = 2|suffix";
        // Run just the "let y = 2" span between the bars.
        let out = run_selection(&EchoRunner, text, (7, 16)).unwrap();
        assert_eq!(out.text, "run(let y = 2)");
        assert_eq!(out.range, (7, 16));
    }

    #[test]
    fn empty_selection_is_rejected() {
        let err = run_selection(&EchoRunner, "abc", (1, 1)).unwrap_err();
        assert_eq!(err, SnippetError::EmptySelection);
    }

    #[test]
    fn out_of_range_end_is_rejected() {
        let err = run_selection(&EchoRunner, "abc", (0, 99)).unwrap_err();
        assert_eq!(err, SnippetError::OutOfRange);
    }

    #[test]
    fn inverted_range_is_rejected() {
        let err = run_selection(&EchoRunner, "abc", (3, 1)).unwrap_err();
        assert_eq!(err, SnippetError::OutOfRange);
    }

    #[test]
    fn non_char_boundary_is_rejected() {
        // "café" — 'é' is two bytes (3..5), so offset 4 splits it.
        let text = "café";
        assert_eq!(text.len(), 5);
        let err = run_selection(&EchoRunner, text, (0, 4)).unwrap_err();
        assert_eq!(err, SnippetError::OutOfRange);
        // A boundary-aligned multi-byte selection runs fine.
        let ok = run_selection(&EchoRunner, text, (0, 5)).unwrap();
        assert_eq!(ok.text, "run(café)");
        assert_eq!(ok.range, (0, 5));
    }

    #[test]
    fn runner_unavailable_propagates() {
        let err = run_selection(&DownRunner, "abc", (0, 3)).unwrap_err();
        assert_eq!(
            err,
            SnippetError::RunnerUnavailable("no engine".to_string())
        );
    }

    #[test]
    fn failed_run_surfaces_error_and_does_not_replace() {
        let err = run_selection(&FailingRunner, "abc", (0, 3)).unwrap_err();
        assert_eq!(
            err,
            SnippetError::Failed {
                status: 2,
                message: "boom".to_string(),
            }
        );
    }

    #[test]
    fn script_output_helpers() {
        let ok = ScriptOutput::ok("hi");
        assert_eq!(ok.status, 0);
        assert!(ok.is_success());
        let bad = ScriptOutput {
            stdout: String::new(),
            status: 1,
        };
        assert!(!bad.is_success());
    }

    #[test]
    fn works_through_a_trait_object() {
        let runner: &dyn NcScriptRunner = &EchoRunner;
        let out = run_selection(runner, "z", (0, 1)).unwrap();
        assert_eq!(out.text, "run(z)");
        assert_eq!(out.range, (0, 1));
    }
}
