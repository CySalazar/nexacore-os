//! # `nexacore-shell`
//!
//! System shell for NexaCore OS.
//!
//! v1 ships a traditional command-line shell sufficient for development
//! and basic system administration. The long-term vision is an
//! **intent-based shell**: natural language is the primary interface, with
//! the shell lowering user intent into a structured plan that the user
//! previews and approves before execution.
//!
//! ## Status
//!
//! Phase 1 complete — lexer, parser, environment, glob, line editor,
//! tab completion, executor, 15 builtins, 20 external commands, REPL.
//!
//! ## Design rationale
//!
//! - **Plan-then-execute**: AI-generated commands never auto-execute.
//!   The user always sees a plan and approves it.
//! - **Capability-aware**: the shell holds a capability for the user's
//!   session and forwards it to invoked commands.
//! - **Auditable**: every command, plan, and result are logged to the
//!   per-user audit log.
//!
//! ## Pipeline
//!
//! ```text
//! raw &str
//!   ──► [`lexer::tokenize`]      →  Vec<Token>
//!   ──► [`parser::parse`]        →  CommandList AST
//!   ──► [`env::ShellEnv::expand`]→  expanded strings
//!   ──► [`glob::expand_glob`]    →  path-expanded args
//!   ──► [`executor`]             →  process / built-in dispatch
//! ```

#![cfg_attr(not(feature = "std"), no_std)]
#![doc(html_root_url = "https://docs.nexacore-os.org/nexacore-shell")]
#![deny(missing_docs)]
#![cfg_attr(
    test,
    allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::unnecessary_wraps,
        clippy::indexing_slicing,
    )
)]

extern crate alloc;

/// Built-in command registry.
///
/// Exposes [`crate::command::register_builtins`], which is called by the executor before each
/// pipeline run.
pub mod command;

/// External commands (Phase 1: implemented as builtins).
///
/// | Module | Commands |
/// |--------|---------|
/// | `commands::fs_cmds` | `ls`, `cat`, `cp`, `mv`, `rm`, `mkdir`, `touch` |
/// | `commands::text_cmds` | `grep`, `head`, `tail`, `wc` |
/// | `commands::sys_cmds` | `uname`, `whoami`, `hostname`, `ps`, `kill` |
/// | `commands::fs_info` | `df`, `find` |
pub mod commands;

/// Tab-completion engine.
///
/// ## Completion contexts
///
/// | Context | Triggered when |
/// |---|---|
/// | [`completion::CompletionContext::Command`] | The word under the cursor is the first token on the line. |
/// | [`completion::CompletionContext::FilePath`] | Any subsequent word position. |
/// | [`completion::CompletionContext::Variable`] | The word starts with `$`. |
///
/// ## Algorithm
///
/// 1. [`completion::detect_context`] scans backwards from `cursor` to find the current
///    word and classify it.
/// 2. [`completion::complete`] dispatches to the appropriate completion strategy and
///    collects candidates:
///    - **Command**: built-ins list + each directory on `$PATH` (via
///      [`glob::FsQuery::list_dir`]).
///    - **FilePath**: split `partial` into directory/prefix, list the
///      directory, filter by prefix.
///    - **Variable**: iterate environment variable names, filter by prefix.
/// 3. Candidates are sorted and deduplicated before being returned.
pub mod completion;

/// Environment variable resolution and expansion.
///
/// This module provides [`env::ShellEnv`], the runtime variable store for an
/// NexaCore shell session. [`env::ShellEnv::expand`] performs `$VAR`, `${VAR}`, and
/// `${VAR:-default}` substitution.
pub mod env;

/// Command executor — process spawning and pipeline management.
///
/// Pipelines are executed left-to-right. The output of each stage is held in
/// [`executor::ExecContext::output`] and is available for the next stage to consume.
/// Full OS-level piping will be added with the kernel process layer.
pub mod executor;

/// Glob (pathname) expansion.
pub mod glob;

/// Network-interface query interface, injected by the caller.
///
/// Mirrors [`glob::FsQuery`] so this crate stays IPC-agnostic. Backs the
/// `ifconfig` builtin in [`commands::net_cmds`].
pub mod netquery;

/// Lexical tokenisation of raw shell input.
///
/// Shell lexer — converts raw input text into a flat sequence of [`lexer::Token`]s.
/// The lexer returns the first [`lexer::LexError`] it encounters and stops. Partial
/// token vectors are discarded.
pub mod lexer;

/// Interactive line editor with history and key bindings.
///
/// This module provides [`line_editor::LineEditor`], the line-editing layer consumed by the
/// REPL. It accepts raw byte input, maps byte sequences to [`line_editor::EditAction`]
/// values via [`line_editor::map_key`], and maintains a character buffer with a logical
/// cursor position.
///
/// ## Key bindings
///
/// | Byte sequence | Action |
/// |---|---|
/// | Printable ASCII / UTF-8 | [`line_editor::EditAction::Insert`] |
/// | `\x7f` or `\x08` | [`line_editor::EditAction::Backspace`] |
/// | `\x1b[A` | [`line_editor::EditAction::HistoryUp`] |
/// | `\x1b[B` | [`line_editor::EditAction::HistoryDown`] |
/// | `\x1b[C` | [`line_editor::EditAction::MoveRight`] |
/// | `\x1b[D` | [`line_editor::EditAction::MoveLeft`] |
/// | `\x1b[H` or `\x1b[1~` | [`line_editor::EditAction::Home`] |
/// | `\x1b[F` or `\x1b[4~` | [`line_editor::EditAction::End`] |
/// | `\x1b[3~` | [`line_editor::EditAction::Delete`] |
/// | `\x03` | [`line_editor::EditAction::Interrupt`] |
/// | `\x04` | [`line_editor::EditAction::Eof`] |
/// | `\x09` | [`line_editor::EditAction::Complete`] |
/// | `\x0c` | [`line_editor::EditAction::ClearScreen`] |
/// | `\r` or `\n` | [`line_editor::EditAction::Submit`] |
///
/// ## Rendering
///
/// [`line_editor::LineEditor::render_line`] produces a sequence of ANSI bytes that:
/// 1. Moves the cursor to column 0 (`\r`).
/// 2. Erases from cursor to end of line (`\x1b[K`).
/// 3. Writes the prompt.
/// 4. Writes the buffer content.
/// 5. Repositions the cursor at the logical cursor position.
pub mod line_editor;

/// Shell parser — converts the token stream into an AST.
///
/// - [`lexer::Token::Newline`] is treated identically to [`lexer::Token::Semicolon`].
/// - [`lexer::Token::EnvVar`] tokens are preserved as the string `"$NAME"` inside
///   `SimpleCommand::argv` for later expansion by [`env::ShellEnv::expand`].
pub mod parser;

/// Read-eval-print loop.
///
/// This module drives the interactive shell session. It provides two public
/// entry points:
///
/// - [`repl::format_prompt`]: formats the shell prompt string by expanding `PS1`
///   escape sequences.
/// - [`repl::process_line`]: runs a single input line through the full shell
///   pipeline — tokenise → expand aliases → parse → execute.
///
/// The [`repl::Shell`] struct bundles the environment, line editor, and current
/// working directory. In a live session the REPL owner calls [`repl::process_line`]
/// for every line obtained from the line editor.
pub mod repl;

/// Per-session audit trail.
///
/// This module provides [`audit::AuditLog`], a lightweight append-only log that
/// records every command processed by the REPL.
pub mod audit;

/// Intent classification — lightweight agent integration.
///
/// Given a raw command or natural-language string, [`intent::classify_intent`]
/// returns the most appropriate [`intent::IntentClass`], which the REPL uses
/// to route to the correct agent. Classification is driven by four private
/// keyword tables: `GUIDANCE_KEYWORDS`, `ADMIN_KEYWORDS`, `SECURITY_KEYWORDS`,
/// and `TASK_KEYWORDS`.
pub mod intent;
