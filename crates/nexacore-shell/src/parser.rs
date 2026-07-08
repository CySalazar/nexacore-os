//! Shell parser — transforms the flat [`crate::lexer::Token`] stream produced
//! by [`crate::lexer::tokenize`] into an abstract syntax tree (AST).
//!
//! ## Grammar
//!
//! ```text
//! command_list  := pipeline ((';' | '&&' | '||' | '&') pipeline)* [';' | '&']
//! pipeline      := simple_cmd ('|' simple_cmd)*
//! simple_cmd    := (VAR=val)* word+ redirect*
//! redirect      := ('>' | '>>' | '<' | '2>') word
//! ```
//!
//! ## Design decisions
//!
//! - [`crate::lexer::Token::Newline`] is treated identically to [`crate::lexer::Token::Semicolon`].
//! - Consecutive separators (e.g. `; ;`) are collapsed: empty segments are
//!   silently skipped rather than returned as errors.
//! - A `Word` token is classified as an environment override (`VAR=val`) only
//!   when (a) it contains `=`, (b) the portion before `=` is a valid POSIX
//!   identifier (`[A-Za-z_][A-Za-z0-9_]*`), **and** (c) the immediately
//!   following token is a word-class token — ensuring that `VAR=val` alone
//!   on the command line is treated as a command, not a dangling override.
//! - [`crate::lexer::Token::EnvVar`] tokens are preserved as the string `"$NAME"` inside
//!   `argv`; actual substitution is deferred to [`crate::env::ShellEnv::expand`].

#[cfg(not(feature = "std"))]
use alloc::{borrow::ToOwned, format, string::String, vec::Vec};

use crate::lexer::Token;

// ── AST node types ────────────────────────────────────────────────────────────

/// The direction of an I/O redirect.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RedirectKind {
    /// `<` — redirect stdin from a file.
    In,
    /// `>` — redirect stdout to a file, truncating it.
    Out,
    /// `>>` — redirect stdout to a file, appending to it.
    Append,
    /// `2>` — redirect stderr to a file.
    Err,
}

/// A single I/O redirect specification attached to a [`SimpleCommand`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Redirect {
    /// Whether this is stdin, stdout, append, or stderr.
    pub kind: RedirectKind,
    /// The file path or word that is the target of the redirect.
    pub target: String,
}

/// A simple command: a program name, its arguments, optional I/O redirects,
/// and optional per-command environment variable overrides.
///
/// # Examples
///
/// ```rust
/// use nexacore_shell::{
///     lexer::tokenize,
///     parser::{SimpleCommand, parse},
/// };
///
/// let tokens = tokenize("ls -la").unwrap();
/// let cmd_list = parse(&tokens).unwrap();
/// let cmd = &cmd_list.entries[0].0.commands[0];
/// assert_eq!(cmd.argv, vec!["ls", "-la"]);
/// assert!(cmd.redirects.is_empty());
/// assert!(cmd.env_overrides.is_empty());
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SimpleCommand {
    /// The command name followed by its positional arguments.
    ///
    /// `argv[0]` is the command name. Arguments that originated from
    /// [`Token::EnvVar`] are stored as `"$NAME"` strings; expansion happens
    /// at execution time in [`crate::env::ShellEnv::expand`].
    pub argv: Vec<String>,
    /// Zero or more I/O redirects attached to this command.
    pub redirects: Vec<Redirect>,
    /// Per-command environment variable overrides that appear before the
    /// command name in the token stream (e.g. `FOO=bar cmd`).
    pub env_overrides: Vec<(String, String)>,
}

/// A pipeline: one or more [`SimpleCommand`]s whose standard I/O streams are
/// connected in sequence via pipes (`|`).
///
/// # Examples
///
/// ```rust
/// use nexacore_shell::{lexer::tokenize, parser::parse};
///
/// let tokens = tokenize("ls | grep rs").unwrap();
/// let cmd_list = parse(&tokens).unwrap();
/// assert_eq!(cmd_list.entries[0].0.commands.len(), 2);
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pipeline {
    /// The ordered sequence of commands connected by `|`.
    ///
    /// Guaranteed to be non-empty after a successful parse.
    pub commands: Vec<SimpleCommand>,
}

/// How two adjacent [`Pipeline`]s are connected in a [`CommandList`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Connector {
    /// `;` — run the next pipeline unconditionally after the previous one.
    Semi,
    /// `&&` — run the next pipeline only if the previous exited with code 0.
    And,
    /// `||` — run the next pipeline only if the previous exited non-zero.
    Or,
    /// `&` — launch the preceding pipeline in the background; do not wait for
    /// it before starting the next pipeline.
    Background,
}

/// A complete, parsed command line: one or more [`Pipeline`]s connected by
/// [`Connector`]s.
///
/// # Examples
///
/// ```rust
/// use nexacore_shell::{
///     lexer::tokenize,
///     parser::{Connector, parse},
/// };
///
/// let tokens = tokenize("make && ./run").unwrap();
/// let cmd_list = parse(&tokens).unwrap();
/// assert_eq!(cmd_list.entries.len(), 2);
/// assert_eq!(cmd_list.entries[0].1, Some(Connector::And));
/// assert_eq!(cmd_list.entries[1].1, None);
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommandList {
    /// Ordered sequence of `(pipeline, optional connector to next pipeline)`.
    ///
    /// The connector on the *last* entry is always `None`. An empty `Vec`
    /// means no commands were present in the input (e.g. blank line, comment).
    pub entries: Vec<(Pipeline, Option<Connector>)>,
}

// ── ParseError ────────────────────────────────────────────────────────────────

/// Errors that the parser can produce.
///
/// All variants carry enough context for the caller to produce a user-facing
/// error message without needing to re-inspect the token stream.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParseError {
    /// An operator or token appeared in a position where the grammar does not
    /// permit it. The inner string is a human-readable description.
    UnexpectedToken(String),
    /// A pipeline was present but contained no recognisable command tokens.
    MissingCommand,
    /// A `|` was found at the start or end of a pipeline, or between two
    /// operators with nothing in between.
    EmptyPipeline,
    /// A redirect operator (`>`, `>>`, `<`, `2>`) was not followed by a
    /// word-class token that could serve as the redirect target.
    InvalidRedirect,
}

impl core::fmt::Display for ParseError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::UnexpectedToken(tok) => {
                write!(f, "unexpected token: {tok}")
            }
            Self::MissingCommand => {
                write!(f, "missing command")
            }
            Self::EmptyPipeline => {
                write!(f, "empty pipeline: `|` requires a command on both sides")
            }
            Self::InvalidRedirect => {
                write!(
                    f,
                    "invalid redirect: operator must be followed by a filename"
                )
            }
        }
    }
}

impl core::error::Error for ParseError {}

// ── Public entry point ────────────────────────────────────────────────────────

/// Parse a flat token slice into a [`CommandList`].
///
/// # Grammar
///
/// ```text
/// command_list  := pipeline ((';' | '&&' | '||' | '&') pipeline)* [';' | '&']
/// pipeline      := simple_cmd ('|' simple_cmd)*
/// simple_cmd    := (VAR=val)* word+ redirect*
/// redirect      := ('>' | '>>' | '<' | '2>') word
/// ```
///
/// # Errors
///
/// Returns a [`ParseError`] when the token stream violates the grammar:
///
/// - [`ParseError::EmptyPipeline`] — a `|` at the start or end of a pipeline.
/// - [`ParseError::InvalidRedirect`] — a redirect operator with no following
///   word-class token.
/// - [`ParseError::MissingCommand`] — a pipeline region contains only
///   non-command tokens.
/// - [`ParseError::UnexpectedToken`] — any other grammatically invalid token.
///
/// # Examples
///
/// ```rust
/// use nexacore_shell::{
///     lexer::tokenize,
///     parser::{Connector, parse},
/// };
///
/// // Empty input yields an empty command list.
/// let empty = parse(&[]).unwrap();
/// assert!(empty.entries.is_empty());
///
/// // Semicolon-separated commands.
/// let tokens = tokenize("echo hello ; echo world").unwrap();
/// let cmd_list = parse(&tokens).unwrap();
/// assert_eq!(cmd_list.entries.len(), 2);
/// assert_eq!(cmd_list.entries[0].1, Some(Connector::Semi));
/// ```
pub fn parse(tokens: &[Token]) -> Result<CommandList, ParseError> {
    let mut parser = Parser::new(tokens);
    parser.parse_command_list()
}

// ── Internal parser state ─────────────────────────────────────────────────────

/// Recursive-descent parser that walks the token slice.
///
/// The parser uses a simple cursor (`pos`) over a shared reference to the
/// token slice. All methods advance the cursor and return structured AST nodes
/// or errors.
struct Parser<'a> {
    tokens: &'a [Token],
    pos: usize,
}

impl<'a> Parser<'a> {
    fn new(tokens: &'a [Token]) -> Self {
        Parser { tokens, pos: 0 }
    }

    // ── Cursor helpers ────────────────────────────────────────────────────

    /// Peek at the current token without consuming it.
    fn peek(&self) -> Option<&Token> {
        self.tokens.get(self.pos)
    }

    /// Consume and return the current token, advancing the cursor.
    fn advance(&mut self) -> Option<&Token> {
        let tok = self.tokens.get(self.pos);
        if tok.is_some() {
            self.pos += 1;
        }
        tok
    }

    // ── Top-level ─────────────────────────────────────────────────────────

    /// Parse `command_list := pipeline ((sep) pipeline)* [sep]`.
    ///
    /// Separators are `;`, `&&`, `||`, `&`, and `\n`. Consecutive separators
    /// are collapsed: we skip any separator-only gaps between real pipelines.
    fn parse_command_list(&mut self) -> Result<CommandList, ParseError> {
        let mut entries: Vec<(Pipeline, Option<Connector>)> = Vec::new();

        // Skip any leading separator tokens (e.g. a bare newline at start).
        self.skip_separators();

        while self.peek().is_some() {
            let pipeline = self.parse_pipeline()?;
            let connector = self.consume_connector();
            let is_last = connector.is_none();
            entries.push((pipeline, connector));
            // If there was no connector (end of input), stop.
            if is_last {
                break;
            }
            // Skip any extra separators between pipelines.
            self.skip_separators();
        }

        Ok(CommandList { entries })
    }

    /// Skip zero or more leading separator tokens (`;`, `\n`).
    ///
    /// We do not skip `&&`, `||`, or `&` here because those require a
    /// preceding pipeline and would be caught as errors by `parse_pipeline`.
    fn skip_separators(&mut self) {
        while let Some(tok) = self.peek() {
            match tok {
                Token::Semicolon | Token::Newline => {
                    self.pos += 1;
                }
                _ => break,
            }
        }
    }

    /// Consume one connector token and return the matching [`Connector`].
    /// Returns `None` if the next token is not a connector (including
    /// end-of-input).
    fn consume_connector(&mut self) -> Option<Connector> {
        match self.peek()? {
            Token::Semicolon | Token::Newline => {
                self.pos += 1;
                Some(Connector::Semi)
            }
            Token::DoubleAmpersand => {
                self.pos += 1;
                Some(Connector::And)
            }
            Token::DoublePipe => {
                self.pos += 1;
                Some(Connector::Or)
            }
            Token::Ampersand => {
                self.pos += 1;
                Some(Connector::Background)
            }
            _ => None,
        }
    }

    // ── Pipeline ──────────────────────────────────────────────────────────

    /// Parse `pipeline := simple_cmd ('|' simple_cmd)*`.
    ///
    /// A leading `|` (i.e. the next token is already a Pipe) is an
    /// [`ParseError::EmptyPipeline`] error.
    fn parse_pipeline(&mut self) -> Result<Pipeline, ParseError> {
        // A pipe at the very start of a pipeline is invalid.
        if self.peek() == Some(&Token::Pipe) {
            return Err(ParseError::EmptyPipeline);
        }

        let mut commands: Vec<SimpleCommand> = Vec::new();
        let cmd = self.parse_simple_command()?;
        commands.push(cmd);

        while self.peek() == Some(&Token::Pipe) {
            self.pos += 1; // consume `|`
            // A pipe at the end (nothing follows or next is another operator)
            // is an EmptyPipeline error.
            match self.peek() {
                None
                | Some(
                    Token::Pipe
                    | Token::Semicolon
                    | Token::Newline
                    | Token::DoubleAmpersand
                    | Token::DoublePipe
                    | Token::Ampersand,
                ) => {
                    return Err(ParseError::EmptyPipeline);
                }
                _ => {}
            }
            let cmd = self.parse_simple_command()?;
            commands.push(cmd);
        }

        Ok(Pipeline { commands })
    }

    // ── Simple command ────────────────────────────────────────────────────

    /// Parse `simple_cmd := (VAR=val)* word+ redirect*`.
    ///
    /// Returns [`ParseError::MissingCommand`] when the token region contains
    /// no word-class tokens at all (e.g. only redirects with no command name).
    fn parse_simple_command(&mut self) -> Result<SimpleCommand, ParseError> {
        let mut env_overrides: Vec<(String, String)> = Vec::new();
        let mut argv: Vec<String> = Vec::new();
        let mut redirects: Vec<Redirect> = Vec::new();

        // Phase 1: collect leading VAR=val overrides.
        // A token is an env override only when it is a bare Word containing
        // `=`, the left-hand side is a valid identifier, and the *next* token
        // is a word-class token (ensuring the override precedes a command).
        while let Some(Token::Word(w)) = self.peek() {
            if let Some((name, value)) = split_env_override(w) {
                // Only treat as override if followed by a word-class token.
                if self.next_is_word_class(1) {
                    env_overrides.push((name, value));
                    self.pos += 1;
                    continue;
                }
            }
            // Not an env override — move on to Phase 2.
            break;
        }

        // Phase 2: collect argv words and redirects intermixed.
        loop {
            match self.peek() {
                // Redirect operators — consume the operator then the target word.
                Some(Token::RedirectOut) => {
                    self.pos += 1;
                    let target = self.expect_word_token()?;
                    redirects.push(Redirect {
                        kind: RedirectKind::Out,
                        target,
                    });
                }
                Some(Token::RedirectAppend) => {
                    self.pos += 1;
                    let target = self.expect_word_token()?;
                    redirects.push(Redirect {
                        kind: RedirectKind::Append,
                        target,
                    });
                }
                Some(Token::RedirectIn) => {
                    self.pos += 1;
                    let target = self.expect_word_token()?;
                    redirects.push(Redirect {
                        kind: RedirectKind::In,
                        target,
                    });
                }
                Some(Token::RedirectErr) => {
                    self.pos += 1;
                    let target = self.expect_word_token()?;
                    redirects.push(Redirect {
                        kind: RedirectKind::Err,
                        target,
                    });
                }

                // Word-class tokens → argv entries.
                Some(Token::Word(_) | Token::SingleQuoted(_) | Token::DoubleQuoted(_)) => {
                    let s = self.consume_word_token();
                    argv.push(s);
                }
                Some(Token::EnvVar(_)) => {
                    // EnvVar in argv position: store as "$NAME" for later
                    // expansion by ShellEnv::expand.
                    let s = self.consume_envvar_token();
                    argv.push(s);
                }

                // Anything else (operators, pipe, end) — stop.
                _ => break,
            }
        }

        if argv.is_empty() && env_overrides.is_empty() {
            return Err(ParseError::MissingCommand);
        }

        // A command with only env overrides and no argv is valid in POSIX
        // (it sets the variable in the current environment), but we require
        // at least one argv word for safety. If argv is empty but overrides
        // exist, treat the last override as the command itself.
        // (This edge case is extremely rare in practice.)
        if argv.is_empty() {
            return Err(ParseError::MissingCommand);
        }

        Ok(SimpleCommand {
            argv,
            redirects,
            env_overrides,
        })
    }

    // ── Token consumption helpers ─────────────────────────────────────────

    /// Return `true` if the token at `offset` positions ahead of `pos` is a
    /// word-class token (one that can contribute to argv or be a redirect
    /// target).
    ///
    /// Used to determine whether a `VAR=val` token is a genuine env override
    /// (i.e. it precedes an actual command) rather than a standalone
    /// assignment.
    fn next_is_word_class(&self, offset: usize) -> bool {
        matches!(
            self.tokens.get(self.pos + offset),
            Some(
                Token::Word(_) | Token::SingleQuoted(_) | Token::DoubleQuoted(_) | Token::EnvVar(_)
            )
        )
    }

    /// Consume the current token, which must be a word-class token, and
    /// return its string representation.
    ///
    /// # Panics
    ///
    /// Panics if the current token is not a word-class token. Callers must
    /// verify `peek()` before calling this method.
    fn consume_word_token(&mut self) -> String {
        match self.advance() {
            Some(Token::Word(s) | Token::SingleQuoted(s) | Token::DoubleQuoted(s)) => s.clone(),
            other => {
                // Callers must verify `peek()` before calling; reaching here
                // means a logic error in the parser, not malformed input.
                unreachable!("consume_word_token called on non-word token: {other:?}");
            }
        }
    }

    /// Consume the current [`Token::EnvVar`] and return `"$NAME"`.
    ///
    /// For `${VAR:-default}` the raw specifier is `"VAR:-default"`, so we
    /// emit `"${VAR:-default}"` to preserve the original syntax for the
    /// expander.
    ///
    /// # Panics
    ///
    /// Panics if the current token is not `Token::EnvVar`. Callers must
    /// verify `peek()` before calling.
    fn consume_envvar_token(&mut self) -> String {
        match self.advance() {
            Some(Token::EnvVar(spec)) => {
                // If the spec contains `:-` or `:+` etc., it came from the
                // braced form `${...}`; reconstruct the full `${...}` syntax
                // so the expander can process it correctly.
                if spec.contains(':') || spec == "?" || spec == "$" {
                    format!("${{{spec}}}")
                } else {
                    format!("${spec}")
                }
            }
            other => {
                // Callers must verify `peek()` before calling.
                unreachable!("consume_envvar_token called on non-EnvVar token: {other:?}");
            }
        }
    }

    /// Expect the next token to be a word-class token for use as a redirect
    /// target. Returns the string or [`ParseError::InvalidRedirect`] if the
    /// next token is not word-class.
    fn expect_word_token(&mut self) -> Result<String, ParseError> {
        match self.peek() {
            Some(Token::Word(_) | Token::SingleQuoted(_) | Token::DoubleQuoted(_)) => {
                Ok(self.consume_word_token())
            }
            Some(Token::EnvVar(_)) => Ok(self.consume_envvar_token()),
            _ => Err(ParseError::InvalidRedirect),
        }
    }
}

// ── Private helpers ───────────────────────────────────────────────────────────

/// Attempt to split a `Word` string into `(name, value)` for an environment
/// variable override.
///
/// Returns `Some((name, value))` if and only if:
/// - The string contains `=`.
/// - The portion before the first `=` is a non-empty, valid POSIX identifier
///   (`[A-Za-z_][A-Za-z0-9_]*`).
///
/// Returns `None` otherwise (e.g. `"=val"`, `"123=val"`, `"no-equals"`).
fn split_env_override(s: &str) -> Option<(String, String)> {
    let eq_pos = s.find('=')?;
    let name = &s[..eq_pos];
    let value = &s[eq_pos + 1..];

    if name.is_empty() {
        return None;
    }

    // POSIX identifier: first char must be letter or underscore.
    let mut chars = name.chars();
    let first = chars.next()?;
    if !first.is_ascii_alphabetic() && first != '_' {
        return None;
    }
    // Remaining chars must be alphanumeric or underscore.
    if !chars.all(|c| c.is_ascii_alphanumeric() || c == '_') {
        return None;
    }

    Some((name.to_owned(), value.to_owned()))
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lexer::{Token, tokenize};

    // ── Helpers ───────────────────────────────────────────────────────────

    /// Parse a shell input string, panicking on lex or parse errors.
    fn p(input: &str) -> CommandList {
        let tokens = tokenize(input).expect("lex failed");
        parse(&tokens).expect("parse failed")
    }

    // ── Empty / trivial input ─────────────────────────────────────────────

    #[test]
    fn empty_tokens_yields_empty_list() {
        let result = parse(&[]).unwrap();
        assert!(result.entries.is_empty());
    }

    #[test]
    fn whitespace_only_yields_empty_list() {
        // Lexer strips whitespace; parser receives empty token slice.
        let result = p("   ");
        assert!(result.entries.is_empty());
    }

    #[test]
    fn comment_only_yields_empty_list() {
        let result = p("# just a comment");
        assert!(result.entries.is_empty());
    }

    // ── Single command ────────────────────────────────────────────────────

    #[test]
    fn single_command_no_args() {
        let cl = p("ls");
        assert_eq!(cl.entries.len(), 1);
        let (pipeline, connector) = &cl.entries[0];
        assert_eq!(pipeline.commands.len(), 1);
        assert_eq!(pipeline.commands[0].argv, vec!["ls"]);
        assert!(connector.is_none());
    }

    #[test]
    fn single_command_with_args() {
        let cl = p("ls -la /tmp");
        let cmd = &cl.entries[0].0.commands[0];
        assert_eq!(cmd.argv, vec!["ls", "-la", "/tmp"]);
    }

    // ── Pipeline ──────────────────────────────────────────────────────────

    #[test]
    fn two_stage_pipeline() {
        let cl = p("ls | cat");
        let pipeline = &cl.entries[0].0;
        assert_eq!(pipeline.commands.len(), 2);
        assert_eq!(pipeline.commands[0].argv, vec!["ls"]);
        assert_eq!(pipeline.commands[1].argv, vec!["cat"]);
    }

    #[test]
    fn three_stage_pipeline() {
        let cl = p("cat file | grep pat | wc -l");
        let pipeline = &cl.entries[0].0;
        assert_eq!(pipeline.commands.len(), 3);
        assert_eq!(pipeline.commands[0].argv, vec!["cat", "file"]);
        assert_eq!(pipeline.commands[1].argv, vec!["grep", "pat"]);
        assert_eq!(pipeline.commands[2].argv, vec!["wc", "-l"]);
    }

    // ── Redirects ─────────────────────────────────────────────────────────

    #[test]
    fn redirect_stdout() {
        let cl = p("ls > out.txt");
        let cmd = &cl.entries[0].0.commands[0];
        assert_eq!(cmd.argv, vec!["ls"]);
        assert_eq!(cmd.redirects.len(), 1);
        assert_eq!(cmd.redirects[0].kind, RedirectKind::Out);
        assert_eq!(cmd.redirects[0].target, "out.txt");
    }

    #[test]
    fn redirect_stdin() {
        let cl = p("cat < input.txt");
        let cmd = &cl.entries[0].0.commands[0];
        assert_eq!(cmd.redirects[0].kind, RedirectKind::In);
        assert_eq!(cmd.redirects[0].target, "input.txt");
    }

    #[test]
    fn redirect_append() {
        let cl = p("ls >> out.txt");
        let cmd = &cl.entries[0].0.commands[0];
        assert_eq!(cmd.redirects[0].kind, RedirectKind::Append);
        assert_eq!(cmd.redirects[0].target, "out.txt");
    }

    #[test]
    fn redirect_stderr() {
        let cl = p("cmd 2> err.log");
        let cmd = &cl.entries[0].0.commands[0];
        assert_eq!(cmd.redirects[0].kind, RedirectKind::Err);
        assert_eq!(cmd.redirects[0].target, "err.log");
    }

    #[test]
    fn multiple_redirects_on_one_command() {
        let cl = p("cmd < in.txt > out.txt");
        let cmd = &cl.entries[0].0.commands[0];
        assert_eq!(cmd.redirects.len(), 2);
        assert_eq!(cmd.redirects[0].kind, RedirectKind::In);
        assert_eq!(cmd.redirects[1].kind, RedirectKind::Out);
    }

    // ── Connectors ────────────────────────────────────────────────────────

    #[test]
    fn and_connector() {
        let cl = p("cmd1 && cmd2");
        assert_eq!(cl.entries.len(), 2);
        assert_eq!(cl.entries[0].1, Some(Connector::And));
        assert_eq!(cl.entries[1].1, None);
    }

    #[test]
    fn or_connector() {
        let cl = p("cmd1 || cmd2");
        assert_eq!(cl.entries.len(), 2);
        assert_eq!(cl.entries[0].1, Some(Connector::Or));
    }

    #[test]
    fn semicolon_connector() {
        let cl = p("cmd1 ; cmd2");
        assert_eq!(cl.entries.len(), 2);
        assert_eq!(cl.entries[0].1, Some(Connector::Semi));
    }

    #[test]
    fn background_connector() {
        let cl = p("cmd1 &");
        assert_eq!(cl.entries.len(), 1);
        assert_eq!(cl.entries[0].1, Some(Connector::Background));
    }

    #[test]
    fn background_with_following_command() {
        let cl = p("sleep 5 & echo done");
        assert_eq!(cl.entries.len(), 2);
        assert_eq!(cl.entries[0].1, Some(Connector::Background));
        assert_eq!(cl.entries[1].0.commands[0].argv, vec!["echo", "done"]);
    }

    // ── Environment overrides ─────────────────────────────────────────────

    #[test]
    fn env_override_before_command() {
        // Tokens representing `FOO=bar cmd`
        let tokens = vec![
            Token::Word("FOO=bar".to_owned()),
            Token::Word("cmd".to_owned()),
        ];
        let cl = parse(&tokens).unwrap();
        let cmd = &cl.entries[0].0.commands[0];
        assert_eq!(
            cmd.env_overrides,
            vec![("FOO".to_owned(), "bar".to_owned())]
        );
        assert_eq!(cmd.argv, vec!["cmd"]);
    }

    #[test]
    fn multiple_env_overrides() {
        let tokens = vec![
            Token::Word("A=1".to_owned()),
            Token::Word("B=2".to_owned()),
            Token::Word("cmd".to_owned()),
        ];
        let cl = parse(&tokens).unwrap();
        let cmd = &cl.entries[0].0.commands[0];
        assert_eq!(cmd.env_overrides.len(), 2);
        assert_eq!(cmd.env_overrides[0], ("A".to_owned(), "1".to_owned()));
        assert_eq!(cmd.env_overrides[1], ("B".to_owned(), "2".to_owned()));
    }

    #[test]
    fn word_with_equals_alone_is_command_not_override() {
        // `FOO=bar` with nothing after it: no following word-class token, so
        // it must be treated as argv, not an env override.
        let tokens = vec![Token::Word("FOO=bar".to_owned())];
        let cl = parse(&tokens).unwrap();
        let cmd = &cl.entries[0].0.commands[0];
        assert!(cmd.env_overrides.is_empty());
        assert_eq!(cmd.argv, vec!["FOO=bar"]);
    }

    // ── Quoted arguments ──────────────────────────────────────────────────

    #[test]
    fn single_quoted_arg_in_argv() {
        let tokens = vec![
            Token::Word("echo".to_owned()),
            Token::SingleQuoted("hello world".to_owned()),
        ];
        let cl = parse(&tokens).unwrap();
        assert_eq!(
            cl.entries[0].0.commands[0].argv,
            vec!["echo", "hello world"]
        );
    }

    #[test]
    fn double_quoted_arg_in_argv() {
        let tokens = vec![
            Token::Word("echo".to_owned()),
            Token::DoubleQuoted("hello $USER".to_owned()),
        ];
        let cl = parse(&tokens).unwrap();
        assert_eq!(
            cl.entries[0].0.commands[0].argv,
            vec!["echo", "hello $USER"]
        );
    }

    // ── EnvVar tokens in argv ─────────────────────────────────────────────

    #[test]
    fn env_var_token_in_argv_becomes_dollar_name() {
        let tokens = vec![
            Token::Word("echo".to_owned()),
            Token::EnvVar("HOME".to_owned()),
        ];
        let cl = parse(&tokens).unwrap();
        assert_eq!(cl.entries[0].0.commands[0].argv, vec!["echo", "$HOME"]);
    }

    #[test]
    fn env_var_with_default_in_argv() {
        let tokens = vec![
            Token::Word("echo".to_owned()),
            Token::EnvVar("VAR:-default".to_owned()),
        ];
        let cl = parse(&tokens).unwrap();
        assert_eq!(
            cl.entries[0].0.commands[0].argv,
            vec!["echo", "${VAR:-default}"]
        );
    }

    // ── Newline as separator ──────────────────────────────────────────────

    #[test]
    fn newline_acts_as_semicolon() {
        let cl = p("cmd1\ncmd2");
        assert_eq!(cl.entries.len(), 2);
        assert_eq!(cl.entries[0].1, Some(Connector::Semi));
    }

    // ── Mixed ─────────────────────────────────────────────────────────────

    #[test]
    fn pipeline_with_redirect() {
        let cl = p("ls -la | grep test > out.txt");
        let pipeline = &cl.entries[0].0;
        assert_eq!(pipeline.commands.len(), 2);
        let grep_cmd = &pipeline.commands[1];
        assert_eq!(grep_cmd.argv, vec!["grep", "test"]);
        assert_eq!(grep_cmd.redirects[0].kind, RedirectKind::Out);
        assert_eq!(grep_cmd.redirects[0].target, "out.txt");
    }

    #[test]
    fn consecutive_separators_are_collapsed() {
        // `cmd1 ; ; cmd2` — the double semicolons should not be an error.
        let cl = p("cmd1 ; ; cmd2");
        // We get two entries; the empty gap is skipped.
        assert_eq!(cl.entries.len(), 2);
    }

    // ── Error cases ───────────────────────────────────────────────────────

    #[test]
    fn pipe_at_start_is_error() {
        let tokens = vec![Token::Pipe, Token::Word("cat".to_owned())];
        let err = parse(&tokens).unwrap_err();
        assert_eq!(err, ParseError::EmptyPipeline);
    }

    #[test]
    fn pipe_at_end_is_error() {
        let tokens = vec![Token::Word("ls".to_owned()), Token::Pipe];
        let err = parse(&tokens).unwrap_err();
        assert_eq!(err, ParseError::EmptyPipeline);
    }

    #[test]
    fn redirect_without_target_is_error() {
        let tokens = vec![Token::Word("ls".to_owned()), Token::RedirectOut];
        let err = parse(&tokens).unwrap_err();
        assert_eq!(err, ParseError::InvalidRedirect);
    }

    #[test]
    fn redirect_followed_by_operator_is_error() {
        // `ls > ;` — the redirect target is a semicolon, which is not a word.
        let tokens = vec![
            Token::Word("ls".to_owned()),
            Token::RedirectOut,
            Token::Semicolon,
        ];
        let err = parse(&tokens).unwrap_err();
        assert_eq!(err, ParseError::InvalidRedirect);
    }

    // ── Display ───────────────────────────────────────────────────────────

    #[test]
    fn display_unexpected_token() {
        let e = ParseError::UnexpectedToken("|".to_owned());
        assert!(e.to_string().contains("unexpected token"));
    }

    #[test]
    fn display_missing_command() {
        assert!(ParseError::MissingCommand.to_string().contains("missing"));
    }

    #[test]
    fn display_empty_pipeline() {
        assert!(ParseError::EmptyPipeline.to_string().contains("pipeline"));
    }

    #[test]
    fn display_invalid_redirect() {
        assert!(ParseError::InvalidRedirect.to_string().contains("redirect"));
    }

    // ── split_env_override unit tests ─────────────────────────────────────

    #[test]
    fn split_env_override_valid() {
        assert_eq!(
            split_env_override("FOO=bar"),
            Some(("FOO".to_owned(), "bar".to_owned()))
        );
    }

    #[test]
    fn split_env_override_empty_value() {
        assert_eq!(
            split_env_override("FOO="),
            Some(("FOO".to_owned(), String::new()))
        );
    }

    #[test]
    fn split_env_override_underscore_prefix() {
        assert_eq!(
            split_env_override("_MY_VAR=x"),
            Some(("_MY_VAR".to_owned(), "x".to_owned()))
        );
    }

    #[test]
    fn split_env_override_digit_prefix_is_invalid() {
        assert_eq!(split_env_override("1FOO=bar"), None);
    }

    #[test]
    fn split_env_override_no_equals_is_invalid() {
        assert_eq!(split_env_override("FOO"), None);
    }

    #[test]
    fn split_env_override_empty_name_is_invalid() {
        assert_eq!(split_env_override("=bar"), None);
    }
}
