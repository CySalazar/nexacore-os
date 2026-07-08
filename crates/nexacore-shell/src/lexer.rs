//! Shell lexer — converts raw input text into a flat sequence of [`crate::lexer::Token`]s.
//!
//! This is the first stage of the shell's parsing pipeline:
//!
//! ```text
//! raw &str  ──►  tokenize()  ──►  Vec<Token>  ──►  parser  ──►  AST
//! ```
//!
//! The lexer is intentionally dumb: it does **not** perform glob expansion,
//! variable substitution, or arithmetic evaluation. Those concerns belong to
//! later pipeline stages ([`crate::glob`], [`crate::env`]). The lexer only
//! recognises syntactic structure.
//!
//! ## Operator precedence
//!
//! Two-character operators (`||`, `>>`, `&&`) are always preferred over their
//! single-character prefixes. The lexer peeks one character ahead whenever it
//! encounters `|`, `>`, or `&`.
//!
//! ## Quoting rules
//!
//! | Quote style | Escape processing | Variable expansion |
//! |---|---|---|
//! | Single `'...'` | None — content is 100 % literal | No |
//! | Double `"..."` | None at lex time | Deferred to [`crate::env`] |
//! | Backslash `\x` | Next character taken literally | N/A |
//!
//! ## Error handling
//!
//! The lexer returns the first [`crate::lexer::LexError`] it encounters and stops. Partial
//! token vectors are discarded.

#[cfg(not(feature = "std"))]
use alloc::{string::String, vec::Vec};

use thiserror::Error;

// ── Token ────────────────────────────────────────────────────────────────────

/// A lexical token produced from shell input.
///
/// Tokens carry enough information for the parser to reconstruct the full
/// semantic structure of a command line without looking at raw bytes again.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Token {
    /// A bare word or unquoted string fragment.
    ///
    /// Includes glob meta-characters (`*`, `?`, `[`) when they appear outside
    /// quotes — expansion is deferred to [`crate::glob`].
    Word(String),

    /// `|` — pipe: connect stdout of the left command to stdin of the right.
    Pipe,

    /// `>` — redirect stdout to a file (truncate).
    RedirectOut,

    /// `>>` — redirect stdout to a file (append).
    RedirectAppend,

    /// `<` — redirect stdin from a file.
    RedirectIn,

    /// `2>` — redirect stderr to a file.
    RedirectErr,

    /// `;` — command separator: run commands sequentially.
    Semicolon,

    /// `&` — background operator: run the preceding command in the background.
    Ampersand,

    /// `&&` — logical AND: run the right command only if the left succeeds.
    DoubleAmpersand,

    /// `||` — logical OR: run the right command only if the left fails.
    DoublePipe,

    /// `\n` — newline, used as a command terminator.
    Newline,

    /// Content between single quotes — literal, no escape or variable
    /// processing whatsoever.
    SingleQuoted(String),

    /// Content between double quotes — variable references (`$VAR`) are
    /// preserved as-is for later expansion by [`crate::env`].
    DoubleQuoted(String),

    /// An environment-variable reference: `$VAR`, `${VAR}`, or
    /// `${VAR:-default}`.
    ///
    /// The inner `String` is the raw specifier *without* the leading `$` or
    /// surrounding `{}`. For `${VAR:-default}` it is `"VAR:-default"`.
    EnvVar(String),
}

// ── LexError ─────────────────────────────────────────────────────────────────

/// Errors that the lexer can produce.
///
/// All variants are non-exhaustive from a semantic standpoint but exhaustively
/// listed here; callers should handle each arm explicitly.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum LexError {
    /// A single-quoted string was opened but the closing `'` was never found.
    #[error("unterminated single quote")]
    UnterminatedSingleQuote,

    /// A double-quoted string was opened but the closing `"` was never found.
    #[error("unterminated double quote")]
    UnterminatedDoubleQuote,

    /// The lexer encountered a character it cannot classify in the current
    /// context. Currently unused; reserved for future restricted-character
    /// handling.
    #[error("unexpected character: {0:?}")]
    UnexpectedChar(char),
}

// ── Internal lexer state ──────────────────────────────────────────────────────

/// Mutable state threaded through every helper in the tokeniser.
///
/// Using a struct keeps the helpers' signatures tidy: each helper receives
/// `&mut LexState` and mutates `pos`, `tokens`, and `word_buf` in-place.
struct LexState<'a> {
    /// The input as a slice of `char` so we can index by codepoint.
    chars: &'a [char],
    /// Current position (codepoint index) into `chars`.
    pos: usize,
    /// Accumulator for the current unquoted word being assembled.
    word_buf: String,
    /// Output token list.
    tokens: Vec<Token>,
}

impl<'a> LexState<'a> {
    /// Construct a new lexer state for the given char slice.
    fn new(chars: &'a [char]) -> Self {
        Self {
            chars,
            pos: 0,
            word_buf: String::new(),
            tokens: Vec::new(),
        }
    }

    /// Return the character at `pos`, or `None` if at end.
    fn current(&self) -> Option<char> {
        self.chars.get(self.pos).copied()
    }

    /// Return the character at `pos + 1` (peek ahead), or `None`.
    fn peek_next(&self) -> Option<char> {
        self.chars.get(self.pos + 1).copied()
    }

    /// Advance position by `n`.
    fn advance(&mut self, n: usize) {
        self.pos += n;
    }

    /// If `word_buf` is non-empty, emit it as a `Token::Word` and reset.
    fn flush_word(&mut self) {
        if !self.word_buf.is_empty() {
            self.tokens
                .push(Token::Word(core::mem::take(&mut self.word_buf)));
        }
    }

    /// Push a single character into `word_buf`.
    fn push_word_char(&mut self, c: char) {
        self.word_buf.push(c);
    }

    /// Emit an operator token (after flushing any pending word).
    fn emit(&mut self, token: Token) {
        self.flush_word();
        self.tokens.push(token);
    }
}

// ── tokenize ─────────────────────────────────────────────────────────────────

/// Tokenise a shell input string into a flat sequence of [`Token`]s.
///
/// # Behaviour summary
///
/// - Leading / trailing whitespace (space, tab) is ignored.
/// - `#` outside of quotes starts a comment that extends to end-of-line.
/// - Operators (`|`, `||`, `>`, `>>`, `<`, `2>`, `;`, `&`, `&&`, `\n`) are
///   emitted as dedicated token variants; two-character operators take
///   precedence over single-character ones.
/// - `$VAR`, `${VAR}`, and `${VAR:-default}` emit [`Token::EnvVar`].
/// - Single-quoted strings are literal; double-quoted strings preserve `$`
///   references for later variable expansion.
/// - A backslash escapes the immediately following character into the current
///   word accumulator; a trailing backslash at end-of-input is included
///   literally.
/// - Glob characters (`*`, `?`, `[`) are accumulated into [`Token::Word`].
/// - An empty or all-whitespace input returns an empty `Vec`.
///
/// # Errors
///
/// Returns [`LexError::UnterminatedSingleQuote`] or
/// [`LexError::UnterminatedDoubleQuote`] if a quoted string is not closed
/// before the end of input.
///
/// # Examples
///
/// ```rust
/// use nexacore_shell::lexer::{Token, tokenize};
///
/// let tokens = tokenize("echo hello").unwrap();
/// assert_eq!(
///     tokens,
///     vec![Token::Word("echo".into()), Token::Word("hello".into())]
/// );
/// ```
///
/// ```rust
/// use nexacore_shell::lexer::{Token, tokenize};
///
/// let tokens = tokenize("ls | grep rs").unwrap();
/// assert_eq!(
///     tokens,
///     vec![
///         Token::Word("ls".into()),
///         Token::Pipe,
///         Token::Word("grep".into()),
///         Token::Word("rs".into()),
///     ]
/// );
/// ```
///
/// ```rust
/// use nexacore_shell::lexer::{LexError, tokenize};
///
/// let err = tokenize("echo 'unterminated").unwrap_err();
/// assert_eq!(err, LexError::UnterminatedSingleQuote);
/// ```
pub fn tokenize(input: &str) -> Result<Vec<Token>, LexError> {
    let chars: Vec<char> = input.chars().collect();
    let mut st = LexState::new(&chars);

    while st.pos < st.chars.len() {
        let Some(ch) = st.current() else { break };
        lex_one(&mut st, ch)?;
    }

    st.flush_word();
    Ok(st.tokens)
}

// ── Per-character dispatch ────────────────────────────────────────────────────

/// Dispatch a single character to the appropriate handler.
///
/// This is the top-level inner loop body, split out so that `tokenize` itself
/// stays below the cognitive-complexity threshold.
fn lex_one(st: &mut LexState<'_>, ch: char) -> Result<(), LexError> {
    match ch {
        ' ' | '\t' => {
            st.flush_word();
            st.advance(1);
        }
        '\n' => {
            st.emit(Token::Newline);
            st.advance(1);
        }
        '#' => lex_comment(st),
        '\\' => lex_backslash(st),
        '\'' => lex_single_quote(st)?,
        '"' => lex_double_quote(st)?,
        '|' => lex_pipe(st),
        '>' => lex_redirect_out(st),
        '<' => {
            st.emit(Token::RedirectIn);
            st.advance(1);
        }
        ';' => {
            st.emit(Token::Semicolon);
            st.advance(1);
        }
        '&' => lex_ampersand(st),
        '$' => lex_env_var(st),
        // `2>` stderr redirect: only when the *next* character is `>`.
        '2' if st.peek_next() == Some('>') => {
            st.emit(Token::RedirectErr);
            st.advance(2);
        }
        _ => {
            st.push_word_char(ch);
            st.advance(1);
        }
    }
    Ok(())
}

// ── Individual token handlers ─────────────────────────────────────────────────

/// Skip a `#`-introduced comment up to (but not including) the newline.
fn lex_comment(st: &mut LexState<'_>) {
    st.flush_word();
    // Advance past '#' and all characters until newline or end-of-input.
    while st.pos < st.chars.len() && st.current() != Some('\n') {
        st.advance(1);
    }
    // The '\n' itself (if present) is left for the next iteration so it gets
    // emitted as Token::Newline.
}

/// Handle a backslash escape: include the *next* character literally.
fn lex_backslash(st: &mut LexState<'_>) {
    if let Some(next) = st.peek_next() {
        st.push_word_char(next);
        st.advance(2);
    } else {
        // Trailing backslash at end-of-input: include it literally.
        st.push_word_char('\\');
        st.advance(1);
    }
}

/// Lex a single-quoted string `'...'`.
///
/// Everything inside is literal — no escape processing, no variable expansion.
fn lex_single_quote(st: &mut LexState<'_>) -> Result<(), LexError> {
    st.flush_word();
    st.advance(1); // consume opening `'`
    let content = collect_until(st, '\'')?;
    st.tokens.push(Token::SingleQuoted(content));
    st.advance(1); // consume closing `'`
    Ok(())
}

/// Lex a double-quoted string `"..."`.
///
/// Content is preserved verbatim (including `$VAR` references) for later
/// expansion by [`crate::env`].
fn lex_double_quote(st: &mut LexState<'_>) -> Result<(), LexError> {
    st.flush_word();
    st.advance(1); // consume opening `"`
    let content = collect_until_double_quote(st)?;
    st.tokens.push(Token::DoubleQuoted(content));
    st.advance(1); // consume closing `"`
    Ok(())
}

/// Lex `|` or `||`.
fn lex_pipe(st: &mut LexState<'_>) {
    if st.peek_next() == Some('|') {
        st.emit(Token::DoublePipe);
        st.advance(2);
    } else {
        st.emit(Token::Pipe);
        st.advance(1);
    }
}

/// Lex `>` or `>>`.
fn lex_redirect_out(st: &mut LexState<'_>) {
    if st.peek_next() == Some('>') {
        st.emit(Token::RedirectAppend);
        st.advance(2);
    } else {
        st.emit(Token::RedirectOut);
        st.advance(1);
    }
}

/// Lex `&` or `&&`.
fn lex_ampersand(st: &mut LexState<'_>) {
    if st.peek_next() == Some('&') {
        st.emit(Token::DoubleAmpersand);
        st.advance(2);
    } else {
        st.emit(Token::Ampersand);
        st.advance(1);
    }
}

/// Lex `$VAR`, `${VAR}`, or `${VAR:-default}`.
fn lex_env_var(st: &mut LexState<'_>) {
    // A `$` in the middle of an accumulated word flushes first, so that
    // `foo$BAR` produces `[Word("foo"), EnvVar("BAR")]`.
    st.flush_word();
    st.advance(1); // consume '$'

    if st.current() == Some('{') {
        lex_env_var_braced(st);
    } else {
        lex_env_var_bare(st);
    }
}

/// Lex the braced form `${VAR}` or `${VAR:-default}`.
fn lex_env_var_braced(st: &mut LexState<'_>) {
    st.advance(1); // consume '{'
    let mut spec = String::new();
    while st.pos < st.chars.len() && st.current() != Some('}') {
        if let Some(c) = st.current() {
            spec.push(c);
        }
        st.advance(1);
    }
    if st.current() == Some('}') {
        st.advance(1); // consume '}'
    }
    // If '}' is absent we still emit what we collected; a future
    // LexError::UnterminatedBrace can be added without breaking callers.
    st.tokens.push(Token::EnvVar(spec));
}

/// Lex the bare form `$VAR` — identifier chars are `[A-Za-z0-9_]`.
fn lex_env_var_bare(st: &mut LexState<'_>) {
    let mut name = String::new();
    while let Some(c) = st.current() {
        if is_ident_char(c) {
            name.push(c);
            st.advance(1);
        } else {
            break;
        }
    }
    st.tokens.push(Token::EnvVar(name));
}

// ── Shared helpers ────────────────────────────────────────────────────────────

/// Collect characters until `terminator` is reached.
///
/// Used for single-quoted strings. Returns `Err` if end-of-input is reached
/// before `terminator`.
fn collect_until(st: &mut LexState<'_>, terminator: char) -> Result<String, LexError> {
    let mut buf = String::new();
    while st.pos < st.chars.len() && st.current() != Some(terminator) {
        if let Some(c) = st.current() {
            buf.push(c);
        }
        st.advance(1);
    }
    if st.current() != Some(terminator) {
        return Err(LexError::UnterminatedSingleQuote);
    }
    Ok(buf)
}

/// Collect characters until `"` is reached.
///
/// Identical logic to [`collect_until`] but returns
/// [`LexError::UnterminatedDoubleQuote`] on EOF.
fn collect_until_double_quote(st: &mut LexState<'_>) -> Result<String, LexError> {
    let mut buf = String::new();
    while st.pos < st.chars.len() && st.current() != Some('"') {
        if let Some(c) = st.current() {
            buf.push(c);
        }
        st.advance(1);
    }
    if st.current() != Some('"') {
        return Err(LexError::UnterminatedDoubleQuote);
    }
    Ok(buf)
}

/// Returns `true` if `c` is a valid environment-variable identifier character.
///
/// Matches POSIX: `[A-Za-z0-9_]`.
#[inline]
fn is_ident_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '_'
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // Convenience constructors so test assertions stay compact.
    fn w(s: &str) -> Token {
        Token::Word(s.to_owned())
    }
    fn sq(s: &str) -> Token {
        Token::SingleQuoted(s.to_owned())
    }
    fn dq(s: &str) -> Token {
        Token::DoubleQuoted(s.to_owned())
    }
    fn ev(s: &str) -> Token {
        Token::EnvVar(s.to_owned())
    }

    // ── Basic ─────────────────────────────────────────────────────────────

    #[test]
    fn empty_input_returns_empty_vec() {
        assert_eq!(tokenize("").unwrap(), vec![]);
    }

    #[test]
    fn whitespace_only_returns_empty_vec() {
        assert_eq!(tokenize("   \t  ").unwrap(), vec![]);
    }

    #[test]
    fn single_word() {
        assert_eq!(tokenize("ls").unwrap(), vec![w("ls")]);
    }

    #[test]
    fn multiple_words() {
        assert_eq!(tokenize("ls -la").unwrap(), vec![w("ls"), w("-la")]);
    }

    #[test]
    fn multiple_words_extra_spaces() {
        assert_eq!(tokenize("  ls   -la  ").unwrap(), vec![w("ls"), w("-la")]);
    }

    // ── Operators ─────────────────────────────────────────────────────────

    #[test]
    fn pipe_operator() {
        assert_eq!(
            tokenize("ls | cat").unwrap(),
            vec![w("ls"), Token::Pipe, w("cat")]
        );
    }

    #[test]
    fn double_pipe_operator() {
        assert_eq!(
            tokenize("cmd1 || cmd2").unwrap(),
            vec![w("cmd1"), Token::DoublePipe, w("cmd2")]
        );
    }

    #[test]
    fn redirect_out() {
        assert_eq!(
            tokenize("ls > file").unwrap(),
            vec![w("ls"), Token::RedirectOut, w("file")]
        );
    }

    #[test]
    fn redirect_append() {
        assert_eq!(
            tokenize("ls >> file").unwrap(),
            vec![w("ls"), Token::RedirectAppend, w("file")]
        );
    }

    #[test]
    fn redirect_in() {
        assert_eq!(
            tokenize("cat < file").unwrap(),
            vec![w("cat"), Token::RedirectIn, w("file")]
        );
    }

    #[test]
    fn redirect_stderr() {
        assert_eq!(
            tokenize("cmd 2> err.log").unwrap(),
            vec![w("cmd"), Token::RedirectErr, w("err.log")]
        );
    }

    #[test]
    fn semicolon_separator() {
        assert_eq!(
            tokenize("echo a; echo b").unwrap(),
            vec![w("echo"), w("a"), Token::Semicolon, w("echo"), w("b")]
        );
    }

    #[test]
    fn ampersand_background() {
        assert_eq!(
            tokenize("sleep 10 &").unwrap(),
            vec![w("sleep"), w("10"), Token::Ampersand]
        );
    }

    #[test]
    fn double_ampersand_and() {
        assert_eq!(
            tokenize("make && ./run").unwrap(),
            vec![w("make"), Token::DoubleAmpersand, w("./run")]
        );
    }

    #[test]
    fn newline_as_separator() {
        assert_eq!(
            tokenize("echo a\necho b").unwrap(),
            vec![w("echo"), w("a"), Token::Newline, w("echo"), w("b")]
        );
    }

    // ── Quoting ───────────────────────────────────────────────────────────

    #[test]
    fn single_quoted_string() {
        assert_eq!(
            tokenize("echo 'hello world'").unwrap(),
            vec![w("echo"), sq("hello world")]
        );
    }

    #[test]
    fn single_quoted_preserves_special_chars() {
        // Inside single quotes, operators and $ are literal.
        assert_eq!(
            tokenize("echo '$HOME | ls'").unwrap(),
            vec![w("echo"), sq("$HOME | ls")]
        );
    }

    #[test]
    fn double_quoted_string() {
        assert_eq!(
            tokenize("echo \"hello $USER\"").unwrap(),
            vec![w("echo"), dq("hello $USER")]
        );
    }

    #[test]
    fn unterminated_single_quote_is_error() {
        assert_eq!(
            tokenize("echo 'unterminated").unwrap_err(),
            LexError::UnterminatedSingleQuote
        );
    }

    #[test]
    fn unterminated_double_quote_is_error() {
        assert_eq!(
            tokenize("echo \"unterminated").unwrap_err(),
            LexError::UnterminatedDoubleQuote
        );
    }

    // ── Backslash escape ──────────────────────────────────────────────────

    #[test]
    fn backslash_escape_space() {
        // `echo hello\ world` produces one word "hello world".
        assert_eq!(
            tokenize("echo hello\\ world").unwrap(),
            vec![w("echo"), w("hello world")]
        );
    }

    #[test]
    fn backslash_escape_operator() {
        // `echo a\|b` — the pipe is escaped, becomes a literal word character.
        assert_eq!(tokenize("echo a\\|b").unwrap(), vec![w("echo"), w("a|b")]);
    }

    #[test]
    fn trailing_backslash_included_literally() {
        assert_eq!(tokenize("echo foo\\").unwrap(), vec![w("echo"), w("foo\\")]);
    }

    // ── Comments ──────────────────────────────────────────────────────────

    #[test]
    fn hash_starts_comment() {
        assert_eq!(
            tokenize("echo hello # this is a comment").unwrap(),
            vec![w("echo"), w("hello")]
        );
    }

    #[test]
    fn comment_followed_by_newline_then_command() {
        assert_eq!(
            tokenize("echo a # comment\necho b").unwrap(),
            vec![w("echo"), w("a"), Token::Newline, w("echo"), w("b")]
        );
    }

    // ── Environment variables ─────────────────────────────────────────────

    #[test]
    fn bare_env_var() {
        assert_eq!(tokenize("echo $HOME").unwrap(), vec![w("echo"), ev("HOME")]);
    }

    #[test]
    fn braced_env_var() {
        assert_eq!(
            tokenize("echo ${PATH}").unwrap(),
            vec![w("echo"), ev("PATH")]
        );
    }

    #[test]
    fn braced_env_var_with_default() {
        // The specifier inside `${}` is captured verbatim, colon-minus and all.
        let input = concat!("echo ${VAR", ":-default}");
        assert_eq!(
            tokenize(input).unwrap(),
            vec![w("echo"), ev("VAR:-default")]
        );
    }

    // ── Glob characters ───────────────────────────────────────────────────

    #[test]
    fn glob_star_in_word() {
        assert_eq!(tokenize("*.rs").unwrap(), vec![w("*.rs")]);
    }

    #[test]
    fn glob_question_mark_in_word() {
        assert_eq!(tokenize("file?.txt").unwrap(), vec![w("file?.txt")]);
    }

    #[test]
    fn glob_bracket_in_word() {
        assert_eq!(tokenize("[abc]*").unwrap(), vec![w("[abc]*")]);
    }

    // ── Mixed / compound ──────────────────────────────────────────────────

    #[test]
    fn complex_pipeline() {
        let tokens = tokenize("ls -la | grep \"test\" > out.txt").unwrap();
        assert_eq!(
            tokens,
            vec![
                w("ls"),
                w("-la"),
                Token::Pipe,
                w("grep"),
                dq("test"),
                Token::RedirectOut,
                w("out.txt"),
            ]
        );
    }

    #[test]
    fn multiple_operators_in_sequence() {
        // `cmd1; cmd2 && cmd3 || cmd4`
        let tokens = tokenize("cmd1; cmd2 && cmd3 || cmd4").unwrap();
        assert_eq!(
            tokens,
            vec![
                w("cmd1"),
                Token::Semicolon,
                w("cmd2"),
                Token::DoubleAmpersand,
                w("cmd3"),
                Token::DoublePipe,
                w("cmd4"),
            ]
        );
    }

    #[test]
    fn adjacent_single_and_double_quotes() {
        // `'hello'"world"` — two adjacent quoted tokens, no separator.
        let tokens = tokenize("'hello'\"world\"").unwrap();
        assert_eq!(tokens, vec![sq("hello"), dq("world")]);
    }

    #[test]
    fn env_var_adjacent_to_word() {
        // `foo$BAR` — word then env var, no space.
        let tokens = tokenize("foo$BAR").unwrap();
        assert_eq!(tokens, vec![w("foo"), ev("BAR")]);
    }

    #[test]
    fn stderr_redirect_no_space() {
        // `cmd2>err` — the `2>` sequence is recognised inside a word boundary.
        let tokens = tokenize("cmd2>err").unwrap();
        assert_eq!(tokens, vec![w("cmd"), Token::RedirectErr, w("err")]);
    }

    // ── LexError Display ──────────────────────────────────────────────────

    #[test]
    fn display_unterminated_single_quote() {
        let msg = LexError::UnterminatedSingleQuote.to_string();
        assert_eq!(msg, "unterminated single quote");
    }

    #[test]
    fn display_unterminated_double_quote() {
        let msg = LexError::UnterminatedDoubleQuote.to_string();
        assert_eq!(msg, "unterminated double quote");
    }

    #[test]
    fn display_unexpected_char() {
        let msg = LexError::UnexpectedChar('\x00').to_string();
        assert!(msg.contains("unexpected character"));
    }
}
