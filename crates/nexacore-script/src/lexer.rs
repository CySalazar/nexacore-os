//! ncScript lexer (WS18-02.2) — turns source text into a token stream per
//! the lexical rules of the `NCIP-ncScript-030` § S13 grammar.
//!
//! Handles keywords, identifiers, integer / float / string / bool literals,
//! all single- and multi-character operators, line (`//`) and nestable block
//! (`/* … */`) comments, the `#![capabilities(...)]` attribute opener, loop
//! labels (`'name`), and an optional leading `#!` shebang line. Whitespace and
//! comments are discarded; every emitted token carries its 1-based line/column
//! for diagnostics.

use alloc::{string::String, vec::Vec};

/// A lexical token.
#[derive(Debug, Clone, PartialEq)]
pub enum Token {
    // ---- literals ----
    /// Integer literal.
    Int(i64),
    /// Float literal.
    Float(f64),
    /// String literal (escapes already decoded).
    Str(String),
    /// Boolean literal.
    Bool(bool),
    /// Identifier.
    Ident(String),
    /// Loop label, e.g. `'outer` (carries the name without the quote).
    Label(String),

    // ---- keywords ----
    /// `let`
    Let,
    /// `mut`
    Mut,
    /// `fn`
    Fn,
    /// `struct`
    Struct,
    /// `enum`
    Enum,
    /// `const`
    Const,
    /// `impl`
    Impl,
    /// `use`
    Use,
    /// `while`
    While,
    /// `for`
    For,
    /// `in`
    In,
    /// `loop`
    Loop,
    /// `if`
    If,
    /// `else`
    Else,
    /// `match`
    Match,
    /// `self`
    SelfKw,
    /// `scope`
    Scope,
    /// `spawn`
    Spawn,
    /// `await`
    Await,
    /// `return`
    Return,
    /// `break`
    Break,
    /// `continue`
    Continue,
    /// `as`
    As,
    /// `where`
    Where,

    // ---- punctuation ----
    /// `|`
    Pipe,
    /// `(`
    LParen,
    /// `)`
    RParen,
    /// `{`
    LBrace,
    /// `}`
    RBrace,
    /// `[`
    LBracket,
    /// `]`
    RBracket,
    /// `,`
    Comma,
    /// `;`
    Semicolon,
    /// `:`
    Colon,
    /// `::`
    ColonColon,
    /// `.`
    Dot,
    /// `->`
    Arrow,
    /// `=>`
    FatArrow,
    /// `?`
    Question,
    /// `_`
    Underscore,
    /// `#![` — opens an inner attribute (the capability header).
    AttrOpen,

    // ---- operators ----
    /// `=`
    Assign,
    /// `+=`
    PlusEq,
    /// `-=`
    MinusEq,
    /// `*=`
    StarEq,
    /// `/=`
    SlashEq,
    /// `%=`
    PercentEq,
    /// `==`
    EqEq,
    /// `!=`
    NotEq,
    /// `<`
    Lt,
    /// `<=`
    Le,
    /// `>`
    Gt,
    /// `>=`
    Ge,
    /// `&&`
    AndAnd,
    /// `||`
    OrOr,
    /// `!`
    Not,
    /// `+`
    Plus,
    /// `-`
    Minus,
    /// `*`
    Star,
    /// `/`
    Slash,
    /// `%`
    Percent,
}

/// A token with its source position (1-based line and column).
#[derive(Debug, Clone, PartialEq)]
pub struct SpannedToken {
    /// The token.
    pub token: Token,
    /// 1-based line.
    pub line: u32,
    /// 1-based column (in characters).
    pub col: u32,
}

/// What went wrong while lexing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LexErrorKind {
    /// A character that cannot begin any token.
    UnexpectedChar(char),
    /// A string literal without a closing quote.
    UnterminatedString,
    /// A block comment without a closing `*/`.
    UnterminatedBlockComment,
    /// An invalid escape sequence inside a string.
    InvalidEscape(char),
    /// A numeric literal that failed to parse.
    InvalidNumber,
    /// A `'` not followed by a label identifier.
    InvalidLabel,
}

/// A lexer error with position.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LexError {
    /// What went wrong.
    pub kind: LexErrorKind,
    /// 1-based line.
    pub line: u32,
    /// 1-based column.
    pub col: u32,
}

impl core::fmt::Display for LexError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "lex error at {}:{}: ", self.line, self.col)?;
        match &self.kind {
            LexErrorKind::UnexpectedChar(c) => write!(f, "unexpected character {c:?}"),
            LexErrorKind::UnterminatedString => f.write_str("unterminated string literal"),
            LexErrorKind::UnterminatedBlockComment => f.write_str("unterminated block comment"),
            LexErrorKind::InvalidEscape(c) => write!(f, "invalid escape '\\{c}'"),
            LexErrorKind::InvalidNumber => f.write_str("invalid numeric literal"),
            LexErrorKind::InvalidLabel => f.write_str("expected identifier after `'`"),
        }
    }
}

impl core::error::Error for LexError {}

/// Map an identifier to its keyword token, or `None` if it is a plain ident.
fn keyword(s: &str) -> Option<Token> {
    Some(match s {
        "let" => Token::Let,
        "mut" => Token::Mut,
        "fn" => Token::Fn,
        "struct" => Token::Struct,
        "enum" => Token::Enum,
        "const" => Token::Const,
        "impl" => Token::Impl,
        "use" => Token::Use,
        "while" => Token::While,
        "for" => Token::For,
        "in" => Token::In,
        "loop" => Token::Loop,
        "if" => Token::If,
        "else" => Token::Else,
        "match" => Token::Match,
        "self" => Token::SelfKw,
        "scope" => Token::Scope,
        "spawn" => Token::Spawn,
        "await" => Token::Await,
        "return" => Token::Return,
        "break" => Token::Break,
        "continue" => Token::Continue,
        "as" => Token::As,
        "where" => Token::Where,
        "true" => Token::Bool(true),
        "false" => Token::Bool(false),
        _ => return None,
    })
}

struct Lexer {
    chars: Vec<char>,
    pos: usize,
    line: u32,
    col: u32,
    out: Vec<SpannedToken>,
}

impl Lexer {
    fn new(src: &str) -> Self {
        Self {
            chars: src.chars().collect(),
            pos: 0,
            line: 1,
            col: 1,
            out: Vec::new(),
        }
    }

    fn peek(&self) -> Option<char> {
        self.chars.get(self.pos).copied()
    }

    fn peek_at(&self, n: usize) -> Option<char> {
        self.chars.get(self.pos + n).copied()
    }

    /// Advance one character, tracking line/column.
    fn bump(&mut self) -> Option<char> {
        let c = self.chars.get(self.pos).copied()?;
        self.pos += 1;
        if c == '\n' {
            self.line += 1;
            self.col = 1;
        } else {
            self.col += 1;
        }
        Some(c)
    }

    fn err(&self, kind: LexErrorKind, line: u32, col: u32) -> LexError {
        let _ = self;
        LexError { kind, line, col }
    }

    fn push(&mut self, token: Token, line: u32, col: u32) {
        self.out.push(SpannedToken { token, line, col });
    }

    fn run(mut self) -> Result<Vec<SpannedToken>, LexError> {
        // Optional shebang on the very first line: `#!` not followed by `[`.
        if self.pos == 0
            && self.peek() == Some('#')
            && self.peek_at(1) == Some('!')
            && self.peek_at(2) != Some('[')
        {
            while let Some(c) = self.peek() {
                if c == '\n' {
                    break;
                }
                self.bump();
            }
        }

        loop {
            self.skip_trivia()?;
            let (line, col) = (self.line, self.col);
            let Some(c) = self.peek() else { break };
            match c {
                '"' => self.lex_string()?,
                '\'' => self.lex_label()?,
                c if c.is_ascii_digit() => self.lex_number()?,
                c if c == '_' || c.is_ascii_alphabetic() => self.lex_ident_or_keyword(),
                '#' => {
                    // Only `#![` is valid here (shebang handled above).
                    if self.peek_at(1) == Some('!') && self.peek_at(2) == Some('[') {
                        self.bump();
                        self.bump();
                        self.bump();
                        self.push(Token::AttrOpen, line, col);
                    } else {
                        return Err(self.err(LexErrorKind::UnexpectedChar('#'), line, col));
                    }
                }
                _ => self.lex_operator(c, line, col)?,
            }
        }
        Ok(self.out)
    }

    /// Skip whitespace and comments (line + nestable block).
    fn skip_trivia(&mut self) -> Result<(), LexError> {
        loop {
            match self.peek() {
                Some(c) if c.is_whitespace() => {
                    self.bump();
                }
                Some('/') if self.peek_at(1) == Some('/') => {
                    while let Some(c) = self.peek() {
                        if c == '\n' {
                            break;
                        }
                        self.bump();
                    }
                }
                Some('/') if self.peek_at(1) == Some('*') => {
                    let (line, col) = (self.line, self.col);
                    self.bump();
                    self.bump();
                    let mut depth = 1u32;
                    while depth > 0 {
                        match self.peek() {
                            None => {
                                return Err(self.err(
                                    LexErrorKind::UnterminatedBlockComment,
                                    line,
                                    col,
                                ));
                            }
                            Some('/') if self.peek_at(1) == Some('*') => {
                                self.bump();
                                self.bump();
                                depth += 1;
                            }
                            Some('*') if self.peek_at(1) == Some('/') => {
                                self.bump();
                                self.bump();
                                depth -= 1;
                            }
                            _ => {
                                self.bump();
                            }
                        }
                    }
                }
                _ => return Ok(()),
            }
        }
    }

    fn lex_string(&mut self) -> Result<(), LexError> {
        let (line, col) = (self.line, self.col);
        self.bump(); // opening quote
        let mut s = String::new();
        loop {
            match self.bump() {
                None => return Err(self.err(LexErrorKind::UnterminatedString, line, col)),
                Some('"') => break,
                Some('\\') => {
                    let (eline, ecol) = (self.line, self.col);
                    match self.bump() {
                        Some('n') => s.push('\n'),
                        Some('t') => s.push('\t'),
                        Some('r') => s.push('\r'),
                        Some('\\') => s.push('\\'),
                        Some('"') => s.push('"'),
                        Some('0') => s.push('\0'),
                        Some(other) => {
                            return Err(self.err(LexErrorKind::InvalidEscape(other), eline, ecol));
                        }
                        None => return Err(self.err(LexErrorKind::UnterminatedString, line, col)),
                    }
                }
                Some(c) => s.push(c),
            }
        }
        self.push(Token::Str(s), line, col);
        Ok(())
    }

    #[allow(
        clippy::indexing_slicing,
        reason = "start..self.pos is always an in-bounds sub-slice of self.chars"
    )]
    fn lex_label(&mut self) -> Result<(), LexError> {
        let (line, col) = (self.line, self.col);
        self.bump(); // the quote
        let start = self.pos;
        if !matches!(self.peek(), Some(c) if c == '_' || c.is_ascii_alphabetic()) {
            return Err(self.err(LexErrorKind::InvalidLabel, line, col));
        }
        while matches!(self.peek(), Some(c) if c == '_' || c.is_ascii_alphanumeric()) {
            self.bump();
        }
        let name: String = self.chars[start..self.pos].iter().collect();
        self.push(Token::Label(name), line, col);
        Ok(())
    }

    #[allow(
        clippy::indexing_slicing,
        reason = "start..self.pos is always an in-bounds sub-slice of self.chars"
    )]
    fn lex_ident_or_keyword(&mut self) {
        let (line, col) = (self.line, self.col);
        let start = self.pos;
        while matches!(self.peek(), Some(c) if c == '_' || c.is_ascii_alphanumeric()) {
            self.bump();
        }
        let word: String = self.chars[start..self.pos].iter().collect();
        let tok = if word == "_" {
            Token::Underscore
        } else if let Some(kw) = keyword(&word) {
            kw
        } else {
            Token::Ident(word)
        };
        self.push(tok, line, col);
    }

    #[allow(
        clippy::indexing_slicing,
        reason = "start..self.pos is always an in-bounds sub-slice of self.chars"
    )]
    #[allow(
        clippy::cognitive_complexity,
        reason = "hex/decimal/float/exponent are clearest as one linear scan"
    )]
    fn lex_number(&mut self) -> Result<(), LexError> {
        let (line, col) = (self.line, self.col);
        let start = self.pos;

        // Hex integer: 0x...
        if self.peek() == Some('0') && matches!(self.peek_at(1), Some('x' | 'X')) {
            self.bump();
            self.bump();
            let hstart = self.pos;
            while matches!(self.peek(), Some(c) if c.is_ascii_hexdigit() || c == '_') {
                self.bump();
            }
            let digits: String = self.chars[hstart..self.pos]
                .iter()
                .filter(|c| **c != '_')
                .collect();
            let v = i64::from_str_radix(&digits, 16)
                .map_err(|_| self.err(LexErrorKind::InvalidNumber, line, col))?;
            self.push(Token::Int(v), line, col);
            return Ok(());
        }

        // Decimal integer part.
        while matches!(self.peek(), Some(c) if c.is_ascii_digit() || c == '_') {
            self.bump();
        }

        // Float: a `.` followed by a digit (so `5.foo` stays int + dot + ident).
        let is_float =
            self.peek() == Some('.') && matches!(self.peek_at(1), Some(c) if c.is_ascii_digit());
        if is_float {
            self.bump(); // '.'
            while matches!(self.peek(), Some(c) if c.is_ascii_digit() || c == '_') {
                self.bump();
            }
            // Optional exponent.
            if matches!(self.peek(), Some('e' | 'E')) {
                self.bump();
                if matches!(self.peek(), Some('+' | '-')) {
                    self.bump();
                }
                while matches!(self.peek(), Some(c) if c.is_ascii_digit()) {
                    self.bump();
                }
            }
            let text: String = self.chars[start..self.pos]
                .iter()
                .filter(|c| **c != '_')
                .collect();
            let v: f64 = text
                .parse()
                .map_err(|_| self.err(LexErrorKind::InvalidNumber, line, col))?;
            self.push(Token::Float(v), line, col);
        } else {
            let text: String = self.chars[start..self.pos]
                .iter()
                .filter(|c| **c != '_')
                .collect();
            let v: i64 = text
                .parse()
                .map_err(|_| self.err(LexErrorKind::InvalidNumber, line, col))?;
            self.push(Token::Int(v), line, col);
        }
        Ok(())
    }

    /// Lex a single- or multi-character operator / punctuation token.
    #[allow(
        clippy::cognitive_complexity,
        reason = "a flat match over the operator alphabet is clearer than splitting it"
    )]
    fn lex_operator(&mut self, c: char, line: u32, col: u32) -> Result<(), LexError> {
        let next = self.peek_at(1);
        // Two-character tokens first.
        let two = match (c, next) {
            (':', Some(':')) => Some(Token::ColonColon),
            ('-', Some('>')) => Some(Token::Arrow),
            ('=', Some('>')) => Some(Token::FatArrow),
            ('=', Some('=')) => Some(Token::EqEq),
            ('!', Some('=')) => Some(Token::NotEq),
            ('<', Some('=')) => Some(Token::Le),
            ('>', Some('=')) => Some(Token::Ge),
            ('&', Some('&')) => Some(Token::AndAnd),
            ('|', Some('|')) => Some(Token::OrOr),
            ('+', Some('=')) => Some(Token::PlusEq),
            ('-', Some('=')) => Some(Token::MinusEq),
            ('*', Some('=')) => Some(Token::StarEq),
            ('/', Some('=')) => Some(Token::SlashEq),
            ('%', Some('=')) => Some(Token::PercentEq),
            _ => None,
        };
        if let Some(tok) = two {
            self.bump();
            self.bump();
            self.push(tok, line, col);
            return Ok(());
        }
        // Single-character tokens.
        let one = match c {
            '(' => Token::LParen,
            ')' => Token::RParen,
            '{' => Token::LBrace,
            '}' => Token::RBrace,
            '[' => Token::LBracket,
            ']' => Token::RBracket,
            ',' => Token::Comma,
            ';' => Token::Semicolon,
            ':' => Token::Colon,
            '.' => Token::Dot,
            '?' => Token::Question,
            '=' => Token::Assign,
            '<' => Token::Lt,
            '>' => Token::Gt,
            '!' => Token::Not,
            '+' => Token::Plus,
            '-' => Token::Minus,
            '*' => Token::Star,
            '/' => Token::Slash,
            '%' => Token::Percent,
            '|' => Token::Pipe,
            other => return Err(self.err(LexErrorKind::UnexpectedChar(other), line, col)),
        };
        self.bump();
        self.push(one, line, col);
        Ok(())
    }
}

/// Tokenize ncScript source into a stream of [`SpannedToken`].
///
/// # Errors
///
/// Returns the first [`LexError`] encountered (unterminated string/comment,
/// invalid escape/number, or an unexpected character).
pub fn tokenize(src: &str) -> Result<Vec<SpannedToken>, LexError> {
    Lexer::new(src).run()
}

#[cfg(test)]
mod tests {
    use alloc::{vec, vec::Vec};

    use super::*;

    fn toks(src: &str) -> Vec<Token> {
        tokenize(src)
            .unwrap()
            .into_iter()
            .map(|s| s.token)
            .collect()
    }

    #[test]
    fn empty_and_whitespace_yield_no_tokens() {
        assert!(toks("").is_empty());
        assert!(toks("   \n\t  \r\n").is_empty());
    }

    #[test]
    fn keywords_vs_identifiers() {
        assert_eq!(toks("let"), vec![Token::Let]);
        assert_eq!(
            toks("fn match enum"),
            vec![Token::Fn, Token::Match, Token::Enum]
        );
        // `letx` is an identifier, not the `let` keyword.
        assert_eq!(toks("letx"), vec![Token::Ident("letx".into())]);
        assert_eq!(
            toks("true false"),
            vec![Token::Bool(true), Token::Bool(false)]
        );
        assert_eq!(toks("_"), vec![Token::Underscore]);
        assert_eq!(toks("_x"), vec![Token::Ident("_x".into())]);
    }

    #[test]
    fn integer_float_and_method_call_disambiguation() {
        assert_eq!(toks("42"), vec![Token::Int(42)]);
        assert_eq!(toks("0xFF"), vec![Token::Int(255)]);
        assert_eq!(toks("1_000"), vec![Token::Int(1000)]);
        assert_eq!(toks("2.5"), vec![Token::Float(2.5)]);
        assert_eq!(toks("1.5e3"), vec![Token::Float(1500.0)]);
        // `5.foo` must be int, dot, ident — NOT a float.
        assert_eq!(
            toks("5.foo"),
            vec![Token::Int(5), Token::Dot, Token::Ident("foo".into())]
        );
    }

    #[test]
    fn strings_with_escapes() {
        assert_eq!(toks(r#""hi""#), vec![Token::Str("hi".into())]);
        assert_eq!(
            toks(r#""a\nb\t\"c\\""#),
            vec![Token::Str("a\nb\t\"c\\".into())]
        );
    }

    #[test]
    fn unterminated_string_errors_at_open_quote() {
        let e = tokenize("\"oops").unwrap_err();
        assert_eq!(e.kind, LexErrorKind::UnterminatedString);
        assert_eq!((e.line, e.col), (1, 1));
    }

    #[test]
    fn line_and_nested_block_comments_are_skipped() {
        assert_eq!(toks("1 // comment\n2"), vec![Token::Int(1), Token::Int(2)]);
        assert_eq!(
            toks("1 /* a /* nested */ b */ 2"),
            vec![Token::Int(1), Token::Int(2)]
        );
    }

    #[test]
    fn unterminated_block_comment_errors() {
        let e = tokenize("/* open").unwrap_err();
        assert_eq!(e.kind, LexErrorKind::UnterminatedBlockComment);
    }

    #[test]
    fn multi_char_operators() {
        assert_eq!(
            toks("== != <= >= && || -> => :: += -= *= /= %="),
            vec![
                Token::EqEq,
                Token::NotEq,
                Token::Le,
                Token::Ge,
                Token::AndAnd,
                Token::OrOr,
                Token::Arrow,
                Token::FatArrow,
                Token::ColonColon,
                Token::PlusEq,
                Token::MinusEq,
                Token::StarEq,
                Token::SlashEq,
                Token::PercentEq,
            ]
        );
        // `<<=`-style: `<=` then `=`? Here just confirm `<` `=` greedy → `<=`.
        assert_eq!(toks("<="), vec![Token::Le]);
        assert_eq!(toks("< ="), vec![Token::Lt, Token::Assign]);
    }

    #[test]
    fn capability_header_opener_and_shebang() {
        // Shebang on line 1 is skipped entirely.
        assert_eq!(toks("#!/usr/bin/env ncscript\nlet"), vec![Token::Let]);
        // `#![` is the attribute opener.
        assert_eq!(
            toks("#![capabilities(fs.read)]"),
            vec![
                Token::AttrOpen,
                Token::Ident("capabilities".into()),
                Token::LParen,
                Token::Ident("fs".into()),
                Token::Dot,
                Token::Ident("read".into()),
                Token::RParen,
                Token::RBracket,
            ]
        );
    }

    #[test]
    fn loop_label() {
        assert_eq!(
            toks("'outer loop"),
            vec![Token::Label("outer".into()), Token::Loop]
        );
        assert_eq!(tokenize("' ").unwrap_err().kind, LexErrorKind::InvalidLabel);
    }

    #[test]
    fn spans_track_line_and_column() {
        let t = tokenize("let\n  x").unwrap();
        assert_eq!(t[0].token, Token::Let);
        assert_eq!((t[0].line, t[0].col), (1, 1));
        assert_eq!(t[1].token, Token::Ident("x".into()));
        assert_eq!((t[1].line, t[1].col), (2, 3));
    }

    #[test]
    fn unexpected_character_errors() {
        assert_eq!(
            tokenize("@").unwrap_err().kind,
            LexErrorKind::UnexpectedChar('@')
        );
    }

    #[test]
    fn realistic_snippet_tokenizes() {
        let src = "fn add(a: Int, b: Int) -> Int { a + b }";
        let t = toks(src);
        assert_eq!(t.first(), Some(&Token::Fn));
        assert_eq!(t.last(), Some(&Token::RBrace));
        assert!(t.contains(&Token::Arrow));
        assert!(t.contains(&Token::Plus));
    }
}
