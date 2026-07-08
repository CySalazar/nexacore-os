//! Syntax highlighting for the common formats (WS8-08.3) and ncScript `.oss`
//! (WS8-08.4).
//!
//! Every highlighter maps source text to a list of [`Span`]s (byte offset +
//! length + [`TokenKind`]); anything left uncovered renders as plain text. The
//! line-oriented formats (Markdown, TOML/YAML, log) are highlighted per line;
//! JSON and ncScript are scanned as a whole so multi-line constructs (ncScript
//! block comments) are handled. The ncScript keyword set is the exact one from
//! the `nexacore-script` lexer (`NCIP-ncScript-030` §S13), so the two never
//! drift.

use alloc::vec::Vec;

/// The kind of a highlighted token, mapped to a theme colour by the UI.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TokenKind {
    /// A language keyword.
    Keyword,
    /// A boolean literal.
    Boolean,
    /// A null / nil literal.
    Null,
    /// A string literal.
    StringLit,
    /// A numeric literal.
    Number,
    /// A comment.
    Comment,
    /// Structural punctuation (`{}`, `[]`, `:`, `,`).
    Punctuation,
    /// A Markdown heading line.
    Heading,
    /// A Markdown inline-code span.
    Code,
    /// A Markdown list marker.
    ListMarker,
    /// A key in a key/value line or a JSON object.
    Key,
    /// A TOML/`ini` `[section]` header.
    Section,
    /// An ncScript loop label (`'name`).
    Label,
    /// An ncScript inner attribute opener (`#![`).
    Attribute,
    /// A log severity word.
    LogLevel,
}

/// A highlighted token: `[start, start + len)` bytes carry `kind`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Span {
    /// Byte offset of the token in the source.
    pub start: usize,
    /// Byte length of the token.
    pub len: usize,
    /// The token kind.
    pub kind: TokenKind,
}

impl Span {
    fn new(start: usize, len: usize, kind: TokenKind) -> Self {
        Self { start, len, kind }
    }
}

/// Produces highlight spans for a body of text.
pub trait Highlighter {
    /// The highlight spans for `text`, in ascending start order.
    fn highlight(&self, text: &str) -> Vec<Span>;
}

/// Iterate `(base_offset, line)` for each line, tracking byte offsets. The line
/// excludes its terminator.
fn for_each_line(text: &str, mut f: impl FnMut(usize, &str)) {
    let mut base = 0usize;
    for chunk in text.split_inclusive('\n') {
        let line = chunk.strip_suffix('\n').unwrap_or(chunk);
        let line = line.strip_suffix('\r').unwrap_or(line);
        f(base, line);
        base += chunk.len();
    }
}

/// Scan a double-quoted string starting at byte `open` (the `"`); returns the
/// byte length including both quotes, honouring `\` escapes.
fn scan_double_quoted(s: &str, open: usize) -> usize {
    let rest = s.get(open + 1..).unwrap_or("");
    let mut escaped = false;
    for (i, c) in rest.char_indices() {
        if escaped {
            escaped = false;
        } else if c == '\\' {
            escaped = true;
        } else if c == '"' {
            return i + 1 + c.len_utf8();
        }
    }
    s.len() - open // unterminated: to end of text
}

/// A JSON highlighter (strings, keys, numbers, `true`/`false`/`null`, braces).
#[derive(Debug, Clone, Copy, Default)]
pub struct JsonHighlighter;

impl Highlighter for JsonHighlighter {
    fn highlight(&self, text: &str) -> Vec<Span> {
        let mut spans = Vec::new();
        let bytes = text.as_bytes();
        let mut i = 0usize;
        while i < text.len() {
            let Some(&b) = bytes.get(i) else { break };
            match b {
                b'"' => {
                    let len = scan_double_quoted(text, i);
                    // A string followed (past whitespace) by ':' is a key.
                    let after = i + len;
                    let is_key = text
                        .get(after..)
                        .map(str::trim_start)
                        .is_some_and(|r| r.starts_with(':'));
                    spans.push(Span::new(
                        i,
                        len,
                        if is_key {
                            TokenKind::Key
                        } else {
                            TokenKind::StringLit
                        },
                    ));
                    i = after;
                }
                b'{' | b'}' | b'[' | b']' | b':' | b',' => {
                    spans.push(Span::new(i, 1, TokenKind::Punctuation));
                    i += 1;
                }
                b'-' | b'0'..=b'9' => {
                    let len = scan_number(text, i);
                    if len > 0 {
                        spans.push(Span::new(i, len, TokenKind::Number));
                        i += len;
                    } else {
                        i += 1;
                    }
                }
                b if b.is_ascii_alphabetic() => {
                    let word = scan_word(text, i);
                    let end = i + word.len();
                    match word {
                        "true" | "false" => {
                            spans.push(Span::new(i, word.len(), TokenKind::Boolean));
                        }
                        "null" => spans.push(Span::new(i, word.len(), TokenKind::Null)),
                        _ => {}
                    }
                    i = end.max(i + 1);
                }
                _ => i += 1,
            }
        }
        spans
    }
}

/// Scan a numeric literal (JSON/generic) from byte `start`; returns its byte
/// length (`0` if none).
fn scan_number(s: &str, start: usize) -> usize {
    let rest = s.get(start..).unwrap_or("");
    let mut len = 0usize;
    for (i, c) in rest.char_indices() {
        let ok =
            c.is_ascii_digit() || matches!(c, '.' | '-' | '+' | 'e' | 'E') || (i == 0 && c == '-');
        if ok {
            len = i + c.len_utf8();
        } else {
            break;
        }
    }
    // Require at least one digit.
    if rest
        .get(..len)
        .is_some_and(|t| t.bytes().any(|b| b.is_ascii_digit()))
    {
        len
    } else {
        0
    }
}

/// Scan an identifier word (`[A-Za-z0-9_]`) from byte `start`.
fn scan_word(s: &str, start: usize) -> &str {
    let rest = s.get(start..).unwrap_or("");
    let mut end = 0usize;
    for (i, c) in rest.char_indices() {
        if c == '_' || c.is_ascii_alphanumeric() {
            end = i + c.len_utf8();
        } else {
            break;
        }
    }
    rest.get(..end).unwrap_or("")
}

/// A Markdown highlighter (headings, list markers, inline code).
#[derive(Debug, Clone, Copy, Default)]
pub struct MarkdownHighlighter;

impl Highlighter for MarkdownHighlighter {
    fn highlight(&self, text: &str) -> Vec<Span> {
        let mut spans = Vec::new();
        for_each_line(text, |base, line| {
            let trimmed = line.trim_start();
            let indent = line.len() - trimmed.len();
            // ATX heading: 1-6 '#' then a space.
            let hashes = trimmed.bytes().take_while(|&b| b == b'#').count();
            if (1..=6).contains(&hashes) && trimmed.as_bytes().get(hashes) == Some(&b' ') {
                spans.push(Span::new(base, line.len(), TokenKind::Heading));
                return;
            }
            // List marker: '-', '*', or '+' then a space.
            if matches!(trimmed.as_bytes().first(), Some(b'-' | b'*' | b'+'))
                && trimmed.as_bytes().get(1) == Some(&b' ')
            {
                spans.push(Span::new(base + indent, 1, TokenKind::ListMarker));
            }
            // Inline code: `...` spans.
            let mut i = 0usize;
            while let Some(rel) = line.get(i..).and_then(|r| r.find('`')) {
                let open = i + rel;
                if let Some(close_rel) = line.get(open + 1..).and_then(|r| r.find('`')) {
                    let len = close_rel + 2; // both backticks
                    spans.push(Span::new(base + open, len, TokenKind::Code));
                    i = open + len;
                } else {
                    break;
                }
            }
        });
        spans
    }
}

/// A TOML/YAML/`ini` key–value highlighter (comments, sections, keys, strings,
/// numbers, booleans).
#[derive(Debug, Clone, Copy, Default)]
pub struct KeyValueHighlighter;

impl Highlighter for KeyValueHighlighter {
    fn highlight(&self, text: &str) -> Vec<Span> {
        let mut spans = Vec::new();
        for_each_line(text, |base, line| {
            let trimmed = line.trim_start();
            let indent = line.len() - trimmed.len();
            if trimmed.starts_with('#') {
                spans.push(Span::new(base + indent, trimmed.len(), TokenKind::Comment));
                return;
            }
            if trimmed.starts_with('[') && trimmed.contains(']') {
                spans.push(Span::new(base + indent, trimmed.len(), TokenKind::Section));
                return;
            }
            // Split on the first top-level '=' or ':'.
            if let Some(sep) = line.find(['=', ':']) {
                let key = line.get(..sep).unwrap_or("");
                let key_trim = key.trim();
                if !key_trim.is_empty() {
                    let key_start = base + indent;
                    spans.push(Span::new(key_start, key_trim.len(), TokenKind::Key));
                }
                highlight_scalar(line, sep + 1, base, &mut spans);
            }
        });
        spans
    }
}

/// Highlight a scalar value region (`from` byte) into `spans`: quoted strings,
/// numbers, and `true`/`false`.
fn highlight_scalar(line: &str, from: usize, base: usize, spans: &mut Vec<Span>) {
    let region = line.get(from..).unwrap_or("");
    let value = region.trim_start();
    let start = from + (region.len() - value.len());
    if value.starts_with('"') {
        let len = scan_double_quoted(line, start);
        spans.push(Span::new(base + start, len, TokenKind::StringLit));
    } else if matches!(value.as_bytes().first(), Some(b'0'..=b'9' | b'-')) {
        let len = scan_number(line, start);
        if len > 0 {
            spans.push(Span::new(base + start, len, TokenKind::Number));
        }
    } else {
        let word = scan_word(line, start);
        if matches!(word, "true" | "false") {
            spans.push(Span::new(base + start, word.len(), TokenKind::Boolean));
        }
    }
}

/// Severity words a [`LogHighlighter`] recognises.
const LOG_LEVELS: [&str; 8] = [
    "TRACE", "DEBUG", "INFO", "WARN", "WARNING", "ERROR", "FATAL", "CRITICAL",
];

/// A log-file highlighter (severity words, bracketed fields, quoted strings).
#[derive(Debug, Clone, Copy, Default)]
pub struct LogHighlighter;

impl Highlighter for LogHighlighter {
    fn highlight(&self, text: &str) -> Vec<Span> {
        let mut spans = Vec::new();
        for_each_line(text, |base, line| {
            let bytes = line.as_bytes();
            let mut i = 0usize;
            while i < line.len() {
                let Some(&b) = bytes.get(i) else { break };
                if b == b'[' {
                    if let Some(close) = line.get(i..).and_then(|r| r.find(']')) {
                        spans.push(Span::new(base + i, close + 1, TokenKind::Key));
                        i += close + 1;
                        continue;
                    }
                }
                if b == b'"' {
                    let len = scan_double_quoted(line, i);
                    spans.push(Span::new(base + i, len, TokenKind::StringLit));
                    i += len;
                    continue;
                }
                if b.is_ascii_uppercase() {
                    let word = scan_word(line, i);
                    if LOG_LEVELS.contains(&word) {
                        spans.push(Span::new(base + i, word.len(), TokenKind::LogLevel));
                        i += word.len();
                        continue;
                    }
                    if !word.is_empty() {
                        i += word.len();
                        continue;
                    }
                }
                i += 1;
            }
        });
        spans
    }
}

/// ncScript keywords — the exact set from `nexacore-script`'s lexer.
const NCSCRIPT_KEYWORDS: [&str; 24] = [
    "let", "mut", "fn", "struct", "enum", "const", "impl", "use", "while", "for", "in", "loop",
    "if", "else", "match", "self", "scope", "spawn", "await", "return", "break", "continue", "as",
    "where",
];

/// An ncScript (`.oss`) highlighter, aligned to the `nexacore-script` grammar.
///
/// Highlights line (`//`) and nestable block (`/* */`) comments, strings,
/// numbers, keywords, booleans, loop labels (`'name`), and the `#![` attribute
/// opener. Scanned over the whole source so block comments span lines.
#[derive(Debug, Clone, Copy, Default)]
pub struct NcScriptHighlighter;

impl Highlighter for NcScriptHighlighter {
    fn highlight(&self, text: &str) -> Vec<Span> {
        let mut spans = Vec::new();
        let bytes = text.as_bytes();
        // A leading `#!` (not `#![`) is a shebang comment line.
        let mut i = if text.starts_with("#!") && bytes.get(2) != Some(&b'[') {
            let len = text.find('\n').unwrap_or(text.len());
            spans.push(Span::new(0, len, TokenKind::Comment));
            len
        } else {
            0
        };
        while i < text.len() {
            let Some(&b) = bytes.get(i) else { break };
            let two = text.get(i..i + 2);
            if two == Some("//") {
                let end = text
                    .get(i..)
                    .and_then(|r| r.find('\n'))
                    .map_or(text.len(), |n| i + n);
                spans.push(Span::new(i, end - i, TokenKind::Comment));
                i = end;
            } else if two == Some("/*") {
                let len = scan_block_comment(text, i);
                spans.push(Span::new(i, len, TokenKind::Comment));
                i += len;
            } else if text.get(i..i + 3) == Some("#![") {
                spans.push(Span::new(i, 3, TokenKind::Attribute));
                i += 3;
            } else if b == b'"' {
                let len = scan_double_quoted(text, i);
                spans.push(Span::new(i, len, TokenKind::StringLit));
                i += len;
            } else if b == b'\'' {
                // A loop label: `'` then an identifier.
                let word = scan_word(text, i + 1);
                if word.is_empty() {
                    i += 1;
                } else {
                    spans.push(Span::new(i, word.len() + 1, TokenKind::Label));
                    i += word.len() + 1;
                }
            } else if b.is_ascii_digit() {
                let len = scan_number(text, i);
                spans.push(Span::new(i, len.max(1), TokenKind::Number));
                i += len.max(1);
            } else if b == b'_' || b.is_ascii_alphabetic() {
                let word = scan_word(text, i);
                let len = word.len();
                if NCSCRIPT_KEYWORDS.contains(&word) {
                    spans.push(Span::new(i, len, TokenKind::Keyword));
                } else if matches!(word, "true" | "false") {
                    spans.push(Span::new(i, len, TokenKind::Boolean));
                }
                i += len.max(1);
            } else {
                i += 1;
            }
        }
        spans
    }
}

/// Scan a nestable `/* … */` block comment from byte `start`; returns its byte
/// length (to end of text if unterminated).
fn scan_block_comment(s: &str, start: usize) -> usize {
    let mut depth = 0u32;
    let mut i = start;
    while i < s.len() {
        match s.get(i..i + 2) {
            Some("/*") => {
                depth += 1;
                i += 2;
            }
            Some("*/") => {
                depth -= 1;
                i += 2;
                if depth == 0 {
                    return i - start;
                }
            }
            _ => i += 1,
        }
    }
    s.len() - start
}

#[cfg(test)]
mod tests {
    use super::*;

    fn kinds_at<'a>(text: &'a str, spans: &[Span]) -> Vec<(&'a str, TokenKind)> {
        spans
            .iter()
            .map(|s| (text.get(s.start..s.start + s.len).unwrap_or(""), s.kind))
            .collect()
    }

    #[test]
    fn json_keys_strings_numbers_and_keywords() {
        let src = r#"{"name": "Ada", "age": 42, "ok": true, "x": null}"#;
        let spans = JsonHighlighter.highlight(src);
        let got = kinds_at(src, &spans);
        assert!(got.contains(&("\"name\"", TokenKind::Key)));
        assert!(got.contains(&("\"Ada\"", TokenKind::StringLit)));
        assert!(got.contains(&("42", TokenKind::Number)));
        assert!(got.contains(&("true", TokenKind::Boolean)));
        assert!(got.contains(&("null", TokenKind::Null)));
    }

    #[test]
    fn markdown_headings_lists_and_code() {
        let src = "# Title\n- item with `code`\nplain";
        let spans = MarkdownHighlighter.highlight(src);
        let got = kinds_at(src, &spans);
        assert!(
            got.iter()
                .any(|&(t, k)| t == "# Title" && k == TokenKind::Heading)
        );
        assert!(
            got.iter()
                .any(|&(t, k)| t == "-" && k == TokenKind::ListMarker)
        );
        assert!(
            got.iter()
                .any(|&(t, k)| t == "`code`" && k == TokenKind::Code)
        );
    }

    #[test]
    fn keyvalue_toml_yaml() {
        let src = "# comment\n[server]\nhost = \"localhost\"\nport: 8080\ndebug = true";
        let spans = KeyValueHighlighter.highlight(src);
        let got = kinds_at(src, &spans);
        assert!(got.contains(&("# comment", TokenKind::Comment)));
        assert!(got.contains(&("[server]", TokenKind::Section)));
        assert!(got.contains(&("host", TokenKind::Key)));
        assert!(got.contains(&("\"localhost\"", TokenKind::StringLit)));
        assert!(got.contains(&("8080", TokenKind::Number)));
        assert!(got.contains(&("true", TokenKind::Boolean)));
    }

    #[test]
    fn log_levels_brackets_strings() {
        let src = "[2026-07-02] ERROR failed to open \"db.sqlite\"";
        let spans = LogHighlighter.highlight(src);
        let got = kinds_at(src, &spans);
        assert!(got.contains(&("[2026-07-02]", TokenKind::Key)));
        assert!(got.contains(&("ERROR", TokenKind::LogLevel)));
        assert!(got.contains(&("\"db.sqlite\"", TokenKind::StringLit)));
    }

    #[test]
    fn ncscript_keywords_comments_labels() {
        let src = "// header\nlet x = 42;\n'outer loop { break }\n/* multi\n line */ fn";
        let spans = NcScriptHighlighter.highlight(src);
        let got = kinds_at(src, &spans);
        assert!(got.contains(&("// header", TokenKind::Comment)));
        assert!(got.contains(&("let", TokenKind::Keyword)));
        assert!(got.contains(&("42", TokenKind::Number)));
        assert!(got.contains(&("'outer", TokenKind::Label)));
        assert!(got.contains(&("loop", TokenKind::Keyword)));
        // The block comment spans two lines.
        assert!(
            got.iter()
                .any(|&(t, k)| t == "/* multi\n line */" && k == TokenKind::Comment)
        );
        assert!(got.contains(&("fn", TokenKind::Keyword)));
    }

    #[test]
    fn ncscript_shebang_and_attribute() {
        let src = "#!/usr/bin/env ncscript\n#![capabilities(fs.read)]\nlet";
        let spans = NcScriptHighlighter.highlight(src);
        let got = kinds_at(src, &spans);
        assert!(
            got.iter()
                .any(|&(t, k)| t == "#!/usr/bin/env ncscript" && k == TokenKind::Comment)
        );
        assert!(got.contains(&("#![", TokenKind::Attribute)));
        assert!(got.contains(&("let", TokenKind::Keyword)));
    }

    #[test]
    fn string_literal_does_not_leak_into_keys() {
        // A ':' inside a string must not make the value look like a key.
        let src = r#"{"url": "http://x"}"#;
        let spans = JsonHighlighter.highlight(src);
        let got = kinds_at(src, &spans);
        assert!(got.contains(&("\"url\"", TokenKind::Key)));
        assert!(got.contains(&("\"http://x\"", TokenKind::StringLit)));
    }
}
