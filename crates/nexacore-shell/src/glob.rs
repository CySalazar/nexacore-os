//! Glob (pathname) expansion.
//!
//! Expands shell patterns containing `*`, `?`, and `[...]` into sorted lists
//! of matching filesystem paths. This module is used by the shell pipeline
//! after environment expansion and before executor dispatch.
//!
//! ## Pattern syntax
//!
//! | Metacharacter | Meaning |
//! |---|---|
//! | `*`   | Zero or more characters, excluding `/`. |
//! | `?`   | Exactly one character, excluding `/`. |
//! | `[abc]` | Any character in the set. |
//! | `[a-z]` | Any character in the range. |
//! | `[!abc]` or `[^abc]` | Any character *not* in the set/range. |
//! | All other chars | Literal match. |
//!
//! ## Hidden files
//!
//! Files whose names start with `.` (hidden files) are excluded from `*` and
//! `?` matches unless the pattern component itself begins with `.`. This
//! matches the default behaviour of bash and POSIX shells.
//!
//! ## No-match fallback
//!
//! When no files match the pattern, the original pattern string is returned
//! unchanged (bash / POSIX "nullglob disabled" mode).

#[cfg(not(feature = "std"))]
use alloc::{
    format,
    string::{String, ToString},
    vec,
    vec::Vec,
};

// ── FsQuery ───────────────────────────────────────────────────────────────────

/// Trait for filesystem queries, enabling testing without a real kernel.
///
/// The shell's glob expander uses this trait instead of calling the operating
/// system directly. Production code passes an implementation that calls the
/// actual VFS; test code passes a mock populated with known entries.
///
/// # Examples
///
/// ```rust
/// use nexacore_shell::glob::{FsQuery, expand_glob};
///
/// struct MockFs;
/// impl FsQuery for MockFs {
///     fn list_dir(&self, _path: &str) -> Result<Vec<String>, String> {
///         Ok(vec!["foo.rs".into(), "bar.rs".into(), "baz.txt".into()])
///     }
/// }
///
/// let results = expand_glob("*.rs", "/src", &MockFs);
/// assert_eq!(results, vec!["bar.rs".to_string(), "foo.rs".to_string()]);
/// ```
pub trait FsQuery {
    /// List the direct children of `path`.
    ///
    /// Returns file and directory names only (not full paths). The
    /// implementation must not include `.` or `..` entries.
    ///
    /// # Errors
    ///
    /// Returns `Err(String)` if the directory cannot be read (does not exist,
    /// permission denied, etc.). The error string is for diagnostics only; the
    /// glob expander treats any error as an empty directory.
    fn list_dir(&self, path: &str) -> Result<Vec<String>, String>;
}

// ── Public API ────────────────────────────────────────────────────────────────

/// Expand a glob pattern against the filesystem.
///
/// # Behaviour
///
/// - If `pattern` contains no metacharacters ([`is_glob`] returns `false`),
///   returns `vec![pattern.to_string()]` immediately (no filesystem access).
/// - If `pattern` contains a `/`, the portion before the last `/` is treated
///   as the directory and the portion after as the filename pattern.
/// - Otherwise `cwd` is used as the directory.
/// - Directory entries are obtained via `fs.list_dir(dir)`. Any I/O error is
///   treated as an empty directory.
/// - Matching uses [`glob_match`].
/// - Hidden files (names starting with `.`) are excluded unless the pattern
///   component itself starts with `.`.
/// - If no entries match, the original `pattern` is returned unchanged (bash
///   nullglob-off mode).
/// - Results are sorted alphabetically.
///
/// # Examples
///
/// ```rust
/// use nexacore_shell::glob::{FsQuery, expand_glob};
///
/// struct StaticFs;
/// impl FsQuery for StaticFs {
///     fn list_dir(&self, _path: &str) -> Result<Vec<String>, String> {
///         Ok(vec![
///             "alpha.rs".into(),
///             "beta.rs".into(),
///             "gamma.txt".into(),
///             ".hidden".into(),
///         ])
///     }
/// }
///
/// // *.rs matches Rust source files but not hidden files.
/// let rs = expand_glob("*.rs", "/src", &StaticFs);
/// assert_eq!(rs, vec!["alpha.rs".to_string(), "beta.rs".to_string()]);
///
/// // No match returns the literal pattern.
/// let none = expand_glob("*.go", "/src", &StaticFs);
/// assert_eq!(none, vec!["*.go".to_string()]);
/// ```
pub fn expand_glob(pattern: &str, cwd: &str, fs: &dyn FsQuery) -> Vec<String> {
    // Fast path: no metacharacters — return as-is without hitting the FS.
    if !is_glob(pattern) {
        return vec![pattern.to_string()];
    }

    // Split pattern into (directory, filename-pattern).
    let (dir, file_pat) = split_pattern(pattern, cwd);

    // Whether the filename pattern starts with `.` (controls hidden-file visibility).
    let show_hidden = file_pat.starts_with('.');

    // Obtain directory entries; treat errors as empty.
    let entries = fs.list_dir(&dir).unwrap_or_default();

    // Filter entries: hidden-file rule first, then glob_match.
    let mut matches: Vec<String> = entries
        .into_iter()
        .filter(|name| {
            // Exclude hidden files unless the pattern explicitly starts with '.'.
            if name.starts_with('.') && !show_hidden {
                return false;
            }
            glob_match(&file_pat, name)
        })
        .map(|name| {
            // Reconstruct the full path when a directory prefix was present.
            if pattern.contains('/') {
                format!("{}/{name}", dir.trim_end_matches('/'))
            } else {
                name
            }
        })
        .collect();

    if matches.is_empty() {
        // Bash nullglob-off: return the literal pattern.
        return vec![pattern.to_string()];
    }

    matches.sort();
    matches
}

/// Return `true` if `s` contains any glob metacharacter (`*`, `?`, `[`).
///
/// This is a cheap O(n) scan used to skip the filesystem call for plain words.
///
/// # Examples
///
/// ```rust
/// use nexacore_shell::glob::is_glob;
///
/// assert!(is_glob("*.rs"));
/// assert!(is_glob("file?.txt"));
/// assert!(is_glob("[abc]*"));
/// assert!(!is_glob("plain_word"));
/// assert!(!is_glob("path/to/file"));
/// ```
pub fn is_glob(s: &str) -> bool {
    s.contains('*') || s.contains('?') || s.contains('[')
}

/// Match a single filename against a glob pattern (no path separators).
///
/// # Rules
///
/// - `*` matches zero or more characters, *not* including `/`.
/// - `?` matches exactly one character, *not* including `/`.
/// - `[abc]` matches any character in the set.
/// - `[a-z]` matches any character in the inclusive range.
/// - `[!abc]` or `[^abc]` matches any character *not* in the set/range.
/// - All other pattern characters are literal.
/// - An empty pattern matches only an empty string.
///
/// The algorithm is iterative with backtracking via a saved `(pat_idx, name_idx)`
/// position for `*` wildcards, achieving O(m·n) worst-case time without
/// recursion or heap allocation beyond the input slices.
///
/// # Examples
///
/// ```rust
/// use nexacore_shell::glob::glob_match;
///
/// assert!(glob_match("*.rs", "main.rs"));
/// assert!(!glob_match("*.rs", "main.txt"));
/// assert!(glob_match("file?.txt", "file1.txt"));
/// assert!(!glob_match("file?.txt", "file10.txt"));
/// assert!(glob_match("[abc]*", "apple.txt"));
/// assert!(glob_match("[a-z]*", "zebra"));
/// assert!(!glob_match("[!a-z]*", "lower"));
/// assert!(glob_match("*", "anything"));
/// assert!(glob_match("", ""));
/// assert!(!glob_match("", "nonempty"));
/// ```
pub fn glob_match(pattern: &str, name: &str) -> bool {
    let pat: Vec<char> = pattern.chars().collect();
    let txt: Vec<char> = name.chars().collect();
    glob_match_chars(&pat, &txt)
}

// ── Private helpers ───────────────────────────────────────────────────────────

/// Split a glob pattern into `(directory, filename_pattern)`.
///
/// If `pattern` contains a `/`, the last `/` separates the directory prefix
/// from the filename glob. Otherwise `cwd` is used as the directory.
///
/// Edge cases:
/// - `"*.rs"` → `(cwd, "*.rs")`
/// - `"/src/*.rs"` → `("/src", "*.rs")`
/// - `"src/"` → `("src", "")` — empty file pattern; will match nothing useful.
fn split_pattern(pattern: &str, cwd: &str) -> (String, String) {
    pattern.rfind('/').map_or_else(
        || (cwd.to_string(), pattern.to_string()),
        |slash_pos| {
            let dir = &pattern[..slash_pos];
            let file_pat = &pattern[slash_pos + 1..];
            // Handle absolute vs relative directory.
            let dir_str = if dir.is_empty() {
                "/".to_string()
            } else {
                dir.to_string()
            };
            (dir_str, file_pat.to_string())
        },
    )
}

/// Core matching engine operating on `char` slices.
///
/// Uses the classic "NFA-simulation via star-backtrack" algorithm:
/// - Walk `pat` and `txt` in lockstep.
/// - On `*`, record a backtrack point `(p_star, t_star)`.
/// - On mismatch (no backtrack point available) → `false`.
/// - On mismatch with a backtrack point → advance `t_star` and retry.
///
/// This avoids recursion and is safe for all inputs.
///
/// # Indexing safety
///
/// All `pat[p]` and `txt[t]` accesses are guarded by explicit bounds checks
/// immediately before the access (`p < pat.len()` / `t < txt.len()`). The
/// slice ranges `pat[p..]` are constructed only when `p < pat.len()`.
/// Clippy's `indexing_slicing` lint fires conservatively; the allow attribute
/// below is intentional and the proofs are in the adjacent guard conditions.
#[allow(clippy::indexing_slicing)]
fn glob_match_chars(pat: &[char], txt: &[char]) -> bool {
    let mut p = 0usize; // index into pat
    let mut t = 0usize; // index into txt

    // Backtrack state saved when a `*` is encountered.
    let mut star_p: Option<usize> = None; // pat index just after the `*`
    let mut star_t: usize = 0; // txt index when the `*` was matched (can advance)

    while t < txt.len() {
        if p < pat.len() {
            // Bounds proof: p < pat.len() checked immediately above.
            match pat[p] {
                '*' => {
                    // Record the star position; `*` initially matches zero chars.
                    star_p = Some(p + 1);
                    star_t = t;
                    p += 1;
                    continue;
                }
                '?' => {
                    // `?` never matches `/` (path separator).
                    // Bounds proof: t < txt.len() — outer while condition.
                    if txt[t] == '/' {
                        // Try to backtrack through `*` if available.
                        if let Some(sp) = star_p {
                            star_t += 1;
                            t = star_t;
                            p = sp;
                            continue;
                        }
                        return false;
                    }
                    p += 1;
                    t += 1;
                    continue;
                }
                '[' => {
                    // Bounds proof: p < pat.len() (above); t < txt.len() (outer while).
                    let (matched, consumed) = match_bracket(&pat[p..], txt[t]);
                    if matched {
                        p += consumed;
                        t += 1;
                    } else if let Some(sp) = star_p {
                        star_t += 1;
                        t = star_t;
                        p = sp;
                    } else {
                        return false;
                    }
                    continue;
                }
                pc => {
                    // Literal character: must match exactly.
                    // Bounds proof: t < txt.len() — outer while condition.
                    if txt[t] == pc {
                        p += 1;
                        t += 1;
                        continue;
                    } else if let Some(sp) = star_p {
                        star_t += 1;
                        t = star_t;
                        p = sp;
                        continue;
                    }
                    return false;
                }
            }
        }
        // Pattern exhausted but text remains.
        if let Some(sp) = star_p {
            // The last `*` can consume more text.
            star_t += 1;
            t = star_t;
            p = sp;
        } else {
            return false;
        }
    }

    // Text is exhausted. Pattern must also be exhausted (only trailing `*`s allowed).
    // Bounds proof: p < pat.len() checked before each pat[p] access.
    while p < pat.len() && pat[p] == '*' {
        p += 1;
    }
    p == pat.len()
}

/// Parse a `[...]` character class starting at `pat[0]` and test `ch`.
///
/// Returns `(matched, chars_consumed)` where `chars_consumed` is the number
/// of pattern characters consumed including the opening `[` and closing `]`.
///
/// If the class is malformed (no closing `]`), it is treated as a literal `[`
/// that never matches (conservative, no panic).
///
/// Supported forms:
/// - `[abc]` — match any char in the set.
/// - `[a-z]` — match any char in the inclusive range.
/// - `[!abc]` or `[^abc]` — negate the set.
/// - Mixed: `[a-zA-Z0-9]` — multiple ranges/literals in one class.
///
/// # Indexing safety
///
/// All `pat[i]` accesses are guarded by `i < pat.len()`. The slice
/// `pat[class_start..close_pos]` is valid because `close_pos` is found via
/// a bounded scan and `class_start <= close_pos <= pat.len()`.
#[allow(clippy::indexing_slicing)]
fn match_bracket(pat: &[char], ch: char) -> (bool, usize) {
    // pat[0] is '['. Parse until ']'.
    let mut i = 1usize; // Skip '['.
    // Bounds proof: i == 1; we check i < pat.len() before pat[i].
    let negated = if i < pat.len() && (pat[i] == '!' || pat[i] == '^') {
        i += 1;
        true
    } else {
        false
    };

    // Find the closing `]`. An empty class `[]` is treated as literal; if
    // `]` appears as the first char after `[` or `[!`, it is a literal `]`
    // (POSIX rule).
    let class_start = i;
    let mut found_close = false;
    let mut close_pos = i;

    // Bounds proof: i < pat.len() is checked at each iteration.
    while i < pat.len() {
        if pat[i] == ']' && i != class_start {
            found_close = true;
            close_pos = i;
            break;
        }
        i += 1;
    }

    if !found_close {
        // Malformed class — treat `[` as a literal that never matches `ch`
        // (unless `ch` itself is `[`). Consume only the `[`.
        return (ch == '[', 1);
    }

    // Evaluate the character class against `ch`.
    // Bounds proof: class_start <= close_pos <= pat.len() by construction.
    let class = &pat[class_start..close_pos];
    let in_class = char_in_class(class, ch);
    let matched = if negated { !in_class } else { in_class };

    // +1 for the opening '[', class body length, +1 for ']', +1 if negated.
    let consumed = 1 + (close_pos - class_start) + 1 + usize::from(negated);
    (matched, consumed)
}

/// Test whether `ch` is in the character class body `class`.
///
/// `class` is the slice between `[` (and optional `!`/`^`) and `]`.
/// Ranges `a-z` and individual characters are supported.
///
/// # Indexing safety
///
/// All `class[i]` accesses are guarded by `i < class.len()` or
/// `i + 2 < class.len()`. The range-check form `i + 2 < class.len()` ensures
/// that `class[i]`, `class[i+1]`, and `class[i+2]` are all in-bounds.
#[allow(clippy::indexing_slicing)]
fn char_in_class(class: &[char], ch: char) -> bool {
    let mut i = 0;
    while i < class.len() {
        // Bounds proof for range: i + 2 < class.len() → i, i+1, i+2 all valid.
        if i + 2 < class.len() && class[i + 1] == '-' {
            // Range: class[i]–class[i+2].
            if class[i] <= ch && ch <= class[i + 2] {
                return true;
            }
            i += 3;
        } else {
            // Bounds proof: i < class.len() from while condition.
            if class[i] == ch {
                return true;
            }
            i += 1;
        }
    }
    false
}

// ── Path helpers ─────────────────────────────────────────────────────────────

/// Resolve `path` relative to `base`, normalising `.` and `..` components.
///
/// # Rules
///
/// - If `path` starts with `/` it is treated as an absolute path; `base` is
///   ignored.
/// - Otherwise `path` is joined to `base`.
/// - Each `.` component is removed.
/// - Each `..` component removes the last segment of the accumulated path,
///   stopping at the filesystem root `/`.
/// - A trailing `/` on the result is stripped unless the result is the root
///   itself.
///
/// # Examples
///
/// ```rust
/// use nexacore_shell::glob::normalize_path_simple;
///
/// // Absolute path ignores base.
/// assert_eq!(normalize_path_simple("/home", "/tmp"), "/tmp");
///
/// // Relative path is joined to base.
/// assert_eq!(
///     normalize_path_simple("/home/root", "docs"),
///     "/home/root/docs"
/// );
///
/// // Single-dot component is stripped.
/// assert_eq!(normalize_path_simple("/a/b", "./c"), "/a/b/c");
///
/// // Double-dot component goes up one level.
/// assert_eq!(normalize_path_simple("/a/b/c", ".."), "/a/b");
///
/// // Cannot go above root.
/// assert_eq!(normalize_path_simple("/", ".."), "/");
/// ```
pub fn normalize_path_simple(base: &str, path: &str) -> String {
    // Build the component list from the absolute starting point.
    let mut components: Vec<&str> = Vec::new();

    if !path.starts_with('/') {
        // Relative path — begin from base, then append path below.
        for seg in base.split('/') {
            push_component(&mut components, seg);
        }
    }
    // Append the path segments (handles both absolute and relative cases).
    for seg in path.split('/') {
        push_component(&mut components, seg);
    }

    if components.is_empty() {
        return "/".to_string();
    }

    let mut result = String::new();
    for seg in &components {
        result.push('/');
        result.push_str(seg);
    }
    result
}

/// Push a single path segment onto the component stack, applying `.`/`..`
/// normalisation rules.
///
/// - Empty segments and `.` are silently dropped.
/// - `..` pops the last component (clamped at root).
/// - All other segments are pushed as-is.
#[inline]
fn push_component<'a>(stack: &mut Vec<&'a str>, seg: &'a str) {
    match seg {
        "" | "." => {}
        ".." => {
            stack.pop();
        }
        other => stack.push(other),
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── Mock filesystem ───────────────────────────────────────────────────────

    struct MockFs {
        entries: Vec<String>,
    }

    impl MockFs {
        fn new(entries: &[&str]) -> Self {
            Self {
                entries: entries.iter().map(|s| (*s).to_string()).collect(),
            }
        }
    }

    impl FsQuery for MockFs {
        fn list_dir(&self, _path: &str) -> Result<Vec<String>, String> {
            Ok(self.entries.clone())
        }
    }

    struct ErrorFs;
    impl FsQuery for ErrorFs {
        fn list_dir(&self, _path: &str) -> Result<Vec<String>, String> {
            Err("permission denied".to_string())
        }
    }

    // ── is_glob ───────────────────────────────────────────────────────────────

    #[test]
    fn is_glob_detects_star() {
        assert!(is_glob("*.rs"));
    }

    #[test]
    fn is_glob_detects_question_mark() {
        assert!(is_glob("file?.txt"));
    }

    #[test]
    fn is_glob_detects_bracket() {
        assert!(is_glob("[abc]*"));
    }

    #[test]
    fn is_glob_plain_word_is_false() {
        assert!(!is_glob("plainword"));
        assert!(!is_glob("path/to/file.txt"));
        assert!(!is_glob(""));
    }

    // ── glob_match ────────────────────────────────────────────────────────────

    #[test]
    fn glob_match_empty_pattern_matches_empty_string() {
        assert!(glob_match("", ""));
    }

    #[test]
    fn glob_match_empty_pattern_does_not_match_nonempty() {
        assert!(!glob_match("", "x"));
    }

    #[test]
    fn glob_match_literal_exact() {
        assert!(glob_match("main.rs", "main.rs"));
    }

    #[test]
    fn glob_match_literal_mismatch() {
        assert!(!glob_match("main.rs", "lib.rs"));
    }

    #[test]
    fn glob_match_star_matches_zero_chars() {
        assert!(glob_match("a*", "a"));
    }

    #[test]
    fn glob_match_star_matches_suffix() {
        assert!(glob_match("*.rs", "main.rs"));
        assert!(glob_match("*.rs", "lib.rs"));
    }

    #[test]
    fn glob_match_star_does_not_match_wrong_extension() {
        assert!(!glob_match("*.rs", "main.txt"));
    }

    #[test]
    fn glob_match_bare_star_matches_any_non_separator() {
        assert!(glob_match("*", "anything"));
        assert!(glob_match("*", ""));
    }

    #[test]
    fn glob_match_question_matches_single_char() {
        assert!(glob_match("file?.txt", "file1.txt"));
        assert!(glob_match("file?.txt", "fileA.txt"));
    }

    #[test]
    fn glob_match_question_does_not_match_multiple_chars() {
        assert!(!glob_match("file?.txt", "file10.txt"));
    }

    #[test]
    fn glob_match_question_does_not_match_empty() {
        assert!(!glob_match("?", ""));
    }

    #[test]
    fn glob_match_character_class_set() {
        assert!(glob_match("[abc]*", "apple.txt"));
        assert!(glob_match("[abc]*", "banana"));
        assert!(!glob_match("[abc]*", "dog"));
    }

    #[test]
    fn glob_match_character_class_range() {
        assert!(glob_match("[a-z]*", "zebra"));
        assert!(glob_match("[a-z]*", "alpha"));
        assert!(!glob_match("[a-z]*", "Alpha")); // uppercase not in range
    }

    #[test]
    fn glob_match_negated_class_exclamation() {
        assert!(glob_match("[!a]*", "bingo"));
        assert!(!glob_match("[!a]*", "apple"));
    }

    #[test]
    fn glob_match_negated_class_caret() {
        assert!(glob_match("[^a]*", "bingo"));
        assert!(!glob_match("[^a]*", "apple"));
    }

    #[test]
    fn glob_match_multiple_wildcards() {
        assert!(glob_match("*.*", "file.txt"));
        assert!(!glob_match("*.*", "nodot"));
    }

    #[test]
    fn glob_match_star_at_start_and_end() {
        assert!(glob_match("*main*", "main"));
        assert!(glob_match("*main*", "contains_main_here"));
        assert!(!glob_match("*main*", "other"));
    }

    // ── expand_glob ───────────────────────────────────────────────────────────

    #[test]
    fn expand_glob_star_matches_non_hidden_files() {
        let fs = MockFs::new(&["alpha.rs", "beta.rs", ".hidden", "gamma.txt"]);
        let mut results = expand_glob("*", "/src", &fs);
        results.sort();
        assert!(!results.contains(&".hidden".to_string()));
        assert!(results.contains(&"alpha.rs".to_string()));
        assert!(results.contains(&"beta.rs".to_string()));
        assert!(results.contains(&"gamma.txt".to_string()));
    }

    #[test]
    fn expand_glob_star_rs_matches_rust_files() {
        let fs = MockFs::new(&["main.rs", "lib.rs", "config.toml"]);
        let results = expand_glob("*.rs", "/src", &fs);
        assert_eq!(results, vec!["lib.rs".to_string(), "main.rs".to_string()]);
    }

    #[test]
    fn expand_glob_question_matches_single_char() {
        let fs = MockFs::new(&["a1", "a2", "ab", "abc"]);
        let results = expand_glob("a?", "/dir", &fs);
        assert_eq!(
            results,
            vec!["a1".to_string(), "a2".to_string(), "ab".to_string()]
        );
    }

    #[test]
    fn expand_glob_hidden_files_excluded_from_star() {
        let fs = MockFs::new(&[".bashrc", ".profile", "readme.txt"]);
        let results = expand_glob("*", "/home", &fs);
        assert_eq!(results, vec!["readme.txt".to_string()]);
    }

    #[test]
    fn expand_glob_dot_pattern_matches_hidden_files() {
        let fs = MockFs::new(&[".bashrc", ".profile", "readme.txt"]);
        let results = expand_glob(".*", "/home", &fs);
        assert_eq!(results, vec![".bashrc".to_string(), ".profile".to_string()]);
    }

    #[test]
    fn expand_glob_no_match_returns_literal_pattern() {
        let fs = MockFs::new(&["main.rs", "lib.rs"]);
        let results = expand_glob("*.go", "/src", &fs);
        assert_eq!(results, vec!["*.go".to_string()]);
    }

    #[test]
    fn expand_glob_fs_error_returns_literal_pattern() {
        let results = expand_glob("*.rs", "/nonexistent", &ErrorFs);
        assert_eq!(results, vec!["*.rs".to_string()]);
    }

    #[test]
    fn expand_glob_non_glob_pattern_no_fs_access() {
        // A non-glob pattern must be returned as-is without calling FsQuery.
        // ErrorFs would return an error if called, but the fast path exits first.
        let results = expand_glob("plainfile.txt", "/src", &ErrorFs);
        assert_eq!(results, vec!["plainfile.txt".to_string()]);
    }

    #[test]
    fn expand_glob_character_class_pattern() {
        let fs = MockFs::new(&["apple.txt", "banana.txt", "cherry.txt", "Dog.txt"]);
        let results = expand_glob("[a-c]*", "/dir", &fs);
        assert_eq!(
            results,
            vec![
                "apple.txt".to_string(),
                "banana.txt".to_string(),
                "cherry.txt".to_string()
            ]
        );
    }

    #[test]
    fn expand_glob_results_are_sorted() {
        let fs = MockFs::new(&["z.rs", "a.rs", "m.rs"]);
        let results = expand_glob("*.rs", "/src", &fs);
        assert_eq!(
            results,
            vec!["a.rs".to_string(), "m.rs".to_string(), "z.rs".to_string()]
        );
    }

    #[test]
    fn expand_glob_with_path_prefix() {
        // Pattern with `/` splits dir/file.
        struct DirAwareFs;
        impl FsQuery for DirAwareFs {
            fn list_dir(&self, path: &str) -> Result<Vec<String>, String> {
                if path == "/src" {
                    Ok(vec!["main.rs".into(), "lib.rs".into()])
                } else {
                    Ok(vec![])
                }
            }
        }
        let results = expand_glob("/src/*.rs", "/cwd", &DirAwareFs);
        assert_eq!(
            results,
            vec!["/src/lib.rs".to_string(), "/src/main.rs".to_string()]
        );
    }

    #[test]
    fn expand_glob_negated_class() {
        let fs = MockFs::new(&["file1.txt", "file2.txt", "fileA.txt"]);
        let results = expand_glob("file[!12].txt", "/dir", &fs);
        assert_eq!(results, vec!["fileA.txt".to_string()]);
    }

    #[test]
    fn expand_glob_empty_directory_returns_literal() {
        let fs = MockFs::new(&[]);
        let results = expand_glob("*.rs", "/empty", &fs);
        assert_eq!(results, vec!["*.rs".to_string()]);
    }
}
