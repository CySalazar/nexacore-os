//! Localisation framework: message catalogs, lookup, runtime language switch
//! (WS12-07).
//!
//! NexaCore ships English strings in code; this module lets the UI show them in
//! the user's language and swap language live, without a restart:
//!
//! - [`Catalog`] — a gettext-class message catalog for one locale: `msgid →
//!   msgstr`, with plural forms (`msgid_plural` / `msgstr[N]`) (WS12-07.1).
//! - [`Catalog::parse`] — the runtime loader: parses the line-based `.po`-subset
//!   catalog text into a [`Catalog`] (WS12-07.2).
//! - [`Catalog::get`] / [`Catalog::get_plural`] / [`translate`] — string lookup,
//!   falling back to the `msgid` when a translation is missing (WS12-07.3).
//! - [`Localization`] — the registry that holds several catalogs and an active
//!   locale, and resolves a `msgid` through `active → fallback → msgid`.
//!   Switching locale is a field mutation, so language changes take effect
//!   immediately with no restart (WS12-07.7).
//! - [`NumberFormat`] — locale-aware number formatting: grouping and decimal
//!   separators per locale, over deterministic fixed-point integers (no floats)
//!   (WS12-07.4).
//! - [`CivilDateTime`] + [`DateTimeFormat`] — locale-aware date/time formatting:
//!   field order (MDY/DMY/YMD), separators, and 12-/24-hour clock (WS12-07.5).
//! - [`LayoutDirection`] — right-to-left layout support: locale → writing
//!   direction, logical `leading`/`trailing` edges, and horizontal mirroring so
//!   the same layout code lays out LTR and RTL correctly (WS12-07.6).
//! - [`tr!`] / [`tr_plural!`] + [`extract_messages`] / [`generate_pot`] /
//!   [`merge`] — the string extraction + translation pipeline: mark UI strings
//!   with the macros, scan the sources to collect them, emit a catalog template
//!   for translators, and merge new extractions with existing translations
//!   without losing human work (WS12-07.8).
//!
//! Pure logic, `no_std + alloc`, dependency-free.
//!
//! [`tr!`]: crate::tr
//! [`tr_plural!`]: crate::tr_plural

use alloc::{
    collections::{BTreeMap, BTreeSet},
    string::{String, ToString},
    vec::Vec,
};

/// A gettext-class message catalog for a single locale (WS12-07.1).
///
/// Holds singular messages (`msgid → msgstr`) and plural messages (`msgid →
/// [msgstr[0], msgstr[1], …]`) keyed by the singular `msgid`. Built from catalog
/// text via [`Catalog::parse`] or programmatically with the `insert_*` methods.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Catalog {
    locale: String,
    singular: BTreeMap<String, String>,
    plural: BTreeMap<String, Vec<String>>,
}

impl Catalog {
    /// An empty catalog for `locale` (a BCP-47-ish tag such as `"it"` or
    /// `"pt-BR"`).
    #[must_use]
    pub fn new(locale: &str) -> Self {
        Self {
            locale: locale.to_string(),
            singular: BTreeMap::new(),
            plural: BTreeMap::new(),
        }
    }

    /// The locale tag this catalog is for.
    #[must_use]
    pub fn locale(&self) -> &str {
        &self.locale
    }

    /// Insert (or replace) a singular translation.
    pub fn insert(&mut self, msgid: &str, msgstr: &str) {
        self.singular.insert(msgid.to_string(), msgstr.to_string());
    }

    /// Insert (or replace) a plural translation: `forms[i]` is `msgstr[i]`.
    pub fn insert_plural(&mut self, msgid: &str, forms: &[&str]) {
        self.plural.insert(
            msgid.to_string(),
            forms.iter().map(|s| (*s).to_string()).collect(),
        );
    }

    /// Number of singular entries.
    #[must_use]
    pub fn len(&self) -> usize {
        self.singular.len()
    }

    /// `true` when the catalog has no singular entries.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.singular.is_empty()
    }

    /// Look up a singular translation, or `None` when `msgid` is untranslated
    /// (WS12-07.3).
    #[must_use]
    pub fn get(&self, msgid: &str) -> Option<&str> {
        self.singular.get(msgid).map(String::as_str)
    }

    /// Look up a plural translation, selecting the form for count `n` via `rule`
    /// (WS12-07.3).
    ///
    /// The form index `rule(n)` is clamped to the last available form, so a
    /// catalog that only provides one form still resolves. Returns `None` when
    /// `msgid` has no plural entry.
    #[must_use]
    pub fn get_plural(&self, msgid: &str, n: u64, rule: PluralRule) -> Option<&str> {
        let forms = self.plural.get(msgid)?;
        if forms.is_empty() {
            return None;
        }
        let idx = rule(n).min(forms.len() - 1);
        forms.get(idx).map(String::as_str)
    }

    /// Parse catalog text in the line-based `.po`-subset format (WS12-07.2).
    ///
    /// Recognised lines (blank lines and `#`-comments are ignored):
    ///
    /// ```text
    /// msgid "source string"
    /// msgstr "translation"
    ///
    /// msgid "one item"
    /// msgid_plural "many items"
    /// msgstr[0] "un elemento"
    /// msgstr[1] "molti elementi"
    /// ```
    ///
    /// String literals are double-quoted and support the escapes `\"`, `\\`,
    /// `\n`, and `\t`. An entry ends at the next `msgid` or end of input.
    ///
    /// # Errors
    ///
    /// Returns [`ParseError`] on a malformed line (missing quotes, an unknown
    /// keyword, a bad escape, `msgstr` without a preceding `msgid`, or a
    /// `msgstr[i]` index that is not a number).
    pub fn parse(locale: &str, text: &str) -> Result<Self, ParseError> {
        let mut cat = Self::new(locale);
        let mut cur_id: Option<String> = None;
        let mut cur_forms: BTreeMap<usize, String> = BTreeMap::new();
        let mut cur_singular: Option<String> = None;

        for (i, raw) in text.lines().enumerate() {
            let line = raw.trim();
            let lineno = i + 1;
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            if let Some(rest) = line.strip_prefix("msgid_plural") {
                // Belongs to the open entry; only its presence matters here.
                let _ = parse_quoted(rest, lineno)?;
            } else if let Some(rest) = line.strip_prefix("msgid") {
                // A new entry starts: flush the previous one first.
                flush_entry(&mut cat, &mut cur_id, &mut cur_singular, &mut cur_forms);
                cur_id = Some(parse_quoted(rest, lineno)?);
            } else if let Some(rest) = line.strip_prefix("msgstr[") {
                let close = rest.find(']').ok_or(ParseError {
                    line: lineno,
                    kind: ParseErrorKind::Malformed,
                })?;
                let idx: usize = rest[..close].parse().map_err(|_| ParseError {
                    line: lineno,
                    kind: ParseErrorKind::BadIndex,
                })?;
                if cur_id.is_none() {
                    return Err(ParseError {
                        line: lineno,
                        kind: ParseErrorKind::OrphanMsgstr,
                    });
                }
                cur_forms.insert(idx, parse_quoted(&rest[close + 1..], lineno)?);
            } else if let Some(rest) = line.strip_prefix("msgstr") {
                if cur_id.is_none() {
                    return Err(ParseError {
                        line: lineno,
                        kind: ParseErrorKind::OrphanMsgstr,
                    });
                }
                cur_singular = Some(parse_quoted(rest, lineno)?);
            } else {
                return Err(ParseError {
                    line: lineno,
                    kind: ParseErrorKind::UnknownKeyword,
                });
            }
        }
        flush_entry(&mut cat, &mut cur_id, &mut cur_singular, &mut cur_forms);
        Ok(cat)
    }
}

/// Flush the entry accumulated during [`Catalog::parse`] into `cat`, resetting
/// the plural-form accumulator for the next entry.
fn flush_entry(
    cat: &mut Catalog,
    id: &mut Option<String>,
    singular: &mut Option<String>,
    forms: &mut BTreeMap<usize, String>,
) {
    if let Some(msgid) = id.take() {
        if let Some(s) = singular.take() {
            cat.singular.insert(msgid.clone(), s);
        }
        if !forms.is_empty() {
            // Dense-pack by ascending index; gaps are dropped.
            let packed: Vec<String> = forms.values().cloned().collect();
            cat.plural.insert(msgid, packed);
        }
    }
    forms.clear();
}

/// Parse a single double-quoted, escape-aware string literal from `s` (which may
/// have leading whitespace before the opening quote).
fn parse_quoted(s: &str, lineno: usize) -> Result<String, ParseError> {
    let s = s.trim();
    let bytes = s.as_bytes();
    if bytes.first() != Some(&b'"') || bytes.last() != Some(&b'"') || bytes.len() < 2 {
        return Err(ParseError {
            line: lineno,
            kind: ParseErrorKind::Malformed,
        });
    }
    let inner = &s[1..s.len() - 1];
    let mut out = String::with_capacity(inner.len());
    let mut chars = inner.chars();
    while let Some(c) = chars.next() {
        if c == '\\' {
            match chars.next() {
                Some('n') => out.push('\n'),
                Some('t') => out.push('\t'),
                Some('"') => out.push('"'),
                Some('\\') => out.push('\\'),
                _ => {
                    return Err(ParseError {
                        line: lineno,
                        kind: ParseErrorKind::BadEscape,
                    });
                }
            }
        } else if c == '"' {
            // An unescaped quote inside the literal is malformed.
            return Err(ParseError {
                line: lineno,
                kind: ParseErrorKind::Malformed,
            });
        } else {
            out.push(c);
        }
    }
    Ok(out)
}

/// Why [`Catalog::parse`] rejected the catalog text.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ParseError {
    /// 1-based line number of the offending line.
    pub line: usize,
    /// What was wrong.
    pub kind: ParseErrorKind,
}

/// The class of a [`ParseError`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParseErrorKind {
    /// A quoted string was missing or unbalanced.
    Malformed,
    /// An unknown leading keyword (not `msgid`/`msgid_plural`/`msgstr`).
    UnknownKeyword,
    /// A `msgstr` appeared before any `msgid`.
    OrphanMsgstr,
    /// A `msgstr[i]` index was not a number.
    BadIndex,
    /// An unsupported backslash escape.
    BadEscape,
}

/// Selects the plural form index for a count (WS12-07.3).
///
/// Different languages have different plural rules (CLDR); a catalog is loaded
/// with the rule for its locale. The framework ships [`plural_rule_default`]
/// (English/Romance: `1` is singular, everything else plural).
pub type PluralRule = fn(u64) -> usize;

/// The default plural rule (English/Romance): form `0` for `n == 1`, form `1`
/// otherwise.
#[must_use]
pub fn plural_rule_default(n: u64) -> usize {
    usize::from(n != 1)
}

/// Translate `msgid` against `catalog`, falling back to `msgid` itself when it
/// is untranslated (WS12-07.3).
///
/// The fallback means an in-progress translation never leaves a blank in the UI:
/// the untranslated source string shows through instead.
#[must_use]
pub fn translate<'a>(catalog: &'a Catalog, msgid: &'a str) -> &'a str {
    catalog.get(msgid).unwrap_or(msgid)
}

/// The localisation registry: several catalogs plus an active locale, with live
/// switching (WS12-07.7).
///
/// Resolution goes `active catalog → fallback catalog → msgid`, so a string
/// missing from the active locale degrades to the fallback (typically the source
/// language) rather than vanishing. [`set_locale`] swaps the active catalog in
/// place — no reload, no restart.
///
/// [`set_locale`]: Localization::set_locale
#[derive(Debug, Clone, Default)]
pub struct Localization {
    catalogs: BTreeMap<String, Catalog>,
    active: String,
    fallback: String,
}

impl Localization {
    /// A registry whose fallback (and initial active) locale is `fallback`.
    ///
    /// The fallback is usually the source language the code is written in
    /// (`"en"`), so untranslated strings resolve to it.
    #[must_use]
    pub fn new(fallback: &str) -> Self {
        Self {
            catalogs: BTreeMap::new(),
            active: fallback.to_string(),
            fallback: fallback.to_string(),
        }
    }

    /// Register (or replace) a catalog, keyed by its locale.
    pub fn add_catalog(&mut self, catalog: Catalog) {
        self.catalogs.insert(catalog.locale.clone(), catalog);
    }

    /// The active locale tag.
    #[must_use]
    pub fn active_locale(&self) -> &str {
        &self.active
    }

    /// The fallback locale tag.
    #[must_use]
    pub fn fallback_locale(&self) -> &str {
        &self.fallback
    }

    /// Whether a catalog is registered for `locale`.
    #[must_use]
    pub fn has_locale(&self, locale: &str) -> bool {
        self.catalogs.contains_key(locale)
    }

    /// Switch the active locale live (WS12-07.7).
    ///
    /// Returns `true` when a catalog is registered for `locale`; otherwise the
    /// active locale is still set (so lookups resolve via the fallback) and
    /// `false` is returned, letting the caller flag a missing translation set.
    pub fn set_locale(&mut self, locale: &str) -> bool {
        self.active = locale.to_string();
        self.has_locale(locale)
    }

    /// Translate `msgid` through `active → fallback → msgid` (WS12-07.3/.7).
    #[must_use]
    pub fn translate<'a>(&'a self, msgid: &'a str) -> &'a str {
        if let Some(s) = self.catalogs.get(&self.active).and_then(|c| c.get(msgid)) {
            return s;
        }
        if self.active != self.fallback {
            if let Some(s) = self.catalogs.get(&self.fallback).and_then(|c| c.get(msgid)) {
                return s;
            }
        }
        msgid
    }

    /// Translate a plural `msgid` for count `n` through `active → fallback`,
    /// falling back to `msgid` when no plural entry is found (WS12-07.3).
    #[must_use]
    pub fn translate_plural<'a>(&'a self, msgid: &'a str, n: u64, rule: PluralRule) -> &'a str {
        if let Some(s) = self
            .catalogs
            .get(&self.active)
            .and_then(|c| c.get_plural(msgid, n, rule))
        {
            return s;
        }
        if self.active != self.fallback {
            if let Some(s) = self
                .catalogs
                .get(&self.fallback)
                .and_then(|c| c.get_plural(msgid, n, rule))
            {
                return s;
            }
        }
        msgid
    }
}

/// Locale-aware number formatting (WS12-07.4).
///
/// Holds the grouping (thousands) separator, the decimal separator, and the
/// grouping size for a locale. Formatting works over integers and deterministic
/// fixed-point values (`value × 10⁻ᶠ`), so there is no floating-point rounding to
/// vary the output.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NumberFormat {
    grouping: char,
    decimal: char,
    group_size: usize,
}

impl NumberFormat {
    /// A number format with the given `grouping` and `decimal` separators and a
    /// grouping size of 3. A `group_size` of 0 disables grouping.
    #[must_use]
    pub fn new(grouping: char, decimal: char) -> Self {
        Self {
            grouping,
            decimal,
            group_size: 3,
        }
    }

    /// The number format for `locale` (WS12-07.4).
    ///
    /// Recognises the primary subtag (e.g. `it` from `it-IT`). English uses
    /// `1,234.56`; Italian/German/Spanish/Portuguese/Dutch use `1.234,56`; French
    /// uses `1 234,56`. An unknown locale falls back to the English style.
    #[must_use]
    pub fn for_locale(locale: &str) -> Self {
        match primary_subtag(locale) {
            "it" | "de" | "es" | "pt" | "nl" | "da" => Self::new('.', ','),
            "fr" => Self::new(' ', ','),
            // en and anything unrecognised.
            _ => Self::new(',', '.'),
        }
    }

    /// The grouping (thousands) separator.
    #[must_use]
    pub fn grouping(self) -> char {
        self.grouping
    }

    /// The decimal separator.
    #[must_use]
    pub fn decimal(self) -> char {
        self.decimal
    }

    /// Format a signed integer with grouping, e.g. `-1,234,567`.
    #[must_use]
    pub fn format_i64(&self, n: i64) -> String {
        let grouped = self.group_digits(&alloc::format!("{}", n.unsigned_abs()));
        if n < 0 {
            alloc::format!("-{grouped}")
        } else {
            grouped
        }
    }

    /// Format a fixed-point value: `value` scaled by `10^frac`, with `frac`
    /// fractional digits.
    ///
    /// `format_fixed(123_456, 2)` → `"1,234.56"` (English). `frac == 0` is
    /// equivalent to [`format_i64`]. This is exact — no floating point involved.
    ///
    /// [`format_i64`]: NumberFormat::format_i64
    #[must_use]
    pub fn format_fixed(&self, value: i64, frac: usize) -> String {
        let mut digits = alloc::format!("{}", value.unsigned_abs());
        if frac == 0 {
            let grouped = self.group_digits(&digits);
            return if value < 0 {
                alloc::format!("-{grouped}")
            } else {
                grouped
            };
        }
        // Left-pad so there is at least one integer digit before the fraction.
        while digits.len() <= frac {
            digits.insert(0, '0');
        }
        let split = digits.len() - frac;
        let int_part = self.group_digits(&digits[..split]);
        let frac_part = &digits[split..];
        let sign = if value < 0 { "-" } else { "" };
        alloc::format!("{sign}{int_part}{}{frac_part}", self.decimal)
    }

    /// Insert the grouping separator into a string of ASCII digits (no sign).
    fn group_digits(&self, digits: &str) -> String {
        if self.group_size == 0 || digits.len() <= self.group_size {
            return digits.to_string();
        }
        let len = digits.len();
        // Upper bound: every digit plus at most one separator each.
        let mut out = String::with_capacity(len * 2);
        for (i, ch) in digits.chars().enumerate() {
            if i > 0 && (len - i) % self.group_size == 0 {
                out.push(self.grouping);
            }
            out.push(ch);
        }
        out
    }
}

/// A plain civil date-time (no time zone), the input to [`DateTimeFormat`]
/// (WS12-07.5).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CivilDateTime {
    /// Full year, e.g. `2026`.
    pub year: i32,
    /// Month, `1..=12`.
    pub month: u8,
    /// Day of month, `1..=31`.
    pub day: u8,
    /// Hour, `0..=23`.
    pub hour: u8,
    /// Minute, `0..=59`.
    pub minute: u8,
    /// Second, `0..=59`.
    pub second: u8,
}

/// The order of the day/month/year fields in a formatted date (WS12-07.5).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DateOrder {
    /// Year-month-day, e.g. `2026-07-11` (ISO, Japanese).
    Ymd,
    /// Day-month-year, e.g. `11/07/2026` (most of Europe).
    Dmy,
    /// Month-day-year, e.g. `07/11/2026` (US English).
    Mdy,
}

/// Locale-aware date/time formatting (WS12-07.5).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DateTimeFormat {
    order: DateOrder,
    date_sep: char,
    time_sep: char,
    hour24: bool,
}

impl DateTimeFormat {
    /// A date/time format with the given date field order, date separator, time
    /// separator (usually `:`) and 12-/24-hour clock.
    #[must_use]
    pub fn new(order: DateOrder, date_sep: char, time_sep: char, hour24: bool) -> Self {
        Self {
            order,
            date_sep,
            time_sep,
            hour24,
        }
    }

    /// The date/time format for `locale` (WS12-07.5).
    ///
    /// `en-US` uses `MM/DD/YYYY` with a 12-hour clock; `en-GB`, Italian, French
    /// and Spanish use `DD/MM/YYYY` 24-hour; German uses `DD.MM.YYYY`; Japanese,
    /// Chinese and Korean use `YYYY/MM/DD`. Unknown locales fall back to ISO
    /// `YYYY-MM-DD` 24-hour.
    #[must_use]
    pub fn for_locale(locale: &str) -> Self {
        // Exact region-sensitive tags first.
        match locale {
            "en-US" | "en_US" => return Self::new(DateOrder::Mdy, '/', ':', false),
            "en-GB" | "en_GB" => return Self::new(DateOrder::Dmy, '/', ':', true),
            _ => {}
        }
        match primary_subtag(locale) {
            "it" | "fr" | "es" | "pt" | "nl" => Self::new(DateOrder::Dmy, '/', ':', true),
            "de" | "da" => Self::new(DateOrder::Dmy, '.', ':', true),
            "en" => Self::new(DateOrder::Mdy, '/', ':', false),
            "ja" | "zh" | "ko" => Self::new(DateOrder::Ymd, '/', ':', true),
            // iso and anything unrecognised.
            _ => Self::new(DateOrder::Ymd, '-', ':', true),
        }
    }

    /// Format the date part, with zero-padded month/day and a 4-digit year.
    #[must_use]
    pub fn format_date(&self, dt: &CivilDateTime) -> String {
        let y = alloc::format!("{:04}", dt.year);
        let m = alloc::format!("{:02}", dt.month);
        let d = alloc::format!("{:02}", dt.day);
        let s = self.date_sep;
        match self.order {
            DateOrder::Ymd => alloc::format!("{y}{s}{m}{s}{d}"),
            DateOrder::Dmy => alloc::format!("{d}{s}{m}{s}{y}"),
            DateOrder::Mdy => alloc::format!("{m}{s}{d}{s}{y}"),
        }
    }

    /// Format the time part: `HH:MM:SS` on a 24-hour clock, or `H:MM:SS AM/PM` on
    /// a 12-hour clock.
    #[must_use]
    pub fn format_time(&self, dt: &CivilDateTime) -> String {
        let sep = self.time_sep;
        if self.hour24 {
            alloc::format!("{:02}{sep}{:02}{sep}{:02}", dt.hour, dt.minute, dt.second)
        } else {
            let (h12, meridiem) = to_12_hour(dt.hour);
            alloc::format!("{h12}{sep}{:02}{sep}{:02} {meridiem}", dt.minute, dt.second)
        }
    }

    /// Format the full date-time as `<date> <time>`.
    #[must_use]
    pub fn format_datetime(&self, dt: &CivilDateTime) -> String {
        alloc::format!("{} {}", self.format_date(dt), self.format_time(dt))
    }
}

/// Convert a 24-hour hour to a (12-hour hour, meridiem) pair.
fn to_12_hour(hour24: u8) -> (u8, &'static str) {
    let meridiem = if hour24 < 12 { "AM" } else { "PM" };
    let h = hour24 % 12;
    let h12 = if h == 0 { 12 } else { h };
    (h12, meridiem)
}

/// The primary language subtag of a BCP-47-ish locale tag (the part before the
/// first `-` or `_`), lowercased conceptually by the caller's data.
fn primary_subtag(locale: &str) -> &str {
    let end = locale.find(['-', '_']).unwrap_or(locale.len());
    &locale[..end]
}

/// The writing direction of a UI, for right-to-left layout support (WS12-07.6).
///
/// Modelling the horizontal edges as *logical* (`leading` / `trailing`) rather
/// than physical (`left` / `right`) lets one body of layout code drive both
/// directions: in [`Ltr`] the leading edge is the left, in [`Rtl`] it is the
/// right. [`resolve_x`] mirrors a child's horizontal position for [`Rtl`].
///
/// [`Ltr`]: LayoutDirection::Ltr
/// [`Rtl`]: LayoutDirection::Rtl
/// [`resolve_x`]: LayoutDirection::resolve_x
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LayoutDirection {
    /// Left-to-right (Latin, Cyrillic, CJK, …).
    Ltr,
    /// Right-to-left (Arabic, Hebrew, Persian, …).
    Rtl,
}

impl LayoutDirection {
    /// The layout direction for `locale` (WS12-07.6).
    ///
    /// Arabic (`ar`), Hebrew (`he`/`iw`), Persian (`fa`), Urdu (`ur`), Yiddish
    /// (`yi`), Pashto (`ps`) and Dhivehi (`dv`) are right-to-left; every other
    /// locale is left-to-right.
    #[must_use]
    pub fn from_locale(locale: &str) -> Self {
        match primary_subtag(locale) {
            "ar" | "he" | "iw" | "fa" | "ur" | "yi" | "ps" | "dv" => Self::Rtl,
            _ => Self::Ltr,
        }
    }

    /// Whether the direction is right-to-left.
    #[must_use]
    pub fn is_rtl(self) -> bool {
        matches!(self, Self::Rtl)
    }

    /// The physical side of the leading (start) edge.
    #[must_use]
    pub fn leading_side(self) -> Side {
        match self {
            Self::Ltr => Side::Left,
            Self::Rtl => Side::Right,
        }
    }

    /// The physical side of the trailing (end) edge.
    #[must_use]
    pub fn trailing_side(self) -> Side {
        match self {
            Self::Ltr => Side::Right,
            Self::Rtl => Side::Left,
        }
    }

    /// Resolve the physical x of a child laid out at logical offset `x` (from the
    /// leading edge), given the child and container widths (WS12-07.6).
    ///
    /// [`Ltr`] returns `x` unchanged; [`Rtl`] mirrors it to
    /// `container_w - x - child_w`, using saturating arithmetic so a child that
    /// overflows the container clamps to `0` rather than underflowing.
    ///
    /// [`Ltr`]: LayoutDirection::Ltr
    /// [`Rtl`]: LayoutDirection::Rtl
    #[must_use]
    pub fn resolve_x(self, x: u32, child_w: u32, container_w: u32) -> u32 {
        match self {
            Self::Ltr => x,
            Self::Rtl => container_w.saturating_sub(x).saturating_sub(child_w),
        }
    }

    /// Resolve a logical text alignment to a physical one (WS12-07.6).
    ///
    /// `Start` maps to the leading side (left in LTR, right in RTL), `End` to the
    /// trailing side, and `Center` stays centred.
    #[must_use]
    pub fn resolve_align(self, align: TextAlign) -> PhysicalAlign {
        match (align, self) {
            (TextAlign::Center, _) => PhysicalAlign::Center,
            (TextAlign::Start, Self::Ltr) | (TextAlign::End, Self::Rtl) => PhysicalAlign::Left,
            (TextAlign::Start, Self::Rtl) | (TextAlign::End, Self::Ltr) => PhysicalAlign::Right,
        }
    }
}

/// A physical horizontal side.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Side {
    /// The left side.
    Left,
    /// The right side.
    Right,
}

/// A logical (writing-direction-relative) text alignment (WS12-07.6).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TextAlign {
    /// The leading edge (left in LTR, right in RTL).
    Start,
    /// Centred.
    Center,
    /// The trailing edge (right in LTR, left in RTL).
    End,
}

/// A physical (resolved) text alignment (WS12-07.6).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PhysicalAlign {
    /// Left-aligned.
    Left,
    /// Centred.
    Center,
    /// Right-aligned.
    Right,
}

// ---------------------------------------------------------------------------
// String extraction + translation pipeline (WS12-07.8)
// ---------------------------------------------------------------------------

/// Mark a UI string for translation and look it up at runtime (WS12-07.8).
///
/// `tr!(l10n, "Save")` expands to `l10n.translate("Save")`. The macro is also the
/// marker the [`extract_messages`] scanner looks for, so every string wrapped in
/// `tr!` is collected into the catalog template automatically.
#[macro_export]
macro_rules! tr {
    ($l10n:expr, $msgid:literal $(,)?) => {
        $l10n.translate($msgid)
    };
}

/// Mark a pluralised UI string and look it up for count `n` (WS12-07.8).
///
/// `tr_plural!(l10n, "%d file", "%d files", n)` expands to
/// `l10n.translate_plural("%d file", n, plural_rule_default)`. Both literals are
/// collected by [`extract_messages`] as a plural entry.
#[macro_export]
macro_rules! tr_plural {
    ($l10n:expr, $one:literal, $many:literal, $n:expr $(,)?) => {
        $l10n.translate_plural($one, $n, $crate::i18n::plural_rule_default)
    };
}

/// A translatable message discovered by [`extract_messages`] (WS12-07.8).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExtractedMessage {
    /// The `msgid` (the source string / singular form).
    pub msgid: String,
    /// The plural form, when the string was marked with [`tr_plural!`].
    ///
    /// [`tr_plural!`]: crate::tr_plural
    pub plural: Option<String>,
}

/// Scan Rust source text for `tr!` / `tr_plural!` markers and collect the
/// translatable strings, in source order and de-duplicated by `msgid`
/// (WS12-07.8).
///
/// String literals and `//` / `/* */` comments in the source are skipped, so a
/// `tr!(…)` that only appears inside a string or a comment is not mistaken for a
/// real call.
#[must_use]
pub fn extract_messages(source: &str) -> Vec<ExtractedMessage> {
    let mut out: Vec<ExtractedMessage> = Vec::new();
    let mut seen: BTreeSet<String> = BTreeSet::new();
    let mut i = 0;
    while i < source.len() {
        // Skip literals and comments so their contents can't look like calls.
        if source[i..].starts_with('"') {
            i = skip_string(source, i);
            continue;
        }
        if source[i..].starts_with("//") {
            i = skip_line_comment(source, i);
            continue;
        }
        if source[i..].starts_with("/*") {
            i = skip_block_comment(source, i);
            continue;
        }
        if let Some(open) = macro_at(source, i, "tr_plural") {
            if let Some((inner, end)) = capture_args(source, open) {
                let lits = string_literals(&inner);
                if let (Some(one), Some(many)) = (lits.first(), lits.get(1)) {
                    if seen.insert(one.clone()) {
                        out.push(ExtractedMessage {
                            msgid: one.clone(),
                            plural: Some(many.clone()),
                        });
                    }
                }
                i = end;
                continue;
            }
        }
        if let Some(open) = macro_at(source, i, "tr") {
            if let Some((inner, end)) = capture_args(source, open) {
                if let Some(msgid) = string_literals(&inner).into_iter().next() {
                    if seen.insert(msgid.clone()) {
                        out.push(ExtractedMessage {
                            msgid,
                            plural: None,
                        });
                    }
                }
                i = end;
                continue;
            }
        }
        i += next_char_len(source, i);
    }
    out
}

/// Generate a catalog template (POT-style) from extracted messages: one entry
/// per message with an empty `msgstr`, ready for a translator to fill
/// (WS12-07.8).
#[must_use]
pub fn generate_pot(messages: &[ExtractedMessage]) -> String {
    let mut out = String::new();
    for m in messages {
        out.push_str(&alloc::format!("msgid \"{}\"\n", escape_po(&m.msgid)));
        if let Some(pl) = &m.plural {
            out.push_str(&alloc::format!("msgid_plural \"{}\"\n", escape_po(pl)));
            out.push_str("msgstr[0] \"\"\n");
            out.push_str("msgstr[1] \"\"\n");
        } else {
            out.push_str("msgstr \"\"\n");
        }
        out.push('\n');
    }
    out
}

/// Merge freshly-[`extract_messages`]ed strings with an existing translated
/// catalog (WS12-07.8), gettext `msgmerge`-style.
///
/// The result carries a translation for every current message that `existing`
/// already had (human work is preserved), drops entries no longer present in the
/// sources (obsolete), and simply omits new/untranslated ones — at runtime those
/// fall back to the `msgid`, and they appear in the [`generate_pot`] template for
/// a translator to complete.
#[must_use]
pub fn merge(existing: &Catalog, messages: &[ExtractedMessage]) -> Catalog {
    let mut merged = Catalog::new(existing.locale());
    for m in messages {
        if m.plural.is_some() {
            if let Some(forms) = existing.plural.get(&m.msgid) {
                merged.plural.insert(m.msgid.clone(), forms.clone());
            }
        } else if let Some(s) = existing.get(&m.msgid) {
            merged.insert(&m.msgid, s);
        }
    }
    merged
}

/// Escape a string for a `.po` double-quoted literal (inverse of the unescaping
/// in [`Catalog::parse`]).
fn escape_po(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\t' => out.push_str("\\t"),
            _ => out.push(c),
        }
    }
    out
}

/// Byte length of the char starting at `i` (1 when `i` is past a valid boundary
/// fallback).
fn next_char_len(source: &str, i: usize) -> usize {
    source[i..].chars().next().map_or(1, char::len_utf8)
}

/// Is `b` an identifier-continuation byte (`[A-Za-z0-9_]`)?
fn is_ident_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_'
}

/// If an invocation of `name!(` begins exactly at byte `i` (with an identifier
/// boundary before it), return the byte index just after the `(`.
fn macro_at(source: &str, i: usize, name: &str) -> Option<usize> {
    if i > 0 {
        if let Some(&prev) = source.as_bytes().get(i - 1) {
            if is_ident_byte(prev) {
                return None;
            }
        }
    }
    let rest = source.get(i..)?.strip_prefix(name)?;
    let rest = rest.strip_prefix('!')?.trim_start();
    let rest = rest.strip_prefix('(')?;
    Some(source.len() - rest.len())
}

/// Capture the balanced `(...)` argument text starting at byte `open` (just after
/// the `(`), respecting string literals. Returns the inner text and the byte
/// index just after the closing `)`.
fn capture_args(source: &str, open: usize) -> Option<(String, usize)> {
    let rest = source.get(open..)?;
    let mut depth = 1usize;
    let mut in_str = false;
    let mut escaped = false;
    let mut inner = String::new();
    let mut consumed = 0usize;
    for ch in rest.chars() {
        consumed += ch.len_utf8();
        if in_str {
            inner.push(ch);
            if escaped {
                escaped = false;
            } else if ch == '\\' {
                escaped = true;
            } else if ch == '"' {
                in_str = false;
            }
            continue;
        }
        match ch {
            '"' => {
                in_str = true;
                inner.push(ch);
            }
            '(' => {
                depth += 1;
                inner.push(ch);
            }
            ')' => {
                depth -= 1;
                if depth == 0 {
                    return Some((inner, open + consumed));
                }
                inner.push(ch);
            }
            _ => inner.push(ch),
        }
    }
    None
}

/// Extract every double-quoted, escape-aware string literal from `s`, in order.
fn string_literals(s: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut chars = s.chars();
    while let Some(c) = chars.next() {
        if c != '"' {
            continue;
        }
        let mut lit = String::new();
        let mut escaped = false;
        for d in chars.by_ref() {
            if escaped {
                match d {
                    'n' => lit.push('\n'),
                    't' => lit.push('\t'),
                    other => lit.push(other),
                }
                escaped = false;
            } else if d == '\\' {
                escaped = true;
            } else if d == '"' {
                break;
            } else {
                lit.push(d);
            }
        }
        out.push(lit);
    }
    out
}

/// Return the byte index just after the string literal opening at byte `i`.
fn skip_string(source: &str, i: usize) -> usize {
    let mut escaped = false;
    let mut consumed = 0usize;
    let rest = &source[i..];
    for (n, ch) in rest.char_indices() {
        if n == 0 {
            continue; // the opening quote
        }
        consumed = n + ch.len_utf8();
        if escaped {
            escaped = false;
        } else if ch == '\\' {
            escaped = true;
        } else if ch == '"' {
            return i + consumed;
        }
    }
    i + rest.len().max(consumed)
}

/// Return the byte index just after the end of a `//` line comment at byte `i`.
fn skip_line_comment(source: &str, i: usize) -> usize {
    source[i..]
        .find('\n')
        .map_or(source.len(), |off| i + off + 1)
}

/// Return the byte index just after the closing `*/` of a block comment at byte
/// `i`, or end of source if unterminated.
fn skip_block_comment(source: &str, i: usize) -> usize {
    source[i + 2..]
        .find("*/")
        .map_or(source.len(), |off| i + 2 + off + 2)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_reads_singular_entries() {
        let cat = Catalog::parse(
            "it",
            "# greeting catalog\nmsgid \"Hello\"\nmsgstr \"Ciao\"\n\nmsgid \"Bye\"\nmsgstr \"Addio\"\n",
        )
        .unwrap();
        assert_eq!(cat.locale(), "it");
        assert_eq!(cat.len(), 2);
        assert_eq!(cat.get("Hello"), Some("Ciao"));
        assert_eq!(cat.get("Bye"), Some("Addio"));
        assert_eq!(cat.get("Missing"), None);
    }

    #[test]
    fn parse_handles_escapes() {
        let cat = Catalog::parse("it", "msgid \"a\\tb\"\nmsgstr \"x\\ny\\\"z\"\n").unwrap();
        assert_eq!(cat.get("a\tb"), Some("x\ny\"z"));
    }

    #[test]
    fn parse_reads_plural_forms() {
        let cat = Catalog::parse(
            "it",
            "msgid \"%d file\"\nmsgid_plural \"%d files\"\nmsgstr[0] \"%d file\"\nmsgstr[1] \"%d file (plurale)\"\n",
        )
        .unwrap();
        assert_eq!(
            cat.get_plural("%d file", 1, plural_rule_default),
            Some("%d file")
        );
        assert_eq!(
            cat.get_plural("%d file", 5, plural_rule_default),
            Some("%d file (plurale)")
        );
    }

    #[test]
    fn get_plural_clamps_to_last_available_form() {
        let mut cat = Catalog::new("en");
        cat.insert_plural("item", &["one item"]); // only one form
        assert_eq!(
            cat.get_plural("item", 9, plural_rule_default),
            Some("one item")
        );
        assert_eq!(cat.get_plural("nope", 1, plural_rule_default), None);
    }

    #[test]
    fn parse_rejects_malformed_lines() {
        // Missing closing quote.
        let e = Catalog::parse("it", "msgid \"oops\nmsgstr \"x\"\n").unwrap_err();
        assert_eq!(e.line, 1);
        assert_eq!(e.kind, ParseErrorKind::Malformed);
        // msgstr with no preceding msgid.
        let e = Catalog::parse("it", "msgstr \"x\"\n").unwrap_err();
        assert_eq!(e.kind, ParseErrorKind::OrphanMsgstr);
        // Unknown keyword.
        let e = Catalog::parse("it", "msgfoo \"x\"\n").unwrap_err();
        assert_eq!(e.kind, ParseErrorKind::UnknownKeyword);
    }

    #[test]
    fn translate_falls_back_to_msgid() {
        let cat = Catalog::parse("it", "msgid \"Hello\"\nmsgstr \"Ciao\"\n").unwrap();
        assert_eq!(translate(&cat, "Hello"), "Ciao");
        assert_eq!(translate(&cat, "Untranslated"), "Untranslated");
    }

    #[test]
    fn plural_rule_default_matches_english() {
        assert_eq!(plural_rule_default(0), 1);
        assert_eq!(plural_rule_default(1), 0);
        assert_eq!(plural_rule_default(2), 1);
    }

    #[test]
    fn localization_resolves_active_then_fallback_then_msgid() {
        let en = Catalog::parse(
            "en",
            "msgid \"Hello\"\nmsgstr \"Hello\"\nmsgid \"Save\"\nmsgstr \"Save\"\n",
        )
        .unwrap();
        let it = Catalog::parse("it", "msgid \"Hello\"\nmsgstr \"Ciao\"\n").unwrap();
        let mut l10n = Localization::new("en");
        l10n.add_catalog(en);
        l10n.add_catalog(it);

        // Active = fallback (en).
        assert_eq!(l10n.active_locale(), "en");
        assert_eq!(l10n.translate("Hello"), "Hello");

        // Switch to it: "Hello" from it, "Save" falls back to en, unknown → msgid.
        assert!(l10n.set_locale("it"));
        assert_eq!(l10n.translate("Hello"), "Ciao");
        assert_eq!(l10n.translate("Save"), "Save"); // fallback
        assert_eq!(l10n.translate("Quit"), "Quit"); // msgid
    }

    #[test]
    fn set_locale_reports_missing_catalog_but_still_switches() {
        let mut l10n = Localization::new("en");
        l10n.add_catalog(Catalog::parse("en", "msgid \"Hi\"\nmsgstr \"Hi\"\n").unwrap());
        // No German catalog registered.
        assert!(!l10n.set_locale("de"));
        assert_eq!(l10n.active_locale(), "de");
        // Lookup still resolves via the fallback.
        assert_eq!(l10n.translate("Hi"), "Hi");
    }

    #[test]
    fn language_switch_is_live_and_reversible() {
        let en = Catalog::parse("en", "msgid \"Yes\"\nmsgstr \"Yes\"\n").unwrap();
        let it = Catalog::parse("it", "msgid \"Yes\"\nmsgstr \"Si\"\n").unwrap();
        let mut l10n = Localization::new("en");
        l10n.add_catalog(en);
        l10n.add_catalog(it);
        assert_eq!(l10n.translate("Yes"), "Yes");
        l10n.set_locale("it");
        assert_eq!(l10n.translate("Yes"), "Si"); // no restart needed
        l10n.set_locale("en");
        assert_eq!(l10n.translate("Yes"), "Yes"); // switched back
    }

    #[test]
    fn localization_translate_plural_through_active_and_fallback() {
        let mut en = Catalog::new("en");
        en.insert_plural("%d msg", &["%d message", "%d messages"]);
        let it = Catalog::new("it"); // no plural entry for it
        let mut l10n = Localization::new("en");
        l10n.add_catalog(en);
        l10n.add_catalog(it);
        l10n.set_locale("it");
        // Missing in it → fallback to en plural forms.
        assert_eq!(
            l10n.translate_plural("%d msg", 1, plural_rule_default),
            "%d message"
        );
        assert_eq!(
            l10n.translate_plural("%d msg", 3, plural_rule_default),
            "%d messages"
        );
        // Unknown msgid → msgid.
        assert_eq!(
            l10n.translate_plural("%d x", 2, plural_rule_default),
            "%d x"
        );
    }

    // --- WS12-07.4: number formatting --------------------------------------

    #[test]
    fn number_format_groups_integers_per_locale() {
        let en = NumberFormat::for_locale("en-US");
        let it = NumberFormat::for_locale("it");
        let fr = NumberFormat::for_locale("fr-FR");
        assert_eq!(en.format_i64(1_234_567), "1,234,567");
        assert_eq!(it.format_i64(1_234_567), "1.234.567");
        assert_eq!(fr.format_i64(1_234_567), "1 234 567");
        assert_eq!(en.format_i64(-1_000), "-1,000");
        assert_eq!(en.format_i64(42), "42"); // below grouping threshold
    }

    #[test]
    fn number_format_fixed_point_is_exact() {
        let en = NumberFormat::new(',', '.');
        let it = NumberFormat::new('.', ',');
        assert_eq!(en.format_fixed(123_456, 2), "1,234.56");
        assert_eq!(it.format_fixed(123_456, 2), "1.234,56");
        // Left-pads a value smaller than the fractional scale.
        assert_eq!(en.format_fixed(5, 2), "0.05");
        assert_eq!(en.format_fixed(-7, 2), "-0.07");
        // frac == 0 behaves like format_i64.
        assert_eq!(en.format_fixed(1_000, 0), "1,000");
    }

    #[test]
    fn unknown_locale_falls_back_to_english_numbers() {
        let x = NumberFormat::for_locale("xx-YY");
        assert_eq!(x.grouping(), ',');
        assert_eq!(x.decimal(), '.');
    }

    // --- WS12-07.5: date/time formatting -----------------------------------

    fn sample() -> CivilDateTime {
        CivilDateTime {
            year: 2026,
            month: 7,
            day: 4,
            hour: 14,
            minute: 5,
            second: 9,
        }
    }

    #[test]
    fn date_order_follows_locale() {
        let dt = sample();
        assert_eq!(
            DateTimeFormat::for_locale("en-US").format_date(&dt),
            "07/04/2026"
        );
        assert_eq!(
            DateTimeFormat::for_locale("it").format_date(&dt),
            "04/07/2026"
        );
        assert_eq!(
            DateTimeFormat::for_locale("de").format_date(&dt),
            "04.07.2026"
        );
        assert_eq!(
            DateTimeFormat::for_locale("ja").format_date(&dt),
            "2026/07/04"
        );
        // Unknown → ISO.
        assert_eq!(
            DateTimeFormat::for_locale("xx").format_date(&dt),
            "2026-07-04"
        );
    }

    #[test]
    fn time_uses_12_or_24_hour_per_locale() {
        let dt = sample();
        // it → 24h.
        assert_eq!(
            DateTimeFormat::for_locale("it").format_time(&dt),
            "14:05:09"
        );
        // en-US → 12h with meridiem.
        assert_eq!(
            DateTimeFormat::for_locale("en-US").format_time(&dt),
            "2:05:09 PM"
        );
    }

    #[test]
    fn twelve_hour_edges_map_correctly() {
        assert_eq!(to_12_hour(0), (12, "AM")); // midnight
        assert_eq!(to_12_hour(11), (11, "AM"));
        assert_eq!(to_12_hour(12), (12, "PM")); // noon
        assert_eq!(to_12_hour(23), (11, "PM"));
    }

    #[test]
    fn format_datetime_joins_date_and_time() {
        let dt = sample();
        assert_eq!(
            DateTimeFormat::for_locale("en-GB").format_datetime(&dt),
            "04/07/2026 14:05:09"
        );
    }

    #[test]
    fn primary_subtag_extracts_language() {
        assert_eq!(primary_subtag("pt-BR"), "pt");
        assert_eq!(primary_subtag("en_US"), "en");
        assert_eq!(primary_subtag("de"), "de");
        assert_eq!(primary_subtag(""), "");
    }

    // --- WS12-07.6: RTL layout ---------------------------------------------

    #[test]
    fn layout_direction_from_locale() {
        assert_eq!(LayoutDirection::from_locale("ar"), LayoutDirection::Rtl);
        assert_eq!(LayoutDirection::from_locale("he-IL"), LayoutDirection::Rtl);
        assert_eq!(LayoutDirection::from_locale("fa"), LayoutDirection::Rtl);
        assert_eq!(LayoutDirection::from_locale("en-US"), LayoutDirection::Ltr);
        assert_eq!(LayoutDirection::from_locale("it"), LayoutDirection::Ltr);
        assert!(LayoutDirection::from_locale("ur").is_rtl());
        assert!(!LayoutDirection::from_locale("de").is_rtl());
    }

    #[test]
    fn logical_edges_flip_with_direction() {
        assert_eq!(LayoutDirection::Ltr.leading_side(), Side::Left);
        assert_eq!(LayoutDirection::Ltr.trailing_side(), Side::Right);
        assert_eq!(LayoutDirection::Rtl.leading_side(), Side::Right);
        assert_eq!(LayoutDirection::Rtl.trailing_side(), Side::Left);
    }

    #[test]
    fn resolve_x_mirrors_only_in_rtl() {
        // LTR is identity.
        assert_eq!(LayoutDirection::Ltr.resolve_x(10, 20, 100), 10);
        // RTL mirrors: 100 - 10 - 20 = 70.
        assert_eq!(LayoutDirection::Rtl.resolve_x(10, 20, 100), 70);
        // A child flush to the leading edge lands flush to the opposite edge.
        assert_eq!(LayoutDirection::Rtl.resolve_x(0, 30, 100), 70);
        // Overflow clamps to 0 rather than underflowing.
        assert_eq!(LayoutDirection::Rtl.resolve_x(90, 30, 100), 0);
    }

    #[test]
    fn resolve_align_maps_logical_to_physical() {
        use LayoutDirection::{Ltr, Rtl};
        assert_eq!(Ltr.resolve_align(TextAlign::Start), PhysicalAlign::Left);
        assert_eq!(Ltr.resolve_align(TextAlign::End), PhysicalAlign::Right);
        assert_eq!(Rtl.resolve_align(TextAlign::Start), PhysicalAlign::Right);
        assert_eq!(Rtl.resolve_align(TextAlign::End), PhysicalAlign::Left);
        assert_eq!(Rtl.resolve_align(TextAlign::Center), PhysicalAlign::Center);
    }

    // --- WS12-07.8: extraction + translation pipeline ----------------------

    #[test]
    fn tr_macros_translate_at_runtime() {
        let mut l10n = Localization::new("en");
        let mut it = Catalog::parse("it", "msgid \"Save\"\nmsgstr \"Salva\"\n").unwrap();
        it.insert_plural("%d file", &["%d file", "%d file (pl)"]);
        l10n.add_catalog(it);
        l10n.set_locale("it");
        assert_eq!(crate::tr!(l10n, "Save"), "Salva");
        assert_eq!(crate::tr_plural!(l10n, "%d file", "%d files", 1), "%d file");
        assert_eq!(
            crate::tr_plural!(l10n, "%d file", "%d files", 3),
            "%d file (pl)"
        );
    }

    #[test]
    fn extract_collects_singular_and_plural_in_order() {
        let src = r#"
            let a = tr!(l10n, "Save");
            let b = tr_plural!(l10n, "%d file", "%d files", n);
            let c = tr!(l10n, "Open");
        "#;
        let msgs = extract_messages(src);
        assert_eq!(msgs.len(), 3);
        assert_eq!(msgs[0].msgid, "Save");
        assert_eq!(msgs[0].plural, None);
        assert_eq!(msgs[1].msgid, "%d file");
        assert_eq!(msgs[1].plural.as_deref(), Some("%d files"));
        assert_eq!(msgs[2].msgid, "Open");
    }

    #[test]
    fn extract_dedups_by_msgid() {
        let src = "tr!(l, \"Hi\"); tr!(l, \"Hi\"); tr!(l, \"Bye\");";
        let msgs = extract_messages(src);
        assert_eq!(msgs.len(), 2);
        assert_eq!(msgs[0].msgid, "Hi");
        assert_eq!(msgs[1].msgid, "Bye");
    }

    #[test]
    fn extract_ignores_strings_comments_and_false_positives() {
        let src = r#"
            let s = "not a call: tr!(l, \"nope\")";  // tr!(l, "also nope")
            /* block: tr!(l, "still nope") */
            let real = tr!(l10n, "Real");
            let sub = subtract!(x); // 'tr' as a suffix must not match
        "#;
        let msgs = extract_messages(src);
        assert_eq!(msgs.len(), 1);
        assert_eq!(msgs[0].msgid, "Real");
    }

    #[test]
    fn generate_pot_emits_empty_msgstr_template() {
        let msgs =
            extract_messages("tr!(l, \"Save\"); tr_plural!(l, \"%d file\", \"%d files\", n);");
        let pot = generate_pot(&msgs);
        assert!(pot.contains("msgid \"Save\"\nmsgstr \"\"\n"));
        assert!(pot.contains(
            "msgid \"%d file\"\nmsgid_plural \"%d files\"\nmsgstr[0] \"\"\nmsgstr[1] \"\"\n"
        ));
    }

    #[test]
    fn generate_pot_escapes_specials() {
        let msgs = alloc::vec![ExtractedMessage {
            msgid: "a\"b\nc".to_string(),
            plural: None,
        }];
        let pot = generate_pot(&msgs);
        assert!(pot.contains("msgid \"a\\\"b\\nc\"\n"));
    }

    #[test]
    fn merge_preserves_translations_drops_obsolete_omits_new() {
        let existing = Catalog::parse(
            "it",
            "msgid \"Save\"\nmsgstr \"Salva\"\nmsgid \"Old\"\nmsgstr \"Vecchio\"\n",
        )
        .unwrap();
        // Current sources have Save (kept) and New (untranslated); Old is gone.
        let msgs = alloc::vec![
            ExtractedMessage {
                msgid: "Save".to_string(),
                plural: None,
            },
            ExtractedMessage {
                msgid: "New".to_string(),
                plural: None,
            },
        ];
        let merged = merge(&existing, &msgs);
        assert_eq!(merged.locale(), "it");
        assert_eq!(merged.get("Save"), Some("Salva")); // preserved
        assert_eq!(merged.get("Old"), None); // obsolete dropped
        assert_eq!(merged.get("New"), None); // untranslated → falls back at runtime
    }

    #[test]
    fn merge_preserves_existing_plural_forms() {
        let mut existing = Catalog::new("it");
        existing.insert_plural("%d file", &["%d file", "%d file (pl)"]);
        let msgs = alloc::vec![ExtractedMessage {
            msgid: "%d file".to_string(),
            plural: Some("%d files".to_string()),
        }];
        let merged = merge(&existing, &msgs);
        assert_eq!(
            merged.get_plural("%d file", 5, plural_rule_default),
            Some("%d file (pl)")
        );
    }
}
