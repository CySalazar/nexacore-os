//! POSIX-TZ timezone parsing and UTC→local conversion (WS12-02.4/.5).
//!
//! IANA distributes each zone's rules in a compact POSIX TZ string (the last
//! line of a TZif file), e.g. `CET-1CEST,M3.5.0,M10.5.0/3` or
//! `EST5EDT,M3.2.0,M11.1.0`. [`PosixTz::parse`] decodes the standard/daylight
//! abbreviations, their UTC offsets, and the `Mm.w.d` daylight-transition
//! rules; [`PosixTz::to_local`] applies them to a UTC instant to obtain the
//! effective offset, DST flag, and abbreviation.
//!
//! POSIX encodes the offset as the value *added to local time to reach UTC*, so
//! the sign is inverted relative to the familiar "UTC+1"; this module stores
//! the intuitive `utc_offset_secs` (seconds added to UTC to reach local).
//!
//! Only the `Mm.w.d` transition form is supported (the form IANA emits); the
//! Julian `Jn`/`n` forms parse to `None`.

use alloc::string::{String, ToString};

use crate::civil::{CivilTime, civil_to_unix, days_from_civil, weekday_from_days};

/// A daylight-transition rule in `Mm.w.d` form: month `m` (1–12), week `w`
/// (1–5, where 5 means "last"), weekday `dow` (0=Sunday), at `time_secs` local.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TzRule {
    /// Month, 1–12.
    pub month: u8,
    /// Week of month, 1–5 (5 = last occurrence).
    pub week: u8,
    /// Day of week, 0=Sunday..6=Saturday.
    pub dow: u8,
    /// Transition time, seconds after local midnight (default 2·3600).
    pub time_secs: i32,
}

/// The daylight-saving half of a zone.
#[derive(Debug, Clone, PartialEq, Eq)]
struct DstInfo {
    abbr: String,
    utc_offset_secs: i32,
    start: TzRule,
    end: TzRule,
}

/// A parsed POSIX timezone.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PosixTz {
    std_abbr: String,
    std_utc_offset_secs: i32,
    dst: Option<DstInfo>,
}

/// The result of resolving a UTC instant in a zone.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalTime {
    /// Seconds added to UTC to reach local time (e.g. +3600 for CET).
    pub utc_offset_secs: i32,
    /// Whether daylight saving is in effect.
    pub is_dst: bool,
    /// The abbreviation in effect (e.g. `"CEST"`).
    pub abbr: String,
}

impl PosixTz {
    /// The fixed-offset UTC zone.
    #[must_use]
    pub fn utc() -> Self {
        Self {
            std_abbr: "UTC".to_string(),
            std_utc_offset_secs: 0,
            dst: None,
        }
    }

    /// The standard-time UTC offset in seconds (seconds added to UTC).
    #[must_use]
    pub const fn std_utc_offset_secs(&self) -> i32 {
        self.std_utc_offset_secs
    }

    /// Parse a POSIX TZ string. Returns `None` on malformed input or an
    /// unsupported (`Jn`/`n`) transition form.
    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        let mut cur = s;
        let (std_abbr, rest) = take_abbr(cur)?;
        cur = rest;
        let (posix_off, rest) = take_offset(cur)?;
        cur = rest;
        let std_utc_offset_secs = -posix_off; // POSIX sign is inverted.

        if cur.is_empty() {
            return Some(Self {
                std_abbr,
                std_utc_offset_secs,
                dst: None,
            });
        }

        // Daylight abbreviation, optional offset (default: one hour east).
        let (dst_abbr, rest) = take_abbr(cur)?;
        cur = rest;
        let dst_utc_offset_secs = if cur.starts_with(',') {
            std_utc_offset_secs + 3600
        } else {
            let (dst_posix_off, rest) = take_offset(cur)?;
            cur = rest;
            -dst_posix_off
        };

        // ,start,end
        let rules = cur.strip_prefix(',')?;
        let (start_str, end_str) = rules.split_once(',')?;
        let start = parse_rule(start_str)?;
        let end = parse_rule(end_str)?;

        Some(Self {
            std_abbr,
            std_utc_offset_secs,
            dst: Some(DstInfo {
                abbr: dst_abbr,
                utc_offset_secs: dst_utc_offset_secs,
                start,
                end,
            }),
        })
    }

    /// Resolve `unix_secs` (UTC) to the local offset, DST flag, and abbreviation.
    #[must_use]
    pub fn to_local(&self, unix_secs: i64) -> LocalTime {
        let Some(dst) = &self.dst else {
            return LocalTime {
                utc_offset_secs: self.std_utc_offset_secs,
                is_dst: false,
                abbr: self.std_abbr.clone(),
            };
        };

        let year = crate::civil::unix_to_civil(unix_secs).year;
        // Start transition is specified in standard local time; end transition
        // in daylight local time. Convert both to UTC instants.
        let start_utc = rule_transition_utc(dst.start, year, self.std_utc_offset_secs);
        let end_utc = rule_transition_utc(dst.end, year, dst.utc_offset_secs);

        let is_dst = if start_utc <= end_utc {
            // Northern hemisphere: DST in [start, end).
            unix_secs >= start_utc && unix_secs < end_utc
        } else {
            // Southern hemisphere: DST wraps the year end.
            unix_secs >= start_utc || unix_secs < end_utc
        };

        if is_dst {
            LocalTime {
                utc_offset_secs: dst.utc_offset_secs,
                is_dst: true,
                abbr: dst.abbr.clone(),
            }
        } else {
            LocalTime {
                utc_offset_secs: self.std_utc_offset_secs,
                is_dst: false,
                abbr: self.std_abbr.clone(),
            }
        }
    }

    /// Convert a UTC instant to local broken-down civil time in this zone.
    #[must_use]
    pub fn to_civil_local(&self, unix_secs: i64) -> (CivilTime, LocalTime) {
        let local = self.to_local(unix_secs);
        let local_secs = unix_secs + i64::from(local.utc_offset_secs);
        (crate::civil::unix_to_civil(local_secs), local)
    }
}

/// Compute the UTC instant of an `Mm.w.d` transition in `year`, where the
/// transition wall time is expressed with `wall_utc_offset_secs` local offset.
fn rule_transition_utc(rule: TzRule, year: i64, wall_utc_offset_secs: i32) -> i64 {
    let day = nth_weekday_of_month(year, rule.month, rule.week, rule.dow);
    let local_secs = civil_to_unix(CivilTime {
        year,
        month: rule.month,
        day,
        hour: 0,
        minute: 0,
        second: 0,
        weekday: 0,
    }) + i64::from(rule.time_secs);
    // local = UTC + offset ⇒ UTC = local − offset.
    local_secs - i64::from(wall_utc_offset_secs)
}

/// The day-of-month of the `week`-th `dow` in `month`/`year` (`week` 5 = last).
fn nth_weekday_of_month(year: i64, month: u8, week: u8, dow: u8) -> u8 {
    let first_dow = weekday_from_days(days_from_civil(year, month, 1));
    // Days to add to the 1st to reach the first `dow`.
    let shift = (i64::from(dow) - i64::from(first_dow)).rem_euclid(7);
    let mut day = 1 + shift + i64::from(week.saturating_sub(1)) * 7;
    let dim = i64::from(days_in_month(year, month));
    while day > dim {
        day -= 7;
    }
    u8::try_from(day).unwrap_or(1)
}

/// Days in `month` of `year`, honouring leap years.
fn days_in_month(year: i64, month: u8) -> u8 {
    match month {
        2 if is_leap(year) => 29,
        2 => 28,
        4 | 6 | 9 | 11 => 30,
        // 1, 3, 5, 7, 8, 10, 12 (and, unreachably, out-of-range months).
        _ => 31,
    }
}

const fn is_leap(y: i64) -> bool {
    (y % 4 == 0 && y % 100 != 0) || y % 400 == 0
}

// ---- POSIX TZ string tokenisers --------------------------------------------

/// Take a zone abbreviation: either `<...>` quoted, or a run of ASCII letters.
fn take_abbr(s: &str) -> Option<(String, &str)> {
    if let Some(rest) = s.strip_prefix('<') {
        let end = rest.find('>')?;
        let name = rest.get(..end)?.to_string();
        let after = rest.get(end + 1..)?;
        return Some((name, after));
    }
    let len = s.chars().take_while(char::is_ascii_alphabetic).count();
    if len < 3 {
        return None;
    }
    let name = s.get(..len)?.to_string();
    let rest = s.get(len..)?;
    Some((name, rest))
}

/// Take a POSIX offset `[+|-]h[:mm[:ss]]`; returns `(seconds, rest)`.
fn take_offset(s: &str) -> Option<(i32, &str)> {
    let (sign, rest) = match s.as_bytes().first() {
        Some(b'-') => (-1, s.get(1..)?),
        Some(b'+') => (1, s.get(1..)?),
        _ => (1, s),
    };
    // Take the hh[:mm[:ss]] numeric run.
    let end = rest
        .find(|c: char| !(c.is_ascii_digit() || c == ':'))
        .unwrap_or(rest.len());
    let field = rest.get(..end)?;
    let after = rest.get(end..)?;
    if field.is_empty() {
        return None;
    }
    let mut parts = field.split(':');
    let h: i32 = parts.next()?.parse().ok()?;
    let m: i32 = parts.next().map_or(Some(0), |p| p.parse().ok())?;
    let sec: i32 = parts.next().map_or(Some(0), |p| p.parse().ok())?;
    Some((sign * (h * 3600 + m * 60 + sec), after))
}

/// Parse an `Mm.w.d[/time]` rule (only this form is supported).
fn parse_rule(s: &str) -> Option<TzRule> {
    let (date, time) = s.split_once('/').unwrap_or((s, "2"));
    let body = date.strip_prefix('M')?;
    let mut parts = body.split('.');
    let month: u8 = parts.next()?.parse().ok()?;
    let week: u8 = parts.next()?.parse().ok()?;
    let dow: u8 = parts.next()?.parse().ok()?;
    if parts.next().is_some() || !(1..=12).contains(&month) || !(1..=5).contains(&week) || dow > 6 {
        return None;
    }
    // time is a positive H[:M[:S]] with no sign.
    let (secs, rest) = take_offset(time)?;
    if !rest.is_empty() {
        return None;
    }
    Some(TzRule {
        month,
        week,
        dow,
        time_secs: secs,
    })
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    #[test]
    fn parse_fixed_utc() {
        let tz = PosixTz::parse("UTC0").unwrap();
        assert_eq!(tz.std_utc_offset_secs(), 0);
        assert_eq!(tz.to_local(1_704_067_200).abbr, "UTC");
    }

    #[test]
    fn parse_central_europe() {
        let tz = PosixTz::parse("CET-1CEST,M3.5.0,M10.5.0/3").unwrap();
        assert_eq!(tz.std_utc_offset_secs(), 3600); // CET = UTC+1

        // Mid-January 2024: standard time (CET, +1h, not DST).
        let jan = 1_705_320_000; // 2024-01-15T12:00:00Z
        let l = tz.to_local(jan);
        assert_eq!(l.utc_offset_secs, 3600);
        assert!(!l.is_dst);
        assert_eq!(l.abbr, "CET");

        // Mid-July 2024: daylight time (CEST, +2h, DST).
        let jul = 1_721_044_800; // 2024-07-15T12:00:00Z
        let l = tz.to_local(jul);
        assert_eq!(l.utc_offset_secs, 7200);
        assert!(l.is_dst);
        assert_eq!(l.abbr, "CEST");
    }

    #[test]
    fn cet_transitions_2024_are_exact() {
        let tz = PosixTz::parse("CET-1CEST,M3.5.0,M10.5.0/3").unwrap();
        // DST begins 2024-03-31 01:00 UTC (02:00 CET → 03:00 CEST).
        let just_before = 1_711_846_800 - 1; // 2024-03-31T00:59:59Z
        let at_start = 1_711_846_800; // 2024-03-31T01:00:00Z
        assert!(!tz.to_local(just_before).is_dst);
        assert!(tz.to_local(at_start).is_dst);

        // DST ends 2024-10-27 01:00 UTC (03:00 CEST → 02:00 CET).
        let just_before_end = 1_729_990_800 - 1; // 2024-10-27T00:59:59Z
        let at_end = 1_729_990_800; // 2024-10-27T01:00:00Z
        assert!(tz.to_local(just_before_end).is_dst);
        assert!(!tz.to_local(at_end).is_dst);
    }

    #[test]
    fn us_eastern_local_civil_time() {
        let tz = PosixTz::parse("EST5EDT,M3.2.0,M11.1.0").unwrap();
        assert_eq!(tz.std_utc_offset_secs(), -5 * 3600);
        // 2024-07-04T16:00:00Z → EDT (UTC-4) → 12:00 local.
        let (ct, l) = tz.to_civil_local(1_720_108_800);
        assert!(l.is_dst);
        assert_eq!(l.abbr, "EDT");
        assert_eq!((ct.year, ct.month, ct.day, ct.hour), (2024, 7, 4, 12));
    }

    #[test]
    fn southern_hemisphere_wraps_year() {
        // A stylised Southern zone: std UTC+10, DST UTC+11, Oct..Apr.
        let tz = PosixTz::parse("AEST-10AEDT,M10.1.0,M4.1.0/3").unwrap();
        // January (mid-summer south) is DST.
        assert!(tz.to_local(1_704_067_200).is_dst); // 2024-01-01
        // July (mid-winter south) is standard.
        assert!(!tz.to_local(1_720_000_000).is_dst); // 2024-07
    }

    #[test]
    fn malformed_and_unsupported_forms_rejected() {
        assert!(PosixTz::parse("").is_none());
        assert!(PosixTz::parse("XY0").is_none()); // abbr too short
        // Julian form unsupported.
        assert!(PosixTz::parse("EST5EDT,J100,J300").is_none());
    }
}
