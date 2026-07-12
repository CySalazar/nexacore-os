//! `date` - format an injected epoch timestamp (WS8-10.10).
//!
//! Pure `no_std` code has no ambient clock, so "now" is never read from the
//! environment: it is injected through the [`Clock`] seam (host double
//! [`FixedClock`]) or passed directly as an `i64` count of seconds since the
//! Unix epoch. Every function is therefore deterministic and host-testable.
//!
//! ## Integer calendar math, UTC
//!
//! Decomposition uses the well-known civil-from-days algorithm implemented
//! entirely with [`i64::div_euclid`] / [`i64::rem_euclid`] - the floor-division
//! methods - so there is no `/`/`%` operator, no floating point, and negative
//! (pre-1970) timestamps decompose correctly. All output is **UTC**: there is no
//! timezone seam, so no local-time offset is applied.
//!
//! ## Supported `strftime` specifiers
//!
//! | Spec | Meaning | Example |
//! |------|---------|---------|
//! | `%Y` | year (unpadded) | `2026` |
//! | `%y` | year mod 100, zero-padded | `26` |
//! | `%m` | month `01`-`12` | `07` |
//! | `%d` | day of month `01`-`31` | `12` |
//! | `%e` | day of month, space-padded | `12` / ` 1` |
//! | `%H` | hour `00`-`23` | `14` |
//! | `%I` | hour `01`-`12` (12-hour clock) | `02` |
//! | `%M` | minute `00`-`59` | `05` |
//! | `%S` | second `00`-`59` | `09` |
//! | `%p` | `AM` / `PM` | `PM` |
//! | `%j` | day of year `001`-`366` | `193` |
//! | `%a` | abbreviated weekday | `Sun` |
//! | `%A` | full weekday | `Sunday` |
//! | `%b` | abbreviated month | `Jul` |
//! | `%B` | full month | `July` |
//! | `%F` | ISO date, `%Y-%m-%d` | `2026-07-12` |
//! | `%T` | time, `%H:%M:%S` | `14:05:09` |
//! | `%%` | a literal `%` | `%` |
//!
//! Any other `%X` sequence is emitted verbatim (as `%X`), matching GNU `date`.

use alloc::{
    format,
    string::{String, ToString},
};

/// The default `date` output format: `Www Mmm _d HH:MM:SS YYYY` (UTC).
pub const DEFAULT_FORMAT: &str = "%a %b %e %H:%M:%S %Y";

/// A civil (Gregorian, UTC) date-time decomposed from an epoch second count.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CivilDateTime {
    /// Proleptic Gregorian year (may be negative for far-past timestamps).
    pub year: i64,
    /// Month of year, `1`-`12`.
    pub month: i64,
    /// Day of month, `1`-`31`.
    pub day: i64,
    /// Hour of day, `0`-`23`.
    pub hour: i64,
    /// Minute of hour, `0`-`59`.
    pub minute: i64,
    /// Second of minute, `0`-`59`.
    pub second: i64,
    /// Day of week, `0` = Sunday .. `6` = Saturday.
    pub weekday: i64,
    /// Day of year, `1`-`366`.
    pub ordinal: i64,
}

/// Days in the given number of whole seconds, flooring toward the past.
const SECS_PER_DAY: i64 = 86_400;

impl CivilDateTime {
    /// Decompose `secs` (seconds since the Unix epoch) into a UTC civil
    /// date-time. Negative values (before 1970) are handled correctly.
    #[must_use]
    pub fn from_epoch(secs: i64) -> Self {
        let days = secs.div_euclid(SECS_PER_DAY);
        let sod = secs.rem_euclid(SECS_PER_DAY);
        let (year, month, day) = civil_from_days(days);
        // Sunday-based weekday: 1970-01-01 (day 0) was a Thursday (index 4).
        let weekday = (days.rem_euclid(7) + 4).rem_euclid(7);
        let ordinal = days - days_from_civil(year, 1, 1) + 1;
        Self {
            year,
            month,
            day,
            hour: sod.div_euclid(3600),
            minute: sod.rem_euclid(3600).div_euclid(60),
            second: sod.rem_euclid(60),
            weekday,
            ordinal,
        }
    }
}

/// Convert a day count since the Unix epoch into `(year, month, day)` (UTC),
/// using Howard Hinnant's civil-from-days algorithm with floor division.
// The short names (`doe`, `doy`, `yoe`, `y`) are the canonical variable names
// from the published algorithm; renaming them would obscure the reference.
#[allow(clippy::similar_names)]
fn civil_from_days(days: i64) -> (i64, i64, i64) {
    // Shift the epoch to 0000-03-01 so leap days fall at the end of the cycle.
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097); // [0, 146096]
    let yoe = (doe - doe.div_euclid(1460) + doe.div_euclid(36_524) - doe.div_euclid(146_096))
        .div_euclid(365);
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe.div_euclid(4) - yoe.div_euclid(100)); // [0, 365]
    let mp = (5 * doy + 2).div_euclid(153); // [0, 11]
    let day = doy - (153 * mp + 2).div_euclid(5) + 1; // [1, 31]
    let month = if mp < 10 { mp + 3 } else { mp - 9 }; // [1, 12]
    let year = if month <= 2 { y + 1 } else { y };
    (year, month, day)
}

/// Convert a `(year, month, day)` UTC date into a day count since the Unix
/// epoch (inverse of [`civil_from_days`]).
// Canonical algorithm variable names (`doe`, `doy`, `yoe`); see above.
#[allow(clippy::similar_names)]
fn days_from_civil(year: i64, month: i64, day: i64) -> i64 {
    let y = if month <= 2 { year - 1 } else { year };
    let era = y.div_euclid(400);
    let yoe = y - era * 400; // [0, 399]
    let mp = if month > 2 { month - 3 } else { month + 9 };
    let doy = (153 * mp + 2).div_euclid(5) + day - 1; // [0, 365]
    let doe = yoe * 365 + yoe.div_euclid(4) - yoe.div_euclid(100) + doy; // [0, 146096]
    era * 146_097 + doe - 719_468
}

/// Abbreviated weekday name for `w` (`0` = Sunday).
const fn weekday_abbrev(w: i64) -> &'static str {
    match w {
        0 => "Sun",
        1 => "Mon",
        2 => "Tue",
        3 => "Wed",
        4 => "Thu",
        5 => "Fri",
        _ => "Sat",
    }
}

/// Full weekday name for `w` (`0` = Sunday).
const fn weekday_name(w: i64) -> &'static str {
    match w {
        0 => "Sunday",
        1 => "Monday",
        2 => "Tuesday",
        3 => "Wednesday",
        4 => "Thursday",
        5 => "Friday",
        _ => "Saturday",
    }
}

/// Abbreviated month name for `m` (`1` = January).
const fn month_abbrev(m: i64) -> &'static str {
    match m {
        1 => "Jan",
        2 => "Feb",
        3 => "Mar",
        4 => "Apr",
        5 => "May",
        6 => "Jun",
        7 => "Jul",
        8 => "Aug",
        9 => "Sep",
        10 => "Oct",
        11 => "Nov",
        _ => "Dec",
    }
}

/// Full month name for `m` (`1` = January).
const fn month_name(m: i64) -> &'static str {
    match m {
        1 => "January",
        2 => "February",
        3 => "March",
        4 => "April",
        5 => "May",
        6 => "June",
        7 => "July",
        8 => "August",
        9 => "September",
        10 => "October",
        11 => "November",
        _ => "December",
    }
}

/// Render one `strftime` specifier character against `dt`.
fn render_spec(dt: &CivilDateTime, c: char) -> String {
    match c {
        'Y' => dt.year.to_string(),
        'y' => format!("{:02}", dt.year.rem_euclid(100)),
        'm' => format!("{:02}", dt.month),
        'd' => format!("{:02}", dt.day),
        'e' => format!("{:2}", dt.day),
        'H' => format!("{:02}", dt.hour),
        'I' => format!("{:02}", hour12(dt.hour)),
        'M' => format!("{:02}", dt.minute),
        'S' => format!("{:02}", dt.second),
        'p' => if dt.hour < 12 { "AM" } else { "PM" }.to_string(),
        'j' => format!("{:03}", dt.ordinal),
        'a' => weekday_abbrev(dt.weekday).to_string(),
        'A' => weekday_name(dt.weekday).to_string(),
        'b' => month_abbrev(dt.month).to_string(),
        'B' => month_name(dt.month).to_string(),
        'F' => format!("{}-{:02}-{:02}", dt.year, dt.month, dt.day),
        'T' => format!("{:02}:{:02}:{:02}", dt.hour, dt.minute, dt.second),
        '%' => String::from("%"),
        other => format!("%{other}"),
    }
}

/// Twelve-hour-clock hour for a 24-hour `hour` (`0` and `12` both map sensibly).
const fn hour12(hour: i64) -> i64 {
    let h = hour.rem_euclid(12);
    if h == 0 { 12 } else { h }
}

/// Format `secs` (seconds since the Unix epoch) with a `strftime`-subset `fmt`.
///
/// See the [module docs](self) for the supported specifiers. Unknown specifiers
/// are echoed verbatim.
#[must_use]
pub fn format_epoch(secs: i64, fmt: &str) -> String {
    let dt = CivilDateTime::from_epoch(secs);
    let mut out = String::new();
    let mut chars = fmt.chars();
    while let Some(c) = chars.next() {
        if c == '%' {
            match chars.next() {
                Some(spec) => out.push_str(&render_spec(&dt, spec)),
                None => out.push('%'),
            }
        } else {
            out.push(c);
        }
    }
    out
}

/// Format `secs` with the [`DEFAULT_FORMAT`].
#[must_use]
pub fn format_default(secs: i64) -> String {
    format_epoch(secs, DEFAULT_FORMAT)
}

/// The seam that yields the current time as epoch seconds.
///
/// On hardware this bridges to the kernel's monotonic-plus-wall clock; host
/// tests use [`FixedClock`]. No utility ever reads an ambient clock directly.
pub trait Clock {
    /// The current time, in whole seconds since the Unix epoch (UTC).
    fn now(&self) -> i64;
}

/// A fixed-time host double for [`Clock`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FixedClock {
    /// The epoch second this clock always reports.
    secs: i64,
}

impl FixedClock {
    /// A clock frozen at `secs` seconds since the epoch.
    #[must_use]
    pub fn new(secs: i64) -> Self {
        Self { secs }
    }
}

impl Clock for FixedClock {
    fn now(&self) -> i64 {
        self.secs
    }
}

/// `date +FMT`: render the clock's current time with `fmt`.
#[must_use]
pub fn date<C: Clock>(clock: &C, fmt: &str) -> String {
    format_epoch(clock.now(), fmt)
}

/// `date`: render the clock's current time with the [`DEFAULT_FORMAT`].
#[must_use]
pub fn date_default<C: Clock>(clock: &C) -> String {
    format_default(clock.now())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn epoch_zero_is_thursday_1970() {
        let dt = CivilDateTime::from_epoch(0);
        assert_eq!(dt.year, 1970);
        assert_eq!(dt.month, 1);
        assert_eq!(dt.day, 1);
        assert_eq!(dt.hour, 0);
        assert_eq!(dt.minute, 0);
        assert_eq!(dt.second, 0);
        assert_eq!(dt.weekday, 4); // Thursday
        assert_eq!(dt.ordinal, 1);
    }

    #[test]
    fn known_timestamp_decomposes() {
        // 1_700_000_000 = 2023-11-14 22:13:20 UTC (a Tuesday).
        let dt = CivilDateTime::from_epoch(1_700_000_000);
        assert_eq!((dt.year, dt.month, dt.day), (2023, 11, 14));
        assert_eq!((dt.hour, dt.minute, dt.second), (22, 13, 20));
        assert_eq!(dt.weekday, 2);
    }

    #[test]
    fn leap_day_decomposes() {
        // 2020-02-29 00:00:00 UTC.
        let dt = CivilDateTime::from_epoch(1_582_934_400);
        assert_eq!((dt.year, dt.month, dt.day), (2020, 2, 29));
        assert_eq!(dt.ordinal, 60);
    }

    #[test]
    fn negative_timestamp_before_epoch() {
        // -1 second = 1969-12-31 23:59:59 UTC (a Wednesday).
        let dt = CivilDateTime::from_epoch(-1);
        assert_eq!((dt.year, dt.month, dt.day), (1969, 12, 31));
        assert_eq!((dt.hour, dt.minute, dt.second), (23, 59, 59));
        assert_eq!(dt.weekday, 3);
    }

    #[test]
    fn default_format_epoch_zero() {
        assert_eq!(format_default(0), "Thu Jan  1 00:00:00 1970");
    }

    #[test]
    fn iso_and_time_specifiers() {
        let secs = 1_700_000_000;
        assert_eq!(format_epoch(secs, "%F %T"), "2023-11-14 22:13:20");
    }

    #[test]
    fn twelve_hour_and_ampm() {
        // 22:13 -> 10:13 PM.
        assert_eq!(format_epoch(1_700_000_000, "%I:%M %p"), "10:13 PM");
        // Midnight -> 12 AM.
        assert_eq!(format_epoch(0, "%I %p"), "12 AM");
    }

    #[test]
    fn weekday_month_names_and_ordinal() {
        let secs = 1_700_000_000;
        assert_eq!(format_epoch(secs, "%A %B %j"), "Tuesday November 318");
        assert_eq!(format_epoch(secs, "%a %b"), "Tue Nov");
    }

    #[test]
    fn two_digit_year_and_space_padded_day() {
        // 2001-01-01: %y = 01, %e day padded.
        let dt = 978_307_200; // 2001-01-01 00:00:00 UTC
        assert_eq!(format_epoch(dt, "%y %e"), "01  1");
    }

    #[test]
    fn literal_percent_and_unknown_spec() {
        assert_eq!(format_epoch(0, "100%%"), "100%");
        assert_eq!(format_epoch(0, "%Q"), "%Q");
        // Trailing lone percent is emitted as-is.
        assert_eq!(format_epoch(0, "x%"), "x%");
    }

    #[test]
    fn clock_seam_drives_date() {
        let clock = FixedClock::new(1_700_000_000);
        assert_eq!(now_secs(&clock), 1_700_000_000);
        assert_eq!(date(&clock, "%F"), "2023-11-14");
        assert_eq!(date_default(&clock), "Tue Nov 14 22:13:20 2023");
    }

    /// Local helper mirroring a `Clock::now` read, for the seam test.
    fn now_secs<C: Clock>(clock: &C) -> i64 {
        clock.now()
    }

    #[test]
    fn round_trip_days_civil() {
        for &secs in &[0_i64, 1_700_000_000, -1, 1_582_934_400, 978_307_200] {
            let days = secs.div_euclid(SECS_PER_DAY);
            let (y, m, d) = civil_from_days(days);
            assert_eq!(days_from_civil(y, m, d), days);
        }
    }
}
