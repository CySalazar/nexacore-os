//! `uptime` - format an injected uptime duration and load (WS8-10.10).
//!
//! Like the rest of the crate, `uptime` reads nothing ambient: the elapsed time
//! since boot, the load average, and the processor count are all injected as an
//! [`UptimeInfo`] value. All arithmetic is integer-only (via the `div_euclid` /
//! `rem_euclid` methods, so no `/`/`%` operator and no floating point); the load
//! average is carried as hundredths of a unit (`125` renders as `1.25`).
//!
//! ## Output shape
//!
//! [`uptime_clause`] renders the familiar `up H:MM` phrase, growing to
//! `up N days, H:MM` past a day and shrinking to `up M min` under an hour.
//! [`uptime_line`] assembles the full line, appending the user count, load
//! average, and processor count when those optional fields are present.

use alloc::{format, string::String, vec::Vec};

/// Seconds in a day and an hour, for the integer decomposition.
const SECS_PER_DAY: u64 = 86_400;
/// Seconds in an hour.
const SECS_PER_HOUR: u64 = 3_600;
/// Seconds in a minute.
const SECS_PER_MIN: u64 = 60;

/// A load average, each field expressed in **hundredths** of a unit so no
/// floating point is needed (e.g. `125` means a load of `1.25`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LoadAvg {
    /// One-minute load average, in hundredths.
    pub one: u32,
    /// Five-minute load average, in hundredths.
    pub five: u32,
    /// Fifteen-minute load average, in hundredths.
    pub fifteen: u32,
}

impl LoadAvg {
    /// Construct a load average from three hundredths values.
    #[must_use]
    pub const fn new(one: u32, five: u32, fifteen: u32) -> Self {
        Self { one, five, fifteen }
    }
}

/// Everything `uptime` needs, injected as a value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UptimeInfo {
    /// Seconds elapsed since boot.
    pub uptime_secs: u64,
    /// Number of logged-in users, if known.
    pub users: Option<u32>,
    /// Load average, if known.
    pub load: Option<LoadAvg>,
    /// Number of processors, if known.
    pub nproc: Option<u32>,
}

impl UptimeInfo {
    /// A minimal info carrying only an uptime duration.
    #[must_use]
    pub const fn from_secs(uptime_secs: u64) -> Self {
        Self {
            uptime_secs,
            users: None,
            load: None,
            nproc: None,
        }
    }
}

/// Render one hundredths value as `whole.frac` with two fractional digits.
fn render_hundredths(value: u32) -> String {
    let whole = value.div_euclid(100);
    let frac = value.rem_euclid(100);
    format!("{whole}.{frac:02}")
}

/// Render the `up ...` clause describing how long the system has been running.
///
/// - one hour or more, same day: `up H:MM`
/// - one day or more: `up N day[s], H:MM`
/// - under an hour: `up M min`
#[must_use]
pub fn uptime_clause(uptime_secs: u64) -> String {
    let days = uptime_secs.div_euclid(SECS_PER_DAY);
    let within_day = uptime_secs.rem_euclid(SECS_PER_DAY);
    let hours = within_day.div_euclid(SECS_PER_HOUR);
    let minutes = within_day
        .rem_euclid(SECS_PER_HOUR)
        .div_euclid(SECS_PER_MIN);

    if days > 0 {
        let day_word = if days == 1 { "day" } else { "days" };
        format!("up {days} {day_word}, {hours}:{minutes:02}")
    } else if hours > 0 {
        format!("up {hours}:{minutes:02}")
    } else {
        format!("up {minutes} min")
    }
}

/// Render `load average: a, b, c` from a [`LoadAvg`].
#[must_use]
pub fn format_load(load: LoadAvg) -> String {
    format!(
        "load average: {}, {}, {}",
        render_hundredths(load.one),
        render_hundredths(load.five),
        render_hundredths(load.fifteen)
    )
}

/// Assemble the full `uptime` line from an [`UptimeInfo`].
///
/// Always begins with the [`uptime_clause`]; then, for each present optional
/// field, appends a comma-separated segment: `N user[s]`, the load average, and
/// `N CPU[s]`.
#[must_use]
pub fn uptime_line(info: &UptimeInfo) -> String {
    let mut segments: Vec<String> = Vec::new();
    segments.push(uptime_clause(info.uptime_secs));
    if let Some(users) = info.users {
        let user_word = if users == 1 { "user" } else { "users" };
        segments.push(format!("{users} {user_word}"));
    }
    if let Some(load) = info.load {
        segments.push(format_load(load));
    }
    if let Some(nproc) = info.nproc {
        let cpu_word = if nproc == 1 { "CPU" } else { "CPUs" };
        segments.push(format!("{nproc} {cpu_word}"));
    }
    segments.join(", ")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clause_hours_and_minutes() {
        // 3h45m.
        assert_eq!(uptime_clause(3 * 3600 + 45 * 60), "up 3:45");
    }

    #[test]
    fn clause_pads_minutes() {
        // 1h05m.
        assert_eq!(uptime_clause(3600 + 5 * 60), "up 1:05");
    }

    #[test]
    fn clause_under_an_hour() {
        assert_eq!(uptime_clause(12 * 60), "up 12 min");
        assert_eq!(uptime_clause(0), "up 0 min");
    }

    #[test]
    fn clause_days_singular_and_plural() {
        assert_eq!(
            uptime_clause(SECS_PER_DAY + 2 * 3600 + 30 * 60),
            "up 1 day, 2:30"
        );
        assert_eq!(
            uptime_clause(3 * SECS_PER_DAY + 4 * 3600 + 5 * 60),
            "up 3 days, 4:05"
        );
    }

    #[test]
    fn load_renders_two_decimals() {
        assert_eq!(
            format_load(LoadAvg::new(125, 80, 7)),
            "load average: 1.25, 0.80, 0.07"
        );
    }

    #[test]
    fn full_line_with_all_fields() {
        let info = UptimeInfo {
            uptime_secs: 3 * 3600 + 45 * 60,
            users: Some(2),
            load: Some(LoadAvg::new(100, 50, 25)),
            nproc: Some(4),
        };
        assert_eq!(
            uptime_line(&info),
            "up 3:45, 2 users, load average: 1.00, 0.50, 0.25, 4 CPUs"
        );
    }

    #[test]
    fn full_line_singular_user_and_cpu() {
        let info = UptimeInfo {
            uptime_secs: 90 * 60,
            users: Some(1),
            load: None,
            nproc: Some(1),
        };
        assert_eq!(uptime_line(&info), "up 1:30, 1 user, 1 CPU");
    }

    #[test]
    fn line_from_secs_only() {
        assert_eq!(uptime_line(&UptimeInfo::from_secs(5400)), "up 1:30");
    }
}
