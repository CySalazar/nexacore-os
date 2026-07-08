//! Civil-time conversion between Unix seconds and calendar date/time.
//!
//! Uses Howard Hinnant's `days_from_civil` / `civil_from_days` algorithms,
//! which are exact for the full proleptic Gregorian calendar and branch-free.
//! All conversions are in UTC; timezone offsets are applied by [`crate::tz`].
#![allow(
    // Hinnant's algorithms are defined in terms of exact floor division.
    clippy::integer_division,
    // `era`/`yoe`/`doe`/`doy`/`mp` are the algorithm's canonical variable names.
    clippy::similar_names,
    // The algorithm's month (1..=12), day (1..=31), and time-of-day fields are
    // provably within u8 range by construction; the casts cannot truncate or
    // lose sign.
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss
)]

/// A broken-down civil date and time (UTC unless a timezone offset was applied
/// before construction).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CivilTime {
    /// Full year (e.g. 2024).
    pub year: i64,
    /// Month, 1–12.
    pub month: u8,
    /// Day of month, 1–31.
    pub day: u8,
    /// Hour, 0–23.
    pub hour: u8,
    /// Minute, 0–59.
    pub minute: u8,
    /// Second, 0–59.
    pub second: u8,
    /// Day of week, 0 = Sunday .. 6 = Saturday.
    pub weekday: u8,
}

/// Days from 1970-01-01 to the given civil date (Hinnant). Valid for any date.
#[must_use]
pub fn days_from_civil(y: i64, m: u8, d: u8) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400; // [0, 399]
    let mp = i64::from((u32::from(m) + 9) % 12); // Mar=0..Feb=11
    let doy = (153 * mp + 2) / 5 + i64::from(d) - 1; // [0, 365]
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy; // [0, 146096]
    era * 146_097 + doe - 719_468
}

/// Civil date from days since 1970-01-01 (Hinnant). Returns `(year, month,
/// day)`.
#[must_use]
pub fn civil_from_days(z: i64) -> (i64, u8, u8) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097; // [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365; // [0, 399]
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11]
    let d = (doy - (153 * mp + 2) / 5 + 1) as u8; // [1, 31]
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u8; // [1, 12]
    (if m <= 2 { y + 1 } else { y }, m, d)
}

/// The weekday (0 = Sunday) for a count of days since the Unix epoch.
#[must_use]
pub fn weekday_from_days(z: i64) -> u8 {
    // 1970-01-01 was a Thursday (=4). Rust's `rem_euclid` keeps it non-negative.
    ((z + 4).rem_euclid(7)) as u8
}

/// Convert Unix seconds (UTC) to a [`CivilTime`].
#[must_use]
pub fn unix_to_civil(unix_secs: i64) -> CivilTime {
    let days = unix_secs.div_euclid(86_400);
    let secs_of_day = unix_secs.rem_euclid(86_400);
    let (year, month, day) = civil_from_days(days);
    let hour = (secs_of_day / 3_600) as u8;
    let minute = ((secs_of_day % 3_600) / 60) as u8;
    let second = (secs_of_day % 60) as u8;
    CivilTime {
        year,
        month,
        day,
        hour,
        minute,
        second,
        weekday: weekday_from_days(days),
    }
}

/// Convert a civil UTC date/time back to Unix seconds. The time fields are not
/// range-validated beyond what the arithmetic implies.
#[must_use]
pub fn civil_to_unix(ct: CivilTime) -> i64 {
    let days = days_from_civil(ct.year, ct.month, ct.day);
    days * 86_400 + i64::from(ct.hour) * 3_600 + i64::from(ct.minute) * 60 + i64::from(ct.second)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn epoch_is_thursday() {
        let ct = unix_to_civil(0);
        assert_eq!((ct.year, ct.month, ct.day), (1970, 1, 1));
        assert_eq!(ct.weekday, 4); // Thursday
        assert_eq!((ct.hour, ct.minute, ct.second), (0, 0, 0));
    }

    #[test]
    fn known_timestamp_2024() {
        // 1704067200 = 2024-01-01T00:00:00Z (a Monday).
        let ct = unix_to_civil(1_704_067_200);
        assert_eq!((ct.year, ct.month, ct.day), (2024, 1, 1));
        assert_eq!(ct.weekday, 1); // Monday
    }

    #[test]
    fn leap_day_2000() {
        let secs = civil_to_unix(CivilTime {
            year: 2000,
            month: 2,
            day: 29,
            hour: 12,
            minute: 0,
            second: 0,
            weekday: 0,
        });
        let ct = unix_to_civil(secs);
        assert_eq!((ct.year, ct.month, ct.day, ct.hour), (2000, 2, 29, 12));
    }

    #[test]
    fn round_trip_many_dates() {
        for &s in &[
            -1i64,
            0,
            946_684_800,   // 2000-01-01
            1_234_567_890, // 2009-02-13
            1_704_067_200, // 2024-01-01
            4_102_444_800, // 2100-01-01
        ] {
            assert_eq!(civil_to_unix(unix_to_civil(s)), s);
        }
    }

    #[test]
    fn pre_epoch_date() {
        // 1969-12-31T23:59:59Z = -1
        let ct = unix_to_civil(-1);
        assert_eq!((ct.year, ct.month, ct.day), (1969, 12, 31));
        assert_eq!((ct.hour, ct.minute, ct.second), (23, 59, 59));
    }
}
