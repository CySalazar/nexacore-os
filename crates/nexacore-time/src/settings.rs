//! Timezone settings hook (WS12-02.6).
//!
//! [`TimezoneSetting`] is the surface the Settings panel binds to: it pairs a
//! human IANA zone name (`Europe/Rome`) with the POSIX TZ string the time
//! service actually evaluates, and serialises to the config store. A small
//! built-in table maps common IANA names to their POSIX strings so the panel
//! can offer a picker without shipping the full TZif database.

use alloc::string::{String, ToString};

use crate::tz::PosixTz;

/// The selected timezone, as stored by Settings and consumed by the clock.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TimezoneSetting {
    /// Human-facing IANA zone id, e.g. `"Europe/Rome"`.
    pub iana_name: String,
    /// The POSIX TZ string the time service evaluates.
    pub posix_tz: String,
}

impl TimezoneSetting {
    /// Build a setting from an IANA name, resolving its POSIX string from the
    /// built-in table. Returns `None` for an unknown zone.
    #[must_use]
    pub fn from_iana(iana_name: &str) -> Option<Self> {
        let posix = builtin_posix(iana_name)?;
        Some(Self {
            iana_name: iana_name.to_string(),
            posix_tz: posix.to_string(),
        })
    }

    /// The default zone (UTC).
    #[must_use]
    pub fn utc() -> Self {
        Self {
            iana_name: "UTC".to_string(),
            posix_tz: "UTC0".to_string(),
        }
    }

    /// Parse the stored POSIX string into an evaluable [`PosixTz`].
    #[must_use]
    pub fn timezone(&self) -> Option<PosixTz> {
        PosixTz::parse(&self.posix_tz)
    }

    /// Serialise to the config-store `key=value` form.
    #[must_use]
    pub fn serialize(&self) -> String {
        let mut s = String::new();
        s.push_str("timezone=");
        s.push_str(&self.iana_name);
        s.push_str("\nposix=");
        s.push_str(&self.posix_tz);
        s.push('\n');
        s
    }

    /// Parse the config-store form produced by [`Self::serialize`]. Returns
    /// `None` if either key is missing.
    #[must_use]
    pub fn parse(text: &str) -> Option<Self> {
        let mut iana = None;
        let mut posix = None;
        for line in text.lines() {
            let line = line.trim();
            if let Some(v) = line.strip_prefix("timezone=") {
                iana = Some(v.trim().to_string());
            } else if let Some(v) = line.strip_prefix("posix=") {
                posix = Some(v.trim().to_string());
            }
        }
        Some(Self {
            iana_name: iana?,
            posix_tz: posix?,
        })
    }
}

/// The built-in IANA→POSIX-TZ table (a curated subset; the full TZif database
/// is a future, larger data drop). Rules are the 2007-onward US and 1996-onward
/// EU conventions.
#[must_use]
pub fn builtin_posix(iana: &str) -> Option<&'static str> {
    Some(match iana {
        "UTC" => "UTC0",
        "Europe/London" => "GMT0BST,M3.5.0/1,M10.5.0",
        "Europe/Rome" | "Europe/Paris" | "Europe/Berlin" | "Europe/Madrid" => {
            "CET-1CEST,M3.5.0,M10.5.0/3"
        }
        "America/New_York" => "EST5EDT,M3.2.0,M11.1.0",
        "America/Chicago" => "CST6CDT,M3.2.0,M11.1.0",
        "America/Los_Angeles" => "PST8PDT,M3.2.0,M11.1.0",
        "Asia/Tokyo" => "JST-9",
        "Asia/Kolkata" => "IST-5:30",
        "Australia/Sydney" => "AEST-10AEDT,M10.1.0,M4.1.0/3",
        _ => return None,
    })
}

/// The IANA zone ids the built-in table knows, for a settings picker.
#[must_use]
pub fn builtin_zone_ids() -> &'static [&'static str] {
    &[
        "UTC",
        "Europe/London",
        "Europe/Rome",
        "Europe/Paris",
        "Europe/Berlin",
        "Europe/Madrid",
        "America/New_York",
        "America/Chicago",
        "America/Los_Angeles",
        "Asia/Tokyo",
        "Asia/Kolkata",
        "Australia/Sydney",
    ]
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    #[test]
    fn from_iana_resolves_and_evaluates() {
        let tz = TimezoneSetting::from_iana("Europe/Rome").unwrap();
        assert_eq!(tz.posix_tz, "CET-1CEST,M3.5.0,M10.5.0/3");
        let parsed = tz.timezone().unwrap();
        assert_eq!(parsed.std_utc_offset_secs(), 3600);
    }

    #[test]
    fn unknown_zone_is_none() {
        assert!(TimezoneSetting::from_iana("Mars/Olympus").is_none());
    }

    #[test]
    fn setting_round_trips_through_config() {
        let tz = TimezoneSetting::from_iana("America/New_York").unwrap();
        let text = tz.serialize();
        let parsed = TimezoneSetting::parse(&text).unwrap();
        assert_eq!(parsed, tz);
    }

    #[test]
    fn all_builtin_zones_parse() {
        for id in builtin_zone_ids() {
            let setting = TimezoneSetting::from_iana(id).unwrap();
            assert!(
                setting.timezone().is_some(),
                "zone {id} POSIX failed to parse"
            );
        }
    }
}
