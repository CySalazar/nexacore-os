//! # `nexacore-time`
//!
//! The NexaCore OS time service (WS12-02): NTP synchronisation, a
//! monotonic/wall clock split, and IANA/POSIX timezone handling.
//!
//! | Concern | Item | Sub-task |
//! |---------|------|----------|
//! | SNTP client (query + parse + offset) | [`sntp`] | .1 |
//! | Wall-clock discipline from NTP offset | [`clock::WallClock::discipline`] | .2 |
//! | Monotonic clock, separate from wall | [`clock::MonotonicClock`] | .3 |
//! | IANA/POSIX timezone parsing | [`tz::PosixTz`] | .4 |
//! | UTC→local conversion | [`tz::PosixTz::to_civil_local`] | .5 |
//! | Settings-panel hook | [`settings::TimezoneSetting`] | .6 |
//!
//! Dep-free `no_std + alloc`, so it builds for `x86_64-unknown-none`. The
//! network transport for SNTP and the hardware timer source for the monotonic
//! clock are supplied by the caller; everything here is pure logic.
//!
//! ## Example
//!
//! ```
//! use nexacore_time::settings::TimezoneSetting;
//!
//! let tz = TimezoneSetting::from_iana("Europe/Rome")
//!     .unwrap()
//!     .timezone()
//!     .unwrap();
//! // 2024-07-15T12:00:00Z is CEST (UTC+2) → 14:00 local.
//! let (civil, local) = tz.to_civil_local(1_721_044_800);
//! assert_eq!(local.abbr, "CEST");
//! assert_eq!((civil.hour, civil.minute), (14, 0));
//! ```

#![no_std]
#![forbid(unsafe_code)]
#![deny(missing_docs)]

extern crate alloc;

pub mod civil;
pub mod clock;
pub mod settings;
pub mod sntp;
pub mod tz;
