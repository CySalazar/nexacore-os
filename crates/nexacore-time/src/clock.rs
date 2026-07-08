//! Monotonic and wall clocks with NTP disciplining (WS12-02.2/.3).
//!
//! Two clocks with different guarantees:
//!
//! * [`MonotonicClock`] never moves backward. It is driven by a hardware timer
//!   reading; [`MonotonicClock::tick`] clamps each new reading to be
//!   non-decreasing, so it is safe for measuring durations across an NTP step.
//! * [`WallClock`] maps the monotonic reading to Unix wall-clock time via an
//!   offset. An NTP measurement adjusts that offset
//!   ([`WallClock::discipline`]) — stepping wall time without ever perturbing
//!   the monotonic clock.

/// A never-decreasing monotonic clock, in nanoseconds.
#[derive(Debug, Clone, Copy, Default)]
pub struct MonotonicClock {
    ns: u64,
}

impl MonotonicClock {
    /// A monotonic clock starting at zero.
    #[must_use]
    pub const fn new() -> Self {
        Self { ns: 0 }
    }

    /// Feed a raw hardware-timer reading; the clock advances to it but never
    /// moves backward. Returns the (clamped) current value.
    pub fn tick(&mut self, raw_ns: u64) -> u64 {
        self.ns = self.ns.max(raw_ns);
        self.ns
    }

    /// The current monotonic value in nanoseconds.
    #[must_use]
    pub const fn now(self) -> u64 {
        self.ns
    }
}

/// A wall clock: Unix time in nanoseconds, expressed as the monotonic reading
/// plus a signed offset. Only the offset is disciplined by NTP.
#[derive(Debug, Clone, Copy, Default)]
pub struct WallClock {
    /// `wall_unix_ns = monotonic_ns + offset_ns`.
    offset_ns: i128,
}

impl WallClock {
    /// A wall clock with a zero offset (wall == monotonic until set).
    #[must_use]
    pub const fn new() -> Self {
        Self { offset_ns: 0 }
    }

    /// The current Unix wall time (nanoseconds) for a monotonic reading.
    #[must_use]
    pub fn now_unix_nanos(&self, monotonic_ns: u64) -> i128 {
        i128::from(monotonic_ns) + self.offset_ns
    }

    /// Set the wall clock so that `monotonic_ns` maps to `unix_ns`.
    pub fn set_from_unix(&mut self, unix_ns: i128, monotonic_ns: u64) {
        self.offset_ns = unix_ns - i128::from(monotonic_ns);
    }

    /// Apply an NTP offset (nanoseconds): shift wall time by `offset` without
    /// touching the monotonic clock. A positive offset means the local wall
    /// clock was behind the server and is stepped forward.
    pub fn discipline(&mut self, ntp_offset_ns: i64) {
        self.offset_ns += i128::from(ntp_offset_ns);
    }

    /// The current offset in nanoseconds.
    #[must_use]
    pub const fn offset_ns(&self) -> i128 {
        self.offset_ns
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn monotonic_never_goes_backward() {
        let mut c = MonotonicClock::new();
        assert_eq!(c.tick(100), 100);
        assert_eq!(c.tick(250), 250);
        // A backward reading (timer glitch) is clamped.
        assert_eq!(c.tick(50), 250);
        assert_eq!(c.now(), 250);
    }

    #[test]
    fn wall_clock_maps_and_disciplines() {
        let mut mono = MonotonicClock::new();
        let mut wall = WallClock::new();
        mono.tick(1_000);
        wall.set_from_unix(1_704_067_200_000_000_000, mono.now());
        assert_eq!(wall.now_unix_nanos(mono.now()), 1_704_067_200_000_000_000);

        // Time passes on the monotonic clock; wall tracks it.
        mono.tick(1_000 + 5_000_000_000);
        assert_eq!(
            wall.now_unix_nanos(mono.now()),
            1_704_067_200_000_000_000 + 5_000_000_000
        );

        // NTP says we are 250 ms behind: step wall forward, monotonic untouched.
        let before_mono = mono.now();
        wall.discipline(250_000_000);
        assert_eq!(mono.now(), before_mono);
        assert_eq!(
            wall.now_unix_nanos(mono.now()),
            1_704_067_200_000_000_000 + 5_000_000_000 + 250_000_000
        );
    }

    #[test]
    fn negative_discipline_steps_back_wall_only() {
        let mut wall = WallClock::new();
        wall.set_from_unix(1_000_000_000, 0);
        wall.discipline(-400_000_000);
        assert_eq!(wall.now_unix_nanos(0), 600_000_000);
    }
}
