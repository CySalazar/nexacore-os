//! MB14.c.2.c — PIT-based microsecond busy delay.
//!
//! The Intel MP-Spec § B.4 / SDM Vol 3A § 8.4 INIT-SIPI-SIPI handshake
//! demands two hard timings on the BSP between writes to the LAPIC ICR:
//!
//! - **10 ms** after the INIT IPI before the first SIPI, so the AP's
//!   INIT pulse can fully clear inside the LAPIC.
//! - **200 μs** between the two SIPIs (per Intel MP-Spec B.4 step 6).
//!
//! The kernel currently has no calibrated time source we can use that
//! early in boot — the LAPIC timer is preemption-only and the TSC ratio
//! is unknown until we calibrate it against a reference. The PIT
//! (Programmable Interval Timer at I/O ports 0x40–0x43) runs at a
//! fixed 1.193 182 `MHz` regardless of CPU frequency and exposes a
//! "OUT pin" status bit at port 0x61 bit 5, making channel 2 mode 0
//! (interrupt on terminal count) the canonical busy-wait timer for
//! early-boot AP startup.
//!
//! The implementation programs channel 2 in mode 0 with the requested
//! count, gates it via port 0x61 bit 0 (`SPKR_GATE`), then spins until
//! bit 5 (`SPKR_OUT`) goes high. The speaker is left muted (bit 1 = 0)
//! so the BSP delay does not produce audible tones.
//!
//! ## Range
//!
//! The PIT counter is 16 bits, so the maximum single-shot delay is
//! `0xFFFF / 1.193 MHz ≈ 54.9 ms`. MB14.c.2.c needs at most 10 ms;
//! [`pit_delay_us`] returns immediately if a longer delay is requested.
//!
//! ## References
//!
//! - Intel 8254 PIT datasheet (mode 0: interrupt on terminal count)
//! - IBM PC AT Technical Reference (port 0x61 layout)
//! - Intel MP-Spec v1.4 § B.4 — BSP Initialization of APs

#![allow(
    unsafe_code,
    reason = "port-I/O against the PIT and KBD-controller ports is unavoidable for an early-boot busy-wait"
)]

/// PIT base frequency in Hz: 1.193 182 `MHz`, fixed across every PC chipset
/// since the IBM PC AT.
const PIT_HZ: u32 = 1_193_182;

/// I/O port for PIT channel 2 data (count low byte then high byte).
#[cfg(target_arch = "x86_64")]
const PIT_CH2_DATA: u16 = 0x42;

/// I/O port for the PIT mode/command register.
#[cfg(target_arch = "x86_64")]
const PIT_MODE: u16 = 0x43;

/// KBD-controller status port: bit 0 gates PIT channel 2,
/// bit 1 routes its output to the speaker (left masked here),
/// bit 5 mirrors the channel-2 OUT pin.
#[cfg(target_arch = "x86_64")]
const KBD_CTRL_B: u16 = 0x61;

/// `KBD_CTRL_B` bit 0 — PIT channel 2 gate enable.
#[cfg(target_arch = "x86_64")]
const KBD_CTRL_B_SPKR_GATE: u8 = 1 << 0;

/// `KBD_CTRL_B` bit 1 — speaker data enable. Kept 0 in MB14.c.2.c so the
/// BSP delay does not produce audible tones.
#[cfg(target_arch = "x86_64")]
const KBD_CTRL_B_SPKR_DATA: u8 = 1 << 1;

/// `KBD_CTRL_B` bit 5 — PIT channel 2 OUT pin state. Goes high when the
/// channel reaches its terminal count.
#[cfg(target_arch = "x86_64")]
const KBD_CTRL_B_SPKR_OUT: u8 = 1 << 5;

/// PIT mode-byte programming channel 2 in mode 0 (interrupt on terminal
/// count), 16-bit binary count, access lobyte/hibyte.
///
/// Layout (Intel 8254 § "Mode Control Word"):
/// ```text
///   bits 7..6  = 10  (SC1=1, SC0=0 — channel 2)
///   bits 5..4  = 11  (RW1=1, RW0=1 — lobyte then hibyte)
///   bits 3..1  = 000 (M2=0, M1=0, M0=0 — mode 0)
///   bit  0     = 0   (binary count)
/// → 1011_0000 = 0xB0
/// ```
#[cfg(target_arch = "x86_64")]
const PIT_MODE_CH2_M0_BIN_LH: u8 = 0xB0;

/// Compute the 16-bit PIT count corresponding to `us` microseconds.
///
/// The PIT runs at `PIT_HZ` Hz, so a count of `N` expires after
/// `N / PIT_HZ` seconds. For a requested `us`-microsecond delay we want
/// `N = us * PIT_HZ / 1_000_000`. The product fits in `u64` for any `us`
/// up to the 16-bit count limit (~54.9 ms), so we use `u64` arithmetic
/// and clamp to `u16::MAX` on overflow.
///
/// Returns `None` when `us == 0` (no delay) or when the result would
/// overflow 16 bits (caller should split into multiple calls).
#[must_use]
pub fn pit_count_for_us(us: u32) -> Option<u16> {
    if us == 0 {
        return None;
    }
    let ticks: u64 = u64::from(us)
        .checked_mul(u64::from(PIT_HZ))?
        .checked_div(1_000_000)?;
    if ticks == 0 || ticks > u64::from(u16::MAX) {
        return None;
    }
    #[allow(
        clippy::cast_possible_truncation,
        reason = "ticks <= u16::MAX checked above"
    )]
    Some(ticks as u16)
}

/// Busy-wait for `us` microseconds via PIT channel 2 mode 0.
///
/// `us` ≤ 54 900 (the 16-bit PIT count limit). Larger requests are
/// silently truncated to a single 54.9 ms wait; callers requiring longer
/// delays must loop.
///
/// # Safety considerations
///
/// The function touches I/O ports `0x42`, `0x43`, and `0x61` directly.
/// On any standard PC firmware these belong to the legacy PIT / KBD
/// controller and are not claimed by another driver in this kernel.
///
/// Interrupts may stay enabled around the call; the PIT count race is
/// harmless because we never enable PIT IRQ delivery, only the OUT-pin
/// status bit at port `0x61`.
#[cfg(target_arch = "x86_64")]
pub fn pit_delay_us(us: u32) {
    use super::arch::{inb, outb};

    let Some(count) = pit_count_for_us(us) else {
        return;
    };

    // SAFETY: legacy PIT / KBD ports — no other driver in this kernel
    // claims them. All reads/writes are 8-bit, well-defined per Intel
    // 8254 spec / IBM PC AT Tech Ref.
    unsafe {
        // 1. Ensure speaker data is off, channel 2 gate is off.
        let b = inb(KBD_CTRL_B);
        outb(
            KBD_CTRL_B,
            b & !(KBD_CTRL_B_SPKR_GATE | KBD_CTRL_B_SPKR_DATA),
        );

        // 2. Program channel 2: mode 0, binary count, lobyte/hibyte.
        outb(PIT_MODE, PIT_MODE_CH2_M0_BIN_LH);
        outb(PIT_CH2_DATA, (count & 0xFF) as u8);
        outb(PIT_CH2_DATA, (count >> 8) as u8);

        // 3. Toggle the gate off→on to start the count from `count`.
        let b = inb(KBD_CTRL_B) & !(KBD_CTRL_B_SPKR_GATE | KBD_CTRL_B_SPKR_DATA);
        outb(KBD_CTRL_B, b);
        outb(KBD_CTRL_B, b | KBD_CTRL_B_SPKR_GATE);

        // 4. Spin until OUT goes high (terminal count reached).
        while (inb(KBD_CTRL_B) & KBD_CTRL_B_SPKR_OUT) == 0 {
            core::hint::spin_loop();
        }

        // 5. Close the gate so subsequent callers start clean.
        outb(KBD_CTRL_B, b);
    }
}

/// Non-x86 host stub. `cargo test --workspace --all-features` exercises
/// the count math through [`pit_count_for_us`]; the bare-metal delay is
/// not reachable from a host build.
#[cfg(not(target_arch = "x86_64"))]
pub fn pit_delay_us(_us: u32) {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zero_microseconds_returns_none() {
        assert_eq!(pit_count_for_us(0), None);
    }

    #[test]
    fn one_microsecond_rounds_down_to_one_tick() {
        // 1 µs * 1.193 MHz / 1 MHz ≈ 1.19 → integer count = 1.
        assert_eq!(pit_count_for_us(1), Some(1));
    }

    #[test]
    fn ten_milliseconds_yields_expected_count() {
        // 10 000 µs * 1 193 182 / 1 000 000 = 11_931
        assert_eq!(pit_count_for_us(10_000), Some(11_931));
    }

    #[test]
    fn two_hundred_microseconds_yields_expected_count() {
        // 200 µs * 1 193 182 / 1 000 000 = 238
        assert_eq!(pit_count_for_us(200), Some(238));
    }

    #[test]
    fn count_caps_at_pit_max_range() {
        // 55_000 µs * 1.193 MHz ≈ 65_625 > 0xFFFF → None.
        assert_eq!(pit_count_for_us(55_000), None);
    }

    #[test]
    fn count_at_max_pit_range() {
        // 54_900 µs * 1.193 MHz = 65_499 → fits in u16.
        let c = pit_count_for_us(54_900).expect("54.9 ms must fit");
        assert!(c < u16::MAX);
    }

    #[test]
    fn count_is_monotonic_in_microseconds() {
        let mut prev = 0u16;
        for us in [1u32, 10, 100, 1_000, 10_000] {
            let c = pit_count_for_us(us).expect("non-zero count");
            assert!(c > prev, "{us} µs should yield more ticks than {prev}");
            prev = c;
        }
    }
}
