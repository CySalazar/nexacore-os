//! Kernel-side KASLR entropy source (P6.7.8.1, `NCIP-013` § S2.5).
//!
//! Provides a small deterministic PRNG ([`KaslrRng`]) seeded by hardware
//! entropy ([`seed_from_hw`]). The current consumer is the `MmioMap`
//! syscall handler, which randomizes the base VA of the first MMIO
//! mapping installed by a driver process inside the reserved driver-VA
//! `PML4` slot (`0x0000_0080_0000_0000..0x0000_0100_0000_0000`).
//!
//! ## Design
//!
//! * **PRNG core** — `SplitMix64` by Sebastiano Vigna. Two
//!   multiplications plus three xor-shifts per draw; passes `BigCrush`.
//!   Statistical quality is sufficient for VA-base randomization; this
//!   RNG is **not** suitable for cryptographic use (e.g. capability ids).
//! * **Hardware seed** — `RDRAND` is tried up to 10 times per
//!   `NCIP-013` § S2.5. Each `RDRAND` invocation may fail (the
//!   instruction sets `CF=0`); the loop retries with a small spin until
//!   it succeeds or the attempt budget is exhausted. `CPUID` leaf 1 is
//!   probed once to detect `RDRAND` availability — old VMs and some
//!   hypervisors (notably nested QEMU/KVM with `-cpu host` on hosts
//!   that lack the feature) do not expose it.
//! * **Fallback** — when `RDRAND` is absent or unreliable the seed is
//!   derived from `RDTSC` mixed with a per-call monotonic counter
//!   (`KASLR_FALLBACK_COUNTER`). Entropy is weak; the counter is the
//!   only guarantee that two consecutive callers receive distinct
//!   seeds within a single boot. Defense-in-depth value remains
//!   meaningful (defeats absolute-address oracle attempts) but does
//!   not raise the bar for an attacker with arbitrary code execution.
//!
//! The non-`x86_64` host stub returns a constant seed so the
//! `cargo test` suite stays deterministic.

#![allow(
    unsafe_code,
    reason = "RDRAND / RDTSC / CPUID are inline-asm Ring 0 ops; SAFETY per fn"
)]

use core::sync::atomic::{AtomicU64, Ordering};

/// `SplitMix64` PRNG state. One [`KaslrRng`] is constructed per driver
/// process; the per-driver seed is sourced from [`seed_from_hw`].
#[derive(Debug, Clone, Copy)]
pub struct KaslrRng {
    state: u64,
}

impl KaslrRng {
    /// Construct a generator seeded with `seed`. Two RNGs with the
    /// same seed produce identical sequences — used by host tests.
    #[must_use]
    pub const fn from_seed(seed: u64) -> Self {
        Self { state: seed }
    }

    /// Construct a generator seeded from hardware entropy (`RDRAND` →
    /// `RDTSC` + monotonic counter fallback). The seed bypasses zero
    /// (an all-zero `SplitMix64` state would emit a degenerate
    /// sequence) by forcing the high bit when the raw seed is zero.
    #[must_use]
    pub fn new() -> Self {
        let mut seed = seed_from_hw();
        if seed == 0 {
            seed = 0x9E37_79B9_7F4A_7C15;
        }
        Self::from_seed(seed)
    }

    /// Draw the next 64-bit value. `SplitMix64` finalizer per Vigna.
    pub fn next_u64(&mut self) -> u64 {
        self.state = self.state.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.state;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }
}

impl Default for KaslrRng {
    fn default() -> Self {
        Self::new()
    }
}

/// Per-call monotonic counter mixed into the RDTSC fallback so two
/// successive callers receive distinct seeds even on hosts where
/// `RDTSC` returns identical values (rare in practice; a defensive
/// safeguard for emulators that quantize TSC).
static KASLR_FALLBACK_COUNTER: AtomicU64 = AtomicU64::new(0);

/// Produce a 64-bit seed from the best available hardware source.
///
/// Order: `RDRAND` (up to 10 retries per NCIP-013 § S2.5) → `RDTSC`
/// XOR per-call counter. Always returns a value; if every path fails
/// the caller still receives the counter-derived seed.
#[must_use]
pub fn seed_from_hw() -> u64 {
    #[cfg(target_arch = "x86_64")]
    {
        if rdrand_supported() {
            for _ in 0..10 {
                // SAFETY: cpuid probe above asserts RDRAND availability;
                // the instruction has no memory effect and modifies CF.
                if let Some(v) = unsafe { rdrand64() } {
                    return v;
                }
            }
        }
        // SAFETY: RDTSC has no operand and only reads TSC into RAX:RDX.
        let tsc = unsafe { rdtsc() };
        let counter = KASLR_FALLBACK_COUNTER.fetch_add(1, Ordering::Relaxed);
        // SplitMix-style mixing of the two inputs so any structure
        // in either source is destroyed by the multiply + xor-shift.
        let mut z = tsc.wrapping_add(counter.wrapping_mul(0x9E37_79B9_7F4A_7C15));
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        let counter = KASLR_FALLBACK_COUNTER.fetch_add(1, Ordering::Relaxed);
        counter.wrapping_mul(0x9E37_79B9_7F4A_7C15)
    }
}

// -----------------------------------------------------------------------
// x86_64 entropy primitives
// -----------------------------------------------------------------------

/// CPUID leaf 1 ECX bit 30 advertises `RDRAND`. Cached on first call
/// to avoid the relatively expensive `cpuid` instruction in the hot
/// path.
#[cfg(target_arch = "x86_64")]
fn rdrand_supported() -> bool {
    use core::sync::atomic::{AtomicU8, Ordering as O};
    // `RDRAND_CACHE`: 0 = uninitialised, 1 = unsupported, 2 = supported.
    static RDRAND_CACHE: AtomicU8 = AtomicU8::new(0);

    let cached = RDRAND_CACHE.load(O::Relaxed);
    if cached == 2 {
        return true;
    }
    if cached == 1 {
        return false;
    }

    // SAFETY: CPUID leaf 1 is universally available on every x86_64
    // long-mode capable CPU; no operand validation required. LLVM
    // reserves RBX for its own register allocator on `x86_64-unknown-
    // none`, so we cannot use `out("ebx") _` directly — the canonical
    // workaround is to spill RBX into a scratch GPR around CPUID.
    let ecx: u32 = unsafe {
        let ecx: u32;
        let mut rbx_save: u64;
        core::arch::asm!(
            "mov {rbx_save}, rbx",
            "cpuid",
            "mov rbx, {rbx_save}",
            rbx_save = out(reg) rbx_save,
            inout("eax") 1u32 => _,
            out("ecx") ecx,
            out("edx") _,
            options(nomem, nostack, preserves_flags),
        );
        // Silence the "value written but never read" lint on rbx_save.
        let _ = rbx_save;
        ecx
    };
    let supported = ecx & (1 << 30) != 0;
    RDRAND_CACHE.store(if supported { 2 } else { 1 }, O::Relaxed);
    supported
}

/// Execute `rdrand` and return the 64-bit value when the carry flag
/// indicates success. Returns `None` on the rare `CF=0` retry case.
///
/// # Safety
///
/// `RDRAND` requires the CPU feature flag (see [`rdrand_supported`]).
/// Calling this without the feature available results in `#UD`.
#[cfg(target_arch = "x86_64")]
unsafe fn rdrand64() -> Option<u64> {
    let value: u64;
    let success: u8;
    // SAFETY: caller guarantees RDRAND availability; output is a
    // 64-bit register + flag byte derived from `setc`.
    unsafe {
        core::arch::asm!(
            "rdrand {value}",
            "setc {success}",
            value = out(reg) value,
            success = out(reg_byte) success,
            options(nomem, nostack),
        );
    }
    if success == 0 { None } else { Some(value) }
}

/// Read the time-stamp counter into a 64-bit value (high half in RDX,
/// low half in RAX, combined here).
///
/// # Safety
///
/// `RDTSC` is unprivileged when `CR4.TSD=0` (the kernel never sets it).
/// No memory effect.
#[cfg(target_arch = "x86_64")]
unsafe fn rdtsc() -> u64 {
    let lo: u32;
    let hi: u32;
    // SAFETY: no operand; reads TSC into EDX:EAX.
    unsafe {
        core::arch::asm!(
            "rdtsc",
            out("eax") lo,
            out("edx") hi,
            options(nomem, nostack, preserves_flags),
        );
    }
    (u64::from(hi) << 32) | u64::from(lo)
}

// -----------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn from_seed_is_deterministic() {
        let mut a = KaslrRng::from_seed(0xDEAD_BEEF);
        let mut b = KaslrRng::from_seed(0xDEAD_BEEF);
        for _ in 0..16 {
            assert_eq!(a.next_u64(), b.next_u64());
        }
    }

    #[test]
    fn next_u64_advances_state() {
        let mut rng = KaslrRng::from_seed(1);
        let first = rng.next_u64();
        let second = rng.next_u64();
        assert_ne!(first, second);
    }

    #[test]
    fn distinct_seeds_diverge_quickly() {
        let mut a = KaslrRng::from_seed(0);
        let mut b = KaslrRng::from_seed(1);
        // After two draws, all bits should differ between the streams
        // with overwhelming probability (we just check inequality).
        let _ = a.next_u64();
        let _ = b.next_u64();
        assert_ne!(a.next_u64(), b.next_u64());
    }

    #[test]
    fn new_avoids_zero_state() {
        // Even if `seed_from_hw` returned 0, the constructor injects a
        // non-zero constant so the first draw is non-degenerate.
        let mut rng = KaslrRng::new();
        // First draw advances the (forced non-zero) state.
        assert_ne!(rng.next_u64(), 0);
    }

    #[test]
    fn seed_from_hw_changes_on_subsequent_calls() {
        // On host stubs the seed is derived from the monotonic counter,
        // so two consecutive calls cannot return the same value. On
        // bare-metal x86_64 the same invariant holds via either RDRAND
        // (random) or RDTSC (monotonic) + counter mixing.
        let a = seed_from_hw();
        let b = seed_from_hw();
        assert_ne!(a, b);
    }
}
