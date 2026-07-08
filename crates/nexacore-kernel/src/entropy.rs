//! Kernel-side CSPRNG for capability-token minting (P6.7.8.9).
//!
//! P6.7.8.8 closed the `DriverLoad (73)` syscall handler at the
//! signature-verification boundary but deferred NCIP-013 § S5.3 step 8
//! (minting attenuated child tokens and pre-installing them in the
//! driver's initial capability namespace). P6.7.8.9 wires that step.
//! Minting a `CapabilityToken` requires a fresh `CapabilityId`, which
//! consumes 16 bytes of cryptographic-quality randomness — this module
//! supplies them.
//!
//! ## Two-phase architecture
//!
//! **Phase 1 — early-boot seed.** [`seed_from_hw_32`] gathers 32 bytes
//! of entropy by mixing `RDRAND` and `RDTSC`:
//!
//! - `RDRAND` is queried via the same `CPUID 1/ECX bit 30` probe used
//!   by [`crate::kaslr`] (see `NCIP-013` § S2.5); each 64-bit chunk is
//!   retried up to 10 times if the carry flag indicates failure.
//! - The result is XOR-mixed with a `RDTSC` jitter chain. The mix
//!   defeats the published `RDRAND`-backdoor hypothesis by ensuring
//!   that *even a fully-controlled* `RDRAND` output is post-hoc `XOR`ed
//!   with a value the attacker cannot predict (`RDTSC` at the exact
//!   nanosecond of the call).
//!
//! The seed is consumed by [`KernelCsprng`] (a [`ChaCha20Rng`] wrapper
//! from `rand_chacha 0.3`).
//!
//! **Phase 2 — post-boot reseeding (designed, not yet wired).**
//! [`KernelCsprng::add_entropy`] and [`KernelCsprng::reseed`] let the
//! IRQ handler chain (`NCIP-013` § S4) and the network drivers
//! (`NCIP-Driver-Net-015`) feed environmental entropy into the CSPRNG
//! once the system is up. The Phase-1 RDRAND/RDTSC seed is enough to
//! safely mint the boot-time driver capability tokens; long-running
//! production workloads will want the upgraded entropy stream.
//!
//! ## Why not `nexacore-crypto[rng]`?
//!
//! `nexacore-crypto`'s `rng` feature pulls `getrandom 0.2`, which in turn
//! requires a working `libc::getrandom(2)` (Linux) or
//! `BCryptGenRandom` (Windows) — neither exists on
//! `x86_64-unknown-none`. The kernel therefore owns the bare-metal
//! CSPRNG path directly; this module is the single audit point.
//!
//! ## Why not enable `nexacore-capability/mint`?
//!
//! That feature path requires `nexacore-types/id-generation` which itself
//! requires `getrandom` — same bare-metal incompatibility. P6.7.8.9
//! bypasses it entirely: [`CapabilityId::from_bytes`] is
//! `pub const fn` and [`nexacore_capability::CapabilityToken::sign_payload`]
//! is unconditional, so the kernel constructs `TokenPayload` directly
//! with [`KernelCsprng`]-sourced bytes and signs with
//! [`nexacore_crypto::signing::NexaCoreSigningKey::sign`]. No bare-metal `getrandom`
//! pulled.
//!
//! [`CapabilityId::from_bytes`]: nexacore_types::identity::CapabilityId::from_bytes

#![allow(
    unsafe_code,
    reason = "RDRAND / RDTSC are inline-asm Ring 0 ops; SAFETY documented per fn"
)]

use core::sync::atomic::{AtomicU64, Ordering};

use rand_chacha::ChaCha20Rng;
use rand_core::{RngCore, SeedableRng};
use spin::Mutex;

/// Length of the Phase-1 seed extracted by [`seed_from_hw_32`].
pub const SEED_BYTES: usize = 32;

/// Per-call monotonic counter mixed into the RDTSC fallback so two
/// successive callers receive distinct seeds even on hosts where
/// `RDTSC` returns identical values (rare; some emulators quantize
/// the TSC). Duplicate of the pattern in [`crate::kaslr`], kept local
/// so the two modules stay independently auditable.
static SEED_FALLBACK_COUNTER: AtomicU64 = AtomicU64::new(0);

/// CSPRNG wrapper: a [`ChaCha20Rng`] plus the two phase-2 reseed APIs.
///
/// Construct via [`KernelCsprng::from_seed`]; the wider system
/// accesses the singleton through [`with_csprng`].
#[derive(Debug)]
pub struct KernelCsprng {
    inner: ChaCha20Rng,
}

impl KernelCsprng {
    /// Construct a fresh CSPRNG seeded from `seed`. Two CSPRNGs built
    /// from the same seed produce identical output streams — used by
    /// host tests to assert determinism.
    #[must_use]
    pub fn from_seed(seed: [u8; SEED_BYTES]) -> Self {
        Self {
            inner: ChaCha20Rng::from_seed(seed),
        }
    }

    /// Draw 16 random bytes. The primary consumer is `CapabilityId`
    /// construction (`UUIDv4`-shaped 16-byte identifier).
    #[must_use]
    pub fn next_16_bytes(&mut self) -> [u8; 16] {
        let mut out = [0u8; 16];
        self.inner.fill_bytes(&mut out);
        out
    }

    /// Mix `bytes` into the CSPRNG state without fully replacing the
    /// seed. Phase-2 entropy-folding API.
    ///
    /// Implementation: a fresh 32-byte buffer is filled with the
    /// current output stream, then byte-wise XOR-mixed with up to
    /// `SEED_BYTES` of `bytes` (any excess is dropped — callers
    /// wanting a full re-key should use [`Self::reseed`] instead),
    /// then the inner `ChaCha20Rng` is reseeded with the mixed
    /// buffer. The output stream therefore depends on *both* the
    /// prior state and the new entropy.
    ///
    /// Wakeup path callers will be hardware interrupt handlers + the
    /// network drivers (`NCIP-Driver-Net-015`) once Phase-2 wiring
    /// lands — see the module docstring.
    pub fn add_entropy(&mut self, bytes: &[u8]) {
        let mut buf = [0u8; SEED_BYTES];
        self.inner.fill_bytes(&mut buf);
        for (slot, b) in buf.iter_mut().zip(bytes.iter()) {
            *slot ^= *b;
        }
        self.inner = ChaCha20Rng::from_seed(buf);
    }

    /// Replace the seed wholesale with `new_seed`. Reserved for explicit
    /// re-key operations (e.g. wake-from-S3, manual operator action).
    /// Routine post-boot entropy folding should use [`Self::add_entropy`].
    pub fn reseed(&mut self, new_seed: [u8; SEED_BYTES]) {
        self.inner = ChaCha20Rng::from_seed(new_seed);
    }
}

// =============================================================================
// Global singleton
// =============================================================================

/// Global CSPRNG. Initialised lazily on first [`with_csprng`] call (or
/// eagerly by [`init_for_test`] under `cfg(test)`).
static KERNEL_CSPRNG: Mutex<Option<KernelCsprng>> = Mutex::new(None);

/// Run `f` with exclusive access to the kernel CSPRNG.
///
/// First call extracts a fresh Phase-1 seed via [`seed_from_hw_32`];
/// subsequent calls reuse the existing `ChaCha20Rng` state.
///
/// The closure runs while the spin lock is held — keep the work short
/// (allocate a 16-byte buffer, draw, leave). The CSPRNG itself uses
/// only stack-resident state.
#[must_use = "the closure return value is the only output of the CSPRNG call"]
pub fn with_csprng<F, R>(f: F) -> R
where
    F: FnOnce(&mut KernelCsprng) -> R,
{
    let mut guard = KERNEL_CSPRNG.lock();
    let rng = guard.get_or_insert_with(|| KernelCsprng::from_seed(seed_from_hw_32()));
    f(rng)
}

/// `cfg(test)` helper that resets the global CSPRNG to a deterministic
/// seed. Tests that depend on a specific draw sequence call this in
/// their setup; production code never touches the singleton this way.
#[cfg(test)]
pub fn init_for_test(seed: [u8; SEED_BYTES]) {
    *KERNEL_CSPRNG.lock() = Some(KernelCsprng::from_seed(seed));
}

// =============================================================================
// Hardware seed extraction
// =============================================================================

/// Extract a 32-byte Phase-1 seed from hardware.
///
/// `RDRAND`-preferred, `RDTSC`-fallback, both XOR-mixed so a compromised
/// `RDRAND` does not fully determine the seed.
///
/// Always returns 32 bytes. On the `x86_64` target the first 16
/// 64-bit chunks come from `RDRAND` (10-retry budget per chunk) and
/// the second 16 chunks worth of mixing come from `RDTSC` + the
/// monotonic counter. On non-`x86_64` host stubs only the counter +
/// `SplitMix` mixing is used; this is fine for the test-only path.
#[must_use]
pub fn seed_from_hw_32() -> [u8; SEED_BYTES] {
    let mut seed = [0u8; SEED_BYTES];
    #[cfg(target_arch = "x86_64")]
    {
        // 4 × 64-bit chunks from RDRAND (when available).
        let mut rdrand_buf = [0u64; 4];
        if rdrand_supported() {
            for slot in &mut rdrand_buf {
                for _ in 0..10 {
                    // SAFETY: cpuid probe above asserts availability.
                    if let Some(v) = unsafe { rdrand64() } {
                        *slot = v;
                        break;
                    }
                }
            }
        }

        // 4 × 64-bit chunks from RDTSC + monotonic counter +
        // SplitMix64 finalizer (per-chunk, so consecutive chunks differ
        // even on emulators with quantized TSC).
        let mut rdtsc_buf = [0u64; 4];
        for slot in &mut rdtsc_buf {
            // SAFETY: RDTSC has no operand; reads TSC into EDX:EAX.
            let tsc = unsafe { rdtsc() };
            let counter = SEED_FALLBACK_COUNTER.fetch_add(1, Ordering::Relaxed);
            let mut z = tsc.wrapping_add(counter.wrapping_mul(0x9E37_79B9_7F4A_7C15));
            z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
            *slot = z ^ (z >> 31);
        }

        // Interleave RDRAND and RDTSC chunks via XOR. Result: even if
        // RDRAND is fully attacker-controlled, the XOR with an
        // attacker-unobservable RDTSC value keeps the output
        // unpredictable.
        for (i, chunk) in rdrand_buf.iter().zip(rdtsc_buf.iter()).enumerate() {
            let mixed = chunk.0 ^ chunk.1;
            // Write LE bytes into `seed[i*8 .. i*8+8]` — i ∈ 0..4 so
            // the index range is statically in bounds.
            #[allow(
                clippy::indexing_slicing,
                reason = "i < 4 by loop construction; seed.len() == 32 > 31 = 4*8-1"
            )]
            {
                let base = i * 8;
                seed[base..base + 8].copy_from_slice(&mixed.to_le_bytes());
            }
        }
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        // Host stub: monotonic counter + SplitMix finalizer. Sufficient
        // for unit tests that need *some* variation across calls but
        // never gets to bare-metal production.
        for slot_idx in 0..4 {
            let counter = SEED_FALLBACK_COUNTER.fetch_add(1, Ordering::Relaxed);
            let mut z = counter.wrapping_add((slot_idx as u64).wrapping_mul(0x9E37_79B9_7F4A_7C15));
            z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
            let bytes = (z ^ (z >> 31)).to_le_bytes();
            #[allow(clippy::indexing_slicing, reason = "slot_idx < 4; seed.len() == 32")]
            {
                let base = slot_idx * 8;
                seed[base..base + 8].copy_from_slice(&bytes);
            }
        }
    }
    seed
}

// -----------------------------------------------------------------------
// x86_64 entropy primitives — duplicated from `crate::kaslr` so the two
// modules stay independently auditable. The duplication is intentional;
// merging them via a shared private helper would obscure the audit
// trail.
// -----------------------------------------------------------------------

#[cfg(target_arch = "x86_64")]
fn rdrand_supported() -> bool {
    use core::sync::atomic::{AtomicU8, Ordering as O};
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
    // reserves RBX on `x86_64-unknown-none`, so we spill RBX into a
    // scratch GPR around the CPUID — same workaround as
    // `crate::kaslr::rdrand_supported`.
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
        let _ = rbx_save;
        ecx
    };
    let supported = ecx & (1 << 30) != 0;
    RDRAND_CACHE.store(if supported { 2 } else { 1 }, O::Relaxed);
    supported
}

#[cfg(target_arch = "x86_64")]
unsafe fn rdrand64() -> Option<u64> {
    let value: u64;
    let success: u8;
    // SAFETY: caller guarantees RDRAND availability; output is a
    // 64-bit register + a flag byte derived from `setc`.
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

#[cfg(target_arch = "x86_64")]
unsafe fn rdtsc() -> u64 {
    let lo: u32;
    let hi: u32;
    // SAFETY: no operand; reads TSC into EDX:EAX (`CR4.TSD = 0` in
    // kernel mode by construction).
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

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seed_from_hw_returns_32_bytes() {
        let seed = seed_from_hw_32();
        // Length is statically 32; assert anyway so the contract is
        // exercised by `cargo test`.
        assert_eq!(seed.len(), 32);
    }

    #[test]
    fn seed_from_hw_changes_on_subsequent_calls() {
        let a = seed_from_hw_32();
        let b = seed_from_hw_32();
        assert_ne!(a, b, "two consecutive seeds must differ");
    }

    #[test]
    fn from_seed_is_deterministic() {
        let seed = [0xAB; 32];
        let mut a = KernelCsprng::from_seed(seed);
        let mut b = KernelCsprng::from_seed(seed);
        for _ in 0..8 {
            assert_eq!(a.next_16_bytes(), b.next_16_bytes());
        }
    }

    #[test]
    fn next_16_bytes_advances_state() {
        let mut rng = KernelCsprng::from_seed([1; 32]);
        let first = rng.next_16_bytes();
        let second = rng.next_16_bytes();
        assert_ne!(first, second);
    }

    #[test]
    fn add_entropy_changes_subsequent_output() {
        let seed = [0x42; 32];
        let mut a = KernelCsprng::from_seed(seed);
        let mut b = KernelCsprng::from_seed(seed);
        b.add_entropy(b"phase-2 entropy injection");
        // After folding, the streams must diverge.
        assert_ne!(a.next_16_bytes(), b.next_16_bytes());
    }

    #[test]
    fn reseed_replaces_state() {
        let mut a = KernelCsprng::from_seed([0; 32]);
        let mut b = KernelCsprng::from_seed([0; 32]);
        let _ = a.next_16_bytes();
        // Reseed `a` to the same seed `b` was started with — its next
        // draw must match the first draw `b` was about to produce.
        a.reseed([0; 32]);
        assert_eq!(a.next_16_bytes(), b.next_16_bytes());
    }

    #[test]
    fn with_csprng_returns_consistent_stream_after_init_for_test() {
        init_for_test([0xCD; 32]);
        let a = with_csprng(KernelCsprng::next_16_bytes);
        let b = with_csprng(KernelCsprng::next_16_bytes);
        // Same singleton — second call must differ from the first.
        assert_ne!(a, b);
    }
}
