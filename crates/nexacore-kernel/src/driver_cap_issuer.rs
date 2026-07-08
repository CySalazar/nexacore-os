//! Kernel-side Ed25519 signing key used to mint driver capability
//! tokens deposited at `DriverLoad` (P6.7.8.9, `NCIP-013` § S5.3 step 8).
//!
//! ## Two distinct trust roots
//!
//! `NCIP-013` deliberately separates two signing roles:
//!
//! 1. **Driver issuers** — the entities that sign `NexaCore-Pack v1`
//!    driver manifests. Their public keys live in
//!    [`crate::known_issuers::KNOWN_ISSUERS`] (`NCIP-013` § S5.4) and
//!    are consumed by [`crate::driver_manifest::verify_manifest`] at
//!    `DriverLoad` time.
//! 2. **Kernel capability issuer** — *this* module. The kernel itself
//!    signs the `CapabilityToken`s it deposits in a freshly-spawned
//!    driver's address space so that subsequent
//!    `MmioMap`/`DmaMap`/`IrqAttach` syscalls passing those tokens
//!    can be authenticated against
//!    [`crate::capabilities::Ed25519CapabilityProvider`].
//!
//! Keeping the two roots separate means a compromise of a driver
//! issuer key does NOT let the attacker mint capability tokens, and
//! vice versa.
//!
//! ## Per-boot seed (NCIP-026 WI-6)
//!
//! [`init_issuer_seed`] installs a **per-boot secret** signing seed at boot,
//! and [`kernel_signing_key`] uses it. On a confidential substrate the seed is
//! TEE-derived; otherwise it degrades to hardware entropy
//! ([`crate::entropy::seed_from_hw_32`]) — either way the signing key is no
//! longer the publicly-known [`DRIVER_CAP_ISSUER_SEED`] constant, so an attacker
//! cannot forge capability tokens with a known key (R1). The kernel registers
//! the public half as the *sole* trusted capability issuer
//! ([`crate::known_issuers::register_kernel_cap_issuer`] /
//! `is_kernel_cap_issuer`), kept separate from the manifest-issuer allowlist.
//! The constant survives only as a deterministic fallback for host unit tests
//! and any pre-`init` call.
//!
//! Remaining follow-up — the **TEE derivation** itself (`tee_seed`, a tracked
//! stub on the non-confidential VM103 substrate, NCIP-026 WI-8):
//! - On Intel TDX, derive from a fixed-context `TDREPORT` sealing key (HKDF over
//!   `TDREPORT.measurement` + a domain separator).
//! - On AMD SEV-SNP, derive from `SNP_DERIVE_KEY` with the same schema.
//!
//! Activating a real TEE root (key custody policy + activation gate) will need
//! its own NCIP.

use nexacore_crypto::signing::NexaCoreSigningKey;

/// 32-byte fallback seed for the kernel driver-capability issuer's Ed25519
/// signing key.
///
/// **DEV / FALLBACK ONLY.** A fixed, obviously-placeholder pattern
/// (`0xCA, 0xFE, 0xBA, 0xBE` × 8). On a real boot [`init_issuer_seed`] replaces
/// it with a per-boot **secret** seed (TEE-derived when available, otherwise
/// hardware entropy — NCIP-026 WI-6), so the signing key is no longer a publicly
/// known constant. This constant survives only as the value
/// [`kernel_signing_key`] returns when `init_issuer_seed` has not run — i.e. on
/// host unit tests and any pre-init call — keeping those paths deterministic.
pub const DRIVER_CAP_ISSUER_SEED: [u8; 32] = [
    0xCA, 0xFE, 0xBA, 0xBE, 0xCA, 0xFE, 0xBA, 0xBE, //
    0xCA, 0xFE, 0xBA, 0xBE, 0xCA, 0xFE, 0xBA, 0xBE, //
    0xCA, 0xFE, 0xBA, 0xBE, 0xCA, 0xFE, 0xBA, 0xBE, //
    0xCA, 0xFE, 0xBA, 0xBE, 0xCA, 0xFE, 0xBA, 0xBE, //
];

/// Per-boot issuer seed, installed once by [`init_issuer_seed`] at boot. While
/// `None`, [`kernel_signing_key`] falls back to [`DRIVER_CAP_ISSUER_SEED`].
/// (`spin::Mutex` rather than `spin::Once` — the kernel's `spin` build does not
/// enable the `once` feature.)
static ISSUER_SEED: spin::Mutex<Option<[u8; 32]>> = spin::Mutex::new(None);

/// Source the per-boot issuer seed from a hardware TEE sealing key, if one is
/// available on this machine (NCIP-026 WI-6 / WI-8).
///
/// Returns `None` today: NexaCore runs as an untrusted guest and no TEE has been
/// detected/activated yet, so the caller degrades to hardware entropy. The
/// TEE-derivation path is a tracked follow-up — on **Intel TDX** derive via
/// HKDF over a fixed-context `TDREPORT` sealing key, on **AMD SEV-SNP** via
/// `SNP_DERIVE_KEY` with the same domain separator (see the module docstring) —
/// and is intentionally not HW-testable on the non-confidential VM103 substrate.
#[must_use]
fn tee_seed() -> Option<[u8; 32]> {
    // No confidential-computing root is wired yet (WI-8). Probe-and-degrade.
    None
}

/// Install the per-boot kernel capability-issuer seed (NCIP-026 WI-6).
///
/// Call **once**, early in `kmain`, **before** any driver is spawned or any
/// capability is deposited — the deposited tokens are signed with this key and
/// the kernel registers its public half in the issuer allowlist
/// ([`crate::known_issuers::register_kernel_cap_issuer`]); both must be in place
/// before the first `MmioMap`/`DmaMap`/`IrqAttach`. Subsequent calls are no-ops
/// (the seed is fixed for the boot). Returns the source for the boot log.
///
/// Degrades to [`crate::entropy::seed_from_hw_32`] when no TEE is present, so
/// the signing key is still per-boot and secret (not the public CAFEBABE
/// constant) even on a non-confidential substrate.
pub fn init_issuer_seed() -> IssuerSeedSource {
    let (seed, source) = tee_seed().map_or_else(
        || {
            (
                crate::entropy::seed_from_hw_32(),
                IssuerSeedSource::HwEntropy,
            )
        },
        |s| (s, IssuerSeedSource::Tee),
    );
    let mut guard = ISSUER_SEED.lock();
    if guard.is_none() {
        *guard = Some(seed);
    }
    source
}

/// Where [`init_issuer_seed`] sourced the per-boot seed (boot-log telemetry).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IssuerSeedSource {
    /// Derived from a hardware TEE sealing key.
    Tee,
    /// Degraded to hardware entropy (no TEE present).
    HwEntropy,
}

/// Construct the kernel's driver-capability issuer signing key.
///
/// Uses the per-boot seed installed by [`init_issuer_seed`] when present,
/// otherwise the [`DRIVER_CAP_ISSUER_SEED`] fallback (host tests / pre-init).
/// The resulting [`NexaCoreSigningKey`] owns its key material with `ZeroizeOnDrop`;
/// callers should hold it on the stack for the minimum time needed to mint +
/// sign the deposit batch.
#[must_use]
pub fn kernel_signing_key() -> NexaCoreSigningKey {
    let seed = (*ISSUER_SEED.lock()).unwrap_or(DRIVER_CAP_ISSUER_SEED);
    NexaCoreSigningKey::from_bytes(seed)
}

/// The 32-byte Ed25519 **public** half of the current issuer signing key.
///
/// Registered in the issuer allowlist at boot so the WI-3 issuer check on the
/// `MmioMap`/`DmaMap`/`IrqAttach` path resolves the per-boot key.
#[must_use]
pub fn kernel_issuer_pubkey() -> [u8; 32] {
    kernel_signing_key().verifying_key().as_bytes()
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signing_key_round_trips_to_same_verifying_key() {
        // Both `NexaCoreSigningKey::from_bytes` calls deterministically
        // derive the same public key — verified by comparing the
        // raw 32-byte representations.
        let k1 = kernel_signing_key();
        let k2 = kernel_signing_key();
        assert_eq!(k1.verifying_key().as_bytes(), k2.verifying_key().as_bytes());
    }

    #[test]
    fn signing_key_produces_verifiable_signature() {
        let key = kernel_signing_key();
        let vk = key.verifying_key();
        let msg = b"P6.7.8.9 cap deposit trampoline";
        let sig = key.sign(msg);
        // `verify` returns `Ok(())` only when the signature matches
        // the message under the public key.
        assert!(vk.verify(msg, &sig).is_ok());
    }

    #[test]
    fn issuer_pubkey_matches_signing_key_public_half() {
        // NCIP-026 WI-6: the pubkey registered in the allowlist must be exactly
        // the public half of the key that signs deposited cap tokens. (No
        // `init_issuer_seed` here — that mutates process-global ISSUER_SEED and
        // would break the other tests' deterministic CAFEBABE fallback; the
        // boot-init path is HW-verified instead.)
        assert_eq!(
            kernel_issuer_pubkey(),
            kernel_signing_key().verifying_key().as_bytes()
        );
    }

    #[test]
    fn seed_is_documented_placeholder_pattern() {
        // Assert the seed matches the documented `0xCAFEBABE × 8`
        // pattern. If a future PR changes the placeholder, this test
        // catches the drift and forces the documentation to follow.
        for chunk in DRIVER_CAP_ISSUER_SEED.chunks_exact(4) {
            assert_eq!(chunk, &[0xCA, 0xFE, 0xBA, 0xBE]);
        }
    }
}
