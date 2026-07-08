//! Static allowlist of Ed25519 public keys that the kernel trusts to sign
//! driver manifests.
//!
//! Specified by `NCIP-Driver-Framework-013` § S5.4: the kernel MUST refuse
//! a driver whose manifest carries an `nexacore_issuer_pubkey` not present in
//! this table. There is **no TOFU / runtime trust acquisition** path —
//! every issuer is baked at compile time so the trust base is explicit,
//! small, auditable, and reviewable in a single location.
//!
//! ## Provisioning workflow
//!
//! Issuers are added by editing `docs/protocol/driver-issuers.toml` and
//! re-running the kernel build. Each entry consists of a 32-byte Ed25519
//! verifying key (the primary lookup key per § S5.4) and a short ASCII
//! label retained for boot-log auditability. The file format is
//! intentionally trivial so a human reviewer can verify it without
//! tooling.
//!
//! ## Phase 1 state
//!
//! No first-party driver image has been signed yet — the table is
//! empty. The first issuer will be provisioned alongside the
//! `nexacore-driver-virtio-net` image (P6.7.8 M1). Until then, every
//! `DriverLoad` call returns [`crate::driver_manifest::DriverManifestError::UnknownIssuer`]
//! because [`lookup_issuer`] cannot resolve any key.

use nexacore_crypto::signing::VERIFYING_KEY_LEN;

/// An entry in the static driver-issuer allowlist.
///
/// The `id` is a short ASCII label suitable for boot-log auditability
/// (e.g. `"nexacore-os-stichting"`, `"nexacore-driver-team"`); it is NOT used
/// to look up the entry. The primary lookup key per `NCIP-013` § S5.4
/// is the 32-byte verifying key itself — the same bytes the manifest
/// carries in `nexacore_issuer_pubkey`.
#[derive(Debug, Clone, Copy)]
pub struct KnownIssuer {
    /// Stable issuer identifier. ASCII-only. Logging metadata only —
    /// the kernel never uses this for an authority decision.
    pub id: &'static str,
    /// Ed25519 verifying key bytes (`VERIFYING_KEY_LEN = 32`).
    /// Primary lookup key.
    pub verifying_key: [u8; VERIFYING_KEY_LEN],
}

/// Static allowlist consulted by `DriverLoad`.
///
/// Keep the array as `&'static [...]` (rather than a `const N: usize`)
/// so adding entries is a one-line edit that does not cascade into
/// call-site array-length generics.
pub static KNOWN_ISSUERS: &[KnownIssuer] = &[
    // DEV-ONLY issuer: the Ed25519 verifying key derived from the
    // fixed CAFEBABE seed in `driver_cap_issuer::DRIVER_CAP_ISSUER_SEED`.
    // This is the *issuer* identity, NOT the kernel capability signer.
    // In Phase 1 the same seed serves double duty (issuer == kernel
    // signer) because no external issuer has been provisioned yet.
    // Production will replace this with the Stichting NexaCore key.
    KnownIssuer {
        id: "dev-only-cafebabe",
        verifying_key: [
            0xAA, 0x73, 0x31, 0x87, 0xFE, 0xB4, 0xD4, 0x8A, 0x0A, 0xF5, 0x65, 0x89, 0x0E, 0x96,
            0x79, 0xCA, 0x43, 0x28, 0xE4, 0x59, 0x85, 0xDB, 0x9A, 0xB3, 0x54, 0x58, 0xD3, 0xD1,
            0x80, 0xB5, 0x24, 0x16,
        ],
    },
];

/// Per-boot kernel capability-issuer verifying key, installed once at boot by
/// [`register_kernel_cap_issuer`] (NCIP-026 WI-6).
///
/// The kernel's *capability* signing key is derived per boot (TEE / entropy),
/// so its public half cannot be baked into the static [`KNOWN_ISSUERS`] table.
/// It is kept **separate** from the manifest-issuer allowlist on purpose: the
/// capability path ([`is_kernel_cap_issuer`]) must trust **only** this secret
/// per-boot key — never the public, dev-placeholder manifest issuers, which an
/// attacker could otherwise use to forge capability tokens. (`spin::Mutex`
/// rather than `spin::Once`: the kernel's `spin` build omits the `once` feature.)
static KERNEL_CAP_ISSUER: spin::Mutex<Option<[u8; VERIFYING_KEY_LEN]>> = spin::Mutex::new(None);

/// Register the per-boot kernel capability-issuer public key (NCIP-026 WI-6).
///
/// Call **once**, early in `kmain`, right after
/// [`crate::driver_cap_issuer::init_issuer_seed`] and **before** any driver is
/// spawned, so [`is_kernel_cap_issuer`] resolves the per-boot key that signed
/// the deposited capability tokens. Subsequent calls are no-ops.
pub fn register_kernel_cap_issuer(pubkey: [u8; VERIFYING_KEY_LEN]) {
    let mut guard = KERNEL_CAP_ISSUER.lock();
    if guard.is_none() {
        *guard = Some(pubkey);
    }
}

/// Whether `pubkey` is the per-boot kernel capability-issuer (NCIP-026 WI-6, R1).
///
/// Used by the driver-syscall path (`MmioMap`/`DmaMap`/`IrqAttach`) to check a
/// deposited capability token's issuer. Trusts **only** the per-boot secret key
/// registered by [`register_kernel_cap_issuer`] — deliberately NOT the static
/// manifest issuers, so a token signed with a public dev key is rejected. Returns
/// `false` before registration (fail-closed).
#[must_use]
pub fn is_kernel_cap_issuer(pubkey: &[u8; VERIFYING_KEY_LEN]) -> bool {
    KERNEL_CAP_ISSUER.lock().as_ref() == Some(pubkey)
}

/// Look an issuer up by Ed25519 verifying key. Returns `None` if the
/// key is not on the static allowlist.
///
/// Used by [`crate::driver_manifest::verify_manifest`] to check the
/// manifest's `nexacore_issuer_pubkey` field against the kernel-static
/// trust base before running the Ed25519 signature math (NCIP-013
/// § S5.4). The constant-time guarantee of the `subtle` crate is
/// not required: the issuer pubkey is non-secret (it ships in the
/// manifest, which is unencrypted on disk), and an attacker who can
/// observe timing of `KNOWN_ISSUERS` traversal learns nothing they
/// could not already learn by reading the binary.
#[must_use]
pub fn lookup_issuer(pubkey: &[u8; VERIFYING_KEY_LEN]) -> Option<&'static KnownIssuer> {
    KNOWN_ISSUERS.iter().find(|i| &i.verifying_key == pubkey)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dev_only_issuer_is_present() {
        assert_eq!(
            KNOWN_ISSUERS.len(),
            1,
            "P6.7.9: one DEV-ONLY issuer (CAFEBABE seed)"
        );
        assert_eq!(KNOWN_ISSUERS[0].id, "dev-only-cafebabe");
    }

    #[test]
    fn lookup_unknown_issuer_returns_none() {
        assert!(lookup_issuer(&[0u8; VERIFYING_KEY_LEN]).is_none());
        assert!(lookup_issuer(&[0xFFu8; VERIFYING_KEY_LEN]).is_none());
    }

    #[test]
    fn dev_only_issuer_key_matches_cap_issuer_seed() {
        let key = crate::driver_cap_issuer::kernel_signing_key();
        let derived = key.verifying_key().as_bytes();
        assert_eq!(
            &KNOWN_ISSUERS[0].verifying_key, &derived,
            "DEV-ONLY issuer verifying key must match the kernel signing key's public half"
        );
    }

    #[test]
    fn dev_only_lookup_succeeds() {
        let key = crate::driver_cap_issuer::kernel_signing_key();
        let derived = key.verifying_key().as_bytes();
        let found = lookup_issuer(&derived);
        assert!(
            found.is_some(),
            "DEV-ONLY issuer must be discoverable via lookup_issuer"
        );
        assert_eq!(found.unwrap().id, "dev-only-cafebabe");
    }

    #[test]
    fn known_issuer_struct_holds_id_and_key() {
        let issuer = KnownIssuer {
            id: "test-issuer",
            verifying_key: [0xAB; VERIFYING_KEY_LEN],
        };
        assert_eq!(issuer.id, "test-issuer");
        assert_eq!(issuer.verifying_key[0], 0xAB);
        assert_eq!(issuer.verifying_key.len(), 32);
    }

    #[test]
    fn kernel_cap_issuer_registers_and_is_separate_from_manifest_allowlist() {
        // NCIP-026 WI-6: the per-boot cap issuer is trusted ONLY via
        // `is_kernel_cap_issuer`, never via `lookup_issuer` (the manifest
        // allowlist), so a public manifest issuer cannot authorise a cap token.
        let cap_key = [0x5Au8; VERIFYING_KEY_LEN];
        // (This process-global slot is touched by no other test.)
        register_kernel_cap_issuer(cap_key);
        assert!(is_kernel_cap_issuer(&cap_key));
        assert!(!is_kernel_cap_issuer(&[0x00u8; VERIFYING_KEY_LEN]));
        // The static manifest allowlist does NOT contain the cap issuer, and the
        // cap path does NOT trust the static (public, dev) manifest issuer.
        assert!(lookup_issuer(&cap_key).is_none());
        assert!(!is_kernel_cap_issuer(&KNOWN_ISSUERS[0].verifying_key));
        // call_once semantics: a second registration does not overwrite.
        register_kernel_cap_issuer([0x11u8; VERIFYING_KEY_LEN]);
        assert!(is_kernel_cap_issuer(&cap_key));
        assert!(!is_kernel_cap_issuer(&[0x11u8; VERIFYING_KEY_LEN]));
    }
}
