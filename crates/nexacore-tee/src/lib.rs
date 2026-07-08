//! # `nexacore-tee`
//!
//! Trusted Execution Environment abstractions for NexaCore OS.
//!
//! TEE attestation is the **hardware root of trust** for NexaCore OS. Mesh
//! participation is gated on producing a valid remote attestation report.
//! This crate exposes a vendor-neutral [`TeeBackend`] trait, plus concrete
//! implementations for Intel TDX and AMD SEV-SNP. Apple Secure Enclave and
//! `ARMv9` CCA Realms are planned for v1.1+.
//!
//! ## Status
//!
//! Draft v0.2 — P5.1 trait surface plus [`MockTeeBackend`] usable by every
//! other crate's tests. The TDX and SEV-SNP backends are implemented as
//! compile-only scaffolds gated behind feature flags; real hardware
//! integration lands in P5.2 / P5.3.
//!
//! ## Design rationale
//!
//! 1. **Vendor neutrality.** Callers depend only on [`TeeBackend`]. Adding
//!    a new TEE family is a matter of implementing the trait, not changing
//!    consumers.
//! 2. **No software fallback.** A node without a working TEE cannot
//!    participate in the mesh. The trait does NOT expose a "best-effort"
//!    mode — every method returns a hard [`TeeError`] if the platform is
//!    unsupported.
//! 3. **Attestation freshness.** Quotes are short-lived; re-attestation is
//!    cheap and frequent. Replay defence is the responsibility of the
//!    consumer (typically `nexacore-mesh`), which feeds a peer-supplied nonce
//!    into each call.
//! 4. **TEE diversity defence.** A break of one vendor MUST NOT break the
//!    whole network. The trait does not assume a single vendor, and the
//!    measurement allowlist is per-family.
//! 5. **`no_std + alloc`.** Mandatory: this crate is consumed by
//!    `nexacore-kernel` (`no_std + no_main`) in P6.
//!
//! ## Modules
//!
//! - [`traits`] — the [`TeeBackend`] trait, the [`TeeFamily`] enum, and the
//!   [`TeeError`] taxonomy.
//! - [`attestation`] — [`Quote`], [`Measurement`], [`Nonce`] types; vendor-
//!   neutral verification helpers.
//! - [`sealed_keys`] — [`SealedBlob`], [`SealPolicy`], [`TeeSharedKey`].
//! - [`mock`] (feature `mock`, default-on) — deterministic in-process
//!   backend for tests.
//! - `tdx` (feature `tdx`) — Intel TDX backend scaffold.
//! - `sev_snp` (feature `sev-snp`) — AMD SEV-SNP backend scaffold.
//!
//! See [`/docs/04-security-model.md`](../../../docs/04-security-model.md)
//! § "TEE compromise resistance" and
//! [`/docs/07-hardware-requirements.md`](../../../docs/07-hardware-requirements.md)
//! for the security and hardware policies this crate enforces.

#![doc(html_root_url = "https://docs.nexacore-os.org/nexacore-tee")]
#![cfg_attr(not(test), no_std)]
#![deny(missing_docs)]

extern crate alloc;

pub mod attestation;
pub mod cpuid;
pub mod sealed_keys;
pub mod sealing;
pub mod select;
pub mod traits;

#[cfg(feature = "mock")]
pub mod mock;

#[cfg(feature = "tdx")]
pub mod tdx;

#[cfg(feature = "sev-snp")]
pub mod sev_snp;

// -----------------------------------------------------------------------------
// Top-level re-exports
// -----------------------------------------------------------------------------
// We re-export the most-used types at the crate root so callers can write
// `use nexacore_tee::{TeeBackend, Quote, Measurement, SealedBlob};` without
// having to navigate the module tree.

pub use attestation::{Measurement, Nonce, Quote, QuoteVersion};
pub use cpuid::CpuVendor;
#[cfg(feature = "mock")]
pub use mock::MockTeeBackend;
pub use sealed_keys::{SealPolicy, SealedBlob, TeeSharedKey};
pub use sealing::{
    MasterKeyKdf, SealingAvailability, SealingBackendKind, SealingError, SealingProvider,
    SecurityProfile, SoftwareKeystore, Tpm2SealingProvider, current_security_profile,
    select_sealing_backend,
};
pub use select::{BackendAvailability, select_tee_family};
pub use traits::{TeeBackend, TeeError, TeeErrorKind, TeeFamily};

// -----------------------------------------------------------------------------
// Crate-level sanity tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod sanity {
    //! Crate-level sanity tests asserting the public surface compiles and
    //! that the type sizes are within reasonable bounds. Per-module tests
    //! live alongside the module they cover.

    use super::*;

    /// Compile-time size sanity. Quotes are variable-length, but
    /// [`Measurement`] and [`Nonce`] are fixed and small. If these change
    /// unexpectedly the test fires; the breaking change is then made
    /// explicit in a PR review.
    #[test]
    fn fixed_type_sizes_are_stable() {
        // 48 bytes per Intel TDX MRTD; cross-vendor common denominator.
        assert_eq!(core::mem::size_of::<Measurement>(), 48);
        // 32 bytes = 256 bits, sized for any modern hash output.
        assert_eq!(core::mem::size_of::<Nonce>(), 32);
        // TeeFamily must fit in one byte for compact wire encoding.
        assert!(core::mem::size_of::<TeeFamily>() <= 1);
    }
}
