//! TEE-bound sealed-key primitives: [`SealedBlob`], [`SealPolicy`], and
//! [`TeeSharedKey`].
//!
//! Sealing binds an opaque blob to a specific TEE measurement and family.
//! Only the same TEE measurement, running on the same family, can unseal
//! the blob later. This is the foundation for persistent state (per-user
//! token vaults in `nexacore-tokenization`, long-lived session keys, the
//! BDFL-veto signing key once the founder transitions to a TEE-resident
//! key, …).
//!
//! `TeeSharedKey` is the return type of
//! [`crate::TeeBackend::derive_key_for`]: a 32-byte symmetric key bound
//! to a peer attestation, suitable as IKM for HKDF.

use alloc::vec::Vec;

use crate::{attestation::Measurement, traits::TeeFamily};

// -----------------------------------------------------------------------------
// SealPolicy
// -----------------------------------------------------------------------------

/// The policy under which a blob is sealed.
///
/// Sealing requires the **same TEE family** AND the **same measurement**
/// to unseal. A future extension may add coarser policies (e.g., "any
/// measurement signed by the same vendor key"), but the v1 contract is
/// strict equality.
#[derive(Debug, Clone, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub struct SealPolicy {
    /// The TEE family allowed to unseal.
    pub family: TeeFamily,
    /// The measurement allowed to unseal. Byte-equality with the
    /// unsealing TEE's measurement is required.
    pub measurement: Measurement,
}

impl SealPolicy {
    /// Convenience constructor.
    #[must_use]
    pub const fn new(family: TeeFamily, measurement: Measurement) -> Self {
        Self {
            family,
            measurement,
        }
    }

    /// Returns `true` if `(other_family, other_measurement)` is allowed
    /// to unseal under this policy.
    #[must_use]
    pub fn allows(&self, other_family: TeeFamily, other_measurement: &Measurement) -> bool {
        self.family == other_family && &self.measurement == other_measurement
    }
}

// -----------------------------------------------------------------------------
// SealedBlob
// -----------------------------------------------------------------------------

/// A blob sealed under a [`SealPolicy`]. The blob is safe to persist to
/// untrusted storage.
///
/// The on-disk layout (when written via `postcard` per `NCIP-Serde-004`) is:
///
/// ```text
/// ┌────────────────────┬──────────────────────┬─────────────┐
/// │ envelope version 1 │  serialized policy   │  ciphertext │
/// │      (u8)          │   (postcard bytes)   │  (Vec<u8>)  │
/// └────────────────────┴──────────────────────┴─────────────┘
/// ```
///
/// The envelope version is included so future formats can be introduced
/// without breaking old blobs.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct SealedBlob {
    /// Envelope version. Increment per NCIP.
    pub envelope_version: u8,
    /// The sealing policy. Stored alongside the ciphertext so the
    /// backend can quickly reject blobs whose policy does not match the
    /// current TEE.
    pub policy: SealPolicy,
    /// Opaque ciphertext. The backend chooses the AEAD; v1 reference
    /// implementations use ChaCha20-Poly1305 with a per-blob random nonce
    /// (the nonce is included in the ciphertext per RFC 8439 conventions
    /// but is invisible at this layer).
    pub ciphertext: Vec<u8>,
}

impl SealedBlob {
    /// The current envelope version. Backends MUST emit this value when
    /// sealing; verifiers MAY accept older versions and SHOULD reject
    /// newer versions until the corresponding NCIP ratifies them.
    pub const CURRENT_ENVELOPE_VERSION: u8 = 1;
}

// -----------------------------------------------------------------------------
// TeeSharedKey
// -----------------------------------------------------------------------------

/// A 32-byte symmetric key derived inside a TEE from a peer's
/// attestation. Suitable as IKM for HKDF; not itself an AEAD key.
///
/// **Why a newtype**: the type system prevents accidental confusion with
/// other 32-byte arrays (peer public keys, hashes, …). A function that
/// expects a `TeeSharedKey` cannot accept a `[u8; 32]` without an
/// explicit conversion that documents the intent.
///
/// **Zeroization**: the key zeroizes its bytes on [`Drop`] via a
/// volatile write loop and a compiler fence (no `zeroize` crate
/// dependency to keep `nexacore-tee` slim; the same guarantee can be lifted
/// to `zeroize::Zeroize` derive later if/when the workspace adds the
/// crate at workspace level).
#[derive(Clone, PartialEq, Eq)]
pub struct TeeSharedKey(pub(crate) [u8; 32]);

impl TeeSharedKey {
    /// Constructs a `TeeSharedKey` from raw bytes. Intended for use by
    /// `TeeBackend` implementations only; callers outside this crate
    /// must obtain a `TeeSharedKey` via
    /// [`crate::TeeBackend::derive_key_for`].
    #[doc(hidden)]
    #[must_use]
    pub const fn from_bytes_internal(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Borrows the underlying bytes. Use with care — the bytes are
    /// secret. Prefer passing the `TeeSharedKey` itself through the API
    /// and let the consumer (HKDF wrapper) borrow internally.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl Drop for TeeSharedKey {
    fn drop(&mut self) {
        // Volatile write loop prevents the optimizer from eliminating
        // the zero-out as dead-store. Equivalent to what `zeroize` does
        // for fixed-size byte arrays.
        for byte in &mut self.0 {
            // SAFETY: `byte` is a `&mut u8` obtained by safe iteration
            // over `self.0`. `write_volatile` to a valid, aligned,
            // properly-sized destination is sound. The whole reason we
            // reach for `unsafe` here is to defeat dead-store
            // elimination; `zeroize` would do the same under the hood.
            // See the module-level rationale for why we don't pull
            // `zeroize` as a dep.
            #[allow(unsafe_code)]
            unsafe {
                core::ptr::write_volatile(byte, 0u8);
            }
        }
        // Compiler fence prevents reordering of the zero-writes past
        // the Drop boundary.
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    }
}

impl core::fmt::Debug for TeeSharedKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // **Intentionally redacted** to prevent accidental key leakage via
        // `Debug` formatting. If you need the actual bytes for a test or
        // an audit trail, call `as_bytes()` explicitly.
        write!(f, "TeeSharedKey(<redacted, 32 bytes>)")
    }
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seal_policy_allows_exact_match() {
        let p = SealPolicy::new(TeeFamily::Mock, Measurement::zero());
        assert!(p.allows(TeeFamily::Mock, &Measurement::zero()));
    }

    #[test]
    fn seal_policy_rejects_family_mismatch() {
        let p = SealPolicy::new(TeeFamily::Mock, Measurement::zero());
        assert!(!p.allows(TeeFamily::IntelTdx, &Measurement::zero()));
    }

    #[test]
    fn seal_policy_rejects_measurement_mismatch() {
        let mut other = [0u8; 48];
        other[0] = 1;
        let p = SealPolicy::new(TeeFamily::Mock, Measurement::zero());
        assert!(!p.allows(TeeFamily::Mock, &Measurement(other)));
    }

    #[test]
    fn shared_key_debug_is_redacted() {
        let k = TeeSharedKey::from_bytes_internal([0xAB; 32]);
        let s = alloc::format!("{k:?}");
        assert!(!s.contains("ab"), "key bytes leaked: {s}");
        assert!(s.contains("redacted"));
    }

    #[test]
    fn shared_key_drop_zeroizes() {
        // Verify that the Drop impl zeroizes the in-place memory.
        //
        // We use `ManuallyDrop` so the value's address never changes:
        // calling `mem::drop(key)` would *move* `key` into the
        // parameter slot of `drop`, and the Drop impl would zero a
        // different stack slot than the one our raw pointer captured.
        // `ManuallyDrop::drop(&mut k)` runs the destructor in place,
        // so the volatile writes hit the exact bytes `ptr` points at.
        use core::mem::ManuallyDrop;

        let mut k = ManuallyDrop::new(TeeSharedKey::from_bytes_internal([0xFFu8; 32]));
        let ptr = k.as_bytes().as_ptr();

        // SAFETY: we never use `k` again after this call, satisfying
        // the `ManuallyDrop::drop` precondition.
        #[allow(unsafe_code)]
        unsafe {
            ManuallyDrop::drop(&mut k);
        }

        // SAFETY: `ptr` aliases the (now-dropped) inner bytes. The
        // surrounding `ManuallyDrop` storage is still live (it lives
        // until the end of this function), so the read is in-bounds
        // of an allocated object. This test exists to guard against
        // accidental removal of the Drop impl.
        #[allow(unsafe_code)]
        let observed = unsafe { core::slice::from_raw_parts(ptr, 32) };

        assert!(
            observed.iter().all(|b| *b == 0),
            "Drop did not zeroize TeeSharedKey memory (observed {observed:?})"
        );
    }
}
