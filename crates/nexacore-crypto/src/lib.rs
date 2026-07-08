//! # `nexacore-crypto`
//!
//! Cryptographic primitives for NexaCore OS.
//!
//! This crate wraps battle-tested cryptographic libraries from the
//! `RustCrypto` family (see <https://github.com/RustCrypto>) behind
//! NexaCore-specific typed APIs. It provides the composition layer (typed
//! keys, nonces, ciphertexts) — it does **not** invent algorithms.
//!
//! ## ⚠️ Status: `AWAITING_CRYPTO_REVIEW`
//!
//! This crate has not yet been reviewed by an external cryptographer
//! (P3.2 in `/todo.md`, blocked on funding via P4). The implementation
//! follows established RustCrypto APIs with RFC test vectors for every
//! primitive, but no public auditor has signed off on the composition
//! layer. Do not use the output of this crate in adversarial settings
//! until that review lands.
//!
//! ## Design rationale
//!
//! 1. **Use libraries; do not write crypto.** Every primitive delegates
//!    to a well-reviewed implementation. This crate is the typed
//!    composition layer.
//! 2. **Strict, opaque error types.** Cryptographic failures map onto
//!    [`nexacore_types::NexaCoreError::Crypto`]. Error messages never expose
//!    key material, plaintext, or correlation hints.
//! 3. **Constant-time on adversarial paths.** AEAD tag verification and
//!    signature verification go through [`subtle::ConstantTimeEq`] (or
//!    the equivalent inside the wrapped library). Equality comparisons
//!    on keys/MACs/tags MUST NOT use `==`.
//! 4. **`Zeroize` on every secret.** Keys, shared secrets, and any
//!    intermediate buffer that holds key material implements
//!    [`zeroize::Zeroize`] and wipes itself on `Drop`.
//! 5. **Algorithm agility.** Cipher suites are negotiated, not
//!    hardcoded. Sunset dates for deprecated algorithms are tracked in
//!    `/docs/04-security-model.md` § "Crypto agility".
//! 6. **`no_std + alloc`.** Like the rest of the foundational layer.
//!
//! ## Module map
//!
//! | Module | Phase | What |
//! |---|---|---|
//! | [`aead`]    | P1.2 | Authenticated Encryption with Associated Data (`ChaCha20-Poly1305`, RFC 8439). |
//! | [`signing`] | P1.2 | Digital signatures (`Ed25519`, RFC 8032). |
//! | [`kex`]     | P1.2 | Key exchange (`X25519`, RFC 7748). Hybrid PQ in Phase 4. |
//! | [`hash`]    | P1.2 | Cryptographic hashes (`SHA-256`, `SHA3-256`, `BLAKE3`). |
//! | [`kdf`]     | P1.2 | Key derivation (`HKDF-SHA-256`, `Argon2id`). |
//! | [`fpe`]     | P4   | Format-preserving encryption (placeholder). |
//! | [`snark`]   | P4   | Zero-knowledge predicates (placeholder). |
//!
//! ## See also
//!
//! - [`/docs/04-security-model.md`](../../../docs/04-security-model.md)
//!   for the security rationale.
//! - [`/docs/09-tech-specifications.md`](../../../docs/09-tech-specifications.md)
//!   for the dependency rationale and version pins.

#![doc(html_root_url = "https://docs.nexacore-os.org/nexacore-crypto")]
#![no_std]
#![forbid(unsafe_code)]
#![deny(missing_docs)]
// See `nexacore-types/src/lib.rs` for the rationale on this `cfg_attr`.
#![cfg_attr(
    test,
    allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::unnecessary_wraps,
        clippy::indexing_slicing,
    )
)]

extern crate alloc;

pub mod aead;
pub mod hash;
pub mod kdf;
pub mod kex;
pub mod signing;

// Phase 4 placeholder modules. They exist as empty modules so downstream
// crates can `use nexacore_crypto::fpe;` without conditional compilation,
// and so the public-API surface is visible from day one.
pub mod fpe;
pub mod snark;
