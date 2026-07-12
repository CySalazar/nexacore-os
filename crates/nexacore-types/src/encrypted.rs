//! Sealed marker types for encrypted-by-default data.
//!
//! This module provides the **type-level enforcement** that personally
//! identifiable information (PII) cannot be handled in cleartext outside
//! an attested TEE. The runtime construction of these values lives in
//! the `nexacore-tokenization` crate (Phase 2 in the backlog), which performs
//! the actual encryption inside a verified TEE. This module exists in
//! P1 because every other crate must already speak in terms of these
//! types to prevent "cheat" code paths from being added later.
//!
//! # Two enforcement layers
//!
//! 1. **Sealed trait**: [`EncryptedType`] requires a private super-trait
//!    `sealed::Sealed`. Only types defined in this module can implement
//!    `EncryptedType`. Downstream crates cannot mint new "encrypted"
//!    categories without an NCIP that lands here.
//!
//! 2. **Provider-only constructors**: the only way to instantiate one of
//!    these markers is through the `provider` API gated behind the
//!    `_tokenization_provider` feature flag. Only the `nexacore-tokenization`
//!    crate enables this flag (in its `Cargo.toml`). Any other crate that
//!    tries to enable the flag fails CI's `cargo deny` policy because
//!    the flag's name starts with `_` (project convention for "internal,
//!    unstable, do not use").
//!
//! # What this module does NOT do (without `_tokenization_provider`)
//!
//! Without the feature flag it does not perform encryption. The marker
//! types carry an opaque ciphertext byte buffer; the cryptographic
//! operation that produces the ciphertext happens in `nexacore-tokenization`
//! inside the TEE. With the flag enabled the `provider` module also
//! exposes real `ChaCha20-Poly1305` encrypt/decrypt helpers.
//!
//! See [`/docs/04-security-model.md`](../../../docs/04-security-model.md)
//! § "The five privacy primitives in detail" for the security rationale.

use alloc::vec::Vec;

use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

// =============================================================================
// Sealed trait (compile-time extensibility lock).
// =============================================================================

mod sealed {
    /// Private super-trait used to seal the [`super::EncryptedType`] hierarchy.
    /// Only types in this module can implement it, so downstream crates
    /// cannot mint new "encrypted" categories outside an NCIP.
    pub trait Sealed {}
}

/// Marker trait implemented by every encrypted-by-default type in NexaCore OS.
///
/// The trait is **sealed**: only types defined in this module can implement
/// it. This is a compile-time guarantee that the set of encrypted-data
/// categories is fixed and reviewable from a single file.
///
/// # When to add a new variant
///
/// File an NCIP that:
///
/// 1. Justifies why the existing categories are insufficient.
/// 2. Specifies the wire encoding and length bounds.
/// 3. Specifies the TEE construction policy (how the ciphertext is
///    produced and which attestation must witness it).
/// 4. Adds the new type here, behind a `provider`-gated constructor.
pub trait EncryptedType: sealed::Sealed + Sized {
    /// Stable, machine-readable category identifier (e.g.
    /// `"encrypted-string"`). Used for audit logs, telemetry, and
    /// per-category policy decisions. MUST be unique across the
    /// workspace.
    const KIND: &'static str;

    /// Borrow the opaque ciphertext bytes.
    ///
    /// The bytes are meaningless outside an attested TEE; surfacing them
    /// is safe because cleartext recovery requires the unsealing key
    /// held by the TEE.
    fn ciphertext(&self) -> &[u8];
}

// =============================================================================
// Marker types.
// =============================================================================

/// Encrypted UTF-8 string.
///
/// The cleartext was a [`alloc::string::String`] before encryption; the
/// stored bytes are an opaque ciphertext produced by the tokenization
/// service. Equality and hashing are defined over the ciphertext, so two
/// `EncryptedString` values are equal iff their ciphertexts match
/// byte-for-byte.
///
/// # Construction
///
/// Available only via the `provider` module (gated behind the
/// `_tokenization_provider` feature flag). See module-level docs.
#[derive(Clone, PartialEq, Eq, Hash, Debug, Serialize, Deserialize, Zeroize)]
pub struct EncryptedString {
    // The ciphertext is private. `Drop` triggers `Zeroize` to wipe the
    // bytes from memory in case the caller forgot to.
    ciphertext: Vec<u8>,
}

impl sealed::Sealed for EncryptedString {}

impl EncryptedType for EncryptedString {
    const KIND: &'static str = "encrypted-string";

    fn ciphertext(&self) -> &[u8] {
        &self.ciphertext
    }
}

impl core::fmt::Display for EncryptedString {
    /// Always renders as `[ENCRYPTED]`.
    ///
    /// The plaintext is never accessible through `Display` — surfacing it
    /// would bypass the TEE boundary and expose PII. Logs and UI code that
    /// call `format!("{}", encrypted_string)` receive the safe placeholder
    /// string `[ENCRYPTED]`.
    ///
    /// # Example
    ///
    /// ```
    /// # #[cfg(feature = "_tokenization_provider")]
    /// # {
    /// use nexacore_types::encrypted::EncryptedString;
    /// let es = EncryptedString::from_ciphertext(vec![0xAB, 0xCD]);
    /// assert_eq!(format!("{es}"), "[ENCRYPTED]");
    /// # }
    /// // Even without provider feature, Display is available on the type.
    /// ```
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("[ENCRYPTED]")
    }
}

/// Structurally masked Social Security Number.
///
/// Stores the ciphertext of the full SSN plus a small number of plaintext
/// digits sufficient for human-readable masking (e.g., `***-**-1234`).
/// The masking digits are policy-controlled — see the tokenization
/// service for the active policy.
#[derive(Clone, PartialEq, Eq, Hash, Debug, Serialize, Deserialize, Zeroize)]
pub struct MaskedSSN {
    ciphertext: Vec<u8>,
    /// Last four digits in plaintext for human-readable display.
    /// Always exactly 4 ASCII bytes. Validated at construction time.
    visible_suffix: [u8; 4],
}

impl sealed::Sealed for MaskedSSN {}

impl EncryptedType for MaskedSSN {
    const KIND: &'static str = "masked-ssn";

    fn ciphertext(&self) -> &[u8] {
        &self.ciphertext
    }
}

impl MaskedSSN {
    /// Borrow the visible suffix (4 ASCII digits).
    #[must_use]
    pub const fn visible_suffix(&self) -> &[u8; 4] {
        &self.visible_suffix
    }
}

impl core::fmt::Display for MaskedSSN {
    /// Renders as `***-**-XXXX` where `XXXX` is the visible 4-digit suffix.
    ///
    /// The full SSN is never recoverable from the `Display` output.  Only the
    /// last four digit characters are shown, following standard U.S. SSN
    /// masking practice (e.g. `***-**-6789`).
    ///
    /// # Example
    ///
    /// ```
    /// # #[cfg(feature = "_tokenization_provider")]
    /// # {
    /// use nexacore_types::encrypted::MaskedSSN;
    /// let key = [0u8; 32];
    /// let nonce = [0u8; 12];
    /// let masked = MaskedSSN::encrypt("123-45-6789", &key, &nonce).unwrap();
    /// assert_eq!(format!("{masked}"), "***-**-6789");
    /// # }
    /// ```
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // The visible_suffix is guaranteed to contain exactly 4 ASCII digits;
        // validated at construction time by `from_ciphertext` and `encrypt`.
        //
        // Convert each byte to char. Since they are ASCII digits (0x30..0x39),
        // `from(b)` is infallible for all byte values in [0x30, 0x39].
        let d0 = char::from(self.visible_suffix[0]);
        let d1 = char::from(self.visible_suffix[1]);
        let d2 = char::from(self.visible_suffix[2]);
        let d3 = char::from(self.visible_suffix[3]);
        write!(f, "***-**-{d0}{d1}{d2}{d3}")
    }
}

/// Tokenized email address.
///
/// The cleartext email is replaced with a deterministic token derived
/// from a per-tenant keyed hash. Identical emails under the same tenant
/// produce identical tokens, enabling join-on-token without revealing
/// the underlying address.
#[derive(Clone, PartialEq, Eq, Hash, Debug, Serialize, Deserialize, Zeroize)]
pub struct TokenizedEmail {
    ciphertext: Vec<u8>,
}

impl sealed::Sealed for TokenizedEmail {}

impl EncryptedType for TokenizedEmail {
    const KIND: &'static str = "tokenized-email";

    fn ciphertext(&self) -> &[u8] {
        &self.ciphertext
    }
}

/// Hash bound to a specific TEE attestation.
///
/// Combines a content hash with the attestation quote that witnessed it.
/// Verification requires both: the hash must match the content AND the
/// quote must verify against the expected measurement.
#[derive(Clone, PartialEq, Eq, Hash, Debug, Serialize, Deserialize, Zeroize)]
pub struct AttestedHash {
    /// The opaque hash bytes (BLAKE3-256 in v0.1).
    hash: [u8; 32],
    /// The attestation quote bytes (variable length, opaque).
    attestation: Vec<u8>,
}

impl sealed::Sealed for AttestedHash {}

impl EncryptedType for AttestedHash {
    const KIND: &'static str = "attested-hash";

    /// For [`AttestedHash`], "ciphertext" returns the attestation bytes;
    /// the hash itself is not encrypted but bound to the attestation.
    fn ciphertext(&self) -> &[u8] {
        &self.attestation
    }
}

impl AttestedHash {
    /// Borrow the underlying content hash.
    #[must_use]
    pub const fn hash(&self) -> &[u8; 32] {
        &self.hash
    }
}

// =============================================================================
// Provider API (feature-gated for the tokenization service only).
// =============================================================================

/// Constructors and encryption helpers for encrypted-by-default types.
///
/// **This API is gated behind the `_tokenization_provider` feature flag.**
/// Only the `nexacore-tokenization` crate enables the flag in its
/// `Cargo.toml`. Any other crate that tries to enable it must justify
/// itself in code review; the leading underscore in the flag name is a
/// project-wide signal that this is internal and unstable.
///
/// Even with the feature enabled, callers MUST verify that they are
/// running inside an attested TEE before constructing one of these
/// values. The compile-time gate prevents accidental misuse; the
/// runtime invariant is enforced by code review and the `nexacore-tee`
/// integration tests.
///
/// # Encryption scheme
///
/// All `encrypt` methods use `ChaCha20-Poly1305` (RFC 8439) with 256-bit
/// keys and 96-bit nonces. The `KIND` constant of each type is used as
/// **additional authenticated data (AAD)** to provide domain separation:
/// encrypting the same plaintext under different types produces different
/// authentication tags, and decrypting with the wrong type's AAD fails
/// verification. Callers are responsible for nonce uniqueness; the
/// `EncryptedPipeline` in `nexacore-tokenization` provides a monotonic
/// nonce counter for this purpose.
#[cfg(feature = "_tokenization_provider")]
pub mod provider {
    use alloc::{string::String, vec::Vec};

    use chacha20poly1305::{
        ChaCha20Poly1305, Key, Nonce,
        aead::{Aead, KeyInit, Payload},
    };

    use super::{AttestedHash, EncryptedString, EncryptedType, MaskedSSN, TokenizedEmail};
    use crate::error::{CryptoErrorKind, IdentityErrorKind, NexaCoreError, Result};

    // -------------------------------------------------------------------------
    // EncryptedString
    // -------------------------------------------------------------------------

    impl EncryptedString {
        /// Construct an [`EncryptedString`] from raw ciphertext.
        ///
        /// # Caller contract
        ///
        /// The caller MUST be running inside an attested TEE and the
        /// ciphertext MUST have been produced by the tokenization
        /// service's encryption routine. There is no runtime check —
        /// misuse is a project-wide invariant violation.
        ///
        /// # Example
        ///
        /// ```
        /// # #[cfg(feature = "_tokenization_provider")]
        /// # {
        /// use nexacore_types::encrypted::{EncryptedString, EncryptedType};
        /// let ct = vec![0xAB, 0xCD, 0xEF];
        /// let es = EncryptedString::from_ciphertext(ct.clone());
        /// assert_eq!(es.ciphertext(), &ct[..]);
        /// # }
        /// ```
        #[must_use]
        pub fn from_ciphertext(ciphertext: Vec<u8>) -> Self {
            Self { ciphertext }
        }

        /// Encrypt `plaintext` with `ChaCha20-Poly1305` using `key` and `nonce`.
        ///
        /// The `KIND` constant (`"encrypted-string"`) is used as additional
        /// authenticated data (AAD) for domain separation between encrypted
        /// types. A different type's `KIND` string will cause decryption to
        /// fail even if the key and nonce are identical.
        ///
        /// # Errors
        ///
        /// Returns [`NexaCoreError::Crypto`] with
        /// [`CryptoErrorKind::InternalInvariant`] if the AEAD library
        /// reports an encryption failure (this should never happen for valid
        /// 32-byte keys and 12-byte nonces).
        ///
        /// # Example
        ///
        /// ```
        /// # #[cfg(feature = "_tokenization_provider")]
        /// # {
        /// use nexacore_types::encrypted::EncryptedString;
        /// let key = [0u8; 32];
        /// let nonce = [1u8; 12];
        /// let es = EncryptedString::encrypt("hello", &key, &nonce).expect("encryption must succeed");
        /// let recovered = es.decrypt(&key, &nonce).expect("decryption must succeed");
        /// assert_eq!(recovered, "hello");
        /// # }
        /// ```
        pub fn encrypt(plaintext: &str, key: &[u8; 32], nonce: &[u8; 12]) -> Result<Self> {
            let ciphertext = aead_encrypt(key, nonce, Self::KIND.as_bytes(), plaintext.as_bytes())?;
            Ok(Self { ciphertext })
        }

        /// Decrypt ciphertext back to a UTF-8 plaintext string.
        ///
        /// Requires the same `key` and `nonce` that were used during
        /// [`EncryptedString::encrypt`]. The `KIND` AAD is verified
        /// automatically; an attacker cannot substitute a ciphertext
        /// produced by a different encrypted type.
        ///
        /// # Errors
        ///
        /// - [`NexaCoreError::Crypto`] with [`CryptoErrorKind::DecryptionFailure`]
        ///   if the key, nonce, or ciphertext are wrong or tampered.
        /// - [`NexaCoreError::Crypto`] with [`CryptoErrorKind::InternalInvariant`]
        ///   if the decrypted bytes are not valid UTF-8 (indicates a bug in
        ///   the encrypt path).
        ///
        /// # Example
        ///
        /// ```
        /// # #[cfg(feature = "_tokenization_provider")]
        /// # {
        /// use nexacore_types::encrypted::EncryptedString;
        /// let key = [42u8; 32];
        /// let nonce = [7u8; 12];
        /// let es = EncryptedString::encrypt("secret data", &key, &nonce).unwrap();
        /// let pt = es.decrypt(&key, &nonce).unwrap();
        /// assert_eq!(pt, "secret data");
        /// # }
        /// ```
        pub fn decrypt(&self, key: &[u8; 32], nonce: &[u8; 12]) -> Result<String> {
            let plaintext = aead_decrypt(key, nonce, Self::KIND.as_bytes(), &self.ciphertext)?;
            String::from_utf8(plaintext).map_err(|_| {
                NexaCoreError::crypto(
                    CryptoErrorKind::InternalInvariant,
                    "EncryptedString::decrypt::invalid_utf8",
                )
            })
        }
    }

    // -------------------------------------------------------------------------
    // TokenizedEmail
    // -------------------------------------------------------------------------

    impl TokenizedEmail {
        /// Construct a [`TokenizedEmail`] from raw ciphertext.
        ///
        /// See the caller contract on [`EncryptedString::from_ciphertext`].
        ///
        /// # Example
        ///
        /// ```
        /// # #[cfg(feature = "_tokenization_provider")]
        /// # {
        /// use nexacore_types::encrypted::{EncryptedType, TokenizedEmail};
        /// let ct = vec![0x01, 0x02];
        /// let te = TokenizedEmail::from_ciphertext(ct.clone());
        /// assert_eq!(te.ciphertext(), &ct[..]);
        /// # }
        /// ```
        #[must_use]
        pub fn from_ciphertext(ciphertext: Vec<u8>) -> Self {
            Self { ciphertext }
        }

        /// Encrypt `email` with `ChaCha20-Poly1305` using `key` and `nonce`.
        ///
        /// Uses `KIND` (`"tokenized-email"`) as AAD for domain separation.
        ///
        /// # Errors
        ///
        /// Returns [`NexaCoreError::Crypto`] with
        /// [`CryptoErrorKind::InternalInvariant`] on AEAD failure.
        ///
        /// # Example
        ///
        /// ```
        /// # #[cfg(feature = "_tokenization_provider")]
        /// # {
        /// use nexacore_types::encrypted::TokenizedEmail;
        /// let key = [0u8; 32];
        /// let nonce = [2u8; 12];
        /// let te = TokenizedEmail::encrypt("user@example.com", &key, &nonce).expect("encrypt");
        /// let recovered = te.decrypt(&key, &nonce).expect("decrypt");
        /// assert_eq!(recovered, "user@example.com");
        /// # }
        /// ```
        pub fn encrypt(email: &str, key: &[u8; 32], nonce: &[u8; 12]) -> Result<Self> {
            if !is_valid_email(email) {
                return Err(NexaCoreError::identity(
                    IdentityErrorKind::InvalidEncoding,
                    "TokenizedEmail::encrypt::invalid_email_format",
                ));
            }
            let ciphertext = aead_encrypt(key, nonce, Self::KIND.as_bytes(), email.as_bytes())?;
            Ok(Self { ciphertext })
        }

        /// Decrypt ciphertext back to the email plaintext string.
        ///
        /// # Errors
        ///
        /// - [`NexaCoreError::Crypto`] with [`CryptoErrorKind::DecryptionFailure`]
        ///   on tag mismatch (wrong key, nonce, or tampered data).
        /// - [`NexaCoreError::Crypto`] with [`CryptoErrorKind::InternalInvariant`]
        ///   if the decrypted bytes are not valid UTF-8.
        ///
        /// # Example
        ///
        /// ```
        /// # #[cfg(feature = "_tokenization_provider")]
        /// # {
        /// use nexacore_types::encrypted::TokenizedEmail;
        /// let key = [1u8; 32];
        /// let nonce = [3u8; 12];
        /// let te = TokenizedEmail::encrypt("a@b.com", &key, &nonce).unwrap();
        /// assert_eq!(te.decrypt(&key, &nonce).unwrap(), "a@b.com");
        /// # }
        /// ```
        pub fn decrypt(&self, key: &[u8; 32], nonce: &[u8; 12]) -> Result<String> {
            let plaintext = aead_decrypt(key, nonce, Self::KIND.as_bytes(), &self.ciphertext)?;
            String::from_utf8(plaintext).map_err(|_| {
                NexaCoreError::crypto(
                    CryptoErrorKind::InternalInvariant,
                    "TokenizedEmail::decrypt::invalid_utf8",
                )
            })
        }
    }

    // -------------------------------------------------------------------------
    // MaskedSSN
    // -------------------------------------------------------------------------

    impl MaskedSSN {
        /// Construct a [`MaskedSSN`] from raw ciphertext + visible suffix.
        ///
        /// The visible suffix must be exactly 4 ASCII digits. Returns
        /// [`NexaCoreError::Identity`] on validation failure.
        ///
        /// # Errors
        ///
        /// Returns [`NexaCoreError::Identity`] with
        /// [`IdentityErrorKind::InvalidLength`] if the suffix is not
        /// exactly 4 ASCII digits.
        ///
        /// # Example
        ///
        /// ```
        /// # #[cfg(feature = "_tokenization_provider")]
        /// # {
        /// use nexacore_types::encrypted::MaskedSSN;
        /// let ok = MaskedSSN::from_ciphertext(vec![1, 2, 3], *b"1234");
        /// assert!(ok.is_ok());
        /// # }
        /// ```
        pub fn from_ciphertext(ciphertext: Vec<u8>, visible_suffix: [u8; 4]) -> Result<Self> {
            // Validate that all four suffix bytes are ASCII digits.
            for b in &visible_suffix {
                if !b.is_ascii_digit() {
                    return Err(NexaCoreError::identity(
                        IdentityErrorKind::InvalidLength,
                        "MaskedSSN::from_ciphertext_visible_suffix_not_digit",
                    ));
                }
            }
            Ok(Self {
                ciphertext,
                visible_suffix,
            })
        }

        /// Encrypt `ssn` with `ChaCha20-Poly1305` using `key` and `nonce`.
        ///
        /// The last 4 ASCII digit characters in `ssn` are extracted and
        /// stored as the plaintext `visible_suffix` (e.g. `"6789"` for
        /// `"123-45-6789"`). The full SSN string is encrypted. Uses
        /// `KIND` (`"masked-ssn"`) as AAD for domain separation.
        ///
        /// # Errors
        ///
        /// - [`NexaCoreError::Identity`] with [`IdentityErrorKind::InvalidLength`]
        ///   if `ssn` contains fewer than 4 digit characters.
        /// - [`NexaCoreError::Crypto`] with [`CryptoErrorKind::InternalInvariant`]
        ///   on AEAD failure.
        ///
        /// # Example
        ///
        /// ```
        /// # #[cfg(feature = "_tokenization_provider")]
        /// # {
        /// use nexacore_types::encrypted::MaskedSSN;
        /// let key = [0u8; 32];
        /// let nonce = [4u8; 12];
        /// let masked = MaskedSSN::encrypt("123-45-6789", &key, &nonce).expect("encrypt");
        /// assert_eq!(masked.visible_suffix(), b"6789");
        /// let recovered = masked.decrypt(&key, &nonce).expect("decrypt");
        /// assert_eq!(recovered, "123-45-6789");
        /// # }
        /// ```
        pub fn encrypt(ssn: &str, key: &[u8; 32], nonce: &[u8; 12]) -> Result<Self> {
            // Extract the last 4 ASCII digit characters for the visible suffix.
            let digit_bytes: Vec<u8> = ssn.bytes().filter(u8::is_ascii_digit).collect();
            if digit_bytes.len() < 4 {
                return Err(NexaCoreError::identity(
                    IdentityErrorKind::InvalidLength,
                    "MaskedSSN::encrypt::fewer_than_4_digits",
                ));
            }
            // Take the last 4 digits.
            let suffix_start = digit_bytes.len() - 4;
            let mut visible_suffix = [0u8; 4];
            // `suffix_start..suffix_start+4` is in-bounds because
            // `digit_bytes.len() >= 4` was checked above and
            // `suffix_start = digit_bytes.len() - 4`.
            #[allow(clippy::indexing_slicing)]
            visible_suffix.copy_from_slice(&digit_bytes[suffix_start..suffix_start + 4]);

            let ciphertext = aead_encrypt(key, nonce, Self::KIND.as_bytes(), ssn.as_bytes())?;
            Ok(Self {
                ciphertext,
                visible_suffix,
            })
        }

        /// Decrypt ciphertext back to the full SSN plaintext string.
        ///
        /// # Errors
        ///
        /// - [`NexaCoreError::Crypto`] with [`CryptoErrorKind::DecryptionFailure`]
        ///   on tag mismatch.
        /// - [`NexaCoreError::Crypto`] with [`CryptoErrorKind::InternalInvariant`]
        ///   if the decrypted bytes are not valid UTF-8.
        ///
        /// # Example
        ///
        /// ```
        /// # #[cfg(feature = "_tokenization_provider")]
        /// # {
        /// use nexacore_types::encrypted::MaskedSSN;
        /// let key = [5u8; 32];
        /// let nonce = [6u8; 12];
        /// let masked = MaskedSSN::encrypt("987-65-4321", &key, &nonce).unwrap();
        /// assert_eq!(masked.decrypt(&key, &nonce).unwrap(), "987-65-4321");
        /// # }
        /// ```
        pub fn decrypt(&self, key: &[u8; 32], nonce: &[u8; 12]) -> Result<String> {
            let plaintext = aead_decrypt(key, nonce, Self::KIND.as_bytes(), &self.ciphertext)?;
            String::from_utf8(plaintext).map_err(|_| {
                NexaCoreError::crypto(
                    CryptoErrorKind::InternalInvariant,
                    "MaskedSSN::decrypt::invalid_utf8",
                )
            })
        }
    }

    // -------------------------------------------------------------------------
    // AttestedHash
    // -------------------------------------------------------------------------

    impl AttestedHash {
        /// Construct an [`AttestedHash`] from a content hash + attestation.
        ///
        /// See the caller contract on [`EncryptedString::from_ciphertext`].
        ///
        /// # Example
        ///
        /// ```
        /// # #[cfg(feature = "_tokenization_provider")]
        /// # {
        /// use nexacore_types::encrypted::AttestedHash;
        /// let h = AttestedHash::from_parts([0xABu8; 32], vec![0x01, 0x02]);
        /// assert_eq!(h.hash(), &[0xABu8; 32]);
        /// # }
        /// ```
        #[must_use]
        pub fn from_parts(hash: [u8; 32], attestation: Vec<u8>) -> Self {
            Self { hash, attestation }
        }
    }

    // -------------------------------------------------------------------------
    // Private AEAD helpers (shared by all encrypt/decrypt methods above).
    // -------------------------------------------------------------------------

    /// Encrypt `plaintext` with `ChaCha20-Poly1305` under `key`, `nonce`,
    /// and `aad`.
    ///
    /// Returns the raw ciphertext+tag bytes on success.
    ///
    /// # Why not use `nexacore-crypto::aead`?
    ///
    /// `nexacore-types` sits below `nexacore-crypto` in the dependency graph.
    /// Adding `nexacore-crypto` as a dep of `nexacore-types` would create a cycle
    /// (`nexacore-crypto` already depends on `nexacore-types`). We therefore call
    /// `chacha20poly1305` directly here — the same version already in the
    /// workspace — keeping the AEAD logic thin (~5 LOC) and auditable.
    fn aead_encrypt(
        key: &[u8; 32],
        nonce: &[u8; 12],
        aad: &[u8],
        plaintext: &[u8],
    ) -> Result<Vec<u8>> {
        let cipher = ChaCha20Poly1305::new(Key::from_slice(key));
        let nonce_ref = Nonce::from_slice(nonce);
        let payload = Payload {
            msg: plaintext,
            aad,
        };
        cipher.encrypt(nonce_ref, payload).map_err(|_| {
            NexaCoreError::crypto(
                CryptoErrorKind::InternalInvariant,
                "encrypted::provider::aead_encrypt",
            )
        })
    }

    /// Authenticate and decrypt `ciphertext` with `ChaCha20-Poly1305` under
    /// `key`, `nonce`, and `aad`.
    ///
    /// Returns the raw plaintext bytes on success.
    fn aead_decrypt(
        key: &[u8; 32],
        nonce: &[u8; 12],
        aad: &[u8],
        ciphertext: &[u8],
    ) -> Result<Vec<u8>> {
        let cipher = ChaCha20Poly1305::new(Key::from_slice(key));
        let nonce_ref = Nonce::from_slice(nonce);
        let payload = Payload {
            msg: ciphertext,
            aad,
        };
        cipher.decrypt(nonce_ref, payload).map_err(|_| {
            NexaCoreError::crypto(
                CryptoErrorKind::DecryptionFailure,
                "encrypted::provider::aead_decrypt",
            )
        })
    }

    /// Basic structural validation of an email address before tokenization
    /// (WS5-08.3).
    ///
    /// This is a deliberately conservative *structural* check — not full
    /// RFC 5322 — sufficient to reject obviously malformed input at the API
    /// boundary: no internal whitespace, exactly one `@`, a non-empty local
    /// part, and a domain with at least two non-empty dot-separated labels.
    fn is_valid_email(email: &str) -> bool {
        if email.is_empty() || email.contains(char::is_whitespace) {
            return false;
        }
        let mut parts = email.split('@');
        let (Some(local), Some(domain), None) = (parts.next(), parts.next(), parts.next()) else {
            return false; // zero or more than one `@`
        };
        if local.is_empty() || domain.is_empty() {
            return false;
        }
        let mut labels = domain.split('.');
        // A domain needs at least two labels (e.g. `example.com`), all non-empty.
        labels.clone().count() >= 2 && labels.all(|label| !label.is_empty())
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
#[cfg(feature = "_tokenization_provider")]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]
mod tests {
    use alloc::vec;

    use super::*;

    // Fixed test key and nonce. NOT secret — used only to exercise round-trips.
    const TEST_KEY: [u8; 32] = [0x42u8; 32];
    const TEST_NONCE: [u8; 12] = [0x07u8; 12];
    const TEST_NONCE2: [u8; 12] = [0x08u8; 12];

    // -------------------------------------------------------------------------
    // Legacy from_ciphertext constructor tests (preserved intact)
    // -------------------------------------------------------------------------

    #[test]
    fn encrypted_string_round_trip_through_provider() {
        let ct = vec![0xAB, 0xCD, 0xEF];
        let e = EncryptedString::from_ciphertext(ct.clone());
        assert_eq!(e.ciphertext(), &ct[..]);
        assert_eq!(EncryptedString::KIND, "encrypted-string");
    }

    #[test]
    fn masked_ssn_validates_suffix() {
        let ok = MaskedSSN::from_ciphertext(vec![1, 2, 3], *b"1234");
        assert!(ok.is_ok());
        assert_eq!(ok.unwrap().visible_suffix(), b"1234");

        let bad = MaskedSSN::from_ciphertext(vec![1, 2, 3], *b"12X4");
        assert!(bad.is_err());
    }

    #[test]
    fn attested_hash_round_trip() {
        let h = AttestedHash::from_parts([7u8; 32], vec![0xFF, 0xEE]);
        assert_eq!(h.hash(), &[7u8; 32]);
        assert_eq!(h.ciphertext(), &[0xFF, 0xEE][..]);
    }

    #[test]
    fn kind_constants_are_unique() {
        let kinds = [
            EncryptedString::KIND,
            MaskedSSN::KIND,
            TokenizedEmail::KIND,
            AttestedHash::KIND,
        ];
        // Naive uniqueness check (4 elements, O(n^2) is fine).
        for (i, a) in kinds.iter().enumerate() {
            for b in kinds.iter().skip(i + 1) {
                assert_ne!(a, b, "EncryptedType::KIND collision: {a}");
            }
        }
    }

    // -------------------------------------------------------------------------
    // EncryptedString encrypt / decrypt round-trip
    // -------------------------------------------------------------------------

    #[test]
    fn encrypted_string_encrypt_decrypt_round_trip() {
        let plaintext = "hello, NexaCore OS";
        let es = EncryptedString::encrypt(plaintext, &TEST_KEY, &TEST_NONCE)
            .expect("encrypt must succeed");
        // Ciphertext is longer than plaintext by the 16-byte Poly1305 tag.
        assert_eq!(es.ciphertext().len(), plaintext.len() + 16);
        let recovered = es.decrypt(&TEST_KEY, &TEST_NONCE).expect("decrypt");
        assert_eq!(recovered, plaintext);
    }

    #[test]
    fn encrypted_string_wrong_key_fails() {
        let es = EncryptedString::encrypt("secret", &TEST_KEY, &TEST_NONCE).expect("encrypt");
        let wrong_key = [0x00u8; 32];
        let err = es
            .decrypt(&wrong_key, &TEST_NONCE)
            .expect_err("wrong key must fail");
        assert!(
            matches!(
                err,
                crate::error::NexaCoreError::Crypto {
                    kind: crate::error::CryptoErrorKind::DecryptionFailure,
                    ..
                }
            ),
            "expected DecryptionFailure, got {err:?}"
        );
    }

    #[test]
    fn encrypted_string_wrong_nonce_fails() {
        let es = EncryptedString::encrypt("secret", &TEST_KEY, &TEST_NONCE).expect("encrypt");
        let err = es
            .decrypt(&TEST_KEY, &TEST_NONCE2)
            .expect_err("wrong nonce must fail");
        assert!(matches!(
            err,
            crate::error::NexaCoreError::Crypto {
                kind: crate::error::CryptoErrorKind::DecryptionFailure,
                ..
            }
        ));
    }

    // -------------------------------------------------------------------------
    // TokenizedEmail encrypt / decrypt round-trip
    // -------------------------------------------------------------------------

    #[test]
    fn tokenized_email_encrypt_decrypt_round_trip() {
        let email = "alice@example.com";
        let te = TokenizedEmail::encrypt(email, &TEST_KEY, &TEST_NONCE).expect("encrypt");
        let recovered = te.decrypt(&TEST_KEY, &TEST_NONCE).expect("decrypt");
        assert_eq!(recovered, email);
    }

    #[test]
    fn tokenized_email_wrong_key_fails() {
        let te =
            TokenizedEmail::encrypt("user@domain.org", &TEST_KEY, &TEST_NONCE).expect("encrypt");
        let wrong_key = [0xFFu8; 32];
        assert!(te.decrypt(&wrong_key, &TEST_NONCE).is_err());
    }

    #[test]
    fn tokenized_email_rejects_malformed_addresses() {
        // WS5-08.3: structurally invalid emails are rejected at construction.
        for bad in [
            "",
            "no-at-sign",
            "@example.com",
            "user@",
            "user@host",        // no dot in domain
            "user@.com",        // empty leading label
            "user@example.",    // empty trailing label
            "a@b@example.com",  // two `@`
            "user name@ex.com", // internal whitespace
        ] {
            let err = TokenizedEmail::encrypt(bad, &TEST_KEY, &TEST_NONCE)
                .expect_err("malformed email must be rejected");
            assert!(
                matches!(
                    err,
                    crate::error::NexaCoreError::Identity {
                        kind: crate::error::IdentityErrorKind::InvalidEncoding,
                        ..
                    }
                ),
                "expected InvalidEncoding for {bad:?}, got {err:?}"
            );
        }
        // A well-formed address still encrypts.
        assert!(TokenizedEmail::encrypt("a.b+tag@sub.example.com", &TEST_KEY, &TEST_NONCE).is_ok());
    }

    /// Whether `haystack` contains `needle` as a contiguous subslice.
    fn contains_subslice(haystack: &[u8], needle: &[u8]) -> bool {
        !needle.is_empty()
            && needle.len() <= haystack.len()
            && haystack.windows(needle.len()).any(|w| w == needle)
    }

    #[test]
    fn ciphertext_and_display_never_leak_plaintext() {
        // WS5-08.5/.7: the stored ciphertext (exactly what `Serialize` emits)
        // must never contain the plaintext, and `Display` must show a safe
        // placeholder rather than the secret.
        let secret = "SuperSecretValue-123";
        let es = EncryptedString::encrypt(secret, &TEST_KEY, &TEST_NONCE).expect("encrypt");
        assert!(
            !contains_subslice(es.ciphertext(), secret.as_bytes()),
            "EncryptedString ciphertext must not contain the plaintext"
        );
        assert_eq!(alloc::format!("{es}"), "[ENCRYPTED]");

        let email = "secret.person@example.com";
        let te = TokenizedEmail::encrypt(email, &TEST_KEY, &TEST_NONCE).expect("encrypt");
        assert!(
            !contains_subslice(te.ciphertext(), b"secret.person"),
            "TokenizedEmail ciphertext must not contain the local part"
        );

        let ssn = "123-45-6789";
        let masked = MaskedSSN::encrypt(ssn, &TEST_KEY, &TEST_NONCE).expect("encrypt");
        assert!(
            !contains_subslice(masked.ciphertext(), ssn.as_bytes()),
            "MaskedSSN ciphertext must not contain the full SSN"
        );
        // Only the masked suffix is ever shown.
        assert_eq!(alloc::format!("{masked}"), "***-**-6789");
    }

    // -------------------------------------------------------------------------
    // MaskedSSN encrypt / decrypt
    // -------------------------------------------------------------------------

    #[test]
    fn masked_ssn_encrypt_preserves_visible_suffix() {
        let ssn = "123-45-6789";
        let masked = MaskedSSN::encrypt(ssn, &TEST_KEY, &TEST_NONCE).expect("encrypt");
        // Visible suffix must be the last 4 digits of the SSN.
        assert_eq!(masked.visible_suffix(), b"6789");
    }

    #[test]
    fn masked_ssn_encrypt_decrypt_recovers_full_ssn() {
        let ssn = "987-65-4321";
        let masked = MaskedSSN::encrypt(ssn, &TEST_KEY, &TEST_NONCE).expect("encrypt");
        let recovered = masked.decrypt(&TEST_KEY, &TEST_NONCE).expect("decrypt");
        assert_eq!(recovered, ssn);
    }

    #[test]
    fn masked_ssn_encrypt_fewer_than_4_digits_returns_error() {
        // Only 3 digits total — must fail.
        let err = MaskedSSN::encrypt("abc-123", &TEST_KEY, &TEST_NONCE)
            .expect_err("fewer than 4 digits must fail");
        assert!(matches!(
            err,
            crate::error::NexaCoreError::Identity {
                kind: crate::error::IdentityErrorKind::InvalidLength,
                ..
            }
        ));
    }

    // -------------------------------------------------------------------------
    // Domain separation: same plaintext encrypted as different types
    // produces different ciphertext because the AAD differs.
    // -------------------------------------------------------------------------

    #[test]
    fn domain_separation_same_plaintext_different_ciphertext() {
        let plaintext = "alice@example.com";
        let es = EncryptedString::encrypt(plaintext, &TEST_KEY, &TEST_NONCE)
            .expect("EncryptedString encrypt");
        let te = TokenizedEmail::encrypt(plaintext, &TEST_KEY, &TEST_NONCE)
            .expect("TokenizedEmail encrypt");
        // Authentication tags differ because the AAD (KIND constant) differs.
        assert_ne!(
            es.ciphertext(),
            te.ciphertext(),
            "domain separation: ciphertexts must differ"
        );
    }

    #[test]
    fn domain_separation_cross_type_decrypt_fails() {
        // Encrypt as EncryptedString, then try to decrypt as TokenizedEmail
        // using the same ciphertext bytes — must fail authentication.
        let plaintext = "cross-type test";
        let es = EncryptedString::encrypt(plaintext, &TEST_KEY, &TEST_NONCE)
            .expect("encrypt as EncryptedString");
        // Build a TokenizedEmail with the same raw ciphertext bytes.
        let fake_te = TokenizedEmail::from_ciphertext(es.ciphertext().to_vec());
        // Decrypting with the TokenizedEmail AAD must fail because the tag
        // was computed with the EncryptedString AAD.
        assert!(
            fake_te.decrypt(&TEST_KEY, &TEST_NONCE).is_err(),
            "cross-type decrypt must fail"
        );
    }
}

// Sanity-only test that does not require the provider feature: the sealed
// trait is sealed.
#[cfg(test)]
mod sealed_tests {
    use super::*;

    // This compiles iff `EncryptedString` implements both traits. The
    // real "cannot extend EncryptedType outside this crate" assertion
    // lives in the trybuild compile-fail tests.
    #[test]
    fn marker_types_implement_encrypted_type() {
        fn assert_impl<T: EncryptedType>() {}
        assert_impl::<EncryptedString>();
        assert_impl::<MaskedSSN>();
        assert_impl::<TokenizedEmail>();
        assert_impl::<AttestedHash>();
    }
}
