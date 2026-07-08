//! WS5-08.6 — kernel-side validation of encrypted SDK types at the syscall
//! boundary.
//!
//! The SDK exposes encrypted-by-default value types
//! ([`nexacore_types::encrypted`]) — `EncryptedString`, `MaskedSSN`,
//! `TokenizedEmail`, `AttestedHash` — each wrapping an opaque AEAD ciphertext
//! produced by the tokenization service. When such a value crosses a syscall
//! boundary it is marshalled as a **self-describing envelope** so the kernel
//! can enforce the encrypted-by-default invariant *before* the bytes reach a
//! handler: a syscall argument typed as carrying an encrypted value must be a
//! structurally valid envelope, never raw plaintext smuggled through.
//!
//! ## The boundary contract
//!
//! The kernel does **not** hold the unsealing key, so it cannot decrypt or
//! verify the Poly1305 tag — that authentication belongs to the tokenization
//! service / TEE that owns the key. What the kernel *can* and *must* do is a
//! fail-closed **structural** check:
//!
//! 1. The buffer is at least a header long.
//! 2. The magic + version identify a NexaCore encrypted-value envelope.
//! 3. The declared kind is known and matches the kind the syscall expects
//!    (so a `MaskedSSN` slot cannot be fed a `TokenizedEmail`).
//! 4. The declared ciphertext length matches the buffer exactly (no trailing
//!    smuggled bytes, no truncation).
//! 5. The ciphertext is large enough to *be* an AEAD output — it must carry at
//!    least the 16-byte Poly1305 tag (AEAD kinds) or the exact attestation
//!    width (`AttestedHash`).
//!
//! A raw plaintext buffer (e.g. the literal bytes `123-45-6789`) fails at step
//! 2; a truncated or padded envelope fails at step 4; a tag-less ciphertext
//! fails at step 5. The check is the kernel's half of the defence-in-depth:
//! the cryptographic guarantee is still the AEAD tag the key-holder verifies,
//! but the kernel guarantees no un-enveloped value ever crosses the boundary.
//!
//! ## Envelope wire format (`NCEV`, little-endian)
//!
//! | Offset | Size | Field                                              |
//! |-------:|-----:|----------------------------------------------------|
//! | 0      | 4    | magic = `ENC_ARG_MAGIC` (`b"NCEV"`)              |
//! | 4      | 1    | version = `ENC_ARG_VERSION`                     |
//! | 5      | 1    | kind tag (`EncryptedKind`)                      |
//! | 6      | 12   | nonce (ChaCha20-Poly1305 96-bit)                  |
//! | 18     | 4    | `ct_len` (u32 LE) — ciphertext byte length        |
//! | 22     | …    | ciphertext (`ct_len` bytes, includes the 16B tag) |
//!
//! Header is `ENC_ARG_HEADER_LEN` = 22 bytes; total = `22 + ct_len`.

#![allow(
    clippy::doc_markdown,
    reason = "module references AEAD, SDK, NCEV, TEE without backticks in prose"
)]

extern crate alloc;

use alloc::vec::Vec;

/// Envelope magic: NexaCore Encrypted Value.
pub const ENC_ARG_MAGIC: [u8; 4] = *b"NCEV";

/// Envelope wire version.
pub const ENC_ARG_VERSION: u8 = 1;

/// Header length in bytes (magic + version + kind + nonce + `ct_len`).
pub const ENC_ARG_HEADER_LEN: usize = 4 + 1 + 1 + 12 + 4;

/// ChaCha20-Poly1305 nonce length (96-bit).
pub const ENC_ARG_NONCE_LEN: usize = 12;

/// Poly1305 authentication tag length appended to every AEAD ciphertext.
pub const ENC_ARG_TAG_LEN: usize = 16;

/// Attestation width for [`EncryptedKind::AttestedHash`] (a 32-byte digest,
/// not an AEAD output).
pub const ENC_ARG_ATTESTED_HASH_LEN: usize = 32;

/// The encrypted SDK value categories that can cross a syscall boundary.
///
/// The numeric tags are the on-wire `kind` byte; the [`Self::kind_name`]
/// strings mirror `nexacore_types::encrypted::EncryptedType::KIND` exactly
/// (pinned by `tests::kind_tags_match_sdk_kind_constants`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum EncryptedKind {
    /// `EncryptedString` — opaque AEAD ciphertext.
    EncryptedString = 1,
    /// `MaskedSSN` — AEAD ciphertext + 4 plaintext suffix digits (the suffix
    /// is carried inside the ciphertext envelope, not separately).
    MaskedSsn = 2,
    /// `TokenizedEmail` — AEAD ciphertext.
    TokenizedEmail = 3,
    /// `AttestedHash` — a 32-byte attestation digest (not AEAD).
    AttestedHash = 4,
}

impl EncryptedKind {
    /// The on-wire kind byte.
    #[must_use]
    pub const fn tag(self) -> u8 {
        self as u8
    }

    /// Decode a kind byte. Returns `None` for an unknown tag.
    #[must_use]
    pub const fn from_tag(tag: u8) -> Option<Self> {
        match tag {
            1 => Some(Self::EncryptedString),
            2 => Some(Self::MaskedSsn),
            3 => Some(Self::TokenizedEmail),
            4 => Some(Self::AttestedHash),
            _ => None,
        }
    }

    /// The stable category identifier, identical to the SDK `KIND` constant.
    #[must_use]
    pub const fn kind_name(self) -> &'static str {
        match self {
            Self::EncryptedString => "encrypted-string",
            Self::MaskedSsn => "masked-ssn",
            Self::TokenizedEmail => "tokenized-email",
            Self::AttestedHash => "attested-hash",
        }
    }

    /// `true` for AEAD-backed kinds (ciphertext must carry the Poly1305 tag).
    #[must_use]
    pub const fn is_aead(self) -> bool {
        !matches!(self, Self::AttestedHash)
    }
}

/// Why a candidate encrypted-value envelope failed kernel validation.
///
/// Every variant is a *reject* — the validator is fail-closed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EncryptedArgError {
    /// Buffer shorter than [`ENC_ARG_HEADER_LEN`].
    TooShort,
    /// Magic is not [`ENC_ARG_MAGIC`] — likely raw plaintext or an unrelated
    /// buffer presented where an encrypted value was required.
    BadMagic,
    /// Version byte is not [`ENC_ARG_VERSION`].
    UnsupportedVersion,
    /// Kind byte does not decode to a known [`EncryptedKind`].
    UnknownKind,
    /// Decoded kind differs from the kind the syscall slot expects.
    KindMismatch,
    /// Declared `ct_len` does not match the buffer length exactly (trailing
    /// or missing bytes).
    LengthMismatch,
    /// AEAD ciphertext shorter than the mandatory [`ENC_ARG_TAG_LEN`], or an
    /// [`EncryptedKind::AttestedHash`] not exactly [`ENC_ARG_ATTESTED_HASH_LEN`].
    PayloadTooShort,
}

/// A validated, borrowed view over an encrypted-value envelope.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EncryptedArgView<'a> {
    /// The decoded value category.
    pub kind: EncryptedKind,
    /// The 96-bit AEAD nonce (12 bytes).
    pub nonce: [u8; ENC_ARG_NONCE_LEN],
    /// The opaque ciphertext (AEAD output incl. tag, or the attestation
    /// digest for [`EncryptedKind::AttestedHash`]).
    pub ciphertext: &'a [u8],
}

/// Read a little-endian `u32` from `buf[off..off+4]`, or `None` if out of
/// range.
fn read_u32_le(buf: &[u8], off: usize) -> Option<u32> {
    let bytes: [u8; 4] = buf.get(off..off + 4)?.try_into().ok()?;
    Some(u32::from_le_bytes(bytes))
}

/// Validate a syscall-boundary encrypted-value envelope, fail-closed.
///
/// `expected` is the kind the receiving syscall slot requires. Returns a
/// borrowed [`EncryptedArgView`] on success.
///
/// # Errors
///
/// Returns an [`EncryptedArgError`] for any structural defect: too short,
/// bad magic/version, unknown or mismatched kind, length mismatch, or a
/// payload too short to be a valid AEAD/attestation output. See each variant.
pub fn validate_encrypted_arg(
    buf: &[u8],
    expected: EncryptedKind,
) -> Result<EncryptedArgView<'_>, EncryptedArgError> {
    // 1. Minimum length: at least a full header.
    if buf.len() < ENC_ARG_HEADER_LEN {
        return Err(EncryptedArgError::TooShort);
    }

    // 2. Magic.
    if buf.get(0..4) != Some(&ENC_ARG_MAGIC) {
        return Err(EncryptedArgError::BadMagic);
    }

    // 3. Version.
    if buf.get(4) != Some(&ENC_ARG_VERSION) {
        return Err(EncryptedArgError::UnsupportedVersion);
    }

    // 4. Kind.
    let kind_byte = *buf.get(5).ok_or(EncryptedArgError::TooShort)?;
    let kind = EncryptedKind::from_tag(kind_byte).ok_or(EncryptedArgError::UnknownKind)?;
    if kind != expected {
        return Err(EncryptedArgError::KindMismatch);
    }

    // 5. Nonce.
    let nonce: [u8; ENC_ARG_NONCE_LEN] = buf
        .get(6..6 + ENC_ARG_NONCE_LEN)
        .ok_or(EncryptedArgError::TooShort)?
        .try_into()
        .map_err(|_| EncryptedArgError::TooShort)?;

    // 6. Declared ciphertext length must match the buffer exactly — no
    //    trailing smuggled bytes, no truncation.
    let ct_len = read_u32_le(buf, 18).ok_or(EncryptedArgError::TooShort)? as usize;
    let expected_total = ENC_ARG_HEADER_LEN
        .checked_add(ct_len)
        .ok_or(EncryptedArgError::LengthMismatch)?;
    if expected_total != buf.len() {
        return Err(EncryptedArgError::LengthMismatch);
    }

    // 7. Payload minimum: AEAD kinds must carry the Poly1305 tag; the
    //    attestation kind must be exactly its digest width.
    let payload_ok = if kind.is_aead() {
        ct_len >= ENC_ARG_TAG_LEN
    } else {
        ct_len == ENC_ARG_ATTESTED_HASH_LEN
    };
    if !payload_ok {
        return Err(EncryptedArgError::PayloadTooShort);
    }

    let ciphertext = buf
        .get(ENC_ARG_HEADER_LEN..)
        .ok_or(EncryptedArgError::TooShort)?;

    Ok(EncryptedArgView {
        kind,
        nonce,
        ciphertext,
    })
}

/// Build a wire envelope for an encrypted value. Used by the SDK marshalling
/// path and by tests; the inverse of [`validate_encrypted_arg`].
///
/// `ciphertext` is the opaque AEAD output (or attestation digest); `nonce` is
/// the 96-bit AEAD nonce. The caller is responsible for the ciphertext being a
/// genuine AEAD output — this function only frames it.
#[must_use]
pub fn encode_envelope(
    kind: EncryptedKind,
    nonce: &[u8; ENC_ARG_NONCE_LEN],
    ciphertext: &[u8],
) -> Vec<u8> {
    let mut out = Vec::with_capacity(ENC_ARG_HEADER_LEN + ciphertext.len());
    out.extend_from_slice(&ENC_ARG_MAGIC);
    out.push(ENC_ARG_VERSION);
    out.push(kind.tag());
    out.extend_from_slice(nonce);
    #[allow(
        clippy::cast_possible_truncation,
        reason = "ciphertext length is bounded by the syscall buffer cap, far below u32::MAX"
    )]
    out.extend_from_slice(&(ciphertext.len() as u32).to_le_bytes());
    out.extend_from_slice(ciphertext);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn good_envelope(kind: EncryptedKind, ct: &[u8]) -> Vec<u8> {
        let nonce = [7u8; ENC_ARG_NONCE_LEN];
        encode_envelope(kind, &nonce, ct)
    }

    #[test]
    fn header_len_is_22() {
        assert_eq!(ENC_ARG_HEADER_LEN, 22);
    }

    #[test]
    fn round_trip_encrypted_string() {
        // 16-byte tag + 5 bytes ciphertext.
        let ct = [0xABu8; ENC_ARG_TAG_LEN + 5];
        let env = good_envelope(EncryptedKind::EncryptedString, &ct);
        let view = validate_encrypted_arg(&env, EncryptedKind::EncryptedString).expect("valid");
        assert_eq!(view.kind, EncryptedKind::EncryptedString);
        assert_eq!(view.nonce, [7u8; ENC_ARG_NONCE_LEN]);
        assert_eq!(view.ciphertext, &ct[..]);
    }

    #[test]
    fn attested_hash_requires_exact_32_bytes() {
        let ok = good_envelope(EncryptedKind::AttestedHash, &[0u8; 32]);
        assert!(validate_encrypted_arg(&ok, EncryptedKind::AttestedHash).is_ok());
        let short = good_envelope(EncryptedKind::AttestedHash, &[0u8; 31]);
        assert_eq!(
            validate_encrypted_arg(&short, EncryptedKind::AttestedHash),
            Err(EncryptedArgError::PayloadTooShort)
        );
        let long = good_envelope(EncryptedKind::AttestedHash, &[0u8; 33]);
        assert_eq!(
            validate_encrypted_arg(&long, EncryptedKind::AttestedHash),
            Err(EncryptedArgError::PayloadTooShort)
        );
    }

    #[test]
    fn raw_plaintext_is_rejected_by_magic() {
        // A naive caller passes raw PII bytes where an encrypted value is
        // required. No NCEV magic → BadMagic (the core invariant).
        let raw = b"123-45-6789 plus padding to exceed the header length....";
        assert_eq!(
            validate_encrypted_arg(raw, EncryptedKind::MaskedSsn),
            Err(EncryptedArgError::BadMagic)
        );
    }

    #[test]
    fn too_short_buffer_rejected() {
        assert_eq!(
            validate_encrypted_arg(b"NCEV", EncryptedKind::EncryptedString),
            Err(EncryptedArgError::TooShort)
        );
    }

    #[test]
    fn wrong_version_rejected() {
        let mut env = good_envelope(EncryptedKind::EncryptedString, &[0u8; 16]);
        env[4] = 2; // bump version
        assert_eq!(
            validate_encrypted_arg(&env, EncryptedKind::EncryptedString),
            Err(EncryptedArgError::UnsupportedVersion)
        );
    }

    #[test]
    fn unknown_kind_rejected() {
        let mut env = good_envelope(EncryptedKind::EncryptedString, &[0u8; 16]);
        env[5] = 9; // not a known kind
        assert_eq!(
            validate_encrypted_arg(&env, EncryptedKind::EncryptedString),
            Err(EncryptedArgError::UnknownKind)
        );
    }

    #[test]
    fn kind_mismatch_rejected() {
        let env = good_envelope(EncryptedKind::TokenizedEmail, &[0u8; 16]);
        assert_eq!(
            validate_encrypted_arg(&env, EncryptedKind::MaskedSsn),
            Err(EncryptedArgError::KindMismatch)
        );
    }

    #[test]
    fn trailing_bytes_rejected_as_length_mismatch() {
        let mut env = good_envelope(EncryptedKind::EncryptedString, &[0u8; 16]);
        env.push(0xFF); // smuggle a trailing byte; ct_len still says 16
        assert_eq!(
            validate_encrypted_arg(&env, EncryptedKind::EncryptedString),
            Err(EncryptedArgError::LengthMismatch)
        );
    }

    #[test]
    fn truncated_ciphertext_rejected_as_length_mismatch() {
        let mut env = good_envelope(EncryptedKind::EncryptedString, &[0u8; 20]);
        env.truncate(env.len() - 2); // drop 2 ciphertext bytes; ct_len lies
        assert_eq!(
            validate_encrypted_arg(&env, EncryptedKind::EncryptedString),
            Err(EncryptedArgError::LengthMismatch)
        );
    }

    #[test]
    fn aead_ciphertext_without_tag_rejected() {
        // ct_len = 8 < TAG_LEN(16): cannot be a valid AEAD output.
        let env = good_envelope(EncryptedKind::TokenizedEmail, &[0u8; 8]);
        assert_eq!(
            validate_encrypted_arg(&env, EncryptedKind::TokenizedEmail),
            Err(EncryptedArgError::PayloadTooShort)
        );
    }

    #[test]
    fn empty_aead_plaintext_is_valid_when_tag_present() {
        // Encrypting an empty string yields exactly the 16-byte tag.
        let env = good_envelope(EncryptedKind::EncryptedString, &[0u8; ENC_ARG_TAG_LEN]);
        assert!(validate_encrypted_arg(&env, EncryptedKind::EncryptedString).is_ok());
    }

    #[test]
    fn kind_tags_match_sdk_kind_constants() {
        // Pin the kernel envelope kind names to the SDK `KIND` constants so a
        // rename on either side fails the build instead of silently diverging.
        use nexacore_types::encrypted::{
            AttestedHash, EncryptedString, EncryptedType, MaskedSSN, TokenizedEmail,
        };
        assert_eq!(
            EncryptedKind::EncryptedString.kind_name(),
            EncryptedString::KIND
        );
        assert_eq!(EncryptedKind::MaskedSsn.kind_name(), MaskedSSN::KIND);
        assert_eq!(
            EncryptedKind::TokenizedEmail.kind_name(),
            TokenizedEmail::KIND
        );
        assert_eq!(EncryptedKind::AttestedHash.kind_name(), AttestedHash::KIND);
    }

    #[test]
    fn kind_tag_round_trips() {
        for k in [
            EncryptedKind::EncryptedString,
            EncryptedKind::MaskedSsn,
            EncryptedKind::TokenizedEmail,
            EncryptedKind::AttestedHash,
        ] {
            assert_eq!(EncryptedKind::from_tag(k.tag()), Some(k));
        }
        assert_eq!(EncryptedKind::from_tag(0), None);
        assert_eq!(EncryptedKind::from_tag(5), None);
    }
}
