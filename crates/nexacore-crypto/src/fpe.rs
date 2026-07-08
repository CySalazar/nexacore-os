//! Format-preserving encryption (Phase 4 placeholder).
//!
//! # Status
//!
//! Empty module. The functional implementation lands in Phase 4
//! (mesh release) once the routing-metadata format is finalized.
//!
//! # Why not now
//!
//! Format-preserving encryption (`FF1` / `FF3-1`) is only required by
//! the mesh layer's PII routing-metadata path: we need to encrypt
//! values like phone numbers and email addresses while preserving
//! their length and character set so they can fit in legacy database
//! columns and be looked up by deterministic indexes. None of the P1
//! consumers exercise this requirement.
//!
//! Shipping `FF1`/`FF3-1` prematurely would risk the implementation
//! drifting from the eventual wire format mandated by
//! `/ncips/ncip-mesh-001.md` (not yet drafted). We instead keep the
//! module path stable so downstream code can already write
//! `use nexacore_crypto::fpe;` without conditional compilation.
//!
//! # When the implementation lands
//!
//! It will provide:
//!
//! * `Ff1Cipher::new(key, tweak)` for the NIST-standardised FF1 mode.
//! * `Ff3_1Cipher::new(key, tweak)` for the more recent FF3-1 mode.
//! * Domain-restricted encryption: `encrypt_decimal`, `encrypt_alpha`,
//!   etc., over fixed alphabets.
//! * RFC test vectors for both modes.
//!
//! See `/docs/04-security-model.md` § "Format-preserving encryption".
