//! NexaCore-Pack v1 binary blob builder.
//!
//! [`build_opack`] is the single entry point: given all manifest data,
//! the ELF image bytes, and the Ed25519 signing seed, it produces the
//! complete `.opack` byte vector ready to write to disk.
//!
//! ## Binary layout produced
//!
//! ```text
//! Offset  Size  Field
//! ─────── ───── ──────────────────────────────────────────────────
//! 0x00    8     magic            = b"OMNIPACK"
//! 0x08    4     version          = 1u32 (little-endian)
//! 0x0C    4     flags            = 0u32 (reserved, always 0)
//! 0x10    8     manifest_offset  = 0x40 (immediately follows header)
//! 0x18    8     manifest_len     (postcard bytes, ≤ 16 KiB)
//! 0x20    8     signature_offset = 0x40 + manifest_len
//! 0x28    8     signature_len    = 64 (Ed25519 always 64 bytes)
//! 0x30    8     image_offset     = 0x40 + manifest_len + 64
//! 0x38    8     image_len
//! 0x40    *     manifest.pc      postcard-encoded DriverManifestBody
//! *       64    signature        Ed25519 over manifest.pc
//! *       *     image.elf        Ring 3 ELF
//! ─────── ───── ──────────────────────────────────────────────────
//! ```
//!
//! The format is defined in `NCIP-Driver-Framework-013` § S5.5 and
//! implemented in `crates/nexacore-kernel/src/driver_manifest.rs`.

use nexacore_crypto::hash::{Blake3, NexaCoreHash};
use nexacore_crypto::signing::{NexaCoreSigningKey, SIGNATURE_LEN, SIGNING_KEY_LEN, VERIFYING_KEY_LEN};
use nexacore_kernel::driver_manifest::{
    DriverCapabilities, DriverManifestBody, DriverMatchers, DriverMetaBody, NEXACORE_PACK_HEADER_LEN,
    NEXACORE_PACK_MAGIC, NEXACORE_PACK_MAX_BYTES, NEXACORE_PACK_MAX_MANIFEST_BYTES, NEXACORE_PACK_VERSION,
};
use nexacore_types::wire::encode_canonical;

use crate::error::PackError;

/// All inputs required to build an NexaCore-Pack v1 blob.
///
/// Owned strings and `Vec`s are consumed by [`build_opack`] to avoid
/// unnecessary copies; the ELF image is borrowed because it is typically
/// large and the caller may still need it.
pub struct PackInput<'img> {
    /// Driver short name (`DriverMetaBody::name`).
    pub name: String,
    /// Semantic version string (`DriverMetaBody::version`).
    pub version: String,
    /// Ed25519 issuer verifying key bytes (decoded from the manifest's
    /// `nexacore_issuer_pubkey` hex field). Must match the verifying key
    /// corresponding to `signing_seed`; the caller is responsible for
    /// validating this before constructing [`PackInput`].
    pub issuer_pubkey: [u8; VERIFYING_KEY_LEN],
    /// Capability declarations for `DriverManifestBody::capabilities`.
    pub capabilities: DriverCapabilities,
    /// Device-match table for `DriverManifestBody::matchers`.
    pub matchers: DriverMatchers,
    /// Raw Ring 3 ELF image bytes. BLAKE3 is computed here.
    pub image_bytes: &'img [u8],
    /// 32-byte Ed25519 signing seed. Used to produce the 64-byte
    /// signature over `manifest.pc`. The key material is passed by value
    /// so the caller can zeroize it after this call returns.
    pub signing_seed: [u8; SIGNING_KEY_LEN],
}

/// Build an NexaCore-Pack v1 binary blob from the provided inputs.
///
/// Steps follow NCIP-013 § S5.3 in order:
///
/// 1. Compute `BLAKE3(image_bytes)` → `nexacore_image_hash` ([`nexacore_crypto::hash::Blake3`]).
/// 2. Construct [`DriverManifestBody`] from the inputs.
/// 3. Encode the body via [`encode_canonical`] (postcard 1.x).
/// 4. Assert manifest size ≤ 16 KiB ([`PackError::ManifestTooLarge`]).
/// 5. Sign the postcard bytes with `signing_seed` → 64-byte Ed25519
///    signature ([`nexacore_crypto::signing::NexaCoreSigningKey`]).
/// 6. Compute section offsets using [`u64::checked_add`] throughout.
/// 7. Assert total size ≤ 32 MiB ([`PackError::PackTooLarge`]).
/// 8. Write 64-byte header ‖ `manifest.pc` ‖ `signature` ‖ `image.elf`.
///
/// # Errors
///
/// - [`PackError::PostcardEncode`] — [`encode_canonical`] fails.
/// - [`PackError::ManifestTooLarge`] — postcard bytes exceed 16 KiB.
/// - [`PackError::PackTooLarge`] — total blob exceeds 32 MiB.
/// - [`PackError::OffsetOverflow`] — section offset arithmetic overflows.
///
/// # Example
///
/// ```no_run
/// use nexacore_driver_pack::pack::{PackInput, build_opack};
/// use nexacore_kernel::driver_manifest::{DriverCapabilities, DriverMatchers};
///
/// let seed = [0u8; 32]; // use a real seed in production
/// let blob = build_opack(PackInput {
///     name: "my-driver".to_string(),
///     version: "0.1.0".to_string(),
///     issuer_pubkey: [0u8; 32], // must be the verifying key for `seed`
///     capabilities: DriverCapabilities::default(),
///     matchers: DriverMatchers::default(),
///     image_bytes: b"ELF",
///     signing_seed: seed,
/// }).unwrap();
/// assert!(blob.starts_with(b"OMNIPACK"));
/// ```
pub fn build_opack(input: PackInput<'_>) -> Result<Vec<u8>, PackError> {
    // Step 1 — BLAKE3 image hash (NCIP-013 § S5.3 step 2).
    let nexacore_image_hash: [u8; nexacore_crypto::hash::HASH_LEN] = Blake3::hash(input.image_bytes);

    // Step 2 — Construct the manifest body (the postcard signing payload,
    // NCIP-013 § S5.3 step 5).
    let body = DriverManifestBody {
        meta: DriverMetaBody {
            name: input.name,
            version: input.version,
            nexacore_image_hash,
            nexacore_issuer_pubkey: input.issuer_pubkey,
        },
        capabilities: input.capabilities,
        matchers: input.matchers,
    };

    // Step 3 — Postcard-encode the manifest body via the NexaCore canonical
    // wire encoding (NCIP-Serde-004; postcard 1.x).
    let manifest_pc: Vec<u8> =
        encode_canonical(&body).map_err(|e| PackError::PostcardEncode { msg: e.to_string() })?;

    // Step 4 — Size guard: manifest MUST fit in 16 KiB (NCIP-013 § S5.5).
    if manifest_pc.len() as u64 > NEXACORE_PACK_MAX_MANIFEST_BYTES {
        return Err(PackError::ManifestTooLarge {
            actual: manifest_pc.len(),
            limit: NEXACORE_PACK_MAX_MANIFEST_BYTES,
        });
    }

    // Step 5 — Sign the manifest bytes with the issuer's Ed25519 key
    // (NCIP-013 § S5.3 step 5). Ed25519 signing is deterministic
    // (RFC 8032); no external RNG is required.
    let signing_key = NexaCoreSigningKey::from_bytes(input.signing_seed);
    let sig_bytes: [u8; SIGNATURE_LEN] = signing_key.sign(&manifest_pc).to_bytes();

    // Step 6 — Compute section offsets. The manifest section begins
    // immediately after the 64-byte fixed header (offset 0x40). All
    // arithmetic uses checked_add to surface impossible-input paths.
    let manifest_offset: u64 = NEXACORE_PACK_HEADER_LEN as u64; // always 0x40
    let manifest_len: u64 = manifest_pc.len() as u64;
    let signature_offset: u64 =
        manifest_offset
            .checked_add(manifest_len)
            .ok_or(PackError::OffsetOverflow {
                section: "signature",
            })?;
    let signature_len: u64 = SIGNATURE_LEN as u64; // always 64
    let image_offset: u64 = signature_offset
        .checked_add(signature_len)
        .ok_or(PackError::OffsetOverflow { section: "image" })?;
    let image_len: u64 = input.image_bytes.len() as u64;

    // Step 7 — Size guard: total blob MUST be ≤ 32 MiB (NCIP-013 § S5.2).
    let total_len: u64 = image_offset
        .checked_add(image_len)
        .ok_or(PackError::OffsetOverflow { section: "total" })?;
    if total_len > NEXACORE_PACK_MAX_BYTES {
        return Err(PackError::PackTooLarge {
            actual: total_len,
            limit: NEXACORE_PACK_MAX_BYTES,
        });
    }

    // Step 8 — Assemble the blob. The capacity is exact (no reallocation).
    let capacity = usize::try_from(total_len).map_err(|_| PackError::OffsetOverflow {
        section: "capacity",
    })?;
    let mut out: Vec<u8> = Vec::with_capacity(capacity);

    // 64-byte fixed header (NCIP-013 § S5.5 layout, little-endian):
    out.extend_from_slice(&NEXACORE_PACK_MAGIC); // 0x00  8  magic
    out.extend_from_slice(&NEXACORE_PACK_VERSION.to_le_bytes()); // 0x08  4  version = 1
    out.extend_from_slice(&0u32.to_le_bytes()); // 0x0C  4  flags = 0
    out.extend_from_slice(&manifest_offset.to_le_bytes()); // 0x10  8
    out.extend_from_slice(&manifest_len.to_le_bytes()); // 0x18  8
    out.extend_from_slice(&signature_offset.to_le_bytes()); // 0x20  8
    out.extend_from_slice(&signature_len.to_le_bytes()); // 0x28  8
    out.extend_from_slice(&image_offset.to_le_bytes()); // 0x30  8
    out.extend_from_slice(&image_len.to_le_bytes()); // 0x38  8

    // Payload:
    out.extend_from_slice(&manifest_pc); // 0x40 ..  manifest.pc
    out.extend_from_slice(&sig_bytes); // ..   64  Ed25519 signature
    out.extend_from_slice(input.image_bytes); // ..   ..  image.elf

    debug_assert_eq!(
        out.len(),
        capacity,
        "pre-computed capacity must match final length"
    );
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use nexacore_kernel::driver_manifest::DriverCapabilities;
    use nexacore_kernel::driver_manifest::DriverMatchers;

    fn test_seed() -> [u8; SIGNING_KEY_LEN] {
        [0x42; SIGNING_KEY_LEN]
    }

    fn test_pubkey() -> [u8; VERIFYING_KEY_LEN] {
        let key = NexaCoreSigningKey::from_bytes(test_seed());
        key.verifying_key().as_bytes()
    }

    fn minimal_input(image: &[u8]) -> PackInput<'_> {
        PackInput {
            name: "test".to_string(),
            version: "0.1.0".to_string(),
            issuer_pubkey: test_pubkey(),
            capabilities: DriverCapabilities::default(),
            matchers: DriverMatchers::default(),
            image_bytes: image,
            signing_seed: test_seed(),
        }
    }

    #[test]
    fn build_opack_starts_with_magic() {
        let blob = build_opack(minimal_input(b"ELF")).unwrap();
        assert!(blob.starts_with(b"OMNIPACK"));
    }

    #[test]
    fn build_opack_version_field_is_one() {
        let blob = build_opack(minimal_input(b"ELF")).unwrap();
        let version = u32::from_le_bytes(blob[8..12].try_into().unwrap());
        assert_eq!(version, 1);
    }

    #[test]
    fn build_opack_flags_field_is_zero() {
        let blob = build_opack(minimal_input(b"ELF")).unwrap();
        let flags = u32::from_le_bytes(blob[12..16].try_into().unwrap());
        assert_eq!(flags, 0);
    }

    #[test]
    fn build_opack_manifest_offset_is_0x40() {
        let blob = build_opack(minimal_input(b"ELF")).unwrap();
        let offset = u64::from_le_bytes(blob[16..24].try_into().unwrap());
        assert_eq!(offset, 0x40);
    }

    #[test]
    fn build_opack_signature_is_64_bytes() {
        let blob = build_opack(minimal_input(b"ELF")).unwrap();
        let sig_len = u64::from_le_bytes(blob[40..48].try_into().unwrap());
        assert_eq!(sig_len, 64);
    }

    #[test]
    fn build_opack_image_bytes_survive_round_trip() {
        let image = b"this-is-the-ring3-elf-payload";
        let blob = build_opack(minimal_input(image)).unwrap();
        let img_offset: usize =
            u64::from_le_bytes(blob[48..56].try_into().unwrap())
                .try_into()
                .unwrap();
        let img_len: usize =
            u64::from_le_bytes(blob[56..64].try_into().unwrap())
                .try_into()
                .unwrap();
        assert_eq!(&blob[img_offset..img_offset + img_len], image);
    }

    #[test]
    fn build_opack_empty_image_succeeds() {
        let blob = build_opack(minimal_input(b"")).unwrap();
        let img_len = u64::from_le_bytes(blob[56..64].try_into().unwrap());
        assert_eq!(img_len, 0);
    }

    #[test]
    fn build_opack_header_len_matches_constant() {
        assert_eq!(NEXACORE_PACK_HEADER_LEN, 64);
    }
}
