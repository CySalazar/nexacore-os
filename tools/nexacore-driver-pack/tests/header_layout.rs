//! Byte-exact header-layout tests for `NexaCore-Pack v1`.
// Test helpers intentionally use `expect`, `panic!`, and direct indexing —
// all appropriate in test code where an unexpected condition is a test failure.
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::missing_panics_doc
)]
//!
//! Each test builds a blob with [`nexacore_driver_pack::pack::build_opack`] and
//! manually reads specific byte offsets, verifying they match the fixed-field
//! layout defined in NCIP-013 § S5.5:
//!
//! ```text
//! Offset  Size  Field
//! ─────── ───── ─────────────────────────────────────────────────────────
//! 0x00    8     magic            = b"OMNIPACK"
//! 0x08    4     version          = 1u32 LE
//! 0x0C    4     flags            = 0u32 LE
//! 0x10    8     manifest_offset  = 0x40 (64, immediately after header)
//! 0x18    8     manifest_len
//! 0x20    8     signature_offset = manifest_offset + manifest_len
//! 0x28    8     signature_len    = 64 (Ed25519 always 64 bytes)
//! 0x30    8     image_offset     = signature_offset + signature_len
//! 0x38    8     image_len
//! 0x40    *     manifest.pc      postcard-encoded DriverManifestBody
//! *       64    Ed25519 signature over manifest.pc
//! *       *     image.elf
//! ─────── ───── ─────────────────────────────────────────────────────────
//! ```

use nexacore_driver_pack::pack::{PackInput, build_opack};
use nexacore_kernel::driver_manifest::{DriverCapabilities, DriverMatchers};

// ---------------------------------------------------------------------------
// RFC 8032 § 7.1 test-vector 1 — used throughout these tests as the
// canonical signing identity so the values are reproducible.
//
// SK seed : 9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60
// Verifying key: d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a
// ---------------------------------------------------------------------------

const RFC8032_SK_HEX: &str = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60";
const RFC8032_PK_HEX: &str = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";

/// Decode a 64-character lowercase hex string into a 32-byte array.
/// `panic!` on any invalid character — acceptable in test helpers.
fn hex32(hex: &str) -> [u8; 32] {
    assert_eq!(hex.len(), 64, "expected 64 hex chars");
    let mut out = [0u8; 32];
    for (i, chunk) in hex.as_bytes().chunks_exact(2).enumerate() {
        out[i] = (nibble(chunk[0]) << 4) | nibble(chunk[1]);
    }
    out
}

fn nibble(c: u8) -> u8 {
    match c {
        b'0'..=b'9' => c - b'0',
        b'a'..=b'f' => c - b'a' + 10,
        _ => panic!("non-hex digit: {c}"),
    }
}

/// Read a little-endian `u64` at `offset` from a byte slice.
///
/// `panic!`s on out-of-bounds — acceptable for test helpers.
fn le64(buf: &[u8], offset: usize) -> u64 {
    let slice = buf
        .get(offset..offset + 8)
        .expect("offset out of bounds for le64");
    u64::from_le_bytes(slice.try_into().expect("slice length mismatch"))
}

/// Read a little-endian `u32` at `offset` from a byte slice.
fn le32(buf: &[u8], offset: usize) -> u32 {
    let slice = buf
        .get(offset..offset + 4)
        .expect("offset out of bounds for le32");
    u32::from_le_bytes(slice.try_into().expect("slice length mismatch"))
}

// ---------------------------------------------------------------------------
// Shared fixture builder
// ---------------------------------------------------------------------------

/// Build a minimal but valid NexaCore-Pack v1 blob.
///
/// Uses the RFC 8032 test vector for deterministic output; the ELF image is a
/// tiny stand-in (`b"TESTELF"`) — the tool does not parse ELF, only hashes it.
/// Capabilities include 3 MMIO regions and 2 IRQ lines per the plan spec.
fn build_test_blob() -> Vec<u8> {
    use nexacore_capability::scope::Resource;

    let mut caps = DriverCapabilities::default();
    caps.mmio_regions.push(Resource::MmioRegion {
        phys_base: 0x1_0000_0000,
        len: 0x1_0000,
    });
    caps.mmio_regions.push(Resource::MmioRegion {
        phys_base: 0x1_0001_0000,
        len: 0x1000,
    });
    caps.mmio_regions.push(Resource::MmioRegion {
        phys_base: 0x1_0002_0000,
        len: 0x1000,
    });
    caps.irq_lines.push(Resource::IrqLine(33));
    caps.irq_lines.push(Resource::IrqLine(34));

    let mut matchers = DriverMatchers::default();
    matchers
        .pci_vendor_device
        .push(nexacore_kernel::driver_manifest::PciMatcher {
            vendor: 0x1AF4,
            device: 0x1041,
        });

    build_opack(PackInput {
        name: "nexacore-driver-test".to_string(),
        version: "0.1.0".to_string(),
        issuer_pubkey: hex32(RFC8032_PK_HEX),
        capabilities: caps,
        matchers,
        image_bytes: b"TESTELF",
        signing_seed: hex32(RFC8032_SK_HEX),
    })
    .expect("build_opack must succeed for the canonical test fixture")
}

// ---------------------------------------------------------------------------
// Layout tests
// ---------------------------------------------------------------------------

/// The first 8 bytes must be the ASCII string `OMNIPACK`.
#[test]
fn magic_bytes_at_offset_0() {
    let blob = build_test_blob();
    let magic = blob.get(0..8).expect("blob too short for magic");
    assert_eq!(magic, b"OMNIPACK", "magic mismatch");
}

/// Bytes 8–11 (LE u32) must be `1` (`NEXACORE_PACK_VERSION`).
#[test]
fn version_at_offset_8_is_1() {
    let blob = build_test_blob();
    assert_eq!(le32(&blob, 0x08), 1, "version field must be 1");
}

/// Bytes 12–15 (LE u32) must be `0` (reserved flags, always zero).
#[test]
fn flags_at_offset_0x0c_are_zero() {
    let blob = build_test_blob();
    assert_eq!(le32(&blob, 0x0C), 0, "flags field must be 0");
}

/// `manifest_offset` (LE u64 at 0x10) must be exactly `0x40` (64).
///
/// The manifest section always starts immediately after the 64-byte fixed
/// header per NCIP-013 § S5.5.
#[test]
fn manifest_offset_is_0x40() {
    let blob = build_test_blob();
    assert_eq!(le64(&blob, 0x10), 0x40, "manifest_offset must be 0x40");
}

/// `signature_offset` must equal `manifest_offset + manifest_len`.
///
/// The signature section follows the manifest section with no gap and no
/// overlap (NCIP-013 § S5.5 contiguous layout).
#[test]
fn signature_offset_follows_manifest() {
    let blob = build_test_blob();
    let manifest_off = le64(&blob, 0x10);
    let manifest_len = le64(&blob, 0x18);
    let signature_off = le64(&blob, 0x20);
    assert_eq!(
        signature_off,
        manifest_off + manifest_len,
        "signature_offset must equal manifest_offset + manifest_len",
    );
}

/// `signature_len` (LE u64 at 0x28) must be exactly `64` (Ed25519 always).
#[test]
fn signature_len_is_64() {
    let blob = build_test_blob();
    assert_eq!(le64(&blob, 0x28), 64, "signature_len must be 64 bytes");
}

/// `image_offset` must equal `signature_offset + 64`.
///
/// The image section follows the signature section with no gap.
#[test]
fn image_offset_follows_signature() {
    let blob = build_test_blob();
    let signature_off = le64(&blob, 0x20);
    let signature_len = le64(&blob, 0x28);
    let image_off = le64(&blob, 0x30);
    assert_eq!(
        image_off,
        signature_off + signature_len,
        "image_offset must equal signature_offset + signature_len",
    );
}

/// Total blob length must equal `image_offset + image_len`.
///
/// Verifies that the capacity pre-computed in `build_opack` matches the
/// actual assembled blob length.
#[test]
fn total_blob_length_matches_header_fields() {
    let blob = build_test_blob();
    let image_off = le64(&blob, 0x30);
    let image_len = le64(&blob, 0x38);
    let expected_len = usize::try_from(image_off + image_len)
        .expect("header fields produce a length that fits in usize");
    assert_eq!(
        blob.len(),
        expected_len,
        "blob.len() must equal image_offset + image_len from the header",
    );
}

/// The blob starts with the 64-byte header followed immediately by the
/// manifest.pc bytes — no padding between header and payload.
#[test]
fn payload_starts_at_byte_64() {
    // The manifest_offset field should equal NEXACORE_PACK_HEADER_LEN = 64.
    let blob = build_test_blob();
    let manifest_off = le64(&blob, 0x10);
    assert_eq!(
        manifest_off, 64,
        "NEXACORE_PACK_HEADER_LEN is 64; manifest must start immediately after it",
    );
    // Also confirm the blob is at least 64 bytes (header) + at least 1 byte.
    assert!(
        blob.len() > 64,
        "blob must be longer than the 64-byte header alone",
    );
}
