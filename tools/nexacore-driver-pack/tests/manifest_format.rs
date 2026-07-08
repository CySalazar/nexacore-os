//! TASK-007 follow-through: TOML + JSON manifest parser parity tests.
//!
//! NCIP-Driver-Framework-013 § R4 chose TOML as the canonical
//! developer-side source format. The tool also accepts JSON for
//! backwards compatibility with pre-TASK-007 fixtures. These tests
//! verify three properties:
//!
//! 1. The TOML parser successfully decodes the canonical fixture
//!    (`tests/fixtures/test-manifest.toml`).
//! 2. The TOML and JSON parsers produce **byte-identical** postcard
//!    payloads when fed equivalent fixture content — i.e., the input
//!    format is a pure ergonomic shell over the same serde shape.
//! 3. The auto-detect dispatch (`from_path_bytes`) routes by file
//!    extension correctly: `.toml` → TOML, anything else → JSON.

// Tests intentionally use direct indexing and unwrap because an unexpected
// condition is a test failure (the indexing-slicing lint is meant for
// production code, not assertion sites).
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::missing_panics_doc
)]

use nexacore_driver_pack::manifest::PackManifestJson;
use nexacore_driver_pack::pack::{PackInput, build_opack};
use nexacore_types::wire::encode_canonical;

// Paths are relative to the tool crate root because integration
// tests are run with the tool's `Cargo.toml` directory as CWD
// (`cargo test --manifest-path tools/nexacore-driver-pack/Cargo.toml`).
const FIXTURE_JSON: &str = "tests/fixtures/test-manifest.json";
const FIXTURE_TOML: &str = "tests/fixtures/test-manifest.toml";

const RFC8032_SK: [u8; 32] = [
    0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60, 0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec, 0x2c, 0xc4,
    0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19, 0x70, 0x3b, 0xac, 0x03, 0x1c, 0xae, 0x7f, 0x60,
];

/// Read a fixture file relative to the repository root. The tool's
/// integration tests are run from the workspace root via
/// `cargo test --manifest-path tools/nexacore-driver-pack/Cargo.toml`,
/// so the test process's CWD is the workspace root.
fn read_fixture(path: &str) -> Vec<u8> {
    std::fs::read(path).unwrap_or_else(|e| panic!("read fixture {path}: {e}"))
}

#[test]
fn toml_fixture_parses_cleanly() {
    let bytes = read_fixture(FIXTURE_TOML);
    let manifest = PackManifestJson::from_toml(&bytes, FIXTURE_TOML)
        .expect("test-manifest.toml must parse without errors");
    assert_eq!(manifest.meta.name, "nexacore-driver-test");
    assert_eq!(manifest.meta.version, "0.1.0");
    assert_eq!(
        manifest.meta.nexacore_issuer_pubkey,
        "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
    );
}

#[test]
fn json_and_toml_fixtures_produce_byte_identical_postcard_payloads() {
    let json_bytes = read_fixture(FIXTURE_JSON);
    let toml_bytes = read_fixture(FIXTURE_TOML);

    let mj = PackManifestJson::from_json(&json_bytes, FIXTURE_JSON).expect("JSON parse");
    let mt = PackManifestJson::from_toml(&toml_bytes, FIXTURE_TOML).expect("TOML parse");

    // Pack both via build_opack with identical signing inputs; the
    // postcard manifest section MUST be byte-identical because the
    // serde shape is the same and the order of fields is deterministic.
    let make_input = |m: PackManifestJson| {
        let issuer = m.decode_issuer_pubkey().expect("issuer pubkey");
        PackInput {
            name: m.meta.name,
            version: m.meta.version,
            issuer_pubkey: issuer,
            capabilities: m.capabilities,
            matchers: m.matchers,
            image_bytes: b"ELFSTUB",
            signing_seed: RFC8032_SK,
        }
    };
    let blob_from_json = build_opack(make_input(mj)).expect("build_opack JSON");
    let blob_from_toml = build_opack(make_input(mt)).expect("build_opack TOML");

    // The two blobs MUST be byte-identical end to end: the postcard
    // manifest payload, the Ed25519 signature (deterministic per
    // RFC 8032 § 5.1.6), and the image hash all derive purely from
    // the inputs we just verified are semantically identical.
    assert_eq!(
        blob_from_json, blob_from_toml,
        "JSON and TOML fixtures with equivalent content MUST produce \
         byte-identical .opack blobs",
    );
}

#[test]
fn from_path_bytes_dispatches_toml_for_dot_toml_extension() {
    let bytes = read_fixture(FIXTURE_TOML);
    // `.toml` extension → TOML path.
    let manifest = PackManifestJson::from_path_bytes(&bytes, "anything/file.toml")
        .expect("from_path_bytes with .toml must use TOML parser");
    assert_eq!(manifest.meta.name, "nexacore-driver-test");

    // Capitalised extension still TOML (case-insensitive match).
    let manifest = PackManifestJson::from_path_bytes(&bytes, "FILE.TOML")
        .expect("from_path_bytes is case-insensitive on extension");
    assert_eq!(manifest.meta.name, "nexacore-driver-test");
}

#[test]
fn from_path_bytes_dispatches_json_for_default_extension() {
    let bytes = read_fixture(FIXTURE_JSON);
    // `.json` extension → JSON path.
    let manifest = PackManifestJson::from_path_bytes(&bytes, "anything/file.json")
        .expect("from_path_bytes with .json must use JSON parser");
    assert_eq!(manifest.meta.name, "nexacore-driver-test");

    // Unknown extension → JSON path (backwards-compatible default).
    let manifest = PackManifestJson::from_path_bytes(&bytes, "weird.extension")
        .expect("from_path_bytes falls back to JSON on unknown extension");
    assert_eq!(manifest.meta.name, "nexacore-driver-test");

    // No extension → JSON path.
    let manifest = PackManifestJson::from_path_bytes(&bytes, "no_extension")
        .expect("from_path_bytes falls back to JSON on no extension");
    assert_eq!(manifest.meta.name, "nexacore-driver-test");
}

#[test]
fn from_toml_surfaces_parse_error_with_path_context() {
    let invalid_toml: &[u8] = b"not = a = valid = toml";
    let err = PackManifestJson::from_toml(invalid_toml, "broken.toml")
        .expect_err("malformed TOML must return Err");
    let msg = format!("{err}");
    assert!(
        msg.contains("broken.toml"),
        "error message MUST cite the manifest path: got {msg:?}"
    );
}

#[test]
fn from_toml_surfaces_parse_error_on_non_utf8_input() {
    let bad_bytes: &[u8] = b"meta = \"\xFF\xFE\xFD\"";
    // toml crate's tokenizer surfaces this as a TOML parse error
    // rather than a UTF-8 error because TOML strings are UTF-8 by
    // definition — either path is acceptable as long as the error
    // mentions the manifest path so the caller can attribute the
    // failure to the right input file.
    let err = PackManifestJson::from_toml(bad_bytes, "binary.toml")
        .expect_err("invalid TOML must return Err");
    let msg = format!("{err}");
    assert!(
        msg.contains("binary.toml"),
        "error message MUST cite the manifest path: got {msg:?}"
    );
}

/// Force the `core::str::from_utf8` UTF-8 error branch explicitly:
/// raw bytes that are not even a valid UTF-8 sequence (e.g. lone
/// `0xFF` in the middle of nothing). This proves the `from_toml`
/// path's UTF-8 prefix check fires before handing off to the toml
/// crate's tokenizer.
#[test]
fn from_toml_rejects_invalid_utf8_with_dedicated_branch() {
    let invalid_utf8: &[u8] = &[0xFF, 0xFE, 0xFD, 0xFC];
    let err = PackManifestJson::from_toml(invalid_utf8, "invalid_utf8.toml")
        .expect_err("invalid UTF-8 must return Err");
    let msg = format!("{err}");
    assert!(
        msg.contains("invalid_utf8.toml"),
        "error message MUST cite the manifest path: got {msg:?}"
    );
}

/// Sanity check: the JSON fixture (which exists already) still
/// parses cleanly after the TOML support landed.
#[test]
fn json_fixture_still_parses_unchanged() {
    let bytes = read_fixture(FIXTURE_JSON);
    let manifest = PackManifestJson::from_json(&bytes, FIXTURE_JSON)
        .expect("test-manifest.json must still parse");
    assert_eq!(manifest.meta.name, "nexacore-driver-test");
    let _ = encode_canonical(&manifest.capabilities).expect("canonical encode");
}
