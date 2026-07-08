//! Host-mode integration tests for the K3 panic record
//! ([`nexacore_kernel::bare_metal::panic::PanicRecord`]).
//!
//! Specified by `NCIP-Kernel-012` § S4. The `#[panic_handler]` itself
//! is gated `target_os = "none"` and is not exercised here (the host
//! target has its own panic implementation). The tests target the
//! encoding pipeline: `PanicRecord` → `nexacore_types::wire::
//! encode_into_slice` → static buffer.

#![cfg(feature = "bare-metal")]
// Test-only relaxations: integration tests fail-loudly via
// `expect`/`unwrap` and reach for `format!`-style ergonomics. The
// workspace's strict pedantic lints are intentionally relaxed here.
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::integer_division,
    clippy::missing_docs_in_private_items,
    clippy::uninlined_format_args
)]

use nexacore_kernel::bare_metal::panic::{
    OVERFLOW_MARKER, PANIC_RECORD_MAX_BYTES, PanicLocation, PanicRecord,
};
use nexacore_types::wire::{decode_canonical, encode_into_slice};

/// Roundtrip helper: builds a `PanicRecord`, encodes it into a fixed
/// 1 KiB buffer, decodes it into a `serde_json::Value`-like decoded
/// form. Returns the encoded length.
///
/// We decode into a tuple struct matching `PanicRecord`'s field order
/// because postcard does not carry field names — name reconstruction
/// would require a parallel `Deserialize` impl, and the test goal is
/// only to assert the encoding is well-formed and round-tripable.
#[derive(serde::Deserialize, Debug, PartialEq, Eq)]
struct DecodedPanic<'a> {
    kernel_version: &'a str,
    panic_at: DecodedLocation<'a>,
    message: &'a str,
    stack_pointer: Option<u64>,
}

#[derive(serde::Deserialize, Debug, PartialEq, Eq)]
struct DecodedLocation<'a> {
    file: &'a str,
    line: u32,
    column: u32,
}

#[test]
fn panic_record_round_trips_through_wire() {
    let record = PanicRecord {
        kernel_version: "0.1.0-test",
        panic_at: PanicLocation {
            file: "crates/nexacore-kernel/src/foo.rs",
            line: 42,
            column: 7,
        },
        message: "invariant X violated",
        stack_pointer: None,
    };

    let mut buf = [0u8; PANIC_RECORD_MAX_BYTES];
    let written = encode_into_slice(&record, &mut buf).expect("encode");
    assert!(written > 0, "must produce a non-empty record");
    assert!(written <= PANIC_RECORD_MAX_BYTES);

    let decoded: DecodedPanic = decode_canonical(&buf[..written]).expect("decode");
    assert_eq!(decoded.kernel_version, "0.1.0-test");
    assert_eq!(decoded.panic_at.file, "crates/nexacore-kernel/src/foo.rs");
    assert_eq!(decoded.panic_at.line, 42);
    assert_eq!(decoded.panic_at.column, 7);
    assert_eq!(decoded.message, "invariant X violated");
    assert_eq!(decoded.stack_pointer, None);
}

#[test]
fn oversize_panic_record_returns_encode_error() {
    // A message larger than the buffer cap forces an overflow on
    // `encode_into_slice`. The panic handler falls back to
    // `OVERFLOW_MARKER` in this case.
    let huge_message: String = "x".repeat(PANIC_RECORD_MAX_BYTES * 2);
    let record = PanicRecord {
        kernel_version: "0.1.0-test",
        panic_at: PanicLocation {
            file: "f",
            line: 1,
            column: 1,
        },
        message: &huge_message,
        stack_pointer: None,
    };

    let mut buf = [0u8; PANIC_RECORD_MAX_BYTES];
    let err = encode_into_slice(&record, &mut buf).expect_err("must overflow");
    // We only assert the kind is EncodeFailed; the context string is
    // private to `nexacore_types::wire`.
    assert!(matches!(
        err,
        nexacore_types::error::NexaCoreError::Wire {
            kind: nexacore_types::error::WireErrorKind::EncodeFailed,
            ..
        }
    ));
}

#[test]
fn overflow_marker_is_well_formed_ascii() {
    // The fallback marker must be printable ASCII so a developer
    // reading the serial console after a kernel panic can spot it.
    assert!(
        OVERFLOW_MARKER
            .iter()
            .all(|&b| b.is_ascii() && (b == b'\n' || !b.is_ascii_control()))
    );
    assert!(OVERFLOW_MARKER.ends_with(b"\n"));
}

#[test]
fn panic_record_max_bytes_is_one_kib() {
    // The cap is part of the K3 wire contract: forensics tools rely
    // on it being exactly 1024 bytes so they can size their parser's
    // input buffer to match. Changing this constant is breaking-
    // change-equivalent for the post-mortem pipeline (currently
    // dormant until a forensics NCIP lands; the assertion is a
    // structural reminder).
    assert_eq!(PANIC_RECORD_MAX_BYTES, 1024);
}

#[test]
fn typical_panic_record_fits_in_a_tenth_of_the_buffer() {
    // Sanity check on the 1 KiB cap: a representative kernel panic
    // (path of ≤ 60 chars, message of ≤ 80 chars, line ≤ 999) should
    // encode to ≤ 100 bytes, leaving 10x headroom for unusually long
    // messages or future schema growth.
    let record = PanicRecord {
        kernel_version: "0.1.0",
        panic_at: PanicLocation {
            file: "crates/nexacore-kernel/src/scheduling.rs",
            line: 318,
            column: 12,
        },
        message: "task table exhausted (1024 slots)",
        stack_pointer: None,
    };
    let mut buf = [0u8; PANIC_RECORD_MAX_BYTES];
    let written = encode_into_slice(&record, &mut buf).expect("encode");
    assert!(
        written <= PANIC_RECORD_MAX_BYTES / 10,
        "encoded {} bytes",
        written
    );
}
