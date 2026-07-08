//! `nexacore-driver-pack` — NexaCore OS driver-pack v1 producer.
//!
//! This library crate exposes the core logic used by the `nexacore-driver-pack`
//! binary. Integration tests in `tests/` import from here, and downstream
//! build systems that want to produce `.opack` blobs programmatically can
//! use this crate directly.
//!
//! ## Usage (binary — see `--help` for full reference)
//!
//! ```text
//! nexacore-driver-pack \
//!   --manifest  path/to/driver.json \
//!   --image     path/to/ring3.elf \
//!   --signing-key path/to/ed25519.seed \
//!   --output    driver.opack
//! ```
//!
//! ## Library entry points
//!
//! - [`manifest::PackManifestJson`] — parse a JSON manifest.
//! - [`pack::build_opack`] — assemble a signed NexaCore-Pack v1 blob.
//! - [`keyfile::read_signing_seed`] — read a hex-encoded Ed25519 seed file.
//! - [`error::PackError`] — typed error enum with exit-code mapping.
//!
//! ## Wire format
//!
//! The tool produces blobs conforming to `NCIP-Driver-Framework-013` § S5.5.
//! The kernel-side decoder lives in
//! [`nexacore_kernel::driver_manifest::decode_nexacore_pack`].

#![cfg_attr(
    test,
    allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::indexing_slicing,
        clippy::panic,
        clippy::missing_panics_doc,
        clippy::missing_errors_doc,
        clippy::tests_outside_test_module
    )
)]

/// Typed error enum and exit-code mapping.
pub mod error;
/// Signing-key file reader and Unix permission checker.
pub mod keyfile;
/// JSON manifest schema and deserialization.
pub mod manifest;
/// NexaCore-Pack v1 binary blob builder.
pub mod pack;
