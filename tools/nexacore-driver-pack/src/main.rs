//! Binary entry-point for `nexacore-driver-pack`.
//!
//! Orchestrates the driver-pack pipeline:
//!
//! 1. Parse CLI arguments ([`args::Args::parse`]).
//! 2. Read and deserialize the driver manifest. The format is
//!    auto-detected from the file extension: `.toml` → TOML
//!    (NCIP-Driver-Framework-013 § R4 canonical developer-side
//!    source format); anything else → JSON (backwards-compatible
//!    with pre-TASK-007 fixtures).
//! 3. Read the Ed25519 signing seed from the key file.
//! 4. Derive the verifying key; assert it matches `nexacore_issuer_pubkey` in the
//!    manifest (NCIP-013 § S5.4).
//! 5. Read the Ring 3 ELF image bytes.
//! 6. Call [`nexacore_driver_pack::pack::build_opack`] to assemble the signed blob.
//! 7. Write the blob atomically to the output path.
//!
//! ## Exit codes
//!
//! | Code | Category |
//! |------|----------|
//! | 0 | Success |
//! | 1 | Usage / I/O error |
//! | 2 | Manifest parse error |
//! | 3 | Signing key error |
//! | 4 | Pack build / write error |

// `args` is a binary-local module; `pub(crate)` makes clippy happy about
// visibility within the binary's single-crate scope.
mod args;

use std::path::Path;

use nexacore_crypto::signing::NexaCoreSigningKey;
use nexacore_driver_pack::{
    error::PackError,
    keyfile::read_signing_seed,
    manifest::{PackManifestJson, hex_encode},
    pack::{PackInput, build_opack},
};

use crate::args::Args;

// `eprintln!`, `std::process::exit`, and `println!` are deliberately used in
// the binary entrypoint.  The project's `disallowed_*` lints prevent accidental
// use of these in library code; the binary `main()` is the exact exit/print
// call-site the lint notes describe as acceptable.
#[allow(clippy::disallowed_macros, clippy::disallowed_methods)]
fn main() {
    let args = match Args::parse() {
        Ok(a) => a,
        Err(e) => {
            eprintln!("nexacore-driver-pack: error: {e}");
            std::process::exit(e.exit_code());
        }
    };

    if let Err(e) = run(&args) {
        eprintln!("nexacore-driver-pack: error: {e}");
        std::process::exit(e.exit_code());
    }
}

/// Execute the full driver-pack pipeline.
///
/// # Pipeline (NCIP-013 § S5.3)
///
/// 1. Read and parse the JSON manifest (`--manifest`).
/// 2. Decode `nexacore_issuer_pubkey` from the manifest's hex field.
/// 3. Read the 32-byte signing seed from the key file (`--signing-key`).
/// 4. Derive the Ed25519 verifying key and assert it matches the manifest's
///    declared issuer pubkey.  A mismatch here means the kernel would reject
///    the produced blob at `DriverLoad` (NCIP-013 § S5.4).
/// 5. Read the ELF image bytes (`--image`).
/// 6. Call [`build_opack`] to assemble the signed binary blob.
/// 7. Write the blob atomically to `--output` via [`write_atomic`].
///
/// # Errors
///
/// Returns the first [`PackError`] encountered.  Each variant carries a
/// human-readable message and maps to a specific exit code via
/// [`PackError::exit_code`].
fn run(args: &Args) -> Result<(), PackError> {
    // ── Step 1: read and parse the manifest (TOML or JSON) ────────────────────
    // NCIP-Driver-Framework-013 § R4 chose TOML as the canonical
    // developer-side source format. The tool also accepts JSON for
    // backwards compatibility with the pre-TASK-007 test fixtures
    // and the CI smoke. Dispatch is by file extension via
    // `PackManifestJson::from_path_bytes`.
    let manifest_path = args.manifest.to_string_lossy().into_owned();
    let manifest_bytes = std::fs::read(&args.manifest).map_err(|source| PackError::Io {
        path: manifest_path.clone(),
        source,
    })?;
    let manifest = PackManifestJson::from_path_bytes(&manifest_bytes, &manifest_path)?;

    // ── Step 2: decode the issuer pubkey declared in the manifest ─────────────
    let manifest_issuer_pubkey: [u8; 32] = manifest.decode_issuer_pubkey()?;

    // ── Step 3: read the Ed25519 signing seed from the key file ───────────────
    let signing_seed = read_signing_seed(&args.signing_key, args.allow_loose_permissions)?;

    // ── Step 4: validate the signing key against the manifest pubkey ──────────
    // Derives the Ed25519 verifying key from the seed and compares it byte-for-
    // byte to `nexacore_issuer_pubkey`.  Catching the mismatch here — before doing
    // any hashing or encoding work — ensures that a driver developer who passes
    // the wrong `--signing-key` gets a clear diagnostic rather than producing a
    // blob that will silently fail at `DriverLoad` (NCIP-013 § S5.4).
    //
    // `signing_seed: [u8; 32]` is `Copy`, so the array value is not consumed
    // here; it is passed again to `PackInput` below.
    let derived_pubkey: [u8; 32] = NexaCoreSigningKey::from_bytes(signing_seed)
        .verifying_key()
        .as_bytes();
    if derived_pubkey != manifest_issuer_pubkey {
        return Err(PackError::IssuerKeyMismatch {
            manifest_pubkey: hex_encode(&manifest_issuer_pubkey),
            signing_key_pubkey: hex_encode(&derived_pubkey),
        });
    }

    // ── Step 5: read the ELF image bytes ─────────────────────────────────────
    let image_path = args.image.to_string_lossy().into_owned();
    let image_bytes = std::fs::read(&args.image).map_err(|source| PackError::Io {
        path: image_path,
        source,
    })?;

    // ── Step 6: build the NexaCore-Pack v1 blob ──────────────────────────────────
    let blob = build_opack(PackInput {
        name: manifest.meta.name,
        version: manifest.meta.version,
        issuer_pubkey: manifest_issuer_pubkey,
        capabilities: manifest.capabilities,
        matchers: manifest.matchers,
        image_bytes: &image_bytes,
        // `signing_seed` is `Copy` — the array value is copied here, not moved.
        signing_seed,
    })?;

    // ── Step 7: write the blob atomically ────────────────────────────────────
    write_atomic(&args.output, &blob)
}

/// Write `data` to `dest` atomically via a sibling temp file and rename.
///
/// The temporary file is `<dest>.tmp` in the same directory.  On success the
/// temp file is renamed over `dest` — a POSIX-atomic operation when both paths
/// are on the same file-system volume (see POSIX `rename(2)`).  On any failure
/// the temp file is removed via a best-effort `remove_file` call.
///
/// # Errors
///
/// - [`PackError::OutputPath`] — `dest` has no parent directory or no
///   file-name component (e.g. a bare `/` or empty path).
/// - [`PackError::Io`] — the write, sync, or rename failed.
fn write_atomic(dest: &Path, data: &[u8]) -> Result<(), PackError> {
    let parent = dest.parent().ok_or_else(|| PackError::OutputPath {
        path: dest.to_string_lossy().into_owned(),
        msg: "path has no parent directory".into(),
    })?;
    let file_name = dest.file_name().ok_or_else(|| PackError::OutputPath {
        path: dest.to_string_lossy().into_owned(),
        msg: "path has no file-name component".into(),
    })?;

    let mut tmp_name = file_name.to_os_string();
    tmp_name.push(".tmp");
    let tmp_path = parent.join(tmp_name);

    // Write the data, then rename atomically.  `and_then` chains the rename
    // so that both operations share the same cleanup path on failure.
    let result = std::fs::write(&tmp_path, data)
        .map_err(|source| PackError::Io {
            path: tmp_path.to_string_lossy().into_owned(),
            source,
        })
        .and_then(|()| {
            std::fs::rename(&tmp_path, dest).map_err(|source| PackError::Io {
                path: dest.to_string_lossy().into_owned(),
                source,
            })
        });

    if result.is_err() {
        // Best-effort cleanup.  The file may not exist if `write` itself failed
        // before the OS created the file (unlikely but theoretically possible).
        let _ = std::fs::remove_file(&tmp_path);
    }

    result
}
