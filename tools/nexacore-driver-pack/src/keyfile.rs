//! Signing-key file reader for `nexacore-driver-pack`.
//!
//! The `--signing-key` flag accepts a path to a file containing the
//! 32-byte Ed25519 seed (private key) encoded as a 64-character lowercase
//! hex string with an optional trailing newline.
//!
//! On POSIX platforms the file's permission bits are checked before
//! reading: if the key file is group-readable or world-readable a warning
//! is emitted to stderr. This behaviour can be suppressed with
//! `--allow-loose-permissions` for CI / test environments.

use std::path::Path;

use nexacore_crypto::signing::SIGNING_KEY_LEN;

use crate::error::PackError;
use crate::manifest::{HexContext, decode_hex32};

/// Read a 32-byte Ed25519 signing seed from a hex-encoded file.
///
/// The file must contain exactly 64 non-whitespace hex characters
/// (optionally followed by whitespace / a trailing newline).
///
/// On Unix, the file's permission mode is checked before reading; if the
/// mode includes group-read (`0o040`) or world-read (`0o004`) bits and
/// `allow_loose_permissions` is `false`, a warning is printed to stderr.
/// The warning is non-fatal — the seed is still read and returned. Pass
/// `allow_loose_permissions = true` to silence it (e.g. in CI).
///
/// # Errors
///
/// - [`PackError::Io`] — the file cannot be read.
/// - [`PackError::SigningKeyBadLength`] — the trimmed content is not
///   exactly 64 characters.
/// - [`PackError::SigningKeyHexDecode`] — a non-hex character is present.
///
/// # Example
///
/// ```no_run
/// use std::path::Path;
/// use nexacore_driver_pack::keyfile::read_signing_seed;
///
/// // A file containing the 64-char hex seed:
/// // "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"
/// let seed = read_signing_seed(Path::new("/tmp/test.seed"), false).unwrap();
/// assert_eq!(seed.len(), 32);
/// ```
pub fn read_signing_seed(
    path: &Path,
    allow_loose_permissions: bool,
) -> Result<[u8; SIGNING_KEY_LEN], PackError> {
    #[cfg(unix)]
    check_key_file_permissions(path, allow_loose_permissions);

    // On non-Unix platforms (future ports) the permission check is a no-op,
    // so the parameter would be unused without this attribute.
    #[cfg(not(unix))]
    let _ = allow_loose_permissions;

    let raw = std::fs::read(path).map_err(|source| PackError::Io {
        path: path.to_string_lossy().into_owned(),
        source,
    })?;

    // Interpret the file as UTF-8; strip surrounding whitespace (covers
    // trailing `\n` from most editors).
    let content = String::from_utf8_lossy(&raw);
    let trimmed = content.trim();

    decode_hex32(trimmed, HexContext::SigningKey)
}

/// Inspect the Unix permission bits of the signing key file and emit a
/// warning to stderr if group-readable or world-readable bits are set.
///
/// This is a best-effort safeguard; failure to stat the file is also
/// reported as a non-fatal warning (the subsequent read will fail with a
/// clearer error if the file is genuinely inaccessible).
///
/// The `eprintln!` calls are intentional: this function exists to emit
/// human-readable CLI warnings to the operator's terminal. The project
/// bans `println!` in library code as a logging discipline, but deliberate
/// user-facing warnings written to stderr are the correct tool here —
/// `tracing` is not a dependency of this crate and would be heavyweight for
/// a single CLI diagnostic.
#[cfg(unix)]
#[allow(clippy::disallowed_macros)]
fn check_key_file_permissions(path: &Path, allow_loose_permissions: bool) {
    use std::os::unix::fs::PermissionsExt as _;

    if allow_loose_permissions {
        return;
    }

    match std::fs::metadata(path) {
        Ok(meta) => {
            let mode = meta.permissions().mode();
            // Bits 0o044: group-read (0o040) | world-read (0o004).
            if mode & 0o044 != 0 {
                eprintln!(
                    "nexacore-driver-pack: WARNING: signing key file '{}' has loose \
                     permissions (mode {:#o}). Recommended: chmod 0400 '{}'. \
                     Pass --allow-loose-permissions to silence this warning.",
                    path.display(),
                    mode & 0o777,
                    path.display(),
                );
            }
        }
        Err(e) => {
            // Non-fatal: the subsequent `fs::read` will produce the real error.
            eprintln!(
                "nexacore-driver-pack: WARNING: could not stat signing key file '{}': {e}",
                path.display(),
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write_temp_key(name: &str, hex: &str) -> std::path::PathBuf {
        let path = std::env::temp_dir().join(format!("nexacore-dp-test-{name}"));
        std::fs::write(&path, hex).unwrap();
        path
    }

    #[test]
    fn read_signing_seed_valid_hex() {
        let hex = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60";
        let path = write_temp_key("valid", hex);
        let seed = read_signing_seed(&path, true).unwrap();
        assert_eq!(seed[0], 0x9D);
        assert_eq!(seed[31], 0x60);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn read_signing_seed_strips_trailing_newline() {
        let hex = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60\n";
        let path = write_temp_key("newline", hex);
        let seed = read_signing_seed(&path, true).unwrap();
        assert_eq!(seed[0], 0x9D);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn read_signing_seed_rejects_short_hex() {
        let path = write_temp_key("short", "abcdef");
        let err = read_signing_seed(&path, true).unwrap_err();
        assert!(matches!(err, PackError::SigningKeyBadLength { .. }));
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn read_signing_seed_rejects_invalid_hex_char() {
        let hex = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7fXX";
        let path = write_temp_key("badhex", hex);
        let err = read_signing_seed(&path, true).unwrap_err();
        assert!(matches!(err, PackError::SigningKeyHexDecode { .. }));
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn read_signing_seed_rejects_missing_file() {
        let err = read_signing_seed(Path::new("/tmp/nonexistent-nexacore-dp-seed-test"), true).unwrap_err();
        assert!(matches!(err, PackError::Io { .. }));
    }
}
