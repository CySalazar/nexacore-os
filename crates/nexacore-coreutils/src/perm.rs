//! `chmod` / `chown` on capability tokens (WS8-10.11).
//!
//! These are the NexaCore analogues of `chmod` and `chown`, but they operate on
//! the capability model, **not** on Unix mode bits or `uid:gid` pairs. They
//! mutate an entry through the [`fs::FileSystem`](crate::fs) seam's
//! [`set_capabilities`](crate::fs::FileSystem::set_capabilities) and
//! [`set_owner`](crate::fs::FileSystem::set_owner) operations and are
//! fail-closed: a missing path or an invalid token is an error, never a silent
//! no-op.
//!
//! ## Divergence from GNU `chmod` / `chown`
//!
//! This is deliberately not a re-implementation of the POSIX permission model.
//! Feeds the permission-model write-up (WS8-10.19).
//!
//! - **No octal modes.** GNU accepts `chmod 0755`; here there is no numeric
//!   mode. Access is a set of named [capability tokens](Capability)
//!   (`read` / `write` / `execute`), granted or revoked individually.
//! - **No `ugo` classes.** GNU has separate user/group/other triples
//!   (`chmod g+w`); NexaCore attaches a single capability grant to the entry
//!   itself - there is no owner/group/other axis, because authority flows from
//!   the capability token a caller holds, not from which class it falls into.
//! - **Symbolic operators only.** A [spec](parse_spec) is `+tokens`,
//!   `-tokens`, or `=tokens`: `+` grants, `-` revokes, `=` sets the grant
//!   exactly (revoking everything else). Tokens may be single letters
//!   (`r`/`w`/`x`), full names (`read`/`write`/`execute`), or comma-separated
//!   mixtures (`+read,x`).
//! - **`chown` reassigns one principal.** GNU's `chown user:group` sets an owner
//!   *and* a group; here [`chown`] reassigns only the single owning principal
//!   id. There is no group owner - group membership is modelled as *roles* on a
//!   principal (see the `identity` module), not as a second owner on the file.

use alloc::{vec, vec::Vec};

use crate::{
    CoreError,
    fs::{Capabilities, FileSystem, FsError},
};

/// A single capability token that can be granted on or revoked from an entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Capability {
    /// Permission to read an entry's contents (or list a directory).
    Read,
    /// Permission to write an entry (or add entries to a directory).
    Write,
    /// Permission to execute an entry (or traverse a directory).
    Execute,
}

/// A grant or revocation of one [`Capability`] token.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TokenOp {
    /// Grant the token (set it present).
    Grant(Capability),
    /// Revoke the token (set it absent).
    Revoke(Capability),
}

/// Apply one [`TokenOp`] to a [`Capabilities`] grant, returning the new grant.
#[must_use]
fn apply_token(mut caps: Capabilities, op: TokenOp) -> Capabilities {
    let present = matches!(op, TokenOp::Grant(_));
    let which = match op {
        TokenOp::Grant(c) | TokenOp::Revoke(c) => c,
    };
    match which {
        Capability::Read => caps.read = present,
        Capability::Write => caps.write = present,
        Capability::Execute => caps.execute = present,
    }
    caps
}

/// Apply a sequence of [`TokenOp`]s to a [`Capabilities`] grant in order.
#[must_use]
pub fn apply_ops(caps: Capabilities, ops: &[TokenOp]) -> Capabilities {
    ops.iter().fold(caps, |acc, op| apply_token(acc, *op))
}

/// Parse the token list of a spec body into capability tokens.
///
/// Each comma-separated piece is either a full token name (`read`, `write`,
/// `execute`) or a run of single-letter tokens (`r`, `w`, `x`). An empty body
/// yields an empty list.
fn parse_tokens(body: &str) -> Result<Vec<Capability>, CoreError> {
    let mut caps: Vec<Capability> = Vec::new();
    if body.is_empty() {
        return Ok(caps);
    }
    for piece in body.split(',') {
        if piece.is_empty() {
            return Err(CoreError::InvalidArgument);
        }
        match piece {
            "read" => caps.push(Capability::Read),
            "write" => caps.push(Capability::Write),
            "execute" => caps.push(Capability::Execute),
            letters => {
                for ch in letters.chars() {
                    caps.push(match ch {
                        'r' => Capability::Read,
                        'w' => Capability::Write,
                        'x' => Capability::Execute,
                        _ => return Err(CoreError::InvalidArgument),
                    });
                }
            }
        }
    }
    Ok(caps)
}

/// Parse a symbolic capability spec into a list of [`TokenOp`]s.
///
/// The spec is one operator character (`+`, `-`, or `=`) followed by a token
/// list (see `parse_tokens`). `+` grants each token, `-` revokes each, and `=`
/// sets the grant exactly - revoking all three tokens first, then granting the
/// listed ones (so `=` with an empty list clears every capability).
///
/// # Errors
///
/// [`CoreError::InvalidArgument`] if the spec is empty, has an unknown operator,
/// contains an unknown token, or is a `+`/`-` spec with no tokens.
pub fn parse_spec(spec: &str) -> Result<Vec<TokenOp>, CoreError> {
    let mut chars = spec.chars();
    let op = chars.next().ok_or(CoreError::InvalidArgument)?;
    let listed = parse_tokens(chars.as_str())?;
    match op {
        '+' => grant_or_revoke(&listed, true),
        '-' => grant_or_revoke(&listed, false),
        '=' => {
            let mut ops = vec![
                TokenOp::Revoke(Capability::Read),
                TokenOp::Revoke(Capability::Write),
                TokenOp::Revoke(Capability::Execute),
            ];
            ops.extend(listed.iter().map(|c| TokenOp::Grant(*c)));
            Ok(ops)
        }
        _ => Err(CoreError::InvalidArgument),
    }
}

/// Build grant (or revoke) ops for every listed token, rejecting an empty list.
fn grant_or_revoke(listed: &[Capability], grant: bool) -> Result<Vec<TokenOp>, CoreError> {
    if listed.is_empty() {
        return Err(CoreError::InvalidArgument);
    }
    Ok(listed
        .iter()
        .map(|c| {
            if grant {
                TokenOp::Grant(*c)
            } else {
                TokenOp::Revoke(*c)
            }
        })
        .collect())
}

/// `chmod`-equivalent: apply capability-token `ops` to the entry at `path`,
/// returning the resulting grant.
///
/// Reads the current grant through the seam, applies each op in order, and
/// writes the result back.
///
/// # Errors
///
/// Any [`FsError`] from reading or writing `path` (missing path, relative path,
/// etc.) - fail-closed.
pub fn chmod<F: FileSystem>(
    fs: &mut F,
    path: &str,
    ops: &[TokenOp],
) -> Result<Capabilities, FsError> {
    let meta = fs.metadata(path)?;
    let new_caps = apply_ops(meta.capabilities, ops);
    fs.set_capabilities(path, new_caps)?;
    Ok(new_caps)
}

/// `chmod`-equivalent driven by a symbolic [spec](parse_spec) string.
///
/// # Errors
///
/// [`PermError::Parse`] if the spec is invalid, or [`PermError::Fs`] if the
/// filesystem operation fails.
pub fn chmod_spec<F: FileSystem>(
    fs: &mut F,
    path: &str,
    spec: &str,
) -> Result<Capabilities, PermError> {
    let ops = parse_spec(spec).map_err(PermError::Parse)?;
    chmod(fs, path, &ops).map_err(PermError::Fs)
}

/// `chown`-equivalent: reassign the owning principal of the entry at `path`.
///
/// # Errors
///
/// Any [`FsError`] from the seam (missing path, relative path) - fail-closed.
pub fn chown<F: FileSystem>(fs: &mut F, path: &str, new_owner: u64) -> Result<(), FsError> {
    fs.set_owner(path, new_owner)
}

/// An error from a spec-driven `chmod`: either parsing the spec or applying it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PermError {
    /// The symbolic spec could not be parsed.
    Parse(CoreError),
    /// The filesystem operation failed.
    Fs(FsError),
}

impl core::fmt::Display for PermError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Parse(e) => write!(f, "invalid permission spec: {e}"),
            Self::Fs(e) => write!(f, "{e}"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fs::{MemFs, ROOT_OWNER};

    fn fs() -> MemFs {
        // `/f` starts read-write (no execute), the MemFs default for a file.
        MemFs::new().with_text_file("/f", "data")
    }

    #[test]
    fn apply_ops_grants_and_revokes() {
        let caps = apply_ops(
            Capabilities::read_write(),
            &[
                TokenOp::Grant(Capability::Execute),
                TokenOp::Revoke(Capability::Write),
            ],
        );
        assert_eq!(caps.as_rwx(), "r-x");
    }

    #[test]
    fn parse_plus_letters_and_names() {
        assert_eq!(
            parse_spec("+rx").unwrap(),
            [
                TokenOp::Grant(Capability::Read),
                TokenOp::Grant(Capability::Execute),
            ]
        );
        assert_eq!(
            parse_spec("+read,execute").unwrap(),
            [
                TokenOp::Grant(Capability::Read),
                TokenOp::Grant(Capability::Execute),
            ]
        );
    }

    #[test]
    fn parse_minus_revokes() {
        assert_eq!(
            parse_spec("-w").unwrap(),
            [TokenOp::Revoke(Capability::Write)]
        );
    }

    #[test]
    fn parse_equals_sets_exactly() {
        // `=rx` revokes all, then grants read and execute.
        let start = Capabilities::all();
        let ops = parse_spec("=rx").unwrap();
        assert_eq!(apply_ops(start, &ops).as_rwx(), "r-x");
    }

    #[test]
    fn parse_equals_empty_clears_all() {
        let ops = parse_spec("=").unwrap();
        assert_eq!(apply_ops(Capabilities::all(), &ops).as_rwx(), "---");
    }

    #[test]
    fn parse_rejects_bad_specs() {
        assert_eq!(parse_spec(""), Err(CoreError::InvalidArgument));
        assert_eq!(parse_spec("+"), Err(CoreError::InvalidArgument));
        assert_eq!(parse_spec("-"), Err(CoreError::InvalidArgument));
        assert_eq!(parse_spec("*rw"), Err(CoreError::InvalidArgument));
        assert_eq!(parse_spec("+q"), Err(CoreError::InvalidArgument));
        assert_eq!(parse_spec("+read,,x"), Err(CoreError::InvalidArgument));
    }

    #[test]
    fn chmod_mutates_through_seam() {
        let mut fs = fs();
        let caps = chmod(&mut fs, "/f", &[TokenOp::Grant(Capability::Execute)]).unwrap();
        assert_eq!(caps.as_rwx(), "rwx");
        assert_eq!(fs.metadata("/f").unwrap().capabilities.as_rwx(), "rwx");
    }

    #[test]
    fn chmod_spec_end_to_end() {
        let mut fs = fs();
        let caps = chmod_spec(&mut fs, "/f", "=r").unwrap();
        assert_eq!(caps.as_rwx(), "r--");
    }

    #[test]
    fn chmod_missing_path_is_fail_closed() {
        let mut fs = fs();
        assert_eq!(
            chmod(&mut fs, "/nope", &[TokenOp::Grant(Capability::Read)]),
            Err(FsError::NotFound)
        );
    }

    #[test]
    fn chmod_spec_reports_parse_and_fs_errors() {
        let mut fs = fs();
        assert_eq!(
            chmod_spec(&mut fs, "/f", "+q"),
            Err(PermError::Parse(CoreError::InvalidArgument))
        );
        assert_eq!(
            chmod_spec(&mut fs, "/nope", "+r"),
            Err(PermError::Fs(FsError::NotFound))
        );
    }

    #[test]
    fn chmod_relative_path_is_invalid() {
        let mut fs = fs();
        assert_eq!(
            chmod(&mut fs, "f", &[TokenOp::Grant(Capability::Read)]),
            Err(FsError::InvalidPath)
        );
    }

    #[test]
    fn chown_reassigns_owner() {
        let mut fs = fs();
        assert_eq!(fs.owner("/f"), Ok(ROOT_OWNER));
        chown(&mut fs, "/f", 1000).unwrap();
        assert_eq!(fs.owner("/f"), Ok(1000));
    }

    #[test]
    fn chown_missing_path_is_fail_closed() {
        let mut fs = fs();
        assert_eq!(chown(&mut fs, "/nope", 1), Err(FsError::NotFound));
    }

    #[test]
    fn perm_error_display() {
        use alloc::format;
        assert_eq!(
            format!("{}", PermError::Fs(FsError::NotFound)),
            "no such file or directory"
        );
        assert_eq!(
            format!("{}", PermError::Parse(CoreError::InvalidArgument)),
            "invalid permission spec: invalid argument"
        );
    }
}
