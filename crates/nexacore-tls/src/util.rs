//! Small internal helpers.

/// Constant-time equality over two byte slices.
///
/// Returns `false` immediately for a length mismatch (lengths are not secret),
/// then folds a XOR accumulator over every byte so the comparison time does
/// not depend on *where* two equal-length inputs first differ. Used for
/// `Finished` verify-data checks, where an early-exit compare could leak MAC
/// bytes to an active attacker.
// `util` is a private module, but `constant_time_eq` is used from sibling
// modules (client, server), so it must be crate-visible.
#[allow(clippy::redundant_pub_crate)]
#[must_use]
pub(crate) fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}
