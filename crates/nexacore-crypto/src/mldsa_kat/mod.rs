//! Known-answer test (KAT) vectors for ML-DSA-65 (FIPS 204).
//!
//! These are the official NIST **ACVP** FIPS 204 test vectors
//! (`ML-DSA-keyGen-FIPS204`, `ML-DSA-sigGen-FIPS204`,
//! `ML-DSA-sigVer-FIPS204`, `vsId` 42) restricted to the `ML-DSA-65`
//! parameter set (NIST security category 3). They are stored as raw
//! lower-case hex with no whitespace, one artefact per file, and are
//! compiled in only for `#[cfg(test)]` builds (see `mldsa.rs`).
//!
//! The sign/verify vectors use the ACVP *internal* interface
//! (`ML-DSA.Sign_internal` / `ML-DSA.Verify_internal`, no domain
//! separator / context prefix), so the KATs are validated directly
//! against the underlying `ml-dsa` primitive. The NexaCore public
//! wrapper in `mldsa.rs` layers the FIPS 204 *external* interface
//! (Algorithm 2 / 3, with context) on top and is exercised by
//! round-trip + tamper tests.
//!
//! Provenance: <https://github.com/usnistgov/ACVP-Server> (FIPS 204),
//! mirrored via the RustCrypto `ml-dsa` test-vector set.

// --- ML-DSA-keyGen-FIPS204 (tcId 26) -------------------------------------
/// 32-byte key-generation seed (`xi`).
pub(super) const KEYGEN_SEED: &str = include_str!("keygen_seed.hex");
/// Expected 1952-byte encoded public (verifying) key derived from the seed.
pub(super) const KEYGEN_PK: &str = include_str!("keygen_pk.hex");

// --- ML-DSA-sigGen-FIPS204, deterministic group (tcId 21) ----------------
/// Expected 4032-byte expanded signing key (skEncode form).
pub(super) const SIGGEN_SK: &str = include_str!("siggen_sk.hex");
/// Message that was signed.
pub(super) const SIGGEN_MSG: &str = include_str!("siggen_msg.hex");
/// Expected 3309-byte deterministic signature (`rnd = 0^32`).
pub(super) const SIGGEN_SIG: &str = include_str!("siggen_sig.hex");

// --- ML-DSA-sigVer-FIPS204 (tg 2, shared verifying key) ------------------
/// 1952-byte verifying key shared by every sigVer case below.
pub(super) const SIGVER_PK: &str = include_str!("sigver_pk.hex");
/// Accepting case (tcId 20, "no modification"): message.
pub(super) const SIGVER_ACCEPT_MSG: &str = include_str!("sigver_accept_msg.hex");
/// Accepting case (tcId 20): valid signature — verification MUST succeed.
pub(super) const SIGVER_ACCEPT_SIG: &str = include_str!("sigver_accept_sig.hex");
/// Rejecting case (tcId 17, "modify message"): message.
pub(super) const SIGVER_REJECT_MSG_MSG: &str = include_str!("sigver_reject_msg_msg.hex");
/// Rejecting case (tcId 17): signature over a different message — MUST fail.
pub(super) const SIGVER_REJECT_MSG_SIG: &str = include_str!("sigver_reject_msg_sig.hex");
/// Rejecting case (tcId 18, "modify signature"): message.
pub(super) const SIGVER_REJECT_SIG_MSG: &str = include_str!("sigver_reject_sig_msg.hex");
/// Rejecting case (tcId 18): tampered signature — verification MUST fail.
pub(super) const SIGVER_REJECT_SIG_SIG: &str = include_str!("sigver_reject_sig_sig.hex");
