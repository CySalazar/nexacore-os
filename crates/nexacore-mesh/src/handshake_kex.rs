//! Forward-secret key agreement for the mesh handshake (WS6-03.4).
//!
//! This is the concrete cryptography behind invariant **I2** (forward secrecy):
//! the session chain keys are derived from *ephemeral* X25519 Diffie–Hellman, so
//! compromising a node's long-term static key **after** the handshake does not
//! reveal the session keys — the ephemeral secrets are single-use and zeroized.
//!
//! Per spec §3:
//! - `dh1 = DH(esk_B, epk_A)`, `chain_key_0 = KDF(H(transcript_after_m1) || dh1, "chain-0")`;
//! - `dh2 = DH(epk_B, esk_A)`, `chain_key_1 = KDF(chain_key_0 || dh2, "chain-1")`.
//!
//! No primitive is implemented here. The DH uses `nexacore-crypto`'s vetted
//! X25519 ([`NexaCoreEphemeralSecret`]) and rejects the all-zero shared secret
//! that a low-order peer key produces ([`NexaCoreSharedSecret::is_trivial`],
//! spec §4.2). The KDF uses `nexacore-crypto`'s `HKDF-SHA-256`
//! ([`hkdf_extract_and_expand`]) under the [`KDF_INFO_PREFIX`] info string
//! (spec §1). This module remains subject to the WS10-03 crypto review.
//!
//! [`NexaCoreSharedSecret::is_trivial`]: nexacore_crypto::kex::NexaCoreSharedSecret::is_trivial

use std::vec::Vec;

use nexacore_crypto::{
    kdf::hkdf_extract_and_expand,
    kex::{KEY_LEN, NexaCoreEphemeralSecret, NexaCorePublicKey, SHARED_SECRET_LEN},
};

/// The KDF info-string prefix (spec §1): every `KDF` call binds
/// `"NexaCore-PROTO-v0.2/handshake/" || info_suffix`.
pub const KDF_INFO_PREFIX: &str = "NexaCore-PROTO-v0.2/handshake/";

/// An ephemeral X25519 keypair for one handshake (single-use, forward secrecy).
pub struct Ephemeral {
    secret: NexaCoreEphemeralSecret,
    public: [u8; KEY_LEN],
}

impl Ephemeral {
    /// Generate a fresh ephemeral keypair.
    #[must_use]
    pub fn generate() -> Self {
        let secret = NexaCoreEphemeralSecret::generate();
        let public = secret.public_key().as_bytes();
        Self { secret, public }
    }

    /// The ephemeral public key to send to the peer (`epk`).
    #[must_use]
    pub fn public(&self) -> [u8; KEY_LEN] {
        self.public
    }

    /// Perform the ephemeral X25519 DH with the peer's public key, consuming the
    /// secret (single-use).
    ///
    /// Returns `None` when the shared secret is the all-zero "trivial" value a
    /// low-order peer key produces — an honest peer aborts the handshake (§4.2).
    #[must_use]
    pub fn diffie_hellman(self, peer_public: &[u8; KEY_LEN]) -> Option<[u8; SHARED_SECRET_LEN]> {
        let Self { secret, .. } = self;
        let peer = NexaCorePublicKey::from_bytes(*peer_public);
        let shared = secret.diffie_hellman(&peer);
        if shared.is_trivial() {
            None
        } else {
            Some(*shared.as_bytes())
        }
    }
}

/// `KDF(ikm, info_suffix)` (spec §1): `HKDF-SHA-256` over `ikm` with the info
/// `"NexaCore-PROTO-v0.2/handshake/" || info_suffix`, producing a 32-byte key.
fn kdf(ikm: &[u8], info_suffix: &str) -> Option<[u8; 32]> {
    let mut info = Vec::with_capacity(KDF_INFO_PREFIX.len() + info_suffix.len());
    info.extend_from_slice(KDF_INFO_PREFIX.as_bytes());
    info.extend_from_slice(info_suffix.as_bytes());
    hkdf_extract_and_expand(&[], ikm, &info, 32)
        .ok()
        .and_then(|v| <[u8; 32]>::try_from(v.as_slice()).ok())
}

/// Derive `chain_key_0 = KDF(H(transcript_after_m1) || dh1, "chain-0")` (spec §3.2).
///
/// Returns `None` if the KDF fails (a build-time invariant — should not happen).
#[must_use]
pub fn chain_key_0(
    transcript_after_m1: &[u8; 32],
    dh1: &[u8; SHARED_SECRET_LEN],
) -> Option<[u8; 32]> {
    let mut ikm = Vec::with_capacity(64);
    ikm.extend_from_slice(transcript_after_m1);
    ikm.extend_from_slice(dh1);
    kdf(&ikm, "chain-0")
}

/// Derive `chain_key_1 = KDF(chain_key_0 || dh2, "chain-1")` (spec §3.3).
#[must_use]
pub fn chain_key_1(chain_key_0: &[u8; 32], dh2: &[u8; SHARED_SECRET_LEN]) -> Option<[u8; 32]> {
    let mut ikm = Vec::with_capacity(64);
    ikm.extend_from_slice(chain_key_0);
    ikm.extend_from_slice(dh2);
    kdf(&ikm, "chain-1")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ephemeral_dh_is_symmetric() {
        let a = Ephemeral::generate();
        let b = Ephemeral::generate();
        let a_pub = a.public();
        let b_pub = b.public();
        let ss_a = a.diffie_hellman(&b_pub);
        let ss_b = b.diffie_hellman(&a_pub);
        assert!(ss_a.is_some());
        assert_eq!(ss_a, ss_b); // both sides agree on the shared secret
    }

    #[test]
    fn low_order_peer_key_is_rejected() {
        let e = Ephemeral::generate();
        // The all-zero public key is a low-order point → trivial shared secret.
        assert!(e.diffie_hellman(&[0u8; KEY_LEN]).is_none());
    }

    #[test]
    fn forward_secrecy_independent_sessions_differ() {
        // Each handshake uses fresh ephemerals, so two sessions derive unrelated
        // chain keys — the essence of forward secrecy (I2).
        fn session_chain_key() -> Option<[u8; 32]> {
            let a = Ephemeral::generate();
            let b = Ephemeral::generate();
            let b_pub = b.public();
            // dh over fresh ephemerals; symmetry is tested separately.
            let dh1 = a.diffie_hellman(&b_pub)?;
            chain_key_0(&[1u8; 32], &dh1)
        }
        let s1 = session_chain_key();
        let s2 = session_chain_key();
        assert!(s1.is_some() && s2.is_some());
        assert_ne!(s1, s2);
    }

    #[test]
    fn chain_key_derivation_is_deterministic_and_chained() {
        let transcript = [2u8; 32];
        let dh1 = [3u8; SHARED_SECRET_LEN];
        let ck0_a = chain_key_0(&transcript, &dh1);
        let ck0_b = chain_key_0(&transcript, &dh1);
        assert_eq!(ck0_a, ck0_b); // deterministic
        assert!(ck0_a.is_some());
        if let Some(ck0) = ck0_a {
            let ck1 = chain_key_1(&ck0, &[4u8; SHARED_SECRET_LEN]);
            assert!(ck1.is_some());
            // chain_key_1 advances the chain — distinct from chain_key_0.
            assert_ne!(ck1, ck0_a);
        }
    }

    #[test]
    fn chain_keys_bind_the_transcript_and_dh() {
        // Different transcript → different chain_key_0.
        let dh1 = [5u8; SHARED_SECRET_LEN];
        let k_a = chain_key_0(&[1u8; 32], &dh1);
        let k_b = chain_key_0(&[9u8; 32], &dh1);
        assert_ne!(k_a, k_b);
        // Different DH → different chain_key_0.
        let k_c = chain_key_0(&[1u8; 32], &[6u8; SHARED_SECRET_LEN]);
        assert_ne!(k_a, k_c);
    }
}
