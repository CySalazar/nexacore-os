//! Key exchange: KEXINIT, algorithm negotiation, the exchange hash, and
//! RFC 4253 §7.2 key derivation (curve25519-sha256, RFC 8731).
//!
//! The negotiated profile is fixed to what `nexacore-crypto` provides:
//! `curve25519-sha256` key exchange, an `ssh-ed25519` host key, and a
//! ChaCha20-Poly1305 AEAD packet cipher (advertised as
//! `chacha20-poly1305@nexacore`). Negotiation is still performed against the
//! peer's name-lists so an incompatible peer fails cleanly.

use alloc::{string::String, vec::Vec};

use nexacore_crypto::{
    hash::{NexaCoreHash, Sha256H},
    kex::generate_ephemeral,
};

use crate::{
    error::SshError,
    packet::SSH_MSG_KEXINIT,
    wire::{Reader, Writer},
};

/// The key-exchange algorithm this implementation offers.
pub const KEX_ALGORITHM: &str = "curve25519-sha256";
/// The host-key algorithm this implementation offers.
pub const HOST_KEY_ALGORITHM: &str = "ssh-ed25519";
/// The packet cipher this implementation offers (NexaCore AEAD profile).
pub const CIPHER_ALGORITHM: &str = "chacha20-poly1305@nexacore";
/// The MAC name (implicit for an AEAD cipher).
pub const MAC_ALGORITHM: &str = "aead";
/// The compression algorithm (none).
pub const COMPRESSION_ALGORITHM: &str = "none";

/// A parsed/constructed `SSH_MSG_KEXINIT` message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KexInit {
    /// The 16-byte anti-replay cookie.
    pub cookie: [u8; 16],
    /// Offered key-exchange algorithms, in preference order.
    pub kex_algorithms: Vec<String>,
    /// Offered host-key algorithms.
    pub host_key_algorithms: Vec<String>,
    /// Offered client→server ciphers.
    pub cipher_c2s: Vec<String>,
    /// Offered server→client ciphers.
    pub cipher_s2c: Vec<String>,
}

impl KexInit {
    /// Build the KEXINIT this implementation offers, with the given `cookie`.
    #[must_use]
    pub fn offer(cookie: [u8; 16]) -> Self {
        let one = |s: &str| alloc::vec![String::from(s)];
        Self {
            cookie,
            kex_algorithms: one(KEX_ALGORITHM),
            host_key_algorithms: one(HOST_KEY_ALGORITHM),
            cipher_c2s: one(CIPHER_ALGORITHM),
            cipher_s2c: one(CIPHER_ALGORITHM),
        }
    }

    /// Encode to the full message payload (starting with `SSH_MSG_KEXINIT`).
    /// This byte sequence is `I_C` / `I_S` in the exchange hash.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.put_u8(SSH_MSG_KEXINIT);
        w.put_raw(&self.cookie);
        let names = |w: &mut Writer, list: &[String]| {
            let refs: Vec<&str> = list.iter().map(String::as_str).collect();
            w.put_name_list(&refs);
        };
        names(&mut w, &self.kex_algorithms);
        names(&mut w, &self.host_key_algorithms);
        names(&mut w, &self.cipher_c2s);
        names(&mut w, &self.cipher_s2c);
        // MAC c2s/s2c, compression c2s/s2c, languages c2s/s2c.
        w.put_name_list(&[MAC_ALGORITHM]);
        w.put_name_list(&[MAC_ALGORITHM]);
        w.put_name_list(&[COMPRESSION_ALGORITHM]);
        w.put_name_list(&[COMPRESSION_ALGORITHM]);
        w.put_name_list(&[]);
        w.put_name_list(&[]);
        w.put_bool(false); // first_kex_packet_follows
        w.put_u32(0); // reserved
        w.into_bytes()
    }

    /// Parse a KEXINIT message payload.
    ///
    /// # Errors
    /// [`SshError::ShortBuffer`] on truncation, [`SshError::Protocol`] if the
    /// message type byte is not `SSH_MSG_KEXINIT`.
    pub fn parse(payload: &[u8]) -> Result<Self, SshError> {
        let mut r = Reader::new(payload);
        if r.get_u8()? != SSH_MSG_KEXINIT {
            return Err(SshError::Protocol("expected KEXINIT"));
        }
        let cookie: [u8; 16] = r
            .get_bytes(16)?
            .try_into()
            .map_err(|_| SshError::ShortBuffer)?;
        let kex_algorithms = r.get_name_list()?;
        let host_key_algorithms = r.get_name_list()?;
        let cipher_c2s = r.get_name_list()?;
        let cipher_s2c = r.get_name_list()?;
        // Remaining lists (mac, compression, languages) are parsed to validate
        // framing but not retained (the AEAD profile fixes them).
        let _mac_c2s = r.get_name_list()?;
        let _mac_s2c = r.get_name_list()?;
        let _comp_c2s = r.get_name_list()?;
        let _comp_s2c = r.get_name_list()?;
        Ok(Self {
            cookie,
            kex_algorithms,
            host_key_algorithms,
            cipher_c2s,
            cipher_s2c,
        })
    }
}

/// The algorithms chosen by [`negotiate`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Negotiated {
    /// Chosen key-exchange algorithm.
    pub kex: String,
    /// Chosen host-key algorithm.
    pub host_key: String,
    /// Chosen client→server cipher.
    pub cipher_c2s: String,
    /// Chosen server→client cipher.
    pub cipher_s2c: String,
}

/// Pick the client's most-preferred name that the server also offers
/// (client-preference wins, per RFC 4253 §7.1).
fn choose(client: &[String], server: &[String]) -> Option<String> {
    client
        .iter()
        .find(|c| server.iter().any(|s| s == *c))
        .cloned()
}

/// Negotiate algorithms from the client and server KEXINITs.
///
/// # Errors
/// [`SshError::NoCommonAlgorithm`] for the first category with no overlap.
pub fn negotiate(client: &KexInit, server: &KexInit) -> Result<Negotiated, SshError> {
    Ok(Negotiated {
        kex: choose(&client.kex_algorithms, &server.kex_algorithms)
            .ok_or(SshError::NoCommonAlgorithm("kex"))?,
        host_key: choose(&client.host_key_algorithms, &server.host_key_algorithms)
            .ok_or(SshError::NoCommonAlgorithm("host-key"))?,
        cipher_c2s: choose(&client.cipher_c2s, &server.cipher_c2s)
            .ok_or(SshError::NoCommonAlgorithm("cipher c2s"))?,
        cipher_s2c: choose(&client.cipher_s2c, &server.cipher_s2c)
            .ok_or(SshError::NoCommonAlgorithm("cipher s2c"))?,
    })
}

/// Build the `ssh-ed25519` host-key blob `string("ssh-ed25519") ||
/// string(pubkey)`.
#[must_use]
pub fn host_key_blob(ed25519_pubkey: &[u8; 32]) -> Vec<u8> {
    let mut w = Writer::new();
    w.put_string(HOST_KEY_ALGORITHM.as_bytes());
    w.put_string(ed25519_pubkey);
    w.into_bytes()
}

/// Parse an `ssh-ed25519` host-key blob, returning the 32-byte public key.
///
/// # Errors
/// [`SshError::Protocol`] if the algorithm name or key length is wrong.
pub fn parse_host_key_blob(blob: &[u8]) -> Result<[u8; 32], SshError> {
    let mut r = Reader::new(blob);
    if r.get_string()? != HOST_KEY_ALGORITHM.as_bytes() {
        return Err(SshError::Protocol("host-key algorithm"));
    }
    r.get_string()?
        .try_into()
        .map_err(|_| SshError::Protocol("host-key length"))
}

/// Build the `ssh-ed25519` signature blob `string("ssh-ed25519") ||
/// string(sig)`.
#[must_use]
pub fn signature_blob(ed25519_sig: &[u8; 64]) -> Vec<u8> {
    let mut w = Writer::new();
    w.put_string(HOST_KEY_ALGORITHM.as_bytes());
    w.put_string(ed25519_sig);
    w.into_bytes()
}

/// Parse an `ssh-ed25519` signature blob, returning the 64-byte signature.
///
/// # Errors
/// [`SshError::Protocol`] if the algorithm name or signature length is wrong.
pub fn parse_signature_blob(blob: &[u8]) -> Result<[u8; 64], SshError> {
    let mut r = Reader::new(blob);
    if r.get_string()? != HOST_KEY_ALGORITHM.as_bytes() {
        return Err(SshError::Protocol("signature algorithm"));
    }
    r.get_string()?
        .try_into()
        .map_err(|_| SshError::Protocol("signature length"))
}

/// The pieces of the transcript that the exchange hash binds.
pub struct ExchangeHashInput<'a> {
    /// Client identification string (no CR LF).
    pub v_c: &'a [u8],
    /// Server identification string (no CR LF).
    pub v_s: &'a [u8],
    /// Client KEXINIT payload (`I_C`).
    pub i_c: &'a [u8],
    /// Server KEXINIT payload (`I_S`).
    pub i_s: &'a [u8],
    /// Server host-key blob (`K_S`).
    pub k_s: &'a [u8],
    /// Client ephemeral public key (`Q_C`).
    pub q_c: &'a [u8; 32],
    /// Server ephemeral public key (`Q_S`).
    pub q_s: &'a [u8; 32],
    /// Shared secret `K`, as raw 32-byte big-endian.
    pub shared: &'a [u8; 32],
}

/// Compute the exchange hash `H` (RFC 8731 §3.1).
#[must_use]
pub fn exchange_hash(input: &ExchangeHashInput) -> [u8; 32] {
    let mut w = Writer::new();
    w.put_string(input.v_c);
    w.put_string(input.v_s);
    w.put_string(input.i_c);
    w.put_string(input.i_s);
    w.put_string(input.k_s);
    w.put_string(input.q_c);
    w.put_string(input.q_s);
    w.put_mpint(input.shared);
    Sha256H::hash(&w.into_bytes())
}

/// Derive one key `HASH(K || H || X || session_id)` (RFC 4253 §7.2). Since
/// SHA-256 yields exactly 32 bytes, no extension round is needed for a 32-byte
/// AEAD key.
fn derive_key(shared: &[u8; 32], h: &[u8; 32], x: u8, session_id: &[u8; 32]) -> [u8; 32] {
    let mut w = Writer::new();
    w.put_mpint(shared); // K as mpint
    w.put_raw(h);
    w.put_u8(x);
    w.put_raw(session_id);
    Sha256H::hash(&w.into_bytes())
}

/// Derive the two AEAD encryption keys (client→server = 'C', server→client =
/// 'D'). `session_id` equals `H` for the initial key exchange.
#[must_use]
pub fn derive_enc_keys(
    shared: &[u8; 32],
    h: &[u8; 32],
    session_id: &[u8; 32],
) -> ([u8; 32], [u8; 32]) {
    (
        derive_key(shared, h, b'C', session_id),
        derive_key(shared, h, b'D', session_id),
    )
}

/// Generate a random 16-byte KEXINIT cookie (sourced from a fresh ephemeral
/// public key, which `nexacore-crypto` fills from the system RNG).
#[must_use]
pub fn random_cookie() -> [u8; 16] {
    let (_secret, public) = generate_ephemeral();
    let bytes = public.as_bytes();
    let mut cookie = [0u8; 16];
    cookie.copy_from_slice(bytes.get(..16).unwrap_or(&[0u8; 16]));
    cookie
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    #[test]
    fn kexinit_round_trips() {
        let k = KexInit::offer([0x11; 16]);
        let encoded = k.encode();
        assert_eq!(encoded.first(), Some(&SSH_MSG_KEXINIT));
        let parsed = KexInit::parse(&encoded).unwrap();
        assert_eq!(parsed, k);
    }

    #[test]
    fn negotiation_picks_common_algorithms() {
        let client = KexInit::offer([1; 16]);
        let server = KexInit::offer([2; 16]);
        let n = negotiate(&client, &server).unwrap();
        assert_eq!(n.kex, KEX_ALGORITHM);
        assert_eq!(n.host_key, HOST_KEY_ALGORITHM);
        assert_eq!(n.cipher_c2s, CIPHER_ALGORITHM);
    }

    #[test]
    fn negotiation_fails_without_overlap() {
        let client = KexInit::offer([1; 16]);
        let mut server = KexInit::offer([2; 16]);
        server.kex_algorithms = alloc::vec![String::from("diffie-hellman-group14-sha1")];
        assert_eq!(
            negotiate(&client, &server),
            Err(SshError::NoCommonAlgorithm("kex"))
        );
    }

    #[test]
    fn host_key_and_signature_blobs_round_trip() {
        let pk = [0x42u8; 32];
        assert_eq!(parse_host_key_blob(&host_key_blob(&pk)).unwrap(), pk);
        let sig = [0x37u8; 64];
        assert_eq!(parse_signature_blob(&signature_blob(&sig)).unwrap(), sig);
    }

    #[test]
    fn exchange_hash_is_stable_and_order_sensitive() {
        let q_c = [1u8; 32];
        let q_s = [2u8; 32];
        let shared = [3u8; 32];
        let base = ExchangeHashInput {
            v_c: b"SSH-2.0-A",
            v_s: b"SSH-2.0-B",
            i_c: b"ic",
            i_s: b"is",
            k_s: b"ks",
            q_c: &q_c,
            q_s: &q_s,
            shared: &shared,
        };
        let h1 = exchange_hash(&base);
        // Swapping Q_C and Q_S changes the transcript → different hash.
        let swapped = ExchangeHashInput {
            q_c: &q_s,
            q_s: &q_c,
            ..base
        };
        assert_ne!(h1, exchange_hash(&swapped));
    }

    #[test]
    fn enc_keys_differ_per_direction() {
        let shared = [4u8; 32];
        let h = [5u8; 32];
        let (c2s, s2c) = derive_enc_keys(&shared, &h, &h);
        assert_ne!(c2s, s2c);
    }
}
