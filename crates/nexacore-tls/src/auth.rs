//! Handshake authentication helpers: the `CertificateVerify` signed content
//! and the server's credential bundle.
//!
//! RFC 8446 § 4.4.3 defines the bytes covered by a `CertificateVerify`
//! signature as 64 `0x20` octets, a context string, a single `0x00`, and the
//! transcript hash through the `Certificate` message. Binding the transcript
//! this way makes the signature cover the whole negotiation, not just a bare
//! nonce, defeating transcript-substitution attacks.

use alloc::vec::Vec;

use nexacore_crypto::{hash::HASH_LEN, signing::NexaCoreSigningKey};

/// Context string for a server-sent `CertificateVerify`.
pub const SERVER_CONTEXT: &[u8] = b"TLS 1.3, server CertificateVerify";

/// Context string for a client-sent `CertificateVerify` (client auth).
pub const CLIENT_CONTEXT: &[u8] = b"TLS 1.3, client CertificateVerify";

/// Build the exact byte string a `CertificateVerify` signs.
///
/// `is_server` selects the context string. `transcript_hash` is the SHA-256
/// transcript hash through the `Certificate` message.
#[must_use]
pub fn certificate_verify_content(is_server: bool, transcript_hash: &[u8; HASH_LEN]) -> Vec<u8> {
    let context = if is_server {
        SERVER_CONTEXT
    } else {
        CLIENT_CONTEXT
    };
    let mut out = Vec::with_capacity(64 + context.len() + 1 + HASH_LEN);
    out.extend(core::iter::repeat_n(0x20u8, 64));
    out.extend_from_slice(context);
    out.push(0x00);
    out.extend_from_slice(transcript_hash);
    out
}

/// A server's authentication material: its certificate chain (leaf first) and
/// the `ed25519` private key matching the leaf's public key. The private key
/// signs the `CertificateVerify`.
pub struct ServerCredentials {
    /// The leaf private key.
    pub signing_key: NexaCoreSigningKey,
    /// The certificate chain, leaf first, in the wire format understood by the
    /// configured [`crate::certstore::CertVerifier`].
    pub chain: Vec<Vec<u8>>,
}

impl core::fmt::Debug for ServerCredentials {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ServerCredentials")
            .field("chain_len", &self.chain.len())
            .finish_non_exhaustive()
    }
}
