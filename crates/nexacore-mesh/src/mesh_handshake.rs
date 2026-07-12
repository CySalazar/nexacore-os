//! Noise handshake substrate for the mesh transport (WS6-03.2).
//!
//! The mesh peer-to-peer channel is built on the Noise Protocol Framework: this
//! module wires the [`NOISE_PATTERN`] (`Noise_IK_25519_ChaChaPoly_BLAKE2s`, per
//! `docs/03-mesh-protocol.md` and `docs/protocol/handshake.md`) using the vetted
//! [`snow`] implementation, and exposes a thin, host-testable [`MeshHandshake`]
//! that drives the handshake to completion and yields a [`MeshTransport`] for the
//! post-handshake AEAD channel.
//!
//! `Noise_IK` gives mutual authentication in two messages: the initiator already
//! knows the responder's static public key (learned via discovery), transmits
//! its own static key immediately, and both sides authenticate each other. The
//! X25519 static/ephemeral keys here are the transport-security layer only; the
//! NexaCore handshake layer (m1/m2/m3 — ED25519 transcript signatures, TEE
//! attestation, version and measurement binding, WS6-03.3–.7) is layered on top.
//!
//! No cryptography is implemented here — this is wiring over `snow`. The mesh
//! handshake remains subject to the WS10-03 crypto review before production.

use std::vec::Vec;

/// The Noise handshake pattern the mesh uses (spec: `docs/protocol/handshake.md`).
pub const NOISE_PATTERN: &str = "Noise_IK_25519_ChaChaPoly_BLAKE2s";

/// The largest Noise message this module buffers (Noise messages are ≤ 65535 B).
const MAX_NOISE_MESSAGE: usize = 65535;

/// An error from the Noise handshake or transport layer (WS6-03.2).
#[derive(Debug)]
pub enum HandshakeError {
    /// The underlying Noise operation failed (bad key, decrypt failure, …).
    Noise(snow::Error),
    /// The [`NOISE_PATTERN`] string could not be parsed (a build-time invariant
    /// failure — should never happen with the constant pattern).
    BadPattern,
    /// A transport was requested before the handshake finished.
    HandshakeNotFinished,
}

impl core::fmt::Display for HandshakeError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Noise(e) => write!(f, "noise error: {e}"),
            Self::BadPattern => write!(f, "invalid noise pattern"),
            Self::HandshakeNotFinished => write!(f, "handshake not finished"),
        }
    }
}

impl std::error::Error for HandshakeError {}

impl From<snow::Error> for HandshakeError {
    fn from(e: snow::Error) -> Self {
        Self::Noise(e)
    }
}

/// Parse the [`NOISE_PATTERN`] into `snow` params.
fn noise_params() -> Result<snow::params::NoiseParams, HandshakeError> {
    NOISE_PATTERN
        .parse()
        .map_err(|_| HandshakeError::BadPattern)
}

/// Generate an X25519 static keypair for a mesh node, returned as
/// `(private, public)` raw 32-byte keys (WS6-03.2).
///
/// # Errors
///
/// Returns [`HandshakeError`] if the crypto backend cannot produce a keypair.
pub fn generate_static_keypair() -> Result<(Vec<u8>, Vec<u8>), HandshakeError> {
    let keypair = snow::Builder::new(noise_params()?).generate_keypair()?;
    Ok((keypair.private, keypair.public))
}

/// One side of the Noise handshake (WS6-03.2).
pub struct MeshHandshake {
    inner: snow::HandshakeState,
}

impl MeshHandshake {
    /// The initiator: knows its own static key and the responder's static public
    /// key (the `IK` precondition, learned via discovery).
    ///
    /// # Errors
    ///
    /// Returns [`HandshakeError`] on an invalid key or builder failure.
    pub fn initiator(
        local_static_private: &[u8],
        remote_static_public: &[u8],
    ) -> Result<Self, HandshakeError> {
        let inner = snow::Builder::new(noise_params()?)
            .local_private_key(local_static_private)
            .remote_public_key(remote_static_public)
            .build_initiator()?;
        Ok(Self { inner })
    }

    /// The responder: knows only its own static key.
    ///
    /// # Errors
    ///
    /// Returns [`HandshakeError`] on an invalid key or builder failure.
    pub fn responder(local_static_private: &[u8]) -> Result<Self, HandshakeError> {
        let inner = snow::Builder::new(noise_params()?)
            .local_private_key(local_static_private)
            .build_responder()?;
        Ok(Self { inner })
    }

    /// Write the next handshake message carrying `payload`, returning the wire
    /// bytes to send to the peer.
    ///
    /// # Errors
    ///
    /// Returns [`HandshakeError`] if the Noise state cannot produce the message.
    pub fn write_message(&mut self, payload: &[u8]) -> Result<Vec<u8>, HandshakeError> {
        let mut buf = vec![0u8; MAX_NOISE_MESSAGE];
        let len = self.inner.write_message(payload, &mut buf)?;
        buf.truncate(len);
        Ok(buf)
    }

    /// Read a handshake message from the peer, returning its decrypted payload.
    ///
    /// # Errors
    ///
    /// Returns [`HandshakeError`] if the message fails to authenticate/decrypt.
    pub fn read_message(&mut self, message: &[u8]) -> Result<Vec<u8>, HandshakeError> {
        let mut buf = vec![0u8; MAX_NOISE_MESSAGE];
        let len = self.inner.read_message(message, &mut buf)?;
        buf.truncate(len);
        Ok(buf)
    }

    /// Whether the handshake has completed.
    #[must_use]
    pub fn is_finished(&self) -> bool {
        self.inner.is_handshake_finished()
    }

    /// The peer's authenticated static public key, once known.
    #[must_use]
    pub fn remote_static(&self) -> Option<Vec<u8>> {
        self.inner.get_remote_static().map(<[u8]>::to_vec)
    }

    /// Consume the finished handshake and move to the transport (AEAD) phase.
    ///
    /// # Errors
    ///
    /// Returns [`HandshakeError::HandshakeNotFinished`] if called before the
    /// handshake completed, or a Noise error otherwise.
    pub fn into_transport(self) -> Result<MeshTransport, HandshakeError> {
        if !self.inner.is_handshake_finished() {
            return Err(HandshakeError::HandshakeNotFinished);
        }
        let inner = self.inner.into_transport_mode()?;
        Ok(MeshTransport { inner })
    }
}

/// The post-handshake transport channel: authenticated encryption both ways
/// (WS6-03.2).
pub struct MeshTransport {
    inner: snow::TransportState,
}

impl MeshTransport {
    /// Encrypt `plaintext` for the peer.
    ///
    /// # Errors
    ///
    /// Returns [`HandshakeError`] if the Noise transport cannot encrypt.
    pub fn encrypt(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, HandshakeError> {
        // Ciphertext is plaintext + 16-byte AEAD tag.
        let mut buf = vec![0u8; plaintext.len() + 16];
        let len = self.inner.write_message(plaintext, &mut buf)?;
        buf.truncate(len);
        Ok(buf)
    }

    /// Decrypt a `ciphertext` from the peer.
    ///
    /// # Errors
    ///
    /// Returns [`HandshakeError`] if authentication/decryption fails.
    pub fn decrypt(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>, HandshakeError> {
        let mut buf = vec![0u8; MAX_NOISE_MESSAGE];
        let len = self.inner.read_message(ciphertext, &mut buf)?;
        buf.truncate(len);
        Ok(buf)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Both ends of an established mesh channel.
    struct Channel {
        initiator: MeshTransport,
        responder: MeshTransport,
    }

    /// Drive a full IK handshake between a fresh initiator and responder,
    /// asserting each side authenticated the other's real static key.
    fn establish() -> Result<Channel, HandshakeError> {
        let (i_priv, i_pub) = generate_static_keypair()?;
        let (r_priv, r_pub) = generate_static_keypair()?;

        let mut initiator = MeshHandshake::initiator(&i_priv, &r_pub)?;
        let mut responder = MeshHandshake::responder(&r_priv)?;

        // IK: -> e, es, s, ss   then   <- e, ee, se
        let m1 = initiator.write_message(&[])?;
        responder.read_message(&m1)?;
        let m2 = responder.write_message(&[])?;
        initiator.read_message(&m2)?;

        // Each side must have authenticated the other's real static key.
        assert_eq!(responder.remote_static().as_deref(), Some(i_pub.as_slice()));
        assert_eq!(initiator.remote_static().as_deref(), Some(r_pub.as_slice()));

        Ok(Channel {
            initiator: initiator.into_transport()?,
            responder: responder.into_transport()?,
        })
    }

    #[test]
    fn ik_handshake_completes_and_transport_roundtrips_both_ways() {
        let outcome = establish();
        assert!(outcome.is_ok(), "handshake failed to establish");
        if let Ok(Channel {
            initiator: mut init_tx,
            responder: mut resp_tx,
        }) = outcome
        {
            // Initiator → responder.
            let res = init_tx.encrypt(b"ping").and_then(|ct| resp_tx.decrypt(&ct));
            assert!(matches!(res.as_deref(), Ok(b"ping")));
            // Responder → initiator.
            let res = resp_tx.encrypt(b"pong").and_then(|ct| init_tx.decrypt(&ct));
            assert!(matches!(res.as_deref(), Ok(b"pong")));
        }
    }

    #[test]
    fn wrong_responder_key_fails_the_handshake() {
        // The initiator points at the WRONG responder static key: IK binds the
        // responder's static into the first message, so the real responder
        // cannot decrypt it and the handshake fails (no silent success).
        let result: Result<(), HandshakeError> = (|| {
            let (i_priv, _) = generate_static_keypair()?;
            let (r_priv, _) = generate_static_keypair()?;
            let (_, wrong_pub) = generate_static_keypair()?;
            let mut initiator = MeshHandshake::initiator(&i_priv, &wrong_pub)?;
            let mut responder = MeshHandshake::responder(&r_priv)?;
            let m1 = initiator.write_message(&[])?;
            responder.read_message(&m1)?; // must fail to authenticate
            Ok(())
        })();
        assert!(
            result.is_err(),
            "handshake with wrong responder key must fail"
        );
    }

    #[test]
    fn into_transport_before_finish_is_rejected() {
        let result: Result<(), HandshakeError> = (|| {
            let (i_priv, _) = generate_static_keypair()?;
            let (_, r_pub) = generate_static_keypair()?;
            let initiator = MeshHandshake::initiator(&i_priv, &r_pub)?;
            // No messages exchanged → not finished.
            assert!(!initiator.is_finished());
            match initiator.into_transport() {
                Err(HandshakeError::HandshakeNotFinished) => Ok(()),
                Ok(_) => Err(HandshakeError::HandshakeNotFinished), // wrong: it should reject
                Err(e) => Err(e),
            }
        })();
        assert!(
            result.is_ok(),
            "premature into_transport must be rejected cleanly"
        );
    }

    #[test]
    fn pattern_is_the_spec_ik_suite() {
        assert_eq!(NOISE_PATTERN, "Noise_IK_25519_ChaChaPoly_BLAKE2s");
        assert!(noise_params().is_ok());
    }
}
