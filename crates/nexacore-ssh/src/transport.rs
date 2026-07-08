//! The SSH-2 transport handshake and the resulting encrypted session.
//!
//! [`client_handshake`] and [`server_handshake`] drive the full transport
//! setup over a [`Transport`] byte stream: identification-string exchange,
//! KEXINIT, curve25519-sha256 ECDH (`KEX_ECDH_INIT` / `KEX_ECDH_REPLY`),
//! host-key signature verification of the exchange hash, and `NEWKEYS`. Each
//! returns a [`Session`] whose [`Session::send`] / [`Session::recv`] carry
//! application payloads over the AEAD packet channel.
#![allow(
    // The SSH transcript variables are canonically named in mirrored pairs
    // (V_C/V_S, I_C/I_S, Q_C/Q_S, secret_c/secret_s); keeping those names is
    // clearer than renaming to satisfy the similarity heuristic.
    clippy::similar_names
)]

use alloc::vec::Vec;

use nexacore_crypto::{
    kex::{NexaCorePublicKey, generate_ephemeral},
    signing::{NexaCoreSignature, NexaCoreSigningKey, NexaCoreVerifyingKey},
};

use crate::{
    error::SshError,
    kex::{
        ExchangeHashInput, KexInit, derive_enc_keys, exchange_hash, host_key_blob, negotiate,
        parse_host_key_blob, parse_signature_blob, random_cookie, signature_blob,
    },
    packet::{
        OpeningKey, SSH_MSG_KEX_ECDH_INIT, SSH_MSG_KEX_ECDH_REPLY, SSH_MSG_NEWKEYS, SealingKey,
        encode_record, parse_record,
    },
    wire::{Reader, Writer},
};

/// This implementation's identification string (without the trailing CR LF).
pub const IDENTIFICATION: &[u8] = b"SSH-2.0-NexaCore_0.2";

/// Guard against an unbounded identification line from a hostile peer.
const MAX_IDENT_LEN: usize = 255;

/// A bidirectional byte stream the handshake and session read and write.
pub trait Transport {
    /// Write all of `data`.
    ///
    /// # Errors
    /// [`SshError::Transport`] on I/O failure.
    fn write_all(&mut self, data: &[u8]) -> Result<(), SshError>;

    /// Fill `buf` completely.
    ///
    /// # Errors
    /// [`SshError::Transport`] on I/O failure or early EOF.
    fn read_exact(&mut self, buf: &mut [u8]) -> Result<(), SshError>;
}

/// An established, encrypted SSH transport session.
pub struct Session {
    seal: SealingKey,
    open: OpeningKey,
    id: [u8; 32],
    peer_host_key: [u8; 32],
}

impl Session {
    /// The session identifier (`H` from the initial key exchange), used to bind
    /// later authentication signatures.
    #[must_use]
    pub fn session_id(&self) -> &[u8; 32] {
        &self.id
    }

    /// The peer's `ssh-ed25519` public host key (for `known_hosts` checking by
    /// the caller).
    #[must_use]
    pub fn peer_host_key(&self) -> &[u8; 32] {
        &self.peer_host_key
    }

    /// Encrypt and send `payload` as one packet.
    ///
    /// # Errors
    /// [`SshError::Transport`] on I/O failure, [`SshError::Decrypt`] on an AEAD
    /// failure.
    pub fn send<T: Transport>(&mut self, t: &mut T, payload: &[u8]) -> Result<(), SshError> {
        let wire = self.seal.seal_packet(payload)?;
        t.write_all(&wire)
    }

    /// Receive and decrypt one packet's payload.
    ///
    /// # Errors
    /// [`SshError::Transport`] on I/O failure, [`SshError::Decrypt`] on a bad
    /// tag / tampering.
    pub fn recv<T: Transport>(&mut self, t: &mut T) -> Result<Vec<u8>, SshError> {
        let mut prefix = [0u8; 4];
        t.read_exact(&mut prefix)?;
        let mut body = alloc::vec![0u8; OpeningKey::ciphertext_len(prefix)];
        t.read_exact(&mut body)?;
        self.open.open_packet(prefix, &body)
    }
}

// ---- framing helpers --------------------------------------------------------

fn write_line<T: Transport>(t: &mut T, line: &[u8]) -> Result<(), SshError> {
    t.write_all(line)?;
    t.write_all(b"\r\n")
}

fn read_line<T: Transport>(t: &mut T) -> Result<Vec<u8>, SshError> {
    let mut line = Vec::new();
    loop {
        let mut b = [0u8; 1];
        t.read_exact(&mut b)?;
        if b[0] == b'\n' {
            if line.last() == Some(&b'\r') {
                line.pop();
            }
            return Ok(line);
        }
        if line.len() >= MAX_IDENT_LEN {
            return Err(SshError::BadIdentification);
        }
        line.push(b[0]);
    }
}

fn write_record<T: Transport>(t: &mut T, payload: &[u8]) -> Result<(), SshError> {
    t.write_all(&encode_record(payload))
}

fn read_record<T: Transport>(t: &mut T) -> Result<Vec<u8>, SshError> {
    let mut len_bytes = [0u8; 4];
    t.read_exact(&mut len_bytes)?;
    let packet_length = u32::from_be_bytes(len_bytes) as usize;
    let mut body = alloc::vec![0u8; packet_length];
    t.read_exact(&mut body)?;
    // Reassemble the full record for the shared parser.
    let mut record = Vec::with_capacity(4 + packet_length);
    record.extend_from_slice(&len_bytes);
    record.extend_from_slice(&body);
    parse_record(&record)
}

/// Perform the client side of the transport handshake.
///
/// # Errors
/// Any [`SshError`] from I/O, negotiation, or signature verification.
pub fn client_handshake<T: Transport>(t: &mut T) -> Result<Session, SshError> {
    // 1. Identification strings.
    write_line(t, IDENTIFICATION)?;
    let v_s = read_line(t)?;
    if !v_s.starts_with(b"SSH-2.0-") {
        return Err(SshError::BadIdentification);
    }
    let v_c = IDENTIFICATION.to_vec();

    // 2. KEXINIT exchange.
    let client_kex = KexInit::offer(random_cookie());
    let i_c = client_kex.encode();
    write_record(t, &i_c)?;
    let i_s = read_record(t)?;
    let server_kex = KexInit::parse(&i_s)?;
    let _negotiated = negotiate(&client_kex, &server_kex)?;

    // 3. ECDH init.
    let (secret_c, q_c) = generate_ephemeral();
    let q_c_bytes = q_c.as_bytes();
    let mut w = Writer::new();
    w.put_u8(SSH_MSG_KEX_ECDH_INIT);
    w.put_string(&q_c_bytes);
    write_record(t, &w.into_bytes())?;

    // 4. ECDH reply.
    let reply = read_record(t)?;
    let mut r = Reader::new(&reply);
    if r.get_u8()? != SSH_MSG_KEX_ECDH_REPLY {
        return Err(SshError::Protocol("expected KEX_ECDH_REPLY"));
    }
    let k_s = r.get_string()?.to_vec();
    let q_s_bytes: [u8; 32] = r
        .get_string()?
        .try_into()
        .map_err(|_| SshError::Protocol("Q_S len"))?;
    let sig_blob = r.get_string()?;

    let peer_host_key = parse_host_key_blob(&k_s)?;
    let q_s = NexaCorePublicKey::from_bytes(q_s_bytes);
    let shared = *secret_c.diffie_hellman(&q_s).as_bytes();

    // 5. Exchange hash + host-key signature verification.
    let h = exchange_hash(&ExchangeHashInput {
        v_c: &v_c,
        v_s: &v_s,
        i_c: &i_c,
        i_s: &i_s,
        k_s: &k_s,
        q_c: &q_c_bytes,
        q_s: &q_s_bytes,
        shared: &shared,
    });
    let sig = parse_signature_blob(sig_blob)?;
    let verifying =
        NexaCoreVerifyingKey::from_bytes(&peer_host_key).map_err(|_| SshError::BadSignature)?;
    verifying
        .verify(&h, &NexaCoreSignature::from_bytes(sig))
        .map_err(|_| SshError::BadSignature)?;

    // 6. NEWKEYS.
    write_record(t, &[SSH_MSG_NEWKEYS])?;
    expect_newkeys(t)?;

    // 7. Keys: the client seals with C→S and opens with S→C.
    let (c2s, s2c) = derive_enc_keys(&shared, &h, &h);
    Ok(Session {
        seal: SealingKey::new(c2s),
        open: OpeningKey::new(s2c),
        id: h,
        peer_host_key,
    })
}

/// Perform the server side of the transport handshake, authenticating with the
/// Ed25519 `host_key`.
///
/// # Errors
/// Any [`SshError`] from I/O or negotiation.
pub fn server_handshake<T: Transport>(
    t: &mut T,
    host_key: &NexaCoreSigningKey,
) -> Result<Session, SshError> {
    // 1. Identification strings.
    let v_c = read_line(t)?;
    if !v_c.starts_with(b"SSH-2.0-") {
        return Err(SshError::BadIdentification);
    }
    write_line(t, IDENTIFICATION)?;
    let v_s = IDENTIFICATION.to_vec();

    // 2. KEXINIT exchange.
    let i_c = read_record(t)?;
    let client_kex = KexInit::parse(&i_c)?;
    let server_kex = KexInit::offer(random_cookie());
    let i_s = server_kex.encode();
    write_record(t, &i_s)?;
    let _negotiated = negotiate(&client_kex, &server_kex)?;

    // 3. ECDH init from the client.
    let init = read_record(t)?;
    let mut r = Reader::new(&init);
    if r.get_u8()? != SSH_MSG_KEX_ECDH_INIT {
        return Err(SshError::Protocol("expected KEX_ECDH_INIT"));
    }
    let q_c_bytes: [u8; 32] = r
        .get_string()?
        .try_into()
        .map_err(|_| SshError::Protocol("Q_C len"))?;

    // 4. Server ephemeral + shared secret + host key blob.
    let (secret_s, q_s) = generate_ephemeral();
    let q_s_bytes = q_s.as_bytes();
    let q_c = NexaCorePublicKey::from_bytes(q_c_bytes);
    let shared = *secret_s.diffie_hellman(&q_c).as_bytes();
    let host_pub = host_key.verifying_key().as_bytes();
    let k_s = host_key_blob(&host_pub);

    // 5. Exchange hash + signature.
    let h = exchange_hash(&ExchangeHashInput {
        v_c: &v_c,
        v_s: &v_s,
        i_c: &i_c,
        i_s: &i_s,
        k_s: &k_s,
        q_c: &q_c_bytes,
        q_s: &q_s_bytes,
        shared: &shared,
    });
    let sig = host_key.sign(&h).to_bytes();

    let mut w = Writer::new();
    w.put_u8(SSH_MSG_KEX_ECDH_REPLY);
    w.put_string(&k_s);
    w.put_string(&q_s_bytes);
    w.put_string(&signature_blob(&sig));
    write_record(t, &w.into_bytes())?;

    // 6. NEWKEYS.
    write_record(t, &[SSH_MSG_NEWKEYS])?;
    expect_newkeys(t)?;

    // 7. Keys: the server seals with S→C and opens with C→S.
    let (c2s, s2c) = derive_enc_keys(&shared, &h, &h);
    Ok(Session {
        seal: SealingKey::new(s2c),
        open: OpeningKey::new(c2s),
        id: h,
        peer_host_key: host_pub,
    })
}

fn expect_newkeys<T: Transport>(t: &mut T) -> Result<(), SshError> {
    let msg = read_record(t)?;
    if msg.first() == Some(&SSH_MSG_NEWKEYS) {
        Ok(())
    } else {
        Err(SshError::Protocol("expected NEWKEYS"))
    }
}
