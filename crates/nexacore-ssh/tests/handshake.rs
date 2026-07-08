//! End-to-end transport handshake over an in-memory byte pipe.
//!
//! Runs a real client and server handshake in two threads, then exchanges
//! encrypted application packets both ways — proving the two peers derive the
//! same exchange hash and session keys and that the AEAD channel round-trips.

#![allow(clippy::unwrap_used)]

use std::{
    collections::VecDeque,
    sync::mpsc::{Receiver, Sender, channel},
    thread,
};

use nexacore_crypto::signing::NexaCoreSigningKey;
use nexacore_ssh::{
    Session, SshError, Transport,
    transport::{client_handshake, server_handshake},
};

/// A byte-stream transport backed by a pair of mpsc channels.
struct ChannelTransport {
    tx: Sender<Vec<u8>>,
    rx: Receiver<Vec<u8>>,
    buf: VecDeque<u8>,
}

impl Transport for ChannelTransport {
    fn write_all(&mut self, data: &[u8]) -> Result<(), SshError> {
        self.tx.send(data.to_vec()).map_err(|_| SshError::Transport)
    }

    fn read_exact(&mut self, out: &mut [u8]) -> Result<(), SshError> {
        while self.buf.len() < out.len() {
            let chunk = self.rx.recv().map_err(|_| SshError::Transport)?;
            self.buf.extend(chunk);
        }
        for slot in out.iter_mut() {
            *slot = self.buf.pop_front().ok_or(SshError::Transport)?;
        }
        Ok(())
    }
}

fn duplex() -> (ChannelTransport, ChannelTransport) {
    let (a_tx, a_rx) = channel();
    let (b_tx, b_rx) = channel();
    (
        ChannelTransport {
            tx: a_tx,
            rx: b_rx,
            buf: VecDeque::new(),
        },
        ChannelTransport {
            tx: b_tx,
            rx: a_rx,
            buf: VecDeque::new(),
        },
    )
}

#[test]
fn full_handshake_and_bidirectional_app_data() {
    let (mut client_t, mut server_t) = duplex();
    let host_key = NexaCoreSigningKey::from_bytes([0x5a; 32]);
    let host_pub = host_key.verifying_key().as_bytes();

    let server = thread::spawn(move || -> (Session, ChannelTransport) {
        let sess = server_handshake(&mut server_t, &host_key).unwrap();
        (sess, server_t)
    });

    let mut client_session = client_handshake(&mut client_t).unwrap();
    let (mut server_session, mut server_t) = server.join().unwrap();

    // Both peers agreed on the same session id, and the client saw the real
    // host key.
    assert_eq!(client_session.session_id(), server_session.session_id());
    assert_eq!(client_session.peer_host_key(), &host_pub);

    // Client → server.
    client_session
        .send(&mut client_t, b"run: uname -a")
        .unwrap();
    assert_eq!(
        server_session.recv(&mut server_t).unwrap(),
        b"run: uname -a"
    );

    // Server → client.
    server_session
        .send(&mut server_t, b"Linux nexacore")
        .unwrap();
    assert_eq!(
        client_session.recv(&mut client_t).unwrap(),
        b"Linux nexacore"
    );

    // A second round advances the sequence numbers on both directions.
    client_session.send(&mut client_t, b"exit").unwrap();
    assert_eq!(server_session.recv(&mut server_t).unwrap(), b"exit");
}

#[test]
fn client_learns_server_host_key_for_known_hosts() {
    // The client's Session must expose the server's real Ed25519 host key so a
    // caller can check it against known_hosts. (The signature-rejection path is
    // covered by the exchange-hash and packet-tamper unit tests.)
    let (mut client_t, mut server_t) = duplex();

    let server = thread::spawn(move || {
        let host_key = NexaCoreSigningKey::from_bytes([0x11; 32]);
        let _ = server_handshake(&mut server_t, &host_key);
    });

    let session = client_handshake(&mut client_t).unwrap();
    server.join().unwrap();
    assert_eq!(
        session.peer_host_key(),
        &NexaCoreSigningKey::from_bytes([0x11; 32])
            .verifying_key()
            .as_bytes()
    );
}
