//! Channel multiplexing driven over two real encrypted `Session`s.
//!
//! Runs a full transport handshake between a client and server thread, then
//! moves `ChannelTable`-produced payloads across the encrypted `Session::send`
//! / `Session::recv` seam: opening a channel, exchanging data larger than the
//! peer's max packet, and multiplexing a second channel independently.

#![allow(clippy::unwrap_used)]

use std::{
    collections::VecDeque,
    sync::mpsc::{Receiver, Sender, channel},
    thread,
};

use nexacore_crypto::signing::NexaCoreSigningKey;
use nexacore_ssh::{
    ChannelTable, Session, SshError, Transport,
    channel::{SSH_MSG_CHANNEL_DATA, SSH_MSG_CHANNEL_OPEN},
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

/// Establish two connected, encrypted sessions plus their transports.
fn connected() -> (Session, ChannelTransport, Session, ChannelTransport) {
    let (mut client_t, mut server_t) = duplex();
    let host_key = NexaCoreSigningKey::from_bytes([0x5a; 32]);
    let server = thread::spawn(move || -> (Session, ChannelTransport) {
        let sess = server_handshake(&mut server_t, &host_key).unwrap();
        (sess, server_t)
    });
    let client_session = client_handshake(&mut client_t).unwrap();
    let (server_session, server_t) = server.join().unwrap();
    (client_session, client_t, server_session, server_t)
}

#[test]
fn channel_open_and_chunked_data_over_encrypted_session() {
    let (mut c_sess, mut c_t, mut s_sess, mut s_t) = connected();
    let mut client = ChannelTable::new();
    let mut server = ChannelTable::new();

    // Client opens a channel; the OPEN travels over the encrypted session.
    let (c_id, open_msg) = client.open("session", 64, 1024);
    c_sess.send(&mut c_t, &open_msg).unwrap();

    // Server accepts with a deliberately tiny max packet and replies.
    let open_in = s_sess.recv(&mut s_t).unwrap();
    assert_eq!(open_in.first(), Some(&SSH_MSG_CHANNEL_OPEN));
    let (s_id, conf_msg) = server.accept(&open_in, 64, 4).unwrap();
    s_sess.send(&mut s_t, &conf_msg).unwrap();
    let confirmed = client
        .on_open_confirmation(&c_sess.recv(&mut c_t).unwrap())
        .unwrap();
    assert_eq!(confirmed, c_id);

    // Client sends 10 bytes; the tiny max packet forces three CHANNEL_DATA
    // messages across the wire.
    let payload = b"payload-10";
    let msgs = client.data(c_id, payload).unwrap();
    assert_eq!(msgs.len(), 3);
    for m in &msgs {
        c_sess.send(&mut c_t, m).unwrap();
    }

    let mut reassembled = Vec::new();
    for _ in 0..msgs.len() {
        let wire = s_sess.recv(&mut s_t).unwrap();
        assert_eq!(wire.first(), Some(&SSH_MSG_CHANNEL_DATA));
        let (got, part) = server.on_data(&wire).unwrap();
        assert_eq!(got, s_id);
        reassembled.extend_from_slice(&part);
    }
    assert_eq!(reassembled, payload);
    assert_eq!(client.send_window(c_id), Some(54));

    // Teardown: EOF + CLOSE both ways over the session.
    let eof = client.eof(c_id).unwrap();
    c_sess.send(&mut c_t, &eof).unwrap();
    server.on_eof(&s_sess.recv(&mut s_t).unwrap()).unwrap();

    let close = client.close(c_id).unwrap();
    c_sess.send(&mut c_t, &close).unwrap();
    server.on_close(&s_sess.recv(&mut s_t).unwrap()).unwrap();
    let close_back = server.close(s_id).unwrap();
    s_sess.send(&mut s_t, &close_back).unwrap();
    client.on_close(&c_sess.recv(&mut c_t).unwrap()).unwrap();

    assert!(!client.is_open(c_id));
    assert!(!server.is_open(s_id));
}

#[test]
fn two_channels_multiplex_independently_over_one_session() {
    let (mut c_sess, mut c_t, mut s_sess, mut s_t) = connected();
    let mut client = ChannelTable::new();
    let mut server = ChannelTable::new();

    // Open two channels over the single encrypted session.
    let (c1, open1) = client.open("session", 40, 1024);
    let (c2, open2) = client.open("session", 40, 1024);
    c_sess.send(&mut c_t, &open1).unwrap();
    c_sess.send(&mut c_t, &open2).unwrap();

    let (s1, conf1) = server
        .accept(&s_sess.recv(&mut s_t).unwrap(), 40, 1024)
        .unwrap();
    let (s2, conf2) = server
        .accept(&s_sess.recv(&mut s_t).unwrap(), 40, 1024)
        .unwrap();
    s_sess.send(&mut s_t, &conf1).unwrap();
    s_sess.send(&mut s_t, &conf2).unwrap();
    client
        .on_open_confirmation(&c_sess.recv(&mut c_t).unwrap())
        .unwrap();
    client
        .on_open_confirmation(&c_sess.recv(&mut c_t).unwrap())
        .unwrap();

    // Data on channel 1 only.
    for m in client.data(c1, b"one").unwrap() {
        c_sess.send(&mut c_t, &m).unwrap();
    }
    let (got, data) = server.on_data(&s_sess.recv(&mut s_t).unwrap()).unwrap();
    assert_eq!(got, s1);
    assert_eq!(data, b"one");

    // Channel 2's windows are untouched by channel 1's traffic.
    assert_eq!(client.send_window(c1), Some(37));
    assert_eq!(client.send_window(c2), Some(40));
    assert_eq!(server.recv_window(s1), Some(37));
    assert_eq!(server.recv_window(s2), Some(40));
    let _ = (c2, s2);
}
