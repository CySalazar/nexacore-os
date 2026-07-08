//! End-to-end TLS 1.3 handshake tests.
//!
//! A NexaCore client and server complete a full `TLS_CHACHA20_POLY1305_SHA256`
//! / `x25519` / `ed25519` handshake in-process: `ClientHello`, `ServerHello`,
//! the server's encrypted flight (with a real `ed25519` `CertificateVerify`
//! over the transcript and a certificate that chains to the client's trust
//! anchor), the client `Finished`, and bidirectional application data — plus
//! the negative paths (tampering, wrong name, untrusted anchor, ALPN mismatch).

#![allow(
    clippy::unwrap_used,
    clippy::similar_names,
    clippy::missing_panics_doc,
    clippy::indexing_slicing
)]

use nexacore_crypto::signing::NexaCoreSigningKey;
use nexacore_tls::{
    auth::ServerCredentials,
    certstore::{CertStore, NexaCertTbs, NexaCertVerifier, encode_nexacert},
    client::{ClientConfig, ClientConnection},
    error::TlsError,
    server::{ServerConfig, ServerConnection},
};

const ROOT_NAME: &[u8] = b"NexaCore Root CA";
const LEAF_NAME: &[u8] = b"server.nexacore.lan";

fn issue(
    subject_name: &[u8],
    subject_spki: [u8; 32],
    issuer_name: &[u8],
    issuer_key: &NexaCoreSigningKey,
    not_before: u64,
    not_after: u64,
    is_ca: bool,
) -> Vec<u8> {
    let tbs = NexaCertTbs {
        subject: subject_name.to_vec(),
        issuer: issuer_name.to_vec(),
        subject_spki,
        not_before,
        not_after,
        is_ca,
        path_len: 0,
    }
    .encode()
    .unwrap();
    let sig = issuer_key.sign(&tbs).to_bytes();
    encode_nexacert(&tbs, &sig).unwrap()
}

/// Build a server credential (leaf cert + private key) and the matching client
/// trust store.
fn pki() -> (ServerCredentials, CertStore) {
    let root = NexaCoreSigningKey::from_bytes([1u8; 32]);
    let leaf = NexaCoreSigningKey::from_bytes([2u8; 32]);
    let leaf_spki = leaf.verifying_key().as_bytes();
    let leaf_cert = issue(LEAF_NAME, leaf_spki, ROOT_NAME, &root, 0, 1_000_000, false);

    let creds = ServerCredentials {
        signing_key: leaf,
        chain: vec![leaf_cert],
    };
    let mut store = CertStore::new();
    store.add_anchor(ROOT_NAME.to_vec(), root.verifying_key().as_bytes());
    (creds, store)
}

fn client_config(store: CertStore, name: Option<&[u8]>, alpn: &[&[u8]]) -> ClientConfig {
    ClientConfig {
        server_name: name.map(<[u8]>::to_vec),
        alpn: alpn.iter().map(|p| p.to_vec()).collect(),
        store,
        now: 500,
    }
}

fn server_config(creds: ServerCredentials, alpn: &[&[u8]]) -> ServerConfig {
    ServerConfig {
        credentials: creds,
        alpn: alpn.iter().map(|p| p.to_vec()).collect(),
    }
}

#[test]
fn full_handshake_negotiates_and_carries_application_data() {
    let (creds, store) = pki();
    let cfg = client_config(store, Some(LEAF_NAME), &[b"h2", b"http/1.1"]);
    let (mut client, client_hello) = ClientConnection::start(cfg, NexaCertVerifier).unwrap();

    let mut server = ServerConnection::new(server_config(creds, &[b"http/1.1"]));
    let (server_hello, flight) = server.accept(&client_hello).unwrap();
    let client_finished = client.process_flight(&server_hello, &flight).unwrap();
    server.finish(&client_finished).unwrap();

    assert!(client.is_complete());
    assert!(server.is_complete());

    // Server preference wins: http/1.1 chosen even though the client listed h2
    // first.
    assert_eq!(client.alpn_protocol(), Some(b"http/1.1".as_slice()));
    assert_eq!(server.alpn_protocol(), Some(b"http/1.1".as_slice()));

    // Application data, both directions, under the application traffic keys.
    let req = b"GET / HTTP/1.1\r\nHost: server.nexacore.lan\r\n\r\n";
    let rec = client.seal_application(req).unwrap();
    assert_eq!(server.open_application(&rec).unwrap(), req);

    let resp = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nhi";
    let rec = server.seal_application(resp).unwrap();
    assert_eq!(client.open_application(&rec).unwrap(), resp);

    // A second record in each direction (sequence numbers advance).
    let rec = client.seal_application(b"ping").unwrap();
    assert_eq!(server.open_application(&rec).unwrap(), b"ping");
}

#[test]
fn tampered_server_flight_breaks_the_handshake() {
    let (creds, store) = pki();
    let cfg = client_config(store, Some(LEAF_NAME), &[]);
    let (mut client, client_hello) = ClientConnection::start(cfg, NexaCertVerifier).unwrap();
    let mut server = ServerConnection::new(server_config(creds, &[]));
    let (server_hello, mut flight) = server.accept(&client_hello).unwrap();

    // Flip a ciphertext byte in the encrypted flight.
    let last = flight.len() - 1;
    flight[last] ^= 0x01;
    let err = client.process_flight(&server_hello, &flight).unwrap_err();
    assert_eq!(err, TlsError::DecryptFailed);
}

#[test]
fn wrong_server_name_is_rejected_by_the_client() {
    let (creds, store) = pki();
    // Client expects a different host than the leaf certifies.
    let cfg = client_config(store, Some(b"attacker.example"), &[]);
    let (mut client, client_hello) = ClientConnection::start(cfg, NexaCertVerifier).unwrap();
    let mut server = ServerConnection::new(server_config(creds, &[]));
    let (server_hello, flight) = server.accept(&client_hello).unwrap();
    let err = client.process_flight(&server_hello, &flight).unwrap_err();
    assert_eq!(err, TlsError::BadCertificate);
}

#[test]
fn untrusted_anchor_is_rejected() {
    let (creds, _store) = pki();
    // Empty store: no trust anchors → the chain cannot be validated.
    let cfg = client_config(CertStore::new(), Some(LEAF_NAME), &[]);
    let (mut client, client_hello) = ClientConnection::start(cfg, NexaCertVerifier).unwrap();
    let mut server = ServerConnection::new(server_config(creds, &[]));
    let (server_hello, flight) = server.accept(&client_hello).unwrap();
    let err = client.process_flight(&server_hello, &flight).unwrap_err();
    assert_eq!(err, TlsError::BadCertificate);
}

#[test]
fn alpn_mismatch_fails_at_the_server() {
    let (creds, store) = pki();
    // Client offers only h2; server insists on http/1.1 → no common protocol.
    let cfg = client_config(store, Some(LEAF_NAME), &[b"h2"]);
    let (_client, client_hello) = ClientConnection::start(cfg, NexaCertVerifier).unwrap();
    let mut server = ServerConnection::new(server_config(creds, &[b"http/1.1"]));
    let err = server.accept(&client_hello).unwrap_err();
    assert_eq!(
        err,
        TlsError::PeerAlert(nexacore_tls::alert::AlertDescription::NoApplicationProtocol)
    );
}

// ---- stream layer over a threaded channel transport -------------------------

mod stream_transport {
    use std::sync::mpsc::{Receiver, Sender};

    use nexacore_tls::{
        error::TlsResult,
        stream::{RecordTransport, TlsClientStream, TlsServerStream},
    };

    use super::*;

    struct ChannelTransport {
        tx: Sender<Vec<u8>>,
        rx: Receiver<Vec<u8>>,
    }

    impl RecordTransport for ChannelTransport {
        fn send(&mut self, record: &[u8]) -> TlsResult<()> {
            self.tx.send(record.to_vec()).map_err(|_| TlsError::Closed)
        }
        fn recv_record(&mut self) -> TlsResult<Vec<u8>> {
            self.rx.recv().map_err(|_| TlsError::Closed)
        }
    }

    #[test]
    fn tls_streams_handshake_and_exchange_over_a_channel() {
        let (creds, store) = pki();
        let (c2s_tx, c2s_rx) = std::sync::mpsc::channel();
        let (s2c_tx, s2c_rx) = std::sync::mpsc::channel();

        let client_transport = ChannelTransport {
            tx: c2s_tx,
            rx: s2c_rx,
        };
        let server_transport = ChannelTransport {
            tx: s2c_tx,
            rx: c2s_rx,
        };

        let server_thread = std::thread::spawn(move || {
            let mut srv =
                TlsServerStream::accept(server_config(creds, &[b"http/1.1"]), server_transport)
                    .unwrap();
            let req = srv.read().unwrap();
            assert_eq!(req, b"hello from client");
            srv.write(b"hello from server").unwrap();
            srv.alpn_protocol().map(<[u8]>::to_vec)
        });

        let cfg = client_config(store, Some(LEAF_NAME), &[b"http/1.1"]);
        let mut cli = TlsClientStream::connect(cfg, NexaCertVerifier, client_transport).unwrap();
        assert_eq!(cli.alpn_protocol(), Some(b"http/1.1".as_slice()));
        cli.write(b"hello from client").unwrap();
        assert_eq!(cli.read().unwrap(), b"hello from server");

        let server_alpn = server_thread.join().unwrap();
        assert_eq!(server_alpn.as_deref(), Some(b"http/1.1".as_slice()));
    }
}
