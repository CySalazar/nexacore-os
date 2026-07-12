//! End-to-end `ssh-userauth` (RFC 4252) over an in-memory byte pipe.
//!
//! Each test brings up a real encrypted [`Session`] via the transport
//! handshake, then drives one authentication exchange between a client driver
//! and the server-side verify path (behind the [`AuthProvider`] seam) over the
//! same channel-backed [`Transport`] double the handshake tests use.

#![allow(clippy::unwrap_used, clippy::indexing_slicing, clippy::panic)]

use std::{
    collections::VecDeque,
    sync::mpsc::{Receiver, Sender, channel},
    thread,
};

use nexacore_crypto::signing::NexaCoreSigningKey;
use nexacore_ssh::{
    Session, SshError, Transport,
    auth::{
        AuthProvider, AuthResponse, CONNECTION_SERVICE, ServerAuthOutcome, USERAUTH_SERVICE,
        client_request_service, client_userauth_password, client_userauth_publickey,
        client_userauth_publickey_query, encode_userauth_publickey, server_accept_service,
        server_handle_auth,
    },
    transport::{client_handshake, server_handshake},
};

// ---- transport double (mirrors tests/handshake.rs) --------------------------

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

/// Run both transport handshakes and return the two live sessions plus their
/// transports (client first).
fn established() -> (Session, ChannelTransport, Session, ChannelTransport) {
    let (mut client_t, mut server_t) = duplex();
    let host_key = NexaCoreSigningKey::from_bytes([0x5a; 32]);
    let server = thread::spawn(move || {
        let s = server_handshake(&mut server_t, &host_key).unwrap();
        (s, server_t)
    });
    let client_session = client_handshake(&mut client_t).unwrap();
    let (server_session, server_t) = server.join().unwrap();
    (client_session, client_t, server_session, server_t)
}

// ---- test double for the credential/authorized-key seam ---------------------

struct TestProvider {
    keys: Vec<(String, [u8; 32])>,
    passwords: Vec<(String, Vec<u8>)>,
}

impl AuthProvider for TestProvider {
    fn authorize_key(&self, user: &str, algorithm: &str, public_key: &[u8; 32]) -> bool {
        algorithm == "ssh-ed25519" && self.keys.iter().any(|(u, k)| u == user && k == public_key)
    }

    fn verify_password(&self, user: &str, password: &[u8]) -> bool {
        self.passwords
            .iter()
            .any(|(u, p)| u == user && p.as_slice() == password)
    }
}

// ---- tests ------------------------------------------------------------------

#[test]
fn service_request_is_accepted() {
    let (mut cs, mut ct, mut ss, mut st) = established();
    let server = thread::spawn(move || server_accept_service(&mut ss, &mut st).unwrap());
    client_request_service(&mut cs, &mut ct, USERAUTH_SERVICE).unwrap();
    assert_eq!(server.join().unwrap(), USERAUTH_SERVICE);
}

#[test]
fn publickey_success_and_success_ends_auth() {
    let (mut cs, mut ct, mut ss, mut st) = established();
    let key = NexaCoreSigningKey::from_bytes([0x21; 32]);
    let pubkey = key.verifying_key().as_bytes();
    let provider = TestProvider {
        keys: vec![(String::from("alice"), pubkey)],
        passwords: vec![],
    };

    let server = thread::spawn(move || server_handle_auth(&mut ss, &mut st, &provider).unwrap());
    let resp = client_userauth_publickey(&mut cs, &mut ct, "alice", &key).unwrap();
    let outcome = server.join().unwrap();

    assert_eq!(resp, AuthResponse::Success);
    assert_eq!(
        outcome,
        ServerAuthOutcome::Authenticated {
            user: String::from("alice")
        }
    );
}

#[test]
fn publickey_query_returns_pk_ok() {
    let (mut cs, mut ct, mut ss, mut st) = established();
    let key = NexaCoreSigningKey::from_bytes([0x33; 32]);
    let pubkey = key.verifying_key().as_bytes();
    let provider = TestProvider {
        keys: vec![(String::from("bob"), pubkey)],
        passwords: vec![],
    };

    let server = thread::spawn(move || server_handle_auth(&mut ss, &mut st, &provider).unwrap());
    let resp = client_userauth_publickey_query(&mut cs, &mut ct, "bob", &pubkey).unwrap();
    let outcome = server.join().unwrap();

    assert_eq!(
        resp,
        AuthResponse::PkOk {
            algorithm: String::from("ssh-ed25519"),
            public_key: pubkey,
        }
    );
    assert_eq!(
        outcome,
        ServerAuthOutcome::KeyAcknowledged {
            user: String::from("bob"),
            public_key: pubkey,
        }
    );
}

#[test]
fn publickey_wrong_signature_is_rejected() {
    let (mut cs, mut ct, mut ss, mut st) = established();
    // The advertised key (authorized) and the signing key differ, so the
    // signature does not verify against the advertised public key.
    let advertised = NexaCoreSigningKey::from_bytes([0x44; 32]);
    let advertised_pub = advertised.verifying_key().as_bytes();
    let impostor = NexaCoreSigningKey::from_bytes([0x45; 32]);
    let provider = TestProvider {
        keys: vec![(String::from("carol"), advertised_pub)],
        passwords: vec![],
    };

    let session_id = *cs.session_id();
    let server = thread::spawn(move || server_handle_auth(&mut ss, &mut st, &provider).unwrap());
    let request = encode_userauth_publickey(
        &session_id,
        "carol",
        CONNECTION_SERVICE,
        &advertised_pub,
        &impostor,
    );
    cs.send(&mut ct, &request).unwrap();
    let resp = nexacore_ssh::auth::parse_userauth_response(&cs.recv(&mut ct).unwrap()).unwrap();
    let outcome = server.join().unwrap();

    assert!(matches!(resp, AuthResponse::Failure { .. }));
    assert!(matches!(outcome, ServerAuthOutcome::Rejected { .. }));
}

#[test]
fn publickey_unknown_key_is_rejected() {
    let (mut cs, mut ct, mut ss, mut st) = established();
    // The key signs correctly but is not in the authorized set.
    let key = NexaCoreSigningKey::from_bytes([0x55; 32]);
    let provider = TestProvider {
        keys: vec![(
            String::from("dave"),
            NexaCoreSigningKey::from_bytes([0x99; 32])
                .verifying_key()
                .as_bytes(),
        )],
        passwords: vec![],
    };

    let server = thread::spawn(move || server_handle_auth(&mut ss, &mut st, &provider).unwrap());
    let resp = client_userauth_publickey(&mut cs, &mut ct, "dave", &key).unwrap();
    let outcome = server.join().unwrap();

    assert!(matches!(resp, AuthResponse::Failure { .. }));
    assert!(matches!(outcome, ServerAuthOutcome::Rejected { .. }));
}

#[test]
fn password_success() {
    let (mut cs, mut ct, mut ss, mut st) = established();
    let provider = TestProvider {
        keys: vec![],
        passwords: vec![(String::from("erin"), b"hunter2".to_vec())],
    };

    let server = thread::spawn(move || server_handle_auth(&mut ss, &mut st, &provider).unwrap());
    let resp = client_userauth_password(&mut cs, &mut ct, "erin", b"hunter2").unwrap();
    let outcome = server.join().unwrap();

    assert_eq!(resp, AuthResponse::Success);
    assert_eq!(
        outcome,
        ServerAuthOutcome::Authenticated {
            user: String::from("erin")
        }
    );
}

#[test]
fn password_wrong_is_rejected() {
    let (mut cs, mut ct, mut ss, mut st) = established();
    let provider = TestProvider {
        keys: vec![],
        passwords: vec![(String::from("erin"), b"hunter2".to_vec())],
    };

    let server = thread::spawn(move || server_handle_auth(&mut ss, &mut st, &provider).unwrap());
    let resp = client_userauth_password(&mut cs, &mut ct, "erin", b"wrong").unwrap();
    let outcome = server.join().unwrap();

    assert!(matches!(resp, AuthResponse::Failure { .. }));
    assert!(matches!(outcome, ServerAuthOutcome::Rejected { .. }));
}

#[test]
fn failure_carries_remaining_methods_name_list() {
    let (mut cs, mut ct, mut ss, mut st) = established();
    let provider = TestProvider {
        keys: vec![],
        passwords: vec![(String::from("erin"), b"hunter2".to_vec())],
    };

    let server = thread::spawn(move || server_handle_auth(&mut ss, &mut st, &provider).unwrap());
    let resp = client_userauth_password(&mut cs, &mut ct, "erin", b"wrong").unwrap();
    server.join().unwrap();

    match resp {
        AuthResponse::Failure {
            methods,
            partial_success,
        } => {
            assert_eq!(
                methods,
                vec![String::from("publickey"), String::from("password")]
            );
            assert!(!partial_success);
        }
        other => panic!("expected Failure, got {other:?}"),
    }
}
