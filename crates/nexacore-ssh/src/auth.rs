//! The `ssh-userauth` service: SSH-2 user authentication (RFC 4252).
//!
//! This layers on top of an established transport [`Session`](crate::Session):
//! its [`send`](crate::Session::send) / [`recv`](crate::Session::recv) carry the
//! authentication messages over the AEAD packet channel. Two methods are
//! implemented:
//!
//! * **publickey** (`ssh-ed25519`, RFC 4252 §7) — the client proves possession
//!   of a private key by signing the session-bound request blob; the signature
//!   is verified with Ed25519 from `nexacore-crypto`. Both the *query* form (no
//!   signature → the server replies `SSH_MSG_USERAUTH_PK_OK`) and the
//!   *authenticating* form are supported.
//! * **password** (RFC 4252 §8) — the client sends the cleartext password over
//!   the encrypted channel; the server checks it.
//!
//! The credential / authorized-key decision is a seam: the server side calls an
//! [`AuthProvider`] rather than embedding a policy, so hosts (and tests) supply
//! their own key store and password check.
//!
//! # Message layout
//!
//! | Message | Value |
//! |---------|-------|
//! | `SSH_MSG_SERVICE_REQUEST` | 5 |
//! | `SSH_MSG_SERVICE_ACCEPT` | 6 |
//! | `SSH_MSG_USERAUTH_REQUEST` | 50 |
//! | `SSH_MSG_USERAUTH_FAILURE` | 51 |
//! | `SSH_MSG_USERAUTH_SUCCESS` | 52 |
//! | `SSH_MSG_USERAUTH_BANNER` | 53 |
//! | `SSH_MSG_USERAUTH_PK_OK` | 60 |

use alloc::{
    string::{String, ToString},
    vec::Vec,
};

use nexacore_crypto::signing::{NexaCoreSignature, NexaCoreSigningKey, NexaCoreVerifyingKey};

use crate::{
    error::SshError,
    kex::{host_key_blob, parse_host_key_blob, parse_signature_blob, signature_blob},
    transport::{Session, Transport},
    wire::{Reader, Writer},
};

/// `SSH_MSG_SERVICE_REQUEST` (RFC 4253 §10).
pub const SSH_MSG_SERVICE_REQUEST: u8 = 5;
/// `SSH_MSG_SERVICE_ACCEPT` (RFC 4253 §10).
pub const SSH_MSG_SERVICE_ACCEPT: u8 = 6;
/// `SSH_MSG_USERAUTH_REQUEST` (RFC 4252 §5).
pub const SSH_MSG_USERAUTH_REQUEST: u8 = 50;
/// `SSH_MSG_USERAUTH_FAILURE` (RFC 4252 §5.1).
pub const SSH_MSG_USERAUTH_FAILURE: u8 = 51;
/// `SSH_MSG_USERAUTH_SUCCESS` (RFC 4252 §5.1).
pub const SSH_MSG_USERAUTH_SUCCESS: u8 = 52;
/// `SSH_MSG_USERAUTH_BANNER` (RFC 4252 §5.4).
pub const SSH_MSG_USERAUTH_BANNER: u8 = 53;
/// `SSH_MSG_USERAUTH_PK_OK` (method-specific, RFC 4252 §7).
pub const SSH_MSG_USERAUTH_PK_OK: u8 = 60;

/// The user-authentication service name.
pub const USERAUTH_SERVICE: &str = "ssh-userauth";
/// The connection-protocol service name, requested after authentication.
pub const CONNECTION_SERVICE: &str = "ssh-connection";
/// The `publickey` method name (RFC 4252 §7).
pub const METHOD_PUBLICKEY: &str = "publickey";
/// The `password` method name (RFC 4252 §8).
pub const METHOD_PASSWORD: &str = "password";
/// The only public-key algorithm supported (`nexacore-crypto` Ed25519).
pub const PUBLICKEY_ALGORITHM: &str = "ssh-ed25519";

/// The methods this server offers, sent in every `SSH_MSG_USERAUTH_FAILURE`
/// name-list as the authentications that can still continue.
pub const OFFERED_METHODS: [&str; 2] = [METHOD_PUBLICKEY, METHOD_PASSWORD];

// =============================================================================
// Seam: the credential / authorized-key policy
// =============================================================================

/// The host's authentication policy: the authorized-key store and the password
/// check. The server-side verify path ([`server_handle_auth`]) calls this
/// rather than embedding any credential logic.
pub trait AuthProvider {
    /// Whether `public_key` (of the given `algorithm`) is an authorized key for
    /// `user`. The signature is verified separately by the caller; this decides
    /// only whether the key itself is accepted (the `authorized_keys` check).
    fn authorize_key(&self, user: &str, algorithm: &str, public_key: &[u8; 32]) -> bool;

    /// Whether `password` authenticates `user`.
    fn verify_password(&self, user: &str, password: &[u8]) -> bool;
}

// =============================================================================
// Parsed responses (client view) and outcomes (server view)
// =============================================================================

/// A parsed authentication reply, as seen by the client.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthResponse {
    /// `SSH_MSG_USERAUTH_SUCCESS`: authentication completed; auth is over.
    Success,
    /// `SSH_MSG_USERAUTH_FAILURE`: the attempt was rejected. `methods` is the
    /// name-list of authentications that can still continue.
    Failure {
        /// Authentications that can continue.
        methods: Vec<String>,
        /// Whether partial success was signalled (RFC 4252 §5.1).
        partial_success: bool,
    },
    /// `SSH_MSG_USERAUTH_PK_OK`: the server accepts this key for a signed
    /// request (answer to the publickey query form).
    PkOk {
        /// The public-key algorithm echoed from the query.
        algorithm: String,
        /// The 32-byte Ed25519 public key echoed from the query.
        public_key: [u8; 32],
    },
    /// `SSH_MSG_USERAUTH_BANNER`: an informational message. Drivers surface it
    /// to the caller but otherwise keep waiting for a terminal reply.
    Banner {
        /// The banner text.
        message: String,
    },
}

/// The result of the server processing one `SSH_MSG_USERAUTH_REQUEST`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ServerAuthOutcome {
    /// The user authenticated; `SSH_MSG_USERAUTH_SUCCESS` was sent.
    Authenticated {
        /// The authenticated user name.
        user: String,
    },
    /// A publickey *query* named an authorized key; `SSH_MSG_USERAUTH_PK_OK`
    /// was sent and the client is expected to follow up with a signed request.
    KeyAcknowledged {
        /// The user name from the query.
        user: String,
        /// The acknowledged public key.
        public_key: [u8; 32],
    },
    /// The attempt was rejected; `SSH_MSG_USERAUTH_FAILURE` was sent.
    Rejected {
        /// The user name from the request.
        user: String,
        /// The method that was rejected.
        method: String,
    },
}

// =============================================================================
// Message encoders
// =============================================================================

/// Encode `SSH_MSG_SERVICE_REQUEST` for `service`.
#[must_use]
pub fn encode_service_request(service: &str) -> Vec<u8> {
    let mut w = Writer::new();
    w.put_u8(SSH_MSG_SERVICE_REQUEST);
    w.put_string(service.as_bytes());
    w.into_bytes()
}

/// Encode `SSH_MSG_SERVICE_ACCEPT` for `service`.
#[must_use]
pub fn encode_service_accept(service: &str) -> Vec<u8> {
    let mut w = Writer::new();
    w.put_u8(SSH_MSG_SERVICE_ACCEPT);
    w.put_string(service.as_bytes());
    w.into_bytes()
}

/// The RFC 4252 §7 blob a publickey request is signed over:
/// `string(session_id) || byte(50) || string(user) || string(service) ||
/// string("publickey") || TRUE || string(algorithm) || string(key_blob)`.
fn publickey_signed_data(
    session_id: &[u8; 32],
    user: &str,
    service: &str,
    algorithm: &str,
    key_blob: &[u8],
) -> Vec<u8> {
    let mut w = Writer::new();
    w.put_string(session_id);
    w.put_u8(SSH_MSG_USERAUTH_REQUEST);
    w.put_string(user.as_bytes());
    w.put_string(service.as_bytes());
    w.put_string(METHOD_PUBLICKEY.as_bytes());
    w.put_bool(true);
    w.put_string(algorithm.as_bytes());
    w.put_string(key_blob);
    w.into_bytes()
}

/// Encode a publickey *query* `SSH_MSG_USERAUTH_REQUEST` (no signature): the
/// server answers `SSH_MSG_USERAUTH_PK_OK` if it would accept a signed request.
#[must_use]
pub fn encode_userauth_publickey_query(
    user: &str,
    service: &str,
    public_key: &[u8; 32],
) -> Vec<u8> {
    let key_blob = host_key_blob(public_key);
    let mut w = Writer::new();
    w.put_u8(SSH_MSG_USERAUTH_REQUEST);
    w.put_string(user.as_bytes());
    w.put_string(service.as_bytes());
    w.put_string(METHOD_PUBLICKEY.as_bytes());
    w.put_bool(false);
    w.put_string(PUBLICKEY_ALGORITHM.as_bytes());
    w.put_string(&key_blob);
    w.into_bytes()
}

/// Encode an authenticating publickey `SSH_MSG_USERAUTH_REQUEST`.
///
/// `public_key` is the advertised key that goes into the request (and that the
/// server verifies against); `signer` produces the signature over the RFC 4252
/// §7 blob. In the honest path `public_key == signer.verifying_key()`; passing
/// a mismatched pair models a bad signature.
#[must_use]
pub fn encode_userauth_publickey(
    session_id: &[u8; 32],
    user: &str,
    service: &str,
    public_key: &[u8; 32],
    signer: &NexaCoreSigningKey,
) -> Vec<u8> {
    let key_blob = host_key_blob(public_key);
    let signed_blob =
        publickey_signed_data(session_id, user, service, PUBLICKEY_ALGORITHM, &key_blob);
    let sig = signer.sign(&signed_blob).to_bytes();
    let sig_blob = signature_blob(&sig);

    let mut w = Writer::new();
    w.put_u8(SSH_MSG_USERAUTH_REQUEST);
    w.put_string(user.as_bytes());
    w.put_string(service.as_bytes());
    w.put_string(METHOD_PUBLICKEY.as_bytes());
    w.put_bool(true);
    w.put_string(PUBLICKEY_ALGORITHM.as_bytes());
    w.put_string(&key_blob);
    w.put_string(&sig_blob);
    w.into_bytes()
}

/// Encode a password `SSH_MSG_USERAUTH_REQUEST` (RFC 4252 §8).
#[must_use]
pub fn encode_userauth_password(user: &str, service: &str, password: &[u8]) -> Vec<u8> {
    let mut w = Writer::new();
    w.put_u8(SSH_MSG_USERAUTH_REQUEST);
    w.put_string(user.as_bytes());
    w.put_string(service.as_bytes());
    w.put_string(METHOD_PASSWORD.as_bytes());
    w.put_bool(false); // not a password change
    w.put_string(password);
    w.into_bytes()
}

/// Encode `SSH_MSG_USERAUTH_FAILURE` with the name-list of methods that can
/// continue and the partial-success flag.
#[must_use]
pub fn encode_userauth_failure(methods: &[&str], partial_success: bool) -> Vec<u8> {
    let mut w = Writer::new();
    w.put_u8(SSH_MSG_USERAUTH_FAILURE);
    w.put_name_list(methods);
    w.put_bool(partial_success);
    w.into_bytes()
}

/// Encode `SSH_MSG_USERAUTH_SUCCESS`.
#[must_use]
pub fn encode_userauth_success() -> Vec<u8> {
    alloc::vec![SSH_MSG_USERAUTH_SUCCESS]
}

/// Encode `SSH_MSG_USERAUTH_BANNER` with `message` and `language` tag.
#[must_use]
pub fn encode_userauth_banner(message: &str, language: &str) -> Vec<u8> {
    let mut w = Writer::new();
    w.put_u8(SSH_MSG_USERAUTH_BANNER);
    w.put_string(message.as_bytes());
    w.put_string(language.as_bytes());
    w.into_bytes()
}

/// Encode `SSH_MSG_USERAUTH_PK_OK` echoing the accepted key.
#[must_use]
pub fn encode_userauth_pk_ok(algorithm: &str, public_key: &[u8; 32]) -> Vec<u8> {
    let key_blob = host_key_blob(public_key);
    let mut w = Writer::new();
    w.put_u8(SSH_MSG_USERAUTH_PK_OK);
    w.put_string(algorithm.as_bytes());
    w.put_string(&key_blob);
    w.into_bytes()
}

// =============================================================================
// Response parsing (client view)
// =============================================================================

/// Parse one authentication reply payload into an [`AuthResponse`].
///
/// # Errors
/// [`SshError::ShortBuffer`] on truncation, [`SshError::Protocol`] on an
/// unexpected message type or malformed body.
pub fn parse_userauth_response(payload: &[u8]) -> Result<AuthResponse, SshError> {
    let mut r = Reader::new(payload);
    match r.get_u8()? {
        SSH_MSG_USERAUTH_SUCCESS => Ok(AuthResponse::Success),
        SSH_MSG_USERAUTH_FAILURE => {
            let methods = r.get_name_list()?;
            let partial_success = r.get_bool()?;
            Ok(AuthResponse::Failure {
                methods,
                partial_success,
            })
        }
        SSH_MSG_USERAUTH_PK_OK => {
            let algorithm = read_utf8(&mut r)?;
            let key_blob = r.get_string()?;
            let public_key = parse_host_key_blob(key_blob)?;
            Ok(AuthResponse::PkOk {
                algorithm,
                public_key,
            })
        }
        SSH_MSG_USERAUTH_BANNER => {
            let message = read_utf8(&mut r)?;
            let _language = r.get_string()?;
            Ok(AuthResponse::Banner { message })
        }
        _ => Err(SshError::Protocol("unexpected userauth reply")),
    }
}

fn read_utf8(r: &mut Reader) -> Result<String, SshError> {
    let bytes = r.get_string()?;
    core::str::from_utf8(bytes)
        .map(ToString::to_string)
        .map_err(|_| SshError::Protocol("string not utf8"))
}

// =============================================================================
// Client drivers
// =============================================================================

/// Request the given `service` and wait for the server to accept it.
///
/// # Errors
/// [`SshError::Transport`] / [`SshError::Decrypt`] from the channel, or
/// [`SshError::Protocol`] if the reply is not a matching `SSH_MSG_SERVICE_ACCEPT`.
pub fn client_request_service<T: Transport>(
    session: &mut Session,
    t: &mut T,
    service: &str,
) -> Result<(), SshError> {
    session.send(t, &encode_service_request(service))?;
    let reply = session.recv(t)?;
    let mut r = Reader::new(&reply);
    if r.get_u8()? != SSH_MSG_SERVICE_ACCEPT {
        return Err(SshError::Protocol("expected SERVICE_ACCEPT"));
    }
    if read_utf8(&mut r)? != service {
        return Err(SshError::Protocol("service name mismatch"));
    }
    Ok(())
}

/// Send a publickey *query* (no signature) for `user` and read the reply.
///
/// # Errors
/// Transport/decrypt errors, or [`SshError::Protocol`] on a malformed reply.
pub fn client_userauth_publickey_query<T: Transport>(
    session: &mut Session,
    t: &mut T,
    user: &str,
    public_key: &[u8; 32],
) -> Result<AuthResponse, SshError> {
    session.send(
        t,
        &encode_userauth_publickey_query(user, CONNECTION_SERVICE, public_key),
    )?;
    recv_terminal(session, t)
}

/// Authenticate `user` with the `key` via the publickey method, signing the
/// RFC 4252 §7 blob bound to this session, and read the reply.
///
/// # Errors
/// Transport/decrypt errors, or [`SshError::Protocol`] on a malformed reply.
pub fn client_userauth_publickey<T: Transport>(
    session: &mut Session,
    t: &mut T,
    user: &str,
    key: &NexaCoreSigningKey,
) -> Result<AuthResponse, SshError> {
    let public_key = key.verifying_key().as_bytes();
    let session_id = *session.session_id();
    let request =
        encode_userauth_publickey(&session_id, user, CONNECTION_SERVICE, &public_key, key);
    session.send(t, &request)?;
    recv_terminal(session, t)
}

/// Authenticate `user` with a `password` and read the reply.
///
/// # Errors
/// Transport/decrypt errors, or [`SshError::Protocol`] on a malformed reply.
pub fn client_userauth_password<T: Transport>(
    session: &mut Session,
    t: &mut T,
    user: &str,
    password: &[u8],
) -> Result<AuthResponse, SshError> {
    session.send(
        t,
        &encode_userauth_password(user, CONNECTION_SERVICE, password),
    )?;
    recv_terminal(session, t)
}

/// Receive replies, transparently skipping informational banners, until a
/// terminal reply (`SUCCESS` / `FAILURE` / `PK_OK`) arrives.
fn recv_terminal<T: Transport>(session: &mut Session, t: &mut T) -> Result<AuthResponse, SshError> {
    loop {
        let reply = session.recv(t)?;
        match parse_userauth_response(&reply)? {
            AuthResponse::Banner { .. } => {}
            terminal => return Ok(terminal),
        }
    }
}

// =============================================================================
// Server drivers
// =============================================================================

/// Read an `SSH_MSG_SERVICE_REQUEST`, accept it, and return the requested
/// service name.
///
/// # Errors
/// Transport/decrypt errors, or [`SshError::Protocol`] if the message is not a
/// service request.
pub fn server_accept_service<T: Transport>(
    session: &mut Session,
    t: &mut T,
) -> Result<String, SshError> {
    let msg = session.recv(t)?;
    let mut r = Reader::new(&msg);
    if r.get_u8()? != SSH_MSG_SERVICE_REQUEST {
        return Err(SshError::Protocol("expected SERVICE_REQUEST"));
    }
    let service = read_utf8(&mut r)?;
    session.send(t, &encode_service_accept(&service))?;
    Ok(service)
}

/// Read one `SSH_MSG_USERAUTH_REQUEST`, evaluate it against `provider`, send the
/// appropriate reply, and return the outcome.
///
/// The publickey signature is verified with Ed25519 over the RFC 4252 §7 blob
/// bound to this session; both the verification and the [`AuthProvider`]
/// authorization must pass for success.
///
/// # Errors
/// Transport/decrypt errors, or [`SshError::Protocol`] / [`SshError::ShortBuffer`]
/// on a malformed request.
pub fn server_handle_auth<T: Transport, A: AuthProvider>(
    session: &mut Session,
    t: &mut T,
    provider: &A,
) -> Result<ServerAuthOutcome, SshError> {
    let session_id = *session.session_id();
    let payload = session.recv(t)?;
    let mut r = Reader::new(&payload);
    if r.get_u8()? != SSH_MSG_USERAUTH_REQUEST {
        return Err(SshError::Protocol("expected USERAUTH_REQUEST"));
    }
    let user = read_utf8(&mut r)?;
    let service = read_utf8(&mut r)?;
    let method = read_utf8(&mut r)?;

    match method.as_str() {
        METHOD_PUBLICKEY => {
            handle_publickey(session, t, provider, &session_id, &user, &service, &mut r)
        }
        METHOD_PASSWORD => handle_password(session, t, provider, &user, &mut r),
        _ => {
            reject(session, t)?;
            Ok(ServerAuthOutcome::Rejected { user, method })
        }
    }
}

fn handle_publickey<T: Transport, A: AuthProvider>(
    session: &mut Session,
    t: &mut T,
    provider: &A,
    session_id: &[u8; 32],
    user: &str,
    service: &str,
    r: &mut Reader,
) -> Result<ServerAuthOutcome, SshError> {
    let has_signature = r.get_bool()?;
    let algorithm = read_utf8(r)?;
    let key_blob = r.get_string()?.to_vec();
    let public_key = parse_host_key_blob(&key_blob)?;

    let reject_pk = |session: &mut Session, t: &mut T| -> Result<ServerAuthOutcome, SshError> {
        reject(session, t)?;
        Ok(ServerAuthOutcome::Rejected {
            user: user.to_string(),
            method: METHOD_PUBLICKEY.to_string(),
        })
    };

    let authorized = provider.authorize_key(user, &algorithm, &public_key);

    if !has_signature {
        // Query form: acknowledge with PK_OK iff the key is authorized.
        if authorized {
            session.send(t, &encode_userauth_pk_ok(&algorithm, &public_key))?;
            return Ok(ServerAuthOutcome::KeyAcknowledged {
                user: user.to_string(),
                public_key,
            });
        }
        return reject_pk(session, t);
    }

    let sig_blob = r.get_string()?;
    let signature = parse_signature_blob(sig_blob)?;
    let signed = publickey_signed_data(session_id, user, service, &algorithm, &key_blob);
    let signature_ok = NexaCoreVerifyingKey::from_bytes(&public_key)
        .and_then(|vk| vk.verify(&signed, &NexaCoreSignature::from_bytes(signature)))
        .is_ok();

    if authorized && signature_ok {
        session.send(t, &encode_userauth_success())?;
        Ok(ServerAuthOutcome::Authenticated {
            user: user.to_string(),
        })
    } else {
        reject_pk(session, t)
    }
}

fn handle_password<T: Transport, A: AuthProvider>(
    session: &mut Session,
    t: &mut T,
    provider: &A,
    user: &str,
    r: &mut Reader,
) -> Result<ServerAuthOutcome, SshError> {
    let _change = r.get_bool()?; // password-change requests are not supported
    let password = r.get_string()?;
    if provider.verify_password(user, password) {
        session.send(t, &encode_userauth_success())?;
        Ok(ServerAuthOutcome::Authenticated {
            user: user.to_string(),
        })
    } else {
        reject(session, t)?;
        Ok(ServerAuthOutcome::Rejected {
            user: user.to_string(),
            method: METHOD_PASSWORD.to_string(),
        })
    }
}

/// Send a standard `SSH_MSG_USERAUTH_FAILURE` listing the offered methods.
fn reject<T: Transport>(session: &mut Session, t: &mut T) -> Result<(), SshError> {
    session.send(t, &encode_userauth_failure(&OFFERED_METHODS, false))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::indexing_slicing)]

    use super::*;

    #[test]
    fn service_messages_round_trip() {
        let encoded = encode_service_request(USERAUTH_SERVICE);
        let mut r = Reader::new(&encoded);
        assert_eq!(r.get_u8().unwrap(), SSH_MSG_SERVICE_REQUEST);
        assert_eq!(r.get_string().unwrap(), USERAUTH_SERVICE.as_bytes());
    }

    #[test]
    fn success_and_failure_parse() {
        assert_eq!(
            parse_userauth_response(&encode_userauth_success()).unwrap(),
            AuthResponse::Success
        );
        let failure = encode_userauth_failure(&OFFERED_METHODS, false);
        assert_eq!(
            parse_userauth_response(&failure).unwrap(),
            AuthResponse::Failure {
                methods: alloc::vec![
                    String::from(METHOD_PUBLICKEY),
                    String::from(METHOD_PASSWORD)
                ],
                partial_success: false,
            }
        );
    }

    #[test]
    fn pk_ok_and_banner_parse() {
        let pk = [0x7bu8; 32];
        assert_eq!(
            parse_userauth_response(&encode_userauth_pk_ok(PUBLICKEY_ALGORITHM, &pk)).unwrap(),
            AuthResponse::PkOk {
                algorithm: String::from(PUBLICKEY_ALGORITHM),
                public_key: pk,
            }
        );
        assert_eq!(
            parse_userauth_response(&encode_userauth_banner("hi", "en")).unwrap(),
            AuthResponse::Banner {
                message: String::from("hi")
            }
        );
    }

    #[test]
    fn signed_data_binds_session_and_user() {
        let key_blob = host_key_blob(&[0x01; 32]);
        let base = publickey_signed_data(
            &[0xAA; 32],
            "alice",
            CONNECTION_SERVICE,
            PUBLICKEY_ALGORITHM,
            &key_blob,
        );
        // A different session id yields a different signed blob (session binding).
        let other_session = publickey_signed_data(
            &[0xBB; 32],
            "alice",
            CONNECTION_SERVICE,
            PUBLICKEY_ALGORITHM,
            &key_blob,
        );
        assert_ne!(base, other_session);
        // A different user yields a different signed blob.
        let other_user = publickey_signed_data(
            &[0xAA; 32],
            "bob",
            CONNECTION_SERVICE,
            PUBLICKEY_ALGORITHM,
            &key_blob,
        );
        assert_ne!(base, other_user);
    }

    #[test]
    fn publickey_request_signature_verifies() {
        let key = NexaCoreSigningKey::from_bytes([0x09; 32]);
        let public_key = key.verifying_key().as_bytes();
        let session_id = [0x5c; 32];
        let request =
            encode_userauth_publickey(&session_id, "alice", CONNECTION_SERVICE, &public_key, &key);

        // Re-derive the signed blob and confirm the embedded signature verifies.
        let mut r = Reader::new(&request);
        assert_eq!(r.get_u8().unwrap(), SSH_MSG_USERAUTH_REQUEST);
        let _user = r.get_string().unwrap();
        let _service = r.get_string().unwrap();
        let _method = r.get_string().unwrap();
        assert!(r.get_bool().unwrap());
        let algorithm = r.get_string().unwrap();
        let key_blob = r.get_string().unwrap().to_vec();
        let sig_blob = r.get_string().unwrap();
        let sig = parse_signature_blob(sig_blob).unwrap();

        let signed = publickey_signed_data(
            &session_id,
            "alice",
            CONNECTION_SERVICE,
            core::str::from_utf8(algorithm).unwrap(),
            &key_blob,
        );
        let vk = NexaCoreVerifyingKey::from_bytes(&public_key).unwrap();
        assert!(
            vk.verify(&signed, &NexaCoreSignature::from_bytes(sig))
                .is_ok()
        );
    }
}
