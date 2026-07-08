//! TLS 1.3 client handshake state machine (RFC 8446 § 4.1, client side).
//!
//! Drives `ClientHello → {ServerHello} → {EncryptedExtensions, Certificate,
//! CertificateVerify, Finished} → Finished`, deriving the handshake and
//! application traffic keys along the way and authenticating the server via the
//! configured [`CertStore`] and [`CertVerifier`]. The flow is expressed as
//! flight-in / flight-out byte buffers so it is fully host-testable without a
//! socket; [`crate::stream`] adapts it to the socket API.

use alloc::vec::Vec;

use nexacore_crypto::{
    kex::{NexaCoreEphemeralSecret, NexaCorePublicKey},
    signing::{NexaCoreSignature, NexaCoreVerifyingKey},
};

use crate::{
    auth::certificate_verify_content,
    certstore::{CertStore, CertVerifier},
    error::{TlsError, TlsResult},
    handshake::{self, ClientHello, HandshakeType, ServerHello},
    keyschedule::{KeySchedule, TrafficSecret, transcript_hash},
    params::{CIPHER_CHACHA20_POLY1305_SHA256, GROUP_X25519, SIG_ED25519, TLS13_VERSION},
    record::{self, ContentType, DirectionKeys},
    util::constant_time_eq,
};

/// Client configuration for a handshake.
///
/// Holds the expected server name (SNI + leaf-name binding), the ALPN
/// protocols to offer (in preference order), the trust store, and the current
/// wall-clock time (Unix seconds) for validity checks.
pub struct ClientConfig {
    /// SNI host name; also required to match the leaf certificate subject.
    pub server_name: Option<Vec<u8>>,
    /// ALPN protocols to offer, most-preferred first.
    pub alpn: Vec<Vec<u8>>,
    /// Trust anchors.
    pub store: CertStore,
    /// Current time (Unix seconds) for certificate validity.
    pub now: u64,
}

/// A client connection progressing through the handshake and into application
/// data. Generic over the certificate backend `V`.
pub struct ClientConnection<V: CertVerifier> {
    config: ClientConfig,
    verifier: V,
    ephemeral: Option<NexaCoreEphemeralSecret>,
    transcript: Vec<u8>,
    schedule: KeySchedule,
    write: Option<DirectionKeys>,
    read: Option<DirectionKeys>,
    client_hs: Option<TrafficSecret>,
    server_hs: Option<TrafficSecret>,
    pending_client_ap: Option<TrafficSecret>,
    negotiated_alpn: Option<Vec<u8>>,
    complete: bool,
}

impl<V: CertVerifier> ClientConnection<V> {
    /// Begin the handshake: generate the `x25519` key share, build the
    /// `ClientHello`, and return its plaintext record. The connection then
    /// awaits the server's flight.
    ///
    /// # Errors
    /// [`TlsError`] on any encoding failure.
    pub fn start(config: ClientConfig, verifier: V) -> TlsResult<(Self, Vec<u8>)> {
        let ephemeral = NexaCoreEphemeralSecret::generate();
        let key_share = ephemeral.public_key().as_bytes().to_vec();
        let random = random_32();
        let session_id = random_32().to_vec();

        let ch = ClientHello {
            random,
            legacy_session_id: session_id,
            cipher_suites: alloc::vec![CIPHER_CHACHA20_POLY1305_SHA256],
            key_share_group: GROUP_X25519,
            key_share,
            supported_versions: alloc::vec![TLS13_VERSION],
            supported_groups: alloc::vec![GROUP_X25519],
            signature_algorithms: alloc::vec![SIG_ED25519],
            server_name: config.server_name.clone(),
            alpn: config.alpn.clone(),
        };
        let framed = ch.encode()?;
        let record = record::encode_plaintext(ContentType::Handshake, &framed)?;

        let mut conn = Self {
            config,
            verifier,
            ephemeral: Some(ephemeral),
            transcript: Vec::new(),
            schedule: KeySchedule::new(),
            write: None,
            read: None,
            client_hs: None,
            server_hs: None,
            pending_client_ap: None,
            negotiated_alpn: None,
            complete: false,
        };
        conn.transcript.extend_from_slice(&framed);
        Ok((conn, record))
    }

    /// Process the server's `ServerHello` record and its encrypted flight,
    /// authenticate the server, and return the client `Finished` record.
    ///
    /// # Errors
    /// [`TlsError`] on any protocol, authentication, or crypto failure.
    pub fn process_flight(
        &mut self,
        server_hello_record: &[u8],
        encrypted_flight_record: &[u8],
    ) -> TlsResult<Vec<u8>> {
        self.consume_server_hello(server_hello_record)?;

        // Decrypt the server flight under the server handshake traffic key.
        let (ct, header, body) = record::read_record(encrypted_flight_record)?;
        if ct != ContentType::ApplicationData {
            return Err(TlsError::UnexpectedMessage);
        }
        let read = self.read.as_mut().ok_or(TlsError::UnexpectedMessage)?;
        let (inner_ct, plaintext) = read.open(header, body)?;
        if inner_ct != ContentType::Handshake {
            return Err(TlsError::UnexpectedMessage);
        }

        self.consume_encrypted_flight(&plaintext)?;
        self.send_client_finished()
    }

    /// The ALPN protocol negotiated with the server, if any.
    #[must_use]
    pub fn alpn_protocol(&self) -> Option<&[u8]> {
        self.negotiated_alpn.as_deref()
    }

    /// Whether the handshake has completed and application data may flow.
    #[must_use]
    pub const fn is_complete(&self) -> bool {
        self.complete
    }

    /// Seal application data into a record under the client application key.
    ///
    /// # Errors
    /// [`TlsError::Closed`] if the handshake is not complete, else a crypto
    /// error.
    pub fn seal_application(&mut self, data: &[u8]) -> TlsResult<Vec<u8>> {
        if !self.complete {
            return Err(TlsError::Closed);
        }
        let write = self.write.as_mut().ok_or(TlsError::Closed)?;
        write.seal(ContentType::ApplicationData, data)
    }

    /// Open an application-data record from the server.
    ///
    /// # Errors
    /// [`TlsError::Closed`] if not complete, [`TlsError::DecryptFailed`] on
    /// authentication failure, or [`TlsError::UnexpectedMessage`] for a
    /// non-application record.
    pub fn open_application(&mut self, record_bytes: &[u8]) -> TlsResult<Vec<u8>> {
        if !self.complete {
            return Err(TlsError::Closed);
        }
        let (ct, header, body) = record::read_record(record_bytes)?;
        if ct != ContentType::ApplicationData {
            return Err(TlsError::UnexpectedMessage);
        }
        let read = self.read.as_mut().ok_or(TlsError::Closed)?;
        let (inner_ct, data) = read.open(header, body)?;
        if inner_ct != ContentType::ApplicationData {
            return Err(TlsError::UnexpectedMessage);
        }
        Ok(data)
    }

    // ---- internal steps -----------------------------------------------------

    fn consume_server_hello(&mut self, server_hello_record: &[u8]) -> TlsResult<()> {
        let (ct, _hdr, body) = record::read_record(server_hello_record)?;
        if ct != ContentType::Handshake {
            return Err(TlsError::UnexpectedMessage);
        }
        let messages = handshake::split_messages(body)?;
        let (ty, sh_body) = messages.into_iter().next().ok_or(TlsError::Decode)?;
        if ty != HandshakeType::ServerHello {
            return Err(TlsError::UnexpectedMessage);
        }
        // The framed ServerHello for the transcript is type||len||body.
        let framed = handshake::encode_handshake(HandshakeType::ServerHello, &sh_body)?;
        self.transcript.extend_from_slice(&framed);

        let sh = ServerHello::parse(&sh_body)?;
        if sh.selected_version != TLS13_VERSION
            || sh.cipher_suite != CIPHER_CHACHA20_POLY1305_SHA256
            || sh.key_share_group != GROUP_X25519
            || sh.key_share.len() != 32
        {
            return Err(TlsError::NoCommonParameters);
        }

        // ECDHE.
        let peer_bytes: [u8; 32] = sh
            .key_share
            .as_slice()
            .try_into()
            .map_err(|_| TlsError::Decode)?;
        let peer = NexaCorePublicKey::from_bytes(peer_bytes);
        let ephemeral = self.ephemeral.take().ok_or(TlsError::UnexpectedMessage)?;
        let shared = ephemeral.diffie_hellman(&peer);
        if shared.is_trivial() {
            return Err(TlsError::NoCommonParameters);
        }

        let th = transcript_hash(&self.transcript);
        let (client_hs, server_hs) = self
            .schedule
            .derive_handshake_secrets(shared.as_bytes(), &th)?;
        self.read = Some(server_hs.direction_keys()?);
        self.write = Some(client_hs.direction_keys()?);
        self.client_hs = Some(client_hs);
        self.server_hs = Some(server_hs);
        Ok(())
    }

    fn consume_encrypted_flight(&mut self, plaintext: &[u8]) -> TlsResult<()> {
        let messages = handshake::split_messages(plaintext)?;
        let mut iter = messages.into_iter();

        // EncryptedExtensions.
        let (ty, ee_body) = iter.next().ok_or(TlsError::UnexpectedMessage)?;
        if ty != HandshakeType::EncryptedExtensions {
            return Err(TlsError::UnexpectedMessage);
        }
        self.negotiated_alpn = handshake::parse_encrypted_extensions(&ee_body)?;
        self.append_framed(HandshakeType::EncryptedExtensions, &ee_body)?;

        // Certificate.
        let (ty, cert_body) = iter.next().ok_or(TlsError::UnexpectedMessage)?;
        if ty != HandshakeType::Certificate {
            return Err(TlsError::UnexpectedMessage);
        }
        let chain = handshake::parse_certificate(&cert_body)?;
        let leaf = crate::certstore::verify_chain(
            &self.verifier,
            &chain,
            &self.config.store,
            self.config.now,
            self.config.server_name.as_deref(),
        )?;
        self.append_framed(HandshakeType::Certificate, &cert_body)?;
        let th_through_cert = transcript_hash(&self.transcript);

        // CertificateVerify: signature over the transcript through Certificate,
        // using the leaf's public key.
        let (ty, cv_body) = iter.next().ok_or(TlsError::UnexpectedMessage)?;
        if ty != HandshakeType::CertificateVerify {
            return Err(TlsError::UnexpectedMessage);
        }
        let (scheme, sig) = handshake::parse_certificate_verify(&cv_body)?;
        if scheme != SIG_ED25519 {
            return Err(TlsError::NoCommonParameters);
        }
        let content = certificate_verify_content(true, &th_through_cert);
        let vk = NexaCoreVerifyingKey::from_bytes(&leaf.subject_spki)
            .map_err(|_| TlsError::BadSignature)?;
        let sig_bytes: [u8; 64] = sig
            .as_slice()
            .try_into()
            .map_err(|_| TlsError::BadSignature)?;
        let signature = NexaCoreSignature::from_bytes(sig_bytes);
        vk.verify(&content, &signature)
            .map_err(|_| TlsError::BadSignature)?;
        self.append_framed(HandshakeType::CertificateVerify, &cv_body)?;
        let th_through_cv = transcript_hash(&self.transcript);

        // server Finished.
        let (ty, fin_body) = iter.next().ok_or(TlsError::UnexpectedMessage)?;
        if ty != HandshakeType::Finished {
            return Err(TlsError::UnexpectedMessage);
        }
        // The server Finished base key is the server handshake traffic secret,
        // stashed when the handshake secrets were derived.
        let server_hs = self.server_hs.ok_or(TlsError::UnexpectedMessage)?;
        let expected = server_hs.verify_data(&th_through_cv)?;
        if !constant_time_eq(&expected, &fin_body) {
            return Err(TlsError::BadFinished);
        }
        self.append_framed(HandshakeType::Finished, &fin_body)?;

        // Application secrets, bound to the transcript through server Finished.
        let th_app = transcript_hash(&self.transcript);
        let (client_ap, server_ap) = self.schedule.derive_application_secrets(&th_app)?;
        // Switch: application read (server) now; application write (client)
        // switches after we send the client Finished under the handshake key.
        self.read = Some(server_ap.direction_keys()?);
        self.pending_client_ap = Some(client_ap);
        Ok(())
    }

    fn send_client_finished(&mut self) -> TlsResult<Vec<u8>> {
        let th = transcript_hash(&self.transcript);
        let client_hs = self.client_hs.as_ref().ok_or(TlsError::UnexpectedMessage)?;
        let verify = client_hs.verify_data(&th)?;
        let fin = handshake::encode_finished(&verify)?;

        // Seal under the client handshake traffic key.
        let mut write = client_hs.direction_keys()?;
        let record = write.seal(ContentType::Handshake, &fin)?;

        // Now switch the client's write direction to the application key.
        let client_ap = self
            .pending_client_ap
            .take()
            .ok_or(TlsError::UnexpectedMessage)?;
        self.write = Some(client_ap.direction_keys()?);
        self.complete = true;
        Ok(record)
    }

    fn append_framed(&mut self, ty: HandshakeType, body: &[u8]) -> TlsResult<()> {
        let framed = handshake::encode_handshake(ty, body)?;
        self.transcript.extend_from_slice(&framed);
        Ok(())
    }
}

/// A single-use source of 32 uniformly-random bytes, taken from a fresh
/// `x25519` public key (a CSPRNG-derived value). Used for the `Hello` random
/// and legacy session id, which only need to be unpredictable and unique.
fn random_32() -> [u8; 32] {
    NexaCoreEphemeralSecret::generate().public_key().as_bytes()
}
