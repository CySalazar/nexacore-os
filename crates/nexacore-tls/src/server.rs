//! TLS 1.3 server handshake state machine (RFC 8446 § 4.1, server side).
//!
//! Consumes a `ClientHello`, negotiates
//! `TLS_CHACHA20_POLY1305_SHA256` / `x25519` / `ed25519`, and produces the
//! `ServerHello` plus the encrypted flight (`EncryptedExtensions`,
//! `Certificate`, `CertificateVerify`, `Finished`). It then verifies the
//! client's `Finished`. As with the client, the API is flight-in / flight-out
//! so the whole exchange runs in-process for tests.

use alloc::vec::Vec;

use nexacore_crypto::kex::{NexaCoreEphemeralSecret, NexaCorePublicKey};

use crate::{
    alpn,
    auth::{ServerCredentials, certificate_verify_content},
    error::{TlsError, TlsResult},
    handshake::{self, ClientHello, HandshakeType, ServerHello},
    keyschedule::{KeySchedule, TrafficSecret, transcript_hash},
    params::{
        CIPHER_CHACHA20_POLY1305_SHA256, CipherSuite, GROUP_X25519, NamedGroup, SIG_ED25519,
        SignatureScheme, TLS13_VERSION,
    },
    record::{self, ContentType, DirectionKeys},
    util::constant_time_eq,
};

/// Server configuration: its credentials and its ALPN preference list.
pub struct ServerConfig {
    /// The server's certificate chain + leaf private key.
    pub credentials: ServerCredentials,
    /// ALPN protocols the server supports, most-preferred first (may be empty).
    pub alpn: Vec<Vec<u8>>,
}

/// A server connection progressing through the handshake and into application
/// data.
pub struct ServerConnection {
    config: ServerConfig,
    transcript: Vec<u8>,
    schedule: KeySchedule,
    write: Option<DirectionKeys>,
    read: Option<DirectionKeys>,
    client_hs: Option<TrafficSecret>,
    pending_client_ap: Option<TrafficSecret>,
    th_app: Option<[u8; 32]>,
    negotiated_alpn: Option<Vec<u8>>,
    complete: bool,
}

impl ServerConnection {
    /// Create a server awaiting a `ClientHello`.
    #[must_use]
    pub fn new(config: ServerConfig) -> Self {
        Self {
            config,
            transcript: Vec::new(),
            schedule: KeySchedule::new(),
            write: None,
            read: None,
            client_hs: None,
            pending_client_ap: None,
            th_app: None,
            negotiated_alpn: None,
            complete: false,
        }
    }

    /// Consume the `ClientHello` record; return `(ServerHello record, encrypted
    /// flight record)`.
    ///
    /// # Errors
    /// [`TlsError`] on negotiation, encoding, or crypto failure.
    pub fn accept(&mut self, client_hello_record: &[u8]) -> TlsResult<(Vec<u8>, Vec<u8>)> {
        let ch = self.consume_client_hello(client_hello_record)?;

        // Negotiate — each is a membership test against our single support.
        let _suite = CipherSuite::select(&ch.cipher_suites)?;
        let _group = NamedGroup::select(&ch.supported_groups)?;
        let _sig = SignatureScheme::select(&ch.signature_algorithms)?;
        if ch.key_share_group != GROUP_X25519 || ch.key_share.len() != 32 {
            return Err(TlsError::NoCommonParameters);
        }
        let prefs: Vec<&[u8]> = self.config.alpn.iter().map(Vec::as_slice).collect();
        self.negotiated_alpn = alpn::select(&prefs, &ch.alpn)?.map(<[u8]>::to_vec);

        // ECDHE.
        let peer_bytes: [u8; 32] = ch
            .key_share
            .as_slice()
            .try_into()
            .map_err(|_| TlsError::Decode)?;
        let peer = NexaCorePublicKey::from_bytes(peer_bytes);
        let ephemeral = NexaCoreEphemeralSecret::generate();
        let server_share = ephemeral.public_key().as_bytes().to_vec();
        let shared = ephemeral.diffie_hellman(&peer);
        if shared.is_trivial() {
            return Err(TlsError::NoCommonParameters);
        }

        // ServerHello.
        let sh = ServerHello {
            random: random_32(),
            legacy_session_id: ch.legacy_session_id,
            cipher_suite: CIPHER_CHACHA20_POLY1305_SHA256,
            selected_version: TLS13_VERSION,
            key_share_group: GROUP_X25519,
            key_share: server_share,
        };
        let sh_framed = sh.encode()?;
        self.transcript.extend_from_slice(&sh_framed);
        let sh_record = record::encode_plaintext(ContentType::Handshake, &sh_framed)?;

        // Handshake secrets from CH..SH.
        let th = transcript_hash(&self.transcript);
        let (client_hs, server_hs) = self
            .schedule
            .derive_handshake_secrets(shared.as_bytes(), &th)?;
        self.client_hs = Some(client_hs);
        // Server reads client's handshake traffic, writes its own.
        self.read = Some(client_hs.direction_keys()?);

        // Build the encrypted flight.
        let flight_record = self.build_flight(server_hs)?;
        Ok((sh_record, flight_record))
    }

    /// Verify the client's `Finished` record, completing the handshake.
    ///
    /// # Errors
    /// [`TlsError::BadFinished`] if the client MAC does not verify, or a
    /// framing/crypto error.
    pub fn finish(&mut self, client_finished_record: &[u8]) -> TlsResult<()> {
        let (ct, header, body) = record::read_record(client_finished_record)?;
        if ct != ContentType::ApplicationData {
            return Err(TlsError::UnexpectedMessage);
        }
        let read = self.read.as_mut().ok_or(TlsError::UnexpectedMessage)?;
        let (inner_ct, plaintext) = read.open(header, body)?;
        if inner_ct != ContentType::Handshake {
            return Err(TlsError::UnexpectedMessage);
        }
        let messages = handshake::split_messages(&plaintext)?;
        let (ty, fin_body) = messages.into_iter().next().ok_or(TlsError::Decode)?;
        if ty != HandshakeType::Finished {
            return Err(TlsError::UnexpectedMessage);
        }
        let client_hs = self.client_hs.ok_or(TlsError::UnexpectedMessage)?;
        let th_app = self.th_app.ok_or(TlsError::UnexpectedMessage)?;
        let expected = client_hs.verify_data(&th_app)?;
        if !constant_time_eq(&expected, &fin_body) {
            return Err(TlsError::BadFinished);
        }
        // Switch server read to the client application key.
        let client_ap = self
            .pending_client_ap
            .take()
            .ok_or(TlsError::UnexpectedMessage)?;
        self.read = Some(client_ap.direction_keys()?);
        self.complete = true;
        Ok(())
    }

    /// The negotiated ALPN protocol, if any.
    #[must_use]
    pub fn alpn_protocol(&self) -> Option<&[u8]> {
        self.negotiated_alpn.as_deref()
    }

    /// Whether the handshake has completed.
    #[must_use]
    pub const fn is_complete(&self) -> bool {
        self.complete
    }

    /// Seal application data under the server application key.
    ///
    /// # Errors
    /// [`TlsError::Closed`] if the handshake is not complete.
    pub fn seal_application(&mut self, data: &[u8]) -> TlsResult<Vec<u8>> {
        if !self.complete {
            return Err(TlsError::Closed);
        }
        let write = self.write.as_mut().ok_or(TlsError::Closed)?;
        write.seal(ContentType::ApplicationData, data)
    }

    /// Open an application-data record from the client.
    ///
    /// # Errors
    /// [`TlsError::Closed`] if not complete, else a framing/crypto error.
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

    fn consume_client_hello(&mut self, record_bytes: &[u8]) -> TlsResult<ClientHello> {
        let (ct, _hdr, body) = record::read_record(record_bytes)?;
        if ct != ContentType::Handshake {
            return Err(TlsError::UnexpectedMessage);
        }
        let messages = handshake::split_messages(body)?;
        let (ty, ch_body) = messages.into_iter().next().ok_or(TlsError::Decode)?;
        if ty != HandshakeType::ClientHello {
            return Err(TlsError::UnexpectedMessage);
        }
        let framed = handshake::encode_handshake(HandshakeType::ClientHello, &ch_body)?;
        self.transcript.extend_from_slice(&framed);
        ClientHello::parse(&ch_body)
    }

    fn build_flight(&mut self, server_hs: TrafficSecret) -> TlsResult<Vec<u8>> {
        // EncryptedExtensions.
        let ee = handshake::encode_encrypted_extensions(self.negotiated_alpn.as_deref())?;
        self.transcript.extend_from_slice(&ee);

        // Certificate.
        let cert = handshake::encode_certificate(&self.config.credentials.chain)?;
        self.transcript.extend_from_slice(&cert);
        let th_through_cert = transcript_hash(&self.transcript);

        // CertificateVerify.
        let content = certificate_verify_content(true, &th_through_cert);
        let signature = self.config.credentials.signing_key.sign(&content);
        let cv = handshake::encode_certificate_verify(SIG_ED25519, &signature.to_bytes())?;
        self.transcript.extend_from_slice(&cv);
        let th_through_cv = transcript_hash(&self.transcript);

        // server Finished.
        let verify = server_hs.verify_data(&th_through_cv)?;
        let fin = handshake::encode_finished(&verify)?;
        self.transcript.extend_from_slice(&fin);

        // Seal EE||Cert||CertVerify||Finished as one Handshake record under the
        // server handshake traffic key.
        let mut plaintext = Vec::new();
        plaintext.extend_from_slice(&ee);
        plaintext.extend_from_slice(&cert);
        plaintext.extend_from_slice(&cv);
        plaintext.extend_from_slice(&fin);
        let mut write = server_hs.direction_keys()?;
        let flight_record = write.seal(ContentType::Handshake, &plaintext)?;

        // Application secrets bound to CH..server Finished.
        let th_app = transcript_hash(&self.transcript);
        self.th_app = Some(th_app);
        let (client_ap, server_ap) = self.schedule.derive_application_secrets(&th_app)?;
        self.pending_client_ap = Some(client_ap);
        // Server application writes now go under server_ap; reads stay on the
        // client handshake key until the client Finished arrives.
        self.write = Some(server_ap.direction_keys()?);
        Ok(flight_record)
    }
}

/// 32 uniformly-random bytes from a fresh `x25519` public key.
fn random_32() -> [u8; 32] {
    NexaCoreEphemeralSecret::generate().public_key().as_bytes()
}
