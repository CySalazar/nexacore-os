//! The TLS-over-socket architecture (WS4-03.1).
//!
//! The handshake state machines in [`crate::client`] / [`crate::server`] are
//! pure flight-in / flight-out logic. This module defines the thin seam that
//! carries their record buffers over a byte transport — in production the
//! NexaCore socket API, in tests an in-memory pipe.
//!
//! A [`RecordTransport`] moves whole TLS records. The stream drivers
//! ([`TlsClientStream`], [`TlsServerStream`]) run the handshake to completion
//! over any transport and then expose `write` / `read` for application data.
//! Keeping the socket dependency behind a trait is what lets the entire TLS
//! stack be unit-tested on the host without a network.

use alloc::vec::Vec;

use crate::{
    certstore::CertVerifier,
    client::{ClientConfig, ClientConnection},
    error::TlsResult,
    server::{ServerConfig, ServerConnection},
};

/// A transport that carries whole TLS records.
///
/// The implementer is responsible for reading exactly one record per
/// [`RecordTransport::recv_record`] (read the 5-byte header, then the declared
/// body length) and for writing a record atomically.
pub trait RecordTransport {
    /// Send one complete record.
    ///
    /// # Errors
    /// [`crate::TlsError::Closed`] if the underlying transport is gone.
    fn send(&mut self, record: &[u8]) -> TlsResult<()>;

    /// Receive the next complete record.
    ///
    /// # Errors
    /// [`crate::TlsError::Closed`] at end of stream.
    fn recv_record(&mut self) -> TlsResult<Vec<u8>>;
}

/// A completed client TLS stream over a transport `T`.
pub struct TlsClientStream<T: RecordTransport, V: CertVerifier> {
    conn: ClientConnection<V>,
    transport: T,
}

impl<T: RecordTransport, V: CertVerifier> TlsClientStream<T, V> {
    /// Run the full client handshake over `transport`, returning the connected
    /// stream ready for application data.
    ///
    /// # Errors
    /// Any [`crate::TlsError`] from the handshake or transport.
    pub fn connect(config: ClientConfig, verifier: V, mut transport: T) -> TlsResult<Self> {
        let (mut conn, client_hello) = ClientConnection::start(config, verifier)?;
        transport.send(&client_hello)?;
        let server_hello = transport.recv_record()?;
        let flight = transport.recv_record()?;
        let client_finished = conn.process_flight(&server_hello, &flight)?;
        transport.send(&client_finished)?;
        Ok(Self { conn, transport })
    }

    /// The negotiated ALPN protocol, if any.
    #[must_use]
    pub fn alpn_protocol(&self) -> Option<&[u8]> {
        self.conn.alpn_protocol()
    }

    /// Encrypt and send application data.
    ///
    /// # Errors
    /// Any [`crate::TlsError`] from sealing or the transport.
    pub fn write(&mut self, data: &[u8]) -> TlsResult<()> {
        let record = self.conn.seal_application(data)?;
        self.transport.send(&record)
    }

    /// Receive and decrypt one application-data record.
    ///
    /// # Errors
    /// Any [`crate::TlsError`] from the transport or opening.
    pub fn read(&mut self) -> TlsResult<Vec<u8>> {
        let record = self.transport.recv_record()?;
        self.conn.open_application(&record)
    }
}

/// A completed server TLS stream over a transport `T`.
pub struct TlsServerStream<T: RecordTransport> {
    conn: ServerConnection,
    transport: T,
}

impl<T: RecordTransport> TlsServerStream<T> {
    /// Run the full server handshake over `transport`, returning the connected
    /// stream.
    ///
    /// # Errors
    /// Any [`crate::TlsError`] from the handshake or transport.
    pub fn accept(config: ServerConfig, mut transport: T) -> TlsResult<Self> {
        let mut conn = ServerConnection::new(config);
        let client_hello = transport.recv_record()?;
        let (server_hello, flight) = conn.accept(&client_hello)?;
        transport.send(&server_hello)?;
        transport.send(&flight)?;
        let client_finished = transport.recv_record()?;
        conn.finish(&client_finished)?;
        Ok(Self { conn, transport })
    }

    /// The negotiated ALPN protocol, if any.
    #[must_use]
    pub fn alpn_protocol(&self) -> Option<&[u8]> {
        self.conn.alpn_protocol()
    }

    /// Encrypt and send application data.
    ///
    /// # Errors
    /// Any [`crate::TlsError`] from sealing or the transport.
    pub fn write(&mut self, data: &[u8]) -> TlsResult<()> {
        let record = self.conn.seal_application(data)?;
        self.transport.send(&record)
    }

    /// Receive and decrypt one application-data record.
    ///
    /// # Errors
    /// Any [`crate::TlsError`] from the transport or opening.
    pub fn read(&mut self) -> TlsResult<Vec<u8>> {
        let record = self.transport.recv_record()?;
        self.conn.open_application(&record)
    }
}

/// An in-memory record pipe for host tests: two FIFO queues wired
/// client↔server. Not part of the production path.
#[derive(Default)]
pub struct MemoryPipe {
    /// Records queued for the peer to read.
    outbound: alloc::collections::VecDeque<Vec<u8>>,
}

impl MemoryPipe {
    /// A new empty pipe endpoint.
    #[must_use]
    pub fn new() -> Self {
        Self {
            outbound: alloc::collections::VecDeque::new(),
        }
    }

    /// Push a record for the peer.
    pub fn push(&mut self, record: Vec<u8>) {
        self.outbound.push_back(record);
    }

    /// Pop the next record, if any.
    #[must_use]
    pub fn pop(&mut self) -> Option<Vec<u8>> {
        self.outbound.pop_front()
    }

    /// Whether any records are queued.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.outbound.is_empty()
    }
}
