//! # `nexacore-tls`
//!
//! A `no_std + alloc` implementation of **TLS 1.3** (RFC 8446) layered above
//! the NexaCore socket API, built on `nexacore-crypto` primitives.
//!
//! ## Scope (WS4-03)
//!
//! | Area | Module | Status |
//! |------|--------|--------|
//! | Architecture over the socket API | [`stream`] | host-tested |
//! | Record layer (framing + AEAD) | [`record`] | host-tested |
//! | Key schedule (HKDF-Expand-Label, Derive-Secret) | [`keyschedule`] | host-tested |
//! | Client handshake | [`client`] | host-tested |
//! | Server handshake | [`server`] | host-tested |
//! | Cert store + trust anchors | [`certstore`] | host-tested |
//! | Chain / constraint verification | [`certstore`] | host-tested |
//! | ALPN negotiation | [`alpn`] | host-tested |
//!
//! ## Supported profile
//!
//! Exactly one value in each negotiable dimension, chosen to match the
//! primitives `nexacore-crypto` exposes:
//!
//! * cipher suite `TLS_CHACHA20_POLY1305_SHA256` (`0x1303`)
//! * key exchange group `x25519` (`0x001D`)
//! * signature scheme `ed25519` (`0x0807`)
//! * protocol version `TLS 1.3` (`0x0304`)
//!
//! Anything else is refused with [`error::TlsError::NoCommonParameters`]
//! (fail-closed negotiation).
//!
//! ## What is *not* here
//!
//! Full X.509/DER parsing with RSA and ECDSA is out of scope: the certificate
//! **path logic** is implemented and tested against a bundled `ed25519`
//! certificate format ([`certstore::NexaCertVerifier`]), while interop with a
//! real OpenSSL chain (WS4-03.10) is the deferred rig goal. `0-RTT`, PSK
//! resumption, `HelloRetryRequest`, and client authentication are likewise
//! future work.
//!
//! ## Example
//!
//! An in-process handshake — the same code the tests exercise — is available
//! through [`client::ClientConnection`] and [`server::ServerConnection`].

#![no_std]
#![forbid(unsafe_code)]
#![deny(missing_docs)]
#![cfg_attr(
    test,
    allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::indexing_slicing,
        clippy::missing_docs_in_private_items
    )
)]

extern crate alloc;

pub mod alert;
pub mod alpn;
pub mod auth;
pub mod certstore;
pub mod client;
pub mod codec;
pub mod error;
pub mod handshake;
pub mod keyschedule;
pub mod params;
pub mod record;
pub mod server;
pub mod stream;
mod util;

pub use error::{TlsError, TlsResult};
