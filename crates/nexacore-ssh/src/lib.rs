//! # `nexacore-ssh`
//!
//! The SSH-2 transport layer for NexaCore OS (WS4-06.1), built over the
//! `nexacore-crypto` primitives.
//!
//! | Concern | Item |
//! |---------|------|
//! | SSH wire data types (RFC 4251 §5) | [`wire::Reader`], [`wire::Writer`] |
//! | Binary packet protocol + AEAD channel (RFC 4253 §6) | [`packet`] |
//! | KEXINIT, negotiation, exchange hash, key derivation | [`kex`] |
//! | Handshake state machine + encrypted session | [`transport`] |
//! | Connection-protocol channels + flow control (RFC 4254) | [`channel`] |
//!
//! ## What this provides
//!
//! The transport half of SSH-2: identification-string exchange, algorithm
//! negotiation, `curve25519-sha256` key exchange (RFC 8731), Ed25519 host-key
//! authentication of the exchange hash, `NEWKEYS`, and an AEAD packet channel.
//! [`transport::client_handshake`] / [`transport::server_handshake`] run it end
//! to end and return a [`transport::Session`] carrying application payloads.
//!
//! Authentication (`publickey`/`password`, WS4-06.2) and the `ssh`/`scp`
//! commands (WS4-06.4/.5) layer on top of this session. Channel multiplexing
//! and flow control (WS4-06.3) ride over it via [`channel::ChannelTable`].
//!
//! ## Cipher profile
//!
//! The packet cipher is ChaCha20-Poly1305 under a documented *NexaCore SSH
//! AEAD profile* (see [`packet`]). It is not byte-compatible with
//! `chacha20-poly1305@openssh.com`, whose separate length-encryption key needs
//! raw ChaCha20 block access that `nexacore-crypto`'s combined AEAD does not
//! expose — wire interop with stock OpenSSH is a documented seam, mirroring the
//! `nexacore-tls` X.509 gap.
//!
//! `no_std + alloc`. The `rng` feature of `nexacore-crypto` (ephemeral keys)
//! pulls `getrandom`, so the bare-metal `x86_64-unknown-none` gate is N/A, as
//! for `nexacore-tls`.

#![no_std]
#![forbid(unsafe_code)]
#![deny(missing_docs)]

extern crate alloc;

pub mod auth;
pub mod channel;
pub mod error;
pub mod kex;
pub mod packet;
pub mod transport;
pub mod wire;

pub use channel::ChannelTable;
pub use error::SshError;
pub use transport::{Session, Transport, client_handshake, server_handshake};
