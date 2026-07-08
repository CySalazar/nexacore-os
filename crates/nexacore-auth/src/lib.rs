//! # `nexacore-auth`
//!
//! Host-testable core of NexaCore OS's users / auth / identity layer (WS12-05).
//!
//! NexaCore starts as an implicit single-root system; this crate is the
//! device-independent half of turning it multi-user: a user-store schema,
//! passphrase hashing, a PAM-class pluggable authentication stack, per-user
//! privileges (the per-user root capability), per-user home-key derivation, and
//! account creation. Every strength- or platform-critical effect sits behind a
//! trait so the orchestration logic is exercised entirely host-side.
//!
//! ## Modules
//!
//! - [`hash`] (WS12-05.2) — [`hash::Credential`] and the [`hash::PasswordHasher`]
//!   seam. The crate ships a BLAKE3 placeholder; the production memory-hard
//!   **Argon2id** (`nexacore-crypto::kdf`) plugs in behind the trait. Credential
//!   verification is constant-time.
//! - [`store`] (WS12-05.1/.5/.6/.7) — [`store::UserStore`] and
//!   [`store::UserRecord`] (the schema), [`store::Privileges`] (the per-user
//!   root capability), [`store::derive_home_key`] (per-user home encryption
//!   key), and [`store::create_account`].
//! - [`auth`] (WS12-05.4) — [`auth::AuthStack`], a PAM-style ordered stack of
//!   [`auth::AuthModule`]s with `required` / `requisite` / `sufficient` /
//!   `optional` control flow, plus [`auth::PasswordModule`].
//!
//! The TEE-bound credential (WS12-05.3) is the caller's sealing provider
//! (WS10-08); this crate never holds the master secret. Greeter integration
//! (WS12-05.8, WS7-15) and the VM-103 multi-user tests (.9/.10) are downstream.
//!
//! ## `no_std` + `alloc`
//!
//! `#![no_std]`, pulling only `alloc` (and BLAKE3 for the placeholder hasher /
//! home-key derivation), so it compiles for `x86_64-unknown-none` as well as
//! the developer host.

#![no_std]
#![deny(missing_docs)]
#![cfg_attr(
    test,
    allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::indexing_slicing,
        clippy::missing_docs_in_private_items,
    )
)]

extern crate alloc;

pub mod auth;
pub mod hash;
pub mod store;

/// Errors from identity and account-management operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthError {
    /// The username is already registered in the store.
    UsernameTaken,
    /// The uid is already registered in the store.
    UidTaken,
    /// The username is empty or contains a path separator.
    InvalidUsername,
    /// No user with the given uid or name exists.
    UserNotFound,
}
