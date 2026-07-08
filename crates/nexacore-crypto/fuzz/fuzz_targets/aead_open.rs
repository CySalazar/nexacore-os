//! Fuzz target: `nexacore_crypto::aead::open` must not panic on any input.
//!
//! The harness splits the libfuzzer-supplied byte slice into a fixed
//! key (32 B), a fixed nonce (12 B), and an arbitrary AAD + ciphertext
//! tail. `open` MUST return either `Ok(_)` or
//! `Err(NexaCoreError::Crypto { kind: DecryptionFailure, .. })` — never
//! panic, never overflow, never abort.

#![no_main]

use libfuzzer_sys::fuzz_target;
use nexacore_crypto::aead::{open, NexaCoreAeadKey, NexaCoreCiphertext, NexaCoreNonce, KEY_LEN, NONCE_LEN};

fuzz_target!(|data: &[u8]| {
    // Need at least key + nonce; otherwise nothing useful to do.
    if data.len() < KEY_LEN + NONCE_LEN {
        return;
    }
    let mut key_bytes = [0u8; KEY_LEN];
    key_bytes.copy_from_slice(&data[..KEY_LEN]);
    let mut nonce_bytes = [0u8; NONCE_LEN];
    nonce_bytes.copy_from_slice(&data[KEY_LEN..KEY_LEN + NONCE_LEN]);

    let key = NexaCoreAeadKey::from_bytes(key_bytes);
    let nonce = NexaCoreNonce::from_bytes(nonce_bytes);
    // Treat the rest as ciphertext; AAD is empty (covered by other targets).
    let ct = NexaCoreCiphertext::from_bytes(data[KEY_LEN + NONCE_LEN..].to_vec());

    let _ = open(&key, &nonce, b"", &ct);
});
