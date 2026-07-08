//! Fuzz target: `NexaCoreVerifyingKey::verify` must not panic on any input.
//!
//! Splits the input into a fixed pubkey (32 B), a fixed signature
//! (64 B), and an arbitrary message tail. The function MUST return
//! either `Ok(())` or `Err(NexaCoreError::Crypto { kind: InvalidSignature
//! | InvalidKey, .. })` — never panic.

#![no_main]

use libfuzzer_sys::fuzz_target;
use nexacore_crypto::signing::{
    NexaCoreSignature, NexaCoreVerifyingKey, SIGNATURE_LEN, VERIFYING_KEY_LEN,
};

fuzz_target!(|data: &[u8]| {
    if data.len() < VERIFYING_KEY_LEN + SIGNATURE_LEN {
        return;
    }
    let mut pk_bytes = [0u8; VERIFYING_KEY_LEN];
    pk_bytes.copy_from_slice(&data[..VERIFYING_KEY_LEN]);
    let mut sig_bytes = [0u8; SIGNATURE_LEN];
    sig_bytes.copy_from_slice(
        &data[VERIFYING_KEY_LEN..VERIFYING_KEY_LEN + SIGNATURE_LEN],
    );

    // `from_bytes` may legitimately reject pk_bytes (off-curve points).
    let Ok(vk) = NexaCoreVerifyingKey::from_bytes(&pk_bytes) else {
        return;
    };
    let sig = NexaCoreSignature::from_bytes(sig_bytes);
    let msg = &data[VERIFYING_KEY_LEN + SIGNATURE_LEN..];

    let _ = vk.verify(msg, &sig);
});
