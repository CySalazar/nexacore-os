//! Fuzz target: the postcard canonical wire decoder must never panic on
//! arbitrary input (WS13-02.2).
//!
//! `decode_canonical::<T>` is the trust boundary for every wire-format message
//! the OS ingests. On any byte slice it MUST return `Ok(_)` or
//! `Err(NexaCoreError::Wire { .. })` — never panic, never overflow, never run
//! unboundedly. We decode the same bytes into several representative shapes
//! (variable-length, nested, scalar) to exercise the length-prefix and varint
//! paths.

#![no_main]

use libfuzzer_sys::fuzz_target;
use nexacore_types::wire::decode_canonical;

fuzz_target!(|data: &[u8]| {
    // Variable-length byte vector (length-prefixed path).
    let _ = decode_canonical::<Vec<u8>>(data);
    // UTF-8 string (length-prefix + validity path).
    let _ = decode_canonical::<String>(data);
    // Nested/variable: a vector of strings.
    let _ = decode_canonical::<Vec<String>>(data);
    // Fixed scalars (varint path).
    let _ = decode_canonical::<u64>(data);
    let _ = decode_canonical::<(u32, i64, bool)>(data);
});
