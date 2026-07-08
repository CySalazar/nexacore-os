//! Fuzz target: the IP packet parsers must never panic on a malformed frame
//! (WS13-02.4).
//!
//! `parse_ipv4_packet` / `parse_ipv6_packet` are the trust boundary for raw
//! bytes arriving off the NIC. On any slice they MUST return `Some((header,
//! payload))` or `None` — never panic on a short header, a bogus IHL/total-
//! length, or a truncated extension chain. The returned payload slice must stay
//! within `data`, so we touch it to force any out-of-bounds slice to fault
//! under the sanitizer.

#![no_main]

use libfuzzer_sys::fuzz_target;
use nexacore_net::ip::{parse_ipv4_packet, parse_ipv6_packet};

fuzz_target!(|data: &[u8]| {
    if let Some((_hdr, payload)) = parse_ipv4_packet(data) {
        // Force the returned slice to be read so an out-of-range payload
        // pointer faults instead of silently aliasing.
        let _ = payload.iter().fold(0u8, |a, &b| a ^ b);
    }
    if let Some((_hdr, payload)) = parse_ipv6_packet(data) {
        let _ = payload.iter().fold(0u8, |a, &b| a ^ b);
    }
});
