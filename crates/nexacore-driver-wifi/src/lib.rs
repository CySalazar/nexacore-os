//! # `nexacore-driver-wifi`
//!
//! NexaCore OS Wi-Fi driver + WPA2/WPA3 supplicant core (WS2-11).
//!
//! ## Scope
//!
//! Host-testable, `no_std + alloc`, dep-free byte-logic for Wi-Fi support on an
//! Intel `iwlwifi`-class chipset plus a WPA2/WPA3 supplicant:
//!
//! - [`regs`] — iwlwifi CSR register offsets and the host-command (`HCMD`)
//!   header/opcodes the driver writes to the device (WS2-11.1).
//! - [`frame`] — IEEE 802.11 MAC-header and management-frame parsing: the
//!   information-element iterator, beacon / probe-response decode for scan
//!   results, and authentication / association request+response builders and
//!   parsers (WS2-11.4 / WS2-11.5).
//! - [`eapol`] — the IEEE 802.1X / 802.11i EAPOL-Key frame codec and the WPA2
//!   4-way handshake state machine (WS2-11.7).
//! - [`sae`] — the WPA3 SAE Commit / Confirm message framing and the
//!   peer state machine (WS2-11.8).
//! - [`key`] — the PTK / GTK key hierarchy split and the CCMP nonce / AAD
//!   construction (WS2-11.9).
//!
//! ## Crypto seams
//!
//! 802.11i needs HMAC-SHA1 (the PRF and EAPOL-Key MIC) and AES-CCMP; SAE needs
//! finite-field / elliptic-curve crypto. `nexacore-crypto` provides
//! SHA-256/HKDF/BLAKE3 but none of those, so the deriving/authenticating steps
//! are injected through the [`eapol::Prf`] / [`eapol::KeyMic`] traits (mirroring
//! the WS5-06 FPE and WS10 certificate seam-gating). The byte layouts, the
//! handshake/SAE state machines and the key split are exercised host-side with
//! deterministic mock implementations.
//!
//! ## Out of scope (rig / device)
//!
//! Firmware (uCode) load via `DmaMap`, the TX/RX queue rings, `IrqAttach`
//! (WS2-11.2/.3/.6), the network-stack link provider (WS2-11.10, WS4), the
//! settings UI (WS2-11.11, WS7) and real-laptop-HW association + DHCP
//! (WS2-11.12) all land later.

#![doc(html_root_url = "https://docs.nexacore-os.org/nexacore-driver-wifi")]
#![cfg_attr(not(test), no_std)]
#![deny(missing_docs)]
// Test-only allow list — mirrors the precedent set by `nexacore-driver-ahci`
// (WS2-07) and `nexacore-driver-tpm` (WS2-15). Tests use `.unwrap()` for
// terseness; production code keeps the workspace deny invariants.
#![cfg_attr(
    test,
    allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::indexing_slicing,
    )
)]

extern crate alloc;

pub mod eapol;
pub mod frame;
pub mod key;
pub mod regs;
pub mod sae;
