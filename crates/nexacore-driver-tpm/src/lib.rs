//! # `nexacore-driver-tpm`
//!
//! Host-testable core of the NexaCore OS discrete-TPM 2.0 driver (WS2-15). The
//! correctness that is *byte layout* — the TPM 2.0 command/response wire format
//! — lives here as pure `no_std` logic and is unit tested on the host; the MMIO
//! locality handshake and command/response transfer that can only be confirmed
//! against a real (or emulated `swtpm`) TPM stay in the bring-up shell.
//!
//! * **[`regs`]** — the TIS (TPM Interface Specification, `0xFED4_xxxx`) and CRB
//!   (Command Response Buffer) MMIO register maps with their status bits
//!   (WS2-15.1 / WS2-15.2).
//! * **[`cmd`]** — TPM 2.0 command serialization (TPM 2.0 Part 1 § 18, Part 3):
//!   the [`cmd::TpmCommand`] builder (big-endian header + back-patched size),
//!   the password authorization area, [`cmd::build_pcr_extend`] (WS2-15.5),
//!   [`cmd::build_quote`] (WS2-15.6), and [`cmd::parse_response_header`].
//! * **[`pcr`]** — the measured-boot PCR bank, extend chain, and event log
//!   (WS10-05.5 / .6 / .11).
//! * **[`quote`]** — the `TPM2_Quote` attestation `TPMS_ATTEST` /
//!   `TPMS_QUOTE_INFO`: `pcrDigest` over the measured bank
//!   ([`nexacore_crypto`] hash), canonical marshalling, and the
//!   [`quote::QuoteSigner`] signing seam (WS10-05.7).
//!
//! The locality acquire/release + command/response buffer transfer (WS2-15.3),
//! the live command round-trip (WS2-15.4 hardware half), the `nexacore-tee`
//! integration (WS2-15.7), and the swtpm end-to-end (WS2-15.9) are device-side.

#![no_std]
#![doc(html_root_url = "https://docs.nexacore-os.org/nexacore-driver-tpm")]
#![deny(missing_docs)]
// TPM is a big-endian wire protocol assembled from bytes; `as` truncation in the
// serializers is inherent and each site is bounds-reasoned.
#![allow(clippy::cast_possible_truncation)]
// PCR-index → (byte, bit) divides by the constant 8.
#![allow(clippy::integer_division)]
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

pub mod cmd;
pub mod pcr;
pub mod quote;
pub mod regs;

pub use cmd::{TpmCommand, TpmError, build_pcr_extend, build_quote, parse_response_header};
pub use quote::{
    Attest, ClockInfo, Quote, QuoteError, QuoteRequest, QuoteSigner, generate_quote, pcr_digest,
    selected_pcr_values,
};
