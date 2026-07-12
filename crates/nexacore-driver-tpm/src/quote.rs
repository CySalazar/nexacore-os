//! TPM 2.0 `TPM2_Quote` attestation data (WS10-05.7).
//!
//! A quote is the TPM's signed statement "these PCRs currently hold these
//! values". The signed body is a `TPMS_ATTEST` structure (TPM 2.0 Part 2
//! § 10.12.8) whose `attested` union carries a `TPMS_QUOTE_INFO`
//! (§ 10.12.5): a [`PcrSelection`] plus a `pcrDigest` — the hash of the
//! concatenated selected PCR values. The whole `TPMS_ATTEST` is then signed
//! by the Attestation Key (AK) so a remote verifier can check both the
//! signature and, by replaying the measured-boot log ([`crate::pcr`]), the
//! `pcrDigest`.
//!
//! This module builds and marshals the `TPMS_ATTEST` to the canonical
//! big-endian TPM wire form and computes the `pcrDigest` with
//! [`nexacore_crypto`]'s hash for the bank algorithm (SHA-256 for the
//! measured bank). Signing is abstracted behind the [`QuoteSigner`] seam so
//! the host build can exercise the full quote path with a deterministic
//! double instead of real TPM hardware; on-device, the seam is backed by a
//! `TPM2_Quote` command round-trip ([`crate::cmd::build_quote`]).

use alloc::vec::Vec;

use nexacore_crypto::hash::{NexaCoreHash, Sha256H};

use crate::{
    cmd::{PcrSelection, TPM_ALG_SHA256},
    pcr::{ExtendHash, PCR_COUNT, PcrBank, PcrValue},
};

/// `TPM_GENERATED_VALUE` — the magic that prefixes every TPM-produced
/// attestation, proving the structure originated inside a TPM (`"\xffTCG"`).
pub const TPM_GENERATED_VALUE: u32 = 0xFF54_4347;

/// `TPM_ST_ATTEST_QUOTE` — the `TPMI_ST_ATTEST` tag for a quote.
pub const TPM_ST_ATTEST_QUOTE: u16 = 0x8018;

/// `sizeofSelect` for the 24-PCR platform bank (3 bytes = 24 bits).
pub const PCR_SELECT_SIZE: u8 = 3;

/// Why a quote could not be built or a `TPMS_ATTEST` could not be parsed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QuoteError {
    /// The PCR bank algorithm has no matching [`nexacore_crypto`] hash.
    UnsupportedAlg,
    /// The buffer ended before a field could be read.
    Truncated,
    /// A structural field was inconsistent (e.g. unexpected selection count).
    Malformed,
}

/// `TPMS_CLOCK_INFO` (TPM 2.0 Part 2 § 10.11.1) — the TPM's monotonic time
/// and reboot counters, folded into the attestation so a verifier can order
/// quotes and detect resets.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClockInfo {
    /// Milliseconds since the TPM's clock was last reset.
    pub clock: u64,
    /// Number of times the TPM has been power-cycled (`resetCount`).
    pub reset_count: u32,
    /// Number of times the TPM has restarted without losing state
    /// (`restartCount`).
    pub restart_count: u32,
    /// `safe` — whether `clock` is guaranteed not to have gone backwards.
    pub safe: bool,
}

/// The signer of a quote: it takes the marshalled `TPMS_ATTEST` and returns
/// the AK signature over it. The on-device implementation issues a
/// `TPM2_Quote`; host tests supply a deterministic double.
pub trait QuoteSigner {
    /// Sign the marshalled `TPMS_ATTEST` bytes with the AK.
    fn sign(&self, attest: &[u8]) -> Vec<u8>;
}

/// The inputs to a quote, grouped so the high-level [`generate_quote`] stays
/// under the argument-count budget.
#[derive(Debug, Clone, Copy)]
pub struct QuoteRequest<'a> {
    /// The AK name that goes in `qualifiedSigner` (a `TPM2B_NAME`).
    pub ak_name: &'a [u8],
    /// The caller-supplied nonce bound into `extraData` (a `TPM2B_DATA`),
    /// making the quote fresh / non-replayable.
    pub nonce: &'a [u8],
    /// The TPM clock / reboot counters at quote time.
    pub clock_info: ClockInfo,
    /// The TPM `firmwareVersion`.
    pub firmware_version: u64,
    /// The PCR bank algorithm (e.g. [`TPM_ALG_SHA256`]).
    pub bank_alg: u16,
    /// Which PCRs are quoted.
    pub selection: PcrSelection,
}

/// A `TPMS_ATTEST` carrying a `TPMS_QUOTE_INFO` (TPM 2.0 Part 2 § 10.12.8 /
/// § 10.12.5). The fields are public so a verifier can inspect a parsed
/// quote; use [`Attest::quote`] to build one for signing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Attest {
    /// `magic` — must be [`TPM_GENERATED_VALUE`].
    pub magic: u32,
    /// `type` — [`TPM_ST_ATTEST_QUOTE`] for a quote.
    pub kind: u16,
    /// `qualifiedSigner` — the AK name.
    pub qualified_signer: Vec<u8>,
    /// `extraData` — the caller nonce.
    pub extra_data: Vec<u8>,
    /// `clockInfo`.
    pub clock_info: ClockInfo,
    /// `firmwareVersion`.
    pub firmware_version: u64,
    /// The bank algorithm of the quoted `TPML_PCR_SELECTION`.
    pub bank_alg: u16,
    /// `pcrSelect` — which PCRs the digest covers.
    pub pcr_select: PcrSelection,
    /// `pcrDigest` — the hash over the concatenated selected PCR values.
    pub pcr_digest: Vec<u8>,
}

/// A generated quote: the marshalled `TPMS_ATTEST` and the AK signature over
/// it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Quote {
    /// The canonical `TPMS_ATTEST` wire bytes that were signed.
    pub attest: Vec<u8>,
    /// The AK signature over [`Quote::attest`].
    pub signature: Vec<u8>,
}

impl Attest {
    /// Build a quote `TPMS_ATTEST` from `request` and a pre-computed
    /// `pcr_digest` (see [`pcr_digest`]).
    #[must_use]
    pub fn quote(request: &QuoteRequest<'_>, pcr_digest: Vec<u8>) -> Self {
        Self {
            magic: TPM_GENERATED_VALUE,
            kind: TPM_ST_ATTEST_QUOTE,
            qualified_signer: request.ak_name.to_vec(),
            extra_data: request.nonce.to_vec(),
            clock_info: request.clock_info,
            firmware_version: request.firmware_version,
            bank_alg: request.bank_alg,
            pcr_select: request.selection,
            pcr_digest,
        }
    }

    /// Marshal to the canonical big-endian `TPMS_ATTEST` wire form.
    #[must_use]
    pub fn marshal(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        put_u32(&mut buf, self.magic);
        put_u16(&mut buf, self.kind);
        put_tpm2b(&mut buf, &self.qualified_signer);
        put_tpm2b(&mut buf, &self.extra_data);
        // clockInfo
        put_u64(&mut buf, self.clock_info.clock);
        put_u32(&mut buf, self.clock_info.reset_count);
        put_u32(&mut buf, self.clock_info.restart_count);
        buf.push(u8::from(self.clock_info.safe));
        put_u64(&mut buf, self.firmware_version);
        // attested: TPMS_QUOTE_INFO { pcrSelect: TPML_PCR_SELECTION, pcrDigest }.
        put_u32(&mut buf, 1); // count — one bank
        put_u16(&mut buf, self.bank_alg);
        buf.push(PCR_SELECT_SIZE);
        buf.extend_from_slice(&self.pcr_select.bitmap());
        put_tpm2b(&mut buf, &self.pcr_digest);
        buf
    }

    /// Parse a `TPMS_ATTEST` (quote form) back from its wire bytes.
    ///
    /// # Errors
    ///
    /// [`QuoteError::Truncated`] if the buffer ends early; [`QuoteError::Malformed`]
    /// if a structural field is inconsistent.
    pub fn parse(buf: &[u8]) -> Result<Self, QuoteError> {
        let mut r = Reader::new(buf);
        let magic = r.u32()?;
        let kind = r.u16()?;
        let qualified_signer = r.tpm2b()?;
        let extra_data = r.tpm2b()?;
        let clock_info = ClockInfo {
            clock: r.u64()?,
            reset_count: r.u32()?,
            restart_count: r.u32()?,
            safe: r.u8()? != 0,
        };
        let firmware_version = r.u64()?;
        // TPML_PCR_SELECTION — this model quotes exactly one bank.
        if r.u32()? != 1 {
            return Err(QuoteError::Malformed);
        }
        let bank_alg = r.u16()?;
        if r.u8()? != PCR_SELECT_SIZE {
            return Err(QuoteError::Malformed);
        }
        let bitmap: [u8; 3] = r
            .take(PCR_SELECT_SIZE as usize)?
            .try_into()
            .map_err(|_| QuoteError::Truncated)?;
        let pcr_select = PcrSelection::from_bitmap(bitmap);
        let pcr_digest = r.tpm2b()?;
        Ok(Self {
            magic,
            kind,
            qualified_signer,
            extra_data,
            clock_info,
            firmware_version,
            bank_alg,
            pcr_select,
            pcr_digest,
        })
    }
}

// -----------------------------------------------------------------------------
// Big-endian marshalling helpers.
// -----------------------------------------------------------------------------

fn put_u16(buf: &mut Vec<u8>, v: u16) {
    buf.extend_from_slice(&v.to_be_bytes());
}

fn put_u32(buf: &mut Vec<u8>, v: u32) {
    buf.extend_from_slice(&v.to_be_bytes());
}

fn put_u64(buf: &mut Vec<u8>, v: u64) {
    buf.extend_from_slice(&v.to_be_bytes());
}

/// Append a `TPM2B` (a `u16` length prefix followed by the bytes).
fn put_tpm2b(buf: &mut Vec<u8>, bytes: &[u8]) {
    put_u16(buf, bytes.len() as u16);
    buf.extend_from_slice(bytes);
}

/// A forward-only, bounds-checked cursor over the wire bytes.
struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    const fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8], QuoteError> {
        let end = self.pos.checked_add(n).ok_or(QuoteError::Truncated)?;
        let slice = self.buf.get(self.pos..end).ok_or(QuoteError::Truncated)?;
        self.pos = end;
        Ok(slice)
    }

    fn u8(&mut self) -> Result<u8, QuoteError> {
        self.take(1)?.first().copied().ok_or(QuoteError::Truncated)
    }

    fn u16(&mut self) -> Result<u16, QuoteError> {
        let b: [u8; 2] = self
            .take(2)?
            .try_into()
            .map_err(|_| QuoteError::Truncated)?;
        Ok(u16::from_be_bytes(b))
    }

    fn u32(&mut self) -> Result<u32, QuoteError> {
        let b: [u8; 4] = self
            .take(4)?
            .try_into()
            .map_err(|_| QuoteError::Truncated)?;
        Ok(u32::from_be_bytes(b))
    }

    fn u64(&mut self) -> Result<u64, QuoteError> {
        let b: [u8; 8] = self
            .take(8)?
            .try_into()
            .map_err(|_| QuoteError::Truncated)?;
        Ok(u64::from_be_bytes(b))
    }

    fn tpm2b(&mut self) -> Result<Vec<u8>, QuoteError> {
        let len = self.u16()? as usize;
        Ok(self.take(len)?.to_vec())
    }
}

/// Collect the values of the selected PCRs from `bank`, in ascending PCR
/// index order — the order the TPM hashes them for the `pcrDigest`.
#[must_use]
pub fn selected_pcr_values<H: ExtendHash>(
    bank: &PcrBank<H>,
    selection: PcrSelection,
) -> Vec<PcrValue> {
    let mut out = Vec::new();
    for index in 0..PCR_COUNT {
        let idx = index as u8;
        if selection.is_selected(idx) {
            if let Some(value) = bank.pcr(idx) {
                out.push(value);
            }
        }
    }
    out
}

/// Compute the quoted `pcrDigest`: the `bank_alg` hash over the selected PCR
/// `values` concatenated in ascending index order.
///
/// # Errors
///
/// [`QuoteError::UnsupportedAlg`] if `bank_alg` has no matching hash.
pub fn pcr_digest(bank_alg: u16, values: &[PcrValue]) -> Result<Vec<u8>, QuoteError> {
    let mut concat = Vec::with_capacity(core::mem::size_of_val(values));
    for value in values {
        concat.extend_from_slice(value);
    }
    match bank_alg {
        TPM_ALG_SHA256 => Ok(Sha256H::hash(&concat).to_vec()),
        _ => Err(QuoteError::UnsupportedAlg),
    }
}

/// Build and sign a quote over the selected measured PCRs of `bank`.
///
/// Collects the selected PCR values, computes the `pcrDigest`, marshals the
/// `TPMS_ATTEST`, and signs it through the [`QuoteSigner`] seam.
///
/// # Errors
///
/// [`QuoteError::UnsupportedAlg`] if the bank algorithm has no matching hash.
pub fn generate_quote<H: ExtendHash, S: QuoteSigner>(
    bank: &PcrBank<H>,
    request: &QuoteRequest<'_>,
    signer: &S,
) -> Result<Quote, QuoteError> {
    let values = selected_pcr_values(bank, request.selection);
    let digest = pcr_digest(request.bank_alg, &values)?;
    let attest = Attest::quote(request, digest).marshal();
    let signature = signer.sign(&attest);
    Ok(Quote { attest, signature })
}

#[cfg(test)]
mod tests {
    use alloc::vec;

    use super::*;

    /// The same deterministic, order-sensitive SHA-256 stand-in `pcr.rs` uses
    /// to exercise the extend chain (FNV-1a spread over 32 bytes).
    struct TestHash;

    impl ExtendHash for TestHash {
        fn hash(&self, data: &[u8]) -> PcrValue {
            let mut acc = 0xcbf2_9ce4_8422_2325u64;
            for &b in data {
                acc = (acc ^ u64::from(b)).wrapping_mul(0x0000_0100_0000_01b3);
            }
            let mut out = [0u8; 32];
            for (i, slot) in out.iter_mut().enumerate() {
                let mixed = acc
                    .wrapping_add(i as u64)
                    .wrapping_mul(0x9E37_79B9_7F4A_7C15);
                *slot = (mixed >> ((i % 8) * 8)) as u8;
            }
            out
        }
    }

    /// A deterministic signing double: the "signature" is a domain-tagged
    /// hash of the attest, so tests can recompute it without a real AK.
    struct DoubleSigner;

    impl QuoteSigner for DoubleSigner {
        fn sign(&self, attest: &[u8]) -> Vec<u8> {
            let mut out = Sha256H::hash(attest).to_vec();
            out.push(0xAA);
            out
        }
    }

    fn measured_bank() -> PcrBank<TestHash> {
        let mut bank = PcrBank::new(TestHash);
        bank.measure(0, b"bootloader-image", "bootloader").unwrap();
        bank.measure(0, b"kernel-image", "kernel").unwrap();
        bank.measure(4, b"driver-manifest", "drivers").unwrap();
        bank.measure(7, b"secure-boot-policy", "policy").unwrap();
        bank
    }

    fn selection_047() -> PcrSelection {
        let mut sel = PcrSelection::new();
        sel.select(0);
        sel.select(4);
        sel.select(7);
        sel
    }

    fn request(sel: PcrSelection, nonce: &[u8]) -> QuoteRequest<'_> {
        QuoteRequest {
            ak_name: b"AK-name-0001",
            nonce,
            clock_info: ClockInfo {
                clock: 123_456,
                reset_count: 2,
                restart_count: 1,
                safe: true,
            },
            firmware_version: 0x0001_0002_0003_0004,
            bank_alg: TPM_ALG_SHA256,
            selection: sel,
        }
    }

    #[test]
    fn pcr_digest_is_sha256_over_selected_values_in_ascending_order() {
        let bank = measured_bank();
        let sel = selection_047();

        // Independently build the ascending-order concatenation of PCRs 0/4/7.
        let mut concat = Vec::new();
        concat.extend_from_slice(&bank.pcr(0).unwrap());
        concat.extend_from_slice(&bank.pcr(4).unwrap());
        concat.extend_from_slice(&bank.pcr(7).unwrap());
        let expected = Sha256H::hash(&concat).to_vec();

        let values = selected_pcr_values(&bank, sel);
        assert_eq!(values.len(), 3);
        let digest = pcr_digest(TPM_ALG_SHA256, &values).unwrap();
        assert_eq!(digest, expected);
    }

    #[test]
    fn pcr_digest_rejects_unknown_bank_algorithm() {
        let values = vec![[7u8; 32]];
        assert_eq!(pcr_digest(0x0004, &values), Err(QuoteError::UnsupportedAlg));
    }

    #[test]
    fn changing_a_selected_pcr_changes_the_digest() {
        let bank = measured_bank();
        let sel = selection_047();
        let base = pcr_digest(TPM_ALG_SHA256, &selected_pcr_values(&bank, sel)).unwrap();

        // A different bank where PCR 7 was extended with a tampered policy.
        let mut tampered = PcrBank::new(TestHash);
        tampered
            .measure(0, b"bootloader-image", "bootloader")
            .unwrap();
        tampered.measure(0, b"kernel-image", "kernel").unwrap();
        tampered.measure(4, b"driver-manifest", "drivers").unwrap();
        tampered
            .measure(7, b"EVIL-secure-boot-policy", "policy")
            .unwrap();
        let changed = pcr_digest(TPM_ALG_SHA256, &selected_pcr_values(&tampered, sel)).unwrap();

        assert_ne!(base, changed);
    }

    #[test]
    fn pcr_select_bitmap_matches_the_selected_indices() {
        let mut sel = PcrSelection::new();
        sel.select(0);
        sel.select(7);
        sel.select(23);
        let bank = measured_bank();
        let digest = pcr_digest(TPM_ALG_SHA256, &selected_pcr_values(&bank, sel)).unwrap();
        let attest = Attest::quote(&request(sel, b"nonce"), digest);
        let bytes = attest.marshal();

        // Re-parse and confirm the selection survived with exactly those bits.
        let parsed = Attest::parse(&bytes).unwrap();
        assert_eq!(parsed.pcr_select.bitmap(), [0x81, 0x00, 0x80]);
        assert!(parsed.pcr_select.is_selected(0));
        assert!(parsed.pcr_select.is_selected(7));
        assert!(parsed.pcr_select.is_selected(23));
        assert!(!parsed.pcr_select.is_selected(4));
    }

    #[test]
    fn caller_nonce_is_bound_into_the_marshalled_attest() {
        let bank = measured_bank();
        let sel = selection_047();
        let digest = pcr_digest(TPM_ALG_SHA256, &selected_pcr_values(&bank, sel)).unwrap();

        let nonce_a = b"nonce-AAAA";
        let nonce_b = b"nonce-BBBB";
        let bytes_a = Attest::quote(&request(sel, nonce_a), digest.clone()).marshal();
        let bytes_b = Attest::quote(&request(sel, nonce_b), digest).marshal();

        // The nonce appears verbatim in the wire bytes and changes them.
        assert!(bytes_a.windows(nonce_a.len()).any(|w| w == nonce_a));
        assert_ne!(bytes_a, bytes_b);
        // And it round-trips out of `extraData`.
        assert_eq!(Attest::parse(&bytes_a).unwrap().extra_data, nonce_a);
    }

    #[test]
    fn attest_round_trips_through_marshal_and_parse() {
        let bank = measured_bank();
        let sel = selection_047();
        let digest = pcr_digest(TPM_ALG_SHA256, &selected_pcr_values(&bank, sel)).unwrap();
        let attest = Attest::quote(&request(sel, b"fresh-nonce"), digest);

        let bytes = attest.marshal();
        let parsed = Attest::parse(&bytes).unwrap();
        assert_eq!(parsed, attest);
        assert_eq!(parsed.magic, TPM_GENERATED_VALUE);
        assert_eq!(parsed.kind, TPM_ST_ATTEST_QUOTE);
    }

    #[test]
    fn generate_quote_produces_expected_digest_and_signs_the_attest() {
        let bank = measured_bank();
        let sel = selection_047();
        let req = request(sel, b"remote-challenge");

        let quote = generate_quote(&bank, &req, &DoubleSigner).unwrap();

        // The attest embeds the expected pcrDigest.
        let expected_digest = pcr_digest(TPM_ALG_SHA256, &selected_pcr_values(&bank, sel)).unwrap();
        let parsed = Attest::parse(&quote.attest).unwrap();
        assert_eq!(parsed.pcr_digest, expected_digest);
        assert_eq!(parsed.extra_data, b"remote-challenge");

        // The signature is exactly the double over the marshalled attest.
        assert_eq!(quote.signature, DoubleSigner.sign(&quote.attest));
    }
}
