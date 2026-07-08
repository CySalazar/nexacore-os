//! EAPOL-Key codec and the WPA2 4-way handshake state machine (WS2-11.7).
//!
//! The supplicant proves possession of the PMK and installs the per-session PTK
//! through the IEEE 802.11i 4-way handshake carried in IEEE 802.1X EAPOL-Key
//! frames:
//!
//! ```text
//!   AP → STA  msg1: ANonce, Ack
//!   STA → AP  msg2: SNonce, MIC, RSN IE   (STA derives the PTK here)
//!   AP → STA  msg3: Install, MIC, Secure, (encrypted GTK)
//!   STA → AP  msg4: MIC, Secure           (handshake complete)
//! ```
//!
//! [`EapolKey`] parses/builds the frame; [`Supplicant`] drives the state
//! machine. The two operations that need vetted crypto absent from
//! `nexacore-crypto` — the PRF that derives the PTK (HMAC-SHA1) and the
//! EAPOL-Key MIC (HMAC-SHA1 / AES-CMAC) — are injected through the [`Prf`] and
//! [`KeyMic`] traits; the GTK in msg3 is AES-key-wrapped under the KEK and is
//! surfaced encrypted (unwrap is the same crypto seam). Everything else — frame
//! layout, replay handling, the canonical PTK key-derivation input, and the
//! message sequencing — is host-tested with deterministic mocks.

// Lengths are bounded by the EAPOL frame size; key-data length casts to the
// 16-bit wire field are range-checked. `ptk_bits / 8` is an exact bit→byte
// conversion.
#![allow(clippy::cast_possible_truncation, clippy::integer_division)]

#[cfg(test)]
use alloc::vec;
use alloc::vec::Vec;

use crate::frame::MacAddr;

/// EAPOL protocol version 2 (802.1X-2004), what modern supplicants emit.
pub const EAPOL_VERSION: u8 = 2;
/// EAPOL packet type for an EAPOL-Key frame.
pub const EAPOL_TYPE_KEY: u8 = 3;
/// Key-descriptor type for the RSN (WPA2) key descriptor.
pub const KEY_DESC_TYPE_RSN: u8 = 2;

/// Length of the EAPOL header (version, type, length).
pub const EAPOL_HEADER_LEN: usize = 4;
/// Length of the fixed EAPOL-Key body (before the variable key-data field).
pub const KEY_BODY_FIXED_LEN: usize = 95;
/// Offset of the 16-byte Key MIC field within the full EAPOL frame.
pub const MIC_OFFSET: usize = EAPOL_HEADER_LEN + 77;
/// Length of the Key MIC field.
pub const MIC_LEN: usize = 16;
/// Length of a nonce.
pub const NONCE_LEN: usize = 32;

/// Key Info bit-field flags (big-endian 16-bit field).
pub mod key_info {
    /// Mask for the key-descriptor version (bits 0–2).
    pub const VERSION_MASK: u16 = 0x0007;
    /// Key type: set = pairwise, clear = group (bit 3).
    pub const PAIRWISE: u16 = 1 << 3;
    /// Install flag (bit 6).
    pub const INSTALL: u16 = 1 << 6;
    /// Key Ack — AP expects a reply (bit 7).
    pub const ACK: u16 = 1 << 7;
    /// Key MIC present (bit 8).
    pub const MIC: u16 = 1 << 8;
    /// Secure — both sides have the keys (bit 9).
    pub const SECURE: u16 = 1 << 9;
    /// Error (bit 10).
    pub const ERROR: u16 = 1 << 10;
    /// Request (bit 11).
    pub const REQUEST: u16 = 1 << 11;
    /// Encrypted Key Data (bit 12).
    pub const ENCRYPTED: u16 = 1 << 12;
}

/// A parsed EAPOL-Key frame (borrows its key-data from the input).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EapolKey<'a> {
    /// Key Info bit-field.
    pub key_info: u16,
    /// Negotiated key length.
    pub key_length: u16,
    /// Replay counter (monotone per handshake).
    pub replay_counter: u64,
    /// Key Nonce (ANonce in msg1/3, SNonce in msg2).
    pub nonce: [u8; NONCE_LEN],
    /// Key MIC (zero in msg1).
    pub mic: [u8; MIC_LEN],
    /// Key data (RSN IE in msg2; AES-wrapped GTK in msg3 — possibly encrypted).
    pub key_data: &'a [u8],
}

impl<'a> EapolKey<'a> {
    /// Parse a full EAPOL frame (header + EAPOL-Key body). Returns `None` if it
    /// is not a well-formed EAPOL-Key frame.
    #[must_use]
    pub fn parse(frame: &'a [u8]) -> Option<Self> {
        let hdr = frame.get(..EAPOL_HEADER_LEN)?;
        if *hdr.get(1)? != EAPOL_TYPE_KEY {
            return None;
        }
        let body = frame.get(EAPOL_HEADER_LEN..)?;
        if *body.first()? != KEY_DESC_TYPE_RSN {
            return None;
        }
        let key_info = u16::from_be_bytes([*body.get(1)?, *body.get(2)?]);
        let key_length = u16::from_be_bytes([*body.get(3)?, *body.get(4)?]);
        let replay_counter = u64::from_be_bytes(body.get(5..13)?.try_into().ok()?);
        let nonce: [u8; NONCE_LEN] = body.get(13..45)?.try_into().ok()?;
        let mic: [u8; MIC_LEN] = body.get(77..93)?.try_into().ok()?;
        let kd_len = u16::from_be_bytes([*body.get(93)?, *body.get(94)?]) as usize;
        let key_data = body.get(95..95 + kd_len)?;
        Some(Self {
            key_info,
            key_length,
            replay_counter,
            nonce,
            mic,
            key_data,
        })
    }

    /// `true` if this is a pairwise-key message.
    #[must_use]
    pub const fn pairwise(&self) -> bool {
        self.key_info & key_info::PAIRWISE != 0
    }

    /// `true` if the Key MIC bit is set.
    #[must_use]
    pub const fn has_mic(&self) -> bool {
        self.key_info & key_info::MIC != 0
    }
}

/// Build an EAPOL-Key frame with the MIC field left zeroed (call
/// [`KeyMic::compute`] over the result and patch [`MIC_OFFSET`]).
#[must_use]
pub fn build_key_frame(
    key_info: u16,
    key_length: u16,
    replay_counter: u64,
    nonce: &[u8; NONCE_LEN],
    key_data: &[u8],
) -> Vec<u8> {
    let mut v = Vec::with_capacity(EAPOL_HEADER_LEN + KEY_BODY_FIXED_LEN + key_data.len());
    // EAPOL header: version, type, body length (BE).
    let body_len = (KEY_BODY_FIXED_LEN + key_data.len()) as u16;
    v.push(EAPOL_VERSION);
    v.push(EAPOL_TYPE_KEY);
    v.extend_from_slice(&body_len.to_be_bytes());
    // EAPOL-Key body.
    v.push(KEY_DESC_TYPE_RSN);
    v.extend_from_slice(&key_info.to_be_bytes());
    v.extend_from_slice(&key_length.to_be_bytes());
    v.extend_from_slice(&replay_counter.to_be_bytes());
    v.extend_from_slice(nonce);
    v.extend_from_slice(&[0u8; 16]); // Key IV
    v.extend_from_slice(&[0u8; 8]); // Key RSC
    v.extend_from_slice(&[0u8; 8]); // Key ID (reserved)
    v.extend_from_slice(&[0u8; MIC_LEN]); // MIC (zeroed)
    v.extend_from_slice(&(key_data.len() as u16).to_be_bytes());
    v.extend_from_slice(key_data);
    v
}

/// Patch the computed MIC into a frame produced by [`build_key_frame`].
pub fn set_mic(frame: &mut [u8], mic: &[u8; MIC_LEN]) {
    if let Some(slot) = frame.get_mut(MIC_OFFSET..MIC_OFFSET + MIC_LEN) {
        slot.copy_from_slice(mic);
    }
}

/// PRF seam: derives keying material from the PMK. WPA2 uses HMAC-SHA1
/// (`PRF-384`/`PRF-512`); injected because `nexacore-crypto` lacks SHA-1.
pub trait Prf {
    /// `PRF(key, label, data)` truncated to `out_len` bytes.
    fn prf(&self, key: &[u8], label: &[u8], data: &[u8], out_len: usize) -> Vec<u8>;
}

/// MIC seam: computes/validates the EAPOL-Key MIC over a frame whose MIC field
/// is zeroed, using the KCK. WPA2 uses HMAC-SHA1-128 or AES-CMAC.
pub trait KeyMic {
    /// Compute the 16-byte MIC over `frame_with_zero_mic` using `kck`.
    fn compute(&self, kck: &[u8], frame_with_zero_mic: &[u8]) -> [u8; MIC_LEN];
}

/// The canonical PTK key-derivation data:
/// `min(AA,SPA) ‖ max(AA,SPA) ‖ min(ANonce,SNonce) ‖ max(ANonce,SNonce)`.
#[must_use]
pub fn ptk_kdf_data(
    aa: MacAddr,
    spa: MacAddr,
    anonce: &[u8; NONCE_LEN],
    snonce: &[u8; NONCE_LEN],
) -> Vec<u8> {
    let mut v = Vec::with_capacity(2 * 6 + 2 * NONCE_LEN);
    if aa <= spa {
        v.extend_from_slice(&aa);
        v.extend_from_slice(&spa);
    } else {
        v.extend_from_slice(&spa);
        v.extend_from_slice(&aa);
    }
    if anonce <= snonce {
        v.extend_from_slice(anonce);
        v.extend_from_slice(snonce);
    } else {
        v.extend_from_slice(snonce);
        v.extend_from_slice(anonce);
    }
    v
}

/// Derive a `ptk_bits`-bit PTK from the PMK via the injected [`Prf`].
#[must_use]
pub fn derive_ptk<P: Prf>(
    prf: &P,
    pmk: &[u8],
    aa: MacAddr,
    spa: MacAddr,
    anonce: &[u8; NONCE_LEN],
    snonce: &[u8; NONCE_LEN],
    ptk_bits: usize,
) -> Vec<u8> {
    let data = ptk_kdf_data(aa, spa, anonce, snonce);
    prf.prf(pmk, b"Pairwise key expansion", &data, ptk_bits / 8)
}

/// State of the 4-way handshake from the supplicant's point of view.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HandshakeState {
    /// Waiting for msg1 (ANonce).
    Idle,
    /// Sent msg2; waiting for msg3.
    AwaitingMsg3,
    /// Sent msg4; PTK installed.
    Complete,
    /// A replayed counter or failed MIC aborted the handshake.
    Failed,
}

/// Supplicant side of the 4-way handshake.
#[derive(Debug, Clone)]
pub struct Supplicant {
    state: HandshakeState,
    aa: MacAddr,
    spa: MacAddr,
    snonce: [u8; NONCE_LEN],
    rsn_ie: Vec<u8>,
    anonce: [u8; NONCE_LEN],
    ptk: Vec<u8>,
    last_replay: Option<u64>,
}

/// Bytes of KCK at the front of the PTK (used to MIC msg2/msg4).
pub const KCK_LEN: usize = 16;

impl Supplicant {
    /// New supplicant for `(aa = AP, spa = station)` with a chosen `snonce` and
    /// the station's RSN IE (echoed in msg2).
    #[must_use]
    pub fn new(aa: MacAddr, spa: MacAddr, snonce: [u8; NONCE_LEN], rsn_ie: Vec<u8>) -> Self {
        Self {
            state: HandshakeState::Idle,
            aa,
            spa,
            snonce,
            rsn_ie,
            anonce: [0u8; NONCE_LEN],
            ptk: Vec::new(),
            last_replay: None,
        }
    }

    /// Current handshake state.
    #[must_use]
    pub const fn state(&self) -> HandshakeState {
        self.state
    }

    /// The derived PTK (empty until msg1 is processed).
    #[must_use]
    pub fn ptk(&self) -> &[u8] {
        &self.ptk
    }

    /// Process msg1: validate, derive the PTK, and return the msg2 frame to
    /// send (MIC already inserted). Returns `None` on a malformed/out-of-state
    /// message.
    pub fn on_msg1<P: Prf, M: KeyMic>(
        &mut self,
        frame: &[u8],
        pmk: &[u8],
        prf: &P,
        mic: &M,
        ptk_bits: usize,
    ) -> Option<Vec<u8>> {
        if self.state != HandshakeState::Idle {
            return None;
        }
        let m1 = EapolKey::parse(frame)?;
        // msg1: pairwise, Ack, no MIC.
        if !m1.pairwise() || m1.key_info & key_info::ACK == 0 || m1.has_mic() {
            return None;
        }
        self.anonce = m1.nonce;
        self.ptk = derive_ptk(
            prf,
            pmk,
            self.aa,
            self.spa,
            &m1.nonce,
            &self.snonce,
            ptk_bits,
        );
        self.last_replay = Some(m1.replay_counter);

        // Build msg2: pairwise, MIC set; key data = station RSN IE; SNonce.
        let info = key_info::PAIRWISE | key_info::MIC;
        let mut m2 = build_key_frame(info, 0, m1.replay_counter, &self.snonce, &self.rsn_ie);
        let kck = self.ptk.get(..KCK_LEN)?;
        let tag = mic.compute(kck, &m2);
        set_mic(&mut m2, &tag);
        self.state = HandshakeState::AwaitingMsg3;
        Some(m2)
    }

    /// Process msg3: check replay, verify the MIC, and return the msg4 frame to
    /// send. The (possibly encrypted) GTK in `key_data` is left to the caller's
    /// AES-unwrap seam. Returns `None` on malformed/out-of-state; a replay or
    /// bad MIC moves the state to [`HandshakeState::Failed`].
    pub fn on_msg3<M: KeyMic>(&mut self, frame: &[u8], mic: &M) -> Option<Vec<u8>> {
        if self.state != HandshakeState::AwaitingMsg3 {
            return None;
        }
        let m3 = EapolKey::parse(frame)?;
        if m3.key_info & (key_info::ACK | key_info::MIC | key_info::INSTALL) == 0 {
            return None;
        }
        // Replay protection: counter must advance past msg1's.
        if let Some(prev) = self.last_replay {
            if m3.replay_counter <= prev {
                self.state = HandshakeState::Failed;
                return None;
            }
        }
        // Verify the MIC over the frame with the MIC field zeroed.
        let kck = self.ptk.get(..KCK_LEN)?;
        let mut zeroed = frame.to_vec();
        set_mic(&mut zeroed, &[0u8; MIC_LEN]);
        let expected = mic.compute(kck, &zeroed);
        if expected != m3.mic {
            self.state = HandshakeState::Failed;
            return None;
        }
        self.last_replay = Some(m3.replay_counter);

        // Build msg4: pairwise, MIC, Secure; empty key data.
        let info = key_info::PAIRWISE | key_info::MIC | key_info::SECURE;
        let mut m4 = build_key_frame(info, 0, m3.replay_counter, &[0u8; NONCE_LEN], &[]);
        let tag = mic.compute(kck, &m4);
        set_mic(&mut m4, &tag);
        self.state = HandshakeState::Complete;
        Some(m4)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const AA: MacAddr = [0x06, 0xaa, 0xbb, 0xcc, 0xdd, 0xee];
    const SPA: MacAddr = [0x02, 0x11, 0x22, 0x33, 0x44, 0x55];

    /// Deterministic mock PRF: repeats a byte derived from the inputs.
    struct MockPrf;
    impl Prf for MockPrf {
        fn prf(&self, key: &[u8], label: &[u8], data: &[u8], out_len: usize) -> Vec<u8> {
            let seed = key
                .iter()
                .chain(label)
                .chain(data)
                .fold(0u8, |a, b| a.wrapping_add(*b));
            vec![seed; out_len]
        }
    }

    /// Deterministic mock MIC: 16-byte fold of kck+frame (not cryptographic).
    struct MockMic;
    impl KeyMic for MockMic {
        fn compute(&self, kck: &[u8], frame: &[u8]) -> [u8; MIC_LEN] {
            let mut out = [0u8; MIC_LEN];
            for (i, b) in kck.iter().chain(frame).enumerate() {
                let slot = i % MIC_LEN;
                if let Some(v) = out.get_mut(slot) {
                    *v = v.wrapping_add(*b);
                }
            }
            out
        }
    }

    fn anonce() -> [u8; NONCE_LEN] {
        [0xA1; NONCE_LEN]
    }
    fn snonce() -> [u8; NONCE_LEN] {
        [0x52; NONCE_LEN]
    }

    fn msg1() -> Vec<u8> {
        build_key_frame(key_info::PAIRWISE | key_info::ACK, 16, 1, &anonce(), &[])
    }

    #[test]
    fn key_frame_round_trips() {
        let f = msg1();
        let k = EapolKey::parse(&f).unwrap();
        assert!(k.pairwise());
        assert!(!k.has_mic());
        assert_eq!(k.replay_counter, 1);
        assert_eq!(k.nonce, anonce());
    }

    #[test]
    fn parse_rejects_non_key_frame() {
        // type byte != EAPOL_TYPE_KEY.
        let bad = [EAPOL_VERSION, 1, 0, 0, 0];
        assert!(EapolKey::parse(&bad).is_none());
    }

    #[test]
    fn ptk_kdf_data_is_order_canonical() {
        // Swapping AA/SPA and the nonces yields the same derivation input.
        let a = ptk_kdf_data(AA, SPA, &anonce(), &snonce());
        let b = ptk_kdf_data(SPA, AA, &snonce(), &anonce());
        assert_eq!(a, b, "min/max ordering makes the input symmetric");
        assert_eq!(a.len(), 12 + 2 * NONCE_LEN);
    }

    #[test]
    fn msg1_drives_msg2_and_derives_ptk() {
        let mut s = Supplicant::new(AA, SPA, snonce(), vec![0x30, 0x02, 0x01, 0x00]);
        let m2 = s
            .on_msg1(
                &msg1(),
                b"pmk-32-bytes-................",
                &MockPrf,
                &MockMic,
                384,
            )
            .unwrap();
        assert_eq!(s.state(), HandshakeState::AwaitingMsg3);
        assert_eq!(s.ptk().len(), 48, "384-bit PTK");
        // msg2 carries SNonce, MIC bit, and a nonzero MIC.
        let k2 = EapolKey::parse(&m2).unwrap();
        assert!(k2.has_mic());
        assert_eq!(k2.nonce, snonce());
        assert_ne!(k2.mic, [0u8; MIC_LEN]);
    }

    fn full_handshake() -> (Supplicant, Vec<u8>) {
        let mut s = Supplicant::new(AA, SPA, snonce(), vec![0x30, 0x02, 0x01, 0x00]);
        s.on_msg1(&msg1(), b"pmk", &MockPrf, &MockMic, 384).unwrap();
        // Build msg3 with a valid MIC over the zeroed frame.
        let info = key_info::PAIRWISE
            | key_info::ACK
            | key_info::MIC
            | key_info::INSTALL
            | key_info::SECURE;
        let mut m3 = build_key_frame(info, 16, 2, &anonce(), &[]);
        let kck = &s.ptk()[..KCK_LEN];
        let tag = MockMic.compute(kck, &m3); // MIC field already zero
        set_mic(&mut m3, &tag);
        (s, m3)
    }

    #[test]
    fn msg3_with_valid_mic_completes_handshake() {
        let (mut s, m3) = full_handshake();
        let m4 = s.on_msg3(&m3, &MockMic).unwrap();
        assert_eq!(s.state(), HandshakeState::Complete);
        let k4 = EapolKey::parse(&m4).unwrap();
        assert!(k4.key_info & key_info::SECURE != 0);
        assert!(k4.has_mic());
    }

    #[test]
    fn msg3_with_bad_mic_fails() {
        let (mut s, mut m3) = full_handshake();
        // Corrupt the MIC.
        set_mic(&mut m3, &[0xFF; MIC_LEN]);
        assert!(s.on_msg3(&m3, &MockMic).is_none());
        assert_eq!(s.state(), HandshakeState::Failed);
    }

    #[test]
    fn msg3_replayed_counter_fails() {
        let mut s = Supplicant::new(AA, SPA, snonce(), vec![0x30, 0x02]);
        s.on_msg1(&msg1(), b"pmk", &MockPrf, &MockMic, 384).unwrap();
        // msg3 with replay_counter == msg1's (1) → replay.
        let info = key_info::PAIRWISE | key_info::ACK | key_info::MIC | key_info::INSTALL;
        let mut m3 = build_key_frame(info, 16, 1, &anonce(), &[]);
        let kck = &s.ptk()[..KCK_LEN];
        let tag = MockMic.compute(kck, &m3);
        set_mic(&mut m3, &tag);
        assert!(s.on_msg3(&m3, &MockMic).is_none());
        assert_eq!(s.state(), HandshakeState::Failed);
    }

    #[test]
    fn out_of_order_msg3_before_msg1_is_ignored() {
        let mut s = Supplicant::new(AA, SPA, snonce(), Vec::new());
        let (_, m3) = full_handshake();
        assert!(s.on_msg3(&m3, &MockMic).is_none());
        assert_eq!(s.state(), HandshakeState::Idle);
    }
}
