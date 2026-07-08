//! PTK / GTK key hierarchy and the CCMP nonce / header construction
//! (WS2-11.9).
//!
//! The 4-way handshake ([`crate::eapol`]) yields a flat PTK; this module splits
//! it into the named sub-keys and builds the per-frame CCMP nonce and header the
//! data path stamps onto each protected frame. The AES-CCMP encryption itself
//! needs an AES core absent from `nexacore-crypto`, so it stays a seam — the
//! deterministic nonce/header/PN layout here is what the encryptor consumes and
//! is host-tested.

// PN packs into a 48-bit field; the byte extraction casts are range-bounded.
// `kck`/`kek` are the spec's sub-key names and read as "too similar".
#![allow(clippy::cast_possible_truncation, clippy::similar_names)]

use alloc::vec::Vec;

use crate::frame::MacAddr;

/// Key Confirmation Key length (CCMP).
pub const KCK_LEN: usize = 16;
/// Key Encryption Key length (CCMP).
pub const KEK_LEN: usize = 16;
/// Temporal Key length for CCMP-128.
pub const TK_LEN_CCMP128: usize = 16;
/// Total PTK length for CCMP-128 (`KCK ‖ KEK ‖ TK`).
pub const PTK_LEN_CCMP128: usize = KCK_LEN + KEK_LEN + TK_LEN_CCMP128;

/// The pairwise transient key split into its sub-keys.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ptk {
    /// Key Confirmation Key — MICs the EAPOL-Key frames.
    pub kck: [u8; KCK_LEN],
    /// Key Encryption Key — AES-key-wraps the GTK in msg3.
    pub kek: [u8; KEK_LEN],
    /// Temporal Key — encrypts the data path (CCMP).
    pub tk: [u8; TK_LEN_CCMP128],
}

impl Ptk {
    /// Split a derived PTK byte string into KCK ‖ KEK ‖ TK. Returns `None` if it
    /// is shorter than [`PTK_LEN_CCMP128`].
    #[must_use]
    pub fn from_bytes(ptk: &[u8]) -> Option<Self> {
        let kck: [u8; KCK_LEN] = ptk.get(..KCK_LEN)?.try_into().ok()?;
        let kek: [u8; KEK_LEN] = ptk.get(KCK_LEN..KCK_LEN + KEK_LEN)?.try_into().ok()?;
        let tk: [u8; TK_LEN_CCMP128] = ptk
            .get(KCK_LEN + KEK_LEN..PTK_LEN_CCMP128)?
            .try_into()
            .ok()?;
        Some(Self { kck, kek, tk })
    }
}

/// A group temporal key, with its key id (0–3), as delivered in msg3.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Gtk {
    /// The group key bytes.
    pub key: Vec<u8>,
    /// Key id (0–3); the data path tags broadcast frames with it.
    pub key_id: u8,
}

impl Gtk {
    /// Build a GTK, masking the key id to two bits.
    #[must_use]
    pub fn new(key: Vec<u8>, key_id: u8) -> Self {
        Self {
            key,
            key_id: key_id & 0x03,
        }
    }
}

/// Length of a CCMP packet number.
pub const PN_LEN: usize = 6;
/// Length of the CCMP nonce.
pub const CCMP_NONCE_LEN: usize = 13;
/// Length of the CCMP header prepended to a protected frame body.
pub const CCMP_HEADER_LEN: usize = 8;

/// Build the 13-byte CCMP nonce: `flags(priority) ‖ A2 ‖ PN` (PN most-significant
/// octet first), per IEEE 802.11 § CCMP.
#[must_use]
pub fn ccmp_nonce(priority: u8, a2: MacAddr, pn: u64) -> [u8; CCMP_NONCE_LEN] {
    let mut n = [0u8; CCMP_NONCE_LEN];
    n[0] = priority & 0x0F;
    if let Some(slot) = n.get_mut(1..7) {
        slot.copy_from_slice(&a2);
    }
    // PN is a 48-bit value, MSB first in the nonce.
    for (i, b) in n.iter_mut().skip(7).enumerate() {
        let shift = (PN_LEN - 1 - i) * 8;
        *b = (pn >> shift) as u8;
    }
    n
}

/// Build the 8-byte CCMP header: `PN0 PN1 Rsvd KeyID(ExtIV) PN2 PN3 PN4 PN5`,
/// where PN0 is the least-significant octet of the 48-bit PN.
#[must_use]
pub fn ccmp_header(pn: u64, key_id: u8) -> [u8; CCMP_HEADER_LEN] {
    let pn_bytes = pn.to_le_bytes(); // little-endian: [PN0, PN1, PN2, PN3, PN4, PN5, ..]
    // ExtIV bit (bit 5) is always set for CCMP; key id in bits 6–7.
    let key_id_byte = 0x20 | ((key_id & 0x03) << 6);
    [
        pn_bytes[0],
        pn_bytes[1],
        0,
        key_id_byte,
        pn_bytes[2],
        pn_bytes[3],
        pn_bytes[4],
        pn_bytes[5],
    ]
}

/// Monotone replay window over the 48-bit receive PN: a received PN must be
/// strictly greater than the highest accepted one.
#[derive(Debug, Clone, Copy, Default)]
pub struct PnReplay {
    highest: u64,
}

impl PnReplay {
    /// New replay window starting from PN 0 (nothing accepted yet).
    #[must_use]
    pub const fn new() -> Self {
        Self { highest: 0 }
    }

    /// Accept `pn` if it advances past the highest seen; reject (replay) and
    /// leave the window unchanged otherwise.
    pub fn accept(&mut self, pn: u64) -> bool {
        if pn > self.highest {
            self.highest = pn;
            true
        } else {
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const A2: MacAddr = [0x06, 0xaa, 0xbb, 0xcc, 0xdd, 0xee];

    #[test]
    fn ptk_splits_into_subkeys() {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&[0x11; KCK_LEN]);
        bytes.extend_from_slice(&[0x22; KEK_LEN]);
        bytes.extend_from_slice(&[0x33; TK_LEN_CCMP128]);
        let ptk = Ptk::from_bytes(&bytes).unwrap();
        assert_eq!(ptk.kck, [0x11; KCK_LEN]);
        assert_eq!(ptk.kek, [0x22; KEK_LEN]);
        assert_eq!(ptk.tk, [0x33; TK_LEN_CCMP128]);
    }

    #[test]
    fn ptk_from_short_buffer_is_none() {
        assert!(Ptk::from_bytes(&[0u8; PTK_LEN_CCMP128 - 1]).is_none());
    }

    #[test]
    fn gtk_masks_key_id() {
        let g = Gtk::new(alloc::vec![0xAB; 16], 0xFF);
        assert_eq!(g.key_id, 3);
    }

    #[test]
    fn ccmp_nonce_layout() {
        let pn = 0x0000_0102_0304_0506; // 48-bit
        let n = ccmp_nonce(0x07, A2, pn);
        assert_eq!(n[0], 0x07, "priority in flags");
        assert_eq!(&n[1..7], &A2, "A2 in the middle");
        // PN most-significant first: 01 02 03 04 05 06.
        assert_eq!(&n[7..13], &[0x01, 0x02, 0x03, 0x04, 0x05, 0x06]);
    }

    #[test]
    fn ccmp_header_layout_and_extiv() {
        let pn = 0x0000_0605_0403_0201;
        let h = ccmp_header(pn, 2);
        assert_eq!(h[0], 0x01, "PN0 is least-significant");
        assert_eq!(h[1], 0x02);
        assert_eq!(h[2], 0x00, "reserved");
        assert_eq!(h[3] & 0x20, 0x20, "ExtIV bit set");
        assert_eq!(h[3] >> 6, 2, "key id in top two bits");
        assert_eq!(&h[4..8], &[0x03, 0x04, 0x05, 0x06]);
    }

    #[test]
    fn pn_replay_rejects_non_advancing() {
        let mut w = PnReplay::new();
        assert!(w.accept(1));
        assert!(w.accept(2));
        assert!(!w.accept(2), "equal PN is a replay");
        assert!(!w.accept(1), "older PN is a replay");
        assert!(w.accept(3));
    }
}
