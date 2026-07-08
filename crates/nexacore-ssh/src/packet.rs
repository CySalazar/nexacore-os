//! The SSH binary packet protocol (RFC 4253 §6) and the AEAD packet channel.
//!
//! A *record* is `packet_length(u32) || padding_length(u8) || payload ||
//! padding`, where the padding rounds `4 + 1 + payload_len + pad` up to a
//! multiple of the block size (8) with `pad ∈ [4, 255]`. Before `NEWKEYS`,
//! records travel in the clear ([`encode_record`] / [`parse_record`]). After
//! `NEWKEYS`, each record is sealed with ChaCha20-Poly1305 under a
//! per-direction key and a nonce derived from the packet sequence number
//! ([`SealingKey`] / [`OpeningKey`]).
//!
//! ## NexaCore SSH AEAD profile
//!
//! The sealed wire form is `uint32(ciphertext_len) || AEAD(record)`, with the
//! cleartext length bound as additional authenticated data (so truncation is
//! detected) and the nonce = `0x00000000 || seq_be64`. This differs from
//! `chacha20-poly1305@openssh.com`, which encrypts the packet-length field
//! under a second key; wire interop with OpenSSH's exact construction needs
//! raw ChaCha20 block access that `nexacore-crypto`'s combined AEAD does not
//! expose (a documented seam, mirroring the TLS X.509 gap).

use alloc::vec::Vec;

use nexacore_crypto::aead::{
    NexaCoreAeadKey, NexaCoreCiphertext, NexaCoreNonce, TAG_LEN, open, seal,
};

use crate::{error::SshError, wire::Reader};

/// `SSH_MSG_DISCONNECT`.
pub const SSH_MSG_DISCONNECT: u8 = 1;
/// `SSH_MSG_KEXINIT`.
pub const SSH_MSG_KEXINIT: u8 = 20;
/// `SSH_MSG_NEWKEYS`.
pub const SSH_MSG_NEWKEYS: u8 = 21;
/// `SSH_MSG_KEX_ECDH_INIT`.
pub const SSH_MSG_KEX_ECDH_INIT: u8 = 30;
/// `SSH_MSG_KEX_ECDH_REPLY`.
pub const SSH_MSG_KEX_ECDH_REPLY: u8 = 31;

/// The block size the padding rounds to (stream/AEAD ciphers use 8).
const BLOCK: usize = 8;
/// Minimum padding bytes per RFC 4253 §6.
const MIN_PAD: usize = 4;

/// Encode `payload` into a cleartext binary-packet record.
#[must_use]
pub fn encode_record(payload: &[u8]) -> Vec<u8> {
    // Round (4 length + 1 pad_len + payload + pad) up to a BLOCK multiple.
    let unpadded = 4 + 1 + payload.len();
    let mut pad = BLOCK - (unpadded % BLOCK);
    if pad < MIN_PAD {
        pad += BLOCK;
    }
    let packet_length = 1 + payload.len() + pad;

    let mut out = Vec::with_capacity(4 + packet_length);
    out.extend_from_slice(
        &u32::try_from(packet_length)
            .unwrap_or(u32::MAX)
            .to_be_bytes(),
    );
    out.push(u8::try_from(pad).unwrap_or(0));
    out.extend_from_slice(payload);
    // Deterministic zero padding (RFC allows any padding; zeros keep tests
    // reproducible and the AEAD tag still authenticates the whole record).
    out.resize(out.len() + pad, 0);
    out
}

/// Parse a cleartext record, returning its payload.
///
/// # Errors
/// [`SshError::ShortBuffer`] on truncation, [`SshError::Protocol`] if the
/// padding length is inconsistent.
pub fn parse_record(bytes: &[u8]) -> Result<Vec<u8>, SshError> {
    let mut r = Reader::new(bytes);
    let packet_length = r.get_u32()? as usize;
    let body = r.get_bytes(packet_length)?;
    let (&pad_len, rest) = body.split_first().ok_or(SshError::ShortBuffer)?;
    let pad_len = pad_len as usize;
    let payload_len = rest
        .len()
        .checked_sub(pad_len)
        .ok_or(SshError::Protocol("padding"))?;
    Ok(rest
        .get(..payload_len)
        .ok_or(SshError::ShortBuffer)?
        .to_vec())
}

/// Derive the 12-byte AEAD nonce for packet sequence number `seq`.
fn nonce_for(seq: u32) -> NexaCoreNonce {
    let mut n = [0u8; 12];
    n.get_mut(4..12)
        .unwrap_or(&mut [])
        .copy_from_slice(&u64::from(seq).to_be_bytes());
    NexaCoreNonce::from_bytes(n)
}

/// A per-direction sealing key plus its packet sequence counter.
pub struct SealingKey {
    key: NexaCoreAeadKey,
    seq: u32,
}

impl SealingKey {
    /// Build a sealing key from raw AEAD key bytes.
    #[must_use]
    pub fn new(key: [u8; 32]) -> Self {
        Self {
            key: NexaCoreAeadKey::from_bytes(key),
            seq: 0,
        }
    }

    /// Seal `payload` into a wire packet, advancing the sequence number.
    ///
    /// # Errors
    /// [`SshError::Decrypt`] if the AEAD layer fails (should not happen for
    /// sealing).
    pub fn seal_packet(&mut self, payload: &[u8]) -> Result<Vec<u8>, SshError> {
        let record = encode_record(payload);
        let ct_len = u32::try_from(record.len() + TAG_LEN).unwrap_or(u32::MAX);
        let aad = ct_len.to_be_bytes();
        let ct =
            seal(&self.key, &nonce_for(self.seq), &aad, &record).map_err(|_| SshError::Decrypt)?;
        self.seq = self.seq.wrapping_add(1);

        let mut out = Vec::with_capacity(4 + ct.as_bytes().len());
        out.extend_from_slice(&aad);
        out.extend_from_slice(ct.as_bytes());
        Ok(out)
    }
}

/// A per-direction opening key plus its packet sequence counter.
pub struct OpeningKey {
    key: NexaCoreAeadKey,
    seq: u32,
}

impl OpeningKey {
    /// Build an opening key from raw AEAD key bytes.
    #[must_use]
    pub fn new(key: [u8; 32]) -> Self {
        Self {
            key: NexaCoreAeadKey::from_bytes(key),
            seq: 0,
        }
    }

    /// The cleartext length prefix is 4 bytes; a caller reads that first, then
    /// this many ciphertext bytes.
    #[must_use]
    pub fn ciphertext_len(prefix: [u8; 4]) -> usize {
        u32::from_be_bytes(prefix) as usize
    }

    /// Open a ciphertext body (the bytes following the 4-byte length prefix)
    /// into its payload, advancing the sequence number.
    ///
    /// # Errors
    /// [`SshError::Decrypt`] on tag mismatch/tampering, or a parse error.
    pub fn open_packet(&mut self, prefix: [u8; 4], ciphertext: &[u8]) -> Result<Vec<u8>, SshError> {
        let ct = NexaCoreCiphertext::from_bytes(ciphertext.to_vec());
        let record =
            open(&self.key, &nonce_for(self.seq), &prefix, &ct).map_err(|_| SshError::Decrypt)?;
        self.seq = self.seq.wrapping_add(1);
        parse_record(&record)
    }
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::indexing_slicing,
        clippy::cast_possible_truncation
    )]

    use super::*;

    #[test]
    fn record_round_trips_and_is_block_aligned() {
        for len in [0usize, 1, 5, 8, 31, 200] {
            let payload: Vec<u8> = (0..len).map(|i| i as u8).collect();
            let rec = encode_record(&payload);
            assert_eq!(rec.len() % BLOCK, 0, "len {len} not block aligned");
            assert!(rec.len() >= 16, "record must be at least 16 bytes");
            assert_eq!(parse_record(&rec).unwrap(), payload);
        }
    }

    #[test]
    fn aead_channel_round_trips() {
        let key = [7u8; 32];
        let mut seal = SealingKey::new(key);
        let mut open = OpeningKey::new(key);
        for payload in [&b"hello"[..], b"", b"the quick brown fox jumps"] {
            let wire = seal.seal_packet(payload).unwrap();
            let prefix: [u8; 4] = wire.get(..4).unwrap().try_into().unwrap();
            let body = wire.get(4..).unwrap();
            assert_eq!(OpeningKey::ciphertext_len(prefix), body.len());
            assert_eq!(open.open_packet(prefix, body).unwrap(), payload);
        }
    }

    #[test]
    fn sequence_desync_fails_to_open() {
        let key = [9u8; 32];
        let mut seal = SealingKey::new(key);
        let mut open = OpeningKey::new(key);
        // Seal two packets but only open the second → nonce/seq mismatch.
        let _first = seal.seal_packet(b"one").unwrap();
        let wire = seal.seal_packet(b"two").unwrap();
        let prefix: [u8; 4] = wire.get(..4).unwrap().try_into().unwrap();
        let body = wire.get(4..).unwrap();
        assert_eq!(open.open_packet(prefix, body), Err(SshError::Decrypt));
    }

    #[test]
    fn tampered_ciphertext_rejected() {
        let key = [3u8; 32];
        let mut seal = SealingKey::new(key);
        let mut open = OpeningKey::new(key);
        let mut wire = seal.seal_packet(b"secret").unwrap();
        let last = wire.len() - 1;
        wire[last] ^= 0xff;
        let prefix: [u8; 4] = wire.get(..4).unwrap().try_into().unwrap();
        let body = wire.get(4..).unwrap();
        assert_eq!(open.open_packet(prefix, body), Err(SshError::Decrypt));
    }
}
