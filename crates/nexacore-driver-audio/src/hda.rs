//! Intel HDA controller register map + CORB/RIRB verb codec (WS2-10.1, .2).
//!
//! The HDA driver talks to codecs by writing 32-bit *verbs* into the CORB ring
//! and reading 64-bit responses from the RIRB ring. The register offsets and
//! the verb encode / response decode are pure byte/bit logic and are host-
//! tested here; the MMIO ring setup + the response IRQ are device-side.

/// HDA controller register offsets (from the controller MMIO base, HDA 1.0a § 3).
pub mod regs {
    /// Global Capabilities (16-bit).
    pub const GCAP: usize = 0x00;
    /// Global Control (32-bit).
    pub const GCTL: usize = 0x08;
    /// Wake Enable (16-bit).
    pub const WAKEEN: usize = 0x0C;
    /// State Change Status (16-bit) — codec presence bitmap.
    pub const STATESTS: usize = 0x0E;
    /// CORB Lower Base Address (32-bit).
    pub const CORBLBASE: usize = 0x40;
    /// CORB Upper Base Address (32-bit).
    pub const CORBUBASE: usize = 0x44;
    /// CORB Write Pointer (16-bit).
    pub const CORBWP: usize = 0x48;
    /// CORB Read Pointer (16-bit).
    pub const CORBRP: usize = 0x4A;
    /// CORB Control (8-bit).
    pub const CORBCTL: usize = 0x4C;
    /// RIRB Lower Base Address (32-bit).
    pub const RIRBLBASE: usize = 0x50;
    /// RIRB Upper Base Address (32-bit).
    pub const RIRBUBASE: usize = 0x54;
    /// RIRB Write Pointer (16-bit).
    pub const RIRBWP: usize = 0x58;
    /// RIRB Control (8-bit).
    pub const RIRBCTL: usize = 0x5C;
}

/// `GCTL` bit 0: controller reset (0 = reset asserted, 1 = run).
pub const GCTL_CRST: u32 = 1 << 0;
/// `CORBCTL` bit 1: enable the CORB DMA engine.
pub const CORBCTL_RUN: u8 = 1 << 1;
/// `RIRBCTL` bit 1: enable the RIRB DMA engine.
pub const RIRBCTL_RUN: u8 = 1 << 1;

/// Common HDA verb command ids (12-bit form).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum HdaVerb {
    /// Get a node parameter (payload = parameter id, see [`param`]).
    GetParameter = 0xF00,
    /// Get the selected connection-list entry.
    GetConnectionSelect = 0xF01,
    /// Set the converter stream/channel.
    SetStreamChannel = 0x706,
    /// Set the converter PCM format.
    SetConverterFormat = 0x200,
    /// Set the power state of a node.
    SetPowerState = 0x705,
}

/// Node-parameter ids for [`HdaVerb::GetParameter`].
pub mod param {
    /// Vendor / device id of the codec.
    pub const VENDOR_ID: u8 = 0x00;
    /// Revision id.
    pub const REVISION_ID: u8 = 0x02;
    /// Subordinate node count.
    pub const NODE_COUNT: u8 = 0x04;
    /// Function group type.
    pub const FUNCTION_GROUP_TYPE: u8 = 0x05;
    /// Audio widget capabilities.
    pub const AUDIO_WIDGET_CAP: u8 = 0x09;
    /// Supported PCM sizes / rates.
    pub const PCM_SIZE_RATE: u8 = 0x0A;
}

/// Encode a 32-bit HDA verb command for the CORB.
///
/// Layout: `cad[31:28] | nid[27:20] | verb[19:8] | payload[7:0]` — the 12-bit
/// verb + 8-bit payload form.
#[must_use]
pub fn make_verb(codec_addr: u8, node_id: u8, verb: HdaVerb, payload: u8) -> u32 {
    ((codec_addr as u32 & 0xF) << 28)
        | ((node_id as u32) << 20)
        | ((verb as u32 & 0xFFF) << 8)
        | (payload as u32)
}

/// A decoded RIRB response entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HdaResponse {
    /// The 32-bit codec response payload.
    pub response: u32,
    /// The codec address that produced the response (`resp_ex[3:0]`).
    pub codec_addr: u8,
    /// Whether the response was unsolicited (`resp_ex` bit 4).
    pub unsolicited: bool,
}

/// Decode a 64-bit RIRB entry (`response | resp_ex << 32`).
#[must_use]
pub fn decode_response(rirb_entry: u64) -> HdaResponse {
    let response = (rirb_entry & 0xFFFF_FFFF) as u32;
    let resp_ex = (rirb_entry >> 32) as u32;
    HdaResponse {
        response,
        codec_addr: (resp_ex & 0xF) as u8,
        unsolicited: resp_ex & (1 << 4) != 0,
    }
}

/// Decode the `STATESTS` bitmap into the list of present codec addresses
/// (0..=14). A set bit `n` means a codec is present at address `n`.
pub fn present_codecs(statests: u16) -> impl Iterator<Item = u8> {
    (0u8..15).filter(move |n| statests & (1 << n) != 0)
}

#[cfg(test)]
mod tests {
    use alloc::vec::Vec;

    use super::*;

    #[test]
    fn verb_encoding_packs_fields() {
        // Codec 1, node 2, GET_PARAMETER(VENDOR_ID).
        let v = make_verb(1, 2, HdaVerb::GetParameter, param::VENDOR_ID);
        assert_eq!(v >> 28, 1); // cad
        assert_eq!((v >> 20) & 0xFF, 2); // nid
        assert_eq!((v >> 8) & 0xFFF, 0xF00); // verb
        assert_eq!(v & 0xFF, 0x00); // payload
    }

    #[test]
    fn verb_encoding_node_count() {
        let v = make_verb(0, 1, HdaVerb::GetParameter, param::NODE_COUNT);
        assert_eq!(v, (1 << 20) | (0xF00 << 8) | 0x04);
    }

    #[test]
    fn response_decode_extracts_codec_and_flag() {
        // response = 0xDEADBEEF, resp_ex = codec 3, unsolicited.
        let entry = 0xDEAD_BEEFu64 | ((0x0000_0013u64) << 32);
        let r = decode_response(entry);
        assert_eq!(r.response, 0xDEAD_BEEF);
        assert_eq!(r.codec_addr, 3);
        assert!(r.unsolicited);
    }

    #[test]
    fn present_codecs_lists_set_bits() {
        // codecs at address 0 and 2.
        let codecs: Vec<u8> = present_codecs(0b101).collect();
        assert_eq!(codecs, alloc::vec![0, 2]);
    }
}
