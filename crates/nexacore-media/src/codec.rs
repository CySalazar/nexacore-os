//! Codec identification and bitstream-header parsing (WS8-02.3 / WS8-02.4).
//!
//! The full pixel/PCM decode is library-gated behind the [`crate::decode`]
//! traits, but a media player must recover *stream parameters* (resolution,
//! sample-rate, channel count, key-frame flags) before it ever asks the
//! library to decode — to size GPU surfaces, configure the sound card, and
//! seek to key-frames.  Those parsers are pure, deterministic, and fully
//! host-testable, so they live here:
//!
//! * [`parse_h264_sps`] — H.264 Sequence Parameter Set → coded dimensions.
//! * [`parse_vp9_frame`] — VP9 uncompressed frame header → key-frame flag and
//!   (for key-frames) dimensions.
//! * [`parse_opus_head`] — Opus identification header → sample-rate/channels.
//! * [`parse_aac_adts`] — AAC ADTS frame header → sample-rate/channels.
//!
//! All multi-bit reads go through [`BitReader`], an MSB-first bit cursor with
//! Exp-Golomb support that returns `None` on overrun (never panics).

#![allow(
    clippy::doc_markdown,
    reason = "prose names wire formats (MP4, EBML, OpusHead, ADTS, FourCC) that are not crate items"
)]
#![allow(
    clippy::trivially_copy_pass_by_ref,
    reason = "FourCC accessors take `&[u8; 4]` to match call sites that hold byte-string literals"
)]
#![allow(
    clippy::match_same_arms,
    reason = "codec lookup tables keep one arm per recognised tag even when several fall through to the same codec, for readability"
)]
#![allow(
    clippy::cognitive_complexity,
    reason = "the H.264 SPS parser is one linear walk of the bitstream syntax; splitting it would obscure the spec order"
)]

use alloc::vec::Vec;

use crate::reader::ByteReader;

/// Video compression formats the player recognises.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum VideoCodec {
    /// ITU-T H.264 / MPEG-4 AVC.
    H264,
    /// Google VP9.
    Vp9,
    /// Google VP8.
    Vp8,
    /// AOMedia AV1.
    Av1,
    /// An unrecognised or unsupported video codec.
    Unknown,
}

/// Audio compression formats the player recognises.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AudioCodec {
    /// MPEG-4 AAC (Advanced Audio Coding).
    Aac,
    /// Xiph Opus.
    Opus,
    /// MPEG-1/2 Audio Layer III.
    Mp3,
    /// Xiph Vorbis.
    Vorbis,
    /// Xiph FLAC.
    Flac,
    /// An unrecognised or unsupported audio codec.
    Unknown,
}

impl VideoCodec {
    /// Map an ISO-BMFF sample-entry FourCC to a codec.
    #[must_use]
    pub fn from_fourcc(fourcc: &[u8; 4]) -> Self {
        match fourcc {
            b"avc1" | b"avc3" => Self::H264,
            b"vp09" => Self::Vp9,
            b"vp08" => Self::Vp8,
            b"av01" => Self::Av1,
            _ => Self::Unknown,
        }
    }

    /// Map a Matroska/WebM `CodecID` string to a codec.
    #[must_use]
    pub fn from_codec_id(id: &str) -> Self {
        match id {
            "V_MPEG4/ISO/AVC" => Self::H264,
            "V_VP9" => Self::Vp9,
            "V_VP8" => Self::Vp8,
            "V_AV1" => Self::Av1,
            _ => Self::Unknown,
        }
    }
}

impl AudioCodec {
    /// Map an ISO-BMFF sample-entry FourCC to a codec.
    #[must_use]
    pub fn from_fourcc(fourcc: &[u8; 4]) -> Self {
        match fourcc {
            b"mp4a" => Self::Aac,
            b"Opus" => Self::Opus,
            b"fLaC" => Self::Flac,
            b".mp3" => Self::Mp3,
            _ => Self::Unknown,
        }
    }

    /// Map a Matroska/WebM `CodecID` string to a codec.
    #[must_use]
    pub fn from_codec_id(id: &str) -> Self {
        match id {
            "A_AAC" => Self::Aac,
            "A_OPUS" => Self::Opus,
            "A_MPEG/L3" => Self::Mp3,
            "A_VORBIS" => Self::Vorbis,
            "A_FLAC" => Self::Flac,
            _ => Self::Unknown,
        }
    }
}

/// Coded picture dimensions recovered from a video header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VideoParams {
    /// Display width in luma samples (after cropping).
    pub width: u32,
    /// Display height in luma samples (after cropping).
    pub height: u32,
}

/// PCM parameters recovered from an audio header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AudioParams {
    /// Output sample-rate in Hz.
    pub sample_rate: u32,
    /// Channel count.
    pub channels: u8,
}

// ---------------------------------------------------------------------------
// Bit reader (MSB-first) with Exp-Golomb, used by the H.264 and VP9 parsers.
// ---------------------------------------------------------------------------

/// An MSB-first bit cursor over a borrowed byte slice.
pub struct BitReader<'a> {
    buf: &'a [u8],
    /// Absolute bit position from the start of `buf`.
    bit: usize,
}

impl<'a> BitReader<'a> {
    /// Wrap `buf`, positioned at bit 0.
    #[must_use]
    pub const fn new(buf: &'a [u8]) -> Self {
        Self { buf, bit: 0 }
    }

    /// Read a single bit as a `bool` (`true` == 1).
    pub fn flag(&mut self) -> Option<bool> {
        let byte_index = self.bit >> 3; // / 8
        let bit_offset = 7 - (self.bit & 7); // 7 - (bit % 8)
        let byte = self.buf.get(byte_index).copied()?;
        self.bit += 1;
        Some((byte >> bit_offset) & 1 == 1)
    }

    /// Read `n` bits (`n <= 32`) MSB-first as an unsigned integer.
    pub fn bits(&mut self, n: u32) -> Option<u32> {
        if n > 32 {
            return None;
        }
        let mut value: u32 = 0;
        for _ in 0..n {
            let bit = u32::from(self.flag()?);
            value = value.checked_shl(1)?.checked_add(bit)?;
        }
        Some(value)
    }

    /// Unsigned Exp-Golomb code (`ue(v)`).
    pub fn ue(&mut self) -> Option<u32> {
        let mut leading_zeros: u32 = 0;
        while !self.flag()? {
            leading_zeros += 1;
            if leading_zeros > 31 {
                return None;
            }
        }
        if leading_zeros == 0 {
            return Some(0);
        }
        let suffix = self.bits(leading_zeros)?;
        // (1 << leading_zeros) - 1 + suffix, without overflow.
        let base = 1u32.checked_shl(leading_zeros)?.checked_sub(1)?;
        base.checked_add(suffix)
    }

    /// Signed Exp-Golomb code (`se(v)`).
    pub fn se(&mut self) -> Option<i32> {
        let code = self.ue()?;
        // Mapping: 0->0, 1->1, 2->-1, 3->2, 4->-2, ...
        let magnitude = code.div_ceil(2);
        let signed = i32::try_from(magnitude).ok()?;
        if code % 2 == 1 {
            Some(signed)
        } else {
            Some(-signed)
        }
    }
}

/// Strip H.264/H.265 `emulation_prevention_three_byte`s (`00 00 03` → `00 00`).
///
/// The RBSP is what the bit-syntax is defined over; the NAL byte-stream inserts
/// an `0x03` after any `00 00` that would otherwise look like a start code.
fn unescape_rbsp(nal: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(nal.len());
    let mut zeros = 0u8;
    for &byte in nal {
        if zeros >= 2 && byte == 0x03 {
            zeros = 0;
            continue;
        }
        out.push(byte);
        if byte == 0 {
            zeros = zeros.saturating_add(1);
        } else {
            zeros = 0;
        }
    }
    out
}

/// Parse an H.264 Sequence Parameter Set into coded dimensions (WS8-02.3).
///
/// `sps` is the SPS NAL **including** its one-byte header (`nal_unit_type == 7`);
/// `emulation_prevention` bytes are removed internally.  Returns `None` if the
/// NAL is not an SPS or is truncated.  Cropping is applied for the common
/// 4:2:0 / 4:2:2 / 4:4:4 chroma formats.
#[must_use]
pub fn parse_h264_sps(sps: &[u8]) -> Option<VideoParams> {
    let header = sps.first().copied()?;
    if header & 0x1f != 7 {
        return None; // not an SPS NAL
    }
    let rbsp = unescape_rbsp(sps.get(1..)?);
    let mut r = BitReader::new(&rbsp);

    let profile_idc = r.bits(8)?;
    let _constraints_and_reserved = r.bits(8)?;
    let _level_idc = r.bits(8)?;
    let _sps_id = r.ue()?;

    let mut chroma_format_idc = 1u32; // 4:2:0 default for older profiles
    if matches!(
        profile_idc,
        100 | 110 | 122 | 244 | 44 | 83 | 86 | 118 | 128 | 138 | 139 | 134 | 135
    ) {
        chroma_format_idc = r.ue()?;
        if chroma_format_idc == 3 {
            let _separate_colour_plane_flag = r.flag()?;
        }
        let _bit_depth_luma_minus8 = r.ue()?;
        let _bit_depth_chroma_minus8 = r.ue()?;
        let _qpprime = r.flag()?;
        if r.flag()? {
            // seq_scaling_matrix_present_flag — skip the scaling lists.
            let list_count = if chroma_format_idc == 3 { 12 } else { 8 };
            for i in 0..list_count {
                let size = if i < 6 { 16 } else { 64 };
                skip_scaling_list(&mut r, size)?;
            }
        }
    }

    let _log2_max_frame_num_minus4 = r.ue()?;
    let pic_order_cnt_type = r.ue()?;
    if pic_order_cnt_type == 0 {
        let _log2_max_poc_lsb_minus4 = r.ue()?;
    } else if pic_order_cnt_type == 1 {
        let _delta_pic_order_always_zero = r.flag()?;
        let _offset_for_non_ref_pic = r.se()?;
        let _offset_for_top_to_bottom = r.se()?;
        let cycle_len = r.ue()?;
        for _ in 0..cycle_len {
            let _offset = r.se()?;
        }
    }

    let _max_num_ref_frames = r.ue()?;
    let _gaps_allowed = r.flag()?;
    let pic_width_in_mbs_minus1 = r.ue()?;
    let pic_height_in_map_units_minus1 = r.ue()?;
    let frame_mbs_only_flag = r.flag()?;
    if !frame_mbs_only_flag {
        let _mb_adaptive_frame_field = r.flag()?;
    }
    let _direct_8x8_inference = r.flag()?;

    let (crop_left, crop_right, crop_top, crop_bottom) = if r.flag()? {
        // Evaluated left-to-right: left, right, top, bottom (spec order).
        (r.ue()?, r.ue()?, r.ue()?, r.ue()?)
    } else {
        (0u32, 0, 0, 0)
    };

    // Coded luma dimensions before cropping.
    let width_mbs = pic_width_in_mbs_minus1.checked_add(1)?;
    let frame_height_mbs = (2u32.checked_sub(u32::from(frame_mbs_only_flag))?)
        .checked_mul(pic_height_in_map_units_minus1.checked_add(1)?)?;
    let coded_width = width_mbs.checked_mul(16)?;
    let coded_height = frame_height_mbs.checked_mul(16)?;

    // Crop units depend on chroma sub-sampling (ITU-T H.264 Table 6-1).
    let (sub_width_c, sub_height_c) = match chroma_format_idc {
        0 => (1u32, 1u32), // monochrome
        2 => (2, 1),       // 4:2:2
        3 => (1, 1),       // 4:4:4
        _ => (2, 2),       // 4:2:0
    };
    let crop_unit_x = sub_width_c;
    let crop_unit_y =
        sub_height_c.checked_mul(2u32.checked_sub(u32::from(frame_mbs_only_flag))?)?;

    let width = coded_width.checked_sub(
        crop_left
            .checked_add(crop_right)?
            .checked_mul(crop_unit_x)?,
    )?;
    let height = coded_height.checked_sub(
        crop_top
            .checked_add(crop_bottom)?
            .checked_mul(crop_unit_y)?,
    )?;

    Some(VideoParams { width, height })
}

/// Skip a scaling list of `size` coefficients (de-sync-safe).
fn skip_scaling_list(r: &mut BitReader<'_>, size: u32) -> Option<()> {
    let mut last_scale: i32 = 8;
    let mut next_scale: i32 = 8;
    for _ in 0..size {
        if next_scale != 0 {
            let delta = r.se()?;
            // (last_scale + delta + 256) mod 256, overflow- and panic-safe.
            next_scale = last_scale.wrapping_add(delta).rem_euclid(256);
        }
        if next_scale != 0 {
            last_scale = next_scale;
        }
    }
    Some(())
}

/// Key-frame status and (for key-frames) dimensions from a VP9 frame header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Vp9FrameInfo {
    /// `true` if this is a key-frame (intra-only, resets references).
    pub key_frame: bool,
    /// `true` if the frame is shown (vs. an alt-ref hidden frame).
    pub show_frame: bool,
    /// Frame dimensions; present only for key-frames (inter frames reuse the
    /// reference size unless explicitly overridden, which this header-only
    /// parser does not track).
    pub dimensions: Option<VideoParams>,
}

/// Parse the VP9 uncompressed frame header (WS8-02.3).
///
/// Covers the fields up to the key-frame frame size; returns `None` on a
/// malformed marker or sync code.
#[must_use]
pub fn parse_vp9_frame(frame: &[u8]) -> Option<Vp9FrameInfo> {
    let mut r = BitReader::new(frame);
    // frame_marker must be 0b10.
    if r.bits(2)? != 0b10 {
        return None;
    }
    let profile_low = u32::from(r.flag()?);
    let profile_high = u32::from(r.flag()?);
    let profile = (profile_high << 1) | profile_low;
    if profile == 3 {
        let _reserved_zero = r.flag()?;
    }
    let show_existing_frame = r.flag()?;
    if show_existing_frame {
        let _frame_to_show = r.bits(3)?;
        return Some(Vp9FrameInfo {
            key_frame: false,
            show_frame: true,
            dimensions: None,
        });
    }
    let frame_type_inter = r.flag()?; // 0 == key, 1 == inter
    let show_frame = r.flag()?;
    let _error_resilient = r.flag()?;

    if frame_type_inter {
        return Some(Vp9FrameInfo {
            key_frame: false,
            show_frame,
            dimensions: None,
        });
    }

    // Key-frame: sync code, colour config, then frame size.
    if r.bits(24)? != 0x49_83_42 {
        return None;
    }
    if profile >= 2 {
        let _ten_or_twelve_bit = r.flag()?;
    }
    let color_space = r.bits(3)?;
    if color_space != 7 {
        // not CS_RGB
        let _color_range = r.flag()?;
        if profile == 1 || profile == 3 {
            let _subsampling_x = r.flag()?;
            let _subsampling_y = r.flag()?;
            let _reserved = r.flag()?;
        }
    } else if profile == 1 || profile == 3 {
        let _reserved = r.flag()?;
    }

    // frame_size: width_minus_1 (16), height_minus_1 (16).
    let width = r.bits(16)?.checked_add(1)?;
    let height = r.bits(16)?.checked_add(1)?;

    Some(Vp9FrameInfo {
        key_frame: true,
        show_frame,
        dimensions: Some(VideoParams { width, height }),
    })
}

/// Parse the Opus identification header (`OpusHead`, WS8-02.4).
///
/// Recovers the output channel count and the input sample-rate.  Opus always
/// decodes to 48 kHz internally; `input_sample_rate` is informational, so the
/// returned `sample_rate` is the original rate when non-zero, else 48 kHz.
#[must_use]
pub fn parse_opus_head(head: &[u8]) -> Option<AudioParams> {
    let mut r = ByteReader::new(head);
    if r.take(8)? != b"OpusHead" {
        return None;
    }
    let _version = r.u8()?;
    let channels = r.u8()?;
    if channels == 0 {
        return None;
    }
    let _pre_skip = r.u16()?;
    // Input sample-rate is little-endian in the Opus header.
    let rate_le: [u8; 4] = r.take(4)?.try_into().ok()?;
    let input_rate = u32::from_le_bytes(rate_le);
    let sample_rate = if input_rate == 0 { 48_000 } else { input_rate };
    Some(AudioParams {
        sample_rate,
        channels,
    })
}

/// MPEG-4 AAC sampling-frequency index table (ISO/IEC 14496-3).
const AAC_SAMPLE_RATES: [u32; 13] = [
    96_000, 88_200, 64_000, 48_000, 44_100, 32_000, 24_000, 22_050, 16_000, 12_000, 11_025, 8_000,
    7_350,
];

/// Parse an AAC ADTS frame header (WS8-02.4).
///
/// Recognises the 0xFFF sync word, decodes the sampling-frequency index and the
/// channel configuration.  Returns `None` if the sync word is absent or the
/// indices are reserved.
#[must_use]
pub fn parse_aac_adts(frame: &[u8]) -> Option<AudioParams> {
    let mut r = BitReader::new(frame);
    // syncword: 12 bits all set.
    if r.bits(12)? != 0xFFF {
        return None;
    }
    let _mpeg_version = r.flag()?;
    let _layer = r.bits(2)?;
    let _protection_absent = r.flag()?;
    let _profile = r.bits(2)?;
    let sampling_frequency_index = usize::try_from(r.bits(4)?).ok()?;
    let _private_bit = r.flag()?;
    let channel_configuration = r.bits(3)?;

    let sample_rate = *AAC_SAMPLE_RATES.get(sampling_frequency_index)?;
    let channels = u8::try_from(channel_configuration).ok()?;
    if channels == 0 {
        // channel_configuration 0 means "defined in AOT-specific config".
        return None;
    }
    Some(AudioParams {
        sample_rate,
        channels,
    })
}
