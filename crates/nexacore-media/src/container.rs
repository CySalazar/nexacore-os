//! Container demuxers: ISO-BMFF (MP4) and EBML (MKV/WebM) (WS8-02.2).
//!
//! A demuxer turns a container byte-stream into a set of [`Track`]s and a
//! time-ordered list of elementary [`Packet`]s the decoders consume.  Both
//! parsers are pure and host-testable: they validate every length, never index
//! a slice unchecked, and reconstruct sample timing from the container's own
//! tables (MP4 `stts`/`stsz`/`stsc`/`stco`/`stss`; Matroska cluster + block
//! timestamps).
//!
//! Scope of the host-verifiable core:
//! * MP4: walks the box tree, recovers the codec from the sample-entry FourCC,
//!   and rebuilds every sample's file offset, size, presentation time, and
//!   key-frame flag from the sample tables.  Composition offsets (`ctts`,
//!   B-frame PTS reorder) are a documented follow-up — DTS is used as PTS.
//! * Matroska/WebM: walks the EBML tree, recovers tracks from `Tracks`, and
//!   emits one packet per `SimpleBlock`/`Block`.  No-lacing and fixed-lacing
//!   blocks are split exactly; Xiph/EBML lacing is a documented follow-up
//!   (the laced payload is emitted as a single packet).

#![allow(
    clippy::doc_markdown,
    reason = "prose names container structures (MP4, EBML, VisualSampleEntry, TrackEntry, SimpleBlock, …) that are not crate items"
)]
#![allow(
    clippy::similar_names,
    reason = "the MP4 sample tables are conventionally named `stsz`/`stsc`/`stss`/`stco`; the four-letter atom names are the domain vocabulary"
)]
#![allow(
    clippy::trivially_copy_pass_by_ref,
    reason = "box lookups take `&[u8; 4]` to match call sites that hold FourCC byte-string literals"
)]

use alloc::{string::String, vec::Vec};

use crate::{
    codec::{AudioCodec, VideoCodec},
    reader::ByteReader,
};

/// Broad classification of a track's media type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrackKind {
    /// A video (image sequence) track.
    Video,
    /// An audio track.
    Audio,
    /// A subtitle / caption track.
    Subtitle,
    /// Anything else (metadata, fonts, …).
    Other,
}

/// The codec carried by a track.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CodecId {
    /// A video codec.
    Video(VideoCodec),
    /// An audio codec.
    Audio(AudioCodec),
    /// An unrecognised codec.
    Other,
}

/// A media track: one elementary stream within a container.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Track {
    /// Container-assigned track identifier (MP4 `track_ID`, MKV `TrackNumber`).
    pub id: u32,
    /// Broad media classification.
    pub kind: TrackKind,
    /// Identified codec.
    pub codec: CodecId,
    /// Media timescale in ticks per second (informational; packet timestamps
    /// are pre-converted to microseconds).
    pub timescale: u32,
    /// Codec-private setup data (MP4 `avcC`/`dOps`, MKV `CodecPrivate`).
    pub codec_private: Vec<u8>,
    /// Declared coded width in pixels, if the container states it (video only).
    pub width: Option<u32>,
    /// Declared coded height in pixels, if the container states it (video only).
    pub height: Option<u32>,
}

/// One elementary-stream access unit (a coded frame / audio packet).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Packet {
    /// Owning track id.
    pub track_id: u32,
    /// Presentation timestamp in microseconds from the start of the stream.
    pub timestamp_us: i64,
    /// Packet duration in microseconds (`0` if the container does not state it).
    pub duration_us: i64,
    /// `true` if this packet is independently decodable (a key-frame / sync
    /// sample); seeking targets these.
    pub keyframe: bool,
    /// The coded bytes.
    pub data: Vec<u8>,
}

/// Recognised container formats.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContainerFormat {
    /// ISO base-media file format (MP4 / MOV / M4A).
    Mp4,
    /// Matroska or WebM (both EBML; WebM is a Matroska profile).
    Matroska,
    /// Unrecognised.
    Unknown,
}

/// Detect the container format from the leading bytes.
#[must_use]
pub fn detect_format(bytes: &[u8]) -> ContainerFormat {
    // EBML files (MKV/WebM) start with the EBML header magic 0x1A45DFA3.
    if bytes.starts_with(&[0x1A, 0x45, 0xDF, 0xA3]) {
        return ContainerFormat::Matroska;
    }
    // ISO-BMFF: bytes 4..8 are the 'ftyp' box type.
    if bytes.get(4..8) == Some(b"ftyp") {
        return ContainerFormat::Mp4;
    }
    ContainerFormat::Unknown
}

/// A parsed container: its tracks and the demultiplexed packets.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Demuxer {
    format: ContainerFormat,
    tracks: Vec<Track>,
    packets: Vec<Packet>,
}

impl Demuxer {
    /// Detect the format and demultiplex the whole buffer.
    ///
    /// Returns `None` if the format is unrecognised or the structure is too
    /// malformed to yield any track.
    #[must_use]
    pub fn parse(bytes: &[u8]) -> Option<Self> {
        match detect_format(bytes) {
            ContainerFormat::Mp4 => parse_mp4(bytes),
            ContainerFormat::Matroska => parse_matroska(bytes),
            ContainerFormat::Unknown => None,
        }
    }

    /// The detected container format.
    #[must_use]
    pub const fn format(&self) -> ContainerFormat {
        self.format
    }

    /// All parsed tracks.
    #[must_use]
    pub fn tracks(&self) -> &[Track] {
        &self.tracks
    }

    /// All demultiplexed packets, in file order.
    #[must_use]
    pub fn packets(&self) -> &[Packet] {
        &self.packets
    }

    /// The first video track, if any.
    #[must_use]
    pub fn video_track(&self) -> Option<&Track> {
        self.tracks.iter().find(|t| t.kind == TrackKind::Video)
    }

    /// The first audio track, if any.
    #[must_use]
    pub fn audio_track(&self) -> Option<&Track> {
        self.tracks.iter().find(|t| t.kind == TrackKind::Audio)
    }

    /// Iterator over packets belonging to `track_id`.
    pub fn packets_for(&self, track_id: u32) -> impl Iterator<Item = &Packet> {
        self.packets.iter().filter(move |p| p.track_id == track_id)
    }

    /// Build a demuxer directly from parts (host integration tests only).
    #[cfg(test)]
    pub(crate) fn from_parts(
        format: ContainerFormat,
        tracks: Vec<Track>,
        packets: Vec<Packet>,
    ) -> Self {
        Self {
            format,
            tracks,
            packets,
        }
    }
}

/// Convert `ticks` at `timescale` ticks/second to microseconds (saturating).
fn ticks_to_us(ticks: u64, timescale: u32) -> i64 {
    if timescale == 0 {
        return 0;
    }
    let micros = u128::from(ticks)
        .checked_mul(1_000_000)
        .and_then(|n| n.checked_div(u128::from(timescale)))
        .unwrap_or(0);
    i64::try_from(micros).unwrap_or(i64::MAX)
}

// ===========================================================================
// ISO-BMFF (MP4)
// ===========================================================================

/// One box: its FourCC type and its content slice (excluding the header).
struct Mp4Box<'a> {
    kind: [u8; 4],
    body: &'a [u8],
}

/// Iterate the boxes directly contained in `data` (one nesting level).
fn iter_boxes(data: &[u8]) -> Vec<Mp4Box<'_>> {
    let mut out = Vec::new();
    let mut r = ByteReader::new(data);
    while r.remaining() >= 8 {
        let Some(size32) = r.u32() else { break };
        let Some(kind) = r.take(4).and_then(|s| <[u8; 4]>::try_from(s).ok()) else {
            break;
        };
        let body_len = if size32 == 1 {
            // 64-bit largesize follows the type.
            match r.u64() {
                Some(large) => match usize::try_from(large.saturating_sub(16)) {
                    Ok(n) => n,
                    Err(_) => break,
                },
                None => break,
            }
        } else if size32 == 0 {
            // Extends to end of the enclosing buffer.
            r.remaining()
        } else {
            match usize::try_from(size32).map(|s| s.saturating_sub(8)) {
                Ok(n) => n,
                Err(_) => break,
            }
        };
        let Some(body) = r.take(body_len) else { break };
        out.push(Mp4Box { kind, body });
    }
    out
}

/// First child box of type `kind` within `data`.
fn find_box<'a>(data: &'a [u8], kind: &[u8; 4]) -> Option<&'a [u8]> {
    iter_boxes(data)
        .into_iter()
        .find(|b| &b.kind == kind)
        .map(|b| b.body)
}

/// Demultiplex an ISO-BMFF buffer.
fn parse_mp4(bytes: &[u8]) -> Option<Demuxer> {
    let moov = find_box(bytes, b"moov")?;
    let mut tracks = Vec::new();
    let mut packets = Vec::new();

    for trak in iter_boxes(moov).into_iter().filter(|b| &b.kind == b"trak") {
        if let Some((track, mut trak_packets)) = parse_mp4_trak(trak.body, bytes) {
            tracks.push(track);
            packets.append(&mut trak_packets);
        }
    }

    if tracks.is_empty() {
        return None;
    }
    // Stable sort by timestamp keeps interleaving deterministic for the player.
    packets.sort_by_key(|p| p.timestamp_us);
    Some(Demuxer {
        format: ContainerFormat::Mp4,
        tracks,
        packets,
    })
}

/// Parse a single `trak` into its track metadata and packets.
fn parse_mp4_trak(trak: &[u8], file: &[u8]) -> Option<(Track, Vec<Packet>)> {
    let tkhd = find_box(trak, b"tkhd");
    let track_id = tkhd.and_then(parse_tkhd_id).unwrap_or(0);
    let (decl_w, decl_h) = tkhd.and_then(parse_tkhd_dims).unwrap_or((None, None));

    let mdia = find_box(trak, b"mdia")?;
    let mdhd = find_box(mdia, b"mdhd")?;
    let timescale = parse_mdhd_timescale(mdhd)?;
    let handler = find_box(mdia, b"hdlr")
        .and_then(parse_hdlr_type)
        .unwrap_or(*b"    ");

    let minf = find_box(mdia, b"minf")?;
    let stbl = find_box(minf, b"stbl")?;
    let stsd = find_box(stbl, b"stsd")?;

    let (codec, kind, codec_private) = parse_stsd(stsd, &handler);

    // Sample tables.
    let stts = find_box(stbl, b"stts").map(parse_stts).unwrap_or_default();
    let stsz = find_box(stbl, b"stsz").and_then(parse_stsz)?;
    let stsc = find_box(stbl, b"stsc").map(parse_stsc).unwrap_or_default();
    let chunk_offsets = parse_chunk_offsets(stbl)?;
    let sync_samples = find_box(stbl, b"stss").map(parse_stss);

    let packets = build_mp4_packets(
        track_id,
        timescale,
        file,
        &stts,
        &stsz,
        &stsc,
        &chunk_offsets,
        sync_samples.as_deref(),
    );

    let (width, height) = match codec {
        CodecId::Video(_) => (decl_w, decl_h),
        _ => (None, None),
    };

    let track = Track {
        id: track_id,
        kind,
        codec,
        timescale,
        codec_private,
        width,
        height,
    };
    Some((track, packets))
}

/// `tkhd` track_ID (offset depends on the version flag).
fn parse_tkhd_id(tkhd: &[u8]) -> Option<u32> {
    let mut r = ByteReader::new(tkhd);
    let version = r.u8()?;
    r.skip(3)?; // flags
    if version == 1 {
        r.skip(16)?; // creation+modification (u64 each)
    } else {
        r.skip(8)?; // creation+modification (u32 each)
    }
    r.u32()
}

/// `tkhd` declared width/height (16.16 fixed-point, integer part taken).
fn parse_tkhd_dims(tkhd: &[u8]) -> Option<(Option<u32>, Option<u32>)> {
    let mut r = ByteReader::new(tkhd);
    let version = r.u8()?;
    r.skip(3)?;
    // creation, modification, track_ID, reserved, duration.
    if version == 1 {
        r.skip(16 + 4 + 4 + 8)?;
    } else {
        r.skip(8 + 4 + 4 + 4)?;
    }
    r.skip(8)?; // reserved[2]
    r.skip(2 + 2)?; // layer, alternate_group
    r.skip(2)?; // volume
    r.skip(2)?; // reserved
    r.skip(36)?; // matrix[9]
    let width = r.u32()? >> 16;
    let height = r.u32()? >> 16;
    let w = if width == 0 { None } else { Some(width) };
    let h = if height == 0 { None } else { Some(height) };
    Some((w, h))
}

/// `mdhd` media timescale (ticks per second).
fn parse_mdhd_timescale(mdhd: &[u8]) -> Option<u32> {
    let mut r = ByteReader::new(mdhd);
    let version = r.u8()?;
    r.skip(3)?;
    if version == 1 {
        r.skip(16)?; // creation+modification (u64 each)
    } else {
        r.skip(8)?; // creation+modification (u32 each)
    }
    r.u32()
}

/// `hdlr` handler_type (`vide`, `soun`, …).
fn parse_hdlr_type(hdlr: &[u8]) -> Option<[u8; 4]> {
    let mut r = ByteReader::new(hdlr);
    r.skip(4)?; // version+flags
    r.skip(4)?; // pre_defined
    r.take(4)?.try_into().ok()
}

/// Decode `stsd`: codec, kind, and best-effort codec-private bytes.
fn parse_stsd(stsd: &[u8], handler: &[u8; 4]) -> (CodecId, TrackKind, Vec<u8>) {
    let mut r = ByteReader::new(stsd);
    if r.skip(4).is_none() || r.u32().is_none() {
        return (CodecId::Other, TrackKind::Other, Vec::new());
    }
    // First sample entry: size(4) + format(4) + ...
    let Some(entry_size) = r.u32() else {
        return (CodecId::Other, TrackKind::Other, Vec::new());
    };
    let Some(fourcc_slice) = r.take(4) else {
        return (CodecId::Other, TrackKind::Other, Vec::new());
    };
    let fourcc: [u8; 4] = match fourcc_slice.try_into() {
        Ok(f) => f,
        Err(_) => return (CodecId::Other, TrackKind::Other, Vec::new()),
    };
    // Remaining body of this sample entry (entry_size includes size+format = 8).
    let body_len = usize::try_from(entry_size)
        .map(|s| s.saturating_sub(8))
        .unwrap_or(0);
    let entry_body = r.take(body_len).unwrap_or(&[]);

    match handler {
        b"vide" => {
            let codec = VideoCodec::from_fourcc(&fourcc);
            let private = extract_codec_private(entry_body, true);
            (CodecId::Video(codec), TrackKind::Video, private)
        }
        b"soun" => {
            let codec = AudioCodec::from_fourcc(&fourcc);
            let private = extract_codec_private(entry_body, false);
            (CodecId::Audio(codec), TrackKind::Audio, private)
        }
        b"sbtl" | b"subt" | b"text" => (CodecId::Other, TrackKind::Subtitle, Vec::new()),
        _ => (CodecId::Other, TrackKind::Other, Vec::new()),
    }
}

/// Best-effort codec-private extraction from a sample-entry body.
///
/// Skips the fixed `VisualSampleEntry` (78 bytes) / `AudioSampleEntry`
/// (20 bytes) header after the shared 8-byte `SampleEntry`, then returns the
/// first recognised child box (`avcC`/`vpcC`/`dOps`).  Returns empty on any
/// shortfall — codec-private is optional metadata.
fn extract_codec_private(entry_body: &[u8], video: bool) -> Vec<u8> {
    let mut r = ByteReader::new(entry_body);
    if r.skip(8).is_none() {
        return Vec::new();
    }
    let fixed = if video { 78 } else { 20 };
    if r.skip(fixed).is_none() {
        return Vec::new();
    }
    let Some(rest) = r.take(r.remaining()) else {
        return Vec::new();
    };
    for b in iter_boxes(rest) {
        if matches!(&b.kind, b"avcC" | b"vpcC" | b"dOps" | b"hvcC" | b"av1C") {
            return b.body.to_vec();
        }
    }
    Vec::new()
}

/// `stts` decoded into (sample_count, sample_delta) runs.
fn parse_stts(stts: &[u8]) -> Vec<(u32, u32)> {
    let mut r = ByteReader::new(stts);
    let mut out = Vec::new();
    if r.skip(4).is_none() {
        return out;
    }
    let Some(count) = r.u32() else { return out };
    for _ in 0..count {
        match (r.u32(), r.u32()) {
            (Some(sc), Some(sd)) => out.push((sc, sd)),
            _ => break,
        }
    }
    out
}

/// `stsz` decoded into per-sample sizes.
fn parse_stsz(stsz: &[u8]) -> Option<Vec<u32>> {
    let mut r = ByteReader::new(stsz);
    r.skip(4)?; // version+flags
    let sample_size = r.u32()?;
    let sample_count = r.u32()?;
    let mut sizes = Vec::new();
    if sample_size != 0 {
        for _ in 0..sample_count {
            sizes.push(sample_size);
        }
    } else {
        for _ in 0..sample_count {
            sizes.push(r.u32()?);
        }
    }
    Some(sizes)
}

/// `stsc` decoded into (first_chunk, samples_per_chunk) runs.
fn parse_stsc(stsc: &[u8]) -> Vec<(u32, u32)> {
    let mut r = ByteReader::new(stsc);
    let mut out = Vec::new();
    if r.skip(4).is_none() {
        return out;
    }
    let Some(count) = r.u32() else { return out };
    for _ in 0..count {
        let first_chunk = r.u32();
        let samples_per_chunk = r.u32();
        let _sample_description_index = r.u32();
        match (first_chunk, samples_per_chunk) {
            (Some(fc), Some(spc)) => out.push((fc, spc)),
            _ => break,
        }
    }
    out
}

/// Chunk offsets from `stco` (32-bit) or `co64` (64-bit).
fn parse_chunk_offsets(stbl: &[u8]) -> Option<Vec<u64>> {
    if let Some(stco) = find_box(stbl, b"stco") {
        let mut r = ByteReader::new(stco);
        r.skip(4)?;
        let count = r.u32()?;
        let mut out = Vec::new();
        for _ in 0..count {
            out.push(u64::from(r.u32()?));
        }
        return Some(out);
    }
    if let Some(co64) = find_box(stbl, b"co64") {
        let mut r = ByteReader::new(co64);
        r.skip(4)?;
        let count = r.u32()?;
        let mut out = Vec::new();
        for _ in 0..count {
            out.push(r.u64()?);
        }
        return Some(out);
    }
    None
}

/// `stss` sync-sample numbers (1-based).
fn parse_stss(stss: &[u8]) -> Vec<u32> {
    let mut r = ByteReader::new(stss);
    let mut out = Vec::new();
    if r.skip(4).is_none() {
        return out;
    }
    let Some(count) = r.u32() else { return out };
    for _ in 0..count {
        match r.u32() {
            Some(n) => out.push(n),
            None => break,
        }
    }
    out
}

/// Samples-per-chunk for a 1-based chunk index, given the `stsc` runs.
fn samples_per_chunk(chunk_1based: u32, runs: &[(u32, u32)]) -> u32 {
    let mut spc = 0;
    for &(first_chunk, count) in runs {
        if first_chunk <= chunk_1based {
            spc = count;
        } else {
            break;
        }
    }
    spc
}

/// Sample delta (in timescale ticks) for a 0-based sample index.
fn sample_delta(sample_index: usize, runs: &[(u32, u32)]) -> u32 {
    let mut seen: usize = 0;
    for &(count, delta) in runs {
        let next = seen.saturating_add(usize::try_from(count).unwrap_or(usize::MAX));
        if sample_index < next {
            return delta;
        }
        seen = next;
    }
    runs.last().map_or(0, |&(_, delta)| delta)
}

/// Rebuild the packet list from the MP4 sample tables.
#[allow(clippy::too_many_arguments)]
fn build_mp4_packets(
    track_id: u32,
    timescale: u32,
    file: &[u8],
    stts: &[(u32, u32)],
    stsz: &[u32],
    stsc: &[(u32, u32)],
    chunk_offsets: &[u64],
    sync_samples: Option<&[u32]>,
) -> Vec<Packet> {
    let mut packets = Vec::new();
    let mut sample_index: usize = 0;
    let mut dts_ticks: u64 = 0;

    for (chunk_idx, &chunk_offset) in chunk_offsets.iter().enumerate() {
        let chunk_1based = u32::try_from(chunk_idx.saturating_add(1)).unwrap_or(u32::MAX);
        let spc = samples_per_chunk(chunk_1based, stsc);
        let mut file_offset = chunk_offset;

        for _ in 0..spc {
            let Some(&size) = stsz.get(sample_index) else {
                return packets;
            };
            let delta = sample_delta(sample_index, stts);
            // No `stss` means every sample is a sync sample; otherwise the
            // 1-based sample number must be listed.
            let keyframe = sync_samples.is_none_or(|list| {
                let one_based = u32::try_from(sample_index.saturating_add(1)).unwrap_or(u32::MAX);
                list.contains(&one_based)
            });

            let start = usize::try_from(file_offset).unwrap_or(usize::MAX);
            let end = start.saturating_add(usize::try_from(size).unwrap_or(usize::MAX));
            let data = file.get(start..end).map(<[u8]>::to_vec).unwrap_or_default();

            packets.push(Packet {
                track_id,
                timestamp_us: ticks_to_us(dts_ticks, timescale),
                duration_us: ticks_to_us(u64::from(delta), timescale),
                keyframe,
                data,
            });

            dts_ticks = dts_ticks.saturating_add(u64::from(delta));
            file_offset = file_offset.saturating_add(u64::from(size));
            sample_index = sample_index.saturating_add(1);
        }
    }

    packets
}

// ===========================================================================
// EBML (Matroska / WebM)
// ===========================================================================

// Element IDs (with marker bit retained, as `ebml_vint(keep_marker = true)`
// returns them).
const ID_SEGMENT: u64 = 0x1853_8067;
const ID_INFO: u64 = 0x1549_A966;
const ID_TIMESTAMP_SCALE: u64 = 0x002A_D7B1;
const ID_TRACKS: u64 = 0x1654_AE6B;
const ID_TRACK_ENTRY: u64 = 0xAE;
const ID_TRACK_NUMBER: u64 = 0xD7;
const ID_TRACK_TYPE: u64 = 0x83;
const ID_CODEC_ID: u64 = 0x86;
const ID_CODEC_PRIVATE: u64 = 0x63A2;
const ID_VIDEO: u64 = 0xE0;
const ID_PIXEL_WIDTH: u64 = 0xB0;
const ID_PIXEL_HEIGHT: u64 = 0xBA;
const ID_CLUSTER: u64 = 0x1F43_B675;
const ID_TIMESTAMP: u64 = 0xE7;
const ID_SIMPLE_BLOCK: u64 = 0xA3;
const ID_BLOCK_GROUP: u64 = 0xA0;
const ID_BLOCK: u64 = 0xA1;

/// A raw EBML element: its ID, and its content slice.
struct EbmlElement<'a> {
    id: u64,
    body: &'a [u8],
}

/// Iterate the EBML elements directly contained in `data` (one level).
fn iter_ebml(data: &[u8]) -> Vec<EbmlElement<'_>> {
    let mut out = Vec::new();
    let mut r = ByteReader::new(data);
    while !r.is_empty() {
        let Some(id) = r.ebml_vint(true) else { break };
        let Some(size) = r.ebml_vint(false) else {
            break;
        };
        // Unknown-size sentinel: all data bits set -> spans to end of `data`.
        let body_len = if is_unknown_size(size) {
            r.remaining()
        } else {
            match usize::try_from(size) {
                Ok(n) => n.min(r.remaining()),
                Err(_) => break,
            }
        };
        let Some(body) = r.take(body_len) else { break };
        out.push(EbmlElement { id, body });
    }
    out
}

/// `true` if `size` is the EBML "unknown size" value for any vint width.
///
/// A length-`L` vint encodes "unknown" as all `7 × L` data bits set; this spans
/// the parser's supported widths `L = 1..=8` (`0x7F`, `0x3FFF`, … `2^56 − 1`).
fn is_unknown_size(size: u64) -> bool {
    (1u32..=8).any(|l| size == (1u64 << (7 * l)) - 1)
}

/// Read a big-endian unsigned integer of `body.len()` bytes (<= 8).
fn ebml_uint(body: &[u8]) -> u64 {
    let mut value: u64 = 0;
    for &byte in body.iter().take(8) {
        value = (value << 8) | u64::from(byte);
    }
    value
}

/// Demultiplex a Matroska/WebM buffer.
fn parse_matroska(bytes: &[u8]) -> Option<Demuxer> {
    // Top level: EBML header, then Segment.
    let segment = iter_ebml(bytes).into_iter().find(|e| e.id == ID_SEGMENT)?;

    // TimestampScale (ns per tick); default 1_000_000 ns = 1 ms.
    let mut timestamp_scale_ns: u64 = 1_000_000;
    let mut tracks = Vec::new();
    let mut packets = Vec::new();

    for elem in iter_ebml(segment.body) {
        match elem.id {
            ID_INFO => {
                for info in iter_ebml(elem.body) {
                    if info.id == ID_TIMESTAMP_SCALE {
                        let scale = ebml_uint(info.body);
                        if scale != 0 {
                            timestamp_scale_ns = scale;
                        }
                    }
                }
            }
            ID_TRACKS => {
                for entry in iter_ebml(elem.body) {
                    if entry.id == ID_TRACK_ENTRY {
                        tracks.push(parse_mkv_track(entry.body, timestamp_scale_ns));
                    }
                }
            }
            ID_CLUSTER => {
                parse_mkv_cluster(elem.body, timestamp_scale_ns, &mut packets);
            }
            _ => {}
        }
    }

    if tracks.is_empty() {
        return None;
    }
    packets.sort_by_key(|p| p.timestamp_us);
    Some(Demuxer {
        format: ContainerFormat::Matroska,
        tracks,
        packets,
    })
}

/// Parse one Matroska `TrackEntry`.
fn parse_mkv_track(entry: &[u8], timestamp_scale_ns: u64) -> Track {
    let mut number: u32 = 0;
    let mut track_type: u64 = 0;
    let mut codec_id = String::new();
    let mut codec_private = Vec::new();
    let mut width = None;
    let mut height = None;

    for e in iter_ebml(entry) {
        match e.id {
            ID_TRACK_NUMBER => number = u32::try_from(ebml_uint(e.body)).unwrap_or(0),
            ID_TRACK_TYPE => track_type = ebml_uint(e.body),
            ID_CODEC_ID => {
                if let Ok(s) = core::str::from_utf8(e.body) {
                    codec_id = String::from(s.trim_end_matches('\0'));
                }
            }
            ID_CODEC_PRIVATE => codec_private = e.body.to_vec(),
            ID_VIDEO => {
                for v in iter_ebml(e.body) {
                    match v.id {
                        ID_PIXEL_WIDTH => width = u32::try_from(ebml_uint(v.body)).ok(),
                        ID_PIXEL_HEIGHT => height = u32::try_from(ebml_uint(v.body)).ok(),
                        _ => {}
                    }
                }
            }
            _ => {}
        }
    }

    let (kind, codec) = match track_type {
        1 => (
            TrackKind::Video,
            CodecId::Video(VideoCodec::from_codec_id(&codec_id)),
        ),
        2 => (
            TrackKind::Audio,
            CodecId::Audio(AudioCodec::from_codec_id(&codec_id)),
        ),
        0x11 => (TrackKind::Subtitle, CodecId::Other),
        _ => (TrackKind::Other, CodecId::Other),
    };

    // Track timescale in ticks/second derived from the ns scale.
    let timescale = u32::try_from(
        1_000_000_000u64
            .checked_div(timestamp_scale_ns)
            .unwrap_or(1000),
    )
    .unwrap_or(1000);

    Track {
        id: number,
        kind,
        codec,
        timescale,
        codec_private,
        width,
        height,
    }
}

/// Parse one Matroska `Cluster`, appending its blocks' packets.
fn parse_mkv_cluster(cluster: &[u8], timestamp_scale_ns: u64, packets: &mut Vec<Packet>) {
    let mut cluster_ts: u64 = 0;
    for e in iter_ebml(cluster) {
        match e.id {
            ID_TIMESTAMP => cluster_ts = ebml_uint(e.body),
            ID_SIMPLE_BLOCK => {
                decode_block(e.body, cluster_ts, timestamp_scale_ns, true, packets);
            }
            ID_BLOCK_GROUP => {
                for bg in iter_ebml(e.body) {
                    if bg.id == ID_BLOCK {
                        // Block in a BlockGroup carries no keyframe flag; treat
                        // as non-key (BlockGroups wrap referenced frames).
                        decode_block(bg.body, cluster_ts, timestamp_scale_ns, false, packets);
                    }
                }
            }
            _ => {}
        }
    }
}

/// Decode a (Simple)Block body into one or more packets.
fn decode_block(
    block: &[u8],
    cluster_ts: u64,
    timestamp_scale_ns: u64,
    simple: bool,
    packets: &mut Vec<Packet>,
) {
    let mut r = ByteReader::new(block);
    let Some(track_number) = r.ebml_vint(false) else {
        return;
    };
    // Relative timestamp is a signed 16-bit big-endian value.
    let Some(rel_bytes) = r.take(2).and_then(|s| <[u8; 2]>::try_from(s).ok()) else {
        return;
    };
    let rel = i32::from(i16::from_be_bytes(rel_bytes));
    let Some(flags) = r.u8() else {
        return;
    };
    let keyframe = simple && (flags & 0x80) != 0;
    let lacing = (flags >> 1) & 0x03;

    let abs_ticks = i64::try_from(cluster_ts)
        .unwrap_or(i64::MAX)
        .saturating_add(i64::from(rel));
    let timestamp_us = ticks_scaled_us(abs_ticks, timestamp_scale_ns);
    let track_id = u32::try_from(track_number).unwrap_or(0);

    let payload = r.take(r.remaining()).unwrap_or(&[]);
    let frames = split_laced(payload, lacing);
    for frame in frames {
        packets.push(Packet {
            track_id,
            timestamp_us,
            duration_us: 0,
            keyframe,
            data: frame,
        });
    }
}

/// Apply the EBML `timestamp_scale_ns` to a tick count, yielding microseconds.
fn ticks_scaled_us(ticks: i64, timestamp_scale_ns: u64) -> i64 {
    let ns = i128::from(ticks).saturating_mul(i128::from(timestamp_scale_ns));
    let us = ns.checked_div(1000).unwrap_or(0);
    i64::try_from(us).unwrap_or(i64::MAX)
}

/// Split a block payload into frames according to its lacing mode.
///
/// `lacing`: 0 = none, 1 = Xiph, 2 = fixed-size, 3 = EBML.  None and fixed are
/// split exactly; Xiph/EBML are a documented follow-up and emit the payload as
/// a single frame.
fn split_laced(payload: &[u8], lacing: u8) -> Vec<Vec<u8>> {
    if lacing == 2 {
        // Fixed-size lacing: first byte is (frame_count - 1), frames equal size.
        let mut r = ByteReader::new(payload);
        if let Some(count_minus_1) = r.u8() {
            let count = usize::from(count_minus_1).saturating_add(1);
            let rest = r.take(r.remaining()).unwrap_or(&[]);
            if rest.len() % count == 0 {
                if let Some(frame_len) = rest.len().checked_div(count) {
                    if frame_len > 0 {
                        return rest.chunks(frame_len).map(<[u8]>::to_vec).collect();
                    }
                }
            }
        }
        return Vec::new();
    }
    // None (and unsupported Xiph/EBML, degraded): the whole payload is one frame.
    if payload.is_empty() {
        Vec::new()
    } else {
        alloc::vec![payload.to_vec()]
    }
}
