//! Host tests for the media-player core (WS8-02).
//!
//! Each container/codec parser is exercised against synthetic bitstreams built
//! by the helpers below, and the decode/sync/sink/playlist/player orchestration
//! is driven end-to-end with mock backends.

#![allow(
    clippy::similar_names,
    clippy::trivially_copy_pass_by_ref,
    clippy::cast_possible_truncation,
    reason = "test fixtures build synthetic containers: the MP4 atom helpers share domain-similar names, box sizes cast usize->u32, and FourCC helpers take &[u8; 4]"
)]

extern crate std;

use alloc::{boxed::Box, vec, vec::Vec};

use nexacore_types::ai::{AudioFormat, PcmEncoding};

use crate::{
    codec::{
        AudioCodec, VideoCodec, parse_aac_adts, parse_h264_sps, parse_opus_head, parse_vp9_frame,
    },
    container::{CodecId, ContainerFormat, Demuxer, Packet, Track, TrackKind},
    decode::{
        Acceleration, AudioDecoder, AudioFrame, DecodeError, DecoderFactory, DecoderSelector,
        HwProbe, PixelFormat, VideoDecoder, VideoFrame,
    },
    player::{MediaPlayer, PlayerState, run_session},
    playlist::{Playlist, RepeatMode},
    sink::{AudioSink, HeadlessAudioSink, HeadlessVideoSink, VideoSink, present_scheduled},
    sync::{AvSyncClock, FrameAction, SyncThresholds},
};

// ---------------------------------------------------------------------------
// Bit / byte builders.
// ---------------------------------------------------------------------------

/// An MSB-first bit writer with Exp-Golomb support (mirrors `codec::BitReader`).
#[derive(Default)]
struct BitWriter {
    bits: Vec<bool>,
}

impl BitWriter {
    fn new() -> Self {
        Self::default()
    }

    fn bit(&mut self, b: bool) {
        self.bits.push(b);
    }

    fn put(&mut self, value: u32, n: u32) {
        for i in (0..n).rev() {
            self.bit((value >> i) & 1 == 1);
        }
    }

    fn ue(&mut self, v: u32) {
        let x = v + 1;
        let m = 31 - x.leading_zeros();
        for _ in 0..m {
            self.bit(false);
        }
        self.put(x, m + 1);
    }

    fn into_bytes(self) -> Vec<u8> {
        let mut out = Vec::new();
        for chunk in self.bits.chunks(8) {
            let mut byte = 0u8;
            for (i, &b) in chunk.iter().enumerate() {
                if b {
                    byte |= 1 << (7 - i);
                }
            }
            out.push(byte);
        }
        out
    }
}

fn be32(v: u32) -> [u8; 4] {
    v.to_be_bytes()
}

/// Build an ISO-BMFF box: `size(4) + type(4) + body`.
fn mp4_box(kind: &[u8; 4], body: &[u8]) -> Vec<u8> {
    let mut v = Vec::new();
    v.extend_from_slice(&be32(8 + body.len() as u32));
    v.extend_from_slice(kind);
    v.extend_from_slice(body);
    v
}

/// Concatenate byte slices.
fn cat(parts: &[&[u8]]) -> Vec<u8> {
    let mut v = Vec::new();
    for p in parts {
        v.extend_from_slice(p);
    }
    v
}

/// Build an EBML element: `id + size-as-8-byte-vint + body`.
fn ebml(id: &[u8], body: &[u8]) -> Vec<u8> {
    let mut v = Vec::new();
    v.extend_from_slice(id);
    // 8-byte length vint: 0x01 then 7 big-endian bytes.
    let len = body.len() as u64;
    v.push(0x01);
    v.extend_from_slice(&len.to_be_bytes()[1..]);
    v.extend_from_slice(body);
    v
}

// ===========================================================================
// codec.rs — header parsers (WS8-02.3 / WS8-02.4)
// ===========================================================================

#[test]
fn h264_sps_recovers_dimensions() {
    // Baseline profile (66), frame_mbs_only=1, no cropping; 1280x720.
    let mut w = BitWriter::new();
    w.put(66, 8); // profile_idc
    w.put(0, 8); // constraints + reserved
    w.put(31, 8); // level_idc
    w.ue(0); // seq_parameter_set_id
    w.ue(0); // log2_max_frame_num_minus4
    w.ue(0); // pic_order_cnt_type
    w.ue(0); // log2_max_pic_order_cnt_lsb_minus4
    w.ue(0); // max_num_ref_frames
    w.bit(false); // gaps_in_frame_num_value_allowed_flag
    w.ue(79); // pic_width_in_mbs_minus1 -> 80*16 = 1280
    w.ue(44); // pic_height_in_map_units_minus1 -> 45*16 = 720
    w.bit(true); // frame_mbs_only_flag
    w.bit(false); // direct_8x8_inference_flag
    w.bit(false); // frame_cropping_flag
    w.bit(false); // vui_parameters_present_flag
    w.bit(true); // rbsp_stop_one_bit

    let mut nal = vec![0x67u8]; // nal_ref_idc=3, type=7 (SPS)
    nal.extend_from_slice(&w.into_bytes());

    let params = parse_h264_sps(&nal).expect("SPS parses");
    assert_eq!(params.width, 1280);
    assert_eq!(params.height, 720);
}

#[test]
fn h264_sps_applies_cropping() {
    // 1920x1088 coded, cropped by 4 map-units (8 px) at the bottom -> 1080.
    let mut w = BitWriter::new();
    w.put(66, 8);
    w.put(0, 8);
    w.put(40, 8);
    w.ue(0);
    w.ue(0);
    w.ue(0);
    w.ue(0);
    w.ue(0);
    w.bit(false);
    w.ue(119); // 120*16 = 1920
    w.ue(67); // 68*16 = 1088
    w.bit(true); // frame_mbs_only
    w.bit(false);
    w.bit(true); // frame_cropping_flag
    w.ue(0); // left
    w.ue(0); // right
    w.ue(0); // top
    w.ue(4); // bottom: 4 * CropUnitY(2) = 8 px
    w.bit(false); // vui
    w.bit(true);

    let mut nal = vec![0x67u8];
    nal.extend_from_slice(&w.into_bytes());
    let params = parse_h264_sps(&nal).expect("SPS parses");
    assert_eq!(params.width, 1920);
    assert_eq!(params.height, 1080);
}

#[test]
fn h264_sps_rejects_non_sps_nal() {
    // type 1 (non-IDR slice) is not an SPS.
    assert!(parse_h264_sps(&[0x61, 0x00, 0x00]).is_none());
}

#[test]
fn vp9_keyframe_header_recovers_dimensions() {
    let mut w = BitWriter::new();
    w.put(0b10, 2); // frame_marker
    w.bit(false); // profile_low_bit
    w.bit(false); // profile_high_bit -> profile 0
    w.bit(false); // show_existing_frame
    w.bit(false); // frame_type: key
    w.bit(true); // show_frame
    w.bit(false); // error_resilient_mode
    w.put(0x49_83_42, 24); // sync code
    w.put(1, 3); // color_space (not CS_RGB)
    w.bit(false); // color_range
    w.put(639, 16); // width_minus_1 -> 640
    w.put(479, 16); // height_minus_1 -> 480

    let info = parse_vp9_frame(&w.into_bytes()).expect("VP9 header parses");
    assert!(info.key_frame);
    assert!(info.show_frame);
    let dims = info.dimensions.expect("key-frame carries dimensions");
    assert_eq!(dims.width, 640);
    assert_eq!(dims.height, 480);
}

#[test]
fn vp9_interframe_has_no_dimensions() {
    let mut w = BitWriter::new();
    w.put(0b10, 2);
    w.bit(false);
    w.bit(false);
    w.bit(false); // show_existing_frame
    w.bit(true); // frame_type: inter
    w.bit(true); // show_frame
    w.bit(false);

    let info = parse_vp9_frame(&w.into_bytes()).expect("VP9 inter header parses");
    assert!(!info.key_frame);
    assert!(info.dimensions.is_none());
}

#[test]
fn opus_head_recovers_rate_and_channels() {
    let mut head = Vec::new();
    head.extend_from_slice(b"OpusHead");
    head.push(1); // version
    head.push(2); // channel count
    head.extend_from_slice(&[0x00, 0x00]); // pre-skip (BE, ignored)
    head.extend_from_slice(&48_000u32.to_le_bytes()); // input sample rate (LE)
    head.extend_from_slice(&[0x00, 0x00]); // output gain
    head.push(0); // mapping family

    let params = parse_opus_head(&head).expect("OpusHead parses");
    assert_eq!(params.sample_rate, 48_000);
    assert_eq!(params.channels, 2);
}

#[test]
fn aac_adts_recovers_rate_and_channels() {
    // sync 0xFFF, sampling_frequency_index 4 (44100), channel_configuration 2.
    let header = [0xFFu8, 0xF9, 0x50, 0x80, 0x00, 0x00, 0x00];
    let params = parse_aac_adts(&header).expect("ADTS parses");
    assert_eq!(params.sample_rate, 44_100);
    assert_eq!(params.channels, 2);
}

#[test]
fn aac_adts_rejects_bad_syncword() {
    assert!(parse_aac_adts(&[0x00, 0x00, 0x00, 0x00]).is_none());
}

// ===========================================================================
// container.rs — demuxers (WS8-02.2)
// ===========================================================================

#[test]
fn mp4_demux_recovers_track_and_packets() {
    let ftyp = mp4_box(b"ftyp", &cat(&[b"isom", &be32(0), b"isom"]));
    let mdat_data = vec![0xAAu8, 0xBB, 0xCC, 0xDD, 0xEE];
    let mdat = mp4_box(b"mdat", &mdat_data);
    let mdat_data_offset = (ftyp.len() + 8) as u32;

    // tkhd v0 (track_ID=1, 64x48).
    let mut tkhd_body = Vec::new();
    tkhd_body.extend_from_slice(&[0, 0, 0, 0]); // version+flags
    tkhd_body.extend_from_slice(&[0; 8]); // creation+modification
    tkhd_body.extend_from_slice(&be32(1)); // track_ID
    tkhd_body.extend_from_slice(&be32(0)); // reserved
    tkhd_body.extend_from_slice(&be32(0)); // duration
    tkhd_body.extend_from_slice(&[0; 8]); // reserved[2]
    tkhd_body.extend_from_slice(&[0; 4]); // layer + alternate_group
    tkhd_body.extend_from_slice(&[0; 4]); // volume + reserved
    tkhd_body.extend_from_slice(&[0; 36]); // matrix
    tkhd_body.extend_from_slice(&be32(64 << 16)); // width
    tkhd_body.extend_from_slice(&be32(48 << 16)); // height
    let tkhd = mp4_box(b"tkhd", &tkhd_body);

    // mdhd v0 (timescale 1000).
    let mut mdhd_body = Vec::new();
    mdhd_body.extend_from_slice(&[0, 0, 0, 0]);
    mdhd_body.extend_from_slice(&[0; 8]);
    mdhd_body.extend_from_slice(&be32(1000)); // timescale
    mdhd_body.extend_from_slice(&be32(0)); // duration
    let mdhd = mp4_box(b"mdhd", &mdhd_body);

    // hdlr (vide).
    let mut hdlr_body = Vec::new();
    hdlr_body.extend_from_slice(&[0; 4]);
    hdlr_body.extend_from_slice(&[0; 4]);
    hdlr_body.extend_from_slice(b"vide");
    hdlr_body.extend_from_slice(&[0; 12]);
    hdlr_body.push(0);
    let hdlr = mp4_box(b"hdlr", &hdlr_body);

    // stsd: one avc1 entry with 86 fixed bytes.
    let mut avc1_body = Vec::new();
    avc1_body.extend_from_slice(&[0; 86]);
    let avc1 = mp4_box(b"avc1", &avc1_body);
    let mut stsd_body = Vec::new();
    stsd_body.extend_from_slice(&[0; 4]);
    stsd_body.extend_from_slice(&be32(1));
    stsd_body.extend_from_slice(&avc1);
    let stsd = mp4_box(b"stsd", &stsd_body);

    // stts: 2 samples, delta 500 ticks each.
    let mut stts_body = Vec::new();
    stts_body.extend_from_slice(&[0; 4]);
    stts_body.extend_from_slice(&be32(1));
    stts_body.extend_from_slice(&be32(2));
    stts_body.extend_from_slice(&be32(500));
    let stts = mp4_box(b"stts", &stts_body);

    // stsz: sizes [2, 3].
    let mut stsz_body = Vec::new();
    stsz_body.extend_from_slice(&[0; 4]);
    stsz_body.extend_from_slice(&be32(0)); // sample_size=0 -> per-sample
    stsz_body.extend_from_slice(&be32(2)); // count
    stsz_body.extend_from_slice(&be32(2));
    stsz_body.extend_from_slice(&be32(3));
    let stsz = mp4_box(b"stsz", &stsz_body);

    // stsc: chunk 1 holds 2 samples.
    let mut stsc_body = Vec::new();
    stsc_body.extend_from_slice(&[0; 4]);
    stsc_body.extend_from_slice(&be32(1));
    stsc_body.extend_from_slice(&be32(1)); // first_chunk
    stsc_body.extend_from_slice(&be32(2)); // samples_per_chunk
    stsc_body.extend_from_slice(&be32(1)); // sample_description_index
    let stsc = mp4_box(b"stsc", &stsc_body);

    // stco: chunk offset = mdat data offset.
    let mut stco_body = Vec::new();
    stco_body.extend_from_slice(&[0; 4]);
    stco_body.extend_from_slice(&be32(1));
    stco_body.extend_from_slice(&be32(mdat_data_offset));
    let stco = mp4_box(b"stco", &stco_body);

    // stss: sample 1 is a sync sample.
    let mut stss_body = Vec::new();
    stss_body.extend_from_slice(&[0; 4]);
    stss_body.extend_from_slice(&be32(1));
    stss_body.extend_from_slice(&be32(1));
    let stss = mp4_box(b"stss", &stss_body);

    let stbl = mp4_box(b"stbl", &cat(&[&stsd, &stts, &stsz, &stsc, &stco, &stss]));
    let minf = mp4_box(b"minf", &stbl);
    let mdia = mp4_box(b"mdia", &cat(&[&mdhd, &hdlr, &minf]));
    let trak = mp4_box(b"trak", &cat(&[&tkhd, &mdia]));
    let moov = mp4_box(b"moov", &trak);

    let file = cat(&[&ftyp, &mdat, &moov]);

    let demux = Demuxer::parse(&file).expect("MP4 parses");
    assert_eq!(demux.format(), ContainerFormat::Mp4);
    assert_eq!(demux.tracks().len(), 1);
    let track = &demux.tracks()[0];
    assert_eq!(track.id, 1);
    assert_eq!(track.kind, TrackKind::Video);
    assert_eq!(track.codec, CodecId::Video(VideoCodec::H264));
    assert_eq!(track.timescale, 1000);
    assert_eq!(track.width, Some(64));
    assert_eq!(track.height, Some(48));

    let packets = demux.packets();
    assert_eq!(packets.len(), 2);
    assert_eq!(packets[0].timestamp_us, 0);
    assert!(packets[0].keyframe);
    assert_eq!(packets[0].data, vec![0xAA, 0xBB]);
    assert_eq!(packets[1].timestamp_us, 500_000);
    assert!(!packets[1].keyframe);
    assert_eq!(packets[1].data, vec![0xCC, 0xDD, 0xEE]);
}

#[test]
fn matroska_demux_recovers_track_and_block() {
    let ebml_header = ebml(&[0x1A, 0x45, 0xDF, 0xA3], &[]);

    let ts_scale = ebml(&[0x2A, 0xD7, 0xB1], &[0x0F, 0x42, 0x40]); // 1_000_000
    let info = ebml(&[0x15, 0x49, 0xA9, 0x66], &ts_scale);

    let track_number = ebml(&[0xD7], &[0x01]);
    let track_type = ebml(&[0x83], &[0x01]); // video
    let codec_id = ebml(&[0x86], b"V_VP9");
    let track_entry = ebml(&[0xAE], &cat(&[&track_number, &track_type, &codec_id]));
    let tracks = ebml(&[0x16, 0x54, 0xAE, 0x6B], &track_entry);

    let timestamp = ebml(&[0xE7], &[0x0A]); // cluster ts = 10
    let mut block_body = Vec::new();
    block_body.push(0x81); // track number vint -> 1
    block_body.extend_from_slice(&[0x00, 0x00]); // rel timestamp 0
    block_body.push(0x80); // flags: keyframe
    block_body.extend_from_slice(&[0x11, 0x22, 0x33]); // payload
    let simple_block = ebml(&[0xA3], &block_body);
    let cluster = ebml(
        &[0x1F, 0x43, 0xB6, 0x75],
        &cat(&[&timestamp, &simple_block]),
    );

    let segment = ebml(&[0x18, 0x53, 0x80, 0x67], &cat(&[&info, &tracks, &cluster]));
    let file = cat(&[&ebml_header, &segment]);

    let demux = Demuxer::parse(&file).expect("MKV parses");
    assert_eq!(demux.format(), ContainerFormat::Matroska);
    assert_eq!(demux.tracks().len(), 1);
    let track = &demux.tracks()[0];
    assert_eq!(track.id, 1);
    assert_eq!(track.kind, TrackKind::Video);
    assert_eq!(track.codec, CodecId::Video(VideoCodec::Vp9));

    let packets = demux.packets();
    assert_eq!(packets.len(), 1);
    assert_eq!(packets[0].track_id, 1);
    assert_eq!(packets[0].timestamp_us, 10_000); // 10 ticks * 1_000_000 ns / 1000
    assert!(packets[0].keyframe);
    assert_eq!(packets[0].data, vec![0x11, 0x22, 0x33]);
}

#[test]
fn detect_format_rejects_garbage() {
    assert_eq!(
        crate::container::detect_format(&[0, 1, 2, 3, 4, 5, 6, 7]),
        ContainerFormat::Unknown
    );
    assert!(Demuxer::parse(&[0, 1, 2, 3, 4, 5, 6, 7]).is_none());
}

// ===========================================================================
// sync.rs — A/V sync clock (WS8-02.7)
// ===========================================================================

#[test]
fn sync_clock_presents_drops_and_waits() {
    let mut clock = AvSyncClock::new();
    clock.set_master_us(1_000_000);

    // In window -> present.
    assert_eq!(clock.classify(1_000_000), FrameAction::Present);
    assert_eq!(clock.classify(1_020_000), FrameAction::Present);
    // Far behind -> drop.
    assert_eq!(clock.classify(800_000), FrameAction::Drop);
    // Ahead -> wait by the drift.
    assert_eq!(
        clock.classify(1_200_000),
        FrameAction::Wait { delay_us: 200_000 }
    );
}

#[test]
fn sync_clock_records_stats() {
    let mut clock = AvSyncClock::with_thresholds(SyncThresholds {
        present_window_us: 10_000,
        drop_threshold_us: 50_000,
    });
    clock.set_master_us(500_000);
    clock.decide(500_000); // present
    clock.decide(400_000); // drop
    clock.decide(600_000); // wait
    clock.decide(505_000); // present
    let stats = clock.stats();
    assert_eq!(stats.presented, 2);
    assert_eq!(stats.dropped, 1);
    assert_eq!(stats.waited, 1);
}

// ===========================================================================
// sink.rs — headless sinks + scheduling (WS8-02.5 / WS8-02.6)
// ===========================================================================

fn sample_video_frame(pts_us: i64) -> VideoFrame {
    VideoFrame {
        width: 64,
        height: 48,
        pts_us,
        format: PixelFormat::I420,
        data: vec![0u8; 64 * 48],
    }
}

fn stereo_format() -> AudioFormat {
    AudioFormat {
        sample_rate: 48_000,
        channels: 2,
        encoding: PcmEncoding::S16Le,
    }
}

#[test]
fn headless_video_sink_records_presentation() {
    let mut sink = HeadlessVideoSink::new();
    sink.present(&sample_video_frame(123)).unwrap();
    assert_eq!(sink.presented, 1);
    assert_eq!(sink.last_dimensions, Some((64, 48)));
    assert_eq!(sink.last_pts_us, Some(123));
}

#[test]
fn headless_audio_sink_tracks_buffer_duration() {
    let mut sink = HeadlessAudioSink::new();
    let frame = AudioFrame {
        pts_us: 0,
        format: stereo_format(),
        // 4800 frames * 4 bytes/frame = 0.1 s at 48 kHz.
        pcm: vec![0u8; 4800 * 4],
    };
    sink.queue(&frame).unwrap();
    assert_eq!(sink.queued_frames, 1);
    assert_eq!(sink.queued_us(), 100_000);
    sink.advance_playhead(40_000);
    assert_eq!(sink.playhead_us(), 40_000);
    assert_eq!(sink.queued_us(), 60_000);
    assert_eq!(sink.format(), Some(stereo_format()));
}

#[test]
fn present_scheduled_presents_in_window_drops_when_late() {
    let mut sink = HeadlessVideoSink::new();
    let mut clock = AvSyncClock::new();
    clock.set_master_us(1_000_000);

    let action = present_scheduled(&mut sink, &mut clock, &sample_video_frame(1_000_000)).unwrap();
    assert_eq!(action, FrameAction::Present);
    assert_eq!(sink.presented, 1);

    let action = present_scheduled(&mut sink, &mut clock, &sample_video_frame(500_000)).unwrap();
    assert_eq!(action, FrameAction::Drop);
    assert_eq!(sink.presented, 1); // not presented
}

// ===========================================================================
// decode.rs — backend selection (WS8-02.8)
// ===========================================================================

struct OneFramePerPacketVideo {
    codec: VideoCodec,
}

impl VideoDecoder for OneFramePerPacketVideo {
    fn codec(&self) -> VideoCodec {
        self.codec
    }
    fn decode(&mut self, packet: &Packet) -> Result<Option<VideoFrame>, DecodeError> {
        Ok(Some(VideoFrame {
            width: 64,
            height: 48,
            pts_us: packet.timestamp_us,
            format: PixelFormat::I420,
            data: packet.data.clone(),
        }))
    }
    fn flush(&mut self) -> Vec<VideoFrame> {
        Vec::new()
    }
}

struct PcmPerPacketAudio {
    codec: AudioCodec,
    format: AudioFormat,
    frames_per_packet: usize,
}

impl AudioDecoder for PcmPerPacketAudio {
    fn codec(&self) -> AudioCodec {
        self.codec
    }
    fn decode(&mut self, packet: &Packet) -> Result<Option<AudioFrame>, DecodeError> {
        Ok(Some(AudioFrame {
            pts_us: packet.timestamp_us,
            format: self.format,
            pcm: vec![0u8; self.frames_per_packet * self.format.frame_size()],
        }))
    }
}

struct Probe {
    hw_video: Vec<VideoCodec>,
    hw_audio: Vec<AudioCodec>,
}

impl HwProbe for Probe {
    fn supports_video(&self, codec: VideoCodec) -> bool {
        self.hw_video.contains(&codec)
    }
    fn supports_audio(&self, codec: AudioCodec) -> bool {
        self.hw_audio.contains(&codec)
    }
}

struct Factory {
    allow_hw_video: bool,
}

impl DecoderFactory for Factory {
    fn create_video(
        &self,
        codec: VideoCodec,
        acceleration: Acceleration,
    ) -> Option<Box<dyn VideoDecoder>> {
        if codec == VideoCodec::Unknown {
            return None;
        }
        if acceleration == Acceleration::Hardware && !self.allow_hw_video {
            return None;
        }
        Some(Box::new(OneFramePerPacketVideo { codec }))
    }
    fn create_audio(
        &self,
        codec: AudioCodec,
        _acceleration: Acceleration,
    ) -> Option<Box<dyn AudioDecoder>> {
        if codec == AudioCodec::Unknown {
            return None;
        }
        Some(Box::new(PcmPerPacketAudio {
            codec,
            format: stereo_format(),
            frames_per_packet: 1024,
        }))
    }
}

#[test]
fn selector_prefers_hardware_when_available() {
    let probe = Probe {
        hw_video: vec![VideoCodec::H264],
        hw_audio: vec![],
    };
    let factory = Factory {
        allow_hw_video: true,
    };
    let selector = DecoderSelector::new(&probe, &factory);
    let selected = selector
        .select_video(VideoCodec::H264)
        .expect("video selected");
    assert_eq!(selected.acceleration, Acceleration::Hardware);
    assert_eq!(selected.decoder.codec(), VideoCodec::H264);
}

#[test]
fn selector_falls_back_to_software_when_unsupported() {
    let probe = Probe {
        hw_video: vec![VideoCodec::H264],
        hw_audio: vec![],
    };
    let factory = Factory {
        allow_hw_video: true,
    };
    let selector = DecoderSelector::new(&probe, &factory);
    let selected = selector
        .select_video(VideoCodec::Vp9)
        .expect("video selected");
    assert_eq!(selected.acceleration, Acceleration::Software);
}

#[test]
fn selector_falls_back_when_hardware_construction_declines() {
    // Probe says HW is supported, but the factory cannot build it.
    let probe = Probe {
        hw_video: vec![VideoCodec::H264],
        hw_audio: vec![],
    };
    let factory = Factory {
        allow_hw_video: false,
    };
    let selector = DecoderSelector::new(&probe, &factory);
    let selected = selector
        .select_video(VideoCodec::H264)
        .expect("video selected");
    assert_eq!(selected.acceleration, Acceleration::Software);
}

#[test]
fn selector_returns_none_when_no_backend() {
    let probe = Probe {
        hw_video: vec![],
        hw_audio: vec![],
    };
    let factory = Factory {
        allow_hw_video: false,
    };
    let selector = DecoderSelector::new(&probe, &factory);
    assert!(selector.select_video(VideoCodec::Unknown).is_none());
}

// ===========================================================================
// playlist.rs — model (WS8-02.9)
// ===========================================================================

#[test]
fn playlist_advance_respects_repeat_modes() {
    let mut pl = Playlist::new();
    pl.push("a");
    pl.push("b");
    pl.push("c");
    assert_eq!(pl.current().map(|e| e.uri.as_str()), Some("a"));

    // Repeat off: stops at the tail.
    assert_eq!(pl.advance().map(|e| e.uri.as_str()), Some("b"));
    assert_eq!(pl.advance().map(|e| e.uri.as_str()), Some("c"));
    assert!(pl.advance().is_none());
    assert_eq!(pl.current().map(|e| e.uri.as_str()), Some("c"));

    // Repeat all: wraps.
    pl.seek_to(2);
    pl.set_repeat(RepeatMode::All);
    assert_eq!(pl.advance().map(|e| e.uri.as_str()), Some("a"));

    // Repeat one: stays.
    pl.set_repeat(RepeatMode::One);
    assert_eq!(pl.advance().map(|e| e.uri.as_str()), Some("a"));
    assert_eq!(pl.advance().map(|e| e.uri.as_str()), Some("a"));
}

#[test]
fn playlist_remove_adjusts_selection() {
    let mut pl = Playlist::new();
    pl.push("a");
    pl.push("b");
    pl.push("c");
    pl.seek_to(1); // select "b"
    pl.remove(0); // remove "a" before selection
    assert_eq!(pl.current().map(|e| e.uri.as_str()), Some("b"));
    pl.remove(1); // remove "c" after selection
    assert_eq!(pl.current().map(|e| e.uri.as_str()), Some("b"));
    pl.remove(0); // remove "b" (selected)
    assert_eq!(pl.len(), 0);
    assert!(pl.current().is_none());
}

#[test]
fn playlist_move_item_preserves_selection() {
    let mut pl = Playlist::new();
    pl.push("a");
    pl.push("b");
    pl.push("c");
    pl.seek_to(2); // select "c"
    pl.move_item(2, 0); // move "c" to the front
    assert_eq!(pl.entries()[0].uri, "c");
    assert_eq!(pl.current().map(|e| e.uri.as_str()), Some("c"));
    assert_eq!(pl.current_index(), Some(0));
}

#[test]
fn playlist_shuffle_is_deterministic_and_reversible() {
    let mut a = Playlist::new();
    let mut b = Playlist::new();
    for uri in ["0", "1", "2", "3", "4", "5"] {
        a.push(uri);
        b.push(uri);
    }
    a.set_shuffle(Some(0xDEAD_BEEF));
    b.set_shuffle(Some(0xDEAD_BEEF));
    assert!(a.is_shuffled());

    // Same seed -> same traversal order.  With repeat-all, six cyclic steps
    // visit every entry exactly once regardless of the starting position.
    a.set_repeat(RepeatMode::All);
    b.set_repeat(RepeatMode::All);
    let mut order_a = vec![a.current().unwrap().uri.clone()];
    let mut order_b = vec![b.current().unwrap().uri.clone()];
    for _ in 0..5 {
        order_a.push(a.advance().unwrap().uri.clone());
        order_b.push(b.advance().unwrap().uri.clone());
    }
    assert_eq!(order_a, order_b);

    // The traversal is a permutation of all six entries.
    let mut distinct = order_a.clone();
    distinct.sort();
    distinct.dedup();
    assert_eq!(distinct.len(), 6);

    // Disabling shuffle restores list order.
    a.set_shuffle(None);
    assert!(!a.is_shuffled());
}

#[test]
fn playlist_skip_navigation() {
    let mut pl = Playlist::new();
    pl.push("a");
    pl.push("b");
    assert_eq!(pl.skip_next().map(|e| e.uri.as_str()), Some("b"));
    assert!(pl.skip_next().is_none()); // off + tail
    assert_eq!(pl.skip_previous().map(|e| e.uri.as_str()), Some("a"));
}

// ===========================================================================
// player.rs — transport + end-to-end session
// ===========================================================================

#[test]
fn player_transport_transitions() {
    let mut player = MediaPlayer::new();
    assert_eq!(player.state(), PlayerState::Idle);
    player.play(); // empty -> no-op
    assert_eq!(player.state(), PlayerState::Idle);

    player.playlist_mut().push("a");
    player.playlist_mut().push("b");
    player.play();
    assert_eq!(player.state(), PlayerState::Playing);
    player.pause();
    assert_eq!(player.state(), PlayerState::Paused);
    player.set_position_us(42);
    player.stop();
    assert_eq!(player.state(), PlayerState::Idle);
    assert_eq!(player.position_us(), 0);

    // End-of-stream advances to "b", then ends.
    player.play();
    player.on_end_of_stream();
    assert_eq!(player.state(), PlayerState::Playing);
    assert_eq!(player.current().map(|e| e.uri.as_str()), Some("b"));
    player.on_end_of_stream();
    assert_eq!(player.state(), PlayerState::Ended);
}

#[test]
fn run_session_pumps_audio_master_and_video() {
    let video_track = Track {
        id: 1,
        kind: TrackKind::Video,
        codec: CodecId::Video(VideoCodec::H264),
        timescale: 90_000,
        codec_private: Vec::new(),
        width: Some(64),
        height: Some(48),
    };
    let audio_track = Track {
        id: 2,
        kind: TrackKind::Audio,
        codec: CodecId::Audio(AudioCodec::Aac),
        timescale: 48_000,
        codec_private: Vec::new(),
        width: None,
        height: None,
    };
    let packets = vec![
        Packet {
            track_id: 2,
            timestamp_us: 0,
            duration_us: 0,
            keyframe: true,
            data: vec![],
        },
        Packet {
            track_id: 1,
            timestamp_us: 0,
            duration_us: 0,
            keyframe: true,
            data: vec![1, 2],
        },
        Packet {
            track_id: 2,
            timestamp_us: 100_000,
            duration_us: 0,
            keyframe: true,
            data: vec![],
        },
        Packet {
            track_id: 1,
            timestamp_us: 100_000,
            duration_us: 0,
            keyframe: false,
            data: vec![3],
        },
    ];
    let demux = Demuxer::from_parts(
        ContainerFormat::Matroska,
        vec![video_track, audio_track],
        packets,
    );

    let mut vd = OneFramePerPacketVideo {
        codec: VideoCodec::H264,
    };
    let mut ad = PcmPerPacketAudio {
        codec: AudioCodec::Aac,
        format: stereo_format(),
        frames_per_packet: 4800,
    };
    let mut vs = HeadlessVideoSink::new();
    let mut audio_sink = HeadlessAudioSink::new();
    let mut clock = AvSyncClock::new();

    let summary = run_session(
        &demux,
        &mut vd,
        &mut ad,
        &mut vs,
        &mut audio_sink,
        &mut clock,
    );
    assert_eq!(summary.audio_queued, 2);
    assert_eq!(summary.video_presented, 2);
    assert_eq!(summary.video_dropped, 0);
    assert_eq!(summary.decode_errors, 0);
    assert_eq!(vs.presented, 2);
    assert_eq!(audio_sink.queued_frames, 2);
}

#[test]
fn run_session_drops_late_video() {
    let video_track = Track {
        id: 1,
        kind: TrackKind::Video,
        codec: CodecId::Video(VideoCodec::H264),
        timescale: 90_000,
        codec_private: Vec::new(),
        width: None,
        height: None,
    };
    let audio_track = Track {
        id: 2,
        kind: TrackKind::Audio,
        codec: CodecId::Audio(AudioCodec::Aac),
        timescale: 48_000,
        codec_private: Vec::new(),
        width: None,
        height: None,
    };
    // Audio jumps the master to 1s; the video frame at t=0 is hopelessly late.
    let packets = vec![
        Packet {
            track_id: 2,
            timestamp_us: 1_000_000,
            duration_us: 0,
            keyframe: true,
            data: vec![],
        },
        Packet {
            track_id: 1,
            timestamp_us: 0,
            duration_us: 0,
            keyframe: true,
            data: vec![9],
        },
    ];
    let demux = Demuxer::from_parts(
        ContainerFormat::Matroska,
        vec![video_track, audio_track],
        packets,
    );

    let mut vd = OneFramePerPacketVideo {
        codec: VideoCodec::H264,
    };
    let mut ad = PcmPerPacketAudio {
        codec: AudioCodec::Aac,
        format: stereo_format(),
        frames_per_packet: 1,
    };
    let mut vs = HeadlessVideoSink::new();
    let mut audio_sink = HeadlessAudioSink::new();
    let mut clock = AvSyncClock::new();

    let summary = run_session(
        &demux,
        &mut vd,
        &mut ad,
        &mut vs,
        &mut audio_sink,
        &mut clock,
    );
    assert_eq!(summary.video_dropped, 1);
    assert_eq!(summary.video_presented, 0);
    assert_eq!(vs.presented, 0);
}
