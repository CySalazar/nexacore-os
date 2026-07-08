//! virtio-snd control + PCM transfer messages (WS2-10.4, .5, .6).
//!
//! virtio-snd uses a control virtqueue (codec/PCM configuration), a tx queue
//! (playback PCM), and an rx queue (capture PCM). The message structures are
//! byte-exact per VIRTIO 1.x § 5.14; the virtqueue plumbing is rig-side.

use alloc::vec::Vec;

/// virtio-snd control request codes (`virtio_snd_ctrl_request::code`).
pub mod code {
    /// Query PCM stream info.
    pub const PCM_INFO: u32 = 0x0100;
    /// Set PCM stream parameters.
    pub const PCM_SET_PARAMS: u32 = 0x0101;
    /// Prepare a PCM stream.
    pub const PCM_PREPARE: u32 = 0x0102;
    /// Release a PCM stream.
    pub const PCM_RELEASE: u32 = 0x0103;
    /// Start a PCM stream.
    pub const PCM_START: u32 = 0x0104;
    /// Stop a PCM stream.
    pub const PCM_STOP: u32 = 0x0105;
}

/// virtio-snd response status codes (`virtio_snd_hdr::code` in responses).
pub mod status {
    /// Success.
    pub const OK: u32 = 0x8000;
    /// Unsupported request.
    pub const NOT_SUPP: u32 = 0x8001;
    /// Invalid parameter.
    pub const BAD_MSG: u32 = 0x8002;
    /// I/O error.
    pub const IO_ERR: u32 = 0x8003;
}

/// virtio-snd PCM sample format codes (`virtio_snd_pcm_set_params::format`).
pub mod fmt {
    /// Signed 16-bit.
    pub const S16: u8 = 5;
    /// Signed 32-bit.
    pub const S32: u8 = 8;
    /// 32-bit float.
    pub const FLOAT: u8 = 9;
}

/// The 4-byte `virtio_snd_hdr` carrying a request/response code.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SndCtrlHdr {
    /// Request or response code.
    pub code: u32,
}

impl SndCtrlHdr {
    /// Serialize to 4 little-endian bytes.
    #[must_use]
    pub fn to_bytes(self) -> [u8; 4] {
        self.code.to_le_bytes()
    }
}

/// `virtio_snd_pcm_set_params` — configure a PCM stream's buffer geometry and
/// format before `PCM_PREPARE`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SndPcmSetParams {
    /// Target stream id.
    pub stream_id: u32,
    /// Total ring buffer size in bytes.
    pub buffer_bytes: u32,
    /// Period (interrupt granularity) in bytes.
    pub period_bytes: u32,
    /// Feature bitmap (0 for the base set).
    pub features: u32,
    /// Channel count.
    pub channels: u8,
    /// Format code (see [`fmt`]).
    pub format: u8,
    /// Sample-rate code (`virtio_snd_pcm_rate`).
    pub rate: u8,
}

impl SndPcmSetParams {
    /// Serialize the full `PCM_SET_PARAMS` control request (header + body).
    #[must_use]
    pub fn to_bytes(self) -> Vec<u8> {
        let mut out = Vec::with_capacity(24);
        // virtio_snd_pcm_hdr: { hdr.code, stream_id }.
        out.extend_from_slice(&code::PCM_SET_PARAMS.to_le_bytes());
        out.extend_from_slice(&self.stream_id.to_le_bytes());
        // body.
        out.extend_from_slice(&self.buffer_bytes.to_le_bytes());
        out.extend_from_slice(&self.period_bytes.to_le_bytes());
        out.extend_from_slice(&self.features.to_le_bytes());
        out.push(self.channels);
        out.push(self.format);
        out.push(self.rate);
        out.push(0); // padding
        out
    }
}

/// The 4-byte `virtio_snd_pcm_xfer` header prefixing PCM data in a tx/rx buffer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PcmXferHdr {
    /// Stream id the payload belongs to.
    pub stream_id: u32,
}

impl PcmXferHdr {
    /// Serialize a playback/capture buffer: the 4-byte xfer header followed by
    /// the raw PCM `payload`.
    #[must_use]
    pub fn frame(self, payload: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(4 + payload.len());
        out.extend_from_slice(&self.stream_id.to_le_bytes());
        out.extend_from_slice(payload);
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ctrl_hdr_is_le_code() {
        assert_eq!(
            SndCtrlHdr {
                code: code::PCM_START
            }
            .to_bytes(),
            0x0104u32.to_le_bytes()
        );
    }

    #[test]
    fn set_params_layout() {
        let p = SndPcmSetParams {
            stream_id: 0,
            buffer_bytes: 16384,
            period_bytes: 4096,
            features: 0,
            channels: 2,
            format: fmt::S16,
            rate: 0,
        };
        let b = p.to_bytes();
        assert_eq!(b.len(), 24);
        assert_eq!(&b[0..4], &code::PCM_SET_PARAMS.to_le_bytes()); // code
        assert_eq!(&b[8..12], &16384u32.to_le_bytes()); // buffer_bytes
        assert_eq!(&b[12..16], &4096u32.to_le_bytes()); // period_bytes
        assert_eq!(b[20], 2); // channels
        assert_eq!(b[21], fmt::S16); // format
    }

    #[test]
    fn pcm_xfer_prefixes_payload() {
        let buf = PcmXferHdr { stream_id: 7 }.frame(&[1, 2, 3, 4]);
        assert_eq!(&buf[0..4], &7u32.to_le_bytes());
        assert_eq!(&buf[4..], &[1, 2, 3, 4]);
    }
}
