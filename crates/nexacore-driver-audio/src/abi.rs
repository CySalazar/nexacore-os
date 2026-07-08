//! DE-H2 audio syscall ABI (WS2-10.8).
//!
//! The request/response enums are the userspace↔kernel contract for opening
//! PCM streams and moving audio frames. They are deliberately small and
//! integer-typed; the canonical wire encoding routes through the workspace
//! `nexacore-types::wire` helper at the call boundary (this crate keeps the ABI
//! types dependency-free for `no_std` reuse by the driver).

/// PCM sample format.
///
/// The `Le` suffix denotes little-endian byte order, shared by every variant
/// by design; the postfix is intentional.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(clippy::enum_variant_names)]
#[repr(u8)]
pub enum PcmFormat {
    /// Signed 16-bit little-endian.
    S16Le = 0,
    /// Signed 24-bit little-endian (in 4-byte containers).
    S24Le = 1,
    /// Signed 32-bit little-endian.
    S32Le = 2,
    /// 32-bit IEEE float little-endian.
    F32Le = 3,
}

impl PcmFormat {
    /// Bytes occupied by one sample of this format.
    #[must_use]
    pub fn bytes_per_sample(self) -> usize {
        match self {
            Self::S16Le => 2,
            Self::S24Le | Self::S32Le | Self::F32Le => 4,
        }
    }

    /// Bytes occupied by one frame of `channels` samples.
    #[must_use]
    pub fn frame_bytes(self, channels: u16) -> usize {
        self.bytes_per_sample() * channels as usize
    }
}

/// A DE-H2 audio request from a userspace app.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AudioRequest {
    /// Open a playback stream with the given format / rate / channel count.
    OpenPlayback {
        /// Sample format.
        format: PcmFormat,
        /// Sample rate in Hz.
        rate_hz: u32,
        /// Channel count.
        channels: u16,
    },
    /// Open a capture stream.
    OpenCapture {
        /// Sample format.
        format: PcmFormat,
        /// Sample rate in Hz.
        rate_hz: u32,
        /// Channel count.
        channels: u16,
    },
    /// Set a stream's volume (0..=100).
    SetVolume {
        /// Stream id returned by an open request.
        stream_id: u32,
        /// Volume percent (clamped to 0..=100 by the mixer).
        percent: u8,
    },
    /// Close a stream.
    Close {
        /// Stream id.
        stream_id: u32,
    },
}

/// A DE-H2 audio response.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AudioResponse {
    /// A stream was opened; carries its id.
    Opened {
        /// Allocated stream id.
        stream_id: u32,
    },
    /// The request succeeded with no payload.
    Ok,
    /// The request failed with a static reason slug.
    Error {
        /// PII-safe static reason.
        reason: &'static str,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frame_bytes_by_format() {
        assert_eq!(PcmFormat::S16Le.bytes_per_sample(), 2);
        assert_eq!(PcmFormat::S32Le.bytes_per_sample(), 4);
        assert_eq!(PcmFormat::S16Le.frame_bytes(2), 4); // stereo s16
        assert_eq!(PcmFormat::F32Le.frame_bytes(2), 8);
    }

    #[test]
    fn request_response_round_trip_shapes() {
        let r = AudioRequest::OpenPlayback {
            format: PcmFormat::S16Le,
            rate_hz: 48_000,
            channels: 2,
        };
        assert_eq!(
            r,
            AudioRequest::OpenPlayback {
                format: PcmFormat::S16Le,
                rate_hz: 48_000,
                channels: 2
            }
        );
        assert_eq!(
            AudioResponse::Opened { stream_id: 5 },
            AudioResponse::Opened { stream_id: 5 }
        );
    }
}
