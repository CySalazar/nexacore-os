//! Audio bridge from the guest to `virtio-snd` (WS9-03.7).
//!
//! Guest applications play audio through the guest's sound server; the guest
//! agent exposes each PCM stream to the host, and the [`AudioBridge`] routes it
//! to a host `virtio-snd` output. This module owns the **routing table and
//! stream lifecycle**, not the sample transport or mixing: PCM frames flow
//! through the `virtio-snd` device backend, and per-stream mixing lives in
//! `nexacore-driver-audio`. Routing is capability-gated and validates the
//! negotiated PCM format fail-closed.

use std::collections::BTreeMap;

use super::{AppBridgeError, AppBridgeResult};

/// PCM sample encoding of a guest stream.
///
/// The `Le` suffix denotes little-endian byte order, matching the ALSA/PipeWire
/// format identifiers these mirror; it is intrinsic to the format name.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(clippy::enum_variant_names)]
pub enum SampleFormat {
    /// Signed 16-bit little-endian.
    S16Le,
    /// Signed 32-bit little-endian.
    S32Le,
    /// 32-bit float little-endian.
    F32Le,
}

/// A negotiated PCM format.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AudioFormat {
    /// Sample rate in Hz.
    pub rate_hz: u32,
    /// Channel count.
    pub channels: u8,
    /// Sample encoding.
    pub sample_format: SampleFormat,
}

impl AudioFormat {
    /// Validate the format against the bridge's accepted envelope: a standard
    /// sample rate and 1–8 channels.
    ///
    /// # Errors
    ///
    /// [`AppBridgeError::Protocol`] if the rate or channel count is unsupported.
    pub fn validate(self) -> AppBridgeResult<()> {
        const RATES: [u32; 6] = [8_000, 16_000, 44_100, 48_000, 88_200, 96_000];
        if !RATES.contains(&self.rate_hz) {
            return Err(AppBridgeError::Protocol("unsupported sample rate"));
        }
        if self.channels == 0 || self.channels > 8 {
            return Err(AppBridgeError::Protocol("unsupported channel count"));
        }
        Ok(())
    }
}

/// A guest PCM stream to be routed to the host.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GuestAudioStream {
    /// Guest-assigned stream id.
    pub id: u32,
    /// Negotiated PCM format.
    pub format: AudioFormat,
}

/// A live route from a guest stream to a host `virtio-snd` sink.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HostAudioRoute {
    /// Guest stream id.
    pub stream: u32,
    /// Host sink id (a `virtio-snd` output stream).
    pub sink: u32,
}

/// Routes guest audio streams to host `virtio-snd` sinks.
#[derive(Debug, Clone)]
pub struct AudioBridge {
    default_sink: u32,
    max_streams: usize,
    permitted: bool,
    routes: BTreeMap<u32, HostAudioRoute>,
}

impl AudioBridge {
    /// A bridge routing to `default_sink`, admitting up to `max_streams`
    /// concurrent streams. `permitted` reflects the container's audio grant;
    /// when `false`, opening a stream fails closed.
    #[must_use]
    pub fn new(default_sink: u32, max_streams: usize, permitted: bool) -> Self {
        Self {
            default_sink,
            max_streams,
            permitted,
            routes: BTreeMap::new(),
        }
    }

    /// Number of live routes.
    #[must_use]
    pub fn len(&self) -> usize {
        self.routes.len()
    }

    /// Whether no streams are routed.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.routes.is_empty()
    }

    /// The route for a guest stream, if open.
    #[must_use]
    pub fn route_of(&self, stream: u32) -> Option<HostAudioRoute> {
        self.routes.get(&stream).copied()
    }

    /// Open a route for `stream`, mapping it to the default host sink.
    ///
    /// # Errors
    ///
    /// [`AppBridgeError::Capability`] if the audio grant is absent;
    /// [`AppBridgeError::Protocol`] for an invalid format or a duplicate stream
    /// id; [`AppBridgeError::TooManyWindows`] is **not** used — the stream limit
    /// raises [`AppBridgeError::Protocol`] with a distinct slug.
    pub fn open_stream(&mut self, stream: GuestAudioStream) -> AppBridgeResult<HostAudioRoute> {
        if !self.permitted {
            return Err(AppBridgeError::Capability("audio"));
        }
        stream.format.validate()?;
        if self.routes.contains_key(&stream.id) {
            return Err(AppBridgeError::Protocol("duplicate audio stream id"));
        }
        if self.routes.len() >= self.max_streams {
            return Err(AppBridgeError::Protocol("audio stream limit reached"));
        }
        let route = HostAudioRoute {
            stream: stream.id,
            sink: self.default_sink,
        };
        self.routes.insert(stream.id, route);
        Ok(route)
    }

    /// Close a route. Returns whether the stream was open.
    pub fn close_stream(&mut self, stream: u32) -> bool {
        self.routes.remove(&stream).is_some()
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]
mod tests {
    use super::*;

    fn stream(id: u32) -> GuestAudioStream {
        GuestAudioStream {
            id,
            format: AudioFormat {
                rate_hz: 48_000,
                channels: 2,
                sample_format: SampleFormat::S16Le,
            },
        }
    }

    #[test]
    fn open_routes_to_default_sink() {
        let mut a = AudioBridge::new(9, 4, true);
        let route = a.open_stream(stream(1)).unwrap();
        assert_eq!(route, HostAudioRoute { stream: 1, sink: 9 });
        assert_eq!(a.route_of(1), Some(route));
    }

    #[test]
    fn without_capability_open_fails_closed() {
        let mut a = AudioBridge::new(9, 4, false);
        assert_eq!(
            a.open_stream(stream(1)),
            Err(AppBridgeError::Capability("audio"))
        );
    }

    #[test]
    fn invalid_format_is_rejected() {
        let mut a = AudioBridge::new(9, 4, true);
        let mut s = stream(1);
        s.format.rate_hz = 12_345;
        assert_eq!(
            a.open_stream(s),
            Err(AppBridgeError::Protocol("unsupported sample rate"))
        );
        let mut s2 = stream(2);
        s2.format.channels = 0;
        assert_eq!(
            a.open_stream(s2),
            Err(AppBridgeError::Protocol("unsupported channel count"))
        );
    }

    #[test]
    fn duplicate_stream_is_rejected() {
        let mut a = AudioBridge::new(9, 4, true);
        a.open_stream(stream(1)).unwrap();
        assert_eq!(
            a.open_stream(stream(1)),
            Err(AppBridgeError::Protocol("duplicate audio stream id"))
        );
    }

    #[test]
    fn stream_limit_is_enforced() {
        let mut a = AudioBridge::new(9, 1, true);
        a.open_stream(stream(1)).unwrap();
        assert_eq!(
            a.open_stream(stream(2)),
            Err(AppBridgeError::Protocol("audio stream limit reached"))
        );
    }

    #[test]
    fn close_removes_route() {
        let mut a = AudioBridge::new(9, 4, true);
        a.open_stream(stream(1)).unwrap();
        assert!(a.close_stream(1));
        assert!(a.is_empty());
        assert!(!a.close_stream(1));
    }
}
