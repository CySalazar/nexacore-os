//! Screen capture and recording (WS7-18).
//!
//! Screenshots and screen recordings all start the same way: resolve *what* to
//! capture (a region, a window, one output, or the whole extended desktop from
//! WS7-11) to a rectangle, extract those pixels from a source framebuffer, then
//! hand the frame to an encoder. This module owns the **geometry, pixel
//! extraction, and recording pacing** — all host-testable — while the actual
//! image/video **encoding is a seam** ([`ImageEncoder`], [`VideoEncoder`]) so
//! the concrete PNG (`nexacore-image`) and video (`nexacore-media`) codecs plug
//! in at the app layer without a dependency cycle.
//!
//! The the test VM end-to-end check — capture a region to a file and play back a
//! recording — is the deferred rig sub-task WS7-18.7.

#![allow(
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::integer_division
)]

use alloc::{vec, vec::Vec};

use crate::{DisplayError, geometry::Rect, output::OutputId, surface::WindowId};

// -----------------------------------------------------------------------------
// WS7-18.1 — capture API
// -----------------------------------------------------------------------------

/// What to capture.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CaptureTarget {
    /// A specific rectangle in the global desktop coordinate space.
    Region(Rect),
    /// A single window, by id.
    Window(WindowId),
    /// One output (monitor), by id.
    Output(OutputId),
    /// The whole extended desktop (all enabled outputs).
    FullDesktop,
}

/// Geometry lookups a capture needs to resolve a [`CaptureTarget`] to a rect.
///
/// The window manager provides window rectangles; the WS7-11
/// [`OutputManager`](crate::output::OutputManager) provides output/desktop
/// rectangles. Kept as a trait so `capture` couples to neither directly.
pub trait CaptureGeometry {
    /// The global-space rectangle of a window, if it exists.
    fn window_rect(&self, id: WindowId) -> Option<Rect>;
    /// The global-space rectangle of an output, if it exists and is enabled.
    fn output_rect(&self, id: OutputId) -> Option<Rect>;
    /// The bounding rectangle of the whole desktop, if any output is enabled.
    fn desktop_rect(&self) -> Option<Rect>;
}

/// Resolve a capture target to its global-space rectangle.
///
/// # Errors
///
/// [`DisplayError::UnknownWindow`] / [`DisplayError::UnknownOutput`] if the
/// referenced window/output is absent; [`DisplayError::InvalidSize`] if the
/// resolved rectangle is empty (e.g. `FullDesktop` with no enabled output).
pub fn resolve_capture_rect<G: CaptureGeometry>(
    target: CaptureTarget,
    geom: &G,
) -> Result<Rect, DisplayError> {
    let rect = match target {
        CaptureTarget::Region(r) => r,
        CaptureTarget::Window(id) => geom
            .window_rect(id)
            .ok_or(DisplayError::UnknownWindow(id))?,
        CaptureTarget::Output(id) => geom
            .output_rect(id)
            .ok_or(DisplayError::UnknownOutput(id))?,
        CaptureTarget::FullDesktop => geom.desktop_rect().ok_or(DisplayError::InvalidSize)?,
    };
    if rect.is_empty() {
        return Err(DisplayError::InvalidSize);
    }
    Ok(rect)
}

// -----------------------------------------------------------------------------
// captured frame + pixel extraction (WS7-18.2/.3/.4)
// -----------------------------------------------------------------------------

/// A captured RGBA frame: `width * height` `ARGB8888` pixels, row-major.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CaptureFrame {
    /// Frame width in pixels.
    pub width: u32,
    /// Frame height in pixels.
    pub height: u32,
    /// `width * height` pixels, row-major.
    pub pixels: Vec<u32>,
}

impl CaptureFrame {
    /// A zeroed (transparent) frame of the given size.
    #[must_use]
    pub fn new(width: u32, height: u32) -> Self {
        Self {
            width,
            height,
            pixels: vec![0u32; (width as usize) * (height as usize)],
        }
    }

    /// The pixel at `(x, y)`, if in bounds.
    #[must_use]
    pub fn pixel(&self, x: u32, y: u32) -> Option<u32> {
        if x >= self.width || y >= self.height {
            return None;
        }
        self.pixels
            .get((y as usize) * (self.width as usize) + (x as usize))
            .copied()
    }

    /// Whether the frame has zero area.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.width == 0 || self.height == 0
    }
}

/// Extract `region` (global-space) from a source framebuffer of `src_w × src_h`
/// pixels at the same origin, returning the clipped pixels as a [`CaptureFrame`].
///
/// The source buffer is assumed to cover the rectangle `origin..origin+size` in
/// the same coordinate space as `region`; `src_origin` is that origin (e.g. an
/// output's top-left). Copying is fully bounds-checked — an out-of-range region
/// is clipped, never indexed past the buffer.
///
/// # Errors
///
/// [`DisplayError::InvalidSize`] if `src` is shorter than `src_w * src_h`, or
/// the region does not overlap the source.
pub fn capture_region(
    src: &[u32],
    src_origin: (i32, i32),
    src_w: u32,
    src_h: u32,
    region: Rect,
) -> Result<CaptureFrame, DisplayError> {
    if src.len() < (src_w as usize) * (src_h as usize) {
        return Err(DisplayError::InvalidSize);
    }
    let src_rect = Rect {
        x: src_origin.0,
        y: src_origin.1,
        w: src_w,
        h: src_h,
    };
    let clip = region
        .intersect(&src_rect)
        .ok_or(DisplayError::InvalidSize)?;
    let mut frame = CaptureFrame::new(clip.w, clip.h);

    // Local (within-source) offset of the clip's top-left.
    let local_x = (clip.x - src_origin.0) as u32;
    let local_y = (clip.y - src_origin.1) as u32;

    for row in 0..clip.h {
        let sy = (local_y + row) as usize;
        let src_start = sy * (src_w as usize) + (local_x as usize);
        let dst_start = (row as usize) * (clip.w as usize);
        let n = clip.w as usize;
        if let (Some(s), Some(d)) = (
            src.get(src_start..src_start + n),
            frame.pixels.get_mut(dst_start..dst_start + n),
        ) {
            d.copy_from_slice(s);
        }
    }
    Ok(frame)
}

/// An image encoder seam (e.g. PNG via `nexacore-image`).
pub trait ImageEncoder {
    /// Encode a captured frame to an image file's bytes.
    ///
    /// # Errors
    ///
    /// Returns [`DisplayError`] if the frame cannot be encoded.
    fn encode(&self, frame: &CaptureFrame) -> Result<Vec<u8>, DisplayError>;
}

/// Capture `target` from the provided source framebuffer and encode it to an
/// image file's bytes in one call (screenshot).
///
/// # Errors
///
/// Propagates [`resolve_capture_rect`] / [`capture_region`] errors, or the
/// encoder's error.
pub fn screenshot<G: CaptureGeometry, E: ImageEncoder>(
    target: CaptureTarget,
    geom: &G,
    src: &[u32],
    src_origin: (i32, i32),
    src_w: u32,
    src_h: u32,
    encoder: &E,
) -> Result<Vec<u8>, DisplayError> {
    let rect = resolve_capture_rect(target, geom)?;
    let frame = capture_region(src, src_origin, src_w, src_h, rect)?;
    encoder.encode(&frame)
}

// -----------------------------------------------------------------------------
// WS7-18.5 / .6 — recording pipeline
// -----------------------------------------------------------------------------

/// Recording configuration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RecordingConfig {
    /// Target frames per second.
    pub fps: u32,
}

impl RecordingConfig {
    /// The inter-frame interval in microseconds for the target fps.
    #[must_use]
    pub fn frame_interval_us(self) -> u64 {
        if self.fps == 0 {
            return 0;
        }
        1_000_000 / u64::from(self.fps)
    }
}

/// A video encoder seam (e.g. an MP4/WebM muxer over `nexacore-media`).
pub trait VideoEncoder {
    /// Encode one frame at `timestamp_us`.
    ///
    /// # Errors
    ///
    /// Returns [`DisplayError`] if the frame cannot be encoded.
    fn push_frame(&mut self, frame: &CaptureFrame, timestamp_us: u64) -> Result<(), DisplayError>;

    /// Finalize the stream and return the playable container bytes.
    ///
    /// # Errors
    ///
    /// Returns [`DisplayError`] if the container cannot be finalized.
    fn finish(&mut self) -> Result<Vec<u8>, DisplayError>;
}

/// Paces captured frames to a target fps and drives a [`VideoEncoder`].
///
/// The compositor may present faster or slower than the target rate; [`Recorder::offer`]
/// encodes a frame only when the target interval has elapsed, so the output
/// stream holds a steady cadence regardless of present jitter.
#[derive(Debug)]
pub struct Recorder<E: VideoEncoder> {
    encoder: E,
    interval_us: u64,
    next_due_us: u64,
    started: bool,
    frames_encoded: u64,
}

impl<E: VideoEncoder> Recorder<E> {
    /// Start a recorder driving `encoder` at `config`'s frame rate.
    pub fn new(encoder: E, config: RecordingConfig) -> Self {
        Self {
            encoder,
            interval_us: config.frame_interval_us(),
            next_due_us: 0,
            started: false,
            frames_encoded: 0,
        }
    }

    /// Number of frames encoded so far.
    #[must_use]
    pub fn frames_encoded(&self) -> u64 {
        self.frames_encoded
    }

    /// Offer a captured frame presented at `now_us`. Encodes it (and returns
    /// `true`) if the target interval has elapsed since the last encoded frame;
    /// otherwise drops it (returns `false`).
    ///
    /// # Errors
    ///
    /// Propagates the encoder's error.
    pub fn offer(&mut self, frame: &CaptureFrame, now_us: u64) -> Result<bool, DisplayError> {
        if !self.started {
            self.started = true;
            self.next_due_us = now_us;
        }
        if now_us < self.next_due_us {
            return Ok(false);
        }
        self.encoder.push_frame(frame, now_us)?;
        self.frames_encoded += 1;
        // Advance the schedule, skipping any intervals we fell behind on so the
        // cadence does not runaway after a stall.
        self.next_due_us = self.next_due_us.saturating_add(self.interval_us.max(1));
        if self.next_due_us <= now_us {
            self.next_due_us = now_us.saturating_add(self.interval_us.max(1));
        }
        Ok(true)
    }

    /// Finish the recording and return the playable container bytes.
    ///
    /// # Errors
    ///
    /// Propagates the encoder's error.
    pub fn finish(mut self) -> Result<Vec<u8>, DisplayError> {
        self.encoder.finish()
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

    /// Minimal geometry double.
    struct Geom {
        window: Option<Rect>,
        output: Option<Rect>,
        desktop: Option<Rect>,
    }
    impl CaptureGeometry for Geom {
        fn window_rect(&self, _id: WindowId) -> Option<Rect> {
            self.window
        }
        fn output_rect(&self, _id: OutputId) -> Option<Rect> {
            self.output
        }
        fn desktop_rect(&self) -> Option<Rect> {
            self.desktop
        }
    }

    /// A 4x4 source framebuffer whose pixel value encodes `y*10 + x`.
    fn src4x4() -> Vec<u32> {
        let mut v = Vec::new();
        for y in 0..4u32 {
            for x in 0..4u32 {
                v.push(y * 10 + x);
            }
        }
        v
    }

    #[test]
    fn resolve_targets() {
        let g = Geom {
            window: Some(Rect {
                x: 10,
                y: 10,
                w: 100,
                h: 80,
            }),
            output: Some(Rect {
                x: 0,
                y: 0,
                w: 1920,
                h: 1080,
            }),
            desktop: Some(Rect {
                x: 0,
                y: 0,
                w: 3840,
                h: 1080,
            }),
        };
        assert_eq!(
            resolve_capture_rect(CaptureTarget::Window(WindowId(1)), &g).unwrap(),
            Rect {
                x: 10,
                y: 10,
                w: 100,
                h: 80
            }
        );
        assert_eq!(
            resolve_capture_rect(CaptureTarget::FullDesktop, &g).unwrap(),
            Rect {
                x: 0,
                y: 0,
                w: 3840,
                h: 1080
            }
        );
        assert_eq!(
            resolve_capture_rect(
                CaptureTarget::Region(Rect {
                    x: 1,
                    y: 2,
                    w: 3,
                    h: 4
                }),
                &g
            )
            .unwrap(),
            Rect {
                x: 1,
                y: 2,
                w: 3,
                h: 4
            }
        );
    }

    #[test]
    fn resolve_missing_window_errors() {
        let g = Geom {
            window: None,
            output: None,
            desktop: None,
        };
        assert_eq!(
            resolve_capture_rect(CaptureTarget::Window(WindowId(9)), &g),
            Err(DisplayError::UnknownWindow(WindowId(9)))
        );
        assert_eq!(
            resolve_capture_rect(CaptureTarget::FullDesktop, &g),
            Err(DisplayError::InvalidSize)
        );
    }

    #[test]
    fn region_capture_extracts_subrect() {
        let src = src4x4();
        // Capture the 2x2 block at (1,1): values 11,12 / 21,22.
        let frame = capture_region(
            &src,
            (0, 0),
            4,
            4,
            Rect {
                x: 1,
                y: 1,
                w: 2,
                h: 2,
            },
        )
        .unwrap();
        assert_eq!(frame.width, 2);
        assert_eq!(frame.height, 2);
        assert_eq!(frame.pixel(0, 0), Some(11));
        assert_eq!(frame.pixel(1, 0), Some(12));
        assert_eq!(frame.pixel(0, 1), Some(21));
        assert_eq!(frame.pixel(1, 1), Some(22));
    }

    #[test]
    fn region_capture_clips_to_source() {
        let src = src4x4();
        // Region straddles the right/bottom edge → clipped to 2x2 at (2,2).
        let frame = capture_region(
            &src,
            (0, 0),
            4,
            4,
            Rect {
                x: 2,
                y: 2,
                w: 5,
                h: 5,
            },
        )
        .unwrap();
        assert_eq!((frame.width, frame.height), (2, 2));
        assert_eq!(frame.pixel(0, 0), Some(22));
        assert_eq!(frame.pixel(1, 1), Some(33));
    }

    #[test]
    fn region_capture_honours_origin() {
        let src = src4x4();
        // Source covers global (100,100)..(104,104). Capture (101,101,2,2).
        let frame = capture_region(
            &src,
            (100, 100),
            4,
            4,
            Rect {
                x: 101,
                y: 101,
                w: 2,
                h: 2,
            },
        )
        .unwrap();
        assert_eq!(frame.pixel(0, 0), Some(11)); // local (1,1)
    }

    #[test]
    fn region_disjoint_from_source_errors() {
        let src = src4x4();
        assert_eq!(
            capture_region(
                &src,
                (0, 0),
                4,
                4,
                Rect {
                    x: 100,
                    y: 100,
                    w: 2,
                    h: 2
                }
            ),
            Err(DisplayError::InvalidSize)
        );
    }

    #[test]
    fn short_source_buffer_errors() {
        let src = vec![0u32; 3];
        assert_eq!(
            capture_region(
                &src,
                (0, 0),
                4,
                4,
                Rect {
                    x: 0,
                    y: 0,
                    w: 2,
                    h: 2
                }
            ),
            Err(DisplayError::InvalidSize)
        );
    }

    /// Records frames and their timestamps.
    #[derive(Default)]
    struct MockEncoder {
        timestamps: Vec<u64>,
        finished: bool,
    }
    impl VideoEncoder for MockEncoder {
        fn push_frame(
            &mut self,
            _frame: &CaptureFrame,
            timestamp_us: u64,
        ) -> Result<(), DisplayError> {
            self.timestamps.push(timestamp_us);
            Ok(())
        }
        fn finish(&mut self) -> Result<Vec<u8>, DisplayError> {
            self.finished = true;
            Ok(vec![0xAA, 0xBB])
        }
    }

    #[test]
    fn recorder_paces_to_target_fps() {
        // 30 fps → 33_333 us interval.
        let mut rec = Recorder::new(MockEncoder::default(), RecordingConfig { fps: 30 });
        let frame = CaptureFrame::new(2, 2);
        // Present at 60 fps (16_666 us apart): every other frame should encode.
        let mut encoded = 0;
        for i in 0..6u64 {
            if rec.offer(&frame, i * 16_666).unwrap() {
                encoded += 1;
            }
        }
        // Frames at t=0, 33_332(no), 49_998(yes)... → roughly half.
        assert_eq!(encoded, rec.frames_encoded());
        assert!((3..=4).contains(&encoded));
    }

    #[test]
    fn recorder_finishes_to_bytes() {
        let mut rec = Recorder::new(MockEncoder::default(), RecordingConfig { fps: 30 });
        let frame = CaptureFrame::new(2, 2);
        rec.offer(&frame, 0).unwrap();
        let bytes = rec.finish().unwrap();
        assert_eq!(bytes, vec![0xAA, 0xBB]);
    }

    #[test]
    fn frame_interval_matches_fps() {
        assert_eq!(RecordingConfig { fps: 30 }.frame_interval_us(), 33_333);
        assert_eq!(RecordingConfig { fps: 0 }.frame_interval_us(), 0);
    }
}
