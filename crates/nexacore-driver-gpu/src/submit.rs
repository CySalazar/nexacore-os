//! GPU submit seam, KMS-class vendor scaffold, and presentation throughput.
//!
//! * [`GpuSubmit`] is the seam the tensor HAL (WS5) dispatches GPU compute /
//!   3D submissions through (WS2-09.11) — a backend implements it over the
//!   virtio-gpu control queue or a real KMS driver.
//! * [`KmsDriver`] is the vendor-driver scaffold (WS2-09.15): the trait a real
//!   Intel/AMD/NVIDIA KMS-class driver fills in once the bring-up lands. Stage 1
//!   is virtio-gpu; stages 2–3 swap in [`KmsVendor`]-specific implementations
//!   behind this same seam.
//! * [`FpsMeter`] is the integer-only presentation-throughput instrument
//!   (WS2-09.14): a sliding-window frames-per-second and bytes-per-window meter.

// The FPS math divides frame counts by the window length (both runtime values).
#![allow(clippy::integer_division, clippy::cast_lossless)]

use alloc::vec::Vec;
use core::fmt;

use crate::display::ScanoutMode;

/// Failure modes for GPU submission and KMS operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SubmitError {
    /// The backend is not initialised / no device is bound yet.
    NotReady,
    /// The submission exceeds a queue or resource limit.
    CapacityExceeded,
    /// The requested operation is not supported by this backend.
    Unsupported,
}

impl fmt::Display for SubmitError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::NotReady => "gpu backend not ready",
            Self::CapacityExceeded => "gpu submission capacity exceeded",
            Self::Unsupported => "gpu operation unsupported",
        };
        f.write_str(s)
    }
}

impl core::error::Error for SubmitError {}

/// The seam the tensor HAL dispatches GPU work through.
pub trait GpuSubmit: Send + Sync {
    /// Submit a command stream to context `ctx_id`. Returns a fence id the
    /// caller polls for completion.
    ///
    /// # Errors
    ///
    /// Returns [`SubmitError`] if the backend cannot accept the submission.
    fn submit(&self, ctx_id: u32, commands: &[u8]) -> Result<u64, SubmitError>;

    /// Whether the work behind `fence_id` has completed on the host.
    fn fence_signalled(&self, fence_id: u64) -> bool;
}

/// GPU vendor / class behind a [`KmsDriver`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KmsVendor {
    /// The virtio-gpu paravirtual device (stage 1).
    VirtioGpu,
    /// Intel integrated / discrete (i915/xe class).
    Intel,
    /// AMD (amdgpu class).
    Amd,
    /// NVIDIA (nouveau / proprietary class).
    Nvidia,
}

/// Vendor KMS-class driver scaffold. Stage-1 virtio-gpu and the future real
/// vendor drivers implement this so the compositor is driver-agnostic.
pub trait KmsDriver: Send + Sync {
    /// The vendor / class this driver targets.
    fn vendor(&self) -> KmsVendor;

    /// Program `mode` onto scanout `scanout_id`.
    ///
    /// # Errors
    ///
    /// Returns [`SubmitError`] if the mode cannot be set.
    fn set_mode(&self, scanout_id: u32, mode: ScanoutMode) -> Result<(), SubmitError>;

    /// Flip scanout `scanout_id` to display `resource_id`.
    ///
    /// # Errors
    ///
    /// Returns [`SubmitError`] if the flip cannot be queued.
    fn page_flip(&self, scanout_id: u32, resource_id: u32) -> Result<(), SubmitError>;
}

/// Sliding-window presentation throughput meter (integer-only).
///
/// Records `(timestamp_µs, bytes)` per presented frame and reports
/// frames-per-second (×1000) and bytes-per-window over a fixed time window.
#[derive(Debug, Clone)]
pub struct FpsMeter {
    window_us: u64,
    frames: Vec<(u64, u64)>,
}

impl FpsMeter {
    /// One-second default window.
    pub const DEFAULT_WINDOW_US: u64 = 1_000_000;

    /// Create a meter with the given window length in microseconds (clamped to
    /// at least 1 to avoid division by zero).
    #[must_use]
    pub fn new(window_us: u64) -> Self {
        Self {
            window_us: window_us.max(1),
            frames: Vec::new(),
        }
    }

    /// Record a presented frame at `now_us` carrying `bytes` of pixel data,
    /// pruning samples older than the window.
    pub fn record(&mut self, now_us: u64, bytes: u64) {
        // Keep frames still inside the window: `ts + window > now`. Phrased this
        // way (rather than `ts > now - window`) so an early window — where
        // `now < window` — does not saturate the cutoff to 0 and wrongly prune
        // the frame at timestamp 0.
        self.frames
            .retain(|&(ts, _)| ts.saturating_add(self.window_us) > now_us);
        self.frames.push((now_us, bytes));
    }

    /// Frames currently in the window.
    #[must_use]
    pub fn frame_count(&self) -> usize {
        self.frames.len()
    }

    /// Frames-per-second scaled by 1000 (so 59.94 fps reads as `59940`),
    /// normalised to the window length.
    #[must_use]
    pub fn fps_milli(&self) -> u64 {
        (self.frames.len() as u64).saturating_mul(1_000_000_000) / self.window_us
    }

    /// Total pixel bytes presented within the window.
    #[must_use]
    pub fn throughput_bytes(&self) -> u64 {
        self.frames.iter().map(|&(_, b)| b).sum()
    }
}

#[cfg(test)]
mod tests {
    use core::sync::atomic::{AtomicU64, Ordering};

    use super::*;

    /// Minimal recording KMS driver exercising the scaffold trait.
    struct RecordingKms {
        flips: AtomicU64,
    }
    impl KmsDriver for RecordingKms {
        fn vendor(&self) -> KmsVendor {
            KmsVendor::VirtioGpu
        }
        fn set_mode(&self, _scanout_id: u32, mode: ScanoutMode) -> Result<(), SubmitError> {
            if mode.width == 0 {
                Err(SubmitError::Unsupported)
            } else {
                Ok(())
            }
        }
        fn page_flip(&self, _scanout_id: u32, _resource_id: u32) -> Result<(), SubmitError> {
            self.flips.fetch_add(1, Ordering::Relaxed);
            Ok(())
        }
    }

    #[test]
    fn kms_scaffold_records_flips() {
        let kms = RecordingKms {
            flips: AtomicU64::new(0),
        };
        assert_eq!(kms.vendor(), KmsVendor::VirtioGpu);
        assert!(
            kms.set_mode(
                0,
                ScanoutMode {
                    width: 1920,
                    height: 1080
                }
            )
            .is_ok()
        );
        assert_eq!(
            kms.set_mode(
                0,
                ScanoutMode {
                    width: 0,
                    height: 0
                }
            ),
            Err(SubmitError::Unsupported)
        );
        kms.page_flip(0, 1).unwrap();
        kms.page_flip(0, 2).unwrap();
        assert_eq!(kms.flips.load(Ordering::Relaxed), 2);
    }

    #[test]
    fn fps_meter_windows_frames() {
        let mut m = FpsMeter::new(FpsMeter::DEFAULT_WINDOW_US);
        // 60 frames across one second at ~16.6ms spacing.
        for i in 0..60u64 {
            m.record(i * 16_666, 8_294_400); // 1080p BGRA bytes per frame
        }
        assert_eq!(m.frame_count(), 60);
        // 60 frames in a 1s window → 60000 milli-fps.
        assert_eq!(m.fps_milli(), 60_000);
        assert_eq!(m.throughput_bytes(), 60 * 8_294_400);
    }

    #[test]
    fn fps_meter_prunes_old_frames() {
        let mut m = FpsMeter::new(FpsMeter::DEFAULT_WINDOW_US);
        m.record(0, 100);
        m.record(2_000_000, 200); // 2s later → first frame pruned
        assert_eq!(m.frame_count(), 1);
        assert_eq!(m.throughput_bytes(), 200);
    }

    #[test]
    fn submit_error_displays() {
        extern crate alloc;
        use alloc::string::ToString;
        assert_eq!(SubmitError::NotReady.to_string(), "gpu backend not ready");
    }
}
