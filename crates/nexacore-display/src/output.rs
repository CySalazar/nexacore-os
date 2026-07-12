//! Multi-monitor output model and desktop layout (WS7-11).
//!
//! The WS7-01 compositor renders one screen. This module lifts that to an
//! **extended desktop** spanning several outputs, each with its own mode
//! (resolution + refresh), [`ScaleFactor`] (WS7-04),
//! and [`Rotation`]. Outputs are placed in a shared **global logical
//! coordinate space**; the union of their rectangles is the desktop, and every
//! window/cursor position is expressed in that space.
//!
//! The model is pure and host-testable: [`OutputManager`] enumerates outputs,
//! edits their mode/scale/rotation/position, arranges them into an extended
//! desktop, answers "which output owns this point", and processes hotplug
//! connect/disconnect. The mapping a live compositor needs — a global-space
//! coordinate to a device pixel in a specific output's framebuffer, accounting
//! for the output's position, scale, and rotation — is
//! [`Output::global_to_device`]. Driving the real KMS/`virtio-gpu` scanouts is
//! the device-side follow-up (WS7-11.9, rig).

#![allow(
    clippy::float_arithmetic,
    clippy::cast_precision_loss,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::integer_division
)]

use alloc::{string::String, vec::Vec};

use libm::roundf;

use crate::{DisplayError, geometry::Rect, scale::ScaleFactor};

/// Stable identifier of a physical output (connector).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct OutputId(pub u32);

/// Display rotation applied to an output, in 90° steps.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Rotation {
    /// Landscape, no rotation (0°).
    #[default]
    Normal,
    /// Rotated 90° clockwise.
    Rotate90,
    /// Rotated 180°.
    Rotate180,
    /// Rotated 270° clockwise.
    Rotate270,
}

impl Rotation {
    /// Rotation angle in degrees.
    #[must_use]
    pub const fn degrees(self) -> u16 {
        match self {
            Self::Normal => 0,
            Self::Rotate90 => 90,
            Self::Rotate180 => 180,
            Self::Rotate270 => 270,
        }
    }

    /// Whether this rotation swaps width and height (portrait orientations).
    #[must_use]
    pub const fn swaps_axes(self) -> bool {
        matches!(self, Self::Rotate90 | Self::Rotate270)
    }

    /// Apply the rotation to a device `(w, h)`, swapping axes for 90°/270°.
    #[must_use]
    pub const fn apply_size(self, w: u32, h: u32) -> (u32, u32) {
        if self.swaps_axes() { (h, w) } else { (w, h) }
    }
}

/// A supported output mode: device resolution and refresh rate.
///
/// Refresh is stored in **milli-hertz** so `59.94 Hz` is `59_940` — exact
/// integer arithmetic, no float in the mode table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OutputMode {
    /// Native (unrotated) width in device pixels.
    pub width: u32,
    /// Native (unrotated) height in device pixels.
    pub height: u32,
    /// Refresh rate in milli-hertz.
    pub refresh_mhz: u32,
}

impl OutputMode {
    /// A mode with the given device resolution and refresh (milli-hertz).
    #[must_use]
    pub const fn new(width: u32, height: u32, refresh_mhz: u32) -> Self {
        Self {
            width,
            height,
            refresh_mhz,
        }
    }

    /// Pixel count of the mode.
    #[must_use]
    pub const fn pixels(self) -> u64 {
        self.width as u64 * self.height as u64
    }

    /// Ordering key for "preferred" selection: more pixels, then higher refresh.
    const fn rank(self) -> (u64, u32) {
        (self.pixels(), self.refresh_mhz)
    }
}

/// A single physical output and its current configuration.
#[derive(Debug, Clone)]
pub struct Output {
    id: OutputId,
    name: String,
    modes: Vec<OutputMode>,
    active_mode: usize,
    scale: ScaleFactor,
    rotation: Rotation,
    /// Top-left position in the global logical coordinate space.
    position: (i32, i32),
    enabled: bool,
}

impl Output {
    /// Build an output from its id, connector name, and supported modes.
    ///
    /// The preferred mode (most pixels, then highest refresh) is made active;
    /// scale defaults to 1×, rotation to [`Rotation::Normal`], position to the
    /// origin, and the output is enabled.
    ///
    /// # Errors
    ///
    /// [`DisplayError::InvalidMode`] if `modes` is empty.
    pub fn new(id: OutputId, name: String, modes: Vec<OutputMode>) -> Result<Self, DisplayError> {
        if modes.is_empty() {
            return Err(DisplayError::InvalidMode);
        }
        let active_mode = modes
            .iter()
            .enumerate()
            .max_by_key(|(_, m)| m.rank())
            .map_or(0, |(i, _)| i);
        Ok(Self {
            id,
            name,
            modes,
            active_mode,
            scale: ScaleFactor::ONE,
            rotation: Rotation::Normal,
            position: (0, 0),
            enabled: true,
        })
    }

    /// The output's id.
    #[must_use]
    pub fn id(&self) -> OutputId {
        self.id
    }

    /// The connector name (e.g. `eDP-1`, `HDMI-A-1`).
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// The supported modes.
    #[must_use]
    pub fn modes(&self) -> &[OutputMode] {
        &self.modes
    }

    /// The active mode.
    #[must_use]
    pub fn active_mode(&self) -> OutputMode {
        // `active_mode` is an always-valid index (constructor + `set_mode`
        // guarantee it); fall back to the first mode, then to a 1×1 sentinel
        // that the non-empty-modes invariant makes unreachable.
        self.modes
            .get(self.active_mode)
            .or_else(|| self.modes.first())
            .copied()
            .unwrap_or(OutputMode::new(1, 1, 1_000))
    }

    /// The current scale factor.
    #[must_use]
    pub fn scale(&self) -> ScaleFactor {
        self.scale
    }

    /// The current rotation.
    #[must_use]
    pub fn rotation(&self) -> Rotation {
        self.rotation
    }

    /// The global-space top-left position.
    #[must_use]
    pub fn position(&self) -> (i32, i32) {
        self.position
    }

    /// Whether the output contributes to the desktop.
    #[must_use]
    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// The device resolution after rotation (framebuffer pixels).
    #[must_use]
    pub fn device_size(&self) -> (u32, u32) {
        let m = self.active_mode();
        self.rotation.apply_size(m.width, m.height)
    }

    /// The output's extent in **logical** pixels (device size ÷ scale).
    #[must_use]
    pub fn logical_size(&self) -> (u32, u32) {
        let (dw, dh) = self.device_size();
        let s = self.scale.value();
        let lw = roundf(dw as f32 / s) as u32;
        let lh = roundf(dh as f32 / s) as u32;
        (lw.max(1), lh.max(1))
    }

    /// The output's rectangle in the global logical coordinate space.
    #[must_use]
    pub fn bounds(&self) -> Rect {
        let (lw, lh) = self.logical_size();
        Rect {
            x: self.position.0,
            y: self.position.1,
            w: lw,
            h: lh,
        }
    }

    /// Map a global logical point to a device pixel within this output's
    /// framebuffer, honouring position, scale, and rotation.
    ///
    /// Returns `None` if the point is outside the output's bounds. The result
    /// is a `(x, y)` device-pixel coordinate in the **rotated** framebuffer
    /// (i.e. what a scanout at [`Output::device_size`] expects).
    #[must_use]
    pub fn global_to_device(&self, gx: i32, gy: i32) -> Option<(u32, u32)> {
        if !self.bounds().contains_point(gx, gy) {
            return None;
        }
        // Local logical offset within the output.
        let lx = (gx - self.position.0) as f32;
        let ly = (gy - self.position.1) as f32;
        // Logical → device (rotated framebuffer) pixels.
        let s = self.scale.value();
        let dx = (lx * s) as u32;
        let dy = (ly * s) as u32;
        Some((dx, dy))
    }

    /// Select an active mode by index into [`Output::modes`].
    ///
    /// # Errors
    ///
    /// [`DisplayError::InvalidMode`] if `idx` is out of range.
    pub fn set_mode(&mut self, idx: usize) -> Result<(), DisplayError> {
        if idx >= self.modes.len() {
            return Err(DisplayError::InvalidMode);
        }
        self.active_mode = idx;
        Ok(())
    }

    /// Set the per-output scale factor (WS7-04 integration).
    pub fn set_scale(&mut self, scale: ScaleFactor) {
        self.scale = scale;
    }

    /// Set the per-output rotation.
    pub fn set_rotation(&mut self, rotation: Rotation) {
        self.rotation = rotation;
    }

    /// Set the global-space top-left position.
    pub fn set_position(&mut self, x: i32, y: i32) {
        self.position = (x, y);
    }

    /// Enable or disable the output.
    pub fn set_enabled(&mut self, enabled: bool) {
        self.enabled = enabled;
    }
}

/// A hotplug transition reported by [`OutputManager`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HotplugEvent {
    /// An output was connected.
    Connected(OutputId),
    /// An output was disconnected.
    Disconnected(OutputId),
}

/// Manages the set of outputs and their extended-desktop layout.
///
/// Outputs are kept in insertion order. All geometry lives in the global
/// logical coordinate space; [`OutputManager::desktop_bounds`] is the union of
/// enabled outputs.
#[derive(Debug, Clone, Default)]
pub struct OutputManager {
    outputs: Vec<Output>,
}

impl OutputManager {
    /// An empty manager (no outputs).
    #[must_use]
    pub fn new() -> Self {
        Self {
            outputs: Vec::new(),
        }
    }

    /// All outputs in registration order.
    #[must_use]
    pub fn outputs(&self) -> &[Output] {
        &self.outputs
    }

    /// Number of registered outputs.
    #[must_use]
    pub fn len(&self) -> usize {
        self.outputs.len()
    }

    /// Whether no outputs are registered.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.outputs.is_empty()
    }

    /// Ids of the enabled outputs (those contributing to the desktop).
    #[must_use]
    pub fn enabled_ids(&self) -> Vec<OutputId> {
        self.outputs
            .iter()
            .filter(|o| o.enabled)
            .map(Output::id)
            .collect()
    }

    /// A shared reference to an output by id.
    #[must_use]
    pub fn get(&self, id: OutputId) -> Option<&Output> {
        self.outputs.iter().find(|o| o.id == id)
    }

    fn get_mut(&mut self, id: OutputId) -> Result<&mut Output, DisplayError> {
        self.outputs
            .iter_mut()
            .find(|o| o.id == id)
            .ok_or(DisplayError::UnknownOutput(id))
    }

    /// Register a newly connected output (hotplug).
    ///
    /// # Errors
    ///
    /// [`DisplayError::DuplicateOutput`] if an output with the same id already
    /// exists.
    pub fn connect(&mut self, output: Output) -> Result<HotplugEvent, DisplayError> {
        let id = output.id;
        if self.outputs.iter().any(|o| o.id == id) {
            return Err(DisplayError::DuplicateOutput(id));
        }
        self.outputs.push(output);
        Ok(HotplugEvent::Connected(id))
    }

    /// Remove a disconnected output (hotplug).
    ///
    /// # Errors
    ///
    /// [`DisplayError::UnknownOutput`] if no output with that id exists.
    pub fn disconnect(&mut self, id: OutputId) -> Result<HotplugEvent, DisplayError> {
        let before = self.outputs.len();
        self.outputs.retain(|o| o.id != id);
        if self.outputs.len() == before {
            return Err(DisplayError::UnknownOutput(id));
        }
        Ok(HotplugEvent::Disconnected(id))
    }

    /// Set an output's active mode.
    ///
    /// # Errors
    ///
    /// [`DisplayError::UnknownOutput`] / [`DisplayError::InvalidMode`].
    pub fn set_mode(&mut self, id: OutputId, idx: usize) -> Result<(), DisplayError> {
        self.get_mut(id)?.set_mode(idx)
    }

    /// Set an output's scale.
    ///
    /// # Errors
    ///
    /// [`DisplayError::UnknownOutput`] if the output does not exist.
    pub fn set_scale(&mut self, id: OutputId, scale: ScaleFactor) -> Result<(), DisplayError> {
        self.get_mut(id)?.set_scale(scale);
        Ok(())
    }

    /// Set an output's rotation.
    ///
    /// # Errors
    ///
    /// [`DisplayError::UnknownOutput`] if the output does not exist.
    pub fn set_rotation(&mut self, id: OutputId, rotation: Rotation) -> Result<(), DisplayError> {
        self.get_mut(id)?.set_rotation(rotation);
        Ok(())
    }

    /// Set an output's global-space position.
    ///
    /// # Errors
    ///
    /// [`DisplayError::UnknownOutput`] if the output does not exist.
    pub fn set_position(&mut self, id: OutputId, x: i32, y: i32) -> Result<(), DisplayError> {
        self.get_mut(id)?.set_position(x, y);
        Ok(())
    }

    /// Enable or disable an output.
    ///
    /// # Errors
    ///
    /// [`DisplayError::UnknownOutput`] if the output does not exist.
    pub fn set_enabled(&mut self, id: OutputId, enabled: bool) -> Result<(), DisplayError> {
        self.get_mut(id)?.set_enabled(enabled);
        Ok(())
    }

    /// The extended-desktop bounding box: the union of every enabled output's
    /// rectangle. `None` when no output is enabled.
    #[must_use]
    pub fn desktop_bounds(&self) -> Option<Rect> {
        let mut it = self.outputs.iter().filter(|o| o.enabled);
        let first = it.next()?;
        let mut acc = first.bounds();
        for o in it {
            acc = acc.union(&o.bounds());
        }
        Some(acc)
    }

    /// The output owning a global logical point (first enabled match), if any.
    #[must_use]
    pub fn output_at(&self, gx: i32, gy: i32) -> Option<OutputId> {
        self.outputs
            .iter()
            .find(|o| o.enabled && o.bounds().contains_point(gx, gy))
            .map(Output::id)
    }

    /// Whether any two enabled outputs' rectangles overlap. A well-formed
    /// extended desktop has no overlaps (mirroring is a separate mode).
    #[must_use]
    pub fn has_overlap(&self) -> bool {
        let enabled: Vec<&Output> = self.outputs.iter().filter(|o| o.enabled).collect();
        for (i, a) in enabled.iter().enumerate() {
            for b in enabled.iter().skip(i + 1) {
                if a.bounds().intersect(&b.bounds()).is_some() {
                    return true;
                }
            }
        }
        false
    }

    /// Arrange all enabled outputs left-to-right at `y = 0`, packing each after
    /// the previous with no gap. A deterministic default extended-desktop
    /// layout. Returns the resulting desktop width.
    pub fn auto_arrange_horizontal(&mut self) -> u32 {
        let mut x = 0i32;
        for o in self.outputs.iter_mut().filter(|o| o.enabled) {
            o.set_position(x, 0);
            let (lw, _) = o.logical_size();
            x = x.saturating_add(i32::try_from(lw).unwrap_or(i32::MAX));
        }
        u32::try_from(x.max(0)).unwrap_or(u32::MAX)
    }

    /// The primary output: the enabled output at the global origin, else the
    /// first enabled output.
    #[must_use]
    pub fn primary(&self) -> Option<OutputId> {
        self.output_at(0, 0)
            .or_else(|| self.outputs.iter().find(|o| o.enabled).map(Output::id))
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
    use alloc::{string::ToString, vec};

    use super::*;

    fn modes() -> Vec<OutputMode> {
        vec![
            OutputMode::new(1920, 1080, 60_000),
            OutputMode::new(2560, 1440, 59_940),
            OutputMode::new(1280, 720, 60_000),
        ]
    }

    fn output(id: u32) -> Output {
        Output::new(OutputId(id), "HDMI-A-1".to_string(), modes()).unwrap()
    }

    #[test]
    fn new_selects_preferred_mode() {
        let o = output(1);
        // 2560x1440 has the most pixels.
        assert_eq!(o.active_mode(), OutputMode::new(2560, 1440, 59_940));
    }

    #[test]
    fn empty_modes_rejected() {
        assert!(matches!(
            Output::new(OutputId(1), "x".to_string(), vec![]),
            Err(DisplayError::InvalidMode)
        ));
    }

    #[test]
    fn rotation_swaps_logical_size() {
        let mut o = output(1);
        o.set_mode(0).unwrap(); // 1920x1080
        assert_eq!(o.logical_size(), (1920, 1080));
        o.set_rotation(Rotation::Rotate90);
        assert_eq!(o.device_size(), (1080, 1920));
        assert_eq!(o.logical_size(), (1080, 1920));
    }

    #[test]
    fn scale_halves_logical_size() {
        let mut o = output(1);
        o.set_mode(0).unwrap(); // 1920x1080 device
        o.set_scale(ScaleFactor::integer(2));
        assert_eq!(o.logical_size(), (960, 540));
        // A logical point maps back to a device pixel via the scale.
        o.set_position(0, 0);
        assert_eq!(o.global_to_device(100, 50), Some((200, 100)));
    }

    #[test]
    fn global_to_device_outside_is_none() {
        let mut o = output(1);
        o.set_mode(0).unwrap();
        o.set_position(0, 0);
        assert_eq!(o.global_to_device(5000, 5000), None);
    }

    #[test]
    fn auto_arrange_extends_desktop() {
        let mut m = OutputManager::new();
        let mut a = output(1);
        a.set_mode(0).unwrap(); // 1920x1080
        let mut b = output(2);
        b.set_mode(0).unwrap(); // 1920x1080
        m.connect(a).unwrap();
        m.connect(b).unwrap();
        let width = m.auto_arrange_horizontal();
        assert_eq!(width, 3840);
        assert_eq!(
            m.desktop_bounds(),
            Some(Rect {
                x: 0,
                y: 0,
                w: 3840,
                h: 1080
            })
        );
        assert!(!m.has_overlap());
        // The second output owns points past the first's width.
        assert_eq!(m.output_at(100, 100), Some(OutputId(1)));
        assert_eq!(m.output_at(2000, 100), Some(OutputId(2)));
    }

    #[test]
    fn overlap_is_detected() {
        let mut m = OutputManager::new();
        m.connect(output(1)).unwrap();
        m.connect(output(2)).unwrap();
        m.set_position(OutputId(1), 0, 0).unwrap();
        m.set_position(OutputId(2), 100, 100).unwrap();
        assert!(m.has_overlap());
    }

    #[test]
    fn hotplug_connect_disconnect() {
        let mut m = OutputManager::new();
        assert_eq!(
            m.connect(output(1)).unwrap(),
            HotplugEvent::Connected(OutputId(1))
        );
        assert_eq!(
            m.connect(output(1)),
            Err(DisplayError::DuplicateOutput(OutputId(1)))
        );
        assert_eq!(
            m.disconnect(OutputId(1)).unwrap(),
            HotplugEvent::Disconnected(OutputId(1))
        );
        assert_eq!(
            m.disconnect(OutputId(1)),
            Err(DisplayError::UnknownOutput(OutputId(1)))
        );
    }

    #[test]
    fn set_mode_out_of_range_rejected() {
        let mut m = OutputManager::new();
        m.connect(output(1)).unwrap();
        assert_eq!(m.set_mode(OutputId(1), 99), Err(DisplayError::InvalidMode));
        assert_eq!(
            m.set_mode(OutputId(9), 0),
            Err(DisplayError::UnknownOutput(OutputId(9)))
        );
    }

    #[test]
    fn disabled_output_leaves_desktop() {
        let mut m = OutputManager::new();
        let mut a = output(1);
        a.set_mode(0).unwrap();
        let mut b = output(2);
        b.set_mode(0).unwrap();
        m.connect(a).unwrap();
        m.connect(b).unwrap();
        m.auto_arrange_horizontal();
        m.set_enabled(OutputId(2), false).unwrap();
        assert_eq!(
            m.desktop_bounds(),
            Some(Rect {
                x: 0,
                y: 0,
                w: 1920,
                h: 1080
            })
        );
        assert_eq!(m.enabled_ids(), vec![OutputId(1)]);
    }

    #[test]
    fn primary_is_origin_output() {
        let mut m = OutputManager::new();
        let mut a = output(1);
        a.set_mode(0).unwrap();
        m.connect(a).unwrap();
        m.auto_arrange_horizontal();
        assert_eq!(m.primary(), Some(OutputId(1)));
    }
}
