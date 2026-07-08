//! Display configuration panel for Settings (WS7-11.8).
//!
//! [`DisplaySettingsPanel`] is the Settings-app view over the compositor's
//! [`OutputManager`](nexacore_display::output::OutputManager) (WS7-11 core). It
//! turns the live output set into a render-ready view model ([`OutputRow`] per
//! monitor, with its selectable modes, scale, rotation, position, and
//! primary/enabled flags) and applies the user's edits back through the
//! manager, validating the resulting extended-desktop layout **fail-closed**
//! (at least one enabled output, no overlapping outputs).
//!
//! The panel holds a working copy of the layout; the caller commits it to the
//! compositor once [`DisplaySettingsPanel::validate`] passes. Rendering the
//! widgets and pushing modeset ioctls are the desktop-runtime/rig follow-ups.

#![allow(
    clippy::float_arithmetic,
    clippy::cast_precision_loss,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss
)]

use alloc::{
    string::{String, ToString},
    vec::Vec,
};

use nexacore_display::{
    DisplayError,
    output::{Output, OutputId, OutputManager, Rotation},
    scale::ScaleFactor,
};

/// Errors surfaced by the display settings panel.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum PanelError {
    /// A manager-level failure (unknown output, invalid mode, duplicate id).
    Display(DisplayError),
    /// The requested scale percentage is not a supported factor.
    InvalidScale,
    /// Applying the configuration would leave no output enabled.
    NoEnabledOutput,
    /// Two or more enabled outputs overlap in the global layout.
    OverlappingLayout,
}

impl From<DisplayError> for PanelError {
    fn from(e: DisplayError) -> Self {
        Self::Display(e)
    }
}

impl core::fmt::Display for PanelError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Display(e) => write!(f, "display settings: {e}"),
            Self::InvalidScale => write!(f, "display settings: unsupported scale"),
            Self::NoEnabledOutput => {
                write!(f, "display settings: at least one output must be enabled")
            }
            Self::OverlappingLayout => write!(f, "display settings: outputs overlap"),
        }
    }
}

impl core::error::Error for PanelError {}

/// A selectable mode option in a [`OutputRow`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ModeOption {
    /// Index into the output's mode list (argument to [`DisplaySettingsPanel::select_mode`]).
    pub index: usize,
    /// Device width in pixels.
    pub width: u32,
    /// Device height in pixels.
    pub height: u32,
    /// Refresh rate in milli-hertz.
    pub refresh_mhz: u32,
    /// Whether this is the output's active mode.
    pub is_active: bool,
}

/// A per-output row in the display settings view model.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutputRow {
    /// The output's id.
    pub id: OutputId,
    /// Connector name.
    pub name: String,
    /// Whether the output is enabled (part of the desktop).
    pub enabled: bool,
    /// Whether this is the primary output.
    pub is_primary: bool,
    /// Selectable modes.
    pub modes: Vec<ModeOption>,
    /// Current scale as a percentage (`100` = 1×).
    pub scale_percent: u32,
    /// Current rotation.
    pub rotation: Rotation,
    /// Global-space top-left position.
    pub position: (i32, i32),
    /// Current logical extent.
    pub logical_size: (u32, u32),
}

/// The Settings display panel: an editable view over an [`OutputManager`].
#[derive(Debug, Clone, Default)]
pub struct DisplaySettingsPanel {
    manager: OutputManager,
}

impl DisplaySettingsPanel {
    /// Wrap a working copy of the compositor's output manager.
    #[must_use]
    pub fn new(manager: OutputManager) -> Self {
        Self { manager }
    }

    /// The underlying manager (to commit to the compositor once valid).
    #[must_use]
    pub fn manager(&self) -> &OutputManager {
        &self.manager
    }

    /// Build the view model: one [`OutputRow`] per output, in registration
    /// order.
    #[must_use]
    pub fn rows(&self) -> Vec<OutputRow> {
        let primary = self.manager.primary();
        self.manager
            .outputs()
            .iter()
            .map(|o| Self::row_for(o, primary == Some(o.id())))
            .collect()
    }

    fn row_for(o: &Output, is_primary: bool) -> OutputRow {
        let active = o.active_mode();
        let modes = o
            .modes()
            .iter()
            .enumerate()
            .map(|(index, m)| ModeOption {
                index,
                width: m.width,
                height: m.height,
                refresh_mhz: m.refresh_mhz,
                is_active: *m == active,
            })
            .collect();
        OutputRow {
            id: o.id(),
            name: o.name().to_string(),
            enabled: o.is_enabled(),
            is_primary,
            modes,
            scale_percent: scale_to_percent(o.scale()),
            rotation: o.rotation(),
            position: o.position(),
            logical_size: o.logical_size(),
        }
    }

    /// Select an output's active mode.
    ///
    /// # Errors
    ///
    /// [`PanelError::Display`] if the output or mode index is invalid.
    pub fn select_mode(&mut self, id: OutputId, idx: usize) -> Result<(), PanelError> {
        self.manager.set_mode(id, idx)?;
        Ok(())
    }

    /// Set an output's scale from a percentage (`100` = 1×, `150` = 1.5×).
    ///
    /// # Errors
    ///
    /// [`PanelError::InvalidScale`] if the percentage is not a supported factor;
    /// [`PanelError::Display`] if the output does not exist.
    pub fn set_scale_percent(&mut self, id: OutputId, percent: u32) -> Result<(), PanelError> {
        let factor = ScaleFactor::new(percent as f32 / 100.0).ok_or(PanelError::InvalidScale)?;
        self.manager.set_scale(id, factor)?;
        Ok(())
    }

    /// Set an output's rotation.
    ///
    /// # Errors
    ///
    /// [`PanelError::Display`] if the output does not exist.
    pub fn set_rotation(&mut self, id: OutputId, rotation: Rotation) -> Result<(), PanelError> {
        self.manager.set_rotation(id, rotation)?;
        Ok(())
    }

    /// Move an output to a new global-space position.
    ///
    /// # Errors
    ///
    /// [`PanelError::Display`] if the output does not exist.
    pub fn move_output(&mut self, id: OutputId, x: i32, y: i32) -> Result<(), PanelError> {
        self.manager.set_position(id, x, y)?;
        Ok(())
    }

    /// Enable or disable an output.
    ///
    /// # Errors
    ///
    /// [`PanelError::Display`] if the output does not exist.
    pub fn set_enabled(&mut self, id: OutputId, enabled: bool) -> Result<(), PanelError> {
        self.manager.set_enabled(id, enabled)?;
        Ok(())
    }

    /// Re-pack the enabled outputs left-to-right into a gap-free extended
    /// desktop (the "arrange displays" button).
    pub fn arrange_horizontal(&mut self) {
        self.manager.auto_arrange_horizontal();
    }

    /// Validate the current configuration before it is committed.
    ///
    /// # Errors
    ///
    /// [`PanelError::NoEnabledOutput`] if nothing is enabled;
    /// [`PanelError::OverlappingLayout`] if two enabled outputs overlap.
    pub fn validate(&self) -> Result<(), PanelError> {
        if self.manager.enabled_ids().is_empty() {
            return Err(PanelError::NoEnabledOutput);
        }
        if self.manager.has_overlap() {
            return Err(PanelError::OverlappingLayout);
        }
        Ok(())
    }
}

/// Convert a scale factor to a rounded percentage (`1.5×` → `150`).
fn scale_to_percent(scale: ScaleFactor) -> u32 {
    (scale.value() * 100.0 + 0.5) as u32
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]
mod tests {
    use alloc::vec;

    use nexacore_display::output::OutputMode;

    use super::*;

    fn panel() -> DisplaySettingsPanel {
        let mut m = OutputManager::new();
        let a = Output::new(
            OutputId(1),
            "eDP-1".to_string(),
            vec![
                OutputMode::new(1920, 1080, 60_000),
                OutputMode::new(1280, 720, 60_000),
            ],
        )
        .unwrap();
        let b = Output::new(
            OutputId(2),
            "HDMI-A-1".to_string(),
            vec![OutputMode::new(1920, 1080, 60_000)],
        )
        .unwrap();
        m.connect(a).unwrap();
        m.connect(b).unwrap();
        m.auto_arrange_horizontal();
        DisplaySettingsPanel::new(m)
    }

    #[test]
    fn rows_expose_modes_and_primary() {
        let p = panel();
        let rows = p.rows();
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].name, "eDP-1");
        assert_eq!(rows[0].modes.len(), 2);
        assert!(rows[0].modes[0].is_active); // 1920x1080 preferred
        assert!(rows[0].is_primary); // at global origin
        assert!(!rows[1].is_primary);
    }

    #[test]
    fn set_scale_percent_updates_logical_size() {
        let mut p = panel();
        p.set_scale_percent(OutputId(1), 200).unwrap();
        let row = &p.rows()[0];
        assert_eq!(row.scale_percent, 200);
        assert_eq!(row.logical_size, (960, 540));
    }

    #[test]
    fn unsupported_scale_is_rejected() {
        let mut p = panel();
        // 0% is not a valid factor.
        assert_eq!(
            p.set_scale_percent(OutputId(1), 0),
            Err(PanelError::InvalidScale)
        );
    }

    #[test]
    fn rotation_round_trips_into_row() {
        let mut p = panel();
        p.set_rotation(OutputId(1), Rotation::Rotate90).unwrap();
        assert_eq!(p.rows()[0].rotation, Rotation::Rotate90);
        assert_eq!(p.rows()[0].logical_size, (1080, 1920));
    }

    #[test]
    fn overlap_fails_validation() {
        let mut p = panel();
        p.move_output(OutputId(2), 0, 0).unwrap(); // stack on top of output 1
        assert_eq!(p.validate(), Err(PanelError::OverlappingLayout));
    }

    #[test]
    fn disabling_all_fails_validation() {
        let mut p = panel();
        p.set_enabled(OutputId(1), false).unwrap();
        p.set_enabled(OutputId(2), false).unwrap();
        assert_eq!(p.validate(), Err(PanelError::NoEnabledOutput));
    }

    #[test]
    fn valid_extended_desktop_passes() {
        let p = panel();
        assert!(p.validate().is_ok());
    }

    #[test]
    fn unknown_output_edit_is_display_error() {
        let mut p = panel();
        assert_eq!(
            p.select_mode(OutputId(99), 0),
            Err(PanelError::Display(DisplayError::UnknownOutput(OutputId(
                99
            ))))
        );
    }
}
