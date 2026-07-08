//! Output/input device routing (WS2-10.11).
//!
//! The audio service tracks the available playback (output) and capture (input)
//! devices and which is the default for each direction. Routing is fail-closed:
//! with no device registered for a direction, `default` returns `None` and the
//! caller leaves the stream unrouted rather than guessing.

use alloc::vec::Vec;

/// Opaque audio device id.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct DeviceId(pub u32);

/// Audio data direction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AudioDirection {
    /// Playback (speakers / headphones).
    Output,
    /// Capture (microphone / line-in).
    Input,
}

/// Tracks registered devices and the default per direction.
#[derive(Debug, Default, Clone)]
pub struct AudioRouter {
    devices: Vec<(DeviceId, AudioDirection)>,
    default_output: Option<DeviceId>,
    default_input: Option<DeviceId>,
}

impl AudioRouter {
    /// An empty router.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a device in the given direction. The first device registered for
    /// a direction becomes its default.
    pub fn add_device(&mut self, id: DeviceId, direction: AudioDirection) {
        if !self
            .devices
            .iter()
            .any(|&(d, dir)| d == id && dir == direction)
        {
            self.devices.push((id, direction));
            match direction {
                AudioDirection::Output if self.default_output.is_none() => {
                    self.default_output = Some(id);
                }
                AudioDirection::Input if self.default_input.is_none() => {
                    self.default_input = Some(id);
                }
                _ => {}
            }
        }
    }

    /// Devices registered for `direction`.
    #[must_use]
    pub fn devices(&self, direction: AudioDirection) -> Vec<DeviceId> {
        self.devices
            .iter()
            .filter(|&&(_, dir)| dir == direction)
            .map(|&(d, _)| d)
            .collect()
    }

    /// Set the default device for `direction`. Returns `false` (no change) if
    /// the device is not registered in that direction — a stream is never routed
    /// to a device that was never enumerated.
    pub fn set_default(&mut self, id: DeviceId, direction: AudioDirection) -> bool {
        if !self
            .devices
            .iter()
            .any(|&(d, dir)| d == id && dir == direction)
        {
            return false;
        }
        match direction {
            AudioDirection::Output => self.default_output = Some(id),
            AudioDirection::Input => self.default_input = Some(id),
        }
        true
    }

    /// The default device for `direction`, or `None` if none is registered.
    #[must_use]
    pub fn default_device(&self, direction: AudioDirection) -> Option<DeviceId> {
        match direction {
            AudioDirection::Output => self.default_output,
            AudioDirection::Input => self.default_input,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_router_routes_nothing() {
        let r = AudioRouter::new();
        assert_eq!(r.default_device(AudioDirection::Output), None);
        assert_eq!(r.default_device(AudioDirection::Input), None);
    }

    #[test]
    fn first_device_becomes_default() {
        let mut r = AudioRouter::new();
        r.add_device(DeviceId(1), AudioDirection::Output);
        r.add_device(DeviceId(2), AudioDirection::Output);
        assert_eq!(r.default_device(AudioDirection::Output), Some(DeviceId(1)));
        assert_eq!(r.devices(AudioDirection::Output).len(), 2);
    }

    #[test]
    fn set_default_requires_registration() {
        let mut r = AudioRouter::new();
        r.add_device(DeviceId(1), AudioDirection::Output);
        // Switching to an unregistered device is refused (fail-closed).
        assert!(!r.set_default(DeviceId(9), AudioDirection::Output));
        assert_eq!(r.default_device(AudioDirection::Output), Some(DeviceId(1)));
        // Switching to a registered one works.
        r.add_device(DeviceId(2), AudioDirection::Output);
        assert!(r.set_default(DeviceId(2), AudioDirection::Output));
        assert_eq!(r.default_device(AudioDirection::Output), Some(DeviceId(2)));
    }

    #[test]
    fn directions_are_independent() {
        let mut r = AudioRouter::new();
        r.add_device(DeviceId(1), AudioDirection::Output);
        r.add_device(DeviceId(2), AudioDirection::Input);
        assert_eq!(r.default_device(AudioDirection::Output), Some(DeviceId(1)));
        assert_eq!(r.default_device(AudioDirection::Input), Some(DeviceId(2)));
    }
}
