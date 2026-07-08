//! Guest agent window protocol and the host-side window registry (WS9-03.2).
//!
//! PID 1 of the guest image ([`super::image`]) is the **guest agent**: it runs
//! a headless Wayland compositor, and reports each toplevel window's lifecycle
//! and geometry to the host over a `virtio-vsock` control channel. The guest
//! renders every window into a single guest framebuffer exported over
//! `virtio-gpu`; a window's [`GuestWindow::guest_rect`] is its position *within
//! that framebuffer*.
//!
//! This module defines the two message directions ([`GuestToHost`],
//! [`HostToGuest`]) with a canonical wire codec, and the host-side
//! [`GuestWindowRegistry`] state machine that folds guest reports into a
//! validated view of the guest's windows. The registry is **fail-closed**: a
//! report referencing an unknown window, or one that would exceed the window
//! limit, is rejected rather than silently applied.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use super::{AppBridgeError, AppBridgeResult, Rect, Size};

/// Identifier of a guest toplevel window, assigned by the guest agent.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct WindowId(pub u64);

/// Pixel format of the guest framebuffer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum PixelFormat {
    /// 32-bit `A8R8G8B8`, alpha in the high byte.
    Argb8888,
    /// 32-bit `X8R8G8B8`, ignored high byte.
    Xrgb8888,
    /// 32-bit `A8B8G8R8`.
    Abgr8888,
    /// 32-bit `X8B8G8R8`.
    Xbgr8888,
}

impl PixelFormat {
    /// Bytes per pixel for this format.
    ///
    /// Every currently-supported format is 32 bpp; the method takes `self` so
    /// the API stays stable when packed/10-bit formats are added.
    #[must_use]
    #[allow(clippy::unused_self)]
    pub const fn bytes_per_pixel(self) -> u32 {
        4
    }
}

/// The guest's single exported framebuffer (the headless compositor output).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct GuestOutput {
    /// `virtio-gpu` resource id backing the guest framebuffer.
    pub resource_id: u32,
    /// Framebuffer extent in pixels.
    pub size: Size,
    /// Row stride in bytes.
    pub stride: u32,
    /// Pixel format.
    pub format: PixelFormat,
}

/// A window reported by the guest agent, tracked on the host.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GuestWindow {
    /// The guest-assigned id.
    pub id: WindowId,
    /// The window's rectangle **within the guest framebuffer**.
    pub guest_rect: Rect,
    /// Toplevel title (for the host titlebar / task switcher).
    pub title: String,
    /// Application id (Wayland `app_id`, for grouping / icons).
    pub app_id: String,
}

/// Messages the guest agent sends to the host (guest → host).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum GuestToHost {
    /// The exported framebuffer changed (first frame, resolution change, or
    /// resource re-allocation).
    OutputChanged(GuestOutput),
    /// A new toplevel window was mapped.
    WindowMapped {
        /// Window id.
        id: WindowId,
        /// Rectangle within the guest framebuffer.
        guest_rect: Rect,
        /// Toplevel title.
        title: String,
        /// Wayland `app_id`.
        app_id: String,
    },
    /// An existing window was moved or resized within the guest framebuffer.
    WindowMoved {
        /// Window id.
        id: WindowId,
        /// New rectangle within the guest framebuffer.
        guest_rect: Rect,
    },
    /// A window's title changed.
    WindowTitle {
        /// Window id.
        id: WindowId,
        /// New title.
        title: String,
    },
    /// A region of a window was repainted (damage, in guest-framebuffer coords).
    WindowDamaged {
        /// Window id.
        id: WindowId,
        /// Damaged area within the guest framebuffer.
        area: Rect,
    },
    /// A window was unmapped/destroyed.
    WindowUnmapped {
        /// Window id.
        id: WindowId,
    },
}

/// Messages the host sends to the guest agent (host → guest).
///
/// Coordinates in pointer events are **guest-window-local** (origin at the
/// window's top-left), already translated by [`super::input::InputRouter`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum HostToGuest {
    /// Pointer moved to a window-local position.
    PointerMotion {
        /// Target window.
        id: WindowId,
        /// Window-local X.
        x: i32,
        /// Window-local Y.
        y: i32,
    },
    /// A pointer button changed state.
    PointerButton {
        /// Target window.
        id: WindowId,
        /// Linux input button code (e.g. `0x110` = `BTN_LEFT`).
        button: u32,
        /// Whether the button is now pressed.
        pressed: bool,
    },
    /// A discrete scroll step.
    PointerScroll {
        /// Target window.
        id: WindowId,
        /// Horizontal steps.
        dx: i32,
        /// Vertical steps.
        dy: i32,
    },
    /// A key changed state (evdev keycode).
    Key {
        /// Target (focused) window.
        id: WindowId,
        /// evdev keycode.
        keycode: u32,
        /// Whether the key is now pressed.
        pressed: bool,
    },
    /// Keyboard focus entered or left a window.
    Focus {
        /// Target window.
        id: WindowId,
        /// Whether the window now holds focus.
        focused: bool,
    },
    /// The host asked the window to close (e.g. titlebar close button).
    CloseRequest {
        /// Target window.
        id: WindowId,
    },
}

impl GuestToHost {
    /// Encode to the canonical wire form.
    ///
    /// # Errors
    ///
    /// Returns a [`nexacore_types::NexaCoreError`] on encoding failure.
    pub fn to_wire(&self) -> nexacore_types::Result<Vec<u8>> {
        nexacore_types::wire::encode_canonical(self)
    }

    /// Decode from the canonical wire form.
    ///
    /// # Errors
    ///
    /// Returns a [`nexacore_types::NexaCoreError`] if the bytes are malformed.
    pub fn from_wire(bytes: &[u8]) -> nexacore_types::Result<Self> {
        nexacore_types::wire::decode_canonical(bytes)
    }
}

impl HostToGuest {
    /// Encode to the canonical wire form.
    ///
    /// # Errors
    ///
    /// Returns a [`nexacore_types::NexaCoreError`] on encoding failure.
    pub fn to_wire(&self) -> nexacore_types::Result<Vec<u8>> {
        nexacore_types::wire::encode_canonical(self)
    }

    /// Decode from the canonical wire form.
    ///
    /// # Errors
    ///
    /// Returns a [`nexacore_types::NexaCoreError`] if the bytes are malformed.
    pub fn from_wire(bytes: &[u8]) -> nexacore_types::Result<Self> {
        nexacore_types::wire::decode_canonical(bytes)
    }
}

/// What changed in the registry as a result of applying a [`GuestToHost`].
///
/// The [`super::bridge::WindowBridge`] and [`super::input::InputRouter`] consume
/// these to keep host surfaces and focus in sync without re-scanning the whole
/// registry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegistryEvent {
    /// The guest framebuffer was (re)declared.
    OutputChanged(GuestOutput),
    /// A new window was mapped.
    Mapped(WindowId),
    /// A window's geometry changed.
    Moved(WindowId),
    /// A window's title changed.
    Retitled(WindowId),
    /// A window was damaged in the given area.
    Damaged(WindowId, Rect),
    /// A window was unmapped.
    Unmapped(WindowId),
}

/// Host-side registry of the guest's windows, driven by [`GuestToHost`] reports.
///
/// Maintains the current [`GuestOutput`], the set of live windows, and their
/// bottom-to-top stacking order (newest mapped window on top). All mutations go
/// through [`GuestWindowRegistry::apply`], which validates against the crate's
/// fail-closed invariants.
#[derive(Debug, Clone)]
pub struct GuestWindowRegistry {
    output: Option<GuestOutput>,
    windows: BTreeMap<WindowId, GuestWindow>,
    /// Bottom-to-top stacking order.
    stack: Vec<WindowId>,
    max_windows: usize,
}

impl GuestWindowRegistry {
    /// A new registry admitting at most `max_windows` concurrent windows.
    #[must_use]
    pub fn new(max_windows: usize) -> Self {
        Self {
            output: None,
            windows: BTreeMap::new(),
            stack: Vec::new(),
            max_windows,
        }
    }

    /// The current guest framebuffer, if declared.
    #[must_use]
    pub fn output(&self) -> Option<GuestOutput> {
        self.output
    }

    /// A window by id.
    #[must_use]
    pub fn window(&self, id: WindowId) -> Option<&GuestWindow> {
        self.windows.get(&id)
    }

    /// Number of live windows.
    #[must_use]
    pub fn len(&self) -> usize {
        self.windows.len()
    }

    /// Whether there are no live windows.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.windows.is_empty()
    }

    /// Window ids in bottom-to-top stacking order.
    #[must_use]
    pub fn stack_order(&self) -> &[WindowId] {
        &self.stack
    }

    /// Fold a guest report into the registry.
    ///
    /// # Errors
    ///
    /// - [`AppBridgeError::TooManyWindows`] if a `WindowMapped` would exceed the
    ///   limit, or maps an id that is already live.
    /// - [`AppBridgeError::UnknownWindow`] if a move/title/damage/unmap names an
    ///   id that is not live.
    /// - [`AppBridgeError::Protocol`] if a window is reported before any
    ///   [`GuestToHost::OutputChanged`], or a geometry escapes the framebuffer.
    pub fn apply(&mut self, msg: GuestToHost) -> AppBridgeResult<RegistryEvent> {
        match msg {
            GuestToHost::OutputChanged(out) => {
                if out.size.is_empty() {
                    return Err(AppBridgeError::Protocol("output has zero extent"));
                }
                self.output = Some(out);
                Ok(RegistryEvent::OutputChanged(out))
            }
            GuestToHost::WindowMapped {
                id,
                guest_rect,
                title,
                app_id,
            } => {
                let out = self.require_output()?;
                Self::check_within_output(guest_rect, out)?;
                if self.windows.contains_key(&id) {
                    return Err(AppBridgeError::Protocol("remap of live window id"));
                }
                if self.windows.len() >= self.max_windows {
                    return Err(AppBridgeError::TooManyWindows);
                }
                self.windows.insert(
                    id,
                    GuestWindow {
                        id,
                        guest_rect,
                        title,
                        app_id,
                    },
                );
                self.stack.push(id);
                Ok(RegistryEvent::Mapped(id))
            }
            GuestToHost::WindowMoved { id, guest_rect } => {
                let out = self.require_output()?;
                Self::check_within_output(guest_rect, out)?;
                let w = self
                    .windows
                    .get_mut(&id)
                    .ok_or(AppBridgeError::UnknownWindow(id.0))?;
                w.guest_rect = guest_rect;
                Ok(RegistryEvent::Moved(id))
            }
            GuestToHost::WindowTitle { id, title } => {
                let w = self
                    .windows
                    .get_mut(&id)
                    .ok_or(AppBridgeError::UnknownWindow(id.0))?;
                w.title = title;
                Ok(RegistryEvent::Retitled(id))
            }
            GuestToHost::WindowDamaged { id, area } => {
                if !self.windows.contains_key(&id) {
                    return Err(AppBridgeError::UnknownWindow(id.0));
                }
                Ok(RegistryEvent::Damaged(id, area))
            }
            GuestToHost::WindowUnmapped { id } => {
                if self.windows.remove(&id).is_none() {
                    return Err(AppBridgeError::UnknownWindow(id.0));
                }
                self.stack.retain(|&s| s != id);
                Ok(RegistryEvent::Unmapped(id))
            }
        }
    }

    /// Raise a window to the top of the stack (e.g. on focus/click). Returns
    /// whether the window exists.
    pub fn raise(&mut self, id: WindowId) -> bool {
        if !self.windows.contains_key(&id) {
            return false;
        }
        self.stack.retain(|&s| s != id);
        self.stack.push(id);
        true
    }

    fn require_output(&self) -> AppBridgeResult<GuestOutput> {
        self.output
            .ok_or(AppBridgeError::Protocol("window reported before output"))
    }

    fn check_within_output(rect: Rect, out: GuestOutput) -> AppBridgeResult<()> {
        if rect.is_empty() {
            return Err(AppBridgeError::Protocol("window has zero extent"));
        }
        let output_rect = Rect::new(0, 0, out.size.w, out.size.h);
        if !rect.is_within(output_rect) {
            return Err(AppBridgeError::Protocol("window escapes framebuffer"));
        }
        Ok(())
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

    fn output() -> GuestOutput {
        GuestOutput {
            resource_id: 7,
            size: Size::new(1920, 1080),
            stride: 1920 * 4,
            format: PixelFormat::Xrgb8888,
        }
    }

    fn map(id: u64, rect: Rect) -> GuestToHost {
        GuestToHost::WindowMapped {
            id: WindowId(id),
            guest_rect: rect,
            title: "app".into(),
            app_id: "org.example.App".into(),
        }
    }

    #[test]
    fn window_before_output_is_protocol_error() {
        let mut r = GuestWindowRegistry::new(8);
        assert_eq!(
            r.apply(map(1, Rect::new(0, 0, 100, 100))),
            Err(AppBridgeError::Protocol("window reported before output"))
        );
    }

    #[test]
    fn map_move_unmap_lifecycle() {
        let mut r = GuestWindowRegistry::new(8);
        r.apply(GuestToHost::OutputChanged(output())).unwrap();
        assert_eq!(
            r.apply(map(1, Rect::new(10, 10, 200, 150))).unwrap(),
            RegistryEvent::Mapped(WindowId(1))
        );
        assert_eq!(r.len(), 1);
        assert_eq!(
            r.apply(GuestToHost::WindowMoved {
                id: WindowId(1),
                guest_rect: Rect::new(20, 20, 200, 150),
            })
            .unwrap(),
            RegistryEvent::Moved(WindowId(1))
        );
        assert_eq!(
            r.window(WindowId(1)).unwrap().guest_rect,
            Rect::new(20, 20, 200, 150)
        );
        assert_eq!(
            r.apply(GuestToHost::WindowUnmapped { id: WindowId(1) })
                .unwrap(),
            RegistryEvent::Unmapped(WindowId(1))
        );
        assert!(r.is_empty());
    }

    #[test]
    fn move_unknown_window_is_rejected() {
        let mut r = GuestWindowRegistry::new(8);
        r.apply(GuestToHost::OutputChanged(output())).unwrap();
        assert_eq!(
            r.apply(GuestToHost::WindowMoved {
                id: WindowId(99),
                guest_rect: Rect::new(0, 0, 10, 10),
            }),
            Err(AppBridgeError::UnknownWindow(99))
        );
    }

    #[test]
    fn window_limit_is_enforced() {
        let mut r = GuestWindowRegistry::new(2);
        r.apply(GuestToHost::OutputChanged(output())).unwrap();
        r.apply(map(1, Rect::new(0, 0, 10, 10))).unwrap();
        r.apply(map(2, Rect::new(0, 0, 10, 10))).unwrap();
        assert_eq!(
            r.apply(map(3, Rect::new(0, 0, 10, 10))),
            Err(AppBridgeError::TooManyWindows)
        );
    }

    #[test]
    fn geometry_escaping_framebuffer_is_rejected() {
        let mut r = GuestWindowRegistry::new(8);
        r.apply(GuestToHost::OutputChanged(output())).unwrap();
        assert_eq!(
            r.apply(map(1, Rect::new(1900, 0, 100, 100))),
            Err(AppBridgeError::Protocol("window escapes framebuffer"))
        );
    }

    #[test]
    fn raise_reorders_stack() {
        let mut r = GuestWindowRegistry::new(8);
        r.apply(GuestToHost::OutputChanged(output())).unwrap();
        r.apply(map(1, Rect::new(0, 0, 10, 10))).unwrap();
        r.apply(map(2, Rect::new(0, 0, 10, 10))).unwrap();
        assert_eq!(r.stack_order(), &[WindowId(1), WindowId(2)]);
        assert!(r.raise(WindowId(1)));
        assert_eq!(r.stack_order(), &[WindowId(2), WindowId(1)]);
    }

    #[test]
    fn messages_round_trip_on_the_wire() {
        let g = map(5, Rect::new(1, 2, 3, 4));
        assert_eq!(GuestToHost::from_wire(&g.to_wire().unwrap()).unwrap(), g);
        let h = HostToGuest::Key {
            id: WindowId(5),
            keycode: 30,
            pressed: true,
        };
        assert_eq!(HostToGuest::from_wire(&h.to_wire().unwrap()).unwrap(), h);
    }
}
