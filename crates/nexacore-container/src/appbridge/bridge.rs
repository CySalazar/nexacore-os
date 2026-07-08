//! Compositor bridge — map guest windows onto NexaCore surfaces (WS9-03.3).
//!
//! The [`WindowBridge`] consumes [`super::agent::RegistryEvent`]s and drives a
//! [`CompositorSink`] so that each guest toplevel becomes exactly one NexaCore
//! compositor surface. `CompositorSink` is the **seam to WS7-01**: the real
//! implementation attaches to the live NexaCore compositor and samples the
//! guest `virtio-gpu` resource, but the bridge's mapping logic — clipping
//! ([`super::clip`]), placement, z-order, damage translation — is pure and
//! host-tested here against a recording sink.
//!
//! Because `nexacore-container` sits below `nexacore-display` in the crate graph
//! (and must not create a dependency cycle), the surface description
//! [`HostSurfaceDesc`] uses raw geometry/value fields mirroring the compositor's
//! scene-node shape rather than importing its types. The desktop layer binds
//! these to real compositor nodes.

use std::collections::BTreeMap;

use super::{
    AppBridgeError, AppBridgeResult, Point, Rect,
    agent::{GuestWindowRegistry, RegistryEvent, WindowId},
    clip::WindowClip,
};

/// Identifier of a host compositor surface, assigned by the [`CompositorSink`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SurfaceId(pub u64);

/// Description of a NexaCore compositor surface backed by a guest window.
///
/// The surface samples `source_rect` of the guest framebuffer resource
/// `source_resource` and paints it at `dest` on the host desktop.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostSurfaceDesc {
    /// `virtio-gpu` resource id of the guest framebuffer.
    pub source_resource: u32,
    /// The window's sub-rectangle within the guest framebuffer (post-clip).
    pub source_rect: Rect,
    /// Where the surface is painted on the host desktop.
    pub dest: Rect,
    /// Stacking index (0 = bottom); higher paints on top.
    pub z: u32,
    /// Toplevel title (for the host titlebar / switcher).
    pub title: String,
    /// Wayland `app_id`.
    pub app_id: String,
    /// Opacity in permille (`1000` = opaque).
    pub opacity_permille: u32,
}

/// The seam to the NexaCore compositor (WS7-01). The desktop layer implements
/// this over live compositor scene nodes; tests use a recording double.
pub trait CompositorSink {
    /// Create a surface for `desc`, returning its assigned id.
    fn create_surface(&mut self, desc: &HostSurfaceDesc) -> SurfaceId;
    /// Update an existing surface's geometry/metadata.
    fn update_surface(&mut self, id: SurfaceId, desc: &HostSurfaceDesc);
    /// Mark a region of a surface as damaged (surface-local coordinates).
    fn damage_surface(&mut self, id: SurfaceId, area: Rect);
    /// Raise a surface to the top of the stack.
    fn raise_surface(&mut self, id: SurfaceId);
    /// Destroy a surface.
    fn destroy_surface(&mut self, id: SurfaceId);
}

/// Maps the guest window set onto host compositor surfaces.
///
/// One container gets one bridge. Its `desktop_offset` places the container's
/// windows on the host desktop while preserving their relative arrangement in
/// the guest framebuffer.
#[derive(Debug, Clone)]
pub struct WindowBridge {
    clip: WindowClip,
    desktop_offset: Point,
    surfaces: BTreeMap<WindowId, SurfaceId>,
}

impl WindowBridge {
    /// A bridge that places guest windows at `desktop_offset` on the host
    /// desktop, using the default clip policy.
    #[must_use]
    pub fn new(desktop_offset: Point) -> Self {
        Self {
            clip: WindowClip::default(),
            desktop_offset,
            surfaces: BTreeMap::new(),
        }
    }

    /// Override the clip policy (e.g. a stricter desktop-in-desktop threshold).
    #[must_use]
    pub fn with_clip(mut self, clip: WindowClip) -> Self {
        self.clip = clip;
        self
    }

    /// The host surface backing a guest window, if mapped.
    #[must_use]
    pub fn surface_of(&self, id: WindowId) -> Option<SurfaceId> {
        self.surfaces.get(&id).copied()
    }

    /// Number of live host surfaces.
    #[must_use]
    pub fn surface_count(&self) -> usize {
        self.surfaces.len()
    }

    /// Apply one registry event, driving `sink` accordingly.
    ///
    /// `registry` must already reflect `event` (i.e. the caller applies the
    /// [`super::agent::GuestToHost`] to the registry, then hands the resulting
    /// event here). Reads the up-to-date window geometry from `registry`.
    ///
    /// # Errors
    ///
    /// - [`AppBridgeError::DesktopInDesktop`] if a mapped/moved window covers
    ///   the whole guest output (the surface is **not** created/updated).
    /// - [`AppBridgeError::UnknownWindow`] if an event references a window the
    ///   registry no longer holds.
    /// - [`AppBridgeError::Protocol`] if no guest output has been declared.
    pub fn sync<S: CompositorSink>(
        &mut self,
        sink: &mut S,
        registry: &GuestWindowRegistry,
        event: RegistryEvent,
    ) -> AppBridgeResult<()> {
        match event {
            RegistryEvent::OutputChanged(_) => {
                // Resolution/resource change: refresh every live surface's
                // source resource + clip against the new output.
                let ids: Vec<WindowId> = self.surfaces.keys().copied().collect();
                for id in ids {
                    self.refresh(sink, registry, id)?;
                }
                Ok(())
            }
            RegistryEvent::Mapped(id) => {
                let desc = self.describe(registry, id)?;
                let sid = sink.create_surface(&desc);
                self.surfaces.insert(id, sid);
                sink.raise_surface(sid);
                Ok(())
            }
            RegistryEvent::Moved(id) | RegistryEvent::Retitled(id) => {
                self.refresh(sink, registry, id)
            }
            RegistryEvent::Damaged(id, area) => {
                let sid = self
                    .surfaces
                    .get(&id)
                    .copied()
                    .ok_or(AppBridgeError::UnknownWindow(id.0))?;
                let desc = self.describe(registry, id)?;
                // Intersect the guest-fb damage with the window's source rect,
                // then translate to surface-local coordinates.
                if let Some(hit) = area.intersect(desc.source_rect) {
                    let local = Rect::new(
                        hit.x - desc.source_rect.x,
                        hit.y - desc.source_rect.y,
                        hit.w,
                        hit.h,
                    );
                    sink.damage_surface(sid, local);
                }
                Ok(())
            }
            RegistryEvent::Unmapped(id) => {
                if let Some(sid) = self.surfaces.remove(&id) {
                    sink.destroy_surface(sid);
                }
                Ok(())
            }
        }
    }

    /// Recompute a surface's description and push it to the sink.
    fn refresh<S: CompositorSink>(
        &self,
        sink: &mut S,
        registry: &GuestWindowRegistry,
        id: WindowId,
    ) -> AppBridgeResult<()> {
        let sid = self
            .surfaces
            .get(&id)
            .copied()
            .ok_or(AppBridgeError::UnknownWindow(id.0))?;
        let desc = self.describe(registry, id)?;
        sink.update_surface(sid, &desc);
        Ok(())
    }

    /// Build the host surface description for a live guest window.
    fn describe(
        &self,
        registry: &GuestWindowRegistry,
        id: WindowId,
    ) -> AppBridgeResult<HostSurfaceDesc> {
        let output = registry
            .output()
            .ok_or(AppBridgeError::Protocol("no guest output declared"))?;
        let win = registry
            .window(id)
            .ok_or(AppBridgeError::UnknownWindow(id.0))?;
        let source_rect = self.clip.compute(output.size, win.guest_rect)?;
        let dest = Rect::new(
            source_rect.x.saturating_add(self.desktop_offset.x),
            source_rect.y.saturating_add(self.desktop_offset.y),
            source_rect.w,
            source_rect.h,
        );
        let z = registry
            .stack_order()
            .iter()
            .position(|&w| w == id)
            .and_then(|p| u32::try_from(p).ok())
            .unwrap_or(0);
        Ok(HostSurfaceDesc {
            source_resource: output.resource_id,
            source_rect,
            dest,
            z,
            title: win.title.clone(),
            app_id: win.app_id.clone(),
            opacity_permille: 1000,
        })
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
    use super::{
        super::{
            Size,
            agent::{GuestOutput, GuestToHost, PixelFormat},
        },
        *,
    };

    /// A recording [`CompositorSink`] for host tests.
    #[derive(Debug, Default)]
    struct RecordingSink {
        next: u64,
        created: Vec<HostSurfaceDesc>,
        updated: Vec<(SurfaceId, HostSurfaceDesc)>,
        damaged: Vec<(SurfaceId, Rect)>,
        raised: Vec<SurfaceId>,
        destroyed: Vec<SurfaceId>,
    }

    impl CompositorSink for RecordingSink {
        fn create_surface(&mut self, desc: &HostSurfaceDesc) -> SurfaceId {
            self.next += 1;
            self.created.push(desc.clone());
            SurfaceId(self.next)
        }
        fn update_surface(&mut self, id: SurfaceId, desc: &HostSurfaceDesc) {
            self.updated.push((id, desc.clone()));
        }
        fn damage_surface(&mut self, id: SurfaceId, area: Rect) {
            self.damaged.push((id, area));
        }
        fn raise_surface(&mut self, id: SurfaceId) {
            self.raised.push(id);
        }
        fn destroy_surface(&mut self, id: SurfaceId) {
            self.destroyed.push(id);
        }
    }

    fn output() -> GuestOutput {
        GuestOutput {
            resource_id: 42,
            size: Size::new(1920, 1080),
            stride: 1920 * 4,
            format: PixelFormat::Xrgb8888,
        }
    }

    fn setup() -> (GuestWindowRegistry, WindowBridge, RecordingSink) {
        let mut reg = GuestWindowRegistry::new(8);
        reg.apply(GuestToHost::OutputChanged(output())).unwrap();
        let bridge = WindowBridge::new(Point::new(500, 200));
        (reg, bridge, RecordingSink::default())
    }

    fn map(reg: &mut GuestWindowRegistry, id: u64, rect: Rect) -> RegistryEvent {
        reg.apply(GuestToHost::WindowMapped {
            id: WindowId(id),
            guest_rect: rect,
            title: "t".into(),
            app_id: "a".into(),
        })
        .unwrap()
    }

    #[test]
    fn mapping_creates_offset_surface() {
        let (mut reg, mut bridge, mut sink) = setup();
        let ev = map(&mut reg, 1, Rect::new(100, 100, 400, 300));
        bridge.sync(&mut sink, &reg, ev).unwrap();
        assert_eq!(bridge.surface_count(), 1);
        assert_eq!(sink.created.len(), 1);
        let d = &sink.created[0];
        assert_eq!(d.source_resource, 42);
        assert_eq!(d.source_rect, Rect::new(100, 100, 400, 300));
        // Placed at desktop_offset (500,200).
        assert_eq!(d.dest, Rect::new(600, 300, 400, 300));
        assert_eq!(sink.raised.len(), 1);
    }

    #[test]
    fn fullscreen_window_creates_no_surface() {
        let (mut reg, mut bridge, mut sink) = setup();
        let ev = map(&mut reg, 1, Rect::new(0, 0, 1920, 1080));
        assert_eq!(
            bridge.sync(&mut sink, &reg, ev),
            Err(AppBridgeError::DesktopInDesktop)
        );
        assert_eq!(sink.created.len(), 0);
        assert_eq!(bridge.surface_count(), 0);
    }

    #[test]
    fn move_updates_surface_geometry() {
        let (mut reg, mut bridge, mut sink) = setup();
        let ev = map(&mut reg, 1, Rect::new(100, 100, 400, 300));
        bridge.sync(&mut sink, &reg, ev).unwrap();
        let mv = reg
            .apply(GuestToHost::WindowMoved {
                id: WindowId(1),
                guest_rect: Rect::new(150, 120, 400, 300),
            })
            .unwrap();
        bridge.sync(&mut sink, &reg, mv).unwrap();
        assert_eq!(sink.updated.len(), 1);
        assert_eq!(sink.updated[0].1.dest, Rect::new(650, 320, 400, 300));
    }

    #[test]
    fn damage_is_translated_to_surface_local() {
        let (mut reg, mut bridge, mut sink) = setup();
        let ev = map(&mut reg, 1, Rect::new(100, 100, 400, 300));
        bridge.sync(&mut sink, &reg, ev).unwrap();
        // Damage a 50x50 patch at guest (120,130) — inside the window.
        let dmg = reg
            .apply(GuestToHost::WindowDamaged {
                id: WindowId(1),
                area: Rect::new(120, 130, 50, 50),
            })
            .unwrap();
        bridge.sync(&mut sink, &reg, dmg).unwrap();
        assert_eq!(sink.damaged.len(), 1);
        // Surface-local = guest - window origin = (20,30).
        assert_eq!(sink.damaged[0].1, Rect::new(20, 30, 50, 50));
    }

    #[test]
    fn unmap_destroys_surface() {
        let (mut reg, mut bridge, mut sink) = setup();
        let ev = map(&mut reg, 1, Rect::new(100, 100, 400, 300));
        bridge.sync(&mut sink, &reg, ev).unwrap();
        let sid = bridge.surface_of(WindowId(1)).unwrap();
        let un = reg
            .apply(GuestToHost::WindowUnmapped { id: WindowId(1) })
            .unwrap();
        bridge.sync(&mut sink, &reg, un).unwrap();
        assert_eq!(sink.destroyed, vec![sid]);
        assert_eq!(bridge.surface_count(), 0);
    }
}
