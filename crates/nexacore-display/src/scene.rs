//! Compositor scene-graph with per-node damage tracking (WS7-01.3).
//!
//! The compositor models the desktop as a tree of [`SceneNode`]s: the root is
//! the screen, children are windows, and their children are sub-surfaces
//! (toolbars, popovers, …). Every node carries a screen-space [`Rect`], a
//! visibility flag and an opacity, and remembers whether it changed since the
//! last frame.
//!
//! Damage is *per node*: mutating a node records the affected screen rect(s) so
//! [`SceneGraph::collect_damage`] returns only the regions that must repaint —
//! moving a window damages its old and new positions, never the whole screen.
//! This is the front half of the damage-driven pipeline; the back half (writing
//! only those rects) is [`crate::compositor`] / [`crate::render_backend`].
//!
//! The tree is an arena ([`Vec<SceneNode>`] indexed by [`NodeId`]) so it stays
//! `no_std + alloc` and needs no reference counting. Nodes are never removed
//! from the arena (ids stay stable); [`SceneGraph::set_visible`] hides a subtree
//! instead.

#![allow(
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::integer_division
)]

use alloc::{vec, vec::Vec};

use crate::geometry::{DamageRegion, Rect};

/// Stable handle into a [`SceneGraph`]'s node arena.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct NodeId(pub u32);

/// One node in the compositor scene-graph.
#[derive(Debug, Clone)]
pub struct SceneNode {
    /// Screen-space bounds of the node's surface.
    pub bounds: Rect,
    /// When `false`, the node and its subtree are not composited.
    pub visible: bool,
    /// Per-node opacity (`255` = opaque). Drives cross-fades (WS7-01.9).
    pub opacity: u8,
    parent: Option<NodeId>,
    children: Vec<NodeId>,
    dirty: bool,
}

impl SceneNode {
    /// The node's parent, or `None` for the root.
    #[must_use]
    pub const fn parent(&self) -> Option<NodeId> {
        self.parent
    }

    /// The node's direct children, in back-to-front order.
    #[must_use]
    pub fn children(&self) -> &[NodeId] {
        &self.children
    }

    /// `true` when the node changed since the last [`SceneGraph::clear_damage`].
    #[must_use]
    pub const fn is_dirty(&self) -> bool {
        self.dirty
    }
}

/// An arena-backed scene-graph rooted at the screen rectangle.
#[derive(Debug, Clone)]
pub struct SceneGraph {
    nodes: Vec<SceneNode>,
    root: NodeId,
    screen: Rect,
    damage: DamageRegion,
}

impl SceneGraph {
    /// Create a scene-graph whose root covers `screen`.
    #[must_use]
    pub fn new(screen: Rect) -> Self {
        let root = SceneNode {
            bounds: screen,
            visible: true,
            opacity: 255,
            parent: None,
            children: Vec::new(),
            dirty: false,
        };
        Self {
            nodes: vec![root],
            root: NodeId(0),
            screen,
            damage: DamageRegion::new(),
        }
    }

    /// The root node id (the screen).
    #[must_use]
    pub const fn root(&self) -> NodeId {
        self.root
    }

    /// Borrow a node, or `None` if the id is stale/out of range.
    #[must_use]
    pub fn node(&self, id: NodeId) -> Option<&SceneNode> {
        self.nodes.get(id.0 as usize)
    }

    /// Number of nodes in the arena (including the root).
    #[must_use]
    pub fn len(&self) -> usize {
        self.nodes.len()
    }

    /// `true` if the graph has only the root.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.nodes.len() <= 1
    }

    /// Add a child of `parent` with screen-space `bounds`, returning its id.
    /// The new node starts visible, opaque and dirty (it must paint once). A
    /// stale `parent` id appends to the root.
    pub fn add_child(&mut self, parent: NodeId, bounds: Rect) -> NodeId {
        let id = NodeId(self.nodes.len() as u32);
        let parent = if (parent.0 as usize) < self.nodes.len() {
            parent
        } else {
            self.root
        };
        self.nodes.push(SceneNode {
            bounds,
            visible: true,
            opacity: 255,
            parent: Some(parent),
            children: Vec::new(),
            dirty: true,
        });
        if let Some(p) = self.nodes.get_mut(parent.0 as usize) {
            p.children.push(id);
        }
        self.damage_rect(bounds);
        id
    }

    /// Move/resize a node. Damages both the old and the new screen rect so the
    /// vacated area repaints (WS7-01.3). No-op on a stale id.
    pub fn set_bounds(&mut self, id: NodeId, bounds: Rect) {
        let old = match self.nodes.get(id.0 as usize) {
            Some(n) => n.bounds,
            None => return,
        };
        if old == bounds {
            return;
        }
        if let Some(n) = self.nodes.get_mut(id.0 as usize) {
            n.bounds = bounds;
            n.dirty = true;
        }
        self.damage_rect(old);
        self.damage_rect(bounds);
    }

    /// Show or hide a node's subtree, damaging its bounds.
    pub fn set_visible(&mut self, id: NodeId, visible: bool) {
        let bounds = match self.nodes.get_mut(id.0 as usize) {
            Some(n) if n.visible != visible => {
                n.visible = visible;
                n.dirty = true;
                n.bounds
            }
            _ => return,
        };
        self.damage_rect(bounds);
    }

    /// Set a node's opacity, damaging its bounds (cross-fades repaint).
    pub fn set_opacity(&mut self, id: NodeId, opacity: u8) {
        let bounds = match self.nodes.get_mut(id.0 as usize) {
            Some(n) if n.opacity != opacity => {
                n.opacity = opacity;
                n.dirty = true;
                n.bounds
            }
            _ => return,
        };
        self.damage_rect(bounds);
    }

    /// Mark a node's content dirty (e.g. its surface contents changed) without
    /// moving it.
    pub fn mark_dirty(&mut self, id: NodeId) {
        let bounds = match self.nodes.get_mut(id.0 as usize) {
            Some(n) => {
                n.dirty = true;
                n.bounds
            }
            None => return,
        };
        self.damage_rect(bounds);
    }

    /// The accumulated damage since the last [`Self::clear_damage`], clamped to
    /// the screen.
    #[must_use]
    pub fn damage(&self) -> &DamageRegion {
        &self.damage
    }

    /// Collect the screen-space damage rects to repaint this frame.
    #[must_use]
    pub fn collect_damage(&self) -> Vec<Rect> {
        self.damage.iter().copied().collect()
    }

    /// `true` if any node changed since the last [`Self::clear_damage`].
    #[must_use]
    pub fn has_damage(&self) -> bool {
        !self.damage.is_empty()
    }

    /// Clear all damage and per-node dirty flags after the frame is presented.
    pub fn clear_damage(&mut self) {
        self.damage.clear();
        for n in &mut self.nodes {
            n.dirty = false;
        }
    }

    /// Visit visible nodes back-to-front (a stable painter's-order traversal),
    /// calling `f(id, node, effective_opacity)`. A node whose ancestor is hidden
    /// is skipped; opacity multiplies down the tree.
    pub fn visit_paint_order(&self, mut f: impl FnMut(NodeId, &SceneNode, u8)) {
        self.visit_from(self.root, 255, &mut f);
    }

    fn visit_from(
        &self,
        id: NodeId,
        parent_opacity: u8,
        f: &mut impl FnMut(NodeId, &SceneNode, u8),
    ) {
        let Some(node) = self.nodes.get(id.0 as usize) else {
            return;
        };
        if !node.visible {
            return;
        }
        // Effective opacity = parent * self, in 0..=255 (rounded).
        let eff = ((u32::from(parent_opacity) * u32::from(node.opacity) + 127) / 255) as u8;
        f(id, node, eff);
        for &child in &node.children {
            self.visit_from(child, eff, f);
        }
    }

    fn damage_rect(&mut self, r: Rect) {
        if let Some(clipped) = r.clamp_to(&self.screen) {
            self.damage.add(clipped);
        }
    }
}

#[cfg(test)]
#[allow(clippy::integer_division)]
mod tests {
    use super::*;

    fn screen() -> Rect {
        Rect {
            x: 0,
            y: 0,
            w: 1920,
            h: 1080,
        }
    }

    #[test]
    fn new_graph_has_root_and_no_damage() {
        let g = SceneGraph::new(screen());
        assert_eq!(g.len(), 1);
        assert!(g.is_empty());
        assert!(!g.has_damage());
        assert_eq!(g.node(g.root()).unwrap().bounds, screen());
    }

    #[test]
    fn add_child_damages_its_bounds() {
        let mut g = SceneGraph::new(screen());
        let w = g.add_child(
            g.root(),
            Rect {
                x: 100,
                y: 100,
                w: 400,
                h: 300,
            },
        );
        assert_eq!(g.len(), 2);
        assert!(g.has_damage());
        assert_eq!(g.node(w).unwrap().parent(), Some(g.root()));
        assert!(g.node(w).unwrap().is_dirty());
        let dmg = g.collect_damage();
        assert!(dmg.iter().any(|r| r.contains_point(150, 150)));
    }

    #[test]
    fn move_damages_old_and_new_only_not_whole_screen() {
        let mut g = SceneGraph::new(screen());
        let w = g.add_child(
            g.root(),
            Rect {
                x: 0,
                y: 0,
                w: 200,
                h: 200,
            },
        );
        g.clear_damage();
        assert!(!g.has_damage());
        g.set_bounds(
            w,
            Rect {
                x: 800,
                y: 800,
                w: 200,
                h: 200,
            },
        );
        let dmg = g.collect_damage();
        // Old position and new position are dirty…
        assert!(dmg.iter().any(|r| r.contains_point(50, 50)), "old region");
        assert!(dmg.iter().any(|r| r.contains_point(850, 850)), "new region");
        // …but the middle of the screen between them is NOT damaged.
        assert!(
            !dmg.iter().any(|r| r.contains_point(500, 500)),
            "incremental damage must not cover untouched area"
        );
    }

    #[test]
    fn clear_damage_resets_dirty_flags() {
        let mut g = SceneGraph::new(screen());
        let w = g.add_child(g.root(), screen());
        g.clear_damage();
        assert!(!g.has_damage());
        assert!(!g.node(w).unwrap().is_dirty());
    }

    #[test]
    fn hidden_node_is_skipped_in_paint_order() {
        let mut g = SceneGraph::new(screen());
        let a = g.add_child(g.root(), screen());
        let _b = g.add_child(a, screen());
        g.set_visible(a, false);
        let mut painted = Vec::new();
        g.visit_paint_order(|id, _, _| painted.push(id));
        // Root paints, but the hidden subtree (a and its child b) does not.
        assert!(painted.contains(&g.root()));
        assert!(!painted.contains(&a));
    }

    #[test]
    fn opacity_multiplies_down_the_tree() {
        let mut g = SceneGraph::new(screen());
        let a = g.add_child(g.root(), screen());
        let b = g.add_child(a, screen());
        g.set_opacity(a, 128);
        g.set_opacity(b, 128);
        let mut eff_b = 255u8;
        g.visit_paint_order(|id, _, eff| {
            if id == b {
                eff_b = eff;
            }
        });
        // 128/255 * 128/255 ≈ 0.25 → ~64.
        assert!((60..=68).contains(&eff_b), "got {eff_b}");
    }

    #[test]
    fn stale_id_is_ignored() {
        let mut g = SceneGraph::new(screen());
        g.set_bounds(NodeId(999), screen()); // no panic
        assert!(!g.has_damage());
        assert!(g.node(NodeId(999)).is_none());
    }
}
