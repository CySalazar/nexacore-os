//! Retained widget tree: measure → layout → render → hit-test.
//!
//! # Widget model (ADR-0042 D4)
//!
//! The tree is a recursive `enum Widget` with five leaf/internal variants.
//! The four-step pipeline is:
//!
//! 1. **`measure`** — compute the intrinsic [`Size`] from content + theme.
//! 2. **`layout`** — assign concrete [`Rect`]s to `self` and all descendants.
//! 3. **`render`** — paint into a [`Canvas`] reading colours from [`Theme`].
//! 4. **`dispatch_click`** — return the [`WidgetId`] of the deepest interactive
//!    widget whose laid-out rect contains the point.
//!
//! Layout is **pure**: calling `layout(bounds, theme)` on the same tree with
//! the same arguments always produces the same rects — no randomness, no I/O.
//!
//! ## Interactive vs. pass-through widgets
//!
//! | Variant | Interactive | `dispatch_click` returns id |
//! |---------|-------------|------------------------------|
//! | `Label` | no | `None` |
//! | `Button` | yes | `Some(id)` |
//! | `TextInput` | yes | `Some(id)` |
//! | `List` | no | `None` |
//! | `Container` | no (pass-through) | delegates to children |
//!
//! ## `no_std` note
//!
//! Widget text is stored as `alloc::string::String`; item lists as
//! `alloc::vec::Vec<String>`.  No `std` API is required.
//!
//! ## Example
//!
//! ```
//! use nexacore_display::geometry::Rect;
//! use nexacore_ui::{
//!     layout::Direction,
//!     theme::Theme,
//!     widget::{Widget, WidgetId},
//! };
//!
//! let theme = Theme::nexacore();
//! let mut root = Widget::Container {
//!     direction: Direction::Vertical,
//!     children: vec![Widget::Label {
//!         text: String::from("Hello"),
//!         rect: Rect {
//!             x: 0,
//!             y: 0,
//!             w: 0,
//!             h: 0,
//!         },
//!     }],
//!     rect: Rect {
//!         x: 0,
//!         y: 0,
//!         w: 0,
//!         h: 0,
//!     },
//! };
//! root.layout(
//!     Rect {
//!         x: 0,
//!         y: 0,
//!         w: 300,
//!         h: 200,
//!     },
//!     &theme,
//! );
//! let r = root.rect();
//! assert_eq!(r.x, 0);
//! assert_eq!(r.y, 0);
//! ```

extern crate alloc;

use alloc::{string::String, vec::Vec};

use nexacore_display::geometry::Rect;

use crate::{
    canvas::Canvas,
    layout::{Direction, Size},
    text::{GLYPH_H, GLYPH_W, draw_text, measure_text},
    theme::Theme,
};

// ---------------------------------------------------------------------------
// WidgetId
// ---------------------------------------------------------------------------

/// A caller-assigned identifier for an interactive widget.
///
/// The application maps each id to an action handler.  The `nexacore-ui` core
/// never generates ids; it only echoes them back through [`Widget::dispatch_click`].
///
/// Ids are intentionally plain `u32` wrappers so they are `Copy`, `Eq`, `Ord`,
/// `Hash`, and `no_std`-clean without any allocation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct WidgetId(pub u32);

// ---------------------------------------------------------------------------
// Widget
// ---------------------------------------------------------------------------

/// A node in the retained widget tree.
///
/// Each variant stores its laid-out `Rect` (populated by [`Widget::layout`]).
/// Before the first `layout` call the rect is zero (the default supplied by
/// the caller at construction time).
#[derive(Debug, Clone)]
pub enum Widget {
    /// A non-interactive text label.
    Label {
        /// The displayed text (UTF-8; measured by codepoint count).
        text: String,
        /// Laid-out rectangle — set by [`Widget::layout`].
        rect: Rect,
    },

    /// A clickable push button.
    Button {
        /// Stable caller-assigned id returned by [`Widget::dispatch_click`].
        id: WidgetId,
        /// The button label text.
        text: String,
        /// Laid-out rectangle — set by [`Widget::layout`].
        rect: Rect,
    },

    /// A single-line text input field.
    TextInput {
        /// Stable caller-assigned id returned by [`Widget::dispatch_click`].
        id: WidgetId,
        /// The current text content.
        text: String,
        /// Cursor byte-index position within `text`.
        cursor: usize,
        /// Laid-out rectangle — set by [`Widget::layout`].
        rect: Rect,
    },

    /// A vertical list of read-only text items.
    List {
        /// Ordered list of item strings.
        items: Vec<String>,
        /// Laid-out rectangle — set by [`Widget::layout`].
        rect: Rect,
    },

    /// A layout container that stacks children along a [`Direction`].
    Container {
        /// The stacking axis.
        direction: Direction,
        /// Ordered child widgets.
        children: Vec<Widget>,
        /// Laid-out rectangle — set by [`Widget::layout`].
        rect: Rect,
    },
}

impl Widget {
    /// Returns the laid-out [`Rect`] for this widget.
    ///
    /// Before [`Widget::layout`] is called the rect has the value supplied at
    /// construction time (typically a zero rect).
    ///
    /// # Example
    ///
    /// ```
    /// use nexacore_display::geometry::Rect;
    /// use nexacore_ui::widget::Widget;
    ///
    /// let w = Widget::Label {
    ///     text: String::from("Hi"),
    ///     rect: Rect {
    ///         x: 5,
    ///         y: 10,
    ///         w: 80,
    ///         h: 16,
    ///     },
    /// };
    /// assert_eq!(w.rect().x, 5);
    /// ```
    #[must_use]
    pub fn rect(&self) -> Rect {
        match self {
            Self::Label { rect, .. }
            | Self::Button { rect, .. }
            | Self::TextInput { rect, .. }
            | Self::List { rect, .. }
            | Self::Container { rect, .. } => *rect,
        }
    }

    /// Computes the intrinsic [`Size`] of this widget given `theme`.
    ///
    /// - **Label / Button / `TextInput`** — width from [`measure_text`] plus
    ///   `2 * theme.padding`; height from `GLYPH_H * theme.text_scale` plus
    ///   `2 * theme.padding`.
    /// - **List** — width = max item width + `2 * theme.padding`;
    ///   height = sum of item heights + `theme.spacing` between items +
    ///   `2 * theme.padding`.
    /// - **Container (Vertical)** — width = max child width;
    ///   height = sum of child heights + `theme.spacing` between children.
    /// - **Container (Horizontal)** — width = sum of child widths + spacing;
    ///   height = max child height.
    ///
    /// Measurement does NOT recurse into the stored `rect`; it is a pure
    /// function of the widget content and the theme.
    ///
    /// # Example
    ///
    /// ```
    /// use nexacore_display::geometry::Rect;
    /// use nexacore_ui::{theme::Theme, widget::Widget};
    ///
    /// let theme = Theme::nexacore(); // text_scale=2, padding=8
    /// let w = Widget::Label {
    ///     text: String::from("Hi"),
    ///     rect: Rect {
    ///         x: 0,
    ///         y: 0,
    ///         w: 0,
    ///         h: 0,
    ///     },
    /// };
    /// let s = w.measure(&theme);
    /// // "Hi" = 2 chars × 8 × scale(2) = 32 wide; + 2*padding(8) = 48
    /// assert_eq!(s.w, 2 * 8 * 2 + 2 * 8);
    /// // GLYPH_H * scale(2) + 2*padding(8) = 16 + 16 = 32
    /// assert_eq!(s.h, 8 * 2 + 2 * 8);
    /// ```
    #[must_use]
    pub fn measure(&self, theme: &Theme) -> Size {
        match self {
            Self::Label { text, .. } | Self::Button { text, .. } => {
                let (tw, _) = measure_text(text, theme.text_scale);
                Size {
                    w: tw + 2 * theme.padding,
                    h: GLYPH_H * theme.text_scale + 2 * theme.padding,
                }
            }
            Self::TextInput { text, .. } => {
                let (tw, _) = measure_text(text, theme.text_scale);
                // Ensure a minimum width so an empty input is still visible.
                let min_w = GLYPH_W * theme.text_scale * 10 + 2 * theme.padding;
                Size {
                    w: (tw + 2 * theme.padding).max(min_w),
                    h: GLYPH_H * theme.text_scale + 2 * theme.padding,
                }
            }
            Self::List { items, .. } => {
                if items.is_empty() {
                    return Size {
                        w: 2 * theme.padding,
                        h: 2 * theme.padding,
                    };
                }
                let item_h = GLYPH_H * theme.text_scale + 2 * theme.padding;
                let max_w = items
                    .iter()
                    .map(|s| {
                        let (tw, _) = measure_text(s, theme.text_scale);
                        tw + 2 * theme.padding
                    })
                    .max()
                    .unwrap_or(0);
                // n is bounded by the item count; saturating from usize to u32
                // is safe in practice (nobody has 2^32 list items).
                let n = u32::try_from(items.len()).unwrap_or(u32::MAX);
                let total_h = item_h * n + theme.spacing * n.saturating_sub(1) + 2 * theme.padding;
                Size {
                    w: max_w,
                    h: total_h,
                }
            }
            Self::Container {
                direction,
                children,
                ..
            } => {
                if children.is_empty() {
                    return Size { w: 0, h: 0 };
                }
                let n = u32::try_from(children.len()).unwrap_or(u32::MAX);
                match direction {
                    Direction::Vertical => {
                        let max_w = children
                            .iter()
                            .map(|c| c.measure(theme).w)
                            .max()
                            .unwrap_or(0);
                        let total_h: u32 = children
                            .iter()
                            .map(|c| c.measure(theme).h)
                            .fold(0u32, u32::saturating_add)
                            .saturating_add(theme.spacing * n.saturating_sub(1));
                        Size {
                            w: max_w,
                            h: total_h,
                        }
                    }
                    Direction::Horizontal => {
                        let total_w: u32 = children
                            .iter()
                            .map(|c| c.measure(theme).w)
                            .fold(0u32, u32::saturating_add)
                            .saturating_add(theme.spacing * n.saturating_sub(1));
                        let max_h = children
                            .iter()
                            .map(|c| c.measure(theme).h)
                            .max()
                            .unwrap_or(0);
                        Size {
                            w: total_w,
                            h: max_h,
                        }
                    }
                }
            }
        }
    }

    /// Assigns concrete [`Rect`]s to this widget and all of its descendants.
    ///
    /// For leaf widgets (`Label`, `Button`, `TextInput`, `List`) the widget's
    /// measured size is positioned at the origin of `bounds`; the width is
    /// clamped to `bounds.w` and the height to `bounds.h` so widgets never
    /// overflow their allocation.
    ///
    /// For `Container`, children are stacked along the container's
    /// [`Direction`] with `theme.spacing` between them.  Each child receives
    /// its measured size as its allocation.
    ///
    /// Layout is **pure** — repeated calls with the same arguments produce
    /// identical rects (no randomness, no I/O).
    ///
    /// # Example
    ///
    /// ```
    /// use nexacore_display::geometry::Rect;
    /// use nexacore_ui::{
    ///     layout::Direction,
    ///     theme::Theme,
    ///     widget::{Widget, WidgetId},
    /// };
    ///
    /// let theme = Theme::nexacore();
    /// let mut w = Widget::Label {
    ///     text: String::from("X"),
    ///     rect: Rect {
    ///         x: 0,
    ///         y: 0,
    ///         w: 0,
    ///         h: 0,
    ///     },
    /// };
    /// let bounds = Rect {
    ///     x: 10,
    ///     y: 20,
    ///     w: 200,
    ///     h: 100,
    /// };
    /// w.layout(bounds, &theme);
    /// // Label always sits at the top-left of its allocation.
    /// assert_eq!(w.rect().x, 10);
    /// assert_eq!(w.rect().y, 20);
    /// ```
    pub fn layout(&mut self, bounds: Rect, theme: &Theme) {
        // Measure first (before any mutable borrow of inner fields).
        let sz = self.measure(theme);
        match self {
            Self::Label { rect, .. }
            | Self::Button { rect, .. }
            | Self::TextInput { rect, .. }
            | Self::List { rect, .. } => {
                // Leaf: position at the top-left of bounds, use measured size
                // clamped to available bounds.
                *rect = Rect {
                    x: bounds.x,
                    y: bounds.y,
                    w: sz.w.min(bounds.w),
                    h: sz.h.min(bounds.h),
                };
            }
            Self::Container {
                direction,
                children,
                rect,
            } => {
                // Container occupies the full bounds allocation.
                *rect = bounds;

                // Stack children along `direction`.
                let mut cursor_x = bounds.x;
                let mut cursor_y = bounds.y;

                // Collect child sizes first (to avoid borrow conflict with
                // the mutable borrow of `children` in the loop).
                let sizes: Vec<Size> = children.iter().map(|c| c.measure(theme)).collect();
                let dir = *direction;
                let spacing = theme.spacing;

                for (child, child_sz) in children.iter_mut().zip(sizes.iter()) {
                    let child_bounds = Rect {
                        x: cursor_x,
                        y: cursor_y,
                        w: child_sz.w,
                        h: child_sz.h,
                    };
                    child.layout(child_bounds, theme);
                    match dir {
                        Direction::Vertical => {
                            // child_sz.h + spacing fits in i32 for any sane layout.
                            #[allow(clippy::cast_possible_wrap)]
                            {
                                cursor_y += child_sz.h as i32 + spacing as i32;
                            }
                        }
                        Direction::Horizontal => {
                            #[allow(clippy::cast_possible_wrap)]
                            {
                                cursor_x += child_sz.w as i32 + spacing as i32;
                            }
                        }
                    }
                }
            }
        }
    }

    /// Renders this widget (and all descendants) into `canvas` using `theme`.
    ///
    /// - **Label** — draws text with `theme.text` colour at `theme.padding`
    ///   inset from `rect.x / rect.y`.
    /// - **Button** — filled rectangle in `theme.accent`, border in
    ///   `theme.border` (1 px), centred text in `theme.bg_canvas`.
    /// - **`TextInput`** — filled rectangle in `theme.bg_canvas`, border in
    ///   `theme.border` (1 px), text at left with `theme.padding` inset, a
    ///   vertical cursor bar at the text end.
    /// - **List** — each item is a thin-bordered row with text at padding inset.
    /// - **Container** — renders each child in order; no background of its own.
    ///
    /// All colours come from `theme`; no colour is hard-coded in this method.
    ///
    /// # Example
    ///
    /// ```
    /// use nexacore_display::geometry::Rect;
    /// use nexacore_ui::{canvas::Canvas, theme::Theme, widget::Widget};
    ///
    /// let theme = Theme::nexacore();
    /// let mut w = Widget::Label {
    ///     text: String::from("Hi"),
    ///     rect: Rect {
    ///         x: 0,
    ///         y: 0,
    ///         w: 100,
    ///         h: 32,
    ///     },
    /// };
    /// let mut buf = vec![0u32; 100 * 32];
    /// let mut c = Canvas::new(&mut buf, 100, 32).unwrap();
    /// w.render(&mut c, &theme);
    /// // Some pixels should be set (charcoal text on a clear background).
    /// assert!(buf.iter().any(|&p| p != 0));
    /// ```
    pub fn render(&self, canvas: &mut Canvas<'_>, theme: &Theme) {
        match self {
            Self::Label { text, rect } => {
                #[allow(clippy::cast_possible_wrap)]
                let tx = rect.x + theme.padding as i32;
                #[allow(clippy::cast_possible_wrap)]
                let ty = rect.y + theme.padding as i32;
                draw_text(canvas, tx, ty, text, theme.text, theme.text_scale);
            }
            Self::Button { text, rect, .. } => {
                // Elevated, rounded accent surface: soft shadow, then a rounded
                // fill (WS7-19.4). The shadow is painted first so the surface
                // sits over it.
                canvas.draw_shadow(rect, theme.elevation);
                canvas.fill_rounded_rect(rect, theme.radius, theme.accent);
                // Centred text in bg_canvas colour.
                let (tw, th) = measure_text(text, theme.text_scale);
                // Integer division for centering; halving a u32 is always
                // well-defined; the result fits in i32 for any sane canvas.
                #[allow(clippy::integer_division, clippy::cast_possible_wrap)]
                let tx = rect.x + (rect.w.saturating_sub(tw) / 2) as i32;
                #[allow(clippy::integer_division, clippy::cast_possible_wrap)]
                let ty = rect.y + (rect.h.saturating_sub(th) / 2) as i32;
                draw_text(canvas, tx, ty, text, theme.bg_canvas, theme.text_scale);
            }
            Self::TextInput { text, rect, .. } => {
                // Rounded field surface (WS7-19.4).
                canvas.fill_rounded_rect(rect, theme.radius, theme.bg_canvas);
                // Text at padding inset.
                #[allow(clippy::cast_possible_wrap)]
                let tx = rect.x + theme.padding as i32;
                #[allow(clippy::cast_possible_wrap)]
                let ty = rect.y + theme.padding as i32;
                let (tw, _) = measure_text(text, theme.text_scale);
                draw_text(canvas, tx, ty, text, theme.text, theme.text_scale);
                // Cursor bar: 1-pixel-wide vertical line at the end of the text.
                #[allow(clippy::cast_possible_wrap)]
                let cursor_x = tx + tw as i32;
                for dy in 0..(GLYPH_H * theme.text_scale) {
                    #[allow(clippy::cast_possible_wrap)]
                    let py = ty + dy as i32;
                    if cursor_x >= 0 && py >= 0 {
                        #[allow(clippy::cast_sign_loss)]
                        canvas.put_pixel(cursor_x as u32, py as u32, theme.text);
                    }
                }
            }
            Self::List { items, rect } => {
                // Draw each item as a bordered row.
                let item_h = GLYPH_H * theme.text_scale + 2 * theme.padding;
                let mut row_y = rect.y;
                for item in items {
                    let row_rect = Rect {
                        x: rect.x,
                        y: row_y,
                        w: rect.w,
                        h: item_h,
                    };
                    canvas.fill_rounded_rect(&row_rect, theme.radius, theme.bg_canvas);
                    #[allow(clippy::cast_possible_wrap)]
                    let tx = rect.x + theme.padding as i32;
                    #[allow(clippy::cast_possible_wrap)]
                    let ty = row_y + theme.padding as i32;
                    draw_text(canvas, tx, ty, item, theme.text, theme.text_scale);
                    #[allow(clippy::cast_possible_wrap)]
                    {
                        row_y += item_h as i32 + theme.spacing as i32;
                    }
                }
            }
            Self::Container { children, .. } => {
                for child in children {
                    child.render(canvas, theme);
                }
            }
        }
    }

    /// Returns the [`WidgetId`] of the **deepest** interactive widget whose
    /// laid-out rect contains `point`, or `None` if the point hits empty space
    /// or a non-interactive widget (`Label`, `List`, `Container`).
    ///
    /// For `Container`, children are tested in reverse order (front-to-back in
    /// render order) so that visually topmost widgets win on overlap.
    ///
    /// This method requires that [`Widget::layout`] has been called; before
    /// layout, all rects are zero and a click at `(0, 0)` may or may not
    /// match depending on the zero-rect width/height.
    ///
    /// # Example
    ///
    /// ```
    /// use nexacore_display::geometry::Rect;
    /// use nexacore_ui::{
    ///     theme::Theme,
    ///     widget::{Widget, WidgetId},
    /// };
    ///
    /// let theme = Theme::nexacore();
    /// let btn_id = WidgetId(1);
    /// let mut btn = Widget::Button {
    ///     id: btn_id,
    ///     text: String::from("OK"),
    ///     rect: Rect {
    ///         x: 0,
    ///         y: 0,
    ///         w: 0,
    ///         h: 0,
    ///     },
    /// };
    /// btn.layout(
    ///     Rect {
    ///         x: 10,
    ///         y: 10,
    ///         w: 80,
    ///         h: 30,
    ///     },
    ///     &theme,
    /// );
    /// // Click inside the button.
    /// assert_eq!(btn.dispatch_click((15, 15)), Some(btn_id));
    /// // Click outside.
    /// assert_eq!(btn.dispatch_click((5, 5)), None);
    /// ```
    #[must_use]
    pub fn dispatch_click(&self, point: (i32, i32)) -> Option<WidgetId> {
        match self {
            // Non-interactive leaves — always return None regardless of
            // whether the click is inside.
            Self::Label { .. } | Self::List { .. } => None,
            // Interactive leaves — return id if the click is within the rect.
            Self::Button { id, rect, .. } | Self::TextInput { id, rect, .. } => {
                if rect.contains_point(point.0, point.1) {
                    Some(*id)
                } else {
                    None
                }
            }
            Self::Container { children, rect, .. } => {
                // Only recurse if the click is within the container bounds.
                if !rect.contains_point(point.0, point.1) {
                    return None;
                }
                // Test children in reverse order so visually topmost (last
                // rendered) child wins on overlap.
                for child in children.iter().rev() {
                    if let Some(id) = child.dispatch_click(point) {
                        return Some(id);
                    }
                }
                None
            }
        }
    }
}
