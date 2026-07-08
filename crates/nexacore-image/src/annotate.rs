//! [`AnnotationLayer`] — highlight / arrow / text-block annotations with alpha
//! compositing (WS8-03.6).
//!
//! Annotations are a non-destructive overlay: they live in a layer and are
//! composited onto a copy of the [`ImageBuffer`] only when the user flattens or
//! exports. Compositing is integer alpha blending
//! (`out = (src·a + dst·(255−a)) / 255`). Glyph shaping is the font stack's job
//! (WS7); a text annotation here renders as a filled marker block so the model
//! and compositing are host-testable without a font engine.

use alloc::{string::String, vec::Vec};

use crate::buffer::ImageBuffer;

/// An RGBA color (straight, not premultiplied).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Color(pub [u8; 4]);

impl Color {
    /// Opaque red/green/blue helpers and a raw constructor.
    #[must_use]
    pub const fn rgba(r: u8, g: u8, b: u8, a: u8) -> Self {
        Self([r, g, b, a])
    }

    /// The alpha channel.
    #[must_use]
    pub const fn alpha(self) -> u8 {
        self.0[3]
    }
}

/// A single annotation primitive (WS8-03.6).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Annotation {
    /// A filled, typically semi-transparent rectangle (the highlighter).
    Highlight {
        /// Top-left x.
        x: u32,
        /// Top-left y.
        y: u32,
        /// Width in pixels.
        w: u32,
        /// Height in pixels.
        h: u32,
        /// Fill color (alpha controls the blend).
        color: Color,
    },
    /// A straight line from `(x0,y0)` to `(x1,y1)` (the arrow shaft).
    Arrow {
        /// Start x.
        x0: i32,
        /// Start y.
        y0: i32,
        /// End x.
        x1: i32,
        /// End y.
        y1: i32,
        /// Stroke color.
        color: Color,
    },
    /// A text label, rendered here as a filled marker block of `w × h`
    /// (real glyph rendering is the WS7 font stack).
    Text {
        /// Top-left x.
        x: u32,
        /// Top-left y.
        y: u32,
        /// Marker block width.
        w: u32,
        /// Marker block height.
        h: u32,
        /// The label text (carried through to the renderer).
        text: String,
        /// Text/marker color.
        color: Color,
    },
}

/// An ordered, non-destructive overlay of [`Annotation`]s (WS8-03.6).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct AnnotationLayer {
    items: Vec<Annotation>,
}

impl AnnotationLayer {
    /// Create an empty layer.
    #[must_use]
    pub fn new() -> Self {
        Self { items: Vec::new() }
    }

    /// Append an annotation (drawn last = on top).
    pub fn add(&mut self, annotation: Annotation) {
        self.items.push(annotation);
    }

    /// Number of annotations.
    #[must_use]
    pub fn len(&self) -> usize {
        self.items.len()
    }

    /// Whether the layer is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
    }

    /// Remove the annotation at `index`, returning it if present (undo support).
    pub fn remove(&mut self, index: usize) -> Option<Annotation> {
        if index < self.items.len() {
            Some(self.items.remove(index))
        } else {
            None
        }
    }

    /// Clear all annotations.
    pub fn clear(&mut self) {
        self.items.clear();
    }

    /// The annotations, in draw order.
    #[must_use]
    pub fn items(&self) -> &[Annotation] {
        &self.items
    }

    /// Composite every annotation onto `image`, bottom-to-top (WS8-03.6).
    ///
    /// Mutates `image` in place. Out-of-bounds pixels are skipped.
    pub fn render_onto(&self, image: &mut ImageBuffer) {
        for item in &self.items {
            match item {
                Annotation::Highlight { x, y, w, h, color }
                | Annotation::Text {
                    x, y, w, h, color, ..
                } => fill_rect(image, *x, *y, *w, *h, *color),
                Annotation::Arrow {
                    x0,
                    y0,
                    x1,
                    y1,
                    color,
                } => draw_line(image, *x0, *y0, *x1, *y1, *color),
            }
        }
    }
}

/// Alpha-blend `src` over the pixel at `(x, y)` (`out = src·a + dst·(255−a)`).
fn blend_pixel(image: &mut ImageBuffer, x: u32, y: u32, src: Color) {
    let a = u32::from(src.alpha());
    if a == 0 {
        return;
    }
    let Some(dst) = image.pixel(x, y) else {
        return;
    };
    let mix = |s: u8, d: u8| -> u8 { ((u32::from(s) * a + u32::from(d) * (255 - a)) / 255) as u8 };
    let out = [
        mix(src.0[0], dst[0]),
        mix(src.0[1], dst[1]),
        mix(src.0[2], dst[2]),
        // Alpha accumulates toward opaque.
        (a + u32::from(dst[3]) * (255 - a) / 255).min(255) as u8,
    ];
    image.set_pixel(x, y, out);
}

/// Alpha-blend a filled rectangle.
fn fill_rect(image: &mut ImageBuffer, x: u32, y: u32, w: u32, h: u32, color: Color) {
    for row in y..y.saturating_add(h) {
        for col in x..x.saturating_add(w) {
            blend_pixel(image, col, row, color);
        }
    }
}

/// Draw a 1px line via integer Bresenham, alpha-blended.
fn draw_line(image: &mut ImageBuffer, x0: i32, y0: i32, x1: i32, y1: i32, color: Color) {
    let dx = (x1 - x0).abs();
    let dy = -(y1 - y0).abs();
    let sx = if x0 < x1 { 1 } else { -1 };
    let sy = if y0 < y1 { 1 } else { -1 };
    let mut err = dx + dy;
    let (mut x, mut y) = (x0, y0);
    loop {
        if x >= 0 && y >= 0 {
            blend_pixel(image, x as u32, y as u32, color);
        }
        if x == x1 && y == y1 {
            break;
        }
        let e2 = 2 * err;
        if e2 >= dy {
            err += dy;
            x += sx;
        }
        if e2 <= dx {
            err += dx;
            y += sy;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn white(w: u32, h: u32) -> ImageBuffer {
        ImageBuffer::filled(w, h, [255, 255, 255, 255]).unwrap()
    }

    #[test]
    fn layer_add_remove_clear() {
        let mut layer = AnnotationLayer::new();
        assert!(layer.is_empty());
        layer.add(Annotation::Highlight {
            x: 0,
            y: 0,
            w: 1,
            h: 1,
            color: Color::rgba(255, 255, 0, 128),
        });
        assert_eq!(layer.len(), 1);
        assert!(layer.remove(0).is_some());
        assert!(layer.remove(0).is_none());
        assert!(layer.is_empty());
    }

    #[test]
    fn opaque_highlight_replaces_pixels() {
        let mut img = white(4, 4);
        let mut layer = AnnotationLayer::new();
        layer.add(Annotation::Highlight {
            x: 1,
            y: 1,
            w: 2,
            h: 2,
            color: Color::rgba(0, 0, 0, 255),
        });
        layer.render_onto(&mut img);
        assert_eq!(img.pixel(1, 1), Some([0, 0, 0, 255]));
        assert_eq!(img.pixel(2, 2), Some([0, 0, 0, 255]));
        // Outside the rect is untouched.
        assert_eq!(img.pixel(0, 0), Some([255, 255, 255, 255]));
        assert_eq!(img.pixel(3, 3), Some([255, 255, 255, 255]));
    }

    #[test]
    fn semi_transparent_highlight_blends() {
        let mut img = white(2, 2);
        let mut layer = AnnotationLayer::new();
        // 50% black over white → ~127 grey.
        layer.add(Annotation::Highlight {
            x: 0,
            y: 0,
            w: 1,
            h: 1,
            color: Color::rgba(0, 0, 0, 128),
        });
        layer.render_onto(&mut img);
        let px = img.pixel(0, 0).unwrap();
        assert!((px[0] as i32 - 127).abs() <= 1, "blend off: {px:?}");
    }

    #[test]
    fn zero_alpha_is_noop() {
        let mut img = white(2, 2);
        let mut layer = AnnotationLayer::new();
        layer.add(Annotation::Highlight {
            x: 0,
            y: 0,
            w: 2,
            h: 2,
            color: Color::rgba(255, 0, 0, 0),
        });
        layer.render_onto(&mut img);
        assert_eq!(img.pixel(0, 0), Some([255, 255, 255, 255]));
    }

    #[test]
    fn arrow_draws_a_connected_line() {
        let mut img = white(5, 5);
        let mut layer = AnnotationLayer::new();
        layer.add(Annotation::Arrow {
            x0: 0,
            y0: 0,
            x1: 4,
            y1: 4,
            color: Color::rgba(255, 0, 0, 255),
        });
        layer.render_onto(&mut img);
        // The diagonal endpoints and midpoint are painted red.
        assert_eq!(img.pixel(0, 0), Some([255, 0, 0, 255]));
        assert_eq!(img.pixel(2, 2), Some([255, 0, 0, 255]));
        assert_eq!(img.pixel(4, 4), Some([255, 0, 0, 255]));
    }

    #[test]
    fn text_renders_marker_block() {
        let mut img = white(4, 4);
        let mut layer = AnnotationLayer::new();
        layer.add(Annotation::Text {
            x: 0,
            y: 0,
            w: 2,
            h: 1,
            text: alloc::string::String::from("hi"),
            color: Color::rgba(0, 0, 255, 255),
        });
        layer.render_onto(&mut img);
        assert_eq!(img.pixel(0, 0), Some([0, 0, 255, 255]));
        assert_eq!(img.pixel(1, 0), Some([0, 0, 255, 255]));
    }

    #[test]
    fn render_skips_out_of_bounds() {
        let mut img = white(2, 2);
        let mut layer = AnnotationLayer::new();
        layer.add(Annotation::Highlight {
            x: 1,
            y: 1,
            w: 100,
            h: 100,
            color: Color::rgba(0, 0, 0, 255),
        });
        // Must not panic; only the in-bounds pixel is affected.
        layer.render_onto(&mut img);
        assert_eq!(img.pixel(1, 1), Some([0, 0, 0, 255]));
    }
}
