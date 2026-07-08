//! SVG-class vector icons: path parsing, filling, and the brand icon set
//! (WS7-05.1 / .2).
//!
//! Icons are authored as SVG **path data** (the `d` attribute) over a square
//! viewBox — not full SVG documents. [`parse_path`] turns a path string into a
//! flattened [`IconPath`] (contours of line segments, Bézier curves
//! subdivided), and [`render`] fills it into an ARGB8888 bitmap at any target
//! size with an even-odd scanline rasterizer. [`IconDef`] pairs a regular and a
//! bold path so the [`brand`] set ships size- and weight-variant icons
//! (WS7-05.2).
//!
//! `no_std + alloc`, pure arithmetic over `f32` — no transcendental functions,
//! so it needs no `libm`. Pixels are the compositor's `0xAA_RR_GG_BB`
//! ARGB8888 `u32`.

// Vector rasterization is inherently floating-point and quantizes coordinates
// to pixel indices written into a pre-sized buffer.
#![allow(
    clippy::float_arithmetic,
    clippy::cast_precision_loss,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::integer_division,
    // Exact float comparisons here are intentional (exact viewBox assertions
    // in tests over representable values).
    clippy::float_cmp
)]

use alloc::{vec, vec::Vec};

/// Bézier flattening steps per curve segment.
const BEZIER_STEPS: u32 = 16;

/// A flattened icon path: closed contours of `(x, y)` points in viewBox units.
#[derive(Debug, Clone, PartialEq)]
pub struct IconPath {
    contours: Vec<Vec<(f32, f32)>>,
    viewbox: f32,
}

impl IconPath {
    /// The contours (each a closed polyline in viewBox units).
    #[must_use]
    pub fn contours(&self) -> &[Vec<(f32, f32)>] {
        &self.contours
    }

    /// The square viewBox side length the contours are expressed in.
    #[must_use]
    pub fn viewbox(&self) -> f32 {
        self.viewbox
    }

    /// `true` if the path has no drawable contour.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.contours.iter().all(|c| c.len() < 2)
    }
}

// =============================================================================
// Path-data parser
// =============================================================================

/// Cursor over SVG path-data bytes.
struct PathParser<'a> {
    s: &'a [u8],
    i: usize,
}

impl<'a> PathParser<'a> {
    fn new(s: &'a [u8]) -> Self {
        Self { s, i: 0 }
    }

    fn skip_sep(&mut self) {
        while let Some(&c) = self.s.get(self.i) {
            if c == b' ' || c == b',' || c == b'\n' || c == b'\t' || c == b'\r' {
                self.i += 1;
            } else {
                break;
            }
        }
    }

    fn peek(&self) -> Option<u8> {
        self.s.get(self.i).copied()
    }

    /// Read a signed decimal number (no exponent), advancing past it.
    fn read_number(&mut self) -> Option<f32> {
        self.skip_sep();
        let start = self.i;
        if matches!(self.peek(), Some(b'+' | b'-')) {
            self.i += 1;
        }
        let mut saw_digit = false;
        while matches!(self.peek(), Some(b'0'..=b'9')) {
            self.i += 1;
            saw_digit = true;
        }
        if self.peek() == Some(b'.') {
            self.i += 1;
            while matches!(self.peek(), Some(b'0'..=b'9')) {
                self.i += 1;
                saw_digit = true;
            }
        }
        if !saw_digit {
            return None;
        }
        let slice = self.s.get(start..self.i)?;
        core::str::from_utf8(slice).ok()?.parse::<f32>().ok()
    }

    fn read_point(&mut self, rel_x: f32, rel_y: f32) -> Option<(f32, f32)> {
        let x = self.read_number()? + rel_x;
        let y = self.read_number()? + rel_y;
        Some((x, y))
    }
}

/// Parse SVG path data `d` over a square `viewbox` into a flattened
/// [`IconPath`].
///
/// Supports `M/m L/l H/h V/v C/c Q/q Z/z` (absolute and relative). Bézier
/// curves are subdivided into `BEZIER_STEPS` segments. Returns `None` on an
/// unsupported command, malformed numbers, or a non-positive viewBox.
#[must_use]
pub fn parse_path(d: &str, viewbox: f32) -> Option<IconPath> {
    if !viewbox.is_finite() || viewbox <= 0.0 {
        return None;
    }
    let mut p = PathParser::new(d.as_bytes());
    let mut contours: Vec<Vec<(f32, f32)>> = Vec::new();
    let mut cur: Vec<(f32, f32)> = Vec::new();
    let (mut cx, mut cy) = (0.0f32, 0.0f32);
    let (mut sx, mut sy) = (0.0f32, 0.0f32);
    let mut cmd = 0u8;

    loop {
        p.skip_sep();
        let Some(nc) = p.peek() else { break };
        if nc.is_ascii_alphabetic() {
            cmd = nc;
            p.i += 1;
        } else {
            // Implicit repeat of the previous command; after a moveto the
            // implicit command is a lineto (SVG rule).
            cmd = match cmd {
                b'M' => b'L',
                b'm' => b'l',
                0 => return None,
                other => other,
            };
        }

        match cmd {
            b'M' | b'm' => {
                let (rx, ry) = if cmd == b'm' { (cx, cy) } else { (0.0, 0.0) };
                let (x, y) = p.read_point(rx, ry)?;
                if cur.len() >= 2 {
                    contours.push(core::mem::take(&mut cur));
                } else {
                    cur.clear();
                }
                cur.push((x, y));
                cx = x;
                cy = y;
                sx = x;
                sy = y;
            }
            b'L' | b'l' => {
                let (rx, ry) = if cmd == b'l' { (cx, cy) } else { (0.0, 0.0) };
                let (x, y) = p.read_point(rx, ry)?;
                cur.push((x, y));
                cx = x;
                cy = y;
            }
            b'H' | b'h' => {
                let base = if cmd == b'h' { cx } else { 0.0 };
                let x = p.read_number()? + base;
                cur.push((x, cy));
                cx = x;
            }
            b'V' | b'v' => {
                let base = if cmd == b'v' { cy } else { 0.0 };
                let y = p.read_number()? + base;
                cur.push((cx, y));
                cy = y;
            }
            b'C' | b'c' => {
                let (rx, ry) = if cmd == b'c' { (cx, cy) } else { (0.0, 0.0) };
                let p1 = p.read_point(rx, ry)?;
                let p2 = p.read_point(rx, ry)?;
                let pe = p.read_point(rx, ry)?;
                flatten_cubic((cx, cy), p1, p2, pe, &mut cur);
                cx = pe.0;
                cy = pe.1;
            }
            b'Q' | b'q' => {
                let (rx, ry) = if cmd == b'q' { (cx, cy) } else { (0.0, 0.0) };
                let p1 = p.read_point(rx, ry)?;
                let pe = p.read_point(rx, ry)?;
                flatten_quad((cx, cy), p1, pe, &mut cur);
                cx = pe.0;
                cy = pe.1;
            }
            b'Z' | b'z' => {
                if !cur.is_empty() {
                    cur.push((sx, sy));
                    contours.push(core::mem::take(&mut cur));
                }
                cx = sx;
                cy = sy;
            }
            _ => return None,
        }
    }
    if cur.len() >= 2 {
        contours.push(cur);
    }
    Some(IconPath { contours, viewbox })
}

/// Subdivide a cubic Bézier `p0→pe` (controls `p1`,`p2`) into line segments,
/// pushing the endpoints (`t > 0`) onto `out`.
fn flatten_cubic(
    p0: (f32, f32),
    p1: (f32, f32),
    p2: (f32, f32),
    pe: (f32, f32),
    out: &mut Vec<(f32, f32)>,
) {
    for step in 1..=BEZIER_STEPS {
        let t = step as f32 / BEZIER_STEPS as f32;
        let u = 1.0 - t;
        let w0 = u * u * u;
        let w1 = 3.0 * u * u * t;
        let w2 = 3.0 * u * t * t;
        let w3 = t * t * t;
        out.push((
            w0 * p0.0 + w1 * p1.0 + w2 * p2.0 + w3 * pe.0,
            w0 * p0.1 + w1 * p1.1 + w2 * p2.1 + w3 * pe.1,
        ));
    }
}

/// Subdivide a quadratic Bézier `p0→pe` (control `p1`) into line segments.
fn flatten_quad(p0: (f32, f32), p1: (f32, f32), pe: (f32, f32), out: &mut Vec<(f32, f32)>) {
    for step in 1..=BEZIER_STEPS {
        let t = step as f32 / BEZIER_STEPS as f32;
        let u = 1.0 - t;
        let w0 = u * u;
        let w1 = 2.0 * u * t;
        let w2 = t * t;
        out.push((
            w0 * p0.0 + w1 * p1.0 + w2 * pe.0,
            w0 * p0.1 + w1 * p1.1 + w2 * pe.1,
        ));
    }
}

// =============================================================================
// Renderer (even-odd scanline fill)
// =============================================================================

/// Fill `path` into a `size × size` ARGB8888 bitmap with `fill` color, using an
/// even-odd scanline rasterizer (WS7-05.1).
///
/// The viewBox is scaled uniformly to the target size. Pixels whose center is
/// inside an odd number of contour crossings are set to `fill`; all others stay
/// transparent (`0`).
#[must_use]
pub fn render(path: &IconPath, size: u32, fill: u32) -> Vec<u32> {
    let mut out = vec![0u32; (size as usize).saturating_mul(size as usize)];
    if size == 0 || !path.viewbox.is_finite() || path.viewbox <= 0.0 {
        return out;
    }
    let scale = size as f32 / path.viewbox;
    let mut xs: Vec<f32> = Vec::new();

    for y in 0..size {
        let cy = y as f32 + 0.5;
        xs.clear();
        for contour in &path.contours {
            if contour.len() < 2 {
                continue;
            }
            // Iterate closed edges (last→first via cycle) without indexing.
            for (&(x0, y0), &(x1, y1)) in contour
                .iter()
                .zip(contour.iter().cycle().skip(1))
                .take(contour.len())
            {
                let (py0, py1) = (y0 * scale, y1 * scale);
                // Does the scanline cross this edge? Half-open in Y to avoid
                // double-counting shared vertices.
                let crosses = (py0 <= cy && cy < py1) || (py1 <= cy && cy < py0);
                if crosses {
                    let t = (cy - py0) / (py1 - py0);
                    xs.push((x0 + t * (x1 - x0)) * scale);
                }
            }
        }
        if xs.is_empty() {
            continue;
        }
        xs.sort_by(f32::total_cmp);
        let row = (y as usize).saturating_mul(size as usize);
        for x in 0..size {
            let cx = x as f32 + 0.5;
            // Even-odd: inside iff an odd number of crossings lie to the left.
            let left = xs.iter().filter(|&&xv| xv <= cx).count();
            if left % 2 == 1 {
                if let Some(slot) = out.get_mut(row + x as usize) {
                    *slot = fill;
                }
            }
        }
    }
    out
}

// =============================================================================
// Icon set + weight variants (WS7-05.2)
// =============================================================================

/// Stroke/fill weight variant of a brand icon.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IconWeight {
    /// Standard weight.
    Regular,
    /// Heavier weight (thicker shapes) for emphasis / small sizes.
    Bold,
}

/// A named brand icon with regular and bold path-data variants over a square
/// viewBox.
#[derive(Debug, Clone, Copy)]
pub struct IconDef {
    /// Stable icon name (lookup key).
    pub name: &'static str,
    /// Square viewBox side the path data is authored in.
    pub viewbox: f32,
    /// Regular-weight path data.
    pub regular: &'static str,
    /// Bold-weight path data.
    pub bold: &'static str,
}

impl IconDef {
    /// The path-data string for `weight`.
    #[must_use]
    pub fn path_data(&self, weight: IconWeight) -> &'static str {
        match weight {
            IconWeight::Regular => self.regular,
            IconWeight::Bold => self.bold,
        }
    }

    /// Parse this icon's `weight` variant into an [`IconPath`].
    #[must_use]
    pub fn path(&self, weight: IconWeight) -> Option<IconPath> {
        parse_path(self.path_data(weight), self.viewbox)
    }

    /// Render this icon at `size × size` pixels in `fill` color and `weight`.
    #[must_use]
    pub fn render(&self, weight: IconWeight, size: u32, fill: u32) -> Option<Vec<u32>> {
        Some(render(&self.path(weight)?, size, fill))
    }
}

/// The brand icon set (HIG WS7-00 — geometric, 24-unit viewBox).
pub mod brand {
    use super::IconDef;

    /// `plus` — add / new.
    pub const PLUS: IconDef = IconDef {
        name: "plus",
        viewbox: 24.0,
        regular: "M11 4 H13 V11 H20 V13 H13 V20 H11 V13 H4 V11 H11 Z",
        bold: "M10 4 H14 V10 H20 V14 H14 V20 H10 V14 H4 V10 H10 Z",
    };

    /// `square` — placeholder / container glyph.
    pub const SQUARE: IconDef = IconDef {
        name: "square",
        viewbox: 24.0,
        regular: "M5 5 H19 V19 H5 Z",
        bold: "M3 3 H21 V21 H3 Z",
    };

    /// `check` — confirmation mark.
    pub const CHECK: IconDef = IconDef {
        name: "check",
        viewbox: 24.0,
        regular: "M4 13 L9 18 L20 6 L18 4 L9 14 L6 11 Z",
        bold: "M3 13 L9 19 L21 6 L18 3 L9 14 L6 10 Z",
    };

    /// All brand icons, in name order.
    pub const ALL: [IconDef; 3] = [PLUS, SQUARE, CHECK];
}

/// Look up a brand icon by name (WS7-05.2).
#[must_use]
pub fn brand_icon(name: &str) -> Option<IconDef> {
    brand::ALL.into_iter().find(|i| i.name == name)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn alpha_at(buf: &[u32], size: u32, x: u32, y: u32) -> u8 {
        let idx = (y * size + x) as usize;
        ((buf[idx] >> 24) & 0xFF) as u8
    }

    fn filled_count(buf: &[u32]) -> usize {
        buf.iter().filter(|&&p| (p >> 24) & 0xFF != 0).count()
    }

    // ---- Parser (WS7-05.1) --------------------------------------------------

    #[test]
    fn parse_square_path() {
        let p = parse_path("M4 4 H20 V20 H4 Z", 24.0).unwrap();
        assert_eq!(p.contours().len(), 1);
        assert!(!p.is_empty());
        assert_eq!(p.viewbox(), 24.0);
    }

    #[test]
    fn parse_relative_and_implicit_lineto() {
        // 'm' then implicit relative linetos.
        let p = parse_path("m4 4 l16 0 l0 16 l-16 0 z", 24.0).unwrap();
        assert_eq!(p.contours().len(), 1);
        assert!(!p.is_empty());
    }

    #[test]
    fn parse_rejects_unsupported_command_and_bad_viewbox() {
        assert!(parse_path("M0 0 A 1 1 0 0 1 2 2", 24.0).is_none()); // arc unsupported
        assert!(parse_path("M0 0 L1 1", 0.0).is_none()); // bad viewbox
    }

    #[test]
    fn parse_curve_flattens_to_segments() {
        let p = parse_path("M0 12 C0 0 24 0 24 12 Z", 24.0).unwrap();
        // One contour with the moveto + flattened curve points + close.
        assert!(p.contours()[0].len() > BEZIER_STEPS as usize);
    }

    // ---- Renderer (WS7-05.1) ------------------------------------------------

    #[test]
    fn render_square_fills_interior_not_exterior() {
        let p = parse_path("M4 4 H20 V20 H4 Z", 24.0).unwrap();
        let buf = render(&p, 24, 0xFF_FF_FF_FF);
        assert_eq!(buf.len(), 24 * 24);
        // Center is inside the 4..20 square.
        assert_eq!(alpha_at(&buf, 24, 12, 12), 0xFF);
        // Corners are outside.
        assert_eq!(alpha_at(&buf, 24, 1, 1), 0x00);
        assert_eq!(alpha_at(&buf, 24, 22, 22), 0x00);
    }

    #[test]
    fn render_triangle_respects_diagonal() {
        // Right triangle with the right angle at the top-left.
        let p = parse_path("M2 2 L22 2 L2 22 Z", 24.0).unwrap();
        let buf = render(&p, 24, 0xFF_FF_FF_FF);
        // Near the top-left is inside; the bottom-right is across the diagonal.
        assert_eq!(alpha_at(&buf, 24, 4, 4), 0xFF);
        assert_eq!(alpha_at(&buf, 24, 20, 20), 0x00);
    }

    #[test]
    fn render_empty_for_zero_size() {
        let p = parse_path("M4 4 H20 V20 H4 Z", 24.0).unwrap();
        assert!(render(&p, 0, 0xFF_FF_FF_FF).is_empty());
    }

    // ---- Icon set + weights (WS7-05.2) --------------------------------------

    #[test]
    fn brand_lookup_and_variants() {
        assert!(brand_icon("plus").is_some());
        assert!(brand_icon("nope").is_none());

        let plus = brand_icon("plus").unwrap();
        let reg = plus.render(IconWeight::Regular, 24, 0xFF_FF_FF_FF).unwrap();
        let bold = plus.render(IconWeight::Bold, 24, 0xFF_FF_FF_FF).unwrap();
        // Both render the plus center filled.
        assert_eq!(alpha_at(&reg, 24, 12, 12), 0xFF);
        assert_eq!(alpha_at(&bold, 24, 12, 12), 0xFF);
        // Bold has wider arms ⇒ strictly more filled pixels.
        assert!(
            filled_count(&bold) > filled_count(&reg),
            "bold {} should exceed regular {}",
            filled_count(&bold),
            filled_count(&reg)
        );
    }

    #[test]
    fn brand_icons_all_parse() {
        for def in brand::ALL {
            assert!(def.path(IconWeight::Regular).is_some(), "{}", def.name);
            assert!(def.path(IconWeight::Bold).is_some(), "{}", def.name);
        }
    }

    #[test]
    fn icon_renders_at_multiple_sizes() {
        let sq = brand_icon("square").unwrap();
        for size in [16u32, 24, 48] {
            let buf = sq.render(IconWeight::Regular, size, 0xFF_10_20_30).unwrap();
            assert_eq!(buf.len(), (size * size) as usize);
            // Center pixel is inside the square at every size.
            assert_eq!(alpha_at(&buf, size, size / 2, size / 2), 0xFF);
        }
    }
}
