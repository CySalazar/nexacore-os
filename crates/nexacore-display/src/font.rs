//! `TrueType` / `OpenType` (glyf-flavored) font parsing (WS7-03.1).
//!
//! Parses the sfnt table directory and the core tables needed to lay out and
//! rasterize text: `head` (units-per-em, loca format), `maxp` (glyph count),
//! `hhea` + `hmtx` (horizontal advances), `loca` (glyph offsets), `glyf` (glyph
//! outlines), and `cmap` (character → glyph mapping, format 4). It yields an
//! [`Outline`] in font design units that the rasterizer (WS7-03.2) consumes.
//!
//! Both simple and **composite/compound** glyphs are decoded — the latter by
//! recursively assembling their referenced components under a 2×2 `F2Dot14`
//! transform + offset (WS7-19.3), which is what makes accented Latin render.
//!
//! Out of scope for this parser (returned as an explicit error, follow-up work):
//! CFF/`OTTO` (`PostScript`) outlines.
//!
//! `no_std + alloc`; borrows the font bytes, allocates only the decoded outline.

// Parsing a binary format inherently casts between the spec's u8/i16/u16/u32
// and Rust indices/coordinates. Every read is bounds-checked through the
// `be_*` helpers (which return `Option`), so these casts cannot read OOB.
#![allow(
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_sign_loss,
    clippy::cast_lossless
)]

use alloc::vec::Vec;

/// A single point of a glyph contour, in font design units.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Point {
    /// X coordinate (design units; divide by `units_per_em` for em fractions).
    pub x: i16,
    /// Y coordinate (design units), Y-up as in the font's coordinate system.
    pub y: i16,
    /// On-curve point; an off-curve point is a quadratic Bézier control point.
    pub on_curve: bool,
}

/// A decoded simple-glyph outline: closed contours plus metrics, all in font
/// design units. An empty glyph (e.g. the space) has no contours.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Outline {
    /// Closed contours; each is a ring of [`Point`]s (on/off-curve).
    pub contours: Vec<Vec<Point>>,
    /// Horizontal advance width (from `hmtx`).
    pub advance: u16,
    /// Glyph bounding box minimum X.
    pub x_min: i16,
    /// Glyph bounding box minimum Y.
    pub y_min: i16,
    /// Glyph bounding box maximum X.
    pub x_max: i16,
    /// Glyph bounding box maximum Y.
    pub y_max: i16,
}

impl Outline {
    /// `true` if the glyph has no contours (e.g. whitespace).
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.contours.is_empty()
    }
}

/// An error while parsing a font or a glyph.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum FontError {
    /// The data is too short, or a structure ran past the end of the buffer.
    Truncated,
    /// The sfnt version is not a glyf-based `TrueType`/`OpenType` font (e.g. CFF).
    UnsupportedFormat,
    /// A required table (named) is absent from the directory.
    MissingTable(&'static str),
    /// The glyph id is `>= num_glyphs`.
    GlyphOutOfRange,
    /// Defensive guard: the simple-glyph decoder was handed a composite glyph.
    /// The public [`Font::glyph_outline`] dispatches composites to the compound
    /// assembler, so this is not reached in normal decoding.
    UnsupportedCompositeGlyph,
}

impl core::fmt::Display for FontError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Truncated => write!(f, "font: data truncated"),
            Self::UnsupportedFormat => write!(f, "font: unsupported sfnt format (not glyf-based)"),
            Self::MissingTable(t) => write!(f, "font: missing required table '{t}'"),
            Self::GlyphOutOfRange => write!(f, "font: glyph id out of range"),
            Self::UnsupportedCompositeGlyph => {
                write!(f, "font: composite glyphs not yet supported")
            }
        }
    }
}

impl core::error::Error for FontError {}

// --- big-endian readers (bounds-checked, never panic) ----------------------
// `pub(crate)` so the sibling `kerning` module can reuse them on raw table data.

pub(crate) fn be_u16(d: &[u8], o: usize) -> Option<u16> {
    d.get(o..o.checked_add(2)?)?
        .try_into()
        .ok()
        .map(u16::from_be_bytes)
}

pub(crate) fn be_i16(d: &[u8], o: usize) -> Option<i16> {
    d.get(o..o.checked_add(2)?)?
        .try_into()
        .ok()
        .map(i16::from_be_bytes)
}

pub(crate) fn be_u32(d: &[u8], o: usize) -> Option<u32> {
    d.get(o..o.checked_add(4)?)?
        .try_into()
        .ok()
        .map(u32::from_be_bytes)
}

/// A parsed font face, borrowing the raw font bytes.
#[derive(Debug, Clone)]
pub struct Font<'a> {
    data: &'a [u8],
    units_per_em: u16,
    num_glyphs: u16,
    long_loca: bool,
    num_h_metrics: u16,
    loca: usize,
    glyf: usize,
    hmtx: usize,
    cmap: usize,
}

impl<'a> Font<'a> {
    /// Parses the sfnt directory and the core tables.
    ///
    /// # Errors
    ///
    /// [`FontError::Truncated`] on short data, [`FontError::UnsupportedFormat`]
    /// for non-glyf sfnt, or [`FontError::MissingTable`] if a required table is
    /// absent.
    pub fn parse(data: &'a [u8]) -> Result<Self, FontError> {
        let version = be_u32(data, 0).ok_or(FontError::Truncated)?;
        // 0x00010000 = TrueType outlines; 0x74727565 = 'true'. 'OTTO' (CFF) and
        // collections are out of scope.
        if version != 0x0001_0000 && version != 0x7472_7565 {
            return Err(FontError::UnsupportedFormat);
        }
        let num_tables = be_u16(data, 4).ok_or(FontError::Truncated)?;

        let find = |want: &[u8; 4]| -> Option<usize> {
            for i in 0..num_tables as usize {
                let rec = 12 + i * 16;
                if data.get(rec..rec.checked_add(4)?) == Some(want.as_slice()) {
                    return be_u32(data, rec + 8).map(|o| o as usize);
                }
            }
            None
        };

        let head = find(b"head").ok_or(FontError::MissingTable("head"))?;
        let maxp = find(b"maxp").ok_or(FontError::MissingTable("maxp"))?;
        let hhea = find(b"hhea").ok_or(FontError::MissingTable("hhea"))?;
        let hmtx = find(b"hmtx").ok_or(FontError::MissingTable("hmtx"))?;
        let loca = find(b"loca").ok_or(FontError::MissingTable("loca"))?;
        let glyf = find(b"glyf").ok_or(FontError::MissingTable("glyf"))?;
        let cmap = find(b"cmap").ok_or(FontError::MissingTable("cmap"))?;

        let units_per_em = be_u16(data, head + 18).ok_or(FontError::Truncated)?;
        let loc_fmt = be_i16(data, head + 50).ok_or(FontError::Truncated)?;
        let num_glyphs = be_u16(data, maxp + 4).ok_or(FontError::Truncated)?;
        let num_h_metrics = be_u16(data, hhea + 34).ok_or(FontError::Truncated)?;

        Ok(Self {
            data,
            units_per_em,
            num_glyphs,
            long_loca: loc_fmt == 1,
            num_h_metrics,
            loca,
            glyf,
            hmtx,
            cmap,
        })
    }

    /// Font design units per em (the outline coordinate scale).
    #[must_use]
    pub fn units_per_em(&self) -> u16 {
        self.units_per_em
    }

    /// Number of glyphs in the font.
    #[must_use]
    pub fn num_glyphs(&self) -> u16 {
        self.num_glyphs
    }

    /// Maps a Unicode scalar to a glyph id via the `cmap` (format 4, BMP).
    ///
    /// Returns `None` for unmapped characters or if no format-4 subtable exists.
    #[must_use]
    pub fn glyph_index(&self, ch: char) -> Option<u16> {
        let sub = self.cmap_format4_subtable()?;
        cmap4_lookup(sub, ch as u32)
    }

    /// Returns the raw bytes of a table by its 4-byte tag, if present.
    ///
    /// Used to reach optional tables (e.g. `kern`, `GPOS`) that the core parser
    /// does not eagerly decode.
    #[must_use]
    pub fn table_data(&self, tag: [u8; 4]) -> Option<&'a [u8]> {
        let num_tables = be_u16(self.data, 4)?;
        for i in 0..num_tables as usize {
            let rec = 12 + i * 16;
            if self.data.get(rec..rec.checked_add(4)?) == Some(tag.as_slice()) {
                let off = be_u32(self.data, rec + 8)? as usize;
                let len = be_u32(self.data, rec + 12)? as usize;
                return self.data.get(off..off.checked_add(len)?);
            }
        }
        None
    }

    /// Builds a [`Kerning`](crate::kerning::Kerning) view over this font's
    /// `kern` and `GPOS` tables (either or both may be absent).
    #[must_use]
    pub fn kerning(&self) -> crate::kerning::Kerning<'a> {
        crate::kerning::Kerning::from_tables(self.table_data(*b"kern"), self.table_data(*b"GPOS"))
    }

    /// Horizontal advance width of a glyph, in design units (`hmtx`).
    ///
    /// For glyphs at or beyond `numberOfHMetrics`, the last metric's advance is
    /// repeated (the `TrueType` convention for monospaced trailing runs).
    #[must_use]
    pub fn advance_width(&self, gid: u16) -> u16 {
        let last = self.num_h_metrics.saturating_sub(1);
        let idx = gid.min(last) as usize;
        be_u16(self.data, self.hmtx + idx * 4).unwrap_or(0)
    }

    /// Decodes a glyph's outline (contours + metrics) in design units.
    ///
    /// Handles both simple and composite glyphs; composites are assembled from
    /// their components recursively (bounded by `Self::MAX_COMPOSITE_DEPTH`).
    ///
    /// # Errors
    ///
    /// [`FontError::GlyphOutOfRange`] if `gid >= num_glyphs`, or
    /// [`FontError::Truncated`] on malformed glyph data.
    pub fn glyph_outline(&self, gid: u16) -> Result<Outline, FontError> {
        self.glyph_outline_at(gid, 0)
    }

    /// Maximum composite-glyph nesting depth. Composites reference other glyphs,
    /// which may themselves be composite; this bounds recursion (and defends
    /// against a malformed font whose components cycle).
    const MAX_COMPOSITE_DEPTH: u8 = 8;

    /// Decodes glyph `gid`, dispatching to the simple or composite decoder.
    /// `depth` tracks composite nesting for the recursion guard.
    fn glyph_outline_at(&self, gid: u16, depth: u8) -> Result<Outline, FontError> {
        if gid >= self.num_glyphs {
            return Err(FontError::GlyphOutOfRange);
        }
        let (start, end) = self.loca_range(gid)?;
        let advance = self.advance_width(gid);
        if start >= end {
            // Empty glyph (no outline) — e.g. the space.
            return Ok(Outline {
                contours: Vec::new(),
                advance,
                x_min: 0,
                y_min: 0,
                x_max: 0,
                y_max: 0,
            });
        }
        let g = self
            .data
            .get(self.glyf + start..self.glyf + end)
            .ok_or(FontError::Truncated)?;
        // numberOfContours < 0 marks a composite (compound) glyph.
        if be_i16(g, 0).ok_or(FontError::Truncated)? < 0 {
            self.parse_composite_glyph(g, advance, depth)
        } else {
            parse_simple_glyph(g, advance)
        }
    }

    /// Assembles a composite (compound) glyph: each component references another
    /// glyph, positioned by a 2×2 `F2Dot14` transform plus an X/Y offset. The
    /// referenced outlines are decoded recursively and their transformed
    /// contours concatenated (`OpenType` `glyf`, composite description).
    ///
    /// Point-matching component offsets (the rare `ARGS_ARE_XY_VALUES`-clear
    /// form) are treated as a zero offset — accented Latin, which is the reason
    /// this path exists, always uses XY offsets.
    fn parse_composite_glyph(
        &self,
        g: &[u8],
        advance: u16,
        depth: u8,
    ) -> Result<Outline, FontError> {
        // Component-record flag bits (OpenType).
        const ARG_1_AND_2_ARE_WORDS: u16 = 0x0001;
        const ARGS_ARE_XY_VALUES: u16 = 0x0002;
        const WE_HAVE_A_SCALE: u16 = 0x0008;
        const MORE_COMPONENTS: u16 = 0x0020;
        const WE_HAVE_AN_X_AND_Y_SCALE: u16 = 0x0040;
        const WE_HAVE_A_TWO_BY_TWO: u16 = 0x0080;

        // Bounding box from the (spec-authoritative) composite header.
        let x_min = be_i16(g, 2).ok_or(FontError::Truncated)?;
        let y_min = be_i16(g, 4).ok_or(FontError::Truncated)?;
        let x_max = be_i16(g, 6).ok_or(FontError::Truncated)?;
        let y_max = be_i16(g, 8).ok_or(FontError::Truncated)?;

        let mut contours: Vec<Vec<Point>> = Vec::new();
        if depth >= Self::MAX_COMPOSITE_DEPTH {
            // Too deep / cyclic — stop expanding, keep what the bbox promises.
            return Ok(Outline {
                contours,
                advance,
                x_min,
                y_min,
                x_max,
                y_max,
            });
        }

        let mut pos = 10; // after numberOfContours + 4 bbox i16
        loop {
            let flags = be_u16(g, pos).ok_or(FontError::Truncated)?;
            let component_gid = be_u16(g, pos + 2).ok_or(FontError::Truncated)?;
            pos += 4;

            // Arguments: dx/dy (or point indices, which we do not follow).
            let (arg1, arg2) = if flags & ARG_1_AND_2_ARE_WORDS != 0 {
                let a = be_i16(g, pos).ok_or(FontError::Truncated)? as i32;
                let b = be_i16(g, pos + 2).ok_or(FontError::Truncated)? as i32;
                pos += 4;
                (a, b)
            } else {
                let a = *g.get(pos).ok_or(FontError::Truncated)? as i8 as i32;
                let b = *g.get(pos + 1).ok_or(FontError::Truncated)? as i8 as i32;
                pos += 2;
                (a, b)
            };
            let (dx, dy) = if flags & ARGS_ARE_XY_VALUES != 0 {
                (arg1, arg2)
            } else {
                (0, 0) // point-matching: unsupported, treat as no offset
            };

            // 2×2 transform in F2Dot14 fixed point (unit = 1<<14 = 16384).
            // x' = xx*x + yx*y + dx ; y' = xy*x + yy*y + dy (OpenType a,b,c,d).
            let (mut xx, mut xy, mut yx, mut yy) = (16384_i32, 0_i32, 0_i32, 16384_i32);
            if flags & WE_HAVE_A_SCALE != 0 {
                let scale = be_i16(g, pos).ok_or(FontError::Truncated)? as i32;
                pos += 2;
                xx = scale;
                yy = scale;
            } else if flags & WE_HAVE_AN_X_AND_Y_SCALE != 0 {
                xx = be_i16(g, pos).ok_or(FontError::Truncated)? as i32;
                yy = be_i16(g, pos + 2).ok_or(FontError::Truncated)? as i32;
                pos += 4;
            } else if flags & WE_HAVE_A_TWO_BY_TWO != 0 {
                xx = be_i16(g, pos).ok_or(FontError::Truncated)? as i32;
                xy = be_i16(g, pos + 2).ok_or(FontError::Truncated)? as i32;
                yx = be_i16(g, pos + 4).ok_or(FontError::Truncated)? as i32;
                yy = be_i16(g, pos + 6).ok_or(FontError::Truncated)? as i32;
                pos += 8;
            }

            // Decode the referenced glyph and splice its transformed contours.
            // The identity transform (xx=yy=16384, xy=yx=0) reproduces points
            // exactly: (16384 * x) >> 14 == x.
            let child = self.glyph_outline_at(component_gid, depth + 1)?;
            for contour in &child.contours {
                let mut out = Vec::with_capacity(contour.len());
                for p in contour {
                    let px = p.x as i32;
                    let py = p.y as i32;
                    let nx = ((xx * px + yx * py) >> 14) + dx;
                    let ny = ((xy * px + yy * py) >> 14) + dy;
                    out.push(Point {
                        x: nx as i16,
                        y: ny as i16,
                        on_curve: p.on_curve,
                    });
                }
                contours.push(out);
            }

            if flags & MORE_COMPONENTS == 0 {
                break;
            }
        }

        Ok(Outline {
            contours,
            advance,
            x_min,
            y_min,
            x_max,
            y_max,
        })
    }

    fn loca_range(&self, gid: u16) -> Result<(usize, usize), FontError> {
        let i = gid as usize;
        if self.long_loca {
            let a = be_u32(self.data, self.loca + i * 4).ok_or(FontError::Truncated)? as usize;
            let b =
                be_u32(self.data, self.loca + (i + 1) * 4).ok_or(FontError::Truncated)? as usize;
            Ok((a, b))
        } else {
            // Short loca stores offset / 2.
            let a = be_u16(self.data, self.loca + i * 2).ok_or(FontError::Truncated)? as usize * 2;
            let b = be_u16(self.data, self.loca + (i + 1) * 2).ok_or(FontError::Truncated)?
                as usize
                * 2;
            Ok((a, b))
        }
    }

    fn cmap_format4_subtable(&self) -> Option<&'a [u8]> {
        let base = self.cmap;
        let num_tables = be_u16(self.data, base + 2)?;
        for i in 0..num_tables as usize {
            let rec = base + 4 + i * 8;
            let sub_off = be_u32(self.data, rec + 4)? as usize;
            let sub = base + sub_off;
            if be_u16(self.data, sub)? == 4 {
                let len = be_u16(self.data, sub + 2)? as usize;
                return self.data.get(sub..sub.checked_add(len)?);
            }
        }
        None
    }
}

/// Format-4 `cmap` lookup: maps a BMP code point to a glyph id.
fn cmap4_lookup(sub: &[u8], c: u32) -> Option<u16> {
    if c > 0xFFFF {
        return None;
    }
    let c = c as u16;
    let seg_x2 = be_u16(sub, 6)? as usize;
    let seg_count = seg_x2 >> 1;
    let end_base = 14;
    let start_base = end_base + seg_x2 + 2; // endCode[] + reservedPad
    let delta_base = start_base + seg_x2;
    let range_base = delta_base + seg_x2;
    for i in 0..seg_count {
        let end = be_u16(sub, end_base + i * 2)?;
        if c <= end {
            let start = be_u16(sub, start_base + i * 2)?;
            if c < start {
                return None; // in a gap between segments
            }
            let id_delta = be_i16(sub, delta_base + i * 2)?;
            let id_range = be_u16(sub, range_base + i * 2)? as usize;
            if id_range == 0 {
                return Some(((c as i32 + id_delta as i32) & 0xFFFF) as u16);
            }
            // glyphIdArray indirection.
            let gi = range_base + i * 2 + id_range + (c - start) as usize * 2;
            let g = be_u16(sub, gi)?;
            if g == 0 {
                return Some(0);
            }
            return Some(((g as i32 + id_delta as i32) & 0xFFFF) as u16);
        }
    }
    None
}

/// Decodes a simple (non-composite) glyph from its `glyf` slice.
fn parse_simple_glyph(g: &[u8], advance: u16) -> Result<Outline, FontError> {
    let num_contours = be_i16(g, 0).ok_or(FontError::Truncated)?;
    if num_contours < 0 {
        return Err(FontError::UnsupportedCompositeGlyph);
    }
    let nc = num_contours as usize;
    let x_min = be_i16(g, 2).ok_or(FontError::Truncated)?;
    let y_min = be_i16(g, 4).ok_or(FontError::Truncated)?;
    let x_max = be_i16(g, 6).ok_or(FontError::Truncated)?;
    let y_max = be_i16(g, 8).ok_or(FontError::Truncated)?;

    let mut pos = 10;
    let mut end_pts = Vec::with_capacity(nc);
    for _ in 0..nc {
        end_pts.push(be_u16(g, pos).ok_or(FontError::Truncated)?);
        pos += 2;
    }
    let num_points = end_pts.last().map_or(0, |&e| e as usize + 1);

    // Skip the hinting instruction stream.
    let instr_len = be_u16(g, pos).ok_or(FontError::Truncated)? as usize;
    pos = pos.checked_add(2 + instr_len).ok_or(FontError::Truncated)?;

    // Flags (with the 0x08 repeat run-length).
    let mut flags = Vec::with_capacity(num_points);
    while flags.len() < num_points {
        let f = *g.get(pos).ok_or(FontError::Truncated)?;
        pos += 1;
        flags.push(f);
        if f & 0x08 != 0 {
            let repeats = *g.get(pos).ok_or(FontError::Truncated)?;
            pos += 1;
            for _ in 0..repeats {
                if flags.len() < num_points {
                    flags.push(f);
                }
            }
        }
    }

    // X coordinates: 0x02 = short (u8, sign from 0x10); else 0x10 set = repeat
    // previous X, clear = i16 delta.
    let mut xs = Vec::with_capacity(num_points);
    let mut x = 0i32;
    for &f in &flags {
        if f & 0x02 != 0 {
            let d = *g.get(pos).ok_or(FontError::Truncated)? as i32;
            pos += 1;
            x += if f & 0x10 != 0 { d } else { -d };
        } else if f & 0x10 == 0 {
            x += be_i16(g, pos).ok_or(FontError::Truncated)? as i32;
            pos += 2;
        }
        xs.push(x);
    }

    // Y coordinates: 0x04 = short, 0x20 = sign/repeat.
    let mut ys = Vec::with_capacity(num_points);
    let mut y = 0i32;
    for &f in &flags {
        if f & 0x04 != 0 {
            let d = *g.get(pos).ok_or(FontError::Truncated)? as i32;
            pos += 1;
            y += if f & 0x20 != 0 { d } else { -d };
        } else if f & 0x20 == 0 {
            y += be_i16(g, pos).ok_or(FontError::Truncated)? as i32;
            pos += 2;
        }
        ys.push(y);
    }

    // Split the flat point list into contours via endPtsOfContours.
    let mut contours = Vec::with_capacity(nc);
    let mut start = 0usize;
    for &e in &end_pts {
        let end_idx = e as usize;
        let mut contour = Vec::new();
        let mut i = start;
        while i <= end_idx {
            let px = *xs.get(i).ok_or(FontError::Truncated)?;
            let py = *ys.get(i).ok_or(FontError::Truncated)?;
            let on = flags.get(i).is_some_and(|fl| fl & 0x01 != 0);
            contour.push(Point {
                x: px as i16,
                y: py as i16,
                on_curve: on,
            });
            i += 1;
        }
        contours.push(contour);
        start = end_idx + 1;
    }

    Ok(Outline {
        contours,
        advance,
        x_min,
        y_min,
        x_max,
        y_max,
    })
}

/// Shared synthetic in-memory font used by host tests across crate modules.
#[cfg(test)]
pub(crate) mod test_support {
    use alloc::vec::Vec;

    fn pu16(v: &mut Vec<u8>, x: u16) {
        v.extend_from_slice(&x.to_be_bytes());
    }
    fn pi16(v: &mut Vec<u8>, x: i16) {
        v.extend_from_slice(&x.to_be_bytes());
    }
    fn pu32(v: &mut Vec<u8>, x: u32) {
        v.extend_from_slice(&x.to_be_bytes());
    }

    /// Builds a minimal-but-valid glyf-based font with 2 glyphs:
    /// glyph 0 = empty (.notdef-ish), glyph 1 = a 512×512 square mapped from 'A'.
    // `pub(crate)` (not `pub`) keeps this test helper crate-internal; the module
    // is already `pub(crate)`, so clippy flags the modifier as redundant.
    #[allow(clippy::redundant_pub_crate)]
    pub(crate) fn build_test_font() -> Vec<u8> {
        let mut head = alloc::vec![0u8; 54];
        head[18..20].copy_from_slice(&1024u16.to_be_bytes()); // unitsPerEm
        // indexToLocFormat at 50 stays 0 (short loca).

        let mut maxp = alloc::vec![0u8; 32];
        maxp[0..4].copy_from_slice(&0x0001_0000u32.to_be_bytes());
        maxp[4..6].copy_from_slice(&2u16.to_be_bytes()); // numGlyphs

        let mut hhea = alloc::vec![0u8; 36];
        hhea[34..36].copy_from_slice(&2u16.to_be_bytes()); // numberOfHMetrics

        let mut hmtx = Vec::new();
        pu16(&mut hmtx, 0);
        pi16(&mut hmtx, 0); // glyph 0: advance 0
        pu16(&mut hmtx, 600);
        pi16(&mut hmtx, 0); // glyph 1: advance 600

        // glyph 1: 1 contour, 4 on-curve points (square), i16 deltas.
        let mut glyf = Vec::new();
        pi16(&mut glyf, 1); // numberOfContours
        pi16(&mut glyf, 0);
        pi16(&mut glyf, 0);
        pi16(&mut glyf, 512);
        pi16(&mut glyf, 512); // bbox
        pu16(&mut glyf, 3); // endPtsOfContours[0] -> 4 points
        pu16(&mut glyf, 0); // instructionLength
        glyf.extend_from_slice(&[0x01, 0x01, 0x01, 0x01]); // flags: on-curve, i16
        pi16(&mut glyf, 0);
        pi16(&mut glyf, 512);
        pi16(&mut glyf, 0);
        pi16(&mut glyf, -512); // x deltas -> 0,512,512,0
        pi16(&mut glyf, 0);
        pi16(&mut glyf, 0);
        pi16(&mut glyf, 512);
        pi16(&mut glyf, 0); // y deltas -> 0,0,512,512

        let mut loca = Vec::new();
        pu16(&mut loca, 0); // glyph 0 start
        pu16(&mut loca, 0); // glyph 1 start (glyph 0 empty)
        pu16(&mut loca, (glyf.len() >> 1) as u16); // end (offset / 2)

        let mut cmap = Vec::new();
        pu16(&mut cmap, 0); // version
        pu16(&mut cmap, 1); // numTables
        pu16(&mut cmap, 3);
        pu16(&mut cmap, 1); // platform 3, encoding 1
        pu32(&mut cmap, 12); // subtable offset
        let mut sub = Vec::new();
        pu16(&mut sub, 4); // format
        pu16(&mut sub, 32); // length
        pu16(&mut sub, 0); // language
        pu16(&mut sub, 4); // segCountX2 (2 segments)
        pu16(&mut sub, 4);
        pu16(&mut sub, 1);
        pu16(&mut sub, 0); // searchRange/entrySelector/rangeShift (ignored)
        pu16(&mut sub, 0x41);
        pu16(&mut sub, 0xFFFF); // endCode
        pu16(&mut sub, 0); // reservedPad
        pu16(&mut sub, 0x41);
        pu16(&mut sub, 0xFFFF); // startCode
        pi16(&mut sub, -64);
        pi16(&mut sub, 1); // idDelta: 'A'(0x41) -> 1
        pu16(&mut sub, 0);
        pu16(&mut sub, 0); // idRangeOffset
        cmap.extend_from_slice(&sub);

        let tables: [(&[u8; 4], Vec<u8>); 7] = [
            (b"head", head),
            (b"maxp", maxp),
            (b"hhea", hhea),
            (b"hmtx", hmtx),
            (b"loca", loca),
            (b"glyf", glyf),
            (b"cmap", cmap),
        ];
        let num = tables.len();

        let mut font = Vec::new();
        pu32(&mut font, 0x0001_0000); // sfnt version
        pu16(&mut font, num as u16);
        pu16(&mut font, 0);
        pu16(&mut font, 0);
        pu16(&mut font, 0); // search hints (ignored)
        font.resize(12 + num * 16, 0); // reserve the table directory

        for (i, (tag, data)) in tables.iter().enumerate() {
            while font.len() % 4 != 0 {
                font.push(0);
            }
            let off = font.len();
            let rec = 12 + i * 16;
            font[rec..rec + 4].copy_from_slice(*tag);
            font[rec + 8..rec + 12].copy_from_slice(&(off as u32).to_be_bytes());
            font[rec + 12..rec + 16].copy_from_slice(&(data.len() as u32).to_be_bytes());
            font.extend_from_slice(data);
        }
        font
    }

    /// Builds a glyf font with 3 glyphs: 0 = empty, 1 = the 512×512 square,
    /// 2 = a **composite** glyph that references glyph 1 with an identity
    /// transform and an XY offset of (+100, +200), mapped from 'A'. Exercises
    /// the compound-glyph assembler (WS7-19.3).
    // Verbose but linear synthetic-font construction (byte layout by hand).
    #[allow(clippy::redundant_pub_crate, clippy::too_many_lines)]
    pub(crate) fn build_composite_test_font() -> Vec<u8> {
        let mut head = alloc::vec![0u8; 54];
        head[18..20].copy_from_slice(&1024u16.to_be_bytes()); // unitsPerEm

        let mut maxp = alloc::vec![0u8; 32];
        maxp[0..4].copy_from_slice(&0x0001_0000u32.to_be_bytes());
        maxp[4..6].copy_from_slice(&3u16.to_be_bytes()); // numGlyphs

        let mut hhea = alloc::vec![0u8; 36];
        hhea[34..36].copy_from_slice(&3u16.to_be_bytes()); // numberOfHMetrics

        let mut hmtx = Vec::new();
        pu16(&mut hmtx, 0);
        pi16(&mut hmtx, 0); // glyph 0
        pu16(&mut hmtx, 600);
        pi16(&mut hmtx, 0); // glyph 1
        pu16(&mut hmtx, 650);
        pi16(&mut hmtx, 0); // glyph 2

        // glyph 1: the simple 512×512 square (as in build_test_font).
        let mut g1 = Vec::new();
        pi16(&mut g1, 1);
        pi16(&mut g1, 0);
        pi16(&mut g1, 0);
        pi16(&mut g1, 512);
        pi16(&mut g1, 512);
        pu16(&mut g1, 3);
        pu16(&mut g1, 0);
        g1.extend_from_slice(&[0x01, 0x01, 0x01, 0x01]);
        pi16(&mut g1, 0);
        pi16(&mut g1, 512);
        pi16(&mut g1, 0);
        pi16(&mut g1, -512);
        pi16(&mut g1, 0);
        pi16(&mut g1, 0);
        pi16(&mut g1, 512);
        pi16(&mut g1, 0);

        // glyph 2: composite -> component references glyph 1 at (+100,+200).
        let mut g2 = Vec::new();
        pi16(&mut g2, -1); // numberOfContours < 0 => composite
        pi16(&mut g2, 100);
        pi16(&mut g2, 200);
        pi16(&mut g2, 612);
        pi16(&mut g2, 712); // bbox = square + offset
        // flags: ARG_1_AND_2_ARE_WORDS (0x0001) | ARGS_ARE_XY_VALUES (0x0002).
        pu16(&mut g2, 0x0003);
        pu16(&mut g2, 1); // component glyphIndex = 1
        pi16(&mut g2, 100); // dx
        pi16(&mut g2, 200); // dy

        let mut glyf = Vec::new();
        glyf.extend_from_slice(&g1);
        glyf.extend_from_slice(&g2);

        let mut loca = Vec::new();
        pu16(&mut loca, 0); // glyph 0 start (empty)
        pu16(&mut loca, 0); // glyph 1 start
        pu16(&mut loca, (g1.len() >> 1) as u16); // glyph 2 start
        pu16(&mut loca, (glyf.len() >> 1) as u16); // end

        // cmap: 'A' (0x41) -> glyph 2 via idDelta = 2 - 0x41 = -63.
        let mut cmap = Vec::new();
        pu16(&mut cmap, 0);
        pu16(&mut cmap, 1);
        pu16(&mut cmap, 3);
        pu16(&mut cmap, 1);
        pu32(&mut cmap, 12);
        let mut sub = Vec::new();
        pu16(&mut sub, 4);
        pu16(&mut sub, 32);
        pu16(&mut sub, 0);
        pu16(&mut sub, 4);
        pu16(&mut sub, 4);
        pu16(&mut sub, 1);
        pu16(&mut sub, 0);
        pu16(&mut sub, 0x41);
        pu16(&mut sub, 0xFFFF);
        pu16(&mut sub, 0);
        pu16(&mut sub, 0x41);
        pu16(&mut sub, 0xFFFF);
        pi16(&mut sub, -63); // 'A' -> 2
        pi16(&mut sub, 1);
        pu16(&mut sub, 0);
        pu16(&mut sub, 0);
        cmap.extend_from_slice(&sub);

        let tables: [(&[u8; 4], Vec<u8>); 7] = [
            (b"head", head),
            (b"maxp", maxp),
            (b"hhea", hhea),
            (b"hmtx", hmtx),
            (b"loca", loca),
            (b"glyf", glyf),
            (b"cmap", cmap),
        ];
        let num = tables.len();

        let mut font = Vec::new();
        pu32(&mut font, 0x0001_0000);
        pu16(&mut font, num as u16);
        pu16(&mut font, 0);
        pu16(&mut font, 0);
        pu16(&mut font, 0);
        font.resize(12 + num * 16, 0);

        for (i, (tag, data)) in tables.iter().enumerate() {
            while font.len() % 4 != 0 {
                font.push(0);
            }
            let off = font.len();
            let rec = 12 + i * 16;
            font[rec..rec + 4].copy_from_slice(*tag);
            font[rec + 8..rec + 12].copy_from_slice(&(off as u32).to_be_bytes());
            font[rec + 12..rec + 16].copy_from_slice(&(data.len() as u32).to_be_bytes());
            font.extend_from_slice(data);
        }
        font
    }
}

#[cfg(test)]
mod tests {
    use super::{
        test_support::{build_composite_test_font, build_test_font},
        *,
    };

    #[test]
    fn composite_glyph_assembles_translated_component() {
        let f = build_composite_test_font();
        let font = Font::parse(&f).unwrap();
        assert_eq!(font.num_glyphs(), 3);
        assert_eq!(font.glyph_index('A'), Some(2));

        let o = font.glyph_outline(2).unwrap();
        assert_eq!(o.advance, 650);
        // Composite bbox from the header.
        assert_eq!((o.x_min, o.y_min, o.x_max, o.y_max), (100, 200, 612, 712));
        // One contour spliced from the referenced square, translated (+100,+200).
        assert_eq!(o.contours.len(), 1);
        let c = &o.contours[0];
        assert_eq!(c.len(), 4);
        assert_eq!((c[0].x, c[0].y), (100, 200)); // (0,0) + offset
        assert_eq!((c[1].x, c[1].y), (612, 200)); // (512,0) + offset
        assert_eq!((c[2].x, c[2].y), (612, 712)); // (512,512) + offset
        assert_eq!((c[3].x, c[3].y), (100, 712)); // (0,512) + offset
        assert!(c.iter().all(|p| p.on_curve));
    }

    #[test]
    fn composite_referenced_simple_glyph_still_decodes_standalone() {
        // Decoding the component directly is unaffected by the composite path.
        let f = build_composite_test_font();
        let font = Font::parse(&f).unwrap();
        let o = font.glyph_outline(1).unwrap();
        assert_eq!(o.contours.len(), 1);
        assert_eq!((o.x_max, o.y_max), (512, 512));
    }

    #[test]
    fn parses_core_metrics() {
        let f = build_test_font();
        let font = Font::parse(&f).unwrap();
        assert_eq!(font.units_per_em(), 1024);
        assert_eq!(font.num_glyphs(), 2);
    }

    #[test]
    fn cmap_maps_known_char_and_rejects_unmapped() {
        let f = build_test_font();
        let font = Font::parse(&f).unwrap();
        assert_eq!(font.glyph_index('A'), Some(1));
        assert_eq!(font.glyph_index('B'), None);
    }

    #[test]
    fn hmtx_advance_widths() {
        let f = build_test_font();
        let font = Font::parse(&f).unwrap();
        assert_eq!(font.advance_width(1), 600);
        assert_eq!(font.advance_width(0), 0);
        // Beyond numberOfHMetrics repeats the last advance.
        assert_eq!(font.advance_width(50), 600);
    }

    #[test]
    fn glyph_outline_is_the_square() {
        let f = build_test_font();
        let font = Font::parse(&f).unwrap();
        let o = font.glyph_outline(1).unwrap();
        assert_eq!(o.advance, 600);
        assert_eq!((o.x_max, o.y_max), (512, 512));
        assert_eq!(o.contours.len(), 1);
        let c = &o.contours[0];
        assert_eq!(c.len(), 4);
        assert_eq!((c[0].x, c[0].y), (0, 0));
        assert_eq!((c[1].x, c[1].y), (512, 0));
        assert_eq!((c[2].x, c[2].y), (512, 512));
        assert_eq!((c[3].x, c[3].y), (0, 512));
        assert!(c.iter().all(|p| p.on_curve));
    }

    #[test]
    fn empty_glyph_is_space_like() {
        let f = build_test_font();
        let font = Font::parse(&f).unwrap();
        assert!(font.glyph_outline(0).unwrap().is_empty());
    }

    #[test]
    fn rejects_bad_input() {
        assert_eq!(Font::parse(&[0u8, 0]).unwrap_err(), FontError::Truncated);
        // Valid header length but CFF/'OTTO' sfnt version.
        let mut otto = build_test_font();
        otto[0..4].copy_from_slice(&0x4F54_544Fu32.to_be_bytes());
        assert_eq!(
            Font::parse(&otto).unwrap_err(),
            FontError::UnsupportedFormat
        );
        // Out-of-range glyph id.
        let f = build_test_font();
        let font = Font::parse(&f).unwrap();
        assert_eq!(font.glyph_outline(99), Err(FontError::GlyphOutOfRange));
    }
}
