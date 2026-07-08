//! Pair kerning extraction from the legacy `kern` table and `GPOS` (WS7-03.6).
//!
//! Horizontal layout needs, for each adjacent glyph pair, an extra advance
//! adjustment (kerning) on top of the per-glyph advance width
//! ([`crate::font::Font::advance_width`]). Modern `OpenType` fonts carry this in
//! the `GPOS` table's pair-adjustment lookups; older fonts use the legacy `kern`
//! table. This module extracts both:
//!
//! * [`KernTable`] — the legacy `kern` table, version 0, format-0 (horizontal)
//!   subtables: an explicit, sorted list of `(left, right) → adjustment` pairs.
//! * [`GposKerning`] — `GPOS` pair adjustment (`LookupType` 2, including the
//!   `LookupType` 9 *extension* wrapper), both `PairPos` formats: format 1
//!   (explicit per-glyph pair sets) and format 2 (class-based pair matrices),
//!   with `Coverage` formats 1/2 and `ClassDef` formats 1/2. Only the horizontal
//!   advance (`XAdvance`) of the first glyph is read, which is what kerning uses.
//! * [`Kerning`] — a combined view: when `GPOS` is present it supersedes the
//!   `kern` table (the `OpenType` rule), otherwise the `kern` table is used.
//!
//! Every read is bounds-checked, so malformed tables yield "no kerning" (`0`)
//! rather than a panic. `no_std + alloc`, dep-free.

use alloc::{collections::BTreeMap, vec::Vec};

use crate::font::{be_i16, be_u16, be_u32};

/// Bit in a `ValueRecord`'s value format selecting the `XAdvance` field.
const VF_X_ADVANCE: u16 = 0x0004;
/// Bit selecting the `XPlacement` field (precedes `XAdvance` in a record).
const VF_X_PLACEMENT: u16 = 0x0001;
/// Bit selecting the `YPlacement` field (precedes `XAdvance` in a record).
const VF_Y_PLACEMENT: u16 = 0x0002;

/// A combined kerning view over a font's `kern` and `GPOS` tables.
///
/// Construct via [`Kerning::from_tables`] or [`crate::font::Font::kerning`].
#[derive(Debug, Clone)]
pub struct Kerning<'a> {
    kern: Option<KernTable>,
    gpos: Option<GposKerning<'a>>,
}

impl<'a> Kerning<'a> {
    /// Builds a kerning view from the optional raw `kern` and `GPOS` table bytes.
    #[must_use]
    pub fn from_tables(kern: Option<&[u8]>, gpos: Option<&'a [u8]>) -> Self {
        Self {
            kern: kern.and_then(KernTable::parse),
            gpos: gpos.and_then(GposKerning::parse),
        }
    }

    /// `true` if neither table provided any usable kerning.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.kern.is_none() && self.gpos.is_none()
    }

    /// Horizontal kerning adjustment (design units) to add between `left` and
    /// `right`, or `0` if the pair is not kerned.
    ///
    /// When `GPOS` kerning is present it is authoritative and the legacy `kern`
    /// table is ignored (the `OpenType` precedence rule).
    #[must_use]
    pub fn adjustment(&self, left: u16, right: u16) -> i32 {
        if let Some(gpos) = &self.gpos {
            return i32::from(gpos.adjustment(left, right));
        }
        if let Some(kern) = &self.kern {
            return i32::from(kern.adjustment(left, right));
        }
        0
    }
}

/// The legacy `kern` table (version 0), parsed to a flat pair map.
#[derive(Debug, Clone)]
pub struct KernTable {
    pairs: BTreeMap<(u16, u16), i16>,
}

impl KernTable {
    /// Parses a `kern` table, collecting every horizontal format-0 subtable.
    ///
    /// Returns `None` for the Apple version-1 header, a malformed table, or one
    /// carrying no horizontal format-0 pairs.
    #[must_use]
    pub fn parse(data: &[u8]) -> Option<Self> {
        // Only the Microsoft/OpenType version-0 header is supported; Apple's
        // version-1 (u32 0x00010000) header layout is out of scope.
        if be_u16(data, 0)? != 0 {
            return None;
        }
        let n_tables = be_u16(data, 2)? as usize;
        let mut pairs = BTreeMap::new();
        let mut off = 4;
        for _ in 0..n_tables {
            let length = be_u16(data, off + 2)? as usize;
            let coverage = be_u16(data, off + 4)?;
            let format = coverage >> 8;
            let horizontal = coverage & 0x0001 != 0;
            if format == 0 && horizontal {
                let n_pairs = be_u16(data, off + 6)? as usize;
                // Subtable header (6) + format-0 search header (8) = 14 bytes.
                let mut p = off + 14;
                for _ in 0..n_pairs {
                    let left = be_u16(data, p)?;
                    let right = be_u16(data, p + 2)?;
                    let value = be_i16(data, p + 4)?;
                    pairs.insert((left, right), value);
                    p += 6;
                }
            }
            if length == 0 {
                break; // guard against a malformed zero length looping forever
            }
            off += length;
        }
        if pairs.is_empty() {
            None
        } else {
            Some(Self { pairs })
        }
    }

    /// Kerning adjustment for `(left, right)`, or `0` if the pair is absent.
    #[must_use]
    pub fn adjustment(&self, left: u16, right: u16) -> i16 {
        self.pairs.get(&(left, right)).copied().unwrap_or(0)
    }
}

/// `GPOS` pair-adjustment kerning: the offsets of every `PairPos` subtable found
/// by scanning `LookupType` 2 (and `LookupType` 9 extension) lookups.
#[derive(Debug, Clone)]
pub struct GposKerning<'a> {
    data: &'a [u8],
    subtables: Vec<usize>,
}

impl<'a> GposKerning<'a> {
    /// Parses a `GPOS` table, collecting every pair-adjustment subtable offset.
    ///
    /// Returns `None` for a non-1.x `GPOS`, a malformed table, or one with no
    /// pair-adjustment lookups.
    #[must_use]
    pub fn parse(data: &'a [u8]) -> Option<Self> {
        if be_u16(data, 0)? != 1 {
            return None; // major version must be 1
        }
        let lookup_list = be_u16(data, 8)? as usize;
        let lookup_count = be_u16(data, lookup_list)? as usize;
        let mut subtables = Vec::new();
        for i in 0..lookup_count {
            let lk = lookup_list + be_u16(data, lookup_list + 2 + i * 2)? as usize;
            let lookup_type = be_u16(data, lk)?;
            let sub_count = be_u16(data, lk + 4)? as usize;
            for j in 0..sub_count {
                let sub = lk + be_u16(data, lk + 6 + j * 2)? as usize;
                match lookup_type {
                    2 => subtables.push(sub),
                    9 => {
                        // Extension: posFormat(2), extensionLookupType(2),
                        // extensionOffset(u32, from the extension subtable start).
                        if be_u16(data, sub + 2)? == 2 {
                            let ext = be_u32(data, sub + 4)? as usize;
                            subtables.push(sub + ext);
                        }
                    }
                    _ => {}
                }
            }
        }
        if subtables.is_empty() {
            None
        } else {
            Some(Self { data, subtables })
        }
    }

    /// Kerning adjustment for `(left, right)` from the first subtable that
    /// supplies a non-zero `XAdvance`, or `0`.
    #[must_use]
    pub fn adjustment(&self, left: u16, right: u16) -> i16 {
        for &s in &self.subtables {
            if let Some(v) = pairpos_adjustment(self.data, s, left, right) {
                if v != 0 {
                    return v;
                }
            }
        }
        0
    }
}

/// Dispatches a `PairPos` subtable at `s` by its `posFormat`.
fn pairpos_adjustment(data: &[u8], s: usize, left: u16, right: u16) -> Option<i16> {
    match be_u16(data, s)? {
        1 => pairpos_format1(data, s, left, right),
        2 => pairpos_format2(data, s, left, right),
        _ => None,
    }
}

/// `PairPos` format 1: per-first-glyph pair sets reached through `Coverage`.
fn pairpos_format1(data: &[u8], s: usize, left: u16, right: u16) -> Option<i16> {
    let cov_off = be_u16(data, s + 2)? as usize;
    let value_format1 = be_u16(data, s + 4)?;
    let value_format2 = be_u16(data, s + 6)?;
    let pair_set_count = be_u16(data, s + 8)? as usize;

    let index = coverage_index(data, s + cov_off, left)?;
    if index >= pair_set_count {
        return None;
    }
    let pair_set = s + be_u16(data, s + 10 + index * 2)? as usize;
    let pair_value_count = be_u16(data, pair_set)? as usize;
    let record_size = 2 + value_size(value_format1) + value_size(value_format2);
    for k in 0..pair_value_count {
        let rec = pair_set + 2 + k * record_size;
        if be_u16(data, rec)? == right {
            return read_x_advance(data, rec + 2, value_format1);
        }
    }
    Some(0)
}

/// `PairPos` format 2: a class×class matrix of pair adjustments.
fn pairpos_format2(data: &[u8], s: usize, left: u16, right: u16) -> Option<i16> {
    let cov_off = be_u16(data, s + 2)? as usize;
    let value_format1 = be_u16(data, s + 4)?;
    let value_format2 = be_u16(data, s + 6)?;
    let class_def1 = be_u16(data, s + 8)? as usize;
    let class_def2 = be_u16(data, s + 10)? as usize;
    let class1_count = be_u16(data, s + 12)? as usize;
    let class2_count = be_u16(data, s + 14)? as usize;

    // The subtable applies only to first glyphs listed in its coverage.
    coverage_index(data, s + cov_off, left)?;
    let class1 = classdef_lookup(data, s + class_def1, left)? as usize;
    let class2 = classdef_lookup(data, s + class_def2, right)? as usize;
    if class1 >= class1_count || class2 >= class2_count {
        return Some(0);
    }
    let class2_size = value_size(value_format1) + value_size(value_format2);
    let record_start = s + 16 + class1 * (class2_count * class2_size) + class2 * class2_size;
    read_x_advance(data, record_start, value_format1)
}

/// Reads the `XAdvance` field of a `ValueRecord` at `vr`, given its value
/// format, or `0` when the format omits `XAdvance`.
fn read_x_advance(data: &[u8], vr: usize, value_format: u16) -> Option<i16> {
    if value_format & VF_X_ADVANCE == 0 {
        return Some(0);
    }
    // XAdvance follows XPlacement / YPlacement when those are present.
    let mut off = 0;
    if value_format & VF_X_PLACEMENT != 0 {
        off += 2;
    }
    if value_format & VF_Y_PLACEMENT != 0 {
        off += 2;
    }
    be_i16(data, vr + off)
}

/// Size in bytes of a `ValueRecord` for the given value format (2 per set bit).
fn value_size(value_format: u16) -> usize {
    value_format.count_ones() as usize * 2
}

/// Coverage-table lookup: the coverage index of `glyph`, or `None` if uncovered.
fn coverage_index(data: &[u8], off: usize, glyph: u16) -> Option<usize> {
    match be_u16(data, off)? {
        1 => {
            let count = be_u16(data, off + 2)? as usize;
            for i in 0..count {
                let g = be_u16(data, off + 4 + i * 2)?;
                if g == glyph {
                    return Some(i);
                }
                if g > glyph {
                    return None; // glyph array is sorted ascending
                }
            }
            None
        }
        2 => {
            let range_count = be_u16(data, off + 2)? as usize;
            for i in 0..range_count {
                let r = off + 4 + i * 6;
                let start = be_u16(data, r)?;
                let end = be_u16(data, r + 2)?;
                if glyph >= start && glyph <= end {
                    let start_index = be_u16(data, r + 4)? as usize;
                    return Some(start_index + (glyph - start) as usize);
                }
            }
            None
        }
        _ => None,
    }
}

/// `ClassDef` lookup: the class of `glyph` (class `0` when unlisted).
fn classdef_lookup(data: &[u8], off: usize, glyph: u16) -> Option<u16> {
    match be_u16(data, off)? {
        1 => {
            let start = be_u16(data, off + 2)?;
            let count = be_u16(data, off + 4)? as usize;
            if glyph >= start {
                let idx = (glyph - start) as usize;
                if idx < count {
                    return be_u16(data, off + 6 + idx * 2);
                }
            }
            Some(0)
        }
        2 => {
            let range_count = be_u16(data, off + 2)? as usize;
            for i in 0..range_count {
                let r = off + 4 + i * 6;
                let start = be_u16(data, r)?;
                let end = be_u16(data, r + 2)?;
                if glyph >= start && glyph <= end {
                    return be_u16(data, r + 4);
                }
            }
            Some(0)
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pu16(v: &mut Vec<u8>, x: u16) {
        v.extend_from_slice(&x.to_be_bytes());
    }
    fn pi16(v: &mut Vec<u8>, x: i16) {
        v.extend_from_slice(&x.to_be_bytes());
    }
    fn pu32(v: &mut Vec<u8>, x: u32) {
        v.extend_from_slice(&x.to_be_bytes());
    }

    // --- legacy kern table ---------------------------------------------------

    fn build_kern(pairs: &[(u16, u16, i16)]) -> Vec<u8> {
        let mut t = Vec::new();
        pu16(&mut t, 0); // version
        pu16(&mut t, 1); // nTables
        let n = u16::try_from(pairs.len()).expect("test pair count fits in u16");
        let length = 14 + n * 6;
        pu16(&mut t, 0); // subtable version
        pu16(&mut t, length); // subtable length
        pu16(&mut t, 0x0001); // coverage: format 0, horizontal
        pu16(&mut t, n); // nPairs
        pu16(&mut t, 0); // searchRange
        pu16(&mut t, 0); // entrySelector
        pu16(&mut t, 0); // rangeShift
        for &(l, r, v) in pairs {
            pu16(&mut t, l);
            pu16(&mut t, r);
            pi16(&mut t, v);
        }
        t
    }

    #[test]
    fn kern_table_format0_lookup() {
        let t = build_kern(&[(1, 2, -40), (1, 3, 15), (4, 5, -100)]);
        let k = KernTable::parse(&t).unwrap();
        assert_eq!(k.adjustment(1, 2), -40);
        assert_eq!(k.adjustment(1, 3), 15);
        assert_eq!(k.adjustment(4, 5), -100);
        assert_eq!(k.adjustment(2, 1), 0, "unkerned pair is zero");
        assert_eq!(k.adjustment(9, 9), 0);
    }

    #[test]
    fn kern_table_rejects_apple_v1_and_empty() {
        // Apple version-1 header (u32 0x00010000) → major u16 == 1, rejected.
        let mut v1 = Vec::new();
        pu32(&mut v1, 0x0001_0000);
        assert!(KernTable::parse(&v1).is_none());
        // A version-0 table with zero subtables yields no pairs.
        let mut empty = Vec::new();
        pu16(&mut empty, 0);
        pu16(&mut empty, 0);
        assert!(KernTable::parse(&empty).is_none());
    }

    // --- GPOS PairPos format 1 ----------------------------------------------

    /// Minimal `GPOS` with one `LookupType` 2 / `PairPos` format-1 subtable for a
    /// single pair `(left, right)` carrying `XAdvance == value`.
    fn build_gpos_format1(left: u16, right: u16, value: i16) -> Vec<u8> {
        let mut g = alloc::vec![0u8; 46];
        // Header: major, minor, scriptList, featureList, lookupList.
        g[0..2].copy_from_slice(&1u16.to_be_bytes());
        g[8..10].copy_from_slice(&10u16.to_be_bytes()); // lookupListOffset = 10
        // LookupList @10: count=1, offset[0]=4 (-> Lookup @14).
        g[10..12].copy_from_slice(&1u16.to_be_bytes());
        g[12..14].copy_from_slice(&4u16.to_be_bytes());
        // Lookup @14: type=2, flag=0, subCount=1, subOffset[0]=8 (-> PairPos @22).
        g[14..16].copy_from_slice(&2u16.to_be_bytes());
        g[18..20].copy_from_slice(&1u16.to_be_bytes());
        g[20..22].copy_from_slice(&8u16.to_be_bytes());
        // PairPos format 1 @22.
        g[22..24].copy_from_slice(&1u16.to_be_bytes()); // posFormat
        g[24..26].copy_from_slice(&12u16.to_be_bytes()); // coverageOffset -> @34
        g[26..28].copy_from_slice(&VF_X_ADVANCE.to_be_bytes()); // valueFormat1
        g[28..30].copy_from_slice(&0u16.to_be_bytes()); // valueFormat2
        g[30..32].copy_from_slice(&1u16.to_be_bytes()); // pairSetCount
        g[32..34].copy_from_slice(&18u16.to_be_bytes()); // pairSetOffset[0] -> @40
        // Coverage format 1 @34: count=1, glyph=[left].
        g[34..36].copy_from_slice(&1u16.to_be_bytes());
        g[36..38].copy_from_slice(&1u16.to_be_bytes());
        g[38..40].copy_from_slice(&left.to_be_bytes());
        // PairSet @40: count=1, record = (right, XAdvance).
        g[40..42].copy_from_slice(&1u16.to_be_bytes());
        g[42..44].copy_from_slice(&right.to_be_bytes());
        g[44..46].copy_from_slice(&value.to_be_bytes());
        g
    }

    #[test]
    fn gpos_format1_lookup() {
        let g = build_gpos_format1(3, 5, -50);
        let k = GposKerning::parse(&g).unwrap();
        assert_eq!(k.adjustment(3, 5), -50);
        assert_eq!(k.adjustment(5, 3), 0, "reverse pair is unkerned");
        assert_eq!(k.adjustment(3, 9), 0, "right not in pair set");
        assert_eq!(k.adjustment(7, 5), 0, "left not covered");
    }

    // --- GPOS PairPos format 2 (class based) --------------------------------

    /// Minimal `GPOS` with a `PairPos` format-2 subtable: class1(left)=1,
    /// class2(right)=1, and matrix entry `[1][1].XAdvance == value`.
    fn build_gpos_format2(left: u16, right: u16, value: i16) -> Vec<u8> {
        let mut g = alloc::vec![0u8; 68];
        g[0..2].copy_from_slice(&1u16.to_be_bytes());
        g[8..10].copy_from_slice(&10u16.to_be_bytes());
        g[10..12].copy_from_slice(&1u16.to_be_bytes());
        g[12..14].copy_from_slice(&4u16.to_be_bytes());
        g[14..16].copy_from_slice(&2u16.to_be_bytes()); // lookupType 2
        g[18..20].copy_from_slice(&1u16.to_be_bytes());
        g[20..22].copy_from_slice(&8u16.to_be_bytes());
        // PairPos format 2 @22.
        g[22..24].copy_from_slice(&2u16.to_be_bytes()); // posFormat
        g[24..26].copy_from_slice(&24u16.to_be_bytes()); // coverageOffset -> @46
        g[26..28].copy_from_slice(&VF_X_ADVANCE.to_be_bytes()); // valueFormat1
        g[28..30].copy_from_slice(&0u16.to_be_bytes()); // valueFormat2
        g[30..32].copy_from_slice(&30u16.to_be_bytes()); // classDef1Offset -> @52
        g[32..34].copy_from_slice(&38u16.to_be_bytes()); // classDef2Offset -> @60
        g[34..36].copy_from_slice(&2u16.to_be_bytes()); // class1Count
        g[36..38].copy_from_slice(&2u16.to_be_bytes()); // class2Count
        // Class matrix @38 (2×2, each entry one i16 XAdvance):
        //   [1][1] is at 38 + 1*(2*2) + 1*2 = 44.
        g[44..46].copy_from_slice(&value.to_be_bytes());
        // Coverage format 1 @46: count=1, glyph=[left].
        g[46..48].copy_from_slice(&1u16.to_be_bytes());
        g[48..50].copy_from_slice(&1u16.to_be_bytes());
        g[50..52].copy_from_slice(&left.to_be_bytes());
        // ClassDef1 format 1 @52: startGlyph=left, count=1, classValues=[1].
        g[52..54].copy_from_slice(&1u16.to_be_bytes());
        g[54..56].copy_from_slice(&left.to_be_bytes());
        g[56..58].copy_from_slice(&1u16.to_be_bytes());
        g[58..60].copy_from_slice(&1u16.to_be_bytes());
        // ClassDef2 format 1 @60: startGlyph=right, count=1, classValues=[1].
        g[60..62].copy_from_slice(&1u16.to_be_bytes());
        g[62..64].copy_from_slice(&right.to_be_bytes());
        g[64..66].copy_from_slice(&1u16.to_be_bytes());
        g[66..68].copy_from_slice(&1u16.to_be_bytes());
        g
    }

    #[test]
    fn gpos_format2_class_lookup() {
        let g = build_gpos_format2(3, 5, -30);
        let k = GposKerning::parse(&g).unwrap();
        assert_eq!(k.adjustment(3, 5), -30);
        assert_eq!(
            k.adjustment(3, 6),
            0,
            "right is class 0 -> matrix [1][0] = 0"
        );
        assert_eq!(k.adjustment(4, 5), 0, "left not in coverage");
    }

    // --- GPOS LookupType 9 extension wrapper --------------------------------

    /// Wraps a `PairPos` format-1 subtable in a `LookupType` 9 extension.
    fn build_gpos_extension(left: u16, right: u16, value: i16) -> Vec<u8> {
        let mut g = alloc::vec![0u8; 54];
        g[0..2].copy_from_slice(&1u16.to_be_bytes());
        g[8..10].copy_from_slice(&10u16.to_be_bytes());
        g[10..12].copy_from_slice(&1u16.to_be_bytes());
        g[12..14].copy_from_slice(&4u16.to_be_bytes());
        // Lookup @14: type=9 (extension), subOffset[0]=8 -> ExtensionPos @22.
        g[14..16].copy_from_slice(&9u16.to_be_bytes());
        g[18..20].copy_from_slice(&1u16.to_be_bytes());
        g[20..22].copy_from_slice(&8u16.to_be_bytes());
        // ExtensionPos @22: posFormat=1, extType=2, extOffset=8 -> PairPos @30.
        g[22..24].copy_from_slice(&1u16.to_be_bytes());
        g[24..26].copy_from_slice(&2u16.to_be_bytes());
        g[26..30].copy_from_slice(&8u32.to_be_bytes());
        // PairPos format 1 @30.
        g[30..32].copy_from_slice(&1u16.to_be_bytes());
        g[32..34].copy_from_slice(&12u16.to_be_bytes()); // coverageOffset -> @42
        g[34..36].copy_from_slice(&VF_X_ADVANCE.to_be_bytes());
        g[36..38].copy_from_slice(&0u16.to_be_bytes());
        g[38..40].copy_from_slice(&1u16.to_be_bytes()); // pairSetCount
        g[40..42].copy_from_slice(&18u16.to_be_bytes()); // pairSetOffset -> @48
        // Coverage format 1 @42.
        g[42..44].copy_from_slice(&1u16.to_be_bytes());
        g[44..46].copy_from_slice(&1u16.to_be_bytes());
        g[46..48].copy_from_slice(&left.to_be_bytes());
        // PairSet @48.
        g[48..50].copy_from_slice(&1u16.to_be_bytes());
        g[50..52].copy_from_slice(&right.to_be_bytes());
        g[52..54].copy_from_slice(&value.to_be_bytes());
        g
    }

    #[test]
    fn gpos_extension_lookup_is_followed() {
        let g = build_gpos_extension(7, 8, 25);
        let k = GposKerning::parse(&g).unwrap();
        assert_eq!(k.adjustment(7, 8), 25);
    }

    // --- combined view -------------------------------------------------------

    #[test]
    fn combined_prefers_gpos_over_kern() {
        let kern = build_kern(&[(3, 5, 999)]);
        let gpos = build_gpos_format1(3, 5, -50);
        let k = Kerning::from_tables(Some(&kern), Some(&gpos));
        assert!(!k.is_empty());
        assert_eq!(k.adjustment(3, 5), -50, "GPOS supersedes the kern table");
    }

    #[test]
    fn combined_falls_back_to_kern_without_gpos() {
        let kern = build_kern(&[(1, 2, -7)]);
        let k = Kerning::from_tables(Some(&kern), None);
        assert_eq!(k.adjustment(1, 2), -7);
        assert_eq!(k.adjustment(2, 1), 0);
    }

    #[test]
    fn combined_empty_when_no_tables() {
        let k = Kerning::from_tables(None, None);
        assert!(k.is_empty());
        assert_eq!(k.adjustment(1, 2), 0);
    }
}
