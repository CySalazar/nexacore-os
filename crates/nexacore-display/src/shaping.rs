//! Complex-text analysis for shaping (WS7-17): script itemization, a Unicode
//! BiDi subset, and Arabic contextual joining — the host-testable half of the
//! shaping pipeline.
//!
//! Turning shaped runs into positioned glyphs needs a HarfBuzz-class engine with
//! the font's `GSUB`/`GPOS` tables (ligatures, CJK, COLR/CBDT colour emoji); that
//! sits behind the [`crate::shaping::ShapingEngine`] seam (WS7-17.1/.2/.5/.6), library-gated like
//! the WS8-02 codecs. The analysis here — *which* script each run is
//! ([`crate::shaping::script_runs`], WS7-17.7), the visual order of mixed LTR/RTL text
//! ([`crate::shaping::bidi`], WS7-17.3), and the contextual form of each Arabic letter
//! ([`crate::shaping::arabic_forms`], WS7-17.4) — is pure and host-tested.

use alloc::vec::Vec;

// =============================================================================
// Script itemization (WS7-17.7)
// =============================================================================

/// The script a character belongs to (the subset NexaCore itemizes for fallback).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Script {
    /// Latin / ASCII letters.
    Latin,
    /// Arabic (RTL, cursive joining).
    Arabic,
    /// Hebrew (RTL).
    Hebrew,
    /// CJK Unified Ideographs (Han).
    Han,
    /// Japanese Hiragana.
    Hiragana,
    /// Japanese Katakana.
    Katakana,
    /// Korean Hangul.
    Hangul,
    /// Emoji / pictographs (colour-font territory).
    Emoji,
    /// Script-neutral (spaces, punctuation, digits) — attaches to a neighbour.
    Common,
}

/// The script of a single character (WS7-17.7).
#[must_use]
pub fn script_of(c: char) -> Script {
    let u = c as u32;
    match u {
        0x0600..=0x06FF | 0x0750..=0x077F | 0xFB50..=0xFDFF | 0xFE70..=0xFEFF => Script::Arabic,
        0x0590..=0x05FF => Script::Hebrew,
        0x3040..=0x309F => Script::Hiragana,
        0x30A0..=0x30FF => Script::Katakana,
        0x4E00..=0x9FFF | 0x3400..=0x4DBF => Script::Han,
        0xAC00..=0xD7AF | 0x1100..=0x11FF => Script::Hangul,
        0x1F000..=0x1FAFF | 0x2600..=0x27BF => Script::Emoji,
        _ if c.is_ascii_alphabetic() || (0x00C0..=0x024F).contains(&u) => Script::Latin,
        _ => Script::Common,
    }
}

/// A maximal run of characters in one script (WS7-17.7).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ScriptRun {
    /// Byte offset of the run start in the source string.
    pub start: usize,
    /// Byte offset of the run end (exclusive).
    pub end: usize,
    /// The run's script.
    pub script: Script,
}

/// Itemize `text` into maximal script runs (WS7-17.7).
///
/// `Common` characters (spaces/punctuation) attach to the **preceding** run so
/// the fallback font does not flicker mid-word; a leading `Common` run keeps
/// `Common` until the first real script is seen.
#[must_use]
pub fn script_runs(text: &str) -> Vec<ScriptRun> {
    let mut runs: Vec<ScriptRun> = Vec::new();
    for (idx, c) in text.char_indices() {
        let mut s = script_of(c);
        if s == Script::Common {
            // Attach to the current run's script if there is one.
            if let Some(last) = runs.last() {
                s = last.script;
            }
        }
        let end = idx + c.len_utf8();
        if let Some(last) = runs.last_mut() {
            if last.script == s {
                last.end = end;
                continue;
            }
        }
        runs.push(ScriptRun {
            start: idx,
            end,
            script: s,
        });
    }
    runs
}

// =============================================================================
// BiDi subset (WS7-17.3)
// =============================================================================

/// The BiDi character types this subset resolves (UAX #9).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BidiClass {
    /// Strong left-to-right.
    L,
    /// Strong right-to-left (Hebrew).
    R,
    /// Strong right-to-left Arabic letter.
    Al,
    /// European number (ASCII digit).
    En,
    /// Arabic number.
    An,
    /// Whitespace.
    Ws,
    /// Other neutral (punctuation, symbols).
    On,
}

/// The BiDi class of a character (UAX #9 subset).
#[must_use]
pub fn bidi_class(c: char) -> BidiClass {
    let u = c as u32;
    match u {
        0x0030..=0x0039 => BidiClass::En,
        0x0660..=0x0669 | 0x06F0..=0x06F9 => BidiClass::An,
        0x0600..=0x06FF | 0x0750..=0x077F | 0xFB50..=0xFDFF | 0xFE70..=0xFEFF => BidiClass::Al,
        0x0590..=0x05FF => BidiClass::R,
        0x0020 | 0x0009 | 0x000A => BidiClass::Ws,
        _ if c.is_ascii_alphabetic() || (0x00C0..=0x024F).contains(&u) => BidiClass::L,
        _ if c.is_alphabetic() => BidiClass::L,
        _ => BidiClass::On,
    }
}

/// The result of BiDi resolution for a paragraph (WS7-17.3).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BidiParagraph {
    /// The base paragraph embedding level (0 = LTR, 1 = RTL).
    pub base_level: u8,
    /// Per-character embedding level (by `char` index, not byte).
    pub levels: Vec<u8>,
}

/// Resolve the base level and per-character embedding levels of `text`
/// (WS7-17.3).
///
/// A UAX #9 subset: rules P2/P3 for the base level, a simplified weak/neutral
/// resolution, and implicit levelling — no explicit embedding/override controls.
#[must_use]
pub fn bidi(text: &str) -> BidiParagraph {
    let classes: Vec<BidiClass> = text.chars().map(bidi_class).collect();

    // P2/P3 — base level from the first strong character.
    let base_level = classes
        .iter()
        .find_map(|c| match c {
            BidiClass::L => Some(0),
            BidiClass::R | BidiClass::Al => Some(1),
            _ => None,
        })
        .unwrap_or(0);

    // Resolve each character's "strong direction" by carrying the last strong
    // class across numbers and neutrals (a practical stand-in for W/N rules):
    // numbers and neutrals take the surrounding strong direction, else the base.
    let mut levels = Vec::with_capacity(classes.len());
    let mut last_strong = if base_level == 1 {
        BidiClass::R
    } else {
        BidiClass::L
    };
    for &class in &classes {
        let dir = match class {
            BidiClass::L => {
                last_strong = BidiClass::L;
                0
            }
            BidiClass::R | BidiClass::Al => {
                last_strong = BidiClass::Al;
                1
            }
            // Arabic/European numbers render LTR but sit at an odd+1 level inside
            // RTL so the digits themselves stay left-to-right (UAX #9 I1/I2).
            BidiClass::En | BidiClass::An => {
                if base_level == 1 {
                    2
                } else {
                    0
                }
            }
            // Neutrals take the last strong direction.
            BidiClass::Ws | BidiClass::On => {
                u8::from(matches!(last_strong, BidiClass::R | BidiClass::Al))
            }
        };
        levels.push(dir);
    }

    BidiParagraph { base_level, levels }
}

/// Reorder character indices from logical to visual order (UAX #9 rule L2): each
/// maximal run at the highest level (and above) is reversed, from the highest
/// level down to one above the base (WS7-17.3).
#[must_use]
pub fn reorder_visual(para: &BidiParagraph) -> Vec<usize> {
    let n = para.levels.len();
    let mut order: Vec<usize> = (0..n).collect();
    let max_level = para.levels.iter().copied().max().unwrap_or(0);
    if max_level == 0 {
        return order; // pure LTR — logical == visual.
    }
    // L2: from the highest level down to the lowest odd level (1, where RTL
    // runs live), reverse each contiguous run of characters at >= that level.
    let mut level = max_level;
    while level >= 1 {
        let mut i = 0;
        while i < n {
            if para.levels.get(i).copied().unwrap_or(0) >= level {
                let start = i;
                while i < n && para.levels.get(i).copied().unwrap_or(0) >= level {
                    i += 1;
                }
                order.get_mut(start..i).map(<[usize]>::reverse);
            } else {
                i += 1;
            }
        }
        level -= 1;
    }
    order
}

// =============================================================================
// Arabic contextual joining (WS7-17.4)
// =============================================================================

/// The cursive joining behaviour of a character (UAX #9 / Arabic shaping).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum JoiningType {
    /// Dual-joining (joins on both sides) — most Arabic letters.
    Dual,
    /// Right-joining only (e.g. `alef`, `dal`, `reh`).
    Right,
    /// Non-joining.
    None,
    /// Transparent (combining marks) — does not affect neighbours.
    Transparent,
}

/// The contextual form an Arabic letter takes given its neighbours (WS7-17.4).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum JoinForm {
    /// No joins (standalone).
    Isolated,
    /// Joins the following letter only.
    Initial,
    /// Joins both neighbours.
    Medial,
    /// Joins the preceding letter only.
    Final,
}

/// The joining type of a character (the common Arabic subset).
#[must_use]
pub fn joining_type(c: char) -> JoiningType {
    let u = c as u32;
    match u {
        // Combining marks (harakat) are transparent.
        0x064B..=0x065F | 0x0670 | 0x06D6..=0x06DC => JoiningType::Transparent,
        // Right-joining letters: alef, dal, dhal, reh, zain, waw, …
        0x0622..=0x0625 | 0x0627 | 0x062F | 0x0630 | 0x0631 | 0x0632 | 0x0648 | 0x0649 => {
            JoiningType::Right
        }
        // The bulk of Arabic letters are dual-joining.
        0x0628..=0x064A => JoiningType::Dual,
        _ => JoiningType::None,
    }
}

/// Resolve the contextual [`JoinForm`] of each character in an Arabic string
/// (WS7-17.4).
///
/// Transparent marks inherit and do not break joining; the visual glyph
/// selection itself is the [`ShapingEngine`]'s job.
#[must_use]
pub fn arabic_forms(text: &str) -> Vec<JoinForm> {
    let types: Vec<JoiningType> = text.chars().map(joining_type).collect();
    let mut forms = Vec::with_capacity(types.len());
    for (i, &jt) in types.iter().enumerate() {
        if jt == JoiningType::Transparent || jt == JoiningType::None {
            forms.push(JoinForm::Isolated);
            continue;
        }
        // Does the previous non-transparent letter join forward (Dual)?
        let joins_prev = prev_joining(&types, i).is_some_and(|t| matches!(t, JoiningType::Dual));
        // Can this letter join the next? Only Dual letters join forward.
        let joins_next = jt == JoiningType::Dual
            && next_joining(&types, i)
                .is_some_and(|t| matches!(t, JoiningType::Dual | JoiningType::Right));
        forms.push(match (joins_prev, joins_next) {
            (true, true) => JoinForm::Medial,
            (true, false) => JoinForm::Final,
            (false, true) => JoinForm::Initial,
            (false, false) => JoinForm::Isolated,
        });
    }
    forms
}

fn prev_joining(types: &[JoiningType], i: usize) -> Option<JoiningType> {
    types
        .get(..i)?
        .iter()
        .rev()
        .copied()
        .find(|t| *t != JoiningType::Transparent)
}

fn next_joining(types: &[JoiningType], i: usize) -> Option<JoiningType> {
    types
        .get(i + 1..)?
        .iter()
        .copied()
        .find(|t| *t != JoiningType::Transparent)
}

// =============================================================================
// Shaping engine seam (WS7-17.1/.2/.5/.6)
// =============================================================================

/// A positioned glyph the renderer blits.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PositionedGlyph {
    /// Glyph id within the run's font.
    pub glyph_id: u32,
    /// Horizontal advance in font units.
    pub advance: i32,
    /// Source cluster (char index) this glyph came from.
    pub cluster: usize,
}

/// The HarfBuzz-class shaping seam (WS7-17.1/.2/.5/.6).
///
/// The production engine applies the font's `OpenType` `GSUB`/`GPOS` features
/// (ligatures, contextual Arabic forms, CJK, colour-emoji `COLR`/`CBDT`) to turn
/// a script run into positioned glyphs; tests use a mock.
pub trait ShapingEngine {
    /// Shape `text[run.start..run.end]` into positioned glyphs.
    fn shape(&self, text: &str, run: ScriptRun, rtl: bool) -> Vec<PositionedGlyph>;
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── itemization ───────────────────────────────────────────────────────

    #[test]
    fn script_of_classifies_mixed_scripts() {
        assert_eq!(script_of('A'), Script::Latin);
        assert_eq!(script_of('ا'), Script::Arabic); // alef
        assert_eq!(script_of('中'), Script::Han);
        assert_eq!(script_of('あ'), Script::Hiragana);
        assert_eq!(script_of('😀'), Script::Emoji);
        assert_eq!(script_of(' '), Script::Common);
    }

    #[test]
    fn script_runs_segment_and_attach_common() {
        // "Hi 中文" → Latin run (incl. the space) then Han run.
        let runs = script_runs("Hi 中文");
        assert_eq!(runs.len(), 2);
        assert_eq!(runs[0].script, Script::Latin);
        assert_eq!(runs[1].script, Script::Han);
        // The space attached to the Latin run.
        assert_eq!(&"Hi 中文"[runs[0].start..runs[0].end], "Hi ");
    }

    #[test]
    fn emoji_is_its_own_run() {
        let runs = script_runs("A😀");
        assert_eq!(runs.len(), 2);
        assert_eq!(runs[1].script, Script::Emoji);
    }

    // ── BiDi ──────────────────────────────────────────────────────────────

    #[test]
    fn pure_ltr_is_base_0_identity_order() {
        let para = bidi("hello");
        assert_eq!(para.base_level, 0);
        assert!(para.levels.iter().all(|&l| l == 0));
        assert_eq!(reorder_visual(&para), alloc::vec![0, 1, 2, 3, 4]);
    }

    #[test]
    fn pure_rtl_is_base_1_reversed_order() {
        // Three Arabic letters → base level 1, visual order reversed.
        let para = bidi("ابت");
        assert_eq!(para.base_level, 1);
        assert!(para.levels.iter().all(|&l| l == 1));
        assert_eq!(reorder_visual(&para), alloc::vec![2, 1, 0]);
    }

    #[test]
    fn ltr_with_rtl_run_levels_the_rtl_higher() {
        // "a" + two Arabic letters: base LTR(0); the Arabic chars get level 1.
        let para = bidi("aبت");
        assert_eq!(para.base_level, 0);
        assert_eq!(para.levels[0], 0);
        assert_eq!(para.levels[1], 1);
        assert_eq!(para.levels[2], 1);
        // L2: the level-1 run [1,2] is reversed → [0, 2, 1].
        assert_eq!(reorder_visual(&para), alloc::vec![0, 2, 1]);
    }

    #[test]
    fn european_numbers_stay_ltr_inside_rtl() {
        // Arabic letter + ASCII digits "12": digits get level 2 inside RTL.
        let para = bidi("ا12");
        assert_eq!(para.base_level, 1);
        assert_eq!(para.levels[0], 1);
        assert_eq!(para.levels[1], 2);
        assert_eq!(para.levels[2], 2);
    }

    // ── Arabic joining ─────────────────────────────────────────────────────

    #[test]
    fn joining_types_of_common_letters() {
        assert_eq!(joining_type('ب'), JoiningType::Dual); // beh
        assert_eq!(joining_type('ا'), JoiningType::Right); // alef
        assert_eq!(joining_type('\u{064B}'), JoiningType::Transparent); // fathatan
    }

    #[test]
    fn three_dual_letters_are_init_medial_final() {
        // ببب — first Initial, middle Medial, last Final.
        let forms = arabic_forms("ببب");
        assert_eq!(
            forms,
            alloc::vec![JoinForm::Initial, JoinForm::Medial, JoinForm::Final]
        );
    }

    #[test]
    fn right_joining_letter_does_not_connect_forward() {
        // ا (right-joining) then ب (dual): alef does not join the following
        // letter, so both stand alone.
        let forms = arabic_forms("اب");
        assert_eq!(forms, alloc::vec![JoinForm::Isolated, JoinForm::Isolated]);
    }

    #[test]
    fn lam_alef_connects_initial_final() {
        // لا — lam (dual) takes Initial, alef (right-joining) takes Final.
        let forms = arabic_forms("لا");
        assert_eq!(forms, alloc::vec![JoinForm::Initial, JoinForm::Final]);
    }

    #[test]
    fn transparent_mark_does_not_break_joining() {
        // ب + fathatan + ب: the mark is transparent, so the two beh still join.
        let forms = arabic_forms("ب\u{064B}ب");
        assert_eq!(forms[0], JoinForm::Initial);
        assert_eq!(forms[1], JoinForm::Isolated); // the mark itself
        assert_eq!(forms[2], JoinForm::Final);
    }
}
