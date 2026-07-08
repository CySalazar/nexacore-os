//! Acceptance test suite for `nexacore-ui` (TASK-20, ADR-0042).
//!
//! Covers:
//! - Deterministic layout golden test (tree→rects, purity)
//! - Event dispatch (button/text-input/label/empty hit-test)
//! - UTF-8 text measurement (codepoints, not bytes)
//! - Golden render hash (pins the raster output of "NexaCore")
//! - Canvas bounds safety (off-canvas glyph writes do not panic)

use alloc::string::String;

use nexacore_display::geometry::Rect;

use crate::{
    canvas::Canvas,
    color::{CHARCOAL, CREAM},
    layout::Direction,
    text::{draw_text, glyph_for, measure_text},
    theme::Theme,
    widget::{Widget, WidgetId},
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// FNV-1a constants declared at module scope to avoid items-after-statements.
const FNV_OFFSET_BASIS: u32 = 0x811C_9DC5;
const FNV_PRIME: u32 = 0x0100_0193;

/// FNV-1a 32-bit hash over a byte slice.
///
/// Implemented inline so no new dependency is introduced.  This is the
/// standard FNV-1a algorithm: `hash = (hash ^ byte) * FNV_PRIME_32` for each
/// byte.  It is deterministic and platform-independent.
///
/// The purpose is purely to pin pixel-buffer contents in the golden render
/// test — not cryptographic security.
fn fnv1a_32(data: &[u8]) -> u32 {
    let mut hash = FNV_OFFSET_BASIS;
    for &b in data {
        hash ^= u32::from(b);
        hash = hash.wrapping_mul(FNV_PRIME);
    }
    hash
}

/// Convenience: hash a `&[u32]` pixel buffer by viewing it as bytes.
fn hash_pixels(pixels: &[u32]) -> u32 {
    // Interpret the u32 slice as a byte slice for hashing.
    // Each u32 contributes 4 bytes (little-endian on x86).
    let mut hash: u32 = FNV_OFFSET_BASIS;
    for &px in pixels {
        let bytes = px.to_le_bytes();
        for &b in &bytes {
            hash ^= u32::from(b);
            hash = hash.wrapping_mul(FNV_PRIME);
        }
    }
    hash
}

// ---------------------------------------------------------------------------
// Layout golden test
// ---------------------------------------------------------------------------

/// Compute expected rects by hand for the canonical three-widget vertical
/// container.
///
/// `Theme::nexacore()`: `text_scale=2`, `padding=8`, `spacing=6`.
///
/// Label "NexaCore OS":
///   measure: w = 11 chars * 8 * 2 + 2*8 = 192, h = 8*2 + 2*8 = 32
///   rect: (0, 0, 192, 32)
///
/// Button "Click":
///   measure: w = 5 * 8 * 2 + 2*8 = 96, h = 32
///   rect: (0, 0+32+6=38, 96, 32)
///
/// `TextInput` (empty):
///   measure: `min_w` = 10 * 8 * 2 + 2 * 8 = 176, h = 32
///   rect: (0, 38+32+6=76, 176, 32)
///
/// Container:
///   measure: w = max(192, 96, 176) = 192
///            h = 32 + 32 + 32 + 2*6 = 108
///   rect after layout(Rect{0,0,300,200}): (0, 0, 300, 200)
fn expected_label_rect() -> Rect {
    Rect {
        x: 0,
        y: 0,
        w: 11 * 8 * 2 + 2 * 8, // 192
        h: 8 * 2 + 2 * 8,      // 32
    }
}

fn expected_button_rect() -> Rect {
    // Button is placed after label + spacing.
    Rect {
        x: 0,
        y: 38,                // 32 (label h) + 6 (spacing)
        w: 5 * 8 * 2 + 2 * 8, // 96
        h: 32,
    }
}

fn expected_textinput_rect() -> Rect {
    // TextInput is placed after button + spacing.
    Rect {
        x: 0,
        y: 76,                 // 38 (button y) + 32 (button h) + 6 (spacing)
        w: 10 * 8 * 2 + 2 * 8, // 176 (min width)
        h: 32,
    }
}

/// Build the canonical three-widget test tree.
fn make_test_tree() -> (Widget, WidgetId, WidgetId) {
    let btn_id = WidgetId(1);
    let input_id = WidgetId(2);
    let zero = Rect {
        x: 0,
        y: 0,
        w: 0,
        h: 0,
    };
    let tree = Widget::Container {
        direction: Direction::Vertical,
        children: alloc::vec![
            Widget::Label {
                text: String::from("NexaCore OS"),
                rect: zero,
            },
            Widget::Button {
                id: btn_id,
                text: String::from("Click"),
                rect: zero,
            },
            Widget::TextInput {
                id: input_id,
                text: String::new(),
                cursor: 0,
                rect: zero,
            },
        ],
        rect: zero,
    };
    (tree, btn_id, input_id)
}

#[test]
fn layout_golden_rects() {
    let theme = Theme::nexacore();
    let bounds = Rect {
        x: 0,
        y: 0,
        w: 300,
        h: 200,
    };
    let (mut tree, _, _) = make_test_tree();
    tree.layout(bounds, &theme);

    // Container rect = the full bounds allocation.
    assert_eq!(
        tree.rect(),
        bounds,
        "container rect must be the full bounds"
    );

    // Extract child rects.
    let Widget::Container { ref children, .. } = tree else {
        panic!("expected Container");
    };
    let label_rect = children[0].rect();
    let button_rect = children[1].rect();
    let input_rect = children[2].rect();

    assert_eq!(label_rect, expected_label_rect(), "Label rect mismatch");
    assert_eq!(button_rect, expected_button_rect(), "Button rect mismatch");
    assert_eq!(
        input_rect,
        expected_textinput_rect(),
        "TextInput rect mismatch"
    );
}

#[test]
fn layout_is_pure() {
    // Running layout twice with the same arguments must yield identical rects.
    let theme = Theme::nexacore();
    let bounds = Rect {
        x: 0,
        y: 0,
        w: 300,
        h: 200,
    };

    let (mut tree_a, _, _) = make_test_tree();
    let (mut tree_b, _, _) = make_test_tree();
    tree_a.layout(bounds, &theme);
    tree_b.layout(bounds, &theme);

    // Compare all child rects.
    let Widget::Container {
        children: ref ca, ..
    } = tree_a
    else {
        panic!("expected Container");
    };
    let Widget::Container {
        children: ref cb, ..
    } = tree_b
    else {
        panic!("expected Container");
    };
    for (a, b) in ca.iter().zip(cb.iter()) {
        assert_eq!(a.rect(), b.rect(), "layout not pure for child");
    }
}

// ---------------------------------------------------------------------------
// Event dispatch test
// ---------------------------------------------------------------------------

#[test]
fn dispatch_click_interactive_widgets() {
    let theme = Theme::nexacore();
    let bounds = Rect {
        x: 0,
        y: 0,
        w: 300,
        h: 200,
    };
    let (mut tree, btn_id, input_id) = make_test_tree();
    tree.layout(bounds, &theme);

    let btn_rect = expected_button_rect();
    let input_rect = expected_textinput_rect();
    let label_rect = expected_label_rect();

    // Click inside button — must return button id.
    let inside_btn = (btn_rect.x + 5, btn_rect.y + 5);
    assert_eq!(
        tree.dispatch_click(inside_btn),
        Some(btn_id),
        "click inside button must return its id"
    );

    // Click inside text input — must return input id.
    let inside_input = (input_rect.x + 5, input_rect.y + 5);
    assert_eq!(
        tree.dispatch_click(inside_input),
        Some(input_id),
        "click inside text input must return its id"
    );

    // Click inside label — label is non-interactive, must return None.
    let inside_label = (label_rect.x + 5, label_rect.y + 5);
    assert_eq!(
        tree.dispatch_click(inside_label),
        None,
        "click on label must return None"
    );

    // Click just outside the button (one pixel right of the right edge).
    // btn_rect.w fits in i32 for any sane layout.
    #[allow(clippy::cast_possible_wrap)]
    let just_outside_btn = (btn_rect.x + btn_rect.w as i32, btn_rect.y + 5);
    assert_eq!(
        tree.dispatch_click(just_outside_btn),
        None,
        "click just outside button must return None"
    );

    // Click in empty space below all widgets — also None.
    assert_eq!(
        tree.dispatch_click((10, 190)),
        None,
        "click on empty space must return None"
    );
}

// ---------------------------------------------------------------------------
// UTF-8 text measurement
// ---------------------------------------------------------------------------

#[test]
fn utf8_measurement_codepoints_not_bytes() {
    // "café" is 4 codepoints but 5 UTF-8 bytes.
    let (w, h) = measure_text("café", 1);
    assert_eq!(w, 4 * 8, "width must count codepoints (4), not bytes (5)");
    assert_eq!(h, 8, "height must be GLYPH_H * scale");

    // scale 2.
    let (w2, h2) = measure_text("hello", 2);
    assert_eq!(w2, 5 * 8 * 2, "5-char string at scale 2");
    assert_eq!(h2, 8 * 2, "height at scale 2");

    // Empty string.
    let (we, he) = measure_text("", 1);
    assert_eq!(we, 0, "empty string width must be 0");
    assert_eq!(he, 8, "empty string height must still be GLYPH_H");

    // Emoji — counts as 1 codepoint regardless of byte length.
    let (wx, _) = measure_text("x🦀", 1);
    assert_eq!(wx, 2 * 8, "emoji counts as 1 glyph");

    // CJK character — also 1 codepoint.
    let (wk, _) = measure_text("中", 1);
    assert_eq!(wk, 8, "CJK char counts as 1 glyph (width = 8)");

    // Scale 0 is treated as 1.
    let (ws, hs) = measure_text("A", 0);
    assert_eq!(ws, 8, "scale 0 treated as 1");
    assert_eq!(hs, 8, "scale 0 treated as 1 height");
}

// ---------------------------------------------------------------------------
// Golden render hash
// ---------------------------------------------------------------------------

/// Canvas size for the golden render test.
/// 8 chars × 8 px/char = 64 px wide; 8 px tall.  Keep a small buffer.
const GOLDEN_W: u32 = 64;
const GOLDEN_H: u32 = 16;

/// The expected FNV-1a hash of the pixel buffer after rendering "NexaCore" at
/// scale 1, charcoal (`0xFF1F2421`) on black (`0x00000000`), at position (0, 0),
/// into a `64 × 16` canvas.
///
/// This constant PINS the raster output of the text renderer.  If the font
/// data, bit ordering, glyph lookup, or the FNV-1a implementation changes,
/// this value will change — the failing test is the signal to review the diff.
/// Update it only after deliberate review.
///
/// Captured on 2026-06-24 (NexaCore rebrand: raster text "OMNI" → "NexaCore")
/// using the `print_golden_hash` test.
const GOLDEN_HASH: u32 = 0x82AD_7102;

#[test]
fn golden_render_hash() {
    let mut pixels = alloc::vec![0u32; (GOLDEN_W * GOLDEN_H) as usize];
    let mut canvas = Canvas::new(&mut pixels, GOLDEN_W, GOLDEN_H).unwrap();
    draw_text(&mut canvas, 0, 0, "NexaCore", CHARCOAL, 1);

    // The rendered region must be non-blank (some pixels are the text colour).
    assert!(
        pixels.iter().any(|&p| p == CHARCOAL),
        "rendered text region must contain at least one text-colour pixel"
    );

    // The background (pixels not set by the glyph) must still be 0 (unchanged).
    // There must be more background pixels than text pixels for a sparse glyph.
    let text_pixels = pixels.iter().filter(|&&p| p == CHARCOAL).count();
    let bg_pixels = pixels.iter().filter(|&&p| p == 0).count();
    assert!(
        bg_pixels > text_pixels,
        "sparse glyph: more background pixels ({bg_pixels}) than text pixels ({text_pixels})"
    );

    // Compute the hash of the buffer and assert it matches the pinned value.
    let hash = hash_pixels(&pixels);
    assert_eq!(
        hash, GOLDEN_HASH,
        "golden pixel hash mismatch (got 0x{hash:08X}, expected 0x{GOLDEN_HASH:08X}); \
         raster output has changed — update GOLDEN_HASH after deliberate review"
    );
}

/// Verifies the golden hash infrastructure: recomputes the hash and checks it
/// against `GOLDEN_HASH`.  This is a redundant check that the hash function
/// itself is deterministic across test runs.
#[test]
fn golden_hash_is_deterministic() {
    let mut pixels_a = alloc::vec![0u32; (GOLDEN_W * GOLDEN_H) as usize];
    let mut canvas_a = Canvas::new(&mut pixels_a, GOLDEN_W, GOLDEN_H).unwrap();
    draw_text(&mut canvas_a, 0, 0, "NexaCore", CHARCOAL, 1);
    let hash_a = hash_pixels(&pixels_a);

    let mut pixels_b = alloc::vec![0u32; (GOLDEN_W * GOLDEN_H) as usize];
    let mut canvas_b = Canvas::new(&mut pixels_b, GOLDEN_W, GOLDEN_H).unwrap();
    draw_text(&mut canvas_b, 0, 0, "NexaCore", CHARCOAL, 1);
    let hash_b = hash_pixels(&pixels_b);

    assert_eq!(hash_a, hash_b, "hash must be deterministic across renders");
    assert_eq!(hash_a, GOLDEN_HASH, "hash must match the pinned constant");
}

// ---------------------------------------------------------------------------
// Canvas bounds safety
// ---------------------------------------------------------------------------

#[test]
fn blit_glyph_off_canvas_does_not_panic() {
    let mut pixels = alloc::vec![0u32; 16 * 16];
    let mut canvas = Canvas::new(&mut pixels, 16, 16).unwrap();
    let g = *glyph_for('A');

    // Fully off-canvas (negative coordinates).
    canvas.blit_glyph(-100, -100, g, CHARCOAL, 1);
    // Partially off the right/bottom edge.
    canvas.blit_glyph(14, 14, g, CHARCOAL, 1);
    // Fully past the right/bottom edge.
    canvas.blit_glyph(1000, 1000, g, CHARCOAL, 1);
    // Scale that would overflow if unchecked.
    canvas.blit_glyph(0, 0, g, CHARCOAL, 1000);
    // None of these should have written outside the 16*16 buffer.
    // (If they did, we'd have UB — the bounds-checked get_mut prevents that.)
    assert_eq!(pixels.len(), 16 * 16, "buffer length must be unchanged");
}

#[test]
fn draw_text_off_canvas_does_not_panic() {
    let mut pixels = alloc::vec![0u32; 32 * 8];
    let mut canvas = Canvas::new(&mut pixels, 32, 8).unwrap();

    // Start position before the left edge.
    draw_text(&mut canvas, -200, 0, "HELLO", CHARCOAL, 1);
    // Start position past the right edge.
    draw_text(&mut canvas, 10000, 0, "HELLO", CHARCOAL, 1);
    // Negative y.
    draw_text(&mut canvas, 0, -100, "HELLO", CHARCOAL, 1);
    // Partially off-canvas (text wider than canvas).
    draw_text(&mut canvas, 28, 0, "HELLO", CHARCOAL, 1);

    // Buffer length must be unchanged.
    assert_eq!(pixels.len(), 32 * 8, "buffer length must be unchanged");
}

#[test]
fn fill_rect_outside_canvas_does_not_panic() {
    let mut pixels = alloc::vec![CREAM; 8 * 8];
    let mut canvas = Canvas::new(&mut pixels, 8, 8).unwrap();
    let outside = Rect {
        x: 100,
        y: 100,
        w: 10,
        h: 10,
    };
    canvas.fill_rect(&outside, CHARCOAL);
    // All pixels should still be CREAM.
    assert!(
        pixels.iter().all(|&p| p == CREAM),
        "fill_rect outside canvas must not modify any pixel"
    );
}

// ---------------------------------------------------------------------------
// FNV helper self-test
// ---------------------------------------------------------------------------

#[test]
fn fnv1a_known_vector() {
    // FNV-1a 32 of the empty string is the offset basis by definition.
    assert_eq!(fnv1a_32(&[]), 0x811C_9DC5);
    // FNV-1a 32 of b"a": (0x811C9DC5 ^ 0x61) * 0x01000193 = 0xE40C292C.
    // Computed independently; matches the FNV reference test vectors.
    assert_eq!(fnv1a_32(b"a"), 0xE40C_292C);
}
