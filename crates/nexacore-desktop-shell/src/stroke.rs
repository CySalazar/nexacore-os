//! Anti-aliased line-segment stroking for small vector glyphs (titlebar
//! button icons). Coverage is computed from the pixel-centre distance to the
//! segment and blended via [`Canvas::blend_pixel`].

use nexacore_ui::canvas::Canvas;

/// Strokes the segment `(x0,y0)→(x1,y1)` with a round-capped line `width`
/// pixels wide, anti-aliased, in `color` (ARGB; alpha honoured by the blend).
#[allow(
    clippy::float_arithmetic,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::cast_precision_loss,
    reason = "distance-field rasterisation is inherently floating-point"
)]
pub fn stroke_line(
    canvas: &mut Canvas<'_>,
    x0: f32,
    y0: f32,
    x1: f32,
    y1: f32,
    width: f32,
    color: u32,
) {
    let half = width * 0.5;
    let pad = half + 1.0;
    let min_x = libm::floorf(x0.min(x1) - pad).max(0.0) as i32;
    let min_y = libm::floorf(y0.min(y1) - pad).max(0.0) as i32;
    let max_x = libm::ceilf(x0.max(x1) + pad) as i32;
    let max_y = libm::ceilf(y0.max(y1) + pad) as i32;

    let dx = x1 - x0;
    let dy = y1 - y0;
    let len_sq = dx * dx + dy * dy;

    let mut y = min_y;
    while y <= max_y {
        let mut x = min_x;
        while x <= max_x {
            let px = x as f32 + 0.5;
            let py = y as f32 + 0.5;
            // Project the pixel centre onto the segment, clamped to [0,1].
            let t = if len_sq <= f32::EPSILON {
                0.0
            } else {
                (((px - x0) * dx + (py - y0) * dy) / len_sq).clamp(0.0, 1.0)
            };
            let cx = x0 + t * dx;
            let cy = y0 + t * dy;
            let dist = libm::sqrtf((px - cx) * (px - cx) + (py - cy) * (py - cy));
            // 1px soft edge around the half-width core.
            let cov = (half + 0.5 - dist).clamp(0.0, 1.0);
            if cov > 0.0 {
                canvas.blend_pixel(x, y, color, (cov * 255.0) as u8);
            }
            x += 1;
        }
        y += 1;
    }
}

/// Strokes an anti-aliased circle outline of `radius` (to the stroke centre)
/// and line `width`, centred at `(cx, cy)`.
#[allow(
    clippy::float_arithmetic,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::cast_precision_loss,
    reason = "distance-field rasterisation is inherently floating-point"
)]
pub fn stroke_circle(
    canvas: &mut Canvas<'_>,
    cx: f32,
    cy: f32,
    radius: f32,
    width: f32,
    color: u32,
) {
    let half = width * 0.5;
    let pad = radius + half + 1.0;
    let min_x = libm::floorf(cx - pad).max(0.0) as i32;
    let min_y = libm::floorf(cy - pad).max(0.0) as i32;
    let max_x = libm::ceilf(cx + pad) as i32;
    let max_y = libm::ceilf(cy + pad) as i32;
    let mut y = min_y;
    while y <= max_y {
        let mut x = min_x;
        while x <= max_x {
            let dx = x as f32 + 0.5 - cx;
            let dy = y as f32 + 0.5 - cy;
            let dist_to_ring = libm::sqrtf(dx * dx + dy * dy) - radius;
            let dist = if dist_to_ring < 0.0 {
                -dist_to_ring
            } else {
                dist_to_ring
            };
            let cov = (half + 0.5 - dist).clamp(0.0, 1.0);
            if cov > 0.0 {
                canvas.blend_pixel(x, y, color, (cov * 255.0) as u8);
            }
            x += 1;
        }
        y += 1;
    }
}

/// Six hexagon-vertex offsets from the brand mark's centre at 90°, 30°,
/// −30°, −90°, −150°, 150°, radius 8 (at `scale == 1.0`) — precomputed so
/// drawing needs no runtime trig.
const HEX_OFFSETS: [(f32, f32); 6] = [
    (0.0, -8.0),
    (6.928_2, -4.0),
    (6.928_2, 4.0),
    (0.0, 8.0),
    (-6.928_2, 4.0),
    (-6.928_2, -4.0),
];
/// Diameter of each of the six hexagon-vertex dots, at `scale == 1.0`.
const HEX_DOT_D: f32 = 2.4;
/// Diameter of the centre "mission anchor" dot, at `scale == 1.0`.
const CENTER_DOT_D: f32 = 3.4;

/// Draws the shared NexaCore brand mark: a six-dot hexagon ring in `color`
/// plus a solid centre "mission anchor" dot in `anchor_color`, centred at
/// `(cx, cy)`. `scale` multiplies the whole glyph (the hexagon radius baked
/// into [`HEX_OFFSETS`] and both dot diameters) uniformly, so callers can
/// reuse one geometry for slots of different sizes (the menu bar's 26×26
/// logo slot and the dock's 48×48 launcher tile both call this with
/// `scale == 1.0` today, reproducing the mockup's fixed-size mark; a future
/// caller with a differently sized slot can pass another scale).
#[allow(
    clippy::float_arithmetic,
    reason = "small glyph geometry; distance-field stroking is float-based throughout"
)]
pub(crate) fn draw_brand_mark(
    canvas: &mut Canvas<'_>,
    cx: f32,
    cy: f32,
    scale: f32,
    color: u32,
    anchor_color: u32,
) {
    for (dx, dy) in HEX_OFFSETS {
        fill_dot(
            canvas,
            cx + dx * scale,
            cy + dy * scale,
            HEX_DOT_D * scale,
            color,
        );
    }
    fill_dot(canvas, cx, cy, CENTER_DOT_D * scale, anchor_color);
}

/// Fills an anti-aliased disc of `diameter`, centred at `(cx, cy)`.
#[allow(
    clippy::float_arithmetic,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::cast_precision_loss,
    reason = "distance-field rasterisation is inherently floating-point"
)]
pub fn fill_dot(canvas: &mut Canvas<'_>, cx: f32, cy: f32, diameter: f32, color: u32) {
    let r = diameter * 0.5;
    let pad = r + 1.0;
    let min_x = libm::floorf(cx - pad).max(0.0) as i32;
    let min_y = libm::floorf(cy - pad).max(0.0) as i32;
    let max_x = libm::ceilf(cx + pad) as i32;
    let max_y = libm::ceilf(cy + pad) as i32;
    let mut y = min_y;
    while y <= max_y {
        let mut x = min_x;
        while x <= max_x {
            let dx = x as f32 + 0.5 - cx;
            let dy = y as f32 + 0.5 - cy;
            let cov = (r + 0.5 - libm::sqrtf(dx * dx + dy * dy)).clamp(0.0, 1.0);
            if cov > 0.0 {
                canvas.blend_pixel(x, y, color, (cov * 255.0) as u8);
            }
            x += 1;
        }
        y += 1;
    }
}

/// Strokes a crescent-moon outline (two-circle "lune" construction).
///
/// The visible arc of a circle (radius `big_r`, centred at `(cx, cy)`)
/// after a second, smaller circle (radius `small_r`, centred `(dx, dy)`
/// away) "bites" into it — the classic construction used for a moon glyph.
/// Each ring only draws the arc that lies outside the *other* circle, so
/// the two partial rings join into one crescent silhouette. A visual
/// approximation of an SVG two-arc moon path, not a byte-exact port (see
/// the M7 plan's "Plan-level decisions").
#[allow(
    clippy::float_arithmetic,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::cast_precision_loss,
    clippy::too_many_arguments,
    clippy::similar_names,
    reason = "distance-field rasterisation is inherently floating-point; a two-circle lune needs both centres and radii"
)]
pub fn stroke_crescent(
    canvas: &mut Canvas<'_>,
    cx: f32,
    cy: f32,
    big_r: f32,
    dx: f32,
    dy: f32,
    small_r: f32,
    width: f32,
    color: u32,
) {
    let half = width * 0.5;
    let pad = big_r.max(small_r) + half + 1.0;
    let bite_cx = cx + dx;
    let bite_cy = cy + dy;
    let min_x = libm::floorf(cx.min(bite_cx) - pad).max(0.0) as i32;
    let min_y = libm::floorf(cy.min(bite_cy) - pad).max(0.0) as i32;
    let max_x = libm::ceilf(cx.max(bite_cx) + pad) as i32;
    let max_y = libm::ceilf(cy.max(bite_cy) + pad) as i32;
    let mut y = min_y;
    while y <= max_y {
        let mut x = min_x;
        while x <= max_x {
            let px = x as f32 + 0.5;
            let py = y as f32 + 0.5;
            let dist_big = libm::sqrtf((px - cx) * (px - cx) + (py - cy) * (py - cy));
            let dist_small =
                libm::sqrtf((px - bite_cx) * (px - bite_cx) + (py - bite_cy) * (py - bite_cy));
            // Big ring, only where it's outside the small circle (the bite).
            let big_ring = (half + 0.5 - (dist_big - big_r).abs()).clamp(0.0, 1.0);
            let big_visible = if dist_small > small_r { big_ring } else { 0.0 };
            // Small ring, only where it's inside the big circle.
            let small_ring = (half + 0.5 - (dist_small - small_r).abs()).clamp(0.0, 1.0);
            let small_visible = if dist_big < big_r { small_ring } else { 0.0 };
            let cov = big_visible.max(small_visible);
            if cov > 0.0 {
                canvas.blend_pixel(x, y, color, (cov * 255.0) as u8);
            }
            x += 1;
        }
        y += 1;
    }
}

#[cfg(test)]
mod tests {
    use nexacore_ui::canvas::Canvas;

    use super::stroke_line;

    #[test]
    fn diagonal_stroke_lays_ink_with_soft_edges() {
        const BG: u32 = 0xFF10_1010;
        const INK: u32 = 0xFFF0_F0F0;
        let mut buf = alloc::vec![BG; 32 * 32];
        {
            let mut c = Canvas::new(&mut buf, 32, 32).unwrap();
            stroke_line(&mut c, 4.0, 4.0, 27.0, 27.0, 1.8, INK);
        }
        let touched = buf.iter().filter(|&&p| p != BG).count();
        assert!(touched > 20, "stroke must lay ink ({touched} px)");
        // AA: at least one partially-blended pixel (neither BG nor full INK)
        assert!(
            buf.iter().any(|&p| p != BG && p != INK),
            "stroke must be anti-aliased"
        );
    }

    #[test]
    fn circle_and_dot_lay_antialiased_ink() {
        const BG: u32 = 0xFF10_1010;
        const INK: u32 = 0xFFF0_F0F0;
        let mut buf = alloc::vec![BG; 32 * 32];
        {
            let mut c = Canvas::new(&mut buf, 32, 32).unwrap();
            super::stroke_circle(&mut c, 16.0, 16.0, 10.0, 1.6, INK);
            super::fill_dot(&mut c, 16.0, 16.0, 5.0, INK);
        }
        let center = buf[16 * 32 + 16];
        assert_eq!(center, INK, "dot centre is solid ink");
        // Ring: a pixel on the circle at 3 o'clock is inked, midway between dot and ring is not.
        assert_ne!(buf[16 * 32 + 26], BG, "ring inked at r=10");
        assert_eq!(buf[16 * 32 + 21], BG, "gap between dot and ring untouched");
        assert!(
            buf.iter().any(|&p| p != BG && p != INK),
            "edges are anti-aliased"
        );
    }
}
