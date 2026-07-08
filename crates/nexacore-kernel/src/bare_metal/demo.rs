//! Graphical desktop orchestrator — M5 milestone.
//!
//! Provides [`run_desktop`], which initialises the GOP framebuffer UI and
//! runs the PS/2 + RTC event loop until the user requests power-off. The
//! caller (`kmain`) is responsible for the serial banner and ACPI S5 after
//! this function returns.
//!
//! ## Layout
//!
//! ```text
//! ┌──────────────────────────────────────────────────────────────┐
//! │ System Info (W=484)       │ Terminal (W=480)                 │
//! │ • kernel version          │ [output lines scrolling...]      │
//! │ • memory regions          │ ...                              │
//! │ • display resolution      │ nexacore$ _                          │
//! │ • serial port             │                                  │
//! │ [ Power Off ]             │                                  │
//! ├──────────────────────────────────────────────────────────────┤
//! │ NexaCore OS │              HH:MM:SS                              │
//! └──────────────────────────────────────────────────────────────┘
//! ```
//!
//! Shutdown is exclusively user-driven via the "Power Off" button in the
//! System Info window — no auto-off timer, no keyboard shortcut.

#![allow(
    clippy::doc_markdown,
    reason = "module doc references ASCII box drawing, register names, hex offsets without ticks"
)]
#![allow(
    clippy::similar_names,
    reason = "(cx0, cy0), (cpx, cpy) are pixel coord pairs by convention; renaming hurts clarity"
)]
#![allow(
    clippy::map_unwrap_or,
    reason = "Option::map(...).unwrap_or(...) reads more naturally for default-value chains"
)]
#![allow(
    clippy::too_many_lines,
    reason = "run_desktop is the orchestrator event loop; splitting hides the polling structure"
)]
#![allow(
    clippy::cast_possible_truncation,
    reason = "framebuffer/echo-buf indices fit u32 by design"
)]
#![allow(
    clippy::needless_pass_by_value,
    reason = "framebuffer ownership transfer is intentional for the run_desktop top-level"
)]

use super::{
    arch, cpuinfo, cursor::Cursor, early_console, font, graphics, graphics::FrameBuffer, input,
    vga, virtio_tablet, widget, wm,
};

// =============================================================================
// Constants
// =============================================================================

/// Maximum number of output lines kept in the terminal's circular history buffer.
///
/// When this limit is reached the oldest line is silently overwritten.  The
/// value is chosen to fill the Terminal window (height 300 px, 12 px per line,
/// minus the input row) without scrollbar infrastructure.
const TERM_MAX_LINES: usize = 20;

/// Maximum number of bytes per terminal output line.
///
/// The Terminal window is 480 px wide with 8 px margins on each side, leaving
/// 464 usable pixels.  At 8 px per character the visible column count is 58;
/// we use 56 to keep a comfortable right margin and avoid right-edge clipping.
const TERM_LINE_WIDTH: usize = 56;

/// User's choice when exiting the desktop event loop.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DesktopExitAction {
    /// ACPI S5 — full power off.
    PowerOff,
    /// System reset (ACPI reset register / port 0xCF9 / triple-fault).
    Reboot,
}

/// "Power Off" button in the System Info window content area.
const POWEROFF_BTN: widget::Button = widget::Button {
    rel_x: 8,
    rel_y: 268, // 254 + 14 (extra row for feature flag wrap)
    width: 96,
    height: 22,
    label: "Power Off",
};

/// "Reboot" button placed to the right of the Power Off button.
const REBOOT_BTN: widget::Button = widget::Button {
    rel_x: 8 + 96 + 12, // POWEROFF_BTN.rel_x + width + gap
    rel_y: 268,
    width: 80,
    height: 22,
    label: "Reboot",
};

// =============================================================================
// Public entry point
// =============================================================================

/// Initialise and run the graphical desktop until the user requests power-off
/// or reboot.
///
/// Blocks in the PS/2 + RTC event loop. Before returning it draws the
/// appropriate overlay ("Powering off…" / "Rebooting…") so the caller can
/// proceed directly to ACPI S5 or system reset.
///
/// # Parameters
///
/// - `framebuffer` — GOP framebuffer (GOP path). `None` falls back to VGA
///   text mode.
/// - `region_count` — number of physical memory regions from the bootloader;
///   displayed in the System Info window.
/// - `free_mib` — free physical RAM in MiB from the frame allocator.
/// - `total_mib` — total usable physical RAM in MiB from the frame allocator.
/// - `phys_offset` — bootloader's `physical_memory_offset`. Required by the
///   VirtIO tablet driver to translate `static mut` virtual addresses into
///   physical addresses via the page-table walker.
#[allow(
    clippy::cognitive_complexity,
    reason = "event loop orchestrator: branches mirror input sources (keyboard/mouse/RTC)"
)]
pub fn run_desktop(
    framebuffer: Option<graphics::FrameBuffer>,
    region_count: usize,
    free_mib: u32,
    total_mib: u32,
    phys_offset: u64,
    cpu_total: usize,
    cpu_bsp_apic_id: u32,
) -> DesktopExitAction {
    let fb_opt: Option<&FrameBuffer> = framebuffer.as_ref();

    // ── Window manager ────────────────────────────────────────────────────────
    let mut wm_state = wm::WindowManager::new();
    wm_state.add(wm::Window {
        x: 20,
        y: 20,
        width: 484,
        height: 322, // 308 + 14 (extra row for feature flag wrap)
        title: "System Info",
        bg_color: graphics::DARK_NAVY,
    });
    wm_state.add(wm::Window {
        x: 524,
        y: 20,
        width: 480,
        height: 300,
        title: "Terminal",
        bg_color: 0xFF_00_05_0E,
    });
    // Build Info window — full width below the existing two. Surfaces the
    // git commit, branch, build timestamp, and milestone status so the
    // running image is self-describing on Proxmox / VirtualBox / QEMU.
    wm_state.add(wm::Window {
        x: 20,
        y: 350,
        width: 984,
        height: 198,
        title: "Build Info",
        bg_color: graphics::DARK_NAVY,
    });

    // ── Terminal echo buffer ──────────────────────────────────────────────────
    let mut echo_buf = [0u8; 40];
    let mut echo_len: usize = 0;

    // ── Terminal output history ───────────────────────────────────────────────
    // Circular buffer that accumulates command output lines for the terminal
    // window. Each slot is padded to TERM_LINE_WIDTH bytes so render_terminal
    // can read directly into font::render_str without extra allocation.
    let mut term_lines: [[u8; TERM_LINE_WIDTH]; TERM_MAX_LINES] =
        [[b' '; TERM_LINE_WIDTH]; TERM_MAX_LINES];
    let mut term_line_lens: [usize; TERM_MAX_LINES] = [0; TERM_MAX_LINES];
    // Index of the *next* slot to write; wraps modulo TERM_MAX_LINES.
    let mut term_next_line: usize = 0;

    // Push a one-line welcome message into the circular buffer so the
    // terminal is not blank on first render.
    term_push_line(
        &mut term_lines,
        &mut term_line_lens,
        &mut term_next_line,
        b"NexaCore OS Shell v0.1-alpha",
    );
    term_push_line(
        &mut term_lines,
        &mut term_line_lens,
        &mut term_next_line,
        b"Type 'echo hello' to test",
    );

    // ── Shell interpreter state ───────────────────────────────────────────────
    // Lives for the duration of the desktop demo; every Enter keystroke in the
    // Terminal window runs `process_line` against these.
    // Only declared when the shell pipeline is actually compiled in (bare-metal,
    // target_os = none, non-test). The narrower cfg matches the usage site to
    // prevent unused-variable warnings in host builds.
    #[cfg(all(feature = "bare-metal", target_os = "none", not(test)))]
    let mut shell_env = {
        let mut e = nexacore_shell::env::ShellEnv::new();
        e.set("PATH", "/bin");
        e.set("HOME", "/");
        e.set("USER", "root");
        e.set("HOSTNAME", "nexacore");
        e.set("SHELL", "/bin/nexacore-shell");
        e.set("TERM", "framebuffer");
        e.set("NEXACORE_AGENT", "1");
        e
    };
    #[cfg(all(feature = "bare-metal", target_os = "none", not(test)))]
    let mut shell_cwd = alloc::string::String::from("/");

    // ── Initial render ────────────────────────────────────────────────────────
    if let Some(fb) = fb_opt {
        fb.clear(graphics::DARK_NAVY);
        wm::draw_taskbar(fb);
        let (h, m, s) = arch::rtc_time();
        render_clock(fb, h, m, s);
        wm_state.draw_all(fb);
        render_sysinfo(
            fb,
            &wm_state,
            region_count,
            free_mib,
            total_mib,
            cpu_total,
            cpu_bsp_apic_id,
        );
        render_terminal(
            fb,
            &wm_state,
            &term_lines,
            &term_line_lens,
            term_next_line,
            &echo_buf,
            echo_len,
        );
        render_buildinfo(fb, &wm_state);
    } else {
        render_vga_fallback(region_count, free_mib, total_mib);
    }

    // ── Mouse init: prefer VirtIO tablet (absolute), fall back to PS/2 ───────
    // SAFETY: `phys_offset` is the bootloader's `physical_memory_offset`
    // passed by `kmain`; ring 0; interrupts are masked for the whole demo.
    let mut vtablet = unsafe { virtio_tablet::VirtioTablet::try_init(phys_offset) };
    let use_virtio = vtablet.is_some();
    if use_virtio {
        early_console::write_str("[virtio] tablet ready\n");
    } else {
        early_console::write_str("[virtio] no legacy tablet found, using PS/2\n");
        input::ps2_mouse_init();
    }

    // ── Cursor ────────────────────────────────────────────────────────────────
    // Start at (0, 0) to match QEMU's initial virtual-cursor position. In VNC
    // mode QEMU converts absolute VNC coordinates to PS/2 relative deltas from
    // its own (0, 0) origin; starting here keeps the two in sync from the first
    // mouse event onward. The VirtIO tablet path overwrites it on the first
    // event anyway, so the starting position is harmless either way.
    let mut cursor_state: Option<Cursor> = fb_opt.map(|fb| Cursor::new(fb, 0, 0));

    // ── Event loop ────────────────────────────────────────────────────────────
    let mut last_rtc = arch::rtc_seconds();

    let exit_action = 'event: loop {
        // ── Mouse input: VirtIO tablet (absolute) when present, else PS/2 ──
        if let Some(ref mut tablet) = vtablet {
            if let Some(state) = tablet.poll() {
                if let Some(fb) = fb_opt {
                    // Scale absolute [0..=0x7FFF] coords into framebuffer px.
                    #[allow(
                        clippy::cast_possible_truncation,
                        reason = "fb dimensions are u32; scaled product divided by 0x7FFF fits in u32"
                    )]
                    #[allow(
                        clippy::integer_division,
                        reason = "abs coord scaling truncates to pixel; sub-pixel accuracy unwanted"
                    )]
                    let px = (u64::from(state.abs_x) * u64::from(fb.width) / 0x7FFF) as u32;
                    #[allow(
                        clippy::cast_possible_truncation,
                        reason = "fb dimensions are u32; scaled product divided by 0x7FFF fits in u32"
                    )]
                    #[allow(
                        clippy::integer_division,
                        reason = "abs coord scaling truncates to pixel; sub-pixel accuracy unwanted"
                    )]
                    let py = (u64::from(state.abs_y) * u64::from(fb.height) / 0x7FFF) as u32;
                    if let Some(c) = &mut cursor_state {
                        c.move_to(fb, px, py);
                    }
                    if state.buttons & 0x01 != 0 {
                        let (cpx, cpy) = cursor_state
                            .as_ref()
                            .map(|c| (c.cx, c.cy))
                            .unwrap_or((0, 0));
                        if let Some(c) = &cursor_state {
                            c.hide(fb);
                        }
                        wm_state.click_hit_test(fb, cpx, cpy);
                        let cx0 = wm_state.get(0).map_or(0, |w| w.x + 1);
                        let cy0 = wm_state.get(0).map_or(0, |w| w.y + wm::TITLEBAR_H);
                        if widget::button_hit_test(&POWEROFF_BTN, cx0, cy0, cpx, cpy) {
                            widget::draw_button(fb, cx0, cy0, &POWEROFF_BTN, true);
                            break 'event DesktopExitAction::PowerOff;
                        }
                        if widget::button_hit_test(&REBOOT_BTN, cx0, cy0, cpx, cpy) {
                            widget::draw_button(fb, cx0, cy0, &REBOOT_BTN, true);
                            break 'event DesktopExitAction::Reboot;
                        }
                        if let Some(c) = &mut cursor_state {
                            c.show(fb);
                        }
                    }
                }
            }
        } else if let Some(ev) = input::ps2_mouse_poll() {
            if let Some(fb) = fb_opt {
                // In QEMU/VNC mode PS/2 deltas are already in screen pixels
                // (QEMU converts absolute VNC coordinates to relative PS/2
                // events 1:1). Using ×1 keeps the software cursor in sync with
                // the VNC pointer; a real PS/2 mouse would need a higher factor.
                let dx = ev.dx;
                let dy = ev.dy;
                if dx != 0 || dy != 0 {
                    if let Some(c) = &mut cursor_state {
                        c.move_by(fb, dx, dy);
                    }
                }
                // Left button click → title-bar focus / power-off button.
                if ev.buttons & 0x01 != 0 {
                    let (px, py) = cursor_state
                        .as_ref()
                        .map(|c| (c.cx, c.cy))
                        .unwrap_or((0, 0));

                    if let Some(c) = &cursor_state {
                        c.hide(fb);
                    }

                    wm_state.click_hit_test(fb, px, py);

                    let cx0 = wm_state.get(0).map_or(0, |w| w.x + 1);
                    let cy0 = wm_state.get(0).map_or(0, |w| w.y + wm::TITLEBAR_H);
                    if widget::button_hit_test(&POWEROFF_BTN, cx0, cy0, px, py) {
                        widget::draw_button(fb, cx0, cy0, &POWEROFF_BTN, true);
                        break 'event DesktopExitAction::PowerOff;
                    }
                    if widget::button_hit_test(&REBOOT_BTN, cx0, cy0, px, py) {
                        widget::draw_button(fb, cx0, cy0, &REBOOT_BTN, true);
                        break 'event DesktopExitAction::Reboot;
                    }

                    if let Some(c) = &mut cursor_state {
                        c.show(fb);
                    }
                }
            }
        }

        if let Some(key) = input::ps2_poll() {
            match key {
                // ── Escape: intentionally ignored ────────────────────────────
                // Shutdown is only allowed via the "Power Off" button so the
                // user cannot terminate the session by accident.
                input::Key::Escape => {}

                // ── Window focus (Tab) ───────────────────────────────────────
                input::Key::Tab => {
                    if let Some(fb) = fb_opt {
                        if let Some(c) = &cursor_state {
                            c.hide(fb);
                        }
                        wm_state.tab_focus(fb);
                        if let Some(c) = &mut cursor_state {
                            c.show(fb);
                        }
                    }
                }

                // ── Enter: title-bar focus / button activation / command exec ─
                input::Key::Enter => {
                    if let Some(fb) = fb_opt {
                        let (px, py) = cursor_state
                            .as_ref()
                            .map(|c| (c.cx, c.cy))
                            .unwrap_or((0, 0));

                        if let Some(c) = &cursor_state {
                            c.hide(fb);
                        }

                        // Title bar → shift keyboard focus.
                        wm_state.click_hit_test(fb, px, py);

                        // Power Off / Reboot button → highlight + exit.
                        let cx0 = wm_state.get(0).map_or(0, |w| w.x + 1);
                        let cy0 = wm_state.get(0).map_or(0, |w| w.y + wm::TITLEBAR_H);
                        if widget::button_hit_test(&POWEROFF_BTN, cx0, cy0, px, py) {
                            widget::draw_button(fb, cx0, cy0, &POWEROFF_BTN, true);
                            break 'event DesktopExitAction::PowerOff;
                        }
                        if widget::button_hit_test(&REBOOT_BTN, cx0, cy0, px, py) {
                            widget::draw_button(fb, cx0, cy0, &REBOOT_BTN, true);
                            break 'event DesktopExitAction::Reboot;
                        }

                        // ── Terminal Enter: execute the typed command ─────────
                        // Build command string from the echo buffer.
                        // justification: echo_len is guarded to <= echo_buf.len();
                        // prompt + cmd are sliced within TERM_LINE_WIDTH by min().
                        #[allow(clippy::indexing_slicing)]
                        let cmd_bytes = &echo_buf[..echo_len];
                        if let Ok(cmd_str) = core::str::from_utf8(cmd_bytes) {
                            // Echo the prompt + command into the output history.
                            let mut prompt_line = [0u8; TERM_LINE_WIDTH];
                            let prompt = b"$ ";
                            let pl = prompt.len();
                            // justification: prompt is 2 bytes, pl < TERM_LINE_WIDTH;
                            // cmd_len = min(cmd_str.len(), TERM_LINE_WIDTH - pl) keeps
                            // pl + cmd_len <= TERM_LINE_WIDTH == prompt_line.len().
                            #[allow(clippy::indexing_slicing)]
                            {
                                prompt_line[..pl].copy_from_slice(prompt);
                                let cmd_len = cmd_str.len().min(TERM_LINE_WIDTH - pl);
                                prompt_line[pl..pl + cmd_len]
                                    .copy_from_slice(&cmd_bytes[..cmd_len]);
                                term_push_line(
                                    &mut term_lines,
                                    &mut term_line_lens,
                                    &mut term_next_line,
                                    &prompt_line[..pl + cmd_len],
                                );
                            }

                            // Execute through the shell pipeline (bare-metal only).
                            #[cfg(all(feature = "bare-metal", target_os = "none", not(test)))]
                            if !cmd_str.is_empty() {
                                let fs = KernelFsQuery;
                                // This bare-metal debug shell has no network IPC of its
                                // own (unlike `omni-apps-image`'s windowed Terminal) —
                                // `ifconfig` here reports no interfaces rather than
                                // querying a real stack.
                                let net = nexacore_shell::netquery::NoNet;
                                let (_exit_code, output) = nexacore_shell::repl::process_line(
                                    cmd_str,
                                    &mut shell_env,
                                    &mut shell_cwd,
                                    &fs,
                                    &net,
                                );
                                // Push each line of the command output into the
                                // terminal history.  Empty trailing lines are
                                // skipped so a command that ends with '\n' does not
                                // waste a history slot.
                                for line in output.split(|&b| b == b'\n') {
                                    if !line.is_empty() {
                                        term_push_line(
                                            &mut term_lines,
                                            &mut term_line_lens,
                                            &mut term_next_line,
                                            line,
                                        );
                                    }
                                }
                            }
                        }

                        // Clear the input buffer and redraw.
                        echo_len = 0;
                        render_terminal(
                            fb,
                            &wm_state,
                            &term_lines,
                            &term_line_lens,
                            term_next_line,
                            &echo_buf,
                            echo_len,
                        );

                        if let Some(c) = &mut cursor_state {
                            c.show(fb);
                        }
                    }
                }

                // ── Backspace ────────────────────────────────────────────────
                input::Key::Backspace => {
                    if let Some(fb) = fb_opt {
                        if let Some(c) = &cursor_state {
                            c.hide(fb);
                        }
                        #[allow(
                            clippy::implicit_saturating_sub,
                            reason = "explicit form documents intent for security audit"
                        )]
                        if echo_len > 0 {
                            echo_len -= 1;
                        }
                        render_terminal(
                            fb,
                            &wm_state,
                            &term_lines,
                            &term_line_lens,
                            term_next_line,
                            &echo_buf,
                            echo_len,
                        );
                        if let Some(c) = &mut cursor_state {
                            c.show(fb);
                        }
                    }
                }

                // ── Printable key → terminal echo ────────────────────────────
                input::Key::Char(byte) => {
                    if let Some(fb) = fb_opt {
                        if let Some(c) = &cursor_state {
                            c.hide(fb);
                        }
                        if echo_len < 40 {
                            #[allow(
                                clippy::indexing_slicing,
                                reason = "echo_len < 40 <= echo_buf.len() guarded above"
                            )]
                            {
                                echo_buf[echo_len] = byte;
                            }
                            echo_len += 1;
                        }
                        render_terminal(
                            fb,
                            &wm_state,
                            &term_lines,
                            &term_line_lens,
                            term_next_line,
                            &echo_buf,
                            echo_len,
                        );
                        if let Some(c) = &mut cursor_state {
                            c.show(fb);
                        }
                    }
                }

                // ── Arrow keys → cursor movement ─────────────────────────────
                input::Key::ArrowUp => {
                    if let Some(fb) = fb_opt {
                        if let Some(c) = &mut cursor_state {
                            c.move_by(fb, 0, -4);
                        }
                    }
                }
                input::Key::ArrowDown => {
                    if let Some(fb) = fb_opt {
                        if let Some(c) = &mut cursor_state {
                            c.move_by(fb, 0, 4);
                        }
                    }
                }
                input::Key::ArrowLeft => {
                    if let Some(fb) = fb_opt {
                        if let Some(c) = &mut cursor_state {
                            c.move_by(fb, -4, 0);
                        }
                    }
                }
                input::Key::ArrowRight => {
                    if let Some(fb) = fb_opt {
                        if let Some(c) = &mut cursor_state {
                            c.move_by(fb, 4, 0);
                        }
                    }
                }
            }
        }

        // ── RTC tick ──────────────────────────────────────────────────────────
        // Refresh the clock once per second; no countdown / auto-shutdown.
        let curr = arch::rtc_seconds();
        let delta = if curr >= last_rtc {
            curr - last_rtc
        } else {
            60 - last_rtc + curr
        };
        if delta >= 1 {
            last_rtc = curr;
            if let Some(fb) = fb_opt {
                if let Some(c) = &cursor_state {
                    c.hide(fb);
                }
                let (h, m, s) = arch::rtc_time();
                render_clock(fb, h, m, s);
                if let Some(c) = &mut cursor_state {
                    c.show(fb);
                }
            }
        }

        // Cooperative idle (FU2a, 2026-06-04). The desktop is a System-priority
        // kmain loop; busy-spinning here monopolised the CPU (a timer-tick
        // heartbeat found it current at essentially every sample), starving the
        // Ring-3 network services so the TCP datapath scheduled only
        // intermittently. `hlt` yields the quantum: the CPU sleeps until the next
        // LAPIC timer interrupt, whose resched tail rotates to a runnable peer;
        // the desktop resumes here on its next round-robin turn. UI latency drops
        // to the timer-tick cadence, which is imperceptible.
        #[cfg(target_arch = "x86_64")]
        // SAFETY: the desktop runs in ring 0 with IF=1, so `hlt` resumes on the
        // next interrupt (the periodic LAPIC timer is always armed).
        #[allow(unsafe_code, reason = "cooperative idle: hlt yields CPU to peers")]
        unsafe {
            core::arch::asm!("hlt", options(nomem, nostack, preserves_flags));
        }
        #[cfg(not(target_arch = "x86_64"))]
        core::hint::spin_loop();
    };

    // ── Exit overlay ──────────────────────────────────────────────────────────
    if let Some(fb) = fb_opt {
        if let Some(c) = &cursor_state {
            c.hide(fb);
        }
        match exit_action {
            DesktopExitAction::PowerOff => wm::show_poweroff_overlay(fb),
            DesktopExitAction::Reboot => wm::show_reboot_overlay(fb),
        }
    } else {
        let msg = match exit_action {
            DesktopExitAction::PowerOff => b"Powering off...              ",
            DesktopExitAction::Reboot => b"Rebooting...                 ",
        };
        vga::write_at(16, 4, msg, vga::YELLOW, vga::BLACK);
    }

    exit_action
}

// =============================================================================
// Private rendering helpers
// =============================================================================

/// Render the RTC clock (HH:MM:SS) centred in the taskbar.
#[allow(
    clippy::integer_division,
    reason = "pixel and clock digit math; integer truncation is intentional"
)]
fn render_clock(fb: &FrameBuffer, h: u8, m: u8, s: u8) {
    let y0 = fb.height.saturating_sub(wm::TASKBAR_H);
    let time_w = 64_u32; // 8 chars × 8px
    let tx = (fb.width / 2).saturating_sub(time_w / 2);
    let ty = y0 + 10;

    // Clear the clock area (slightly wider to erase the previous value).
    fb.draw_rect_filled(
        tx.saturating_sub(4),
        y0 + 1,
        tx + time_w + 4,
        fb.height,
        graphics::DARK_NAVY,
    );

    let buf: [u8; 8] = [
        b'0' + h / 10,
        b'0' + h % 10,
        b':',
        b'0' + m / 10,
        b'0' + m % 10,
        b':',
        b'0' + s / 10,
        b'0' + s % 10,
    ];
    if let Ok(time_str) = core::str::from_utf8(&buf) {
        font::render_str(fb, tx, ty, time_str, graphics::WHITE, graphics::DARK_NAVY);
    }
}

/// Render the System Info window content (labels + Power Off button).
#[allow(
    clippy::too_many_arguments,
    reason = "render_sysinfo paints a fixed-format panel; every argument is a distinct visible field"
)]
#[allow(
    clippy::too_many_lines,
    reason = "linear sequence of font::render_str calls — one per displayed row"
)]
fn render_sysinfo(
    fb: &FrameBuffer,
    wm_state: &wm::WindowManager,
    region_count: usize,
    free_mib: u32,
    total_mib: u32,
    cpu_total: usize,
    cpu_bsp_apic_id: u32,
) {
    let Some(w) = wm_state.get(0) else { return };
    let cx = w.x + 8;
    let cy = w.y + wm::TITLEBAR_H + 8;
    let step: u32 = 14;

    font::render_str(
        fb,
        cx,
        cy,
        "Kernel  : nexacore-kernel v",
        graphics::CYAN,
        w.bg_color,
    );
    font::render_str(
        fb,
        cx + 23 * 8,
        cy,
        env!("CARGO_PKG_VERSION"),
        graphics::WHITE,
        w.bg_color,
    );
    font::render_str(
        fb,
        cx,
        cy + step,
        "Boot    : UEFI + GOP Framebuffer",
        graphics::CYAN,
        w.bg_color,
    );
    font::render_str(
        fb,
        cx,
        cy + step * 2,
        "Memory  : ",
        graphics::CYAN,
        w.bg_color,
    );
    font::render_usize_scaled(
        fb,
        cx + 10 * 8,
        cy + step * 2,
        region_count,
        graphics::WHITE,
        w.bg_color,
        1,
    );
    let rw = font::digit_width(region_count, 1);
    font::render_str(
        fb,
        cx + 10 * 8 + rw + 4,
        cy + step * 2,
        "regions",
        graphics::WHITE,
        w.bg_color,
    );
    font::render_str(
        fb,
        cx,
        cy + step * 3,
        "Display : ",
        graphics::CYAN,
        w.bg_color,
    );
    font::render_usize_scaled(
        fb,
        cx + 10 * 8,
        cy + step * 3,
        fb.width as usize,
        graphics::WHITE,
        w.bg_color,
        1,
    );
    let dw = font::digit_width(fb.width as usize, 1);
    font::render_str(
        fb,
        cx + 10 * 8 + dw,
        cy + step * 3,
        " x ",
        graphics::WHITE,
        w.bg_color,
    );
    let xh = cx + 10 * 8 + dw + 3 * 8;
    font::render_usize_scaled(
        fb,
        xh,
        cy + step * 3,
        fb.height as usize,
        graphics::WHITE,
        w.bg_color,
        1,
    );
    let hw = font::digit_width(fb.height as usize, 1);
    font::render_str(
        fb,
        xh + hw,
        cy + step * 3,
        " @ 32bpp",
        graphics::WHITE,
        w.bg_color,
    );
    font::render_str(
        fb,
        cx,
        cy + step * 4,
        "Serial  : COM1 @ 115200 8N1",
        graphics::CYAN,
        w.bg_color,
    );
    // RAM stats from BitmapFrameAllocator (Track B MB1).
    font::render_str(
        fb,
        cx,
        cy + step * 5,
        "Ram     : ",
        graphics::CYAN,
        w.bg_color,
    );
    font::render_usize_scaled(
        fb,
        cx + 10 * 8,
        cy + step * 5,
        free_mib as usize,
        graphics::WHITE,
        w.bg_color,
        1,
    );
    let fw = font::digit_width(free_mib as usize, 1);
    font::render_str(
        fb,
        cx + 10 * 8 + fw,
        cy + step * 5,
        " /",
        graphics::DARK_GRAY,
        w.bg_color,
    );
    font::render_usize_scaled(
        fb,
        cx + 10 * 8 + fw + 2 * 8 + 4,
        cy + step * 5,
        total_mib as usize,
        graphics::WHITE,
        w.bg_color,
        1,
    );
    let tw = font::digit_width(total_mib as usize, 1);
    font::render_str(
        fb,
        cx + 10 * 8 + fw + 2 * 8 + 4 + tw,
        cy + step * 5,
        " MiB free",
        graphics::LIGHT_CYAN,
        w.bg_color,
    );
    // Track B MB2: page-table walker.
    font::render_str(
        fb,
        cx,
        cy + step * 6,
        "Paging  : mapper ready (MB2)",
        graphics::CYAN,
        w.bg_color,
    );
    // Track B MB3: IDT loaded.
    font::render_str(
        fb,
        cx,
        cy + step * 7,
        "IDT     : loaded #DE #DF #GP #PF",
        graphics::CYAN,
        w.bg_color,
    );
    // Track B MB4: syscall dispatcher.
    font::render_str(
        fb,
        cx,
        cy + step * 8,
        "Syscall : LSTAR+INT80 ready (MB4)",
        graphics::CYAN,
        w.bg_color,
    );
    // Track B MB5: ELF64 loader.
    font::render_str(
        fb,
        cx,
        cy + step * 9,
        "ELF     : parser ready (MB5)",
        graphics::CYAN,
        w.bg_color,
    );

    // ── CPU rows (MB14.a/c.1 + CPUID snapshot) ────────────────────────
    let snap = cpuinfo::snapshot();

    // Row 10 — CPU brand (CPUID 0x80000002..4).
    font::render_str(
        fb,
        cx,
        cy + step * 10,
        "CPU     : ",
        graphics::CYAN,
        w.bg_color,
    );
    {
        let brand = cpuinfo::trim_brand(&snap.brand);
        let brand_str = core::str::from_utf8(brand).unwrap_or("(non-ASCII)");
        font::render_str(
            fb,
            cx + 10 * 8,
            cy + step * 10,
            brand_str,
            graphics::WHITE,
            w.bg_color,
        );
    }

    // Row 11 — CPU vendor (CPUID 0).
    font::render_str(
        fb,
        cx,
        cy + step * 11,
        "Vendor  : ",
        graphics::CYAN,
        w.bg_color,
    );
    {
        let vendor_str = core::str::from_utf8(&snap.vendor).unwrap_or("(non-ASCII)");
        font::render_str(
            fb,
            cx + 10 * 8,
            cy + step * 11,
            vendor_str,
            graphics::WHITE,
            w.bg_color,
        );
    }

    // Row 12 — Family / Model / Stepping (CPUID 1 EAX decoded).
    font::render_str(
        fb,
        cx,
        cy + step * 12,
        "CPUID   : Family ",
        graphics::CYAN,
        w.bg_color,
    );
    let fm = snap.family_model;
    let mut x_cursor = cx + 17 * 8;
    font::render_usize_scaled(
        fb,
        x_cursor,
        cy + step * 12,
        fm.family as usize,
        graphics::WHITE,
        w.bg_color,
        1,
    );
    x_cursor += font::digit_width(fm.family as usize, 1);
    font::render_str(
        fb,
        x_cursor,
        cy + step * 12,
        " Model ",
        graphics::CYAN,
        w.bg_color,
    );
    x_cursor += 7 * 8;
    font::render_usize_scaled(
        fb,
        x_cursor,
        cy + step * 12,
        fm.model as usize,
        graphics::WHITE,
        w.bg_color,
        1,
    );
    x_cursor += font::digit_width(fm.model as usize, 1);
    font::render_str(
        fb,
        x_cursor,
        cy + step * 12,
        " Step ",
        graphics::CYAN,
        w.bg_color,
    );
    x_cursor += 6 * 8;
    font::render_usize_scaled(
        fb,
        x_cursor,
        cy + step * 12,
        fm.stepping as usize,
        graphics::WHITE,
        w.bg_color,
        1,
    );

    // Row 13 — logical cores enumerated via the MADT.
    font::render_str(
        fb,
        cx,
        cy + step * 13,
        "Cores   : ",
        graphics::CYAN,
        w.bg_color,
    );
    let mut xc = cx + 10 * 8;
    font::render_usize_scaled(
        fb,
        xc,
        cy + step * 13,
        cpu_total,
        graphics::WHITE,
        w.bg_color,
        1,
    );
    xc += font::digit_width(cpu_total, 1);
    font::render_str(
        fb,
        xc,
        cy + step * 13,
        " logical (BSP+",
        graphics::DARK_GRAY,
        w.bg_color,
    );
    xc += 14 * 8;
    let ap_count = cpu_total.saturating_sub(1);
    font::render_usize_scaled(
        fb,
        xc,
        cy + step * 13,
        ap_count,
        graphics::WHITE,
        w.bg_color,
        1,
    );
    xc += font::digit_width(ap_count, 1);
    font::render_str(
        fb,
        xc,
        cy + step * 13,
        " AP)",
        graphics::DARK_GRAY,
        w.bg_color,
    );

    // Row 14 — BSP LAPIC ID + APIC mode.
    font::render_str(
        fb,
        cx,
        cy + step * 14,
        "APIC    : BSP id=",
        graphics::CYAN,
        w.bg_color,
    );
    let mut xa = cx + 17 * 8;
    font::render_usize_scaled(
        fb,
        xa,
        cy + step * 14,
        cpu_bsp_apic_id as usize,
        graphics::WHITE,
        w.bg_color,
        1,
    );
    xa += font::digit_width(cpu_bsp_apic_id as usize, 1);
    font::render_str(
        fb,
        xa,
        cy + step * 14,
        " mode=xAPIC",
        graphics::DARK_GRAY,
        w.bg_color,
    );

    // Row 15+ — feature flags (selected subset of CPUID 1/7).
    // The feature string can exceed the window width on CPUs with many
    // extensions, so we word-wrap at the nearest space boundary.
    font::render_str(
        fb,
        cx,
        cy + step * 15,
        "Feats   : ",
        graphics::CYAN,
        w.bg_color,
    );
    {
        let feats = cpuinfo::trim_feature_summary(&snap.feature_summary);
        let feats_str = core::str::from_utf8(feats).unwrap_or("(non-ASCII)");
        let label_px = 10 * 8;
        let max_value_px = w.width.saturating_sub(16 + label_px);
        #[allow(
            clippy::integer_division,
            reason = "pixel-to-char conversion; sub-char precision is meaningless"
        )]
        let max_chars = (max_value_px / 8) as usize;
        let mut remaining = feats_str;
        let mut row_off: u32 = 0;
        while !remaining.is_empty() {
            let (line, rest) = if remaining.len() <= max_chars {
                (remaining, "")
            } else {
                let cut = remaining[..max_chars].rfind(' ').unwrap_or(max_chars);
                let (l, r) = remaining.split_at(cut);
                (l, r.trim_start())
            };
            let x_off = label_px;
            font::render_str(
                fb,
                cx + x_off,
                cy + step * (15 + row_off),
                line,
                graphics::LIGHT_CYAN,
                w.bg_color,
            );
            remaining = rest;
            row_off += 1;
        }
    }

    widget::draw_button(fb, w.x + 1, w.y + wm::TITLEBAR_H, &POWEROFF_BTN, false);
    widget::draw_button(fb, w.x + 1, w.y + wm::TITLEBAR_H, &REBOOT_BTN, false);
}

/// Kernel VFS adapter for the nexacore-shell `FsQuery` trait.
///
/// Reads directory listings directly from the global `SHELL_VFS` that was
/// initialised in `kmain` before the desktop demo was entered.
///
/// This type is only meaningful inside a bare-metal build where the VFS
/// global exists.
#[cfg(all(feature = "bare-metal", target_os = "none", not(test)))]
struct KernelFsQuery;

#[cfg(all(feature = "bare-metal", target_os = "none", not(test)))]
impl nexacore_shell::glob::FsQuery for KernelFsQuery {
    /// List the direct children of `path` by querying `SHELL_VFS`.
    ///
    /// # Safety invariant
    ///
    /// Single-CPU, no-preemption: the bare-metal kernel runs on one logical
    /// core with maskable interrupts disabled during the desktop event loop.
    /// `SHELL_VFS` is never written after `kmain` finishes initialisation,
    /// so reading it here is free of data races.
    fn list_dir(
        &self,
        path: &str,
    ) -> Result<alloc::vec::Vec<alloc::string::String>, alloc::string::String> {
        // SAFETY: single-CPU bare-metal; SHELL_VFS is not aliased here.
        // We only read (shared reference) from the VFS; no mutation occurs.
        #[allow(unsafe_code, reason = "single-CPU VFS read; SAFETY comment above")]
        unsafe {
            (*core::ptr::addr_of!(crate::SHELL_VFS))
                .as_ref()
                .map_or_else(
                    || Err(alloc::string::String::from("no VFS")),
                    |vfs| {
                        vfs.list_directory(path).map_or_else(
                            |_| Err(alloc::string::String::from("not found")),
                            |entries| Ok(entries.iter().map(|e| e.name.clone()).collect()),
                        )
                    },
                )
        }
    }
}

/// Append one line of text into the circular terminal-output buffer.
///
/// - `lines` — the 2-D array of line bytes (`[TERM_MAX_LINES][TERM_LINE_WIDTH]`).
/// - `lens` — corresponding length of each used slot.
/// - `next` — index of the next slot to fill; updated to `(*next + 1) %
///   TERM_MAX_LINES` after the write.
/// - `text` — raw bytes to store; silently truncated to `TERM_LINE_WIDTH`.
///
/// # Example
///
/// ```rust,ignore
/// // This is a bare-metal function; not callable in host doctests.
/// // Usage:
/// // term_push_line(&mut lines, &mut lens, &mut next, b"hello world");
/// ```
fn term_push_line(
    lines: &mut [[u8; TERM_LINE_WIDTH]; TERM_MAX_LINES],
    lens: &mut [usize; TERM_MAX_LINES],
    next: &mut usize,
    text: &[u8],
) {
    let len = text.len().min(TERM_LINE_WIDTH);
    // Copy the text bytes into the current slot.
    #[allow(
        clippy::indexing_slicing,
        reason = "len <= TERM_LINE_WIDTH; *next < TERM_MAX_LINES by modulo invariant"
    )]
    {
        lines[*next][..len].copy_from_slice(&text[..len]);
        // Clear the remainder of the slot so old data does not bleed through.
        for i in len..TERM_LINE_WIDTH {
            lines[*next][i] = b' ';
        }
        lens[*next] = len;
    }
    *next = (*next + 1) % TERM_MAX_LINES;
}

/// Render the Build Info window content.
///
/// Surfaces build-time metadata (git commit, branch, build timestamp) injected
/// by `crates/nexacore-kernel/build.rs`, plus static milestone status so the
/// running image is self-describing without consulting the host repo.
fn render_buildinfo(fb: &FrameBuffer, wm_state: &wm::WindowManager) {
    use core::sync::atomic::Ordering;

    use super::driver_loader::{E1000E_LIVE, E1000E_MAC};
    let Some(w) = wm_state.get(2) else { return };
    let cx_l = w.x + 8;
    #[allow(
        clippy::integer_division,
        reason = "half-width column split; sub-pixel precision is meaningless on a pixel grid"
    )]
    let cx_r = w.x + w.width / 2 + 8;
    let cy = w.y + wm::TITLEBAR_H + 8;
    let step: u32 = 14;

    // Helper closure: "Label  : value" with cyan label + white value.
    let row =
        |row_idx: u32, col_x: u32, label: &str, label_w: u32, value: &str, value_color: u32| {
            font::render_str(
                fb,
                col_x,
                cy + step * row_idx,
                label,
                graphics::CYAN,
                w.bg_color,
            );
            font::render_str(
                fb,
                col_x + label_w * 8,
                cy + step * row_idx,
                value,
                value_color,
                w.bg_color,
            );
        };

    // ── Left column: identity + provenance ─────────────────────────────
    row(
        0,
        cx_l,
        "Version  : nexacore-kernel v",
        23,
        env!("CARGO_PKG_VERSION"),
        graphics::WHITE,
    );
    row(
        1,
        cx_l,
        "Branch   : ",
        11,
        env!("NEXACORE_GIT_BRANCH"),
        graphics::WHITE,
    );
    row(
        2,
        cx_l,
        "Commit   : ",
        11,
        env!("NEXACORE_GIT_HASH"),
        graphics::LIGHT_CYAN,
    );
    row(
        3,
        cx_l,
        "Built    : ",
        11,
        env!("NEXACORE_BUILD_DATE"),
        graphics::WHITE,
    );
    row(
        4,
        cx_l,
        "Rustc    : ",
        11,
        "1.85 stable + x86_64-unknown-none",
        graphics::WHITE,
    );
    row(5, cx_l, "License  : ", 11, "Apache-2.0", graphics::WHITE);
    row(
        6,
        cx_l,
        "Repo     : ",
        11,
        "github.com/CySalazar/nexacore-os",
        graphics::WHITE,
    );

    // ── Right column: implementation status ────────────────────────────
    row(
        0,
        cx_r,
        "Phase    : ",
        11,
        "2 - AI Runtime (Sprint 11)",
        graphics::WHITE,
    );
    row(
        1,
        cx_r,
        "Track A  : ",
        11,
        "Desktop M1-M5  OK",
        graphics::WHITE,
    );
    row(
        2,
        cx_r,
        "Track B  : ",
        11,
        "MB1-MB14 OK (cycle closed)",
        graphics::WHITE,
    );
    row(
        3,
        cx_r,
        "Active   : ",
        11,
        "TASK-27 USB HID/storage",
        graphics::LIGHT_CYAN,
    );
    row(
        4,
        cx_r,
        "Next     : ",
        11,
        "M5: xHCI+USB enum done",
        graphics::WHITE,
    );
    row(
        5,
        cx_r,
        "Tests    : ",
        11,
        "4640+1077 tests pass",
        graphics::WHITE,
    );

    // e1000e live status — show MAC if bring-up succeeded.
    // justification: buf has 32 bytes; pos starts at 13 and advances at most
    // 6*3-1 = 17 more bytes (< 32). hex is a 16-byte const; nibbles are 4-bit
    // values (0..=15). E1000E_MAC has exactly 6 elements accessed by literal index.
    #[allow(clippy::indexing_slicing)]
    if E1000E_LIVE.load(Ordering::Relaxed) {
        let m = [
            E1000E_MAC[0].load(Ordering::Relaxed),
            E1000E_MAC[1].load(Ordering::Relaxed),
            E1000E_MAC[2].load(Ordering::Relaxed),
            E1000E_MAC[3].load(Ordering::Relaxed),
            E1000E_MAC[4].load(Ordering::Relaxed),
            E1000E_MAC[5].load(Ordering::Relaxed),
        ];
        // Format "e1000e LIVE  52:54:00:12:34:56" into a stack buffer.
        let hex = b"0123456789ABCDEF";
        let mut buf = [0u8; 32];
        buf[0] = b'e';
        buf[1] = b'1';
        buf[2] = b'0';
        buf[3] = b'0';
        buf[4] = b'0';
        buf[5] = b'e';
        buf[6] = b' ';
        buf[7] = b'L';
        buf[8] = b'I';
        buf[9] = b'V';
        buf[10] = b'E';
        buf[11] = b' ';
        buf[12] = b' ';
        let mut pos = 13;
        for (i, byte) in m.iter().enumerate() {
            buf[pos] = hex[(byte >> 4) as usize];
            buf[pos + 1] = hex[(byte & 0xF) as usize];
            pos += 2;
            if i < 5 {
                buf[pos] = b':';
                pos += 1;
            }
        }
        // SAFETY: buf is filled with ASCII hex + separators only.
        #[allow(unsafe_code)]
        let mac_str = unsafe { core::str::from_utf8_unchecked(&buf[..pos]) };
        row(6, cx_r, "Network  : ", 11, mac_str, 0xFF_00_DD_00);
    } else {
        row(6, cx_r, "Network  : ", 11, "no e1000e", graphics::DARK_GRAY);
    }
    row(7, cx_r, "Author   : ", 11, "cySalazar", graphics::WHITE);
}

/// Render the terminal window: scrolling output history followed by the input line.
///
/// Clears the entire terminal content area, paints up to `TERM_MAX_LINES` lines
/// of output history (oldest-first), then paints the `nexacore$ ` prompt and the
/// current echo buffer at the bottom.
///
/// The circular buffer is read starting from `next_line` (the oldest unwritten
/// slot) and wrapping around, so the most recent output always appears
/// immediately above the input line.
#[allow(
    clippy::too_many_arguments,
    reason = "render_terminal mirrors render_sysinfo in passing every visible datum as a distinct argument"
)]
fn render_terminal(
    fb: &FrameBuffer,
    wm_state: &wm::WindowManager,
    lines: &[[u8; TERM_LINE_WIDTH]; TERM_MAX_LINES],
    lens: &[usize; TERM_MAX_LINES],
    next_line: usize,
    echo: &[u8; 40],
    echo_len: usize,
) {
    let Some(w) = wm_state.get(1) else { return };
    let tx = w.x + 8;
    let ty_base = w.y + wm::TITLEBAR_H + 8;
    let line_height: u32 = 12;
    let x_end = w.x + w.width - 1;

    // Clear the full terminal content area so no stale pixels remain.
    let term_height = TERM_MAX_LINES as u32 * line_height + 20;
    fb.draw_rect_filled(tx, ty_base, x_end, ty_base + term_height, w.bg_color);

    // Paint history lines oldest-first.  The circular buffer stores entries in
    // insertion order; `next_line` is the next *write* slot, so reading from
    // `next_line` gives the oldest entry and wrapping around gives the newest.
    for i in 0..TERM_MAX_LINES {
        let idx = (next_line + i) % TERM_MAX_LINES;
        #[allow(
            clippy::indexing_slicing,
            reason = "idx < TERM_MAX_LINES by modulo; i < TERM_MAX_LINES by loop bound"
        )]
        let len = lens[idx];
        if len == 0 {
            continue;
        }
        #[allow(
            clippy::indexing_slicing,
            reason = "idx < TERM_MAX_LINES; len <= TERM_LINE_WIDTH by invariant"
        )]
        if let Ok(s) = core::str::from_utf8(&lines[idx][..len]) {
            let ty = ty_base + i as u32 * line_height;
            font::render_str(fb, tx, ty, s, graphics::WHITE, w.bg_color);
        }
    }

    // Input line: prompt + typed chars + cursor.
    let input_y = ty_base + TERM_MAX_LINES as u32 * line_height + 4;
    font::render_str(fb, tx, input_y, "nexacore$ ", graphics::CYAN, w.bg_color);
    // Prompt is 6 characters × 8 px/char = 48 px.
    let echo_x = tx + 6 * 8;
    let visible = echo.get(..echo_len).unwrap_or(&[]);
    if let Ok(echo_str) = core::str::from_utf8(visible) {
        font::render_str(fb, echo_x, input_y, echo_str, graphics::WHITE, w.bg_color);
    }
    // Cursor indicator one position past the last character.
    if echo_len < 40 {
        font::render_str(
            fb,
            echo_x + echo_len as u32 * 8,
            input_y,
            "|",
            graphics::LIGHT_CYAN,
            w.bg_color,
        );
    }
}

/// VGA text-mode fallback banner (no GOP framebuffer).
fn render_vga_fallback(region_count: usize, free_mib: u32, total_mib: u32) {
    vga::clear(vga::WHITE, vga::BLACK);
    vga::write_at(3, 2, &[0xCD_u8; 76], vga::CYAN, vga::BLACK);
    vga::write_at(7, 2, &[0xCD_u8; 76], vga::CYAN, vga::BLACK);
    vga::write_at(4, 27, b"  O M N I   O S  ", vga::YELLOW, vga::BLACK);
    vga::write_at(5, 27, b"  Boot Demo       ", vga::WHITE, vga::BLACK);
    vga::write_at(6, 27, b"  v", vga::WHITE, vga::BLACK);
    vga::write_at(
        6,
        30,
        env!("CARGO_PKG_VERSION").as_bytes(),
        vga::LIGHT_CYAN,
        vga::BLACK,
    );
    vga::write_at(9, 4, b"Kernel:", vga::LIGHT_CYAN, vga::BLACK);
    vga::write_at(9, 20, b"nexacore-kernel v", vga::WHITE, vga::BLACK);
    vga::write_at(
        9,
        33,
        env!("CARGO_PKG_VERSION").as_bytes(),
        vga::WHITE,
        vga::BLACK,
    );
    vga::write_at(10, 4, b"Boot mode:", vga::LIGHT_CYAN, vga::BLACK);
    vga::write_at(
        10,
        20,
        b"UEFI / bootloader 0.11 (OVMF)",
        vga::WHITE,
        vga::BLACK,
    );
    vga::write_at(11, 4, b"Memory:", vga::LIGHT_CYAN, vga::BLACK);
    vga::write_usize_at(11, 20, region_count, vga::WHITE, vga::BLACK);
    vga::write_at(11, 23, b"physical regions mapped", vga::WHITE, vga::BLACK);
    vga::write_at(12, 4, b"Ram:", vga::LIGHT_CYAN, vga::BLACK);
    vga::write_usize_at(12, 20, free_mib as usize, vga::WHITE, vga::BLACK);
    vga::write_at(12, 23, b"/", vga::WHITE, vga::BLACK);
    vga::write_usize_at(12, 25, total_mib as usize, vga::WHITE, vga::BLACK);
    vga::write_at(12, 28, b"MiB free", vga::LIGHT_CYAN, vga::BLACK);
    vga::write_at(13, 4, b"Serial:", vga::LIGHT_CYAN, vga::BLACK);
    vga::write_at(13, 20, b"COM1 @ 115200 8N1", vga::WHITE, vga::BLACK);
    vga::write_at(
        14,
        4,
        b"Syscall: LSTAR+INT80 ready (MB4)",
        vga::LIGHT_CYAN,
        vga::BLACK,
    );
    vga::write_at(
        15,
        4,
        b"ELF  : parser ready (MB5)     ",
        vga::LIGHT_CYAN,
        vga::BLACK,
    );
    vga::write_at(
        16,
        4,
        b"Powering off in:    seconds  ",
        vga::YELLOW,
        vga::BLACK,
    );
}
