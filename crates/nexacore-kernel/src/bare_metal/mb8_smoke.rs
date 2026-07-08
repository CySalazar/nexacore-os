//! MB8 preemption smoke — two-task interleave on the serial port.
//!
//! Enabled via `--features mb8-smoke`. Spawns two kernel tasks that print
//! 'A' and 'B' in tight infinite loops with **no cooperative yield**. If
//! the LAPIC timer is actually preempting them, the serial output shows
//! alternating bursts of 'A' and 'B'; if preemption is broken, only one
//! letter ever appears (whichever task ran first).
//!
//! The function takes over the boot path: after spawning the two tasks it
//! halts the kmain bootstrap task with `hlt`, leaving the timer to do all
//! task switching. It never returns — the regular desktop demo + power-off
//! path is unreachable when `mb8-smoke` is enabled.

#![allow(unsafe_code)]

use crate::{bare_metal::early_console, scheduling::PriorityClass};

// ---------------------------------------------------------------------------
// Task bodies
// ---------------------------------------------------------------------------

/// Task A: writes "A" forever. The inner `core::hint::black_box` prevents
/// the optimiser from collapsing the loop into a single emit; we want a
/// genuinely tight loop so the only way another task gets the CPU is via
/// a hardware preemption.
fn task_a_body() -> ! {
    loop {
        early_console::emit(b"A");
        for _ in 0..100_000_u32 {
            core::hint::spin_loop();
        }
    }
}

/// Task B: writes "B" forever. Same shape as Task A — small busy delay so
/// the serial port has time to drain between bursts.
fn task_b_body() -> ! {
    loop {
        early_console::emit(b"B");
        for _ in 0..100_000_u32 {
            core::hint::spin_loop();
        }
    }
}

// ---------------------------------------------------------------------------
// Entry point — called from kmain after `sti`, never returns
// ---------------------------------------------------------------------------

/// Spawn Task A and Task B as Interactive-priority kernel tasks, then
/// halt the boot flow. The LAPIC timer is responsible for switching
/// between the bootstrap (kmain) task, Task A, and Task B from this
/// point on.
///
/// `mapper` is the kernel's active `PageMapper`, used by
/// `spawn_kernel_task` to map each task's kernel stack into the MB10
/// isolated VA range (`0xFFFF_C000_…`).
pub fn run(mapper: &mut super::paging::PageMapper) -> ! {
    early_console::write_str("[mb8-smoke] starting two-task preemption test\n");

    // SAFETY: single-CPU, no SMP. The static muts are not aliased — kmain
    // is the only caller into this function and it holds no other handles.
    unsafe {
        let sched = &mut *core::ptr::addr_of_mut!(crate::SCHEDULER);
        let fa = &mut *core::ptr::addr_of_mut!(crate::FRAME_ALLOC);

        // Task A.
        if let Some(phys) = fa.alloc_frame() {
            match sched.spawn_kernel_task(
                task_a_body,
                phys.0,
                mapper,
                fa,
                PriorityClass::Interactive,
            ) {
                Ok(_) => early_console::write_str("[mb8-smoke] task A spawned\n"),
                Err(_) => early_console::write_str("[mb8-smoke] task A SPAWN FAILED\n"),
            }
        } else {
            early_console::write_str("[mb8-smoke] task A NO FRAME\n");
        }

        // Task B.
        if let Some(phys) = fa.alloc_frame() {
            match sched.spawn_kernel_task(
                task_b_body,
                phys.0,
                mapper,
                fa,
                PriorityClass::Interactive,
            ) {
                Ok(_) => early_console::write_str("[mb8-smoke] task B spawned\n"),
                Err(_) => early_console::write_str("[mb8-smoke] task B SPAWN FAILED\n"),
            }
        } else {
            early_console::write_str("[mb8-smoke] task B NO FRAME\n");
        }
    }

    early_console::write_str("[mb8-smoke] kmain halting — timer drives scheduler\n");

    // Halt loop: wait for the timer to preempt us into Task A / Task B and
    // then alternate. `hlt` blocks until the next interrupt, which keeps
    // CPU idle while still allowing the LAPIC timer to fire.
    loop {
        unsafe {
            core::arch::asm!("hlt", options(nomem, nostack, preserves_flags));
        }
    }
}
