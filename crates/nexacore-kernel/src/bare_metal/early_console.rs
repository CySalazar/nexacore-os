//! Pre-allocator console writer to the 16550 UART on COM1 (`0x3f8`).
//!
//! The panic handler emits its [`super::panic::PanicRecord`] byte-by-
//! byte through this module **before** any allocation could be made
//! (the panic path is non-allocating by `NCIP-Kernel-012` § S1
//! constraint 1) and **after** [`super::arch::interrupts::disable`]
//! has run. The writer is therefore deliberately minimal: it polls
//! the UART line-status register (LSR) for the THR-empty bit and
//! writes one byte. No buffering, no formatting, no allocation.
//!
//! At K4 the console is also used by `kmain` to print the boot banner
//! and the memory-region count (`NCIP-Kernel-005` § S3). That code path
//! is not allocation-sensitive but goes through this module anyway so
//! that there is a single audit point for early-boot console writes.
//!
//! # Emission atomicity (ADR-0023)
//!
//! Three writer classes share COM1: kernel boot logging, Ring 3
//! `WriteConsole` (syscall 60), and the panic/fatal-exception path.
//! Coherent serial lines are the prerequisite for every hardware
//! verification on the test VM, so emission follows a locking discipline:
//!
//! - [`lock`] returns a [`ConsoleGuard`] that masks interrupts (IF)
//!   **first** and then acquires the global `CONSOLE_LOCK` spin
//!   mutex. The IF-before-mutex order is load-bearing: a same-CPU
//!   holder can never be preempted while holding the lock, so no
//!   same-CPU waiter can spin on a parked holder (the cooperative
//!   scheduler has no priority inheritance). Cross-CPU waiters spin
//!   bounded by the holder's UART drain time.
//! - [`emit`] takes the guard for exactly one slice — every slice is
//!   atomic against both preemption and other CPUs.
//! - Multi-slice writers (the `WriteConsole` handler's 256-byte chunk
//!   loop) hold one guard across all their slices via
//!   [`ConsoleGuard::emit`], making the whole logical write atomic.
//! - The panic and fatal-exception paths NEVER take the lock: they use
//!   [`emit_raw`] (lock-free) after [`begin_fatal_dump`] force-unlocks
//!   a possibly-held mutex. A `#PF`/`#GP` can fire *inside* a holder's
//!   IF-off window (exceptions are not maskable by IF); spinning on the
//!   dead holder's mutex would deadlock the machine right when
//!   forensics matter most. The cost is that a fatal dump may splice
//!   into a partially-emitted line — forensics beat formatting.
//!
//! # Host testability (ADR-0023 § 5)
//!
//! The byte sink and the IF control are cfg-split: the real UART and
//! the real `cli`/`sti` exist only on `x86_64` + `target_os = "none"`.
//! Host test builds route bytes into an in-memory sink so the
//! interleaving guarantee is assertable in `cargo test`; non-test host
//! builds get inert no-ops (unchanged behaviour for non-x86 hosts).
//! Before this split the module was host-*compilable* but never
//! host-*callable* on `x86_64` (ring-3 `cli` faults — the P10.3
//! SIGSEGV class).

#[cfg(all(target_arch = "x86_64", target_os = "none"))]
use super::arch;

/// COM1 base I/O port.
///
/// The 16550 UART register block is COM1 base + offset; this module
/// hardcodes COM1 since it is universally available under QEMU's
/// default `q35` machine model and on every UEFI-capable physical
/// platform that surfaces a legacy serial port.
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
const COM1: u16 = 0x3f8;

/// Line-status register offset: bit 5 set ⇔ THR (transmit-holding
/// register) is empty and accepts a new byte.
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
const LSR_OFFSET: u16 = 5;

/// LSR bit indicating the THR is empty.
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
const LSR_THR_EMPTY: u8 = 1 << 5;

/// Global console emission lock (ADR-0023).
///
/// Serialises whole emission units (single slices via [`emit`], whole
/// user buffers via [`ConsoleGuard::emit`]) against each other. On
/// today's single-emitting-CPU configuration the mutex is uncontended
/// (the IF mask already excludes same-CPU interleaving); it exists so
/// the discipline survives the moment APs start emitting (MB14 SMP).
static CONSOLE_LOCK: spin::Mutex<()> = spin::Mutex::new(());

/// Initialise the 16550 UART on COM1 to a known-good state.
///
/// Must be called once, before the first [`write_str`] or [`emit`],
/// from `kernel_entry` (after `interrupts::disable`). The sequence
/// follows the `OSDev` 16550 canonical init:
///
/// 1. Disable UART interrupts — IRQ4 must not fire before the IDT is
///    installed (and we already ran `interrupts::disable`, but the UART
///    interrupt enable register is separate from RFLAGS.IF).
/// 2. Set baud-rate divisor = 1 (→ 115 200 baud).
/// 3. Set 8N1 line format, clearing DLAB so subsequent writes go to THR.
/// 4. Enable and flush the 14-byte FIFOs.
/// 5. Assert DTR + RTS + OUT2 (required by some multiplexers; no-op on QEMU).
///
/// On non-bare-metal builds this function is an inert no-op so host
/// builds and tests never execute privileged port I/O.
pub fn init() {
    #[cfg(all(target_arch = "x86_64", target_os = "none"))]
    unsafe {
        arch::outb(COM1 + 1, 0x00); // IER: disable all UART interrupts
        arch::outb(COM1 + 3, 0x80); // LCR: set DLAB to access divisor latch
        arch::outb(COM1, 0x01); // DLL: divisor low byte  (1 → 115200 baud)
        arch::outb(COM1 + 1, 0x00); // DLM: divisor high byte
        arch::outb(COM1 + 3, 0x03); // LCR: 8-bit, no parity, 1 stop; clears DLAB
        arch::outb(COM1 + 2, 0xC7); // FCR: enable FIFO, clear TX+RX, 14-byte trigger
        arch::outb(COM1 + 4, 0x0B); // MCR: DTR + RTS + OUT2
    }
}

// ---------------------------------------------------------------------------
// IF control — real only on the bare-metal target (ADR-0023 § 5)
// ---------------------------------------------------------------------------

/// Snapshot the IF state and disable maskable interrupts.
///
/// Returns the prior "interrupts enabled" state so the caller can
/// restore it exactly. Real `pushfq`/`cli` only on the bare-metal
/// target; host builds (tests included) have no interrupt state to
/// protect and get a constant `false`.
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
fn irq_save_disable() -> bool {
    let was_enabled = arch::interrupts::are_enabled();
    arch::interrupts::disable();
    was_enabled
}

/// Host stub — see the bare-metal twin above.
#[cfg(not(all(target_arch = "x86_64", target_os = "none")))]
fn irq_save_disable() -> bool {
    false
}

/// Restore the IF state captured by [`irq_save_disable`].
///
/// IF is only re-enabled when it was set on entry, so the panic path —
/// which runs with interrupts already disabled — is never handed an
/// enabled-interrupt state it did not have.
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
fn irq_restore(was_enabled: bool) {
    if was_enabled {
        // SAFETY: we only re-enable IF when it was set on entry; this
        // restores the caller's interrupt state and never enables
        // interrupts in a context (e.g. the panic path) that entered
        // with IF=0.
        unsafe { arch::interrupts::enable() }
    }
}

/// Host stub — see the bare-metal twin above.
#[cfg(not(all(target_arch = "x86_64", target_os = "none")))]
fn irq_restore(_was_enabled: bool) {}

// ---------------------------------------------------------------------------
// Console guard (ADR-0023)
// ---------------------------------------------------------------------------

/// RAII guard for multi-slice atomic console emission.
///
/// Holds the global `CONSOLE_LOCK` with interrupts masked for its
/// whole lifetime. Obtain via [`lock`]; emit any number of slices via
/// [`ConsoleGuard::emit`]; the drop releases the mutex **before**
/// restoring IF (the inverse of the acquisition order — re-enabling IF
/// while still holding the mutex would re-open the same-CPU
/// preempt-while-held window the ordering exists to close).
pub struct ConsoleGuard {
    /// `Some` until dropped. An `Option` so [`Drop::drop`] can release
    /// the mutex explicitly before restoring the IF state (struct
    /// fields would otherwise drop only after the `drop` body ran).
    lock: Option<spin::MutexGuard<'static, ()>>,
    /// IF state captured on acquisition, restored on drop.
    irq_was_enabled: bool,
}

impl ConsoleGuard {
    /// Emit one slice under the held guard.
    ///
    /// All slices emitted through the same guard are contiguous on the
    /// wire: no other [`emit`]/[`lock`] user can interleave until the
    /// guard drops. The call blocks until the UART drains the slice
    /// (≈ 90 ms/KiB at 115 200 baud) — callers bound their total
    /// payload accordingly (see `ATOMIC_CONSOLE_WRITE_MAX` in the
    /// `WriteConsole` handler).
    #[allow(
        clippy::unused_self,
        reason = "&self is the proof-of-held-lock token: emission through \
                  the guard is only legal while the lock is held"
    )]
    pub fn emit(&self, bytes: &[u8]) {
        for &b in bytes {
            emit_byte(b);
        }
    }
}

impl Drop for ConsoleGuard {
    fn drop(&mut self) {
        // Release the mutex FIRST, then restore IF — see the type docs.
        self.lock.take();
        irq_restore(self.irq_was_enabled);
    }
}

/// Acquire the console for a multi-slice atomic emission.
///
/// Order is IF-off → mutex (see [`ConsoleGuard`] and the module docs
/// for why this order is load-bearing). Never call from the panic or
/// fatal-exception path — those must use [`emit_raw`] after
/// [`begin_fatal_dump`].
pub fn lock() -> ConsoleGuard {
    let irq_was_enabled = irq_save_disable();
    let lock = CONSOLE_LOCK.lock();
    ConsoleGuard {
        lock: Some(lock),
        irq_was_enabled,
    }
}

/// Emit a byte slice to COM1 in polled mode, atomically.
///
/// This function blocks until every byte is delivered to the UART
/// data register. At `115_200` baud a 1 KiB record drains in ≈ 90 ms;
/// the K3 `PANIC_RECORD_MAX_BYTES` cap of 1024 sizes the worst case
/// against this constraint.
///
/// The slice is emitted under a [`ConsoleGuard`], so it can never
/// interleave with another `emit`/guard user — neither by same-CPU
/// timer preemption (the fused-line artifact observed on the test VM as
/// `[driver-loader]   bus[nexacore-net] service starting`) nor by another
/// CPU (SMP-future).
///
/// # Behaviour on non-bare-metal builds
///
/// Host test builds append to an in-memory sink (so interleaving is
/// assertable in `cargo test`); non-test host builds are inert no-ops.
/// Host-mode integration tests on the UART path therefore MUST NOT
/// assert console side-effects; they only exercise the pre-encoding
/// pipeline.
pub fn emit(bytes: &[u8]) {
    let guard = lock();
    guard.emit(bytes);
}

/// Emit a byte slice WITHOUT taking the console lock.
///
/// Reserved for the panic and fatal-exception paths, which may run
/// while the lock is held by the very context they interrupted
/// (exceptions are not maskable by IF). Pair with
/// [`begin_fatal_dump`]. Output may splice into a partially-emitted
/// line — forensics beat formatting (ADR-0023 § 4).
pub fn emit_raw(bytes: &[u8]) {
    for &b in bytes {
        emit_byte(b);
    }
}

/// Force-release the console lock on entry to a NON-RETURNING fatal
/// path (exception handlers that end in `halt_forever`, the panic
/// handler).
///
/// A fatal exception can fire inside a [`ConsoleGuard`] holder's
/// IF-off window; the holder will never resume, so its mutex must be
/// broken for the dump's `write_str`/`write_usize` calls (which take
/// the lock) to make progress.
///
/// Sound only because the caller never returns to the interrupted
/// context: on a single emitting CPU the holder is provably dead. On
/// SMP a live holder on another CPU would have its bytes spliced by
/// the dump — an accepted forensics trade-off (ADR-0023 § 4).
pub fn begin_fatal_dump() {
    // SAFETY: per the function contract the caller is a non-returning
    // fatal path; the (possibly) interrupted lock holder never resumes,
    // so breaking the lock cannot corrupt a live critical section on
    // this CPU. `()` data means there is no protected state to tear.
    unsafe { CONSOLE_LOCK.force_unlock() };
}

/// Emit a single byte to the active sink.
///
/// Bare-metal: wait for THR-empty, then `outb` to the data register at
/// COM1 base. Host test builds: append to the in-memory test sink.
/// Other host builds: no-op.
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
fn emit_byte(b: u8) {
    // Spin until LSR bit 5 (THR empty) is set.
    //
    // SAFETY: COM1 LSR (`0x3fd`) is a well-defined, read-only-side-
    // effect-free register on the 16550 UART. The kernel runs in
    // ring 0 with full port-I/O permission.
    while unsafe { arch::inb(COM1 + LSR_OFFSET) } & LSR_THR_EMPTY == 0 {
        core::hint::spin_loop();
    }
    // SAFETY: writing to COM1's data register (`0x3f8`) once the THR
    // is empty is the documented protocol for the 16550 UART. The
    // value `b` is an arbitrary 8-bit payload and is always valid.
    unsafe { arch::outb(COM1, b) };
}

/// Host-test twin of [`emit_byte`] — appends to the in-memory sink.
#[cfg(all(test, not(target_os = "none")))]
fn emit_byte(b: u8) {
    test_sink::push(b);
}

/// Inert host twin of [`emit_byte`] (non-test builds off the
/// bare-metal target).
#[cfg(all(not(test), not(all(target_arch = "x86_64", target_os = "none"))))]
fn emit_byte(_b: u8) {}

/// Convenience for code paths that want to push a `&str` rather than
/// raw bytes (e.g., the K4 `kmain` banner — `NCIP-Kernel-005` § S3).
pub fn write_str(s: &str) {
    emit(s.as_bytes());
}

/// Decimal printer for `usize`.
///
/// Used by the K4 `kmain` banner to report
/// `boot_info.memory_regions.len()` without pulling in any
/// `core::fmt` machinery (a writer trait + buffer that would not fit
/// the bump heap's worst-case path). Buffer is 20 bytes — enough for
/// `u64::MAX` (20 decimal digits). Writes left-to-right. The whole
/// rendered number is one atomic [`emit`] slice.
pub fn write_usize(mut n: usize) {
    if n == 0 {
        emit(b"0");
        return;
    }
    let mut buf = [0u8; 20];
    let mut i = buf.len();
    while n > 0 {
        i -= 1;
        // `n % 10` is in 0..=9, so the truncating cast to `u8` is
        // exact. We index into `buf` via `i`, which we just
        // decremented within the bounds of `buf.len()`.
        #[allow(
            clippy::cast_possible_truncation,
            clippy::indexing_slicing,
            reason = "n % 10 is 0..=9 (fits u8); i is bounded by buf.len()"
        )]
        {
            buf[i] = b'0' + (n % 10) as u8;
        }
        n /= 10;
    }
    #[allow(clippy::indexing_slicing, reason = "i is bounded by buf.len() above")]
    emit(&buf[i..]);
}

// ---------------------------------------------------------------------------
// Host test sink (ADR-0023 § 5)
// ---------------------------------------------------------------------------

/// In-memory byte sink used by host test builds so the emission
/// discipline (atomic slices, multi-slice guards, raw bypass) is
/// directly assertable in `cargo test`.
#[cfg(all(test, not(target_os = "none")))]
mod test_sink {
    use std::vec::Vec;

    use spin::Mutex;

    /// The shared sink. Tests that read it serialise on
    /// [`super::tests::SINK_TEST_GUARD`] so parallel test execution
    /// cannot pollute each other's captures. `spin::Mutex` (not
    /// `std::sync::Mutex`) per the workspace `disallowed_methods`
    /// policy — and the kernel already depends on it.
    static SINK: Mutex<Vec<u8>> = Mutex::new(Vec::new());

    /// Append one byte (called by the host-test `emit_byte`).
    pub(super) fn push(b: u8) {
        SINK.lock().push(b);
    }

    /// Drain and return everything captured so far.
    pub(super) fn take() -> Vec<u8> {
        core::mem::take(&mut *SINK.lock())
    }
}

#[cfg(all(test, not(target_os = "none")))]
mod tests {
    use std::{sync::Barrier, vec::Vec};

    use super::{ConsoleGuard, emit, emit_raw, lock, test_sink, write_usize};

    /// Serialises the sink-reading tests against each other (the sink
    /// is process-global; the default test harness runs in parallel).
    /// `spin::Mutex` per the workspace `disallowed_methods` policy; no
    /// poisoning to handle.
    static SINK_TEST_GUARD: spin::Mutex<()> = spin::Mutex::new(());

    /// Acquire the test serialisation guard.
    fn sink_test_guard() -> spin::MutexGuard<'static, ()> {
        SINK_TEST_GUARD.lock()
    }

    /// TASK-03 acceptance: concurrent `emit` calls never interleave
    /// the bytes of a single slice. 8 threads × 50 slices × 300 bytes
    /// of a thread-unique value; afterwards the sink must be a
    /// concatenation of intact 300-byte single-value runs.
    #[test]
    fn concurrent_emits_do_not_interleave() {
        const THREADS: usize = 8;
        const SLICES_PER_THREAD: usize = 50;
        const SLICE_LEN: usize = 300;

        let _serial = sink_test_guard();
        let _ = test_sink::take();

        let barrier = Barrier::new(THREADS);
        std::thread::scope(|scope| {
            for t in 0..THREADS {
                let barrier = &barrier;
                scope.spawn(move || {
                    #[allow(clippy::cast_possible_truncation, reason = "t < 8 fits u8 trivially")]
                    let payload = [b'A' + t as u8; SLICE_LEN];
                    barrier.wait();
                    for _ in 0..SLICES_PER_THREAD {
                        emit(&payload);
                    }
                });
            }
        });

        let captured = test_sink::take();
        assert_eq!(captured.len(), THREADS * SLICES_PER_THREAD * SLICE_LEN);
        for run in captured.chunks(SLICE_LEN) {
            let first = run.first().copied().expect("chunks() yields non-empty");
            assert!(
                run.iter().all(|&b| b == first),
                "interleaved slice detected: run starts with {first:#04x} \
                 but contains a foreign byte"
            );
        }
    }

    /// Multi-slice writes under ONE guard are contiguous even while
    /// other threads emit concurrently — the `WriteConsole`
    /// whole-buffer guarantee. The guard is taken before the
    /// competitor threads start, so the competitor output can only
    /// land after the guarded bytes.
    #[test]
    fn guard_spans_multiple_slices_atomically() {
        const COMPETITORS: usize = 4;
        const GUARDED_SLICES: usize = 3;
        const SLICE_LEN: usize = 100;

        let _serial = sink_test_guard();
        let _ = test_sink::take();

        let guard: ConsoleGuard = lock();
        std::thread::scope(|scope| {
            for _ in 0..COMPETITORS {
                scope.spawn(|| emit(&[b'x'; SLICE_LEN]));
            }
            // Emit the guarded multi-slice write while competitors are
            // (potentially) spinning on the console lock.
            for _ in 0..GUARDED_SLICES {
                guard.emit(&[b'G'; SLICE_LEN]);
            }
            drop(guard);
        });

        let captured = test_sink::take();
        assert_eq!(captured.len(), (COMPETITORS + GUARDED_SLICES) * SLICE_LEN);
        // The guarded bytes form one contiguous prefix run.
        let (guarded, competitors) = captured.split_at(GUARDED_SLICES * SLICE_LEN);
        assert!(
            guarded.iter().all(|&b| b == b'G'),
            "guarded multi-slice write was interleaved"
        );
        assert!(competitors.iter().all(|&b| b == b'x'));
    }

    /// The panic-path bypass must make progress while the console lock
    /// is held (a fatal exception can fire inside a holder's critical
    /// section). A deadlock here would hang the test suite — the test
    /// passing IS the liveness assertion.
    #[test]
    fn emit_raw_bypasses_the_lock() {
        let _serial = sink_test_guard();
        let _ = test_sink::take();

        let guard = lock();
        emit_raw(b"panic-forensics");
        drop(guard);

        assert_eq!(test_sink::take(), b"panic-forensics");
    }

    /// `write_usize` renders decimal correctly and as a single slice.
    #[test]
    fn write_usize_renders_decimal() {
        let _serial = sink_test_guard();
        let _ = test_sink::take();

        write_usize(0);
        write_usize(42);
        write_usize(18_446_744_073_709_551_615);

        let captured = test_sink::take();
        assert_eq!(
            core::str::from_utf8(&captured).expect("ASCII digits"),
            "04218446744073709551615"
        );
    }

    /// `begin_fatal_dump` breaks a held lock so the fatal dump's
    /// ordinary `write_str` calls (which lock) can proceed.
    #[test]
    fn begin_fatal_dump_breaks_a_held_lock() {
        let _serial = sink_test_guard();
        let _ = test_sink::take();

        // Simulate the interrupted holder: leak a guard (the fatal
        // handler never returns to it, so it is never dropped).
        let dead_holder = lock();
        core::mem::forget(dead_holder);

        super::begin_fatal_dump();

        // The dump path locks again — must not deadlock.
        emit(b"#PF dump");
        assert_eq!(test_sink::take(), b"#PF dump");
    }

    /// Sanity: the sink helper drains (regression guard for the other
    /// tests' `take()`-based isolation).
    #[test]
    fn sink_take_drains() {
        let _serial = sink_test_guard();
        let _ = test_sink::take();
        emit(b"a");
        assert_eq!(test_sink::take(), b"a");
        assert_eq!(test_sink::take(), Vec::<u8>::new());
    }
}
