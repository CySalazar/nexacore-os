//! Kernel panic handler and `PanicRecord` payload.
//!
//! Specified by [`NCIP-Kernel-012`] § S1. The `#[panic_handler]`
//! attribute-bearing function is the **only** symbol with that
//! attribute in the workspace; it is gated `#[cfg(not(test))]` so the
//! host test harness's panic handler retains its slot.
//!
//! ## Contract (binding by § S1)
//!
//! 1. **No allocation on the panic path.** Every buffer is a stack-
//!    allocated `[u8; PANIC_RECORD_MAX_BYTES]` or a `static`. The
//!    serializer is [`nexacore_types::wire::encode_into_slice`] which is
//!    itself non-allocating.
//! 2. **Disable interrupts first.** A nested interrupt during panic
//!    encoding would corrupt the static state.
//! 3. **No sensitive bytes in the record.** Kernel version, source
//!    location, and the panic message string only — never user
//!    register state, syscall arguments, capability tokens, or sealed
//!    plaintext. Enforced by code review of [`PanicRecord`]'s
//!    `Serialize` impl (a future cargo-clippy lint will enforce it
//!    structurally).
//! 4. **Halt on completion.** The function is `-> !`; control never
//!    returns.

use serde::Serialize;

// The `arch` and `early_console` modules are only invoked from the
// `#[panic_handler]` function, which is itself gated `target_os =
// "none"`. On host builds the imports would be unused — gate them on
// the same cfg as the consumer.
#[cfg(all(target_os = "none", not(test)))]
use super::{arch, early_console};

/// Static buffer cap for the encoded panic record.
///
/// Sized for the 16550 UART at `115_200` baud (≈ 11 KiB/s); a 1 KiB
/// record drains in ≈ 90 ms, which bounds the post-panic blackout
/// window for forensics tooling.
pub const PANIC_RECORD_MAX_BYTES: usize = 1024;

/// Structured payload for the panic console — kernel-internal
/// infrastructural state only.
///
/// Field selection is deliberate: every field carries enough context
/// for post-mortem reconstruction (`kernel_version` for the symbol
/// table, `panic_at` for the source line, `message` for the failed
/// invariant) and **nothing else**. Adding fields requires an NCIP
/// per the K3 specification.
#[derive(Serialize)]
pub struct PanicRecord<'a> {
    /// Kernel build version (`CARGO_PKG_VERSION` at compile time).
    pub kernel_version: &'static str,
    /// Source location of the panic call.
    pub panic_at: PanicLocation<'a>,
    /// The panic message string. Bounded by the Rust runtime's
    /// formatting buffer (typically ≤ 256 bytes for non-allocating
    /// panic messages).
    pub message: &'a str,
    /// Reserved for the stack pointer captured at panic time.
    ///
    /// Always `None` at K3 (stack unwinding is out of scope until K4
    /// formalises the boot frame). The field exists so that adding
    /// it later is a non-breaking change at the wire-format level.
    pub stack_pointer: Option<u64>,
}

/// Source location of the panic call site.
///
/// Mirrors `core::panic::Location` without the `'static` constraints
/// so the `Serialize` impl can borrow from the live `PanicInfo`.
#[derive(Serialize)]
pub struct PanicLocation<'a> {
    /// Source filename (relative to the crate root).
    pub file: &'a str,
    /// Source line number (1-indexed).
    pub line: u32,
    /// Source column number (1-indexed).
    pub column: u32,
}

impl<'a> PanicRecord<'a> {
    /// Build a `PanicRecord` from a live `PanicInfo`.
    ///
    /// All references borrow from the `PanicInfo`; the resulting
    /// `PanicRecord` is therefore tied to the lifetime of the live
    /// info struct, which is exactly the scope of the
    /// `#[panic_handler]` function.
    #[must_use]
    pub fn from_info(info: &'a core::panic::PanicInfo<'a>) -> Self {
        let (file, line, column) = info.location().map_or(("<unknown>", 0, 0), |loc| {
            (loc.file(), loc.line(), loc.column())
        });
        // `PanicInfo::message()` returns a `&PanicMessage` whose
        // `Display` impl produces the formatted text. We cannot
        // allocate, so we forward the message via the raw underlying
        // `&str` if present (literal panic args) and fall back to a
        // stable placeholder otherwise. Allocating a formatted
        // representation would violate § S1 constraint 1.
        let message = info
            .message()
            .as_str()
            .unwrap_or("<formatted; not captured>");
        PanicRecord {
            kernel_version: env!("CARGO_PKG_VERSION"),
            panic_at: PanicLocation { file, line, column },
            message,
            stack_pointer: None,
        }
    }
}

/// Overflow-marker emitted to the console when [`PanicRecord`]
/// encoding does not fit in [`PANIC_RECORD_MAX_BYTES`].
///
/// Forensics tooling looks for this exact 22-byte prefix to know that
/// the next post-panic line is *not* a postcard-encoded record.
pub const OVERFLOW_MARKER: &[u8] = b"NexaCore-KPANIC-OVERFLOW\n";

/// The actual `#[panic_handler]` entry point.
///
/// Gated `target_os = "none"` (rather than the looser `not(test)`)
/// because the panic-impl lang item is also supplied by `std`. A host
/// build of this crate with `--features bare-metal` enabled (e.g.,
/// `cargo build --workspace --all-features` on a developer laptop)
/// links against `std` transitively via `serde_derive`/`thiserror`
/// build-deps, which would cause a duplicate-lang-item error at link
/// time. `target_os = "none"` is exactly the cross-target where no
/// `std` is present, which is what the kernel binary actually
/// requires.
#[cfg(all(target_os = "none", not(test)))]
#[panic_handler]
fn panic(info: &core::panic::PanicInfo) -> ! {
    // Step 1: disable interrupts. A nested interrupt that triggered
    // its own panic would corrupt the static encode buffer.
    arch::interrupts::disable();

    // Step 1b: break a possibly-held console lock (ADR-0023 § 4). The
    // panic may have fired inside a `ConsoleGuard` holder's critical
    // section; that holder never resumes, and spinning on its mutex
    // would deadlock the machine instead of emitting forensics. All
    // emission below uses the lock-free `emit_raw` path.
    early_console::begin_fatal_dump();

    // Step 2: encode the record into a stack-local static-sized
    // buffer. No allocation. On overflow, fall back to a fixed
    // ASCII marker so post-mortem tooling can detect the case.
    let record = PanicRecord::from_info(info);
    let mut buf = [0u8; PANIC_RECORD_MAX_BYTES];
    match nexacore_types::wire::encode_into_slice(&record, &mut buf) {
        Ok(written) => {
            // `encode_into_slice` returns `written ≤ buf.len()` by
            // contract: the encoder either fills a prefix of `buf` or
            // returns `EncodeFailed` (the `Err` arm below). The
            // `get(..written)` form keeps clippy::indexing_slicing
            // satisfied without a runtime panic path.
            if let Some(slice) = buf.get(..written) {
                // Lock-free: the panic path never takes the console
                // lock (see Step 1b above and ADR-0023 § 4).
                early_console::emit_raw(slice);
            } else {
                early_console::emit_raw(OVERFLOW_MARKER);
            }
        }
        Err(_) => early_console::emit_raw(OVERFLOW_MARKER),
    }
    // Append a newline so a downstream line-oriented log parser
    // sees a clean record terminator regardless of the postcard
    // self-delimiting framing.
    early_console::emit_raw(b"\n");

    // Step 3: halt forever. Never returns.
    arch::halt_forever()
}
