//! Bare-metal shell binary for NexaCore OS.
//!
//! This binary is the PID 1 shell image that the NexaCore OS kernel spawns after
//! boot. It runs as a `no_std + no_main` ELF on `x86_64-unknown-none`,
//! compiled with the `nexacore-shell` library in its `no_std` mode.
//!
//! ## Architecture
//!
//! ```text
//! _start()
//!   │  initialise ShellEnv + cwd
//!   │  print welcome banner  (sys_write)
//!   └─► REPL loop
//!         ├─ format_prompt → sys_write(fd 1)
//!         ├─ sys_read(fd 0) → line bytes
//!         └─ process_line → (exit_code, output_bytes)
//!               └─ sys_write(output_bytes, fd 1)
//! ```
//!
//! ## Global allocator
//!
//! A bump allocator backed by a 256 KiB static buffer provides heap support
//! for [`alloc::string::String`], [`alloc::vec::Vec`], and
//! [`alloc::collections::BTreeMap`]. The allocator never frees individual
//! blocks; this is acceptable for Phase 1 because the process lifetime equals
//! the session lifetime.
//!
//! ## Syscall layer
//!
//! Minimal inline asm wrappers for the four syscalls this binary actually
//! needs: `FdWrite (64)`, `FdRead (63)`, `FsListDir (92)`, `TaskExit (11)`.
//! `nexacore-usys` is deliberately NOT linked because it transitively depends on
//! `nexacore-types` with default features, which pulls in `getrandom` — a crate
//! with no implementation for `x86_64-unknown-none`. The inline stubs follow
//! the System V AMD64 ABI used by all other image crates in this workspace.
//!
//! ## Build
//!
//! ```sh
//! cargo build --manifest-path crates/nexacore-shell-image/Cargo.toml \
//!             --target x86_64-unknown-none --release
//! ```

#![no_std]
#![no_main]
#![allow(unsafe_code)]
#![warn(missing_docs)]

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;
use core::panic::PanicInfo;

use nexacore_shell::env::ShellEnv;
use nexacore_shell::glob::FsQuery;
use nexacore_shell::netquery::NoNet;
use nexacore_shell::repl::process_line;
#[allow(unused_imports)]
use nexacore_shell::repl::format_prompt;

// =============================================================================
// Global allocator — bump allocator backed by a static buffer
// =============================================================================
//
// The shell pipeline allocates `String`, `Vec`, and `BTreeMap` on the heap.
// A bump allocator satisfies `GlobalAlloc` with zero external dependencies.
// It never frees: blocks are released only when the process exits. The 256 KiB
// budget covers typical interactive sessions; raise `HEAP_SIZE` for deeper
// pipelines or wider glob expansions.

/// Size of the static heap backing the bump allocator (256 KiB).
const HEAP_SIZE: usize = 256 * 1024;

// SAFETY: HEAP is only mutated through the bump allocator below, which runs
// on the single-threaded bare-metal execution model. There is no concurrent
// mutator in Phase 1.
static mut HEAP: [u8; HEAP_SIZE] = [0u8; HEAP_SIZE];

// SAFETY: Same single-threaded guarantee as HEAP; HEAP_POS is only read and
// written inside `BumpAllocator::alloc`.
static mut HEAP_POS: usize = 0;

/// Bump allocator: allocate-only, no per-block deallocation.
struct BumpAllocator;

// SAFETY: BumpAllocator is a ZST with no interior state; all mutable state
// lives in the `static mut` globals above. Single-threaded bare-metal target
// means no data races.
unsafe impl core::alloc::GlobalAlloc for BumpAllocator {
    /// Allocate a block satisfying `layout`.
    ///
    /// Aligns the current heap cursor to `layout.align()`, advances it by
    /// `layout.size()`, and returns a pointer to the newly reserved range.
    /// Returns null if the heap is exhausted; the `alloc` runtime will then
    /// invoke the OOM handler which triggers the panic handler.
    ///
    /// # Safety
    ///
    /// Per `GlobalAlloc` contract: `layout.size() > 0` and `layout.align()`
    /// is a power of two. Caller (the `alloc` crate) guarantees these.
    unsafe fn alloc(&self, layout: core::alloc::Layout) -> *mut u8 {
        // SAFETY: raw pointer read of HEAP_POS — safe in single-threaded
        // bare-metal context; no concurrent writer exists.
        let pos = unsafe { core::ptr::addr_of!(HEAP_POS).read() };
        let align = layout.align();
        let size = layout.size();

        // Align the cursor upwards.
        let aligned = pos.wrapping_add(align - 1) & !(align - 1);
        let new_pos = aligned.wrapping_add(size);

        if new_pos > HEAP_SIZE {
            return core::ptr::null_mut();
        }

        // SAFETY: new_pos <= HEAP_SIZE, so aligned < HEAP_SIZE, so the add
        // is in-bounds. Writing new_pos is safe for the same single-threaded
        // reason as the read above.
        unsafe {
            core::ptr::addr_of_mut!(HEAP_POS).write(new_pos);
            core::ptr::addr_of_mut!(HEAP).cast::<u8>().add(aligned)
        }
    }

    /// No-op deallocation.
    ///
    /// The bump allocator does not reclaim individual blocks. Memory is
    /// effectively freed when the process exits.
    ///
    /// # Safety
    ///
    /// Per `GlobalAlloc` contract: `ptr` was returned by a prior call to
    /// `alloc` with a compatible `layout`. We do nothing, so no invariant
    /// is violated.
    unsafe fn dealloc(&self, _ptr: *mut u8, _layout: core::alloc::Layout) {
        // Intentionally empty: bump allocators do not support individual frees.
    }
}

/// Global allocator instance.
#[global_allocator]
static ALLOCATOR: BumpAllocator = BumpAllocator;

// =============================================================================
// Minimal syscall wrappers (System V AMD64 ABI)
// =============================================================================
//
// We inline only the four syscalls the shell image actually uses. This avoids
// a dependency on `nexacore-usys`, which transitively pulls in `getrandom` (via
// `nexacore-types` default features), a crate that has no implementation for
// `x86_64-unknown-none`. The ABI is identical to what `KernelSyscall` in
// `nexacore-usys` implements; the constants mirror `nexacore_kernel::syscall::SyscallNumber`.

/// `FdWrite (64)` — kernel syscall number for writing bytes to a file descriptor.
const SYS_FD_WRITE: u64 = 64;

/// `FdRead (63)` — kernel syscall number for reading bytes from a file descriptor.
const SYS_FD_READ: u64 = 63;

/// `FsListDir (92)` — kernel syscall number for listing directory entries.
const SYS_FS_LIST_DIR: u64 = 92;

/// `TaskExit (11)` — kernel syscall number for terminating the calling task.
const SYS_TASK_EXIT: u64 = 11;

/// Issue a two-register-return syscall (`rax = value`, `rdx = errno`).
///
/// Follows the NexaCore OS kernel ABI defined in
/// `crates/nexacore-kernel/src/syscall.rs`: `rax` carries the syscall number on
/// entry and the return value on exit; `rdx` carries argument `a2` on entry
/// and the errno code on exit (0 = success); `rcx` and `r11` are clobbered by
/// the `syscall` instruction itself (per the Intel SDM / SysV AMD64 ABI).
///
/// # Safety
///
/// The caller must ensure:
/// 1. `number` is a valid NexaCore OS syscall number.
/// 2. Pointer arguments (`a0`..`a5` that represent pointers) are valid,
///    non-null, and the caller holds appropriate access for the duration of
///    the syscall.
/// 3. Scalar arguments satisfy the range constraints documented for each
///    syscall in `crates/nexacore-kernel/src/syscall.rs`.
#[inline(always)]
unsafe fn syscall2(
    number: u64,
    a0: u64,
    a1: u64,
    a2: u64,
    a3: u64,
    a4: u64,
    a5: u64,
) -> (u64, u64) {
    let rax: u64;
    let rdx: u64;
    // SAFETY: `syscall` is the canonical Ring 3 → Ring 0 transition on
    // x86_64; the kernel's `nexacore_syscall_entry` preserves all GPRs except
    // rax, rcx, r11 (clobbered by the instruction itself). Caller contract
    // documented on the function.
    unsafe {
        core::arch::asm!(
            "syscall",
            inlateout("rax") number => rax,
            in("rdi") a0,
            in("rsi") a1,
            inlateout("rdx") a2 => rdx,
            in("r10") a3,
            in("r8")  a4,
            in("r9")  a5,
            out("rcx") _,
            out("r11") _,
            options(nostack, preserves_flags),
        );
    }
    (rax, rdx)
}

/// Write `buf` to file descriptor `fd`.
///
/// Returns the number of bytes written (may be less than `buf.len()` on a
/// partial write). Returns 0 on any error (best-effort; the shell REPL
/// continues regardless of write failures to avoid recursive error spirals).
fn sys_write(fd: u32, buf: &[u8]) -> usize {
    if buf.is_empty() {
        return 0;
    }
    // SAFETY: buf is a valid Rust slice; ptr and len are correct by
    // construction. FdWrite (64) is a read-only operation on buf from the
    // kernel's perspective.
    let (rax, rdx) = unsafe {
        syscall2(
            SYS_FD_WRITE,
            u64::from(fd),
            buf.as_ptr() as u64,
            buf.len() as u64,
            0,
            0,
            0,
        )
    };
    if rdx != 0 { 0 } else { rax as usize }
}

/// Read up to `buf.len()` bytes from file descriptor `fd`.
///
/// Returns the byte count read (0 = EOF or error).
fn sys_read(fd: u32, buf: &mut [u8]) -> usize {
    if buf.is_empty() {
        return 0;
    }
    // SAFETY: buf is a valid mutable slice for the entire syscall duration;
    // the kernel writes at most buf.len() bytes.
    let (rax, rdx) = unsafe {
        syscall2(
            SYS_FD_READ,
            u64::from(fd),
            buf.as_mut_ptr() as u64,
            buf.len() as u64,
            0,
            0,
            0,
        )
    };
    if rdx != 0 { 0 } else { rax as usize }
}

/// List the entries of the directory at `path`.
///
/// The kernel fills `out_buf` with a newline-separated list of entry names
/// and returns the byte count written. Returns an empty `Vec` on any error.
fn sys_list_dir(path: &str, out_buf: &mut [u8]) -> usize {
    let path_bytes = path.as_bytes();
    // SAFETY: path bytes and out_buf are valid slices; the kernel writes at
    // most out_buf.len() bytes. FsListDir (92) interprets a0/a1 as the path
    // (ptr, len) and a2/a3 as the output buffer (ptr, len).
    let (rax, rdx) = unsafe {
        syscall2(
            SYS_FS_LIST_DIR,
            path_bytes.as_ptr() as u64,
            path_bytes.len() as u64,
            out_buf.as_mut_ptr() as u64,
            out_buf.len() as u64,
            0,
            0,
        )
    };
    if rdx != 0 { 0 } else { rax as usize }
}

/// Terminate the calling process with exit `code`.
///
/// Issues `TaskExit (11)`. Never returns; the trailing `loop {}` is a
/// defensive hint to the compiler that this path diverges.
fn sys_exit(code: u32) -> ! {
    // SAFETY: TaskExit (11) takes a single u32 exit code in rdi and never
    // returns to user space; the kernel dequeues the task immediately.
    // `options(noreturn)` informs the compiler that control flow ends here.
    unsafe {
        core::arch::asm!(
            "syscall",
            in("rax") SYS_TASK_EXIT,
            in("rdi") u64::from(code),
            options(noreturn),
        );
    }
}

// =============================================================================
// Panic handler
// =============================================================================

/// Panic handler — write a sentinel message to stdout then call `TaskExit(1)`.
///
/// Uses the inline `sys_write` / `sys_exit` stubs so it does not depend on
/// any global state that might itself be corrupt during a panic.
#[panic_handler]
fn panic(_info: &PanicInfo<'_>) -> ! {
    // Best-effort write; ignore return value (we are already in a panic).
    sys_write(1, b"[nexacore-shell] panic -- exiting\n");
    sys_exit(1)
}

// =============================================================================
// FsQuery implementation
// =============================================================================

/// [`FsQuery`] implementation backed by the `FsListDir (92)` syscall.
///
/// Used by the shell's glob expander to enumerate directory entries at runtime.
/// Errors from the kernel (non-zero errno) are surfaced as `Err(String)` so
/// the glob expander can fall back to returning the literal pattern unchanged.
struct SyscallFs;

impl FsQuery for SyscallFs {
    /// List the direct children of `path`.
    ///
    /// Issues `FsListDir (92)` into a 4 KiB stack buffer, then splits the
    /// newline-separated result into individual entry names.
    ///
    /// # Errors
    ///
    /// Returns `Err(String)` when the syscall returns a non-zero errno (e.g.
    /// the directory does not exist or the caller lacks read permission). The
    /// glob expander treats any error as an empty directory — no crash.
    fn list_dir(&self, path: &str) -> Result<Vec<String>, String> {
        // 4 KiB is sufficient for a Phase 1 directory listing. Directories
        // with more than ~200 entries will be silently truncated; a
        // cursor-based approach will be introduced in a later sprint.
        let mut buf = [0u8; 4096];
        let n = sys_list_dir(path, &mut buf);
        if n == 0 && !path.is_empty() {
            // n == 0 after a non-empty path usually means the syscall failed.
            // Return an empty list so the glob expander degrades gracefully.
            return Err(String::from("list_dir failed"));
        }
        // The kernel fills the buffer with newline-separated entry names.
        let text = core::str::from_utf8(&buf[..n]).unwrap_or("");
        Ok(text
            .split('\n')
            .filter(|s| !s.is_empty())
            .map(String::from)
            .collect())
    }
}

// =============================================================================
// ELF entry point
// =============================================================================

/// ELF entry point.
///
/// The kernel's `spawn_from_elf` jumps here with `rsp = user_stack_top`.
/// This function initialises the shell environment, prints the welcome banner,
/// and runs the interactive REPL loop until stdin reaches EOF.
///
/// `#[unsafe(no_mangle)]` ensures the linker places this symbol at the ELF
/// entry address. `extern "C"` selects the System V AMD64 calling convention,
/// which the kernel uses when jumping to user space after `spawn_from_elf`.
#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    // ── Initialise shell environment ─────────────────────────────────────────
    let mut env = ShellEnv::new();
    env.set("PATH", "/bin");
    env.set("HOME", "/");
    env.set("USER", "root");
    env.set("HOSTNAME", "nexacore");
    env.set("SHELL", "/bin/nexacore-shell");
    env.set("TERM", "vt100");
    // Enable agent intent labels by default. Users can `unset NEXACORE_AGENT` to
    // suppress the `[TASK]`/`[ADMIN]`/… prefixes on command output.
    env.set("NEXACORE_AGENT", "1");

    let mut cwd = String::from("/");
    let fs = SyscallFs;

    // ── Welcome banner ───────────────────────────────────────────────────────
    let banner = concat!(
        "\x1b[1;36m",
        "  ____  __  __ _   _ ___    ___  ____  \n",
        " / __ \\|  \\/  | \\ | |_ _|  / _ \\/ ___| \n",
        "| |  | | |\\/| |  \\| || |  | | | \\___ \\ \n",
        "| |__| | |  | | |\\  || |  | |_| |___) |\n",
        " \\____/|_|  |_|_| \\_|___|  \\___/|____/ \n",
        "\x1b[0m\n",
        "Welcome to NexaCore OS shell. Type 'help' for available commands.\n\n",
    );
    sys_write(1, banner.as_bytes());
    sys_write(1, b"[shell-dbg] entering REPL\n");

    let mut line_buf = [0u8; 1024];

    loop {
        // Build prompt manually without format! (PIE vtable issue).
        sys_write(1, b"\x1b[1;32mroot@nexacore\x1b[0m:\x1b[1;34m");
        sys_write(1, cwd.as_bytes());
        sys_write(1, b"\x1b[0m$ ");

        // Read one line (up to 1 KiB) from stdin.
        let n = sys_read(0, &mut line_buf);
        if n == 0 {
            // No data yet — yield CPU and retry. The kernel's ReadConsole/
            // FdRead returns 0 when the buffer is empty; we poll until
            // the user types something. A future sprint will add blocking
            // I/O so this busy-wait is replaced by a scheduler park.
            continue;
        }

        let input = match core::str::from_utf8(&line_buf[..n]) {
            Ok(s) => s.trim_end_matches('\n').trim_end_matches('\r'),
            Err(_) => continue,
        };

        if input.is_empty() {
            continue;
        }

        if input == "exit" {
            sys_write(1, b"exit\n");
            sys_exit(0);
        }

        // NoNet: this bare-metal shell image has no network syscalls wired in
        // yet (unlike `omni-apps-image`'s windowed Terminal) — `ifconfig`
        // here reports no interfaces rather than querying a real stack.
        let (_exit_code, output) = process_line(input, &mut env, &mut cwd, &fs, &NoNet);

        // Write all buffered output to stdout, handling partial writes.
        let mut written = 0usize;
        while written < output.len() {
            let chunk = sys_write(1, &output[written..]);
            if chunk == 0 {
                // Write returned 0 — console may be busy; stop to avoid
                // an infinite loop on a broken fd.
                break;
            }
            written = written.saturating_add(chunk);
        }
    }
}
