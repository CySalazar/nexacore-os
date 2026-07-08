//! Display syscall wrappers — `DisplayMap (79)` + input-event IPC receiver.
//!
//! Thin typed wrappers over the two display primitives exposed by the NexaCore OS
//! kernel for Ring-3 compositors and display probes (ADR-0040 D5, TASK-18
//! DE-C1):
//!
//! - `display_map` — maps the framebuffer into the caller's address space
//!   via `DisplayMap (79)`, gated by a `Display` capability token.
//! - `recv_input_event` — drains one message from the display-input IPC
//!   channel via `IpcTryReceive (24)` and decodes it as a
//!   `DisplayInputEvent`.
//!
//! Both functions are available only when the `bare-metal` feature is enabled
//! (i.e. when building for `x86_64-unknown-none`); the rest of the module
//! (constants) compiles unconditionally and is host-testable.
//!
//! ## ABI: `DisplayMap (79)`
//!
//! ```text
//! rdi = offset   (byte offset into the framebuffer, 4 KiB-aligned)
//! rsi = len      (byte count, 4 KiB-aligned, offset+len ≤ fb_len)
//! rdx = flags    (reserved; must be 0)
//! r10 = cap_ptr  (pointer to the Display capability token bytes)
//! r8  = cap_len  (length of the token byte slice)
//!
//! Returns: rax = user VA (on success), rdx = errno
//! ```
//!
//! `EACCES` is returned if no valid Display capability is presented.
//! `EINVAL` is returned for misaligned or out-of-range `offset`/`len`.
//!
//! ## ABI: `IpcTryReceive (24)` (input path)
//!
//! ```text
//! rdi = channel_id
//! rsi = buf_ptr
//! rdx = buf_len
//!
//! Returns: rax = bytes_written (or u64::MAX on error), rdx = errno
//! ```
//!
//! An empty channel returns `rax = u64::MAX`; the caller should yield and
//! retry.  Each payload is a postcard-encoded `DisplayInputEvent`.
//!
//! ## Device-info field mapping
//!
//! The kernel writes a `VirtioDeviceInfo` struct into the deposit window with
//! fields carrying display parameters (ADR-0040 D3 / TASK-18 shared contract):
//!
//! | `VirtioDeviceInfo` field | Display meaning       |
//! |--------------------------|-----------------------|
//! | `bar_phys`               | input channel id      |
//! | `common_offset`          | framebuffer width (px)|
//! | `notify_offset`          | framebuffer height(px)|
//! | `isr_offset`             | stride (px / row)     |
//! | `device_offset`          | bytes per pixel       |
//! | `mmio_len`               | total fb bytes        |
//!
//! ## Feature flags
//!
//! | Feature      | Effect |
//! |-------------|--------|
//! | `bare-metal` | Enables the `display_map` and `recv_input_event` functions
//! |               using inline `asm!`; without this feature the module only
//! |               exports the `syscall_nr` constants and `ACTION_TAG_DISPLAY_MAP`. |
//!
//! ## Examples
//!
//! Constant access (compiles on any host):
//!
//! ```rust
//! use nexacore_usys::display::syscall_nr;
//!
//! assert_eq!(syscall_nr::DISPLAY_MAP, 79);
//! assert_eq!(syscall_nr::IPC_TRY_RECEIVE, 24);
//! ```

#[cfg(feature = "bare-metal")]
use nexacore_types::display_channel::DisplayInputEvent;

#[cfg(feature = "bare-metal")]
use crate::{Errno, SysResult};

// =============================================================================
// Syscall number constants
// =============================================================================

/// Kernel syscall numbers for display operations.
///
/// These constants match the `SyscallNumber` enum in
/// `crates/nexacore-kernel/src/syscall.rs`.  Callers MUST use these constants —
/// never hard-code literal integers.
pub mod syscall_nr {
    /// `DisplayMap (79)` — map the framebuffer into the caller's address space.
    ///
    /// Capability-gated: the caller must present a valid `Display` capability
    /// token (see [`super::ACTION_TAG_DISPLAY_MAP`]).
    pub const DISPLAY_MAP: u64 = 79;
    /// `IpcTryReceive (24)` — non-blocking receive from an IPC channel.
    ///
    /// Re-exported here for the display-input drain path; this is the same
    /// syscall used by every other IPC consumer in the workspace.
    pub const IPC_TRY_RECEIVE: u64 = 24;
}

/// Deposit-window action tag for the `Display` capability (ADR-0040 D3).
///
/// Pass this as the `action_tag` argument to
/// `nexacore_driver_shared::caps::find_token` to locate the Display capability
/// token deposited by the kernel before spawning the compositor / probe.
///
/// # Example
///
/// ```rust
/// use nexacore_usys::display::ACTION_TAG_DISPLAY_MAP;
///
/// // The kernel uses action tag 7 when it deposits the Display cap.
/// assert_eq!(ACTION_TAG_DISPLAY_MAP, 7u32);
/// ```
pub const ACTION_TAG_DISPLAY_MAP: u32 = 7;

// =============================================================================
// Bare-metal-only functions
// =============================================================================

#[cfg(feature = "bare-metal")]
mod bare {
    use nexacore_types::wire::decode_canonical;

    use super::{DisplayInputEvent, Errno, SysResult, syscall_nr};

    /// Sentinel value returned in `rax` by `IpcTryReceive` when the channel
    /// queue is empty (no message available).
    const IPC_QUEUE_EMPTY: u64 = u64::MAX;

    /// Issue the `DisplayMap (79)` syscall.
    ///
    /// Maps `len` bytes of the framebuffer, starting at `offset` bytes from the
    /// beginning of the framebuffer, into the caller's address space.
    ///
    /// - `offset` must be 4 KiB-aligned and satisfy `offset + len ≤ fb_len`.
    /// - `len` must be 4 KiB-aligned.
    /// - `cap` must be the capability token bytes obtained from the kernel
    ///   deposit window via
    ///   `nexacore_driver_shared::caps::find_token(ACTION_TAG_DISPLAY_MAP, ...)`.
    ///
    /// On success returns a raw pointer to the base of the mapped framebuffer
    /// region.  The caller may write to `[ptr, ptr + len)` using
    /// `core::ptr::write_volatile` (required to prevent elision by the
    /// compiler).
    ///
    /// # Errors
    ///
    /// | Errno           | Meaning |
    /// |-----------------|---------|
    /// | [`Errno::Access`]  | No valid Display capability presented. |
    /// | [`Errno::Invalid`] | `offset` or `len` is misaligned or out of range. |
    ///
    /// # Safety note on the returned pointer
    ///
    /// The returned `*mut u8` is valid for `len` bytes and writable by the
    /// calling task.  All writes MUST use `core::ptr::write_volatile`; plain
    /// writes may be elided by the compiler because the memory is not otherwise
    /// accessed from Rust's perspective.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// # #[cfg(feature = "bare-metal")]
    /// # {
    /// use nexacore_usys::display::display_map;
    ///
    /// // In a real compositor: obtain cap from the deposit window first.
    /// let cap: &[u8] = &[];
    /// // display_map(0, 4096, cap) would issue the syscall.
    /// # }
    /// ```
    #[allow(unsafe_code, clippy::similar_names)]
    pub fn display_map(offset: u64, len: u64, cap: &[u8]) -> SysResult<*mut u8> {
        let rax: u64;
        let rdx: u64;
        // SAFETY: canonical Ring 3 → Ring 0 transition.  `cap` is a valid
        // slice for the duration of the syscall.  `offset`, `len`, and the
        // zero flags word are scalars.  ALL argument registers are declared
        // `inout => _` (full-clobber, ADR-0035 lesson) so the compiler cannot
        // reuse their values after the `syscall` instruction.  `rcx` and `r11`
        // are clobbered by the `SYSCALL` instruction per the AMD64 architecture
        // specification.
        unsafe {
            core::arch::asm!(
                "syscall",
                inlateout("rax") syscall_nr::DISPLAY_MAP => rax,
                inout("rdi") offset => _,
                inout("rsi") len => _,
                inlateout("rdx") 0u64 => rdx,  // flags = 0
                inout("r10") cap.as_ptr() as u64 => _,
                inout("r8")  cap.len() as u64 => _,
                inout("r9")  0u64 => _,
                out("rcx") _,
                out("r11") _,
                options(nostack, preserves_flags),
            );
        }
        if rdx == 0 {
            // Success: rax holds the user virtual address of the mapped region.
            Ok(rax as *mut u8)
        } else {
            Err(Errno::from_raw(rdx))
        }
    }

    /// Drain one message from the display-input IPC channel and decode it as a
    /// [`DisplayInputEvent`].
    ///
    /// This is a non-blocking call.  Returns:
    ///
    /// - `Ok(Some(event))` — a message was available and decoded successfully.
    /// - `Ok(None)` — the channel queue is empty; the caller should
    ///   `task_yield()` and retry.
    /// - `Err(e)` — the kernel signalled an error (e.g. invalid `channel_id`).
    ///
    /// `buf` must be at least
    /// [`nexacore_types::display_channel::MAX_EVENT_BYTES`] (= 32) bytes.
    ///
    /// # Errors
    ///
    /// | Errno           | Meaning |
    /// |-----------------|---------|
    /// | [`Errno::BadFd`]   | `channel_id` is not valid. |
    /// | [`Errno::Io`]      | Postcard decode of the payload failed. |
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// # #[cfg(feature = "bare-metal")]
    /// # {
    /// use nexacore_usys::display::recv_input_event;
    ///
    /// let mut buf = [0u8; 32];
    /// // In a real compositor loop:
    /// // while let Ok(Some(ev)) = recv_input_event(channel_id, &mut buf) { ... }
    /// # }
    /// ```
    #[allow(unsafe_code, clippy::similar_names)]
    pub fn recv_input_event(
        channel_id: u64,
        buf: &mut [u8],
    ) -> SysResult<Option<DisplayInputEvent>> {
        let rax: u64;
        // SAFETY: canonical Ring 3 → Ring 0 transition.  `buf` is a valid
        // writable slice for the duration of the syscall; the kernel writes at
        // most `buf.len()` bytes.  All argument registers are declared
        // `inout => _` (full-clobber, ADR-0035).
        unsafe {
            core::arch::asm!(
                "syscall",
                inlateout("rax") syscall_nr::IPC_TRY_RECEIVE => rax,
                inout("rdi") channel_id => _,
                inout("rsi") buf.as_mut_ptr() as u64 => _,
                inout("rdx") buf.len() as u64 => _,
                inout("r10") 0u64 => _,
                inout("r8")  0u64 => _,
                inout("r9")  0u64 => _,
                out("rcx") _,
                out("r11") _,
                options(nostack, preserves_flags),
            );
        }
        if rax == IPC_QUEUE_EMPTY {
            // Empty queue — not an error, just no data right now.
            return Ok(None);
        }
        // rax is the byte count written; bounded by buf.len() ≤ usize::MAX.
        #[allow(
            clippy::cast_possible_truncation,
            reason = "kernel writes at most buf.len() bytes which fits in usize on x86_64"
        )]
        let n = rax as usize;
        let payload = buf.get(..n).ok_or(Errno::Fault)?;
        decode_canonical::<DisplayInputEvent>(payload)
            .map(Some)
            .map_err(|_| Errno::Io)
    }
}

#[cfg(feature = "bare-metal")]
pub use bare::{display_map, recv_input_event};

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_map_syscall_number_is_79() {
        assert_eq!(syscall_nr::DISPLAY_MAP, 79);
    }

    #[test]
    fn ipc_try_receive_syscall_number_is_24() {
        assert_eq!(syscall_nr::IPC_TRY_RECEIVE, 24);
    }

    #[test]
    fn action_tag_display_map_is_7() {
        assert_eq!(ACTION_TAG_DISPLAY_MAP, 7u32);
    }
}
