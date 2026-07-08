//! AI syscall wrappers (numbers 80–84) — TASK-11 (DE-G6, ADR-0032).
//!
//! Thin userspace wrappers over the kernel's AI syscall relay
//! (`ai_handlers::ai_relay`): the kernel copies the arguments via the
//! `uaccess` layer, builds the postcard
//! [`nexacore_types::ai::AiSyscallRequest`], and carries it to the
//! nexacore-runtime service over the `"ai"`/`"ai_reply"` two-channel IPC
//! rendezvous. The caller never serialises anything — the ABI is raw
//! pointers + lengths, mirrored by [`crate::ai::AiInvokeArgs`].
//!
//! ## ABI (two-register return, `(rax = output_len, rdx = errno)`)
//!
//! `(model_id_ptr, model_id_len = 16, input_ptr, input_len, output_ptr,
//! output_cap)` for `AiInvoke` (80), `AiEmbed` (82), `AiClassify` (83),
//! `AiTranscribe` (84). `AiStream` (81) uses a channel-based ABI and is
//! not wired yet (kernel returns `ENOSYS`; see ADR-0032 § Stream).
//!
//! ## Errors the kernel returns
//!
//! | errno | Meaning |
//! |-------|---------|
//! | `EINVAL`  | `model_id_len != 16`, input over the payload bound, or malformed relay reply |
//! | `EFAULT`  | unreadable input pointer / unwritable output pointer (uaccess probe, WI-4b) |
//! | `ENOENT`  | the runtime service has not registered `"ai"`/`"ai_reply"` yet |
//! | `EIO`     | IPC failure, or the service answered with a structured error |
//! | `ENOSPC`  | the response exceeds `output_cap` |
//! | `ENOSYS`  | `AiStream`, or the host/test build of the kernel |
//!
//! The wrappers are bare-metal-gated like the rest of the crate's
//! syscall surface; argument-shape helpers are host-testable.

use nexacore_types::ai::AI_MAX_PAYLOAD;

/// AI syscall numbers (mirror `nexacore_kernel::syscall::SyscallNumber`).
pub mod syscall_nr {
    /// `AiInvoke (80)` — single-turn inference.
    pub const AI_INVOKE: u64 = 80;
    /// `AiStream (81)` — streaming inference (kernel: ENOSYS until the
    /// channel ABI lands).
    pub const AI_STREAM: u64 = 81;
    /// `AiEmbed (82)` — dense vector embedding (postcard `Vec<f32>` out).
    pub const AI_EMBED: u64 = 82;
    /// `AiClassify (83)` — label classification (service: not yet supported).
    pub const AI_CLASSIFY: u64 = 83;
    /// `AiTranscribe (84)` — speech-to-text (service: not yet supported).
    pub const AI_TRANSCRIBE: u64 = 84;
}

/// The compact model-id length the ABI mandates.
pub const MODEL_ID_LEN: usize = 16;

/// Borrowed argument set for one AI syscall — the shape the kernel ABI
/// expects, validated host-side by [`AiInvokeArgs::validate`].
#[derive(Debug)]
pub struct AiInvokeArgs<'a> {
    /// Compact 16-byte model identifier (zero-extended by the runtime).
    pub model_id: &'a [u8; MODEL_ID_LEN],
    /// UTF-8 prompt / input payload (≤ [`AI_MAX_PAYLOAD`] bytes; the
    /// postcard envelope adds a small header, so inputs within a few
    /// dozen bytes of the bound may still get `EINVAL` from the kernel).
    pub input: &'a [u8],
    /// Caller's response buffer.
    pub output: &'a mut [u8],
}

impl AiInvokeArgs<'_> {
    /// Host-side argument validation mirroring the kernel's checks, so
    /// callers can fail fast without a syscall. Returns `false` when the
    /// input exceeds [`AI_MAX_PAYLOAD`] or the output buffer is empty.
    #[must_use]
    pub fn validate(&self) -> bool {
        self.input.len() <= AI_MAX_PAYLOAD && !self.output.is_empty()
    }
}

#[cfg(feature = "bare-metal")]
mod bare {
    use super::{AiInvokeArgs, syscall_nr};
    use crate::{Errno, SysResult};

    /// Issue one buffer-ABI AI syscall (80/82/83/84). Returns the number
    /// of bytes the kernel wrote into `args.output`.
    ///
    /// # Errors
    ///
    /// [`Errno`] per the module-level errno table.
    #[allow(unsafe_code, clippy::similar_names)]
    fn ai_call(number: u64, args: &mut AiInvokeArgs<'_>) -> SysResult<usize> {
        if !args.validate() {
            return Err(Errno::from_raw(22)); // EINVAL, mirrored host-side
        }
        let rax: u64;
        let rdx: u64;
        // SAFETY: canonical Ring 3 → Ring 0 transition; the slices are
        // valid for the duration of the call; argument registers follow
        // the two-register kernel ABI (`crates/nexacore-kernel/src/syscall.rs`).
        unsafe {
            core::arch::asm!(
                "syscall",
                inlateout("rax") number => rax,
                in("rdi") args.model_id.as_ptr() as u64,
                in("rsi") args.model_id.len() as u64,
                inlateout("rdx") args.input.as_ptr() as u64 => rdx,
                in("r10") args.input.len() as u64,
                in("r8")  args.output.as_mut_ptr() as u64,
                in("r9")  args.output.len() as u64,
                out("rcx") _,
                out("r11") _,
                options(nostack),
            );
        }
        if rdx == 0 {
            #[allow(
                clippy::cast_possible_truncation,
                reason = "kernel bounds output_len to output_cap ≤ usize::MAX"
            )]
            Ok(rax as usize)
        } else {
            Err(Errno::from_raw(rdx))
        }
    }

    /// `AiInvoke (80)` — single-turn inference; the response text lands
    /// in `args.output`.
    ///
    /// # Errors
    ///
    /// [`Errno`] per the module-level errno table.
    pub fn ai_invoke(args: &mut AiInvokeArgs<'_>) -> SysResult<usize> {
        ai_call(syscall_nr::AI_INVOKE, args)
    }

    /// `AiEmbed (82)` — embedding; the response is a postcard `Vec<f32>`.
    ///
    /// # Errors
    ///
    /// [`Errno`] per the module-level errno table.
    pub fn ai_embed(args: &mut AiInvokeArgs<'_>) -> SysResult<usize> {
        ai_call(syscall_nr::AI_EMBED, args)
    }
}

#[cfg(feature = "bare-metal")]
pub use bare::{ai_embed, ai_invoke};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn syscall_numbers_match_kernel_abi() {
        assert_eq!(syscall_nr::AI_INVOKE, 80);
        assert_eq!(syscall_nr::AI_STREAM, 81);
        assert_eq!(syscall_nr::AI_EMBED, 82);
        assert_eq!(syscall_nr::AI_CLASSIFY, 83);
        assert_eq!(syscall_nr::AI_TRANSCRIBE, 84);
    }

    #[test]
    fn args_validate_mirrors_kernel_bounds() {
        let model = [0x41u8; MODEL_ID_LEN];
        let input = [0u8; AI_MAX_PAYLOAD];
        let mut out = [0u8; 16];
        let args = AiInvokeArgs {
            model_id: &model,
            input: &input,
            output: &mut out,
        };
        assert!(args.validate(), "input at the bound is accepted");

        let oversized = [0u8; AI_MAX_PAYLOAD + 1];
        let mut out2 = [0u8; 16];
        let args = AiInvokeArgs {
            model_id: &model,
            input: &oversized,
            output: &mut out2,
        };
        assert!(!args.validate(), "input over the bound is rejected");

        let mut empty: [u8; 0] = [];
        let args = AiInvokeArgs {
            model_id: &model,
            input: b"hi",
            output: &mut empty,
        };
        assert!(!args.validate(), "empty output buffer is rejected");
    }
}
