//! System V AMD64 ABI stack argument layout builder.
//!
//! When the kernel launches a new user-space process it must write `argc`,
//! the `argv[]` pointer array, and the `envp[]` pointer array onto the
//! process's user stack before transferring control to `_start`. This module
//! implements that layout in pure safe Rust so it is testable on host builds
//! without requiring the `bare-metal` feature.
//!
//! ## Memory layout (growing downward — high addresses at the bottom)
//!
//! ```text
//! High addresses (bottom of stack / stack_top)
//!   ├── string data area: envp strings then argv strings (each NUL-terminated)
//!   ├── padding to reach 8-byte alignment from the pointer-array base
//!   ├── NULL  (envp sentinel — 8 bytes)
//!   ├── envp[N-1] pointer  (8 bytes)
//!   ├── …
//!   ├── envp[0] pointer
//!   ├── NULL  (argv sentinel — 8 bytes)
//!   ├── argv[argc-1] pointer  (8 bytes)
//!   ├── …
//!   ├── argv[0] pointer
//!   ├── argc  (u64, 8 bytes)
//! RSP → (16-byte aligned per ABI)
//! Low addresses (top of stack)
//! ```
//!
//! All pointers are absolute virtual addresses calculated from `stack_top`.
//! The layout is fully determined at construction time; no runtime patching
//! is needed after [`crate::user_stack_args::build_stack_args`] returns.
//!
//! ## ABI reference
//!
//! System V AMD64 ABI, version 1.0, §3.4 "Process Initialization":
//! - `rsp` must be 16-byte aligned before the call instruction in `_start`.
//! - The stack frame at `rsp` is `argc` (u64), followed by `argv[0]`…
//!   `argv[argc-1]`, a NULL, then `envp[0]`… `envp[n-1]`, a NULL.

extern crate alloc;
use alloc::vec::Vec;

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

/// The fully-serialised System V AMD64 ABI argument block for a new user
/// process.
///
/// After constructing this value the kernel writes `data` into the user
/// stack region and sets `RSP = stack_top - rsp_offset`.
///
/// # Example
///
/// ```
/// # use nexacore_kernel::user_stack_args::build_stack_args;
/// let stack_top: u64 = 0x0010_0000;
/// let layout = build_stack_args(stack_top, &["/bin/sh"], &[]);
/// assert_eq!(layout.argc, 1);
/// let rsp_va = stack_top - layout.rsp_offset as u64;
/// assert_eq!(
///     rsp_va % 16,
///     0,
///     "RSP virtual address must be 16-byte aligned"
/// );
/// ```
pub struct StackArgsLayout {
    /// Raw bytes to write starting at `stack_top - data.len()`.
    ///
    /// The kernel copies these bytes verbatim to the top of the user stack
    /// (i.e. at virtual address `stack_top - data.len()`).
    pub data: Vec<u8>,

    /// Byte offset from `stack_top` where RSP should point.
    ///
    /// Invariant: `(stack_top - rsp_offset) % 16 == 0` — the resulting
    /// virtual address is 16-byte aligned per the System V AMD64 ABI.
    pub rsp_offset: usize,

    /// The `argc` value encoded in the layout (number of argv strings).
    pub argc: u64,
}

// ---------------------------------------------------------------------------
// Public functions
// ---------------------------------------------------------------------------

/// Build the System V AMD64 ABI argument block for a new process.
///
/// # Parameters
///
/// - `stack_top`: the virtual address of the highest byte of the user stack
///   region (exclusive upper bound — the first byte written is at
///   `stack_top - data.len()`).
/// - `argv`: argument strings. `argv[0]` is typically the program name.
/// - `envp`: environment key-value pairs. Each pair `(k, v)` is serialised
///   as the NUL-terminated string `"k=v\0"`.
///
/// # Returns
///
/// A [`StackArgsLayout`] whose `data` field contains the complete in-memory
/// image to write to the stack, and whose `rsp_offset` gives the offset from
/// `stack_top` at which RSP should be set before entering user mode.
///
/// # Layout details
///
/// Strings are packed contiguously at the *high-address* end of `data`
/// (closest to `stack_top`). The pointer arrays and `argc` occupy the
/// *low-address* end. A padding region between the two ensures the pointer
/// arrays start at an 8-byte-aligned address within the stack VA space.
///
/// # Example
///
/// ```
/// # use nexacore_kernel::user_stack_args::build_stack_args;
/// let stack_top: u64 = 0x0010_0000;
/// let layout = build_stack_args(
///     stack_top,
///     &["/bin/sh", "-c", "echo hi"],
///     &[("PATH", "/bin"), ("HOME", "/root")],
/// );
/// assert_eq!(layout.argc, 3);
/// // The virtual address of RSP must be 16-byte aligned.
/// let rsp_va = stack_top - layout.rsp_offset as u64;
/// assert_eq!(rsp_va % 16, 0);
/// // `data` is non-empty and contains the packed layout.
/// assert!(!layout.data.is_empty());
/// ```
#[allow(
    clippy::cast_possible_truncation,
    reason = "alignment deltas (& 7, & 15) always fit in usize on every supported target"
)]
#[allow(
    clippy::indexing_slicing,
    reason = "data is sized exactly to hold every write; all slice bounds are proven by construction"
)]
pub fn build_stack_args(stack_top: u64, argv: &[&str], envp: &[(&str, &str)]) -> StackArgsLayout {
    // -----------------------------------------------------------------------
    // Step 1: Serialise all strings into a contiguous byte buffer.
    //
    // Order: envp strings first (lowest offset within the strings block),
    // then argv strings. Each string is NUL-terminated.
    // -----------------------------------------------------------------------
    let mut strings_buf: Vec<u8> = Vec::new();

    // Record the byte offset (within strings_buf) where each envp string
    // starts so we can compute its absolute VA later.
    let mut envp_offsets: Vec<usize> = Vec::with_capacity(envp.len());
    for (k, v) in envp {
        envp_offsets.push(strings_buf.len());
        strings_buf.extend_from_slice(k.as_bytes());
        strings_buf.push(b'=');
        strings_buf.extend_from_slice(v.as_bytes());
        strings_buf.push(b'\0');
    }

    // Record the byte offset (within strings_buf) where each argv string starts.
    let mut argv_offsets: Vec<usize> = Vec::with_capacity(argv.len());
    for s in argv {
        argv_offsets.push(strings_buf.len());
        strings_buf.extend_from_slice(s.as_bytes());
        strings_buf.push(b'\0');
    }

    let strings_len = strings_buf.len();

    // -----------------------------------------------------------------------
    // Step 2: Calculate sizes.
    //
    // The in-memory layout from LOWEST VA (RSP) to HIGHEST VA (stack_top):
    //
    //   [argc         8 bytes]   ← RSP (16-byte aligned)
    //   [argv[0]      8 bytes]
    //   …
    //   [argv[argc-1] 8 bytes]
    //   [NULL argv sentinel  8 bytes]
    //   [envp[0]      8 bytes]
    //   …
    //   [envp[N-1]    8 bytes]
    //   [NULL envp sentinel  8 bytes]
    //   [pad          0..15 bytes to align the strings VA to 8 bytes]
    //   [strings      strings_len bytes]
    //
    // We build `data` with index 0 at the LOWEST address (RSP) and the
    // last index at the HIGHEST address (just below stack_top).
    //
    // Alignment strategy
    // ------------------
    // The pointer table is exactly `ptr_table_bytes` bytes (always a multiple
    // of 8). RSP must be 16-byte aligned.
    //
    // RSP VA = stack_top - total_size.
    //
    // We need (stack_top - total_size) % 16 == 0.
    // Equivalently: total_size % 16 == stack_top % 16.
    //
    // Strings area VA = stack_top - strings_len (before padding); we add
    // `str_pad` bytes between the NULL-envp-sentinel and the strings so that
    // the strings area base is 8-byte aligned:
    //   str_pad = (strings_len & 7 == 0) ? 0 : (8 - strings_len % 8)
    // which is equivalent to: str_pad = (8 - strings_len % 8) % 8 (= (-strings_len) & 7).
    //
    // Then candidate_total = ptr_table_bytes + str_pad + strings_len.
    // If (stack_top - candidate_total) % 16 != 0, add another 8 bytes of
    // padding (bumping str_pad by 8). At most one such addition is needed
    // because ptr_table_bytes is always a multiple of 8 and the increment
    // is 8 — flipping the low bit of the halved total.
    // -----------------------------------------------------------------------

    // Size of the pointer-table region:
    //   argc (8) + argv[0..argc-1] * 8 + NULL (8) + envp[0..N-1] * 8 + NULL (8)
    let ptr_table_bytes: usize = 8 + (argv.len() + 1) * 8 + (envp.len() + 1) * 8;

    // Minimum padding so the strings VA is 8-byte aligned. Because the strings
    // sit at VA = stack_top - strings_len - str_pad, we need:
    //   (stack_top - strings_len - str_pad) % 8 == 0
    // ⟹ str_pad = (stack_top as usize - strings_len) & 7   (modular)
    // This is always in [0, 7].
    let str_pad_min: usize = (stack_top as usize).wrapping_sub(strings_len) & 7;

    // candidate_total using minimum padding.
    let candidate_total: usize = ptr_table_bytes + str_pad_min + strings_len;

    // Add 8 more padding bytes if needed to make (stack_top - total) 16-aligned.
    let rsp_va_candidate: u64 = stack_top.wrapping_sub(candidate_total as u64);
    let extra: usize = if rsp_va_candidate & 15 != 0 { 8 } else { 0 };

    let str_pad: usize = str_pad_min + extra;
    let total_size: usize = ptr_table_bytes + str_pad + strings_len;

    // rsp_offset = distance from stack_top to RSP (= total_size, since RSP
    // is at the very bottom of the data block).
    let rsp_offset: usize = total_size;

    // -----------------------------------------------------------------------
    // Step 3: Build the `data` Vec.
    //
    // data[0] = lowest VA = RSP = argc location.
    // data[total_size - 1] = highest VA = last byte of strings area.
    // -----------------------------------------------------------------------
    let mut data: Vec<u8> = alloc::vec![0u8; total_size];

    // Write cursor (byte index within `data`), starts at 0 (RSP / argc).
    let mut cursor: usize = 0;

    // Helper: write a u64 in little-endian at `cursor`, advance by 8.
    //
    // The bounds are proven: each call is accounted for in `total_size`.
    macro_rules! write_u64 {
        ($val:expr) => {{
            let bytes = ($val as u64).to_le_bytes();
            data[cursor..cursor + 8].copy_from_slice(&bytes);
            cursor += 8;
        }};
    }

    // argc.
    write_u64!(argv.len() as u64);

    // Absolute VA of the first byte of the strings block.
    //
    // The strings are placed in data at offset `ptr_table_bytes + str_pad`
    // (after the pointer table and the alignment pad). The data buffer starts
    // at VA = stack_top - total_size. Therefore:
    //
    //   strings_va_base = (stack_top - total_size) + (ptr_table_bytes + str_pad)
    //                   = stack_top - (ptr_table_bytes + str_pad + strings_len)
    //                       + (ptr_table_bytes + str_pad)
    //                   = stack_top - strings_len
    //
    // The str_pad cancels out — strings always end at stack_top.
    let strings_va_base: u64 = stack_top.wrapping_sub(strings_len as u64);

    // argv pointers.
    for &off in &argv_offsets {
        write_u64!(strings_va_base.wrapping_add(off as u64));
    }
    // NULL argv sentinel.
    write_u64!(0u64);

    // envp pointers.
    for &off in &envp_offsets {
        write_u64!(strings_va_base.wrapping_add(off as u64));
    }
    // NULL envp sentinel.
    write_u64!(0u64);

    // str_pad bytes of zero — already zeroed by vec initialisation.
    cursor += str_pad;

    // Copy the strings area.
    data[cursor..cursor + strings_len].copy_from_slice(&strings_buf);
    // cursor + strings_len == total_size at this point.

    StackArgsLayout {
        data,
        rsp_offset,
        argc: argv.len() as u64,
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(
    clippy::indexing_slicing,
    reason = "test helpers index into known-good buffers; panics are acceptable in tests"
)]
#[allow(
    clippy::cast_possible_truncation,
    reason = "test code targets x86_64 host; u64->usize is lossless on 64-bit platforms"
)]
mod tests {
    use super::*;

    /// Convenience: read a NUL-terminated C string from `data` at `va`,
    /// given that `data` was written at `[stack_top - data.len() .. stack_top]`.
    fn read_cstr(data: &[u8], stack_top: u64, va: u64) -> &[u8] {
        // Offset from the start of `data` buffer:
        //   buf_offset = va - (stack_top - data.len())
        let buf_base: u64 = stack_top - data.len() as u64;
        assert!(
            va >= buf_base,
            "VA {va:#x} is below the buffer base {buf_base:#x}"
        );
        let start = (va - buf_base) as usize;
        assert!(
            start < data.len(),
            "VA {va:#x} maps to offset {start} which is out of bounds"
        );
        let end = data[start..]
            .iter()
            .position(|&b| b == 0)
            .map_or(data.len(), |pos| start + pos);
        &data[start..end]
    }

    /// Read a little-endian u64 from `data` at byte offset `offset`.
    fn read_u64(data: &[u8], offset: usize) -> u64 {
        let bytes: [u8; 8] = data[offset..offset + 8].try_into().unwrap();
        u64::from_le_bytes(bytes)
    }

    /// Offset within `data` where RSP lives (= `rsp_offset` bytes from `stack_top`,
    /// but measured from the start of `data`: `data.len() - rsp_offset`).
    fn rsp_data_offset(layout: &StackArgsLayout) -> usize {
        layout.data.len() - layout.rsp_offset
    }

    // -----------------------------------------------------------------------

    #[test]
    fn test_empty_args() {
        // argc=0, no argv, no envp.
        let layout = build_stack_args(0x0010_0000, &[], &[]);
        assert_eq!(layout.argc, 0, "argc should be 0");
        let off = rsp_data_offset(&layout);
        // argc field at RSP.
        assert_eq!(read_u64(&layout.data, off), 0, "argc in data should be 0");
        // NULL argv sentinel immediately follows argc.
        assert_eq!(read_u64(&layout.data, off + 8), 0, "argv NULL sentinel");
        // NULL envp sentinel follows the argv sentinel.
        assert_eq!(read_u64(&layout.data, off + 16), 0, "envp NULL sentinel");
    }

    #[test]
    fn test_single_arg() {
        // argc=1, argv[0] = "/bin/sh", no envp.
        let layout = build_stack_args(0x0010_0000, &["/bin/sh"], &[]);
        assert_eq!(layout.argc, 1);
        let off = rsp_data_offset(&layout);
        assert_eq!(read_u64(&layout.data, off), 1, "argc");
        // argv[0] pointer — must be non-zero.
        let argv0_va = read_u64(&layout.data, off + 8);
        assert_ne!(argv0_va, 0, "argv[0] pointer must not be NULL");
        // NULL argv sentinel.
        assert_eq!(read_u64(&layout.data, off + 16), 0, "argv NULL sentinel");
        // NULL envp sentinel.
        assert_eq!(read_u64(&layout.data, off + 24), 0, "envp NULL sentinel");
        // The pointer must resolve to the correct string.
        let s = read_cstr(&layout.data, 0x0010_0000, argv0_va);
        assert_eq!(s, b"/bin/sh", "argv[0] string content");
    }

    #[test]
    fn test_multiple_args() {
        // argc=3.
        let argv = ["/bin/echo", "-n", "hello"];
        let layout = build_stack_args(0x0010_0000, &argv, &[]);
        assert_eq!(layout.argc, 3);
        let off = rsp_data_offset(&layout);
        assert_eq!(read_u64(&layout.data, off), 3);
        // Read back each argv pointer.
        for (i, expected) in argv.iter().enumerate() {
            let ptr = read_u64(&layout.data, off + 8 + i * 8);
            assert_ne!(ptr, 0, "argv[{i}] pointer must not be NULL");
            let s = read_cstr(&layout.data, 0x0010_0000, ptr);
            assert_eq!(s, expected.as_bytes(), "argv[{i}] content mismatch");
        }
        // NULL argv sentinel is at off + 8 + 3*8 = off + 32.
        assert_eq!(read_u64(&layout.data, off + 32), 0, "argv NULL sentinel");
        // NULL envp sentinel is at off + 40.
        assert_eq!(read_u64(&layout.data, off + 40), 0, "envp NULL sentinel");
    }

    #[test]
    fn test_with_envp() {
        // PATH=/bin and HOME=/ in envp.
        let envp = [("PATH", "/bin"), ("HOME", "/")];
        let layout = build_stack_args(0x0020_0000, &["/bin/sh"], &envp);
        assert_eq!(layout.argc, 1);
        let off = rsp_data_offset(&layout);
        // argc
        assert_eq!(read_u64(&layout.data, off), 1);
        // argv[0] pointer — skip to envp section: off + 8 (argc) + 8 (argv[0]) + 8 (NULL argv).
        let envp_ptr0 = read_u64(&layout.data, off + 24);
        let envp_ptr1 = read_u64(&layout.data, off + 32);
        assert_ne!(envp_ptr0, 0, "envp[0] must not be NULL");
        assert_ne!(envp_ptr1, 0, "envp[1] must not be NULL");
        let s0 = read_cstr(&layout.data, 0x0020_0000, envp_ptr0);
        let s1 = read_cstr(&layout.data, 0x0020_0000, envp_ptr1);
        assert_eq!(s0, b"PATH=/bin", "envp[0] content");
        assert_eq!(s1, b"HOME=/", "envp[1] content");
        // NULL envp sentinel.
        assert_eq!(read_u64(&layout.data, off + 40), 0, "envp NULL sentinel");
    }

    #[test]
    fn test_rsp_16_byte_aligned() {
        // The virtual address of RSP = stack_top - rsp_offset must be
        // 16-byte aligned per the System V AMD64 ABI. We cannot require
        // `rsp_offset % 16 == 0` in general because alignment depends on
        // `stack_top % 16`; the invariant is `(stack_top - rsp_offset) % 16 == 0`.
        for &stack_top in &[
            0x0010_0000u64,
            0x0010_0008,
            0x0010_0010,
            0xFFFF_F000,
            0xC000_0000,
        ] {
            for argv_count in 0usize..=4 {
                let argv: Vec<&str> = (0..argv_count).map(|_| "arg").collect();
                let layout = build_stack_args(stack_top, &argv, &[("K", "V")]);
                let rsp_va = stack_top.wrapping_sub(layout.rsp_offset as u64);
                assert_eq!(
                    rsp_va % 16,
                    0,
                    "RSP not 16-byte aligned for stack_top={stack_top:#x} argc={argv_count} rsp_va={rsp_va:#x}"
                );
            }
        }
    }

    #[test]
    fn test_null_sentinels() {
        // Verify the NULL sentinels are present after argv and envp arrays.
        let argv = ["a", "b"];
        let envp = [("K", "V"), ("X", "Y")];
        let layout = build_stack_args(0x0010_0000, &argv, &envp);
        let off = rsp_data_offset(&layout);
        // Layout at off:
        //   [0]:    argc (u64)       = 2
        //   [8]:    argv[0] ptr
        //   [16]:   argv[1] ptr
        //   [24]:   NULL (argv sentinel)
        //   [32]:   envp[0] ptr
        //   [40]:   envp[1] ptr
        //   [48]:   NULL (envp sentinel)
        assert_eq!(read_u64(&layout.data, off + 24), 0, "argv NULL sentinel");
        assert_eq!(read_u64(&layout.data, off + 48), 0, "envp NULL sentinel");
    }

    #[test]
    fn test_argc_value_correct() {
        for count in 0usize..=8 {
            let argv: Vec<&str> = (0..count).map(|_| "x").collect();
            let layout = build_stack_args(0x0010_0000, &argv, &[]);
            assert_eq!(
                layout.argc, count as u64,
                "argc field mismatch for count={count}"
            );
            let off = rsp_data_offset(&layout);
            assert_eq!(
                read_u64(&layout.data, off),
                count as u64,
                "argc in data mismatch for count={count}"
            );
        }
    }

    #[test]
    fn test_strings_null_terminated() {
        // Every string in the layout must be NUL-terminated.
        let argv = ["/bin/sh", "hello world", "foo"];
        let envp = [("HOME", "/root"), ("TERM", "xterm-256color")];
        let layout = build_stack_args(0x0010_0000, &argv, &envp);
        let off = rsp_data_offset(&layout);
        // Check argv strings.
        for (i, arg) in argv.iter().enumerate() {
            let ptr = read_u64(&layout.data, off + 8 + i * 8);
            let buf_base: u64 = 0x0010_0000u64 - layout.data.len() as u64;
            let byte_off = (ptr - buf_base) as usize;
            // Find expected NUL.
            let expected_nul_pos = byte_off + arg.len();
            assert!(
                expected_nul_pos < layout.data.len(),
                "NUL position out of buffer for argv[{i}]"
            );
            assert_eq!(
                layout.data[expected_nul_pos], 0,
                "argv[{i}] is not NUL-terminated"
            );
        }
        // Check envp strings.
        for (i, (k, v)) in envp.iter().enumerate() {
            let ptr = read_u64(&layout.data, off + 8 + (argv.len() + 1) * 8 + i * 8);
            let buf_base: u64 = 0x0010_0000u64 - layout.data.len() as u64;
            let byte_off = (ptr - buf_base) as usize;
            let expected_len = k.len() + 1 /* '=' */ + v.len();
            let expected_nul_pos = byte_off + expected_len;
            assert!(
                expected_nul_pos < layout.data.len(),
                "NUL position out of buffer for envp[{i}]"
            );
            assert_eq!(
                layout.data[expected_nul_pos], 0,
                "envp[{i}] is not NUL-terminated"
            );
        }
    }

    #[test]
    fn test_pointer_values_correct() {
        // The pointers stored in argv[] must point to the exact string data.
        let argv = ["first", "second", "third"];
        let layout = build_stack_args(0x0080_0000, &argv, &[]);
        let off = rsp_data_offset(&layout);
        for (i, expected) in argv.iter().enumerate() {
            let ptr = read_u64(&layout.data, off + 8 + i * 8);
            let s = read_cstr(&layout.data, 0x0080_0000, ptr);
            assert_eq!(s, expected.as_bytes(), "argv[{i}] pointer target mismatch");
        }
    }

    #[test]
    fn test_roundtrip_argv_readable() {
        // Read back all argv strings from the layout and verify they match
        // the inputs exactly. This exercises the full build → read path.
        let argv = ["/usr/bin/cat", "--number", "/etc/passwd", "--show-ends"];
        let envp = [
            ("PATH", "/usr/bin:/bin"),
            ("LANG", "en_US.UTF-8"),
            ("HOME", "/home/user"),
        ];
        let stack_top: u64 = 0x0040_0000;
        let layout = build_stack_args(stack_top, &argv, &envp);

        assert_eq!(layout.argc, argv.len() as u64);
        let off = rsp_data_offset(&layout);

        // Verify argc in buffer.
        assert_eq!(read_u64(&layout.data, off), argv.len() as u64);

        // Verify all argv strings.
        for (i, expected) in argv.iter().enumerate() {
            let ptr = read_u64(&layout.data, off + 8 + i * 8);
            let s = read_cstr(&layout.data, stack_top, ptr);
            assert_eq!(s, expected.as_bytes(), "roundtrip argv[{i}] mismatch");
        }

        // Verify NULL argv sentinel.
        assert_eq!(read_u64(&layout.data, off + 8 + argv.len() * 8), 0);

        // Verify all envp strings.
        let envp_base = off + 8 + (argv.len() + 1) * 8;
        for (i, (k, v)) in envp.iter().enumerate() {
            let ptr = read_u64(&layout.data, envp_base + i * 8);
            let s = read_cstr(&layout.data, stack_top, ptr);
            let expected = alloc::format!("{k}={v}");
            assert_eq!(s, expected.as_bytes(), "roundtrip envp[{i}] mismatch");
        }

        // Verify NULL envp sentinel.
        assert_eq!(read_u64(&layout.data, envp_base + envp.len() * 8), 0);
    }

    #[test]
    fn test_empty_env_value() {
        // Environment variable with an empty value: "KEY=" should be serialised
        // as the bytes [b'K', b'E', b'Y', b'=', b'\0'].
        let layout = build_stack_args(0x0010_0000, &[], &[("EMPTY", "")]);
        let off = rsp_data_offset(&layout);
        let envp_ptr = read_u64(&layout.data, off + 16); // off+8 is NULL argv sentinel
        let s = read_cstr(&layout.data, 0x0010_0000, envp_ptr);
        assert_eq!(s, b"EMPTY=", "empty-value env var");
    }

    #[test]
    fn test_data_length_covers_all_fields() {
        // The `data` Vec must be at least large enough to hold:
        //   argc (8) + (argv.len()+1)*8 + (envp.len()+1)*8 bytes
        // of pointer table, plus the strings themselves.
        let argv = ["a", "bb", "ccc"];
        let envp = [("K1", "V1"), ("K2", "V2")];
        let layout = build_stack_args(0x0010_0000, &argv, &envp);

        let strings_len: usize = argv.iter().map(|s| s.len() + 1).sum::<usize>()
            + envp
                .iter()
                .map(|(k, v)| k.len() + 1 + v.len() + 1)
                .sum::<usize>();
        let ptr_table: usize = 8 + (argv.len() + 1) * 8 + (envp.len() + 1) * 8;

        // The data buffer must hold at least the pointer table + strings
        // (plus any alignment padding). Allow for up to 15 bytes of padding.
        assert!(
            layout.data.len() >= ptr_table + strings_len,
            "data too short: len={} ptr_table={ptr_table} strings_len={strings_len}",
            layout.data.len()
        );
        assert!(
            layout.data.len() <= ptr_table + strings_len + 15,
            "data unexpectedly large: len={} expected<={} bytes of padding",
            layout.data.len(),
            ptr_table + strings_len + 15
        );
    }
}
