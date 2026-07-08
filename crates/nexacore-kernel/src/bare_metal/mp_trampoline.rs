//! MB14.c.2.b.1 — pure-function builders for the AP startup trampoline.
//!
//! ## Scope
//!
//! Application Processors come out of reset in 16-bit real mode at
//! `CS:0000` where `CS = SIPI_vector << 4`. To bring them into long mode
//! the BSP must place a 16→32→64-bit trampoline at a known 4 KiB-aligned
//! physical page (typically `0x0000_8000`) and supply a temporary GDT plus
//! a temporary 4-level paging hierarchy. MB14.c.2.b.1 ships the *pure*
//! builders for those three artefacts:
//!
//! - [`build_trampoline_blob`] — the 256-byte machine-code blob with
//!   16-bit real-mode entry, 32-bit protected-mode transition, and
//!   64-bit long-mode `jmp rax` to a caller-provided kernel entry.
//! - [`build_temp_gdt`] / [`build_temp_gdtr`] — the 4-entry GDT and
//!   matching 32-bit pseudo-descriptor consumed by `lgdt`.
//! - [`pml4_entry_pdpt`] / [`pdpt_entry_pd`] / [`pd_entry_2mib`] /
//!   [`build_temp_identity_paging`] — the page-table entry layouts used
//!   to identity-map the first 2 MiB of physical memory, which covers the
//!   trampoline page at `0x8000`.
//!
//! **No MMIO, no physical writes, no unsafe.** The builders return owned
//! values; emplacement (write the blob to the trampoline page, allocate
//! and identity-map the temp PML4/PDPT/PD pages, hand off to the live
//! `start_aps`) lands in MB14.c.2.b.2.
//!
//! ## Why pure functions
//!
//! Every bit of the machine-code blob, GDT descriptor, and page-table
//! entry is pinned by host-side `cargo test` assertions against:
//!
//! - Intel SDM Vol 2 (instruction reference) for the opcodes / ModR/M
//!   bytes.
//! - Intel SDM Vol 3A § 3.4.5 (segment descriptor format) for the GDT.
//! - Intel SDM Vol 3A § 4.5 (IA-32e paging) for the PML4 / PDPT / PD
//!   entry bit layout.
//!
//! A bit-level regression therefore surfaces as a deterministic test
//! failure on the dev host instead of a triple-fault on Proxmox.
//!
//! ## Trampoline layout
//!
//! The blob is exactly [`TRAMPOLINE_BLOB_SIZE`] = 256 bytes (well under
//! one 4 KiB page). Section offsets are stable constants:
//!
//! | Offset | Section                              |
//! |-------:|--------------------------------------|
//! | `0x00` | 16-bit real-mode entry (`cli`/`cld`/`lgdt`/`mov cr0, …`/far jump) |
//! | `0x21` | 32-bit protected-mode transition (load `CR3`, set `PAE`, set `LME`, set `PG`, far jump) |
//! | `0x61` | 64-bit long-mode tail (`mov rax, kernel_ap_entry; jmp rax`) |
//! | `0x70` | 4-entry GDT (null + 32-bit code + 32-bit data + 64-bit code) |
//! | `0x90` | 6-byte GDTR pseudo-descriptor (`lim16 || base32`) |
//!
//! ## References
//!
//! - Intel SDM Vol 3A § 8.4 — MP Initialization Protocol
//! - Intel SDM Vol 3A § 9.10 — APIC Bus Message Passing
//! - Intel SDM Vol 2 — JMP / LGDT / MOV-CRn / RDMSR / WRMSR opcodes
//! - AMD64 APM Vol 2 § 14.8 — startup-IPI handshake & trampoline pattern

// Trampoline builders are pure-data byte writers — no unsafe needed.
// (The kernel-wide forbid(unsafe_code) policy stays in effect for this
// module without an explicit allow.)
//
// Module-level lint relaxations:
// - `cast_possible_truncation`: every `as u8` here extracts a specific
//   byte from a wider integer that has been explicitly bit-shifted to
//   isolate it. Each cast is paired with the documented shift, and the
//   byte-exact tests below pin the output. Equivalent code via
//   `to_le_bytes()` would not change semantics but obscure the per-byte
//   correspondence with the Intel/AMD instruction-encoding tables.
// - `indexing_slicing`: every `blob[…]` index is a compile-time constant
//   bounded by `TRAMPOLINE_BLOB_SIZE`, validated by
//   `section_offsets_are_monotonically_increasing` in the test module.
// - `too_many_lines`: `build_trampoline_blob` is a single linear sequence
//   of instruction-byte writes pinned to the SDM. Splitting per-section
//   would force re-introducing intermediate helpers that obscure the
//   1:1 byte ↔ instruction mapping.
// - `similar_names`: `gdt` / `gdtr` mirror the actual x86 mnemonics (the
//   table vs its register pseudo-descriptor). Renaming would make the
//   code less, not more, readable.
#![allow(
    clippy::cast_possible_truncation,
    reason = "every `as u8` extracts an explicitly bit-shifted byte; behaviour pinned by byte-exact tests"
)]
#![allow(
    clippy::indexing_slicing,
    reason = "every blob index is a compile-time constant within TRAMPOLINE_BLOB_SIZE"
)]
#![allow(
    clippy::too_many_lines,
    reason = "linear instruction-byte sequence pinned to Intel SDM — splitting obscures the byte/mnemonic mapping"
)]
#![allow(
    clippy::similar_names,
    reason = "`gdt` vs `gdtr` mirror the x86 mnemonics (table vs pseudo-descriptor)"
)]

use crate::bare_metal::paging::{PTE_HUGE, PTE_PRESENT, PTE_WRITABLE};

// =====================================================================
// Public constants — blob layout
// =====================================================================

/// Total size in bytes of the trampoline blob.
///
/// 256 bytes is generous: the actual machine code + GDT + GDTR sums to
/// 0x96 (150) bytes. The blob is page-padded with zeros so emplacement
/// can copy a fixed-size slice without per-section knowledge.
pub const TRAMPOLINE_BLOB_SIZE: usize = 256;

/// Offset within the blob of the 16-bit real-mode entry point.
///
/// AP execution starts here. Must be `0x00` because the SIPI vector
/// `V` causes `CS:IP = V0:0000`, and the blob is copied to physical
/// `V << 12`.
pub const TRAMPOLINE_OFFSET_RM16: usize = 0x00;

/// Offset within the blob of the 32-bit protected-mode section.
pub const TRAMPOLINE_OFFSET_PM32: usize = 0x22;

/// Offset within the blob of the 64-bit long-mode tail.
pub const TRAMPOLINE_OFFSET_LM64: usize = 0x62;

/// Offset within the blob of the embedded 4-entry GDT (8-byte aligned).
pub const TRAMPOLINE_OFFSET_GDT: usize = 0x70;

/// Offset within the blob of the 6-byte GDTR pseudo-descriptor
/// (`lim16 || base32`).
pub const TRAMPOLINE_OFFSET_GDTR: usize = 0x90;

/// Number of descriptors in the temporary GDT (null, 32-bit code,
/// 32-bit data, 64-bit code).
pub const TRAMPOLINE_GDT_ENTRIES: usize = 4;

/// Total size of the trampoline GDT in bytes (`TRAMPOLINE_GDT_ENTRIES * 8`).
pub const TRAMPOLINE_GDT_SIZE: usize = TRAMPOLINE_GDT_ENTRIES * 8;

/// Size of the 32-bit GDTR pseudo-descriptor in bytes (`lim16 || base32`).
pub const TRAMPOLINE_GDTR_SIZE: usize = 6;

/// Selector for the trampoline 32-bit code descriptor (GDT slot 1).
pub const TRAMPOLINE_SEL_CODE32: u16 = 0x08;

/// Selector for the trampoline 32-bit data descriptor (GDT slot 2).
pub const TRAMPOLINE_SEL_DATA32: u16 = 0x10;

/// Selector for the trampoline 64-bit code descriptor (GDT slot 3).
pub const TRAMPOLINE_SEL_CODE64: u16 = 0x18;

// =====================================================================
// Relocation offsets (private — exposed via tests)
// =====================================================================

/// Offset of the `lgdt` `disp16` field inside the 16-bit section.
///
/// The 2-byte little-endian value here is `base_paddr + TRAMPOLINE_OFFSET_GDTR`
/// (the absolute physical address of the GDTR pseudo-descriptor, which
/// fits in 16 bits when `base_paddr <= 0xFFFF - TRAMPOLINE_OFFSET_GDTR`).
const RELOC_GDTR_DISP16: usize = 0x0E;

/// Offset of the 16→32 far-jump `off32` field (selector immediately
/// follows at `RELOC_PM32_OFFSET + 4`).
const RELOC_PM32_OFFSET: usize = 0x1C;

/// Offset of the 32-bit `mov eax, temp_pml4_paddr` immediate.
const RELOC_PML4_PADDR: usize = 0x32;

/// Offset of the 32→64 far-jump `off32` field (selector immediately
/// follows at `RELOC_LM64_OFFSET + 4`).
const RELOC_LM64_OFFSET: usize = 0x5C;

/// Offset of the 64-bit `mov rax, kernel_ap_entry` immediate (8 bytes).
const RELOC_KERNEL_ENTRY: usize = 0x64;

// =====================================================================
// Trampoline blob
// =====================================================================

/// Build the AP real-mode → 32-bit → 64-bit trampoline blob.
///
/// # Parameters
///
/// - `base_paddr`: physical address where the blob will be copied.
///   Must be 4 KiB-aligned and ≤ `0xFF000` (so the SIPI vector field —
///   which is `base_paddr >> 12` — fits in 8 bits). Real-mode `lgdt`
///   reaches the GDTR via a 16-bit displacement against `DS = 0`, so
///   `base_paddr + TRAMPOLINE_OFFSET_GDTR` must fit in 16 bits.
/// - `temp_pml4_paddr`: physical address of the temporary 4-level paging
///   root loaded into `CR3` before enabling `PG`. Must be 4 KiB-aligned
///   and ≤ 4 GiB (the 32-bit `mov eax, imm32` relocation cannot reach
///   higher).
/// - `kernel_ap_entry`: 64-bit virtual address of the per-AP kernel
///   entry point. Reached by the final `jmp rax` once long mode is
///   active. Must be addressable in the long-mode address space the
///   temporary PML4 establishes.
///
/// # Returns
///
/// A [`TRAMPOLINE_BLOB_SIZE`]-byte blob ready for copy to `base_paddr`.
/// The first byte is `0xFA` (`cli`); the layout follows the table in the
/// module-level documentation.
#[must_use]
pub fn build_trampoline_blob(
    base_paddr: u32,
    temp_pml4_paddr: u32,
    kernel_ap_entry: u64,
) -> [u8; TRAMPOLINE_BLOB_SIZE] {
    let mut blob = [0u8; TRAMPOLINE_BLOB_SIZE];

    // -----------------------------------------------------------------
    // 16-bit real-mode entry @ 0x00..0x21
    // -----------------------------------------------------------------
    //
    // Intel SDM Vol 2 references in [brackets].

    // 0x00  FA              cli                                [SDM Vol 2 CLI]
    // 0x01  FC              cld                                [SDM Vol 2 CLD]
    blob[0x00] = 0xFA;
    blob[0x01] = 0xFC;

    // 0x02  31 C0           xor ax, ax                         [SDM Vol 2 XOR; ModR/M C0 = AX,AX]
    blob[0x02] = 0x31;
    blob[0x03] = 0xC0;

    // 0x04  8E D8           mov ds, ax                         [SDM Vol 2 MOV Sreg,r/m16; D8 = DS,AX]
    // 0x06  8E C0           mov es, ax                         [C0 = ES,AX]
    // 0x08  8E D0           mov ss, ax                         [D0 = SS,AX]
    blob[0x04] = 0x8E;
    blob[0x05] = 0xD8;
    blob[0x06] = 0x8E;
    blob[0x07] = 0xC0;
    blob[0x08] = 0x8E;
    blob[0x09] = 0xD0;

    // 0x0A  66 0F 01 16 <disp16>   o32 lgdt [GDTR]            [SDM Vol 2 LGDT m16&32]
    //   - 0x66 operand-size prefix forces 32-bit base load (default in
    //     real mode is m16&24 — high byte of base masked).
    //   - ModR/M 0x16 = mod=00 (disp16), reg=2 (LGDT), rm=110 (disp16).
    blob[0x0A] = 0x66;
    blob[0x0B] = 0x0F;
    blob[0x0C] = 0x01;
    blob[0x0D] = 0x16;
    let gdtr_abs16 = (base_paddr as u16).wrapping_add(TRAMPOLINE_OFFSET_GDTR as u16);
    blob[RELOC_GDTR_DISP16] = gdtr_abs16 as u8;
    blob[RELOC_GDTR_DISP16 + 1] = (gdtr_abs16 >> 8) as u8;

    // 0x10  0F 20 C0        mov eax, cr0                       [SDM Vol 2 MOV r32,CR; C0 = EAX,CR0]
    blob[0x10] = 0x0F;
    blob[0x11] = 0x20;
    blob[0x12] = 0xC0;

    // 0x13  66 83 C8 01     o32 or eax, 1                      [SDM Vol 2 OR r/m32,imm8 sign-extended]
    //   - 0x66 forces 32-bit operand in 16-bit mode.
    //   - ModR/M C8 = mod=11, reg=1 (OR), rm=0 (EAX).
    blob[0x13] = 0x66;
    blob[0x14] = 0x83;
    blob[0x15] = 0xC8;
    blob[0x16] = 0x01;

    // 0x17  0F 22 C0        mov cr0, eax                       [SDM Vol 2 MOV CR,r32; C0 = CR0,EAX]
    blob[0x17] = 0x0F;
    blob[0x18] = 0x22;
    blob[0x19] = 0xC0;

    // 0x1A  66 EA <off32> <sel16>  o32 jmp far CODE32:OFF32   [SDM Vol 2 JMP m16:32 with 66 prefix]
    blob[0x1A] = 0x66;
    blob[0x1B] = 0xEA;
    let pm32_abs = base_paddr.wrapping_add(TRAMPOLINE_OFFSET_PM32 as u32);
    blob[RELOC_PM32_OFFSET] = pm32_abs as u8;
    blob[RELOC_PM32_OFFSET + 1] = (pm32_abs >> 8) as u8;
    blob[RELOC_PM32_OFFSET + 2] = (pm32_abs >> 16) as u8;
    blob[RELOC_PM32_OFFSET + 3] = (pm32_abs >> 24) as u8;
    blob[0x20] = TRAMPOLINE_SEL_CODE32 as u8;
    blob[0x20 + 1] = (TRAMPOLINE_SEL_CODE32 >> 8) as u8;

    // -----------------------------------------------------------------
    // 32-bit protected-mode @ 0x22..0x62
    // -----------------------------------------------------------------

    // 0x22  B8 10 00 00 00  mov eax, 0x10                      (data selector)
    blob[0x22] = 0xB8;
    blob[0x23] = TRAMPOLINE_SEL_DATA32 as u8;
    blob[0x24] = (TRAMPOLINE_SEL_DATA32 >> 8) as u8;
    blob[0x25] = 0x00;
    blob[0x26] = 0x00;

    // 0x27  8E D8           mov ds, ax
    // 0x29  8E C0           mov es, ax
    // 0x2B  8E D0           mov ss, ax
    // 0x2D  8E E0           mov fs, ax                         (E0 = FS,AX)
    // 0x2F  8E E8           mov gs, ax                         (E8 = GS,AX)
    blob[0x27] = 0x8E;
    blob[0x28] = 0xD8;
    blob[0x29] = 0x8E;
    blob[0x2A] = 0xC0;
    blob[0x2B] = 0x8E;
    blob[0x2C] = 0xD0;
    blob[0x2D] = 0x8E;
    blob[0x2E] = 0xE0;
    blob[0x2F] = 0x8E;
    blob[0x30] = 0xE8;

    // 0x31  B8 <imm32>      mov eax, temp_pml4_paddr           [RELOC]
    blob[0x31] = 0xB8;
    blob[RELOC_PML4_PADDR] = temp_pml4_paddr as u8;
    blob[RELOC_PML4_PADDR + 1] = (temp_pml4_paddr >> 8) as u8;
    blob[RELOC_PML4_PADDR + 2] = (temp_pml4_paddr >> 16) as u8;
    blob[RELOC_PML4_PADDR + 3] = (temp_pml4_paddr >> 24) as u8;

    // 0x36  0F 22 D8        mov cr3, eax                       (D8 = CR3,EAX)
    blob[0x36] = 0x0F;
    blob[0x37] = 0x22;
    blob[0x38] = 0xD8;

    // 0x39  0F 20 E0        mov eax, cr4                       (E0 = EAX,CR4)
    blob[0x39] = 0x0F;
    blob[0x3A] = 0x20;
    blob[0x3B] = 0xE0;

    // 0x3C  83 C8 20        or eax, 0x20                       (CR4.PAE = bit 5)
    blob[0x3C] = 0x83;
    blob[0x3D] = 0xC8;
    blob[0x3E] = 0x20;

    // 0x3F  0F 22 E0        mov cr4, eax                       (E0 = CR4,EAX)
    blob[0x3F] = 0x0F;
    blob[0x40] = 0x22;
    blob[0x41] = 0xE0;

    // 0x42  B9 80 00 00 C0  mov ecx, 0xC000_0080               (IA32_EFER)
    blob[0x42] = 0xB9;
    blob[0x43] = 0x80;
    blob[0x44] = 0x00;
    blob[0x45] = 0x00;
    blob[0x46] = 0xC0;

    // 0x47  0F 32           rdmsr                              [SDM Vol 2 RDMSR]
    blob[0x47] = 0x0F;
    blob[0x48] = 0x32;

    // 0x49  0D 00 09 00 00  or eax, 0x900                      (IA32_EFER.LME | NXE)
    //
    // MB14.c.2.d.1 fix: bit 8 (LME) alone is insufficient when the BSP's
    // kernel page tables set the NX bit (bit 63) on non-executable
    // pages (data / bss / rodata). Without `EFER.NXE = 1`, the AP's
    // page-walker treats bit 63 of a PTE as a *reserved* bit; any
    // memory access whose PTE has it set faults with a reserved-bit
    // page fault. Setting NXE here brings the AP into the same NX
    // policy the BSP uses, so all of higher-half (text + rodata +
    // data + bss) is reachable.
    blob[0x49] = 0x0D;
    blob[0x4A] = 0x00;
    blob[0x4B] = 0x09; // bit 8 (LME) | bit 11 (NXE)
    blob[0x4C] = 0x00;
    blob[0x4D] = 0x00;

    // 0x4E  0F 30           wrmsr                              [SDM Vol 2 WRMSR]
    blob[0x4E] = 0x0F;
    blob[0x4F] = 0x30;

    // 0x50  0F 20 C0        mov eax, cr0
    blob[0x50] = 0x0F;
    blob[0x51] = 0x20;
    blob[0x52] = 0xC0;

    // 0x53  0D 01 00 00 80  or eax, 0x8000_0001                (CR0.PG | CR0.PE)
    blob[0x53] = 0x0D;
    blob[0x54] = 0x01;
    blob[0x55] = 0x00;
    blob[0x56] = 0x00;
    blob[0x57] = 0x80;

    // 0x58  0F 22 C0        mov cr0, eax                       (commit PG+PE — now in IA-32e compat mode)
    blob[0x58] = 0x0F;
    blob[0x59] = 0x22;
    blob[0x5A] = 0xC0;

    // 0x5B  EA <off32> <sel16>  jmp far CODE64:OFF32           [SDM Vol 2 JMP m16:32 in 32-bit mode]
    blob[0x5B] = 0xEA;
    let lm64_abs = base_paddr.wrapping_add(TRAMPOLINE_OFFSET_LM64 as u32);
    blob[RELOC_LM64_OFFSET] = lm64_abs as u8;
    blob[RELOC_LM64_OFFSET + 1] = (lm64_abs >> 8) as u8;
    blob[RELOC_LM64_OFFSET + 2] = (lm64_abs >> 16) as u8;
    blob[RELOC_LM64_OFFSET + 3] = (lm64_abs >> 24) as u8;
    blob[0x60] = TRAMPOLINE_SEL_CODE64 as u8;
    blob[0x60 + 1] = (TRAMPOLINE_SEL_CODE64 >> 8) as u8;

    // -----------------------------------------------------------------
    // 64-bit long-mode tail @ 0x62..0x6E
    // -----------------------------------------------------------------

    // 0x62  48 B8 <imm64>   mov rax, kernel_ap_entry           [SDM Vol 2 MOV r64,imm64 with REX.W]
    blob[0x62] = 0x48;
    blob[0x63] = 0xB8;
    blob[RELOC_KERNEL_ENTRY] = kernel_ap_entry as u8;
    blob[RELOC_KERNEL_ENTRY + 1] = (kernel_ap_entry >> 8) as u8;
    blob[RELOC_KERNEL_ENTRY + 2] = (kernel_ap_entry >> 16) as u8;
    blob[RELOC_KERNEL_ENTRY + 3] = (kernel_ap_entry >> 24) as u8;
    blob[RELOC_KERNEL_ENTRY + 4] = (kernel_ap_entry >> 32) as u8;
    blob[RELOC_KERNEL_ENTRY + 5] = (kernel_ap_entry >> 40) as u8;
    blob[RELOC_KERNEL_ENTRY + 6] = (kernel_ap_entry >> 48) as u8;
    blob[RELOC_KERNEL_ENTRY + 7] = (kernel_ap_entry >> 56) as u8;

    // 0x6C  FF E0           jmp rax                            [SDM Vol 2 JMP r/m64; E0 = RAX]
    blob[0x6C] = 0xFF;
    blob[0x6D] = 0xE0;

    // 0x6E..0x70  90 90    nop nop                             (alignment padding)
    blob[0x6E] = 0x90;
    blob[0x6F] = 0x90;

    // -----------------------------------------------------------------
    // Embedded GDT @ 0x70..0x90
    // -----------------------------------------------------------------

    let gdt = build_temp_gdt();
    let gdt_off = TRAMPOLINE_OFFSET_GDT;
    let mut i = 0;
    while i < TRAMPOLINE_GDT_ENTRIES {
        let entry = gdt[i].to_le_bytes();
        let mut j = 0;
        while j < 8 {
            blob[gdt_off + i * 8 + j] = entry[j];
            j += 1;
        }
        i += 1;
    }

    // -----------------------------------------------------------------
    // GDTR pseudo-descriptor @ 0x90..0x96
    // -----------------------------------------------------------------

    let gdt_base = base_paddr.wrapping_add(TRAMPOLINE_OFFSET_GDT as u32);
    let gdtr = build_temp_gdtr(gdt_base);
    let gdtr_off = TRAMPOLINE_OFFSET_GDTR;
    let mut i = 0;
    while i < TRAMPOLINE_GDTR_SIZE {
        blob[gdtr_off + i] = gdtr[i];
        i += 1;
    }

    blob
}

// =====================================================================
// GDT builders
// =====================================================================

/// Build the trampoline's 4-entry GDT.
///
/// Slot layout (Intel SDM Vol 3A § 3.4.5 descriptor format):
/// - Slot 0 (sel `0x00`): null descriptor.
/// - Slot 1 (sel [`TRAMPOLINE_SEL_CODE32`]): 32-bit code, base 0, limit
///   `0xFFFFF` (× 4 KiB granularity = 4 GiB), DPL=0, P=1, S=1,
///   Type=`Exec-Read` (`1010b`), G=1, D=1, L=0 → encoded
///   `0x00CF_9A00_0000_FFFF`.
/// - Slot 2 (sel [`TRAMPOLINE_SEL_DATA32`]): 32-bit data, same base/limit,
///   Type=`Read-Write` (`0010b`) → `0x00CF_9200_0000_FFFF`.
/// - Slot 3 (sel [`TRAMPOLINE_SEL_CODE64`]): 64-bit code, L=1, D=0 →
///   `0x00AF_9A00_0000_FFFF`.
#[must_use]
pub const fn build_temp_gdt() -> [u64; TRAMPOLINE_GDT_ENTRIES] {
    [
        0x0000_0000_0000_0000,
        0x00CF_9A00_0000_FFFF,
        0x00CF_9200_0000_FFFF,
        0x00AF_9A00_0000_FFFF,
    ]
}

/// Build the 32-bit GDTR pseudo-descriptor (`lim16 || base32`).
///
/// The limit is `TRAMPOLINE_GDT_SIZE - 1` per Intel SDM Vol 3A § 3.5.1
/// (GDTR limit is the offset of the last valid byte). `gdt_base_paddr` is
/// stored as little-endian.
#[must_use]
pub const fn build_temp_gdtr(gdt_base_paddr: u32) -> [u8; TRAMPOLINE_GDTR_SIZE] {
    let limit = (TRAMPOLINE_GDT_SIZE - 1) as u16;
    [
        limit as u8,
        (limit >> 8) as u8,
        gdt_base_paddr as u8,
        (gdt_base_paddr >> 8) as u8,
        (gdt_base_paddr >> 16) as u8,
        (gdt_base_paddr >> 24) as u8,
    ]
}

// =====================================================================
// Temporary paging entry builders
// =====================================================================

/// Mask isolating the 4 KiB-aligned frame address in a non-PS page-table
/// entry (Intel SDM Vol 3A § 4.5, bits \[51:12\]).
const PTE_FRAME_4K_MASK: u64 = 0x000F_FFFF_FFFF_F000;

/// Mask isolating the 2 MiB-aligned frame address in a PS=1 PD entry
/// (Intel SDM Vol 3A § 4.5, bits \[51:21\]).
const PTE_FRAME_2M_MASK: u64 = 0x000F_FFFF_FFE0_0000;

/// Build a PML4 entry pointing at a child PDPT.
///
/// Sets `P` + `R/W` and stores the child PDPT physical frame in bits
/// \[51:12\]. `child_pdpt_paddr` must be 4 KiB-aligned — excess low bits
/// are masked away to keep the invariant explicit.
#[must_use]
pub const fn pml4_entry_pdpt(child_pdpt_paddr: u64) -> u64 {
    (child_pdpt_paddr & PTE_FRAME_4K_MASK) | PTE_PRESENT | PTE_WRITABLE
}

/// Build a PDPT entry pointing at a child PD.
///
/// Identical flag layout to [`pml4_entry_pdpt`] — the `PS` bit must stay
/// 0 for a PDPT entry that references a PD.
#[must_use]
pub const fn pdpt_entry_pd(child_pd_paddr: u64) -> u64 {
    (child_pd_paddr & PTE_FRAME_4K_MASK) | PTE_PRESENT | PTE_WRITABLE
}

/// Build a PD entry that maps a 2 MiB page directly (`PS = 1`).
///
/// `target_paddr` must be 2 MiB-aligned; excess low bits are masked
/// away. The encoded entry sets `P` + `R/W` + `PS` and stores the
/// target frame in bits \[51:21\].
#[must_use]
pub const fn pd_entry_2mib(target_paddr: u64) -> u64 {
    (target_paddr & PTE_FRAME_2M_MASK) | PTE_PRESENT | PTE_WRITABLE | PTE_HUGE
}

/// A complete 3-page temporary 4-level paging hierarchy that
/// identity-maps the first 2 MiB of physical memory using one 2 MiB
/// huge page.
///
/// The trampoline at physical `0x0000_8000` lives in this 2 MiB window,
/// so the AP can transition from 32-bit protected mode to 64-bit long
/// mode without first faulting on its own instruction stream. Once in
/// long mode, the per-AP entry stub will load the real kernel `CR3` and
/// jump to the higher-half kernel image — outside the scope of this
/// temporary hierarchy.
#[derive(Debug, Clone, Copy)]
pub struct TempIdentityPaging {
    /// The PML4 page (one populated entry at index 0).
    pub pml4: [u64; 512],
    /// The PDPT page (one populated entry at index 0).
    pub pdpt: [u64; 512],
    /// The PD page (one populated entry at index 0, PS=1, maps 0..2 MiB).
    pub pd: [u64; 512],
}

/// Build a [`TempIdentityPaging`] hierarchy that identity-maps the first
/// 2 MiB of physical memory using a single 2 MiB huge PD entry.
///
/// `pdpt_paddr` and `pd_paddr` are the physical addresses MB14.c.2.b.2
/// will allocate for the PDPT and PD pages; the PML4 root points at
/// `pdpt_paddr` and the PDPT entry 0 points at `pd_paddr`. The PD entry
/// 0 is a self-contained `pd_entry_2mib(0)` — the target frame is
/// embedded in the entry itself, not in a separate page.
#[must_use]
pub const fn build_temp_identity_paging(pdpt_paddr: u64, pd_paddr: u64) -> TempIdentityPaging {
    let mut pml4 = [0u64; 512];
    let mut pdpt = [0u64; 512];
    let mut pd = [0u64; 512];

    pml4[0] = pml4_entry_pdpt(pdpt_paddr);
    pdpt[0] = pdpt_entry_pd(pd_paddr);
    pd[0] = pd_entry_2mib(0);

    TempIdentityPaging { pml4, pdpt, pd }
}

// =====================================================================
// Host-side tests
// =====================================================================

#[cfg(test)]
#[allow(
    clippy::indexing_slicing,
    reason = "tests panic on bounds violation by design — surfaces builder regressions as test failures, not silent wrong bytes"
)]
mod tests {
    use super::*;

    /// Canonical base address used in the encoding tests. Matches the
    /// MB14.c.2.b plan (trampoline page = `0x8000`).
    const BASE: u32 = 0x0000_8000;

    /// Canonical temporary PML4 address used in tests.
    const TEMP_PML4: u32 = 0x0000_9000;

    /// Canonical kernel AP entry address (higher-half).
    const KERNEL_AP_ENTRY: u64 = 0xFFFF_FFFF_8010_0000;

    // ------------------- 16-bit prologue ----------------------------

    #[test]
    fn blob_starts_with_cli_cld() {
        let b = build_trampoline_blob(BASE, TEMP_PML4, KERNEL_AP_ENTRY);
        assert_eq!(b[0x00], 0xFA, "cli");
        assert_eq!(b[0x01], 0xFC, "cld");
    }

    #[test]
    fn blob_loads_zero_segments_via_xor_ax_ax() {
        let b = build_trampoline_blob(BASE, TEMP_PML4, KERNEL_AP_ENTRY);
        // xor ax, ax
        assert_eq!(&b[0x02..0x04], &[0x31, 0xC0]);
        // mov ds, ax / mov es, ax / mov ss, ax
        assert_eq!(&b[0x04..0x0A], &[0x8E, 0xD8, 0x8E, 0xC0, 0x8E, 0xD0]);
    }

    #[test]
    fn blob_loads_gdt_via_o32_lgdt() {
        let b = build_trampoline_blob(BASE, TEMP_PML4, KERNEL_AP_ENTRY);
        // 66 0F 01 16 <disp16>
        assert_eq!(b[0x0A], 0x66);
        assert_eq!(b[0x0B], 0x0F);
        assert_eq!(b[0x0C], 0x01);
        assert_eq!(b[0x0D], 0x16);
        let disp = u16::from_le_bytes([b[0x0E], b[0x0F]]);
        assert_eq!(
            u32::from(disp),
            BASE + TRAMPOLINE_OFFSET_GDTR as u32,
            "GDTR disp16 must point at the embedded GDTR pseudo-descriptor"
        );
    }

    #[test]
    fn blob_sets_pe_in_cr0() {
        let b = build_trampoline_blob(BASE, TEMP_PML4, KERNEL_AP_ENTRY);
        // mov eax, cr0   ; 0F 20 C0
        assert_eq!(&b[0x10..0x13], &[0x0F, 0x20, 0xC0]);
        // o32 or eax, 1  ; 66 83 C8 01
        assert_eq!(&b[0x13..0x17], &[0x66, 0x83, 0xC8, 0x01]);
        // mov cr0, eax   ; 0F 22 C0
        assert_eq!(&b[0x17..0x1A], &[0x0F, 0x22, 0xC0]);
    }

    #[test]
    fn blob_16to32_far_jump_targets_pm32_section() {
        let b = build_trampoline_blob(BASE, TEMP_PML4, KERNEL_AP_ENTRY);
        // 66 EA <off32> <sel16>  (8 bytes total)
        assert_eq!(b[0x1A], 0x66, "operand-size prefix");
        assert_eq!(b[0x1B], 0xEA, "far jmp opcode");
        let off = u32::from_le_bytes([b[0x1C], b[0x1D], b[0x1E], b[0x1F]]);
        let sel = u16::from_le_bytes([b[0x20], b[0x21]]);
        assert_eq!(off, BASE + TRAMPOLINE_OFFSET_PM32 as u32);
        assert_eq!(sel, TRAMPOLINE_SEL_CODE32);
    }

    // ------------------- 32-bit transition --------------------------

    #[test]
    fn blob_32bit_loads_data_selector_into_segregs() {
        let b = build_trampoline_blob(BASE, TEMP_PML4, KERNEL_AP_ENTRY);
        // B8 10 00 00 00   mov eax, 0x10
        assert_eq!(&b[0x22..0x27], &[0xB8, 0x10, 0x00, 0x00, 0x00]);
        // mov ds/es/ss/fs/gs, ax  (8E + ModR/M each)
        assert_eq!(
            &b[0x27..0x31],
            &[0x8E, 0xD8, 0x8E, 0xC0, 0x8E, 0xD0, 0x8E, 0xE0, 0x8E, 0xE8]
        );
    }

    #[test]
    fn blob_32bit_loads_temp_pml4_into_cr3() {
        let b = build_trampoline_blob(BASE, TEMP_PML4, KERNEL_AP_ENTRY);
        // B8 <imm32>     mov eax, temp_pml4_paddr
        assert_eq!(b[0x31], 0xB8);
        let imm = u32::from_le_bytes([b[0x32], b[0x33], b[0x34], b[0x35]]);
        assert_eq!(imm, TEMP_PML4);
        // 0F 22 D8       mov cr3, eax
        assert_eq!(&b[0x36..0x39], &[0x0F, 0x22, 0xD8]);
    }

    #[test]
    fn blob_32bit_enables_pae_in_cr4() {
        let b = build_trampoline_blob(BASE, TEMP_PML4, KERNEL_AP_ENTRY);
        // 0F 20 E0   mov eax, cr4
        assert_eq!(&b[0x39..0x3C], &[0x0F, 0x20, 0xE0]);
        // 83 C8 20   or eax, 0x20
        assert_eq!(&b[0x3C..0x3F], &[0x83, 0xC8, 0x20]);
        // 0F 22 E0   mov cr4, eax
        assert_eq!(&b[0x3F..0x42], &[0x0F, 0x22, 0xE0]);
    }

    #[test]
    fn blob_32bit_sets_lme_via_efer_msr() {
        let b = build_trampoline_blob(BASE, TEMP_PML4, KERNEL_AP_ENTRY);
        // B9 80 00 00 C0   mov ecx, 0xC0000080  (IA32_EFER)
        assert_eq!(&b[0x42..0x47], &[0xB9, 0x80, 0x00, 0x00, 0xC0]);
        // 0F 32           rdmsr
        assert_eq!(&b[0x47..0x49], &[0x0F, 0x32]);
        // 0D 00 09 00 00  or eax, 0x900  (LME = bit 8 | NXE = bit 11)
        // MB14.c.2.d.1: NXE is required so the AP's page walker honours
        // the kernel's NX bit on .data/.bss pages.
        assert_eq!(&b[0x49..0x4E], &[0x0D, 0x00, 0x09, 0x00, 0x00]);
        // 0F 30           wrmsr
        assert_eq!(&b[0x4E..0x50], &[0x0F, 0x30]);
    }

    #[test]
    fn blob_32bit_enables_paging_with_pe_pg() {
        let b = build_trampoline_blob(BASE, TEMP_PML4, KERNEL_AP_ENTRY);
        // 0F 20 C0           mov eax, cr0
        assert_eq!(&b[0x50..0x53], &[0x0F, 0x20, 0xC0]);
        // 0D 01 00 00 80     or eax, 0x80000001  (PG | PE)
        assert_eq!(&b[0x53..0x58], &[0x0D, 0x01, 0x00, 0x00, 0x80]);
        // 0F 22 C0           mov cr0, eax
        assert_eq!(&b[0x58..0x5B], &[0x0F, 0x22, 0xC0]);
    }

    #[test]
    fn blob_32to64_far_jump_targets_lm64_section() {
        let b = build_trampoline_blob(BASE, TEMP_PML4, KERNEL_AP_ENTRY);
        // EA <off32> <sel16>  (no 0x66 prefix in 32-bit mode — default is 32-bit)
        assert_eq!(b[0x5B], 0xEA);
        let off = u32::from_le_bytes([b[0x5C], b[0x5D], b[0x5E], b[0x5F]]);
        let sel = u16::from_le_bytes([b[0x60], b[0x61]]);
        assert_eq!(off, BASE + TRAMPOLINE_OFFSET_LM64 as u32);
        assert_eq!(sel, TRAMPOLINE_SEL_CODE64);
    }

    // ------------------- 64-bit tail --------------------------------

    #[test]
    fn blob_64bit_loads_kernel_entry_and_jumps() {
        let b = build_trampoline_blob(BASE, TEMP_PML4, KERNEL_AP_ENTRY);
        // 48 B8 <imm64>     mov rax, kernel_ap_entry
        assert_eq!(b[0x62], 0x48, "REX.W prefix");
        assert_eq!(b[0x63], 0xB8);
        let imm = u64::from_le_bytes([
            b[0x64], b[0x65], b[0x66], b[0x67], b[0x68], b[0x69], b[0x6A], b[0x6B],
        ]);
        assert_eq!(imm, KERNEL_AP_ENTRY);
        // FF E0   jmp rax
        assert_eq!(&b[0x6C..0x6E], &[0xFF, 0xE0]);
    }

    // ------------------- Relocations cover only documented bytes ----

    #[test]
    fn relocations_isolate_at_documented_offsets() {
        let b1 = build_trampoline_blob(BASE, TEMP_PML4, KERNEL_AP_ENTRY);
        let b2 = build_trampoline_blob(BASE, TEMP_PML4 + 0x1000, KERNEL_AP_ENTRY);
        // Only the 4 bytes at RELOC_PML4_PADDR may change.
        for i in 0..TRAMPOLINE_BLOB_SIZE {
            if (0x32..0x36).contains(&i) {
                continue;
            }
            assert_eq!(b1[i], b2[i], "byte at offset {i:#x} should not change");
        }
    }

    #[test]
    fn kernel_entry_relocation_changes_only_8_bytes() {
        let b1 = build_trampoline_blob(BASE, TEMP_PML4, 0x1111_2222_3333_4444);
        let b2 = build_trampoline_blob(BASE, TEMP_PML4, 0xAAAA_BBBB_CCCC_DDDD);
        for i in 0..TRAMPOLINE_BLOB_SIZE {
            if (0x64..0x6C).contains(&i) {
                continue;
            }
            assert_eq!(b1[i], b2[i], "byte at offset {i:#x} should not change");
        }
    }

    // ------------------- GDT layout ---------------------------------

    #[test]
    fn gdt_has_four_entries_with_canonical_layout() {
        let gdt = build_temp_gdt();
        assert_eq!(gdt.len(), 4);
        assert_eq!(gdt[0], 0, "slot 0 is null");
        assert_eq!(
            gdt[1], 0x00CF_9A00_0000_FFFF,
            "slot 1: 32-bit code (flat, G=1, D=1, P=1, S=1, Type=A)"
        );
        assert_eq!(
            gdt[2], 0x00CF_9200_0000_FFFF,
            "slot 2: 32-bit data (flat, G=1, D=1, P=1, S=1, Type=2)"
        );
        assert_eq!(
            gdt[3], 0x00AF_9A00_0000_FFFF,
            "slot 3: 64-bit code (flat, G=1, L=1, D=0, P=1, S=1, Type=A)"
        );
    }

    #[test]
    fn gdt_32bit_code_descriptor_decodes_correctly() {
        // SDM Vol 3A § 3.4.5: access byte at byte 5, flags byte at byte 6.
        let gdt = build_temp_gdt();
        let bytes = gdt[1].to_le_bytes();
        // Limit[15:0]
        assert_eq!(bytes[0], 0xFF);
        assert_eq!(bytes[1], 0xFF);
        // Base[23:0] all zero
        assert_eq!(bytes[2], 0x00);
        assert_eq!(bytes[3], 0x00);
        assert_eq!(bytes[4], 0x00);
        // Access: P=1 DPL=00 S=1 Type=1010 → 1001_1010 = 0x9A
        assert_eq!(bytes[5], 0x9A);
        // Flags|Limit[19:16]: G=1 D/B=1 L=0 AVL=0 + LimitHi=0xF → 1100_1111 = 0xCF
        assert_eq!(bytes[6], 0xCF);
        // Base[31:24]
        assert_eq!(bytes[7], 0x00);
    }

    #[test]
    fn gdt_64bit_code_descriptor_has_long_mode_flag() {
        let gdt = build_temp_gdt();
        let bytes = gdt[3].to_le_bytes();
        // Flags byte: G=1 D/B=0 L=1 AVL=0 + LimitHi=0xF → 1010_1111 = 0xAF
        assert_eq!(bytes[6], 0xAF, "L=1 (long mode), D/B=0 (per SDM)");
    }

    #[test]
    fn gdtr_pseudo_desc_packs_limit_and_base() {
        let gdtr = build_temp_gdtr(0x0000_8070);
        // Limit = 32-1 = 31 = 0x001F
        assert_eq!(gdtr[0], 0x1F);
        assert_eq!(gdtr[1], 0x00);
        // Base = 0x0000_8070 LE
        assert_eq!(gdtr[2], 0x70);
        assert_eq!(gdtr[3], 0x80);
        assert_eq!(gdtr[4], 0x00);
        assert_eq!(gdtr[5], 0x00);
    }

    // ------------------- Embedded GDT inside the blob ---------------

    #[test]
    fn blob_embeds_gdt_at_documented_offset() {
        let b = build_trampoline_blob(BASE, TEMP_PML4, KERNEL_AP_ENTRY);
        let gdt = build_temp_gdt();
        for (i, expected) in gdt.iter().enumerate() {
            let bytes = expected.to_le_bytes();
            let off = TRAMPOLINE_OFFSET_GDT + i * 8;
            assert_eq!(&b[off..off + 8], &bytes, "GDT slot {i} mismatch");
        }
    }

    #[test]
    fn blob_embeds_gdtr_at_documented_offset() {
        let b = build_trampoline_blob(BASE, TEMP_PML4, KERNEL_AP_ENTRY);
        let gdt_base = BASE + TRAMPOLINE_OFFSET_GDT as u32;
        let gdtr = build_temp_gdtr(gdt_base);
        for (i, expected) in gdtr.iter().enumerate() {
            assert_eq!(
                b[TRAMPOLINE_OFFSET_GDTR + i],
                *expected,
                "GDTR byte {i} mismatch"
            );
        }
    }

    // ------------------- Page-table entry layout --------------------

    #[test]
    fn pml4_entry_sets_present_and_writable_and_carries_frame() {
        let pdpt = 0x0000_0000_0009_3000_u64;
        let e = pml4_entry_pdpt(pdpt);
        assert_eq!(e & 1, 1, "P bit set");
        assert_eq!(e & 0b10, 0b10, "R/W bit set");
        assert_eq!(e & 0x000F_FFFF_FFFF_F000, pdpt, "frame stored at 51:12");
        // PS bit must be 0 — PML4 entries do not support PS.
        assert_eq!(e & 0x80, 0, "PS=0 in PML4 entry");
    }

    #[test]
    fn pml4_entry_masks_low_12_bits_of_input() {
        let e = pml4_entry_pdpt(0x0000_0000_0009_3FFF);
        // Low 12 bits of input are discarded — only flags survive.
        assert_eq!(
            e & 0x000F_FFFF_FFFF_F000,
            0x0000_0000_0009_3000,
            "unaligned input must be masked to 4 KiB boundary"
        );
    }

    #[test]
    fn pdpt_entry_pd_has_ps_clear() {
        let e = pdpt_entry_pd(0x0000_0000_000A_4000);
        assert_eq!(e & 0x80, 0, "PS=0 when pointing at a PD");
        assert_eq!(e & 1, 1, "P set");
        assert_eq!(e & 0b10, 0b10, "R/W set");
    }

    #[test]
    fn pd_entry_2mib_sets_ps_and_carries_2mib_frame() {
        let e = pd_entry_2mib(0x0000_0000_0040_0000);
        assert_eq!(e & 1, 1, "P set");
        assert_eq!(e & 0b10, 0b10, "R/W set");
        assert_eq!(e & 0x80, 0x80, "PS=1 (2 MiB page)");
        assert_eq!(
            e & 0x000F_FFFF_FFE0_0000,
            0x0000_0000_0040_0000,
            "2 MiB-aligned frame stored at 51:21"
        );
    }

    #[test]
    fn pd_entry_2mib_masks_low_21_bits_of_input() {
        let e = pd_entry_2mib(0x0000_0000_0040_FFFF);
        assert_eq!(
            e & 0x000F_FFFF_FFE0_0000,
            0x0000_0000_0040_0000,
            "unaligned input must be masked to 2 MiB boundary"
        );
    }

    // ------------------- Composed identity-mapping ------------------

    #[test]
    fn identity_paging_links_pml4_pdpt_pd_in_order() {
        let pdpt_paddr = 0x0000_0000_0009_1000;
        let pd_paddr = 0x0000_0000_0009_2000;
        let p = build_temp_identity_paging(pdpt_paddr, pd_paddr);

        // PML4[0] points at the PDPT.
        assert_eq!(p.pml4[0] & 0x000F_FFFF_FFFF_F000, pdpt_paddr);
        // PDPT[0] points at the PD.
        assert_eq!(p.pdpt[0] & 0x000F_FFFF_FFFF_F000, pd_paddr);
        // PD[0] maps physical 0..2 MiB as a single 2 MiB page.
        assert_eq!(p.pd[0] & 0x000F_FFFF_FFE0_0000, 0);
        assert_eq!(p.pd[0] & 0x80, 0x80, "PS=1");
    }

    #[test]
    fn identity_paging_zeroes_all_other_entries() {
        let p = build_temp_identity_paging(0x0009_1000, 0x0009_2000);
        for i in 1..512 {
            assert_eq!(p.pml4[i], 0, "PML4[{i}] must be 0");
            assert_eq!(p.pdpt[i], 0, "PDPT[{i}] must be 0");
            assert_eq!(p.pd[i], 0, "PD[{i}] must be 0");
        }
    }

    // ------------------- Constants invariants -----------------------

    #[test]
    fn blob_size_is_one_page_or_less() {
        const _BLOB_FITS_IN_PAGE: () = assert!(TRAMPOLINE_BLOB_SIZE <= 4096);
        // Final blob byte is within the array.
        let b = build_trampoline_blob(BASE, TEMP_PML4, KERNEL_AP_ENTRY);
        assert_eq!(b.len(), TRAMPOLINE_BLOB_SIZE);
    }

    #[test]
    fn section_offsets_are_monotonically_increasing() {
        // Compile-time invariants: each comparison folds to `true`, so we
        // surface a build-break (not a runtime assertion) if a future
        // refactor invalidates the layout.
        const _RM16_BEFORE_PM32: () = assert!(TRAMPOLINE_OFFSET_RM16 < TRAMPOLINE_OFFSET_PM32);
        const _PM32_BEFORE_LM64: () = assert!(TRAMPOLINE_OFFSET_PM32 < TRAMPOLINE_OFFSET_LM64);
        const _LM64_BEFORE_GDT: () = assert!(TRAMPOLINE_OFFSET_LM64 < TRAMPOLINE_OFFSET_GDT);
        const _GDT_BEFORE_GDTR: () = assert!(TRAMPOLINE_OFFSET_GDT < TRAMPOLINE_OFFSET_GDTR);
        const _GDT_FITS_BEFORE_GDTR: () =
            assert!(TRAMPOLINE_OFFSET_GDT + TRAMPOLINE_GDT_SIZE <= TRAMPOLINE_OFFSET_GDTR);
        const _GDTR_FITS_IN_BLOB: () =
            assert!(TRAMPOLINE_OFFSET_GDTR + TRAMPOLINE_GDTR_SIZE <= TRAMPOLINE_BLOB_SIZE);
    }

    #[test]
    fn selectors_match_gdt_slot_indices() {
        assert_eq!(TRAMPOLINE_SEL_CODE32 as usize, 8);
        assert_eq!(TRAMPOLINE_SEL_DATA32 as usize, 16);
        assert_eq!(TRAMPOLINE_SEL_CODE64 as usize, 24);
    }
}
