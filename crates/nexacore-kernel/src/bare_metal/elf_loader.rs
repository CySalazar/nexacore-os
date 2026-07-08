//! ELF64 loader — minimal parser + segment mapper (Track B, MB5).
//!
//! Parses a statically-linked ELF64 binary (`ET_EXEC` or `ET_DYN`,
//! `EM_X86_64`, little-endian) and maps its `PT_LOAD` segments into the
//! active page tables via [`super::paging::PageMapper`].
//!
//! ## Scope
//!
//! - [`Elf64::parse`] validates the ELF header and program-header table
//!   without copying any data.
//! - [`Elf64::load_segments`] yields a [`LoadSegment`] for every `PT_LOAD`
//!   entry; the caller decides whether to map or inspect the segment.
//! - `Elf64::map_and_load` allocates physical frames, maps each segment
//!   into the page tables, and copies the segment's file image; BSS
//!   (memsz > filesz) is zeroed.
//!
//! ## Portability
//!
//! The parser (`parse`, `load_segments`, `entry_point`) compiles on every
//! target so that host-side unit tests run on the developer machine.
//! `map_and_load` is gated `#[cfg(target_arch = "x86_64")]` because it
//! calls into the x86_64-only `PageMapper` and `BitmapFrameAllocator`.

#![allow(
    unsafe_code,
    reason = "ELF segment loader copies file bytes via raw ptr::copy_nonoverlapping"
)]
#![allow(
    clippy::integer_division,
    reason = "ELF page math uses 4 KiB byte-aligned truncation by design"
)]
#![allow(
    clippy::indexing_slicing,
    clippy::doc_markdown,
    reason = "byte-offset slicing has explicit bounds check; ELF acronyms in prose"
)]

// ---------------------------------------------------------------------------
// ELF constants
// ---------------------------------------------------------------------------

const ELF_MAGIC: [u8; 4] = [0x7f, b'E', b'L', b'F'];
const ELFCLASS64: u8 = 2;
const ELFDATA2LSB: u8 = 1;
const ET_EXEC: u16 = 2;
const ET_DYN: u16 = 3;
const EM_X86_64: u16 = 62;
const PT_LOAD: u32 = 1;

/// ELF segment flag: executable.
pub const PF_X: u32 = 1;
/// ELF segment flag: writable.
pub const PF_W: u32 = 2;
/// ELF segment flag: readable.
pub const PF_R: u32 = 4;

// ---------------------------------------------------------------------------
// Private read helpers
// ---------------------------------------------------------------------------

#[inline]
fn r_u16(data: &[u8], off: usize) -> Option<u16> {
    u16::from_le_bytes(data.get(off..off + 2)?.try_into().ok()?).into()
}

#[inline]
fn r_u32(data: &[u8], off: usize) -> Option<u32> {
    u32::from_le_bytes(data.get(off..off + 4)?.try_into().ok()?).into()
}

#[inline]
fn r_u64(data: &[u8], off: usize) -> Option<u64> {
    u64::from_le_bytes(data.get(off..off + 8)?.try_into().ok()?).into()
}

/// Compute, for page `page_i` of a PT_LOAD segment, where the file-backed
/// bytes land inside that 4 KiB page and which slice of `file_data` to copy.
///
/// Returns `(dst_off, file_start, copy_len)`:
/// - `dst_off`   — byte offset *within the page* where the copy begins. Non-zero
///   only on the first page of a non-page-aligned segment (`page_intra != 0`),
///   where the segment does not start at the page boundary; the leading
///   `page_intra` bytes precede the segment and must stay zero.
/// - `file_start`— offset into `file_data` to copy from.
/// - `copy_len`  — number of bytes to copy (clamped to both the page tail and
///   the remaining file data; `0` once the file portion is exhausted, leaving
///   the page fully zero-filled for BSS).
///
/// Invariants (relied on by the unsafe copy in `map_and_load_into`):
/// `dst_off + copy_len <= 4096` and `file_start + copy_len <= file_len`.
///
/// The historical bug this fixes: the previous code used
/// `(page_i * 4096).saturating_sub(page_intra)` as the *file* start AND wrote
/// at page offset 0, so the first page of a segment whose `p_vaddr` is not
/// page-aligned had its bytes shifted left by `page_intra` — corrupting every
/// address in the segment (entry point included). It went unnoticed until the
/// virtio-net driver image became the first binary whose `_start` sat at
/// `file_data[0]` of such a segment.
fn page_copy_plan(page_intra: usize, file_len: usize, page_i: usize) -> (usize, usize, usize) {
    if page_i == 0 {
        // First page: segment begins at `page_intra` within the page.
        let dst_off = page_intra;
        let avail_in_page = 4096 - dst_off;
        let copy_len = file_len.min(avail_in_page);
        (dst_off, 0, copy_len)
    } else {
        // Subsequent pages: file offset accounts for the first page only
        // carrying `4096 - page_intra` bytes of the segment.
        let file_start = page_i * 4096 - page_intra;
        if file_start >= file_len {
            return (0, file_len, 0);
        }
        let copy_len = (file_len - file_start).min(4096);
        (0, file_start, copy_len)
    }
}

// ---------------------------------------------------------------------------
// ElfError
// ---------------------------------------------------------------------------

/// Errors returned by the ELF64 loader.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ElfError {
    /// Binary is too short to contain a valid ELF64 header.
    TooShort,
    /// Magic bytes `0x7fELF` not found.
    BadMagic,
    /// `EI_CLASS` is not `ELFCLASS64` (2).
    NotElf64,
    /// `EI_DATA` is not `ELFDATA2LSB` (1).
    NotLittleEndian,
    /// `e_machine` is not `EM_X86_64` (62).
    UnsupportedMachine,
    /// `e_type` is neither `ET_EXEC` (2) nor `ET_DYN` (3).
    UnsupportedType,
    /// Program-header table is absent, too small, or out of bounds.
    BadPhdrs,
    /// Frame allocator could not provide a physical frame.
    OutOfFrames,
    /// `PageMapper::map_4k` refused the mapping (already mapped or OOM).
    MappingFailed,
    /// A `PT_LOAD` segment's mapped range overflows the address space or is
    /// not wholly within the canonical user half (`< USER_HALF_END`).
    ///
    /// Rejecting this prevents a crafted (or buggy) ELF from mapping
    /// user-flagged pages into the shared kernel half via an out-of-range or
    /// overflowing `p_vaddr` (`NCIP-Kernel-Sec-026` §S3.1 / risk R8).
    SegmentOutOfBounds,
}

// ---------------------------------------------------------------------------
// LoadSegment
// ---------------------------------------------------------------------------

/// A single `PT_LOAD` segment ready to be mapped into the address space.
#[derive(Debug, Clone, Copy)]
pub struct LoadSegment<'a> {
    /// Virtual address of the first byte of this segment.
    pub virt_addr: u64,
    /// Slice of the ELF binary that contains the file image for this segment.
    pub file_data: &'a [u8],
    /// Size of the segment in memory (may be larger than `file_data.len()`).
    pub mem_size: usize,
    /// ELF segment flags (`PF_R`, `PF_W`, `PF_X`).
    pub flags: u32,
}

// ---------------------------------------------------------------------------
// SegIter — private iterator over PT_LOAD entries
// ---------------------------------------------------------------------------

struct SegIter<'a> {
    data: &'a [u8],
    phoff: usize,
    phentsize: usize,
    phnum: usize,
    idx: usize,
}

impl<'a> Iterator for SegIter<'a> {
    type Item = Result<LoadSegment<'a>, ElfError>;

    #[allow(
        clippy::cast_possible_truncation,
        reason = "ELF offsets/sizes fit usize on supported platforms"
    )]
    fn next(&mut self) -> Option<Self::Item> {
        loop {
            if self.idx >= self.phnum {
                return None;
            }
            let i = self.idx;
            self.idx += 1;

            let base = self.phoff + i * self.phentsize;
            let data = self.data;

            let Some(p_type) = r_u32(data, base) else {
                return Some(Err(ElfError::BadPhdrs));
            };
            if p_type != PT_LOAD {
                continue;
            }

            let Some(p_flags) = r_u32(data, base + 4) else {
                return Some(Err(ElfError::BadPhdrs));
            };
            let Some(p_offset_raw) = r_u64(data, base + 8) else {
                return Some(Err(ElfError::BadPhdrs));
            };
            let Some(p_vaddr) = r_u64(data, base + 16) else {
                return Some(Err(ElfError::BadPhdrs));
            };
            let Some(p_filesz_raw) = r_u64(data, base + 32) else {
                return Some(Err(ElfError::BadPhdrs));
            };
            let Some(p_memsz_raw) = r_u64(data, base + 40) else {
                return Some(Err(ElfError::BadPhdrs));
            };

            let p_offset = p_offset_raw as usize;
            let p_filesz = p_filesz_raw as usize;
            let p_memsz = p_memsz_raw as usize;

            let Some(file_data) = data.get(p_offset..p_offset + p_filesz) else {
                return Some(Err(ElfError::BadPhdrs));
            };

            return Some(Ok(LoadSegment {
                virt_addr: p_vaddr,
                file_data,
                mem_size: p_memsz,
                flags: p_flags,
            }));
        }
    }
}

// ---------------------------------------------------------------------------
// Elf64
// ---------------------------------------------------------------------------

/// A parsed ELF64 binary.
///
/// Holds a reference to the raw bytes; no allocation occurs during parsing.
#[derive(Debug, PartialEq, Eq)]
pub struct Elf64<'a> {
    data: &'a [u8],
    entry: u64,
    e_type: u16,
    phoff: usize,
    phentsize: usize,
    phnum: usize,
}

impl<'a> Elf64<'a> {
    /// Parse an ELF64 binary and validate its header.
    ///
    /// # Errors
    ///
    /// Returns [`ElfError`] if the binary is malformed, too short, or
    /// targets an unsupported architecture or type.
    #[allow(
        clippy::cast_possible_truncation,
        reason = "phoff/phentsize/phnum fit usize on supported platforms"
    )]
    pub fn parse(data: &'a [u8]) -> Result<Self, ElfError> {
        if data.len() < 64 {
            return Err(ElfError::TooShort);
        }
        // SAFETY: len >= 64 was checked above; these accesses are all within bounds.
        if data.get(0..4) != Some(&ELF_MAGIC[..]) {
            return Err(ElfError::BadMagic);
        }
        if data.get(4).copied() != Some(ELFCLASS64) {
            return Err(ElfError::NotElf64);
        }
        if data.get(5).copied() != Some(ELFDATA2LSB) {
            return Err(ElfError::NotLittleEndian);
        }

        let e_type = r_u16(data, 16).ok_or(ElfError::TooShort)?;
        if e_type != ET_EXEC && e_type != ET_DYN {
            return Err(ElfError::UnsupportedType);
        }

        let e_machine = r_u16(data, 18).ok_or(ElfError::TooShort)?;
        if e_machine != EM_X86_64 {
            return Err(ElfError::UnsupportedMachine);
        }

        let entry = r_u64(data, 24).ok_or(ElfError::TooShort)?;
        let phoff = r_u64(data, 32).ok_or(ElfError::TooShort)? as usize;
        let phentsize = r_u16(data, 54).ok_or(ElfError::TooShort)? as usize;
        let phnum = r_u16(data, 56).ok_or(ElfError::TooShort)? as usize;

        if phentsize < 56 || phoff == 0 || phnum == 0 {
            return Err(ElfError::BadPhdrs);
        }
        if data.len() < phoff + phnum * phentsize {
            return Err(ElfError::TooShort);
        }

        Ok(Self {
            data,
            entry,
            e_type,
            phoff,
            phentsize,
            phnum,
        })
    }

    /// Returns the virtual entry-point address from the ELF header,
    /// adjusted for the load bias when the ELF is a PIE (`ET_DYN`).
    #[inline]
    #[must_use]
    pub fn entry_point(&self) -> u64 {
        self.entry + self.load_bias()
    }

    /// Load bias applied to PIE (`ET_DYN`) executables.
    ///
    /// `ET_EXEC` binaries have absolute addresses and no bias.
    /// `ET_DYN` binaries have relative addresses starting near zero;
    /// the kernel maps them at this fixed base address.
    #[inline]
    #[must_use]
    pub fn load_bias(&self) -> u64 {
        if self.e_type == ET_DYN { 0x40_0000 } else { 0 }
    }

    /// Returns an iterator over the `PT_LOAD` program-header entries.
    pub fn load_segments(&self) -> impl Iterator<Item = Result<LoadSegment<'a>, ElfError>> + 'a {
        SegIter {
            data: self.data,
            phoff: self.phoff,
            phentsize: self.phentsize,
            phnum: self.phnum,
            idx: 0,
        }
    }

    /// Allocate physical frames, map each `PT_LOAD` segment, and copy the
    /// file image. BSS bytes (`memsz > filesz`) are zeroed. Maps into the
    /// active address space (`mapper.root_phys`).
    ///
    /// Returns the entry-point virtual address on success.
    ///
    /// # Errors
    ///
    /// Returns [`ElfError::OutOfFrames`] if the frame allocator is exhausted,
    /// or [`ElfError::MappingFailed`] if a page is already mapped.
    ///
    /// `phys_offset` must equal `BootInfo.physical_memory_offset` — the
    /// virtual base of the bootloader's direct physical-memory window.
    #[cfg(target_arch = "x86_64")]
    pub fn map_and_load<const N: usize>(
        &self,
        mapper: &mut super::paging::PageMapper,
        alloc: &mut crate::memory::BitmapFrameAllocator<N>,
        phys_offset: u64,
    ) -> Result<u64, ElfError> {
        let root = mapper.root_phys;
        self.map_and_load_into(root, mapper, alloc, phys_offset)
    }

    /// Variant of [`Self::map_and_load`] that maps into an explicit
    /// page-table root (e.g. a per-process PML4 owned by an
    /// [`super::address_space::AddressSpace`]).
    ///
    /// MB11: required to load a user ELF into a per-process CR3 without
    /// mutating the live `mapper.root_phys`.
    ///
    /// # Errors
    ///
    /// Same as [`Self::map_and_load`].
    #[cfg(target_arch = "x86_64")]
    pub fn map_and_load_into<const N: usize>(
        &self,
        root_phys: crate::memory::PhysAddr,
        mapper: &mut super::paging::PageMapper,
        alloc: &mut crate::memory::BitmapFrameAllocator<N>,
        phys_offset: u64,
    ) -> Result<u64, ElfError> {
        use core::ptr;

        let bias = self.load_bias();

        for seg_result in self.load_segments() {
            let seg = seg_result?;

            // Validate the segment's mapped range with checked arithmetic
            // BEFORE touching the page tables (NCIP-Kernel-Sec-026 §S3.1, risks
            // R8/R3-enabler). A bias/p_vaddr that overflows, or a range that
            // is not wholly within the user half, is rejected — otherwise an
            // ET_EXEC `p_vaddr` in the kernel half would map user-flagged
            // pages into shared kernel page-table entries.
            let Some((page_base, page_intra, num_pages)) =
                validate_segment_span(seg.virt_addr, bias, seg.mem_size)?
            else {
                // Degenerate empty PT_LOAD: nothing to map.
                continue;
            };

            for page_i in 0..num_pages {
                let virt = crate::memory::VirtAddr(page_base + page_i as u64 * 4096);
                let frame = alloc.alloc_frame().ok_or(ElfError::OutOfFrames)?;

                if !mapper.map_4k_into(root_phys, virt, frame, pte_flags(seg.flags), alloc) {
                    return Err(ElfError::MappingFailed);
                }

                // SAFETY: frame.0 + phys_offset is within the bootloader's
                // direct-mapped physical window; the frame was just allocated
                // and is not aliased elsewhere.
                let dst = (frame.0 + phys_offset) as *mut u8;

                // Where the file-backed bytes land *within this page*. For the
                // first page of a non-page-aligned segment (`page_intra != 0`)
                // the segment does not start at the page boundary, so the file
                // data must be written at offset `page_intra`, not 0 — the
                // leading `page_intra` bytes precede the segment and stay zero.
                let (dst_off, file_start, copy_len) =
                    page_copy_plan(page_intra, seg.file_data.len(), page_i);

                // SAFETY: dst points at a freshly-allocated, unaliased 4 KiB
                // frame via the direct map. `page_copy_plan` guarantees
                // `dst_off + copy_len <= 4096` and `file_start + copy_len <=
                // file_data.len()`, so both the zero-fill and the copy stay in
                // bounds of the page and the source slice respectively.
                unsafe {
                    // Leading gap before the segment start (first page only).
                    if dst_off > 0 {
                        ptr::write_bytes(dst, 0, dst_off);
                    }
                    if copy_len > 0 {
                        ptr::copy_nonoverlapping(
                            seg.file_data[file_start..].as_ptr(),
                            dst.add(dst_off),
                            copy_len,
                        );
                    }
                    // Trailing zero-fill: BSS and any partial final page.
                    let written = dst_off + copy_len;
                    if written < 4096 {
                        ptr::write_bytes(dst.add(written), 0, 4096 - written);
                    }
                }
            }
        }

        // Process R_X86_64_RELATIVE relocations for PIE (ET_DYN) binaries.
        // Each entry in the RELA table stores an offset where the load bias
        // must be added to the stored value. Without this step, GOT entries
        // and other absolute references resolve to addresses near zero,
        // causing immediate page faults.
        if bias != 0 {
            self.apply_relative_relocs(root_phys, mapper, bias, phys_offset);
        }

        Ok(self.entry + bias)
    }

    /// Scan the ELF for PT_DYNAMIC, find the RELA table, and process all
    /// `R_X86_64_RELATIVE` entries by adding `bias` to the stored addend.
    #[cfg(target_arch = "x86_64")]
    fn apply_relative_relocs(
        &self,
        root_phys: crate::memory::PhysAddr,
        mapper: &super::paging::PageMapper,
        bias: u64,
        phys_offset: u64,
    ) {
        const PT_DYNAMIC: u32 = 2;
        const DT_RELA: u64 = 7;
        const DT_RELASZ: u64 = 8;
        const R_X86_64_RELATIVE: u32 = 8;

        // Find PT_DYNAMIC segment.
        let mut dyn_offset = 0usize;
        let mut dyn_size = 0usize;
        for i in 0..self.phnum {
            let base = self.phoff + i * self.phentsize;
            if let Some(p_type) = r_u32(self.data, base) {
                if p_type == PT_DYNAMIC {
                    // justification: bare-metal x86_64 only; usize == u64.
                    // On any 32-bit host the cast may truncate but this code is
                    // gated to target_arch = "x86_64" via the module cfg.
                    #[allow(clippy::cast_possible_truncation)]
                    {
                        dyn_offset = r_u64(self.data, base + 8).unwrap_or(0) as usize;
                        dyn_size = r_u64(self.data, base + 32).unwrap_or(0) as usize;
                    }
                    break;
                }
            }
        }
        if dyn_offset == 0 || dyn_size == 0 {
            return;
        }

        // Parse DYNAMIC entries to find RELA offset and size.
        let mut rela_off = 0u64;
        let mut rela_sz = 0u64;
        let mut pos = dyn_offset;
        while pos + 16 <= dyn_offset + dyn_size {
            let tag = r_u64(self.data, pos).unwrap_or(0);
            let val = r_u64(self.data, pos + 8).unwrap_or(0);
            if tag == 0 {
                break;
            } // DT_NULL
            if tag == DT_RELA {
                rela_off = val;
            }
            if tag == DT_RELASZ {
                rela_sz = val;
            }
            pos += 16;
        }
        if rela_off == 0 || rela_sz == 0 {
            return;
        }

        // The RELA entries are at file offset = rela_off (for PIE, this
        // is the same as the virt_addr since the base is 0).
        // justification: bare-metal x86_64 only; usize == u64.
        #[allow(clippy::cast_possible_truncation)]
        let rela_file_off = rela_off as usize;
        #[allow(clippy::cast_possible_truncation)]
        let num_entries = rela_sz as usize / 24;

        for i in 0..num_entries {
            let ent_off = rela_file_off + i * 24;
            let Some(r_offset) = r_u64(self.data, ent_off) else {
                continue;
            };
            let Some(r_info) = r_u64(self.data, ent_off + 8) else {
                continue;
            };
            let Some(r_addend) = r_u64(self.data, ent_off + 16) else {
                continue;
            };

            let r_type = (r_info & 0xFFFF_FFFF) as u32;
            if r_type != R_X86_64_RELATIVE {
                continue;
            }

            // Write (bias + addend) at virtual address (bias + r_offset).
            let target_va = bias + r_offset;
            let value = bias + r_addend;

            // Translate VA → physical via the page table we just built.
            if let Some(phys) = mapper.translate_in(root_phys, crate::memory::VirtAddr(target_va)) {
                let dst = (phys.0 + phys_offset) as *mut u64;
                // SAFETY: the page was just mapped and allocated by us;
                // writing the relocation value is required for the binary
                // to function correctly at the biased address.
                unsafe {
                    core::ptr::write(dst, value);
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// pte_flags — private
// ---------------------------------------------------------------------------

/// Converts ELF segment flags to x86_64 PTE flags.
///
/// Enforces **W^X** per `NCIP-Kernel-Sec-026` §S3.1 (risk R3): a segment is
/// mapped executable only when it carries `PF_X`. A non-executable segment —
/// in particular a writable data/BSS segment (`PF_W` without `PF_X`) — gets
/// `PTE_NO_EXEC`, so user-writable memory is never executable and a single
/// memory-write bug cannot be turned into code injection. Before this, the
/// loader ignored `PF_X` entirely and mapped every user page executable,
/// making writable segments RWX.
#[cfg(target_arch = "x86_64")]
fn pte_flags(elf_flags: u32) -> u64 {
    use super::paging::{PTE_NO_EXEC, PTE_PRESENT, PTE_USER, PTE_WRITABLE};
    let mut f = PTE_PRESENT | PTE_USER;
    if elf_flags & PF_W != 0 {
        f |= PTE_WRITABLE;
    }
    if elf_flags & PF_X == 0 {
        f |= PTE_NO_EXEC;
    }
    f
}

/// Validate and compute the page span of a `PT_LOAD` segment
/// (`NCIP-Kernel-Sec-026` §S3.1, risks R8 / R3-enabler).
///
/// All address arithmetic is checked. Returns:
/// - `Ok(None)` for a degenerate empty (zero-page) segment — nothing to map;
/// - `Ok(Some((page_base, page_intra, num_pages)))` for a valid segment whose
///   entire `[page_base, page_base + num_pages*4096)` span lies within the
///   canonical user half (`< USER_HALF_END`);
/// - `Err(SegmentOutOfBounds)` if the math overflows or the span reaches the
///   kernel half.
///
/// Pure (no I/O) so the bound logic is unit-testable without a page mapper.
#[cfg(target_arch = "x86_64")]
fn validate_segment_span(
    virt_addr: u64,
    bias: u64,
    mem_size: usize,
) -> Result<Option<(u64, usize, usize)>, ElfError> {
    let seg_start = virt_addr
        .checked_add(bias)
        .ok_or(ElfError::SegmentOutOfBounds)?;
    let page_base = seg_start & !0xFFF;
    let page_intra = (virt_addr & 0xFFF) as usize;
    let total_mem = page_intra
        .checked_add(mem_size)
        .ok_or(ElfError::SegmentOutOfBounds)?;
    let num_pages = total_mem.div_ceil(4096);
    if num_pages == 0 {
        return Ok(None);
    }
    let span_bytes = u64::try_from(num_pages)
        .ok()
        .and_then(|n| n.checked_mul(4096))
        .ok_or(ElfError::SegmentOutOfBounds)?;
    let seg_end = page_base
        .checked_add(span_bytes)
        .ok_or(ElfError::SegmentOutOfBounds)?;
    if seg_end > super::usermode::USER_HALF_END {
        return Err(ElfError::SegmentOutOfBounds);
    }
    Ok(Some((page_base, page_intra, num_pages)))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// A 120-byte hand-crafted ELF64 binary: ET_EXEC, EM_X86_64,
    /// one PT_LOAD segment at 0x4000_0000, entry=0x4000_0000,
    /// filesz=120, memsz=4096.
    const TEST_ELF: [u8; 120] = [
        // e_ident[16]: magic + class64 + LSB + version + sysv + padding
        0x7f, b'E', b'L', b'F', 2, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        // e_type=ET_EXEC, e_machine=EM_X86_64
        0x02, 0x00, 0x3E, 0x00, // e_version=1
        0x01, 0x00, 0x00, 0x00, // e_entry=0x4000_0000
        0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00, // e_phoff=64
        0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // e_shoff=0
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // e_flags=0
        0x00, 0x00, 0x00, 0x00, // e_ehsize=64, e_phentsize=56, e_phnum=1
        0x40, 0x00, 0x38, 0x00, 0x01, 0x00, // e_shentsize=64, e_shnum=0, e_shstrndx=0
        0x40, 0x00, 0x00, 0x00, 0x00, 0x00,
        // Program header at offset 64:
        // p_type=PT_LOAD
        0x01, 0x00, 0x00, 0x00, // p_flags=PF_R|PF_X=5
        0x05, 0x00, 0x00, 0x00, // p_offset=0
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // p_vaddr=0x4000_0000
        0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00,
        // p_paddr=0x4000_0000 (not used by loader)
        0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00, // p_filesz=120
        0x78, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // p_memsz=4096
        0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // p_align=4096
        0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];

    #[test]
    fn parse_valid_elf_succeeds() {
        assert!(Elf64::parse(&TEST_ELF).is_ok());
    }

    #[test]
    fn entry_point_is_correct() {
        let elf = Elf64::parse(&TEST_ELF).unwrap();
        assert_eq!(elf.entry_point(), 0x4000_0000);
    }

    #[test]
    #[allow(clippy::indexing_slicing, reason = "segs.len() == 1 asserted above")]
    fn one_load_segment_found() {
        let elf = Elf64::parse(&TEST_ELF).unwrap();
        let segs: Vec<_> = elf.load_segments().collect();
        assert_eq!(segs.len(), 1);
        assert!(segs[0].is_ok());
    }

    #[test]
    fn segment_virt_addr_correct() {
        let elf = Elf64::parse(&TEST_ELF).unwrap();
        let seg = elf.load_segments().next().unwrap().unwrap();
        assert_eq!(seg.virt_addr, 0x4000_0000);
    }

    #[test]
    fn segment_file_data_has_correct_length() {
        let elf = Elf64::parse(&TEST_ELF).unwrap();
        let seg = elf.load_segments().next().unwrap().unwrap();
        assert_eq!(seg.file_data.len(), 120);
    }

    #[test]
    fn segment_mem_size_is_one_page() {
        let elf = Elf64::parse(&TEST_ELF).unwrap();
        let seg = elf.load_segments().next().unwrap().unwrap();
        assert_eq!(seg.mem_size, 4096);
    }

    #[test]
    fn segment_flags_rx() {
        let elf = Elf64::parse(&TEST_ELF).unwrap();
        let seg = elf.load_segments().next().unwrap().unwrap();
        assert_eq!(seg.flags, PF_R | PF_X);
    }

    #[test]
    fn reject_bad_magic() {
        let mut buf = TEST_ELF;
        buf[0] = 0x00;
        assert_eq!(Elf64::parse(&buf), Err(ElfError::BadMagic));
    }

    #[test]
    fn reject_not_64bit() {
        let mut buf = TEST_ELF;
        buf[4] = 1; // ELFCLASS32
        assert_eq!(Elf64::parse(&buf), Err(ElfError::NotElf64));
    }

    #[test]
    fn reject_big_endian() {
        let mut buf = TEST_ELF;
        buf[5] = 2; // ELFDATA2MSB
        assert_eq!(Elf64::parse(&buf), Err(ElfError::NotLittleEndian));
    }

    #[test]
    fn reject_not_x86_64() {
        let mut buf = TEST_ELF;
        // e_machine at offset 18: set to 3 (EM_386)
        buf[18] = 3;
        buf[19] = 0;
        assert_eq!(Elf64::parse(&buf), Err(ElfError::UnsupportedMachine));
    }

    #[test]
    fn reject_too_short() {
        assert_eq!(Elf64::parse(&TEST_ELF[..10]), Err(ElfError::TooShort));
    }

    // -- page_copy_plan: segment placement within pages (regression guard) ----

    #[test]
    fn page_copy_plan_aligned_first_page_starts_at_zero() {
        // page-aligned segment (page_intra = 0), file larger than a page:
        // first page copies a full 4096 bytes at offset 0.
        assert_eq!(page_copy_plan(0, 0x1800, 0), (0, 0, 4096));
    }

    #[test]
    fn page_copy_plan_unaligned_first_page_offsets_by_page_intra() {
        // REGRESSION: a segment whose p_vaddr is not page-aligned
        // (page_intra = 0x2c0, matching the virtio-net driver image's exec
        // segment) must place its bytes at page offset 0x2c0 — NOT 0 — so the
        // entry point at file_data[0] lands at VA page_base + 0x2c0. The old
        // code returned dst_off = 0, shifting the whole segment left by 0x2c0.
        let (dst_off, file_start, copy_len) = page_copy_plan(0x2c0, 0x184a, 0);
        assert_eq!(
            dst_off, 0x2c0,
            "first byte must sit at page offset page_intra"
        );
        assert_eq!(file_start, 0, "first page copies from file offset 0");
        assert_eq!(copy_len, 4096 - 0x2c0, "copy is clamped to the page tail");
        // Invariants the unsafe copy relies on.
        assert!(dst_off + copy_len <= 4096);
        assert!(file_start + copy_len <= 0x184a);
    }

    #[test]
    fn page_copy_plan_unaligned_second_page_continuation() {
        // Page 1 of the same unaligned segment continues from where page 0
        // stopped: file offset = 4096 - page_intra, written at page offset 0.
        let (dst_off, file_start, copy_len) = page_copy_plan(0x2c0, 0x184a, 1);
        assert_eq!(dst_off, 0);
        assert_eq!(file_start, 4096 - 0x2c0);
        // Remaining file bytes (0xB0A) fit within the page, so copy_len is the
        // whole tail — no page clamp applies on this continuation page.
        assert_eq!(copy_len, 0x184a - (4096 - 0x2c0));
        assert!(file_start + copy_len <= 0x184a);
    }

    #[test]
    fn page_copy_plan_bss_page_is_all_zero() {
        // A page wholly beyond file_data (BSS tail) copies nothing.
        let (dst_off, _file_start, copy_len) = page_copy_plan(0, 0x10, 1);
        assert_eq!(dst_off, 0);
        assert_eq!(copy_len, 0, "BSS-only page must be fully zero-filled");
    }

    #[test]
    fn page_copy_plan_partial_final_page_clamps_to_file() {
        // Aligned segment, file ends mid-page: copy only the remaining bytes,
        // leaving the page tail for the trailing zero-fill.
        let (dst_off, file_start, copy_len) = page_copy_plan(0, 0x1010, 1);
        assert_eq!(dst_off, 0);
        assert_eq!(file_start, 4096);
        assert_eq!(copy_len, 0x1010 - 4096);
        assert!(file_start + copy_len <= 0x1010);
    }

    // --- NCIP-Kernel-Sec-026 §S3.1: W^X (R3) + segment-span validation (R8) ---

    #[test]
    fn pte_flags_exec_segment_is_executable() {
        // PF_R | PF_X (code): executable → NX bit MUST be clear.
        let f = pte_flags(PF_R | PF_X);
        assert_eq!(f & crate::bare_metal::paging::PTE_NO_EXEC, 0);
        assert_ne!(f & crate::bare_metal::paging::PTE_PRESENT, 0);
    }

    #[test]
    fn pte_flags_writable_data_segment_is_nx_not_rwx() {
        // PF_R | PF_W (data/BSS): writable + non-exec → NX set, WRITABLE set,
        // i.e. W^X holds (never RWX).
        let f = pte_flags(PF_R | PF_W);
        assert_ne!(f & crate::bare_metal::paging::PTE_NO_EXEC, 0);
        assert_ne!(f & crate::bare_metal::paging::PTE_WRITABLE, 0);
    }

    #[test]
    fn pte_flags_rodata_is_nx_and_not_writable() {
        let f = pte_flags(PF_R);
        assert_ne!(f & crate::bare_metal::paging::PTE_NO_EXEC, 0);
        assert_eq!(f & crate::bare_metal::paging::PTE_WRITABLE, 0);
    }

    #[test]
    fn segment_span_user_half_ok() {
        assert_eq!(
            validate_segment_span(0x4000_0000, 0, 4096),
            Ok(Some((0x4000_0000, 0, 1)))
        );
    }

    #[test]
    fn segment_span_unaligned_intra_spans_two_pages() {
        // vaddr 0x4000_0010, mem 4096 → crosses a page boundary (intra=0x10).
        assert_eq!(
            validate_segment_span(0x4000_0010, 0, 4096),
            Ok(Some((0x4000_0000, 0x10, 2)))
        );
    }

    #[test]
    fn segment_span_empty_is_none() {
        assert_eq!(validate_segment_span(0x4000_0000, 0, 0), Ok(None));
    }

    #[test]
    fn segment_span_kernel_half_rejected() {
        // p_vaddr at/above USER_HALF_END MUST be rejected (R8 / R3-enabler).
        let kh = crate::bare_metal::usermode::USER_HALF_END;
        assert_eq!(
            validate_segment_span(kh, 0, 4096),
            Err(ElfError::SegmentOutOfBounds)
        );
    }

    #[test]
    fn segment_span_ending_at_user_half_ok_but_crossing_rejected() {
        let last_page = crate::bare_metal::usermode::USER_HALF_END - 4096;
        // Ends exactly at USER_HALF_END → allowed.
        assert!(validate_segment_span(last_page, 0, 4096).is_ok());
        // One byte past the boundary → rejected.
        assert_eq!(
            validate_segment_span(last_page, 0, 4097),
            Err(ElfError::SegmentOutOfBounds)
        );
    }

    #[test]
    fn segment_span_bias_overflow_rejected() {
        assert_eq!(
            validate_segment_span(u64::MAX, 0x1000, 1),
            Err(ElfError::SegmentOutOfBounds)
        );
    }
}
