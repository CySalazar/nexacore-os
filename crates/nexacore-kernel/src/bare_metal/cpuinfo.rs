//! CPU identification via the `CPUID` instruction.
//!
//! Reads vendor string, processor brand string, family/model/stepping,
//! and a hand-picked subset of feature flags useful in NexaCore OS context
//! (SSE/AVX/AES/RDRAND/x2APIC). Used by the desktop demo's System Info
//! panel and (in the future) by capability gates that depend on
//! microarchitectural features.
//!
//! ## CPUID leaves consumed
//!
//! | Leaf       | Sub-leaf | Field                                |
//! |-----------:|---------:|--------------------------------------|
//! | `0x0000_0000` | —     | Max basic leaf + vendor string (EBX/EDX/ECX, 4 bytes each, concatenated) |
//! | `0x0000_0001` | —     | Family/Model/Stepping in EAX + ECX/EDX feature flags |
//! | `0x0000_0007` | `0`   | EBX/ECX/EDX extended features (AVX2, BMI1/2, …) |
//! | `0x8000_0000` | —     | Max extended leaf                       |
//! | `0x8000_0002` | —     | Brand string bytes `0..16` (EAX/EBX/ECX/EDX) |
//! | `0x8000_0003` | —     | Brand string bytes 16..32                   |
//! | `0x8000_0004` | —     | Brand string bytes 32..48                   |
//!
//! ## Why pure-function formatters
//!
//! The actual `CPUID` instruction is x86_64-only (`unsafe`); the
//! formatters that build the printable strings (`format_family_model`,
//! `format_feature_summary`) are pure data transformations and are
//! pinned by host-side `cargo test`.
//!
//! ## References
//!
//! - Intel SDM Vol 2 — `CPUID` instruction reference.
//! - AMD64 APM Vol 3 § E.3 — CPUID specification.

#![allow(
    unsafe_code,
    reason = "CPUID is an unprivileged x86_64 instruction wrapped here in a thin safe API"
)]
// Module-level relaxations:
// - `similar_names`: `eax` / `ebx` / `ecx` / `edx` are x86 register
//   mnemonics; renaming them would obscure the SDM correspondence.
// - `indexing_slicing`: every `[i]` site in this module operates on a
//   compile-time-known fixed-size array (`[u8; 12]`, `[u8; 48]`, etc.)
//   whose bounds are pinned by the host-side tests; out-of-bounds is
//   surfaced as a deterministic test failure on the dev host.
// - `many_single_char_names`: the byte-packing loops use single-letter
//   names that mirror the SDM's algebraic notation (`a`, `b`, `c`,
//   `r`, `s`); spelling them out would not improve clarity.
#![allow(
    clippy::similar_names,
    reason = "eax/ebx/ecx/edx are x86 register mnemonics; renaming obscures the SDM correspondence"
)]
#![allow(
    clippy::indexing_slicing,
    reason = "every index in this module operates on a compile-time fixed-size array bounded by host tests"
)]
#![allow(
    clippy::many_single_char_names,
    reason = "single-letter bindings mirror the SDM byte-packing algebra"
)]
#![allow(
    clippy::identity_op,
    reason = "explicit `i*16+0` keeps the byte-offset arithmetic uniform across the four CPUID dwords"
)]

use core::sync::atomic::{AtomicU32, Ordering};

// =====================================================================
// CPUID primitive
// =====================================================================

/// `CPUID` output registers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct CpuidRegs {
    /// `EAX`.
    pub eax: u32,
    /// `EBX`.
    pub ebx: u32,
    /// `ECX`.
    pub ecx: u32,
    /// `EDX`.
    pub edx: u32,
}

/// Execute `CPUID` with the given leaf and sub-leaf.
///
/// `CPUID` is unprivileged on every `x86_64` CPU since the original
/// Pentium and has no side-effects beyond clobbering the four output
/// registers. On non-x86_64 host builds the function returns a zeroed
/// [`CpuidRegs`] so callers can be tested without conditional compilation.
#[cfg(target_arch = "x86_64")]
#[must_use]
pub fn cpuid(leaf: u32, sub_leaf: u32) -> CpuidRegs {
    let mut eax: u32;
    let mut ebx: u32;
    let mut ecx: u32;
    let mut edx: u32;
    // SAFETY: CPUID is unprivileged and side-effect-free on every
    // x86_64 CPU. The inline-asm template uses preserves_flags +
    // nostack + nomem because CPUID does not touch memory or RSP and
    // its flag clobber is on Intel-only registers we do not depend
    // on (per SDM Vol 2 "CPUID — Flags Affected: None").
    unsafe {
        core::arch::asm!(
            "mov {tmp:r}, rbx",  // save rbx (LLVM reserves it as a base
            "cpuid",             //  pointer in some configurations).
            "xchg {tmp:r}, rbx",
            tmp = lateout(reg) ebx,
            inout("eax") leaf => eax,
            inout("ecx") sub_leaf => ecx,
            out("edx") edx,
            options(nomem, nostack, preserves_flags),
        );
    }
    CpuidRegs { eax, ebx, ecx, edx }
}

/// Host stub — returns zeroed regs.
#[cfg(not(target_arch = "x86_64"))]
#[must_use]
pub fn cpuid(_leaf: u32, _sub_leaf: u32) -> CpuidRegs {
    CpuidRegs::default()
}

// =====================================================================
// Vendor string (CPUID leaf 0)
// =====================================================================

/// Length of the CPU vendor string (12 ASCII bytes, no NUL terminator).
pub const VENDOR_LEN: usize = 12;

/// Read the 12-byte CPU vendor string via CPUID leaf 0.
///
/// Bytes layout (Intel SDM Vol 2 — `CPUID`):
/// - EBX bytes 0..4 → vendor[0..4]
/// - EDX bytes 0..4 → vendor[4..8]
/// - ECX bytes 0..4 → vendor[8..12]
///
/// Returns the byte sequence verbatim — typical values are
/// `b"GenuineIntel"`, `b"AuthenticAMD"`, `b"KVMKVMKVM\0\0\0"`,
/// `b"TCGTCGTCGTCG"` (QEMU TCG), `b"VMwareVMware"`, etc.
#[must_use]
pub fn vendor() -> [u8; VENDOR_LEN] {
    let r = cpuid(0, 0);
    unpack_vendor(r)
}

/// Pure function: pack `(EBX, EDX, ECX)` into the 12-byte vendor layout.
///
/// Exposed for host-side tests so the byte ordering is locked.
#[must_use]
pub fn unpack_vendor(r: CpuidRegs) -> [u8; VENDOR_LEN] {
    let mut out = [0u8; VENDOR_LEN];
    let parts = [
        r.ebx.to_le_bytes(),
        r.edx.to_le_bytes(),
        r.ecx.to_le_bytes(),
    ];
    let mut i = 0;
    while i < 3 {
        let mut j = 0;
        while j < 4 {
            out[i * 4 + j] = parts[i][j];
            j += 1;
        }
        i += 1;
    }
    out
}

// =====================================================================
// Brand string (CPUID 0x8000_0002..0x8000_0004)
// =====================================================================

/// Length of the CPU brand string (48 ASCII bytes; NUL-terminated by
/// firmware when shorter than the maximum).
pub const BRAND_LEN: usize = 48;

/// Read the 48-byte processor brand string (CPUID extended leaves
/// `0x8000_0002`..`0x8000_0004`).
///
/// Returns all-zero bytes if the CPU does not support extended leaves
/// up to `0x8000_0004`. The string is **left-padded** in CPUID output
/// (some BIOSes write the brand string with leading spaces); callers
/// that want a trimmed view should call [`trim_brand`].
#[must_use]
pub fn brand_string() -> [u8; BRAND_LEN] {
    let max_ext = cpuid(0x8000_0000, 0).eax;
    if max_ext < 0x8000_0004 {
        return [0u8; BRAND_LEN];
    }
    let a = cpuid(0x8000_0002, 0);
    let b = cpuid(0x8000_0003, 0);
    let c = cpuid(0x8000_0004, 0);
    unpack_brand(a, b, c)
}

/// Pure function: pack three CPUID outputs into the 48-byte brand
/// string layout.
#[must_use]
pub fn unpack_brand(a: CpuidRegs, b: CpuidRegs, c: CpuidRegs) -> [u8; BRAND_LEN] {
    let mut out = [0u8; BRAND_LEN];
    let parts: [[u8; 4]; 12] = [
        a.eax.to_le_bytes(),
        a.ebx.to_le_bytes(),
        a.ecx.to_le_bytes(),
        a.edx.to_le_bytes(),
        b.eax.to_le_bytes(),
        b.ebx.to_le_bytes(),
        b.ecx.to_le_bytes(),
        b.edx.to_le_bytes(),
        c.eax.to_le_bytes(),
        c.ebx.to_le_bytes(),
        c.ecx.to_le_bytes(),
        c.edx.to_le_bytes(),
    ];
    let mut i = 0;
    while i < 12 {
        let mut j = 0;
        while j < 4 {
            out[i * 4 + j] = parts[i][j];
            j += 1;
        }
        i += 1;
    }
    out
}

/// Return the brand string with leading + trailing ASCII spaces and
/// NUL bytes removed.
///
/// Most BIOSes left-pad the brand string with spaces (e.g.
/// `"  Intel(R) Xeon(R) Gold 6126 CPU @ 2.60GHz"`); a few NUL-terminate
/// shorter values. The output is a sub-slice of the input; the original
/// 48-byte buffer is the caller's responsibility.
#[must_use]
pub fn trim_brand(buf: &[u8; BRAND_LEN]) -> &[u8] {
    let mut start = 0usize;
    while start < BRAND_LEN && (buf[start] == b' ' || buf[start] == 0) {
        start += 1;
    }
    let mut end = BRAND_LEN;
    while end > start && (buf[end - 1] == b' ' || buf[end - 1] == 0) {
        end -= 1;
    }
    #[allow(
        clippy::indexing_slicing,
        reason = "start <= end <= BRAND_LEN guaranteed by the loops above"
    )]
    &buf[start..end]
}

// =====================================================================
// Family / Model / Stepping (CPUID leaf 1 EAX)
// =====================================================================

/// Decoded `(family, model, stepping)` triple from CPUID leaf 1 EAX.
///
/// Per Intel SDM Vol 2 — CPUID:
/// - `stepping` = EAX\[3:0\]
/// - `model_id_base` = EAX\[7:4\]
/// - `family_id_base` = EAX\[11:8\]
/// - `model_id_ext` = EAX\[19:16\]
/// - `family_id_ext` = EAX\[27:20\]
///
/// Effective family:
/// - If `family_id_base == 0x0F` → `family = family_id_base + family_id_ext`.
/// - Otherwise → `family = family_id_base`.
///
/// Effective model:
/// - If `family_id_base ∈ {0x06, 0x0F}` → `model = (model_id_ext << 4) | model_id_base`.
/// - Otherwise → `model = model_id_base`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct FamilyModel {
    /// Effective CPU family (already includes `family_id_ext` when applicable).
    pub family: u32,
    /// Effective CPU model (already includes `model_id_ext` when applicable).
    pub model: u32,
    /// Stepping (low nibble of EAX).
    pub stepping: u32,
}

/// Read CPUID leaf 1 EAX and decode family / model / stepping.
#[must_use]
pub fn family_model() -> FamilyModel {
    decode_family_model(cpuid(1, 0).eax)
}

/// Pure function: decode the family/model/stepping from leaf 1 EAX.
#[must_use]
pub fn decode_family_model(eax: u32) -> FamilyModel {
    let stepping = eax & 0xF;
    let model_id_base = (eax >> 4) & 0xF;
    let family_id_base = (eax >> 8) & 0xF;
    let model_id_ext = (eax >> 16) & 0xF;
    let family_id_ext = (eax >> 20) & 0xFF;

    let family = if family_id_base == 0x0F {
        family_id_base + family_id_ext
    } else {
        family_id_base
    };
    let model = if family_id_base == 0x06 || family_id_base == 0x0F {
        (model_id_ext << 4) | model_id_base
    } else {
        model_id_base
    };
    FamilyModel {
        family,
        model,
        stepping,
    }
}

// =====================================================================
// Feature flags (subset)
// =====================================================================

/// Hand-picked subset of CPUID feature flags surfaced in the NexaCore OS
/// System Info panel.
///
/// Each variant maps to a single bit in one of the CPUID feature
/// dwords; the helper [`format_feature_summary`] emits the
/// space-separated mnemonic list rendered by `demo.rs`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct CpuFeatures {
    /// CPUID 1 EDX raw value.
    pub edx1: u32,
    /// CPUID 1 ECX raw value.
    pub ecx1: u32,
    /// CPUID 7 sub-leaf 0 EBX raw value (extended features).
    pub ebx7: u32,
}

/// Read the feature-flag dwords from CPUID leaves 1 and 7.
#[must_use]
pub fn features() -> CpuFeatures {
    let max = cpuid(0, 0).eax;
    let leaf1 = cpuid(1, 0);
    let leaf7 = if max >= 7 {
        cpuid(7, 0)
    } else {
        CpuidRegs::default()
    };
    CpuFeatures {
        edx1: leaf1.edx,
        ecx1: leaf1.ecx,
        ebx7: leaf7.ebx,
    }
}

/// Bit positions for the feature mnemonics we surface. Pinned by host
/// tests so a typo cannot silently shift a label.
mod bits {
    // CPUID 1 EDX.
    pub(super) const EDX1_SSE: u32 = 25;
    pub(super) const EDX1_SSE2: u32 = 26;
    // CPUID 1 ECX.
    pub(super) const ECX1_SSE3: u32 = 0;
    pub(super) const ECX1_SSSE3: u32 = 9;
    pub(super) const ECX1_SSE41: u32 = 19;
    pub(super) const ECX1_SSE42: u32 = 20;
    pub(super) const ECX1_X2APIC: u32 = 21;
    pub(super) const ECX1_AES: u32 = 25;
    pub(super) const ECX1_AVX: u32 = 28;
    pub(super) const ECX1_RDRAND: u32 = 30;
    // CPUID 7:0 EBX.
    pub(super) const EBX7_AVX2: u32 = 5;
    pub(super) const EBX7_RDSEED: u32 = 18;
}

/// Mnemonic table — order matches the `format_feature_summary` output.
const FEATURE_TABLE: &[(&[u8], FeatureSource)] = &[
    (b"SSE", FeatureSource::Edx1(bits::EDX1_SSE)),
    (b"SSE2", FeatureSource::Edx1(bits::EDX1_SSE2)),
    (b"SSE3", FeatureSource::Ecx1(bits::ECX1_SSE3)),
    (b"SSSE3", FeatureSource::Ecx1(bits::ECX1_SSSE3)),
    (b"SSE4.1", FeatureSource::Ecx1(bits::ECX1_SSE41)),
    (b"SSE4.2", FeatureSource::Ecx1(bits::ECX1_SSE42)),
    (b"AES", FeatureSource::Ecx1(bits::ECX1_AES)),
    (b"AVX", FeatureSource::Ecx1(bits::ECX1_AVX)),
    (b"AVX2", FeatureSource::Ebx7(bits::EBX7_AVX2)),
    (b"RDRAND", FeatureSource::Ecx1(bits::ECX1_RDRAND)),
    (b"RDSEED", FeatureSource::Ebx7(bits::EBX7_RDSEED)),
    (b"x2APIC", FeatureSource::Ecx1(bits::ECX1_X2APIC)),
];

#[derive(Debug, Clone, Copy)]
enum FeatureSource {
    Edx1(u32),
    Ecx1(u32),
    Ebx7(u32),
}

/// Maximum length of the feature-summary byte buffer.
///
/// Generous upper bound — the longest sensible combination of every
/// mnemonic + separators is well under this.
pub const FEATURE_SUMMARY_LEN: usize = 96;

/// Pure function: format the active subset of `FEATURE_TABLE` as a
/// space-separated ASCII byte buffer.
///
/// The output is null-padded to [`FEATURE_SUMMARY_LEN`]; callers use
/// [`trim_feature_summary`] to obtain the printable slice.
#[must_use]
pub fn format_feature_summary(f: CpuFeatures) -> [u8; FEATURE_SUMMARY_LEN] {
    let mut out = [0u8; FEATURE_SUMMARY_LEN];
    let mut pos = 0usize;
    let mut first = true;
    for (name, src) in FEATURE_TABLE {
        let set = match *src {
            FeatureSource::Edx1(b) => (f.edx1 >> b) & 1 == 1,
            FeatureSource::Ecx1(b) => (f.ecx1 >> b) & 1 == 1,
            FeatureSource::Ebx7(b) => (f.ebx7 >> b) & 1 == 1,
        };
        if !set {
            continue;
        }
        if !first {
            if pos >= FEATURE_SUMMARY_LEN {
                break;
            }
            #[allow(
                clippy::indexing_slicing,
                reason = "pos < FEATURE_SUMMARY_LEN checked above"
            )]
            {
                out[pos] = b' ';
            }
            pos += 1;
        }
        first = false;
        for &b in *name {
            if pos >= FEATURE_SUMMARY_LEN {
                break;
            }
            #[allow(
                clippy::indexing_slicing,
                reason = "pos < FEATURE_SUMMARY_LEN checked above"
            )]
            {
                out[pos] = b;
            }
            pos += 1;
        }
    }
    out
}

/// Return the printable slice of a feature-summary buffer (drops the
/// trailing NUL padding).
#[must_use]
pub fn trim_feature_summary(buf: &[u8; FEATURE_SUMMARY_LEN]) -> &[u8] {
    let mut end = FEATURE_SUMMARY_LEN;
    while end > 0 && buf[end - 1] == 0 {
        end -= 1;
    }
    #[allow(
        clippy::indexing_slicing,
        reason = "end <= FEATURE_SUMMARY_LEN guaranteed by the loop above"
    )]
    &buf[..end]
}

// =====================================================================
// Cached snapshot
// =====================================================================

/// One-shot cached snapshot of the BSP's CPUID data.
///
/// `kmain` calls [`init`] once during boot; subsequent reads via
/// [`snapshot`] are wait-free. Updating in place from APs is not
/// supported — APs may execute different microcode revisions, but the
/// System Info panel only renders the BSP figures.
#[derive(Debug, Clone, Copy)]
pub struct CpuSnapshot {
    /// 12-byte vendor string from CPUID 0.
    pub vendor: [u8; VENDOR_LEN],
    /// 48-byte brand string from CPUID `0x8000_0002..4`.
    pub brand: [u8; BRAND_LEN],
    /// Decoded family/model/stepping.
    pub family_model: FamilyModel,
    /// Feature-summary buffer (NUL-padded).
    pub feature_summary: [u8; FEATURE_SUMMARY_LEN],
}

impl CpuSnapshot {
    /// Empty snapshot — used as the static initial value.
    #[must_use]
    pub const fn empty() -> Self {
        Self {
            vendor: [0; VENDOR_LEN],
            brand: [0; BRAND_LEN],
            family_model: FamilyModel {
                family: 0,
                model: 0,
                stepping: 0,
            },
            feature_summary: [0; FEATURE_SUMMARY_LEN],
        }
    }

    /// Collect the snapshot by running every CPUID query.
    #[must_use]
    pub fn collect() -> Self {
        Self {
            vendor: vendor(),
            brand: brand_string(),
            family_model: family_model(),
            feature_summary: format_feature_summary(features()),
        }
    }
}

// Atomics ensure the snapshot store is visible to later GS-relative
// reads in the demo. We pack the relevant scalar fields into atomics;
// the brand/vendor/feature buffers live in a separate static behind a
// "ready" flag set last.
static SNAPSHOT_READY: AtomicU32 = AtomicU32::new(0);
static mut SNAPSHOT_STORAGE: CpuSnapshot = CpuSnapshot::empty();

/// One-shot initialiser: collect CPUID once and stash in
/// `SNAPSHOT_STORAGE`. Safe to call multiple times; subsequent calls
/// short-circuit.
pub fn init() {
    if SNAPSHOT_READY.load(Ordering::Acquire) != 0 {
        return;
    }
    let snap = CpuSnapshot::collect();
    // SAFETY: single-CPU bare-metal boot path; no concurrent writer
    // exists. The `SNAPSHOT_READY.store` below `Release`-orders the
    // write so later `Acquire`-loaders observe the populated snapshot.
    unsafe {
        let dst = &raw mut SNAPSHOT_STORAGE;
        core::ptr::write_volatile(dst, snap);
    }
    SNAPSHOT_READY.store(1, Ordering::Release);
}

/// Read the cached BSP snapshot. Returns an empty snapshot if [`init`]
/// has not been called.
#[must_use]
pub fn snapshot() -> CpuSnapshot {
    if SNAPSHOT_READY.load(Ordering::Acquire) == 0 {
        return CpuSnapshot::empty();
    }
    // SAFETY: paired with the `Release` store in `init`; once
    // `SNAPSHOT_READY != 0` we are guaranteed to observe the
    // fully-populated buffer.
    unsafe {
        let src = &raw const SNAPSHOT_STORAGE;
        core::ptr::read_volatile(src)
    }
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

    /// Build CPUID regs from a vendor-string layout (EBX, EDX, ECX).
    fn vendor_regs(s: &[u8; 12]) -> CpuidRegs {
        CpuidRegs {
            eax: 0,
            ebx: u32::from_le_bytes([s[0], s[1], s[2], s[3]]),
            edx: u32::from_le_bytes([s[4], s[5], s[6], s[7]]),
            ecx: u32::from_le_bytes([s[8], s[9], s[10], s[11]]),
        }
    }

    #[test]
    fn vendor_unpacks_genuine_intel() {
        let bytes = *b"GenuineIntel";
        let r = vendor_regs(&bytes);
        let v = unpack_vendor(r);
        assert_eq!(&v[..], &bytes[..]);
    }

    #[test]
    fn vendor_unpacks_authentic_amd() {
        let bytes = *b"AuthenticAMD";
        let r = vendor_regs(&bytes);
        let v = unpack_vendor(r);
        assert_eq!(&v[..], &bytes[..]);
    }

    #[test]
    fn brand_unpack_layout_matches_intel_sdm() {
        // Build three CPUID outputs that, concatenated, spell a known
        // 48-byte brand string. Each register is little-endian.
        let s = *b"Intel(R) Xeon(R) CPU E5-2670 v3 @ 2.30GHz       ";
        let mut regs = [CpuidRegs::default(); 3];
        for (i, r) in regs.iter_mut().enumerate() {
            r.eax =
                u32::from_le_bytes([s[i * 16 + 0], s[i * 16 + 1], s[i * 16 + 2], s[i * 16 + 3]]);
            r.ebx =
                u32::from_le_bytes([s[i * 16 + 4], s[i * 16 + 5], s[i * 16 + 6], s[i * 16 + 7]]);
            r.ecx =
                u32::from_le_bytes([s[i * 16 + 8], s[i * 16 + 9], s[i * 16 + 10], s[i * 16 + 11]]);
            r.edx = u32::from_le_bytes([
                s[i * 16 + 12],
                s[i * 16 + 13],
                s[i * 16 + 14],
                s[i * 16 + 15],
            ]);
        }
        let b = unpack_brand(regs[0], regs[1], regs[2]);
        assert_eq!(&b[..], &s[..]);
    }

    #[test]
    fn trim_brand_strips_leading_spaces_and_trailing_padding() {
        let mut buf = [0u8; BRAND_LEN];
        let s = b"   Hello World!   ";
        buf[..s.len()].copy_from_slice(s);
        let t = trim_brand(&buf);
        assert_eq!(t, b"Hello World!");
    }

    #[test]
    fn trim_brand_handles_all_blank() {
        let buf = [0u8; BRAND_LEN];
        let t = trim_brand(&buf);
        assert_eq!(t.len(), 0);
    }

    #[test]
    fn family_model_decodes_family_06_with_extended_model() {
        // Skylake-X EAX = 0x0005_065E:
        //   stepping = 0xE, model_base = 0x5, family_base = 0x6,
        //   model_ext = 0x5 → effective model = 0x55 = 85.
        let fm = decode_family_model(0x0005_065E);
        assert_eq!(fm.family, 6);
        assert_eq!(fm.model, 0x55);
        assert_eq!(fm.stepping, 0xE);
    }

    #[test]
    fn family_model_decodes_family_0f_with_extended_family() {
        // AMD K8 EAX = 0x0010_0F00:
        //   family_base = 0xF, family_ext = 0x01 → effective family = 0x10.
        let fm = decode_family_model(0x0010_0F00);
        assert_eq!(fm.family, 0x10);
    }

    #[test]
    fn family_model_decodes_pre_modern_layout() {
        // EAX = 0x0000_0500: family_base = 5, model_base = 0, stepping = 0.
        // Neither 0x06 nor 0x0F → no extension applied.
        let fm = decode_family_model(0x0000_0500);
        assert_eq!(fm.family, 5);
        assert_eq!(fm.model, 0);
        assert_eq!(fm.stepping, 0);
    }

    #[test]
    fn feature_summary_emits_only_set_flags() {
        // SSE + SSE2 + SSE4.2 + AES + AVX (no AVX2, no x2APIC).
        let f = CpuFeatures {
            edx1: (1 << bits::EDX1_SSE) | (1 << bits::EDX1_SSE2),
            ecx1: (1 << bits::ECX1_SSE42) | (1 << bits::ECX1_AES) | (1 << bits::ECX1_AVX),
            ebx7: 0,
        };
        let buf = format_feature_summary(f);
        let s = trim_feature_summary(&buf);
        assert_eq!(s, b"SSE SSE2 SSE4.2 AES AVX");
    }

    #[test]
    fn feature_summary_empty_when_no_features() {
        let buf = format_feature_summary(CpuFeatures::default());
        let s = trim_feature_summary(&buf);
        assert!(s.is_empty());
    }

    #[test]
    fn feature_summary_with_x2apic_and_avx2() {
        let f = CpuFeatures {
            edx1: 1 << bits::EDX1_SSE2,
            ecx1: (1 << bits::ECX1_X2APIC) | (1 << bits::ECX1_RDRAND),
            ebx7: (1 << bits::EBX7_AVX2) | (1 << bits::EBX7_RDSEED),
        };
        let buf = format_feature_summary(f);
        let s = trim_feature_summary(&buf);
        assert_eq!(s, b"SSE2 AVX2 RDRAND RDSEED x2APIC");
    }

    #[test]
    fn snapshot_empty_returns_zeroed_fields() {
        let s = CpuSnapshot::empty();
        assert_eq!(&s.vendor[..], &[0u8; VENDOR_LEN][..]);
        assert_eq!(&s.brand[..], &[0u8; BRAND_LEN][..]);
        assert_eq!(s.family_model, FamilyModel::default());
        assert!(trim_feature_summary(&s.feature_summary).is_empty());
    }
}
