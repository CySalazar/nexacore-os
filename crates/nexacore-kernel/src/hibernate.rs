//! Hibernation memory-image serialization format (WS12-06.3).
//!
//! Hibernation (ACPI S4) snapshots the whole of physical RAM to stable
//! storage, powers the machine off, and reconstructs the exact memory state
//! on the next boot. This module is the **device-independent, host-testable**
//! core: the image *format* and its (de)serialization. It deliberately does
//! **not** implement the S4 power transition itself (WS12-06.2) — it only
//! turns a set of physical frames into a self-describing byte image and back.
//!
//! The design mirrors [`crate::swap`] and [`crate::metrics`]: a fail-closed
//! `encode`/`decode` pair over a small binary layout, with the actual reading
//! and writing of physical frames kept behind a seam so the format logic can
//! be exercised without a live frame allocator.
//!
//! # Image layout
//!
//! ```text
//! ┌────────────────────────── HEADER (32 bytes) ──────────────────────────┐
//! │ magic[8] "NCHIB001" │ version:u32 │ page_size:u32 │ page_count:u64 │   │
//! │ payload_checksum:u64 (FNV-1a over the payload bytes)                   │
//! └───────────────────────────────────────────────────────────────────────┘
//! ┌────────────────────────── PAYLOAD (page_count records) ───────────────┐
//! │ record := pfn:u64 ‖ tag:u8 ‖ tag-specific body                        │
//! │   tag 0 (ZERO)    → no body   (all-zero page, elided)                 │
//! │   tag 1 (RAW)     → page_size raw bytes                               │
//! │   tag 2 (RLE)     → fill:u8   (a uniform, non-zero page)              │
//! └───────────────────────────────────────────────────────────────────────┘
//! ```
//!
//! Two size optimisations keep a typical image small:
//!
//! - **zero-page elision** — an all-zero frame is stored as a single tag byte,
//!   never its 4 KiB of zeros (the common case: most of RAM is untouched);
//! - **run-length encoding** — a frame filled with one repeated non-zero byte
//!   is stored as that byte, not the full page.
//!
//! # Fail-closed decoding
//!
//! [`decode`](crate::hibernate::decode) rejects, without ever writing a frame past the failure point:
//!
//! - a bad magic ([`HibernateError::BadMagic`](crate::hibernate::HibernateError::BadMagic));
//! - a format-version mismatch ([`HibernateError::VersionMismatch`](crate::hibernate::HibernateError::VersionMismatch));
//! - an unsupported page size ([`HibernateError::UnsupportedPageSize`](crate::hibernate::HibernateError::UnsupportedPageSize));
//! - a truncated header or payload ([`HibernateError::Truncated`](crate::hibernate::HibernateError::Truncated));
//! - a payload that does not match the stored checksum
//!   ([`HibernateError::ChecksumMismatch`](crate::hibernate::HibernateError::ChecksumMismatch));
//! - a malformed record or trailing garbage ([`HibernateError::Corrupt`](crate::hibernate::HibernateError::Corrupt)).
//!
//! The bare-metal kernel supplies the production [`FrameSource`](crate::hibernate::FrameSource) / [`FrameSink`](crate::hibernate::FrameSink)
//! (wired to the frame allocator and the direct map); host tests use
//! [`MemFrameStore`](crate::hibernate::MemFrameStore).

use alloc::{collections::BTreeMap, vec::Vec};

/// Physical page size, in bytes (the hibernation record unit).
pub const PAGE_SIZE: usize = PAGE_SIZE_U32 as usize;

/// Physical page size as a `u32`, for the on-image header field.
pub const PAGE_SIZE_U32: u32 = 4096;

/// A single physical page.
pub type Page = [u8; PAGE_SIZE];

/// A physical frame number (the page's index in physical memory).
pub type FrameNumber = u64;

/// Image magic (`"NCHIB001"`).
pub const HIBERNATE_MAGIC: [u8; 8] = *b"NCHIB001";

/// The image format version this module reads and writes.
pub const FORMAT_VERSION: u32 = 1;

/// Serialized header length, in bytes (`magic ‖ version ‖ page_size ‖
/// page_count ‖ checksum` = 8 + 4 + 4 + 8 + 8).
pub const HEADER_LEN: usize = 32;

/// Record tag: an all-zero page, stored as this flag with no body.
const TAG_ZERO: u8 = 0;
/// Record tag: a verbatim page, followed by [`PAGE_SIZE`] raw bytes.
const TAG_RAW: u8 = 1;
/// Record tag: a uniform non-zero page, followed by a single fill byte.
const TAG_RLE: u8 = 2;

/// FNV-1a 64-bit offset basis.
const FNV_OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
/// FNV-1a 64-bit prime.
const FNV_PRIME: u64 = 0x0000_0100_0000_01b3;

// =============================================================================
// Errors
// =============================================================================

/// Error from the hibernation image codec.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HibernateError {
    /// The header magic did not match [`HIBERNATE_MAGIC`].
    BadMagic,
    /// The image was written by an incompatible format version.
    VersionMismatch,
    /// The image page size differs from [`PAGE_SIZE`].
    UnsupportedPageSize,
    /// The image ended before a header field or a full record could be read.
    Truncated,
    /// The payload checksum did not match the value in the header.
    ChecksumMismatch,
    /// A record carried an unknown tag, or trailing bytes followed the last
    /// declared record.
    Corrupt,
    /// The frame source or sink reported a read/write failure.
    Io,
}

// =============================================================================
// Header
// =============================================================================

/// The parsed image header (WS12-06.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HibernateHeader {
    /// Format version the image was written with.
    pub version: u32,
    /// Page size the image records use, in bytes.
    pub page_size: u32,
    /// Number of page records in the payload.
    pub page_count: u64,
    /// FNV-1a checksum over the payload bytes.
    pub checksum: u64,
}

impl HibernateHeader {
    /// Parse and validate the fixed-size header at the start of `image`.
    ///
    /// # Errors
    ///
    /// - [`HibernateError::Truncated`] if `image` is shorter than
    ///   [`HEADER_LEN`].
    /// - [`HibernateError::BadMagic`] on a magic mismatch.
    /// - [`HibernateError::VersionMismatch`] on an unsupported version.
    /// - [`HibernateError::UnsupportedPageSize`] on a page size other than
    ///   [`PAGE_SIZE`].
    pub fn parse(image: &[u8]) -> Result<Self, HibernateError> {
        let magic = image.get(0..8).ok_or(HibernateError::Truncated)?;
        if magic != HIBERNATE_MAGIC {
            return Err(HibernateError::BadMagic);
        }
        let version = u32::from_le_bytes(read_array4(image, 8)?);
        if version != FORMAT_VERSION {
            return Err(HibernateError::VersionMismatch);
        }
        let page_size = u32::from_le_bytes(read_array4(image, 12)?);
        if page_size != PAGE_SIZE_U32 {
            return Err(HibernateError::UnsupportedPageSize);
        }
        let page_count = u64::from_le_bytes(read_array8(image, 16)?);
        let checksum = u64::from_le_bytes(read_array8(image, 24)?);
        Ok(Self {
            version,
            page_size,
            page_count,
            checksum,
        })
    }
}

// =============================================================================
// Seam: frame source (encode) and frame sink (decode)
// =============================================================================

/// The read seam: supplies the bytes of a physical frame to [`encode`].
///
/// The bare-metal kernel implements this over the frame allocator and the
/// direct map; host tests use [`MemFrameStore`].
pub trait FrameSource {
    /// Copy the page at physical frame `pfn` into `out`.
    ///
    /// # Errors
    ///
    /// [`HibernateError::Io`] if the frame cannot be read.
    fn read_frame(&self, pfn: FrameNumber, out: &mut Page) -> Result<(), HibernateError>;
}

/// The write seam: restores the bytes of a physical frame from [`decode`].
///
/// The bare-metal kernel implements this over the frame allocator and the
/// direct map; host tests use [`MemFrameStore`].
pub trait FrameSink {
    /// Write `page` to physical frame `pfn`.
    ///
    /// # Errors
    ///
    /// [`HibernateError::Io`] if the frame cannot be written.
    fn write_frame(&mut self, pfn: FrameNumber, page: &Page) -> Result<(), HibernateError>;
}

/// An in-memory [`FrameSource`] + [`FrameSink`] for host tests: a map from
/// physical frame number to page contents.
#[derive(Debug, Clone, Default)]
pub struct MemFrameStore {
    /// Backing frames, keyed by physical frame number.
    frames: BTreeMap<FrameNumber, Page>,
}

impl MemFrameStore {
    /// An empty store (no frames).
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Insert or replace the page stored at `pfn`.
    pub fn set(&mut self, pfn: FrameNumber, page: &Page) {
        self.frames.insert(pfn, *page);
    }

    /// The page stored at `pfn`, if any.
    #[must_use]
    pub fn get(&self, pfn: FrameNumber) -> Option<&Page> {
        self.frames.get(&pfn)
    }

    /// The number of frames held.
    #[must_use]
    pub fn len(&self) -> usize {
        self.frames.len()
    }

    /// Whether the store holds no frames.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.frames.is_empty()
    }
}

impl FrameSource for MemFrameStore {
    fn read_frame(&self, pfn: FrameNumber, out: &mut Page) -> Result<(), HibernateError> {
        let page = self.frames.get(&pfn).ok_or(HibernateError::Io)?;
        out.copy_from_slice(page);
        Ok(())
    }
}

impl FrameSink for MemFrameStore {
    fn write_frame(&mut self, pfn: FrameNumber, page: &Page) -> Result<(), HibernateError> {
        self.frames.insert(pfn, *page);
        Ok(())
    }
}

// =============================================================================
// Encode / decode
// =============================================================================

/// Serialize the `frames` read from `src` into a hibernation image.
///
/// Each frame becomes one payload record, with zero-page elision and RLE
/// applied automatically. The returned bytes are `header ‖ payload`, ready to
/// be handed back to [`decode`].
///
/// # Errors
///
/// [`HibernateError::Io`] if any frame cannot be read from `src`.
pub fn encode(frames: &[FrameNumber], src: &dyn FrameSource) -> Result<Vec<u8>, HibernateError> {
    let mut payload: Vec<u8> = Vec::new();
    let mut page = [0u8; PAGE_SIZE];
    for &pfn in frames {
        src.read_frame(pfn, &mut page)?;
        payload.extend_from_slice(&pfn.to_le_bytes());
        match classify(&page) {
            PageKind::Zero => payload.push(TAG_ZERO),
            PageKind::Uniform(fill) => {
                payload.push(TAG_RLE);
                payload.push(fill);
            }
            PageKind::Raw => {
                payload.push(TAG_RAW);
                payload.extend_from_slice(&page);
            }
        }
    }

    let checksum = fnv1a64(&payload);
    let mut out = Vec::with_capacity(HEADER_LEN.saturating_add(payload.len()));
    out.extend_from_slice(&HIBERNATE_MAGIC);
    out.extend_from_slice(&FORMAT_VERSION.to_le_bytes());
    out.extend_from_slice(&PAGE_SIZE_U32.to_le_bytes());
    out.extend_from_slice(&(frames.len() as u64).to_le_bytes());
    out.extend_from_slice(&checksum.to_le_bytes());
    out.extend_from_slice(&payload);
    Ok(out)
}

/// Reconstruct the frames from a hibernation image, writing each into `sink`.
///
/// Returns the parsed header on success. Fail-closed: on any structural
/// problem the function returns an error and does not continue writing frames.
///
/// # Errors
///
/// Any [`HibernateError`] variant — see the module-level "Fail-closed
/// decoding" section.
pub fn decode(image: &[u8], sink: &mut dyn FrameSink) -> Result<HibernateHeader, HibernateError> {
    let header = HibernateHeader::parse(image)?;

    // The payload is everything past the fixed header. `parse` already proved
    // the image is at least HEADER_LEN long.
    let payload = image.get(HEADER_LEN..).ok_or(HibernateError::Truncated)?;
    if fnv1a64(payload) != header.checksum {
        return Err(HibernateError::ChecksumMismatch);
    }

    let mut pos: usize = 0;
    for _ in 0..header.page_count {
        let pfn_bytes: [u8; 8] = take(payload, &mut pos, 8)?
            .try_into()
            .map_err(|_| HibernateError::Truncated)?;
        let pfn = u64::from_le_bytes(pfn_bytes);
        let tag = take(payload, &mut pos, 1)?
            .first()
            .copied()
            .ok_or(HibernateError::Truncated)?;

        let page = match tag {
            TAG_ZERO => [0u8; PAGE_SIZE],
            TAG_RLE => {
                let fill = take(payload, &mut pos, 1)?
                    .first()
                    .copied()
                    .ok_or(HibernateError::Truncated)?;
                [fill; PAGE_SIZE]
            }
            TAG_RAW => {
                let mut p = [0u8; PAGE_SIZE];
                p.copy_from_slice(take(payload, &mut pos, PAGE_SIZE)?);
                p
            }
            _ => return Err(HibernateError::Corrupt),
        };

        sink.write_frame(pfn, &page)?;
    }

    // Reject trailing bytes after the last declared record.
    if pos != payload.len() {
        return Err(HibernateError::Corrupt);
    }
    Ok(header)
}

// =============================================================================
// Helpers
// =============================================================================

/// How a page should be encoded, chosen by [`classify`].
enum PageKind {
    /// Every byte is zero — elided to a bare tag.
    Zero,
    /// Every byte equals the same non-zero value — stored as that fill byte.
    Uniform(u8),
    /// Mixed content — stored verbatim.
    Raw,
}

/// Classify a page for encoding: all-zero, uniform non-zero, or raw.
fn classify(page: &Page) -> PageKind {
    let Some(&first) = page.first() else {
        return PageKind::Zero;
    };
    if page.iter().all(|&b| b == first) {
        if first == 0 {
            PageKind::Zero
        } else {
            PageKind::Uniform(first)
        }
    } else {
        PageKind::Raw
    }
}

/// Advance `pos` by `n` bytes over `buf`, returning the consumed slice.
///
/// Returns [`HibernateError::Truncated`] if fewer than `n` bytes remain.
fn take<'a>(buf: &'a [u8], pos: &mut usize, n: usize) -> Result<&'a [u8], HibernateError> {
    let end = pos.checked_add(n).ok_or(HibernateError::Truncated)?;
    let slice = buf.get(*pos..end).ok_or(HibernateError::Truncated)?;
    *pos = end;
    Ok(slice)
}

/// FNV-1a 64-bit hash over `bytes` (payload checksum; not a security hash).
fn fnv1a64(bytes: &[u8]) -> u64 {
    let mut hash = FNV_OFFSET;
    for &b in bytes {
        hash ^= u64::from(b);
        hash = hash.wrapping_mul(FNV_PRIME);
    }
    hash
}

/// Read a fixed 4-byte little-endian field at `offset`, or [`HibernateError::Truncated`].
fn read_array4(buf: &[u8], offset: usize) -> Result<[u8; 4], HibernateError> {
    let end = offset.checked_add(4).ok_or(HibernateError::Truncated)?;
    buf.get(offset..end)
        .and_then(|s| s.try_into().ok())
        .ok_or(HibernateError::Truncated)
}

/// Read a fixed 8-byte little-endian field at `offset`, or [`HibernateError::Truncated`].
fn read_array8(buf: &[u8], offset: usize) -> Result<[u8; 8], HibernateError> {
    let end = offset.checked_add(8).ok_or(HibernateError::Truncated)?;
    buf.get(offset..end)
        .and_then(|s| s.try_into().ok())
        .ok_or(HibernateError::Truncated)
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::cast_possible_truncation,
    clippy::missing_docs_in_private_items
)]
mod tests {
    use super::*;

    /// A page whose byte `i` is `(seed + i) as u8` — non-uniform, distinct per seed.
    fn patterned_page(seed: u8) -> Page {
        let mut p = [0u8; PAGE_SIZE];
        for (i, b) in p.iter_mut().enumerate() {
            *b = seed.wrapping_add(i as u8);
        }
        p
    }

    fn size_of_raw_records(n: usize) -> usize {
        // pfn(8) + tag(1) + PAGE_SIZE body, per record.
        n * (9 + PAGE_SIZE)
    }

    #[test]
    fn round_trips_multi_page_image() {
        let mut src = MemFrameStore::new();
        src.set(10, &patterned_page(1));
        src.set(20, &patterned_page(2));
        src.set(30, &patterned_page(3));
        let frames = [10, 20, 30];

        let image = encode(&frames, &src).unwrap();

        let mut sink = MemFrameStore::new();
        let header = decode(&image, &mut sink).unwrap();

        assert_eq!(header.version, FORMAT_VERSION);
        assert_eq!(header.page_size, PAGE_SIZE_U32);
        assert_eq!(header.page_count, 3);
        assert_eq!(sink.len(), 3);
        for pfn in frames {
            assert_eq!(
                sink.get(pfn),
                src.get(pfn),
                "frame {pfn} not restored exactly"
            );
        }
    }

    #[test]
    fn zero_page_elision_shrinks_and_restores_zeros() {
        // Two raw frames and one all-zero frame.
        let mut src = MemFrameStore::new();
        src.set(1, &patterned_page(7));
        src.set(2, &[0u8; PAGE_SIZE]); // zero page
        src.set(3, &patterned_page(9));
        let frames = [1, 2, 3];

        let image = encode(&frames, &src).unwrap();

        // The zero page must NOT store its 4 KiB body — only 9 bytes (pfn+tag).
        // Exact expected size: header + 2 raw records + 1 elided zero record.
        let expected = HEADER_LEN + size_of_raw_records(2) + 9;
        assert_eq!(image.len(), expected, "zero page was not elided");
        // Sanity: strictly smaller than an all-raw image of 3 pages.
        assert!(image.len() < HEADER_LEN + size_of_raw_records(3));

        let mut sink = MemFrameStore::new();
        decode(&image, &mut sink).unwrap();
        assert_eq!(
            sink.get(2),
            Some(&[0u8; PAGE_SIZE]),
            "zero page not restored"
        );
        assert_eq!(sink.get(1), src.get(1));
        assert_eq!(sink.get(3), src.get(3));
    }

    #[test]
    fn rle_uniform_page_round_trips_compactly() {
        let mut src = MemFrameStore::new();
        src.set(5, &[0xABu8; PAGE_SIZE]); // uniform non-zero page
        let frames = [5];

        let image = encode(&frames, &src).unwrap();

        // pfn(8) + tag(1) + fill(1) = 10 payload bytes, not a full page.
        assert_eq!(image.len(), HEADER_LEN + 10);

        let mut sink = MemFrameStore::new();
        decode(&image, &mut sink).unwrap();
        assert_eq!(sink.get(5), Some(&[0xABu8; PAGE_SIZE]));
    }

    #[test]
    fn rejects_bad_magic() {
        let mut src = MemFrameStore::new();
        src.set(1, &patterned_page(1));
        let mut image = encode(&[1], &src).unwrap();
        image[0] ^= 0xFF; // corrupt the magic

        let mut sink = MemFrameStore::new();
        assert_eq!(decode(&image, &mut sink), Err(HibernateError::BadMagic));
        assert!(sink.is_empty(), "no frame written on rejection");
    }

    #[test]
    fn rejects_version_mismatch() {
        let mut src = MemFrameStore::new();
        src.set(1, &patterned_page(1));
        let mut image = encode(&[1], &src).unwrap();
        // Version field is the 4 bytes at offset 8.
        image[8] = image[8].wrapping_add(1);

        let mut sink = MemFrameStore::new();
        assert_eq!(
            decode(&image, &mut sink),
            Err(HibernateError::VersionMismatch)
        );
    }

    #[test]
    fn rejects_truncated_header() {
        let mut src = MemFrameStore::new();
        src.set(1, &patterned_page(1));
        let image = encode(&[1], &src).unwrap();
        let short = &image[..20]; // cut inside the header

        let mut sink = MemFrameStore::new();
        assert_eq!(decode(short, &mut sink), Err(HibernateError::Truncated));
    }

    #[test]
    fn rejects_truncated_records() {
        // Header claims one more record than the payload provides; the checksum
        // (over the intact payload) still matches, so decode must fail-closed in
        // the record loop with Truncated.
        let mut src = MemFrameStore::new();
        src.set(1, &patterned_page(1));
        let mut image = encode(&[1], &src).unwrap();
        // page_count is the u64 at offset 16 → bump it to 2.
        let mut pc = u64::from_le_bytes(image[16..24].try_into().unwrap());
        pc += 1;
        image[16..24].copy_from_slice(&pc.to_le_bytes());

        let mut sink = MemFrameStore::new();
        assert_eq!(decode(&image, &mut sink), Err(HibernateError::Truncated));
    }

    #[test]
    fn rejects_bad_checksum() {
        let mut src = MemFrameStore::new();
        src.set(1, &patterned_page(1));
        let mut image = encode(&[1], &src).unwrap();
        // Flip a byte in the payload (past the 32-byte header).
        let last = image.len() - 1;
        image[last] ^= 0xFF;

        let mut sink = MemFrameStore::new();
        assert_eq!(
            decode(&image, &mut sink),
            Err(HibernateError::ChecksumMismatch)
        );
    }
}
