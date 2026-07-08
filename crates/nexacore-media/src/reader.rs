//! Bounds-checked big-endian byte reader shared by the container demuxers.
//!
//! Container formats are big-endian on the wire: ISO-BMFF box sizes/types and
//! EBML element IDs/sizes are all most-significant-byte-first.  Every accessor
//! returns `Option`, never indexes a slice directly, and advances the cursor
//! only on success — so a truncated or malformed file yields `None` instead of
//! a panic (the workspace denies `indexing_slicing` outside tests).

#![allow(
    clippy::redundant_pub_crate,
    reason = "`reader` is a private module; `pub(crate)` documents the intended crate-internal API and `pub` would trip `unreachable_pub`"
)]

/// A forward-only cursor over a borrowed byte slice.
pub(crate) struct ByteReader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> ByteReader<'a> {
    /// Wrap `buf`, positioned at the start.
    pub(crate) const fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    /// Bytes remaining after the cursor.
    pub(crate) const fn remaining(&self) -> usize {
        self.buf.len().saturating_sub(self.pos)
    }

    /// `true` once the cursor reached the end.
    pub(crate) const fn is_empty(&self) -> bool {
        self.remaining() == 0
    }

    /// Read one byte and advance.
    pub(crate) fn u8(&mut self) -> Option<u8> {
        let v = self.buf.get(self.pos).copied()?;
        self.pos += 1;
        Some(v)
    }

    /// Read a big-endian `u16` and advance.
    pub(crate) fn u16(&mut self) -> Option<u16> {
        let end = self.pos.checked_add(2)?;
        let arr: [u8; 2] = self.buf.get(self.pos..end)?.try_into().ok()?;
        self.pos = end;
        Some(u16::from_be_bytes(arr))
    }

    /// Read a big-endian `u32` and advance.
    pub(crate) fn u32(&mut self) -> Option<u32> {
        let end = self.pos.checked_add(4)?;
        let arr: [u8; 4] = self.buf.get(self.pos..end)?.try_into().ok()?;
        self.pos = end;
        Some(u32::from_be_bytes(arr))
    }

    /// Read a big-endian `u64` and advance.
    pub(crate) fn u64(&mut self) -> Option<u64> {
        let end = self.pos.checked_add(8)?;
        let arr: [u8; 8] = self.buf.get(self.pos..end)?.try_into().ok()?;
        self.pos = end;
        Some(u64::from_be_bytes(arr))
    }

    /// Borrow `n` bytes and advance the cursor past them.
    pub(crate) fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        let end = self.pos.checked_add(n)?;
        let slice = self.buf.get(self.pos..end)?;
        self.pos = end;
        Some(slice)
    }

    /// Advance the cursor by `n`, failing if it would overrun the buffer.
    pub(crate) fn skip(&mut self, n: usize) -> Option<()> {
        let end = self.pos.checked_add(n)?;
        if end > self.buf.len() {
            return None;
        }
        self.pos = end;
        Some(())
    }

    /// Read an EBML variable-length integer (used by Matroska/WebM).
    ///
    /// The first byte's leading-zero count gives the total length (1..=8); the
    /// marker bit is the highest set bit.  When `keep_marker` is `false` the
    /// marker bit is cleared (element *sizes* want the raw value; element *IDs*
    /// keep the full marker-included form for matching).
    pub(crate) fn ebml_vint(&mut self, keep_marker: bool) -> Option<u64> {
        let first = self.u8()?;
        if first == 0 {
            // A leading zero byte would imply length > 8: unsupported.
            return None;
        }
        let length = first.leading_zeros() as usize + 1;
        if length > 8 {
            return None;
        }
        // Mask off the marker bit unless the caller wants the ID form.
        let mut value: u64 = if keep_marker {
            u64::from(first)
        } else {
            let marker = 0x80_u8 >> (length - 1);
            u64::from(first & !marker)
        };
        for _ in 1..length {
            let byte = self.u8()?;
            value = value.checked_shl(8)?.checked_add(u64::from(byte))?;
        }
        Some(value)
    }
}
