//! Bounds-safe TLS wire codec helpers.
//!
//! TLS structures are built from big-endian integers and length-prefixed
//! vectors (`opaque field<lo..hi>`). [`Reader`] and [`Writer`] centralise that
//! encoding so the message modules never index a slice by hand — every read is
//! length-checked and fails closed with [`TlsError::Decode`].

use alloc::vec::Vec;

use crate::error::{TlsError, TlsResult};

/// A forward-only, bounds-checked reader over a byte slice.
pub struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    /// Wrap a slice.
    #[must_use]
    pub const fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    /// Bytes not yet consumed.
    #[must_use]
    pub fn remaining(&self) -> usize {
        self.buf.len().saturating_sub(self.pos)
    }

    /// Whether the whole input has been consumed.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.remaining() == 0
    }

    /// Take exactly `n` bytes.
    ///
    /// # Errors
    /// [`TlsError::Decode`] if fewer than `n` bytes remain.
    pub fn take(&mut self, n: usize) -> TlsResult<&'a [u8]> {
        let end = self.pos.checked_add(n).ok_or(TlsError::Decode)?;
        let slice = self.buf.get(self.pos..end).ok_or(TlsError::Decode)?;
        self.pos = end;
        Ok(slice)
    }

    /// Read a `u8`.
    ///
    /// # Errors
    /// [`TlsError::Decode`] if no bytes remain.
    pub fn u8(&mut self) -> TlsResult<u8> {
        let s = self.take(1)?;
        s.first().copied().ok_or(TlsError::Decode)
    }

    /// Read a big-endian `u16`.
    ///
    /// # Errors
    /// [`TlsError::Decode`] on short input.
    pub fn u16(&mut self) -> TlsResult<u16> {
        match self.take(2)? {
            [hi, lo] => Ok((u16::from(*hi) << 8) | u16::from(*lo)),
            _ => Err(TlsError::Decode),
        }
    }

    /// Read a big-endian 24-bit integer as `u32`.
    ///
    /// # Errors
    /// [`TlsError::Decode`] on short input.
    pub fn u24(&mut self) -> TlsResult<u32> {
        match self.take(3)? {
            [a, b, c] => Ok((u32::from(*a) << 16) | (u32::from(*b) << 8) | u32::from(*c)),
            _ => Err(TlsError::Decode),
        }
    }

    /// Read a `u8`-length-prefixed vector, returning its body.
    ///
    /// # Errors
    /// [`TlsError::Decode`] on short input.
    pub fn vec_u8(&mut self) -> TlsResult<&'a [u8]> {
        let n = self.u8()? as usize;
        self.take(n)
    }

    /// Read a `u16`-length-prefixed vector, returning its body.
    ///
    /// # Errors
    /// [`TlsError::Decode`] on short input.
    pub fn vec_u16(&mut self) -> TlsResult<&'a [u8]> {
        let n = self.u16()? as usize;
        self.take(n)
    }

    /// Read a 24-bit-length-prefixed vector, returning its body.
    ///
    /// # Errors
    /// [`TlsError::Decode`] on short input.
    pub fn vec_u24(&mut self) -> TlsResult<&'a [u8]> {
        let n = self.u24()? as usize;
        self.take(n)
    }
}

/// A growable big-endian writer with length-prefix backpatching.
#[derive(Default)]
pub struct Writer {
    buf: Vec<u8>,
}

impl Writer {
    /// A fresh empty writer.
    #[must_use]
    pub fn new() -> Self {
        Self { buf: Vec::new() }
    }

    /// Consume the writer, returning the accumulated bytes.
    #[must_use]
    pub fn into_bytes(self) -> Vec<u8> {
        self.buf
    }

    /// Current length.
    #[must_use]
    pub fn len(&self) -> usize {
        self.buf.len()
    }

    /// Whether nothing has been written.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.buf.is_empty()
    }

    /// Append a single byte.
    pub fn u8(&mut self, v: u8) {
        self.buf.push(v);
    }

    /// Append a big-endian `u16`.
    pub fn u16(&mut self, v: u16) {
        self.buf.extend_from_slice(&v.to_be_bytes());
    }

    /// Append a big-endian 24-bit integer (low 24 bits of `v`).
    pub fn u24(&mut self, v: u32) {
        let b = v.to_be_bytes();
        // b = [hi, a, b, c]; write the low 3 bytes.
        self.buf.extend_from_slice(b.get(1..4).unwrap_or_default());
    }

    /// Append raw bytes.
    pub fn bytes(&mut self, v: &[u8]) {
        self.buf.extend_from_slice(v);
    }

    /// Append `body` prefixed by its length as a `u8`.
    ///
    /// # Errors
    /// [`TlsError::BadValue`] if `body` is longer than 255.
    pub fn vec_u8(&mut self, body: &[u8]) -> TlsResult<()> {
        let n = u8::try_from(body.len()).map_err(|_| TlsError::BadValue)?;
        self.u8(n);
        self.bytes(body);
        Ok(())
    }

    /// Append `body` prefixed by its length as a `u16`.
    ///
    /// # Errors
    /// [`TlsError::BadValue`] if `body` is longer than 65535.
    pub fn vec_u16(&mut self, body: &[u8]) -> TlsResult<()> {
        let n = u16::try_from(body.len()).map_err(|_| TlsError::BadValue)?;
        self.u16(n);
        self.bytes(body);
        Ok(())
    }

    /// Append `body` prefixed by its length as a 24-bit integer.
    ///
    /// # Errors
    /// [`TlsError::BadValue`] if `body` is longer than `2^24 - 1`.
    pub fn vec_u24(&mut self, body: &[u8]) -> TlsResult<()> {
        let n = u32::try_from(body.len()).map_err(|_| TlsError::BadValue)?;
        if n > 0x00FF_FFFF {
            return Err(TlsError::BadValue);
        }
        self.u24(n);
        self.bytes(body);
        Ok(())
    }
}
