//! SSH wire data types (RFC 4251 §5).
//!
//! [`Writer`] and [`Reader`] encode/decode the SSH primitive types used
//! throughout the protocol: `byte`, `boolean`, `uint32`, `uint64`, `string`
//! (a `uint32` length followed by that many bytes), `name-list` (a `string` of
//! comma-separated names), and `mpint` (a `string` holding a two's-complement,
//! minimal-length big-endian integer). All multi-byte integers are big-endian.
//!
//! The reader is bounds-safe: every accessor returns [`SshError::ShortBuffer`]
//! rather than panicking on truncated input.

use alloc::{string::String, vec::Vec};

use crate::error::SshError;

/// Builds an SSH byte stream from primitive values.
#[derive(Debug, Default, Clone)]
pub struct Writer {
    buf: Vec<u8>,
}

impl Writer {
    /// A new empty writer.
    #[must_use]
    pub fn new() -> Self {
        Self { buf: Vec::new() }
    }

    /// Consume the writer, returning the accumulated bytes.
    #[must_use]
    pub fn into_bytes(self) -> Vec<u8> {
        self.buf
    }

    /// The bytes written so far.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.buf
    }

    /// Append a single byte.
    pub fn put_u8(&mut self, v: u8) {
        self.buf.push(v);
    }

    /// Append a boolean (`0` or `1`).
    pub fn put_bool(&mut self, v: bool) {
        self.buf.push(u8::from(v));
    }

    /// Append a big-endian `uint32`.
    pub fn put_u32(&mut self, v: u32) {
        self.buf.extend_from_slice(&v.to_be_bytes());
    }

    /// Append a big-endian `uint64`.
    pub fn put_u64(&mut self, v: u64) {
        self.buf.extend_from_slice(&v.to_be_bytes());
    }

    /// Append raw bytes with no length prefix.
    pub fn put_raw(&mut self, bytes: &[u8]) {
        self.buf.extend_from_slice(bytes);
    }

    /// Append a `string`: a `uint32` length followed by the bytes.
    pub fn put_string(&mut self, bytes: &[u8]) {
        self.put_u32(u32::try_from(bytes.len()).unwrap_or(u32::MAX));
        self.buf.extend_from_slice(bytes);
    }

    /// Append a `name-list` from an iterator of names (comma-joined `string`).
    pub fn put_name_list(&mut self, names: &[&str]) {
        let mut joined = String::new();
        for (i, n) in names.iter().enumerate() {
            if i != 0 {
                joined.push(',');
            }
            joined.push_str(n);
        }
        self.put_string(joined.as_bytes());
    }

    /// Append an `mpint`: a `string` holding the minimal two's-complement
    /// big-endian encoding of a non-negative integer given as raw big-endian
    /// bytes. Leading zero bytes are stripped; a `0x00` is prepended if the top
    /// bit of the first significant byte is set (to keep the value positive).
    pub fn put_mpint(&mut self, be: &[u8]) {
        // Strip leading zeros.
        let mut start = 0;
        while start < be.len() && be.get(start) == Some(&0) {
            start += 1;
        }
        let sig = be.get(start..).unwrap_or(&[]);
        if sig.is_empty() {
            self.put_string(&[]); // value is zero
            return;
        }
        let needs_pad = sig.first().is_some_and(|b| b & 0x80 != 0);
        let len = sig.len() + usize::from(needs_pad);
        self.put_u32(u32::try_from(len).unwrap_or(u32::MAX));
        if needs_pad {
            self.buf.push(0x00);
        }
        self.buf.extend_from_slice(sig);
    }
}

/// Reads SSH primitive values from a byte slice, tracking a cursor.
#[derive(Debug, Clone)]
pub struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    /// A reader over `buf`.
    #[must_use]
    pub fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    /// Bytes not yet consumed.
    #[must_use]
    pub fn remaining(&self) -> usize {
        self.buf.len().saturating_sub(self.pos)
    }

    /// Whether the reader is fully consumed.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.remaining() == 0
    }

    /// Read one byte.
    ///
    /// # Errors
    /// [`SshError::ShortBuffer`] if no bytes remain.
    pub fn get_u8(&mut self) -> Result<u8, SshError> {
        let b = *self.buf.get(self.pos).ok_or(SshError::ShortBuffer)?;
        self.pos += 1;
        Ok(b)
    }

    /// Read a boolean (`0` is false, anything else true).
    ///
    /// # Errors
    /// [`SshError::ShortBuffer`] if no bytes remain.
    pub fn get_bool(&mut self) -> Result<bool, SshError> {
        Ok(self.get_u8()? != 0)
    }

    /// Read a big-endian `uint32`.
    ///
    /// # Errors
    /// [`SshError::ShortBuffer`] if fewer than 4 bytes remain.
    pub fn get_u32(&mut self) -> Result<u32, SshError> {
        let end = self.pos.checked_add(4).ok_or(SshError::ShortBuffer)?;
        let slice = self.buf.get(self.pos..end).ok_or(SshError::ShortBuffer)?;
        let arr: [u8; 4] = slice.try_into().map_err(|_| SshError::ShortBuffer)?;
        self.pos = end;
        Ok(u32::from_be_bytes(arr))
    }

    /// Read `n` raw bytes.
    ///
    /// # Errors
    /// [`SshError::ShortBuffer`] if fewer than `n` bytes remain.
    pub fn get_bytes(&mut self, n: usize) -> Result<&'a [u8], SshError> {
        let end = self.pos.checked_add(n).ok_or(SshError::ShortBuffer)?;
        let slice = self.buf.get(self.pos..end).ok_or(SshError::ShortBuffer)?;
        self.pos = end;
        Ok(slice)
    }

    /// Read a `string` (a `uint32` length then that many bytes).
    ///
    /// # Errors
    /// [`SshError::ShortBuffer`] on truncation.
    pub fn get_string(&mut self) -> Result<&'a [u8], SshError> {
        let len = self.get_u32()? as usize;
        self.get_bytes(len)
    }

    /// Read a `name-list` into a `Vec` of owned names.
    ///
    /// # Errors
    /// [`SshError::ShortBuffer`] on truncation, [`SshError::Protocol`] if the
    /// list is not valid UTF-8.
    pub fn get_name_list(&mut self) -> Result<Vec<String>, SshError> {
        let raw = self.get_string()?;
        if raw.is_empty() {
            return Ok(Vec::new());
        }
        let s = core::str::from_utf8(raw).map_err(|_| SshError::Protocol("name-list utf8"))?;
        Ok(s.split(',').map(String::from).collect())
    }
}
