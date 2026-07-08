//! Directory objects and tree path resolution (WS3-01.6).
//!
//! A directory's data is a sequence of entries `(inode: u64, name_len: u8,
//! name: name_len bytes)`. Names are UTF-8, at most 255 bytes, and must be in
//! Unicode NFC. ASCII is always NFC and is enforced here; verifying NFC for
//! non-ASCII names needs a Unicode-normalization table absent from the
//! workspace, so it is delegated to a [`NfcCheck`] seam (the conservative
//! [`AsciiNfc`] default rejects non-ASCII).

#![allow(clippy::cast_possible_truncation)]

use alloc::{string::String, vec::Vec};

use super::V3Error;

/// Maximum directory-entry name length in bytes.
pub const NAME_MAX: usize = 255;
/// Fixed per-entry header bytes (`inode` + `name_len`).
pub const ENTRY_FIXED: usize = 9;

/// Decides whether a non-ASCII name is in Unicode NFC.
pub trait NfcCheck {
    /// `true` if `name` is already NFC-normalised.
    fn is_nfc(&self, name: &str) -> bool;
}

/// Conservative NFC policy: ASCII is NFC; anything else is rejected (a real
/// normalizer must be supplied for non-ASCII names).
#[derive(Debug, Clone, Copy, Default)]
pub struct AsciiNfc;

impl NfcCheck for AsciiNfc {
    fn is_nfc(&self, name: &str) -> bool {
        name.is_ascii()
    }
}

/// Validate a name's length and UTF-8 form (UTF-8 is guaranteed by `&str`); the
/// NFC check is applied separately via [`NfcCheck`].
///
/// # Errors
/// [`V3Error::InvalidName`] for an empty, over-long, `.`/`..`, or
/// `/`/NUL-containing name.
pub fn validate_name(name: &str) -> Result<(), V3Error> {
    if name.is_empty() || name.len() > NAME_MAX || name == "." || name == ".." {
        return Err(V3Error::InvalidName);
    }
    if name.as_bytes().contains(&b'/') || name.as_bytes().contains(&0) {
        return Err(V3Error::InvalidName);
    }
    Ok(())
}

/// One directory entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DirEntry {
    /// Inode the name resolves to.
    pub inode: u64,
    /// Entry name.
    pub name: String,
}

/// An in-memory directory object (the decoded form of a directory's data).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Directory {
    entries: Vec<DirEntry>,
}

impl Directory {
    /// New empty directory.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    /// The entries, in insertion order.
    #[must_use]
    pub fn entries(&self) -> &[DirEntry] {
        &self.entries
    }

    /// Number of entries.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// `true` if the directory has no entries.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Resolve a single name to its inode.
    #[must_use]
    pub fn lookup(&self, name: &str) -> Option<u64> {
        self.entries
            .iter()
            .find(|e| e.name == name)
            .map(|e| e.inode)
    }

    /// Insert an entry after validating the name (length/UTF-8 + NFC via
    /// `nfc`). Rejects duplicates and invalid names.
    ///
    /// # Errors
    /// [`V3Error::InvalidName`] if the name fails [`validate_name`], is not NFC,
    /// or already exists.
    pub fn insert<N: NfcCheck>(&mut self, name: &str, inode: u64, nfc: &N) -> Result<(), V3Error> {
        validate_name(name)?;
        if !nfc.is_nfc(name) {
            return Err(V3Error::InvalidName);
        }
        if self.lookup(name).is_some() {
            return Err(V3Error::InvalidName);
        }
        self.entries.push(DirEntry {
            inode,
            name: String::from(name),
        });
        Ok(())
    }

    /// Remove an entry by name; returns its inode if present.
    pub fn remove(&mut self, name: &str) -> Option<u64> {
        let pos = self.entries.iter().position(|e| e.name == name)?;
        Some(self.entries.remove(pos).inode)
    }

    /// Encode to the on-disk byte sequence.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut v = Vec::new();
        for e in &self.entries {
            let nb = e.name.as_bytes();
            let len = nb.len().min(NAME_MAX);
            v.extend_from_slice(&e.inode.to_le_bytes());
            v.push(len as u8);
            v.extend_from_slice(nb.get(..len).unwrap_or(nb));
        }
        v
    }

    /// Decode a directory from its on-disk bytes.
    ///
    /// An entry with inode `0` (the reserved null inode) terminates parsing, so
    /// a zero-padded block decodes to the entries that precede the padding. A
    /// truncated trailing entry makes the whole object [`V3Error::Corrupt`].
    ///
    /// # Errors
    /// [`V3Error::Corrupt`] on a truncated entry or a non-UTF-8 name.
    pub fn decode(buf: &[u8]) -> Result<Self, V3Error> {
        let mut entries = Vec::new();
        let mut rest = buf;
        while rest.len() >= ENTRY_FIXED {
            let inode = u64::from_le_bytes(
                rest.get(0..8)
                    .ok_or(V3Error::Corrupt)?
                    .try_into()
                    .map_err(|_| V3Error::Corrupt)?,
            );
            if inode == 0 {
                break; // zero padding / terminator
            }
            let len = *rest.get(8).ok_or(V3Error::Corrupt)? as usize;
            let name_bytes = rest
                .get(ENTRY_FIXED..ENTRY_FIXED + len)
                .ok_or(V3Error::Corrupt)?;
            let name = core::str::from_utf8(name_bytes).map_err(|_| V3Error::Corrupt)?;
            entries.push(DirEntry {
                inode,
                name: String::from(name),
            });
            rest = rest.get(ENTRY_FIXED + len..).unwrap_or(&[]);
        }
        Ok(Self { entries })
    }
}

/// Resolve a slash-free component path from `root_inode`.
///
/// Each directory is loaded through `load` (`inode → Directory`); empty and `.`
/// components are skipped. Returns the final inode, or `None` if any component
/// is missing.
pub fn resolve_path(
    root_inode: u64,
    components: &[&str],
    mut load: impl FnMut(u64) -> Option<Directory>,
) -> Option<u64> {
    let mut current = root_inode;
    for comp in components {
        if comp.is_empty() || *comp == "." {
            continue;
        }
        let dir = load(current)?;
        current = dir.lookup(comp)?;
    }
    Some(current)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_rejects_bad_names() {
        assert!(validate_name("file.txt").is_ok());
        assert_eq!(validate_name(""), Err(V3Error::InvalidName));
        assert_eq!(validate_name("a/b"), Err(V3Error::InvalidName));
        assert_eq!(validate_name("."), Err(V3Error::InvalidName));
        assert_eq!(validate_name(".."), Err(V3Error::InvalidName));
        let long = "x".repeat(NAME_MAX + 1);
        assert_eq!(validate_name(&long), Err(V3Error::InvalidName));
    }

    #[test]
    fn insert_lookup_remove() {
        let mut d = Directory::new();
        d.insert("alpha", 10, &AsciiNfc).unwrap();
        d.insert("beta", 11, &AsciiNfc).unwrap();
        assert_eq!(d.len(), 2);
        assert_eq!(d.lookup("alpha"), Some(10));
        assert_eq!(d.lookup("missing"), None);
        // Duplicate rejected.
        assert!(d.insert("alpha", 99, &AsciiNfc).is_err());
        assert_eq!(d.remove("alpha"), Some(10));
        assert!(d.lookup("alpha").is_none());
    }

    #[test]
    fn ascii_nfc_rejects_non_ascii_by_default() {
        let mut d = Directory::new();
        // "café" is non-ASCII → conservative AsciiNfc rejects it.
        assert_eq!(d.insert("café", 1, &AsciiNfc), Err(V3Error::InvalidName));
    }

    #[test]
    fn non_ascii_accepted_with_real_normalizer() {
        struct AlwaysNfc;
        impl NfcCheck for AlwaysNfc {
            fn is_nfc(&self, _: &str) -> bool {
                true
            }
        }
        let mut d = Directory::new();
        d.insert("café", 1, &AlwaysNfc).unwrap();
        assert_eq!(d.lookup("café"), Some(1));
    }

    #[test]
    fn encode_decode_round_trips() {
        let mut d = Directory::new();
        d.insert("readme.md", 2, &AsciiNfc).unwrap();
        d.insert("src", 3, &AsciiNfc).unwrap();
        let back = Directory::decode(&d.encode()).unwrap();
        assert_eq!(back, d);
    }

    #[test]
    fn decode_rejects_truncated_entry() {
        // inode(8) + len=10 but no name bytes.
        let mut buf = 7u64.to_le_bytes().to_vec();
        buf.push(10);
        assert_eq!(Directory::decode(&buf), Err(V3Error::Corrupt));
    }

    #[test]
    fn path_resolution_walks_the_tree() {
        // / (1) → "usr" (2) → "bin" (3)
        let mut root = Directory::new();
        root.insert("usr", 2, &AsciiNfc).unwrap();
        let mut usr = Directory::new();
        usr.insert("bin", 3, &AsciiNfc).unwrap();
        let load = |ino: u64| match ino {
            1 => Some(root.clone()),
            2 => Some(usr.clone()),
            _ => None,
        };
        assert_eq!(resolve_path(1, &["usr", "bin"], load), Some(3));
        assert_eq!(resolve_path(1, &["usr", "missing"], load), None);
        assert_eq!(resolve_path(1, &[], load), Some(1));
    }
}
