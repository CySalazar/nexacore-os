//! FAT16 write path for staging the UEFI bootloader into a fresh ESP.
//!
//! Cluster allocation, directory creation, and file placement (WS11-03.6).
//!
//! This is the mutating counterpart to the read-only [`crate::FatFs`]: it
//! borrows the same on-disk image **mutably** and grows it in place. The only
//! entry point is [`FatWriter::write_file`], which
//!
//! * splits a DOS-style path (`\EFI\BOOT\BOOTX64.EFI`) into 8.3 components,
//! * auto-creates any missing parent directories (allocating a cluster and
//!   seeding `.`/`..` for each),
//! * allocates a FAT chain for the file data and writes it across the clusters,
//! * and records a directory entry with the first cluster and byte size.
//!
//! It writes **FAT16 only** (matching [`crate::mkfat`]) and only 8.3 short
//! names — enough for the ESP's `\EFI\BOOT\BOOTX64.EFI`, and correctly read
//! back by this crate's own reader. Everything is fail-closed: an out-of-space
//! volume, a full directory, an already-present name, or a path that does not
//! fit an 8.3 name returns an error and mutates nothing further.

use alloc::vec::Vec;

use crate::{Bpb, FatError, FatType};

/// The FAT16 values that denote an in-use, followable data cluster: `2` up to
/// (but not including) the `0xFFF8` reserved/end-of-chain band. A `next` value
/// outside this range terminates a chain walk.
const DATA_CLUSTERS: core::ops::Range<u32> = 2..0xFFF8;
/// FAT16 end-of-chain marker written for the last cluster of a chain.
const FAT16_EOC: u16 = 0xFFFF;
/// A free FAT entry.
const FAT16_FREE: u16 = 0x0000;
/// Bytes per directory entry.
const DIR_ENTRY_SIZE: usize = 32;
/// `0xE5` — a deleted directory entry (also treated as a free slot).
const ENTRY_DELETED: u8 = 0xE5;
/// Directory attribute bit.
const ATTR_DIRECTORY: u8 = 0x10;
/// Archive attribute bit (set on ordinary files).
const ATTR_ARCHIVE: u8 = 0x20;

/// Where a directory lives: either the fixed FAT16 root region or the cluster
/// chain rooted at `first_cluster`.
#[derive(Clone, Copy)]
enum Dir {
    /// The fixed-size FAT12/16 root directory region.
    Root,
    /// A subdirectory whose chain starts at this cluster.
    Chain(u32),
}

/// A located directory entry: its first data cluster and whether it is a dir.
struct Found {
    first_cluster: u32,
    is_dir: bool,
}

/// A mutable FAT16 volume: the write counterpart of [`crate::FatFs`].
///
/// Borrows the image mutably and grows it in place; drop it before re-opening
/// the image read-only.
pub struct FatWriter<'a> {
    image: &'a mut [u8],
    cluster_size: usize,
    fat_start: usize,
    fat_size_bytes: usize,
    num_fats: usize,
    root_start: usize,
    root_slots: usize,
    data_start: usize,
    cluster_count: u32,
}

impl<'a> FatWriter<'a> {
    /// Wrap a mutable FAT16 image for writing.
    ///
    /// # Errors
    /// [`FatError`] if the BPB is unparseable, and [`FatError::Unsupported`] if
    /// the volume is not FAT16 (the only width this writer emits).
    pub fn new(image: &'a mut [u8]) -> Result<Self, FatError> {
        let bpb = Bpb::parse(image)?;
        if bpb.fat_type() != FatType::Fat16 {
            return Err(FatError::Unsupported);
        }
        let bytes_per_sector = usize::from(bpb.bytes_per_sector);
        let cluster_size = usize::from(bpb.sectors_per_cluster) * bytes_per_sector;
        let fat_start = usize::from(bpb.reserved_sectors) * bytes_per_sector;
        let fat_size_bytes = bpb.fat_size_sectors as usize * bytes_per_sector;
        let num_fats = usize::from(bpb.num_fats);
        let root_start = (usize::from(bpb.reserved_sectors)
            + num_fats * bpb.fat_size_sectors as usize)
            * bytes_per_sector;
        let root_slots = usize::from(bpb.root_entries);
        let data_start = bpb.first_data_sector() as usize * bytes_per_sector;
        let cluster_count = bpb.cluster_count();
        Ok(Self {
            image,
            cluster_size,
            fat_start,
            fat_size_bytes,
            num_fats,
            root_start,
            root_slots,
            data_start,
            cluster_count,
        })
    }

    /// Create `path` (DOS-style, e.g. `\EFI\BOOT\BOOTX64.EFI`) with `data`,
    /// auto-creating any missing parent directories.
    ///
    /// # Errors
    /// * [`FatError::InvalidPath`] — empty path, a component that does not fit
    ///   an 8.3 short name, a parent that names an existing *file*, or a target
    ///   name that already exists.
    /// * [`FatError::NoSpace`] — no free cluster or directory slot remains.
    pub fn write_file(&mut self, path: &str, data: &[u8]) -> Result<(), FatError> {
        let components = split_path(path)?;
        let (file_name, dirs) = components.split_last().ok_or(FatError::InvalidPath)?;

        // Walk (creating as needed) to the parent directory.
        let mut dir = Dir::Root;
        for component in dirs {
            let name = encode_8_3(component)?;
            match self.find(dir, &name)? {
                Some(f) if f.is_dir => dir = Dir::Chain(f.first_cluster),
                Some(_) => return Err(FatError::InvalidPath), // a file blocks the path
                None => dir = self.create_dir(dir, &name)?,
            }
        }

        // The file itself must not already exist.
        let name = encode_8_3(file_name)?;
        if self.find(dir, &name)?.is_some() {
            return Err(FatError::InvalidPath);
        }

        let first_cluster = self.write_data_chain(data)?;
        self.add_entry(
            dir,
            &name,
            ATTR_ARCHIVE,
            first_cluster,
            u32::try_from(data.len()).map_err(|_| FatError::NoSpace)?,
        )?;
        Ok(())
    }

    // --- FAT table -----------------------------------------------------------

    /// Read the FAT16 entry for `cluster` (from the first FAT copy).
    fn fat_get(&self, cluster: u32) -> Result<u16, FatError> {
        let off = self.fat_start + (cluster as usize) * 2;
        rd_u16(self.image, off)
    }

    /// Write the FAT16 entry for `cluster` into every FAT copy.
    fn fat_set(&mut self, cluster: u32, value: u16) -> Result<(), FatError> {
        for copy in 0..self.num_fats {
            let off = self.fat_start + copy * self.fat_size_bytes + (cluster as usize) * 2;
            wr_u16(self.image, off, value)?;
        }
        Ok(())
    }

    /// Allocate one free cluster, mark it end-of-chain, and zero its data.
    ///
    /// # Errors
    /// [`FatError::NoSpace`] when no free cluster remains.
    fn alloc_cluster(&mut self) -> Result<u32, FatError> {
        // Valid data clusters are numbered 2..(cluster_count + 2).
        let last = self.cluster_count + 1;
        for cluster in 2..=last {
            if self.fat_get(cluster)? == FAT16_FREE {
                self.fat_set(cluster, FAT16_EOC)?;
                self.zero_cluster(cluster)?;
                return Ok(cluster);
            }
        }
        Err(FatError::NoSpace)
    }

    // --- data clusters -------------------------------------------------------

    /// Byte offset of a data cluster (`>= 2`) within the image.
    fn cluster_offset(&self, cluster: u32) -> Result<usize, FatError> {
        let rel = cluster.checked_sub(2).ok_or(FatError::BadCluster)? as usize;
        rel.checked_mul(self.cluster_size)
            .and_then(|o| o.checked_add(self.data_start))
            .ok_or(FatError::BadCluster)
    }

    /// Overwrite an entire cluster with zeros.
    fn zero_cluster(&mut self, cluster: u32) -> Result<(), FatError> {
        let start = self.cluster_offset(cluster)?;
        let end = start
            .checked_add(self.cluster_size)
            .ok_or(FatError::BadCluster)?;
        let slot = self.image.get_mut(start..end).ok_or(FatError::Truncated)?;
        slot.fill(0);
        Ok(())
    }

    /// Allocate a chain for `data` and write it across the clusters.
    ///
    /// Returns the first cluster, or `0` for empty data (an empty file has no
    /// chain, matching how the reader treats `first_cluster < 2`).
    ///
    /// # Errors
    /// [`FatError::NoSpace`] when the volume cannot hold the data.
    fn write_data_chain(&mut self, data: &[u8]) -> Result<u32, FatError> {
        if data.is_empty() {
            return Ok(0);
        }
        let mut first: u32 = 0;
        let mut prev: u32 = 0;
        for chunk in data.chunks(self.cluster_size) {
            let cluster = self.alloc_cluster()?;
            if first == 0 {
                first = cluster;
            } else {
                // Link the previous cluster to this one (keep this one as EOC).
                let link = u16::try_from(cluster).map_err(|_| FatError::BadCluster)?;
                self.fat_set(prev, link)?;
            }
            let start = self.cluster_offset(cluster)?;
            let end = start.checked_add(chunk.len()).ok_or(FatError::BadCluster)?;
            let slot = self.image.get_mut(start..end).ok_or(FatError::Truncated)?;
            slot.copy_from_slice(chunk);
            prev = cluster;
        }
        Ok(first)
    }

    // --- directories ---------------------------------------------------------

    /// The absolute byte offsets of every 32-byte slot in `dir`, in order.
    ///
    /// For a subdirectory this walks the cluster chain (bounded by the cluster
    /// count so a hostile cycle cannot loop forever).
    #[allow(
        clippy::integer_division,
        reason = "cluster_size / DIR_ENTRY_SIZE is the exact slots-per-cluster count"
    )]
    fn dir_slots(&self, dir: Dir) -> Result<Vec<usize>, FatError> {
        let mut slots = Vec::new();
        match dir {
            Dir::Root => {
                for i in 0..self.root_slots {
                    slots.push(self.root_start + i * DIR_ENTRY_SIZE);
                }
            }
            Dir::Chain(first) => {
                let per_cluster = self.cluster_size / DIR_ENTRY_SIZE;
                let mut cluster = first;
                let max_steps = self.cluster_count as usize + 2;
                for _ in 0..max_steps {
                    if cluster < 2 {
                        break;
                    }
                    let base = self.cluster_offset(cluster)?;
                    for i in 0..per_cluster {
                        slots.push(base + i * DIR_ENTRY_SIZE);
                    }
                    let next = u32::from(self.fat_get(cluster)?);
                    if !DATA_CLUSTERS.contains(&next) {
                        break;
                    }
                    if next == cluster {
                        return Err(FatError::ChainCycle);
                    }
                    cluster = next;
                }
            }
        }
        Ok(slots)
    }

    /// Find an entry named `name` (raw 11-byte 8.3 field) in `dir`.
    fn find(&self, dir: Dir, name: &[u8; 11]) -> Result<Option<Found>, FatError> {
        for off in self.dir_slots(dir)? {
            let raw = self
                .image
                .get(off..off + DIR_ENTRY_SIZE)
                .ok_or(FatError::Truncated)?;
            let first = *raw.first().ok_or(FatError::Truncated)?;
            if first == 0x00 {
                break; // end of directory
            }
            if first == ENTRY_DELETED {
                continue;
            }
            let attr = *raw.get(11).ok_or(FatError::Truncated)?;
            if attr == 0x0F || attr & 0x08 != 0 {
                continue; // LFN fragment or volume label
            }
            if raw.get(0..11) == Some(name.as_slice()) {
                let hi = u32::from(rd_u16(raw, 20)?);
                let lo = u32::from(rd_u16(raw, 26)?);
                return Ok(Some(Found {
                    first_cluster: (hi << 16) | lo,
                    is_dir: attr & ATTR_DIRECTORY != 0,
                }));
            }
        }
        Ok(None)
    }

    /// Find a free slot offset in `dir`, extending a subdirectory chain by one
    /// cluster if it is full. The fixed root cannot be extended.
    ///
    /// # Errors
    /// [`FatError::NoSpace`] if the root is full or no cluster is free.
    fn free_slot(&mut self, dir: Dir) -> Result<usize, FatError> {
        for off in self.dir_slots(dir)? {
            let first = *self.image.get(off).ok_or(FatError::Truncated)?;
            if first == 0x00 || first == ENTRY_DELETED {
                return Ok(off);
            }
        }
        match dir {
            Dir::Root => Err(FatError::NoSpace),
            Dir::Chain(first) => {
                // Append a fresh cluster to the chain and use its first slot.
                let last = self.chain_last(first)?;
                let fresh = self.alloc_cluster()?;
                let link = u16::try_from(fresh).map_err(|_| FatError::BadCluster)?;
                self.fat_set(last, link)?;
                self.cluster_offset(fresh)
            }
        }
    }

    /// The last cluster of the chain starting at `first`.
    fn chain_last(&self, first: u32) -> Result<u32, FatError> {
        let mut cluster = first;
        let max_steps = self.cluster_count as usize + 2;
        for _ in 0..max_steps {
            let next = u32::from(self.fat_get(cluster)?);
            if !DATA_CLUSTERS.contains(&next) {
                return Ok(cluster);
            }
            if next == cluster {
                return Err(FatError::ChainCycle);
            }
            cluster = next;
        }
        Err(FatError::ChainCycle)
    }

    /// Write a raw 8.3 directory entry into a free slot of `dir`.
    fn add_entry(
        &mut self,
        dir: Dir,
        name: &[u8; 11],
        attr: u8,
        first_cluster: u32,
        size: u32,
    ) -> Result<(), FatError> {
        let off = self.free_slot(dir)?;
        self.write_entry_at(off, name, attr, first_cluster, size)
    }

    /// Write a raw 8.3 directory entry at absolute offset `off`.
    fn write_entry_at(
        &mut self,
        off: usize,
        name: &[u8; 11],
        attr: u8,
        first_cluster: u32,
        size: u32,
    ) -> Result<(), FatError> {
        // Zero the whole 32-byte slot first, then lay down the fields.
        self.image
            .get_mut(off..off + DIR_ENTRY_SIZE)
            .ok_or(FatError::Truncated)?
            .fill(0);
        wr_bytes(self.image, off, name)?;
        wr_u8(self.image, off + 11, attr)?;
        // High and low 16 bits of the first cluster (FAT16 uses only the low).
        let low = u16::try_from(first_cluster & 0xFFFF).unwrap_or(0);
        let high = u16::try_from(first_cluster >> 16).unwrap_or(0);
        wr_u16(self.image, off + 20, high)?;
        wr_u16(self.image, off + 26, low)?;
        wr_u32(self.image, off + 28, size)?;
        Ok(())
    }

    /// Create a subdirectory named `name` inside `parent`, seed its `.`/`..`
    /// entries, and return its location.
    ///
    /// # Errors
    /// [`FatError::NoSpace`] when out of clusters or directory slots.
    fn create_dir(&mut self, parent: Dir, name: &[u8; 11]) -> Result<Dir, FatError> {
        let cluster = self.alloc_cluster()?; // zeroed on allocation
        // "." points to the directory itself.
        let dot = *b".          ";
        let dotdot = *b"..         ";
        let base = self.cluster_offset(cluster)?;
        self.write_entry_at(base, &dot, ATTR_DIRECTORY, cluster, 0)?;
        // ".." points to the parent (cluster 0 when the parent is the root).
        let parent_cluster = match parent {
            Dir::Root => 0,
            Dir::Chain(c) => c,
        };
        self.write_entry_at(
            base + DIR_ENTRY_SIZE,
            &dotdot,
            ATTR_DIRECTORY,
            parent_cluster,
            0,
        )?;
        // Link the new directory into its parent.
        self.add_entry(parent, name, ATTR_DIRECTORY, cluster, 0)?;
        Ok(Dir::Chain(cluster))
    }
}

/// Split a DOS-style path (`\EFI\BOOT\BOOTX64.EFI`) into its components,
/// accepting both `\` and `/` separators and ignoring empty segments.
///
/// # Errors
/// [`FatError::InvalidPath`] if no non-empty component remains.
fn split_path(path: &str) -> Result<Vec<&str>, FatError> {
    let components: Vec<&str> = path.split(['\\', '/']).filter(|c| !c.is_empty()).collect();
    if components.is_empty() {
        return Err(FatError::InvalidPath);
    }
    Ok(components)
}

/// Encode one path component into an 11-byte, space-padded 8.3 short name
/// (upper-cased). Rejects names that do not fit 8 + 3.
///
/// # Errors
/// [`FatError::InvalidPath`] on an empty name, a base longer than 8, an
/// extension longer than 3, more than one `.`, or a non-8.3 byte.
fn encode_8_3(component: &str) -> Result<[u8; 11], FatError> {
    if component.is_empty() || component == "." || component == ".." {
        return Err(FatError::InvalidPath);
    }
    let mut parts = component.splitn(2, '.');
    let base = parts.next().unwrap_or("");
    let ext = parts.next().unwrap_or("");
    // A second '.' inside the extension is not representable in 8.3.
    if ext.contains('.') {
        return Err(FatError::InvalidPath);
    }
    if base.is_empty() || base.len() > 8 || ext.len() > 3 {
        return Err(FatError::InvalidPath);
    }
    let mut field = [b' '; 11];
    encode_field(base, &mut field[0..8])?;
    encode_field(ext, &mut field[8..11])?;
    Ok(field)
}

/// Upper-case and validate one 8.3 field (base or extension) into `dst`.
fn encode_field(src: &str, dst: &mut [u8]) -> Result<(), FatError> {
    for (i, ch) in src.chars().enumerate() {
        if !ch.is_ascii() {
            return Err(FatError::InvalidPath);
        }
        let b = ch as u8;
        // Reject control characters, spaces, and characters illegal in 8.3.
        if b <= b' '
            || matches!(
                b,
                b'"' | b'*'
                    | b'+'
                    | b','
                    | b'/'
                    | b':'
                    | b';'
                    | b'<'
                    | b'='
                    | b'>'
                    | b'?'
                    | b'['
                    | b'\\'
                    | b']'
                    | b'|'
                    | 0x7F
            )
        {
            return Err(FatError::InvalidPath);
        }
        *dst.get_mut(i).ok_or(FatError::InvalidPath)? = b.to_ascii_uppercase();
    }
    Ok(())
}

/// Read a little-endian `u16` at `off`, bounds-checked.
fn rd_u16(b: &[u8], off: usize) -> Result<u16, FatError> {
    b.get(off..off + 2)
        .and_then(|s| s.try_into().ok())
        .map(u16::from_le_bytes)
        .ok_or(FatError::Truncated)
}

/// Write a single byte at `off`, bounds-checked.
fn wr_u8(b: &mut [u8], off: usize, v: u8) -> Result<(), FatError> {
    *b.get_mut(off).ok_or(FatError::Truncated)? = v;
    Ok(())
}

/// Copy `src` to `off`, bounds-checked.
fn wr_bytes(b: &mut [u8], off: usize, src: &[u8]) -> Result<(), FatError> {
    b.get_mut(off..off + src.len())
        .ok_or(FatError::Truncated)?
        .copy_from_slice(src);
    Ok(())
}

/// Write a little-endian `u16` at `off`, bounds-checked.
fn wr_u16(b: &mut [u8], off: usize, v: u16) -> Result<(), FatError> {
    b.get_mut(off..off + 2)
        .ok_or(FatError::Truncated)?
        .copy_from_slice(&v.to_le_bytes());
    Ok(())
}

/// Write a little-endian `u32` at `off`, bounds-checked.
fn wr_u32(b: &mut [u8], off: usize, v: u32) -> Result<(), FatError> {
    b.get_mut(off..off + 4)
        .ok_or(FatError::Truncated)?
        .copy_from_slice(&v.to_le_bytes());
    Ok(())
}

#[cfg(test)]
mod tests {
    use alloc::vec::Vec;

    use super::*;
    use crate::{DirEntry, FatFs, mkfat::format_fat16};

    /// 8 MiB ESP → FAT16 with 512-byte clusters (so >512-byte files span
    /// multiple clusters and genuinely exercise the FAT chain).
    fn fresh_esp() -> Vec<u8> {
        format_fat16(16_384, b"ESP").unwrap()
    }

    /// Read a file back through the crate's own reader by walking `path`.
    fn read_back(image: &[u8], path: &str) -> Vec<u8> {
        let fs = FatFs::open(image).unwrap();
        let comps: Vec<&str> = path.split('\\').filter(|c| !c.is_empty()).collect();
        let (file, dirs) = comps.split_last().unwrap();
        let mut entries = fs.root().unwrap();
        for dir in dirs {
            let e: DirEntry = entries
                .iter()
                .find(|e| e.name.eq_ignore_ascii_case(dir))
                .unwrap()
                .clone();
            entries = fs.read_dir(&e).unwrap();
        }
        let f = entries
            .iter()
            .find(|e| e.name.eq_ignore_ascii_case(file))
            .unwrap();
        fs.read_file(f).unwrap()
    }

    #[test]
    fn writes_a_single_cluster_file_readable_by_the_reader() {
        let mut img = fresh_esp();
        let data = b"UEFI stub\n";
        FatWriter::new(&mut img)
            .unwrap()
            .write_file("\\HELLO.BIN", data)
            .unwrap();
        assert_eq!(read_back(&img, "\\HELLO.BIN"), data);
    }

    #[test]
    fn writes_a_multi_cluster_file() {
        let mut img = fresh_esp();
        // 2000 bytes over 512-byte clusters → 4 clusters, non-trivial chain.
        let data: Vec<u8> = (0..2000u32).map(|i| (i & 0xFF) as u8).collect();
        FatWriter::new(&mut img)
            .unwrap()
            .write_file("\\BIG.DAT", &data)
            .unwrap();
        let back = read_back(&img, "\\BIG.DAT");
        assert_eq!(back.len(), data.len());
        assert_eq!(back, data);
    }

    #[test]
    fn auto_creates_nested_parent_dirs_for_bootloader() {
        let mut img = fresh_esp();
        // A realistic bootloader image spanning several clusters.
        let boot: Vec<u8> = (0..3000u32)
            .map(|i| (i.wrapping_mul(7) & 0xFF) as u8)
            .collect();
        FatWriter::new(&mut img)
            .unwrap()
            .write_file("\\EFI\\BOOT\\BOOTX64.EFI", &boot)
            .unwrap();

        // The reader must now navigate the auto-created EFI and BOOT dirs.
        let fs = FatFs::open(&img).unwrap();
        let efi = fs
            .root()
            .unwrap()
            .into_iter()
            .find(|e| e.name == "EFI")
            .unwrap();
        assert!(efi.is_dir);
        let boot_dir = fs
            .read_dir(&efi)
            .unwrap()
            .into_iter()
            .find(|e| e.name == "BOOT")
            .unwrap();
        assert!(boot_dir.is_dir);
        assert_eq!(read_back(&img, "\\EFI\\BOOT\\BOOTX64.EFI"), boot);
    }

    #[test]
    fn two_files_in_the_same_new_dir_coexist() {
        let mut img = fresh_esp();
        {
            let mut w = FatWriter::new(&mut img).unwrap();
            w.write_file("\\EFI\\BOOT\\BOOTX64.EFI", b"aaa").unwrap();
            w.write_file("\\EFI\\BOOT\\BOOTIA32.EFI", b"bbbb").unwrap();
        }
        assert_eq!(read_back(&img, "\\EFI\\BOOT\\BOOTX64.EFI"), b"aaa");
        assert_eq!(read_back(&img, "\\EFI\\BOOT\\BOOTIA32.EFI"), b"bbbb");
    }

    #[test]
    fn rejects_invalid_paths() {
        let mut img = fresh_esp();
        let mut w = FatWriter::new(&mut img).unwrap();
        assert_eq!(w.write_file("", b"x").err(), Some(FatError::InvalidPath));
        assert_eq!(w.write_file("\\", b"x").err(), Some(FatError::InvalidPath));
        // A name component longer than the 8.3 base field.
        assert_eq!(
            w.write_file("\\TOOLONGNAME.EFI", b"x").err(),
            Some(FatError::InvalidPath)
        );
    }

    #[test]
    fn rejects_duplicate_file() {
        let mut img = fresh_esp();
        let mut w = FatWriter::new(&mut img).unwrap();
        w.write_file("\\A.BIN", b"first").unwrap();
        assert_eq!(
            w.write_file("\\A.BIN", b"second").err(),
            Some(FatError::InvalidPath)
        );
    }

    #[test]
    fn fails_closed_on_out_of_space() {
        let mut img = fresh_esp();
        let mut w = FatWriter::new(&mut img).unwrap();
        // Far larger than the ~8 MiB volume: must fail-closed, not panic.
        let huge: Vec<u8> = alloc::vec![0xAB; 32 * 1024 * 1024];
        assert_eq!(
            w.write_file("\\HUGE.BIN", &huge).err(),
            Some(FatError::NoSpace)
        );
    }
}
