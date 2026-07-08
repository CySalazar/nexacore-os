//! Fuzz target: the NCFS v3 parse/mount trust boundary must never panic on
//! corrupt or adversarial bytes (WS3-01.14, gate §S9.5).
//!
//! Every v3 decoder — the superblock, inode, directory object, and extent — and
//! the dual-superblock `mount` walk untrusted on-disk bytes. On any input they
//! MUST return `Ok(_)` or `Err(V3Error::..)`, never panic on a bad magic,
//! version, length, or out-of-range field. The device-backed `mount` is
//! additionally exercised over a block image built from the fuzz bytes.

#![no_main]

use libfuzzer_sys::fuzz_target;
use nexacore_fs::v3::{
    BLOCK_SIZE,
    blockdev::{BlockDevice, MemBlockDevice},
    dirent::Directory,
    extent::Extent,
    inode::InodeV3,
    superblock::{self, SuperblockV3},
};

fuzz_target!(|data: &[u8]| {
    let key = [0u8; 32];

    // Object parsers over arbitrary byte slices.
    let _ = InodeV3::decode(data);
    let _ = Directory::decode(data);
    let _ = Extent::decode(data);

    // Superblock decode over a block-sized window of the input.
    let mut block = [0u8; BLOCK_SIZE];
    let n = data.len().min(BLOCK_SIZE);
    block[..n].copy_from_slice(&data[..n]);
    let _ = SuperblockV3::decode(&block, &key);

    // Mount over a device populated from the fuzz bytes (needs at least the two
    // superblock slots).
    if data.len() >= BLOCK_SIZE {
        let block_count = (data.len() / BLOCK_SIZE).max(2) as u64;
        let mut dev = MemBlockDevice::new(block_count);
        for i in 0..block_count {
            let start = (i as usize) * BLOCK_SIZE;
            let mut b = [0u8; BLOCK_SIZE];
            if let Some(chunk) = data.get(start..start + BLOCK_SIZE) {
                b.copy_from_slice(chunk);
            } else if let Some(tail) = data.get(start..) {
                b[..tail.len()].copy_from_slice(tail);
            }
            let _ = dev.write_block(i, &b);
        }
        let _ = superblock::mount(&dev, &key);
    }
});
