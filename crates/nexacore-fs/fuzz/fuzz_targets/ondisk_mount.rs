//! Fuzz target: the on-disk volume parser must never panic on a corrupt or
//! adversarial disk image (WS13-02.3).
//!
//! `OnDiskVolume::mount` is the trust boundary for untrusted block devices. On
//! any byte slice it MUST return `Ok(_)` or `Err(FsError::..)` — never panic on
//! a bad superblock, out-of-range inode pointer, or truncated image. When a
//! mount succeeds, we additionally exercise the read-only inspection paths
//! (`fsck`, `superblock`, `free_blocks`, `list_directory`) which walk the
//! parsed structures and are the most likely to trip a latent bounds bug.

#![no_main]

use libfuzzer_sys::fuzz_target;
use nexacore_fs::ondisk::OnDiskVolume;

fuzz_target!(|data: &[u8]| {
    if let Ok(volume) = OnDiskVolume::mount(data) {
        // Walk the parsed structures via the read-only inspection surface.
        let _ = volume.fsck();
        let _ = volume.superblock();
        let _ = volume.free_blocks();
        let _ = volume.list_directory("/");
        let _ = volume.exists("/");
    }
});
