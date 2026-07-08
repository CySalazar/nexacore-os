#!/usr/bin/env bash
# =============================================================================
# NexaCore OS — Build initramfs archive
# =============================================================================
# Builds the bare-metal Ring 3 image crates for x86_64-unknown-none, then packs
# them into the flat initramfs format expected by nexacore_kernel::initramfs.
#
# Output: crates/nexacore-kernel/src/embedded_initramfs.bin
#
# The kernel embeds this file via include_bytes! and loads every entry into the
# VFS under /bin/<name> at boot. Running this script is a prerequisite for
# booting into the shell and the userspace network stack.
#
# Packed entries (in order):
#   /bin/nexacore-shell             ← crates/nexacore-shell-image            (PID-1 shell)
#   /bin/nexacore-net               ← crates/nexacore-net-image              (TCP/IP service)
#   /bin/nexacore-netcheck          ← crates/nexacore-netcheck-image         (M0 self-test)
#   /bin/nexacore-runtime           ← crates/nexacore-runtime-image           (AI service, TASK-11)
#   /bin/nexacore-aicheck           ← crates/nexacore-aicheck-image           (TASK-11 self-test)
#   /bin/nexacore-driver-net-virtio ← crates/nexacore-driver-net-virtio-image (NIC driver)
#
# NOTE: the virtio-net driver IS packed here for M0. The kernel spawns it at
# boot (after the DEV-ONLY probe loader, before nexacore-net) and deposits its
# MmioMap/DmaMap/IrqAttach capability tokens via the same cap-deposit machinery
# the probe loader uses — NOT via the signed DriverLoad (73) path, which is
# deferred to a later milestone (identical deposit format).
#
# Usage:
#   scripts/build-shell-initramfs.sh              # release build (default)
#   scripts/build-shell-initramfs.sh --debug      # debug build
# =============================================================================

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUTPUT="${REPO_ROOT}/crates/nexacore-kernel/src/embedded_initramfs.bin"

PROFILE="release"
if [[ "${1:-}" == "--debug" ]]; then
    PROFILE="debug"
fi

# Portable byte size of a file. GNU `stat -c%s` and BSD/macOS `stat -f%z` are
# incompatible, so use `wc -c` (works on both) and strip whitespace.
file_size() { wc -c < "$1" | tr -d '[:space:]'; }

# -------------------------------------------------------------------------
# Entry table: "vfs_name|crate_dir|elf_basename"
# The VFS name is what the kernel spawns (/bin/<vfs_name>); elf_basename is
# the compiled binary under target/x86_64-unknown-none/<profile>/.
# -------------------------------------------------------------------------
ENTRIES=(
    "nexacore-shell|crates/nexacore-shell-image|nexacore-shell-image"
    "nexacore-net|crates/nexacore-net-image|nexacore-net-image"
    "nexacore-netcheck|crates/nexacore-netcheck-image|nexacore-netcheck-image"
    "nexacore-runtime|crates/nexacore-runtime-image|nexacore-runtime-image"
    "nexacore-aicheck|crates/nexacore-aicheck-image|nexacore-aicheck-image"
    "nexacore-driver-net-virtio|crates/nexacore-driver-net-virtio-image|nexacore-driver-net-virtio-image"
    # TASK-14 (ADR-0036): Ring 3 NVMe block driver + BLK service smoke client.
    # blkcheck stays packed for NVMe-driver regression smokes but is NOT
    # boot-spawned (it would corrupt the nexacore-fsd volume — see kmain).
    "nexacore-driver-nvme|crates/nexacore-driver-nvme-image|nexacore-driver-nvme-image"
    "nexacore-blkcheck|crates/nexacore-blkcheck-image|nexacore-blkcheck-image"
    # TASK-15 (ADR-0037): NCFS root daemon — mounts the on-disk root from
    # nvme0 (or formats a fresh one) and proves reboot persistence.
    "nexacore-fsd|crates/nexacore-fsd-image|nexacore-fsd-image"
    # TASK-18 (DE-C1, ADR-0040): display-map + input-event smoke probe.
    # Validates DisplayMap (79) and the display-input IPC channel on VM-103
    # (serial capture + colour-bar visual check).
    "nexacore-display-probe|crates/nexacore-display-probe|nexacore-display-probe"
    # TASK-19 (DE-C2/DE-C3, ADR-0041): Ring 3 compositor + window manager image.
    # Maps the framebuffer, drives the nexacore-display Compositor, creates three
    # overlapping test windows, and runs an input loop exercising focus switch
    # and window destruction (no ghosting). VM-103 acceptance artifact.
    "nexacore-display-image|crates/nexacore-display-image|nexacore-display-image"
    # TASK-20 (DE-C4/DE-C5, ADR-0042): Ring 3 nexacore-ui widget demo image.
    # Renders a single window with an nexacore-ui widget tree (title label +
    # TextInput + Submit button + status label) in brand colours; input loop
    # drives the TextInput on keystroke and Submit on Enter.
    # VM-103 acceptance artifact ("finestra demo con widget interattivi e
    # testo leggibile"). The kernel display boot-spawn prefers this over
    # nexacore-display-image (/bin/nexacore-ui-demo-image).
    "nexacore-ui-demo-image|crates/nexacore-ui-demo-image|nexacore-ui-demo-image"
    # TASK-22 (DE-D1/DE-D4, ADR-0044): Ring 3 windowed terminal + text editor
    # display image.  Hosts two nexacore-ui windows: an nexacore-shell terminal (left)
    # and an NCFS-backed text editor (/notes.txt, right).  Tab cycles focus;
    # Esc saves the editor buffer via the IPC FS service.  M4 acceptance
    # artifact.  The kernel display boot-spawn prefers this over
    # nexacore-ui-demo-image (/bin/nexacore-apps-image).
    "nexacore-apps-image|crates/nexacore-apps-image|nexacore-apps-image"
    # TASK-26 (ADR-0048): Ring 3 xHCI USB host controller driver.
    # Enumerates root-hub ports via the Phase-1 Enumerator state machine and
    # logs the discovered device VID/PID.  Loaded best-effort by the kernel at
    # boot (additive; absent image → log + continue).
    "nexacore-driver-xhci|crates/nexacore-driver-xhci-image|nexacore-driver-xhci-image"
)

# -------------------------------------------------------------------------
# Step 1: build each image crate
# -------------------------------------------------------------------------
declare -a NAMES ELF_PATHS ELF_SIZES
for entry in "${ENTRIES[@]}"; do
    IFS='|' read -r vfs_name crate_dir elf_base <<< "${entry}"
    echo "[initramfs] Building ${crate_dir} (${PROFILE})..."
    if [[ "${PROFILE}" == "release" ]]; then
        cargo build --manifest-path "${REPO_ROOT}/${crate_dir}/Cargo.toml" \
            --target x86_64-unknown-none --release
    else
        cargo build --manifest-path "${REPO_ROOT}/${crate_dir}/Cargo.toml" \
            --target x86_64-unknown-none
    fi
    elf_path="${REPO_ROOT}/${crate_dir}/target/x86_64-unknown-none/${PROFILE}/${elf_base}"
    if [[ ! -f "${elf_path}" ]]; then
        echo "[initramfs] ERROR: ELF not found at ${elf_path}" >&2
        exit 1
    fi
    elf_size=$(file_size "${elf_path}")
    echo "[initramfs]   ${vfs_name}: ${elf_path} (${elf_size} bytes)"
    NAMES+=("${vfs_name}")
    ELF_PATHS+=("${elf_path}")
    ELF_SIZES+=("${elf_size}")
done

# -------------------------------------------------------------------------
# Step 2: pack into the flat initramfs archive format
# -------------------------------------------------------------------------
# Format per entry (matches nexacore_kernel::initramfs::build_archive):
#   [name_len: u16 LE] [name] [elf_len: u32 LE] [elf]
# Entries are concatenated; the parser walks them until the buffer ends.

# Append a single entry to OUTPUT. Args: name elf_path elf_size
pack_entry() {
    local name="$1" elf_path="$2" elf_size="$3"
    local name_len=${#name}
    {
        # name_len as u16 LE
        printf "\\x$(printf '%02x' $((name_len & 0xFF)))\\x$(printf '%02x' $(((name_len >> 8) & 0xFF)))"
        # name bytes
        printf '%s' "${name}"
        # elf_len as u32 LE
        printf "\\x$(printf '%02x' $((elf_size & 0xFF)))\\x$(printf '%02x' $(((elf_size >> 8) & 0xFF)))\\x$(printf '%02x' $(((elf_size >> 16) & 0xFF)))\\x$(printf '%02x' $(((elf_size >> 24) & 0xFF)))"
        # elf bytes
        cat "${elf_path}"
    } >> "${OUTPUT}"
}

echo "[initramfs] Packing ${#NAMES[@]} entries..."
: > "${OUTPUT}"   # truncate
for i in "${!NAMES[@]}"; do
    echo "[initramfs]   + ${NAMES[$i]} (${ELF_SIZES[$i]} bytes)"
    pack_entry "${NAMES[$i]}" "${ELF_PATHS[$i]}" "${ELF_SIZES[$i]}"
done

OUTPUT_SIZE=$(file_size "${OUTPUT}")
echo "[initramfs] Archive written: ${OUTPUT} (${OUTPUT_SIZE} bytes)"
echo "[initramfs] Done. Rebuild kernel-runner to pick up the embedded blob."
