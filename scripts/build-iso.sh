#!/usr/bin/env bash
# =============================================================================
# NexaCore OS — build a UEFI-bootable hybrid ISO from the current commit
# =============================================================================
#
# Produces a single .iso file that boots directly into the NexaCore OS graphical
# desktop on UEFI machines (QEMU, VirtualBox, VMware, physical hardware via
# USB stick). The ISO is a LIVE image — there is no installer (NexaCore OS does
# not yet have a persistent filesystem layer).
#
# Output layout:
#   dist/iso/nexacore-os-<short_sha>.iso   ← unique per commit
#   dist/iso/nexacore-os-latest.iso        ← symlink to the most recent build
#
# Both files are gitignored by default (see .gitignore). The directory itself
# is tracked via dist/iso/.gitkeep so the path always exists in the working
# tree.
#
# Prerequisites:
#   - xorriso (apt: xorriso)
#   - rustup; the nightly used by disk-image's bootloader 0.11 build.rs is
#     pinned in disk-image/rust-toolchain.toml and installed on demand
#
# Usage:
#   bash scripts/build-iso.sh                  # build ISO for HEAD
#   bash scripts/build-iso.sh --skip-build     # reuse existing boot-uefi.img
#   bash scripts/build-iso.sh --skip-initramfs # reuse existing embedded_initramfs.bin
#
# By default the ISO build regenerates the embedded initramfs (userspace image
# ELFs, including the branded desktop /bin/nexacore-apps-image) so the shipped
# image always matches the current tree.
# =============================================================================

set -euo pipefail

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
KERNEL_RUNNER_DIR="${REPO_ROOT}/kernel-runner"
DISK_IMAGE_DIR="${REPO_ROOT}/disk-image"
ISO_OUT_DIR="${REPO_ROOT}/dist/iso"
ISO_ROOT="${REPO_ROOT}/dist/.iso-root"
KERNEL_ELF="${KERNEL_RUNNER_DIR}/target/x86_64-unknown-none/release/kernel-runner"
UEFI_IMG="${KERNEL_RUNNER_DIR}/target/x86_64-unknown-none/release/boot-uefi.img"

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
log()  { echo "  [iso] $*"; }
ok()   { echo "  [iso] ✓ $*"; }
fail() { echo "  [iso] ✗ ERROR: $*" >&2; exit 1; }

SKIP_BUILD=0
SKIP_INITRAMFS=0
for arg in "$@"; do
    case "$arg" in
        --skip-build) SKIP_BUILD=1 ;;
        --skip-initramfs) SKIP_INITRAMFS=1 ;;
        -h|--help)
            sed -n '3,30p' "${BASH_SOURCE[0]}"
            exit 0
            ;;
        *) fail "unknown option: $arg" ;;
    esac
done

# ---------------------------------------------------------------------------
# Prerequisites
# ---------------------------------------------------------------------------
command -v xorriso >/dev/null 2>&1 || fail "xorriso non trovato. Installa con: sudo apt install -y xorriso"
command -v cargo >/dev/null 2>&1 || fail "cargo non trovato nel PATH"
command -v rustup >/dev/null 2>&1 || fail "rustup non trovato nel PATH (richiesto per la toolchain pinnata)"

# Pinned nightly for the disk-image builder (WS0-04.1): the channel is read
# from disk-image/rust-toolchain.toml — the single source of truth — and
# installed on demand so the ISO is always built by the same compiler.
DISK_IMAGE_TOOLCHAIN="$(sed -n 's/^channel *= *"\([^"]*\)".*/\1/p' "${DISK_IMAGE_DIR}/rust-toolchain.toml")"
[[ -n "$DISK_IMAGE_TOOLCHAIN" ]] || fail "channel non trovato in ${DISK_IMAGE_DIR}/rust-toolchain.toml"
if ! rustup toolchain list 2>/dev/null | grep -q "^${DISK_IMAGE_TOOLCHAIN}"; then
    log "Installing pinned toolchain ${DISK_IMAGE_TOOLCHAIN} (profile minimal)..."
    rustup toolchain install "${DISK_IMAGE_TOOLCHAIN}" --profile minimal \
        || fail "installazione toolchain ${DISK_IMAGE_TOOLCHAIN} fallita"
fi
# Idempotent: also repairs a partially-installed pin. rust-src is needed by
# `-Z build-std=core`; llvm-tools-preview by bootloader's BIOS stage objcopy.
rustup component add --toolchain "${DISK_IMAGE_TOOLCHAIN}" rust-src llvm-tools-preview >/dev/null \
    || fail "installazione componenti (rust-src, llvm-tools-preview) per ${DISK_IMAGE_TOOLCHAIN} fallita"

# ---------------------------------------------------------------------------
# SOURCE_DATE_EPOCH (WS0-04.2): pin every build-generated timestamp to the
# commit time so two builds of the same commit are byte-identical
# (https://reproducible-builds.org/docs/source-date-epoch/).
# Precedence: caller env > git commit timestamp > fixed fallback epoch.
# The fallback covers trees without git metadata (e.g. the rsync'd build
# tree on the Proxmox host): builds stay deterministic, just not tied to a
# commit. Consumed by the TAG fallback and README "Built:" line below and by
# the ISO normalization steps (WS0-04.3); also honored by xorriso and any
# cargo build script that supports the convention.
# ---------------------------------------------------------------------------
if [[ -z "${SOURCE_DATE_EPOCH:-}" ]]; then
    if ! SOURCE_DATE_EPOCH="$(git -C "$REPO_ROOT" log -1 --format=%ct 2>/dev/null)"; then
        SOURCE_DATE_EPOCH=1767225600   # 2026-01-01T00:00:00Z
    fi
fi
[[ "$SOURCE_DATE_EPOCH" =~ ^[0-9]+$ ]] || fail "SOURCE_DATE_EPOCH non numerico: '${SOURCE_DATE_EPOCH}'"
export SOURCE_DATE_EPOCH
# GNU date uses -d @epoch, BSD/macOS date uses -r epoch.
BUILD_DATE_UTC="$(date -u -d "@${SOURCE_DATE_EPOCH}" +"%Y-%m-%d %H:%M:%S UTC" 2>/dev/null \
    || date -u -r "${SOURCE_DATE_EPOCH}" +"%Y-%m-%d %H:%M:%S UTC")"
log "SOURCE_DATE_EPOCH=${SOURCE_DATE_EPOCH} (${BUILD_DATE_UTC})"

# WS13-06.8 — reproducible builds: strip machine-specific absolute paths (the
# workspace root, the cargo registry/home, the toolchain sysroot) out of the
# build artifacts via `--remap-path-prefix`, so the kernel ELF / ISO is
# byte-identical regardless of WHERE the repo is checked out or WHO builds it.
# (cargo's native `trim-paths` profile option is still unstable on the pinned
# stable toolchain, so the equivalent flags are applied explicitly here, where
# the absolute paths are known.) Combined with the pinned toolchain
# (rust-toolchain.toml, WS13-06.9) and SOURCE_DATE_EPOCH this makes the release
# reproducible — asserted by scripts/repro-iso-test.sh (WS13-06.11).
RUSTC_SYSROOT="$(rustc --print sysroot 2>/dev/null || echo "${HOME}/.rustup")"
REMAP_FLAGS="--remap-path-prefix=${REPO_ROOT}=/nexacore"
REMAP_FLAGS+=" --remap-path-prefix=${CARGO_HOME:-${HOME}/.cargo}=/cargo"
REMAP_FLAGS+=" --remap-path-prefix=${RUSTC_SYSROOT}=/rust"
export RUSTFLAGS="${RUSTFLAGS:-} ${REMAP_FLAGS}"
log "reproducible RUSTFLAGS (remap-path-prefix) applied"

# Determine short SHA for filename uniqueness; fall back to the (pinned)
# build epoch so the name — which also lands in the embedded README via
# ${TAG} — stays deterministic on trees without git metadata.
if SHORT_SHA="$(git -C "$REPO_ROOT" rev-parse --short HEAD 2>/dev/null)"; then
    TAG="$SHORT_SHA"
    if ! git -C "$REPO_ROOT" diff --quiet HEAD 2>/dev/null; then
        TAG="${TAG}-dirty"
    fi
else
    TAG="$(date -u -d "@${SOURCE_DATE_EPOCH}" +%Y%m%dT%H%M%SZ 2>/dev/null \
        || date -u -r "${SOURCE_DATE_EPOCH}" +%Y%m%dT%H%M%SZ)"
fi
ISO_OUT="${ISO_OUT_DIR}/nexacore-os-${TAG}.iso"

# ---------------------------------------------------------------------------
# Build
# ---------------------------------------------------------------------------
if [[ "$SKIP_BUILD" -eq 0 ]]; then
    # Regenerate the embedded initramfs BEFORE compiling kernel-runner, so the
    # ISO always ships the current userspace images — critically
    # /bin/nexacore-apps-image, the branded desktop the kernel boot-spawns
    # (WS7-19.2). kernel-runner embeds crates/nexacore-kernel/src/embedded_initramfs.bin
    # via include_bytes!; without this step it would bake in whatever stale (or
    # empty) blob is on disk, and an absent apps-image makes kmain fall back to
    # the bare_metal demo desktop (the off-brand cyan-on-black screen).
    if [[ "$SKIP_INITRAMFS" -eq 0 ]]; then
        log "Building embedded initramfs (userspace images incl. branded desktop)..."
        bash "${REPO_ROOT}/scripts/build-shell-initramfs.sh" \
            || fail "initramfs build failed (scripts/build-shell-initramfs.sh)"
        INITRAMFS_BIN="${REPO_ROOT}/crates/nexacore-kernel/src/embedded_initramfs.bin"
        [[ -s "$INITRAMFS_BIN" ]] || fail "embedded_initramfs.bin is empty after build"
        ok "embedded_initramfs.bin: $(du -h "$INITRAMFS_BIN" | cut -f1)"
    else
        log "--skip-initramfs: reusing existing embedded_initramfs.bin"
    fi

    log "Building kernel-runner ELF (release)..."
    (cd "$KERNEL_RUNNER_DIR" && cargo build --target x86_64-unknown-none --release --quiet)
    [[ -f "$KERNEL_ELF" ]] || fail "kernel-runner ELF non trovato: $KERNEL_ELF"
    ok "kernel-runner ELF: $(du -h "$KERNEL_ELF" | cut -f1)"

    # The FAT filesystem inside boot-uefi.img gets its directory-entry
    # timestamps from the wall clock (fatfs DefaultTimeProvider): without
    # freezing time the image — and therefore the ISO — changes on every
    # rebuild. faketime pins the clock to SOURCE_DATE_EPOCH (TZ=UTC so the
    # host timezone cannot leak in). Without faketime the build still works
    # but full-rebuild reproducibility is not guaranteed (repro-iso-test.sh
    # will catch it).
    #
    # faketime wraps ONLY the builder binary, never cargo: under libfaketime's
    # LD_PRELOAD with a frozen clock, the `rustc -vV` probe that cargo spawns
    # deadlocks at startup and cargo waits on it forever (observed as multi-
    # hour hangs on the build host). So: compile with a clean clock first,
    # then run the already-built builder — the only step that writes FAT
    # timestamps — under faketime. DONT_FAKE_MONOTONIC (both spellings, for
    # old and new libfaketime) keeps CLOCK_MONOTONIC real as extra hardening.
    FAKETIME_PREFIX=()
    if command -v faketime >/dev/null 2>&1; then
        FAKETIME_PREFIX=(env "TZ=UTC" "DONT_FAKE_MONOTONIC=1" \
            "FAKETIME_DONT_FAKE_MONOTONIC=1" faketime -f "@${BUILD_DATE_UTC% UTC}")
    else
        log "WARNING: faketime non trovato — i timestamp FAT in boot-uefi.img seguiranno l'orologio reale (build non riproducibile; apt install libfaketime)"
    fi
    log "Building UEFI boot image (cargo +${DISK_IMAGE_TOOLCHAIN})..."
    (cd "$DISK_IMAGE_DIR" && cargo "+${DISK_IMAGE_TOOLCHAIN}" build --release --quiet)
    DISK_IMAGE_BIN="${DISK_IMAGE_DIR}/target/release/disk-image"
    [[ -x "$DISK_IMAGE_BIN" ]] || fail "builder non trovato dopo la build: $DISK_IMAGE_BIN"
    (cd "$DISK_IMAGE_DIR" && ${FAKETIME_PREFIX[@]+"${FAKETIME_PREFIX[@]}"} \
        "$DISK_IMAGE_BIN" "$KERNEL_ELF" >/dev/null)
    [[ -f "$UEFI_IMG" ]] || fail "boot-uefi.img non trovato: $UEFI_IMG"
    ok "boot-uefi.img: $(du -h "$UEFI_IMG" | cut -f1)"
else
    [[ -f "$UEFI_IMG" ]] || fail "--skip-build: boot-uefi.img mancante. Esegui senza --skip-build."
    log "Reusing existing boot-uefi.img: $(du -h "$UEFI_IMG" | cut -f1)"
fi

# ---------------------------------------------------------------------------
# ISO wrap (xorriso, UEFI-only El Torito via appended GPT partition)
# ---------------------------------------------------------------------------
mkdir -p "$ISO_OUT_DIR" "$ISO_ROOT"

# Drop a README inside the ISO so it is not a completely empty data track —
# some tools warn on empty ISOs.
cat > "${ISO_ROOT}/README.txt" <<EOF
NexaCore OS — live UEFI boot image
Commit: ${TAG}
Built:  ${BUILD_DATE_UTC}

This ISO boots a live graphical desktop. There is no installer.
Boot only on UEFI firmware (QEMU/OVMF, VirtualBox EFI, VMware EFI, modern PCs).
EOF

# ---------------------------------------------------------------------------
# Normalize the ISO source tree (WS0-04.3): clamp every mtime to
# SOURCE_DATE_EPOCH, walking entries in sorted order, so the image content
# never depends on when (or in which readdir order) the tree was
# materialized. xorriso itself honours the exported SOURCE_DATE_EPOCH for
# volume dates and GPT GUID derivation; ISO 9660 directory records are
# name-sorted by spec, and identical mtimes remove the remaining
# input-order sensitivity.
# ---------------------------------------------------------------------------
# ISO 8601 with trailing Z: parsed as UTC by both GNU and BSD touch -d
# (touch -t would use local time and make the mtimes depend on the host TZ).
TOUCH_DATE="$(date -u -d "@${SOURCE_DATE_EPOCH}" +%Y-%m-%dT%H:%M:%SZ 2>/dev/null \
    || date -u -r "${SOURCE_DATE_EPOCH}" +%Y-%m-%dT%H:%M:%SZ)"
find "$ISO_ROOT" -depth -print0 | sort -z | while IFS= read -r -d '' entry; do
    touch -d "$TOUCH_DATE" "$entry"
done
touch -d "$TOUCH_DATE" "$UEFI_IMG"

log "Wrapping into hybrid UEFI ISO..."
xorriso -as mkisofs \
    -iso-level 3 \
    -V "NEXACORE_OS" \
    -append_partition 2 0xef "$UEFI_IMG" \
    -appended_part_as_gpt \
    -e --interval:appended_partition_2:all:: \
    -no-emul-boot \
    -isohybrid-gpt-basdat \
    -partition_offset 16 \
    -o "$ISO_OUT" \
    "$ISO_ROOT" \
    >/dev/null 2>&1

[[ -f "$ISO_OUT" ]] || fail "xorriso non ha prodotto l'ISO: $ISO_OUT"

# ---------------------------------------------------------------------------
# Checksum (WS0-04.4): emit <iso>.sha256 next to the ISO, in `sha256sum -c`
# format with the bare filename so it verifies from inside dist/iso/.
# sha256sum on Linux, shasum -a 256 on macOS/BSD.
# ---------------------------------------------------------------------------
ISO_NAME="$(basename "$ISO_OUT")"
(
    cd "$ISO_OUT_DIR"
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$ISO_NAME" > "${ISO_NAME}.sha256"
    else
        shasum -a 256 "$ISO_NAME" > "${ISO_NAME}.sha256"
    fi
)
[[ -s "${ISO_OUT}.sha256" ]] || fail "checksum non prodotto: ${ISO_OUT}.sha256"

# ---------------------------------------------------------------------------
# Detached signature (WS0-04.5): Ed25519 over the raw ISO bytes, emitted as
# <iso>.sig. The dedicated private key is NEVER in the repo: it is read from
# $NEXACORE_RELEASE_SIGNING_KEY or ~/.nexacore-release/nexacore-release-ed25519.pem.
# Missing key ⇒ the build still succeeds (dev builds don't sign); the skip
# is logged loudly so a release pipeline can't miss it. The matching public
# key is committed at keys/nexacore-release-ed25519.pub.pem (see keys/README.md).
# ---------------------------------------------------------------------------
SIGNING_KEY="${NEXACORE_RELEASE_SIGNING_KEY:-${HOME}/.nexacore-release/nexacore-release-ed25519.pem}"
RELEASE_PUBKEY="${REPO_ROOT}/keys/nexacore-release-ed25519.pub.pem"
if [[ -f "$SIGNING_KEY" ]]; then
    log "Signing ISO (Ed25519, key: ${SIGNING_KEY})..."
    openssl pkeyutl -sign -inkey "$SIGNING_KEY" -rawin \
        -in "$ISO_OUT" -out "${ISO_OUT}.sig" \
        || fail "firma dell'ISO fallita (chiave: ${SIGNING_KEY})"
    # Sanity: a signature we cannot verify against the committed public key
    # is worse than no signature — fail the build immediately.
    if [[ -f "$RELEASE_PUBKEY" ]]; then
        openssl pkeyutl -verify -pubin -inkey "$RELEASE_PUBKEY" -rawin \
            -in "$ISO_OUT" -sigfile "${ISO_OUT}.sig" >/dev/null \
            || fail "la firma appena creata NON verifica contro ${RELEASE_PUBKEY} (chiave sbagliata?)"
        ok "Signature verified against $(basename "$RELEASE_PUBKEY")"
    else
        log "WARNING: ${RELEASE_PUBKEY} assente — firma creata ma non verificata"
    fi
    ln -sfn "${ISO_NAME}.sig" "${ISO_OUT_DIR}/nexacore-os-latest.iso.sig"
    ok "Signature: ${ISO_OUT}.sig"
else
    log "WARNING: nessuna chiave di firma (${SIGNING_KEY}) — .sig NON generato (ok per build di sviluppo)"
fi

# Refresh the "latest" symlinks for convenience.
ln -sfn "$ISO_NAME" "${ISO_OUT_DIR}/nexacore-os-latest.iso"
ln -sfn "${ISO_NAME}.sha256" "${ISO_OUT_DIR}/nexacore-os-latest.iso.sha256"

ok "ISO: $ISO_OUT ($(du -h "$ISO_OUT" | cut -f1))"
ok "SHA256: $(cut -d' ' -f1 "${ISO_OUT}.sha256") (${ISO_OUT}.sha256)"
ok "Latest: ${ISO_OUT_DIR}/nexacore-os-latest.iso -> $(readlink "${ISO_OUT_DIR}/nexacore-os-latest.iso")"
