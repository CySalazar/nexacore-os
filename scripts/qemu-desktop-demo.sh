#!/usr/bin/env bash
# NexaCore OS — interactive QEMU desktop demo
# =============================================================================
# Boots the kernel-runner ELF under QEMU with a visible display so the
# graphical desktop (M5) can be used interactively. Unlike the CI smoke test,
# this script does NOT set a timeout and does NOT capture serial output —
# it is designed for manual exploration.
#
# Prerequisites:
#   - qemu-system-x86_64 in PATH  (brew install qemu on macOS)
#   - OVMF firmware (auto-detected from common Homebrew/apt locations)
#
# Usage:
#   scripts/qemu-desktop-demo.sh                   # build + run
#   scripts/qemu-desktop-demo.sh --skip-build      # reuse existing image
#   scripts/qemu-desktop-demo.sh --release         # release profile
#   scripts/qemu-desktop-demo.sh --print-expected  # print boot markers, exit 0
#
# Boot markers (plan WS0-03): before launching, the expected boot lines are
# read from the shared assert file tests/expected-boot-lines.txt and printed
# as a reference checklist — the demo is interactive (serial on stdio), so
# verification is visual. '@hw-only ' lines (Proxmox-rig-only) are skipped.
# See docs/14-qemu-proxmox-parity.md.
#
# Environment:
#   OVMF_CODE            path to OVMF code firmware (edk2-x86_64-code.fd or OVMF.fd)
#   OVMF_VARS            path to OVMF vars template (optional, defaults to a temp copy)
#   QEMU_BINARY          override qemu-system-x86_64
#   DISPLAY_TYPE         sdl | cocoa | gtk | vnc=:0  (default: auto-detect)
#   EXPECTED_LINES_FILE  override the shared assert file path
# =============================================================================

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
KERNEL_RUNNER_DIR="${REPO_ROOT}/kernel-runner"
DISK_IMAGE_DIR="${REPO_ROOT}/disk-image"
QEMU_BINARY="${QEMU_BINARY:-qemu-system-x86_64}"

PROFILE="dev"
PROFILE_DIR="debug"
SKIP_BUILD=0
PRINT_EXPECTED=0

for arg in "$@"; do
    case "$arg" in
        --release)  PROFILE="release"; PROFILE_DIR="release" ;;
        --skip-build) SKIP_BUILD=1 ;;
        --print-expected) PRINT_EXPECTED=1 ;;
        *) echo "unknown argument: $arg" >&2; echo "usage: $0 [--release] [--skip-build] [--print-expected]" >&2; exit 2 ;;
    esac
done

# ---------------------------------------------------------------------------
# Expected boot markers — shared assert file (plan WS0-03). The demo does not
# capture the serial stream, so the markers are printed as a visual checklist;
# '@hw-only ' lines (Proxmox-rig-only IOMMU/NIC) are skipped in QEMU.
# ---------------------------------------------------------------------------
EXPECTED_LINES_FILE="${EXPECTED_LINES_FILE:-${REPO_ROOT}/tests/expected-boot-lines.txt}"
EXPECTED_LINES=()
if [[ -r "${EXPECTED_LINES_FILE}" ]]; then
    while IFS= read -r exp_line || [[ -n "${exp_line}" ]]; do
        [[ -z "${exp_line}" || "${exp_line}" == \#* ]] && continue
        [[ "${exp_line}" == "@hw-only "* ]] && continue
        EXPECTED_LINES+=("${exp_line}")
    done < "${EXPECTED_LINES_FILE}"
fi

if [[ "${PRINT_EXPECTED}" -eq 1 ]]; then
    if [[ ${#EXPECTED_LINES[@]} -eq 0 ]]; then
        echo "no usable expected lines in ${EXPECTED_LINES_FILE}" >&2; exit 2
    fi
    printf '%s\n' "${EXPECTED_LINES[@]}"
    exit 0
fi

# ---------------------------------------------------------------------------
# ANSI helpers
# ---------------------------------------------------------------------------
info()  { printf '\033[1;34m[demo]\033[0m %s\n' "$*"; }
ok()    { printf '\033[1;32m[demo] OK:\033[0m %s\n' "$*"; }
fail()  { printf '\033[1;31m[demo] FAIL:\033[0m %s\n' "$*" >&2; exit 1; }

# ---------------------------------------------------------------------------
# Detect OVMF firmware
# ---------------------------------------------------------------------------
detect_ovmf_code() {
    local candidates=(
        "${OVMF_CODE:-}"
        "/opt/homebrew/Cellar/qemu/"*"/share/qemu/edk2-x86_64-code.fd"
        "/usr/share/ovmf/OVMF.fd"
        "/usr/share/qemu/OVMF.fd"
        "/usr/share/edk2-ovmf/x64/OVMF_CODE.fd"
    )
    for p in "${candidates[@]}"; do
        # expand globs
        for f in $p; do
            [[ -f "$f" ]] && echo "$f" && return 0
        done
    done
    return 1
}

detect_ovmf_vars() {
    local candidates=(
        "${OVMF_VARS:-}"
        "/opt/homebrew/Cellar/qemu/"*"/share/qemu/edk2-i386-vars.fd"
        "/usr/share/ovmf/OVMF_VARS.fd"
        "/usr/share/qemu/OVMF_VARS.fd"
        "/usr/share/edk2-ovmf/x64/OVMF_VARS.fd"
    )
    for p in "${candidates[@]}"; do
        for f in $p; do
            [[ -f "$f" ]] && echo "$f" && return 0
        done
    done
    return 1
}

# ---------------------------------------------------------------------------
# Detect display backend
# ---------------------------------------------------------------------------
detect_display() {
    if [[ -n "${DISPLAY_TYPE:-}" ]]; then
        echo "$DISPLAY_TYPE"; return
    fi
    case "$(uname -s)" in
        Darwin) echo "cocoa" ;;
        Linux)
            if [[ -n "${WAYLAND_DISPLAY:-}" ]]; then echo "gtk"
            elif [[ -n "${DISPLAY:-}" ]];         then echo "sdl"
            else                                       echo "vnc=:0"
            fi
            ;;
        *) echo "sdl" ;;
    esac
}

# ---------------------------------------------------------------------------
# Build
# ---------------------------------------------------------------------------
if [[ "$SKIP_BUILD" -eq 0 ]]; then
    info "building kernel-runner ELF (${PROFILE})..."
    (cd "${KERNEL_RUNNER_DIR}" && \
        cargo build \
            $([ "$PROFILE" = "release" ] && echo "--release" || true) \
            --target x86_64-unknown-none \
            --quiet)

    KERNEL_ELF="${KERNEL_RUNNER_DIR}/target/x86_64-unknown-none/${PROFILE_DIR}/kernel-runner"
    info "kernel ELF: ${KERNEL_ELF}"

    info "building UEFI disk image..."
    (cd "${DISK_IMAGE_DIR}" && \
        cargo run \
            $([ "$PROFILE" = "release" ] && echo "--release" || true) \
            --quiet -- "${KERNEL_ELF}")
fi

UEFI_IMAGE="${KERNEL_RUNNER_DIR}/target/x86_64-unknown-none/${PROFILE_DIR}/boot-uefi.img"
[[ -f "$UEFI_IMAGE" ]] || fail "UEFI image not found: ${UEFI_IMAGE}"
info "UEFI image: ${UEFI_IMAGE}"

# ---------------------------------------------------------------------------
# OVMF
# ---------------------------------------------------------------------------
OVMF_CODE_PATH="$(detect_ovmf_code)" || fail "OVMF firmware not found. Set OVMF_CODE= or install ovmf package."
info "OVMF code: ${OVMF_CODE_PATH}"

VARS_TEMPLATE="$(detect_ovmf_vars 2>/dev/null || true)"
VARS_FILE="$(mktemp /tmp/nexacore-ovmf-vars.XXXXXX)"
if [[ -n "$VARS_TEMPLATE" && -f "$VARS_TEMPLATE" ]]; then
    cp "$VARS_TEMPLATE" "$VARS_FILE"
    info "OVMF vars: ${VARS_TEMPLATE} (temp copy)"
else
    # Create a blank 64K NVRAM file — OVMF will initialise it.
    dd if=/dev/zero of="$VARS_FILE" bs=1024 count=64 2>/dev/null
    info "OVMF vars: blank NVRAM (64 KiB)"
fi
trap 'rm -f "$VARS_FILE"' EXIT

# ---------------------------------------------------------------------------
# Launch
# ---------------------------------------------------------------------------
DISPLAY_BACKEND="$(detect_display)"
info "display backend: ${DISPLAY_BACKEND}"

# Reference checklist: boot markers to eyeball on the serial (stdio) stream.
if [[ ${#EXPECTED_LINES[@]} -gt 0 ]]; then
    info "expected boot markers (from $(basename "${EXPECTED_LINES_FILE}")):"
    for m in "${EXPECTED_LINES[@]}"; do printf '       %s\n' "${m}"; done
else
    info "WARNING: shared assert file missing/empty (${EXPECTED_LINES_FILE}) — no checklist"
fi

info "launching QEMU… (close the window or press Ctrl-C to quit)"
echo ""

exec "${QEMU_BINARY}" \
    -machine "q35,accel=tcg" \
    -cpu qemu64 \
    -m 256M \
    -smp 1 \
    -drive "if=pflash,format=raw,readonly=on,file=${OVMF_CODE_PATH}" \
    -drive "if=pflash,format=raw,file=${VARS_FILE}" \
    -drive "if=none,format=raw,file=${UEFI_IMAGE},id=boot" \
    -device "virtio-blk-pci,drive=boot" \
    -serial stdio \
    -display "${DISPLAY_BACKEND}" \
    -no-reboot
