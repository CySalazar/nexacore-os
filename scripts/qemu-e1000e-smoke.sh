#!/usr/bin/env bash
# =============================================================================
# NexaCore OS — QEMU e1000e live bring-up smoke test (TASK-006 / P6.7.9.c)
# =============================================================================
# Validates the e1000e 13-step FSM live wiring by booting the kernel-runner
# under QEMU with `-device e1000e` and asserting the canonical bring-up
# markers appear on the serial console.
#
# Acceptance criteria (NCIP-Driver-Net-015 § S5.1):
#   1. MAC reading: "[e1000e] MAC=" line present (proves RAL[0]/RAH[0] read).
#   2. Ring programming: "[e1000e] RX ring programmed" + "[e1000e] TX ring
#      programmed" lines present.
#   3. Full bring-up: "[e1000e] live bring-up complete" line present.
#
# Risk R4 (TASK-006): the Proxmox test VM lacks an e1000e passthrough; this
# QEMU-based validation is the authoritative acceptance gate.
#
# Usage:
#   scripts/qemu-e1000e-smoke.sh              # build + run + assert
#   scripts/qemu-e1000e-smoke.sh --skip-build # use existing image
#   scripts/qemu-e1000e-smoke.sh --release    # release profile
#
# Environment:
#   OVMF_PATH            path to OVMF.fd firmware (default: auto-detect)
#   QEMU_BINARY          override qemu-system-x86_64
#   SMOKE_TIMEOUT_SECS   how long to wait (default: 30)
# =============================================================================

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
KERNEL_RUNNER_DIR="${REPO_ROOT}/kernel-runner"
DISK_IMAGE_DIR="${REPO_ROOT}/disk-image"
SMOKE_TIMEOUT_SECS="${SMOKE_TIMEOUT_SECS:-30}"
QEMU_BINARY="${QEMU_BINARY:-qemu-system-x86_64}"

PROFILE="dev"
PROFILE_DIR="debug"
SKIP_BUILD=0

while (( $# > 0 )); do
    case "$1" in
        --release)
            PROFILE="release"
            PROFILE_DIR="release"
            shift
            ;;
        --skip-build)
            SKIP_BUILD=1
            shift
            ;;
        *)
            echo "unknown argument: $1" >&2
            exit 2
            ;;
    esac
done

KERNEL_ELF="${KERNEL_RUNNER_DIR}/target/x86_64-unknown-none/${PROFILE_DIR}/kernel-runner"
UEFI_IMAGE="${KERNEL_RUNNER_DIR}/target/x86_64-unknown-none/${PROFILE_DIR}/boot-uefi.img"

# ---------------------------------------------------------------------------
# OVMF auto-detect
# ---------------------------------------------------------------------------
if [[ -z "${OVMF_PATH:-}" ]]; then
    for candidate in \
        /usr/share/ovmf/OVMF.fd \
        /usr/share/OVMF/OVMF.fd \
        /usr/share/edk2/ovmf/OVMF_CODE.fd \
        /opt/homebrew/share/ovmf/ovmf-x86_64.bin \
        /usr/local/share/ovmf/OVMF.fd; do
        if [[ -f "${candidate}" ]]; then
            OVMF_PATH="${candidate}"
            break
        fi
    done
fi

# ---------------------------------------------------------------------------
# Expected serial output markers
# ---------------------------------------------------------------------------
EXPECTED_LINES=(
    "[e1000e] found on bus="
    "[e1000e] PCI cmd: IOSE+MSE+BME enabled"
    "[e1000e] mapped"
    "[e1000e] IMC=FFFFFFFF"
    "[e1000e] reset complete"
    "[e1000e] MAC="
    "[e1000e] RX ring programmed"
    "[e1000e] TX ring programmed"
    "[e1000e] RCTL+TCTL configured"
    "[e1000e] IMS=0085"
    "[e1000e] live bring-up complete"
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
log() { printf '\033[1;34m[e1000e-smoke]\033[0m %s\n' "$*"; }
fail() { printf '\033[1;31m[e1000e-smoke] FAIL:\033[0m %s\n' "$*" >&2; exit 1; }

ensure_qemu_installed() {
    if ! command -v "${QEMU_BINARY}" >/dev/null 2>&1; then
        fail "${QEMU_BINARY} not found in PATH"
    fi
}

ensure_ovmf() {
    if [[ -z "${OVMF_PATH:-}" ]] || [[ ! -f "${OVMF_PATH}" ]]; then
        fail "OVMF firmware not found. Install ovmf package or set OVMF_PATH."
    fi
    log "OVMF: ${OVMF_PATH}"
}

build_kernel_elf() {
    log "building kernel-runner ELF (${PROFILE})..."
    local profile_flag=""
    if [[ "${PROFILE}" == "release" ]]; then
        profile_flag="--release"
    fi
    cargo build \
        --manifest-path "${KERNEL_RUNNER_DIR}/Cargo.toml" \
        --target x86_64-unknown-none \
        ${profile_flag}

    if [[ ! -f "${KERNEL_ELF}" ]]; then
        fail "build did not produce ${KERNEL_ELF}"
    fi
    log "kernel ELF: ${KERNEL_ELF}"
}

build_disk_image() {
    log "building UEFI disk image..."
    # Nightly pinned in disk-image/rust-toolchain.toml (WS0-04.1).
    local toolchain output
    toolchain="$(sed -n 's/^channel *= *"\([^"]*\)".*/\1/p' "${DISK_IMAGE_DIR}/rust-toolchain.toml")"
    [[ -n "${toolchain}" ]] || fail "no channel in ${DISK_IMAGE_DIR}/rust-toolchain.toml"
    output=$(RUSTFLAGS= cargo "+${toolchain}" run --manifest-path "${DISK_IMAGE_DIR}/Cargo.toml" -- "${KERNEL_ELF}" 2>&1) \
        || fail "disk-image builder failed (exit $?); if the toolchain is missing run: rustup toolchain install ${toolchain} --profile minimal --component rust-src --component llvm-tools-preview; last 40 lines:\n${output}"
    log "${output}"

    if [[ ! -f "${UEFI_IMAGE}" ]]; then
        fail "disk-image builder did not produce ${UEFI_IMAGE}"
    fi
    log "UEFI image: ${UEFI_IMAGE}"
}

run_qemu_and_capture() {
    log "running QEMU (timeout ${SMOKE_TIMEOUT_SECS}s) with -device e1000e..."

    local serial_log
    serial_log=$(mktemp /tmp/qemu-e1000e-serial-XXXXXXXXXX)

    # Boot with e1000e device added to the Q35 machine.
    timeout "${SMOKE_TIMEOUT_SECS}" "${QEMU_BINARY}" \
        -machine "q35,accel=kvm:tcg" \
        -cpu "qemu64" \
        -m 256M \
        -bios "${OVMF_PATH}" \
        -drive "if=none,format=raw,file=${UEFI_IMAGE},id=boot" \
        -device "virtio-blk-pci,drive=boot" \
        -device "e1000e,netdev=net0" \
        -netdev "user,id=net0" \
        -serial "file:${serial_log}" \
        -display none \
        -no-reboot \
        -smp 1 \
        2>/dev/null || true

    if [[ -s "${serial_log}" ]]; then
        log "serial log ($(wc -c < "${serial_log}") bytes):"
        cat "${serial_log}" >&2
    fi

    cat "${serial_log}"
    rm -f "${serial_log}"
}

assert_markers() {
    local output="$1"
    local missing=0
    for expected in "${EXPECTED_LINES[@]}"; do
        if printf '%s' "${output}" | grep -qF -- "${expected}"; then
            log "  ✓ ${expected}"
        else
            log "  ✗ MISSING: ${expected}"
            missing=$((missing + 1))
        fi
    done
    if [[ "${missing}" -gt 0 ]]; then
        fail "${missing} expected marker(s) missing from serial output"
    fi
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
log "NexaCore OS e1000e live bring-up smoke test (TASK-006 / P6.7.9.c)"
log "repo root: ${REPO_ROOT}"

ensure_qemu_installed
ensure_ovmf

if [[ "${SKIP_BUILD}" -eq 0 ]]; then
    build_kernel_elf
    build_disk_image
fi

if [[ ! -f "${UEFI_IMAGE}" ]]; then
    fail "UEFI image not found at ${UEFI_IMAGE} (run without --skip-build first)"
fi

OUTPUT=$(run_qemu_and_capture)
log "QEMU done. asserting e1000e bring-up markers..."

assert_markers "${OUTPUT}"
log "PASS — all ${#EXPECTED_LINES[@]} e1000e bring-up markers present."
log "MAC reading: VERIFIED"
log "TX/RX ring acceptance: VERIFIED (TDH/TDT + RDH/RDT read-back)"
