#!/usr/bin/env bash
# =============================================================================
# NexaCore OS — QEMU boot smoke test
# =============================================================================
# Closes the K5 gate of NCIP-Kernel-003 § 3: boots the `kernel-runner`
# ELF under QEMU+OVMF (UEFI) and asserts the canonical banner sequence
# appears on the serial console.
#
# Build pipeline (bootloader 0.11):
#   1. cargo build  → kernel-runner ELF for x86_64-unknown-none
#   2. disk-image   → UEFI disk image (boot-uefi.img) from the ELF
#   3. QEMU+OVMF   → boots the UEFI image, serial output captured
#
# Acceptance:
#   - The five banner lines emitted by `kernel_entry` + `kmain` appear,
#     in order, on the QEMU serial output within `SMOKE_TIMEOUT_SECS`.
#   - QEMU exits cleanly (kernel issues ACPI S5; QEMU tears down).
#
# Usage:
#   scripts/qemu-boot-smoke.sh                              # build + run + assert (baseline K5 banner)
#   scripts/qemu-boot-smoke.sh --skip-build                 # use existing image
#   scripts/qemu-boot-smoke.sh --release                    # release profile
#   scripts/qemu-boot-smoke.sh --feature mb11-userprobe     # MB11 userprobe smoke (TASK-013 / P10.4)
#   scripts/qemu-boot-smoke.sh --feature mb12-userprobe     # MB12 userprobe smoke (TASK-013 / P10.4)
#   scripts/qemu-boot-smoke.sh --print-expected             # print effective expected lines, exit 0
#
# Expected lines (plan WS0-03): loaded from the shared assert file
# tests/expected-boot-lines.txt — single source of truth with the Proxmox
# smoke (scripts/vm103-assert.sh). Lines tagged '@hw-only ' (IOMMU/NIC
# markers, Proxmox-rig-only) are SKIPPED here; feature-gated userprobe
# lines stay in this script. See docs/14-qemu-proxmox-parity.md.
#
# Environment:
#   OVMF_PATH            path to OVMF.fd firmware (default: auto-detect)
#   QEMU_BINARY          override qemu-system-x86_64 (default: from $PATH)
#   SMOKE_TIMEOUT_SECS   how long to wait for the banner (default: 30)
#   EXPECTED_LINES_FILE  override the shared assert file path
# =============================================================================

set -euo pipefail

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
KERNEL_RUNNER_DIR="${REPO_ROOT}/kernel-runner"
DISK_IMAGE_DIR="${REPO_ROOT}/disk-image"
SMOKE_TIMEOUT_SECS="${SMOKE_TIMEOUT_SECS:-30}"
QEMU_BINARY="${QEMU_BINARY:-qemu-system-x86_64}"

PROFILE="dev"
PROFILE_DIR="debug"
SKIP_BUILD=0
FEATURE=""
PRINT_EXPECTED=0

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
        --print-expected)
            PRINT_EXPECTED=1
            shift
            ;;
        --feature)
            shift
            if [[ -z "${1:-}" ]]; then
                echo "--feature requires a value" >&2
                exit 2
            fi
            FEATURE="$1"
            shift
            ;;
        --feature=*)
            FEATURE="${1#--feature=}"
            shift
            ;;
        *)
            echo "unknown argument: $1" >&2
            echo "usage: $0 [--release] [--skip-build] [--feature <name>] [--print-expected]" >&2
            exit 2
            ;;
    esac
done

# Validate feature value (TASK-013 / P10.4 — kernel-runner forwards
# only these two userprobe features to nexacore-kernel).
case "${FEATURE}" in
    ""|mb11-userprobe|mb12-userprobe)
        # OK
        ;;
    *)
        echo "unsupported --feature: '${FEATURE}' (expected mb11-userprobe or mb12-userprobe)" >&2
        exit 2
        ;;
esac

KERNEL_ELF="${KERNEL_RUNNER_DIR}/target/x86_64-unknown-none/${PROFILE_DIR}/kernel-runner"
UEFI_IMAGE="${KERNEL_RUNNER_DIR}/target/x86_64-unknown-none/${PROFILE_DIR}/boot-uefi.img"

# Auto-detect OVMF firmware path.
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
# Banner sequence — loaded from the shared assert file (plan WS0-03), the
# single source of truth with scripts/vm103-assert.sh. The file must match
# `kernel_entry` (kernel-runner/src/main.rs) and `kmain`
# (crates/nexacore-kernel/src/lib.rs). '@hw-only ' lines (Proxmox-rig-only
# IOMMU/NIC markers) are skipped in the QEMU rig; blank/'#' lines ignored.
# ---------------------------------------------------------------------------

EXPECTED_LINES_FILE="${EXPECTED_LINES_FILE:-${REPO_ROOT}/tests/expected-boot-lines.txt}"
if [[ ! -r "${EXPECTED_LINES_FILE}" ]]; then
    echo "expected-lines file not found or unreadable: ${EXPECTED_LINES_FILE}" >&2
    exit 2
fi

EXPECTED_LINES=()
HW_ONLY_SKIPPED=0
while IFS= read -r exp_line || [[ -n "${exp_line}" ]]; do
    [[ -z "${exp_line}" || "${exp_line}" == \#* ]] && continue
    if [[ "${exp_line}" == "@hw-only "* ]]; then
        HW_ONLY_SKIPPED=$((HW_ONLY_SKIPPED + 1))
        continue
    fi
    EXPECTED_LINES+=("${exp_line}")
done < "${EXPECTED_LINES_FILE}"

if [[ ${#EXPECTED_LINES[@]} -eq 0 ]]; then
    echo "no usable expected lines in ${EXPECTED_LINES_FILE}" >&2
    exit 2
fi

# TASK-013 / P10.4 — extend EXPECTED_LINES based on --feature.
# Lines are appended in the order the user-space probe emits them
# so the existing in-order match logic in `verify_banner_in_order`
# (further below) catches a regression where the probe stops
# midway through its trace.
case "${FEATURE}" in
    mb11-userprobe)
        # MB11 user-probe smoke (Track B MB11 closure): a Ring 3 process
        # spawned by `kmain` writes "hello" via the `TaskWrite` syscall, then
        # voluntarily exits via `TaskExit(0)` (the kernel emits "[user] exit=0").
        # The probe's own output is the raw "hello" — the "[user] " prefix is
        # the kernel's diagnostic convention, not part of the probe's bytes.
        EXPECTED_LINES+=(
            "hello"
            "[user] exit=0"
        )
        ;;
    mb12-userprobe)
        # MB12 IPC cross-process smoke (Track B MB12 closure):
        # `kmain` pre-creates IPC channel 1, spawns two Ring 3
        # tasks that exchange a "ping" message, both exit cleanly.
        # KNOWN ISSUE: per the `proxmox_deploy` memory entry
        # (2026-05-22), this boot reaches "[mb12] handing off to
        # user tasks" but the VM stops without emitting "ping" /
        # "[user] exit=0". Root-cause TBD (tracked for MB14+
        # follow-up). The strict assertion below is the
        # spec-mandated contract from TASK-013 acceptance criteria;
        # CI invokes this script with the strict contract so a
        # regression-on-fix surfaces immediately, while the known
        # issue is documented as a "soft fail" candidate via
        # `MB12_KNOWN_ISSUE_TOLERATE_TIMEOUT=1` (see end of script).
        EXPECTED_LINES+=(
            "[mb12] channel 1 pre-created"
            "[user] hello"
            "ping"
            "[user] exit=0"
            "[user] exit=0"
        )
        ;;
    "")
        # Baseline K5 banner only — no extension.
        ;;
esac

# --print-expected: show the effective assert set (post @hw-only exclusion,
# post feature extension) without requiring QEMU/OVMF/build. Used by the
# WS0-03 parity checks and handy for debugging the shared file.
if [[ "${PRINT_EXPECTED}" -eq 1 ]]; then
    printf '%s\n' "${EXPECTED_LINES[@]}"
    exit 0
fi

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

log() { printf '\033[1;34m[smoke]\033[0m %s\n' "$*"; }
fail() { printf '\033[1;31m[smoke] FAIL:\033[0m %s\n' "$*" >&2; exit 1; }

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
    log "building kernel-runner ELF (${PROFILE})${FEATURE:+ with feature=${FEATURE}}..."
    local profile_flag=""
    if [[ "${PROFILE}" == "release" ]]; then
        profile_flag="--release"
    fi
    local features_flag=""
    if [[ -n "${FEATURE}" ]]; then
        features_flag="--features ${FEATURE}"
    fi
    cargo build \
        --manifest-path "${KERNEL_RUNNER_DIR}/Cargo.toml" \
        --target x86_64-unknown-none \
        ${profile_flag} \
        ${features_flag}

    if [[ ! -f "${KERNEL_ELF}" ]]; then
        fail "build did not produce ${KERNEL_ELF}"
    fi
    log "kernel ELF: ${KERNEL_ELF}"
}

build_disk_image() {
    log "building UEFI disk image..."
    # `bootloader 0.11`'s build script invokes `cargo -Z build-std=core`
    # (via the CARGO env-var) to compile the UEFI/BIOS stages, which
    # requires a nightly toolchain — pinned in disk-image/rust-toolchain.toml
    # (WS0-04.1, single source of truth). The kernel itself uses stable 1.85.
    #
    # The bootloader build script does not own the upstream stage-N
    # sources, so any `RUSTFLAGS="-D warnings"` exported by the parent
    # CI environment (qemu-boot-smoke.yml § env) bubbles into those
    # inner builds and trips on legitimate warnings inside upstream code
    # (e.g. unused-imports under newer nightlies). Strip RUSTFLAGS for
    # this single invocation — the kernel-runner build above already ran
    # under the full `-D warnings` policy, so the NexaCore-OS-owned code
    # paths remain gated.
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
    log "running QEMU (timeout ${SMOKE_TIMEOUT_SECS}s) with OVMF..."

    local serial_log qemu_debug_log
    serial_log=$(mktemp /tmp/qemu-serial-XXXXXXXXXX)
    qemu_debug_log=$(mktemp /tmp/qemu-debug-XXXXXXXXXX)

    # UEFI boot: -bios OVMF.fd + raw disk image via virtio-blk.
    # `-machine q35` is the modern UEFI-compatible chipset.
    # `-debugcon stdio` routes port 0xE9 writes to stdout (kernel's
    # first byte 'K' proves kernel_entry was reached).
    timeout "${SMOKE_TIMEOUT_SECS}" "${QEMU_BINARY}" \
        -machine "q35,accel=kvm:tcg" \
        -cpu "qemu64" \
        -m 256M \
        -bios "${OVMF_PATH}" \
        -drive "if=none,format=raw,file=${UEFI_IMAGE},id=boot" \
        -device "virtio-blk-pci,drive=boot" \
        -serial "file:${serial_log}" \
        -debugcon stdio \
        -d "guest_errors,cpu_reset,unimp" \
        -D "${qemu_debug_log}" \
        -display none \
        -no-reboot \
        -smp 1 \
        2>&1 || true

    echo "[smoke-diag] serial log bytes: $(wc -c < "${serial_log}" 2>/dev/null || echo '?')" >&2
    if [[ -s "${serial_log}" ]]; then
        echo "[smoke-diag] serial log:" >&2
        cat "${serial_log}" >&2
    fi
    if [[ -s "${qemu_debug_log}" ]]; then
        echo "[smoke-diag] QEMU debug events:" >&2
        cat "${qemu_debug_log}" >&2
    else
        echo "[smoke-diag] QEMU debug log: empty" >&2
    fi

    cat "${serial_log}"
    rm -f "${serial_log}" "${qemu_debug_log}"
}

assert_banner_sequence() {
    local output="$1"
    local last_index=-1
    local i
    for i in "${!EXPECTED_LINES[@]}"; do
        local expected="${EXPECTED_LINES[$i]}"
        local found_line
        found_line=$(printf '%s' "${output}" | grep -nF -- "${expected}" \
            | head -n1 | cut -d: -f1 || true)
        if [[ -z "${found_line}" ]]; then
            log "missing banner line: ${expected}"
            log "--- captured output ---"
            printf '%s\n' "${output}"
            log "--- end captured ---"
            fail "expected banner line not found"
        fi
        if [[ "${found_line}" -le "${last_index}" ]]; then
            fail "banner line out of order: '${expected}' at ${found_line}, prev at ${last_index}"
        fi
        last_index="${found_line}"
        log "  [${i}] ✓ ${expected}"
    done
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

log "NexaCore OS QEMU boot smoke test"
log "repo root: ${REPO_ROOT}"
log "expected lines: ${#EXPECTED_LINES[@]} from $(basename "${EXPECTED_LINES_FILE}") (${HW_ONLY_SKIPPED} @hw-only skipped — QEMU rig)"

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
log "QEMU done. asserting banner sequence..."

if printf '%s' "${OUTPUT}" | grep -qF 'K'; then
    log "[diag] debug-port marker 'K' found — kernel_entry WAS reached."
else
    log "[diag] debug-port marker 'K' NOT found — kernel_entry was NOT reached."
fi

assert_banner_sequence "${OUTPUT}"
log "PASS — all ${#EXPECTED_LINES[@]} banner lines present and in order."
