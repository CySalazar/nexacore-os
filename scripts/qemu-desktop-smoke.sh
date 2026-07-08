#!/usr/bin/env bash
# =============================================================================
# NexaCore OS — headless QEMU desktop smoke + screenshot (WS13-01.4)
# =============================================================================
# Boots the kernel-runner ELF under QEMU+OVMF *headlessly* (no window), with a
# standard VGA adapter and a QMP control socket, waits for the canonical desktop
# boot markers on the serial console, then captures a PPM/PNG screenshot of the
# rendered desktop through QMP `screendump`. Used by the `desktop-smoke` job of
# .github/workflows/qemu-boot-smoke.yml to upload the screenshot as a CI
# artifact.
#
# Acceptance:
#   - the desktop boot markers (tests/expected-boot-lines.txt, '@hw-only' lines
#     skipped — those are Proxmox-rig-only) appear, in order, on the serial
#     console within SMOKE_TIMEOUT_SECS;
#   - a non-empty screenshot is written to the requested path.
#
# Usage:
#   scripts/qemu-desktop-smoke.sh --screenshot artifacts/desktop.png
#   scripts/qemu-desktop-smoke.sh --screenshot out.png --skip-build --release
#
# Environment:
#   QEMU_BINARY          override qemu-system-x86_64
#   OVMF_PATH            path to OVMF firmware (default: auto-detect)
#   SMOKE_TIMEOUT_SECS   how long to wait for the markers (default: 60)
#   EXPECTED_LINES_FILE  override the shared assert file path
# =============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
KERNEL_RUNNER_DIR="${REPO_ROOT}/kernel-runner"
DISK_IMAGE_DIR="${REPO_ROOT}/disk-image"

QEMU_BINARY="${QEMU_BINARY:-qemu-system-x86_64}"
SMOKE_TIMEOUT_SECS="${SMOKE_TIMEOUT_SECS:-60}"
EXPECTED_LINES_FILE="${EXPECTED_LINES_FILE:-${REPO_ROOT}/tests/expected-boot-lines.txt}"

PROFILE="dev"
PROFILE_DIR="debug"
SKIP_BUILD=0
SCREENSHOT=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        --release)    PROFILE="release"; PROFILE_DIR="release" ;;
        --skip-build) SKIP_BUILD=1 ;;
        --screenshot) SCREENSHOT="${2:-}"; shift ;;
        *) echo "unknown argument: $1" >&2
           echo "usage: $0 --screenshot <path> [--release] [--skip-build]" >&2
           exit 2 ;;
    esac
    shift
done

[[ -n "${SCREENSHOT}" ]] || { echo "error: --screenshot <path> is required" >&2; exit 2; }

log()  { printf '[desktop-smoke] %s\n' "$*" >&2; }
fail() { printf '[desktop-smoke] ERROR: %s\n' "$*" >&2; exit 1; }

# --- Expected boot markers (skip Proxmox-rig-only '@hw-only' lines) -----------
EXPECTED_LINES=()
if [[ -r "${EXPECTED_LINES_FILE}" ]]; then
    while IFS= read -r exp_line || [[ -n "${exp_line}" ]]; do
        [[ -z "${exp_line}" || "${exp_line}" == \#* ]] && continue
        [[ "${exp_line}" == @hw-only\ * ]] && continue
        EXPECTED_LINES+=("${exp_line}")
    done < "${EXPECTED_LINES_FILE}"
fi
[[ ${#EXPECTED_LINES[@]} -gt 0 ]] || fail "no usable expected lines in ${EXPECTED_LINES_FILE}"

# --- Auto-detect OVMF firmware ------------------------------------------------
if [[ -z "${OVMF_PATH:-}" ]]; then
    for candidate in \
        /usr/share/ovmf/OVMF.fd \
        /usr/share/OVMF/OVMF.fd \
        /usr/share/edk2/ovmf/OVMF_CODE.fd \
        /usr/share/qemu/OVMF.fd \
        /usr/local/share/ovmf/OVMF.fd; do
        [[ -r "${candidate}" ]] && { OVMF_PATH="${candidate}"; break; }
    done
fi
[[ -n "${OVMF_PATH:-}" && -r "${OVMF_PATH}" ]] || fail "OVMF firmware not found; set OVMF_PATH"

# --- Build kernel-runner ELF + UEFI disk image --------------------------------
UEFI_IMAGE="${KERNEL_RUNNER_DIR}/target/x86_64-unknown-none/${PROFILE_DIR}/boot-uefi-kernel-runner.img"
KERNEL_ELF="${KERNEL_RUNNER_DIR}/target/x86_64-unknown-none/${PROFILE_DIR}/kernel-runner"

if [[ "${SKIP_BUILD}" -eq 0 ]]; then
    log "building kernel-runner ELF (${PROFILE})..."
    ( cd "${KERNEL_RUNNER_DIR}" && cargo build \
        $([[ "${PROFILE}" == "release" ]] && echo "--release") \
        --target x86_64-unknown-none )
    [[ -f "${KERNEL_ELF}" ]] || fail "kernel-runner ELF not produced at ${KERNEL_ELF}"

    log "building UEFI disk image..."
    toolchain="$(sed -n 's/^channel *= *"\([^"]*\)".*/\1/p' "${DISK_IMAGE_DIR}/rust-toolchain.toml")"
    [[ -n "${toolchain}" ]] || fail "no channel in ${DISK_IMAGE_DIR}/rust-toolchain.toml"
    RUSTFLAGS= cargo "+${toolchain}" run --manifest-path "${DISK_IMAGE_DIR}/Cargo.toml" -- "${KERNEL_ELF}"
fi
[[ -f "${UEFI_IMAGE}" ]] || fail "UEFI image not found at ${UEFI_IMAGE} (run without --skip-build)"

# --- Boot headless with a VGA adapter + QMP control socket --------------------
mkdir -p "$(dirname "${SCREENSHOT}")"
work="$(mktemp -d /tmp/desktop-smoke-XXXXXX)"
serial_log="${work}/serial.log"
qmp_sock="${work}/qmp.sock"
ppm="${work}/screen.ppm"
cleanup() { [[ -n "${qemu_pid:-}" ]] && kill "${qemu_pid}" 2>/dev/null || true; rm -rf "${work}"; }
trap cleanup EXIT

log "launching QEMU headless (VGA std, QMP) ..."
"${QEMU_BINARY}" \
    -machine "q35,accel=kvm:tcg" \
    -cpu qemu64 \
    -m 256M \
    -bios "${OVMF_PATH}" \
    -drive "if=none,format=raw,file=${UEFI_IMAGE},id=boot" \
    -device "virtio-blk-pci,drive=boot" \
    -vga std \
    -display none \
    -serial "file:${serial_log}" \
    -qmp "unix:${qmp_sock},server,nowait" \
    -no-reboot \
    -smp 1 &
qemu_pid=$!

# --- Wait for the final boot marker on the serial console ---------------------
final_marker="${EXPECTED_LINES[${#EXPECTED_LINES[@]}-1]}"
log "waiting up to ${SMOKE_TIMEOUT_SECS}s for marker: ${final_marker}"
deadline=$((SECONDS + SMOKE_TIMEOUT_SECS))
seen_markers=0
while (( SECONDS < deadline )); do
    if [[ -s "${serial_log}" ]] && grep -qF "${final_marker}" "${serial_log}"; then
        seen_markers=1
        break
    fi
    kill -0 "${qemu_pid}" 2>/dev/null || break
    sleep 1
done

# --- Capture the screenshot via QMP `screendump` ------------------------------
log "capturing screenshot via QMP screendump -> ${ppm}"
python3 - "${qmp_sock}" "${ppm}" <<'PY'
import json, socket, sys, time
sock_path, out = sys.argv[1], sys.argv[2]
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
for _ in range(30):
    try:
        s.connect(sock_path); break
    except OSError:
        time.sleep(1)
else:
    sys.exit("could not connect to QMP socket")
f = s.makefile("rw", encoding="utf-8", newline="\n")
f.readline()                                   # greeting
def cmd(obj):
    f.write(json.dumps(obj) + "\n"); f.flush()
    while True:
        line = f.readline()
        if not line:
            sys.exit("QMP closed")
        msg = json.loads(line)
        if "return" in msg or "error" in msg:
            return msg
        # ignore asynchronous events
cmd({"execute": "qmp_capabilities"})
res = cmd({"execute": "screendump", "arguments": {"filename": out}})
if "error" in res:
    sys.exit("screendump failed: %s" % res["error"])
PY

[[ -s "${ppm}" ]] || fail "screendump produced no image"

# Convert PPM -> PNG if a converter exists; otherwise keep the PPM bytes.
if command -v pnmtopng >/dev/null 2>&1; then
    pnmtopng "${ppm}" > "${SCREENSHOT}"
elif command -v magick >/dev/null 2>&1; then
    magick "${ppm}" "${SCREENSHOT}"
elif command -v convert >/dev/null 2>&1; then
    convert "${ppm}" "${SCREENSHOT}"
else
    log "no PPM->PNG converter found; writing raw PPM to ${SCREENSHOT}"
    cp "${ppm}" "${SCREENSHOT}"
fi
[[ -s "${SCREENSHOT}" ]] || fail "screenshot ${SCREENSHOT} is empty"
log "screenshot written: ${SCREENSHOT} ($(wc -c < "${SCREENSHOT}") bytes)"

# --- Assert the boot markers actually appeared --------------------------------
if [[ "${seen_markers}" -ne 1 ]]; then
    log "serial log so far:"; cat "${serial_log}" >&2 || true
    fail "desktop boot markers not observed within ${SMOKE_TIMEOUT_SECS}s"
fi
log "desktop boot markers observed; smoke PASSED"
