#!/usr/bin/env bash
# =============================================================================
# NexaCore OS — ISO reproducibility test (WS0-04.7)
# =============================================================================
# Builds the release ISO twice from the same tree and asserts the two images
# are byte-identical. This is the acceptance test for the WS0-04 pipeline
# (pinned toolchain, SOURCE_DATE_EPOCH, normalized mtimes).
#
# Modes:
#   default      two full build-iso.sh runs: the kernel cargo build is
#                incremental (no-op on an unchanged tree) but the UEFI boot
#                image and the ISO are regenerated from scratch each run —
#                this exercises FAT creation and the xorriso wrap.
#   --wrap-only  two `build-iso.sh --skip-build` runs: only the xorriso wrap
#                is exercised (fast pre-check; assumes boot-uefi.img exists).
#
# Exit codes (vm103-assert.sh discipline):
#   0  ISOs are byte-identical
#   1  ISOs differ (first differing byte is cited)
#   2  usage error
#   3  infrastructure error (build failed, artifacts missing)
# =============================================================================

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ISO_LINK="${REPO_ROOT}/dist/iso/nexacore-os-latest.iso"

log()  { echo "  [repro] $*"; }
ok()   { echo "  [repro] ✓ $*"; }
fail_infra() { echo "  [repro] ✗ INFRA ERROR: $*" >&2; exit 3; }

BUILD_FLAGS=()
case "${1:-}" in
    "") ;;
    --wrap-only) BUILD_FLAGS+=("--skip-build") ;;
    -h|--help) sed -n '3,26p' "${BASH_SOURCE[0]}"; exit 0 ;;
    *) echo "usage: $0 [--wrap-only]" >&2; exit 2 ;;
esac

# SOURCE_DATE_EPOCH must be identical across the two runs. build-iso.sh
# already derives a stable value (env > git > fixed fallback); freeze it
# here explicitly so the assertion below cannot be perturbed by a commit
# landing between run 1 and run 2.
if [[ -z "${SOURCE_DATE_EPOCH:-}" ]]; then
    if ! SOURCE_DATE_EPOCH="$(git -C "$REPO_ROOT" log -1 --format=%ct 2>/dev/null)"; then
        SOURCE_DATE_EPOCH=1767225600   # keep in sync with build-iso.sh fallback
    fi
fi
export SOURCE_DATE_EPOCH
log "SOURCE_DATE_EPOCH=${SOURCE_DATE_EPOCH}"

WORK_DIR="$(mktemp -d /tmp/nexacore-repro-XXXXXX)"
trap 'rm -rf "$WORK_DIR"' EXIT

# Concurrent build-iso.sh runs queue on cargo's target-dir lock; a second
# repro test piling onto a stuck one is how the build host accumulated
# hung builds. Fail fast instead (flock is Linux-only; macOS skips the
# guard — the full build doesn't run there anyway, see WS13-08).
if command -v flock >/dev/null 2>&1; then
    exec 9>"/tmp/nexacore-iso-build.lock"
    flock -n 9 || fail_infra "another ISO build/test holds /tmp/nexacore-iso-build.lock"
fi

build_and_capture() {
    local n="$1" dest="$2"
    log "build #${n}..."
    bash "${REPO_ROOT}/scripts/build-iso.sh" ${BUILD_FLAGS[@]+"${BUILD_FLAGS[@]}"} \
        > "${WORK_DIR}/build-${n}.log" 2>&1 \
        || fail_infra "build #${n} failed; log: ${WORK_DIR}/build-${n}.log (preserved)"
    [[ -f "$ISO_LINK" ]] || fail_infra "build #${n} produced no ISO at ${ISO_LINK}"
    cp "$(readlink -f "$ISO_LINK")" "$dest"
}

build_and_capture 1 "${WORK_DIR}/a.iso"
build_and_capture 2 "${WORK_DIR}/b.iso"

SHA_A="$(sha256sum "${WORK_DIR}/a.iso" 2>/dev/null | cut -d' ' -f1)" \
    || SHA_A="$(shasum -a 256 "${WORK_DIR}/a.iso" | cut -d' ' -f1)"
SHA_B="$(sha256sum "${WORK_DIR}/b.iso" 2>/dev/null | cut -d' ' -f1)" \
    || SHA_B="$(shasum -a 256 "${WORK_DIR}/b.iso" | cut -d' ' -f1)"
log "build #1 sha256: ${SHA_A}"
log "build #2 sha256: ${SHA_B}"

if DIFF="$(cmp "${WORK_DIR}/a.iso" "${WORK_DIR}/b.iso" 2>&1)"; then
    ok "REPRODUCIBLE: two consecutive builds are byte-identical (${SHA_A})"
    exit 0
else
    # Preserve evidence for diagnosis before the trap cleans the workdir.
    KEEP_DIR="/tmp/nexacore-repro-failed-$$"
    mkdir -p "$KEEP_DIR" && cp "${WORK_DIR}/a.iso" "${WORK_DIR}/b.iso" "$KEEP_DIR/" 2>/dev/null || true
    echo "  [repro] ✗ NOT REPRODUCIBLE: ${DIFF}" >&2
    echo "  [repro]   first differing bytes (cmp -l, max 10):" >&2
    cmp -l "${WORK_DIR}/a.iso" "${WORK_DIR}/b.iso" 2>/dev/null | head -10 | sed 's/^/  [repro]     /' >&2 || true
    echo "  [repro]   evidence preserved in ${KEEP_DIR}" >&2
    exit 1
fi
