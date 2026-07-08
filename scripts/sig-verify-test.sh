#!/usr/bin/env bash
# =============================================================================
# NexaCore OS — detached-signature verification test (WS0-04.8)
# =============================================================================
# Asserts the Ed25519 detached-signature contract of the release pipeline
# (WS0-04.5): a `.sig` emitted by build-iso.sh must verify against the
# committed public key, and ONLY against it, and ONLY for untampered bytes.
#
# Modes:
#   default        self-test: ephemeral keypair exercises the exact
#                  sign/verify recipe of build-iso.sh — positive case,
#                  tampered-payload case, wrong-key case, committed-pubkey
#                  sanity, and the --iso code path of this very script.
#   --iso <path>   operational verify: check <path>.sig against the release
#                  public key (keys/nexacore-release-ed25519.pub.pem). This is
#                  what CI and end users run on real artifacts.
#
# Environment:
#   NEXACORE_OPENSSL          openssl binary to use (must support Ed25519 -rawin;
#                         auto-detected otherwise — macOS LibreSSL does not)
#   NEXACORE_RELEASE_PUBKEY   override the public key path (used by the self-test
#                         to exercise --iso mode with an ephemeral key)
#
# Exit codes (vm103-assert.sh discipline):
#   0  all assertions passed / signature verified
#   1  verification failed (or a self-test assertion failed)
#   2  usage error
#   3  infrastructure error (no capable openssl, missing files)
# =============================================================================

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RELEASE_PUBKEY="${NEXACORE_RELEASE_PUBKEY:-${REPO_ROOT}/keys/nexacore-release-ed25519.pub.pem}"

log()  { echo "  [sig] $*"; }
ok()   { echo "  [sig] ✓ $*"; }
fail_assert() { echo "  [sig] ✗ FAIL: $*" >&2; exit 1; }
fail_infra()  { echo "  [sig] ✗ INFRA ERROR: $*" >&2; exit 3; }

ISO_PATH=""
case "${1:-}" in
    "") ;;
    --iso)
        [[ -n "${2:-}" ]] || { echo "usage: $0 [--iso <path>]" >&2; exit 2; }
        ISO_PATH="$2"
        ;;
    -h|--help) sed -n '3,31p' "${BASH_SOURCE[0]}"; exit 0 ;;
    *) echo "usage: $0 [--iso <path>]" >&2; exit 2 ;;
esac

# ---------------------------------------------------------------------------
# Resolve an openssl that supports Ed25519 + `pkeyutl -rawin`. The macOS
# system binary is LibreSSL and supports neither; Homebrew openssl@3 does.
# Probe by actually generating and using a throwaway key — version strings
# are not a reliable capability signal across OpenSSL/LibreSSL forks.
# ---------------------------------------------------------------------------
PROBE_DIR="$(mktemp -d /tmp/nexacore-sig-XXXXXX)"
trap 'rm -rf "$PROBE_DIR"' EXIT

openssl_capable() {
    local bin="$1"
    command -v "$bin" >/dev/null 2>&1 || return 1
    "$bin" genpkey -algorithm ed25519 -out "${PROBE_DIR}/probe.pem" >/dev/null 2>&1 || return 1
    printf 'probe' > "${PROBE_DIR}/probe.dat"
    "$bin" pkeyutl -sign -inkey "${PROBE_DIR}/probe.pem" -rawin \
        -in "${PROBE_DIR}/probe.dat" -out "${PROBE_DIR}/probe.sig" >/dev/null 2>&1
}

OPENSSL=""
for candidate in "${NEXACORE_OPENSSL:-}" openssl \
        /opt/homebrew/opt/openssl@3/bin/openssl \
        /usr/local/opt/openssl@3/bin/openssl; do
    [[ -n "$candidate" ]] || continue
    if openssl_capable "$candidate"; then OPENSSL="$candidate"; break; fi
done
[[ -n "$OPENSSL" ]] || fail_infra "no openssl with Ed25519 -rawin support found (tried: \${NEXACORE_OPENSSL}, openssl, Homebrew openssl@3)"
log "openssl: ${OPENSSL} ($("$OPENSSL" version))"

# The exact recipe from build-iso.sh / keys/README.md — kept in one place so
# the test cannot drift from what the pipeline actually does.
verify() { # <pubkey> <payload> <sig>
    "$OPENSSL" pkeyutl -verify -pubin -inkey "$1" -rawin -in "$2" -sigfile "$3" >/dev/null 2>&1
}

# ---------------------------------------------------------------------------
# --iso mode: verify a real artifact against the release public key.
# ---------------------------------------------------------------------------
if [[ -n "$ISO_PATH" ]]; then
    [[ -f "$ISO_PATH" ]]          || fail_infra "artifact not found: ${ISO_PATH}"
    [[ -f "${ISO_PATH}.sig" ]]    || fail_infra "detached signature not found: ${ISO_PATH}.sig"
    [[ -f "$RELEASE_PUBKEY" ]]    || fail_infra "public key not found: ${RELEASE_PUBKEY}"
    if verify "$RELEASE_PUBKEY" "$ISO_PATH" "${ISO_PATH}.sig"; then
        ok "VERIFIED: $(basename "$ISO_PATH") against $(basename "$RELEASE_PUBKEY")"
        exit 0
    else
        fail_assert "signature ${ISO_PATH}.sig does NOT verify against ${RELEASE_PUBKEY}"
    fi
fi

# ---------------------------------------------------------------------------
# Self-test mode: five assertions over the sign/verify contract.
# ---------------------------------------------------------------------------
WORK="$PROBE_DIR"

# Committed-pubkey sanity: it must exist and parse as an Ed25519 public key,
# otherwise --iso mode (and CI re-verification) is broken at the root.
[[ -f "$RELEASE_PUBKEY" ]] || fail_infra "release public key missing: ${RELEASE_PUBKEY}"
KEY_DESC="$("$OPENSSL" pkey -pubin -in "$RELEASE_PUBKEY" -noout -text 2>/dev/null | head -1)"
[[ "$KEY_DESC" == *ED25519* || "$KEY_DESC" == *Ed25519* ]] \
    || fail_assert "committed key is not Ed25519: ${RELEASE_PUBKEY} (${KEY_DESC:-unreadable})"
ok "1/5 committed public key is valid Ed25519: $(basename "$RELEASE_PUBKEY")"

# Ephemeral keypairs A (signer) and B (wrong key).
"$OPENSSL" genpkey -algorithm ed25519 -out "${WORK}/a.pem" 2>/dev/null
"$OPENSSL" pkey -in "${WORK}/a.pem" -pubout -out "${WORK}/a.pub.pem" 2>/dev/null
"$OPENSSL" genpkey -algorithm ed25519 -out "${WORK}/b.pem" 2>/dev/null
"$OPENSSL" pkey -in "${WORK}/b.pem" -pubout -out "${WORK}/b.pub.pem" 2>/dev/null

# Deterministic sample payload (stands in for the ISO bytes).
printf 'NexaCore OS release artifact payload — WS0-04.8 self-test\n' > "${WORK}/payload.iso"
"$OPENSSL" pkeyutl -sign -inkey "${WORK}/a.pem" -rawin \
    -in "${WORK}/payload.iso" -out "${WORK}/payload.iso.sig" \
    || fail_infra "signing the test payload failed"

verify "${WORK}/a.pub.pem" "${WORK}/payload.iso" "${WORK}/payload.iso.sig" \
    || fail_assert "2/5 a correct signature does NOT verify (positive case)"
ok "2/5 valid signature verifies against the right key"

# Tampered payload: flip the first byte, signature must be rejected.
cp "${WORK}/payload.iso" "${WORK}/tampered.iso"
printf 'X' | dd of="${WORK}/tampered.iso" bs=1 count=1 conv=notrunc 2>/dev/null
if verify "${WORK}/a.pub.pem" "${WORK}/tampered.iso" "${WORK}/payload.iso.sig"; then
    fail_assert "3/5 the signature verifies a TAMPERED payload"
fi
ok "3/5 tampered payload correctly rejected"

# Wrong key: the signature must not verify against any other public key.
if verify "${WORK}/b.pub.pem" "${WORK}/payload.iso" "${WORK}/payload.iso.sig"; then
    fail_assert "4/5 the signature verifies against the WRONG key"
fi
ok "4/5 wrong key correctly rejected"

# --iso code path: re-invoke this script in operational mode on the ephemeral
# artifact, overriding the pubkey, asserting both verdicts (0 then 1).
NEXACORE_RELEASE_PUBKEY="${WORK}/a.pub.pem" NEXACORE_OPENSSL="$OPENSSL" \
    bash "${BASH_SOURCE[0]}" --iso "${WORK}/payload.iso" >/dev/null \
    || fail_assert "5/5 the --iso path fails on the positive case"
cp "${WORK}/payload.iso.sig" "${WORK}/tampered.iso.sig"
if NEXACORE_RELEASE_PUBKEY="${WORK}/a.pub.pem" NEXACORE_OPENSSL="$OPENSSL" \
    bash "${BASH_SOURCE[0]}" --iso "${WORK}/tampered.iso" >/dev/null 2>&1; then
    fail_assert "5/5 the --iso path accepts a tampered artifact"
fi
ok "5/5 --iso path correct on positive and negative case"

ok "SELF-TEST PASSED: Ed25519 detached-signature contract holds (5/5)"
