#!/usr/bin/env bash
# scripts/check-no-blanket-allow.sh
#
# Enforces ADR-0003: no blanket crate-root #![allow(...)] in production crates.
#
# Scans every workspace member's crate-root file (src/lib.rs / src/main.rs),
# PLUS the explicitly-named bootable binaries `kernel-runner` and `disk-image`
# (workspace-excluded, but still subject to the policy). The member list is
# DERIVED from `cargo metadata` (WS13-03.4) so the scan can never drift behind
# a newly-added crate.
#
# Allowlisted crate-root forms (documented in ADR-0003):
#   - #![doc(...)]
#   - #![warn(...)]
#   - #![cfg_attr(test, allow(...))]                  (test-only relaxation)
#   - #![cfg_attr(all(feature = "bare-metal", ...))]  (no_std / no_main gating)
#   - #![allow(unsafe_code)]   ONLY in a binary crate root (src/main.rs):
#       a bare-metal no_main image's entry trampoline / raw-hardware access is
#       inherently unsafe at the crate root. Library crates MUST still localize
#       unsafe to the offending item.
#
# Any other crate-root #![allow(...)] is a violation and exits 1. Crate-root
# attributes are matched at column 0 only; an indented `#![allow(...)]` is a
# MODULE/BLOCK inner attribute (already localized) and is out of scope.
#
# Usage: scripts/check-no-blanket-allow.sh
# Exit:  0 = clean, 1 = violations found
#
# See: docs/adr/0003-no-blanket-allows-in-production-crates.md

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

violations=0
violation_log=$(mktemp)
trap 'rm -f "$violation_log"' EXIT

# ---------------------------------------------------------------------------
# Derive the set of crate-root files to scan.
#
# (1) Every workspace member, from `cargo metadata` (auto-derived — WS13-03.4,
#     WS13-03.1). (2) The bootable binaries `kernel-runner` (WS13-03.2) and
#     `disk-image` (WS13-03.3), which are workspace-EXCLUDED (they build only
#     for x86_64-unknown-none) but still covered by ADR-0003.
# ---------------------------------------------------------------------------
files=""

if command -v cargo >/dev/null 2>&1; then
    while IFS= read -r f; do
        [[ -n "$f" ]] && files+="$f"$'\n'
    done < <(
        cargo metadata --no-deps --format-version 1 2>/dev/null | python -c '
import json, os, sys
try:
    meta = json.load(sys.stdin)
except Exception:
    sys.exit(0)
members = set(meta.get("workspace_members", []))
for pkg in meta.get("packages", []):
    if pkg.get("id") not in members:
        continue
    crate_dir = os.path.dirname(pkg["manifest_path"])
    for rel in ("src/lib.rs", "src/main.rs"):
        p = os.path.join(crate_dir, rel)
        if os.path.isfile(p):
            print(os.path.relpath(p).replace(os.sep, "/"))
' || true
    )
fi

# Fallback / explicit additions: bootable binaries excluded from the workspace.
for extra in "kernel-runner" "disk-image"; do
    for rel in "src/lib.rs" "src/main.rs"; do
        [[ -f "$extra/$rel" ]] && files+="$extra/$rel"$'\n'
    done
done

# If cargo metadata produced nothing (e.g. offline), fall back to a glob of
# non-image crate roots so the guard still runs.
if [[ -z "$(echo "$files" | grep -v '^$' || true)" ]]; then
    for d in crates/*/; do
        case "$d" in
            *-image/) continue ;;
        esac
        for rel in "src/lib.rs" "src/main.rs"; do
            [[ -f "$d$rel" ]] && files+="$d$rel"$'\n'
        done
    done
fi

files=$(echo "$files" | sort -u | grep -v '^$' || true)

for file in $files; do
    [[ -z "$file" ]] && continue
    # A binary crate root (src/main.rs) may carry `#![allow(unsafe_code)]`.
    is_bin=0
    case "$file" in
        */main.rs) is_bin=1 ;;
    esac

    # Scan crate-root inner attributes (#![...]) at COLUMN 0 only. We collect
    # logical attribute lines: each runs from `#![` to the matching `]`.
    awk -v is_bin="$is_bin" '
        BEGIN { in_attr = 0; buf = ""; depth = 0; start_line = 0 }

        {
            line = $0
            if (!in_attr) {
                # Crate-root attribute: `#![` at column 0 (indented `#![` is a
                # module/block inner attribute — already localized, out of scope).
                if (match(line, /^#!\[/)) {
                    in_attr = 1
                    start_line = NR
                    buf = line
                    depth = 0
                    n = length(line)
                    for (i = 1; i <= n; i++) {
                        ch = substr(line, i, 1)
                        if (ch == "(") depth++
                        else if (ch == ")") depth--
                    }
                    if (depth == 0 && index(line, "]") > 0) {
                        emit(buf, start_line, is_bin)
                        in_attr = 0; buf = ""
                    }
                }
            } else {
                buf = buf "\n" line
                n = length(line)
                for (i = 1; i <= n; i++) {
                    ch = substr(line, i, 1)
                    if (ch == "(") depth++
                    else if (ch == ")") depth--
                }
                if (depth == 0 && index(line, "]") > 0) {
                    emit(buf, start_line, is_bin)
                    in_attr = 0; buf = ""
                }
            }
        }

        function emit(attr, ln, bin,    is_allowed) {
            is_allowed = 0

            # Whitelist patterns (ADR-0003 § Escape hatches):
            if (attr ~ /^#!\[doc\(/)                                          is_allowed = 1
            else if (attr ~ /^#!\[warn\(/)                                    is_allowed = 1
            else if (attr ~ /^#!\[cfg_attr\([[:space:]]*test[[:space:]]*,[[:space:]]*allow\(/) is_allowed = 1
            else if (attr ~ /^#!\[cfg_attr\(all\(feature[[:space:]]*=[[:space:]]*"bare-metal"/) is_allowed = 1
            # Bootable binary roots (src/main.rs) may declare crate-wide unsafe.
            else if (bin == 1 && attr ~ /^#!\[allow\([[:space:]]*unsafe_code[[:space:]]*\)\]/) is_allowed = 1
            # Not an allow attribute at all → ignore (#![no_std], #![deny], …).
            else if (attr !~ /allow/) is_allowed = 1

            if (!is_allowed) {
                summary = attr
                gsub(/\n/, " ", summary)
                gsub(/[[:space:]]+/, " ", summary)
                if (length(summary) > 100) summary = substr(summary, 1, 97) "..."
                printf("VIOLATION %s:%d %s\n", FILENAME, ln, summary)
            }
        }
    ' "$file" >> "$violation_log" || true
done

# ---------------------------------------------------------------------------
# Documented exceptions (ADR-0003 § Exceptions). Each entry is a `file:lint`
# pair that stays as a crate-root allow with a written rationale because it
# cannot be cleanly fixed or relocated. Keep this list SHORT and justified.
#
#   - crates/nexacore-container/src/lib.rs : clippy::literal_string_with_formatting_args
#     Known upstream false positive — the diagnostic points at the clippy.toml
#     banner comments, not at any crate source, so there is no item to relocate
#     the allow onto. The lint stays active everywhere else in the workspace.
#   - kernel-runner/src/main.rs : clippy::missing_docs_in_private_items
#     kernel-runner is a thin bare-metal `no_std + no_main` bootable wrapper
#     (NCIP-Kernel-005); private-item doc rigor is not warranted for a boot
#     trampoline. (unsafe_code on this binary root is handled by the awk rule.)
# ---------------------------------------------------------------------------
documented_exceptions() {
    grep -vE \
        -e 'crates/nexacore-container/src/lib\.rs:[0-9]+ .*literal_string_with_formatting_args' \
        -e 'kernel-runner/src/main\.rs:[0-9]+ .*missing_docs_in_private_items' \
        "$1" || true
}
filtered_log=$(mktemp)
trap 'rm -f "$violation_log" "$filtered_log"' EXIT
documented_exceptions "$violation_log" > "$filtered_log"
mv "$filtered_log" "$violation_log"

if [[ -s "$violation_log" ]]; then
    echo "Blanket #![allow(...)] policy violation (see ADR-0003)." >&2
    echo "" >&2
    cat "$violation_log" >&2
    echo "" >&2
    echo "Allowed crate-root forms:" >&2
    echo "  - #![doc(...)]" >&2
    echo "  - #![warn(...)]" >&2
    echo "  - #![cfg_attr(test, allow(...))]" >&2
    echo "  - #![cfg_attr(all(feature = \"bare-metal\", ...))]" >&2
    echo "  - #![allow(unsafe_code)]  (binary crate root / src/main.rs only)" >&2
    echo "" >&2
    echo "Move each violation to a localized #[allow(<lint>, reason = \"...\")] " >&2
    echo "at the offending item. See docs/adr/0003-no-blanket-allows-in-production-crates.md." >&2
    exit 1
fi

echo "check-no-blanket-allow: ok (scanned $(echo "$files" | wc -l | tr -d ' ') crate-root files)"
exit 0
