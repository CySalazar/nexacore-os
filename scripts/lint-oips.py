#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
#
# NexaCore OS — NCIP structural linter
# -------------------------------
# Validates every file under `/ncips/` against the canonical structure defined in
# `NCIP-Process-001` and `ncips/ncip-template.md`.
#
# Why a custom linter (rather than markdownlint + JSON-schema):
# - YAML frontmatter rules and Markdown body rules need a unified pass — splitting them across
#   tools doubles the surface and makes errors less actionable.
# - The "filename ↔ frontmatter coherence" check (e.g., `ncip-process-001.md` ↔ `ncip: 1` and
#   slug `process`) is NCIP-specific and not expressible cleanly in generic linters.
# - The index-table cross-check (`ncips/README.md` must list every NCIP file) is a project-local
#   invariant.
#
# Exit codes:
#   0 — all NCIPs valid.
#   1 — at least one structural violation. Errors are printed to stderr in a CI-friendly format
#       (`<file>:<line>: <severity>: <message>`).
#   2 — internal error (linter bug, missing dependency, IO failure).
#
# Dependencies: stdlib only (re, pathlib, sys, dataclasses). PyYAML is intentionally avoided to
# keep the linter zero-install in CI; we parse the small frontmatter subset we need by hand.

from __future__ import annotations

import re
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable

# ---------------------------------------------------------------------------
# Configuration: structural rules
# ---------------------------------------------------------------------------

# Where the NCIP registry lives, relative to repo root.
NCIPS_DIR_NAME = "ncips"

# Files in /ncips/ that are NOT individual NCIPs and must be skipped by the per-file linter.
NON_NCIP_FILES = {"README.md", "ncip-template.md"}

# Filename pattern: ncip-<slug>-<NNN>.md
#   - <slug>: kebab-case, lowercase letters/digits/hyphens, 1–60 chars, no leading/trailing hyphen.
#   - <NNN>: exactly 3 zero-padded digits.
FILENAME_RE = re.compile(
    r"^ncip-(?P<slug>[a-z0-9]+(?:-[a-z0-9]+)*)-(?P<number>\d{3})\.md$"
)

# The sentinel file `ncip-0000-template.md` uses an inverted shape (number-first) on purpose:
# it is a permanent, immovable anchor for the reserved number 0000 (todo.md P2.2 names it
# explicitly). The linter treats it as a fixed-name exception with synthetic slug/number.
SENTINEL_FILENAME = "ncip-0000-template.md"
SENTINEL_SLUG = "template"
SENTINEL_NUMBER = 0

# Required frontmatter keys. Order is intentional (used in error messages).
REQUIRED_FRONTMATTER_KEYS = (
    "ncip",
    "title",
    "track",
    "status",
    "authors",
    "created",
    "license",
)

# Optional but recognized frontmatter keys (presence allowed, absence allowed).
OPTIONAL_FRONTMATTER_KEYS = (
    "updated",
    "requires",
    "supersedes",
    "superseded-by",
    "discussion",
    "activated",
)

ALLOWED_TRACKS = {"Standards Track", "Process", "Informational", "Meta"}

ALLOWED_STATUSES = {
    "Draft",
    "Review",
    "Last Call",
    "Active",
    "Final",
    "Rejected",
    "Withdrawn",
    "Superseded",
}

ALLOWED_LICENSES = {"CC0-1.0"}

# Required body sections, in canonical order. The linter checks presence (any order is allowed
# in practice, but we WARN on out-of-order to keep NCIPs readable).
REQUIRED_SECTIONS = (
    "Abstract",
    "Motivation",
    "Specification",
    "Rationale",
    "Backwards Compatibility",
    "Test Cases",
    "Reference Implementation",
    "Security Considerations",
    "Privacy Considerations",
    "Copyright",
)

# Sections that MAY contain "N/A — <reason>" boilerplate (the NCIP genuinely has no content).
# Other sections, if present, MUST contain substantive text.
SECTIONS_ALLOWING_NA = (
    "Backwards Compatibility",
    "Test Cases",
    "Reference Implementation",
)

# Heading regex: matches `## <Section Name>` (level-2 ATX heading).
HEADING_RE = re.compile(r"^##\s+(?P<title>.+?)\s*$")

# Date regex: ISO-8601 calendar date, no time component.
ISO_DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")


# ---------------------------------------------------------------------------
# Diagnostic record — accumulated and reported in a CI-friendly format.
# ---------------------------------------------------------------------------


@dataclass
class Diagnostic:
    """A single lint finding tied to a file (and optionally a line)."""

    path: Path
    line: int  # 1-based; use 0 for "whole file"
    severity: str  # "error" or "warning"
    message: str

    def format(self) -> str:
        # CI-friendly: "<path>:<line>: <severity>: <message>".
        # GitHub Actions parses "::error file=...,line=...::message" but we keep a portable
        # plain format and rely on the calling workflow to re-emit annotations if desired.
        loc = f"{self.path}" if self.line == 0 else f"{self.path}:{self.line}"
        return f"{loc}: {self.severity}: {self.message}"


@dataclass
class LintResult:
    """Mutable accumulator for diagnostics across all NCIP files."""

    diagnostics: list[Diagnostic] = field(default_factory=list)

    def error(self, path: Path, line: int, message: str) -> None:
        self.diagnostics.append(Diagnostic(path, line, "error", message))

    def warning(self, path: Path, line: int, message: str) -> None:
        self.diagnostics.append(Diagnostic(path, line, "warning", message))

    @property
    def error_count(self) -> int:
        return sum(1 for d in self.diagnostics if d.severity == "error")

    @property
    def warning_count(self) -> int:
        return sum(1 for d in self.diagnostics if d.severity == "warning")


# ---------------------------------------------------------------------------
# Frontmatter parser — handles the small YAML subset NCIPs need.
# ---------------------------------------------------------------------------


def split_frontmatter(text: str, path: Path, result: LintResult) -> tuple[dict[str, str | list[str]], int, str]:
    """
    Split a Markdown file into (frontmatter_dict, frontmatter_end_line, body_text).

    Returns an empty dict and 0 if the frontmatter is malformed; errors are appended to `result`.
    The parser handles:
      - scalar values: `key: value`
      - YAML null sentinel `~`
      - list values, both inline `key: [a, b]` and block `key:\n  - a\n  - b`
    It does NOT handle nested mappings, multi-line scalars, anchors, or other YAML features —
    NCIPs are intentionally simple.
    """
    lines = text.splitlines()
    if not lines or lines[0].strip() != "---":
        result.error(path, 1, "missing frontmatter delimiter `---` on line 1")
        return {}, 0, text

    end_idx = None
    for i in range(1, len(lines)):
        if lines[i].strip() == "---":
            end_idx = i
            break
    if end_idx is None:
        result.error(path, 1, "frontmatter never closed (no second `---` delimiter)")
        return {}, 0, text

    fm_lines = lines[1:end_idx]
    body_lines = lines[end_idx + 1 :]
    body_text = "\n".join(body_lines)

    # Parse the limited YAML subset.
    fm: dict[str, str | list[str]] = {}
    current_list_key: str | None = None
    for line_no_within_fm, raw in enumerate(fm_lines, start=2):  # +2: line 1 is `---`
        stripped = raw.rstrip()
        if not stripped or stripped.lstrip().startswith("#"):
            continue

        # Inside a block list (continuation).
        if current_list_key is not None and stripped.startswith("  - "):
            value = stripped[4:].strip()
            assert isinstance(fm[current_list_key], list)
            fm[current_list_key].append(value)  # type: ignore[union-attr]
            continue
        else:
            current_list_key = None

        # Top-level `key: value`.
        if ":" not in stripped:
            result.error(
                path,
                line_no_within_fm,
                f"frontmatter line lacks `key: value` form: {stripped!r}",
            )
            continue

        key, _, value = stripped.partition(":")
        key = key.strip()
        value = value.strip()

        if value == "":
            # Block list opening: `key:\n  - a\n  - b`.
            fm[key] = []
            current_list_key = key
        elif value.startswith("[") and value.endswith("]"):
            # Inline list: `key: [a, b, c]` (or `key: []`).
            inner = value[1:-1].strip()
            fm[key] = (
                [item.strip() for item in inner.split(",") if item.strip()] if inner else []
            )
        elif value == "~":
            # YAML null.
            fm[key] = ""
        else:
            # Scalar.
            fm[key] = value

    return fm, end_idx + 1, body_text


# ---------------------------------------------------------------------------
# Frontmatter validation
# ---------------------------------------------------------------------------


def validate_frontmatter(
    fm: dict[str, str | list[str]],
    path: Path,
    expected_slug: str,
    expected_number: int,
    result: LintResult,
) -> None:
    """Validate the parsed frontmatter against required schema and filename coherence."""
    # Required keys present?
    for key in REQUIRED_FRONTMATTER_KEYS:
        if key not in fm:
            result.error(path, 1, f"missing required frontmatter key: `{key}`")

    # Unknown keys (typo guard)?
    known = set(REQUIRED_FRONTMATTER_KEYS) | set(OPTIONAL_FRONTMATTER_KEYS)
    for key in fm:
        if key not in known:
            result.warning(path, 1, f"unrecognized frontmatter key: `{key}` (typo?)")

    # Number coherence with filename.
    if "ncip" in fm:
        raw = fm["ncip"]
        try:
            actual_number = int(str(raw))
        except (TypeError, ValueError):
            result.error(path, 1, f"frontmatter `ncip:` is not an integer: {raw!r}")
            actual_number = -1
        if actual_number != expected_number:
            result.error(
                path,
                1,
                f"frontmatter `ncip: {actual_number}` does not match filename "
                f"number `{expected_number:03d}`",
            )

    # Track validity.
    if "track" in fm and fm["track"] not in ALLOWED_TRACKS:
        result.error(
            path,
            1,
            f"`track: {fm['track']!r}` is not one of {sorted(ALLOWED_TRACKS)}",
        )

    # Status validity.
    if "status" in fm and fm["status"] not in ALLOWED_STATUSES:
        result.error(
            path,
            1,
            f"`status: {fm['status']!r}` is not one of {sorted(ALLOWED_STATUSES)}",
        )

    # License validity.
    if "license" in fm and fm["license"] not in ALLOWED_LICENSES:
        result.error(
            path,
            1,
            f"`license: {fm['license']!r}` must be in {sorted(ALLOWED_LICENSES)} "
            f"(NCIPs are CC0-1.0 by policy; codebase remains AGPL-3.0)",
        )

    # Authors must be a non-empty list.
    if "authors" in fm:
        authors = fm["authors"]
        if not isinstance(authors, list) or not authors:
            result.error(path, 1, "`authors` must be a non-empty list (block or inline)")

    # Date format checks.
    for key in ("created", "updated"):
        if key in fm and fm[key]:
            value = str(fm[key])
            if not ISO_DATE_RE.match(value):
                result.error(
                    path,
                    1,
                    f"`{key}: {value!r}` is not ISO-8601 date `YYYY-MM-DD`",
                )

    # Title must not contain trailing punctuation per house style.
    if "title" in fm:
        title = str(fm["title"]).strip()
        if title.endswith(".") or title.endswith(":"):
            result.warning(path, 1, "title should not end with `.` or `:` (house style)")
        if not title:
            result.error(path, 1, "title is empty")


# ---------------------------------------------------------------------------
# Body validation — section presence and ordering.
# ---------------------------------------------------------------------------


def validate_body(
    body_text: str,
    path: Path,
    body_start_line: int,
    fm: dict[str, str | list[str]],
    result: LintResult,
) -> None:
    """Validate that all required sections are present and roughly ordered."""
    found_sections: list[tuple[str, int]] = []  # (section_name, absolute_line_no)

    for offset, line in enumerate(body_text.splitlines()):
        match = HEADING_RE.match(line)
        if match:
            found_sections.append((match.group("title").strip(), body_start_line + offset))

    found_names = [name for name, _ in found_sections]

    # Presence check.
    missing = [s for s in REQUIRED_SECTIONS if s not in found_names]
    for missing_section in missing:
        result.error(path, 0, f"missing required section: `## {missing_section}`")

    # Order check.
    indices_in_canonical = [
        REQUIRED_SECTIONS.index(name) for name in found_names if name in REQUIRED_SECTIONS
    ]
    if indices_in_canonical != sorted(indices_in_canonical):
        result.warning(
            path,
            0,
            "required sections are out of canonical order (see ncip-template.md)",
        )

    # Empty / placeholder TODO check — except for sentinel NCIP-0000.
    is_sentinel = fm.get("ncip") in ("0000", 0, "0")
    is_template = path.name == "ncip-template.md"
    if not is_sentinel and not is_template:
        # Build a quick map of section -> body text between this heading and the next heading.
        section_bodies = _section_bodies(body_text)
        for section in REQUIRED_SECTIONS:
            content = section_bodies.get(section, "").strip()
            if not content:
                # Already reported as missing if the heading itself is absent.
                continue
            if content.upper() == "TODO":
                result.error(path, 0, f"section `## {section}` contains placeholder `TODO`")
            if content.startswith("N/A") and section not in SECTIONS_ALLOWING_NA:
                result.error(
                    path,
                    0,
                    f"section `## {section}` cannot be `N/A` "
                    f"(allowed only for {list(SECTIONS_ALLOWING_NA)})",
                )


def _section_bodies(body_text: str) -> dict[str, str]:
    """Return a mapping `section_name -> raw text between this heading and the next`."""
    sections: dict[str, str] = {}
    current_name: str | None = None
    buffer: list[str] = []
    for line in body_text.splitlines():
        match = HEADING_RE.match(line)
        if match:
            if current_name is not None:
                sections[current_name] = "\n".join(buffer).strip()
            current_name = match.group("title").strip()
            buffer = []
        elif current_name is not None:
            buffer.append(line)
    if current_name is not None:
        sections[current_name] = "\n".join(buffer).strip()
    return sections


# ---------------------------------------------------------------------------
# Per-file lint entrypoint
# ---------------------------------------------------------------------------


def lint_ncip_file(path: Path, result: LintResult) -> None:
    """Lint a single NCIP file. Filename must be of the form `ncip-<slug>-<NNN>.md`,
    or the fixed sentinel name `ncip-0000-template.md` (handled as a special case).
    """
    if path.name == SENTINEL_FILENAME:
        slug = SENTINEL_SLUG
        number = SENTINEL_NUMBER
    else:
        match = FILENAME_RE.match(path.name)
        if not match:
            result.error(
                path,
                0,
                f"filename `{path.name}` does not match `ncip-<slug>-<NNN>.md`",
            )
            return
        slug = match.group("slug")
        number = int(match.group("number"))

    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        result.error(path, 0, f"cannot read file: {exc}")
        return

    fm, body_start_line, body_text = split_frontmatter(text, path, result)
    if not fm:
        return

    validate_frontmatter(fm, path, slug, number, result)
    validate_body(body_text, path, body_start_line, fm, result)


# ---------------------------------------------------------------------------
# Index cross-check — `ncips/README.md` must list every NCIP.
# ---------------------------------------------------------------------------


def lint_index(ncips_dir: Path, ncip_paths: Iterable[Path], result: LintResult) -> None:
    """Verify that the index table in `ncips/README.md` mentions every NCIP file."""
    readme = ncips_dir / "README.md"
    if not readme.is_file():
        result.error(readme, 0, "missing `ncips/README.md` (index file required)")
        return
    try:
        readme_text = readme.read_text(encoding="utf-8")
    except OSError as exc:
        result.error(readme, 0, f"cannot read index file: {exc}")
        return
    for path in ncip_paths:
        # Resolve the number for both the canonical pattern and the sentinel.
        if path.name == SENTINEL_FILENAME:
            number_str = "0000"
        else:
            match = FILENAME_RE.match(path.name)
            if not match:
                continue
            number_str = match.group("number")
        # The index table may render "0000" or "001" — accept the zero-padded form
        # AND the integer form (e.g. "1") because Markdown tables sometimes drop padding.
        if number_str not in readme_text and str(int(number_str)) not in readme_text:
            result.error(
                readme,
                0,
                f"index does not reference NCIP `{path.name}` (expected number `{number_str}`)",
            )


# ---------------------------------------------------------------------------
# Driver
# ---------------------------------------------------------------------------


def find_repo_root(start: Path) -> Path:
    """Walk up from `start` until we find a directory containing both `ncips/` and `Cargo.toml`."""
    current = start.resolve()
    for parent in (current, *current.parents):
        if (parent / NCIPS_DIR_NAME).is_dir() and (parent / "Cargo.toml").is_file():
            return parent
    raise SystemExit(2)  # internal error — caller invoked us outside the repo


def main(argv: list[str]) -> int:
    # If an explicit path is provided, use it as the repo root; otherwise discover by walking up.
    if len(argv) >= 2:
        repo_root = Path(argv[1]).resolve()
        if not (repo_root / NCIPS_DIR_NAME).is_dir():
            print(
                f"error: `{repo_root}/{NCIPS_DIR_NAME}` does not exist", file=sys.stderr
            )
            return 2
    else:
        repo_root = find_repo_root(Path(__file__))

    ncips_dir = repo_root / NCIPS_DIR_NAME
    result = LintResult()

    # Collect candidate NCIP files (everything under ncips/ that ends in .md and isn't a known
    # non-NCIP file).
    ncip_files = sorted(
        p for p in ncips_dir.glob("*.md") if p.name not in NON_NCIP_FILES and p.is_file()
    )

    if not ncip_files:
        result.error(ncips_dir, 0, "no NCIP files found (registry is empty)")

    # The template file is excluded from the per-file lint (it intentionally has TODOs).
    for ncip_path in ncip_files:
        if ncip_path.name == "ncip-template.md":
            continue
        lint_ncip_file(ncip_path, result)

    # Cross-check the index.
    lint_index(ncips_dir, ncip_files, result)

    # Emit diagnostics.
    for diag in result.diagnostics:
        print(diag.format(), file=sys.stderr)

    summary = (
        f"ncip-lint: {result.error_count} error(s), {result.warning_count} warning(s) "
        f"across {len(ncip_files)} file(s)"
    )
    print(summary, file=sys.stderr)

    return 1 if result.error_count > 0 else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
