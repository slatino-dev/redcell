#!/usr/bin/env python3
"""scrub_check — fail if the working tree leaks private infra or secrets.

This is a defensive gate, run in CI and locally, that scans tracked-style text
files for identifiers that must never land in a public repo: internal hostnames,
CGNAT/private network addresses, and API-key-shaped tokens. It exits non-zero and prints
every offending ``file:line`` so the leak can be removed before commit.

It deliberately scans source/text files only and skips the repo's own VCS and
build/cache directories. This script is part of redcell's hygiene tooling, not
its test corpus.

Usage:
    python scripts/scrub_check.py [ROOT]   # ROOT defaults to repo root
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

# Patterns that must never appear in the working tree.
PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("internal-host", re.compile(r"redacted-host")),
    ("cgnat-100.64", re.compile(r"\b100\.64\.\d{1,3}\.\d{1,3}\b")),
    ("private network-domain", re.compile(r"ts\.net")),
    ("redacted-mesh", re.compile(r"redacted-mesh")),
    ("hermes-key", re.compile(r"redacted-key")),
    ("api-key", re.compile(r"sk-[A-Za-z0-9]{20,}")),
]

# Directories never worth scanning.
SKIP_DIRS = {
    ".git",
    ".venv",
    "venv",
    "__pycache__",
    ".mypy_cache",
    ".ruff_cache",
    ".pytest_cache",
    "node_modules",
    "dist",
    "build",
    ".eggs",
}

# Only scan files that are plausibly text/source.
TEXT_SUFFIXES = {
    ".py",
    ".pyi",
    ".md",
    ".txt",
    ".toml",
    ".cfg",
    ".ini",
    ".yaml",
    ".yml",
    ".json",
    ".sh",
    ".env",
    ".gitignore",
    ".gitkeep",
    "",  # extensionless (LICENSE, etc.)
}

# This file itself defines the patterns above, so exclude it from the scan.
SELF = Path(__file__).resolve()


def iter_files(root: Path):
    """Yield candidate text files under ``root``, skipping noise dirs."""
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        if any(part in SKIP_DIRS for part in path.parts):
            continue
        if path.suffix.lower() not in TEXT_SUFFIXES:
            continue
        if path.resolve() == SELF:
            continue
        yield path


def scan(root: Path) -> list[tuple[Path, int, str, str]]:
    """Return a list of (file, line_no, label, line_text) for every match."""
    findings: list[tuple[Path, int, str, str]] = []
    for path in iter_files(root):
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        for lineno, line in enumerate(text.splitlines(), start=1):
            for label, pattern in PATTERNS:
                if pattern.search(line):
                    findings.append((path, lineno, label, line.strip()))
    return findings


def main(argv: list[str]) -> int:
    root = Path(argv[1]).resolve() if len(argv) > 1 else Path(__file__).resolve().parent.parent
    findings = scan(root)
    if not findings:
        print("scrub_check: OK (no forbidden identifiers found)")
        return 0
    print("scrub_check: FAILED — forbidden identifiers found:", file=sys.stderr)
    for path, lineno, label, line in findings:
        rel = path.relative_to(root) if path.is_relative_to(root) else path
        print(f"  {rel}:{lineno}: [{label}] {line}", file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
