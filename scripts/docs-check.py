#!/usr/bin/env python3
"""Docs-check gate (RPR-005).

Reuses the existing dependency-free policy checks for Markdown link resolution,
backlog integrity, text hygiene, and Git whitespace. Documentation-specific
checks that arrive with later tasks extend this command.
"""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "scripts"))

import validate_repository as policy  # noqa: E402


def check_docs() -> list[str]:
    files = policy.repository_files()
    failures: list[str] = []
    failures.extend(policy.check_markdown_links(files))
    failures.extend(policy.check_backlog(files))
    failures.extend(policy.check_text_hygiene(files))
    failures.extend(policy.check_git_whitespace())
    return failures


def main() -> int:
    failures = check_docs()
    if failures:
        print("FAIL: docs check")
        for failure in failures:
            print(f"  - {failure}")
        return 1
    print("PASS: docs check")
    return 0


if __name__ == "__main__":
    sys.exit(main())
