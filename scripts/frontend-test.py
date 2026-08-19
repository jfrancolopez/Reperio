#!/usr/bin/env python3
"""Frontend-test gate (RPR-005, extended by RPR-116 and RPR-117).

No UI test framework exists yet. The gate verifies the web placeholder manifest
is valid, versioned, and licensed, runs the deterministic RPR-116 design
system check (design tokens, derived tokens.css, accessible component catalog,
and WCAG contrast pairs), and runs the RPR-117 application-shell check
(sidebar/top status, planned tabs, case/source context, connection state with
bounded SSE reconnect, route-level loading/error boundaries, persistent
unauthenticated-LAN warning, and a strict single-origin CSP). It becomes the
real frontend-test entry point when browser-based UI tests arrive (RPR-132+).
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "scripts"))

import app_shell_check  # noqa: E402
import design_system_check  # noqa: E402


def check_frontend() -> list[str]:
    package_json = ROOT / "web" / "package.json"
    if not package_json.exists():
        return ["web/package.json is missing"]
    try:
        manifest = json.loads(package_json.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        return [f"web/package.json is invalid: {error}"]
    failures = []
    if manifest.get("name") != "reperio-web":
        failures.append("web/package.json: unexpected name")
    if not isinstance(manifest.get("version"), str) or not manifest["version"]:
        failures.append("web/package.json: missing version")
    if manifest.get("license") != "Apache-2.0":
        failures.append("web/package.json: license must be Apache-2.0")
    if not (ROOT / "web" / "README.md").exists():
        failures.append("web/README.md is missing")
    failures.extend(design_system_check.check_design_system())
    failures.extend(app_shell_check.check_app_shell())
    return failures


def main() -> int:
    failures = check_frontend()
    if failures:
        print("FAIL: frontend")
        for failure in failures:
            print(f"  - {failure}")
        return 1
    print("PASS: frontend placeholder manifest, design system, and app shell")
    return 0


if __name__ == "__main__":
    sys.exit(main())
