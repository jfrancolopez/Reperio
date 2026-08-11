#!/usr/bin/env python3
"""Schema-check gate (RPR-005).

Validates repository JSON syntax and the dependency-registry license policy.
Versioned config/catalog/OpenAPI schema compatibility checks join this command
as those schemas land (RPR-007, RPR-021+).
"""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "scripts"))

import check_dependency_licenses as licenses  # noqa: E402
import validate_repository as policy  # noqa: E402


def check_schemas() -> list[str]:
    failures: list[str] = []

    files = policy.repository_files()
    failures.extend(policy.check_json(files))

    registry = licenses.load_json(licenses.REGISTRY_PATH)
    license_policy = licenses.load_json(licenses.POLICY_PATH)
    failures.extend(licenses.validate_registry(registry, license_policy))

    return failures


def main() -> int:
    failures = check_schemas()
    if failures:
        print("FAIL: schema check")
        for failure in failures:
            print(f"  - {failure}")
        return 1
    print("PASS: schema check")
    return 0


if __name__ == "__main__":
    sys.exit(main())
