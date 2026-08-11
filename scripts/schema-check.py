#!/usr/bin/env python3
"""Schema-check gate (RPR-005, extended by RPR-006).

Validates repository JSON syntax, the dependency-registry license policy, and
version compatibility between every versioned JSON document and its JSON Schema
in ``scripts/schemas/``. A deliberately broken schema fixture is exercised by
the RPR-006 CI gate and the unit suite to prove the gate fails.

Versioned config/catalog/OpenAPI schema compatibility joins this command as
those schemas land (RPR-007, RPR-021+).
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "scripts"))

import check_dependency_licenses as licenses  # noqa: E402
import check_schema_compat as compat  # noqa: E402
import validate_repository as policy  # noqa: E402


def check_schemas(registry_path: Path = licenses.REGISTRY_PATH) -> list[str]:
    failures: list[str] = []

    files = policy.repository_files()
    failures.extend(policy.check_json(files))

    registry = licenses.load_json(registry_path)
    license_policy = licenses.load_json(licenses.POLICY_PATH)
    failures.extend(licenses.validate_registry(registry, license_policy))
    failures.extend(compat.check_schema_compatibility(registry_path))

    return failures


def main() -> int:
    parser = argparse.ArgumentParser(description="Repository schema-check gate")
    parser.add_argument(
        "--registry",
        type=Path,
        default=licenses.REGISTRY_PATH,
        help="dependency registry JSON to validate (default: %(default)s)",
    )
    args = parser.parse_args()

    failures = check_schemas(args.registry)
    if failures:
        print("FAIL: schema check")
        for failure in failures:
            print(f"  - {failure}")
        return 1
    print("PASS: schema check")
    return 0


if __name__ == "__main__":
    sys.exit(main())
