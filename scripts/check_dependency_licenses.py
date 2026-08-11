#!/usr/bin/env python3
"""Machine-checkable dependency license gate for RPR-001.

Validates ``docs/dependency-registry.json`` against
``scripts/dependency-license-policy.json``. A dependency is rejected when it is
missing license metadata, uses an unknown SPDX identifier, uses a reciprocal
license outside separate-process use, or violates the intake schema.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
REGISTRY_PATH = ROOT / "docs" / "dependency-registry.json"
POLICY_PATH = ROOT / "scripts" / "dependency-license-policy.json"

REQUIRED_ENTRY_FIELDS = ("name", "version", "license", "source", "architecture", "linkage")
LINKAGE_VALUES = ("linked", "separate_process")
SPDX_PATTERN = re.compile(r"^[A-Za-z0-9.+-]+$")


def load_json(path: Path) -> dict:
    try:
        with path.open(encoding="utf-8") as handle:
            data = json.load(handle)
    except (OSError, json.JSONDecodeError) as error:
        raise SystemExit(f"{path.relative_to(ROOT)}: cannot read JSON: {error}")
    if not isinstance(data, dict):
        raise SystemExit(f"{path.relative_to(ROOT)}: expected a JSON object")
    return data


def validate_registry(
    registry: dict, policy: dict, relative_root: Path = ROOT
) -> list[str]:
    failures: list[str] = []

    registry_version = registry.get("schema_version")
    if registry_version != 1:
        failures.append("dependency registry: unsupported schema_version, expected 1")
    if not isinstance(registry.get("dependencies"), list):
        failures.append("dependency registry: missing 'dependencies' list")

    allowed = set(policy.get("allowed", []))
    separate_process = set(policy.get("separate_process_allowed", []))
    policy_version = policy.get("schema_version")
    if policy_version != 1:
        failures.append("license policy: unsupported schema_version, expected 1")
    if not allowed and not separate_process:
        failures.append("license policy: no allowed or separate-process licenses defined")

    seen_names: dict[str, str] = {}
    for index, entry in enumerate(registry.get("dependencies", [])):
        label = _entry_label(entry, index)
        if not isinstance(entry, dict):
            failures.append(f"{label}: entry is not an object")
            continue

        name = entry.get("name")
        if not isinstance(name, str) or not name:
            failures.append(f"{label}: missing non-empty 'name'")
        else:
            previous_version = seen_names.get(name)
            if previous_version is not None:
                failures.append(f"{label}: duplicate dependency name {name!r}")
            seen_names[name] = entry.get("version") or ""

        for field in REQUIRED_ENTRY_FIELDS:
            if field not in entry:
                failures.append(f"{label}: missing required field {field!r}")

        version = entry.get("version")
        if version is None:
            failures.append(f"{label}: missing 'version' (immutable version required)")
        elif isinstance(version, str) and version.lower() in {"latest", "head"}:
            failures.append(f"{label}: mutable version {version!r} is not allowed")

        license_id = entry.get("license")
        if license_id is None or license_id == "":
            failures.append(f"{label}: missing license metadata")
        elif not isinstance(license_id, str) or not SPDX_PATTERN.match(license_id):
            failures.append(f"{label}: invalid SPDX license identifier {license_id!r}")
        else:
            if license_id in separate_process:
                if entry.get("linkage") != "separate_process":
                    failures.append(
                        f"{label}: reciprocal license {license_id} requires "
                        "linkage=separate_process"
                    )
            elif license_id not in allowed:
                failures.append(
                    f"{label}: license {license_id} is not approved and not "
                    "authorized for separate-process use"
                )

        linkage = entry.get("linkage")
        if linkage not in LINKAGE_VALUES:
            failures.append(f"{label}: linkage must be one of {sorted(LINKAGE_VALUES)}")

        architecture = entry.get("architecture")
        if isinstance(architecture, list):
            if not architecture:
                failures.append(f"{label}: architecture list is empty")
        else:
            failures.append(f"{label}: 'architecture' must be a non-empty list")

        source = entry.get("source")
        if isinstance(source, str):
            if not source.startswith(("https://", "http://")):
                failures.append(f"{label}: 'source' must be an absolute URL")
        else:
            failures.append(f"{label}: 'source' must be a URL string")

    return failures


def _entry_label(entry, index: int) -> str:
    if isinstance(entry, dict) and isinstance(entry.get("name"), str):
        return f"dependency {entry['name']!r}"
    return f"dependency at index {index}"


def main() -> int:
    parser = argparse.ArgumentParser(description="Dependency license policy gate")
    parser.add_argument(
        "--registry",
        type=Path,
        default=REGISTRY_PATH,
        help="path to the dependency registry JSON (default: %(default)s)",
    )
    parser.add_argument(
        "--policy",
        type=Path,
        default=POLICY_PATH,
        help="path to the license policy JSON (default: %(default)s)",
    )
    args = parser.parse_args()

    registry = load_json(args.registry)
    policy = load_json(args.policy)
    failures = validate_registry(registry, policy)

    if failures:
        print("FAIL: dependency-license policy")
        for failure in failures:
            print(f"  - {failure}")
        return 1
    print("PASS: dependency-license policy")
    return 0


if __name__ == "__main__":
    sys.exit(main())
