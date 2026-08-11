#!/usr/bin/env python3
"""Synthetic fixture gate (RPR-008).

Builds the deterministic FAT12 fixture twice, verifies the two builds are
byte-identical, reads the image with the dependency-free reader, attaches the
artifact categories, and compares the derived machine-readable results against
the hash-pinned manifest ``fixtures/expected/fixture-manifest.json``. Coverage
for every planned category is asserted. ``--emit`` regenerates the pinned
manifest after a reviewed builder/schema change; it must never be used to paper
over a drift. Generated images are held in memory only.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import fixture_builder as builder  # noqa: E402
import fixture_reader as reader  # noqa: E402

EXPECTED_MANIFEST = ROOT / "fixtures" / "expected" / "fixture-manifest.json"
MANIFEST_LABEL = "reperio-fixture-v1"


def category_for(findings: list[dict]) -> list[dict]:
    name_to_category: dict[str, str] = {}
    for spec in builder.catalog():
        name_to_category[spec["display"]] = spec["category"]
        name_to_category[spec["short"]] = spec["category"]
        if spec.get("deleted"):
            name_to_category["?" + spec["short"][1:]] = spec["category"]
    for finding in findings:
        category = name_to_category.get(finding["name"])
        if category is None:
            category = name_to_category.get(finding["short_name"])
        finding["category"] = category
    return findings


def derive_manifest() -> dict:
    image, _ = builder.build_image()
    derived = reader.read_image(image)
    findings = category_for(derived["findings"])
    return {
        "schema_version": 1,
        "spec": {
            "label": MANIFEST_LABEL,
            "geometry": builder.GEOMETRY_LABEL,
            "image_sha256": builder.image_sha256(image),
            "image_size": len(image),
            "volume_label": builder.VOLUME_LABEL,
            "volume_serial": builder.VOLUME_SERIAL,
            "categories": list(builder.CATEGORIES),
        },
        "findings": findings,
    }


def build_twice_identical() -> str:
    image_one, _ = builder.build_image()
    image_two, _ = builder.build_image()
    if image_one != image_two:
        raise AssertionError("fixture builds are not deterministic (byte mismatch)")
    return builder.image_sha256(image_one)


def compare_manifests(expected: dict, current: dict) -> list[str]:
    failures: list[str] = []
    expected_spec = expected.get("spec", {})
    current_spec = current.get("spec", {})
    if expected_spec.get("image_sha256") != current_spec.get("image_sha256"):
        failures.append(
            f"image hash drift: expected {expected_spec.get('image_sha256')!r}, "
            f"derived {current_spec.get('image_sha256')!r}"
        )
    if expected_spec.get("image_size") != current_spec.get("image_size"):
        failures.append(
            f"image size drift: expected {expected_spec.get('image_size')!r}, "
            f"derived {current_spec.get('image_size')!r}"
        )
    expected_findings = expected.get("findings", [])
    current_findings = current.get("findings", [])
    if len(expected_findings) != len(current_findings):
        failures.append(
            f"finding count drift: expected {len(expected_findings)}, "
            f"derived {len(current_findings)}"
        )
    for index, (expected_finding, current_finding) in enumerate(
        zip(expected_findings, current_findings)
    ):
        if expected_finding != current_finding:
            failures.append(f"finding[{index}] drift: expected {expected_finding!r}")
            failures.append(f"finding[{index}] derived: {current_finding!r}")

    expected_categories = set(expected_spec.get("categories", []))
    derived_categories = {finding.get("category") for finding in current_findings}
    missing = sorted(expected_categories - derived_categories)
    if missing:
        failures.append(f"category coverage drift: missing categories {missing}")
    for finding in current_findings:
        if finding.get("category") not in expected_categories:
            failures.append(
                f"finding {finding.get('name')!r} has unexpected category "
                f"{finding.get('category')!r}"
            )
    return failures


def check_fixtures() -> list[str]:
    failures: list[str] = []
    if not EXPECTED_MANIFEST.exists():
        return [f"{EXPECTED_MANIFEST.relative_to(ROOT)}: pinned manifest is missing"]
    try:
        expected = json.loads(EXPECTED_MANIFEST.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        return [f"cannot read expected manifest: {error}"]

    try:
        image_sha = build_twice_identical()
    except AssertionError as error:
        failures.append(str(error))
        return failures

    current = derive_manifest()
    if current["spec"]["image_sha256"] != image_sha:
        failures.append("internal inconsistency: derived manifest hash differs from build")
    failures.extend(compare_manifests(expected, current))
    return failures


def emit_manifest() -> None:
    manifest = derive_manifest()
    EXPECTED_MANIFEST.parent.mkdir(parents=True, exist_ok=True)
    EXPECTED_MANIFEST.write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    print(f"wrote {EXPECTED_MANIFEST.relative_to(ROOT)}")


def main() -> int:
    parser = argparse.ArgumentParser(description="Reperio synthetic fixture gate")
    parser.add_argument(
        "--emit",
        action="store_true",
        help="regenerate the pinned expected manifest (reviewed changes only)",
    )
    args = parser.parse_args()

    if args.emit:
        emit_manifest()
        return 0

    failures = check_fixtures()
    if failures:
        print("FAIL: synthetic fixture gate")
        for failure in failures:
            print(f"  - {failure}")
        return 1
    print("PASS: synthetic fixture gate (deterministic, hash-pinned, category-complete)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
