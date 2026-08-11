#!/usr/bin/env python3

from __future__ import annotations

import hashlib
import json
import sys
import unittest
from pathlib import Path
from typing import Any

REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPOSITORY_ROOT / "scripts"))

import fixture_builder as builder  # noqa: E402
import fixtures_check as fixtures_check  # noqa: E402

EXPECTED_MANIFEST = REPOSITORY_ROOT / "fixtures" / "expected" / "fixture-manifest.json"


def load_manifest() -> dict[str, Any]:
    with EXPECTED_MANIFEST.open(encoding="utf-8") as handle:
        manifest: dict[str, Any] = json.load(handle)
    return manifest


class FixtureGateTests(unittest.TestCase):
    def test_build_is_deterministic(self) -> None:
        first, _ = builder.build_image()
        second, _ = builder.build_image()
        self.assertEqual(first, second)
        self.assertEqual(builder.image_sha256(first), builder.image_sha256(first))

    def test_pinned_manifest_matches_current_build(self) -> None:
        self.assertEqual(fixtures_check.check_fixtures(), [])

    def test_manifest_structure_and_version(self) -> None:
        manifest = load_manifest()
        self.assertEqual(manifest["schema_version"], 1)
        self.assertEqual(manifest["spec"]["image_size"], 1474560)
        self.assertEqual(manifest["spec"]["volume_label"], "REPERIO")
        self.assertEqual(sorted(manifest["spec"]["categories"]), sorted(builder.CATEGORIES))
        self.assertEqual(manifest["spec"]["label"], fixtures_check.MANIFEST_LABEL)
        self.assertRegex(manifest["spec"]["image_sha256"], r"^[a-f0-9]{64}$")

    def test_finding_names_are_stable(self) -> None:
        manifest = load_manifest()
        unicode_entries = [
            finding for finding in manifest["findings"] if finding["category"] == "unicode"
        ]
        self.assertEqual(len(unicode_entries), 1)
        self.assertEqual(unicode_entries[0]["name"], "naïve-文件.txt")
        self.assertEqual(unicode_entries[0]["short_name"], "NAIVE~1.TXT")
        deleted_entries = [
            finding for finding in manifest["findings"] if finding["category"] == "deleted"
        ]
        self.assertEqual(deleted_entries[0]["name"], "?ELETED1.TXT")
        self.assertEqual(deleted_entries[0]["state"], "deleted")

    def test_hashes_identical_only_within_duplicate_category(self) -> None:
        manifest = load_manifest()
        hashes_by_name: dict[str, str | None] = {}
        for finding in manifest["findings"]:
            hashes_by_name[finding["name"]] = finding["sha256"]
        self.assertEqual(hashes_by_name["COPY_A~1.TXT"], hashes_by_name["COPY_B~1.TXT"])
        self.assertIsNotNone(hashes_by_name["COPY_A~1.TXT"])
        duplicate = hashes_by_name["COPY_A~1.TXT"]
        for name, digest in hashes_by_name.items():
            if name.startswith("COPY_"):
                continue
            if digest is not None and name == "VAULT~1.BIN":
                continue
            self.assertNotEqual(digest, duplicate)

    def test_reader_detects_all_categories(self) -> None:
        image, _ = builder.build_image()
        derived = fixtures_check.derive_manifest()["findings"]
        categories = {finding["category"] for finding in derived}
        self.assertEqual(categories, set(builder.CATEGORIES))

    def test_malformed_state_detection(self) -> None:
        manifest = load_manifest()
        corrupt = [
            finding for finding in manifest["findings"] if finding["short_name"] == "CORRUPT1.TXT"
        ][0]
        damaged = [
            finding for finding in manifest["findings"] if finding["short_name"] == "DAMAGE~1.DAT"
        ][0]
        self.assertEqual(corrupt["state"], "lfn-checksum-mismatch")
        self.assertEqual(corrupt["category"], "malformed")
        self.assertEqual(damaged["state"], "truncated")
        self.assertEqual(damaged["size"], 4096)
        self.assertEqual(damaged["read_bytes"], 512)

    def test_vault_content_hashes_to_manifest_digest(self) -> None:
        vault = next(spec for spec in builder.catalog() if spec["category"] == "encrypted-test")
        manifest = load_manifest()
        vault_finding = next(
            finding for finding in manifest["findings"] if finding["category"] == "encrypted-test"
        )
        self.assertEqual(hashlib.sha256(vault["content"]).hexdigest(), vault_finding["sha256"])


if __name__ == "__main__":
    unittest.main()
