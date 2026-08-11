#!/usr/bin/env python3

from __future__ import annotations

import sys
import unittest
from pathlib import Path

REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPOSITORY_ROOT / "scripts"))

import check_schema_compat as compat  # noqa: E402

FIXTURES = REPOSITORY_ROOT / "scripts" / "tests" / "fixtures"


class SchemaCompatibilityTests(unittest.TestCase):
    def test_registry_matches_pinned_schema(self) -> None:
        failures = compat.check_schema_compatibility(
            REPOSITORY_ROOT / "docs" / "dependency-registry.json"
        )

        self.assertEqual([], failures)

    def test_license_policy_matches_pinned_schema(self) -> None:
        failures = compat.check_schema_compatibility(
            REPOSITORY_ROOT / "scripts" / "dependency-license-policy.json"
        )

        self.assertEqual([], failures)

    def test_deliberately_broken_fixture_is_rejected(self) -> None:
        data_path = FIXTURES / "dependency-registry_broken.json"

        failures = compat.check_schema_compatibility(data_path)

        self.assertTrue(failures, "broken fixture must fail the schema gate")
        self.assertTrue(
            any("does not match" in failure for failure in failures),
            failures,
        )

    def test_unknown_document_has_no_schema_is_rejected(self) -> None:
        temporary = FIXTURES / "not-a-real-document.json"
        try:
            temporary.write_text('{"schema_version": 1}', encoding="utf-8")

            failures = compat.check_schema_compatibility(temporary)

            self.assertTrue(any("no schema found" in failure for failure in failures))
        finally:
            temporary.unlink(missing_ok=True)

    def test_schema_version_extraction(self) -> None:
        self.assertEqual(1, compat.schema_version_from_id(".../dependency-registry/v1"))
        self.assertEqual(None, compat.schema_version_from_id("not-a-uri"))
        self.assertEqual(None, compat.schema_version_from_id(123))


if __name__ == "__main__":
    unittest.main()
