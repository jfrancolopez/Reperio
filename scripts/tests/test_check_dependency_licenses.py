#!/usr/bin/env python3

from __future__ import annotations

import sys
import unittest
from pathlib import Path


REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPOSITORY_ROOT / "scripts"))

import check_dependency_licenses as licenses  # noqa: E402

FIXTURES = REPOSITORY_ROOT / "scripts" / "tests" / "fixtures"
POLICY = REPOSITORY_ROOT / "scripts" / "dependency-license-policy.json"


def load(name: str) -> dict:
    return licenses.load_json(FIXTURES / name)


class DependencyLicensePolicyTests(unittest.TestCase):
    def test_allowed_fixture_passes(self) -> None:
        registry = load("dependencies_allowed.json")
        policy = licenses.load_json(POLICY)

        failures = licenses.validate_registry(registry, policy)

        self.assertEqual([], failures)

    def test_rejected_fixture_contains_expected_failures(self) -> None:
        registry = load("dependencies_rejected.json")
        policy = licenses.load_json(POLICY)

        failures = licenses.validate_registry(registry, policy)

        self.assertTrue(
            any("missing license metadata" in failure for failure in failures),
            failures,
        )
        self.assertTrue(
            any("requires linkage=separate_process" in failure for failure in failures),
            failures,
        )

    def test_unknown_license_is_rejected(self) -> None:
        registry = {
            "schema_version": 1,
            "dependencies": [
                {
                    "name": "license-unknown",
                    "version": "1.0.0",
                    "license": "NOT-A-LICENSE",
                    "source": "https://example.invalid/x",
                    "architecture": ["amd64"],
                    "linkage": "linked",
                }
            ],
        }
        policy = {"schema_version": 1, "allowed": ["MIT"], "separate_process_allowed": []}

        failures = licenses.validate_registry(registry, policy)

        self.assertTrue(any("is not approved" in failure for failure in failures))

    def test_missing_required_field_is_rejected(self) -> None:
        registry = {
            "schema_version": 1,
            "dependencies": [
                {
                    "name": "missing-version",
                    "license": "MIT",
                    "source": "https://example.invalid/x",
                    "architecture": ["amd64"],
                    "linkage": "linked",
                }
            ],
        }
        policy = {"schema_version": 1, "allowed": ["MIT"], "separate_process_allowed": []}

        failures = licenses.validate_registry(registry, policy)

        self.assertTrue(any("missing required field 'version'" in failure for failure in failures))
        self.assertTrue(any("missing 'version'" in failure for failure in failures))

    def test_unsupported_schema_version_is_rejected(self) -> None:
        registry = {"schema_version": 99, "dependencies": []}
        policy = {"schema_version": 1, "allowed": ["MIT"], "separate_process_allowed": []}

        failures = licenses.validate_registry(registry, policy)

        self.assertTrue(any("unsupported schema_version" in failure for failure in failures))


if __name__ == "__main__":
    unittest.main()
