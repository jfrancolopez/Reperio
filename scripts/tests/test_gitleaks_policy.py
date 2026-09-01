#!/usr/bin/env python3

from __future__ import annotations

import tomllib
import unittest
from pathlib import Path

REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
POLICY_PATH = REPOSITORY_ROOT / ".gitleaks.toml"

EXPECTED_FIXTURES = {
    "^abcdefghij12345$": r"^tests/test_audit_helpers\.py$",
    "^sk-abcdefghijklmnop123456$": r"^tests/test_openai_compatible\.py$",
    "^abc123def456gh789$": r"^tests/test_apprise_adapter\.py$",
    "^correct-horse-battery-staple-42$": r"^tests/test_secret_reveal\.py$",
}


class GitleaksPolicyTests(unittest.TestCase):
    def test_extends_defaults_without_disabling_rules(self) -> None:
        policy = load_policy()

        self.assertEqual({"useDefault": True}, policy["extend"])

    def test_inert_fixture_exceptions_require_exact_value_and_path(self) -> None:
        policy = load_policy()
        allowlists = policy["allowlists"]
        fixture_rules = [entry for entry in allowlists if "regexes" in entry]

        self.assertEqual(len(EXPECTED_FIXTURES), len(fixture_rules))
        actual = {
            entry["regexes"][0]: entry["paths"][0]
            for entry in fixture_rules
            if entry["condition"] == "AND"
            and entry["regexTarget"] == "secret"
            and entry["targetRules"] == ["generic-api-key"]
        }
        self.assertEqual(EXPECTED_FIXTURES, actual)

    def test_only_generated_bytecode_has_a_path_only_exception(self) -> None:
        policy = load_policy()
        path_only = [entry for entry in policy["allowlists"] if "regexes" not in entry]

        self.assertEqual(1, len(path_only))
        self.assertEqual([r"(^|/)__pycache__/"], path_only[0]["paths"])
        self.assertEqual(["generic-api-key"], path_only[0]["targetRules"])

    def test_scan_script_loads_policy_for_worktree_and_history(self) -> None:
        script = (REPOSITORY_ROOT / "scripts" / "scan-secrets.sh").read_text(encoding="utf-8")

        self.assertEqual(2, script.count("--config .gitleaks.toml"))


def load_policy() -> dict:
    return tomllib.loads(POLICY_PATH.read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
