#!/usr/bin/env python3

from __future__ import annotations

import unittest
from typing import Any

from worker.threat_scan import (
    CLAMAV_SIGNATURE_VERSION,
    THREAT_SCAN_VERSION,
    ThreatScanError,
    label_match,
    override_label,
    parse_rule_set,
    safe_download_warning,
    scan_with_clamav,
    scan_with_yara,
    signature_update_allowed,
    signature_update_required,
)


def rule_set(version: str = "yara-rules-v1", rules: tuple[str, ...] = ("EICAR_test",)) -> Any:
    return parse_rule_set("\n".join(rules) + "\n", version=version)


class RuleSetTests(unittest.TestCase):
    def test_parse_rule_set(self) -> None:
        rules = parse_rule_set("rule1\nrule2\n# comment\n", version="yara-rules-v1")
        self.assertEqual(("rule1", "rule2"), rules.rules)
        self.assertEqual("yara-rules-v1", rules.version)

    def test_unsafe_rule_rejected(self) -> None:
        with self.assertRaisesRegex(ThreatScanError, "not safe"):
            parse_rule_set("bad rule; rm -rf /\n", version="yara-rules-v1")

    def test_empty_rule_set_rejected(self) -> None:
        with self.assertRaisesRegex(ThreatScanError, "at least one rule"):
            parse_rule_set("# only comments\n", version="yara-rules-v1")


class ScanTests(unittest.TestCase):
    def test_harmless_signature(self) -> None:
        outcome = scan_with_yara(
            rule_set(), content_hash="abc", runner=lambda req: {"matches": ["EICAR_test"]}
        )
        self.assertEqual("ok", outcome["status"])
        self.assertEqual(1, len(outcome["matches"]))
        self.assertFalse(outcome["network_access"])
        self.assertTrue(outcome["exportable_after_warning"])

    def test_no_match(self) -> None:
        outcome = scan_with_yara(rule_set(), content_hash="abc", runner=lambda req: {"matches": []})
        self.assertEqual([], outcome["matches"])

    def test_malformed_file(self) -> None:
        outcome = scan_with_yara(
            rule_set(),
            content_hash="abc",
            runner=lambda req: {"status": "malformed", "matches": []},
        )
        self.assertEqual("ok", outcome["status"])

    def test_timeout(self) -> None:
        outcome = scan_with_yara(
            rule_set(), content_hash="abc", runner=lambda req: {"timed_out": True}
        )
        self.assertEqual("timed_out", outcome["status"])

    def test_crash(self) -> None:
        def broken(req: Any) -> dict[str, Any]:
            raise RuntimeError("segfault")

        outcome = scan_with_yara(rule_set(), content_hash="abc", runner=broken)
        self.assertEqual("crashed", outcome["status"])

    def test_invalid_timeout_rejected(self) -> None:
        with self.assertRaisesRegex(ThreatScanError, "timeout"):
            scan_with_yara(rule_set(), content_hash="abc", runner=lambda req: {}, timeout_seconds=0)


class ClamAvTests(unittest.TestCase):
    def test_infected(self) -> None:
        outcome = scan_with_clamav(
            CLAMAV_SIGNATURE_VERSION,
            content_path="/scratch/x",
            runner=lambda req: {"infected": True},
        )
        self.assertEqual(1, len(outcome["matches"]))
        self.assertFalse(outcome["network_access"])

    def test_clean(self) -> None:
        outcome = scan_with_clamav(
            CLAMAV_SIGNATURE_VERSION,
            content_path="/scratch/x",
            runner=lambda req: {"infected": False},
        )
        self.assertEqual([], outcome["matches"])


class LabelTests(unittest.TestCase):
    def test_label_and_confidence(self) -> None:
        match = label_match("EICAR_test", "malware", 0.9)
        self.assertEqual("malware", match.label)
        self.assertAlmostEqual(0.9, match.confidence)

    def test_invalid_label_rejected(self) -> None:
        with self.assertRaisesRegex(ThreatScanError, "not supported"):
            label_match("rule", "benign", 0.5)

    def test_false_positive_override(self) -> None:
        match = label_match("EICAR_test", "malware", 0.9)
        overridden = override_label(match, "suspicious")
        self.assertEqual("suspicious", overridden.label)
        self.assertEqual("EICAR_test", overridden.rule)


class PolicyTests(unittest.TestCase):
    def test_no_auto_deletion(self) -> None:
        self.assertIn("export with care", safe_download_warning())

    def test_signature_update_required(self) -> None:
        self.assertFalse(signature_update_required(rule_set()))
        self.assertTrue(signature_update_required(rule_set(version="yara-rules-v0")))

    def test_signature_update_only_when_explicit(self) -> None:
        self.assertFalse(signature_update_allowed(explicit_run=False))
        self.assertTrue(signature_update_allowed(explicit_run=True))

    def test_version_constant(self) -> None:
        self.assertEqual("threat-scan-v1", THREAT_SCAN_VERSION)


if __name__ == "__main__":
    unittest.main()
