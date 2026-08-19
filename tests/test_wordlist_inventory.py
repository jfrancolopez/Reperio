#!/usr/bin/env python3

from __future__ import annotations

import unittest
from typing import Any

from worker.wordlist_inventory import (
    WORDLIST_INVENTORY_VERSION,
    WordlistInventoryError,
    estimate_mask_space,
    hash_matches,
    import_allowed,
    inventory_summary,
    ordered_strategies,
    register_dictionaries,
    set_enabled,
    validate_mask,
    validate_rule,
)


def dictionary_record(name: str = "top100", **overrides: Any) -> dict[str, Any]:
    record: dict[str, Any] = {
        "name": name,
        "source": "scratch://wordlists/top100.txt",
        "license": "CC0-1.0",
        "sha256": "a" * 64,
        "size_bytes": 4096,
        "language": "en",
        "enabled": True,
    }
    record.update(overrides)
    return record


def inventory(*records: dict[str, Any]) -> Any:
    return register_dictionaries(list(records))


class RegistrationTests(unittest.TestCase):
    def test_valid_inventory(self) -> None:
        result = inventory(dictionary_record(), dictionary_record("top200"))
        self.assertEqual(2, len(result.dictionaries))
        self.assertEqual("CC0-1.0", result.by_name("top100").license)

    def test_duplicate_dictionary_rejected(self) -> None:
        with self.assertRaisesRegex(WordlistInventoryError, "more than once"):
            inventory(dictionary_record(), dictionary_record())

    def test_missing_license_rejected(self) -> None:
        with self.assertRaisesRegex(WordlistInventoryError, "requires field 'license'"):
            inventory(dictionary_record(license=""))

    def test_invalid_hash_rejected(self) -> None:
        with self.assertRaisesRegex(WordlistInventoryError, "64 hex"):
            inventory(dictionary_record(sha256="not-a-hash"))

    def test_unsafe_source_rejected(self) -> None:
        with self.assertRaisesRegex(WordlistInventoryError, "https or scratch"):
            inventory(dictionary_record(source="http://insecure.example.com/list.txt"))

    def test_hash_change_detected(self) -> None:
        dictionary = inventory(dictionary_record()).by_name("top100")
        self.assertTrue(hash_matches(dictionary, "a" * 64))
        self.assertFalse(hash_matches(dictionary, "b" * 64))


class RuleTests(unittest.TestCase):
    def test_valid_rule(self) -> None:
        self.assertIsNone(validate_rule("l"))
        self.assertIsNone(validate_rule("$2026"))

    def test_shell_syntax_rejected(self) -> None:
        self.assertIsNotNone(validate_rule("l; rm -rf /"))
        self.assertIsNotNone(validate_rule("$(whoami)"))
        self.assertIsNotNone(validate_rule("a | b"))

    def test_empty_rule_rejected(self) -> None:
        self.assertIsNotNone(validate_rule(""))


class MaskTests(unittest.TestCase):
    def test_valid_masks(self) -> None:
        self.assertIsNone(validate_mask("?l?l?l?d?d"))
        self.assertIsNone(validate_mask("?1?1?1?1?1?1?1?1"))
        self.assertIsNone(validate_mask("[a-z]?d"))

    def test_invalid_mask(self) -> None:
        self.assertIsNotNone(validate_mask("?x?x"))
        self.assertIsNotNone(validate_mask("?l ?d"))

    def test_shell_syntax_in_mask_rejected(self) -> None:
        self.assertIsNotNone(validate_mask("?l; rm"))

    def test_search_space_estimate(self) -> None:
        self.assertEqual(26 * 10, estimate_mask_space("?l?d"))
        self.assertEqual(95**2, estimate_mask_space("?a?a"))
        self.assertEqual(3, estimate_mask_space("[abc]"))
        self.assertEqual(3, estimate_mask_space("[a-z]"))

    def test_invalid_mask_space_rejected(self) -> None:
        with self.assertRaisesRegex(WordlistInventoryError, "unknown charset"):
            estimate_mask_space("?x")


class ImportTests(unittest.TestCase):
    def test_no_download_without_admin_action(self) -> None:
        allowed, warning = import_allowed(size_bytes=4096, explicit_admin_action=False)
        self.assertFalse(allowed)
        if warning is not None:
            self.assertIn("explicit admin action", warning)

    def test_huge_import_rejected(self) -> None:
        allowed, _ = import_allowed(size_bytes=10**12, explicit_admin_action=True)
        self.assertFalse(allowed)

    def test_admin_action_allows_bounded_import(self) -> None:
        allowed, _ = import_allowed(size_bytes=4096, explicit_admin_action=True)
        self.assertTrue(allowed)


class StrategyTests(unittest.TestCase):
    def test_ordered_deduped(self) -> None:
        result = inventory(dictionary_record(), dictionary_record("two"))
        strategies = ordered_strategies(["two", "top100", "two"], result)
        self.assertEqual(("two", "top100"), strategies)

    def test_disabled_dictionary_excluded(self) -> None:
        result = set_enabled(
            inventory(dictionary_record("disabled_dict", enabled=True)), "disabled_dict", False
        )
        with self.assertRaisesRegex(WordlistInventoryError, "disabled"):
            ordered_strategies(["disabled_dict"], result)

    def test_summary(self) -> None:
        result = inventory(dictionary_record(), dictionary_record("two"))
        summary = inventory_summary(result)
        self.assertEqual(2, summary["count"])
        self.assertEqual(2, len(summary["enabled"]))

    def test_version_constant(self) -> None:
        self.assertEqual("wordlist-inventory-v1", WORDLIST_INVENTORY_VERSION)


if __name__ == "__main__":
    unittest.main()
