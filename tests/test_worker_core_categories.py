from __future__ import annotations

import unittest

from worker import content_signature, core_categories, interest_scoring, windows_noise_rules


class WorkerCoreCategoriesTests(unittest.TestCase):
    def test_representative_media_document_archive_and_noise_categories(self) -> None:
        cases = {
            "Users/Alice/Pictures/photo.jpg": (b"\xff\xd8\xffdata", {"media"}),
            "Users/Alice/Documents/report.pdf": (b"%PDF-1.7\n", {"documents"}),
            "Users/Alice/Downloads/archive.zip": (b"PK\x03\x04data", {"archives"}),
            "Windows/System32/kernel32.dll": (
                b"MZ" + b"\0" * 32,
                {"software/code/databases", "system/noise"},
            ),
        }
        for path, (sample, expected) in cases.items():
            with self.subTest(path=path):
                signature = content_signature.detect_content_signature_bytes(sample)
                noise = windows_noise_rules.evaluate_windows_noise(
                    display_path=path, signature=signature
                )
                result = core_categories.assign_core_categories(
                    core_categories.CategoryInput(
                        display_path=path, signature=signature, noise=noise
                    )
                )
                self.assertTrue(expected.issubset(set(result.categories)))
                self.assertIn(
                    f"category_version:{core_categories.CATEGORY_VERSION}", result.evidence
                )

    def test_ambiguous_backup_wallet_archive_keeps_all_relevant_tabs(self) -> None:
        signature = content_signature.detect_content_signature_bytes(b"PK\x03\x04data")

        result = core_categories.assign_core_categories(
            core_categories.CategoryInput(
                display_path="Users/Alice/Backup/wallet-keystore.zip",
                signature=signature,
                state="carved",
            )
        )

        self.assertEqual(
            {"archives", "backups/mobile", "deleted/carved", "wallets/vaults/keys"},
            set(result.categories),
        )

    def test_messages_browser_corrupted_and_unknown_are_explainable(self) -> None:
        signature = content_signature.detect_content_signature_bytes(
            b"%PDF-1.7\nPK\x03\x04", extension_mime="message/rfc822"
        )

        result = core_categories.assign_core_categories(
            core_categories.CategoryInput(
                display_path="Users/Alice/AppData/Local/Google/Chrome/User Data/mail.eml",
                signature=signature,
            )
        )

        self.assertTrue(
            {"browser", "messages/email", "documents", "corrupted"}.issubset(result.categories)
        )
        corrupted = assignment(result, "corrupted")
        self.assertIn("contradictory_type_evidence", corrupted.evidence)

    def test_missing_signature_remains_reachable_as_unknown(self) -> None:
        result = core_categories.assign_core_categories(
            core_categories.CategoryInput(display_path="lost/file.bin", signature=None)
        )

        self.assertEqual(("unknown",), result.categories)
        self.assertIn("missing_signature", assignment(result, "unknown").evidence)

    def test_score_noise_signal_can_assign_system_noise_without_rule_object(self) -> None:
        score = interest_scoring.ScoreResult(
            scoring_version=interest_scoring.SCORING_VERSION,
            ruleset_version=None,
            interest_score=15,
            noise_score=25,
            confidence=0.6,
            evidence=("noise_score:test",),
        )

        result = core_categories.assign_core_categories(
            core_categories.CategoryInput(display_path="cache.bin", score=score)
        )

        self.assertIn("system/noise", result.categories)
        self.assertIn("unknown", result.categories)

    def test_category_version_migration_is_recorded(self) -> None:
        result = core_categories.assign_core_categories(
            core_categories.CategoryInput(
                display_path="file.bin", signature=None, category_version="core-categories-v0"
            )
        )

        self.assertEqual(core_categories.CATEGORY_VERSION, result.category_version)
        self.assertIn("migrated_from:core-categories-v0", result.evidence)


def assignment(
    result: core_categories.CategoryResult, category: str
) -> core_categories.CategoryAssignment:
    for item in result.assignments:
        if item.category == category:
            return item
    raise AssertionError(f"missing category {category}")


if __name__ == "__main__":
    unittest.main()
