from __future__ import annotations

import unittest

from worker import content_signature, interest_scoring, windows_noise_rules, windows_profiles


class WorkerInterestScoringTests(unittest.TestCase):
    def test_golden_personal_document_beats_system_noise_independently(self) -> None:
        signature = content_signature.detect_content_signature_bytes(b"%PDF-1.7\n")
        profile = profile_fixture()
        noise = windows_noise_rules.evaluate_windows_noise(
            display_path="Users/Alice/Documents/tax.pdf", signature=signature, profile=profile
        )

        score = interest_scoring.score_finding(
            interest_scoring.ScoreInput(
                display_path="Users/Alice/Documents/tax.pdf",
                signature=signature,
                noise=noise,
                profile=profile,
            )
        )

        self.assertGreaterEqual(score.interest_score, 70)
        self.assertEqual(0, score.noise_score)
        self.assertIn("personal_mime_signal", score.evidence)

    def test_system_dll_has_high_noise_without_category_deletion(self) -> None:
        signature = content_signature.detect_content_signature_bytes(b"MZ" + b"\0" * 32)
        noise = windows_noise_rules.evaluate_windows_noise(
            display_path="Windows/System32/kernel32.dll", signature=signature
        )

        score = interest_scoring.score_finding(
            interest_scoring.ScoreInput(
                display_path="Windows/System32/kernel32.dll", signature=signature, noise=noise
            )
        )

        self.assertGreaterEqual(score.noise_score, 60)
        self.assertGreater(score.interest_score, 0)
        self.assertIn("noise_rule:win-os-components", score.evidence)

    def test_boundary_values_are_clamped(self) -> None:
        signature = content_signature.detect_content_signature_bytes(b"%PDF-1.7\nPK\x03\x04")
        noise = windows_noise_rules.evaluate_windows_noise(
            display_path="Users/Alice/AppData/Local/Temp/file.pdf", signature=signature
        )

        score = interest_scoring.score_finding(
            interest_scoring.ScoreInput(
                display_path="Users/Alice/Desktop/file.pdf",
                signature=signature,
                noise=noise,
                state="carved",
                application="browser",
            )
        )

        self.assertGreaterEqual(score.interest_score, 0)
        self.assertLessEqual(score.interest_score, 100)
        self.assertGreaterEqual(score.confidence, 0.0)
        self.assertLessEqual(score.confidence, 1.0)

    def test_missing_evidence_lowers_confidence_but_scores_deterministically(self) -> None:
        first = interest_scoring.score_finding(
            interest_scoring.ScoreInput(display_path="unknown.bin", signature=None, noise=None)
        )
        second = interest_scoring.score_finding(
            interest_scoring.ScoreInput(display_path="unknown.bin", signature=None, noise=None)
        )

        self.assertEqual(first, second)
        self.assertIn("missing_signature", first.evidence)
        self.assertLess(first.confidence, 0.5)

    def test_contradictory_signals_are_explicit_review_not_suppression(self) -> None:
        signature = content_signature.detect_content_signature_bytes(b"\xff\xd8\xffphoto")
        noise = windows_noise_rules.evaluate_windows_noise(
            display_path="Windows/System32/photo.jpg", signature=signature
        )

        score = interest_scoring.score_finding(
            interest_scoring.ScoreInput(
                display_path="Windows/System32/photo.jpg", signature=signature, noise=noise
            )
        )

        self.assertGreater(score.interest_score, score.noise_score)
        self.assertIn("noise_conflict_review", score.evidence)

    def test_rules_version_migration_is_recorded(self) -> None:
        score = interest_scoring.score_finding(
            interest_scoring.ScoreInput(
                display_path="unknown.bin",
                signature=None,
                noise=None,
                scoring_version="interest-score-v0",
            )
        )

        self.assertEqual(interest_scoring.SCORING_VERSION, score.scoring_version)
        self.assertIn("migrated_from:interest-score-v0", score.evidence)


def profile_fixture() -> windows_profiles.WindowsUserProfile:
    return windows_profiles.WindowsUserProfile(
        profile_id="profile1",
        installation_id="win1",
        volume_id="vol1",
        root_path="Users/Alice",
        display_name="Alice",
        sid="S-1-5-21-1",
        evidence=("ntuser.dat",),
    )


if __name__ == "__main__":
    unittest.main()
