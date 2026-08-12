from __future__ import annotations

import unittest

from worker import content_signature, windows_noise_rules, windows_profiles


class WorkerWindowsNoiseRulesTests(unittest.TestCase):
    def test_os_component_dll_lowers_visibility_with_reason_and_override(self) -> None:
        decision = windows_noise_rules.evaluate_windows_noise(
            display_path="Windows/System32/kernel32.dll",
            signature=content_signature.detect_content_signature_bytes(b"MZ" + b"\0" * 32),
        )

        self.assertEqual("lower", decision.visibility)
        self.assertIn("win-os-components", decision.rule_ids)
        self.assertIn("Windows OS component path", decision.reasons)
        self.assertTrue(decision.override_allowed)

    def test_winsxs_driver_font_update_browser_temp_and_package_rules(self) -> None:
        paths = {
            "Windows/WinSxS/amd64/file.dll": "win-winsxs",
            "Windows/System32/drivers/acpi.sys": "win-os-components",
            "Windows/Fonts/arial.ttf": "win-fonts",
            "Windows/SoftwareDistribution/Download/cache.bin": "win-update-cache",
            "Users/Alice/AppData/Local/Google/Chrome/User Data/Default/Cache/data_1": "browser-cache",
            "Users/Alice/AppData/Local/Temp/tmp.bin": "temp-files",
            "Users/Alice/AppData/Local/Packages/app/cache.bin": "package-store",
        }

        for path, rule_id in paths.items():
            with self.subTest(path=path):
                decision = windows_noise_rules.evaluate_windows_noise(
                    display_path=path,
                    signature=content_signature.detect_content_signature_bytes(
                        b"random cache bytes"
                    ),
                )

                self.assertEqual("lower", decision.visibility)
                self.assertIn(rule_id, decision.rule_ids)

    def test_personal_photo_in_system_directory_is_review_not_hidden(self) -> None:
        decision = windows_noise_rules.evaluate_windows_noise(
            display_path="Windows/System32/vacation.jpg",
            signature=content_signature.detect_content_signature_bytes(b"\xff\xd8\xff\xe0photo"),
        )

        self.assertEqual("review", decision.visibility)
        self.assertIn("noise_rule_conflict", decision.evidence)
        self.assertIn("personal_content_signature", decision.evidence)

    def test_personal_pdf_in_unusual_temp_directory_remains_reachable(self) -> None:
        profile = windows_profiles.WindowsUserProfile(
            profile_id="profile1",
            installation_id=None,
            volume_id="vol1",
            root_path="Users/Alice",
            display_name="Alice",
            sid="S-1-5-21-1",
            evidence=("ntuser.dat",),
        )

        decision = windows_noise_rules.evaluate_windows_noise(
            display_path="Users/Alice/AppData/Local/Temp/tax.pdf",
            signature=content_signature.detect_content_signature_bytes(b"%PDF-1.7\n"),
            profile=profile,
        )

        self.assertEqual("review", decision.visibility)
        self.assertIn("profile:profile1", decision.evidence)
        self.assertTrue(decision.override_allowed)

    def test_unmatched_personal_file_has_normal_visibility(self) -> None:
        decision = windows_noise_rules.evaluate_windows_noise(
            display_path="Users/Alice/Documents/report.docx",
            signature=content_signature.detect_content_signature_bytes(
                b"PK\x03\x04word/document.xml"
            ),
        )

        self.assertEqual("normal", decision.visibility)
        self.assertEqual((), decision.rule_ids)


if __name__ == "__main__":
    unittest.main()
