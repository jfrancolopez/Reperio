from __future__ import annotations

import unittest

from scanner.entry_normalization import NormalizedEntry, normalize_entry, raw_entry
from worker import core_categories, sensitive_locators, windows_profiles


class WorkerSensitiveLocatorsTests(unittest.TestCase):
    def test_bitcoin_core_wallet_and_electrum_layouts(self) -> None:
        entries = (
            entry("Users/Alice/AppData/Roaming/Bitcoin/wallets/main/wallet.dat", "1"),
            entry("Users/Alice/AppData/Roaming/Electrum/wallets/default_wallet", "2"),
        )

        result = sensitive_locators.locate_sensitive_artifacts(
            entries, profiles=(profile_fixture(),)
        )

        self.assertEqual(2, len(result.findings))
        self.assertEqual({"wallet"}, {finding.artifact_type for finding in result.findings})
        self.assertTrue(all(finding.profile_id == "profile1" for finding in result.findings))

    def test_web3_keystore_and_browser_vault_require_validated_evidence(self) -> None:
        keystore = entry("Users/Alice/AppData/Roaming/Ethereum/keystore/key.json", "1")
        browser = entry(
            "Users/Alice/AppData/Local/Google/Chrome/User Data/Default/Local State", "2"
        )

        result = sensitive_locators.locate_sensitive_artifacts(
            (keystore, browser),
            metadata_by_path={
                keystore.display_path: {"validated_indicators": ("web3_keystore", "crypto_kdf")},
                browser.display_path: {"validated_indicators": ("browser_vault",)},
            },
        )

        self.assertEqual(
            {"keystore", "browser_vault"}, {finding.artifact_type for finding in result.findings}
        )

    def test_recovery_indicator_is_redacted_and_secret_value_is_not_emitted(self) -> None:
        seed = entry("Users/Alice/Documents/recovery.txt", "1")

        result = sensitive_locators.locate_sensitive_artifacts(
            (seed,),
            metadata_by_path={
                seed.display_path: {"validated_indicators": ("bip39_mnemonic_shape",)}
            },
        )

        self.assertEqual("recovery_material", result.findings[0].artifact_type)
        joined = " ".join(result.findings[0].evidence)
        self.assertIn("validated_recovery_indicator", joined)
        self.assertNotIn("abandon abandon", joined)

    def test_encrypted_deleted_private_key_remains_visible_with_state(self) -> None:
        key = entry("Users/Alice/.ssh/id_rsa", "1", allocated=False)

        result = sensitive_locators.locate_sensitive_artifacts(
            (key,), metadata_by_path={key.display_path: {"encrypted": True}}
        )

        finding = result.findings[0]
        self.assertEqual("private_key", finding.artifact_type)
        self.assertEqual("deleted/carved", finding.recovery_state)
        self.assertTrue(finding.encrypted)
        self.assertIn("encrypted_artifact_visible", finding.warnings)
        self.assertIn("deleted_or_carved_origin", finding.warnings)

    def test_weak_wallet_name_is_low_confidence_and_decoy_prose_is_ignored(self) -> None:
        weak = entry("Users/Alice/Documents/wallet-notes.txt", "1")
        decoy = entry("Users/Alice/Documents/not a wallet sample wallet prose.txt", "2")

        result = sensitive_locators.locate_sensitive_artifacts((weak, decoy))

        self.assertEqual(1, len(result.findings))
        self.assertEqual("weak_name_match", result.findings[0].artifact_type)
        self.assertLess(result.findings[0].confidence, 0.5)

    def test_category_hook_and_no_network_actions(self) -> None:
        vault = entry("Recovered/archive/member.kdbx", "1")
        category = core_categories.CategoryResult(
            category_version=core_categories.CATEGORY_VERSION,
            assignments=(
                core_categories.CategoryAssignment("wallets/vaults/keys", ("fixture",), 0.9),
            ),
            evidence=("fixture",),
        )

        result = sensitive_locators.locate_sensitive_artifacts(
            (vault,), categories_by_path={vault.display_path: category}
        )

        self.assertEqual((), result.network_actions)
        self.assertEqual("password_vault", result.findings[0].artifact_type)
        self.assertIn("category:wallets/vaults/keys", result.findings[0].evidence)


def entry(path: str, object_id: str, *, allocated: bool = True) -> NormalizedEntry:
    return normalize_entry(
        raw_entry(
            volume_id="vol1", object_id=object_id, path_bytes=path.encode(), allocated=allocated
        )
    )


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
