from __future__ import annotations

import unittest

from worker import protected_artifacts


class WorkerProtectedArtifactsTests(unittest.TestCase):
    def test_protected_and_unprotected_pairs_for_archives_pdf_and_office(self) -> None:
        cases = (
            (
                candidate(
                    "zip_encrypted",
                    "archive.zip",
                    "application/zip",
                    {"encrypted": True, "kdf": "zip-aes"},
                ),
                True,
                "encrypted-archive",
            ),
            (candidate("zip_plain", "archive.zip", "application/zip", {}), False, "none"),
            (
                candidate(
                    "pdf_encrypted", "file.pdf", "application/pdf", {"password_required": True}
                ),
                True,
                "encrypted-pdf",
            ),
            (candidate("pdf_plain", "file.pdf", "application/pdf", {}), False, "none"),
            (
                candidate(
                    "office_encrypted",
                    "file.docx",
                    "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
                    {"encrypted": True},
                ),
                True,
                "encrypted-office-document",
            ),
        )
        for item, expected_protected, expected_kind in cases:
            with self.subTest(artifact_id=item.artifact_id):
                result = protected_artifacts.classify_protected_artifact(item)

            self.assertEqual(expected_protected, result.protected)
            self.assertEqual(expected_kind, result.protection_kind)

    def test_wallet_vault_key_backup_and_whole_volume_signatures_are_visible(self) -> None:
        cases = (
            candidate("wallet", "Users/Alice/wallet.dat", "application/octet-stream", {}),
            candidate("vault", "Passwords/vault.kdbx", "application/octet-stream", {}),
            candidate("cert", "Secrets/id.p12", "application/octet-stream", {}),
            candidate(
                "volume",
                "disk.header",
                "application/octet-stream",
                {"whole_volume_encryption_signature": True, "format": "bitlocker"},
            ),
        )

        results = [protected_artifacts.classify_protected_artifact(item) for item in cases]

        self.assertEqual((True, True, True, True), tuple(result.protected for result in results))
        self.assertEqual("wallet-or-keystore", results[0].protection_kind)
        self.assertEqual("password-vault", results[1].protection_kind)
        self.assertEqual("certificate-key-bundle", results[2].protection_kind)
        self.assertEqual("whole-volume-encryption", results[3].protection_kind)

    def test_entropy_alone_is_weak_and_compressed_data_is_not_overstated(self) -> None:
        result = protected_artifacts.classify_protected_artifact(
            candidate("entropy", "compressed.bin", "application/octet-stream", {}, entropy=7.9)
        )

        self.assertFalse(result.protected)
        self.assertLess(result.confidence, 0.5)
        self.assertIn("high_entropy_weak_evidence_only", result.warnings)
        self.assertEqual(("high_entropy",), result.evidence)

    def test_corrupt_headers_renamed_formats_and_unsupported_encryption_are_labeled(self) -> None:
        corrupt = protected_artifacts.classify_protected_artifact(
            candidate(
                "corrupt", "archive.zip", "application/zip", {"encrypted": True, "corrupt": True}
            )
        )
        unsupported = protected_artifacts.classify_protected_artifact(
            candidate(
                "unsupported",
                "file.one",
                "application/octet-stream",
                {"unsupported_encryption": True},
            )
        )
        renamed = protected_artifacts.classify_protected_artifact(
            candidate("renamed", "file.bin", "application/pdf", {"original_name": "file.pdf"})
        )

        self.assertFalse(corrupt.protected)
        self.assertIn("corrupt_protection_header", corrupt.warnings)
        self.assertFalse(unsupported.protected)
        self.assertEqual("unsupported", unsupported.protection_kind)
        self.assertIn("unsupported_encryption_format", unsupported.warnings)
        self.assertFalse(renamed.protected)
        self.assertIn("renamed_format_evidence", renamed.warnings)


def candidate(
    artifact_id: str,
    path: str,
    mime_type: str,
    metadata: dict[str, object],
    *,
    entropy: float | None = None,
) -> protected_artifacts.ProtectedCandidate:
    return protected_artifacts.ProtectedCandidate(
        artifact_id=artifact_id,
        display_path=path,
        mime_type=mime_type,
        signature="signature",
        metadata=metadata,
        entropy=entropy,
    )


if __name__ == "__main__":
    unittest.main()
