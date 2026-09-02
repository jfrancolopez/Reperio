from __future__ import annotations

import io
import json
import tarfile
import tempfile
import unittest
from pathlib import Path

from shared import diagnostics_backup


class DiagnosticsBackupTests(unittest.TestCase):
    def test_live_backup_is_refused_until_workers_paused(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = fixture_state(Path(tmp) / "state")

            with self.assertRaises(diagnostics_backup.DiagnosticsBackupError) as captured:
                diagnostics_backup.create_state_backup(
                    root,
                    Path(tmp) / "backup.tar.gz",
                    workers_paused=lambda: False,
                )

            self.assertEqual("workers_not_paused", captured.exception.code)

    def test_backup_restore_round_trip_excludes_secrets_and_source_content(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = fixture_state(Path(tmp) / "state")
            archive = Path(tmp) / "backup.tar.gz"

            result = diagnostics_backup.create_state_backup(
                root, archive, workers_paused=lambda: True, include_derivatives=True
            )
            restored = diagnostics_backup.restore_state_backup(archive, Path(tmp) / "restore")

            self.assertIn("catalog.sqlite3", result.entries)
            self.assertIn("settings.json", restored)
            self.assertIn("checkpoints/stage.chk", restored)
            self.assertIn("derivatives/thumb.webp", restored)
            self.assertNotIn("secrets/master.key", restored)
            self.assertNotIn("source/raw.bin", restored)

    def test_backup_archive_cannot_overwrite_state(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = fixture_state(Path(tmp) / "state")

            with self.assertRaisesRegex(
                diagnostics_backup.DiagnosticsBackupError, "outside the state"
            ):
                diagnostics_backup.create_state_backup(
                    root, root / "catalog.sqlite3", workers_paused=lambda: True
                )

    def test_restore_requires_empty_non_symlink_destination(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            archive = Path(tmp) / "backup.tar.gz"
            write_archive(
                archive,
                {"format_version": 1, "schema_version": 1, "entries": []},
                {},
            )
            restore = Path(tmp) / "restore"
            restore.mkdir()
            (restore / "existing").write_text("keep", encoding="utf-8")

            with self.assertRaisesRegex(diagnostics_backup.DiagnosticsBackupError, "must be empty"):
                diagnostics_backup.restore_state_backup(archive, restore)

    def test_restore_rejects_corrupt_archive_member(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            archive = Path(tmp) / "corrupt.tar.gz"
            manifest = {
                "format_version": 1,
                "schema_version": 1,
                "entries": [{"path": "settings.json", "sha256": "0" * 64, "size_bytes": 2}],
            }
            write_archive(archive, manifest, {"settings.json": b"{}"})

            with self.assertRaises(diagnostics_backup.DiagnosticsBackupError) as captured:
                diagnostics_backup.restore_state_backup(archive, Path(tmp) / "restore")

            self.assertEqual("integrity_mismatch", captured.exception.code)

    def test_restore_rejects_newer_schema(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            archive = Path(tmp) / "future.tar.gz"
            write_archive(
                archive,
                {"format_version": 1, "schema_version": 999, "entries": []},
                {},
            )

            with self.assertRaises(diagnostics_backup.DiagnosticsBackupError) as captured:
                diagnostics_backup.restore_state_backup(archive, Path(tmp) / "restore")

            self.assertEqual("future_schema", captured.exception.code)

    def test_restore_rejects_missing_manifest_member(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            archive = Path(tmp) / "missing.tar.gz"
            write_archive(
                archive,
                {
                    "format_version": 1,
                    "schema_version": 1,
                    "entries": [{"path": "settings.json", "sha256": "0" * 64, "size_bytes": 2}],
                },
                {},
            )

            with self.assertRaisesRegex(diagnostics_backup.DiagnosticsBackupError, "missing"):
                diagnostics_backup.restore_state_backup(archive, Path(tmp) / "restore")

    def test_redacted_support_bundle_masks_secret_like_fields(self) -> None:
        bundle = diagnostics_backup.build_redacted_support_bundle(
            settings={"destination_token": "live-token", "theme": "dark"},
            secret_snapshot=[{"ref": "vault:abc", "value": "********"}],
        )

        self.assertEqual("********", bundle["settings"]["destination_token"])
        self.assertEqual("dark", bundle["settings"]["theme"])
        self.assertEqual("********", bundle["secrets"][0]["value"])

    def test_redacted_support_bundle_masks_untrusted_secret_value(self) -> None:
        bundle = diagnostics_backup.build_redacted_support_bundle(
            settings={}, secret_snapshot=[{"ref": "vault:abc", "value": "live-secret"}]
        )

        self.assertNotIn("live-secret", json.dumps(bundle))
        self.assertEqual("********", bundle["secrets"][0]["value"])


def fixture_state(root: Path) -> Path:
    root.mkdir()
    (root / "catalog.sqlite3").write_bytes(b"catalog")
    (root / "settings.json").write_text('{"theme":"dark"}', encoding="utf-8")
    (root / "checkpoints").mkdir()
    (root / "checkpoints" / "stage.chk").write_bytes(b"checkpoint")
    (root / "derivatives").mkdir()
    (root / "derivatives" / "thumb.webp").write_bytes(b"thumb")
    (root / "secrets").mkdir()
    (root / "secrets" / "master.key").write_bytes(b"secret")
    (root / "source").mkdir()
    (root / "source" / "raw.bin").write_bytes(b"source")
    return root


def write_archive(archive_path: Path, manifest: dict[str, object], files: dict[str, bytes]) -> None:
    with tarfile.open(archive_path, "w:gz") as archive:
        manifest_bytes = json.dumps(manifest).encode("utf-8")
        manifest_info = tarfile.TarInfo("manifest.json")
        manifest_info.size = len(manifest_bytes)
        archive.addfile(manifest_info, io.BytesIO(manifest_bytes))
        for name, data in files.items():
            info = tarfile.TarInfo(name)
            info.size = len(data)
            archive.addfile(info, io.BytesIO(data))


if __name__ == "__main__":
    unittest.main()
