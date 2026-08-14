from __future__ import annotations

import sqlite3
import tempfile
import unittest
from pathlib import Path

from shared.browser_artifact_schemas import validate_browser_artifact
from worker import sqlite_artifacts


class WorkerSqliteArtifactsTests(unittest.TestCase):
    def test_copied_bundle_reports_wal_and_shm_companions(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "scratch"
            root.mkdir()
            database = root / "History"
            sqlite3.connect(database).close()
            (root / "History-wal").write_bytes(b"synthetic wal")
            (root / "History-shm").write_bytes(b"synthetic shm")

            bundle = sqlite_artifacts.copied_sqlite_bundle(database, root, "History")

        self.assertEqual(database.resolve(), bundle.database_path)
        self.assertIn("sqlite_wal_present:History", bundle.warnings)
        self.assertIn("sqlite_shm_present:History", bundle.warnings)

    def test_copied_bundle_rejects_source_path_outside_scratch(self) -> None:
        with (
            tempfile.TemporaryDirectory() as scratch_tmp,
            tempfile.TemporaryDirectory() as source_tmp,
        ):
            outside = Path(source_tmp) / "places.sqlite"
            outside.write_bytes(b"source")
            with self.assertRaises(ValueError):
                sqlite_artifacts.copied_sqlite_bundle(outside, Path(scratch_tmp), "places.sqlite")

    def test_stale_wal_companion_is_labeled_without_blocking_database(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "scratch"
            root.mkdir()
            database = root / "History"
            connection = sqlite3.connect(database)
            try:
                connection.execute("CREATE TABLE urls (id INTEGER PRIMARY KEY)")
                connection.commit()
            finally:
                connection.close()
            (root / "History-wal").write_bytes(b"not a wal")
            bundle = sqlite_artifacts.copied_sqlite_bundle(database, root, "History")

            copied_connection, warnings = sqlite_artifacts.open_copied_sqlite_bundle(bundle)

        self.assertIsNotNone(copied_connection)
        if copied_connection is not None:
            copied_connection.close()
        self.assertIn("sqlite_wal_present:History", warnings)
        self.assertIn("sqlite_shm_missing:History", warnings)

    def test_uncheckpointed_wal_rows_are_visible_from_copied_companion(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "scratch"
            root.mkdir()
            database = root / "History"
            writer = sqlite3.connect(database)
            try:
                writer.execute("PRAGMA journal_mode=WAL")
                writer.execute("PRAGMA wal_autocheckpoint=0")
                writer.execute("CREATE TABLE urls (id INTEGER PRIMARY KEY, url TEXT)")
                writer.execute("INSERT INTO urls VALUES (1, 'https://wal.example.test/')")
                writer.commit()
                bundle = sqlite_artifacts.copied_sqlite_bundle(database, root, "History")

                copied_connection, warnings = sqlite_artifacts.open_copied_sqlite_bundle(bundle)
                try:
                    self.assertIsNotNone(copied_connection)
                    assert copied_connection is not None
                    url = copied_connection.execute("SELECT url FROM urls WHERE id = 1").fetchone()[
                        0
                    ]
                finally:
                    if copied_connection is not None:
                        copied_connection.close()
            finally:
                writer.close()

        self.assertEqual("https://wal.example.test/", url)
        self.assertIn("sqlite_wal_present:History", warnings)

    def test_deleted_row_candidates_are_labeled_lower_confidence_and_duplicate_linked(self) -> None:
        result = sqlite_artifacts.recover_deleted_sqlite_rows(
            browser_family="chromium",
            profile_id="profile-1",
            parser_version="test-parser-v1",
            entry_ids={"History": "entry-History"},
            live_validation_keys={"https://example.test/|2024-01-01T00:00:00Z"},
            candidates=(
                sqlite_artifacts.DeletedSqliteRowCandidate(
                    artifact_kind="visit",
                    source_artifact="History",
                    row_reference="freelist:page1:cell2",
                    validation_key="https://example.test/|2024-01-01T00:00:00Z",
                    fields={
                        "url": "https://example.test/",
                        "title": "Deleted",
                        "visit_time": {
                            "raw_epoch": 1,
                            "normalized_utc": "2024-01-01T00:00:00Z",
                            "display_timezone": "UTC",
                        },
                    },
                ),
            ),
        )

        self.assertEqual(1, len(result.records))
        record = result.records[0]
        self.assertTrue(validate_browser_artifact(record).valid, record)
        self.assertEqual(0.55, record["recovery_confidence"])
        self.assertEqual("validated_deleted_row", record["sqlite_recovery_state"])
        self.assertEqual(
            "https://example.test/|2024-01-01T00:00:00Z", record["duplicate_of_live_row"]
        )
        self.assertIn("deleted_sqlite_row_duplicate_live:freelist:page1:cell2", result.warnings)

    def test_invalid_deleted_row_candidate_is_rejected_without_record(self) -> None:
        result = sqlite_artifacts.recover_deleted_sqlite_rows(
            browser_family="firefox",
            profile_id="profile-2",
            parser_version="test-parser-v1",
            entry_ids={},
            live_validation_keys=set(),
            candidates=(
                sqlite_artifacts.DeletedSqliteRowCandidate(
                    artifact_kind="visit",
                    source_artifact="places.sqlite",
                    row_reference="random-page",
                    validation_key="",
                    fields={"url": "https://example.test/"},
                ),
            ),
        )

        self.assertEqual((), result.records)
        self.assertIn("deleted_sqlite_row_rejected:random-page:missing_key", result.warnings)


if __name__ == "__main__":
    unittest.main()
