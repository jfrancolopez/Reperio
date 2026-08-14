from __future__ import annotations

import sqlite3
import tempfile
import unittest
from contextlib import closing
from pathlib import Path

from shared import catalog_schema

NOW = "2026-08-11T14:40:00Z"
HASH = "a" * 64


class CatalogSchemaTests(unittest.TestCase):
    def test_schema_creation_enables_foreign_keys_and_wal(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "catalog.sqlite3"
            connection = catalog_schema.connect_catalog(db_path)
            try:
                catalog_schema.create_initial_schema(connection)

                tables = {
                    row[0]
                    for row in connection.execute(
                        "SELECT name FROM sqlite_master WHERE type = 'table'"
                    )
                }

                self.assertEqual(1, connection.execute("PRAGMA foreign_keys").fetchone()[0])
                self.assertEqual("wal", connection.execute("PRAGMA journal_mode").fetchone()[0])
                self.assertTrue(
                    {
                        "sources",
                        "scan_cases",
                        "volumes",
                        "entries",
                        "contents",
                        "findings",
                        "evidence",
                        "jobs",
                        "events",
                        "review_actions",
                        "artifacts",
                        "derivatives",
                        "browser_artifacts",
                        "exports",
                        "audit_references",
                    }.issubset(tables)
                )
            finally:
                connection.close()

    def test_browser_artifact_table_rejects_invalid_kind_confidence_and_json(self) -> None:
        with closing(self._connection()) as connection:
            self._insert_source(connection)
            self._insert_case(connection)

            connection.execute(
                """
                INSERT INTO browser_artifacts
                (browser_artifact_id, case_id, profile_id, artifact_kind, browser_family,
                 raw_provenance_json, artifact_json, recovery_confidence, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    "browser_1",
                    "case_1",
                    "profile_1",
                    "visit",
                    "chromium",
                    '{"entry_id":"entry_1"}',
                    '{"url":"https://example.test"}',
                    1.0,
                    NOW,
                ),
            )

            with self.assertRaises(sqlite3.IntegrityError):
                connection.execute(
                    """
                    INSERT INTO browser_artifacts
                    (browser_artifact_id, case_id, profile_id, artifact_kind, browser_family,
                     raw_provenance_json, artifact_json, recovery_confidence, created_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        "browser_bad_kind",
                        "case_1",
                        "profile_1",
                        "cookie_value",
                        "chromium",
                        "{}",
                        "{}",
                        0.5,
                        NOW,
                    ),
                )
            with self.assertRaises(sqlite3.IntegrityError):
                connection.execute(
                    """
                    INSERT INTO browser_artifacts
                    (browser_artifact_id, case_id, profile_id, artifact_kind, browser_family,
                     raw_provenance_json, artifact_json, recovery_confidence, created_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        "browser_bad_confidence",
                        "case_1",
                        "profile_1",
                        "visit",
                        "chromium",
                        "{}",
                        "{}",
                        1.5,
                        NOW,
                    ),
                )

    def test_constraints_reject_bad_foreign_keys_enums_timestamps_and_json(self) -> None:
        with closing(self._connection()) as connection:
            with self.assertRaises(sqlite3.IntegrityError):
                connection.execute(
                    """
                    INSERT INTO scan_cases
                    (case_id, source_id, state, policy_json, created_at, updated_at)
                    VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    ("case_missing", "source_missing", "created", "{}", NOW, NOW),
                )

            self._insert_source(connection)
            with self.assertRaises(sqlite3.IntegrityError):
                self._insert_case(connection, state="invalid")
            with self.assertRaises(sqlite3.IntegrityError):
                self._insert_case(connection, case_id="case_bad_json", policy_json="not-json")
            with self.assertRaises(sqlite3.IntegrityError):
                self._insert_case(connection, case_id="case_bad_time", created_at="2026-08-11")

    def test_path_bytes_round_trip_unicode_and_null_without_being_identifier(self) -> None:
        with closing(self._connection()) as connection:
            self._insert_source(connection)
            self._insert_case(connection)
            path_bytes = "photos/été\x00raw.jpg".encode()
            name_bytes = "été\x00raw.jpg".encode()

            connection.execute(
                """
                INSERT INTO entries
                (entry_id, case_id, entry_kind, path_bytes, display_path, name_bytes,
                 metadata_json, discovered_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    "entry_1",
                    "case_1",
                    "file",
                    path_bytes,
                    "photos/ete raw.jpg",
                    name_bytes,
                    "{}",
                    NOW,
                ),
            )

            primary_key_flags = {
                row[1]: row[5]
                for row in connection.execute("PRAGMA table_info(entries)").fetchall()
            }
            stored_path, stored_name = connection.execute(
                "SELECT path_bytes, name_bytes FROM entries WHERE entry_id = ?", ("entry_1",)
            ).fetchone()

            self.assertEqual(path_bytes, stored_path)
            self.assertEqual(name_bytes, stored_name)
            self.assertEqual(1, primary_key_flags["entry_id"])
            self.assertEqual(0, primary_key_flags["path_bytes"])
            self.assertEqual(0, primary_key_flags["display_path"])

    def test_concurrent_reader_and_writer_smoke(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "catalog.sqlite3"
            writer = catalog_schema.connect_catalog(db_path)
            reader = catalog_schema.connect_catalog(db_path)
            try:
                catalog_schema.create_initial_schema(writer)

                writer.execute("BEGIN IMMEDIATE")
                self._insert_source(writer, source_id="source_pending")

                self.assertEqual(0, reader.execute("SELECT COUNT(*) FROM sources").fetchone()[0])

                writer.execute("COMMIT")
                self.assertEqual(1, reader.execute("SELECT COUNT(*) FROM sources").fetchone()[0])
            finally:
                reader.close()
                writer.close()

    def _connection(self) -> sqlite3.Connection:
        connection = sqlite3.connect(":memory:")
        catalog_schema.create_initial_schema(connection)
        return connection

    def _insert_source(self, connection: sqlite3.Connection, source_id: str = "source_1") -> None:
        connection.execute(
            """
            INSERT INTO sources
            (source_id, stable_identity, media_kind, size_bytes, sector_size,
             fingerprint_sha256, status, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                source_id,
                f"stable-{source_id}",
                "block",
                1024,
                512,
                HASH,
                "candidate",
                NOW,
                NOW,
            ),
        )

    def _insert_case(
        self,
        connection: sqlite3.Connection,
        case_id: str = "case_1",
        state: str = "created",
        policy_json: str = "{}",
        created_at: str = NOW,
    ) -> None:
        connection.execute(
            """
            INSERT INTO scan_cases
            (case_id, source_id, state, policy_json, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (case_id, "source_1", state, policy_json, created_at, NOW),
        )


if __name__ == "__main__":
    unittest.main()
