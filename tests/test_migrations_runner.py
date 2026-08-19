from __future__ import annotations

import sqlite3
import tempfile
import unittest
from pathlib import Path

from migrations import runner
from shared import catalog_schema


class MigrationRunnerTests(unittest.TestCase):
    def test_upgrade_from_empty_database_reaches_current_schema(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "catalog.sqlite3"

            result = runner.migrate_catalog(db_path)

            self.assertEqual(runner.CURRENT_SCHEMA_VERSION, result.current_version)
            self.assertEqual((1, 2, 3, 4, 5, 6, 7), result.applied_versions)
            self.assertIsNone(result.backup_path)
            self.assertTrue(result.workers_allowed)
            self.assertTrue(runner.ready_for_workers(db_path))

    def test_upgrade_from_prior_unversioned_fixture_adds_version_record_and_backup(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            db_path = root / "catalog.sqlite3"
            backup_dir = root / "backups"
            connection = catalog_schema.connect_catalog(db_path)
            catalog_schema.create_initial_schema(connection)
            connection.close()

            result = runner.migrate_catalog(db_path, backup_dir=backup_dir)

            self.assertEqual(runner.CURRENT_SCHEMA_VERSION, result.current_version)
            self.assertEqual((1, 2, 3, 4, 5, 6, 7), result.applied_versions)
            self.assertIsNotNone(result.backup_path)
            assert result.backup_path is not None
            self.assertTrue(result.backup_path.exists())
            backup = catalog_schema.connect_catalog(result.backup_path)
            try:
                self.assertIsNotNone(
                    backup.execute(
                        """
                        SELECT 1 FROM sqlite_master
                        WHERE type = 'table' AND name = 'sources'
                        """
                    ).fetchone()
                )
                self.assertEqual(0, runner.current_schema_version(backup))
            finally:
                backup.close()
            self.assertEqual(runner.CURRENT_SCHEMA_VERSION, _version_rows(db_path))

    def test_failed_migration_rolls_back_and_workers_are_not_ready(self) -> None:
        def fail_after_ddl(connection: sqlite3.Connection) -> None:
            connection.execute("CREATE TABLE transient_table (id INTEGER PRIMARY KEY) STRICT")
            raise RuntimeError("injected failure")

        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "catalog.sqlite3"
            bad_migrations = (runner.Migration(1, "broken", fail_after_ddl),)

            with self.assertRaises(RuntimeError):
                runner.migrate_catalog(db_path, migrations=bad_migrations)

            connection = catalog_schema.connect_catalog(db_path)
            try:
                self.assertIsNone(
                    connection.execute(
                        """
                        SELECT 1 FROM sqlite_master
                        WHERE type = 'table' AND name = 'transient_table'
                        """
                    ).fetchone()
                )
            finally:
                connection.close()
            self.assertFalse(runner.ready_for_workers(db_path))

    def test_already_current_database_applies_nothing(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "catalog.sqlite3"
            runner.migrate_catalog(db_path)

            result = runner.migrate_catalog(db_path)

            self.assertEqual((), result.applied_versions)
            self.assertIsNone(result.backup_path)
            self.assertTrue(result.workers_allowed)

    def test_future_version_is_refused(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "catalog.sqlite3"
            runner.migrate_catalog(db_path)
            connection = catalog_schema.connect_catalog(db_path)
            try:
                connection.execute(
                    """
                    INSERT INTO schema_migrations (version, name, applied_at)
                    VALUES (?, ?, ?)
                    """,
                    (999, "future", "2026-08-11T14:40:00Z"),
                )
            finally:
                connection.close()

            with self.assertRaises(runner.FutureSchemaError):
                runner.migrate_catalog(db_path)


def _version_rows(db_path: Path) -> int:
    connection = catalog_schema.connect_catalog(db_path)
    try:
        return int(connection.execute("SELECT COUNT(*) FROM schema_migrations").fetchone()[0])
    finally:
        connection.close()


if __name__ == "__main__":
    unittest.main()
