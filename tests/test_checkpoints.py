from __future__ import annotations

import sqlite3
import tempfile
import unittest
from contextlib import closing
from pathlib import Path

from migrations import runner
from shared import catalog_schema, checkpoints, job_state

NOW = "2026-08-11T14:40:00Z"
LATER = "2026-08-11T14:41:00Z"
SOURCE = "a" * 64
OTHER_SOURCE = "b" * 64


class CheckpointTests(unittest.TestCase):
    def test_checkpoint_round_trip_and_supersession_history(self) -> None:
        with closing(self._connection()) as connection:
            self._create_job(connection)
            checkpoints.save_checkpoint(
                connection,
                checkpoint_id="checkpoint_1",
                job_id="job_1",
                source_fingerprint=SOURCE,
                stage="filesystem",
                tool_name="parser",
                tool_version="1.0.0",
                cursor={"offset": 10},
                counters={"files": 1},
                blob=b"first",
                created_at=NOW,
            )
            checkpoints.save_checkpoint(
                connection,
                checkpoint_id="checkpoint_2",
                job_id="job_1",
                source_fingerprint=SOURCE,
                stage="filesystem",
                tool_name="parser",
                tool_version="1.0.0",
                cursor={"offset": 20},
                counters={"files": 2},
                blob=b"second",
                created_at=LATER,
            )

            latest = checkpoints.load_latest_checkpoint(
                connection,
                job_id="job_1",
                source_fingerprint=SOURCE,
                stage="filesystem",
                tool_name="parser",
                tool_version="1.0.0",
            )
            old = connection.execute(
                "SELECT superseded_by_checkpoint_id FROM checkpoints WHERE checkpoint_id = ?",
                ("checkpoint_1",),
            ).fetchone()

            self.assertEqual("checkpoint_2", latest.checkpoint_id)
            self.assertEqual("checkpoint_1", latest.supersedes_checkpoint_id)
            self.assertEqual({"offset": 20}, latest.cursor)
            self.assertEqual({"files": 2}, latest.counters)
            self.assertEqual(b"second", latest.blob)
            self.assertEqual("checkpoint_2", old[0])

    def test_atomic_crash_simulation_rolls_back_partial_checkpoint(self) -> None:
        with closing(self._connection()) as connection:
            self._create_job(connection)
            with self.assertRaises(RuntimeError):
                checkpoints.save_checkpoint(
                    connection,
                    checkpoint_id="checkpoint_crash",
                    job_id="job_1",
                    source_fingerprint=SOURCE,
                    stage="filesystem",
                    tool_name="parser",
                    tool_version="1.0.0",
                    cursor={"offset": 10},
                    counters={"files": 1},
                    blob=b"partial",
                    created_at=NOW,
                    inject_failure_after_insert=True,
                )

            self.assertEqual(
                0, connection.execute("SELECT COUNT(*) FROM checkpoints").fetchone()[0]
            )

    def test_corrupt_checkpoint_requires_restart_stage(self) -> None:
        with closing(self._connection()) as connection:
            self._create_job(connection)
            self._save_valid(connection)
            connection.execute(
                "UPDATE checkpoints SET blob = ? WHERE checkpoint_id = ?",
                (b"corrupt", "checkpoint_1"),
            )

            with self.assertRaises(checkpoints.CheckpointError) as captured:
                self._load(connection)

            self.assertTrue(captured.exception.restart_stage)
            self.assertIn("integrity", str(captured.exception))

    def test_unsupported_checkpoint_version_requires_restart_stage(self) -> None:
        with closing(self._connection()) as connection:
            self._create_job(connection)
            checkpoints.save_checkpoint(
                connection,
                checkpoint_id="checkpoint_old",
                job_id="job_1",
                source_fingerprint=SOURCE,
                stage="filesystem",
                tool_name="parser",
                tool_version="1.0.0",
                cursor={"offset": 10},
                counters={"files": 1},
                blob=b"old",
                created_at=NOW,
                checkpoint_version=99,
            )

            with self.assertRaises(checkpoints.CheckpointError) as captured:
                self._load(connection)

            self.assertTrue(captured.exception.restart_stage)
            self.assertIn("unsupported", str(captured.exception))

    def test_source_and_tool_mismatch_require_restart_stage(self) -> None:
        with closing(self._connection()) as connection:
            self._create_job(connection)
            self._save_valid(connection)

            with self.assertRaises(checkpoints.CheckpointError) as source_error:
                checkpoints.load_latest_checkpoint(
                    connection,
                    job_id="job_1",
                    source_fingerprint=OTHER_SOURCE,
                    stage="filesystem",
                    tool_name="parser",
                    tool_version="1.0.0",
                )
            with self.assertRaises(checkpoints.CheckpointError) as tool_error:
                checkpoints.load_latest_checkpoint(
                    connection,
                    job_id="job_1",
                    source_fingerprint=SOURCE,
                    stage="filesystem",
                    tool_name="parser",
                    tool_version="2.0.0",
                )

            self.assertTrue(source_error.exception.restart_stage)
            self.assertTrue(tool_error.exception.restart_stage)
            self.assertIn("source", str(source_error.exception))
            self.assertIn("tool", str(tool_error.exception))

    def test_malformed_json_checkpoint_requires_restart_stage(self) -> None:
        with closing(self._connection()) as connection:
            self._create_job(connection)
            self._save_valid(connection)
            connection.execute(
                "UPDATE checkpoints SET cursor_json = ? WHERE checkpoint_id = ?",
                ("[]", "checkpoint_1"),
            )

            with self.assertRaises(checkpoints.CheckpointError) as captured:
                self._load(connection)

            self.assertTrue(captured.exception.restart_stage)
            self.assertIn("malformed", str(captured.exception))

    def test_checkpoint_rejects_invalid_identity_and_non_finite_payload(self) -> None:
        with closing(self._connection()) as connection:
            self._create_job(connection)
            with self.assertRaisesRegex(checkpoints.CheckpointError, "fingerprint"):
                checkpoints.save_checkpoint(
                    connection,
                    checkpoint_id="checkpoint_bad_fingerprint",
                    job_id="job_1",
                    source_fingerprint="not-a-hash",
                    stage="filesystem",
                    tool_name="parser",
                    tool_version="1.0.0",
                    cursor={},
                    counters={},
                    blob=b"invalid",
                    created_at=NOW,
                )
            with self.assertRaisesRegex(checkpoints.CheckpointError, "canonical JSON"):
                checkpoints.save_checkpoint(
                    connection,
                    checkpoint_id="checkpoint_nan",
                    job_id="job_1",
                    source_fingerprint=SOURCE,
                    stage="filesystem",
                    tool_name="parser",
                    tool_version="1.0.0",
                    cursor={"offset": float("nan")},
                    counters={},
                    blob=b"invalid",
                    created_at=NOW,
                )

    def test_old_schema_database_migrates_to_checkpoint_table(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "catalog.sqlite3"
            connection = catalog_schema.connect_catalog(db_path)
            try:
                connection.execute(
                    """
                    CREATE TABLE jobs (
                        job_id TEXT PRIMARY KEY,
                        case_id TEXT,
                        job_type TEXT NOT NULL,
                        state TEXT NOT NULL,
                        input_json TEXT NOT NULL,
                        idempotency_key TEXT NOT NULL UNIQUE,
                        attempts INTEGER NOT NULL DEFAULT 0,
                        max_attempts INTEGER NOT NULL DEFAULT 1,
                        lease_owner TEXT,
                        lease_expires_at TEXT,
                        error_json TEXT,
                        created_at TEXT NOT NULL,
                        updated_at TEXT NOT NULL
                    ) STRICT
                    """
                )
                connection.execute(
                    """
                    CREATE TABLE schema_migrations (
                        version INTEGER PRIMARY KEY,
                        name TEXT NOT NULL UNIQUE,
                        applied_at TEXT NOT NULL
                    ) STRICT
                    """
                )
                connection.execute(
                    """
                    INSERT INTO schema_migrations (version, name, applied_at)
                    VALUES (1, 'initial_catalog_schema', ?)
                    """,
                    (NOW,),
                )
            finally:
                connection.close()

            runner.migrate_catalog(db_path)
            connection = catalog_schema.connect_catalog(db_path)
            try:
                self.assertIsNotNone(
                    connection.execute(
                        """
                        SELECT 1 FROM sqlite_master
                        WHERE type = 'table' AND name = 'checkpoints'
                        """
                    ).fetchone()
                )
                self.assertIsNotNone(connection.execute("PRAGMA table_info(jobs)").fetchall())
                self.assertIn(
                    "retry_after_at",
                    {row[1] for row in connection.execute("PRAGMA table_info(jobs)")},
                )
            finally:
                connection.close()

    def _connection(self) -> sqlite3.Connection:
        connection = sqlite3.connect(":memory:", isolation_level=None)
        catalog_schema.create_initial_schema(connection)
        return connection

    def _create_job(self, connection: sqlite3.Connection) -> None:
        job_state.create_job(
            connection,
            job_id="job_1",
            job_type="scan",
            input_payload={"stage": "filesystem"},
            idempotency_key="idem_job_1",
            now=NOW,
        )

    def _save_valid(self, connection: sqlite3.Connection) -> None:
        checkpoints.save_checkpoint(
            connection,
            checkpoint_id="checkpoint_1",
            job_id="job_1",
            source_fingerprint=SOURCE,
            stage="filesystem",
            tool_name="parser",
            tool_version="1.0.0",
            cursor={"offset": 10},
            counters={"files": 1},
            blob=b"valid",
            created_at=NOW,
        )

    def _load(self, connection: sqlite3.Connection) -> checkpoints.CheckpointRecord:
        return checkpoints.load_latest_checkpoint(
            connection,
            job_id="job_1",
            source_fingerprint=SOURCE,
            stage="filesystem",
            tool_name="parser",
            tool_version="1.0.0",
        )


if __name__ == "__main__":
    unittest.main()
