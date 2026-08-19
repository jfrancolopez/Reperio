#!/usr/bin/env python3

from __future__ import annotations

import sqlite3
import tempfile
import unittest
from contextlib import closing
from pathlib import Path

from migrations import runner
from shared import catalog_schema, event_outbox, media_checkpoints, media_identity

NOW = "2026-08-19T10:00:00Z"
LATER = "2026-08-19T11:00:00Z"
FINGERPRINT_A = "a" * 64
FINGERPRINT_B = "b" * 64


def medium_record(
    *,
    fingerprint: str | None = FINGERPRINT_A,
    capacity: int = 32 * 1024 * 1024,
    generation: int = 0,
    geometry: dict | None = None,
    sessions: list[dict] | None = None,
) -> dict:
    signals = media_identity.normalize_medium_signals(
        {
            "size_bytes": capacity,
            "sampled_fingerprint_sha256": fingerprint,
            "media_change_generation": generation,
            "geometry": geometry,
            "toc_sessions": sessions,
        }
    )
    return media_identity.medium_identity_record(
        "reader_1", signals, identity_strength="reader-plus-medium"
    )


class MigrationTests(unittest.TestCase):
    def test_migration_round_trip_adds_media_tables_and_column(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "catalog.sqlite3"
            result = runner.migrate_catalog(db_path)
            self.assertEqual(7, result.current_version)
            connection = catalog_schema.connect_catalog(db_path)
            try:
                tables = {
                    row[0]
                    for row in connection.execute(
                        "SELECT name FROM sqlite_master WHERE type = 'table'"
                    )
                }
                self.assertIn("source_devices", tables)
                self.assertIn("source_media", tables)
                columns = {row[1] for row in connection.execute("PRAGMA table_info(checkpoints)")}
                self.assertIn("medium_identity_json", columns)
            finally:
                connection.close()

    def test_upgrade_from_version_6_preserves_data(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "catalog.sqlite3"
            old = runner.migrate_catalog(db_path, migrations=runner.DEFAULT_MIGRATIONS[:6])
            self.assertEqual(6, old.current_version)
            connection = catalog_schema.connect_catalog(db_path)
            connection.execute(
                """
                INSERT INTO sources
                (source_id, stable_identity, media_kind, size_bytes, sector_size,
                 fingerprint_sha256, status, created_at, updated_at)
                VALUES ('s1', 'stable-1', 'block', 1024, 512, ?, 'candidate', ?, ?)
                """,
                (FINGERPRINT_A, NOW, NOW),
            )
            connection.commit()
            connection.close()

            upgraded = runner.migrate_catalog(db_path)
            self.assertEqual(7, upgraded.current_version)
            connection = catalog_schema.connect_catalog(db_path)
            try:
                self.assertEqual(
                    1,
                    connection.execute(
                        "SELECT COUNT(*) FROM sources WHERE source_id = 's1'"
                    ).fetchone()[0],
                )
            finally:
                connection.close()


class MediumIdentityKeyTests(unittest.TestCase):
    def test_key_is_deterministic_and_identity_based(self) -> None:
        record = medium_record()
        self.assertEqual(
            media_checkpoints.medium_identity_key(record),
            media_checkpoints.medium_identity_key(record),
        )
        self.assertNotEqual(
            media_checkpoints.medium_identity_key(record),
            media_checkpoints.medium_identity_key(medium_record(fingerprint=FINGERPRINT_B)),
        )


class ResumeEligibilityTests(unittest.TestCase):
    def test_same_medium_reinsertion_is_eligible(self) -> None:
        eligibility = media_checkpoints.resume_eligibility(medium_record(), medium_record())
        self.assertTrue(eligibility.eligible)
        self.assertIsNone(eligibility.reason)
        self.assertFalse(eligibility.offers_new_case)

    def test_same_reader_different_medium_blocks_and_offers_new_case(self) -> None:
        eligibility = media_checkpoints.resume_eligibility(
            medium_record(fingerprint=FINGERPRINT_A, capacity=16 * 1024 * 1024),
            medium_record(fingerprint=FINGERPRINT_A, capacity=32 * 1024 * 1024),
        )
        self.assertFalse(eligibility.eligible)
        self.assertEqual("capacity_changed", eligibility.reason)
        self.assertTrue(eligibility.offers_new_case)

    def test_same_capacity_different_samples_blocks(self) -> None:
        eligibility = media_checkpoints.resume_eligibility(
            medium_record(fingerprint=FINGERPRINT_A), medium_record(fingerprint=FINGERPRINT_B)
        )
        self.assertFalse(eligibility.eligible)
        self.assertEqual("fingerprint_changed", eligibility.reason)

    def test_added_optical_session_blocks(self) -> None:
        before = medium_record(sessions=[{"start_sector": 0, "length_sectors": 1000}])
        after = medium_record(
            sessions=[
                {"start_sector": 0, "length_sectors": 1000},
                {"start_sector": 1000, "length_sectors": 500},
            ]
        )
        eligibility = media_checkpoints.resume_eligibility(before, after)
        self.assertFalse(eligibility.eligible)
        self.assertEqual("toc_sessions_changed", eligibility.reason)

    def test_changed_floppy_geometry_blocks(self) -> None:
        before = medium_record(
            geometry={"cylinders": 80, "heads": 2, "sectors_per_track": 18, "bytes_per_sector": 512}
        )
        after = medium_record(
            geometry={"cylinders": 80, "heads": 2, "sectors_per_track": 36, "bytes_per_sector": 512}
        )
        eligibility = media_checkpoints.resume_eligibility(before, after)
        self.assertFalse(eligibility.eligible)
        self.assertEqual("geometry_changed", eligibility.reason)

    def test_unreadable_sample_blocks_resume(self) -> None:
        eligibility = media_checkpoints.resume_eligibility(
            medium_record(fingerprint=FINGERPRINT_A), medium_record(fingerprint=None)
        )
        self.assertFalse(eligibility.eligible)
        self.assertEqual("unreadable_sample_identity_weak", eligibility.reason)

    def test_generation_bump_blocks_resume(self) -> None:
        eligibility = media_checkpoints.resume_eligibility(
            medium_record(generation=0), medium_record(generation=1)
        )
        self.assertFalse(eligibility.eligible)
        self.assertEqual("media_replaced", eligibility.reason)


class MediumCheckpointStorageTests(unittest.TestCase):
    def _connection(self) -> sqlite3.Connection:
        scratch = Path(tempfile.mkdtemp(prefix="rpr180-"))
        db_path = scratch / "catalog.sqlite3"
        runner.migrate_catalog(db_path)
        return catalog_schema.connect_catalog(db_path)

    def test_checkpoint_save_and_load_resumes_on_same_medium(self) -> None:
        with closing(self._connection()) as connection:
            self._insert_job(connection)
            record = medium_record()
            media_checkpoints.save_medium_checkpoint(
                connection,
                checkpoint_id="ckpt_1",
                job_id="job_1",
                medium_identity=record,
                stage="entries",
                tool_name="fat16",
                tool_version="1.0",
                cursor={"next": 42},
                counters={"entries": 100},
                blob=b"stage-data",
                created_at=NOW,
            )
            loaded, eligibility = media_checkpoints.load_medium_checkpoint(
                connection,
                job_id="job_1",
                medium_identity=record,
                stage="entries",
                tool_name="fat16",
                tool_version="1.0",
            )
            assert loaded is not None
            self.assertTrue(eligibility.eligible)
            self.assertEqual({"next": 42}, loaded.cursor)
            self.assertEqual(b"stage-data", loaded.blob)

    def test_interrupted_checkpoint_rolls_back(self) -> None:
        with closing(self._connection()) as connection:
            with self.assertRaises(TypeError):
                media_checkpoints.save_medium_checkpoint(
                    connection,
                    checkpoint_id="ckpt_bad",
                    job_id="job_1",
                    medium_identity=medium_record(),
                    stage="entries",
                    tool_name="fat16",
                    tool_version="1.0",
                    cursor={"bad": object()},
                    counters={},
                    blob=b"x",
                    created_at=NOW,
                )
            self.assertEqual(
                0,
                connection.execute(
                    "SELECT COUNT(*) FROM checkpoints WHERE checkpoint_id = 'ckpt_bad'"
                ).fetchone()[0],
            )

    def test_changed_medium_blocks_load_and_offers_new_case(self) -> None:
        with closing(self._connection()) as connection:
            self._insert_job(connection)
            media_checkpoints.save_medium_checkpoint(
                connection,
                checkpoint_id="ckpt_1",
                job_id="job_1",
                medium_identity=medium_record(fingerprint=FINGERPRINT_A),
                stage="entries",
                tool_name="fat16",
                tool_version="1.0",
                cursor={},
                counters={},
                blob=b"x",
                created_at=NOW,
            )
            with self.assertRaises(media_checkpoints.MediaCheckpointError) as caught:
                media_checkpoints.load_medium_checkpoint(
                    connection,
                    job_id="job_1",
                    medium_identity=medium_record(fingerprint=FINGERPRINT_B),
                    stage="entries",
                    tool_name="fat16",
                    tool_version="1.0",
                )
            self.assertTrue(caught.exception.offers_new_case)
            self.assertIn("fingerprint_changed", str(caught.exception))

    def test_media_event_does_not_touch_job_state(self) -> None:
        with closing(self._connection()) as connection:
            self._insert_source_case(connection)
            media_checkpoints.record_medium_event(
                connection,
                event_id="event_1",
                case_id="case_1",
                event_type="media.replaced",
                payload={"media_id": "media_1", "reason": "fingerprint_changed"},
                now=NOW,
            )
            events = event_outbox.list_events(connection, case_id="case_1")
            self.assertEqual("media.replaced", events[0]["event_type"])

    def test_prior_findings_stay_browsable_when_source_absent(self) -> None:
        with closing(self._connection()) as connection:
            self._insert_source_case(connection)
            connection.execute(
                """
                INSERT INTO findings
                (finding_id, case_id, finding_type, severity, title, summary, status, confidence, created_at)
                VALUES ('finding_1', 'case_1', 'photo', 'medium', 't', 's', 'new', 0.9, ?)
                """,
                (NOW,),
            )
            media_checkpoints.record_medium_event(
                connection,
                event_id="event_2",
                case_id="case_1",
                event_type="media.disconnect",
                payload={"source_id": "source_1"},
                now=LATER,
            )
            count = connection.execute(
                "SELECT COUNT(*) FROM findings WHERE case_id = 'case_1'"
            ).fetchone()[0]
            self.assertEqual(1, count)

    def test_unsupported_medium_event_is_rejected(self) -> None:
        with closing(self._connection()) as connection:
            self._insert_source_case(connection)
            with self.assertRaisesRegex(media_checkpoints.MediaCheckpointError, "unsupported"):
                media_checkpoints.record_medium_event(
                    connection,
                    event_id="event_3",
                    case_id="case_1",
                    event_type="media.deleted",
                    payload={},
                    now=NOW,
                )

    def _insert_job(self, connection: sqlite3.Connection) -> None:
        connection.execute(
            """
            INSERT INTO jobs
            (job_id, job_type, state, input_json, idempotency_key, created_at, updated_at)
            VALUES ('job_1', 'scan', 'running', '{}', 'idem_1', ?, ?)
            """,
            (NOW, NOW),
        )
        connection.commit()

    def _insert_source_case(self, connection: sqlite3.Connection) -> None:
        connection.execute(
            """
            INSERT INTO sources
            (source_id, stable_identity, media_kind, size_bytes, sector_size,
             fingerprint_sha256, status, created_at, updated_at)
            VALUES ('source_1', 'stable-source-1', 'block', 1024, 512, ?, 'approved', ?, ?)
            """,
            (FINGERPRINT_A, NOW, NOW),
        )
        connection.execute(
            """
            INSERT INTO scan_cases
            (case_id, source_id, state, policy_json, created_at, updated_at)
            VALUES ('case_1', 'source_1', 'completed', '{}', ?, ?)
            """,
            (NOW, NOW),
        )
        connection.commit()


if __name__ == "__main__":
    unittest.main()
