from __future__ import annotations

import json
import sqlite3
import tempfile
import unittest
from contextlib import closing
from pathlib import Path

from migrations import runner
from shared import catalog_schema, job_state

NOW = "2026-08-11T14:40:00Z"
EXACT_EXPIRY = "2026-08-11T14:40:30Z"
AFTER_EXPIRY = "2026-08-11T14:40:31Z"


class JobLeaseRetryTests(unittest.TestCase):
    def test_race_allows_one_atomic_claim(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "catalog.sqlite3"
            runner.migrate_catalog(db_path)
            first = catalog_schema.connect_catalog(db_path)
            second = catalog_schema.connect_catalog(db_path)
            try:
                self._create_job(first, "job_race")

                first_claim = job_state.claim_next_job(
                    first, owner="worker_a", now=NOW, lease_seconds=30
                )
                second_claim = job_state.claim_next_job(
                    second, owner="worker_b", now=NOW, lease_seconds=30
                )

                self.assertIsNotNone(first_claim)
                self.assertIsNone(second_claim)
                job = job_state.get_job(first, "job_race")
                self.assertEqual("leased", job["state"])
                self.assertEqual("worker_a", job["lease_owner"])
                self.assertEqual(EXACT_EXPIRY, job["lease_expires_at"])
            finally:
                second.close()
                first.close()

    def test_clock_skew_boundary_keeps_exact_expiry_owned_until_after_boundary(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "catalog.sqlite3"
            runner.migrate_catalog(db_path)
            owner = catalog_schema.connect_catalog(db_path)
            contender = catalog_schema.connect_catalog(db_path)
            try:
                self._create_job(owner, "job_boundary")
                self.assertIsNotNone(
                    job_state.claim_next_job(owner, owner="worker_a", now=NOW, lease_seconds=30)
                )

                self.assertTrue(
                    job_state.heartbeat_job(
                        owner,
                        job_id="job_boundary",
                        owner="worker_a",
                        now=EXACT_EXPIRY,
                        lease_seconds=30,
                    )
                )
                self.assertIsNone(
                    job_state.claim_next_job(
                        contender, owner="worker_b", now=EXACT_EXPIRY, lease_seconds=30
                    )
                )
                self.assertIsNotNone(
                    job_state.claim_next_job(
                        contender, owner="worker_b", now="2026-08-11T14:41:01Z", lease_seconds=30
                    )
                )
            finally:
                contender.close()
                owner.close()

    def test_duplicate_submission_returns_existing_without_duplicate_record(self) -> None:
        with closing(self._connection()) as connection:
            key = job_state.stage_idempotency_key(
                case_id="case_1", stage="scan", input_payload={"source_id": "source_1"}
            )
            first = job_state.create_or_get_job(
                connection,
                job_id="job_first",
                job_type="scan",
                input_payload={"source_id": "source_1"},
                idempotency_key=key,
                now=NOW,
            )
            duplicate = job_state.create_or_get_job(
                connection,
                job_id="job_second",
                job_type="scan",
                input_payload={"source_id": "source_1"},
                idempotency_key=key,
                now=NOW,
            )

            self.assertEqual(first["job_id"], duplicate["job_id"])
            self.assertEqual(1, connection.execute("SELECT COUNT(*) FROM jobs").fetchone()[0])
            with self.assertRaises(job_state.JobStateError):
                job_state.create_or_get_job(
                    connection,
                    job_id="job_conflict",
                    job_type="scan",
                    input_payload={"source_id": "different"},
                    idempotency_key=key,
                    now=NOW,
                )

    def test_transient_and_permanent_errors_drive_retry_state(self) -> None:
        with closing(self._connection()) as connection:
            self._create_job(connection, "job_transient", max_attempts=3)
            job_state.claim_next_job(connection, owner="worker_a", now=NOW, lease_seconds=30)

            next_state = job_state.finish_attempt(
                connection,
                job_id="job_transient",
                now=NOW,
                error_class="transient",
                retry_policy=job_state.RetryPolicy(base_delay_seconds=10, max_delay_seconds=60),
            )

            transient = job_state.get_job(connection, "job_transient")
            self.assertEqual("retrying", next_state)
            self.assertEqual("2026-08-11T14:40:10Z", transient["retry_after_at"])
            self.assertEqual("transient", json.loads(transient["error_json"])["class"])

            self._create_job(connection, "job_permanent", max_attempts=3)
            job_state.claim_next_job(connection, owner="worker_a", now=NOW, lease_seconds=30)
            self.assertEqual(
                "failed",
                job_state.finish_attempt(
                    connection,
                    job_id="job_permanent",
                    now=NOW,
                    error_class="permanent",
                ),
            )
            permanent = job_state.get_job(connection, "job_permanent")
            self.assertIsNone(permanent["retry_after_at"])
            self.assertEqual("permanent", json.loads(permanent["error_json"])["class"])

    def test_worker_kill_expired_job_resumes_without_duplicate_normalized_record(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "catalog.sqlite3"
            runner.migrate_catalog(db_path)
            first = catalog_schema.connect_catalog(db_path)
            second = catalog_schema.connect_catalog(db_path)
            try:
                self._create_job(first, "job_killed", max_attempts=2)
                first_claim = job_state.claim_next_job(
                    first, owner="worker_a", now=NOW, lease_seconds=30
                )
                second_claim = job_state.claim_next_job(
                    second, owner="worker_b", now=AFTER_EXPIRY, lease_seconds=30
                )

                self.assertIsNotNone(first_claim)
                self.assertIsNotNone(second_claim)
                job = job_state.get_job(second, "job_killed")
                self.assertEqual("job_killed", job["job_id"])
                self.assertEqual("worker_b", job["lease_owner"])
                self.assertEqual(2, job["attempts"])
                self.assertEqual(1, second.execute("SELECT COUNT(*) FROM jobs").fetchone()[0])
            finally:
                second.close()
                first.close()

    def test_lease_bounds_reject_zero_negative_and_excessive_values(self) -> None:
        with closing(self._connection()) as connection:
            self._create_job(connection, "job_bounds")
            for lease_seconds in (0, -1, job_state.MAX_LEASE_SECONDS + 1, True):
                with self.assertRaisesRegex(job_state.JobStateError, "lease_seconds"):
                    job_state.claim_next_job(
                        connection,
                        owner="worker_a",
                        now=NOW,
                        lease_seconds=lease_seconds,
                    )

    def test_idempotency_payload_rejects_non_finite_json(self) -> None:
        with self.assertRaisesRegex(job_state.JobStateError, "canonical JSON"):
            job_state.stage_idempotency_key(
                case_id="case_1", stage="scan", input_payload={"score": float("nan")}
            )

        for kwargs in (
            {"base_delay_seconds": 0},
            {"base_delay_seconds": 30, "max_delay_seconds": 29},
        ):
            with self.assertRaisesRegex(job_state.JobStateError, "retry policy"):
                job_state.RetryPolicy(**kwargs)

    def _connection(self) -> sqlite3.Connection:
        connection = sqlite3.connect(":memory:")
        catalog_schema.create_initial_schema(connection)
        return connection

    def _create_job(
        self,
        connection: sqlite3.Connection,
        job_id: str,
        max_attempts: int = 2,
    ) -> None:
        job_state.create_job(
            connection,
            job_id=job_id,
            job_type="scan",
            input_payload={"stage": job_id},
            idempotency_key=f"idem_{job_id}",
            now=NOW,
            max_attempts=max_attempts,
        )


if __name__ == "__main__":
    unittest.main()
