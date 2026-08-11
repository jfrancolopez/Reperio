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
LATER = "2026-08-11T14:41:00Z"


class JobStateTests(unittest.TestCase):
    def test_full_transition_matrix_rejects_invalid_edges(self) -> None:
        allowed = job_state.ALLOWED_TRANSITIONS
        states = set(allowed)

        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "catalog.sqlite3"
            runner.migrate_catalog(db_path)
            connection = catalog_schema.connect_catalog(db_path)
            try:
                for from_state in states:
                    for to_state in states:
                        job_id = f"job_{from_state}_{to_state}".replace("-", "_")
                        self._insert_job(connection, job_id, from_state)
                        if to_state in allowed[from_state]:
                            job_state.transition_job(
                                connection, job_id=job_id, to_state=to_state, now=LATER
                            )
                            self.assertEqual(
                                to_state, job_state.get_job(connection, job_id)["state"]
                            )
                        else:
                            with self.assertRaises(job_state.JobStateError):
                                job_state.transition_job(
                                    connection, job_id=job_id, to_state=to_state, now=LATER
                                )
                for terminal in job_state.TERMINAL_STATES:
                    self.assertEqual(frozenset(), allowed[terminal])
            finally:
                connection.close()

    def test_concurrent_claim_allows_only_one_worker(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "catalog.sqlite3"
            runner.migrate_catalog(db_path)
            first = catalog_schema.connect_catalog(db_path)
            second = catalog_schema.connect_catalog(db_path)
            try:
                job_state.create_job(
                    first,
                    job_id="job_claim",
                    job_type="scan",
                    input_payload={"stage": "scan"},
                    idempotency_key="idem_claim",
                    now=NOW,
                    max_attempts=2,
                )

                claimed_first = job_state.claim_pending_job(
                    first, job_id="job_claim", owner="worker_a", now=LATER
                )
                claimed_second = job_state.claim_pending_job(
                    second, job_id="job_claim", owner="worker_b", now=LATER
                )

                job = job_state.get_job(first, "job_claim")
                self.assertTrue(claimed_first)
                self.assertFalse(claimed_second)
                self.assertEqual("leased", job["state"])
                self.assertEqual("worker_a", job["lease_owner"])
                self.assertEqual(1, job["attempts"])
            finally:
                second.close()
                first.close()

    def test_process_death_retries_then_fails_at_retry_exhaustion(self) -> None:
        with closing(self._connection()) as connection:
            job_state.create_job(
                connection,
                job_id="job_retry",
                job_type="scan",
                input_payload={"source_id": "source_1"},
                idempotency_key="idem_retry",
                now=NOW,
                max_attempts=2,
            )

            self.assertTrue(
                job_state.claim_pending_job(
                    connection, job_id="job_retry", owner="worker_a", now=LATER
                )
            )
            self.assertEqual(
                "retrying",
                job_state.record_process_death(connection, job_id="job_retry", now=LATER),
            )
            job_state.release_for_retry(connection, job_id="job_retry", now=LATER)
            self.assertTrue(
                job_state.claim_pending_job(
                    connection, job_id="job_retry", owner="worker_b", now=LATER
                )
            )
            self.assertEqual(
                "failed", job_state.record_process_death(connection, job_id="job_retry", now=LATER)
            )

            job = job_state.get_job(connection, "job_retry")
            self.assertEqual("failed", job["state"])
            self.assertEqual(
                {
                    "attempts": 2,
                    "kind": "process-death",
                    "max_attempts": 2,
                    "retryable": False,
                },
                json.loads(job["error_json"]),
            )

    def test_safe_stop_is_distinct_from_failure_and_can_resume(self) -> None:
        with closing(self._connection()) as connection:
            self._insert_job(connection, "job_safe_stop", "running")

            job_state.safe_stop_job(connection, job_id="job_safe_stop", now=LATER)
            stopped = job_state.get_job(connection, "job_safe_stop")
            job_state.transition_job(
                connection, job_id="job_safe_stop", to_state="running", now=LATER
            )

            self.assertEqual("paused", stopped["state"])
            self.assertEqual(
                {"kind": "safe-stop", "retryable": True}, json.loads(stopped["error_json"])
            )
            self.assertEqual("running", job_state.get_job(connection, "job_safe_stop")["state"])

    def test_completed_job_cannot_be_rerun_and_input_remains_unchanged(self) -> None:
        with closing(self._connection()) as connection:
            job_state.create_job(
                connection,
                job_id="job_done",
                job_type="scan",
                input_payload={"z": 1, "a": "fixed"},
                idempotency_key="idem_done",
                now=NOW,
            )
            original_input = job_state.get_job(connection, "job_done")["input_json"]
            job_state.claim_pending_job(connection, job_id="job_done", owner="worker_a", now=LATER)
            job_state.transition_job(connection, job_id="job_done", to_state="running", now=LATER)
            job_state.transition_job(connection, job_id="job_done", to_state="completed", now=LATER)

            with self.assertRaises(job_state.JobStateError):
                job_state.transition_job(
                    connection, job_id="job_done", to_state="running", now=LATER
                )

            self.assertEqual(
                original_input, job_state.get_job(connection, "job_done")["input_json"]
            )
            self.assertEqual('{"a":"fixed","z":1}', original_input)

    def _connection(self) -> sqlite3.Connection:
        connection = sqlite3.connect(":memory:")
        catalog_schema.create_initial_schema(connection)
        return connection

    def _insert_job(self, connection: sqlite3.Connection, job_id: str, state: str) -> None:
        connection.execute(
            """
            INSERT INTO jobs
            (job_id, job_type, state, input_json, idempotency_key,
             attempts, max_attempts, created_at, updated_at)
            VALUES (?, 'scan', ?, '{}', ?, 0, 2, ?, ?)
            """,
            (job_id, state, f"idem_{job_id}", NOW, NOW),
        )


if __name__ == "__main__":
    unittest.main()
