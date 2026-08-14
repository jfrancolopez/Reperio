from __future__ import annotations

import asyncio
import sqlite3
import tempfile
import unittest
from contextlib import closing
from pathlib import Path
from typing import Any

from migrations import runner
from shared import catalog_schema, event_outbox, job_state
from tests.test_api_service import asgi_request

try:
    from api.app import create_app
except ModuleNotFoundError as error:
    raise unittest.SkipTest("FastAPI runtime dependencies are not installed") from error

NOW = "2026-08-11T14:40:00Z"
LATER = "2026-08-11T14:41:00Z"
HASH = "b" * 64


class EventOutboxTests(unittest.TestCase):
    def test_job_transition_and_event_are_one_transaction(self) -> None:
        with closing(self._connection()) as connection:
            self._insert_source_case_and_job(connection)

            event = event_outbox.transition_job_and_append_event(
                connection,
                job_id="job_1",
                to_state="running",
                event_id="event_1",
                event_type="job.state",
                now=LATER,
            )

            self.assertEqual("running", job_state.get_job(connection, "job_1")["state"])
            self.assertEqual(1, event["sequence"])
            self.assertEqual({"job_id": "job_1", "state": "running"}, event["payload"])

    def test_failed_event_insert_rolls_back_job_transition(self) -> None:
        with closing(self._connection()) as connection:
            self._insert_source_case_and_job(connection)

            with self.assertRaises(TypeError):
                event_outbox.transition_job_and_append_event(
                    connection,
                    job_id="job_1",
                    to_state="running",
                    event_id="event_bad",
                    event_type="job.state",
                    now=LATER,
                    payload={"bad": object()},
                )

            self.assertEqual("leased", job_state.get_job(connection, "job_1")["state"])
            self.assertEqual(0, connection.execute("SELECT COUNT(*) FROM events").fetchone()[0])

    def test_resume_returns_missed_events_once_and_tolerates_duplicate_delivery(self) -> None:
        with closing(self._connection()) as connection:
            self._insert_source_case_and_job(connection)
            self._append_event(connection, "event_1", "job.state", {"state": "running"})
            self._append_event(connection, "event_2", "job.progress", {"percent": 25})

            first = event_outbox.list_events(connection, case_id="case_1", after_sequence=0)
            resumed = event_outbox.list_events(connection, case_id="case_1", after_sequence=1)
            marked = event_outbox.mark_published(
                connection, event_ids=["event_1", "event_1"], published_at=LATER
            )

            self.assertEqual([1, 2], [event["sequence"] for event in first])
            self.assertEqual(["event_2"], [event["event_id"] for event in resumed])
            self.assertEqual(1, marked)

    def test_retention_compacts_only_published_events_before_boundary(self) -> None:
        with closing(self._connection()) as connection:
            self._insert_source_case_and_job(connection)
            self._append_event(connection, "event_old", "job.state", {"state": "running"})
            self._append_event(connection, "event_new", "job.progress", {"percent": 50}, now=LATER)
            event_outbox.mark_published(connection, event_ids=["event_old"], published_at=LATER)

            deleted = event_outbox.compact_published_events(
                connection, before_created_at=LATER, limit=100
            )

            self.assertEqual(1, deleted)
            self.assertEqual(["event_new"], self._event_ids(connection))

    def test_sse_format_is_passive_and_uses_sequence_as_resume_id(self) -> None:
        with closing(self._connection()) as connection:
            self._insert_source_case_and_job(connection)
            event = self._append_event(connection, "event_1", "job.progress", {"percent": 25})

        payload = event_outbox.format_sse(event)

        self.assertIn("id: 1\n", payload)
        self.assertIn("event: job.progress\n", payload)
        self.assertIn('"percent":25', payload)
        self.assertNotIn("<script", payload.lower())

    def test_api_poll_and_sse_resume_after_restart(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "catalog.sqlite3"
            runner.migrate_catalog(db_path)
            connection = catalog_schema.connect_catalog(db_path)
            try:
                self._insert_source_case_and_job(connection)
                self._append_event(connection, "event_1", "job.state", {"state": "running"})
                self._append_event(connection, "event_2", "job.progress", {"percent": 25})
            finally:
                connection.close()

            restarted_app = create_app(catalog_path=db_path)
            poll = asyncio.run(asgi_request(restarted_app, "GET", "/api/v1/cases/case_1/events"))
            stream = asyncio.run(
                asgi_request(
                    restarted_app,
                    "GET",
                    "/api/v1/cases/case_1/events/stream",
                    headers={"last-event-id": "1"},
                )
            )

        self.assertEqual(200, poll.status_code)
        self.assertEqual([1, 2], [event["sequence"] for event in poll.json["events"]])
        self.assertEqual("2", str(poll.json["next_after"]))
        self.assertEqual(200, stream.status_code)
        self.assertEqual("text/event-stream; charset=utf-8", stream.headers["content-type"])
        self.assertIn("id: 2\n", stream.body.decode())
        self.assertNotIn("id: 1\n", stream.body.decode())

    def _connection(self) -> sqlite3.Connection:
        connection = sqlite3.connect(":memory:")
        catalog_schema.create_initial_schema(connection)
        return connection

    def _insert_source_case_and_job(self, connection: sqlite3.Connection) -> None:
        connection.execute(
            """
            INSERT INTO sources
            (source_id, stable_identity, media_kind, size_bytes, sector_size,
             fingerprint_sha256, status, created_at, updated_at)
            VALUES ('source_1', 'stable-source-1', 'block', 1024, 512, ?, 'candidate', ?, ?)
            """,
            (HASH, NOW, NOW),
        )
        connection.execute(
            """
            INSERT INTO scan_cases
            (case_id, source_id, state, policy_json, created_at, updated_at)
            VALUES ('case_1', 'source_1', 'created', '{}', ?, ?)
            """,
            (NOW, NOW),
        )
        job_state.create_job(
            connection,
            job_id="job_1",
            job_type="scan",
            input_payload={"stage": "scan"},
            idempotency_key="idem_1",
            now=NOW,
            case_id="case_1",
        )
        job_state.transition_job(connection, job_id="job_1", to_state="leased", now=NOW)
        connection.commit()

    def _append_event(
        self,
        connection: sqlite3.Connection,
        event_id: str,
        event_type: str,
        payload: dict[str, Any],
        *,
        now: str = NOW,
    ) -> dict[str, Any]:
        return event_outbox.append_event(
            connection,
            event_id=event_id,
            case_id="case_1",
            job_id="job_1",
            event_type=event_type,
            payload=payload,
            now=now,
        )

    def _event_ids(self, connection: sqlite3.Connection) -> list[str]:
        return [
            row[0] for row in connection.execute("SELECT event_id FROM events ORDER BY sequence")
        ]


if __name__ == "__main__":
    unittest.main()
