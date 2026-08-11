"""Durable job state machine helpers backed by the catalog jobs table."""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Mapping
from typing import Any

TERMINAL_STATES = frozenset({"completed", "completed-warning", "failed", "cancelled"})

ALLOWED_TRANSITIONS = {
    "pending": frozenset({"leased", "cancelled"}),
    "leased": frozenset({"running", "pending", "retrying", "failed", "cancelled"}),
    "running": frozenset(
        {"paused", "retrying", "completed", "completed-warning", "failed", "cancelled"}
    ),
    "paused": frozenset({"running", "cancelled"}),
    "retrying": frozenset({"pending", "failed", "cancelled"}),
    "completed": frozenset(),
    "completed-warning": frozenset(),
    "failed": frozenset(),
    "cancelled": frozenset(),
}


class JobStateError(ValueError):
    """Raised when a job state operation violates the durable contract."""


def create_job(
    connection: sqlite3.Connection,
    *,
    job_id: str,
    job_type: str,
    input_payload: Mapping[str, Any],
    idempotency_key: str,
    now: str,
    case_id: str | None = None,
    max_attempts: int = 1,
) -> None:
    """Create a pending job with immutable serialized input."""

    connection.execute(
        """
        INSERT INTO jobs
        (job_id, case_id, job_type, state, input_json, idempotency_key,
         attempts, max_attempts, created_at, updated_at)
        VALUES (?, ?, ?, 'pending', ?, ?, 0, ?, ?, ?)
        """,
        (
            job_id,
            case_id,
            job_type,
            _canonical_json(input_payload),
            idempotency_key,
            max_attempts,
            now,
            now,
        ),
    )


def claim_pending_job(connection: sqlite3.Connection, *, job_id: str, owner: str, now: str) -> bool:
    """Atomically move one pending job to leased and increment its attempt count."""

    cursor = connection.execute(
        """
        UPDATE jobs
        SET state = 'leased', lease_owner = ?, attempts = attempts + 1, updated_at = ?
        WHERE job_id = ? AND state = 'pending' AND attempts < max_attempts
        """,
        (owner, now, job_id),
    )
    return cursor.rowcount == 1


def transition_job(
    connection: sqlite3.Connection,
    *,
    job_id: str,
    to_state: str,
    now: str,
    error: Mapping[str, Any] | None = None,
) -> None:
    """Apply one validated state transition without mutating job input."""

    job = get_job(connection, job_id)
    from_state = str(job["state"])
    _validate_transition(from_state, to_state)
    connection.execute(
        """
        UPDATE jobs
        SET state = ?, error_json = ?, lease_owner = ?, lease_expires_at = NULL, updated_at = ?
        WHERE job_id = ?
        """,
        (
            to_state,
            _canonical_json(error) if error is not None else None,
            None if to_state != "leased" else job["lease_owner"],
            now,
            job_id,
        ),
    )


def safe_stop_job(connection: sqlite3.Connection, *, job_id: str, now: str) -> None:
    """Pause a running job without recording it as a failure."""

    transition_job(
        connection,
        job_id=job_id,
        to_state="paused",
        now=now,
        error={"kind": "safe-stop", "retryable": True},
    )


def record_process_death(connection: sqlite3.Connection, *, job_id: str, now: str) -> str:
    """Record worker death as retrying until attempts are exhausted, then failed."""

    job = get_job(connection, job_id)
    state = str(job["state"])
    if state not in {"leased", "running"}:
        raise JobStateError(f"process death cannot be recorded from {state}")

    attempts = int(job["attempts"])
    max_attempts = int(job["max_attempts"])
    next_state = "retrying" if attempts < max_attempts else "failed"
    transition_job(
        connection,
        job_id=job_id,
        to_state=next_state,
        now=now,
        error={
            "kind": "process-death",
            "retryable": next_state == "retrying",
            "attempts": attempts,
            "max_attempts": max_attempts,
        },
    )
    return next_state


def release_for_retry(connection: sqlite3.Connection, *, job_id: str, now: str) -> None:
    """Move a retrying job back to pending; retry timing is added in RPR-024."""

    transition_job(connection, job_id=job_id, to_state="pending", now=now)


def get_job(connection: sqlite3.Connection, job_id: str) -> dict[str, Any]:
    row = connection.execute("SELECT * FROM jobs WHERE job_id = ?", (job_id,)).fetchone()
    if row is None:
        raise JobStateError(f"unknown job {job_id}")
    columns = [column[0] for column in connection.execute("SELECT * FROM jobs LIMIT 0").description]
    return dict(zip(columns, row, strict=True))


def _validate_transition(from_state: str, to_state: str) -> None:
    if to_state not in ALLOWED_TRANSITIONS:
        raise JobStateError(f"unknown target state {to_state}")
    if to_state not in ALLOWED_TRANSITIONS[from_state]:
        raise JobStateError(f"invalid job transition {from_state} -> {to_state}")


def _canonical_json(payload: Mapping[str, Any]) -> str:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"))
