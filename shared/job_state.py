"""Durable job state machine helpers backed by the catalog jobs table."""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
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


@dataclass(frozen=True)
class RetryPolicy:
    base_delay_seconds: int = 30
    max_delay_seconds: int = 300


def stage_idempotency_key(*, case_id: str, stage: str, input_payload: Mapping[str, Any]) -> str:
    """Return a deterministic idempotency key for one case stage and input."""

    return _canonical_json({"case_id": case_id, "input": input_payload, "stage": stage})


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


def create_or_get_job(
    connection: sqlite3.Connection,
    *,
    job_id: str,
    job_type: str,
    input_payload: Mapping[str, Any],
    idempotency_key: str,
    now: str,
    case_id: str | None = None,
    max_attempts: int = 1,
) -> dict[str, Any]:
    """Create a job once, or return the matching existing job for duplicate submission."""

    input_json = _canonical_json(input_payload)
    try:
        create_job(
            connection,
            job_id=job_id,
            job_type=job_type,
            input_payload=input_payload,
            idempotency_key=idempotency_key,
            now=now,
            case_id=case_id,
            max_attempts=max_attempts,
        )
        return get_job(connection, job_id)
    except sqlite3.IntegrityError:
        existing = connection.execute(
            "SELECT job_id FROM jobs WHERE idempotency_key = ?", (idempotency_key,)
        ).fetchone()
        if existing is None:
            raise
        job = get_job(connection, str(existing[0]))
        if (
            job["job_type"] != job_type
            or job["case_id"] != case_id
            or job["input_json"] != input_json
        ):
            raise JobStateError("idempotency key reused for different job input")
        return job


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


def claim_next_job(
    connection: sqlite3.Connection, *, owner: str, now: str, lease_seconds: int
) -> dict[str, Any] | None:
    """Atomically lease the next runnable pending, retrying, or expired job."""

    lease_expires_at = _add_seconds(now, lease_seconds)
    with connection:
        row = connection.execute(
            """
            SELECT job_id, state FROM jobs
            WHERE
                (state = 'pending')
                OR (state = 'retrying' AND retry_after_at <= ?)
                OR (state IN ('leased', 'running') AND lease_expires_at < ?)
            ORDER BY created_at, job_id
            LIMIT 1
            """,
            (now, now),
        ).fetchone()
        if row is None:
            return None
        job_id = str(row[0])
        cursor = connection.execute(
            """
            UPDATE jobs
            SET state = 'leased', lease_owner = ?, lease_expires_at = ?,
                retry_after_at = NULL, attempts = attempts + 1, updated_at = ?
            WHERE job_id = ?
              AND attempts < max_attempts
              AND (
                  state = 'pending'
                  OR (state = 'retrying' AND retry_after_at <= ?)
                  OR (state IN ('leased', 'running') AND lease_expires_at < ?)
              )
            """,
            (owner, lease_expires_at, now, job_id, now, now),
        )
        if cursor.rowcount != 1:
            return None
        return get_job(connection, job_id)


def heartbeat_job(
    connection: sqlite3.Connection,
    *,
    job_id: str,
    owner: str,
    now: str,
    lease_seconds: int,
) -> bool:
    """Extend a live lease owned by the worker; exact-expiry heartbeats are accepted."""

    cursor = connection.execute(
        """
        UPDATE jobs
        SET lease_expires_at = ?, updated_at = ?
        WHERE job_id = ?
          AND lease_owner = ?
          AND state IN ('leased', 'running')
          AND lease_expires_at >= ?
        """,
        (_add_seconds(now, lease_seconds), now, job_id, owner, now),
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


def finish_attempt(
    connection: sqlite3.Connection,
    *,
    job_id: str,
    now: str,
    error_class: str,
    retry_policy: RetryPolicy = RetryPolicy(),
) -> str:
    """Finish a failed attempt as retrying or failed using explicit error classes."""

    if error_class not in {"transient", "permanent"}:
        raise JobStateError(f"unknown error class {error_class}")
    job = get_job(connection, job_id)
    state = str(job["state"])
    if state not in {"leased", "running"}:
        raise JobStateError(f"attempt cannot finish from {state}")

    attempts = int(job["attempts"])
    max_attempts = int(job["max_attempts"])
    retryable = error_class == "transient" and attempts < max_attempts
    next_state = "retrying" if retryable else "failed"
    delay = _retry_delay_seconds(attempts, retry_policy) if retryable else None
    connection.execute(
        """
        UPDATE jobs
        SET state = ?, lease_owner = NULL, lease_expires_at = NULL, retry_after_at = ?,
            error_json = ?, updated_at = ?
        WHERE job_id = ?
        """,
        (
            next_state,
            _add_seconds(now, delay) if delay is not None else None,
            _canonical_json(
                {
                    "attempts": attempts,
                    "class": error_class,
                    "kind": "attempt-failed",
                    "retryable": retryable,
                }
            ),
            now,
            job_id,
        ),
    )
    return next_state


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


def _add_seconds(timestamp: str, seconds: int) -> str:
    parsed = datetime.strptime(timestamp, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)
    return (parsed + timedelta(seconds=seconds)).strftime("%Y-%m-%dT%H:%M:%SZ")


def _retry_delay_seconds(attempts: int, retry_policy: RetryPolicy) -> int:
    uncapped = retry_policy.base_delay_seconds * (2 ** max(attempts - 1, 0))
    return int(min(uncapped, retry_policy.max_delay_seconds))
