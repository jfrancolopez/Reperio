"""Transactional event outbox and SSE helpers for catalog events."""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Iterable, Mapping
from typing import Any

from shared import job_state

MAX_POLL_LIMIT = 500


class EventOutboxError(ValueError):
    """Raised when an event outbox operation violates the contract."""


def append_event(
    connection: sqlite3.Connection,
    *,
    event_id: str,
    case_id: str,
    event_type: str,
    payload: Mapping[str, Any],
    now: str,
    job_id: str | None = None,
) -> dict[str, Any]:
    """Append one per-case ordered event in the caller's transaction."""
    _validate_public_id("event_id", event_id)
    _validate_public_id("case_id", case_id)
    if job_id is not None:
        _validate_public_id("job_id", job_id)
    if not event_type or len(event_type) > 128 or any(char in event_type for char in "\x00\n\r"):
        raise EventOutboxError("event_type must be bounded single-line text")

    sequence = _next_sequence(connection, case_id)
    payload_json = _canonical_json(payload)
    connection.execute(
        """
        INSERT INTO events
        (event_id, case_id, sequence, job_id, event_type, payload_json, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
        (event_id, case_id, sequence, job_id, event_type, payload_json, now),
    )
    return get_event(connection, event_id)


def transition_job_and_append_event(
    connection: sqlite3.Connection,
    *,
    job_id: str,
    to_state: str,
    event_id: str,
    event_type: str,
    now: str,
    payload: Mapping[str, Any] | None = None,
    error: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Apply a job transition and its event in one SQLite transaction."""
    with connection:
        job = job_state.get_job(connection, job_id)
        case_id = job.get("case_id")
        if not isinstance(case_id, str) or not case_id:
            raise EventOutboxError("job must belong to a scan case before emitting case events")
        job_state.transition_job(connection, job_id=job_id, to_state=to_state, now=now, error=error)
        event_payload = dict(payload or {})
        event_payload.setdefault("job_id", job_id)
        event_payload.setdefault("state", to_state)
        return append_event(
            connection,
            event_id=event_id,
            case_id=case_id,
            job_id=job_id,
            event_type=event_type,
            payload=event_payload,
            now=now,
        )


def list_events(
    connection: sqlite3.Connection, *, case_id: str, after_sequence: int = 0, limit: int = 100
) -> list[dict[str, Any]]:
    """Return ordered events after a per-case sequence for polling or SSE resume."""
    _validate_public_id("case_id", case_id)
    if (
        isinstance(after_sequence, bool)
        or not isinstance(after_sequence, int)
        or after_sequence < 0
    ):
        raise EventOutboxError("after_sequence must be a non-negative integer")
    if isinstance(limit, bool) or not isinstance(limit, int) or limit <= 0:
        raise EventOutboxError("limit must be a positive integer")
    bounded_limit = min(max(limit, 1), MAX_POLL_LIMIT)
    rows = connection.execute(
        """
        SELECT event_id, case_id, sequence, job_id, event_type, payload_json, published_at, created_at
        FROM events
        WHERE case_id = ? AND sequence > ?
        ORDER BY sequence
        LIMIT ?
        """,
        (case_id, after_sequence, bounded_limit),
    ).fetchall()
    return [_event_from_row(row) for row in rows]


def mark_published(
    connection: sqlite3.Connection, *, event_ids: Iterable[str], published_at: str
) -> int:
    """Mark outbox rows published after delivery without changing ordering."""
    ids = tuple(event_ids)
    if not ids:
        return 0
    for event_id in ids:
        _validate_public_id("event_id", event_id)
    placeholders = ",".join("?" for _ in ids)
    cursor = connection.execute(
        f"UPDATE events SET published_at = COALESCE(published_at, ?) WHERE event_id IN ({placeholders})",
        (published_at, *ids),
    )
    return cursor.rowcount


def compact_published_events(
    connection: sqlite3.Connection, *, before_created_at: str, limit: int = 1000
) -> int:
    """Delete old already-published events only; unpublished rows are retained."""
    if isinstance(limit, bool) or not isinstance(limit, int) or limit <= 0:
        raise EventOutboxError("limit must be a positive integer")
    cursor = connection.execute(
        """
        DELETE FROM events
        WHERE event_id IN (
            SELECT event_id FROM events
            WHERE published_at IS NOT NULL AND created_at < ?
            ORDER BY created_at, event_id
            LIMIT ?
        )
        """,
        (before_created_at, min(max(limit, 1), 10_000)),
    )
    return cursor.rowcount


def format_sse(event: Mapping[str, Any]) -> str:
    """Serialize one event in passive Server-Sent Events format."""
    sequence = int(event["sequence"])
    data = _canonical_json(
        {
            "case_id": event["case_id"],
            "created_at": event["created_at"],
            "event_id": event["event_id"],
            "payload": event["payload"],
            "sequence": sequence,
            "type": event["event_type"],
        }
    )
    return f"id: {sequence}\nevent: {event['event_type']}\ndata: {data}\n\n"


def get_event(connection: sqlite3.Connection, event_id: str) -> dict[str, Any]:
    _validate_public_id("event_id", event_id)
    row = connection.execute(
        """
        SELECT event_id, case_id, sequence, job_id, event_type, payload_json, published_at, created_at
        FROM events
        WHERE event_id = ?
        """,
        (event_id,),
    ).fetchone()
    if row is None:
        raise EventOutboxError(f"unknown event {event_id}")
    return _event_from_row(row)


def _next_sequence(connection: sqlite3.Connection, case_id: str) -> int:
    row = connection.execute(
        "SELECT COALESCE(MAX(sequence), 0) + 1 FROM events WHERE case_id = ?", (case_id,)
    ).fetchone()
    return int(row[0])


def _event_from_row(row: sqlite3.Row | tuple[Any, ...]) -> dict[str, Any]:
    return {
        "event_id": row[0],
        "case_id": row[1],
        "sequence": row[2],
        "job_id": row[3],
        "event_type": row[4],
        "payload": json.loads(row[5]),
        "published_at": row[6],
        "created_at": row[7],
    }


def _canonical_json(payload: Mapping[str, Any]) -> str:
    try:
        return json.dumps(payload, allow_nan=False, sort_keys=True, separators=(",", ":"))
    except TypeError:
        raise
    except (ValueError, RecursionError) as error:
        raise EventOutboxError("event payload is not canonical JSON") from error


def _validate_public_id(label: str, value: str) -> None:
    if not value or len(value) > 128 or any(char in value for char in "/\\\x00\n\r"):
        raise EventOutboxError(f"{label} must be a bounded non-path identifier")
