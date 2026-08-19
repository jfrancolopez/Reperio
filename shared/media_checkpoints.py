"""Medium-identity-bound checkpoints and replacement-aware resume (RPR-180).

Checkpoint keys bind to the full medium identity (reader id plus capacity,
geometry, optical TOC/sessions, and sampled fingerprint), never to a reader
path or kernel name. A scan resumes only when the same verified medium is
reinserted; any change to fingerprint, geometry, TOC, session table, or
capacity blocks resume and offers a new case. Replacement and disconnect
observations are recorded as versioned events so prior findings stay browsable.
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from shared import event_outbox, media_identity

MEDIUM_CHECKPOINT_VERSION = 1

MEDIUM_EVENT_TYPES = frozenset({"media.replaced", "media.disconnect", "media.reinserted"})


class MediaCheckpointError(ValueError):
    def __init__(self, message: str, *, offers_new_case: bool = False) -> None:
        super().__init__(message)
        self.offers_new_case = offers_new_case


@dataclass(frozen=True)
class ResumeEligibility:
    eligible: bool
    reason: str | None
    offers_new_case: bool
    medium_identity_key: str


@dataclass(frozen=True)
class MediumCheckpointRecord:
    checkpoint_id: str
    job_id: str
    medium_identity_key: str
    medium_identity_json: str | None
    stage: str
    checkpoint_version: int
    tool_name: str
    tool_version: str
    cursor: dict[str, Any]
    counters: dict[str, Any]
    blob: bytes
    integrity_sha256: str


def medium_identity_key(record: Mapping[str, Any]) -> str:
    """Return the canonical sha256 key for a validated medium-identity record."""
    validation = media_identity.validate_media_identity(record)
    if not validation.valid:
        raise MediaCheckpointError(
            f"invalid medium identity: {', '.join(validation.warnings)}",
            offers_new_case=True,
        )
    signals = record.get("medium_signals")
    if not isinstance(signals, Mapping):
        raise MediaCheckpointError("missing medium signals", offers_new_case=True)
    if not media_identity.is_plausible_medium({"medium_signals": signals}):
        raise MediaCheckpointError("no medium present", offers_new_case=True)
    canonical = _canonical_json({"reader_id": record.get("reader_id"), "medium_signals": signals})
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def resume_eligibility(
    previous: Mapping[str, Any] | None, current: Mapping[str, Any]
) -> ResumeEligibility:
    """Decide whether a checkpoint from ``previous`` may resume with ``current``.

    The same verified medium reinserted into the same reader is eligible.
    Every difference — fingerprint, geometry, TOC/sessions, capacity, or a
    replacement generation bump — blocks resume and offers a new case.
    """
    if previous is None:
        return ResumeEligibility(False, "no_previous_medium", True, medium_identity_key(current))
    try:
        previous_key = medium_identity_key(previous)
    except MediaCheckpointError as error:
        return ResumeEligibility(False, error.args[0], True, medium_identity_key(current))
    current_key = medium_identity_key(current)
    if previous_key == current_key:
        return ResumeEligibility(True, None, False, current_key)

    previous_signals = previous.get("medium_signals") or {}
    current_signals = current.get("medium_signals") or {}
    reason = _difference_reason(previous_signals, current_signals)
    return ResumeEligibility(False, reason, True, current_key)


def save_medium_checkpoint(
    connection: sqlite3.Connection,
    *,
    checkpoint_id: str,
    job_id: str,
    medium_identity: Mapping[str, Any],
    stage: str,
    tool_name: str,
    tool_version: str,
    cursor: Mapping[str, Any],
    counters: Mapping[str, Any],
    blob: bytes,
    created_at: str,
) -> None:
    """Store a checkpoint bound to the full medium identity."""
    medium_key = medium_identity_key(medium_identity)
    medium_json = _canonical_json(medium_identity)
    cursor_json = _canonical_json(cursor)
    counters_json = _canonical_json(counters)
    digest = _integrity_hash(
        medium_key=medium_key,
        stage=stage,
        checkpoint_version=MEDIUM_CHECKPOINT_VERSION,
        tool_name=tool_name,
        tool_version=tool_version,
        cursor_json=cursor_json,
        counters_json=counters_json,
        blob=blob,
    )
    try:
        connection.execute("BEGIN IMMEDIATE")
        previous = _latest_checkpoint_id(connection, job_id, stage)
        connection.execute(
            """
            INSERT INTO checkpoints
            (checkpoint_id, job_id, source_fingerprint, medium_identity_json, stage,
             checkpoint_version, tool_name, tool_version, cursor_json, counters_json,
             blob, integrity_sha256, supersedes_checkpoint_id, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                checkpoint_id,
                job_id,
                medium_key,
                medium_json,
                stage,
                MEDIUM_CHECKPOINT_VERSION,
                tool_name,
                tool_version,
                cursor_json,
                counters_json,
                blob,
                digest,
                previous,
                created_at,
            ),
        )
        if previous is not None:
            connection.execute(
                """
                UPDATE checkpoints
                SET superseded_by_checkpoint_id = ?
                WHERE checkpoint_id = ?
                """,
                (checkpoint_id, previous),
            )
        connection.execute("COMMIT")
    except Exception:
        connection.execute("ROLLBACK")
        raise


def load_medium_checkpoint(
    connection: sqlite3.Connection,
    *,
    job_id: str,
    medium_identity: Mapping[str, Any],
    stage: str,
    tool_name: str,
    tool_version: str,
) -> tuple[MediumCheckpointRecord | None, ResumeEligibility]:
    """Load the latest stage checkpoint and its resume eligibility."""
    current = resume_eligibility(None, medium_identity)
    eligibility = current
    row = connection.execute(
        """
        SELECT checkpoint_id, job_id, source_fingerprint, medium_identity_json, stage,
               checkpoint_version, tool_name, tool_version, cursor_json, counters_json,
               blob, integrity_sha256
        FROM checkpoints
        WHERE job_id = ? AND stage = ? AND superseded_by_checkpoint_id IS NULL
        ORDER BY created_at DESC, checkpoint_id DESC
        LIMIT 1
        """,
        (job_id, stage),
    ).fetchone()
    if row is None:
        return None, ResumeEligibility(False, "no_checkpoint", False, current.medium_identity_key)
    record = _record_from_row(row)

    previous_medium: Mapping[str, Any] | None = None
    if record.medium_identity_json is not None:
        try:
            previous_medium = json.loads(record.medium_identity_json)
        except json.JSONDecodeError:
            raise MediaCheckpointError(
                "stored medium identity is corrupt", offers_new_case=True
            ) from None
    eligibility = resume_eligibility(previous_medium, medium_identity)
    if not eligibility.eligible:
        raise MediaCheckpointError(
            f"checkpoint medium mismatch: {eligibility.reason}", offers_new_case=True
        )
    if record.checkpoint_version != MEDIUM_CHECKPOINT_VERSION:
        raise MediaCheckpointError(
            "unsupported medium checkpoint version; restart stage", offers_new_case=True
        )
    if record.tool_name != tool_name or record.tool_version != tool_version:
        raise MediaCheckpointError(
            "checkpoint tool version mismatch; restart stage", offers_new_case=True
        )
    expected = _integrity_hash(
        medium_key=record.medium_identity_key,
        stage=record.stage,
        checkpoint_version=record.checkpoint_version,
        tool_name=record.tool_name,
        tool_version=record.tool_version,
        cursor_json=_canonical_json(record.cursor),
        counters_json=_canonical_json(record.counters),
        blob=record.blob,
    )
    if expected != record.integrity_sha256:
        raise MediaCheckpointError(
            "checkpoint integrity hash mismatch; restart stage", offers_new_case=True
        )
    return record, eligibility


def record_medium_event(
    connection: sqlite3.Connection,
    *,
    event_id: str,
    case_id: str,
    event_type: str,
    payload: Mapping[str, Any],
    now: str,
) -> dict[str, Any]:
    """Record a replacement/disconnect/reinsert event without touching job state."""
    if event_type not in MEDIUM_EVENT_TYPES:
        raise MediaCheckpointError(f"unsupported medium event type {event_type!r}")
    return event_outbox.append_event(
        connection,
        event_id=event_id,
        case_id=case_id,
        event_type=event_type,
        payload=payload,
        now=now,
    )


def _difference_reason(previous: Mapping[str, Any], current: Mapping[str, Any]) -> str:
    if previous.get("capacity_bytes") != current.get("capacity_bytes"):
        return "capacity_changed"
    previous_fingerprint = _fingerprint(previous.get("sampled_fingerprint_sha256"))
    current_fingerprint = _fingerprint(current.get("sampled_fingerprint_sha256"))
    if previous_fingerprint is None or current_fingerprint is None:
        return "unreadable_sample_identity_weak"
    if previous_fingerprint != current_fingerprint:
        return "fingerprint_changed"
    if _canonical_json(previous.get("toc_sessions")) != _canonical_json(
        current.get("toc_sessions")
    ):
        return "toc_sessions_changed"
    if _canonical_json(previous.get("geometry")) != _canonical_json(current.get("geometry")):
        return "geometry_changed"
    if _nonnegative_int(previous.get("media_change_generation")) != _nonnegative_int(
        current.get("media_change_generation")
    ):
        return "media_replaced"
    return "medium_identity_changed"


def _record_from_row(row: tuple[Any, ...]) -> MediumCheckpointRecord:
    return MediumCheckpointRecord(
        checkpoint_id=str(row[0]),
        job_id=str(row[1]),
        medium_identity_key=str(row[2]),
        medium_identity_json=str(row[3]) if row[3] is not None else None,
        stage=str(row[4]),
        checkpoint_version=int(row[5]),
        tool_name=str(row[6]),
        tool_version=str(row[7]),
        cursor=dict(json.loads(str(row[8]))),
        counters=dict(json.loads(str(row[9]))),
        blob=bytes(row[10]),
        integrity_sha256=str(row[11]),
    )


def _latest_checkpoint_id(connection: sqlite3.Connection, job_id: str, stage: str) -> str | None:
    row = connection.execute(
        """
        SELECT checkpoint_id FROM checkpoints
        WHERE job_id = ? AND stage = ? AND superseded_by_checkpoint_id IS NULL
        ORDER BY created_at DESC, checkpoint_id DESC
        LIMIT 1
        """,
        (job_id, stage),
    ).fetchone()
    return None if row is None else str(row[0])


def _integrity_hash(
    *,
    medium_key: str,
    stage: str,
    checkpoint_version: int,
    tool_name: str,
    tool_version: str,
    cursor_json: str,
    counters_json: str,
    blob: bytes,
) -> str:
    digest = hashlib.sha256()
    for value in (
        medium_key,
        stage,
        str(checkpoint_version),
        tool_name,
        tool_version,
        cursor_json,
        counters_json,
    ):
        encoded = value.encode("utf-8")
        digest.update(len(encoded).to_bytes(8, "big"))
        digest.update(encoded)
    digest.update(len(blob).to_bytes(8, "big"))
    digest.update(blob)
    return digest.hexdigest()


def _canonical_json(payload: object) -> str:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"))


def _fingerprint(value: object) -> str | None:
    if not isinstance(value, str):
        return None
    stripped = value.strip()
    if len(stripped) != 64 or any(char not in "0123456789abcdef" for char in stripped):
        return None
    return stripped


def _nonnegative_int(value: object) -> int:
    if isinstance(value, int) and value >= 0:
        return value
    return 0
