"""Versioned checkpoint storage for restartable scanner stages."""

from __future__ import annotations

import hashlib
import json
import re
import sqlite3
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

SUPPORTED_CHECKPOINT_VERSION = 1
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
MAX_CHECKPOINT_TEXT = 128


class CheckpointError(ValueError):
    """Raised when a checkpoint cannot be trusted for resume."""

    def __init__(self, message: str, *, restart_stage: bool = True) -> None:
        super().__init__(message)
        self.restart_stage = restart_stage


@dataclass(frozen=True)
class CheckpointRecord:
    checkpoint_id: str
    job_id: str
    source_fingerprint: str
    stage: str
    checkpoint_version: int
    tool_name: str
    tool_version: str
    cursor: dict[str, Any]
    counters: dict[str, Any]
    blob: bytes
    integrity_sha256: str
    supersedes_checkpoint_id: str | None


def save_checkpoint(
    connection: sqlite3.Connection,
    *,
    checkpoint_id: str,
    job_id: str,
    source_fingerprint: str,
    stage: str,
    tool_name: str,
    tool_version: str,
    cursor: Mapping[str, Any],
    counters: Mapping[str, Any],
    blob: bytes,
    created_at: str,
    checkpoint_version: int = SUPPORTED_CHECKPOINT_VERSION,
    inject_failure_after_insert: bool = False,
) -> None:
    """Atomically store a checkpoint and supersede the previous stage checkpoint."""

    _validate_checkpoint_inputs(
        source_fingerprint=source_fingerprint,
        stage=stage,
        checkpoint_version=checkpoint_version,
        tool_name=tool_name,
        tool_version=tool_version,
        blob=blob,
    )
    cursor_json = _canonical_json(cursor)
    counters_json = _canonical_json(counters)
    digest = _integrity_hash(
        source_fingerprint=source_fingerprint,
        stage=stage,
        checkpoint_version=checkpoint_version,
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
            (checkpoint_id, job_id, source_fingerprint, stage, checkpoint_version,
             tool_name, tool_version, cursor_json, counters_json, blob,
             integrity_sha256, supersedes_checkpoint_id, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                checkpoint_id,
                job_id,
                source_fingerprint,
                stage,
                checkpoint_version,
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
        if inject_failure_after_insert:
            raise RuntimeError("injected checkpoint failure")
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


def load_latest_checkpoint(
    connection: sqlite3.Connection,
    *,
    job_id: str,
    source_fingerprint: str,
    stage: str,
    tool_name: str,
    tool_version: str,
) -> CheckpointRecord:
    """Load and validate the latest checkpoint for a stage."""

    row = connection.execute(
        """
        SELECT checkpoint_id, job_id, source_fingerprint, stage, checkpoint_version,
               tool_name, tool_version, cursor_json, counters_json, blob,
               integrity_sha256, supersedes_checkpoint_id
        FROM checkpoints
        WHERE job_id = ? AND stage = ? AND superseded_by_checkpoint_id IS NULL
        ORDER BY created_at DESC, checkpoint_id DESC
        LIMIT 1
        """,
        (job_id, stage),
    ).fetchone()
    if row is None:
        raise CheckpointError("no checkpoint is available; restart stage")
    record = _record_from_row(row)
    if record.checkpoint_version != SUPPORTED_CHECKPOINT_VERSION:
        raise CheckpointError("unsupported checkpoint version; restart stage")
    if record.source_fingerprint != source_fingerprint:
        raise CheckpointError("checkpoint source fingerprint mismatch; restart stage")
    if record.tool_name != tool_name or record.tool_version != tool_version:
        raise CheckpointError("checkpoint tool version mismatch; restart stage")
    expected = _integrity_hash(
        source_fingerprint=record.source_fingerprint,
        stage=record.stage,
        checkpoint_version=record.checkpoint_version,
        tool_name=record.tool_name,
        tool_version=record.tool_version,
        cursor_json=_canonical_json(record.cursor),
        counters_json=_canonical_json(record.counters),
        blob=record.blob,
    )
    if expected != record.integrity_sha256:
        raise CheckpointError("checkpoint integrity hash mismatch; restart stage")
    return record


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


def _record_from_row(row: tuple[Any, ...]) -> CheckpointRecord:
    try:
        cursor = json.loads(str(row[7]))
        counters = json.loads(str(row[8]))
        if not isinstance(cursor, dict) or not isinstance(counters, dict):
            raise ValueError("checkpoint cursor and counters must be objects")
        return CheckpointRecord(
            checkpoint_id=str(row[0]),
            job_id=str(row[1]),
            source_fingerprint=str(row[2]),
            stage=str(row[3]),
            checkpoint_version=int(row[4]),
            tool_name=str(row[5]),
            tool_version=str(row[6]),
            cursor=cursor,
            counters=counters,
            blob=bytes(row[9]),
            integrity_sha256=str(row[10]),
            supersedes_checkpoint_id=None if row[11] is None else str(row[11]),
        )
    except (TypeError, ValueError, json.JSONDecodeError, RecursionError) as error:
        raise CheckpointError("checkpoint record is malformed; restart stage") from error


def _canonical_json(payload: Mapping[str, Any]) -> str:
    try:
        return json.dumps(payload, allow_nan=False, sort_keys=True, separators=(",", ":"))
    except (TypeError, ValueError, RecursionError) as error:
        raise CheckpointError("checkpoint payload is not canonical JSON") from error


def _validate_checkpoint_inputs(
    *,
    source_fingerprint: str,
    stage: str,
    checkpoint_version: int,
    tool_name: str,
    tool_version: str,
    blob: bytes,
) -> None:
    if not isinstance(source_fingerprint, str) or SHA256_RE.fullmatch(source_fingerprint) is None:
        raise CheckpointError("checkpoint source fingerprint is invalid")
    if (
        not isinstance(checkpoint_version, int)
        or isinstance(checkpoint_version, bool)
        or checkpoint_version <= 0
    ):
        raise CheckpointError("checkpoint version is invalid")
    for value, label in (
        (stage, "stage"),
        (tool_name, "tool name"),
        (tool_version, "tool version"),
    ):
        if (
            not isinstance(value, str)
            or not value
            or len(value) > MAX_CHECKPOINT_TEXT
            or "\x00" in value
        ):
            raise CheckpointError(f"checkpoint {label} is invalid")
    if not isinstance(blob, bytes):
        raise CheckpointError("checkpoint blob is invalid")


def _integrity_hash(
    *,
    source_fingerprint: str,
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
        source_fingerprint,
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
