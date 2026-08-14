"""Helpers for copied SQLite artifacts and recoverable deleted-row records."""

from __future__ import annotations

import sqlite3
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path
from typing import Any
from urllib.parse import quote

from shared.browser_artifact_schemas import validate_browser_artifact
from shared.browser_normalization import normalize_browser_record


@dataclass(frozen=True)
class CopiedSqliteBundle:
    database_path: Path
    label: str
    wal_path: Path | None = None
    shm_path: Path | None = None
    warnings: tuple[str, ...] = ()


@dataclass(frozen=True)
class DeletedSqliteRowCandidate:
    artifact_kind: str
    source_artifact: str
    row_reference: str
    fields: Mapping[str, Any]
    validation_key: str


@dataclass(frozen=True)
class DeletedSqliteRecoveryResult:
    records: tuple[dict[str, Any], ...]
    warnings: tuple[str, ...] = ()


def copied_sqlite_bundle(database_path: Path, root: Path, label: str) -> CopiedSqliteBundle:
    resolved = database_path.resolve()
    root = root.resolve()
    if not _under(resolved, root):
        raise ValueError(f"{label} must be under copied profile directory")
    wal = _companion(resolved, root, "-wal")
    shm = _companion(resolved, root, "-shm")
    warnings: list[str] = []
    if wal is not None:
        warnings.append(f"sqlite_wal_present:{label}")
        if shm is None:
            warnings.append(f"sqlite_shm_missing:{label}")
    if shm is not None:
        warnings.append(f"sqlite_shm_present:{label}")
    return CopiedSqliteBundle(resolved, label, wal, shm, tuple(warnings))


def open_copied_sqlite_bundle(
    bundle: CopiedSqliteBundle,
) -> tuple[sqlite3.Connection | None, tuple[str, ...]]:
    warnings = list(bundle.warnings)
    if bundle.wal_path is not None:
        connection = _connect(bundle.database_path, immutable=False)
        if connection is not None:
            return connection, tuple(warnings)
        warnings.append(f"sqlite_wal_unreadable_ignored:{bundle.label}")
    connection = _connect(bundle.database_path, immutable=True)
    return connection, tuple(warnings)


def recover_deleted_sqlite_rows(
    *,
    browser_family: str,
    profile_id: str,
    parser_version: str,
    entry_ids: Mapping[str, str],
    live_validation_keys: set[str],
    candidates: Sequence[DeletedSqliteRowCandidate],
) -> DeletedSqliteRecoveryResult:
    records: list[dict[str, Any]] = []
    warnings: list[str] = []
    for candidate in candidates:
        if not candidate.validation_key:
            warnings.append(f"deleted_sqlite_row_rejected:{candidate.row_reference}:missing_key")
            continue
        record = {
            "artifact_id": _artifact_id(
                profile_id,
                candidate.artifact_kind,
                candidate.source_artifact,
                candidate.row_reference,
                "deleted",
            ),
            "artifact_kind": candidate.artifact_kind,
            "browser_family": browser_family,
            "profile_id": profile_id,
            "raw_provenance": {
                "entry_id": entry_ids.get(candidate.source_artifact, "unknown"),
                "source_artifact": candidate.source_artifact,
                "parser": parser_version,
                "row_reference": candidate.row_reference,
                "recovery_state": "validated_deleted_sqlite_row",
            },
            "recovery_confidence": 0.55,
            "parser_version": parser_version,
            "sqlite_recovery_state": "validated_deleted_row",
            **candidate.fields,
        }
        if candidate.validation_key in live_validation_keys:
            record["duplicate_of_live_row"] = candidate.validation_key
            warnings.append(f"deleted_sqlite_row_duplicate_live:{candidate.row_reference}")
        normalized = normalize_browser_record(record)
        validation = validate_browser_artifact(normalized)
        if validation.valid:
            records.append(normalized)
        else:
            warnings.extend(
                f"deleted_sqlite_row_rejected:{candidate.row_reference}:{warning}"
                for warning in validation.warnings
            )
    return DeletedSqliteRecoveryResult(tuple(records), tuple(dict.fromkeys(warnings)))


def _connect(path: Path, *, immutable: bool) -> sqlite3.Connection | None:
    suffix = "?mode=ro&immutable=1" if immutable else "?mode=ro"
    connection: sqlite3.Connection | None = None
    try:
        connection = sqlite3.connect(f"file:{quote(path.as_posix())}{suffix}", uri=True)
        connection.row_factory = sqlite3.Row
        connection.execute("SELECT 1").fetchone()
    except sqlite3.DatabaseError:
        if connection is not None:
            connection.close()
        return None
    return connection


def _companion(database_path: Path, root: Path, suffix: str) -> Path | None:
    companion = database_path.with_name(f"{database_path.name}{suffix}").resolve()
    if not _under(companion, root):
        raise ValueError("SQLite companion must be under copied profile directory")
    return companion if companion.exists() else None


def _under(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
    except ValueError:
        return False
    return True


def _artifact_id(*values: str) -> str:
    digest = sha256("\0".join(values).encode("utf-8")).hexdigest()
    return f"browser-artifact-{digest[:32]}"
