"""Numbered SQLite migration runner for Reperio catalog databases."""

from __future__ import annotations

import sqlite3
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from pathlib import Path

from shared import catalog_schema

CURRENT_SCHEMA_VERSION = 7


class MigrationError(RuntimeError):
    """Raised when a migration cannot complete safely."""

    workers_allowed = False


class FutureSchemaError(MigrationError):
    """Raised when a database is newer than this application understands."""


@dataclass(frozen=True)
class Migration:
    version: int
    name: str
    apply: Callable[[sqlite3.Connection], None]


@dataclass(frozen=True)
class MigrationResult:
    current_version: int
    applied_versions: tuple[int, ...]
    backup_path: Path | None
    workers_allowed: bool


def migrate_catalog(
    database_path: Path,
    *,
    backup_dir: Path | None = None,
    migrations: Sequence[Migration] | None = None,
) -> MigrationResult:
    """Upgrade a catalog database to the current schema version."""

    selected = tuple(migrations or DEFAULT_MIGRATIONS)
    _validate_migration_sequence(selected)
    database_path.parent.mkdir(parents=True, exist_ok=True)
    existed_before = database_path.exists() and database_path.stat().st_size > 0
    connection = catalog_schema.connect_catalog(database_path)
    try:
        current = current_schema_version(connection)
        target = selected[-1].version if selected else 0
        if current > target:
            raise FutureSchemaError(
                f"database schema version {current} is newer than supported {target}"
            )
        if current == target:
            return MigrationResult(current, (), None, True)

        backup_path = (
            _backup_database(database_path, backup_dir, current, target) if existed_before else None
        )
        applied = _apply_pending_migrations(connection, current, selected)
        return MigrationResult(current_schema_version(connection), applied, backup_path, True)
    except sqlite3.Error as error:
        raise MigrationError(str(error)) from error
    finally:
        connection.close()


def current_schema_version(connection: sqlite3.Connection) -> int:
    """Return the recorded schema version, or 0 for an unversioned database."""

    catalog_schema.configure_connection(connection)
    table_exists = connection.execute(
        "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'schema_migrations'"
    ).fetchone()
    if table_exists is None:
        return 0
    row = connection.execute("SELECT MAX(version) FROM schema_migrations").fetchone()
    return int(row[0] or 0)


def ready_for_workers(database_path: Path) -> bool:
    """Return true only when the catalog has the exact supported schema."""

    if not database_path.exists():
        return False
    connection = catalog_schema.connect_catalog(database_path)
    try:
        return current_schema_version(connection) == CURRENT_SCHEMA_VERSION
    finally:
        connection.close()


def _apply_initial_schema(connection: sqlite3.Connection) -> None:
    for statement in catalog_schema.initial_schema_statements():
        connection.execute(statement)


def _add_retry_after_column(connection: sqlite3.Connection) -> None:
    if not _column_exists(connection, "jobs", "retry_after_at"):
        connection.execute(
            """
            ALTER TABLE jobs ADD COLUMN
            retry_after_at TEXT CHECK (
                retry_after_at IS NULL OR (
                    length(retry_after_at) = 20
                    AND substr(retry_after_at, 5, 1) = '-'
                    AND substr(retry_after_at, 8, 1) = '-'
                    AND substr(retry_after_at, 11, 1) = 'T'
                    AND substr(retry_after_at, 14, 1) = ':'
                    AND substr(retry_after_at, 17, 1) = ':'
                    AND substr(retry_after_at, 20, 1) = 'Z'
                )
            )
            """
        )


def _add_checkpoints_table(connection: sqlite3.Connection) -> None:
    if not _table_exists(connection, "checkpoints"):
        for statement in catalog_schema.initial_schema_statements():
            if "CREATE TABLE IF NOT EXISTS checkpoints" in statement:
                connection.execute(statement)
            if "idx_checkpoints_latest" in statement:
                connection.execute(statement)


def _add_event_sequences(connection: sqlite3.Connection) -> None:
    if not _table_exists(connection, "events"):
        _create_events_table_and_indexes(connection)
        return
    if _column_exists(connection, "events", "sequence"):
        return
    connection.execute("ALTER TABLE events RENAME TO events_v3")
    _create_events_table_and_indexes(connection)
    connection.execute(
        """
        INSERT INTO events
        (event_id, case_id, sequence, job_id, event_type, payload_json, published_at, created_at)
        SELECT event_id, case_id,
               ROW_NUMBER() OVER (
                   PARTITION BY COALESCE(case_id, event_id)
                   ORDER BY created_at, event_id
               ),
               job_id, event_type, payload_json, published_at, created_at
        FROM events_v3
        ORDER BY created_at, event_id
        """
    )
    connection.execute("DROP TABLE events_v3")


def _create_events_table_and_indexes(connection: sqlite3.Connection) -> None:
    for statement in catalog_schema.initial_schema_statements():
        if "CREATE TABLE IF NOT EXISTS events" in statement:
            connection.execute(statement)
        if "idx_events_case_sequence" in statement or "idx_events_case_created" in statement:
            connection.execute(statement)
        if "idx_events_unpublished" in statement:
            connection.execute(statement)


def _add_finding_query_indexes(connection: sqlite3.Connection) -> None:
    if not _table_exists(connection, "findings") or not _table_exists(connection, "evidence"):
        _create_findings_tables_and_indexes(connection)
        return
    connection.execute(
        "CREATE INDEX IF NOT EXISTS idx_findings_query ON findings(case_id, created_at, finding_id)"
    )
    connection.execute(
        "CREATE INDEX IF NOT EXISTS idx_findings_filters ON findings(finding_type, severity, status)"
    )


def _create_findings_tables_and_indexes(connection: sqlite3.Connection) -> None:
    for statement in catalog_schema.initial_schema_statements():
        if "CREATE TABLE IF NOT EXISTS findings" in statement:
            connection.execute(statement)
        if "CREATE TABLE IF NOT EXISTS evidence" in statement:
            connection.execute(statement)
        if "idx_findings_" in statement or "idx_evidence_finding" in statement:
            connection.execute(statement)


def _add_browser_artifacts_table(connection: sqlite3.Connection) -> None:
    if _table_exists(connection, "browser_artifacts"):
        return
    for statement in catalog_schema.initial_schema_statements():
        if "CREATE TABLE IF NOT EXISTS browser_artifacts" in statement:
            connection.execute(statement)
        if "idx_browser_artifacts_" in statement:
            connection.execute(statement)


def _add_media_checkpoint_bindings(connection: sqlite3.Connection) -> None:
    if not _column_exists(connection, "checkpoints", "medium_identity_json"):
        connection.execute(
            "ALTER TABLE checkpoints ADD COLUMN "
            "medium_identity_json TEXT CHECK "
            "(medium_identity_json IS NULL OR json_valid(medium_identity_json))"
        )
    if not _table_exists(connection, "source_devices"):
        for statement in catalog_schema.initial_schema_statements():
            if "CREATE TABLE IF NOT EXISTS source_devices" in statement:
                connection.execute(statement)
            if "idx_source_devices_reader" in statement:
                connection.execute(statement)
    if not _table_exists(connection, "source_media"):
        for statement in catalog_schema.initial_schema_statements():
            if "CREATE TABLE IF NOT EXISTS source_media" in statement:
                connection.execute(statement)
            if "idx_source_media_" in statement:
                connection.execute(statement)


DEFAULT_MIGRATIONS = (
    Migration(1, "initial_catalog_schema", _apply_initial_schema),
    Migration(2, "job_retry_after", _add_retry_after_column),
    Migration(3, "versioned_checkpoints", _add_checkpoints_table),
    Migration(4, "event_outbox_sequences", _add_event_sequences),
    Migration(5, "finding_query_indexes", _add_finding_query_indexes),
    Migration(6, "browser_artifact_schemas", _add_browser_artifacts_table),
    Migration(7, "media_checkpoint_bindings", _add_media_checkpoint_bindings),
)


def _validate_migration_sequence(migrations: Sequence[Migration]) -> None:
    expected = 1
    for migration in migrations:
        if migration.version != expected:
            raise MigrationError("migrations must be contiguous and start at version 1")
        expected += 1


def _apply_pending_migrations(
    connection: sqlite3.Connection, current: int, migrations: Sequence[Migration]
) -> tuple[int, ...]:
    applied: list[int] = []
    try:
        connection.execute("BEGIN IMMEDIATE")
        _ensure_version_table(connection)
        for migration in migrations:
            if migration.version <= current:
                continue
            migration.apply(connection)
            connection.execute(
                """
                INSERT INTO schema_migrations (version, name, applied_at)
                VALUES (?, ?, strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
                """,
                (migration.version, migration.name),
            )
            applied.append(migration.version)
        connection.execute("COMMIT")
    except Exception:
        connection.execute("ROLLBACK")
        raise
    return tuple(applied)


def _ensure_version_table(connection: sqlite3.Connection) -> None:
    connection.execute(
        """
        CREATE TABLE IF NOT EXISTS schema_migrations (
            version INTEGER PRIMARY KEY CHECK (version > 0),
            name TEXT NOT NULL UNIQUE,
            applied_at TEXT NOT NULL CHECK (
                length(applied_at) = 20
                AND substr(applied_at, 5, 1) = '-'
                AND substr(applied_at, 8, 1) = '-'
                AND substr(applied_at, 11, 1) = 'T'
                AND substr(applied_at, 14, 1) = ':'
                AND substr(applied_at, 17, 1) = ':'
                AND substr(applied_at, 20, 1) = 'Z'
            )
        ) STRICT
        """
    )


def _table_exists(connection: sqlite3.Connection, table: str) -> bool:
    return (
        connection.execute(
            "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?", (table,)
        ).fetchone()
        is not None
    )


def _column_exists(connection: sqlite3.Connection, table: str, column: str) -> bool:
    return any(row[1] == column for row in connection.execute(f"PRAGMA table_info({table})"))


def _backup_database(
    database_path: Path, backup_dir: Path | None, current: int, target: int
) -> Path:
    destination_dir = backup_dir or database_path.parent / "backups"
    destination_dir.mkdir(parents=True, exist_ok=True)
    backup_path = destination_dir / f"{database_path.name}.v{current}-to-v{target}.bak"
    source = sqlite3.connect(database_path)
    destination = sqlite3.connect(backup_path)
    try:
        source.backup(destination)
    finally:
        destination.close()
        source.close()
    return backup_path
