"""Numbered SQLite migration runner for Reperio catalog databases."""

from __future__ import annotations

import sqlite3
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from pathlib import Path

from shared import catalog_schema

CURRENT_SCHEMA_VERSION = catalog_schema.INITIAL_SCHEMA_VERSION


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


DEFAULT_MIGRATIONS = (Migration(1, "initial_catalog_schema", _apply_initial_schema),)


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
