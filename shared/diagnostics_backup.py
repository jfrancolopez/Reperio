"""Redacted diagnostics and safe state backup utilities."""

from __future__ import annotations

import hashlib
import json
import tarfile
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from migrations import runner

BACKUP_FORMAT_VERSION = 1
DEFAULT_INCLUDE_DIRS = frozenset({"checkpoints"})
DEFAULT_INCLUDE_FILES = frozenset({"catalog.sqlite3", "settings.json"})
EXCLUDED_NAMES = frozenset({"secrets", "source", "sources", "source-content", "disk-images"})


class DiagnosticsBackupError(ValueError):
    """Raised when diagnostics backup or restore would be unsafe."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


@dataclass(frozen=True)
class BackupResult:
    archive_path: Path
    manifest_sha256: str
    entries: tuple[str, ...]


def build_redacted_support_bundle(
    *,
    settings: Mapping[str, Any],
    secret_snapshot: Iterable[Mapping[str, Any]] = (),
    diagnostics: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Build a JSON-serializable support payload without secret values."""

    return {
        "format_version": BACKUP_FORMAT_VERSION,
        "settings": _redact(settings),
        "secrets": tuple(_redact(secret) for secret in secret_snapshot),
        "diagnostics": _redact(diagnostics or {}),
    }


def create_state_backup(
    state_root: Path,
    archive_path: Path,
    *,
    workers_paused: Callable[[], bool],
    include_derivatives: bool = False,
    schema_version: int = runner.CURRENT_SCHEMA_VERSION,
) -> BackupResult:
    """Create a consistent state backup only while workers are paused."""

    if not workers_paused():
        raise DiagnosticsBackupError("workers_not_paused", "backup requires paused workers")
    state_root = state_root.resolve()
    archive_path.parent.mkdir(parents=True, exist_ok=True)
    entries = _state_entries(state_root, include_derivatives=include_derivatives)
    manifest = _manifest(state_root, entries, schema_version=schema_version)
    with tarfile.open(archive_path, "w:gz") as archive:
        manifest_bytes = json.dumps(manifest, sort_keys=True, indent=2).encode("utf-8")
        manifest_info = tarfile.TarInfo("manifest.json")
        manifest_info.size = len(manifest_bytes)
        archive.addfile(manifest_info, _BytesReader(manifest_bytes))
        for path in entries:
            archive.add(path, arcname=str(path.relative_to(state_root)), recursive=False)
    return BackupResult(
        archive_path=archive_path,
        manifest_sha256=hashlib.sha256(manifest_bytes).hexdigest(),
        entries=tuple(str(path.relative_to(state_root)) for path in entries),
    )


def restore_state_backup(
    archive_path: Path,
    restore_root: Path,
    *,
    max_schema_version: int = runner.CURRENT_SCHEMA_VERSION,
) -> tuple[str, ...]:
    """Restore a validated backup into an empty state directory."""

    restore_root.mkdir(parents=True, exist_ok=True)
    with tarfile.open(archive_path, "r:gz") as archive:
        manifest = _load_manifest(archive)
        if int(manifest.get("schema_version", 0)) > max_schema_version:
            raise DiagnosticsBackupError("future_schema", "backup schema is newer than supported")
        expected = {item["path"]: item["sha256"] for item in manifest.get("entries", ())}
        restored: list[str] = []
        for member in archive.getmembers():
            if member.name == "manifest.json":
                continue
            _validate_member(member)
            if member.name not in expected:
                raise DiagnosticsBackupError(
                    "unexpected_member", "archive contains unmanifested data"
                )
            data = archive.extractfile(member)
            if data is None:
                raise DiagnosticsBackupError("invalid_member", "archive member cannot be read")
            content = data.read()
            if hashlib.sha256(content).hexdigest() != expected[member.name]:
                raise DiagnosticsBackupError("integrity_mismatch", "backup member hash mismatch")
            target = restore_root / member.name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(content)
            restored.append(member.name)
    return tuple(sorted(restored))


def _state_entries(state_root: Path, *, include_derivatives: bool) -> tuple[Path, ...]:
    allowed_dirs = set(DEFAULT_INCLUDE_DIRS)
    if include_derivatives:
        allowed_dirs.add("derivatives")
    entries: list[Path] = []
    for child in state_root.iterdir():
        if child.name in EXCLUDED_NAMES:
            continue
        if child.is_file() and child.name in DEFAULT_INCLUDE_FILES:
            entries.append(child)
        elif child.is_dir() and child.name in allowed_dirs:
            entries.extend(path for path in child.rglob("*") if path.is_file())
    return tuple(sorted(entries))


def _manifest(
    state_root: Path, entries: tuple[Path, ...], *, schema_version: int
) -> dict[str, Any]:
    return {
        "format_version": BACKUP_FORMAT_VERSION,
        "schema_version": schema_version,
        "entries": [
            {
                "path": str(path.relative_to(state_root)),
                "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
                "size_bytes": path.stat().st_size,
            }
            for path in entries
        ],
    }


def _load_manifest(archive: tarfile.TarFile) -> dict[str, Any]:
    try:
        manifest_member = archive.getmember("manifest.json")
        manifest_file = archive.extractfile(manifest_member)
    except (KeyError, tarfile.TarError) as error:
        raise DiagnosticsBackupError("missing_manifest", "backup manifest is missing") from error
    if manifest_file is None:
        raise DiagnosticsBackupError("missing_manifest", "backup manifest cannot be read")
    try:
        manifest = json.loads(manifest_file.read().decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise DiagnosticsBackupError("corrupt_manifest", "backup manifest is corrupt") from error
    if not isinstance(manifest, dict) or manifest.get("format_version") != BACKUP_FORMAT_VERSION:
        raise DiagnosticsBackupError("unsupported_backup", "backup format is unsupported")
    return manifest


def _validate_member(member: tarfile.TarInfo) -> None:
    path = Path(member.name)
    if member.isdir() or member.issym() or member.islnk() or member.isdev():
        raise DiagnosticsBackupError("unsafe_member", "backup member type is unsafe")
    if path.is_absolute() or ".." in path.parts:
        raise DiagnosticsBackupError("unsafe_path", "backup member path is unsafe")
    if path.parts and path.parts[0] in EXCLUDED_NAMES:
        raise DiagnosticsBackupError("excluded_member", "backup contains excluded state")


def _redact(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {
            str(key): "********" if _secretish(str(key)) else _redact(item)
            for key, item in value.items()
        }
    if isinstance(value, list | tuple):
        return tuple(_redact(item) for item in value)
    return value


def _secretish(key: str) -> bool:
    lowered = key.lower()
    return any(token in lowered for token in ("secret", "token", "password", "key"))


class _BytesReader:
    def __init__(self, data: bytes) -> None:
        self._data = data
        self._offset = 0

    def read(self, size: int = -1) -> bytes:
        if size < 0:
            size = len(self._data) - self._offset
        chunk = self._data[self._offset : self._offset + size]
        self._offset += len(chunk)
        return chunk
