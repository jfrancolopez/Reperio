"""Verified local export engine (RPR-106).

Streams recovered content from the scratch store to a temporary name in the
destination, verifies size and SHA-256, fsyncs, and atomically finalizes.
Failures never mark an item complete and never remove a completed copy; only
proven-incomplete partial files are cleaned up. Before any copy the destination
is proven physically separate from the selected source medium.
"""

from __future__ import annotations

import hashlib
import os
import secrets
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from shared.destination_contract import recheck_source_separation

LOCAL_EXPORT_VERSION = "local-export-v1"
COPY_CHUNK_BYTES = 1024 * 1024
PARTIAL_SUFFIX = ".partial"
FINAL_SUFFIX = ".final"


class ExportError(ValueError):
    """Raised when a local export step cannot complete safely."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


@dataclass(frozen=True)
class ExportItem:
    export_item_id: str
    source_path: str
    expected_size: int
    expected_sha256: str


@dataclass(frozen=True)
class ExportProgress:
    item_id: str
    copied_bytes: int
    total_bytes: int
    phase: str
    updated_at: str


@dataclass(frozen=True)
class ExportResult:
    item_id: str
    state: str
    destination_path: str | None
    size: int
    sha256: str | None
    verified: bool
    error: str | None
    updated_at: str

    @classmethod
    def failed(cls, item_id: str, *, error: str, now: str) -> ExportResult:
        return cls(
            item_id=item_id,
            state="failed",
            destination_path=None,
            size=0,
            sha256=None,
            verified=False,
            error=error,
            updated_at=now,
        )


ProgressCallback = Callable[[ExportProgress], None]
Writer = Callable[[Path, bytes], None]


def ensure_under_root(path: str, root: str) -> Path:
    """Resolve ``path`` and prove it stays inside ``root`` (hostile-content guard)."""
    resolved_path = Path(path).resolve()
    resolved_root = Path(root).resolve()
    if resolved_root != resolved_path and resolved_root not in resolved_path.parents:
        raise ExportError(
            "source_outside_scratch", "source path must live inside the scratch store"
        )
    return resolved_path


def prove_destination_separation(
    destination_path: str,
    source: Mapping[str, Any],
    *,
    mounts: list[Mapping[str, Any]] | tuple[Mapping[str, Any], ...] | None = None,
    holders: Mapping[str, Any] | None = None,
    evaluate: Any = None,
) -> str:
    """Recheck that the destination is not the source medium, its reader, or a child."""
    result = recheck_source_separation(
        destination_path,
        source,
        mounts=mounts or (),
        holders=holders or {},
        evaluate=evaluate,
    )
    if not result["separate"]:
        raise ExportError(
            "destination_not_separate_from_source",
            "destination is on the selected source medium or a child partition",
        )
    return str(result["destination_path"])


def prepare_copy(
    *,
    item_id: str,
    destination_dir: str,
    expected_size: int,
    replace: bool = False,
) -> tuple[Path, Path]:
    """Create a unique partial path and refuse to overwrite a finished copy."""
    root = Path(destination_dir).resolve()
    if not root.is_dir():
        raise ExportError("destination_missing", "destination directory does not exist")
    final = root / f"{item_id}{FINAL_SUFFIX}"
    if final.exists() and not replace:
        raise ExportError("destination_exists", "a completed export for this item already exists")
    token = secrets.token_hex(8)
    partial = root / f".{item_id}.{token}{PARTIAL_SUFFIX}"
    return partial, final


def copy_stream(
    item: ExportItem,
    partial: Path,
    *,
    on_progress: ProgressCallback | None = None,
    writer: Writer | None = None,
    now: str = "",
    chunk_size: int = COPY_CHUNK_BYTES,
) -> tuple[int, str]:
    """Stream the source into the partial file while hashing and counting bytes."""
    source = ensure_under_root(item.source_path, os.path.dirname(item.source_path))
    write = writer if writer is not None else _default_writer
    digest = hashlib.sha256()
    copied = 0
    try:
        with source.open("rb") as handle:
            while True:
                chunk = handle.read(chunk_size)
                if not chunk:
                    break
                if copied + len(chunk) > item.expected_size:
                    raise ExportError("source_changed", "source grew beyond the expected size")
                write(partial, chunk)
                digest.update(chunk)
                copied += len(chunk)
                if on_progress is not None:
                    on_progress(
                        ExportProgress(
                            item_id=item.export_item_id,
                            copied_bytes=copied,
                            total_bytes=item.expected_size,
                            phase="copying",
                            updated_at=now,
                        )
                    )
    except OSError as error:
        raise ExportError("copy_io_failed", f"copy failed: {error.strerror or error}") from error
    if copied != item.expected_size:
        raise ExportError("source_changed", "source ended before the expected size")
    return copied, digest.hexdigest()


def verify_copy(partial: Path, *, expected_size: int, expected_sha256: str) -> None:
    """Confirm the copied file matches the recorded size and digest."""
    actual_size = partial.stat().st_size
    if actual_size != expected_size:
        raise ExportError("verification_failed", "copied size does not match the expected size")
    digest = hashlib.sha256()
    with partial.open("rb") as handle:
        for chunk in iter(lambda: handle.read(COPY_CHUNK_BYTES), b""):
            digest.update(chunk)
    actual_sha256 = digest.hexdigest()
    if actual_sha256 != expected_sha256:
        raise ExportError("verification_failed", "copied digest does not match the expected digest")


def finalize_copy(partial: Path, final: Path, *, fsync: bool = True) -> None:
    """Fsync the partial, then atomically rename it to the final name."""
    if fsync:
        _fsync_file(partial)
    try:
        os.replace(partial, final)
    except OSError as error:
        raise ExportError(
            "finalize_failed", f"cannot finalize copy: {error.strerror or error}"
        ) from error
    if fsync:
        _fsync_dir(final.parent)


def cleanup_partial(partial: Path) -> bool:
    """Remove a proven-incomplete partial file. Returns whether it was removed."""
    try:
        existed = partial.exists()
        partial.unlink(missing_ok=True)
        return existed
    except OSError:
        return False


def export_local_item(
    item: ExportItem,
    *,
    destination_dir: str,
    now: str,
    on_progress: ProgressCallback | None = None,
    writer: Writer | None = None,
    replace: bool = False,
) -> ExportResult:
    """Run one item through prepare, copy, verify, and atomic finalize."""
    try:
        partial, final = prepare_copy(
            item_id=item.export_item_id,
            destination_dir=destination_dir,
            expected_size=item.expected_size,
            replace=replace,
        )
    except ExportError as error:
        return ExportResult.failed(item.export_item_id, error=error.code, now=now)
    try:
        copied, sha256 = copy_stream(item, partial, on_progress=on_progress, writer=writer, now=now)
        verify_copy(partial, expected_size=item.expected_size, expected_sha256=item.expected_sha256)
        finalize_copy(partial, final)
    except ExportError as error:
        cleanup_partial(partial)
        return ExportResult.failed(item.export_item_id, error=error.code, now=now)
    except OSError as error:
        cleanup_partial(partial)
        return ExportResult.failed(item.export_item_id, error=f"unexpected_{error.errno}", now=now)
    return ExportResult(
        item_id=item.export_item_id,
        state="completed",
        destination_path=str(final),
        size=copied,
        sha256=sha256,
        verified=sha256 == item.expected_sha256,
        error=None,
        updated_at=now,
    )


def _default_writer(path: Path, chunk: bytes) -> None:
    with path.open("ab") as handle:
        handle.write(chunk)


def _fsync_file(path: Path) -> None:
    with path.open("rb") as handle:
        os.fsync(handle.fileno())


def _fsync_dir(directory: Path) -> None:
    try:
        fd = os.open(str(directory), os.O_RDONLY | os.O_DIRECTORY)
    except OSError:
        return
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def list_partials(destination_dir: str) -> list[str]:
    """Return incomplete partial names for cleanup under policy."""
    root = Path(destination_dir)
    if not root.is_dir():
        return []
    return sorted(str(path.name) for path in root.glob(f".*{PARTIAL_SUFFIX}"))


def prune_partials(destination_dir: str) -> int:
    """Remove all proven-incomplete partials; never touches finalized copies."""
    removed = 0
    for path in Path(destination_dir).glob(f".*{PARTIAL_SUFFIX}"):
        try:
            path.unlink(missing_ok=True)
            removed += 1
        except OSError:
            continue
    return removed
