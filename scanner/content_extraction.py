"""Read-only allocated file content extraction into scratch storage."""

from __future__ import annotations

import hashlib
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from typing import Any, Protocol

from scanner.entry_normalization import Extent, NormalizedEntry
from shared.scratch_store import ScratchObject, ScratchStore

CHUNK_SIZE = 1024 * 1024


class ContentExtractionError(ValueError):
    """Raised when extraction input violates scanner safety constraints."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


@dataclass(frozen=True)
class ExtractionResult:
    entry_id: str
    status: str
    size_bytes: int
    sha256: str | None
    scratch_object: ScratchObject | None
    warnings: tuple[str, ...] = ()
    error_code: str | None = None
    checkpoint: Mapping[str, Any] | None = None


class ExtentReader(Protocol):
    def read_at(self, offset_bytes: int, length_bytes: int) -> bytes: ...


def extract_allocated_content(
    entry: NormalizedEntry,
    *,
    reader: ExtentReader,
    scratch: ScratchStore,
    max_size_bytes: int,
    resume_checkpoint: Mapping[str, Any] | None = None,
) -> ExtractionResult:
    """Stream allocated content to scratch without blocking catalog entry creation."""

    if max_size_bytes <= 0:
        raise ContentExtractionError("invalid_limit", "maximum extraction size must be positive")
    if not entry.allocated:
        return _skipped(entry, "not_allocated")
    if entry.entry_type not in {"file", "deleted"}:
        return _skipped(entry, "metadata_only")
    if entry.size_bytes == 0:
        scratch_object = scratch.put_bytes((), provenance=_provenance(entry), expected_size=0)
        return ExtractionResult(
            entry.entry_id, "complete", 0, scratch_object.sha256, scratch_object
        )
    if not entry.extents:
        return _skipped(entry, "metadata_only")
    expected_size = (
        entry.size_bytes if entry.size_bytes is not None else sum_extent_lengths(entry.extents)
    )
    if expected_size > max_size_bytes:
        return ExtractionResult(
            entry.entry_id,
            "skipped",
            0,
            None,
            None,
            warnings=("size_limit_exceeded",),
            checkpoint={"entry_id": entry.entry_id, "status": "size_limit_exceeded"},
        )

    start_extent = int((resume_checkpoint or {}).get("extent_index", 0))
    if start_extent < 0 or start_extent >= len(entry.extents):
        start_extent = 0
    chunks = _read_chunks(entry.extents[start_extent:], reader=reader)
    try:
        scratch_object = scratch.put_bytes(
            chunks,
            provenance=_provenance(entry),
            expected_size=expected_size - sum_extent_lengths(entry.extents[:start_extent]),
        )
    except OSError as error:
        return ExtractionResult(
            entry.entry_id,
            "partial",
            0,
            None,
            None,
            warnings=("io_error",),
            error_code=error.__class__.__name__,
            checkpoint={"entry_id": entry.entry_id, "extent_index": start_extent},
        )
    return ExtractionResult(
        entry.entry_id,
        "complete" if start_extent == 0 else "resumed",
        scratch_object.size_bytes,
        scratch_object.sha256,
        scratch_object,
        warnings=_sparse_warnings(entry.extents),
    )


def expected_sha256(entry: NormalizedEntry, *, reader: ExtentReader) -> str:
    """Compute the source byte hash from extents for byte-compare tests."""

    digest = hashlib.sha256()
    for chunk in _read_chunks(entry.extents, reader=reader):
        digest.update(chunk)
    return digest.hexdigest()


def sum_extent_lengths(extents: Iterable[Extent]) -> int:
    total = 0
    for extent in extents:
        if extent.offset_bytes < 0 or extent.length_bytes < 0:
            raise ContentExtractionError("bad_extent", "extent values must not be negative")
        total += extent.length_bytes
    return total


def _read_chunks(extents: Iterable[Extent], *, reader: ExtentReader) -> Iterable[bytes]:
    for extent in extents:
        if extent.offset_bytes < 0 or extent.length_bytes < 0:
            raise ContentExtractionError("bad_extent", "extent values must not be negative")
        remaining = extent.length_bytes
        offset = extent.offset_bytes
        if extent.sparse:
            while remaining > 0:
                chunk_size = min(CHUNK_SIZE, remaining)
                yield bytes(chunk_size)
                remaining -= chunk_size
            continue
        while remaining > 0:
            chunk_size = min(CHUNK_SIZE, remaining)
            chunk = reader.read_at(offset, chunk_size)
            if len(chunk) != chunk_size:
                raise OSError("short read from source extent")
            yield chunk
            offset += chunk_size
            remaining -= chunk_size


def _skipped(entry: NormalizedEntry, code: str) -> ExtractionResult:
    return ExtractionResult(
        entry.entry_id,
        "skipped",
        0,
        None,
        None,
        warnings=(code,),
        checkpoint={"entry_id": entry.entry_id, "status": code},
    )


def _sparse_warnings(extents: tuple[Extent, ...]) -> tuple[str, ...]:
    if any(extent.sparse for extent in extents):
        return ("sparse_zero_filled",)
    return ()


def _provenance(entry: NormalizedEntry) -> dict[str, str]:
    return {
        "entry_id": entry.entry_id,
        "volume_id": entry.volume_id,
        "object_id": entry.object_id,
        "path_sha256": hashlib.sha256(entry.raw_path_bytes).hexdigest(),
    }
