"""Progressive ingestion of completed PhotoRec carved output."""

from __future__ import annotations

import hashlib
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from shared.scratch_store import ScratchObject, ScratchStore


class CarvedIngestionError(ValueError):
    """Raised when carved output cannot be safely represented."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


@dataclass(frozen=True)
class ObservedFile:
    path: Path
    size_bytes: int
    mtime_ns: int


@dataclass(frozen=True)
class CarvedRecord:
    carved_id: str
    source_path: str
    scratch_object: ScratchObject | None
    status: str
    provenance: Mapping[str, Any]
    warnings: tuple[str, ...] = ()


def scan_carved_outputs(
    quarantine_dir: Path,
    *,
    previous: Mapping[str, ObservedFile],
    finalized_suffix: str = ".done",
) -> tuple[tuple[Path, ...], dict[str, ObservedFile]]:
    """Return completed files only after stable observation or finalized rename."""

    if not quarantine_dir.exists():
        return (), dict(previous)
    ready: list[Path] = []
    current: dict[str, ObservedFile] = {}
    for path in sorted(quarantine_dir.rglob("*")):
        if path.is_symlink() or not path.is_file():
            continue
        if path.name.endswith(finalized_suffix):
            ready.append(path)
            continue
        stat = path.stat()
        observed = ObservedFile(path, stat.st_size, stat.st_mtime_ns)
        current[str(path)] = observed
        prior = previous.get(str(path))
        if (
            prior is not None
            and prior.size_bytes == observed.size_bytes
            and prior.mtime_ns == observed.mtime_ns
        ):
            ready.append(path)
    return tuple(ready), current


def ingest_carved_file(
    path: Path,
    *,
    scratch: ScratchStore,
    source_id: str,
    carve_range: tuple[int, int] | None = None,
) -> CarvedRecord:
    """Hash/store one completed carved file with carved provenance."""

    if path.is_symlink() or not path.is_file():
        raise CarvedIngestionError("unsafe_carved_path", "carved output must be a regular file")
    size = path.stat().st_size
    provenance = _provenance(path, source_id=source_id, carve_range=carve_range)
    if size == 0:
        return CarvedRecord(
            _carved_id(path, b""),
            str(path),
            None,
            "skipped",
            provenance,
            warnings=("zero_length_carved_output",),
        )
    try:
        scratch_object = scratch.put_bytes(
            _file_chunks(path), provenance=provenance, expected_size=size
        )
    except OSError as error:
        return CarvedRecord(
            _carved_id(path, b""),
            str(path),
            None,
            "partial",
            provenance,
            warnings=(error.__class__.__name__,),
        )
    return CarvedRecord(
        _carved_id(path, scratch_object.sha256.encode("ascii")),
        str(path),
        scratch_object,
        "ingested",
        provenance,
    )


def ingest_ready_outputs(
    quarantine_dir: Path,
    *,
    scratch: ScratchStore,
    source_id: str,
    previous: Mapping[str, ObservedFile],
    already_ingested: Iterable[str] = (),
) -> tuple[tuple[CarvedRecord, ...], dict[str, ObservedFile]]:
    ready, current = scan_carved_outputs(quarantine_dir, previous=previous)
    seen = set(already_ingested)
    records: list[CarvedRecord] = []
    for path in ready:
        key = str(path)
        if key in seen:
            continue
        record = ingest_carved_file(path, scratch=scratch, source_id=source_id)
        records.append(record)
        seen.add(key)
    return tuple(records), current


def _file_chunks(path: Path) -> Iterable[bytes]:
    with path.open("rb") as handle:
        while True:
            chunk = handle.read(1024 * 1024)
            if not chunk:
                break
            yield chunk


def _provenance(
    path: Path, *, source_id: str, carve_range: tuple[int, int] | None
) -> dict[str, object]:
    payload: dict[str, object] = {
        "entry_kind": "carved",
        "source_id": source_id,
        "carved_path_name": path.name,
    }
    if carve_range is not None:
        payload["offset_bytes"] = carve_range[0]
        payload["length_bytes"] = carve_range[1]
    return payload


def _carved_id(path: Path, digest_bytes: bytes) -> str:
    digest = hashlib.sha256(str(path).encode("utf-8") + b"\0" + digest_bytes).hexdigest()
    return f"carved-{digest[:32]}"
