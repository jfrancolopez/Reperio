"""Deleted and orphan filesystem entry recovery classification."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field, replace

from scanner import content_extraction
from scanner.entry_normalization import NormalizedEntry, RawTimestamp
from shared.scratch_store import ScratchStore


@dataclass(frozen=True)
class DeletedRecoveryResult:
    entry_id: str
    recovery_state: str
    extraction: content_extraction.ExtractionResult | None
    warnings: tuple[str, ...] = ()
    original_path: str | None = None
    original_name: str | None = None
    raw_name_bytes: bytes = b""
    raw_timestamps: Mapping[str, RawTimestamp] = field(default_factory=dict)
    parent_object_id: str | None = None
    parent_entry_id: str | None = None
    orphan: bool = False
    recovery_health: str = "unknown"


def recover_deleted_entry(
    entry: NormalizedEntry,
    *,
    reader: content_extraction.ExtentReader,
    scratch: ScratchStore,
    max_size_bytes: int,
) -> DeletedRecoveryResult:
    """Attempt deleted/orphan content recovery without treating it as allocated."""

    if entry.allocated:
        return _result(entry, "allocated_not_deleted", None, health="not_deleted")
    if entry.entry_type not in {"deleted", "file"}:
        return _result(entry, "metadata_only", None, ("metadata_only",), health="unrecoverable")
    if entry.size_bytes == 0:
        if not entry.extents:
            return _recover_with_extraction(
                entry,
                reader=reader,
                scratch=scratch,
                max_size_bytes=max_size_bytes,
            )
        return _result(
            entry,
            "unrecoverable",
            None,
            ("size_metadata_conflict",),
            health="unrecoverable",
        )
    if not entry.extents:
        return _result(entry, "unrecoverable", None, ("missing_extents",), health="unrecoverable")

    return _recover_with_extraction(
        entry,
        reader=reader,
        scratch=scratch,
        max_size_bytes=max_size_bytes,
    )


def _recover_with_extraction(
    entry: NormalizedEntry,
    *,
    reader: content_extraction.ExtentReader,
    scratch: ScratchStore,
    max_size_bytes: int,
) -> DeletedRecoveryResult:
    extraction_entry = _as_extractable_deleted(entry)
    try:
        extraction = content_extraction.extract_allocated_content(
            extraction_entry,
            reader=reader,
            scratch=scratch,
            max_size_bytes=max_size_bytes,
        )
    except content_extraction.ContentExtractionError as error:
        if error.code != "bad_extent":
            raise
        return _result(entry, "unrecoverable", None, (error.code,), health="unrecoverable")
    state = _recovery_state(extraction)
    warnings = [*extraction.warnings]
    health = state
    if entry.size_bytes is None:
        warnings.append("missing_size_metadata")
        if state == "intact":
            state = "partial"
            health = "partial"
    return _result(
        entry,
        state,
        extraction,
        tuple(warnings),
        health=health,
    )


def _as_extractable_deleted(entry: NormalizedEntry) -> NormalizedEntry:
    return replace(
        entry,
        entry_type="deleted",
        attributes=tuple(dict.fromkeys((*entry.attributes, "deleted_source"))),
        owner_id=entry.owner_id,
        allocated=True,
    )


def _result(
    entry: NormalizedEntry,
    recovery_state: str,
    extraction: content_extraction.ExtractionResult | None,
    warnings: tuple[str, ...] = (),
    *,
    health: str,
) -> DeletedRecoveryResult:
    return DeletedRecoveryResult(
        entry_id=entry.entry_id,
        recovery_state=recovery_state,
        extraction=extraction,
        warnings=tuple(dict.fromkeys((*entry.warnings, *warnings))),
        original_path=entry.display_path,
        original_name=entry.display_name,
        raw_name_bytes=entry.raw_name_bytes,
        raw_timestamps=dict(entry.raw_timestamps),
        parent_object_id=entry.parent_object_id,
        parent_entry_id=entry.parent_entry_id,
        orphan="orphan_parent" in entry.warnings
        or (entry.parent_object_id is not None and entry.parent_entry_id is None),
        recovery_health=health,
    )


def _recovery_state(extraction: content_extraction.ExtractionResult) -> str:
    if extraction.status in {"complete", "resumed"}:
        return "intact"
    if extraction.status == "partial":
        return "partial"
    if "size_limit_exceeded" in extraction.warnings:
        return "deferred_size_limit"
    if "metadata_only" in extraction.warnings:
        return "unrecoverable"
    return "unrecoverable"
