"""Deleted and orphan filesystem entry recovery classification."""

from __future__ import annotations

from dataclasses import dataclass

from scanner import content_extraction
from scanner.entry_normalization import NormalizedEntry
from shared.scratch_store import ScratchStore


@dataclass(frozen=True)
class DeletedRecoveryResult:
    entry_id: str
    recovery_state: str
    extraction: content_extraction.ExtractionResult | None
    warnings: tuple[str, ...] = ()


def recover_deleted_entry(
    entry: NormalizedEntry,
    *,
    reader: content_extraction.ExtentReader,
    scratch: ScratchStore,
    max_size_bytes: int,
) -> DeletedRecoveryResult:
    """Attempt deleted/orphan content recovery without treating it as allocated."""

    if entry.allocated:
        return DeletedRecoveryResult(entry.entry_id, "allocated_not_deleted", None)
    if entry.entry_type not in {"deleted", "file"}:
        return DeletedRecoveryResult(entry.entry_id, "metadata_only", None, ("metadata_only",))
    if not entry.extents:
        return DeletedRecoveryResult(entry.entry_id, "unrecoverable", None, ("missing_extents",))

    extraction_entry = _as_extractable_deleted(entry)
    extraction = content_extraction.extract_allocated_content(
        extraction_entry,
        reader=reader,
        scratch=scratch,
        max_size_bytes=max_size_bytes,
    )
    return DeletedRecoveryResult(
        entry.entry_id,
        _recovery_state(extraction),
        extraction,
        tuple(dict.fromkeys((*entry.warnings, *extraction.warnings))),
    )


def _as_extractable_deleted(entry: NormalizedEntry) -> NormalizedEntry:
    return NormalizedEntry(
        entry_id=entry.entry_id,
        volume_id=entry.volume_id,
        object_id=entry.object_id,
        parent_object_id=entry.parent_object_id,
        parent_entry_id=entry.parent_entry_id,
        raw_path_bytes=entry.raw_path_bytes,
        display_path=entry.display_path,
        raw_name_bytes=entry.raw_name_bytes,
        display_name=entry.display_name,
        entry_type="deleted",
        attributes=tuple(dict.fromkeys((*entry.attributes, "deleted_source"))),
        owner_id=entry.owner_id,
        size_bytes=entry.size_bytes,
        allocated=True,
        raw_timestamps=entry.raw_timestamps,
        extents=entry.extents,
        alternate_stream=entry.alternate_stream,
        warnings=entry.warnings,
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
