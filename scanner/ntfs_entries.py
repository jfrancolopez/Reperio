"""NTFS-specific entry enrichment without host filesystem access."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any

from scanner.entry_normalization import NormalizedEntry

NTFS_FLAGS = {
    "resident": "ntfs_resident",
    "compressed": "ntfs_compressed",
    "sparse": "ntfs_sparse",
    "reparse_point": "ntfs_reparse_point",
    "hidden": "hidden",
    "system": "system",
}
MFT_METADATA_NAMES = frozenset({"$MFT", "$MFTMirr", "$LogFile", "$Bitmap", "$Secure"})


@dataclass(frozen=True)
class NtfsEntryDetails:
    mft_reference: str | None
    attribute_id: str | None
    alternate_stream: str | None
    resident: bool
    compressed: bool
    sparse: bool
    reparse_tag: str | None
    hard_links: tuple[str, ...]
    dos_name: str | None
    recycle_bin_original_path: str | None
    recycle_bin_deletion_time: str | None
    metadata_file: bool


def enrich_ntfs_entry(
    entry: NormalizedEntry, metadata: Mapping[str, Any] | None = None
) -> tuple[NormalizedEntry, NtfsEntryDetails]:
    """Return an NTFS-aware normalized entry and structured NTFS facts."""
    facts = metadata or {}
    details = NtfsEntryDetails(
        mft_reference=_string(facts.get("mft_reference")) or entry.object_id.split("-", 1)[0],
        attribute_id=_string(facts.get("attribute_id")) or _attribute_id(entry.object_id),
        alternate_stream=entry.alternate_stream,
        resident=_bool(facts.get("resident")),
        compressed=_bool(facts.get("compressed")),
        sparse=_bool(facts.get("sparse")),
        reparse_tag=_string(facts.get("reparse_tag")),
        hard_links=_safe_strings(facts.get("hard_links")),
        dos_name=_string(facts.get("dos_name")),
        recycle_bin_original_path=_recycle_original_path(entry, facts),
        recycle_bin_deletion_time=_string(facts.get("recycle_bin_deletion_time")),
        metadata_file=entry.display_name in MFT_METADATA_NAMES or _bool(facts.get("metadata_file")),
    )
    attributes = [*entry.attributes]
    warnings = [*entry.warnings]
    for key, attribute in NTFS_FLAGS.items():
        if getattr(details, key, False) if hasattr(details, key) else _bool(facts.get(key)):
            attributes.append(attribute)
    if details.alternate_stream is not None:
        attributes.append("ntfs_alternate_data_stream")
    if details.hard_links:
        attributes.append("ntfs_hard_link")
        warnings.append("host_link_not_followed")
    if details.reparse_tag is not None:
        warnings.append("reparse_point_not_followed")
    if details.metadata_file:
        attributes.append("ntfs_metadata_file")
    if details.dos_name is not None:
        attributes.append("ntfs_dos_name")
    if details.recycle_bin_original_path is not None:
        attributes.append("ntfs_recycle_bin_record")

    enriched = NormalizedEntry(
        entry_id=entry.entry_id,
        volume_id=entry.volume_id,
        object_id=entry.object_id,
        parent_object_id=entry.parent_object_id,
        parent_entry_id=entry.parent_entry_id,
        raw_path_bytes=entry.raw_path_bytes,
        display_path=entry.display_path,
        raw_name_bytes=entry.raw_name_bytes,
        display_name=entry.display_name,
        entry_type=entry.entry_type,
        attributes=tuple(dict.fromkeys(attributes)),
        owner_id=entry.owner_id,
        size_bytes=entry.size_bytes,
        allocated=entry.allocated,
        raw_timestamps=entry.raw_timestamps,
        extents=entry.extents,
        alternate_stream=entry.alternate_stream,
        warnings=tuple(dict.fromkeys(warnings)),
    )
    return enriched, details


def _attribute_id(object_id: str) -> str | None:
    parts = object_id.split("-")
    return "-".join(parts[1:]) if len(parts) > 1 else None


def _recycle_original_path(entry: NormalizedEntry, facts: Mapping[str, Any]) -> str | None:
    explicit = _string(facts.get("recycle_bin_original_path"))
    if explicit is not None:
        return explicit
    path = entry.display_path.replace("\\", "/")
    if "/$Recycle.Bin/" in f"/{path}" and "/$R" in f"/{path}":
        return "unknown_original_path"
    return None


def _safe_strings(value: object) -> tuple[str, ...]:
    if not isinstance(value, Sequence) or isinstance(value, str):
        return ()
    cleaned: list[str] = []
    for item in value:
        text = _string(item)
        if text is not None:
            cleaned.append(text)
    return tuple(dict.fromkeys(cleaned))


def _string(value: object) -> str | None:
    if not isinstance(value, str):
        return None
    cleaned = " ".join(value.replace("\x00", "").split())
    return cleaned[:256] if cleaned else None


def _bool(value: object) -> bool:
    return value is True
