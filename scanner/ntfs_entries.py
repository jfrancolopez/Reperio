"""NTFS-specific entry enrichment without host filesystem access."""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, replace
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
MFT_METADATA_NAMES = frozenset(
    {
        "$AttrDef",
        "$BadClus",
        "$Bitmap",
        "$Boot",
        "$Extend",
        "$LogFile",
        "$MFT",
        "$MFTMirr",
        "$ObjId",
        "$Quota",
        "$Reparse",
        "$Secure",
        "$UpCase",
        "$UsnJrnl",
        "$Volume",
    }
)
_MFT_METADATA_NAMES_CASEFOLD = frozenset(name.casefold() for name in MFT_METADATA_NAMES)
_OBJECT_ID = re.compile(r"^(?P<mft>\d+)(?:-(?P<attribute>\d+(?:-\d+)*))?$")


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
    hidden: bool = False
    system: bool = False
    reparse_point: bool = False
    ads_parent_entry_id: str | None = None
    malformed_attributes: tuple[str, ...] = ()


def enrich_ntfs_entry(
    entry: NormalizedEntry, metadata: Mapping[str, Any] | None = None
) -> tuple[NormalizedEntry, NtfsEntryDetails]:
    """Return an NTFS-aware normalized entry and structured NTFS facts."""
    warnings = [*entry.warnings]
    malformed: list[str] = []
    facts: Mapping[str, Any]
    if metadata is None:
        facts = {}
    else:
        facts = metadata
    parsed_mft_reference, parsed_attribute_id = _object_identifiers(entry.object_id)
    if parsed_mft_reference is None:
        malformed.append("object_id")
        warnings.append("ntfs_malformed_object_id")
    if ":" in entry.display_name and entry.alternate_stream is None:
        malformed.append("alternate_stream")
    mft_reference = _optional_string(facts, "mft_reference", malformed)
    attribute_id = _optional_string(facts, "attribute_id", malformed)
    resident = _optional_bool(facts, "resident", malformed)
    compressed = _optional_bool(facts, "compressed", malformed)
    sparse = _optional_bool(facts, "sparse", malformed) or any(
        extent.sparse for extent in entry.extents
    )
    reparse_tag = _optional_string(facts, "reparse_tag", malformed)
    reparse_point = _optional_bool(facts, "reparse_point", malformed) or (
        "ntfs_reparse_point" in entry.attributes
    )
    if reparse_tag is not None:
        reparse_point = True
    hidden = _optional_bool(facts, "hidden", malformed) or "hidden" in entry.attributes
    system = _optional_bool(facts, "system", malformed) or "system" in entry.attributes
    hard_links = _optional_strings(facts, "hard_links", malformed)
    dos_name = _optional_string(facts, "dos_name", malformed)
    recycle_bin_original_path = _recycle_original_path(entry, facts, malformed)
    recycle_bin_deletion_time = _optional_string(facts, "recycle_bin_deletion_time", malformed)
    metadata_file = _is_metadata_file(entry.display_path) or _optional_bool(
        facts, "metadata_file", malformed
    )
    details = NtfsEntryDetails(
        mft_reference=mft_reference or parsed_mft_reference,
        attribute_id=attribute_id or parsed_attribute_id,
        alternate_stream=entry.alternate_stream,
        resident=resident,
        compressed=compressed,
        sparse=sparse,
        reparse_tag=reparse_tag,
        hard_links=hard_links,
        dos_name=dos_name,
        recycle_bin_original_path=recycle_bin_original_path,
        recycle_bin_deletion_time=recycle_bin_deletion_time,
        metadata_file=metadata_file,
        hidden=hidden,
        system=system,
        reparse_point=reparse_point,
        malformed_attributes=tuple(dict.fromkeys(malformed)),
    )
    attributes = [*entry.attributes]
    for key, attribute in NTFS_FLAGS.items():
        if getattr(details, key):
            attributes.append(attribute)
    if details.alternate_stream is not None:
        attributes.append("ntfs_alternate_data_stream")
    if details.hard_links:
        attributes.append("ntfs_hard_link")
        warnings.append("host_link_not_followed")
    if details.reparse_point:
        warnings.append("reparse_point_not_followed")
    if details.metadata_file:
        attributes.append("ntfs_metadata_file")
    if details.dos_name is not None:
        attributes.append("ntfs_dos_name")
    if details.recycle_bin_original_path is not None:
        attributes.append("ntfs_recycle_bin_record")
    warnings.extend(f"ntfs_malformed_attribute:{name}" for name in malformed)

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


def enrich_ntfs_entries(
    entries: Sequence[NormalizedEntry],
    metadata_by_object_id: Mapping[str, Mapping[str, Any]] | None = None,
) -> tuple[tuple[NormalizedEntry, ...], tuple[NtfsEntryDetails, ...]]:
    """Enrich an NTFS batch and resolve ADS to its primary entry when present."""
    facts_by_object_id = metadata_by_object_id or {}
    enriched_entries: list[NormalizedEntry] = []
    details: list[NtfsEntryDetails] = []
    for entry in entries:
        facts = facts_by_object_id.get(entry.object_id)
        if not isinstance(facts, Mapping):
            facts = None
        enriched, entry_details = enrich_ntfs_entry(entry, facts)
        enriched_entries.append(enriched)
        details.append(entry_details)

    primary_by_mft: dict[str, str] = {}
    for entry, entry_details in zip(enriched_entries, details):
        if entry_details.alternate_stream is None and entry_details.mft_reference is not None:
            primary_by_mft.setdefault(entry_details.mft_reference, entry.entry_id)

    for index, (entry, entry_details) in enumerate(zip(enriched_entries, details)):
        if entry_details.alternate_stream is None:
            continue
        parent_entry_id = primary_by_mft.get(entry_details.mft_reference or "")
        if parent_entry_id is None or parent_entry_id == entry.entry_id:
            enriched_entries[index] = replace(
                entry,
                warnings=tuple(dict.fromkeys((*entry.warnings, "ntfs_ads_parent_missing"))),
            )
            continue
        details[index] = replace(entry_details, ads_parent_entry_id=parent_entry_id)

    return tuple(enriched_entries), tuple(details)


def _object_identifiers(object_id: object) -> tuple[str | None, str | None]:
    if not isinstance(object_id, str):
        return None, None
    match = _OBJECT_ID.fullmatch(object_id)
    if match is None:
        return None, None
    return match.group("mft"), match.group("attribute")


def _recycle_original_path(
    entry: NormalizedEntry, facts: Mapping[str, Any], malformed: list[str]
) -> str | None:
    explicit = _optional_string(facts, "recycle_bin_original_path", malformed)
    if explicit is not None:
        return explicit
    parts = tuple(part for part in entry.display_path.replace("\\", "/").split("/") if part)
    recycle_bin = any(part.casefold() == "$recycle.bin" for part in parts)
    recycle_record = any(
        part.casefold().startswith(("$r", "$i")) and len(part) > 2 for part in parts
    )
    if recycle_bin and recycle_record:
        return "unknown_original_path"
    return None


def _is_metadata_file(display_path: str) -> bool:
    name = display_path.replace("\\", "/").rsplit("/", 1)[-1]
    base_name = name.split(":", 1)[0]
    return base_name.casefold() in _MFT_METADATA_NAMES_CASEFOLD


def _optional_bool(facts: Mapping[str, Any], key: str, malformed: list[str]) -> bool:
    if key not in facts or facts[key] is None:
        return False
    value = facts[key]
    if type(value) is not bool:
        malformed.append(key)
        return False
    return value


def _optional_strings(facts: Mapping[str, Any], key: str, malformed: list[str]) -> tuple[str, ...]:
    if key not in facts or facts[key] is None:
        return ()
    value = facts[key]
    if not isinstance(value, Sequence) or isinstance(value, str | bytes | bytearray):
        malformed.append(key)
        return ()
    cleaned: list[str] = []
    for item in value:
        if not isinstance(item, str):
            malformed.append(key)
            continue
        text = _string(item)
        if text is not None:
            cleaned.append(text)
    return tuple(dict.fromkeys(cleaned))


def _optional_string(facts: Mapping[str, Any], key: str, malformed: list[str]) -> str | None:
    if key not in facts or facts[key] is None:
        return None
    value = facts[key]
    if not isinstance(value, str):
        malformed.append(key)
        return None
    return _string(value)


def _string(value: object) -> str | None:
    if not isinstance(value, str):
        return None
    cleaned = " ".join(value.replace("\x00", "").split())
    return cleaned[:256] if cleaned else None
