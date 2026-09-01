"""FAT32 and exFAT entry normalization helpers."""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass

from scanner.entry_normalization import Extent, NormalizedEntry, RawTimestamp

SUPPORTED_FAT_FILESYSTEMS = frozenset({"fat12", "fat32", "exfat"})
END_OF_CHAIN = frozenset({*range(0xFF8, 0x1000), 0x0FFFFFF8, 0x0FFFFFFF, 0xFFFFFFFF})
BAD_CLUSTER = frozenset({0xFF7, 0x0FFFFFF7, 0xFFFFFFF7})


@dataclass(frozen=True)
class FatEntryDetails:
    filesystem: str
    short_name: str | None
    long_name: str | None
    volume_label: str | None
    first_cluster: int | None
    cluster_chain: tuple[int, ...]
    chain_status: str
    timezone_state: str
    warnings: tuple[str, ...] = ()


def enrich_fat_entry(
    entry: NormalizedEntry,
    *,
    filesystem: str,
    short_name: str | None = None,
    long_name: str | None = None,
    volume_label: str | None = None,
    first_cluster: int | None = None,
    cluster_chain: Sequence[int] = (),
    cluster_size_bytes: int = 4096,
    data_offset_bytes: int = 0,
    max_clusters: int = 4096,
    timestamp_fields: dict[str, str] | None = None,
) -> tuple[NormalizedEntry, FatEntryDetails]:
    """Return FAT/exFAT-aware metadata with explicit filesystem limitations."""

    if filesystem not in SUPPORTED_FAT_FILESYSTEMS:
        raise ValueError("unsupported FAT filesystem")
    warnings: list[str] = [*entry.warnings]
    attributes: list[str] = [*entry.attributes, filesystem]
    chain, chain_status, chain_warnings = normalize_cluster_chain(
        cluster_chain, max_clusters=max_clusters
    )
    warnings.extend(chain_warnings)
    if not entry.allocated:
        attributes.append("deleted_entry")
    if long_name and long_name != entry.display_name:
        attributes.append("fat_long_name")
    if short_name:
        attributes.append("fat_short_name")
    if volume_label:
        attributes.append("volume_label")
    if timestamp_fields:
        warnings.append("fat_timestamp_timezone_ambiguous")
    if chain_status != "empty":
        attributes.append(f"cluster_chain:{chain_status}")

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
        entry_type="virtual" if volume_label else entry.entry_type,
        attributes=tuple(dict.fromkeys(attributes)),
        owner_id=entry.owner_id,
        size_bytes=entry.size_bytes,
        allocated=entry.allocated,
        raw_timestamps=_fat_timestamps(timestamp_fields),
        extents=cluster_extents(chain, cluster_size_bytes, data_offset_bytes),
        alternate_stream=entry.alternate_stream,
        warnings=tuple(dict.fromkeys(warnings)),
    )
    detail_warnings = [*chain_warnings]
    if timestamp_fields:
        detail_warnings.append("fat_timestamp_timezone_ambiguous")
    details = FatEntryDetails(
        filesystem=filesystem,
        short_name=_clean_name(short_name),
        long_name=_clean_name(long_name),
        volume_label=_clean_name(volume_label),
        first_cluster=first_cluster,
        cluster_chain=chain,
        chain_status=chain_status,
        timezone_state="local_ambiguous" if timestamp_fields else "missing",
        warnings=tuple(dict.fromkeys(detail_warnings)),
    )
    return enriched, details


def normalize_cluster_chain(
    chain: Sequence[int], *, max_clusters: int
) -> tuple[tuple[int, ...], str, tuple[str, ...]]:
    if max_clusters <= 0:
        raise ValueError("max_clusters must be positive")
    normalized: list[int] = []
    warnings: list[str] = []
    seen: set[int] = set()
    for cluster in chain:
        if cluster in END_OF_CHAIN:
            return tuple(normalized), "complete", tuple(warnings)
        if cluster in BAD_CLUSTER or cluster < 2:
            warnings.append("fat_bad_cluster")
            return tuple(normalized), "corrupt", tuple(dict.fromkeys(warnings))
        if cluster in seen:
            warnings.append("fat_cluster_loop_bounded")
            return tuple(normalized), "corrupt", tuple(dict.fromkeys(warnings))
        if len(normalized) >= max_clusters:
            warnings.append("fat_cluster_chain_bounded")
            return tuple(normalized), "truncated", tuple(dict.fromkeys(warnings))
        seen.add(cluster)
        normalized.append(cluster)
    if not normalized:
        return (), "empty", ()
    return tuple(normalized), "complete", tuple(warnings)


def cluster_extents(
    chain: Sequence[int], cluster_size_bytes: int, data_offset_bytes: int
) -> tuple[Extent, ...]:
    if cluster_size_bytes <= 0 or data_offset_bytes < 0:
        raise ValueError("invalid FAT cluster geometry")
    return tuple(
        Extent(
            data_offset_bytes + (cluster - 2) * cluster_size_bytes,
            cluster_size_bytes,
        )
        for cluster in chain
    )


def _fat_timestamps(fields: dict[str, str] | None) -> dict[str, RawTimestamp]:
    if not fields:
        return {}
    return {name: RawTimestamp(value, "local_ambiguous") for name, value in fields.items()}


def _clean_name(value: str | None) -> str | None:
    if value is None:
        return None
    cleaned = " ".join(value.replace("\x00", "").split())
    return cleaned[:255] if cleaned else None
