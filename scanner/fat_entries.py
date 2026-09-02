"""FAT32 and exFAT entry normalization helpers."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, replace

from scanner.entry_normalization import Extent, NormalizedEntry, RawTimestamp

SUPPORTED_FAT_FILESYSTEMS = frozenset({"fat12", "fat32", "exfat"})
END_OF_CHAIN = frozenset({*range(0xFF8, 0x1000), *range(0x0FFFFFF8, 0x10000000), 0xFFFFFFFF})
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

    if not isinstance(filesystem, str) or filesystem not in SUPPORTED_FAT_FILESYSTEMS:
        raise ValueError("unsupported FAT filesystem")
    warnings: list[str] = [*entry.warnings]
    attributes: list[str] = [*entry.attributes, filesystem]
    chain, chain_status, chain_warnings = normalize_cluster_chain(
        cluster_chain, max_clusters=max_clusters
    )
    warnings.extend(chain_warnings)
    clean_short_name = _clean_name(short_name)
    clean_long_name = _clean_name(long_name)
    clean_volume_label = _clean_name(volume_label)
    clean_first_cluster = _clean_first_cluster(first_cluster, warnings)
    clean_timestamps, timestamp_warnings = _clean_timestamps(timestamp_fields)
    warnings.extend(timestamp_warnings)
    if not entry.allocated:
        attributes.append("deleted_entry")
    if clean_long_name and clean_long_name != entry.display_name:
        attributes.append("fat_long_name")
    if clean_short_name:
        attributes.append("fat_short_name")
    if clean_volume_label:
        attributes.append("volume_label")
    if clean_timestamps:
        warnings.append("fat_timestamp_timezone_ambiguous")
    if chain_status != "empty":
        attributes.append(f"cluster_chain:{chain_status}")
    if _is_fragmented(chain):
        attributes.append("cluster_chain:fragmented")
        warnings.append("fat_cluster_chain_fragmented")
    extents = (
        ()
        if clean_volume_label
        else cluster_extents(
            chain,
            cluster_size_bytes,
            data_offset_bytes,
            size_bytes=entry.size_bytes,
        )
    )
    if (
        chain
        and entry.size_bytes is not None
        and sum(extent.length_bytes for extent in extents) != entry.size_bytes
    ):
        warnings.append("fat_extent_size_mismatch")
    raw_timestamps = {**entry.raw_timestamps, **_fat_timestamps(clean_timestamps)}
    timezone_state = _timezone_state(entry.raw_timestamps, clean_timestamps)

    enriched = replace(
        entry,
        display_path=_display_path_with_name(entry.display_path, clean_long_name),
        display_name=clean_long_name or entry.display_name,
        entry_type="virtual" if volume_label else entry.entry_type,
        attributes=tuple(dict.fromkeys(attributes)),
        raw_timestamps=raw_timestamps,
        extents=extents,
        warnings=tuple(dict.fromkeys(warnings)),
    )
    detail_warnings = [*chain_warnings, *timestamp_warnings]
    if clean_timestamps:
        detail_warnings.append("fat_timestamp_timezone_ambiguous")
    details = FatEntryDetails(
        filesystem=filesystem,
        short_name=clean_short_name,
        long_name=clean_long_name,
        volume_label=clean_volume_label,
        first_cluster=clean_first_cluster,
        cluster_chain=chain,
        chain_status=chain_status,
        timezone_state=timezone_state,
        warnings=tuple(dict.fromkeys(detail_warnings)),
    )
    return enriched, details


def normalize_cluster_chain(
    chain: Sequence[int], *, max_clusters: int
) -> tuple[tuple[int, ...], str, tuple[str, ...]]:
    if isinstance(max_clusters, bool) or not isinstance(max_clusters, int) or max_clusters <= 0:
        raise ValueError("max_clusters must be positive")
    if not isinstance(chain, Sequence) or isinstance(chain, str | bytes | bytearray):
        return (), "corrupt", ("fat_malformed_cluster_chain",)
    normalized: list[int] = []
    warnings: list[str] = []
    seen: set[int] = set()
    for cluster in chain:
        if type(cluster) is not int:
            warnings.append("fat_invalid_cluster")
            return tuple(normalized), "corrupt", tuple(dict.fromkeys(warnings))
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
    warnings.append("fat_chain_end_unknown")
    return tuple(normalized), "complete", tuple(dict.fromkeys(warnings))


def cluster_extents(
    chain: Sequence[int],
    cluster_size_bytes: int,
    data_offset_bytes: int,
    *,
    size_bytes: int | None = None,
) -> tuple[Extent, ...]:
    if (
        isinstance(cluster_size_bytes, bool)
        or not isinstance(cluster_size_bytes, int)
        or cluster_size_bytes <= 0
        or isinstance(data_offset_bytes, bool)
        or not isinstance(data_offset_bytes, int)
        or data_offset_bytes < 0
        or (
            size_bytes is not None
            and (isinstance(size_bytes, bool) or not isinstance(size_bytes, int) or size_bytes < 0)
        )
    ):
        raise ValueError("invalid FAT cluster geometry")
    extents: list[Extent] = []
    remaining = size_bytes
    for cluster in chain:
        if type(cluster) is not int or cluster < 2:
            raise ValueError("invalid FAT cluster")
        if remaining == 0:
            break
        length = cluster_size_bytes if remaining is None else min(cluster_size_bytes, remaining)
        extents.append(Extent(data_offset_bytes + (cluster - 2) * cluster_size_bytes, length))
        if remaining is not None:
            remaining -= length
    return tuple(extents)


def _fat_timestamps(fields: Mapping[str, str] | None) -> dict[str, RawTimestamp]:
    if not fields:
        return {}
    return {name: RawTimestamp(value, "local_ambiguous") for name, value in fields.items()}


def _clean_first_cluster(value: object, warnings: list[str]) -> int | None:
    if value is None:
        return None
    if type(value) is not int or value < 0:
        warnings.append("fat_invalid_first_cluster")
        return None
    return value


def _clean_timestamps(
    fields: object,
) -> tuple[dict[str, str], tuple[str, ...]]:
    if fields is None:
        return {}, ()
    if not isinstance(fields, Mapping):
        return {}, ("fat_malformed_timestamp_fields",)
    cleaned: dict[str, str] = {}
    warnings: list[str] = []
    for name, value in fields.items():
        if not isinstance(name, str) or not isinstance(value, str):
            warnings.append("fat_malformed_timestamp_fields")
            continue
        cleaned[name] = value
    return cleaned, tuple(dict.fromkeys(warnings))


def _timezone_state(existing: Mapping[str, RawTimestamp], fields: Mapping[str, str]) -> str:
    if fields:
        return "local_ambiguous"
    for timestamp in existing.values():
        return timestamp.timezone_state
    return "missing"


def _is_fragmented(chain: Sequence[int]) -> bool:
    return any(current != previous + 1 for previous, current in zip(chain, chain[1:]))


def _display_path_with_name(path: str, name: str | None) -> str:
    if name is None:
        return path
    if "/" not in path:
        return name
    return f"{path.rsplit('/', 1)[0]}/{name}"


def _clean_name(value: str | None) -> str | None:
    if value is None:
        return None
    cleaned = " ".join(value.replace("\x00", "").split())
    return cleaned[:255] if cleaned else None
