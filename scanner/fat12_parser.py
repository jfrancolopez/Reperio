"""Read-only DOS FAT12 floppy enumeration and deleted-file recovery planning."""

from __future__ import annotations

import struct
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import datetime
from typing import Protocol

from scanner.entry_normalization import Extent
from scanner.photorec_carving import CarveRange

FAT12_EOC_MIN = 0xFF8
FAT12_BAD_CLUSTER = 0xFF7
FAT12_RESERVED_MIN = 0xFF0
FAT12_MAX_CLUSTER = 0xFEF
DIRECTORY_ENTRY_SIZE = 32


class Fat12Error(ValueError):
    """Raised when a source cannot be represented as a supported DOS FAT12 floppy."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


class Fat12Reader(Protocol):
    """Small read-only range interface supplied by the scanner source boundary."""

    def read_at(self, offset_bytes: int, length_bytes: int) -> bytes: ...


@dataclass(frozen=True)
class Fat12Geometry:
    label: str
    total_sectors: int
    sectors_per_cluster: int
    root_entries: int
    sectors_per_fat: int
    sectors_per_track: int
    heads: int
    cylinders: int
    media_descriptor: int
    bytes_per_sector: int = 512
    reserved_sectors: int = 1
    fat_count: int = 2

    @property
    def size_bytes(self) -> int:
        return self.total_sectors * self.bytes_per_sector

    @property
    def root_directory_sectors(self) -> int:
        size = self.root_entries * DIRECTORY_ENTRY_SIZE
        return (size + self.bytes_per_sector - 1) // self.bytes_per_sector

    @property
    def first_data_sector(self) -> int:
        return (
            self.reserved_sectors
            + self.fat_count * self.sectors_per_fat
            + self.root_directory_sectors
        )

    @property
    def cluster_count(self) -> int:
        return (self.total_sectors - self.first_data_sector) // self.sectors_per_cluster


SUPPORTED_GEOMETRIES = (
    Fat12Geometry("360 KiB", 720, 2, 112, 2, 9, 2, 40, 0xFD),
    Fat12Geometry("720 KiB", 1440, 2, 112, 3, 9, 2, 80, 0xF9),
    Fat12Geometry("1.2 MiB", 2400, 1, 224, 7, 15, 2, 80, 0xF9),
    Fat12Geometry("1.44 MiB", 2880, 1, 224, 9, 18, 2, 80, 0xF0),
)


@dataclass(frozen=True)
class Fat12Entry:
    entry_index: int
    name: str
    short_name: str
    raw_short_name: bytes
    entry_type: str
    attributes: tuple[str, ...]
    allocated: bool
    size_bytes: int
    first_cluster: int | None
    cluster_chain: tuple[int, ...]
    chain_confidence: str
    recovery_state: str
    timestamps: tuple[tuple[str, str], ...]
    extents: tuple[Extent, ...]
    warnings: tuple[str, ...] = ()


@dataclass(frozen=True)
class Fat12ScanResult:
    geometry: Fat12Geometry
    entries: tuple[Fat12Entry, ...]
    carve_ranges: tuple[CarveRange, ...]
    unreadable_sectors: tuple[int, ...]
    warnings: tuple[str, ...] = ()


@dataclass
class _ReadState:
    reader: Fat12Reader
    known_bad_sectors: set[int]
    unreadable_sectors: set[int]

    def read_sectors(self, start_sector: int, count: int, sector_size: int) -> bytes:
        chunks: list[bytes] = []
        for sector in range(start_sector, start_sector + count):
            if sector in self.known_bad_sectors:
                self.unreadable_sectors.add(sector)
                chunks.append(bytes(sector_size))
                continue
            try:
                data = self.reader.read_at(sector * sector_size, sector_size)
            except OSError:
                data = b""
            if len(data) != sector_size:
                self.unreadable_sectors.add(sector)
                data = data[:sector_size].ljust(sector_size, b"\x00")
            chunks.append(data)
        return b"".join(chunks)


def scan_fat12(
    reader: Fat12Reader,
    *,
    source_size_bytes: int,
    known_bad_sectors: Iterable[int] = (),
) -> Fat12ScanResult:
    """Enumerate a supported FAT12 superfloppy without mounting or writing it."""

    if source_size_bytes < 512:
        raise Fat12Error("source_too_small", "source is too small for a DOS FAT boot sector")
    try:
        boot = reader.read_at(0, 512)
    except OSError as error:
        raise Fat12Error("boot_sector_unreadable", "FAT12 boot sector could not be read") from error
    if len(boot) != 512:
        raise Fat12Error("boot_sector_unreadable", "FAT12 boot sector was truncated")

    geometry = detect_geometry(boot, source_size_bytes=source_size_bytes)
    bad_sectors = set(known_bad_sectors)
    state = _ReadState(reader, bad_sectors, set(bad_sectors))
    fats = _read_fat_copies(state, geometry)
    fat, fat_warnings = _select_fat(fats, geometry)

    root_start = geometry.reserved_sectors + geometry.fat_count * geometry.sectors_per_fat
    root = state.read_sectors(
        root_start, geometry.root_directory_sectors, geometry.bytes_per_sector
    )
    entries = _parse_root_directory(root, geometry, fat, state.unreadable_sectors)
    carve_ranges = _free_cluster_ranges(fat, geometry, state.unreadable_sectors)

    warnings = list(fat_warnings)
    if any(
        root_start <= sector < root_start + geometry.root_directory_sectors
        for sector in state.unreadable_sectors
    ):
        warnings.append("root_directory_read_gap")
    if state.unreadable_sectors:
        warnings.append("source_read_gaps")
    return Fat12ScanResult(
        geometry=geometry,
        entries=entries,
        carve_ranges=carve_ranges,
        unreadable_sectors=tuple(sorted(state.unreadable_sectors)),
        warnings=tuple(dict.fromkeys(warnings)),
    )


def detect_geometry(boot: bytes, *, source_size_bytes: int) -> Fat12Geometry:
    """Require a valid DOS BPB that exactly matches one advertised geometry."""

    if len(boot) < 512:
        raise Fat12Error("boot_sector_unreadable", "FAT12 boot sector was truncated")
    if boot[0] not in {0xE9, 0xEB} or boot[510:512] != b"\x55\xaa":
        raise Fat12Error("non_dos_signature", "source lacks a supported DOS boot signature")
    if boot[54:62].rstrip(b" \x00").upper() != b"FAT12":
        raise Fat12Error("non_dos_signature", "source does not identify as DOS FAT12")

    total_sectors_16 = struct.unpack_from("<H", boot, 19)[0]
    total_sectors_32 = struct.unpack_from("<I", boot, 32)[0]
    total_sectors = total_sectors_16 or total_sectors_32
    fields = {
        "bytes_per_sector": struct.unpack_from("<H", boot, 11)[0],
        "sectors_per_cluster": boot[13],
        "reserved_sectors": struct.unpack_from("<H", boot, 14)[0],
        "fat_count": boot[16],
        "root_entries": struct.unpack_from("<H", boot, 17)[0],
        "total_sectors": total_sectors,
        "media_descriptor": boot[21],
        "sectors_per_fat": struct.unpack_from("<H", boot, 22)[0],
        "sectors_per_track": struct.unpack_from("<H", boot, 24)[0],
        "heads": struct.unpack_from("<H", boot, 26)[0],
    }
    candidates = [
        geometry for geometry in SUPPORTED_GEOMETRIES if geometry.size_bytes == source_size_bytes
    ]
    if not candidates:
        raise Fat12Error(
            "unsupported_geometry", "source capacity is not an advertised FAT12 floppy geometry"
        )
    matches = [geometry for geometry in candidates if _geometry_matches(geometry, fields)]
    if len(matches) != 1:
        raise Fat12Error(
            "ambiguous_geometry",
            "boot geometry does not exactly match the supported capacity; geometry was not guessed",
        )
    geometry = matches[0]
    if geometry.cluster_count >= 4085:
        raise Fat12Error("not_fat12", "BPB cluster count exceeds FAT12 limits")
    return geometry


def _geometry_matches(geometry: Fat12Geometry, fields: dict[str, int]) -> bool:
    return all(
        fields[name] == getattr(geometry, name)
        for name in (
            "bytes_per_sector",
            "sectors_per_cluster",
            "reserved_sectors",
            "fat_count",
            "root_entries",
            "total_sectors",
            "media_descriptor",
            "sectors_per_fat",
            "sectors_per_track",
            "heads",
        )
    )


def _read_fat_copies(state: _ReadState, geometry: Fat12Geometry) -> tuple[bytes, ...]:
    copies: list[bytes] = []
    for index in range(geometry.fat_count):
        start = geometry.reserved_sectors + index * geometry.sectors_per_fat
        copies.append(
            state.read_sectors(start, geometry.sectors_per_fat, geometry.bytes_per_sector)
        )
    return tuple(copies)


def _select_fat(
    copies: tuple[bytes, ...], geometry: Fat12Geometry
) -> tuple[tuple[int, ...], tuple[str, ...]]:
    decoded = tuple(_decode_fat(copy, geometry.cluster_count + 2) for copy in copies)
    valid = [fat for fat in decoded if _fat_header_valid(fat, geometry.media_descriptor)]
    if not valid:
        return tuple(0 for _ in range(geometry.cluster_count + 2)), ("fat_copies_corrupt",)
    warnings: list[str] = []
    if len(valid) != len(decoded):
        warnings.append("fat_copy_corrupt")
    if any(fat != valid[0] for fat in valid[1:]):
        warnings.append("fat_copies_disagree")
    return valid[0], tuple(warnings)


def _decode_fat(raw: bytes, count: int) -> tuple[int, ...]:
    values: list[int] = []
    for index in range(count):
        offset = index + index // 2
        if offset + 1 >= len(raw):
            values.append(0)
            continue
        word = raw[offset] | (raw[offset + 1] << 8)
        values.append((word >> 4) & 0xFFF if index & 1 else word & 0xFFF)
    return tuple(values)


def _fat_header_valid(fat: tuple[int, ...], media_descriptor: int) -> bool:
    return len(fat) >= 2 and fat[0] == 0xF00 | media_descriptor and fat[1] >= FAT12_EOC_MIN


def _parse_root_directory(
    root: bytes,
    geometry: Fat12Geometry,
    fat: tuple[int, ...],
    unreadable_sectors: set[int],
) -> tuple[Fat12Entry, ...]:
    entries: list[Fat12Entry] = []
    pending_lfn: list[bytes] = []
    for index in range(geometry.root_entries):
        raw = root[index * DIRECTORY_ENTRY_SIZE : (index + 1) * DIRECTORY_ENTRY_SIZE]
        if len(raw) != DIRECTORY_ENTRY_SIZE or raw[0] == 0x00:
            break
        attributes = raw[11]
        if attributes == 0x0F:
            pending_lfn.append(raw)
            continue
        if attributes & 0x08:
            pending_lfn.clear()
            continue

        deleted = raw[0] == 0xE5
        short_name = _decode_short_name(raw[0:11], deleted=deleted)
        long_name, lfn_warning = _decode_lfn(pending_lfn, raw[0:11], deleted=deleted)
        pending_lfn.clear()
        name = long_name or short_name
        first_cluster = struct.unpack_from("<H", raw, 26)[0]
        size_bytes = struct.unpack_from("<I", raw, 28)[0]
        warnings: list[str] = []
        if lfn_warning:
            warnings.append(lfn_warning)

        if deleted:
            chain, confidence, recovery_state, chain_warnings = _deleted_chain(
                first_cluster, size_bytes, fat, geometry
            )
        else:
            chain, confidence, recovery_state, chain_warnings = _allocated_chain(
                first_cluster, size_bytes, fat, geometry
            )
        warnings.extend(chain_warnings)
        extents = _cluster_extents(chain, geometry)
        if _chain_has_bad_sector(chain, geometry, unreadable_sectors):
            warnings.append("fat12_bad_sector_in_content")
            recovery_state = "partial_bad_sector"
            confidence = "low"

        entries.append(
            Fat12Entry(
                entry_index=index,
                name=name,
                short_name=short_name,
                raw_short_name=bytes(raw[0:11]),
                entry_type="directory" if attributes & 0x10 else "file",
                attributes=_attribute_names(attributes),
                allocated=not deleted,
                size_bytes=size_bytes,
                first_cluster=first_cluster if first_cluster >= 2 else None,
                cluster_chain=chain,
                chain_confidence=confidence,
                recovery_state=recovery_state,
                timestamps=_timestamps(raw),
                extents=extents,
                warnings=tuple(dict.fromkeys(warnings)),
            )
        )
    return tuple(entries)


def _allocated_chain(
    first_cluster: int,
    size_bytes: int,
    fat: tuple[int, ...],
    geometry: Fat12Geometry,
) -> tuple[tuple[int, ...], str, str, tuple[str, ...]]:
    if size_bytes == 0 and first_cluster < 2:
        return (), "certain", "allocated_intact", ()
    if first_cluster < 2 or first_cluster >= len(fat):
        return (), "low", "partial", ("fat12_missing_first_cluster",)
    chain: list[int] = []
    seen: set[int] = set()
    cursor = first_cluster
    warnings: list[str] = []
    status = "allocated_intact"
    while 2 <= cursor < len(fat) and len(chain) <= geometry.cluster_count:
        if cursor in seen:
            warnings.append("fat12_cluster_loop")
            status = "partial"
            break
        chain.append(cursor)
        seen.add(cursor)
        next_cluster = fat[cursor]
        if next_cluster >= FAT12_EOC_MIN:
            break
        if next_cluster == FAT12_BAD_CLUSTER:
            warnings.append("fat12_bad_cluster_marker")
            status = "partial_bad_sector"
            break
        if next_cluster == 0:
            warnings.append("fat12_chain_terminated_free")
            status = "partial"
            break
        if next_cluster >= FAT12_RESERVED_MIN or next_cluster < 2:
            warnings.append("fat12_reserved_cluster_marker")
            status = "partial"
            break
        cursor = next_cluster
    expected = _clusters_for_size(size_bytes, geometry)
    if len(chain) < expected:
        warnings.append("fat12_cluster_chain_short")
        status = "partial"
    elif len(chain) > expected and expected > 0:
        chain = chain[:expected]
        warnings.append("fat12_cluster_chain_long")
    if status == "allocated_intact" and any(
        current != previous + 1 for previous, current in zip(chain, chain[1:])
    ):
        warnings.append("fat12_fragmented_chain")
        status = "allocated_fragmented"
    confidence = "certain" if status == "allocated_intact" and not warnings else "high"
    if status.startswith("partial"):
        confidence = "low"
    return tuple(chain), confidence, status, tuple(warnings)


def _deleted_chain(
    first_cluster: int,
    size_bytes: int,
    fat: tuple[int, ...],
    geometry: Fat12Geometry,
) -> tuple[tuple[int, ...], str, str, tuple[str, ...]]:
    count = _clusters_for_size(size_bytes, geometry)
    if first_cluster < 2 or count == 0:
        return (), "unknown", "deleted_metadata_only", ("fat12_deleted_chain_missing",)
    candidate = tuple(range(first_cluster, first_cluster + count))
    if candidate[-1] >= len(fat):
        return (), "low", "deleted_partial", ("fat12_deleted_chain_out_of_range",)
    if any(fat[cluster] != 0 for cluster in candidate):
        return (), "low", "deleted_reused", ("fat12_deleted_cluster_reused",)
    warnings = ["fat12_deleted_chain_inferred_contiguous"]
    if count > 1:
        warnings.append("fat12_deleted_fragmentation_unknown")
    return candidate, "medium", "deleted_contiguous_candidate", tuple(warnings)


def _clusters_for_size(size_bytes: int, geometry: Fat12Geometry) -> int:
    cluster_size = geometry.sectors_per_cluster * geometry.bytes_per_sector
    return (size_bytes + cluster_size - 1) // cluster_size if size_bytes else 0


def _cluster_extents(chain: tuple[int, ...], geometry: Fat12Geometry) -> tuple[Extent, ...]:
    cluster_size = geometry.sectors_per_cluster * geometry.bytes_per_sector
    return tuple(
        Extent(
            (geometry.first_data_sector + (cluster - 2) * geometry.sectors_per_cluster)
            * geometry.bytes_per_sector,
            cluster_size,
        )
        for cluster in chain
    )


def _chain_has_bad_sector(
    chain: tuple[int, ...], geometry: Fat12Geometry, unreadable_sectors: set[int]
) -> bool:
    for cluster in chain:
        start = geometry.first_data_sector + (cluster - 2) * geometry.sectors_per_cluster
        if any(
            sector in unreadable_sectors
            for sector in range(start, start + geometry.sectors_per_cluster)
        ):
            return True
    return False


def _free_cluster_ranges(
    fat: tuple[int, ...], geometry: Fat12Geometry, unreadable_sectors: set[int]
) -> tuple[CarveRange, ...]:
    readable_sectors: list[int] = []
    for cluster in range(2, min(len(fat), geometry.cluster_count + 2)):
        if fat[cluster] != 0:
            continue
        first = geometry.first_data_sector + (cluster - 2) * geometry.sectors_per_cluster
        readable_sectors.extend(
            sector
            for sector in range(first, first + geometry.sectors_per_cluster)
            if sector not in unreadable_sectors
        )
    if not readable_sectors:
        return ()
    ranges: list[CarveRange] = []
    start = previous = readable_sectors[0]
    for sector in readable_sectors[1:]:
        if sector != previous + 1:
            ranges.append(_sector_range(start, previous, geometry.bytes_per_sector))
            start = sector
        previous = sector
    ranges.append(_sector_range(start, previous, geometry.bytes_per_sector))
    return tuple(ranges)


def _sector_range(first: int, last: int, sector_size: int) -> CarveRange:
    return CarveRange(first * sector_size, (last - first + 1) * sector_size)


def _decode_short_name(raw: bytes, *, deleted: bool) -> str:
    name = bytearray(raw[:8])
    if deleted:
        name[0] = ord("?")
    base = bytes(name).rstrip(b" ").decode("latin-1", errors="replace") or "?"
    extension = raw[8:11].rstrip(b" ").decode("latin-1", errors="replace")
    return f"{base}.{extension}" if extension else base


def _decode_lfn(
    entries: list[bytes], short_name: bytes, *, deleted: bool
) -> tuple[str | None, str | None]:
    if not entries or deleted:
        return None, None
    expected_checksum = _lfn_checksum(short_name)
    ordered: dict[int, list[int]] = {}
    expected_count: int | None = None
    for raw in entries:
        order = raw[0]
        sequence = order & 0x1F
        if order & 0x40:
            expected_count = sequence
        if sequence == 0 or raw[13] != expected_checksum:
            return None, "fat12_lfn_invalid"
        units_raw = raw[1:11] + raw[14:26] + raw[28:32]
        ordered[sequence] = [
            struct.unpack_from("<H", units_raw, offset)[0] for offset in range(0, len(units_raw), 2)
        ]
    if expected_count is None or set(ordered) != set(range(1, expected_count + 1)):
        return None, "fat12_lfn_invalid"
    units = [unit for index in range(1, expected_count + 1) for unit in ordered[index]]
    units = [unit for unit in units if unit not in {0x0000, 0xFFFF}]
    try:
        return b"".join(struct.pack("<H", unit) for unit in units).decode("utf-16le"), None
    except UnicodeDecodeError:
        return None, "fat12_lfn_invalid"


def _lfn_checksum(short_name: bytes) -> int:
    checksum = 0
    for value in short_name:
        checksum = (((checksum & 1) << 7) | (checksum >> 1)) + value
        checksum &= 0xFF
    return checksum


def _attribute_names(value: int) -> tuple[str, ...]:
    names = (
        (0x01, "read_only"),
        (0x02, "hidden"),
        (0x04, "system"),
        (0x10, "directory"),
        (0x20, "archive"),
    )
    return tuple(name for bit, name in names if value & bit)


def _timestamps(raw: bytes) -> tuple[tuple[str, str], ...]:
    values = (
        ("created", struct.unpack_from("<H", raw, 16)[0], struct.unpack_from("<H", raw, 14)[0]),
        ("accessed", struct.unpack_from("<H", raw, 18)[0], None),
        ("modified", struct.unpack_from("<H", raw, 24)[0], struct.unpack_from("<H", raw, 22)[0]),
    )
    parsed: list[tuple[str, str]] = []
    for name, date_bits, time_bits in values:
        value = _fat_datetime(date_bits, time_bits)
        if value is not None:
            parsed.append((name, value))
    return tuple(parsed)


def _fat_datetime(date_bits: int, time_bits: int | None) -> str | None:
    day = date_bits & 0x1F
    month = (date_bits >> 5) & 0x0F
    year = 1980 + ((date_bits >> 9) & 0x7F)
    if day == 0 or month == 0:
        return None
    hour = minute = second = 0
    if time_bits is not None:
        second = (time_bits & 0x1F) * 2
        minute = (time_bits >> 5) & 0x3F
        hour = (time_bits >> 11) & 0x1F
    try:
        return datetime(year, month, day, hour, minute, second).isoformat()
    except ValueError:
        return None
