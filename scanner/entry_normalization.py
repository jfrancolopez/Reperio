"""Canonical filesystem entry and path normalization models."""

from __future__ import annotations

import hashlib
import unicodedata
from dataclasses import dataclass

from scanner.filesystem_enumeration import FilesystemEntry

VALID_ENTRY_TYPES = frozenset({"file", "directory", "symlink", "virtual", "unknown", "deleted"})


class EntryNormalizationError(ValueError):
    """Raised when an enumerated entry cannot be represented safely."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


@dataclass(frozen=True)
class RawTimestamp:
    value: str | None
    timezone_state: str


@dataclass(frozen=True)
class Extent:
    offset_bytes: int
    length_bytes: int
    sparse: bool = False


@dataclass(frozen=True)
class NormalizedEntry:
    entry_id: str
    volume_id: str
    object_id: str
    parent_object_id: str | None
    parent_entry_id: str | None
    raw_path_bytes: bytes
    display_path: str
    raw_name_bytes: bytes
    display_name: str
    entry_type: str
    attributes: tuple[str, ...]
    owner_id: str | None
    size_bytes: int | None
    allocated: bool
    raw_timestamps: dict[str, RawTimestamp]
    extents: tuple[Extent, ...]
    alternate_stream: str | None
    warnings: tuple[str, ...] = ()


def normalize_entries(entries: tuple[FilesystemEntry, ...]) -> tuple[NormalizedEntry, ...]:
    """Normalize an enumeration batch without interpreting paths on the host."""

    normalized: list[NormalizedEntry] = []
    object_to_entry_id: dict[str, str] = {}
    seen_sibling_names: set[tuple[str | None, bytes]] = set()
    for entry in entries:
        parent_entry_id = object_to_entry_id.get(entry.parent_object_id or "")
        normalized_entry = normalize_entry(
            entry,
            parent_entry_id=parent_entry_id,
            duplicate_name=(entry.parent_object_id, _encode_path(entry.name)) in seen_sibling_names,
            orphan_parent=entry.parent_object_id is not None and parent_entry_id is None,
        )
        normalized.append(normalized_entry)
        object_to_entry_id[entry.object_id] = normalized_entry.entry_id
        seen_sibling_names.add((entry.parent_object_id, normalized_entry.raw_name_bytes))
    return tuple(normalized)


def normalize_entry(
    entry: FilesystemEntry,
    *,
    parent_entry_id: str | None = None,
    duplicate_name: bool = False,
    orphan_parent: bool = False,
    raw_timestamps: dict[str, RawTimestamp] | None = None,
    extents: tuple[Extent, ...] = (),
    owner_id: str | None = None,
    size_bytes: int | None = None,
    attributes: tuple[str, ...] = (),
) -> NormalizedEntry:
    """Normalize one entry while preserving hostile byte/path content."""

    if entry.entry_type not in VALID_ENTRY_TYPES:
        raise EntryNormalizationError("invalid_entry_type", "entry type is not supported")
    if size_bytes is not None and size_bytes < 0:
        raise EntryNormalizationError("invalid_size", "entry size must not be negative")
    for extent in extents:
        if extent.offset_bytes < 0 or extent.length_bytes < 0:
            raise EntryNormalizationError("invalid_extent", "extent values must not be negative")

    raw_path_bytes = _encode_path(entry.path)
    raw_name_bytes = _encode_path(entry.name)
    display_path, path_warnings = _display_path(raw_path_bytes)
    display_name, name_warnings = _display_path(raw_name_bytes)
    alternate_stream = _alternate_stream(display_name)
    warnings = [*path_warnings, *name_warnings]
    if duplicate_name:
        warnings.append("duplicate_sibling_name")
    if orphan_parent:
        warnings.append("orphan_parent")
    if _has_traversal_segment(raw_path_bytes):
        warnings.append("path_traversal_segment")
    if alternate_stream is not None:
        warnings.append("alternate_stream")

    return NormalizedEntry(
        entry_id=entry.entry_id
        or _stable_entry_id(entry.volume_id, entry.object_id, raw_path_bytes),
        volume_id=entry.volume_id,
        object_id=entry.object_id,
        parent_object_id=entry.parent_object_id,
        parent_entry_id=parent_entry_id,
        raw_path_bytes=raw_path_bytes,
        display_path=display_path,
        raw_name_bytes=raw_name_bytes,
        display_name=display_name,
        entry_type="deleted"
        if not entry.allocated and entry.entry_type == "file"
        else entry.entry_type,
        attributes=tuple(dict.fromkeys(attributes)),
        owner_id=owner_id,
        size_bytes=size_bytes,
        allocated=entry.allocated,
        raw_timestamps=dict(raw_timestamps or {}),
        extents=extents,
        alternate_stream=alternate_stream,
        warnings=tuple(dict.fromkeys(warnings)),
    )


def raw_entry(
    *,
    volume_id: str,
    object_id: str,
    path_bytes: bytes,
    entry_type: str = "file",
    parent_object_id: str | None = None,
    allocated: bool = True,
) -> FilesystemEntry:
    """Build an enumerated entry from arbitrary bytes for fixture/property tests."""

    display = path_bytes.decode("utf-8", errors="surrogateescape")
    name = display.rsplit("/", 1)[-1]
    return FilesystemEntry(
        volume_id=volume_id,
        object_id=object_id,
        parent_object_id=parent_object_id,
        entry_id=_stable_entry_id(volume_id, object_id, path_bytes),
        name=name,
        entry_type=entry_type,
        allocated=allocated,
        path=display,
    )


def _encode_path(value: str) -> bytes:
    return unicodedata.normalize("NFC", value).encode("utf-8", errors="surrogateescape")


def _display_path(value: bytes) -> tuple[str, tuple[str, ...]]:
    warnings: list[str] = []
    decoded = value.decode("utf-8", errors="replace")
    if "\ufffd" in decoded:
        warnings.append("invalid_unicode")
    if "\x00" in decoded:
        warnings.append("nul_byte")
        decoded = decoded.replace("\x00", "\\0")
    return decoded, tuple(warnings)


def _alternate_stream(display_name: str) -> str | None:
    if ":" not in display_name:
        return None
    base, stream = display_name.split(":", 1)
    if base and stream:
        return stream
    return None


def _has_traversal_segment(path_bytes: bytes) -> bool:
    return any(segment == b".." for segment in path_bytes.replace(b"\\", b"/").split(b"/"))


def _stable_entry_id(volume_id: str, object_id: str, path_bytes: bytes) -> str:
    digest = hashlib.sha256(
        b"\0".join((volume_id.encode(), object_id.encode(), path_bytes))
    ).hexdigest()
    return f"entry-{digest[:32]}"
