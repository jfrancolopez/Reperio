"""Cross-platform Recycle Bin / Trash normalization (RPR-186).

Isolated parsers and locators for Windows ``$Recycle.Bin`` metadata/payload
pairs, macOS user and volume Trash layouts, and freedesktop ``files``/``info``
Trash layouts. Entries normalize platform/user, original path, deletion time,
metadata/payload link, and a recovery state that separates "currently in trash"
from "filesystem-deleted after the trash was emptied". Original paths are
treated as untrusted data: they are preserved for display but never used as
host output paths, and unsafe-looking values are flagged.
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from dataclasses import dataclass
from urllib.parse import unquote

PARSER_VERSION = "recycle-bin-v1"
PLATFORMS = frozenset({"windows", "macos", "freedesktop"})
RECOVERY_STATES = frozenset({"present", "deleted", "carved"})

WINDOWS_RECYCLE_DIR = "$Recycle.Bin"
MACOS_USER_TRASH = ".Trash"
MACOS_VOLUME_TRASH = ".Trashes"
FREEDESKTOP_TRASH_INFO_DIR = "info"
FREEDESKTOP_TRASH_FILES_DIR = "files"

TRASHINFO_SECTION_RE = re.compile(r"\[(Trash Info)\]")
TIMESTAMP_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}$")


class RecycleBinError(ValueError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


@dataclass(frozen=True)
class WindowsMeta:
    original_path: str
    size_bytes: int
    meta_version: int


@dataclass(frozen=True)
class WindowsPair:
    base_name: str
    metadata_ref: str | None
    payload_ref: str | None


@dataclass(frozen=True)
class TrashInfo:
    name: str
    original_path: str | None
    deletion_time: str | None
    warnings: tuple[str, ...] = ()


@dataclass(frozen=True)
class RecycleEntry:
    entry_id: str
    platform: str
    user: str
    volume: str
    original_path: str | None
    deletion_time: str | None
    metadata_ref: str | None
    payload_ref: str | None
    recovery_state: str
    warnings: tuple[str, ...] = ()
    parser_version: str = PARSER_VERSION


def parse_windows_i_file(data: bytes) -> WindowsMeta | None:
    """Parse a ``$I<name>`` metadata file (version 1 or 2).

    Returns ``None`` for headers that are too short or whose declared size is
    out of range. Path text is bounded to 520 bytes of UTF-16LE.
    """
    if len(data) < 24:
        return None
    version = _uint32(data, 0)
    if version == 1:
        size_bytes = _uint32(data, 4)
        path_bytes = data[8 : 8 + 520]
    elif version == 2:
        size_bytes = int.from_bytes(data[8:16], "little")
        path_length = _uint32(data, 16)
        path_bytes = data[20 : 20 + max(0, min(path_length, 520))]
    else:
        return None
    if size_bytes < 0:
        return None
    try:
        path = path_bytes.decode("utf-16-le", errors="replace").rstrip("\x00")
    except (UnicodeDecodeError, ValueError):
        return None
    if not path or len(path) > 260:
        return None
    return WindowsMeta(original_path=path, size_bytes=size_bytes, meta_version=version)


def pair_windows_entries(names: Iterable[str]) -> list[WindowsPair]:
    """Group ``$I``/``$R`` payload and metadata names into paired/orphan sets."""
    metadata: dict[str, str] = {}
    payload: dict[str, str] = {}
    for name in names:
        if name.startswith("$I") and len(name) > 2:
            metadata[name[2:]] = name
        elif name.startswith("$R") and len(name) > 2:
            payload[name[2:]] = name
    paired: dict[str, WindowsPair] = {}
    for base in sorted(set(metadata) | set(payload)):
        paired[base] = WindowsPair(
            base_name=base,
            metadata_ref=metadata.get(base),
            payload_ref=payload.get(base),
        )
    return [paired[base] for base in sorted(paired)]


def parse_trashinfo(text: str, *, name: str) -> TrashInfo:
    """Parse one freedesktop ``.trashinfo`` file.

    Missing or corrupt fields leave the entry visible with warnings instead of
    dropping it; the deletion time may be absent or uncertain.
    """
    warnings: list[str] = []
    original_path: str | None = None
    deletion_time: str | None = None
    if not text.startswith("[Trash Info]"):
        warnings.append("missing_trash_info_header")
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if line == "[Trash Info]":
            continue
        if "=" not in line:
            continue
        key, _, value = line.partition("=")
        key = key.strip()
        value = value.strip()
        if key == "Path":
            decoded = unquote(value)
            if "\x00" in decoded or ".." in decoded.split("/"):
                warnings.append("unsafe_original_path")
            original_path = decoded
        elif key == "DeletionDate":
            if TIMESTAMP_RE.fullmatch(value):
                deletion_time = value
            else:
                warnings.append("uncertain_deletion_time")
    if original_path is None:
        warnings.append("missing_original_path")
    return TrashInfo(
        name=name,
        original_path=original_path,
        deletion_time=deletion_time,
        warnings=tuple(warnings),
    )


def normalize_recycle_entry(
    *,
    entry_id: str,
    platform: str,
    user: str,
    volume: str,
    original_path: str | None,
    deletion_time: str | None,
    metadata_ref: str | None,
    payload_ref: str | None,
    payload_present: bool,
) -> RecycleEntry:
    """Normalize one trash item into a present/deleted/carved recovery state.

    - ``present``: metadata and payload are both in the trash now.
    - ``deleted``: metadata exists but the payload is gone (trash emptied).
    - ``carved``: payload exists without attributable metadata.
    """
    if platform not in PLATFORMS:
        raise RecycleBinError("unsupported_platform", f"platform {platform!r} is not supported")
    recovery_state = _recovery_state(metadata_ref, payload_ref, payload_present)
    if recovery_state is None:
        raise RecycleBinError("invalid_entry", "a trash entry needs metadata or a payload")
    warnings: list[str] = []
    if original_path is not None and _unsafe_path(original_path):
        warnings.append("unsafe_original_path")
    if deletion_time is not None and not TIMESTAMP_RE.fullmatch(deletion_time):
        warnings.append("uncertain_deletion_time")
    return RecycleEntry(
        entry_id=entry_id,
        platform=platform,
        user=user,
        volume=volume,
        original_path=original_path,
        deletion_time=deletion_time,
        metadata_ref=metadata_ref,
        payload_ref=payload_ref,
        recovery_state=recovery_state,
        warnings=tuple(warnings),
    )


def mark_carved_duplicate(entry: RecycleEntry, *, content_id: str) -> RecycleEntry:
    """Flag a carved payload that also matches a recovered copy elsewhere."""
    return RecycleEntry(
        entry_id=entry.entry_id,
        platform=entry.platform,
        user=entry.user,
        volume=entry.volume,
        original_path=entry.original_path,
        deletion_time=entry.deletion_time,
        metadata_ref=entry.metadata_ref,
        payload_ref=entry.payload_ref,
        recovery_state=entry.recovery_state,
        warnings=tuple(dict.fromkeys((*entry.warnings, f"carved_duplicate:{content_id}"))),
    )


def normalize_windows_pair(
    pair: WindowsPair,
    *,
    entry_id: str,
    sid: str,
    volume: str,
    original_path: str | None,
    size_bytes: int | None = None,
    deletion_time: str | None = None,
) -> RecycleEntry:
    return normalize_recycle_entry(
        entry_id=entry_id,
        platform="windows",
        user=sid,
        volume=volume,
        original_path=original_path,
        deletion_time=deletion_time,
        metadata_ref=pair.metadata_ref,
        payload_ref=pair.payload_ref,
        payload_present=pair.payload_ref is not None,
    )


def _recovery_state(
    metadata_ref: str | None, payload_ref: str | None, payload_present: bool
) -> str | None:
    if metadata_ref is not None and payload_ref is not None and payload_present:
        return "present"
    if metadata_ref is not None and not payload_present:
        return "deleted"
    if payload_ref is not None and payload_present:
        return "carved"
    return None


def _unsafe_path(path: str) -> bool:
    if "\x00" in path:
        return True
    normalized = path.replace("\\", "/")
    parts = [part for part in normalized.split("/") if part]
    return ".." in parts


def _uint32(data: bytes, offset: int) -> int:
    return (
        int.from_bytes(data[offset : offset + 4], "little", signed=False)
        if len(data) >= offset + 4
        else -1
    )
