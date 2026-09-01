"""Read-only mount, holder, and stacked-storage inspection for RPR-014."""

from __future__ import annotations

import posixpath
import re
from collections.abc import Iterable, Mapping
from pathlib import Path
from typing import Any

DEFAULT_MOUNTINFO = Path("/proc/self/mountinfo")
DEFAULT_SYS_DEV_BLOCK = Path("/sys/dev/block")
SUPPORTED_HOLDER_TYPES = frozenset({"device_mapper", "lvm", "mdraid"})
MAJOR_MINOR_RE = re.compile(r"^(0|[1-9][0-9]*):(0|[1-9][0-9]*)$")
SAFE_TYPE_RE = re.compile(r"^[a-z][a-z0-9_]{0,63}$")


def inspect_live_storage_state(
    device: Mapping[str, Any],
    *,
    mountinfo_path: Path = DEFAULT_MOUNTINFO,
    sys_dev_block: Path = DEFAULT_SYS_DEV_BLOCK,
) -> dict[str, Any]:
    """Gather Linux kernel facts read-only and evaluate the source storage state."""
    source_major_minors = _source_major_minors(device)
    mounts, mountinfo_available = _read_mountinfo(mountinfo_path)
    sysfs_available = sys_dev_block.is_dir()
    result = inspect_storage_state(
        device,
        mounts=mounts,
        holders=read_holder_graph(source_major_minors, sys_dev_block=sys_dev_block),
    )
    missing = []
    if not mountinfo_available:
        missing.append("mountinfo")
    if not sysfs_available:
        missing.append("sysfs")
    if missing:
        result["blockers"].append(
            {
                "reason": "storage_inspection_unavailable",
                "major_minor": "unknown",
                "detail": ",".join(missing),
            }
        )
        result["safe_for_preparation"] = False
        result["inspection_complete"] = False
    return result


def read_mountinfo(path: Path = DEFAULT_MOUNTINFO) -> list[dict[str, Any]]:
    """Read sanitized mount facts from Linux mountinfo without touching devices."""
    return _read_mountinfo(path)[0]


def _read_mountinfo(path: Path) -> tuple[list[dict[str, Any]], bool]:
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError:
        return [], False
    mounts: list[dict[str, Any]] = []
    for line in lines:
        fields = line.split()
        if len(fields) < 6 or "-" not in fields:
            continue
        separator = fields.index("-")
        if separator + 1 >= len(fields):
            continue
        major_minor = fields[2]
        mount_point = _unescape_mountinfo(fields[4])
        options = fields[5]
        fstype = _safe_fstype(fields[separator + 1])
        normalized = _normalize_mount(
            {"major_minor": major_minor, "mount_point": mount_point, "options": options}
        )
        if normalized is not None:
            mounts.append(
                {
                    "major_minor": normalized["major_minor"],
                    "mount_point": normalized["mount_point"],
                    "read_only": normalized["mode"] == "ro",
                    "fstype": fstype,
                }
            )
    return mounts, True


def read_holder_graph(
    source_major_minors: Iterable[str], *, sys_dev_block: Path = DEFAULT_SYS_DEV_BLOCK
) -> dict[str, list[dict[str, str]]]:
    """Read the transitive sysfs holder graph using metadata files only."""
    graph: dict[str, list[dict[str, str]]] = {}
    pending = [value for value in source_major_minors if _valid_major_minor(value)]
    visited: set[str] = set()
    while pending:
        parent = pending.pop()
        if parent in visited:
            continue
        visited.add(parent)
        try:
            entries = sorted((sys_dev_block / parent / "holders").iterdir(), key=lambda p: p.name)
        except OSError:
            continue
        for entry in entries:
            holder_major_minor = _read_text(entry / "dev")
            if holder_major_minor is None or not _valid_major_minor(holder_major_minor):
                continue
            graph.setdefault(parent, []).append(
                {
                    "major_minor": holder_major_minor,
                    "holder_type": _holder_type(entry.name),
                    "holder_name": _safe_name(entry.name),
                }
            )
            pending.append(holder_major_minor)
    return graph


def inspect_storage_state(
    device: Mapping[str, Any],
    *,
    mounts: Iterable[Mapping[str, Any]] = (),
    holders: Mapping[str, Iterable[Mapping[str, str]]] | None = None,
) -> dict[str, Any]:
    """Inspect source-related mounts and holders from sanitized fixture facts.

    ``mounts`` and ``holders`` are injected facts gathered by future hostd code.
    This function performs no mount, open, repair, or write operation.
    """
    source_major_minors = _source_major_minors(device)
    holder_graph = _normalize_holders(holders or {})
    related_major_minors = _with_descendants(source_major_minors, holder_graph)
    related_mounts: list[dict[str, str]] = []
    for mount in mounts:
        normalized_mount = _normalize_mount(mount)
        if normalized_mount is not None and normalized_mount["major_minor"] in related_major_minors:
            related_mounts.append(normalized_mount)
    related_holders = _related_holders(source_major_minors, holder_graph)

    blockers: list[dict[str, str]] = []
    if not source_major_minors:
        blockers.append(
            {
                "reason": "missing_source_topology",
                "major_minor": "unknown",
                "detail": "source has no valid major:minor identity",
            }
        )
    for mount in related_mounts:
        if mount["mode"] == "rw":
            blockers.append(
                {
                    "reason": "source_mounted_read_write",
                    "major_minor": mount["major_minor"],
                    "detail": mount["mount_point"],
                }
            )
    for holder in related_holders:
        if holder["holder_type"] not in SUPPORTED_HOLDER_TYPES:
            blockers.append(
                {
                    "reason": "unsupported_holder",
                    "major_minor": holder["major_minor"],
                    "detail": holder["holder_name"],
                }
            )

    return {
        "source_id": device.get("source_id"),
        "kernel_name": device.get("kernel_name"),
        "safe_for_preparation": not blockers,
        "blockers": blockers,
        "mounts": related_mounts,
        "holders": related_holders,
        "relationships": sorted(related_major_minors, key=_major_minor_key),
        "relationship_edges": _relationship_edges(device, related_holders),
        "inspection_complete": True,
    }


def _source_major_minors(device: Mapping[str, Any]) -> set[str]:
    values: set[str] = set()
    major_minor = device.get("major_minor")
    if isinstance(major_minor, str) and _valid_major_minor(major_minor):
        values.add(major_minor)
    children = device.get("children")
    if isinstance(children, list):
        for child in children:
            if isinstance(child, Mapping):
                child_major_minor = child.get("major_minor")
                if isinstance(child_major_minor, str) and _valid_major_minor(child_major_minor):
                    values.add(child_major_minor)
    return values


def _normalize_mount(mount: Mapping[str, Any]) -> dict[str, str] | None:
    major_minor = str(mount.get("major_minor", ""))
    mount_point = _normalize_path(str(mount.get("mount_point", "")))
    if not _valid_major_minor(major_minor) or mount_point is None:
        return None
    mode = _mount_mode(mount)
    return {"major_minor": major_minor, "mount_point": mount_point, "mode": mode}


def _mount_mode(mount: Mapping[str, Any]) -> str:
    options = mount.get("options")
    if isinstance(options, str):
        option_set = {option.strip() for option in options.split(",")}
    elif isinstance(options, list):
        option_set = {str(option).strip() for option in options}
    else:
        option_set = set()
    options_mode = "ro" if "ro" in option_set and "rw" not in option_set else "rw"
    read_only = mount.get("read_only")
    if read_only is True and "rw" not in option_set:
        return "ro"
    if read_only is False:
        return "rw"
    return options_mode


def _normalize_holders(
    holders: Mapping[str, Iterable[Mapping[str, str]]],
) -> dict[str, list[dict[str, str]]]:
    normalized: dict[str, list[dict[str, str]]] = {}
    for major_minor, records in holders.items():
        if not _valid_major_minor(major_minor):
            continue
        for record in records:
            holder_major_minor = str(record.get("major_minor", ""))
            if not _valid_major_minor(holder_major_minor):
                continue
            holder_type = _safe_type(str(record.get("holder_type", "unsupported")))
            holder_name = _safe_name(str(record.get("holder_name", holder_major_minor)))
            holder = {
                "major_minor": holder_major_minor,
                "holder_type": holder_type,
                "holder_name": holder_name,
                "parent_major_minor": major_minor,
            }
            existing = next(
                (
                    item
                    for item in normalized.get(major_minor, [])
                    if item["major_minor"] == holder_major_minor
                ),
                None,
            )
            if existing is not None:
                if existing != holder:
                    existing["holder_type"] = "unsupported"
                    existing["holder_name"] = "ambiguous-holder"
                continue
            normalized.setdefault(major_minor, []).append(holder)
    return normalized


def _with_descendants(
    source_major_minors: set[str], holders: Mapping[str, list[dict[str, str]]]
) -> set[str]:
    related = set(source_major_minors)
    pending = list(source_major_minors)
    while pending:
        current = pending.pop()
        for holder in holders.get(current, []):
            child = holder["major_minor"]
            if child not in related:
                related.add(child)
                pending.append(child)
    return related


def _related_holders(
    source_major_minors: set[str], holders: Mapping[str, list[dict[str, str]]]
) -> list[dict[str, str]]:
    related: list[dict[str, str]] = []
    pending = list(source_major_minors)
    seen_edges: set[tuple[str, str]] = set()
    while pending:
        current = pending.pop()
        for holder in holders.get(current, []):
            edge = (holder["parent_major_minor"], holder["major_minor"])
            if edge in seen_edges:
                continue
            seen_edges.add(edge)
            related.append(dict(holder))
            pending.append(holder["major_minor"])
    return sorted(
        related,
        key=lambda holder: (
            _major_minor_key(holder["parent_major_minor"]),
            _major_minor_key(holder["major_minor"]),
        ),
    )


def _safe_name(value: str) -> str:
    cleaned = " ".join(value.replace("\x00", "").split())
    if not cleaned or "/" in cleaned or ".." in cleaned:
        return "unsupported-holder"
    return cleaned[:128]


def _safe_type(value: str) -> str:
    return value if SAFE_TYPE_RE.fullmatch(value) is not None else "unsupported"


def _safe_fstype(value: str) -> str:
    lowered = value.lower()
    return lowered if re.fullmatch(r"^[a-z0-9][a-z0-9._-]{0,63}$", lowered) else "unknown"


def _normalize_path(value: str) -> str | None:
    if (
        not value.startswith("/")
        or len(value) > 4096
        or "\x00" in value
        or any(ord(char) < 32 for char in value)
    ):
        return None
    return posixpath.normpath(value)


def _unescape_mountinfo(value: str) -> str:
    replacements = {"\\040": " ", "\\011": "\t", "\\012": "\n", "\\134": "\\"}
    for escaped, decoded in replacements.items():
        value = value.replace(escaped, decoded)
    return value


def _holder_type(name: str) -> str:
    if name.startswith("dm-"):
        return "device_mapper"
    if name.startswith("md"):
        return "mdraid"
    return "unsupported"


def _read_text(path: Path) -> str | None:
    try:
        value = path.read_text(encoding="utf-8").strip()
    except OSError:
        return None
    return value or None


def _relationship_edges(
    device: Mapping[str, Any], holders: Iterable[Mapping[str, str]]
) -> list[dict[str, str]]:
    edges: list[dict[str, str]] = []
    parent = device.get("major_minor")
    children = device.get("children")
    if isinstance(parent, str) and _valid_major_minor(parent) and isinstance(children, list):
        for child in children:
            if not isinstance(child, Mapping):
                continue
            child_major_minor = child.get("major_minor")
            if isinstance(child_major_minor, str) and _valid_major_minor(child_major_minor):
                edges.append(
                    {
                        "parent_major_minor": parent,
                        "child_major_minor": child_major_minor,
                        "relationship_type": "partition",
                    }
                )
    for holder in holders:
        edges.append(
            {
                "parent_major_minor": holder["parent_major_minor"],
                "child_major_minor": holder["major_minor"],
                "relationship_type": holder["holder_type"],
            }
        )
    return edges


def _valid_major_minor(value: str) -> bool:
    return MAJOR_MINOR_RE.fullmatch(value) is not None


def _major_minor_key(value: str) -> tuple[int, int]:
    major, minor = value.split(":", 1)
    return int(major), int(minor)
