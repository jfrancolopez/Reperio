"""Read-only mount, holder, and stacked-storage inspection for RPR-014."""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from typing import Any

SUPPORTED_HOLDER_TYPES = frozenset({"device_mapper", "mdraid"})


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
        "relationships": sorted(related_major_minors),
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
    mount_point = str(mount.get("mount_point", ""))
    if not _valid_major_minor(major_minor) or not mount_point.startswith("/"):
        return None
    mode = _mount_mode(mount)
    return {"major_minor": major_minor, "mount_point": mount_point, "mode": mode}


def _mount_mode(mount: Mapping[str, Any]) -> str:
    if mount.get("read_only") is True:
        return "ro"
    if mount.get("read_only") is False:
        return "rw"
    options = mount.get("options")
    if isinstance(options, str):
        option_set = {option.strip() for option in options.split(",")}
    elif isinstance(options, list):
        option_set = {str(option).strip() for option in options}
    else:
        option_set = set()
    return "ro" if "ro" in option_set and "rw" not in option_set else "rw"


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
            holder_type = str(record.get("holder_type", "unsupported"))
            holder_name = _safe_name(str(record.get("holder_name", holder_major_minor)))
            normalized.setdefault(major_minor, []).append(
                {
                    "major_minor": holder_major_minor,
                    "holder_type": holder_type,
                    "holder_name": holder_name,
                    "parent_major_minor": major_minor,
                }
            )
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
    return related


def _safe_name(value: str) -> str:
    cleaned = " ".join(value.replace("\x00", "").split())
    if not cleaned or "/" in cleaned or ".." in cleaned:
        return "unsupported-holder"
    return cleaned[:128]


def _valid_major_minor(value: str) -> bool:
    major, separator, minor = value.partition(":")
    return bool(separator) and major.isdigit() and minor.isdigit()
