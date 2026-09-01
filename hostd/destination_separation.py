"""Scratch/export physical-separation checks for RPR-015."""

from __future__ import annotations

import re
from collections.abc import Iterable, Mapping
from pathlib import Path
from typing import Any

from hostd import storage_inspection

NETWORK_FILESYSTEMS = frozenset({"nfs", "nfs4", "cifs", "smb3", "sshfs", "fuse.sshfs"})
MAJOR_MINOR_RE = re.compile(r"^(0|[1-9][0-9]*):(0|[1-9][0-9]*)$")
FSTYPE_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}$")


def evaluate_live_destination_separation(
    source: Mapping[str, Any],
    destination_path: Path,
    *,
    mountinfo_path: Path = storage_inspection.DEFAULT_MOUNTINFO,
    sys_dev_block: Path = storage_inspection.DEFAULT_SYS_DEV_BLOCK,
) -> dict[str, Any]:
    """Resolve destination backing storage from read-only Linux kernel facts."""
    mounts = storage_inspection.read_mountinfo(mountinfo_path)
    source_major_minors = _source_major_minors(source)
    holders = storage_inspection.read_holder_graph(source_major_minors, sys_dev_block=sys_dev_block)
    result = evaluate_destination_separation(
        source, destination_path, mounts=mounts, holders=holders
    )
    missing = []
    if not mountinfo_path.is_file():
        missing.append("mountinfo")
    if not sys_dev_block.is_dir():
        missing.append("sysfs")
    if missing:
        result["blockers"].append(
            {"reason": "separation_inspection_unavailable", "detail": ",".join(missing)}
        )
        result["separate"] = False
        result["inspection_complete"] = False
    return result


def evaluate_destination_separation(
    source: Mapping[str, Any],
    destination_path: Path,
    *,
    mounts: Iterable[Mapping[str, Any]],
    holders: Mapping[str, Iterable[Mapping[str, str]]] | None = None,
) -> dict[str, Any]:
    """Return whether ``destination_path`` is physically separate from source.

    The function consumes injected mount and holder facts and never creates,
    mounts, opens, writes, or deletes the destination or source.
    """
    blockers: list[dict[str, str]] = []
    warnings: list[str] = []
    try:
        resolved_path = destination_path.resolve(strict=False)
    except (OSError, RuntimeError) as error:
        resolved_path = destination_path.absolute()
        blockers.append(
            {"reason": "destination_path_unresolvable", "detail": error.__class__.__name__}
        )

    if not destination_path.exists():
        blockers.append({"reason": "destination_path_missing", "detail": str(destination_path)})

    source_major_minors = _source_major_minors(source)
    if not source_major_minors:
        blockers.append({"reason": "missing_source_topology", "detail": "no valid major:minor"})

    mount = _find_mount(resolved_path, mounts)
    if mount is None:
        blockers.append({"reason": "destination_not_mounted", "detail": str(resolved_path)})
        return _result(destination_path, resolved_path, None, blockers, warnings, [])

    fstype = mount.get("fstype", "")
    if fstype in NETWORK_FILESYSTEMS:
        warnings.append("network_filesystem_physical_separation_not_locally_provable")
        return _result(
            destination_path, resolved_path, mount, blockers, warnings, [mount["major_minor"]]
        )

    ancestry = _expand_ancestry(_normalize_holders(holders or {}))
    source_ancestry = set(source_major_minors)
    for major_minor in source_major_minors:
        source_ancestry.update(ancestry.get(major_minor, set()))
    destination_ancestry = {mount["major_minor"], *ancestry.get(mount["major_minor"], set())}
    overlap = sorted(source_ancestry & destination_ancestry, key=_major_minor_key)
    if overlap:
        blockers.append(
            {
                "reason": "destination_shares_source_physical_disk",
                "detail": ",".join(overlap),
            }
        )

    return _result(
        destination_path,
        resolved_path,
        mount,
        blockers,
        warnings,
        sorted(destination_ancestry, key=_major_minor_key),
        source_ancestry=sorted(source_ancestry, key=_major_minor_key),
    )


def _result(
    requested_path: Path,
    resolved_path: Path,
    mount: dict[str, str] | None,
    blockers: list[dict[str, str]],
    warnings: list[str],
    destination_ancestry: list[str],
    *,
    source_ancestry: list[str] | None = None,
) -> dict[str, Any]:
    return {
        "requested_path": str(requested_path),
        "resolved_path": str(resolved_path),
        "separate": not blockers,
        "blockers": blockers,
        "warnings": warnings,
        "mount": mount,
        "destination_ancestry": destination_ancestry,
        "source_ancestry": source_ancestry or [],
        "inspection_complete": True,
    }


def _find_mount(path: Path, mounts: Iterable[Mapping[str, Any]]) -> dict[str, str] | None:
    candidates: list[dict[str, str]] = []
    for mount in mounts:
        normalized = _normalize_mount(mount)
        if normalized is None:
            continue
        mount_point = Path(normalized["mount_point"])
        if path == mount_point or mount_point in path.parents:
            candidates.append(normalized)
    if not candidates:
        return None
    return max(candidates, key=lambda item: len(Path(item["mount_point"]).parts))


def _normalize_mount(mount: Mapping[str, Any]) -> dict[str, str] | None:
    mount_point = str(mount.get("mount_point", ""))
    major_minor = str(mount.get("major_minor", ""))
    fstype = str(mount.get("fstype", "")).lower()
    if (
        not mount_point.startswith("/")
        or len(mount_point) > 4096
        or "\x00" in mount_point
        or any(ord(char) < 32 for char in mount_point)
        or not _valid_major_minor(major_minor)
    ):
        return None
    if FSTYPE_RE.fullmatch(fstype) is None:
        fstype = "unknown"
    try:
        resolved_mount_point = Path(mount_point).resolve(strict=False)
    except (OSError, RuntimeError):
        return None
    return {
        "mount_point": str(resolved_mount_point),
        "major_minor": major_minor,
        "fstype": fstype,
    }


def _source_major_minors(source: Mapping[str, Any]) -> set[str]:
    values: set[str] = set()
    major_minor = source.get("major_minor")
    if isinstance(major_minor, str) and _valid_major_minor(major_minor):
        values.add(major_minor)
    children = source.get("children")
    if isinstance(children, list):
        for child in children:
            if isinstance(child, Mapping):
                child_major_minor = child.get("major_minor")
                if isinstance(child_major_minor, str) and _valid_major_minor(child_major_minor):
                    values.add(child_major_minor)
    return values


def _normalize_holders(
    holders: Mapping[str, Iterable[Mapping[str, str]]],
) -> dict[str, list[str]]:
    normalized: dict[str, list[str]] = {}
    for parent, records in holders.items():
        if not _valid_major_minor(parent):
            continue
        for record in records:
            child = str(record.get("major_minor", ""))
            if _valid_major_minor(child):
                normalized.setdefault(child, []).append(parent)
    return normalized


def _expand_ancestry(parent_by_child: Mapping[str, list[str]]) -> dict[str, set[str]]:
    expanded: dict[str, set[str]] = {}

    def visit(node: str, seen: set[str]) -> set[str]:
        if node in seen:
            return set()
        parents = set(parent_by_child.get(node, []))
        result = set(parents)
        for parent in parents:
            result.update(visit(parent, seen | {node}))
        return result

    for node in parent_by_child:
        expanded[node] = visit(node, set())
    return expanded


def _valid_major_minor(value: str) -> bool:
    return MAJOR_MINOR_RE.fullmatch(value) is not None


def _major_minor_key(value: str) -> tuple[int, int]:
    major, minor = value.split(":", 1)
    return int(major), int(minor)
