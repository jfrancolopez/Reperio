"""Scratch/export physical-separation checks for RPR-015."""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from pathlib import Path
from typing import Any

NETWORK_FILESYSTEMS = frozenset({"nfs", "nfs4", "cifs", "smb3", "sshfs", "fuse.sshfs"})


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
    resolved_path = destination_path.resolve(strict=False)
    blockers: list[dict[str, str]] = []
    warnings: list[str] = []

    if not destination_path.exists():
        blockers.append({"reason": "destination_path_missing", "detail": str(destination_path)})

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

    source_major_minors = _source_major_minors(source)
    ancestry = _expand_ancestry(_normalize_holders(holders or {}))
    destination_ancestry = {mount["major_minor"], *ancestry.get(mount["major_minor"], set())}
    overlap = sorted(source_major_minors & destination_ancestry)
    if overlap:
        blockers.append(
            {
                "reason": "destination_shares_source_physical_disk",
                "detail": ",".join(overlap),
            }
        )

    return _result(
        destination_path, resolved_path, mount, blockers, warnings, sorted(destination_ancestry)
    )


def _result(
    requested_path: Path,
    resolved_path: Path,
    mount: dict[str, str] | None,
    blockers: list[dict[str, str]],
    warnings: list[str],
    destination_ancestry: list[str],
) -> dict[str, Any]:
    return {
        "requested_path": str(requested_path),
        "resolved_path": str(resolved_path),
        "separate": not blockers,
        "blockers": blockers,
        "warnings": warnings,
        "mount": mount,
        "destination_ancestry": destination_ancestry,
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
    fstype = str(mount.get("fstype", ""))
    if not mount_point.startswith("/") or not _valid_major_minor(major_minor):
        return None
    return {
        "mount_point": str(Path(mount_point).resolve(strict=False)),
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
    major, separator, minor = value.partition(":")
    return bool(separator) and major.isdigit() and minor.isdigit()
