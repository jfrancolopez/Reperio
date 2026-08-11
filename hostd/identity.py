"""Stable source identity resolution for RPR-011.

This layer consumes sanitized block-device facts from ``hostd.block_devices`` and
binds them to stable opaque source IDs. Mutable kernel names remain reported as
current facts, but they are never the source identity.
"""

from __future__ import annotations

import hashlib
import os
from pathlib import Path
from typing import Any

DEFAULT_DEV_DISK_BY_ID = Path("/dev/disk/by-id")


class IdentityCollisionError(ValueError):
    """Raised when two current devices resolve to the same stable identity."""


def attach_stable_identities(
    devices: list[dict[str, Any]], dev_disk_by_id: Path = DEFAULT_DEV_DISK_BY_ID
) -> list[dict[str, Any]]:
    """Return devices augmented with opaque stable identity facts.

    Prefer ``/dev/disk/by-id`` names. If unavailable, use serial-backed facts.
    If no serial/WWN evidence exists, use a weaker immutable-facts identity and
    add a warning so callers can require stronger confirmation in later tasks.
    """
    by_id_names = _by_id_names_by_kernel(dev_disk_by_id)
    resolved: list[dict[str, Any]] = []
    seen: dict[str, str] = {}

    for device in devices:
        identified = _with_identity(device, by_id_names)
        source_id = identified["source_id"]
        existing = seen.get(source_id)
        if existing is not None:
            raise IdentityCollisionError(
                f"stable identity collision for {source_id!r}: {existing!r} and "
                f"{identified.get('kernel_name')!r}"
            )
        seen[source_id] = str(identified.get("kernel_name"))
        resolved.append(identified)
    return resolved


def _with_identity(device: dict[str, Any], by_id_names: dict[str, list[str]]) -> dict[str, Any]:
    copy = dict(device)
    warnings = list(copy.get("warnings", []))
    kernel_name = _string(copy.get("kernel_name"))
    matched_by_id = by_id_names.get(kernel_name, [])

    if matched_by_id:
        identity_basis = {
            "by_id": matched_by_id[0],
            "size_bytes": copy.get("size_bytes"),
            "logical_block_size": copy.get("logical_block_size"),
            "physical_block_size": copy.get("physical_block_size"),
            "transport": copy.get("transport"),
            "topology": _topology(copy),
        }
        strength = "by-id"
    elif _string(copy.get("serial")):
        identity_basis = {
            "vendor": copy.get("vendor"),
            "model": copy.get("model"),
            "serial": copy.get("serial"),
            "size_bytes": copy.get("size_bytes"),
            "logical_block_size": copy.get("logical_block_size"),
            "physical_block_size": copy.get("physical_block_size"),
            "transport": copy.get("transport"),
            "topology": _topology(copy),
        }
        strength = "serial-facts"
    else:
        identity_basis = {
            "vendor": copy.get("vendor"),
            "model": copy.get("model"),
            "device_type": copy.get("device_type"),
            "size_bytes": copy.get("size_bytes"),
            "logical_block_size": copy.get("logical_block_size"),
            "physical_block_size": copy.get("physical_block_size"),
            "transport": copy.get("transport"),
            "removable": copy.get("removable"),
            "topology": _topology(copy),
        }
        strength = "weak-facts"
        warnings.append("missing_stable_serial_or_by_id")

    digest = _digest(identity_basis)
    copy.update(
        {
            "source_id": f"source_{digest}",
            "identity_strength": strength,
            "identity_warnings": warnings,
            "by_id_name": matched_by_id[0] if matched_by_id else None,
        }
    )
    copy["children"] = [_with_child_identity(child, copy) for child in copy.get("children", [])]
    return copy


def _with_child_identity(child: dict[str, Any], parent: dict[str, Any]) -> dict[str, Any]:
    copy = dict(child)
    basis = {
        "parent_source_id": parent["source_id"],
        "start_sector": copy.get("start_sector"),
        "size_bytes": copy.get("size_bytes"),
    }
    copy["source_id"] = f"source_{_digest(basis)}"
    copy["parent_source_id"] = parent["source_id"]
    copy["identity_strength"] = "parent-topology"
    return copy


def _by_id_names_by_kernel(dev_disk_by_id: Path) -> dict[str, list[str]]:
    mapping: dict[str, list[str]] = {}
    try:
        entries = sorted(dev_disk_by_id.iterdir(), key=lambda path: path.name)
    except OSError:
        return mapping

    for entry in entries:
        if not entry.is_symlink():
            continue
        name = _safe_by_id_name(entry.name)
        if name is None:
            continue
        try:
            target = os.fsdecode(entry.resolve(strict=False))
        except OSError:
            continue
        kernel_name = Path(target).name
        if not kernel_name or ".." in kernel_name or "/" in kernel_name:
            continue
        mapping.setdefault(kernel_name, []).append(name)
    return mapping


def _safe_by_id_name(name: str) -> str | None:
    if not name or "/" in name or "\x00" in name or ".." in name:
        return None
    return name[:192]


def _topology(device: dict[str, Any]) -> list[dict[str, Any]]:
    children = device.get("children")
    if not isinstance(children, list):
        return []
    return sorted(
        (
            {
                "start_sector": child.get("start_sector"),
                "size_bytes": child.get("size_bytes"),
            }
            for child in children
            if isinstance(child, dict)
        ),
        key=lambda item: (item.get("start_sector") or 0, item.get("size_bytes") or 0),
    )


def _digest(value: object) -> str:
    normalized = repr(_normalize(value)).encode()
    return hashlib.sha256(normalized).hexdigest()[:32]


def _normalize(value: object) -> object:
    if isinstance(value, dict):
        return {key: _normalize(value[key]) for key in sorted(value)}
    if isinstance(value, list):
        return [_normalize(item) for item in value]
    return value


def _string(value: object) -> str:
    return value if isinstance(value, str) else ""
