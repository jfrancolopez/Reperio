"""Stable source identity resolution for RPR-011 and RPR-178.

This layer consumes sanitized block-device facts from ``hostd.block_devices`` and
binds them to stable opaque source IDs. Mutable kernel names remain reported as
current facts, but they are never the source identity.

For removable media (RPR-178) the layer separates the reusable *reader* identity
from the inserted *medium* identity. A different same-capacity card, disc, or
floppy inserted into the same reader therefore resolves to a distinct medium
``source_id``; only the sampled fingerprint and medium facts make that possible,
so missing fingerprints degrade identity strength with an explicit warning.
"""

from __future__ import annotations

import hashlib
import os
from pathlib import Path
from typing import Any

from shared import media_identity

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
        if media_identity.is_removable(device):
            identified = _with_media_identity(identified)
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


def _with_media_identity(device: dict[str, Any]) -> dict[str, Any]:
    """Bind a removable reader to its inserted-medium identity.

    ``device`` must already carry a reader identity from ``_with_identity``.
    The returned copy keeps ``reader_id`` and ``reader_identity_strength``
    while replacing ``source_id`` with the medium-bound identity, so a
    same-capacity medium swap changes the source identity.
    """
    copy = dict(device)
    reader_id = _string(copy.get("source_id"))
    reader_strength = _string(copy.get("identity_strength"))
    reader_warnings = list(copy.get("identity_warnings", []))

    signals = media_identity.normalize_medium_signals(copy)
    warnings = list(media_identity.identity_warnings_for(copy, signals))
    has_fingerprint = (
        media_identity._normalized_fingerprint(signals.get("sampled_fingerprint_sha256"))
        is not None
    )
    strength = "reader-plus-medium" if has_fingerprint else "reader-facts"
    if not has_fingerprint and strength_warning_needed(copy):
        warnings.append("missing_sampled_fingerprint")

    medium_id = _medium_source_id(reader_id, signals)
    copy["reader_id"] = reader_id
    copy["reader_identity_strength"] = reader_strength
    copy["source_id"] = medium_id
    copy["identity_strength"] = strength
    copy["identity_warnings"] = list(dict.fromkeys(reader_warnings + warnings))
    copy["medium_identity"] = media_identity.medium_identity_record(
        reader_id, signals, identity_strength=strength, warnings=tuple(warnings)
    )
    copy["children"] = [_with_child_identity(child, copy) for child in copy.get("children", [])]
    return copy


def _medium_source_id(reader_id: str, signals: dict[str, Any]) -> str:
    basis = {"reader_id": reader_id, "medium_signals": signals}
    return f"medium_{_digest(basis)}"


def strength_warning_needed(device: dict[str, Any]) -> bool:
    """Return true when the medium is present but the fingerprint is missing."""
    return bool(
        media_identity.is_plausible_medium(
            {"medium_signals": media_identity.normalize_medium_signals(device)}
        )
    )


def _with_identity(device: dict[str, Any], by_id_names: dict[str, list[str]]) -> dict[str, Any]:
    copy = dict(device)
    warnings = list(copy.get("warnings", []))
    kernel_name = _string(copy.get("kernel_name"))
    matched_by_id = by_id_names.get(kernel_name, [])
    removable = bool(copy.get("removable"))

    if matched_by_id:
        identity_basis: dict[str, Any] = {"by_id": matched_by_id[0]}
        if not removable:
            identity_basis.update(_medium_dependent_facts(copy))
        strength = "by-id"
    elif _string(copy.get("serial")):
        identity_basis = {
            "vendor": copy.get("vendor"),
            "model": copy.get("model"),
            "serial": copy.get("serial"),
        }
        if not removable:
            identity_basis.update(_medium_dependent_facts(copy))
        strength = "serial-facts"
    else:
        identity_basis = {
            "vendor": copy.get("vendor"),
            "model": copy.get("model"),
            "device_type": copy.get("device_type"),
            "transport": copy.get("transport"),
            "removable": removable,
        }
        if not removable:
            identity_basis.update(_medium_dependent_facts(copy))
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


def _medium_dependent_facts(device: dict[str, Any]) -> dict[str, Any]:
    return {
        "size_bytes": device.get("size_bytes"),
        "logical_block_size": device.get("logical_block_size"),
        "physical_block_size": device.get("physical_block_size"),
        "topology": _topology(device),
    }


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
