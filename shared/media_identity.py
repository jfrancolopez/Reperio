"""Versioned source-kind and media-identity contract for removable media (RPR-178).

This module is the schema-and-validation half of the removable source identity
contract. It separates the reusable *reader* (card reader, optical drive, floppy
drive, legacy adapter) from the inserted *medium* (card, disc, floppy, legacy
medium) so that replacing a same-capacity medium in the same reader yields a
distinct source identity. No function here treats a kernel name (``/dev/sdX``,
``/dev/sr0``, ``/dev/fd0``) as identity.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

MEDIA_IDENTITY_SCHEMA_VERSION = 1

SOURCE_KINDS = frozenset(
    {
        "fixed_disk",
        "usb_flash",
        "memory_card",
        "optical_disc",
        "floppy_media",
        "legacy_medium",
    }
)

READER_KINDS = frozenset(
    {"fixed_reader", "card_reader", "optical_drive", "floppy_drive", "legacy_reader"}
)

IDENTITY_STRENGTHS = frozenset(
    {
        "by-id",
        "wwn-facts",
        "serial-facts",
        "weak-facts",
        "reader-plus-medium",
        "reader-facts",
    }
)

MEDIUM_SIGNAL_FIELDS = (
    "capacity_bytes",
    "logical_block_size",
    "physical_block_size",
    "geometry",
    "toc_sessions",
    "sampled_fingerprint_sha256",
    "media_change_generation",
)

MEDIUM_SIGNAL_WARNING_MESSAGES = {
    "missing_stable_serial_or_by_id": (
        "reader has no stable serial, WWN, or by-id name; medium identity relies "
        "on sampled fingerprint and medium facts"
    ),
    "missing_sampled_fingerprint": (
        "sampled fingerprint unavailable; medium identity is weak and a "
        "same-capacity replacement cannot be distinguished"
    ),
    "unreadable_fingerprint_sample": "fingerprint sample was unreadable; identity is weak",
    "no_medium_present": "removable reader has no readable medium present",
    "missing_toc_or_geometry": (
        "optical/floppy medium lacks TOC or geometry evidence; identity is weaker"
    ),
}


@dataclass(frozen=True)
class MediaIdentityValidationResult:
    valid: bool
    warnings: tuple[str, ...] = ()


def source_kind_for_device(device: Mapping[str, Any]) -> str:
    """Classify a sanitized device into a source kind.

    Removable readers never receive a ``fixed_disk`` label, and fixed disks are
    not remapped to reader kinds even when they are removable in sysfs.
    """
    device_type = device.get("device_type")
    removable = bool(device.get("removable"))
    if device_type == "optical":
        return "optical_disc"
    if device_type == "floppy":
        return "floppy_media"
    if device_type == "sd_card" or (removable and device_type == "usb_storage"):
        return "memory_card" if device_type == "sd_card" else "usb_flash"
    if removable:
        return "legacy_medium"
    return "fixed_disk"


def reader_kind_for_device(device: Mapping[str, Any]) -> str:
    """Classify the reusable reader hosting a removable medium."""
    device_type = device.get("device_type")
    if device_type == "optical":
        return "optical_drive"
    if device_type == "floppy":
        return "floppy_drive"
    if device_type == "sd_card":
        return "card_reader"
    if device_type == "usb_storage":
        return "card_reader"
    if device_type in {"loop", "block"}:
        return "legacy_reader"
    return "fixed_reader"


def is_removable(device: Mapping[str, Any]) -> bool:
    """Return true when a device represents a removable medium reader."""
    return source_kind_for_device(device) != "fixed_disk"


def medium_identity_record(
    reader_id: str,
    medium_signals: Mapping[str, Any],
    *,
    identity_strength: str,
    warnings: tuple[str, ...] = (),
) -> dict[str, Any]:
    """Build the normalized versioned medium-identity record.

    ``medium_signals`` must contain the fields named by ``MEDIUM_SIGNAL_FIELDS``
    (callers use :func:`normalize_medium_signals` to fill defaults). The record
    is what later tasks bind to checkpoints, so every field is deterministic.
    """
    signals = dict(medium_signals)
    record = {
        "schema_version": MEDIA_IDENTITY_SCHEMA_VERSION,
        "reader_id": reader_id,
        "identity_strength": identity_strength,
        "warnings": list(warnings),
        "medium_signals": {field: signals.get(field) for field in MEDIUM_SIGNAL_FIELDS},
    }
    if not is_plausible_medium(record):
        record["has_medium"] = False
    else:
        record["has_medium"] = True
    return record


def normalize_medium_signals(device: Mapping[str, Any]) -> dict[str, Any]:
    """Extract deterministic medium signals from sanitized device facts."""
    return {
        "capacity_bytes": device.get("size_bytes"),
        "logical_block_size": device.get("logical_block_size"),
        "physical_block_size": device.get("physical_block_size"),
        "geometry": _normalized_geometry(device.get("geometry")),
        "toc_sessions": _normalized_sessions(device.get("toc_sessions")),
        "sampled_fingerprint_sha256": _normalized_fingerprint(
            device.get("sampled_fingerprint_sha256")
        ),
        "media_change_generation": _nonnegative_int(
            device.get("media_change_generation"), default=0
        ),
    }


def validate_media_identity(record: Mapping[str, Any]) -> MediaIdentityValidationResult:
    """Validate a medium-identity record against the versioned contract."""
    warnings: list[str] = []
    if record.get("schema_version") != MEDIA_IDENTITY_SCHEMA_VERSION:
        return MediaIdentityValidationResult(False, ("unsupported_schema_version",))
    reader_id = record.get("reader_id")
    if not isinstance(reader_id, str) or not reader_id.startswith("reader_"):
        warnings.append("invalid_reader_id")
    strength = record.get("identity_strength")
    if strength not in IDENTITY_STRENGTHS:
        warnings.append("unknown_identity_strength")
    signals = record.get("medium_signals")
    if not isinstance(signals, Mapping):
        return MediaIdentityValidationResult(False, ("missing_medium_signals",))
    for field in MEDIUM_SIGNAL_FIELDS:
        if field not in signals:
            warnings.append(f"missing_signal:{field}")
    return MediaIdentityValidationResult(not warnings, tuple(warnings))


def is_plausible_medium(record: Mapping[str, Any]) -> bool:
    """Return true when a readable medium appears to be present.

    A reader without capacity and without a fingerprint carries no medium. This
    is the machine-readable form of the ``no_medium_present`` warning and is
    never a substitute for read-only verification performed by hostd tasks.
    """
    signals = record.get("medium_signals")
    if not isinstance(signals, Mapping):
        return False
    capacity = _positive_int(signals.get("capacity_bytes"))
    fingerprint = _normalized_fingerprint(signals.get("sampled_fingerprint_sha256"))
    return capacity is not None or fingerprint is not None


def identity_warnings_for(
    device: Mapping[str, Any], medium_signals: Mapping[str, Any]
) -> tuple[str, ...]:
    """Derive the documented evidence warnings for a medium-identity record."""
    warnings: list[str] = []
    if not bool(device.get("removable")):
        return ()
    if not is_plausible_medium({"medium_signals": medium_signals}):
        warnings.append("no_medium_present")
    if _normalized_fingerprint(medium_signals.get("sampled_fingerprint_sha256")) is None:
        warnings.append("missing_sampled_fingerprint")
    if device.get("fingerprint_unreadable"):
        warnings.append("unreadable_fingerprint_sample")
    if source_kind_for_device(device) in {"optical_disc", "floppy_media"}:
        if medium_signals.get("toc_sessions") is None and medium_signals.get("geometry") is None:
            warnings.append("missing_toc_or_geometry")
    return tuple(dict.fromkeys(warnings))


def _normalized_geometry(value: object) -> Any:
    if not isinstance(value, Mapping):
        return None
    allowed = ("cylinders", "heads", "sectors_per_track", "bytes_per_sector")
    cleaned: dict[str, int] = {}
    for key in allowed:
        number = value.get(key)
        if isinstance(number, int) and number > 0:
            cleaned[key] = number
    return cleaned or None


def _normalized_sessions(value: object) -> Any:
    if not isinstance(value, list):
        return None
    sessions = []
    for entry in value:
        if not isinstance(entry, Mapping):
            continue
        start = entry.get("start_sector")
        length = entry.get("length_sectors")
        if not isinstance(start, int) or not isinstance(length, int):
            continue
        if start < 0 or length < 0:
            continue
        sessions.append({"start_sector": start, "length_sectors": length})
    return sessions or None


def _normalized_fingerprint(value: object) -> str | None:
    if not isinstance(value, str):
        return None
    stripped = value.strip()
    if len(stripped) != 64 or any(char not in "0123456789abcdef" for char in stripped):
        return None
    return stripped


def _positive_int(value: object) -> int | None:
    if isinstance(value, int) and value > 0:
        return value
    return None


def _nonnegative_int(value: object, *, default: int) -> int:
    if isinstance(value, int) and value >= 0:
        return value
    return default
