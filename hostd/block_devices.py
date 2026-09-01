"""Sanitized Linux block-device enumeration for RPR-010.

The implementation reads a sysfs-shaped tree from an injectable root so tests can
exercise device classes and races without privileged access. It returns facts
only; stable identity and safety decisions are implemented by later tasks.
"""

from __future__ import annotations

import hashlib
import os
import re
from pathlib import Path
from typing import Any

SECTOR_BYTES = 512
DEFAULT_SYS_BLOCK = Path("/sys/block")

KNOWN_TRANSPORTS = ("usb", "ata", "sata", "nvme", "mmc", "scsi", "virtio", "loop")
KERNEL_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+-]{0,127}$")
MAJOR_MINOR_RE = re.compile(r"^(0|[1-9][0-9]*):(0|[1-9][0-9]*)$")
MAX_BLOCK_SIZE = 16 * 1024 * 1024


def list_block_devices(sys_block: Path = DEFAULT_SYS_BLOCK) -> list[dict[str, Any]]:
    """Return sanitized whole-disk and partition facts from ``/sys/block``.

    Transient devices can disappear while being read. Such entries are skipped
    rather than crashing enumeration, matching hotplug/media-change behavior.
    """
    devices: list[dict[str, Any]] = []
    try:
        entries = sorted(sys_block.iterdir(), key=lambda path: path.name)
    except OSError:
        return devices

    for entry in entries:
        try:
            device = _read_device(entry)
        except OSError:
            continue
        if device is not None:
            devices.append(device)
    return devices


def _read_device(entry: Path) -> dict[str, Any] | None:
    name = entry.name
    if not _valid_kernel_name(name):
        return None

    major_minor = _read_text(entry / "dev")
    if major_minor is None or MAJOR_MINOR_RE.fullmatch(major_minor) is None:
        return None

    size_sectors = _read_int(entry / "size", default=0)
    logical_block_size = _read_int(entry / "queue" / "logical_block_size", default=SECTOR_BYTES)
    if not _valid_block_size(logical_block_size):
        logical_block_size = SECTOR_BYTES
    physical_block_size = _read_int(
        entry / "queue" / "physical_block_size", default=logical_block_size
    )
    if not _valid_block_size(physical_block_size):
        physical_block_size = logical_block_size
    removable = _read_bool(entry / "removable")
    read_only = _read_bool(entry / "ro")
    device_type = _classify_device(name, entry)

    warnings: list[str] = []
    device: dict[str, Any] = {
        "candidate_id": _candidate_id("dev", major_minor, name),
        "kind": "whole_disk",
        "kernel_name": name,
        "major_minor": major_minor,
        "device_type": device_type,
        "transport": _transport(name, entry),
        "removable": removable,
        "read_only": read_only,
        "size_bytes": size_sectors * SECTOR_BYTES,
        "logical_block_size": logical_block_size,
        "physical_block_size": physical_block_size,
        "model": _sanitize(_read_text(entry / "device" / "model")),
        "vendor": _sanitize(_read_text(entry / "device" / "vendor")),
        "serial": _sanitize(_read_text(entry / "device" / "serial")),
        "wwn": _sanitize(_read_text(entry / "wwid") or _read_text(entry / "device" / "wwid")),
        "has_media": size_sectors > 0,
        "warnings": warnings,
        "children": [],
    }
    if removable and size_sectors == 0:
        warnings.append("empty_or_unreadable_removable_reader")

    children = []
    try:
        child_entries = sorted(entry.iterdir(), key=lambda path: path.name)
    except OSError:
        child_entries = []
    for child in child_entries:
        try:
            partition = _read_partition(child, parent=device)
        except OSError:
            continue
        if partition is not None:
            children.append(partition)
    device["children"] = children
    return device


def _read_partition(child: Path, parent: dict[str, Any]) -> dict[str, Any] | None:
    name = child.name
    if not _valid_kernel_name(name) or _read_text(child / "partition") is None:
        return None
    major_minor = _read_text(child / "dev")
    if major_minor is None or MAJOR_MINOR_RE.fullmatch(major_minor) is None:
        return None
    size_sectors = _read_int(child / "size", default=0)
    start_sector = _read_int(child / "start", default=0)
    return {
        "candidate_id": _candidate_id("part", major_minor, name),
        "kind": "partition",
        "kernel_name": name,
        "major_minor": major_minor,
        "parent_candidate_id": parent["candidate_id"],
        "parent_kernel_name": parent["kernel_name"],
        "device_type": "partition",
        "transport": parent["transport"],
        "removable": parent["removable"],
        "read_only": parent["read_only"],
        "start_sector": start_sector,
        "size_bytes": size_sectors * SECTOR_BYTES,
        "logical_block_size": parent["logical_block_size"],
        "physical_block_size": parent["physical_block_size"],
        "has_media": parent["has_media"],
        "warnings": [],
    }


def _classify_device(name: str, entry: Path) -> str:
    subsystem = _resolved_name(entry / "device" / "subsystem")
    if name.startswith("loop"):
        return "loop"
    if name.startswith("nvme"):
        return "nvme"
    if name.startswith("mmcblk"):
        return "sd_card"
    if name.startswith("sr") or subsystem == "scsi_generic":
        return "optical"
    if name.startswith("fd"):
        return "floppy"
    if name.startswith("dm-"):
        return "device_mapper"
    if _transport(name, entry) == "usb":
        return "usb_storage"
    if _transport(name, entry) in {"ata", "sata"} or name.startswith(("sd", "hd")):
        return "disk"
    return "block"


def _transport(name: str, entry: Path) -> str:
    if name.startswith("loop"):
        return "loop"
    if name.startswith("nvme"):
        return "nvme"
    if name.startswith("mmcblk"):
        return "mmc"
    resolved = _resolved_text(entry / "device")
    combined = f"{resolved} {_read_text(entry / 'device' / 'transport') or ''}".lower()
    for transport in KNOWN_TRANSPORTS:
        if transport in combined:
            return "sata" if transport == "ata" else transport
    return "unknown"


def _read_text(path: Path) -> str | None:
    try:
        text = path.read_text(encoding="utf-8").strip()
    except OSError:
        return None
    if not text:
        return None
    return text


def _read_int(path: Path, *, default: int) -> int:
    text = _read_text(path)
    if text is None:
        return default
    try:
        value = int(text, 10)
    except ValueError:
        return default
    return value if value >= 0 else default


def _read_bool(path: Path) -> bool:
    return _read_int(path, default=0) == 1


def _sanitize(value: str | None) -> str | None:
    if value is None:
        return None
    cleaned = " ".join(value.replace("\x00", "").split())
    return cleaned[:128] if cleaned else None


def _valid_kernel_name(name: str) -> bool:
    return KERNEL_NAME_RE.fullmatch(name) is not None and ".." not in name


def _valid_block_size(value: int) -> bool:
    return 0 < value <= MAX_BLOCK_SIZE and value & (value - 1) == 0


def _candidate_id(kind: str, major_minor: str, name: str) -> str:
    digest = hashlib.sha256(f"{kind}:{major_minor}:{name}".encode()).hexdigest()[:24]
    return f"{kind}_{digest}"


def _resolved_text(path: Path) -> str:
    try:
        return os.fsdecode(path.resolve(strict=False))
    except OSError:
        return ""


def _resolved_name(path: Path) -> str | None:
    text = _resolved_text(path)
    if not text:
        return None
    return Path(text).name
