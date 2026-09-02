"""Kernel read-only preparation and verification for RPR-016."""

from __future__ import annotations

import array
import fcntl
import os
import re
import stat
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any, Protocol

BLKROSET = 0x125D
BLKROGET = 0x125E
KERNEL_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+-]{0,127}$")
MAJOR_MINOR_RE = re.compile(r"^(0|[1-9][0-9]*):(0|[1-9][0-9]*)$")


class ReadOnlyOperationError(OSError):
    """Raised when a kernel read-only operation cannot be completed."""


class ReadOnlyOps(Protocol):
    """Narrow interface for setting and verifying kernel read-only state."""

    def set_read_only(self, target: Mapping[str, str]) -> None: ...

    def verify_read_only(self, target: Mapping[str, str]) -> bool: ...


class LinuxIoctlReadOnlyOps:
    """Linux BLKROSET/BLKROGET implementation using sanitized kernel names."""

    def __init__(self, device_root: Path = Path("/dev")) -> None:
        self.device_root = device_root

    def set_read_only(self, target: Mapping[str, str]) -> None:
        fd = self._open(target)
        try:
            value = array.array("i", [1])
            fcntl.ioctl(fd, BLKROSET, value, True)
        finally:
            os.close(fd)

    def verify_read_only(self, target: Mapping[str, str]) -> bool:
        fd = self._open(target)
        try:
            value = array.array("i", [0])
            fcntl.ioctl(fd, BLKROGET, value, True)
            return value[0] == 1
        finally:
            os.close(fd)

    def _open(self, target: Mapping[str, str]) -> int:
        kernel_name = target.get("kernel_name", "")
        if not _valid_kernel_name(kernel_name):
            raise ReadOnlyOperationError(f"invalid kernel name {kernel_name!r}")
        path = self.device_root / kernel_name
        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
        try:
            fd = os.open(path, flags)
        except OSError as error:
            raise ReadOnlyOperationError(error.__class__.__name__) from error
        try:
            opened = os.fstat(fd)
            expected_major, expected_minor = _major_minor(target.get("major_minor", ""))
            if not stat.S_ISBLK(opened.st_mode):
                raise ReadOnlyOperationError("opened target is not a block device")
            if (os.major(opened.st_rdev), os.minor(opened.st_rdev)) != (
                expected_major,
                expected_minor,
            ):
                raise ReadOnlyOperationError("opened target identity changed")
        except Exception:
            os.close(fd)
            raise
        return fd


def prepare_read_only(
    device: Mapping[str, Any],
    *,
    ops: ReadOnlyOps,
    storage_state: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Set and verify kernel read-only state for a source and its children."""
    storage_blockers = list((storage_state or {}).get("blockers", []))
    if storage_state is None:
        storage_blockers.append({"reason": "storage_inspection_required"})
    elif storage_state.get("inspection_complete") is not True:
        storage_blockers.append({"reason": "storage_inspection_incomplete"})
    elif storage_state.get("safe_for_preparation") is not True:
        storage_blockers.append({"reason": "storage_state_not_safe"})
    if storage_blockers:
        return {
            "source_id": device.get("source_id"),
            "prepared": False,
            "targets": [],
            "blockers": [
                {"reason": "storage_state_blocked", "detail": str(blocker)}
                for blocker in storage_blockers
            ],
            "audit": _audit(device, [], False),
        }

    targets = _targets(device)
    results: list[dict[str, str | bool]] = []
    blockers = _target_blockers(device, targets)
    if blockers:
        return {
            "source_id": device.get("source_id"),
            "prepared": False,
            "targets": [],
            "blockers": blockers,
            "audit": _audit(device, [], False),
        }
    for target in targets:
        result: dict[str, str | bool] = {
            "kernel_name": target["kernel_name"],
            "major_minor": target["major_minor"],
            "set_read_only": False,
            "verified_read_only": False,
        }
        try:
            ops.set_read_only(target)
            result["set_read_only"] = True
        except OSError as error:
            blockers.append(
                {
                    "reason": "read_only_set_failed",
                    "major_minor": target["major_minor"],
                    "detail": error.__class__.__name__,
                }
            )
            results.append(result)
            continue

        try:
            verified = ops.verify_read_only(target)
        except OSError as error:
            blockers.append(
                {
                    "reason": "read_only_verify_failed",
                    "major_minor": target["major_minor"],
                    "detail": error.__class__.__name__,
                }
            )
            results.append(result)
            continue
        result["verified_read_only"] = verified
        if not verified:
            blockers.append(
                {
                    "reason": "read_only_verify_false",
                    "major_minor": target["major_minor"],
                    "detail": target["kernel_name"],
                }
            )
        results.append(result)

    prepared = (
        bool(targets)
        and not blockers
        and all(bool(result["verified_read_only"]) for result in results)
    )
    return {
        "source_id": device.get("source_id"),
        "prepared": prepared,
        "targets": results,
        "blockers": blockers,
        "audit": _audit(device, results, prepared),
    }


def _targets(device: Mapping[str, Any]) -> list[dict[str, str]]:
    targets: list[dict[str, str]] = []
    _append_target(targets, device)
    children = device.get("children")
    if isinstance(children, Sequence) and not isinstance(children, str | bytes):
        for child in children:
            if isinstance(child, Mapping):
                _append_target(targets, child)
    return targets


def _append_target(targets: list[dict[str, str]], item: Mapping[str, Any]) -> None:
    kernel_name = item.get("kernel_name")
    major_minor = item.get("major_minor")
    if isinstance(kernel_name, str) and isinstance(major_minor, str):
        if _valid_kernel_name(kernel_name) and _valid_major_minor(major_minor):
            targets.append({"kernel_name": kernel_name, "major_minor": major_minor})


def _target_blockers(
    device: Mapping[str, Any], targets: Sequence[Mapping[str, str]]
) -> list[dict[str, str]]:
    children = device.get("children")
    if not isinstance(children, Sequence) or isinstance(children, str | bytes):
        return [{"reason": "invalid_source_topology", "detail": "children must be a list"}]
    expected_count = 1 + len(children)
    if len(targets) != expected_count:
        return [{"reason": "invalid_source_target", "detail": "target facts are incomplete"}]
    kernel_names = {target["kernel_name"] for target in targets}
    major_minors = {target["major_minor"] for target in targets}
    if len(kernel_names) != len(targets) or len(major_minors) != len(targets):
        return [{"reason": "duplicate_source_target", "detail": "target facts are ambiguous"}]
    return []


def _audit(
    device: Mapping[str, Any], targets: Sequence[Mapping[str, Any]], prepared: bool
) -> dict[str, Any]:
    return {
        "event": "kernel_read_only_preparation",
        "source_id": device.get("source_id"),
        "prepared": prepared,
        "target_count": len(targets),
        "verified_major_minors": [
            target.get("major_minor")
            for target in targets
            if target.get("verified_read_only") is True
        ],
    }


def _valid_kernel_name(value: str) -> bool:
    return KERNEL_NAME_RE.fullmatch(value) is not None and ".." not in value


def _valid_major_minor(value: str) -> bool:
    return MAJOR_MINOR_RE.fullmatch(value) is not None


def _major_minor(value: str) -> tuple[int, int]:
    if not _valid_major_minor(value):
        raise ReadOnlyOperationError("invalid major:minor")
    major, minor = value.split(":", 1)
    return int(major), int(minor)
