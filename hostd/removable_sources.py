"""Host-controller discovery and preparation for removable sources (RPR-179).

Prepares flash/card, optical, and floppy readers for a scan by proving two
things independently: a stable medium identity (RPR-178) and kernel-level
read-only state. Physical write-lock switches and write-once optical media are
reported as informational defense-in-depth only, never as substitutes for
kernel/process denial. This module exposes no eject, burn, blank, format,
packet-write, repair, remount-write, or generic ioctl operation.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from typing import Any, Protocol

from hostd import read_only, storage_inspection
from shared import media_identity

SOURCE_KINDS = frozenset({"usb_flash", "memory_card", "optical_disc", "floppy_media"})
ALLOWED_READ_ONLY_OPS = frozenset({"capacity", "geometry", "optical_toc", "identity_fingerprint"})
FORBIDDEN_OP_NAMES = frozenset(
    {
        "write",
        "eject",
        "burn",
        "blank",
        "format",
        "packet_write",
        "repair",
        "remount_write",
        "ioctl",
    }
)
PHYSICAL_LOCK_SOURCES = frozenset(
    {"sd-write-protect-switch", "optical-write-once", "sysfs-ro", "none"}
)
WRITE_ONCE_OPTICAL_MEDIA = frozenset({"cdr", "cdrw", "dvdr", "dvdplusr", "bdr", "bdrw"})


class RemovableSourceError(ValueError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


class ForbiddenOperationError(RemovableSourceError):
    pass


class ScanLaunchDenied(RemovableSourceError):
    pass


@dataclass(frozen=True)
class PhysicalLockReport:
    write_protected: bool
    write_once: bool
    source: str
    informational_only: bool = True


@dataclass(frozen=True)
class HotplugEvent:
    reader_id: str
    kind: str
    media_change_generation: int
    changed: bool


@dataclass(frozen=True)
class PreparedSource:
    source_id: str
    reader_id: str
    source_kind: str
    medium_present: bool
    medium_identity_proven: bool
    read_only_verified: bool
    physical_lock: PhysicalLockReport
    automount_blockers: tuple[str, ...]
    blockers: tuple[str, ...]
    warnings: tuple[str, ...] = ()

    @property
    def ready_for_scan(self) -> bool:
        return (
            self.medium_identity_proven
            and self.read_only_verified
            and not self.blockers
            and not self.automount_blockers
        )


class ReadOnlyProofOps(Protocol):
    """Narrow interface for kernel read-only set+verify (see hostd.read_only)."""

    def set_read_only(self, target: Mapping[str, str]) -> None: ...

    def verify_read_only(self, target: Mapping[str, str]) -> bool: ...


def prepare_removable_source(
    device: Mapping[str, Any],
    *,
    ops: ReadOnlyProofOps,
    storage_state: Mapping[str, Any] | None = None,
) -> PreparedSource:
    """Prepare one removable source or return the reasons it cannot be used.

    Medium identity must be provable (a valid medium-identity record with a
    present medium) and kernel read-only state must be set and verified for the
    device and every child partition. Physical locks are informational only.
    """
    source_id = _string(device.get("source_id"))
    reader_id = _string(device.get("reader_id") or device.get("source_id"))
    source_kind = media_identity.source_kind_for_device(device)
    if source_kind not in SOURCE_KINDS:
        return _not_removable(source_id, reader_id, source_kind)

    identity_proven, identity_blockers, medium_present = _prove_medium_identity(device)
    ro_result = read_only.prepare_read_only(device, ops=ops, storage_state=storage_state)
    automount_blockers, warnings = _automount_notes(storage_state)
    blockers: list[str] = list(identity_blockers) + [
        blocker.get("reason", "read_only_failed")
        for blocker in ro_result.get("blockers", [])
        if isinstance(blocker, Mapping)
    ]
    physical_lock = physical_lock_report(device)
    return PreparedSource(
        source_id=source_id,
        reader_id=reader_id,
        source_kind=source_kind,
        medium_present=medium_present,
        medium_identity_proven=identity_proven,
        read_only_verified=bool(ro_result.get("prepared")),
        physical_lock=physical_lock,
        automount_blockers=tuple(automount_blockers),
        blockers=tuple(dict.fromkeys(blockers)),
        warnings=tuple(dict.fromkeys(warnings)),
    )


def require_scan_launch_approval(device: Mapping[str, Any], prepared: PreparedSource) -> None:
    """Refuse to launch a scan unless read-only and identity are both proven."""
    if prepared.medium_identity_proven and prepared.read_only_verified and not prepared.blockers:
        return
    reasons = list(prepared.blockers)
    if not prepared.medium_identity_proven:
        reasons.insert(0, "medium_identity_not_proven")
    if not prepared.read_only_verified:
        reasons.insert(0, "read_only_not_verified")
    raise ScanLaunchDenied(
        "scan_launch_denied",
        f"scan launch refused for source {prepared.source_id!r}: " + ", ".join(reasons),
    )


def report_hotplug_change(
    previous: Mapping[str, Any] | None, current: Mapping[str, Any]
) -> HotplugEvent:
    """Compare a previous and current device snapshot for media change/unplug."""
    prior_reader = previous.get("reader_id") if previous is not None else None
    prior_source = previous.get("source_id") if previous is not None else None
    reader_id = _string(
        current.get("reader_id") or current.get("source_id") or prior_reader or prior_source
    )
    previous_generation = (
        _nonnegative_int(previous.get("media_change_generation"), 0) if previous else 0
    )
    current_generation = _nonnegative_int(current.get("media_change_generation"), 0)
    if previous is None:
        kind = "unchanged"
    else:
        previous_present = media_identity.is_plausible_medium(
            {"medium_signals": _signals(previous)}
        )
        current_present = media_identity.is_plausible_medium({"medium_signals": _signals(current)})
        if not previous_present and current_present:
            kind = "populated"
        elif previous_present and not current_present:
            kind = "emptied"
        elif previous_present and current_present and current_generation > previous_generation:
            kind = "swapped"
        else:
            kind = "unchanged"
    changed = kind in {"populated", "emptied", "swapped"}
    return HotplugEvent(
        reader_id=reader_id,
        kind=kind,
        media_change_generation=current_generation,
        changed=changed,
    )


def detect_automount(
    source_id: str,
    *,
    mounts: Iterable[Mapping[str, Any]] = (),
    holders: Mapping[str, Iterable[Mapping[str, str]]] | None = None,
) -> dict[str, Any]:
    """Report whether a source is mounted/held. Never performs a remount."""
    inspection = storage_inspection.inspect_storage_state(
        {"source_id": source_id, "kernel_name": None, "children": []},
        mounts=mounts,
        holders=holders,
    )
    blockers = [
        blocker["reason"]
        for blocker in inspection.get("blockers", [])
        if isinstance(blocker, Mapping)
    ]
    return {
        "source_id": source_id,
        "mounts": inspection.get("mounts", []),
        "holders": inspection.get("holders", []),
        "mounted_read_write": any(
            mount.get("mode") == "rw" for mount in inspection.get("mounts", [])
        ),
        "automount_blockers": tuple(dict.fromkeys(blockers)),
    }


def assert_allowed_read_only_op(op: str) -> None:
    """Refuse any operation outside the fixed read-only allowlist."""
    if op not in ALLOWED_READ_ONLY_OPS or any(forbidden in op for forbidden in FORBIDDEN_OP_NAMES):
        raise ForbiddenOperationError("forbidden_operation", f"operation {op!r} is not allowed")


def read_geometry(device: Mapping[str, Any]) -> dict[str, Any]:
    """Read-only geometry facts for floppy/geometry-bearing media."""
    assert_allowed_read_only_op("geometry")
    geometry = device.get("geometry")
    if not isinstance(geometry, Mapping):
        return {"available": False, "geometry": None}
    allowed = ("cylinders", "heads", "sectors_per_track", "bytes_per_sector")
    cleaned = {key: geometry[key] for key in allowed if isinstance(geometry.get(key), int)}
    return {"available": bool(cleaned), "geometry": cleaned or None}


def read_optical_toc(device: Mapping[str, Any]) -> dict[str, Any]:
    """Read-only optical TOC/session facts for optical media."""
    assert_allowed_read_only_op("optical_toc")
    sessions = device.get("toc_sessions")
    if not isinstance(sessions, list):
        return {"available": False, "sessions": None}
    normalized = [
        {"start_sector": session["start_sector"], "length_sectors": session["length_sectors"]}
        for session in sessions
        if isinstance(session, Mapping)
        and isinstance(session.get("start_sector"), int)
        and isinstance(session.get("length_sectors"), int)
    ]
    return {"available": bool(normalized), "sessions": normalized or None}


def physical_lock_report(device: Mapping[str, Any]) -> PhysicalLockReport:
    """Report physical/capability write protection as informational evidence."""
    device_type = device.get("device_type")
    if device_type in {"optical", "optical_drive"}:
        write_once = _is_write_once(device)
        return PhysicalLockReport(
            write_protected=write_once,
            write_once=write_once,
            source="optical-write-once",
        )
    if bool(device.get("write_protected")) or bool(device.get("sd_lock")):
        return PhysicalLockReport(
            write_protected=True, write_once=False, source="sd-write-protect-switch"
        )
    if bool(device.get("read_only")):
        return PhysicalLockReport(write_protected=True, write_once=False, source="sysfs-ro")
    return PhysicalLockReport(write_protected=False, write_once=False, source="none")


def _prove_medium_identity(device: Mapping[str, Any]) -> tuple[bool, list[str], bool]:
    record = device.get("medium_identity")
    if not isinstance(record, Mapping):
        return False, ["missing_medium_identity_record"], bool(device.get("has_media"))
    validation = media_identity.validate_media_identity(record)
    medium_present = bool(record.get("has_medium"))
    if not validation.valid:
        return False, ["medium_identity_invalid"], medium_present
    if not medium_present:
        return False, ["no_medium_present"], False
    signals = record.get("medium_signals")
    fingerprint = (
        signals.get("sampled_fingerprint_sha256") if isinstance(signals, Mapping) else None
    )
    if not isinstance(fingerprint, str) or len(fingerprint) != 64:
        return False, ["medium_identity_weak_no_fingerprint"], True
    return True, [], True


def _signals(device: Mapping[str, Any]) -> Mapping[str, Any]:
    record = device.get("medium_identity")
    if isinstance(record, Mapping):
        signals = record.get("medium_signals")
        if isinstance(signals, Mapping):
            return signals
    return media_identity.normalize_medium_signals(device)


def _automount_notes(storage_state: Mapping[str, Any] | None) -> tuple[list[str], list[str]]:
    if not storage_state:
        return [], []
    blockers: list[str] = []
    warnings: list[str] = []
    for blocker in storage_state.get("blockers", []):
        reason = (
            str(blocker.get("reason", "storage_state_blocked"))
            if isinstance(blocker, Mapping)
            else "storage_state_blocked"
        )
        blockers.append(reason)
    for mount in storage_state.get("mounts", []):
        if isinstance(mount, Mapping) and mount.get("mode") == "ro":
            warnings.append("source_mounted_read_only")
    return blockers, warnings


def _is_write_once(device: Mapping[str, Any]) -> bool:
    model = str(device.get("model") or "").lower()
    media_type = str(device.get("media_type") or "").lower()
    combined = f"{model} {media_type}"
    return any(
        re.search(rf"\b{token}\b", combined) is not None for token in WRITE_ONCE_OPTICAL_MEDIA
    ) or bool(device.get("write_once"))


def _not_removable(source_id: str, reader_id: str, source_kind: str) -> PreparedSource:
    return PreparedSource(
        source_id=source_id,
        reader_id=reader_id,
        source_kind=source_kind,
        medium_present=False,
        medium_identity_proven=False,
        read_only_verified=False,
        physical_lock=PhysicalLockReport(False, False, "none"),
        automount_blockers=(),
        blockers=("not_a_removable_source",),
    )


def _string(value: object) -> str:
    return value if isinstance(value, str) else ""


def _nonnegative_int(value: object, default: int) -> int:
    if isinstance(value, int) and value >= 0:
        return value
    return default
