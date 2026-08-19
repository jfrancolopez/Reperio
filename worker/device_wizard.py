"""New-scan device wizard planner (RPR-118).

Assembles sanitized device facts into grouped source cards (disk, flash/card,
optical, floppy/legacy), reports reader/media identity, mount, system-disk and
health facts, and decides whether a scan may start. A scan never starts
automatically: an explicit operator confirmation must match the current medium
identity, and changed, replaced, ambiguous, or unproven media are blocked with
clear reasons. This module performs no I/O and never opens source media.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any

from shared import media_identity

DEVICE_WIZARD_VERSION = "device-wizard-v1"

SOURCE_GROUPS = ("disk", "flash", "optical", "floppy")

CARD_STATES = ("ready", "needs_confirmation", "ambiguous", "blocked", "empty")

HEALTH_FAILED = frozenset({"failed", "critical"})

MOUNT_POINT_FIELDS = ("mount_points", "mounts")

MEDIUM_SIGNAL_COMPARISON_FIELDS = (
    "capacity_bytes",
    "geometry",
    "toc_sessions",
    "sampled_fingerprint_sha256",
)


class DeviceWizardError(ValueError):
    """Raised when wizard inputs are invalid or unsafe."""


@dataclass(frozen=True)
class SourceCard:
    source_id: str
    reader_id: str
    source_kind: str
    reader_kind: str
    group: str
    medium_present: bool
    medium_identity_proven: bool
    identity_strength: str
    identity_warnings: tuple[str, ...]
    model: str | None
    serial: str | None
    capacity_bytes: int | None
    transport: str | None
    geometry: object
    toc_sessions: object
    mounted: bool
    mount_points: tuple[str, ...]
    mounted_read_only: bool | None
    is_system_disk: bool
    system_uses: tuple[str, ...]
    health_state: str
    health_reasons: tuple[str, ...]
    read_only_verified: bool
    write_protected: bool
    disk_key: str | None
    expected_generation: int | None
    identity_record: Mapping[str, object]
    warnings: tuple[str, ...] = ()


@dataclass(frozen=True)
class StartEligibility:
    state: str
    block_reasons: tuple[str, ...] = ()
    warnings: tuple[str, ...] = ()


@dataclass(frozen=True)
class MediaChangeStatus:
    status: str
    reasons: tuple[str, ...] = ()


def source_group(source_kind: str) -> str:
    if source_kind in {"fixed_disk"}:
        return "disk"
    if source_kind in {"usb_flash", "memory_card"}:
        return "flash"
    if source_kind == "optical_disc":
        return "optical"
    if source_kind in {"floppy_media", "legacy_medium"}:
        return "floppy"
    raise DeviceWizardError("unknown_source_kind", f"no wizard group for {source_kind!r}")


def build_source_card(device: Mapping[str, object]) -> SourceCard:
    """Build one deterministic source card from sanitized device facts."""
    source_kind = media_identity.source_kind_for_device(device)
    identity = _identity_record(device)
    signals = _signals(identity)
    mount_points = _mount_points(device)
    mounted = bool(mount_points)
    health_state = str(device.get("health_state") or "unavailable")
    health_reasons = _string_tuple(device.get("health_reasons"))
    system_uses = _string_tuple(device.get("system_uses"))
    identity_warnings = list(_string_tuple(identity.get("warnings")))
    identity_warnings.extend(media_identity.identity_warnings_for(device, signals))
    if media_identity.is_removable(device) and not _optional_string(device.get("serial")):
        identity_warnings.append("missing_serial")
    warnings: list[str] = list(dict.fromkeys(identity_warnings))
    if health_state in {"failed", "critical"}:
        warnings.append("health_failed")
    elif health_state == "warning":
        warnings.append("health_warning")
    elif health_state in {"unavailable", "unknown"}:
        warnings.append("health_unavailable")
    if mounted and not bool(device.get("read_only")):
        warnings.append("source_mounted_read_write")
    return SourceCard(
        source_id=_required_string(device.get("source_id"), "source_id"),
        reader_id=str(device.get("reader_id") or device.get("source_id") or ""),
        source_kind=source_kind,
        reader_kind=media_identity.reader_kind_for_device(device),
        group=source_group(source_kind),
        medium_present=_medium_present(identity),
        medium_identity_proven=_identity_proven(identity),
        identity_strength=str(identity.get("identity_strength") or "unknown"),
        identity_warnings=tuple(dict.fromkeys(identity_warnings)),
        model=_optional_string(device.get("model")),
        serial=_optional_string(device.get("serial")),
        capacity_bytes=_positive_int(signals.get("capacity_bytes")),
        transport=_optional_string(device.get("transport")),
        geometry=signals.get("geometry"),
        toc_sessions=signals.get("toc_sessions"),
        mounted=mounted,
        mount_points=tuple(mount_points),
        mounted_read_only=bool(device.get("read_only")) if mounted else None,
        is_system_disk=bool(device.get("is_system_disk")),
        system_uses=tuple(system_uses),
        health_state=health_state,
        health_reasons=tuple(health_reasons),
        read_only_verified=bool(device.get("read_only_verified")),
        write_protected=bool(device.get("write_protected") or device.get("sd_lock")),
        disk_key=_optional_string(
            device.get("disk_key") or device.get("major_minor") or device.get("parent_disk_id")
        ),
        identity_record=identity,
        expected_generation=_nonnegative_int(device.get("media_change_generation")),
        warnings=tuple(dict.fromkeys(warnings)),
    )


def group_sources(devices: Sequence[Mapping[str, object]]) -> list[tuple[str, list[SourceCard]]]:
    """Group source cards in SOURCE_GROUPS order; each card belongs to one group."""
    grouped: dict[str, list[SourceCard]] = {group: [] for group in SOURCE_GROUPS}
    for device in devices:
        card = build_source_card(device)
        grouped[card.group].append(card)
    return [(group, grouped[group]) for group in SOURCE_GROUPS if grouped[group]]


def media_change_status(
    card: SourceCard, previous_record: Mapping[str, object] | None
) -> MediaChangeStatus:
    """Detect same, replaced, changed, or unproven media in the same reader.

    A replacement with the same capacity and no fingerprint cannot be
    distinguished and stays ``unproven`` (identity already weak). Replacing a
    disc/floppy in the same reader is ``replaced_medium`` and always requires a
    fresh confirmation.
    """
    if previous_record is None:
        return MediaChangeStatus("new")
    previous_signals = _signals(previous_record)
    previous_strength = str(previous_record.get("identity_strength") or "unknown")
    if previous_strength == "reader-facts" or not card.medium_identity_proven:
        return MediaChangeStatus("unproven", ("no_proven_medium_identity",))
    current_signals = _signals(card.identity_record)
    fingerprint = _normalized_fingerprint(current_signals.get("sampled_fingerprint_sha256"))
    previous_fingerprint = _normalized_fingerprint(
        previous_signals.get("sampled_fingerprint_sha256")
    )
    if fingerprint is None:
        return MediaChangeStatus("unproven", ("missing_fingerprint",))
    if previous_fingerprint and fingerprint != previous_fingerprint:
        return MediaChangeStatus("replaced_medium", ("fingerprint_mismatch",))
    changed = [
        field
        for field in MEDIUM_SIGNAL_COMPARISON_FIELDS
        if field != "sampled_fingerprint_sha256"
        and _normalized_value(current_signals.get(field))
        != _normalized_value(previous_signals.get(field))
    ]
    if changed:
        return MediaChangeStatus("changed_signals", tuple(f"{field}_changed" for field in changed))
    return MediaChangeStatus("same_medium")


def confirm_source(
    card: SourceCard,
    *,
    confirmation: Mapping[str, object] | None,
    previous_record: Mapping[str, object] | None = None,
    destination: Mapping[str, object] | None = None,
) -> StartEligibility:
    """Evaluate a single card for start; confirmation must match current medium."""
    reasons: list[str] = []
    warnings: list[str] = list(card.warnings)
    if not card.medium_present:
        return StartEligibility("empty", ("no_medium_present",), tuple(warnings))
    if not card.medium_identity_proven:
        return StartEligibility("ambiguous", ("medium_identity_unproven",), tuple(warnings))
    change = media_change_status(card, previous_record)
    if change.status in {"replaced_medium", "changed_signals"}:
        reasons.append("media_changed")
    if not _confirmation_matches(card, confirmation):
        reasons.append("confirmation_required")
    if card.is_system_disk:
        reasons.append("system_disk")
    if not card.read_only_verified:
        reasons.append("read_only_not_verified")
    if card.mounted and not card.mounted_read_only:
        reasons.append("source_mounted_read_write")
    if _destination_on_source_disk(card, destination):
        reasons.append("destination_on_source_disk")
    if card.health_state in HEALTH_FAILED:
        reasons.append("health_failed")

    if reasons:
        return StartEligibility("blocked", tuple(dict.fromkeys(reasons)), tuple(warnings))
    if change.status in {"replaced_medium", "changed_signals"}:
        return StartEligibility("needs_confirmation", (), tuple(warnings))
    return StartEligibility("ready", (), tuple(warnings))


def wizard_state(
    devices: Sequence[Mapping[str, object]],
    *,
    confirmations: Mapping[str, Mapping[str, object]] | None = None,
    previous_records: Mapping[str, Mapping[str, object]] | None = None,
    destination: Mapping[str, object] | None = None,
) -> dict[str, Any]:
    """Overall wizard state; never auto-selects or auto-starts a source."""
    confirmations = confirmations or {}
    previous_records = previous_records or {}
    destination = destination or {}
    cards = [build_source_card(device) for device in devices]
    per_card: list[dict[str, object]] = []
    for card in cards:
        eligibility = confirm_source(
            card,
            confirmation=confirmations.get(card.source_id),
            previous_record=previous_records.get(card.source_id),
            destination=destination,
        )
        per_card.append(
            {
                "source_id": card.source_id,
                "group": card.group,
                "state": eligibility.state,
                "block_reasons": list(eligibility.block_reasons),
                "warnings": list(eligibility.warnings),
                "card": card,
            }
        )
    ready = [item for item in per_card if item["state"] == "ready"]
    can_start = len(ready) == 1 and len(cards) == 1
    reasons: list[str] = []
    if len(cards) != 1:
        reasons.append("one_source_required")
    elif not ready:
        reasons.append("no_ready_source")
    return {
        "wizard_version": DEVICE_WIZARD_VERSION,
        "can_start": can_start,
        "cannot_start_reasons": reasons,
        "cards": per_card,
        "auto_started": False,
    }


def configuration_summary(
    card: SourceCard,
    *,
    destination: Mapping[str, object] | None = None,
    scratch: Mapping[str, object] | None = None,
    resource_profile: str = "default",
) -> dict[str, Any]:
    """Deterministic configuration summary shown before start."""
    destination = destination or {}
    scratch = scratch or {}
    return {
        "source": {
            "source_id": card.source_id,
            "reader_id": card.reader_id,
            "source_kind": card.source_kind,
            "reader_kind": card.reader_kind,
            "identity_strength": card.identity_strength,
            "capacity_bytes": card.capacity_bytes,
            "transport": card.transport,
            "geometry": card.geometry,
            "toc_sessions": card.toc_sessions,
        },
        "destination": {
            "separate_from_source": bool(destination.get("separate_from_source")),
            "kind": destination.get("kind"),
        },
        "scratch": {
            "separate_from_source": bool(scratch.get("separate_from_source")),
            "kind": scratch.get("kind"),
        },
        "resource_profile": resource_profile,
        "safety": {
            "read_only_verified": card.read_only_verified,
            "write_protected": card.write_protected,
            "medium_identity_proven": card.medium_identity_proven,
            "is_system_disk": card.is_system_disk,
        },
    }


def _identity_record(device: Mapping[str, object]) -> Mapping[str, object]:
    identity = device.get("medium_identity")
    if isinstance(identity, Mapping):
        return identity
    return {}


def _signals(identity: Mapping[str, object]) -> Mapping[str, object]:
    signals = identity.get("medium_signals")
    if isinstance(signals, Mapping):
        return signals
    return {}


def _identity_proven(identity: Mapping[str, object]) -> bool:
    strength = str(identity.get("identity_strength") or "")
    return strength in media_identity.IDENTITY_STRENGTHS and strength != "reader-facts"


def _medium_present(identity: Mapping[str, object]) -> bool:
    signals = _signals(identity)
    if _positive_int(signals.get("capacity_bytes")) is not None:
        return True
    return _normalized_fingerprint(signals.get("sampled_fingerprint_sha256")) is not None


def _confirmation_matches(card: SourceCard, confirmation: Mapping[str, object] | None) -> bool:
    if not isinstance(confirmation, Mapping) or not confirmation:
        return False
    source_match = confirmation.get("source_id") == card.source_id
    generation = confirmation.get("media_change_generation")
    if not isinstance(generation, int) or generation < 0:
        return False
    if card.expected_generation is not None and generation != card.expected_generation:
        return False
    return bool(source_match)


def _destination_on_source_disk(card: SourceCard, destination: Mapping[str, object] | None) -> bool:
    if not isinstance(destination, Mapping) or not card.disk_key:
        return False
    destination_key = destination.get("disk_key")
    return isinstance(destination_key, str) and destination_key == card.disk_key


def _mount_points(device: Mapping[str, object]) -> list[str]:
    points: list[str] = []
    for field in MOUNT_POINT_FIELDS:
        value = device.get(field)
        if isinstance(value, list | tuple):
            points.extend(str(item) for item in value if isinstance(item, str))
    return list(dict.fromkeys(points))


def _required_string(value: object, name: str) -> str:
    if isinstance(value, str) and value:
        return value
    raise DeviceWizardError("missing_field", f"{name} must be a non-empty string")


def _optional_string(value: object) -> str | None:
    return str(value) if isinstance(value, str) and value else None


def _positive_int(value: object) -> int | None:
    if isinstance(value, int) and value > 0:
        return value
    return None


def _nonnegative_int(value: object) -> int | None:
    if isinstance(value, int) and value >= 0:
        return value
    return None


def _string_tuple(value: object) -> tuple[str, ...]:
    if isinstance(value, list | tuple):
        return tuple(str(item) for item in value if isinstance(item, str))
    return ()


def _normalized_fingerprint(value: object) -> str | None:
    if isinstance(value, str) and value:
        return value.lower()
    return None


def _normalized_value(value: object) -> object:
    return value
