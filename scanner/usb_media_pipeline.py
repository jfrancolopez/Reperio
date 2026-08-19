"""USB flash and memory-card deep-pipeline planning (RPR-181).

Deterministically classifies the removable medium family, decides partitioned
versus partitionless/superfloppy versus lost-partition layout, plans the deep
pipeline stages (enumeration, deleted-entry recovery, bounded carving,
classification, export), tags distinct provenance for allocated/hidden/trashed/
deleted/carved findings, and derives UI-visible flash capability states without
ever declaring unrecoverable blocks "clean".
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any

from scanner.lost_volume_candidates import LostVolumeCandidate
from scanner.partition_discovery import PartitionDiscoveryResult

USB_PIPELINE_VERSION = "usb-deep-pipeline-v1"

MEDIUM_FAMILIES = frozenset({"usb_flash", "memory_card"})
CARD_TYPES = frozenset(
    {
        "sd_card",
        "microsd",
        "compactflash",
        "memory_stick",
        "smartmedia",
        "mmc",
        "microdrive",
        "unknown",
    }
)
PARTITION_MODES = frozenset(
    {"partitioned", "partitionless_superfloppy", "lost_partition", "raw_unallocated"}
)
PROVENANCE_KINDS = frozenset({"allocated", "hidden", "trashed", "deleted", "carved"})

STAGE_VOLUMES = "volumes"
STAGE_ENUMERATION = "enumeration"
STAGE_DELETED_RECOVERY = "deleted_recovery"
STAGE_CARVING = "carving"
STAGE_CLASSIFICATION = "classification"
STAGE_EXPORT = "export"

TRASH_PATH_MARKERS = (".trash", ".trashes", "$recycle.bin", "found.000")
HIDDEN_NAME_PREFIX = "."
DCIM_PATH_MARKERS = ("/dcim/", "/dcim_", "100ncdng", "dcim/")
BACKUP_PATH_MARKERS = ("/backup", "/backups", "backup/", "portable_backup")
CARVING_BUDGET_BYTES = 64 * 1024 * 1024

CARD_TYPE_MARKERS = {
    "microsd": ("microsd", "micro_sd", "micro sd"),
    "compactflash": ("compactflash", "compact flash", "cf"),
    "memory_stick": ("memorystick", "memory stick", "ms"),
    "smartmedia": ("smartmedia", "smart media"),
    "mmc": ("mmc", "mmcplus", "mmc_plus"),
    "microdrive": ("microdrive", "micro drive"),
    "sd_card": ("sd", "sdxc", "sdhc"),
}


class UsbMediaPipelineError(ValueError):
    """Raised when USB media pipeline inputs are invalid or unsafe."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


@dataclass(frozen=True)
class MediumFamily:
    family: str
    card_type: str = "unknown"
    basis: str = ""

    def validate(self) -> None:
        if self.family not in MEDIUM_FAMILIES:
            raise UsbMediaPipelineError("invalid_family", "medium family is not supported")
        if self.card_type not in CARD_TYPES:
            raise UsbMediaPipelineError("invalid_card_type", "card type is not supported")


@dataclass(frozen=True)
class PartitioningMode:
    mode: str
    reasons: tuple[str, ...] = ()
    root_volume_offset_bytes: int = 0


@dataclass(frozen=True)
class ProvenanceClassification:
    provenance: str
    reasons: tuple[str, ...] = ()

    def validate(self) -> None:
        if self.provenance not in PROVENANCE_KINDS:
            raise UsbMediaPipelineError("invalid_provenance", "provenance kind is not recognized")


@dataclass(frozen=True)
class FlashCapabilityState:
    states: frozenset[str]
    can_verify_clean: bool
    warnings: tuple[str, ...] = ()


@dataclass(frozen=True)
class InterestRanking:
    boosted: bool
    boost_reason: str
    preserves_other_findings: bool = True


@dataclass(frozen=True)
class CarveRange:
    offset_bytes: int
    length_bytes: int


def classify_medium_family(
    device: Mapping[str, Any],
    *,
    card_type_hint: str | None = None,
) -> MediumFamily:
    """Classify a removable device into a medium family and card type."""
    family = device.get("source_kind") or device.get("family")
    if family in ("usb_flash", "memory_card"):
        return MediumFamily(family, _card_type(card_type_hint or device.get("card_type")))
    device_type = str(device.get("device_type") or "").lower()
    if "usb" in device_type or device_type == "usb_storage":
        return MediumFamily("usb_flash", "unknown", "usb_storage")
    if device_type in ("sd_card", "removable"):
        return MediumFamily("memory_card", _card_type(card_type_hint), "removable_reader")
    raise UsbMediaPipelineError(
        "unsupported_medium", "device is not a USB flash or memory-card medium"
    )


def determine_partitioning_mode(
    partition_result: PartitionDiscoveryResult | None,
    *,
    lost_candidates: Sequence[LostVolumeCandidate] = (),
    source_size_bytes: int = 0,
) -> PartitioningMode:
    """Decide partitioned versus partitionless/superfloppy versus lost layout."""
    if source_size_bytes < 0:
        raise UsbMediaPipelineError("invalid_media_size", "media size must not be negative")

    if partition_result is not None:
        allocated = [p for p in partition_result.partitions if p.allocated]
        if allocated:
            return PartitioningMode("partitioned", ("allocated_partitions",))
        warnings = partition_result.warnings
        if "partition_table_missing" in warnings or "no_partitions" in warnings:
            return _partitionless_or_lost(lost_candidates)
        return PartitioningMode("raw_unallocated", tuple(warnings))

    return _partitionless_or_lost(lost_candidates)


def _partitionless_or_lost(candidates: Sequence[LostVolumeCandidate]) -> PartitioningMode:
    root = [c for c in candidates if c.offset_bytes == 0]
    if root:
        return PartitioningMode(
            "partitionless_superfloppy",
            ("superfloppy_root_volume",),
            root_volume_offset_bytes=0,
        )
    if candidates:
        return PartitioningMode("lost_partition", ("lost_volume_candidates",))
    return PartitioningMode("raw_unallocated", ("no_partition_table_no_signatures",))


def deep_pipeline_plan(mode: str, *, enable_carving: bool = True) -> tuple[str, ...]:
    """Return the ordered deep-pipeline stages for a partitioning mode."""
    if mode not in PARTITION_MODES:
        raise UsbMediaPipelineError("invalid_mode", "partitioning mode is not supported")
    plan = [STAGE_VOLUMES, STAGE_ENUMERATION, STAGE_DELETED_RECOVERY]
    if enable_carving:
        plan.append(STAGE_CARVING)
    plan.extend((STAGE_CLASSIFICATION, STAGE_EXPORT))
    return tuple(plan)


def remaining_stages(plan: Sequence[str], completed: Sequence[str]) -> tuple[str, ...]:
    """Return the stages still pending for resume after a disconnect."""
    completed_set = set(completed)
    return tuple(stage for stage in plan if stage not in completed_set)


def bounded_carve_ranges(
    media_size_bytes: int,
    *,
    budget_bytes: int = CARVING_BUDGET_BYTES,
) -> tuple[CarveRange, ...]:
    """Bounded unallocated/whole-medium carve plan that never covers the source."""
    if media_size_bytes <= 0 or budget_bytes <= 0:
        raise UsbMediaPipelineError("invalid_carve_bounds", "carve bounds must be positive")
    ranges: list[CarveRange] = []
    remaining = budget_bytes
    offset = 0
    while remaining > 0 and offset < media_size_bytes:
        length = min(remaining, media_size_bytes - offset)
        ranges.append(CarveRange(offset, length))
        remaining -= length
        offset += length
    return tuple(ranges)


def classify_provenance(
    *,
    allocated: bool,
    entry_type: str,
    path: str,
    attributes: Sequence[str] = (),
) -> ProvenanceClassification:
    """Tag distinct provenance for allocated, hidden, trashed, deleted, carved."""
    lowered = path.lower()
    if not allocated:
        return ProvenanceClassification("deleted", ("not_allocated",))
    if any(marker in lowered for marker in TRASH_PATH_MARKERS):
        return ProvenanceClassification("trashed", ("trash_path",))
    name = path.rsplit("/", 1)[-1]
    if name.startswith(HIDDEN_NAME_PREFIX) or "hidden" in attributes:
        return ProvenanceClassification("hidden", ("hidden_attribute_or_dotname",))
    if entry_type == "carved":
        return ProvenanceClassification("carved", ("carved_source",))
    return ProvenanceClassification("allocated", ("allocated_entry",))


def flash_capability_state(device: Mapping[str, Any]) -> FlashCapabilityState:
    """Derive bounded TRIM/GC/wear-leveling/continued-use UI states."""
    states: set[str] = set()
    warnings: list[str] = []
    if bool(device.get("trim_supported")):
        states.add("trim_supported")
    if bool(device.get("garbage_collection_active")):
        states.add("garbage_collection_active")
    if bool(device.get("wear_leveling_active")):
        states.add("wear_leveling_active")
    continued_use = str(device.get("continued_use_limit") or "").lower()
    if continued_use and continued_use not in {"none", "unknown", ""}:
        states.add("continued_use_limited")
    elif device.get("continued_use_limit") in (None, "unknown"):
        warnings.append("continued_use_limit_unknown")
    if not states:
        states.add("unknown")
        warnings.append("flash_capabilities_unknown")
    can_verify_clean = (
        bool(device.get("trim_supported"))
        and "cannot_verify_clean" not in {str(value).lower() for value in device.values()}
        and not bool(device.get("unrecoverable_blocks"))
    )
    if device.get("unrecoverable_blocks"):
        warnings.append("unrecoverable_blocks_present")
    return FlashCapabilityState(frozenset(states), can_verify_clean, tuple(dict.fromkeys(warnings)))


def dcim_interest_ranking(path: str) -> InterestRanking:
    """Boost camera/DCIM and portable-backup content without hiding other files."""
    lowered = path.lower()
    if any(marker in lowered for marker in DCIM_PATH_MARKERS):
        return InterestRanking(True, "dcim_camera_content")
    if any(marker in lowered for marker in BACKUP_PATH_MARKERS):
        return InterestRanking(True, "portable_backup_content")
    return InterestRanking(False, "no_boost")


def _card_type(value: Any) -> str:
    if value is None:
        return "unknown"
    normalized = str(value).strip().lower()
    for card_type, markers in CARD_TYPE_MARKERS.items():
        if normalized in markers or any(marker in normalized for marker in markers):
            return card_type
    return "unknown"
