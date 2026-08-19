"""Read-only nested disk and VM image inspection (RPR-165).

Safe adapters for prioritized raw/VHD/VHDX/VMDK/ISO containers copied into
scratch. Every adapter is read-only: no hypervisor starts and no mount ever
writes. Differencing/backing paths cannot escape the content store, recursion is
opt-in and depth/size/work-bounded, and child volumes normalize into findings.
Missing backing files and corrupt images are explicit outcomes. Pure and
dependency-free; container inspection is injected as a runner.
"""

from __future__ import annotations

import os
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Any

CONTAINER_IMAGES_VERSION = "container-images-v1"

CONTAINER_KINDS = frozenset({"raw", "vhd", "vhdx", "vmdk", "iso"})
DEFAULT_MAX_DEPTH = 3
DEFAULT_MAX_IMAGE_BYTES = 64 * 1024 * 1024 * 1024

Runner = Callable[[Mapping[str, Any]], Mapping[str, Any]]


class ContainerImagesError(ValueError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


@dataclass(frozen=True)
class ImageBudget:
    max_depth: int
    max_image_bytes: int
    max_work_items: int


def default_budget() -> ImageBudget:
    return ImageBudget(
        max_depth=DEFAULT_MAX_DEPTH,
        max_image_bytes=DEFAULT_MAX_IMAGE_BYTES,
        max_work_items=1000,
    )


def detect_container(kind_or_signature: str) -> str:
    """Detect the container kind from a normalized signature."""
    kind = kind_or_signature.lower()
    if kind in CONTAINER_KINDS:
        return kind
    signatures = {
        "vmdk": ("KDMV", "vmware"),
        "vhdx": ("vhdxfile", "msft"),
        "vhd": ("conectix", "microsoft virtual"),
        "iso": ("iso9660", "udf"),
    }
    lowered = kind_or_signature.lower()
    for candidate, markers in signatures.items():
        if any(marker.lower() in lowered for marker in markers):
            return candidate
    raise ContainerImagesError(
        "undetected_container", "no supported container kind could be detected"
    )


def nested_source_identity(
    *, kind: str, source_id: str, parent_id: str | None, depth: int
) -> dict[str, Any]:
    """Normalized nested-source identity with depth and parent linkage."""
    if depth < 0:
        raise ContainerImagesError("invalid_depth", "depth must be non-negative")
    return {
        "kind": kind,
        "source_id": source_id,
        "parent_id": parent_id,
        "depth": depth,
    }


def validate_backing_path(backing_path: str, content_store_root: str) -> str:
    """Backing/differencing paths must stay inside the content store."""
    normalized = os.path.normpath(backing_path)
    if normalized.startswith("..") or normalized in {"..", "."}:
        raise ContainerImagesError(
            "backing_escape", "backing path attempts to escape the content store"
        )
    root = os.path.normpath(content_store_root)
    if normalized != root and not normalized.startswith(root + os.sep):
        raise ContainerImagesError(
            "backing_escape", "backing path resolves outside the content store"
        )
    return normalized


def adapter_plan(
    *,
    kind: str,
    scratch_path: str,
    content_store_root: str,
    backing_path: str | None = None,
    budget: ImageBudget | None = None,
) -> dict[str, Any]:
    """Read-only adapter plan: no hypervisor, no write mount, scratch copy only."""
    detected = detect_container(kind)
    budget = budget or default_budget()
    plan: dict[str, Any] = {
        "version": CONTAINER_IMAGES_VERSION,
        "kind": detected,
        "scratch_path": scratch_path,
        "hypervisor_starts": False,
        "mount_write": False,
        "read_only": True,
        "budget": {
            "max_depth": budget.max_depth,
            "max_image_bytes": budget.max_image_bytes,
            "max_work_items": budget.max_work_items,
        },
    }
    if backing_path is not None:
        plan["backing_path"] = validate_backing_path(backing_path, content_store_root)
    return plan


def missing_backing_outcome() -> dict[str, Any]:
    """Explicit outcome when a differencing image's backing file is absent."""
    return {"status": "missing_backing", "reason": "backing file is not present", "read_only": True}


def corrupt_image_outcome() -> dict[str, Any]:
    """Explicit outcome for a corrupt or truncated image."""
    return {"status": "corrupt", "reason": "image header or data is corrupt", "read_only": True}


def recursion_allowed(*, opt_in: bool, depth: int, budget: ImageBudget) -> bool:
    """Recursion is opt-in and depth-bounded."""
    return opt_in and depth < budget.max_depth


def within_size_budget(size_bytes: int, budget: ImageBudget) -> bool:
    return size_bytes <= budget.max_image_bytes


def within_work_budget(work_items: int, budget: ImageBudget) -> bool:
    return work_items <= budget.max_work_items


def parse_child_volumes(image: Mapping[str, Any]) -> tuple[dict[str, Any], ...]:
    """Normalize child volume records from an inspected image."""
    children: list[dict[str, Any]] = []
    for index, volume in enumerate(image.get("volumes") or ()):
        if not isinstance(volume, dict):
            continue
        children.append(
            {
                "volume_id": f"{image.get('source_id') or 'image'}-v{index + 1}",
                "label": str(volume.get("label") or ""),
                "filesystem": str(volume.get("filesystem") or "unknown"),
                "size_bytes": _nonnegative_int(volume.get("size_bytes")),
                "parent_source_id": image.get("source_id"),
            }
        )
    return tuple(children)


def normalize_findings(image: Mapping[str, Any]) -> list[dict[str, Any]]:
    """Normalized findings for a container and its child volumes."""
    findings: list[dict[str, Any]] = []
    identity = nested_source_identity(
        kind=str(image.get("kind") or "raw"),
        source_id=str(image.get("source_id") or "unknown"),
        parent_id=image.get("parent_id"),
        depth=_nonnegative_int(image.get("depth")),
    )
    findings.append({**identity, "finding_type": "container_image"})
    for volume in parse_child_volumes(image):
        findings.append(
            {
                "kind": "child_volume",
                "source_id": volume["volume_id"],
                "parent_id": identity["source_id"],
                "depth": identity["depth"] + 1,
                "filesystem": volume["filesystem"],
                "finding_type": "child_volume",
            }
        )
    return findings


def run_adapter(plan: Mapping[str, Any], runner: Runner) -> dict[str, Any]:
    """Run the injected read-only adapter with normalized outcomes."""
    try:
        result = runner(plan)
    except Exception as exc:
        return {"status": "crashed", "reason": f"adapter crashed: {exc}", "read_only": True}
    outcome = {
        "status": str(result.get("status") or "ok"),
        "read_only": True,
        "hypervisor_started": False,
        "mount_write": False,
    }
    return outcome


def _nonnegative_int(value: Any) -> int:
    if isinstance(value, bool):
        return 0
    if isinstance(value, int) and value >= 0:
        return value
    return 0
