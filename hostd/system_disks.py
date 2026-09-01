"""Default active-system-disk denial for RPR-013.

This module evaluates sanitized device facts against injected protected uses
derived from mounts, swap, Reperio state, and container storage. It does not
mount, open, repair, or write any source device.
"""

from __future__ import annotations

import posixpath
import re
from collections.abc import Iterable, Mapping
from typing import Any

SYSTEM_DISK_OVERRIDE_WARNING = (
    "This source backs the running system. Scanning it can produce inconsistent recovery "
    "results or destabilize the host; keep this warning visible for the entire scan."
)

CRITICAL_MOUNTS = frozenset({"/", "/boot", "/boot/efi", "/usr", "/var"})
CONTAINER_STORAGE_PREFIXES = ("/var/lib/docker", "/var/lib/containers", "/var/lib/kubelet")
MAJOR_MINOR_RE = re.compile(r"^(0|[1-9][0-9]*):(0|[1-9][0-9]*)$")


class SystemDiskOverrideError(ValueError):
    """Raised when a system-disk override policy is absent or incomplete."""


def protected_uses_from_mounts(
    mounts: Iterable[Mapping[str, Any]], *, state_paths: Iterable[str] = ()
) -> list[dict[str, str]]:
    """Normalize mount records into protected source-use references.

    Each mount record needs ``mount_point`` and ``major_minor``. A root, boot,
    Reperio state path, or known container-storage path protects the backing
    major:minor by default.
    """
    state_path_set = {
        normalized for path in state_paths if (normalized := _normalize_path(path)) is not None
    }
    protected: list[dict[str, str]] = []
    for mount in mounts:
        mount_point = _normalize_path(str(mount.get("mount_point", "")))
        major_minor = str(mount.get("major_minor", ""))
        if mount_point is None or not _valid_major_minor(major_minor):
            continue
        reason = _mount_reason(mount_point, state_path_set)
        if reason is not None:
            protected.append(
                {"major_minor": major_minor, "reason": reason, "mount_point": mount_point}
            )
    return protected


def protected_uses_from_swaps(swaps: Iterable[Mapping[str, Any]]) -> list[dict[str, str]]:
    """Normalize active swap records into protected source-use references."""
    protected: list[dict[str, str]] = []
    for swap in swaps:
        major_minor = str(swap.get("major_minor", ""))
        if _valid_major_minor(major_minor):
            protected.append({"major_minor": major_minor, "reason": "active_swap"})
    return protected


def evaluate_system_disk_denial(
    device: Mapping[str, Any],
    protected_uses: Iterable[Mapping[str, str]],
    *,
    ancestry: Mapping[str, Iterable[str]] | None = None,
) -> dict[str, Any]:
    """Return default launch eligibility for one candidate source device."""
    source_major_minors = _source_major_minors(device)
    expanded_ancestry = _expand_ancestry(ancestry or {})
    reasons: list[dict[str, str]] = []

    for protected in protected_uses:
        protected_major_minor = protected.get("major_minor", "")
        if not _valid_major_minor(protected_major_minor):
            continue
        if _matches_source(source_major_minors, protected_major_minor, expanded_ancestry):
            reason = protected.get("reason", "protected_system_use")
            reasons.append(
                {
                    "reason": reason,
                    "protected_major_minor": protected_major_minor,
                    "detail": protected.get("mount_point", reason),
                }
            )

    return {
        "source_id": device.get("source_id"),
        "kernel_name": device.get("kernel_name"),
        "denied_by_default": bool(reasons),
        "override_required": bool(reasons),
        "denial_reasons": reasons,
    }


def require_system_disk_override(
    evaluation: Mapping[str, Any], policy: Mapping[str, Any]
) -> dict[str, Any]:
    """Validate and return persistent evidence for a launch-policy decision."""
    if not evaluation.get("denied_by_default"):
        return {"override_used": False, "persistent_warnings": []}
    if policy.get("allow_system_disk") is not True:
        raise SystemDiskOverrideError("system-disk source is denied by default")
    if policy.get("persistent_warning") != SYSTEM_DISK_OVERRIDE_WARNING:
        raise SystemDiskOverrideError("system-disk override requires the persistent warning text")
    if policy.get("operator_acknowledged") is not True:
        raise SystemDiskOverrideError("system-disk override requires operator acknowledgment")
    return {
        "override_used": True,
        "source_id": evaluation.get("source_id"),
        "persistent_warnings": [SYSTEM_DISK_OVERRIDE_WARNING],
        "denial_reasons": list(evaluation.get("denial_reasons", [])),
    }


def _source_major_minors(device: Mapping[str, Any]) -> set[str]:
    values = set()
    major_minor = device.get("major_minor")
    if isinstance(major_minor, str) and _valid_major_minor(major_minor):
        values.add(major_minor)
    children = device.get("children")
    if isinstance(children, list):
        for child in children:
            if isinstance(child, Mapping):
                child_major_minor = child.get("major_minor")
                if isinstance(child_major_minor, str) and _valid_major_minor(child_major_minor):
                    values.add(child_major_minor)
    return values


def _matches_source(
    source_major_minors: set[str], protected_major_minor: str, ancestry: Mapping[str, set[str]]
) -> bool:
    if protected_major_minor in source_major_minors:
        return True
    ancestors = ancestry.get(protected_major_minor, set())
    return bool(source_major_minors & ancestors)


def _expand_ancestry(ancestry: Mapping[str, Iterable[str]]) -> dict[str, set[str]]:
    expanded: dict[str, set[str]] = {}

    def visit(node: str, seen: set[str]) -> set[str]:
        if node in seen:
            return set()
        parents = {parent for parent in ancestry.get(node, []) if _valid_major_minor(parent)}
        result = set(parents)
        for parent in parents:
            result.update(visit(parent, seen | {node}))
        return result

    for node in ancestry:
        if _valid_major_minor(node):
            expanded[node] = visit(node, set())
    return expanded


def _mount_reason(mount_point: str, state_paths: set[str]) -> str | None:
    if mount_point in CRITICAL_MOUNTS:
        return f"critical_mount:{mount_point}"
    if any(_paths_overlap(mount_point, state_path) for state_path in state_paths):
        return "reperio_state"
    if any(_paths_overlap(mount_point, prefix) for prefix in CONTAINER_STORAGE_PREFIXES):
        return "container_storage"
    return None


def _paths_overlap(first: str, second: str) -> bool:
    return first == second or first.startswith(second + "/") or second.startswith(first + "/")


def _normalize_path(path: str) -> str | None:
    if not path.startswith("/") or "\x00" in path:
        return None
    return posixpath.normpath(path)


def _valid_major_minor(value: str) -> bool:
    return MAJOR_MINOR_RE.fullmatch(value) is not None
