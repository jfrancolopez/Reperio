"""Locate backup, virtual-machine, and sync-root artifacts deterministically."""

from __future__ import annotations

import hashlib
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from pathlib import PurePosixPath
from typing import Any

from scanner.entry_normalization import NormalizedEntry
from worker.core_categories import CategoryResult
from worker.windows_profiles import WindowsUserProfile

LOCATOR_VERSION = "backup-locators-v1"


@dataclass(frozen=True)
class LocatorPolicy:
    schedule_nested: bool = False
    max_nested_depth: int = 1
    max_scheduled_items: int = 128


@dataclass(frozen=True)
class BackupCandidate:
    candidate_id: str
    kind: str
    display_path: str
    profile_id: str | None
    nested_depth: int
    schedule_scan: bool
    evidence: tuple[str, ...]
    warnings: tuple[str, ...]


@dataclass(frozen=True)
class BackupLocatorResult:
    locator_version: str
    candidates: tuple[BackupCandidate, ...]
    warnings: tuple[str, ...]


def locate_backup_artifacts(
    entries: Iterable[NormalizedEntry],
    *,
    profiles: Iterable[WindowsUserProfile] = (),
    categories_by_path: Mapping[str, CategoryResult] | None = None,
    metadata_by_path: Mapping[str, Mapping[str, Any]] | None = None,
    policy: LocatorPolicy = LocatorPolicy(),
) -> BackupLocatorResult:
    """Inventory backup-like artifacts and schedule only by bounded explicit policy."""

    profile_tuple = tuple(profiles)
    categories = {_norm_path(path): value for path, value in (categories_by_path or {}).items()}
    metadata = {_norm_path(path): value for path, value in (metadata_by_path or {}).items()}
    candidates: list[BackupCandidate] = []
    warnings: list[str] = []
    scheduled = 0
    for entry in entries:
        candidate = _candidate_for(
            entry,
            profile_tuple,
            categories.get(_norm_path(entry.display_path)),
            metadata.get(_norm_path(entry.display_path)),
            policy,
            scheduled,
        )
        if candidate is None:
            continue
        if candidate.schedule_scan:
            scheduled += 1
        candidates.append(candidate)
        warnings.extend(candidate.warnings)
    return BackupLocatorResult(
        LOCATOR_VERSION,
        tuple(sorted(candidates, key=lambda item: item.display_path.lower())),
        tuple(dict.fromkeys(warnings)),
    )


def _candidate_for(
    entry: NormalizedEntry,
    profiles: tuple[WindowsUserProfile, ...],
    category: CategoryResult | None,
    metadata: Mapping[str, Any] | None,
    policy: LocatorPolicy,
    scheduled_count: int,
) -> BackupCandidate | None:
    path = _norm_path(entry.display_path)
    suffix = PurePosixPath(path).suffix.lower()
    evidence: list[str] = []
    warnings: list[str] = []
    kind: str | None = None
    if entry.entry_type == "symlink":
        warnings.append("symlink_like_entry_not_scheduled")
    if _has(path, "windowsimagebackup"):
        kind = "windows_backup"
        evidence.append("path:windowsimagebackup")
    elif _has(path, "filehistory"):
        kind = "file_history"
        evidence.append("path:filehistory")
    elif suffix in {".vhd", ".vhdx", ".vmdk", ".qcow2", ".vdi"}:
        kind = "disk_or_vm_image"
        evidence.append(f"extension:{suffix}")
    elif _has(path, "itunes", "mobilebackup", "android backup") or suffix in {".ipa", ".ab"}:
        kind = "phone_backup"
        evidence.append(f"phone_backup_signal:{suffix or 'path'}")
    elif _has(path, "onedrive", "dropbox", "google drive"):
        kind = "sync_root"
        evidence.append("sync_root_path")
    elif suffix in {".bkf", ".bak"} or _has(path, "backup"):
        kind = "generic_backup"
        evidence.append(f"generic_backup_signal:{suffix or 'path'}")
    if category is not None and "backups/mobile" in category.categories:
        kind = kind or "generic_backup"
        evidence.append("category:backups/mobile")
    if kind is None:
        return None
    if metadata and metadata.get("catalog_state") == "broken":
        warnings.append("broken_catalog")
        evidence.append("catalog_state:broken")
    nested_depth = _nested_depth(path)
    schedule = _schedule(kind, entry, nested_depth, policy, scheduled_count)
    if nested_depth > 0:
        evidence.append(f"nested_depth:{nested_depth}")
    if not schedule:
        warnings.append("not_scheduled_by_policy")
    profile = _matching_profile(path, profiles)
    if profile is not None:
        evidence.append(f"profile:{profile.profile_id}")
    return BackupCandidate(
        candidate_id=_stable_id(entry.volume_id, entry.display_path, kind),
        kind=kind,
        display_path=entry.display_path,
        profile_id=profile.profile_id if profile else None,
        nested_depth=nested_depth,
        schedule_scan=schedule,
        evidence=tuple(dict.fromkeys(evidence)),
        warnings=tuple(dict.fromkeys(warnings)),
    )


def _schedule(
    kind: str,
    entry: NormalizedEntry,
    nested_depth: int,
    policy: LocatorPolicy,
    scheduled_count: int,
) -> bool:
    if entry.entry_type == "symlink":
        return False
    if kind == "sync_root":
        return False
    if scheduled_count >= policy.max_scheduled_items:
        return False
    if nested_depth == 0:
        return True
    return policy.schedule_nested and nested_depth <= policy.max_nested_depth


def _nested_depth(path: str) -> int:
    markers = (".vhd/", ".vhdx/", ".vmdk/", ".qcow2/", ".vdi/", ".zip/")
    return sum(path.count(marker) for marker in markers)


def _matching_profile(
    path: str, profiles: tuple[WindowsUserProfile, ...]
) -> WindowsUserProfile | None:
    for profile in profiles:
        if path.startswith(_norm_path(profile.root_path) + "/"):
            return profile
    return None


def _has(path: str, *fragments: str) -> bool:
    return any(fragment in path for fragment in fragments)


def _norm_path(path: str) -> str:
    return path.replace("\\", "/").strip("/").lower()


def _stable_id(*values: str) -> str:
    return f"backup-{hashlib.sha256(chr(0).join(values).encode('utf-8')).hexdigest()[:24]}"
