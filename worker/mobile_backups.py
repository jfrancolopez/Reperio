"""Locate iOS/Finder and Android backup layouts without parsing active content."""

from __future__ import annotations

import hashlib
import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from typing import Any

from scanner.entry_normalization import NormalizedEntry
from worker.backup_locators import BackupCandidate

MOBILE_BACKUP_VERSION = "mobile-backups-v1"
IOS_HASH_RE = re.compile(r"^[0-9a-f]{40}$")


@dataclass(frozen=True)
class MobileBackupRecord:
    backup_id: str
    platform: str
    layout: str
    root_path: str
    device_name: str | None
    device_identifier: str | None
    encrypted: bool | None
    complete: bool
    supported: bool
    evidence: tuple[str, ...]
    warnings: tuple[str, ...]


@dataclass(frozen=True)
class MobileBackupResult:
    mobile_backup_version: str
    records: tuple[MobileBackupRecord, ...]
    warnings: tuple[str, ...]


def locate_mobile_backups(
    entries: Iterable[NormalizedEntry],
    *,
    metadata_by_path: Mapping[str, Mapping[str, Any]] | None = None,
    backup_candidates: Iterable[BackupCandidate] = (),
) -> MobileBackupResult:
    """Detect mobile backup layouts from path and inert manifest metadata only."""

    entry_tuple = tuple(entries)
    metadata = {_norm_path(path): value for path, value in (metadata_by_path or {}).items()}
    candidate_roots = tuple(_norm_path(candidate.display_path) for candidate in backup_candidates)
    roots = _roots(entry_tuple, candidate_roots)
    records_list: list[MobileBackupRecord] = []
    for root in sorted(roots):
        record = _record(root, entry_tuple, metadata)
        if record is not None:
            records_list.append(record)
    records = tuple(records_list)
    warnings: list[str] = []
    for record in records:
        warnings.extend(record.warnings)
    return MobileBackupResult(MOBILE_BACKUP_VERSION, records, tuple(dict.fromkeys(warnings)))


def _roots(entries: tuple[NormalizedEntry, ...], candidate_roots: tuple[str, ...]) -> set[str]:
    roots: set[str] = set()
    for entry in entries:
        path = _norm_path(entry.display_path)
        parts = tuple(part for part in path.split("/") if part)
        for index, part in enumerate(parts):
            if (
                part == "backup"
                and index >= 1
                and parts[index - 1]
                in {
                    "mobilesync",
                    "mobile sync",
                }
                and len(parts) > index + 1
            ):
                roots.add("/".join(parts[: index + 2]))
            if part == "android" and len(parts) > index + 1:
                roots.add("/".join(parts[: index + 2]))
        if path.endswith(".ab"):
            roots.add(path)
    for root in candidate_roots:
        if "mobilebackup" in root or root.endswith(".ab"):
            roots.add(root)
    return roots


def _record(
    root: str,
    entries: tuple[NormalizedEntry, ...],
    metadata: Mapping[str, Mapping[str, Any]],
) -> MobileBackupRecord | None:
    children = tuple(
        entry for entry in entries if _norm_path(entry.display_path).startswith(root + "/")
    )
    if root.endswith(".ab"):
        return _android_record(root, (), metadata.get(root), direct_file=True)
    if not children:
        return None
    if "/mobilesync/backup/" in f"/{root}/" or "/mobile sync/backup/" in f"/{root}/":
        return _ios_record(root, children, metadata)
    if "/android/" in f"/{root}/":
        return _android_record(root, children, metadata.get(root), direct_file=False)
    return None


def _ios_record(
    root: str,
    children: tuple[NormalizedEntry, ...],
    metadata: Mapping[str, Mapping[str, Any]],
) -> MobileBackupRecord:
    leaf = root.rsplit("/", 1)[-1]
    evidence = ["layout:ios_mobile_sync_backup"]
    warnings: list[str] = []
    if IOS_HASH_RE.match(leaf):
        evidence.append("hashed_backup_folder")
    else:
        warnings.append("moved_or_renamed_backup_folder")
    child_names = {_norm_path(child.display_name) for child in children}
    complete = {"manifest.db", "manifest.plist", "status.plist"}.issubset(child_names)
    if not complete:
        warnings.append("partial_backup")
    manifest_path = next(
        (
            _norm_path(child.display_path)
            for child in children
            if _norm_path(child.display_name) == "manifest.plist"
        ),
        root,
    )
    manifest = metadata.get(manifest_path, {})
    encrypted = _bool_or_none(manifest.get("IsEncrypted"))
    if encrypted:
        warnings.append("encrypted_backup_visible")
    return MobileBackupRecord(
        backup_id=_stable_id("ios", root),
        platform="ios",
        layout="itunes_finder",
        root_path=root,
        device_name=_string(manifest.get("Device Name")),
        device_identifier=_string(manifest.get("Unique Identifier")) or leaf
        if IOS_HASH_RE.match(leaf)
        else None,
        encrypted=encrypted,
        complete=complete,
        supported=True,
        evidence=tuple(dict.fromkeys(evidence)),
        warnings=tuple(dict.fromkeys(warnings)),
    )


def _android_record(
    root: str,
    children: tuple[NormalizedEntry, ...],
    metadata: Mapping[str, Any] | None,
    *,
    direct_file: bool,
) -> MobileBackupRecord:
    evidence = ["layout:android_ab" if direct_file else "layout:android_directory"]
    warnings: list[str] = []
    complete = direct_file or any(
        _norm_path(child.display_name) in {"manifest.json", "backup.ab"} for child in children
    )
    if not complete:
        warnings.append("partial_backup")
    supported = direct_file or bool(metadata and metadata.get("supported_layout"))
    if not supported:
        warnings.append("unsupported_android_layout_visible")
    encrypted = _bool_or_none((metadata or {}).get("encrypted"))
    if encrypted:
        warnings.append("encrypted_backup_visible")
    return MobileBackupRecord(
        backup_id=_stable_id("android", root),
        platform="android",
        layout="android_ab" if direct_file else "android_directory",
        root_path=root,
        device_name=_string((metadata or {}).get("device_name")),
        device_identifier=_string((metadata or {}).get("device_identifier")),
        encrypted=encrypted,
        complete=complete,
        supported=supported,
        evidence=tuple(dict.fromkeys(evidence)),
        warnings=tuple(dict.fromkeys(warnings)),
    )


def _bool_or_none(value: Any) -> bool | None:
    if value is None:
        return None
    if isinstance(value, bool):
        return value
    return str(value).strip().casefold() in {"true", "1", "yes"}


def _string(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text or None


def _norm_path(path: str) -> str:
    return path.replace("\\", "/").strip("/").lower()


def _stable_id(*values: str) -> str:
    return f"mobile-{hashlib.sha256(chr(0).join(values).encode('utf-8')).hexdigest()[:24]}"
