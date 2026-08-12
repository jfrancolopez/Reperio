"""Deterministic Windows installation and user-profile locator."""

from __future__ import annotations

import hashlib
from collections.abc import Iterable
from dataclasses import dataclass

from scanner.entry_normalization import NormalizedEntry

WELL_KNOWN_PROFILE_DIRS = frozenset({"desktop", "documents", "downloads", "pictures", "appdata"})


@dataclass(frozen=True)
class WindowsInstallation:
    installation_id: str
    volume_id: str
    root_path: str
    evidence: tuple[str, ...]
    registry_present: bool


@dataclass(frozen=True)
class WindowsUserProfile:
    profile_id: str
    installation_id: str | None
    volume_id: str
    root_path: str
    display_name: str
    sid: str | None
    evidence: tuple[str, ...]
    portable: bool = False


@dataclass(frozen=True)
class ProfileDiscoveryResult:
    installations: tuple[WindowsInstallation, ...]
    profiles: tuple[WindowsUserProfile, ...]


def discover_windows_profiles(entries: Iterable[NormalizedEntry]) -> ProfileDiscoveryResult:
    """Locate Windows installs and profiles using normalized path evidence only."""

    materialized = tuple(entries)
    installations = _installations(materialized)
    profiles = _profiles(materialized, installations)
    return ProfileDiscoveryResult(installations, profiles)


def _installations(entries: tuple[NormalizedEntry, ...]) -> tuple[WindowsInstallation, ...]:
    by_root: dict[tuple[str, str], set[str]] = {}
    registry: set[tuple[str, str]] = set()
    for entry in entries:
        parts = _parts(entry.display_path)
        if len(parts) < 2:
            continue
        if parts[0].lower() != "windows":
            continue
        key = (entry.volume_id, parts[0])
        if parts[1].lower() in {"system32", "syswow64", "winsxs"}:
            by_root.setdefault(key, set()).add(f"windows/{parts[1].lower()}")
        if [part.lower() for part in parts[1:4]] == ["system32", "config", "software"]:
            registry.add(key)
    result: list[WindowsInstallation] = []
    for key, evidence in sorted(by_root.items()):
        volume_id, root = key
        root_path = root
        result.append(
            WindowsInstallation(
                installation_id=_stable_id("win", volume_id, root_path),
                volume_id=volume_id,
                root_path=root_path,
                evidence=tuple(sorted(evidence)),
                registry_present=key in registry,
            )
        )
    return tuple(result)


def _profiles(
    entries: tuple[NormalizedEntry, ...], installations: tuple[WindowsInstallation, ...]
) -> tuple[WindowsUserProfile, ...]:
    candidates: dict[tuple[str, str], set[str]] = {}
    sids: dict[tuple[str, str], str] = {}
    for entry in entries:
        parts = _parts(entry.display_path)
        if len(parts) < 2:
            continue
        lower = [part.lower() for part in parts]
        root_path: str | None = None
        display_name: str | None = None
        if lower[0] == "users" and len(parts) >= 2:
            root_path = "/".join(parts[:2])
            display_name = parts[1]
        elif lower[0] == "documents and settings" and len(parts) >= 2:
            root_path = "/".join(parts[:2])
            display_name = parts[1]
        elif len(parts) >= 2 and any(part.lower() in WELL_KNOWN_PROFILE_DIRS for part in parts[1:]):
            root_path = parts[0]
            display_name = parts[0]
        if root_path is None or display_name is None:
            continue
        key = (entry.volume_id, root_path)
        candidates.setdefault(key, set()).add(_profile_evidence(parts))
        if entry.owner_id is not None and entry.owner_id.startswith("S-"):
            sids[key] = entry.owner_id
    profiles: list[WindowsUserProfile] = []
    for key, evidence in sorted(candidates.items()):
        volume_id, root_path = key
        display_name = root_path.rsplit("/", 1)[-1]
        installation = _matching_installation(volume_id, installations)
        portable = not root_path.lower().startswith(("users/", "documents and settings/"))
        profiles.append(
            WindowsUserProfile(
                profile_id=_stable_id("profile", volume_id, root_path, sids.get(key) or ""),
                installation_id=installation.installation_id if installation else None,
                volume_id=volume_id,
                root_path=root_path,
                display_name=display_name,
                sid=sids.get(key),
                evidence=tuple(sorted(evidence)),
                portable=portable,
            )
        )
    return tuple(profiles)


def _profile_evidence(parts: tuple[str, ...]) -> str:
    lowered = [part.lower() for part in parts]
    if "ntuser.dat" in lowered:
        return "ntuser.dat"
    for part in lowered:
        if part in WELL_KNOWN_PROFILE_DIRS:
            return f"well_known:{part}"
    return "profile_root"


def _matching_installation(
    volume_id: str, installations: tuple[WindowsInstallation, ...]
) -> WindowsInstallation | None:
    for installation in installations:
        if installation.volume_id == volume_id:
            return installation
    return None


def _parts(path: str) -> tuple[str, ...]:
    return tuple(part for part in path.replace("\\", "/").strip("/").split("/") if part)


def _stable_id(prefix: str, *values: str) -> str:
    digest = hashlib.sha256("\0".join(values).encode("utf-8")).hexdigest()
    return f"{prefix}-{digest[:24]}"
