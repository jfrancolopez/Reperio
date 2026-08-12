"""Evidence-only Windows software and utility inventory."""

from __future__ import annotations

import hashlib
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from typing import Any

from scanner.entry_normalization import NormalizedEntry
from worker.core_categories import CategoryResult
from worker.windows_profiles import WindowsUserProfile

INVENTORY_VERSION = "software-inventory-v1"


@dataclass(frozen=True)
class SoftwareEvidence:
    kind: str
    path: str
    details: Mapping[str, str]


@dataclass(frozen=True)
class SoftwareRecord:
    inventory_id: str
    name: str
    normalized_name: str
    publisher: str | None
    version: str | None
    install_time: str | None
    install_roots: tuple[str, ...]
    related_profile_ids: tuple[str, ...]
    evidence: tuple[SoftwareEvidence, ...]
    categories: tuple[str, ...]
    complete: bool


@dataclass(frozen=True)
class SoftwareInventoryResult:
    inventory_version: str
    records: tuple[SoftwareRecord, ...]
    warnings: tuple[str, ...]


def inventory_installed_software(
    entries: Iterable[NormalizedEntry],
    *,
    metadata_by_path: Mapping[str, Mapping[str, Any]] | None = None,
    categories_by_path: Mapping[str, CategoryResult] | None = None,
    profiles: Iterable[WindowsUserProfile] = (),
) -> SoftwareInventoryResult:
    """Build installed-software records from path/metadata evidence only."""

    metadata = {_norm_path(path): values for path, values in (metadata_by_path or {}).items()}
    categories = {_norm_path(path): value for path, value in (categories_by_path or {}).items()}
    profile_tuple = tuple(profiles)
    grouped: dict[str, list[_Candidate]] = {}
    warnings: list[str] = []
    for entry in entries:
        candidate = _candidate_for(
            entry, metadata.get(_norm_path(entry.display_path)), profile_tuple
        )
        if candidate is None:
            if _looks_like_app_folder(entry.display_path):
                warnings.append(f"false_positive_folder:{entry.display_path}")
            continue
        category = categories.get(_norm_path(entry.display_path))
        if category is not None and "software/code/databases" not in category.categories:
            warnings.append(f"non_software_category:{entry.display_path}")
            continue
        grouped.setdefault(candidate.key, []).append(candidate)
    records = tuple(_record_from(key, candidates) for key, candidates in sorted(grouped.items()))
    return SoftwareInventoryResult(INVENTORY_VERSION, records, tuple(dict.fromkeys(warnings)))


@dataclass(frozen=True)
class _Candidate:
    key: str
    name: str
    publisher: str | None
    version: str | None
    install_time: str | None
    install_root: str
    profile_id: str | None
    evidence: SoftwareEvidence
    complete: bool


def _candidate_for(
    entry: NormalizedEntry,
    metadata: Mapping[str, Any] | None,
    profiles: tuple[WindowsUserProfile, ...],
) -> _Candidate | None:
    path = _norm_path(entry.display_path)
    parts = tuple(part for part in path.split("/") if part)
    if metadata and metadata.get("display_name"):
        name = str(metadata["display_name"])
        publisher = _string(metadata.get("publisher"))
        version = _string(metadata.get("version"))
        install_time = _string(metadata.get("install_time"))
        root = (
            _string(metadata.get("install_location"))
            or _root_from_uninstall(parts)
            or entry.display_path
        )
        kind = "uninstall_registry"
        return _candidate(
            name, publisher, version, install_time, root, None, kind, entry.display_path
        )
    if len(parts) >= 3 and parts[0] == "program files" and parts[1] == "windowsapps":
        package = parts[2]
        name = package.split("_")[0]
        version = package.split("_")[1] if "_" in package else None
        return _candidate(
            name,
            None,
            version,
            None,
            "/".join(parts[:3]),
            None,
            "store_package",
            entry.display_path,
        )
    if (
        len(parts) >= 2
        and parts[0] in {"program files", "program files (x86)"}
        and entry.display_name.lower().endswith((".exe", ".dll"))
    ):
        root_parts = parts[:3] if len(parts) >= 3 else parts[:2]
        name = root_parts[-1]
        return _candidate(
            name,
            None,
            None,
            None,
            "/".join(root_parts),
            None,
            "application_directory",
            entry.display_path,
        )
    profile = _matching_profile(path, profiles)
    if profile is not None and entry.display_name.lower().endswith(".exe"):
        return _candidate(
            entry.display_name[:-4],
            None,
            None,
            None,
            entry.display_path.rsplit("/", 1)[0],
            profile.profile_id,
            "portable_app",
            entry.display_path,
        )
    return None


def _candidate(
    name: str,
    publisher: str | None,
    version: str | None,
    install_time: str | None,
    root: str,
    profile_id: str | None,
    kind: str,
    path: str,
) -> _Candidate:
    normalized_name = _norm_name(name)
    return _Candidate(
        key="|".join((normalized_name, publisher or "", version or "")),
        name=name,
        publisher=publisher,
        version=version,
        install_time=install_time,
        install_root=root,
        profile_id=profile_id,
        evidence=SoftwareEvidence(kind, path, {"name": name}),
        complete=kind != "uninstall_registry" or bool(publisher and version),
    )


def _record_from(key: str, candidates: list[_Candidate]) -> SoftwareRecord:
    first = candidates[0]
    publisher = first.publisher or _first(candidate.publisher for candidate in candidates)
    version = first.version or _first(candidate.version for candidate in candidates)
    install_time = _first(candidate.install_time for candidate in candidates)
    roots = tuple(
        sorted({candidate.install_root for candidate in candidates if candidate.install_root})
    )
    profiles = tuple(
        sorted({candidate.profile_id for candidate in candidates if candidate.profile_id})
    )
    evidence = tuple(candidate.evidence for candidate in candidates)
    return SoftwareRecord(
        inventory_id=_stable_id(key),
        name=first.name,
        normalized_name=first.key.split("|", 1)[0],
        publisher=publisher,
        version=version,
        install_time=install_time,
        install_roots=roots,
        related_profile_ids=profiles,
        evidence=evidence,
        categories=("software/code/databases",),
        complete=all(candidate.complete for candidate in candidates),
    )


def _root_from_uninstall(parts: tuple[str, ...]) -> str | None:
    if "uninstall" not in parts:
        return None
    return "/".join(parts)


def _matching_profile(
    path: str, profiles: tuple[WindowsUserProfile, ...]
) -> WindowsUserProfile | None:
    for profile in profiles:
        if path.startswith(_norm_path(profile.root_path) + "/"):
            return profile
    return None


def _looks_like_app_folder(path: str) -> bool:
    lowered = _norm_path(path)
    return lowered.startswith(("program files/", "program files (x86)/")) and not lowered.endswith(
        (".exe", ".dll")
    )


def _first(values: Iterable[str | None]) -> str | None:
    for value in values:
        if value:
            return value
    return None


def _string(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text or None


def _norm_name(value: str) -> str:
    return " ".join(value.casefold().replace("_", " ").replace("-", " ").split())


def _norm_path(value: str) -> str:
    return value.replace("\\", "/").strip("/").lower()


def _stable_id(value: str) -> str:
    return f"software-{hashlib.sha256(value.encode('utf-8')).hexdigest()[:24]}"
