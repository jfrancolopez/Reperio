"""Deterministic Windows browser profile locator."""

from __future__ import annotations

import hashlib
from collections.abc import Iterable
from dataclasses import dataclass

from scanner.entry_normalization import NormalizedEntry
from worker.windows_profiles import WindowsUserProfile

CHROMIUM_MARKERS = frozenset(
    {"history", "bookmarks", "preferences", "secure preferences", "cookies"}
)
FIREFOX_MARKERS = frozenset({"places.sqlite", "prefs.js", "cookies.sqlite", "sessionstore.jsonlz4"})


@dataclass(frozen=True)
class BrowserProfile:
    browser_profile_id: str
    browser_family: str
    browser_name: str
    profile_path: str
    profile_name: str
    volume_id: str
    owner_profile_id: str | None
    owner_sid: str | None
    evidence: tuple[str, ...]
    companion_entry_ids: tuple[str, ...]
    portable: bool
    partial: bool


@dataclass
class _Candidate:
    browser_family: str
    profile_path: str
    profile_name: str
    evidence: set[str]
    entry_ids: set[str]


def locate_windows_browser_profiles(
    entries: Iterable[NormalizedEntry],
    windows_profiles: Iterable[WindowsUserProfile] = (),
) -> tuple[BrowserProfile, ...]:
    materialized = tuple(entries)
    owners = tuple(windows_profiles)
    candidates: dict[tuple[str, str, str], _Candidate] = {}
    for entry in materialized:
        detected = _detect_profile(entry)
        if detected is None:
            continue
        browser_name, browser_family, profile_path, profile_name, evidence = detected
        key = (entry.volume_id, browser_name, profile_path.lower())
        bucket = candidates.setdefault(
            key,
            _Candidate(browser_family, profile_path, profile_name, set(), set()),
        )
        bucket.evidence.add(evidence)
        bucket.entry_ids.add(entry.entry_id)

    profiles: list[BrowserProfile] = []
    for (volume_id, browser_name, _), facts in sorted(candidates.items()):
        profile_evidence = tuple(sorted(facts.evidence))
        if not _has_profile_artifact(profile_evidence):
            continue
        profile_path = facts.profile_path
        owner = _owner_for(profile_path, volume_id, owners)
        entry_ids = tuple(sorted(facts.entry_ids))
        profiles.append(
            BrowserProfile(
                browser_profile_id=_stable_id(volume_id, browser_name, profile_path),
                browser_family=facts.browser_family,
                browser_name=browser_name,
                profile_path=profile_path,
                profile_name=facts.profile_name,
                volume_id=volume_id,
                owner_profile_id=owner.profile_id if owner else None,
                owner_sid=owner.sid if owner else None,
                evidence=profile_evidence,
                companion_entry_ids=entry_ids,
                portable=owner is None,
                partial=len(profile_evidence) == 1,
            )
        )
    return tuple(profiles)


def _detect_profile(entry: NormalizedEntry) -> tuple[str, str, str, str, str] | None:
    parts = tuple(part for part in entry.display_path.replace("\\", "/").split("/") if part)
    lowered = tuple(part.lower() for part in parts)
    if not parts:
        return None
    chromium = _chromium_profile(parts, lowered)
    if chromium is not None:
        return chromium
    firefox = _firefox_profile(parts, lowered)
    if firefox is not None:
        return firefox
    return _portable_profile(parts, lowered)


def _chromium_profile(
    parts: tuple[str, ...], lowered: tuple[str, ...]
) -> tuple[str, str, str, str, str] | None:
    variants = (
        (("google", "chrome", "user data"), "Chrome"),
        (("microsoft", "edge", "user data"), "Edge"),
        (("bravesoftware", "brave-browser", "user data"), "Brave"),
        (("vivaldi", "user data"), "Vivaldi"),
        (("chromium", "user data"), "Chromium"),
    )
    for marker, browser_name in variants:
        index = _find_sequence(lowered, marker)
        if index is None or len(parts) <= index + len(marker):
            continue
        profile_index = index + len(marker)
        profile_name = parts[profile_index]
        if _artifact_evidence(parts[profile_index + 1 :], CHROMIUM_MARKERS) is None:
            continue
        profile_path = "/".join(parts[: profile_index + 1])
        return (
            browser_name,
            "chromium",
            profile_path,
            profile_name,
            _artifact_evidence(parts[profile_index + 1 :], CHROMIUM_MARKERS) or "chromium_profile",
        )
    opera_index = _find_sequence(lowered, ("opera software",))
    if opera_index is not None and len(parts) > opera_index + 1:
        profile_name = parts[opera_index + 1]
        evidence = _artifact_evidence(parts[opera_index + 2 :], CHROMIUM_MARKERS)
        if evidence is not None:
            return (
                "Opera",
                "chromium",
                "/".join(parts[: opera_index + 2]),
                profile_name,
                evidence,
            )
    return None


def _firefox_profile(
    parts: tuple[str, ...], lowered: tuple[str, ...]
) -> tuple[str, str, str, str, str] | None:
    marker = ("mozilla", "firefox", "profiles")
    index = _find_sequence(lowered, marker)
    if index is not None and len(parts) > index + len(marker):
        profile_index = index + len(marker)
        evidence = _artifact_evidence(parts[profile_index + 1 :], FIREFOX_MARKERS)
        if evidence is not None:
            profile_name = parts[profile_index]
            return (
                "Firefox",
                "firefox",
                "/".join(parts[: profile_index + 1]),
                profile_name,
                evidence,
            )
    tor_marker = ("tor browser", "browser", "torbrowser", "data", "browser")
    tor_index = _find_sequence(lowered, tor_marker)
    if tor_index is not None and len(parts) > tor_index + len(tor_marker):
        profile_index = tor_index + len(tor_marker)
        evidence = _artifact_evidence(parts[profile_index + 1 :], FIREFOX_MARKERS)
        if evidence is not None:
            profile_name = parts[profile_index]
            return (
                "Tor Browser",
                "firefox",
                "/".join(parts[: profile_index + 1]),
                profile_name,
                evidence,
            )
    return None


def _portable_profile(
    parts: tuple[str, ...], lowered: tuple[str, ...]
) -> tuple[str, str, str, str, str] | None:
    marker = ("googlechromeportable", "data", "profile")
    index = _find_sequence(lowered, marker)
    if index is not None:
        evidence = _artifact_evidence(parts[index + len(marker) :], CHROMIUM_MARKERS)
        if evidence is not None:
            profile_path = "/".join(parts[: index + len(marker)])
            return ("Chrome", "chromium", profile_path, "profile", evidence)
    return None


def _artifact_evidence(parts: tuple[str, ...], markers: frozenset[str]) -> str | None:
    for part in parts:
        lowered = part.lower()
        if lowered in markers:
            return lowered
    return None


def _has_profile_artifact(evidence: tuple[str, ...]) -> bool:
    return any(item in CHROMIUM_MARKERS or item in FIREFOX_MARKERS for item in evidence)


def _owner_for(
    profile_path: str, volume_id: str, profiles: tuple[WindowsUserProfile, ...]
) -> WindowsUserProfile | None:
    lowered = profile_path.lower()
    for profile in profiles:
        if profile.volume_id == volume_id and lowered.startswith(profile.root_path.lower() + "/"):
            return profile
    return None


def _find_sequence(parts: tuple[str, ...], sequence: tuple[str, ...]) -> int | None:
    if not sequence:
        return None
    last = len(parts) - len(sequence) + 1
    for index in range(max(last, 0)):
        if parts[index : index + len(sequence)] == sequence:
            return index
    return None


def _stable_id(*values: str) -> str:
    digest = hashlib.sha256("\0".join(values).encode("utf-8")).hexdigest()
    return f"browser-profile-{digest[:24]}"
