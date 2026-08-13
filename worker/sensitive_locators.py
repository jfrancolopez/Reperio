"""Evidence-only wallet, vault, key, and certificate locators."""

from __future__ import annotations

import hashlib
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from pathlib import PurePosixPath
from typing import Any

from scanner.entry_normalization import NormalizedEntry
from worker.core_categories import CategoryResult
from worker.windows_profiles import WindowsUserProfile

LOCATOR_VERSION = "sensitive-locators-v1"
SECRET_MARKERS = ("secret", "private_key", "mnemonic", "seed_phrase", "password", "decrypted")


@dataclass(frozen=True)
class SensitiveFinding:
    finding_id: str
    locator_version: str
    artifact_type: str
    display_path: str
    profile_id: str | None
    recovery_state: str
    sensitivity: str
    confidence: float
    encrypted: bool | None
    evidence: tuple[str, ...]
    warnings: tuple[str, ...]


@dataclass(frozen=True)
class SensitiveLocatorResult:
    locator_version: str
    findings: tuple[SensitiveFinding, ...]
    warnings: tuple[str, ...]
    network_actions: tuple[str, ...] = ()


def locate_sensitive_artifacts(
    entries: Iterable[NormalizedEntry],
    *,
    metadata_by_path: Mapping[str, Mapping[str, Any]] | None = None,
    categories_by_path: Mapping[str, CategoryResult] | None = None,
    profiles: Iterable[WindowsUserProfile] = (),
) -> SensitiveLocatorResult:
    """Locate sensitive artifacts without exposing secret values or contacting networks."""

    metadata = {_norm_path(path): value for path, value in (metadata_by_path or {}).items()}
    categories = {_norm_path(path): value for path, value in (categories_by_path or {}).items()}
    profile_tuple = tuple(profiles)
    findings: list[SensitiveFinding] = []
    warnings: list[str] = []
    for entry in entries:
        finding = _finding_for(
            entry,
            metadata.get(_norm_path(entry.display_path)),
            categories.get(_norm_path(entry.display_path)),
            profile_tuple,
        )
        if finding is None:
            continue
        findings.append(finding)
        warnings.extend(finding.warnings)
    return SensitiveLocatorResult(
        LOCATOR_VERSION,
        tuple(sorted(findings, key=lambda item: item.display_path.lower())),
        tuple(dict.fromkeys(warnings)),
    )


def _finding_for(
    entry: NormalizedEntry,
    metadata: Mapping[str, Any] | None,
    category: CategoryResult | None,
    profiles: tuple[WindowsUserProfile, ...],
) -> SensitiveFinding | None:
    path = _norm_path(entry.display_path)
    suffix = PurePosixPath(path).suffix.lower()
    evidence: list[str] = []
    warnings: list[str] = []
    artifact_type = _artifact_type(path, suffix, metadata)
    if artifact_type is None:
        if _decoy_name(path):
            warnings.append("decoy_name_ignored")
        return None
    if category is not None and "wallets/vaults/keys" in category.categories:
        evidence.append("category:wallets/vaults/keys")
    evidence.extend(_path_evidence(path, suffix, artifact_type))
    evidence.extend(_metadata_evidence(metadata or {}))
    encrypted = _bool_or_none((metadata or {}).get("encrypted"))
    if encrypted:
        warnings.append("encrypted_artifact_visible")
    if entry.entry_type == "deleted" or not entry.allocated:
        warnings.append("deleted_or_carved_origin")
    if artifact_type == "recovery_material" and "validated_recovery_indicator" not in evidence:
        warnings.append("weak_recovery_indicator")
    confidence = _confidence(artifact_type, evidence, path)
    profile = _matching_profile(path, profiles)
    if profile is not None:
        evidence.append(f"profile:{profile.profile_id}")
    return SensitiveFinding(
        finding_id=_stable_id(entry.volume_id, entry.display_path, artifact_type),
        locator_version=LOCATOR_VERSION,
        artifact_type=artifact_type,
        display_path=entry.display_path,
        profile_id=profile.profile_id if profile else None,
        recovery_state="deleted/carved"
        if entry.entry_type == "deleted" or not entry.allocated
        else "allocated",
        sensitivity="high"
        if artifact_type in {"wallet", "keystore", "private_key", "recovery_material"}
        else "medium",
        confidence=confidence,
        encrypted=encrypted,
        evidence=tuple(dict.fromkeys(_redact(item) for item in evidence)),
        warnings=tuple(dict.fromkeys(warnings)),
    )


def _artifact_type(path: str, suffix: str, metadata: Mapping[str, Any] | None) -> str | None:
    if _decoy_name(path):
        return None
    indicators = set(str(item) for item in (metadata or {}).get("validated_indicators", ()))
    if _has(path, "bitcoin/wallets", "bitcoin/blocks") and (
        path.endswith("wallet.dat") or "wallet.dat" in path
    ):
        return "wallet"
    if _has(path, "electrum/wallets") or "electrum_wallet" in indicators:
        return "wallet"
    if suffix == ".json" and {"web3_keystore", "crypto_kdf"}.issubset(indicators):
        return "keystore"
    if (
        _has(path, "browser", "chrome/user data", "firefox/profiles")
        and "browser_vault" in indicators
    ):
        return "browser_vault"
    if suffix in {".key", ".pem"} or _has(path, ".ssh/id_rsa", ".ssh/id_ed25519"):
        return "private_key"
    if suffix in {".p12", ".pfx", ".cer", ".crt"}:
        return "certificate"
    if suffix == ".kdbx" or "password_vault" in indicators:
        return "password_vault"
    if "bip39_mnemonic_shape" in indicators or "seed_phrase_shape" in indicators:
        return "recovery_material"
    if _has(path, "wallet", "keystore", "vault"):
        return "weak_name_match"
    return None


def _path_evidence(path: str, suffix: str, artifact_type: str) -> tuple[str, ...]:
    evidence = [f"artifact_type:{artifact_type}"]
    if suffix:
        evidence.append(f"extension:{suffix}")
    if _has(path, "bitcoin"):
        evidence.append("path:bitcoin")
    if _has(path, "electrum"):
        evidence.append("path:electrum")
    if _has(path, "browser", "chrome/user data", "firefox/profiles"):
        evidence.append("path:browser_profile")
    return tuple(evidence)


def _metadata_evidence(metadata: Mapping[str, Any]) -> tuple[str, ...]:
    evidence: list[str] = []
    for indicator in metadata.get("validated_indicators", ()):
        text = str(indicator)
        if text in {"bip39_mnemonic_shape", "seed_phrase_shape"}:
            evidence.append("validated_recovery_indicator")
        else:
            evidence.append(f"indicator:{text}")
    if metadata.get("encrypted") is not None:
        evidence.append(f"encrypted:{bool(_bool_or_none(metadata.get('encrypted')))}")
    return tuple(evidence)


def _confidence(artifact_type: str, evidence: list[str], path: str) -> float:
    if artifact_type == "weak_name_match":
        return 0.3
    score = 0.55 + (0.08 * len(set(evidence)))
    if _decoy_name(path):
        score -= 0.25
    return round(max(0.1, min(0.95, score)), 2)


def _decoy_name(path: str) -> bool:
    return _has(path, "fake wallet", "not a wallet", "sample wallet prose")


def _matching_profile(
    path: str, profiles: tuple[WindowsUserProfile, ...]
) -> WindowsUserProfile | None:
    for profile in profiles:
        if path.startswith(_norm_path(profile.root_path) + "/"):
            return profile
    return None


def _bool_or_none(value: Any) -> bool | None:
    if value is None:
        return None
    if isinstance(value, bool):
        return value
    return str(value).strip().casefold() in {"true", "1", "yes"}


def _redact(value: str) -> str:
    lower = value.casefold()
    if any(marker in lower for marker in SECRET_MARKERS):
        key, _, detail = value.partition(":")
        if key == "indicator":
            return value
        return f"{key}:<redacted:{hashlib.sha256(detail.encode('utf-8')).hexdigest()[:8]}>"
    return value


def _has(path: str, *fragments: str) -> bool:
    return any(fragment in path for fragment in fragments)


def _norm_path(path: str) -> str:
    return path.replace("\\", "/").strip("/").lower()


def _stable_id(*values: str) -> str:
    return f"sensitive-{hashlib.sha256(chr(0).join(values).encode('utf-8')).hexdigest()[:24]}"
