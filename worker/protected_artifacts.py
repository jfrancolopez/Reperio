"""Deterministic protected/encrypted artifact classification."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import PurePosixPath
from typing import Any

PARSER_VERSION = "protected-artifacts-v1"
PROTECTED_EXTENSIONS = {
    ".kdbx": "password-vault",
    ".keychain": "password-vault",
    ".p12": "certificate-key-bundle",
    ".pfx": "certificate-key-bundle",
    ".gpg": "encrypted-message",
    ".pgp": "encrypted-message",
}
WALLET_NAMES = frozenset({"wallet.dat", "keystore", "utc--", "electrum"})


@dataclass(frozen=True)
class ProtectedCandidate:
    artifact_id: str
    display_path: str
    mime_type: str
    signature: str
    metadata: Mapping[str, Any]
    entropy: float | None = None
    warnings: tuple[str, ...] = ()


@dataclass(frozen=True)
class ProtectedArtifactResult:
    artifact_id: str
    protected: bool
    protection_kind: str
    format_name: str
    kdf: str | None
    confidence: float
    evidence: tuple[str, ...]
    warnings: tuple[str, ...]
    parser_version: str = PARSER_VERSION


def classify_protected_artifact(candidate: ProtectedCandidate) -> ProtectedArtifactResult:
    evidence: list[str] = []
    warnings = list(candidate.warnings)
    metadata = candidate.metadata
    path = PurePosixPath(candidate.display_path.lower())
    suffix = path.suffix
    format_name = _format_name(candidate, suffix)
    kdf = _string(metadata.get("kdf") or metadata.get("kdf_name"))

    if bool(metadata.get("corrupt")) or "corrupt_header" in candidate.warnings:
        warnings.append("corrupt_protection_header")
        return _result(candidate, False, "unknown", format_name, kdf, 0.0, evidence, warnings)
    if bool(metadata.get("unsupported_encryption")):
        warnings.append("unsupported_encryption_format")
        return _result(candidate, False, "unsupported", format_name, kdf, 0.0, evidence, warnings)

    if bool(metadata.get("encrypted")) or bool(metadata.get("password_required")):
        evidence.append("metadata_encrypted_flag")
        if candidate.mime_type in {
            "application/zip",
            "application/x-7z-compressed",
            "application/vnd.rar",
        }:
            return _result(
                candidate, True, "encrypted-archive", format_name, kdf, 0.95, evidence, warnings
            )
        if candidate.mime_type == "application/pdf":
            return _result(
                candidate, True, "encrypted-pdf", format_name, kdf, 0.95, evidence, warnings
            )
        if _is_office(candidate.mime_type):
            return _result(
                candidate,
                True,
                "encrypted-office-document",
                format_name,
                kdf,
                0.92,
                evidence,
                warnings,
            )
        return _result(
            candidate, True, "encrypted-artifact", format_name, kdf, 0.75, evidence, warnings
        )

    if suffix in PROTECTED_EXTENSIONS:
        evidence.append(f"protected_extension:{suffix}")
        return _result(
            candidate,
            True,
            PROTECTED_EXTENSIONS[suffix],
            format_name,
            kdf,
            0.82,
            evidence,
            warnings,
        )
    if _looks_wallet(path, metadata):
        evidence.append("wallet_or_keystore_evidence")
        return _result(
            candidate, True, "wallet-or-keystore", format_name, kdf, 0.78, evidence, warnings
        )
    if bool(metadata.get("whole_volume_encryption_signature")):
        evidence.append("whole_volume_encryption_signature")
        return _result(
            candidate, True, "whole-volume-encryption", format_name, kdf, 0.9, evidence, warnings
        )
    if candidate.entropy is not None and candidate.entropy >= 7.5:
        warnings.append("high_entropy_weak_evidence_only")
        return _result(
            candidate, False, "unknown", format_name, kdf, 0.2, ("high_entropy",), warnings
        )
    if (
        suffix
        != PurePosixPath(str(metadata.get("original_name", candidate.display_path)).lower()).suffix
    ):
        warnings.append("renamed_format_evidence")
    return _result(candidate, False, "none", format_name, kdf, 0.0, evidence, warnings)


def _result(
    candidate: ProtectedCandidate,
    protected: bool,
    protection_kind: str,
    format_name: str,
    kdf: str | None,
    confidence: float,
    evidence: tuple[str, ...] | list[str],
    warnings: tuple[str, ...] | list[str],
) -> ProtectedArtifactResult:
    return ProtectedArtifactResult(
        artifact_id=candidate.artifact_id,
        protected=protected,
        protection_kind=protection_kind,
        format_name=format_name,
        kdf=kdf,
        confidence=confidence,
        evidence=tuple(dict.fromkeys(evidence)),
        warnings=tuple(dict.fromkeys(warnings)),
    )


def _format_name(candidate: ProtectedCandidate, suffix: str) -> str:
    if isinstance(candidate.metadata.get("format"), str):
        return str(candidate.metadata["format"])[:128]
    if candidate.mime_type == "application/pdf":
        return "pdf"
    if candidate.mime_type.startswith("application/vnd.openxmlformats"):
        return "office-openxml"
    if candidate.mime_type.startswith("application/zip"):
        return "zip"
    if suffix:
        return suffix.removeprefix(".")
    return candidate.signature or "unknown"


def _is_office(mime_type: str) -> bool:
    return mime_type.startswith("application/vnd.openxmlformats") or mime_type in {
        "application/msword",
        "application/vnd.ms-excel",
        "application/vnd.ms-powerpoint",
    }


def _looks_wallet(path: PurePosixPath, metadata: Mapping[str, Any]) -> bool:
    text = "/".join(path.parts)
    if any(name in text for name in WALLET_NAMES):
        return True
    return bool(metadata.get("wallet_family") or metadata.get("keystore_cipher"))


def _string(value: object) -> str | None:
    if isinstance(value, str) and value:
        return value[:128]
    return None
