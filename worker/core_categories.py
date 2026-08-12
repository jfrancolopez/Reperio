"""Versioned multi-label core category assignment."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import PurePosixPath
from typing import Any

from worker.content_signature import SignatureResult
from worker.interest_scoring import ScoreResult
from worker.windows_noise_rules import NoiseDecision

CATEGORY_VERSION = "core-categories-v1"


@dataclass(frozen=True)
class CategoryAssignment:
    category: str
    evidence: tuple[str, ...]
    confidence: float


@dataclass(frozen=True)
class CategoryInput:
    display_path: str
    signature: SignatureResult | None = None
    score: ScoreResult | None = None
    noise: NoiseDecision | None = None
    metadata: Mapping[str, Any] | None = None
    state: str = "allocated"
    category_version: str = CATEGORY_VERSION


@dataclass(frozen=True)
class CategoryResult:
    category_version: str
    assignments: tuple[CategoryAssignment, ...]
    evidence: tuple[str, ...]

    @property
    def categories(self) -> tuple[str, ...]:
        return tuple(assignment.category for assignment in self.assignments)


def assign_core_categories(payload: CategoryInput) -> CategoryResult:
    """Assign explainable categories without hiding or deleting any finding."""

    path = _normalized_path(payload.display_path)
    suffix = PurePosixPath(path).suffix.lower()
    evidence: list[str] = [f"category_version:{CATEGORY_VERSION}"]
    if payload.category_version != CATEGORY_VERSION:
        evidence.append(f"migrated_from:{payload.category_version}")
    assignments: dict[str, list[str]] = {}
    signature = payload.signature
    mime = signature.mime_type if signature else ""
    sig = signature.signature if signature else ""
    if signature is None:
        _add(assignments, "unknown", "missing_signature")
    else:
        evidence.append(f"signature:{sig}")
        if mime.startswith("image/"):
            _add(assignments, "media", f"mime:{mime}")
        if mime == "application/pdf" or sig == "docx" or suffix in {".txt", ".rtf", ".odt"}:
            _add(assignments, "documents", f"document_signal:{mime or suffix}")
        if mime == "application/zip" or sig == "zip" or suffix in {".7z", ".rar", ".tar", ".gz"}:
            _add(assignments, "archives", f"archive_signal:{sig or suffix}")
        if sig in {"unknown", "empty"}:
            _add(assignments, "unknown", f"signature:{sig}")
        if "polyglot_signature" in signature.evidence or "extension_mismatch" in signature.evidence:
            _add(assignments, "corrupted", "contradictory_type_evidence")
    if suffix in {".eml", ".msg", ".mbox", ".pst", ".ost"} or _has(path, "mail", "outlook"):
        _add(assignments, "messages/email", f"path_or_extension:{suffix or 'mail_path'}")
    if _has(path, "browser", "chrome/user data", "firefox/profiles", "edge/user data"):
        _add(assignments, "browser", "browser_path")
    if _has(path, "backup", "filehistory", "time machine", "mobilebackup") or suffix in {
        ".bkf",
        ".bak",
        ".vhd",
        ".vhdx",
        ".vmdk",
        ".qcow2",
        ".ipa",
        ".ab",
    }:
        _add(assignments, "backups/mobile", f"backup_signal:{suffix or 'path'}")
    if _has(path, "wallet", "keystore", "vault", "private key", ".ssh") or suffix in {
        ".key",
        ".pem",
        ".p12",
        ".pfx",
        ".kdbx",
    }:
        _add(assignments, "wallets/vaults/keys", f"sensitive_artifact_signal:{suffix or 'path'}")
    if (
        suffix
        in {
            ".exe",
            ".dll",
            ".sys",
            ".py",
            ".js",
            ".ts",
            ".json",
            ".db",
            ".sqlite",
            ".sqlite3",
            ".mdb",
        }
        or sig == "pe-executable"
    ):
        _add(assignments, "software/code/databases", f"software_code_db_signal:{sig or suffix}")
    if payload.state in {"deleted", "carved"}:
        _add(assignments, "deleted/carved", f"state:{payload.state}")
    if payload.noise is not None and payload.noise.visibility in {"lower", "review"}:
        _add(assignments, "system/noise", f"noise_visibility:{payload.noise.visibility}")
    elif payload.score is not None and payload.score.noise_score > 0:
        _add(assignments, "system/noise", f"noise_score:{payload.score.noise_score}")
    if not assignments:
        _add(assignments, "unknown", "no_category_signal")
    return CategoryResult(
        category_version=CATEGORY_VERSION,
        assignments=tuple(
            CategoryAssignment(category, tuple(dict.fromkeys(reasons)), _confidence(reasons))
            for category, reasons in sorted(assignments.items())
        ),
        evidence=tuple(dict.fromkeys(evidence)),
    )


def _add(assignments: dict[str, list[str]], category: str, reason: str) -> None:
    assignments.setdefault(category, []).append(reason)


def _confidence(reasons: list[str]) -> float:
    return min(0.95, round(0.55 + (0.1 * len(set(reasons))), 2))


def _normalized_path(path: str) -> str:
    return path.replace("\\", "/").strip("/").lower()


def _has(path: str, *fragments: str) -> bool:
    return any(fragment in path for fragment in fragments)
