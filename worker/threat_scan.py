"""Offline YARA/ClamAV threat scanning adapters (RPR-169).

Labels potentially dangerous recovered content using an offline YARA-rule adapter
and an optional ClamAV adapter. Rule and signature versions are tracked
separately; scanning is strictly local with no network access unless a signature
update is explicitly run. Matches receive malware/suspicious labels with
confidence, a safe-download warning, and remain fully exportable; the tool never
deletes or quarantines automatically and never executes content. Pure and
dependency-free; the scanner process is injected as a runner.
"""

from __future__ import annotations

import re
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Any

THREAT_SCAN_VERSION = "threat-scan-v1"

YARA_RULES_VERSION = "yara-rules-v1"
CLAMAV_SIGNATURE_VERSION = "clamav-sigs-v1"

LABELS = frozenset({"malware", "suspicious"})
RULE_NAME_RE = re.compile(r"^[A-Za-z0-9._:-]{1,128}$")

Runner = Callable[[Mapping[str, Any]], Mapping[str, Any]]


class ThreatScanError(ValueError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


@dataclass(frozen=True)
class RuleSet:
    version: str
    rules: tuple[str, ...]
    updated_at: str = ""

    def contains(self, rule: str) -> bool:
        return rule in self.rules


@dataclass(frozen=True)
class ScanMatch:
    rule: str
    label: str
    confidence: float
    detail: str = ""

    def metadata(self) -> dict[str, Any]:
        return {
            "rule": self.rule,
            "label": self.label,
            "confidence": self.confidence,
            "detail": self.detail,
        }


def parse_rule_set(text: str, *, version: str) -> RuleSet:
    """Parse a YARA rule set, validating rule names and rejecting empty sets."""
    rules = tuple(
        line.strip()
        for line in text.splitlines()
        if line.strip() and not line.lstrip().startswith(("#", "//", "/*"))
    )
    for rule in rules:
        if not RULE_NAME_RE.match(rule):
            raise ThreatScanError("unsafe_rule", f"rule name {rule!r} is not safe")
    if not rules:
        raise ThreatScanError("empty_rule_set", "a rule set must contain at least one rule")
    return RuleSet(version=version, rules=rules)


def scan_with_yara(
    rule_set: RuleSet,
    *,
    content_hash: str,
    runner: Runner,
    timeout_seconds: int = 30,
) -> dict[str, Any]:
    """Offline YARA scan; local only, timeout/crash are explicit outcomes."""
    if timeout_seconds <= 0:
        raise ThreatScanError("invalid_timeout", "timeout must be positive")
    invocation = {
        "version": THREAT_SCAN_VERSION,
        "engine": "yara",
        "rule_version": rule_set.version,
        "rules": list(rule_set.rules),
        "content_hash": content_hash,
        "network_access": False,
        "timeout_seconds": timeout_seconds,
    }
    try:
        result = runner(invocation)
    except Exception as exc:
        return {"status": "crashed", "reason": f"scanner crashed: {exc}", "network_access": False}
    if bool(result.get("timed_out")):
        return {
            "status": "timed_out",
            "reason": "scanner exceeded its time budget",
            "network_access": False,
        }
    matches = result.get("matches") or ()
    normalized = [_match(rule) for rule in matches if isinstance(rule, str)]
    return {
        "status": "ok",
        "rule_version": rule_set.version,
        "matches": normalized,
        "network_access": False,
        "exportable_after_warning": True,
    }


def scan_with_clamav(
    signature_version: str,
    *,
    content_path: str,
    runner: Runner,
    timeout_seconds: int = 30,
) -> dict[str, Any]:
    """Optional offline ClamAV adapter; signatures update only when explicitly run."""
    invocation = {
        "version": THREAT_SCAN_VERSION,
        "engine": "clamav",
        "signature_version": signature_version,
        "content_path": content_path,
        "network_access": False,
        "timeout_seconds": timeout_seconds,
    }
    try:
        result = runner(invocation)
    except Exception as exc:
        return {"status": "crashed", "reason": f"scanner crashed: {exc}", "network_access": False}
    if bool(result.get("timed_out")):
        return {
            "status": "timed_out",
            "reason": "scanner exceeded its time budget",
            "network_access": False,
        }
    infected = bool(result.get("infected"))
    return {
        "status": "ok",
        "signature_version": signature_version,
        "matches": [
            {"rule": "clamav", "label": "malware", "confidence": 0.9, "detail": "signature match"}
        ]
        if infected
        else [],
        "network_access": False,
        "exportable_after_warning": True,
    }


def label_match(rule: str, label: str, confidence: float) -> ScanMatch:
    """Normalize a match; labels are malware or suspicious with bounded confidence."""
    if label not in LABELS:
        raise ThreatScanError("invalid_label", f"label {label!r} is not supported")
    if not (0.0 <= confidence <= 1.0):
        raise ThreatScanError("invalid_confidence", "confidence must be between 0 and 1")
    return ScanMatch(rule=rule, label=label, confidence=confidence)


def override_label(original: ScanMatch, override: str) -> ScanMatch:
    """False-positive override preserves the original rule while relabelling."""
    if override not in LABELS:
        raise ThreatScanError("invalid_label", f"override {override!r} is not supported")
    return ScanMatch(
        rule=original.rule, label=override, confidence=original.confidence, detail="overridden"
    )


def safe_download_warning() -> str:
    return "recovered content may be dangerous; export with care after a safe-download review"


def signature_update_required(rule_set: RuleSet) -> bool:
    return rule_set.version != YARA_RULES_VERSION


def signature_update_allowed(*, explicit_run: bool) -> bool:
    """Signature updates run only when explicitly requested; never auto-downloaded."""
    return explicit_run


def _match(rule: str) -> dict[str, Any]:
    return label_match(rule, "malware", 0.9).metadata()
