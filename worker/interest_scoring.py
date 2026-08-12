"""Versioned deterministic interest and noise scoring."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from worker.content_signature import SignatureResult
from worker.windows_noise_rules import RULESET_VERSION, NoiseDecision
from worker.windows_profiles import WindowsUserProfile

SCORING_VERSION = "interest-score-v1"


@dataclass(frozen=True)
class ScoreInput:
    display_path: str
    signature: SignatureResult | None
    noise: NoiseDecision | None
    profile: WindowsUserProfile | None = None
    metadata: Mapping[str, Any] | None = None
    state: str = "allocated"
    application: str | None = None
    scoring_version: str = SCORING_VERSION


@dataclass(frozen=True)
class ScoreResult:
    scoring_version: str
    ruleset_version: str | None
    interest_score: int
    noise_score: int
    confidence: float
    evidence: tuple[str, ...]


def score_finding(payload: ScoreInput) -> ScoreResult:
    """Return stable independent interest/noise scores from deterministic signals."""

    if payload.scoring_version != SCORING_VERSION:
        return _migrated_score(payload)
    interest = 10
    noise = 0
    confidence = 0.5
    evidence: list[str] = [f"scoring_version:{SCORING_VERSION}"]
    signature = payload.signature
    if signature is None:
        evidence.append("missing_signature")
        confidence -= 0.15
    else:
        confidence += min(signature.confidence, 1.0) * 0.25
        evidence.append(f"signature:{signature.signature}")
        if signature.mime_type.startswith("image/") or signature.mime_type == "application/pdf":
            interest += 30
            evidence.append("personal_mime_signal")
        elif signature.signature == "docx":
            interest += 25
            evidence.append("document_signal")
        elif signature.signature in {"zip", "random", "unknown"}:
            interest += 5
        if "extension_mismatch" in signature.evidence or "polyglot_signature" in signature.evidence:
            interest += 8
            confidence -= 0.1
            evidence.append("contradictory_type_evidence")
    path = payload.display_path.replace("\\", "/").lower()
    if any(
        fragment in path for fragment in ("/documents/", "/desktop/", "/downloads/", "/pictures/")
    ):
        interest += 20
        evidence.append("well_known_user_path")
    if payload.profile is not None:
        interest += 10
        confidence += 0.1
        evidence.append(f"profile:{payload.profile.profile_id}")
    if payload.state in {"deleted", "carved"}:
        interest += 10
        evidence.append(f"state:{payload.state}")
    if payload.application:
        evidence.append(f"application:{payload.application}")
    if payload.noise is not None:
        evidence.append(f"noise_ruleset:{payload.noise.ruleset_version}")
        if payload.noise.visibility == "lower":
            noise += 60
            confidence += 0.1
            evidence.extend(f"noise_rule:{rule_id}" for rule_id in payload.noise.rule_ids)
        elif payload.noise.visibility == "review":
            noise += 25
            interest += 5
            evidence.append("noise_conflict_review")
    return ScoreResult(
        scoring_version=SCORING_VERSION,
        ruleset_version=payload.noise.ruleset_version if payload.noise else None,
        interest_score=_clamp_score(interest),
        noise_score=_clamp_score(noise),
        confidence=_clamp_confidence(confidence),
        evidence=tuple(dict.fromkeys(evidence)),
    )


def _migrated_score(payload: ScoreInput) -> ScoreResult:
    current = score_finding(
        ScoreInput(
            display_path=payload.display_path,
            signature=payload.signature,
            noise=payload.noise,
            profile=payload.profile,
            metadata=payload.metadata,
            state=payload.state,
            application=payload.application,
            scoring_version=SCORING_VERSION,
        )
    )
    return ScoreResult(
        scoring_version=SCORING_VERSION,
        ruleset_version=current.ruleset_version or RULESET_VERSION,
        interest_score=current.interest_score,
        noise_score=current.noise_score,
        confidence=max(0.0, round(current.confidence - 0.05, 2)),
        evidence=(*current.evidence, f"migrated_from:{payload.scoring_version}"),
    )


def _clamp_score(value: int) -> int:
    return max(0, min(100, value))


def _clamp_confidence(value: float) -> float:
    return round(max(0.0, min(1.0, value)), 2)
