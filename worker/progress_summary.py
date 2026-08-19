"""Credible progress and completion summaries (RPR-113).

Assigns deterministic per-stage weights, computes overall percent only when
every active stage has a known denominator, falls back to activity-only (elapsed
heartbeat, counts) otherwise, and never fabricates an ETA or percentage without
a denominator. Completion summaries distinguish warnings, failures, and
unsupported/skipped stages and carry export counts plus the local UI link.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass

from scanner.scheduler import (
    STAGE_ARTIFACTS,
    STAGE_CARVING,
    STAGE_COMPLETED,
    STAGE_ENRICHMENT,
    STAGE_ENUMERATION,
    STAGE_FAILED,
    STAGE_FINALIZATION,
    STAGE_SKIPPED,
    STAGE_VALIDATION,
    STAGE_VOLUMES,
)

PROGRESS_SUMMARY_VERSION = "progress-summary-v1"

STAGE_WEIGHTS: dict[str, float] = {
    STAGE_VALIDATION: 0.05,
    STAGE_VOLUMES: 0.10,
    STAGE_ENUMERATION: 0.30,
    STAGE_ARTIFACTS: 0.15,
    STAGE_ENRICHMENT: 0.15,
    STAGE_CARVING: 0.20,
    STAGE_FINALIZATION: 0.05,
}

COMPLETION_STATES = frozenset({"completed", "completed-warning", "failed"})


class ProgressSummaryError(ValueError):
    """Raised when progress inputs are invalid or unsafe."""


@dataclass(frozen=True)
class StageProgress:
    stage: str
    done: int
    denominator: int | None


@dataclass(frozen=True)
class ProgressEstimate:
    percent: int | None
    eta_seconds: int | None
    mode: str
    reasons: tuple[str, ...] = ()


@dataclass(frozen=True)
class CompletionSummary:
    case_id: str
    state: str
    stages: Mapping[str, str]
    counts: Mapping[str, int]
    warnings: tuple[str, ...]
    failed_stages: tuple[str, ...]
    skipped_stages: tuple[str, ...]
    export_counts: Mapping[str, int]
    elapsed_seconds: int
    ui_link: str
    summary_version: str = PROGRESS_SUMMARY_VERSION


def stage_weight(stage: str) -> float:
    if stage not in STAGE_WEIGHTS:
        raise ProgressSummaryError("unknown_stage", "stage has no defined weight")
    return STAGE_WEIGHTS[stage]


def stage_percent(progress: StageProgress) -> int | None:
    """Percent for one stage; None when the denominator is unknown."""
    if progress.done < 0 or (progress.denominator is not None and progress.denominator < 0):
        raise ProgressSummaryError("invalid_progress", "progress values must not be negative")
    if progress.denominator is None or progress.denominator == 0:
        return None
    fraction = max(0.0, min(1.0, progress.done / progress.denominator))
    return int(round(fraction * 100))


def eta_seconds(progress: StageProgress, *, elapsed_seconds: int) -> int | None:
    """Estimated remaining seconds; only when denominator and progress exist."""
    if elapsed_seconds < 0:
        raise ProgressSummaryError("invalid_elapsed", "elapsed must not be negative")
    if progress.denominator is None or progress.denominator == 0 or progress.done <= 0:
        return None
    remaining = progress.denominator - progress.done
    if remaining <= 0:
        return 0
    rate = progress.done / elapsed_seconds if elapsed_seconds > 0 else 0.0
    if rate <= 0:
        return None
    return max(1, int(round(remaining / rate)))


def overall_progress(
    active: Sequence[StageProgress],
    statuses: Mapping[str, str],
) -> ProgressEstimate:
    """Weighted overall percent; activity-only fallback without denominators."""
    if not active:
        return ProgressEstimate(0, 0, "idle")
    reasons: list[str] = []
    weighted = 0.0
    weight_total = 0.0
    unknown_denominator = False
    for progress in active:
        weight = stage_weight(progress.stage)
        if statuses.get(progress.stage) == STAGE_COMPLETED:
            weighted += weight
            weight_total += weight
            continue
        if progress.denominator is None or progress.denominator == 0:
            unknown_denominator = True
            reasons.append(f"unknown_denominator:{progress.stage}")
            continue
        percent = stage_percent(progress)
        if percent is None:
            unknown_denominator = True
            reasons.append(f"unknown_denominator:{progress.stage}")
            continue
        weighted += weight * (percent / 100.0)
        weight_total += weight

    if unknown_denominator or weight_total <= 0:
        return ProgressEstimate(None, None, "activity_only", tuple(dict.fromkeys(reasons)))
    percent = int(round(weighted / weight_total * 100))
    return ProgressEstimate(percent, None, "weighted", tuple(reasons))


def heartbeat_due(last_heartbeat_at: str | None, *, now: str, throttle_seconds: int) -> bool:
    """Throttle heartbeat emission; no heartbeat before the first interval."""
    if throttle_seconds <= 0:
        raise ProgressSummaryError("invalid_throttle", "throttle must be positive")
    if last_heartbeat_at is None:
        return True
    import datetime

    last = datetime.datetime.fromisoformat(last_heartbeat_at.replace("Z", "+00:00"))
    current = datetime.datetime.fromisoformat(now.replace("Z", "+00:00"))
    return (current - last).total_seconds() >= throttle_seconds


def build_completion_summary(
    *,
    case_id: str,
    stages: Mapping[str, str],
    counts: Mapping[str, int],
    warnings: Sequence[str] = (),
    export_counts: Mapping[str, int] | None = None,
    elapsed_seconds: int = 0,
    ui_link: str = "",
) -> CompletionSummary:
    """Build a final snapshot that distinguishes warnings, failures, skipped."""
    if elapsed_seconds < 0:
        raise ProgressSummaryError("invalid_elapsed", "elapsed must not be negative")
    failed = tuple(sorted(stage for stage, state in stages.items() if state == STAGE_FAILED))
    skipped = tuple(sorted(stage for stage, state in stages.items() if state == STAGE_SKIPPED))
    state = _completion_state(failed, skipped, warnings)
    return CompletionSummary(
        case_id=case_id,
        state=state,
        stages=dict(stages),
        counts=dict(counts),
        warnings=tuple(warnings),
        failed_stages=failed,
        skipped_stages=skipped,
        export_counts=dict(export_counts or {}),
        elapsed_seconds=elapsed_seconds,
        ui_link=ui_link,
    )


def heartbeat_snapshot(
    *,
    case_id: str,
    stages: Mapping[str, str],
    active: Sequence[StageProgress],
    counts: Mapping[str, int],
    elapsed_seconds: int,
    now: str,
) -> dict[str, object]:
    """Activity-only fallback payload when a denominator is unavailable."""
    estimate = overall_progress(active, stages)
    payload: dict[str, object] = {
        "summary_version": PROGRESS_SUMMARY_VERSION,
        "case_id": case_id,
        "mode": estimate.mode,
        "percent": estimate.percent,
        "eta_seconds": estimate.eta_seconds,
        "elapsed_seconds": elapsed_seconds,
        "counts": dict(counts),
        "recorded_at": now,
        "stage_states": {stage: stages.get(stage, "pending") for stage in STAGE_WEIGHTS},
    }
    if estimate.reasons:
        payload["reasons"] = list(estimate.reasons)
    return payload


def _completion_state(
    failed: Sequence[str], skipped: Sequence[str], warnings: Sequence[str]
) -> str:
    if failed:
        return "failed"
    if warnings or skipped:
        return "completed-warning"
    return "completed"
