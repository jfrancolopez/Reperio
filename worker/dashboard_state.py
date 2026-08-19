"""Live-scan dashboard state (RPR-119).

Maps scanner job state, stage statuses, progress estimates, counters, and
source facts into the deterministic dashboard payload: ordered stage list,
current activity, credible progress (never a fabricated percentage), warnings
and errors, read-only/source facts, control states that follow the job state,
bounded live new-finding samples, and a results link that works before
completion. Pure and dependency-free; performs no I/O.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any

from scanner.scheduler import (
    STAGE_PENDING,
    STAGE_RUNNING,
    stage_order,
)
from worker.progress_summary import overall_progress

DASHBOARD_VERSION = "dashboard-v1"

JOB_STATES = frozenset(
    {
        "pending",
        "running",
        "paused",
        "retrying",
        "completed",
        "completed-warning",
        "failed",
        "cancelled",
    }
)

MAX_LIVE_SAMPLES = 5

CONTROL_JOB_RULES = {
    "pause": frozenset({"running"}),
    "resume": frozenset({"paused"}),
    "safe_stop": frozenset({"running", "paused", "pending", "retrying"}),
}


class DashboardError(ValueError):
    """Raised when a dashboard input is invalid."""


@dataclass(frozen=True)
class Controls:
    pause_enabled: bool
    resume_enabled: bool
    safe_stop_enabled: bool
    reasons: tuple[str, ...] = ()


def control_state(job_state: str) -> Controls:
    """Control availability follows the job state; no controls for terminal states."""
    reasons: list[str] = []
    pause_enabled = job_state in CONTROL_JOB_RULES["pause"]
    resume_enabled = job_state in CONTROL_JOB_RULES["resume"]
    safe_stop_enabled = job_state in CONTROL_JOB_RULES["safe_stop"]
    if job_state not in JOB_STATES:
        raise DashboardError("unknown_job_state", f"job state {job_state!r} is not recognized")
    if job_state in {"completed", "completed-warning", "failed", "cancelled"}:
        reasons.append("terminal_state")
    elif not (pause_enabled or resume_enabled or safe_stop_enabled):
        reasons.append("no_available_control")
    return Controls(pause_enabled, resume_enabled, safe_stop_enabled, tuple(reasons))


def current_activity(stage_statuses: Mapping[str, str]) -> str | None:
    """The running stage, or None when no stage is currently running."""
    for stage in stage_order():
        if stage_statuses.get(stage) == STAGE_RUNNING:
            return stage
    return None


def bounded_samples(
    samples: Sequence[Mapping[str, Any]], *, limit: int = MAX_LIVE_SAMPLES
) -> list[dict[str, Any]]:
    """Deterministic bounded slice of live new-finding samples."""
    if limit < 0:
        raise DashboardError("invalid_limit", "sample limit must not be negative")
    return [dict(sample) for sample in samples[:limit]]


def dashboard_snapshot(
    *,
    case_id: str,
    job_state: str,
    stage_statuses: Mapping[str, str],
    stage_progress: Sequence[Any] = (),
    counts: Mapping[str, int] | None = None,
    warnings: Sequence[str] = (),
    errors: Sequence[str] = (),
    source_facts: Mapping[str, Any] | None = None,
    live_samples: Sequence[Mapping[str, Any]] = (),
    ui_base: str = "",
    now: str,
) -> dict[str, Any]:
    """Build the deterministic live dashboard payload for the job state."""
    if job_state not in JOB_STATES:
        raise DashboardError("unknown_job_state", f"job state {job_state!r} is not recognized")
    estimate = overall_progress(stage_progress, stage_statuses)
    controls = control_state(job_state)
    ordered_stages = [
        {"stage": stage, "state": stage_statuses.get(stage, STAGE_PENDING)}
        for stage in stage_order()
    ]
    results_link = f"{ui_base}/case/{case_id}" if ui_base else f"/case/{case_id}"
    return {
        "dashboard_version": DASHBOARD_VERSION,
        "case_id": case_id,
        "job_state": job_state,
        "stages": ordered_stages,
        "current_activity": current_activity(stage_statuses),
        "progress": {
            "mode": estimate.mode,
            "percent": estimate.percent,
            "eta_seconds": estimate.eta_seconds,
        },
        "counters": dict(counts or {}),
        "warnings": list(warnings),
        "errors": list(errors),
        "source_facts": dict(source_facts or {}),
        "controls": {
            "pause": controls.pause_enabled,
            "resume": controls.resume_enabled,
            "safe_stop": controls.safe_stop_enabled,
            "reasons": list(controls.reasons),
        },
        "results_link": results_link,
        "live_samples": bounded_samples(live_samples),
        "recorded_at": now,
    }
