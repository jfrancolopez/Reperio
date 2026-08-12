"""Pause, safe-stop, and restart coordination for scanner stages."""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Any, Protocol

from scanner import messages, scheduler
from shared import checkpoints


class LifecycleError(ValueError):
    """Raised when scanner lifecycle control cannot proceed safely."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


@dataclass(frozen=True)
class PauseRequest:
    requested: bool
    reason: str


@dataclass(frozen=True)
class PauseDecision:
    should_pause: bool
    reason: str | None
    checkpoint_payload: dict[str, Any] | None = None

    def ack_message(self, *, stage: str, sequence: int = 0) -> bytes:
        if not self.should_pause or self.reason is None:
            raise LifecycleError("pause_not_requested", "pause acknowledgement requires a pause")
        return messages.encode_message(
            "pause_ack", sequence, {"stage": stage, "reason": self.reason}
        )


@dataclass(frozen=True)
class StopPolicy:
    graceful_signal: str = "TERM"
    force_signal: str = "KILL"
    timeout_seconds: int = 10

    def __post_init__(self) -> None:
        if self.timeout_seconds <= 0:
            raise LifecycleError("invalid_stop_policy", "stop timeout must be positive")


@dataclass(frozen=True)
class StopResult:
    status: str
    signal_sent: str
    force_signal_sent: str | None
    checkpoint_preserved: bool
    reason: str


@dataclass(frozen=True)
class RestartDecision:
    status: str
    runnable: tuple[str, ...]
    reason: str
    cursor: Mapping[str, Any] | None = None


class StageProcess(Protocol):
    def send_signal(self, signal_name: str) -> None: ...

    def wait(self, timeout_seconds: int) -> bool: ...


def cooperative_pause(
    *,
    stage: str,
    cursor: Mapping[str, Any],
    counters: Mapping[str, Any],
    pause: PauseRequest,
) -> PauseDecision:
    """Return a checkpointable pause decision without discarding committed batches."""

    if stage not in scheduler.STAGES:
        raise LifecycleError("unknown_stage", "pause requested for unknown stage")
    if not pause.requested:
        return PauseDecision(False, None)
    payload = {
        "stage": stage,
        "cursor": dict(cursor),
        "counters": dict(counters),
        "reason": pause.reason,
    }
    return PauseDecision(True, pause.reason, payload)


def safe_stop_process(process: StageProcess, *, policy: StopPolicy = StopPolicy()) -> StopResult:
    """Signal a subprocess, using force only after the graceful timeout expires."""

    process.send_signal(policy.graceful_signal)
    if process.wait(policy.timeout_seconds):
        return StopResult("stopped", policy.graceful_signal, None, True, "graceful stop completed")
    process.send_signal(policy.force_signal)
    process.wait(1)
    return StopResult(
        "force_stopped",
        policy.graceful_signal,
        policy.force_signal,
        True,
        "graceful stop timed out; force signal sent after checkpoint preservation",
    )


def restart_from_checkpoint(
    *,
    load_checkpoint: Callable[[], checkpoints.CheckpointRecord],
    completed_stages: set[str],
    expected_source_fingerprint: str,
    current_source_fingerprint: str,
    config: scheduler.SchedulerConfig = scheduler.SchedulerConfig(),
) -> RestartDecision:
    """Validate source/checkpoint state and return the next restart plan."""

    if current_source_fingerprint != expected_source_fingerprint:
        return RestartDecision("blocked", (), "source reconnect fingerprint mismatch")
    try:
        checkpoint = load_checkpoint()
    except checkpoints.CheckpointError as error:
        plan = scheduler.restart_plan(completed_stages, config)
        return RestartDecision("restart_stage", plan.runnable, str(error))
    plan = scheduler.restart_plan(completed_stages | {checkpoint.stage}, config)
    return RestartDecision("resume", plan.runnable, "checkpoint validated", checkpoint.cursor)


def paused_statuses(statuses: Mapping[str, str]) -> dict[str, str]:
    """Expose scheduler pause propagation through the lifecycle API."""

    return scheduler.pause_all(statuses)
