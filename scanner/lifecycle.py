"""Pause, safe-stop, and restart coordination for scanner stages."""

from __future__ import annotations

import copy
import json
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from subprocess import TimeoutExpired
from typing import Any, Protocol

from scanner import messages, scheduler
from shared import checkpoints

ALLOWED_STOP_SIGNALS = frozenset({"TERM", "KILL"})
MAX_STOP_TIMEOUT_SECONDS = 300
FORCE_WAIT_SECONDS = 1
MAX_CHECKPOINT_PAYLOAD_BYTES = 1024 * 1024


class LifecycleError(ValueError):
    """Raised when scanner lifecycle control cannot proceed safely."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


@dataclass(frozen=True)
class PauseRequest:
    requested: bool
    reason: str

    def __post_init__(self) -> None:
        if type(self.requested) is not bool:
            raise LifecycleError("invalid_pause_request", "pause request flag must be boolean")
        _validate_reason(self.reason, required=self.requested)


@dataclass(frozen=True)
class PauseDecision:
    should_pause: bool
    reason: str | None
    checkpoint_payload: dict[str, Any] | None = None
    checkpoint_persisted: bool = False

    def __post_init__(self) -> None:
        if type(self.should_pause) is not bool:
            raise LifecycleError("invalid_pause_decision", "pause decision flag must be boolean")
        if self.should_pause:
            _validate_reason(self.reason, required=True)
        elif self.reason is not None or self.checkpoint_payload is not None:
            raise LifecycleError("invalid_pause_decision", "non-pause decision contains pause data")
        if self.checkpoint_payload is not None and not isinstance(self.checkpoint_payload, dict):
            raise LifecycleError("invalid_pause_decision", "checkpoint payload must be an object")
        if type(self.checkpoint_persisted) is not bool:
            raise LifecycleError(
                "invalid_pause_decision", "checkpoint persistence flag must be boolean"
            )
        if self.checkpoint_persisted and (not self.should_pause or self.checkpoint_payload is None):
            raise LifecycleError(
                "invalid_pause_decision", "persisted checkpoint requires a pause payload"
            )

    def ack_message(self, *, stage: str, sequence: int = 0) -> bytes:
        if not self.should_pause or self.reason is None:
            raise LifecycleError("pause_not_requested", "pause acknowledgement requires a pause")
        if not isinstance(stage, str) or stage not in scheduler.STAGES:
            raise LifecycleError("unknown_stage", "pause acknowledgement has an unknown stage")
        return messages.encode_message(
            "pause_ack", sequence, {"stage": stage, "reason": self.reason}
        )


@dataclass(frozen=True)
class StopPolicy:
    graceful_signal: str = "TERM"
    force_signal: str = "KILL"
    timeout_seconds: int = 10

    def __post_init__(self) -> None:
        if (
            not isinstance(self.graceful_signal, str)
            or not isinstance(self.force_signal, str)
            or self.graceful_signal not in ALLOWED_STOP_SIGNALS
            or self.force_signal not in ALLOWED_STOP_SIGNALS
            or self.graceful_signal == self.force_signal
            or type(self.timeout_seconds) is not int
            or not 0 < self.timeout_seconds <= MAX_STOP_TIMEOUT_SECONDS
        ):
            raise LifecycleError(
                "invalid_stop_policy", "stop policy signals or timeout are out of bounds"
            )


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

    def wait(self, timeout_seconds: int) -> bool | int: ...


def cooperative_pause(
    *,
    stage: str,
    cursor: Mapping[str, Any],
    counters: Mapping[str, Any],
    pause: PauseRequest,
    persist_checkpoint: Callable[[Mapping[str, Any]], object] | None = None,
) -> PauseDecision:
    """Create a pause snapshot and optionally persist it before acknowledgement."""

    if not isinstance(stage, str) or stage not in scheduler.STAGES:
        raise LifecycleError("unknown_stage", "pause requested for unknown stage")
    if not pause.requested:
        return PauseDecision(False, None)

    payload = _snapshot_mapping(
        {
            "stage": stage,
            "cursor": cursor,
            "counters": counters,
            "reason": pause.reason,
        },
        label="pause checkpoint",
    )
    if persist_checkpoint is not None:
        try:
            result = persist_checkpoint(copy.deepcopy(payload))
        except Exception as error:
            raise LifecycleError(
                "checkpoint_failed", "pause checkpoint could not be persisted"
            ) from error
        if result is False:
            raise LifecycleError("checkpoint_failed", "pause checkpoint was not persisted")
    return PauseDecision(
        True,
        pause.reason,
        payload,
        checkpoint_persisted=persist_checkpoint is not None,
    )


def safe_stop_process(
    process: StageProcess,
    *,
    policy: StopPolicy = StopPolicy(),
    checkpoint_preserved: bool = False,
) -> StopResult:
    """Stop a subprocess without force-killing before a durable checkpoint exists."""

    if type(checkpoint_preserved) is not bool:
        raise LifecycleError("invalid_stop_request", "checkpoint preservation flag must be boolean")
    try:
        process.send_signal(policy.graceful_signal)
    except ProcessLookupError:
        return StopResult(
            "already_stopped", "", None, checkpoint_preserved, "process already exited"
        )
    except OSError:
        return StopResult(
            "stop_failed", "", None, checkpoint_preserved, "graceful stop signal could not be sent"
        )

    graceful_wait = _wait_for_exit(process, policy.timeout_seconds)
    if graceful_wait.exited:
        return StopResult(
            "stopped",
            policy.graceful_signal,
            None,
            checkpoint_preserved,
            "graceful stop completed",
        )
    if not graceful_wait.timed_out:
        return StopResult(
            "stop_failed",
            policy.graceful_signal,
            None,
            checkpoint_preserved,
            "graceful stop status could not be verified",
        )
    if not checkpoint_preserved:
        return StopResult(
            "force_blocked",
            policy.graceful_signal,
            None,
            False,
            "graceful stop timed out; force signal withheld until checkpoint preservation",
        )

    try:
        process.send_signal(policy.force_signal)
    except ProcessLookupError:
        return StopResult(
            "stopped",
            policy.graceful_signal,
            None,
            True,
            "process exited before force signal was needed",
        )
    except OSError:
        return StopResult(
            "force_failed",
            policy.graceful_signal,
            None,
            True,
            "graceful stop timed out; force signal could not be sent",
        )

    force_wait = _wait_for_exit(process, FORCE_WAIT_SECONDS)
    if force_wait.exited:
        return StopResult(
            "force_stopped",
            policy.graceful_signal,
            policy.force_signal,
            True,
            "graceful stop timed out; force signal sent after checkpoint preservation",
        )
    return StopResult(
        "force_stop_timeout" if force_wait.timed_out else "force_failed",
        policy.graceful_signal,
        policy.force_signal,
        True,
        "force signal sent but process exit could not be verified",
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

    if not _valid_fingerprint(expected_source_fingerprint) or not _valid_fingerprint(
        current_source_fingerprint
    ):
        return RestartDecision("blocked", (), "source fingerprint is invalid")
    if current_source_fingerprint != expected_source_fingerprint:
        return RestartDecision("blocked", (), "source reconnect fingerprint mismatch")
    try:
        checkpoint = load_checkpoint()
    except checkpoints.CheckpointError as error:
        plan = _restart_plan(completed_stages, config)
        status = "restart_stage" if error.restart_stage else "blocked"
        runnable = plan.runnable if error.restart_stage else ()
        return RestartDecision(status, runnable, _safe_reason(str(error)))
    validation_error, cursor = _checkpoint_snapshot_error(checkpoint, current_source_fingerprint)
    if validation_error is not None:
        plan = _restart_plan(completed_stages, config)
        return RestartDecision("restart_stage", plan.runnable, validation_error)
    plan = _restart_plan(completed_stages, config)
    return RestartDecision("resume", plan.runnable, "checkpoint validated", cursor)


def paused_statuses(statuses: Mapping[str, str]) -> dict[str, str]:
    """Expose scheduler pause propagation through the lifecycle API."""

    return scheduler.pause_all(statuses)


@dataclass(frozen=True)
class _WaitResult:
    exited: bool
    timed_out: bool


def _wait_for_exit(process: StageProcess, timeout_seconds: int) -> _WaitResult:
    try:
        result = process.wait(timeout_seconds)
    except (TimeoutExpired, TimeoutError):
        return _WaitResult(False, True)
    except OSError:
        return _WaitResult(False, False)
    if type(result) is bool:
        return _WaitResult(result, not result)
    if type(result) is int:
        return _WaitResult(True, False)
    raise LifecycleError("invalid_process_status", "stage process returned an invalid wait status")


def _snapshot_mapping(value: Mapping[str, Any], *, label: str) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise LifecycleError("invalid_checkpoint", f"{label} must be an object")
    try:
        normalized = _materialize_json(value, label=label)
        encoded = json.dumps(normalized, allow_nan=False, sort_keys=True, separators=(",", ":"))
        if len(encoded.encode("utf-8")) > MAX_CHECKPOINT_PAYLOAD_BYTES:
            raise LifecycleError("checkpoint_too_large", f"{label} exceeds the bounded limit")
        snapshot = json.loads(encoded)
    except LifecycleError:
        raise
    except (TypeError, ValueError, RecursionError, OverflowError) as error:
        raise LifecycleError("invalid_checkpoint", f"{label} is not canonical JSON") from error
    if not isinstance(snapshot, dict):
        raise LifecycleError("invalid_checkpoint", f"{label} must be an object")
    return snapshot


def _materialize_json(value: object, *, label: str) -> object:
    if isinstance(value, Mapping):
        normalized: dict[str, object] = {}
        for key, child in value.items():
            if not isinstance(key, str):
                raise LifecycleError("invalid_checkpoint", f"{label} keys must be strings")
            normalized[key] = _materialize_json(child, label=label)
        return normalized
    if isinstance(value, list | tuple):
        return [_materialize_json(child, label=label) for child in value]
    return value


def _validate_reason(reason: object, *, required: bool) -> None:
    if not isinstance(reason, str):
        raise LifecycleError("invalid_pause_reason", "pause reason must be text")
    if len(reason) > messages.MAX_FIELD_CHARS or any(char in reason for char in "\x00\n\r"):
        raise LifecycleError(
            "invalid_pause_reason", "pause reason is too long or contains controls"
        )
    if required and not reason.strip():
        raise LifecycleError("invalid_pause_reason", "pause reason must not be empty")


def _valid_fingerprint(value: object) -> bool:
    return isinstance(value, str) and checkpoints.SHA256_RE.fullmatch(value) is not None


def _checkpoint_snapshot_error(
    checkpoint: object, current_source_fingerprint: str
) -> tuple[str | None, dict[str, Any] | None]:
    if not isinstance(checkpoint, checkpoints.CheckpointRecord):
        return "checkpoint record is malformed; restart stage", None
    if checkpoint.source_fingerprint != current_source_fingerprint:
        return "checkpoint source fingerprint mismatch; restart stage", None
    if (
        type(checkpoint.checkpoint_version) is not int
        or checkpoint.checkpoint_version != checkpoints.SUPPORTED_CHECKPOINT_VERSION
    ):
        return "unsupported checkpoint version; restart stage", None
    if not isinstance(checkpoint.stage, str) or checkpoint.stage not in scheduler.STAGES:
        return "checkpoint stage is unknown; restart stage", None
    try:
        cursor = _snapshot_mapping(checkpoint.cursor, label="checkpoint cursor")
        _snapshot_mapping(checkpoint.counters, label="checkpoint counters")
    except LifecycleError as error:
        return (
            _safe_reason(str(error), fallback="checkpoint record is malformed; restart stage"),
            None,
        )
    return None, cursor


def _restart_plan(
    completed_stages: set[str], config: scheduler.SchedulerConfig
) -> scheduler.StagePlan:
    try:
        return scheduler.restart_plan(set(completed_stages), config)
    except scheduler.SchedulerError as error:
        raise LifecycleError("invalid_restart_plan", str(error)) from error


def _safe_reason(reason: str, fallback: str = "checkpoint cannot be trusted; restart stage") -> str:
    if (
        not isinstance(reason, str)
        or len(reason) > messages.MAX_FIELD_CHARS
        or any(char in reason for char in "\x00\n\r")
    ):
        return fallback
    return reason
