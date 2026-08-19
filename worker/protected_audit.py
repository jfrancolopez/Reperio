"""Protected-target audit job model (RPR-095).

Detection and auditing are separate: a protected artifact is detected first
(RPR-081) and an audit target is created from it, never re-detected by the
audit job. Audit jobs are opt-in and model only opaque secret-set references;
plaintext secrets are rejected. State transitions, checkpoints, resource
budgets, cost estimates, and result-secret references are deterministic and
dependency-free so the job runner and migration layer can reuse them.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass, replace
from typing import Any

AUDIT_VERSION = "protected-audit-v1"
SECRET_REF_PREFIX = "vault:"
SECRET_REF_RE = re.compile(rf"^{SECRET_REF_PREFIX}[0-9a-f]{{32}}$")

TARGET_FORMATS = frozenset(
    {"kdbx", "pdf", "office-openxml", "zip", "7z", "rar", "gpg", "wallet", "volume"}
)
KDF_NAMES = frozenset({"pbkdf2", "scrypt", "argon2", "bcrypt", "na", "unknown"})
ENGINE_STRATEGIES = frozenset({"stdin", "fd"})
AUDIT_STATES = frozenset(
    {"pending", "queued", "running", "verifying", "completed", "failed", "blocked", "cancelled"}
)
COST_TIERS = frozenset({"low", "medium", "high"})

ALLOWED_TRANSITIONS: dict[str, frozenset[str]] = {
    "pending": frozenset({"queued", "cancelled", "failed"}),
    "queued": frozenset({"running", "cancelled", "failed"}),
    "running": frozenset({"verifying", "failed", "cancelled"}),
    "verifying": frozenset({"completed", "failed"}),
    "completed": frozenset(),
    "failed": frozenset({"queued"}),
    "blocked": frozenset({"queued"}),
    "cancelled": frozenset(),
}

DEFAULT_BUDGET_BY_FORMAT: dict[str, tuple[int, int, int]] = {
    "kdbx": (300, 512 * 1024 * 1024, 3),
    "pdf": (300, 512 * 1024 * 1024, 3),
    "office-openxml": (300, 512 * 1024 * 1024, 3),
    "zip": (120, 256 * 1024 * 1024, 3),
    "7z": (300, 512 * 1024 * 1024, 3),
    "rar": (300, 512 * 1024 * 1024, 3),
    "gpg": (300, 512 * 1024 * 1024, 3),
    "wallet": (600, 1024 * 1024 * 1024, 3),
    "volume": (1800, 4 * 1024 * 1024 * 1024, 3),
}

KDF_COST_MULTIPLIER: dict[str, float] = {
    "pbkdf2": 1.0,
    "scrypt": 1.6,
    "argon2": 1.6,
    "bcrypt": 1.3,
    "na": 1.0,
    "unknown": 1.0,
}


class ProtectedAuditError(ValueError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


@dataclass(frozen=True)
class ResourceBudget:
    max_cpu_seconds: int
    max_memory_bytes: int
    max_attempts: int

    def within(self, cpu_seconds: int, memory_bytes: int) -> bool:
        return cpu_seconds <= self.max_cpu_seconds and memory_bytes <= self.max_memory_bytes


@dataclass(frozen=True)
class CostEstimate:
    cpu_seconds: int
    memory_bytes: int
    tier: str


@dataclass(frozen=True)
class AuditCheckpoint:
    stage: str
    cursor: str
    counters: Mapping[str, int]


@dataclass(frozen=True)
class AuditTarget:
    target_id: str
    artifact_id: str
    finding_id: str
    format: str
    kdf: str
    protection_kind: str
    status: str
    secret_set_ref: str
    engine_strategy: str
    budget: ResourceBudget
    checkpoint: AuditCheckpoint | None
    result_secret_ref: str | None
    attempts: int
    state: str
    error_code: str | None
    parser_version: str = AUDIT_VERSION


def normalize_target(record: Mapping[str, Any]) -> AuditTarget:
    """Normalize and validate one audit target record.

    Detection data (protection kind, format) is read-only input. Unsupported
    formats are rejected here; plaintext secrets are never accepted.
    """
    target_id = _required_str(record, "target_id")
    artifact_id = _required_str(record, "artifact_id")
    finding_id = _required_str(record, "finding_id")
    format_name = _required_str(record, "format")
    if format_name not in TARGET_FORMATS:
        raise ProtectedAuditError(
            "unsupported_format", f"format {format_name!r} is not an audit target format"
        )
    kdf = str(record.get("kdf") or "unknown")
    if kdf not in KDF_NAMES:
        raise ProtectedAuditError("unsupported_kdf", f"KDF {kdf!r} is not recognized")
    protection_kind = str(record.get("protection_kind") or "unknown")[:128]
    secret_set_ref = _secret_ref(record.get("secret_set_ref"), "secret_set_ref")
    engine_strategy = str(record.get("engine_strategy") or "stdin")
    if engine_strategy not in ENGINE_STRATEGIES:
        raise ProtectedAuditError(
            "unsupported_strategy", f"engine strategy {engine_strategy!r} is not supported"
        )
    budget = _budget(record.get("budget"), format_name)
    raw_secret_result = record.get("result_secret_ref")
    result_secret_ref = (
        _secret_ref(raw_secret_result, "result_secret_ref")
        if raw_secret_result is not None
        else None
    )
    attempts = _nonnegative_int(record.get("attempts"), "attempts")
    state = str(record.get("state") or "pending")
    if state not in AUDIT_STATES:
        raise ProtectedAuditError("invalid_state", f"state {state!r} is not an audit state")
    return AuditTarget(
        target_id=target_id,
        artifact_id=artifact_id,
        finding_id=finding_id,
        format=format_name,
        kdf=kdf,
        protection_kind=protection_kind,
        status=str(record.get("status") or "pending"),
        secret_set_ref=secret_set_ref,
        engine_strategy=engine_strategy,
        budget=budget,
        checkpoint=_checkpoint(record.get("checkpoint")),
        result_secret_ref=result_secret_ref,
        attempts=attempts,
        state=state,
        error_code=record.get("error_code") if isinstance(record.get("error_code"), str) else None,
    )


def estimate_target_cost(format_name: str, kdf: str) -> CostEstimate:
    """Deterministic worst-case CPU/memory estimate for one target."""
    if format_name not in TARGET_FORMATS:
        raise ProtectedAuditError(
            "unsupported_format", "cannot estimate cost for an unknown format"
        )
    cpu_seconds, memory_bytes, _ = DEFAULT_BUDGET_BY_FORMAT[format_name]
    multiplier = KDF_COST_MULTIPLIER.get(kdf, 1.0)
    cpu = int(cpu_seconds * multiplier)
    if cpu <= 120:
        tier = "low"
    elif cpu <= 480:
        tier = "medium"
    else:
        tier = "high"
    return CostEstimate(cpu_seconds=cpu, memory_bytes=memory_bytes, tier=tier)


def transition_audit(target: AuditTarget, to_state: str) -> AuditTarget:
    """Apply one validated audit-job state transition."""
    if to_state not in AUDIT_STATES:
        raise ProtectedAuditError("invalid_state", f"state {to_state!r} is not an audit state")
    if to_state not in ALLOWED_TRANSITIONS[target.state]:
        raise ProtectedAuditError(
            "invalid_transition", f"invalid audit transition {target.state} -> {to_state}"
        )
    return replace(target, state=to_state)


def fail_audit(target: AuditTarget, error_code: str) -> AuditTarget:
    if target.state not in {"pending", "queued", "running", "verifying"}:
        raise ProtectedAuditError("invalid_transition", "audit is already terminal")
    return replace(target, state="failed", error_code=error_code[:128])


def block_audit(target: AuditTarget, error_code: str) -> AuditTarget:
    if target.state not in {"pending", "queued"}:
        raise ProtectedAuditError("invalid_transition", "only pending or queued audits may block")
    return replace(target, state="blocked", error_code=error_code[:128])


def restart_audit(target: AuditTarget) -> AuditTarget:
    """Reset a failed or blocked audit for another attempt without changing the target."""
    if target.state not in {"failed", "blocked"}:
        raise ProtectedAuditError("invalid_transition", "only failed or blocked audits may restart")
    if target.attempts >= target.budget.max_attempts:
        raise ProtectedAuditError("attempt_limit", "audit has exhausted its attempt budget")
    return replace(target, state="queued", attempts=target.attempts + 1, error_code=None)


def update_checkpoint(
    target: AuditTarget, stage: str, cursor: str, counters: Mapping[str, int]
) -> AuditTarget:
    """Advance the audit checkpoint and enforce the resource budget."""
    if target.state not in {"running", "verifying"}:
        raise ProtectedAuditError("invalid_checkpoint", "checkpoints only advance while running")
    cpu_seconds = int(counters.get("cpu_seconds", 0)) + int(counters.get("elapsed_seconds", 0))
    if not target.budget.within(cpu_seconds, int(counters.get("memory_bytes", 0))):
        raise ProtectedAuditError("budget_exceeded", "audit exceeds its resource budget")
    return replace(
        target,
        checkpoint=AuditCheckpoint(stage=stage[:128], cursor=cursor[:512], counters=dict(counters)),
    )


def verify_secret_reference(target: AuditTarget, secret_store: object) -> AuditTarget:
    """Check the supplied secret set still exists; block the audit otherwise.

    ``secret_store`` must expose ``metadata(ref)`` and raise ``KeyError`` when a
    reference no longer exists. Secret values are never read here.
    """
    metadata = getattr(secret_store, "metadata")
    try:
        metadata(target.secret_set_ref)
    except (KeyError, IndexError):
        return block_audit(target, "secret_set_missing")
    return target


def _secret_ref(value: object, label: str) -> str:
    if not isinstance(value, str) or not SECRET_REF_RE.fullmatch(value):
        raise ProtectedAuditError(
            "inline_secret_rejected", f"{label} must be an opaque vault reference"
        )
    return value


def _budget(value: object, format_name: str) -> ResourceBudget:
    default_cpu, default_memory, default_attempts = DEFAULT_BUDGET_BY_FORMAT[format_name]
    if value is None:
        return ResourceBudget(default_cpu, default_memory, default_attempts)
    if not isinstance(value, Mapping):
        raise ProtectedAuditError("malformed_budget", "budget must be an object")
    return ResourceBudget(
        max_cpu_seconds=_positive_int(value.get("max_cpu_seconds", default_cpu), "max_cpu_seconds"),
        max_memory_bytes=_positive_int(
            value.get("max_memory_bytes", default_memory), "max_memory_bytes"
        ),
        max_attempts=_positive_int(value.get("max_attempts", default_attempts), "max_attempts"),
    )


def _checkpoint(value: object) -> AuditCheckpoint | None:
    if value is None:
        return None
    if not isinstance(value, Mapping):
        raise ProtectedAuditError("malformed_checkpoint", "checkpoint must be an object")
    counters = value.get("counters")
    if not isinstance(counters, Mapping):
        raise ProtectedAuditError("malformed_checkpoint", "checkpoint counters must be an object")
    normalized: dict[str, int] = {}
    for key, item in counters.items():
        try:
            normalized[str(key)[:128]] = int(item)
        except (TypeError, ValueError) as error:
            raise ProtectedAuditError(
                "malformed_checkpoint", "checkpoint counters must be ints"
            ) from error
    return AuditCheckpoint(
        stage=str(value.get("stage") or "unknown")[:128],
        cursor=str(value.get("cursor") or "")[:512],
        counters=normalized,
    )


def _required_str(record: Mapping[str, Any], name: str) -> str:
    value = str(record.get(name) or "")
    if not value:
        raise ProtectedAuditError("missing_field", f"{name} is required")
    return value


def _positive_int(value: object, label: str) -> int:
    if not isinstance(value, int) or value <= 0:
        raise ProtectedAuditError("invalid_integer", f"{label} must be a positive integer")
    return value


def _nonnegative_int(value: object, label: str) -> int:
    if value is None:
        return 0
    if not isinstance(value, int) or value < 0:
        raise ProtectedAuditError("invalid_integer", f"{label} must be a non-negative integer")
    return value
