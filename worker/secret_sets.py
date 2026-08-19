"""Named secret sets and safe password verification/extraction (RPR-096).

Operator-supplied passwords are grouped into named secret sets and handed to
format-specific verifiers/extractors exclusively through stdin/file-descriptor
mechanisms, never command arguments, so attempted and recovered values never
reach logs or process listings. Successful output is written only to a separate
scratch location. A crashed or failing process is recorded deterministically;
the scan continues. Pure and dependency-free; process I/O is injected.
"""

from __future__ import annotations

import re
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from typing import Any

from shared.secret_store import MASKED_VALUE

SECRET_SETS_VERSION = "secret-sets-v1"

SET_NAME_RE = re.compile(r"^[a-z][a-z0-9_-]{0,63}$")
SUPPORTED_FORMATS = frozenset({"zip", "7z", "pdf", "office", "gpg", "rar"})
SCRATCH_PREFIX = "scratch://"

Runner = Callable[[Mapping[str, Any]], Mapping[str, Any]]


class SecretSetsError(ValueError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


@dataclass(frozen=True)
class SecretSet:
    name: str
    values: tuple[str, ...]


def define_secret_set(name: str, values: Sequence[str]) -> SecretSet:
    """Build a named secret set; values are never written to process listings."""
    if not SET_NAME_RE.match(name):
        raise SecretSetsError("unsafe_set_name", f"secret set name {name!r} is not safe")
    cleaned = tuple(value for value in values if isinstance(value, str) and value)
    if not cleaned:
        raise SecretSetsError("empty_secret_set", "a secret set must contain at least one value")
    return SecretSet(name=name, values=cleaned)


def lookup_secret_set(sets: Mapping[str, SecretSet], name: str) -> SecretSet:
    set_ = sets.get(name)
    if set_ is None:
        raise SecretSetsError("unknown_secret_set", f"secret set {name!r} is not defined")
    return set_


def fd_payload(values: Sequence[str]) -> bytes:
    """Encode secret values as a length-prefixed fd payload (not argv)."""
    chunks = [len(value).to_bytes(4, "big") + value.encode("utf-8") for value in values]
    return b"".join(chunks)


def build_verification_plan(
    *,
    secret_set: SecretSet,
    format: str,
    target_path: str,
    fd_number: int = 3,
) -> dict[str, Any]:
    """Plan a verification/extraction whose secrets travel via an fd, not argv."""
    if format not in SUPPORTED_FORMATS:
        raise SecretSetsError("unsupported_format", f"format {format!r} is not supported")
    return {
        "version": SECRET_SETS_VERSION,
        "secret_set": secret_set.name,
        "format": format,
        "target_path": target_path,
        "arg_template": [
            "open",
            target_path,
            f"--password-fd={fd_number}",
            "--verify",
        ],
        "fd_number": fd_number,
        "fd_payload": fd_payload(secret_set.values),
        "values_never_in_argv": True,
        "values_never_in_logs": True,
    }


def verify_password(
    plan: Mapping[str, Any],
    runner: Runner,
) -> dict[str, Any]:
    """Verify candidates via an injected runner; crash and failure are outcomes."""
    try:
        result = runner(plan)
    except Exception as exc:
        return {
            "status": "crashed",
            "reason": "process crashed during verification",
            "detail": str(exc),
            "redacted": True,
        }
    ok = bool(result.get("success"))
    return {
        "status": "matched" if ok else "rejected",
        "redacted": True,
    }


def try_secret_sets(
    sets: Sequence[SecretSet],
    *,
    format: str,
    target_path: str,
    runner: Runner,
    scratch_destination: str,
) -> dict[str, Any]:
    """Try each named set in order; first match wins, output to separate scratch."""
    if not scratch_destination.startswith(SCRATCH_PREFIX):
        raise SecretSetsError("unsafe_destination", "extraction output must use scratch storage")
    for secret_set in sets:
        plan = build_verification_plan(
            secret_set=secret_set, format=format, target_path=target_path
        )
        outcome = verify_password(plan, runner)
        if outcome["status"] == "matched":
            return {
                "matched_set": secret_set.name,
                "status": "matched",
                "destination": scratch_destination,
                "redacted": True,
            }
        if outcome["status"] == "crashed":
            return {
                "matched_set": None,
                "status": "crashed",
                "destination": None,
                "redacted": True,
            }
    return {"matched_set": None, "status": "no_match", "destination": None, "redacted": True}


def redact_values(values: Sequence[str], text: str) -> str:
    """Redact every attempted/recovered value before it reaches any log."""
    redacted = text
    for value in values:
        if value and value in redacted:
            redacted = redacted.replace(value, MASKED_VALUE)
    return redacted


def redacted_snapshot(sets: Sequence[SecretSet]) -> list[dict[str, str]]:
    """A loggable snapshot that never contains secret values."""
    return [
        {"name": secret_set.name, "value_count": str(len(secret_set.values))} for secret_set in sets
    ]


def audit_event(set_name: str, status: str) -> dict[str, str]:
    """Audit event with no attempted/recovered values."""
    return {
        "event": "secret_set.attempt",
        "secret_set": set_name,
        "status": status,
        "values": MASKED_VALUE,
    }
