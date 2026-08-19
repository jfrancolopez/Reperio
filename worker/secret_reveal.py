"""Safe reveal, copy, and lifecycle of recovered secrets (RPR-102).

Adds the reveal/permission and redaction layer on top of the encrypted secret
store. Plaintext secret values are returned only through permission-gated,
time-bounded reveal sessions that auto-hide, and never enter audit records,
events, telemetry, or support bundles.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from shared.secret_store import MASKED_VALUE, SECRET_REF_PREFIX, SecretStore

SECRET_REVEAL_VERSION = "secret-reveal-v1"
REVEAL_MODES = frozenset({"authenticated", "unauthenticated_lan", "denied"})
REVEAL_EVENT_TYPE = "secret.reveal"
CLIPBOARD_EVENT_TYPE = "secret.clipboard"
REDACTED_REF = "vault:[redacted]"


class RevealError(ValueError):
    """Raised when a reveal or clipboard action violates policy."""


@dataclass(frozen=True)
class RevealPolicy:
    mode: str
    auto_hide_seconds: int
    clipboard_clear_seconds: int
    non_persistent: bool = False
    require_lan_warning_ack: bool = True

    def __post_init__(self) -> None:
        if self.mode not in REVEAL_MODES:
            raise RevealError("reveal mode must be authenticated, unauthenticated_lan, or denied")
        if self.auto_hide_seconds <= 0 or self.clipboard_clear_seconds <= 0:
            raise RevealError("hide and clipboard clear durations must be positive")


@dataclass(frozen=True)
class RevealDecision:
    allowed: bool
    mode: str
    reasons: tuple[str, ...] = ()


@dataclass(frozen=True)
class RevealSession:
    ref: str
    expires_at: str
    auto_hidden: bool = False
    revealed_value: str | None = None
    non_persistent: bool = False
    reason: str | None = None

    def hide(self, *, now: str, auto: bool) -> RevealSession:
        return RevealSession(
            ref=self.ref,
            expires_at=self.expires_at,
            auto_hidden=True,
            revealed_value=None,
            non_persistent=self.non_persistent,
            reason="auto_hide_expired" if auto else "manual_hide",
        )


@dataclass(frozen=True)
class ClipboardCopy:
    value: str
    clear_at: str


def reveal_permission(
    policy: RevealPolicy,
    *,
    mode: str,
    lan_warning_acknowledged: bool,
) -> RevealDecision:
    """Decide whether a reveal may occur for the given mode."""
    reasons: list[str] = []
    if policy.mode == "denied":
        reasons.append("reveal_mode_denied")
    if mode not in REVEAL_MODES:
        reasons.append("invalid_reveal_mode")
    if (
        policy.mode == "unauthenticated_lan"
        and policy.require_lan_warning_ack
        and not lan_warning_acknowledged
    ):
        reasons.append("lan_warning_not_acknowledged")
    return RevealDecision(allowed=not reasons, mode=mode, reasons=tuple(dict.fromkeys(reasons)))


def create_reveal_session(
    *,
    ref: str,
    value: str,
    policy: RevealPolicy,
    now: str,
) -> RevealSession:
    """Open a time-bounded session carrying the plaintext for reveal."""
    _require_valid_ref(ref)
    return RevealSession(
        ref=ref,
        expires_at=_plus_seconds(now, policy.auto_hide_seconds),
        revealed_value=value,
        non_persistent=policy.non_persistent,
    )


def auto_hide_due(session: RevealSession, *, now: str) -> bool:
    return _is_after(now, session.expires_at)


def reveal_audit_record(
    *,
    ref: str,
    decision: RevealDecision,
    now: str,
    session: RevealSession | None = None,
    forbidden_values: tuple[str, ...] = (),
) -> dict[str, Any]:
    """Audit record that can never carry secret values."""
    record: dict[str, Any] = {
        "event_type": REVEAL_EVENT_TYPE,
        "ref": ref,
        "mode": decision.mode,
        "allowed": decision.allowed,
        "reasons": list(decision.reasons),
        "masked_value": MASKED_VALUE,
        "reveal_version": SECRET_REVEAL_VERSION,
        "recorded_at": now,
    }
    if session is not None:
        record["auto_hidden"] = session.auto_hidden
        record["non_persistent"] = session.non_persistent
    assert_secret_free(record, forbidden_values)
    return record


def clipboard_prepare(
    session: RevealSession,
    *,
    policy: RevealPolicy,
    now: str,
) -> ClipboardCopy:
    """Prepare a clipboard copy that must be auto-cleared."""
    if session.auto_hidden or session.revealed_value is None:
        raise RevealError("reveal session is hidden; cannot copy")
    return ClipboardCopy(
        value=session.revealed_value,
        clear_at=_plus_seconds(now, policy.clipboard_clear_seconds),
    )


def clipboard_due(copy: ClipboardCopy, *, now: str) -> bool:
    return _is_after(now, copy.clear_at)


def clipboard_audit_record(
    *,
    ref: str,
    mode: str,
    now: str,
    forbidden_values: tuple[str, ...] = (),
) -> dict[str, Any]:
    record: dict[str, Any] = {
        "event_type": CLIPBOARD_EVENT_TYPE,
        "ref": ref,
        "mode": mode,
        "masked_value": MASKED_VALUE,
        "reveal_version": SECRET_REVEAL_VERSION,
        "recorded_at": now,
    }
    assert_secret_free(record, forbidden_values)
    return record


def scrub_secret_refs(text: str) -> str:
    """Replace opaque vault references with a redacted marker in text."""
    import re

    return re.sub(rf"{re.escape(SECRET_REF_PREFIX)}[0-9a-f]{{32}}", REDACTED_REF, text)


def assert_secret_free(record: Any, forbidden_values: tuple[str, ...]) -> None:
    """Fail if any plaintext secret appears anywhere in the record."""
    if not forbidden_values:
        return
    serialized = repr(record)
    for value in forbidden_values:
        if value in serialized:
            raise RevealError("secret value leaked into an audit or telemetry record")


def delete_secret(store: SecretStore, *, ref: str) -> dict[str, Any]:
    """Delete the encrypted secret; audit and result status are left intact."""
    _require_valid_ref(ref)
    store.delete(ref)
    return {
        "event_type": "secret.deleted",
        "ref": ref,
        "masked_value": MASKED_VALUE,
        "deleted": True,
    }


def _require_valid_ref(ref: str) -> None:
    if not ref.startswith(SECRET_REF_PREFIX):
        raise RevealError("secret reference must be opaque vault reference")
    name = ref.removeprefix(SECRET_REF_PREFIX)
    if len(name) != 32 or any(char not in "0123456789abcdef" for char in name):
        raise RevealError("secret reference is malformed")


def _plus_seconds(timestamp: str, seconds: int) -> str:
    try:
        import datetime

        dt = datetime.datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
        return (dt + datetime.timedelta(seconds=seconds)).isoformat().replace("+00:00", "Z")
    except ValueError as error:
        raise RevealError("timestamp must be ISO-8601 UTC") from error


def _is_after(after: str, before: str) -> bool:
    import datetime

    return datetime.datetime.fromisoformat(
        after.replace("Z", "+00:00")
    ) > datetime.datetime.fromisoformat(before.replace("Z", "+00:00"))
