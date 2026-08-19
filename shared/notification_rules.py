"""Configurable notification rules, event summaries, and redaction (RPR-111).

Rules select which outbox events may produce a notification, with threshold,
throttle, and quiet-hour controls. Summaries are built from allowlisted payload
fields only and pass a final redaction pass so filenames, URLs, document text,
thumbnails, wallet identifiers, recovery phrases, keys, and passwords never
reach a notification by default. High-value/sensitive alerts are counts-only
and carry a local UI link. This module never touches job state; delivery
failure leaves the outbox event unpublished and the job untouched.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

NOTIFICATION_VERSION = "notification-rules-v1"
REDACTED = "[redacted]"

NOTIFICATION_EVENT_TYPES = frozenset(
    {
        "job.start",
        "job.progress",
        "job.heartbeat",
        "job.count",
        "job.high-value-sensitive-count",
        "job.health",
        "job.disconnect",
        "job.pause",
        "job.failure",
        "job.export",
        "job.password-success",
        "job.completion",
    }
)

COUNT_EVENT_TYPES = frozenset({"job.count", "job.high-value-sensitive-count"})
SEVERITIES = frozenset({"info", "warning", "critical"})

# Sensitive payload keys are never interpolated into summaries by default.
FORBIDDEN_KEYS = frozenset(
    {
        "display_path",
        "path",
        "source_path",
        "original_path",
        "url",
        "uri",
        "endpoint",
        "thumbnail",
        "thumb",
        "text",
        "document",
        "recovery_phrase",
        "seed",
        "passphrase",
        "password",
        "wallet_id",
        "wallet",
        "keystore",
        "private_key",
        "key",
        "secret",
        "api_key",
        "token",
        "note",
        "error_detail",
    }
)

# Final safety net for anything that leaks past interpolation.
FORBIDDEN_PATTERNS = (
    re.compile(r"(?i)(?:recovery|seed)\s*(?:phrase|words?)?[=:\s][A-Za-z ]{12,}"),
    re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    re.compile(r"(?i)wallet[_-]?id\s*[=:]\s*\S{6,}"),
    re.compile(r"(?i)password\s*[=:]\s*\S{6,}"),
    re.compile(r"(?i)api[_-]?key\s*[=:]\s*\S{8,}"),
    re.compile(r"(?i)bearer\s+[a-z0-9._~+/\-]{16,}"),
)

SAFE_TOKENS = frozenset(
    {
        "case_id",
        "job_id",
        "state",
        "percent",
        "count",
        "high_value_count",
        "sensitive_count",
        "health",
    }
)

TOKEN_RE = re.compile(r"\{([a-z_][a-z0-9_]*)\}")

DEFAULT_TEMPLATES: dict[str, str] = {
    "job.start": "Scan job {job_id} started",
    "job.progress": "Scan job {job_id} is {percent}% complete",
    "job.heartbeat": "Scan job {job_id} is still running",
    "job.count": "Scan found {count} findings so far",
    "job.high-value-sensitive-count": (
        "High-value and sensitive findings detected for job {job_id}"
    ),
    "job.health": "Host health check for job {job_id}: {health}",
    "job.disconnect": "Source disconnected during job {job_id}",
    "job.pause": "Scan job {job_id} paused",
    "job.failure": "Scan job {job_id} failed",
    "job.export": "Export for job {job_id} completed with {count} items",
    "job.password-success": "A supplied password worked for job {job_id}",
    "job.completion": "Scan job {job_id} completed",
}

DEFAULT_SEVERITY: dict[str, str] = {
    "job.start": "info",
    "job.progress": "info",
    "job.heartbeat": "info",
    "job.count": "info",
    "job.high-value-sensitive-count": "critical",
    "job.health": "warning",
    "job.disconnect": "warning",
    "job.pause": "info",
    "job.failure": "critical",
    "job.export": "info",
    "job.password-success": "warning",
    "job.completion": "info",
}


class NotificationRulesError(ValueError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


@dataclass(frozen=True)
class NotificationRule:
    event_type: str
    enabled: bool
    threshold: int | None
    threshold_once: bool
    throttle_seconds: int
    quiet_start: str | None
    quiet_end: str | None
    severity: str
    template: str

    @property
    def is_count_rule(self) -> bool:
        return self.event_type in COUNT_EVENT_TYPES


@dataclass(frozen=True)
class NotificationRules:
    version: str
    rules: tuple[NotificationRule, ...]
    local_ui_base: str

    def rule_for(self, event_type: str) -> NotificationRule | None:
        for rule in self.rules:
            if rule.event_type == event_type:
                return rule
        return None


@dataclass(frozen=True)
class NotificationDecision:
    send: bool
    reason: str
    crossed_once: bool


@dataclass(frozen=True)
class NotificationSummary:
    event_type: str
    severity: str
    title: str
    body: str
    counts_only: bool
    local_ui_link: str
    redactions: tuple[str, ...]


def default_notification_rules(local_ui_base: str) -> NotificationRules:
    rules: list[NotificationRule] = []
    for event_type in sorted(NOTIFICATION_EVENT_TYPES):
        rules.append(
            NotificationRule(
                event_type=event_type,
                enabled=True,
                threshold=1 if event_type in COUNT_EVENT_TYPES else None,
                threshold_once=event_type == "job.count",
                throttle_seconds=0,
                quiet_start=None,
                quiet_end=None,
                severity=DEFAULT_SEVERITY[event_type],
                template=DEFAULT_TEMPLATES[event_type],
            )
        )
    return NotificationRules(
        version=NOTIFICATION_VERSION, rules=tuple(rules), local_ui_base=local_ui_base
    )


def validate_notification_rules(rules: NotificationRules) -> tuple[str, ...]:
    warnings: list[str] = []
    seen: set[str] = set()
    for rule in rules.rules:
        if rule.event_type in seen:
            warnings.append(f"{rule.event_type}:duplicate_rule")
        seen.add(rule.event_type)
        if rule.event_type not in NOTIFICATION_EVENT_TYPES:
            warnings.append(f"{rule.event_type}:unsupported_event_type")
        if rule.severity not in SEVERITIES:
            warnings.append(f"{rule.event_type}:unsupported_severity")
        if rule.throttle_seconds < 0:
            warnings.append(f"{rule.event_type}:negative_throttle")
        if (rule.quiet_start is None) != (rule.quiet_end is None):
            warnings.append(f"{rule.event_type}:incomplete_quiet_hours")
        for token in TOKEN_RE.findall(rule.template):
            if token not in SAFE_TOKENS:
                warnings.append(f"{rule.event_type}:unsafe_template_token:{token}")
    if not rules.local_ui_base:
        warnings.append("missing_local_ui_base")
    return tuple(warnings)


def evaluate_notification(
    rules: NotificationRules,
    *,
    event_type: str,
    now: str,
    last_sent_at: str | None,
    count: int = 0,
    crossed_once: bool = False,
) -> NotificationDecision:
    """Decide whether one event may notify, given throttle and quiet hours."""
    rule = rules.rule_for(event_type)
    if rule is None:
        return NotificationDecision(False, "no_rule", crossed_once)
    if not rule.enabled:
        return NotificationDecision(False, "disabled", crossed_once)
    if rule.is_count_rule and rule.threshold is not None and count < rule.threshold:
        return NotificationDecision(False, "below_threshold", crossed_once)
    if rule.is_count_rule and rule.threshold_once and crossed_once:
        return NotificationDecision(False, "already_crossed_once", True)
    if _in_quiet_hours(rule, now):
        return NotificationDecision(False, "quiet_hours", crossed_once)
    if last_sent_at is not None and rule.throttle_seconds > 0:
        elapsed = _to_epoch(now) - _to_epoch(last_sent_at)
        if elapsed < rule.throttle_seconds:
            return NotificationDecision(False, "throttled", crossed_once)
    next_crossed = crossed_once or (rule.is_count_rule and rule.threshold is not None)
    return NotificationDecision(True, "matched", next_crossed)


def build_summary(
    event: Mapping[str, Any], rules: NotificationRules, *, decision: NotificationDecision
) -> NotificationSummary | None:
    if not decision.send:
        return None
    event_type = str(event.get("event_type") or "")
    rule = rules.rule_for(event_type)
    if rule is None:
        return None
    payload = event.get("payload") or {}
    if not isinstance(payload, Mapping):
        return None

    case_id = _safe_str(payload.get("case_id")) or str(event.get("case_id") or "")
    counts_only = event_type == "job.high-value-sensitive-count"
    body = _render_template(rule.template, payload)
    redacted, redactions = redact_text(body)

    return NotificationSummary(
        event_type=event_type,
        severity=rule.severity,
        title=rule.template,
        body=redacted,
        counts_only=counts_only,
        local_ui_link=_local_ui_link(rules.local_ui_base, case_id),
        redactions=tuple(redactions),
    )


def redact_text(value: str) -> tuple[str, list[str]]:
    """Redact forbidden patterns and report what was replaced."""
    result = value
    redactions: list[str] = []
    for index, pattern in enumerate(FORBIDDEN_PATTERNS):
        if pattern.search(result):
            result = pattern.sub(REDACTED, result)
            redactions.append(f"pattern:{index}")
    return result, redactions


def _render_template(template: str, payload: Mapping[str, Any]) -> str:
    def replace(match: re.Match[str]) -> str:
        token = match.group(1)
        if token not in SAFE_TOKENS or token in FORBIDDEN_KEYS:
            return REDACTED
        value = payload.get(token)
        if value is None:
            return "?"
        return str(value)

    return TOKEN_RE.sub(replace, template)


def _local_ui_link(base: str, case_id: str) -> str:
    return f"{base.rstrip('/')}/#/case/{case_id}" if case_id else base.rstrip("/")


def _in_quiet_hours(rule: NotificationRule, now: str) -> bool:
    if rule.quiet_start is None or rule.quiet_end is None:
        return False
    minutes = _minutes_of_day(now)
    start = _parse_hhmm(rule.quiet_start)
    end = _parse_hhmm(rule.quiet_end)
    if start <= end:
        return start <= minutes < end
    return minutes >= start or minutes < end


def _parse_hhmm(value: str) -> int:
    try:
        hour, minute = (int(part) for part in value.split(":", 1))
    except (ValueError, AttributeError) as error:
        raise NotificationRulesError(
            "invalid_quiet_hours", f"quiet hours {value!r} are invalid"
        ) from error
    if not (0 <= hour <= 23 and 0 <= minute <= 59):
        raise NotificationRulesError("invalid_quiet_hours", f"quiet hours {value!r} are invalid")
    return hour * 60 + minute


def _minutes_of_day(now: str) -> int:
    parsed = datetime.strptime(now, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)
    return parsed.hour * 60 + parsed.minute


def _to_epoch(now: str) -> int:
    parsed = datetime.strptime(now, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)
    return int(parsed.timestamp())


def _safe_str(value: object) -> str:
    return str(value) if isinstance(value, str | int) else ""
