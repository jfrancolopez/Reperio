"""Remote-provider privacy gate and audit (RPR-093).

Provides a hard local/LAN/remote distinction for provider endpoints, explicit
admin acknowledgment before any remote call, per-provider/category/data-size
policy enforcement, an outbound payload preview/redaction option, and redacted
audit records. A private endpoint that later resolves to a public network
re-triggers acknowledgment. Remote calls are impossible before acknowledgment.
"""

from __future__ import annotations

import ipaddress
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from urllib.parse import urlsplit

from worker.provider_contract import REDACTED, SECRET_PATTERNS

PRIVACY_GATE_VERSION = "privacy-gate-v1"
ENDPOINT_CLASSES = frozenset({"local", "lan", "remote"})
GATE_STATES = frozenset({"acknowledged", "revoked"})
GATE_EVENT_TYPE = "privacy.gate"

ResolveHost = Callable[[str], str | None]


def _unresolved_host(_host: str) -> str | None:
    return None


DEFAULT_RESOLVER: ResolveHost = _unresolved_host

# Cloud metadata services reachable over link-local; gated as remote for safety.
CLOUD_METADATA_HOSTS = frozenset({"169.254.169.254", "metadata.google.internal", "metadata"})

MAX_AUDIT_DETAIL = 256


class PrivacyGateError(ValueError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


@dataclass(frozen=True)
class EndpointClassification:
    endpoint: str
    host: str
    ip: str | None
    endpoint_class: str
    reason: str
    warnings: tuple[str, ...] = ()


@dataclass(frozen=True)
class PrivacyPolicy:
    allowed_categories: frozenset[str]
    max_payload_bytes: int
    deny_categories: frozenset[str] = frozenset()
    preview_redact: bool = True


@dataclass(frozen=True)
class ProviderAcknowledgment:
    provider: str
    accepted_endpoint: str
    endpoint_class: str
    state: str
    acknowledged_at: str

    def revoked(self) -> ProviderAcknowledgment:
        return ProviderAcknowledgment(
            provider=self.provider,
            accepted_endpoint=self.accepted_endpoint,
            endpoint_class=self.endpoint_class,
            state="revoked",
            acknowledged_at=self.acknowledged_at,
        )


@dataclass(frozen=True)
class GateDecision:
    allowed: bool
    endpoint_class: str
    reasons: tuple[str, ...] = ()
    preview: Mapping[str, object] | None = None


def classify_endpoint(
    endpoint: str, *, resolver: ResolveHost = DEFAULT_RESOLVER
) -> EndpointClassification:
    """Classify an endpoint as local, LAN, or remote using IP-based rules."""
    netloc = endpoint
    hostname: str | None = None
    if "://" in endpoint:
        parsed = urlsplit(endpoint)
        netloc = parsed.netloc
        hostname = parsed.hostname
    if netloc.count(":") > 1:
        host = netloc
    elif hostname is not None:
        host = hostname
    else:
        host = netloc.split(":")[0]
    if "@" in host:
        host = host.rsplit("@", 1)[1]
    host = host.strip("[]").lower()
    if not host:
        raise PrivacyGateError("invalid_endpoint", "endpoint has no host")

    warnings: list[str] = []
    if host in CLOUD_METADATA_HOSTS:
        return EndpointClassification(
            endpoint, host, host, "remote", "cloud_metadata_endpoint", tuple(warnings)
        )
    if host == "localhost" or host.endswith(".localhost"):
        return EndpointClassification(endpoint, host, None, "local", "localhost")
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        ip = None
    resolved = ip
    if resolved is None:
        resolved_host = resolver(host)
        if resolved_host:
            try:
                resolved = ipaddress.ip_address(resolved_host)
            except ValueError:
                warnings.append("unresolvable_hostname")
        else:
            warnings.append("unresolvable_hostname")

    if resolved is not None:
        if resolved.is_loopback:
            return EndpointClassification(
                endpoint, host, str(resolved), "local", "loopback", tuple(warnings)
            )
        if resolved.is_private or resolved.is_link_local or resolved.is_reserved:
            return EndpointClassification(
                endpoint, host, str(resolved), "lan", "private_or_link_local", tuple(warnings)
            )
        return EndpointClassification(
            endpoint, host, str(resolved), "remote", "public_ip", tuple(warnings)
        )
    return EndpointClassification(endpoint, host, None, "remote", "unknown_public", tuple(warnings))


def gate_decision(
    *,
    provider: str,
    endpoint_class: str,
    acknowledgment: ProviderAcknowledgment | None,
    policy: PrivacyPolicy,
    categories: set[str] | frozenset[str] | None = None,
    payload_bytes: int = 0,
) -> GateDecision:
    """Decide whether a provider call may proceed and why not otherwise."""
    reasons: list[str] = []
    denied_categories = (set(categories or ()) & set(policy.deny_categories)) - set(
        policy.allowed_categories
    )
    if denied_categories:
        reasons.append("category_denied")
    if payload_bytes > policy.max_payload_bytes:
        reasons.append("payload_too_large")
    if endpoint_class == "remote":
        if acknowledgment is None or acknowledgment.state != "acknowledged":
            reasons.append("remote_not_acknowledged")
        elif acknowledgment.endpoint_class != "remote":
            reasons.append("endpoint_class_promoted_requires_reacknowledgment")
        elif acknowledgment.accepted_endpoint != provider and not _endpoint_matches(
            acknowledgment.accepted_endpoint, provider
        ):
            reasons.append("provider_acknowledgment_mismatch")
    return GateDecision(
        allowed=not reasons,
        endpoint_class=endpoint_class,
        reasons=tuple(dict.fromkeys(reasons)),
    )


def evaluate_redirect(
    original: EndpointClassification, final: EndpointClassification
) -> GateDecision:
    """Block redirects that move a remote call onto a private or local network."""
    reasons: list[str] = []
    if original.endpoint_class == "remote" and final.endpoint_class != "remote":
        reasons.append("redirect_to_private")
    return GateDecision(
        allowed=not reasons,
        endpoint_class=final.endpoint_class,
        reasons=tuple(reasons),
    )


def preview_outbound(payload: Mapping[str, object], *, policy: PrivacyPolicy) -> dict[str, object]:
    """Build a redacted preview of what would be sent; never sends anything."""
    if not policy.preview_redact:
        return {"redacted": False, "payload": dict(payload)}
    preview_text = _flatten(payload)
    redacted_text = preview_text
    for pattern in SECRET_PATTERNS:
        if pattern.search(redacted_text):
            redacted_text = pattern.sub(REDACTED, redacted_text)
    return {
        "redacted": redacted_text != preview_text,
        "payload": dict(payload),
        "preview": redacted_text,
        "byte_size": len(preview_text.encode("utf-8")),
    }


def audit_record(
    *,
    provider: str,
    decision: GateDecision,
    now: str,
    preview: Mapping[str, object] | None = None,
) -> dict[str, object]:
    """Produce a redacted audit record with no payload content or secrets."""
    detail = ", ".join(decision.reasons)[:MAX_AUDIT_DETAIL]
    return {
        "event_type": GATE_EVENT_TYPE,
        "provider": provider,
        "endpoint_class": decision.endpoint_class,
        "allowed": decision.allowed,
        "reasons": list(decision.reasons),
        "detail": detail,
        "preview_redacted": bool(preview and preview.get("redacted")),
        "recorded_at": now,
        "gate_version": PRIVACY_GATE_VERSION,
    }


def _endpoint_matches(accepted: str, provider: str) -> bool:
    return accepted == provider or accepted.rstrip("/") == provider.rstrip("/")


def _flatten(value: object, prefix: str = "") -> str:
    if isinstance(value, Mapping):
        return " ".join(_flatten(item, f"{prefix}.{key}") for key, item in value.items())
    if isinstance(value, list | tuple):
        return " ".join(_flatten(item, prefix) for item in value)
    return f"{prefix}={value}" if prefix else str(value)
