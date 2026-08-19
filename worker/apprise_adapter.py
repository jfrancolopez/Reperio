"""Pinned Apprise notification adapter boundary (RPR-112).

Wraps the Apprise library as a sidecar adapter: service URLs are secret-backed
(opaque ``vault:`` references), never stored and never returned after creation.
Message bodies are bounded and truncated, delivery uses a bounded
exponential-backoff schedule with normalized error codes, and every returned
record is redacted so notification secrets never leak into logs or events.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

from worker.provider_contract import REDACTED, SECRET_PATTERNS

APPRISE_ADAPTER_VERSION = "apprise-adapter-v1"
APPRISE_VERSION = "1.12.0"
APPRISE_SOURCE = "https://pypi.org/project/apprise/1.12.0/"
APPRISE_WHEEL_SHA256 = "28edabfec5a9d5dbcd9aa28bdfd8928ecb68764e40214b6e648eab6d974b5a93"

MAX_MESSAGE_BYTES = 4096
MAX_MESSAGE_CHARACTERS = 1024
MAX_ATTEMPTS = 4
BACKOFF_BASE_SECONDS = 5.0
BACKOFF_MULTIPLIER = 2.0
BACKOFF_MAX_SECONDS = 120.0
TRUNCATION_MARKER = "…[truncated]"

DELIVERY_STATES = frozenset({"pending", "sent", "failed", "skipped"})
RETRYABLE_CODES = frozenset({"timeout", "delivery_failed", "rate_limited"})


class AppriseAdapterError(ValueError):
    """Raised when a notification cannot be delivered safely."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


@dataclass(frozen=True)
class AppriseProfile:
    destination_id: str
    service_secret_ref: str
    tags: frozenset[str] = frozenset()
    apprise_version: str = APPRISE_VERSION

    def validate(self) -> None:
        if not self.destination_id or not self.service_secret_ref.startswith("vault:"):
            raise AppriseAdapterError(
                "invalid_profile", "service URL must be a secret-backed vault reference"
            )


@dataclass(frozen=True)
class DeliveryAttempt:
    destination_id: str
    attempt: int
    state: str
    error: str | None = None
    redacted_detail: str | None = None
    scheduled_at: str | None = None


class AppriseClient(Protocol):
    def notify(self, url: str, body: str, title: str | None = None) -> bool: ...

    def test(self, url: str) -> bool: ...


class AppriseLoader(Protocol):
    def load(self) -> AppriseClient: ...


class InstalledAppriseLoader:
    """Production loader for the pinned Apprise sidecar."""

    def load(self) -> AppriseClient:
        try:
            import apprise  # type: ignore[import-not-found]
        except ImportError as error:
            raise AppriseAdapterError(
                "apprise_unavailable", "pinned Apprise sidecar is not installed"
            ) from error
        return _AppriseClientWrapper(apprise)


class _AppriseClientWrapper:
    def __init__(self, apprise_module: object) -> None:
        self._apprise = apprise_module

    def notify(self, url: str, body: str, title: str | None = None) -> bool:
        from apprise import Apprise

        client = Apprise()
        if not client.add(url):
            return False
        return bool(client.notify(body=body, title=title or ""))

    def test(self, url: str) -> bool:
        from apprise import Apprise

        client = Apprise()
        if not client.add(url):
            return False
        return bool(client.test())


def validate_profile(profile: AppriseProfile) -> None:
    profile.validate()
    if profile.apprise_version != APPRISE_VERSION:
        raise AppriseAdapterError(
            "unpinned_apprise", "Apprise version must match the pinned release"
        )


def truncate_message(text: str) -> str:
    """Bound a notification body to a safe size with a visible marker."""
    if len(text) <= MAX_MESSAGE_CHARACTERS:
        return text
    return text[: MAX_MESSAGE_CHARACTERS - len(TRUNCATION_MARKER)] + TRUNCATION_MARKER


def backoff_delay(attempt: int) -> int:
    """Bounded deterministic exponential backoff in whole seconds."""
    if attempt < 1:
        raise AppriseAdapterError("invalid_attempt", "attempt must be positive")
    delay = BACKOFF_BASE_SECONDS * (BACKOFF_MULTIPLIER ** (attempt - 1))
    return int(min(delay, BACKOFF_MAX_SECONDS))


def retry_allowed(attempt: int) -> bool:
    return attempt < MAX_ATTEMPTS


def redact_secret(value: str) -> str:
    """Replace any secret-shaped fragments so they never reach logs or events."""
    redacted = value
    for pattern in SECRET_PATTERNS:
        redacted = pattern.sub(REDACTED, redacted)
    return redacted


def normalize_delivery_error(
    error: AppriseAdapterError | OSError | TimeoutError,
    *,
    secret_value: str | None,
) -> DeliveryAttempt:
    """Map an exception to a redacted delivery record without the secret."""
    code = getattr(error, "code", None)
    if isinstance(code, str) and code != "apprise_unavailable":
        normalized = code
    elif isinstance(error, TimeoutError):
        normalized = "timeout"
    else:
        normalized = "delivery_failed"
    detail = redact_secret(str(error))
    if secret_value:
        detail = detail.replace(secret_value, REDACTED)
    return DeliveryAttempt(
        destination_id="",
        attempt=0,
        state="failed",
        error=normalized,
        redacted_detail=detail,
    )


def send_notification(
    profile: AppriseProfile,
    message: str,
    *,
    secret_value: str,
    now: str,
    loader: AppriseLoader | None = None,
) -> DeliveryAttempt:
    """Deliver a truncated notification and never expose the service URL."""
    validate_profile(profile)
    body = truncate_message(message)
    selected = loader or InstalledAppriseLoader()
    try:
        client = selected.load()
        sent = client.notify(secret_value, body)
    except AppriseAdapterError as error:
        return _failed(profile, error.code, error, secret_value, now)
    except (OSError, TimeoutError) as error:
        return _failed(
            profile,
            "delivery_failed" if not isinstance(error, TimeoutError) else "timeout",
            error,
            secret_value,
            now,
        )
    if not sent:
        return DeliveryAttempt(
            destination_id=profile.destination_id,
            attempt=1,
            state="failed",
            error="delivery_failed",
            scheduled_at=_retry_schedule(1, now),
        )
    return DeliveryAttempt(
        destination_id=profile.destination_id,
        attempt=1,
        state="sent",
        scheduled_at=now,
    )


def test_notification(
    profile: AppriseProfile,
    *,
    secret_value: str,
    now: str,
    loader: AppriseLoader | None = None,
) -> DeliveryAttempt:
    """Send a bounded test notification to a secret-backed service URL."""
    validate_profile(profile)
    selected = loader or InstalledAppriseLoader()
    try:
        client = selected.load()
        ok = client.test(secret_value)
    except AppriseAdapterError as error:
        return _failed(profile, error.code, error, secret_value, now)
    except (OSError, TimeoutError) as error:
        return _failed(profile, "delivery_failed", error, secret_value, now)
    return DeliveryAttempt(
        destination_id=profile.destination_id,
        attempt=1,
        state="sent" if ok else "failed",
        error=None if ok else "test_failed",
        scheduled_at=now,
    )


def _failed(
    profile: AppriseProfile,
    code: str,
    error: BaseException,
    secret_value: str,
    now: str,
) -> DeliveryAttempt:
    detail = redact_secret(str(error))
    if secret_value:
        detail = detail.replace(secret_value, REDACTED)
    return DeliveryAttempt(
        destination_id=profile.destination_id,
        attempt=1,
        state="failed",
        error=code,
        redacted_detail=detail,
        scheduled_at=now,
    )


def _retry_schedule(attempt: int, now: str) -> str | None:
    import datetime

    delay = backoff_delay(attempt)
    timestamp = datetime.datetime.fromisoformat(now.replace("Z", "+00:00"))
    return (timestamp + datetime.timedelta(seconds=delay)).isoformat().replace("+00:00", "Z")
