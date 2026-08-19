#!/usr/bin/env python3

from __future__ import annotations

import unittest

from worker import apprise_adapter
from worker.apprise_adapter import (
    APPRISE_VERSION,
    AppriseAdapterError,
    AppriseClient,
    AppriseLoader,
    AppriseProfile,
    backoff_delay,
    normalize_delivery_error,
    redact_secret,
    retry_allowed,
    send_notification,
    truncate_message,
    validate_profile,
)
from worker.apprise_adapter import (
    test_notification as send_test_notification,
)

NOW = "2026-08-19T10:00:00Z"
SECRET_URL = "mailtos://smtp://user:supersecretpass@smtp.local:25/"
SECRET_REF = "vault:" + "b" * 32


class FakeWebhookClient:
    """In-process self-hosted route fixture; records delivery without leaking."""

    def __init__(self, *, fail: bool = False, raise_timeout: bool = False) -> None:
        self.urls: list[str] = []
        self.bodies: list[str] = []
        self.fail = fail
        self.raise_timeout = raise_timeout

    def notify(self, url: str, body: str, title: str | None = None) -> bool:
        self.urls.append(url)
        self.bodies.append(body)
        if self.raise_timeout:
            raise TimeoutError("connection timed out")
        return not self.fail

    def test(self, url: str) -> bool:
        self.urls.append(url)
        if self.raise_timeout:
            raise TimeoutError("connection timed out")
        return not self.fail


class FakeLoader(AppriseLoader):
    def __init__(self, client: FakeWebhookClient) -> None:
        self._client = client

    def load(self) -> AppriseClient:
        return self._client


class ProfileTests(unittest.TestCase):
    def test_profile_requires_secret_backed_url(self) -> None:
        with self.assertRaisesRegex(AppriseAdapterError, "secret-backed"):
            validate_profile(AppriseProfile("dest_1", "https://public.example/x"))

    def test_profile_requires_pinned_apprise_version(self) -> None:
        with self.assertRaisesRegex(AppriseAdapterError, "pinned"):
            validate_profile(AppriseProfile("dest_1", SECRET_REF, apprise_version="0.0.6"))


class MessageTests(unittest.TestCase):
    def test_short_message_unchanged(self) -> None:
        self.assertEqual("hello", truncate_message("hello"))

    def test_long_message_truncated_with_marker(self) -> None:
        long_message = "x" * 5000
        truncated = truncate_message(long_message)
        self.assertLess(len(truncated), 1100)
        self.assertTrue(truncated.endswith("…[truncated]"))


class BackoffTests(unittest.TestCase):
    def test_bounded_exponential_backoff(self) -> None:
        delays = [backoff_delay(i) for i in range(1, 7)]
        self.assertEqual([5, 10, 20, 40, 80, 120], delays)

    def test_retry_capped(self) -> None:
        self.assertTrue(retry_allowed(1))
        self.assertTrue(retry_allowed(3))
        self.assertFalse(retry_allowed(4))

    def test_invalid_attempt_rejected(self) -> None:
        with self.assertRaisesRegex(AppriseAdapterError, "attempt"):
            backoff_delay(0)


class DeliveryTests(unittest.TestCase):
    def test_email_route_fixture_success(self) -> None:
        profile = AppriseProfile("dest_email", SECRET_REF, frozenset({"email"}))
        client = FakeWebhookClient()
        result = send_notification(
            profile, "scan completed", secret_value=SECRET_URL, now=NOW, loader=FakeLoader(client)
        )
        self.assertEqual("sent", result.state)
        self.assertIsNone(result.error)
        self.assertIn(SECRET_URL, client.urls)

    def test_webhook_route_fixture_success(self) -> None:
        profile = AppriseProfile("dest_webhook", SECRET_REF, frozenset({"webhook"}))
        client = FakeWebhookClient()
        result = send_test_notification(
            profile, secret_value=SECRET_URL, now=NOW, loader=FakeLoader(client)
        )
        self.assertEqual("sent", result.state)

    def test_delivery_failure_is_normalized(self) -> None:
        profile = AppriseProfile("dest_email", SECRET_REF)
        client = FakeWebhookClient(fail=True)
        result = send_notification(
            profile, "x", secret_value=SECRET_URL, now=NOW, loader=FakeLoader(client)
        )
        self.assertEqual("failed", result.state)
        self.assertEqual("delivery_failed", result.error)

    def test_timeout_is_normalized(self) -> None:
        profile = AppriseProfile("dest_email", SECRET_REF)
        client = FakeWebhookClient(raise_timeout=True)
        result = send_notification(
            profile, "x", secret_value=SECRET_URL, now=NOW, loader=FakeLoader(client)
        )
        self.assertEqual("failed", result.state)
        self.assertEqual("timeout", result.error)

    def test_bad_secret_ref_is_rejected(self) -> None:
        profile = AppriseProfile("dest_email", "not-a-ref")
        with self.assertRaisesRegex(AppriseAdapterError, "secret-backed"):
            send_notification(profile, "x", secret_value="", now=NOW)


class RedactionTests(unittest.TestCase):
    def test_service_url_never_leaks_from_results(self) -> None:
        profile = AppriseProfile("dest_email", SECRET_REF)
        client = FakeWebhookClient(fail=True)
        result = send_notification(
            profile, "x", secret_value=SECRET_URL, now=NOW, loader=FakeLoader(client)
        )
        self.assertNotIn(SECRET_URL, repr(result))
        self.assertNotIn("supersecretpass", repr(result))

    def test_redact_secret_shapes(self) -> None:
        redacted = redact_secret("error with api_key=abc123def456gh789 and sk-secret1234567890")
        self.assertNotIn("api_key=abc123def456gh789", redacted)
        self.assertNotIn("sk-secret1234567890", redacted)
        self.assertIn(apprise_adapter.REDACTED, redacted)

    def test_normalize_error_redacts_secret_value(self) -> None:
        attempt = normalize_delivery_error(TimeoutError("took too long"), secret_value=SECRET_URL)
        self.assertNotIn(SECRET_URL, repr(attempt))
        self.assertEqual("timeout", attempt.error)

    def test_profile_never_returns_service_url(self) -> None:
        profile = AppriseProfile("dest_email", SECRET_REF)
        self.assertEqual(SECRET_REF, profile.service_secret_ref)
        self.assertNotIn("smtp", repr(profile))

    def test_pinned_version_constant(self) -> None:
        self.assertEqual("1.12.0", APPRISE_VERSION)
        self.assertEqual(64, len(apprise_adapter.APPRISE_WHEEL_SHA256))


if __name__ == "__main__":
    unittest.main()
