#!/usr/bin/env python3

from __future__ import annotations

import unittest

from worker.privacy_gate import (
    EndpointClassification,
    GateDecision,
    PrivacyGateError,
    PrivacyPolicy,
    ProviderAcknowledgment,
    audit_record,
    classify_endpoint,
    evaluate_redirect,
    gate_decision,
    preview_outbound,
)


def policy(
    *,
    allowed_categories: frozenset[str] = frozenset({"photo", "document"}),
    max_payload_bytes: int = 1024,
    deny_categories: frozenset[str] = frozenset({"vault"}),
    preview_redact: bool = True,
) -> PrivacyPolicy:
    return PrivacyPolicy(
        allowed_categories=allowed_categories,
        max_payload_bytes=max_payload_bytes,
        deny_categories=deny_categories,
        preview_redact=preview_redact,
    )


def ack(
    *,
    provider: str = "sample_provider",
    endpoint_class: str = "remote",
    accepted_endpoint: str | None = None,
    state: str = "acknowledged",
    acknowledged_at: str = "2026-08-19T10:00:00Z",
) -> ProviderAcknowledgment:
    return ProviderAcknowledgment(
        provider=provider,
        accepted_endpoint=accepted_endpoint or provider,
        endpoint_class=endpoint_class,
        state=state,
        acknowledged_at=acknowledged_at,
    )


class ClassifyEndpointTests(unittest.TestCase):
    def test_loopback_is_local(self) -> None:
        for endpoint in ("http://127.0.0.1:9000", "http://localhost", "http://[::1]/"):
            classification = classify_endpoint(endpoint)
            self.assertEqual("local", classification.endpoint_class, endpoint)

    def test_private_ranges_are_lan(self) -> None:
        for ip in ("10.1.2.3", "172.16.9.9", "192.168.1.5", "fd00::1"):
            self.assertEqual("lan", classify_endpoint(f"https://{ip}").endpoint_class, ip)

    def test_public_ip_is_remote(self) -> None:
        classification = classify_endpoint("https://8.8.8.8/v1")
        self.assertEqual("remote", classification.endpoint_class)

    def test_cloud_metadata_is_remote(self) -> None:
        classification = classify_endpoint("http://169.254.169.254/latest/meta-data")
        self.assertEqual("remote", classification.endpoint_class)
        self.assertEqual("cloud_metadata_endpoint", classification.reason)

    def test_hostname_resolution_classifies(self) -> None:
        def resolver(host: str) -> str | None:
            return {"internal.lan": "10.0.0.4", "public.example.com": "1.2.3.4"}[host]

        self.assertEqual(
            "lan", classify_endpoint("https://internal.lan", resolver=resolver).endpoint_class
        )
        self.assertEqual(
            "remote",
            classify_endpoint("https://public.example.com", resolver=resolver).endpoint_class,
        )

    def test_unresolvable_hostname_is_remote_with_warning(self) -> None:
        classification = classify_endpoint("https://no-such-host.invalid")
        self.assertEqual("remote", classification.endpoint_class)
        self.assertIn("unresolvable_hostname", classification.warnings)

    def test_endpoint_without_host_is_rejected(self) -> None:
        with self.assertRaisesRegex(PrivacyGateError, "no host"):
            classify_endpoint("https://")


class GateDecisionTests(unittest.TestCase):
    def test_remote_calls_blocked_before_acknowledgment(self) -> None:
        decision = gate_decision(
            provider="p", endpoint_class="remote", acknowledgment=None, policy=policy()
        )
        self.assertFalse(decision.allowed)
        self.assertIn("remote_not_acknowledged", decision.reasons)

    def test_remote_call_allowed_after_acknowledgment(self) -> None:
        decision = gate_decision(
            provider="p", endpoint_class="remote", acknowledgment=ack(provider="p"), policy=policy()
        )
        self.assertTrue(decision.allowed)

    def test_revoked_acknowledgment_blocks(self) -> None:
        decision = gate_decision(
            provider="p",
            endpoint_class="remote",
            acknowledgment=ack(provider="p", state="revoked"),
            policy=policy(),
        )
        self.assertFalse(decision.allowed)
        self.assertIn("remote_not_acknowledged", decision.reasons)

    def test_endpoint_promoted_to_public_retriggers_acknowledgment(self) -> None:
        decision = gate_decision(
            provider="p",
            endpoint_class="remote",
            acknowledgment=ack(provider="p", endpoint_class="lan"),
            policy=policy(),
        )
        self.assertFalse(decision.allowed)
        self.assertIn("endpoint_class_promoted_requires_reacknowledgment", decision.reasons)

    def test_private_endpoint_does_not_need_acknowledgment(self) -> None:
        decision = gate_decision(
            provider="p", endpoint_class="lan", acknowledgment=None, policy=policy()
        )
        self.assertTrue(decision.allowed)

    def test_provider_policy_deny_blocks(self) -> None:
        decision = gate_decision(
            provider="p",
            endpoint_class="remote",
            acknowledgment=ack(provider="p"),
            policy=policy(),
            categories={"vault"},
        )
        self.assertFalse(decision.allowed)
        self.assertIn("category_denied", decision.reasons)

    def test_data_size_policy_blocks(self) -> None:
        decision = gate_decision(
            provider="p",
            endpoint_class="remote",
            acknowledgment=ack(provider="p"),
            policy=policy(max_payload_bytes=100),
            payload_bytes=1000,
        )
        self.assertFalse(decision.allowed)
        self.assertIn("payload_too_large", decision.reasons)

    def test_provider_acknowledgment_mismatch_blocks(self) -> None:
        decision = gate_decision(
            provider="p_other",
            endpoint_class="remote",
            acknowledgment=ack(provider="p_ack"),
            policy=policy(),
        )
        self.assertFalse(decision.allowed)
        self.assertIn("provider_acknowledgment_mismatch", decision.reasons)


class RedirectTests(unittest.TestCase):
    def test_redirect_to_private_network_is_blocked(self) -> None:
        original = EndpointClassification(
            "https://p.example", "p.example", None, "remote", "public"
        )
        final = EndpointClassification("http://10.0.0.8", "10.0.0.8", "10.0.0.8", "lan", "private")
        decision = evaluate_redirect(original, final)
        self.assertFalse(decision.allowed)
        self.assertIn("redirect_to_private", decision.reasons)

    def test_redirect_to_public_is_allowed(self) -> None:
        original = EndpointClassification(
            "https://p.example", "p.example", None, "remote", "public"
        )
        final = EndpointClassification("https://9.9.9.9", "9.9.9.9", "9.9.9.9", "remote", "public")
        decision = evaluate_redirect(original, final)
        self.assertTrue(decision.allowed)


class PreviewRedactionTests(unittest.TestCase):
    def test_preview_redacts_secrets(self) -> None:
        preview = preview_outbound(
            {"api_key": "sk-abcdefghijklmnop", "name": "alice"}, policy=policy()
        )
        self.assertTrue(preview["redacted"])
        self.assertNotIn("sk-abcdefghijklmnop", str(preview["preview"]))
        self.assertIn("[redacted]", str(preview["preview"]))

    def test_preview_without_redaction_keeps_content(self) -> None:
        preview = preview_outbound(
            {"api_key": "sk-abcdefghijklmnop"}, policy=policy(preview_redact=False)
        )
        self.assertFalse(preview["redacted"])
        self.assertIn("sk-abcdefghijklmnop", str(preview["payload"]))


class AuditTests(unittest.TestCase):
    def test_audit_record_redacts_payload(self) -> None:
        decision = GateDecision(
            allowed=False, endpoint_class="remote", reasons=("category_denied",)
        )
        preview = preview_outbound({"password": "super-secret-pass"}, policy=policy())
        record = audit_record(
            provider="p", decision=decision, now="2026-08-19T10:00:00Z", preview=preview
        )
        self.assertEqual("privacy.gate", record["event_type"])
        self.assertTrue(record["preview_redacted"])
        serialized = str(record)
        self.assertNotIn("super-secret-pass", serialized)
        self.assertNotIn("super-secret-pass", str(preview.get("preview")))
        self.assertNotIn("category_denied" * 0 + "vault", serialized)

    def test_audit_record_contains_no_payload_content(self) -> None:
        decision = GateDecision(allowed=True, endpoint_class="remote", reasons=())
        record = audit_record(provider="p", decision=decision, now="2026-08-19T10:00:00Z")
        serialized = str(record)
        self.assertNotIn("payload", serialized)
        self.assertIn("recorded_at", serialized)

    def test_revoke_is_reversible_flag(self) -> None:
        original = ack(provider="p")
        revoked = original.revoked()
        self.assertEqual("revoked", revoked.state)
        self.assertEqual(original.acknowledged_at, revoked.acknowledged_at)


if __name__ == "__main__":
    unittest.main()
