#!/usr/bin/env python3

from __future__ import annotations

import json
import unittest
from typing import Any

from worker.openai_compatible import (
    OpenAiCompatibleError,
    build_request,
    call_adapter,
    endpoint_uri,
    negotiate_capabilities,
    no_key_allowed,
    parse_completion,
    redact_message,
    retry_delay_seconds,
    should_retry,
    validate_endpoint,
    validate_redirect,
)
from worker.provider_contract import ProviderError


def ok(body: bytes, **kwargs: Any) -> dict[str, Any]:
    result = parse_completion(body, **kwargs)
    if isinstance(result, ProviderError):
        raise AssertionError(result.message)
    return result


def err(body: bytes, **kwargs: Any) -> ProviderError:
    result = parse_completion(body, **kwargs)
    assert isinstance(result, ProviderError)
    return result


LAN_URLS = (
    "http://localhost:8080",
    "http://127.0.0.1:11434",
    "http://10.0.0.5:8000",
    "http://192.168.1.10:8080/v1",
    "http://[::1]:8000",
    "http://ollama.local:11434",
)
PUBLIC_URLS = ("https://api.example.com/v1", "http://8.8.8.8:8080", "https://example.org")


def llama_mock(body: bytes, status: int = 200) -> Any:
    return {"status": status, "body": body, "headers": {}}


def vllm_body(content: str = "hello") -> bytes:
    return json.dumps({"choices": [{"message": {"content": content}}]}).encode()


def lmstudio_body(content: str = "hello") -> bytes:
    return json.dumps({"choices": [{"message": {"content": content}}]}).encode()


class EndpointPolicyTests(unittest.TestCase):
    def test_private_lan_endpoints_accepted(self) -> None:
        for url in LAN_URLS:
            policy = validate_endpoint(url)
            self.assertTrue(policy.private_or_loopback, url)

    def test_public_endpoints_rejected(self) -> None:
        for url in PUBLIC_URLS:
            with self.assertRaisesRegex(OpenAiCompatibleError, "loopback, private, or link-local"):
                validate_endpoint(url)

    def test_invalid_scheme_rejected(self) -> None:
        with self.assertRaisesRegex(OpenAiCompatibleError, "scheme must be http or https"):
            validate_endpoint("ftp://localhost:8080")

    def test_path_prefix_preserved(self) -> None:
        self.assertEqual(
            "http://localhost:8080/v1/chat/completions",
            endpoint_uri("http://localhost:8080/v1", "/chat/completions"),
        )


class NoKeyTests(unittest.TestCase):
    def test_lan_no_key_allowed(self) -> None:
        self.assertTrue(no_key_allowed("http://localhost:11434"))

    def test_public_key_required(self) -> None:
        self.assertFalse(no_key_allowed("https://api.example.com/v1"))


class RedirectTests(unittest.TestCase):
    def test_same_host_redirect_allowed(self) -> None:
        self.assertTrue(validate_redirect("http://localhost:8080/v1/chat", "http://localhost:8080"))

    def test_cross_host_redirect_blocked(self) -> None:
        self.assertFalse(
            validate_redirect("http://evil.example.com/v1/chat", "http://localhost:8080")
        )
        self.assertFalse(validate_redirect("http://localhost:9999", "http://localhost:8080"))


class RequestBuildTests(unittest.TestCase):
    def test_streaming_disabled_by_default(self) -> None:
        request = build_request(
            base_url="http://localhost:8080",
            model="mock",
            task="text",
            messages=[{"role": "user", "content": "hi"}],
        )
        self.assertFalse(request["json"]["stream"])

    def test_structured_output_json_schema(self) -> None:
        schema = {"name": "finding", "schema": {"type": "object"}}
        request = build_request(
            base_url="http://localhost:8080",
            model="mock",
            task="classification",
            json_schema=schema,
        )
        self.assertEqual("json_schema", request["json"]["response_format"]["type"])

    def test_no_key_on_lan(self) -> None:
        request = build_request(
            base_url="http://localhost:8080", model="mock", task="text", messages=[]
        )
        self.assertNotIn("Authorization", request["headers"])

    def test_secret_reference_resolves_to_bearer(self) -> None:
        request = build_request(
            base_url="http://localhost:8080",
            model="mock",
            task="text",
            api_key_ref="vault:abc123",
            secrets={"vault:abc123": "sk-local"},
        )
        self.assertEqual("Bearer sk-local", request["headers"]["Authorization"])

    def test_inline_key_rejected(self) -> None:
        with self.assertRaisesRegex(OpenAiCompatibleError, "opaque vault secrets"):
            build_request(
                base_url="http://localhost:8080",
                model="mock",
                task="text",
                api_key_ref="sk-raw-key-1234",
            )

    def test_missing_secret_rejected(self) -> None:
        with self.assertRaisesRegex(OpenAiCompatibleError, "is not available"):
            build_request(
                base_url="http://localhost:8080",
                model="mock",
                task="text",
                api_key_ref="vault:abc123",
                secrets={},
            )

    def test_embeddings_uses_input_field(self) -> None:
        request = build_request(
            base_url="http://localhost:8080", model="mock", task="embeddings", messages=["text"]
        )
        self.assertEqual("embeddings", request["url"].split("/")[-1])
        self.assertIn("input", request["json"])


class RetryTests(unittest.TestCase):
    def test_retryable_codes(self) -> None:
        self.assertTrue(should_retry("rate_limited", 429, 0))
        self.assertTrue(should_retry("unavailable", 503, 0))
        self.assertTrue(should_retry("timeout", None, 0))

    def test_budget_exhausted(self) -> None:
        self.assertFalse(should_retry("rate_limited", 429, 3))

    def test_non_retryable(self) -> None:
        self.assertFalse(should_retry("malformed_json", 200, 0))

    def test_backoff_bounded(self) -> None:
        self.assertEqual(0.5, retry_delay_seconds(0))
        self.assertEqual(1.0, retry_delay_seconds(1))
        self.assertEqual(4.0, retry_delay_seconds(10))


class ParseTests(unittest.TestCase):
    def test_llama_mock_response(self) -> None:
        parsed = ok(llama_mock(vllm_body("from llama")).pop("body"), model="mock", task="text")
        self.assertEqual("from llama", parsed["content"])

    def test_vllm_shape(self) -> None:
        parsed = ok(vllm_body("vllm answer"), model="mock", task="text")
        self.assertEqual("vllm answer", parsed["content"])

    def test_lm_studio_shape(self) -> None:
        parsed = ok(lmstudio_body("lm studio answer"), model="mock", task="text")
        self.assertEqual("lm studio answer", parsed["content"])

    def test_malformed_json(self) -> None:
        parsed = err(b"{not json", model="mock", task="text")
        self.assertEqual("malformed_json", parsed.code)

    def test_structured_output_validated(self) -> None:
        schema = {"name": "finding", "schema": {"type": "object"}}
        body = json.dumps({"choices": [{"message": {"content": '{"ok": true}'}}]}).encode()
        parsed = ok(body, model="mock", task="classification", json_schema=schema)
        self.assertEqual({"ok": True}, parsed["structured"])

    def test_structured_output_invalid(self) -> None:
        schema = {"name": "finding", "schema": {"type": "object"}}
        body = json.dumps({"choices": [{"message": {"content": "not json"}}]}).encode()
        parsed = err(body, model="mock", task="classification", json_schema=schema)
        self.assertEqual("invalid_structured_output", parsed.code)


class CallAdapterTests(unittest.TestCase):
    def test_transport_injected(self) -> None:
        request = build_request(
            base_url="http://localhost:8080", model="mock", task="text", messages=[]
        )
        response = call_adapter(request, lambda req: {"status": 200, "body": vllm_body()})
        self.assertEqual(200, response["status"])

    def test_ssrf_blocked_for_public_request(self) -> None:
        request = {"url": "http://8.8.8.8:8080/v1/chat/completions", "method": "POST"}
        with self.assertRaisesRegex(OpenAiCompatibleError, "violates endpoint policy"):
            call_adapter(request, lambda req: {"status": 200})


class CapabilityTests(unittest.TestCase):
    def test_negotiate_capabilities(self) -> None:
        caps = negotiate_capabilities(
            {
                "provider": "mock",
                "model": "mock-v1",
                "tasks": ["text", "vision"],
                "modalities": ["text", "image"],
                "max_input_bytes": 1000,
                "max_input_images": 4,
                "max_timeout_seconds": 60,
            }
        )
        self.assertTrue(caps.supports("vision"))
        self.assertFalse(caps.supports("embeddings"))


class RedactTests(unittest.TestCase):
    def test_secret_pattern_redacted(self) -> None:
        redacted = redact_message(
            "key=sk-abcdefghijklmnop123456 and vault:0123456789abcdef0123456789abcdef"
        )
        self.assertNotIn("sk-abcdefghijklmnop123456", redacted)
        self.assertNotIn("vault:0123456789abcdef0123456789abcdef", redacted)


if __name__ == "__main__":
    unittest.main()
