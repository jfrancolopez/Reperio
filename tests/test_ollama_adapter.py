#!/usr/bin/env python3

from __future__ import annotations

import json
import unittest
from typing import Any

from worker.ollama_adapter import (
    CancellationToken,
    OllamaAdapterError,
    build_embed_request,
    build_generate_request,
    call_with_cancel,
    missing_model_guidance,
    model_available,
    negotiate_capabilities,
    parse_embed,
    parse_generate,
    parse_tags,
    pull_allowed,
    redact_message,
    select_model,
)


def tags_body(*models: dict[str, Any]) -> bytes:
    return json.dumps({"models": list(models)}).encode()


def generate_body(response: str = "answer", done: bool = True) -> bytes:
    return json.dumps({"response": response, "done": done}).encode()


def embed_body(*vectors: list[float]) -> bytes:
    return json.dumps({"embeddings": list(vectors)}).encode()


class ParseTagsTests(unittest.TestCase):
    def test_models_ordered_and_capabilities(self) -> None:
        body = tags_body(
            {
                "name": "llama3.2",
                "size": 5_000_000,
                "details": {"capabilities": ["vision", "tools"]},
            },
            {"name": "tiny", "size": 500_000},
        )
        models = parse_tags(body)
        self.assertEqual(["llama3.2", "tiny"], [model.name for model in models])
        self.assertTrue(models[0].supports_vision)
        self.assertFalse(models[1].supports_vision)

    def test_malformed_tags(self) -> None:
        with self.assertRaisesRegex(OllamaAdapterError, "not valid JSON"):
            parse_tags(b"{broken")

    def test_empty_tags(self) -> None:
        self.assertEqual((), parse_tags(tags_body()))


class ModelSelectionTests(unittest.TestCase):
    def test_exact_preferred_model(self) -> None:
        models = parse_tags(tags_body({"name": "tiny", "size": 1}, {"name": "big", "size": 100}))
        selected = select_model(models, preferred="big")
        if selected is None:
            self.fail("no model selected")
        self.assertEqual("big", selected.name)

    def test_smallest_fallback(self) -> None:
        models = parse_tags(tags_body({"name": "big", "size": 100}, {"name": "tiny", "size": 1}))
        selected = select_model(models)
        if selected is None:
            self.fail("no model selected")
        self.assertEqual("tiny", selected.name)

    def test_no_models(self) -> None:
        self.assertIsNone(select_model(parse_tags(tags_body())))

    def test_model_available(self) -> None:
        models = parse_tags(tags_body({"name": "llama3.2", "size": 1}))
        self.assertTrue(model_available(models, "llama3.2"))
        self.assertFalse(model_available(models, "missing"))


class PullPolicyTests(unittest.TestCase):
    def test_no_auto_pull_without_admin_action(self) -> None:
        allowed, warning = pull_allowed(size_bytes=10_000_000_000, explicit_admin_action=False)
        self.assertFalse(allowed)
        if warning is not None:
            self.assertIn("explicit admin action", warning)

    def test_admin_action_allows_large_pull(self) -> None:
        allowed, warning = pull_allowed(size_bytes=10_000_000_000, explicit_admin_action=True)
        self.assertTrue(allowed)
        if warning is not None:
            self.assertIn("admin action", warning)

    def test_missing_model_guidance(self) -> None:
        guidance = missing_model_guidance("llama3.2")
        self.assertIn("ollama pull llama3.2", guidance)
        self.assertNotIn("auto", guidance.split(" explicitly ")[0])


class GenerateRequestTests(unittest.TestCase):
    def test_json_format_requested(self) -> None:
        request = build_generate_request(
            "http://localhost:11434", model="llama3.2", prompt="classify", format_json=True
        )
        self.assertEqual("json", request["json"]["format"])
        self.assertFalse(request["json"]["stream"])
        self.assertIn("/api/generate", request["url"])

    def test_images_base64_encoded(self) -> None:
        request = build_generate_request(
            "http://localhost:11434", model="vision", prompt="describe", images=["jpg-bytes"]
        )
        self.assertEqual(["anBnLWJ5dGVz"], request["json"]["images"])

    def test_invalid_model_rejected(self) -> None:
        with self.assertRaisesRegex(OllamaAdapterError, "not safe"):
            build_generate_request("http://localhost:11434", model="bad model", prompt="x")

    def test_endpoint_policy_enforced(self) -> None:
        with self.assertRaisesRegex(OllamaAdapterError, "violates policy"):
            build_generate_request("https://ollama.example.com", model="llama3.2", prompt="x")


class ParseGenerateTests(unittest.TestCase):
    def test_plain_response(self) -> None:
        parsed = parse_generate(generate_body("hello"))
        self.assertEqual("hello", parsed["response"])
        self.assertTrue(parsed["done"])

    def test_invalid_json_output(self) -> None:
        with self.assertRaisesRegex(OllamaAdapterError, "not valid JSON"):
            parse_generate(generate_body("not json"), expect_json=True)

    def test_valid_json_output(self) -> None:
        parsed = parse_generate(generate_body('{"ok": true}'), expect_json=True)
        self.assertEqual({"ok": True}, parsed["structured"])

    def test_malformed_response(self) -> None:
        with self.assertRaisesRegex(OllamaAdapterError, "not valid JSON"):
            parse_generate(b"<html>oops</html>")


class ParseEmbedTests(unittest.TestCase):
    def test_embeddings(self) -> None:
        vectors = parse_embed(embed_body([0.1, 0.2], [0.3, 0.4]))
        self.assertEqual(2, len(vectors))
        self.assertEqual([0.1, 0.2], vectors[0])

    def test_empty_embeddings(self) -> None:
        with self.assertRaisesRegex(OllamaAdapterError, "no embeddings"):
            parse_embed(embed_body())

    def test_embed_request_built(self) -> None:
        request = build_embed_request("http://localhost:11434", model="llama3.2", inputs=["a", "b"])
        self.assertIn("/api/embed", request["url"])
        self.assertEqual(["a", "b"], request["json"]["input"])


class CapabilityTests(unittest.TestCase):
    def test_vision_model_declares_vision(self) -> None:
        caps = negotiate_capabilities({"model": "llava", "capabilities": ["vision"]})
        self.assertTrue(caps.supports("vision"))
        self.assertTrue(caps.supports("embeddings"))

    def test_text_only_model(self) -> None:
        caps = negotiate_capabilities({"model": "llama3.2", "capabilities": []})
        self.assertFalse(caps.supports("vision"))
        self.assertTrue(caps.supports("text"))


class CancellationTests(unittest.TestCase):
    def test_pre_call_cancellation(self) -> None:
        request = build_generate_request("http://localhost:11434", model="llama3.2", prompt="x")
        token = CancellationToken()
        token.cancel()
        with self.assertRaisesRegex(OllamaAdapterError, "cancelled"):
            call_with_cancel(request, lambda req: {"status": 200}, token)

    def test_post_call_cancellation(self) -> None:
        request = build_generate_request("http://localhost:11434", model="llama3.2", prompt="x")
        token = CancellationToken()

        def cancel_during(req: Any) -> dict[str, Any]:
            token.cancel()
            return {"status": 200, "body": generate_body()}

        with self.assertRaisesRegex(OllamaAdapterError, "cancelled"):
            call_with_cancel(request, cancel_during, token)

    def test_endpoint_unavailable(self) -> None:
        request = build_generate_request("http://localhost:11434", model="llama3.2", prompt="x")

        def broken(req: Any) -> dict[str, Any]:
            raise ConnectionError("refused")

        with self.assertRaisesRegex(OllamaAdapterError, "unavailable"):
            call_with_cancel(request, broken, CancellationToken())


class RedactTests(unittest.TestCase):
    def test_secret_pattern_redacted(self) -> None:
        redacted = redact_message("password=supersecretvalue1234")
        self.assertNotIn("supersecretvalue1234", redacted)


if __name__ == "__main__":
    unittest.main()
