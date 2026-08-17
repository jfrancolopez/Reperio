from __future__ import annotations

import unittest

from worker import provider_contract


def content_uri() -> str:
    return "scratch://sha256/" + "a" * 64


class ProviderContractTests(unittest.TestCase):
    def test_golden_capability_records_for_each_task_family(self) -> None:
        cases = (
            ("text", False),
            ("vision", True),
            ("embeddings", False),
            ("translation", False),
            ("classification", False),
            ("summarization", False),
        )
        for task, needs_vision in cases:
            with self.subTest(task=task):
                capabilities = provider_contract.provider_capabilities(
                    {
                        "provider": "ollama",
                        "model": "llama3.1",
                        "mode": "local",
                        "tasks": ["vision", task],
                        "modalities": ["text", "image"] if needs_vision else ["text"],
                        "max_input_bytes": 4096,
                        "max_input_images": 4 if needs_vision else 0,
                        "max_timeout_seconds": 120,
                        "streaming": False,
                    }
                )
            self.assertTrue(capabilities.supports(task))
            self.assertEqual("local", capabilities.mode)
            self.assertIn(task, provider_contract.TASK_LIMITS)

    def test_build_request_bounds_limits_and_rejects_paths(self) -> None:
        request = provider_contract.build_request(
            task="classification",
            provider="ollama",
            model="llama3.1",
            prompt_version="prompt-v1",
            mode="local",
            input_refs=(content_uri(),),
            evidence_refs=("finding:abc123",),
            input_bytes=1000,
        )
        self.assertEqual(provider_contract.SCHEMA_VERSION, request.schema_version)
        self.assertEqual("classification", request.task)
        self.assertEqual(4_000, request.limits.max_output_characters)

        with self.assertRaises(provider_contract.ProviderContractError) as captured:
            provider_contract.build_request(
                task="text",
                provider="ollama",
                model="llama3.1",
                prompt_version="prompt-v1",
                mode="local",
                input_refs=("/var/source/photo.jpg",),
                input_bytes=100,
            )
        self.assertEqual("request_path_rejected", captured.exception.code)

        with self.assertRaises(provider_contract.ProviderContractError) as captured:
            provider_contract.build_request(
                task="embeddings",
                provider="ollama",
                model="llama3.1",
                prompt_version="prompt-v1",
                mode="local",
                input_bytes=1_000_000,
            )
        self.assertEqual("request_size_limit", captured.exception.code)

        with self.assertRaises(provider_contract.ProviderContractError) as captured:
            provider_contract.build_request(
                task="vision",
                provider="ollama",
                model="llama3.1",
                prompt_version="prompt-v1",
                mode="local",
                input_images=5,
            )
        self.assertEqual("request_image_limit", captured.exception.code)

    def test_provider_cannot_request_tools_or_paths(self) -> None:
        request = classification_request()
        for record in (
            {"tool_calls": [{"name": "read_file"}], "content": "x"},
            {"message": {"tool_use": {"name": "shell"}}, "content": "x"},
        ):
            with self.subTest(record=record):
                with self.assertRaises(provider_contract.ProviderContractError) as captured:
                    provider_contract.normalize_result(record, expected=request)
                self.assertEqual("provider_requested_access", captured.exception.code)

    def test_normalize_result_golden_identity_evidence_and_limit_checks(self) -> None:
        request = classification_request()
        golden = provider_contract.normalize_result(
            {
                "schema_version": provider_contract.SCHEMA_VERSION,
                "task": "classification",
                "provider": "ollama",
                "model": "llama3.1",
                "prompt_version": "prompt-v1",
                "content": "personal",
                "evidence": ["finding:abc123", "evidence:xyz789"],
                "confidence": 0.9,
                "usage": {"input_tokens": 10, "output_tokens": 2},
            },
            expected=request,
        )
        self.assertEqual("personal", golden.content)
        self.assertEqual(("finding:abc123", "evidence:xyz789"), golden.evidence)
        self.assertEqual(0.9, golden.confidence)
        self.assertTrue(golden.redacted is False)

        mismatched = dict(golden.__dict__)
        mismatched["provider"] = "other"
        with self.assertRaises(provider_contract.ProviderContractError) as captured:
            provider_contract.normalize_result(mismatched, expected=request)
        self.assertEqual("identity_mismatch", captured.exception.code)

        no_evidence = dict(golden.__dict__)
        no_evidence["evidence"] = []
        with self.assertRaises(provider_contract.ProviderContractError) as captured:
            provider_contract.normalize_result(no_evidence, expected=request)
        self.assertEqual("missing_evidence", captured.exception.code)

        missing_schema = dict(golden.__dict__)
        missing_schema.pop("schema_version")
        with self.assertRaises(provider_contract.ProviderContractError) as captured:
            provider_contract.normalize_result(missing_schema, expected=request)
        self.assertEqual("malformed_output", captured.exception.code)

    def test_malformed_output_and_output_budget_are_rejected(self) -> None:
        request = classification_request()
        for record in (
            {"content": None},
            {"content": ""},
        ):
            with self.subTest(record=record):
                with self.assertRaises(provider_contract.ProviderContractError) as captured:
                    provider_contract.normalize_result(record, expected=request)
                self.assertEqual("malformed_output", captured.exception.code)

        huge = {
            "schema_version": provider_contract.SCHEMA_VERSION,
            "task": "classification",
            "provider": "ollama",
            "model": "llama3.1",
            "prompt_version": "prompt-v1",
            "content": "x" * 5000,
            "evidence": ["finding:abc123"],
        }
        with self.assertRaises(provider_contract.ProviderContractError) as captured:
            provider_contract.normalize_result(huge, expected=request)
        self.assertEqual("output_limit", captured.exception.code)

    def test_unsupported_task_and_modality_are_rejected(self) -> None:
        text_only = provider_contract.provider_capabilities(
            {
                "provider": "ollama",
                "model": "llama3.1",
                "mode": "local",
                "tasks": ["text"],
                "modalities": ["text"],
                "max_input_bytes": 4096,
                "max_input_images": 0,
                "max_timeout_seconds": 120,
                "streaming": False,
            }
        )
        with self.assertRaises(provider_contract.ProviderContractError) as captured:
            provider_contract.require_supported(text_only, "vision")
        self.assertEqual("unsupported_task", captured.exception.code)
        with self.assertRaises(provider_contract.ProviderContractError) as captured:
            provider_contract.require_modality(text_only, "image")
        self.assertEqual("unsupported_modality", captured.exception.code)

    def test_timeout_error_is_retryable_and_passive(self) -> None:
        error = provider_contract.timeout_error(
            task="translation", provider="ollama", model="llama3.1"
        )
        self.assertEqual("timeout", error.code)
        self.assertTrue(error.retryable)
        self.assertFalse(error.redacted)
        self.assertEqual(provider_contract.SCHEMA_VERSION, error.schema_version)

    def test_secret_redaction_in_results_and_errors(self) -> None:
        leaker = {
            "schema_version": provider_contract.SCHEMA_VERSION,
            "task": "classification",
            "provider": "ollama",
            "model": "llama3.1",
            "prompt_version": "prompt-v1",
            "content": "api_key: sk-ABCDEFGHIJKLMNOP, vault: vault:0123456789abcdef0123456789abcdef",
            "evidence": ["finding:abc123"],
        }
        result = provider_contract.normalize_result(leaker, expected=classification_request())
        self.assertTrue(result.redacted)
        self.assertNotIn("sk-ABCDEFGHIJKLMNOP", result.content)
        self.assertNotIn("vault:0123456789abcdef0123456789abcdef", result.content)
        self.assertIn("secret_redacted", result.warnings)

        error = provider_contract.normalize_error(
            {
                "schema_version": provider_contract.SCHEMA_VERSION,
                "code": "provider_error",
                "message": "auth failed bearer 0123456789abcdef0123456789abcdef0123456789",
                "retryable": False,
            },
            task="text",
            provider="ollama",
            model="llama3.1",
        )
        self.assertTrue(error.redacted)
        self.assertNotIn("0123456789abcdef0123456789abcdef0123456789", error.message)


def classification_request() -> provider_contract.ProviderRequest:
    return provider_contract.build_request(
        task="classification",
        provider="ollama",
        model="llama3.1",
        prompt_version="prompt-v1",
        mode="local",
        input_refs=(content_uri(),),
        evidence_refs=("finding:abc123",),
        input_bytes=1000,
    )


if __name__ == "__main__":
    unittest.main()
