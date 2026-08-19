#!/usr/bin/env python3

from __future__ import annotations

import unittest
from typing import Any

from worker.ai_budget import (
    AI_BUDGET_VERSION,
    AiBudgetError,
    batch_items,
    cache_hit,
    cache_key,
    cache_lookup,
    cache_merge,
    cache_store,
    chunk_text,
    concurrency_for,
    new_usage_metrics,
    per_item_outcome,
    rate_limit_wait_seconds,
    record_usage,
    request_allowed,
    run_batch,
    usage_summary,
    within_budget,
)
from worker.ollama_adapter import CancellationToken


class CacheKeyTests(unittest.TestCase):
    def test_key_includes_all_dimensions(self) -> None:
        first = cache_key(
            content_hash="a" * 64,
            input_refs=["r1"],
            prompt_version="p1",
            provider="ollama",
            model="m1",
            schema_version="s1",
        )
        changed = cache_key(
            content_hash="b" * 64,
            input_refs=["r1"],
            prompt_version="p1",
            provider="ollama",
            model="m1",
            schema_version="s1",
        )
        self.assertNotEqual(first, changed)
        self.assertEqual(64, len(first))

    def test_version_change_is_a_miss(self) -> None:
        old = cache_key(
            content_hash="a" * 64,
            input_refs=[],
            prompt_version="p1",
            provider="ollama",
            model="m1",
            schema_version="s1",
        )
        new = cache_key(
            content_hash="a" * 64,
            input_refs=[],
            prompt_version="p2",
            provider="ollama",
            model="m1",
            schema_version="s1",
        )
        self.assertNotEqual(old, new)

    def test_unchanged_content_identical_key(self) -> None:
        first = cache_key(
            content_hash="a" * 64,
            input_refs=["r1", "r2"],
            prompt_version="p1",
            provider="ollama",
            model="m1",
            schema_version="s1",
        )
        second = cache_key(
            content_hash="a" * 64,
            input_refs=["r1", "r2"],
            prompt_version="p1",
            provider="ollama",
            model="m1",
            schema_version="s1",
        )
        self.assertEqual(first, second)


class CacheStoreTests(unittest.TestCase):
    def test_hit_and_miss(self) -> None:
        cache: dict[str, str] = {}
        key = cache_key(
            content_hash="a" * 64,
            input_refs=[],
            prompt_version="p1",
            provider="ollama",
            model="m1",
            schema_version="s1",
        )
        self.assertFalse(cache_hit(cache, key))
        cache_store(cache, key, "result")
        self.assertTrue(cache_hit(cache, key))
        self.assertEqual("result", cache_lookup(cache, key))

    def test_restart_restores_cache(self) -> None:
        persisted = {"deadbeef": "result"}
        cache = cache_merge({}, persisted)
        self.assertEqual("result", cache_lookup(cache, "deadbeef"))


class BatchTests(unittest.TestCase):
    def test_bounded_by_size_and_bytes(self) -> None:
        items = list(range(10))
        batches = batch_items(items, max_batch_size=4, max_batch_bytes=1_000_000)
        self.assertEqual([4, 4, 2], [len(batch) for batch in batches])

    def test_oversized_item_rejected(self) -> None:
        with self.assertRaisesRegex(AiBudgetError, "exceeds the maximum batch byte limit"):
            batch_items(["x" * 100], max_batch_size=10, max_batch_bytes=10)

    def test_invalid_limits(self) -> None:
        with self.assertRaisesRegex(AiBudgetError, "must be positive"):
            batch_items([], max_batch_size=0)

    def test_empty_items(self) -> None:
        self.assertEqual((), batch_items([]))

    def test_chunking_bounded(self) -> None:
        chunks = chunk_text("abcdefghij", max_chars=4, overlap=1)
        self.assertTrue(all(len(chunk) <= 4 for chunk in chunks))
        self.assertGreater(len(chunks), 1)
        self.assertEqual("a", chunks[0][0])
        self.assertEqual("j", chunks[-1][-1])

    def test_chunk_invalid_overlap(self) -> None:
        with self.assertRaisesRegex(AiBudgetError, "chunk limits"):
            chunk_text("abc", max_chars=2, overlap=2)


class BudgetTests(unittest.TestCase):
    def test_retry_budget(self) -> None:
        self.assertTrue(within_budget(0))
        self.assertTrue(within_budget(2))
        self.assertFalse(within_budget(3))

    def test_rate_limit(self) -> None:
        self.assertTrue(request_allowed(59, per_minute=60))
        self.assertFalse(request_allowed(60, per_minute=60))
        self.assertEqual(60.0, rate_limit_wait_seconds(60, per_minute=60))
        self.assertEqual(0.0, rate_limit_wait_seconds(0, per_minute=60))

    def test_concurrency_per_provider(self) -> None:
        self.assertEqual(2, concurrency_for({"ollama": 2}, "ollama"))
        self.assertEqual(1, concurrency_for({}, "ollama"))


class MetricsTests(unittest.TestCase):
    def test_usage_totals(self) -> None:
        metrics = new_usage_metrics()
        record_usage(metrics, provider="ollama", model="m1", calls=1, tokens_in=10, tokens_out=5)
        record_usage(metrics, provider="ollama", model="m1", calls=1, tokens_in=10)
        summary = usage_summary(metrics)
        self.assertEqual(2, summary["calls"])
        self.assertEqual(20, summary["tokens_in"])
        self.assertEqual(5, summary["tokens_out"])


class OutcomeTests(unittest.TestCase):
    def test_per_item_outcome_completed(self) -> None:
        outcomes: dict[str, dict[str, Any]] = {}
        per_item_outcome(outcomes, entry_id="e1", status="completed", provider="ollama", model="m1")
        self.assertEqual("completed", outcomes["e1"]["status"])

    def test_invalid_outcome_rejected(self) -> None:
        with self.assertRaisesRegex(AiBudgetError, "completed or failed"):
            per_item_outcome({}, entry_id="e1", status="pending", provider="p", model="m")


class RunBatchTests(unittest.TestCase):
    def test_all_completed_within_budget(self) -> None:
        result = run_batch([{"entry_id": "e1"}, {"entry_id": "e2"}], provider="ollama", model="m1")
        self.assertEqual(2, result["completed"])
        self.assertEqual(0, result["failures"])

    def test_partial_batch_failure_never_aborts(self) -> None:
        result = run_batch(
            [{"entry_id": "e1"}, {"entry_id": "e2"}, {"entry_id": "e3"}],
            provider="ollama",
            model="m1",
            budget=2,
        )
        self.assertEqual(1, result["completed"])
        self.assertEqual(2, result["failures"])
        self.assertEqual("failed", result["outcomes"]["e2"]["status"])
        self.assertEqual("completed", result["outcomes"]["e1"]["status"])

    def test_cancellation_honoured(self) -> None:
        token = CancellationToken()
        token.cancel()
        with self.assertRaisesRegex(AiBudgetError, "cancelled"):
            run_batch([{"entry_id": "e1"}], provider="ollama", model="m1", token=token)

    def test_version_constant(self) -> None:
        self.assertEqual("ai-budget-v1", AI_BUDGET_VERSION)


if __name__ == "__main__":
    unittest.main()
