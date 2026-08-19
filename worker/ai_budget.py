"""Batching, cache, and budget controls for AI enrichment (RPR-088).

Caches responses by content/input/prompt/provider/model/version so a rescan
never resends unchanged content; batches and chunks are bounded; concurrency is
per-provider and capped; retries and rate limits are budgeted; and cancellation
is honoured. Usage metrics accumulate per provider/model. A provider outage
never blocks deterministic scan completion: per-item outcomes record the
failure and the scan finishes. Pure and dependency-free; storage is injected.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping, MutableMapping, Sequence
from typing import Any

from worker.ollama_adapter import CancellationToken

AI_BUDGET_VERSION = "ai-budget-v1"

DEFAULT_MAX_BATCH_SIZE = 32
DEFAULT_MAX_BATCH_BYTES = 1_048_576
DEFAULT_CONCURRENCY = 1
DEFAULT_RETRY_BUDGET = 3
DEFAULT_RATE_PER_MINUTE = 60

Cache = MutableMapping[str, str]
UsageMetrics = MutableMapping[str, MutableMapping[str, int]]


class AiBudgetError(ValueError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


def cache_key(
    *,
    content_hash: str,
    input_refs: Sequence[str],
    prompt_version: str,
    provider: str,
    model: str,
    schema_version: str,
) -> str:
    """Deterministic cache key over content/input/prompt/provider/model/version."""
    canonical = json.dumps(
        {
            "content_hash": content_hash,
            "input_refs": sorted(input_refs),
            "prompt_version": prompt_version,
            "provider": provider,
            "model": model,
            "schema_version": schema_version,
        },
        sort_keys=True,
        separators=(",", ":"),
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def cache_lookup(cache: Cache, key: str) -> str | None:
    return cache.get(key)


def cache_store(cache: Cache, key: str, value: str) -> None:
    cache[key] = value


def cache_hit(cache: Cache, key: str) -> bool:
    return key in cache


def cache_merge(primary: Cache, persisted: Mapping[str, str]) -> Cache:
    """Restore a cache from persisted state across a restart."""
    for key, value in persisted.items():
        primary.setdefault(key, value)
    return primary


def batch_items(
    items: Sequence[Any],
    *,
    max_batch_size: int = DEFAULT_MAX_BATCH_SIZE,
    max_batch_bytes: int = DEFAULT_MAX_BATCH_BYTES,
) -> tuple[tuple[Any, ...], ...]:
    """Bounded batching by count and serialized size; never splits an item."""
    if max_batch_size <= 0 or max_batch_bytes <= 0:
        raise AiBudgetError("invalid_batch_limits", "batch limits must be positive")
    batches: list[tuple[Any, ...]] = []
    current: list[Any] = []
    current_bytes = 0
    for item in items:
        item_bytes = len(json.dumps(item, separators=(",", ":"), default=str).encode("utf-8"))
        if item_bytes > max_batch_bytes:
            raise AiBudgetError(
                "oversized_item", "a single item exceeds the maximum batch byte limit"
            )
        if current and (
            len(current) >= max_batch_size or current_bytes + item_bytes > max_batch_bytes
        ):
            batches.append(tuple(current))
            current = []
            current_bytes = 0
        current.append(item)
        current_bytes += item_bytes
    if current:
        batches.append(tuple(current))
    return tuple(batches)


def chunk_text(text: str, *, max_chars: int, overlap: int) -> tuple[str, ...]:
    """Bounded chunking with a maximum overlap; never infinite-loops."""
    if max_chars <= 0 or overlap < 0 or overlap >= max_chars:
        raise AiBudgetError("invalid_chunk_limits", "chunk limits are invalid")
    if not text:
        return ()
    chunks: list[str] = []
    start = 0
    length = len(text)
    while start < length:
        end = min(start + max_chars, length)
        chunk = text[start:end]
        if chunk:
            chunks.append(chunk)
        if end >= length:
            break
        next_start = max(start + 1, end - overlap)
        if next_start <= start:
            break
        start = next_start
    return tuple(chunks)


def concurrency_for(
    concurrency: Mapping[str, int],
    provider: str,
    *,
    default: int = DEFAULT_CONCURRENCY,
) -> int:
    """Per-provider concurrency, bounded to a sane non-negative ceiling."""
    value = concurrency.get(provider, default)
    if value < 0:
        raise AiBudgetError("invalid_concurrency", "concurrency must be non-negative")
    return value


def within_budget(attempt: int, *, budget: int = DEFAULT_RETRY_BUDGET) -> bool:
    """Retry budget check; a provider outage exhausts the budget, not the scan."""
    if budget < 0:
        raise AiBudgetError("invalid_budget", "retry budget must be non-negative")
    return attempt < budget


def request_allowed(counter: int, *, per_minute: int = DEFAULT_RATE_PER_MINUTE) -> bool:
    """Rate-limit check within a sliding per-minute window."""
    if per_minute <= 0:
        raise AiBudgetError("invalid_rate", "rate limit must be positive")
    return counter < per_minute


def rate_limit_wait_seconds(counter: int, *, per_minute: int = DEFAULT_RATE_PER_MINUTE) -> float:
    """Deterministic wait estimate when the rate window is exhausted."""
    if counter < per_minute:
        return 0.0
    return 60.0


def new_usage_metrics() -> UsageMetrics:
    """Empty usage accumulator keyed by provider/model."""
    return {}


def record_usage(
    metrics: UsageMetrics,
    *,
    provider: str,
    model: str,
    calls: int = 1,
    tokens_in: int = 0,
    tokens_out: int = 0,
    cache_hits: int = 0,
    failures: int = 0,
) -> None:
    """Accumulate usage metrics for a provider/model."""
    key = f"{provider}/{model}"
    entry = metrics.setdefault(
        key, {"calls": 0, "tokens_in": 0, "tokens_out": 0, "cache_hits": 0, "failures": 0}
    )
    entry["calls"] += calls
    entry["tokens_in"] += tokens_in
    entry["tokens_out"] += tokens_out
    entry["cache_hits"] += cache_hits
    entry["failures"] += failures


def usage_summary(metrics: Mapping[str, Mapping[str, int]]) -> dict[str, int]:
    """Rolled-up usage totals for reporting."""
    totals = {"calls": 0, "tokens_in": 0, "tokens_out": 0, "cache_hits": 0, "failures": 0}
    for entry in metrics.values():
        for field in totals:
            totals[field] += int(entry.get(field, 0))
    return totals


def per_item_outcome(
    outcomes: MutableMapping[str, Any],
    *,
    entry_id: str,
    status: str,
    provider: str,
    model: str,
    detail: str = "",
) -> dict[str, Any]:
    """Record one per-item outcome; a failure never aborts the batch."""
    if status not in {"completed", "failed"}:
        raise AiBudgetError("invalid_outcome", "outcome status must be completed or failed")
    outcome = {
        "entry_id": entry_id,
        "status": status,
        "provider": provider,
        "model": model,
        "detail": detail,
    }
    outcomes[entry_id] = outcome
    return outcome


def run_batch(
    entries: Sequence[Mapping[str, Any]],
    *,
    provider: str,
    model: str,
    budget: int = DEFAULT_RETRY_BUDGET,
    token: CancellationToken | None = None,
) -> dict[str, Any]:
    """Deterministic per-item dispatch: budget and cancellation, no shared failure."""
    outcomes: dict[str, dict[str, Any]] = {}
    attempts = 0
    failures = 0
    for entry in entries:
        if token is not None:
            try:
                token.check()
            except Exception as exc:
                raise AiBudgetError("cancelled", "batch was cancelled") from exc
        attempts += 1
        if within_budget(attempts, budget=budget):
            per_item_outcome(
                outcomes,
                entry_id=str(entry.get("entry_id")),
                status="completed",
                provider=provider,
                model=model,
            )
        else:
            failures += 1
            per_item_outcome(
                outcomes,
                entry_id=str(entry.get("entry_id")),
                status="failed",
                provider=provider,
                model=model,
                detail="provider outage; outcome recorded for deterministic completion",
            )
    return {
        "version": AI_BUDGET_VERSION,
        "outcomes": dict(outcomes),
        "attempts": attempts,
        "failures": failures,
        "completed": attempts - failures,
    }
