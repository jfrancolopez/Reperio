"""Export queue that runs while scanning continues (RPR-108).

The queue accepts only content whose extraction is currently ready (a verified
scratch object with known size and hash). Items still being extracted are held
as ``waiting`` and retried with a capped budget; items that become ready later
transition to exported once copied and verified. Completion reports the exact
ready/exported/waiting/failed counts, and dismissing a finding mid-export never
touches an already-completed copy. Queue steps consume a readiness snapshot
instead of holding any catalog lock, so scanner ingest is never blocked.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any

EXPORT_QUEUE_VERSION = "export-queue-v1"

MAX_WAIT_RETRIES = 5
RETRY_BASE_DELAY_SECONDS = 2.0
RETRY_MAX_DELAY_SECONDS = 60.0

QUEUE_STATES = frozenset({"ready", "waiting", "exported", "failed", "skipped"})


class ExportQueueError(ValueError):
    """Raised when an export-queue input is invalid."""


@dataclass(frozen=True)
class QueueItem:
    export_item_id: str
    state: str
    attempts: int = 0
    error: str | None = None
    destination_path: str | None = None
    verified: bool = False


@dataclass(frozen=True)
class QueueStep:
    item_id: str
    before: str
    after: str
    attempts: int
    delay_seconds: float | None = None
    error: str | None = None


@dataclass(frozen=True)
class CompletionReport:
    ready: int
    exported: int
    waiting: int
    failed: int
    skipped: int

    @property
    def total(self) -> int:
        return self.ready + self.exported + self.waiting + self.failed + self.skipped


def retry_delay_seconds(attempt: int) -> float:
    """Bounded exponential retry delay; ``attempt`` is 1-based."""
    if attempt < 1:
        raise ExportQueueError("invalid_attempt", "attempt must be positive")
    return float(min(RETRY_BASE_DELAY_SECONDS * (2 ** (attempt - 1)), RETRY_MAX_DELAY_SECONDS))


def classify_readiness(
    item_id: str,
    *,
    content_ready: bool,
    dismissed: bool = False,
) -> str:
    """Map an item's current content state to a queue status."""
    if dismissed:
        return "skipped"
    if content_ready:
        return "ready"
    return "waiting"


def step_queue(
    items: Sequence[QueueItem],
    *,
    readiness_of: Mapping[str, bool],
    exporter_results: Mapping[str, bool],
    dismissed: Mapping[str, bool] | None = None,
) -> tuple[tuple[QueueItem, ...], tuple[QueueStep, ...]]:
    """Advance the queue from a readiness snapshot without holding a lock.

    Rules:
    - ``waiting`` with content ready becomes ``ready``; with content still
      unavailable it stays waiting and increments attempts until the budget is
      exhausted, then fails.
    - ``ready`` that copies+verifies becomes ``exported``; a failed copy stays
      ``ready`` (never marked complete) unless the retry budget is exhausted.
    - ``ready``/``waiting`` items dismissed mid-export become ``skipped``.
    - ``exported`` and ``failed``/``skipped`` terminal states are unchanged.
    """
    dismissed = dismissed or {}
    next_items: list[QueueItem] = []
    steps: list[QueueStep] = []
    for item in items:
        before = item.state
        after = before
        attempts = item.attempts
        error = item.error
        delay: float | None = None
        if before in {"exported", "failed", "skipped"}:
            next_items.append(item)
            continue
        if dismissed.get(item.export_item_id, False):
            after = "skipped"
            error = None
            next_items.append(
                QueueItem(item.export_item_id, after, item.attempts, error, None, False)
            )
            steps.append(QueueStep(item.export_item_id, before, after, item.attempts))
            continue
        if before == "waiting":
            attempts += 1
            if readiness_of.get(item.export_item_id, False):
                after = "ready"
                error = None
            elif attempts > MAX_WAIT_RETRIES:
                after = "failed"
                error = "extraction_timeout"
            else:
                after = "waiting"
                delay = retry_delay_seconds(attempts)
        elif before == "ready":
            if exporter_results.get(item.export_item_id, False):
                after = "exported"
                error = None
            elif item.attempts >= MAX_WAIT_RETRIES:
                after = "failed"
                error = "export_failed"
            else:
                attempts += 1
                delay = retry_delay_seconds(attempts)
        if after != before or delay is not None or error != item.error:
            next_items.append(
                QueueItem(
                    item.export_item_id,
                    after,
                    attempts,
                    error,
                    item.destination_path if after == "exported" else None,
                    verified=(after == "exported"),
                )
            )
            steps.append(QueueStep(item.export_item_id, before, after, attempts, delay, error))
        else:
            next_items.append(item)
    return tuple(next_items), tuple(steps)


def build_completion_report(items: Sequence[QueueItem]) -> CompletionReport:
    """Accurate ready/exported/waiting/failed/skipped counts."""
    counts = {state: 0 for state in QUEUE_STATES}
    for item in items:
        if item.state not in counts:
            raise ExportQueueError("unknown_state", f"unrecognized queue state {item.state!r}")
        counts[item.state] += 1
    return CompletionReport(
        ready=counts["ready"],
        exported=counts["exported"],
        waiting=counts["waiting"],
        failed=counts["failed"],
        skipped=counts["skipped"],
    )


def queue_snapshot(
    items: Sequence[QueueItem],
    *,
    export_id: str,
    case_id: str,
    dynamic_saved_search: bool = False,
) -> dict[str, Any]:
    """Deterministic queue snapshot with explicit dynamic-export flag."""
    report = build_completion_report(items)
    return {
        "export_queue_version": EXPORT_QUEUE_VERSION,
        "export_id": export_id,
        "case_id": case_id,
        "dynamic_saved_search": dynamic_saved_search,
        "counts": {
            "ready": report.ready,
            "exported": report.exported,
            "waiting": report.waiting,
            "failed": report.failed,
            "skipped": report.skipped,
        },
        "items": [
            {
                "export_item_id": item.export_item_id,
                "state": item.state,
                "attempts": item.attempts,
                "error": item.error,
                "destination_path": item.destination_path,
                "verified": item.verified,
            }
            for item in items
        ],
    }
