#!/usr/bin/env python3

from __future__ import annotations

import unittest

from worker.export_queue import (
    EXPORT_QUEUE_VERSION,
    CompletionReport,
    ExportQueueError,
    QueueItem,
    build_completion_report,
    classify_readiness,
    queue_snapshot,
    retry_delay_seconds,
    step_queue,
)


def item(item_id: str, state: str, attempts: int = 0) -> QueueItem:
    return QueueItem(item_id, state, attempts, verified=(state == "exported"))


class ClassifyReadinessTests(unittest.TestCase):
    def test_ready_content_is_ready(self) -> None:
        self.assertEqual("ready", classify_readiness("i1", content_ready=True))

    def test_pending_extraction_waits(self) -> None:
        self.assertEqual("waiting", classify_readiness("i1", content_ready=False))

    def test_dismissed_is_skipped(self) -> None:
        self.assertEqual("skipped", classify_readiness("i1", content_ready=True, dismissed=True))


class RetryDelayTests(unittest.TestCase):
    def test_bounded_exponential_backoff(self) -> None:
        self.assertEqual(2.0, retry_delay_seconds(1))
        self.assertEqual(4.0, retry_delay_seconds(2))
        self.assertEqual(60.0, retry_delay_seconds(6))

    def test_invalid_attempt_rejected(self) -> None:
        with self.assertRaisesRegex(ExportQueueError, "attempt"):
            retry_delay_seconds(0)


class StepQueueTests(unittest.TestCase):
    def test_waiting_becomes_ready_when_content_ready(self) -> None:
        result, steps = step_queue(
            [item("i1", "waiting")],
            readiness_of={"i1": True},
            exporter_results={},
        )
        self.assertEqual("ready", result[0].state)
        self.assertEqual(
            ("i1", "waiting", "ready"), (steps[0].item_id, steps[0].before, steps[0].after)
        )

    def test_waiting_stays_waiting_and_retries(self) -> None:
        result, steps = step_queue(
            [item("i1", "waiting", attempts=0)],
            readiness_of={"i1": False},
            exporter_results={},
        )
        self.assertEqual("waiting", result[0].state)
        self.assertEqual(1, result[0].attempts)
        self.assertIsNotNone(steps[0].delay_seconds)

    def test_waiting_budget_exhausted_fails(self) -> None:
        result, _ = step_queue(
            [item("i1", "waiting", attempts=5)],
            readiness_of={"i1": False},
            exporter_results={},
        )
        self.assertEqual("failed", result[0].state)
        self.assertEqual("extraction_timeout", result[0].error)

    def test_ready_exported_when_copy_verifies(self) -> None:
        result, steps = step_queue(
            [item("i1", "ready")],
            readiness_of={"i1": True},
            exporter_results={"i1": True},
        )
        self.assertEqual("exported", result[0].state)
        self.assertTrue(result[0].verified)
        self.assertEqual("exported", steps[0].after)

    def test_ready_failed_copy_stays_ready(self) -> None:
        result, steps = step_queue(
            [item("i1", "ready", attempts=0)],
            readiness_of={"i1": True},
            exporter_results={"i1": False},
        )
        self.assertEqual("ready", result[0].state)
        self.assertEqual(1, result[0].attempts)
        self.assertIsNotNone(steps[0].delay_seconds)

    def test_ready_budget_exhausted_fails(self) -> None:
        result, _ = step_queue(
            [item("i1", "ready", attempts=5)],
            readiness_of={"i1": True},
            exporter_results={"i1": False},
        )
        self.assertEqual("failed", result[0].state)
        self.assertEqual("export_failed", result[0].error)

    def test_dismissed_mid_export_skipped(self) -> None:
        result, steps = step_queue(
            [item("i1", "waiting")],
            readiness_of={"i1": False},
            exporter_results={},
            dismissed={"i1": True},
        )
        self.assertEqual("skipped", result[0].state)
        self.assertEqual("skipped", steps[0].after)

    def test_terminal_states_unchanged(self) -> None:
        result, steps = step_queue(
            [item("i1", "exported"), item("i2", "failed"), item("i3", "skipped")],
            readiness_of={},
            exporter_results={},
        )
        self.assertEqual(["exported", "failed", "skipped"], [q.state for q in result])
        self.assertEqual((), steps)

    def test_restart_resumes_from_snapshot(self) -> None:
        first, _ = step_queue(
            [item("i1", "waiting")],
            readiness_of={"i1": True},
            exporter_results={},
        )
        second, _ = step_queue(first, readiness_of={"i1": True}, exporter_results={"i1": True})
        self.assertEqual("exported", second[0].state)


class CompletionReportTests(unittest.TestCase):
    def test_accurate_counts(self) -> None:
        items = [
            item("a", "ready"),
            item("b", "exported"),
            item("c", "waiting"),
            item("d", "failed"),
            item("e", "skipped"),
        ]
        report = build_completion_report(items)
        self.assertEqual(CompletionReport(1, 1, 1, 1, 1), report)
        self.assertEqual(5, report.total)

    def test_unknown_state_rejected(self) -> None:
        with self.assertRaisesRegex(ExportQueueError, "unknown_state"):
            build_completion_report([item("a", "bogus")])


class QueueSnapshotTests(unittest.TestCase):
    def test_snapshot_marks_dynamic_export_explicit(self) -> None:
        snapshot = queue_snapshot(
            [item("i1", "exported", attempts=2)],
            export_id="export_1",
            case_id="case_1",
            dynamic_saved_search=True,
        )
        self.assertEqual(EXPORT_QUEUE_VERSION, snapshot["export_queue_version"])
        self.assertTrue(snapshot["dynamic_saved_search"])
        self.assertEqual(
            {"ready": 0, "exported": 1, "waiting": 0, "failed": 0, "skipped": 0}, snapshot["counts"]
        )
        self.assertEqual(2, snapshot["items"][0]["attempts"])
        self.assertTrue(snapshot["items"][0]["verified"])

    def test_snapshot_never_locks(self) -> None:
        snapshot = queue_snapshot([item("i1", "waiting")], export_id="e", case_id="c")
        self.assertEqual("waiting", snapshot["items"][0]["state"])
        self.assertFalse(snapshot["dynamic_saved_search"])


if __name__ == "__main__":
    unittest.main()
