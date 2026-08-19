#!/usr/bin/env python3

from __future__ import annotations

import unittest
from typing import cast

from scanner.scheduler import (
    STAGE_ARTIFACTS,
    STAGE_CARVING,
    STAGE_COMPLETED,
    STAGE_ENUMERATION,
    STAGE_FAILED,
    STAGE_RUNNING,
    STAGE_SKIPPED,
    STAGE_VALIDATION,
    STAGE_VOLUMES,
)
from worker.progress_summary import (
    COMPLETION_STATES,
    PROGRESS_SUMMARY_VERSION,
    ProgressSummaryError,
    StageProgress,
    build_completion_summary,
    eta_seconds,
    heartbeat_due,
    heartbeat_snapshot,
    overall_progress,
    stage_percent,
)


class StagePercentTests(unittest.TestCase):
    def test_known_denominator_percent(self) -> None:
        self.assertEqual(50, stage_percent(StageProgress(STAGE_ENUMERATION, 5, 10)))

    def test_completed_denominator_percent(self) -> None:
        self.assertEqual(100, stage_percent(StageProgress(STAGE_ENUMERATION, 10, 10)))

    def test_unknown_denominator_is_none(self) -> None:
        self.assertIsNone(stage_percent(StageProgress(STAGE_ENUMERATION, 3, None)))
        self.assertIsNone(stage_percent(StageProgress(STAGE_ENUMERATION, 3, 0)))

    def test_negative_input_rejected(self) -> None:
        with self.assertRaisesRegex(ProgressSummaryError, "negative"):
            stage_percent(StageProgress(STAGE_ENUMERATION, -1, 10))


class EtaTests(unittest.TestCase):
    def test_eta_only_with_denominator_and_progress(self) -> None:
        progress = StageProgress(STAGE_ENUMERATION, 5, 10)
        self.assertIsNotNone(eta_seconds(progress, elapsed_seconds=100))

    def test_no_eta_without_denominator(self) -> None:
        progress = StageProgress(STAGE_ENUMERATION, 5, None)
        self.assertIsNone(eta_seconds(progress, elapsed_seconds=100))

    def test_no_eta_with_zero_progress(self) -> None:
        progress = StageProgress(STAGE_ENUMERATION, 0, 10)
        self.assertIsNone(eta_seconds(progress, elapsed_seconds=100))

    def test_completed_eta_is_zero(self) -> None:
        progress = StageProgress(STAGE_ENUMERATION, 10, 10)
        self.assertEqual(0, eta_seconds(progress, elapsed_seconds=100))

    def test_no_fabricated_eta_without_rate(self) -> None:
        progress = StageProgress(STAGE_ENUMERATION, 0, 10)
        self.assertIsNone(eta_seconds(progress, elapsed_seconds=0))


class OverallProgressTests(unittest.TestCase):
    def test_all_known_denominators_weighted_percent(self) -> None:
        active = [
            StageProgress(STAGE_VALIDATION, 10, 10),
            StageProgress(STAGE_ENUMERATION, 50, 100),
        ]
        statuses = {STAGE_VALIDATION: STAGE_COMPLETED, STAGE_ENUMERATION: STAGE_RUNNING}
        estimate = overall_progress(active, statuses)
        self.assertEqual("weighted", estimate.mode)
        self.assertIsNotNone(estimate.percent)
        percent = cast(int, estimate.percent)
        self.assertGreaterEqual(percent, 0)
        self.assertLessEqual(percent, 100)

    def test_unknown_denominator_falls_back_to_activity_only(self) -> None:
        active = [
            StageProgress(STAGE_VALIDATION, 10, 10),
            StageProgress(STAGE_CARVING, 5, None),
        ]
        statuses = {STAGE_VALIDATION: STAGE_COMPLETED, STAGE_CARVING: STAGE_RUNNING}
        estimate = overall_progress(active, statuses)
        self.assertEqual("activity_only", estimate.mode)
        self.assertIsNone(estimate.percent)
        self.assertIn("unknown_denominator:carving", estimate.reasons)

    def test_idle_when_no_active_stages(self) -> None:
        estimate = overall_progress([], {})
        self.assertEqual("idle", estimate.mode)
        self.assertEqual(0, estimate.percent)

    def test_unknown_stage_rejected(self) -> None:
        with self.assertRaisesRegex(ProgressSummaryError, "unknown_stage"):
            overall_progress([StageProgress("nonsense", 1, 10)], {})

    def test_no_fabricated_percent_without_denominator(self) -> None:
        active = [StageProgress(STAGE_CARVING, 50, None)]
        estimate = overall_progress(active, {STAGE_CARVING: STAGE_RUNNING})
        self.assertIsNone(estimate.percent)
        self.assertIsNone(estimate.eta_seconds)


class HeartbeatTests(unittest.TestCase):
    def test_first_heartbeat_always_due(self) -> None:
        self.assertTrue(heartbeat_due(None, now="2026-08-19T10:00:00Z", throttle_seconds=30))

    def test_throttled_when_recent(self) -> None:
        self.assertFalse(
            heartbeat_due("2026-08-19T10:00:05Z", now="2026-08-19T10:00:10Z", throttle_seconds=30)
        )

    def test_due_after_interval(self) -> None:
        self.assertTrue(
            heartbeat_due("2026-08-19T10:00:05Z", now="2026-08-19T10:01:00Z", throttle_seconds=30)
        )

    def test_invalid_throttle_rejected(self) -> None:
        with self.assertRaisesRegex(ProgressSummaryError, "throttle"):
            heartbeat_due(None, now="2026-08-19T10:00:00Z", throttle_seconds=0)


class CompletionSummaryTests(unittest.TestCase):
    def test_clean_completion_state(self) -> None:
        summary = build_completion_summary(
            case_id="case-1",
            stages={s: STAGE_COMPLETED for s in (STAGE_VALIDATION, STAGE_ENUMERATION)},
            counts={"findings": 12},
            elapsed_seconds=300,
            ui_link="http://localhost:8080/case/case-1",
        )
        self.assertEqual("completed", summary.state)
        self.assertEqual((), summary.warnings)
        self.assertEqual(300, summary.elapsed_seconds)

    def test_warnings_and_skipped_yield_completed_warning(self) -> None:
        summary = build_completion_summary(
            case_id="case-2",
            stages={
                STAGE_VALIDATION: STAGE_COMPLETED,
                STAGE_ARTIFACTS: STAGE_SKIPPED,
            },
            counts={},
            warnings=("carving noise above threshold",),
        )
        self.assertEqual("completed-warning", summary.state)
        self.assertEqual((STAGE_ARTIFACTS,), summary.skipped_stages)
        self.assertEqual(("carving noise above threshold",), summary.warnings)

    def test_failure_distinguishes_failed_stage(self) -> None:
        summary = build_completion_summary(
            case_id="case-3",
            stages={STAGE_VALIDATION: STAGE_FAILED, STAGE_ENUMERATION: STAGE_SKIPPED},
            counts={},
        )
        self.assertEqual("failed", summary.state)
        self.assertEqual((STAGE_VALIDATION,), summary.failed_stages)

    def test_export_counts_and_ui_link(self) -> None:
        summary = build_completion_summary(
            case_id="case-4",
            stages={STAGE_VALIDATION: STAGE_COMPLETED},
            counts={"findings": 4},
            export_counts={"recovered_files": 3, "thumbnails": 3},
            ui_link="http://localhost:8080/case/case-4",
        )
        self.assertEqual({"recovered_files": 3, "thumbnails": 3}, summary.export_counts)
        self.assertEqual("http://localhost:8080/case/case-4", summary.ui_link)

    def test_summary_snapshot_is_deterministic(self) -> None:
        kwargs: dict[str, object] = dict(
            case_id="case-5",
            stages={STAGE_VALIDATION: STAGE_COMPLETED},
            counts={"findings": 1},
        )
        first = build_completion_summary(
            case_id=cast(str, kwargs["case_id"]),
            stages=cast(dict[str, str], kwargs["stages"]),
            counts=cast(dict[str, int], kwargs["counts"]),
        )
        second = build_completion_summary(
            case_id=cast(str, kwargs["case_id"]),
            stages=cast(dict[str, str], kwargs["stages"]),
            counts=cast(dict[str, int], kwargs["counts"]),
        )
        self.assertEqual(first, second)

    def test_summary_version_constant(self) -> None:
        self.assertEqual("progress-summary-v1", PROGRESS_SUMMARY_VERSION)
        self.assertIn("completed", COMPLETION_STATES)
        self.assertIn("failed", COMPLETION_STATES)

    def test_negative_elapsed_rejected(self) -> None:
        with self.assertRaisesRegex(ProgressSummaryError, "elapsed"):
            build_completion_summary(case_id="case-6", stages={}, counts={}, elapsed_seconds=-1)


class HeartbeatSnapshotTests(unittest.TestCase):
    def test_activity_only_snapshot_payload(self) -> None:
        payload = heartbeat_snapshot(
            case_id="case-7",
            stages={STAGE_CARVING: STAGE_RUNNING},
            active=[StageProgress(STAGE_CARVING, 5, None)],
            counts={"findings": 2},
            elapsed_seconds=60,
            now="2026-08-19T10:00:00Z",
        )
        self.assertEqual("activity_only", payload["mode"])
        self.assertIsNone(payload["percent"])
        self.assertIsNone(payload["eta_seconds"])
        self.assertEqual(60, payload["elapsed_seconds"])
        self.assertIn("reasons", payload)

    def test_weighted_snapshot_has_percent(self) -> None:
        payload = heartbeat_snapshot(
            case_id="case-8",
            stages={STAGE_ENUMERATION: STAGE_RUNNING},
            active=[StageProgress(STAGE_ENUMERATION, 5, 10)],
            counts={"findings": 1},
            elapsed_seconds=30,
            now="2026-08-19T10:00:00Z",
        )
        self.assertEqual("weighted", payload["mode"])
        self.assertIsNotNone(payload["percent"])

    def test_stage_states_always_present_for_all_stages(self) -> None:
        payload = heartbeat_snapshot(
            case_id="case-9",
            stages={STAGE_VALIDATION: STAGE_COMPLETED},
            active=[],
            counts={},
            elapsed_seconds=1,
            now="2026-08-19T10:00:00Z",
        )
        stage_states = cast(dict[str, str], payload["stage_states"])
        self.assertEqual(STAGE_COMPLETED, stage_states[STAGE_VALIDATION])
        self.assertEqual("pending", stage_states[STAGE_VOLUMES])


if __name__ == "__main__":
    unittest.main()
