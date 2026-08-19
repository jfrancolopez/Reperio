#!/usr/bin/env python3

from __future__ import annotations

import unittest

from scanner.scheduler import (
    STAGE_CARVING,
    STAGE_COMPLETED,
    STAGE_ENUMERATION,
    STAGE_FAILED,
    STAGE_RUNNING,
    STAGE_VALIDATION,
    STAGE_VOLUMES,
)
from worker.dashboard_state import (
    DASHBOARD_VERSION,
    DashboardError,
    bounded_samples,
    control_state,
    current_activity,
    dashboard_snapshot,
)
from worker.progress_summary import StageProgress

NOW = "2026-08-19T10:00:00Z"


def stage_statuses(**overrides: str) -> dict[str, str]:
    statuses: dict[str, str] = {
        STAGE_VALIDATION: STAGE_COMPLETED,
        STAGE_VOLUMES: STAGE_COMPLETED,
        STAGE_ENUMERATION: STAGE_RUNNING,
        STAGE_CARVING: "pending",
    }
    statuses.update(overrides)
    return statuses


class ControlStateTests(unittest.TestCase):
    def test_pause_only_while_running(self) -> None:
        self.assertTrue(control_state("running").pause_enabled)
        self.assertFalse(control_state("paused").pause_enabled)

    def test_resume_only_while_paused(self) -> None:
        self.assertTrue(control_state("paused").resume_enabled)
        self.assertFalse(control_state("running").resume_enabled)

    def test_safe_stop_while_active(self) -> None:
        for state in ("running", "paused", "pending", "retrying"):
            with self.subTest(state=state):
                self.assertTrue(control_state(state).safe_stop_enabled)

    def test_terminal_states_disable_controls(self) -> None:
        for state in ("completed", "completed-warning", "failed", "cancelled"):
            with self.subTest(state=state):
                controls = control_state(state)
                self.assertFalse(controls.pause_enabled)
                self.assertFalse(controls.resume_enabled)
                self.assertFalse(controls.safe_stop_enabled)
                self.assertIn("terminal_state", controls.reasons)

    def test_unknown_state_rejected(self) -> None:
        with self.assertRaisesRegex(DashboardError, "unknown_job_state"):
            control_state("bogus")


class ActivityTests(unittest.TestCase):
    def test_current_running_stage(self) -> None:
        self.assertEqual(STAGE_ENUMERATION, current_activity(stage_statuses()))

    def test_no_activity_when_idle(self) -> None:
        self.assertIsNone(current_activity({STAGE_VALIDATION: STAGE_COMPLETED}))


class SampleTests(unittest.TestCase):
    def test_samples_bounded(self) -> None:
        samples = [{"id": i} for i in range(20)]
        bounded = bounded_samples(samples)
        self.assertEqual(5, len(bounded))
        self.assertEqual(0, bounded[0]["id"])

    def test_invalid_limit_rejected(self) -> None:
        with self.assertRaisesRegex(DashboardError, "limit"):
            bounded_samples([], limit=-1)


class DashboardSnapshotTests(unittest.TestCase):
    def test_running_snapshot(self) -> None:
        snapshot = dashboard_snapshot(
            case_id="case_1",
            job_state="running",
            stage_statuses=stage_statuses(),
            stage_progress=[StageProgress(STAGE_ENUMERATION, 5, 10)],
            counts={"findings": 12},
            warnings=["carving noise"],
            source_facts={"read_only_verified": True, "source_kind": "memory_card"},
            live_samples=[{"entry_id": "e1", "path": "dcim/x.jpg"}],
            ui_base="http://localhost:8080",
            now=NOW,
        )
        self.assertEqual(DASHBOARD_VERSION, snapshot["dashboard_version"])
        self.assertEqual("running", snapshot["job_state"])
        self.assertEqual(STAGE_ENUMERATION, snapshot["current_activity"])
        self.assertTrue(snapshot["controls"]["pause"])
        self.assertEqual("weighted", snapshot["progress"]["mode"])
        self.assertIsNotNone(snapshot["progress"]["percent"])
        self.assertEqual(12, snapshot["counters"]["findings"])
        self.assertEqual("http://localhost:8080/case/case_1", snapshot["results_link"])
        self.assertEqual(1, len(snapshot["live_samples"]))

    def test_unknown_percentage_not_fabricated(self) -> None:
        snapshot = dashboard_snapshot(
            case_id="case_2",
            job_state="running",
            stage_statuses=stage_statuses(),
            stage_progress=[StageProgress(STAGE_CARVING, 3, None)],
            now=NOW,
        )
        self.assertEqual("activity_only", snapshot["progress"]["mode"])
        self.assertIsNone(snapshot["progress"]["percent"])
        self.assertIsNone(snapshot["progress"]["eta_seconds"])

    def test_controls_follow_paused_state(self) -> None:
        snapshot = dashboard_snapshot(
            case_id="case_3",
            job_state="paused",
            stage_statuses=stage_statuses(),
            now=NOW,
        )
        self.assertFalse(snapshot["controls"]["pause"])
        self.assertTrue(snapshot["controls"]["resume"])
        self.assertTrue(snapshot["controls"]["safe_stop"])

    def test_completion_with_warnings(self) -> None:
        snapshot = dashboard_snapshot(
            case_id="case_4",
            job_state="completed-warning",
            stage_statuses={s: STAGE_COMPLETED for s in stage_statuses()},
            warnings=["carving noise above threshold"],
            now=NOW,
        )
        self.assertEqual("completed-warning", snapshot["job_state"])
        self.assertFalse(snapshot["controls"]["pause"])
        self.assertEqual(("carving noise above threshold",), tuple(snapshot["warnings"]))

    def test_failed_state_reports_errors(self) -> None:
        snapshot = dashboard_snapshot(
            case_id="case_5",
            job_state="failed",
            stage_statuses={**stage_statuses(), STAGE_CARVING: STAGE_FAILED},
            errors=["carving stage crashed"],
            now=NOW,
        )
        self.assertEqual(["carving stage crashed"], snapshot["errors"])
        self.assertEqual("failed", snapshot["job_state"])

    def test_results_link_works_before_completion(self) -> None:
        snapshot = dashboard_snapshot(
            case_id="case_6",
            job_state="pending",
            stage_statuses=stage_statuses(),
            now=NOW,
        )
        self.assertEqual("/case/case_6", snapshot["results_link"])

    def test_stage_list_ordered(self) -> None:
        snapshot = dashboard_snapshot(
            case_id="case_7",
            job_state="running",
            stage_statuses=stage_statuses(),
            now=NOW,
        )
        stages = [item["stage"] for item in snapshot["stages"]]
        self.assertEqual(
            [
                STAGE_VALIDATION,
                STAGE_VOLUMES,
                STAGE_ENUMERATION,
                "artifacts",
                STAGE_CARVING,
                "enrichment",
                "finalization",
            ],
            stages,
        )

    def test_unknown_job_state_rejected(self) -> None:
        with self.assertRaisesRegex(DashboardError, "unknown_job_state"):
            dashboard_snapshot(case_id="c", job_state="bogus", stage_statuses={}, now=NOW)


if __name__ == "__main__":
    unittest.main()
