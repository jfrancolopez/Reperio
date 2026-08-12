from __future__ import annotations

import unittest

from scanner import scheduler


class ScannerSchedulerTests(unittest.TestCase):
    def test_graph_order_and_conservative_io_waves(self) -> None:
        waves = scheduler.execution_waves()

        self.assertEqual(
            (
                (scheduler.STAGE_VALIDATION,),
                (scheduler.STAGE_VOLUMES,),
                (scheduler.STAGE_ENUMERATION,),
                (scheduler.STAGE_ARTIFACTS,),
                (scheduler.STAGE_CARVING,),
                (scheduler.STAGE_ENRICHMENT,),
                (scheduler.STAGE_FINALIZATION,),
            ),
            waves,
        )

    def test_carving_never_starts_before_validation_volumes_and_enumeration(self) -> None:
        statuses = scheduler.initial_statuses()
        statuses[scheduler.STAGE_VALIDATION] = scheduler.STAGE_COMPLETED
        statuses[scheduler.STAGE_VOLUMES] = scheduler.STAGE_COMPLETED

        plan = scheduler.runnable_stages(statuses, scheduler.SchedulerConfig(max_io_cost=4))

        self.assertIn(scheduler.STAGE_ENUMERATION, plan.runnable)
        self.assertNotIn(scheduler.STAGE_CARVING, plan.runnable)
        self.assertEqual(scheduler.PRODUCT_SCAN_MODE, plan.scan_mode)

    def test_pause_propagates_to_pending_and_running_only(self) -> None:
        statuses = scheduler.initial_statuses()
        statuses[scheduler.STAGE_VALIDATION] = scheduler.STAGE_COMPLETED
        statuses[scheduler.STAGE_VOLUMES] = scheduler.STAGE_RUNNING

        paused = scheduler.pause_all(statuses)

        self.assertEqual(scheduler.STAGE_COMPLETED, paused[scheduler.STAGE_VALIDATION])
        self.assertEqual(scheduler.STAGE_PAUSED, paused[scheduler.STAGE_VOLUMES])
        self.assertEqual(scheduler.STAGE_PAUSED, paused[scheduler.STAGE_ENUMERATION])

    def test_failed_optional_stage_skips_dependents_but_allows_finalization(self) -> None:
        statuses = scheduler.initial_statuses()
        for stage in (
            scheduler.STAGE_VALIDATION,
            scheduler.STAGE_VOLUMES,
            scheduler.STAGE_ENUMERATION,
        ):
            statuses[stage] = scheduler.STAGE_COMPLETED

        updated, scan_failed = scheduler.apply_stage_failure(statuses, scheduler.STAGE_ARTIFACTS)
        plan = scheduler.runnable_stages(updated)

        self.assertFalse(scan_failed)
        self.assertEqual(scheduler.STAGE_FAILED, updated[scheduler.STAGE_ARTIFACTS])
        self.assertEqual(scheduler.STAGE_SKIPPED, updated[scheduler.STAGE_ENRICHMENT])
        self.assertEqual((scheduler.STAGE_CARVING,), plan.runnable)
        updated[scheduler.STAGE_CARVING] = scheduler.STAGE_COMPLETED
        self.assertEqual(
            (scheduler.STAGE_FINALIZATION,), scheduler.runnable_stages(updated).runnable
        )

    def test_mandatory_stage_failure_fails_dependent_scan(self) -> None:
        statuses = scheduler.initial_statuses()

        updated, scan_failed = scheduler.apply_stage_failure(statuses, scheduler.STAGE_VALIDATION)

        self.assertTrue(scan_failed)
        self.assertEqual(scheduler.STAGE_FAILED, updated[scheduler.STAGE_VALIDATION])
        self.assertEqual(scheduler.STAGE_FAILED, updated[scheduler.STAGE_VOLUMES])
        self.assertEqual((), scheduler.runnable_stages(updated).runnable)

    def test_restart_with_completed_dependencies_does_not_rerun_them(self) -> None:
        plan = scheduler.restart_plan(
            {
                scheduler.STAGE_VALIDATION,
                scheduler.STAGE_VOLUMES,
                scheduler.STAGE_ENUMERATION,
            },
            scheduler.SchedulerConfig(max_io_cost=2),
        )

        self.assertNotIn(scheduler.STAGE_VALIDATION, plan.runnable)
        self.assertNotIn(scheduler.STAGE_ENUMERATION, plan.runnable)
        self.assertEqual((scheduler.STAGE_ARTIFACTS, scheduler.STAGE_CARVING), plan.runnable)

    def test_capability_configuration_disables_optional_stages(self) -> None:
        plan = scheduler.restart_plan(
            {
                scheduler.STAGE_VALIDATION,
                scheduler.STAGE_VOLUMES,
                scheduler.STAGE_ENUMERATION,
                scheduler.STAGE_ARTIFACTS,
                scheduler.STAGE_CARVING,
            },
            scheduler.SchedulerConfig(enable_enrichment=False),
        )

        self.assertEqual((scheduler.STAGE_FINALIZATION,), plan.runnable)


if __name__ == "__main__":
    unittest.main()
