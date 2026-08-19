#!/usr/bin/env python3

from __future__ import annotations

import unittest
from typing import Any

from shared import media_identity
from worker.device_wizard import build_source_card
from worker.medium_workflow import (
    MEDIUM_WORKFLOW_VERSION,
    MediumWorkflowError,
    assert_no_destructive_controls,
    insertion_state,
    plan_batch,
    scratch_estimate,
    unsupported_medium_explanation,
    workflow_snapshot,
)

FINGERPRINT = "a" * 64


def device(**overrides: Any) -> dict[str, Any]:
    dev: dict[str, Any] = {
        "source_id": "src_1",
        "reader_id": "reader_1",
        "device_type": "sd_card",
        "removable": True,
        "read_only": True,
        "read_only_verified": True,
        "size_bytes": 32 * 1024 * 1024,
        "major_minor": "179:0",
        "medium_identity": media_identity.medium_identity_record(
            "reader_1",
            media_identity.normalize_medium_signals(
                {"size_bytes": 32 * 1024 * 1024, "sampled_fingerprint_sha256": FINGERPRINT}
            ),
            identity_strength="reader-plus-medium",
        ),
    }
    dev.update(overrides)
    return dev


def card(**overrides: Any) -> Any:
    return build_source_card(device(**overrides))


class InsertionStateTests(unittest.TestCase):
    def test_present_medium(self) -> None:
        state = insertion_state(card())
        self.assertEqual("present", state.state)

    def test_empty_reader_explained(self) -> None:
        empty_card = card(
            medium_identity=media_identity.medium_identity_record(
                "reader_1",
                media_identity.normalize_medium_signals({"size_bytes": 0}),
                identity_strength="reader-facts",
            )
        )
        state = insertion_state(empty_card)
        self.assertEqual("empty", state.state)
        self.assertIn("no_medium_present", state.reasons)
        self.assertIn("Insert a supported medium", unsupported_medium_explanation(empty_card))


class ScratchEstimateTests(unittest.TestCase):
    def test_sufficient_scratch(self) -> None:
        estimate = scratch_estimate(card(), available_bytes=100 * 1024 * 1024)
        self.assertTrue(estimate.sufficient)
        self.assertEqual(48 * 1024 * 1024, estimate.needed_bytes)

    def test_insufficient_scratch_reported(self) -> None:
        estimate = scratch_estimate(card(), available_bytes=10 * 1024 * 1024)
        self.assertFalse(estimate.sufficient)
        self.assertEqual("insufficient_scratch", estimate.reason)

    def test_invalid_multiplier_rejected(self) -> None:
        with self.assertRaisesRegex(MediumWorkflowError, "multiplier"):
            scratch_estimate(card(), available_bytes=100, multiplier=0)


class PlanBatchTests(unittest.TestCase):
    def test_one_at_a_time_queue(self) -> None:
        cards = [card(source_id="s1", reader_id="r1"), card(source_id="s2", reader_id="r2")]
        steps, warnings = plan_batch(cards)
        self.assertEqual("ready", steps[0].status)
        self.assertEqual("queued", steps[1].status)
        self.assertTrue(steps[0].can_finish)
        self.assertEqual((), warnings)

    def test_replacing_media_never_starts_automatically(self) -> None:
        cards = [card(source_id="s1", reader_id="r1"), card(source_id="s2", reader_id="r1")]
        steps, warnings = plan_batch(cards)
        self.assertEqual("queued", steps[1].status)
        self.assertIn("same_reader_replaced:r1", warnings)

    def test_completed_prior_case_finishes(self) -> None:
        steps, _ = plan_batch([card(source_id="s1", reader_id="r1")], completed_source_ids=["s1"])
        self.assertEqual("completed", steps[0].status)
        self.assertTrue(steps[0].can_finish)

    def test_queued_medium_cannot_insert_next(self) -> None:
        cards = [card(source_id="s1", reader_id="r1"), card(source_id="s2", reader_id="r2")]
        steps, _ = plan_batch(cards)
        self.assertFalse(steps[0].can_insert_next)
        self.assertTrue(steps[0].can_finish)


class DestructiveGuardTests(unittest.TestCase):
    def test_destructive_labels_forbidden(self) -> None:
        for label in ("erase", "format", "initialize", "burn", "blank", "repair", "wipe", "delete"):
            with self.subTest(label=label):
                with self.assertRaisesRegex(MediumWorkflowError, "destructive_control"):
                    assert_no_destructive_controls([label])

    def test_safe_controls_allowed(self) -> None:
        assert_no_destructive_controls(["start", "pause", "safe_stop", "finish", "insert_next"])

    def test_snapshot_never_exposes_destructive_controls(self) -> None:
        snapshot = workflow_snapshot(
            [card()],
            scratch_available_bytes=100 * 1024 * 1024,
            controls=["start", "pause", "safe_stop", "finish", "insert_next"],
        )
        self.assertEqual([], snapshot["destructive_controls"])

    def test_snapshot_rejects_destructive_control(self) -> None:
        with self.assertRaisesRegex(MediumWorkflowError, "destructive_control"):
            workflow_snapshot([card()], controls=["start", "format"])


class WorkflowSnapshotTests(unittest.TestCase):
    def test_snapshot_active_source_and_scratch(self) -> None:
        snapshot = workflow_snapshot(
            [card(source_id="s1", reader_id="r1")],
            scratch_available_bytes=100 * 1024 * 1024,
        )
        self.assertEqual(MEDIUM_WORKFLOW_VERSION, snapshot["workflow_version"])
        self.assertEqual("s1", snapshot["active_source_id"])
        self.assertTrue(snapshot["scratch"]["sufficient"])

    def test_insufficient_scratch_in_snapshot(self) -> None:
        snapshot = workflow_snapshot([card(source_id="s1")], scratch_available_bytes=1)
        self.assertFalse(snapshot["scratch"]["sufficient"])
        self.assertEqual("insufficient_scratch", snapshot["scratch"]["reason"])

    def test_prior_cases_browsable_during_next_scan(self) -> None:
        snapshot = workflow_snapshot(
            [card(source_id="s2", reader_id="r2")],
            completed_source_ids=["s1"],
            prior_cases_available=True,
        )
        self.assertTrue(snapshot["prior_cases_browsable"])


if __name__ == "__main__":
    unittest.main()
