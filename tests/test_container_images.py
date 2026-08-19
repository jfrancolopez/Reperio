#!/usr/bin/env python3

from __future__ import annotations

import unittest
from typing import Any

from worker.container_images import (
    CONTAINER_IMAGES_VERSION,
    ContainerImagesError,
    adapter_plan,
    corrupt_image_outcome,
    default_budget,
    detect_container,
    missing_backing_outcome,
    nested_source_identity,
    normalize_findings,
    parse_child_volumes,
    recursion_allowed,
    run_adapter,
    validate_backing_path,
    within_size_budget,
    within_work_budget,
)


class DetectTests(unittest.TestCase):
    def test_kind_detection(self) -> None:
        for kind in ("raw", "vhd", "vhdx", "vmdk", "iso"):
            self.assertEqual(kind, detect_container(kind))

    def test_signature_detection(self) -> None:
        self.assertEqual("vmdk", detect_container("KDMV"))
        self.assertEqual("vhdx", detect_container("vhdxfile"))
        self.assertEqual("iso", detect_container("ISO9660"))

    def test_undetected_rejected(self) -> None:
        with self.assertRaisesRegex(ContainerImagesError, "no supported container kind"):
            detect_container("mystery-blob")


class IdentityTests(unittest.TestCase):
    def test_nested_identity(self) -> None:
        identity = nested_source_identity(
            kind="vhdx", source_id="child", parent_id="parent", depth=1
        )
        self.assertEqual(1, identity["depth"])
        self.assertEqual("parent", identity["parent_id"])

    def test_negative_depth_rejected(self) -> None:
        with self.assertRaisesRegex(ContainerImagesError, "non-negative"):
            nested_source_identity(kind="vhdx", source_id="x", parent_id=None, depth=-1)


class BackingPathTests(unittest.TestCase):
    def test_valid_backing_within_store(self) -> None:
        path = validate_backing_path("/content/store/child.vhdx", "/content/store")
        self.assertEqual("/content/store/child.vhdx", path)

    def test_traversal_rejected(self) -> None:
        with self.assertRaisesRegex(ContainerImagesError, "escape"):
            validate_backing_path("../../etc/passwd", "/content/store")

    def test_absolute_escape_rejected(self) -> None:
        with self.assertRaisesRegex(ContainerImagesError, "outside the content store"):
            validate_backing_path("/etc/passwd", "/content/store")


class PlanTests(unittest.TestCase):
    def test_read_only_adapter_plan(self) -> None:
        plan = adapter_plan(
            kind="vhdx", scratch_path="/scratch/job-1/img.vhdx", content_store_root="/content/store"
        )
        self.assertFalse(plan["hypervisor_starts"])
        self.assertFalse(plan["mount_write"])
        self.assertTrue(plan["read_only"])

    def test_backing_plan_validated(self) -> None:
        plan = adapter_plan(
            kind="vmdk",
            scratch_path="/scratch/job-1/img.vmdk",
            content_store_root="/content/store",
            backing_path="/content/store/backing.vmdk",
        )
        self.assertIn("backing_path", plan)

    def test_missing_backing_outcome(self) -> None:
        self.assertEqual("missing_backing", missing_backing_outcome()["status"])

    def test_corrupt_image_outcome(self) -> None:
        self.assertEqual("corrupt", corrupt_image_outcome()["status"])


class BudgetTests(unittest.TestCase):
    def test_recursion_opt_in_and_bounded(self) -> None:
        budget = default_budget()
        self.assertTrue(recursion_allowed(opt_in=True, depth=0, budget=budget))
        self.assertFalse(recursion_allowed(opt_in=False, depth=0, budget=budget))
        self.assertFalse(recursion_allowed(opt_in=True, depth=3, budget=budget))

    def test_size_and_work_budgets(self) -> None:
        budget = default_budget()
        self.assertTrue(within_size_budget(1000, budget))
        self.assertFalse(within_size_budget(10**14, budget))
        self.assertTrue(within_work_budget(500, budget))
        self.assertFalse(within_work_budget(5000, budget))


class FindingsTests(unittest.TestCase):
    def test_child_volumes_normalized(self) -> None:
        image = {
            "source_id": "img-1",
            "kind": "vhdx",
            "volumes": [{"label": "system", "filesystem": "ntfs", "size_bytes": 1000}],
        }
        volumes = parse_child_volumes(image)
        self.assertEqual("img-1-v1", volumes[0]["volume_id"])
        self.assertEqual("img-1", volumes[0]["parent_source_id"])

    def test_normalized_findings_include_container_and_children(self) -> None:
        image = {
            "source_id": "img-1",
            "kind": "vhdx",
            "depth": 0,
            "volumes": [{"filesystem": "ntfs", "size_bytes": 1}],
        }
        findings = normalize_findings(image)
        self.assertEqual("container_image", findings[0]["finding_type"])
        self.assertEqual("child_volume", findings[1]["finding_type"])
        self.assertEqual(1, findings[1]["depth"])


class RunTests(unittest.TestCase):
    def test_ok_outcome(self) -> None:
        plan = adapter_plan(
            kind="raw", scratch_path="/scratch/job-1/img.raw", content_store_root="/content/store"
        )
        outcome = run_adapter(plan, lambda req: {"status": "ok", "volumes": []})
        self.assertEqual("ok", outcome["status"])
        self.assertFalse(outcome["hypervisor_started"])
        self.assertFalse(outcome["mount_write"])
        self.assertTrue(outcome["read_only"])

    def test_crash_outcome(self) -> None:
        plan = adapter_plan(
            kind="raw", scratch_path="/scratch/job-1/img.raw", content_store_root="/content/store"
        )

        def broken(req: Any) -> dict[str, Any]:
            raise RuntimeError("boom")

        outcome = run_adapter(plan, broken)
        self.assertEqual("crashed", outcome["status"])

    def test_version_constant(self) -> None:
        self.assertEqual("container-images-v1", CONTAINER_IMAGES_VERSION)


if __name__ == "__main__":
    unittest.main()
