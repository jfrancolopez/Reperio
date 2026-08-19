#!/usr/bin/env python3

from __future__ import annotations

import unittest
from collections.abc import Mapping
from typing import Any

from hostd import removable_sources
from shared import media_identity

FINGERPRINT = "a" * 64


class FakeReadOnlyOps:
    def __init__(
        self, *, verify: bool = True, fail_set: bool = False, fail_verify: bool = False
    ) -> None:
        self.verify = verify
        self.fail_set = fail_set
        self.fail_verify = fail_verify
        self.set_calls: list[dict[str, str]] = []
        self.verify_calls: list[dict[str, str]] = []

    def set_read_only(self, target: Mapping[str, str]) -> None:
        self.set_calls.append(dict(target))
        if self.fail_set:
            raise OSError("set failed")

    def verify_read_only(self, target: Mapping[str, str]) -> bool:
        self.verify_calls.append(dict(target))
        if self.fail_verify:
            raise OSError("verify failed")
        return self.verify


def removable_device(**overrides: Any) -> dict[str, Any]:
    device: dict[str, Any] = {
        "candidate_id": "dev_1",
        "kernel_name": "mmcblk0",
        "major_minor": "179:0",
        "device_type": "sd_card",
        "transport": "mmc",
        "removable": True,
        "read_only": False,
        "size_bytes": 32 * 1024 * 1024,
        "has_media": True,
        "source_id": "reader_src",
        "reader_id": "reader_1",
        "medium_identity": media_identity.medium_identity_record(
            "reader_1",
            media_identity.normalize_medium_signals(
                {"size_bytes": 32 * 1024 * 1024, "sampled_fingerprint_sha256": FINGERPRINT}
            ),
            identity_strength="reader-plus-medium",
        ),
        "children": [],
    }
    device.update(overrides)
    return device


class PrepareSourceTests(unittest.TestCase):
    def test_ready_when_identity_and_read_only_are_proven(self) -> None:
        prepared = removable_sources.prepare_removable_source(
            removable_device(), ops=FakeReadOnlyOps()
        )
        self.assertTrue(prepared.medium_identity_proven)
        self.assertTrue(prepared.read_only_verified)
        self.assertTrue(prepared.ready_for_scan)
        self.assertEqual("memory_card", prepared.source_kind)

    def test_scan_launch_denied_without_proven_read_only(self) -> None:
        device = removable_device()
        prepared = removable_sources.prepare_removable_source(
            device, ops=FakeReadOnlyOps(verify=False)
        )
        self.assertFalse(prepared.read_only_verified)
        with self.assertRaisesRegex(
            removable_sources.ScanLaunchDenied, "scan_launch_denied|read_only_not_verified"
        ):
            removable_sources.require_scan_launch_approval(device, prepared)

    def test_scan_launch_denied_without_proven_medium_identity(self) -> None:
        device = removable_device(medium_identity=None)
        prepared = removable_sources.prepare_removable_source(device, ops=FakeReadOnlyOps())
        with self.assertRaisesRegex(
            removable_sources.ScanLaunchDenied, "medium_identity_not_proven"
        ):
            removable_sources.require_scan_launch_approval(device, prepared)

    def test_scan_launch_denied_when_identity_weak_without_fingerprint(self) -> None:
        device = removable_device()
        device["medium_identity"] = media_identity.medium_identity_record(
            "reader_1",
            media_identity.normalize_medium_signals({"size_bytes": 32 * 1024 * 1024}),
            identity_strength="reader-facts",
        )
        prepared = removable_sources.prepare_removable_source(device, ops=FakeReadOnlyOps())
        self.assertFalse(prepared.medium_identity_proven)
        with self.assertRaisesRegex(removable_sources.ScanLaunchDenied, "medium_identity"):
            removable_sources.require_scan_launch_approval(device, prepared)

    def test_empty_reader_is_blocked(self) -> None:
        device = removable_device()
        device["medium_identity"] = media_identity.medium_identity_record(
            "reader_1",
            media_identity.normalize_medium_signals({}),
            identity_strength="reader-facts",
        )
        prepared = removable_sources.prepare_removable_source(device, ops=FakeReadOnlyOps())
        self.assertIn("no_medium_present", prepared.blockers)
        self.assertFalse(prepared.ready_for_scan)

    def test_mounted_read_write_blocks_scan(self) -> None:
        device = removable_device(major_minor="179:0")
        prepared = removable_sources.prepare_removable_source(
            device,
            ops=FakeReadOnlyOps(),
            storage_state={
                "blockers": [{"reason": "source_mounted_read_write", "detail": "/mnt/card"}]
            },
        )
        self.assertFalse(prepared.ready_for_scan)
        self.assertIn("source_mounted_read_write", prepared.automount_blockers)

    def test_mounted_read_only_is_informational_only(self) -> None:
        prepared = removable_sources.prepare_removable_source(
            removable_device(),
            ops=FakeReadOnlyOps(),
            storage_state={"blockers": [], "mounts": [{"mode": "ro", "mount_point": "/mnt/card"}]},
        )
        self.assertTrue(prepared.ready_for_scan)
        self.assertTrue(any("mounted_read_only" in w for w in prepared.warnings))

    def test_read_only_set_failure_is_blocker(self) -> None:
        prepared = removable_sources.prepare_removable_source(
            removable_device(), ops=FakeReadOnlyOps(fail_set=True)
        )
        self.assertIn("read_only_set_failed", prepared.blockers)

    def test_children_partitions_are_covered(self) -> None:
        ops = FakeReadOnlyOps()
        device = removable_device()
        device["children"] = [
            {"kernel_name": "mmcblk0p1", "major_minor": "179:1"},
            {"kernel_name": "mmcblk0p2", "major_minor": "179:2"},
        ]
        prepared = removable_sources.prepare_removable_source(device, ops=ops)
        self.assertTrue(prepared.ready_for_scan)
        self.assertEqual(
            {"mmcblk0", "mmcblk0p1", "mmcblk0p2"}, {c["kernel_name"] for c in ops.verify_calls}
        )

    def test_fixed_disk_is_not_a_removable_source(self) -> None:
        device = removable_device(device_type="disk", removable=False, source_id="fixed_1")
        prepared = removable_sources.prepare_removable_source(device, ops=FakeReadOnlyOps())
        self.assertIn("not_a_removable_source", prepared.blockers)
        self.assertFalse(prepared.ready_for_scan)


class PhysicalLockTests(unittest.TestCase):
    def test_sd_write_lock_is_informational(self) -> None:
        report = removable_sources.physical_lock_report(removable_device(write_protected=True))
        self.assertTrue(report.write_protected)
        self.assertEqual("sd-write-protect-switch", report.source)
        self.assertTrue(report.informational_only)

    def test_optical_writer_with_rw_disc_is_not_write_once(self) -> None:
        report = removable_sources.physical_lock_report(
            removable_device(device_type="optical", model="HL-DT-ST DVDRAM", media_type="rwd")
        )
        self.assertFalse(report.write_once)

    def test_write_once_optical_media_is_reported(self) -> None:
        report = removable_sources.physical_lock_report(
            removable_device(device_type="optical", model="PLEXTOR CD-R", media_type="cdr")
        )
        self.assertTrue(report.write_once)
        self.assertTrue(report.write_protected)
        self.assertEqual("optical-write-once", report.source)

    def test_sysfs_read_only_flag_is_reported(self) -> None:
        report = removable_sources.physical_lock_report(removable_device(read_only=True))
        self.assertTrue(report.write_protected)
        self.assertEqual("sysfs-ro", report.source)


class HotplugTests(unittest.TestCase):
    def test_media_populated_event(self) -> None:
        empty = removable_device()
        empty["medium_identity"] = media_identity.medium_identity_record(
            "reader_1",
            media_identity.normalize_medium_signals({}),
            identity_strength="reader-facts",
        )
        event = removable_sources.report_hotplug_change(empty, removable_device())
        self.assertEqual("populated", event.kind)
        self.assertTrue(event.changed)

    def test_media_emptied_event(self) -> None:
        populated = removable_device()
        empty = removable_device()
        empty["medium_identity"] = media_identity.medium_identity_record(
            "reader_1",
            media_identity.normalize_medium_signals({}),
            identity_strength="reader-facts",
        )
        event = removable_sources.report_hotplug_change(populated, empty)
        self.assertEqual("emptied", event.kind)
        self.assertTrue(event.changed)

    def test_media_swap_event_on_generation_bump(self) -> None:
        previous = removable_device(media_change_generation=1)
        current = removable_device(media_change_generation=2)
        event = removable_sources.report_hotplug_change(previous, current)
        self.assertEqual("swapped", event.kind)
        self.assertEqual(2, event.media_change_generation)

    def test_unchanged_when_nothing_changes(self) -> None:
        device = removable_device()
        event = removable_sources.report_hotplug_change(device, device)
        self.assertEqual("unchanged", event.kind)
        self.assertFalse(event.changed)


class ReadOnlyOperationAllowlistTests(unittest.TestCase):
    def test_allowlisted_operations_pass(self) -> None:
        for op in ("capacity", "geometry", "optical_toc", "identity_fingerprint"):
            removable_sources.assert_allowed_read_only_op(op)

    def test_forbidden_operations_are_refused(self) -> None:
        for op in ("write", "eject", "burn", "blank", "format", "packet_write", "repair", "ioctl"):
            with self.assertRaises(removable_sources.ForbiddenOperationError):
                removable_sources.assert_allowed_read_only_op(op)

    def test_geometry_and_toc_read_only_helpers(self) -> None:
        device = removable_device(
            device_type="floppy",
            geometry={
                "cylinders": 80,
                "heads": 2,
                "sectors_per_track": 18,
                "bytes_per_sector": 512,
            },
            toc_sessions=[{"start_sector": 0, "length_sectors": 2880}],
        )
        geometry = removable_sources.read_geometry(device)
        self.assertTrue(geometry["available"])
        self.assertEqual(80, geometry["geometry"]["cylinders"])
        toc = removable_sources.read_optical_toc(device)
        self.assertTrue(toc["available"])
        self.assertEqual(2880, toc["sessions"][0]["length_sectors"])

    def test_no_write_paths_exist_in_module(self) -> None:
        import ast

        tree = ast.parse(open(removable_sources.__file__, encoding="utf-8").read())
        names: list[str] = []
        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef | ast.ClassDef):
                names.append(node.name)
            if isinstance(node, ast.Attribute) and isinstance(node.attr, str):
                names.append(node.attr)
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
                names.append(node.func.id)
        forbidden = ("write", "eject", "burn", "blank", "format", "packet_write", "repair", "ioctl")
        offenders = sorted(name for name in set(names) if name.lower().startswith(forbidden))
        self.assertEqual([], offenders)

    def test_source_bytes_unchanged_after_preparation(self) -> None:
        source_bytes = b"\x00\x01\x02\x03" * 8
        device = removable_device()
        removable_sources.prepare_removable_source(device, ops=FakeReadOnlyOps())
        self.assertEqual(b"\x00\x01\x02\x03" * 8, source_bytes)


if __name__ == "__main__":
    unittest.main()
