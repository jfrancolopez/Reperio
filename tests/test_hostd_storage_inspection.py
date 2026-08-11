#!/usr/bin/env python3

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from hostd import block_devices, identity, storage_inspection
from tests.test_hostd_block_devices import make_disk, make_partition


def source_with_partition(root: Path, name: str = "loop0") -> dict:
    disk = make_disk(root, name, "7:0" if name.startswith("loop") else "8:0", transport="loop")
    make_partition(disk, f"{name}p1" if name.startswith("loop") else f"{name}1", "7:1")
    return identity.attach_stable_identities(
        block_devices.list_block_devices(root), root / "missing"
    )[0]


class HostdStorageInspectionTests(unittest.TestCase):
    def test_loop_device_mounted_read_only_reports_safe_mount(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            source = source_with_partition(Path(tmp))

        result = storage_inspection.inspect_storage_state(
            source,
            mounts=[{"major_minor": "7:1", "mount_point": "/mnt/source", "options": "ro,nosuid"}],
        )

        self.assertTrue(result["safe_for_preparation"])
        self.assertEqual("ro", result["mounts"][0]["mode"])
        self.assertEqual([], result["blockers"])

    def test_loop_device_mounted_read_write_blocks_preparation(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            source = source_with_partition(Path(tmp))

        result = storage_inspection.inspect_storage_state(
            source,
            mounts=[{"major_minor": "7:1", "mount_point": "/mnt/source", "options": "rw,relatime"}],
        )

        self.assertFalse(result["safe_for_preparation"])
        self.assertEqual("source_mounted_read_write", result["blockers"][0]["reason"])

    def test_nested_device_mapper_relationships_are_reported(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            source = source_with_partition(Path(tmp), "sda")

        result = storage_inspection.inspect_storage_state(
            source,
            mounts=[{"major_minor": "253:1", "mount_point": "/mnt/lv", "options": "ro"}],
            holders={
                "7:1": [
                    {"major_minor": "253:0", "holder_type": "device_mapper", "holder_name": "dm-0"}
                ],
                "253:0": [
                    {"major_minor": "253:1", "holder_type": "device_mapper", "holder_name": "dm-1"}
                ],
            },
        )

        self.assertTrue(result["safe_for_preparation"])
        self.assertEqual(
            ["253:0", "253:1"], [holder["major_minor"] for holder in result["holders"]]
        )
        self.assertIn("253:1", result["relationships"])

    def test_unsupported_holder_blocks_preparation(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            source = source_with_partition(Path(tmp))

        result = storage_inspection.inspect_storage_state(
            source,
            holders={
                "7:1": [
                    {
                        "major_minor": "254:0",
                        "holder_type": "unknown_stack",
                        "holder_name": "mystery",
                    }
                ]
            },
        )

        self.assertFalse(result["safe_for_preparation"])
        self.assertEqual("unsupported_holder", result["blockers"][0]["reason"])

    def test_disappearing_mount_race_is_ignored_without_crashing(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            source = source_with_partition(Path(tmp))

        result = storage_inspection.inspect_storage_state(
            source,
            mounts=[
                {"mount_point": "/vanished", "options": "rw"},
                {"major_minor": "not-a-device", "mount_point": "/bad", "options": "rw"},
            ],
            holders={"bad": [{"major_minor": "253:0"}]},
        )

        self.assertTrue(result["safe_for_preparation"])
        self.assertEqual([], result["mounts"])
        self.assertEqual([], result["holders"])

    def test_mdraid_holder_is_supported_and_reported(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            source = source_with_partition(Path(tmp))

        result = storage_inspection.inspect_storage_state(
            source,
            holders={
                "7:1": [{"major_minor": "9:0", "holder_type": "mdraid", "holder_name": "md0"}]
            },
        )

        self.assertTrue(result["safe_for_preparation"])
        self.assertEqual("mdraid", result["holders"][0]["holder_type"])


if __name__ == "__main__":
    unittest.main()
