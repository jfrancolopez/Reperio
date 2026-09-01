#!/usr/bin/env python3

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from hostd import block_devices, identity, storage_inspection
from tests.test_hostd_block_devices import make_disk, make_partition, write


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
        self.assertEqual("partition", result["relationship_edges"][0]["relationship_type"])

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

    def test_conflicting_holder_facts_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            source = source_with_partition(Path(tmp))

        result = storage_inspection.inspect_storage_state(
            source,
            holders={
                "7:1": [
                    {
                        "major_minor": "253:0",
                        "holder_type": "device_mapper",
                        "holder_name": "dm-0",
                    },
                    {
                        "major_minor": "253:0",
                        "holder_type": "unknown_stack",
                        "holder_name": "other",
                    },
                ]
            },
        )

        self.assertFalse(result["safe_for_preparation"])
        self.assertEqual("unsupported", result["holders"][0]["holder_type"])

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

    def test_missing_source_topology_fails_closed(self) -> None:
        result = storage_inspection.inspect_storage_state({"source_id": "source_unknown"})

        self.assertFalse(result["safe_for_preparation"])
        self.assertEqual("missing_source_topology", result["blockers"][0]["reason"])

    def test_conflicting_mount_mode_fails_closed_as_read_write(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            source = source_with_partition(Path(tmp))

        result = storage_inspection.inspect_storage_state(
            source,
            mounts=[
                {
                    "major_minor": "7:1",
                    "mount_point": "/mnt/source",
                    "read_only": True,
                    "options": "rw,relatime",
                }
            ],
        )

        self.assertFalse(result["safe_for_preparation"])
        self.assertEqual("rw", result["mounts"][0]["mode"])

    def test_live_collector_reads_mountinfo_and_nested_sysfs_holders(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = source_with_partition(root / "block")
            mountinfo = root / "mountinfo"
            mountinfo.write_text(
                "36 25 0:32 / /run rw,nosuid - tmpfs tmpfs rw\n"
                "37 25 253:1 / /mnt/source\\040copy ro,nosuid - ext4 /dev/dm-1 ro\n",
                encoding="utf-8",
            )
            write(root / "sys" / "7:1" / "holders" / "dm-0" / "dev", "253:0")
            write(root / "sys" / "253:0" / "holders" / "dm-1" / "dev", "253:1")

            result = storage_inspection.inspect_live_storage_state(
                source, mountinfo_path=mountinfo, sys_dev_block=root / "sys"
            )

        self.assertTrue(result["safe_for_preparation"])
        self.assertEqual("/mnt/source copy", result["mounts"][0]["mount_point"])
        self.assertEqual(["253:0", "253:1"], [item["major_minor"] for item in result["holders"]])
        self.assertEqual(
            ["device_mapper", "device_mapper"],
            [item["relationship_type"] for item in result["relationship_edges"][1:]],
        )

    def test_live_collector_ignores_disappearing_or_malformed_kernel_facts(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = source_with_partition(root / "block")
            (root / "mountinfo").write_text("", encoding="utf-8")
            write(root / "sys" / "7:1" / "holders" / "vanished" / "dev", "bad")

            result = storage_inspection.inspect_live_storage_state(
                source,
                mountinfo_path=root / "mountinfo",
                sys_dev_block=root / "sys",
            )

        self.assertTrue(result["safe_for_preparation"])
        self.assertEqual([], result["holders"])

    def test_live_collector_failure_cannot_claim_safe(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = source_with_partition(root / "block")

            result = storage_inspection.inspect_live_storage_state(
                source,
                mountinfo_path=root / "missing-mountinfo",
                sys_dev_block=root / "missing-sysfs",
            )

        self.assertFalse(result["safe_for_preparation"])
        self.assertFalse(result["inspection_complete"])
        self.assertEqual("storage_inspection_unavailable", result["blockers"][0]["reason"])


if __name__ == "__main__":
    unittest.main()
