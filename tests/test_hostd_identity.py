#!/usr/bin/env python3

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from hostd import block_devices, identity
from tests.test_hostd_block_devices import make_disk, make_partition


def link_by_id(root: Path, name: str, kernel_name: str) -> None:
    by_id = root / "by-id"
    by_id.mkdir(parents=True, exist_ok=True)
    (by_id / name).symlink_to(Path("..") / ".." / kernel_name)


class HostdStableIdentityTests(unittest.TestCase):
    def test_by_id_identity_survives_kernel_rename(self) -> None:
        with tempfile.TemporaryDirectory() as first, tempfile.TemporaryDirectory() as second:
            first_root = Path(first)
            second_root = Path(second)
            make_disk(first_root / "sys", "sda", "8:0", transport="usb", model="USB Disk")
            make_disk(second_root / "sys", "sdb", "8:16", transport="usb", model="USB Disk")
            link_by_id(first_root / "dev", "usb-Reperio_Disk_123", "sda")
            link_by_id(second_root / "dev", "usb-Reperio_Disk_123", "sdb")

            first_devices = identity.attach_stable_identities(
                block_devices.list_block_devices(first_root / "sys"), first_root / "dev" / "by-id"
            )
            second_devices = identity.attach_stable_identities(
                block_devices.list_block_devices(second_root / "sys"), second_root / "dev" / "by-id"
            )

        self.assertEqual(first_devices[0]["source_id"], second_devices[0]["source_id"])
        self.assertEqual("by-id", first_devices[0]["identity_strength"])
        self.assertEqual("usb-Reperio_Disk_123", first_devices[0]["by_id_name"])

    def test_serial_facts_are_used_without_by_id(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            disk = make_disk(root / "sys", "sda", "8:0", transport="sata", model="SSD")
            (disk / "device" / "serial").write_text("SERIAL123\n", encoding="utf-8")

            devices = identity.attach_stable_identities(
                block_devices.list_block_devices(root / "sys"), root / "missing-by-id"
            )

        self.assertEqual("serial-facts", devices[0]["identity_strength"])
        self.assertNotIn("missing_stable_serial_or_by_id", devices[0]["identity_warnings"])

    def test_missing_serial_uses_weaker_identity_with_warning(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            make_disk(root / "sys", "sda", "8:0", transport="sata", model="No Serial")

            devices = identity.attach_stable_identities(
                block_devices.list_block_devices(root / "sys"), root / "missing-by-id"
            )

        self.assertEqual("weak-facts", devices[0]["identity_strength"])
        self.assertIn("missing_stable_serial_or_by_id", devices[0]["identity_warnings"])
        self.assertNotIn("sda", devices[0]["source_id"])

    def test_partition_identity_is_bound_to_parent_topology(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            disk = make_disk(root / "sys", "sda", "8:0", transport="usb")
            make_partition(disk, "sda1", "8:1", start=2048)
            link_by_id(root / "dev", "usb-Reperio_Disk_123", "sda")

            devices = identity.attach_stable_identities(
                block_devices.list_block_devices(root / "sys"), root / "dev" / "by-id"
            )

        child = devices[0]["children"][0]
        self.assertEqual(devices[0]["source_id"], child["parent_source_id"])
        self.assertEqual("parent-topology", child["identity_strength"])
        self.assertNotEqual(devices[0]["source_id"], child["source_id"])

    def test_collision_cases_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            make_disk(root / "sys", "sda", "8:0", size=4096, model="Same")
            make_disk(root / "sys", "sdb", "8:16", size=4096, model="Same")

            devices = block_devices.list_block_devices(root / "sys")

            with self.assertRaisesRegex(identity.IdentityCollisionError, "collision"):
                identity.attach_stable_identities(devices, root / "missing-by-id")

    def test_by_id_output_does_not_include_mutable_device_path(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            make_disk(root / "sys", "sda", "8:0", transport="usb")
            link_by_id(root / "dev", "usb-Reperio_Disk_123", "sda")

            devices = identity.attach_stable_identities(
                block_devices.list_block_devices(root / "sys"), root / "dev" / "by-id"
            )

        encoded = repr(devices)
        self.assertNotIn("/dev/", encoded)
        self.assertNotIn(str(root), encoded)


if __name__ == "__main__":
    unittest.main()
