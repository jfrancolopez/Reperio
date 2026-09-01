#!/usr/bin/env python3

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest import mock

from hostd import block_devices


def write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def make_disk(
    root: Path,
    name: str,
    major_minor: str,
    *,
    size: int = 2048,
    removable: bool = False,
    read_only: bool = False,
    transport: str | None = None,
    model: str | None = None,
) -> Path:
    disk = root / name
    disk.mkdir(parents=True)
    write(disk / "dev", major_minor)
    write(disk / "size", str(size))
    write(disk / "removable", "1" if removable else "0")
    write(disk / "ro", "1" if read_only else "0")
    write(disk / "queue" / "logical_block_size", "512")
    write(disk / "queue" / "physical_block_size", "4096")
    if transport is not None:
        write(disk / "device" / "transport", transport)
    if model is not None:
        write(disk / "device" / "model", model)
    return disk


def make_partition(disk: Path, name: str, major_minor: str, *, start: int = 2048) -> None:
    part = disk / name
    part.mkdir()
    write(part / "partition", "1")
    write(part / "dev", major_minor)
    write(part / "start", str(start))
    write(part / "size", "4096")


class HostdBlockDeviceEnumerationTests(unittest.TestCase):
    def test_enumerates_whole_disk_and_partition_relationship(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            disk = make_disk(root, "sda", "8:0", transport="sata", model=" Test Disk \n")
            make_partition(disk, "sda1", "8:1")

            devices = block_devices.list_block_devices(root)

        self.assertEqual(1, len(devices))
        self.assertEqual("whole_disk", devices[0]["kind"])
        self.assertEqual("disk", devices[0]["device_type"])
        self.assertEqual("sata", devices[0]["transport"])
        self.assertEqual("Test Disk", devices[0]["model"])
        self.assertEqual(1, len(devices[0]["children"]))
        self.assertEqual("partition", devices[0]["children"][0]["kind"])
        self.assertEqual(
            devices[0]["candidate_id"], devices[0]["children"][0]["parent_candidate_id"]
        )

    def test_represents_required_device_classes(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            make_disk(root, "loop0", "7:0", transport="loop")
            make_disk(root, "sdb", "8:16", removable=True, transport="usb")
            make_disk(root, "nvme0n1", "259:0")
            make_disk(root, "mmcblk0", "179:0", removable=True)
            make_disk(root, "sr0", "11:0", removable=True, read_only=True, size=0)
            make_disk(root, "fd0", "2:0", removable=True, size=2880)
            make_disk(root, "dm-0", "253:0")

            devices = block_devices.list_block_devices(root)

        by_name = {device["kernel_name"]: device for device in devices}
        self.assertEqual("loop", by_name["loop0"]["device_type"])
        self.assertEqual("usb_storage", by_name["sdb"]["device_type"])
        self.assertEqual("nvme", by_name["nvme0n1"]["device_type"])
        self.assertEqual("sd_card", by_name["mmcblk0"]["device_type"])
        self.assertEqual("optical", by_name["sr0"]["device_type"])
        self.assertEqual("floppy", by_name["fd0"]["device_type"])
        self.assertEqual("device_mapper", by_name["dm-0"]["device_type"])
        self.assertIn("empty_or_unreadable_removable_reader", by_name["sr0"]["warnings"])

    def test_disappearing_and_malformed_entries_do_not_crash_listing(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            make_disk(root, "sda", "8:0")
            (root / "vanished").mkdir()
            write(root / "bad/name" / "dev", "1:1")

            devices = block_devices.list_block_devices(root)

        self.assertEqual(["sda"], [device["kernel_name"] for device in devices])

    def test_device_disappearing_during_read_is_skipped(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            make_disk(root, "sda", "8:0")
            make_disk(root, "sdb", "8:16")
            original = block_devices._read_device

            def read_or_disappear(path: Path) -> dict | None:
                if path.name == "sdb":
                    raise FileNotFoundError(path)
                return original(path)

            with mock.patch.object(block_devices, "_read_device", side_effect=read_or_disappear):
                devices = block_devices.list_block_devices(root)

        self.assertEqual(["sda"], [device["kernel_name"] for device in devices])

    def test_unsafe_identifiers_and_invalid_geometry_are_sanitized(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            make_disk(root, "sda", "../../8:0")
            valid = make_disk(root, "sdb", "8:16")
            write(valid / "size", "-1")
            write(valid / "queue" / "logical_block_size", "0")
            write(valid / "queue" / "physical_block_size", "not-a-number")
            make_disk(root, "bad name", "9:0")

            devices = block_devices.list_block_devices(root)

        self.assertEqual(["sdb"], [device["kernel_name"] for device in devices])
        self.assertEqual("8:16", devices[0]["major_minor"])
        self.assertEqual(0, devices[0]["size_bytes"])
        self.assertEqual(512, devices[0]["logical_block_size"])
        self.assertEqual(512, devices[0]["physical_block_size"])

    @unittest.skipUnless(Path("/sys/block").is_dir(), "Linux sysfs is unavailable")
    def test_live_linux_sysfs_enumeration_is_unprivileged_and_sanitized(self) -> None:
        devices = block_devices.list_block_devices()

        for device in devices:
            self.assertRegex(device["kernel_name"], block_devices.KERNEL_NAME_RE)
            self.assertRegex(device["major_minor"], block_devices.MAJOR_MINOR_RE)
            self.assertGreaterEqual(device["size_bytes"], 0)
            self.assertNotIn("/dev/", repr(device))

    def test_missing_sysfs_root_returns_empty_list(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            devices = block_devices.list_block_devices(Path(tmp) / "missing")

        self.assertEqual([], devices)

    def test_facts_are_sanitized_and_do_not_include_device_paths(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            make_disk(root, "sda", "8:0", model="Disk\x00 Model")

            devices = block_devices.list_block_devices(root)

        self.assertEqual("Disk Model", devices[0]["model"])
        encoded = repr(devices)
        self.assertNotIn("/dev/", encoded)
        self.assertNotIn(str(root), encoded)


if __name__ == "__main__":
    unittest.main()
