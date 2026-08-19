#!/usr/bin/env python3

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from hostd import block_devices, identity
from shared import media_identity
from tests.test_hostd_block_devices import make_disk

FINGERPRINT_ONE = "a" * 64
FINGERPRINT_TWO = "b" * 64


def removable_disk(
    root: Path,
    name: str,
    major_minor: str,
    *,
    transport: str,
    size: int = 2048,
    model: str | None = None,
    read_only: bool = True,
) -> Path:
    return make_disk(
        root / "sys",
        name,
        major_minor,
        size=size,
        removable=True,
        read_only=read_only,
        transport=transport,
        model=model,
    )


def identified(root: Path, devices: list[dict], fingerprint: str | None) -> list[dict]:
    for device in devices:
        if fingerprint is not None:
            device["sampled_fingerprint_sha256"] = fingerprint
    return identity.attach_stable_identities(devices, root / "missing-by-id")


class SharedMediaIdentityContractTests(unittest.TestCase):
    def test_schema_version_is_stable(self) -> None:
        self.assertEqual(1, media_identity.MEDIA_IDENTITY_SCHEMA_VERSION)

    def test_source_kind_classification(self) -> None:
        cases = [
            ({"device_type": "disk", "removable": False}, "fixed_disk"),
            ({"device_type": "usb_storage", "removable": True}, "usb_flash"),
            ({"device_type": "sd_card", "removable": True}, "memory_card"),
            ({"device_type": "optical", "removable": True}, "optical_disc"),
            ({"device_type": "floppy", "removable": True}, "floppy_media"),
            ({"device_type": "block", "removable": True}, "legacy_medium"),
        ]
        for device, expected in cases:
            with self.subTest(device=device):
                self.assertEqual(expected, media_identity.source_kind_for_device(device))

    def test_reader_kind_classification(self) -> None:
        self.assertEqual(
            "optical_drive", media_identity.reader_kind_for_device({"device_type": "optical"})
        )
        self.assertEqual(
            "floppy_drive", media_identity.reader_kind_for_device({"device_type": "floppy"})
        )
        self.assertEqual(
            "card_reader", media_identity.reader_kind_for_device({"device_type": "sd_card"})
        )
        self.assertEqual(
            "card_reader", media_identity.reader_kind_for_device({"device_type": "usb_storage"})
        )
        self.assertEqual(
            "fixed_reader", media_identity.reader_kind_for_device({"device_type": "disk"})
        )

    def test_identity_record_validation(self) -> None:
        signals = {
            "capacity_bytes": 1048576,
            "logical_block_size": 512,
            "physical_block_size": 512,
            "geometry": None,
            "toc_sessions": [{"start_sector": 0, "length_sectors": 2048}],
            "sampled_fingerprint_sha256": FINGERPRINT_ONE,
            "media_change_generation": 3,
        }
        record = media_identity.medium_identity_record(
            "reader_abc", signals, identity_strength="reader-plus-medium"
        )
        result = media_identity.validate_media_identity(record)
        self.assertTrue(result.valid, result.warnings)

    def test_identity_record_rejects_bad_reader_id(self) -> None:
        record = media_identity.medium_identity_record(
            "not-a-reader",
            media_identity.normalize_medium_signals({"removable": True}),
            identity_strength="reader-facts",
        )
        result = media_identity.validate_media_identity(record)
        self.assertFalse(result.valid)
        self.assertIn("invalid_reader_id", result.warnings)

    def test_unsupported_schema_version_is_invalid(self) -> None:
        record = media_identity.medium_identity_record(
            "reader_abc",
            media_identity.normalize_medium_signals({"removable": True}),
            identity_strength="reader-facts",
        )
        record["schema_version"] = 2
        self.assertFalse(media_identity.validate_media_identity(record).valid)

    def test_empty_reader_is_not_a_plausible_medium(self) -> None:
        signals = media_identity.normalize_medium_signals(
            {"removable": True, "size_bytes": 0, "device_type": "optical"}
        )
        record = media_identity.medium_identity_record(
            "reader_abc", signals, identity_strength="reader-facts"
        )
        self.assertFalse(record["has_medium"])
        self.assertIn(
            "no_medium_present",
            media_identity.identity_warnings_for(
                {"removable": True, "device_type": "optical"}, signals
            ),
        )

    def test_warnings_for_missing_fingerprint_and_toc(self) -> None:
        signals = media_identity.normalize_medium_signals(
            {"removable": True, "device_type": "floppy", "size_bytes": 1474560}
        )
        warnings = media_identity.identity_warnings_for(
            {"removable": True, "device_type": "floppy"}, signals
        )
        self.assertIn("missing_sampled_fingerprint", warnings)
        self.assertIn("missing_toc_or_geometry", warnings)

    def test_unreadable_fingerprint_warning(self) -> None:
        signals = media_identity.normalize_medium_signals(
            {"removable": True, "device_type": "optical", "size_bytes": 1048576}
        )
        warnings = media_identity.identity_warnings_for(
            {"removable": True, "device_type": "optical", "fingerprint_unreadable": True},
            signals,
        )
        self.assertIn("unreadable_fingerprint_sample", warnings)


class HostdRemovableMediaIdentityTests(unittest.TestCase):
    def test_stable_usb_serial_reader_identity(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            disk = removable_disk(root, "sdb", "8:16", transport="usb", model="USB Stick")
            (disk / "device" / "serial").write_text("STICK123\n", encoding="utf-8")

            devices = identified(
                root, block_devices.list_block_devices(root / "sys"), FINGERPRINT_ONE
            )
            device = devices[0]

        self.assertEqual("serial-facts", device["reader_identity_strength"])
        self.assertTrue(device["source_id"].startswith("medium_"))
        self.assertTrue(device["reader_id"].startswith("source_"))
        self.assertNotIn("sdb", device["source_id"])
        self.assertNotIn("sdb", device["reader_id"])

    def test_sd_card_without_serial_uses_weak_reader_with_warning(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            removable_disk(root, "mmcblk0", "179:0", transport="mmc", model="CardReader")

            devices = identified(
                root, block_devices.list_block_devices(root / "sys"), FINGERPRINT_ONE
            )

        device = devices[0]
        self.assertEqual("weak-facts", device["reader_identity_strength"])
        self.assertIn("missing_stable_serial_or_by_id", device["identity_warnings"])
        self.assertEqual("reader-plus-medium", device["identity_strength"])

    def test_two_same_size_cards_in_same_reader_are_distinct(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            removable_disk(root, "mmcblk0", "179:0", transport="mmc", model="CardReader", size=8192)

            first = identified(
                root, block_devices.list_block_devices(root / "sys"), FINGERPRINT_ONE
            )
            second = identified(
                root, block_devices.list_block_devices(root / "sys"), FINGERPRINT_TWO
            )

        self.assertEqual(first[0]["reader_id"], second[0]["reader_id"])
        self.assertNotEqual(first[0]["source_id"], second[0]["source_id"])

    def test_optical_disc_swap_in_one_drive_is_distinct(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            removable_disk(
                root, "sr0", "11:0", transport="sata", model="DVD Writer", size=4700372992
            )

            disc_one = list(block_devices.list_block_devices(root / "sys"))
            disc_one[0]["toc_sessions"] = [{"start_sector": 0, "length_sectors": 9175040}]
            disc_one = identified(root, disc_one, FINGERPRINT_ONE)

            disc_two = list(block_devices.list_block_devices(root / "sys"))
            disc_two[0]["toc_sessions"] = [{"start_sector": 0, "length_sectors": 9175040}]
            disc_two = identified(root, disc_two, FINGERPRINT_TWO)

        self.assertEqual(disc_one[0]["reader_id"], disc_two[0]["reader_id"])
        self.assertNotEqual(disc_one[0]["source_id"], disc_two[0]["source_id"])
        self.assertIn("optical_disc", media_identity.source_kind_for_device(disc_one[0]))

    def test_optical_changed_toc_is_distinct_medium(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            removable_disk(
                root, "sr0", "11:0", transport="sata", model="DVD Writer", size=4700372992
            )

            before = list(block_devices.list_block_devices(root / "sys"))
            before[0]["toc_sessions"] = [{"start_sector": 0, "length_sectors": 9175040}]
            before = identified(root, before, FINGERPRINT_ONE)

            after = list(block_devices.list_block_devices(root / "sys"))
            after[0]["toc_sessions"] = [
                {"start_sector": 0, "length_sectors": 9175040},
                {"start_sector": 9175040, "length_sectors": 100000},
            ]
            after = identified(root, after, FINGERPRINT_ONE)

        self.assertNotEqual(before[0]["source_id"], after[0]["source_id"])

    def test_floppy_swap_in_one_drive_is_distinct(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            removable_disk(root, "fd0", "2:0", transport="sata", model="Floppy Drive", size=1474560)

            first = identified(
                root, block_devices.list_block_devices(root / "sys"), FINGERPRINT_ONE
            )
            second = identified(
                root, block_devices.list_block_devices(root / "sys"), FINGERPRINT_TWO
            )

        self.assertEqual(first[0]["reader_id"], second[0]["reader_id"])
        self.assertNotEqual(first[0]["source_id"], second[0]["source_id"])

    def test_empty_reader_has_no_plausible_medium(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            removable_disk(root, "sr0", "11:0", transport="sata", model="DVD Writer", size=0)

            devices = identified(root, block_devices.list_block_devices(root / "sys"), None)

        device = devices[0]
        self.assertFalse(device["medium_identity"]["has_medium"])
        self.assertIn("no_medium_present", device["identity_warnings"])

    def test_unreadable_fingerprint_sample_yields_weak_identity(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            removable_disk(root, "mmcblk0", "179:0", transport="mmc", model="CardReader")

            devices = list(block_devices.list_block_devices(root / "sys"))
            devices[0]["fingerprint_unreadable"] = True
            devices = identified(root, devices, None)

        device = devices[0]
        self.assertEqual("reader-facts", device["identity_strength"])
        self.assertIn("unreadable_fingerprint_sample", device["identity_warnings"])

    def test_kernel_name_is_never_identity_for_removable(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            removable_disk(root, "sr0", "11:0", transport="sata", model="DVD Writer")

            devices = identified(
                root, block_devices.list_block_devices(root / "sys"), FINGERPRINT_ONE
            )

        encoded = repr(devices)
        self.assertNotIn("/dev/", encoded)
        self.assertNotIn("sr0", devices[0]["source_id"])
        self.assertNotIn("sr0", devices[0]["reader_id"])

    def test_partition_child_binds_to_medium_identity(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            disk = removable_disk(root, "sdb", "8:16", transport="usb", model="USB Stick")
            from tests.test_hostd_block_devices import make_partition

            make_partition(disk, "sdb1", "8:17", start=2048)
            devices = identified(
                root, block_devices.list_block_devices(root / "sys"), FINGERPRINT_ONE
            )

        parent = devices[0]
        child = parent["children"][0]
        self.assertTrue(parent["source_id"].startswith("medium_"))
        self.assertEqual(parent["source_id"], child["parent_source_id"])


if __name__ == "__main__":
    unittest.main()
