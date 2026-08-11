#!/usr/bin/env python3

from __future__ import annotations

import errno
import tempfile
import unittest
from pathlib import Path

from hostd import fingerprint


def facts(size: int = 4096, sector_size: int = 512) -> dict:
    return {
        "source_id": "source_abcdefghijklmnop",
        "identity_strength": "by-id",
        "by_id_name": "usb-Reperio_Disk_123",
        "model": "Synthetic",
        "serial": "SERIAL123",
        "transport": "usb",
        "device_type": "usb_storage",
        "size_bytes": size,
        "logical_block_size": sector_size,
        "physical_block_size": sector_size,
    }


def reader_for(data: bytes) -> fingerprint.ReadAt:
    return lambda offset, length: data[offset : offset + length]


class HostdSampledFingerprintTests(unittest.TestCase):
    def test_matching_fixture_produces_same_fingerprint(self) -> None:
        data = bytes(index % 251 for index in range(4096))

        first = fingerprint.fingerprint_from_reader(
            reader_for(data), size_bytes=len(data), sector_size=512, identity_facts=facts()
        )
        second = fingerprint.fingerprint_from_reader(
            reader_for(data), size_bytes=len(data), sector_size=512, identity_facts=facts()
        )

        self.assertEqual(first["fingerprint_hash"], second["fingerprint_hash"])
        self.assertEqual(3, first["sample_count"])
        self.assertNotIn(data[:16].hex(), repr(first))

    def test_one_sector_changed_is_detected(self) -> None:
        original = bytearray(bytes(index % 251 for index in range(4096)))
        changed = bytearray(original)
        changed[2048] ^= 0xFF

        first = fingerprint.fingerprint_from_reader(
            reader_for(bytes(original)), size_bytes=4096, sector_size=512, identity_facts=facts()
        )
        second = fingerprint.fingerprint_from_reader(
            reader_for(bytes(changed)), size_bytes=4096, sector_size=512, identity_facts=facts()
        )

        self.assertNotEqual(first["fingerprint_hash"], second["fingerprint_hash"])

    def test_truncated_sample_is_explicit(self) -> None:
        data = b"A" * 1024

        result = fingerprint.fingerprint_from_reader(
            reader_for(data), size_bytes=4096, sector_size=512, identity_facts=facts()
        )

        statuses = [sample["status"] for sample in result["samples"]]
        self.assertIn("truncated", statuses)
        self.assertEqual(3, result["sample_count"])

    def test_unreadable_sample_is_explicit(self) -> None:
        data = b"A" * 4096

        def read_at(offset: int, length: int) -> bytes:
            if offset == 2048:
                raise OSError(errno.EIO, "synthetic unreadable sector")
            return data[offset : offset + length]

        result = fingerprint.fingerprint_from_reader(
            read_at, size_bytes=4096, sector_size=512, identity_facts=facts()
        )

        unreadable = [sample for sample in result["samples"] if sample["status"] == "unreadable"]
        self.assertEqual(1, len(unreadable))
        self.assertNotIn("synthetic unreadable sector", repr(result))

    def test_sector_size_change_changes_fingerprint(self) -> None:
        data = bytes(index % 251 for index in range(4096))

        first = fingerprint.fingerprint_from_reader(
            reader_for(data), size_bytes=4096, sector_size=512, identity_facts=facts(4096, 512)
        )
        second = fingerprint.fingerprint_from_reader(
            reader_for(data), size_bytes=4096, sector_size=1024, identity_facts=facts(4096, 1024)
        )

        self.assertNotEqual(first["fingerprint_hash"], second["fingerprint_hash"])
        self.assertEqual(1024, second["sector_size"])

    def test_sample_plan_is_bounded(self) -> None:
        plan = fingerprint.sample_plan(size_bytes=10 * 1024 * 1024 * 1024, sector_size=512)

        self.assertLessEqual(len(plan), fingerprint.MAX_SAMPLES)
        self.assertEqual((0, 512), plan[0])

    def test_path_wrapper_opens_read_only_and_hashes_file_fixture(self) -> None:
        data = bytes(index % 251 for index in range(4096))
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "fixture.bin"
            path.write_bytes(data)

            result = fingerprint.fingerprint_path(path, facts(size=len(data)))

        self.assertEqual("ok", result["samples"][0]["status"])
        self.assertEqual(len(data), result["size_bytes"])


if __name__ == "__main__":
    unittest.main()
