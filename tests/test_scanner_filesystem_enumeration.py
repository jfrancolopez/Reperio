from __future__ import annotations

import unittest
from pathlib import Path

from scanner import filesystem_enumeration, partition_discovery

NTFS_FSSTAT = """
FILE SYSTEM INFORMATION
--------------------------------------------
File System Type: NTFS
Volume Serial Number: omitted
"""

FAT_FSSTAT = """
FILE SYSTEM INFORMATION
--------------------------------------------
File System Type: FAT32
"""

EXFAT_FSSTAT = """
FILE SYSTEM INFORMATION
--------------------------------------------
File System Type: ExFAT
"""

FLS_OUTPUT = """
d/- 5: Documents
r/- 6: Documents/report.txt
r/* 7: deleted.bin
"""


class FakeRunner:
    def __init__(
        self,
        fsstat: filesystem_enumeration.TskCommandResult,
        fls: filesystem_enumeration.TskCommandResult,
    ) -> None:
        self.fsstat = fsstat
        self.fls = fls
        self.calls: list[tuple[str, tuple[str, ...], int]] = []

    def run_fsstat(
        self, args: tuple[str, ...], timeout_seconds: int
    ) -> filesystem_enumeration.TskCommandResult:
        self.calls.append(("fsstat", args, timeout_seconds))
        return self.fsstat

    def run_fls(
        self, args: tuple[str, ...], timeout_seconds: int
    ) -> filesystem_enumeration.TskCommandResult:
        self.calls.append(("fls", args, timeout_seconds))
        return self.fls


class ScannerFilesystemEnumerationTests(unittest.TestCase):
    def test_ntfs_fixture_identifies_volume_and_stable_entry_ids(self) -> None:
        runner = FakeRunner(
            filesystem_enumeration.TskCommandResult(0, NTFS_FSSTAT, ""),
            filesystem_enumeration.TskCommandResult(0, FLS_OUTPUT, ""),
        )

        result = filesystem_enumeration.enumerate_filesystem(
            Path("/dev/reperio-source"),
            partition(),
            source_id="source_1",
            runner=runner,
            timeout_seconds=9,
        )

        self.assertEqual("ntfs", result.volume.filesystem)
        self.assertTrue(result.volume.supported)
        self.assertEqual("entry-vol-source_1-2048-8192-6", result.entries[1].entry_id)
        self.assertEqual("5", result.entries[1].parent_object_id)
        self.assertFalse(result.entries[2].allocated)
        self.assertEqual(
            [
                (
                    "fsstat",
                    ("fsstat", "-o", "2048", "/dev/reperio-source"),
                    9,
                ),
                (
                    "fls",
                    ("fls", "-r", "-p", "-o", "2048", "/dev/reperio-source"),
                    9,
                ),
            ],
            runner.calls,
        )

    def test_fat_fixture_is_supported(self) -> None:
        volume = filesystem_enumeration.identify_volume(
            FAT_FSSTAT, "", 0, source_id="source_1", partition=partition()
        )

        self.assertEqual("fat32", volume.filesystem)
        self.assertTrue(volume.supported)

    def test_exfat_fixture_is_supported(self) -> None:
        volume = filesystem_enumeration.identify_volume(
            EXFAT_FSSTAT, "", 0, source_id="source_1", partition=partition()
        )

        self.assertEqual("exfat", volume.filesystem)
        self.assertTrue(volume.supported)

    def test_unsupported_volume_skips_entry_enumeration(self) -> None:
        runner = FakeRunner(
            filesystem_enumeration.TskCommandResult(0, "File System Type: HFS+\n", ""),
            filesystem_enumeration.TskCommandResult(0, FLS_OUTPUT, ""),
        )

        result = filesystem_enumeration.enumerate_filesystem(
            Path("/dev/reperio-source"), partition(), source_id="source_1", runner=runner
        )

        self.assertEqual("hfs", result.volume.filesystem)
        self.assertFalse(result.volume.supported)
        self.assertEqual((), result.entries)
        self.assertEqual(1, len(runner.calls))
        self.assertIn("filesystem_unsupported:hfs", result.warnings)

    def test_corrupt_volume_normalizes_exit_stderr_and_partial_entries(self) -> None:
        entries, warnings = filesystem_enumeration.parse_fls_output(
            FLS_OUTPUT + "not parseable\n",
            "bad cluster chain\x00details",
            1,
            volume_id="vol-source_1-2048-8192",
            batch_size=10,
        )

        self.assertEqual(3, len(entries))
        self.assertIn("fls_unparsed_line", warnings)
        self.assertIn("fls_exit:1", warnings)
        self.assertIn("fls_stderr:bad cluster chain details", warnings)

    def test_entry_batches_are_bounded_and_warn_when_truncated(self) -> None:
        entries, warnings = filesystem_enumeration.parse_fls_output(
            FLS_OUTPUT,
            "",
            0,
            volume_id="vol-source_1-2048-8192",
            batch_size=2,
        )

        self.assertEqual(2, len(entries))
        self.assertIn("fls_batch_truncated", warnings)

    def test_mount_repair_or_write_command_surface_is_refused(self) -> None:
        with self.assertRaises(filesystem_enumeration.FilesystemEnumerationError) as captured:
            filesystem_enumeration.enumerate_filesystem(
                Path("/dev/reperio-source"),
                partition(),
                source_id="source_1",
                runner=FakeRunner(
                    filesystem_enumeration.TskCommandResult(0, NTFS_FSSTAT, ""),
                    filesystem_enumeration.TskCommandResult(0, FLS_OUTPUT, ""),
                ),
                fsstat_binary="mount",
            )

        self.assertEqual("unsafe_filesystem_command", captured.exception.code)

    def test_noncanonical_tool_paths_and_invalid_limits_are_rejected(self) -> None:
        with self.assertRaisesRegex(
            filesystem_enumeration.FilesystemEnumerationError, "unexpected filesystem tool"
        ):
            filesystem_enumeration.enumerate_filesystem(
                Path("/dev/reperio-source"),
                partition(),
                source_id="source_1",
                runner=FakeRunner(
                    filesystem_enumeration.TskCommandResult(0, NTFS_FSSTAT, ""),
                    filesystem_enumeration.TskCommandResult(0, FLS_OUTPUT, ""),
                ),
                fsstat_binary="/tmp/fsstat",
            )

        with self.assertRaisesRegex(filesystem_enumeration.FilesystemEnumerationError, "timeout"):
            filesystem_enumeration.enumerate_filesystem(
                Path("/dev/reperio-source"),
                partition(),
                source_id="source_1",
                runner=FakeRunner(
                    filesystem_enumeration.TskCommandResult(0, NTFS_FSSTAT, ""),
                    filesystem_enumeration.TskCommandResult(0, FLS_OUTPUT, ""),
                ),
                timeout_seconds=0,
            )


def partition() -> partition_discovery.PartitionEntry:
    return partition_discovery.PartitionEntry(
        slot="002:",
        offset_bytes=2048 * 512,
        length_bytes=8192 * 512,
        start_sector=2048,
        end_sector=10239,
        sector_count=8192,
        description="Basic data partition (DATA)",
        partition_type="Basic data partition",
        label="DATA",
        allocated=True,
    )


if __name__ == "__main__":
    unittest.main()
