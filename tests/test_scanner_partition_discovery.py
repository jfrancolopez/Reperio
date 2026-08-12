from __future__ import annotations

import unittest
from pathlib import Path

from scanner import partition_discovery

GPT_OUTPUT = """
DOS Partition Table
Offset Sector: 0
Units are in 512-byte sectors

      Slot      Start        End          Length       Description
000:  Meta      0000000000   0000000000   0000000001   Safety Table
001:  -----     0000000000   0000000033   0000000034   Unallocated
002:  Meta      0000000034   0000002047   0000002014   GPT Header
003:  Meta      0000002048   0000010239   0000008192   Basic data partition (DATA)
""".replace("DOS Partition Table", "Partition Table: GUID Partition Table")

MBR_OUTPUT = """
Partition Table: DOS Partition Table
Offset Sector: 0
Units are in 512-byte sectors

      Slot      Start        End          Length       Description
000:  Meta      0000000000   0000000000   0000000001   Primary Table (#0)
001:  -----     0000000000   0000000062   0000000063   Unallocated
002:  Meta      0000000063   0000002047   0000001985   NTFS / exFAT (0x07)
"""

EXTENDED_OUTPUT = """
Partition Table: DOS Partition Table
Offset Sector: 0
Units are in 512-byte sectors

      Slot      Start        End          Length       Description
000:  Meta      0000002048   0000004095   0000002048   DOS Extended (0x05)
001:  Meta      0000004096   0000008191   0000004096   Linux (0x83)
"""


class FakeRunner:
    def __init__(self, result: partition_discovery.TskCommandResult) -> None:
        self.result = result
        self.calls: list[tuple[tuple[str, ...], int]] = []

    def run_mmls(
        self, args: tuple[str, ...], timeout_seconds: int
    ) -> partition_discovery.TskCommandResult:
        self.calls.append((args, timeout_seconds))
        return self.result


class ScannerPartitionDiscoveryTests(unittest.TestCase):
    def test_gpt_partitions_are_normalized_with_byte_offsets(self) -> None:
        result = partition_discovery.parse_mmls_output(
            GPT_OUTPUT, "", 0, source_id="source_1", sector_size=512
        )

        self.assertEqual("GUID Partition Table", result.table_type)
        data = result.partitions[-1]
        self.assertEqual(2048 * 512, data.offset_bytes)
        self.assertEqual(8192 * 512, data.length_bytes)
        self.assertEqual("Basic data partition", data.partition_type)
        self.assertEqual("DATA", data.label)
        self.assertTrue(data.allocated)

    def test_mbr_partition_type_and_unallocated_status_are_preserved(self) -> None:
        result = partition_discovery.parse_mmls_output(
            MBR_OUTPUT, "", 0, source_id="source_1", sector_size=512
        )

        self.assertEqual("DOS Partition Table", result.table_type)
        self.assertFalse(result.partitions[0].allocated)
        self.assertFalse(result.partitions[1].allocated)
        self.assertEqual("NTFS / exFAT", result.partitions[2].partition_type)
        self.assertEqual("0x07", result.partitions[2].label)

    def test_hybrid_overlap_is_reportable_without_crashing(self) -> None:
        output = MBR_OUTPUT + "003:  Meta      0000001024   0000003071   0000002048   HFS (0xaf)\n"

        result = partition_discovery.parse_mmls_output(
            output, "", 0, source_id="source_1", sector_size=512
        )

        self.assertIn("overlapping_partitions", result.warnings)

    def test_extended_entries_are_kept_as_distinct_partitions(self) -> None:
        result = partition_discovery.parse_mmls_output(
            EXTENDED_OUTPUT, "", 0, source_id="source_1", sector_size=512
        )

        self.assertEqual(2, len(result.partitions))
        self.assertEqual("DOS Extended", result.partitions[0].partition_type)
        self.assertEqual("Linux", result.partitions[1].partition_type)

    def test_corrupt_gpt_exit_and_stderr_are_normalized_as_warnings(self) -> None:
        result = partition_discovery.parse_mmls_output(
            GPT_OUTPUT,
            "invalid backup GPT\nraw path omitted\x00",
            1,
            source_id="source_1",
            sector_size=512,
        )

        self.assertIn("mmls_exit:1", result.warnings)
        self.assertIn("mmls_stderr:invalid backup GPT raw path omitted", result.warnings)
        self.assertGreater(len(result.partitions), 0)

    def test_unpartitioned_media_is_reported_without_failure(self) -> None:
        result = partition_discovery.parse_mmls_output(
            "Partition Table: None\n", "", 0, source_id="source_1", sector_size=512
        )

        self.assertEqual("None", result.table_type)
        self.assertEqual((), result.partitions)
        self.assertIn("unsupported_table:None", result.warnings)
        self.assertIn("no_partitions", result.warnings)

    def test_sector_size_changes_normalized_byte_offsets(self) -> None:
        result = partition_discovery.parse_mmls_output(
            MBR_OUTPUT, "", 0, source_id="source_1", sector_size=4096
        )

        self.assertEqual(63 * 4096, result.partitions[2].offset_bytes)
        self.assertEqual(1985 * 4096, result.partitions[2].length_bytes)

    def test_discover_partitions_invokes_only_bounded_mmls_command(self) -> None:
        runner = FakeRunner(partition_discovery.TskCommandResult(0, MBR_OUTPUT, ""))

        result = partition_discovery.discover_partitions(
            Path("/dev/reperio-source"),
            source_id="source_1",
            sector_size=512,
            runner=runner,
            timeout_seconds=7,
        )

        self.assertEqual("source_1", result.source_id)
        self.assertEqual((("mmls", "-B", "-S", "512", "/dev/reperio-source"), 7), runner.calls[0])

    def test_repair_or_write_command_surface_is_refused(self) -> None:
        with self.assertRaises(partition_discovery.PartitionDiscoveryError) as captured:
            partition_discovery.discover_partitions(
                Path("/dev/reperio-source"),
                source_id="source_1",
                sector_size=512,
                runner=FakeRunner(partition_discovery.TskCommandResult(0, "", "")),
                mmls_binary="testdisk",
            )
        self.assertEqual("unsafe_partition_command", captured.exception.code)


if __name__ == "__main__":
    unittest.main()
