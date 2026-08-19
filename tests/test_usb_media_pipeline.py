#!/usr/bin/env python3

from __future__ import annotations

import unittest

from scanner import photorec_carving
from scanner.lost_volume_candidates import LostVolumeCandidate
from scanner.partition_discovery import PartitionDiscoveryResult, PartitionEntry
from scanner.usb_media_pipeline import (
    MediumFamily,
    UsbMediaPipelineError,
    bounded_carve_ranges,
    classify_medium_family,
    classify_provenance,
    dcim_interest_ranking,
    deep_pipeline_plan,
    determine_partitioning_mode,
    flash_capability_state,
    remaining_stages,
)


def partition_result(
    *, table: str | None, entries: tuple[PartitionEntry, ...], warnings: tuple[str, ...] = ()
) -> PartitionDiscoveryResult:
    return PartitionDiscoveryResult(
        source_id="source_1",
        table_type=table,
        sector_size=512,
        partitions=entries,
        warnings=warnings,
    )


def partition(
    description: str, *, start: int, length: int, allocated: bool = True
) -> PartitionEntry:
    return PartitionEntry(
        slot="000:",
        offset_bytes=start * 512,
        length_bytes=length * 512,
        start_sector=start,
        end_sector=start + length - 1,
        sector_count=length,
        description=description,
        partition_type=description,
        label=None,
        allocated=allocated,
    )


def candidate(offset: int, signature: str = "exfat") -> LostVolumeCandidate:
    return LostVolumeCandidate(
        candidate_id=f"lost-volume-{offset}",
        offset_bytes=offset,
        length_bytes=128 * 1024 * 1024,
        signature=signature,
        confidence=0.85,
        status="candidate",
        warnings=(),
        schedule=(photorec_carving.CarveRange(offset, 1024),),
    )


class MediumFamilyTests(unittest.TestCase):
    def test_usb_flash_family(self) -> None:
        family = classify_medium_family({"source_kind": "usb_flash"})
        self.assertEqual("usb_flash", family.family)

    def test_sd_card_type_mapping(self) -> None:
        family = classify_medium_family({"source_kind": "memory_card"}, card_type_hint="microSD")
        self.assertEqual("microsd", family.card_type)

    def test_compactflash_mapping(self) -> None:
        family = classify_medium_family({"source_kind": "memory_card"}, card_type_hint="CF")
        self.assertEqual("compactflash", family.card_type)

    def test_unknown_card_type(self) -> None:
        family = classify_medium_family({"source_kind": "memory_card"})
        self.assertEqual("unknown", family.card_type)

    def test_fixed_disk_is_rejected(self) -> None:
        with self.assertRaisesRegex(UsbMediaPipelineError, "not a USB flash"):
            classify_medium_family({"device_type": "fixed_disk"})

    def test_validation_rejects_bad_family(self) -> None:
        with self.assertRaisesRegex(UsbMediaPipelineError, "family"):
            MediumFamily("optical_disc").validate()


class PartitioningModeTests(unittest.TestCase):
    def test_partitioned_fat32_sd(self) -> None:
        result = partition_result(
            table="DOS Partition Table", entries=(partition("FAT32", start=2048, length=1000),)
        )
        mode = determine_partitioning_mode(result)
        self.assertEqual("partitioned", mode.mode)

    def test_partitionless_superfloppy_exfat(self) -> None:
        result = partition_result(table=None, entries=(), warnings=("partition_table_missing",))
        mode = determine_partitioning_mode(result, lost_candidates=(candidate(0, "exfat"),))
        self.assertEqual("partitionless_superfloppy", mode.mode)
        self.assertEqual(0, mode.root_volume_offset_bytes)

    def test_lost_partition(self) -> None:
        result = partition_result(table=None, entries=(), warnings=("no_partitions",))
        mode = determine_partitioning_mode(result, lost_candidates=(candidate(1048576, "ntfs"),))
        self.assertEqual("lost_partition", mode.mode)

    def test_raw_unallocated_unknown_medium(self) -> None:
        result = partition_result(table=None, entries=(), warnings=("partition_table_missing",))
        mode = determine_partitioning_mode(result, lost_candidates=())
        self.assertEqual("raw_unallocated", mode.mode)


class DeepPipelinePlanTests(unittest.TestCase):
    def test_full_plan_with_carving(self) -> None:
        plan = deep_pipeline_plan("partitioned", enable_carving=True)
        self.assertEqual(
            (
                "volumes",
                "enumeration",
                "deleted_recovery",
                "carving",
                "classification",
                "export",
            ),
            plan,
        )

    def test_plan_without_carving_is_bounded(self) -> None:
        plan = deep_pipeline_plan("partitionless_superfloppy", enable_carving=False)
        self.assertNotIn("carving", plan)
        self.assertIn("export", plan)

    def test_invalid_mode_rejected(self) -> None:
        with self.assertRaisesRegex(UsbMediaPipelineError, "mode"):
            deep_pipeline_plan("mounted")

    def test_resume_after_disconnect(self) -> None:
        plan = deep_pipeline_plan("partitioned")
        remaining = remaining_stages(plan, ("volumes", "enumeration", "deleted_recovery"))
        self.assertEqual(("carving", "classification", "export"), remaining)


class CarveBudgetTests(unittest.TestCase):
    def test_bounded_carve_ranges(self) -> None:
        ranges = bounded_carve_ranges(100 * 1024 * 1024, budget_bytes=10 * 1024 * 1024)
        self.assertEqual(1, len(ranges))
        self.assertEqual(10 * 1024 * 1024, ranges[0].length_bytes)
        total = sum(item.length_bytes for item in ranges)
        self.assertLessEqual(total, 10 * 1024 * 1024)

    def test_invalid_bounds_rejected(self) -> None:
        with self.assertRaisesRegex(UsbMediaPipelineError, "bounds"):
            bounded_carve_ranges(0, budget_bytes=1024)


class ProvenanceTests(unittest.TestCase):
    def test_allocated_provenance(self) -> None:
        result = classify_provenance(allocated=True, entry_type="file", path="/DCIM/IMG_0001.JPG")
        self.assertEqual("allocated", result.provenance)

    def test_deleted_provenance(self) -> None:
        result = classify_provenance(allocated=False, entry_type="deleted", path="/lost.JPG")
        self.assertEqual("deleted", result.provenance)

    def test_trashed_provenance(self) -> None:
        result = classify_provenance(
            allocated=True, entry_type="file", path="/.Trashes/501/old.pdf"
        )
        self.assertEqual("trashed", result.provenance)

    def test_hidden_provenance(self) -> None:
        result = classify_provenance(allocated=True, entry_type="file", path="/.hidden")
        self.assertEqual("hidden", result.provenance)

    def test_carved_provenance(self) -> None:
        result = classify_provenance(allocated=True, entry_type="carved", path="/carved/1.bin")
        self.assertEqual("carved", result.provenance)

    def test_fragmented_overwritten_still_deleted(self) -> None:
        result = classify_provenance(allocated=False, entry_type="deleted", path="/frag.bin")
        self.assertEqual("deleted", result.provenance)
        self.assertTrue(result.reasons)


class FlashCapabilityTests(unittest.TestCase):
    def test_unknown_state_never_clean(self) -> None:
        state = flash_capability_state({})
        self.assertIn("unknown", state.states)
        self.assertFalse(state.can_verify_clean)

    def test_trim_with_unrecoverable_blocks_not_clean(self) -> None:
        state = flash_capability_state({"trim_supported": True, "unrecoverable_blocks": True})
        self.assertIn("trim_supported", state.states)
        self.assertFalse(state.can_verify_clean)
        self.assertIn("unrecoverable_blocks_present", state.warnings)

    def test_wear_leveling_and_continued_use_limited(self) -> None:
        state = flash_capability_state({"wear_leveling_active": True, "continued_use_limit": "low"})
        self.assertIn("wear_leveling_active", state.states)
        self.assertIn("continued_use_limited", state.states)


class InterestRankingTests(unittest.TestCase):
    def test_dcim_camera_boosted(self) -> None:
        ranking = dcim_interest_ranking("/DCIM/100NCDNG/IMG_0042.JPG")
        self.assertTrue(ranking.boosted)
        self.assertEqual("dcim_camera_content", ranking.boost_reason)
        self.assertTrue(ranking.preserves_other_findings)

    def test_portable_backup_boosted(self) -> None:
        ranking = dcim_interest_ranking("/backup/notes.txt")
        self.assertTrue(ranking.boosted)
        self.assertEqual("portable_backup_content", ranking.boost_reason)

    def test_other_files_not_boosted_but_preserved(self) -> None:
        ranking = dcim_interest_ranking("/random/old.txt")
        self.assertFalse(ranking.boosted)
        self.assertTrue(ranking.preserves_other_findings)


if __name__ == "__main__":
    unittest.main()
