from __future__ import annotations

import unittest

from scanner import entry_normalization, fat_entries, filesystem_enumeration


class ScannerFatEntryTests(unittest.TestCase):
    def test_fat32_long_and_short_names_preserve_unicode_and_timezone_limits(self) -> None:
        entry = normalized("11", "Résumé 2026.txt", allocated=True)

        enriched, details = fat_entries.enrich_fat_entry(
            entry,
            filesystem="fat32",
            short_name="RESUME~1.TXT",
            long_name="Résumé 2026.txt",
            first_cluster=5,
            cluster_chain=(5, 9, 0x0FFFFFFF),
            cluster_size_bytes=512,
            data_offset_bytes=4096,
            timestamp_fields={"modified": "2026-08-14 12:00:00"},
        )

        self.assertEqual("fat32", details.filesystem)
        self.assertEqual("RESUME~1.TXT", details.short_name)
        self.assertEqual("Résumé 2026.txt", details.long_name)
        self.assertEqual((5, 9), details.cluster_chain)
        self.assertEqual("local_ambiguous", details.timezone_state)
        self.assertEqual(
            (5632, 512), (enriched.extents[0].offset_bytes, enriched.extents[0].length_bytes)
        )
        self.assertIn("fat_short_name", enriched.attributes)
        self.assertIn("fat_timestamp_timezone_ambiguous", enriched.warnings)

    def test_exfat_deleted_fragmented_entry_is_distinct_and_extractable(self) -> None:
        entry = normalized("12", "deleted photo.jpg", allocated=False)

        enriched, details = fat_entries.enrich_fat_entry(
            entry,
            filesystem="exfat",
            first_cluster=20,
            cluster_chain=(20, 35, 36),
            cluster_size_bytes=1024,
            data_offset_bytes=8192,
        )

        self.assertFalse(enriched.allocated)
        self.assertEqual("deleted", enriched.entry_type)
        self.assertIn("deleted_entry", enriched.attributes)
        self.assertEqual("complete", details.chain_status)
        self.assertEqual((20, 35, 36), details.cluster_chain)
        self.assertEqual(3, len(enriched.extents))

    def test_volume_label_is_cataloged_as_virtual_metadata(self) -> None:
        entry = normalized("13", "NO NAME", entry_type="virtual")

        enriched, details = fat_entries.enrich_fat_entry(
            entry,
            filesystem="fat32",
            volume_label="BACKUP_DISK",
        )

        self.assertEqual("virtual", enriched.entry_type)
        self.assertEqual("BACKUP_DISK", details.volume_label)
        self.assertIn("volume_label", enriched.attributes)

    def test_corrupt_cluster_loop_is_bounded_and_visible(self) -> None:
        chain, status, warnings = fat_entries.normalize_cluster_chain((4, 5, 6, 5), max_clusters=10)

        self.assertEqual((4, 5, 6), chain)
        self.assertEqual("corrupt", status)
        self.assertIn("fat_cluster_loop_bounded", warnings)

    def test_cluster_chain_limit_is_bounded(self) -> None:
        chain, status, warnings = fat_entries.normalize_cluster_chain(
            tuple(range(2, 20)), max_clusters=3
        )

        self.assertEqual((2, 3, 4), chain)
        self.assertEqual("truncated", status)
        self.assertIn("fat_cluster_chain_bounded", warnings)


def normalized(
    object_id: str,
    path: str,
    *,
    allocated: bool = True,
    entry_type: str = "file",
) -> entry_normalization.NormalizedEntry:
    raw = filesystem_enumeration.FilesystemEntry(
        volume_id="vol1",
        object_id=object_id,
        parent_object_id=None,
        entry_id=f"entry-vol1-{object_id}",
        name=path.rsplit("/", 1)[-1],
        entry_type=entry_type,
        allocated=allocated,
        path=path,
    )
    return entry_normalization.normalize_entry(raw, size_bytes=4096)


if __name__ == "__main__":
    unittest.main()
