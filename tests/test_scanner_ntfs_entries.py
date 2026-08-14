from __future__ import annotations

import unittest

from scanner import entry_normalization, filesystem_enumeration, ntfs_entries
from tests.test_scanner_entry_normalization import enumerated


class ScannerNtfsEntryTests(unittest.TestCase):
    def test_ads_object_id_and_stream_are_distinct_and_preserved(self) -> None:
        entries, warnings = filesystem_enumeration.parse_fls_output(
            "r/- 38-128-4: wallet.dat:Zone.Identifier\n",
            "",
            0,
            volume_id="vol1",
            batch_size=10,
        )
        normalized = entry_normalization.normalize_entry(entries[0])

        enriched, details = ntfs_entries.enrich_ntfs_entry(normalized)

        self.assertEqual((), warnings)
        self.assertEqual("38-128-4", entries[0].object_id)
        self.assertEqual("Zone.Identifier", details.alternate_stream)
        self.assertEqual("128-4", details.attribute_id)
        self.assertIn("ntfs_alternate_data_stream", enriched.attributes)

    def test_resident_compressed_sparse_reparse_and_dos_name_flags_are_queryable(self) -> None:
        normalized = entry_normalization.normalize_entry(enumerated("42", "Docs/REPORT~1.TXT"))

        enriched, details = ntfs_entries.enrich_ntfs_entry(
            normalized,
            {
                "resident": True,
                "compressed": True,
                "sparse": True,
                "reparse_point": True,
                "reparse_tag": "IO_REPARSE_TAG_SYMLINK",
                "dos_name": "REPORT~1.TXT",
            },
        )

        self.assertTrue(details.resident)
        self.assertEqual("REPORT~1.TXT", details.dos_name)
        self.assertIn("ntfs_resident", enriched.attributes)
        self.assertIn("ntfs_compressed", enriched.attributes)
        self.assertIn("ntfs_sparse", enriched.attributes)
        self.assertIn("ntfs_reparse_point", enriched.attributes)
        self.assertIn("ntfs_dos_name", enriched.attributes)
        self.assertIn("reparse_point_not_followed", enriched.warnings)

    def test_hard_links_are_recorded_but_not_followed_on_host(self) -> None:
        normalized = entry_normalization.normalize_entry(enumerated("43", "link-target.txt"))

        enriched, details = ntfs_entries.enrich_ntfs_entry(
            normalized, {"hard_links": ["Users/A/link-target.txt", "Users/B/link-target.txt"]}
        )

        self.assertEqual(("Users/A/link-target.txt", "Users/B/link-target.txt"), details.hard_links)
        self.assertIn("ntfs_hard_link", enriched.attributes)
        self.assertIn("host_link_not_followed", enriched.warnings)

    def test_mft_metadata_and_recycle_bin_linkage_are_explicit(self) -> None:
        mft = entry_normalization.normalize_entry(enumerated("0", "$MFT"))
        recycle = entry_normalization.normalize_entry(
            enumerated("44", "$Recycle.Bin/S-1-5-21/$RABC123.docx")
        )

        enriched_mft, mft_details = ntfs_entries.enrich_ntfs_entry(mft)
        enriched_recycle, recycle_details = ntfs_entries.enrich_ntfs_entry(
            recycle,
            {
                "recycle_bin_original_path": "C:/Users/A/Documents/report.docx",
                "recycle_bin_deletion_time": "2026-01-02T03:04:05Z",
            },
        )

        self.assertTrue(mft_details.metadata_file)
        self.assertIn("ntfs_metadata_file", enriched_mft.attributes)
        self.assertEqual(
            "C:/Users/A/Documents/report.docx", recycle_details.recycle_bin_original_path
        )
        self.assertEqual("2026-01-02T03:04:05Z", recycle_details.recycle_bin_deletion_time)
        self.assertIn("ntfs_recycle_bin_record", enriched_recycle.attributes)


if __name__ == "__main__":
    unittest.main()
