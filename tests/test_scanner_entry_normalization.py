from __future__ import annotations

import unittest

from scanner import entry_normalization, filesystem_enumeration


class ScannerEntryNormalizationTests(unittest.TestCase):
    def test_duplicate_names_remain_distinct_by_object_id(self) -> None:
        entries = (
            enumerated("10", "Docs", entry_type="directory"),
            enumerated("11", "Docs/report.txt", parent_object_id="10"),
            enumerated("12", "Docs/report.txt", parent_object_id="10"),
        )

        normalized = entry_normalization.normalize_entries(entries)

        self.assertEqual(normalized[1].raw_path_bytes, normalized[2].raw_path_bytes)
        self.assertNotEqual(normalized[1].entry_id, normalized[2].entry_id)
        self.assertIn("duplicate_sibling_name", normalized[2].warnings)

    def test_invalid_unicode_bytes_are_representable(self) -> None:
        entry = entry_normalization.raw_entry(
            volume_id="vol1", object_id="20", path_bytes=b"bad-\xff-name.txt"
        )

        normalized = entry_normalization.normalize_entry(entry)

        self.assertEqual(b"bad-\xff-name.txt", normalized.raw_path_bytes)
        self.assertIn("invalid_unicode", normalized.warnings)
        self.assertIn("\ufffd", normalized.display_path)

    def test_alternate_stream_is_preserved_without_host_following(self) -> None:
        normalized = entry_normalization.normalize_entry(
            enumerated("30", "wallet.dat:Zone.Identifier")
        )

        self.assertEqual("Zone.Identifier", normalized.alternate_stream)
        self.assertIn("alternate_stream", normalized.warnings)
        self.assertEqual(b"wallet.dat:Zone.Identifier", normalized.raw_name_bytes)

    def test_orphan_parent_relationship_is_explicit(self) -> None:
        normalized = entry_normalization.normalize_entries(
            (enumerated("40", "lost/file.txt", parent_object_id="missing"),)
        )

        self.assertIsNone(normalized[0].parent_entry_id)
        self.assertEqual("missing", normalized[0].parent_object_id)
        self.assertIn("orphan_parent", normalized[0].warnings)

    def test_path_traversal_string_is_data_not_filesystem_operation(self) -> None:
        normalized = entry_normalization.normalize_entry(enumerated("50", "safe/../../etc/passwd"))

        self.assertEqual("safe/../../etc/passwd", normalized.display_path)
        self.assertEqual(b"safe/../../etc/passwd", normalized.raw_path_bytes)
        self.assertIn("path_traversal_segment", normalized.warnings)

    def test_raw_timestamps_timezone_state_and_extents_are_preserved(self) -> None:
        timestamp = entry_normalization.RawTimestamp("2026-01-02 03:04:05", "filesystem-local")
        extent = entry_normalization.Extent(offset_bytes=4096, length_bytes=8192, sparse=True)

        normalized = entry_normalization.normalize_entry(
            enumerated("60", "photo.jpg"),
            raw_timestamps={"mtime": timestamp},
            extents=(extent,),
            owner_id="1000",
            size_bytes=123,
            attributes=("hidden", "hidden", "archive"),
        )

        self.assertEqual(timestamp, normalized.raw_timestamps["mtime"])
        self.assertEqual((extent,), normalized.extents)
        self.assertEqual(("hidden", "archive"), normalized.attributes)
        self.assertEqual("1000", normalized.owner_id)
        self.assertEqual(123, normalized.size_bytes)

    def test_arbitrary_byte_names_round_trip_in_property_corpus(self) -> None:
        samples = [b"", b"ascii.txt", b"..", b"a/b/c", bytes(range(1, 32)), b"\xed\xa0\x80"]

        for index, sample in enumerate(samples):
            with self.subTest(sample=sample):
                entry = entry_normalization.raw_entry(
                    volume_id="vol1", object_id=str(index), path_bytes=sample or b"."
                )

                normalized = entry_normalization.normalize_entry(entry)

                self.assertEqual(sample or b".", normalized.raw_path_bytes)


def enumerated(
    object_id: str,
    path: str,
    *,
    entry_type: str = "file",
    parent_object_id: str | None = None,
    allocated: bool = True,
) -> filesystem_enumeration.FilesystemEntry:
    return filesystem_enumeration.FilesystemEntry(
        volume_id="vol1",
        object_id=object_id,
        parent_object_id=parent_object_id,
        entry_id=f"entry-vol1-{object_id}",
        name=path.rsplit("/", 1)[-1],
        entry_type=entry_type,
        allocated=allocated,
        path=path,
    )


if __name__ == "__main__":
    unittest.main()
