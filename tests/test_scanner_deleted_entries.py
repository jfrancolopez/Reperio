from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from scanner import deleted_entries, entry_normalization, filesystem_enumeration
from tests.test_scanner_content_extraction import FakeReader, extent, make_store


class ScannerDeletedEntriesTests(unittest.TestCase):
    def test_deleted_file_recovers_intact_content_with_deleted_provenance(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = make_store(Path(tmp) / "scratch")
            timestamp = entry_normalization.RawTimestamp("2026-01-02T03:04:05Z", "filesystem")
            entry = normalized_deleted(
                "7",
                "deleted.bin",
                size=6,
                extents=(extent(0, 6),),
                raw_timestamps={"mtime": timestamp},
            )

            result = deleted_entries.recover_deleted_entry(
                entry,
                reader=FakeReader(b"deleted"),
                scratch=store,
                max_size_bytes=1024,
            )

            self.assertEqual("intact", result.recovery_state)
            self.assertEqual("intact", result.recovery_health)
            self.assertEqual("deleted.bin", result.original_name)
            self.assertEqual("deleted.bin", result.original_path)
            self.assertEqual(b"deleted.bin", result.raw_name_bytes)
            self.assertEqual(timestamp, result.raw_timestamps["mtime"])
            self.assertIsNotNone(result.extraction)
            assert result.extraction is not None
            self.assertEqual("complete", result.extraction.status)
            scratch_object = result.extraction.scratch_object
            assert scratch_object is not None
            self.assertEqual(b"delete", scratch_object.path.read_bytes())

    def test_partially_overwritten_deleted_file_is_labeled_partial(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = make_store(Path(tmp) / "scratch")
            entry = normalized_deleted(
                "8", "partial.bin", size=10, extents=(extent(0, 5), extent(5, 5))
            )

            result = deleted_entries.recover_deleted_entry(
                entry,
                reader=FakeReader(b"partial-data", fail_at=5),
                scratch=store,
                max_size_bytes=1024,
            )

            self.assertEqual("partial", result.recovery_state)
            self.assertEqual("partial", result.recovery_health)
            self.assertIsNotNone(result.extraction)
            self.assertIn("io_error", result.warnings)

    def test_zeroed_metadata_and_unrecoverable_deleted_entries_are_explicit(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = make_store(Path(tmp) / "scratch")
            entry = normalized_deleted("9", "zeroed.bin", size=None, extents=())

            result = deleted_entries.recover_deleted_entry(
                entry,
                reader=FakeReader(),
                scratch=store,
                max_size_bytes=1024,
            )

            self.assertEqual("unrecoverable", result.recovery_state)
            self.assertEqual("unrecoverable", result.recovery_health)
            self.assertIsNone(result.extraction)
            self.assertIn("missing_extents", result.warnings)

    def test_zero_length_deleted_file_is_recovered_as_empty_content(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = make_store(Path(tmp) / "scratch")
            entry = normalized_deleted("15", "empty.bin", size=0, extents=())

            result = deleted_entries.recover_deleted_entry(
                entry, reader=FakeReader(), scratch=store, max_size_bytes=1024
            )

            self.assertEqual("intact", result.recovery_state)
            self.assertIsNotNone(result.extraction)
            assert result.extraction is not None
            self.assertEqual(0, result.extraction.size_bytes)

    def test_allocated_record_is_not_recovered_as_deleted(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = make_store(Path(tmp) / "scratch")
            entry = normalized_deleted(
                "10", "allocated.bin", size=6, extents=(extent(0, 6),), allocated=True
            )
            reader = FakeReader(b"delete")

            result = deleted_entries.recover_deleted_entry(
                entry, reader=reader, scratch=store, max_size_bytes=1024
            )

            self.assertEqual("allocated_not_deleted", result.recovery_state)
            self.assertEqual("not_deleted", result.recovery_health)
            self.assertEqual([], reader.reads)
            self.assertIsNone(result.extraction)

    def test_orphan_file_with_extents_is_recovered_and_labeled(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = make_store(Path(tmp) / "scratch")
            entry = normalized_deleted(
                "11",
                "lost/file.bin",
                size=6,
                extents=(extent(0, 6),),
                parent_object_id="missing-parent",
                orphan_parent=True,
            )

            result = deleted_entries.recover_deleted_entry(
                entry, reader=FakeReader(b"delete"), scratch=store, max_size_bytes=1024
            )

            self.assertTrue(result.orphan)
            self.assertEqual("missing-parent", result.parent_object_id)
            self.assertIn("orphan_parent", result.warnings)

    def test_duplicate_deleted_content_shares_bytes_and_keeps_both_provenances(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = make_store(Path(tmp) / "scratch")
            first = normalized_deleted("12", "first.bin", size=6, extents=(extent(0, 6),))
            second = normalized_deleted("13", "second.bin", size=6, extents=(extent(0, 6),))

            first_result = deleted_entries.recover_deleted_entry(
                first, reader=FakeReader(b"delete"), scratch=store, max_size_bytes=1024
            )
            second_result = deleted_entries.recover_deleted_entry(
                second, reader=FakeReader(b"delete"), scratch=store, max_size_bytes=1024
            )

            assert first_result.extraction is not None
            assert second_result.extraction is not None
            assert first_result.extraction.scratch_object is not None
            assert second_result.extraction.scratch_object is not None
            self.assertEqual(
                first_result.extraction.scratch_object.content_id,
                second_result.extraction.scratch_object.content_id,
            )
            self.assertEqual(2, second_result.extraction.scratch_object.ref_count)
            self.assertEqual(
                {first.entry_id, second.entry_id},
                {
                    str(provenance["entry_id"])
                    for provenance in second_result.extraction.scratch_object.provenance
                },
            )

    def test_missing_size_metadata_with_extents_is_partial_not_intact(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = make_store(Path(tmp) / "scratch")
            entry = normalized_deleted("14", "unknown-size.bin", size=None, extents=(extent(0, 6),))

            result = deleted_entries.recover_deleted_entry(
                entry, reader=FakeReader(b"delete"), scratch=store, max_size_bytes=1024
            )

            self.assertEqual("partial", result.recovery_state)
            self.assertEqual("partial", result.recovery_health)
            self.assertIn("missing_size_metadata", result.warnings)

    def test_orphan_parent_and_deleted_directory_remain_catalogable_metadata(self) -> None:
        directory = filesystem_enumeration.FilesystemEntry(
            volume_id="vol1",
            object_id="10",
            parent_object_id="missing-parent",
            entry_id="entry-vol1-10",
            name="lost-dir",
            entry_type="directory",
            allocated=False,
            path="lost-dir",
        )

        normalized = entry_normalization.normalize_entry(directory, orphan_parent=True)

        self.assertEqual("deleted", normalized.entry_type)
        self.assertFalse(normalized.allocated)
        self.assertIn("orphan_parent", normalized.warnings)


def normalized_deleted(
    object_id: str,
    path: str,
    *,
    size: int | None,
    extents: tuple[entry_normalization.Extent, ...],
    allocated: bool = False,
    parent_object_id: str | None = None,
    orphan_parent: bool = False,
    raw_timestamps: dict[str, entry_normalization.RawTimestamp] | None = None,
) -> entry_normalization.NormalizedEntry:
    raw = filesystem_enumeration.FilesystemEntry(
        volume_id="vol1",
        object_id=object_id,
        parent_object_id=parent_object_id,
        entry_id=f"entry-vol1-{object_id}",
        name=path.rsplit("/", 1)[-1],
        entry_type="file",
        allocated=allocated,
        path=path,
    )
    return entry_normalization.normalize_entry(
        raw,
        size_bytes=size,
        extents=extents,
        raw_timestamps=raw_timestamps,
        orphan_parent=orphan_parent,
    )


if __name__ == "__main__":
    unittest.main()
