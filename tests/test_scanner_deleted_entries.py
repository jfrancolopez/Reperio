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
            entry = normalized_deleted("7", "deleted.bin", size=6, extents=(extent(0, 6),))

            result = deleted_entries.recover_deleted_entry(
                entry,
                reader=FakeReader(b"deleted"),
                scratch=store,
                max_size_bytes=1024,
            )

            self.assertEqual("intact", result.recovery_state)
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
            self.assertIsNone(result.extraction)
            self.assertIn("missing_extents", result.warnings)

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
) -> entry_normalization.NormalizedEntry:
    raw = filesystem_enumeration.FilesystemEntry(
        volume_id="vol1",
        object_id=object_id,
        parent_object_id=None,
        entry_id=f"entry-vol1-{object_id}",
        name=path.rsplit("/", 1)[-1],
        entry_type="file",
        allocated=False,
        path=path,
    )
    return entry_normalization.normalize_entry(raw, size_bytes=size, extents=extents)


if __name__ == "__main__":
    unittest.main()
