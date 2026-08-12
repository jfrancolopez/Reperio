from __future__ import annotations

import hashlib
import os
import tempfile
import unittest
from pathlib import Path

from scanner import content_extraction, entry_normalization, filesystem_enumeration
from shared import scratch_store

DATA = b"abcdefghij" * 10


class FakeReader:
    def __init__(self, data: bytes = DATA, *, fail_at: int | None = None) -> None:
        self.data = data
        self.fail_at = fail_at
        self.reads: list[tuple[int, int]] = []

    def read_at(self, offset_bytes: int, length_bytes: int) -> bytes:
        self.reads.append((offset_bytes, length_bytes))
        if self.fail_at is not None and offset_bytes >= self.fail_at:
            raise OSError("fixture EIO")
        return self.data[offset_bytes : offset_bytes + length_bytes]


class ScannerContentExtractionTests(unittest.TestCase):
    def test_allocated_file_streams_to_scratch_and_matches_source_hash(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = make_store(Path(tmp) / "scratch")
            reader = FakeReader(DATA)
            entry = normalized_entry(size=len(DATA), extents=(extent(0, len(DATA)),))

            result = content_extraction.extract_allocated_content(
                entry, reader=reader, scratch=store, max_size_bytes=1024
            )

            self.assertEqual("complete", result.status)
            self.assertEqual(hashlib.sha256(DATA).hexdigest(), result.sha256)
            self.assertEqual(
                result.sha256, content_extraction.expected_sha256(entry, reader=FakeReader(DATA))
            )
            scratch_object = result.scratch_object
            assert scratch_object is not None
            self.assertEqual(DATA, scratch_object.path.read_bytes())

    def test_sparse_extent_is_zero_filled_and_warned(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = make_store(Path(tmp) / "scratch")
            entry = normalized_entry(size=6, extents=(extent(0, 3), extent(0, 3, sparse=True)))

            result = content_extraction.extract_allocated_content(
                entry, reader=FakeReader(b"abc"), scratch=store, max_size_bytes=1024
            )

            self.assertEqual("complete", result.status)
            scratch_object = result.scratch_object
            assert scratch_object is not None
            self.assertEqual(b"abc\x00\x00\x00", scratch_object.path.read_bytes())
            self.assertIn("sparse_zero_filled", result.warnings)

    def test_bad_extent_is_rejected_before_scratch_commit(self) -> None:
        with self.assertRaises(content_extraction.ContentExtractionError) as captured:
            content_extraction.sum_extent_lengths((extent(-1, 1),))

        self.assertEqual("bad_extent", captured.exception.code)

    def test_interruption_returns_partial_checkpoint_without_blocking_entry(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = make_store(Path(tmp) / "scratch")
            entry = normalized_entry(size=20, extents=(extent(0, 10), extent(10, 10)))

            result = content_extraction.extract_allocated_content(
                entry, reader=FakeReader(DATA, fail_at=10), scratch=store, max_size_bytes=1024
            )

            self.assertEqual("partial", result.status)
            self.assertIsNone(result.scratch_object)
            self.assertEqual({"entry_id": entry.entry_id, "extent_index": 0}, result.checkpoint)

    def test_resume_from_checkpoint_extracts_remaining_extents(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = make_store(Path(tmp) / "scratch")
            entry = normalized_entry(size=20, extents=(extent(0, 10), extent(10, 10)))

            result = content_extraction.extract_allocated_content(
                entry,
                reader=FakeReader(DATA),
                scratch=store,
                max_size_bytes=1024,
                resume_checkpoint={"extent_index": 1},
            )

            self.assertEqual("resumed", result.status)
            scratch_object = result.scratch_object
            assert scratch_object is not None
            self.assertEqual(DATA[10:20], scratch_object.path.read_bytes())

    def test_zero_length_and_metadata_only_entries_are_explicit(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = make_store(Path(tmp) / "scratch")
            zero = normalized_entry(size=0, extents=())
            directory = normalized_entry(size=None, extents=(), entry_type="directory")

            zero_result = content_extraction.extract_allocated_content(
                zero, reader=FakeReader(), scratch=store, max_size_bytes=1024
            )
            directory_result = content_extraction.extract_allocated_content(
                directory, reader=FakeReader(), scratch=store, max_size_bytes=1024
            )

            self.assertEqual("complete", zero_result.status)
            self.assertEqual(hashlib.sha256(b"").hexdigest(), zero_result.sha256)
            self.assertEqual("skipped", directory_result.status)
            self.assertIn("metadata_only", directory_result.warnings)

    def test_size_limit_is_explicit_skip(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = make_store(Path(tmp) / "scratch")
            entry = normalized_entry(size=20, extents=(extent(0, 20),))

            result = content_extraction.extract_allocated_content(
                entry, reader=FakeReader(DATA), scratch=store, max_size_bytes=10
            )

            self.assertEqual("skipped", result.status)
            self.assertIn("size_limit_exceeded", result.warnings)


def normalized_entry(
    *,
    size: int | None,
    extents: tuple[entry_normalization.Extent, ...],
    entry_type: str = "file",
) -> entry_normalization.NormalizedEntry:
    raw = filesystem_enumeration.FilesystemEntry(
        volume_id="vol1",
        object_id="42",
        parent_object_id=None,
        entry_id="entry-vol1-42",
        name="file.bin",
        entry_type=entry_type,
        allocated=True,
        path="file.bin",
    )
    return entry_normalization.normalize_entry(raw, size_bytes=size, extents=extents)


def extent(
    offset_bytes: int, length_bytes: int, *, sparse: bool = False
) -> entry_normalization.Extent:
    return entry_normalization.Extent(offset_bytes, length_bytes, sparse)


def make_store(root: Path) -> scratch_store.ScratchStore:
    root.mkdir()
    return scratch_store.ScratchStore(
        root,
        source={"major_minor": "8:0", "children": [{"major_minor": "8:1"}]},
        mounts=[{"mount_point": str(root), "major_minor": "8:99", "fstype": "ext4"}],
        quota_bytes=1024 * 1024,
        statvfs=lambda path: fake_statvfs(available_bytes=1024 * 1024),
    )


def fake_statvfs(*, available_bytes: int) -> os.statvfs_result:
    return os.statvfs_result((4096, 4096, 1, 1, available_bytes // 4096, 1, 1, 1, 255, 255))


if __name__ == "__main__":
    unittest.main()
