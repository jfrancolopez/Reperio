from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path

from scanner import carved_ingestion
from shared import scratch_store


class ScannerCarvedIngestionTests(unittest.TestCase):
    def test_growing_file_is_not_ingested_until_stable(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            quarantine = Path(tmp) / "quarantine"
            quarantine.mkdir()
            carved = quarantine / "f001.jpg"
            carved.write_bytes(b"part")

            ready, previous = carved_ingestion.scan_carved_outputs(quarantine, previous={})
            carved.write_bytes(b"partial-growing")
            second_ready, _second_previous = carved_ingestion.scan_carved_outputs(
                quarantine, previous=previous
            )

            self.assertEqual((), ready)
            self.assertEqual((), second_ready)

    def test_stable_file_is_ingested_on_second_scan(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            quarantine = root / "quarantine"
            quarantine.mkdir()
            carved = quarantine / "f001.pdf"
            carved.write_bytes(b"pdf bytes")
            store = make_store(root / "scratch")

            _ready, previous = carved_ingestion.scan_carved_outputs(quarantine, previous={})
            records, _current = carved_ingestion.ingest_ready_outputs(
                quarantine, scratch=store, source_id="source1", previous=previous
            )

            self.assertEqual(1, len(records))
            self.assertEqual("ingested", records[0].status)
            scratch_object = records[0].scratch_object
            assert scratch_object is not None
            self.assertEqual(b"pdf bytes", scratch_object.path.read_bytes())

    def test_finalize_rename_marker_is_ingested_immediately(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            quarantine = root / "quarantine"
            quarantine.mkdir()
            carved = quarantine / "f002.zip.done"
            carved.write_bytes(b"zip bytes")
            store = make_store(root / "scratch")

            records, _current = carved_ingestion.ingest_ready_outputs(
                quarantine, scratch=store, source_id="source1", previous={}
            )

            self.assertEqual(1, len(records))
            self.assertEqual("ingested", records[0].status)

    def test_duplicate_allocated_bytes_link_instead_of_vanishing(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            store = make_store(root / "scratch")
            existing = store.put_bytes([b"same"], provenance={"entry_id": "allocated"})
            carved = root / "f003.jpg"
            carved.write_bytes(b"same")

            record = carved_ingestion.ingest_carved_file(carved, scratch=store, source_id="source1")

            scratch_object = record.scratch_object
            assert scratch_object is not None
            self.assertEqual(existing.sha256, scratch_object.sha256)
            self.assertEqual(2, scratch_object.ref_count)
            self.assertEqual("carved", scratch_object.provenance[-1]["entry_kind"])

    def test_zero_length_output_is_skipped_explicitly(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            store = make_store(root / "scratch")
            carved = root / "empty.bin"
            carved.write_bytes(b"")

            record = carved_ingestion.ingest_carved_file(carved, scratch=store, source_id="source1")

            self.assertEqual("skipped", record.status)
            self.assertIn("zero_length_carved_output", record.warnings)
            self.assertIsNone(record.scratch_object)

    def test_corrupt_unreadable_output_returns_partial(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            store = make_store(root / "scratch")
            missing = root / "missing.bin"

            with self.assertRaises(carved_ingestion.CarvedIngestionError):
                carved_ingestion.ingest_carved_file(missing, scratch=store, source_id="source1")

    def test_restart_skips_already_ingested_paths(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            quarantine = root / "quarantine"
            quarantine.mkdir()
            carved = quarantine / "f004.jpg.done"
            carved.write_bytes(b"data")
            store = make_store(root / "scratch")

            records, current = carved_ingestion.ingest_ready_outputs(
                quarantine, scratch=store, source_id="source1", previous={}
            )
            restart_records, _restart_current = carved_ingestion.ingest_ready_outputs(
                quarantine,
                scratch=store,
                source_id="source1",
                previous=current,
                already_ingested={records[0].source_path},
            )

            self.assertEqual(1, len(records))
            self.assertEqual((), restart_records)


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
