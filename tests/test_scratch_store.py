from __future__ import annotations

import hashlib
import os
import tempfile
import unittest
from collections.abc import Callable
from pathlib import Path

from shared import scratch_store


class ScratchStoreTests(unittest.TestCase):
    def test_duplicate_content_shares_storage_and_retains_provenance(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "scratch"
            root.mkdir()
            store = make_store(root)

            first = store.put_bytes([b"same"], provenance={"entry_id": "entry1"})
            second = store.put_bytes([b"same"], provenance={"entry_id": "entry2"})

            self.assertEqual(first.sha256, second.sha256)
            self.assertEqual(first.path, second.path)
            self.assertEqual(2, second.ref_count)
            self.assertEqual(({"entry_id": "entry1"}, {"entry_id": "entry2"}), second.provenance)

    def test_concurrent_duplicate_simulation_uses_existing_final_object(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "scratch"
            root.mkdir()
            store = make_store(root)
            expected_hash = hashlib.sha256(b"content").hexdigest()
            final_path = root.resolve(strict=False) / "objects" / expected_hash[:2] / expected_hash
            final_path.parent.mkdir(parents=True)
            final_path.write_bytes(b"content")

            result = store.put_bytes([b"content"], provenance={"entry_id": "entry1"})

            self.assertEqual(final_path, result.path)
            self.assertEqual(b"content", final_path.read_bytes())

    def test_disk_full_is_reported_and_temp_file_is_removed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "scratch"
            root.mkdir()
            store = make_store(root, statvfs=lambda path: fake_statvfs(available_bytes=1))

            with self.assertRaises(scratch_store.ScratchStoreError) as captured:
                store.put_bytes([b"too large"], provenance={"entry_id": "entry1"})

            self.assertEqual("disk_full", captured.exception.code)
            self.assertEqual([], list((root / "tmp").glob("*")))

    def test_crash_cleanup_removes_only_incomplete_owned_files(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "scratch"
            root.mkdir()
            store = make_store(root)
            store.initialize()
            incomplete = root / "tmp" / ".reperio-incomplete-deadbeef"
            keeper = root / "tmp" / "unrelated"
            incomplete.write_bytes(b"partial")
            keeper.write_bytes(b"keep")

            removed = store.cleanup_incomplete()

            self.assertEqual(1, removed)
            self.assertFalse(incomplete.exists())
            self.assertTrue(keeper.exists())

    def test_hash_mismatch_removes_temp_and_refuses_object(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "scratch"
            root.mkdir()
            store = make_store(root)

            with self.assertRaises(scratch_store.ScratchStoreError) as captured:
                store.put_bytes(
                    [b"actual"], provenance={"entry_id": "entry1"}, expected_sha256="0" * 64
                )

            self.assertEqual("hash_mismatch", captured.exception.code)
            self.assertEqual([], list((root / "objects").rglob("*")))

    def test_symlink_attack_in_scratch_tree_is_refused(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "scratch"
            root.mkdir()
            store = make_store(root)
            store.initialize()
            (root / "tmp" / ".reperio-incomplete-link").symlink_to(root)

            with self.assertRaises(scratch_store.ScratchStoreError) as captured:
                store.cleanup_incomplete()

            self.assertEqual("scratch_symlink", captured.exception.code)

    def test_same_disk_scratch_is_refused_before_write(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "scratch"
            root.mkdir()

            with self.assertRaises(scratch_store.ScratchStoreError) as captured:
                make_store(root, scratch_major_minor="8:1")

            self.assertEqual("scratch_not_separate", captured.exception.code)

    def test_quota_exceeded_is_reported(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "scratch"
            root.mkdir()
            store = make_store(root, quota_bytes=4)

            with self.assertRaises(scratch_store.ScratchStoreError) as captured:
                store.put_bytes([b"12345"], provenance={"entry_id": "entry1"})

            self.assertEqual("quota_exceeded", captured.exception.code)


def make_store(
    root: Path,
    *,
    quota_bytes: int = 1024 * 1024,
    scratch_major_minor: str = "8:99",
    statvfs: Callable[[Path], os.statvfs_result] | None = None,
) -> scratch_store.ScratchStore:
    return scratch_store.ScratchStore(
        root,
        source={"major_minor": "8:0", "children": [{"major_minor": "8:1"}]},
        mounts=[{"mount_point": str(root), "major_minor": scratch_major_minor, "fstype": "ext4"}],
        quota_bytes=quota_bytes,
        statvfs=statvfs,
    )


def fake_statvfs(*, available_bytes: int) -> os.statvfs_result:
    return os.statvfs_result((4096, 4096, 1, 1, available_bytes // 4096, 1, 1, 1, 255, 255))


if __name__ == "__main__":
    unittest.main()
