#!/usr/bin/env python3

from __future__ import annotations

import unittest

from worker import recycle_bin


def windows_meta_v1(path: str, size: int = 1024) -> bytes:
    header = (1).to_bytes(4, "little") + size.to_bytes(4, "little")
    return header + path.encode("utf-16-le") + b"\x00" * 8


def windows_meta_v2(path: str, size: int = 1024) -> bytes:
    encoded = path.encode("utf-16-le")
    header = (2).to_bytes(4, "little") + b"\x00" * 4 + size.to_bytes(8, "little")
    return header + len(encoded).to_bytes(4, "little") + encoded + b"\x00" * 8


class WindowsParsingTests(unittest.TestCase):
    def test_parse_windows_i_file_version_1(self) -> None:
        meta = recycle_bin.parse_windows_i_file(
            windows_meta_v1(r"C:\Users\alice\Documents\report.docx")
        )
        assert meta is not None
        self.assertEqual(r"C:\Users\alice\Documents\report.docx", meta.original_path)
        self.assertEqual(1024, meta.size_bytes)
        self.assertEqual(1, meta.meta_version)

    def test_parse_windows_i_file_version_2(self) -> None:
        meta = recycle_bin.parse_windows_i_file(windows_meta_v2(r"D:\photos\IMG_0001.jpg"))
        assert meta is not None
        self.assertEqual(r"D:\photos\IMG_0001.jpg", meta.original_path)
        self.assertEqual(2, meta.meta_version)

    def test_short_or_malformed_metadata_is_none(self) -> None:
        self.assertIsNone(recycle_bin.parse_windows_i_file(b"\x00" * 8))
        self.assertIsNone(recycle_bin.parse_windows_i_file(b"\x09\x00\x00\x00" + b"\x00" * 12))

    def test_pair_windows_entries_handles_paired_and_orphans(self) -> None:
        pairs = recycle_bin.pair_windows_entries(
            ["$Ireport", "$Rreport", "$Ronly-payload", "$Ionly-meta"]
        )
        by_base = {pair.base_name: pair for pair in pairs}
        self.assertEqual("$Ireport", by_base["report"].metadata_ref)
        self.assertEqual("$Rreport", by_base["report"].payload_ref)
        self.assertEqual("$Ionly-meta", by_base["only-meta"].metadata_ref)
        self.assertIsNone(by_base["only-meta"].payload_ref)
        self.assertEqual("$Ronly-payload", by_base["only-payload"].payload_ref)
        self.assertIsNone(by_base["only-payload"].metadata_ref)


class TrashInfoParsingTests(unittest.TestCase):
    def test_parse_valid_trashinfo(self) -> None:
        info = recycle_bin.parse_trashinfo(
            "[Trash Info]\nPath=/home/alice/note.txt\nDeletionDate=2026-08-01T12:30:00\n",
            name="note.txt.trashinfo",
        )
        self.assertEqual("/home/alice/note.txt", info.original_path)
        self.assertEqual("2026-08-01T12:30:00", info.deletion_time)
        self.assertEqual((), info.warnings)

    def test_parse_url_encoded_trashinfo_path(self) -> None:
        info = recycle_bin.parse_trashinfo(
            "[Trash Info]\nPath=/tmp/my%20folder/caf%C3%A9.png\nDeletionDate=2026-08-01T12:30:00\n",
            name="cafe.png.trashinfo",
        )
        self.assertEqual("/tmp/my folder/café.png", info.original_path)

    def test_missing_or_corrupt_trashinfo_stays_visible(self) -> None:
        info = recycle_bin.parse_trashinfo("garbage without a header", name="x.trashinfo")
        self.assertIn("missing_trash_info_header", info.warnings)
        self.assertIn("missing_original_path", info.warnings)
        self.assertIsNone(info.original_path)

    def test_traversal_path_is_flagged(self) -> None:
        info = recycle_bin.parse_trashinfo(
            "[Trash Info]\nPath=/../etc/passwd\nDeletionDate=2026-08-01T12:30:00\n",
            name="x.trashinfo",
        )
        self.assertIn("unsafe_original_path", info.warnings)

    def test_uncertain_deletion_time_is_flagged(self) -> None:
        info = recycle_bin.parse_trashinfo(
            "[Trash Info]\nPath=/home/a/x\nDeletionDate=not-a-time\n", name="x.trashinfo"
        )
        self.assertIn("uncertain_deletion_time", info.warnings)


class NormalizeEntryTests(unittest.TestCase):
    def test_present_entry_has_paired_metadata_and_payload(self) -> None:
        entry = recycle_bin.normalize_recycle_entry(
            entry_id="e_1",
            platform="freedesktop",
            user="1000",
            volume="root",
            original_path="/home/alice/a.txt",
            deletion_time="2026-08-01T12:30:00",
            metadata_ref="info/a.txt.trashinfo",
            payload_ref="files/a.txt",
            payload_present=True,
        )
        self.assertEqual("present", entry.recovery_state)
        self.assertEqual((), entry.warnings)

    def test_filesystem_deleted_payload_is_separate_state(self) -> None:
        entry = recycle_bin.normalize_recycle_entry(
            entry_id="e_2",
            platform="freedesktop",
            user="1000",
            volume="root",
            original_path="/home/alice/old.txt",
            deletion_time="2026-08-01T12:30:00",
            metadata_ref="info/old.txt.trashinfo",
            payload_ref=None,
            payload_present=False,
        )
        self.assertEqual("deleted", entry.recovery_state)

    def test_orphan_payload_is_carved(self) -> None:
        entry = recycle_bin.normalize_recycle_entry(
            entry_id="e_3",
            platform="windows",
            user="S-1-5-21-1",
            volume="C",
            original_path=None,
            deletion_time=None,
            metadata_ref=None,
            payload_ref="$Rcarved.bin",
            payload_present=True,
        )
        self.assertEqual("carved", entry.recovery_state)

    def test_unsafe_original_path_is_flagged(self) -> None:
        entry = recycle_bin.normalize_recycle_entry(
            entry_id="e_4",
            platform="macos",
            user="501",
            volume="System",
            original_path="/../etc/passwd\x00",
            deletion_time=None,
            metadata_ref="meta",
            payload_ref="files/x",
            payload_present=True,
        )
        self.assertIn("unsafe_original_path", entry.warnings)

    def test_unicode_original_path_preserved(self) -> None:
        entry = recycle_bin.normalize_recycle_entry(
            entry_id="e_5",
            platform="macos",
            user="501",
            volume="System",
            original_path="/Users/Δημήτρης/照片.jpg",
            deletion_time="2026-08-01T12:30:00",
            metadata_ref="meta",
            payload_ref="files/照片.jpg",
            payload_present=True,
        )
        self.assertEqual("/Users/Δημήτρης/照片.jpg", entry.original_path)
        self.assertEqual((), entry.warnings)

    def test_carved_duplicate_is_marked(self) -> None:
        entry = recycle_bin.normalize_recycle_entry(
            entry_id="e_6",
            platform="freedesktop",
            user="1000",
            volume="root",
            original_path=None,
            deletion_time=None,
            metadata_ref=None,
            payload_ref="files/dup.bin",
            payload_present=True,
        )
        marked = recycle_bin.mark_carved_duplicate(entry, content_id="content_sha256_a")
        self.assertTrue(any(w.startswith("carved_duplicate:") for w in marked.warnings))

    def test_entry_with_neither_metadata_nor_payload_is_rejected(self) -> None:
        with self.assertRaisesRegex(recycle_bin.RecycleBinError, "needs metadata"):
            recycle_bin.normalize_recycle_entry(
                entry_id="e_7",
                platform="freedesktop",
                user="1000",
                volume="root",
                original_path=None,
                deletion_time=None,
                metadata_ref=None,
                payload_ref=None,
                payload_present=False,
            )

    def test_windows_pair_normalizes_orphan_metadata(self) -> None:
        pair = recycle_bin.WindowsPair("only-meta", "$Ionly-meta", None)
        entry = recycle_bin.normalize_windows_pair(
            pair,
            entry_id="e_8",
            sid="S-1-5-21-2",
            volume="D",
            original_path=None,
            deletion_time=None,
        )
        self.assertEqual("deleted", entry.recovery_state)
        self.assertEqual("S-1-5-21-2", entry.user)


if __name__ == "__main__":
    unittest.main()
