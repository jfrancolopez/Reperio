from __future__ import annotations

import unittest

from scanner.entry_normalization import NormalizedEntry, normalize_entry, raw_entry
from worker import backup_locators, mobile_backups

IOS_ID_ONE = "a" * 40
IOS_ID_TWO = "b" * 40


class WorkerMobileBackupsTests(unittest.TestCase):
    def test_multiple_ios_devices_from_hashed_backup_folders(self) -> None:
        entries = ios_backup(IOS_ID_ONE) + ios_backup(IOS_ID_TWO)

        result = mobile_backups.locate_mobile_backups(entries)

        self.assertEqual(2, len(result.records))
        self.assertEqual(
            {IOS_ID_ONE, IOS_ID_TWO}, {record.device_identifier for record in result.records}
        )
        self.assertTrue(all(record.complete for record in result.records))

    def test_partial_android_backup_remains_visible(self) -> None:
        entries = (entry("Users/Alice/AppData/Local/Android/Broken/files.db", "1"),)

        result = mobile_backups.locate_mobile_backups(entries)

        self.assertEqual(1, len(result.records))
        self.assertFalse(result.records[0].complete)
        self.assertIn("partial_backup", result.records[0].warnings)
        self.assertIn("unsupported_android_layout_visible", result.records[0].warnings)

    def test_encrypted_ios_backup_records_manifest_state_without_decrypting(self) -> None:
        entries = ios_backup(IOS_ID_ONE)
        manifest = f"Users/Alice/AppData/Roaming/Apple Computer/MobileSync/Backup/{IOS_ID_ONE}/Manifest.plist"

        result = mobile_backups.locate_mobile_backups(
            entries,
            metadata_by_path={
                manifest: {
                    "IsEncrypted": True,
                    "Device Name": "Alice iPhone",
                    "Unique Identifier": IOS_ID_ONE,
                }
            },
        )

        self.assertTrue(result.records[0].encrypted)
        self.assertEqual("Alice iPhone", result.records[0].device_name)
        self.assertIn("encrypted_backup_visible", result.records[0].warnings)

    def test_moved_ios_folder_is_detected_with_warning(self) -> None:
        entries = ios_backup("renamed-phone")

        result = mobile_backups.locate_mobile_backups(entries)

        self.assertEqual(1, len(result.records))
        self.assertIn("moved_or_renamed_backup_folder", result.records[0].warnings)

    def test_false_positive_manifest_without_layout_is_ignored(self) -> None:
        entries = (entry("Users/Alice/Documents/Manifest.plist", "1"),)

        result = mobile_backups.locate_mobile_backups(entries)

        self.assertEqual((), result.records)

    def test_android_backup_candidate_file_from_rpr056_is_detected(self) -> None:
        item = entry("Recovered/phone.ab", "1")
        candidate = backup_locators.BackupCandidate(
            candidate_id="backup1",
            kind="phone_backup",
            display_path=item.display_path,
            profile_id=None,
            nested_depth=0,
            schedule_scan=True,
            evidence=("fixture",),
            warnings=(),
        )

        result = mobile_backups.locate_mobile_backups((item,), backup_candidates=(candidate,))

        self.assertEqual(1, len(result.records))
        self.assertEqual("android", result.records[0].platform)
        self.assertEqual("android_ab", result.records[0].layout)


def ios_backup(identifier: str) -> tuple[NormalizedEntry, ...]:
    root = f"Users/Alice/AppData/Roaming/Apple Computer/MobileSync/Backup/{identifier}"
    return (
        entry(f"{root}/Manifest.db", f"{identifier}-1"),
        entry(f"{root}/Manifest.plist", f"{identifier}-2"),
        entry(f"{root}/Status.plist", f"{identifier}-3"),
    )


def entry(path: str, object_id: str) -> NormalizedEntry:
    return normalize_entry(
        raw_entry(volume_id="vol1", object_id=object_id, path_bytes=path.encode())
    )


if __name__ == "__main__":
    unittest.main()
