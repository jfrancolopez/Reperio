from __future__ import annotations

import unittest

from scanner import entry_normalization, filesystem_enumeration
from worker import windows_profiles


class WorkerWindowsProfilesTests(unittest.TestCase):
    def test_multiple_users_are_attached_to_windows_installation(self) -> None:
        result = windows_profiles.discover_windows_profiles(
            entries(
                ("Windows/System32/config/SOFTWARE", "SYSTEM"),
                ("Windows/System32/kernel32.dll", "SYSTEM"),
                ("Users/Alice/NTUSER.DAT", "S-1-5-21-100"),
                ("Users/Bob/Documents/tax.pdf", "S-1-5-21-200"),
            )
        )

        self.assertEqual(1, len(result.installations))
        self.assertTrue(result.installations[0].registry_present)
        self.assertEqual({"Alice", "Bob"}, {profile.display_name for profile in result.profiles})
        self.assertEqual(
            {"S-1-5-21-100", "S-1-5-21-200"}, {profile.sid for profile in result.profiles}
        )

    def test_old_documents_and_settings_layout_is_supported(self) -> None:
        result = windows_profiles.discover_windows_profiles(
            entries(
                ("Windows/System32/kernel32.dll", "SYSTEM"),
                ("Documents and Settings/Carol/Desktop/note.txt", "S-1-5-21-300"),
            )
        )

        self.assertEqual("Documents and Settings/Carol", result.profiles[0].root_path)
        self.assertIn("well_known:desktop", result.profiles[0].evidence)

    def test_missing_registry_still_reports_installation_with_evidence(self) -> None:
        result = windows_profiles.discover_windows_profiles(
            entries(("Windows/System32/cmd.exe", None))
        )

        self.assertEqual(1, len(result.installations))
        self.assertFalse(result.installations[0].registry_present)
        self.assertIn("windows/system32", result.installations[0].evidence)

    def test_portable_user_folder_without_windows_install_is_reported(self) -> None:
        result = windows_profiles.discover_windows_profiles(
            entries(("Franco/Documents/file.txt", "S-1-5-21-400"))
        )

        self.assertEqual(0, len(result.installations))
        self.assertTrue(result.profiles[0].portable)
        self.assertIsNone(result.profiles[0].installation_id)

    def test_duplicate_usernames_keep_distinct_sids_and_profile_ids(self) -> None:
        normalized = [entry("Users/Sam/Desktop/a.txt", "S-1-5-21-1", volume_id="vol1")]
        normalized.extend(entries(("Users/Sam/Desktop/b.txt", "S-1-5-21-2"), volume_id="vol2"))

        result = windows_profiles.discover_windows_profiles(tuple(normalized))

        self.assertEqual(2, len(result.profiles))
        self.assertEqual({"Sam"}, {profile.display_name for profile in result.profiles})
        self.assertEqual(2, len({profile.profile_id for profile in result.profiles}))
        self.assertEqual({"S-1-5-21-1", "S-1-5-21-2"}, {profile.sid for profile in result.profiles})


def entries(
    *items: tuple[str, str | None], volume_id: str = "vol1"
) -> tuple[entry_normalization.NormalizedEntry, ...]:
    return tuple(entry(path, owner_id, volume_id=volume_id) for path, owner_id in items)


def entry(
    path: str, owner_id: str | None, *, volume_id: str = "vol1"
) -> entry_normalization.NormalizedEntry:
    raw = filesystem_enumeration.FilesystemEntry(
        volume_id=volume_id,
        object_id=f"obj-{path}",
        parent_object_id=None,
        entry_id=f"entry-{volume_id}-{path}",
        name=path.rsplit("/", 1)[-1],
        entry_type="file",
        allocated=True,
        path=path,
    )
    return entry_normalization.normalize_entry(raw, owner_id=owner_id)


if __name__ == "__main__":
    unittest.main()
