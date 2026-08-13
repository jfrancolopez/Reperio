from __future__ import annotations

import unittest

from scanner.entry_normalization import NormalizedEntry, normalize_entry, raw_entry
from worker import backup_locators, core_categories, windows_profiles


class WorkerBackupLocatorsTests(unittest.TestCase):
    def test_renamed_backup_is_inventoried_by_category_evidence(self) -> None:
        item = entry("Users/Alice/Documents/family-copy.bin", "1")
        category = backup_category()

        result = backup_locators.locate_backup_artifacts(
            (item,), categories_by_path={item.display_path: category}, profiles=(profile_fixture(),)
        )

        self.assertEqual(1, len(result.candidates))
        self.assertEqual("generic_backup", result.candidates[0].kind)
        self.assertIn("category:backups/mobile", result.candidates[0].evidence)

    def test_nested_disk_image_requires_explicit_bounded_policy_to_schedule(self) -> None:
        item = entry("Backups/base.vhd/nested.vmdk", "1")

        default = backup_locators.locate_backup_artifacts((item,))
        explicit = backup_locators.locate_backup_artifacts(
            (item,), policy=backup_locators.LocatorPolicy(schedule_nested=True, max_nested_depth=1)
        )

        self.assertFalse(default.candidates[0].schedule_scan)
        self.assertIn("not_scheduled_by_policy", default.candidates[0].warnings)
        self.assertTrue(explicit.candidates[0].schedule_scan)

    def test_broken_catalog_remains_visible_with_warning(self) -> None:
        item = entry("WindowsImageBackup/catalog.bkf", "1")

        result = backup_locators.locate_backup_artifacts(
            (item,), metadata_by_path={item.display_path: {"catalog_state": "broken"}}
        )

        self.assertEqual("windows_backup", result.candidates[0].kind)
        self.assertIn("broken_catalog", result.candidates[0].warnings)

    def test_symlink_like_filesystem_entry_is_not_scheduled(self) -> None:
        item = entry("Users/Alice/OneDrive", "1", entry_type="symlink")

        result = backup_locators.locate_backup_artifacts((item,))

        self.assertEqual("sync_root", result.candidates[0].kind)
        self.assertFalse(result.candidates[0].schedule_scan)
        self.assertIn("symlink_like_entry_not_scheduled", result.candidates[0].warnings)

    def test_huge_backup_set_is_inventoried_but_schedule_is_capped(self) -> None:
        items = tuple(entry(f"Backup/set-{index}.vhd", str(index)) for index in range(5))

        result = backup_locators.locate_backup_artifacts(
            items, policy=backup_locators.LocatorPolicy(max_scheduled_items=2)
        )

        self.assertEqual(5, len(result.candidates))
        self.assertEqual(2, sum(candidate.schedule_scan for candidate in result.candidates))
        self.assertTrue(
            any("not_scheduled_by_policy" in item.warnings for item in result.candidates)
        )


def entry(path: str, object_id: str, *, entry_type: str = "file") -> NormalizedEntry:
    return normalize_entry(
        raw_entry(
            volume_id="vol1", object_id=object_id, path_bytes=path.encode(), entry_type=entry_type
        )
    )


def profile_fixture() -> windows_profiles.WindowsUserProfile:
    return windows_profiles.WindowsUserProfile(
        profile_id="profile1",
        installation_id="win1",
        volume_id="vol1",
        root_path="Users/Alice",
        display_name="Alice",
        sid="S-1-5-21-1",
        evidence=("ntuser.dat",),
    )


def backup_category() -> core_categories.CategoryResult:
    return core_categories.CategoryResult(
        category_version=core_categories.CATEGORY_VERSION,
        assignments=(core_categories.CategoryAssignment("backups/mobile", ("fixture",), 0.9),),
        evidence=("fixture",),
    )


if __name__ == "__main__":
    unittest.main()
