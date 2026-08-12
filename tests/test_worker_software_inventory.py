from __future__ import annotations

import unittest

from scanner.entry_normalization import NormalizedEntry, normalize_entry, raw_entry
from worker import software_inventory, windows_profiles


class WorkerSoftwareInventoryTests(unittest.TestCase):
    def test_msi_uninstall_and_application_directory_collapse_with_provenance(self) -> None:
        entries = (
            entry("Program Files/Acme/Editor/editor.exe", "1", "editor.exe"),
            entry(
                "Windows/System32/config/SOFTWARE/Microsoft/Windows/CurrentVersion/Uninstall/AcmeEditor",
                "2",
                "AcmeEditor",
            ),
        )
        metadata = {
            entries[1].display_path: {
                "display_name": "Editor",
                "publisher": "Acme",
                "version": "1.2.3",
                "install_time": "2026-01-02T03:04:05Z",
                "install_location": "Program Files/Acme/Editor",
            }
        }

        result = software_inventory.inventory_installed_software(entries, metadata_by_path=metadata)

        self.assertEqual(2, len(result.records))
        registry = next(record for record in result.records if record.publisher == "Acme")
        self.assertEqual("Editor", registry.name)
        self.assertEqual("1.2.3", registry.version)
        self.assertEqual(("uninstall_registry",), tuple(item.kind for item in registry.evidence))

    def test_store_package_fixture_extracts_name_and_version(self) -> None:
        result = software_inventory.inventory_installed_software(
            (entry("Program Files/WindowsApps/Contoso.App_2.0.0.0_x64/app.exe", "1", "app.exe"),)
        )

        self.assertEqual(1, len(result.records))
        self.assertEqual("contoso.app", result.records[0].normalized_name)
        self.assertEqual("2.0.0.0", result.records[0].version)
        self.assertEqual("store_package", result.records[0].evidence[0].kind)

    def test_portable_app_links_to_user_profile(self) -> None:
        profile = profile_fixture()

        result = software_inventory.inventory_installed_software(
            (entry("Users/Alice/Tools/Recuva.exe", "1", "Recuva.exe"),), profiles=(profile,)
        )

        self.assertEqual(1, len(result.records))
        self.assertEqual((profile.profile_id,), result.records[0].related_profile_ids)
        self.assertEqual("portable_app", result.records[0].evidence[0].kind)

    def test_incomplete_uninstall_entry_remains_visible_as_incomplete(self) -> None:
        uninstall = entry(
            "Windows/System32/config/SOFTWARE/Microsoft/Windows/CurrentVersion/Uninstall/BrokenApp",
            "1",
            "BrokenApp",
        )

        result = software_inventory.inventory_installed_software(
            (uninstall,), metadata_by_path={uninstall.display_path: {"display_name": "Broken App"}}
        )

        self.assertEqual(1, len(result.records))
        self.assertFalse(result.records[0].complete)
        self.assertIsNone(result.records[0].publisher)

    def test_false_positive_program_files_folder_does_not_create_inventory_record(self) -> None:
        result = software_inventory.inventory_installed_software(
            (entry("Program Files/Readme", "1", "Readme", entry_type="directory"),)
        )

        self.assertEqual((), result.records)
        self.assertIn("false_positive_folder:Program Files/Readme", result.warnings)


def entry(path: str, object_id: str, name: str, *, entry_type: str = "file") -> NormalizedEntry:
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


if __name__ == "__main__":
    unittest.main()
