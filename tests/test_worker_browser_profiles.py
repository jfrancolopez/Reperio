from __future__ import annotations

import unittest

from scanner import entry_normalization, filesystem_enumeration
from worker import browser_profiles, windows_profiles


class WorkerBrowserProfilesTests(unittest.TestCase):
    def test_chrome_default_and_numbered_profiles_attach_to_owner(self) -> None:
        normalized = entries(
            ("Users/Alice/NTUSER.DAT", "S-1-5-21-100"),
            ("Users/Alice/AppData/Local/Google/Chrome/User Data/Default/History", "S-1-5-21-100"),
            (
                "Users/Alice/AppData/Local/Google/Chrome/User Data/Profile 1/Bookmarks",
                "S-1-5-21-100",
            ),
        )
        owners = windows_profiles.discover_windows_profiles(normalized).profiles

        result = browser_profiles.locate_windows_browser_profiles(normalized, owners)

        self.assertEqual({"Default", "Profile 1"}, {profile.profile_name for profile in result})
        self.assertEqual({"S-1-5-21-100"}, {profile.owner_sid for profile in result})
        self.assertEqual({"Chrome"}, {profile.browser_name for profile in result})

    def test_edge_brave_vivaldi_opera_chromium_firefox_and_tor_are_detected(self) -> None:
        result = browser_profiles.locate_windows_browser_profiles(
            entries(
                ("Users/Bob/AppData/Local/Microsoft/Edge/User Data/Default/History", None),
                (
                    "Users/Bob/AppData/Local/BraveSoftware/Brave-Browser/User Data/Default/History",
                    None,
                ),
                ("Users/Bob/AppData/Local/Vivaldi/User Data/Default/History", None),
                ("Users/Bob/AppData/Roaming/Opera Software/Opera Stable/History", None),
                ("Users/Bob/AppData/Local/Chromium/User Data/Default/Bookmarks", None),
                (
                    "Users/Bob/AppData/Roaming/Mozilla/Firefox/Profiles/abc.default/places.sqlite",
                    None,
                ),
                (
                    "Users/Bob/Desktop/Tor Browser/Browser/TorBrowser/Data/Browser/profile.default/places.sqlite",
                    None,
                ),
            )
        )

        self.assertEqual(
            {"Brave", "Chromium", "Edge", "Firefox", "Opera", "Tor Browser", "Vivaldi"},
            {profile.browser_name for profile in result},
        )

    def test_portable_profile_is_detected_without_owner_profile(self) -> None:
        result = browser_profiles.locate_windows_browser_profiles(
            entries(("Tools/GoogleChromePortable/Data/profile/History", None))
        )

        self.assertEqual(1, len(result))
        self.assertTrue(result[0].portable)
        self.assertIsNone(result[0].owner_profile_id)

    def test_partial_profile_is_labeled_but_still_reported(self) -> None:
        result = browser_profiles.locate_windows_browser_profiles(
            entries(
                (
                    "Users/Carol/AppData/Roaming/Mozilla/Firefox/Profiles/partial.default/prefs.js",
                    None,
                )
            )
        )

        self.assertEqual(1, len(result))
        self.assertTrue(result[0].partial)
        self.assertIn("prefs.js", result[0].evidence)

    def test_decoy_folder_without_browser_artifacts_is_ignored(self) -> None:
        result = browser_profiles.locate_windows_browser_profiles(
            entries(("Users/Dan/Documents/Chrome/Profile 1/readme.txt", None))
        )

        self.assertEqual((), result)


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
