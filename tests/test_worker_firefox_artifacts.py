from __future__ import annotations

import json
import sqlite3
import tempfile
import unittest
from pathlib import Path

from shared.browser_artifact_schemas import validate_browser_artifact
from worker import firefox_artifacts
from worker.browser_profiles import BrowserProfile


class WorkerFirefoxArtifactsTests(unittest.TestCase):
    def test_parses_firefox_places_session_cache_and_extensions(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            scratch, profile_path = copied_profile(Path(tmp))
            create_places(profile_path / "places.sqlite")
            write_sessionstore(profile_path / "sessionstore.json")
            write_cache(profile_path / "cache2" / "index.json")
            write_extensions(profile_path / "extensions.json")

            result = firefox_artifacts.parse_firefox_profile(
                profile("Firefox", "ff-profile-1"),
                copied_profile_path=profile_path,
                job_scratch=scratch,
            )

        kinds = {record["artifact_kind"] for record in result.records}
        self.assertEqual(
            {"visit", "bookmark", "download", "search", "session_tab", "cache_entry", "extension"},
            kinds,
        )
        for record in result.records:
            self.assertTrue(validate_browser_artifact(record).valid, record)
            self.assertEqual("firefox-artifacts-v1", record["raw_provenance"]["parser"])
        visit = only_kind(result.records, "visit")
        self.assertEqual(False, visit["private_context"])
        session = only_kind(result.records, "session_tab")
        self.assertEqual("https://session.example.test/", session["url"])

    def test_tor_profile_uses_firefox_schema_and_degrades_missing_optional_artifacts(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            scratch, profile_path = copied_profile(Path(tmp))
            create_places(profile_path / "places.sqlite", include_downloads=False)

            result = firefox_artifacts.parse_firefox_profile(
                profile("Tor Browser", "tor-profile-1"),
                copied_profile_path=profile_path,
                job_scratch=scratch,
            )

        self.assertIn("visit", {record["artifact_kind"] for record in result.records})
        self.assertIn("missing_artifact:sessionstore.json", result.warnings)
        self.assertIn("missing_artifact:extensions.json", result.warnings)

    def test_corrupt_places_is_labeled_without_blocking_session_artifacts(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            scratch, profile_path = copied_profile(Path(tmp))
            (profile_path / "places.sqlite").write_bytes(b"not sqlite")
            write_sessionstore(profile_path / "sessionstore.json")

            result = firefox_artifacts.parse_firefox_profile(
                profile("Firefox", "ff-profile-1"),
                copied_profile_path=profile_path,
                job_scratch=scratch,
            )

        self.assertIn("malformed_artifact:places.sqlite", result.warnings)
        self.assertEqual({"session_tab"}, {record["artifact_kind"] for record in result.records})

    def test_wal_companion_and_missing_tables_are_bounded(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            scratch, profile_path = copied_profile(Path(tmp))
            connection = sqlite3.connect(profile_path / "places.sqlite")
            try:
                connection.execute("CREATE TABLE moz_places (id INTEGER PRIMARY KEY, url TEXT)")
                connection.commit()
            finally:
                connection.close()
            (profile_path / "places.sqlite-wal").write_bytes(b"synthetic wal companion")
            (profile_path / "places.sqlite-shm").write_bytes(b"synthetic shm companion")

            result = firefox_artifacts.parse_firefox_profile(
                profile("Firefox", "ff-profile-1"),
                copied_profile_path=profile_path,
                job_scratch=scratch,
            )

        self.assertIn("missing_table:moz_historyvisits", result.warnings)
        self.assertNotIn("malformed_artifact:places.sqlite", result.warnings)
        self.assertEqual((), result.records)

    def test_rejects_profile_copy_outside_job_scratch(self) -> None:
        with (
            tempfile.TemporaryDirectory() as scratch_tmp,
            tempfile.TemporaryDirectory() as source_tmp,
        ):
            outside = Path(source_tmp) / "profile.default"
            outside.mkdir()
            with self.assertRaises(firefox_artifacts.FirefoxArtifactError) as captured:
                firefox_artifacts.parse_firefox_profile(
                    profile("Firefox", "ff-profile-1"),
                    copied_profile_path=outside,
                    job_scratch=Path(scratch_tmp),
                )

        self.assertEqual("input_not_copied", captured.exception.code)


def copied_profile(root: Path) -> tuple[Path, Path]:
    scratch = root / "scratch"
    profile_path = scratch / "profile.default"
    profile_path.mkdir(parents=True)
    return scratch, profile_path


def profile(browser_name: str, profile_id: str) -> BrowserProfile:
    return BrowserProfile(
        browser_profile_id=profile_id,
        browser_family="firefox",
        browser_name=browser_name,
        profile_path=f"Users/Alice/AppData/Roaming/Mozilla/Firefox/Profiles/{profile_id}",
        profile_name="profile.default",
        volume_id="vol1",
        owner_profile_id="windows-profile-1",
        owner_sid="S-1-5-21-100",
        evidence=("places.sqlite", "sessionstore.json", "extensions.json"),
        companion_entry_ids=(
            "entry-places.sqlite",
            "entry-sessionstore.json",
            "entry-extensions.json",
        ),
        portable=False,
        partial=False,
    )


def create_places(path: Path, *, include_downloads: bool = True) -> None:
    connection = sqlite3.connect(path)
    try:
        connection.execute(
            """
            CREATE TABLE moz_places (
                id INTEGER PRIMARY KEY,
                url TEXT,
                title TEXT,
                visit_count INTEGER,
                last_visit_date INTEGER
            )
            """
        )
        connection.execute(
            """
            CREATE TABLE moz_historyvisits (
                id INTEGER PRIMARY KEY,
                place_id INTEGER,
                visit_date INTEGER,
                from_visit INTEGER,
                visit_type INTEGER
            )
            """
        )
        connection.execute(
            """
            CREATE TABLE moz_bookmarks (
                id INTEGER PRIMARY KEY,
                fk INTEGER,
                type INTEGER,
                title TEXT,
                dateAdded INTEGER
            )
            """
        )
        connection.execute(
            "CREATE TABLE moz_inputhistory (place_id INTEGER, input TEXT, use_count INTEGER)"
        )
        connection.execute(
            "INSERT INTO moz_places VALUES (1, 'https://example.test/', 'Example', 3, 1780000000000000)"
        )
        connection.execute("INSERT INTO moz_historyvisits VALUES (2, 1, 1780000000000000, NULL, 1)")
        connection.execute(
            "INSERT INTO moz_bookmarks VALUES (3, 1, 1, 'Bookmark', 1780000010000000)"
        )
        connection.execute("INSERT INTO moz_inputhistory VALUES (1, 'synthetic search', 2)")
        if include_downloads:
            connection.execute(
                """
                CREATE TABLE moz_downloads (
                    id INTEGER PRIMARY KEY,
                    source TEXT,
                    target TEXT,
                    startTime INTEGER,
                    endTime INTEGER,
                    currBytes INTEGER,
                    maxBytes INTEGER
                )
                """
            )
            connection.execute(
                "INSERT INTO moz_downloads VALUES (4, ?, ?, 1780000020000000, 1780000030000000, 7, 7)",
                ("https://download.example.test/file.txt", "C:/Users/Alice/Downloads/file.txt"),
            )
        connection.commit()
    finally:
        connection.close()


def write_sessionstore(path: Path) -> None:
    path.write_text(
        json.dumps(
            {
                "windows": [
                    {
                        "tabs": [
                            {
                                "index": 1,
                                "lastAccessed": 1780000040000,
                                "entries": [
                                    {
                                        "url": "https://session.example.test/",
                                        "title": "Session",
                                    }
                                ],
                            }
                        ]
                    }
                ]
            }
        ),
        encoding="utf-8",
    )


def write_cache(path: Path) -> None:
    path.parent.mkdir(parents=True)
    path.write_text(
        json.dumps(
            {
                "entries": [
                    {
                        "url": "https://cache.example.test/image.png",
                        "cache_key": "cache-key-ff-1",
                        "stored_time": 1780000050000000,
                    }
                ]
            }
        ),
        encoding="utf-8",
    )


def write_extensions(path: Path) -> None:
    path.write_text(
        json.dumps(
            {
                "addons": [
                    {
                        "id": "synthetic@example.test",
                        "defaultLocale": {"name": "Synthetic Add-on"},
                        "version": "1.0",
                        "path": "extensions/synthetic@example.test.xpi",
                        "active": True,
                    }
                ]
            }
        ),
        encoding="utf-8",
    )


def only_kind(records: tuple[dict[str, object], ...], kind: str) -> dict[str, object]:
    matches = [record for record in records if record["artifact_kind"] == kind]
    if len(matches) != 1:
        raise AssertionError(f"expected one {kind}, got {len(matches)}")
    return matches[0]


if __name__ == "__main__":
    unittest.main()
