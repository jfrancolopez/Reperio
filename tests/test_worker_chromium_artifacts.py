from __future__ import annotations

import json
import sqlite3
import tempfile
import unittest
from pathlib import Path

from shared.browser_artifact_schemas import validate_browser_artifact
from worker import chromium_artifacts
from worker.browser_profiles import BrowserProfile


class WorkerChromiumArtifactsTests(unittest.TestCase):
    def test_parses_chrome_profile_artifacts_with_provenance(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            scratch, profile_path = copied_profile(Path(tmp))
            write_history(profile_path / "History")
            write_bookmarks(profile_path / "Bookmarks")
            write_preferences(profile_path / "Preferences")
            write_sessions(profile_path / "Sessions.json")
            write_cache(profile_path / "Cache" / "index.json")

            result = chromium_artifacts.parse_chromium_profile(
                profile("Chrome", "chrome-profile-1"),
                copied_profile_path=profile_path,
                job_scratch=scratch,
            )

            kinds = {record["artifact_kind"] for record in result.records}
            self.assertEqual(
                {
                    "visit",
                    "download",
                    "bookmark",
                    "search",
                    "session_tab",
                    "cache_entry",
                    "extension",
                },
                kinds,
            )
            for record in result.records:
                self.assertTrue(validate_browser_artifact(record).valid, record)
                self.assertEqual("chromium-artifacts-v1", record["raw_provenance"]["parser"])
            visit = only_kind(result.records, "visit")
            self.assertEqual(4, visit["typed_count"])
            self.assertEqual(805306368, visit["transition"])
            download = only_kind(result.records, "download")
            self.assertEqual("https://example.test/file.zip", download["source_url"])

    def test_versioned_edge_and_brave_profiles_degrade_missing_optional_tables(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            scratch = Path(tmp) / "scratch"
            edge_path = scratch / "edge"
            brave_path = scratch / "brave"
            edge_path.mkdir(parents=True)
            brave_path.mkdir(parents=True)
            write_history(edge_path / "History", include_downloads=False)
            write_history(brave_path / "History", include_searches=False)

            edge = chromium_artifacts.parse_chromium_profile(
                profile("Edge", "edge-profile-1"),
                copied_profile_path=edge_path,
                job_scratch=scratch,
            )
            brave = chromium_artifacts.parse_chromium_profile(
                profile("Brave", "brave-profile-1"),
                copied_profile_path=brave_path,
                job_scratch=scratch,
            )

            self.assertIn("missing_table:downloads", edge.warnings)
            self.assertIn("visit", {record["artifact_kind"] for record in edge.records})
            self.assertIn("visit", {record["artifact_kind"] for record in brave.records})
            self.assertNotIn("search", {record["artifact_kind"] for record in brave.records})

    def test_malformed_history_is_labeled_without_losing_json_artifacts(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            scratch, profile_path = copied_profile(Path(tmp))
            (profile_path / "History").write_bytes(b"not a sqlite database")
            write_bookmarks(profile_path / "Bookmarks")

            result = chromium_artifacts.parse_chromium_profile(
                profile("Chrome", "chrome-profile-1"),
                copied_profile_path=profile_path,
                job_scratch=scratch,
            )

            self.assertIn("malformed_artifact:History", result.warnings)
            self.assertEqual({"bookmark"}, {record["artifact_kind"] for record in result.records})

    def test_locked_style_wal_companions_do_not_block_read_only_parse(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            scratch, profile_path = copied_profile(Path(tmp))
            write_history(profile_path / "History")
            (profile_path / "History-wal").write_bytes(b"synthetic wal companion")
            (profile_path / "History-shm").write_bytes(b"synthetic shm companion")

            result = chromium_artifacts.parse_chromium_profile(
                profile("Chrome", "chrome-profile-1"),
                copied_profile_path=profile_path,
                job_scratch=scratch,
            )

            self.assertIn("visit", {record["artifact_kind"] for record in result.records})
            self.assertNotIn("malformed_artifact:History", result.warnings)

    def test_missing_tables_and_source_paths_are_rejected_or_labeled(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            scratch, profile_path = copied_profile(root)
            sqlite3.connect(profile_path / "History").close()
            outside = root / "source" / "Default"
            outside.mkdir(parents=True)

            result = chromium_artifacts.parse_chromium_profile(
                profile("Chrome", "chrome-profile-1"),
                copied_profile_path=profile_path,
                job_scratch=scratch,
            )

            self.assertIn("missing_table:urls", result.warnings)
            self.assertIn("missing_table:visits", result.warnings)
            with self.assertRaises(chromium_artifacts.ChromiumArtifactError) as captured:
                chromium_artifacts.parse_chromium_profile(
                    profile("Chrome", "chrome-profile-1"),
                    copied_profile_path=outside,
                    job_scratch=scratch,
                )
            self.assertEqual("input_not_copied", captured.exception.code)


def copied_profile(root: Path) -> tuple[Path, Path]:
    scratch = root / "scratch"
    profile_path = scratch / "Default"
    profile_path.mkdir(parents=True)
    return scratch, profile_path


def profile(browser_name: str, profile_id: str) -> BrowserProfile:
    return BrowserProfile(
        browser_profile_id=profile_id,
        browser_family="chromium",
        browser_name=browser_name,
        profile_path=f"Users/Alice/{browser_name}/Default",
        profile_name="Default",
        volume_id="vol1",
        owner_profile_id="windows-profile-1",
        owner_sid="S-1-5-21-100",
        evidence=("history", "bookmarks", "preferences"),
        companion_entry_ids=("entry-History", "entry-Bookmarks", "entry-Preferences"),
        portable=False,
        partial=False,
    )


def write_history(
    path: Path, *, include_downloads: bool = True, include_searches: bool = True
) -> None:
    connection = sqlite3.connect(path)
    with connection:
        connection.execute(
            "CREATE TABLE urls (id INTEGER PRIMARY KEY, url TEXT, title TEXT, visit_count INTEGER, typed_count INTEGER, last_visit_time INTEGER)"
        )
        connection.execute(
            "CREATE TABLE visits (id INTEGER PRIMARY KEY, url INTEGER, visit_time INTEGER, from_visit INTEGER, transition INTEGER)"
        )
        connection.execute(
            "INSERT INTO urls VALUES (1, 'https://example.test/', 'Example', 7, 4, 13368163200000000)"
        )
        connection.execute("INSERT INTO visits VALUES (10, 1, 13368163200000000, 9, 805306368)")
        if include_searches:
            connection.execute(
                "CREATE TABLE keyword_search_terms (keyword_id INTEGER, url_id INTEGER, term TEXT)"
            )
            connection.execute("INSERT INTO keyword_search_terms VALUES (2, 1, 'synthetic query')")
        if include_downloads:
            connection.execute(
                "CREATE TABLE downloads (id INTEGER PRIMARY KEY, current_path TEXT, target_path TEXT, start_time INTEGER, end_time INTEGER, received_bytes INTEGER, total_bytes INTEGER)"
            )
            connection.execute(
                "INSERT INTO downloads VALUES (3, 'C:/Temp/file.zip', 'C:/Users/Alice/Downloads/file.zip', 13368163201000000, 13368163202000000, 42, 42)"
            )
            connection.execute(
                "CREATE TABLE downloads_url_chains (id INTEGER, chain_index INTEGER, url TEXT)"
            )
            connection.execute(
                "INSERT INTO downloads_url_chains VALUES (3, 0, 'https://example.test/file.zip')"
            )
    connection.close()


def write_bookmarks(path: Path) -> None:
    path.write_text(
        json.dumps(
            {
                "roots": {
                    "bookmark_bar": {
                        "children": [
                            {
                                "type": "url",
                                "name": "Bookmark",
                                "url": "https://example.test/bookmark",
                                "date_added": "13368163203000000",
                            }
                        ]
                    }
                }
            }
        ),
        encoding="utf-8",
    )


def write_preferences(path: Path) -> None:
    path.write_text(
        json.dumps(
            {
                "extensions": {
                    "settings": {
                        "abcdefghijklmnopabcdefghijklmnop": {
                            "path": "Extensions/abcdefghijklmnopabcdefghijklmnop/1.0",
                            "state": 1,
                            "manifest": {"name": "Synthetic Extension", "version": "1.0"},
                        }
                    }
                }
            }
        ),
        encoding="utf-8",
    )


def write_sessions(path: Path) -> None:
    path.write_text(
        json.dumps(
            {
                "tabs": [
                    {
                        "url": "https://example.test/session",
                        "title": "Session Tab",
                        "last_active_time": 13368163204000000,
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
                        "url": "https://example.test/cache.png",
                        "cache_key": "https://example.test/cache.png",
                        "stored_time": 13368163205000000,
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
