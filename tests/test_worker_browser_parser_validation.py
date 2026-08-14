from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from tests.test_worker_chromium_artifacts import (
    copied_profile as copied_chromium_profile,
)
from tests.test_worker_chromium_artifacts import (
    profile as chromium_profile,
)
from tests.test_worker_chromium_artifacts import (
    write_bookmarks,
    write_cache,
    write_history,
    write_preferences,
    write_sessions,
)
from tests.test_worker_firefox_artifacts import copied_profile as copied_firefox_profile
from tests.test_worker_firefox_artifacts import create_places, write_extensions, write_sessionstore
from tests.test_worker_firefox_artifacts import profile as firefox_profile
from tests.test_worker_firefox_artifacts import write_cache as write_firefox_cache
from tests.test_worker_legacy_webcache_artifacts import (
    FakeParserRuntime,
    copied_webcache,
    lines,
    resources,
)
from tests.test_worker_legacy_webcache_artifacts import (
    profile as legacy_profile,
)
from worker import (
    browser_parser_validation,
    chromium_artifacts,
    firefox_artifacts,
    legacy_webcache_artifacts,
    parser_sandbox,
)

Golden = browser_parser_validation.BrowserGoldenRecord


class WorkerBrowserParserValidationTests(unittest.TestCase):
    def test_chromium_fixture_matches_golden_reference(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            scratch, profile_path = copied_chromium_profile(Path(tmp))
            write_history(profile_path / "History")
            write_bookmarks(profile_path / "Bookmarks")
            write_preferences(profile_path / "Preferences")
            write_sessions(profile_path / "Sessions.json")
            write_cache(profile_path / "Cache" / "index.json")

            parsed = chromium_artifacts.parse_chromium_profile(
                chromium_profile("Chrome", "chrome-profile-1"),
                copied_profile_path=profile_path,
                job_scratch=scratch,
            )

        result = browser_parser_validation.validate_browser_parser_output(
            browser_family="chromium",
            parser=chromium_artifacts.PARSER_VERSION,
            records=parsed.records,
            expected=chromium_golden(),
        )

        self.assertEqual("pass", result.status)
        self.assertEqual(7, result.matched_count)
        self.assertEqual("synthetic-golden-browser-fixtures-v1", result.as_report()["reference"])

    def test_firefox_fixture_matches_golden_reference(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            scratch, profile_path = copied_firefox_profile(Path(tmp))
            create_places(profile_path / "places.sqlite")
            write_sessionstore(profile_path / "sessionstore.json")
            write_firefox_cache(profile_path / "cache2" / "index.json")
            write_extensions(profile_path / "extensions.json")

            parsed = firefox_artifacts.parse_firefox_profile(
                firefox_profile("Firefox", "ff-profile-1"),
                copied_profile_path=profile_path,
                job_scratch=scratch,
            )

        result = browser_parser_validation.validate_browser_parser_output(
            browser_family="firefox",
            parser=firefox_artifacts.PARSER_VERSION,
            records=parsed.records,
            expected=firefox_golden(),
        )

        self.assertEqual("pass", result.status)
        self.assertEqual(7, result.matched_count)

    def test_legacy_webcache_fixture_matches_golden_reference(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            scratch, webcache = copied_webcache(Path(tmp))
            runtime = FakeParserRuntime(
                parser_sandbox.ParserProcessResult(
                    0,
                    lines(
                        {
                            "artifact_kind": "visit",
                            "row_reference": "Containers:1",
                            "url": "https://example.test/",
                            "title": "Example",
                            "timestamp": "2026-01-02T03:04:05Z",
                        },
                        {
                            "artifact_kind": "download",
                            "row_reference": "Containers:2",
                            "source_url": "https://example.test/file.zip",
                            "target_path": "C:/Users/Alice/Downloads/file.zip",
                            "start_time": "2026-01-02T03:04:06Z",
                            "end_time": "2026-01-02T03:04:07Z",
                            "received_bytes": 42,
                            "total_bytes": 42,
                        },
                        {
                            "artifact_kind": "favorite",
                            "row_reference": "Favorites:3",
                            "url": "https://example.test/bookmark",
                            "title": "Bookmark",
                            "created_time": "2026-01-02T03:04:08Z",
                        },
                        {
                            "artifact_kind": "cache_entry",
                            "row_reference": "Cache:4",
                            "url": "https://example.test/app.js",
                            "cache_key": "cache-key-1",
                            "stored_time": "2026-01-02T03:04:09Z",
                        },
                    ),
                )
            )

            parsed = legacy_webcache_artifacts.parse_legacy_webcache(
                legacy_profile(),
                copied_webcache_path=webcache,
                job_scratch=scratch,
                resource_profile=resources(),
                runtime=runtime,
                entry_id="entry-WebCacheV01.dat",
            )

        result = browser_parser_validation.validate_browser_parser_output(
            browser_family="legacy_ie_edge",
            parser=legacy_webcache_artifacts.PARSER_VERSION,
            records=parsed.records,
            expected=legacy_golden(),
        )

        self.assertEqual("pass", result.status)
        self.assertEqual(4, result.matched_count)

    def test_mismatches_are_reported_without_silent_selection(self) -> None:
        actual = [
            {
                "artifact_kind": "visit",
                "url": "https://changed.example.test/",
                "raw_provenance": {"source_artifact": "History", "row_reference": "visits:10"},
            }
        ]
        expected = [
            Golden(
                "visit",
                "History",
                "visits:10",
                {
                    "url": "https://example.test/",
                    "visit_time.normalized_utc": "2024-08-01T00:00:00Z",
                },
            ),
            Golden(
                "download",
                "History",
                "downloads:3",
                {"source_url": "https://example.test/file.zip"},
            ),
        ]

        result = browser_parser_validation.validate_browser_parser_output(
            browser_family="chromium",
            parser="chromium-artifacts-v1",
            records=actual,
            expected=expected,
        )

        self.assertEqual("fail", result.status)
        self.assertEqual(("download:History:downloads:3",), result.missing)
        self.assertIn("visit:History:visits:10:url", result.mismatches[0])

    def test_unvalidated_parser_version_is_rejected(self) -> None:
        with self.assertRaises(ValueError):
            browser_parser_validation.validate_browser_parser_output(
                browser_family="chromium",
                parser="chromium-artifacts-v999",
                records=(),
                expected=(),
            )


def chromium_golden() -> tuple[Golden, ...]:
    return (
        Golden(
            "visit",
            "History",
            "visits:10",
            {"url": "https://example.test/", "visit_time.normalized_utc": "2024-08-15T02:40:00Z"},
        ),
        Golden("search", "History", "keyword_search_terms:1", {"query": "synthetic query"}),
        Golden(
            "download", "History", "downloads:3", {"source_url": "https://example.test/file.zip"}
        ),
        Golden("bookmark", "Bookmarks", "bookmark:1", {"url": "https://example.test/bookmark"}),
        Golden(
            "extension",
            "Preferences",
            "extensions.settings:abcdefghijklmnopabcdefghijklmnop",
            {"extension_id": "abcdefghijklmnopabcdefghijklmnop"},
        ),
        Golden("session_tab", "Sessions.json", "tabs:1", {"url": "https://example.test/session"}),
        Golden(
            "cache_entry",
            "Cache/index.json",
            "entries:1",
            {"cache_key": "https://example.test/cache.png"},
        ),
    )


def firefox_golden() -> tuple[Golden, ...]:
    return (
        Golden(
            "visit",
            "places.sqlite",
            "moz_historyvisits:2",
            {"url": "https://example.test/", "visit_time.normalized_utc": "2026-05-28T20:26:40Z"},
        ),
        Golden("bookmark", "places.sqlite", "moz_bookmarks:3", {"url": "https://example.test/"}),
        Golden(
            "search",
            "places.sqlite",
            "moz_inputhistory:1:synthetic search",
            {"query": "synthetic search"},
        ),
        Golden(
            "download",
            "places.sqlite",
            "moz_downloads:4",
            {"source_url": "https://download.example.test/file.txt"},
        ),
        Golden(
            "session_tab",
            "sessionstore.json",
            "windows:0:tabs:0",
            {"url": "https://session.example.test/"},
        ),
        Golden("cache_entry", "cache2/index.json", "entries:1", {"cache_key": "cache-key-ff-1"}),
        Golden(
            "extension",
            "extensions.json",
            "addons:1:synthetic@example.test",
            {"extension_id": "synthetic@example.test"},
        ),
    )


def legacy_golden() -> tuple[Golden, ...]:
    return (
        Golden(
            "visit",
            "WebCacheV01.dat",
            "Containers:1",
            {"url": "https://example.test/", "visit_time.normalized_utc": "2026-01-02T03:04:05Z"},
        ),
        Golden(
            "download",
            "WebCacheV01.dat",
            "Containers:2",
            {"source_url": "https://example.test/file.zip"},
        ),
        Golden(
            "bookmark", "WebCacheV01.dat", "Favorites:3", {"url": "https://example.test/bookmark"}
        ),
        Golden("cache_entry", "WebCacheV01.dat", "Cache:4", {"cache_key": "cache-key-1"}),
    )


if __name__ == "__main__":
    unittest.main()
