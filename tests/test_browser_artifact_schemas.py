from __future__ import annotations

import unittest

from shared import browser_artifact_schemas


class BrowserArtifactSchemaTests(unittest.TestCase):
    def test_all_required_browser_artifact_schemas_exist(self) -> None:
        schemas = browser_artifact_schemas.browser_artifact_schemas()

        self.assertEqual(
            {
                "profile",
                "visit",
                "download",
                "bookmark",
                "search",
                "session_tab",
                "cookie_metadata",
                "cache_entry",
                "extension",
            },
            set(schemas),
        )
        for schema in schemas.values():
            self.assertEqual(1, schema["schema_version"])
            self.assertIn("raw_provenance", schema["required"])
            self.assertIn("recovery_confidence", schema["required"])

    def test_chromium_visit_golden_keeps_raw_and_normalized_time(self) -> None:
        result = browser_artifact_schemas.validate_browser_artifact(
            {
                "artifact_id": "visit-1",
                "artifact_kind": "visit",
                "browser_family": "chromium",
                "profile_id": "profile-1",
                "url": "https://example.test/",
                "title": "Example",
                "visit_time": timestamp(raw_epoch=13368163200000000),
                "raw_provenance": provenance("History", "visits:1"),
                "recovery_confidence": 1.0,
            }
        )

        self.assertTrue(result.valid, result.warnings)

    def test_firefox_download_golden_accepts_download_specific_fields(self) -> None:
        result = browser_artifact_schemas.validate_browser_artifact(
            {
                "artifact_id": "download-1",
                "artifact_kind": "download",
                "browser_family": "firefox",
                "profile_id": "profile-2",
                "source_url": "https://example.test/file.zip",
                "target_path": "C:/Users/A/Downloads/file.zip",
                "start_time": timestamp(raw_epoch=1780000000000),
                "raw_provenance": provenance("places.sqlite", "moz_annos:7"),
                "recovery_confidence": 0.95,
            }
        )

        self.assertTrue(result.valid, result.warnings)

    def test_legacy_windows_cookie_metadata_excludes_reusable_values(self) -> None:
        result = browser_artifact_schemas.validate_browser_artifact(
            {
                "artifact_id": "cookie-1",
                "artifact_kind": "cookie_metadata",
                "browser_family": "legacy_ie_edge",
                "profile_id": "profile-3",
                "host": "example.test",
                "name": "SID",
                "created_time": timestamp(raw_value="2026-01-02T03:04:05Z"),
                "value": "must-not-be-stored",
                "raw_provenance": provenance("WebCacheV01.dat", "Containers:3"),
                "recovery_confidence": 0.8,
            }
        )

        self.assertFalse(result.valid)
        self.assertIn("forbidden_token_field:value", result.warnings)

    def test_safari_shaped_bookmark_golden_accepts_profile_and_provenance(self) -> None:
        result = browser_artifact_schemas.validate_browser_artifact(
            {
                "artifact_id": "bookmark-1",
                "artifact_kind": "bookmark",
                "browser_family": "safari",
                "profile_id": "profile-4",
                "url": "https://example.test/bookmark",
                "title": "Bookmark",
                "created_time": timestamp(raw_value="734529845.0"),
                "raw_provenance": provenance("Bookmarks.plist", "Children[0]"),
                "recovery_confidence": 0.9,
            }
        )

        self.assertTrue(result.valid, result.warnings)

    def test_missing_timestamp_dual_representation_is_rejected(self) -> None:
        result = browser_artifact_schemas.validate_browser_artifact(
            {
                "artifact_id": "visit-2",
                "artifact_kind": "visit",
                "browser_family": "chromium",
                "profile_id": "profile-1",
                "url": "https://example.test/",
                "title": "Example",
                "visit_time": {"raw_epoch": 1},
                "raw_provenance": provenance("History", "visits:2"),
                "recovery_confidence": 1.0,
            }
        )

        self.assertFalse(result.valid)
        self.assertIn("missing_normalized_timestamp:visit_time", result.warnings)
        self.assertIn("missing_display_timezone:visit_time", result.warnings)


def timestamp(*, raw_epoch: int | None = None, raw_value: str | None = None) -> dict[str, object]:
    result: dict[str, object] = {
        "normalized_utc": "2026-01-02T03:04:05Z",
        "display_timezone": "UTC",
    }
    if raw_epoch is not None:
        result["raw_epoch"] = raw_epoch
    if raw_value is not None:
        result["raw_value"] = raw_value
    return result


def provenance(source_artifact: str, row_reference: str) -> dict[str, str]:
    return {
        "entry_id": "entry-1",
        "source_artifact": source_artifact,
        "parser": "synthetic-browser-golden",
        "row_reference": row_reference,
    }


if __name__ == "__main__":
    unittest.main()
