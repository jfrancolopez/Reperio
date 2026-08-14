from __future__ import annotations

import asyncio
import json
import tempfile
import unittest
from pathlib import Path
from typing import Any

from migrations import runner
from shared import catalog_schema
from tests.test_api_service import asgi_request

try:
    from api.app import create_app
except ModuleNotFoundError as error:
    raise unittest.SkipTest("FastAPI runtime dependencies are not installed") from error

NOW = "2026-08-11T14:40:00Z"
HASH = "d" * 64


class ApiBrowserArtifactTests(unittest.TestCase):
    def test_empty_browser_query_returns_facets_summary_and_histogram(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            app = self._app(Path(tmp))

            listing = asyncio.run(asgi_request(app, "GET", "/api/v1/browser-artifacts"))
            facets = asyncio.run(asgi_request(app, "GET", "/api/v1/browser-artifacts/facets"))
            summary = asyncio.run(asgi_request(app, "GET", "/api/v1/browser-artifacts/summary"))
            histogram = asyncio.run(asgi_request(app, "GET", "/api/v1/browser-artifacts/histogram"))

        self.assertEqual(200, listing.status_code)
        self.assertEqual([], listing.json["artifacts"])
        self.assertIsNone(listing.json["next_cursor"])
        self.assertEqual([], facets.json["facets"]["artifact_kind"])
        self.assertEqual(0, summary.json["summary"]["total"])
        self.assertEqual([], histogram.json["histogram"])

    def test_browser_query_filters_facets_histogram_detail_and_related_findings(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            app = self._app(root)
            connection = catalog_schema.connect_catalog(root / "catalog.sqlite3")
            try:
                self._seed_case(connection)
                self._insert_browser_artifact(
                    connection,
                    "browser_visit",
                    artifact_kind="visit",
                    profile_id="profile_chrome",
                    browser_family="chromium",
                    content_id="content_1",
                    first_observed_at="2026-01-02T03:04:05Z",
                    artifact={
                        "url": "https://example.test/path?q=1",
                        "title": "Example Visit",
                        "url_normalization": {"registrable_domain": "example.test"},
                        "visit_time": {"normalized_utc": "2026-01-02T03:04:05Z"},
                        "os_user_id": "windows-profile-1",
                    },
                )
                self._insert_browser_artifact(
                    connection,
                    "browser_download",
                    artifact_kind="download",
                    profile_id="profile_firefox",
                    browser_family="firefox",
                    content_id="content_2",
                    first_observed_at="2026-01-03T03:04:05Z",
                    artifact={
                        "source_url": "https://download.test/file.zip",
                        "title": "Download",
                        "source_url_normalization": {"registrable_domain": "download.test"},
                        "start_time": {"normalized_utc": "2026-01-03T03:04:05Z"},
                    },
                )
                self._insert_finding(connection, "finding_related", content_id="content_1")
            finally:
                connection.close()

            filtered = asyncio.run(
                asgi_request(
                    app,
                    "GET",
                    "/api/v1/browser-artifacts?case_id=case_1&browser_family=chromium&domain=example.test&os_user_id=windows-profile-1&q=Visit",
                )
            )
            facets = asyncio.run(
                asgi_request(app, "GET", "/api/v1/browser-artifacts/facets?case_id=case_1")
            )
            summary = asyncio.run(
                asgi_request(app, "GET", "/api/v1/browser-artifacts/summary?case_id=case_1")
            )
            histogram = asyncio.run(
                asgi_request(app, "GET", "/api/v1/browser-artifacts/histogram?case_id=case_1")
            )
            detail = asyncio.run(
                asgi_request(app, "GET", "/api/v1/browser-artifacts/browser_visit")
            )

        self.assertEqual(
            ["browser_visit"], [row["browser_artifact_id"] for row in filtered.json["artifacts"]]
        )
        self.assertEqual("History", detail.json["provenance"]["source_artifact"])
        self.assertEqual(
            ["finding_related"], [row["finding_id"] for row in detail.json["related_findings"]]
        )
        self.assertEqual(
            {"chromium": 1, "firefox": 1},
            {row["value"]: row["count"] for row in facets.json["facets"]["browser_family"]},
        )
        self.assertEqual(2, summary.json["summary"]["total"])
        self.assertEqual(
            [{"date": "2026-01-02", "count": 1}, {"date": "2026-01-03", "count": 1}],
            histogram.json["histogram"],
        )

    def test_browser_cursor_is_stable_during_concurrent_ingest(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            app = self._app(root)
            connection = catalog_schema.connect_catalog(root / "catalog.sqlite3")
            try:
                self._seed_case(connection)
                for index in range(6):
                    self._insert_browser_artifact(connection, f"browser_{index:02d}")
            finally:
                connection.close()

            first = asyncio.run(asgi_request(app, "GET", "/api/v1/browser-artifacts?limit=3"))
            connection = catalog_schema.connect_catalog(root / "catalog.sqlite3")
            try:
                self._insert_browser_artifact(connection, "browser_03a")
            finally:
                connection.close()
            second = asyncio.run(
                asgi_request(
                    app,
                    "GET",
                    f"/api/v1/browser-artifacts?limit=3&cursor={first.json['next_cursor']}",
                )
            )

        first_ids = [row["browser_artifact_id"] for row in first.json["artifacts"]]
        second_ids = [row["browser_artifact_id"] for row in second.json["artifacts"]]
        self.assertEqual(["browser_00", "browser_01", "browser_02"], first_ids)
        self.assertEqual(["browser_03", "browser_03a", "browser_04"], second_ids)

    def test_invalid_browser_cursor_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            app = self._app(Path(tmp))

            response = asyncio.run(
                asgi_request(app, "GET", "/api/v1/browser-artifacts?cursor=not-valid")
            )

        self.assertEqual(400, response.status_code)

    def _app(self, root: Path) -> Any:
        db_path = root / "catalog.sqlite3"
        runner.migrate_catalog(db_path)
        return create_app(catalog_path=db_path)

    def _seed_case(self, connection: Any) -> None:
        connection.execute(
            """
            INSERT OR IGNORE INTO sources
            (source_id, stable_identity, media_kind, size_bytes, sector_size,
             fingerprint_sha256, status, created_at, updated_at)
            VALUES ('source_1', 'stable-source-1', 'block', 1024, 512, ?, 'approved', ?, ?)
            """,
            (HASH, NOW, NOW),
        )
        connection.execute(
            """
            INSERT OR IGNORE INTO scan_cases
            (case_id, source_id, state, policy_json, created_at, updated_at)
            VALUES ('case_1', 'source_1', 'running', '{}', ?, ?)
            """,
            (NOW, NOW),
        )

    def _insert_browser_artifact(
        self,
        connection: Any,
        browser_artifact_id: str,
        *,
        artifact_kind: str = "visit",
        profile_id: str = "profile_chrome",
        browser_family: str = "chromium",
        content_id: str | None = None,
        first_observed_at: str = "2026-01-02T03:04:05Z",
        artifact: dict[str, Any] | None = None,
    ) -> None:
        if content_id is not None:
            self._insert_content(connection, content_id)
        raw_provenance = {
            "entry_id": "entry-History",
            "source_artifact": "History",
            "parser": "test-browser-parser",
            "row_reference": browser_artifact_id,
        }
        artifact_payload = artifact or {
            "url": f"https://example.test/{browser_artifact_id}",
            "title": browser_artifact_id,
            "url_normalization": {"registrable_domain": "example.test"},
            "visit_time": {"normalized_utc": first_observed_at},
        }
        connection.execute(
            """
            INSERT INTO browser_artifacts
            (browser_artifact_id, case_id, content_id, profile_id, artifact_kind, browser_family,
             raw_provenance_json, artifact_json, recovery_confidence, first_observed_at, created_at)
            VALUES (?, 'case_1', ?, ?, ?, ?, ?, ?, 1.0, ?, ?)
            """,
            (
                browser_artifact_id,
                content_id,
                profile_id,
                artifact_kind,
                browser_family,
                json.dumps(raw_provenance, sort_keys=True),
                json.dumps(artifact_payload, sort_keys=True),
                first_observed_at,
                NOW,
            ),
        )

    def _insert_content(self, connection: Any, content_id: str) -> None:
        digest = (content_id.encode().hex() + "0" * 64)[:64]
        connection.execute(
            """
            INSERT OR IGNORE INTO contents
            (content_id, source_id, content_sha256, size_bytes, storage_uri, status, created_at)
            VALUES (?, 'source_1', ?, 1, ?, 'present', ?)
            """,
            (content_id, digest, f"scratch://{content_id}", NOW),
        )

    def _insert_finding(self, connection: Any, finding_id: str, *, content_id: str) -> None:
        connection.execute(
            """
            INSERT INTO findings
            (finding_id, case_id, content_id, finding_type, severity, title, summary, status, confidence, created_at)
            VALUES (?, 'case_1', ?, 'browser', 'medium', 'related', 'summary', 'new', 0.9, ?)
            """,
            (finding_id, content_id, NOW),
        )


if __name__ == "__main__":
    unittest.main()
